"""MalConv2 / MalConvGCT (Raff et al., AAAI 2021): a raw-byte classifier over whole files with constant memory.

Our re-implementation of the authors' reference design (github.com/FutureComputing4AI/MalConv2, Apache-2.0,
files MalConvGCT_nocat.py, MalConvML.py, LowMemConv.py):
  context branch  embedding(8) -> Conv1d(8, 2C, W, stride S) -> GLU -> 1x1 Conv1d -> leaky ReLU -> max over time
  main branch     the same layers, then global channel gating: h_t <- h_t * sigmoid(h_t . tanh(A c)), c = context
  head            max over time -> Linear(C, C) -> leaky ReLU -> Linear(C, 1)
Defaults C = 256, W = 256, S = 64 are those of the authors' released checkpoint.

Fixed-memory temporal max pooling: a first pass without gradients runs the branch over the file in chunks and
keeps, for each channel, the value and position of its maximum; a second pass recomputes, with gradients, only the
winning windows (one window of W bytes per channel). Memory depends on the chunk size, not on the file length.
Unlike the reference, consecutive chunks overlap by W - S bytes, so every window position is evaluated exactly once.
Input: uint8 bytes (B, L) with true lengths; byte b is embedded as b + 1, 0 is padding.
"""
from __future__ import annotations


def build(channels: int = 256, window: int = 256, stride: int = 64, embd: int = 8, chunk: int = 1 << 20):
    import torch
    import torch.nn as nn
    import torch.nn.functional as F

    assert chunk % stride == 0

    assert window % stride == 0
    k = window // stride

    class Branch(nn.Module):
        """Conv1d(embd, 2C, window, stride) written as a convolution over blocks of `stride` bytes:
        (B, L, embd) -> (B, embd*stride, L/stride) -> Conv1d(kernel window/stride, stride 1). Same function
        class (the weight is a reshape), much faster on GPUs than a 256-wide kernel over 8 channels."""

        def __init__(self):
            super().__init__()
            self.embd = nn.Embedding(257, embd, padding_idx=0)
            self.conv = nn.Conv1d(embd * stride, 2 * channels, k)
            self.share = nn.Conv1d(channels, channels, 1)

        def forward(self, x):  # x: (B, L) int64 in 0..256, L a multiple of stride
            B, L = x.shape
            h = self.embd(x).view(B, L // stride, stride * embd).transpose(1, 2)
            return F.leaky_relu(self.share(F.glu(self.conv(h), dim=1)))

    class MalConvGCT(nn.Module):
        def __init__(self):
            super().__init__()
            self.ctx = Branch()
            self.main = Branch()
            self.atn = nn.Linear(channels, channels)
            self.fc1 = nn.Linear(channels, channels)
            self.fc2 = nn.Linear(channels, 1)
            self.window, self.stride, self.channels, self.chunk = window, stride, channels, chunk

        def _tokens(self, xb, lengths, start, stop):
            """int64 tokens for bytes [start, stop) of every row: byte + 1, 0 past each file's end."""
            sub = xb[:, start:stop].long() + 1
            pos = torch.arange(start, start + sub.shape[1], device=xb.device)[None, :]
            return sub.masked_fill(pos >= lengths[:, None], 0)

        def _gated(self, h, c):
            g = torch.sigmoid(torch.einsum("bct,bc->bt", h, c)).unsqueeze(1)
            return h * g

        def _pool(self, xb, lengths, fn):
            """Fixed-memory max over time of fn(tokens) -> (B, C) with gradients through the winners only."""
            B, L = xb.shape
            W, S, C = self.window, self.stride, self.channels
            n_pos = torch.clamp((lengths - W) // S + 1, min=1)  # valid window starts per row (>= 1, padded)
            best = torch.full((B, C), float("-inf"), device=xb.device)
            arg = torch.zeros((B, C), dtype=torch.long, device=xb.device)
            with torch.no_grad():
                for start in range(0, max(L - W, 0) + 1, self.chunk):
                    stop = min(start + self.chunk + W - S, max(L, W))
                    tok = self._tokens(xb, lengths, start, stop)
                    if tok.shape[1] < W:
                        tok = F.pad(tok, (0, W - tok.shape[1]))
                    if tok.shape[1] % S:
                        tok = F.pad(tok, (0, S - tok.shape[1] % S))
                    h = fn(tok, None)  # (B, C, T)
                    p0 = start // S
                    pos = p0 + torch.arange(h.shape[2], device=xb.device)
                    h = h.float().masked_fill(pos[None, None, :] >= n_pos[:, None, None], float("-inf"))
                    v, i = h.max(dim=2)
                    upd = v > best
                    best = torch.where(upd, v, best)
                    arg = torch.where(upd, i + p0, arg)
            # Recompute the winning window of every (row, channel) with gradients.
            starts = (arg * S).view(-1)                                    # (B*C,)
            rows = torch.arange(B, device=xb.device).repeat_interleave(C)  # (B*C,)
            offs = starts[:, None] + torch.arange(W, device=xb.device)[None, :]
            raw = xb[rows[:, None], offs.clamp(max=max(L - 1, 0))].long() + 1
            raw = raw.masked_fill(offs >= lengths[rows][:, None], 0)
            h = fn(raw, rows)                                              # (B*C, C, 1)
            h = h[:, :, 0].view(B, C, C)                                   # [row, window of channel k, channel]
            return torch.diagonal(h, dim1=1, dim2=2)                       # (B, C)

        def forward(self, xb, lengths):
            ctx = self._pool(xb, lengths, lambda tok, rows: self.ctx(tok))
            c = torch.tanh(self.atn(ctx))
            c_d = c.detach()

            def main(tok, rows):
                h = self.main(tok)
                return self._gated(h, c_d if rows is None else c[rows])

            pooled = self._pool(xb, lengths, main)
            return self.fc2(F.leaky_relu(self.fc1(pooled))).squeeze(1)

    return MalConvGCT()


def _selftest():
    """CPU check: the fixed-memory forward equals a plain full forward, and gradients flow."""
    import torch
    torch.manual_seed(0)
    m = build(channels=16, window=32, stride=8, chunk=64)
    x = torch.randint(0, 256, (3, 300), dtype=torch.uint8)
    lengths = torch.tensor([300, 150, 20])
    out = m(x, lengths)
    # reference: full forward without chunking, masking invalid positions
    with torch.no_grad():
        def full(branch, gate):
            tok = torch.nn.functional.pad(m._tokens(x, lengths, 0, 300), (0, 4))  # to a multiple of the stride
            h = branch(tok)
            if gate is not None:
                h = m._gated(h, gate)
            n_pos = torch.clamp((lengths - 32) // 8 + 1, min=1)
            pos = torch.arange(h.shape[2])
            return h.masked_fill(pos[None, None, :] >= n_pos[:, None, None], float("-inf")).max(dim=2).values
        c = torch.tanh(m.atn(full(m.ctx, None)))
        ref = m.fc2(torch.nn.functional.leaky_relu(m.fc1(full(m.main, c)))).squeeze(1)
    out.sum().backward()
    grads = sum(p.grad.abs().sum().item() for p in m.parameters() if p.grad is not None)
    return float((out - ref).abs().max()), grads


if __name__ == "__main__":
    print(_selftest())
