"""MalConv (Raff et al., 2017, "Malware Detection by Eating a Whole EXE"): a gated CNN over raw bytes.

Byte b is embedded as index b + 1 (0 is padding). Two parallel 1-D convolutions (kernel 500,
stride 500) are combined by a sigmoid gate, max-pooled over the whole file, then two dense layers
give one logit. Inputs are truncated to max_len (2 MB in the paper).

For the accuracy experiments (D1-D7) prefer the authors' reference code for MalConv2 / MalConvGCT
(github.com/NeuromorphicComputationResearchProgram/MalConv2); this file is enough for latency (C2, D1)
because inference cost depends on input length, not on content.
"""
from __future__ import annotations

import time

import numpy as np


def build(max_len: int = 2_000_000, embed: int = 8, channels: int = 128, window: int = 500):
    import torch
    import torch.nn as nn

    class MalConv(nn.Module):
        def __init__(self):
            super().__init__()
            self.max_len = max_len
            self.embed = nn.Embedding(257, embed, padding_idx=0)
            self.conv = nn.Conv1d(embed, channels, window, stride=window)
            self.gate = nn.Conv1d(embed, channels, window, stride=window)
            self.fc = nn.Sequential(nn.Linear(channels, channels), nn.ReLU(), nn.Linear(channels, 1))

        def forward(self, x):  # x: (batch, length) int64, bytes + 1, 0 = padding
            return self.forward_embedded(self.embed(x))

        def forward_embedded(self, e):  # e: (batch, length, embed) - used for gradients (D4, D7)
            e = e.transpose(1, 2)
            h = self.conv(e) * torch.sigmoid(self.gate(e))
            return self.fc(torch.amax(h, dim=2)).squeeze(1)

    return MalConv()


def byte_histogram(buf: bytes) -> np.ndarray:
    """The cheapest static baseline: normalized byte histogram (256 features)."""
    h = np.bincount(np.frombuffer(buf, dtype=np.uint8), minlength=256).astype(np.float32)
    return h / max(len(buf), 1)


def latency_bench(device: str, sizes=(65_536, 262_144, 1_048_576, 2_000_000), batches=(1, 8, 32),
                  threads=(None,), reps: int = 20) -> list[dict]:
    """Per-file inference latency (model only, and with host->device copy) for each size x batch."""
    import torch
    rows = []
    model = build().to(device).eval()
    rng = np.random.default_rng(0)
    for th in threads:
        if th:
            torch.set_num_threads(th)
        for size in sizes:
            for b in batches:
                host = torch.from_numpy(rng.integers(0, 256, (b, size), dtype=np.uint8))
                with torch.inference_mode():
                    def once():
                        x = host.to(device, non_blocking=False).long() + 1
                        t1 = time.perf_counter()
                        model(x)
                        if device == "cuda":
                            torch.cuda.synchronize()
                        return t1
                    for _ in range(3):
                        once()
                    total, model_only = [], []
                    for _ in range(reps):
                        t0 = time.perf_counter()
                        t1 = once()
                        t2 = time.perf_counter()
                        total.append(t2 - t0)
                        model_only.append(t2 - t1)
                total.sort()
                model_only.sort()
                rows.append({"device": device, "threads": th or torch.get_num_threads(), "file_bytes": size,
                             "batch": b,
                             "ms_per_file_p50": round(total[len(total) // 2] / b * 1000, 3),
                             "ms_per_file_p95": round(total[int(len(total) * 0.95)] / b * 1000, 3),
                             "ms_per_batch_p50": round(total[len(total) // 2] * 1000, 3),
                             "model_only_ms_per_file_p50": round(model_only[len(model_only) // 2] / b * 1000, 3),
                             "files_per_s": round(b / total[len(total) // 2], 1)})
    t0 = time.perf_counter()
    for _ in range(50):
        byte_histogram(rng.integers(0, 256, 2_000_000, dtype=np.uint8).tobytes())
    rows.append({"device": "cpu", "baseline": "byte_histogram", "file_bytes": 2_000_000,
                 "ms_per_file_p50": round((time.perf_counter() - t0) / 50 * 1000, 3)})
    return rows
