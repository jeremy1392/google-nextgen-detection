"""P10 (F6): temporal link prediction with a graph neural network, in the spirit of Euler (King & Huang,
NDSS 2022): learn which entities interact from the past interaction graph, then alert on interactions the
model finds unlikely.

Graph. Each event yields typed edges, by dataset:
  loggen   service -> called method (obs.rpc_edge, the unsampled call graph), person -> application
           (bc.uberproxy), principal -> dataset (colossus.curator), job -> egress destination (net.jupiter),
           job -> executed binary (host.ebpf execve), device owner -> binary (corp.santa / corp.auditd)
  LANL     user -> destination computer, source computer -> destination computer
  DARPA TC executable -> object it acts on (file pattern, remote address, child process)
Model (300 full-batch epochs, dimension 32, chosen by held-out link-prediction AUC). Two GraphSAGE layers (mean aggregation, Hamilton et al. 2017) over the undirected interaction graph
of the warm-up period, on learned node embeddings plus a node-type embedding; a dot-product decoder; trained
with binary cross-entropy against type-aware negative samples (the destination replaced by a random node of
the same type). Static snapshot: trained once at the end of the warm-up (no recurrent unit, unlike Euler).
Cold start: a node never seen in training gets the mean embedding of its type.
Scoring. For an edge (u, v) first met after the warm-up, s = -logit p(u, v); it alerts when s is above the
(1 - alert_share) quantile of the scores of the edges first met in the last quarter of the warm-up (held out
from training). One alert per edge per 24 h.
"""
from __future__ import annotations

import math
from collections import defaultdict

from ..core import Alert, Detector

FAMILY = {"svc": "nhi", "m": "nhi", "ds": "nhi", "ip": "nhi", "exe": "runtime", "bin": "runtime",
          "user": "ueba", "app": "ueba", "h": "ueba", "c": "ueba", "x": "runtime", "o": "runtime"}


def edges_of(ev: dict) -> list[tuple[str, str]]:
    s, p = ev["log_source"], ev.get("payload") or {}
    pr = ev.get("principal") or ""
    if s == "obs.rpc_edge":
        return [(p.get("caller") or f"svc:{ev.get('job')}", f"m:{p.get('method')}")]
    if s == "bc.uberproxy" and pr and p.get("app"):
        return [(pr, f"app:{p['app']}")]
    if s == "colossus.curator" and pr and p.get("dataset"):
        return [(pr, f"ds:{p['dataset']}")]
    if s == "net.jupiter" and p.get("egress") and ev.get("job"):
        return [(f"svc:{ev['job']}", f"ip:{ev.get('dst_ip')}")]
    if s == "host.ebpf" and ev.get("action") == "execve" and ev.get("job"):
        return [(f"svc:{ev['job']}", f"exe:{p.get('exe')}")]
    if s in ("corp.santa", "corp.auditd") and pr:
        return [(pr, f"bin:{p.get('sha256') or p.get('exe')}")]
    if s.startswith("ext."):
        host, dev = ev.get("host"), ev.get("device_id")
        if s == "ext.lanl.auth":
            out = [(pr, f"h:{host}")] if host else []
            if dev and host and dev != host:
                out.append((f"c:{dev}", f"h:{host}"))
            return out
        if dev:
            return [(pr, f"o:{dev}")]
    return []


def _type(node: str) -> str:
    head = node.split(":", 1)[0]
    return {"user": "user", "svc": "svc"}.get(head, head)


class LinkGNN(Detector):
    name = "P10-gnn-link"
    pipeline = "P10"

    def __init__(self, warmup_h: float = 12.0, dim: int = 32, epochs: int = 300, alert_share: float = 0.02,
                 neg: int = 4, seed: int = 0, max_train_edges: int = 2_000_000, record_edges: bool = False,
                 bias: bool = False, lr: float = 0.01):
        self.record_edges, self.rec, self.use_bias, self.lr = record_edges, {}, bias, lr
        self.warmup_h, self.dim, self.epochs, self.alert_share = warmup_h, dim, epochs, alert_share
        self.neg, self.seed, self.max_train_edges = neg, seed, max_train_edges
        self.first_seen: dict[tuple, float] = {}
        self.count: dict[tuple, int] = defaultdict(int)
        self.fitted = False
        self.cache: dict[tuple, float] = {}
        self.last_alert: dict[tuple, float] = {}
        self.stats: dict = {}

    def setup(self, run):
        self.run = run
        self.learn_until = run.start + self.warmup_h * 3600

    # ------------------------------------------------------------------ training
    def _fit(self):
        import numpy as np
        import torch
        torch.manual_seed(self.seed)
        span = self.learn_until - self.run.start
        cut = self.run.start + 0.75 * span
        train = [e for e, t in self.first_seen.items() if t < cut]
        held = [e for e, t in self.first_seen.items() if t >= cut]
        if len(train) > self.max_train_edges:  # keep the most frequent edges
            train = sorted(train, key=lambda e: -self.count[e])[:self.max_train_edges]
        nodes = sorted({x for e in train for x in e})
        self.index = {n: i for i, n in enumerate(nodes)}
        types = sorted({_type(n) for n in nodes} | {"?"})
        self.tindex = {t: i for i, t in enumerate(types)}
        ntype = torch.tensor([self.tindex[_type(n)] for n in nodes])
        by_type = defaultdict(list)
        for n, i in self.index.items():
            by_type[_type(n)].append(i)
        src = torch.tensor([self.index[u] for u, _ in train])
        dst = torch.tensor([self.index[v] for _, v in train])
        w = torch.tensor([math.log1p(self.count[e]) for e in train], dtype=torch.float32)
        n = len(nodes)
        # Undirected, row-normalised adjacency for mean aggregation.
        rows = torch.cat([src, dst])
        cols = torch.cat([dst, src])
        vals = torch.cat([w, w])
        deg = torch.zeros(n).index_add_(0, rows, vals).clamp(min=1e-6)
        adj = torch.sparse_coo_tensor(torch.stack([rows, cols]), vals / deg[rows], (n, n)).coalesce()

        class SAGE(torch.nn.Module):
            def __init__(s, dim):
                super().__init__()
                s.emb = torch.nn.Embedding(n, dim)
                s.temb = torch.nn.Embedding(len(types), dim)
                s.l1 = torch.nn.Linear(2 * dim, dim)
                s.l2 = torch.nn.Linear(2 * dim, dim)
                s.bias = torch.nn.Embedding(n, 1)  # per-node popularity (degree-like prior)
                torch.nn.init.normal_(s.emb.weight, std=0.1)
                torch.nn.init.zeros_(s.bias.weight)

            def forward(s):
                h = s.emb.weight + s.temb(ntype)
                h = torch.relu(s.l1(torch.cat([h, torch.sparse.mm(adj, h)], 1)))
                return s.l2(torch.cat([h, torch.sparse.mm(adj, h)], 1))

        model = SAGE(self.dim)
        opt = torch.optim.Adam(model.parameters(), lr=self.lr)
        b = (lambda i: model.bias.weight[i, 0]) if self.use_bias else (lambda i: 0.0)
        dst_t = ntype[dst]
        pools = {self.tindex[t]: torch.tensor(ix) for t, ix in by_type.items()}
        masks = {ti: (dst_t == ti) for ti in pools}
        masks = {ti: (m, int(m.sum())) for ti, m in masks.items() if m.any()}
        loss_fn = torch.nn.BCEWithLogitsLoss()
        for _ in range(self.epochs):
            z = model()
            pos = (z[src] * z[dst]).sum(1) + b(src) + b(dst)
            negs = []
            for _k in range(self.neg):
                nd = dst.clone()
                for ti, (m, cnt) in masks.items():
                    pool = pools[ti]
                    nd[m] = pool[torch.randint(len(pool), (cnt,))]
                negs.append((z[src] * z[nd]).sum(1) + b(src) + b(nd))
            neg_logits = torch.cat(negs)
            loss = loss_fn(pos, torch.ones_like(pos)) + loss_fn(neg_logits, torch.zeros_like(neg_logits))
            opt.zero_grad()
            loss.backward()
            opt.step()
        with torch.no_grad():
            z = model().numpy()
            bias = model.bias.weight[:, 0].numpy() if self.use_bias else np.zeros(n)
        self.z, self.bias = z, bias
        self.type_mean = {t: z[ix].mean(0) for t, ix in by_type.items()}
        # Cold start: an unseen node gets its type's mean embedding and a low popularity (10th percentile).
        self.type_bias = {t: float(np.quantile(bias[ix], 0.1)) for t, ix in by_type.items()}
        # Validation: held-out edges against type-aware random negatives (link-prediction AUC, no attack labels).
        if held:
            from sklearn.metrics import roc_auc_score
            rng = np.random.default_rng(self.seed)
            negs_v = []
            for u, v in held:
                pool = by_type.get(_type(v)) or [0]
                negs_v.append((u, nodes[pool[int(rng.integers(len(pool)))]]))
            sc = [-self._raw(u, v) for u, v in held] + [-self._raw(u, v) for u, v in negs_v]
            sc = [x if math.isfinite(x) else -1e9 for x in sc]
            self.val_auc = float(roc_auc_score([1] * len(held) + [0] * len(negs_v), sc))
        else:
            self.val_auc = None
        # Threshold from the held-out edges (first met in the last quarter of the warm-up).
        hs = np.array([self._raw(u, v) for u, v in held]) if held else np.array([0.0])
        self.held_scores = np.sort(hs[np.isfinite(hs)]) if np.isfinite(hs).any() else np.array([0.0])
        self.thr = float(np.quantile(self.held_scores, 1.0 - self.alert_share))
        self.fitted = True
        self.stats = {"train_edges": len(train), "held_out_edges": len(held), "nodes": n,
                      "final_loss": round(float(loss), 4), "threshold": round(self.thr, 3),
                      "val_link_auc": round(self.val_auc, 4) if self.val_auc is not None else None,
                      "epochs": self.epochs, "bias": self.use_bias, "dim": self.dim}
        # From now on new edges are scored, not learned (the model is a snapshot).

    def _vec(self, node: str):
        i = self.index.get(node)
        if i is not None:
            return self.z[i], float(self.bias[i])
        m = self.type_mean.get(_type(node))
        return (m, self.type_bias.get(_type(node), 0.0)) if m is not None else (None, 0.0)

    def _raw(self, u: str, v: str) -> float:
        (a, ba), (b, bb) = self._vec(u), self._vec(v)
        if a is None or b is None:
            return float("inf")
        return -(float((a * b).sum()) + ba + bb)

    # ------------------------------------------------------------------ stream
    def edge_metrics(self) -> dict:
        """ROC-AUC / AP of the GNN score and of two heuristics over the recorded new edges (record_edges)."""
        import math as _m

        from sklearn.metrics import average_precision_score, roc_auc_score
        deg = defaultdict(int)
        for u, v in self.first_seen:
            deg[u] += 1
            deg[v] += 1
        edges = list(self.rec)
        y = [self.rec[e][1] for e in edges]
        fin = [self.rec[e][0] for e in edges if _m.isfinite(self.rec[e][0])]
        big = (max(fin) + 1.0) if fin else 1.0
        scores = {"gnn": [self.rec[e][0] if _m.isfinite(self.rec[e][0]) else big for e in edges],
                  "pref_att": [-(_m.log1p(deg.get(u, 0)) + _m.log1p(deg.get(v, 0))) for u, v in edges],
                  "unseen": [float(u not in deg or v not in deg) for u, v in edges]}
        out = {"new_edges": len(edges), "anomalous_new_edges": int(sum(y))}
        for k, s in scores.items():
            ok = 0 < sum(y) < len(y)
            out[k] = {"auc": round(float(roc_auc_score(y, s)), 4) if ok else None,
                      "ap": round(float(average_precision_score(y, s)), 5) if ok else None}
        return out

    def process(self, ev):
        es = edges_of(ev)
        if not es:
            return None
        t = ev["_t"]
        if t < self.learn_until:
            for e in es:
                self.count[e] += 1
                self.first_seen.setdefault(e, t)
            return None
        if not self.fitted:
            self._fit()
        out = None
        for e in es:
            if e in self.first_seen:  # met during the warm-up: known interaction
                continue
            s = self.cache.get(e)
            if s is None:
                s = self.cache[e] = self._raw(*e)
            if self.record_edges:
                c = self.run.by_event.get(ev["event_id"])
                bad = int(bool(c) and c[1] == "anomaly")
                r = self.rec.get(e)
                if r is None:
                    self.rec[e] = [s, bad]
                elif bad:
                    r[1] = 1
            if s <= self.thr or t - self.last_alert.get(e, -1e18) < 86400:
                continue
            self.last_alert[e] = t
            import numpy as np
            q = float(np.searchsorted(self.held_scores, s)) / max(len(self.held_scores), 1)
            fam = FAMILY.get(_type(e[1]), "nhi")
            ent = ev.get("principal") or e[0]
            out = out or []
            out.append(Alert(self.name, f"gnn_unlikely_edge:{_type(e[0])}->{_type(e[1])}", ent,
                             min(0.99, 0.6 + 0.39 * q), [ev["event_id"]], fam))
        return out
