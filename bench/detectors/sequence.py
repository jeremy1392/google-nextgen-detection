"""P4: sequence model over each entity's event stream (n-gram next-event model, in the spirit of
DeepLog's top-g criterion).

Each event becomes a token (source, action, outcome, plus the app / executable / operation that
matters for that source). Per entity type, the model counts which token follows each context of the
previous n-1 tokens of the same entity. After the warm-up, an event is anomalous when its token is not
among the top-g successors of a context seen at least `min_ctx` times. It keeps learning afterwards.
"""
from __future__ import annotations

from collections import defaultdict, deque

from ..core import Alert, Detector
from .fusion import Resolver


def token(ev: dict) -> str:
    p, s = ev["payload"], ev["log_source"]
    detail = ""
    if s == "host.ebpf":
        detail = str(p.get("exe", "")).rsplit("/", 1)[-1]
    elif s == "bc.uberproxy":
        detail = p.get("app", "")
    elif s == "colossus.curator":
        detail = p.get("classification") or ""
    elif s in ("spanner.audit", "bigtable.audit"):
        detail = p.get("classification") or ""
    elif s.startswith("ext."):
        detail = str(p.get("detail", ""))
    return f"{s}:{ev['action']}:{ev.get('outcome', '')}:{detail}"


class NGram(Detector):
    name = "P4-sequence-ngram"
    pipeline = "P4"

    def __init__(self, n: int = 3, top_g: int = 10, min_ctx: int = 20, warmup_h: float = 12.0,
                 cooldown_s: float = 1800.0):
        self.n, self.g, self.min_ctx, self.warmup_h, self.cooldown = n, top_g, min_ctx, warmup_h, cooldown_s
        self.hist: dict[str, deque] = {}
        self.counts: dict[tuple, dict] = defaultdict(lambda: defaultdict(int))
        self.totals: dict[tuple, int] = defaultdict(int)
        self.last_alert: dict[str, float] = {}

    def setup(self, run):
        self.run = run
        self.resolver = Resolver(run)
        self.learn_until = run.start + self.warmup_h * 3600

    def process(self, ev):
        tok = token(ev)
        learning = ev["_t"] < self.learn_until
        out = None
        for key in self.resolver.keys(ev):
            h = self.hist.get(key)
            if h is None:
                h = self.hist[key] = deque(maxlen=self.n - 1)
            if len(h) == self.n - 1:
                ctx = (key.split(":", 1)[0], *(x[0] for x in h))
                succ = self.counts[ctx]
                total = self.totals[ctx]
                if not learning and total >= self.min_ctx:
                    c = succ.get(tok, 0)
                    rank = sum(1 for v in succ.values() if v > c)
                    if rank >= self.g and ev["_t"] - self.last_alert.get(key, -1e18) >= self.cooldown:
                        self.last_alert[key] = ev["_t"]
                        p = (c + 0.1) / (total + 0.1 * (len(succ) + 1))
                        out = out or []
                        out.append(Alert(self.name, f"seq:{ev['log_source']}", key, min(1.0, 1 - p),
                                         [x[1] for x in h] + [ev["event_id"]]))
                succ[tok] += 1
                self.totals[ctx] += 1
            h.append((tok, ev["event_id"]))
        return out
