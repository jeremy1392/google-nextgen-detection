"""B5: best technique per family, combined, versus one technique everywhere.

Runtime signatures (in-container syscalls, endpoint execution) are where hand-written rules are precise;
behaviour of people and services is where fusion is. MIX keeps only the severe runtime rules of P1 and
uses rarity-weighted fusion (P6-hyper) for everything else; alerts are the union of both.
direct=("P7",) (D6): a static-classifier verdict above its threshold alerts on its own, outside fusion.
"""
from __future__ import annotations

from ..core import Detector
from .fusion import Fusion
from .rules import Correlation, TunedCorrelation


class Mix(Detector):
    name = "MIX"
    pipeline = "B5"

    def __init__(self, min_rule_score: float = 0.9, tuned: bool = False, extra: tuple = (), direct: tuple = ()):
        self.rules = TunedCorrelation() if tuned else Correlation()
        self.fusion = Fusion(rarity="hyper", extra=extra)
        from .static import StaticScan
        from .gnn import LinkGNN
        self.direct = [{"P7": StaticScan, "P10": LinkGNN}[x]() for x in direct]
        self.min_rule_score = min_rule_score

    def setup(self, run):
        self.rules.setup(run)
        self.fusion.setup(run)
        for d in self.direct:
            d.setup(run)

    def process(self, ev):
        out = []
        r = self.rules.process(ev)
        if r:
            out += [a for a in r if a.family == "runtime" and a.score >= self.min_rule_score]
        f = self.fusion.process(ev)
        if f:
            out += f
        for d in self.direct:
            out += d.process(ev) or []
        return out or None

    def finish(self):
        self.fusion.finish()
        return None
