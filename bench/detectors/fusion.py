"""The modern camp, part 1: fusing weak signals into entity risk.

P6  probabilistic fusion. Every alert from the classic detectors (P1 rules + P2 baselines) becomes
    a weak signal on the entities its event resolves to (person, device, service, task, machine).
    A signal's weight is its score divided by how often that rule fires (rarity weighting), so a
    rule that fires 250 times a day barely moves the needle. Risk decays with a half-life. An
    entity is alerted when its risk crosses a threshold with at least two distinct signals, or
    with one rare and severe signal.
    Methods (E2): noisy_or (default), sum (risk-based alerting), max (single-signal baseline).

P5  the same, on a causal graph built from the events themselves: identity stitching edges
    (person-device, person-job, job-task, task-machine, principal-dataset, task-destination).
    A signal also lands, damped, on the entity's neighbours, so evidence spread over a person,
    their device and the job they touched adds up on one node.
"""
from __future__ import annotations

import math
from collections import defaultdict, deque

from ..core import Alert, Detector
from .baseline import Baselines
from .rules import Correlation


class Resolver:
    """Event -> canonical entity keys, using the inventory for device owners and services."""

    def __init__(self, run, flow_keys: bool = False):
        inv = run.inventory
        self.owner = {d["device_id"]: f"user:{d['owner']}" for d in inv.get("devices", [])}
        self.services = {s["name"] for s in inv.get("services", [])}
        self.flow_keys = flow_keys  # B4 windows carry no identity: key them by flow class (volume baselines only)

    def keys(self, ev: dict) -> list[str]:
        out = []
        p = ev.get("principal")
        if p:
            out.append(p)
        d = ev.get("device_id")
        if d:
            out.append(f"dev:{d}")
            o = self.owner.get(d)
            if o and o != p:
                out.append(o)
        t = ev.get("task")
        if t:
            out.append(f"task:{t}")
        j = ev.get("job")
        if j:
            out.append(f"svc:{j}" if j in self.services else f"job:{j}")
        h = ev.get("host")
        if h and ev["layer"].startswith("prod"):
            out.append(f"host:{h}")
        if self.flow_keys and ev["log_source"] == "net.b4":
            out.append(f"flow:{ev['payload'].get('flow_class')}")
        return list(dict.fromkeys(out))


class RuleRates:
    """How often each rule fires, so frequent rules weigh less."""

    def __init__(self, start: float, mode: str = "log"):
        self.start, self.n, self.mode = start, defaultdict(int), mode

    def weight(self, alert: Alert, t: float) -> float:
        self.n[alert.rule] += 1
        per_day = self.n[alert.rule] / max((t - self.start) / 86400, 0.25)
        if self.mode == "hyper":  # harsher: a rule firing 100x/day keeps ~9% of its weight
            return alert.score / (1 + per_day / 10)
        return alert.score / (1 + math.log1p(per_day))


class EntityRisk:
    __slots__ = ("risk", "t", "rules", "evidence", "last_alert", "best")

    def __init__(self):
        self.risk, self.t, self.rules = 0.0, 0.0, {}
        self.evidence: deque = deque(maxlen=120)
        self.last_alert, self.best = -1e18, 0.0


class Fusion(Detector):
    name = "P6-risk-fusion"
    pipeline = "P6"

    def __init__(self, method: str = "noisy_or", half_life_h: float = 6.0, threshold: float | None = None,
                 single_pass: float = 0.5, cooldown_h: float = 6.0, window_h: float = 24.0, extra: tuple = (),
                 rarity: str = "log", distinct: str = "rules", warmup_h: float = 12.0, tuned_rules: bool = False,
                 volume: str | None = None):
        self.method, self.half = method, half_life_h * 3600
        self.rarity, self.distinct = rarity, distinct
        self.thr = threshold if threshold is not None else {"noisy_or": 0.7, "sum": 1.2, "max": 0.45}[method]
        self.single_pass, self.cooldown, self.window = single_pass, cooldown_h * 3600, window_h * 3600
        if tuned_rules:
            from .rules import TunedCorrelation
            self.inner = [TunedCorrelation(warmup_h=warmup_h), Baselines(warmup_h=warmup_h, volume=volume)]
        else:
            self.inner = [Correlation(), Baselines(warmup_h=warmup_h, volume=volume)]
        self.volume = volume
        if extra:  # mix in ML / sequence / static-binary detectors as additional signal sources
            from .ml import IForest
            from .sequence import NGram
            from .gnn import LinkGNN
            from .static import StaticScan
            self.inner += [{"P3": IForest, "P4": NGram, "P7": StaticScan, "P10": LinkGNN}[x](warmup_h=warmup_h)
                           for x in extra]
        self.state: dict[str, EntityRisk] = defaultdict(EntityRisk)
        self.signals = 0
        if method != "noisy_or":
            self.name = f"P6-{method}"

    def setup(self, run):
        self.run = run
        for d in self.inner:
            d.setup(run)
        self.resolver = Resolver(run, flow_keys=self.volume is not None)
        self.rates = RuleRates(run.start, self.rarity)

    # ------------------------------------------------------------------ hooks for subclasses
    def targets(self, ev: dict, keys: list[str]) -> list[tuple[str, float]]:
        """(entity, damping) pairs a signal lands on. Flat fusion: the event's own entities."""
        return [(k, 1.0) for k in keys]

    def observe(self, ev: dict, keys: list[str]) -> None:
        """Called for every event (the graph variant builds its edges here)."""

    # ------------------------------------------------------------------ core
    def _apply(self, st: EntityRisk, w: float, src: str, rule: str, evidence: list, t: float) -> None:
        decay = 0.5 ** ((t - st.t) / self.half) if st.t else 1.0
        st.risk *= decay
        st.best *= decay
        st.t = t
        if self.method == "noisy_or":
            st.risk = 1 - (1 - st.risk) * (1 - min(w, 0.99))
        elif self.method == "sum":
            st.risk += w
        else:
            st.risk = max(st.risk, w)
        st.rules[(src, rule)] = t
        st.best = max(st.best, w)
        st.evidence.extend(evidence[:20])

    def _corroboration(self, st: EntityRisk, t: float) -> int:
        """Distinct recent signals: rule ids, or (distinct='detectors') independent detectors."""
        recent = [k for k, tr in st.rules.items() if t - tr < self.window]
        return len({k[0] for k in recent}) if self.distinct == "detectors" else len(recent)

    def _fuse_signals(self, ev: dict, keys: list[str], signals: list) -> list | None:
        if not signals or not keys:
            return None
        t = ev["_t"]
        touched = set()
        for a in signals:
            self.signals += 1
            w = self.rates.weight(a, t)
            for ent, damp in self.targets(ev, keys):
                self._apply(self.state[ent], w * damp, a.detector, a.rule, a.evidence, t)
                if damp >= 1.0:  # neighbours gain risk; only the entities involved may alert
                    touched.add(ent)
        out = None
        for ent in touched:
            st = self.state[ent]
            if st.risk >= self.thr and (self._corroboration(st, t) >= 2 or st.best >= self.single_pass) \
                    and t - st.last_alert >= self.cooldown:
                st.last_alert = t
                out = out or []
                out.append(Alert(self.name, f"risk:{self.method}", ent, min(st.risk, 5.0), list(st.evidence)))
        return out

    def process(self, ev):
        signals = []
        for d in self.inner:
            out = d.process(ev)
            if out:
                signals.extend(out)
        keys = self.resolver.keys(ev)
        self.observe(ev, keys)
        return self._fuse_signals(ev, keys, signals)

    def finish(self):
        for d in self.inner:
            d.finish()
        return None


class GraphFusion(Fusion):
    name = "P5-causal-graph"
    pipeline = "P5"
    HUB = 150      # nodes with more neighbours than this do not relay risk
    DAMP = 0.4     # share of a signal that reaches each neighbour

    def __init__(self, damp: float = 0.4, hub: int = 150, extra_edges: bool = True, **kw):
        super().__init__(**kw)
        self.name = "P5-causal-graph"
        self.adj: dict[str, set] = defaultdict(set)
        self.DAMP, self.HUB, self.extra_edges = damp, hub, extra_edges

    def observe(self, ev, keys):
        extra = list(keys)
        p = ev["payload"]
        if not self.extra_edges:  # F2: identity-stitching edges only
            p = {}
        if p.get("dataset"):
            extra.append(f"ds:{p['dataset']}")
        if self.extra_edges and ev.get("dst_ip") and not ev["dst_ip"].startswith("10."):
            extra.append(f"ip:{ev['dst_ip']}")
        if ev["log_source"] == "net.alts" and p.get("callee"):
            extra.append(p["callee"])
        for i, a in enumerate(extra):
            for b in extra[i + 1:]:
                if len(self.adj[a]) < 2000:
                    self.adj[a].add(b)
                if len(self.adj[b]) < 2000:
                    self.adj[b].add(a)

    def targets(self, ev, keys):
        out = {k: 1.0 for k in keys}
        for k in keys:
            if len(self.adj[k]) > self.HUB:
                continue
            for n in self.adj[k]:
                if n not in out and len(self.adj[n]) <= self.HUB:
                    out[n] = self.DAMP
        return list(out.items())
