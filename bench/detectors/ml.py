"""P3: unsupervised ML on per-entity activity windows (Isolation Forest).

Each entity (person, device, service, task, machine) gets one feature vector per hour of arrival
time: event counts per source (log1p), distinct actions, refused/denied outcomes, distinct
destinations, bytes moved (log), share of events outside 07:00-20:00 local. One model per entity
type is fitted on the warm-up windows; afterwards a window scoring above the 99.5th percentile of
its type's training scores raises an alert whose evidence is that window's events.
"""
from __future__ import annotations

import math
from collections import defaultdict

import numpy as np
from sklearn.ensemble import IsolationForest

from loggen.registry import SOURCES

from ..core import Alert, Detector
from .fusion import Resolver

SRC_INDEX = {s: i for i, s in enumerate(SOURCES)}
N_SRC = len(SRC_INDEX) + 16  # 16 hashed slots for sources of external datasets (A5)


def src_slot(source: str) -> int:
    i = SRC_INDEX.get(source)
    return i if i is not None else len(SRC_INDEX) + (sum(map(ord, source)) % 16)
DENIED = {"deny", "denied", "failure", "fail", "drop", "blocked", "lease_expired"}
BYTE_FIELDS = ("bytes", "bytes_read", "bytes_out", "bytes_written")


class _Win:
    __slots__ = ("counts", "actions", "denied", "dsts", "bytes", "offhours", "n", "ids")

    def __init__(self):
        self.counts = [0] * N_SRC
        self.actions, self.dsts = set(), set()
        self.denied = self.offhours = self.n = 0
        self.bytes = 0.0
        self.ids: list = []

    def vector(self) -> list[float]:
        return [math.log1p(c) for c in self.counts] + [
            math.log1p(len(self.actions)), math.log1p(self.denied), math.log1p(len(self.dsts)),
            math.log1p(self.bytes), self.offhours / max(self.n, 1)]


class IForest(Detector):
    name = "P3-isolation-forest"
    pipeline = "P3"

    def __init__(self, warmup_h: float = 12.0, window_s: float = 3600.0, quantile: float = 99.5):
        self.warmup_h, self.window_s, self.q = warmup_h, window_s, quantile
        self.wins: dict[str, _Win] = defaultdict(_Win)
        self.bucket = None
        self.train: dict[str, list] = defaultdict(list)
        self.models: dict[str, tuple] = {}

    def setup(self, run):
        self.run = run
        self.resolver = Resolver(run)
        self.learn_until = run.start + self.warmup_h * 3600

    @staticmethod
    def _type(key: str) -> str:
        return key.split(":", 1)[0]

    def _flush(self, now: float) -> list[Alert]:
        out = []
        if self.bucket is not None and (self.bucket + 1) * self.window_s >= self.learn_until and self.train \
                and not self.models:
            for typ, rows in self.train.items():
                if len(rows) >= 50:
                    X = np.asarray(rows)
                    m = IsolationForest(n_estimators=100, random_state=0).fit(X)
                    s = -m.score_samples(X)
                    self.models[typ] = (m, float(np.percentile(s, self.q)), float(s.max()))
        learning = not self.models
        if learning:
            for key, w in self.wins.items():
                self.train[self._type(key)].append(w.vector())
        else:
            by_type = defaultdict(list)
            for key, w in self.wins.items():
                by_type[self._type(key)].append((key, w))
            for typ, items in by_type.items():
                if typ not in self.models:
                    continue
                m, thr, top = self.models[typ]
                scores = -m.score_samples(np.asarray([w.vector() for _, w in items]))
                for (key, w), s in zip(items, scores):
                    if s > thr:
                        out.append(Alert(self.name, f"iforest:{typ}", key,
                                         min(1.0, 0.5 + (s - thr) / max(top - thr, 1e-6) * 0.5), w.ids[-300:]))
        self.wins.clear()
        return out

    def process(self, ev):
        b = int(ev["_it"] // self.window_s)
        out = None
        if self.bucket is None:
            self.bucket = b
        elif b > self.bucket:
            out = self._flush(ev["_it"]) or None
            self.bucket = b
        p = ev["payload"]
        hour = self.run.local_hour(ev["_t"])
        nbytes = sum(p.get(f) or 0 for f in BYTE_FIELDS if isinstance(p.get(f), (int, float)))
        for key in self.resolver.keys(ev):
            w = self.wins[key]
            w.counts[src_slot(ev["log_source"])] += 1
            w.actions.add(ev["action"])
            if ev.get("outcome") in DENIED:
                w.denied += 1
            if ev.get("dst_ip"):
                w.dsts.add(ev["dst_ip"])
            w.bytes += nbytes
            w.offhours += not 7 <= hour < 20
            w.n += 1
            w.ids.append(ev["event_id"])
        return out

    def finish(self):
        return self._flush(self.run.end) or None
