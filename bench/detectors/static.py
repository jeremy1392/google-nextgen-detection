"""P7: the static binary classifier (MalConv) as a detector, for D6.

Each corp.binscan event (a binary's first run on a device, emitted by the on-host extraction stage) is
looked up in the known-good cache, then scored by the classifier. The scores are real model outputs on
real binaries (D1: PE test split, D5: ELF test split); the simulation only decides which binary runs
where. The score table (BENCH_BINARY_SCORES, CSV sha256,label,score,platform,role) holds two disjoint
halves of each test split: role=threshold rows set the per-platform threshold at the target false-positive
rate, role=world rows are the binaries bound into the simulated fleet (loggen --binary-corpus).

Binaries seen during warm-up form the known-good cache and are never sent. A hash above the threshold
alerts once per day (later devices running it within the day add no new alert). The service time is the
C2 measurement, added to the alert as an off-path delay.
"""
from __future__ import annotations

import csv
import math
import os

from ..core import Alert, Detector

DEFAULT_SCORES = "experiments/d6/binary_scores.csv"
SERVICE_DELAY_S = 0.0393  # C2 measured: extraction + MalConv service on H100, 200 files/s, p99 = 39.3 ms


def load_scores(path: str) -> tuple[dict, dict]:
    """{sha256: (score, platform)} for the world binaries, {platform: [benign threshold-half scores]}."""
    world, neg = {}, {}
    with open(path, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r["role"] == "world":
                world[r["sha256"]] = (float(r["score"]), r["platform"])
            elif r["label"] == "0":
                neg.setdefault(r["platform"], []).append(float(r["score"]))
    return world, neg


def threshold_at(neg: list[float], fpr: float) -> float:
    """Same rule as the D1 / D5 reports: alert if score > the k-th highest benign score, k = floor(fpr n)."""
    s = sorted(neg, reverse=True)
    k = int(math.floor(fpr * len(s)))
    return s[k] if k < len(s) else s[-1]


class StaticScan(Detector):
    name = "P7-static"
    pipeline = "P7"

    def __init__(self, fpr: float = 1e-3, warmup_h: float = 12.0, scores: str | None = None,
                 delay_s: float = SERVICE_DELAY_S):
        self.fpr, self.warmup_h, self.delay_s = fpr, warmup_h, delay_s
        self.path = scores or os.environ.get("BENCH_BINARY_SCORES", DEFAULT_SCORES)
        self.scores, neg = load_scores(self.path)
        self.thr = {p: threshold_at(v, fpr) for p, v in neg.items()}
        self.seen: dict[str, dict] = {}  # event_id -> what the scan returned (LLM context, D6 analysis)
        self.stats = {"scans": 0, "cache_hits": 0, "unscored": 0, "above_threshold": 0, "alerts": 0,
                      "thresholds": self.thr}

    def setup(self, run):
        self.t_learn = run.start + self.warmup_h * 3600
        self.known: set = set()
        self.alerted: dict[str, float] = {}

    def process(self, ev):
        if ev["log_source"] != "corp.binscan":
            return None
        sha, t = ev["payload"].get("sha256"), ev["_t"]
        if t < self.t_learn:  # the fleet's known-good cache is built during warm-up
            self.known.add(sha)
            return None
        if sha in self.known:
            self.stats["cache_hits"] += 1
            return None
        got = self.scores.get(sha)
        if got is None:
            self.stats["unscored"] += 1
            return None
        score, plat = got
        self.stats["scans"] += 1
        thr = self.thr.get(plat, 0.5)
        self.seen[ev["event_id"]] = {"sha256": sha[:16], "platform": plat, "malconv_score": round(score, 4),
                                     "threshold": round(thr, 4)}
        if score <= thr:
            return None
        self.stats["above_threshold"] += 1
        last = self.alerted.get(sha)
        if last is not None and t - last < 86400:
            return None
        self.alerted[sha] = t
        self.stats["alerts"] += 1
        entity = ev.get("principal") or f"dev:{ev.get('device_id')}"
        a = Alert(self.name, f"malconv:{plat}", entity, score, [ev["event_id"]], family="runtime")
        a.delay_s = self.delay_s
        return [a]
