"""E2 (learned fusion): supervised alternatives to P6-hyper's hand-set weighting.

    python -m bench.e2_learned            # writes experiments/results/E2_learned.json

nb     naive Bayes: each rule's weight is its log-likelihood ratio (fires on anomalies vs on normal activity),
       learned on training seeds; entity risk = decayed sum of weights (a Bayesian network with independent
       evidence nodes).
stack  stacking: logistic regression on per-(entity, hour) counts of each rule.
Both are trained on seeds TRAIN and tested on seeds TEST, against P6-hyper. Each is also trained on the first
batch of anomaly types only, and its recall on the second batch measures generalisation (cf. A4).
"""
from __future__ import annotations

import json
import math
import os
import statistics
from collections import defaultdict

import numpy as np

from loggen.cli import main as loggen_main
from loggen.engine import parse_duration

from .core import Alert, Detector, Run, replay
from .detectors import PIPELINES
from .detectors.baseline import Baselines
from .detectors.fusion import Fusion, Resolver
from .detectors.rules import Correlation
from .score import score
from .validity import FIRST_BATCH

TRAIN, TEST = [101, 102, 103], [104, 105, 106, 107, 108, 109, 110]
CACHE = "experiments/cache_e2"


class Signals(Detector):
    """The weak signals the fusion engines consume (P1 rules + P2 baselines), with their entities."""
    name = "signals"

    def setup(self, run):
        self.inner = [Correlation(), Baselines()]
        for d in self.inner:
            d.setup(run)
        self.resolver = Resolver(run)

    def process(self, ev):
        out = []
        for d in self.inner:
            r = d.process(ev)
            if r:
                for a in r:
                    a.entity = "|".join(self.resolver.keys(ev)) or a.entity
                out += r
        return out or None


def _run(seed: int) -> Run:
    path = os.path.join(CACHE, f"s{seed}")
    if not os.path.exists(os.path.join(path, "manifest.json")):
        loggen_main(["--out", path, "--duration", "36h", "--seed", str(seed)])
    return Run.load(path)


def _label(run, a, allowed=None):
    for e in a.evidence:
        hit = run.by_event.get(e)
        if hit and hit[1] == "anomaly":
            if allowed is None:
                return 1
            ctype = next((c["anomaly_type"] for c in run.cases if c["case_id"] == hit[0]), None)
            if ctype in allowed:
                return 1
    return 0


def train(runs_signals, allowed=None):
    tp, fp = defaultdict(int), defaultdict(int)
    windows = defaultdict(lambda: defaultdict(int))
    wlab = defaultdict(int)
    for run, sigs in runs_signals:
        for a in sigs:
            y = _label(run, a, allowed)
            (tp if y else fp)[a.rule] += 1
            for ent in a.entity.split("|")[:1]:
                key = (id(run), ent, int(a.t_detect // 3600))
                windows[key][a.rule] += 1
                wlab[key] |= y
    rules = sorted(set(tp) | set(fp))
    T, F, R = sum(tp.values()), sum(fp.values()), len(rules)
    llr = {r: math.log((tp[r] + 0.5) / (T + 0.5 * R)) - math.log((fp[r] + 0.5) / (F + 0.5 * R)) for r in rules}
    from sklearn.linear_model import LogisticRegression
    keys = list(windows)
    X = np.array([[math.log1p(windows[k].get(r, 0)) for r in rules] for k in keys])
    y = np.array([wlab[k] for k in keys])
    clf = LogisticRegression(max_iter=2000, class_weight="balanced").fit(X, y) if 0 < y.sum() < len(y) else None
    return {"rules": rules, "llr": llr, "clf": clf}


class NBFusion(Fusion):
    """Fusion whose signal weights are learned log-likelihood ratios."""

    def __init__(self, llr: dict, **kw):
        super().__init__(method="sum", threshold=2.0, **kw)
        self.llr = llr

    def setup(self, run):
        super().setup(run)
        llr = self.llr

        class _W:
            def weight(self, alert, t):
                return llr.get(alert.rule, 0.0)
        self.rates = _W()


def stack_alerts(run, sigs, model) -> list:
    rules, clf = model["rules"], model["clf"]
    idx = {r: i for i, r in enumerate(rules)}
    win = defaultdict(lambda: {"counts": np.zeros(len(rules)), "evidence": [], "t": 0.0})
    for a in sigs:
        ent = a.entity.split("|")[0]
        w = win[(ent, int(a.t_detect // 3600))]
        if a.rule in idx:
            w["counts"][idx[a.rule]] += 1
        w["evidence"] += a.evidence[:5]
        w["t"] = max(w["t"], a.t_detect)
    out = []
    keys = list(win)
    if not keys or clf is None:
        return out
    X = np.log1p(np.stack([win[k]["counts"] for k in keys]))
    p = clf.predict_proba(X)[:, 1]
    for k, pk in zip(keys, p):
        if pk >= 0.5:
            out.append(Alert("stack", "stack", k[0], float(pk), win[k]["evidence"][-100:], None,
                             (k[1] + 1) * 3600.0))  # available at the end of the hour window
    return out


def main() -> dict:
    os.makedirs(CACHE, exist_ok=True)
    train_runs = []
    for s in TRAIN:
        run = _run(s)
        sig = Signals()
        alerts, _ = replay(run, [sig])
        train_runs.append((run, alerts["signals"]))
    models = {"all_types": train(train_runs), "first_batch_only": train(train_runs, FIRST_BATCH)}
    rows = defaultdict(list)
    for s in TEST:
        run = _run(s)
        eval_from = run.start + parse_duration("12h")
        sig = Signals()
        hyper = PIPELINES["P6-hyper"]()
        hyper.name = "P6-hyper"
        nbs = {}
        for tag, m in models.items():
            nb = NBFusion(m["llr"])
            nb.name = f"nb[{tag}]"
            nbs[tag] = nb
        alerts, _ = replay(run, [sig, hyper, *nbs.values()])
        rows["P6-hyper"].append(score(run, alerts["P6-hyper"], eval_from=eval_from))
        for tag, nb in nbs.items():
            rows[f"nb[{tag}]"].append(score(run, alerts[nb.name], eval_from=eval_from))
            rows[f"stack[{tag}]"].append(score(run, stack_alerts(run, alerts["signals"], models[tag]),
                                               eval_from=eval_from))

    def agg(vals):
        vals = [v for v in vals if v is not None]
        if not vals:
            return None
        m = statistics.mean(vals)
        return {"mean": round(m, 4), "sd": round(statistics.stdev(vals), 4) if len(vals) > 1 else 0.0}

    def second_batch(r):
        h = n = 0
        for t, frac in r["recall_by_type"].items():
            if t not in FIRST_BATCH:
                a, b = map(int, frac.split("/"))
                h, n = h + a, n + b
        return h / n if n else None

    out = {"train_seeds": TRAIN, "test_seeds": TEST,
           "top_llr": sorted(models["all_types"]["llr"].items(), key=lambda kv: -kv[1])[:12]}
    for name, rs in rows.items():
        out[name] = {"recall": agg([r["recall"] for r in rs]), "precision": agg([r["precision"] for r in rs]),
                     "fp_per_day": agg([r["fp_per_day"] for r in rs]),
                     "recall_at_10fp": agg([r["recall_at_fp_per_day"].get("10/day") for r in rs]),
                     "average_precision": agg([r["average_precision"] for r in rs]),
                     "brier": agg([r["brier"] for r in rs]),
                     "recall_second_batch": agg([second_batch(r) for r in rs])}
    json.dump(out, open("experiments/results/E2_learned.json", "w"), indent=1)
    return out


if __name__ == "__main__":
    res = main()
    for k, v in res.items():
        if isinstance(v, dict) and "recall" in v:
            print(f"{k:<26} recall {v['recall']}  R@10FP/d {v['recall_at_10fp']}  FP/day {v['fp_per_day']}  "
                  f"2nd-batch recall {v['recall_second_batch']}")
