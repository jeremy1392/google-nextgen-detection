"""H1: nightly regression of detections. A fresh seed, the main pipelines, compared with the reference
distribution (10 seeds of the core plan): any metric worse than mean - 3 sd (or FP/day above mean + 3 sd)
fails, and the command exits with status 1.

    python -m bench.regress [--seed N] [--baseline experiments/results/suite_core.json]
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import tempfile
import time

PIPES = ["P0", "P1", "P2", "P5", "P6", "P6-hyper"]
HIGHER_IS_BETTER = ["recall", "precision"]
LOWER_IS_BETTER = ["fp_per_day"]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="bench.regress")
    ap.add_argument("--seed", type=int, default=int(time.strftime("%Y%m%d")))
    ap.add_argument("--baseline", default="experiments/results/suite_core.json")
    ap.add_argument("--out", default="experiments/results/H1_regression.json")
    args = ap.parse_args(argv)

    from loggen.cli import main as loggen_main
    from loggen.engine import parse_duration

    from .core import Run, replay
    from .detectors import PIPELINES
    from .score import score
    base = [r for r in json.load(open(args.baseline, encoding="utf-8")) if r["condition"] == "base"]
    with tempfile.TemporaryDirectory() as tmp:
        loggen_main(["--out", tmp, "--duration", "36h", "--seed", str(args.seed)])
        run = Run.load(tmp)
        dets = [PIPELINES[p]() for p in PIPES]
        for p, d in zip(PIPES, dets):
            d.name = p
        alerts, _ = replay(run, dets)
        now = {p: score(run, alerts[p], eval_from=run.start + parse_duration("12h")) for p in PIPES}
    report, failed = {"seed": args.seed, "checks": []}, False
    for p in PIPES:
        ref = [r for r in base if r["pipeline"] == p]
        for metric in HIGHER_IS_BETTER + LOWER_IS_BETTER:
            vals = [r[metric] for r in ref if r.get(metric) is not None]
            if len(vals) < 2 or now[p].get(metric) is None:
                continue
            m, sd = statistics.mean(vals), statistics.stdev(vals)
            v = now[p][metric]
            bad = v < m - 3 * sd if metric in HIGHER_IS_BETTER else v > m + 3 * sd
            failed |= bad
            report["checks"].append({"pipeline": p, "metric": metric, "value": v, "ref_mean": round(m, 4),
                                     "ref_sd": round(sd, 4), "status": "FAIL" if bad else "ok"})
    report["status"] = "FAIL" if failed else "PASS"
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    json.dump(report, open(args.out, "w"), indent=1)
    for c in report["checks"]:
        print(f"{c['status']:<5} {c['pipeline']:<9} {c['metric']:<12} {c['value']:<10} ref {c['ref_mean']} ± {c['ref_sd']}")
    print("H1:", report["status"])
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
