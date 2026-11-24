"""B6: closing the single-log exfiltration gap.

Bulk Spanner reads, Bigtable full scans and B4 replication spikes are visible in one audit log each, and no detector
of the study read those logs. B6 adds volume baselines (rows read per principal, table and clock hour on
spanner.audit and bigtable.audit; bytes per 10-minute window and flow class on net.b4), scored against the same key at
the same hour of the day ("hourly") or against all hours ("flat", the naive variant), alone (P2) and inside the
recommended pipeline (FINAL, detection stage). The nightly backup window (01:00-04:30 local: B4 backup traffic about
30 times its daytime level, backup-pipeline streaming reads on Spanner) is the look-alike.

    python -m bench.b6_volume experiments/cache_g11/s8 experiments/cache_g11/s9 ...
"""
from __future__ import annotations

import json
import os
import sys
from concurrent.futures import ProcessPoolExecutor

EXFIL = ("spanner_bulk_export", "bigtable_full_scan", "b4_replication_spike")
PIPES = ["P2", "P2-vol", "P2-volflat", "FINAL-nollm", "FINAL-vol-nollm", "FINAL-volflat-nollm"]
VOL_RULES = ("spanner_rows_volume", "bigtable_rows_volume", "b4_bytes_volume")
OUT = "experiments/results/B6_volume.json"


def one(ds: str) -> dict:
    from loggen.engine import parse_duration

    from .core import Run, replay
    from .detectors import PIPELINES
    from .score import score
    run = Run.load(ds)
    eval_from = run.start + parse_duration("12h")
    days = (run.end - eval_from) / 86400
    dets = [PIPELINES[p]() for p in PIPES]
    for p, d in zip(PIPES, dets):
        d.name = p
    alerts, _ = replay(run, dets)
    res = {"dataset": ds, "days_scored": round(days, 3), "pipelines": {}}
    for p in PIPES:
        m = score(run, alerts[p], eval_from=eval_from)
        vol_fp = night_fp = backup_fp = vol_tp = 0
        for a in alerts[p]:
            if a.t_detect < eval_from:
                continue
            rule = a.rule.split(":", 1)[-1]
            if rule not in VOL_RULES:
                continue
            hits = {run.by_event.get(e) for e in a.evidence} - {None}
            if any(k == "anomaly" for _, k in hits):
                vol_tp += 1
                continue
            vol_fp += 1
            night_fp += 1.0 <= run.local_hour(a.t_detect) < 4.5
            backup_fp += a.entity in ("flow:backup", "svc:backup-pipeline")
        exfil = {t: m["recall_by_type"].get(t, "0/0") for t in EXFIL}
        hit = sum(int(v.split("/")[0]) for v in exfil.values())
        tot = sum(int(v.split("/")[1]) for v in exfil.values())
        res["pipelines"][p] = {
            "recall": m["recall"], "precision": m["precision"], "fp_per_day": m["fp_per_day"],
            "recall_at_10fp": m["recall_at_fp_per_day"].get("10/day"), "cases": m["cases"],
            "exfil_by_type": exfil, "exfil_detected": hit, "exfil_cases": tot,
            "volume_rule_alerts_tp": vol_tp, "volume_rule_fp": vol_fp, "volume_rule_fp_per_day": round(vol_fp / days, 2),
            "volume_rule_fp_in_backup_window": night_fp, "volume_rule_fp_on_backup_entities": backup_fp,
            "fp_per_day_by_rule": m["fp_per_day_by_rule"]}
    return res


def main(datasets: list[str], workers: int = 4) -> dict:
    with ProcessPoolExecutor(workers) as ex:
        rows = list(ex.map(one, datasets))
    agg = {}
    for p in PIPES:
        r = [x["pipelines"][p] for x in rows]
        n = len(r)
        agg[p] = {"worlds": n,
                  "recall_mean": round(sum(x["recall"] for x in r) / n, 3),
                  "fp_per_day_mean": round(sum(x["fp_per_day"] for x in r) / n, 2),
                  "r10_mean": round(sum(x["recall_at_10fp"] for x in r) / n, 3),
                  "exfil_detected": sum(x["exfil_detected"] for x in r), "exfil_cases": sum(x["exfil_cases"] for x in r),
                  "exfil_by_type": {t: f"{sum(int(x['exfil_by_type'][t].split('/')[0]) for x in r)}/"
                                       f"{sum(int(x['exfil_by_type'][t].split('/')[1]) for x in r)}" for t in EXFIL},
                  "volume_rule_fp": sum(x["volume_rule_fp"] for x in r),
                  "volume_rule_fp_in_backup_window": sum(x["volume_rule_fp_in_backup_window"] for x in r),
                  "volume_rule_fp_on_backup_entities": sum(x["volume_rule_fp_on_backup_entities"] for x in r)}
    out = {"note": __doc__.strip().splitlines()[0], "datasets": datasets, "aggregate": agg, "runs": rows}
    return out


if __name__ == "__main__":
    args = sys.argv[1:]
    out = OUT
    if "--out" in args:
        i = args.index("--out")
        out = args[i + 1]
        args = args[:i] + args[i + 2:]
    res = main(args)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    json.dump(res, open(out, "w", encoding="utf-8"), indent=1)
    for p, a in res["aggregate"].items():
        print(f"{p:22s} recall {a['recall_mean']} FP/day {a['fp_per_day_mean']} R@10 {a['r10_mean']} exfil {a['exfil_detected']}/"
              f"{a['exfil_cases']} {a['exfil_by_type']} vol-rule FP {a['volume_rule_fp']} (backup window "
              f"{a['volume_rule_fp_in_backup_window']}, backup entities {a['volume_rule_fp_on_backup_entities']})")
