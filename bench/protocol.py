"""Operating points fixed in advance, analyst dossiers and tie handling (protocol check of R@10).

R@10 reads each pipeline at the best point of its own ranking within 10 false positives a day, and that point is found
with the labels of the world being scored. This module fixes the point in advance instead:

  frozen threshold  the lowest score threshold whose pooled false positives stay within 10 a day on calibration worlds
                    (seeds 1-3), applied unchanged to test worlds (seeds 4-10);
  dossiers          alerts on the same entity within 24 hours of the first one form one analyst dossier (the merge on
                    shared triggering events, TRIGGER > 0, chains alerts across whole worlds and is off);
  top-k a day       each day, the k dossiers with the highest score are worked; recall over the attack cases;
  ties              R@10 as in the paper (stable order: tied alerts in time order) and with each group of tied scores
                    kept or dropped whole (conservative).

    python -m bench.protocol collect experiments/cache_protocol/s1 ...    # replay once, store alert records
    python -m bench.protocol analyze                                      # thresholds, dossiers, top-k
"""
from __future__ import annotations

import glob
import json
import os
import sys
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor

PIPES = ["P0", "P1", "P1-tuned", "P2", "P3", "P4", "P5", "P6", "P6-hyper", "P6-hyper-tuned", "P5-hyper-tuned", "MIX-tuned",
         "FINAL-nollm", "FINAL-vol-nollm"]
STORE = "experiments/protocol"
OUT = "experiments/results/PROTOCOL_frozen.json"
CAL, TEST = (1, 2, 3), (4, 5, 6, 7, 8, 9, 10)
BUDGET = 10.0
DOSSIER_S = 24 * 3600
TRIGGER = 0  # an alert's own triggering events: fused alerts also carry the risk history of the entity and its neighbours


def collect_one(ds: str) -> str:
    from loggen.engine import parse_duration

    from .core import Run, replay
    from .detectors import PIPELINES
    run = Run.load(ds)
    eval_from = run.start + parse_duration("12h")
    case_ids = {c["case_id"] for c in run.cases if c["_first"] >= eval_from}
    dets = [PIPELINES[p]() for p in PIPES]
    for p, d in zip(PIPES, dets):
        d.name = p
    alerts, _ = replay(run, dets)
    rec = {"dataset": ds, "days": (run.end - eval_from) / 86400, "cases": sorted(case_ids), "pipelines": {}}
    for p in PIPES:
        rows = []
        for a in alerts[p]:
            if a.t_detect < eval_from:
                continue
            hits = {run.by_event.get(e) for e in a.evidence} - {None}
            att = sorted({cid for cid, k in hits if k == "anomaly" and cid in case_ids})
            rows.append([round(a.t_detect - eval_from, 3), round(float(a.score), 6), a.entity, att, list(a.evidence)[-30:]])
        rec["pipelines"][p] = rows
    os.makedirs(STORE, exist_ok=True)
    path = os.path.join(STORE, os.path.basename(ds.rstrip("/\\")) + ".json")
    json.dump(rec, open(path, "w", encoding="utf-8"))
    return path


def _r10(rows, n_cases, days, budget=BUDGET, conservative=False):
    """Case recall within `budget` false positives a day, alerts taken by decreasing score."""
    if conservative:
        groups = defaultdict(list)
        for r in rows:
            groups[r[1]].append(r)
        fp, found = 0, set()
        for s in sorted(groups, reverse=True):
            g = groups[s]
            g_fp = sum(1 for r in g if not r[3])
            if (fp + g_fp) / days > budget:
                break
            fp += g_fp
            for r in g:
                found.update(r[3])
        return len(found) / n_cases
    fp, found = 0, set()
    for r in sorted(rows, key=lambda r: -r[1]):  # stable: ties stay in time order
        if r[3]:
            found.update(r[3])
        else:
            fp += 1
            if fp / days > budget:
                break
    return len(found) / n_cases


def _threshold(cal_worlds, p, budget=BUDGET):
    """Lowest score threshold whose pooled calibration FPs stay within the budget (tied scores kept whole)."""
    rows = [r for w in cal_worlds for r in w["pipelines"][p]]
    days = sum(w["days"] for w in cal_worlds)
    fp_at = defaultdict(int)
    for r in rows:
        if not r[3]:
            fp_at[r[1]] += 1
    scores = sorted({r[1] for r in rows}, reverse=True)
    thr, fp = float("inf"), 0
    for s in scores:
        if (fp + fp_at[s]) / days > budget:
            break
        fp += fp_at[s]
        thr = s
    return thr


def _dossiers(rows):
    """Analyst dossiers: alerts are merged when they concern the same entity within 24 hours of the dossier's first
    alert, or when their triggering events overlap (one incident seen from several identities). No label is used.
    Returns [t_open, max score, set of attack cases] per dossier."""
    rows = sorted(rows, key=lambda r: r[0])
    parent = list(range(len(rows)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    open_by, by_event = {}, {}
    for i, r in enumerate(rows):
        t, ent = r[0], r[2]
        j = open_by.get(ent)
        if j is not None and t - rows[j][0] < DOSSIER_S:
            parent[find(i)] = find(j)
        else:
            open_by[ent] = i
        for e in (r[4][-TRIGGER:] if TRIGGER and len(r) > 4 else []):  # the events that triggered this alert, not its whole history
            k = by_event.get(e)
            if k is None:
                by_event[e] = i
            else:
                parent[find(i)] = find(k)
    groups = {}
    for i, r in enumerate(rows):
        g = groups.setdefault(find(i), [r[0], r[1], set()])
        g[0] = min(g[0], r[0])
        g[1] = max(g[1], r[1])
        g[2].update(r[3])
    return list(groups.values())


def _world_metrics(w, p, thr):
    rows = [r for r in w["pipelines"][p] if r[1] >= thr]
    n, days = max(len(w["cases"]), 1), w["days"]
    found = set().union(*[set(r[3]) for r in rows]) if rows else set()
    doss = _dossiers(rows)
    out = {"recall": len(found) / n, "fp_per_day": sum(1 for r in rows if not r[3]) / days, "alerts_per_day": len(rows) / days,
           "dossiers_per_day": len(doss) / days, "fp_dossiers_per_day": sum(1 for d in doss if not d[2]) / days}
    all_doss = _dossiers(w["pipelines"][p])
    for k in (5, 10, 20):
        by_day = defaultdict(list)
        for d in all_doss:
            by_day[int(d[0] // 86400)].append(d)
        sel = set()
        for ds in by_day.values():
            for d in sorted(ds, key=lambda d: (-d[1], d[0]))[:k]:
                sel.update(d[2])
        out[f"recall_top{k}_dossiers_per_day"] = len(sel) / n
    out["r10_stable"] = _r10(w["pipelines"][p], n, days)
    out["r10_conservative"] = _r10(w["pipelines"][p], n, days, conservative=True)
    out["all_dossiers_per_day"] = len(all_doss) / days
    return out


def analyze(store=STORE, out=OUT) -> dict:
    worlds = {}
    for path in sorted(glob.glob(os.path.join(store, "s*.json"))):
        w = json.load(open(path, encoding="utf-8"))
        worlds[int(os.path.basename(path)[1:-5])] = w
    cal = [worlds[s] for s in CAL if s in worlds]
    test = [worlds[s] for s in TEST if s in worlds]
    res = {"calibration_seeds": [s for s in CAL if s in worlds], "test_seeds": [s for s in TEST if s in worlds],
           "budget_fp_per_day": BUDGET, "dossier_window_h": DOSSIER_S / 3600, "pipelines": {}}
    for p in PIPES:
        thr = _threshold(cal, p)
        per = [_world_metrics(w, p, thr) for w in test]
        free = [_world_metrics(w, p, float("-inf")) for w in test]  # the pipeline's own operating point
        mean = lambda xs, k: round(sum(x[k] for x in xs) / len(xs), 3)
        res["pipelines"][p] = {
            "threshold": None if thr == float("inf") else thr,
            "frozen": {k: mean(per, k) for k in ("recall", "fp_per_day", "alerts_per_day", "dossiers_per_day",
                                                  "fp_dossiers_per_day")},
            "frozen_worlds_over_budget": sum(1 for x in per if x["fp_per_day"] > BUDGET),
            "own_operating_point": {k: mean(free, k) for k in ("recall", "fp_per_day", "alerts_per_day", "all_dossiers_per_day",
                                                               "fp_dossiers_per_day")},
            "r10_stable": mean(free, "r10_stable"), "r10_conservative": mean(free, "r10_conservative"),
            "recall_top_k_dossiers_per_day": {k: mean(free, f"recall_top{k}_dossiers_per_day") for k in (5, 10, 20)}}
    os.makedirs(os.path.dirname(out), exist_ok=True)
    json.dump(res, open(out, "w", encoding="utf-8"), indent=1)
    return res


if __name__ == "__main__":
    if sys.argv[1] == "collect":
        with ProcessPoolExecutor(int(os.environ.get("WORKERS", "4"))) as ex:
            for path in ex.map(collect_one, sys.argv[2:]):
                print("stored", path, flush=True)
    else:
        r = analyze()
        print(f"calibration {r['calibration_seeds']}  test {r['test_seeds']}")
        for p, v in r["pipelines"].items():
            f, o = v["frozen"], v["own_operating_point"]
            print(f"{p:16s} thr {v['threshold']}  frozen: recall {f['recall']} FP/d {f['fp_per_day']} dossiers/d "
                  f"{f['dossiers_per_day']} (FP {f['fp_dossiers_per_day']}) over-budget worlds {v['frozen_worlds_over_budget']}"
                  f" | R@10 {v['r10_stable']} cons {v['r10_conservative']} | top-k {v['recall_top_k_dossiers_per_day']}"
                  f" | own: recall {o['recall']} FP/d {o['fp_per_day']} dossiers/d {o['all_dossiers_per_day']}")
