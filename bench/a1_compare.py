"""A1: how far the simulated Borg scheduler is from the real Google 2011 Borg cell.

    python -m bench.a1_compare <loggen run dir> [experiments/results/A1_google2011_stats.json]

Maps loggen's borg.scheduler events onto the trace's event types (task_start -> SCHEDULE;
task_evicted -> EVICT; restarts after crash / OOM -> FAIL; rolling / manual updates -> KILL; there is
no FINISH in the generator), computes the same statistics as modal_apps/a1_google_trace.py and reports
total-variation distance (termination mix, priority mix), Kolmogorov-Smirnov distance (schedule events
per machine-hour), and the ratio of means.
"""
from __future__ import annotations

import json
import os
import sys
from collections import Counter, defaultdict

FAIL_REASONS = {"restart_crash", "restart_oom"}
KILL_REASONS = {"rolling_update", "manual_update"}


def simulated(run_dir: str) -> dict:
    from .core import epoch
    path = os.path.join(run_dir, "logs", "borg.scheduler.jsonl")
    ends, prio = Counter(), Counter()
    per_mh = defaultdict(int)
    machines, hours = set(), set()
    for line in open(path, encoding="utf-8"):
        e = json.loads(line)
        h = int(epoch(e["ts"]) // 3600)
        m = e["payload"].get("machine") or e.get("host")
        machines.add(m)
        hours.add(h)
        if e["action"] == "task_evicted":
            ends["EVICT"] += 1
        elif e["action"] in ("task_finish", "task_fail", "task_kill"):
            ends[{"task_finish": "FINISH", "task_fail": "FAIL", "task_kill": "KILL"}[e["action"]]] += 1
        elif e["action"] == "task_start":
            reason = e["payload"].get("reason", "")
            per_mh[(m, h)] += 1
            prio[{"prod": "production (9-11)", "free": "free (0-1)"}.get(e["payload"].get("priority"),
                                                                      "batch / middle (2-8)")] += 1
            if reason in FAIL_REASONS:
                ends["FAIL"] += 1
            elif reason in KILL_REASONS:
                ends["KILL"] += 1
    for k in ("EVICT", "FAIL", "FINISH", "KILL", "LOST"):
        ends.setdefault(k, 0)
    hours_range = range(min(hours), max(hours) + 1)
    counts = [per_mh.get((m, h), 0) for m in machines for h in hours_range]
    total_end = sum(ends.values()) or 1
    total_prio = sum(prio.values()) or 1
    return {"machines": len(machines), "hours": len(hours_range),
            "termination_mix": {k: v / total_end for k, v in ends.items()},
            "schedule_counts": counts,
            "priority_mix_of_schedules": {"free (0-1)": 0.0, "batch / middle (2-8)": 0.0, "production (9-11)": 0.0,
                                          **{k: v / total_prio for k, v in prio.items()}}}


def _cdf_from_hist(hist: dict[int, int]):
    total = sum(hist.values())
    acc, out = 0, {}
    for k in sorted(hist):
        acc += hist[k]
        out[k] = acc / total
    return out


def ks_distance(sim_counts: list[int], real_hist: dict) -> float:
    real_hist = {int(k): v for k, v in real_hist.items()}
    sim_hist = Counter(min(c, 50) for c in sim_counts)
    a, b = _cdf_from_hist(sim_hist), _cdf_from_hist(real_hist)
    xs = sorted(set(a) | set(b))
    best, ca, cb = 0.0, 0.0, 0.0
    for x in xs:
        ca = a.get(x, ca)
        cb = b.get(x, cb)
        best = max(best, abs(ca - cb))
    return round(best, 4)


def tvd(p: dict, q: dict) -> float:
    keys = set(p) | set(q)
    return round(0.5 * sum(abs(p.get(k, 0) - q.get(k, 0)) for k in keys), 4)


def compare(run_dir: str, real_path: str) -> dict:
    real = json.load(open(real_path, encoding="utf-8"))
    sim = simulated(run_dir)
    counts = sim.pop("schedule_counts")
    mean_sim = sum(counts) / max(len(counts), 1)
    rs = real["schedule_per_machine_hour"]
    return {
        "real": {"machines": real["machines"], "hours": real["hours"], "termination_mix": real["termination_mix"],
                 "schedule_per_machine_hour_mean": rs["mean"], "share_zero": rs["share_zero"],
                 "priority_mix": real["priority_mix_of_schedules"]},
        "simulated": {"machines": sim["machines"], "hours": sim["hours"], "termination_mix": sim["termination_mix"],
                      "schedule_per_machine_hour_mean": round(mean_sim, 4),
                      "share_zero": round(sum(c == 0 for c in counts) / max(len(counts), 1), 4),
                      "priority_mix": sim["priority_mix_of_schedules"]},
        "distance": {"termination_mix_tvd": tvd(sim["termination_mix"], real["termination_mix"]),
                     "priority_mix_tvd": tvd(sim["priority_mix_of_schedules"], real["priority_mix_of_schedules"]),
                     "schedule_per_machine_hour_ks": ks_distance(counts, rs["histogram"]),
                     "schedule_rate_ratio_sim_over_real": round(mean_sim / max(rs["mean"], 1e-9), 4)},
    }


if __name__ == "__main__":
    run = sys.argv[1]
    real = sys.argv[2] if len(sys.argv) > 2 else "experiments/results/A1_google2011_stats.json"
    res = compare(run, real)
    json.dump(res, open("experiments/results/A1_compare.json", "w"), indent=1)
    print(json.dumps(res, indent=1))
