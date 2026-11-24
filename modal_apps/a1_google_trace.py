"""A1: realism of the simulated Borg scheduler against the real Google 2011 Borg cell trace.

    modal run modal_apps/a1_google_trace.py          # writes experiments/results/A1_google2011_stats.json

Reads every task_events part (clusterdata-2011-2, 29 days, ~12.5k machines) staged by datasets.py and
computes: the mix of task termination events, schedule / evict counts per machine-hour, the hour-of-day
profile, and the priority mix. bench/a1_compare.py computes the same from a loggen run and the distances.
"""
from __future__ import annotations

import json
import os

import modal

app = modal.App("a1-google-trace")
vol = modal.Volume.from_name("detection-data", create_if_missing=False)
image = modal.Image.debian_slim(python_version="3.11").pip_install("pandas==2.2.3", "numpy==1.26.4")
EVENTS = {0: "SUBMIT", 1: "SCHEDULE", 2: "EVICT", 3: "FAIL", 4: "FINISH", 5: "KILL", 6: "LOST",
          7: "UPDATE_PENDING", 8: "UPDATE_RUNNING"}


def _part(path: str):
    import numpy as np
    import pandas as pd
    df = pd.read_csv(path, header=None, usecols=[0, 4, 5, 8], names=["ts", "machine", "event", "priority"])
    df = df[(df.ts > 0) & (df.ts < 2**62)]
    df["hour"] = (df.ts // 3_600_000_000).astype(np.int32)
    counts = df.event.value_counts().to_dict()
    prio = df[df.event == 1].priority.value_counts().to_dict()
    sched_evict = df[df.event.isin([1, 2]) & df.machine.notna()]
    agg = sched_evict.groupby(["machine", "hour", "event"]).size().reset_index(name="n")
    return counts, prio, agg[["machine", "hour", "event", "n"]].to_numpy(dtype=np.int64)


@app.function(image=image, volumes={"/data": vol}, timeout=6 * 3600, cpu=16, memory=65536)
def stats():
    import glob
    from collections import Counter
    from concurrent.futures import ProcessPoolExecutor

    import numpy as np
    import pandas as pd
    parts = sorted(glob.glob("/data/google2011/task_events/*.csv.gz"))
    events, prios, aggs = Counter(), Counter(), []
    with ProcessPoolExecutor(16) as pool:
        for c, p, a in pool.map(_part, parts):
            events.update(c)
            prios.update(p)
            aggs.append(a)
    agg = pd.DataFrame(np.concatenate(aggs), columns=["machine", "hour", "event", "n"])
    agg = agg.groupby(["machine", "hour", "event"]).n.sum().reset_index()
    machines = agg.machine.nunique()
    hours = agg.hour.max() - agg.hour.min() + 1
    out = {"parts": len(parts), "machines": int(machines), "hours": int(hours),
           "event_counts": {EVENTS.get(int(k), str(k)): int(v) for k, v in events.items()}}
    ends = {k: out["event_counts"].get(k, 0) for k in ("EVICT", "FAIL", "FINISH", "KILL", "LOST")}
    out["termination_mix"] = {k: v / max(sum(ends.values()), 1) for k, v in ends.items()}
    # Per machine-hour counts, including the zero hours of machines that were seen.
    for ev, name in ((1, "schedule"), (2, "evict")):
        sub = agg[agg.event == ev]
        full = sub.set_index(["machine", "hour"]).n.reindex(
            pd.MultiIndex.from_product([agg.machine.unique(), range(int(agg.hour.min()), int(agg.hour.max()) + 1)]),
            fill_value=0)
        q = np.percentile(full.to_numpy(), [50, 90, 99, 99.9])
        out[f"{name}_per_machine_hour"] = {"mean": float(full.mean()), "p50": q[0], "p90": q[1], "p99": q[2],
                                           "p99.9": q[3], "share_zero": float((full == 0).mean()),
                                           "histogram": {int(k): int(v) for k, v in
                                                         full.clip(upper=50).value_counts().sort_index().items()}}
    # Hour-of-day profile of schedule events (trace time 0 = start; the trace is in US Pacific time
    # but the offset is not published: report the raw profile and its peak-to-trough ratio).
    sched = agg[agg.event == 1].groupby(agg.hour % 24).n.sum()
    out["schedule_hour_profile"] = (sched / sched.mean()).round(3).to_dict()
    out["schedule_peak_to_trough"] = float(sched.max() / max(sched.min(), 1))
    total = sum(prios.values())
    bands = {"free (0-1)": range(0, 2), "batch / middle (2-8)": range(2, 9), "production (9-11)": range(9, 12)}
    out["priority_mix_of_schedules"] = {b: sum(prios.get(p, 0) for p in r) / max(total, 1) for b, r in bands.items()}
    return out


@app.local_entrypoint()
def main(out: str = "experiments/results/A1_google2011_stats.json"):
    res = stats.remote()
    os.makedirs(os.path.dirname(out), exist_ok=True)
    json.dump(res, open(out, "w"), indent=1, default=float)
    print(json.dumps({k: v for k, v in res.items() if k not in ("schedule_hour_profile",)}, indent=1,
                     default=float)[:3000])
