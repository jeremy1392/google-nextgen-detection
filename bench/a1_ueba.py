"""A1, human side: does the generator's user behaviour have the shape of real enterprise data?

Same statistics over three sources of "a person acts from a machine" events:
  generator  bc.uberproxy requests (principal, device), local time from the run's tz offset
  LANL 2015  auth.txt, user accounts only (U*@DOM*), source computer; the start time and weekday of the
             data are not published, so the hour profile is compared at the circular shift that best
             matches, and the weekend is taken as the two consecutive quietest days of the week
  CERT r4.2  logon.csv (Logon rows), pc; local time as given. CERT is itself synthetic (CMU's generator):
             it is a second reference, not ground truth.

Statistics: weekday hour-of-day profile, weekend / weekday activity ratio, distinct machines per active
user-day, distinct active hours per user-day, Gini of total activity across users. Compared with the
Jensen-Shannon distance (hour profile) and the Kolmogorov-Smirnov distance (per user-day distributions).

    python -m bench.a1_ueba generator <run_dir> --out stats_generator.json
    (LANL and CERT run on Modal: modal run modal_apps/a5_external.py::ueba)
    python -m bench.a1_ueba compare stats_generator.json stats_lanl.json stats_cert.json --out A1_ueba.json
"""
from __future__ import annotations

import argparse
import json
import math
import os
from collections import Counter, defaultdict


class Acc:
    """Streaming accumulator over (hour, day, weekday, user, machine) events. weekday=None: unknown, the
    weekend is then inferred as the two consecutive quietest days of the 7-day cycle."""

    def __init__(self):
        self.day_hour = Counter()
        self.weekday_of = {}
        self.user_day_hosts = defaultdict(set)
        self.user_day_hours = defaultdict(set)
        self.user_total = Counter()
        self.events = 0

    def add(self, hour: int, day: int, weekday: int | None, user: str, machine: str) -> None:
        self.events += 1
        self.day_hour[(day, hour)] += 1
        self.weekday_of[day] = weekday
        self.user_day_hosts[(user, day)].add(machine)
        self.user_day_hours[(user, day)].add(hour)
        self.user_total[user] += 1

    def stats(self) -> dict:
        by_day = Counter()
        for (d, _), n in self.day_hour.items():
            by_day[d] += n
        inferred = None
        if any(v is None for v in self.weekday_of.values()):
            phase = Counter()
            for d, n in by_day.items():
                phase[d % 7] += n
            q = min(range(7), key=lambda k: phase[k] + phase[(k + 1) % 7])
            weekday = lambda d: 5 if d % 7 == q else 6 if d % 7 == (q + 1) % 7 else 0
            inferred = q
        else:
            weekday = lambda d: self.weekday_of[d]
        prof = Counter()
        for (d, h), n in self.day_hour.items():
            if weekday(d) < 5:
                prof[h] += n
        tot = sum(prof.values()) or 1
        wd = [n for d, n in by_day.items() if weekday(d) < 5]
        we = [n for d, n in by_day.items() if weekday(d) >= 5]
        hosts = Counter(min(len(v), 6) for v in self.user_day_hosts.values())
        hours = Counter(len(v) for v in self.user_day_hours.values())
        vals = sorted(self.user_total.values())
        n, total = len(vals), sum(vals)
        gini = 2 * sum((i + 1) * v for i, v in enumerate(vals)) / (n * total) - (n + 1) / n if n and total else None
        return {"events": self.events, "days": len(by_day), "users": n, "user_days": len(self.user_day_hosts),
                "weekend_inferred_phase": inferred,
                "hour_profile_weekday": [round(prof[h] / tot, 5) for h in range(24)],
                "weekend_over_weekday": round((sum(we) / len(we)) / (sum(wd) / len(wd)), 4) if we and wd else None,
                "machines_per_user_day": {(str(k) if k < 6 else "6+"): v for k, v in sorted(hosts.items())},
                "active_hours_per_user_day": {str(k): v for k, v in sorted(hours.items())},
                "gini_activity_across_users": round(gini, 4) if gini is not None else None}


def lanl_stats(path: str, days: int = 14) -> dict:
    """LANL auth.txt.gz, user accounts only, first `days` days. Pass 1 finds the quietest hour of the raw
    clock, which becomes the day boundary (hour 0) of pass 2: the data's real start time is not published."""
    import gzip
    limit = days * 86400
    raw = Counter()
    with gzip.open(path, "rt") as f:
        for line in f:
            t = int(line[:line.index(",")])
            if t >= limit:
                break
            if line[line.index(",") + 1] == "U":
                raw[t // 3600 % 24] += 1
    h0 = min(range(24), key=lambda h: raw[h])
    acc = Acc()
    with gzip.open(path, "rt") as f:
        for line in f:
            p = line.split(",", 5)
            t = int(p[0])
            if t >= limit:
                break
            if not p[1].startswith("U"):
                continue
            s = t - h0 * 3600
            acc.add(int(s % 86400 // 3600), int(s // 86400), None, p[1].split("@")[0], p[3])
    return {"source": "lanl_2015", "days_read": days, "day_boundary_raw_hour": h0, **acc.stats()}


def cert_stats(path: str, kind: str = "logon") -> dict:
    """CERT r4.2: logon.csv (Logon rows: one or two per user-day) or http.csv (web requests all day long,
    the closer match to the generator's access-proxy requests). user, pc, local time."""
    import csv
    from datetime import datetime
    acc = Acc()
    with open(path, encoding="utf-8", errors="replace") as f:
        for r in csv.reader(f):
            if r[0] == "id" or len(r) < 4:
                continue
            if kind == "logon" and r[4].strip() != "Logon":
                continue
            dt = datetime.strptime(r[1], "%m/%d/%Y %H:%M:%S")
            acc.add(dt.hour, dt.toordinal(), dt.weekday(), r[2], r[3])
    return {"source": f"cert_r4.2_{kind}", **acc.stats()}


def generator_stats(run_dir: str) -> dict:
    m = json.load(open(os.path.join(run_dir, "manifest.json"), encoding="utf-8"))
    tz = m.get("tz_offset_h", 1.0) * 3600
    from .core import epoch
    acc = Acc()
    with open(os.path.join(run_dir, "logs", "bc.uberproxy.jsonl"), encoding="utf-8") as f:
        for line in f:
            e = json.loads(line)
            p = e.get("principal", "")
            if not p.startswith("user:") or not e.get("device_id"):
                continue
            t = epoch(e["ts"]) + tz
            day = int(t // 86400)
            acc.add(int(t % 86400 // 3600), day, (day + 3) % 7, p, e["device_id"])  # day 0 was a Thursday
    return {"source": "generator", "run": run_dir, **acc.stats()}


def _jsd(p: list, q: list) -> float:
    m = [(a + b) / 2 for a, b in zip(p, q)]
    kl = lambda x, y: sum(a * math.log2(a / b) for a, b in zip(x, y) if a > 0 and b > 0)
    return round(math.sqrt(max(0.0, (kl(p, m) + kl(q, m)) / 2)), 4)


def _best_shift(p: list, q: list) -> tuple[int, float]:
    return min(((s, _jsd(p, q[s:] + q[:s])) for s in range(24)), key=lambda x: x[1])


def _ks(a: dict, b: dict) -> float:
    keys = sorted(set(a) | set(b), key=lambda k: float(k.rstrip("+")))
    ta, tb = sum(a.values()) or 1, sum(b.values()) or 1
    ca = cb = d = 0.0
    for k in keys:
        ca += a.get(k, 0) / ta
        cb += b.get(k, 0) / tb
        d = max(d, abs(ca - cb))
    return round(d, 4)


def compare(gen: dict, refs: list[dict]) -> dict:
    out = {"generator": gen, "references": {}}
    for r in refs:
        name = r["source"]
        shift, jsd_best = _best_shift(gen["hour_profile_weekday"], r["hour_profile_weekday"])
        out["references"][name] = {
            "stats": r,
            "hour_profile_jsd": _jsd(gen["hour_profile_weekday"], r["hour_profile_weekday"]),
            "hour_profile_jsd_best_shift": jsd_best, "best_shift_h": shift,
            "weekend_ratio": {"generator": gen["weekend_over_weekday"], name: r["weekend_over_weekday"]},
            "machines_per_user_day_ks": _ks(gen["machines_per_user_day"], r["machines_per_user_day"]),
            "active_hours_per_user_day_ks": _ks(gen["active_hours_per_user_day"], r["active_hours_per_user_day"]),
            "gini": {"generator": gen["gini_activity_across_users"], name: r["gini_activity_across_users"]}}
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="bench.a1_ueba")
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generator")
    g.add_argument("run")
    g.add_argument("--out", required=True)
    c = sub.add_parser("compare")
    c.add_argument("generator")
    c.add_argument("refs", nargs="+")
    c.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    if a.cmd == "generator":
        res = generator_stats(a.run)
    else:
        res = compare(json.load(open(a.generator)), [json.load(open(x)) for x in a.refs])
    json.dump(res, open(a.out, "w", encoding="utf-8"), indent=1)
    print(json.dumps(res if a.cmd == "generator" else {k: {kk: vv for kk, vv in v.items() if kk != "stats"}
                                                         for k, v in res["references"].items()}, indent=1)[:3000])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
