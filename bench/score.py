"""Scoring against loggen's ground truth.

An alert is a true positive if its evidence touches an anomaly case, a "look-alike" false
positive if it touches a benign case (incident response, SRE session, service launch...), and a
plain false positive otherwise. A case is detected when any alert touches one of its events;
time to detect = when that alert was available - the case's first event.
"""
from __future__ import annotations

import math
from array import array
from collections import Counter, defaultdict

FAMILY = {
    "off_hours_access": "ueba", "first_seen_device": "ueba", "fast_approval": "ueba",
    "new_rpc_edge": "nhi", "egress_shift": "nhi", "unverified_build": "nhi",
    "rare_binary": "runtime",
    "endpoint_beaconing": "runtime", "titan_measurement_mismatch": "runtime",
    "impossible_travel": "ueba", "review_bypass": "ueba", "breakglass_no_incident": "ueba",
    "priority_quota_abuse": "ueba", "tpu_unusual_checkpoint_load": "ueba",
    "spanner_bulk_export": "nhi", "bigtable_full_scan": "nhi", "b4_replication_spike": "nhi",
}


def family(case: dict) -> str:
    t = case["anomaly_type"]
    if t.startswith("ebpf_"):
        return "runtime"
    if t == "read_volume_spike":
        return "ueba" if case["entities"].get("principal", "").startswith("user:") else "nhi"
    return FAMILY.get(t, "other")


def pct(values, q):
    if not values:
        return None
    v = sorted(values)
    return v[min(len(v) - 1, int(q * len(v)))]


def score(run, alerts: list, *, eval_from: float | None = None, batch_s: float | None = None) -> dict:
    """batch_s (C4): alerts only become available at batch boundaries, as in a micro-batch or
    hourly batch job, instead of when the event is processed."""
    t0 = eval_from if eval_from is not None else run.start

    def td(a):
        if not batch_s:
            return a.t_detect
        return run.start + math.ceil((a.t_detect - run.start) / batch_s) * batch_s

    days = max((run.end - t0) / 86400, 1e-9)
    cases = [c for c in run.cases if c["_first"] >= t0]
    case_ids = {c["case_id"] for c in cases}
    alerts = [a for a in alerts if td(a) >= t0]

    kinds = Counter()
    fp_rules = Counter()
    lookalike_by_type = Counter()
    benign_type = {c["case_id"]: c["benign_type"] for c in run.benign}
    first_hit: dict[str, float] = {}
    seen_evidence: dict[str, set] = defaultdict(set)
    labels = []  # (score, is_tp) for the precision/recall curve
    for a in alerts:
        hits = {run.by_event.get(e) for e in a.evidence} - {None}
        anomaly = {cid for cid, k in hits if k == "anomaly" and cid in case_ids}
        if anomaly:
            kinds["tp"] += 1
            for cid in anomaly:
                seen_evidence[cid].update(a.evidence)
                if cid not in first_hit or td(a) < first_hit[cid]:
                    first_hit[cid] = td(a)
        elif any(k == "benign" for _, k in hits):
            kinds["fp_lookalike"] += 1
            for cid, k in hits:
                if k == "benign":
                    lookalike_by_type[benign_type.get(cid, "?")] += 1
        else:
            kinds["fp"] += 1
            fp_rules[a.rule] += 1
        labels.append((a.score, bool(anomaly)))

    ttd = {c["case_id"]: first_hit[c["case_id"]] - c["_first"] for c in cases if c["case_id"] in first_hit}
    by_family = defaultdict(lambda: [0, 0])
    by_type = defaultdict(lambda: [0, 0])
    for c in cases:
        hit = c["case_id"] in first_hit
        by_family[family(c)][0] += hit
        by_family[family(c)][1] += 1
        by_type[c["anomaly_type"]][0] += hit
        by_type[c["anomaly_type"]][1] += 1
    bundles = defaultdict(list)
    for c in cases:
        if c.get("bundle"):
            bundles[c["bundle"]].append(c["case_id"] in first_hit)

    n_alerts = len(alerts)
    fp_total = kinds["fp"] + kinds["fp_lookalike"]
    # F5: share of each detected case's events that its alerts actually point to.
    completeness = [len(seen_evidence[c["case_id"]] & {e["event_id"] for e in c["events"]}) / len(c["events"])
                    for c in cases if c["case_id"] in first_hit and c["events"]]
    # H3: ATT&CK techniques covered.
    techs_all = {t for c in cases for t in c.get("mitre", [])}
    techs_hit = {t for c in cases if c["case_id"] in first_hit for t in c.get("mitre", [])}
    # E3: calibration of scores read as probabilities.
    brier = round(sum((min(max(s, 0.0), 1.0) - y) ** 2 for s, y in labels) / len(labels), 4) if labels else None
    bins = [[0, 0] for _ in range(10)]
    for s, y in labels:
        b = bins[min(9, int(min(max(s, 0.0), 1.0) * 10))]
        b[0] += 1
        b[1] += y
    reliability = [{"bin": f"{i / 10:.1f}-{(i + 1) / 10:.1f}", "alerts": n, "anomaly_rate": round(k / n, 3) if n else None}
                   for i, (n, k) in enumerate(bins)]
    extra = {"evidence_completeness": round(sum(completeness) / len(completeness), 3) if completeness else None,
             "attack_coverage": f"{len(techs_hit)}/{len(techs_all)}", "attack_missed": sorted(techs_all - techs_hit),
             "brier": brier, "reliability": reliability, "batch_s": batch_s}
    return {**extra,
        "alerts": n_alerts, "alerts_per_day": round(n_alerts / days, 1),
        "precision": round(kinds["tp"] / n_alerts, 4) if n_alerts else None,
        "fp_per_day": round(fp_total / days, 1), "fp_lookalike_per_day": round(kinds["fp_lookalike"] / days, 1),
        "fp_lookalike_by_type": dict(lookalike_by_type),
        "fp_per_day_by_rule": {k: round(v / days, 1) for k, v in fp_rules.most_common(8)},
        "cases": len(cases), "recall": round(len(first_hit) / len(cases), 4) if cases else None,
        "recall_by_family": {f: round(h / n, 3) for f, (h, n) in sorted(by_family.items())},
        "recall_by_type": {t: f"{h}/{n}" for t, (h, n) in sorted(by_type.items())},
        "bundles": len(bundles), "bundle_recall": round(sum(any(v) for v in bundles.values()) / len(bundles), 3)
        if bundles else None,
        "ttd_s": {"p50": _r(pct(list(ttd.values()), 0.5)), "p95": _r(pct(list(ttd.values()), 0.95))},
        "average_precision": _average_precision(labels),
        "recall_at_fp_per_day": _recall_at_budget(run, alerts, cases, days),
    }


def _r(x):
    return None if x is None else round(x, 1)


def _average_precision(labels):
    pos = sum(1 for _, y in labels if y)
    if not pos:
        return None
    tp = ap = 0.0
    for i, (_, y) in enumerate(sorted(labels, key=lambda x: -x[0]), 1):
        if y:
            tp += 1
            ap += tp / i
    return round(ap / pos, 4)


def _recall_at_budget(run, alerts, cases, days, budgets=(1, 10, 100)):
    """Case recall when only the top-scored alerts fit in a daily false-positive budget."""
    if not cases:
        return {}
    case_ids = {c["case_id"] for c in cases}
    ranked = sorted(alerts, key=lambda a: -a.score)
    out = {}
    for b in budgets:
        fp, found = 0, set()
        for a in ranked:
            hit = {cid for cid, k in ({run.by_event.get(e) for e in a.evidence} - {None})
                   if k == "anomaly" and cid in case_ids}
            if hit:
                found |= hit
            else:
                fp += 1
                if fp / days > b:
                    break
        out[f"{b}/day"] = round(len(found) / len(cases), 3)
    return out


def _np(values):
    import numpy as np
    if isinstance(values, array):
        dt = np.float32 if values.typecode == "f" else np.float64
        return np.frombuffer(values, dtype=dt).astype(np.float64) if len(values) else np.empty(0)
    return np.asarray(values, dtype=np.float64)


def _pcts(a, qs) -> list:
    """Same nearest-rank definition as pct(), in numpy with one partition: a full LANL replay is ~1e9
    events, which sorted() would turn into ~35 GB of Python floats."""
    import numpy as np
    if not a.size:
        return [None] * len(qs)
    ks = [min(a.size - 1, int(q * a.size)) for q in qs]
    part = np.partition(a, sorted(set(ks)))
    return [float(part[k]) for k in ks]


def latency(timing) -> dict:
    lat, q = _np(timing.lat), _np(timing.queue)
    p50, p95, p99 = _pcts(lat, (0.5, 0.95, 0.99))
    d50, d99 = _pcts(q, (0.5, 0.99))
    total = float(lat.sum())
    us = lambda v: None if v is None else _r(v * 1e6)
    return {"per_event_us": {"p50": us(p50), "p95": us(p95), "p99": us(p99),
                             "max": us(float(lat.max())) if lat.size else None},
            "throughput_eps": int(lat.size / total) if total else None,
            "detection_delay_s": {"p50": _r(d50), "p99": _r(d99)},
            "overload": {"dropped": getattr(timing, "dropped", 0),
                         "dropped_share": round(getattr(timing, "dropped", 0) / max(lat.size + getattr(timing, "dropped", 0), 1), 4),
                         "peak_backlog_s": _r(getattr(timing, "peak_backlog_s", 0.0)),
                         "peak_backlog_events": getattr(timing, "peak_backlog_events", 0)}}
