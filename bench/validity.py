"""Validity analyses (A2, A4).

    python -m bench.validity a2 <loggen run dir>        # shortcut audit
    python -m bench.validity a4 [experiments/results/suite_core.json]

A2  Can a plain logistic regression tell anomalous events from normal ones using features that should not
    carry the answer? Families: "schema" (which fields are present, no values), "timing" (millisecond
    fraction, gap to the previous event of the same source), "id" (event_id characters), and "content"
    (field values, the legitimate upper bound). Trained on the first half of the run, tested on the second.
A4  Rules (P0, P1) were frozen before the second batch of anomaly types was written: recall on the first
    batch vs the second batch measures generalisation to threats the detector was not written for.
"""
from __future__ import annotations

import json
import math
import sys
from collections import defaultdict

FIRST_BATCH = {"read_volume_spike", "new_rpc_edge", "off_hours_access", "first_seen_device", "unverified_build",
               "egress_shift", "rare_binary", "fast_approval", "ebpf_shell_in_container", "ebpf_namespace_escape",
               "ebpf_sensitive_read", "ebpf_kernel_module", "ebpf_ptrace_attach", "ebpf_bpf_load", "ebpf_memfd_exec",
               "ebpf_unexpected_connect"}


def _tokens(ev: dict, family: str, prev_gap: float) -> list[str]:
    p = ev["payload"]
    if family == "schema":
        return [f"src={ev['log_source']}", "top=" + ",".join(sorted(k for k in ev if k not in ("payload",))),
                "payload=" + ",".join(sorted(p))] + [f"has={ev['log_source']}:{k}" for k in p]
    if family == "timing":
        ms = int(ev["ts"][20:23]) if len(ev["ts"]) > 23 else 0
        return [f"ms10={ms // 100}", f"gap={int(math.log10(prev_gap + 1e-3) * 2)}", f"src={ev['log_source']}"]
    if family == "id":
        return [f"c{i}={ch}" for i, ch in enumerate(ev["event_id"][:6])]
    # content: action, outcome and payload values (strings and coarse numbers)
    toks = [f"src={ev['log_source']}", f"act={ev['action']}", f"out={ev.get('outcome')}"]
    for k, v in p.items():
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            toks.append(f"{k}~{int(math.log10(abs(v) + 1))}")
        elif isinstance(v, (str, bool)) or v is None:
            toks.append(f"{k}={str(v)[:60]}")
        elif isinstance(v, list):
            toks += [f"{k}[]={str(x)[:40]}" for x in v[:5]]
    return toks


def a2(run_dir: str) -> dict:
    from sklearn.feature_extraction import FeatureHasher
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import roc_auc_score

    from .core import Run
    run = Run.load(run_dir)
    mid = (run.start + run.end) / 2
    case_type = {c["case_id"]: c["anomaly_type"] for c in run.cases}
    data = {f: ([], [], [], []) for f in ("schema", "timing", "id", "content")}  # train X, train y, test X, test y
    test_types = []
    last = {}
    for ev in run.events():
        gap = max(ev["_t"] - last.get(ev["log_source"], ev["_t"]), 0.0)
        last[ev["log_source"]] = ev["_t"]
        lab = run.by_event.get(ev["event_id"])
        y = int(bool(lab) and lab[1] == "anomaly")
        train = ev["_t"] < mid
        if not train:
            test_types.append(case_type.get(lab[0]) if y else None)
        for f, (xtr, ytr, xte, yte) in data.items():
            (xtr if train else xte).append(_tokens(ev, f, gap))
            (ytr if train else yte).append(y)
    out = {"events": len(test_types) + len(data["id"][0]), "anomalous_test_events": sum(1 for t in test_types if t)}
    for f, (xtr, ytr, xte, yte) in data.items():
        h = FeatureHasher(n_features=2 ** 20, input_type="string")
        clf = LogisticRegression(max_iter=300, class_weight="balanced", C=1.0)
        clf.fit(h.transform(xtr), ytr)
        p = clf.predict_proba(h.transform(xte))[:, 1]
        res = {"auc": round(float(roc_auc_score(yte, p)), 4)}
        if f in ("schema", "content"):
            per = defaultdict(list)
            neg = [s for s, y in zip(p, yte) if not y]
            for s, t in zip(p, test_types):
                if t:
                    per[t].append(s)
            res["auc_by_type"] = {t: round(float(roc_auc_score([1] * len(v) + [0] * len(neg), list(v) + neg)), 3)
                                  for t, v in sorted(per.items())}
        out[f] = res
    return out


def a4(path: str = "experiments/results/suite_core.json") -> dict:
    rows = [r for r in json.load(open(path, encoding="utf-8")) if r["condition"] == "base"]
    out = {}
    for pipe in dict.fromkeys(r["pipeline"] for r in rows):
        hits = {"first_batch": [0, 0], "second_batch": [0, 0]}
        for r in rows:
            if r["pipeline"] != pipe:
                continue
            for t, frac in r["recall_by_type"].items():
                h, n = map(int, frac.split("/"))
                key = "first_batch" if t in FIRST_BATCH else "second_batch"
                hits[key][0] += h
                hits[key][1] += n
        out[pipe] = {k: round(h / n, 3) if n else None for k, (h, n) in hits.items()}
        out[pipe]["drop"] = round(out[pipe]["first_batch"] - out[pipe]["second_batch"], 3) \
            if None not in (out[pipe]["first_batch"], out[pipe]["second_batch"]) else None
    return out


if __name__ == "__main__":
    if sys.argv[1] == "a2":
        res = a2(sys.argv[2])
        json.dump(res, open("experiments/results/A2_shortcut_audit.json", "w"), indent=1)
    else:
        res = a4(*(sys.argv[2:3] or []))
        json.dump(res, open("experiments/results/A4_unseen_types.json", "w"), indent=1)
    print(json.dumps(res, indent=1))
