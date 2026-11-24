"""G10b: per-type wrongful closures of the round-3 models (repeated GRPO runs, KL variant, longer supervised tuning),
on the held-out attack types and on the familiar types of the test worlds, for the same models.

    python -m bench.g10_round3
"""
from __future__ import annotations

import json
from collections import defaultdict

IN = "experiments/results/G10_round3.json"
OUT = "experiments/results/G10_round3_by_type.json"
SECOND_BATCH = {"b4_replication_spike", "bigtable_full_scan", "breakglass_no_incident", "endpoint_beaconing",
                "impossible_travel", "priority_quota_abuse", "review_bypass", "spanner_bulk_export",
                "titan_measurement_mismatch", "tpu_unusual_checkpoint_load"}


def parse(text: str):
    try:
        v = json.loads(text[text.index("{"):text.rindex("}") + 1])
        verdict = v.get("verdict")
        if verdict not in ("malicious", "benign", "needs_review"):
            return None
        return verdict, float(v.get("confidence", 0) or 0)
    except (ValueError, TypeError, AttributeError):
        return None


def closed(text: str) -> bool:
    p = parse(text)
    return p is not None and p[0] == "benign" and p[1] >= 0.7


def main():
    res = json.load(open(IN, encoding="utf-8"))
    rows = {f: [json.loads(x) for x in open(f"experiments/g10/{f}.jsonl", encoding="utf-8")] for f in ("unseen", "test")}
    out = {"train": res.get("train", {}), "models": {}}
    for key, ev in res["evals"].items():
        model, split = key.split("|")
        texts = ev["texts"]
        rs = rows[split]
        assert len(rs) == len(texts), (key, len(rs), len(texts))
        by_type = defaultdict(lambda: [0, 0])
        fam = {"familiar": [0, 0], "held_out": [0, 0]}
        fp = [0, 0]
        confs = defaultdict(int)
        for r, t in zip(rs, texts):
            p = parse(t)
            if p:
                confs[round(p[1], 2)] += 1
            if r["kind"] == "anomaly":
                c = closed(t)
                by_type[r["anomaly_type"]][0] += c
                by_type[r["anomaly_type"]][1] += 1
                g = "held_out" if r["anomaly_type"] in SECOND_BATCH else "familiar"
                fam[g][0] += c
                fam[g][1] += 1
            else:
                fp[0] += closed(t)
                fp[1] += 1
        m = out["models"].setdefault(model, {})
        m[split] = {"attack_alerts_closed": {g: f"{h}/{n}" for g, (h, n) in fam.items() if n},
                    "attack_alerts_closed_rate": {g: round(h / n, 3) for g, (h, n) in fam.items() if n},
                    "fp_closed": round(fp[0] / max(fp[1], 1), 3),
                    "by_type": {t: f"{h}/{n}" for t, (h, n) in sorted(by_type.items())},
                    "confidence_values": dict(sorted(confs.items())),
                    "invalid": ev.get("invalid_json"), "hallucinated_evidence": ev.get("hallucinated_evidence")}
    json.dump(out, open(OUT, "w", encoding="utf-8"), indent=1)
    for model, m in out["models"].items():
        u, t = m.get("unseen", {}), m.get("test", {})
        print(f"{model:10s} held-out (unseen file) {u.get('attack_alerts_closed')} | test file: "
              f"{t.get('attack_alerts_closed')} | FP closed {u.get('fp_closed')} / {t.get('fp_closed')} | conf {t.get('confidence_values')}")
        print("           by type (unseen):", u.get("by_type"))
    return out


if __name__ == "__main__":
    main()
