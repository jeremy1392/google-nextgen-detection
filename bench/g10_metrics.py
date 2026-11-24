"""G10 metrics and the API baseline on the same test cases (verbatim copy of parse / reward / metrics from
modal_apps/g10_rlvr.py, so that the local fine-tuned model and the API model are scored identically).

    python -m bench.g10_metrics api [--model google/gemini-3.1-flash-lite-preview] [--budget 0.4]
    -> experiments/results/G10_api_<name>.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor


def parse(text: str):
    try:
        v = json.loads(text[text.index("{"):text.rindex("}") + 1])
        verdict = v.get("verdict")
        if verdict not in ("malicious", "benign", "needs_review"):
            return None
        conf = float(v.get("confidence", 0) or 0)
        ev = [str(x) for x in (v.get("evidence") or [])][:50]
        return verdict, conf, ev
    except (ValueError, TypeError, AttributeError):
        return None


def reward(text: str, row: dict) -> float:
    p = parse(text)
    if p is None:
        return -1.0
    verdict, conf, cited = p
    attack = row["kind"] == "anomaly"
    r = ({"malicious": 1.0, "needs_review": 0.5, "benign": -1.0} if attack else
         {"benign": 1.0, "needs_review": 0.0, "malicious": -0.5})[verdict]
    cited_set = set(cited)
    if cited_set:
        r -= len(cited_set - set(row["shown_event_ids"])) / len(cited_set)
        if attack:
            r += 0.5 * len(cited_set & set(row["case_event_ids"])) / len(cited_set)
    return r


def target(row: dict) -> str:
    attack = row["kind"] == "anomaly"
    return json.dumps({"verdict": "malicious" if attack else "benign", "confidence": 0.9,
                       "evidence": row["case_event_ids"][:10] if attack else [],
                       "summary": ("The events match an attack pattern; escalate to an analyst." if attack else
                                   "The activity is consistent with legitimate operations.")})


def metrics(rows, texts, latencies=None) -> dict:
    out = {"cases": len(rows)}
    att = [(r, t) for r, t in zip(rows, texts) if r["kind"] == "anomaly"]
    ben = [(r, t) for r, t in zip(rows, texts) if r["kind"] != "anomaly"]
    closed = lambda t: (lambda p: p is not None and p[0] == "benign" and p[1] >= 0.7)(parse(t))
    out["attack_cases"], out["fp_cases"] = len(att), len(ben)
    out["attacks_wrongly_closed"] = round(sum(closed(t) for _, t in att) / max(len(att), 1), 4)
    out["fp_closed"] = round(sum(closed(t) for _, t in ben) / max(len(ben), 1), 4)
    out["invalid_json"] = round(sum(parse(t) is None for t in texts) / max(len(texts), 1), 4)
    cited = [(r, set(parse(t)[2])) for r, t in zip(rows, texts) if parse(t) is not None]
    allc = sum(len(c) for _, c in cited)
    out["hallucinated_evidence"] = round(sum(len(c - set(r["shown_event_ids"])) for r, c in cited) / max(allc, 1), 4)
    ac = [(r, c) for r, c in cited if r["kind"] == "anomaly" and c]
    out["attack_evidence_precision"] = round(sum(len(c & set(r["case_event_ids"])) / len(c) for r, c in ac)
                                             / max(len(ac), 1), 4)
    out["mean_reward"] = round(sum(reward(t, r) for r, t in zip(rows, texts)) / max(len(rows), 1), 4)
    if latencies:
        s = sorted(latencies)
        out["latency_s"] = {"p50": round(s[len(s) // 2], 3), "p95": round(s[int(len(s) * 0.95)], 3)}
    return out




def api(model: str, budget: float, workers: int = 8) -> dict:
    from . import llm
    rows = [json.loads(x) for x in open("experiments/g10/test.jsonl", encoding="utf-8")]
    spent = [0.0]

    def one(r):
        if spent[0] > budget:
            return "", 0.0, 0.0
        res = llm.chat(model, [{"role": "system", "content": r["system"]}, {"role": "user", "content": r["user"]}],
                       max_tokens=4096)
        c = float((res["usage"] or {}).get("cost") or 0)
        spent[0] += c
        return res["text"], c, res["total_s"]

    with ThreadPoolExecutor(workers) as pool:
        out = list(pool.map(one, rows))
    texts = [t for t, _, _ in out]
    m = metrics(rows, texts, [s for _, _, s in out if s])
    m.update(model=model, spent_usd=round(sum(c for _, c, _ in out), 4))
    name = model.split("/")[-1]
    json.dump({"metrics": m, "texts": texts}, open(f"experiments/results/G10_api_{name}.json", "w"), indent=1)
    return m


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="bench.g10_metrics")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("api")
    a.add_argument("--model", default="google/gemini-3.1-flash-lite-preview")
    a.add_argument("--budget", type=float, default=0.4)
    x = p.parse_args(argv)
    print(json.dumps(api(x.model, x.budget), indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
