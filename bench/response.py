"""I1 / I2: time to contain and collateral damage of automatic response, from the LLM decision logs.

    python -m bench.response <bench result json> <loggen run dir> [pipeline=P8]

Policies, applied to every alert the fusion engine raised (the LLM decision log lists them all):
  human_all          every alert goes to a human, who contains it after a modeled delay
  llm_auto           LLM "malicious" with confidence >= 0.8 -> automatic action; LLM "benign" closes the alert;
                     anything else -> human
  llm_auto_strict    automatic only at confidence >= 0.95 (a harness-style restriction); else as above
Modeled (not measured) delays: automatic action 2 s (credential revocation / task kill / endpoint quarantine
through APIs); human review lognormal, median 30 min, 95th percentile 4 h.
Measured on the ground truth: time to contain per anomaly case (first event -> first containment), cases
never contained, wrongful automatic actions per day (on alerts with no anomaly event), human reviews per day.
"""
from __future__ import annotations

import json
import math
import random
import sys

from .core import Run

AUTO_S = 2.0
HUMAN_MEDIAN_S, HUMAN_P95_S = 1800.0, 4 * 3600.0


def _human_delay(rng: random.Random) -> float:
    sigma = math.log(HUMAN_P95_S / HUMAN_MEDIAN_S) / 1.645
    return rng.lognormvariate(math.log(HUMAN_MEDIAN_S), sigma)


def simulate(result: dict, run: Run, pipeline: str = "P8", seed: int = 0, eval_from_h: float = 12.0) -> dict:
    decisions = result["pipelines"][pipeline]["llm_decisions"]
    t0 = run.start + eval_from_h * 3600
    days = (run.end - t0) / 86400
    cases = [c for c in run.cases if c["_first"] >= t0]
    out = {}
    for policy in ("human_all", "llm_auto", "llm_auto_strict"):
        rng = random.Random(seed)
        contained: dict[str, float] = {}
        wrongful_auto = auto = human = 0
        for d in decisions:
            if d["t"] < t0:
                continue
            hit = {run.by_event[e][0] for e in d["evidence"] if e in run.by_event and run.by_event[e][1] == "anomaly"}
            conf = d.get("confidence") or 0.0
            if policy == "human_all":
                when, kind = d["t"] + _human_delay(rng), "human"
            elif d["verdict"] == "malicious" and conf >= (0.8 if policy == "llm_auto" else 0.95):
                when, kind = d["t"] + d.get("latency_s", 0.0) + AUTO_S, "auto"
            elif d.get("suppressed"):
                continue
            else:
                when, kind = d["t"] + d.get("latency_s", 0.0) + _human_delay(rng), "human"
            if kind == "auto":
                auto += 1
                wrongful_auto += not hit
            else:
                human += 1
            for cid in hit:
                contained[cid] = min(contained.get(cid, when), when)
        ttc = sorted(contained[c["case_id"]] - c["_first"] for c in cases if c["case_id"] in contained)
        q = lambda p: round(ttc[min(len(ttc) - 1, int(p * len(ttc)))] / 60, 1) if ttc else None  # noqa: E731
        out[policy] = {"cases": len(cases), "contained": len(ttc), "never_contained": len(cases) - len(ttc),
                       "ttc_min_p50": q(0.5), "ttc_min_p95": q(0.95), "auto_actions_per_day": round(auto / days, 1),
                       "wrongful_auto_actions_per_day": round(wrongful_auto / days, 2),
                       "human_reviews_per_day": round(human / days, 1)}
    return out


if __name__ == "__main__":
    res = json.load(open(sys.argv[1], encoding="utf-8"))
    run = Run.load(sys.argv[2])
    pipes = sys.argv[3].split(",") if len(sys.argv) > 3 else [p for p, m in res["pipelines"].items()
                                                                if m.get("llm_decisions")]
    report = {p: simulate(res, run, p) for p in pipes}
    json.dump(report, open(sys.argv[1].replace(".json", "_response.json"), "w"), indent=1)
    print(json.dumps(report, indent=1))
