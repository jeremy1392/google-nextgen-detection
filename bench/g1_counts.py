"""G1 reconciliation: which population each G1 counter refers to.

The triage model of G1 (P8: rarity-weighted fusion, then Gemini on every fused alert) is called on every fused alert,
warm-up included, and judges an alert "on attack events" when the events SHOWN to it (the last 25 of its evidence)
include an event of any attack case. The scorer counts only alerts available after the warm-up, and a true positive
only when one of the alert's events belongs to an attack case that STARTS after the warm-up. This module counts each
population on the G-series world (seed 7, 2 days, injected text).

    python -m bench.g1_counts
"""
from __future__ import annotations

import json

WORLD = "experiments/cache_g11/s7_inject10"
G = "experiments/results/G_series_v5_2d.json"


def main():
    from loggen.engine import parse_duration

    from .core import Run, replay
    from .detectors.fusion import Fusion
    run = Run.load(WORLD)
    eval_from = run.start + parse_duration("12h")
    days = (run.end - eval_from) / 86400
    scored_cases = {c["case_id"] for c in run.cases if c["_first"] >= eval_from}
    all_cases = {c["case_id"] for c in run.cases}

    d = Fusion(rarity="hyper")
    d.name = "P6-hyper"
    alerts, _ = replay(run, [d])
    fused = alerts["P6-hyper"]
    after = [a for a in fused if a.t_detect >= eval_from]

    def kinds(ev_ids, scope):
        return {cid for cid, k in ({run.by_event.get(e) for e in ev_ids} - {None}) if k == "anomaly" and cid in scope}

    tp = [a for a in after if kinds(a.evidence, scored_cases)]
    pre_attack_only = [a for a in after if not kinds(a.evidence, scored_cases) and kinds(a.evidence, all_cases)]
    out = {
        "world": WORLD, "days_scored": round(days, 3),
        "fused_alerts_total": len(fused), "fused_alerts_during_warmup": len(fused) - len(after),
        "fused_alerts_scored": len(after),
        "scored_true_positives": len(tp), "scored_false_positives": len(after) - len(tp),
        "scored_fp_that_touch_an_attack_started_before_warmup_end": len(pre_attack_only),
        "precision": round(len(tp) / len(after), 4), "fp_per_day": round((len(after) - len(tp)) / days, 1),
        "attack_cases_scored": len(scored_cases),
    }
    g = json.load(open(G, encoding="utf-8"))["pipelines"]
    for name in ("P8", "P8-harness", "P8-g4", "P9-g4", "P8-agent-g4"):
        dec = g[name]["llm_decisions"]
        evf = lambda x: x["evidence"]
        out[name] = {
            "model_calls": len(dec),
            "calls_during_warmup": sum(1 for x in dec if x["t"] < eval_from),
            "calls_shown_any_attack_event": sum(1 for x in dec if kinds(evf(x), all_cases)),
            "calls_shown_scored_attack_event": sum(1 for x in dec if kinds(evf(x), scored_cases)),
            "calls_after_warmup": sum(1 for x in dec if x["t"] >= eval_from),
            "calls_after_warmup_positive_for_scorer": sum(1 for x in dec if x["t"] >= eval_from and kinds(evf(x), scored_cases)),
            "positive_alerts_closed_any_attack": sum(1 for x in dec if x["suppressed"] and kinds(evf(x), all_cases)),
            "positive_alerts_closed_after_warmup_scored": sum(1 for x in dec if x["suppressed"] and x["t"] >= eval_from
                                                              and kinds(evf(x), scored_cases)),
        }
    json.dump(out, open("experiments/results/G1_counts.json", "w", encoding="utf-8"), indent=1)
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
