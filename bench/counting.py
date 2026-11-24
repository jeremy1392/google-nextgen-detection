"""Counting units of the recommended pipeline, stage by stage (attack cases, alerts, model calls, dossiers).

For each world and each model at the end of FINAL, the run is replayed with the model's recorded answers, so that the
alerts reaching analysts can be counted, merged into dossiers and traced back to attack cases:

  cases            attack cases after the warm-up
  detected         cases with at least one alert from the detection stage (no model)
  protected        detected cases with an alert the model cannot close (fast path, or risk >= 0.9 under the policy)
  exposed          detected cases whose every alert goes through the model
  calls            model calls, split into alerts on attack events (positive) and false-positive alerts (negative)
  closed           positive and negative alerts the model closed
  lost             detected cases left with no alert after the model
  queue            alerts and dossiers a day reaching analysts (dossiers merge alerts on one entity within 24 h or sharing
                   an evidence event), with how many dossiers touch an attack

Gemini answers are rebuilt from the decisions stored by the original runs, in call order (the calls are deterministic:
the same alerts reach the model in the same order whatever it answers).

    python -m bench.counting
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

X5 = "experiments/cache_g11/s7_inject10"  # seed 7, 2 days, lag, drift, 12 bundles, injected text in 10% of writable fields
WORLDS = {7: X5, 8: "experiments/cache_g11/s8", 9: "experiments/cache_g11/s9"}
GEMINI = {"flash-lite": {7: ("experiments/final/x5_final_flash.json", "FINAL"), 8: ("experiments/final/s8_llm.json", "FINAL"),
                         9: ("experiments/final/s9_llm.json", "FINAL")},
          "Gemini 4": {7: ("experiments/final/x5_final_g4.json", "FINAL-g4"), 8: ("experiments/final/s8_llm.json", "FINAL-g4"),
                       9: ("experiments/final/s9_llm.json", "FINAL-g4")}}
LOCAL = {"local SFT": "experiments/final/local_answers_sft.jsonl", "local SFT+GRPO": "experiments/final/local_answers_grpo.jsonl"}
OUT = "experiments/results/FINAL_counting.json"
DOSSIER_S = 24 * 3600


def _gemini_answers(model: str) -> str:
    """Replay file for a Gemini run: i-th recorded prompt of the world -> i-th decision of the original run."""
    path = f"experiments/final/replay_{model.replace(' ', '_')}.jsonl"
    with open(path, "w", encoding="utf-8") as f:
        for s, (res, name) in GEMINI[model].items():
            keys = [json.loads(x)["key"] for x in open(f"experiments/final/local_prompts_s{s}.jsonl", encoding="utf-8")]
            dec = json.load(open(res, encoding="utf-8"))["pipelines"][name]["llm_decisions"]
            assert len(keys) == len(dec), (model, s, len(keys), len(dec))
            for k, d in zip(keys, dec):
                text = json.dumps({"verdict": d["verdict"], "confidence": d["confidence"], "evidence": d.get("cited", [])})
                if d["verdict"] == "error":
                    text = "unparsable"
                f.write(json.dumps({"key": k, "text": text, "latency_s": d.get("latency_s", 0.0)}) + "\n")
    return path


def one(world: int, answers: str | None) -> dict:
    """Run in a subprocess (the replay cache of bench.llm is per process)."""
    from loggen.engine import parse_duration

    from .core import Run, replay
    from .detectors.llm_triage import GraphCascade
    from .protocol import _dossiers
    run = Run.load(WORLDS[world])
    eval_from = run.start + parse_duration("12h")
    days = (run.end - eval_from) / 86400
    case_ids = {c["case_id"] for c in run.cases if c["_first"] >= eval_from}
    d = GraphCascade(model="local/replay", max_calls=0 if answers is None else 300)
    d.name = "FINAL"
    alerts, _ = replay(run, [d])

    def cases_of(ev_ids):
        return {cid for cid, k in ({run.by_event.get(e) for e in ev_ids} - {None}) if k == "anomaly" and cid in case_ids}

    rows, detected, protected = [], set(), set()
    for a in alerts["FINAL"]:
        if a.t_detect < eval_from:
            continue
        att = cases_of(a.evidence)
        rows.append([a.t_detect - eval_from, a.score, a.entity, sorted(att), list(a.evidence)[-30:]])
        detected |= att
        if a.rule.startswith("fast:") or a.score >= 0.9:
            protected |= att
    calls = [x for x in d.decisions if x["t"] >= eval_from]
    pos = [x for x in calls if cases_of(x["evidence"])]
    doss = _dossiers(rows)
    return {"world": world, "cases": len(case_ids), "detected_after_model": len(detected), "protected": len(protected),
            "calls": len(calls), "calls_positive": len(pos), "calls_negative": len(calls) - len(pos),
            "closed_positive": sum(1 for x in pos if x["suppressed"]),
            "closed_negative": sum(1 for x in calls if x["suppressed"] and not cases_of(x["evidence"])),
            "alerts_per_day": round(len(rows) / days, 1),
            "fp_alerts_per_day": round(sum(1 for r in rows if not r[3]) / days, 1),
            "dossiers_per_day": round(len(doss) / days, 1),
            "attack_dossiers_per_day": round(sum(1 for g in doss if g[2]) / days, 1),
            "fp_dossiers_per_day": round(sum(1 for g in doss if not g[2]) / days, 1)}


def main():
    variants = {"detection stage (no model)": None, "Gemini 4": _gemini_answers("Gemini 4"), **LOCAL}
    out = {}
    for name, answers in variants.items():
        out[name] = []
        for w in WORLDS:
            env = dict(os.environ, PYTHONIOENCODING="utf-8")
            env.pop("BENCH_LLM_RECORD", None)
            if answers:
                env["BENCH_LLM_REPLAY"] = answers
            else:
                env.pop("BENCH_LLM_REPLAY", None)
            code = f"import json; from bench.counting import one; print(json.dumps(one({w}, {answers!r})))"
            r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env, check=True)
            out[name].append(json.loads(r.stdout.strip().splitlines()[-1]))
    base = {r["world"]: r for r in out["detection stage (no model)"]}
    for name, rows in out.items():
        for r in rows:
            r["detected_by_detection_stage"] = base[r["world"]]["detected_after_model"]
            r["exposed"] = base[r["world"]]["detected_after_model"] - base[r["world"]]["protected"]
            r["cases_lost"] = r["detected_by_detection_stage"] - r["detected_after_model"]
    tot = {}
    for name, rows in out.items():
        keys = [k for k in rows[0] if k != "world" and isinstance(rows[0][k], (int, float))]
        tot[name] = {k: (round(sum(r[k] for r in rows) / len(rows), 1) if k.endswith("per_day") else sum(r[k] for r in rows))
                     for k in keys}
    json.dump({"per_world": out, "three_worlds": tot}, open(OUT, "w", encoding="utf-8"), indent=1)
    for name, t in tot.items():
        print(f"{name:28s}", {k: t[k] for k in ("cases", "detected_by_detection_stage", "protected", "exposed", "calls",
                                                "calls_positive", "closed_positive", "closed_negative", "cases_lost",
                                                "alerts_per_day", "dossiers_per_day", "attack_dossiers_per_day",
                                                "fp_dossiers_per_day")})


if __name__ == "__main__":
    main()
