"""C5 and C6: what each stage costs, from measured results (no new measurement here).

    python -m bench.cost funnel   # C6 -> experiments/results/C6_funnel.json
    python -m bench.cost scale    # C5 -> experiments/results/C5_cost_scale.json (needs suite_scale.json)

Prices are Modal's list prices read on 2026-11-24 (https://modal.com/pricing): CPU $0.0000131 per physical
core-second, H100 $0.001097 per GPU-second, L4 $0.000222 per GPU-second. A detector's measured single-thread
time is charged as one full physical core (conservative: a core runs two such threads). LLM costs are the
amounts OpenRouter billed for the G-series runs.
"""
from __future__ import annotations

import argparse
import json
import os
import statistics

RES = "experiments/results"
CPU_CORE_S = 0.0000131
GPU_S = {"H100": 0.001097, "L4": 0.000222}


def _load(name):
    return json.load(open(os.path.join(RES, name), encoding="utf-8"))


def funnel(days: float = 2.0) -> dict:
    """C6, the cascade funnel of P9 on the 2-day G-series run (lag, drift, injected text), two LLMs; then the
    binary path measured in C2 / D2 for the same fleet size."""
    g = _load("G_series_v5_2d.json")
    out = {"source": "G_series_v5_2d.json (2-day run), C2_e2e_local_v2.json, D1_malconv_report.json",
           "prices": {"cpu_core_s": CPU_CORE_S, "gpu_s": GPU_S}, "log_path": {}, "binary_path": {}}
    for pipe in ("P9", "P9-g4"):
        m = g["pipelines"][pipe]
        s = m["llm"]
        ev = s["events"]
        per_ev_s = m["latency"]["per_event_us"]["p50"] * 1e-6
        mean_s = 1.0 / m["latency"]["throughput_eps"]
        stages = [
            {"stage": "events ingested", "per_day": ev / days, "share_of_events": 1.0,
             "latency_p50_s": None},
            {"stage": "detector signals (P0-P2 rules and baselines)", "per_day": s["signals"] / days,
             "share_of_events": s["signals"] / ev, "latency_p50_s": per_ev_s},
            {"stage": "fast path: rare severe signals, alerted without the LLM", "per_day": s["fast_path"] / days,
             "share_of_events": s["fast_path"] / ev, "latency_p50_s": per_ev_s},
            {"stage": "fused alerts sent to the LLM", "per_day": s["fused"] / days,
             "share_of_events": s["fused"] / ev, "latency_p50_s": per_ev_s},
            {"stage": "kept by the LLM (escalated to an analyst)", "per_day": s["kept"] / days,
             "share_of_events": s["kept"] / ev, "latency_p50_s": per_ev_s + s["llm_latency_s"]["p50"],
             "latency_p95_s": per_ev_s + s["llm_latency_s"]["p95"]},
        ]
        compute_day = ev / days * mean_s * CPU_CORE_S
        out["log_path"][pipe] = {
            "model": s["model"], "stages": stages,
            "analyst_alerts_per_day": (s["fast_path"] + s["kept"]) / days,
            "recall": m["recall"], "fp_per_day": m["fp_per_day"],
            "cost_per_day_usd": {"detection_compute": round(compute_day, 6), "llm": round(s["cost_usd"] / days, 4)},
            "llm_cost_per_call_usd": round(s["cost_usd"] / max(s["llm_calls"], 1), 5),
            "detector_mean_s_per_event": mean_s,
        }
    # Binary path: on-host extraction -> MalConv -> sandbox, per 1,000 new binaries
    c2 = _load("C2_e2e_local_v2.json")
    rep = _load("D1_malconv_report.json")

    def at(sweep, thr):
        return next(x for x in sweep if abs(x["threshold"] - thr) < 1e-9)

    known, unseen = at(rep["test"]["sandbox_sweep"], 0.5), at(rep["test_unseen_toolchain"]["sandbox_sweep"], 0.5)
    for gpu in ("L4", "H100"):
        g2 = c2[gpu]
        rows = g2["modes"]["bucketed"]
        ok = [r for r in rows if r["share_under_50ms"] >= 0.99]
        cap = max(r["achieved_files_per_s"] for r in ok) if ok else None
        out["binary_path"][gpu] = {
            "stage1_extraction_ms": g2["stage1_ms"],
            "malconv_bucketed": [{"files_per_s": r["files_per_s"], "total_ms": r["total_ms"],
                                  "share_under_50ms": r["share_under_50ms"], "mean_batch": r["mean_batch"]}
                                 for r in rows],
            "capacity_files_per_s_99pct_under_50ms": cap,
            "gpu_usd_per_million_binaries_at_capacity": round(1e6 / cap * GPU_S[gpu], 2) if cap else None,
        }
    out["binary_path"]["sandbox_share_at_0.5"] = {
        "known_toolchains": {"benign_escalated": known["benign_escalated"], "malware_missed": known["malware_missed"]},
        "unseen_toolchain": {"benign_escalated": unseen["benign_escalated"], "malware_missed": unseen["malware_missed"]},
        "per_1000_new_benign_binaries": {"known": round(1000 * known["benign_escalated"], 2),
                                         "unseen": round(1000 * unseen["benign_escalated"], 1)},
    }
    return out


def scale() -> dict:
    """C5: per-detector throughput and cost per million events at population x1, x2, x5, x10 (3 seeds)."""
    rows = _load("suite_scale.json")
    out = {"prices": {"cpu_core_s": CPU_CORE_S}, "cells": []}
    for v in sorted({r["variant"] for r in rows}):
        for pipe in dict.fromkeys(r["pipeline"] for r in rows):
            sel = [r for r in rows if r["variant"] == v and r["pipeline"] == pipe]
            if not sel:
                continue
            eps = [r["latency"]["throughput_eps"] for r in sel if r["latency"]["throughput_eps"]]
            mean_eps = statistics.mean(eps)
            out["cells"].append({
                "scale": v, "pipeline": pipe, "seeds": len(sel),
                "throughput_eps": round(mean_eps), "per_event_us_p50": statistics.mean(
                    r["latency"]["per_event_us"]["p50"] for r in sel),
                "per_event_us_p99": statistics.mean(r["latency"]["per_event_us"]["p99"] for r in sel),
                "core_s_per_million_events": round(1e6 / mean_eps, 2),
                "usd_per_million_events": round(1e6 / mean_eps * CPU_CORE_S, 7),
                "recall": round(statistics.mean(r["recall"] for r in sel), 3),
                "fp_per_day": round(statistics.mean(r["fp_per_day"] for r in sel), 1),
                "recall_at_10fp": round(statistics.mean((r["recall_at_fp_per_day"] or {}).get("10/day") or 0
                                                        for r in sel), 3),
            })
    return out


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="bench.cost")
    p.add_argument("what", choices=["funnel", "scale"])
    a = p.parse_args(argv)
    if a.what == "funnel":
        res, path = funnel(), os.path.join(RES, "C6_funnel.json")
    else:
        res, path = scale(), os.path.join(RES, "C5_cost_scale.json")
    json.dump(res, open(path, "w", encoding="utf-8"), indent=1)
    print(json.dumps(res, indent=1)[:4000])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
