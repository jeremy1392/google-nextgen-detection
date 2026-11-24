"""Experiment suites: every combination, generated, replayed and aggregated in one command.

    python -m bench suite core intensity ablation speed --workers 6 --cache <dir>

core       6 conditions x 3 seeds x 8 pipelines   (A3, B1-B5, C7, E1, E2, H4)
intensity  intensity 0.1 .. 1.0                     (E6; below 0.5 anomalies switch to subtle forms)
ablation   one layer removed at a time + Dapper / edge-log sampling variants   (H2, F3)
speed      replay speed 1x .. 100000x on one dataset  (C1, C5, C8)

Results: experiments/results/suite_<plan>.json (raw rows) and experiments/REPORT.md (tables, mean and
95% CI over seeds).
"""
from __future__ import annotations

import json
import math
import os
import shutil
import statistics
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed

from loggen.registry import LAYERS, SOURCES

DURATION, EVAL_FROM = "36h", "12h"
PIPES = ["P0", "P1", "P2", "P3", "P4", "P5", "P6", "P6-sum", "P6-max", "P6-hyper", "P6-indep", "P6+P4"]
SEEDS = [1, 2, 3]
CONDITIONS = {
    "base": [],
    "lag_drop": ["--lag", "--drop-rate", "0.02"],
    "drift": ["--drift", "launch@14h,reorg@16h,holiday@20h+6h"],
    "faint": ["--intensity", "0.3"],
    "bundles": ["--bundles", "10", "--bundle-intensity", "0.3"],
    "mix": ["--lag", "--drop-rate", "0.02", "--drift", "launch@14h,reorg@16h", "--bundles", "6", "--intensity", "0.6"],
}
INTENSITIES = [0.1, 0.2, 0.3, 0.5, 0.7, 1.0]
SPEEDS = [1, 1000, 10000, 50000, 100000]
METRICS = ["recall", "precision", "fp_per_day", "fp_lookalike_per_day", "bundle_recall"]


def _gen(out: str, seed: int, args: list) -> None:
    if os.path.exists(os.path.join(out, "manifest.json")):
        return
    from loggen.cli import main as loggen_main
    loggen_main(["--out", out, "--duration", DURATION, "--seed", str(seed), *args])


def job(spec: dict) -> list[dict]:
    from loggen.engine import parse_duration

    from .core import Run, replay
    from .detectors import PIPELINES
    from .score import latency, score
    _gen(spec["data"], spec["seed"], spec["gen"])
    run = Run.load(spec["data"], drop_context=spec.get("drop_context", []))
    eval_from = run.start + parse_duration(EVAL_FROM)
    rows = []
    for ev in spec["evals"]:
        dets = [PIPELINES[p]() for p in ev["pipelines"]]
        for p, d in zip(ev["pipelines"], dets):
            d.name = p
        shed = {s for s, src in SOURCES.items() if src.layer in ev.get("shed_layers", ())}
        alerts, timing = replay(run, dets, speed=ev.get("speed", 1.0), sources=ev.get("sources"),
                                overload=ev.get("overload", "queue"), max_delay_s=ev.get("max_delay_s"),
                                shed_sources=shed)
        for p, d in zip(ev["pipelines"], dets):
            for batch_s in ev.get("batch", [None]):  # C4: same alerts, released at batch boundaries
                m = score(run, alerts[d.name], eval_from=eval_from, batch_s=batch_s)
                rows.append({**spec["tags"], **ev.get("tags", {}), "pipeline": p, **m,
                             "latency": latency(timing[d.name])})
    if spec.get("cleanup"):
        shutil.rmtree(spec["data"], ignore_errors=True)
    return rows


def plan(name: str, cache: str) -> tuple[list[dict], list[dict]]:
    """Returns (shared datasets to build first, jobs)."""
    shared, jobs = [], []
    base1 = {"data": os.path.join(cache, "base_s1"), "seed": 1, "gen": []}
    if name == "core":
        for cond, args in CONDITIONS.items():
            for seed in SEEDS:
                jobs.append({"data": os.path.join(cache, f"{cond}_s{seed}"), "seed": seed, "gen": args,
                             "tags": {"plan": "core", "condition": cond, "seed": seed}, "cleanup": True,
                             "evals": [{"pipelines": PIPES}]})
    elif name == "intensity":
        for k in INTENSITIES:
            jobs.append({"data": os.path.join(cache, f"int{k}_s1"), "seed": 1, "gen": ["--intensity", str(k)],
                         "tags": {"plan": "intensity", "intensity": k, "seed": 1}, "cleanup": True,
                         "evals": [{"pipelines": PIPES}]})
    elif name == "ablation":
        shared.append(base1)
        variants = {"none": None}
        for layer in LAYERS:
            variants[f"-{layer}"] = [s for s, src in SOURCES.items() if src.layer != layer]
        variants["-obs.rpc_edge"] = [s for s in SOURCES if s != "obs.rpc_edge"]
        variants["-obs.dapper"] = [s for s in SOURCES if s != "obs.dapper"]
        variants["-dapper-and-edge"] = [s for s in SOURCES if s not in ("obs.dapper", "obs.rpc_edge")]
        for v, sources in variants.items():
            jobs.append({**base1, "tags": {"plan": "ablation", "removed": v, "seed": 1},
                         "evals": [{"pipelines": PIPES, "sources": sources}]})
    elif name == "speed":
        shared.append(base1)
        jobs.append({**base1, "tags": {"plan": "speed", "seed": 1},
                     "evals": [{"pipelines": ["P0", "P2", "P4", "P5", "P6", "P6-hyper"], "speed": s,
                                "tags": {"speed": s}}
                               for s in SPEEDS]})
    elif name == "coretuned":  # the main matrix again, for the SOC-tuned variants (10 seeds x 6 conditions)
        for cond, args in CONDITIONS.items():
            for seed in SEEDS:
                jobs.append({"data": os.path.join(cache, f"{cond}_s{seed}"), "seed": seed, "gen": args,
                             "tags": {"plan": "coretuned", "condition": cond, "seed": seed}, "cleanup": True,
                             "evals": [{"pipelines": ["P1-tuned", "P5-hyper-tuned", "P6-hyper-tuned", "MIX-tuned"]}]})
    elif name == "overload":  # C8: queue (back-pressure) vs drop vs shed low-value sources, past a 60 s wait
        for seed in SEEDS_EXTRA:
            data = os.path.join(cache, f"base_s{seed}")
            if not any(x["data"] == data for x in shared):
                shared.append({"data": data, "seed": seed, "gen": []})
            jobs.append({"data": data, "seed": seed, "gen": [], "tags": {"plan": name, "seed": seed},
                         "evals": [{"pipelines": OVERLOAD_PIPES, "speed": s, "overload": pol, "max_delay_s": 60,
                                    "shed_layers": ["observability"], "tags": {"speed": s, "policy": pol}}
                                   for pol in ("queue", "drop", "shed") for s in OVERLOAD_SPEEDS]})
    elif name in ("f3adaptive", "f3heavy"):  # F3: what each sampling of the call graph lets detection see
        no_edge = [s for s in SOURCES if s != "obs.rpc_edge"]
        heavy = ["--anomaly-types", "new_rpc_edge", "--anomalies", "12"] if name == "f3heavy" else []
        variants = {"edgelog": ([], None), "none": ([], no_edge),
                    "uniform": (["--dapper-edges", "uniform"], no_edge),
                    "uniform16": (["--dapper-edges", "uniform", "--dapper-rate", "16"], no_edge),
                    "adaptive": (["--dapper-edges", "adaptive"], no_edge)}
        for v, (gen, sources) in variants.items():
            for seed in SEEDS_EXTRA:
                tag = "plain" if not gen else "_".join(gen).replace("--", "")
                data = os.path.join(cache, f"{name}_{tag}_s{seed}")
                if not gen and not any(x["data"] == data for x in shared):  # edgelog and none read the same data
                    shared.append({"data": data, "seed": seed, "gen": heavy})
                jobs.append({"data": data, "seed": seed, "gen": gen + heavy,
                             "tags": {"plan": name, "variant": v, "seed": seed},
                             "evals": [{"pipelines": ["P2", "P5-hyper", "P6-hyper", "MIX-tuned"], "sources": sources}]})
    elif name == "context":  # B4: same datasets, context tables withheld from the detectors at evaluation time
        for v, drop in CONTEXT_VARIANTS.items():
            for seed in SEEDS_EXTRA:
                data = os.path.join(cache, f"base_s{seed}")
                if not any(x["data"] == data for x in shared):
                    shared.append({"data": data, "seed": seed, "gen": []})
                jobs.append({"data": data, "seed": seed, "gen": [], "drop_context": drop,
                             "tags": {"plan": name, "variant": v, "seed": seed},
                             "evals": [{"pipelines": CONTEXT_PIPES}]})
    elif name in EXTRA_PLANS:
        variants, pipes, gen_of, batch, shared_base = EXTRA_PLANS[name]
        for v in variants:
            for seed in SEEDS_EXTRA:
                if shared_base:
                    data = os.path.join(cache, f"base_s{seed}")
                    if not any(x["data"] == data for x in shared):
                        shared.append({"data": data, "seed": seed, "gen": []})
                    job = {"data": data, "seed": seed, "gen": []}
                else:
                    job = {"data": os.path.join(cache, f"{name}{v}_s{seed}"), "seed": seed, "gen": gen_of(v),
                           "cleanup": True}
                jobs.append({**job, "tags": {"plan": name, "variant": v, "seed": seed},
                             "evals": [{"pipelines": pipes(v), "batch": batch}]})
    else:
        raise SystemExit(f"unknown plan {name}")
    return shared, jobs


SEEDS_EXTRA = [1, 2, 3]
CONTEXT_VARIANTS = {"full": [], "-inventory": ["inventory"], "-oncall": ["oncall"], "-builds": ["builds"],
                    "-all": ["inventory", "oncall", "builds"]}
CONTEXT_PIPES = ["P0", "P1", "P1-tuned", "P5-hyper", "P6-hyper", "MIX-tuned"]
OVERLOAD_PIPES = ["P0", "P2", "P6-hyper", "MIX-tuned"]
OVERLOAD_SPEEDS = [10000, 30000, 100000, 300000]
# name: (variants, pipelines(variant), generator args(variant), batch release list, shared base datasets)
EXTRA_PLANS = {
    "window": ([60, 300, 900], lambda v: ["P2", "P5", "P6", "P6-hyper"],
               lambda v: ["--agg-window", str(v)], [None], False),
    "stitching": ([0.0, 0.05, 0.15, 0.3], lambda v: ["P2", "P5", "P6", "P6-hyper"],
                  lambda v: ["--drop-keys", str(v)], [None], False),
    "batch": (["release"], lambda v: ["P2", "P6", "P6-hyper"], lambda v: [], [None, 300, 3600], True),
    "halflife": (["sweep"], lambda v: ["P6-hyper-hl1", "P6-hyper-hl3", "P6-hyper", "P6-hyper-hl12",
                                        "P6-hyper-hl24"], lambda v: [], [None], True),
    "sampling": ([0.1, 1, 4, 16], lambda v: ["P2", "P5", "P6-hyper"], lambda v: ["--dapper-rate", str(v)],
                 [None], False),
    "mixfamily": (["b5"], lambda v: ["P1", "P5", "P6-hyper", "MIX"], lambda v: [], [None], True),
    "mixtuned": (["b5t"], lambda v: ["P6-hyper", "MIX", "MIX-tuned"], lambda v: [], [None], True),
    "tuning": (["soc"], lambda v: ["P0", "P1", "P1-tuned", "P5", "P5-hyper-tuned", "P6-hyper", "P6-hyper-tuned"],
               lambda v: [], [None], True),
    "graph": (["variants"], lambda v: ["P5", "P5-damp0.2", "P5-damp0.6", "P5-hub50", "P5-hub500",
                                        "P5-identity-only", "P5-hyper"], lambda v: [], [None], True),
    # C5: throughput and cost per million events as the fleet grows (population and traffic x1 .. x10)
    "scale": ([1, 2, 5, 10], lambda v: ["P0", "P1", "P2", "P3", "P4", "P5-hyper", "P6-hyper", "MIX-tuned"],
              lambda v: ["--scale", str(v)], [None], False),
    # F6: GNN link prediction alone and as a fusion signal, on the base, drift (benign launch) and mix conditions
    "gnn": (["base", "drift", "mix"], lambda v: ["P2", "P5-hyper", "P6-hyper", "MIX-tuned", "P10", "P10-q0.5",
                                                 "P10-q10", "P6-hyper+P10", "P5-hyper+P10", "MIX-tuned+P10"],
            lambda v: CONDITIONS[v], [None], False),
    # H5: robustness to heterogeneous people (A1 found the default population far more uniform than CERT/LANL)
    "hetero": ([0.0, 0.5, 1.0], lambda v: ["P0", "P1", "P1-tuned", "P2", "P3", "P4", "P5-hyper", "P6-hyper",
                                           "P6+P4", "MIX-tuned"],
               lambda v: ["--user-heterogeneity", str(v)] if v else [], [None], False),
}


def run_suite(names: list[str], cache: str, workers: int, out_dir: str = "experiments", seeds: int = 3) -> None:
    global SEEDS
    SEEDS = list(range(1, seeds + 1))
    os.makedirs(cache, exist_ok=True)
    os.makedirs(os.path.join(out_dir, "results"), exist_ok=True)
    all_rows = {}
    for name in names:
        shared, jobs = plan(name, cache)
        for s in shared:
            _gen(s["data"], s["seed"], s["gen"])
        rows = []
        with ProcessPoolExecutor(max_workers=workers) as pool:
            futs = [pool.submit(job, j) for j in jobs]
            for i, f in enumerate(as_completed(futs), 1):
                rows.extend(f.result())
                print(f"[{name}] {i}/{len(jobs)} jobs done", file=sys.stderr, flush=True)
        json.dump(rows, open(os.path.join(out_dir, "results", f"suite_{name}.json"), "w", encoding="utf-8"), indent=1)
        all_rows[name] = rows
    write_report(out_dir)


# ---------------------------------------------------------------------- aggregation & report
def _ci(values: list[float]) -> str:
    vals = [v for v in values if v is not None]
    if not vals:
        return "-"
    m = statistics.mean(vals)
    if len(vals) < 2:
        return f"{m:.3g}"
    from scipy.stats import t
    h = t.ppf(0.975, len(vals) - 1) * statistics.stdev(vals) / math.sqrt(len(vals))
    return f"{m:.3g} ± {h:.2g}"


def _get(row: dict, key: str):
    if key == "R@10FP/d":
        return row["recall_at_fp_per_day"].get("10/day")
    if key in ("ueba", "nhi", "runtime"):
        return row["recall_by_family"].get(key)
    if key == "TTD p50 s":
        return row["ttd_s"]["p50"]
    return row.get(key)


def write_report(out_dir: str = "experiments") -> None:
    res = os.path.join(out_dir, "results")
    lines = ["# Experiment report", "",
             "Generated by `python -m bench suite`. Synthetic data from loggen; mean ± 95% CI over seeds "
             "where seeds > 1. Scored after a 12 h warm-up on 36 h runs.", ""]
    cols = ["recall", "precision", "fp_per_day", "fp_lookalike_per_day", "R@10FP/d", "ueba", "nhi", "runtime",
            "bundle_recall", "TTD p50 s"]
    p = os.path.join(res, "suite_core.json")
    if os.path.exists(p):
        rows = json.load(open(p, encoding="utf-8"))
        lines += ["## Core: conditions x pipelines (A3, B1-B5, C7, E1, E2, H4)", ""]
        for cond in CONDITIONS:
            lines += [f"### {cond} `{' '.join(CONDITIONS[cond]) or 'default'}`", "",
                      "| pipeline | " + " | ".join(cols) + " |", "|---" * (len(cols) + 1) + "|"]
            for pipe in PIPES:
                sel = [r for r in rows if r["condition"] == cond and r["pipeline"] == pipe]
                if sel:
                    lines.append(f"| {pipe} | " + " | ".join(_ci([_get(r, c) for r in sel]) for c in cols) + " |")
            lines.append("")
    p = os.path.join(res, "suite_intensity.json")
    if os.path.exists(p):
        rows = json.load(open(p, encoding="utf-8"))
        lines += ["## Intensity sweep: recall (E6)", "", "| pipeline | " + " | ".join(map(str, INTENSITIES)) + " |",
                  "|---" * (len(INTENSITIES) + 1) + "|"]
        for pipe in PIPES:
            vals = [next((r["recall"] for r in rows if r["pipeline"] == pipe and r["intensity"] == k), None)
                    for k in INTENSITIES]
            lines.append(f"| {pipe} | " + " | ".join("-" if v is None else f"{v:.2f}" for v in vals) + " |")
        lines.append("")
    p = os.path.join(res, "suite_ablation.json")
    if os.path.exists(p):
        rows = json.load(open(p, encoding="utf-8"))
        variants = list(dict.fromkeys(r["removed"] for r in rows))
        lines += ["## Source ablation: recall with one layer removed (H2, F3)", "",
                  "| removed | " + " | ".join(PIPES) + " |", "|---" * (len(PIPES) + 1) + "|"]
        for v in variants:
            vals = [next((r["recall"] for r in rows if r["pipeline"] == pp and r["removed"] == v), None) for pp in PIPES]
            lines.append(f"| {v} | " + " | ".join("-" if x is None else f"{x:.2f}" for x in vals) + " |")
        lines.append("")
    p = os.path.join(res, "suite_speed.json")
    if os.path.exists(p):
        rows = json.load(open(p, encoding="utf-8"))
        pipes = list(dict.fromkeys(r["pipeline"] for r in rows))
        lines += ["## Load: detection delay p99 (s) vs replay speed (C1, C5, C8)", "",
                  "| speed | " + " | ".join(pipes) + " |", "|---" * (len(pipes) + 1) + "|"]
        for s in SPEEDS:
            vals = [next((r["latency"]["detection_delay_s"]["p99"] for r in rows
                          if r["pipeline"] == pp and r["speed"] == s), None) for pp in pipes]
            lines.append(f"| {s}x | " + " | ".join("-" if x is None else str(x) for x in vals) + " |")
        thr = {pp: next((r["latency"]["throughput_eps"] for r in rows if r["pipeline"] == pp), None) for pp in pipes}
        lines += ["", "Throughput ceiling (events/s, detector only): " +
                  ", ".join(f"{k} {v:,}" for k, v in thr.items() if v), ""]
    for plan_name, title in (("mixtuned", "Best technique per family with SOC-tuned rules (B5)"),
                             ("tuning", "Classic camp after SOC-style tuning (exceptions learned in warm-up)"),
                             ("sampling", "Dapper sampling density (F3), x default rate"),
                             ("mixfamily", "Best technique per family, combined (B5)"),
                             ("window", "Aggregation window (C3), by window seconds"),
                             ("stitching", "Identity stitching loss (E5), by share of keys dropped"),
                             ("batch", "Streaming vs batch release (C4), by batch seconds (None = streaming)"),
                             ("halflife", "Risk half-life (E4)"), ("graph", "Graph construction (F2)"),
                             ("hetero", "Heterogeneous people (H5), by sigma of the per-person activity multiplier"),
                             ("context", "Value of context (B4): inventory, on-call, build registry withheld"),
                             ("scale", "Fleet scale (C5): population and traffic multiplier"),
                             ("gnn", "GNN link prediction (F6), by condition"),
                             ("f3adaptive", "Call-graph sampling (F3): edge log vs Dapper spans, all anomaly types"),
                             ("f3heavy", "Call-graph sampling (F3): edge log vs Dapper spans, new_rpc_edge only")):
        p = os.path.join(res, f"suite_{plan_name}.json")
        if not os.path.exists(p):
            continue
        rows = json.load(open(p, encoding="utf-8"))
        keyname = "batch_s" if plan_name == "batch" else "variant"
        lines += [f"## {title}", "", f"| {keyname} | pipeline | recall | R@10FP/d | fp_per_day | TTD p50 s | brier |",
                  "|---|---|---|---|---|---|---|"]
        for v in dict.fromkeys(r.get(keyname) for r in rows):
            for pipe in dict.fromkeys(r["pipeline"] for r in rows):
                sel = [r for r in rows if r.get(keyname) == v and r["pipeline"] == pipe]
                if sel:
                    lines.append(f"| {v} | {pipe} | " + " | ".join(
                        _ci([_get(r, c) for r in sel]) for c in ("recall", "R@10FP/d", "fp_per_day", "TTD p50 s",
                                                                  "brier")) + " |")
        lines.append("")
    open(os.path.join(out_dir, "REPORT.md"), "w", encoding="utf-8", newline="\n").write("\n".join(lines))
