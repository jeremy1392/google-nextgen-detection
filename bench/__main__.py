"""python -m bench list | eval <run> [--pipelines P0,P1,P2] [--eval-from 12h] [--speed 1] [--sources ...]"""
from __future__ import annotations

import argparse
import json
import os
import sys

from loggen.engine import parse_duration

from .catalog import EXPERIMENTS, status
from .core import Run, replay
from .detectors import PIPELINES
from .score import latency, score


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="bench")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="every experiment and whether it can run yet")
    ev = sub.add_parser("eval", help="replay a loggen run through pipelines and score them")
    ev.add_argument("run", help="loggen output directory")
    ev.add_argument("--pipelines", default=",".join(PIPELINES))
    ev.add_argument("--eval-from", default="12h", help="score only after this offset (baselines warm up before)")
    ev.add_argument("--speed", type=float, default=1.0, help="replay speed for the queue model (sim s per wall s)")
    ev.add_argument("--sources", help="comma-separated globs: replay only these sources (ablation)")
    ev.add_argument("--json", help="write the full result here")
    sp = sub.add_parser("llm-speed", help="G4: latency / cost of LLMs on one triage case via OpenRouter")
    sp.add_argument("--models", default="gemini-text", help="comma list, or 'gemini-text' for every Gemini text model")
    sp.add_argument("--runs", type=int, default=3)
    sp.add_argument("--reasoning", choices=["default", "low", "off"], default="default")
    sp.add_argument("--json", help="write the full result here")
    su = sub.add_parser("suite", help="generate + replay + aggregate experiment plans (see bench/suite.py)")
    su.add_argument("plans", nargs="+", choices=["core", "intensity", "ablation", "speed", "window", "stitching", "batch", "halflife", "graph", "sampling", "mixfamily", "tuning", "mixtuned", "coretuned", "hetero", "context", "overload", "scale", "gnn", "f3adaptive", "f3heavy"])
    su.add_argument("--workers", type=int, default=6)
    su.add_argument("--seeds", type=int, default=3, help="seeds per condition in the core plan")
    su.add_argument("--cache", default="experiments/cache", help="where generated datasets go")
    sub.add_parser("report", help="rebuild experiments/REPORT.md from saved suite results")
    args = ap.parse_args(argv)

    if args.cmd == "suite":
        from .suite import run_suite
        run_suite(args.plans, args.cache, args.workers, seeds=args.seeds)
        return 0
    if args.cmd == "report":
        from .suite import write_report
        write_report()
        return 0

    if args.cmd == "llm-speed":
        from . import llm
        if args.models == "gemini-text":
            skip = ("image", "omni", "banana", ":batch", "customtools")
            models = sorted(m["id"] for m in llm.list_models() if not any(s in m["id"] for s in skip))
        else:
            models = [m.strip() for m in args.models.split(",")]
        extra = {"default": None, "low": {"reasoning": {"effort": "low"}},
                 "off": {"reasoning": {"enabled": False}}}[args.reasoning]
        rows = llm.speed_probe(models, args.runs, extra)
        rows.sort(key=lambda r: r.get("total_s", 1e9))
        print(f"{'model':<44}{'ok':>5}{'TTFT s':>9}{'total s':>9}{'out tok':>9}{'reason tok':>11}{'$/call':>10}  verdicts")
        for r in rows:
            if "total_s" in r:
                print(f"{r['model']:<44}{r['ok']:>3}/{r['runs']}{r['ttft_s']:>9}{r['total_s']:>9}{r['out_tokens']:>9}"
                      f"{r['reasoning_tokens']:>11}{r['cost_usd']:>10}  {','.join(r['verdicts'])}")
            else:
                print(f"{r['model']:<44}{r['ok']:>3}/{r['runs']}  error: {r['errors']}")
        if args.json:
            os.makedirs(os.path.dirname(os.path.abspath(args.json)), exist_ok=True)
            json.dump(rows, open(args.json, "w", encoding="utf-8"), indent=2)
        return 0

    if args.cmd == "list":
        for e in EXPERIMENTS:
            print(f"{e['id']:<4} {status(e):<48} {e['title']}")
        ready = sum(status(e) == "ready" for e in EXPERIMENTS)
        print(f"\n{len(EXPERIMENTS)} experiments, {ready} ready now, pipelines available: {', '.join(PIPELINES)}")
        return 0

    run = Run.load(args.run)
    names = [p.strip() for p in args.pipelines.split(",")]
    dets = [PIPELINES[p]() for p in names]
    for p, d in zip(names, dets):
        d.name = p  # one alert list per pipeline, even for two variants of the same class
    eval_from = run.start + parse_duration(args.eval_from)
    sources = [s.strip() for s in args.sources.split(",")] if args.sources else None
    alerts, timing = replay(run, dets, speed=args.speed, sources=sources)
    result = {"run": os.path.abspath(args.run), "events": timing["_events"], "wall_s": round(timing["_wall_s"], 1),
              "eval_from": args.eval_from, "speed": args.speed, "sources": sources, "pipelines": {}}
    for p, d in zip(names, dets):
        result["pipelines"][p] = {"detector": d.name, **score(run, alerts[d.name], eval_from=eval_from),
                                  "latency": latency(timing[d.name])}
        if isinstance(getattr(d, "stats", None), dict) and "llm_calls" in d.stats:
            st = dict(d.stats)
            lat = sorted(st.pop("llm_latency_s", []) or [0])
            st["llm_latency_s"] = {"p50": lat[len(lat) // 2], "p95": lat[int(len(lat) * 0.95)]}
            st["cost_usd"] = round(st["cost_usd"], 4)
            result["pipelines"][p]["llm"] = st
            result["pipelines"][p]["llm_decisions"] = d.decisions
    _print(result)
    if args.json:
        os.makedirs(os.path.dirname(os.path.abspath(args.json)), exist_ok=True)
        json.dump(result, open(args.json, "w", encoding="utf-8"), indent=2)
    return 0


def _print(r) -> None:
    print(f"{r['events']:,} events replayed in {r['wall_s']}s (scored after {r['eval_from']}, speed {r['speed']}x)\n")
    cols = ["alerts/day", "precision", "FP/day", "look-alike FP/d", "recall", "ueba", "nhi", "runtime",
            "bundles", "TTD p50 s", "R@10FP/d", "us/event p99", "events/s"]
    print(f"{'':<4}" + "".join(f"{c:>16}" for c in cols))
    for p, m in r["pipelines"].items():
        fam = m["recall_by_family"]
        row = [m["alerts_per_day"], m["precision"], m["fp_per_day"], m["fp_lookalike_per_day"], m["recall"],
               fam.get("ueba"), fam.get("nhi"), fam.get("runtime"), m["bundle_recall"], m["ttd_s"]["p50"],
               m["recall_at_fp_per_day"].get("10/day"), m["latency"]["per_event_us"]["p99"],
               m["latency"]["throughput_eps"]]
        print(f"{p:<4}" + "".join(f"{'-' if v is None else v:>16}" for v in row))
    print()
    for p, m in r["pipelines"].items():
        print(f"{p} recall by type: " + ", ".join(f"{k}={v}" for k, v in m["recall_by_type"].items()))
        if m["fp_lookalike_by_type"]:
            print(f"{p} look-alike FPs: {m['fp_lookalike_by_type']}")
        print(f"{p} top FP rules (per day): {m['fp_per_day_by_rule']}")


if __name__ == "__main__":
    sys.exit(main())
