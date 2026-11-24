"""Command line entry point: python -m loggen --help"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

from . import __version__, anomalies, drift
from .engine import DirSink, Sim, StdoutSink, iso, parse_duration, parse_time
from .registry import LAYERS, SOURCES
from .sources import install_all
from .world import World


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="loggen", description="Synthetic multi-source security telemetry for a "
                                "Borg / Colossus / BeyondCorp-style environment, with labeled anomalies.")
    p.add_argument("--out", default="out/run", help="output directory (default: out/run)")
    p.add_argument("--start", help="simulation start, ISO 8601 UTC (default: 2026-11-23T00:00:00Z, or now with --realtime)")
    p.add_argument("--duration", default="24h", help="simulated time span, e.g. 90m, 6h, 7d (default: 24h)")
    p.add_argument("--seed", type=int, default=7, help="random seed; same seed + options = same logs (default: 7)")
    p.add_argument("--scale", type=float, default=1.0, help="population and traffic multiplier (default: 1.0 = ~200 people)")
    p.add_argument("--tz-offset", type=float, default=1.0, help="local time offset in hours for working hours (default: +1, CET)")
    p.add_argument("--anomalies", type=int, default=52, help="number of labeled anomalies (default: 52, two per type)")
    p.add_argument("--anomaly-types", default="all", help=f"comma-separated subset of: {', '.join(anomalies.INJECTORS)}")
    p.add_argument("--sources", help="only write these sources, comma-separated globs (e.g. 'borg.*,colossus.*')")
    p.add_argument("--combined", action="store_true", help="also write every event to all.jsonl")
    p.add_argument("--stdout", action="store_true", help="stream events to stdout instead of per-source files")
    p.add_argument("--inline-labels", action="store_true", help="add a _truth field to anomalous events (for training)")
    p.add_argument("--realtime", action="store_true", help="pace output on the wall clock (for feeding a pipeline)")
    p.add_argument("--speed", type=float, default=1.0, help="with --realtime: simulated seconds per wall second")
    p.add_argument("--list-sources", action="store_true", help="print the source catalogue and exit")
    x = p.add_argument_group("experiment knobs")
    x.add_argument("--intensity", type=float, default=1.0, help="anomaly strength, 0.1 (faint) .. 1 (default) .. 2")
    x.add_argument("--shuffle-types", action="store_true", help="randomize the order anomaly types are injected in")
    x.add_argument("--bundles", type=int, default=0, help="bundles of weak anomalies sharing one entity (fusion tests)")
    x.add_argument("--bundle-size", type=int, default=3, help="anomalies per bundle (default: 3)")
    x.add_argument("--bundle-intensity", type=float, default=0.3, help="intensity of bundled anomalies (default: 0.3)")
    x.add_argument("--lag", action="store_true", help="add ingest_ts: realistic per-layer delivery delays and outages")
    x.add_argument("--drop-rate", type=float, default=0.0, help="fraction of events lost in transit")
    x.add_argument("--raw", action="store_true", help="add the native log line ('raw') for santa/auditd/dns/netflow/proxy")
    x.add_argument("--injection-rate", type=float, default=0.0,
                   help="fraction of free-text fields carrying instruction-like text (prompt-injection tests)")
    x.add_argument("--user-heterogeneity", type=float, default=0.0,
                   help="H5: sigma of a per-person lognormal activity multiplier (0 = everyone alike)")
    x.add_argument("--injection-target", choices=["any", "attack"], default="any",
                   help="G8: inject into any event's fields, or only into the anomalies' own events (attacker-written)")
    x.add_argument("--drift", default="", help="legitimate baseline changes, e.g. launch@26h,reorg@30h,holiday@48h+24h")
    x.add_argument("--binary-corpus", help="CSV sha256,label[,platform] (0 benign / 1 malicious; platform pe|elf) "
                                           "to take binary hashes from")
    x.add_argument("--binary-scan", action="store_true",
                   help="D6: emit corp.binscan at the first run of each binary on a device (on-host extraction)")
    x.add_argument("--new-binaries-per-day", type=float, default=0.0,
                   help="D6: fleet-wide benign binaries never seen before, per working day (needs --binary-corpus)")
    x.add_argument("--truth-out", help="write ground truth here instead of --out (blind experiments)")
    x.add_argument("--agg-window", type=float, default=300.0,
                   help="seconds per window for monarch / edge log / chunk I/O (C3, default 300)")
    x.add_argument("--dapper-rate", type=float, default=1.0,
                   help="sampled traces relative to the default rate, e.g. 16 for 1/64 instead of 1/1024 (F3)")
    x.add_argument("--dapper-edges", choices=["off", "uniform", "adaptive"], default="off",
                   help="F3: also sample one span per call of every edge: uniform at the Dapper rate (1/1024 x "
                        "--dapper-rate) or adaptive (an edge seen rarely so far is sampled more, up to every call)")
    x.add_argument("--drop-keys", type=float, default=0.0,
                   help="chance of losing each correlation key (principal, device, task, job, trace) (E5)")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.list_sources:
        for layer, title in LAYERS.items():
            print(f"\n{title}")
            for name, src in SOURCES.items():
                if src.layer == layer:
                    print(f"  {name:<22} {src.system:<30} {src.description}")
        return 0

    if args.start:
        start = parse_time(args.start)
    elif args.realtime:
        start = float(int(time.time()))
    else:
        start = parse_time("2026-11-23T00:00:00Z")
    end = start + parse_duration(args.duration)
    kinds = list(anomalies.INJECTORS) if args.anomaly_types == "all" else \
        [k.strip() for k in args.anomaly_types.split(",") if k.strip()]
    unknown = [k for k in kinds if k not in anomalies.INJECTORS]
    if unknown:
        print(f"unknown anomaly type(s): {', '.join(unknown)}", file=sys.stderr)
        return 2

    sim = Sim(start, end, args.seed, scale=args.scale, tz_hours=args.tz_offset)
    sim.source_filter = [g.strip() for g in args.sources.split(",")] if args.sources else None
    sim.inline_labels = args.inline_labels
    sim.realtime, sim.speed = args.realtime, args.speed
    sim.intensity, sim.lag, sim.drop_rate = args.intensity, args.lag, args.drop_rate
    sim.raw, sim.injection_rate = args.raw, args.injection_rate
    sim.agg_window, sim.drop_keys, sim.dapper_rate = args.agg_window, args.drop_keys, args.dapper_rate
    sim.dapper_edges = args.dapper_edges
    sim.binary_scan, sim.new_binaries_per_day = args.binary_scan, args.new_binaries_per_day
    sim.injection_target = args.injection_target
    sim.user_heterogeneity = args.user_heterogeneity
    os.makedirs(args.out, exist_ok=True)
    sim.sinks.append(StdoutSink() if args.stdout else DirSink(args.out, args.combined))

    world = World(sim, args.seed, args.scale, corpus=_load_corpus(args.binary_corpus))
    install_all(sim, world)
    if kinds:
        anomalies.schedule(sim, world, args.anomalies, kinds, args.intensity, args.shuffle_types)
    if args.bundles:
        anomalies.schedule_bundles(sim, world, args.bundles, args.bundle_size, args.bundle_intensity)
    drift_log = drift.schedule(sim, world, args.drift) if args.drift else []
    _write_json(os.path.join(args.out, "context", "inventory.json"), world.inventory())

    t0 = time.monotonic()
    sim.run()
    elapsed = time.monotonic() - t0

    truth_dir = args.truth_out or args.out
    os.makedirs(truth_dir, exist_ok=True)
    cases = _write_truth(sim, os.path.join(truth_dir, "ground_truth.jsonl"), "anomaly")
    benign = _write_truth(sim, os.path.join(truth_dir, "benign_cases.jsonl"), "benign")
    if sim.injections:
        with open(os.path.join(truth_dir, "injections.jsonl"), "w", encoding="utf-8", newline="\n") as f:
            for item in sim.injections:
                f.write(json.dumps(item, ensure_ascii=False) + "\n")
    if drift_log:
        _write_json(os.path.join(args.out, "context", "drift.json"),
                    [{**d, "at": iso(d["at"])} if "at" in d else d for d in drift_log])
    _write_json(os.path.join(args.out, "context", "builds.json"),
                {"synthetic": True, "note": "Build registry: every BCID with verified provenance.",
                 "builds": [{**vars(b), "ts": iso(b.ts)} for b in world.builds.values()]})
    _write_json(os.path.join(args.out, "context", "oncall.json"), _oncall(sim, world))
    manifest = {
        "generator": f"loggen {__version__}", "synthetic": True,
        "note": "Synthetic data. Names, identifiers, domains (example.com) and IPs (RFC 5737) are invented.",
        "seed": args.seed, "scale": args.scale, "start": iso(start), "end": iso(end), "tz_offset_h": args.tz_offset,
        "events_total": sum(sim.counts.values()), "events_by_source": dict(sorted(sim.counts.items())),
        "anomalies": cases, "benign_cases": benign, "injections": len(sim.injections), "dropped": len(sim.dropped),
        "knobs": {k: getattr(args, k) for k in ("intensity", "bundles", "bundle_size", "bundle_intensity", "lag",
                                                 "drop_rate", "raw", "injection_rate", "drift", "shuffle_types",
                                                 "binary_scan", "new_binaries_per_day", "injection_target",
                                                 "user_heterogeneity", "dapper_edges")},
        "elapsed_s": round(elapsed, 1),
    }
    _write_json(os.path.join(args.out, "manifest.json"), manifest)
    if not args.stdout:
        print(f"{manifest['events_total']:,} events from {len(sim.counts)} sources, {cases} anomalies, "
              f"{iso(start)} -> {iso(end)} in {elapsed:.1f}s -> {os.path.abspath(args.out)}", file=sys.stderr)
    return 0


def _write_json(path: str, obj) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def _load_corpus(path: str | None) -> dict:
    if not path:
        return {}
    out: dict = {"benign": [], "malicious": []}
    with open(path, encoding="utf-8") as f:
        for line in f:
            sha, label, platform = (line.strip().split(",") + ["", ""])[:3]
            if len(sha) == 64 and label in ("0", "1"):
                cls = "malicious" if label == "1" else "benign"
                out[cls].append(sha.lower())
                if platform:
                    out.setdefault(f"{cls}:{platform}", []).append(sha.lower())
    return out


def _write_truth(sim, path: str, kind: str) -> int:
    n = 0
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        for case in sim.truth.values():
            if case["kind"] != kind:
                continue
            events = sorted((e for e in case["events"] if e["ts"] < sim.end and sim.wants(e["log_source"])
                             and e["event_id"] not in sim.dropped), key=lambda e: e["ts"])
            if not events:
                continue
            out = {**case, "start": iso(case["start"]), "end": iso(min(case["end"], sim.end)),
                   "first_event": iso(events[0]["ts"]),
                   "sources": sorted({e["log_source"] for e in events}),
                   "events": [{**e, "ts": iso(e["ts"])} for e in events]}
            f.write(json.dumps(out, ensure_ascii=False) + "\n")
            n += 1
    return n


def _oncall(sim, world) -> dict:
    days = range(sim.local_day(sim.start), sim.local_day(sim.end - 1) + 1)
    teams = sorted({u.team for u in world.sres})
    return {"synthetic": True, "rotation": "daily, local midnight",
            "days": [{"local_day_start": iso(d * 86400 - sim.tz),
                      "oncall": {t: world.oncall(t, d * 86400 - sim.tz + 3600).principal for t in teams}}
                     for d in days]}
