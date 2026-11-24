"""C9: does the causal graph stay fast as it grows? Graph size, per-event update latency and 2-hop query
latency, measured at every simulated day boundary while P5 replays a long run.

    python -m bench.c9_graph <loggen run dir> [out.json]
"""
from __future__ import annotations

import json
import random
import sys
import time

import numpy as np

from .core import Run
from .detectors.fusion import GraphFusion


def two_hop(adj, node):
    seen = set(adj.get(node, ()))
    for n in list(seen):
        seen |= adj.get(n, set())
    return seen


def measure(run_dir: str) -> dict:
    run = Run.load(run_dir)
    g = GraphFusion()
    g.name = "P5"
    g.setup(run)
    rng = random.Random(0)
    day_end = run.start + 86400
    lat: list[float] = []
    days = []
    for ev in run.events():
        while ev["_t"] >= day_end:
            nodes = list(g.adj)
            qs = []
            for node in rng.sample(nodes, min(1000, len(nodes))):
                t0 = time.perf_counter()
                two_hop(g.adj, node)
                qs.append(time.perf_counter() - t0)
            edges = sum(len(v) for v in g.adj.values()) // 2
            a = np.array(lat) * 1e6 if lat else np.zeros(1)
            days.append({"day": len(days) + 1, "nodes": len(nodes), "edges": edges, "events": len(lat),
                         "update_us": {"p50": float(np.percentile(a, 50)), "p99": float(np.percentile(a, 99))},
                         "two_hop_us": {"p50": float(np.percentile(np.array(qs) * 1e6, 50)) if qs else None,
                                        "p99": float(np.percentile(np.array(qs) * 1e6, 99)) if qs else None}})
            print(days[-1], flush=True)
            lat = []
            day_end += 86400
        t0 = time.perf_counter()
        g.process(ev)
        lat.append(time.perf_counter() - t0)
    return {"run": run_dir, "days": days}


if __name__ == "__main__":
    res = measure(sys.argv[1])
    json.dump(res, open(sys.argv[2] if len(sys.argv) > 2 else "experiments/results/C9_graph_scaling.json", "w"),
              indent=1)
