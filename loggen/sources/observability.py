"""Observability, decoupled from the critical path: Dapper sampled spans, Monarch time
series, and the unsampled RPC edge log (counts per caller/callee/method)."""
from __future__ import annotations

from ..world import CELLS

WINDOW = 300


def install(sim, w) -> None:
    sim.every(60, lambda t, p: _dapper(sim, w, t, p), phase=15)
    win = sim.agg_window
    sim.every(win, lambda t, p: _monarch(sim, w, t, p), phase=win - 2)
    sim.every(win, lambda t, p: _edges(sim, w, t, p), phase=win - 1)


# ---------------------------------------------------------------------- Dapper
def _tree(sim, w, svc: str, method: str, depth: int) -> dict:
    s = w.services[svc]
    own = sim.rng.lognormvariate(0, 0.5) * s.latency_ms * 0.3
    children = []
    if depth < 3:
        for callee, m in s.calls:
            if sim.rng.random() < 0.7:
                children.append(_tree(sim, w, callee, m, depth + 1))
    return {"svc": svc, "method": method, "ms": own + sum(c["ms"] for c in children), "own": own, "children": children}


def _emit_tree(sim, w, node, trace_id, parent, ts, cell) -> None:
    span_id = sim.hex(16)
    task = w.random_task(sim.rng, node["svc"], cell)
    ok = sim.rng.random() > 0.004
    sim.emit(ts, "obs.dapper", "span",
             {"span_id": span_id, "parent_span_id": parent, "service": node["svc"],
              "method": f"{node['svc']}.{node['method']}", "duration_ms": round(node["ms"], 3),
              "status": "OK" if ok else sim.rng.choice(["DEADLINE_EXCEEDED", "UNAVAILABLE"]), "sampling": "1/1024"},
             site=CELLS[task.cell]["site"], cell=task.cell, job=node["svc"], task=task.id,
             principal=w.services[node["svc"]].principal, trace_id=trace_id)
    offset = ts + node["own"] / 2000.0
    for child in node["children"]:
        _emit_tree(sim, w, child, trace_id, span_id, offset, task.cell)
        offset += child["ms"] / 1000.0


def _dapper(sim, w, t, period) -> None:
    r = sim.rng
    for _ in range(sim.poisson(6 * sim.scale * sim.dapper_rate * sim.prod_load(t))):
        root = r.choice(w.frontends)
        _emit_tree(sim, w, _tree(sim, w, root.name, "Serve", 0), sim.hex(16), None, t + r.random() * period,
                   r.choice(root.cells))


# ---------------------------------------------------------------------- Monarch
def _monarch(sim, w, t, period) -> None:
    r = sim.rng
    t0 = t - period
    load = sim.prod_load(t)
    ovs = sim.overlays("metric", t0, t)
    for s in w.services.values():
        for cell in s.cells:
            share = 0.6 if cell == "zrh-c1" or len(s.cells) == 1 else 0.4
            share = 1.0 if len(s.cells) == 1 else share
            qps = s.qps * share * load * sim.noise(0.08)
            if s.frontend:
                egress = qps * period * 18_000
            elif s.egress:
                egress = 4e9 * sim.noise(0.3)
            else:
                egress = 2e6 * sim.noise(0.5)
            m = {"qps": qps, "error_ratio": 0.0008 * sim.noise(0.4), "latency_p99_ms": s.latency_ms * 2.5 * sim.noise(0.15),
                 "cpu_cores": len(w.tasks[(s.name, cell)]) * (12 if s.tpu else 3) * load * sim.noise(0.1),
                 "egress_bytes": egress}
            label = None
            for o in ovs:
                svc, c, metric = o["key"]
                if svc == s.name and c == cell:
                    m[metric] *= o["value"]
                    label = label or o["label"]
            sim.emit(t + r.uniform(0, 3), "obs.monarch", "timeseries_point",
                     {"window_s": period, "metrics": {k: round(v, 6 if k == "error_ratio" else 1) for k, v in m.items()},
                      "target": f"/{cell}/{s.name}", "collector": f"monarch-collector.{cell}"},
                     label=label, site=CELLS[cell]["site"], cell=cell, job=s.name, principal=s.principal)


# ---------------------------------------------------------------------- F3: per-edge span sampling
def _aux_poisson(sim, lam: float) -> int:
    a = sim.aux_rng
    if lam <= 0:
        return 0
    if lam > 30:
        return max(0, int(round(a.gauss(lam, lam ** 0.5))))
    k, p, limit = 0, 1.0, pow(2.718281828459045, -lam)
    while True:
        p *= a.random()
        if p <= limit:
            return k
        k += 1


def _edge_spans(sim, t0, period, caller, callee, method, cell, calls, label) -> None:
    """Spans for the calls of one edge in one window. uniform: each call sampled at the Dapper rate;
    adaptive: a call is sampled with probability max(rate, 8 / (1 + calls of this edge seen so far)), so a
    never-seen edge has its first calls traced. At most 20 spans per edge and window. Drawn from aux_rng."""
    key = (caller, callee, method)
    base = sim.dapper_rate / 1024.0
    seen = sim.dapper_seen.get(key, 0)
    p = base if sim.dapper_edges == "uniform" else max(base, min(1.0, 8.0 / (1.0 + seen)))
    sim.dapper_seen[key] = seen + calls
    k = min(20, _aux_poisson(sim, calls * p))
    a = sim.aux_rng
    for _ in range(k):
        sim.emit(t0 + a.random() * period, "obs.dapper", "span",
                 {"span_id": sim.aux_hex(16), "parent_span_id": None, "service": callee, "caller": f"svc:{caller}",
                  "method": f"{callee}.{method}", "duration_ms": round(a.lognormvariate(1.5, 0.6), 3), "status": "OK",
                  "sampling": f"edge/{sim.dapper_edges}"},
                 label=label, site=CELLS[cell]["site"], cell=cell, job=callee, principal=f"svc:{callee}",
                 eid=sim.aux_hex(32))


# ---------------------------------------------------------------------- edge log
def _edges(sim, w, t, period) -> None:
    """Every RPC counted, nothing sampled: the complete call graph per window."""
    r = sim.rng
    t0 = t - period
    load = sim.prod_load(t)
    rows: dict[tuple, dict] = {}
    for s in w.callers:
        for cell in s.cells:
            for callee, method in s.calls:
                if cell not in w.services[callee].cells:
                    continue
                calls = s.qps * load * period / max(len(s.calls), 1) * (0.6 if cell == "zrh-c1" else 0.4) * sim.noise(0.1)
                rows[(s.name, callee, method, cell)] = {"calls": calls, "label": None}
    for o in sim.overlays("edge", t0, t):
        row = rows.setdefault(o["key"], {"calls": 0.0, "label": None})
        row["calls"] += o["value"] * (min(o["t1"], t) - max(o["t0"], t0)) / period
        row["label"] = row["label"] or o["label"]
    for (caller, callee, method, cell), row in rows.items():
        n = int(row["calls"])
        if n <= 0:
            continue
        sim.emit(t + r.uniform(0, 3), "obs.rpc_edge", "edge_window",
                 {"window_s": period, "caller": f"svc:{caller}", "callee": f"svc:{callee}",
                  "method": f"{callee}.{method}", "calls": n, "errors": sim.poisson(n * 0.0008),
                  "bytes": int(n * r.uniform(800, 6000))},
                 label=row["label"], site=CELLS[cell]["site"], cell=cell, job=caller, principal=f"svc:{caller}")
        if sim.dapper_edges != "off":
            _edge_spans(sim, t0, period, caller, callee, method, cell, n, row["label"])
