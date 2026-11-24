"""F6, edge level: among the interactions first met after the warm-up, does a GNN rank the attacker's above
the benign newcomers better than classic link-prediction heuristics?

    python -m bench.f6_gnn generator [--seeds 3] [--conditions base,drift,mix]   # loggen runs
    python -m bench.f6_gnn summary

Scores (higher = more anomalous), all fitted on the warm-up graph only:
  gnn        -logit of the P10 GraphSAGE link predictor (bench/detectors/gnn.py)
  pref_att   preferential attachment: -(log(1+deg u) + log(1+deg v))
  cf         collaborative filtering: -(similarity of u to the other sources of v), cosine on neighbour sets
  unseen     1 if u or v never appeared in the warm-up graph, else 0
Labels: an edge is anomalous if one of the events that carry it belongs to an anomaly case. Metrics: ROC-AUC,
average precision, and the share of anomalous edges among the top 1% / 5% of new edges.
Results: experiments/results/F6_gnn_edges.json
"""
from __future__ import annotations

import argparse
import json
import math
import os
import sys
from collections import defaultdict

OUT = "experiments/results/F6_gnn_edges.json"
CACHE = "experiments/cache_f6"


def _heuristics(train_edges):
    nb = defaultdict(set)
    src_of = defaultdict(set)  # v -> sources
    for u, v in train_edges:
        nb[u].add(v)
        nb[v].add(u)
        src_of[v].add(u)

    def pref(u, v):
        return -(math.log1p(len(nb.get(u, ()))) + math.log1p(len(nb.get(v, ()))))

    def cf(u, v):
        nu = nb.get(u)
        if not nu:
            return 0.0
        best = 0.0
        for x in src_of.get(v, ()):
            nx = nb.get(x)
            if nx:
                best = max(best, len(nu & nx) / math.sqrt(len(nu) * len(nx)))
        return -best

    def unseen(u, v):
        return float(u not in nb or v not in nb)

    return {"pref_att": pref, "cf": cf, "unseen": unseen}


def _metrics(y, s):
    from sklearn.metrics import average_precision_score, roc_auc_score
    if not (0 < sum(y) < len(y)):
        return {"auc": None, "ap": None}
    order = sorted(range(len(s)), key=lambda i: -s[i])
    top = lambda q: (sum(y[i] for i in order[:max(1, int(q * len(order)))]) / max(1, int(q * len(order))))
    return {"auc": round(float(roc_auc_score(y, s)), 4), "ap": round(float(average_precision_score(y, s)), 4),
            "precision_top1pct": round(top(0.01), 4), "precision_top5pct": round(top(0.05), 4)}


def edge_eval(run, warmup_h: float = 12.0, label: str = "") -> dict:
    from .core import replay
    from .detectors.gnn import LinkGNN, edges_of
    d = LinkGNN(warmup_h=warmup_h)
    d.name = "P10"
    replay(run, [d])
    heur = _heuristics(d.first_seen)
    lab, first = {}, {}
    for ev in run.events():
        if ev["_t"] < d.learn_until:
            continue
        c = run.by_event.get(ev["event_id"])
        for e in edges_of(ev):
            if e in d.first_seen:
                continue
            first.setdefault(e, ev["_t"])
            if c and c[1] == "anomaly":
                lab[e] = c[0]
    edges = list(first)
    y = [int(e in lab) for e in edges]
    scores = {"gnn": [d._raw(*e) for e in edges]}
    big = max([x for x in scores["gnn"] if math.isfinite(x)] or [0.0]) + 1.0
    scores["gnn"] = [x if math.isfinite(x) else big for x in scores["gnn"]]
    for name, f in heur.items():
        scores[name] = [f(*e) for e in edges]
    return {"run": label, "train": d.stats, "new_edges": len(edges), "anomalous_new_edges": sum(y),
            "anomaly_cases_with_new_edges": len(set(lab.values())),
            "metrics": {k: _metrics(y, v) for k, v in scores.items()},
            "_edges": [(e[0], e[1], yy, {k: scores[k][i] for k in scores}) for i, (e, yy) in enumerate(zip(edges, y))]}


def generator(seeds: int, conditions: list[str]) -> dict:
    from .core import Run
    from .suite import CONDITIONS, _gen
    os.makedirs(CACHE, exist_ok=True)
    rows = []
    for cond in conditions:
        for seed in range(1, seeds + 1):
            path = os.path.join(CACHE, f"{cond}_s{seed}")
            _gen(path, seed, CONDITIONS[cond])
            r = edge_eval(Run.load(path), label=f"{cond}_s{seed}")
            r.update(condition=cond, seed=seed)
            print(cond, seed, r["new_edges"], r["anomalous_new_edges"],
                  {k: v["auc"] for k, v in r["metrics"].items()}, file=sys.stderr, flush=True)
            rows.append(r)
    return {"dataset": "loggen", "runs": rows}


def summary(res: dict) -> dict:
    """Pooled over runs: the edges of every run together (scores are comparable only within a run, so the
    pooled metric is the mean of per-run metrics plus the pooled counts)."""
    from statistics import mean
    out = {}
    for cond in dict.fromkeys(r["condition"] for r in res["runs"]):
        sel = [r for r in res["runs"] if r["condition"] == cond]
        cell = {"runs": len(sel), "new_edges": sum(r["new_edges"] for r in sel),
                "anomalous_new_edges": sum(r["anomalous_new_edges"] for r in sel)}
        for k in sel[0]["metrics"]:
            for m in ("auc", "ap", "precision_top1pct", "precision_top5pct"):
                vals = [r["metrics"][k].get(m) for r in sel if r["metrics"][k].get(m) is not None]
                cell[f"{k}_{m}"] = round(mean(vals), 3) if vals else None
        out[cond] = cell
    return out


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="bench.f6_gnn")
    sub = p.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generator")
    g.add_argument("--seeds", type=int, default=3)
    g.add_argument("--conditions", default="base,drift,mix")
    sub.add_parser("summary")
    a = p.parse_args(argv)
    if a.cmd == "generator":
        res = generator(a.seeds, a.conditions.split(","))
        res["summary"] = summary(res)
        for r in res["runs"]:
            r.pop("_edges", None)
        json.dump(res, open(OUT, "w", encoding="utf-8"), indent=1)
        print(json.dumps(res["summary"], indent=1))
    else:
        res = json.load(open(OUT, encoding="utf-8"))
        print(json.dumps(summary(res), indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
