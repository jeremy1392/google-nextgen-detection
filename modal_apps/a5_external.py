"""A5: the pipelines on real public data (CERT r4.2 insiders, LANL red team), one container per pipeline.

    modal run modal_apps/a5_external.py::prepare          # extract CERT r4.2 + answers (once)
    modal run --detach modal_apps/a5_external.py::cert    # writes experiments/results/A5_cert_r42.json
    modal run --detach modal_apps/a5_external.py::lanl    # writes experiments/results/A5_lanl.json

Warm-up (learning only, not scored): 30 days for CERT, 7 days for LANL.
"""
from __future__ import annotations

import json
import os

import modal

app = modal.App("a5-external")
vol = modal.Volume.from_name("detection-data", create_if_missing=False)
image = (modal.Image.debian_slim(python_version="3.11")
         .pip_install("numpy==1.26.4", "scikit-learn==1.5.2", "scipy==1.14.1")
         .pip_install("torch==2.4.1", index_url="https://download.pytorch.org/whl/cpu")
         .add_local_python_source("bench", "loggen"))
PIPES = ["P2", "P3", "P4", "P5", "P6", "P6-hyper", "P6+P4"]


@app.function(image=image, volumes={"/data": vol}, timeout=6 * 3600, cpu=4, memory=16384)
def extract(release: str = "r4.2"):
    import tarfile
    out = {}
    for name, dest in ((f"{release}.tar.bz2", "/data/cert/extract"), ("answers.tar.bz2", "/data/cert/extract")):
        os.makedirs(dest, exist_ok=True)
        with tarfile.open(f"/data/cert/{name}", "r:bz2") as t:
            t.extractall(dest)
            out[name] = len(t.getnames())
    vol.commit()
    listing = {}
    for root, _, files in os.walk("/data/cert/extract"):
        if files and root.count("/") <= 6:
            listing[root] = sorted(files)[:12]
    return {"members": out, "listing": listing}


def _detectors(names, warmup_h):
    from functools import partial

    from bench.detectors import PIPELINES
    from bench.detectors.baseline import Baselines
    from bench.detectors.fusion import Fusion, GraphFusion
    from bench.detectors.ml import IForest
    from bench.detectors.sequence import NGram
    table = {"P2": partial(Baselines, warmup_h=warmup_h), "P3": partial(IForest, warmup_h=warmup_h),
             "P4": partial(NGram, warmup_h=warmup_h), "P5": partial(GraphFusion, warmup_h=warmup_h),
             "P5-hyper": partial(GraphFusion, rarity="hyper", warmup_h=warmup_h),
             "P6": partial(Fusion, warmup_h=warmup_h), "P6-hyper": partial(Fusion, rarity="hyper", warmup_h=warmup_h),
             "P6+P4": partial(Fusion, extra=("P4",), rarity="hyper", distinct="detectors", warmup_h=warmup_h)}
    dets = []
    for n in names:
        d = (table.get(n) or PIPELINES[n])()
        d.name = n
        dets.append(d)
    return dets


@app.function(image=image, volumes={"/data": vol}, timeout=24 * 3600, cpu=2, memory=16384, nonpreemptible=True)
def run_one(dataset: str, pipeline: str):
    """One pipeline over one dataset. Non-preemptible: a full LANL pass takes hours and has no checkpoint.
    The result is also written to the volume, so it survives the local client."""
    from bench.core import replay
    from bench.external import CertRun, LanlRun
    from bench.score import latency, score
    if dataset == "cert":
        root = _find("/data/cert/extract", "logon.csv")
        answers = _find("/data/cert/extract", "insiders.csv")
        run = CertRun.load_cert(root, answers, "r4.2")
        warm = 30 * 24.0
    else:
        run = LanlRun.load_lanl("/data/lanl")
        warm = 7 * 24.0
    dets = _detectors([pipeline], warm)
    alerts, timing = replay(run, dets)
    m = score(run, alerts[pipeline], eval_from=run.start + warm * 3600)
    res = {"dataset": dataset, "pipeline": pipeline, "events": timing["_events"],
           "wall_s": round(timing["_wall_s"], 1), **m, "latency": latency(timing[pipeline])}
    os.makedirs("/data/results/a5", exist_ok=True)
    json.dump(res, open(f"/data/results/a5/{dataset}_{pipeline}.json", "w"), indent=1)
    vol.commit()
    return res


def _find(base: str, filename: str) -> str:
    for root, _, files in os.walk(base):
        if filename in files:
            return root
    raise FileNotFoundError(f"{filename} under {base}")


def _collect(dataset: str, out: str, pipes=PIPES):
    rows = list(run_one.starmap([(dataset, p) for p in pipes], return_exceptions=True))
    res = [r if isinstance(r, dict) else {"pipeline": p, "error": repr(r)} for p, r in zip(pipes, rows)]
    os.makedirs(os.path.dirname(out), exist_ok=True)
    json.dump(res, open(out, "w"), indent=1)
    for r in res:
        if "error" in r:
            print(r["pipeline"], "ERROR", r["error"][:300])
        else:
            print(f"{r['pipeline']:<9} events {r['events']:,}  cases {r['cases']}  recall {r['recall']}  "
                  f"precision {r['precision']}  FP/day {r['fp_per_day']}  R@10FP/d {r['recall_at_fp_per_day'].get('10/day')}"
                  f"  TTD p50 {r['ttd_s']['p50']} s")


@app.local_entrypoint()
def prepare():
    print(json.dumps(extract.remote(), indent=1)[:3000])


@app.local_entrypoint()
def cert(out: str = "experiments/results/A5_cert_r42.json"):
    _collect("cert", out)


@app.local_entrypoint()
def lanl(out: str = "experiments/results/A5_lanl.json"):
    _collect("lanl", out, ["P2", "P3", "P4", "P5-hyper", "P6-hyper"])


@app.function(image=image, volumes={"/data": vol}, timeout=4 * 3600, cpu=2, memory=16384)
def ueba_stats(dataset: str) -> dict:
    """A1 (human side): the same behaviour statistics as bench.a1_ueba computes on the generator."""
    from bench.a1_ueba import cert_stats, lanl_stats
    if dataset == "lanl":
        return lanl_stats("/data/lanl/auth.txt.gz", days=14)
    kind = dataset.split("_")[1]  # cert_logon / cert_http
    return cert_stats(os.path.join(_find("/data/cert/extract", f"{kind}.csv"), f"{kind}.csv"), kind)


@app.local_entrypoint()
def ueba(out_dir: str = "experiments/results", only: str = "lanl,cert_logon,cert_http"):
    calls = {d: ueba_stats.spawn(d) for d in only.split(",")}
    for d, c in calls.items():
        res = c.get()
        json.dump(res, open(os.path.join(out_dir, f"A1_ueba_stats_{d}.json"), "w"), indent=1)
        print(d, {k: v for k, v in res.items() if k not in ("hour_profile_weekday", "active_hours_per_user_day")})


@app.function(image=image, volumes={"/data": vol}, timeout=24 * 3600, cpu=2, memory=24576, nonpreemptible=True)
def run_multi(dataset: str, pipelines: list[str]) -> list[dict]:
    """Several pipelines in ONE pass over the data (they share the parsing). P10 also records the edge-level
    scores of every edge first met after the warm-up (F6). Each result goes to the volume as soon as it is
    scored, so a preempted run loses nothing that was already written."""
    from bench.core import replay
    from bench.external import CertRun, LanlRun, external_detectors
    from bench.score import latency, score
    if dataset == "cert":
        run = CertRun.load_cert(_find("/data/cert/extract", "logon.csv"), _find("/data/cert/extract", "insiders.csv"),
                                "r4.2")
        warm = 30 * 24.0
    else:
        run = LanlRun.load_lanl("/data/lanl")
        warm = 7 * 24.0
    dets = external_detectors(pipelines, warm)
    for d in dets:
        if d.name == "P10":
            d.record_edges = True
    alerts, timing = replay(run, dets)
    out = []
    os.makedirs("/data/results/a5", exist_ok=True)
    for d in dets:
        m = score(run, alerts[d.name], eval_from=run.start + warm * 3600)
        res = {"dataset": dataset, "pipeline": d.name, "events": timing["_events"], "wall_s": round(timing["_wall_s"], 1),
               **m, "latency": latency(timing[d.name])}
        if d.name == "P10":
            res["gnn"] = {"train": d.stats, "edges": d.edge_metrics()}
        json.dump(res, open(f"/data/results/a5/{dataset}_{d.name}.json", "w"), indent=1)
        vol.commit()
        out.append(res)
    return out


@app.local_entrypoint()
def lanl_gnn(out: str = "experiments/results/A5_lanl_gnn.json"):
    res = run_multi.remote("lanl", ["P10", "P6-hyper+P10"])
    json.dump(res, open(out, "w"), indent=1)
    for r in res:
        print(r["pipeline"], "recall", r["recall"], "FP/day", r["fp_per_day"], "R@10", r["recall_at_fp_per_day"].get("10/day"),
              r.get("gnn", {}).get("edges"))
