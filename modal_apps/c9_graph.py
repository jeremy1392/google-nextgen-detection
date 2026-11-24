"""C9 on Modal: generate 30 simulated days, then measure graph growth and latency day by day.

    modal run --detach modal_apps/c9_graph.py     # writes experiments/results/C9_graph_scaling.json
"""
from __future__ import annotations

import json
import os

import modal

app = modal.App("c9-graph")
vol = modal.Volume.from_name("detection-data", create_if_missing=False)
image = (modal.Image.debian_slim(python_version="3.11")
         .pip_install("numpy==1.26.4", "scikit-learn==1.5.2", "scipy==1.14.1")
         .add_local_python_source("bench", "loggen"))


@app.function(image=image, volumes={"/data": vol}, timeout=12 * 3600, cpu=4, memory=65536)
def run(days: int = 30):
    from bench.c9_graph import measure
    from loggen.cli import main as loggen_main
    out = f"/data/c9/run_{days}d"
    if not os.path.exists(os.path.join(out, "manifest.json")):
        loggen_main(["--out", out, "--duration", f"{days}d", "--seed", "11"])
        vol.commit()
    return measure(out)


@app.local_entrypoint()
def main(out: str = "experiments/results/C9_graph_scaling.json"):
    res = run.remote()
    os.makedirs(os.path.dirname(out), exist_ok=True)
    json.dump(res, open(out, "w"), indent=1)
    for d in res["days"][::3] + res["days"][-1:]:
        print(d)
