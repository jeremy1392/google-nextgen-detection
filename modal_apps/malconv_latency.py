"""C2 / D1 latency: MalConv inference time per file on dedicated Modal CPU and GPU containers.

    modal run modal_apps/malconv_latency.py

Random bytes only (latency does not depend on content), so no malware is involved.
Writes experiments/results/D1_malconv_latency.json.
"""
from __future__ import annotations

import json
import os

import modal

app = modal.App("malconv-latency")
image = (modal.Image.debian_slim(python_version="3.11")
         .pip_install("torch==2.5.1", "numpy==1.26.4")
         .add_local_python_source("bench"))


def _run(device: str, threads=(None,)):
    from bench.malconv import latency_bench
    import torch
    info = {"torch": str(torch.__version__),
            "gpu": torch.cuda.get_device_name(0) if device == "cuda" else None,
            "cpus": os.cpu_count()}
    return {"info": info, "rows": latency_bench(device, threads=threads)}


@app.function(image=image, cpu=8.0, memory=16384, timeout=1800)
def cpu8():
    return _run("cpu", threads=(1, 4, 8))


@app.function(image=image, gpu="T4", timeout=900)
def t4():
    return _run("cuda")


@app.function(image=image, gpu="L4", timeout=900)
def l4():
    return _run("cuda")


@app.function(image=image, gpu="A10G", timeout=900)
def a10g():
    return _run("cuda")


@app.function(image=image, gpu="H100", timeout=900)
def h100():
    return _run("cuda")


@app.local_entrypoint()
def main(out: str = "experiments/results/D1_malconv_latency.json"):
    calls = {name: fn.spawn() for name, fn in
             {"cpu8": cpu8, "T4": t4, "L4": l4, "A10G": a10g, "H100": h100}.items()}
    results = {}
    for name, call in calls.items():
        try:
            results[name] = call.get()
        except Exception as exc:  # report and continue with the other targets
            results[name] = {"error": f"{type(exc).__name__}: {exc}"}
        print(name, "done" if "rows" in results[name] else results[name]["error"])
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=1)
    for name, r in results.items():
        for row in r.get("rows", []):
            if row.get("file_bytes") == 2_000_000 and row.get("batch") in (1, 32) and "baseline" not in row:
                print(f"{name:<6} threads={row['threads']:<3} batch={row['batch']:<3} 2MB: "
                      f"{row['ms_per_file_p50']} ms/file (model only {row['model_only_ms_per_file_p50']}), "
                      f"{row['files_per_s']} files/s")
