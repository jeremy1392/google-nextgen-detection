"""C2 / C6: the article's pipeline, stage by stage, co-located like a datacenter deployment.

    modal run modal_apps/e2e_local.py            # writes experiments/results/C2_e2e_local_v2.json

Everything runs inside ONE container: no network between stages (the architecture under study runs them in one
datacenter; the in-datacenter hop is added afterwards from a parameter, reported as modeled).
Measured, wall-clock, on real binaries (SOREL malware + benign PE from the volume):
  stage 1  on-host: read the binary from local disk, SHA-256, allow-list cache lookup, non-blocking enqueue
  stage 2  MalConv service: dynamic batching (max 32 files or 5 ms), GPU inference, result back
under a Poisson arrival process of new binaries at several rates. Stage 1 is also measured alone.
"""
from __future__ import annotations

import json
import os

import modal

app = modal.App("e2e-local")
vol = modal.Volume.from_name("malconv-data", create_if_missing=False)
image = (modal.Image.debian_slim(python_version="3.11")
         .pip_install("torch==2.5.1", "numpy==1.26.4")
         .add_local_python_source("bench"))
RATES = [50, 200, 500, 1000, 2000]


def _stage_files(n_each: int = 2000) -> list[str]:
    """Copy real binaries out of the shards onto local disk, as they would sit on a host."""
    import csv
    import random
    import zlib
    os.makedirs("/tmp/bin", exist_ok=True)
    rng = random.Random(0)
    picks = []
    for index, root, cond in (("/data/malware_index.csv", "/data/malware", lambda r: r["status"] == "ok"),
                              ("/data/benign_index.csv", "/data/benign", lambda r: True)):
        rows = [r for r in csv.DictReader(open(index)) if cond(r) and r.get("shard")]
        picks += [(root, r) for r in rng.sample(rows, min(n_each, len(rows)))]
    paths = []
    for root, r in picks:
        try:
            with open(f"{root}/{r['shard']}", "rb") as f:
                f.seek(int(r["offset"]))
                data = zlib.decompress(f.read(int(r["length"])))
        except Exception:
            continue
        p = f"/tmp/bin/{r['sha256']}"
        with open(p, "wb") as out:
            out.write(data)
        paths.append(p)
    return paths


def _run(gpu_label: str, seconds_per_rate: float = 20.0) -> dict:
    import hashlib
    import queue
    import random
    import threading
    import time

    import numpy as np
    import torch

    from bench.malconv import build
    paths = _stage_files()
    sizes = {p: os.path.getsize(p) for p in paths}
    allow = set()  # allow-list cache of known-good hashes (empty: every binary is new)

    def stage1(path, q):
        t0 = time.perf_counter()
        with open(path, "rb") as f:
            data = f.read()
        sha = hashlib.sha256(data).hexdigest()
        known = sha in allow
        if not known:
            q.put_nowait((time.perf_counter(), t0, data[:2_000_000], path))
        return time.perf_counter() - t0

    # Stage 1 alone, every file once (cold page cache is not reproducible in a container: files are warm).
    q0 = queue.Queue()
    s1 = sorted((stage1(p, q0), sizes[p]) for p in paths)
    stage1_ms = [x[0] * 1000 for x in s1]

    model = build().cuda().eval()
    out = {"gpu": torch.cuda.get_device_name(0), "files": len(paths),
           "median_file_bytes": int(np.median(list(sizes.values()))),
           "stage1_ms": {"p50": float(np.percentile(stage1_ms, 50)), "p95": float(np.percentile(stage1_ms, 95)),
                         "p99": float(np.percentile(stage1_ms, 99)), "max": float(max(stage1_ms)),
                         "share_under_5ms": float(np.mean(np.array(stage1_ms) < 5))},
           "buckets": BUCKETS, "modes": {}}
    # Warm-up: every bucket shape at several batch sizes, so no measured request pays for lazy CUDA
    # initialisation, kernel selection or allocator growth (the first C2 run measured those at 50 files/s).
    t_w = time.perf_counter()
    with torch.inference_mode(), torch.autocast("cuda", dtype=torch.bfloat16):
        for ln in BUCKETS:
            for b in (1, 2, 4, 8, 16, 32):
                for _ in range(3):
                    model(torch.ones((b, ln), dtype=torch.long, device="cuda"))
    torch.cuda.synchronize()
    out["warmup_s"] = round(time.perf_counter() - t_w, 2)

    def run_batch(items, pad_to):
        """Raw bytes (uint8) to the GPU in one copy; index shift and padding mask on the GPU."""
        lens = [len(b[2]) for b in items]
        x = torch.zeros((len(items), pad_to), dtype=torch.uint8).pin_memory()
        for i, b in enumerate(items):
            x[i, :lens[i]] = torch.from_numpy(np.frombuffer(b[2], dtype=np.uint8).copy())
        xg = x.cuda(non_blocking=True).long() + 1
        pad = torch.arange(pad_to, device="cuda")[None, :] >= torch.tensor(lens, device="cuda")[:, None]
        with torch.autocast("cuda", dtype=torch.bfloat16):
            model(xg.masked_fill(pad, 0)).float().cpu()

    for mode in ("single_pad", "bucketed"):
        out["modes"][mode] = [_serve(rate, mode, stage1, paths, run_batch, seconds_per_rate, gpu_label)
                              for rate in RATES]
    out["rates"] = out["modes"]["bucketed"]
    return out


BUCKETS = [65_536, 262_144, 1_048_576, 2_000_000]


def _serve(rate, mode, stage1, paths, run_batch, seconds_per_rate, gpu_label) -> dict:
    """One arrival rate. Dynamic batching (up to 32 files or 5 ms). single_pad: one batch padded to its
    longest file (shapes vary per batch). bucketed: the batch is split by length bucket and each part is
    padded to its bucket bound (four fixed shapes, small files no longer pay for a 2 MB neighbour)."""
    import queue
    import random
    import threading
    import time

    import numpy as np
    import torch
    q = queue.Queue()
    done = []
    stop = threading.Event()
    hosts = 16  # stage 1 runs on many hosts in parallel; each sends its share of the fleet's new binaries
    finished = []

    def producer(seed):
        rng = random.Random(rate * 100 + seed)
        t_end = time.perf_counter() + seconds_per_rate
        while time.perf_counter() < t_end:
            stage1(rng.choice(paths), q)
            time.sleep(rng.expovariate(rate / hosts))
        finished.append(seed)
        if len(finished) == hosts:
            stop.set()

    threads = [threading.Thread(target=producer, args=(i,)) for i in range(hosts)]
    for th in threads:
        th.start()
    with torch.inference_mode():
        while not (stop.is_set() and q.empty()):
            try:
                first = q.get(timeout=0.05)
            except queue.Empty:
                continue
            batch, deadline = [first], time.perf_counter() + 0.005
            while len(batch) < 32:
                left = deadline - time.perf_counter()
                if left <= 0:
                    break
                try:
                    batch.append(q.get(timeout=left))
                except queue.Empty:
                    break
            t_gpu = time.perf_counter()
            if mode == "single_pad":
                parts = [(batch, max(len(b[2]) for b in batch))]
            else:
                by = {}
                for b in batch:
                    by.setdefault(next(u for u in BUCKETS if len(b[2]) <= u), []).append(b)
                parts = [(by[u], u) for u in sorted(by)]  # small files first
            for items, pad_to in parts:
                run_batch(items, pad_to)
                t_out = time.perf_counter()
                for enq, t0, _, _ in items:
                    done.append({"queue_and_batch_ms": (t_gpu - enq) * 1000, "gpu_ms": (t_out - t_gpu) * 1000,
                                 "total_ms": (t_out - t0) * 1000, "batch": len(batch), "part": len(items)})
    for th in threads:
        th.join()
    tot = np.array([d["total_ms"] for d in done])
    return {
        "mode": mode, "files_per_s": rate, "served": len(done),
        "achieved_files_per_s": round(len(done) / seconds_per_rate, 1),
        "total_ms": {"p50": float(np.percentile(tot, 50)), "p95": float(np.percentile(tot, 95)),
                     "p99": float(np.percentile(tot, 99))},
        "queue_and_batch_ms_p50": float(np.median([d["queue_and_batch_ms"] for d in done])),
        "gpu_ms_p50": float(np.median([d["gpu_ms"] for d in done])),
        "mean_batch": float(np.mean([d["batch"] for d in done])),
        "share_under_50ms": float(np.mean(tot < 50)), "gpu_label": gpu_label}


@app.function(image=image, gpu="L4", volumes={"/data": vol}, timeout=3600, cpu=8, memory=32768)
def on_l4():
    return _run("L4")


@app.function(image=image, gpu="H100", volumes={"/data": vol}, timeout=3600, cpu=8, memory=32768)
def on_h100():
    return _run("H100")


@app.local_entrypoint()
def main(out: str = "experiments/results/C2_e2e_local_v2.json"):
    calls = {"L4": on_l4.spawn(), "H100": on_h100.spawn()}
    res = {k: c.get() for k, c in calls.items()}
    os.makedirs(os.path.dirname(out), exist_ok=True)
    json.dump(res, open(out, "w"), indent=1)
    for k, r in res.items():
        print(k, r["gpu"], "warm-up", r["warmup_s"], "s  stage1:", {a: round(b, 3) for a, b in r["stage1_ms"].items()})
        for mode, rows in r["modes"].items():
            for x in rows:
                print(f"   {mode:<10} {x['files_per_s']:>5} files/s  total p50 {x['total_ms']['p50']:.2f} "
                      f"p95 {x['total_ms']['p95']:.2f} p99 {x['total_ms']['p99']:.2f} ms  "
                      f"(<50ms: {x['share_under_50ms']:.3f}, batch {x['mean_batch']:.1f})")
