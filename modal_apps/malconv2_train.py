"""D1: MalConv2 / MalConvGCT (bench/malconv2.py) on whole PE files, same data and splits as MalConv (D1).

    modal run --detach modal_apps/malconv2_train.py::main     # train + score -> experiments/results/D1_malconv2.json

Reads the shards and /data/splits.csv staged for D1 (malconv_data.py, malconv_train.py::splits). Whole files are
read (up to MAX_BYTES; the count above it is reported), batched by similar length, and scored on the same test
sets as MalConv: newest SOREL months against held-out benign files of the training toolchains, and against benign
files from a toolchain never seen in training (MSVC). Nothing is executed.
"""
from __future__ import annotations

import modal

app = modal.App("malconv2-train")
vol = modal.Volume.from_name("malconv-data", create_if_missing=False)
image = (modal.Image.debian_slim(python_version="3.11")
         .pip_install("torch==2.5.1", "numpy==1.26.4", "scikit-learn==1.5.2", "scipy==1.14.1")
         .add_local_python_source("bench"))
MAX_BYTES = 64 << 20
OUT = "/data/results/malconv2"


def _items():
    import csv
    return [(int(r["label"]), r["split"], r["shard"], int(r["offset"]), int(r["length"]), r["sha256"])
            for r in csv.DictReader(open("/data/splits.csv"))]


def _root(shard: str) -> str:
    if shard.startswith("mal"):
        return "/data/malware"
    if shard.startswith("ben_"):
        return "/data/benign_" + shard.split("-")[0][4:]
    return "/data/benign"


def _tpr_at(y, p, fpr):
    import numpy as np
    from scipy.stats import beta
    y, p = np.asarray(y), np.asarray(p)
    neg = np.sort(p[y == 0])[::-1]
    k = int(np.floor(fpr * len(neg)))
    thr = neg[k] if len(neg) > k else neg[-1]
    pos = p[y == 1]
    tp = int((pos > thr).sum())
    n = len(pos)
    lo = beta.ppf(0.025, tp, n - tp + 1) if tp > 0 else 0.0
    hi = beta.ppf(0.975, tp + 1, n - tp) if tp < n else 1.0
    return {"fpr_target": fpr, "threshold": float(thr), "tpr": tp / max(n, 1), "tpr_ci95": [round(float(lo), 4), round(float(hi), 4)]}


@app.function(image=image, gpu="A100-80GB", volumes={"/data": vol}, timeout=12 * 3600, cpu=16, memory=65536)
def train(epochs: int = 4, batch: int = 16, lr: float = 1e-3, seed: int = 0, limit: int = 0, out: str = OUT) -> dict:
    import json
    import os
    import random
    import time
    import zlib

    import numpy as np
    import torch
    from torch.utils.data import DataLoader, IterableDataset

    from bench.malconv2 import build

    torch.manual_seed(seed)
    torch.backends.cudnn.benchmark = True
    torch.backends.cuda.matmul.allow_tf32 = True
    torch.backends.cudnn.allow_tf32 = True
    os.makedirs(out, exist_ok=True)
    items = _items()
    by = {}
    for it in items:
        by.setdefault(it[1], []).append(it)
    if limit:  # smoke test: a few files of every split, both classes
        rnd = random.Random(seed)
        by = {k: rnd.sample([i for i in v if i[0] == 1], min(limit, sum(i[0] == 1 for i in v)))
              + rnd.sample([i for i in v if i[0] == 0], min(limit, sum(i[0] == 0 for i in v))) for k, v in by.items()}
    tr = by["train"]
    n_mal = sum(i[0] for i in tr)
    n_ben = len(tr) - n_mal

    class Batches(IterableDataset):
        """Shard-ordered reading; within a buffer of 256 files, batches of similar length (less padding)."""

        def __init__(self, its, shuffle, epoch=0):
            self.its, self.shuffle, self.epoch = its, shuffle, epoch

        def __iter__(self):
            info = torch.utils.data.get_worker_info()
            groups = {}
            for it in self.its:
                groups.setdefault(it[2], []).append(it)
            keys = sorted(groups)
            rng = random.Random(seed * 1000 + self.epoch)
            if self.shuffle:
                rng.shuffle(keys)
            if info:
                keys = keys[info.id::info.num_workers]
            buf = []

            def flush():
                buf.sort(key=lambda r: len(r[0]))
                bs = [buf[i:i + batch] for i in range(0, len(buf), batch)]
                if self.shuffle:
                    rng.shuffle(bs)
                buf.clear()
                return bs

            for k in keys:
                g = sorted(groups[k], key=lambda x: x[3])
                if self.shuffle:
                    rng.shuffle(g)
                with open(f"{_root(k)}/{k}", "rb") as f:
                    for label, _, shard, off, ln, sha in g:
                        try:
                            f.seek(off)
                            data = zlib.decompress(f.read(ln))
                        except Exception:
                            continue
                        buf.append((np.frombuffer(data[:MAX_BYTES], dtype=np.uint8), label, sha, len(data)))
                        if len(buf) >= 256:
                            yield from flush()
            if buf:
                yield from flush()

    def collate(rows):
        n = max(len(r[0]) for r in rows)
        x = torch.zeros((len(rows), max(n, 256)), dtype=torch.uint8)
        for i, r in enumerate(rows):
            x[i, :len(r[0])] = torch.from_numpy(r[0].copy())
        return (x, torch.tensor([len(r[0]) for r in rows]), torch.tensor([r[1] for r in rows], dtype=torch.float32),
                [r[2] for r in rows], [r[3] for r in rows])

    model = build().cuda()
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    loss_fn = torch.nn.BCEWithLogitsLoss(pos_weight=torch.tensor([n_ben / max(n_mal, 1)], device="cuda"))

    def scores(its, timing=None):
        model.eval()
        out = []
        dl = DataLoader(Batches(its, False), batch_size=None, num_workers=14, collate_fn=collate)
        with torch.no_grad(), torch.autocast("cuda", dtype=torch.bfloat16):
            for x, lens, y, sha, full in dl:
                t0 = time.perf_counter()
                p = torch.sigmoid(model(x.cuda(non_blocking=True), lens.cuda()).float()).cpu().numpy()
                if timing is not None:
                    torch.cuda.synchronize()
                    timing.append((time.perf_counter() - t0, int(lens.sum()), len(sha)))
                out += list(zip(sha, y.numpy().tolist(), p.tolist(), full))
        model.train()
        return out

    def auc(rows):
        from sklearn.metrics import roc_auc_score
        y = [r[1] for r in rows]
        return float(roc_auc_score(y, [r[2] for r in rows])) if 0 < sum(y) < len(y) else None

    ckpt = f"{out}/ckpt.pt"
    history, best, start = [], (-1.0, None), 0
    if os.path.exists(ckpt):  # restarted after a preemption
        c = torch.load(ckpt, weights_only=False)
        model.load_state_dict(c["model"])
        opt.load_state_dict(c["opt"])
        history, best, start = c["history"], tuple(c["best"]), c["epoch"] + 1
        print("resuming at epoch", start, flush=True)
    for epoch in range(start, epochs):
        t0, seen, total = time.time(), 0, 0.0
        dl = DataLoader(Batches(tr, True, epoch), batch_size=None, num_workers=14, collate_fn=collate, prefetch_factor=4)
        for x, lens, y, _, _ in dl:
            with torch.autocast("cuda", dtype=torch.bfloat16):
                loss = loss_fn(model(x.cuda(non_blocking=True), lens.cuda()).float(), y.cuda())
            opt.zero_grad(set_to_none=True)
            loss.backward()
            opt.step()
            seen += len(y)
            total += float(loss) * len(y)
        v = auc(scores(by["val"]))
        history.append({"epoch": epoch, "train_loss": total / max(seen, 1), "val_auc": v,
                        "seconds": round(time.time() - t0, 1), "samples": seen})
        print(history[-1], flush=True)
        if v is not None and v > best[0]:
            best = (v, epoch)
            torch.save(model.state_dict(), f"{out}/best.pt")
        torch.save({"model": model.state_dict(), "opt": opt.state_dict(), "history": history, "best": list(best),
                    "epoch": epoch}, ckpt)
        vol.commit()
    model.load_state_dict(torch.load(f"{out}/best.pt", weights_only=True))
    timing = []
    test = scores(by["test"], timing)
    unseen = [r for r in test if r[1] == 1] + scores(by["test_unseen_toolchain"])
    for name, rows in (("test", test), ("test_unseen_toolchain", unseen)):
        with open(f"{out}/scores_{name}.csv", "w") as f:
            f.write("sha256,label,score,size\n")
            f.writelines(f"{s},{int(y)},{p:.6f},{n}\n" for s, y, p, n in rows)
    res = {"model": "MalConvGCT (C=256, W=256, S=64), whole files up to 64 MB", "history": history,
           "best_epoch": best[1], "train_mal": n_mal, "train_ben": n_ben}
    for name, rows in (("test", test), ("test_unseen_toolchain", unseen)):
        y = [r[1] for r in rows]
        p = [r[2] for r in rows]
        sweep = []
        for thr in (0.01, 0.1, 0.5, 0.9, 0.99):
            mal = [q for q, yy in zip(p, y) if yy == 1]
            ben = [q for q, yy in zip(p, y) if yy == 0]
            sweep.append({"threshold": thr, "malware_missed": sum(q <= thr for q in mal) / max(len(mal), 1),
                          "benign_escalated": sum(q > thr for q in ben) / max(len(ben), 1)})
        big = [r for r in rows if r[3] > 2_000_000]
        res[name] = {"n_mal": sum(y), "n_ben": len(y) - sum(y), "roc_auc": auc(rows),
                     "tpr_at_fpr": [_tpr_at(y, p, f) for f in (1e-2, 1e-3, 1e-4)], "sandbox_sweep": sweep,
                     "files_over_2mb": len(big), "files_over_64mb": sum(r[3] > MAX_BYTES for r in rows),
                     "roc_auc_files_over_2mb": auc(big) if big else None}
    secs = sum(t for t, _, _ in timing)
    res["inference"] = {"files_per_s": round(sum(n for _, _, n in timing) / max(secs, 1e-9), 1),
                        "mb_per_s": round(sum(b for _, b, _ in timing) / 1e6 / max(secs, 1e-9), 1), "batch": batch}
    import json as _j
    _j.dump(res, open(f"{out}/report.json", "w"), indent=1)
    vol.commit()
    return res


@app.local_entrypoint()
def main(out: str = "experiments/results/D1_malconv2.json"):
    import json
    res = train.remote()
    json.dump(res, open(out, "w"), indent=1)
    print(json.dumps({k: res[k] for k in ("best_epoch",)}, indent=1))
    for name in ("test", "test_unseen_toolchain"):
        r = res[name]
        print(name, "AUC", r["roc_auc"], [(t["fpr_target"], round(t["tpr"], 4)) for t in r["tpr_at_fpr"]])


@app.local_entrypoint()
def smoke():
    import json
    res = train.remote(epochs=1, limit=150, out="/data/results/malconv2_smoke2")
    print(json.dumps({k: res[k] for k in ("history", "inference")}, indent=1))
    print("test AUC", res["test"]["roc_auc"], "unseen AUC", res["test_unseen_toolchain"]["roc_auc"])
