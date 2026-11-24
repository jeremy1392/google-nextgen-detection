"""MalConv on real binaries (D1, D2, D3, D7). Reads the shards staged by malconv_data.py.

    modal run --detach modal_apps/malconv_train.py::train --gpu-epochs 6
    modal run modal_apps/malconv_train.py::report

Splits: malware keeps SOREL's temporal split (train = oldest 70% first-seen, val = next 15%, test = newest
15%). Benign files are split 70/15/15 at random within each source, and one whole source family
(MSVC-built: python_embed, dotnet, powershell) is also held out as "unseen-toolchain" benign test to
measure whether the model learned the toolchain instead of maliciousness.
Every file is read whole and decompressed; MalConv sees its first max_len bytes (2,000,000 as in the
original paper). Results go to /data/results/ in the volume and are printed.
"""
from __future__ import annotations

import hashlib

import modal

app = modal.App("malconv-train")
vol = modal.Volume.from_name("malconv-data", create_if_missing=False)
image = (modal.Image.debian_slim(python_version="3.11")
         .pip_install("torch==2.5.1", "numpy==1.26.4", "scikit-learn==1.5.2", "scipy==1.14.1")
         .add_local_python_source("bench"))
MSVC = {"python_embed", "dotnet", "powershell"}


def _package_group(origin: str) -> str:
    """Package identity across MSYS2 repositories and versions; the package / version for Microsoft builds."""
    import re
    name = origin.rstrip("/").rsplit("/", 1)[-1]
    if name.endswith(".pkg.tar.zst"):
        name = re.sub(r"^mingw-w64-(x86_64|ucrt-x86_64|clang-x86_64|i686|clang-i686|clang-aarch64)-", "", name)
        return "msys2:" + re.sub(r"-[^-]+-[^-]+-any[.]pkg[.]tar[.]zst$", "", name)
    return "ms:" + origin


def make_splits(seed: int = 0) -> str:
    """Write /data/splits.csv once: the single split every model of D1-D7 uses."""
    import csv
    import glob
    import os
    path = "/data/splits.csv"
    if os.path.exists(path):
        return path
    bad = set(open("/data/bad_shas.txt").read().split()) if os.path.exists("/data/bad_shas.txt") else set()
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["sha256", "label", "split", "shard", "offset", "length", "source", "group", "first_seen", "tags"])
        for r in csv.DictReader(open("/data/malware_index.csv")):
            if r["shard"] and r["sha256"] not in bad:
                w.writerow([r["sha256"], 1, r["split"], r["shard"], r["offset"], r["length"], "sorel", "",
                            r["first_seen"], r["tags"]])
        seen = set()
        benign_rows = [r for f in sorted(glob.glob("/data/benign_index*.csv")) for r in csv.DictReader(open(f))]
        for r in benign_rows:
            if r["sha256"] in seen or r["sha256"] in bad:  # collected twice, or stored bytes do not match
                continue
            seen.add(r["sha256"])
            # Group split: every build of one package (mingw64 / ucrt64 / clang64 / i686 / arm64 variants are
            # near-duplicates) lands in the same split, so no near-copy of a test file is seen in training.
            group = _package_group(r["origin"])
            u = int(hashlib.md5(f"{seed}:{group}".encode()).hexdigest(), 16) % 1000 / 1000
            split = "train" if u < 0.70 else "val" if u < 0.85 else "test"
            if r["source"] in MSVC:  # a whole toolchain family never seen in training
                split = "test_unseen_toolchain"
            w.writerow([r["sha256"], 0, split, r["shard"], r["offset"], r["length"], r["source"], group, "", ""])
    vol.commit()
    return path


def _verify_shard(args):
    """Recompute each file's SHA-256 from the stored bytes. Benign files are stored disarmed: their two
    header fields are restored from the index before hashing. Returns the hashes that do not match."""
    import zlib
    shard, rows = args
    bad = []
    try:
        f = open(f"{_root(shard)}/{shard}", "rb")
    except OSError:
        return [r["sha256"] for r in rows]
    with f:
        for r in rows:
            try:
                f.seek(int(r["offset"]))
                data = bytearray(zlib.decompress(f.read(int(r["length"]))))
                if r.get("machine_before") not in (None, ""):  # benign: restore, then hash
                    pe = int.from_bytes(data[0x3C:0x40], "little")
                    data[pe + 4:pe + 6] = int(r["machine_before"]).to_bytes(2, "little")
                    data[pe + 92:pe + 94] = int(r["subsystem_before"]).to_bytes(2, "little")
                    if hashlib.sha256(bytes(data)).hexdigest() != r["sha256"]:
                        bad.append(r["sha256"])
                else:  # SOREL: hashes name the original binary, the object is the disarmed one; check form
                    pe = int.from_bytes(data[0x3C:0x40], "little") if len(data) > 0x40 else 0
                    if data[:2] != b"MZ" or not (0 < pe < len(data) - 94) or data[pe:pe + 4] != b"PE\x00\x00":
                        bad.append(r["sha256"])
            except Exception:
                bad.append(r["sha256"])
    return bad


@app.function(image=image, volumes={"/data": vol}, timeout=6 * 3600, cpu=16, memory=32768)
def verify() -> dict:
    """Integrity of every stored binary; writes /data/bad_shas.txt and removes a stale splits.csv."""
    import csv
    import glob
    import os
    from concurrent.futures import ProcessPoolExecutor
    groups, origin = {}, {}
    for path in ["/data/malware_index.csv"] + sorted(glob.glob("/data/benign_index*.csv")):
        for r in csv.DictReader(open(path)):
            if r.get("shard"):
                groups.setdefault(r["shard"], []).append(r)
                origin[r["sha256"]] = r.get("source", "sorel")
    bad = []
    with ProcessPoolExecutor(16) as pool:
        for b in pool.map(_verify_shard, list(groups.items())):
            bad += b
    open("/data/bad_shas.txt", "w").write("\n".join(bad))
    if os.path.exists("/data/splits.csv"):
        os.remove("/data/splits.csv")
    vol.commit()
    from collections import Counter
    return {"checked": sum(len(v) for v in groups.values()), "bad": len(bad),
            "bad_by_source": dict(Counter(origin.get(s, "?") for s in bad))}


@app.local_entrypoint()
def check():
    import json
    print(json.dumps(verify.remote(), indent=1))


@app.function(image=image, volumes={"/data": vol}, timeout=3600, cpu=2, memory=8192)
def splits(seed: int = 0) -> dict:
    """Create /data/splits.csv (once) and describe it."""
    import csv
    from collections import Counter
    rows = list(csv.DictReader(open(make_splits(seed))))
    by = Counter((r["split"], r["label"]) for r in rows)
    src = Counter((r["split"], r["source"]) for r in rows if r["label"] == "0")
    groups = {s: len({r["group"] for r in rows if r["split"] == s and r["label"] == "0"}) for s in
              ("train", "val", "test", "test_unseen_toolchain")}
    return {"rows": len(rows), "by_split_label": {f"{a}/{'mal' if b == '1' else 'ben'}": n for (a, b), n in sorted(by.items())},
            "benign_by_split_source": {f"{a}/{b}": n for (a, b), n in sorted(src.items())},
            "benign_package_groups_by_split": groups}


@app.local_entrypoint()
def describe():
    import json
    print(json.dumps(splits.remote(), indent=1))


def _items(seed: int = 0):
    """[(label, split, shard, offset, length, meta)] for every stored file, from /data/splits.csv."""
    import csv
    items = []
    for r in csv.DictReader(open(make_splits(seed))):
        items.append((int(r["label"]), r["split"], r["shard"], int(r["offset"]), int(r["length"]),
                      {"sha256": r["sha256"], "source": r["source"], "group": r["group"],
                       "first_seen": float(r["first_seen"]) if r["first_seen"] else None, "tags": r["tags"]}))
    return items


def _read(shard: str, off: int, ln: int, root: str) -> bytes:
    import zlib
    with open(f"{root}/{shard}", "rb") as f:
        f.seek(off)
        return zlib.decompress(f.read(ln))


def _root(shard: str) -> str:
    if shard.startswith("mal"):
        return "/data/malware"
    if shard.startswith("ben_"):  # per-repository benign jobs: ben_<repo>-NNNNN.bin in /data/benign_<repo>
        return "/data/benign_" + shard.split("-")[0][4:]
    return "/data/benign"


@app.function(image=image, gpu="A100-80GB", volumes={"/data": vol}, timeout=8 * 3600, cpu=16, memory=65536)
def train(gpu_epochs: int = 6, max_len: int = 2_000_000, batch: int = 32, lr: float = 1e-3, seed: int = 0):
    import json
    import os
    import random
    import time

    import numpy as np
    import torch
    from torch.utils.data import DataLoader, IterableDataset

    from bench.malconv import build

    torch.manual_seed(seed)
    items = _items(seed)
    by_split = {}
    for it in items:
        by_split.setdefault(it[1], []).append(it)
    train_items = by_split["train"]
    n_mal = sum(i[0] for i in train_items)
    n_ben = len(train_items) - n_mal
    pos_weight = torch.tensor([n_ben / max(n_mal, 1)], device="cuda")  # balance the classes in the loss

    class Stream(IterableDataset):
        """Shard-ordered reading (sequential IO), shuffled shard order and within-shard order per epoch."""

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
            for k in keys:
                g = sorted(groups[k], key=lambda x: x[3])
                if self.shuffle:
                    rng.shuffle(g)
                for label, _, shard, off, ln, meta in g:
                    try:
                        data = _read(shard, off, ln, _root(shard))[:max_len]
                    except Exception:
                        continue
                    yield np.frombuffer(data, dtype=np.uint8), label, meta["sha256"]

    def collate(rows):
        n = max(len(r[0]) for r in rows)
        x = torch.zeros((len(rows), n), dtype=torch.int64)
        for i, (b, _, _) in enumerate(rows):
            x[i, :len(b)] = torch.from_numpy(b.astype(np.int64) + 1)
        return x, torch.tensor([r[1] for r in rows], dtype=torch.float32), [r[2] for r in rows]

    model = build(max_len=max_len).cuda()
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    loss_fn = torch.nn.BCEWithLogitsLoss(pos_weight=pos_weight)

    def scores(its):
        model.eval()
        out = []
        dl = DataLoader(Stream(its, False), batch_size=batch, num_workers=12, collate_fn=collate)
        with torch.inference_mode(), torch.autocast("cuda", dtype=torch.bfloat16):
            for x, y, sha in dl:
                p = torch.sigmoid(model(x.cuda(non_blocking=True)).float()).cpu().numpy()
                out += list(zip(sha, y.numpy().tolist(), p.tolist()))
        model.train()
        return out

    def auc(rows):
        from sklearn.metrics import roc_auc_score
        y = [r[1] for r in rows]
        return float(roc_auc_score(y, [r[2] for r in rows])) if 0 < sum(y) < len(y) else None

    os.makedirs("/data/results/malconv", exist_ok=True)
    history, best = [], (-1.0, None)
    for epoch in range(gpu_epochs):
        t0, seen, total = time.time(), 0, 0.0
        dl = DataLoader(Stream(train_items, True, epoch), batch_size=batch, num_workers=14, collate_fn=collate,
                        prefetch_factor=4, persistent_workers=False)
        for x, y, _ in dl:
            with torch.autocast("cuda", dtype=torch.bfloat16):
                loss = loss_fn(model(x.cuda(non_blocking=True)).float(), y.cuda())
            opt.zero_grad(set_to_none=True)
            loss.backward()
            opt.step()
            seen += len(y)
            total += float(loss) * len(y)
        val = scores(by_split["val"])
        v_auc = auc(val)
        history.append({"epoch": epoch, "train_loss": total / max(seen, 1), "val_auc": v_auc,
                        "seconds": round(time.time() - t0, 1), "samples": seen})
        print(history[-1], flush=True)
        if v_auc is not None and v_auc > best[0]:
            best = (v_auc, epoch)
            torch.save(model.state_dict(), "/data/results/malconv/best.pt")
        vol.commit()
    model.load_state_dict(torch.load("/data/results/malconv/best.pt"))
    result = {"history": history, "best_epoch": best[1], "train_mal": n_mal, "train_ben": n_ben}
    def save(name, rows):
        with open(f"/data/results/malconv/scores_{name}.csv", "w") as f:
            f.write("sha256,label,score\n")
            f.writelines(f"{s},{int(y)},{p:.6f}\n" for s, y, p in rows)

    test_rows = scores(by_split["test"])  # newest malware + held-out benign of the training toolchains
    save("test", test_rows)
    if "test_unseen_toolchain" in by_split:  # same malware against benign from toolchains never trained on
        save("test_unseen_toolchain", [r for r in test_rows if r[1] == 1] + scores(by_split["test_unseen_toolchain"]))
    json.dump(result, open("/data/results/malconv/train.json", "w"), indent=1)
    vol.commit()
    return result


def _tpr_at(y, p, fpr_target):
    """TPR at the threshold whose FPR is <= target, with a Clopper-Pearson 95% interval."""
    import numpy as np
    from scipy.stats import beta
    y, p = np.asarray(y), np.asarray(p)
    neg = np.sort(p[y == 0])[::-1]
    k = int(np.floor(fpr_target * len(neg)))
    thr = neg[k] if k < len(neg) else neg[-1]
    tp = int(((p > thr) & (y == 1)).sum())
    npos = int((y == 1).sum())
    lo = beta.ppf(0.025, tp, npos - tp + 1) if tp > 0 else 0.0
    hi = beta.ppf(0.975, tp + 1, npos - tp) if tp < npos else 1.0
    return {"fpr_target": fpr_target, "threshold": float(thr), "tpr": tp / max(npos, 1),
            "tpr_ci95": [round(float(lo), 4), round(float(hi), 4)], "negatives": len(neg)}


@app.function(image=image, volumes={"/data": vol}, timeout=3 * 3600, cpu=8, memory=32768)
def report():
    """D1 metrics, D2 sandbox-threshold sweep, D3 drift by first-seen month, from the saved scores."""
    import csv
    import json
    from datetime import datetime, timezone

    import numpy as np
    from sklearn.metrics import average_precision_score, roc_auc_score

    meta = {}
    for r in csv.DictReader(open("/data/malware_index.csv")):
        meta[r["sha256"]] = r
    out = {}
    for split in ("test", "test_unseen_toolchain"):
        path = f"/data/results/malconv/scores_{split}.csv"
        try:
            rows = list(csv.DictReader(open(path)))
        except FileNotFoundError:
            continue
        y = np.array([int(r["label"]) for r in rows])
        p = np.array([float(r["score"]) for r in rows])
        res = {"n_mal": int(y.sum()), "n_ben": int((1 - y).sum()), "roc_auc": float(roc_auc_score(y, p)),
               "pr_auc": float(average_precision_score(y, p)),
               "tpr_at_fpr": [_tpr_at(y, p, f) for f in (1e-2, 1e-3, 1e-4)]}
        # D2: share of files escalated to the sandbox vs malware missed, per threshold.
        res["sandbox_sweep"] = [{"threshold": t, "escalated_share": float((p >= t).mean()),
                                 "malware_missed": float(((p < t) & (y == 1)).sum() / max(y.sum(), 1)),
                                 "benign_escalated": float(((p >= t) & (y == 0)).sum() / max((1 - y).sum(), 1))}
                                for t in (0.01, 0.05, 0.1, 0.2, 0.3, 0.5, 0.7, 0.9, 0.95, 0.99)]
        # D3: detection rate at the 1e-3 FPR threshold, per first-seen month of the malware.
        thr = res["tpr_at_fpr"][1]["threshold"]
        months = {}
        for r, s in zip(rows, p):
            if r["label"] == "1" and r["sha256"] in meta:
                m = datetime.fromtimestamp(float(meta[r["sha256"]]["first_seen"]), tz=timezone.utc).strftime("%Y-%m")
                a = months.setdefault(m, [0, 0])
                a[0] += int(s > thr)
                a[1] += 1
        res["tpr_by_month_at_fpr_1e-3"] = {m: round(a / b, 4) for m, (a, b) in sorted(months.items())}
        out[split] = res
    out["train"] = json.load(open("/data/results/malconv/train.json"))
    json.dump(out, open("/data/results/malconv/report.json", "w"), indent=1)
    vol.commit()
    return out


def _load_model():
    import torch

    from bench.malconv import build
    model = build().cuda().eval()
    model.load_state_dict(torch.load("/data/results/malconv/best.pt"))
    return model


def _pe_regions(data: bytes) -> list[tuple[str, int, int]]:
    """Byte ranges of the PE structure (DOS header, DOS stub, PE + optional headers, section table)."""
    n = len(data)
    pe = int.from_bytes(data[0x3C:0x40], "little") if n >= 0x40 else 0
    if not (0x40 <= pe < n - 24):
        return [("dos_header", 0, min(0x40, n)), ("first_4kb_rest", min(0x40, n), min(4096, n)), ("body", min(4096, n), n)]
    opt = int.from_bytes(data[pe + 20:pe + 22], "little")
    nsec = int.from_bytes(data[pe + 6:pe + 8], "little")
    sec_end = min(pe + 24 + opt + 40 * nsec, n)
    regions = [("dos_header", 0, 0x40), ("dos_stub", 0x40, pe), ("pe_headers", pe, min(pe + 24 + opt, n)),
               ("section_table", min(pe + 24 + opt, n), sec_end)]
    regions += [("first_4kb_rest", sec_end, max(sec_end, min(4096, n))), ("body", max(sec_end, min(4096, n)), n)]
    return regions


@app.function(image=image, gpu="A100-80GB", volumes={"/data": vol}, timeout=4 * 3600, cpu=8, memory=65536)
def attribution(n: int = 2000, seed: int = 0):
    """D7: where does MalConv look? Gradient x input per byte, summed by PE region; plus the score when only
    the first 4 KB are shown (header-only ablation)."""
    import json
    import random

    import numpy as np
    import torch
    from sklearn.metrics import roc_auc_score
    model = _load_model()
    items = [i for i in _items(seed) if i[1] == "test"]
    rng = random.Random(seed)
    picks = rng.sample([i for i in items if i[0] == 1], min(n, sum(1 for i in items if i[0] == 1)))
    picks += rng.sample([i for i in items if i[0] == 0], min(n, sum(1 for i in items if i[0] == 0)))
    shares, full, head, ys = {}, [], [], []
    for label, _, shard, off, ln, meta in picks:
        data = _read(shard, off, ln, _root(shard))[:2_000_000]
        x = torch.from_numpy(np.frombuffer(data, dtype=np.uint8).astype(np.int64) + 1).unsqueeze(0).cuda()
        e = model.embed(x).detach().requires_grad_(True)
        logit = model.forward_embedded(e)
        logit.sum().backward()
        attr = (e.grad * e).sum(-1).abs().squeeze(0).detach().cpu().numpy()
        total = attr.sum() or 1.0
        for name, a, b in _pe_regions(data):
            shares.setdefault(name, []).append(float(attr[a:b].sum() / total))
        with torch.inference_mode():
            full.append(float(torch.sigmoid(logit).item()))
            head.append(float(torch.sigmoid(model(x[:, :4096])).item()))
        ys.append(label)
    out = {"files": len(picks), "attribution_share_mean": {k: round(float(np.mean(v)), 4) for k, v in shares.items()},
           "auc_full": float(roc_auc_score(ys, full)), "auc_first_4kb_only": float(roc_auc_score(ys, head))}
    json.dump(out, open("/data/results/malconv/attribution.json", "w"), indent=1)
    vol.commit()
    return out


def _nearest_bytes(model, target):
    """Map embedding vectors (k, d) to the closest byte embeddings (bytes 0..255 are indices 1..256)."""
    import torch
    table = model.embed.weight[1:257]
    return torch.cdist(target, table).argmin(dim=1) + 1


@app.function(image=image, gpu="A100-80GB", volumes={"/data": vol}, timeout=6 * 3600, cpu=8, memory=65536)
def robustness(n: int = 1000, steps: int = 20, seed: int = 0):
    """D4: published evasion attacks on our MalConv, on test malware it detects at the 1e-3 FPR threshold.
    random_pad / benign_pad: append bytes; gradient_pad: Kolosnjaji et al. (2018) padding optimised along
    the gradient in embedding space; dos_header: Demetrio et al. (2019) partial DOS header (bytes 2..0x3B).
    Perturbed files stay in memory; nothing is written out or executed."""
    import csv
    import json
    import random

    import numpy as np
    import torch
    model = _load_model()
    rows = list(csv.DictReader(open("/data/results/malconv/scores_test.csv")))
    neg = sorted((float(r["score"]) for r in rows if r["label"] == "0"), reverse=True)
    thr = neg[int(len(neg) * 1e-3)]
    detected = {r["sha256"] for r in rows if r["label"] == "1" and float(r["score"]) > thr}
    items = {i[5]["sha256"]: i for i in _items(seed) if i[1] == "test"}
    rng = random.Random(seed)
    nrng = np.random.default_rng(seed)
    pool = [items[s] for s in detected if s in items and items[s][4] > 0]
    picks = rng.sample(pool, min(n, len(pool)))
    benign_src = [i for i in items.values() if i[0] == 0][:200]
    benign_bytes = [_read(i[2], i[3], i[4], _root(i[2]))[:200_000] for i in benign_src[:50]]

    def score(data: bytes) -> float:
        x = torch.from_numpy(np.frombuffer(data[:2_000_000], dtype=np.uint8).astype(np.int64) + 1).unsqueeze(0).cuda()
        with torch.inference_mode():
            return float(torch.sigmoid(model(x)).item())

    def optimise(data: bytes, positions: list[int]) -> bytes:
        x = torch.from_numpy(np.frombuffer(data[:2_000_000], dtype=np.uint8).astype(np.int64) + 1).unsqueeze(0).cuda()
        pos = torch.tensor(positions, device="cuda")
        for _ in range(steps):
            e = model.embed(x).detach().requires_grad_(True)
            model.forward_embedded(e).sum().backward()
            step = e[0, pos] - 0.5 * e.grad[0, pos].sign()
            x[0, pos] = _nearest_bytes(model, step.detach())
        return bytes((x[0].cpu().numpy() - 1).astype(np.uint8).tobytes())

    results = {}
    for attack, sizes in (("random_pad", [1024, 10240, 102400]), ("benign_pad", [1024, 10240, 102400]),
                          ("gradient_pad", [1024, 10240]), ("dos_header", [58])):
        for k in sizes:
            evaded = tried = 0
            for label, _, shard, off, ln, meta in picks:
                data = _read(shard, off, ln, _root(shard))
                if attack != "dos_header" and len(data) + k > 2_000_000:
                    continue  # MalConv only reads the first 2 MB: appended bytes would be invisible
                if attack == "random_pad":
                    adv = data + nrng.integers(0, 256, k, dtype=np.uint8).tobytes()
                elif attack == "benign_pad":
                    adv = data + rng.choice(benign_bytes)[:k]
                elif attack == "gradient_pad":
                    adv = optimise(data + nrng.integers(0, 256, k, dtype=np.uint8).tobytes(), list(range(len(data), len(data) + k)))
                else:
                    adv = optimise(data, list(range(2, 0x3C)))
                tried += 1
                evaded += score(adv) <= thr
            results[f"{attack}_{k}"] = {"tried": tried, "evasion_rate": round(evaded / tried, 4) if tried else None}
    out = {"threshold_fpr_1e-3": thr, "malware_detected_pool": len(pool), "attacks": results}
    json.dump(out, open("/data/results/malconv/robustness.json", "w"), indent=1)
    vol.commit()
    return out


@app.local_entrypoint()
def main():
    import json
    print(json.dumps(report.remote(), indent=1)[:6000])
