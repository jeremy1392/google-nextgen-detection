"""D5: static detection on Linux ELF, and transfer from the Windows PE model.

    modal run modal_apps/elf_d5.py::profile     # header census of both classes -> experiments/results/D5_elf_profile.json
    modal run modal_apps/elf_d5.py::prepare     # splits + features + GBDT models (header-only, bytes, both)
    modal run --detach modal_apps/elf_d5.py::scratch    # MalConv trained on ELF from scratch (+ learning curve)
    modal run --detach modal_apps/elf_d5.py::transfer   # PE MalConv zero-shot and fine-tuned (+ learning curve)
    modal run modal_apps/elf_d5.py::summary     # every metric, every subset -> experiments/results/D5_elf.json

Malware: MalwareBazaar ELF (daily bulk exports + API), live samples kept compressed in the volume and never
executed. Benign: ELF executables from Debian (amd64, every release architecture, debian-ports) and OpenWrt,
collected for every architecture the malware comes in (the census showed that an amd64-only benign set lets
a classifier separate the classes by architecture and file type alone). Only executables are compared
(ET_EXEC, or ET_DYN with an interpreter): shared libraries, objects and kernel modules are left out of both
classes. Everything that touches the samples runs in Modal; only aggregate numbers come back.
"""
from __future__ import annotations

import hashlib

import modal

app = modal.App("elf-d5")
data_vol = modal.Volume.from_name("detection-data", create_if_missing=False)
pe_vol = modal.Volume.from_name("malconv-data", create_if_missing=False)
image = (modal.Image.debian_slim(python_version="3.11")
         .pip_install("torch==2.5.1", "numpy==1.26.4", "scikit-learn==1.5.2", "scipy==1.14.1", "pyzipper")
         .add_local_python_source("bench"))
ELF = "/data/elf"
MACHINE = {2: "sparc", 3: "x86", 4: "m68k", 8: "mips", 20: "ppc", 21: "ppc64", 22: "s390", 40: "arm",
           42: "superh", 62: "x86_64", 183: "aarch64", 243: "riscv", 258: "loongarch"}


def elf_header(data: bytes) -> dict:
    """Structural facts from the ELF header, program headers and section headers (no execution)."""
    h = {"size": len(data), "ok": data[:4] == b"\x7fELF" and len(data) >= 52}
    if not h["ok"]:
        return h
    bits = 64 if data[4] == 2 else 32
    order = "big" if data[5] == 2 else "little"
    u = lambda off, n: int.from_bytes(data[off:off + n], order) if off + n <= len(data) else 0
    e_type, machine = u(16, 2), u(18, 2)
    if bits == 64:
        phoff, shoff, phentsize, phnum, shentsize, shnum = u(32, 8), u(40, 8), u(54, 2), u(56, 2), u(58, 2), u(60, 2)
    else:
        phoff, shoff, phentsize, phnum, shentsize, shnum = u(28, 4), u(32, 4), u(42, 2), u(44, 2), u(46, 2), u(48, 2)
    ptypes = {u(phoff + i * phentsize, 4) for i in range(min(phnum, 256))} if phentsize else set()
    stypes = {u(shoff + i * shentsize + 4, 4) for i in range(min(shnum, 4096))} if shentsize and shoff else set()
    h.update({"bits": bits, "endian": order, "machine": MACHINE.get(machine, f"m{machine}"),
              "e_type": {1: "rel", 2: "exec", 3: "dyn", 4: "core"}.get(e_type, f"t{e_type}"),
              "interp": 3 in ptypes, "dynamic": 2 in ptypes, "symtab": 2 in stypes, "no_sections": shnum == 0,
              "upx": b"UPX!" in data[:4096] or b"UPX!" in data[-4096:]})
    return h


def _blob(root: str, shard: str, off: int, ln: int) -> bytes:
    import zlib
    with open(f"{root}/{shard}", "rb") as f:
        f.seek(off)
        return zlib.decompress(f.read(ln))


def _api_sample(sha: str) -> bytes:
    import pyzipper
    with pyzipper.AESZipFile(f"{ELF}/malware/{sha}.zip") as z:
        z.setpassword(b"infected")
        return z.read(z.namelist()[0])


def _census_shard(args):
    import hashlib
    root, shard, rows, label = args
    out = []
    try:
        f = open(f"{root}/{shard}", "rb")
    except OSError:
        return [(r["sha256"], label, {"ok": False, "error": "missing_shard"}) for r in rows]
    import zlib
    with f:
        for r in rows:
            try:
                f.seek(int(r["offset"]))
                data = zlib.decompress(f.read(int(r["length"])))
                h = elf_header(data)
                h["hash_ok"] = hashlib.sha256(data).hexdigest() == r["sha256"]
            except Exception as exc:
                h = {"ok": False, "error": type(exc).__name__}
            out.append((r["sha256"], label, h))
    return out


@app.function(image=image, volumes={"/data": data_vol}, timeout=3 * 3600, cpu=16, memory=32768)
def census() -> dict:
    """Header facts for every stored ELF file; writes /data/elf/headers.csv and returns the distributions."""
    import csv
    import hashlib
    import json
    from collections import Counter
    from concurrent.futures import ProcessPoolExecutor
    jobs = []
    for index, root, label in ((f"{ELF}/malware_bulk_index.csv", f"{ELF}/malware_shards", 1),
                               (f"{ELF}/benign_index.csv", f"{ELF}/benign", 0)):
        groups = {}
        for r in csv.DictReader(open(index)):
            groups.setdefault(r["shard"], []).append(r)
        jobs += [(root, s, rows, label) for s, rows in groups.items()]
    results = []
    with ProcessPoolExecutor(16) as pool:
        for part in pool.map(_census_shard, jobs):
            results += part
    seen = {s for s, _, _ in results}
    for r in csv.DictReader(open(f"{ELF}/malware_index.csv")):  # API downloads, if not already in the bulk exports
        if r["status"] != "ok" or r["sha256"] in seen:
            continue
        try:
            data = _api_sample(r["sha256"])
            h = elf_header(data)
            h["hash_ok"] = hashlib.sha256(data).hexdigest() == r["sha256"]
        except Exception as exc:
            h = {"ok": False, "error": type(exc).__name__}
        results.append((r["sha256"], 1, {**h, "api": True}))
    keys = ["ok", "hash_ok", "size", "bits", "endian", "machine", "e_type", "interp", "dynamic", "symtab",
            "no_sections", "upx", "api", "error"]
    with open(f"{ELF}/headers.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["sha256", "label"] + keys)
        for s, label, h in results:
            w.writerow([s, label] + [h.get(k, "") for k in keys])
    data_vol.commit()
    out = {}
    for label, name in ((1, "malware"), (0, "benign")):
        hs = [h for _, lab, h in results if lab == label]
        good = [h for h in hs if h.get("ok") and h.get("hash_ok")]
        sizes = sorted(h["size"] for h in good)
        out[name] = {
            "files": len(hs), "valid": len(good), "bad": dict(Counter(h.get("error", "not_elf_or_hash") for h in hs
                                                                      if not (h.get("ok") and h.get("hash_ok")))),
            "machine": dict(Counter(h["machine"] for h in good).most_common()),
            "machine_bits_endian": dict(Counter(f'{h["machine"]}/{h["bits"]}/{h["endian"][0]}e' for h in good).most_common(20)),
            "e_type": dict(Counter(h["e_type"] for h in good)),
            "share_static (no PT_INTERP)": round(sum(not h["interp"] for h in good) / max(len(good), 1), 4),
            "share_with_symtab": round(sum(h["symtab"] for h in good) / max(len(good), 1), 4),
            "share_no_sections": round(sum(h["no_sections"] for h in good) / max(len(good), 1), 4),
            "share_upx": round(sum(h["upx"] for h in good) / max(len(good), 1), 4),
            "size_p10_p50_p90": [sizes[int(len(sizes) * q)] for q in (0.1, 0.5, 0.9)] if sizes else None,
            "share_over_2MB": round(sum(s > 2_000_000 for s in sizes) / max(len(sizes), 1), 4)}
        x64 = [h for h in good if h["machine"] == "x86_64"]
        out[name]["x86_64_only"] = {
            "files": len(x64), "e_type": dict(Counter(h["e_type"] for h in x64)),
            "share_static": round(sum(not h["interp"] for h in x64) / max(len(x64), 1), 4),
            "share_with_symtab": round(sum(h["symtab"] for h in x64) / max(len(x64), 1), 4),
            "share_upx": round(sum(h["upx"] for h in x64) / max(len(x64), 1), 4)}
    json.dump(out, open(f"{ELF}/profile.json", "w"), indent=1)
    data_vol.commit()
    return out


@app.local_entrypoint()
def profile(out: str = "experiments/results/D5_elf_profile.json"):
    import json
    import os
    res = census.remote()
    os.makedirs(os.path.dirname(out), exist_ok=True)
    json.dump(res, open(out, "w"), indent=1)
    print(json.dumps(res, indent=1))


# ----------------------------------------------------------------------------------------------- splits
SPLITS = f"{ELF}/d5_splits.csv"
COLS = ["sha256", "label", "split", "store", "shard", "offset", "length", "source", "group", "machine", "bits",
        "endian", "e_type", "interp", "day"]


def _deb_group(pool_path: str) -> str:
    """pool/main/c/clsync/libclsync0_0.4.5_amd64.deb -> deb:clsync (the source package)."""
    parts = pool_path.split("/")
    return "deb:" + (parts[3] if len(parts) > 4 else parts[-1].split("_")[0])


def _make_splits(seed: int = 0) -> dict:
    """Executables only, both classes. Malware: temporal split on the export day (oldest 70% train, next 15%
    val, newest 15% test, whole days only). Benign: split by source package, across architectures and
    releases, so no build of a program seen in training is tested."""
    import csv
    import glob
    from collections import Counter
    hdr = {r["sha256"]: r for r in csv.DictReader(open(f"{ELF}/headers.csv"))
           if r["ok"] == "True" and r["hash_ok"] == "True"}
    exe = lambda e_type, interp: e_type == "exec" or (e_type == "dyn" and interp in ("True", "1"))
    seen, mal = set(), []
    for r in csv.DictReader(open(f"{ELF}/malware_bulk_index.csv")):
        h = hdr.get(r["sha256"])
        if h and exe(h["e_type"], h["interp"]) and r["sha256"] not in seen:
            seen.add(r["sha256"])
            mal.append([r["sha256"], 1, "", "bulk", r["shard"], r["offset"], r["length"], "malwarebazaar", "",
                        h["machine"], h["bits"], h["endian"], h["e_type"], h["interp"] == "True", r["export_day"]])
    for r in csv.DictReader(open(f"{ELF}/malware_index.csv")):
        h = hdr.get(r["sha256"])
        if r["status"] == "ok" and h and exe(h["e_type"], h["interp"]) and r["sha256"] not in seen:
            seen.add(r["sha256"])
            mal.append([r["sha256"], 1, "", "api", "", "", "", "malwarebazaar", "", h["machine"], h["bits"],
                        h["endian"], h["e_type"], h["interp"] == "True", r["first_seen"][:10]])
    mal.sort(key=lambda m: m[-1])
    days = sorted({m[-1] for m in mal})
    per_day, cut, acc = Counter(m[-1] for m in mal), {}, 0
    for d in days:
        acc += per_day[d]
        cut[d] = "train" if acc <= 0.70 * len(mal) else "val" if acc <= 0.85 * len(mal) else "test"
    for m in mal:
        m[2] = cut[m[-1]]
    ben = []
    for r in csv.DictReader(open(f"{ELF}/benign_index.csv")):  # Debian amd64
        h = hdr.get(r["sha256"])
        if h and exe(h["e_type"], h["interp"]) and r["sha256"] not in seen:
            seen.add(r["sha256"])
            ben.append([r["sha256"], 0, "", "deb64", r["shard"], r["offset"], r["length"], "debian-amd64",
                        _deb_group(r["package"]), h["machine"], h["bits"], h["endian"], h["e_type"],
                        h["interp"] == "True", ""])
    for path in sorted(glob.glob(f"{ELF}/benign_arch/*.csv")):
        for r in csv.DictReader(open(path)):
            if r["sha256"] in seen:
                continue
            seen.add(r["sha256"])
            src, grp = r["group"].split(":", 1)
            ben.append([r["sha256"], 0, "", "arch", r["shard"], r["offset"], r["length"], r["source"],
                        ("owrt:" if src == "openwrt" else "deb:") + grp,
                        MACHINE.get(int(r["machine"]), f"m{r['machine']}"), r["bits"], r["endian"],
                        {"2": "exec", "3": "dyn"}.get(r["e_type"], r["e_type"]), r["interp"] == "1", ""])
    for b in ben:
        u = int(hashlib.md5(f"{seed}:{b[8]}".encode()).hexdigest(), 16) % 1000 / 1000
        b[2] = "train" if u < 0.70 else "val" if u < 0.85 else "test"
    rows = mal + ben
    with open(SPLITS, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(COLS)
        w.writerows(rows)
    data_vol.commit()
    by = Counter((r[2], r[1]) for r in rows)
    arch = Counter((r[1], r[9]) for r in rows)
    return {"rows": len(rows),
            "by_split_label": {f"{a}/{'mal' if b else 'ben'}": n for (a, b), n in sorted(by.items())},
            "malware_days": {s: [d for d in days if cut[d] == s][:1] + [d for d in days if cut[d] == s][-1:]
                             for s in ("train", "val", "test")},
            "by_label_machine": {f"{'mal' if a else 'ben'}/{b}": n for (a, b), n in sorted(arch.items())},
            "benign_by_source": dict(Counter(r[7] for r in ben)),
            "benign_pie_share": round(sum(r[12] == "dyn" for r in ben) / max(len(ben), 1), 4),
            "malware_pie_share": round(sum(r[12] == "dyn" for r in mal) / max(len(mal), 1), 4),
            "benign_groups": len({r[8] for r in ben})}


def _read_item(store: str, shard: str, off, ln, sha: str) -> bytes:
    if store == "api":
        return _api_sample(sha)
    root = {"bulk": f"{ELF}/malware_shards", "deb64": f"{ELF}/benign", "arch": f"{ELF}/benign_arch"}[store]
    return _blob(root, shard, int(off), int(ln))


def _load_splits() -> list[dict]:
    import csv
    return list(csv.DictReader(open(SPLITS)))


# --------------------------------------------------------------------------------------------- features
N_HDR = 10


def _features(data: bytes):
    """Header facts (10), byte histogram (256) and byte-entropy histogram (256, Saxe & Berlin 2015, as in
    EMBER: 2048-byte windows, step 1024, 16 entropy bins x 16 nibble bins). Whole file, up to 16 MB."""
    import math

    import numpy as np
    h = elf_header(data)
    names = sorted(MACHINE.values())
    hdr = [names.index(h["machine"]) if h.get("machine") in names else len(names), h.get("bits", 0),
           h.get("endian") == "big", {"exec": 0, "dyn": 1}.get(h.get("e_type"), 2), h.get("interp", False),
           h.get("dynamic", False), h.get("symtab", False), h.get("no_sections", False), h.get("upx", False),
           math.log2(max(len(data), 1))]
    a = np.frombuffer(data[:16 << 20], dtype=np.uint8)
    hist = np.bincount(a, minlength=256).astype(np.float32) / max(a.size, 1)
    W, S = 2048, 1024
    nib = (a >> 4).astype(np.int64)
    if nib.size >= W:
        n = 1 + (nib.size - W) // S
        blocks = nib[:(n + 1) * S].reshape(n + 1, S)
        bc = np.bincount((blocks + 16 * np.arange(n + 1)[:, None]).ravel(), minlength=16 * (n + 1)).reshape(n + 1, 16)
        wc = bc[:-1] + bc[1:]
    else:
        wc = np.bincount(nib, minlength=16)[None, :]
    p = wc / np.maximum(wc.sum(1, keepdims=True), 1)
    with np.errstate(divide="ignore", invalid="ignore"):
        H = -np.where(p > 0, p * np.log2(np.where(p > 0, p, 1)), 0).sum(1)
    ent = np.zeros((16, 16), np.float64)
    np.add.at(ent, np.minimum((H * 4).astype(int), 15), wc)
    ent = (ent / max(ent.sum(), 1)).ravel().astype(np.float32)
    return np.concatenate([np.asarray(hdr, np.float32), hist, ent])


def _feature_chunk(rows):
    """Features of every readable file whose bytes still hash to its SHA-256 (others are dropped)."""
    import numpy as np
    out, keep = [], []
    for r in rows:
        try:
            data = _read_item(r["store"], r["shard"], r["offset"], r["length"], r["sha256"])
            if hashlib.sha256(data).hexdigest() != r["sha256"]:
                continue
            out.append(_features(data))
            keep.append(r["sha256"])
        except Exception:
            continue
    return keep, (np.stack(out) if out else np.zeros((0, N_HDR + 512), np.float32))


def _save_scores(model: str, shas, y, p, split: str = "test"):
    import os
    os.makedirs(f"{ELF}/d5/{model}", exist_ok=True)
    with open(f"{ELF}/d5/{model}/scores_{split}.csv", "w") as f:
        f.write("sha256,label,score\n")
        f.writelines(f"{s},{int(a)},{float(b):.6f}\n" for s, a, b in zip(shas, y, p))


@app.function(image=image, volumes={"/data": data_vol}, timeout=4 * 3600, cpu=32, memory=65536)
def prepare_remote(seed: int = 0) -> dict:
    """Splits, features, and three GBDT models: header-only (the shortcut a reviewer should ask about),
    bytes-only (histograms, no header), header + bytes. Iterations chosen on the validation split."""
    import json
    import os
    from concurrent.futures import ProcessPoolExecutor

    import numpy as np
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.metrics import roc_auc_score
    split_info = _make_splits(seed)
    rows = _load_splits()
    by_shard = {}
    for r in rows:
        by_shard.setdefault((r["store"], r["shard"]), []).append(r)
    chunks = [v[i:i + 500] for v in by_shard.values() for i in range(0, len(v), 500)]
    shas, feats = [], []
    with ProcessPoolExecutor(32) as pool:
        for keep, x in pool.map(_feature_chunk, chunks):
            shas += keep
            feats.append(x)
    X = np.concatenate(feats)
    meta = {r["sha256"]: r for r in rows}
    kept = set(shas)  # every model (GBDT and MalConv) uses exactly the files that read back and hash correctly
    with open(SPLITS, "w", newline="") as f:
        import csv
        w = csv.DictWriter(f, fieldnames=COLS)
        w.writeheader()
        w.writerows(r for r in rows if r["sha256"] in kept)
    data_vol.commit()
    y = np.array([int(meta[s]["label"]) for s in shas])
    split = np.array([meta[s]["split"] for s in shas])
    sha_arr = np.array(shas)
    os.makedirs(f"{ELF}/d5", exist_ok=True)
    np.savez_compressed(f"{ELF}/d5/features.npz", X=X, y=y, split=split, sha=sha_arr)
    views = {"gbdt_header": (0, N_HDR), "gbdt_bytes": (N_HDR, N_HDR + 512), "gbdt_header+bytes": (0, N_HDR + 512)}
    res = {"splits": split_info, "featurized": len(shas), "unreadable": len(rows) - len(shas), "models": {}}
    tr, va, te = split == "train", split == "val", split == "test"
    for name, (a, b) in views.items():
        Xv = X[:, a:b]
        cat = [0] if a == 0 else None  # machine is categorical
        best = (-1.0, None)
        for it in (50, 100, 200, 400, 800):
            clf = HistGradientBoostingClassifier(max_iter=it, learning_rate=0.05, early_stopping=False,
                                                 random_state=seed, categorical_features=cat, class_weight="balanced")
            clf.fit(Xv[tr], y[tr])
            v = roc_auc_score(y[va], clf.predict_proba(Xv[va])[:, 1])
            if v > best[0] + 1e-5:
                best = (v, it, clf)
        clf = best[2]
        _save_scores(name, sha_arr[te], y[te], clf.predict_proba(Xv[te])[:, 1])
        _save_scores(name, sha_arr[va], y[va], clf.predict_proba(Xv[va])[:, 1], split="val")
        res["models"][name] = {"iterations": best[1], "val_auc": round(best[0], 5)}
    json.dump(res, open(f"{ELF}/d5/prepare.json", "w"), indent=1)
    data_vol.commit()
    return res


@app.local_entrypoint()
def prepare():
    import json
    print(json.dumps(prepare_remote.remote(), indent=1))


# ---------------------------------------------------------------------------------------------- MalConv
def _train(tag: str, init: str = "scratch", frac: float = 1.0, epochs: int = 8, lr: float = 1e-3,
           batch: int = 32, max_len: int = 2_000_000, seed: int = 0) -> dict:
    """MalConv (same architecture and input as D1) on ELF executables. init='pe' starts from the D1 model;
    epochs=0 scores the D1 model as it is (zero-shot transfer)."""
    import json
    import os
    import random
    import time

    import numpy as np
    import torch
    from torch.utils.data import DataLoader, IterableDataset

    from bench.malconv import build
    torch.manual_seed(seed)
    by = {}
    for r in _load_splits():
        by.setdefault(r["split"], []).append(r)
    train_rows = by["train"]
    if frac < 1.0:  # learning curve: same fraction of each class; smaller sets are nested in larger ones
        train_rows = [r for r in train_rows
                      if int(hashlib.md5(f"{seed}:{r['sha256']}".encode()).hexdigest(), 16) % 10_000 < frac * 10_000]
    n_mal = sum(r["label"] == "1" for r in train_rows)
    n_ben = len(train_rows) - n_mal

    class Stream(IterableDataset):
        def __init__(self, items, shuffle, epoch=0):
            self.items, self.shuffle, self.epoch = items, shuffle, epoch

        def __iter__(self):
            info = torch.utils.data.get_worker_info()
            groups = {}
            for r in self.items:
                groups.setdefault((r["store"], r["shard"]), []).append(r)
            keys = sorted(groups)
            rng = random.Random(seed * 1000 + self.epoch)
            if self.shuffle:
                rng.shuffle(keys)
            if info:
                keys = keys[info.id::info.num_workers]
            for k in keys:
                g = sorted(groups[k], key=lambda r: int(r["offset"] or 0))
                if self.shuffle:
                    rng.shuffle(g)
                for r in g:
                    try:
                        data = _read_item(r["store"], r["shard"], r["offset"], r["length"], r["sha256"])[:max_len]
                    except Exception:
                        continue
                    yield np.frombuffer(data, dtype=np.uint8), int(r["label"]), r["sha256"]

    def collate(items):
        n = max(len(b) for b, _, _ in items)
        x = torch.zeros((len(items), n), dtype=torch.uint8)
        for i, (b, _, _) in enumerate(items):
            x[i, :len(b)] = torch.from_numpy(b.copy())
        lens = torch.tensor([len(b) for b, _, _ in items])
        return x, lens, torch.tensor([y for _, y, _ in items], dtype=torch.float32), [s for _, _, s in items]

    def to_gpu(x, lens):  # bytes + 1, 0 = padding: the D1 input, built on the GPU instead of as int64 on the host
        xg = x.cuda(non_blocking=True).long() + 1
        pad = torch.arange(xg.shape[1], device="cuda")[None, :] >= lens.cuda()[:, None]
        return xg.masked_fill(pad, 0)

    model = build(max_len=max_len).cuda()
    if init == "pe":
        model.load_state_dict(torch.load("/pe/results/malconv/best.pt"))
    out_dir = f"{ELF}/d5/{tag}"
    os.makedirs(out_dir, exist_ok=True)

    def scores(items):
        model.eval()
        res = []
        dl = DataLoader(Stream(items, False), batch_size=batch, num_workers=14, collate_fn=collate)
        with torch.inference_mode(), torch.autocast("cuda", dtype=torch.bfloat16):
            for x, lens, y, sha in dl:
                p = torch.sigmoid(model(to_gpu(x, lens)).float()).cpu().numpy()
                res += list(zip(sha, y.numpy().tolist(), p.tolist()))
        model.train()
        return res

    def auc(res):
        from sklearn.metrics import roc_auc_score
        y = [r[1] for r in res]
        return float(roc_auc_score(y, [r[2] for r in res])) if 0 < sum(y) < len(y) else None

    history, best, start = [], (-1.0, None), 0
    if epochs == 0:
        history.append({"epoch": None, "val_auc": auc(scores(by["val"]))})
        torch.save(model.state_dict(), f"{out_dir}/best.pt")
    else:
        opt = torch.optim.Adam(model.parameters(), lr=lr)
        loss_fn = torch.nn.BCEWithLogitsLoss(pos_weight=torch.tensor([n_ben / max(n_mal, 1)], device="cuda"))
        ckpt = f"{out_dir}/ckpt.pt"
        split_id = hashlib.md5("".join(sorted(r["sha256"] for r in train_rows)).encode()).hexdigest()
        c = torch.load(ckpt) if os.path.exists(ckpt) else None
        if c and c.get("split_id") == split_id:  # restarted after a preemption: resume after the last finished epoch
            model.load_state_dict(c["model"])
            opt.load_state_dict(c["opt"])
            history, best, start = c["history"], tuple(c["best"]), c["epoch"] + 1
            print(tag, "resuming at epoch", start, flush=True)
        for epoch in range(start, epochs):
            t0, seen, total = time.time(), 0, 0.0
            dl = DataLoader(Stream(train_rows, True, epoch), batch_size=batch, num_workers=14, collate_fn=collate,
                            prefetch_factor=4)
            for x, lens, y, _ in dl:
                with torch.autocast("cuda", dtype=torch.bfloat16):
                    loss = loss_fn(model(to_gpu(x, lens)).float(), y.cuda())
                opt.zero_grad(set_to_none=True)
                loss.backward()
                opt.step()
                seen += len(y)
                total += float(loss) * len(y)
            v = auc(scores(by["val"]))
            history.append({"epoch": epoch, "train_loss": total / max(seen, 1), "val_auc": v,
                            "seconds": round(time.time() - t0, 1), "samples": seen})
            print(tag, history[-1], flush=True)
            if v is not None and v > best[0]:
                best = (v, epoch)
                torch.save(model.state_dict(), f"{out_dir}/best.pt")
            torch.save({"model": model.state_dict(), "opt": opt.state_dict(), "history": history,
                        "best": list(best), "epoch": epoch, "split_id": split_id}, ckpt)
            data_vol.commit()
        model.load_state_dict(torch.load(f"{out_dir}/best.pt"))
    test = scores(by["test"])
    _save_scores(tag, [t[0] for t in test], [t[1] for t in test], [t[2] for t in test])
    result = {"tag": tag, "init": init, "frac": frac, "lr": lr, "epochs": epochs, "history": history,
              "best_epoch": best[1], "train_mal": n_mal, "train_ben": n_ben}
    json.dump(result, open(f"{out_dir}/train.json", "w"), indent=1)
    data_vol.commit()
    return result


@app.function(image=image, gpu="L4", volumes={"/data": data_vol, "/pe": pe_vol}, timeout=10 * 3600,
              cpu=16, memory=65536)
def train_remote(tag: str, init: str = "scratch", frac: float = 1.0, epochs: int = 8, lr: float = 1e-3) -> dict:
    return _train(tag, init, frac, epochs, lr)


def _launch(runs):
    import json
    for r in train_remote.starmap(runs, return_exceptions=True):
        print(json.dumps(r if isinstance(r, dict) else {"error": repr(r)[:400]}, indent=1)[:1500])


@app.local_entrypoint()
def scratch():
    _launch([("malconv_scratch", "scratch", 1.0, 8, 1e-3), ("malconv_scratch_f0.3", "scratch", 0.3, 8, 1e-3),
             ("malconv_scratch_f0.1", "scratch", 0.1, 8, 1e-3)])


@app.local_entrypoint()
def transfer():
    _launch([("malconv_pe_zeroshot", "pe", 1.0, 0, 0.0), ("malconv_pe_finetune", "pe", 1.0, 8, 1e-4),
             ("malconv_pe_finetune_f0.3", "pe", 0.3, 8, 1e-4), ("malconv_pe_finetune_f0.1", "pe", 0.1, 8, 1e-4)])


# ----------------------------------------------------------------------------------------------- report
def _tpr_at(y, p, fpr_target):
    """TPR at the threshold whose FPR is <= target, with a Clopper-Pearson 95% interval (as in D1)."""
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
    return {"fpr_target": fpr_target, "threshold": float(thr), "tpr": round(tp / max(npos, 1), 4),
            "tpr_ci95": [round(float(lo), 4), round(float(hi), 4)], "negatives": len(neg), "positives": npos}


SUBSETS = ("all", "x86_64", "arch_matched", "hard_benign", "arch_seen_in_train", "arch_new_in_test")


@app.function(image=image, volumes={"/data": data_vol}, timeout=3600, cpu=4, memory=16384)
def summary_remote() -> dict:
    """Every model on the test split: overall; x86-64 only; architecture-matched (only architectures with at
    least 50 benign test files); 'hard benign' (benign side reduced to non-PIE ET_EXEC files, the file type
    almost all malware has); and per architecture. Plus malware detection by export week."""
    import csv
    import glob
    import json
    import os
    from collections import Counter
    from datetime import date

    import numpy as np
    from sklearn.metrics import average_precision_score, roc_auc_score
    meta = {r["sha256"]: r for r in _load_splits()}
    test = [m for m in meta.values() if m["split"] == "test"]
    ben_arch = Counter(m["machine"] for m in test if m["label"] == "0")
    mal_arch = Counter(m["machine"] for m in test if m["label"] == "1")
    train_mal_arch = Counter(m["machine"] for m in meta.values() if m["split"] == "train" and m["label"] == "1")
    seen = lambda m: train_mal_arch.get(m["machine"], 0) >= 20  # malware of this architecture was learned
    subsets = {"all": lambda m: True, "x86_64": lambda m: m["machine"] == "x86_64",
               "arch_matched": lambda m: ben_arch.get(m["machine"], 0) >= 50,
               "hard_benign": lambda m: m["label"] == "1" or m["e_type"] == "exec",
               "arch_seen_in_train": lambda m: ben_arch.get(m["machine"], 0) >= 50 and seen(m),
               "arch_new_in_test": lambda m: ben_arch.get(m["machine"], 0) >= 50 and not seen(m)}
    for a in sorted(set(ben_arch) | set(mal_arch)):
        subsets[f"arch:{a}"] = (lambda a: lambda m: m["machine"] == a)(a)
    out = {"test_counts": {"benign_by_arch": dict(ben_arch), "malware_by_arch": dict(mal_arch),
                           "train_malware_by_arch": dict(train_mal_arch)}, "models": {}}
    for path in sorted(glob.glob(f"{ELF}/d5/*/scores_test.csv")):
        model = path.split("/")[-2]
        rows = [r for r in csv.DictReader(open(path)) if r["sha256"] in meta]
        res = {}
        for name, keep in subsets.items():
            sel = [r for r in rows if keep(meta[r["sha256"]])]
            y = np.array([int(r["label"]) for r in sel], dtype=int)
            p = np.array([float(r["score"]) for r in sel])
            n_mal, n_ben = int(y.sum()), int(len(y) - y.sum())
            if n_mal < 5 or n_ben < 20:
                res[name] = {"n_mal": n_mal, "n_ben": n_ben, "note": "too few of one class"}
                continue
            res[name] = {"n_mal": n_mal, "n_ben": n_ben, "roc_auc": round(float(roc_auc_score(y, p)), 4),
                         "pr_auc": round(float(average_precision_score(y, p)), 4),
                         "tpr_at_fpr": [_tpr_at(y, p, f) for f in (1e-2, 1e-3)]}
        thr = res["all"]["tpr_at_fpr"][0]["threshold"] if "tpr_at_fpr" in res["all"] else 0.5
        weeks = {}
        for r in rows:
            m = meta[r["sha256"]]
            if m["label"] == "1" and m["day"]:
                iso = date.fromisoformat(m["day"]).isocalendar()
                a = weeks.setdefault(f"{iso[0]}-W{iso[1]:02d}", [0, 0])
                a[0] += int(float(r["score"]) > thr)
                a[1] += 1
        res["malware_tpr_by_week_at_fpr_1e-2"] = {k: {"tpr": round(a / b, 4), "n": b} for k, (a, b) in sorted(weeks.items())}
        if os.path.exists(f"{ELF}/d5/{model}/train.json"):
            res["train"] = json.load(open(f"{ELF}/d5/{model}/train.json"))
        out["models"][model] = res
    if os.path.exists(f"{ELF}/d5/prepare.json"):
        out["prepare"] = json.load(open(f"{ELF}/d5/prepare.json"))
    json.dump(out, open(f"{ELF}/d5/summary.json", "w"), indent=1)
    data_vol.commit()
    return out


@app.local_entrypoint()
def summary(out: str = "experiments/results/D5_elf.json"):
    import json
    import os
    res = summary_remote.remote()
    os.makedirs(os.path.dirname(out), exist_ok=True)
    json.dump(res, open(out, "w"), indent=1)
    print("test counts", json.dumps(res["test_counts"]))
    for model, r in res["models"].items():
        cells = [f"{model:<26}"]
        for k in SUBSETS:
            v = r.get(k, {})
            cells.append(f"{k}: AUC {v['roc_auc']} TPR@1e-3 {v['tpr_at_fpr'][1]['tpr']}" if "roc_auc" in v else f"{k}: -")
        print(" | ".join(cells))
