"""D5, third platform: macOS Mach-O executables (PE -> ELF -> Mach-O).

    modal run --detach modal_apps/macho_d5.py::collect    # MalwareBazaar daily exports (Mach-O members) + Homebrew
    modal run --detach modal_apps/macho_d5.py::evaluate   # census, splits, GBDT x3, PE MalConv zero-shot
    -> experiments/results/D5_macho.json

Malware: every Mach-O member of MalwareBazaar's daily bulk exports over the last `days` days (thin or universal
binaries; universal files are told apart from Java class files, which share the 0xCAFEBABE magic). Benign:
executables from Homebrew bottles (the macOS packages of Homebrew/core, arm64 and x86-64 builds), at most 20
per formula, grouped by formula for the split. As for ELF, only executables (MH_EXECUTE) are compared. Live
samples stay compressed inside the volume and are never executed; only aggregate numbers come back.
"""
from __future__ import annotations

import hashlib
import json
import os

import modal

app = modal.App("macho-d5")
data_vol = modal.Volume.from_name("detection-data", create_if_missing=False)
pe_vol = modal.Volume.from_name("malconv-data", create_if_missing=False)
image = (modal.Image.debian_slim(python_version="3.11")
         .pip_install("torch==2.5.1", "numpy==1.26.4", "scikit-learn==1.5.2", "scipy==1.14.1", "pyzipper",
                      "requests")
         .add_local_python_source("bench"))
ROOT = "/data/macho"
MAGIC = {b"\xcf\xfa\xed\xfe": ("thin", 64, "little"), b"\xce\xfa\xed\xfe": ("thin", 32, "little"),
         b"\xfe\xed\xfa\xcf": ("thin", 64, "big"), b"\xfe\xed\xfa\xce": ("thin", 32, "big"),
         b"\xca\xfe\xba\xbe": ("fat", 32, "big"), b"\xca\xfe\xba\xbf": ("fat", 64, "big")}
CPU = {7: "x86", 0x01000007: "x86_64", 12: "arm", 0x0100000C: "arm64", 0x0200000C: "arm64_32", 18: "ppc",
       0x01000012: "ppc64"}
FILETYPE = {1: "object", 2: "execute", 6: "dylib", 7: "dylinker", 8: "bundle", 11: "kext_bundle"}


def macho_header(data: bytes, depth: int = 0) -> dict:
    """Structural facts from the Mach-O header and load commands (no execution)."""
    h = {"size": len(data), "ok": False}
    m = MAGIC.get(data[:4])
    if not m:
        return h
    kind, bits, order = m
    if kind == "fat":
        n = int.from_bytes(data[4:8], "big")
        if not (0 < n < 20) or depth:
            return h
        step = 20 if bits == 32 else 32
        archs = []
        for i in range(n):
            o = 8 + i * step
            cpu = int.from_bytes(data[o:o + 4], "big")
            off = int.from_bytes(data[o + 8:o + 12], "big") if bits == 32 else int.from_bytes(data[o + 8:o + 16], "big")
            archs.append((cpu, off))
        first = archs[0][1]
        inner = macho_header(data[first:first + (4 << 20)], depth + 1) if first < len(data) else {"ok": False}
        if not inner.get("ok"):
            return h
        inner.update(size=len(data), fat=True, n_archs=n, archs="+".join(sorted(CPU.get(c, f"c{c}") for c, _ in archs)))
        return inner
    u = lambda off, k: int.from_bytes(data[off:off + k], order) if off + k <= len(data) else 0
    cputype, filetype, ncmds, sizeofcmds, flags = u(4, 4), u(12, 4), u(16, 4), u(20, 4), u(24, 4)
    off = 32 if bits == 64 else 28
    cmds = []
    for _ in range(min(ncmds, 512)):
        cmd, size = u(off, 4), u(off + 4, 4)
        if size < 8:
            break
        cmds.append(cmd)
        off += size
        if off > len(data):
            break
    c = set(cmds)
    h.update(ok=True, fat=False, n_archs=1, archs=CPU.get(cputype, f"c{cputype}"), bits=bits,
             cpu=CPU.get(cputype, f"c{cputype}"), filetype=FILETYPE.get(filetype, f"f{filetype}"), ncmds=ncmds,
             sizeofcmds=sizeofcmds, pie=bool(flags & 0x200000), code_signature=0x1D in c,
             encrypted=(0x21 in c or 0x2C in c), lc_main=0x80000028 in c,
             n_dylibs=sum(x in (0xC, 0x80000018, 0x8000001F) for x in cmds),
             n_segments=sum(x in (0x1, 0x19) for x in cmds), rpath=0x8000001C in c,
             upx=b"UPX!" in data[:4096])
    return h


# ------------------------------------------------------------------------------------------- collection
@app.function(image=image, volumes={"/data": data_vol}, secrets=[modal.Secret.from_name("abusech")],
              timeout=4 * 3600, cpu=2, memory=8192, max_containers=4)
def malware_day(day: str) -> list:
    import zlib

    import pyzipper
    import requests
    sess = requests.Session()
    sess.headers["Auth-Key"] = os.environ["ABUSECH_AUTH_KEY"]
    tmp = f"/tmp/{day}.zip"
    rows = []
    try:
        with sess.get(f"https://datalake.abuse.ch/malware-bazaar/daily/{day}.zip", stream=True, timeout=3600) as r:
            if r.status_code != 200:
                return [{"day": day, "error": f"http {r.status_code}"}]
            with open(tmp, "wb") as f:
                for block in r.iter_content(8 << 20):
                    f.write(block)
        os.makedirs(f"{ROOT}/malware", exist_ok=True)
        shard = f"{ROOT}/malware/{day}.bin"
        with pyzipper.AESZipFile(tmp) as z, open(shard, "wb") as out:
            z.setpassword(b"infected")
            for m in z.infolist():
                with z.open(m) as fh:
                    head = fh.read(8)
                if head[:4] not in MAGIC:
                    continue
                data = z.read(m)
                h = macho_header(data)
                if not h["ok"]:
                    continue
                blob = zlib.compress(data, 6)
                off = out.tell()
                out.write(blob)
                rows.append({"sha256": hashlib.sha256(data).hexdigest(), "label": 1, "group": f"day:{day}",
                             "day": day, "name": m.filename, "store": "malware", "shard": f"{day}.bin",
                             "offset": off, "length": len(blob), **{k: h.get(k) for k in HDR_KEYS}})
        data_vol.commit()
    except Exception as exc:
        rows.append({"day": day, "error": f"{type(exc).__name__}: {str(exc)[:120]}"})
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    return rows


HDR_KEYS = ["size", "fat", "n_archs", "archs", "bits", "cpu", "filetype", "ncmds", "sizeofcmds", "pie",
            "code_signature", "encrypted", "lc_main", "n_dylibs", "n_segments", "rpath", "upx"]


@app.function(image=image, volumes={"/data": data_vol}, timeout=4 * 3600, cpu=2, memory=8192, max_containers=8)
def benign_chunk(items: list, k: int, per_formula: int = 20) -> list:
    """Executables from Homebrew bottles: items = [(formula, tag, url)]. GHCR serves Homebrew's public
    bottles to the anonymous token Homebrew itself uses."""
    import io
    import tarfile
    import zlib

    import requests
    sess = requests.Session()
    sess.headers["Authorization"] = "Bearer QQ=="
    os.makedirs(f"{ROOT}/benign", exist_ok=True)
    shard = f"benign-{k:04d}.bin"
    rows = []
    with open(f"{ROOT}/benign/{shard}", "wb") as out:
        for name, tag, url in items:
            try:
                r = sess.get(url, timeout=600)
                if r.status_code != 200:
                    continue
                kept = 0
                with tarfile.open(fileobj=io.BytesIO(r.content), mode="r:gz") as t:
                    for m in t:
                        if kept >= per_formula or not m.isfile() or m.size < 512:
                            continue
                        f = t.extractfile(m)
                        head = f.read(8)
                        if head[:4] not in MAGIC:
                            continue
                        data = head + f.read()
                        h = macho_header(data)
                        if not h["ok"] or h.get("filetype") != "execute":
                            continue
                        blob = zlib.compress(data, 6)
                        off = out.tell()
                        out.write(blob)
                        kept += 1
                        rows.append({"sha256": hashlib.sha256(data).hexdigest(), "label": 0, "group": f"brew:{name}",
                                     "day": "", "name": f"{name}/{tag}/{m.name}", "store": "benign", "shard": shard,
                                     "offset": off, "length": len(blob), **{k2: h.get(k2) for k2 in HDR_KEYS}})
            except Exception:
                continue
    data_vol.commit()
    return rows


@app.local_entrypoint()
def collect(days: int = 180, formulae: int = 1600, chunks: int = 40):
    import csv
    import random
    from datetime import date, timedelta

    import requests
    day_list = [(date.today() - timedelta(days=d)).isoformat() for d in range(1, days + 1)]
    mal = [r for rows in malware_day.map(day_list, return_exceptions=True) if isinstance(rows, list) for r in rows]
    errors = [r for r in mal if "error" in r]
    mal = [r for r in mal if "error" not in r]
    seen, dedup = set(), []
    for r in sorted(mal, key=lambda r: r["day"]):
        if r["sha256"] not in seen:
            seen.add(r["sha256"])
            dedup.append(r)
    print("malware Mach-O:", len(dedup), "days with errors:", len(errors))
    api = requests.get("https://formulae.brew.sh/api/formula.json", timeout=300).json()
    items = []
    for f in api:
        files = ((f.get("bottle") or {}).get("stable") or {}).get("files") or {}
        arm = next((t for t in ("arm64_sequoia", "arm64_sonoma", "arm64_ventura", "arm64_tahoe") if t in files), None)
        x86 = next((t for t in ("sequoia", "sonoma", "ventura", "tahoe") if t in files), None)
        if arm or x86:
            items.append((f["name"], arm, x86, files))
    random.Random(0).shuffle(items)
    picks = []
    for i, (name, arm, x86, files) in enumerate(items[:formulae]):
        tag = (arm if i % 2 == 0 else x86) or arm or x86  # alternate architectures
        picks.append((name, tag, files[tag]["url"]))
    parts = [picks[i::chunks] for i in range(chunks)]
    ben = [r for rows in benign_chunk.starmap([(p, k) for k, p in enumerate(parts)], return_exceptions=True)
           if isinstance(rows, list) for r in rows]
    bseen, bdedup = set(seen), []
    for r in ben:
        if r["sha256"] not in bseen:
            bseen.add(r["sha256"])
            bdedup.append(r)
    print("benign Mach-O executables:", len(bdedup), "from", len({r['group'] for r in bdedup}), "formulae")
    os.makedirs("experiments/d5_macho", exist_ok=True)
    cols = ["sha256", "label", "group", "day", "name", "store", "shard", "offset", "length", *HDR_KEYS]
    with open("experiments/d5_macho/index.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(dedup + bdedup)
    upload_index.remote(open("experiments/d5_macho/index.csv", encoding="utf-8").read())
    json.dump({"malware_days": days, "malware": len(dedup), "benign": len(bdedup), "day_errors": errors[:20]},
              open("experiments/d5_macho/collect.json", "w"), indent=1)


@app.function(image=image, volumes={"/data": data_vol}, timeout=600)
def upload_index(text: str):
    os.makedirs(ROOT, exist_ok=True)
    open(f"{ROOT}/index.csv", "w").write(text)
    data_vol.commit()


# ------------------------------------------------------------------------------------------- evaluation
def _read(r) -> bytes:
    import zlib
    with open(f"{ROOT}/{r['store']}/{r['shard']}", "rb") as f:
        f.seek(int(r["offset"]))
        return zlib.decompress(f.read(int(r["length"])))


N_HDR = 14


def _features(data: bytes):
    import math

    import numpy as np
    h = macho_header(data)
    cpus = sorted(set(CPU.values()))
    hdr = [cpus.index(h["cpu"]) if h.get("cpu") in cpus else len(cpus), h.get("bits", 0), h.get("fat", False),
           h.get("n_archs", 0), h.get("pie", False), h.get("code_signature", False), h.get("encrypted", False),
           h.get("lc_main", False), h.get("n_dylibs", 0), h.get("n_segments", 0), h.get("rpath", False),
           h.get("upx", False), math.log2(max(h.get("ncmds", 0), 1)), math.log2(max(len(data), 1))]
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


def _chunk(rows):
    import numpy as np
    keep, out = [], []
    for r in rows:
        try:
            data = _read(r)
            if hashlib.sha256(data).hexdigest() != r["sha256"]:
                continue
            out.append(_features(data))
            keep.append(r["sha256"])
        except Exception:
            continue
    return keep, (np.stack(out) if out else np.zeros((0, N_HDR + 512), np.float32))


def _tpr(y, p, fpr):
    import numpy as np
    y, p = np.asarray(y), np.asarray(p)
    neg = np.sort(p[y == 0])[::-1]
    k = int(np.floor(fpr * len(neg)))
    thr = neg[k] if len(neg) > k else neg[-1]
    return float((p[y == 1] > thr).mean())


@app.function(image=image, volumes={"/data": data_vol}, timeout=4 * 3600, cpu=16, memory=32768)
def gbdt(seed: int = 0) -> dict:
    """Census, splits (malware: export days 70/15/15 in time order; benign: formulae 70/15/15 by hash),
    features, and three GBDT views; iterations chosen on validation AUC."""
    import csv
    from collections import Counter
    from concurrent.futures import ProcessPoolExecutor

    import numpy as np
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.metrics import roc_auc_score
    rows = [r for r in csv.DictReader(open(f"{ROOT}/index.csv")) if r["filetype"] == "execute"]
    census = {}
    for lab in ("0", "1"):
        sel = [r for r in rows if r["label"] == lab]
        census["benign" if lab == "0" else "malware"] = {
            "files": len(sel), **{k: dict(Counter(r[k] for r in sel).most_common(8))
                                  for k in ("archs", "fat", "pie", "code_signature", "lc_main", "upx")}}
    days = sorted({r["day"] for r in rows if r["label"] == "1"})
    cut1, cut2 = days[int(0.7 * len(days))], days[int(0.85 * len(days))]
    for r in rows:
        if r["label"] == "1":
            r["split"] = "train" if r["day"] < cut1 else ("val" if r["day"] < cut2 else "test")
        else:
            hb = int(hashlib.md5(f"{seed}:{r['group']}".encode()).hexdigest(), 16) % 100
            r["split"] = "train" if hb < 70 else ("val" if hb < 85 else "test")
    chunks = [rows[i:i + 300] for i in range(0, len(rows), 300)]
    shas, feats = [], []
    with ProcessPoolExecutor(16) as pool:
        for keep, x in pool.map(_chunk, chunks):
            shas += keep
            feats.append(x)
    X = np.concatenate(feats)
    meta = {r["sha256"]: r for r in rows}
    y = np.array([int(meta[s]["label"]) for s in shas])
    split = np.array([meta[s]["split"] for s in shas])
    tr, va, te = split == "train", split == "val", split == "test"
    res = {"census": census, "days": [days[0], days[-1]], "test_days_from": cut2,
           "counts": {s: {"mal": int(((split == s) & (y == 1)).sum()), "ben": int(((split == s) & (y == 0)).sum())}
                      for s in ("train", "val", "test")}, "models": {}}
    os.makedirs(f"{ROOT}/d5", exist_ok=True)
    np.savez_compressed(f"{ROOT}/d5/features.npz", X=X, y=y, split=split, sha=np.array(shas))
    for name, (a, b) in {"gbdt_header": (0, N_HDR), "gbdt_bytes": (N_HDR, N_HDR + 512),
                         "gbdt_header+bytes": (0, N_HDR + 512)}.items():
        best = (-1.0, None, None)
        for it in (50, 100, 200, 400, 800):
            clf = HistGradientBoostingClassifier(max_iter=it, learning_rate=0.05, early_stopping=False,
                                                 random_state=seed, categorical_features=[0] if a == 0 else None,
                                                 class_weight="balanced")
            clf.fit(X[tr, a:b], y[tr])
            v = roc_auc_score(y[va], clf.predict_proba(X[va, a:b])[:, 1])
            if v > best[0] + 1e-5:
                best = (v, it, clf)
        p = best[2].predict_proba(X[te, a:b])[:, 1]
        res["models"][name] = {"iterations": best[1], "val_auc": round(best[0], 5),
                               "test_auc": round(float(roc_auc_score(y[te], p)), 5),
                               "tpr_at_1e-2": round(_tpr(y[te], p, 1e-2), 4), "tpr_at_1e-3": round(_tpr(y[te], p, 1e-3), 4)}
    json.dump(res, open(f"{ROOT}/d5/gbdt.json", "w"), indent=1)
    data_vol.commit()
    return res


@app.function(image=image, gpu="L4", volumes={"/data": data_vol, "/pe": pe_vol}, timeout=2 * 3600, cpu=8,
              memory=32768)
def malconv_zeroshot() -> dict:
    """The D1 PE MalConv, as it is, on the Mach-O test split (first 2 MB of each file)."""
    import numpy as np
    import torch
    from sklearn.metrics import roc_auc_score

    from bench.malconv import build
    d = np.load(f"{ROOT}/d5/features.npz")
    te = d["split"] == "test"
    shas, y = d["sha"][te], d["y"][te]
    import csv
    meta = {r["sha256"]: r for r in csv.DictReader(open(f"{ROOT}/index.csv"))}
    model = build().cuda().eval()
    model.load_state_dict(torch.load("/pe/results/malconv/best.pt", weights_only=True))
    ps = []
    with torch.inference_mode():
        for s in shas:
            data = _read(meta[s])[:2_000_000]
            x = torch.from_numpy(np.frombuffer(data, dtype=np.uint8).astype(np.int64) + 1).unsqueeze(0).cuda()
            ps.append(float(torch.sigmoid(model(x)).item()))
    p = np.array(ps)
    return {"test_files": int(len(y)), "auc": round(float(roc_auc_score(y, p)), 5),
            "tpr_at_1e-2": round(_tpr(y, p, 1e-2), 4), "tpr_at_1e-3": round(_tpr(y, p, 1e-3), 4),
            "benign_flagged_at_0.5": round(float((p[y == 0] > 0.5).mean()), 4),
            "malware_missed_at_0.5": round(float((p[y == 1] <= 0.5).mean()), 4)}


@app.local_entrypoint()
def evaluate(out: str = "experiments/results/D5_macho.json"):
    res = {"gbdt": gbdt.remote()}
    print(json.dumps(res["gbdt"], indent=1)[:3000])
    res["malconv_pe_zeroshot"] = malconv_zeroshot.remote()
    print(res["malconv_pe_zeroshot"])
    res["collect"] = json.load(open("experiments/d5_macho/collect.json"))
    json.dump(res, open(out, "w"), indent=1)
