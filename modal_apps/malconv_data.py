"""Real binaries for the MalConv experiments (D1-D7), staged in the Modal volume "malconv-data".

    modal run modal_apps/malconv_data.py                                   # SOREL meta.db + schema
    modal run --detach modal_apps/malconv_data.py::malware                 # ~1M SOREL malware binaries
    modal run --detach modal_apps/malconv_data.py::benign                  # every benign PE we can source
    modal run modal_apps/malconv_data.py::stats

Malware: SOREL-20M binaries (Sophos / ReversingLabs), already "disarmed" by their authors
(FileHeader.Machine and OptionalHeader.Subsystem set to 0), kept as the zlib objects they publish.
Benign: real open-source / redistributable Windows PE files from several toolchains (MSVC builds of
Python, .NET runtimes and PowerShell; GCC, LLVM and UCRT builds from every MSYS2 Windows repository,
x86 / x64 / ARM64). Every benign file gets the SAME two header fields zeroed, so the classes cannot be
told apart by that artefact. Files are stored whole, zlib-compressed, packed in shards of 4,000 with
an index (sha256 -> shard, offset, length). Nothing is executed; nothing is copied to the local machine.
"""
from __future__ import annotations

import modal

app = modal.App("malconv-data")
vol = modal.Volume.from_name("malconv-data", create_if_missing=True)
image = modal.Image.debian_slim(python_version="3.11").pip_install("boto3", "zstandard", "requests", "pefile")
BUCKET, PREFIX = "sorel-20m", "09-DEC-2020"
SHARD = 4000


def _s3():
    import boto3
    from botocore import UNSIGNED
    from botocore.config import Config
    return boto3.client("s3", region_name="us-east-1",
                        config=Config(signature_version=UNSIGNED, max_pool_connections=128,
                                      retries={"max_attempts": 5, "mode": "adaptive"}))


def header_fields(head: bytes) -> tuple[int, int] | None:
    if len(head) < 0x40 or head[:2] != b"MZ":
        return None
    pe = int.from_bytes(head[0x3C:0x40], "little")
    if pe + 24 + 70 > len(head) or head[pe:pe + 4] != b"PE\0\0":
        return None
    return int.from_bytes(head[pe + 4:pe + 6], "little"), int.from_bytes(head[pe + 92:pe + 94], "little")


def disarm(data: bytes) -> bytes | None:
    """Zero FileHeader.Machine and OptionalHeader.Subsystem, exactly what SOREL did to its malware."""
    if header_fields(data[:65536]) is None:
        return None
    pe = int.from_bytes(data[0x3C:0x40], "little")
    b = bytearray(data)
    b[pe + 4:pe + 6] = b"\0\0"          # FileHeader.Machine
    b[pe + 92:pe + 94] = b"\0\0"        # OptionalHeader.Subsystem (offset 68 in PE32 and PE32+)
    return bytes(b)


class Shards:
    """Append zlib blobs to numbered shard files; remember where each one went."""

    def __init__(self, root: str, prefix: str):
        import os
        os.makedirs(root, exist_ok=True)
        self.root, self.prefix, self.n, self.count, self.f, self.name = root, prefix, 0, SHARD, None, None

    def add(self, blob: bytes) -> tuple[str, int, int]:
        if self.count >= SHARD:
            if self.f:
                self.f.close()
            self.name = f"{self.prefix}-{self.n:05d}.bin"
            self.f = open(f"{self.root}/{self.name}", "wb")
            self.n, self.count = self.n + 1, 0
        off = self.f.tell()
        self.f.write(blob)
        self.count += 1
        return self.name, off, len(blob)

    def close(self):
        if self.f:
            self.f.close()


# ---------------------------------------------------------------------- SOREL metadata
@app.function(image=image, volumes={"/data": vol}, timeout=3 * 3600, cpu=2, memory=8192)
def meta():
    import os
    import sqlite3
    os.makedirs("/data/sorel", exist_ok=True)
    path = "/data/sorel/meta.db"
    if not os.path.exists(path):
        _s3().download_file(BUCKET, f"{PREFIX}/processed-data/meta.db", path)
        vol.commit()
    con = sqlite3.connect(path)
    q = lambda sql: con.execute(sql).fetchall()  # noqa: E731
    return {"rows": q("select is_malware, count(*), min(rl_fs_t), max(rl_fs_t) from meta group by is_malware")}


# ---------------------------------------------------------------------- malware
TAGS = ["adware", "flooder", "ransomware", "dropper", "spyware", "packed", "crypto_miner", "file_infector",
        "installer", "worm", "downloader"]


@app.function(image=image, volumes={"/data": vol}, timeout=20 * 3600, cpu=8, memory=32768)
def malware(n_train: int = 800_000, n_val: int = 50_000, n_test: int = 150_000, max_gb: float = 850.0,
            seed: int = 0):
    """Temporal split on first-seen time: train from the oldest 70%, validation from 70-85%,
    test from the newest 15%. Stops before max_gb of stored data (Modal includes 1 TiB/month free)."""
    import csv
    import random
    import sqlite3
    import zlib
    from concurrent.futures import ThreadPoolExecutor

    con = sqlite3.connect("/data/sorel/meta.db")
    rows = con.execute(f"select sha256, rl_fs_t, rl_ls_const_positives, {', '.join(TAGS)} from meta "
                       "where is_malware = 1 and rl_fs_t is not null").fetchall()
    rows.sort(key=lambda r: r[1])
    n = len(rows)
    pools = {"train": rows[: int(n * 0.70)], "val": rows[int(n * 0.70): int(n * 0.85)], "test": rows[int(n * 0.85):]}
    rng = random.Random(seed)
    picks = []
    for split, k in (("test", n_test), ("val", n_val), ("train", n_train)):  # test first: it must be complete
        picks += [(r, split) for r in rng.sample(pools[split], min(k, len(pools[split])))]
    s3 = _s3()

    def get(item):
        r, split = item
        try:
            blob = s3.get_object(Bucket=BUCKET, Key=f"{PREFIX}/binaries/{r[0]}")["Body"].read()
            head = zlib.decompressobj().decompress(blob, 4096)
            return r, split, blob, header_fields(head), "ok"
        except Exception as exc:
            return r, split, None, None, f"error:{type(exc).__name__}"

    shards = Shards("/data/malware", "mal")
    out = open("/data/malware_index.csv", "w", newline="")
    w = csv.writer(out)
    w.writerow(["sha256", "split", "first_seen", "positives", "tags", "shard", "offset", "length", "machine",
                "subsystem", "status"])
    stored = 0
    counts = {"ok": 0, "error": 0}
    with ThreadPoolExecutor(96) as pool:
        for i in range(0, len(picks), 2000):
            for r, split, blob, hf, status in pool.map(get, picks[i:i + 2000]):
                tags = "".join(str(int(x or 0)) for x in r[3:])
                if blob is None:
                    counts["error"] += 1
                    w.writerow([r[0], split, r[1], r[2], tags, "", "", "", "", "", status])
                    continue
                name, off, ln = shards.add(blob)
                stored += ln
                counts["ok"] += 1
                w.writerow([r[0], split, r[1], r[2], tags, name, off, ln, hf[0] if hf else "", hf[1] if hf else "",
                            status])
            out.flush()
            if (i // 2000) % 25 == 0:
                vol.commit()
            if stored > max_gb * 1e9:
                break
    shards.close()
    out.close()
    vol.commit()
    return {"malware_in_meta": n, "requested": len(picks), **counts, "stored_gb": round(stored / 1e9, 1),
            "periods": {k: [v[0][1], v[-1][1]] for k, v in pools.items()}}


# ---------------------------------------------------------------------- benign
PY_EMBED = ["3.8.10", "3.9.13", "3.10.11", "3.11.9", "3.12.7", "3.13.1"]
NUGET = [("Microsoft.NETCore.App.Runtime.win-x64", v) for v in ("6.0.36", "7.0.20", "8.0.11", "9.0.0")] + \
        [("Microsoft.NETCore.App.Runtime.win-x86", v) for v in ("8.0.11",)] + \
        [("Microsoft.NETCore.App.Runtime.win-arm64", v) for v in ("8.0.11",)] + \
        [("Microsoft.WindowsDesktop.App.Runtime.win-x64", v) for v in ("6.0.36", "8.0.11")] + \
        [("Microsoft.AspNetCore.App.Runtime.win-x64", v) for v in ("6.0.36", "8.0.11")]
PWSH = ["7.2.24", "7.4.6"]


@app.function(image=image, volumes={"/data": vol}, timeout=20 * 3600, cpu=8, memory=32768)
def benign(target: int = 10_000_000, seed: int = 0, repos: str = "mingw64,ucrt64,clang64,mingw32,clangarm64",
           include_ms: bool = True, tag: str = ""):
    """tag='' writes /data/benign + /data/benign_index.csv; tag='clang64' writes /data/benign_clang64 and
    /data/benign_index_clang64.csv (one job per repository, run in parallel)."""
    import csv
    import hashlib
    import io
    import random
    import re
    import tarfile
    import zipfile
    import zlib
    from concurrent.futures import ThreadPoolExecutor

    import requests
    import zstandard

    sess = requests.Session()
    seen: set = set()
    root = f"/data/benign_{tag}" if tag else "/data/benign"
    shards = Shards(root, f"ben_{tag}" if tag else "ben")
    out = open(f"/data/benign_index_{tag}.csv" if tag else "/data/benign_index.csv", "w", newline="")
    w = csv.writer(out)
    w.writerow(["sha256", "source", "origin", "name", "size", "machine_before", "subsystem_before", "shard",
                "offset", "length"])
    log, per_source = {}, {}

    def fetch(url):
        r = sess.get(url, timeout=600)
        r.raise_for_status()
        return r.content

    def store(name, data, source, origin):
        if len(data) < 1024 or len(data) > 128 * 2**20:
            return
        armed = header_fields(data[:65536])
        d = disarm(data)
        if d is None or armed is None:
            return
        sha = hashlib.sha256(data).hexdigest()
        if sha in seen:
            return
        seen.add(sha)
        shard, off, ln = shards.add(zlib.compress(d, 6))
        w.writerow([sha, source, origin, name, len(data), armed[0], armed[1], shard, off, ln])
        per_source[source] = per_source.get(source, 0) + 1

    def zip_members(blob):
        with zipfile.ZipFile(io.BytesIO(blob)) as z:
            for m in z.infolist():
                if m.filename.lower().endswith((".exe", ".dll", ".pyd", ".sys")):
                    yield m.filename, z.read(m)

    # MSVC / .NET builds
    urls = [(f"https://www.python.org/ftp/python/{v}/python-{v}-embed-{a}.zip", "python_embed")
            for v in PY_EMBED for a in ("amd64", "win32")]
    urls += [(f"https://www.nuget.org/api/v2/package/{p}/{v}", "dotnet") for p, v in NUGET]
    urls += [(f"https://github.com/PowerShell/PowerShell/releases/download/v{v}/PowerShell-{v}-win-x64.zip",
              "powershell") for v in PWSH]
    for url, source in (urls if include_ms else []):
        try:
            for name, data in zip_members(fetch(url)):
                store(name, data, source, url)
            log[url] = "ok"
        except Exception as exc:
            log[url] = f"error:{type(exc).__name__}"
    out.flush()

    # GCC / LLVM / UCRT builds, x86 / x64 / ARM64: every MSYS2 Windows repository, latest version of each
    # package (docs / data-only packages skipped). Modest concurrency: this is a community mirror.
    def extract(base, fname):
        try:
            blob = fetch(base + fname)
            got = []
            with zstandard.ZstdDecompressor().stream_reader(io.BytesIO(blob)) as zr:
                with tarfile.open(fileobj=zr, mode="r|") as tar:
                    for m in tar:
                        if m.isfile() and m.name.lower().endswith((".exe", ".dll", ".pyd")):
                            got.append((m.name, tar.extractfile(m).read()))
            return fname, got
        except Exception:
            return fname, []

    for repo in repos.split(","):
        base = f"https://mirror.msys2.org/mingw/{repo}/"
        try:
            listing = fetch(base).decode("utf-8", "replace")
        except Exception as exc:
            log[base] = f"error:{type(exc).__name__}"
            continue
        latest = {}
        for f in re.findall(r'href="(mingw-w64-[^"]+[.]pkg[.]tar[.]zst)"', listing):
            name = re.sub(r"-[^-]+-[^-]+-any[.]pkg[.]tar[.]zst$", "", f)
            if not re.search(r"-(docs?|data|sources?)$", name):
                latest[name] = f
        pkgs = list(latest.values())
        random.Random(seed).shuffle(pkgs)
        scanned = 0
        with ThreadPoolExecutor(8) as pool:
            for i in range(0, len(pkgs), 32):
                for fname, members in pool.map(lambda f: extract(base, f), pkgs[i:i + 32]):
                    for name, data in members:
                        store(name, data, f"msys2_{repo}", base + fname)
                scanned = min(i + 32, len(pkgs))
                out.flush()
                if sum(per_source.values()) >= target:
                    break
        log[base] = f"{scanned}/{len(pkgs)} packages"
        vol.commit()
        if sum(per_source.values()) >= target:
            break
    shards.close()
    out.close()
    vol.commit()
    return {"total": sum(per_source.values()), "by_source": per_source, "log": log}


@app.function(image=image, volumes={"/data": vol}, timeout=1800)
def stats():
    import csv
    import os
    out = {}
    for name in ("malware_index.csv", "benign_index.csv"):
        p = f"/data/{name}"
        if os.path.exists(p):
            rows = list(csv.DictReader(open(p)))
            ok = [r for r in rows if r.get("shard")]
            out[name] = {"rows": len(rows), "stored": len(ok)}
            if name.startswith("malware"):
                out[name]["by_split"] = {s: sum(r["split"] == s for r in ok) for s in ("train", "val", "test")}
                out[name]["machine_zero"] = sum(r["machine"] == "0" for r in ok)
            else:
                src = {}
                for r in ok:
                    src[r["source"]] = src.get(r["source"], 0) + 1
                out[name]["by_source"] = src
    total = 0
    for root, _, files in os.walk("/data"):
        total += sum(os.path.getsize(os.path.join(root, f)) for f in files)
    out["volume_gb"] = round(total / 1e9, 1)
    return out


@app.local_entrypoint()
def main():
    print(meta.remote())
