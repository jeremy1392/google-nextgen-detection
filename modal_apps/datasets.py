"""Public real-world datasets, staged in the Modal volume "detection-data" (A1, A5, D5).

    modal run --detach modal_apps/datasets.py::lanl --base "<signed LANL data-fence URL ending in /cyber1/>"
    modal run --detach modal_apps/datasets.py::google2011       # Borg cell trace, May 2011 (public bucket)
    modal run --detach modal_apps/datasets.py::cert             # CERT insider threat, every release (Figshare API)
    modal run --detach modal_apps/datasets.py::elf_malware      # MalwareBazaar ELF (needs secret "abusech")
    modal run --detach modal_apps/datasets.py::elf_benign       # ELF from Debian packages (amd64)
    modal run --detach modal_apps/datasets.py::elf_benign_arch  # ELF executables, every malware architecture
    modal run modal_apps/datasets.py::inventory

Malware from MalwareBazaar is live (not disarmed): it is kept only inside the volume, compressed, and is
never executed; it is read as bytes by the classifiers. The signed LANL URL is passed on the command line
so it never lands in the repository.
"""
from __future__ import annotations

import modal

app = modal.App("detection-datasets")
vol = modal.Volume.from_name("detection-data", create_if_missing=True)
image = modal.Image.debian_slim(python_version="3.11").pip_install("requests", "pyzipper", "zstandard")


def _download(url: str, dst: str, sess=None, chunk: int = 8 << 20) -> int:
    import os

    import requests
    sess = sess or requests.Session()
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with sess.get(url, stream=True, timeout=600) as r:
        r.raise_for_status()
        with open(dst + ".part", "wb") as f:
            for block in r.iter_content(chunk):
                f.write(block)
    os.replace(dst + ".part", dst)
    return os.path.getsize(dst)


@app.function(image=image, volumes={"/data": vol}, timeout=12 * 3600, cpu=2, memory=4096)
def lanl(base: str):
    out = {}
    for name in ("redteam.txt.gz", "dns.txt.gz", "flows.txt.gz", "proc.txt.gz", "auth.txt.gz"):
        out[name] = _download(base.rstrip("/") + "/" + name, f"/data/lanl/{name}")
        vol.commit()
    return out


@app.function(image=image, volumes={"/data": vol}, timeout=20 * 3600, cpu=4, memory=8192)
def google2011(tables: str = "job_events,task_events,machine_events,machine_attributes,task_constraints"):
    """Google cluster trace 2011 (clusterdata-2011-2): a real Borg cell, 29 days. task_usage (the
    largest table) is not needed for scheduling-event calibration and is left out unless asked for."""
    from concurrent.futures import ThreadPoolExecutor

    import requests
    sess = requests.Session()
    api = "https://storage.googleapis.com/storage/v1/b/clusterdata-2011-2/o"
    names, token = [], None
    while True:
        params = {"fields": "items(name,size),nextPageToken", "maxResults": 1000}
        if token:
            params["pageToken"] = token
        page = sess.get(api, params=params, timeout=120).json()
        names += [(i["name"], int(i["size"])) for i in page.get("items", [])]
        token = page.get("nextPageToken")
        if not token:
            break
    wanted = [n for n, _ in names if n.split("/")[0] in tables.split(",") or "/" not in n]
    get = lambda n: _download(f"https://storage.googleapis.com/clusterdata-2011-2/{n}",  # noqa: E731
                              f"/data/google2011/{n}", sess)
    with ThreadPoolExecutor(16) as pool:
        sizes = list(pool.map(get, wanted))
    vol.commit()
    return {"files": len(wanted), "gb": round(sum(sizes) / 1e9, 2),
            "bucket_total_gb": round(sum(s for _, s in names) / 1e9, 1)}


@app.function(image=image, volumes={"/data": vol}, timeout=20 * 3600, cpu=2, memory=4096)
def cert(article: int = 12841247):
    """Every file of the CERT Insider Threat Test Dataset article, through the Figshare API."""
    import requests
    sess = requests.Session()
    files = sess.get(f"https://api.figshare.com/v2/articles/{article}/files", timeout=120).json()
    out = {}
    for f in files:
        out[f["name"]] = _download(f["download_url"], f"/data/cert/{f['name']}", sess)
        vol.commit()
    return out


@app.function(image=image, volumes={"/data": vol}, secrets=[modal.Secret.from_name("abusech")],
              timeout=24 * 3600, cpu=2, memory=8192)
def elf_malware(limit: int = 2000):
    """Recent ELF samples from MalwareBazaar (daily quota: 2,000 downloads per IP). Run once a day to grow
    the corpus. Each sample is kept as the password-protected zip MalwareBazaar serves (password
    "infected"), plus its metadata; nothing is unpacked to disk or executed here."""
    import csv
    import os

    import requests
    key = os.environ["ABUSECH_AUTH_KEY"]
    sess = requests.Session()
    sess.headers["Auth-Key"] = key
    api = "https://mb-api.abuse.ch/api/v1/"
    q = sess.post(api, data={"query": "get_file_type", "file_type": "elf", "limit": 1000}, timeout=120).json()
    rows = q.get("data") or []
    os.makedirs("/data/elf/malware", exist_ok=True)
    index = "/data/elf/malware_index.csv"
    known = set()
    if os.path.exists(index):
        known = {r["sha256"] for r in csv.DictReader(open(index))}
    new = open(index, "a", newline="")
    w = csv.writer(new)
    if not known:
        w.writerow(["sha256", "first_seen", "signature", "tags", "file_size", "status"])
    got = 0
    for r in rows:
        sha = r.get("sha256_hash")
        if not sha or sha in known or got >= limit:
            continue
        resp = sess.post(api, data={"query": "get_file", "sha256_hash": sha}, timeout=300)
        ok = resp.headers.get("content-type", "").startswith("application/zip")
        if ok:
            with open(f"/data/elf/malware/{sha}.zip", "wb") as f:
                f.write(resp.content)
            got += 1
        w.writerow([sha, r.get("first_seen"), r.get("signature"), "|".join(r.get("tags") or []), r.get("file_size"),
                    "ok" if ok else resp.text[:80]])
    new.close()
    vol.commit()
    return {"listed": len(rows), "downloaded": got, "query_status": q.get("query_status")}


@app.function(image=image, volumes={"/data": vol}, secrets=[modal.Secret.from_name("abusech")],
              timeout=24 * 3600, cpu=4, memory=16384)
def elf_malware_bulk(days: int = 30):
    """ELF samples from MalwareBazaar's daily bulk exports (the FAQ's documented bulk channel, ZIP
    password "infected"). Each export is processed on ephemeral disk: only ELF members are kept, as
    zlib-compressed bytes in shards; nothing is executed and the exports themselves are not retained."""
    import csv
    import hashlib
    import os
    import zlib
    from datetime import date, timedelta

    import pyzipper
    import requests
    sess = requests.Session()
    sess.headers["Auth-Key"] = os.environ["ABUSECH_AUTH_KEY"]
    os.makedirs("/data/elf/malware_shards", exist_ok=True)
    index = open("/data/elf/malware_bulk_index.csv", "w", newline="")
    w = csv.writer(index)
    w.writerow(["sha256", "export_day", "name", "size", "shard", "offset", "length"])
    seen, shard, shard_i, count, log = set(), None, 0, 4000, {}
    for d in range(1, days + 1):
        day = (date.today() - timedelta(days=d)).isoformat()
        tmp = f"/tmp/{day}.zip"
        try:
            with sess.get(f"https://datalake.abuse.ch/malware-bazaar/daily/{day}.zip", stream=True, timeout=1800) as r:
                r.raise_for_status()
                with open(tmp, "wb") as f:
                    for block in r.iter_content(8 << 20):
                        f.write(block)
            kept = 0
            with pyzipper.AESZipFile(tmp) as z:
                z.setpassword(b"infected")
                for m in z.infolist():
                    with z.open(m) as fh:
                        if fh.read(4) != b"\x7fELF":
                            continue
                    data = z.read(m)
                    sha = hashlib.sha256(data).hexdigest()
                    if sha in seen:
                        continue
                    seen.add(sha)
                    if count >= 4000:
                        if shard:
                            shard.close()
                        shard = open(f"/data/elf/malware_shards/elfmal-{shard_i:05d}.bin", "wb")
                        shard_i, count = shard_i + 1, 0
                    blob = zlib.compress(data, 6)
                    off = shard.tell()
                    shard.write(blob)
                    count += 1
                    kept += 1
                    w.writerow([sha, day, m.filename, len(data), f"elfmal-{shard_i - 1:05d}.bin", off, len(blob)])
            log[day] = kept
        except Exception as exc:
            log[day] = f"error:{type(exc).__name__}"
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)
        index.flush()
        vol.commit()
    if shard:
        shard.close()
    index.close()
    vol.commit()
    return {"elf_samples": len(seen), "per_day": log}


@app.function(image=image, volumes={"/data": vol}, timeout=20 * 3600, cpu=8, memory=16384)
def elf_benign(target: int = 200_000, seed: int = 0):
    """ELF executables and shared objects from a random sample of Debian (stable, amd64) packages."""
    import csv
    import gzip
    import hashlib
    import io
    import os
    import random
    import tarfile
    import zlib
    from concurrent.futures import ThreadPoolExecutor

    import requests
    import zstandard
    sess = requests.Session()
    mirror = "https://deb.debian.org/debian/"
    packages = gzip.decompress(sess.get(mirror + "dists/stable/main/binary-amd64/Packages.gz", timeout=600).content)
    files = [ln.split(b": ", 1)[1].decode() for ln in packages.split(b"\n") if ln.startswith(b"Filename: ")]
    random.Random(seed).shuffle(files)

    def members(deb: bytes):
        # .deb = ar archive; the payload is data.tar.{xz,zst,gz}
        pos = 8
        while pos + 60 <= len(deb):
            name = deb[pos:pos + 16].decode().strip()
            size = int(deb[pos + 48:pos + 58].decode().strip())
            body = deb[pos + 60:pos + 60 + size]
            pos += 60 + size + (size & 1)
            if name.startswith("data.tar"):
                if name.endswith(".zst"):
                    body = zstandard.ZstdDecompressor().stream_reader(io.BytesIO(body)).read()
                mode = "r:xz" if name.endswith(".xz") else "r:gz" if name.endswith(".gz") else "r:"
                with tarfile.open(fileobj=io.BytesIO(body), mode=mode) as tar:
                    for m in tar:
                        if m.isfile() and m.size >= 1024:
                            data = tar.extractfile(m).read()
                            if data[:4] == b"\x7fELF":
                                yield m.name, data

    def get(path):
        try:
            return path, list(members(sess.get(mirror + path, timeout=600).content))
        except Exception:
            return path, []

    os.makedirs("/data/elf/benign", exist_ok=True)
    seen, n, shard_i, shard, count = set(), 0, 0, None, 4000
    out = open("/data/elf/benign_index.csv", "w", newline="")
    w = csv.writer(out)
    w.writerow(["sha256", "package", "name", "size", "shard", "offset", "length"])
    with ThreadPoolExecutor(8) as pool:
        for i in range(0, len(files), 64):
            for path, mem in pool.map(get, files[i:i + 64]):
                for name, data in mem:
                    sha = hashlib.sha256(data).hexdigest()
                    if sha in seen:
                        continue
                    seen.add(sha)
                    if count >= 4000:
                        if shard:
                            shard.close()
                        shard = open(f"/data/elf/benign/elfben-{shard_i:05d}.bin", "wb")
                        shard_i, count = shard_i + 1, 0
                    blob = zlib.compress(data, 6)
                    off = shard.tell()
                    shard.write(blob)
                    count += 1
                    n += 1
                    w.writerow([sha, path, name, len(data), f"elfben-{shard_i - 1:05d}.bin", off, len(blob)])
            out.flush()
            if n >= target:
                break
    if shard:
        shard.close()
    out.close()
    vol.commit()
    return {"elf_files": n, "packages_scanned": min(i + 64, len(files)), "packages_total": len(files)}


OWRT = "https://downloads.openwrt.org/releases/24.10.8/packages/"
DEB, PORTS = "https://deb.debian.org/debian/", "https://deb.debian.org/debian-ports/"
# Benign executables for every architecture the ELF malware comes in (D5): Debian stable, Debian bookworm
# for the MIPS ports it was the last release of, debian-ports for powerpc / sh4 / m68k, sid for loong64, and
# OpenWrt (the embedded-Linux distribution that IoT malware shares its targets with).
ARCH_SOURCES = {
    **{f"debian-{a}": ("deb", DEB, [f"dists/stable/main/binary-{a}/Packages.gz"]) for a in
       ("i386", "armhf", "armel", "arm64", "ppc64el")},
    **{f"debian-{a}": ("deb", DEB, [f"dists/bookworm/main/binary-{a}/Packages.gz"]) for a in ("mipsel", "mips64el")},
    **{f"ports-{a}": ("deb", PORTS, [f"dists/sid/main/binary-{a}/Packages.gz"]) for a in ("powerpc", "sh4", "m68k")},
    "debian-loong64": ("deb", DEB, ["dists/sid/main/binary-loong64/Packages.gz"]),  # official since forky
    **{f"openwrt-{a}": ("ipk", OWRT + a + "/", [f"{feed}/Packages.gz" for feed in
                                                  ("base", "packages", "luci", "routing", "telephony")])
       for a in ("mips_24kc", "mipsel_24kc", "arm_arm926ej-s", "arm_cortex-a7_neon-vfpv4", "aarch64_cortex-a53",
                 "i386_pentium4", "x86_64", "powerpc_464fp")},
}
_SKIP_SECTIONS = {"libs", "libdevel", "oldlibs", "doc", "fonts", "localization", "kernel", "debug", "translations"}


def _exe_kind(data: bytes):
    """(machine, bits, endian, e_type, interp) if data is an ELF executable (ET_EXEC, or ET_DYN with an
    interpreter, i.e. PIE), else None. Shared libraries, objects and kernel modules are not executables."""
    if data[:4] != b"\x7fELF" or len(data) < 64:
        return None
    bits, order = (64 if data[4] == 2 else 32), ("big" if data[5] == 2 else "little")
    u = lambda off, n: int.from_bytes(data[off:off + n], order) if off + n <= len(data) else 0
    e_type, machine = u(16, 2), u(18, 2)
    phoff, phentsize, phnum = (u(32, 8), u(54, 2), u(56, 2)) if bits == 64 else (u(28, 4), u(42, 2), u(44, 2))
    interp = phentsize > 0 and any(u(phoff + i * phentsize, 4) == 3 for i in range(min(phnum, 256)))
    if e_type == 2 or (e_type == 3 and interp):
        return machine, bits, order, e_type, interp
    return None


@app.function(image=image, volumes={"/data": vol}, timeout=6 * 3600, cpu=4, memory=16384)
def elf_benign_source(source: str, cap: int = 3000, per_package: int = 20, seed: int = 0) -> dict:
    """Up to `cap` benign ELF executables from one source (see ARCH_SOURCES), packages drawn at random.
    Shards are flushed before each index flush and commit, so a committed row always has its bytes."""
    import csv
    import gzip
    import hashlib
    import io
    import os
    import random
    import tarfile
    import zlib
    from concurrent.futures import ThreadPoolExecutor

    import requests
    import zstandard
    kind, base, indexes = ARCH_SOURCES[source]
    sess = requests.Session()
    pkgs = []
    for ix in indexes:
        try:
            text = gzip.decompress(sess.get(base + ix, timeout=600).content).decode("utf-8", "replace")
        except Exception:
            continue
        feed = ix.rsplit("/", 1)[0] + "/" if kind == "ipk" else ""
        for stanza in text.split("\n\n"):
            f = dict(ln.split(": ", 1) for ln in stanza.split("\n") if ": " in ln and not ln.startswith(" "))
            name, fn = f.get("Package", ""), f.get("Filename")
            if not fn or f.get("Architecture") == "all":
                continue
            if kind == "deb" and (f.get("Section", "").split("/")[-1] in _SKIP_SECTIONS or name.endswith(
                    ("-dev", "-doc", "-data", "-common", "-dbg")) or (name.startswith("lib") and not any(
                    s in name for s in ("-bin", "-tools", "-utils", "-progs")))):
                continue
            if int(f.get("Size", "0") or 0) > 200_000_000:
                continue
            pkgs.append((f.get("Source", name).split(" ")[0], feed + fn))  # group = source package
    random.Random(seed).shuffle(pkgs)

    def tar_members(blob: bytes, name: str):
        if name.endswith(".zst"):
            blob = zstandard.ZstdDecompressor().stream_reader(io.BytesIO(blob)).read()
        mode = "r:xz" if name.endswith(".xz") else "r:gz" if name.endswith(".gz") else "r:"
        with tarfile.open(fileobj=io.BytesIO(blob), mode=mode) as tar:
            for m in tar:
                if m.isfile() and m.size >= 1024:
                    data = tar.extractfile(m).read()
                    if data[:4] == b"\x7fELF":
                        yield m.name, data

    def members(pkg: bytes):
        if pkg[:8] == b"!<arch>\n":  # .deb (and old-style .ipk): ar archive with data.tar.*
            pos = 8
            while pos + 60 <= len(pkg):
                name = pkg[pos:pos + 16].decode().strip().rstrip("/")
                size = int(pkg[pos + 48:pos + 58].decode().strip())
                body = pkg[pos + 60:pos + 60 + size]
                pos += 60 + size + (size & 1)
                if name.startswith("data.tar"):
                    yield from tar_members(body, name)
        else:  # OpenWrt .ipk: gzip'd tar holding ./data.tar.gz
            with tarfile.open(fileobj=io.BytesIO(pkg), mode="r:gz") as outer:
                for m in outer:
                    if m.isfile() and m.name.lstrip("./").startswith("data.tar"):
                        yield from tar_members(outer.extractfile(m).read(), m.name)

    def get(item):
        group, path = item
        try:
            out = []
            for name, data in members(sess.get(base + path, timeout=600).content):
                k = _exe_kind(data)
                if k:
                    out.append((name, data, k))
                    if len(out) >= per_package:
                        break
            return group, path, out
        except Exception:
            return group, path, []

    root = "/data/elf/benign_arch"
    os.makedirs(root, exist_ok=True)
    index = open(f"{root}/{source}.csv", "w", newline="")
    w = csv.writer(index)
    w.writerow(["sha256", "source", "group", "package", "name", "size", "machine", "bits", "endian", "e_type",
                "interp", "shard", "offset", "length"])
    seen, n, scanned, shard_i, shard, count = set(), 0, 0, 0, None, 4000
    with ThreadPoolExecutor(8) as pool:
        for i in range(0, len(pkgs), 32):
            for group, path, mem in pool.map(get, pkgs[i:i + 32]):
                scanned += 1
                for name, data, (machine, bits, order, e_type, interp) in mem:
                    sha = hashlib.sha256(data).hexdigest()
                    if sha in seen or n >= cap:
                        continue
                    seen.add(sha)
                    if count >= 4000:
                        if shard:
                            shard.close()
                        shard = open(f"{root}/{source}-{shard_i:05d}.bin", "wb")
                        shard_i, count = shard_i + 1, 0
                    blob = zlib.compress(data, 6)
                    off = shard.tell()
                    shard.write(blob)
                    count += 1
                    n += 1
                    w.writerow([sha, source, f"{source.split('-')[0]}:{group}", path, name, len(data), machine, bits,
                                order, e_type, int(interp), f"{source}-{shard_i - 1:05d}.bin", off, len(blob)])
            if shard:
                shard.flush()
            index.flush()
            vol.commit()
            if n >= cap:
                break
    if shard:
        shard.close()
    index.close()
    vol.commit()
    return {"source": source, "executables": n, "packages_scanned": scanned, "packages_listed": len(pkgs)}


@app.local_entrypoint()
def elf_benign_arch(cap: int = 3000):
    import json
    rows = list(elf_benign_source.map(list(ARCH_SOURCES), kwargs={"cap": cap}, return_exceptions=True))
    res = [r if isinstance(r, dict) else {"error": repr(r)[:300]} for r in rows]
    print(json.dumps(res, indent=1))


@app.function(image=image, volumes={"/data": vol}, timeout=1800)
def inventory():
    import os
    out = {}
    for top in sorted(os.listdir("/data")):
        total, files = 0, 0
        for root, _, fs in os.walk(f"/data/{top}"):
            files += len(fs)
            total += sum(os.path.getsize(os.path.join(root, f)) for f in fs)
        out[top] = {"files": files, "gb": round(total / 1e9, 2)}
    return out


@app.local_entrypoint()
def main():
    print(inventory.remote())
