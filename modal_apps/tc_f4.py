"""F4 (and A5): DARPA Transparent Computing Engagement 3, CADETS host (FreeBSD, DTrace), all three releases.

    modal run modal_apps/tc_f4.py::fetch              # Google Drive -> /data/tc/raw (+ ThreaTrace node labels)
    modal run modal_apps/tc_f4.py::prepare            # CDM18 JSON -> /data/tc/cadets/events.tsv.gz, time order
    modal run --detach modal_apps/tc_f4.py::evaluate  # pipelines -> experiments/results/F4_tc_cadets.json

Data: ta1-cadets-e3-official{,-1,-2}.json.tar.gz from the E3 release folder (README-E3.md of
darpa-i2o/Transparent-Computing). Labels: the malicious node UUIDs published by ThreaTrace (Wang et al.,
IEEE TIFS 2022), also used by MAGIC (Jia et al., USENIX Security 2024). Only benign system telemetry and
labels are handled; there is no malware here.
"""
from __future__ import annotations

import json
import os

import modal

app = modal.App("tc-f4")
vol = modal.Volume.from_name("detection-data", create_if_missing=False)
image = (modal.Image.debian_slim(python_version="3.11")
         .pip_install("numpy==1.26.4", "scikit-learn==1.5.2", "scipy==1.14.1", "gdown==5.2.0", "orjson==3.10.12")
         .pip_install("torch==2.4.1", index_url="https://download.pytorch.org/whl/cpu")
         .add_local_python_source("bench", "loggen"))

RAW, OUT = "/data/tc/raw", "/data/tc/cadets"
FILES = {  # Google Drive ids from the E3 release folder 1QlbUFWAGq3Hpl8wVdzOdIoZLFxkII4EK
    "ta1-cadets-e3-official.json.tar.gz": "1AcWrYiBmgAqp7DizclKJYYJJBQbnDMfb",
    "ta1-cadets-e3-official-1.json.tar.gz": "1XLCEhf5DR8xw3S-Fimcj32IKnfzHFPJW",
    "ta1-cadets-e3-official-2.json.tar.gz": "1EycO23tEvZVnN3VxOHZ7gdbSCwqEZTI1",
}
GT_PDF = ("TC_Ground_Truth_Report_E3_Update.pdf", "1mrs4LWkGk-3zA7t7v8zrhm0yEDHe57QU")
GT_URL = "https://raw.githubusercontent.com/threaTrace-detector/threaTrace/master/groundtruth/cadets.txt"
PIPES = ["P2", "P3", "P4", "P5", "P5-hyper", "P6", "P6-hyper", "P6+P4", "P10", "P6-hyper+P10"]


@app.function(image=image, volumes={"/data": vol}, timeout=6 * 3600, cpu=2, memory=4096)
def fetch() -> dict:
    import urllib.request

    import gdown
    os.makedirs(RAW, exist_ok=True)
    sizes = {}
    for name, fid in [*FILES.items(), GT_PDF]:
        dest = os.path.join(RAW, name)
        if not (os.path.exists(dest) and os.path.getsize(dest) > 0):
            gdown.download(id=fid, output=dest, quiet=True)
            vol.commit()
        sizes[name] = os.path.getsize(dest)
    urllib.request.urlretrieve(GT_URL, os.path.join(RAW, "threatrace_cadets.txt"))
    sizes["threatrace_cadets.txt"] = os.path.getsize(os.path.join(RAW, "threatrace_cadets.txt"))
    vol.commit()
    return sizes


def _u(v):
    """CDM18 JSON wraps optional fields: {"com.bbn.tc.schema.avro.cdm18.UUID": "..."} or {"string": "..."}."""
    if isinstance(v, dict):
        return next(iter(v.values()), None)
    return v


@app.function(image=image, volumes={"/data": vol}, timeout=12 * 3600, cpu=4, memory=65536)
def prepare() -> dict:
    """One pass over every record. Keeps the entity tables (subjects, principals, netflows) and writes every
    Event as one TSV row: t, type, subject, object, object2, exec, object path, object2 path, uuid."""
    import gzip
    import tarfile
    from collections import Counter

    import orjson
    os.makedirs(OUT, exist_ok=True)
    subjects, netflows, principals = {}, {}, {}
    types, kinds = Counter(), Counter()
    rows = []
    for name in FILES:
        with tarfile.open(os.path.join(RAW, name), "r|gz") as tar:
            for member in tar:
                if not member.isfile():
                    continue
                f = tar.extractfile(member)
                for line in f:
                    rec = orjson.loads(line)["datum"]
                    (kind, d), = rec.items()
                    kind = kind.rsplit(".", 1)[-1]
                    kinds[kind] += 1
                    if kind == "Event":
                        ts = d.get("timestampNanos") or 0
                        props = (d.get("properties") or {}).get("map", {}) or {}
                        types[d["type"]] += 1
                        rows.append((ts, d["type"], _u(d.get("subject")) or "", _u(d.get("predicateObject")) or "",
                                     _u(d.get("predicateObject2")) or "", props.get("exec", ""),
                                     _u(d.get("predicateObjectPath")) or "", _u(d.get("predicateObject2Path")) or "",
                                     d["uuid"]))
                    elif kind == "Subject":
                        props = (d.get("properties") or {}).get("map", {}) or {}
                        subjects[d["uuid"]] = {"pid": d.get("cid"), "parent": _u(d.get("parentSubject")),
                                               "principal": d.get("localPrincipal"),
                                               "cmd": _u(d.get("cmdLine")), "name": props.get("name")}
                    elif kind == "NetFlowObject":
                        netflows[d["uuid"]] = (_u(d.get("remoteAddress")), _u(d.get("remotePort")),
                                               _u(d.get("localAddress")), _u(d.get("localPort")))
                    elif kind == "Principal":
                        principals[d["uuid"]] = {"user": d.get("userId"), "name": _u(d.get("username"))}
        print(name, "events so far", len(rows), flush=True)
    rows.sort(key=lambda r: r[0])
    clean = lambda s: str(s).replace("\t", " ").replace("\n", " ")
    with gzip.open(os.path.join(OUT, "events.tsv.gz"), "wt", compresslevel=3) as f:
        for r in rows:
            f.write("\t".join(clean(x) for x in r) + "\n")
    json.dump({"subjects": subjects, "netflows": netflows, "principals": principals},
              open(os.path.join(OUT, "entities.json"), "w"))
    stats = {"records_by_kind": dict(kinds), "events_by_type": dict(types), "events": len(rows),
             "first_ns": rows[0][0] if rows else None, "last_ns": rows[-1][0] if rows else None,
             "subjects": len(subjects), "netflows": len(netflows), "principals": len(principals)}
    json.dump(stats, open(os.path.join(OUT, "stats.json"), "w"), indent=1)
    vol.commit()
    return stats


@app.function(image=image, volumes={"/data": vol}, timeout=24 * 3600, cpu=2, memory=32768)
def run_one(pipeline: str, warmup_days: float = 3.0, cases: str = "windows") -> dict:
    """One pipeline over the whole CADETS E3 stream; the first warmup_days are learning only. Scored two ways:
    the usual case metrics (one case per day with malicious events) and node level as in ThreaTrace / MAGIC
    (nodes behind the alerts' evidence vs the labelled nodes)."""
    from bench.core import replay
    from bench.external import TcRun, external_detectors
    from bench.score import latency, score
    run = TcRun.load_tc(OUT, os.path.join(RAW, "threatrace_cadets.txt"), cases=cases)
    warm = warmup_days * 24.0
    eval_from = run.start + warm * 3600
    dets = external_detectors([pipeline], warm)
    for d in dets:
        if d.name == "P10":
            d.record_edges = True
    alerts, timing = replay(run, dets)
    m = score(run, alerts[pipeline], eval_from=eval_from)
    scored = [a for a in alerts[pipeline] if (a.t_detect or 0) >= eval_from]
    eids = {e for a in scored for e in a.evidence}
    nodes = run.nodes_of(eids)
    flagged = {x for e in eids for x in nodes.get(e, [])}
    bad_seen = run.bad_seen_after(eval_from)
    tp = flagged & run.bad
    att = run.attack_nodes()
    node = {"labelled_nodes": len(run.bad), "labelled_nodes_seen_after_warmup": len(bad_seen),
            "flagged_nodes": len(flagged), "true_positive_nodes": len(tp),
            "node_precision": round(len(tp) / len(flagged), 4) if flagged else None,
            "node_recall": round(len(tp & bad_seen) / len(bad_seen), 4) if bad_seen else None,
            "attack_nodes": len(att), "attack_nodes_flagged": len(flagged & att),
            "attack_node_recall": round(len(flagged & att) / len(att), 4) if att else None,
            "attack_node_precision": round(len(flagged & att) / len(flagged), 4) if flagged else None}
    res = {"dataset": "darpa-tc-e3-cadets", "pipeline": pipeline, "events": timing["_events"], "cases_mode": cases,
           "case_sizes": {c["case_id"]: len(c["events"]) for c in run.cases},
           "warmup_days": warmup_days, "wall_s": round(timing["_wall_s"], 1), **m, "node_level": node,
           "latency": latency(timing[pipeline])}
    if pipeline == "P10":
        res["gnn"] = {"train": dets[0].stats, "edges": dets[0].edge_metrics()}
    os.makedirs("/data/results/f4", exist_ok=True)
    json.dump(res, open(f"/data/results/f4/cadets_{cases}_{pipeline}.json", "w"), indent=1)
    vol.commit()
    return res


@app.local_entrypoint()
def evaluate(out: str = "experiments/results/F4_tc_cadets.json", pipes: str = ",".join(PIPES)):
    names = pipes.split(",")
    rows = list(run_one.map(names, return_exceptions=True))
    res = [r if isinstance(r, dict) else {"pipeline": p, "error": repr(r)[:600]} for p, r in zip(names, rows)]
    os.makedirs(os.path.dirname(out), exist_ok=True)
    json.dump(res, open(out, "w"), indent=1)
    for r in res:
        if "error" in r:
            print(r["pipeline"], "ERROR", r["error"][:300])
        else:
            print(f"{r['pipeline']:<9} events {r['events']:,} cases {r['cases']} recall {r['recall']} "
                  f"FP/day {r['fp_per_day']} R@10FP/d {r['recall_at_fp_per_day'].get('10/day')} node {r['node_level']}")


@app.local_entrypoint()
def download():
    print(json.dumps(fetch.remote(), indent=1))


@app.local_entrypoint()
def stats():
    print(json.dumps(prepare.remote(), indent=1)[:3000])


@app.function(image=image, volumes={"/data": vol}, timeout=3600, cpu=2, memory=8192)
def label_hist() -> dict:
    """Labelled (ThreaTrace) events per UTC date-hour: to place the report's local attack times on the data."""
    import gzip
    from collections import Counter
    from datetime import datetime, timezone
    bad = {x.strip() for x in open(os.path.join(RAW, "threatrace_cadets.txt")) if x.strip()}
    c, procs = Counter(), Counter()
    with gzip.open(os.path.join(OUT, "events.tsv.gz"), "rt") as f:
        for line in f:
            p = line.rstrip("\n").split("\t")
            if len(p) < 9:
                continue
            if p[2] in bad or p[3] in bad or p[4] in bad:
                h = datetime.fromtimestamp(int(p[0]) / 1e9, tz=timezone.utc).strftime("%Y-%m-%d %H")
                c[h] += 1
                procs[(h[:10], p[5])] += 1
    return {"by_hour": dict(sorted(c.items())), "top_exec_by_day": {d: [(e, n) for (dd, e), n in procs.most_common(400) if dd == d][:6]
                                                                   for d in sorted({h[:10] for h in c})}}


@app.local_entrypoint()
def hist():
    print(json.dumps(label_hist.remote(), indent=1)[:6000])
