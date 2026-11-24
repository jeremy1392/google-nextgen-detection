"""Prod data access & storage: Colossus curator metadata, chunk I/O totals, Spanner and
Bigtable audit, B4 cross-site replication."""
from __future__ import annotations

from ..world import CELLS

CURATOR_OPS = [("Open", 60), ("Stat", 20), ("List", 8), ("Create", 10), ("Delete", 2)]
SQL = {
    "Threads": ["SELECT ThreadId, Snippet FROM Threads WHERE UserId = @p0 ORDER BY Ts DESC LIMIT @p1",
                "SELECT COUNT(*) FROM Threads WHERE UserId = @p0 AND Unread = TRUE"],
    "Messages": ["SELECT * FROM Messages WHERE UserId = @p0 AND ThreadId = @p1"],
    "Labels": ["SELECT LabelId, Name FROM Labels WHERE UserId = @p0"],
    "Files": ["SELECT * FROM Files WHERE OwnerId = @p0 AND ParentId = @p1 LIMIT @p2",
              "SELECT FileId, Size FROM Files WHERE FileId IN UNNEST(@p0)"],
    "Permissions": ["SELECT * FROM Permissions WHERE FileId = @p0"],
    "Revisions": ["SELECT * FROM Revisions WHERE FileId = @p0 ORDER BY Rev DESC LIMIT 1"],
    "Users": ["SELECT UserId, Status FROM Users WHERE PrimaryEmail = @p0",
              "SELECT * FROM Users WHERE DomainId = @p0 LIMIT @p1"],
    "Groups": ["SELECT GroupId FROM Groups WHERE MemberId = @p0"],
    "Domains": ["SELECT * FROM Domains WHERE DomainId = @p0"],
}


def install(sim, w) -> None:
    sim.every(60, lambda t, p: _curator(sim, w, t, p), phase=12)
    sim.every(sim.agg_window, lambda t, p: _chunk_io(sim, w, t, p), phase=sim.agg_window - 1)
    sim.every(60, lambda t, p: _spanner(sim, w, t, p), phase=13)
    sim.every(60, lambda t, p: _bigtable(sim, w, t, p), phase=14)
    sim.every(600, lambda t, p: _b4(sim, w, t, p), phase=599)


def curator(sim, w, ts, *, principal, cell, op, path, dataset=None, job=None, device_id=None, extra=None, label=None):
    ds = w.datasets.get(dataset) if dataset else None
    payload = {"op": op, "path": path, "dataset": dataset, "classification": ds.classification if ds else None,
               "curator": f"curator-{sim.rng.randrange(5)}.{cell}", **(extra or {})}
    if op == "Open":
        payload["mode"] = "r"
    return sim.emit(ts, "colossus.curator", op, payload, outcome="success", label=label,
                    site=CELLS[cell]["site"], cell=cell, principal=principal, job=job, device_id=device_id)


def _colossus_users(w):
    return [(s, d) for s in w.services.values() for d in s.data if w.datasets[d].store == "colossus"]


def _curator(sim, w, t, period) -> None:
    r = sim.rng
    pairs = _colossus_users(w)
    for _ in range(sim.poisson(22 * sim.scale * sim.prod_load(t))):
        s, dname = r.choice(pairs)
        cell = r.choice(s.cells)
        op = r.choices([o[0] for o in CURATOR_OPS], [o[1] for o in CURATOR_OPS])[0]
        curator(sim, w, t + r.random() * period, principal=s.principal, cell=cell, op=op,
                path=w.datasets[dname].random_file(r, cell), dataset=dname, job=s.name)
    # People browsing their own home directories.
    humans = [x for x in w.active(t) if x.user.role in ("swe", "sre", "research")]
    for _ in range(sim.poisson(0.01 * len(humans))):
        x = r.choice(humans)
        cell = r.choice(list(CELLS))
        curator(sim, w, t + r.random() * period, principal=x.user.principal, cell=cell, op=r.choice(["List", "Stat"]),
                path=f"/cns/{cell}/home/{x.user.name}/{r.choice(['scratch', 'notebooks', 'exports'])}",
                device_id=x.device.device_id)


def _chunk_io(sim, w, t, period) -> None:
    """Bytes moved per (principal, dataset, cell) over the last window, as the D servers report it."""
    r = sim.rng
    t0 = t - period
    load = sim.prod_load(t)
    night = 1.0 <= sim.local_hour(t) < 4.5
    rows: dict[tuple, dict] = {}
    for s, dname in _colossus_users(w):
        n_col = sum(1 for d in s.data if w.datasets[d].store == "colossus")
        for cell in s.cells:
            base = s.io_mb_s * 1e6 * period / max(n_col, 1) * load * sim.noise(0.3)
            if s.name == "backup-pipeline":
                base *= 8.0 if night else 0.3  # nightly backup window: big and benign
            writes = dname == "backups" or (s.name == "gemini-trainer" and dname == "gemini-weights") \
                or s.name in ("search-indexer", "security-ingest")
            rows[(s.principal, dname, cell)] = {
                "bytes_read": int(base * (0.1 if writes else 1.0)),
                "bytes_written": int(base * (0.9 if writes else 0.02)), "label": None}
    for o in sim.overlays("chunk_io", t0, t):
        row = rows.setdefault(o["key"], {"bytes_read": 0, "bytes_written": 0, "label": None})
        frac = (min(o["t1"], t) - max(o["t0"], t0)) / period
        row["bytes_read"] += int(o["value"] * frac)
        row["label"] = row["label"] or o["label"]
    for (principal, dname, cell), row in rows.items():
        total = row["bytes_read"] + row["bytes_written"]
        if total <= 0:
            continue
        ds = w.datasets[dname]
        sim.emit(t + r.uniform(0, 5), "colossus.chunkserver", "io_window",
                 {"window_s": period, "dataset": dname, "classification": ds.classification,
                  "path_prefix": ds.location(cell), "bytes_read": row["bytes_read"],
                  "bytes_written": row["bytes_written"], "chunks_touched": max(1, total // (8 * 2**20)),
                  "racks": 9, "encoding": "RS(6,3)"},
                 label=row["label"], site=CELLS[cell]["site"], cell=cell, principal=principal)


def _spanner(sim, w, t, period) -> None:
    r = sim.rng
    users = [(s, d) for s in w.services.values() for d in s.data if w.datasets[d].store == "spanner"]
    for _ in range(sim.poisson(14 * sim.scale * sim.prod_load(t))):
        s, dname = r.choice(users)
        ds = w.datasets[dname]
        cell = r.choice(s.cells)
        method = "StreamingRead" if s.name == "backup-pipeline" else r.choices(["ExecuteSql", "Read", "Commit"], [6, 3, 1])[0]
        table = r.choice(ds.tables)
        rows = int(r.lognormvariate(8, 0.5)) if method == "StreamingRead" else int(r.lognormvariate(1.5, 1.0))
        sim.emit(t + r.random() * period, "spanner.audit", method,
                 {"database": ds.location(cell), "table": table, "classification": ds.classification,
                  "sql_fingerprint": r.choice(SQL.get(table, ["SELECT * FROM " + table + " WHERE Id = @p0"]))
                  if method == "ExecuteSql" else None,
                  "rows_returned": rows if method != "Commit" else 0, "mutations": r.randrange(1, 20) if method == "Commit" else 0,
                  "bytes": rows * r.randrange(200, 2000), "latency_ms": round(r.lognormvariate(1.8, 0.6), 1)},
                 outcome="ok", site=CELLS[cell]["site"], cell=cell, principal=s.principal, job=s.name)
    if r.random() < 0.002:  # rare schema change, always under an approved change
        ds = w.datasets[r.choice(["gmail-metadata", "drive-metadata", "gws-directory"])]
        cell = "zrh-c1"
        sim.emit(t + r.random() * period, "spanner.audit", "UpdateDatabaseDdl",
                 {"database": ds.location(cell), "classification": ds.classification,
                  "ddl": f"ALTER TABLE {r.choice(ds.tables)} ADD COLUMN Ext{r.randrange(99)} STRING(MAX)",
                  "change_ticket": f"chg-{sim.hex(6)}"},
                 outcome="ok", site="zrh", cell=cell, principal="svc:schema-migrator")


def _bigtable(sim, w, t, period) -> None:
    r = sim.rng
    users = [(s, d) for s in w.services.values() for d in s.data if w.datasets[d].store == "bigtable"]
    for _ in range(sim.poisson(8 * sim.scale * sim.prod_load(t))):
        s, dname = r.choice(users)
        ds = w.datasets[dname]
        cell = r.choice(s.cells)
        writer = s.name in ("search-indexer", "security-ingest")
        method = "MutateRows" if writer and r.random() < 0.8 else "ReadRows"
        n = int(r.lognormvariate(3, 1.2))
        sim.emit(t + r.random() * period, "bigtable.audit", method,
                 {"table": f"{ds.location(cell)}/{r.choice(ds.tables)}", "classification": ds.classification,
                  "rows": n, "bytes": n * r.randrange(300, 5000), "row_range": f"{sim.hex(4)}..{sim.hex(4)}",
                  "app_profile": s.name, "latency_ms": round(r.lognormvariate(1.5, 0.6), 1)},
                 outcome="ok", site=CELLS[cell]["site"], cell=cell, principal=s.principal, job=s.name)


def _b4(sim, w, t, period) -> None:
    r = sim.rng
    t0 = t - period
    night = 1.0 <= sim.local_hour(t) < 4.5
    classes = {
        "colossus_geo_replication": 7.5e11 * sim.prod_load(t),
        "spanner_replication": 4.0e10,
        "backup": 3.0e12 if night else 1.0e11,
        "monitoring": 2.0e9,
    }
    for cls, base in classes.items():
        nbytes = base * sim.scale * sim.noise(0.2)
        label = None
        for o in sim.overlays("b4", t0, t):
            if o["key"] == (cls,):
                nbytes += o["value"] * (min(o["t1"], t) - max(o["t0"], t0)) / period
                label = label or o["label"]
        src, dst = ("zrh", "ghs") if r.random() < 0.7 else ("ghs", "zrh")
        sim.emit(t + r.uniform(0, 5), "net.b4", "flow_window",
                 {"window_s": period, "flow_class": cls, "src_site": src, "dst_site": dst, "bytes": int(nbytes),
                  "flows": r.randrange(200, 4000), "dscp": "AF31" if cls != "monitoring" else "CS2",
                  "path": f"b4/{src}-{dst}-{r.randrange(1, 3)}"}, label=label, site=src)
