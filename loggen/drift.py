"""Baseline drift: legitimate changes that move "normal" (H4 experiments).

--drift launch@26h,reorg@30h,holiday@48h+24h
  launch   a new service goes live: new jobs, new RPC edges, new data access (benign novelty)
  reorg    20% of engineers change team, so they touch services they never touched
  holiday  presence drops to 25% over the given span
"""
from __future__ import annotations

from .engine import parse_duration
from .sources import admin, borg, corp
from .world import Dataset


def parse(spec: str) -> list[tuple[str, float, float]]:
    out = []
    for item in filter(None, (x.strip() for x in spec.split(","))):
        kind, _, when = item.partition("@")
        at, _, span = when.partition("+")
        out.append((kind, parse_duration(at or "0"), parse_duration(span) if span else 86400.0))
    return out


def schedule(sim, w, spec: str) -> list[dict]:
    log = []
    for i, (kind, at, span) in enumerate(parse(spec)):
        t = sim.start + at
        cid = f"D{i + 1:02d}-{kind}"
        if kind == "holiday":
            sim.holidays.append((t, t + span))
        elif kind == "launch":
            sim.at(t, _launch, sim, w, cid)
        elif kind == "reorg":
            sim.at(t, _reorg, sim, w, cid, log)
        else:
            raise ValueError(f"unknown drift kind: {kind}")
        log.append({"drift_id": cid, "kind": kind, "at": t, "span_s": span if kind == "holiday" else None})
    return log


def _launch(ts, sim, w, cid) -> None:
    owner = w.pick_member("workspace")
    sim.open_case(cid, {"case_id": cid, "kind": "benign", "benign_type": "service_launch", "start": ts,
                        "end": ts + 3 * 3600, "description": "notes-frontend goes live (new jobs, edges, data access)",
                        "entities": {"principal": "svc:notes-frontend", "job": "notes-frontend",
                                     "owner": owner.principal}})
    sess = w.session_for(owner, ts)
    corp.access(sim, w, sess, ts, app="borgcfg", path="/jobs/new", label=(cid, "launch"))
    mpa_id, t_ok = admin.mpa(sim, w, sess, ts + 5, operation="CreateJob", target="notes-frontend",
                             change={"new_service": "notes-frontend"},
                             justification="launch notes-frontend (launch review approved)",
                             approver=w.pick_member("workspace", exclude=owner), delay=900, label=(cid, "launch"))
    sim.at(t_ok + 30, _go_live, sim, w, cid, owner, sess, mpa_id)


def _go_live(ts, sim, w, cid, owner, sess, mpa_id) -> None:
    w.datasets["notes-metadata"] = Dataset("notes-metadata", "spanner", "user_data", "workspace", ["Notes", "Shares"])
    spec = dict(name="notes-frontend", team="workspace", replicas=6, qps=700, calls=[
        ("auth-service", "CheckToken"), ("spanner-server", "ExecuteSql"), ("colossus-curator", "Open")],
        data=["notes-metadata", "drive-blobs"], kind="serving", frontend=True, tpu=False, infra=False, egress=False,
        cells=["zrh-c1", "ghs-c2"], io_mb_s=10.0, latency_ms=60.0)
    s = w.add_service(spec, ts)
    t = ts
    for cell in s.cells:
        borg.audit(sim, w, t, "CreateJob", principal=owner.principal, cell=cell, job=s.name, mpa_id=mpa_id,
                   device_id=sess.device.device_id, read_only=False, label=(cid, "launch"),
                   request={"job": s.name, "bcid": s.bcid[cell], "replicas": len(w.tasks[(s.name, cell)])})
        for k, task in enumerate(w.tasks[(s.name, cell)]):
            borg.start_task(sim, w, task, t + 5 + k * 10, "job_created", label=(cid, "launch"))
        t += 1800


def _reorg(ts, sim, w, cid, log) -> None:
    movers = [u for u in w.users if u.role == "swe" and sim.rng.random() < 0.2]
    teams = ["gmail", "drive", "photos", "search", "workspace", "storage"]
    moves = []
    for u in movers:
        new = sim.rng.choice([t for t in teams if t != u.team])
        moves.append({"principal": u.principal, "from": u.team, "to": new})
        u.team = new
    w.team_members = {}
    for u in w.users:
        w.team_members.setdefault(u.team, []).append(u)
    log.append({"drift_id": cid, "kind": "reorg_moves", "moves": moves})
