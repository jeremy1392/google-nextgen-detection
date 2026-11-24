"""Anomaly types for the layers the first batch left uncovered, so that every box of the
diagram has labeled cases, not only the container runtime: endpoint network, identity, code
review, breakglass, scheduling, Spanner / Bigtable, B4, Titan and the TPU runtime.

The static rules (bench P0) were frozen before these types were written, so they also measure
how classic content copes with patterns it was not tuned for. Below intensity 0.5 each type
switches to a subtle form that no single event gives away.
"""
from __future__ import annotations

from .anomalies import _case, _n, _user
from .sources import admin, borg, corp, storage
from .world import CELLS, Session

FAR = [("BR", "Sao Paulo"), ("SG", "Singapore"), ("US", "Seattle"), ("AU", "Sydney")]
NEAR = [("FR", "Lyon"), ("DE", "Stuttgart"), ("IT", "Turin")]


# ---------------------------------------------------------------------- corp: endpoint network
def endpoint_beaconing(ts, sim, w, aid, o):
    """One device resolves random-looking subdomains of one domain and opens small flows to one
    address, on a near-fixed interval."""
    r = sim.rng
    s = r.choice(w.active(ts) or [w.session_for(r.choice(w.users), ts)])
    subtle = o["k"] < 0.5
    base = f"{r.choice(['cdn-sync', 'metrics-push', 'update-check'])}.example.net"
    dst = w.ext_ip(r)
    interval = r.uniform(240, 420) if subtle else r.uniform(45, 90)
    n = _n(sim, o, 20, 60)
    _case(sim, aid, "endpoint_beaconing", ts, ts + n * interval,
          f"{s.device.hostname} contacts {base} / {dst} every ~{interval:.0f}s", o, ["T1071.004"],
          principal=s.user.principal, device_id=s.device.device_id, dst_ip=dst)
    common = dict(site=s.site, host=s.device.hostname, device_id=s.device.device_id, src_ip=s.local_ip)
    for k in range(n):
        t = ts + k * interval * r.uniform(0.95, 1.05)
        sub = f"{r.choice(['img', 'static', 'api', 'edge'])}{r.randrange(10)}" if subtle else sim.hex(r.randrange(20, 40))
        sim.emit(t, "corp.dns", "query", {"query": f"{sub}.{base}", "qtype": "A", "rcode": "NOERROR", "answers": [dst],
                                          "resolver": "10.0.0.53" if s.loc == "office" else "doh",
                                          "latency_ms": round(r.lognormvariate(2.5, 0.4), 1)},
                 outcome="noerror", label=(aid, "dns_periodic"), **common)
        sim.emit(t + 0.05, "corp.netflow", "flow",
                 {"proto": "tcp", "src_port": r.randrange(40000, 65000), "dst_port": 443, "bytes_out": r.randrange(300, 900),
                  "bytes_in": r.randrange(200, 600), "packets": r.randrange(6, 12), "duration_ms": r.randrange(80, 400),
                  "direction": "outbound"}, label=(aid, "netflow_periodic_small"), dst_ip=dst, **common)


# ---------------------------------------------------------------------- corp: identity
def impossible_travel(ts, sim, w, aid, o):
    """The same person is seen at their usual location, then shortly after from far away."""
    r = sim.rng
    u = _user(sim, o, w.engineers)
    usual = w.session_for(u, ts)
    subtle = o["k"] < 0.5
    cc, city = r.choice(NEAR if subtle else FAR)
    gap = r.uniform(5400, 9000) if subtle else r.uniform(900, 2700)
    far = Session(u, usual.device, "travel", "remote", "172.20.0.10", w.ext_ip(r), {"country": cc, "city": city},
                  "s-" + sim.hex(12))
    _case(sim, aid, "impossible_travel", ts, ts + gap + 3600,
          f"{u.principal} seen in {usual.geo['city']} then in {city} {gap / 60:.0f} min later", o, ["T1078"],
          principal=u.principal, device_id=usual.device.device_id, src_ip=far.public_ip)
    corp.access(sim, w, usual, ts, label=(aid, "access_usual_location"))
    t = ts + gap
    sim.emit(t, "bc.loas", "cert_issue", {"cert_serial": sim.hex(16), "validity_hours": 20, "issuer": "loas-ca-1",
                                          "security_key": {"type": "FIDO2", "user_presence": True},
                                          "groups": [f"mdb:{u.team}"]},
             outcome="success", label=(aid, "loas_from_far_location"), src_ip=far.public_ip, **corp.ctx(far))
    for k in range(_n(sim, o, 3, 8)):
        corp.access(sim, w, far, t + 30 + k * r.uniform(20, 300), label=(aid, "access_far_location"))


# ---------------------------------------------------------------------- corp: admin workflows
def review_bypass(ts, sim, w, aid, o):
    """A change reaches the build without an independent approval (or with a rubber stamp)."""
    r = sim.rng
    u = _user(sim, o, [x for x in w.engineers if x.role == "swe"])
    s = w.session_for(u, ts)
    svc = r.choice(w.services_for(u) or [x for x in w.services.values() if not x.infra])
    cl = w.next_cl()
    subtle = o["k"] < 0.5
    _case(sim, aid, "review_bypass", ts, ts + 3600,
          f"cl/{cl} for {svc.name} " + ("approved in under a minute by someone outside the team" if subtle
                                        else "submitted without any approval"), o, ["T1195.002"],
          principal=u.principal, job=svc.name, cl=cl)
    base = {"cl": cl, "service": svc.name}
    sim.emit(ts, "admin.code_review", "create_change",
             {**base, "title": "Refactor RPC client", "files": r.randrange(1, 6), "lines_added": r.randrange(10, 200),
              "reviewers": []}, outcome="success", label=(aid, "change_without_reviewers"), **corp.ctx(s))
    reviewer = None
    if subtle:
        reviewer = r.choice([x for x in w.engineers if x.team != u.team])
        sim.emit(ts + r.uniform(20, 60), "admin.code_review", "approve", {**base, "author": u.principal, "vote": "LGTM"},
                 outcome="success", label=(aid, "rubber_stamp_approval"), **corp.ctx(w.session_for(reviewer, ts)))
    t = ts + r.uniform(120, 600)
    sim.emit(t, "admin.code_review", "submit",
             {**base, "approvals": [reviewer.principal] if reviewer else [],
              "override": None if subtle else "submit_without_approval"},
             outcome="success", label=(aid, "submit"), **corp.ctx(s))
    b = w.new_build(svc.name, t + 300, author=u, reviewer=reviewer, cl=cl, verified=subtle, register=subtle)
    admin.build_event(sim, b, t + 300, label=(aid, "build_from_change"))


def breakglass_no_incident(ts, sim, w, aid, o):
    """An SRE who is not on call takes breakglass with no incident, then browses user data in a task."""
    r = sim.rng
    u = _user(sim, o, [x for x in w.sres if not w.is_oncall(x, ts)] or w.sres)
    s = w.session_for(u, ts)
    svc = r.choice([x for x in w.services.values()
                    if any(w.datasets[d].classification == "user_data" and w.datasets[d].store == "colossus"
                           for d in x.data)])
    ds = next(w.datasets[d] for d in svc.data
              if w.datasets[d].classification == "user_data" and w.datasets[d].store == "colossus")
    task = w.random_task(r, svc.name)
    subtle = o["k"] < 0.5
    why = f"investigating ticket b/{r.randrange(10 ** 8, 10 ** 9)}" if subtle else "debugging"
    _case(sim, aid, "breakglass_no_incident", ts, ts + 3600,
          f"{u.principal} (not on call) takes breakglass on {svc.name} with no incident", o, ["T1078.004"],
          principal=u.principal, job=svc.name, task=task.id)
    g = admin.breakglass(sim, w, s, ts, scope=f"{task.cell}/{svc.name}", justification=why,
                         label=(aid, "breakglass_without_incident"))
    path = ds.location(task.cell)
    cmds = ["df -h", f"fileutil ls {path}"] + ([] if subtle else [f"fileutil cat {path}/shard-0001/chunk-0 | head -c 1000000"])
    admin.prod_session(sim, w, s, ts + r.uniform(60, 300), task, why, commands=cmds, breakglass_id=g,
                       label=(aid, "prod_session_on_user_data"))


# ---------------------------------------------------------------------- prod: control plane
def priority_quota_abuse(ts, sim, w, aid, o):
    """A person raises their own quota without approval and runs an ad-hoc job at production
    priority, evicting other teams' batch work."""
    r = sim.rng
    u = _user(sim, o, [x for x in w.engineers if x.role == "swe"])
    s = w.session_for(u, ts)
    cell = r.choice(list(CELLS))
    job = f"{u.name.replace('.', '-')}-adhoc-{sim.hex(4)}"
    subtle = o["k"] < 0.5
    _case(sim, aid, "priority_quota_abuse", ts, ts + 1800,
          f"{u.principal} raises quota without MPA and runs {job} at {'batch' if subtle else 'production'} priority",
          o, ["T1496"], principal=u.principal, job=job, cell=cell)
    borg.audit(sim, w, ts, "SetQuota", principal=u.principal, cell=cell, device_id=s.device.device_id, read_only=False,
               request={"user": u.principal, "cpu_cores": 80 if subtle else 400,
                        "priority_band": "batch" if subtle else "production"},
               label=(aid, "quota_change_without_mpa"))
    borg.audit(sim, w, ts + r.uniform(30, 120), "SubmitJob", principal=u.principal, cell=cell, job=job,
               device_id=s.device.device_id, read_only=False,
               request={"job": job, "priority": "batch" if subtle else "production", "replicas": 20 if subtle else 200},
               label=(aid, "adhoc_job_submit"))
    if subtle:
        return
    batch = [x for x in w.services.values() if x.kind == "batch" and cell in x.cells]
    for k in range(_n(sim, o, 3, 9)):
        v = r.choice(batch)
        task = r.choice(w.tasks[(v.name, cell)])
        sim.emit(ts + 150 + k * r.uniform(1, 10), "borg.scheduler", "task_evicted",
                 {"reason": f"preempted_by:{job}", "machine": task.machine.hostname, "priority": v.kind},
                 label=(aid, "evictions_by_adhoc_job"), site=CELLS[cell]["site"], cell=cell, job=v.name,
                 task=task.id, host=task.machine.hostname)


# ---------------------------------------------------------------------- prod: data plane
def _store_pick(sim, w, o, store):
    r = sim.rng
    dbs = [d for d in w.datasets.values() if d.store == store and d.classification == "user_data"]
    if o.get("service"):
        svc = o["service"]
        own = [w.datasets[d] for d in svc.data if w.datasets[d] in dbs]
        return svc, r.choice(own or dbs)
    pairs = [(s, w.datasets[d]) for s in w.services.values() for d in s.data
             if w.datasets[d] in dbs and s.name != "backup-pipeline"]
    return r.choice(pairs)


def spanner_bulk_export(ts, sim, w, aid, o):
    """A service streams whole tables of user data, far beyond its usual point reads."""
    r = sim.rng
    svc, ds = _store_pick(sim, w, o, "spanner")
    cell = r.choice(svc.cells)
    subtle = o["k"] < 0.5
    _case(sim, aid, "spanner_bulk_export", ts, ts + 3600, f"{svc.principal} reads whole tables of {ds.name}", o,
          ["T1530"], principal=svc.principal, job=svc.name, dataset=ds.name, cell=cell)
    for k in range(_n(sim, o, 4, 12)):
        table = r.choice(ds.tables)
        rows = int(r.uniform(2e4, 8e4) if subtle else r.uniform(5e5, 3e6))
        sim.emit(ts + k * r.uniform(30, 240), "spanner.audit", "ExecuteSql" if subtle else "StreamingRead",
                 {"database": ds.location(cell), "table": table, "classification": ds.classification,
                  "sql_fingerprint": f"SELECT * FROM {table} WHERE UserId IN UNNEST(@p0)" if subtle else None,
                  "rows_returned": rows, "mutations": 0, "bytes": rows * r.randrange(300, 1500),
                  "latency_ms": round(r.uniform(2000, 30000), 1)},
                 outcome="ok", label=(aid, "spanner_bulk_read"), site=CELLS[cell]["site"], cell=cell,
                 principal=svc.principal, job=svc.name)


def bigtable_full_scan(ts, sim, w, aid, o):
    """A service scans a whole user-data table instead of reading row ranges."""
    r = sim.rng
    svc, ds = _store_pick(sim, w, o, "bigtable")
    cell = r.choice(svc.cells)
    subtle = o["k"] < 0.5
    _case(sim, aid, "bigtable_full_scan", ts, ts + 3600, f"{svc.principal} scans {ds.name} end to end", o, ["T1530"],
          principal=svc.principal, job=svc.name, dataset=ds.name, cell=cell)
    for k in range(_n(sim, o, 3, 10)):
        n = int(r.uniform(5e3, 2e4) if subtle else r.uniform(1e6, 5e6))
        sim.emit(ts + k * r.uniform(60, 300), "bigtable.audit", "ReadRows",
                 {"table": f"{ds.location(cell)}/{r.choice(ds.tables)}", "classification": ds.classification,
                  "rows": n, "bytes": n * r.randrange(300, 5000), "row_range": f"{sim.hex(4)}.." if subtle else "",
                  "app_profile": svc.name, "latency_ms": round(r.uniform(500, 20000), 1)},
                 outcome="ok", label=(aid, "bigtable_scan"), site=CELLS[cell]["site"], cell=cell,
                 principal=svc.principal, job=svc.name)


def b4_replication_spike(ts, sim, w, aid, o):
    """Cross-site replication jumps well above its usual level."""
    r = sim.rng
    dur = r.uniform(3600, 3 * 3600)
    factor = 1 + (r.uniform(3, 8) - 1) * o["k"]
    _case(sim, aid, "b4_replication_spike", ts, ts + dur, f"cross-site replication at ~{factor:.1f}x its usual level",
          o, ["T1537"], flow_class="colossus_geo_replication")
    sim.overlay("b4", ("colossus_geo_replication",), ts, ts + dur, 7.5e11 * sim.scale * (factor - 1),
                label=(aid, "b4_volume"))


# ---------------------------------------------------------------------- prod: host & AI runtime
def titan_measurement_mismatch(ts, sim, w, aid, o):
    """A machine boots with measurements that do not match, and goes on receiving tasks."""
    r = sim.rng
    cell = r.choice(list(CELLS))
    m = r.choice(w.machines_by_cell[cell]["compute"])
    subtle = o["k"] < 0.5
    _case(sim, aid, "titan_measurement_mismatch", ts, ts + 1800,
          f"{m.hostname} boot measurements do not match ({'borglet' if subtle else 'kernel, bootloader'})", o,
          ["T1542"], host=m.hostname, cell=cell)
    sim.emit(ts, "host.titan", "attestation",
             {"titan_chip_id": m.titan_id, "reason": "reboot", "secure_boot": True, "boot_stage": "os_handoff",
              "firmware_version": m.firmware, "expected_firmware": "fw-7.4.2",
              "measurements": {"bootloader": sim.hex(16), "kernel": sim.hex(16), "borglet": sim.hex(16)},
              "measurement_mismatch": ["borglet"] if subtle else ["kernel", "bootloader"],
              "verdict": "WARN" if subtle else "MEASUREMENT_MISMATCH"},
             outcome="warn" if subtle else "fail", label=(aid, "attestation_mismatch"), site=CELLS[cell]["site"],
             cell=cell, host=m.hostname)
    pool = [t for (name, c), tasks in w.tasks.items() if c == cell and not w.services[name].tpu for t in tasks]
    for task in r.sample(pool, 2):
        task.machine = m
        borg.start_task(sim, w, task, ts + r.uniform(60, 600), "machine_back_in_service",
                        label=(aid, "task_on_mismatched_machine"))


def tpu_unusual_checkpoint_load(ts, sim, w, aid, o):
    """A job from outside the model team loads the production model checkpoint."""
    r = sim.rng
    u = _user(sim, o, [x for x in w.engineers if x.team != "gemini" and x.role == "swe"])
    ds = w.datasets["gemini-weights"]
    cell = "zrh-c1"
    m = r.choice(w.machines_by_cell[cell]["tpu"])
    job = f"{u.name.replace('.', '-')}-tpu-eval"
    subtle = o["k"] < 0.5
    _case(sim, aid, "tpu_unusual_checkpoint_load", ts, ts + 3600,
          f"{job} ({u.principal}, team {u.team}) loads the production checkpoint", o, ["T1530"],
          principal=u.principal, job=job, dataset=ds.name, cell=cell)
    sim.emit(ts, "tpu.runtime", "load_checkpoint",
             {"checkpoint": f"{ds.location(cell)}/ckpt-{ds.ckpt_step}", "shards": 16 if subtle else 256,
              "bytes": int((2.6e10 if subtle else 4.1e11) * r.uniform(0.9, 1.1)), "slice": "pod-slice-2x2",
              "load_s": round(r.uniform(40, 160), 1)},
             outcome="success", label=(aid, "checkpoint_load_unexpected_job"), principal=u.principal, site="zrh",
             cell=cell, job=job, task=f"{job}.0", host=m.hostname)
    for _ in range(_n(sim, o, 4, 12)):
        storage.curator(sim, w, ts + r.uniform(0, 120), principal=u.principal, cell=cell, op="Open",
                        path=ds.random_file(r, cell), dataset=ds.name, job=job, label=(aid, "weights_open"))


LAYER_INJECTORS = {f.__name__: f for f in (
    endpoint_beaconing, impossible_travel, review_bypass, breakglass_no_incident, priority_quota_abuse,
    spanner_bulk_export, bigtable_full_scan, b4_replication_spike, titan_measurement_mismatch,
    tpu_unusual_checkpoint_load)}
USER_KINDS_MORE = ["impossible_travel", "review_bypass", "priority_quota_abuse"]
SERVICE_KINDS_MORE = ["spanner_bulk_export", "bigtable_full_scan"]
