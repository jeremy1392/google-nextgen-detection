"""Developer & SRE admin workflows: code review -> build (BCID) -> MPA-approved release,
routine prod sessions, breakglass and incident response.

These are the flows that tie a human identity to what runs in prod, so each step reuses
the identifiers of the previous one (CL -> BCID -> mpa_id -> UpdateJob -> task start)."""
from __future__ import annotations

import math

from . import borg, corp, runtime

CHANGE_TITLES = ["Fix flaky test", "Bump dependency", "Add metric for cache hit rate", "Refactor RPC client",
                 "Tune retry budget", "Remove dead flag", "Improve error message", "Add pagination to List call"]
ROUTINE_CMDS = ["top -b -n1", "df -h", "cat /proc/meminfo", "curl -s localhost:{port}/statusz",
                "tail -n 50 /var/log/task.log", "ps aux --sort=-%cpu | head", "ss -tnp | head", "uptime"]


def install(sim, w) -> None:
    sim.every(60, lambda t, p: _tick(sim, w, t, p), phase=1.5)
    sim.every(3600, lambda t, p: _maybe_incident(sim, w, t, p), phase=1200)


def _tick(sim, w, t, period) -> None:
    r = sim.rng
    act = w.active(t)
    eng = [s for s in act if s.user.role in ("swe", "sre", "research", "security")]
    for _ in range(sim.poisson(0.0045 * len(eng))):
        _change(sim, w, r.choice(eng), t + r.random() * period)
    sres = [s for s in act if s.user.role == "sre"]
    for _ in range(sim.poisson(0.002 * len(sres))):
        s = r.choice(sres)
        svc = r.choice(w.services_for(s.user))
        task = w.random_task(r, svc.name)
        ts = t + r.random() * period
        cid = benign_case(sim, "routine_prod_session", ts, f"{s.user.principal} routine session into {task.id}",
                          principal=s.user.principal, task=task.id)
        prod_session(sim, w, s, ts, task, f"routine check, ticket b/{r.randrange(10**8, 10**9)}",
                     label=(cid, "routine_prod_session"))


def benign_case(sim, kind, ts, description, **entities) -> str:
    """Record legitimate activity that looks suspicious, so false positives can be attributed."""
    cid = f"B-{kind}-{sim.hex(6)}"
    sim.open_case(cid, {"case_id": cid, "kind": "benign", "benign_type": kind, "description": description,
                        "mitre": [], "start": ts, "end": ts + 3600, "entities": entities})
    return cid


# ---------------------------------------------------------------------- code -> build -> release
def _change(sim, w, s, ts) -> None:
    r = sim.rng
    u = s.user
    svc = r.choice(w.services_for(u) or [x for x in w.services.values() if not x.infra])
    reviewer = w.pick_member(u.team, exclude=u)
    cl = w.next_cl()
    base = {"cl": cl, "service": svc.name}
    sim.emit(ts, "admin.code_review", "create_change",
             {**base, "title": r.choice(CHANGE_TITLES), "files": r.randrange(1, 25), "lines_added": r.randrange(2, 600),
              "reviewers": [reviewer.principal]}, outcome="success", **corp.ctx(s))
    t2 = ts + r.uniform(600, 3 * 3600)
    rs = w.session_for(reviewer, t2)
    sim.emit(t2, "admin.code_review", "approve", {**base, "author": u.principal, "vote": "LGTM"},
             outcome="success", **corp.ctx(rs))
    t3 = t2 + r.uniform(60, 1800)
    sim.emit(t3, "admin.code_review", "submit", {**base, "approvals": [reviewer.principal]}, outcome="success",
             **corp.ctx(s))
    t4 = t3 + r.uniform(120, 900)
    b = w.new_build(svc.name, t4, author=u, reviewer=reviewer, cl=cl)
    build_event(sim, b, t4)
    if r.random() < 0.35:
        requester = u if u.role in ("swe", "sre", "research") else w.oncall(w.sre_team_for(svc), t4)
        sim.at(t4 + r.uniform(1800, 4 * 3600), _release, sim, w, svc.name, b.bcid, requester)


def build_event(sim, b, ts, label=None):
    return sim.emit(ts, "admin.build", "build_complete",
                    {"bcid": b.bcid, "sha256": b.sha256, "version": b.version, "service": b.service,
                     "provenance": b.provenance(), "duration_s": int(sim.rng.uniform(90, 1500))},
                    outcome="success", label=label, principal=b.author)


def mpa(sim, w, s, ts, *, operation, target, change, justification, approver, delay, label=None):
    """Request + approval. Returns (mpa_id, approval time)."""
    mpa_id = "mpa-" + sim.hex(10)
    sim.emit(ts, "admin.mpa", "request",
             {"mpa_id": mpa_id, "operation": operation, "target": target, "change": change,
              "justification": justification, "required_approvals": 1, "policy": "prod-change"},
             outcome="pending", label=label, **corp.ctx(s))
    t2 = ts + delay
    a = w.session_for(approver, t2)
    sim.emit(t2, "admin.mpa", "approve",
             {"mpa_id": mpa_id, "operation": operation, "target": target, "requester": s.user.principal,
              "approval_latency_s": round(delay, 1), "comment": "LGTM"},
             outcome="approved", label=label, **corp.ctx(a))
    return mpa_id, t2


def _release(ts, sim, w, svc_name, bcid, requester) -> None:
    svc = w.services[svc_name]
    if all(svc.bcid[c] == bcid for c in svc.cells):
        return
    r = sim.rng
    s = w.session_for(requester, ts)
    corp.access(sim, w, s, ts, app="borgcfg", path="/job/update")
    approver = w.pick_member(requester.team, exclude=requester)
    b = w.builds[bcid]
    mpa_id, t_ok = mpa(sim, w, s, ts + 2, operation="UpdateJob", target=f"{svc.cells[0]}/{svc.name}",
                       change={"bcid_from": svc.bcid[svc.cells[0]], "bcid_to": bcid},
                       justification=f"Release {b.version} (cl/{b.cl})", approver=approver,
                       delay=r.lognormvariate(math.log(420), 0.8))
    t = t_ok + r.uniform(5, 40)
    for cell in svc.cells:  # canary cell first, the other one a bit later
        sim.at(t, rollout, sim, w, svc_name, cell, bcid, requester.principal, mpa_id, s.device.device_id)
        t += r.uniform(3600, 3 * 3600)


def rollout(ts, sim, w, svc_name, cell, bcid, principal, mpa_id, device_id=None, reason="release",
            label=None) -> None:
    svc = w.services[svc_name]
    r = sim.rng
    borg.audit(sim, w, ts, "UpdateJob", principal=principal, cell=cell, job=svc_name, mpa_id=mpa_id,
               device_id=device_id, read_only=False, label=label,
               request={"job": svc_name, "reason": reason, "bcid_from": svc.bcid[cell], "bcid_to": bcid,
                        "strategy": "rolling",
                        "max_unavailable": "10%"})
    svc.prev_bcid[cell], svc.bcid[cell] = svc.bcid[cell], bcid
    t = ts + 5
    for task in w.tasks[(svc_name, cell)]:
        borg.start_task(sim, w, task, t, "rolling_update")
        t += r.uniform(8, 30)


# ---------------------------------------------------------------------- prod access
def prod_session(sim, w, s, ts, task, justification, *, commands=None, breakglass_id=None, label=None) -> float:
    """Interactive session into a Borg task. Returns the closing time."""
    r = sim.rng
    sid = "ps-" + sim.hex(10)
    c = corp.ctx(s)
    sim.emit(ts, "admin.prod_ssh", "session_open",
             {"session": sid, "target_task": task.id, "machine": task.machine.hostname, "justification": justification,
              "breakglass_id": breakglass_id, "via": "access-proxy"},
             outcome="success", label=label, cell=task.cell, job=task.job, task=task.id, **c)
    borg.borglet_priv(sim, w, ts + 0.5, "exec_shell", principal=s.user.principal, cell=task.cell,
                      host=task.machine.hostname, task=task.id, job=task.job, device_id=s.device.device_id,
                      extra={"session": sid, "breakglass_id": breakglass_id}, label=label)
    # What the in-container sensor sees: the Borglet joining the task's namespaces, then an interactive
    # shell started by the Borglet, not by the service.
    runtime.ebpf(sim, w, task, ts + 0.7, "setns", {"exe": runtime.BORGLET, "comm": "borglet",
                                                  "parent_exe": "/sbin/init", "target": "task_namespaces",
                                                  "nstype": "CLONE_NEWNS|CLONE_NEWPID", "session": sid}, label=label)
    runtime.ebpf(sim, w, task, ts + 0.8, "execve",
                 {"exe": "/bin/bash", "comm": "bash", "argv": ["bash", "-l"], "parent_exe": runtime.BORGLET,
                  "tty": True, "stdin": "pty", "session": sid, "operator": s.user.principal}, label=label)
    t = ts + r.uniform(3, 20)
    for cmd in commands or r.sample(ROUTINE_CMDS, r.randrange(2, 6)):
        argv = cmd.format(port=task.port)
        sim.emit(t, "admin.prod_ssh", "command", {"session": sid, "argv": argv, "cwd": "/"},
                 outcome="success", label=label, cell=task.cell, job=task.job, task=task.id, **c)
        prog = argv.split()[0]
        runtime.ebpf(sim, w, task, t + 0.05, "execve",
                     {"exe": f"/usr/bin/{prog}", "comm": prog[:15], "argv": argv.split("|")[0].split(),
                      "parent_exe": "/bin/bash", "tty": True, "session": sid}, label=label)
        t += r.uniform(4, 90)
    sim.emit(t, "admin.prod_ssh", "session_close", {"session": sid, "duration_s": round(t - ts, 1)},
             outcome="success", label=label, cell=task.cell, job=task.job, task=task.id, **c)
    return t


def breakglass(sim, w, s, ts, *, scope, justification, incident_id=None, label=None) -> str:
    grant = "bg-" + sim.hex(10)
    sim.emit(ts, "admin.breakglass", "grant",
             {"grant_id": grant, "scope": scope, "justification": justification, "incident_id": incident_id,
              "duration_min": 60, "auto_approved": True, "notified": ["security-oncall", "team-leads"]},
             outcome="granted", label=label, **corp.ctx(s))
    return grant


# ---------------------------------------------------------------------- incidents
def _maybe_incident(sim, w, t, period) -> None:
    if sim.rng.random() < 0.2:
        sim.at(t + sim.rng.random() * period, _incident, sim, w)


def _incident(ts, sim, w) -> None:
    """A real outage: metrics degrade, on-call is paged, investigates, sometimes rolls back."""
    r = sim.rng
    svc = r.choice([s for s in w.services.values() if not s.infra])
    cell = r.choice(svc.cells)
    team = w.sre_team_for(svc)
    oc = w.oncall(team, ts)
    s = w.session_for(oc, ts)
    inc = "inc-" + sim.hex(6)
    dur = r.uniform(20, 90) * 60
    cid = benign_case(sim, "incident_response", ts, f"{inc} on {svc.name}/{cell}, handled by on-call {oc.principal}",
                      principal=oc.principal, job=svc.name, cell=cell, incident_id=inc)
    lb = (cid, "incident_response")
    sim.overlay("metric", (svc.name, cell, "error_ratio"), ts, ts + dur, r.uniform(6, 20), label=lb)
    sim.overlay("metric", (svc.name, cell, "latency_p99_ms"), ts, ts + dur, r.uniform(1.8, 3.5), label=lb)
    base = {"incident_id": inc, "service": svc.name, "cell": cell, "oncall": oc.principal, "team": team}
    severity = r.choice(["P1", "P2", "P2", "P3"])
    sim.emit(ts + 120, "admin.incident", "page", {**base, "severity": severity, "alert": "HighErrorRatio"},
             outcome="paged", principal=oc.principal, label=lb)
    t = ts + 120 + r.uniform(60, 400)
    sim.emit(t, "admin.incident", "acknowledge", base, outcome="acknowledged", label=lb, **corp.ctx(s))
    corp.access(sim, w, s, t + 20, app="monarch-ui", path="/dashboards", label=lb)
    if r.random() < (0.9 if severity != "P3" else 0.3):
        g = breakglass(sim, w, s, t + r.uniform(120, 400), scope=f"{cell}/{svc.name}",
                       justification=f"{inc}: elevated error ratio on {svc.name}", incident_id=inc, label=lb)
        task = w.random_task(r, svc.name, cell)
        prod_session(sim, w, s, t + r.uniform(450, 600), task, f"{inc} investigation", breakglass_id=g, label=lb)
    if r.random() < 0.3 and svc.prev_bcid.get(cell) and svc.prev_bcid[cell] != svc.bcid[cell]:
        second = w.pick_member(team, exclude=oc)
        mpa_id, t_ok = mpa(sim, w, s, t + r.uniform(600, 900), operation="UpdateJob", target=f"{cell}/{svc.name}",
                           change={"bcid_from": svc.bcid[cell], "bcid_to": svc.prev_bcid[cell], "rollback": True},
                           justification=f"{inc}: rollback", approver=second, delay=r.uniform(30, 180),
                           label=lb)
        sim.at(t_ok + 10, rollout, sim, w, svc.name, cell, svc.prev_bcid[cell], oc.principal, mpa_id,
               s.device.device_id, "rollback", lb)
    sim.emit(ts + dur, "admin.incident", "resolve", {**base, "duration_min": round(dur / 60, 1)},
             outcome="resolved", label=lb, **corp.ctx(s))
