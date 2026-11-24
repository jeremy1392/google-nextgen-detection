"""Prod control plane & consensus: BorgMaster RPC audit, scheduling, Binary Authorization
for Borg, Chubby, Paxos and privileged Borglet commands."""
from __future__ import annotations

import math

from ..world import CELLS
from . import runtime

MACHINE_READERS = [  # principal, methods, weight
    ("svc:monarch-collector", ["GetJobStatus", "GetTaskStatus"], 5),
    ("svc:rollout-controller", ["GetJobStatus", "ListTasks"], 3),
    ("svc:borg-repair", ["LookupMachine", "ListTasks"], 1),
]
HUMAN_READS = ["GetJobStatus", "ListJobs", "GetTaskStatus", "ListTasks"]
CHURN_REASONS = [("preempted", 3), ("restart_crash", 1.5), ("restart_oom", 1), ("machine_maintenance", 1.5)]


def install(sim, w) -> None:
    sim.every(60, lambda t, p: _reads(sim, w, t, p), phase=2)
    sim.every(60, lambda t, p: _churn(sim, w, t, p), phase=3)
    sim.every(60, lambda t, p: _chubby(sim, w, t, p), phase=4)
    sim.every(60, lambda t, p: _paxos(sim, w, t, p), phase=5)
    sim.every(300, lambda t, p: _automation(sim, w, t, p), phase=60)
    sim.every(60, lambda t, p: _batch_workload(sim, w, t, p), phase=3.5)


def leader(w, cell: str) -> str:
    return w.borgmasters[cell][w.paxos[cell]["leader"]]


def audit(sim, w, ts, method, *, principal, cell, job=None, request=None, mpa_id=None, device_id=None,
          read_only=True, outcome="success", label=None):
    payload = {"rpc": f"BorgMaster.{method}", "request": request or ({"job": job} if job else {}),
               "mpa_id": mpa_id, "read_only": read_only, "replica": leader(w, cell),
               "latency_ms": round(sim.rng.lognormvariate(2.0 if read_only else 3.5, 0.5), 1)}
    return sim.emit(ts, "borg.master_audit", method, payload, outcome=outcome, label=label,
                    site=CELLS[cell]["site"], cell=cell, principal=principal, device_id=device_id, job=job)


def start_task(sim, w, task, ts, reason, *, build=None, label=None, bab_override=None) -> None:
    """A task (re)starts: placement, provenance verdict, then the binary exec seen by eBPF."""
    s = w.services[task.job]
    b = build or w.builds[s.bcid[task.cell]]
    site = CELLS[task.cell]["site"]
    common = dict(site=site, cell=task.cell, job=task.job, task=task.id, host=task.machine.hostname)
    sim.emit(ts, "borg.scheduler", "task_start",
             {"reason": reason, "machine": task.machine.hostname, "rack": task.machine.rack,
              "priority": "batch" if s.kind == "batch" else "prod", "package_bcid": b.bcid,
              "cpu_cores": 4 if not s.tpu else 16, "ram_gib": 16 if not s.tpu else 96},
             outcome="success", label=label, **common)
    verdict = {"bcid": b.bcid, "sha256": b.sha256, "version": b.version, "provenance": b.provenance(),
               "policy": f"bab/{s.name}", "policy_mode": "enforce", "decision": "ALLOW", "violations": []}
    if bab_override:
        verdict.update(bab_override)
    sim.emit(ts + 0.2, "borg.bab", "admission", verdict, outcome=verdict["decision"].lower(), label=label,
             principal=s.principal, **common)
    # Container init re-executes itself from a memfd before starting the task (a benign fileless exec).
    init = {"exe": "/usr/bin/borg-init", "comm": "borg-init", "parent_exe": runtime.BORGLET}
    runtime.ebpf(sim, w, task, ts + 0.6, "memfd_create", {**init, "name": "borg-init:cloned", "flags": "MFD_CLOEXEC",
                                                         "fd": 3})
    runtime.ebpf(sim, w, task, ts + 0.7, "execveat", {**init, "exe": "memfd:borg-init:cloned (deleted)", "dirfd": 3,
                                                     "path": "", "flags": "AT_EMPTY_PATH"})
    runtime.ebpf(sim, w, task, ts + 1.0, "execve", {"argv": [s.binary, f"--port={task.port}"], "sha256": b.sha256},
                 label=label)
    if s.tpu:
        runtime.tpu_load(sim, w, task, ts + sim.rng.uniform(8, 40))


def _reads(sim, w, t, period) -> None:
    r = sim.rng
    humans = [s for s in w.active(t) if s.user.role in ("swe", "sre", "research")]
    for _ in range(sim.poisson(9 * sim.scale * sim.prod_load(t))):
        ts = t + r.random() * period
        if humans and r.random() < 0.25:
            s = r.choice(humans)
            svcs = w.services_for(s.user) or list(w.services.values())
            svc = r.choice(svcs)
            audit(sim, w, ts, r.choice(HUMAN_READS), principal=s.user.principal, cell=r.choice(svc.cells),
                  job=svc.name, device_id=s.device.device_id)
        else:
            principal, methods, _ = r.choices(MACHINE_READERS, [m[2] for m in MACHINE_READERS])[0]
            svc = r.choice(list(w.services.values()))
            audit(sim, w, ts, r.choice(methods), principal=principal, cell=r.choice(svc.cells), job=svc.name)


def _churn(sim, w, t, period) -> None:
    r = sim.rng
    for cell in CELLS:
        keys = [k for k in w.tasks if k[1] == cell]
        for _ in range(sim.poisson(0.4 * sim.scale)):  # A1: long-lived services rarely restart
            name, _ = r.choice(keys)
            s = w.services[name]
            reason = r.choices([x[0] for x in CHURN_REASONS], [x[1] for x in CHURN_REASONS])[0]
            if reason == "preempted" and s.kind != "batch":
                reason = "restart_crash"
            task = r.choice(w.tasks[(name, cell)])
            ts = t + r.random() * period
            if reason in ("preempted", "machine_maintenance"):
                pool = w.machines_by_cell[cell]["tpu" if s.tpu else "compute"]
                sim.emit(ts, "borg.scheduler", "task_evicted",
                         {"reason": reason, "machine": task.machine.hostname, "priority": s.kind},
                         site=CELLS[cell]["site"], cell=cell, job=name, task=task.id, host=task.machine.hostname)
                task.machine = r.choice(pool)
                ts += r.uniform(2, 30)
            start_task(sim, w, task, ts, reason)


# Calibrated on the Google 2011 Borg cell trace (experiment A1): most scheduling events are short
# free-tier and batch tasks that run to an end (finish, fail, kill, evict), not long-lived services.
BATCH_PRIORITY = (["free", "batch", "prod"], [0.62, 0.35, 0.03])
BATCH_END = (["task_finish", "task_fail", "task_kill", "task_evicted"], [0.40, 0.27, 0.22, 0.11])
BATCH_TEAMS = ["search", "gmail", "drive", "photos", "storage", "gemini", "workspace", "security"]


def _batch_workload(sim, w, t, period) -> None:
    r = sim.rng
    for cell in CELLS:
        pool = w.machines_by_cell[cell]["compute"]
        weights = getattr(w, "_batch_weights", {}).get(cell)
        if weights is None:  # machines differ: some are busy, some mostly idle (heavy-tailed, as in the trace)
            w._batch_weights = getattr(w, "_batch_weights", {})
            weights = w._batch_weights[cell] = [r.gammavariate(0.6, 1.0) for _ in pool]
        for _ in range(sim.poisson(6.8 * len(pool) / 60 * sim.prod_load(t))):
            m = r.choices(pool, weights)[0]
            team = r.choice(BATCH_TEAMS)
            job = f"{team}-batch-{sim.hex(5)}"
            prio = r.choices(*BATCH_PRIORITY)[0]
            ts = t + r.random() * period
            common = dict(site=CELLS[cell]["site"], cell=cell, job=job, task=f"{job}.0", host=m.hostname,
                          principal=f"svc:{team}-batch")
            sim.emit(ts, "borg.scheduler", "task_start",
                     {"reason": "batch_submit", "machine": m.hostname, "rack": m.rack, "priority": prio,
                      "package_bcid": None, "cpu_cores": r.choice([0.5, 1, 2, 4]), "ram_gib": r.choice([1, 2, 4, 8])},
                     outcome="success", **common)
            end = r.choices(*BATCH_END)[0]
            life = r.lognormvariate(math.log(900), 1.2)
            reason = {"task_finish": "completed", "task_fail": r.choice(["exit_code_1", "oom", "segfault"]),
                      "task_kill": "user_kill", "task_evicted": "preempted"}[end]
            sim.emit(ts + life, "borg.scheduler", end,
                     {"reason": reason, "machine": m.hostname, "priority": prio, "runtime_s": int(life)},
                     outcome="success" if end == "task_finish" else "terminated", **common)


def _chubby(sim, w, t, period) -> None:
    r = sim.rng
    for cell in CELLS:
        site = CELLS[cell]["site"]
        names = [s for s in w.services.values() if cell in s.cells]
        for _ in range(sim.poisson(4 * sim.scale)):
            s = r.choice(names)
            op = r.choices(["KeepAlive", "GetContents", "Acquire", "Release", "SetContents"], [10, 4, 1, 1, 0.5])[0]
            path = f"/ls/{cell}/{s.name}/{r.choice(['master-lock', 'config', 'members'])}"
            sim.emit(t + r.random() * period, "borg.chubby", op,
                     {"path": path, "session_id": sim.hex(12), "lease_s": 12, "generation": r.randrange(1, 900),
                      "cell_master": f"/ls/{cell}/chubby/master"},
                     outcome="success" if r.random() > 0.002 else "lease_expired",
                     site=site, cell=cell, principal=s.principal, job=s.name)


def _paxos(sim, w, t, period) -> None:
    r = sim.rng
    for cell in CELLS:
        st = w.paxos[cell]
        site = CELLS[cell]["site"]
        if r.random() < 1 / 2500:  # rare planned failover
            st["epoch"] += 1
            st["leader"] = (st["leader"] + 1 + r.randrange(4)) % 5
            sim.emit(t + 1, "borg.paxos", "leader_election",
                     {"epoch": st["epoch"], "new_leader": leader(w, cell), "reason": "planned_maintenance",
                      "replicas": w.borgmasters[cell]}, outcome="success", site=site, cell=cell, host=leader(w, cell))
            sim.emit(t + 1.2, "borg.chubby", "Acquire",
                     {"path": f"/ls/{cell}/borgmaster/leader", "session_id": sim.hex(12), "lease_s": 12,
                      "generation": st["epoch"]}, outcome="success", site=site, cell=cell,
                     principal="svc:borgmaster", job="borgmaster")
        ops = {"task_state": sim.poisson(140 * sim.scale), "job_update": sim.poisson(2),
               "quota": sim.poisson(0.2), "machine": sim.poisson(3)}
        n = sum(ops.values())
        frm = st["index"]
        st["index"] += n
        sim.emit(t + r.random() * period, "borg.paxos", "log_summary",
                 {"epoch": st["epoch"], "leader": leader(w, cell), "replicas": w.borgmasters[cell],
                  "log_index_from": frm, "log_index_to": st["index"], "ops": ops,
                  "quorum_acks": 5 if r.random() > 0.01 else 4, "snapshot": int(t) % 3600 < 60},
                 outcome="committed", site=site, cell=cell, host=leader(w, cell))


def _automation(sim, w, t, period) -> None:
    """Fleet automation: machine drains and kernel upgrades through privileged Borglet commands."""
    r = sim.rng
    for _ in range(sim.poisson(0.4 * sim.scale)):
        cell = r.choice(list(CELLS))
        m = r.choice(w.machines_by_cell[cell]["compute"])
        cmd = r.choice(["drain_machine", "kernel_upgrade", "restart_borglet"])
        ts = t + r.random() * period
        borglet_priv(sim, w, ts, cmd, principal="svc:borg-repair", cell=cell, host=m.hostname,
                     extra={"ticket": f"auto-{sim.hex(6)}"})
        if cmd == "kernel_upgrade":
            runtime.attest(sim, w, m, ts + r.uniform(240, 600), reason="reboot")


def borglet_priv(sim, w, ts, command, *, principal, cell, host, task=None, job=None, device_id=None,
                 extra=None, label=None):
    payload = {"command": command, "target_task": task, **(extra or {})}
    return sim.emit(ts, "borg.borglet_priv", command, payload, outcome="success", label=label,
                    site=CELLS[cell]["site"], cell=cell, host=host, principal=principal, job=job, task=task,
                    device_id=device_id)
