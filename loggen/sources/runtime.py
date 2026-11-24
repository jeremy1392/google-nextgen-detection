"""Prod host, network & AI runtime: Titan attestation, eBPF syscalls, ALTS service-to-service
authorization, Jupiter / egress flows and TPU runtime telemetry."""
from __future__ import annotations

from ..world import CELLS, SIEM_COLLECTOR_IP
from . import storage

CRAWL_HOSTS = ["www.example.org", "news.example.com", "blog.example.net", "shop.example.org", "docs.example.com"]


def install(sim, w) -> None:
    sim.every(60, lambda t, p: _titan(sim, w, t, p), phase=6)
    sim.every(60, lambda t, p: _ebpf(sim, w, t, p), phase=7)
    sim.every(60, lambda t, p: _alts(sim, w, t, p), phase=8)
    sim.every(60, lambda t, p: _jupiter(sim, w, t, p), phase=9)
    sim.every(60, lambda t, p: _tpu(sim, w, t, p), phase=10)
    sim.every(3600, lambda t, p: _checkpoint(sim, w, t, p), phase=1500)


def _ctx(task) -> dict:
    return {"site": CELLS[task.cell]["site"], "cell": task.cell, "job": task.job, "task": task.id,
            "host": task.machine.hostname}


# ---------------------------------------------------------------------- Titan
def attest(sim, w, m, ts, reason="periodic", label=None):
    stale = m.firmware != "fw-7.4.2"
    payload = {"titan_chip_id": m.titan_id, "reason": reason, "secure_boot": True, "boot_stage": "os_handoff",
               "firmware_version": m.firmware, "expected_firmware": "fw-7.4.2",
               "measurements": {"bootloader": sim.hex(16), "kernel": sim.hex(16), "borglet": sim.hex(16)},
               "verdict": "STALE_FIRMWARE" if stale else "PASS"}
    return sim.emit(ts, "host.titan", "attestation", payload, outcome="warn" if stale else "pass", label=label,
                    site=CELLS[m.cell]["site"], cell=m.cell, host=m.hostname)


def _titan(sim, w, t, period) -> None:
    for _ in range(sim.poisson(len(w.machines) / 1440)):
        attest(sim, w, sim.rng.choice(w.machines), t + sim.rng.random() * period)


# ---------------------------------------------------------------------- eBPF
BORGLET = "/usr/bin/borglet"
ERRNO = {"EPERM": -1, "ENOENT": -2, "EACCES": -13, "ECONNREFUSED": -111, "ETIMEDOUT": -110}


# Canonical sensor schema (A2): every event of a given syscall has exactly these fields, whoever made the
# call. Only attributes a real in-container eBPF sensor can observe are kept (no session ids, no operator,
# no labels): the attack / benign difference must come from values, never from which fields exist.
SYSCALL_FIELDS = {
    "execve": {"argv": [], "tty": False, "stdin": "null", "sha256": None},
    "execveat": {"dirfd": None, "path": None, "flags": None},
    "openat": {"path": None, "flags": None},
    "connect": {"dst_ip": None, "dst_port": None},
    "ptrace": {"request": None, "target_exe": None},
    "process_vm_readv": {"target_exe": None, "bytes": None},
    "bpf": {"cmd": None, "prog_type": None},
    "unshare": {"flags": None},
    "setns": {"target": None, "nstype": None},
    "mount": {"source": None, "target": None, "fstype": None},
    "memfd_create": {"name": None, "flags": None, "fd": None},
    "finit_module": {"module_path": None},
}
SECCOMP_FILTERED = {"unshare", "setns", "mount", "bpf", "finit_module", "init_module"}


def ebpf(sim, w, task, ts, syscall, fields, *, ret=0, label=None):
    """One syscall seen inside a task's container. ret < 0 means the kernel / seccomp refused it."""
    s = w.services[task.job]
    payload = {"syscall": syscall, "container_id": task.container_id, "cgroup": f"/borg/{task.cell}/{task.id}",
               "pid": sim.rng.randrange(2, 60000), "uid": s.uid, "exe": fields.get("exe", s.binary),
               "comm": fields.get("comm", s.name[:15]), "parent_exe": fields.get("parent_exe", BORGLET)}
    for k, default in SYSCALL_FIELDS.get(syscall, {}).items():
        payload[k] = fields.get(k, default)
    payload["ret"] = ret
    payload["errno"] = next((k for k, v in ERRNO.items() if v == ret), str(ret)) if ret < 0 else None
    payload["seccomp_action"] = "SCMP_ACT_ERRNO" if ret == ERRNO["EPERM"] and syscall in SECCOMP_FILTERED else None
    return sim.emit(ts, "host.ebpf", syscall, payload, outcome="denied" if ret < 0 else "observed", label=label,
                    principal=s.principal, **_ctx(task))


def _ebpf(sim, w, t, period) -> None:
    r = sim.rng
    for _ in range(sim.poisson(18 * sim.scale * sim.prod_load(t))):
        caller, callee, _m = r.choice(w.edges)
        task = w.random_task(r, caller)
        ts = t + r.random() * period
        kind = r.choices(["connect", "openat", "execve", "ptrace"], [45, 25, 8, 1])[0]
        s = w.services[caller]
        if kind == "connect":
            peer = w.random_task(r, callee, task.cell)
            # A peer restarting refuses connections for a moment: benign failures.
            ret = ERRNO["ECONNREFUSED"] if r.random() < 0.01 else 0
            ebpf(sim, w, task, ts, "connect", {"dst_ip": peer.ip, "dst_port": peer.port}, ret=ret)
        elif kind == "openat":
            if r.random() < 0.04:  # optional config probed and absent: benign failures
                path, ret = r.choice([f"/borg/{s.name}/conf/overrides.cfg", "/etc/gai.conf",
                                      f"/borg/{s.name}/conf/experiments.cfg"]), ERRNO["ENOENT"]
            else:
                path, ret = r.choice(["/etc/resolv.conf", "/proc/self/status", f"/borg/{s.name}/conf/flags.cfg",
                                      "/var/run/loas/role_cert.pem", "/tmp/spill-" + sim.hex(6)]), 0
            ebpf(sim, w, task, ts, "openat", {"path": path, "flags": "O_RDONLY"}, ret=ret)
        elif kind == "execve":
            # Housekeeping started by the Borglet, or the service shelling out to a known tool.
            exe, argv, parent = r.choice([
                ("/bin/sh", ["sh", "-c", "logrotate /borg/logrotate.conf"], BORGLET),
                ("/usr/bin/fileutil", ["fileutil", "ls", f"/cns/{task.cell}/home/{s.team}"], s.binary),
                ("/usr/local/bin/health_check", ["health_check", f"--port={task.port}"], BORGLET)])
            ebpf(sim, w, task, ts, "execve", {"exe": exe, "comm": exe.rsplit("/", 1)[-1], "argv": argv,
                                              "parent_exe": parent})
        else:  # fleet-wide continuous profiler attaching briefly, then reading stacks: benign but unusual
            prof = {"exe": "/usr/bin/cprof", "comm": "cprof", "parent_exe": BORGLET, "target_exe": s.binary,
                    "tracer_principal": "svc:continuous-profiler"}
            ebpf(sim, w, task, ts, "ptrace", {**prof, "request": "PTRACE_SEIZE", "duration_ms": 200})
            ebpf(sim, w, task, ts + 0.05, "process_vm_readv", {**prof, "bytes": r.randrange(4096, 65536)})
    # A2 hardening: legitimate uses of syscalls that attacks also use, so that no field gives an attack away.
    for _ in range(sim.poisson(0.3 * sim.scale)):  # node metrics agent loading its BPF programs
        task = w.random_task(r, "monarch-collector")
        ebpf(sim, w, task, t + r.random() * period, "bpf",
             {"exe": "/usr/bin/node-metrics-agent", "comm": "node-metrics-ag", "parent_exe": BORGLET,
              "cmd": "BPF_PROG_LOAD", "prog_type": r.choice(["BPF_PROG_TYPE_KPROBE", "BPF_PROG_TYPE_TRACEPOINT"])})
    for _ in range(sim.poisson(0.4 * sim.scale)):  # image decoders entering a sandbox (user + mount ns)
        name = r.choice(["photos-thumbnailer", "search-indexer", "drive-metadata"])
        task = w.random_task(r, name)
        sb = {"exe": f"/borg/{name}/bin/sandbox_helper", "comm": "sandbox_helper",
              "parent_exe": w.services[name].binary, "seccomp_action": "SCMP_ACT_ERRNO"}
        ok = r.random() < 0.5
        ts = t + r.random() * period
        ebpf(sim, w, task, ts, "unshare", {**sb, "flags": "CLONE_NEWUSER|CLONE_NEWNS"},
             ret=0 if ok else ERRNO["EPERM"])
        if ok:  # inside its own namespaces the sandbox mounts a private tmpfs
            ebpf(sim, w, task, ts + 0.01, "mount", {**sb, "source": "tmpfs", "target": "/tmp/sbx",
                                                  "fstype": "tmpfs"})


# ---------------------------------------------------------------------- ALTS
def alts(sim, w, caller_task, callee_task, method, ts, *, decision="ALLOW", trace_id=None, label=None):
    caller, callee = w.services[caller_task.job], w.services[callee_task.job]
    payload = {"caller": caller.principal, "callee": callee.principal, "method": f"{callee.name}.{method}",
               "handshake": "resumed" if sim.rng.random() < 0.8 else "full", "protocol": "ALTSv2",
               "rpc_security_policy": f"rpcsp/{callee.name}", "authz": decision,
               "peer_task": callee_task.id, "record_protocol": "ALTSRP_GCM_AES128_REKEY"}
    return sim.emit(ts, "net.alts", "rpc_authz", payload, outcome=decision.lower(), label=label,
                    principal=caller.principal, src_ip=caller_task.ip, dst_ip=callee_task.ip,
                    trace_id=trace_id or sim.hex(16), **_ctx(caller_task))


def _alts(sim, w, t, period) -> None:
    r = sim.rng
    for _ in range(sim.poisson(18 * sim.scale * sim.prod_load(t))):
        caller, callee, method = r.choice(w.edges)
        ct = w.random_task(r, caller)
        alts(sim, w, ct, w.random_task(r, callee, ct.cell), method, t + r.random() * period,
             decision="DENY" if r.random() < 0.002 else "ALLOW")


# ---------------------------------------------------------------------- Jupiter
def flow(sim, w, task, ts, dst_ip, dst_port, nbytes, *, egress=False, dst_host=None, verdict="allow",
         label=None):
    payload = {"proto": "tcp", "src_port": sim.rng.randrange(32768, 61000), "dst_port": dst_port, "bytes": int(nbytes),
               "packets": max(1, int(nbytes / 1400)), "duration_ms": int(sim.rng.lognormvariate(6.0, 1.2)),
               "src_rack": task.machine.rack, "fabric": "jupiter", "egress": egress,
               "via": "egress-proxy" if egress and verdict == "allow" else None, "dst_host": dst_host,
               "policy_verdict": verdict}
    return sim.emit(ts, "net.jupiter", "flow", payload, outcome=verdict, label=label,
                    principal=w.services[task.job].principal, src_ip=task.ip, dst_ip=dst_ip, **_ctx(task))


def _jupiter(sim, w, t, period) -> None:
    r = sim.rng
    load = sim.prod_load(t)
    for _ in range(sim.poisson(16 * sim.scale * load)):
        caller, callee, _m = r.choice(w.edges)
        ct = w.random_task(r, caller)
        peer = w.random_task(r, callee, ct.cell)
        flow(sim, w, ct, t + r.random() * period, peer.ip, peer.port, r.lognormvariate(11, 1.5))
    # Normal egress: the crawler fetches the web, the exporter ships to the SIEM collector.
    for _ in range(sim.poisson(3 * load)):
        task = w.random_task(r, "search-indexer")
        host = r.choice(CRAWL_HOSTS)
        flow(sim, w, task, t + r.random() * period, w.domain_ip(host), 443, r.lognormvariate(12, 1.0),
             egress=True, dst_host=host)
    for _ in range(sim.poisson(1.0)):
        task = w.random_task(r, "logs-exporter")
        flow(sim, w, task, t + r.random() * period, SIEM_COLLECTOR_IP, 6514, r.lognormvariate(14, 0.6))


# ---------------------------------------------------------------------- TPU runtime
def tpu_load(sim, w, task, ts, label=None) -> None:
    s = w.services[task.job]
    ds = w.datasets["malware-corpus" if s.name == "malconv-scorer" else "gemini-weights"]
    ckpt = ds.location(task.cell) + (f"/ckpt-{ds.ckpt_step}" if ds.name == "gemini-weights" else "/model/latest")
    sim.emit(ts, "tpu.runtime", "load_checkpoint",
             {"checkpoint": ckpt, "shards": 256 if ds.name == "gemini-weights" else 1,
              "bytes": int(sim.rng.uniform(0.9, 1.1) * (4.1e11 if ds.name == "gemini-weights" else 2.6e8)),
              "slice": "pod-slice-4x4" if s.name != "gemini-trainer" else "pod-slice-8x8x4",
              "load_s": round(sim.rng.uniform(40, 160), 1)},
             outcome="success", label=label, principal=s.principal, **_ctx(task))
    for _ in range(sim.rng.randrange(2, 5)):
        storage.curator(sim, w, ts + sim.rng.uniform(0, 30), principal=s.principal, cell=task.cell, op="Open",
                        path=ds.random_file(sim.rng, task.cell), dataset=ds.name, job=s.name, label=label)


def _tpu(sim, w, t, period) -> None:
    r = sim.rng
    load = sim.prod_load(t)
    for cell in w.services["gemini-inference"].cells:
        task = w.random_task(r, "gemini-inference", cell)
        qps = w.services["gemini-inference"].qps * load * sim.noise(0.1) * (0.6 if cell == "zrh-c1" else 0.4)
        sim.emit(t + r.random() * period, "tpu.runtime", "inference_window",
                 {"window_s": 60, "qps": round(qps, 1), "tokens_in": int(qps * 60 * r.uniform(600, 900)),
                  "tokens_out": int(qps * 60 * r.uniform(200, 400)), "p50_ms": round(r.uniform(350, 500)),
                  "p99_ms": round(r.uniform(1500, 2600)), "slice": "pod-slice-4x4",
                  "checkpoint_step": w.datasets["gemini-weights"].ckpt_step},
                 outcome="ok", principal="svc:gemini-inference", **_ctx(task))
    if int(t) % 300 < 60:
        task = w.random_task(r, "gemini-trainer")
        sim.emit(t + r.random() * period, "tpu.runtime", "training_steps",
                 {"window_s": 300, "step": w.datasets["gemini-weights"].ckpt_step + int(t) % 3600 // 3,
                  "loss": round(r.uniform(1.6, 1.9), 4), "tokens_per_s": int(r.uniform(2.1e6, 2.4e6)),
                  "slice": "pod-slice-8x8x4"}, outcome="ok", principal="svc:gemini-trainer", **_ctx(task))
        task = w.random_task(r, "malconv-scorer")
        sim.emit(t + r.random() * period, "tpu.runtime", "scoring_window",
                 {"window_s": 300, "samples_scored": sim.poisson(900), "flagged_ratio": round(r.uniform(0.01, 0.04), 4),
                  "p99_ms": round(r.uniform(18, 45), 1), "model": "malconv-v3"},
                 outcome="ok", principal="svc:malconv-scorer", **_ctx(task))


def _checkpoint(sim, w, t, period) -> None:
    """Hourly checkpoint written by the trainer."""
    ds = w.datasets["gemini-weights"]
    ds.ckpt_step += 1000
    task = w.random_task(sim.rng, "gemini-trainer")
    ts = t + sim.rng.uniform(0, 600)
    sim.emit(ts, "tpu.runtime", "save_checkpoint",
             {"checkpoint": f"{ds.location(task.cell)}/ckpt-{ds.ckpt_step}", "shards": 256, "bytes": int(4.1e11)},
             outcome="success", principal="svc:gemini-trainer", **_ctx(task))
    for i in range(sim.rng.randrange(3, 6)):
        storage.curator(sim, w, ts + i, principal="svc:gemini-trainer", cell=task.cell, op="Create",
                        path=ds.random_file(sim.rng, task.cell), dataset=ds.name, job="gemini-trainer")
