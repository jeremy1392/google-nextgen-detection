"""Labeled anomaly injection.

Each anomaly is a generic deviation from the baseline. Every event it touches is recorded in
ground_truth.jsonl, so a detector can be scored on precision, recall and time to detect.

Every injector takes an options dict `o`:
  k        intensity (1.0 = default strength, 0.2 = barely above noise); used for E6 curves
  user     force the person involved (bundles)
  service  force the service involved (bundles)
  bundle   bundle id: several weak anomalies on one entity, for signal-fusion experiments (E1)
"""
from __future__ import annotations

from .sources import admin, borg, corp, runtime, storage
from .world import CELLS, METHODS, Binary

UNSIGNED_TOOLS = ["sync-helper", "fmt-tool", "dev-setup", "runner", "netcheck"]


def _case(sim, aid, kind, ts, end, description, o, mitre=None, **entities):
    sim.open_case(aid, {"case_id": aid, "kind": "anomaly", "anomaly_type": kind, "description": description,
                        "mitre": mitre or [], "intensity": o["k"], "bundle": o.get("bundle"), "start": ts, "end": end,
                        "entities": {k: v for k, v in entities.items() if v is not None}})


def _n(sim, o, lo, hi) -> int:
    """An event count scaled by intensity."""
    return max(1, int(round(sim.rng.randrange(lo, hi) * o["k"])))


def _user(sim, o, pool):
    return o.get("user") or sim.rng.choice(pool)


def _service(sim, o, pool):
    return o.get("service") or sim.rng.choice(pool)


def _colossus(w):
    return [d for d in w.datasets.values() if d.store == "colossus"]


# ---------------------------------------------------------------------- behavioural deviations
def read_volume_spike(ts, sim, w, aid, o):
    """A principal reads a Colossus dataset at many times its usual volume, or a person reads a
    dataset that normally only services read."""
    r = sim.rng
    if o.get("user"):
        human, u = True, o["user"]
        ds = r.choice([d for d in _colossus(w) if d.team == u.team] or _colossus(w))
    elif o.get("service"):
        human, svc = False, o["service"]
        own = [w.datasets[d] for d in svc.data if w.datasets[d].store == "colossus"]
        ds = r.choice(own or _colossus(w))
    else:
        pairs = [(s, d) for s in w.services.values() for d in s.data if w.datasets[d].store == "colossus"]
        svc, dname = r.choice(pairs)
        ds = w.datasets[dname]
        human = r.random() < 0.5
        u = w.pick_member(ds.team) if human else None
    reader = next((s for s in w.services.values() if ds.name in s.data), None)
    base = (reader.io_mb_s if reader else 20.0) * 1e6 * 300 / max(1, len(reader.data) if reader else 1)
    dur = r.uniform(1800, 5400)
    if human:
        cell = r.choice(list(CELLS))
        principal, device, job = u.principal, w.session_for(u, ts).device.device_id, None
        extra = base * r.uniform(2, 6) * o["k"]
        what = f"{principal} (a person) reads {ds.name}, normally read by services only"
    else:
        cell = r.choice(svc.cells)
        principal, device, job = svc.principal, None, svc.name
        factor = 1 + (r.uniform(15, 40) - 1) * o["k"]
        extra = base * factor
        what = f"{principal} reads {ds.name} at ~{factor:.1f}x its usual volume"
    _case(sim, aid, "read_volume_spike", ts, ts + dur, what, o, ["T1530"], principal=principal, dataset=ds.name,
          cell=cell, device_id=device)
    sim.overlay("chunk_io", (principal, ds.name, cell), ts, ts + dur, extra, label=(aid, "chunk_io_volume"))
    subtle = o["k"] < 0.5  # metadata-only and a small factor: no single event crosses a rule threshold
    for _ in range(_n(sim, o, 25, 60)):
        storage.curator(sim, w, ts + r.random() * dur, principal=principal, cell=cell,
                        op=r.choice(["Stat", "List"]) if subtle else "Open",
                        path=ds.random_file(r, cell), dataset=ds.name, device_id=device, job=job,
                        label=(aid, "curator_open_burst"))


def new_rpc_edge(ts, sim, w, aid, o):
    """A service starts calling a method it has never called."""
    r = sim.rng
    caller = _service(sim, o, [s for s in w.callers if not s.infra])
    known = set(caller.calls)
    options = [(c, m) for c, ms in METHODS.items() for m in ms
               if (c, m) not in known and c != caller.name and set(w.services[c].cells) & set(caller.cells)]
    callee, method = r.choice(options)
    cell = r.choice(sorted(set(w.services[callee].cells) & set(caller.cells)))
    dur = r.uniform(1800, 7200)
    _case(sim, aid, "new_rpc_edge", ts, ts + dur, f"{caller.principal} calls {callee}.{method} for the first time", o,
          principal=caller.principal, callee=f"svc:{callee}", method=f"{callee}.{method}", cell=cell)
    sim.overlay("edge", (caller.name, callee, method, cell), ts, ts + dur, r.uniform(30, 400) * o["k"],
                label=(aid, "rpc_edge_new"))
    for _ in range(_n(sim, o, 4, 12)):
        ct = w.random_task(r, caller.name, cell)
        runtime.alts(sim, w, ct, w.random_task(r, callee, cell), method, ts + r.random() * dur,
                     label=(aid, "alts_new_peer"))


def off_hours_access(ts, sim, w, aid, o):
    """An engineer with no on-call duty works on prod tooling in the middle of the night."""
    r = sim.rng
    u = _user(sim, o, [x for x in w.engineers if x.role in ("swe", "research")])
    s = w.session_for(u, ts)
    dur = r.uniform(1200, 3600)
    _case(sim, aid, "off_hours_access", ts, ts + dur,
          f"{u.principal} uses prod tooling at {sim.local_hour(ts):.1f}h local, outside their usual hours", o,
          ["T1078"], principal=u.principal, device_id=s.device.device_id)
    for _ in range(_n(sim, o, 6, 15)):
        corp.access(sim, w, s, ts + r.random() * dur, app=r.choice(["borgcfg", "colossus-browser", "code-search"]),
                    label=(aid, "uberproxy_off_hours"))
    svc = r.choice(list(w.services.values()))
    for _ in range(_n(sim, o, 4, 10)):
        borg.audit(sim, w, ts + r.random() * dur, r.choice(["GetJobStatus", "ListJobs"]), principal=u.principal,
                   cell=r.choice(svc.cells), job=svc.name, device_id=s.device.device_id,
                   label=(aid, "borg_reads_off_hours"))


def first_seen_device(ts, sim, w, aid, o):
    """A person signs in from a device the inventory has never seen."""
    r = sim.rng
    u = _user(sim, o, w.users)
    subtle = o["k"] < 0.5  # a managed, healthy device that is merely new for this person
    d = w.make_device(u, r.choice(["macbook", "glinux-laptop"]), managed=subtle)
    if subtle:
        d.last_patch_day = sim.local_day(ts)
    s = w.session_for(u, ts, device=d)
    dur = r.uniform(600, 2400)
    _case(sim, aid, "first_seen_device", ts, ts + dur, f"{u.principal} connects from unknown device {d.device_id}", o,
          ["T1078"], principal=u.principal, device_id=d.device_id)
    corp.posture_report(sim, w, d, ts, u.principal, label=(aid, "posture_unmanaged"), enrollment=True)
    for _ in range(_n(sim, o, 5, 11)):
        corp.access(sim, w, s, ts + 5 + r.random() * dur, label=(aid, "uberproxy_unknown_device"))


def unverified_build(ts, sim, w, aid, o):
    """Tasks start with a build that has no verified provenance; BAB is in dry-run for that job."""
    r = sim.rng
    svc = _service(sim, o, [s for s in w.services.values() if not s.infra and not s.tpu])
    cell = r.choice(svc.cells)
    u = w.pick_member(svc.team)
    s = w.session_for(u, ts)
    b = w.new_build(svc.name, ts, author=u, verified=False, builder=f"workstation:{s.device.hostname}",
                    register=False)
    n = min(len(w.tasks[(svc.name, cell)]), max(1, int(round(r.randrange(1, 4) * o["k"]))))
    _case(sim, aid, "unverified_build", ts, ts + 900,
          f"{n} task(s) of {svc.name} in {cell} run {b.bcid}, built on a workstation from unreviewed source", o,
          ["T1525"], principal=u.principal, job=svc.name, cell=cell, bcid=b.bcid)
    admin.build_event(sim, b, ts, label=(aid, "build_unverified"))
    borg.audit(sim, w, ts + 300, "UpdateTask", principal=u.principal, cell=cell, job=svc.name,
               device_id=s.device.device_id, read_only=False, label=(aid, "update_with_unknown_bcid"),
               request={"job": svc.name, "tasks": n, "bcid_to": b.bcid})
    for task in w.tasks[(svc.name, cell)][:n]:
        borg.start_task(sim, w, task, ts + 320 + r.uniform(0, 60), "manual_update", build=b,
                        label=(aid, "bab_dryrun_violation"),
                        bab_override={"policy_mode": "dryrun", "decision": "ALLOW_DRYRUN",
                                      "violations": ["provenance_unverified", "source_not_reviewed"]})


def egress_shift(ts, sim, w, aid, o):
    """A service with no internet egress starts sending to one new external address."""
    r = sim.rng
    svc = _service(sim, o, [s for s in w.services.values() if not s.infra and not s.egress and not s.frontend])
    cell = r.choice(svc.cells)
    dst = w.ext_ip(r)
    dur = r.uniform(3600, 3 * 3600)
    factor = 1 + (r.uniform(8, 25) - 1) * o["k"]
    _case(sim, aid, "egress_shift", ts, ts + dur, f"{svc.principal} egress to {dst}, ~{factor:.1f}x usual egress bytes",
          o, ["T1048"], principal=svc.principal, job=svc.name, cell=cell, dst_ip=dst)
    sim.overlay("metric", (svc.name, cell, "egress_bytes"), ts, ts + dur, factor, label=(aid, "monarch_egress_bytes"))
    if o["k"] < 0.5:  # only the volume metric moves; no flow leaves through an unusual path
        return
    for _ in range(_n(sim, o, 10, 30)):
        runtime.flow(sim, w, w.random_task(r, svc.name, cell), ts + r.random() * dur, dst, 443,
                     r.lognormvariate(15, 0.8), egress=True, label=(aid, "jupiter_new_egress_dst"))


def rare_binary(ts, sim, w, aid, o):
    """An unsigned binary never seen in the fleet runs on one endpoint."""
    r = sim.rng
    if o.get("user"):
        u = o["user"]
        dev = next((w.devices_by_id[d] for d in u.devices if w.devices_by_id[d].sensor), None)
        if dev is None:
            return
        s = w.session_for(u, ts, device=dev)
    else:
        cands = [x for x in w.active(ts) if x.device.sensor] or \
                [x for x in (w.session_for(u, ts) for u in w.engineers[:20]) if x.device.sensor]
        if not cands:
            return
        s = r.choice(cands)
    tool = r.choice(UNSIGNED_TOOLS)
    home = f"/Users/{s.user.name}" if s.device.os == "macOS" else f"/home/{s.user.name}"
    pool = w.corpus_list("malicious", s.device.os)
    sha = r.choice(pool) if pool else sim.hex(64)
    if o["k"] < 0.5:  # signed and installed like a normal tool: only fleet-wide novelty is left
        b = Binary(f"/usr/local/bin/{tool}", s.device.os, ["", "--help"], 1, None, sha, sim.hex(64),
                   sim.hex(10).upper(), f"com.vendor.{tool}", "TEAMID")
    else:
        b = Binary(f"{home}/Downloads/{tool}", s.device.os, ["", "--help"], 1, None, sha, None, None, None, "UNKNOWN")
    _case(sim, aid, "rare_binary", ts, ts + 120, f"first-seen unsigned binary {b.path} on {s.device.hostname}", o,
          ["T1204.002"], principal=s.user.principal, device_id=s.device.device_id, sha256=b.sha256)
    for k in range(_n(sim, o, 1, 4)):
        corp.process_exec(sim, w, s, ts + k * r.uniform(5, 40), binary=b, label=(aid, "exec_unsigned_first_seen"))
    if o["k"] >= 0.5 and r.random() < o["k"]:  # weak versions slip past the EDR
        corp.edr_alert(sim, w, s, ts + r.uniform(2, 20), "first_seen_unsigned_binary", "medium", path=b.path,
                       sha256=b.sha256, label=(aid, "edr_alert"))


def fast_approval(ts, sim, w, aid, o):
    """A prod config change approved within seconds, outside working hours."""
    r = sim.rng
    u = _user(sim, o, [x for x in w.engineers if x.role in ("swe", "sre")])
    svc = r.choice(w.services_for(u) or [x for x in w.services.values() if not x.infra])
    cell = r.choice(svc.cells)
    approver = w.pick_member(u.team, exclude=u)
    s = w.session_for(u, ts)
    delay = r.uniform(3, 12) + (1 - min(o["k"], 1.0)) * r.uniform(60, 240)
    _case(sim, aid, "fast_approval", ts, ts + 600,
          f"MPA for {cell}/{svc.name} approved by {approver.principal} {delay:.0f}s after request", o,
          principal=u.principal, approver=approver.principal, job=svc.name, cell=cell)
    mpa_id, t_ok = admin.mpa(sim, w, s, ts, operation="UpdateJobConfig", target=f"{cell}/{svc.name}",
                             change={"flags": {"--max_inflight": [r.choice([64, 128]), r.choice([512, 1024])]}},
                             justification="config tweak", approver=approver, delay=delay,
                             label=(aid, "mpa_fast_approval"))
    borg.audit(sim, w, t_ok + r.uniform(5, 30), "UpdateJob", principal=u.principal, cell=cell, job=svc.name,
               mpa_id=mpa_id, device_id=s.device.device_id, read_only=False, label=(aid, "update_after_fast_mpa"),
               request={"job": svc.name, "config_only": True})


# ---------------------------------------------------------------------- eBPF runtime patterns
# Sensor-level patterns from public container-runtime rule sets, mapped to MITRE ATT&CK. Each one
# is a short burst of syscalls inside a single task. Refused syscalls carry ret < 0 (seccomp,
# capabilities or egress policy), which is how most of these end in a sandboxed task.
EPERM, EACCES, ENOENT = runtime.ERRNO["EPERM"], runtime.ERRNO["EACCES"], runtime.ERRNO["ENOENT"]


def _ebpf_target(sim, w, o, need_no_egress=False):
    if o.get("service"):
        svc = o["service"]
    else:
        svc = sim.rng.choice([s for s in w.services.values()
                              if not s.infra and not (need_no_egress and (s.egress or s.frontend))])
    return svc, w.random_task(sim.rng, svc.name)


def _ebpf_case(sim, aid, kind, ts, svc, task, description, mitre, o, dur=900):
    _case(sim, aid, kind, ts, ts + dur, description, o, mitre, principal=svc.principal, job=svc.name,
          cell=task.cell, task=task.id, host=task.machine.hostname, container_id=task.container_id)


def _dropped(sim) -> str:
    return f"/tmp/.{sim.rng.choice(['cache', 'x', 'tmp', 'font-unix'])}/{sim.hex(6)}"


def ebpf_shell_in_container(ts, sim, w, aid, o):
    """The service binary spawns a non-interactive shell reading from a socket, then discovery
    commands. Legitimate shells come from the Borglet, with a pty and a prod_ssh session."""
    r = sim.rng
    svc, task = _ebpf_target(sim, w, o)
    if o["k"] < 0.5:  # no shell: the service runs a couple of plain tools it never ran before
        _ebpf_case(sim, aid, "ebpf_shell_in_container", ts, svc, task,
                   f"{svc.binary} runs tools it never ran before in {task.id}", ["T1082"], o)
        for k, argv in enumerate(r.sample([["/usr/bin/curl", "-s", "http://169.254.169.254/"], ["/usr/bin/uname", "-a"],
                                           ["/usr/bin/id"]], 2)):
            runtime.ebpf(sim, w, task, ts + k * r.uniform(1, 20), "execve",
                         {"exe": argv[0], "comm": argv[0].rsplit("/", 1)[-1], "argv": argv, "parent_exe": svc.binary},
                         label=(aid, "unusual_child_process"))
        return
    _ebpf_case(sim, aid, "ebpf_shell_in_container", ts, svc, task,
               f"{svc.binary} spawned /bin/sh with stdin on a socket in {task.id}", ["T1059.004", "T1082"], o)
    runtime.ebpf(sim, w, task, ts, "execve",
                 {"exe": "/bin/sh", "comm": "sh", "argv": ["sh", "-i"], "parent_exe": svc.binary, "tty": False,
                  "stdin": "socket"}, label=(aid, "shell_spawned_by_service"))
    t = ts + r.uniform(2, 10)
    cmds = [["id"], ["uname", "-a"], ["hostname"], ["cat", "/etc/os-release"], ["ls", "-la", "/"], ["env"]]
    for argv in r.sample(cmds, min(len(cmds), _n(sim, o, 2, 5))):
        runtime.ebpf(sim, w, task, t, "execve",
                     {"exe": f"/usr/bin/{argv[0]}", "comm": argv[0], "argv": argv, "parent_exe": "/bin/sh",
                      "tty": False}, label=(aid, "discovery_from_shell"))
        t += r.uniform(1, 15)


def ebpf_namespace_escape(ts, sim, w, aid, o):
    """Namespace and mount syscalls from inside a task, refused by seccomp."""
    r = sim.rng
    svc, task = _ebpf_target(sim, w, o)
    exe = r.choice([svc.binary, _dropped(sim)])
    _ebpf_case(sim, aid, "ebpf_namespace_escape", ts, svc, task,
               f"unshare/setns/mount attempts from {exe} in {task.id}, refused", ["T1611"], o)
    common = {"exe": exe, "comm": exe.rsplit("/", 1)[-1][:15],
              "parent_exe": svc.binary if exe != svc.binary else runtime.BORGLET, "seccomp_action": "SCMP_ACT_ERRNO"}
    attempts = [("unshare", {"flags": "CLONE_NEWNS|CLONE_NEWUSER"}, "unshare_denied"),
                ("setns", {"target": "/proc/1/ns/mnt", "nstype": "CLONE_NEWNS"}, "setns_denied"),
                ("mount", {"source": "/dev/sda1", "target": "/mnt/host", "fstype": "ext4"}, "mount_denied"),
                ("openat", {"path": "/proc/1/root/etc/hostname", "flags": "O_RDONLY"}, "host_root_open_denied")]
    t = ts
    for syscall, fields, signal in r.sample(attempts, min(4, _n(sim, o, 2, 5))):
        runtime.ebpf(sim, w, task, t, syscall, {**common, **fields}, ret=EPERM if syscall != "openat" else EACCES,
                     label=(aid, signal))
        t += r.uniform(0.01, 3)


def ebpf_sensitive_read(ts, sim, w, aid, o):
    """A task opens credential and host-identity paths that are not its own."""
    r = sim.rng
    svc, task = _ebpf_target(sim, w, o)
    other = w.random_task(r, r.choice([s for s in w.services if s != svc.name and not w.services[s].infra]))
    _ebpf_case(sim, aid, "ebpf_sensitive_read", ts, svc, task,
               f"{task.id} opens credential paths outside its own sandbox", ["T1552.001", "T1003.008"], o)
    paths = [("/etc/shadow", EACCES), ("/proc/1/environ", EACCES), ("/root/.ssh/id_ed25519", EACCES),
             (f"/borg/{other.id}/var/run/loas/role_cert.pem", ENOENT), ("/proc/self/mountinfo", 0)]
    t = ts
    for path, ret in r.sample(paths, min(5, _n(sim, o, 3, 6))):
        runtime.ebpf(sim, w, task, t, "openat", {"path": path, "flags": "O_RDONLY"}, ret=ret,
                     label=(aid, "sensitive_path_open"))
        t += r.uniform(0.05, 20)


def ebpf_kernel_module(ts, sim, w, aid, o):
    """A kernel module load attempted from inside a task."""
    r = sim.rng
    svc, task = _ebpf_target(sim, w, o)
    ko = f"{_dropped(sim)}.ko"
    _ebpf_case(sim, aid, "ebpf_kernel_module", ts, svc, task, f"insmod {ko} from {task.id}, refused", ["T1547.006"], o)
    runtime.ebpf(sim, w, task, ts, "execve", {"exe": "/sbin/insmod", "comm": "insmod", "argv": ["insmod", ko],
                                              "parent_exe": "/bin/sh"}, label=(aid, "insmod_exec"))
    runtime.ebpf(sim, w, task, ts + r.uniform(0.01, 0.2), "finit_module",
                 {"exe": "/sbin/insmod", "comm": "insmod", "parent_exe": "/bin/sh", "module_path": ko,
                  "seccomp_action": "SCMP_ACT_ERRNO"}, ret=EPERM, label=(aid, "finit_module_denied"))


def ebpf_ptrace_attach(ts, sim, w, aid, o):
    """An unknown process attaches to the service and reads its memory. The fleet profiler
    (cprof, PTRACE_SEIZE) does the benign version of this all day."""
    r = sim.rng
    svc, task = _ebpf_target(sim, w, o)
    exe = _dropped(sim)
    _ebpf_case(sim, aid, "ebpf_ptrace_attach", ts, svc, task, f"{exe} attaches to {svc.binary} in {task.id}",
               ["T1055.008"], o)
    common = {"exe": exe, "comm": exe.rsplit("/", 1)[-1][:15], "parent_exe": "/bin/sh", "target_exe": svc.binary}
    runtime.ebpf(sim, w, task, ts, "ptrace", {**common, "request": "PTRACE_ATTACH"},
                 label=(aid, "ptrace_attach_unknown_tracer"))
    for k in range(_n(sim, o, 1, 4)):
        runtime.ebpf(sim, w, task, ts + 0.5 + k * r.uniform(0.1, 2), "process_vm_readv",
                     {**common, "bytes": r.randrange(4096, 2**22)}, label=(aid, "process_vm_readv"))


def ebpf_bpf_load(ts, sim, w, aid, o):
    """A task tries to load its own BPF programs, refused (no CAP_BPF)."""
    r = sim.rng
    svc, task = _ebpf_target(sim, w, o)
    exe = r.choice([svc.binary, _dropped(sim)])
    _ebpf_case(sim, aid, "ebpf_bpf_load", ts, svc, task, f"BPF_PROG_LOAD attempts from {exe} in {task.id}",
               ["T1014"], o)
    t = ts
    progs = ["BPF_PROG_TYPE_KPROBE", "BPF_PROG_TYPE_TRACEPOINT", "BPF_PROG_TYPE_SOCKET_FILTER"]
    for prog in r.sample(progs, min(3, _n(sim, o, 1, 4))):
        runtime.ebpf(sim, w, task, t, "bpf", {"exe": exe, "comm": exe.rsplit("/", 1)[-1][:15], "cmd": "BPF_PROG_LOAD",
                                              "prog_type": prog, "missing_capability": "CAP_BPF"},
                     ret=EPERM, label=(aid, "bpf_prog_load_denied"))
        t += r.uniform(0.01, 1)


def ebpf_memfd_exec(ts, sim, w, aid, o):
    """Fileless execution: an anonymous in-memory file is created then executed."""
    r = sim.rng
    svc, task = _ebpf_target(sim, w, o)
    fd = r.randrange(3, 30)
    _ebpf_case(sim, aid, "ebpf_memfd_exec", ts, svc, task, f"{svc.binary} executes a memfd in {task.id}", ["T1620"], o)
    runtime.ebpf(sim, w, task, ts, "memfd_create", {"name": "", "flags": "MFD_CLOEXEC", "fd": fd},
                 label=(aid, "memfd_create"))
    runtime.ebpf(sim, w, task, ts + r.uniform(0.05, 2), "execveat",
                 {"exe": "memfd: (deleted)", "comm": str(fd), "dirfd": fd, "path": "", "flags": "AT_EMPTY_PATH",
                  "parent_exe": svc.binary}, label=(aid, "exec_from_memfd"))


def ebpf_unexpected_connect(ts, sim, w, aid, o):
    """A service with no internet egress retries an outbound connection to one external address
    on a fixed interval; the egress policy drops it."""
    r = sim.rng
    svc, task = _ebpf_target(sim, w, o, need_no_egress=True)
    dst, port = w.ext_ip(r), r.choice([4444, 8443, 9001])
    interval = r.uniform(30, 120)
    n = _n(sim, o, 4, 10)
    _ebpf_case(sim, aid, "ebpf_unexpected_connect", ts, svc, task,
               f"{task.id} retries {dst}:{port} every ~{interval:.0f}s, dropped by egress policy", ["T1071"], o,
               dur=interval * n + 60)
    for k in range(n):
        t = ts + k * interval * r.uniform(0.9, 1.1)
        runtime.ebpf(sim, w, task, t, "connect", {"dst_ip": dst, "dst_port": port},
                     ret=runtime.ERRNO["ETIMEDOUT"], label=(aid, "connect_external_refused"))
        runtime.flow(sim, w, task, t + 0.01, dst, port, 74, egress=True, verdict="drop",
                     label=(aid, "jupiter_egress_dropped"))


INJECTORS = {f.__name__: f for f in (read_volume_spike, new_rpc_edge, off_hours_access, first_seen_device,
                                     unverified_build, egress_shift, rare_binary, fast_approval,
                                     ebpf_shell_in_container, ebpf_namespace_escape, ebpf_sensitive_read,
                                     ebpf_kernel_module, ebpf_ptrace_attach, ebpf_bpf_load, ebpf_memfd_exec,
                                     ebpf_unexpected_connect)}
NIGHT_KINDS = {"off_hours_access", "fast_approval"}
# What can be bundled on one person, and on one service.
USER_KINDS = ["off_hours_access", "first_seen_device", "rare_binary", "fast_approval", "read_volume_spike"]
SERVICE_KINDS = ["new_rpc_edge", "egress_shift", "read_volume_spike", "ebpf_shell_in_container"]


def _pick_time(sim, kind: str, night=None) -> float:
    r = sim.rng
    span = sim.end - sim.start
    lo, hi = sim.start + 0.05 * span, sim.end - min(7200.0, 0.3 * span)
    for _ in range(200):
        t = r.uniform(lo, hi)
        h = sim.local_hour(t)
        if night == "evening":
            if 20.0 <= h < 22.0:
                return t
        elif night or kind in NIGHT_KINDS:
            if 1.0 <= h < 4.0 or (kind == "fast_approval" and not night and h >= 21):
                return t
        else:
            return t
    return r.uniform(lo, hi)


def schedule(sim, w, count: int, kinds: list[str], intensity: float = 1.0, shuffle: bool = False) -> None:
    kinds = list(kinds)
    if shuffle:
        sim.rng.shuffle(kinds)
    for i in range(count):
        kind = kinds[i % len(kinds)]
        sim.at(_pick_time(sim, kind), INJECTORS[kind], sim, w, f"A{i + 1:03d}", {"k": intensity})


def schedule_bundles(sim, w, count: int, size: int, intensity: float) -> None:
    """Several weak anomalies on one entity within a few hours: alone each stays under its
    threshold; together they should add up (signal fusion, E1)."""
    r = sim.rng
    for i in range(count):
        bid = f"BUNDLE{i + 1:02d}"
        if i % 2 == 0:
            focus = {"user": r.choice([u for u in w.engineers if u.role == "swe"])}
            kinds = r.sample(USER_KINDS, min(size, len(USER_KINDS)))
            t0, window = _pick_time(sim, "", night="evening" if intensity < 0.5 else True), 3 * 3600
        else:
            focus = {"service": r.choice([s for s in w.services.values()
                                          if not (s.infra or s.egress or s.frontend or s.tpu)])}
            kinds = r.sample(SERVICE_KINDS, min(size, len(SERVICE_KINDS)))
            t0, window = _pick_time(sim, ""), 6 * 3600
        for j, kind in enumerate(kinds):
            sim.at(t0 + r.uniform(0, window), INJECTORS[kind], sim, w, f"{bid}-{j + 1}",
                   {**focus, "k": intensity, "bundle": bid})


# The other layers of the diagram (endpoint network, identity, code review, scheduling, Spanner,
# Bigtable, B4, Titan, TPU). Imported last: that module builds on the helpers above.
from .anomalies_layers import LAYER_INJECTORS, SERVICE_KINDS_MORE, USER_KINDS_MORE  # noqa: E402

INJECTORS.update(LAYER_INJECTORS)
USER_KINDS += USER_KINDS_MORE
SERVICE_KINDS += SERVICE_KINDS_MORE
