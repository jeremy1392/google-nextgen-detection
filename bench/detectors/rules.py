"""The traditional camp.

P0: stateless rules, one event at a time, transcribed in the spirit of public rule sets
    (Sigma for logs, Falco's default rules for container runtime) onto loggen's schema.
P1: what a SIEM adds on top: lookup tables (inventory, on-call, build registry) and
    windowed correlation (counts per entity over a time window).
"""
from __future__ import annotations

from collections import defaultdict, deque

from ..core import Alert, Detector

SHELLS = {"/bin/sh", "/bin/bash", "/bin/zsh", "/usr/bin/bash"}
TRUSTED_SHELL_PARENTS = {"/usr/bin/borglet", "/bin/sh", "/bin/bash"}
SENSITIVE_PREFIXES = ("/etc/shadow", "/root/.ssh/", "/proc/1/environ", "/proc/1/root")
EGRESS_ALLOWLIST = {"search-indexer", "logs-exporter"}
PROD_APPS = {"borgcfg", "colossus-browser", "breakglass-console", "mpa-console"}
LOW, MED, HIGH = 0.3, 0.6, 0.9


class Rule:
    __slots__ = ("id", "family", "source", "severity", "pred")

    def __init__(self, id, family, source, severity, pred):
        self.id, self.family, self.source, self.severity, self.pred = id, family, source, severity, pred


def _is_private(ip: str | None) -> bool:
    return bool(ip) and (ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16."))


RULES = [
    # --- runtime (Falco-style) -------------------------------------------------------------
    Rule("terminal_shell_in_container", "runtime", "host.ebpf", MED,
         lambda e, p, r: e["action"] == "execve" and p.get("exe") in SHELLS and p.get("tty") is True),
    Rule("shell_untrusted_parent", "runtime", "host.ebpf", HIGH,
         lambda e, p, r: e["action"] == "execve" and p.get("exe") in SHELLS
         and p.get("parent_exe") not in TRUSTED_SHELL_PARENTS),
    Rule("namespace_change", "runtime", "host.ebpf", HIGH, lambda e, p, r: e["action"] in ("unshare", "setns")),
    Rule("mount_in_container", "runtime", "host.ebpf", HIGH, lambda e, p, r: e["action"] == "mount"),
    Rule("read_sensitive_file", "runtime", "host.ebpf", HIGH,
         lambda e, p, r: e["action"] == "openat" and (str(p.get("path", "")).startswith(SENSITIVE_PREFIXES)
                                                      or ("/var/run/loas/" in str(p.get("path", ""))
                                                          and str(p.get("path", "")).startswith("/borg/")))),
    Rule("kernel_module_load", "runtime", "host.ebpf", HIGH,
         lambda e, p, r: e["action"] in ("init_module", "finit_module")
         or str(p.get("exe", "")).endswith(("/insmod", "/modprobe"))),
    Rule("ptrace_attach", "runtime", "host.ebpf", MED,
         lambda e, p, r: e["action"] == "ptrace" and p.get("request") in ("PTRACE_ATTACH", "PTRACE_SEIZE")),
    Rule("process_memory_read", "runtime", "host.ebpf", HIGH, lambda e, p, r: e["action"] == "process_vm_readv"),
    Rule("bpf_program_load", "runtime", "host.ebpf", HIGH,
         lambda e, p, r: e["action"] == "bpf" and p.get("cmd") == "BPF_PROG_LOAD"),
    Rule("fileless_exec_memfd", "runtime", "host.ebpf", HIGH,
         lambda e, p, r: e["action"] == "execveat" and str(p.get("exe", "")).startswith("memfd:")),
    Rule("container_connect_public_ip", "runtime", "host.ebpf", MED,
         lambda e, p, r: e["action"] == "connect" and not _is_private(p.get("dst_ip"))),
    Rule("egress_dropped", "nhi", "net.jupiter", MED, lambda e, p, r: p.get("policy_verdict") == "drop"),
    Rule("egress_not_allowlisted", "nhi", "net.jupiter", MED,
         lambda e, p, r: p.get("egress") and e.get("job") not in EGRESS_ALLOWLIST),
    Rule("attestation_failed", "runtime", "host.titan", LOW, lambda e, p, r: p.get("verdict") != "PASS"),
    # --- endpoints ----------------------------------------------------------------------------
    Rule("santa_unknown_binary", "runtime", "corp.santa", MED, lambda e, p, r: p.get("reason") == "UNKNOWN"),
    Rule("exec_from_downloads_or_tmp", "runtime", "corp.auditd", MED,
         lambda e, p, r: "/Downloads/" in p.get("exe", "") or p.get("exe", "").startswith("/tmp/")),
    Rule("edr_alert_medium_plus", "runtime", "corp.edr", MED, lambda e, p, r: p.get("severity") in ("medium", "high")),
    Rule("usb_mass_storage", "ueba", "corp.usb", LOW, lambda e, p, r: p.get("device_class") == "mass_storage"),
    # --- identity / access ----------------------------------------------------------------
    Rule("offhours_prod_app", "ueba", "bc.uberproxy", MED,
         lambda e, p, r: p.get("app") in PROD_APPS and r.local_hour(e["_t"]) < 6),
    Rule("access_deny_high_tier", "ueba", "bc.uberproxy", LOW,
         lambda e, p, r: e.get("outcome") == "deny" and p.get("required_tier") == "high"),
    Rule("unmanaged_device_posture", "ueba", "bc.device_posture", HIGH, lambda e, p, r: p.get("managed") is False),
    Rule("mtls_unknown_issuer", "ueba", "bc.mtls", MED, lambda e, p, r: p.get("error") == "unknown_issuer"),
    # --- admin / control plane --------------------------------------------------------------
    Rule("breakglass_grant", "ueba", "admin.breakglass", MED, lambda e, p, r: True),
    Rule("mpa_fast_approval", "ueba", "admin.mpa", MED,
         lambda e, p, r: e["action"] == "approve" and p.get("approval_latency_s", 1e9) < 30),
    Rule("bab_not_enforced_allow", "nhi", "borg.bab", HIGH, lambda e, p, r: p.get("decision") != "ALLOW"),
    Rule("unverified_build", "nhi", "admin.build", HIGH, lambda e, p, r: not p.get("provenance", {}).get("verified")),
    Rule("human_shell_into_prod", "ueba", "borg.borglet_priv", LOW,
         lambda e, p, r: e["action"] == "exec_shell" and str(e.get("principal", "")).startswith("user:")),
    # --- data -----------------------------------------------------------------------------------
    Rule("bulk_read_50gb_window", "nhi", "colossus.chunkserver", MED, lambda e, p, r: p.get("bytes_read", 0) > 5e10),
    Rule("human_reads_service_data", "ueba", "colossus.curator", MED,
         lambda e, p, r: str(e.get("principal", "")).startswith("user:") and "/home/" not in p.get("path", "")
         and e["action"] == "Open"),
]


def entity(ev: dict) -> str:
    return ev.get("task") or ev.get("principal") or ev.get("device_id") or ev.get("host") or "?"


class StaticRules(Detector):
    name = "P0-static-rules"
    pipeline = "P0"

    def __init__(self, exclude=()):
        self.by_source = defaultdict(list)
        for rule in RULES:
            if rule.id not in exclude:
                self.by_source[rule.source].append(rule)

    def setup(self, run):
        self.run = run

    def process(self, ev):
        rules = self.by_source.get(ev["log_source"])
        if not rules:
            return None
        p = ev["payload"]
        out = None
        for rule in rules:
            if rule.pred(ev, p, self.run):
                out = out or []
                out.append(Alert(self.name, rule.id, entity(ev), rule.severity, [ev["event_id"]], rule.family))
        return out


class Window:
    """Count events per key over a sliding window; fire once the threshold is reached."""

    def __init__(self, seconds: float, threshold: int):
        self.seconds, self.threshold = seconds, threshold
        self.q: dict = defaultdict(deque)

    def add(self, key, t, eid):
        q = self.q[key]
        q.append((t, eid))
        while q and t - q[0][0] > self.seconds:
            q.popleft()
        if len(q) >= self.threshold:
            ids = [x[1] for x in q]
            q.clear()
            return ids
        return None


class Correlation(StaticRules):
    name = "P1-siem-correlation"
    pipeline = "P1"
    # Rules the enriched / correlated versions below replace.
    REPLACED = {"offhours_prod_app", "breakglass_grant", "access_deny_high_tier", "unmanaged_device_posture",
                "human_reads_service_data", "egress_dropped"}

    def __init__(self):
        super().__init__(exclude=self.REPLACED)
        self.denies = Window(600, 5)
        self.ebpf_denied = Window(300, 3)
        self.human_reads = Window(1800, 10)
        self.dropped = Window(1800, 3)
        self.flagged_devices: set = set()
        self.recent_pages: dict = {}

    def setup(self, run):
        super().setup(run)
        self.known_devices = {d["device_id"] for d in run.inventory.get("devices", [])}

    def _alert(self, rule, ev, score, family, evidence=None):
        return Alert(self.name, rule, entity(ev), score, evidence or [ev["event_id"]], family)

    def process(self, ev):
        out = super().process(ev) or []
        s, p, t, eid = ev["log_source"], ev["payload"], ev["_t"], ev["event_id"]
        principal = ev.get("principal", "")
        if s == "bc.uberproxy":
            dev = ev.get("device_id")
            # without an inventory (B4) this rule cannot be written: every device would be unknown
            if dev and "inventory" not in self.run.dropped and dev not in self.known_devices                     and dev not in self.flagged_devices:
                self.flagged_devices.add(dev)
                out.append(self._alert("device_not_in_inventory", ev, HIGH, "ueba"))
            if ev.get("outcome") == "deny":
                ids = self.denies.add(principal, t, eid)
                if ids:
                    out.append(self._alert("access_deny_burst", ev, MED, "ueba", ids))
            if p.get("app") in PROD_APPS and self.run.local_hour(t) < 6 \
                    and principal not in self.run.oncall_principals(t):
                out.append(self._alert("offhours_prod_app_not_oncall", ev, MED, "ueba"))
        elif s == "bc.device_posture" and p.get("managed") is False and ev.get("device_id") not in self.known_devices:
            out.append(self._alert("unknown_device_posture", ev, HIGH, "ueba"))
        elif s == "admin.incident" and ev["action"] == "page":
            self.recent_pages[p.get("oncall")] = t
        elif s == "admin.breakglass":
            paged = t - self.recent_pages.get(principal, -1e18) < 3600
            if not (p.get("incident_id") and paged):
                out.append(self._alert("breakglass_without_incident", ev, HIGH, "ueba"))
        elif s == "borg.bab" and "builds" not in self.run.dropped and p.get("bcid") not in self.run.builds:
            out.append(self._alert("bcid_not_in_registry", ev, HIGH, "nhi"))
        elif s == "host.ebpf" and ev.get("outcome") == "denied":
            ids = self.ebpf_denied.add(ev.get("task"), t, eid)
            if ids:
                out.append(self._alert("denied_syscall_burst", ev, HIGH, "runtime", ids))
        elif s == "colossus.curator" and principal.startswith("user:") and "/home/" not in p.get("path", ""):
            ids = self.human_reads.add(principal, t, eid)
            if ids:
                out.append(self._alert("human_service_data_burst", ev, HIGH, "ueba", ids))
        elif s == "net.jupiter" and p.get("policy_verdict") == "drop":
            ids = self.dropped.add((ev.get("task"), ev.get("dst_ip")), t, eid)
            if ids:
                out.append(self._alert("repeated_egress_drop", ev, HIGH, "nhi", ids))
        return out or None


class TunedCorrelation(Correlation):
    """P1 after SOC-style tuning. During the warm-up every (rule, executable, parent) - or (rule, principal) for
    non-process rules - that fires is added to an exception list, as an analyst would after reviewing a day of
    alerts; afterwards those combinations no longer alert. It never sees labels."""
    name = "P1-tuned"
    pipeline = "P1"

    def __init__(self, warmup_h: float = 12.0):
        super().__init__()
        self.warmup_h = warmup_h
        self.exceptions: set = set()

    def setup(self, run):
        super().setup(run)
        self.learn_until = run.start + self.warmup_h * 3600

    @staticmethod
    def _key(a, ev):
        p = ev["payload"]
        if p.get("exe"):
            return a.rule, p.get("exe"), p.get("parent_exe")
        return a.rule, ev.get("job") or ev.get("principal")

    def process(self, ev):
        out = super().process(ev)
        if not out:
            return None
        if ev["_t"] < self.learn_until:
            for a in out:
                self.exceptions.add(self._key(a, ev))
            return None
        kept = [a for a in out if self._key(a, ev) not in self.exceptions]
        return kept or None
