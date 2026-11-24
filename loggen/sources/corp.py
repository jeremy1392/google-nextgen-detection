"""Corp network: company devices (Santa, auditd, EDR, DNS, netflow, USB) and the
BeyondCorp identity plane (access proxy, device posture, mTLS, LOAS)."""
from __future__ import annotations

import math

from ..engine import _HUMAN_CURVE
from ..world import APPS, OFFICES, ORG_DOMAIN, PROD_ROLES, PROXY_PUBLIC_IP, TIER_RANK, Binary

INTERNAL_HOSTS = [*APPS, "chat", "calendar", "pkg-mirror", "loas-ca", "time", "uberproxy"]
EXTERNAL_DOMAINS = [
    "github.com", "pypi.org", "files.pythonhosted.org", "stackoverflow.com", "en.wikipedia.org", "arxiv.org",
    "docs.python.org", "registry.npmjs.org", "news.ycombinator.com", "www.youtube.com", "fonts.gstatic.com",
    "update.code.visualstudio.com", "ocsp.digicert.com", "time.apple.com", "swscan.apple.com",
]
USB_KINDS = [  # class, product, weight
    ("HID", "USB keyboard", 4), ("HID", "USB mouse", 4), ("security_key", "FIDO2 security key", 3),
    ("audio", "USB headset", 3), ("video", "USB webcam", 1.5), ("mass_storage", "USB flash drive", 1),
]
EDR_NOISE = [  # rule, severity
    ("dev_tool_spawned_shell_from_ide", "low"),
    ("unsigned_binary_in_build_output", "low"),
    ("browser_extension_unlisted", "low"),
    ("script_read_keychain_item", "medium"),
    ("new_launch_agent_registered", "low"),
]


def install(sim, w) -> None:
    def on_new_session(s, t):
        if s.user.role in PROD_ROLES:
            loas_issue(sim, s, t + sim.rng.uniform(20, 240))
    w.on_new_session = on_new_session
    sim.every(60, lambda t, p: _tick(sim, w, t, p), phase=0.5)
    sim.every(1800, lambda t, p: _posture(sim, w, t, p), phase=11)
    if sim.new_binaries_per_day > 0:
        sim.every(600, lambda t, p: _novelty(sim, w, t, p), phase=45)


def ctx(s) -> dict:
    return {"site": s.site, "host": s.device.hostname, "device_id": s.device.device_id, "principal": s.user.principal}


def _tick(sim, w, t, period) -> None:
    act = w.active(t)
    if not act:
        return
    r, n = sim.rng, len(act)
    if sim.user_heterogeneity > 0:  # H5: heavier users get more of the activity; the total is unchanged
        from itertools import accumulate
        cum = list(accumulate(s.user.activity for s in act))
        pick = lambda: r.choices(act, cum_weights=cum)[0]
    else:
        pick = lambda: r.choice(act)
    for _ in range(sim.poisson(0.45 * n)):
        process_exec(sim, w, pick(), t + r.random() * period)
    for _ in range(sim.poisson(0.9 * n)):
        _dns(sim, w, pick(), t + r.random() * period)
    for _ in range(sim.poisson(0.3 * n)):
        _netflow(sim, w, pick(), t + r.random() * period)
    for _ in range(sim.poisson(0.25 * n)):
        access(sim, w, pick(), t + r.random() * period)
    for _ in range(sim.poisson(0.0015 * n)):
        _usb(sim, w, r.choice(act), t + r.random() * period)
    for _ in range(sim.poisson(0.0004 * n)):
        s = r.choice(act)
        rule, sev = r.choice(EDR_NOISE)
        edr_alert(sim, w, s, t + r.random() * period, rule, sev)


# ---------------------------------------------------------------------- endpoints
def process_exec(sim, w, s, ts, binary=None, label=None, aux=False):
    """aux=True (D6 additions): every random draw and the event id come from sim.aux_rng."""
    d, u = s.device, s.user
    if d.sensor is None:
        return None
    r = sim.aux_rng if aux else sim.rng
    b = binary or w.pick_binary(r, d.os, u.role)
    argv = [b.path.rsplit("/", 1)[-1]] + (r.choice(b.args).split() if b.args else [])
    pid, ppid = r.randrange(400, 99999), r.randrange(1, 400)
    eid = {"eid": sim.aux_hex(32)} if aux else {}
    if d.sensor == "santa":
        payload = {"decision": b.decision, "reason": b.reason, "mode": d.santa_mode, "path": b.path, "argv": argv,
                   "sha256": b.sha256, "cert_sha256": b.cert_sha256, "team_id": b.team_id,
                   "signing_id": b.signing_id, "pid": pid, "ppid": ppid, "uid": d.uid, "user": u.name}
        out = sim.emit(ts, "corp.santa", "EXEC", payload, outcome=b.decision.lower(), label=label, **eid, **ctx(s))
    else:
        payload = {"type": "EXECVE", "syscall": 59, "success": True, "exe": b.path, "comm": argv[0][:15],
                   "argv": argv, "pid": pid, "ppid": ppid, "auid": d.uid, "uid": d.uid, "cwd": f"/home/{u.name}/src",
                   "key": "exec"}
        out = sim.emit(ts, "corp.auditd", "EXECVE", payload, outcome="success", label=label, **eid, **ctx(s))
    if sim.binary_scan:
        _binscan(sim, w, s, ts, b, label)
    return out


def _binscan(sim, w, s, ts, b, label) -> None:
    """D6: the on-host extraction stage (hash, enqueue for the static classifier) at a binary's first run on a
    device. Ids come from aux_rng: switching the knob on adds these events and changes nothing else."""
    if not b.sha256:
        return
    seen = w.device_hashes.setdefault(s.device.device_id, set())
    if b.sha256 in seen:
        return
    seen.add(b.sha256)
    payload = {"sha256": b.sha256, "path": b.path, "os": s.device.os, "signed": b.reason != "UNKNOWN",
               "team_id": b.team_id, "signing_id": b.signing_id, "first_seen_in_fleet": b.sha256 not in w.fleet_hashes}
    w.fleet_hashes.add(b.sha256)
    sim.emit(ts, "corp.binscan", "binary_first_seen", payload, outcome="queued",
             label=(label[0], "binary_first_seen") if label else None, eid=sim.aux_hex(32), **ctx(s))


NOVEL_TOOLS = ["sync-helper", "fmt-tool", "dev-setup", "runner", "netcheck", "jq", "fzf", "rg", "terraform", "kubectl",
               "helm", "gh", "bazelisk", "protoc", "grpcurl", "k9s", "yq", "zstd", "hyperfine", "delta", "lazygit",
               "mkcert", "trivy", "buildifier", "gopls", "rust-analyzer", "clangd", "node", "deno", "uv"]
_MEAN_ACTIVITY = sum(_HUMAN_CURVE) / len(_HUMAN_CURVE)


def _aux_poisson(r, lam: float) -> int:
    limit, k, p = math.exp(-lam), 0, 1.0
    while True:
        p *= r.random()
        if p <= limit:
            return k
        k += 1


def _novelty(sim, w, t, period) -> None:
    """D6: benign binaries the fleet has never run (installs, updates, dev builds): about
    new_binaries_per_day per working day, following who is at work. Some are signed vendor tools, some
    unsigned (the benign twin of the rare_binary anomaly, which uses some of the same tool names). Recorded
    as benign look-alike cases. Everything is drawn from aux_rng, so the rest of the world is unchanged."""
    r = sim.aux_rng
    if w._active_slot != int(t // 600):  # use the people the regular tick already drew; never re-draw them
        return
    act = [x for x in w._active if x.device.sensor]
    lam = sim.new_binaries_per_day * period / 86400 * sim.human_activity(t) / _MEAN_ACTIVITY
    for _ in range(_aux_poisson(r, lam) if act else 0):
        s = r.choice(act)
        sha = w.take_novel(s.device.os)
        if not sha:
            return
        tool = r.choice(NOVEL_TOOLS)
        home = f"/Users/{s.user.name}" if s.device.os == "macOS" else f"/home/{s.user.name}"
        if r.random() < 0.6:  # installed and signed like any vendor tool
            team = "%010X" % r.getrandbits(40)
            b = Binary(f"/usr/local/bin/{tool}", s.device.os, ["", "--version"], 1, None, sha,
                       "%064x" % r.getrandbits(256) if s.device.os == "macOS" else None,
                       team if s.device.os == "macOS" else None, f"com.vendor.{tool}", "TEAMID")
        else:  # a developer build or a download, unsigned
            where = r.choice([f"{home}/Downloads", f"{home}/bin", f"{home}/src/build", f"{home}/.local/bin"])
            b = Binary(f"{where}/{tool}", s.device.os, ["", "--help"], 1, None, sha, None, None, None, "UNKNOWN")
        ts = t + r.random() * (period - 60)
        cid = f"B-new_binary-{sim.aux_hex(6)}"
        sim.open_case(cid, {"case_id": cid, "kind": "benign", "benign_type": "new_binary",
                            "description": f"first run of a new benign binary {b.path} on {s.device.hostname}",
                            "mitre": [], "start": ts, "end": ts + 3600,
                            "entities": {"principal": s.user.principal, "device_id": s.device.device_id,
                                         "sha256": sha}})
        for k in range(1 + (r.random() < 0.5) + (r.random() < 0.2)):
            process_exec(sim, w, s, ts + k * r.uniform(5, 60), binary=b, label=(cid, "exec_new_binary"), aux=True)


def edr_alert(sim, w, s, ts, rule, severity, *, path=None, sha256=None, label=None):
    payload = {"rule": rule, "severity": severity, "status": "open", "verdict": "pending_triage",
               "sensor": s.device.sensor or "chromeos-telemetry", "process_path": path, "sha256": sha256,
               "alert_id": "edr-" + sim.hex(12)}
    return sim.emit(ts, "corp.edr", "alert", payload, outcome="detected", label=label, **ctx(s))


def _dns(sim, w, s, ts) -> None:
    r = sim.rng
    if r.random() < 0.55:
        name = f"{r.choice(INTERNAL_HOSTS)}.{ORG_DOMAIN}"
        answer = OFFICES[s.user.office]["proxy"] if s.loc == "office" else PROXY_PUBLIC_IP
    else:
        name = r.choice(EXTERNAL_DOMAINS)
        answer = w.domain_ip(name)
    rcode = "NXDOMAIN" if r.random() < 0.015 else "NOERROR"
    payload = {"query": name, "qtype": "A" if r.random() < 0.7 else "HTTPS", "rcode": rcode,
               "answers": [] if rcode != "NOERROR" else [answer], "resolver": "10.0.0.53" if s.loc == "office" else "doh",
               "latency_ms": round(r.lognormvariate(2.2, 0.6), 1)}
    sim.emit(ts, "corp.dns", "query", payload, outcome=rcode.lower(), site=s.site, host=s.device.hostname,
             device_id=s.device.device_id, src_ip=s.local_ip)


def _netflow(sim, w, s, ts) -> None:
    r = sim.rng
    if r.random() < 0.7:
        dst, port = (OFFICES[s.user.office]["proxy"] if s.loc == "office" else PROXY_PUBLIC_IP), 443
    else:
        dst, port = w.domain_ip(r.choice(EXTERNAL_DOMAINS)), r.choice([443, 443, 443, 80])
    out_b = int(r.lognormvariate(8.5, 1.2))
    payload = {"proto": "tcp", "src_port": r.randrange(40000, 65000), "dst_port": port, "bytes_out": out_b,
               "bytes_in": int(out_b * r.lognormvariate(2.0, 1.0)), "packets": r.randrange(4, 400),
               "duration_ms": int(r.lognormvariate(7.0, 1.3)), "direction": "outbound"}
    sim.emit(ts, "corp.netflow", "flow", payload, site=s.site, host=s.device.hostname, device_id=s.device.device_id,
             src_ip=s.local_ip, dst_ip=dst)


def _usb(sim, w, s, ts) -> None:
    r = sim.rng
    cls, product, _ = r.choices(USB_KINDS, [k[2] for k in USB_KINDS])[0]
    blocked = cls == "mass_storage" and r.random() < 0.8
    payload = {"device_class": cls, "product": product, "vendor_id": sim.hex(4), "product_id": sim.hex(4),
               "serial": sim.hex(10).upper(), "bus": f"usb{r.randrange(1, 4)}",
               "policy": "block_removable_storage" if cls == "mass_storage" else "allow"}
    sim.emit(ts, "corp.usb", "connect", payload, outcome="blocked" if blocked else "allowed", **ctx(s))


# ---------------------------------------------------------------------- BeyondCorp
def access(sim, w, s, ts, app=None, path=None, label=None):
    """One request through the access proxy. Decision = role/group x device trust tier."""
    r, u, d = sim.rng, s.user, s.device
    app = app or w.pick_app(r, u.role)
    spec = APPS[app]
    reasons = []
    if u.role not in spec.roles:
        reasons.append("principal_not_in_access_group")
    if TIER_RANK[d.trust_tier] < TIER_RANK[spec.min_tier]:
        reasons.append(f"device_tier_{d.trust_tier}_below_{spec.min_tier}")
    ok = not reasons
    if label is not None or r.random() < 0.06:
        mtls(sim, w, s, ts - 0.05, label=label)
    payload = {"app": app, "host": f"{app}.{ORG_DOMAIN}", "path": path or r.choice(spec.paths),
               "method": "POST" if r.random() < 0.15 else "GET", "status": 200 if ok else 403,
               "device_trust_tier": d.trust_tier, "required_tier": spec.min_tier, "deny_reasons": reasons,
               "session_id": s.session_id, "client_location": s.loc, "geo": s.geo, "user_agent": d.user_agent,
               "latency_ms": round(r.lognormvariate(3.3, 0.5), 1)}
    return sim.emit(ts, "bc.uberproxy", "access", payload, outcome="allow" if ok else "deny", label=label,
                    src_ip=s.public_ip, **ctx(s))


def mtls(sim, w, s, ts, label=None):
    d = s.device
    ok = d.managed and sim.rng.random() > 0.003
    payload = {"sni": f"uberproxy.{ORG_DOMAIN}", "tls_version": "TLS1.3", "cipher": "TLS_AES_128_GCM_SHA256",
               "client_cert_sha256": d.cert_sha256,
               "client_cert_issuer": "CN=Corp Device CA 2" if d.managed else "CN=unknown",
               "verified": ok, "error": None if ok else ("unknown_issuer" if not d.managed else "cert_expired"),
               "handshake_ms": round(sim.rng.lognormvariate(3.0, 0.4), 1)}
    return sim.emit(ts, "bc.mtls", "handshake", payload, outcome="success" if ok else "failure", label=label,
                    src_ip=s.public_ip, **ctx(s))


def loas_issue(sim, s, ts) -> None:
    payload = {"cert_serial": sim.hex(16), "validity_hours": 20, "issuer": "loas-ca-1",
               "security_key": {"type": "FIDO2", "user_presence": True}, "groups": [f"mdb:{s.user.team}"]}
    sim.emit(ts, "bc.loas", "cert_issue", payload, outcome="success", src_ip=s.public_ip, **ctx(s))


def posture_report(sim, w, d, ts, owner_principal, label=None, enrollment=False):
    day = sim.local_day(ts)
    age = day - d.last_patch_day
    if not d.managed:
        tier = "unknown"
    elif age <= 21 and d.disk_encrypted and d.screen_lock:
        tier = "high"
    elif age <= 45:
        tier = "medium"
    else:
        tier = "low"
    previous, d.trust_tier = d.trust_tier, tier
    payload = {"os": d.os, "os_version": d.os_version, "managed": d.managed, "serial": d.serial,
               "disk_encrypted": d.disk_encrypted, "screen_lock": d.screen_lock, "firewall": True,
               "sensor": d.sensor, "sensor_healthy": d.sensor is not None or d.os == "ChromeOS",
               "patch_age_days": max(age, 0) if d.managed else None, "trust_tier": tier, "previous_tier": previous,
               "cert_sha256": d.cert_sha256 if d.managed else None, "enrollment_check": enrollment}
    return sim.emit(ts, "bc.device_posture", "posture_report", payload, outcome=tier, label=label,
                    site=d.office, host=d.hostname, device_id=d.device_id, principal=owner_principal)


def _posture(sim, w, t, period) -> None:
    online = {s.device.device_id for s in w.active(t)}
    day = sim.local_day(t)
    for d in w.devices:
        if d.kind != "glinux-workstation" and d.device_id not in online:
            continue
        if sim.rng.random() < 0.004:
            d.last_patch_day = day
        posture_report(sim, w, d, t + sim.rng.random() * period, f"user:{d.owner}")
