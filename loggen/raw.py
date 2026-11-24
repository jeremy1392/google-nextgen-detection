"""Native log lines for sources that have a well-known wire format, so the normalization
step (raw -> structured) can be measured. Called with ev["ts"] still a float."""
from __future__ import annotations

from datetime import datetime, timezone


def _dt(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, tz=timezone.utc)


def _santa(ev):
    p = ev["payload"]
    return (f"[{_dt(ev['ts']).isoformat(timespec='milliseconds').replace('+00:00', 'Z')}] I santad: action=EXEC"
            f"|decision={p['decision']}|reason={p['reason']}|sha256={p['sha256']}|cert_sha256={p.get('cert_sha256') or ''}"
            f"|cn={p.get('signing_id') or ''}|pid={p['pid']}|ppid={p['ppid']}|uid={p['uid']}|user={p['user']}"
            f"|mode={p['mode'][0]}|path={p['path']}|args={' '.join(p['argv'])}")


def _auditd(ev):
    p = ev["payload"]
    stamp = f"audit({ev['ts']:.3f}:{int(ev['ts'] * 1000) % 10_000_000})"
    args = " ".join(f'a{i}="{a}"' for i, a in enumerate(p["argv"]))
    return (f"type=SYSCALL msg={stamp}: arch=c000003e syscall=59 success=yes exit=0 ppid={p['ppid']} pid={p['pid']} "
            f"auid={p['auid']} uid={p['uid']} comm=\"{p['comm']}\" exe=\"{p['exe']}\" key=\"{p['key']}\"\n"
            f"type=EXECVE msg={stamp}: argc={len(p['argv'])} {args}\n"
            f"type=CWD msg={stamp}: cwd=\"{p['cwd']}\"")


def _dns(ev):
    p = ev["payload"]
    return (f"{_dt(ev['ts']).strftime('%d-%b-%Y %H:%M:%S.%f')[:-3]} client @0x7f00 {ev.get('src_ip')}#"
            f"{40000 + int(ev['ts'] * 1000) % 25000} ({p['query']}): query: {p['query']} IN {p['qtype']} + "
            f"({p['resolver']}) rcode={p['rcode']}")


def _netflow(ev):
    p = ev["payload"]
    return ",".join(str(x) for x in (f"{ev['ts']:.3f}", ev.get("src_ip"), p["src_port"], ev.get("dst_ip"), p["dst_port"],
                                     6 if p["proto"] == "tcp" else 17, p["bytes_out"], p["bytes_in"], p["packets"],
                                     p["duration_ms"]))


def _uberproxy(ev):
    p = ev["payload"]
    return (f"{ev.get('src_ip')} - {ev.get('principal')} [{_dt(ev['ts']).strftime('%d/%b/%Y:%H:%M:%S +0000')}] "
            f"\"{p['method']} https://{p['host']}{p['path']} HTTP/2\" {p['status']} - \"{p['user_agent']}\" "
            f"device={ev.get('device_id')} tier={p['device_trust_tier']} decision={ev.get('outcome', '').upper()}")


RENDERERS = {"corp.santa": _santa, "corp.auditd": _auditd, "corp.dns": _dns, "corp.netflow": _netflow,
             "bc.uberproxy": _uberproxy}


def render_raw(ev: dict) -> str | None:
    fn = RENDERERS.get(ev["log_source"])
    return fn(ev) if fn else None
