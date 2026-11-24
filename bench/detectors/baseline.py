"""P2: per-entity statistical baselines (classic UEBA / NHI profiling).

Learns online. During the warm-up it only learns; afterwards it scores, then keeps learning.
Two primitives:
  novelty   first time a (entity, thing) pair is seen: new app for a user, new RPC edge for a
            service, new executable in a job, new egress destination...
  z-score   EWMA mean/variance of a log-scaled value, per entity and per 3-hour bucket of the
            local day (seasonality), for volumes and metrics.
"""
from __future__ import annotations

import math
from collections import defaultdict

from ..core import Alert, Detector


class EWMA:
    __slots__ = ("n", "mean", "var")

    def __init__(self):
        self.n, self.mean, self.var = 0, 0.0, 0.0

    def z(self, x: float) -> float | None:
        if self.n < 5:
            return None
        return (x - self.mean) / math.sqrt(self.var + 0.05)

    def update(self, x: float, alpha: float = 0.1) -> None:
        if self.n == 0:
            self.mean = x
        d = x - self.mean
        self.mean += alpha * d
        self.var = (1 - alpha) * (self.var + alpha * d * d)
        self.n += 1


class VolumeStats(EWMA):
    """EWMA of a log10 volume with a small variance floor: replication and backup volumes vary by about 20%, so the
    floor of the count baselines (0.05, a standard deviation of 0.22 in log10) would hide an eightfold spike."""
    __slots__ = ()

    def z(self, x: float) -> float | None:
        if self.n < 5:
            return None
        return (x - self.mean) / math.sqrt(self.var + 0.002)


class Baselines(Detector):
    name = "P2-entity-baselines"
    pipeline = "P2"

    def __init__(self, warmup_h: float = 12.0, z: float = 4.0, volume: str | None = None):
        self.warmup_h, self.zmax = warmup_h, z
        self.seen: dict[str, set] = defaultdict(set)
        self.stats: dict = defaultdict(EWMA)
        self.hours: dict = defaultdict(lambda: [0] * 24)
        # Volume baselines on database audit logs and the WAN (off by default): "hourly" scores each value against
        # the same key at the same hour of the day, "flat" against all hours (the naive variant).
        assert volume in (None, "hourly", "flat")
        self.volume = volume
        self.vol_acc: dict = {}
        self.vstats: dict = defaultdict(VolumeStats)

    def setup(self, run):
        self.run = run
        self.learn_until = run.start + self.warmup_h * 3600

    # ---------------------------------------------------------------------- primitives
    def _novel(self, space, key, ev, family, score, learning, rule=None):
        if key in self.seen[space]:
            return None
        self.seen[space].add(key)
        if learning:
            return None
        return Alert(self.name, rule or f"new_{space}", str(key[0]), score, [ev["event_id"]], family)

    def _zscore(self, space, key, value, ev, family, learning, rule=None, direction=1):
        bucket = int(self.run.local_hour(ev["_t"]) // 3)
        st = self.stats[(space, key, bucket)]
        if st.n < 5:  # no seasonal history yet: fall back to the entity's overall profile
            st = self.stats[(space, key, None)]
        z = st.z(value)
        self.stats[(space, key, bucket)].update(value)
        self.stats[(space, key, None)].update(value)
        if learning or z is None or z * direction < self.zmax:
            return None
        return Alert(self.name, rule or f"{space}_zscore", str(key[0]), min(1.0, abs(z) / 10), [ev["event_id"]], family)

    # ---------------------------------------------------------------------- dispatch
    def process(self, ev):
        s, p = ev["log_source"], ev["payload"]
        learning = ev["_t"] < self.learn_until
        out = []
        principal = ev.get("principal", "")
        add = out.append

        if s == "bc.uberproxy":
            a = self._novel("device_for_user", (principal, ev.get("device_id")), ev, "ueba", 0.8, learning)
            a and add(a)
            if p.get("required_tier") == "high":
                a = self._novel("prod_app_for_user", (principal, p.get("app")), ev, "ueba", 0.5, learning)
                a and add(a)
                h = self.hours[principal]
                hour = int(self.run.local_hour(ev["_t"]))
                total = sum(h)
                prob = (h[hour] + 0.5) / (total + 12)
                if not learning and total >= 20 and prob < 0.01:
                    add(Alert(self.name, "rare_hour_for_user", principal, 1 - prob * 50, [ev["event_id"]], "ueba"))
                h[hour] += 1
        elif s == "borg.master_audit" and principal.startswith("user:") and p.get("read_only"):
            a = self._novel("job_read_by_user", (principal, ev.get("job")), ev, "ueba", 0.4, learning)
            a and add(a)
        elif s == "admin.mpa" and ev["action"] == "approve":
            a = self._zscore("mpa_latency", ("population",), math.log10(p.get("approval_latency_s", 1) + 1), ev,
                             "ueba", learning, "mpa_unusually_fast", direction=-1)
            a and add(a)
        elif s == "colossus.chunkserver":
            key = (principal, p.get("dataset"), ev.get("cell"))
            a = self._novel("reader_of_dataset", key, ev, "nhi" if principal.startswith("svc:") else "ueba", 0.8,
                            learning)
            if a:
                add(a)
            else:
                a = self._zscore("chunk_read", key, math.log10(p.get("bytes_read", 0) + 1), ev, "nhi", learning)
                a and add(a)
        elif s == "colossus.curator" and principal.startswith("user:") and "/home/" not in p.get("path", ""):
            a = self._novel("dataset_for_user", (principal, p.get("dataset")), ev, "ueba", 0.7, learning)
            a and add(a)
        elif s == "obs.dapper" and p.get("caller"):  # F3: per-edge spans (only with --dapper-edges)
            key = (p.get("caller"), p.get("method"), ev.get("cell"))
            a = self._novel("rpc_edge_span", key, ev, "nhi", 0.8, learning)
            a and add(a)
        elif s == "obs.rpc_edge":
            key = (p.get("caller"), p.get("callee"), p.get("method"), ev.get("cell"))
            a = self._novel("rpc_edge", key, ev, "nhi", 0.8, learning)
            if a:
                add(a)
            else:
                a = self._zscore("edge_calls", key, math.log10(p.get("calls", 0) + 1), ev, "nhi", learning)
                a and add(a)
        elif s == "net.alts":
            a = self._novel("alts_peer", (principal, p.get("method")), ev, "nhi", 0.6, learning)
            a and add(a)
        elif s == "obs.monarch":
            for metric in ("error_ratio", "egress_bytes", "latency_p99_ms"):
                v = p.get("metrics", {}).get(metric)
                if v is not None:
                    a = self._zscore(f"metric_{metric}", (ev.get("job"), ev.get("cell")), math.log10(v + 1e-6), ev,
                                     "nhi", learning)
                    a and add(a)
        elif s == "net.jupiter" and p.get("egress"):
            a = self._novel("egress_dst_for_job", (ev.get("job"), ev.get("dst_ip")), ev, "nhi", 0.7, learning)
            a and add(a)
        elif s == "host.ebpf":
            key = (ev.get("job"), ev["action"], p.get("exe"), p.get("parent_exe") if ev["action"] == "execve" else None)
            a = self._novel("syscall_profile", key, ev, "runtime", 0.6, learning)
            a and add(a)
        elif s.startswith("ext."):
            # External datasets (A5): generic UEBA. New (person, machine), new (person, action), rare hour.
            dev = ev.get("device_id") or ev.get("host")
            if principal and dev:
                a = self._novel("machine_for_user", (principal, dev), ev, "ueba", 0.6, learning)
                a and add(a)
            if principal:
                detail = ev["payload"].get("detail", "")
                a = self._novel("action_for_user", (principal, f"{s}:{ev['action']}:{detail}"), ev, "ueba", 0.5,
                                learning)
                a and add(a)
                h = self.hours[principal]
                hour = int(self.run.local_hour(ev["_t"]))
                total = sum(h)
                prob = (h[hour] + 0.5) / (total + 12)
                if not learning and total >= 50 and prob < 0.005:
                    add(Alert(self.name, "rare_hour_for_user", principal, 1 - prob * 100, [ev["event_id"]], "ueba"))
                h[hour] += 1
        elif s in ("corp.santa", "corp.auditd"):
            a = self._novel("binary_in_fleet", (p.get("sha256") or p.get("exe"),), ev, "runtime", 0.6, learning)
            a and add(a)
        if self.volume and s in ("spanner.audit", "bigtable.audit", "net.b4"):
            a = self._volume(ev, s, p, principal, learning)
            a and add(a)
        return out or None

    # ---------------------------------------------------------------------- volume baselines (gap closing)
    def _volume(self, ev, s, p, principal, learning):
        """Rows read per (principal, table) and clock hour on the Spanner and Bigtable audit logs; bytes per
        10-minute window and flow class on the B4 WAN. One alert per key and hour."""
        if s == "spanner.audit":
            if ev["action"] not in ("ExecuteSql", "Read", "StreamingRead"):
                return None
            key = (principal, f"{p.get('database')}/{p.get('table')}")
            return self._hourly_sum("spanner_rows", key, p.get("rows_returned", 0) or 0, ev, learning)
        if s == "bigtable.audit":
            if ev["action"] != "ReadRows":
                return None
            return self._hourly_sum("bigtable_rows", (principal, p.get("table")), p.get("rows", 0) or 0, ev, learning)
        if s == "net.b4":
            key = (f"flow:{p.get('flow_class')}",)
            hour = int(self.run.local_hour(ev["_t"]))
            x = math.log10((p.get("bytes", 0) or 0) + 1)
            z = self._vol_z("b4_bytes", key, hour, x)
            self._vol_learn("b4_bytes", key, hour, x)
            slot = ("b4_bytes", key)
            h = int((ev["_t"] - self.run.start) // 3600)
            if learning or z is None or z < self.zmax or self.vol_acc.get(slot) == h:
                return None
            self.vol_acc[slot] = h
            return Alert(self.name, "b4_bytes_volume", key[0], min(1.0, z / 10), [ev["event_id"]], "nhi")
        return None

    def _hourly_sum(self, space, key, value, ev, learning):
        t = ev["_t"]
        h = int((t - self.run.start) // 3600)
        acc = self.vol_acc.get((space, key))
        if acc is None or acc[0] != h:
            if acc is not None:  # the previous clock hour of this key is complete: learn it
                self._vol_learn(space, key, acc[2], math.log10(acc[1] + 1))
            acc = self.vol_acc[(space, key)] = [h, 0.0, int(self.run.local_hour(t)), False]
        acc[1] += value
        if learning or acc[3]:
            return None
        z = self._vol_z(space, key, acc[2], math.log10(acc[1] + 1))
        if z is None or z < self.zmax:
            return None
        acc[3] = True
        fam = "ueba" if str(key[0]).startswith("user:") else "nhi"
        return Alert(self.name, f"{space}_volume", str(key[0]), min(1.0, z / 10), [ev["event_id"]], fam)

    def _vol_learn(self, space, key, hour, x):
        if self.volume == "hourly":
            self.vstats[(space, key, hour)].update(x)
        self.vstats[(space, key, None)].update(x)
        if len(key) == 2:
            self.vstats[(space, (key[0], "*"), None)].update(x)  # the principal's prior over all its tables
            self.vstats[(space, ("*", key[1]), None)].update(x)  # the table's prior over all its readers

    def _vol_z(self, space, key, hour, x):
        cands = [(space, key, hour)] if self.volume == "hourly" else []
        cands += [(space, key, None)]
        if len(key) == 2:  # cold start: the principal's other tables, then the table's other readers
            cands += [(space, (key[0], "*"), None), (space, ("*", key[1]), None)]
        for c in cands:
            st = self.vstats.get(c)
            if st is not None and st.n >= 5:
                return st.z(x)
        return None
