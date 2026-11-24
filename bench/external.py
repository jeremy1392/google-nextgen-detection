"""A5: real public datasets replayed through the same pipelines.

CERT Insider Threat r4.2 (CMU SEI): logon, device, http, email and file logs of ~1,000 employees over 17
months; ground truth = the answer files listing every malicious event of each insider scenario.
LANL "Comprehensive, Multi-Source Cyber-Security Events": 58 days of authentication events from a real
enterprise network; ground truth = the red team's authentication events.

Both are exposed as bench.core.Run objects whose events() stream the original files in time order with
loggen's envelope (log_source "ext.*", principal, device_id, action, payload.detail), so P2-P6 run
unchanged. The hand-written rules (P0, P1) target loggen's schema and do not apply.
"""
from __future__ import annotations

import csv
import glob
import gzip
import heapq
import os
from datetime import datetime, timezone
from urllib.parse import urlparse

from .core import Run

INTERNAL_MAIL = "dtaa.com"  # CERT's fictitious company domain


def _cert_ts(s: str) -> float:
    return datetime.strptime(s, "%m/%d/%Y %H:%M:%S").replace(tzinfo=timezone.utc).timestamp()


def _cert_detail(kind: str, r: dict) -> tuple[str, dict]:
    if kind == "logon":
        return r["activity"], {}
    if kind == "device":
        return r["activity"], {}
    if kind == "http":
        host = urlparse(r["url"]).netloc.lower()
        return "visit", {"detail": host}
    if kind == "email":
        rcpt = [x.strip().lower() for x in (r.get("to", "") + ";" + r.get("cc", "") + ";" + r.get("bcc", "")).split(";")
                if x.strip()]
        external = any(not x.endswith("@" + INTERNAL_MAIL) for x in rcpt)
        return "send", {"detail": "external" if external else "internal", "bytes": int(r.get("size") or 0),
                        "attachments": int(r.get("attachments") or 0), "recipients": len(rcpt)}
    if kind == "file":
        name = r.get("filename", "")
        return "copy", {"detail": os.path.splitext(name)[1].lower() or "none"}
    return kind, {}


class CertRun(Run):
    """root: directory holding logon.csv, device.csv, http.csv, email.csv, file.csv (one CERT release)."""

    KINDS = ("logon", "device", "http", "email", "file")

    @classmethod
    def load_cert(cls, root: str, answers: str, release: str = "r4.2") -> "CertRun":
        cases = []
        for r in csv.DictReader(open(os.path.join(answers, "insiders.csv"), encoding="utf-8", errors="replace")):
            if r["dataset"].strip() != release.lstrip("r"):
                continue
            detail = glob.glob(os.path.join(answers, f"{release}-{r['scenario']}", "*" + r["user"] + "*"))
            events = []
            for path in detail:
                for line in open(path, encoding="utf-8", errors="replace"):
                    parts = line.rstrip("\n").split(",")
                    if len(parts) > 2:
                        events.append({"event_id": parts[1], "ts": parts[2], "log_source": f"ext.cert.{parts[0]}",
                                       "signal": parts[0]})
            if not events:
                continue
            first = min(_cert_ts(e["ts"]) for e in events)
            cases.append({"case_id": f"cert-{r['scenario']}-{r['user']}", "kind": "anomaly",
                          "anomaly_type": f"insider_scenario_{r['scenario']}", "mitre": [], "bundle": None,
                          "entities": {"principal": f"user:{r['user']}"}, "events": events,
                          "first_event": datetime.fromtimestamp(first, tz=timezone.utc).isoformat(), "_first": first})
        starts = []
        for k in cls.KINDS:
            with open(os.path.join(root, f"{k}.csv"), encoding="utf-8", errors="replace") as f:
                next(f)
                starts.append(_cert_ts(next(csv.reader(f))[1]))
        start = min(starts)
        end = max(c["_first"] for c in cases) + 120 * 86400 if cases else start + 500 * 86400
        run = cls(root, {"start": "", "end": ""}, {}, set(), {"days": []}, cases, [], start, end, 0.0)
        for c in cases:
            for e in c["events"]:
                run.by_event[e["event_id"]] = (c["case_id"], "anomaly")
        return run

    def events(self, sources=None):
        def read(kind):
            with open(os.path.join(self.path, f"{kind}.csv"), encoding="utf-8", errors="replace") as f:
                for r in csv.DictReader(f):
                    t = _cert_ts(r["date"])
                    action, payload = _cert_detail(kind, r)
                    yield t, {"_t": t, "_it": t, "ts": r["date"], "event_id": r["id"], "log_source": f"ext.cert.{kind}",
                              "layer": "external", "action": action, "principal": f"user:{r['user']}",
                              "device_id": r["pc"], "payload": payload}
        for _, ev in heapq.merge(*(read(k) for k in self.KINDS), key=lambda x: x[0]):
            self.end = max(self.end, ev["_t"])
            yield ev


class LanlRun(Run):
    """root: directory with auth.txt.gz and redteam.txt.gz. Times are seconds from the start of the data;
    they are mapped onto 2015-01-01 (UTC) so that hour-of-day profiles exist."""

    EPOCH = datetime(2015, 1, 1, tzinfo=timezone.utc).timestamp()

    @classmethod
    def load_lanl(cls, root: str) -> "LanlRun":
        red = set()
        cases = {}
        with gzip.open(os.path.join(root, "redteam.txt.gz"), "rt") as f:
            for line in f:
                t, user, src, dst = line.strip().split(",")
                red.add((int(t), user, src, dst))
                day = int(t) // 86400
                cid = f"lanl-{user}-d{day}"
                c = cases.setdefault(cid, {"case_id": cid, "kind": "anomaly", "anomaly_type": "red_team_auth",
                                           "mitre": ["T1078", "T1021"], "bundle": None,
                                           "entities": {"principal": f"user:{user.split('@')[0]}"}, "events": [],
                                           "_first": cls.EPOCH + int(t)})
                c["_first"] = min(c["_first"], cls.EPOCH + int(t))
        run = cls(root, {"start": "", "end": ""}, {}, set(), {"days": []}, list(cases.values()), [],
                  cls.EPOCH, cls.EPOCH + 58 * 86400, 0.0)
        run.red = red
        return run

    def events(self, sources=None):
        n = 0
        with gzip.open(os.path.join(self.path, "auth.txt.gz"), "rt") as f:
            for line in f:
                n += 1
                p = line.rstrip("\n").split(",")
                if len(p) < 9:
                    continue
                t = int(p[0])
                user = p[1].split("@")[0]
                eid = f"a{n}"
                if (t, p[1], p[3], p[4]) in self.red:
                    cid = f"lanl-{p[1]}-d{t // 86400}"
                    if cid in self._case_index:
                        self._case_index[cid]["events"].append({"event_id": eid, "log_source": "ext.lanl.auth",
                                                                "signal": "red_team_auth"})
                        self.by_event[eid] = (cid, "anomaly")
                yield {"_t": self.EPOCH + t, "_it": self.EPOCH + t, "ts": str(t), "event_id": eid,
                       "log_source": "ext.lanl.auth", "layer": "external", "action": p[7] or "auth",
                       "outcome": p[8].lower(), "principal": f"user:{user}", "device_id": p[3],
                       "host": p[4], "payload": {"detail": f"{p[5]}:{p[6]}", "dst_computer": p[4],
                                                 "dst_user": p[2].split("@")[0]}}

    @property
    def _case_index(self):
        if not hasattr(self, "_ci"):
            self._ci = {c["case_id"]: c for c in self.cases}
        return self._ci


def external_detectors(names, warmup_h):
    """The pipelines that apply to external datasets (no loggen-specific rules), with their warm-up."""
    from functools import partial

    from .detectors import PIPELINES
    from .detectors.baseline import Baselines
    from .detectors.fusion import Fusion, GraphFusion
    from .detectors.gnn import LinkGNN
    from .detectors.ml import IForest
    from .detectors.sequence import NGram
    table = {"P2": partial(Baselines, warmup_h=warmup_h), "P3": partial(IForest, warmup_h=warmup_h),
             "P4": partial(NGram, warmup_h=warmup_h), "P5": partial(GraphFusion, warmup_h=warmup_h),
             "P5-hyper": partial(GraphFusion, rarity="hyper", warmup_h=warmup_h),
             "P6": partial(Fusion, warmup_h=warmup_h), "P6-hyper": partial(Fusion, rarity="hyper", warmup_h=warmup_h),
             "P6+P4": partial(Fusion, extra=("P4",), rarity="hyper", distinct="detectors", warmup_h=warmup_h),
             "P10": partial(LinkGNN, warmup_h=warmup_h),
             "P6-hyper+P10": partial(Fusion, extra=("P10",), rarity="hyper", warmup_h=warmup_h)}
    dets = []
    for n in names:
        d = (table.get(n) or PIPELINES[n])()
        d.name = n
        dets.append(d)
    return dets


class TcRun(Run):
    """DARPA TC Engagement 3, one host (CADETS), as prepared by modal_apps/tc_f4.py::prepare.

    Each CDM Event becomes one envelope event: principal = the executable ("exe:<name>", the identity whose
    behaviour is baselined), task = the process instance (subject UUID), device_id = the object it acts on,
    generalised (file path with digits folded, remote address:port, or the child process name), action = the
    CDM event type.

    Ground truth (cases="windows", default): one case per attack in the TC E3 ground-truth report (CADETS:
    four Nginx/Drakon sessions and one phishing run through the host's postfix; report times are EDT, UTC-4;
    each window lasts 3 h from the reported start). An event belongs to the case if it falls in the window and
    touches a ThreaTrace-labelled node first seen inside that window: the attacker's new processes, files and
    connections. Labelled nodes that exist before the window (long-lived daemons and files, active every hour)
    do not make an event malicious. cases="days" keeps the first, noisier definition (any event touching a
    labelled node, one case per day)."""

    import re as _re
    _NUM = _re.compile(r"\d+")
    _HEX = _re.compile(r"[0-9a-f]{8,}")
    WINDOWS = [("2018-04-06T15:00:00", "nginx_drakon_1"), ("2018-04-06T19:00:00", "postfix_phishing"),
               ("2018-04-11T19:00:00", "nginx_drakon_2"), ("2018-04-12T18:00:00", "nginx_drakon_3"),
               ("2018-04-13T13:00:00", "nginx_drakon_4")]
    WINDOW_S = 3 * 3600

    @classmethod
    def load_tc(cls, root: str, labels: str, cases: str = "windows") -> "TcRun":
        import json
        ents = json.load(open(os.path.join(root, "entities.json"), encoding="utf-8"))
        stats = json.load(open(os.path.join(root, "stats.json"), encoding="utf-8"))
        start, end = stats["first_ns"] / 1e9, stats["last_ns"] / 1e9
        run = cls(root, {"start": "", "end": ""}, {}, set(), {"days": []}, [], [], start, end, 0.0)
        run.bad = {x.strip() for x in open(labels, encoding="utf-8") if x.strip()}
        run.subjects, run.netflows = ents["subjects"], ents["netflows"]
        run.mode = cases
        run.windows = [(datetime.fromisoformat(w).replace(tzinfo=timezone.utc).timestamp(), name)
                       for w, name in cls.WINDOWS]
        return run

    def _gen(self, path: str) -> str:
        return self._NUM.sub("N", self._HEX.sub("H", path.lower()))[:160]

    def _obj(self, obj: str, path: str) -> tuple[str, str | None]:
        nf = self.netflows.get(obj)
        if nf:
            return f"net:{nf[0]}:{nf[1]}", nf[0]
        if path:
            return f"file:{self._gen(path)}", None
        s = self.subjects.get(obj)
        if s:
            return f"proc:{s.get('name') or '?'}", None
        return "", None

    def events(self, sources=None):
        cases = {}
        first_bad: dict[str, float] = {}
        self.first_bad = first_bad  # labelled node -> first time seen (complete after the replay)
        n = 0
        with gzip.open(os.path.join(self.path, "events.tsv.gz"), "rt", encoding="utf-8") as f:
            for line in f:
                p = line.rstrip("\n").split("\t")
                if len(p) < 9:
                    continue
                n += 1
                ts, typ, subj, obj, obj2, exe, path, path2, _uuid = p
                t = int(ts) / 1e9
                if t <= 0:
                    continue
                eid = f"t{n}"
                labelled = [x for x in (subj, obj, obj2) if x and x in self.bad]
                cid = atype = None
                if labelled and getattr(self, "mode", "windows") == "days":
                    cid, atype = f"tc-cadets-d{int(t // 86400)}", "tc_e3_attack"
                elif labelled:
                    for x in labelled:
                        first_bad.setdefault(x, t)
                    for w0, name in self.windows:
                        if w0 <= t < w0 + self.WINDOW_S and any(w0 <= first_bad[x] < w0 + self.WINDOW_S
                                                                for x in labelled):
                            cid, atype = f"tc-cadets-{name}", name
                            break
                if cid:
                    c = cases.get(cid)
                    if c is None:
                        c = cases[cid] = {"case_id": cid, "kind": "anomaly", "anomaly_type": atype,
                                          "mitre": [], "bundle": None, "entities": {"principal": ""},
                                          "events": [], "_first": t}
                        self.cases.append(c)
                    c["events"].append({"event_id": eid, "log_source": "ext.tc.cadets", "signal": atype})
                    self.by_event[eid] = (cid, "anomaly")
                exe = exe or (self.subjects.get(subj) or {}).get("name") or "?"
                detail, host = self._obj(obj, path)
                self.end = max(self.end, t)
                yield {"_t": t, "_it": t, "ts": ts, "event_id": eid, "log_source": "ext.tc.cadets",
                       "layer": "external", "action": typ.replace("EVENT_", ""), "outcome": "",
                       "principal": f"exe:{exe}", "task": subj, "device_id": detail or None, "host": host,
                       "payload": {"detail": detail}}

    def attack_nodes(self) -> set:
        """Labelled nodes first seen inside an attack window (windows mode): the attacker's own nodes."""
        return {x for x, t in getattr(self, "first_bad", {}).items()
                if any(w0 <= t < w0 + self.WINDOW_S for w0, _ in self.windows)}

    def bad_seen_after(self, t0: float) -> set:
        """Labelled nodes that appear in at least one event at or after t0 (the node-level recall base)."""
        seen = set()
        with gzip.open(os.path.join(self.path, "events.tsv.gz"), "rt", encoding="utf-8") as f:
            for line in f:
                p = line.rstrip("\n").split("\t")
                if len(p) < 9 or int(p[0]) / 1e9 < t0:
                    continue
                for x in (p[2], p[3], p[4]):
                    if x and x in self.bad:
                        seen.add(x)
        return seen

    def nodes_of(self, eids: set) -> dict:
        """Second pass: the CDM nodes (subject, object, object2) behind the given event ids."""
        out, n = {}, 0
        with gzip.open(os.path.join(self.path, "events.tsv.gz"), "rt", encoding="utf-8") as f:
            for line in f:
                p = line.rstrip("\n").split("\t")
                if len(p) < 9:
                    continue
                n += 1
                if f"t{n}" in eids:
                    out[f"t{n}"] = [x for x in (p[2], p[3], p[4]) if x]
        return out
