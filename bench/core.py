"""Bench core: load a loggen run, replay it through detectors in arrival order, time them.

Detectors see events in ingest order (when the run has --lag), exactly like a streaming
pipeline would. Each detector is timed per event; a single-server queue model turns those
timings into detection delay at a given replay speed, without having to sleep.
"""
from __future__ import annotations

import heapq
import json
import os
import time
from array import array
from dataclasses import dataclass, field
from datetime import datetime


def epoch(text: str) -> float:
    return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()


@dataclass
class Alert:
    detector: str
    rule: str
    entity: str
    score: float
    evidence: list            # event_ids that justify the alert
    family: str | None = None
    t_detect: float = 0.0     # simulated time the alert is available (set by replay)
    delay_s: float = 0.0      # extra delay off the critical path (async LLM call), added by replay


class Detector:
    """Interface: process() sees every event once, in arrival order; finish() flushes windows."""
    name = "base"
    pipeline = "P?"

    def setup(self, run: "Run") -> None:
        pass

    def process(self, ev: dict) -> list[Alert] | None:
        raise NotImplementedError

    def finish(self) -> list[Alert] | None:
        return None


@dataclass
class Run:
    path: str
    manifest: dict
    inventory: dict
    builds: set
    oncall: dict
    cases: list               # anomaly cases
    benign: list              # benign look-alike cases
    start: float = 0.0
    end: float = 0.0
    tz: float = 3600.0
    by_event: dict = field(default_factory=dict)   # event_id -> (case_id, kind)
    dropped: frozenset = frozenset()                # B4: context tables withheld from the detectors

    @classmethod
    def load(cls, path: str, drop_context=None) -> "Run":
        """drop_context (B4): any of inventory, oncall, builds; default from BENCH_DROP_CONTEXT (comma list)."""
        def jl(name):
            p = os.path.join(path, name)
            return [json.loads(x) for x in open(p, encoding="utf-8")] if os.path.exists(p) else []

        def js(name, default):
            p = os.path.join(path, "context", name)
            return json.load(open(p, encoding="utf-8")) if os.path.exists(p) else default

        m = json.load(open(os.path.join(path, "manifest.json"), encoding="utf-8"))
        run = cls(path, m, js("inventory.json", {}), {b["bcid"] for b in js("builds.json", {"builds": []})["builds"]},
                  js("oncall.json", {"days": []}), jl("ground_truth.jsonl"), jl("benign_cases.jsonl"),
                  epoch(m["start"]), epoch(m["end"]), m.get("tz_offset_h", 1.0) * 3600)
        if drop_context is None:
            drop_context = [x for x in os.environ.get("BENCH_DROP_CONTEXT", "").split(",") if x]
        run.dropped = frozenset(drop_context)
        unknown = run.dropped - {"inventory", "oncall", "builds"}
        assert not unknown, f"unknown context table(s): {sorted(unknown)}"
        if "inventory" in run.dropped:
            run.inventory = {}
        if "oncall" in run.dropped:
            run.oncall = {"days": []}
        if "builds" in run.dropped:
            run.builds = set()
        for kind, cases in (("anomaly", run.cases), ("benign", run.benign)):
            for c in cases:
                c["_first"] = epoch(c["first_event"])
                for e in c["events"]:
                    run.by_event[e["event_id"]] = (c["case_id"], kind)
        return run

    def local_hour(self, t: float) -> float:
        return ((t + self.tz) % 86400) / 3600

    def oncall_principals(self, t: float) -> set:
        day = None
        for d in self.oncall.get("days", []):
            if epoch(d["local_day_start"]) <= t:
                day = d
        return set(day["oncall"].values()) if day else set()

    def events(self, sources: list[str] | None = None):
        """All events, in arrival order. Adds _t (event time) and _it (arrival time) as floats."""
        from fnmatch import fnmatch
        logs = os.path.join(self.path, "logs")
        files = sorted(f for f in os.listdir(logs) if f.endswith(".jsonl")
                       and (not sources or any(fnmatch(f[:-6], p) for p in sources)))

        def read(name):
            with open(os.path.join(logs, name), encoding="utf-8") as fh:
                for line in fh:
                    yield json.loads(line)

        merged = heapq.merge(*(read(f) for f in files), key=lambda e: e["ts"])
        pending: list = []
        seq = 0
        for ev in merged:
            ev["_t"] = epoch(ev["ts"])
            ev["_it"] = epoch(ev["ingest_ts"]) if "ingest_ts" in ev else ev["_t"]
            heapq.heappush(pending, (ev["_it"], seq, ev))
            seq += 1
            # Anything that arrived before this event's own time can no longer be overtaken.
            while pending and pending[0][0] <= ev["_t"]:
                yield heapq.heappop(pending)[2]
        while pending:
            yield heapq.heappop(pending)[2]


@dataclass
class Timing:
    lat: array = field(default_factory=lambda: array("f"))  # float32: 4 bytes per event (LANL: 1e9 events)
    busy_until: float = 0.0
    queue: array = field(default_factory=lambda: array("d"))
    dropped: int = 0                 # C8: events refused under the drop / shed policies
    peak_backlog_s: float = 0.0      # C8: longest wait in the queue (simulated seconds)
    peak_backlog_events: int = 0     # C8: most events waiting at once (what hosts or the broker must buffer)
    finish: object = None            # C8: finish times of the events still in the system


def replay(run: Run, detectors: list[Detector], *, speed: float = 1.0, sources: list[str] | None = None,
           eval_from: float | None = None, overload: str = "queue", max_delay_s: float | None = None,
           shed_sources: set | None = None) -> tuple[dict, dict]:
    """Returns ({detector: [alerts]}, {detector: Timing}). speed = simulated seconds per wall second.

    Each detector is a single FIFO server fed at the events' arrival times. overload (C8) says what happens
    when the wait would exceed max_delay_s simulated seconds: "queue" (block / back-pressure: everything is
    kept and waits), "drop" (the arriving event is refused), "shed" (refuse only events from shed_sources,
    the low-value ones; the rest still waits)."""
    from collections import deque
    assert overload in ("queue", "drop", "shed"), overload
    for d in detectors:
        d.setup(run)
    alerts = {d.name: [] for d in detectors}
    timing = {d.name: Timing() for d in detectors}
    for tm in timing.values():
        tm.finish = deque()
    n = 0
    wall0 = time.perf_counter()
    for ev in run.events(sources):
        n += 1
        arrival = (ev["_it"] - run.start) / speed
        for d in detectors:
            tm = timing[d.name]
            fin = tm.finish
            while fin and fin[0] <= arrival:
                fin.popleft()
            wait = max(tm.busy_until - arrival, 0.0) * speed
            if overload != "queue" and max_delay_s is not None and wait > max_delay_s and (
                    overload == "drop" or ev["log_source"] in (shed_sources or ())):
                tm.dropped += 1
                continue
            if wait > tm.peak_backlog_s:
                tm.peak_backlog_s = wait
            if len(fin) > tm.peak_backlog_events:
                tm.peak_backlog_events = len(fin)
            t0 = time.perf_counter()
            out = d.process(ev)
            dt = time.perf_counter() - t0
            off = getattr(d, "offload_s", 0.0)  # time spent in async work (LLM calls): not blocking
            if off:
                d.offload_s = 0.0
                dt = max(dt - off, 0.0)
            tm.lat.append(dt)
            tm.busy_until = max(tm.busy_until, arrival) + dt
            fin.append(tm.busy_until)
            delay = (tm.busy_until - arrival) * speed  # waiting + processing, in simulated seconds
            if n % 50 == 0:
                tm.queue.append(delay)
            if out:
                for a in out:
                    a.t_detect = ev["_it"] + delay + a.delay_s
                alerts[d.name].extend(out)
    for d in detectors:
        out = d.finish()
        if out:
            for a in out:
                a.t_detect = a.t_detect or run.end
            alerts[d.name].extend(out)
    for tm in timing.values():
        tm.finish = None
    timing["_events"] = n
    timing["_wall_s"] = time.perf_counter() - wall0
    return alerts, timing
