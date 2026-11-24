"""G10 data: every alert P8 would send to the LLM, with what a verifier needs to reward an answer.

    python -m bench.g10_data build [--train 101-110] [--test 7,8,9] [--workers 6]
    -> experiments/g10/{train,test}.jsonl  (one triage case per line)

Each line: the exact user message P8 sends (alert, context, evidence events, compacted as in P8), the system
prompt, and the labels: kind (anomaly / benign look-alike / other), the anomaly type, the event ids of the
case inside the evidence (the evidence a correct answer should cite), and every evidence id shown (a cited id
outside this set is hallucinated). Datasets use the G-series settings (2 days, lag, weak-signal bundles,
benign drift); train and test seeds never overlap. No LLM is called here.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from concurrent.futures import ProcessPoolExecutor

OUT = "experiments/g10"
CACHE = "experiments/cache_g10"
GEN = ["--duration", "2d", "--bundles", "12", "--bundle-intensity", "0.3", "--lag",
       "--drift", "launch@26h,reorg@30h,holiday@40h+8h"]


def _seeds(spec: str) -> list[int]:
    out = []
    for part in spec.split(","):
        if "-" in part:
            a, b = part.split("-")
            out += list(range(int(a), int(b) + 1))
        elif part:
            out.append(int(part))
    return out


def record(seed: int, split: str) -> list[dict]:
    from loggen.cli import main as loggen_main
    from loggen.engine import parse_duration

    from .core import Run, replay
    from .detectors.llm_triage import SYSTEM, LLMTriage
    path = os.path.join(CACHE, f"s{seed}") if split == "train" else os.path.join("experiments/cache_g11", f"s{seed}")
    if not os.path.exists(os.path.join(path, "manifest.json")):
        loggen_main(["--out", path, "--seed", str(seed), *GEN])
    run = Run.load(path)
    eval_from = run.start + parse_duration("12h")
    rows = []

    class Recorder(LLMTriage):
        def triage(self, alert, t):
            self.stats["fused"] += 1
            if t < eval_from:
                return alert
            ev = [self.events[e] for e in alert.evidence if e in self.events][-25:]
            hits = {run.by_event.get(e["event_id"]) for e in ev} - {None}
            anomaly = sorted({c for c, k in hits if k == "anomaly"})
            benign = sorted({c for c, k in hits if k == "benign"})
            kind = "anomaly" if anomaly else ("benign_lookalike" if benign else "other_fp")
            case_events = [e["event_id"] for e in ev if (run.by_event.get(e["event_id"]) or (None, None))[1] == "anomaly"]
            atype = next((c["anomaly_type"] for c in run.cases if anomaly and c["case_id"] == anomaly[0]), None)
            btype = next((c.get("benign_type") for c in run.benign if benign and c["case_id"] == benign[0]), None)
            msg = {"alert": {"entity": alert.entity, "risk": round(alert.score, 3), "rule": alert.rule},
                   "context": self._context(alert, t), "events": ev}
            rows.append({"id": f"s{seed}:{len(rows)}", "seed": seed, "split": split, "kind": kind,
                         "anomaly_type": atype, "benign_type": btype, "case_ids": anomaly or benign,
                         "alert_risk": round(alert.score, 3), "case_event_ids": case_events,
                         "shown_event_ids": [e["event_id"] for e in ev], "system": SYSTEM,
                         "user": json.dumps(msg, separators=(",", ":"))})
            return alert

    d = Recorder()
    d.name = "P8-record"
    replay(run, [d])
    return rows


def build(train: list[int], test: list[int], workers: int) -> dict:
    os.makedirs(OUT, exist_ok=True)
    os.makedirs(CACHE, exist_ok=True)
    jobs = [(s, "train") for s in train] + [(s, "test") for s in test]
    with ProcessPoolExecutor(workers) as pool:
        results = list(pool.map(record, *zip(*jobs)))
    counts = {}
    for split in ("train", "test"):
        rows = [r for res, (_, sp) in zip(results, jobs) if sp == split for r in res]
        with open(os.path.join(OUT, f"{split}.jsonl"), "w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
        c = {}
        for r in rows:
            c[r["kind"]] = c.get(r["kind"], 0) + 1
        counts[split] = {"cases": len(rows), **c, "seeds": [s for s, sp in jobs if sp == split]}
    json.dump(counts, open(os.path.join(OUT, "counts.json"), "w"), indent=1)
    print(json.dumps(counts, indent=1), file=sys.stderr)
    return counts


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="bench.g10_data")
    sub = p.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--train", default="101-110")
    b.add_argument("--test", default="7,8,9")
    b.add_argument("--workers", type=int, default=6)
    a = p.parse_args(argv)
    build(_seeds(a.train), _seeds(a.test), a.workers)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
