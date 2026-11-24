"""Every experiment of the preprint, with what it needs. `python -m bench list` shows status."""
from __future__ import annotations

from .detectors import PIPELINES

ALL_P = "P0,P1,P2,P3,P4,P5,P6,P7,P8,P9"
CLASSIC = "P0,P1,P2"


def E(id, title, pipelines, gen="", metrics="", needs=""):
    return {"id": id, "title": title, "pipelines": pipelines.split(",") if pipelines else [], "gen": gen,
            "metrics": metrics, "needs": [n for n in needs.split(",") if n]}


EXPERIMENTS = [
    # A. Data validity
    E("A1", "Realism: generator distributions vs public data", "", "--duration 7d",
      "KS distance per feature", "data:google-cluster-2019,data:lanl-2015,data:cert-r4.2"),
    E("A2", "Shortcut audit: can a trivial model find anomalies from generator artefacts?", "",
      "--duration 2d --inline-labels", "AUC of field-presence / token classifier", "tool:shortcut-audit"),
    E("A3", "Variance across seeds", ALL_P, "--seed 1..10", "mean ± 95% CI of every headline metric"),
    E("A4", "Unseen anomaly types (train/tune on half, test on the other half)", ALL_P,
      "--anomaly-types <half> / <other half>", "recall on held-out types"),
    E("A5", "External validity on public labeled data", ALL_P, "",
      "same metrics on LANL / CERT / DARPA TC-OpTC", "data:lanl-2015,data:cert-r4.2,data:darpa-tc"),
    # B. Detection quality matrix
    E("B1", "Humans (UEBA): detection per pipeline", ALL_P, "--duration 2d --lag",
      "precision, recall_by_family.ueba, FP/day, look-alike FP, TTD"),
    E("B2", "Non-human identities: detection per pipeline", ALL_P, "--duration 2d --lag", "same, family nhi"),
    E("B3", "Code & process runtime: detection per pipeline", ALL_P, "--duration 2d --lag", "same, family runtime"),
    E("B4", "Value of context (inventory, on-call, build registry)", "P0,P1,P6,P8", "--duration 2d",
      "FP/day removed by enrichment at equal recall"),
    E("B5", "Best-per-family mix vs one technique everywhere", ALL_P, "--duration 2d --lag", "recall @ 10 FP/day"),
    # C. Latency & throughput
    E("C1", "End-to-end detection delay under load", ALL_P, "--duration 1d --lag",
      "detection_delay p50/p99 at speed 1, 10, 100, 1000"),
    E("C2", "Per-stage latency waterfall (extraction <5 ms, MalConv <50 ms, sandbox, LLM)", "P7,P8,P9", "--raw",
      "per-stage p50/p95/p99", "P7,P8"),
    E("C3", "Aggregation window size vs time to detect and precision", "P2,P6", "--duration 2d",
      "TTD and precision for 1/5/15-minute windows", "gen:window-size"),
    E("C4", "Streaming vs micro-batch vs hourly batch, same detector", CLASSIC, "--duration 2d --lag",
      "TTD, cost", "tool:batch-runner"),
    E("C5", "Throughput ceiling and cost per million events", ALL_P, "--scale 1..10", "events/s, $/1M events"),
    E("C6", "Cascade funnel: share of events reaching each stage, cost and latency", "P9", "--duration 2d",
      "funnel %, cumulative latency, $/day", "P9"),
    E("C7", "Late and out-of-order data", CLASSIC, "--lag vs no --lag, --drop-rate 0..0.05", "recall, TTD"),
    E("C8", "Overload: block, queue or drop? Host-side cost", CLASSIC, "--duration 6h",
      "queue growth vs speed, enqueue overhead"),
    E("C9", "Graph update and k-hop query latency as the graph grows (1 to 30 days)", "P5", "--duration 30d",
      "update/query p95 vs graph size", "P5"),
    # D. MalConv & binary ML
    E("D1", "MalConv vs MalConv2 vs GBDT (EMBER features) vs byte-histogram LR", "P7", "",
      "AUC, TPR@FPR 1e-3/1e-4, CPU/GPU latency, memory", "P7,data:ember,data:sorel-20m,gpu"),
    E("D2", "Pre-filter threshold sweep: share sent to sandbox vs missed malware (~90/10 claim)", "P7", "",
      "sandbox share, miss rate", "P7,data:sorel-20m"),
    E("D3", "Temporal drift: train on older months, test on newer", "P7", "", "AUC decay per month",
      "P7,data:bodmas,data:sorel-20m"),
    E("D4", "Robustness to published evasions (padding, header edits)", "P7", "",
      "evasion success rate per model", "P7,data:sorel-20m,tool:secml-malware"),
    E("D5", "PE -> ELF / Mach-O transfer", "P7", "", "AUC on ELF corpus", "P7,data:elf-corpus"),
    E("D6", "Marginal value of the MalConv score inside fusion / LLM", "P6,P7,P8", "--binary-corpus",
      "recall@budget with vs without score", "P6,P7,P8"),
    E("D7", "Explainability: which bytes drive the score", "P7", "", "attribution concentration (header vs body)",
      "P7"),
    # E. Signal fusion
    E("E1", "Weak-signal bundles: fusion vs single-signal alerting", "P0,P1,P2,P6", "--bundles 20 --bundle-intensity 0.3",
      "bundle_recall at equal FP/day"),
    E("E2", "Fusion methods: sum, noisy-OR, Bayesian network, stacking, risk-based alerting", "P6",
      "--bundles 20", "recall@budget, AP", "P6"),
    E("E3", "Score calibration", "P3,P6,P8", "", "Brier score, reliability", "P6"),
    E("E4", "Risk half-life and accumulation window sensitivity", "P6", "--bundles 20", "recall@budget vs half-life",
      "P6"),
    E("E5", "Imperfect identity stitching (drop 5-30% of correlation keys)", "P5,P6", "--drop-keys",
      "recall vs key loss", "P5,P6,gen:drop-keys"),
    E("E6", "Minimum detectable effect: intensity sweep", ALL_P, "--intensity 0.1..1.0", "recall vs intensity"),
    # F. Causal graphs
    E("F1", "Flat logs vs graph-neighbourhood features", "P3,P5", "", "recall@budget lift", "P3,P5"),
    E("F2", "Graph construction choices (edge types, with/without traces)", "P5", "", "recall@budget", "P5"),
    E("F3", "Sampling blind spot: Dapper 1/1024 vs unsampled edge log vs adaptive", "P2,P5",
      "--sources ablation", "recall on new_rpc_edge, cost"),
    E("F4", "Graph methods: edge novelty, rare paths, GNN embeddings, StreamSpot/UNICORN/KAIROS", "P5", "",
      "recall@budget, AP", "P5,data:darpa-tc"),
    E("F5", "Investigation completeness: does the graph retrieve all of a case's events?", "P5,P8", "",
      "case event recall", "P5"),
    # G. Dynamic reasoning (LLM)
    E("G1", "LLM triage of P5/P6 alerts: FP removed on benign look-alikes, TP kept", "P8", "",
      "precision gain at equal recall", "P8,llm"),
    E("G2", "Context ablation for the LLM", "P8", "", "triage accuracy per context set", "P8,llm"),
    E("G3", "Agent with tools vs single prompt with pre-collected context", "P8", "",
      "accuracy, latency, tokens, tool calls", "P8,llm"),
    E("G4", "Model size and deployment (small/large, local/API)", "P8", "", "accuracy, p95 latency, $/case",
      "P8,llm"),
    E("G5", "Evidence quality: cited event_ids vs ground truth, hallucinated evidence", "P8", "",
      "evidence precision/recall", "P8,llm"),
    E("G6", "Run-to-run stability", "P8", "", "agreement rate", "P8,llm"),
    E("G7", "Confidence calibration", "P8", "", "Brier, reliability", "P8,llm"),
    E("G8", "Prompt injection via attacker-controlled fields, with and without harness", "P8",
      "--injection-rate 0.3", "policy violation rate", "P8,llm"),
    E("G9", "Harness: unsafe automatic actions blocked, human review load", "P8", "", "blocked actions, reviews/day",
      "P8,llm"),
    # H. Continuous validation & signal engineering
    E("H1", "Nightly regression of detections", ALL_P, "--seed $(date)", "recall per type over versions"),
    E("H2", "Source ablation: value of each log source vs its volume", CLASSIC, "--duration 2d",
      "recall drop per removed source, events/day per source"),
    E("H3", "ATT&CK coverage per pipeline", ALL_P, "", "techniques detected / injected"),
    E("H4", "Baseline drift: launch, reorg, holiday", ALL_P, "--drift launch@26h,reorg@30h,holiday@40h+8h",
      "FP spike and recovery time"),
    # I. Response
    E("I1", "Time to contain: automatic vs human in the loop", "P8,P9", "", "time to contain", "P8,tool:response-sim"),
    E("I2", "Collateral damage of automatic actions on benign look-alikes", "P8,P9", "", "wrongful actions/day",
      "P8,tool:response-sim"),
]


def status(exp: dict) -> str:
    missing = [n for n in exp["needs"] if n.startswith("P") and n not in PIPELINES] + \
              [n for n in exp["needs"] if not n.startswith("P")]
    usable = [p for p in exp["pipelines"] if p in PIPELINES]
    if missing:
        return "needs " + ", ".join(missing)
    if exp["pipelines"] and len(usable) < len(exp["pipelines"]):
        return f"partial ({','.join(usable)} ready)"
    return "ready"
