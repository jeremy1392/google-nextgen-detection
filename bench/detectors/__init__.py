"""Pipelines under test. Each entry builds a fresh detector instance."""
from __future__ import annotations

from functools import partial

from .agent import AgentTriage
from .baseline import Baselines
from .fusion import Fusion, GraphFusion
from .llm_triage import Cascade, GraphCascade, LLMTriage
from .ml import IForest
from .mix import Mix
from .rules import Correlation, StaticRules, TunedCorrelation
from .sequence import NGram
from .gnn import LinkGNN
from .static import StaticScan

PIPELINES = {
    "P0": StaticRules,                       # static rules, one event at a time
    "P1": Correlation,                       # + lookup tables and windowed correlation
    "P2": Baselines,                         # per-entity novelty and seasonal z-scores
    "P3": IForest,                           # Isolation Forest on per-entity hourly windows
    "P4": NGram,                             # n-gram next-event model per entity (DeepLog-style top-g)
    "P5": GraphFusion,                       # risk fusion over the causal / identity graph
    "P6": Fusion,                            # probabilistic fusion (noisy-OR, rarity-weighted)
    "P6-sum": partial(Fusion, method="sum"),  # E2: risk-based alerting (additive)
    "P6-max": partial(Fusion, method="max"),  # E2: single-signal baseline with the same weights
    # Mixes: ML / sequence detectors as extra weak signals. "naive" keeps the default calibration;
    # the others weigh noisy rules harder and require two independent detectors to agree.
    "P6+P4-naive": partial(Fusion, extra=("P4",)),
    "P6+P4": partial(Fusion, extra=("P4",), rarity="hyper", distinct="detectors"),
    "P6+P3+P4": partial(Fusion, extra=("P3", "P4"), rarity="hyper", distinct="detectors"),
    "P5+P4": partial(GraphFusion, extra=("P4",), rarity="hyper", distinct="detectors"),
    "P6-hyper": partial(Fusion, rarity="hyper"),       # E2: rarity weighting ablation
    "P6-indep": partial(Fusion, distinct="detectors"),  # E2: corroboration by independent detectors
    # E4: risk half-life of the best fusion variant
    **{f"P6-hyper-hl{h}": partial(Fusion, rarity="hyper", half_life_h=float(h)) for h in (1, 3, 12, 24)},
    # F2: graph construction and propagation choices
    "P5-damp0.2": partial(GraphFusion, damp=0.2), "P5-damp0.6": partial(GraphFusion, damp=0.6),
    "P5-hub50": partial(GraphFusion, hub=50), "P5-hub500": partial(GraphFusion, hub=500),
    "P5-identity-only": partial(GraphFusion, extra_edges=False),
    "P5-hyper": partial(GraphFusion, rarity="hyper"),
    "P8": LLMTriage,                         # P6 + LLM triage of every fused alert
    "P9": Cascade,                           # fast path for rare severe signals, LLM for the rest
    "P8-g4": partial(LLMTriage, model="google/gemini-4-hydrogen", reasoning="low"),  # G4: fastest Gemini 4
    "P9-g4": partial(Cascade, model="google/gemini-4-hydrogen", reasoning="low"),
    "P8-sync": partial(LLMTriage, async_llm=False),  # C2/C6: LLM call blocking the stream
    "P8-noctx": partial(LLMTriage, use_context=False),  # G2: no inventory / on-call / service context
    "P8-harness": partial(LLMTriage, harness=True),     # G9: deterministic policy over the model
    "P8-rep": LLMTriage,                                # G6: same configuration, run again
    "P9-harness": partial(Cascade, harness=True),
    # The recommended configuration: fast path + tuned context rules, baselines, sequences + rarity-weighted graph
    # fusion + Gemini triage behind the harness (FINAL-nollm: the same without the model)
    "FINAL": GraphCascade,
    "FINAL-g4": partial(GraphCascade, model="google/gemini-4-hydrogen", reasoning="low"),
    "FINAL-nollm": partial(GraphCascade, max_calls=0),
    # closing the single-log exfiltration gap: volume baselines on Spanner, Bigtable and B4 (hourly or flat)
    "P2-vol": partial(Baselines, volume="hourly"),
    "P2-volflat": partial(Baselines, volume="flat"),
    "FINAL-vol-nollm": partial(GraphCascade, max_calls=0, volume="hourly"),
    "FINAL-volflat-nollm": partial(GraphCascade, max_calls=0, volume="flat"),
    "FINAL-vol-g4": partial(GraphCascade, model="google/gemini-4-hydrogen", reasoning="low", volume="hourly"),
    # the same pipeline with the fine-tuned local model (G10) in the last seat; prompts recorded and answered in batch
    # on a GPU (BENCH_LLM_RECORD / BENCH_LLM_REPLAY, bench/llm.py)
    "FINAL-local": partial(GraphCascade, model="local/qwen3-4b-sft-grpo"),
    # ablation of FINAL on the same alerts (answers recorded / replayed): what each design choice adds
    "ABL-graph+model": partial(GraphCascade, model="local/ablation", policy=False, fast=False, harness=False),
    "ABL-graph+model+harness": partial(GraphCascade, model="local/ablation", policy=False, fast=False, harness=True),
    "ABL-graph+model+harness+fast": partial(GraphCascade, model="local/ablation", policy=False, fast=True, harness=True),
    "ABL-FINAL": partial(GraphCascade, model="local/ablation", policy=True, fast=True, harness=True),
    "MIX": Mix,                                         # B5: severe runtime rules + P6-hyper for behaviour
    "P1-tuned": TunedCorrelation,                       # P1 with exceptions learned in the warm-up (SOC tuning)
    "MIX-tuned": partial(Mix, tuned=True),              # B5 with SOC-tuned rules
    "P6-hyper-tuned": partial(Fusion, rarity="hyper", tuned_rules=True),
    "P5-hyper-tuned": partial(GraphFusion, rarity="hyper", tuned_rules=True),
    "P8-agent": AgentTriage,                            # G3: agent investigating with tools
    "P8-agent-g4": partial(AgentTriage, model="google/gemini-4-hydrogen", reasoning="low"),
    "P8-agent-nocap": partial(AgentTriage, max_calls=3000),  # G3 without the call budget confound
    # D6: the static binary classifier alone, and as one more signal in fusion and in LLM triage
    "P7": StaticScan,                                   # MalConv score > threshold at 0.1% FPR
    "P7-1e-2": partial(StaticScan, fpr=1e-2),
    "P6-hyper+P7": partial(Fusion, extra=("P7",), rarity="hyper"),
    "MIX-tuned+P7": partial(Mix, tuned=True, extra=("P7",)),
    "MIX-tuned+P7direct": partial(Mix, tuned=True, direct=("P7",)),  # confident static verdicts alert directly
    "P8+P7": partial(LLMTriage, extra=("P7",)),
    # F6: temporal link prediction GNN (GraphSAGE on the warm-up interaction graph), alone and inside fusion
    "P10": LinkGNN,
    "P10-q0.5": partial(LinkGNN, alert_share=0.005),
    "P10-q10": partial(LinkGNN, alert_share=0.10),
    "P6-hyper+P10": partial(Fusion, extra=("P10",), rarity="hyper"),
    "MIX-tuned+P10": partial(Mix, tuned=True, extra=("P10",)),
    "P5-hyper+P10": partial(GraphFusion, extra=("P10",), rarity="hyper"),
}
LLM_PIPELINES = {"FINAL", "FINAL-g4", "FINAL-local", "P8", "P9", "P8-g4", "P9-g4", "P8-sync", "P8-noctx", "P8-harness", "P8-rep", "P9-harness",
                 "P8-agent", "P8-agent-g4", "P8-agent-nocap", "FINAL-vol-g4", "ABL-graph+model", "ABL-graph+model+harness",
                 "ABL-graph+model+harness+fast", "ABL-FINAL"}
