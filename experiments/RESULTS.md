# Results synthesis (working document for the preprint)

Status: 2026-11-24. Numbers come from `experiments/results/*.json` and `experiments/REPORT.md`; each claim names
its file. "Pending" marks runs still in progress or waiting for a budget decision. Synthetic results are mean ±
95% CI over seeds (10 seeds for the core plan, 3 for the extra plans), scored after a 12 h warm-up.

Setup in one paragraph. A discrete-event generator (loggen v5) simulates a Borg-like fleet and its corporate
side: 35 log sources over seven layers, ~200 people, correlated identities from a person to the data a task
reads, 26 labeled anomaly types in three families (people / non-human identities / runtime code), weak-signal
bundles, and benign look-alikes (incident response, routine SRE sessions, launches, backups, profilers, new
binaries). Pipelines go from static rules (P0) to correlation (P1), per-entity baselines (P2), Isolation Forest
(P3), n-gram sequences (P4), graph fusion (P5), probabilistic fusion (P6), the static binary classifier (P7),
LLM triage (P8), and a cascade (P9). Real data: the Google 2011 cluster trace (calibration), LANL 2015 and CERT
r4.2 (external validity), 184,103 PE files (SOREL-20M malware + benign Windows binaries), 6,566 MalwareBazaar ELF
executables against 77,740 benign ELF executables from Debian, debian-ports and OpenWrt, collected for every
architecture the malware targets.

---

## RQ-A. Is the synthetic environment a valid testbed?

**A1, infrastructure side (Borg).** Calibrated on the Google 2011 trace (`A1_compare_after.json`): task
termination mix TVD 0.036, priority mix TVD 0.105, schedule events per machine-hour KS 0.078, rate ratio
simulated/real 0.93.

**A1, human side** (`A1_ueba.json`, new). Same statistics on the generator's access-proxy requests, LANL auth
(14 days, user accounts, start time unpublished so the hour profile is compared at the best circular shift) and
CERT r4.2 (logons and web requests).

| reference | hour profile JSD | weekend / weekday | machines per user-day KS | active hours per user-day KS | Gini of activity |
|---|---|---|---|---|---|
| generator (default) | - | 0.116 | - | - | 0.049 |
| generator, `--user-heterogeneity 0.8` | - | 0.121 | - | - | 0.393 |
| CERT r4.2 web requests | 0.170 | 0.048 | 0.001 | 0.373 | 0.394 |
| CERT r4.2 logons | 0.425 | 0.064 | 0.080 | 0.849 | 0.251 |
| LANL 2015 auth | 0.338 | 0.677 | 0.918 | 0.512 | 0.697 |

Reading: against the semantically closest reference (CERT web requests), the daily rhythm and the one-machine-
per-day pattern match; the default population is far more uniform than any reference (Gini 0.05). LANL differs
on every axis because its user accounts include automation (weekend ratio 0.68, most user-days on 6+ machines).
CERT is itself synthetic. Consequence: H5 below re-runs the comparison with heterogeneous people.

**A2, shortcut audit** (`A2_shortcut_audit.json`): logistic models restricted to one artefact family try to find
anomalous events. Schema-only AUC 0.61, timing 0.63, identifiers 0.50, content 0.72 overall. Several types remain
separable by content alone (that is what a detector should use), none by identifiers.

**A3, variance across seeds**: every core number is reported with its 95% CI over 10 seeds (REPORT.md).

**A4, unseen anomaly types** (`A4_unseen_types.json`): pipelines tuned on the first 13 types lose two thirds of
their recall on the 13 types never seen during tuning: P1-tuned 0.85 → 0.22, P5-hyper-tuned 0.97 → 0.30,
P6-hyper-tuned 0.90 → 0.22, MIX-tuned 0.93 → 0.26. Tuning on the anomalies you know does not transfer.

**A5, public labeled data.** CERT r4.2, 70 insider cases, 30-day warm-up (`A5_cert_r42.json`):

| pipeline | recall | precision | FP/day | recall at 10 FP/day |
|---|---|---|---|---|
| P2 baselines | 0.886 | 0.005 | 291 | 0.529 |
| P3 Isolation Forest | 0.171 | 0.007 | 23 | 0.129 |
| P4 n-gram | 1.000 | 0.001 | 12,399 | 0.014 |
| P5 graph fusion | 0.471 | 0.040 | 5.4 | 0.471 |
| P6 fusion | 0.457 | 0.116 | 1.5 | 0.457 |
| P6-hyper | 0.300 | 0.086 | 0.9 | 0.300 |
| P6+P4 | 0.271 | 0.016 | 5.7 | 0.271 |

The ordering seen on synthetic data holds on CERT: fusion keeps about half the recall of the raw baselines at
1/50 of the false positives. LANL (`A5_lanl.json`; red team, 58 days, 1,051,430,459 auth events, 7-day warm-up, 169
red-team cases scored): P2 recall 0.373 at 32,211 FP/day; P3 0.343 at 3,661; P4 0.178 at 30,186; P5-hyper 0.0 at 3.3;
P6-hyper 0.0 at 3.0. R@1 = R@10 = R@100 = 0 for every pipeline. Pass time 6,647-14,474 s per pipeline (103k-337k
events/s on one core). The fusion trade-off does not transfer to a single real log: novelty fires 32,000 times a day,
rarity weighting erases it, nothing corroborates.
LANL with the GNN (`A5_lanl_gnn.json`, non-preemptible run, 11,090 s): GraphSAGE on the first 7 days (40,957 nodes,
451,176 training edges, held-out link AUC 0.941); edge level, 511 red-team edges among 509,128 new ones: GNN AUC 0.565
(AP 0.00104), node degree 0.657 (AP 0.0014), unseen 0.372. P10 alone: 4,618 FP/day, recall 0.065 (11 cases), R@10 0.
P6-hyper+P10: 385 alerts (7.5/day), one true-positive alert whose evidence covers 19 of the 169 cases: recall 0.112 =
R@10 (P6-hyper alone: 0 at 3.0).

## RQ-B. Which technique detects what, at what false-positive cost?

Base condition, 10 seeds (REPORT.md, `suite_core_v5.json`):

| pipeline | recall | precision | FP/day | recall at 10 FP/day | people | non-human | runtime |
|---|---|---|---|---|---|---|---|
| P0 static rules | 0.727 ± 0.025 | 0.032 | 4,640 | 0 | 0.78 | 0.38 | 0.90 |
| P1 + correlation | 0.693 ± 0.025 | 0.028 | 4,310 | 0 | 0.68 | 0.38 | 0.90 |
| P2 baselines | 0.561 ± 0.032 | 0.096 | 317 | 0.065 | 0.57 | 0.38 | 0.67 |
| P3 Isolation Forest | 0.360 ± 0.059 | 0.067 | 270 | 0.026 | 0.55 | 0.22 | 0.29 |
| P4 n-gram | 0.578 ± 0.034 | 0.003 | 14,000 | 0.035 | 0.81 | 0.56 | 0.41 |
| P5 graph fusion | 0.762 ± 0.030 | 0.359 | 688 | 0.180 | 0.76 | 0.58 | 0.87 |
| P6 noisy-OR fusion | 0.619 ± 0.033 | 0.212 | 290 | 0.100 | 0.41 | 0.57 | 0.83 |
| P6-hyper | 0.623 ± 0.053 | 0.623 | 30.1 | 0.489 | 0.58 | 0.54 | 0.71 |

- Raw recall favours the classic camp (static rules find 73% of the anomalies) but at thousands of alerts a day;
  at a realistic budget of 10 FP/day, static rules find nothing and rarity-weighted fusion finds half.
- After SOC-style tuning (exceptions learned during warm-up, `suite_tuning.json`) the classic camp comes back:
  P1-tuned 0.53 recall at 10 FP/day (67 FP/day), against P6-hyper-tuned 0.66 (11 FP/day) and P5-hyper-tuned 0.70
  (17 FP/day). Fairness to the old camp matters: the gap is 13-17 points, not 49.
- B5, best per family (`suite_mixtuned.json`): severe runtime rules plus fusion for behaviour (MIX-tuned) reaches
  0.62 recall at 10 FP/day (31 FP/day); the best configuration overall is tuned graph fusion (P5-hyper-tuned, 0.70).
- Each family has a different best technique: n-grams are best on people (0.81) but unusable alone (14,000 FP/day);
  rules stay best on runtime events (0.90); graph fusion is best on non-human identities (0.58).
- **B4, value of context** (`suite_context.json`, new; same datasets, context tables withheld from the detectors,
  3 seeds). A rule that needs a table it lacks is not written (no inventory: no "device not in inventory" rule; no
  build registry: no "build not in registry" rule); without on-call data the off-hours rule loses its exception.

  | withheld | P1-tuned FP/day | P6-hyper FP/day (R@10) | MIX-tuned FP/day (R@10) | recall (all pipelines) |
  |---|---|---|---|---|
  | nothing | 67.0 | 31.0 (0.52) | 31.0 (0.62) | - |
  | inventory | 67.0 | 50.7 (0.51) | 50.7 (0.60) | unchanged |
  | on-call | 76.0 | 31.3 (0.52) | 31.3 (0.62) | P6-hyper 0.639 -> 0.632 |
  | build registry | 67.0 | 31.0 (0.52) | 31.0 (0.62) | unchanged |
  | all three | 76.0 | 51.0 (0.51) | 51.0 (0.60) | P6-hyper 0.639 -> 0.632 |

  Context buys false positives, not recall: the inventory's device -> owner links let fusion merge a person's
  device and account (-39% FP/day for P6-hyper and MIX-tuned); on-call data removes ~9 FP/day from the rules; the
  build-registry rule finds nothing the other signals miss in this generator. For the LLM, G2 below.

- **B5 on 10 seeds** (`suite_coretuned.json`, base): P1-tuned R@10 0.518 at 62.4 FP/day (recall 0.600, 350k ev/s);
  P6-hyper-tuned 0.626 at 10.8 (recall 0.631, 164k); P5-hyper-tuned 0.707 at 18.5 (recall 0.707, 95k); MIX-tuned 0.560
  at 30.4 (recall 0.667, 133k). Gap fusion vs tuned rules: 11-19 points (13-17 on the first 3 seeds).
- **Exfiltration gap, precise**: P4 sees Bigtable scans 4/10 and Spanner exports 3/15 (P6+P4: Bigtable 2/10); no
  pipeline sees a B4 replication spike; no pipeline within an alert budget sees any of the three.
- **B6, volume baselines** (`B6_volume_base.json`, 10 base worlds; `B6_volume_g_worlds.json`, the 3 2-day worlds;
  `bench/b6_volume.py`): rows read per (principal, table, clock hour) on spanner.audit / bigtable.audit, bytes per
  10-min window and flow class on net.b4; z of log10 against the same key at the same hour of day ("hourly", fallbacks:
  other hours, principal's other tables, table's other readers) or all hours ("flat"); one alert per key and hour;
  variance floor 0.002. Base worlds, inside FINAL (detection stage): 0/39 -> 29/39 (Spanner 14/15, Bigtable 8/10, B4
  7/14), recall 0.710 -> 0.798, FP/day 18.6 -> 17.4, no FP from the volume rules. Flat: 24/39 (B4 2/14), FP/day 19.4,
  10 FPs all on backup traffic in the 01:00-04:30 window. Alone (P2-vol): 33/39 (B4 11/14), 5 FPs from volume rules
  (4 on backup entities); P2-volflat 32/39, 10 FPs all in the backup window. 2-day worlds: 0/27 -> 17/27, recall
  0.607 -> 0.688, FP/day 17.8 -> 17.3; flat 14/27 (B4 0/3), 3 backup-window FPs. Written after the gap was seen.

## RQ-C. Can the pipeline meet the latency the architecture claims?

- C1/C5/C8, load (`suite_speed.json`): throughput ceilings per detector, single core: P0 1.07 M events/s, P2 473 k,
  P6-hyper 238 k, P5 93 k, P4 85 k. Detection delay p99 stays under 10 s up to 10,000x real time for P0, P2 and
  P6; P4 and P5 saturate first.
- C2, waterfall, co-located, real binaries (`C2_e2e_local_v2.json`; 4,000 SOREL / benign PE files, 16 host threads,
  Poisson arrivals, dynamic batching up to 32 files or 5 ms, GPU warmed up before measuring). On-host extraction (read,
  SHA-256, cache lookup, enqueue): p50 0.25 ms, 92-93% under 5 ms, p99 23-29 ms (the tail is the largest binaries).
  Extraction + MalConv service, share of files under 50 ms end to end:

  | files/s | L4, one padded batch | L4, length buckets | H100, one padded batch | H100, length buckets |
  |---|---|---|---|---|
  | 50 | 97.6% (p99 91 ms) | 99.3% (p99 40 ms) | 97.5% (p99 61 ms) | 99.3% (p99 46 ms) |
  | 200 | 87.2% (p99 97 ms) | 99.7% (p99 35 ms) | 99.4% (p99 45 ms) | 99.7% (p99 28 ms) |
  | 500 | saturated (p50 7.2 s) | 67.6% (p99 123 ms) | 99.1% (p99 49 ms) | 99.5% (p99 40 ms) |
  | 1,000 | saturated | saturated (p50 5.9 s) | saturated (p50 1.2 s) | 99.1% (p50 14 ms, p99 49 ms) |
  | 2,000 | saturated | saturated | saturated | saturated (p50 0.5 s) |

  Padding every file of a batch to its longest member wastes most of the GPU time: splitting each batch into four
  length buckets (64 KB, 256 KB, 1 MB, 2 MB) doubles the sustainable rate. The architecture's targets (extraction
  < 5 ms, MalConv < 50 ms) hold for >99% of files up to 1,000 new binaries/s per H100, 200 per L4. A first run
  without warm-up (`C2_e2e_local.json`) measured cold-start effects at low load (H100, 50 files/s, p95 104 ms).
- **C5, fleet scale x1 / x2 / x5 / x10** (`suite_scale.json`, `C5_cost_scale.json`, new; population and traffic
  multiplier, 3 seeds, Modal list price $0.0000131 per core-second). Per-event cost does not grow with the fleet:
  core-seconds per million events P0 1.3-1.5, P2 1.8-2.3, P6-hyper 5.2-5.5, MIX-tuned 7.1-7.6, P5-hyper 12-13,
  P4 14-19, Isolation Forest 19-23, i.e. under $0.0003 per million events for every detector. What grows is the
  alert volume of the per-signal camp (P0 4,600 -> 65,000 FP/day, P2 318 -> 2,700, P4 14,000 -> 100,000) while
  fusion keeps its volume (P6-hyper 31 -> 34 FP/day, MIX-tuned 31 -> 45) at the price of recall: MIX-tuned recall
  at 10 FP/day 0.62 / 0.55 / 0.49 / 0.32, P6-hyper 0.52 / 0.42 / 0.41 / 0.33. With a fixed analyst budget, ten
  times the background means each attack competes with ten times the noise: ranking, not compute, is what must
  scale.
- **C6, cascade funnel** (`C6_funnel.json`, new; P9 on the 2-day G-series run, ~200 people): 422,509 events/day
  -> 4,732 detector signals (1.1%) -> 85 fused alerts sent to the LLM (0.02%) + 21 rare severe signals on the fast
  path -> 21.5 (flash-lite) / 26 (Gemini 4) kept by the LLM; analysts see 42-47 alerts/day of which 2-3 are false
  positives. Latency p50: 11 µs per event in the detectors, +0.91 s (flash-lite) / +6.1 s (Gemini 4) for the LLM.
  Cost per day: detection compute $0.0001, LLM $0.067 (flash-lite, $0.0008 per call) / $0.76 (Gemini 4, $0.009
  per call). The binary path per new binary: extraction 0.25 ms p50, MalConv at capacity $1.13 (L4, 197 files/s)
  to $1.24 (H100, 883 files/s) per million binaries; sandbox: 0.9 per 1,000 new benign binaries on known
  toolchains, 299 per 1,000 on an unseen one (D2).
- **C8, overload policies** (`suite_overload.json`, `C8_host_enqueue.json`, new; each detector a FIFO server fed at
  replay speeds 10^4-3x10^5, 3 seeds; past a 60 s wait: queue everything, drop the arriving event, or shed only the
  observability layer). Diurnal peaks overload the detectors well before the average load does.

  | MIX-tuned, speed | queue: recall / delay p99 / peak backlog | drop: recall / dropped | shed: recall / delay p99 |
  |---|---|---|---|
  | 10,000x | 0.700 / 10 s / 693 events | 0.700 / 0.2% | 0.700 / 18 s |
  | 30,000x | 0.700 / 4.7 h / 89,000 | 0.687 / 25% | 0.690 / 3.8 h |
  | 100,000x | 0.700 / 85 h / 437,000 | 0.429 / 72% | 0.690 / 62 h |
  | 300,000x | 0.700 / 315 h / 563,000 | 0.263 / 92% | 0.690 / 255 h |

  Queuing (back-pressure) loses nothing but the delay grows without bound and the backlog moves to the hosts
  (563,000 events x 494 bytes ≈ 280 MB at the peak; serialising and enqueuing an event costs 7 µs p50 in Python, an
  upper bound for an agent). Dropping bounds the delay at the price of recall in proportion to what is dropped.
  Shedding the observability layer (14% of events, worth nothing measurable in H2) keeps recall but cannot bound the
  delay once the rest exceeds capacity. The policy that holds both is capacity for the peak plus shedding.
- C3, aggregation window 60-900 s (`suite_window.json`): no significant effect on P6-hyper recall or FP/day.
- C4, streaming vs batch (`suite_batch.json`): same recall; median time to detect goes from 3 s (streaming) to
  260 s (5-min batches) to 2,330 s (hourly batches) for P6-hyper.
- C7, late and lost data (`--lag --drop-rate 0.02`, REPORT.md): see the lag_drop table.
- C9, graph scaling over 30 days (`C9_graph_scaling.json`): the graph grows to 671k nodes and 1.11 M edges; per-event
  update stays at p50 6.6 µs (p99 47-75 µs) and the 2-hop query plateaus after a week (p50 93 µs on day 1, 142-153 µs
  from day 8 to day 29, p99 under 360 µs).
- G4, LLM latency (`G4_llm_speed_*.json`): fastest models answer a triage prompt in 0.65-0.7 s (2.5 flash-lite,
  3.1 flash-lite preview); Gemini 4 hydrogen with low reasoning 3.3 s. The LLM stage is three orders of
  magnitude slower than the static stages, which is why it runs off the critical path (async) on fused alerts only.

## RQ-D. What does static binary ML on real binaries actually measure?

- D1, PE, feature models (`D1_feature_models.json`, `D1_ember_group_ablation.json`): LightGBM on EMBER features,
  113,775 training files, test AUC 0.99999, TPR 0.99997 at 1e-3 FPR; byte-histogram LR AUC 0.990. Every EMBER
  feature group alone reaches AUC ≥ 0.998: the benign Windows corpus (open-source toolchains) is separable from
  SOREL malware by almost anything. Absolute D-series AUCs measure corpus separability, not real-world difficulty
  (Arp et al. 2022).
- **D1, MalConv** (`D1_malconv_report.json`; raw bytes, first 2 MB, 6 epochs on an A100, best epoch 3 by validation
  AUC 0.99996). Test (newest SOREL months against held-out benign files of the training toolchains, 29,992 / 13,423):
  AUC 0.999993, TPR 0.9992 [0.9988, 0.9995] at 1e-3 FPR, 0.9875 at 1e-4. Against benign software from a toolchain
  never seen in training (MSVC-built: embedded Python, .NET, PowerShell; 3,634 files): AUC 0.958 and TPR 0 at every
  FPR target from 1e-2 down, because more than 1% of these benign files score exactly 1.0 (18% score ≥ 0.999).
  LightGBM on EMBER features keeps AUC 0.9996 and TPR 0.992 on the same unseen-toolchain set: structural PE features
  transfer across toolchains, raw bytes do not. MalConv learned the toolchain as much as the maliciousness.
- **D1, MalConv2** (`D1_malconv2.json`, new; MalConvGCT re-implemented after the authors' reference code: 256 channels,
  256-byte windows, stride 64, global channel gating, fixed-memory temporal max-pooling over whole files up to 64 MB; same
  splits; 4 epochs on an A100, ~17 min each; best epoch 3, val AUC 0.99999). Known toolchains: AUC 0.999993, TPR 1.0 /
  0.9988 [0.9983, 0.9992] / 0.9954 at 1e-2 / 1e-3 / 1e-4 FPR (MalConv: 0.9992 and 0.9875 at 1e-3 and 1e-4); 6,956 test
  files over 2 MB, AUC 0.99994 on them. Unseen toolchain (MSVC): AUC 0.947 (MalConv 0.958), TPR 0.215 at 1e-2 (MalConv 0),
  0.032 at 1e-3, 0.005 at 1e-4; 31.2% of those benign files escalated at 0.5. Inference 153 files/s (231 MB/s) on one A100.
  Reading whole files does not remove the toolchain shortcut: it is not a truncation artefact.
- **D2, pre-filter threshold sweep** (same file): at a 0.5 threshold, 0.08% of malware is missed and 0.09% of benign
  files from known toolchains go to the sandbox, but 29.9% of the unseen-toolchain benign files do. In a fleet where
  one new binary in 1,000 is malicious, the sandbox receives ~0.2% of new binaries on known toolchains and ~30% on an
  unseen one: the architecture's "~90% decided by the pre-filter" holds by a wide margin, until the software mix
  changes.
- **D3, drift**: TPR at 1e-3 FPR by first-seen month of the test malware: 0.9995, 0.9996, 0.9985, 0.9992 (2019-01
  to 2019-04). No decay over four months on SOREL; the toolchain shift above is the drift that matters here.
- **D3 on BODMAS** (`D3_bodmas_drift.json`, new; Yang et al. 2021: EMBER-format features of 57,293 malware and
  77,142 benign PE files, 2019-08 → 2020-09; protocol of TESSERACT: LightGBM trained on 2019-08 → 10 plus the 10,731
  older benign files, then every later month tested on its own; thresholds for 1e-3 FPR set on the last 10% of the
  training period and kept fixed). ROC-AUC never drops below 0.9986, but what a deployed threshold delivers moves:
  TPR 0.962-0.994 (0.962 in the last month), and the real false-positive rate at the "1e-3" threshold reaches
  0.0035 (2020-01) and 0.0062 (2020-02), six times the target. Malware from families never seen in training grows
  from 1.3% of a month (2019-11) to 18% (2020-07); the static model detects 0.70-0.96 of them against 0.97-0.99 of
  known families. Retraining every month on everything seen so far brings TPR to 0.96-0.999 (≥ 0.99 for the last
  five months) with the FPR at threshold ≤ 0.0019. Drift shows up first in calibration and in new families, long
  before it shows in AUC.
- **D4, robustness to published evasions** (`D4_malconv_robustness.json`, new): 1,000 test malware files the model
  detects at the 1e-3 FPR threshold (0.475); perturbed files stay in GPU memory, nothing is written or executed.
  Appending random bytes (1, 10, 100 KB): 0% evade. Appending benign bytes: 0%, 0%, 1.0%. Gradient-optimised padding
  (Kolosnjaji et al. 2018, 20 steps in embedding space): 2.6% at 1 KB, 16.8% at 10 KB. Partial DOS header
  (Demetrio et al. 2019, bytes 2-0x3B, 20 steps): 0.1%. Only the white-box gradient attack moves this model, and
  it needs 10 KB of optimised bytes to evade one file in six.
- **D7, where MalConv looks** (`D7_malconv_attribution.json`, new; gradient x input per byte on 2,000 test malware
  and 2,000 benign files): 85.8% of the attribution mass falls in the body, 5.5% in the PE headers, 3.8% in the rest
  of the first 4 KB, 2.3% in the section table, 1.8% in the DOS stub, 0.8% in the DOS header. Yet the first 4 KB
  alone classify as well as the whole file (AUC 0.999997 vs 0.999998): the header region is sufficient on this
  corpus even though the gradient spreads over the body, which is the corpus-separability caveat again. The low
  weight on the DOS header matches D4 (the DOS-header attack fails).
- D1, MalConv latency (`D1_malconv_latency.json`): CPU single thread 14.8 ms per 64 KB file, batch 32 5.2 ms per
  file; GPU figures in C2.
- **D5, ELF** (`D5_elf_profile.json`, `D5_elf.json`, new):
  - Census: MalwareBazaar ELF is 93% ET_EXEC across 18 architectures (ARM 28%, x86-64 25%, MIPS 13%, x86 13%,
    PPC, SH4, m68k, SPARC, LoongArch); Debian amd64 ELF is 42% objects/kernel modules, 32% shared libraries and
    almost only x86-64. An amd64-only benign set is separable by architecture and file type alone, so the benign
    side was rebuilt from executables of every malware architecture (19 sources) and only executables are compared.
  - Even matched, metadata separates: a 10-feature header model (architecture, class, endianness, type, interpreter,
    dynamic section, symbols, sections, UPX, size) reaches validation AUC 0.998. 61% of benign executables are PIE,
    0.85% of malware.
  - Test (newest export days, 2026-11-20 → 24): header+bytes GBDT AUC 0.968, TPR 0.89 at 1e-3 FPR; bytes only
    0.963 / 0.66; header only 0.966 / 0.60.
  - The drop is one emerging architecture. LoongArch malware appears in the last four days (69 files; 1 in the
    whole training period) while training holds 3,000 benign LoongArch executables. The 69 files are near-identical
    builds of one 1.7 MB binary (sizes within a few bytes, one identical score per model): in effect one sample.
    Every GBDT scores it benign (AUC 0.48-0.49 on bytes, 0.80 header-only, TPR 0); see MalConv below. On architectures whose malware was seen in training,
    header+bytes reaches AUC 0.9997 and TPR 0.95 at 1e-3 FPR. Matching the benign corpus removed the architecture
    shortcut and exposed the real limit: a static model cannot know a new target's malware before it has seen some.
  - MalConv on ELF (test split, `D5_elf.json`; LoongArch at global thresholds in `D5_elf_loongarch.json`):
    PE MalConv zero-shot AUC 0.686, TPR 0 at 1e-2 and 1e-3; fine-tuned from PE AUC 0.988, TPR 0.82 / 0.66 at 1e-2 /
    1e-3; from scratch (59,358 files, best of 8 epochs at val AUC 0.9992) AUC 0.997, TPR 0.969 / 0.789. Learning
    curve from scratch: 10% of the data AUC 0.963 / TPR 0.51 at 1e-3; 30% 0.966 / 0.63; 100% 0.997 / 0.79 (fine-tune:
    0.901 / 0.15, 0.966 / 0.40, 0.988 / 0.66). Hard benign (non-PIE ET_EXEC only): TPR at 1e-3 0.51 (MalConv
    scratch) vs 0.87 (header+bytes GBDT). Raw bytes rank better (AUC), the structural GBDT holds the strict threshold
    better. LoongArch: MalConv from scratch scores the binary 0.853 -> flagged at the 1e-2 global threshold (0.292),
    where 3.6% of LoongArch benign files are flagged too; missed at 1e-3 (threshold 0.9975). PE-initialised MalConv
    (0.002) and every GBDT (0.0) score it benign.
  - **Mach-O** (`D5_macho.json`, new): every Mach-O member of 180 days of MalwareBazaar daily exports (1,036 executables,
    2026-05-29 to 11-22) against 3,008 executables from Homebrew bottles (1,247 formulae, arm64 and x86-64); temporal split
    for malware (test = export days from 2026-11-07: 234 malware), benign split by formula. 65% of training-period malware
    are universal (fat arm64+x86_64) binaries, no Homebrew bottle is: the header GBDT learns it (val AUC 0.9987) and
    collapses on the newest malware, only 17% universal (test AUC 0.539, TPR 0.50 at 1% FPR); bytes-only GBDT AUC 0.978,
    TPR 0.75; header+bytes 0.985 / 0.50. PE MalConv zero-shot: AUC 0.656, TPR 0.13 at 1% FPR, flags 43% of benign at 0.5.
- **D6, the static score inside fusion and LLM triage** (`D6_static_in_fusion.json`, `D6_summary.json`, new).
  The generator binds real binaries to the simulated fleet (PE for macOS as a stand-in, x86-64 ELF for gLinux),
  emits the on-host extraction event at each binary's first run on a device, and adds a stream of never-seen benign
  binaries (installs, updates, dev builds: 0, 300 or 3,000 per working day). P7 reads the real classifier score
  (MalConv for PE, GBDT header+bytes for ELF; threshold at 0.1% FPR on a disjoint half / the validation split;
  binaries seen during warm-up are the known-good cache). Two worlds: "known" (the fleet's software comes from the
  toolchains the classifier was trained on) and "unseen" (the fleet's benign PE software is MSVC-built, the threshold
  is still the lab one). Binary-heavy datasets (24 rare_binary attacks in 2 days, 3 seeds) give the power; mix
  datasets (all 26 types) give the system-level cost.

  | world, new benign binaries/day | P6-hyper (no static score) | P7 alone | P6-hyper + P7 (in fusion) | MIX-tuned + P7 direct |
  |---|---|---|---|---|
  | known, 0 | 0.702 rare_binary recall, 38.0 FP/day | 0.947, 0.0 FP/day | 0.965, 38.0 FP/day | 0.982, 38.6 FP/day |
  | known, 300 | 0.053, 38.5 | 0.947, 1.6 | 0.930, 40.0 | 0.947, 40.7 |
  | known, 3,000 | 0.035, 38.7 | 0.947, 5.3 | 0.754, 41.8 | 0.947, 44.6 |
  | unseen toolchain, 300 | 0.035, 40.7 | 0.982, 57.3 | 0.614, 44.9 | 0.982, 98.9 |
  | unseen toolchain, 3,000 | 0.018, 41.5 | 0.982, 539 | 0.491, 47.4 | 0.982, 582 |

  - Software churn kills behavioural detection of a new malicious binary: "first-seen binary" signals become common
    and the rarity weighting discounts them (0.70 → 0.05 recall as soon as 300 benign binaries a day are new).
  - The static classifier restores it at a cost that grows with churn (1.6 FP/day at 300 new binaries a day, 5.3 at
    3,000, on known toolchains); inside fusion it is discounted in turn when it fires often (0.75 at 3,000 a day).
  - Under a toolchain shift the classifier alone floods the analysts (57 to 539 FP/day); fusion absorbs the flood
    (+5 to +9 FP/day) by discounting the noisy detector, and loses half the binary attacks.
  - Letting a confident static verdict alert on its own, beside behavioural fusion (MIX-tuned + P7 direct), is the
    best design while the classifier's calibration holds (0.95-0.98 recall for +1.6 to +5.3 FP/day) and the worst
    when it breaks (the flood goes straight through: 99 to 582 FP/day). Direct alerting needs a guard on the static
    alert rate; fusion is that guard, paid in recall.
  - On mix datasets the whole-system effect is small (2 rare_binary cases per run): P6-hyper + P7 recall 0.672 vs
    0.649 at 300/day, +0.9 FP/day; P8 + P7 kept the one binary attack P8 closed (n = 1, anecdotal) at equal FP/day.

## RQ-E. Does fusing weak signals beat single-signal alerting?

- E1, bundles of three weak anomalies on one entity (`--bundles 10 --bundle-intensity 0.3`, REPORT.md bundles table).
- E2, fusion methods (`E2_learned.json`, train seeds 101-103, test seeds 104-110): hand-set rarity-weighted
  noisy-OR (P6-hyper) recall 0.55, AP 0.86, 10 FP/day recall 0.45; learned naive-Bayes LLR 0.42 / 0.80 / 0.37;
  learned stacking 0.70 / 0.77 / 0.59. Stacking trained only on the first batch of types keeps 0.59 at 10 FP/day.
- E3, calibration: Brier score per pipeline in every REPORT.md table (P6-hyper 0.24, P5-hyper-tuned 0.10).
- E4, risk half-life (`suite_halflife.json`): 1 h → 9.7 FP/day, 24 h → 120 FP/day; recall at 10 FP/day is best at
  short half-lives (0.56 at 1 h, 0.33 at 24 h).
- E5, identity stitching loss 0-30% of keys (`suite_stitching.json`): P6-hyper FP/day 31 → 38, recall stable;
  P2 FP/day 318 → 512.
- E6, intensity 0.1-1.0 (`suite_intensity.json`): at 0.1, graph fusion keeps 0.64 recall, static rules 0.44,
  Isolation Forest 0.14.

## RQ-F. What does an entity graph add?

- **Graph ablation, same attacks and signals** (`suite_coretuned.json`, base, 10 seeds): tuned graph fusion vs tuned
  flat fusion (P5-hyper-tuned vs P6-hyper-tuned): multi-layer cases 98/121 = 0.81 vs 76/121 = 0.63; single-layer
  156/238 = 0.66 vs 151/238 = 0.63; FP/day 18.5 vs 10.8. The links lift multi-layer recall; the 0.98-vs-0.65 contrast
  of the paper compares two groups of attacks, this one isolates the propagation.

- F1, graph vs flat fusion: P5 recall 0.76 vs P6 0.62 at the default calibration (base table); with the
  rarity weighting, P5-hyper 0.745 at 275 FP/day vs P6-hyper 0.62 at 31 FP/day.
- F2, graph construction (`suite_graph.json`): damping 0.2-0.6 barely matters; a hub cap of 50 cuts FP/day from
  633 to 368 but loses recall (0.76 → 0.70); identity-only edges keep recall, lose ranking (0.16 vs 0.19 at 10 FP/day).
- F3, trace sampling (`suite_sampling.json`, source ablation): removing Dapper and the edge log changes nothing
  measurable for these anomaly types; the 1/1024 sampling blind spot does not show at this scale.
- **F3, sampled spans vs the aggregated edge log** (`suite_f3adaptive.json`, `suite_f3heavy.json`, new). With
  `--dapper-edges`, every call of every edge can become a span (paired worlds: the spans come from the auxiliary
  stream), and P2 gains a novelty rule on span edges. Five ways to see the call graph, 3 seeds, a new_rpc_edge-heavy
  dataset (12 per run) for power:

  | call-graph source | spans per day | edge-log rows per day | new_rpc_edge found by P6-hyper / MIX-tuned |
  |---|---|---|---|
  | unsampled edge log (5-min aggregates) | 26k (traces only) | 19.3k | 23 / 23 |
  | none (edge log removed) | 26k | 0 | 18 / 23 |
  | spans, uniform 1/1024 | 360k | 0 | 19 / 23 |
  | spans, uniform 1/64 | 804k | 0 | 19 / 23 |
  | spans, adaptive (rare edges traced first) | 360k | 0 | 20 / 23 |

  P2 alone finds every new edge in every variant: the ALTS handshake log already shows a service calling a peer
  it never called. For fusion, the aggregated edge log is both the cheapest source (19k rows a day) and the only
  complete one; per-call sampling recovers one of the five cases lost without it, a denser uniform rate (1/64)
  none more for 2.2x the spans, and adaptive sampling two for +0.1% spans. Aggregation beats sampling for
  detection; when sampling is all there is, sample by novelty, not uniformly.
- **F4, DARPA TC Engagement 3, CADETS host** (`F4_tc_cadets.json`, `F4_tc_cadets_daycases.json`, new): 41.35 M CDM
  events, 2018-04-02 -> 13, 224,629 processes, 155,322 flows, converted to the envelope (principal = executable, task =
  process, device = object: file pattern, remote address:port or child process); 3-day warm-up. Labels: ThreaTrace's
  12,858 nodes, ten of which are long-lived daemons/files active every hour, so an event counts as an attack if it falls
  in an attack window of the TC ground-truth report (EDT, 3 h) and touches a labelled node first seen inside that window;
  the labels cover 3 of the 5 CADETS attacks (Nginx/Drakon sessions of April 11, 12, 13; 35, 44,709 and 20,812 events).
  Graph propagation (P5) 3/3 at 109 FP/day (TTD 140 s); noisy-OR fusion 2/3 at 91; per-entity novelty 3/3 at 51,000;
  Isolation Forest 2/3 at 669 (TTD ~1 h); n-gram 2/3 at 15,000; rarity-weighted fusion alone, with n-grams or with the
  GNN: 0/3 at 12-20 FP/day; GNN alone 0/3 at 9,771. None within 10 FP/day. The first pass (one case per day with any
  labelled node) is kept in `F4_tc_cadets_daycases.json` for reference.
- F5, investigation completeness: `evidence_completeness` per pipeline in every result file.
- **F6, graph neural network link prediction** (`F6_gnn_edges.json`, `suite_gnn.json`, new). P10 learns a GraphSAGE
  link predictor (two mean-aggregation layers, dot-product decoder, type-aware negative sampling; 300 epochs and
  dimension 32 chosen by held-out link-prediction AUC, no attack label used) on the interaction graph of the warm-up
  (service -> called method from the unsampled edge log, person -> application, principal -> dataset, job ->
  egress destination, job -> executed binary, owner -> binary), then scores every edge first met afterwards, in
  the spirit of Euler (King & Huang). Edge level, among the ~860 new edges per run (3 seeds x 3 conditions):

  | condition | GNN AUC / AP | preferential attachment AUC / AP | collaborative filtering AUC / AP | unseen node AUC / AP |
  |---|---|---|---|---|
  | base | 0.644 / 0.080 | 0.939 / 0.790 | 0.909 / 0.780 | 0.823 / 0.652 |
  | drift (benign launch) | 0.647 / 0.036 | 0.936 / 0.401 | 0.895 / 0.406 | 0.852 / 0.375 |
  | mix | 0.703 / 0.153 | 0.898 / 0.358 | 0.860 / 0.366 | 0.740 / 0.239 |

  Held-out link-prediction AUC tops out at 0.61: in this environment the benign newcomers (a person opening an app
  for the first time) are not predictable from the graph, and the attacker's new edges are structurally plausible
  (new_rpc_edge picks a callee in the caller's own cells). Node degree alone ranks the attacker's edges far better.
  Alert level (3 seeds): P10 alone 0.08-0.25 recall at 18-380 FP/day; added to fusion it costs ~+30 FP/day and lowers
  recall at 10 FP/day (P6-hyper 0.52 -> 0.33, MIX-tuned 0.62 -> 0.48 on base). An untuned 60-epoch version
  (`*_untuned_e60.json`) gives the same picture. On the real provenance graph of DARPA TC and the LANL authentication
  graph, see F4 and the pending list.

## RQ-G. Does an LLM triage layer help, and is it safe?

- **G10b, stability of the SFT / GRPO contrast** (`G10_round3.json`, `G10_round3_by_type.json`, `bench/g10_round3.py`;
  held-out configuration, every model scored on the 170 familiar-type and 83 held-out-type attack alerts and the 159 FPs):

  | model | familiar closed | held-out closed | FP closed | GRPO groups with gradient |
  |---|---|---|---|---|
  | SFT 1 epoch (sft_u) | 10.6% | 36.1% | 89.3% | - |
  | SFT 2 epochs (sft_u2) | 2.4% | 13.3% | 88.7% | - |
  | + GRPO run 1 (grpo_u) | 33.5% | 85.5% | 98.7% | 18 |
  | + GRPO run 2 (seed 2) | 14.1% | 56.6% | 95.0% | 31 |
  | + GRPO run 3 (seed 3) | 17.1% | 67.5% | 94.3% | 23 |
  | + GRPO KL beta 0.04 | 17.1% | 71.1% | 95.0% | 28 |

  GRPO moves the model towards closing on both populations; the KL term does not prevent it; a second SFT epoch is the
  best model. Held-out closures are mostly breakglass_no_incident (GRPO 41-55/56, SFT 25/56, SFT2 10/56). With the
  reward (+1 / 0 for a benign alert closed / reviewed; -1 / +0.5 for an attack closed / reviewed), closing is optimal when
  P(attack) < 0.4. Re-scoring sft_u gave 36.1% vs 37.3% in round 2 (batched inference). All models state conf 0.9.
  Training ~$9 and evals ~$2.5 of H100 on Modal.
- **G10b reward ablation** (`G10_round4.json`, `G10_round4_by_type.json`; same start sft_u, same seeds 2 and 3, only
  the penalty for closing an attack changes from 1 to 5): held-out 43.4% (seed 2, was 56.6%) and 69.9% (seed 3, was
  67.5%); familiar 13.5% and 17.6% (were 14.1% and 17.1%); FP closed 96.2% (were 95.0% and 94.3%); gradient groups 39 and
  23. Mixed: the mechanism stays a hypothesis. With group-normalised advantages, a group holding only closures and reviews
  gives a closure the same advantage (-2.47 for 1 of 8) whatever the penalty. Six GRPO runs: held-out 43-86%, familiar
  14-34%, all above the SFT start (36%, 11%).
- **Two-epoch SFT (sft_u2) inside FINAL** (`experiments/final/s{7,8,9}_local_sft_u2.json`, answers
  `local_answers_sft_u2.jsonl`, same 482 prompts): recall 0.671 / 0.522 / 0.627 (= detection stage, 0 cases lost), FP/day
  6.7 / 16.0 / 8.0 (mean 10.2 vs 17.8 without a model and 5.8 with Gemini 4); 74 of 482 alerts closed (35 positive);
  confidence 0.9 on every answer; latency p50 0.66 s; dossiers 100.6 a day (7.4 without attack).
- **Units (G1)**: 169 fused alerts after the warm-up, 83 of them on attack events; 73 attack cases, 39 detected by
  fusion (and by the cascade's detection stage: P9 with no model, 39 cases at 33.3 FP/day). "Attacks closed 45/83"
  etc. are alerts; cases lost: flash-lite 17, flash-lite + harness 11, Gemini 4 12, cascade + Gemini 4 9, agent +
  Gemini 4 9 (of 39). G10's "cases" are triaged alerts too (345 test alerts, 186 on attack events).

On 2-day runs with lag, drift and injected text (`G_series_v5_2d*.json`):

| pipeline | recall | precision | FP/day | look-alike FP/day | anomalies wrongly closed | cost (2 days) |
|---|---|---|---|---|---|---|
| P6-hyper (input) | 0.534 | 0.570 | 32.7 | 16.0 | - | - |
| P8 flash-lite | 0.301 | 0.879 | 2.7 | 2.0 | 45 / 83 | $0.20 |
| P8 + harness | 0.384 | 0.796 | 7.3 | 3.3 | 25 / 83 | $0.14 |
| P8 Gemini 4 | 0.370 | 0.884 | 3.3 | 2.7 | 28 / 83 | $1.99 |
| P9 cascade, Gemini 4 | 0.411 | 0.955 | 2.0 | 0.7 | 31 / 83 | $1.52 |
| P8 agent with tools, Gemini 4 | 0.411 | 0.754 | 9.3 | 3.3 | 26 / 71 | $2.91 |

- G1: LLM triage removes 90% of the fused false positives but also closes a third to a half of the real attacks
  it sees; the cascade (rare severe signals bypass the LLM) keeps recall at 0.41 with 2 FP/day.
- G2, context: removing inventory / on-call / service context drops P8 recall from 0.30 to 0.21.
- G3, tool use: the agent investigating with tools keeps more attacks than the single prompt with pre-collected
  context (flash-lite 0.47 vs 0.30 recall, Gemini 4 0.41 vs 0.37) but lets more false positives through (18.7 vs
  2.7, 9.3 vs 3.3 FP/day) and makes 1.8x the calls.
- G5: no hallucinated evidence ids (0.0%); on decisions about real attacks, 56% (flash-lite) and 68% (Gemini 4) of
  the cited events are the attack's own events.
- G6: identical verdicts on a repeated run at temperature 0 (169 / 169).
- G7: Brier 0.25 (flash-lite), 0.18 (Gemini 4).
- **G8, prompt injection, paired design** (`G8_paired_random.json`, `G8_paired_attack.json`, new). Same seed with
  and without injected text: identical world and anomaly cases, so each case is compared with itself. "Exposed"
  = the model saw an injected event in the evidence.
  - Random injection in half of the attacker-writable fields (seeds 7 and 8): flash-lite 13 exposed cases, 0
    closed because of the text, 1 kept because of it; Gemini 4 7 exposed, 0 / 1.
  - Attack-only injection (every writable field of the attack's own events, the realistic threat model): flash-
    lite 9 exposed, 1 closed because of the text (b = 1), 3 kept because of it (c = 3); Gemini 4 9 exposed, b = 0,
    c = 2, and Gemini 4 escalated injected cases to "malicious".
  - Background flip rate on cases the text never reached: ~10%. The unpaired analysis (closure rate with vs
    without injection across different cases) was confounded by case type and is superseded.
- G9, harness: the deterministic policy (no automatic closure of high-risk alerts) recovers 20 of the 45 wrongly
  closed attacks (P8 → P8-harness) at +4.6 FP/day.
- **G10, fine-tuning with verifiable rewards** (`G10_rlvr.json`, `G10_api_*.json`, new). Every alert P8 would send
  to the LLM was recorded with its ground truth (`bench/g10_data.py`: 1,208 training cases from seeds 101-110, 345
  test cases from seeds 7-9, disjoint worlds; 57% / 54% attacks). Qwen3-4B-Instruct-2507 (Apache-2.0; Gemma would need
  the user's Hugging Face licence) was tuned with LoRA (r = 16): supervised on the label, the attack's own event ids
  and a fixed summary (1 epoch), then GRPO with a verifiable reward and no judge model (verdict against the label;
  minus the share of cited event ids absent from the evidence shown; plus the share of cited ids that belong to the
  attack), 8 samples per prompt, 320 prompts, no KL term. Greedy decoding, served with vLLM on one H100.

  | model | attacks wrongly closed | false positives closed | invalid answers | hallucinated evidence | cited ids from the attack | latency p50 |
  |---|---|---|---|---|---|---|
  | Qwen3-4B, zero-shot (1,024-token answers) | 84.4% | 98.7% | 0.3% | 0.02% | 0.46 | 4.32 s |
  | (same, 320-token answers: runs past the budget) | 40.9% | 17.0% | 62% | 0.3% | 0.69 | 1.94 s |
  | + supervised fine-tuning | 26.9% | 98.1% | 1.7% | 0.0% | 0.99 | 0.32 s |
  | + SFT + GRPO | **15.6%** | 96.9% | 2.0% | 0.0% | 0.99 | 0.33 s |
  | Gemini 3.1 flash-lite (API, same cases) | 45.2% | 93.1% | 0% | 0.0% | 0.67 | 1.00 s |

  A 4B model trained on 1,208 labelled triage cases closes more false positives than the API model and wrongly closes
  a third as many attacks, cites the attack's own events instead of the whole evidence list, and answers three
  times faster on a local GPU. GRPO halved the attacks the SFT model still closed although only 18 of the 320 prompt
  groups carried a gradient (in the other 302 all eight samples earned the same reward): after SFT the reward is
  saturated, and a harder curriculum would be the next step. Zero-shot, with a fair answer budget, the 4B model calls almost everything benign (84% of attacks closed).
  Attack types never seen in training and injection robustness: round 2 (pending). Caveat: train and test come from the same generator;
  the shortcut audit (A2) says some types are separable by content, which a fine-tuned model will exploit. On the
  four attack types of the second batch (83 cases), flash-lite wrongly closes 54%.
- **G10, round 2** (`G10_round2.json`, `G10_api_flash_unseen.json`, new).
  - Attack types never seen in training (SFT and GRPO repeated without the second-batch types; 83 attacks of the four
    second-batch types that reach triage + 159 test false positives): attacks wrongly closed by the zero-shot model 100%,
    flash-lite 54.2%, supervised without these types 37.3% (FP closed 90.6%), supervised + GRPO without these types 85.5%
    (FP closed 98.7%), supervised + GRPO with all types 22.9%. GRPO improved the familiar types (26.9% -> 15.6%) and made
    the unseen ones much worse (37.3% -> 85.5%): it learned to close what does not look like its training data (291 of 320
    groups carried no gradient, the few updates pushed towards "benign").
  - Injection robustness (the 46 G11 cases: clean, G8's 5 static strings, the 227 adaptive strings found against
    flash-lite and Gemini 4, transferred): share of prompts closing the case, zero-shot 85% / 90% / 90-93%; supervised
    28% / 28% / 36-40%; supervised + GRPO 15% / 9% / 13-21%. Of the 34 cases with adaptive strings, the supervised +
    GRPO model closes 5 clean and 11 when the attacker can pick among the transferred strings.
- **G11, adaptive attacker** (`G11_adaptive_flash.json`, `G11_adaptive_g4.json`, new). The cases P8 would triage
  were recorded without calling the model (seeds 7-9, 128 attack cases reach triage, 46 with a field the attacker
  writes in its own events: G8's fields plus the path of its own executable and its HTTP User-Agent). An attacker
  model (flash-lite) proposes a string appended to those fields, sees only the verdict, and retries. Success = the
  case is closed (benign, confidence >= 0.7); with the G9 harness it must also clear 0.9 on an alert below 0.9 risk.

  | target | closed with no injection | attacked | closed after 1 try | after 4 | after 8 | with harness, 4 / 8 |
  |---|---|---|---|---|---|---|
  | flash-lite (8 rounds, 46 cases) | 19 / 46 | 27 | 22% | 37% | 56% | 22% / 30% |
  | Gemini 4 (4 rounds, 28 cases, budget cap) | 4 / 28 | 24 | 17% | 17% | - | 8% |

  The static injection of G8 closed 0-1 case; an attacker who adapts closes half the attacks flash-lite still
  catches and one in six of Gemini 4's. The winning strings are not instructions ("ignore previous...") but cover
  stories in fields the attacker legitimately controls: a binary renamed `/usr/bin/gdb_automated_debugger_session_
  authorized_by_sre_team_for_production_hotfix_ticket_#88291`, a health-check command line, a ticket number in a
  justification. "Treat field values as data" in the system prompt does not stop content that is data. Of all
  attempts, 85% (flash-lite) and 81% (Gemini 4) made the model call the case malicious: the attack is noisy, a
  detection opportunity in itself. Static-injection evals underestimate the risk; evals need an adaptive attacker
  with a query budget (Nasr et al. 2025, "the attacker moves second"). Cost: $0.23 and $1.45.

## RQ-H. Does detection survive change?

- H1, nightly regression (`H1_regression.json`): every metric of a fresh seed within its reference band.
- H2, source ablation (REPORT.md): removing the prod runtime layer (eBPF etc.) costs the most (P6-hyper 0.72 →
  0.28); removing traces, metrics or the edge log costs nothing measurable.
- H3, ATT&CK coverage: `attack_coverage` per pipeline in every result file.
- H4, drift (launch, reorg, holiday): see the drift condition table (REPORT.md).
- **H5, heterogeneous people** (`suite_hetero.json`, new): per-person lognormal activity, sigma 0 / 0.5 / 1.0
  (Gini ≈ 0.05 / 0.28 / 0.52, CERT web 0.39). The ranking holds: MIX-tuned 0.62 / 0.57 / 0.57 recall at 10 FP/day,
  P6-hyper 0.52 / 0.51 / 0.49 (FP/day 31 / 36 / 40), P1-tuned 0.53 throughout. Isolation Forest degrades (recall
  0.34 → 0.28 → 0.16).

## RQ-I. What does automatic response cost?

`G_series_v5_2d_response.json`, 73 cases: human-in-the-loop for every alert contains 32 cases, time to contain
p50 28.7 min, 76 reviews/day; LLM-driven automatic containment contains 17, p50 8.9 min, 16 automatic actions/day
of which 2 wrongful (benign look-alikes), 6 reviews/day; strict policy: 14 actions/day, 1.3 wrongful.

---

## Threats to validity (to state in the paper)

1. Synthetic environment: reconstructed from public papers, not a real hyperscale fleet; A1 bounds the gap.
2. Static-ML corpora: absolute AUCs reflect corpus separability (D1 group ablation, D5 header model).
3. LLM results depend on the model version and the prompt; temperature 0, one prompt, two model families.
4. CERT is synthetic; LANL user accounts include automation.
5. Seeds: 10 for the core plan, 3 for extra plans; paired designs where the effect is small (G8).

## Pending


## Complete pipelines end to end, and the recommended one (`FINAL_comparison.json`, new)

Same 2-day world as the G series (seed 7: lag, drift, 12 bundles, injected text in 10% of writable fields; 845,018 events,
73 attack cases after warm-up). FINAL = rare severe signals on a fast path + tuned context-aware rules and behaviour
baselines + rarity-weighted graph fusion + Gemini triage behind a policy-first harness (alerts at risk >= 0.9 go to
analysts without a model call; "benign" closes only at confidence >= 0.9). Adding the sequence model as a fusion signal
floods the graph (1,425 FP/day before triage), so FINAL leaves it out.

| pipeline | recall | precision | FP/day | R@10 | TTD p50 | events/s | model calls | cost (2 days) |
|---|---|---|---|---|---|---|---|---|
| 1 SIEM: tuned rules with context | 0.493 | 0.686 | 49.3 | 0.384 | 3 s | 454k | - | - |
| 2 rarity-weighted fusion | 0.534 | 0.570 | 32.7 | 0.411 | 242 s | 141k | - | - |
| 3 fusion + sequences | 0.616 | 0.150 | 275.3 | 0.027 | 419 s | 56k | - | - |
| 4 MIX-tuned | 0.548 | 0.643 | 33.3 | 0.425 | 142 s | 146k | - | - |
| 5 graph fusion, tuned | 0.671 | 0.899 | 12.7 | 0.671 | 116 s | 126k | - | - |
| 6 fusion + Gemini flash-lite | 0.301 | 0.879 | 2.7 | 0.301 | 352 s | 61k | 169 | $0.20 |
| 7 fusion + flash-lite + harness | 0.384 | 0.796 | 7.3 | 0.384 | 143 s | 75k | 169 | $0.14 |
| 8 fusion + Gemini 4 | 0.370 | 0.884 | 3.3 | 0.370 | 150 s | 79k | 169 | $1.99 |
| 9 cascade + Gemini 4 | 0.411 | 0.955 | 2.0 | 0.411 | 111 s | 74k | 169 | $1.52 |
| 10 agent with tools + Gemini 4 | 0.411 | 0.754 | 9.3 | 0.411 | 111 s | 53k | 300 | $2.91 |
| FINAL detection stage, no model | 0.671 | 0.912 | 13.3 | 0.671 | 11 s | 38k | - | - |
| **FINAL, Gemini flash-lite** | **0.657** | **0.949** | 6.7 | **0.658** | **95 s** | 41k | 153 | $0.17 |
| **FINAL, Gemini 4** | **0.671** | **0.974** | **3.3** | **0.671** | **95 s** | 43k | 153 | $2.04 |
| FINAL, local 4B (SFT) | 0.575 | 0.974 | 2.0 | 0.575 | 242 s | 38k | 153 | $0.04 GPU |
| FINAL, local 4B (SFT + GRPO) | 0.630 | 0.953 | 5.3 | 0.630 | 11 s | 38k | 153 | $0.07 GPU |

Every earlier Gemini pipeline bought its low FP rate by closing real attacks (0.53 -> 0.30-0.41 recall); FINAL keeps 0.66
recall at 6.7 FP/day with flash-lite, and with Gemini 4 keeps every attack its detection stage found (0.671) at 3.3
FP/day and 0.974 precision ($2.04, Gemini latency p50 7.3 s, 16 harness overrides). 39 fast-path alerts bypass the model, 36 high-risk alerts skip it by policy, 153 calls, 26 harness
overrides; the model halves the remaining FPs (13.3 -> 6.7/day) for 1 point of recall. Seeds 8 and 9 (no injection):
the detection stage of FINAL ranks first within 10 FP/day again (R@10 0.52 / 0.63 vs MIX-tuned 0.38 / 0.48, P6-hyper
0.36 / 0.45, P1-tuned 0.33 / 0.39). With Gemini (recall / FP per day):

| pipeline | seed 7 | seed 8 | seed 9 |
|---|---|---|---|
| FINAL detection stage (no model) | 0.671 / 13.3 | 0.522 / 29.3 | 0.627 / 10.7 |
| FINAL, Gemini flash-lite | 0.657 / 6.7 | 0.522 / 18.7 | 0.627 / 8.0 |
| **FINAL, Gemini 4** | **0.671 / 3.3** | **0.522 / 9.3** | **0.627 / 4.7** |
| FINAL, local 4B (SFT) | 0.575 / 2.0 | 0.478 / 3.3 | 0.552 / 1.3 |
| FINAL, local 4B (SFT + GRPO) | 0.630 / 5.3 | 0.507 / 11.3 | 0.627 / 6.0 |
| cascade, Gemini 4 | 0.411 / 2.0 | 0.435 / 4.7 | 0.448 / 2.7 |
| fusion + Gemini flash-lite | 0.301 / 2.7 | 0.362 / 4.7 | 0.328 / 1.3 |

On every world Gemini 4 in FINAL closes none of the attacks its detection stage found and removes 56-75% of the remaining FPs;
the cascade with Gemini 4 detects 9-26 points fewer attacks than FINAL. Means over the three worlds: FINAL + Gemini 4 0.61 recall at 5.8 FP/day, cascade +
Gemini 4 0.43 at 3.1, fusion + flash-lite 0.33 at 2.9. About $2 of Gemini 4 per simulated 2 days (160-167 calls).

**Protocol check** (`PROTOCOL_frozen.json`, `bench/protocol.py`; thresholds frozen on base worlds 1-3, scored on
4-10; dossiers = alerts on one entity within 24 h; ~35 attack cases a day):

| pipeline | R@10 (time order) | R@10 (ties whole) | frozen recall | frozen FP/day | worlds > 10 | dossiers/day (no attack) | top-10 dossiers/day | top-20 |
|---|---|---|---|---|---|---|---|---|
| P1-tuned | 0.51 | 0.43 | 0.43 | 0.4 | 0/7 | 17.9 (0.4) | 0.25 | 0.44 |
| P6-hyper | 0.48 | 0.48 | 0.44 | 8.7 | 2/7 | 33.0 (4.4) | 0.17 | 0.32 |
| P6-hyper-tuned | 0.61 | 0.61 | 0.61 | 9.4 | 4/7 | 54.6 (8.0) | 0.21 | 0.32 |
| MIX-tuned | 0.54 | 0.54 | 0.53 | 9.1 | 2/7 | 41.3 (4.9) | 0.16 | 0.34 |
| P5-hyper-tuned | 0.71 | 0.71 | 0.71 | 10.9 | 3/7 | 101.6 (6.6) | 0.46 | 0.55 |
| FINAL detection stage | 0.71 | 0.71 | 0.71 | 11.0 | 4/7 | 112.6 (6.6) | 0.46 | 0.54 |
| + volume baselines | 0.79 | 0.79 | 0.79 | 11.0 | 4/7 | 115.7 (6.6) | 0.53 | 0.62 |
| P5 (untuned) | 0.18 | 0.18 | 0.11 | 6.7 | 0/7 | 7.7 (4.1) | 0.34 | 0.41 |

Dossiers per detected attack: FINAL 4.3, P5-hyper-tuned 3.8, P6-hyper-tuned 2.2, MIX-tuned 2.0, P1-tuned 1.2. (A
merge on shared triggering events chains alerts across whole worlds and was dropped.)

**Counting units** (`FINAL_counting.json`, `bench/counting.py`; seeds 7-9; Gemini answers replayed from the stored
decisions in call order, exact for Gemini 4; flash-lite left out because its replay differs from the original run by one
case on seed 7):

| variant | cases | detected | to analysts without the model | exposed | model calls (pos / neg) | closed pos / neg | cases lost | alerts/day | dossiers/day (no attack) |
|---|---|---|---|---|---|---|---|---|---|
| detection stage (no model) | 209 | 127 | 102 | 25 | 0 (0 / 0) | 0 / 0 | 0 | 161.6 | 111.6 (11.1) |
| Gemini 4 | 209 | 127 | 102 | 25 | 482 (395 / 87) | 109 / 61 | 0 | 123.8 | 90.9 (4.7) |
| local SFT | 209 | 127 | 102 | 25 | 482 (395 / 87) | 271 / 83 | 15 | 82.9 | 60.2 (2.0) |
| local SFT+GRPO | 209 | 127 | 102 | 25 | 482 (395 / 87) | 118 / 55 | 4 | 123.1 | 89.1 (5.5) |

**Held-out attack types** (rules tuned on the first 16 types; 10 others): FINAL detection stage 113/128 = 0.883 on
tuned types vs 14/81 = 0.173 on held-out types over seeds 7-9; flash-lite and Gemini 4 identical; local SFT 100/128,
12/81; SFT+GRPO 110/128, 13/81; cascade + Gemini 4 80/128, 10/81.

**Ablation of FINAL** (local answers, `experiments/final/s{7,8,9}_abl_{sft,grpo}.json`; 114 extra prompts for the
alerts at risk >= 0.9 answered on Modal, `abl_answers_*.jsonl`), means over 3 worlds, recall / FP per day:

| variant | SFT | SFT+GRPO | calls |
|---|---|---|---|
| graph fusion + model, no harness, no fast path | 0.501 / 0.9 | 0.583 / 6.9 | 596 |
| + harness | 0.516 / 2.0 | 0.583 / 7.3 | 596 |
| + fast path | 0.535 / 2.2 | 0.588 / 7.5 | 596 |
| + policy first (FINAL) | 0.535 / 2.2 | 0.588 / 7.5 | 482 |

Policy first: same decisions by construction, 19% fewer calls. Input effect (Gemini): flat fusion + Gemini 4 0.370 /
3.3 vs FINAL + Gemini 4 0.671 / 3.3 on seed 7; flash-lite over 3 worlds 0.330 / 2.9 vs 0.602 / 11.1.

**Volume extension inside FINAL** (2-day worlds, detection stage): 0.607 / 17.8 -> 0.688 / 17.3 (B6).

**Ablation with Gemini 4** (`experiments/final/s{7,8,9}_abl_g4.json`; 114 extra Gemini 4 calls for the high-risk alerts,
$1.69, `abl_answers_g4.jsonl`, merged with the replayed pipeline answers): graph + model, no harness 0.587 / 3.3; +
harness 0.607 / 5.8 (72 overrides); + fast path 0.607 / 6.0; + policy first (FINAL) 0.607 / 6.0 with 482 calls instead
of 596. Without the harness Gemini 4 erases 4 attacks (s7: 1, s9: 3). The replay reproduces seeds 7 and 9 exactly and
differs from the original seed-8 run by one FP alert (10.0 vs 9.3 FP/day; 19 unparsable answers in both).

**Adaptive attacker against FINAL + Gemini 4** (`G11_adaptive_final_g4.json`, `bench/g11_adaptive.py::attack_final`;
case-level: success only if every alert of the attack is closed by the harness; one cover story per attack in every
field the attacker controls; 4 rounds; feedback = verdict on the first writable alert): 25 exposed attacks, 8 with a
writable field (22 alerts); 1 closed without injection on re-scoring (s8:BUNDLE07-3, single alert, kept in the pipeline
run: Gemini 4 not deterministic at temperature 0); of the 7 attacked, 0 erased; the targeted alert closed in 2, each
case kept another alert. Spent $0.79.

**Fresh worlds, seeds 10-12** (generated after FINAL was fixed; `experiments/final/s1{0,1,2}_nollm.json`), no model:
FINAL detection stage recall 0.593 at 20.0 FP/day, R@10 0.570 (P5-hyper-tuned identical within 1 FP/day); MIX-tuned
0.505 / 31.8 / 0.436; P6-hyper 0.478 / 30.9 / 0.394; P1-tuned 0.403 / 49.8 / 0.314. Held-out types: FINAL 16/83, tuned
types 112/133. With Gemini 4 (`experiments/final/s1{0,1,2}_final_g4.json`): 0.595 / 4.0, 0.594 / 7.3, 0.534 / 6.0 (mean 0.574 / 5.8); 470 calls, $6.03; held-out types 14/83.

Correction: the seed-7 detection stage of FINAL is 0.671 / 13.3 FP/day (`s7_final_nollm_v2.json`, fast path included);
12.7 is row 5 (graph fusion without the fast path). The old `x5_nollm.json` "FINAL-nollm" row is the discarded variant with
the sequence model (1,425 FP/day).

**Local fine-tuned model in place of Gemini** (`experiments/final/s{7,8,9}_local_{sft,grpo}.json`): the 482 prompts FINAL sent
Gemini on the three worlds were recorded (`BENCH_LLM_RECORD`), answered on one H100 by the merged G10 models (vLLM, greedy;
`g10_rlvr.py::final_local`) and replayed into the pipeline (`BENCH_LLM_REPLAY`; 0 missing answers). Exposure: of the 127
attacks the detection stage finds, 102 reach analysts whatever the model says (fast path or risk >= 0.9) and 25 depend on
its verdict (`experiments/g11/cases_final.json`). Closed among those 25: Gemini 4 0, flash-lite 1, SFT+GRPO 4, SFT 15. FPs
removed: Gemini 4 56-75%, SFT+GRPO 44-61%, SFT 85-89%. Means: SFT+GRPO 0.588 recall at 7.5 FP/day, SFT 0.535 at 2.2. Both
models state confidence 0.9 on every answer (the training-target value), so the harness's confidence gate never overrides
them, and their summaries are the training template. Latency p50 0.43 s (SFT+GRPO) and 0.26 s (SFT), single requests on an
idle H100; GPU time at that latency $0.04-0.07 per 2 days, but a reserved H100 costs ~$190 for the same 2 days.
