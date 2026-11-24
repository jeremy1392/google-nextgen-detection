# loggen: synthetic telemetry for NextGen detection

`loggen` generates realistic, correlated security logs for every telemetry source in the
architecture diagrams (`l7_nextgen_detection_architecture.drawio.png`,
`borg_colossus_with_corp.drawio.png`, in [`architecture/`](../architecture/)). It is the data layer for building and scoring the
detection and dynamic-reasoning pipeline. See the [main README](../README.md) for the study it serves; run the
commands below from the repository root.

All of the data is synthetic. People, devices, services and identifiers are invented, domains
use `example.com`, and public IPs come from the RFC 5737 documentation ranges. The system names
(Borg, Colossus, BeyondCorp, etc.) follow Google's public papers, as the write-up does.

Python 3.10+, standard library only.

```bash
python -m loggen                                   # 24 h, ~420k events, ~12 s -> out/run
python -m loggen --duration 7d --scale 2 --combined --out out/week
python -m loggen --sources 'borg.*,colossus.*' --duration 6h
python -m loggen --stdout --realtime --speed 60    # stream 1 simulated minute per second
python -m loggen --list-sources
```

## What it simulates

A single discrete-event clock drives one shared model of the organization:

- ~200 people in Zurich and Brussels, with roles (SWE, SRE, research, security, business), teams,
  working hours, on-call rotations, remote days and occasional travel.
- 1–3 devices per person (gLinux, macOS, ChromeOS) with Santa or auditd sensors, certificates and
  a posture that drifts as patches age.
- Two Borg cells (`zrh-c1` in Zurich, `ghs-c2` in Saint-Ghislain), each with 9 racks, 5 BorgMaster
  replicas, compute, storage and TPU machines.
- 23 services with tasks, a call graph, the datasets they own, and build history.

Every source reads from this one model, so the logs share keys. One release, for example:

```
admin.code_review  create_change  user:lea.ts   cl 612014971
admin.build        build_complete               -> bcid-e9112dff96086b0b
admin.mpa          request / approve            -> mpa-5e8908f83c (approved by user:sara.ak)
borg.master_audit  UpdateJob      user:lea.ts   bcid_to + mpa_id + device_id
borg.bab           admission      svc:gemini-inference  gemini-inference.0  (same bcid, provenance)
host.ebpf          execve         same task, same sha256
```

The shared keys are `principal`, `device_id`, `src_ip`/`dst_ip`, `cell`, `job`, `task`,
`trace_id`, `bcid`, `mpa_id` and `session`, which together make up the "identity stitching" row of
the diagram.

## Sources (35)

| Layer | Sources |
|---|---|
| Corp: company devices | `corp.santa`, `corp.auditd`, `corp.edr`, `corp.dns`, `corp.netflow`, `corp.usb` |
| Corp: BeyondCorp & identity | `bc.uberproxy`, `bc.device_posture`, `bc.mtls`, `bc.loas` |
| Corp: dev & SRE workflows | `admin.code_review`, `admin.build`, `admin.mpa`, `admin.breakglass`, `admin.prod_ssh`, `admin.incident` |
| Prod: control plane | `borg.master_audit`, `borg.scheduler`, `borg.bab`, `borg.chubby`, `borg.paxos`, `borg.borglet_priv` |
| Prod: data access | `colossus.curator`, `colossus.chunkserver`, `spanner.audit`, `bigtable.audit`, `net.b4` |
| Prod: host, network, AI | `host.titan`, `host.ebpf`, `net.alts`, `net.jupiter`, `tpu.runtime` |
| Observability | `obs.dapper` (sampled 1/1024), `obs.monarch`, `obs.rpc_edge` (unsampled call graph) |

Aggregated sources (`colossus.chunkserver`, `net.b4`, `obs.monarch`, `obs.rpc_edge`) emit one
record per window (5 or 10 min) rather than one per operation.

## Event shape

```json
{"ts": "2026-11-23T04:44:33.120Z", "event_id": "…", "log_source": "borg.master_audit",
 "layer": "prod.control_plane", "action": "UpdateJob", "outcome": "success",
 "site": "zrh", "cell": "zrh-c1", "principal": "user:lea.ts", "device_id": "d-d450f369f2",
 "job": "gemini-inference",
 "payload": {"rpc": "BorgMaster.UpdateJob", "request": {"reason": "release", "bcid_from": "…", "bcid_to": "…"},
             "mpa_id": "mpa-5e8908f83c", "read_only": false, "replica": "zrh-c1-r01-c000"}}
```

The envelope fields are always at the top level. Fields specific to a source are in `payload`.
Output is globally sorted by `ts`.

## Output

```
out/run/
  logs/<source>.jsonl      one file per source (or --stdout / --combined all.jsonl)
  ground_truth.jsonl       one line per injected anomaly, with the ids of every event it touched
  context/inventory.json   people, devices, apps, cells, machines, services, datasets (enrichment)
  context/builds.json      build registry: every BCID with verified provenance
  context/oncall.json      on-call per SRE team per day
  manifest.json            seed, window, counts per source
```

The same seed with the same options produces byte-identical output.

## Labeled anomalies

`--anomalies N` (default 32) injects anomalies, cycling through the 16 types below. They are
recorded in `ground_truth.jsonl`, with MITRE ATT&CK ids where relevant. With `--inline-labels`
they are also added as a `_truth` field on each event.

### Behavioural deviations

| Type | What changes | Where it shows |
|---|---|---|
| `read_volume_spike` | A principal reads a dataset at 15–40× its usual volume, or a person reads a dataset only services read | `colossus.chunkserver`, `colossus.curator` |
| `new_rpc_edge` | A service calls a method it has never called | `obs.rpc_edge`, `net.alts` |
| `off_hours_access` | An engineer with no on-call duty uses prod tooling at night | `bc.uberproxy`, `bc.mtls`, `borg.master_audit` |
| `first_seen_device` | A sign-in from a device not in the inventory | `bc.device_posture`, `bc.mtls`, `bc.uberproxy` |
| `unverified_build` | Tasks start with a BCID missing from the registry; BAB is in dry-run for that job | `admin.build`, `borg.master_audit`, `borg.scheduler`, `borg.bab`, `host.ebpf` |
| `egress_shift` | A service with no internet egress starts sending to a new external address | `obs.monarch`, `net.jupiter` |
| `rare_binary` | A first-seen unsigned binary runs on one endpoint | `corp.santa` / `corp.auditd`, `corp.edr` |
| `fast_approval` | An MPA request is approved within seconds, outside working hours | `admin.mpa`, `borg.master_audit` |

### Container runtime (eBPF)

Each one is a short burst of syscalls inside one Borg task, as an in-container eBPF sensor would
record them. The categories follow public container-runtime rule sets. Most attempts are refused
(`ret < 0`, `errno`, `seccomp_action`), because tasks run sandboxed and as a non-root role account.

| Type | What the sensor sees | ATT&CK |
|---|---|---|
| `ebpf_shell_in_container` | The service binary spawns `sh -i` with no tty and stdin on a socket, then `id`, `uname`, `env`… | T1059.004, T1082 |
| `ebpf_namespace_escape` | `unshare` / `setns` / `mount` / opening `/proc/1/root`, refused | T1611 |
| `ebpf_sensitive_read` | Opens `/etc/shadow`, `/proc/1/environ`, or another task's role certificate | T1552.001, T1003.008 |
| `ebpf_kernel_module` | `insmod` of a `.ko` from `/tmp`, `finit_module` refused | T1547.006 |
| `ebpf_ptrace_attach` | Unknown binary does `PTRACE_ATTACH` + `process_vm_readv` on the service | T1055.008 |
| `ebpf_bpf_load` | `bpf(BPF_PROG_LOAD)` without CAP_BPF, refused | T1014 |
| `ebpf_memfd_exec` | `memfd_create` then `execveat(AT_EMPTY_PATH)` (fileless execution) | T1620 |
| `ebpf_unexpected_connect` | A service with no internet egress retries one external address on a fixed interval; dropped | T1071 |

The `ebpf_unexpected_connect` type also shows up in `net.jupiter`, as flows with `policy_verdict: drop`.

### Benign look-alikes

The baseline also contains benign events that look suspicious, which a good detector should not
flag:

- An SRE prod session (routine or breakglass) starts `bash` inside a task. The eBPF parent is the
  Borglet, it has a pty, and the `session` id links it to `admin.prod_ssh` and `borg.borglet_priv`.
- The Borglet runs `sh -c logrotate`, and services call `fileutil`.
- About 1% of `connect` calls get `ECONNREFUSED` while a peer restarts, and about 4% of `openat`
  calls get `ENOENT` on optional config files.

- An incident pages the on-call SRE, who uses breakglass and opens a prod shell, sometimes followed
  by a rollback.
- Nightly backups cause large reads and B4 spikes (01:00–04:30 local).
- The search crawler sends traffic to the internet.
- The continuous profiler attaches to tasks with `ptrace`.
- People travel, and work on weekends or late at night (about 3% of the time).
- Device posture degrades as patches age, so the access proxy denies requests.

## Experiment knobs

| Option | Experiments | Effect |
|---|---|---|
| `--intensity 0.1..2` | E6 | Anomaly strength (counts, volume factors, approval delay, whether the EDR fires) |
| `--bundles N --bundle-size 3 --bundle-intensity 0.3` | E1 | Weak anomalies sharing one person or one service, a few hours apart |
| `--lag`, `--drop-rate` | C1, C7 | Adds `ingest_ts` with per-layer delivery delays (including laptops offline for hours); drops events in transit |
| `--raw` | C2 | Adds the native line (`raw`) for Santa, auditd, DNS, netflow and proxy logs |
| `--injection-rate p` | G8 | Instruction-like text in attacker-controllable fields, listed in `injections.jsonl` |
| `--drift launch@26h,reorg@30h,holiday@40h+8h` | H4 | Legitimate baseline changes: new service, team moves, holiday |
| `--binary-corpus file.csv` | D6 | Binary hashes taken from a real dataset (`sha256,label[,platform]`), so MalConv scores can be joined; with a platform column (`pe` / `elf`), gLinux devices draw ELF files and macOS devices PE files (stand-in: no Mach-O corpus) |
| `--binary-scan` | D6 | `corp.binscan`: the on-host extraction event (hash, path, signer) at the first run of each binary on a device |
| `--new-binaries-per-day N` | D6 | Benign binaries the fleet has never run (installs, updates, dev builds), about N per working day, recorded as `new_binary` look-alikes |
| `--truth-out dir`, `--shuffle-types` | A4 | Blind runs: ground truth written elsewhere |
| `--dapper-edges uniform\|adaptive` | F3 | Also sample spans per call-graph edge (with a `caller` field): uniform at the Dapper rate (1/1024 x `--dapper-rate`), or adaptive (an edge seen rarely so far is traced up to every call); drawn from the auxiliary stream |
| `--user-heterogeneity sigma` | H5 | Per-person lognormal activity multiplier (mean 1) |
| `--injection-target attack` | G8 | Inject only into the fields of the attack's own events (the realistic threat model) |

Benign look-alikes (incident response, routine SRE sessions, service launch) are written to
`benign_cases.jsonl`, so false positives can be attributed to a cause.

Every knob is off by default, and switching one on never changes the rest of the run: the D6 and F3
additions draw from their own random stream and their own event ids, so a dataset with `--binary-scan
--new-binaries-per-day` (or `--dapper-edges`) holds exactly the events of the same seed without them, plus the
new ones (without `--lag` / `--drop-rate`, whose transport draws are per written event).

## Bench

`bench/` replays a run through the pipelines under test, in arrival order (`ingest_ts`), timing
each detector per event. A queue model turns those timings into detection delay at any replay
speed. It then scores against the ground truth.

```bash
python -m bench list                                     # the 52 experiments and what each still needs
python -m bench eval out/run --pipelines P0,P1,P2 --eval-from 12h --speed 100 --json results.json
python -m bench eval out/run --sources 'host.*,borg.*'   # source ablation (H2)
```

Metrics: alerts/day, precision, FP/day (and look-alike FP/day by cause), recall overall, per
family (UEBA / non-human / runtime) and per type, bundle recall, time to detect, average precision,
recall within a 1/10/100 FP/day budget, per-event latency p50/p95/p99, throughput, and detection
delay under load.

| Pipeline | What it is | Status |
|---|---|---|
| P0 | Static rules, one event at a time (Sigma / Falco style), frozen before the second batch of anomaly types | done |
| P1 | P0 + lookup tables (inventory, on-call, build registry) + windowed correlation | done |
| P2 | Per-entity baselines: novelty and seasonal z-scores | done |
| P3 | Isolation Forest on per-entity hourly activity windows, one model per entity type | done |
| P4 | Sequence models on per-entity event streams (DeepLog-style n-gram, top-g) | done |
| P5 | Risk fusion over the causal / identity graph built from the events | done |
| P6 | Probabilistic fusion of P1 + P2 signals: rarity weighting, decay; `P6` noisy-OR, `P6-sum`, `P6-max` | done |
| P7 | Static binary classifier: real MalConv scores on real binaries, looked up at each `corp.binscan` event (`P7` 0.1% FPR threshold, `P7-1e-2`); `P6-hyper+P7`, `MIX-tuned+P7`, `P8+P7` add it as one more signal, `MIX-tuned+P7direct` lets its verdicts alert on their own (D6) | done |
| P8 | P6 + LLM triage of each fused alert via OpenRouter (`P8` 3.1-flash-lite, `P8-g4` Gemini 4 hydrogen) | done |
| P9 | Cascade: fast path for rare severe signals, fusion + LLM for the rest | done |
| P10 | Temporal link prediction: GraphSAGE on the warm-up interaction graph, alerts on unlikely new edges (`P10`, `P10-q0.5`, `P10-q10`); `P6-hyper+P10`, `P5-hyper+P10`, `MIX-tuned+P10` add it as a fusion signal (F6) | done |

```bash
python -m bench suite core intensity ablation speed --workers 8   # every combination -> experiments/REPORT.md
python -m bench suite context overload scale gnn f3adaptive f3heavy  # B4, C8, C5, F6, F3
python -m bench llm-speed --runs 3                                  # G4: every Gemini text model
BENCH_DROP_CONTEXT=inventory,oncall,builds python -m bench eval out/run   # B4: withhold context tables
```

The LLM pipelines read `OPENROUTER_API_KEY` from the environment or a local `.env` (not committed).

```bash
# D6: the static classifier inside fusion. Score tables come from D1 (PE) and D5 (ELF) test splits.
python -m bench.d6 corpus --pe scores_test_pe.csv --elf scores_test_elf.csv   # threshold half / world half
python -m bench.d6 run --seeds 3 --novelty 0,300,3000 [--llm]                  # -> D6_static_in_fusion.json
# G8, paired: same seed with and without --injection-rate, every anomaly case compared with itself
python -m bench.g8_paired with.json with_run/ without.json without_run/ --out G8_paired.json
```

P7 reads its score table from `BENCH_BINARY_SCORES` (default `experiments/d6/binary_scores.csv`).

```bash
python -m bench.cost funnel | scale                       # C6 cascade funnel, C5 cost per million events
python -m bench.f6_gnn generator --seeds 3                # F6, edge level: GNN vs link-prediction heuristics
python -m bench.g11_adaptive record <runs...>             # G11: the cases triage would see (no LLM call)
python -m bench.g11_adaptive attack --target flash|g4     # G11: adaptive attacker with label feedback
python -m bench.g10_data build                            # G10: triage cases with verifiable labels
python -m bench.g10_metrics api                           # G10: API model on the same test cases
python -m bench.d3_bodmas                                 # D3 on BODMAS (feature vectors only)
```

Modal apps (real data, GPU): `modal_apps/tc_f4.py` (DARPA TC E3 CADETS, F4), `modal_apps/a5_external.py`
(CERT, LANL, `::lanl_gnn` for F6), `modal_apps/g10_rlvr.py` (SFT + GRPO with verifiable rewards on
Qwen3-4B, G10 and G4 local), `modal_apps/macho_d5.py` (Mach-O, D5), `modal_apps/elf_d5.py` (ELF, D5),
`modal_apps/malconv_train.py` (D1, D4 `::robustness`, D7 `::attribution`).

## Code layout

```
loggen/engine.py        clock, event heap, sinks, ground truth, overlays for aggregated sources
loggen/world.py         the simulated organization
loggen/registry.py      source catalogue (layer, system, description)
loggen/sources/*.py     baseline generators, one module per diagram box
loggen/anomalies.py     labeled anomaly injection
loggen/cli.py           options and output files
```

To add a source, register it in `registry.py`, then write a generator that calls
`sim.emit(ts, source, action, payload, **keys)`. Install it from the module's `install()`.
