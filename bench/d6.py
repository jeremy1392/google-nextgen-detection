"""D6: marginal value of the static binary classifier inside fusion and LLM triage.

    python -m bench.d6 corpus --pe <D1 scores_test.csv> --pe-unseen <D1 scores_test_unseen_toolchain.csv>
                              --elf <D5 scores_test.csv> --elf-val <D5 scores_val.csv> --elf-meta <D5 d5_splits.csv>
    python -m bench.d6 run [--seeds 3] [--novelty 0,300,3000] [--workers 6] [--llm]
    python -m bench.d6 summary                      # -> experiments/results/D6_summary.json

corpus writes two variants under experiments/d6/<variant>/ (binary_scores.csv for P7, corpus.csv for loggen):
  known    the fleet's binaries come from the toolchains the classifier was trained on (D1 test split)
  unseen   the fleet's benign PE software is MSVC-built (D1's unseen-toolchain benign set), while the alert
           threshold is still calibrated on the known toolchains: what a deployment calibrated in the lab meets
PE: the test split is cut in two halves by hash; the "threshold" half sets the per-platform threshold at the
target false-positive rate, the "world" half is bound into the simulated fleet. ELF: the threshold comes from the
D5 validation split and the D5 test split is the world, x86-64 only (a gLinux workstation runs x86-64 binaries).
gLinux devices draw ELF files, macOS devices PE files as a stand-in (there is no Mach-O corpus).

run: for each variant, seed and novelty rate, two datasets of 2 days: the standard mix (all anomaly types) and a
binary-heavy one (rare_binary only, for statistical power on binary-borne attacks). Every dataset has the
on-host extraction events (--binary-scan). Pipelines with and without the P7 signal are scored on the same data.
Results: experiments/results/D6_static_in_fusion.json.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import subprocess
import sys
from concurrent.futures import ProcessPoolExecutor

OUT = "experiments/d6"
PIPES = ["P6-hyper", "P7", "P7-1e-2", "P6-hyper+P7", "MIX-tuned", "MIX-tuned+P7", "MIX-tuned+P7direct"]
LLM_PIPES = ["P8", "P8+P7"]
VARIANTS = ("known", "unseen")


def _half(sha: str) -> str:
    return "threshold" if int(hashlib.md5(sha.encode()).hexdigest(), 16) % 2 == 0 else "world"


def build_corpus(pe: str, pe_unseen: str, elf: str, elf_val: str, elf_meta: str, elf_arch: str = "x86_64") -> dict:
    keep = {r["sha256"] for r in csv.DictReader(open(elf_meta, encoding="utf-8")) if r["machine"] == elf_arch}
    pe_rows = [(r["sha256"], r["label"], r["score"]) for r in csv.DictReader(open(pe, encoding="utf-8"))]
    unseen_ben = [(r["sha256"], r["label"], r["score"]) for r in csv.DictReader(open(pe_unseen, encoding="utf-8"))
                  if r["label"] == "0"]
    elf_rows = [(r["sha256"], r["label"], r["score"], "threshold") for r in csv.DictReader(open(elf_val, encoding="utf-8"))
                if r["sha256"] in keep]
    elf_rows += [(r["sha256"], r["label"], r["score"], "world") for r in csv.DictReader(open(elf, encoding="utf-8"))
                 if r["sha256"] in keep]
    counts = {}
    for variant in VARIANTS:
        rows = [[s, lab, sc, "pe", _half(s)] for s, lab, sc in pe_rows]
        if variant == "unseen":  # benign world software from the unseen toolchain; threshold still from known ones
            rows = [r for r in rows if not (r[1] == "0" and r[4] == "world")]
            rows += [[s, lab, sc, "pe", "world"] for s, lab, sc in unseen_ben]
        rows += [[s, lab, sc, "elf", role] for s, lab, sc, role in elf_rows]
        d = os.path.join(OUT, variant)
        os.makedirs(d, exist_ok=True)
        with open(f"{d}/binary_scores.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["sha256", "label", "score", "platform", "role"])
            w.writerows(rows)
        with open(f"{d}/corpus.csv", "w", newline="", encoding="utf-8") as f:
            f.writelines(f"{s},{lab},{p}\n" for s, lab, _, p, role in rows if role == "world")
        c = {}
        for _, lab, _, p, role in rows:
            k = f"{p}/{role}/{'mal' if lab == '1' else 'ben'}"
            c[k] = c.get(k, 0) + 1
        counts[variant] = c
    return counts


def _job(args) -> dict:
    variant, seed, nov, heavy, pipes = args
    tag = f"{variant}_s{seed}_nov{int(nov)}_{'binary' if heavy else 'mix'}"
    data = f"experiments/cache/d6_{tag}"
    corpus = os.path.join(OUT, variant, "corpus.csv")
    if not os.path.exists(os.path.join(data, "manifest.json")):
        cmd = [sys.executable, "-m", "loggen", "--duration", "2d", "--seed", str(seed), "--out", data,
               "--binary-corpus", corpus, "--binary-scan", "--new-binaries-per-day", str(nov)]
        cmd += ["--anomaly-types", "rare_binary", "--anomalies", "24"] if heavy else []
        subprocess.run(cmd, check=True, capture_output=True)
    out_json = os.path.join(OUT, f"eval_{tag}.json")
    have = json.load(open(out_json, encoding="utf-8"))["pipelines"] if os.path.exists(out_json) else {}
    missing = [p for p in pipes if p not in have]
    if missing:  # evaluate only what is not there yet, then merge
        env = {**os.environ, "BENCH_BINARY_SCORES": os.path.join(OUT, variant, "binary_scores.csv")}
        tmp = out_json + ".part.json"
        subprocess.run([sys.executable, "-m", "bench", "eval", data, "--pipelines", ",".join(missing), "--json", tmp],
                       check=True, env=env, capture_output=True)
        new = json.load(open(tmp, encoding="utf-8"))
        if have:
            full = json.load(open(out_json, encoding="utf-8"))
            full["pipelines"].update(new["pipelines"])
            new = full
        json.dump(new, open(out_json, "w", encoding="utf-8"), indent=1)
        os.remove(tmp)
    return {"variant": variant, "seed": seed, "novelty_per_day": nov, "dataset": "binary" if heavy else "mix",
            "result": json.load(open(out_json, encoding="utf-8"))}


def run(seeds: int, novelty: list[float], llm: bool, workers: int) -> dict:
    jobs = []
    for variant in VARIANTS:
        for seed in range(1, seeds + 1):
            for nov in novelty:
                for heavy in (False, True):
                    pipes = list(PIPES)
                    if llm and variant == "known" and seed == 1 and not heavy and nov == novelty[len(novelty) // 2]:
                        pipes += LLM_PIPES
                    jobs.append((variant, seed, nov, heavy, pipes))
    with ProcessPoolExecutor(workers) as pool:
        runs = list(pool.map(_job, jobs))
    res = {"pipelines": PIPES + (LLM_PIPES if llm else []), "runs": runs}
    os.makedirs("experiments/results", exist_ok=True)
    json.dump(res, open("experiments/results/D6_static_in_fusion.json", "w", encoding="utf-8"), indent=1)
    return res


def summarize(path: str = "experiments/results/D6_static_in_fusion.json") -> dict:
    """Mean over seeds per (variant, novelty, dataset, pipeline): overall and rare_binary recall, FP/day, the
    false positives caused by never-seen benign binaries, and recall within a 10 FP/day budget."""
    from statistics import mean
    res = json.load(open(path, encoding="utf-8"))
    cells: dict = {}
    for r in res["runs"]:
        for pipe, m in r["result"]["pipelines"].items():
            hit, n = map(int, ((m.get("recall_by_type") or {}).get("rare_binary") or "0/0").split("/"))
            by = m.get("fp_lookalike_by_type") or {}
            share = by.get("new_binary", 0) / sum(by.values()) if by else 0.0  # apportion the per-day rate by type
            cells.setdefault((r["variant"], r["novelty_per_day"], r["dataset"], pipe), []).append({
                "recall": m["recall"], "rb_hit": hit, "rb_n": n, "fp_per_day": m["fp_per_day"],
                "new_binary_fp_per_day": m["fp_lookalike_per_day"] * share,
                "recall_at_10fp": (m.get("recall_at_fp_per_day") or {}).get("10/day")})
    out = []
    for (variant, nov, ds, pipe), rows in sorted(cells.items(), key=lambda x: (x[0][0], x[0][1], x[0][2])):
        avg = lambda k: round(mean(v[k] for v in rows if v[k] is not None), 3) if any(v[k] is not None for v in rows) else None
        hits, n = sum(v["rb_hit"] for v in rows), sum(v["rb_n"] for v in rows)
        out.append({"variant": variant, "novelty_per_day": nov, "dataset": ds, "pipeline": pipe, "seeds": len(rows),
                    "recall": avg("recall"), "rare_binary_recall": round(hits / n, 3) if n else None,
                    "rare_binary_cases": n, "fp_per_day": avg("fp_per_day"),
                    "new_binary_fp_per_day": avg("new_binary_fp_per_day"), "recall_at_10fp": avg("recall_at_10fp")})
    return {"cells": out}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="bench.d6")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("corpus")
    c.add_argument("--pe", required=True, help="D1 test scores (PE)")
    c.add_argument("--pe-unseen", required=True, help="D1 test scores with the unseen-toolchain benign set")
    c.add_argument("--elf", required=True, help="D5 test scores (ELF)")
    c.add_argument("--elf-val", required=True, help="D5 validation scores: the ELF threshold set")
    c.add_argument("--elf-meta", required=True, help="D5 splits CSV, to keep only --elf-arch files")
    c.add_argument("--elf-arch", default="x86_64")
    r = sub.add_parser("run")
    r.add_argument("--seeds", type=int, default=3)
    r.add_argument("--novelty", default="0,300,3000")
    r.add_argument("--workers", type=int, default=6)
    r.add_argument("--llm", action="store_true", help="also P8 / P8+P7 on one mix dataset (known, seed 1, middle rate)")
    sub.add_parser("summary")
    a = p.parse_args(argv)
    if a.cmd == "corpus":
        print(json.dumps(build_corpus(a.pe, a.pe_unseen, a.elf, a.elf_val, a.elf_meta, a.elf_arch), indent=1))
    elif a.cmd == "run":
        run(a.seeds, [float(x) for x in a.novelty.split(",")], a.llm, a.workers)
    else:
        res = summarize()
        json.dump(res, open("experiments/results/D6_summary.json", "w", encoding="utf-8"), indent=1)
        print(f"{'variant':<8}{'nov/d':>6}{'data':>7}  {'pipeline':<14}{'recall':>8}{'rare_bin':>9}{'FP/d':>8}{'newbin FP/d':>12}{'R@10':>7}")
        for c in res["cells"]:
            print(f"{c['variant']:<8}{int(c['novelty_per_day']):>6}{c['dataset']:>7}  {c['pipeline']:<14}{c['recall']!s:>8}"
                  f"{c['rare_binary_recall']!s:>9}{c['fp_per_day']!s:>8}{c['new_binary_fp_per_day']!s:>12}{c['recall_at_10fp']!s:>7}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
