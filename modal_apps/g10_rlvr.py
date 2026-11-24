"""G10 (+ G4 local): fine-tuning a small open model for alert triage, supervised then with verifiable rewards.

    modal run modal_apps/g10_rlvr.py::zeroshot      # base model on the test cases (vLLM) + local latency (G4)
    modal run --detach modal_apps/g10_rlvr.py::pipeline   # SFT -> GRPO -> evaluate base / SFT / SFT+GRPO
    -> experiments/results/G10_rlvr.json

Model: Qwen3-4B-Instruct-2507 (Apache-2.0, no gated licence; Gemma would need the user's Hugging Face licence).
Data: experiments/g10/{train,test}.jsonl from bench/g10_data.py: the exact prompts P8 sends, with labels from
the generator's ground truth. Train seeds 101-110, test seeds 7-9 (disjoint worlds).
Verifiable reward (no judge model): valid JSON; verdict against the label (attack: malicious +1, needs_review
+0.5, benign -1; benign or look-alike: benign +1, needs_review 0, malicious -0.5); minus the share of cited event
ids that were not in the evidence shown (hallucinated evidence); plus 0.5 x the share of cited ids that belong to
the attack (attack cases). SFT target: the label, the attack's own event ids as evidence, a fixed summary.
GRPO: group of 8 samples per prompt, advantage = (r - mean) / std within the group, one policy-gradient step per
group (num_iterations = 1, no KL term: beta = 0), LoRA r = 16 on all linear layers, on top of the SFT adapter.
"""
from __future__ import annotations

import json
import os

import modal

app = modal.App("g10-rlvr")
vol = modal.Volume.from_name("g10-models", create_if_missing=True)
MODEL = "Qwen/Qwen3-4B-Instruct-2507"
train_image = (modal.Image.debian_slim(python_version="3.11")
               .pip_install("torch==2.6.0", "transformers==4.51.3", "peft==0.15.2", "accelerate==1.6.0",
                            "numpy==1.26.4", "huggingface_hub[hf_transfer]==0.30.2")
               .env({"HF_HUB_ENABLE_HF_TRANSFER": "1", "HF_HOME": "/models/hf"})
               .add_local_dir("experiments/g10", "/g10data", ignore=["*.log"]))
infer_image = (modal.Image.debian_slim(python_version="3.11")
               .pip_install("vllm==0.8.5", "huggingface_hub[hf_transfer]==0.30.2")
               .env({"HF_HUB_ENABLE_HF_TRANSFER": "1", "HF_HOME": "/models/hf"})
               .add_local_dir("experiments/g10", "/g10data", ignore=["*.log"]))


def _rows(split):
    return [json.loads(x) for x in open(f"/g10data/{split}.jsonl", encoding="utf-8")]


def parse(text: str):
    try:
        v = json.loads(text[text.index("{"):text.rindex("}") + 1])
        verdict = v.get("verdict")
        if verdict not in ("malicious", "benign", "needs_review"):
            return None
        conf = float(v.get("confidence", 0) or 0)
        ev = [str(x) for x in (v.get("evidence") or [])][:50]
        return verdict, conf, ev
    except (ValueError, TypeError, AttributeError):
        return None


def reward(text: str, row: dict, close_penalty: float = 1.0) -> float:
    """close_penalty: the cost of closing an attack (verdict benign on an attack alert). With 1.0, closing beats
    sending to review whenever the attack probability is below 0.4; with 5.0, below about 0.15."""
    p = parse(text)
    if p is None:
        return -1.0
    verdict, conf, cited = p
    attack = row["kind"] == "anomaly"
    r = ({"malicious": 1.0, "needs_review": 0.5, "benign": -close_penalty} if attack else
         {"benign": 1.0, "needs_review": 0.0, "malicious": -0.5})[verdict]
    cited_set = set(cited)
    if cited_set:
        r -= len(cited_set - set(row["shown_event_ids"])) / len(cited_set)
        if attack:
            r += 0.5 * len(cited_set & set(row["case_event_ids"])) / len(cited_set)
    return r


def target(row: dict) -> str:
    attack = row["kind"] == "anomaly"
    return json.dumps({"verdict": "malicious" if attack else "benign", "confidence": 0.9,
                       "evidence": row["case_event_ids"][:10] if attack else [],
                       "summary": ("The events match an attack pattern; escalate to an analyst." if attack else
                                   "The activity is consistent with legitimate operations.")})


def metrics(rows, texts, latencies=None) -> dict:
    out = {"cases": len(rows)}
    att = [(r, t) for r, t in zip(rows, texts) if r["kind"] == "anomaly"]
    ben = [(r, t) for r, t in zip(rows, texts) if r["kind"] != "anomaly"]
    closed = lambda t: (lambda p: p is not None and p[0] == "benign" and p[1] >= 0.7)(parse(t))
    out["attack_cases"], out["fp_cases"] = len(att), len(ben)
    out["attacks_wrongly_closed"] = round(sum(closed(t) for _, t in att) / max(len(att), 1), 4)
    out["fp_closed"] = round(sum(closed(t) for _, t in ben) / max(len(ben), 1), 4)
    out["invalid_json"] = round(sum(parse(t) is None for t in texts) / max(len(texts), 1), 4)
    cited = [(r, set(parse(t)[2])) for r, t in zip(rows, texts) if parse(t) is not None]
    allc = sum(len(c) for _, c in cited)
    out["hallucinated_evidence"] = round(sum(len(c - set(r["shown_event_ids"])) for r, c in cited) / max(allc, 1), 4)
    ac = [(r, c) for r, c in cited if r["kind"] == "anomaly" and c]
    out["attack_evidence_precision"] = round(sum(len(c & set(r["case_event_ids"])) / len(c) for r, c in ac)
                                             / max(len(ac), 1), 4)
    out["mean_reward"] = round(sum(reward(t, r) for r, t in zip(rows, texts)) / max(len(rows), 1), 4)
    if latencies:
        s = sorted(latencies)
        out["latency_s"] = {"p50": round(s[len(s) // 2], 3), "p95": round(s[int(len(s) * 0.95)], 3)}
    return out


# ------------------------------------------------------------------------------------------- inference
@app.function(image=infer_image, gpu="H100", volumes={"/models": vol}, timeout=3 * 3600)
def evaluate(adapter: str = "", label: str = "base", latency_probe: int = 40, max_tokens: int = 1024,
             rows_file: str = "test", return_texts: bool = False) -> dict:
    """Greedy decoding on every test case (batched), then single-request latency on a sample (G4 local)."""
    import time

    from vllm import LLM, SamplingParams
    path = f"/models/merged/{adapter}" if adapter else MODEL
    llm = LLM(model=path, dtype="bfloat16", max_model_len=12288, gpu_memory_utilization=0.85, seed=0)
    tok = llm.get_tokenizer()
    rows = _rows(rows_file)
    prompts = [tok.apply_chat_template([{"role": "system", "content": r["system"]}, {"role": "user", "content": r["user"]}],
                                       tokenize=False, add_generation_prompt=True) for r in rows]
    sp = SamplingParams(temperature=0.0, max_tokens=max_tokens)
    t0 = time.time()
    outs = llm.generate(prompts, sp)
    batch_s = time.time() - t0
    texts = [o.outputs[0].text for o in outs]
    lat = []
    for p in prompts[:latency_probe]:  # one request at a time: the latency an alert sees on an idle local GPU
        t = time.time()
        llm.generate([p], sp, use_tqdm=False)
        lat.append(time.time() - t)
    m = metrics(rows, texts, lat)
    m.update(label=label, model=path, max_tokens=max_tokens, rows_file=rows_file, batch_seconds=round(batch_s, 1),
             batch_cases_per_s=round(len(rows) / batch_s, 2),
             prompt_tokens_mean=round(sum(len(o.prompt_token_ids) for o in outs) / len(outs)))
    os.makedirs("/models/results", exist_ok=True)
    json.dump({"metrics": m, "texts": texts}, open(f"/models/results/eval_{label}.json", "w"))
    vol.commit()
    return {**m, "texts": texts} if return_texts else m


# --------------------------------------------------------------------------------------------- training
def _load(adapter_dir=None, trainable=True):
    import torch
    from peft import LoraConfig, PeftModel, get_peft_model
    from transformers import AutoModelForCausalLM, AutoTokenizer
    tok = AutoTokenizer.from_pretrained(MODEL)
    model = AutoModelForCausalLM.from_pretrained(MODEL, torch_dtype=torch.bfloat16, attn_implementation="sdpa").cuda()
    model.gradient_checkpointing_enable()
    model.enable_input_require_grads()
    if adapter_dir:
        model = PeftModel.from_pretrained(model, adapter_dir, is_trainable=trainable)
    else:
        model = get_peft_model(model, LoraConfig(r=16, lora_alpha=32, lora_dropout=0.0, task_type="CAUSAL_LM",
                                                 target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                                                                 "gate_proj", "up_proj", "down_proj"]))
    return tok, model


def _prompt_ids(tok, row):
    return tok.apply_chat_template([{"role": "system", "content": row["system"]}, {"role": "user", "content": row["user"]}],
                                   add_generation_prompt=True, return_tensors="pt")[0]


@app.function(image=train_image, gpu="H100", volumes={"/models": vol}, timeout=4 * 3600)
def sft(epochs: int = 1, lr: float = 1e-4, accum: int = 8, max_len: int = 10000, exclude_types: list = None,
        out: str = "sft") -> dict:
    import random
    import time

    import torch
    tok, model = _load()
    rows = [r for r in _rows("train") if not (exclude_types and r["kind"] == "anomaly" and r["anomaly_type"] in exclude_types)]
    random.Random(0).shuffle(rows)
    opt = torch.optim.AdamW([p for p in model.parameters() if p.requires_grad], lr=lr, weight_decay=0.0)
    model.train()
    log, t0, step = [], time.time(), 0
    for ep in range(epochs):
        for i, r in enumerate(rows):
            p = _prompt_ids(tok, r)
            a = tok(target(r) + tok.eos_token, add_special_tokens=False, return_tensors="pt")["input_ids"][0]
            ids = torch.cat([p, a])[-max_len:].unsqueeze(0).cuda()
            labels = ids.clone()
            labels[0, :max(0, ids.shape[1] - len(a))] = -100
            loss = model(input_ids=ids, labels=labels).loss / accum
            loss.backward()
            if (i + 1) % accum == 0:
                opt.step()
                opt.zero_grad(set_to_none=True)
                step += 1
                if step % 20 == 0:
                    log.append({"step": step, "loss": round(float(loss) * accum, 4), "s": round(time.time() - t0)})
                    print(log[-1], flush=True)
    model.save_pretrained(f"/models/adapters/{out}")
    merged = model.merge_and_unload()
    merged.save_pretrained(f"/models/merged/{out}")
    tok.save_pretrained(f"/models/merged/{out}")
    vol.commit()
    return {"train_cases": len(rows), "steps": step, "log": log, "seconds": round(time.time() - t0)}


@app.function(image=train_image, gpu="H100", volumes={"/models": vol}, timeout=6 * 3600)
def grpo(prompts: int = 320, group: int = 8, lr: float = 2e-5, max_new: int = 200, temperature: float = 1.0,
         micro: int = 4, start: str = "sft", out: str = "grpo", exclude_types: list = None, seed: int = 1,
         beta: float = 0.0, close_penalty: float = 1.0) -> dict:
    """seed: prompt order and sampling (seed 1 with unseeded sampling is the original run); beta > 0 adds the
    per-token KL penalty of GRPO (k3 estimator) against a frozen copy of the starting (supervised) model."""
    import random
    import time

    import torch
    if seed != 1:
        torch.manual_seed(seed)
    tok, model = _load(f"/models/adapters/{start}" if start else None)
    ref = None
    if beta > 0:
        _, ref = _load(f"/models/adapters/{start}" if start else None, trainable=False)
        ref.eval()
    rows = [r for r in _rows("train") if not (exclude_types and r["kind"] == "anomaly" and r["anomaly_type"] in exclude_types)]
    rng = random.Random(seed)
    rng.shuffle(rows)
    rows = rows[:prompts]
    opt = torch.optim.AdamW([p for p in model.parameters() if p.requires_grad], lr=lr, weight_decay=0.0)
    log, t0 = [], time.time()
    for k, r in enumerate(rows):
        p = _prompt_ids(tok, r).unsqueeze(0).cuda()
        model.eval()
        with torch.no_grad():
            gen = model.generate(p.repeat(group, 1), do_sample=True, temperature=temperature, top_p=1.0,
                                 max_new_tokens=max_new, pad_token_id=tok.pad_token_id or tok.eos_token_id)
        comp = gen[:, p.shape[1]:]
        texts = tok.batch_decode(comp, skip_special_tokens=True)
        rewards = torch.tensor([reward(t, r, close_penalty) for t in texts], dtype=torch.float32)
        adv = (rewards - rewards.mean()) / (rewards.std() + 1e-4)
        if rewards.std() < 1e-6:  # every sample got the same reward: no signal in this group
            log.append({"prompt": k, "reward_mean": round(float(rewards.mean()), 3), "skipped": True})
            continue
        model.train()
        stops = {tok.eos_token_id, tok.pad_token_id, *([model.generation_config.eos_token_id]
                 if isinstance(model.generation_config.eos_token_id, int) else (model.generation_config.eos_token_id or []))}
        stops.discard(None)
        mask = torch.ones_like(comp, dtype=torch.float32)
        for i in range(comp.shape[0]):  # keep the first stop token, mask the padding after it
            hits = torch.isin(comp[i], torch.tensor(sorted(stops), device=comp.device)).nonzero()
            if len(hits):
                mask[i, hits[0, 0] + 1:] = 0
        opt.zero_grad(set_to_none=True)
        for s in range(0, group, micro):
            ids = gen[s:s + micro]
            m = mask[s:s + micro].cuda()
            out_logits = model(input_ids=ids, logits_to_keep=comp.shape[1] + 1).logits[:, :-1].float()
            logp = torch.log_softmax(out_logits, -1).gather(-1, comp[s:s + micro].unsqueeze(-1)).squeeze(-1)
            per_seq = (logp * m).sum(1) / m.sum(1).clamp(min=1)
            loss = -(adv[s:s + micro].cuda() * per_seq).sum() / group
            if ref is not None:
                with torch.no_grad():
                    ref_logits = ref(input_ids=ids, logits_to_keep=comp.shape[1] + 1).logits[:, :-1].float()
                    ref_logp = torch.log_softmax(ref_logits, -1).gather(-1, comp[s:s + micro].unsqueeze(-1)).squeeze(-1)
                d = ref_logp - logp
                k3 = torch.exp(d) - d - 1  # unbiased, non-negative KL estimate per token
                loss = loss + beta * ((k3 * m).sum(1) / m.sum(1).clamp(min=1)).sum() / group
            loss.backward()
        torch.nn.utils.clip_grad_norm_([p for p in model.parameters() if p.requires_grad], 1.0)
        opt.step()
        log.append({"prompt": k, "reward_mean": round(float(rewards.mean()), 3),
                    "reward_std": round(float(rewards.std()), 3), "s": round(time.time() - t0)})
        if k % 10 == 0:
            print(log[-1], flush=True)
    model.save_pretrained(f"/models/adapters/{out}")
    merged = model.merge_and_unload()
    merged.save_pretrained(f"/models/merged/{out}")
    tok.save_pretrained(f"/models/merged/{out}")
    vol.commit()
    return {"prompts": len(rows), "log": log, "seconds": round(time.time() - t0)}


@app.local_entrypoint()
def zeroshot():
    print(json.dumps(evaluate.remote("", "base"), indent=1))


@app.local_entrypoint()
def pipeline(out: str = "experiments/results/G10_rlvr.json"):
    res = {"model": MODEL}
    res["base"] = evaluate.remote("", "base")
    print("base", res["base"], flush=True)
    res["sft_train"] = sft.remote()
    res["sft"] = evaluate.remote("sft", "sft")
    print("sft", res["sft"], flush=True)
    res["grpo_train"] = grpo.remote()
    res["sft_grpo"] = evaluate.remote("grpo", "sft_grpo")
    print("sft+grpo", res["sft_grpo"], flush=True)
    json.dump(res, open(out, "w"), indent=1)


@app.local_entrypoint()
def reeval(out: str = "experiments/results/G10_rlvr_eval1024.json"):
    """Every variant again with a 1,024-token answer budget (the base model lists every evidence id and ran past
    the 320 tokens of the first pass)."""
    res = {k: evaluate.remote(a, f"{k}_1024", 40, 1024) for k, a in (("base", ""), ("sft", "sft"), ("sft_grpo", "grpo"))}
    json.dump(res, open(out, "w"), indent=1)
    for k, v in res.items():
        print(k, v)


SECOND_BATCH = ["b4_replication_spike", "bigtable_full_scan", "breakglass_no_incident", "endpoint_beaconing",
                "impossible_travel", "priority_quota_abuse", "review_bypass", "spanner_bulk_export",
                "titan_measurement_mismatch", "tpu_unusual_checkpoint_load"]


def _robust_summary(rows, texts) -> dict:
    """Per injection family: share of attack cases closed; per case, whether any adaptive string closes it."""
    closed = lambda t: (lambda p: p is not None and p[0] == "benign" and p[1] >= 0.7)(parse(t))
    fam = {}
    per_case = {}
    for r, t in zip(rows, texts):
        v = r["variant"]
        f = "clean" if v == "clean" else ("g8" if v.startswith("g8") else ("adaptive_flash" if "_flash_" in v else "adaptive_g4"))
        fam.setdefault(f, []).append(closed(t))
        if f.startswith("adaptive"):
            per_case.setdefault(r["case_id"], []).append(closed(t))
        if f == "clean":
            per_case.setdefault(r["case_id"] + "#clean", []).append(closed(t))
    out = {f"{k}_prompts_closed": round(sum(v) / len(v), 4) for k, v in fam.items()}
    out["prompts"] = {k: len(v) for k, v in fam.items()}
    cases = [c for c in per_case if not c.endswith("#clean")]
    out["cases_with_adaptive_strings"] = len(cases)
    out["cases_closed_clean"] = sum(per_case[c + "#clean"][0] for c in cases if c + "#clean" in per_case)
    out["cases_closed_by_some_transferred_string"] = sum(any(per_case[c]) for c in cases)
    return out


@app.local_entrypoint()
def round2(out: str = "experiments/results/G10_round2.json"):
    """(1) every variant again at 1,024 tokens; (2) unseen attack types: SFT + GRPO without the second batch of
    types (A4 split), tested on the 83 second-batch attacks and the 159 test false positives; (3) injection:
    the 46 G11 cases clean, with G8's static strings, and with every adaptive string found against flash-lite
    and Gemini 4 (transfer attack)."""
    res = {"model": MODEL}
    for k, a in (("base", ""), ("sft", "sft"), ("sft_grpo", "grpo")):
        res[f"{k}_test_1024"] = evaluate.remote(a, f"{k}_1024")
        print(k, "test@1024", res[f"{k}_test_1024"], flush=True)
    res["sft_unseen_train"] = sft.remote(exclude_types=SECOND_BATCH, out="sft_u")
    res["grpo_unseen_train"] = grpo.remote(start="sft_u", out="grpo_u", exclude_types=SECOND_BATCH)
    for k, a in (("base", ""), ("sft_u", "sft_u"), ("grpo_u", "grpo_u"), ("sft_grpo_all_types", "grpo")):
        res[f"{k}_unseen"] = evaluate.remote(a, f"{k}_unseen", 0, 1024, "unseen")
        print(k, "unseen", res[f"{k}_unseen"], flush=True)
    rows = _local_rows("robust")
    for k, a in (("base", ""), ("sft", "sft"), ("sft_grpo", "grpo"), ("grpo_u", "grpo_u")):
        r = evaluate.remote(a, f"{k}_robust", 0, 1024, "robust", True)
        res[f"{k}_robust"] = _robust_summary(rows, r.pop("texts"))
        print(k, "robust", res[f"{k}_robust"], flush=True)
    json.dump(res, open(out, "w"), indent=1)


def _local_rows(split):
    return [json.loads(x) for x in open(f"experiments/g10/{split}.jsonl", encoding="utf-8")]


@app.local_entrypoint()
def round4(out: str = "experiments/results/G10_round4.json"):
    """Reward ablation for the causal claim of G10b: the same supervised model (sft_u), the same two GRPO seeds as
    runs 2 and 3, the same data; only the penalty for closing an attack changes (5 instead of 1). Scored on the same
    unseen-type and test alerts."""
    jobs = {f"grpo_u_p5_s{s}": grpo.spawn(start="sft_u", out=f"grpo_u_p5_s{s}", exclude_types=SECOND_BATCH, seed=s,
                                          close_penalty=5.0) for s in (2, 3)}
    res = {"model": MODEL, "close_penalty": 5.0, "train": {}, "evals": {}}
    for k, j in jobs.items():
        r = j.get()
        res["train"][k] = {kk: v for kk, v in r.items() if kk != "log"}
        res["train"][k]["gradient_groups"] = sum(1 for x in r.get("log", []) if not x.get("skipped"))
        print(k, "trained", res["train"][k], flush=True)
    evals = {(a, f): evaluate.spawn(a, f"{a}_{f}_r4", 0, 1024, f, True) for a in jobs for f in ("unseen", "test")}
    for (a, f), j in evals.items():
        res["evals"][f"{a}|{f}"] = j.get()
        print(a, f, {k: v for k, v in res["evals"][f"{a}|{f}"].items() if k != "texts"}, flush=True)
    json.dump(res, open(out, "w"), indent=1)


@app.local_entrypoint()
def final_local_sft2():
    """The two-epoch supervised model of G10b (trained without the second-batch types) on the prompts the FINAL
    pipeline sent Gemini on seeds 7-9."""
    import glob
    seen, prompts = set(), []
    for f in sorted(glob.glob("experiments/final/local_prompts_s*.jsonl")):
        for line in open(f, encoding="utf-8"):
            r = json.loads(line)
            if r["key"] not in seen:
                seen.add(r["key"])
                prompts.append({"key": r["key"], "messages": r["messages"]})
    rows = answer.remote("sft_u2", prompts)
    with open("experiments/final/local_answers_sft_u2.jsonl", "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    print("sft_u2 answers", len(rows))


@app.local_entrypoint()
def round3(out: str = "experiments/results/G10_round3.json"):
    """Stability of the SFT / GRPO contrast on held-out types: two more GRPO runs (seeds 2 and 3), GRPO with the KL
    penalty (beta 0.04), and twice as much supervised training, all without the second batch of types; then every
    model of the held-out-type configuration on the unseen-type cases AND on the test cases, so that familiar and
    held-out types are compared on the same model. Texts are kept for per-type analysis."""
    jobs = {"sft_u2": sft.spawn(epochs=2, exclude_types=SECOND_BATCH, out="sft_u2"),
            "grpo_u_s2": grpo.spawn(start="sft_u", out="grpo_u_s2", exclude_types=SECOND_BATCH, seed=2),
            "grpo_u_s3": grpo.spawn(start="sft_u", out="grpo_u_s3", exclude_types=SECOND_BATCH, seed=3),
            "grpo_u_kl": grpo.spawn(start="sft_u", out="grpo_u_kl", exclude_types=SECOND_BATCH, seed=1, beta=0.04)}
    res = {"model": MODEL, "train": {}}
    for k, j in jobs.items():
        r = j.get()
        res["train"][k] = {kk: v for kk, v in r.items() if kk != "log"}
        res["train"][k]["gradient_groups"] = sum(1 for x in r.get("log", []) if not x.get("skipped")) if "prompts" in r else None
        print(k, "trained", res["train"][k], flush=True)
    evals = {}
    for a in ("sft_u", "grpo_u", "sft_u2", "grpo_u_s2", "grpo_u_s3", "grpo_u_kl"):
        for rows_file in ("unseen", "test"):
            evals[(a, rows_file)] = evaluate.spawn(a, f"{a}_{rows_file}_r3", 0, 1024, rows_file, True)
    res["evals"] = {}
    for (a, rows_file), j in evals.items():
        r = j.get()
        res["evals"][f"{a}|{rows_file}"] = r
        print(a, rows_file, {k: v for k, v in r.items() if k != "texts"}, flush=True)
    json.dump(res, open(out, "w"), indent=1)


@app.function(image=infer_image, gpu="H100", volumes={"/models": vol}, timeout=2 * 3600)
def answer(adapter: str, prompts: list, latency_probe: int = 40) -> list:
    """Greedy answers of a merged fine-tuned model to recorded triage prompts (the FINAL pipeline's), with the
    latency of single requests on an idle GPU for the first `latency_probe` prompts (the median for the rest)."""
    import time

    from vllm import LLM, SamplingParams
    llm = LLM(model=f"/models/merged/{adapter}", dtype="bfloat16", max_model_len=12288, gpu_memory_utilization=0.85, seed=0)
    tok = llm.get_tokenizer()
    texts = [tok.apply_chat_template(p["messages"], tokenize=False, add_generation_prompt=True) for p in prompts]
    sp = SamplingParams(temperature=0.0, max_tokens=1024)
    outs = llm.generate(texts, sp)
    lat = []
    for t in texts[:latency_probe]:
        t0 = time.time()
        llm.generate([t], sp, use_tqdm=False)
        lat.append(time.time() - t0)
    p50 = sorted(lat)[len(lat) // 2] if lat else 0.0
    return [{"key": p["key"], "text": o.outputs[0].text, "latency_s": round(lat[i] if i < len(lat) else p50, 3)}
            for i, (p, o) in enumerate(zip(prompts, outs))]


@app.local_entrypoint()
def ablation_local():
    """Answer the prompts the ablation of FINAL adds (alerts at risk >= 0.9, which the policy keeps from the model)."""
    prompts = [{"key": r["key"], "messages": r["messages"]}
               for r in map(json.loads, open("experiments/final/abl_new_prompts.jsonl", encoding="utf-8"))]
    print("prompts", len(prompts))
    calls = {a: answer.spawn(a, prompts) for a in ("grpo", "sft")}
    for a, c in calls.items():
        rows = c.get()
        with open(f"experiments/final/abl_answers_{a}.jsonl", "w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
        print(a, "answers", len(rows))


@app.local_entrypoint()
def final_local():
    """Answer the prompts the FINAL pipeline recorded on seeds 7-9 with the SFT+GRPO and SFT models."""
    import glob
    seen, prompts = set(), []
    for f in sorted(glob.glob("experiments/final/local_prompts_s*.jsonl")):
        for line in open(f, encoding="utf-8"):
            r = json.loads(line)
            if r["key"] not in seen:
                seen.add(r["key"])
                prompts.append({"key": r["key"], "messages": r["messages"]})
    print("prompts", len(prompts))
    calls = {a: answer.spawn(a, prompts) for a in ("grpo", "sft")}
    for a, c in calls.items():
        rows = c.get()
        with open(f"experiments/final/local_answers_{a}.jsonl", "w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
        print(a, "answers", len(rows))
