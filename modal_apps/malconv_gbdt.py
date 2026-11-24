"""Feature-based references for D1, on exactly the same real binaries and split as MalConv.

    modal run modal_apps/malconv_gbdt.py::features      # EMBER v2 features of every file (parallel, per shard)
    modal run modal_apps/malconv_gbdt.py                # train / evaluate, writes /data/results/<model>/

Models:
  lightgbm_ember   LightGBM on EMBER v2 features (2,381 dims), the EMBER paper's parameters, trained here
  sorel_lgbm_s0-4  the five LightGBM models published with SOREL-20M, applied unchanged to our files
  bytehist_lr      logistic regression on the normalized byte histogram (first 256 EMBER features)
EMBER feature version 2 is defined with LIEF 0.9 / 0.10; this image pins Python 3.8 + LIEF 0.10.1, the
combination the EMBER authors verified. The split comes from /data/splits.csv (see malconv_train.py).
"""
from __future__ import annotations

import modal

app = modal.App("malconv-gbdt")
vol = modal.Volume.from_name("malconv-data", create_if_missing=False)
# EMBER feature version 2 needs LIEF 0.9 / 0.10, whose wheels stop at Python 3.8, which Modal's runtime no
# longer supports: the container carries both a Python 3.8 (EMBER + LIEF 0.10.1, run as a subprocess) and the
# Python 3.11 that Modal runs the functions with.
ember_image = (modal.Image.micromamba(python_version="3.11")
               .apt_install("git")
               .run_commands("micromamba create -y -p /opt/py38 -c conda-forge python=3.8 pip",
                             "/opt/py38/bin/pip install --no-cache-dir lief==0.10.1 numpy==1.21.6 scikit-learn==1.0.2 tqdm",
                             "git clone --depth 1 https://github.com/elastic/ember /opt/ember")
               .pip_install("numpy==1.26.4"))
image = modal.Image.debian_slim(python_version="3.11").pip_install(
    "numpy==1.26.4", "scikit-learn==1.5.2", "scipy==1.14.1", "lightgbm==4.5.0", "boto3")

VEC_SCRIPT = """
import json, sys, zlib
from multiprocessing import Pool
import numpy as np
sys.path.insert(0, "/opt/ember/ember")  # the features module alone: the package __init__ pulls pandas / lightgbm
from features import PEFeatureExtractor

def work(chunk):
    path, items = chunk
    ext = PEFeatureExtractor(feature_version=2)
    shas, rows, failed = [], [], 0
    with open(path, "rb") as f:
        for sha, off, ln in items:
            f.seek(off)
            data = zlib.decompress(f.read(ln))
            try:
                rows.append(np.asarray(ext.feature_vector(data), dtype=np.float32))
                shas.append(sha)
            except Exception:
                failed += 1
    return shas, rows, failed

if __name__ == "__main__":
    path, items_json, out = sys.argv[1:4]
    items = json.load(open(items_json))
    with Pool(8) as pool:
        parts = pool.map(work, [(path, items[i::8]) for i in range(8)])
    shas = [s for p in parts for s in p[0]]
    X = np.stack([r for p in parts for r in p[1]]) if shas else np.zeros((0, 2381), np.float32)
    np.savez(out, shas=np.array(shas), X=X)
    print(json.dumps({"n": len(shas), "failed": sum(p[2] for p in parts)}))
"""


@app.function(image=ember_image, volumes={"/data": vol}, timeout=6 * 3600, cpu=8, memory=16384)
def shard_features(shard: str, items: list):
    import json
    import os
    import subprocess
    root = ("/data/malware" if shard.startswith("mal") else
            "/data/benign_" + shard.split("-")[0][4:] if shard.startswith("ben_") else "/data/benign")
    open("/tmp/vec.py", "w").write(VEC_SCRIPT)
    json.dump(items, open("/tmp/items.json", "w"))
    os.makedirs("/data/features/ember", exist_ok=True)
    out = subprocess.run(["/opt/py38/bin/python", "/tmp/vec.py", f"{root}/{shard}", "/tmp/items.json",
                          f"/data/features/ember/{shard}.npz"], capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(out.stderr[-2000:])
    vol.commit()
    res = json.loads(out.stdout.strip().splitlines()[-1])
    return shard, res["n"], res["failed"]


@app.function(image=image, volumes={"/data": vol}, timeout=600)
def plan_shards():
    import csv
    groups = {}
    for r in csv.DictReader(open("/data/splits.csv")):
        groups.setdefault(r["shard"], []).append((r["sha256"], int(r["offset"]), int(r["length"])))
    return groups


@app.local_entrypoint()
def features():
    groups = plan_shards.remote()
    done = 0
    for shard, n, failed in shard_features.starmap([(s, it) for s, it in groups.items()]):
        done += n
        print(f"{shard}: {n} vectors, {failed} unparsable (total {done})", flush=True)


def _tpr_at(y, p, fpr):
    import numpy as np
    from scipy.stats import beta
    neg = np.sort(p[y == 0])[::-1]
    k = int(np.floor(fpr * len(neg)))
    thr = neg[k] if k < len(neg) else neg[-1]
    tp = int(((p > thr) & (y == 1)).sum())
    n = int((y == 1).sum())
    lo = beta.ppf(0.025, tp, n - tp + 1) if tp > 0 else 0.0
    hi = beta.ppf(0.975, tp + 1, n - tp) if tp < n else 1.0
    return {"fpr_target": fpr, "threshold": float(thr), "tpr": tp / max(n, 1), "tpr_ci95": [float(lo), float(hi)],
            "negatives": len(neg)}


@app.function(image=image, volumes={"/data": vol}, timeout=12 * 3600, cpu=16, memory=131072)
def train_eval():
    import csv
    import glob
    import json
    import os

    import boto3
    import lightgbm as lgb
    import numpy as np
    from botocore import UNSIGNED
    from botocore.config import Config
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import average_precision_score, roc_auc_score

    split = {r["sha256"]: (int(r["label"]), r["split"]) for r in csv.DictReader(open("/data/splits.csv"))}
    feats = {}
    for f in glob.glob("/data/features/ember/*.npz"):
        z = np.load(f)
        for s, x in zip(z["shas"], z["X"]):
            feats[str(s)] = x
    sets = {}
    for s, (y, sp) in split.items():
        if s in feats:
            sets.setdefault(sp, ([], [], []))
            sets[sp][0].append(feats[s])
            sets[sp][1].append(y)
            sets[sp][2].append(s)
    data = {k: (np.stack(v[0]), np.array(v[1]), v[2]) for k, v in sets.items()}
    Xtr, ytr, _ = data["train"]
    Xva, yva, _ = data["val"]
    test_sets = {"test": data["test"]}
    if "test_unseen_toolchain" in data:  # newest malware vs benign from an unseen toolchain
        Xt, yt, st = data["test"]
        Xu, yu, su = data["test_unseen_toolchain"]
        m = yt == 1
        test_sets["test_unseen_toolchain"] = (np.concatenate([Xt[m], Xu]), np.concatenate([yt[m], yu]),
                                              [s for s, k in zip(st, m) if k] + su)

    models = {}
    params = {"boosting": "gbdt", "objective": "binary", "num_iterations": 1000, "learning_rate": 0.05,
              "num_leaves": 2048, "max_depth": 15, "min_data_in_leaf": 50, "feature_fraction": 0.5, "verbose": -1}
    booster = lgb.train(params, lgb.Dataset(Xtr, ytr), valid_sets=[lgb.Dataset(Xva, yva)],
                        callbacks=[lgb.early_stopping(50, verbose=False)])
    models["lightgbm_ember"] = lambda X: booster.predict(X, num_iteration=booster.best_iteration)
    lr = LogisticRegression(max_iter=2000, class_weight="balanced").fit(Xtr[:, :256], ytr)
    models["bytehist_lr"] = lambda X: lr.predict_proba(X[:, :256])[:, 1]
    s3 = boto3.client("s3", config=Config(signature_version=UNSIGNED))
    for seed in range(5):
        path = f"/tmp/sorel_lgbm_{seed}.model"
        s3.download_file("sorel-20m", f"09-DEC-2020/baselines/checkpoints/lightGBM/seed{seed}/lightgbm.model", path)
        b = lgb.Booster(model_file=path)
        models[f"sorel_lgbm_s{seed}"] = (lambda bb: (lambda X: bb.predict(X)))(b)

    report = {"train": {"n": int(len(ytr)), "malware": int(ytr.sum())}, "best_iteration": booster.best_iteration}
    for name, fn in models.items():
        os.makedirs(f"/data/results/{name}", exist_ok=True)
        report[name] = {}
        for tname, (X, y, shas) in test_sets.items():
            p = np.asarray(fn(X), dtype=float)
            with open(f"/data/results/{name}/scores_{tname}.csv", "w") as f:
                f.write("sha256,label,score\n")
                f.writelines(f"{s},{int(a)},{b:.6f}\n" for s, a, b in zip(shas, y, p))
            report[name][tname] = {"n_mal": int(y.sum()), "n_ben": int((1 - y).sum()),
                                   "roc_auc": float(roc_auc_score(y, p)), "pr_auc": float(average_precision_score(y, p)),
                                   "tpr_at_fpr": [_tpr_at(y, p, f) for f in (1e-2, 1e-3, 1e-4)]}
    json.dump(report, open("/data/results/gbdt_report.json", "w"), indent=1)
    vol.commit()
    return report


GROUPS = {"byte_histogram": (0, 256), "byte_entropy": (256, 512), "strings": (512, 616), "general": (616, 626),
          "header": (626, 688), "sections": (688, 943), "imports": (943, 2223), "exports": (2223, 2351),
          "data_directories": (2351, 2381)}


@app.function(image=image, volumes={"/data": vol}, timeout=8 * 3600, cpu=16, memory=131072)
def group_ablation():
    """Which EMBER feature groups carry the separation? LightGBM on each group alone and on all groups but one."""
    import csv
    import glob
    import json

    import lightgbm as lgb
    import numpy as np
    from sklearn.metrics import roc_auc_score
    split = {r["sha256"]: (int(r["label"]), r["split"]) for r in csv.DictReader(open("/data/splits.csv"))}
    X, y, sp = [], [], []
    for f in glob.glob("/data/features/ember/*.npz"):
        z = np.load(f)
        for s, x in zip(z["shas"], z["X"]):
            if str(s) in split:
                X.append(x)
                y.append(split[str(s)][0])
                sp.append(split[str(s)][1])
    X, y, sp = np.stack(X), np.array(y), np.array(sp)
    tr, te, un = sp == "train", sp == "test", (sp == "test_unseen_toolchain") | ((sp == "test") & (y == 1))
    params = {"objective": "binary", "num_leaves": 256, "learning_rate": 0.1, "num_iterations": 300,
              "feature_fraction": 0.8, "verbose": -1}

    def fit_eval(cols):
        b = lgb.train(params, lgb.Dataset(X[tr][:, cols], y[tr]))
        out = {}
        for name, m in (("test", te), ("unseen_toolchain", un)):
            p = b.predict(X[m][:, cols])
            yy = y[m]
            neg = np.sort(p[yy == 0])[::-1]
            thr = neg[int(len(neg) * 1e-3)]
            out[name] = {"auc": round(float(roc_auc_score(yy, p)), 5),
                         "tpr_at_fpr_1e-3": round(float(((p > thr) & (yy == 1)).sum() / max((yy == 1).sum(), 1)), 4)}
        return out

    res = {"alone": {}, "all_but": {}}
    for g, (a, b) in GROUPS.items():
        res["alone"][g] = fit_eval(list(range(a, b)))
        res["all_but"][g] = fit_eval([i for i in range(2381) if not a <= i < b])
    json.dump(res, open("/data/results/ember_group_ablation.json", "w"), indent=1)
    vol.commit()
    return res


@app.local_entrypoint()
def ablation(out: str = "experiments/results/D1_ember_group_ablation.json"):
    import json
    import os
    res = group_ablation.remote()
    os.makedirs(os.path.dirname(out), exist_ok=True)
    json.dump(res, open(out, "w"), indent=1)
    for kind in ("alone", "all_but"):
        for g, v in res[kind].items():
            print(f"{kind:<8} {g:<18} test AUC {v['test']['auc']}  TPR@1e-3 {v['test']['tpr_at_fpr_1e-3']}  "
                  f"unseen AUC {v['unseen_toolchain']['auc']}")


@app.local_entrypoint()
def main(out: str = "experiments/results/D1_feature_models.json"):
    import json
    import os
    rep = train_eval.remote()
    os.makedirs(os.path.dirname(out), exist_ok=True)
    json.dump(rep, open(out, "w"), indent=1)
    for name, v in rep.items():
        if isinstance(v, dict) and "test" in v:
            t = v["test"]
            print(f"{name:<18} AUC {t['roc_auc']:.4f}  TPR@1e-3 {t['tpr_at_fpr'][1]['tpr']:.3f}  "
                  f"unseen-toolchain AUC {v.get('test_unseen_toolchain', {}).get('roc_auc')}")
