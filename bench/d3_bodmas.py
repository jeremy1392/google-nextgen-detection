"""D3 on BODMAS (Yang et al., DLS 2021): temporal drift of a static PE classifier over 14 months.

    python -m bench.d3_bodmas [--data experiments/data/bodmas] [--train-months 3]

BODMAS gives EMBER-format feature vectors (2,381 features, LIEF 0.9.0) for 57,293 malware and 77,142 benign
PE files first seen between August 2019 and September 2020, with the first-seen time and the malware family.
Only feature vectors are used here (no binary). Protocol, after TESSERACT (Pendlebury et al., USENIX
Security 2019): train on the first --train-months months, then test on every later month on its own.
  static     one model trained once; threshold for 1e-3 / 1e-2 FPR set on the benign files of the training
             period's last 10% (by time), kept fixed: what a deployed model meets
  retrain    every month, retrain on everything seen before that month (same threshold rule)
For each test month: ROC-AUC, TPR at the fixed thresholds, the false-positive rate those thresholds really
give, TPR at an oracle threshold set on the month itself, and the TPR on families seen / never seen in training.
Results: experiments/results/D3_bodmas_drift.json
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import time
from collections import defaultdict
from datetime import datetime, timezone

OUT = "experiments/results/D3_bodmas_drift.json"
PARAMS = {"objective": "binary", "learning_rate": 0.05, "num_leaves": 256, "feature_fraction": 0.5,
          "bagging_fraction": 0.5, "bagging_freq": 1, "min_data_in_leaf": 20, "verbose": -1, "num_threads": 12,
          "seed": 0}
ROUNDS = 600


def _month(ts: str) -> str:
    ts = ts.strip()
    for fmt in ("%Y-%m-%d %H:%M:%S%z", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d"):
        try:
            d = datetime.strptime(ts, fmt)
            return d.strftime("%Y-%m")
        except ValueError:
            continue
    return ts[:7]


def load(root: str):
    import numpy as np
    d = np.load(os.path.join(root, "bodmas.npz"))
    X, y = d["X"], d["y"].astype(int)
    meta = list(csv.DictReader(open(os.path.join(root, "bodmas_metadata.csv"), encoding="utf-8")))
    assert len(meta) == len(y), (len(meta), len(y))
    tcol = next(k for k in meta[0] if "time" in k.lower())
    fcol = next((k for k in meta[0] if "family" in k.lower()), None)
    months = [_month(r[tcol]) for r in meta]
    fams = [(r.get(fcol) or "") if fcol else "" for r in meta]
    return X, y, months, fams


def _fit(X, y):
    import lightgbm as lgb
    return lgb.train(PARAMS, lgb.Dataset(X, y), ROUNDS)


def _thr(scores_benign, fpr):
    import numpy as np
    s = np.sort(scores_benign)[::-1]
    k = int(np.floor(fpr * len(s)))
    return float(s[k]) if len(s) > k else float(s[-1])


def _eval(model, X, y, fams, seen_fams, thr):
    import numpy as np
    from sklearn.metrics import roc_auc_score
    p = model.predict(X)
    ben, mal = p[y == 0], p[y == 1]
    out = {"n_mal": int((y == 1).sum()), "n_ben": int((y == 0).sum()),
           "auc": round(float(roc_auc_score(y, p)), 5) if 0 < y.sum() < len(y) else None}
    for name, t in thr.items():
        out[f"tpr_at_train_thr_{name}"] = round(float((mal > t).mean()), 4) if len(mal) else None
        out[f"real_fpr_at_train_thr_{name}"] = round(float((ben > t).mean()), 5) if len(ben) else None
        out[f"tpr_at_month_thr_{name}"] = round(float((mal > _thr(ben, float(name))).mean()), 4) if len(ben) and len(mal) else None
    f = np.array(fams)
    known = np.array([x in seen_fams for x in fams])
    m_known, m_new = (y == 1) & known, (y == 1) & ~known
    t3 = thr["1e-3"]
    out["share_malware_new_family"] = round(float(m_new.sum() / max((y == 1).sum(), 1)), 4)
    out["tpr_known_family_1e-3"] = round(float((p[m_known] > t3).mean()), 4) if m_known.any() else None
    out["tpr_new_family_1e-3"] = round(float((p[m_new] > t3).mean()), 4) if m_new.any() else None
    return out


def run(root: str, train_months: int) -> dict:
    import numpy as np
    X, y, months, fams = load(root)
    months = np.array(months)
    order = sorted({m for m, lab in zip(months, y) if lab == 1})  # the malware window, 2019-08 .. 2020-09
    train_set = order[:train_months]
    tests = order[train_months:]
    res = {"data": "BODMAS", "files": int(len(y)), "malware": int(y.sum()), "benign": int((y == 0).sum()),
           "months": {m: {"mal": int(((months == m) & (y == 1)).sum()), "ben": int(((months == m) & (y == 0)).sum())}
                      for m in order},
           "benign_before_window": int(((months < order[0]) & (y == 0)).sum()),
           "train_months": train_set, "params": PARAMS, "rounds": ROUNDS, "static": {}, "retrain": {}}

    def threshold_split(idx):
        idx = np.array(sorted(idx, key=lambda i: months[i]))  # time order inside the window
        cut = int(len(idx) * 0.9)
        return idx[:cut], idx[cut:]

    tr = np.where(months <= train_set[-1])[0]  # benign files first seen before the window belong to training
    fit_idx, cal_idx = threshold_split(tr)
    t0 = time.time()
    model = _fit(X[fit_idx], y[fit_idx])
    pc = model.predict(X[cal_idx])
    thr = {k: _thr(pc[y[cal_idx] == 0], float(k)) for k in ("1e-3", "1e-2")}
    seen = {fams[i] for i in tr if y[i] == 1}
    res["static_train_s"] = round(time.time() - t0, 1)
    for m in tests:
        ix = np.where(months == m)[0]
        res["static"][m] = _eval(model, X[ix], y[ix], [fams[i] for i in ix], seen, thr)
        print("static", m, res["static"][m]["auc"], res["static"][m]["tpr_at_train_thr_1e-3"], flush=True)
    for k, m in enumerate(tests):
        past = np.where(months < m)[0]
        fi, ci = threshold_split(past)
        mod = _fit(X[fi], y[fi])
        pc = mod.predict(X[ci])
        th = {kk: _thr(pc[y[ci] == 0], float(kk)) for kk in ("1e-3", "1e-2")}
        seen_k = {fams[i] for i in past if y[i] == 1}
        ix = np.where(months == m)[0]
        res["retrain"][m] = _eval(mod, X[ix], y[ix], [fams[i] for i in ix], seen_k, th)
        print("retrain", m, res["retrain"][m]["auc"], res["retrain"][m]["tpr_at_train_thr_1e-3"], flush=True)
    return res


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="bench.d3_bodmas")
    p.add_argument("--data", default="experiments/data/bodmas")
    p.add_argument("--train-months", type=int, default=3)
    a = p.parse_args(argv)
    res = run(a.data, a.train_months)
    json.dump(res, open(OUT, "w", encoding="utf-8"), indent=1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
