"""
================================================================================
deployment_metrics — deployment metrics (descriptive)
================================================================================
  confusion / prf / macro_f1    multiclass from a confusion matrix (same definition as the evaluator:
                                zero_division 0)
  binary_metrics                detection rate, precision, Benign FPR (raw alerts: flows with >= 1 alert)
  bootstrap_files               bootstrap CI over PCAP files (clusters): macro F1, Benign FPR, F1 per class,
                                differences between methods; classes with ground-truth flows from one file ->
                                "cannot be computed"
All functions are pure (no I/O); input = per-flow tables that already hold the ground-truth label and the
Suricata decision.
================================================================================
"""
from __future__ import annotations

from typing import Dict, Optional, Sequence

import numpy as np
import pandas as pd

BENIGN = "BENIGN"


def confusion(y: Sequence, p: Sequence, classes: Sequence[str]) -> np.ndarray:
    """Rows = ground truth, columns = prediction; labels outside classes are ignored (filter them first)."""
    idx = {c: i for i, c in enumerate(classes)}
    yi = pd.Series(y).map(idx).to_numpy()
    pi = pd.Series(p).map(idx).to_numpy()
    ok = ~(pd.isna(yi) | pd.isna(pi))
    K = len(classes)
    return np.bincount(yi[ok].astype(np.int64) * K + pi[ok].astype(np.int64), minlength=K * K).reshape(K, K)


def prf(cm: np.ndarray):
    tp = np.diag(cm).astype(float)
    sup = cm.sum(axis=1).astype(float)
    pred = cm.sum(axis=0).astype(float)
    p = np.divide(tp, pred, out=np.zeros_like(tp), where=pred > 0)
    r = np.divide(tp, sup, out=np.zeros_like(tp), where=sup > 0)
    f = np.divide(2 * p * r, p + r, out=np.zeros_like(tp), where=(p + r) > 0)
    return p, r, f, sup


def macro_f1(cm: np.ndarray, classes: Sequence[str], exclude: Sequence[str] = (), present_only: bool = True) -> float:
    """Mean F1 over the classes. present_only: only classes with support > 0 (for bootstrap replicates that do
    not contain every class); when all classes are present the result equals the evaluator (f1.mean())."""
    _, _, f, sup = prf(cm)
    keep = np.array([c not in exclude for c in classes]) & ((sup > 0) if present_only else True)
    return float(f[keep].mean()) if keep.any() else float("nan")


def per_class_table(cm: np.ndarray, classes: Sequence[str]) -> pd.DataFrame:
    p, r, f, sup = prf(cm)
    return pd.DataFrame({"class": list(classes), "precision": p, "recall": r, "f1": f, "support": sup.astype(int),
                         "predicted": cm.sum(axis=0).astype(int)})


def binary_metrics(is_attack: np.ndarray, alerted: np.ndarray, is_benign: Optional[np.ndarray] = None) -> Dict:
    """Detection rate = attack flows with >= 1 alert / attack flows; precision = alerted attack flows / alerted
    flows; Benign FPR = BENIGN flows with >= 1 alert / BENIGN flows."""
    is_attack = np.asarray(is_attack, bool)
    alerted = np.asarray(alerted, bool)
    is_benign = ~is_attack if is_benign is None else np.asarray(is_benign, bool)
    n_att, n_ben = int(is_attack.sum()), int(is_benign.sum())
    tp, fp = int((is_attack & alerted).sum()), int((is_benign & alerted).sum())
    return {"n_attack": n_att, "n_benign": n_ben, "tp": tp, "fp": fp,
            "dr": tp / n_att if n_att else float("nan"),
            "precision": tp / (tp + fp) if (tp + fp) else float("nan"),
            "benign_fpr": fp / n_ben if n_ben else float("nan")}


# ----------------------------------------------------------------------------
# Bootstrap over files (clusters)
# ----------------------------------------------------------------------------
def bootstrap_files(cms: Dict[str, np.ndarray], ben: Dict[str, np.ndarray], classes: Sequence[str],
                    class_files: Dict[str, int], *, n_rep: int = 1000, seed: int = 1011,
                    exclude_sets: Dict[str, Sequence[str]] = None, alpha: float = 0.05) -> Dict:
    """cms[method] = (F, K, K) confusion matrices per file; ben[method] = (F, 2) [alerted BENIGN flows, BENIGN
    flows]. A replicate = F files drawn with replacement (rng default_rng(seed), the same for all methods ->
    paired differences). Returns point + percentile CI for macro F1 (each exclude set), Benign FPR, F1 per class,
    and the differences between methods. Classes with ground-truth flows from < 2 files -> per-class CI None."""
    exclude_sets = exclude_sets or {"all": ()}
    methods = list(cms)
    F = next(iter(cms.values())).shape[0]
    rng = np.random.default_rng(seed)
    W = np.stack([np.bincount(rng.integers(0, F, F), minlength=F) for _ in range(n_rep)]).astype(float)
    q = [100 * alpha / 2, 100 * (1 - alpha / 2)]
    out: Dict = {"n_files": F, "n_rep": n_rep, "seed": seed, "methods": {}, "diff": {}}
    reps: Dict[str, Dict[str, np.ndarray]] = {}
    for m in methods:
        cm_rep = np.tensordot(W, cms[m], axes=(1, 0))          # (R, K, K)
        b_rep = W @ ben[m]                                      # (R, 2)
        r = {f"macro_f1_{k}": np.array([macro_f1(c, classes, ex) for c in cm_rep]) for k, ex in exclude_sets.items()}
        r["benign_fpr"] = np.divide(b_rep[:, 0], b_rep[:, 1], out=np.full(n_rep, np.nan), where=b_rep[:, 1] > 0)
        f_rep = np.stack([prf(c)[2] for c in cm_rep])
        sup_rep = np.stack([c.sum(axis=1) for c in cm_rep])
        tot = cms[m].sum(axis=0)
        point = {f"macro_f1_{k}": macro_f1(tot, classes, ex) for k, ex in exclude_sets.items()}
        bt = ben[m].sum(axis=0)
        point["benign_fpr"] = float(bt[0] / bt[1]) if bt[1] else float("nan")
        res = {k: {"point": point[k], "ci": [float(np.nanpercentile(v, q[0])), float(np.nanpercentile(v, q[1]))]}
               for k, v in r.items()}
        pc = {}
        f_point = prf(tot)[2]
        for i, c in enumerate(classes):
            if class_files.get(c, 0) < 2:
                pc[c] = {"point": float(f_point[i]), "ci": None, "note": "cannot be computed (ground-truth flows from one file)"}
            else:
                v = np.where(sup_rep[:, i] > 0, f_rep[:, i], np.nan)
                pc[c] = {"point": float(f_point[i]), "ci": [float(np.nanpercentile(v, q[0])),
                                                            float(np.nanpercentile(v, q[1]))]}
        res["f1_per_class"] = pc
        out["methods"][m] = res
        reps[m] = r
    for i, a in enumerate(methods):
        for b in methods[i + 1:]:
            d = {}
            for k in reps[a]:
                v = reps[a][k] - reps[b][k]
                pa, pb = out["methods"][a][k]["point"], out["methods"][b][k]["point"]
                d[k] = {"point": pa - pb, "ci": [float(np.nanpercentile(v, q[0])), float(np.nanpercentile(v, q[1]))]}
            out["diff"][f"{a}-{b}"] = d
    return out
