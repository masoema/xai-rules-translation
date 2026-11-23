"""
================================================================================
evaluator — one rule evaluator for all methods (flow level)
================================================================================
Used in the same way by the three methods:
  - proposed method : XGBoost -> per-class TreeSHAP -> one CART proxy per class
  - Anomaly2Sign    : one multiclass decision tree (Coscia et al., 2024)
  - RF-Surrogate    : random forest -> global surrogate CART -> top-N rules
                      (Saied and Guirguis, 2025)
Each method only hands over a ruleset in the format below; the evaluator computes all
metrics and stores the per-fold artefacts.

Fixed decisions:
  Conflict resolution  The rule with the highest confidence decides. Confidence = precision
                       of the rule on the TRAINING fold, computed here (not taken from each
                       method). Ties -> largest support -> rule order. No rule fires -> BENIGN.
  AIC                  Formula of Coscia et al. (Eq. 9-10): AIC = 2(k - ln MSE),
                       k = total conditions of the ruleset, MSE = one-hot on the test fold.
                       k and MSE are stored as they are.
  AUC-ROC              From the confidence scores; reported as supporting information.
  View                 deployed_only=False (default): conditions before translation.
                       deployed_only=True: only the conditions translated to Suricata
                       (status set by the translation layer).

Format of one rule (dict):
  {"rule_id": "P1-0001",
   "method": "proposed",
   "target_class": "Syn",
   "conditions": [{"feature": "ack_flag_count", "op": "<=", "threshold": 0.5,
                   "translated": None}],
   "suricata": None,
   "meta": {...}}               # optional, free
Thresholds are in ORIGINAL units (not scaled). Operators: <=, <, >, >=.

Technical note: features are compared as float32 (promoted to float64 without rounding),
as sklearn and XGBoost read them. Otherwise values very close to a threshold can fall on
the other side.
================================================================================
"""
import json
import os

import numpy as np
import pandas as pd
from scipy import sparse
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support, roc_auc_score
from sklearn.model_selection import StratifiedKFold

BENIGN = "BENIGN"

_OPS = {
    "<=": np.less_equal,
    "<": np.less,
    ">": np.greater,
    ">=": np.greater_equal,
}


# ============================================================================
# 1. Validation and rule extraction
# ============================================================================
def validate_rules(rules, classes, benign=BENIGN):
    """Check the ruleset format before evaluation; fail early with a clear message."""
    if benign not in classes:
        raise ValueError(f"Label '{benign}' must be in classes.")
    seen = set()
    for r in rules:
        rid = r.get("rule_id")
        if rid in seen:
            raise ValueError(f"duplicate rule_id: {rid}")
        seen.add(rid)
        if r["target_class"] not in classes:
            raise ValueError(f"{rid}: target_class '{r['target_class']}' is not in classes.")
        if r["target_class"] == benign:
            raise ValueError(f"{rid}: a rule must not target {benign} "
                             f"(BENIGN leaves are dropped at extraction).")
        if not r["conditions"]:
            raise ValueError(f"{rid}: rule without conditions.")
        for c in r["conditions"]:
            if c["op"] not in _OPS:
                raise ValueError(f"{rid}: operator '{c['op']}' is not supported.")


def rules_from_tree(tree_model, feature_names, method, id_prefix,
                    class_names=None, target_class=None, positive_label=1,
                    benign=BENIGN, start_index=1, simplify=True):
    """
    Turn the paths of a sklearn DecisionTreeClassifier into rules in the evaluator format.

    Two modes:
      - Multiclass (target_class=None): the leaf class is the class predicted by the tree;
        BENIGN leaves are dropped. Used by Anomaly2Sign and the RF-Surrogate surrogate.
      - One-vs-rest (target_class given): only leaves that predict positive_label become
        rules for target_class. Used by the per-class CART proxies of the proposed method.

    class_names : class names when the tree was trained on encoded labels
                  (e.g. LabelEncoder.classes_). None = use tree_model.classes_.
    simplify    : merge repeated conditions on the same feature into the tightest bound
                  (logically equivalent, does not change predictions; k in the AIC is not
                  counted twice).
    """
    t = tree_model.tree_
    rules = []
    counter = [start_index]

    def leaf_label(node):
        lab = tree_model.classes_[int(np.argmax(t.value[node][0]))]
        if class_names is not None:
            lab = class_names[int(lab)]
        return lab

    def emit(node, conds):
        lab = leaf_label(node)
        if target_class is None:
            if str(lab) == benign:
                return
            cls = str(lab)
        else:
            if lab != positive_label:
                return
            cls = target_class
        if simplify:
            conds = _simplify_conditions(conds)
        rules.append({
            "rule_id": f"{id_prefix}-{counter[0]:04d}",
            "method": method,
            "target_class": cls,
            "conditions": [dict(feature=f, op=op, threshold=float(th), translated=None)
                           for f, op, th in conds],
            "suricata": None,
            "meta": {"leaf_node": int(node), "train_samples": int(t.n_node_samples[node])},
        })
        counter[0] += 1

    def recurse(node, conds):
        if t.children_left[node] == -1:
            emit(node, conds)
            return
        f = feature_names[t.feature[node]]
        th = t.threshold[node]
        recurse(t.children_left[node], conds + [(f, "<=", th)])
        recurse(t.children_right[node], conds + [(f, ">", th)])

    recurse(0, [])
    return rules


def _simplify_conditions(conds):
    """Per feature: keep the smallest upper bound (<=) and the largest lower bound (>)."""
    upper, lower, order = {}, {}, []
    for f, op, th in conds:
        if f not in order:
            order.append(f)
        if op == "<=":
            upper[f] = min(upper.get(f, np.inf), th)
        else:
            lower[f] = max(lower.get(f, -np.inf), th)
    out = []
    for f in order:
        if f in lower:
            out.append((f, ">", lower[f]))
        if f in upper:
            out.append((f, "<=", upper[f]))
    return out


# ============================================================================
# 2. Hit matrix, confidence, conflict resolution, scores
# ============================================================================
def _active_conditions(rule, deployed_only):
    conds = rule["conditions"]
    if not deployed_only:
        return conds
    if any(c.get("translated") is None for c in conds):
        raise ValueError(f"{rule['rule_id']}: translation status not set (run the translation layer first).")
    return [c for c in conds if c["translated"]]


def compute_hits(rules, X, deployed_only=False):
    """
    Rule hit matrix: sparse bool (n_flow x n_rule), True = the rule fires on the flow.
    With deployed_only=True, a rule without any translated condition cannot be deployed
    and never fires.
    """
    n = len(X)
    cache = {}
    rows, cols = [], []
    for j, rule in enumerate(rules):
        conds = _active_conditions(rule, deployed_only)
        if not conds:
            continue
        mask = np.ones(n, dtype=bool)
        for c in conds:
            f = c["feature"]
            if f not in cache:
                if f not in X.columns:
                    raise KeyError(f"{rule['rule_id']}: feature '{f}' is not in the data.")
                col = X[f].to_numpy(dtype=np.float32)
                if not np.isfinite(col).all():
                    raise ValueError(f"Feature '{f}' contains NaN/inf; clean it in preprocessing.")
                cache[f] = col.astype(np.float64)
            mask &= _OPS[c["op"]](cache[f], np.float64(c["threshold"]))
        idx = np.flatnonzero(mask)
        rows.append(idx)
        cols.append(np.full(idx.size, j, dtype=np.int64))
    r = np.concatenate(rows) if rows else np.array([], dtype=np.int64)
    k = np.concatenate(cols) if cols else np.array([], dtype=np.int64)
    return sparse.csr_matrix((np.ones(r.size, dtype=bool), (r, k)),
                             shape=(n, len(rules)), dtype=bool)


def rule_confidence(hits_train, y_train, rules):
    """Confidence = precision of the rule on the training fold; support = number of flows that fire it."""
    y = np.asarray(y_train, dtype=object)
    target = np.array([r["target_class"] for r in rules], dtype=object)
    coo = hits_train.tocoo()
    support = np.bincount(coo.col, minlength=len(rules)).astype(float)
    correct = np.bincount(coo.col, weights=(y[coo.row] == target[coo.col]).astype(float),
                          minlength=len(rules))
    conf = np.divide(correct, support, out=np.zeros(len(rules)), where=support > 0)
    return conf, support


def resolve(hits, rules, conf, support, benign=BENIGN):
    """
    One class per flow. The deciding rule is the one with the highest confidence ->
    largest support -> smallest rule index. No rule fires -> BENIGN.
    Returns: (predicted class, index of the deciding rule; -1 if none).
    """
    n = hits.shape[0]
    target = np.array([r["target_class"] for r in rules], dtype=object)
    pred = np.full(n, benign, dtype=object)
    winner = np.full(n, -1, dtype=np.int64)
    coo = hits.tocoo()
    if coo.nnz:
        order = np.lexsort((coo.col, -support[coo.col], -conf[coo.col], coo.row))
        r_sorted, c_sorted = coo.row[order], coo.col[order]
        first = np.r_[True, r_sorted[1:] != r_sorted[:-1]]
        winner[r_sorted[first]] = c_sorted[first]
        pred[r_sorted[first]] = target[c_sorted[first]]
    return pred, winner


def class_scores(hits, rules, conf, classes, benign=BENIGN):
    """
    Score of class c = highest confidence among the fired rules of class c (0 if none).
    BENIGN score = 1 - highest attack score.
    """
    n, K = hits.shape[0], len(classes)
    cidx = {c: i for i, c in enumerate(classes)}
    S = np.zeros((n, K))
    coo = hits.tocoo()
    if coo.nnz:
        rule_cls = np.array([cidx[r["target_class"]] for r in rules])
        np.maximum.at(S, (coo.row, rule_cls[coo.col]), conf[coo.col])
    b = cidx[benign]
    attack = [i for i in range(K) if i != b]
    S[:, b] = 1.0 - S[:, attack].max(axis=1)
    return S


# ============================================================================
# 3. Metrics
# ============================================================================
def _metrics(y_true, pred, hits, rules, conf, support, scores, classes,
             deployed_only, y_ref, benign):
    y_true = np.asarray(y_true, dtype=object)
    n, K = len(y_true), len(classes)
    cidx = {c: i for i, c in enumerate(classes)}
    attack_classes = [c for c in classes if c != benign]
    is_benign = y_true == benign

    # --- per-class detection ---
    p, r, f1, sup = precision_recall_fscore_support(
        y_true, pred, labels=classes, zero_division=0)
    cm = confusion_matrix(y_true, pred, labels=classes)
    tp = np.diag(cm)
    fp = cm.sum(axis=0) - tp
    fn = cm.sum(axis=1) - tp
    tn = n - tp - fp - fn
    fpr = np.divide(fp, fp + tn, out=np.zeros(K), where=(fp + tn) > 0)

    # --- one-vs-rest AUC-ROC per class ---
    auc = np.full(K, np.nan)
    for i, c in enumerate(classes):
        yb = (y_true == c).astype(int)
        if 0 < yb.sum() < n:
            auc[i] = roc_auc_score(yb, scores[:, i])

    # --- rule quality ---
    active = [_active_conditions(rl, deployed_only) for rl in rules]
    evaluated = np.array([len(a) > 0 for a in active])
    n_rules = int(evaluated.sum())
    total_conditions = int(sum(len(a) for a in active))
    fired = np.asarray(hits.getnnz(axis=0)).ravel() > 0
    firing_rate = float(fired[evaluated].mean()) if n_rules else np.nan

    target = np.array([rl["target_class"] for rl in rules], dtype=object)
    coo = hits.tocoo()
    # hits per rule on flows of the rule's own target class
    on_target = np.bincount(coo.col, weights=(y_true[coo.row] == target[coo.col]).astype(float),
                            minlength=len(rules)).astype(int)
    covered = {c: bool(on_target[target == c].sum() > 0) for c in attack_classes}
    rule_coverage = float(np.mean(list(covered.values()))) if covered else np.nan

    # --- AIC (Coscia et al.) ---
    err = int(np.sum(pred != y_true))
    mse = 2.0 * err / (n * K)          # one-hot: each wrong prediction = 2 differing cells
    aic = 2.0 * (total_conditions - np.log(mse)) if mse > 0 else np.nan

    # --- binary view (supporting) ---
    pred_attack = pred != benign
    detection_rate = float(pred_attack[~is_benign].mean()) if (~is_benign).any() else np.nan
    any_fire = np.asarray(hits.getnnz(axis=1)).ravel() > 0
    benign_fpr = float(any_fire[is_benign].mean()) if is_benign.any() else np.nan

    # --- multi-fire rate: attack flows fired by rules of >= 2 different classes ---
    if coo.nnz:
        pairs = np.unique(np.stack([coo.row, np.array([cidx[x] for x in target[coo.col]])], 1), axis=0)
        n_cls_per_row = np.bincount(pairs[:, 0], minlength=n)
    else:
        n_cls_per_row = np.zeros(n, dtype=int)
    multi_fire = float((n_cls_per_row[~is_benign] >= 2).mean()) if (~is_benign).any() else np.nan

    # --- fidelity to the source model (optional) ---
    fidelity, fid_per_class = None, None
    if y_ref is not None:
        y_ref = np.asarray(y_ref, dtype=object)
        fidelity = float(np.mean(pred == y_ref))
        fid_per_class = {}
        for c in classes:
            m = y_ref == c
            fid_per_class[c] = float(np.mean(pred[m] == c)) if m.any() else None

    per_class = pd.DataFrame({
        "class": classes, "precision": p, "recall": r, "f1": f1, "support": sup,
        "fpr": fpr, "auc_roc": auc,
        "rule_covered": [covered.get(c) for c in classes],
        "n_rules": [int(((target == c) & evaluated).sum()) for c in classes],
    })
    if fid_per_class is not None:
        per_class["fidelity"] = [fid_per_class[c] for c in classes]

    metrics = {
        "view": "deployed" if deployed_only else "pretranslation",
        "n_flows": int(n),
        "macro_f1": float(f1.mean()),
        "macro_precision": float(p.mean()),
        "macro_recall": float(r.mean()),
        "macro_fpr": float(fpr.mean()),
        "benign_fpr": benign_fpr,
        "macro_auc_roc": float(np.nanmean(auc)) if np.isfinite(auc).any() else None,
        "accuracy": float(1 - err / n),
        "rule_coverage": rule_coverage,
        "rule_firing_rate": firing_rate,
        "n_rules": n_rules,
        "total_conditions": total_conditions,
        "mse_onehot": mse,
        "aic_coscia": aic,
        "fidelity": fidelity,
        "supplementary_binary": {"attack_detection_rate": detection_rate,
                                 "benign_fpr": benign_fpr},
        "optional_multi_fire_rate": multi_fire,
    }

    rule_stats = pd.DataFrame({
        "rule_id": [rl["rule_id"] for rl in rules],
        "target_class": target,
        "n_conditions": [len(a) for a in active],
        "evaluated": evaluated,
        "train_support": support,
        "train_confidence": conf,
        "test_hits": np.asarray(hits.getnnz(axis=0)).ravel(),
        "test_hits_on_target_class": on_target,
    })
    return metrics, per_class, rule_stats


# ============================================================================
# 4. Main function
# ============================================================================
def evaluate_ruleset(rules, X_train, y_train, X_test, y_test, classes,
                     y_ref=None, deployed_only=False, benign=BENIGN, meta=None):
    """
    Evaluate one ruleset on one fold.

    rules    : list of rules (format in the module docstring)
    X_train  : DataFrame of training-fold features (original units), for the confidence
    y_train  : training-fold labels (8 classes after grouping)
    X_test   : DataFrame of test-fold features (original units)
    y_test   : test-fold labels
    classes  : fixed class order (the same for all methods)
    y_ref    : optional, source-model predictions on the test fold (fidelity)
    meta     : optional, dict of the configuration (method, seed, fold, k, depth, ...)
    """
    validate_rules(rules, classes, benign)
    classes = list(classes)

    hits_tr = compute_hits(rules, X_train, deployed_only)
    conf, support = rule_confidence(hits_tr, y_train, rules)

    hits = compute_hits(rules, X_test, deployed_only)
    pred, winner = resolve(hits, rules, conf, support, benign)
    scores = class_scores(hits, rules, conf, classes, benign)

    metrics, per_class, rule_stats = _metrics(
        y_test, pred, hits, rules, conf, support, scores, classes,
        deployed_only, y_ref, benign)
    if meta:
        metrics = {"meta": meta, **metrics}

    return {"metrics": metrics, "per_class": per_class, "rule_stats": rule_stats,
            "hits": hits, "pred": pred, "winner": winner, "scores": scores,
            "classes": classes, "y_test": np.asarray(y_test, dtype=object),
            "y_ref": None if y_ref is None else np.asarray(y_ref, dtype=object)}


# ============================================================================
# 5. Per-fold artefacts and fold manifest
# ============================================================================
def artifact_dir(base, method, seed, fold, deployed_only=False):
    """results/{method}/seed{S}/fold{F}/{pretranslation|deployed}/"""
    view = "deployed" if deployed_only else "pretranslation"
    return os.path.join(base, method, f"seed{seed}", f"fold{fold}", view)


def save_artifacts(out_dir, rules, result, row_ids=None):
    """
    Save the ruleset, per-flow predictions and the rule hit matrix, plus the metrics,
    the per-class table and the per-rule statistics. All metrics can be recomputed from
    these files without retraining a model.
    """
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "ruleset.json"), "w", encoding="utf-8") as f:
        json.dump(rules, f, indent=1)
    sparse.save_npz(os.path.join(out_dir, "hits.npz"), result["hits"])

    n = len(result["pred"])
    pred_df = pd.DataFrame({
        "row_id": np.arange(n) if row_ids is None else np.asarray(row_ids),
        "y_true": result["y_test"],
        "y_pred": result["pred"],
        "winner_rule": [rules[w]["rule_id"] if w >= 0 else "" for w in result["winner"]],
    })
    if result["y_ref"] is not None:
        pred_df["y_ref"] = result["y_ref"]
    for i, c in enumerate(result["classes"]):
        pred_df[f"score_{c}"] = np.round(result["scores"][:, i], 6)
    pred_df.to_csv(os.path.join(out_dir, "predictions.csv.gz"), index=False)

    result["per_class"].to_csv(os.path.join(out_dir, "per_class.csv"), index=False)
    result["rule_stats"].to_csv(os.path.join(out_dir, "rule_stats.csv"), index=False)
    with open(os.path.join(out_dir, "metrics.json"), "w", encoding="utf-8") as f:
        json.dump(result["metrics"], f, indent=2, default=_json_default)


def _json_default(o):
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, (np.floating,)):
        return None if np.isnan(o) else float(o)
    if isinstance(o, np.bool_):
        return bool(o)
    raise TypeError(type(o))


def make_fold_manifest(y_strat, seed, n_splits=5, row_ids=None):
    """
    Fold manifest per seed (row_id -> fold), built once and used by ALL methods, so the
    paired test observations are identical across methods.
    y_strat : labels used for stratification.
    """
    y_strat = np.asarray(y_strat)
    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=seed)
    fold = np.empty(len(y_strat), dtype=np.int64)
    for f, (_, te) in enumerate(skf.split(np.zeros(len(y_strat)), y_strat)):
        fold[te] = f
    return pd.DataFrame({"row_id": np.arange(len(y_strat)) if row_ids is None else row_ids,
                         "fold": fold})
