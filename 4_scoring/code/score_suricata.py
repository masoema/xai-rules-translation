"""Score Suricata alerts against the derived ground truth (Sections 4.5 and 4.7 of the paper).

Each method is given twice, with the same NAME:
  --tables NAME=FOLDER  ruleset.json and sid_map.csv of the initial ruleset (the rule order, confidence and
                        support used for conflict resolution; a repaired ruleset uses the tables of its
                        initial ruleset);
  --agg NAME=FOLDER     <pcap>/alerts_agg.parquet from match_alerts.py (or <pcap>/part<i>of<k>/alerts_agg.parquet
                        for a file processed in partitions).

    python score_suricata.py --gt-dir gt --pcaps ../../3_ground_truth/file_lists/files_819.txt \\
        --tables proposed=../../1_rulesets/initial/proposed --agg proposed=agg/proposed \\
        --tables anomaly2sign=../../1_rulesets/initial/anomaly2sign --agg anomaly2sign=agg/anomaly2sign \\
        --tables rf_surrogate=../../1_rulesets/initial/rf_surrogate --agg rf_surrogate=agg/rf_surrogate \\
        --out scores_819.json

For every view (main = derived ground truth without AMBIGUOUS flows; official = official CSV labels of the
joined flows) and method: accuracy, macro F1 (8 classes and without UDP-lag), mean F1 of the six attack
classes other than UDP-lag, Benign FPR, binary detection rate and precision, and 95% bootstrap CIs over PCAP
files (1,000 replicates, seed 1011) for macro F1, Benign FPR and the paired differences between methods.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
for d in (HERE, os.path.join(HERE, "..", "..", "2_translation_layer", "code"), os.path.join(HERE, "..", "..", "3_ground_truth", "code")):
    sys.path.insert(0, os.path.abspath(d))

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

import deployment_metrics as M  # noqa: E402
import deployment_score as ds  # noqa: E402

CLASSES = ["BENIGN", "DrDoS_MSSQL", "DrDoS_NTP", "DrDoS_NetBIOS", "Syn", "TFTP", "UDP-lag", "UDP_Reflection_Attack"]
VIEWS = {"main": "gt_label", "udplag": "gt_label_udplag", "official": "gt_label_official"}
VIEW_EXCLUDE = {"main": ("AMBIGUOUS",), "udplag": ("AMBIGUOUS",), "official": ("NOT_JOINED", "WebDDoS")}


def load_tables(folder: str) -> dict:
    with open(os.path.join(folder, "ruleset.json"), encoding="utf-8") as f:
        rules = json.load(f)
    rules = rules["rules"] if isinstance(rules, dict) else rules
    sm = pd.read_csv(os.path.join(folder, "sid_map.csv"))
    rl, conf, sup, sid2j = ds.rule_tables(rules, sm)
    return {"rules": rl, "conf": conf, "sup": sup, "sid2j": sid2j}


def load_agg(folder: str, pcap: str) -> pd.DataFrame:
    base = os.path.join(folder, pcap)
    whole = os.path.join(base, "alerts_agg.parquet")
    if os.path.exists(whole):
        return pd.read_parquet(whole)
    parts = sorted(p for p in os.listdir(base) if p.startswith("part"))
    if not parts:
        raise FileNotFoundError(f"no alerts_agg.parquet in {base}")
    return ds.combine_aggregates([pd.read_parquet(os.path.join(base, p, "alerts_agg.parquet")) for p in parts])


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--gt-dir", required=True, help="folder with gt_flows_<pcap>.parquet")
    ap.add_argument("--pcaps", required=True, help="file with one PCAP name per line")
    ap.add_argument("--tables", action="append", required=True, help="NAME=FOLDER with ruleset.json and sid_map.csv (repeatable)")
    ap.add_argument("--agg", action="append", required=True, help="NAME=FOLDER with <pcap>/alerts_agg.parquet (repeatable)")
    ap.add_argument("--views", default="main,official")
    ap.add_argument("--n-rep", type=int, default=1000)
    ap.add_argument("--out", required=True, help="output JSON")
    a = ap.parse_args()

    tables = dict(s.split("=", 1) for s in a.tables)
    aggs = dict(s.split("=", 1) for s in a.agg)
    if set(tables) != set(aggs):
        raise SystemExit(f"--tables and --agg must name the same methods: {sorted(tables)} vs {sorted(aggs)}")
    methods = {name: {"tables": load_tables(tables[name]), "agg": aggs[name]} for name in aggs}
    pcaps = [ln.strip().split()[-1] for ln in open(a.pcaps, encoding="utf-8") if ln.strip() and not ln.startswith("#")]
    views = a.views.split(",")
    K, F = len(CLASSES), len(pcaps)
    cms = {v: {m: np.zeros((F, K, K), np.int64) for m in methods} for v in views}
    bens = {v: {m: np.zeros((F, 2)) for m in methods} for v in views}
    att = {v: {m: np.zeros(2, np.int64) for m in methods} for v in views}     # [attack flows alerted, attack flows]
    files_with = {v: {c: set() for c in CLASSES} for v in views}
    t0 = time.time()
    for fi, p in enumerate(pcaps):
        gt = pd.read_parquet(os.path.join(a.gt_dir, f"gt_flows_{p}.parquet"), columns=["flow_idx"] + [VIEWS[v] for v in views])
        n = len(gt)
        pos_of = pd.Index(gt["flow_idx"].to_numpy())
        labs = {v: gt[VIEWS[v]].astype(str).to_numpy() for v in views}
        for v in views:
            vm = ~np.isin(labs[v], VIEW_EXCLUDE[v])
            for c in set(labs[v][vm]):
                if c in files_with[v]:
                    files_with[v][c].add(fi)
        for m, d in methods.items():
            agg = load_agg(d["agg"], p)
            mapped = agg[agg["flow_idx"] >= 0].copy()
            mapped["pos"] = pos_of.get_indexer(mapped["flow_idx"].to_numpy())
            alerted = np.zeros(n, bool)
            alerted[mapped["pos"].to_numpy()] = True
            t = d["tables"]
            pred, _, info = ds.resolve_flows(n, mapped.assign(flow_idx=mapped["pos"])[["flow_idx", "sid"]],
                                             t["rules"], t["conf"], t["sup"], t["sid2j"])
            pred = pred.astype(str)
            for v in views:
                lab = labs[v]
                vm = ~np.isin(lab, VIEW_EXCLUDE[v])
                cms[v][m][fi] = M.confusion(lab[vm], pred[vm], CLASSES)
                ben = vm & (lab == "BENIGN")
                bens[v][m][fi] = [int((ben & alerted).sum()), int(ben.sum())]
                isatt = vm & (lab != "BENIGN")
                att[v][m] += [int((isatt & alerted).sum()), int(isatt.sum())]
        if (fi + 1) % 50 == 0 or fi + 1 == F:
            print(f"{fi + 1}/{F} files ({time.time() - t0:.0f} s)", flush=True)

    out = {"pcaps": F, "classes": CLASSES, "views": {}}
    six = [c for c in CLASSES if c not in ("BENIGN", "UDP-lag")]
    for v in views:
        vo = {}
        for m in methods:
            cm = cms[v][m].sum(axis=0)
            _, _, f, _ = M.prf(cm)
            b = bens[v][m].sum(axis=0)
            alerted_attack, n_attack = att[v][m]
            alerted_flows = alerted_attack + b[0]
            vo[m] = {"accuracy": float(np.trace(cm) / cm.sum()),
                     "macro_f1": M.macro_f1(cm, CLASSES, present_only=False),
                     "macro_f1_without_udplag": M.macro_f1(cm, CLASSES, exclude=("UDP-lag",), present_only=False),
                     # over the classes present in the files (the bootstrap uses this definition; it equals the
                     # values above when every class is present, e.g. on the 819 files)
                     "macro_f1_present_classes": M.macro_f1(cm, CLASSES),
                     "macro_f1_without_udplag_present_classes": M.macro_f1(cm, CLASSES, exclude=("UDP-lag",)),
                     "mean_f1_six_attack_classes": float(np.mean([f[CLASSES.index(c)] for c in six])),
                     "benign_fpr": float(b[0] / b[1]) if b[1] else None,
                     "binary_detection_rate": float(alerted_attack / n_attack) if n_attack else None,
                     "binary_precision": float(alerted_attack / alerted_flows) if alerted_flows else None,
                     "n_benign": int(b[1]), "n_attack": int(n_attack),
                     "per_class": M.per_class_table(cm, CLASSES).to_dict("records")}
        class_files = {c: len(s) for c, s in files_with[v].items()}
        boot = M.bootstrap_files(cms[v], bens[v], CLASSES, class_files, n_rep=a.n_rep,
                                 exclude_sets={"all": (), "without_udplag": ("UDP-lag",)})
        out["views"][v] = {"methods": vo, "bootstrap": boot}
    with open(a.out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(out, f, indent=1)
    for v in views:
        print(f"\nview {v}")
        for m, r in out["views"][v]["methods"].items():
            ci = out["views"][v]["bootstrap"]["methods"][m]
            print(f"  {m:14s} macro F1 w/o UDP-lag (classes present) {100 * ci['macro_f1_without_udplag']['point']:.2f} "
                  f"[{100 * ci['macro_f1_without_udplag']['ci'][0]:.2f}, {100 * ci['macro_f1_without_udplag']['ci'][1]:.2f}]  "
                  f"Benign FPR {100 * r['benign_fpr']:.2f} [{100 * ci['benign_fpr']['ci'][0]:.2f}, {100 * ci['benign_fpr']['ci'][1]:.2f}]  "
                  f"accuracy {100 * r['accuracy']:.2f}")
    print(f"-> {a.out}")


if __name__ == "__main__":
    main()
