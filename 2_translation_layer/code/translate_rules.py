"""Translate a ruleset (ruleset.json, rules before translation) into Suricata signatures and Lua scripts.

The protocol header of a rule whose conditions do not fix the protocol is taken from the training
flows that trigger the rule. Two ways to provide that information:
  --shares-from  ruleset_translated.json of an earlier translation (reproduces the released
                 rulesets without the training data);
  --train        a CSV or Parquet file with the training flows (original feature units and a
                 'protocol' column).
Without either option every such rule gets an `ip` header.

Example (reproduces the released initial ruleset of the proposed method):
    python translate_rules.py --ruleset ../../1_rulesets/initial/proposed/ruleset.json \\
        --shares-from ../../1_rulesets/initial/proposed/ruleset_translated.json \\
        --header "Initial ruleset, proposed method (k = 5, depth 5), trained on the pool of seed 1011" \\
        --out-dir out/proposed
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import suricata_translate as st  # noqa: E402


def load_rules(path: str) -> list:
    with open(path, encoding="utf-8") as f:
        obj = json.load(f)
    return obj["rules"] if isinstance(obj, dict) else obj


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ruleset", required=True, help="ruleset.json (rules before translation)")
    ap.add_argument("--config", default=st.DEFAULT_CONFIG_PATH, help="translation config (default: configs/suricata_translation.yaml)")
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--shares-from", help="ruleset_translated.json of an earlier translation")
    src.add_argument("--train", help="CSV or Parquet file with the training flows")
    ap.add_argument("--header", default="", help="comment line(s) written after the first line of rq1.rules")
    ap.add_argument("--report", action="store_true", help="also write translation_report.json")
    ap.add_argument("--out-dir", required=True)
    a = ap.parse_args()

    rules = load_rules(a.ruleset)
    cfg = st.load_config(a.config)
    shares, X = None, None
    if a.shares_from:
        shares = st.protocol_shares_from_translated(rules, load_rules(a.shares_from))
    elif a.train:
        import pandas as pd
        X = pd.read_parquet(a.train) if a.train.endswith(".parquet") else pd.read_csv(a.train)
    translated, lua, report = st.translate_ruleset(rules, cfg, X_train=X, shares=shares)
    paths = st.write_outputs(a.out_dir, translated, lua, report if a.report else None, header_comment=a.header)
    n_alert = sum(1 for t in translated if t["suricata"])
    print(f"{n_alert} rules ({len(lua)} with a Lua script) -> {paths['rules']}")


if __name__ == "__main__":
    main()
