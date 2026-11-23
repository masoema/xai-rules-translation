"""Build a repaired ruleset from an initial ruleset (Section 4.7 of the paper).

Stage 1 changes only the Lua scripts (arm C0, R, A, RA or AR3); stage 2 optionally removes the
rules learned from fewer than --max-train training flows (AD). The released repaired ruleset is
arm A + AD30:

    python repair_rules.py --initial ../../1_rulesets/initial/proposed --arm A --drop-below 30 \\
        --out-dir out/proposed_repaired

The initial folder must contain rq1.rules, the *.lua scripts, ruleset_translated.json and
ruleset.json (for the training support of each rule).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import suricata_translate_repair as rp  # noqa: E402


def load_rules(path: Path) -> list:
    obj = json.loads(path.read_text(encoding="utf-8"))
    return obj["rules"] if isinstance(obj, dict) else obj


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--initial", required=True, help="folder of the initial ruleset")
    ap.add_argument("--arm", default="A", choices=sorted(rp.ARMS) + ["AR3"])
    ap.add_argument("--drop-below", type=int, default=None, help="remove rules with fewer training flows (AD)")
    ap.add_argument("--max-train", type=int, default=30, help="training-support threshold of arm AR3")
    ap.add_argument("--home-net", default="192.168.50.0/24")
    ap.add_argument("--out-dir", required=True)
    a = ap.parse_args()

    src = Path(a.initial)
    text = (src / "rq1.rules").read_text(encoding="utf-8")
    lua = {p.name: p.read_text(encoding="utf-8") for p in sorted(src.glob("*.lua"))}
    translated = load_rules(src / "ruleset_translated.json")
    train = {r["rule_id"]: r["meta"].get("train_samples", 10**9) for r in load_rules(src / "ruleset.json")}

    if a.arm == "AR3":
        lua, notes = rp.repair_ruleset_ar3(lua, translated, train, a.max_train, a.home_net)
    else:
        lua, notes = rp.repair_ruleset(lua, translated, a.arm, a.home_net)
    dropped = []
    if a.drop_below:
        text, lua, dropped = rp.drop_low_support(text, lua, translated, train, a.drop_below)

    label = a.arm + (f" + AD{a.drop_below}" if a.drop_below else "")
    lines = text.split("\n")
    for i, ln in enumerate(lines):
        if ln.startswith("# Initial ruleset, "):
            lines[i] = f"# Repair arm {label}, " + ln[len("# Initial ruleset, "):]
            break
    out = Path(a.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "rq1.rules").write_text("\n".join(lines), encoding="utf-8", newline="\n")
    for name, s in lua.items():
        (out / name).write_text(s, encoding="utf-8", newline="\n")
    n_alert = sum(ln.startswith("alert") for ln in lines)
    print(f"arm {label}: {len(notes)} Lua scripts changed, {len(dropped)} rules removed, {n_alert} rules left -> {out}")
    if dropped:
        print("removed:", ", ".join(dropped))


if __name__ == "__main__":
    main()
