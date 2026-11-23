"""Map the alerts of one Suricata run (eve.json) to the ground-truth flows of the same PCAP file.

Writes alerts_agg.parquet with one row per (ground-truth flow, sid): flow_idx, sid, n_alerts, t_first_us,
pkts_first (flow_idx -1 = alert not mapped to a ground-truth flow), and agg_info.json with the counts.

    python match_alerts.py --eve OUT/proposed/SAT-01-12-2018_01/eve.json \\
        --gt gt/gt_flows_SAT-01-12-2018_01.parquet --out-dir agg/proposed/SAT-01-12-2018_01
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

import pandas as pd  # noqa: E402

import deployment_score as ds  # noqa: E402

GT_COLS = ["flow_idx", "src_ip", "dst_ip", "src_port", "dst_port", "proto", "ts_us", "end_us"]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--eve", required=True)
    ap.add_argument("--gt", required=True, help="gt_flows_<pcap>.parquet")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--suricata-flows", action="store_true", help="also write suri_seen.parquet (ground-truth flows seen by Suricata)")
    a = ap.parse_args()

    t0 = time.time()
    gt = pd.read_parquet(a.gt, columns=GT_COLS)
    al, fl, counts = ds.read_eve(a.eve, flows=a.suricata_flows)
    pos = ds.map_alerts(al, gt)
    agg = ds.aggregate_alerts(al, pos, gt["flow_idx"].to_numpy())
    os.makedirs(a.out_dir, exist_ok=True)
    agg.to_parquet(os.path.join(a.out_dir, "alerts_agg.parquet"), index=False)
    info = {"n_alerts": int(len(al)), "n_mapped": int((pos >= 0).sum()), "n_unmapped": int((pos < 0).sum()),
            "n_sids_fired": int(agg["sid"].nunique()) if len(agg) else 0,
            "n_flows_alerted": int(agg.loc[agg["flow_idx"] >= 0, "flow_idx"].nunique()) if len(agg) else 0,
            "eve_event_counts": counts, "eve_bytes": os.path.getsize(a.eve)}
    if a.suricata_flows:
        seen = ds.map_suri_flows(gt, fl)
        pd.DataFrame({"flow_idx": gt["flow_idx"].to_numpy()[seen]}).to_parquet(
            os.path.join(a.out_dir, "suri_seen.parquet"), index=False)
        info["gt_flows_with_suricata_flow"] = int(seen.sum())
    info["seconds"] = round(time.time() - t0, 1)
    with open(os.path.join(a.out_dir, "agg_info.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(info, f, indent=1)
    print(f"{info['n_alerts']} alerts, {info['n_mapped']} mapped, {info['n_flows_alerted']} flows alerted -> {a.out_dir}")


if __name__ == "__main__":
    main()
