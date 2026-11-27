# Translation and deployment evaluation of explainable rules — release artefacts

Artefacts of the paper *Translation and deployment evaluation of explainable rules for signature-based DDoS
intrusion detection* (citation and DOI to be added). They contain the rulesets that were run in Suricata, the
translation layer that produced them, the code that derives the ground truth from the CIC-DDoS2019 PCAP files,
and the code that scores Suricata alerts against that ground truth.

Method names: `proposed` = per-class TreeSHAP ranking + one CART proxy per attack class; `anomaly2sign` =
reproduction of Anomaly2Sign (Coscia et al., 2024); `rf_surrogate` = reproduction of the random forest with a
global surrogate tree (Saied and Guirguis, 2025). Rule IDs are those used in the paper (`P*`, `COS-*`, `SAI-*`).

## Contents

```
1_rulesets/
  initial/<method>/        initial ruleset (main run, Section 4.5): rq1.rules + one Lua script per rule,
                           ruleset.json (rules before translation), ruleset_translated.json (translation status
                           per condition), rule_stats.csv (training support and confidence), sid_map.csv
  repaired/<method>/       repaired ruleset, direction check A + removal of rules learned from fewer than
                           30 training flows (Section 4.7); ad30_removed_rules.json lists the removed rules
  repair_arms/             the stage-1 arms tested on 25 PCAP files (C0, R, A, RA) and arm AR3 (Fig. 4)
  et_open/                 reference ruleset: ET Open emerging-dos.rules (suricata-7.0.3, retrieved April 2026,
                           114 active rules), kept because later ET updates disabled part of these rules
2_translation_layer/
  code/suricata_translate.py         translation layer (Algorithm 1 of the paper)
  code/suricata_translate_repair.py  repairs R (rate at zero duration) and A (flow direction), and AD
  code/evaluator.py                  flow-level rule evaluator (conflict resolution, metrics)
  code/translate_rules.py            CLI: ruleset.json -> rq1.rules + Lua scripts
  code/repair_rules.py               CLI: initial ruleset -> repaired ruleset
  code/suricata_batch_pcap.sh        runs Suricata offline per PCAP file and ruleset
  configs/suricata_translation.yaml  feature map, flag bits and other translation settings (Table S4)
  configs/suricata.yaml              Suricata configuration used in the experiments
3_ground_truth/
  code/ground_truth.py, code/ground_truth_rq1.yaml   labelling rules of the derived ground truth
  file_lists/                        the 819 PCAP files, the 794 validation files and the 25 repair files
                                     (with SHA-256 of the PCAP files)
  summary/                           label counts and a summary of the ground truth
4_scoring/
  code/match_alerts.py               CLI: eve.json + ground truth -> alerts per (flow, rule)
  code/score_suricata.py             CLI: metrics with 95% bootstrap confidence intervals over PCAP files
  code/deployment_score.py, code/deployment_metrics.py
```

The per-flow ground truth (`gt_flows_<pcap>.parquet`, 819 files, Parquet only) is released separately on
Zenodo (https://doi.org/10.5281/zenodo.24335258) as a multi-part RAR archive. The CIC-DDoS2019 PCAP and CSV files are not redistributed; they are available from the Canadian Institute for Cybersecurity (https://www.unb.ca/cic/datasets/ddos-2019.html).

## Requirements

- Python 3.10 or later with numpy, pandas, scipy, scikit-learn, pyyaml, pyarrow and polars.
- Suricata 7.0.10 with Lua support (Lua rules are enabled with `--set security.lua.allow-rules=true`).
- For rebuilding the ground truth: CICFlowMeter 4.0 (Java release) and the raw CSV files of CIC-DDoS2019.

The code runs from its own folder; the scripts add the sibling `code/` folders to the Python path.

## Usage

Translate a ruleset (reproduces the released initial ruleset without the training data):

```bash
cd 2_translation_layer/code
python translate_rules.py --ruleset ../../1_rulesets/initial/proposed/ruleset.json \
    --shares-from ../../1_rulesets/initial/proposed/ruleset_translated.json \
    --header "Initial ruleset, proposed method (k = 5, depth 5), trained on the pool of seed 1011" \
    --out-dir out/proposed
```

Build the repaired ruleset:

```bash
python repair_rules.py --initial ../../1_rulesets/initial/proposed --arm A --drop-below 30 --out-dir out/proposed_repaired
```

Run Suricata on the PCAP files:

```bash
./suricata_batch_pcap.sh --config ../configs/suricata.yaml --output-dir runs \
    --ruleset proposed=../../1_rulesets/initial/proposed:rq1.rules \
    --pcap-list ../../3_ground_truth/file_lists/files_819.txt
```

Map the alerts to the ground-truth flows (one call per run) and score:

```bash
cd ../../4_scoring/code
python match_alerts.py --eve runs/proposed/SAT-01-12-2018_01/eve.json \
    --gt gt/gt_flows_SAT-01-12-2018_01.parquet --out-dir agg/proposed/SAT-01-12-2018_01
python score_suricata.py --gt-dir gt --pcaps ../../3_ground_truth/file_lists/files_819.txt \
    --tables proposed=../../1_rulesets/initial/proposed --agg proposed=agg/proposed \
    --out scores_819.json
```

A repaired ruleset is scored with the tables (`--tables`) of its initial ruleset: the sids do not change, and
removed rules simply never fire.

## Checks

- Running `translate_rules.py` and `repair_rules.py` on the released inputs reproduces every released
  `rq1.rules`, Lua script and `ruleset_translated.json` byte for byte (initial rulesets, repaired rulesets and
  all repair arms).
- `match_alerts.py` applied to stored `eve.json` files reproduces the stored alert aggregates exactly
  (checked on four runs of three methods).
- `score_suricata.py` on the stored alert aggregates reproduces the Suricata results of the paper
  (Supplementary Tables S6 and S7): for example, on the 819 files, macro F1 without UDP-lag 90.80% [88.71, 91.83]
  and Benign FPR 47.37% [40.33, 49.69] for the proposed method; on the 794 validation files, Benign FPR 39.58% ->
  1.54% (proposed) and 15.94% -> 1.89% (Anomaly2Sign), with the same paired differences and confidence intervals.
  On the 794 files, which contain no Syn or UDP-lag flows, the paper reports macro F1 over the classes present
  (`macro_f1_present_classes`).

## Licence and citation

The code and rulesets in this repository are released under the MIT licence (see `LICENSE`): they may be
used, changed and redistributed freely, provided the copyright notice is kept. If you use them in research,
please cite this repository (see `CITATION.cff`, or "Cite this repository" on GitHub) and the paper. The
ground truth on Zenodo is released under CC BY 4.0. `1_rulesets/et_open/emerging-dos.rules` is not covered
by the MIT licence; it is redistributed unchanged under the licences stated in its header (GPLv2 and BSD,
Emerging Threats).
