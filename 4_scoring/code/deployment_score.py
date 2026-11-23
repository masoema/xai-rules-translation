"""
================================================================================
deployment_score — scoring of Suricata alerts against the derived ground truth
================================================================================
  read_eve          eve.json (alert + flow) -> alert / flow tables (polars; time -> UTC epoch µs)
  map_alerts        alert -> ground-truth flow: bidirectional 5-tuple + alert time in
                    [start - tol, end + tol]; one alert -> one flow (several: nearest in time)
  aggregate_alerts  (ground-truth flow, sid) -> number of alerts + first alert
  combine_aggregates  the same for the partitions of one PCAP file
  map_suri_flows    ground-truth flows that have a Suricata flow (bidirectional 5-tuple + overlapping time ± tol)
  resolve_flows     conflict resolution = evaluator.resolve (confidence -> support -> rule order);
                    -tcp/-udp variants inherit their source rule through sid_map.source_rule_id;
                    no alert -> BENIGN
The ground truth, the rules and the configuration are not read here; this module changes nothing.
================================================================================
"""
from __future__ import annotations

from typing import Dict, Sequence, Tuple

import numpy as np
import pandas as pd

import evaluator                              # 2_translation_layer/code (on sys.path, see the scripts)
from ground_truth import US, canonical_key    # 3_ground_truth/code

PROTO = {"TCP": 6, "UDP": 17, "ICMP": 1}


# ----------------------------------------------------------------------------
# eve.json
# ----------------------------------------------------------------------------
def _ipv4_expr(col):
    import polars as pl
    parts = pl.col(col).str.split(".")
    ok = parts.list.len() == 4
    val = sum(parts.list.get(i, null_on_oob=True).cast(pl.Int64, strict=False) * (1 << (8 * (3 - i))) for i in range(4))
    return pl.when(ok).then(val).otherwise(0).fill_null(0).cast(pl.Int64)


def _ts_expr(col):
    import polars as pl
    return (pl.col(col).str.to_datetime("%Y-%m-%dT%H:%M:%S%.f%z", time_unit="us")
            .dt.convert_time_zone("UTC").dt.epoch("us"))


def read_eve(path: str, *, flows: bool = True) -> Tuple[pd.DataFrame, pd.DataFrame, Dict]:
    """eve.json -> (alerts, flows, counts). alerts: src_ip, src_port, dst_ip, dst_port, proto, t_us, sid, pkts.
    flows (event_type flow): ... + start_us, end_us. Unreadable rows are counted, not silently dropped."""
    import polars as pl
    schema = {"timestamp": pl.Utf8, "event_type": pl.Utf8, "src_ip": pl.Utf8, "src_port": pl.Int64,
              "dest_ip": pl.Utf8, "dest_port": pl.Int64, "proto": pl.Utf8,
              "alert": pl.Struct({"signature_id": pl.Int64}),
              "flow": pl.Struct({"start": pl.Utf8, "end": pl.Utf8, "pkts_toserver": pl.Int64,
                                 "pkts_toclient": pl.Int64})}
    lf = pl.scan_ndjson(path, schema=schema, ignore_errors=True)
    base = [_ipv4_expr("src_ip").alias("src_ip"), pl.col("src_port").fill_null(0).cast(pl.Int64),
            _ipv4_expr("dest_ip").alias("dst_ip"), pl.col("dest_port").fill_null(0).cast(pl.Int64).alias("dst_port"),
            pl.col("proto").replace_strict(PROTO, default=0, return_dtype=pl.Int64).alias("proto")]
    # pkts = packets of the Suricata flow (both directions) at the alert, including the triggering packet; -1 if absent
    pk = (pl.col("flow").struct.field("pkts_toserver").fill_null(0)
          + pl.col("flow").struct.field("pkts_toclient").fill_null(0))
    al = (lf.filter(pl.col("event_type") == "alert")
          .select(*base, _ts_expr("timestamp").alias("t_us"), pl.col("alert").struct.field("signature_id").alias("sid"),
                  pl.when(pl.col("flow").is_null()).then(-1).otherwise(pk).cast(pl.Int64).alias("pkts"))
          .collect().to_pandas())
    counts = (lf.group_by("event_type").agg(pl.len()).collect().to_pandas()
              .set_index("event_type")["len"].to_dict())
    fl = pd.DataFrame()
    if flows:
        fl = (lf.filter(pl.col("event_type") == "flow")
              .select(*base, pl.col("flow").struct.field("start").alias("start"),
                      pl.col("flow").struct.field("end").alias("end"))
              .with_columns(_ts_expr("start").alias("start_us"), _ts_expr("end").alias("end_us"))
              .drop("start", "end").collect().to_pandas())
    counts = {str(k): int(v) for k, v in counts.items()}
    counts["alert_rows_parsed"] = int(len(al))
    counts["alert_null_time"] = int(al["t_us"].isna().sum()) if len(al) else 0
    return al, fl, counts


# ----------------------------------------------------------------------------
# alert -> ground-truth flow
# ----------------------------------------------------------------------------
def _keys(df: pd.DataFrame, s="src_ip", sp="src_port", d="dst_ip", dp="dst_port", p="proto") -> pd.DataFrame:
    ka, kb = canonical_key(df[s], df[sp], df[d], df[dp], df[p])
    return pd.DataFrame({"ka": ka, "kb": kb})


def map_alerts(alerts: pd.DataFrame, flows: pd.DataFrame, *, tol_us: int = US) -> np.ndarray:
    """Positional index of the ground-truth flow of each alert (-1 = not mapped). Candidates: (A) flow with the
    same key and the last start <= t + tol, (B) flow with the same key and the first end >= t - tol; valid if
    start - tol <= t <= end + tol; the nearest in time is chosen (0 if t is inside [start, end]; tie -> A)."""
    n = len(alerts)
    out = np.full(n, -1, np.int64)
    if not n or not len(flows):
        return out
    A = _keys(alerts).assign(t=np.asarray(alerts["t_us"], np.int64), i=np.arange(n))
    G = _keys(flows).assign(ts=np.asarray(flows["ts_us"], np.int64), te=np.asarray(flows["end_us"], np.int64),
                            g=np.arange(len(flows)))
    best = np.full(n, np.iinfo(np.int64).max, np.int64)
    for left_on, right_on, direction, shift in (("tq", "ts", "backward", tol_us), ("tq", "te", "forward", -tol_us)):
        L = A.assign(tq=A["t"] + shift).sort_values("tq")
        R = G.sort_values(right_on)
        m = pd.merge_asof(L, R, left_on=left_on, right_on=right_on, by=["ka", "kb"], direction=direction)
        m = m.dropna(subset=["g"])
        if not len(m):
            continue
        t, ts, te = m["t"].to_numpy(), m["ts"].to_numpy(np.int64), m["te"].to_numpy(np.int64)
        valid = (t >= ts - tol_us) & (t <= te + tol_us)
        dist = np.where((t >= ts) & (t <= te), 0, np.minimum(np.abs(t - ts), np.abs(t - te)))
        i, g = m["i"].to_numpy()[valid], m["g"].to_numpy(np.int64)[valid]
        dist = dist[valid]
        better = dist < best[i]
        out[i[better]] = g[better]
        best[i[better]] = dist[better]
    return out


def aggregate_alerts(alerts: pd.DataFrame, flow_pos: np.ndarray, flow_idx: np.ndarray) -> pd.DataFrame:
    """(ground-truth flow_idx, sid) -> number of alerts + time of the first alert; flow_idx -1 = not mapped.
    If alerts has a `pkts` column: pkts_first = Suricata flow packets at the first alert (time tie -> fewest pkts)."""
    fi = np.where(flow_pos >= 0, flow_idx[np.clip(flow_pos, 0, None)], -1)
    d = pd.DataFrame({"flow_idx": fi, "sid": alerts["sid"].to_numpy(np.int64), "t_us": alerts["t_us"].to_numpy(np.int64)})
    if "pkts" not in alerts:
        return (d.groupby(["flow_idx", "sid"], sort=True).agg(n_alerts=("t_us", "size"), t_first_us=("t_us", "min"))
                .reset_index())
    d["pkts"] = alerts["pkts"].to_numpy(np.int64)
    d = d.sort_values(["flow_idx", "sid", "t_us", "pkts"], kind="stable")
    return (d.groupby(["flow_idx", "sid"], sort=True)
            .agg(n_alerts=("t_us", "size"), t_first_us=("t_us", "first"), pkts_first=("pkts", "first")).reset_index())


def combine_aggregates(parts: Sequence[pd.DataFrame]) -> pd.DataFrame:
    """Combine the (flow_idx, sid) aggregates of several runs (partitions of one file): alert counts are summed;
    the first alert is the earliest (pkts_first follows that row). Equivalent to aggregate_alerts on all alerts."""
    d = pd.concat([p for p in parts if len(p)], ignore_index=True) if any(len(p) for p in parts) else parts[0]
    cols = ["flow_idx", "sid", "t_first_us"] + (["pkts_first"] if "pkts_first" in d else [])
    d = d.sort_values(cols, kind="stable")
    agg = {"n_alerts": ("n_alerts", "sum"), "t_first_us": ("t_first_us", "first")}
    if "pkts_first" in d:
        agg["pkts_first"] = ("pkts_first", "first")
    return d.groupby(["flow_idx", "sid"], sort=True).agg(**agg).reset_index()


def map_suri_flows(gt_flows: pd.DataFrame, suri: pd.DataFrame, *, tol_us: int = US) -> np.ndarray:
    """True for ground-truth flows that overlap in time (± tol) with a Suricata flow of the same key (the Suricata
    flow with the last start <= ground-truth end + tol; flows of one tuple do not overlap in Suricata)."""
    n = len(gt_flows)
    if not n or not len(suri):
        return np.zeros(n, bool)
    G = _keys(gt_flows).assign(te=np.asarray(gt_flows["end_us"], np.int64) + tol_us,
                               ts=np.asarray(gt_flows["ts_us"], np.int64), i=np.arange(n))
    S = _keys(suri).assign(ss=np.asarray(suri["start_us"], np.int64), se=np.asarray(suri["end_us"], np.int64))
    m = pd.merge_asof(G.sort_values("te"), S.sort_values("ss"), left_on="te", right_on="ss", by=["ka", "kb"],
                      direction="backward").dropna(subset=["ss"])
    ok = m["se"].to_numpy(np.int64) >= m["ts"].to_numpy(np.int64) - tol_us
    out = np.zeros(n, bool)
    out[m["i"].to_numpy()[ok]] = True
    return out


# ----------------------------------------------------------------------------
# Conflict resolution (identical to evaluator.resolve)
# ----------------------------------------------------------------------------
def rule_tables(ruleset: Sequence[Dict], sid_map: pd.DataFrame) -> Tuple[list, np.ndarray, np.ndarray, Dict[int, int]]:
    """Rule order = order of the pre-translation ruleset (as in the evaluator). conf/support from sid_map (source
    rule, training pool). Returns (rules, conf, support, sid -> index of the source rule)."""
    idx = {r["rule_id"]: j for j, r in enumerate(ruleset)}
    conf = np.zeros(len(ruleset))
    sup = np.zeros(len(ruleset))
    sid2j = {}
    for r in sid_map.itertuples():
        j = idx[r.source_rule_id]
        conf[j], sup[j] = r.confidence, r.support
        sid2j[int(r.sid)] = j
    return list(ruleset), conf, sup, sid2j


def resolve_flows(n_flows: int, agg: pd.DataFrame, rules: list, conf: np.ndarray, support: np.ndarray,
                  sid2j: Dict[int, int], benign: str = "BENIGN") -> Tuple[np.ndarray, np.ndarray, Dict]:
    """agg: mapped (flow_idx, sid) with flow_idx = positional index of the ground-truth flow. A hit = a source rule
    with >= 1 alert. Returns (prediction, index of the deciding rule, info on unknown sids)."""
    from scipy import sparse
    a = agg[agg["flow_idx"] >= 0]
    j = a["sid"].map(sid2j)
    unknown = a.loc[j.isna(), "sid"].value_counts().to_dict()
    a, j = a[j.notna()], j[j.notna()].astype(np.int64)
    hits = sparse.csr_matrix((np.ones(len(a), bool), (a["flow_idx"].to_numpy(np.int64), j.to_numpy())),
                             shape=(n_flows, len(rules)), dtype=bool)
    hits.data[:] = True
    pred, win = evaluator.resolve(hits, rules, conf, support, benign=benign)
    return pred, win, {"unknown_sids": {int(k): int(v) for k, v in unknown.items()}}
