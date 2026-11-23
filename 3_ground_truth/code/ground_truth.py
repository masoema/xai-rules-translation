"""
================================================================================
ground_truth — derived ground truth from the CIC-DDoS2019 PCAP files
================================================================================
STAND-ALONE module: it imports no model, ruleset, evaluator or rule result. The ground truth
is built only from the PCAP files, the raw official CIC-DDoS2019 CSV files, the attack
schedule of the dataset paper, and the configuration `ground_truth_rq1.yaml`:

  1 re-extract        CICFlowMeter (Java) per PCAP file -> flows + features  (read_cfm_csv)
  2 behavioural label explicit rules in the config (behaviour_label)
  3 attack type       schedule (Table III of the dataset paper) + protocol/port signatures from
                      the official CSV files + endpoint roles (attacker/victim) checked on them
  4 time-zone align   America/Halifax (DST-aware; 1 December 2018 = AST, UTC-4)
  5 ambiguous         AMBIGUOUS + reason code, excluded from TP/FP

Also: a light PCAP parser (inventory, magic-number check), an index of the official CSV files
(identifiers + label), bidirectional flow matching (5-tuple + time tolerance), and a replay of
the seed sampling (chain: ground-truth flow -> official CSV row -> row_id of a seed).
================================================================================
"""
from __future__ import annotations

import ipaddress
import os
import random
import struct
from collections import defaultdict
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import numpy as np
import pandas as pd

TZ = "America/Halifax"
US = 1_000_000

# ----------------------------------------------------------------------------
# PCAP: magic number + summary of one file (no external dependency)
# ----------------------------------------------------------------------------
_PCAP_MAGIC = {b"\xd4\xc3\xb2\xa1": ("<", 1e-6), b"\xa1\xb2\xc3\xd4": (">", 1e-6),
               b"\x4d\x3c\xb2\xa1": ("<", 1e-9), b"\xa1\xb2\x3c\x4d": (">", 1e-9)}
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


def pcap_kind(path: str) -> Optional[str]:
    """'pcap' / 'pcapng' / None (not a capture file). CIC file names without an extension are supported."""
    if not os.path.isfile(path):
        return None
    with open(path, "rb") as f:
        head = f.read(4)
    if head in _PCAP_MAGIC:
        return "pcap"
    if head == _PCAPNG_MAGIC:
        return "pcapng"
    return None


def pcap_summary(path: str, chunk: int = 64 << 20, sha256: bool = True, zip_path: Optional[str] = None) -> Dict:
    """One pass over a classic pcap file: packets, bytes, time of the first/last packet (epoch
    seconds), packets per IP protocol (Ethernet/IPv4; others 'other'/'non_ip'), sha256 of the file.
    zip_path: read the member `path` directly from a zip archive (no extraction)."""
    import hashlib
    import zipfile
    if zip_path:
        zf = zipfile.ZipFile(zip_path)
        opener = lambda: zf.open(path)            # noqa: E731
    else:
        kind = pcap_kind(path)
        if kind != "pcap":
            raise ValueError(f"{path}: not a classic pcap file ({kind})")
        opener = lambda: open(path, "rb")          # noqa: E731
    h = hashlib.sha256() if sha256 else None
    with opener() as f:
        gh = f.read(24)
        if gh[:4] not in _PCAP_MAGIC:
            raise ValueError(f"{path}: magic number is not that of a classic pcap file")
        if h:
            h.update(gh)
        endian, res = _PCAP_MAGIC[gh[:4]]
        linktype = struct.unpack(endian + "I", gh[20:24])[0]
        rec = struct.Struct(endian + "IIII")
        counts = defaultdict(int)
        n = nbytes = 0
        first = last = None
        tmin = tmax = None
        buf, off, truncated = b"", 0, False
        while True:
            data = f.read(chunk)
            if not data:
                break
            if h:
                h.update(data)
            buf = buf[off:] + data
            off, L = 0, len(buf)
            while off + 16 <= L:
                s, frac, incl, orig = rec.unpack_from(buf, off)
                end = off + 16 + incl
                if end > L:
                    break
                t = s + frac * res
                if first is None:
                    first = t
                last = t
                tmin = t if tmin is None or t < tmin else tmin
                tmax = t if tmax is None or t > tmax else tmax
                p = off + 16
                if linktype == 1 and incl >= 34:
                    et = buf[p + 12] << 8 | buf[p + 13]
                    q = p + 14
                    if et == 0x8100 and incl >= 38:          # VLAN
                        et, q = buf[p + 16] << 8 | buf[p + 17], p + 18
                    counts[_PROTO_NAME.get(buf[q + 9], "other") if et == 0x0800 else "non_ip"] += 1
                else:
                    counts["non_ip"] += 1
                n += 1
                nbytes += orig
                off = end
        if off < len(buf):
            truncated = True
    return {"n_packets": n, "bytes": nbytes, "first_ts": first, "last_ts": last, "min_ts": tmin, "max_ts": tmax,
            "linktype": linktype, "proto_packets": dict(counts), "truncated_tail": truncated,
            "sha256": h.hexdigest() if h else None}


_PROTO_NAME = {6: "tcp", 17: "udp", 1: "icmp"}


# ----------------------------------------------------------------------------
# Time zone
# ----------------------------------------------------------------------------
def local_to_utc_us(ts: pd.Series, tz: str = TZ) -> np.ndarray:
    """Local timestamp (string or naive datetime, Atlantic wall-clock time) -> UTC epoch in microseconds."""
    t = pd.to_datetime(ts, format="ISO8601") if not pd.api.types.is_datetime64_any_dtype(ts) else ts
    t = pd.DatetimeIndex(t).tz_localize(tz, ambiguous="raise", nonexistent="raise").tz_convert("UTC")
    return (t.tz_localize(None) - pd.Timestamp("1970-01-01")) // pd.Timedelta(microseconds=1)


def utc_to_local(epoch_s, tz: str = TZ) -> pd.DatetimeIndex:
    return pd.to_datetime(np.asarray(epoch_s, dtype=float), unit="s", utc=True).tz_convert(tz)


def local_clock_to_utc_s(date: str, hhmm: str, tz: str = TZ) -> float:
    """'2018-12-01', '13:29' (local wall-clock time) -> UTC epoch in seconds."""
    return float(pd.Timestamp(f"{date} {hhmm}").tz_localize(tz).tz_convert("UTC").timestamp())


# ----------------------------------------------------------------------------
# IP
# ----------------------------------------------------------------------------
def ip_to_int(s: pd.Series) -> np.ndarray:
    """IPv4 string -> uint32 (via categories; non-IPv4 -> 0)."""
    cat = pd.Categorical(s.astype(str).str.strip())

    def conv(x):
        try:
            return int(ipaddress.IPv4Address(x))
        except ValueError:
            return 0
    lut = np.array([conv(c) for c in cat.categories], dtype=np.uint32)
    codes = cat.codes
    return np.where(codes >= 0, lut[np.clip(codes, 0, None)] if len(lut) else 0, 0).astype(np.uint32)


def int_to_ip(x: int) -> str:
    return str(ipaddress.IPv4Address(int(x)))


def ip_in(ips: np.ndarray, cidrs: Sequence[str]) -> np.ndarray:
    out = np.zeros(len(ips), dtype=bool)
    for c in cidrs:
        net = ipaddress.IPv4Network(c, strict=False)
        lo, hi = int(net.network_address), int(net.broadcast_address)
        out |= (ips >= lo) & (ips <= hi)
    return out


# ----------------------------------------------------------------------------
# Raw official CSV -> index (identifiers + label), one parquet file per CSV file
# ----------------------------------------------------------------------------
OFFICIAL_ID_COLS = {"Unnamed: 0": "unnamed0", "Source IP": "src_ip", "Source Port": "src_port",
                    "Destination IP": "dst_ip", "Destination Port": "dst_port", "Protocol": "proto",
                    "Timestamp": "ts", "Flow Duration": "flow_duration", "Total Fwd Packets": "tot_fwd",
                    "Total Backward Packets": "tot_bwd", "Total Length of Fwd Packets": "totlen_fwd",
                    "Total Length of Bwd Packets": "totlen_bwd", "Label": "label"}


def build_official_index(csv_path: str, out_path: str, *, tz: str = TZ, block_size: int = 64 << 20) -> Dict:
    """Read a raw official CSV file (streaming, identifier columns only) -> parquet:
    row (0-based data row index, file order), unnamed0, src_ip/dst_ip (uint32), ports, proto,
    ts_us (UTC epoch µs; local Atlantic Timestamp), flow_duration, tot_fwd/bwd, totlen_fwd/bwd, label."""
    import pyarrow as pa
    import pyarrow.csv as pacsv
    import pyarrow.parquet as pq
    with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
        header = f.readline().rstrip("\r\n").split(",")
    want = {h: OFFICIAL_ID_COLS[h.strip()] for h in header if h.strip() in OFFICIAL_ID_COLS}
    missing = set(OFFICIAL_ID_COLS) - {h.strip() for h in want}
    if missing:
        raise KeyError(f"{csv_path}: missing columns: {sorted(missing)}")
    types = {h: pa.string() for h, k in want.items() if k in ("src_ip", "dst_ip", "ts", "label")}
    reader = pacsv.open_csv(csv_path, read_options=pacsv.ReadOptions(block_size=block_size),
                            convert_options=pacsv.ConvertOptions(include_columns=list(want), column_types=types))
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    tmp, writer, row0, labels = out_path + ".tmp", None, 0, defaultdict(int)
    try:
        for batch in reader:
            df = batch.to_pandas().rename(columns=want)
            n = len(df)
            out = pd.DataFrame({"row": np.arange(row0, row0 + n, dtype=np.int64),
                                "unnamed0": pd.to_numeric(df["unnamed0"], errors="coerce").fillna(-1).astype(np.int64),
                                "src_ip": ip_to_int(df["src_ip"]), "dst_ip": ip_to_int(df["dst_ip"]),
                                "src_port": pd.to_numeric(df["src_port"], errors="coerce").fillna(-1).astype(np.int32),
                                "dst_port": pd.to_numeric(df["dst_port"], errors="coerce").fillna(-1).astype(np.int32),
                                "proto": pd.to_numeric(df["proto"], errors="coerce").fillna(-1).astype(np.int16),
                                "ts_us": local_to_utc_us(df["ts"].str.strip(), tz).astype(np.int64),
                                "flow_duration": pd.to_numeric(df["flow_duration"], errors="coerce").astype(np.float64),
                                "tot_fwd": pd.to_numeric(df["tot_fwd"], errors="coerce").astype(np.float64),
                                "tot_bwd": pd.to_numeric(df["tot_bwd"], errors="coerce").astype(np.float64),
                                "totlen_fwd": pd.to_numeric(df["totlen_fwd"], errors="coerce").astype(np.float64),
                                "totlen_bwd": pd.to_numeric(df["totlen_bwd"], errors="coerce").astype(np.float64),
                                "label": df["label"].astype(str).str.strip().astype("category")})
            for k, v in out["label"].value_counts().items():
                labels[str(k)] += int(v)
            tbl = pa.Table.from_pandas(out.assign(label=out["label"].astype(str)), preserve_index=False)
            if writer is None:
                writer = pq.ParquetWriter(tmp, tbl.schema, compression="zstd")
            writer.write_table(tbl)
            row0 += n
    finally:
        if writer is not None:
            writer.close()
    os.replace(tmp, out_path)
    return {"rows": row0, "labels": dict(labels)}


# ----------------------------------------------------------------------------
# CICFlowMeter-4.0 output -> dataset column names (as in the official CIC-DDoS2019 CSV files)
# ----------------------------------------------------------------------------
CFM4_TO_DATASET = {
    "Flow ID": "flow_id", "Src IP": "source_ip", "Src Port": "source_port", "Dst IP": "destination_ip",
    "Dst Port": "destination_port", "Protocol": "protocol", "Timestamp": "timestamp",
    "Flow Duration": "flow_duration", "Tot Fwd Pkts": "total_fwd_packets", "Tot Bwd Pkts": "total_backward_packets",
    "TotLen Fwd Pkts": "total_length_of_fwd_packets", "TotLen Bwd Pkts": "total_length_of_bwd_packets",
    "Fwd Pkt Len Max": "fwd_packet_length_max", "Fwd Pkt Len Min": "fwd_packet_length_min",
    "Fwd Pkt Len Mean": "fwd_packet_length_mean", "Fwd Pkt Len Std": "fwd_packet_length_std",
    "Bwd Pkt Len Max": "bwd_packet_length_max", "Bwd Pkt Len Min": "bwd_packet_length_min",
    "Bwd Pkt Len Mean": "bwd_packet_length_mean", "Bwd Pkt Len Std": "bwd_packet_length_std",
    "Flow Byts/s": "flow_bytes/s", "Flow Pkts/s": "flow_packets/s", "Flow IAT Mean": "flow_iat_mean",
    "Flow IAT Std": "flow_iat_std", "Flow IAT Max": "flow_iat_max", "Flow IAT Min": "flow_iat_min",
    "Fwd IAT Tot": "fwd_iat_total", "Fwd IAT Mean": "fwd_iat_mean", "Fwd IAT Std": "fwd_iat_std",
    "Fwd IAT Max": "fwd_iat_max", "Fwd IAT Min": "fwd_iat_min", "Bwd IAT Tot": "bwd_iat_total",
    "Bwd IAT Mean": "bwd_iat_mean", "Bwd IAT Std": "bwd_iat_std", "Bwd IAT Max": "bwd_iat_max",
    "Bwd IAT Min": "bwd_iat_min", "Fwd PSH Flags": "fwd_psh_flags", "Bwd PSH Flags": "bwd_psh_flags",
    "Fwd URG Flags": "fwd_urg_flags", "Bwd URG Flags": "bwd_urg_flags", "Fwd Header Len": "fwd_header_length",
    "Bwd Header Len": "bwd_header_length", "Fwd Pkts/s": "fwd_packets/s", "Bwd Pkts/s": "bwd_packets/s",
    "Pkt Len Min": "min_packet_length", "Pkt Len Max": "max_packet_length", "Pkt Len Mean": "packet_length_mean",
    "Pkt Len Std": "packet_length_std", "Pkt Len Var": "packet_length_variance", "FIN Flag Cnt": "fin_flag_count",
    "SYN Flag Cnt": "syn_flag_count", "RST Flag Cnt": "rst_flag_count", "PSH Flag Cnt": "psh_flag_count",
    "ACK Flag Cnt": "ack_flag_count", "URG Flag Cnt": "urg_flag_count", "CWE Flag Count": "cwe_flag_count",
    "ECE Flag Cnt": "ece_flag_count", "Down/Up Ratio": "down/up_ratio", "Pkt Size Avg": "average_packet_size",
    "Fwd Seg Size Avg": "avg_fwd_segment_size", "Bwd Seg Size Avg": "avg_bwd_segment_size",
    "Fwd Byts/b Avg": "fwd_avg_bytes/bulk", "Fwd Pkts/b Avg": "fwd_avg_packets/bulk",
    "Fwd Blk Rate Avg": "fwd_avg_bulk_rate", "Bwd Byts/b Avg": "bwd_avg_bytes/bulk",
    "Bwd Pkts/b Avg": "bwd_avg_packets/bulk", "Bwd Blk Rate Avg": "bwd_avg_bulk_rate",
    "Subflow Fwd Pkts": "subflow_fwd_packets", "Subflow Fwd Byts": "subflow_fwd_bytes",
    "Subflow Bwd Pkts": "subflow_bwd_packets", "Subflow Bwd Byts": "subflow_bwd_bytes",
    "Init Fwd Win Byts": "init_win_bytes_forward", "Init Bwd Win Byts": "init_win_bytes_backward",
    "Fwd Act Data Pkts": "act_data_pkt_fwd", "Fwd Seg Size Min": "min_seg_size_forward",
    "Active Mean": "active_mean", "Active Std": "active_std", "Active Max": "active_max", "Active Min": "active_min",
    "Idle Mean": "idle_mean", "Idle Std": "idle_std", "Idle Max": "idle_max", "Idle Min": "idle_min",
    "Label": "cfm_label"}
# The official CSV files (CICFlowMeter-V3) have 'Fwd Header Length.1' (a copy of fwd_header_length),
# 'SimillarHTTP' and 'Inbound'; CICFlowMeter-4.0 does not output these three columns.


def read_cfm_csv(path: str, *, tz: str = TZ) -> pd.DataFrame:
    """CICFlowMeter-4.0 output (`*_Flow.csv`) -> DataFrame with dataset column names + src_ip/dst_ip
    uint32. The CICFlowMeter-4.0 Timestamp is 'dd/mm/yyyy hh:mm:ss AM/PM' in the time zone of the JVM
    that ran it; it is converted with cfm_timestamp_to_utc_us (the JVM zone was pinned to UTC)."""
    df = pd.read_csv(path, low_memory=False)
    df.columns = [c.strip() for c in df.columns]
    unknown = [c for c in df.columns if c not in CFM4_TO_DATASET]
    if unknown:
        raise KeyError(f"{path}: unknown CICFlowMeter columns: {unknown[:5]}")
    df = df.rename(columns=CFM4_TO_DATASET)
    df["src_ip"] = ip_to_int(df["source_ip"])
    df["dst_ip"] = ip_to_int(df["destination_ip"])
    df["fwd_header_length.1"] = df["fwd_header_length"]
    return df


def cfm_timestamp_to_utc_us(ts: pd.Series, jvm_tz: str) -> np.ndarray:
    """CICFlowMeter-4.0 Timestamp ('01/12/2018 01:04:45 PM', one-second precision, JVM zone) -> UTC epoch µs."""
    t = pd.to_datetime(ts.astype(str).str.strip(), format="%d/%m/%Y %I:%M:%S %p")
    t = pd.DatetimeIndex(t).tz_localize(jvm_tz).tz_convert("UTC").tz_localize(None)
    return (t - pd.Timestamp("1970-01-01")) // pd.Timedelta(microseconds=1)


# ----------------------------------------------------------------------------
# Bidirectional flow matching (canonical 5-tuple + start time ± tolerance, one-to-one)
# ----------------------------------------------------------------------------
def canonical_key(src_ip, src_port, dst_ip, dst_port, proto) -> Tuple[np.ndarray, np.ndarray]:
    """Bidirectional key: (smaller endpoint, larger endpoint + protocol) as two int64."""
    a = (np.asarray(src_ip, np.int64) << 16) | np.asarray(src_port, np.int64)
    b = (np.asarray(dst_ip, np.int64) << 16) | np.asarray(dst_port, np.int64)
    lo, hi = np.minimum(a, b), np.maximum(a, b)
    return lo, (hi << 8) | np.asarray(proto, np.int64)


def match_flows(left: pd.DataFrame, right: pd.DataFrame, *, tol_us: int = US, t_col: str = "ts_us",
                rounds: int = 3) -> pd.DataFrame:
    """Match the flows of `left` to `right` (columns src_ip, src_port, dst_ip, dst_port, proto, ts_us):
    bidirectional 5-tuple key + |Δt| <= tol_us; one-to-one (smallest |Δt| first; flows that lose get
    another chance for up to `rounds` rounds). Result: li, ri (positional indices), dt_us."""
    def prep(d):
        ka, kb = canonical_key(d["src_ip"], d["src_port"], d["dst_ip"], d["dst_port"], d["proto"])
        return pd.DataFrame({"ka": ka, "kb": kb, "t": np.asarray(d[t_col], np.int64), "i": np.arange(len(d))})
    L, R = prep(left), prep(right)
    pairs, used_l, used_r = [], np.zeros(len(L), bool), np.zeros(len(R), bool)
    for _ in range(rounds):
        l2, r2 = L[~used_l[L["i"]]], R[~used_r[R["i"]]]
        if not len(l2) or not len(r2):
            break
        m = pd.merge_asof(l2.sort_values("t"), r2.sort_values("t").rename(columns={"i": "ri", "t": "tr"}),
                          left_on="t", right_on="tr", by=["ka", "kb"], tolerance=tol_us, direction="nearest")
        m = m.dropna(subset=["ri"])
        if not len(m):
            break
        m = m.assign(ri=m["ri"].astype(np.int64), dt=(m["t"] - m["tr"]).astype(np.int64))
        m = m.assign(adt=m["dt"].abs()).sort_values(["adt", "i"]).drop_duplicates("ri")
        pairs.append(m[["i", "ri", "dt"]])
        used_l[m["i"].to_numpy()] = True
        used_r[m["ri"].to_numpy()] = True
    if not pairs:
        return pd.DataFrame({"li": np.array([], np.int64), "ri": np.array([], np.int64), "dt_us": np.array([], np.int64)})
    out = pd.concat(pairs, ignore_index=True).rename(columns={"i": "li", "dt": "dt_us"})
    return out.sort_values("li").reset_index(drop=True)


# ----------------------------------------------------------------------------
# Replay of the seed sampling (build_datasets_rigorous.py) -> official CSV row of each row of a seed CSV
# ----------------------------------------------------------------------------
SEED_BUILDER = {"files": ["DrDoS_DNS.csv", "DrDoS_LDAP.csv", "DrDoS_MSSQL.csv", "DrDoS_NTP.csv",
                          "DrDoS_NetBIOS.csv", "DrDoS_SNMP.csv", "DrDoS_SSDP.csv", "DrDoS_UDP.csv", "Syn.csv",
                          "TFTP.csv", "UDPLag.csv"],
                "train_cap": 100_000, "val_cap": 100_000, "n_strata": 10, "train_ratio": 0.80,
                "exclude": ("WebDDoS",),
                "known_counts": {"BENIGN": 56_863, "DrDoS_DNS": 5_071_011, "DrDoS_LDAP": 2_179_930,
                                 "DrDoS_MSSQL": 4_522_492, "DrDoS_NTP": 1_202_642, "DrDoS_NetBIOS": 4_093_279,
                                 "DrDoS_SNMP": 5_159_870, "DrDoS_SSDP": 2_610_611, "DrDoS_UDP": 3_134_645,
                                 "Syn": 1_582_289, "TFTP": 20_082_580, "UDP-lag": 366_461}}


def replay_seed_sampling(labels: Sequence, seed: int, cfg: Dict = SEED_BUILDER,
                         names: Optional[Sequence[str]] = None) -> Tuple[np.ndarray, np.ndarray]:
    """Repeat stratified_reservoir_sample + write_csv (build_datasets_rigorous.py) over the label sequence
    of all day-1 CSV rows (order of cfg['files'], file row order). Returns (train_idx, val_idx): the global
    official row index of row i of training_/validation_day1_seed<S>.csv. The RNG is consumed exactly as in
    the original script (random() per row, randint() when full, shuffle per file).
    names: if given, `labels` holds int codes and names[code] = label (saves memory)."""
    if names is not None:
        lut = [str(x).strip() for x in names]
        labels = (lut[c] for c in labels)
    rng = random.Random(seed)
    tps = max(1, int(cfg["train_cap"] * cfg["train_ratio"]) // cfg["n_strata"])
    vps = max(1, int(cfg["val_cap"] * (1 - cfg["train_ratio"])) // cfg["n_strata"])
    bound = {k: max(1, v // cfg["n_strata"]) for k, v in cfg["known_counts"].items()}
    excl, ns, ratio = set(cfg["exclude"]), cfg["n_strata"], cfg["train_ratio"]
    tr = defaultdict(lambda: defaultdict(list))
    vl = defaultdict(lambda: defaultdict(list))
    seen = defaultdict(int)
    tr_seen = defaultdict(lambda: defaultdict(int))
    vl_seen = defaultdict(lambda: defaultdict(int))
    rnd, rint = rng.random, rng.randint
    for g, lab in enumerate(labels):
        if not lab or lab in excl:
            continue
        seen[lab] += 1
        b = bound.get(lab)
        if b is None:                     # unknown label: total = seen (as .get(label, seen))
            b = max(1, seen[lab] // ns)
        stratum = min(ns - 1, (seen[lab] - 1) // b)
        if rnd() < ratio:
            pool, ps, cap = tr, tr_seen, tps
        else:
            pool, ps, cap = vl, vl_seen, vps
        ps[lab][stratum] += 1
        n = ps[lab][stratum]
        bucket = pool[lab][stratum]
        if n <= cap:
            bucket.append(g)
        else:
            j = rint(0, n - 1)
            if j < cap:
                bucket[j] = g

    def flat(pool):
        out = []
        for lab in pool:
            for s in pool[lab]:
                out.extend(pool[lab][s])
        return out
    tr_rows, vl_rows = flat(tr), flat(vl)
    rng.shuffle(tr_rows)
    rng.shuffle(vl_rows)
    return np.asarray(tr_rows, np.int64), np.asarray(vl_rows, np.int64)


# ----------------------------------------------------------------------------
# CICFlowMeter Java (official release; not the Python package `cicflowmeter`)
# ----------------------------------------------------------------------------
CFM_MAIN = "cic.cs.unb.ca.ifm.Cmd"


def cfm_info(cfm_home: str, java: str = "java") -> Dict:
    """CICFlowMeter version (jar name + sha256), jnetpcap and the Java that is used."""
    import hashlib
    import subprocess
    lib = os.path.join(cfm_home, "lib")
    jars = sorted(os.listdir(lib)) if os.path.isdir(lib) else []
    main = [j for j in jars if j.lower().startswith("cicflowmeter")]
    jn = [j for j in jars if j.lower().startswith("jnetpcap")]

    def sha(p):
        h = hashlib.sha256()
        with open(p, "rb") as f:
            h.update(f.read())
        return h.hexdigest()
    try:
        jv = subprocess.run([java, "-version"], capture_output=True, text=True, timeout=60).stderr.strip().splitlines()
    except (OSError, subprocess.SubprocessError) as e:          # pragma: no cover
        jv = [f"java not available: {e}"]
    native = os.path.join(lib, "native")
    return {"cfm_home": os.path.abspath(cfm_home), "jar": main, "jar_sha256": {j: sha(os.path.join(lib, j)) for j in main},
            "jnetpcap": jn, "native": sorted(os.listdir(native)) if os.path.isdir(native) else [],
            "java": jv[:2], "main_class": CFM_MAIN}


def run_cfm(pcap: str, out_dir: str, cfm_home: str, *, java: str = "java", jvm_tz: str = "UTC",
            log_path: Optional[str] = None, timeout: Optional[int] = None) -> Dict:
    """Run the CICFlowMeter CLI (`cfm <pcap> <out_dir>`) with -Duser.timezone=<jvm_tz>, so the Timestamp
    column does not depend on the zone of the machine. Returns the CSV path, duration and packet counts."""
    import re
    import subprocess
    import time
    lib = os.path.join(cfm_home, "lib")
    cp = os.pathsep.join(os.path.join(lib, j) for j in sorted(os.listdir(lib)) if j.endswith(".jar"))
    os.makedirs(out_dir, exist_ok=True)
    cmd = [java, f"-Djava.library.path={os.path.join(lib, 'native')}", f"-Duser.timezone={jvm_tz}",
           "-classpath", cp, CFM_MAIN, pcap, out_dir]
    t0 = time.time()
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=os.path.join(cfm_home, "bin"))
    secs = time.time() - t0
    txt = (p.stdout or "") + (p.stderr or "")
    if log_path:
        tail = [ln for ln in txt.splitlines() if " flows " not in ln or "done" in ln]
        with open(log_path, "w", encoding="utf-8") as f:
            f.write("\n".join(tail[-200:]))
    m = re.search(r"Total=(\d+),Valid=(\d+),Discarded=(\d+)", txt)
    nflow = re.search(r"is done\. total (\d+) flows", txt)
    csv = os.path.join(out_dir, os.path.basename(pcap) + "_Flow.csv")
    return {"pcap": pcap, "csv": csv, "exit_code": p.returncode, "seconds": round(secs, 1),
            "packets_total": int(m.group(1)) if m else None, "packets_valid": int(m.group(2)) if m else None,
            "packets_discarded": int(m.group(3)) if m else None, "n_flows": int(nflow.group(1)) if nflow else None,
            "jvm_tz": jvm_tz, "ok": p.returncode == 0 and os.path.exists(csv)}


# ----------------------------------------------------------------------------
# CICFlowMeter version check: re-extraction vs official CSV
# ----------------------------------------------------------------------------
def official_frame(csv_path: str, *, tz: str = TZ) -> pd.DataFrame:
    """Full raw official CSV (one file) with dataset column names + src_ip/dst_ip/proto/ts_us."""
    df = pd.read_csv(csv_path, low_memory=False)
    df.columns = [str(c).strip().replace(" ", "_").lower() for c in df.columns]
    df["label"] = df["label"].astype(str).str.strip()
    df["src_ip"], df["dst_ip"] = ip_to_int(df["source_ip"]), ip_to_int(df["destination_ip"])
    df["src_port"], df["dst_port"] = df["source_port"].astype(np.int64), df["destination_port"].astype(np.int64)
    df["proto"] = df["protocol"].astype(np.int64)
    df["ts_us"] = local_to_utc_us(df["timestamp"].astype(str).str.strip(), tz)
    return df


def cfm_frame_for_match(cfm: pd.DataFrame, jvm_tz: str = "UTC") -> pd.DataFrame:
    out = cfm.copy()
    out["src_port"], out["dst_port"] = out["source_port"].astype(np.int64), out["destination_port"].astype(np.int64)
    out["proto"] = out["protocol"].astype(np.int64)
    out["ts_us"] = cfm_timestamp_to_utc_us(out["timestamp"], jvm_tz)
    return out


def compare_features(off: pd.DataFrame, cfm: pd.DataFrame, pairs: pd.DataFrame, features: Sequence[str],
                     rtol: float = 1e-6, atol: float = 1e-6) -> pd.DataFrame:
    """Per feature, on matched flow pairs: share of equal values (|a-b| <= atol + rtol·|a|) and the
    median absolute difference."""
    a = off.iloc[pairs["ri"].to_numpy()]
    b = cfm.iloc[pairs["li"].to_numpy()]
    rows = []
    for f in features:
        if f not in a.columns or f not in b.columns:
            rows.append({"feature": f, "n": 0, "equal": None, "median_abs_diff": None, "note": "column missing"})
            continue
        x = pd.to_numeric(a[f], errors="coerce").to_numpy(np.float64)
        y = pd.to_numeric(b[f], errors="coerce").to_numpy(np.float64)
        ok = np.isfinite(x) & np.isfinite(y)
        with np.errstate(invalid="ignore"):
            eq = np.abs(x - y) <= atol + rtol * np.abs(x)
        both_nan = ~np.isfinite(x) & ~np.isfinite(y)
        rows.append({"feature": f, "n": int(len(x)), "equal": float(np.mean(eq | both_nan)),
                     "median_abs_diff": float(np.median(np.abs(x[ok] - y[ok]))) if ok.any() else None, "note": ""})
    return pd.DataFrame(rows)


# ----------------------------------------------------------------------------
# Facts of the official CSV files (descriptive; basis of the schedule, protocol/port signatures and endpoint roles)
# ----------------------------------------------------------------------------
def official_facts(index_files: Sequence[str], *, top: int = 5, tz: str = TZ) -> Dict:
    """Per label (all official day-1 CSV files): count, time range (UTC and local; min, p01, p50, p99, max),
    protocol, top source/destination IPs and ports, share of one-way flows (tot_bwd == 0, V3 direction),
    median packets. Also per (CSV file, label). Uses no model and no rule result."""
    import pyarrow.parquet as pq
    cols = ["src_ip", "dst_ip", "src_port", "dst_port", "proto", "ts_us", "tot_fwd", "tot_bwd", "flow_duration", "label"]
    acc: Dict[str, Dict] = {}
    per_file = []
    for p in index_files:
        name = os.path.splitext(os.path.basename(p))[0]
        pf = {}
        for batch in pq.ParquetFile(p).iter_batches(batch_size=2_000_000, columns=cols):
            df = batch.to_pandas()
            for lab, g in df.groupby("label", observed=True):
                f = pf.setdefault(lab, {"n": 0, "ts_min": np.iinfo(np.int64).max, "ts_max": np.iinfo(np.int64).min})
                f["n"] += len(g)
                f["ts_min"], f["ts_max"] = min(f["ts_min"], int(g["ts_us"].min())), max(f["ts_max"], int(g["ts_us"].max()))
                a = acc.setdefault(lab, {"n": 0, "ts": [], "proto": defaultdict(int), "src_ip": defaultdict(int),
                                         "dst_ip": defaultdict(int), "src_port": defaultdict(int),
                                         "dst_port": defaultdict(int), "uni": 0, "pk": []})
                a["n"] += len(g)
                step = max(1, len(g) // 50_000)        # time/packet sample for the quantiles (deterministic)
                a["ts"].append(np.concatenate([g["ts_us"].to_numpy()[::step], [g["ts_us"].min(), g["ts_us"].max()]]))
                a["pk"].append((g["tot_fwd"] + g["tot_bwd"]).to_numpy()[::step])
                a["uni"] += int((g["tot_bwd"] == 0).sum())
                for c in ("proto", "src_ip", "dst_ip"):
                    for k, v in g[c].value_counts().head(50).items():
                        a[c][int(k)] += int(v)
                for c in ("src_port", "dst_port"):
                    for k, v in g[c].value_counts().head(200).items():
                        a[c][int(k)] += int(v)
            del df
        per_file += [{"file": name, "label": lab, **v} for lab, v in pf.items()]
    out = {}
    for lab, a in acc.items():
        ts = np.concatenate(a["ts"])
        q = {k: float(np.percentile(ts, v)) for k, v in (("p01", 1), ("p50", 50), ("p99", 99))}
        q.update(min=float(ts.min()), max=float(ts.max()))
        loc = {k: str(utc_to_local([v / US], tz)[0].strftime("%H:%M:%S")) for k, v in q.items()}

        def topk(d, ip=False):
            s = sorted(d.items(), key=lambda kv: -kv[1])[:top]
            return [{"value": int_to_ip(k) if ip else int(k), "share": v / a["n"]} for k, v in s]
        out[lab] = {"n": a["n"], "ts_utc_us": q, "ts_local": loc, "proto": topk(a["proto"]),
                    "src_ip": topk(a["src_ip"], True), "dst_ip": topk(a["dst_ip"], True),
                    "src_port": topk(a["src_port"]), "dst_port": topk(a["dst_port"]),
                    "unidirectional_share": a["uni"] / a["n"], "median_packets": float(np.median(np.concatenate(a["pk"])))}
    return {"labels": out, "per_file": per_file}


# ----------------------------------------------------------------------------
# Inventory of the day-1 PCAP files
# ----------------------------------------------------------------------------
DAY1_PREFIX = "SAT-01-12-2018_"


def pcap_index(name: str) -> int:
    """'SAT-01-12-2018_0' -> 0, '_01' -> 1, '_0817' -> 817 (CIC capture order)."""
    return int(name.rsplit("_", 1)[1])


def list_day1_pcaps(pcap_root: str, zip_root: Optional[str] = None, prefix: str = DAY1_PREFIX) -> pd.DataFrame:
    """All day-1 PCAP files: extracted files (PCAP-01-12_*/<name>, regular file + pcap magic number) and
    members of PCAP-01-12_*.zip that are not extracted (read directly from the zip)."""
    import glob
    import zipfile
    rows = {}
    for p in sorted(glob.glob(os.path.join(pcap_root, "PCAP-01-12_*", prefix + "*"))):
        if pcap_kind(p) == "pcap":
            n = os.path.basename(p)
            rows[n] = {"name": n, "folder": os.path.basename(os.path.dirname(p)), "path": p, "zip": None,
                       "size_bytes": os.path.getsize(p)}
    if zip_root:
        for z in sorted(glob.glob(os.path.join(zip_root, "PCAP-01-12_*.zip"))):
            with zipfile.ZipFile(z) as zf:
                for info in zf.infolist():
                    n = os.path.basename(info.filename)
                    if n.startswith(prefix) and not info.is_dir() and n not in rows:
                        rows[n] = {"name": n, "folder": os.path.splitext(os.path.basename(z))[0], "path": info.filename,
                                   "zip": z, "size_bytes": info.file_size}
    df = pd.DataFrame(list(rows.values()))
    df["idx"] = df["name"].map(pcap_index)
    return df.sort_values("idx").reset_index(drop=True)


def _inventory_one(row: Dict) -> Dict:
    s = pcap_summary(row["path"], zip_path=row.get("zip"))
    return {**row, **s}


def official_counts_in_ranges(index_files: Sequence[str], lo_us: np.ndarray, hi_us: np.ndarray) -> Tuple[pd.DataFrame, Dict]:
    """Number of raw official CSV rows per label with a Timestamp (UTC) in [lo, hi] of each PCAP file, plus
    the number of rows that fall in no file range."""
    import pyarrow.parquet as pq
    ts_by_label: Dict[str, List[np.ndarray]] = defaultdict(list)
    for p in index_files:
        t = pq.read_table(p, columns=["ts_us", "label"]).to_pandas()
        for lab, g in t.groupby("label", observed=True):
            ts_by_label[str(lab)].append(g["ts_us"].to_numpy())
        del t
    out, outside = {}, {}
    order = np.argsort(lo_us)
    lo_s, hi_s = lo_us[order], hi_us[order]
    for lab, parts in ts_by_label.items():
        ts = np.sort(np.concatenate(parts))
        cnt = np.searchsorted(ts, hi_us, side="right") - np.searchsorted(ts, lo_us, side="left")
        out[lab] = cnt
        pos = np.searchsorted(lo_s, ts, side="right") - 1          # last range that starts <= ts
        inside = (pos >= 0) & (ts <= hi_s[np.clip(pos, 0, None)])
        outside[lab] = int((~inside).sum())
    return pd.DataFrame(out), outside


# ----------------------------------------------------------------------------
# Ground-truth rules — all parameters from ground_truth_rq1.yaml
# ----------------------------------------------------------------------------
AMBIGUOUS = "AMBIGUOUS"
BENIGN_LABEL = "BENIGN"
# behaviour_indeterminate only occurs with config version 1 (non-attacker flows), not with version 2.
REASONS = ("cross_window", "behaviour_schedule_conflict", "protocol_mismatch", "protocol_mismatch_udplag_tcp",
           "endpoint_conflict", "webddos_window", "behaviour_indeterminate")
BEHAVIOURS = ("attack_like", "benign_like", "indeterminate")


def load_gt_config(path: str) -> Dict:
    import yaml
    with open(path, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    for k in ("timezone", "date", "taxonomy", "schedule", "endpoints", "signatures", "behaviour"):
        if k not in cfg:
            raise KeyError(f"{path}: key '{k}' missing")
    return cfg


def flow_table(cfm: pd.DataFrame, cfg: Dict, *, jvm_tz: str = "UTC") -> pd.DataFrame:
    """Re-extracted flows (CICFlowMeter-4.0) -> identifiers + behaviour quantities. fwd_c/bwd_c are corrected
    with `extractor.direction_fix` of the config (4.0 shifts one packet from fwd to bwd)."""
    fix = cfg.get("extractor", {}).get("direction_fix", {"fwd": 0, "bwd": 0})
    fwd = cfm["total_fwd_packets"].to_numpy(np.int64)
    bwd = cfm["total_backward_packets"].to_numpy(np.int64)
    n = fwd + bwd
    ts = np.asarray(cfm_timestamp_to_utc_us(cfm["timestamp"], jvm_tz), np.int64)
    dur = cfm["flow_duration"].to_numpy(np.int64)
    byt = (cfm["total_length_of_fwd_packets"] + cfm["total_length_of_bwd_packets"]).to_numpy(np.float64)
    with np.errstate(divide="ignore", invalid="ignore"):
        rate = np.where(dur > 0, n / (dur / US), np.inf)
    return pd.DataFrame({
        "src_ip": cfm["src_ip"].to_numpy(np.uint32), "dst_ip": cfm["dst_ip"].to_numpy(np.uint32),
        "src_port": cfm["source_port"].to_numpy(np.int32), "dst_port": cfm["destination_port"].to_numpy(np.int32),
        "proto": cfm["protocol"].to_numpy(np.int16), "ts_us": ts, "end_us": ts + dur,
        "duration_us": dur, "n_pkts": n, "fwd_c": np.clip(fwd + int(fix.get("fwd", 0)), 0, None),
        "bwd_c": np.clip(bwd + int(fix.get("bwd", 0)), 0, None), "bytes": byt,
        "pkt_rate": rate, "first_syn": cfm["syn_flag_count"].to_numpy() > 0,
        "first_ack": cfm["ack_flag_count"].to_numpy() > 0, "first_fin": cfm["fin_flag_count"].to_numpy() > 0,
        "first_rst": cfm["rst_flag_count"].to_numpy() > 0,
        "dst_multicast_or_broadcast": _mc_bc(cfm["dst_ip"].to_numpy(np.uint32))})


def _mc_bc(ip: np.ndarray) -> np.ndarray:
    ip = ip.astype(np.int64)
    return ((ip >> 28) == 0xE) | (ip == 0xFFFFFFFF) | ((ip & 0xFF) == 0xFF)


# ----------------------------------------------------------------------------
# Aggregate rate per (src, dst, protocol) per calendar minute (config `aggregate`)
# ----------------------------------------------------------------------------
AGG_KEY = ["src_ip", "dst_ip", "proto", "minute"]


def minute_packets(ft: pd.DataFrame, bin_seconds: int = 60) -> pd.DataFrame:
    """Directed packets per (sender, receiver, protocol, minute): fwd_c to (src -> dst), bwd_c to (dst -> src);
    the packets of a flow are spread evenly over the minutes it covers [ts_us, end_us] (duration 0: its start
    minute). The result can be summed across files (sum_minute_packets)."""
    b = int(bin_seconds) * US
    ts = ft["ts_us"].to_numpy(np.int64)
    end = np.maximum(ft["end_us"].to_numpy(np.int64), ts)
    m0, m1 = ts // b, end // b
    k = (m1 - m0 + 1).astype(np.int64)
    idx = np.repeat(np.arange(len(ft)), k)
    minute = m0[idx] + (np.arange(int(k.sum())) - np.repeat(np.cumsum(k) - k, k))
    dur = (end - ts)[idx]
    lo, hi = np.maximum(ts[idx], minute * b), np.minimum(end[idx], (minute + 1) * b)
    frac = np.where(dur > 0, np.clip(hi - lo, 0, None) / np.where(dur > 0, dur, 1), 1.0)
    src, dst = ft["src_ip"].to_numpy(np.int64)[idx], ft["dst_ip"].to_numpy(np.int64)[idx]
    proto = ft["proto"].to_numpy(np.int64)[idx]
    fwd = ft["fwd_c"].to_numpy(np.float64)[idx] * frac
    bwd = ft["bwd_c"].to_numpy(np.float64)[idx] * frac
    d = pd.DataFrame({"src_ip": np.concatenate([src, dst]), "dst_ip": np.concatenate([dst, src]),
                      "proto": np.concatenate([proto, proto]), "minute": np.concatenate([minute, minute]),
                      "pkts": np.concatenate([fwd, bwd])})
    d = d[d["pkts"] > 0]
    return d.groupby(AGG_KEY, sort=False)["pkts"].sum().reset_index()


def sum_minute_packets(parts: Iterable[pd.DataFrame]) -> pd.DataFrame:
    return pd.concat(list(parts), ignore_index=True).groupby(AGG_KEY, sort=True)["pkts"].sum().reset_index()


def attach_minute_rate(ft: pd.DataFrame, agg: pd.DataFrame, bin_seconds: int = 60,
                       column: str = "agg_pkt_rate_minute") -> pd.DataFrame:
    """Add the aggregate rate (packets/s) of the (src, dst, protocol) pair in the minute in which the flow STARTS."""
    b = int(bin_seconds) * US
    key = pd.DataFrame({"src_ip": ft["src_ip"].to_numpy(np.int64), "dst_ip": ft["dst_ip"].to_numpy(np.int64),
                        "proto": ft["proto"].to_numpy(np.int64), "minute": ft["ts_us"].to_numpy(np.int64) // b})
    m = key.merge(agg, on=AGG_KEY, how="left", sort=False)
    out = ft.copy()
    out[column] = m["pkts"].fillna(0.0).to_numpy() / bin_seconds
    return out


def official_view(df: pd.DataFrame, cfg: Dict) -> np.ndarray:
    """Official-label view: the official CSV label after the taxonomy on joined flows; otherwise
    `official_view.unjoined` (not scored)."""
    un = cfg.get("official_view", {}).get("unjoined", "NOT_JOINED")
    joined = df["official_row"].to_numpy() >= 0
    return np.where(joined, df["official_label"].astype(str).to_numpy(), un).astype(object)


_OPS = {"==": np.equal, "!=": np.not_equal, ">": np.greater, ">=": np.greater_equal, "<": np.less, "<=": np.less_equal}


def _cond(ft: pd.DataFrame, c: Dict) -> np.ndarray:
    x = ft[c["field"]].to_numpy()
    if c["op"] == "in":
        return np.isin(x, c["value"])
    return _OPS[c["op"]](x, c["value"])


def behaviour_label(ft: pd.DataFrame, bcfg: Dict) -> Tuple[np.ndarray, np.ndarray]:
    """Ordered behaviour rules (the first matching rule wins); no match -> default."""
    lab = np.full(len(ft), bcfg.get("default", "indeterminate"), dtype=object)
    rid = np.full(len(ft), "default", dtype=object)
    free = np.ones(len(ft), bool)
    for r in bcfg["rules"]:
        if r["label"] not in BEHAVIOURS:
            raise ValueError(f"unknown behaviour label: {r['label']}")
        m = free.copy()
        if r.get("proto") is not None:
            m &= np.isin(ft["proto"].to_numpy(), r["proto"])
        for c in r.get("all", []):
            m &= _cond(ft, c)
        lab[m], rid[m] = r["label"], r["name"]
        free &= ~m
    return lab, rid


def schedule_windows(cfg: Dict, which: Optional[str] = None) -> pd.DataFrame:
    """Attack windows (UTC µs) from the config: original CSV label, taxonomy class, start/end (local time)."""
    which = which or cfg["schedule"]["active"]
    rows = []
    for w in cfg["schedule"][which]:
        rows.append({"label": w["label"], "class": cfg["taxonomy"]["map"].get(w["label"], w["label"]),
                     "out_of_taxonomy": bool(w.get("out_of_taxonomy", False)),
                     "start_us": int(local_clock_to_utc_s(cfg["date"], w["start"], cfg["timezone"]) * US),
                     "end_us": int(local_clock_to_utc_s(cfg["date"], w["end"], cfg["timezone"]) * US)})
    df = pd.DataFrame(rows).sort_values("start_us").reset_index(drop=True)
    if (df["start_us"].to_numpy()[1:] < df["end_us"].to_numpy()[:-1]).any():
        raise ValueError(f"windows of schedule '{which}' overlap")
    return df


def window_of(t_us: np.ndarray, win: pd.DataFrame) -> np.ndarray:
    """Index of the window that contains t (start <= t < end), -1 outside all windows."""
    s, e = win["start_us"].to_numpy(), win["end_us"].to_numpy()
    pos = np.searchsorted(s, t_us, side="right") - 1
    ok = (pos >= 0) & (t_us < e[np.clip(pos, 0, None)])
    return np.where(ok, pos, -1)


def signature_ok(ft: pd.DataFrame, sig: Dict) -> np.ndarray:
    m = np.isin(ft["proto"].to_numpy(), sig["proto"])
    ports = sig.get("ports")
    if ports:
        sp, dp = ft["src_port"].to_numpy(), ft["dst_port"].to_numpy()
        side = sig.get("port_side", "either")
        pm = {"src": np.isin(sp, ports), "dst": np.isin(dp, ports),
              "either": np.isin(sp, ports) | np.isin(dp, ports)}[side]
        m &= pm
    return m


def label_flows(ft: pd.DataFrame, cfg: Dict) -> pd.DataFrame:
    """Ground truth per flow: behaviour, window (flow start/end), endpoints, signature -> gt_label +
    gt_reason (AMBIGUOUS code) + gt_label_udplag (sensitivity: attacker<->victim TCP flows in the UDP-lag
    window are labelled UDP-lag, as in the official labels) + benign_subtag (behaviour of BENIGN flows without
    the attacker endpoint). The decision order is written in the config (comment after `non_attacker`).
    Aggregate behaviour fields (e.g. agg_pkt_rate_minute) must already be added to `ft` (attach_minute_rate)."""
    beh, beh_rule = behaviour_label(ft, cfg["behaviour"])
    win = schedule_windows(cfg)
    ws, we = window_of(ft["ts_us"].to_numpy(), win), window_of(ft["end_us"].to_numpy(), win)
    att_ips = np.asarray([int(ipaddress.IPv4Address(x)) for x in cfg["endpoints"]["attacker"]], np.uint32)
    src, dst = ft["src_ip"].to_numpy(), ft["dst_ip"].to_numpy()
    src_att, dst_att = np.isin(src, att_ips), np.isin(dst, att_ips)
    att = src_att | dst_att
    other = np.where(src_att, dst, src)
    vic_ok = att & ~(src_att & dst_att) & ip_in(other, cfg["endpoints"]["victim"])
    n = len(ft)
    lab = np.full(n, AMBIGUOUS, dtype=object)
    why = np.full(n, "", dtype=object)
    ix = np.clip(ws, 0, None)
    wlab = np.where(ws >= 0, win["label"].to_numpy()[ix], "")
    wcls = np.where(ws >= 0, win["class"].to_numpy()[ix], "")
    oot = np.where(ws >= 0, win["out_of_taxonomy"].to_numpy()[ix], False).astype(bool)
    cross = ws != we
    sig = np.zeros(n, bool)
    for wl, s in cfg["signatures"].items():
        m = wlab == wl
        if m.any():
            sig[m] = signature_ok(ft.loc[m], s)
    udplag = cfg.get("udplag_label", "UDP-lag")
    is_tcp = ft["proto"].to_numpy() == 6
    done = np.zeros(n, bool)
    # 1) without the attacker endpoint: BENIGN whatever the behaviour; behaviour -> sub-tag
    na = cfg.get("non_attacker", {})
    sub_map = na.get("subtag", {"benign_like": "benign_like", "attack_like": "benign_attack_like",
                                "indeterminate": "benign_indeterminate"})
    lab[~att] = na.get("label", BENIGN_LABEL)
    subtag = np.full(n, "", dtype=object)
    for b_, s_ in sub_map.items():
        subtag[~att & (beh == b_)] = s_
    done |= ~att
    # 2) with the attacker endpoint: an attack only if window, behaviour, endpoints and signature are consistent
    a = att & ~done
    for mask, r in ((a & cross, "cross_window"),
                    (a & (ws < 0) & (beh == "benign_like"), "endpoint_conflict"),
                    (a & (ws < 0), "behaviour_schedule_conflict"),
                    (a & oot, "webddos_window"),
                    (a & (beh != "attack_like"), "behaviour_schedule_conflict"),
                    (a & ~vic_ok, "endpoint_conflict"),
                    (a & ~sig & (wlab == udplag) & is_tcp, "protocol_mismatch_udplag_tcp"),
                    (a & ~sig, "protocol_mismatch")):
        m = mask & ~done
        why[m] = r
        done |= m
    m = a & ~done
    lab[m] = wcls[m]
    sens = lab.copy()
    sm = att & vic_ok & is_tcp & (wlab == udplag) & ~cross
    sens[sm] = cfg["taxonomy"]["map"].get(udplag, udplag)
    return pd.DataFrame({"behaviour": beh, "behaviour_rule": beh_rule, "window_start": wlab,
                         "window_end": np.where(we >= 0, win["label"].to_numpy()[np.clip(we, 0, None)], ""),
                         "attacker_involved": att, "attacker_victim": vic_ok, "signature_ok": sig,
                         "gt_label": lab, "gt_reason": why, "gt_label_udplag": sens, "benign_subtag": subtag})
