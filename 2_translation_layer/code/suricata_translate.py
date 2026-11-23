"""
================================================================================
suricata_translate — Suricata translation layer for rules learned on flow features
================================================================================
One layer for all three methods (proposed, Anomaly2Sign, RF-Surrogate). Input = a ruleset in
the evaluator format (conditions in original feature units); output = the same ruleset with a
translation status per condition, the Suricata rule text and one Lua script per rule.

Design:
  - protocol header per rule (not `alert udp` for every class);
  - a status per condition (`translated` bool + `translation` {kind, keyword, note});
  - one feature map (FEATURE_MAP) for all methods; an unknown feature is an error;
  - flags use `flags:X+` (bit X set, other flags free), not `flags:X` (only X);
  - all packet-size conditions are merged into one `dsize` interval; an empty interval
    (flows with packets of different sizes) is moved to Lua, not dropped;
  - rate, volume and time features are computed in Lua with the CICFlowMeter definitions,
    not with `threshold` (a per-source rate across flows, a different meaning).

Decisions:
  Flag columns   The bit of each flag column comes from the config (flag_bits); the mapping
                 was checked against the PCAP files.
  Rates          Rate features -> Lua.
  Header length  fwd/bwd_header_length and min_seg_size_forward are not translated
                 (negative CICFlowMeter overflow values on about 16% of UDP flows; no
                 packet-level definition).
  Protocol       (1) from the rule conditions; (2) otherwise from the training flows that
                 trigger the rule (>= protocol_purity of one protocol), recorded as an extra
                 condition in the deployed view; (3) otherwise `ip`. With split_ip_rules, an
                 `ip` rule whose conditions depend on the protocol (an unset flag, a window
                 with -1) is split into a `tcp` and a `udp` variant (`<rule_id>-tcp/-udp`,
                 `translation.split_from`) instead of dropping those conditions.
  Target         Suricata 7.x (tcp.hdr, byte_test, Lua 5.1-compatible).

Translation kind per condition (`translation.kind`):
  header         protocol / destination port / $HOME_NET direction in the rule header
  native         keyword with the same meaning (flow.pkts_* = running count; Suricata 8 only)
  native_approx  flow aggregate approximated by a per-packet check (dsize, flags, window)
  implied        already covered by the header (e.g. ack_flag_count <= 0.5 in a UDP rule)
  lua            computed in the Lua script of the rule (running flow statistic)
  dropped        not translated (translated = False)
Extra protocol conditions are stored in rule["translation"]["extra_conditions"]
(kind header_inferred); the pre-translation conditions are not changed.

CICFlowMeter definitions reproduced in Lua (checked on the CIC-DDoS2019 data): rate =
count / duration (payload bytes for byte rates); IAT; down/up = floor(bwd/fwd); idle without
the closing term; the FIRST packet is counted twice in the flow packet-length statistics
(mean/std/variance over n+1 values; average_packet_size = (sum + first packet) / n, not a
per-packet size); act_data_pkt_fwd does not count the first packet.

The deployed view only shows the effect of dropped conditions and extra protocol conditions
on flow records. The effect of per-packet checks and running statistics (a rule can fire
before the flow ends) is only visible when the rules run in Suricata.
================================================================================
"""
from __future__ import annotations

import copy
import json
import math
import os
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np
import pandas as pd

try:  # package import or flat import from this folder
    from .evaluator import _OPS, BENIGN, compute_hits  # noqa: F401
except ImportError:
    from evaluator import _OPS, BENIGN, compute_hits  # noqa: F401

TCP, UDP = 6, 17
PROTO_NAME = {TCP: "tcp", UDP: "udp"}
TRANSLATED_KINDS = ("header", "native", "native_approx", "implied", "lua")
KINDS = TRANSLATED_KINDS + ("dropped",)
FLAG_BITS = {"F": 0x01, "S": 0x02, "R": 0x04, "P": 0x08, "A": 0x10, "U": 0x20, "E": 0x40, "C": 0x80}
DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "configs",
                                   "suricata_translation.yaml")

# ----------------------------------------------------------------------------
# Feature map (the 59 model features + the constant flag columns for completeness)
# ----------------------------------------------------------------------------
# CICFlowMeter counts the FIRST packet twice in the flow packet-length statistics (checked
# on 100% of the flows). packet_length_mean/std/variance are computed over n+1 values;
# average_packet_size = (sum + first packet) / n can exceed max_packet_length (79% of the
# flows), so it is not a per-packet size and goes to Lua, not dsize.
SIZE_ALL = ("min_packet_length", "max_packet_length", "packet_length_mean")
SIZE_FWD = ("fwd_packet_length_min", "fwd_packet_length_max", "fwd_packet_length_mean", "avg_fwd_segment_size")
SIZE_BWD = ("bwd_packet_length_min", "bwd_packet_length_max", "bwd_packet_length_mean", "avg_bwd_segment_size")
FLAG_COLS = ("fin_flag_count", "syn_flag_count", "rst_flag_count", "psh_flag_count", "ack_flag_count",
             "urg_flag_count", "ece_flag_count", "cwe_flag_count")
LUA_FEATURES = (
    "average_packet_size", "flow_duration", "flow_bytes/s", "flow_packets/s", "fwd_packets/s", "bwd_packets/s",
    "total_length_of_fwd_packets", "total_length_of_bwd_packets", "act_data_pkt_fwd", "down/up_ratio",
    "fwd_packet_length_std", "bwd_packet_length_std", "packet_length_std", "packet_length_variance",
    "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min",
    "fwd_iat_total", "fwd_iat_mean", "fwd_iat_std", "fwd_iat_max", "fwd_iat_min",
    "bwd_iat_total", "bwd_iat_mean", "bwd_iat_std", "bwd_iat_max", "bwd_iat_min",
    "active_mean", "active_std", "active_max", "active_min",
    "idle_mean", "idle_std", "idle_max", "idle_min",
)
HEADER_ARTIFACTS = ("fwd_header_length", "bwd_header_length", "min_seg_size_forward")

_FAMILY_TEXT = {
    "protocol": ("header", "header `tcp` / `udp` / `ip`", ""),
    "dport": ("header", "destination port in the header (`ip` header -> Lua)", ""),
    "inbound": ("header", "destination `$HOME_NET` (1) / `!$HOME_NET` (0)", "column meaning checked against the PCAP files"),
    "size_all": ("native_approx", "`dsize` (merged interval; empty -> Lua)",
                 "exact when all packets of a flow have the same size (82% of UDP flows, 91% of TCP flows); "
                 "CICFlowMeter counts the first packet twice in packet_length_mean"),
    "size_fwd": ("native_approx", "`dsize` + `flow:to_server` (merged interval; empty -> Lua)", ""),
    "size_bwd": ("native_approx", "`dsize` + `flow:to_client` (direction conflict -> Lua)", ""),
    "flag": ("native_approx", "`flags:X+` / `flags:!X` (bit X from the config); UDP rule -> implied",
             "value > 0 only on TCP"),
    "win_fwd": ("native_approx", "`tcp.hdr; byte_test:2,<op>,N,14` + `flow:to_server`; threshold < 0 -> non-TCP header",
                "-1 on all non-TCP flows"),
    "win_bwd": ("native_approx", "`tcp.hdr; byte_test:2,<op>,N,14` + `flow:to_client`", ""),
    "pkts_fwd": ("native", "`flow.pkts_toserver`", "running count"),
    "pkts_bwd": ("native", "`flow.pkts_toclient`", "running count"),
    "lua": ("lua", "Lua: running flow statistic (CICFlowMeter definition)", ""),
    "dropped": ("dropped", "not translated", "CICFlowMeter artefact: negative on about 16% of UDP flows"),
}


def _build_feature_map() -> Dict[str, str]:
    groups = {
        "protocol": ("protocol",), "dport": ("destination_port",), "inbound": ("inbound",),
        "size_all": SIZE_ALL, "size_fwd": SIZE_FWD, "size_bwd": SIZE_BWD, "flag": FLAG_COLS,
        "win_fwd": ("init_win_bytes_forward",), "win_bwd": ("init_win_bytes_backward",),
        "pkts_fwd": ("total_fwd_packets",), "pkts_bwd": ("total_backward_packets",),
        "lua": LUA_FEATURES, "dropped": HEADER_ARTIFACTS,
    }
    out = {}
    for fam, feats in groups.items():
        for f in feats:
            if f in out:
                raise RuntimeError(f"feature listed twice in the feature map: {f}")
            out[f] = fam
    return out


FEATURE_MAP: Dict[str, str] = _build_feature_map()


# ----------------------------------------------------------------------------
# Config
# ----------------------------------------------------------------------------
@dataclass
class TranslationConfig:
    suricata_version: str = "7"
    flag_semantics_verified: bool = False
    flag_bits: Dict[str, Optional[str]] = field(default_factory=lambda: {
        "fin_flag_count": "F", "syn_flag_count": "S", "rst_flag_count": "R", "psh_flag_count": "P",
        "ack_flag_count": "A", "urg_flag_count": "U", "ece_flag_count": "E", "cwe_flag_count": "C"})
    protocol_purity: float = 0.99
    home_net: str = "$HOME_NET"
    native_flow_pkts: bool = True
    activity_timeout_us: float = 5_000_000.0
    flow_timeout_us: float = 120_000_000.0
    sid_base: Dict[str, int] = field(default_factory=lambda: {
        "proposed": 1_000_000, "anomaly2sign": 2_000_000, "rf_surrogate": 3_000_000})
    msg_prefix: str = "RQ1"
    # Split `ip` rules whose conditions differ between protocols into tcp and udp variants
    # (default False = drop those conditions instead).
    split_ip_rules: bool = False

    def __post_init__(self):
        for col, bit in self.flag_bits.items():
            if bit is not None and bit not in FLAG_BITS:
                raise ValueError(f"flag_bits[{col}] = {bit!r}; choices: {''.join(FLAG_BITS)} or null")

    def to_dict(self) -> Dict:
        return asdict(self)


def load_config(path: Optional[str] = None) -> TranslationConfig:
    """Read configs/suricata_translation.yaml (default) into a TranslationConfig."""
    import yaml
    path = path or DEFAULT_CONFIG_PATH
    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    known = TranslationConfig.__dataclass_fields__
    unknown = set(raw) - set(known)
    if unknown:
        raise KeyError(f"{path}: unknown keys {sorted(unknown)}")
    raw["suricata_version"] = str(raw.get("suricata_version", "7"))
    return TranslationConfig(**raw)


# ----------------------------------------------------------------------------
# Interval helpers (float thresholds -> inclusive integer bounds)
# ----------------------------------------------------------------------------
def _int_interval(conds: Sequence[Dict]) -> Tuple[float, float]:
    """Inclusive integer bounds [lo, hi] that satisfy all conditions (integer values)."""
    lo, hi = -math.inf, math.inf
    for c in conds:
        t, op = float(c["threshold"]), c["op"]
        if op == "<=":
            hi = min(hi, math.floor(t))
        elif op == "<":
            hi = min(hi, math.ceil(t) - 1)
        elif op == ">":
            lo = max(lo, math.floor(t) + 1)
        elif op == ">=":
            lo = max(lo, math.ceil(t))
        else:
            raise ValueError(f"operator '{op}' is not supported")
    return lo, hi


def _holds(conds: Sequence[Dict], v: float) -> bool:
    return all(bool(_OPS[c["op"]](np.float64(v), np.float64(c["threshold"]))) for c in conds)


def _uint_kw(name: str, lo: float, hi: float) -> Optional[str]:
    """Suricata 7 uint keyword with strict operators (<, >, exclusive range a-b)."""
    lo_b = lo > 0
    hi_b = math.isfinite(hi)
    if lo_b and hi_b:
        return f"{name}:{int(lo) - 1}-{int(hi) + 1}" if lo != hi else f"{name}:{int(lo)}"
    if lo_b:
        return f"{name}:>{int(lo) - 1}"
    if hi_b:
        return f"{name}:<{int(hi) + 1}"
    return None


def _dsize_kw(lo: float, hi: float) -> Optional[str]:
    lo_b, hi_b = lo > 0, math.isfinite(hi)
    if lo_b and hi_b:
        return f"dsize:{int(lo)}" if lo == hi else f"dsize:{int(lo) - 1}<>{int(hi) + 1}"
    if lo_b:
        return f"dsize:>{int(lo) - 1}"
    if hi_b:
        return f"dsize:<{int(hi) + 1}"
    return None


# ----------------------------------------------------------------------------
# Protocol header from the training flows
# ----------------------------------------------------------------------------
def protocol_shares(rules: Sequence[Dict], X_train: pd.DataFrame) -> List[Dict]:
    """Per rule: share of the training flows that trigger the rule (pre-translation
    conditions) per protocol. Returns [{"n": hits, 6: share, 17: share}, ...]."""
    if "protocol" not in X_train.columns:
        raise KeyError("X_train must contain the 'protocol' column to infer the header.")
    H = compute_hits(rules, X_train).tocsc()
    proto = X_train["protocol"].to_numpy(dtype=np.float64)
    out = []
    for j in range(len(rules)):
        idx = H.indices[H.indptr[j]:H.indptr[j + 1]]
        n = int(idx.size)
        p = proto[idx]
        out.append({"n": n, TCP: float(np.mean(p == TCP)) if n else 0.0,
                    UDP: float(np.mean(p == UDP)) if n else 0.0})
    return out


def protocol_shares_from_translated(rules: Sequence[Dict], translated: Sequence[Dict]) -> List[Optional[Dict]]:
    """Rebuild the protocol decision of an earlier translation from its ruleset_translated.json,
    so a ruleset can be translated again without the training flows. Only the information
    used by translate_rule is restored: the protocol header chosen from the data and the
    rounded share that is reported."""
    rec = {}
    for t in translated:
        rid = t["translation"].get("split_from") or t["rule_id"]
        rec.setdefault(rid, t["translation"])
    out = []
    for r in rules:
        tr = rec.get(r["rule_id"])
        share = None if tr is None else tr.get("protocol_share")
        if share is None:
            out.append(None)
            continue
        best = UDP if tr.get("protocol_source") == "data" and tr.get("header_protocol") == "udp" else TCP
        out.append({"n": 1, best: float(share), (UDP if best == TCP else TCP): 0.0})
    return out


IP_DISJ_NOTE = "condition differs between protocols (ip header)"


def _proto_extra(p: int, note: Optional[str] = None) -> List[Dict]:
    note = note or f"{PROTO_NAME[p]} header from the training flows"
    return [{"feature": "protocol", "op": ">", "threshold": p - 0.5, "translated": True,
             "translation": {"kind": "header_inferred", "keyword": f"alert {PROTO_NAME[p]}", "note": note}},
            {"feature": "protocol", "op": "<=", "threshold": p + 0.5, "translated": True,
             "translation": {"kind": "header_inferred", "keyword": f"alert {PROTO_NAME[p]}", "note": note}}]


# ----------------------------------------------------------------------------
# Translation of one rule
# ----------------------------------------------------------------------------
def translate_rule(rule: Dict, cfg: TranslationConfig, sid: int,
                   proto_share: Optional[Dict] = None, force_proto: Optional[str] = None) -> Tuple[Dict, Optional[str]]:
    """Return (translated rule, Lua source or None). The input rule is not changed.
    force_proto ('tcp' | 'udp'): variant of a rule with an `ip` header; the header is forced
    to that protocol, which is recorded as an extra condition (deployed view)."""
    r = copy.deepcopy(rule)
    conds = r["conditions"]
    status: List[Optional[Tuple[str, str, str]]] = [None] * len(conds)
    by_feat: Dict[str, List[int]] = {}
    for i, c in enumerate(conds):
        f = c["feature"]
        if f not in FEATURE_MAP:
            raise KeyError(f"{r['rule_id']}: feature '{f}' is not in the Suricata feature map.")
        by_feat.setdefault(f, []).append(i)

    def fam_feats(fam):
        return [f for f in by_feat if FEATURE_MAP[f] == fam]

    def cs(f):
        return [conds[i] for i in by_feat[f]]

    def mark(f_or_idx, kind, kw="", note=""):
        idxs = by_feat[f_or_idx] if isinstance(f_or_idx, str) else f_or_idx
        for i in idxs:
            status[i] = (kind, kw, note)

    # --- 1. protocol required by the conditions --------------------------------
    req: Dict[str, str] = {}                 # feature -> "tcp" | "udp"
    pending: Dict[str, Dict] = {}            # decisions that wait for the header
    for f in fam_feats("protocol"):
        allowed = {p for p in (TCP, UDP) if _holds(cs(f), p)}
        if len(allowed) == 1:
            req[f] = PROTO_NAME[allowed.pop()]
            mark(f, "header", f"alert {req[f]}")
        elif len(allowed) == 2:
            mark(f, "implied", "", "both tcp and udp satisfy the condition")
        else:
            mark(f, "dropped", "", "only protocols other than tcp/udp")
    for f in fam_feats("flag"):
        bit = cfg.flag_bits.get(f)
        if bit is None:
            mark(f, "dropped", "", "flag column without a mapped bit (config)")
            continue
        lo, hi = _int_interval(cs(f))
        if lo > hi:
            mark(f, "dropped", "", "unsatisfiable")
        elif lo >= 2:
            mark(f, "dropped", "", "flag count >= 2 cannot be checked per packet")
        elif lo >= 1:
            req[f] = "tcp"
            pending[f] = {"type": "flag_set", "bit": bit}
        elif hi <= 0:
            pending[f] = {"type": "flag_unset", "bit": bit}   # non-TCP OR TCP without the bit
        else:
            mark(f, "implied", "", "range covers 0 and 1")
    for fam in ("win_fwd", "win_bwd"):
        for f in fam_feats(fam):
            c = cs(f)
            nontcp_ok = _holds(c, -1)
            lo, hi = _int_interval(c)
            tlo, thi = max(lo, 0), min(hi, 65535)
            tcp_ok = tlo <= thi
            full = tcp_ok and tlo == 0 and thi == 65535
            if not tcp_ok and nontcp_ok:
                req[f] = "udp"
                mark(f, "implied", "", "value -1 = non-TCP flow (protocol marker)")
            elif tcp_ok and not nontcp_ok:
                req[f] = "tcp"
                if full:
                    mark(f, "implied", "", "full TCP window range")
                else:
                    pending[f] = {"type": "win", "fam": fam, "lo": tlo, "hi": thi, "disj": False}
            elif tcp_ok and nontcp_ok:
                if full:
                    mark(f, "implied", "", "all flows satisfy the condition")
                else:
                    pending[f] = {"type": "win", "fam": fam, "lo": tlo, "hi": thi, "disj": True}
            else:
                mark(f, "dropped", "", "unsatisfiable")

    # --- 2. protocol header -----------------------------------------------------
    needs = set(req.values())
    extra: List[Dict] = []
    share_txt = None
    if force_proto is not None:
        if needs - {force_proto}:
            raise ValueError(f"{r['rule_id']}: variant {force_proto} contradicts the protocol conditions {needs}")
        proto, source = force_proto, "split"
        extra = _proto_extra(TCP if proto == "tcp" else UDP, f"{proto} variant of a rule with an ip header")
    elif len(needs) == 1:
        proto, source = needs.pop(), "conditions"
    else:
        proto, source = "ip", "default"
        if proto_share and proto_share.get("n", 0) > 0:
            best = max((TCP, UDP), key=lambda p: proto_share[p])
            share_txt = round(proto_share[best], 4)
            if proto_share[best] >= cfg.protocol_purity:
                proto = PROTO_NAME[best]
                source = "data"
        if len(needs) == 2:                  # conflict between conditions (does not occur in practice)
            source = "conflict"
            for f, p in req.items():
                if proto != p:
                    mark(f, "dropped", "", f"protocol conflict (header {proto})")
                    pending.pop(f, None)
        if source == "data":
            extra = _proto_extra(TCP if proto == "tcp" else UDP)

    # --- 3. flags and window once the header is known -------------------------
    flags_set, flags_unset, win_tests = [], [], {}
    for f, d in list(pending.items()):
        if status[by_feat[f][0]] is not None:
            continue
        if d["type"] == "flag_set":
            flags_set.append((f, d["bit"]))
        elif d["type"] == "flag_unset":
            if proto == "udp":
                mark(f, "implied", "", "flag is always 0 on UDP flows")
            elif proto == "tcp":
                flags_unset.append((f, d["bit"]))
            else:
                mark(f, "dropped", "", IP_DISJ_NOTE)
        elif d["type"] == "win":
            if d["disj"] and proto == "udp":
                mark(f, "implied", "", "value -1 on UDP flows satisfies the condition")
            elif d["disj"] and proto == "ip":
                mark(f, "dropped", "", IP_DISJ_NOTE)
            else:
                win_tests[f] = d

    # --- 4. packet direction for per-packet keywords ---------------------------
    fwd_bound = bool(fam_feats("size_fwd")) or any(d["fam"] == "win_fwd" for d in win_tests.values())
    bwd_bound = bool(fam_feats("size_bwd")) or any(d["fam"] == "win_bwd" for d in win_tests.values())
    direction = "to_server" if fwd_bound else ("to_client" if bwd_bound else None)

    opts_native: List[str] = []
    lua_idx: List[int] = []

    # window (tcp.hdr byte_test)
    tcp_hdr_tests: List[str] = []
    for f, d in win_tests.items():
        want = "to_server" if d["fam"] == "win_fwd" else "to_client"
        if want != direction:
            mark(f, "dropped", "", "packet direction conflict (window)")
            continue
        kws = []
        if d["lo"] > 0:
            kws.append(f"byte_test:2,>,{int(d['lo']) - 1},14")
        if d["hi"] < 65535:
            kws.append(f"byte_test:2,<,{int(d['hi']) + 1},14")
        tcp_hdr_tests += kws
        mark(f, "native_approx", "tcp.hdr; " + "; ".join(kws), "packet window, direction " + want)

    # flags
    flag_kw = None
    if flags_set and not flags_unset:
        flag_kw = "flags:" + "".join(sorted({b for _, b in flags_set})) + "+"
    elif flags_unset and not flags_set and len({b for _, b in flags_unset}) == 1:
        flag_kw = f"flags:!{flags_unset[0][1]}"
    elif flags_set or flags_unset:
        for _, b in flags_set:
            tcp_hdr_tests.append(f"byte_test:1,&,{FLAG_BITS[b]},13")
        for _, b in flags_unset:
            tcp_hdr_tests.append(f"byte_test:1,!&,{FLAG_BITS[b]},13")
    for f, b in flags_set:
        mark(f, "native_approx", flag_kw or f"byte_test:1,&,{FLAG_BITS[b]},13", f"bit {b} set in the packet")
    for f, b in flags_unset:
        mark(f, "native_approx", flag_kw or f"byte_test:1,!&,{FLAG_BITS[b]},13", f"bit {b} not set")

    # packet size -> one dsize interval
    members = fam_feats("size_all") + fam_feats("size_fwd")
    if direction == "to_client":
        members += fam_feats("size_bwd")
    else:
        for f in fam_feats("size_bwd"):
            lua_idx += by_feat[f]
            mark(f, "lua", "lua", "packet direction conflict (backward dsize in a to_server rule)")
    dsize_kw = None
    if members:
        lo, hi = _int_interval([c for f in members for c in cs(f)])
        lo = max(lo, 0)
        if lo > hi:
            for f in members:
                lua_idx += by_feat[f]
                mark(f, "lua", "lua", "empty dsize interval (flow with packets of different sizes)")
        else:
            dsize_kw = _dsize_kw(lo, hi)
            for f in members:
                if dsize_kw:
                    mark(f, "native_approx", dsize_kw, "merged payload size interval per packet")
                else:
                    mark(f, "implied", "", "unbounded dsize interval")

    # flow.pkts_*
    pkt_kws = []
    for fam, kwname in (("pkts_fwd", "flow.pkts_toserver"), ("pkts_bwd", "flow.pkts_toclient")):
        for f in fam_feats(fam):
            if not cfg.native_flow_pkts:
                lua_idx += by_feat[f]
                mark(f, "lua", "lua", "native_flow_pkts = false")
                continue
            lo, hi = _int_interval(cs(f))
            if lo > hi:
                mark(f, "dropped", "", "unsatisfiable")
                continue
            kw = _uint_kw(kwname, max(lo, 0), hi)
            if kw:
                pkt_kws.append(kw)
                mark(f, "native", kw, "running count")
            else:
                mark(f, "implied", "", "unbounded interval")

    # destination port
    port = "any"
    for f in fam_feats("dport"):
        lo, hi = _int_interval(cs(f))
        lo, hi = max(lo, 0), min(hi, 65535)
        if lo > hi:
            mark(f, "dropped", "", "unsatisfiable")
        elif proto == "ip":
            lua_idx += by_feat[f]
            mark(f, "lua", "lua", "port in an ip header is not supported")
        elif lo == 0 and hi == 65535:
            mark(f, "implied", "", "all ports")
        else:
            port = str(int(lo)) if lo == hi else f"{int(lo)}:{int(hi)}"
            mark(f, "header", f"port {port}")

    # network direction (inbound)
    dst = "any"
    for f in fam_feats("inbound"):
        ok1, ok0 = _holds(cs(f), 1), _holds(cs(f), 0)
        if ok1 and ok0:
            mark(f, "implied", "", "both 0 and 1 satisfy the condition")
        elif ok1:
            dst = cfg.home_net
            mark(f, "header", f"-> {dst}", "column meaning checked against the PCAP files")
        elif ok0:
            dst = "!" + cfg.home_net
            mark(f, "header", f"-> {dst}", "column meaning checked against the PCAP files")
        else:
            mark(f, "dropped", "", "unsatisfiable")

    # Lua and artefacts
    for f in fam_feats("lua"):
        lua_idx += by_feat[f]
        mark(f, "lua", "lua", "CICFlowMeter definition, running statistic")
    for f in fam_feats("dropped"):
        mark(f, "dropped", "", "CICFlowMeter artefact")
    if any(s is None for s in status):
        missing = [conds[i]["feature"] for i, s in enumerate(status) if s is None]
        raise RuntimeError(f"{r['rule_id']}: conditions without a translation status: {missing}")

    for c, (kind, kw, note) in zip(conds, status):
        c["translated"] = kind in TRANSLATED_KINDS
        c["translation"] = {"kind": kind, "keyword": kw, "note": note}

    # --- 5. rule text + Lua -------------------------------------------------------
    deployable = any(c["translated"] for c in conds)
    lua_src, lua_file, text = None, None, None
    lua_conds = [conds[i] for i in sorted(set(lua_idx))]
    if deployable:
        method, cls, rid = r.get("method", "method"), r["target_class"], r["rule_id"]
        opts = [f'msg:"{cfg.msg_prefix} {method} {cls} {rid}"']
        if lua_conds:
            lua_file = f"{_safe(rid)}.lua"
            lua_src = lua_source(rid, lua_conds, cfg)
            opts.append(f"lua:{lua_file}")
        if direction:
            opts.append(f"flow:{direction}")
        if dsize_kw:
            opts.append(dsize_kw)
        if flag_kw:
            opts.append(flag_kw)
        opts += pkt_kws
        if tcp_hdr_tests:
            opts.append("tcp.hdr")
            opts += tcp_hdr_tests
        opts.append(f"metadata:rq1_rule {rid}, rq1_class {cls}, rq1_method {method}")
        opts += [f"sid:{sid}", "rev:1"]
        arrow = "<>" if lua_conds else "->"
        text = f"alert {proto} any any {arrow} {dst} {port} (" + "; ".join(opts) + ";)"

    r["suricata"] = text
    r["translation"] = {"header_protocol": proto, "protocol_source": source, "protocol_share": share_txt,
                        "extra_conditions": extra if deployable else [], "direction": direction,
                        "lua_file": lua_file, "sid": sid if deployable else None, "deployable": deployable}
    return r, lua_src


def _safe(s: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in str(s))


# ----------------------------------------------------------------------------
# Translation of a ruleset
# ----------------------------------------------------------------------------
def translate_ruleset(rules: Sequence[Dict], cfg: Optional[TranslationConfig] = None,
                      X_train: Optional[pd.DataFrame] = None,
                      shares: Optional[Sequence[Optional[Dict]]] = None) -> Tuple[List[Dict], Dict[str, str], Dict]:
    """Translate a ruleset (evaluator format). X_train (original units, with a 'protocol'
    column) is used to infer the protocol header; alternatively `shares` gives the per-rule
    protocol shares directly (see protocol_shares_from_translated). Neither = no inference.
    Returns (translated rules, {Lua file name: source}, report)."""
    cfg = cfg or TranslationConfig()
    if shares is None:
        shares = protocol_shares(rules, X_train) if X_train is not None else [None] * len(rules)
    out, lua = [], {}
    counters: Dict[str, int] = {}

    def next_sid(method):
        counters[method] = counters.get(method, 0) + 1
        return cfg.sid_base.get(method, 9_000_000) + counters[method]

    n_split = 0
    for rule, share in zip(rules, shares):
        method = rule.get("method", "method")
        tr, src = translate_rule(rule, cfg, next_sid(method), share)
        pieces = [(tr, src)]
        if (cfg.split_ip_rules and tr["translation"]["header_protocol"] == "ip"
                and tr["translation"]["protocol_source"] == "default"
                and any(c["translation"]["note"] == IP_DISJ_NOTE for c in tr["conditions"])):
            # one variant per protocol, each with the conditions that hold for its protocol
            n_split += 1
            pieces = []
            for p in ("tcp", "udp"):
                rv = copy.deepcopy(rule)
                rv["rule_id"] = f"{rule['rule_id']}-{p}"
                trv, srcv = translate_rule(rv, cfg, next_sid(method), share, force_proto=p)
                trv["translation"]["split_from"] = rule["rule_id"]
                pieces.append((trv, srcv))
        for t, s in pieces:
            out.append(t)
            if s is not None:
                lua[t["translation"]["lua_file"]] = s
    rep = translation_report(out, cfg)
    rep["n_rules_source"], rep["n_split"] = len(rules), n_split
    return out, lua, rep


def deployed_view(translated: Sequence[Dict]) -> List[Dict]:
    """Ruleset for the evaluator with deployed_only=True: the original conditions (with their
    `translated` status) + the extra protocol conditions. A rule without translated conditions
    stays in the ruleset but never fires (evaluator behaviour)."""
    out = []
    for r in translated:
        d = copy.deepcopy(r)
        d["conditions"] = d["conditions"] + d.get("translation", {}).get("extra_conditions", [])
        out.append(d)
    return out


def translation_report(translated: Sequence[Dict], cfg: TranslationConfig) -> Dict:
    rows = []
    for r in translated:
        for c in r["conditions"]:
            rows.append({"rule_id": r["rule_id"], "method": r.get("method"), "class": r["target_class"],
                         "feature": c["feature"], "kind": c["translation"]["kind"],
                         "note": c["translation"]["note"]})
    df = pd.DataFrame(rows, columns=["rule_id", "method", "class", "feature", "kind", "note"])
    n = len(df)
    kinds = {k: int((df["kind"] == k).sum()) for k in KINDS}
    by_class = {c: {k: int(((g["kind"]) == k).sum()) for k in KINDS} for c, g in df.groupby("class")}
    by_feature = {f: {k: int((g["kind"] == k).sum()) for k in KINDS if (g["kind"] == k).any()}
                  for f, g in df.groupby("feature")}
    dropped = df[df["kind"] == "dropped"]
    tr = [r["translation"] for r in translated]
    return {
        "n_rules": len(translated),
        "n_deployable": int(sum(t["deployable"] for t in tr)),
        "n_rules_with_lua": int(sum(t["lua_file"] is not None for t in tr)),
        "n_conditions": n,
        "kinds": kinds,
        "share": {k: (v / n if n else None) for k, v in kinds.items()},
        "share_native_or_header": ((kinds["header"] + kinds["native"] + kinds["native_approx"]
                                    + kinds["implied"]) / n) if n else None,
        "header_protocol": {p: int(sum(t["header_protocol"] == p for t in tr)) for p in ("tcp", "udp", "ip")},
        "protocol_source": {s: int(sum(t["protocol_source"] == s for t in tr))
                            for s in ("conditions", "data", "default", "conflict", "split")},
        "by_class": by_class,
        "by_feature": by_feature,
        "dropped_reasons": {k: int(v) for k, v in dropped["note"].value_counts().items()},
        "flag_semantics_verified": cfg.flag_semantics_verified,
        "config": cfg.to_dict(),
    }


def mapping_table(cfg: Optional[TranslationConfig] = None) -> pd.DataFrame:
    """Feature -> Suricata/Lua mapping table (same source as the code)."""
    cfg = cfg or TranslationConfig()
    rows = []
    for f, fam in FEATURE_MAP.items():
        kind, kw, note = _FAMILY_TEXT[fam]
        if fam == "flag":
            bit = cfg.flag_bits.get(f)
            kw = f"`flags:{bit}+` / `flags:!{bit}`; UDP rule -> implied" if bit else "not translated (no mapped bit)"
            if not cfg.flag_semantics_verified:
                note = (note + "; " if note else "") + "bit not verified"
        if fam == "pkts_fwd" and not cfg.native_flow_pkts or fam == "pkts_bwd" and not cfg.native_flow_pkts:
            kind, kw = "lua", "Lua (native_flow_pkts = false)"
        rows.append({"feature": f, "family": fam, "kind": kind, "suricata": kw, "note": note})
    return pd.DataFrame(rows)


# ----------------------------------------------------------------------------
# Output files
# ----------------------------------------------------------------------------
def write_outputs(out_dir: str, translated: Sequence[Dict], lua: Dict[str, str], report: Optional[Dict] = None,
                  rules_name: str = "rq1.rules", header_comment: str = "") -> Dict[str, str]:
    """Write <rules_name> and the *.lua scripts into out_dir (one folder, so Suricata's
    default-rule-path can point to it), plus ruleset_translated.json and, if given,
    translation_report.json."""
    os.makedirs(out_dir, exist_ok=True)
    paths = {"ruleset": os.path.join(out_dir, "ruleset_translated.json"),
             "rules": os.path.join(out_dir, rules_name)}
    with open(paths["ruleset"], "w", encoding="utf-8", newline="\n") as f:
        json.dump(list(translated), f, indent=1)
    with open(paths["rules"], "w", encoding="utf-8", newline="\n") as f:
        f.write("# RQ1 — Suricata translation layer (suricata_translate.py)\n")
        if header_comment:
            f.write("".join(f"# {ln}\n" for ln in header_comment.splitlines()))
        if not (report or {}).get("flag_semantics_verified", True):
            f.write("# NOTE: the meaning of the flag columns is not verified\n")
        for r in translated:
            if r["suricata"]:
                f.write(r["suricata"] + "\n")
            else:
                f.write(f"# not deployed: {r['rule_id']} ({r['target_class']}) — all conditions dropped\n")
    for name, src in lua.items():
        with open(os.path.join(out_dir, name), "w", encoding="utf-8", newline="\n") as f:
            f.write(src)
    if report is not None:
        paths["report"] = os.path.join(out_dir, "translation_report.json")
        with open(paths["report"], "w", encoding="utf-8", newline="\n") as f:
            json.dump(report, f, indent=1, default=str)
    return paths


# ----------------------------------------------------------------------------
# Lua (Suricata 7, compatible with Lua 5.1-5.4)
# ----------------------------------------------------------------------------
_LUA_ENGINE = r"""
local ACTIVITY_TIMEOUT = __ACTIVITY__
local FLOW_TIMEOUT = __FLOWTO__
local SWEEP_EVERY = 20000
local flows = {}
local n_pkts = 0

function init(args)
  local needs = {}
  needs["packet"] = tostring(true)
  return needs
end

-- running statistics (Welford; std/var with n-1, as in CICFlowMeter)
local function st() return {n = 0, sum = 0, mean = 0, m2 = 0, min = nil, max = nil} end
local function add(s, v)
  s.n = s.n + 1
  s.sum = s.sum + v
  local d = v - s.mean
  s.mean = s.mean + d / s.n
  s.m2 = s.m2 + d * (v - s.mean)
  if s.min == nil or v < s.min then s.min = v end
  if s.max == nil or v > s.max then s.max = v end
end
local function mean(s) if s.n == 0 then return 0 end return s.mean end
local function var(s) if s.n < 2 then return 0 end return s.m2 / (s.n - 1) end
local function std(s) return math.sqrt(var(s)) end
local function mn(s) return s.min or 0 end
local function mx(s) return s.max or 0 end

-- flen = flow packet-length statistics as in CICFlowMeter: the first packet is counted twice
local function new_flow(ts, dport)
  return {start = ts, last = ts, last_fwd = nil, last_bwd = nil, dport = dport, first = 0,
          fwd = st(), bwd = st(), all = st(), flen = st(), iat = st(), fiat = st(), biat = st(),
          act_fwd = 0, active = st(), idle = st(), start_active = ts, end_active = ts}
end

local function update(fl, ts, is_fwd, plen)
  local first = (fl.all.n == 0)
  if not first then
    -- CICFlowMeter updateActiveIdleTime, then flowIAT
    if (ts - fl.end_active) > ACTIVITY_TIMEOUT then
      if (fl.end_active - fl.start_active) > 0 then add(fl.active, fl.end_active - fl.start_active) end
      add(fl.idle, ts - fl.end_active)
      fl.start_active = ts
      fl.end_active = ts
    else
      fl.end_active = ts
    end
    add(fl.iat, ts - fl.last)
  else
    fl.first = plen
    add(fl.flen, plen)
  end
  add(fl.all, plen)
  add(fl.flen, plen)
  if is_fwd then
    if fl.last_fwd ~= nil then add(fl.fiat, ts - fl.last_fwd) end
    fl.last_fwd = ts
    add(fl.fwd, plen)
    -- CICFlowMeter: the first packet of the flow is not counted (checked on the CIC-DDoS2019 data)
    if plen >= 1 and not first then fl.act_fwd = fl.act_fwd + 1 end
  else
    if fl.last_bwd ~= nil then add(fl.biat, ts - fl.last_bwd) end
    fl.last_bwd = ts
    add(fl.bwd, plen)
  end
  fl.last = ts
end

local function dur(fl) return fl.last - fl.start end
local function rate(fl, x)
  local d = dur(fl)
  if d <= 0 then return math.huge end
  return x / (d / 1000000)
end
-- the current active period is included (CICFlowMeter adds it when the flow ends)
local function active_st(fl)
  local d = fl.end_active - fl.start_active
  if d <= 0 then return fl.active end
  local s = {n = fl.active.n, sum = fl.active.sum, mean = fl.active.mean, m2 = fl.active.m2,
             min = fl.active.min, max = fl.active.max}
  add(s, d)
  return s
end

local F = {}
F["flow_duration"] = function(fl) return dur(fl) end
F["flow_bytes/s"] = function(fl) return rate(fl, fl.all.sum) end
F["flow_packets/s"] = function(fl) return rate(fl, fl.all.n) end
F["fwd_packets/s"] = function(fl) return rate(fl, fl.fwd.n) end
F["bwd_packets/s"] = function(fl) return rate(fl, fl.bwd.n) end
F["total_fwd_packets"] = function(fl) return fl.fwd.n end
F["total_backward_packets"] = function(fl) return fl.bwd.n end
F["total_length_of_fwd_packets"] = function(fl) return fl.fwd.sum end
F["total_length_of_bwd_packets"] = function(fl) return fl.bwd.sum end
F["act_data_pkt_fwd"] = function(fl) return fl.act_fwd end
F["down/up_ratio"] = function(fl) if fl.fwd.n == 0 then return 0 end return math.floor(fl.bwd.n / fl.fwd.n) end
F["fwd_packet_length_max"] = function(fl) return mx(fl.fwd) end
F["fwd_packet_length_min"] = function(fl) return mn(fl.fwd) end
F["fwd_packet_length_mean"] = function(fl) return mean(fl.fwd) end
F["fwd_packet_length_std"] = function(fl) return std(fl.fwd) end
F["avg_fwd_segment_size"] = function(fl) return mean(fl.fwd) end
F["bwd_packet_length_max"] = function(fl) return mx(fl.bwd) end
F["bwd_packet_length_min"] = function(fl) return mn(fl.bwd) end
F["bwd_packet_length_mean"] = function(fl) return mean(fl.bwd) end
F["bwd_packet_length_std"] = function(fl) return std(fl.bwd) end
F["avg_bwd_segment_size"] = function(fl) return mean(fl.bwd) end
F["min_packet_length"] = function(fl) return mn(fl.flen) end
F["max_packet_length"] = function(fl) return mx(fl.flen) end
F["packet_length_mean"] = function(fl) return mean(fl.flen) end
F["average_packet_size"] = function(fl) return (fl.all.sum + fl.first) / fl.all.n end
F["packet_length_std"] = function(fl) return std(fl.flen) end
F["packet_length_variance"] = function(fl) return var(fl.flen) end
F["flow_iat_mean"] = function(fl) return mean(fl.iat) end
F["flow_iat_std"] = function(fl) return std(fl.iat) end
F["flow_iat_max"] = function(fl) return mx(fl.iat) end
F["flow_iat_min"] = function(fl) return mn(fl.iat) end
F["fwd_iat_total"] = function(fl) return fl.fiat.sum end
F["fwd_iat_mean"] = function(fl) return mean(fl.fiat) end
F["fwd_iat_std"] = function(fl) return std(fl.fiat) end
F["fwd_iat_max"] = function(fl) return mx(fl.fiat) end
F["fwd_iat_min"] = function(fl) return mn(fl.fiat) end
F["bwd_iat_total"] = function(fl) return fl.biat.sum end
F["bwd_iat_mean"] = function(fl) return mean(fl.biat) end
F["bwd_iat_std"] = function(fl) return std(fl.biat) end
F["bwd_iat_max"] = function(fl) return mx(fl.biat) end
F["bwd_iat_min"] = function(fl) return mn(fl.biat) end
F["active_mean"] = function(fl) return mean(active_st(fl)) end
F["active_std"] = function(fl) return std(active_st(fl)) end
F["active_max"] = function(fl) return mx(active_st(fl)) end
F["active_min"] = function(fl) return mn(active_st(fl)) end
F["idle_mean"] = function(fl) return mean(fl.idle) end
F["idle_std"] = function(fl) return std(fl.idle) end
F["idle_max"] = function(fl) return mx(fl.idle) end
F["idle_min"] = function(fl) return mn(fl.idle) end
F["destination_port"] = function(fl) return fl.dport end

local function cmp(v, op, t)
  if op == "<=" then return v <= t end
  if op == "<" then return v < t end
  if op == ">" then return v > t end
  return v >= t
end

local function sweep(ts)
  for k, fl in pairs(flows) do
    if ts - fl.last > FLOW_TIMEOUT then flows[k] = nil end
  end
end

-- used by unit tests; not called by Suricata
function rq1_features(key)
  local fl = flows[key]
  if fl == nil then return nil end
  local out = {}
  for name, fn in pairs(F) do out[name] = fn(fl) end
  return out
end

function match(args)
  local sec, usec = SCPacketTimestamp()
  local ts = sec * 1000000 + usec
  local _, fsrc, fdst, _, fsp, fdp = SCFlowTuple()
  local _, psrc, _, _, psp, _ = SCPacketTuple()
  local ok, fid = pcall(SCFlowId)
  local key = (ok and fid) or (tostring(fsrc) .. ":" .. tostring(fsp) .. ">" .. tostring(fdst) .. ":" .. tostring(fdp))
  local fl = flows[key]
  if fl == nil then
    fl = new_flow(ts, fdp or 0)
    flows[key] = fl
  end
  local is_fwd = (psrc == fsrc) and (psp == fsp)
  local payload = SCPacketPayload()
  local plen = 0
  if payload ~= nil then plen = string.len(payload) end
  update(fl, ts, is_fwd, plen)
  n_pkts = n_pkts + 1
  if n_pkts % SWEEP_EVERY == 0 then sweep(ts) end
  for i = 1, #CONDS do
    local c = CONDS[i]
    if not cmp(F[c[1]](fl), c[2], c[3]) then return 0 end
  end
  return 1
end
"""


def lua_source(rule_id: str, lua_conds: Sequence[Dict], cfg: TranslationConfig) -> str:
    """Lua script of one rule: the flow-statistics engine + the conditions of that rule."""
    for c in lua_conds:
        if c["feature"] not in LUA_FEATURE_SET:
            raise KeyError(f"{rule_id}: feature '{c['feature']}' is not computed by the Lua engine.")
    lines = [f"-- RQ1 {rule_id}: generated by suricata_translate.py",
             "-- running flow statistics from the packets that pass the rule header (<> header, both directions)",
             "CONDS = {"]
    for c in lua_conds:
        lines.append(f'  {{"{c["feature"]}", "{c["op"]}", {float(c["threshold"])!r}}},')
    lines.append("}")
    engine = (_LUA_ENGINE.replace("__ACTIVITY__", repr(float(cfg.activity_timeout_us)))
              .replace("__FLOWTO__", repr(float(cfg.flow_timeout_us))))
    return "\n".join(lines) + "\n" + engine.lstrip("\n")


LUA_FEATURE_SET = set(LUA_FEATURES) | set(SIZE_ALL) | set(SIZE_FWD) | set(SIZE_BWD) | {
    "total_fwd_packets", "total_backward_packets", "destination_port"}


# ----------------------------------------------------------------------------
# Python reference for the Lua definitions (used by unit tests)
# ----------------------------------------------------------------------------
def reference_flow_features(packets: Sequence[Tuple[float, bool, int]], dport: int = 0,
                            activity_timeout_us: float = 5_000_000.0) -> Dict[str, float]:
    """CICFlowMeter-style flow features from packets (ts_us, is_fwd, payload_len), in time
    order. Same definitions as the Lua engine (the current active period is included)."""
    def stats(v):
        v = np.asarray(v, dtype=float)
        if v.size == 0:
            return {"n": 0, "sum": 0.0, "mean": 0.0, "std": 0.0, "var": 0.0, "min": 0.0, "max": 0.0}
        var = float(v.var(ddof=1)) if v.size > 1 else 0.0
        return {"n": int(v.size), "sum": float(v.sum()), "mean": float(v.mean()), "std": math.sqrt(var),
                "var": var, "min": float(v.min()), "max": float(v.max())}

    ts = [p[0] for p in packets]
    fwd = [p for p in packets if p[1]]
    bwd = [p for p in packets if not p[1]]
    iat = np.diff(ts)
    fiat = np.diff([p[0] for p in fwd])
    biat = np.diff([p[0] for p in bwd])
    active, idle = [], []
    sa = ea = ts[0]
    for t in ts[1:]:
        if t - ea > activity_timeout_us:
            if ea - sa > 0:
                active.append(ea - sa)
            idle.append(t - ea)
            sa = ea = t
        else:
            ea = t
    if ea - sa > 0:
        active.append(ea - sa)
    A, Fw, Bw = stats([p[2] for p in packets]), stats([p[2] for p in fwd]), stats([p[2] for p in bwd])
    FL = stats([packets[0][2]] + [p[2] for p in packets])     # first packet counted twice (CICFlowMeter)
    I, FI, BI, AC, ID = stats(iat), stats(fiat), stats(biat), stats(active), stats(idle)
    d = ts[-1] - ts[0]

    def rate(x):
        return math.inf if d <= 0 else x / (d / 1e6)
    out = {
        "flow_duration": d, "flow_bytes/s": rate(A["sum"]), "flow_packets/s": rate(A["n"]),
        "fwd_packets/s": rate(Fw["n"]), "bwd_packets/s": rate(Bw["n"]),
        "total_fwd_packets": Fw["n"], "total_backward_packets": Bw["n"],
        "total_length_of_fwd_packets": Fw["sum"], "total_length_of_bwd_packets": Bw["sum"],
        "act_data_pkt_fwd": sum(1 for i, p in enumerate(packets) if i > 0 and p[1] and p[2] >= 1),
        "down/up_ratio": math.floor(Bw["n"] / Fw["n"]) if Fw["n"] else 0,
        "min_packet_length": FL["min"], "max_packet_length": FL["max"], "packet_length_mean": FL["mean"],
        "average_packet_size": (A["sum"] + packets[0][2]) / A["n"], "packet_length_std": FL["std"],
        "packet_length_variance": FL["var"],
        "destination_port": dport,
    }
    for pre, s in (("fwd", Fw), ("bwd", Bw)):
        out.update({f"{pre}_packet_length_max": s["max"], f"{pre}_packet_length_min": s["min"],
                    f"{pre}_packet_length_mean": s["mean"], f"{pre}_packet_length_std": s["std"],
                    f"avg_{pre}_segment_size": s["mean"]})
    for pre, s in (("flow", I), ("fwd", FI), ("bwd", BI)):
        out.update({f"{pre}_iat_mean": s["mean"], f"{pre}_iat_std": s["std"],
                    f"{pre}_iat_max": s["max"], f"{pre}_iat_min": s["min"]})
    out["fwd_iat_total"], out["bwd_iat_total"] = FI["sum"], BI["sum"]
    for pre, s in (("active", AC), ("idle", ID)):
        out.update({f"{pre}_mean": s["mean"], f"{pre}_std": s["std"], f"{pre}_max": s["max"],
                    f"{pre}_min": s["min"]})
    return out
