"""Repairs of the translation layer: patch the Lua scripts of the initial ruleset without changing
the rules (rq1.rules) and without new parameters.

Two repairs, each can be switched on alone:

  R  undefined duration: at the first packet the duration is 0, so the initial translation gives
     an infinite rate and `rate > threshold` holds at once. The training data contain no flow with
     duration 0 or a single packet, so the rules never saw that state. Here the rates and
     flow_duration have no value until the duration is > 0, and the condition is false for both
     > and <=.
  A  flow direction: the <> header admits both directions, so the inbound condition is not
     enforced. Here inbound is evaluated in Lua from the flow tuple (1 = initiator outside
     HOME_NET and destination inside, otherwise 0).

The base translation module (suricata_translate.py) is not changed. Each expected pattern must
occur exactly once in the Lua source of the initial ruleset; otherwise an error is raised.
"""
from __future__ import annotations

import re
from typing import Dict, Tuple

DURATION_FEATURES = frozenset({"flow_duration", "flow_bytes/s", "flow_packets/s", "fwd_packets/s", "bwd_packets/s"})
RATE_FEATURES = DURATION_FEATURES - {"flow_duration"}
ARMS = {"C0": (False, False), "R": (True, False), "A": (False, True), "RA": (True, True)}

_RATE_T1 = "  if d <= 0 then return math.huge end"
_RATE_NEW = "  if d <= 0 then return nil end"
_DUR_T1 = 'F["flow_duration"] = function(fl) return dur(fl) end'
_DUR_NEW = 'F["flow_duration"] = function(fl) local d = dur(fl); if d <= 0 then return nil end; return d end'
_CMP_T1 = "    if not cmp(F[c[1]](fl), c[2], c[3]) then return 0 end"
_CMP_NEW = "    local v = F[c[1]](fl)\n    if v == nil or not cmp(v, c[2], c[3]) then return 0 end"
_NEWFLOW_T1 = "    fl = new_flow(ts, fdp or 0)"
_NEWFLOW_NEW = "    fl = new_flow(ts, fdp or 0)\n    fl.inbound = rq1_inbound(fsrc, fdst)"
_PORT_T1 = 'F["destination_port"] = function(fl) return fl.dport end'
_PORT_NEW = _PORT_T1 + '\nF["inbound"] = function(fl) return fl.inbound end'
_FTABLE_T1 = "local F = {}"
_CONDS_T1 = "CONDS = {\n"


def _sub(src: str, old: str, new: str) -> str:
    if src.count(old) != 1:
        raise ValueError(f"Lua pattern of the initial translation must occur exactly once, found {src.count(old)}: {old!r}")
    return src.replace(old, new)


def home_prefix(home_net: str) -> str:
    """'192.168.50.0/24' -> '192.168.50.'; only /24, as the HOME_NET of the experiments."""
    net, _, bits = home_net.partition("/")
    octets = net.split(".")
    if bits != "24" or len(octets) != 4 or octets[3] != "0":
        raise ValueError(f"HOME_NET must have the form a.b.c.0/24: {home_net!r}")
    return ".".join(octets[:3]) + "."


def repair_lua(src: str, rule: Dict, repair_rate: bool, repair_direction: bool, home_net: str, guard_duration: bool = True) -> Tuple[str, Dict]:
    """Return (Lua source, note). rule = entry of ruleset_translated.json. Without a relevant repair,
    the source is returned byte-identical. guard_duration=False: only the rate features are guarded,
    flow_duration stays as in the initial translation."""
    lua_feats = {c["feature"] for c in rule["conditions"] if c["translation"]["kind"] == "lua"}
    inbound = [c for c in rule["conditions"] if c["feature"] == "inbound" and c["translation"]["kind"] == "header"]
    guarded = DURATION_FEATURES if guard_duration else RATE_FEATURES
    rate_on = repair_rate and bool(lua_feats & guarded)
    dir_on = repair_direction and bool(inbound)
    note = {"rule_id": rule["rule_id"], "rate": rate_on, "direction": dir_on}
    if rate_on:
        src = _sub(src, _RATE_T1, _RATE_NEW)
        if guard_duration:
            src = _sub(src, _DUR_T1, _DUR_NEW)
    if rate_on or dir_on:
        src = _sub(src, _CMP_T1, _CMP_NEW)
    if dir_on:
        prefix = home_prefix(home_net)
        lines = "".join(f'  {{"inbound", "{c["op"]}", {float(c["threshold"])!r}}},\n' for c in inbound)
        src = _sub(src, _CONDS_T1, _CONDS_T1 + lines)
        helper = (f'local function rq1_in_home(ip) return string.sub(tostring(ip), 1, {len(prefix)}) == "{prefix}" end\n'
                  "local function rq1_inbound(src, dst)\n"
                  "  if (not rq1_in_home(src)) and rq1_in_home(dst) then return 1 end\n"
                  "  return 0\n"
                  "end\n")
        src = _sub(src, _FTABLE_T1, helper + _FTABLE_T1)
        src = _sub(src, _PORT_T1, _PORT_NEW)
        src = _sub(src, _NEWFLOW_T1, _NEWFLOW_NEW)
    return src, note


def _base_rule_id(rule_id: str) -> str:
    return re.sub(r"-(tcp|udp)$", "", rule_id)


def repair_ruleset_ar3(lua: Dict[str, str], translated: list, train_samples: Dict[str, int], max_train: int, home_net: str) -> Tuple[Dict[str, str], list]:
    """Arm AR3: direction repair for all rules (A) + rate guard only for rules with small training support (R3).

    The rate guard applies when the rule has a rate condition in Lua, no flags: keyword, and
    train_samples < max_train. A rule learned from very few flows does not justify an alert at the
    first packet; flags: can make the Lua script see a single packet, so its duration stays 0.
    The logic is the same for all methods."""
    out = dict(lua)
    notes = []
    for t in translated:
        f = t["translation"].get("lua_file")
        if not f:
            continue
        low = train_samples[_base_rule_id(t["rule_id"])] < max_train
        rate = low and not re.search(r"\bflags:", t.get("suricata") or "")
        new, note = repair_lua(lua[f], t, rate, True, home_net, guard_duration=False)
        if new != lua[f]:
            notes.append(dict(note, lua_file=f))
        out[f] = new
    return out, notes


def drop_low_support(rules_text: str, lua: Dict[str, str], translated: list, train_samples: Dict[str, int], max_train: int) -> Tuple[str, Dict[str, str], list]:
    """Arm AD: rules with train_samples < max_train are removed. Returns (rq1.rules text, remaining
    Lua scripts, ids of the removed rules). The sids of the other rules do not change. A rule that is
    not found exactly once in the text raises an error."""
    lines = rules_text.split("\n")
    dropped, out_lua = [], dict(lua)
    for t in translated:
        sid = t["translation"].get("sid")
        if not sid or train_samples[_base_rule_id(t["rule_id"])] >= max_train:
            continue
        hit = [i for i, x in enumerate(lines) if x.startswith("alert") and re.search(rf"\bsid:{int(sid)};", x)]
        if len(hit) != 1:
            raise ValueError(f"{t['rule_id']}: sid {sid} must occur exactly once in rq1.rules, found {len(hit)}")
        del lines[hit[0]]
        dropped.append(t["rule_id"])
        out_lua.pop(t["translation"].get("lua_file"), None)
    return "\n".join(lines), out_lua, dropped


def repair_ruleset(lua: Dict[str, str], translated: list, arm: str, home_net: str) -> Tuple[Dict[str, str], list]:
    """lua = {file name: initial Lua source}. Returns (Lua of the arm, notes for each changed rule)."""
    if arm not in ARMS:
        raise KeyError(f"unknown arm: {arm}")
    rate, direction = ARMS[arm]
    out = dict(lua)
    notes = []
    for t in translated:
        f = t["translation"].get("lua_file")
        if not f:
            continue
        new, note = repair_lua(lua[f], t, rate, direction, home_net)
        if new != lua[f]:
            notes.append(dict(note, lua_file=f))
        out[f] = new
    return out, notes
