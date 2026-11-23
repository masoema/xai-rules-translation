#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
# suricata_batch_pcap.sh — run Suricata offline on each PCAP file × a list of rulesets
# ═══════════════════════════════════════════════════════════════════════════
# The script ONLY runs Suricata and records metadata. Alert counting and scoring are done
# in Python from eve.json (see 4_scoring/).
#
# Behaviour:
#   1. find -type f + PCAP/PCAPNG magic-number check (CIC file names without an extension
#      are supported); folders, non-PCAP files and empty files are never passed to `-r`.
#   2. No `set -e`/eval: the exit code of each run is captured, recorded, and the next run
#      continues; failures are collected in failed_runs.tsv (script exit = 1 if any).
#   3. A list of rulesets (name -> folder + rule file); Lua scripts are found in the same
#      folder through default-rule-path.
#   4. run_metadata.json per run + batch_metadata.json: sha256 of the rules, Lua scripts and
#      config, Suricata version, exact command, duration, exit code. All paths are quoted.
#
# Usage (Linux or WSL; Suricata 7.0.10):
#   ./suricata_batch_pcap.sh --config ../configs/suricata.yaml --output-dir OUT \
#       --ruleset proposed=../../1_rulesets/initial/proposed:rq1.rules \
#       --ruleset anomaly2sign=../../1_rulesets/initial/anomaly2sign:rq1.rules \
#       --ruleset rf_surrogate=../../1_rulesets/initial/rf_surrogate:rq1.rules \
#       --ruleset et=/path/et:emerging-dos.rules \
#       --pcap-list ../../3_ground_truth/file_lists/files_819.txt   # one path per line
#   or --pcap-dir DIR (repeatable; only files directly in DIR, -maxdepth 1)
#   --dry-run       : only list the PCAP files and commands; Suricata is not run
#   --skip-existing : skip runs that already have a run_metadata.json with exit_code 0
#
# Output: OUT/<ruleset>/<pcap_name>/{eve.json, stats.log, suricata.log, run_metadata.json}
#         OUT/batch_metadata.json, OUT/pcap_list.txt, OUT/failed_runs.tsv, OUT/batch.log
# ═══════════════════════════════════════════════════════════════════════════
set -u -o pipefail

SURICATA_BIN="suricata"
CONFIG_FILE=""
OUTPUT_DIR=""
PCAP_DIRS=()
PCAP_LIST=""
RULESETS=()
SKIP_EXISTING=false
DRY_RUN=false
EXTRA_SET=("security.lua.allow-rules=true")

usage() {
    sed -n '2,31p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --config)         CONFIG_FILE="$2"; shift 2 ;;
        --output-dir)     OUTPUT_DIR="$2"; shift 2 ;;
        --pcap-dir)       PCAP_DIRS+=("$2"); shift 2 ;;
        --pcap-list)      PCAP_LIST="$2"; shift 2 ;;
        --ruleset)        RULESETS+=("$2"); shift 2 ;;
        --suricata)       SURICATA_BIN="$2"; shift 2 ;;
        --skip-existing)  SKIP_EXISTING=true; shift ;;
        --dry-run)        DRY_RUN=true; shift ;;
        -h|--help)        usage 0 ;;
        *) echo "ERROR: unknown argument: $1" >&2; usage 2 ;;
    esac
done

die() { echo "ERROR: $*" >&2; exit 2; }
[ -n "$CONFIG_FILE" ] && [ -f "$CONFIG_FILE" ] || die "--config is required and must be a file: '$CONFIG_FILE'"
[ -n "$OUTPUT_DIR" ] || die "--output-dir is required"
[ ${#RULESETS[@]} -gt 0 ] || die "at least one --ruleset NAME=FOLDER:RULE_FILE"
[ ${#PCAP_DIRS[@]} -gt 0 ] || [ -n "$PCAP_LIST" ] || die "--pcap-dir or --pcap-list is required"
command -v sha256sum >/dev/null || die "sha256sum not found"

json_str() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }
sha_file() { sha256sum "$1" | cut -d' ' -f1; }

# ── Magic-number check: pcap (le/be, µs/ns) or pcapng ────────────────────────
pcap_magic() {
    local f="$1" m
    [ -f "$f" ] && [ -s "$f" ] || { echo ""; return; }
    m=$(head -c 4 "$f" | od -An -tx1 | tr -d ' \n')
    case "$m" in
        d4c3b2a1|a1b2c3d4|4d3cb2a1|a1b23c4d) echo "pcap" ;;
        0a0d0d0a) echo "pcapng" ;;
        *) echo "" ;;
    esac
}

# ── Ruleset validation: NAME=FOLDER:FILE ─────────────────────────────────────
declare -A RS_DIR RS_FILE RS_SHA RS_LUA_SHA
RS_NAMES=()
for spec in "${RULESETS[@]}"; do
    name="${spec%%=*}"; rest="${spec#*=}"
    dir="${rest%:*}"; file="${rest##*:}"
    [ -n "$name" ] && [ "$name" != "$spec" ] && [ -n "$dir" ] && [ -n "$file" ] || die "bad --ruleset format: '$spec'"
    [ -f "$dir/$file" ] || die "rule file not found: $dir/$file"
    [[ "$name" =~ ^[A-Za-z0-9_.-]+$ ]] || die "ruleset name may only contain [A-Za-z0-9_.-]: '$name'"
    RS_NAMES+=("$name"); RS_DIR[$name]="$dir"; RS_FILE[$name]="$file"
    RS_SHA[$name]=$(sha_file "$dir/$file")
    # combined hash of all Lua scripts in the folder (sorted by name)
    lua_list=$(find "$dir" -maxdepth 1 -type f -name '*.lua' -print0 | sort -z | xargs -0 -r sha256sum)
    RS_LUA_SHA[$name]=$(printf '%s' "$lua_list" | sha256sum | cut -d' ' -f1)
done

# ── Collect the PCAP files ───────────────────────────────────────────────────
mkdir -p "$OUTPUT_DIR" || die "cannot create $OUTPUT_DIR"
LOG="$OUTPUT_DIR/batch.log"
CANDIDATES=()
if [ -n "$PCAP_LIST" ]; then
    [ -f "$PCAP_LIST" ] || die "--pcap-list not found: $PCAP_LIST"
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%$'\r'}"
        [ -z "$line" ] || [ "${line:0:1}" = "#" ] || CANDIDATES+=("$line")
    done < "$PCAP_LIST"
fi
for d in "${PCAP_DIRS[@]}"; do
    [ -d "$d" ] || die "--pcap-dir is not a folder: $d"
    while IFS= read -r -d '' f; do CANDIDATES+=("$f"); done < <(find "$d" -maxdepth 1 -type f -print0 | sort -z)
done

PCAPS=()
: > "$OUTPUT_DIR/pcap_list.txt"
for f in "${CANDIDATES[@]}"; do
    kind=$(pcap_magic "$f")
    if [ -z "$kind" ]; then
        echo "[skip] not a PCAP/PCAPNG file (magic number) or not a file: $f" | tee -a "$LOG"
        continue
    fi
    PCAPS+=("$f")
    printf '%s\t%s\n' "$f" "$kind" >> "$OUTPUT_DIR/pcap_list.txt"
done
[ ${#PCAPS[@]} -gt 0 ] || die "no valid PCAP file"

SURI_VERSION=$("$SURICATA_BIN" -V 2>&1 | head -1)
CONFIG_SHA=$(sha_file "$CONFIG_FILE")
"$SURICATA_BIN" --build-info > "$OUTPUT_DIR/build_info.txt" 2>&1 || true

{
    printf '{\n  "suricata_version": "%s",\n  "config": "%s",\n  "config_sha256": "%s",\n' \
        "$(json_str "$SURI_VERSION")" "$(json_str "$CONFIG_FILE")" "$CONFIG_SHA"
    printf '  "build_info_sha256": "%s",\n  "n_pcaps": %d,\n  "pcap_list_sha256": "%s",\n' \
        "$(sha_file "$OUTPUT_DIR/build_info.txt")" "${#PCAPS[@]}" "$(sha_file "$OUTPUT_DIR/pcap_list.txt")"
    printf '  "dry_run": %s,\n  "started_at": "%s",\n  "rulesets": [\n' "$DRY_RUN" "$(date -Iseconds)"
    sep=""
    for n in "${RS_NAMES[@]}"; do
        printf '%s    {"name": "%s", "dir": "%s", "rules_file": "%s", "rules_sha256": "%s", "lua_sha256": "%s"}' \
            "$sep" "$n" "$(json_str "${RS_DIR[$n]}")" "$(json_str "${RS_FILE[$n]}")" "${RS_SHA[$n]}" "${RS_LUA_SHA[$n]}"
        sep=$',\n'
    done
    printf '\n  ]\n}\n'
} > "$OUTPUT_DIR/batch_metadata.json"

echo "== $(date -Iseconds) $SURI_VERSION | ${#PCAPS[@]} PCAP × ${#RS_NAMES[@]} ruleset(s) | dry-run=$DRY_RUN" | tee -a "$LOG"
printf 'ruleset\tpcap\texit_code\tnote\n' > "$OUTPUT_DIR/failed_runs.tsv"
N_FAIL=0; N_OK=0; N_SKIP=0

# ── One run ──────────────────────────────────────────────────────────────────
run_one() {
    local name="$1" pcap="$2"
    local pname out start end code
    pname=$(basename "$pcap")
    out="$OUTPUT_DIR/$name/$pname"
    if [ "$SKIP_EXISTING" = true ] && [ -f "$out/run_metadata.json" ] && grep -q '"exit_code": 0,' "$out/run_metadata.json"; then
        N_SKIP=$((N_SKIP + 1)); return 0
    fi
    local cmd=("$SURICATA_BIN" -c "$CONFIG_FILE" -r "$pcap" -l "$out" -k none
               -S "${RS_DIR[$name]}/${RS_FILE[$name]}" --set "default-rule-path=${RS_DIR[$name]}")
    for s in "${EXTRA_SET[@]}"; do cmd+=(--set "$s"); done
    if [ "$DRY_RUN" = true ]; then
        { printf '[dry-run]'; printf ' %q' "${cmd[@]}"; printf '\n'; } | tee -a "$LOG"
        return 0
    fi
    rm -rf "$out"; mkdir -p "$out"
    start=$(date +%s.%N)
    "${cmd[@]}" > "$out/suricata.log" 2>&1
    code=$?
    end=$(date +%s.%N)
    {
        printf '{\n  "ruleset": "%s",\n  "pcap": "%s",\n  "pcap_name": "%s",\n' "$name" "$(json_str "$pcap")" "$(json_str "$pname")"
        printf '  "exit_code": %d,\n  "duration_seconds": %s,\n' "$code" "$(awk -v a="$start" -v b="$end" 'BEGIN{printf "%.3f", b-a}')"
        printf '  "rules_sha256": "%s",\n  "lua_sha256": "%s",\n  "config_sha256": "%s",\n' \
            "${RS_SHA[$name]}" "${RS_LUA_SHA[$name]}" "$CONFIG_SHA"
        printf '  "suricata_version": "%s",\n  "command": "%s",\n  "finished_at": "%s"\n}\n' \
            "$(json_str "$SURI_VERSION")" "$(json_str "$(printf '%q ' "${cmd[@]}")")" "$(date -Iseconds)"
    } > "$out/run_metadata.json"
    if [ "$code" -ne 0 ]; then
        N_FAIL=$((N_FAIL + 1))
        printf '%s\t%s\t%d\t%s\n' "$name" "$pcap" "$code" "see $out/suricata.log" >> "$OUTPUT_DIR/failed_runs.tsv"
        echo "[FAILED] $name $pname exit $code" | tee -a "$LOG"
    else
        N_OK=$((N_OK + 1))
        echo "[ok] $name $pname $(awk -v a="$start" -v b="$end" 'BEGIN{printf "%.1f", b-a}') s" | tee -a "$LOG"
    fi
    return 0
}

for pcap in "${PCAPS[@]}"; do
    for name in "${RS_NAMES[@]}"; do
        run_one "$name" "$pcap"
    done
done

echo "== $(date -Iseconds) done: ok $N_OK, failed $N_FAIL, skipped $N_SKIP" | tee -a "$LOG"
[ "$N_FAIL" -eq 0 ] || exit 1
exit 0
