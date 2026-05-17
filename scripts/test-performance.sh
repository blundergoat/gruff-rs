#!/usr/bin/env bash
# scripts/test-performance.sh — end-to-end performance harness for gruff-rs.
# See `--help` for usage and `.goat-flow/tasks/0.1/M34-performance-test-script.md`
# for the design rationale.

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly REPO_ROOT
readonly PERF_DIR="${REPO_ROOT}/target/perf"
readonly DEFAULT_BASELINE="${PERF_DIR}/baseline.json"
readonly LAST_RUN="${PERF_DIR}/last-run.json"
readonly SCRATCH_BASELINE="${PERF_DIR}/scratch-baseline.json"
readonly SCRATCH_HISTORY="${PERF_DIR}/scratch-history.json"
readonly SCRATCH_PATCH="${PERF_DIR}/scratch-empty.patch"
readonly TIME_LOG="${PERF_DIR}/time.log"
readonly BIN="${REPO_ROOT}/target/release/gruff-rs"

ITERS="${GRUFF_PERF_ITERS:-5}"
TIME_BUDGET_PCT="${GRUFF_PERF_TIME_BUDGET_PCT:-15}"
RSS_BUDGET_PCT="${GRUFF_PERF_RSS_BUDGET_PCT:-25}"
HOST_TAG="${GRUFF_PERF_HOST_TAG:-}"
LARGE_CORPUS="${GRUFF_PERF_LARGE_CORPUS:-}"

# Exit codes (documented in --help).
readonly EXIT_OK=0
readonly EXIT_REGRESSION=1
readonly EXIT_BASELINE_PROBLEM=2
readonly EXIT_RUN_FAILURE=3

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log() { printf '[perf] %s\n' "$*" >&2; }
die() { printf '[perf] error: %s\n' "$*" >&2; exit "${EXIT_RUN_FAILURE}"; }

require_tool() {
    command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1"
}

usage() {
    cat <<'USAGE'
scripts/test-performance.sh — gruff-rs performance harness

Usage:
  scripts/test-performance.sh [--check | --update-baseline] [--baseline PATH] [--force] [--help]

Modes:
  (default)             Run all scenarios, print a table, write target/perf/last-run.json.
  --update-baseline     Same as default, then copy the result to the baseline file.
                        Refuses to overwrite on a dirty git tree unless --force is set.
  --check               Run all scenarios, compare against the baseline, exit non-zero
                        if any scenario exceeds the time or RSS budget.
  --baseline PATH       Override baseline path (default: target/perf/baseline.json).
  --force               Allow --update-baseline on a dirty tree.
  --help                Print this help and exit.

Environment variables:
  GRUFF_PERF_ITERS              Total iterations per scenario (default 5; first is warmup).
  GRUFF_PERF_TIME_BUDGET_PCT    Wall-clock regression budget percent (default 15).
  GRUFF_PERF_RSS_BUDGET_PCT     Peak RSS regression budget percent (default 25).
  GRUFF_PERF_HOST_TAG           Free-form host tag stored in the baseline.
  GRUFF_PERF_LARGE_CORPUS       Absolute path to an external corpus; enables one extra scenario.

Scenarios (each runs ITERS times; the first run is warmup and discarded):
  fixtures.text         analyse fixtures --format text
  fixtures.json         analyse fixtures --format json
  fixtures.sarif        analyse fixtures --format sarif
  fixtures.html         analyse fixtures --format html
  src.json              analyse src --format json (self-scan)
  src.with-baseline     analyse src --format json --baseline=<scratch>
  src.with-history      analyse src --format json --history-file=<scratch>
  src.diff-empty        analyse src --format json --diff-patch <empty-patch>
  list-rules.json       list-rules --format json
  large-corpus.json     analyse "$GRUFF_PERF_LARGE_CORPUS" (only when env var is set)

Exit codes:
  0  Run succeeded; no regressions in --check mode.
  1  Regression detected (--check only).
  2  Missing baseline (--check) or dirty tree on --update-baseline.
  3  Build or scenario invocation failed.
USAGE
}

# ---------------------------------------------------------------------------
# CLI parsing
# ---------------------------------------------------------------------------

MODE="run"
BASELINE_PATH="${DEFAULT_BASELINE}"
FORCE_UPDATE="false"

while (("$#")); do
    case "$1" in
        --help|-h) usage; exit "${EXIT_OK}" ;;
        --check) MODE="check"; shift ;;
        --update-baseline) MODE="update"; shift ;;
        --baseline)
            [[ "$#" -ge 2 ]] || die "--baseline requires a path argument"
            BASELINE_PATH="$2"; shift 2 ;;
        --force) FORCE_UPDATE="true"; shift ;;
        *) die "unknown argument: $1 (try --help)" ;;
    esac
done

if ! [[ "${ITERS}" =~ ^[0-9]+$ ]] || (("${ITERS}" < 2)); then
    die "GRUFF_PERF_ITERS must be an integer >= 2 (got '${ITERS}')"
fi

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

require_tool cargo
require_tool jq
require_tool awk
require_tool git

mkdir -p "${PERF_DIR}"

GIT_COMMIT="$(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
if [[ -z "$(git -C "${REPO_ROOT}" status --porcelain 2>/dev/null)" ]]; then
    GIT_DIRTY="false"
else
    GIT_DIRTY="true"
fi

# Machine metadata.
UNAME_STR="$(uname -srm 2>/dev/null || echo unknown)"
CPU_MODEL="unknown"
if [[ -r /proc/cpuinfo ]]; then
    CPU_MODEL="$(awk -F': ' '/^model name/ {print $2; exit}' /proc/cpuinfo 2>/dev/null || true)"
fi
if [[ -z "${CPU_MODEL}" || "${CPU_MODEL}" == "unknown" ]]; then
    CPU_MODEL="$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo unknown)"
fi

# GNU time detection: we need `/usr/bin/time -f` (BSD time rejects -f).
TIME_BIN=""
if [[ -x /usr/bin/time ]] && /usr/bin/time -f '%e %M' true >/dev/null 2>&1; then
    TIME_BIN="/usr/bin/time"
elif command -v gtime >/dev/null 2>&1 && gtime -f '%e %M' true >/dev/null 2>&1; then
    TIME_BIN="$(command -v gtime)"
else
    log "warning: GNU time not found; peak RSS will be reported as null."
fi

# ---------------------------------------------------------------------------
# Build (timed once)
# ---------------------------------------------------------------------------

log "Building release binary..."
build_start="$(date +%s.%N)"
(cd "${REPO_ROOT}" && cargo build --release --quiet) || die "cargo build --release failed"
build_end="$(date +%s.%N)"
BUILD_SECONDS="$(awk -v s="${build_start}" -v e="${build_end}" 'BEGIN { printf "%.3f", e - s }')"
[[ -x "${BIN}" ]] || die "binary not found at ${BIN}"

VERSION="$("${BIN}" --version 2>/dev/null | awk '{print $2}')"
[[ -n "${VERSION}" ]] || VERSION="unknown"

# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------
#
# Scenarios are declared as parallel arrays: name + argv (as a single
# string parsed by `eval` into an array, since some args contain `=`).
# Setup commands are dispatched by scenario name.

declare -a SCENARIO_NAMES SCENARIO_CMDS

add_scenario() { SCENARIO_NAMES+=("$1"); SCENARIO_CMDS+=("$2"); }

add_scenario "fixtures.text"      "analyse fixtures --format text --fail-on none --no-baseline"
add_scenario "fixtures.json"      "analyse fixtures --format json --fail-on none --no-baseline"
add_scenario "fixtures.sarif"     "analyse fixtures --format sarif --fail-on none --no-baseline"
add_scenario "fixtures.html"      "analyse fixtures --format html --fail-on none --no-baseline"
add_scenario "src.json"           "analyse src --format json --fail-on none --no-baseline"
add_scenario "src.with-baseline"  "analyse src --format json --fail-on none --baseline ${SCRATCH_BASELINE}"
add_scenario "src.with-history"   "analyse src --format json --fail-on none --no-baseline --history-file ${SCRATCH_HISTORY}"
add_scenario "src.diff-empty"     "analyse src --format json --fail-on none --no-baseline --diff-patch ${SCRATCH_PATCH}"
add_scenario "list-rules.json"    "list-rules --format json"
if [[ -n "${LARGE_CORPUS}" ]]; then
    [[ -d "${LARGE_CORPUS}" ]] || die "GRUFF_PERF_LARGE_CORPUS does not exist: ${LARGE_CORPUS}"
    add_scenario "large-corpus.json" "analyse ${LARGE_CORPUS} --format json --fail-on none --no-baseline"
fi

setup_scenario() {
    case "$1" in
        src.with-baseline)
            log "  preparing scratch baseline for $1"
            "${BIN}" analyse src --format json --fail-on none \
                --generate-baseline "${SCRATCH_BASELINE}" >/dev/null
            ;;
        src.with-history)
            : > "${SCRATCH_HISTORY}"
            ;;
        src.diff-empty)
            : > "${SCRATCH_PATCH}"
            ;;
        *) : ;;
    esac
}

# ---------------------------------------------------------------------------
# Measurement
# ---------------------------------------------------------------------------

# run_once <argv-string> -> emits "wall_seconds peak_rss_bytes_or_empty".
# Wall-clock comes from date +%s.%N (nanosecond precision); GNU time's %e is
# centisecond-precise which is too coarse for sub-10ms scenarios. RSS still
# comes from GNU time when available.
run_once() {
    local argv_str="$1"
    # shellcheck disable=SC2206
    local argv=(${argv_str})
    rm -f "${TIME_LOG}"
    local t0 t1 wall rss_bytes=""
    if [[ -n "${TIME_BIN}" ]]; then
        t0="$(date +%s.%N)"
        "${TIME_BIN}" -f '%M' -o "${TIME_LOG}" "${BIN}" "${argv[@]}" >/dev/null \
            || die "scenario invocation failed: ${argv_str}"
        t1="$(date +%s.%N)"
        local rss_kb
        read -r rss_kb < "${TIME_LOG}"
        rss_bytes=$(( rss_kb * 1024 ))
    else
        t0="$(date +%s.%N)"
        "${BIN}" "${argv[@]}" >/dev/null || die "scenario invocation failed: ${argv_str}"
        t1="$(date +%s.%N)"
    fi
    wall="$(awk -v s="${t0}" -v e="${t1}" 'BEGIN { printf "%.6f", e - s }')"
    printf '%s %s\n' "${wall}" "${rss_bytes}"
}

# stats <space-separated-numbers> -> "median min max stddev"
stats() {
    awk -v values="$*" 'BEGIN {
        n = split(values, arr, " ")
        # filter empties
        m = 0
        for (i = 1; i <= n; i++) { if (arr[i] != "") { samples[++m] = arr[i] + 0 } }
        if (m == 0) { print "0 0 0 0"; exit }
        # sort
        for (i = 1; i <= m; i++) {
            for (j = i + 1; j <= m; j++) {
                if (samples[j] < samples[i]) {
                    t = samples[i]; samples[i] = samples[j]; samples[j] = t
                }
            }
        }
        if (m % 2 == 1) { median = samples[(m + 1) / 2] }
        else { median = (samples[m / 2] + samples[m / 2 + 1]) / 2 }
        min = samples[1]; max = samples[m]
        sum = 0
        for (i = 1; i <= m; i++) sum += samples[i]
        mean = sum / m
        ssq = 0
        for (i = 1; i <= m; i++) { d = samples[i] - mean; ssq += d * d }
        stddev = (m > 1) ? sqrt(ssq / (m - 1)) : 0
        printf "%.6f %.6f %.6f %.6f\n", median, min, max, stddev
    }'
}

# Run one scenario and emit its JSON object to stdout.
run_scenario() {
    local name="$1" argv_str="$2"
    log "Scenario: ${name}"
    setup_scenario "${name}"

    local iter_walls=() iter_rss=()
    local i=0
    while (( i < ITERS )); do
        local sample
        sample="$(run_once "${argv_str}")"
        local wall rss
        wall="$(awk '{print $1}' <<< "${sample}")"
        rss="$(awk '{print $2}' <<< "${sample}")"
        if (( i == 0 )); then
            log "  warmup: wall=${wall}s rss=${rss:-n/a}"
        else
            iter_walls+=("${wall}")
            iter_rss+=("${rss:-}")
            log "  iter $((i)): wall=${wall}s rss=${rss:-n/a}"
        fi
        i=$((i + 1))
    done

    local stats_walls stats_rss
    stats_walls="$(stats "${iter_walls[*]}")"
    stats_rss="$(stats "${iter_rss[*]}")"
    local wall_median wall_min wall_max wall_stddev
    read -r wall_median wall_min wall_max wall_stddev <<< "${stats_walls}"
    local rss_median _rss_min _rss_max _rss_stddev
    read -r rss_median _rss_min _rss_max _rss_stddev <<< "${stats_rss}"
    local rss_median_json
    if [[ -z "${TIME_BIN}" ]]; then
        rss_median_json="null"
    else
        rss_median_json="$(printf '%d' "${rss_median%.*}")"
    fi

    # Build iterations array via jq.
    local iter_pairs="["
    local j
    for (( j = 0; j < ${#iter_walls[@]}; j++ )); do
        if (( j > 0 )); then iter_pairs+=", "; fi
        local r="${iter_rss[$j]:-}"
        if [[ -z "${r}" ]]; then r="null"; fi
        iter_pairs+="{\"wall_seconds\": ${iter_walls[$j]}, \"peak_rss_bytes\": ${r}}"
    done
    iter_pairs+="]"

    jq -nc \
        --arg name "${name}" \
        --arg command "gruff-rs ${argv_str}" \
        --argjson iterations "${iter_pairs}" \
        --argjson median "${wall_median}" \
        --argjson min "${wall_min}" \
        --argjson max "${wall_max}" \
        --argjson stddev "${wall_stddev}" \
        --argjson peak_rss "${rss_median_json}" \
        '{
            name: $name,
            command: $command,
            iterations: $iterations,
            median_seconds: $median,
            min_seconds: $min,
            max_seconds: $max,
            stddev_seconds: $stddev,
            peak_rss_bytes: $peak_rss
        }'
}

# ---------------------------------------------------------------------------
# Run all scenarios and assemble the result JSON
# ---------------------------------------------------------------------------

SCENARIO_JSONS=()
for idx in "${!SCENARIO_NAMES[@]}"; do
    SCENARIO_JSONS+=("$(run_scenario "${SCENARIO_NAMES[$idx]}" "${SCENARIO_CMDS[$idx]}")")
done

# Aggregate.
SCENARIOS_JSON="[$(IFS=,; echo "${SCENARIO_JSONS[*]}")]"

RESULT_JSON="$(jq -n \
    --arg version "${VERSION}" \
    --arg commit "${GIT_COMMIT}" \
    --argjson dirty "${GIT_DIRTY}" \
    --arg uname "${UNAME_STR}" \
    --arg cpu "${CPU_MODEL}" \
    --arg host_tag "${HOST_TAG}" \
    --argjson build_seconds "${BUILD_SECONDS}" \
    --argjson iters "${ITERS}" \
    --argjson scenarios "${SCENARIOS_JSON}" \
    --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{
        tool: { name: "gruff-rs", version: $version },
        git: { commit: $commit, dirty: $dirty },
        machine: { uname: $uname, cpu: $cpu, host_tag: $host_tag },
        build: { profile: "release", build_seconds: $build_seconds },
        iters: $iters,
        discarded_warmup: 1,
        generated_at: $generated_at,
        scenarios: $scenarios
    }')"

printf '%s\n' "${RESULT_JSON}" > "${LAST_RUN}"

# ---------------------------------------------------------------------------
# Human-readable summary
# ---------------------------------------------------------------------------

print_table() {
    local json="$1"
    printf '\n%-22s  %12s  %12s  %12s  %12s  %14s\n' \
        "Scenario" "median(s)" "min(s)" "max(s)" "stddev(s)" "peak_rss(MB)"
    printf '%s\n' "----------------------------------------------------------------------------------------------------"
    jq -r '.scenarios[] | [
        .name,
        (.median_seconds | tostring),
        (.min_seconds | tostring),
        (.max_seconds | tostring),
        (.stddev_seconds | tostring),
        (if .peak_rss_bytes == null then "n/a" else ((.peak_rss_bytes / 1048576) | tostring) end)
    ] | @tsv' <<< "${json}" \
        | while IFS=$'\t' read -r name med mn mx sd rss; do
            printf '%-22s  %12.4f  %12.4f  %12.4f  %12.4f  %14s\n' \
                "${name}" "${med}" "${mn}" "${mx}" "${sd}" "${rss}"
        done
}

print_table "${RESULT_JSON}"

log "Wrote ${LAST_RUN}"

# ---------------------------------------------------------------------------
# Mode dispatch: --update-baseline
# ---------------------------------------------------------------------------

if [[ "${MODE}" == "update" ]]; then
    if [[ "${GIT_DIRTY}" == "true" && "${FORCE_UPDATE}" != "true" ]]; then
        log "error: working tree is dirty; refusing to write baseline."
        log "       commit/stash your changes, or re-run with --force."
        exit "${EXIT_BASELINE_PROBLEM}"
    fi
    cp "${LAST_RUN}" "${BASELINE_PATH}"
    log "Baseline updated: ${BASELINE_PATH}"
fi

# ---------------------------------------------------------------------------
# Mode dispatch: --check
# ---------------------------------------------------------------------------

if [[ "${MODE}" == "check" ]]; then
    if [[ ! -r "${BASELINE_PATH}" ]]; then
        log "error: baseline not found at ${BASELINE_PATH}"
        log "       run 'scripts/test-performance.sh --update-baseline' first."
        exit "${EXIT_BASELINE_PROBLEM}"
    fi
    BASELINE_JSON="$(cat "${BASELINE_PATH}")"

    # Warn if machine metadata differs.
    BASE_UNAME="$(jq -r '.machine.uname // ""' <<< "${BASELINE_JSON}")"
    BASE_HOST="$(jq -r '.machine.host_tag // ""' <<< "${BASELINE_JSON}")"
    if [[ "${BASE_UNAME}" != "${UNAME_STR}" || "${BASE_HOST}" != "${HOST_TAG}" ]]; then
        log "warning: baseline machine differs from current host."
        log "         baseline uname='${BASE_UNAME}' host_tag='${BASE_HOST}'"
        log "         current  uname='${UNAME_STR}' host_tag='${HOST_TAG}'"
    fi

    REGRESSIONS_JSON="$(jq -n \
        --argjson current "${RESULT_JSON}" \
        --argjson baseline "${BASELINE_JSON}" \
        --argjson time_budget "${TIME_BUDGET_PCT}" \
        --argjson rss_budget "${RSS_BUDGET_PCT}" \
        '
        ($baseline.scenarios | map({key: .name, value: .}) | from_entries) as $base
        | [
            $current.scenarios[]
            | . as $cur
            | ($base[$cur.name] // null) as $b
            | if $b == null then
                { name: $cur.name, kind: "missing-baseline" }
              else
                ((($cur.median_seconds - $b.median_seconds) / $b.median_seconds * 100) | . * 100 | round / 100) as $time_pct
                | (if $cur.peak_rss_bytes == null or $b.peak_rss_bytes == null or $b.peak_rss_bytes == 0
                   then null
                   else ((($cur.peak_rss_bytes - $b.peak_rss_bytes) / $b.peak_rss_bytes * 100) | . * 100 | round / 100)
                   end) as $rss_pct
                | {
                    name: $cur.name,
                    baseline_median_seconds: $b.median_seconds,
                    current_median_seconds: $cur.median_seconds,
                    time_pct: $time_pct,
                    baseline_peak_rss_bytes: $b.peak_rss_bytes,
                    current_peak_rss_bytes: $cur.peak_rss_bytes,
                    rss_pct: $rss_pct,
                    over_time_budget: ($time_pct > $time_budget),
                    over_rss_budget: (if $rss_pct == null then false else $rss_pct > $rss_budget end)
                  }
              end
          ]
        | map(select(.kind == "missing-baseline" or .over_time_budget or .over_rss_budget))
        ')"

    REG_COUNT="$(jq 'length' <<< "${REGRESSIONS_JSON}")"
    if (( REG_COUNT == 0 )); then
        log "Check passed: all ${#SCENARIO_NAMES[@]} scenarios within budget (time ${TIME_BUDGET_PCT}%, RSS ${RSS_BUDGET_PCT}%)."
        exit "${EXIT_OK}"
    fi

    printf '\nRegressions vs %s:\n' "${BASELINE_PATH}"
    printf '%-22s  %12s  %12s  %8s  %8s\n' "Scenario" "base(s)" "cur(s)" "Δtime%" "Δrss%"
    printf '%s\n' "------------------------------------------------------------------------"
    jq -r '.[] | [
        .name,
        (.baseline_median_seconds // "n/a" | tostring),
        (.current_median_seconds // "n/a" | tostring),
        (.time_pct // "n/a" | tostring),
        (.rss_pct // "n/a" | tostring)
    ] | @tsv' <<< "${REGRESSIONS_JSON}" \
        | while IFS=$'\t' read -r name b c tp rp; do
            printf '%-22s  %12s  %12s  %8s  %8s\n' "${name}" "${b}" "${c}" "${tp}" "${rp}"
        done

    exit "${EXIT_REGRESSION}"
fi

exit "${EXIT_OK}"
