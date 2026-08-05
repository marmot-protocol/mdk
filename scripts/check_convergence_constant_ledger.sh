#!/usr/bin/env bash
set -euo pipefail

# Keep convergence-affecting policy, resource, scheduler, and input-recovery
# constants attached to reviewed ledger IDs. This is deliberately a narrow
# source-name audit; the scope and exclusions live in the tracking plan.

cd "$(dirname "${BASH_SOURCE[0]}")/.."

inventory_path="docs/marmot-architecture/convergence-constant-inventory.txt"
plan_path="docs/marmot-architecture/convergence-reliability-plan.md"
expected_ids=(P1 P2 P3 P4 P5 P6 P7 P8 E1 E2 E3 E4 E5 E6 E7 E8 E9 A1 A2 A3 A4 A5 A6 A7 A8 A9)
inventory_pairs=("__inventory_sentinel__")
inventory_ids=()
fail=0

report() {
    echo "error: $1" >&2
    fail=1
}

contains_expected_id() {
    local candidate="$1"
    local expected
    for expected in "${expected_ids[@]}"; do
        if [[ "$candidate" == "$expected" ]]; then
            return 0
        fi
    done
    return 1
}

contains_inventory_pair() {
    local candidate="$1"
    local existing
    for existing in "${inventory_pairs[@]}"; do
        if [[ "$candidate" == "$existing" ]]; then
            return 0
        fi
    done
    return 1
}

while IFS='|' read -r ledger_id source_path symbol; do
    if [[ -z "$ledger_id" || "$ledger_id" == \#* ]]; then
        continue
    fi

    if [[ -z "$source_path" || -z "$symbol" ]]; then
        report "malformed convergence inventory row for ${ledger_id}"
        continue
    fi
    if ! contains_expected_id "$ledger_id"; then
        report "unexpected convergence ledger id ${ledger_id}"
    fi

    pair="${source_path}|${symbol}"
    if contains_inventory_pair "$pair"; then
        report "duplicate convergence inventory entry ${pair}"
    else
        inventory_pairs+=("$pair")
    fi
    inventory_ids+=("$ledger_id")

    if [[ ! -f "$source_path" ]]; then
        report "convergence inventory source does not exist: ${source_path}"
        continue
    fi
    if ! rg -q "^(pub(\\([^)]*\\))? )?const ${symbol}:" "$source_path"; then
        report "convergence inventory declaration is missing: ${source_path}:${symbol}"
    fi
done < "$inventory_path"

for expected_id in "${expected_ids[@]}"; do
    found=0
    for inventory_id in "${inventory_ids[@]}"; do
        if [[ "$expected_id" == "$inventory_id" ]]; then
            found=1
            break
        fi
    done
    if [[ "$found" -eq 0 ]]; then
        report "convergence inventory is missing ledger id ${expected_id}"
    fi
    if ! rg -q "^\\| ${expected_id} \\|" "$plan_path"; then
        report "convergence plan is missing ledger row ${expected_id}"
    fi
done

discover_constants() {
    local source_path="$1"
    local name_pattern="$2"
    local declaration
    local symbol
    local pair

    while IFS= read -r declaration; do
        symbol="${declaration#*const }"
        symbol="${symbol%%:*}"
        pair="${source_path}|${symbol}"
        if ! contains_inventory_pair "$pair"; then
            report "unreviewed convergence constant ${source_path}:${symbol}"
        fi
    done < <(
        rg --no-filename -o \
            "^(pub(\\([^)]*\\))? )?const (${name_pattern}):" \
            "$source_path" || true
    )
}

discover_constants "crates/cgka-engine/src/convergence.rs" "V1_[A-Z0-9_]+"
discover_constants "crates/cgka-engine/src/canonicalization.rs" "V1_[A-Z0-9_]+"
discover_constants "crates/cgka-engine/src/wire_format.rs" "DEFAULT_MAX_PAST_EPOCHS"
discover_constants \
    "crates/cgka-engine/src/message_processor/mod.rs" \
    "(MAX_CONVERGENCE_[A-Z0-9_]+|MAX_DEFERRED_[A-Z0-9_]+|MAX_PEEL_DEFERRED_[A-Z0-9_]+|MAX_QUEUED_[A-Z0-9_]+|SELF_REMOVE_AUTO_COMMIT_[A-Z0-9_]+)"
discover_constants \
    "crates/cgka-engine/src/openmls_projection.rs" \
    "CANDIDATE_REPLAY_BUDGET_[A-Z0-9_]+"
discover_constants \
    "crates/marmot-app/src/runtime/account_worker.rs" \
    "(CONVERGENCE_[A-Z0-9_]+|MIN_CONVERGENCE_[A-Z0-9_]+|IDLE_CONVERGENCE_[A-Z0-9_]+)"
discover_constants "crates/marmot-app/src/client/epoch_stall.rs" "EPOCH_STALL_[A-Z0-9_]+"
discover_constants \
    "crates/marmot-app/src/lib.rs" \
    "(APP_RUNTIME_RELAY_REBUILD_LOOKBACK|TRANSPORT_CURSOR_MAX_FUTURE_SKEW)"

if [[ "$fail" -ne 0 ]]; then
    exit 1
fi

declaration_count=$((${#inventory_pairs[@]} - 1))
echo "convergence constant ledger gate: ${#expected_ids[@]} ids, ${declaration_count} declarations"
