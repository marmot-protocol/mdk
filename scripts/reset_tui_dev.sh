#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

HOME_ARG="dev/data"
DATA_DIR="$ROOT_DIR/$HOME_ARG"
DM_BIN="$ROOT_DIR/target/debug/dm"
RELAYS="${DARKMATTER_TUI_DEV_RELAYS:-ws://127.0.0.1:28080,ws://127.0.0.1:27777}"

require_command() {
    local command_name=$1
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "error: required command not found: $command_name" >&2
        exit 127
    fi
}

require_docker_compose() {
    require_command docker
    if ! docker compose version >/dev/null 2>&1; then
        echo "error: docker is installed, but the Docker Compose plugin is not available" >&2
        echo "install Docker Compose or use a Docker Desktop version that includes 'docker compose'" >&2
        exit 127
    fi
}

run_json() {
    local output
    if ! output="$("$@" 2>&1)"; then
        echo "error: command failed: $*" >&2
        echo "$output" >&2
        exit 1
    fi
    printf '%s\n' "$output"
}

json_result_field() {
    local field=$1
    jq -er ".result.${field}"
}

stop_daemon_if_running() {
    if [ -x "$DM_BIN" ]; then
        "$DM_BIN" --home "$HOME_ARG" --json daemon stop >/dev/null 2>&1 || true
    fi

    local pid_file="$DATA_DIR/dev/dmd.pid"
    if [ -f "$pid_file" ]; then
        local pid
        pid="$(tr -d '[:space:]' < "$pid_file")"
        if [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1; then
            local command_name
            command_name="$(ps -p "$pid" -o comm= 2>/dev/null || true)"
            if grep -q 'dmd' <<< "$command_name"; then
                kill "$pid" >/dev/null 2>&1 || true
                for _ in {1..30}; do
                    if ! kill -0 "$pid" >/dev/null 2>&1; then
                        break
                    fi
                    sleep 0.1
                done
                if kill -0 "$pid" >/dev/null 2>&1; then
                    kill -9 "$pid" >/dev/null 2>&1 || true
                fi
            fi
        fi
    fi
}

assert_relay_lists_complete() {
    local account=$1
    local name=$2
    local status
    status="$(run_json "$DM_BIN" --home "$HOME_ARG" --account "$account" --json accounts status "$account")"
    if ! jq -e '.result.relay_lists.complete == true' >/dev/null <<< "$status"; then
        echo "error: $name relay lists are not complete" >&2
        jq '.result.relay_lists' <<< "$status" >&2
        exit 1
    fi
}

start_daemon() {
    run_json \
        "$DM_BIN" \
        --home "$HOME_ARG" \
        --secret-store file \
        --json \
        daemon start \
        --discovery-relays "$RELAYS" \
        --default-account-relays "$RELAYS"
}

require_daemon_running() {
    local status
    for _ in {1..30}; do
        status="$(run_json "$DM_BIN" --home "$HOME_ARG" --json daemon status)"
        if jq -e '.ok == true and .result.running == true' >/dev/null <<< "$status"; then
            return 0
        fi
        sleep 0.1
    done

    echo "error: daemon is not running" >&2
    echo "$status" >&2
    exit 1
}

ensure_daemon_running() {
    local status
    status="$(run_json "$DM_BIN" --home "$HOME_ARG" --json daemon status)"
    if jq -e '.ok == true and .result.running == true' >/dev/null <<< "$status"; then
        return 0
    fi

    start_daemon >/dev/null
    require_daemon_running
}

echo "==> stopping local daemon"
require_command jq
require_command curl
stop_daemon_if_running

echo "==> stopping local compose services"
require_docker_compose
docker compose down -v --remove-orphans

echo "==> deleting $HOME_ARG"
rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR"

echo "==> rebuilding dm and dmd"
require_command cargo
cargo build -p darkmatter-cli --bins

echo "==> starting local relays"
docker compose up -d setup nostr-rs-relay strfry-nostr-relay
DARKMATTER_E2E_RELAYS="$RELAYS" ./scripts/wait_for_relays.sh

echo "==> starting daemon"
daemon_start="$(start_daemon)"
if ! jq -e '.ok == true and .result.running == true' >/dev/null <<< "$daemon_start"; then
    echo "error: daemon did not start cleanly" >&2
    echo "$daemon_start" >&2
    exit 1
fi

echo "==> creating Alice"
alice_json="$(run_json "$DM_BIN" --home "$HOME_ARG" --json create-identity)"
ALICE_ACCOUNT_ID="$(json_result_field account_id <<< "$alice_json")"
ALICE_NPUB="$(json_result_field npub <<< "$alice_json")"
run_json \
    "$DM_BIN" \
    --home "$HOME_ARG" \
    --account "$ALICE_ACCOUNT_ID" \
    --json \
    profile update \
    --name Alice \
    --display-name Alice >/dev/null

echo "==> creating Bob"
bob_json="$(run_json "$DM_BIN" --home "$HOME_ARG" --json create-identity)"
BOB_ACCOUNT_ID="$(json_result_field account_id <<< "$bob_json")"
BOB_NPUB="$(json_result_field npub <<< "$bob_json")"
run_json \
    "$DM_BIN" \
    --home "$HOME_ARG" \
    --account "$BOB_ACCOUNT_ID" \
    --json \
    profile update \
    --name Bob \
    --display-name Bob >/dev/null

echo "==> verifying account setup"
assert_relay_lists_complete "$ALICE_ACCOUNT_ID" "Alice"
assert_relay_lists_complete "$BOB_ACCOUNT_ID" "Bob"
run_json "$DM_BIN" --home "$HOME_ARG" --account "$ALICE_ACCOUNT_ID" --json keys fetch "$BOB_ACCOUNT_ID" >/dev/null
run_json "$DM_BIN" --home "$HOME_ARG" --account "$BOB_ACCOUNT_ID" --json keys fetch "$ALICE_ACCOUNT_ID" >/dev/null

echo "==> ensuring daemon is running for TUI handoff"
ensure_daemon_running

cat <<EOF

Local TUI daemon test setup is ready.

Alice pubkey:     $ALICE_ACCOUNT_ID
Alice npub:       $ALICE_NPUB

Bob pubkey:       $BOB_ACCOUNT_ID
Bob npub:         $BOB_NPUB

Open TUIs:
  target/debug/dm --home "$HOME_ARG" --account "$ALICE_ACCOUNT_ID" tui
  target/debug/dm --home "$HOME_ARG" --account "$BOB_ACCOUNT_ID" tui

Relay logs:
  just relay-logs
EOF
