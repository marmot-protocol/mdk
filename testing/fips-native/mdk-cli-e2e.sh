#!/usr/bin/env bash
set -euo pipefail

readonly discovery_relay="ws://127.0.0.1:7778"
readonly fips_endpoint="fips://npub1pq5w2qtanuqfu6xctrqvz6jz5adwa0qyr3wvkfw2xy6yv7fneytq49daxg"
readonly fips_socket="/run/fips/api.sock"
readonly alice_home="/var/lib/mdk/alice"
readonly bob_home="/var/lib/mdk/bob"
readonly alice_socket="/run/mdk/alice.sock"
readonly bob_socket="/run/mdk/bob.sock"
readonly alice_nsec="nsec1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqps52s3re"
readonly alice_npub="npub1lycg5qvjtrp3qjf5f7zl382j9x6nrjz9sdhenvyxq8c3808qxmus6gq266"
readonly bob_nsec="nsec1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqzqs9fwtq"
readonly bob_npub="npub1ujfahuwppkq0xkq7fyzfxzc5qnxxcyuspms8tpr5l222h6xye5fsccv64k"
readonly alice_text="hello over FIPS from Alice"
readonly bob_text="hello over FIPS from Bob"

alice_pid=""
bob_pid=""

cleanup() {
  for pid in "$alice_pid" "$bob_pid"; do
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
}
trap cleanup EXIT INT TERM

fail() {
  printf 'native FIPS MDK CLI test failed: %s\n' "$1" >&2
  for log in /run/mdk/alice.log /run/mdk/bob.log; do
    if [[ -f "$log" ]]; then
      printf '%s:\n' "$log" >&2
      tail -n 80 "$log" >&2
    fi
  done
  exit 1
}

require_ok() {
  local response=$1
  local context=$2
  jq -e '.ok == true' >/dev/null <<<"$response" || fail "$context"
}

wn_for() {
  local home=$1
  local socket=$2
  shift 2
  WN_FIPS_SOCKET="$fips_socket" \
    WN_ALLOW_LOOPBACK_RELAYS=1 \
    WN_SECRET_STORE=file \
    wn --home "$home" --socket "$socket" --secret-store file --json "$@"
}

wn_local() {
  local home=$1
  shift
  WN_FIPS_SOCKET="$fips_socket" \
    WN_ALLOW_LOOPBACK_RELAYS=1 \
    WN_SECRET_STORE=file \
    wn --home "$home" --secret-store file --json "$@"
}

start_daemon() {
  local home=$1
  local socket=$2
  local log=$3
  WN_FIPS_SOCKET="$fips_socket" \
    WN_ALLOW_LOOPBACK_RELAYS=1 \
    WN_SECRET_STORE=file \
    wnd \
      --home "$home" \
      --socket "$socket" \
      --secret-store file \
      --relay "$fips_endpoint" \
      --discovery-relays "$discovery_relay" \
      --default-account-relays "$discovery_relay" \
      >"$log" 2>&1 &
  printf '%s' "$!"
}

wait_for_socket() {
  local socket=$1
  local pid=$2
  for _ in $(seq 1 100); do
    [[ -S "$socket" ]] && return 0
    kill -0 "$pid" 2>/dev/null || return 1
    sleep 0.1
  done
  return 1
}

stop_daemon() {
  local home=$1
  local socket=$2
  local pid=$3
  wn_for "$home" "$socket" daemon stop >/dev/null 2>&1 || true
  for _ in $(seq 1 100); do
    kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.1
  done
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}

configure_fips_inbox() {
  local home=$1
  local npub=$2
  local response
  # Nostr replaceable events have one-second timestamp precision. Ensure the
  # final FIPS-only kind-10050 wins over the login publication.
  sleep 1
  response=$(wn_local "$home" --relay "$discovery_relay" --account "$npub" \
    relays set "$fips_endpoint" --type inbox)
  require_ok "$response" "set FIPS inbox relay"
  jq -e --arg endpoint "$fips_endpoint" \
    '.result.relays == [$endpoint]' >/dev/null <<<"$response" || fail "inbox is not FIPS-only"
}

wait_for_fips_ready() {
  local home=$1
  local socket=$2
  local response
  for _ in $(seq 1 60); do
    response=$(wn_for "$home" "$socket" relay-stats)
    require_ok "$response" "read FIPS relay telemetry"
    if jq -e \
      '.result.fips.enabled == true and .result.fips.connected_endpoints > 0 and .result.fips.reconnecting_endpoints == 0' \
      >/dev/null <<<"$response"; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

poll_for_invite() {
  local group_id=$1
  local response
  for _ in $(seq 1 60); do
    response=$(wn_for "$bob_home" "$bob_socket" --account "$bob_npub" groups invites)
    require_ok "$response" "list Bob invites"
    if jq -e --arg group "$group_id" \
      '.result.invites[]? | select(.group_id == $group)' >/dev/null <<<"$response"; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

poll_for_message() {
  local home=$1
  local socket=$2
  local npub=$3
  local group_id=$4
  local text=$5
  local response
  for _ in $(seq 1 60); do
    response=$(wn_for "$home" "$socket" --account "$npub" messages list "$group_id" --limit 50)
    require_ok "$response" "list received messages"
    if jq -e --arg text "$text" \
      '.result.messages[]? | select(.plaintext == $text)' >/dev/null <<<"$response"; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

install -d -m 0700 /run/mdk "$alice_home" "$bob_home"

alice_login=$(printf '%s\n' "$alice_nsec" | \
  wn_local "$alice_home" --relay "$discovery_relay" login --nsec-stdin)
bob_login=$(printf '%s\n' "$bob_nsec" | \
  wn_local "$bob_home" --relay "$discovery_relay" login --nsec-stdin)
require_ok "$alice_login" "Alice account setup"
require_ok "$bob_login" "Bob account setup"

configure_fips_inbox "$alice_home" "$alice_npub"
configure_fips_inbox "$bob_home" "$bob_npub"

# Refresh Bob's KeyPackage and directory metadata only after his kind-10050
# inbox list advertises the FIPS endpoint. The Welcome route is frozen from
# this selected KeyPackage view during group creation.
alice_fetch=$(wn_local "$alice_home" --relay "$discovery_relay" --account "$alice_npub" \
  keys fetch "$bob_npub" --bootstrap-relays "$discovery_relay")
require_ok "$alice_fetch" "Alice fetch Bob KeyPackage"
jq -e --arg endpoint "$fips_endpoint" \
  '.result.relay_lists.inbox.relays == [$endpoint]' >/dev/null <<<"$alice_fetch" || \
  fail "Alice did not discover Bob's FIPS-only inbox list"

alice_pid=$(start_daemon "$alice_home" "$alice_socket" /run/mdk/alice.log)
bob_pid=$(start_daemon "$bob_home" "$bob_socket" /run/mdk/bob.log)
wait_for_socket "$alice_socket" "$alice_pid" || fail "Alice daemon did not start"
wait_for_socket "$bob_socket" "$bob_pid" || fail "Bob daemon did not start"
wait_for_fips_ready "$alice_home" "$alice_socket" || fail "Alice FIPS backend did not become ready"
wait_for_fips_ready "$bob_home" "$bob_socket" || fail "Bob FIPS backend did not become ready"

create=$(wn_for "$alice_home" "$alice_socket" --account "$alice_npub" \
  groups create fips-demo "$bob_npub")
require_ok "$create" "create FIPS-routed group"
group_id=$(jq -er '.result.group_id' <<<"$create") || fail "group id missing"

alice_relays=$(wn_for "$alice_home" "$alice_socket" --account "$alice_npub" \
  groups relays "$group_id")
require_ok "$alice_relays" "read Alice group relays"
jq -e --arg endpoint "$fips_endpoint" \
  '.result.relays == [$endpoint]' >/dev/null <<<"$alice_relays" || fail "group route is not FIPS-only"

poll_for_invite "$group_id" || fail "Bob did not receive the FIPS Welcome"
accept=$(wn_for "$bob_home" "$bob_socket" --account "$bob_npub" groups accept "$group_id")
require_ok "$accept" "Bob accept invite"

bob_relays=$(wn_for "$bob_home" "$bob_socket" --account "$bob_npub" groups relays "$group_id")
require_ok "$bob_relays" "read Bob group relays"
jq -e --arg endpoint "$fips_endpoint" \
  '.result.relays == [$endpoint]' >/dev/null <<<"$bob_relays" || fail "joined group route is not FIPS-only"

alice_send=$(wn_for "$alice_home" "$alice_socket" --account "$alice_npub" \
  messages send "$group_id" "$alice_text")
require_ok "$alice_send" "Alice send"
jq -e '.result.published > 0' >/dev/null <<<"$alice_send" || fail "Alice send was not published"
poll_for_message "$bob_home" "$bob_socket" "$bob_npub" "$group_id" "$alice_text" || \
  fail "Bob did not receive Alice's message"

bob_send=$(wn_for "$bob_home" "$bob_socket" --account "$bob_npub" \
  messages send "$group_id" "$bob_text")
require_ok "$bob_send" "Bob send"
jq -e '.result.published > 0' >/dev/null <<<"$bob_send" || fail "Bob send was not published"
poll_for_message "$alice_home" "$alice_socket" "$alice_npub" "$group_id" "$bob_text" || \
  fail "Alice did not receive Bob's message"

printf 'native FIPS MDK CLI end-to-end test passed\n'
