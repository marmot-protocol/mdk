#!/bin/sh
set -eu

readonly discovery_relay="${WN_DEMO_DISCOVERY_RELAY:-wss://relay.fips.whitenoise.chat}"
readonly fips_relay_npub="${WN_DEMO_FIPS_RELAY_NPUB:-npub1pq5w2qtanuqfu6xctrqvz6jz5adwa0qyr3wvkfw2xy6yv7fneytq49daxg}"
readonly fips_endpoint="fips://${fips_relay_npub}"
readonly fips_control_socket="${WN_DEMO_FIPS_CONTROL_SOCKET:-/run/fips/control.sock}"
readonly fips_api_socket="${WN_FIPS_SOCKET:-/run/fips/api.sock}"
readonly demo_home="${WN_DEMO_HOME:-/var/lib/mdk/fips-tui-demo}"
readonly demo_socket="${WN_DEMO_SOCKET:-/run/mdk/fips-tui-demo.sock}"

fail() {
  printf 'FIPS TUI demo setup failed: %s\n' "$1" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command is unavailable: $1"
}

wn_json() {
  WN_FIPS_SOCKET="$fips_api_socket" \
    WN_SECRET_STORE=file \
    wn --home "$demo_home" --socket "$demo_socket" --secret-store file --json "$@"
}

wn_local_json() {
  WN_FIPS_SOCKET="$fips_api_socket" \
    WN_SECRET_STORE=file \
    wn --home "$demo_home" --secret-store file --json "$@"
}

require_ok() {
  frame=$1
  context=$2
  printf '%s\n' "$frame" | jq -e '.ok == true' >/dev/null || {
    printf '%s\n' "$frame" >&2
    fail "$context"
  }
}

daemon_running() {
  status=$(wn_json daemon status 2>/dev/null || true)
  printf '%s\n' "$status" | jq -e '.ok == true and .result.running == true' >/dev/null 2>&1
}

stop_daemon() {
  if daemon_running; then
    stop=$(wn_json daemon stop)
    require_ok "$stop" "could not stop the existing demo daemon"
  fi
}

account_npub() {
  accounts=$(wn_local_json accounts list)
  require_ok "$accounts" "could not inspect demo accounts"
  count=$(printf '%s\n' "$accounts" | jq -er '.result.accounts | length')
  case "$count" in
    0)
      created=$(wn_local_json --relay "$discovery_relay" create-identity)
      require_ok "$created" "could not create the demo identity through WebSocket discovery"
      printf '%s\n' "$created" | jq -er '.result.npub'
      ;;
    1)
      printf '%s\n' "$accounts" | jq -er '.result.accounts[0].npub'
      ;;
    *)
      fail "the demo home contains more than one account; use an isolated WN_DEMO_HOME"
      ;;
  esac
}

configure_fips_inbox() {
  npub=$1
  current=$(wn_local_json --account "$npub" relays list --type inbox)
  require_ok "$current" "could not inspect the cached inbox relay list"
  if printf '%s\n' "$current" | jq -e --arg relay "$fips_endpoint" \
    '.result.relays == [$relay]' >/dev/null; then
    return
  fi

  # Nostr replaceable events use second-resolution timestamps. Ensure this
  # FIPS-only kind-10050 supersedes account bootstrap publication.
  sleep 2
  updated=$(wn_local_json --relay "$discovery_relay" --account "$npub" \
    relays set "$fips_endpoint" --type inbox)
  require_ok "$updated" "could not publish the FIPS-only inbox relay list"
  printf '%s\n' "$updated" | jq -e --arg relay "$fips_endpoint" \
    '.result.relays == [$relay]' >/dev/null || \
    fail "the published inbox relay list is not FIPS-only"
}

start_daemon() {
  if daemon_running; then
    return
  fi
  started=$(wn_json --relay "$fips_endpoint" daemon start \
    --discovery-relays "$discovery_relay" \
    --default-account-relays "$discovery_relay")
  require_ok "$started" "could not start wnd with hybrid relay configuration"
}

wait_for_fips_ready() {
  attempts=0
  while [ "$attempts" -lt 60 ]; do
    stats=$(wn_json relay-stats)
    require_ok "$stats" "could not read relay telemetry"
    if printf '%s\n' "$stats" | jq -e \
      '.result.fips.enabled == true and
       .result.fips.connected_endpoints > 0 and
       .result.fips.reconnecting_endpoints == 0' >/dev/null; then
      return
    fi
    attempts=$((attempts + 1))
    sleep 1
  done
  fail "native FIPS did not become ready within 60 seconds; inspect wn relay-stats and the FIPS peer"
}

prepare() {
  require_command fipsctl
  require_command jq
  require_command wn
  [ -S "$fips_control_socket" ] || fail "FIPS control socket is missing: $fips_control_socket"
  [ -S "$fips_api_socket" ] || fail "FIPS native API socket is missing: $fips_api_socket"
  peers=$(fipsctl --socket "$fips_control_socket" show peers)
  printf '%s\n' "$peers" | jq -e --arg npub "$fips_relay_npub" \
    '.peers[]? | select(.npub == $npub and .connectivity == "connected")' >/dev/null || \
    fail "the demo relay peer is not connected in the local FIPS peer table"

  install -d -m 0700 "$demo_home" "$(dirname "$demo_socket")"
  npub=$(account_npub)

  # Mutating a published relay list while a daemon owns the home would race
  # its hosted runtime. Stop only when setup is incomplete; normal reruns keep
  # the long-lived daemon and FIPS flow intact.
  current=$(wn_json --account "$npub" relays list --type inbox 2>/dev/null || true)
  if ! printf '%s\n' "$current" | jq -e --arg relay "$fips_endpoint" \
    '.ok == true and .result.relays == [$relay]' >/dev/null 2>&1; then
    stop_daemon
    configure_fips_inbox "$npub"
  fi

  start_daemon
  wait_for_fips_ready

  printf '\nLinux FIPS TUI client is ready.\n'
  printf 'Account npub: %s\n' "$npub"
  printf 'Discovery relay: %s\n' "$discovery_relay"
  printf 'Delivery relay: %s\n' "$fips_endpoint"
  printf 'When the Mac creates the group, press I and then Enter to accept the invite.\n\n'
}

usage() {
  printf 'usage: mdk-fips-tui-demo [prepare|run|status]\n' >&2
  exit 2
}

mode=${1:-run}
case "$mode" in
  prepare)
    prepare
    ;;
  run)
    prepare
    exec env \
      WN_FIPS_SOCKET="$fips_api_socket" \
      WN_SECRET_STORE=file \
      wn --home "$demo_home" --socket "$demo_socket" --secret-store file tui \
        --discovery-relays "$discovery_relay" \
        --default-account-relays "$discovery_relay"
    ;;
  status)
    wn_json daemon status
    wn_json relay-stats
    ;;
  *)
    usage
    ;;
esac
