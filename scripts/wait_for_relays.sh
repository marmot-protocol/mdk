#!/usr/bin/env bash
set -euo pipefail

DEFAULT_RELAY_URLS="ws://127.0.0.1:28080,ws://127.0.0.1:27777"
RELAY_URLS_CSV="${DARKMATTER_E2E_RELAYS:-$DEFAULT_RELAY_URLS}"
MAX_ATTEMPTS="${DARKMATTER_RELAY_WAIT_ATTEMPTS:-20}"
WAIT_INTERVAL="${DARKMATTER_RELAY_WAIT_INTERVAL:-0.5}"
CONNECTION_TIMEOUT="${DARKMATTER_RELAY_WAIT_TIMEOUT:-3}"

IFS=',' read -r -a RELAY_URLS <<< "$RELAY_URLS_CSV"

check_relay() {
    local relay_url=$1
    local attempts=0
    local http_url
    case "$relay_url" in
        wss://*) http_url="https://${relay_url#wss://}" ;;
        ws://*) http_url="http://${relay_url#ws://}" ;;
        *) http_url="$relay_url" ;;
    esac
    local websocket_key="dGhlIHNhbXBsZSBub25jZQ=="

    echo "Testing relay: $relay_url"

    while [ "$attempts" -lt "$MAX_ATTEMPTS" ]; do
        attempts=$((attempts + 1))

        local output
        output=$(curl -s -v \
            -H "Connection: Upgrade" \
            -H "Upgrade: websocket" \
            -H "Sec-WebSocket-Key: $websocket_key" \
            -H "Sec-WebSocket-Version: 13" \
            --max-time "$CONNECTION_TIMEOUT" \
            "$http_url" 2>&1 || true)

        if grep -q "HTTP/1.1 101 Switching Protocols" <<< "$output"; then
            echo "Relay $relay_url is ready (attempt $attempts)"
            return 0
        fi

        if [ "$attempts" -le 2 ] || [ $((attempts % 5)) -eq 0 ]; then
            echo "  Attempt $attempts/$MAX_ATTEMPTS: relay $relay_url not ready"
        fi

        sleep "$WAIT_INTERVAL"
    done

    echo "Relay $relay_url failed to become ready after $MAX_ATTEMPTS attempts" >&2
    return 1
}

echo "Waiting for local Nostr relays..."

pids=()
for relay_url in "${RELAY_URLS[@]}"; do
    relay_url=$(echo "$relay_url" | xargs)
    if [ -z "$relay_url" ]; then
        continue
    fi
    check_relay "$relay_url" &
    pids+=($!)
done

if [ "${#pids[@]}" -eq 0 ]; then
    echo "No relay URLs configured" >&2
    exit 1
fi

failed=false
for pid in "${pids[@]}"; do
    if ! wait "$pid"; then
        failed=true
    fi
done

if [ "$failed" = true ]; then
    echo "One or more relays failed to become ready" >&2
    exit 1
fi

echo "All relays are ready."
