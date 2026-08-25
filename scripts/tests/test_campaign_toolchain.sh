#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmp_root="$(mktemp -d)"
trap 'rm -rf "$tmp_root"' EXIT

mkdir -p "$tmp_root/scripts"
cp "$repo_root/scripts/check_campaign_toolchain.sh" "$tmp_root/scripts/"
cp "$repo_root/rust-toolchain.toml" "$tmp_root/"
cp "$repo_root/Dockerfile.convergence-campaign" "$tmp_root/"
cp "$repo_root/Dockerfile.quic-broker" "$tmp_root/"

"$tmp_root/scripts/check_campaign_toolchain.sh" >/dev/null

expect_failure() {
    local expected_message="$1"
    shift
    local output
    if output="$("$@" 2>&1)"; then
        echo "expected toolchain gate failure: $expected_message" >&2
        exit 1
    fi
    if [[ "$output" != *"$expected_message"* ]]; then
        echo "toolchain gate failed without expected message: $expected_message" >&2
        printf '%s\n' "$output" >&2
        exit 1
    fi
}

cp "$tmp_root/Dockerfile.quic-broker" "$tmp_root/Dockerfile.quic-broker.clean"
sed -i 's/rust:1\.97\.1-bookworm/rust:1.96.0-bookworm/' "$tmp_root/Dockerfile.quic-broker"
expect_failure 'quic broker builder uses rust:1.96.0-bookworm; expected rust:1.97.1-bookworm' \
    "$tmp_root/scripts/check_campaign_toolchain.sh"

cp "$tmp_root/Dockerfile.quic-broker.clean" "$tmp_root/Dockerfile.quic-broker"
sed -i 's/@sha256:[0-9a-f]\{64\} AS builder/ AS builder/' "$tmp_root/Dockerfile.quic-broker"
expect_failure 'quic broker builder must use a digest-pinned rust image' \
    "$tmp_root/scripts/check_campaign_toolchain.sh"

cp "$tmp_root/Dockerfile.quic-broker.clean" "$tmp_root/Dockerfile.quic-broker"
sed -i 's/@sha256:[0-9a-f]\{64\}$/@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/' \
    "$tmp_root/Dockerfile.quic-broker"
expect_failure 'quic broker runtime pin must match the campaign runtime pin' \
    "$tmp_root/scripts/check_campaign_toolchain.sh"

echo 'campaign toolchain gate tests: pass'
