#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

toolchain="$(sed -n 's/^channel = "\(.*\)"/\1/p' rust-toolchain.toml)"
if [[ -z "$toolchain" ]]; then
    echo 'error: rust-toolchain.toml does not declare a channel' >&2
    exit 1
fi

expected_tag="${toolchain}-bookworm"

check_builder_image() {
    local label="$1"
    local dockerfile="$2"
    local builder_line actual_tag

    builder_line="$(sed -n '/^FROM rust:.* AS builder$/p' "$dockerfile")"
    if [[ ! "$builder_line" =~ ^FROM\ rust:([^@]+)@sha256:[0-9a-f]{64}\ AS\ builder$ ]]; then
        echo "error: ${label} builder must use a digest-pinned rust image" >&2
        exit 1
    fi

    actual_tag="${BASH_REMATCH[1]}"
    if [[ "$actual_tag" != "$expected_tag" ]]; then
        echo "error: ${label} builder uses rust:${actual_tag}; expected rust:${expected_tag}" >&2
        exit 1
    fi
}

check_base_image_digests() {
    local label="$1"
    local dockerfile="$2"
    local from_line

    while IFS= read -r from_line; do
        if [[ ! "$from_line" =~ ^FROM\ [^[:space:]@]+@sha256:[0-9a-f]{64}(\ AS\ [A-Za-z0-9_-]+)?$ ]]; then
            echo "error: ${label} base images must be digest-pinned: ${from_line}" >&2
            exit 1
        fi
    done < <(sed -n '/^FROM /p' "$dockerfile")
}

check_builder_image 'campaign' Dockerfile.convergence-campaign
check_base_image_digests 'campaign' Dockerfile.convergence-campaign

check_copy_coverage() {
    local label="$1"
    local dockerfile="$2"
    local copy_line

    for copy_line in \
        'COPY Cargo.toml Cargo.lock rust-toolchain.toml ./' \
        'COPY .cargo ./.cargo' \
        'COPY crates ./crates' \
        'COPY integrations ./integrations'; do
        if ! grep -Fqx "$copy_line" "$dockerfile"; then
            echo "error: ${label} builder is missing required source coverage: ${copy_line}" >&2
            exit 1
        fi
    done
}

check_copy_coverage 'campaign' Dockerfile.convergence-campaign

if grep -Fq 'RUSTUP_TOOLCHAIN=' Dockerfile.convergence-campaign; then
    echo 'error: release images must use rust-toolchain.toml instead of a fixed RUSTUP_TOOLCHAIN override' >&2
    exit 1
fi

if ! grep -Fq 'snapshot.debian.org/archive/debian/%s bookworm main' Dockerfile.convergence-campaign; then
    echo 'error: campaign runtime packages must use the dated Debian snapshot' >&2
    exit 1
fi

echo "campaign toolchain gate: rust ${toolchain}"
