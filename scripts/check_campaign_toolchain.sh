#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

toolchain="$(sed -n 's/^channel = "\(.*\)"/\1/p' rust-toolchain.toml)"
if [[ -z "$toolchain" ]]; then
    echo 'error: rust-toolchain.toml does not declare a channel' >&2
    exit 1
fi

builder_line="$(sed -n '/^FROM rust:.* AS builder$/p' Dockerfile.convergence-campaign)"
if [[ ! "$builder_line" =~ ^FROM\ rust:([^@]+)@sha256:[0-9a-f]{64}\ AS\ builder$ ]]; then
    echo 'error: campaign builder must use a digest-pinned rust image' >&2
    exit 1
fi

expected_tag="${toolchain}-bookworm"
actual_tag="${BASH_REMATCH[1]}"
if [[ "$actual_tag" != "$expected_tag" ]]; then
    echo "error: campaign builder uses rust:${actual_tag}; expected rust:${expected_tag}" >&2
    exit 1
fi

if ! grep -Fqx 'COPY Cargo.toml Cargo.lock rust-toolchain.toml ./' Dockerfile.convergence-campaign; then
    echo 'error: campaign builder must copy rust-toolchain.toml with workspace manifests' >&2
    exit 1
fi

echo "campaign toolchain gate: rust ${toolchain}"
