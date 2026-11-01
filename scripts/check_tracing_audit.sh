#!/usr/bin/env bash
set -euo pipefail

# Runs the repo-wide tracing and direct-output source audit
# (crates/cgka-conformance-simulator/tests/tracing_audit.rs) without building
# the simulator crate. The audit reads source files with std alone, so rustc
# builds it in seconds and the pull-request pre-check runs it this way.
# `cargo nextest run -p cgka-conformance-simulator --test tracing_audit` runs
# the same tests. Arguments go to the test binary, for example a test name.

cd "$(dirname "${BASH_SOURCE[0]}")/.."

crate=crates/cgka-conformance-simulator
edition="$(sed -n 's/^edition = "\(.*\)"/\1/p' Cargo.toml)"
out=target/tracing-audit
mkdir -p "$out"
# The audit finds the workspace root from env!("CARGO_MANIFEST_DIR"), which
# cargo would set for the simulator crate.
CARGO_MANIFEST_DIR="$PWD/$crate" rustc --edition "$edition" --test \
    -o "$out/tracing_audit" "$crate/tests/tracing_audit.rs"
"$out/tracing_audit" "$@"
