set shell := ["bash", "-cu"]

default:
    @just --list

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all --check

check:
    RUSTFLAGS='-D warnings' cargo check --workspace --all-targets

clippy:
    cargo clippy --workspace --all-targets -- -D warnings

test:
    cargo test --workspace

conformance:
    cargo test -p cgka-conformance

conformance-slow:
    cargo test -p cgka-conformance --features conformance-slow

tamarin:
    @command -v tamarin-prover >/dev/null || { echo "error: tamarin-prover not found on PATH"; exit 127; }
    @make -C formal/tamarin prove

tamarin-interactive:
    @command -v tamarin-prover >/dev/null || { echo "error: tamarin-prover not found on PATH"; exit 127; }
    @make -C formal/tamarin interactive

policy-casegen:
    @cargo run -p cgka-conformance --bin cgka-policy-casegen -- --format tamarin formal/tamarin/policy_cases.json

coverage:
    just coverage-traits
    just coverage-storage
    just coverage-engine
    just coverage-conformance

coverage-html:
    cargo llvm-cov -p cgka-conformance --test canonical_scenarios --test proptest_invariants --test report_runner --ignore-filename-regex 'src/bin/' --html --open

coverage-traits:
    cargo llvm-cov -p cgka-traits --all-targets --summary-only

coverage-storage:
    cargo llvm-cov -p storage-memory --all-targets --summary-only

coverage-engine:
    cargo llvm-cov -p cgka-engine --all-targets --summary-only

coverage-conformance:
    cargo llvm-cov -p cgka-conformance --test canonical_scenarios --test proptest_invariants --test report_runner --ignore-filename-regex 'src/bin/' --summary-only

coverage-conformance-html:
    cargo llvm-cov -p cgka-conformance --test canonical_scenarios --test proptest_invariants --test report_runner --ignore-filename-regex 'src/bin/' --html --open

dead-code-audit:
    @rg -n '#\[allow\(([^]]*dead_code|dead_code)' crates docs plans Cargo.toml || true

dead-code-audit-all:
    @rg -n '#\[allow\(([^]]*dead_code|dead_code)' crates spike docs plans Cargo.toml || true

ci: fmt-check check clippy test
