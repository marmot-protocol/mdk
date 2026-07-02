set shell := ["bash", "-cu"]

otlp-features := "marmot-app/otlp-export,marmot-uniffi/otlp-export,darkmatter-cli/otlp-export"

default:
    @just --list

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all --check

build: build-default build-otlp

build-default:
    cargo build --workspace --all-targets

build-otlp:
    cargo build --workspace --all-targets --features {{otlp-features}}

check: check-default check-otlp

check-default:
    RUSTFLAGS='-D warnings' cargo check --workspace --all-targets

check-otlp:
    RUSTFLAGS='-D warnings' cargo check --workspace --all-targets --features {{otlp-features}}

clippy: clippy-default clippy-otlp

clippy-default:
    cargo clippy --workspace --all-targets -- -D warnings

clippy-otlp:
    cargo clippy --workspace --all-targets --features {{otlp-features}} -- -D warnings

test: test-default test-otlp

test-default:
    cargo nextest run --workspace
    cargo test --workspace --doc

test-otlp:
    cargo nextest run --workspace --features {{otlp-features}}

relay-up:
    docker compose up -d
    ./scripts/wait_for_relays.sh

relay-smoke:
    ./scripts/wait_for_relays.sh

relay-down:
    docker compose down -v

relay-logs:
    docker compose logs -f

tui-reset:
    ./scripts/reset_tui_dev.sh

hermes-dev-setup args="":
    ./scripts/hermes_marmot_dev_setup.sh {{args}}

hermes-dev-teardown args="":
    ./scripts/hermes_marmot_dev_teardown.sh {{args}}

hermes-dev-script-test:
    integrations/hermes/marmot/tests/test_dev_scripts.sh

release-dm-agent version:
    ./scripts/cut-dm-agent-release.sh {{version}}

release-dm-agent-dry-run version:
    ./scripts/cut-dm-agent-release.sh --dry-run {{version}}

hermes-bootstrap-test:
    PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s integrations/hermes/marmot/tests -p 'test_bootstrap_agent.py'

hermes-phone-test-up:
    docker compose --profile hermes-phone-test up -d --build hermes-marmot-phone-test

hermes-phone-test-bootstrap:
    docker compose exec hermes-marmot-phone-test dm-agent bootstrap --qr --home /data/marmot-agent --socket /run/marmot-agent/dm-agent.sock --auth-token-file /data/marmot-agent/control.token

hermes-phone-test-logs:
    docker compose logs -f hermes-marmot-phone-test

hermes-phone-test-down:
    docker compose --profile hermes-phone-test down

hermes-phone-test-reset:
    docker compose --profile hermes-phone-test down -v

hermes-dev-smoke root="":
    #!/usr/bin/env bash
    set -euo pipefail
    root="{{root}}"
    if [ -z "$root" ]; then
        root="${HERMES_MARMOT_DEV_ROOT:-${TMPDIR:-/tmp}/hermes-marmot-test}"
    fi
    "$root/smoke-plugin.sh"

hermes-dev-e2e-deterministic root="":
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -z "{{root}}" ]; then
        ./scripts/hermes_marmot_deterministic_e2e.sh
    else
        ./scripts/hermes_marmot_deterministic_e2e.sh --root "{{root}}"
    fi

hermes-dev-e2e-connector root="":
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -z "{{root}}" ]; then
        ./scripts/hermes_marmot_connector_e2e.sh
    else
        ./scripts/hermes_marmot_connector_e2e.sh --root "{{root}}"
    fi

openclaw-dev-setup args="":
    ./scripts/openclaw_marmot_dev_setup.sh {{args}}

openclaw-dev-teardown args="":
    ./scripts/openclaw_marmot_dev_teardown.sh {{args}}

openclaw-dev-test:
    cd integrations/openclaw/marmot && pnpm install && pnpm typecheck && pnpm test

openclaw-phone-test-up:
    docker compose --profile openclaw-phone-test up -d --build openclaw-marmot-phone-test

openclaw-phone-test-bootstrap:
    docker compose exec openclaw-marmot-phone-test dm-agent bootstrap --qr --home /data/marmot-agent --socket /run/marmot-agent/dm-agent.sock --auth-token-file /data/marmot-agent/control.token

openclaw-phone-test-logs:
    docker compose logs -f openclaw-marmot-phone-test

openclaw-phone-test-down:
    docker compose --profile openclaw-phone-test down

openclaw-phone-test-reset:
    docker compose --profile openclaw-phone-test down -v

openclaw-gateway-up:
    docker compose --profile openclaw-gateway up -d --build openclaw-gateway

openclaw-gateway-bootstrap:
    docker compose exec openclaw-gateway dm-agent bootstrap --qr --home /data/marmot-agent --socket /run/marmot-agent/dm-agent.sock --auth-token-file /data/marmot-agent/control.token

openclaw-gateway-logs:
    docker compose logs -f openclaw-gateway

openclaw-gateway-down:
    docker compose --profile openclaw-gateway down

openclaw-gateway-reset:
    docker compose --profile openclaw-gateway down -v

e2e-test test="":
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -z "{{test}}" ]; then
        DARKMATTER_E2E_REQUIRE_RELAYS=1 cargo nextest run -p darkmatter-cli --test cli -E 'test(=real_local_relays_deliver_cli_messages_over_sdk_path)'
    else
        DARKMATTER_E2E_REQUIRE_RELAYS=1 cargo nextest run -p darkmatter-cli --test cli "{{test}}"
    fi

conformance:
    cargo nextest run -p cgka-conformance-simulator
    cargo test -p cgka-conformance-simulator --doc

conformance-slow:
    cargo nextest run -p cgka-conformance-simulator --features conformance-slow

tracing-audit:
    cargo nextest run -p cgka-conformance-simulator --test tracing_audit

tamarin:
    @command -v tamarin-prover >/dev/null || { echo "error: tamarin-prover not found on PATH"; exit 127; }
    @make -C formal/tamarin prove

tamarin-interactive:
    @command -v tamarin-prover >/dev/null || { echo "error: tamarin-prover not found on PATH"; exit 127; }
    @make -C formal/tamarin interactive

policy-casegen:
    @cargo run -p cgka-conformance-simulator --bin cgka-policy-casegen -- --format tamarin formal/tamarin/policy_cases.json

coverage:
    just coverage-traits
    just coverage-storage
    just coverage-engine
    just coverage-conformance

coverage-html:
    cargo llvm-cov -p cgka-conformance-simulator --test canonical_scenarios --test proptest_invariants --test report_runner --ignore-filename-regex 'src/bin/' --html --open

coverage-traits:
    cargo llvm-cov -p cgka-traits --all-targets --summary-only

coverage-storage:
    cargo llvm-cov -p storage-sqlite --all-targets --summary-only

coverage-engine:
    cargo llvm-cov -p cgka-engine --all-targets --summary-only

coverage-conformance:
    cargo llvm-cov -p cgka-conformance-simulator --test canonical_scenarios --test proptest_invariants --test report_runner --ignore-filename-regex 'src/bin/' --summary-only

coverage-conformance-html:
    cargo llvm-cov -p cgka-conformance-simulator --test canonical_scenarios --test proptest_invariants --test report_runner --ignore-filename-regex 'src/bin/' --html --open

dead-code-audit:
    @rg -n '#\[allow\(([^]]*dead_code|dead_code)' crates docs plans Cargo.toml || true

# Fast local pre-push gate: mechanical/static checks only. GitHub CI runs the
# full `just ci` suite (including the workspace test matrix).
fast-ci: fmt-check check clippy

ci: fmt-check check clippy test
