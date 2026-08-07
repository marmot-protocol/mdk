set shell := ["bash", "-cu"]

otlp-features := "marmot-app/otlp-export,marmot-uniffi/otlp-export,wn-cli/otlp-export"
test-features := "wn-cli/test-policy-overrides,cgka-engine/test-crash-hooks"
simulator-dedicated-filter := "not binary(adversarial_reliability_campaigns) and not binary(policy_sweeps) and not binary(independent_reference_model) and not binary(lifecycle_model) and not binary(mutation_adequacy) and not binary(protocol_decision_gate)"
simulator-smoke-filter := simulator-dedicated-filter + " and not (binary(canonical_scenarios) & (test(=convergence_chaos_family_generates_specs_with_semantic_expectations) | test(=convergence_chaos_family_seed_changes_scenarios) | test(=convergence_e2e_delivery_family_runs_generated_variants)))"

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
    cargo nextest run --workspace --features {{test-features}}
    cargo test --workspace --doc

test-otlp:
    cargo nextest run --workspace --features {{otlp-features}},{{test-features}}

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

# Open the dev TUI as a `just tui-reset` account, by display name or npub/hex.
tui name="Alice":
    #!/usr/bin/env bash
    set -euo pipefail
    selector="$(target/debug/wn --home dev/data --json account list \
        | jq -r --arg name "{{name}}" \
            'first(.result.accounts[] | select((.display_name // .profile.display_name // .profile.name // "") == $name) | .account_id) // $name')"
    exec target/debug/wn --home dev/data --account "$selector" tui

# TUI on production relays in a disposable home. Rebuilds, restarts the drive daemon on the fresh
# build with these relays, then opens the TUI; `c` creates the account on first run.
tui-prod relays="wss://relay.eu.whitenoise.chat,wss://relay.us.whitenoise.chat":
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build -p wn-cli --bins
    if target/debug/wn --home ~/.wn-tui-drive --json daemon status | jq -e '.result.running == true' >/dev/null; then
        target/debug/wn --home ~/.wn-tui-drive daemon stop
    fi
    target/debug/wn --home ~/.wn-tui-drive --secret-store file daemon start \
        --discovery-relays "{{relays}},wss://purplepag.es" \
        --default-account-relays "{{relays}}"
    exec target/debug/wn --home ~/.wn-tui-drive --secret-store file tui \
        --discovery-relays "{{relays}},wss://purplepag.es" \
        --default-account-relays "{{relays}}"

hermes-dev-setup args="":
    ./scripts/hermes_marmot_dev_setup.sh {{args}}

hermes-dev-teardown args="":
    ./scripts/hermes_marmot_dev_teardown.sh {{args}}

hermes-dev-script-test:
    integrations/hermes/marmot/tests/test_dev_scripts.sh

[positional-arguments]
hermes-verify-persisted-config root="":
    ./scripts/hermes_marmot_verify_persisted_config.sh {{ if root == "" { "" } else { "--root \"$1\"" } }}

release-all version:
    ./scripts/cut-full-release.sh {{version}}

release-all-draft version:
    ./scripts/cut-full-release.sh --draft {{version}}

release-all-dry-run version:
    ./scripts/cut-full-release.sh --dry-run {{version}}

release-wn-agent version:
    ./scripts/cut-wn-agent-release.sh {{version}}

release-wn-agent-dry-run version:
    ./scripts/cut-wn-agent-release.sh --dry-run {{version}}

hermes-bootstrap-test:
    PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s integrations/hermes/marmot/tests -p 'test_bootstrap_agent.py'

hermes-phone-test-up:
    docker compose --profile hermes-phone-test up -d --build hermes-marmot-phone-test

hermes-phone-test-bootstrap:
    docker compose exec hermes-marmot-phone-test wn-agent bootstrap --qr --home /data/marmot-agent --socket /run/marmot-agent/wn-agent.sock --auth-token-file /data/marmot-agent/control.token

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

openclaw-dev-script-test:
    integrations/openclaw/marmot/test/dev-scripts.sh

opencode-installer-test:
    integrations/opencode/marmot/tests/test_installer.sh

opencode-dev-e2e-connector:
    cargo test -p wn-opencode --test e2e_connector -- --ignored --nocapture

pi-installer-test:
    integrations/pi/marmot/tests/test_installer.sh

pi-dev-e2e-connector:
    cargo test -p wn-pi --test e2e_connector -- --ignored --nocapture

openclaw-dev-smoke root="":
    #!/usr/bin/env bash
    set -euo pipefail
    root="{{root}}"
    if [ -z "$root" ]; then
        root="${OPENCLAW_MARMOT_DEV_ROOT:-${TMPDIR:-/tmp}/openclaw-marmot-test}"
    fi
    "$root/smoke-plugin.sh"

openclaw-dev-control-smoke root="":
    #!/usr/bin/env bash
    set -euo pipefail
    root="{{root}}"
    if [ -z "$root" ]; then
        root="${OPENCLAW_MARMOT_DEV_ROOT:-${TMPDIR:-/tmp}/openclaw-marmot-test}"
    fi
    "$root/control-smoketest.sh"

openclaw-dev-e2e-connector root="":
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -z "{{root}}" ]; then
        ./scripts/openclaw_marmot_connector_e2e.sh
    else
        ./scripts/openclaw_marmot_connector_e2e.sh --root "{{root}}"
    fi

openclaw-phone-test-up:
    docker compose --profile openclaw-phone-test up -d --build openclaw-marmot-phone-test

openclaw-phone-test-bootstrap:
    docker compose exec openclaw-marmot-phone-test wn-agent bootstrap --qr --home /data/marmot-agent --socket /run/marmot-agent/wn-agent.sock --auth-token-file /data/marmot-agent/control.token

openclaw-phone-test-logs:
    docker compose logs -f openclaw-marmot-phone-test

openclaw-phone-test-down:
    docker compose --profile openclaw-phone-test down

openclaw-phone-test-reset:
    docker compose --profile openclaw-phone-test down -v

openclaw-gateway-up:
    docker compose --profile openclaw-gateway up -d --build openclaw-gateway

openclaw-gateway-bootstrap:
    docker compose exec openclaw-gateway wn-agent bootstrap --qr --home /data/marmot-agent --socket /run/marmot-agent/wn-agent.sock --auth-token-file /data/marmot-agent/control.token

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
        MDK_E2E_REQUIRE_RELAYS=1 cargo nextest run -p wn-cli --test cli --features test-policy-overrides -E 'test(=real_local_relays_deliver_cli_messages_over_sdk_path)'
    else
        MDK_E2E_REQUIRE_RELAYS=1 cargo nextest run -p wn-cli --test cli --features test-policy-overrides "{{test}}"
    fi

conformance:
    cargo nextest run -p cgka-conformance-simulator
    cargo test -p cgka-conformance-simulator --doc

conformance-slow:
    cargo nextest run -p cgka-conformance-simulator --features conformance-slow

# Fast PR feedback: ordinary simulator coverage without dedicated verification
# binaries or the generated multi-minute reliability batches.
simulator-smoke:
    cargo nextest run -p cgka-conformance-simulator --locked --profile ci -E '{{simulator-smoke-filter}}'

# Complete generic simulator coverage for the nightly lane. Dedicated
# adversarial and independent-verification binaries run in later recipes.
simulator-full: simulator-filter-contract
    cargo nextest run -p cgka-conformance-simulator --features conformance-slow --locked --profile ci -E '{{simulator-dedicated-filter}}'

# Prove that the generic nightly lane restores exactly the generated batches
# intentionally removed from the PR smoke lane.
simulator-filter-contract:
    #!/usr/bin/env bash
    set -euo pipefail
    work_dir="$(mktemp -d)"
    trap 'rm -rf "$work_dir"' EXIT
    list_tests() {
        jq -r '."rust-suites" | to_entries[] | .key as $suite | .value.testcases | to_entries[] | select(.value["filter-match"].status == "matches") | "\($suite)::\(.key)"' | sort
    }
    cargo nextest list -p cgka-conformance-simulator --features conformance-slow --locked --profile ci \
        -E '{{simulator-dedicated-filter}}' --message-format json | list_tests >"$work_dir/full"
    cargo nextest list -p cgka-conformance-simulator --locked --profile ci \
        -E '{{simulator-smoke-filter}}' --message-format json | list_tests >"$work_dir/smoke"
    comm -23 "$work_dir/full" "$work_dir/smoke" >"$work_dir/actual"
    printf '%s\n' \
        'cgka-conformance-simulator::canonical_scenarios::convergence_chaos_family_generates_specs_with_semantic_expectations' \
        'cgka-conformance-simulator::canonical_scenarios::convergence_chaos_family_seed_changes_scenarios' \
        'cgka-conformance-simulator::canonical_scenarios::convergence_e2e_delivery_family_runs_generated_variants' \
        >"$work_dir/expected"
    diff -u "$work_dir/expected" "$work_dir/actual"

# Full adversarial reliability gate: all catalog families, test-policy A/B,
# resource sweeps, sustained headline workloads, and the isolated process runner.
adversarial-reliability-ci:
    cargo nextest run -p cgka-conformance-simulator --features test-policy-overrides --test adversarial_reliability_campaigns --locked
    cargo test -p cgka-conformance-simulator --features test-policy-overrides --test adversarial_reliability_campaigns --locked -- --ignored
    cargo nextest run -p cgka-conformance-simulator --features test-policy-overrides --test policy_sweeps --locked
    cargo run -p cgka-conformance-simulator --features test-policy-overrides --bin cgka-conformance-campaign --locked -- --cases 1 --case-timeout-secs 300 --out target/cgka-adversarial-reliability-ci --storage file

# Independent convergence model, lifecycle/fairness, mutation adequacy, and
# protocol decision gates.
convergence-verification-ci:
    cargo nextest run -p cgka-conformance-simulator --test independent_reference_model --locked
    cargo nextest run -p cgka-conformance-simulator --test lifecycle_model --locked
    cargo nextest run -p cgka-conformance-simulator --test mutation_adequacy --locked
    cargo nextest run -p cgka-conformance-simulator --test protocol_decision_gate --locked
    just tla-liveness
    just tla-liveness-counterexample

# Validate the versioned execution-lane policy, all resource/retention/flake
# budgets, and the release evidence-bundle completeness contract.
convergence-lane-policy:
    cargo nextest run -p convergence-campaign-runner --test lane_policy --locked

# Capability-level entry points used by the scheduled workflows. PR checks
# remain split into separately named steps for useful failure attribution.
convergence-nightly-lane: convergence-lane-policy simulator-full adversarial-reliability-ci convergence-verification-ci
    cargo nextest run -p cgka-conformance-simulator --test process_orchestrator --locked
    cargo nextest run -p convergence-campaign-runner --locked

convergence-weekly-lane: convergence-nightly-lane
    cargo run -p cgka-conformance-simulator --features test-policy-overrides --bin cgka-conformance-campaign --locked -- --cases 4 --case-timeout-secs 300 --out target/cgka-weekly-reliability --storage file

# A release run must name a reviewed mixed-build manifest rather
# than silently falling back to a current-build-only campaign.
convergence-release-hardening-lane manifest:
    just convergence-weekly-lane
    cargo run -p convergence-campaign-runner --bin cgka-distributed-campaign --locked -- validate "{{manifest}}" --require-mixed-builds
    cargo run -p convergence-campaign-runner --bin cgka-distributed-campaign --locked -- run "{{manifest}}"

tracing-audit:
    cargo nextest run -p cgka-conformance-simulator --test tracing_audit

tamarin:
    @command -v tamarin-prover >/dev/null || { echo "error: tamarin-prover not found on PATH"; exit 127; }
    @make -C formal/tamarin prove

tamarin-interactive:
    @command -v tamarin-prover >/dev/null || { echo "error: tamarin-prover not found on PATH"; exit 127; }
    @make -C formal/tamarin interactive

# TLC v1.7.4 is pinned for reproducible lifecycle-model output. Override the
# downloaded jar with TLA2TOOLS_JAR=/path/to/tla2tools.jar when working offline;
# an explicit override is trusted as caller-supplied local tooling.
_tla-tools:
    #!/usr/bin/env bash
    set -euo pipefail
    jar="${TLA2TOOLS_JAR:-target/tla/tla2tools-v1.7.4.jar}"
    if [[ -n "${TLA2TOOLS_JAR:-}" ]]; then
        [[ -f "$jar" ]] || { echo "error: TLA2TOOLS_JAR does not exist: $jar" >&2; exit 1; }
        exit 0
    fi
    expected="936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88"
    checksum() {
        if command -v sha256sum >/dev/null; then
            sha256sum "$1" | awk '{print $1}'
        else
            shasum -a 256 "$1" | awk '{print $1}'
        fi
    }
    if [[ ! -f "$jar" ]]; then
        mkdir -p "$(dirname "$jar")"
        tmp="$(mktemp "${jar}.tmp.XXXXXX")"
        trap 'rm -f "$tmp"' EXIT
        curl --fail --location --silent --show-error \
            https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar \
            --output "$tmp"
        actual="$(checksum "$tmp")"
        [[ "$actual" == "$expected" ]] || {
            echo "error: tla2tools v1.7.4 checksum mismatch: expected $expected, got $actual" >&2
            exit 1
        }
        mv "$tmp" "$jar"
        trap - EXIT
    fi
    actual="$(checksum "$jar")"
    [[ "$actual" == "$expected" ]] || {
        echo "error: tla2tools v1.7.4 checksum mismatch: expected $expected, got $actual" >&2
        exit 1
    }

tla-liveness: _tla-tools
    #!/usr/bin/env bash
    set -euo pipefail
    jar="${TLA2TOOLS_JAR:-target/tla/tla2tools-v1.7.4.jar}"
    mkdir -p target/tla/states
    # Settled terminal states are legitimate deadlocks; temporal properties
    # still reject pre-settlement stalls under the declared fairness assumptions.
    java -XX:+UseParallelGC -jar "$jar" -workers 1 -deadlock \
        -metadir target/tla/states \
        -config ConvergenceLifecycle.fair.cfg \
        formal/liveness/ConvergenceLifecycle.tla

tla-liveness-counterexample: _tla-tools
    #!/usr/bin/env bash
    set -euo pipefail
    jar="${TLA2TOOLS_JAR:-target/tla/tla2tools-v1.7.4.jar}"
    output="$(mktemp)"
    trap 'rm -f "$output"' EXIT
    mkdir -p target/tla/states
    if java -XX:+UseParallelGC -jar "$jar" -workers 1 -deadlock \
        -metadir target/tla/states \
        -config ConvergenceLifecycle.unfair.cfg \
        formal/liveness/ConvergenceLifecycle.tla >"$output" 2>&1; then
        cat "$output"
        echo "error: unfair lifecycle model unexpectedly satisfied admin progress" >&2
        exit 1
    fi
    cat "$output"
    grep -q 'Temporal properties were violated' "$output"

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

# Guard against retired legacy naming reappearing (see PR #725).
naming-gate:
    #!/usr/bin/env bash
    set -euo pipefail
    ./scripts/check_legacy_naming.sh
    is_milestone_path() {
        local lowercase
        lowercase="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
        [[ "$lowercase" == *milestone* ]]
    }
    is_milestone_path "docs/milestone-5/design.md"
    is_milestone_path "docs/design-milestone.md"
    is_milestone_path "docs/MileStone-6/design.md"
    ! is_milestone_path "docs/capability/design.md"
    tracked_milestone_paths=()
    while IFS= read -r -d '' path; do
        if is_milestone_path "$path"; then
            tracked_milestone_paths+=("$path")
        fi
    done < <(git ls-files -z)
    if (( ${#tracked_milestone_paths[@]} > 0 )); then
        echo "tracked paths must use capability names, not milestone names:" >&2
        printf '%s\n' "${tracked_milestone_paths[@]}" >&2
        exit 1
    fi

# Keep convergence policy, resource, scheduler, and history-recovery constants
# attached to reviewed convergence-constant ledger entries.
convergence-ledger-gate:
    ./scripts/check_convergence_constant_ledger.sh

# Keep the distributed campaign image on the workspace's pinned Rust toolchain.
campaign-toolchain-gate:
    ./scripts/check_campaign_toolchain.sh

# Prove the normal-build convergence policy pin (mdk#970). The broader test
# matrix explicitly enables test-policy-overrides; this target must not.
test-convergence-policy-pin:
    cargo test -p cgka-engine --test convergence_policy_pin --locked

# Fast local pre-push gate: mechanical/static checks plus the release pin proof.
# GitHub CI runs the full `just ci` suite (including the workspace test matrix).
fast-ci: fmt-check naming-gate convergence-ledger-gate campaign-toolchain-gate check clippy test-convergence-policy-pin

ci: fmt-check naming-gate convergence-ledger-gate campaign-toolchain-gate check clippy test-convergence-policy-pin test
