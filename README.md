# darkmatter

Candidate Marmot v2 protocol draft, CGKA engine, and conformance workspace.

This repository is for team review. It contains:

- the Marmot v2 protocol draft in `spec/`;
- the OpenMLS-backed CGKA engine in `crates/cgka-engine`;
- the simulator, vector fixtures, property tests, and Tamarin model used to test convergence behavior.

The code also includes storage, session, account, Nostr transport, and lab crates. Those crates exist to exercise the
engine boundary and show the integration path toward MDK/whitenoise replacement work. MDK remains the deployed Rust
protocol implementation until this draft and engine are adopted.

## Start Here

If you are landing in this repo for the first time, read these files in order:

1. [`spec/README.md`](spec/README.md) - status and map for the Marmot v2 draft.
2. [`crates/cgka-engine/README.md`](crates/cgka-engine/README.md) - what the engine owns and what it leaves out.
3. [`crates/cgka-conformance-simulator/README.md`](crates/cgka-conformance-simulator/README.md) - how scenarios,
   vectors, generated chaos, and property tests work.
4. [`formal/tamarin/README.md`](formal/tamarin/README.md) - how the formal model maps back to the Rust tests.

After that, choose the review lane that matches the question in front of you.

## Review Lanes

Most reviewers should use one of these two paths.

### Protocol Draft

Use this path when reviewing protocol shape, spec organization, app components, transport boundaries, or compatibility
with the current MIPs.

1. [`spec/README.md`](spec/README.md)
2. [`spec/principles.md`](spec/principles.md)
3. [`spec/foundation/README.md`](spec/foundation/README.md)
4. [`spec/protocol-core/README.md`](spec/protocol-core/README.md)
5. [`spec/transports/nostr.md`](spec/transports/nostr.md)
6. [`spec/app-components/README.md`](spec/app-components/README.md)
7. [`spec/features/README.md`](spec/features/README.md)
8. [`spec/mip-coverage.md`](spec/mip-coverage.md)

The existing MIPs remain the current production reference until this draft is adopted.

### CGKA Engine, Conformance, And Proofs

Use this path when reviewing the engine state machine, convergence model, publish lifecycle, retained history, testing,
portable scenarios, or formal proofs.

1. [`crates/cgka-engine/README.md`](crates/cgka-engine/README.md)
2. [`docs/marmot-architecture/cgka-engine-spec.md`](docs/marmot-architecture/cgka-engine-spec.md)
3. [`docs/marmot-architecture/distributed-convergence.md`](docs/marmot-architecture/distributed-convergence.md)
4. [`crates/cgka-conformance-simulator/README.md`](crates/cgka-conformance-simulator/README.md)
5. [`crates/cgka-conformance-simulator/SCENARIOS.md`](crates/cgka-conformance-simulator/SCENARIOS.md)
6. [`crates/cgka-conformance-simulator/PROPERTY_TESTS.md`](crates/cgka-conformance-simulator/PROPERTY_TESTS.md)
7. [`formal/tamarin/README.md`](formal/tamarin/README.md)

The engine README explains the local state machine. The simulator README explains how we test multi-client convergence,
generated chaos, property tests, and portable vector fixtures.

The Tamarin model is the formal side of the same convergence work. It models the abstract branch-selection and lifecycle
rules that are hard to reason about from local tests alone: deterministic selection from the same valid candidate set,
policy-gated eligibility, retained-anchor replay, stale-branch rejection, delivery reordering and duplication,
app-output invalidation, welcome/commit handoff, proposal consumption, and outbound gating while convergence is syncing.
Rust tests then check that the implementation follows those rules with OpenMLS objects, storage, and the simulator
harness.

## Repository Map

Primary review areas:

- `spec/` - Marmot v2 protocol draft organized by stable protocol surface.
- `crates/cgka-engine` - OpenMLS-backed CGKA engine and local group state machine.
- `crates/cgka-conformance-simulator` - multi-client scenarios, generated chaos, reports, property tests, and vectors.

Engine support:

- `crates/traits` - shared traits and cross-boundary types.
- `crates/storage-memory` - in-memory storage for tests and simulator runs.
- `crates/storage-sqlite` - SQLCipher-backed persistence for session and engine integration.
- `crates/transport-nostr-peeler` - Nostr event to engine-message boundary and MLS envelope peeling.

Integration prototypes:

- `crates/cgka-session` - account-device session wrapper over `Engine<SqliteStorage>`.
- `crates/marmot-account` - app-core home, account records, key storage, and transport adapter orchestration.
- `crates/marmot-app` - first non-lab app runtime bridge used by the CLI, daemon, and TUI.
- `crates/transport-nostr-adapter` - Nostr transport adapter core behind an injectable relay-client boundary.
- `crates/cli` - first real CLI app surface plus `dmd` daemon and `dm tui` for Nostr-keyed accounts, keys, chats,
  groups, messages, and background sync.
- `crates/marmot-lab` - two-client CLI checks over a file-backed fake relay.

Reference and model support:

- `docs/marmot-architecture` - architecture notes, engine contracts, and current-state docs.
- `formal/tamarin` - Tamarin proofs for the convergence selector, lifecycle boundaries, delivery-order behavior, and
  proof-to-test mapping.

## What Feedback We Want

For the protocol draft:

- Are the stable surfaces in the right places?
- Are identity, application payloads, MLS usage, transports, and app components separated clearly?
- Which rules still depend on MIP-era assumptions?
- Which docs need more exact bytes, validation, or authorization rules before another implementation could build from
  them?

For the engine:

- Does the publish-before-apply lifecycle match the protocol we want?
- Are the group states and recovery states understandable?
- Does convergence choose canonical state for the right reasons?
- Do the simulator scenarios and property tests check real behavior rather than shallow markers?

## Current Boundary

This repo is candidate work. It is not the production MDK code path today.

The integration crates show how the engine can fit into account/session and transport layers, but the review focus
should stay on the protocol draft, the engine state machine, and the conformance story.

## Test Commands

Use the smallest command that covers your change.

```sh
# Engine boundary tests.
cargo test -p cgka-engine

# Simulator scenarios, vectors, and default property-test counts.
cargo test -p cgka-conformance-simulator

# Wider simulator property-test run.
cargo test -p cgka-conformance-simulator --features conformance-slow

# Workspace checks.
just fmt-check
just check
just clippy
just test
```

Run vector reports when you want saved JSON reports plus a pass/fail summary:

```sh
cargo run -p cgka-conformance-simulator --bin cgka-conformance-simulator-report -- \
  --vectors crates/cgka-conformance-simulator/vectors \
  --out target/cgka-conformance-simulator-reports
```

Formal model checks:

```sh
just tamarin
```

`just tamarin` requires `tamarin-prover` on `PATH`.

## Agent Guidance

Read `AGENTS.md` in the directory you are changing. `CLAUDE.md` files are symlinks to the same guidance so Claude-based
tooling reads the canonical file.
