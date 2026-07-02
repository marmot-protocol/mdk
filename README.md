# MDK - Marmot Development Kit

Rust implementation workspace for the Marmot protocol.

This repository contains the Marmot engine and production-shaped integration layers:

- OpenMLS-backed CGKA engine and conformance simulator;
- SQLCipher-backed account/device storage;
- account, app-runtime, CLI, daemon, and TUI surfaces;
- Nostr transport adapter and peeler;
- QUIC agent stream preview transport and broker;
- agent control protocol, stream composition, and `dm-agent` connector;
- UniFFI bindings used by app runtimes;
- Tamarin models and architecture notes that map implementation behavior back to the protocol.

The canonical Marmot protocol specification lives in
[marmot-protocol/marmot](https://github.com/marmot-protocol/marmot). This repository keeps implementation architecture,
conformance, diagnostics, and release material.

## Start Here

If you are landing in this repo for the first time, read these files in order:

1. [`crates/cgka-engine/README.md`](crates/cgka-engine/README.md) - what the engine owns and what it leaves out.
2. [`crates/cgka-conformance-simulator/README.md`](crates/cgka-conformance-simulator/README.md) - how scenarios,
   vectors, generated chaos, and property tests work.
3. [`docs/marmot-architecture/index.md`](docs/marmot-architecture/index.md) - implementation architecture map.
4. [`formal/tamarin/README.md`](formal/tamarin/README.md) - how the formal model maps back to Rust tests.

Release checklists live in [`release.md`](release.md).

## Repository Map

Primary implementation areas:

- `crates/cgka-engine` - OpenMLS-backed CGKA engine and local group state machine.
- `crates/cgka-conformance-simulator` - multi-client scenarios, generated chaos, reports, property tests, and vectors.
- `crates/traits` - shared traits and cross-boundary types.
- `crates/storage-sqlite` - SQLCipher-backed persistence for session, engine integration, tests, and simulator runs.
- `crates/transport-nostr-peeler` - Nostr event to engine-message boundary and MLS envelope peeling.
- `crates/transport-nostr-adapter` - Nostr transport adapter core behind an injectable relay-client boundary.
- `crates/transport-quic-stream` - raw QUIC transport binding for transient agent text stream previews.
- `crates/transport-quic-broker` - memory-only QUIC pub/sub broker for forwarding live preview records.
- `crates/cgka-session` - account-device session wrapper over `Engine<SqliteAccountStorage>`.
- `crates/marmot-account` - app-core home, account records, key storage, and transport adapter orchestration.
- `crates/marmot-app` - multi-account app runtime bridge used by the CLI, daemon, TUI, and bindings.
- `crates/marmot-uniffi` - UniFFI bindings over the app runtime.
- `crates/marmot-markdown` - CommonMark and nostr display parser for app messages.
- `crates/marmot-forensics` - append-only JSONL forensic audit schema and recorder traits.
- `crates/agent-control` - `marmot.agent-control.v1` control-protocol DTOs and newline-delimited JSON framing.
- `crates/agent-stream-compose` - reusable live-preview stream composition over the QUIC broker publisher.
- `crates/agent-connector` - local `dm-agent` connector daemon bridging agent control and stream composition.
- `crates/cli` - CLI app surface plus `dmd` daemon and `dm tui`.

Reference and model support:

- `docs/marmot-architecture` - architecture notes, engine contracts, and current-state docs.
- `docs/quic-broker-deployment.md` - local Compose and GHCR/VM deployment notes for `marmot-quic-broker`.
- `formal/tamarin` - Tamarin proofs for convergence selector, lifecycle boundaries, delivery-order behavior, and
  proof-to-test mapping.

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

The CLI real-relay E2E tests use local Nostr relays. Start the repo-owned relay stack before running them:

```sh
just relay-up
just e2e-test
just relay-down
```

Formal model checks:

```sh
just tamarin
```
