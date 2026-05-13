# cgka-engine

OpenMLS-backed implementation of the [`CgkaEngine`](../traits/src/engine.rs)
trait.

This crate owns the local group state machine. It sits above OpenMLS, governs
commit sequencing, enforces MIP-03 admin rules, and returns typed outcomes for
every ingest path.

## What this crate does

- Wraps `MlsGroup` for each joined group and manages its `EpochState`
  lifecycle (`Stable`, `PendingPublish`, `Merging`, `Recovering`).
- Translates `SendIntent`s (create, invite, leave, app-message, capability
  upgrade) into MLS commits; translates inbound `TransportEnvelope`s into typed
  `IngestOutcome`s and `GroupEvent`s.
- Stores inbound payloads as typed raw-transport or peeled-OpenMLS records so
  peel-deferred messages can be retried without polluting convergence replay.
- Retains a small, configurable OpenMLS past-epoch window for delayed
  application messages.
- Maintains a per-leaf capability cache so `feature_status` lookups do not walk
  the ratchet tree.
- Picks a deterministic auto-committer for MIP-03 SelfRemove proposals and
  returns that work as publish-before-apply obligations.

## What it does *not* do

- No transport (no Nostr, no relays). Plug in a `TransportPeeler` impl.
- No persistence beyond what `StorageProvider` exposes. Pair with
  `storage-memory` for tests and `storage-sqlite` for SQLCipher-backed
  persistence.
- No CLI, no FFI, no application logic.

## Run the tests

```sh
cargo test -p cgka-engine
```

These tests cover the engine boundary directly. They use one or a few
`Engine<S>` instances with memory or SQLite storage and a mock peeler. They are
the right place for local rules: command validation, snapshot persistence,
processed-message idempotency, restart behavior, and the exact outputs from a
single engine call.

Run the simulator when you change convergence, delivery, branch selection,
group data, or anything that depends on more than one client:

```sh
cargo test -p cgka-conformance-simulator
cargo test -p cgka-conformance-simulator --features conformance-slow
```

The simulator is the integration and conformance layer for this engine. It wraps
real engine instances with the Nostr peeler, drives them through an in-memory
transport bus, and checks that clients converge after realistic delivery
weirdness. Its README explains the scenario format, vector fixtures, generated
families, reports, and property tests:

- [`../cgka-conformance-simulator/README.md`](../cgka-conformance-simulator/README.md)

Use this crate's tests to prove that an engine method does the right thing. Use
the simulator to prove that many engines still agree after the world gets messy.

See [`tests/AGENTS.md`](tests/AGENTS.md) for the test file map.

## Reading order for a new contributor

1. [`../../docs/marmot-architecture/overview/target-architecture.md`](../../docs/marmot-architecture/overview/target-architecture.md) — what the engine fits into
2. [`../../docs/marmot-architecture/cgka-engine-spec.md`](../../docs/marmot-architecture/cgka-engine-spec.md) — the current engine spec
3. [`../../docs/marmot-architecture/cgka-engine-canonicalization-contract.md`](../../docs/marmot-architecture/cgka-engine-canonicalization-contract.md) — the detailed post-peeling contract
4. [`../../docs/marmot-architecture/distributed-convergence.md`](../../docs/marmot-architecture/distributed-convergence.md) — the branch-selection and convergence model
5. [`AGENTS.md`](AGENTS.md) — module-by-module map of this crate, design deviations, where to look for what

For the protocol rewrite that may eventually replace the monolithic
`marmot_group_data` extension with app components, see
[`../../spec/README.md`](../../spec/README.md).

## Status

`0.1.0`, single internal consumer, not semver-stable. For current readiness and
open production work, start with
[`../../docs/marmot-architecture/overview/current-state.md`](../../docs/marmot-architecture/overview/current-state.md).
