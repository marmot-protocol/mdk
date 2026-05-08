# cgka-engine

OpenMLS-backed implementation of the [`CgkaEngine`](../traits/src/engine.rs) trait.

This crate is the core of the system: it owns the per-group state machine that sits above OpenMLS, governs commit sequencing, enforces MIP-03 admin rules, and surfaces typed outcomes for every ingest path.

## What this crate does

- Wraps `MlsGroup` for each joined group and manages its `EpochState` lifecycle (`Stable → PendingPublish → Merging → Stable`, plus deterministic rollback/replay for recoverable forks).
- Translates `SendIntent`s (create, invite, leave, app-message, capability upgrade) into MLS commits; translates inbound `TransportEnvelope`s into typed `IngestOutcome`s + `GroupEvent`s.
- Maintains a per-leaf capability cache so `feature_status` lookups don't walk the ratchet tree.
- Picks a deterministic auto-committer for MIP-03 SelfRemove proposals.

## What it does *not* do

- No transport (no Nostr, no relays). Plug in a `TransportPeeler` impl.
- No persistence beyond what `StorageProvider` exposes. Pair with `storage-memory` for tests, a future SQLite backend for production.
- No CLI, no FFI, no application logic.

## Run the tests

```sh
cargo test -p cgka-engine
```

Tests are split into three tiers (unit, in-crate integration, multi-client harness). See [`tests/AGENTS.md`](tests/AGENTS.md) for the map.

## Reading order for a new contributor

1. [`../../docs/marmot-architecture/overview/target-architecture.md`](../../docs/marmot-architecture/overview/target-architecture.md) — what the engine fits into
2. [`../../docs/marmot-architecture/cgka-engine-canonicalization-contract.md`](../../docs/marmot-architecture/cgka-engine-canonicalization-contract.md) — the post-peeling engine contract
3. [`../../docs/marmot-architecture/distributed-convergence.md`](../../docs/marmot-architecture/distributed-convergence.md) — the branch-selection and convergence model
4. [`AGENTS.md`](AGENTS.md) — module-by-module map of this crate, design deviations, where to look for what

## Status

`0.1.0`, single internal consumer, not semver-stable. See the implementation plan for what's done vs. open.
