# AGENTS.md — cgka-engine tests

Three tiers, each owning a different correctness question. The crate's tests are
Tier 2; Tiers 1 and 3 live in sibling crates and are listed here for
navigation.

## Tier 1 — In-crate unit tests (other crates)

**Where:** `crates/traits/src/engine_state.rs::tests`, `crates/traits/tests/snapshots.rs`, `crates/storage-memory/src/tests.rs`, `crates/storage-sqlite/src/**::tests`.
**What they prove:** pure-data-structure correctness — state-machine transitions, storage round-trips, snapshot/rollback, JSON shape stability of cross-boundary value types. No engine, no MLS.

```sh
cargo test -p cgka-traits
cargo test -p storage-memory
```

To accept new snapshot shapes after a deliberate change:
```sh
cargo insta review
```

## Tier 2 — Engine integration tests (this directory)

**What they prove:** real OpenMLS-backed engine behavior across one or more engine instances using a pass-through `MockPeeler`. Most files use `Engine<MemoryStorage>`; `sqlite_storage.rs` keeps the persistent backend on the same rail.

| File | Owns |
|---|---|
| `scaffold.rs` | `EngineBuilder` validation; `Box<dyn CgkaEngine>` witness |
| `group_creation.rs` | Phase 4.2 + 4.8 — fresh KeyPackage, create, join welcome, confirm |
| `group_context_view.rs` | `GroupContextView` exporter-secret length contract |
| `group_data_routing_id.rs` | `marmot_group_data.nostr_group_id` randomness/privacy |
| `ingest.rs` | Phase 4.3 — every `StaleReason` variant; send(AppMessage) round-trip |
| `invite_leave.rs` | Phase 4.3b + 4.11 — invite, MIP-03 SelfRemove auto-commit, auto-publish confirm/fail |
| `capabilities.rs` | Phase 4.6/4.7 + 5.4 — `feature_status`, capability cache, capability matrix |
| `fork_detection.rs` | Phase 4.5 — deterministic same-epoch fork recovery plus the unrecoverable `ForkedEpoch` boundary |
| `distributed_convergence.rs` | Stored-message convergence, stale classification, and retained-anchor behavior |
| `mip03_guards.rs` | Phase 4.9 — committer-MUST-NOT-be-leaver, admin-not-last, admin-self-remove |
| `publish_lifecycle.rs` | Explicit publish-before-apply lifecycle for local group evolution |
| `snapshot_privacy.rs` | Snapshot names do not expose plaintext group ids |
| `sqlite_storage.rs` | SQLCipher-backed `Engine<SqliteStorage>` create + confirm smoke |
| `update_group_data.rs` | Group profile GCE updates and convergence-side Marmot record refresh |

```sh
cargo test -p cgka-engine
```

## Tier 3 — Harness scenarios + proptest

**Where:** `crates/cgka-conformance-simulator/tests/`. Multi-client convergence under a deterministic in-memory bus.

| File | Owns |
|---|---|
| `canonical_scenarios.rs` | Scripted + portable harness scenarios: 3-client happy path, welcome-before-commit, SelfRemove convergence, deliberate fork with recovery observation, `ScenarioSpec`, vector fixtures, scheduled faults, generated-family reports |
| `proptest_invariants.rs` | Property tests for selector order, canonicalization, capability negotiation, lifecycle/restart behavior, generated send/leave histories, and delivery-profile convergence |

Quick CI run:
```sh
cargo test -p cgka-conformance-simulator
```

Slower pre-release run:
```sh
cargo test -p cgka-conformance-simulator --features conformance-slow
```

## Workspace-wide

```sh
cargo test --workspace
```

Run before checkpointing broad storage/engine changes; the exact count changes as
backend coverage grows.

## When adding a new test

- New `EpochState` transition → unit test in `crates/traits/src/engine_state.rs::tests` first; integration test only if the engine is involved in the transition.
- New `StaleReason` variant → add a case to `tests/ingest.rs` and a dedicated assertion that the typed variant fires.
- New capability requirement type → extend `tests/capabilities.rs` and the
  simulator capability property so fixed examples and generated matrices agree.
- New MIP-03 rule → add to `tests/mip03_guards.rs`. These tests assert at the engine boundary, not via the harness.
- Multi-client convergence question → harness scenario in `crates/cgka-conformance-simulator/tests/canonical_scenarios.rs`. If it should hold for *any* sequence of intents, encode as a proptest in `proptest_invariants.rs`.
- Cross-implementation or reportable scenario → prefer `ScenarioSpec` / JSON fixtures in `crates/cgka-conformance-simulator/vectors/`, and use `cgka-conformance-simulator-report` for generated report artifacts.

## Why no in-crate `#[cfg(test)]` modules

The engine modules are intentionally test-free: testing them requires an `Engine<S>` instance which requires a storage backend, and we don't want `cgka-engine` to dev-depend on `storage-memory` for module-internal tests. All engine assertions go through `tests/*.rs` integration files which `dev-dependencies` on `storage-memory`.
