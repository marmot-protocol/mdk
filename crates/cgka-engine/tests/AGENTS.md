# AGENTS.md — cgka-engine tests

Three tiers, each owning a different correctness question. The crate's tests are Tier 2; Tiers 1 and 3 live in sibling
crates and are listed here for navigation.

## Tier 1 — In-crate unit tests (other crates)

**Where:** `crates/traits/src/engine_state.rs::tests`, `crates/traits/tests/snapshots.rs`,
`crates/storage-sqlite/src/**::tests`. **What they prove:**
pure-data-structure correctness — state-machine transitions, storage round-trips, snapshot/rollback, JSON shape
stability of cross-boundary value types. No engine, no MLS.

```sh
cargo test -p cgka-traits
cargo test -p storage-sqlite
```

To accept new snapshot shapes after a deliberate change:

```sh
cargo insta review
```

## Tier 2 — Engine integration tests (this directory)

**What they prove:** real OpenMLS-backed engine behavior across one or more engine instances using a pass-through
`MockPeeler`. Most files use in-memory `Engine<SqliteAccountStorage>`; `sqlite_storage.rs` keeps the encrypted file-backed
backend on the same rail.

**Transport visibility.** The pass-through `MockPeeler` gives every test client perfect cross-branch visibility, which
production does not have: a real transport seals a group message under the sender's current-epoch exporter secret and
carries no epoch hint, so a device that never entered that epoch state reads opaque bytes. Tests whose subject is
*what a device can see* must opt into `support::epoch_sealed_peeler::EpochSealedPeeler`, which models that sealing
(`tests/epoch_sealed_transport.rs` owns the resulting behaviors). Reach for it whenever a scenario turns on branch- or
epoch-scoped readability; `MockPeeler` stays right for everything else.

- **File:** `scaffold.rs`
  - **Owns:** `EngineBuilder` validation; `Box<dyn CgkaEngine>` witness

- **File:** `group_creation.rs`
  - **Owns:** Phase 4.2 + 4.8 — fresh KeyPackage, create, join welcome, confirm

- **File:** `group_context_view.rs`
  - **Owns:** `GroupContextView` exporter-secret length contract

- **File:** `ingest.rs`
  - **Owns:** Phase 4.3 — every `StaleReason` variant; send(AppMessage) round-trip

- **File:** `invite_leave.rs`
  - **Owns:** Phase 4.3b + 4.11 — invite, MIP-03 SelfRemove auto-commit, auto-publish confirm/fail

- **File:** `capabilities.rs`
  - **Owns:** Phase 4.6/4.7 + 5.4 — `feature_status`, capability cache, capability matrix

- **File:** `fork_detection.rs`
  - **Owns:** same-epoch fork resolution through the unified distributed-convergence route (committer, observer,
    and restarted-committer shapes) plus the missing-anchor fail-closed halt

- **File:** `distributed_convergence.rs`
  - **Owns:** Stored-message convergence, stale classification, and retained-anchor behavior

- **File:** `convergence_policy_pin.rs`
  - **Owns:** Default-build pinned v1 policy rejection (mdk#970). Run
    `just test-convergence-policy-pin` without `test-policy-overrides`; the broader integration
    matrix enables that feature explicitly for settlement/rewind fixtures.

- **File:** `mip03_guards.rs`
  - **Owns:** Phase 4.9 — committer-MUST-NOT-be-leaver, admin-not-last, admin-self-remove

- **File:** `publish_lifecycle.rs`
  - **Owns:** Explicit publish-before-apply lifecycle for local group evolution

- **File:** `pending_commit_recovery.rs`
  - **Owns:** Crash-during-publish recovery at session open — `hydrate_all_stored_groups` detects a surviving
    `PendingCommit`, clears it, and surfaces `GroupEvent::PendingCommitRecovered` (mdk#150)

- **File:** `record_write_atomicity.rs`
  - **Owns:** Group-projection atomicity under injected record/cache write failures (mdk#333, mdk#794), one test per
    seam that projects the record plus direct-ingest capability-cache coverage. No torn record or capability cache,
    orphaned pending publish, leaked snapshot, stale stored proposal, or epoch split between the record and the epoch
    manager; the group stays usable, and an apply the fault abandoned hands its still-retained winning commit back to
    stored convergence so it is eventually applied

- **File:** `hydration_quarantine.rs`
  - **Owns:** Group hydration-quarantine path — `GroupHydrationQuarantineReason` classification on session open

- **File:** `two_phase_hydration.rs`
  - **Owns:** mdk#1161 two-phase hydration — cheap-pass seeding vs `GroupNotHydrated` gating, `ensure_hydrated`
    promotion and quarantine parity, cheap-pass idempotency, durable transport-route seeding, the bounded ingest
    route backfill (missing and stale-stamped route sets), eager full hydration of unrecoverable groups, and
    retention-window route retirement across rotation and restart

- **File:** `snapshot_privacy.rs`
  - **Owns:** Snapshot names do not expose plaintext group ids

- **File:** `sqlite_storage.rs`
  - **Owns:** SQLCipher-backed `Engine<SqliteAccountStorage>` create + confirm smoke

- **File:** `crash_recovery_sqlite.rs`
  - **Owns:** Debug-feature-gated subprocess-kill coverage at retained-anchor rewind and historical-apply transaction
    boundaries. Reopens encrypted SQLite, observes the stranded pre-hydration state, then verifies hydration restores
    live state and releases convergence snapshots.

- **File:** `update_group_data.rs`
  - **Owns:** Group profile `AppDataUpdate` commits and convergence-side Marmot record refresh

- **File:** `epoch_sealed_transport.rs`
  - **Owns:** Engine behavior under production transport visibility via `support::epoch_sealed_peeler` — the sealing
    model's own semantics plus the fork shapes that only appear when post-fork traffic on an unadopted branch is
    unreadable

- **File:** `audit_log.rs`
  - **Owns:** Append-only forensic audit log wiring — recorder install, JSONL round-trip, and no-op default behavior

```sh
cargo test -p cgka-engine
```

Note: the default build pins the v1 convergence policy; suites that install custom policies need
`cargo test -p cgka-engine --features test-policy-overrides` (CI runs the workspace with
`wn-cli/test-policy-overrides,cgka-engine/test-crash-hooks`, see `justfile`).

## Benchmarks

`benches/group_lifecycle.rs` (criterion) times the group-creation and welcome-join flows over
in-memory SQLite with a pass-through peeler: `create_group` at 1/8/32 invitees, `join_welcome` at
1/8/32 stored key packages, and `join_welcome_large_group` for 32-member joins. Run:

```sh
cargo bench -p cgka-engine --bench group_lifecycle
```

These benches are the measurement rail for engine-lifecycle performance work; extend them when a
change claims a lifecycle speedup.

## Tier 3 — Harness scenarios + proptest

**Where:** `crates/cgka-conformance-simulator/tests/`. Multi-client convergence under a deterministic in-memory bus.

- **File:** `canonical_scenarios.rs`
  - **Owns:** Scripted + portable harness scenarios: 3-client happy path, welcome-before-commit, SelfRemove convergence,
    deliberate fork with convergence resolution, `ScenarioSpec`, vector fixtures, scheduled faults, generated-family
    reports

- **File:** `proptest_invariants.rs`
  - **Owns:** Property tests for selector order, canonicalization, capability negotiation, lifecycle/restart behavior,
    generated send/leave histories, and delivery-profile convergence

- **File:** `candidate_state_graph.rs`
  - **Owns:** Candidate-state-graph branch-selection assertions

- **File:** `canonicalization_contract.rs`
  - **Owns:** Executable canonicalization-contract assertions (quiescence, resolving/settled status)

- **File:** `generated_policy_cases.rs`
  - **Owns:** Generated bounded convergence-policy cases shared with the Tamarin model

- **File:** `openmls_replay_probe.rs`
  - **Owns:** OpenMLS replay-probe behavior

- **File:** `report_runner.rs`
  - **Owns:** Generated-report runner coverage

- **File:** `sqlite_storage_modes.rs`
  - **Owns:** Harness storage-mode coverage over temp file-backed SQLite

- **File:** `tracing_audit.rs`
  - **Owns:** Repo-wide tracing/logging privacy-invariant enforcement

- **File:** `vector_artifacts.rs`
  - **Owns:** Vector manifest and byte-fixture well-formedness checks

- **File:** `agent_text_stream_vectors.rs`
  - **Owns:** Byte-level conformance vectors for the agent text stream QUIC feature: `AgentTextStreamKeyContextV1`
    encoding, HKDF-SHA256 record key / nonce derivation, record AEAD AAD, transcript hashes, and the
    `QuicBrokerControlEnvelopeV1` envelope

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

Run before checkpointing broad storage/engine changes; the exact count changes as backend coverage grows.

## When adding a new test

- New `EpochState` transition → unit test in `crates/traits/src/engine_state.rs::tests` first; add an integration test
  only if the engine is involved in the transition.
- New `StaleReason` variant → add a case to `tests/ingest.rs` and a dedicated assertion that the typed variant fires.
- New capability requirement type → extend `tests/capabilities.rs` and the simulator capability property so fixed
  examples and generated matrices agree.
- New MIP-03 rule → add to `tests/mip03_guards.rs`. These tests assert at the engine boundary, not via the harness.
- Multi-client convergence question → harness scenario in
  `crates/cgka-conformance-simulator/tests/canonical_scenarios.rs`. If it should hold for _any_ sequence of intents,
  encode as a proptest in `proptest_invariants.rs`.
- Cross-implementation or reportable scenario → prefer `ScenarioSpec` / JSON fixtures in
  `crates/cgka-conformance-simulator/vectors/`, and use `cgka-conformance-simulator-report` for generated report
  artifacts.

## Why most engine modules have no in-crate `#[cfg(test)]` modules

Testing engine behavior requires an `Engine<S>` instance which requires a storage backend, so engine-behavior assertions
go through `tests/*.rs` integration files, using `storage-sqlite` in-memory mode unless the test explicitly needs
encrypted file-backed persistence. The exceptions are `src/identity.rs`, `src/engine_metrics.rs`, `src/epoch_manager.rs`,
`src/app_components.rs`, `src/canonicalization.rs`, and `src/group_state_changes.rs`, which carry
small in-crate `#[cfg(test)]` modules for pure-data logic (state transitions, diff helpers, policy ordering) that needs
no `Engine` instance.
