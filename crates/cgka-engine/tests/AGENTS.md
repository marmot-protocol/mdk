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
`MockPeeler`. Most files use in-memory `Engine<SqliteAccountStorage>`; `sqlite_storage.rs` keeps the encrypted
file-backed backend on the same rail.

**Transport visibility.** The pass-through `MockPeeler` gives every test client perfect cross-branch visibility, which
production does not have: a real transport seals a group message under the sender's current-epoch exporter secret and
carries no epoch hint, so a device that never entered that epoch state reads opaque bytes. Tests whose subject is
*what a device can see* must opt into `support::epoch_sealed_peeler::EpochSealedPeeler`, which models that sealing
(`tests/epoch_sealed_transport.rs` owns the resulting behaviors). Reach for it whenever a scenario turns on branch- or
epoch-scoped readability; `MockPeeler` stays right for everything else.

- **File:** `application_data_wire.rs`
  - **Owns:** OpenMLS integration-contract tests for the MLS application-data carriers Marmot uses (pins fork codec
    behavior the engine relies on)

- **File:** `scaffold.rs`
  - **Owns:** `EngineBuilder` validation; `Box<dyn CgkaEngine>` witness

- **File:** `group_creation.rs`
  - **Owns:** Fresh KeyPackage, create, join welcome, confirm

- **File:** `group_context_view.rs`
  - **Owns:** `GroupContextView` exporter-secret length contract

- **File:** `ingest.rs`
  - **Owns:** Every `StaleReason` variant; send(AppMessage) round-trip

- **File:** `invite_leave.rs`
  - **Owns:** Invite, MIP-03 SelfRemove auto-commit, auto-publish confirm/fail

- **File:** `capabilities.rs`
  - **Owns:** `feature_status`, capability cache, capability matrix

- **File:** `fork_detection.rs`
  - **Owns:** Same-epoch fork resolution through the unified distributed-convergence route (committer, observer,
    and restarted-committer shapes) plus the missing-anchor fail-closed halt

- **File:** `deferred_peel_lifecycle.rs`
  - **Owns:** Durable deferred retry lifecycles, generation barriers, capacity limits, context-cache invalidation,
    foreground budgets, and background work/time budgets with restart and eventual-completion checks. Also the
    publish-cycle replay's cost: rows it keeps parked are not lineage-classified, and each retained anchor's context
    is derived once per replay rather than once per row.

- **File:** `distributed_convergence.rs`
  - **Owns:** Stored-message convergence, stale classification, retained-anchor behavior, and the canonical
    application handoff after catch-up (horizon boundary, restart, bounded turns, and independent send gate).

- **File:** `distributed_convergence/historical_application_sender.rs`
  - **Owns:** Source-epoch application attribution after removal, replacement leaf reuse, and rejoin; direct
    ingestion and buffered replay after restart, duplicate suppression, and forged replacement-author rejection.

- **File:** `distributed_convergence/encrypted_media_source_secret.rs`
  - **Owns:** A replayed media application carries its source-epoch encrypted-media secret on `MessageReceived`
    even when the same pass advances past the anchor horizon and prunes that epoch's retained anchor.

- **File:** `convergence_policy_pin.rs`
  - **Owns:** Default-build pinned v1 policy rejection (mdk#970). Run
    `just test-convergence-policy-pin` without `test-policy-overrides`; the broader integration
    matrix enables that feature explicitly for settlement/rewind fixtures.

- **File:** `mip03_guards.rs`
  - **Owns:** Committer-MUST-NOT-be-leaver, admin-not-last, admin-self-remove

- **File:** `publish_lifecycle.rs`
  - **Owns:** Explicit publish-before-apply lifecycle for local group evolution

- **File:** `pending_commit_recovery.rs`
  - **Owns:** Crash-during-publish recovery at session open — `hydrate_all_stored_groups` detects a surviving
    `PendingCommit`, clears it, and surfaces `GroupEvent::PendingCommitRecovered` (mdk#150)

- **File:** `record_write_atomicity.rs`
  - **Owns:** Group-projection atomicity under injected record/cache write failures (mdk#333, mdk#794), one test per
    seam that projects the record plus inbound capability-cache coverage. No torn record or capability cache,
    orphaned pending publish, leaked snapshot, stale stored proposal, or epoch split between the record and the epoch
    manager; the group stays usable, and an apply the fault abandoned hands its still-retained winning commit back to
    stored convergence so it is eventually applied. Also owns the snapshot-guard durability pair: a guard whose
    rollback fails keeps its snapshot for open-time recovery, and a historical peel context is derived once per
    candidate generation rather than once per bounded slice

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
    live state and releases convergence snapshots. Candidate replay kills after temporary processing and restoration
    also verify exact pre-probe group state, epoch authenticator, snapshots, input ledger and queued work before
    hydration, both standalone and inside an outer transaction.
    Resumable selection and peeling also kill after historical rewind and after a restored slice; reopening must
    recover live state and queued work, discard scratch progress, and select the same winning branch.

- **File:** `update_group_data.rs`
  - **Owns:** Group profile `AppDataUpdate` commits and convergence-side Marmot record refresh

- **File:** `epoch_sealed_transport.rs`
  - **Owns:** Engine behavior under production transport visibility via `support::epoch_sealed_peeler` — the sealing
    model's own semantics, the fork shapes that only appear when post-fork traffic on an unadopted branch is
    unreadable, and `Group::local_copy_welcome_created_at`: the join-time clamp, and the quiet release of a deferred
    row older than this copy's Welcome (retained and released exactly as any other, minus the
    `TransportObjectResourceRefused` announcement) while unopenable traffic from an epoch ahead keeps its deferred
    retry. The predicate's own margin is a `cgka-traits` unit test

- **File:** `audit_log.rs`
  - **Owns:** Append-only forensic audit log wiring — recorder install, JSONL round-trip, and no-op default behavior

```sh
cargo test -p cgka-engine
cargo test -p cgka-engine --features test-policy-overrides   # suites that install custom policies
```

The default build pins the v1 convergence policy. CI runs the workspace with the `test-features` list in the root
`Justfile` (`wn-cli/test-policy-overrides,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks`).

## Benchmarks

`benches/group_lifecycle.rs` (criterion) measures engine CPU + storage cost over in-memory SQLite with a pass-through
peeler. Groups: `retained_anchor_snapshot`, `create_group` (1/8/32 invitees, retention on/off), `join_welcome`,
`join_welcome_large_group`, `send_app_message`, `deferred_outbound_preflight`, `ingest_app_message`,
`rejoin_welcome_with_history`, `canonical_advance_with_history`. Run:

```sh
cargo bench -p cgka-engine --bench group_lifecycle
```

These benches are the measurement rail for engine-lifecycle performance work; extend them when a
change claims a lifecycle speedup.

## Tier 3 — Simulator scenarios + proptest

**Where:** `crates/cgka-conformance-simulator/tests/`. Multi-client convergence under a deterministic in-memory bus.
File map: [`../../cgka-conformance-simulator/tests/AGENTS.md`](../../cgka-conformance-simulator/tests/AGENTS.md).
Core files: `canonical_scenarios.rs` (scripted + portable scenarios, `ScenarioSpec`, vector fixtures, scheduled
faults), `proptest_invariants.rs` (property tests), `canonicalization_contract.rs`, `candidate_state_graph.rs`.

```sh
cargo test -p cgka-conformance-simulator                            # quick
cargo test -p cgka-conformance-simulator --features conformance-slow # pre-release
```

## Workspace-wide

```sh
cargo test --workspace
```

Run before checkpointing broad storage/engine changes.

## When adding a new test

- New `EpochState` transition → unit test in `crates/traits/src/engine_state.rs::tests` first; add an integration test
  only if the engine is involved in the transition.
- New `StaleReason` variant → add a case to `tests/ingest.rs` and a dedicated assertion that the typed variant fires.
  A variant a scenario can only reach under a real transport's epoch sealing belongs in
  `tests/epoch_sealed_transport.rs` instead, because the pass-through `MockPeeler` peels everything.
- New capability requirement type → extend `tests/capabilities.rs` and the simulator capability property so fixed
  examples and generated matrices agree.
- New MIP-03 rule → add to `tests/mip03_guards.rs`. These tests assert at the engine boundary, not via the harness.
- Multi-client convergence question → harness scenario in
  `crates/cgka-conformance-simulator/tests/canonical_scenarios.rs`. If it should hold for _any_ sequence of intents,
  encode as a proptest in `proptest_invariants.rs`.
- Cross-implementation or reportable scenario → prefer `ScenarioSpec` / JSON fixtures in
  `crates/cgka-conformance-simulator/vectors/`, and use `cgka-conformance-simulator-report` for generated report
  artifacts.

## In-crate unit tests

Engine-behavior assertions need an `Engine<S>` and a storage backend, so they live in `tests/*.rs` using
`storage-sqlite` in-memory mode (encrypted file-backed only when the test needs it). Pure-data logic (state
transitions, diff helpers, policy ordering, codecs, caches) uses in-crate `#[cfg(test)]` modules; `src/` has many, and
`src/openmls_projection/tests/` and `src/message_processor/tests/` hold `--lib` replay and measurement tests.
