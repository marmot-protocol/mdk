# CGKA Engine — Reliable State-Machine Refactor

> **Historical plan.** This records the April refactor sequence. The prototype
> tree and dedicated spike-findings docs were removed on 2026-05-08. Treat
> references to those artifacts as historical context; current contracts live in
> `docs/marmot-architecture/`, `crates/*/README.md`, and `crates/*/AGENTS.md`.

## Objective

Replace the spike code with a well-tested, well-commented CGKA engine built around a correctly modeled state machine. The deliverable is an OpenMLS-backed `CgkaEngine` implementation that:

- Exposes the target-architecture trait as its only public surface (intent in, events out).
- Models epoch lifecycle as an explicit `EpochState` enum, with deterministic rollback/replay for recoverable fork races.
- Persists group state through a storage trait with an in-memory backend (SQLite deferred).
- Centralizes capability negotiation in a runtime `FeatureRegistry` + `CapabilityStorage`.
- Is exercised by an in-process multi-client test harness plus property-based invariants and fixture-driven unit tests.

Out of scope for this plan: `TransportAdapter` implementations, concrete `NostrMlsPeeler`, `whitenoise-core`, CLI, SQLite storage, KeyPackage expiry scheduling, external vector fixture packaging, public/external API stability.

Decisions captured from the clarifying round (reference only — not tasks):

- **Scope:** engine trait crate + OpenMLS-backed implementation + `TransportPeeler` trait. No concrete peeler, no adapters, no wiring.
- **Storage:** traits + in-memory backend; SQLite deferred.
- **State machines:** `EpochState` (including `Recovering`) + minimal `WelcomeState`; skip `MemberState`.
- **Fork recovery:** same-epoch commit races recover inside the CGKA engine using deterministic ordering plus storage snapshots. `EngineError::ForkedEpoch` remains the unrecoverable fallback.
- **Wire format:** stay on `PURE_PLAINTEXT_WIRE_FORMAT_POLICY` with an explicit "revisit before external rollout" marker.
- **Testing:** in-process multi-client simulator + property-based tests + mock-peeler fixture tests. Scenario DSL deferred.
- **KeyPackages:** generation + validation only; expiry/refresh deferred.
- **Crate layout:** single `traits` crate that starts with engine/peeler/storage traits and grows over time; implementation, in-memory storage, and harness in sibling crates.
- **Archive:** move the entire current `crates/` tree into `spike/crates/` with its own sealed workspace.
- **Maturity:** 0.1.0 iterable. Single internal consumer. Focus on reliability + commentary, not semver discipline.

---

## Current Status (2026-05-04)

This section is a preserved May 4 snapshot, not the current repo status. Since
then, the archived `spike/` tree was deleted, SQLCipher storage, the real Nostr
transport peeler, session lifecycle, distributed convergence, conformance
families, and Tamarin models have landed on `master`.

**Workspace state at the time:** 100 tests passing, 0 failing. `cargo clippy --workspace --all-targets -- -D warnings` green. `cargo fmt --all --check` clean. Slow harness gate (`cargo test -p cgka-conformance-simulator --features conformance-slow`) green. The then-archived spike workspace at `spike/` built independently with known deprecation/dead-code warnings. **All original tasks in the plan were closed; recovery trace observations had a first implementation via `GroupEvent::ForkRecovered` + `ScenarioTrace::recoveries`.**

**Crate inventory (all at 0.1.0, root workspace):**

| Crate | Role | Status |
|---|---|---|
| `cgka-traits` (`crates/traits/`) | Shared trait surface + value types | Stable; insta snapshots locked, including `ForkRecovered` event shape |
| `cgka-engine` (`crates/cgka-engine/`) | OpenMLS-backed engine | Functional; publish-before-apply plus same-epoch fork recovery landed. |
| `storage-memory` (`crates/storage-memory/`) | In-memory backend | Done; snapshots include OpenMLS memory state for recovery tests. |
| `cgka-conformance-simulator` (`crates/cgka-conformance-simulator/`) | Multi-client simulator + proptest | Done; scripted fork scenario now asserts convergence and recovery trace emission. |

**Phase summary:**

| Phase | Status | Notes |
|---|---|---|
| 0 — Archive spike | ✅ | Spike at `spike/`, root excludes it |
| 1 — Crate skeleton | ✅ | Toolchain pinned to `1.90.0` (1.85 → icu, 1.86 → openmls0.8.1 needed `unsigned_is_multiple_of`) |
| 2 — Storage traits + memory | ✅ | 18 storage tests; snapshot/rollback hooks are wired into fork recovery. Memory snapshots include the OpenMLS map. Aggregate uses accessor composition (deviation, see below). |
| 3 — State-machine types | ✅ | All in `cgka-traits`; `Box<dyn CgkaEngine + Send + Sync>` witness compiles |
| 4 — Engine impl | ✅ | All 14 original tasks landed, plus `ForkRecoveryManager` for same-epoch commit races. |
| 5 — Unit tests | ✅ | 5.1 trybuild deferred per plan edit; 5.4 **full 36-cell capability matrix landed** as a single parametrized test in `tests/capabilities.rs::capability_matrix_36_cells`; 5.7 witness compiles; 5.8 insta snapshots locked. |
| 6 — Test harness | ✅ | Bus + client + 4 scripted scenarios green. Proptest depth: 4 properties — (a) true same-id replay via `bus.inject`; (b) convergence under Send+Leave intents; (b') convergence under varied `DeliveryProfile` (FIFO / Reverse / SeededRandom); (c) confirm-vs-fail rollback round trip. Slow gate (`--features conformance-slow`) lifts case counts to 200–1000. Fork scenario asserts deterministic convergence and records the rollback trace. |
| 7 — Docs + hygiene | ✅ | Per-crate `README.md` + `AGENTS.md` pair (cgka-engine, cgka-conformance-simulator) plus thin `README.md` for traits + storage-memory. `tests/AGENTS.md` documents the three-tier test layout. `docs/learnings.md` 2026-04-25 entry added. Clippy/fmt CI gates passing. |

**Phase 4 detail (every task):**

| Task | Status | Implementation site / note |
|---|---|---|
| 4.1 Engine scaffold | ✅ | `crates/cgka-engine/src/engine.rs` |
| 4.2 GroupLifecycle (create/join/invite/leave) | ✅ | `crates/cgka-engine/src/{group_lifecycle,message_processor,update_group_data}.rs` — create / join / invite / leave / **update_group_data** all landed; `leave_group_via_self_remove` only; legacy grep-banned. |
| 4.3 MessageProcessor | ✅ | `crates/cgka-engine/src/message_processor.rs` |
| 4.4 EpochManager module | ✅ | `crates/cgka-engine/src/epoch_manager.rs` — owns `epoch_states`, `pending_to_group`, `pending_counter`, `committed_from_epochs` |
| 4.5 Fork detection | ✅ | `EpochManager::we_committed_from()` + ingest `ProcessMessageError::ValidationError(WrongEpoch)` branch in `message_processor.rs` |
| 4.6 CapabilityManager | ✅ | `crates/cgka-engine/src/capability_manager.rs` — `feature_status`, `upgradeable_capabilities`, `upgrade_group_capabilities` (last via `crates/cgka-engine/src/upgrade.rs` GCE proposal) |
| 4.7 Cache on ingest | ✅ | `cache_self_capabilities`, `cache_from_key_packages`, `cache_from_staged_commit` — all populate `CapabilityStorage`. Cache is **load-bearing for correctness** (see deviations) |
| 4.8 KeyPackageManager | ✅ | `crates/cgka-engine/src/key_package.rs` |
| 4.9 MIP-03 policy guards | ✅ | §149 admin-cannot-self-remove + §150 admin-depletion in `message_processor.rs::do_send_leave` and `auto_committer.rs::decide`. RFC §12.2 committer-not-leaver in auto-committer. §151 remove-beats-self-remove n/a (engine never produces Remove proposals). MIP-01 `marmot_group_data` (`0xF2EE`) wired in `crates/cgka-engine/src/group_data.rs` |
| 4.10 Wire format policy | ✅ | `PURE_PLAINTEXT_WIRE_FORMAT_POLICY` + `WIRE_FORMAT_POLICY_REVIEW_REQUIRED` grep marker in `wire_format.rs` |
| 4.11 LowestIndexAutoCommitter | ✅ | `crates/cgka-engine/src/auto_committer.rs` — pluggable seam; SelfRemove only |
| 4.12 drain_events / drain_auto_publish | ✅ | Both populated by ingest path; tested in `tests/ingest.rs` and `tests/invite_leave.rs::selfremove_full_flow_with_auto_commit` |
| 4.13 PendingStateRef + publish-before-apply | ✅ | `do_create_group` / `do_send_invite` / `do_upgrade_group_capabilities` stage the commit and DEFER merge to `do_confirm_published` (`crates/cgka-engine/src/publish.rs`). New `CgkaEngine::publish_failed` rolls back via `MlsGroup::clear_pending_commit` + Marmot record re-derive from the still-unmerged MLS state. Marmot record holds projected post-merge `members` so `members()` / `feature_status` reflect user intent during `PendingPublish`. Auto-commit (`message_processor.rs:309`) intentionally still merges before publish — documented deviation in `auto_committer.rs` rustdoc. Tests: 5 new in `tests/publish_lifecycle.rs`. |
| 4.14 OpenMLS pin | ✅ | `~0.8.1` family in root `Cargo.toml` |

---

## Design deviations from the plan (all documented in code comments where they landed)

1. **`StorageProvider` aggregate uses accessor composition, not direct supertrait.** The plan said `... + openmls_traits::storage::StorageProvider<CURRENT_VERSION>` as a supertrait. Hand-forwarding 50+ openmls trait methods would have been mechanical churn with zero functional value. Switched to `type Mls; fn mls_storage(&self) -> &Self::Mls`. Documented at `crates/traits/src/storage.rs:120-130`. Memory: `feedback_openmls_accessor_pattern.md`.
2. **`SendResult::GroupCreated { welcomes, pending }` variant added.** The original `SendResult::GroupEvolution` carried a `msg: TransportMessage` but the engine has no consumer for the create-time commit (every other initial member arrives via welcome with post-commit state). Distinct variant for create vs. invite. Side-benefit: eliminates the welcome-before-commit `AlreadyAtEpoch` bounce at creation. Documented at `crates/traits/src/engine.rs::SendResult`.
3. **`CreateGroupRequest::initial_admins: Vec<MemberId>` added.** Bootstraps multi-admin groups so admins can subsequently self-remove (per MIP-03 §149's "not the last admin" constraint). Creator is always implicitly an admin; `initial_admins` adds co-admins. Documented at `crates/traits/src/engine.rs::CreateGroupRequest`.
4. **Per-leaf capability cache is load-bearing for correctness, not just an optimization.** The original Risk #1 in this plan and the `project_openmls_capabilities_access` memory both originally claimed `LeafNode::capabilities()` was publicly reachable. It IS public — but `MlsGroup::public_group()` is `pub(crate)`, so there's no public API to walk to a specific leaf. Cache is populated from KeyPackages we directly handle (invite-side parses + ingest-side `StagedCommit::add_proposals`) plus `MlsGroup::own_leaf_node()` for self. Documented inline at `crates/cgka-engine/src/capability_manager.rs`.
5. **MIP-01 `marmot_group_data` (`0xF2EE`) is owned by the engine, not the transport adapter** — even though most fields (relays, image_*, nostr_group_id) are transport-y. This is because §149/§150 admin guards must fire at commit-construction time in the engine. The engine populates transport-y fields with placeholders that a future transport adapter refines. Documented at `crates/cgka-engine/src/group_data.rs`. (Future component-based MIP-01 split will retire this monolithic module.)
6. **Test identities are 32 bytes via `pad32`.** MIP-01 admin pubkeys MUST be 32-byte x-only secp256k1. The engine strict-fails non-32-byte member identities at admin-set time. Test fixtures use a `pad32(b"alice")` helper to satisfy this. Production identities (real Nostr pubkeys) flow through unchanged.

## Implementation Plan

### Phase 0 — Archive the spike

- [x] Task 0.1. Create a top-level `spike/` directory and move `crates/cgka-engine`, `crates/transport`, `crates/mdk-spike`, `crates/nostr-adapter`, `crates/nostr-mls-peeler`, `crates/whitenoise-core-spike`, and `crates/dm-cli` into `spike/crates/`. Preserves every bit of reference material referenced by `docs/learnings.md` and `docs/marmot-architecture/further-context/spike-findings.md` without deletion. Rationale: we want the spike buildable for lookup value but sealed off from the new workspace.
- [x] Task 0.2. Create `spike/Cargo.toml` as an independent workspace, copying the necessary `[workspace.dependencies]` from the current root `Cargo.toml:19-47` and updating the `members` list to the seven moved crates. The spike becomes a self-contained workspace that can be `cargo check`-ed in isolation. Rationale: the new workspace at repo root shouldn't inherit the spike's dependency graph.
- [x] Task 0.3. Rewrite the root `Cargo.toml` so the top-level workspace members are only the new crates (listed in Phase 1). Add an `exclude = ["spike"]` entry so the spike workspace doesn't get pulled into a root `cargo check`. Rationale: keeps the root `cargo build` fast and sharply scoped.
- [x] Task 0.4. Add a `spike/README.md` (short) explaining that this tree is archived spike code, pointing to `docs/learnings.md` and `docs/marmot-architecture/further-context/spike-findings.md`, and noting it is not built by the main workspace. Rationale: future readers need a one-line orientation.
- [x] Task 0.5. Confirm `cargo check` at repo root (now empty of members) passes, and `cd spike && cargo check` still passes against the moved files. Rationale: mechanical confirmation the move didn't break paths.

### Phase 1 — New crate skeleton

- [x] Task 1.1. Create `crates/traits/` as the shared-traits crate. Initially contains the `CgkaEngine` trait, the `TransportPeeler` trait, the storage traits, the `GroupContext` trait, and all cross-boundary value types (`TransportMessage`, `TransportEnvelope`, `PeeledMessage`, `EncryptedPayload`, `SendIntent`, `SendResult`, `GroupEvent`, `IngestOutcome`, `StaleReason`, `EngineError`, `PendingStateRef`, `MessageId`, `GroupId`, `MemberId`, `EpochId`, etc). Rationale: one crate to import for anything that crosses a seam, as clarified in question 8. Growth room for future non-CGKA traits.
- [x] Task 1.2. Create `crates/cgka-engine/` as the OpenMLS-backed implementation crate. Takes a type-parameter `S: StorageProvider` (see Phase 2) — no dyn-storage dispatch. Rationale: matches the design-doc decision `crates/cgka-engine/src/lib.rs` analogue that generics beat trait objects for storage.
- [x] Task 1.3. Create `crates/storage-memory/` as the in-memory backend. Implements every storage trait from `crates/traits`. Rationale: zero-dependency backend suitable for tests and ephemeral scenarios.
- [x] Task 1.4. Create `crates/cgka-conformance-simulator/` for the multi-client simulator + shared fixtures. Depends on `traits`, `cgka-engine`, `storage-memory`. Rationale: isolates test-only code so it doesn't bloat the production crates.
- [x] Task 1.5. Wire the four crates into the root `[workspace]` members and define `[workspace.dependencies]` (openmls family pinned per `docs/learnings.md:32`, thiserror, tracing, tokio, async-trait, rand, hex, serde, proptest, insta or similar snapshot tool, test-log). Rationale: version pinning is non-negotiable per the spike learning about silent companion-crate skew.
- [x] Task 1.6. Add a `rust-toolchain.toml` pinning `channel = "1.85.0"` (or a newer stable). Edition 2024 requires rustc ≥ 1.85. Document MSRV in the root README. Rationale: reproducibility of tests; avoids surprise when a contributor runs on an older toolchain.

### Phase 2 — Storage traits + in-memory backend

- [x] Task 2.1. Define `GroupStorage` in `crates/traits`: CRUD for `Group` records keyed by `GroupId`. The `Group` struct must NOT contain any Nostr types — per `docs/marmot-architecture/further-context/cgka-engine-design.md:247-268` — so `nostr_group_id` and `relays` stay out. Include `name`, `description`, `epoch`, `members`, `required_capabilities`. Rationale: the leak described in the design doc is the single largest architectural defect in MDK today; enforcing the boundary at the trait level prevents it ever coming back.
- [x] Task 2.2. Define `MessageStorage` with the per-message state enum (`Created → Processed → Failed → Retryable → EpochInvalidated`). Include the snapshot/rollback hooks (`create_group_snapshot`, `rollback_group_to_snapshot`, `release_group_snapshot`) called out in `cgka-engine-design.md:48-54`. Rationale: needed for fork recovery and deterministic replay after epoch races.

  *Status:* trait + storage-memory impl + 18 tests done. `ForkRecoveryManager` now calls these hooks before local and inbound commits. `storage-memory` snapshots the full OpenMLS memory map; production storage should snapshot group-scoped OpenMLS rows plus CGKA metadata atomically.
- [x] Task 2.3. Define `WelcomeStorage` — pending-welcome persistence. Minimal shape matching the minimal `WelcomeState` decided for this plan. Rationale: persistence across restart for in-flight joins.
- [x] Task 2.4. Define `CapabilityStorage` with `feature_requirement`, `register_feature`, `save_member_capabilities`, `member_capabilities` per `cgka-engine-design.md:275-296`. Rationale: local cache of each member's advertised capabilities closes the `Upgradeable` vs `Unavailable` gap noted in the spike at `docs/learnings.md:125` and `docs/marmot-architecture/further-context/spike-findings.md:302-311`.
- [x] Task 2.5. Define `StorageProvider` as the `GroupStorage + MessageStorage + WelcomeStorage + CapabilityStorage + openmls::storage::StorageProvider<CURRENT_VERSION>` aggregate. Include a `backend()` accessor so callers can distinguish impl kinds. Rationale: matches the design-doc aggregate at `cgka-engine-design.md:298-312` and gives a single type parameter on the engine.
- [x] Task 2.6. Implement all storage traits in `crates/storage-memory` using `Arc<Mutex<...>>` internals. The openmls `StorageProvider` half can wrap `OpenMlsRustCrypto`'s default storage. Rationale: simplest correct backend; cloneable for multi-client harness tests.
- [x] Task 2.7. Unit-test the in-memory backend directly: round-trip every type, snapshot + rollback correctness, concurrent-access soundness under tokio runtime. Rationale: storage bugs would mask engine bugs; test the substrate first.

### Phase 3 — State-machine types

- [x] Task 3.1. Define `EpochState` in `crates/traits` with variants `Stable`, `PendingPublish { pending: StagedCommitHandle, pending_ref }`, `Merging`, `Recovering { last_stable_epoch, buffered: Vec<PeeledMessage> }`. Include transition helper methods that are the ONLY public mutation paths — the variants themselves should hold private fields. Rationale: rustls-style "illegal states unrepresentable"; eliminates the defensive `if group.pending_commit().is_some()` checks scattered through today's MDK (see `cgka-engine-design.md:166-172`).
- [x] Task 3.2. Define `WelcomeState` with `None`, `Pending { welcome, group_id }`, `Active` only. No `Declined` variant for now — user-controlled welcome decline is deferred. Rationale: minimal per question-3 decision; covers the auto-accept flow without locking us out of a decline UI later.
- [x] Task 3.3. Define `IngestOutcome` + `StaleReason` matching `docs/marmot-architecture/further-context/spike-findings.md:163-180` — `Processed`, `Stale { reason }` with `AlreadySeen / AlreadyAtEpoch / NotForThisClient / UnknownGroup / OwnEcho / PeelFailed`. Note the new `PeelFailed` variant called out in `docs/learnings.md:140`. Rationale: lets the wiring layer log by category without parsing strings.
- [x] Task 3.4. Define `EngineError` with typed variants: `UnknownGroup`, `UnknownPending`, `NotAMember`, `MissingRequiredCapabilities { required, had }`, `ForkedEpoch { group_id, last_stable, conflicting_epoch }`, `Backend(String)`, `Peeler(PeelerError)`, `Serialize(String)`, `Other(String)`. Rationale: matches spike-findings §1.6 and §2.2 — all the places the spike was using `Backend(String)` or `Other(String)` to hide structure.
- [x] Task 3.5. Define the `CgkaEngine` trait surface in `crates/traits` with the final signature: `async ingest`, `drain_events`, `drain_auto_publish`, `async send`, `async confirm_published`, `async create_group`, `async join_welcome`, `feature_status`, `constructable_capabilities`, `upgradeable_capabilities`, `upgrade_group_capabilities`, `group_context`, `members`, `epoch`, `self_id`, `fresh_key_package`. Note: `drain_events` + `drain_auto_publish` intentionally supersede `cgka-engine-design.md:82`'s `events() -> BoxStream<'_, GroupEvent>` per `spike-findings.md` §1.7 — validated factoring from the spike. Rationale: locks the contract before implementation so tests can be written against the trait, not the impl.
- [x] Task 3.6. Define the `TransportPeeler` trait with the four-method async split (`peel_group_message`, `peel_welcome`, `wrap_group_message`, `wrap_welcome`) per spike-findings §1.3. Include a well-typed `PeelerError` enum. Rationale: structurally-different crypto paths should be structurally-different methods (the spike's big peeler-design learning).
- [x] Task 3.7. Add doc comments on every trait method spelling out the invariants: which state transitions are legal, what errors may fire, what ordering guarantees apply. Rationale: the plan explicitly requires "well commented"; trait-level commentary is the highest-leverage place to pay that cost.

### Phase 4 — Engine implementation (OpenMLS-backed)

Internal subsystems per `cgka-engine-design.md:214-233`. Each is a module inside `crates/cgka-engine/src`; together they implement `CgkaEngine`.

- [x] Task 4.1. Scaffold `Engine<S: StorageProvider>` struct holding `provider`, `signer`, `credential_with_key`, `identity`, `registry: FeatureRegistry`, `peeler: Box<dyn TransportPeeler>`, `storage: S`, and per-group `EpochState`. Remove the spike's `HashMap<GroupId, GroupState>` direct-state pattern and route everything through storage. Rationale: we want the engine to be a thin coordinator over storage + MLS.
- [x] Task 4.2. Build `GroupLifecycle` module — `create_group`, `join_welcome`, `invite`, `leave`, `update_group_data`. Default-route `leave` to `leave_group_via_self_remove` per `docs/learnings.md:115-116` (the spec-compliant call). Forbid `leave_group()` legacy path entirely. Rationale: "opinionated defaults" per spike-findings §2.2.

  *Status:* `create_group`, `join_welcome`, `invite`, `leave`, and `update_group_data` all done with tests.
- [x] Task 4.3. Build `MessageProcessor` module — inbound path (`peel → classify → apply-via-EpochManager → emit GroupEvent`) and outbound path (`SendIntent → validate via EpochState → encrypt → wrap → SendResult`). Rationale: matches `cgka-engine-design.md:221-223` and the design-doc ingest pipeline at `target-architecture.md:137-152`.
- [x] Task 4.4. Build `EpochManager` module owning the `EpochState` transitions + snapshot/rollback glue. Only this module may construct non-`Stable` variants. Rationale: keeps the state machine's integrity in one file.
- [x] Task 4.5. Implement fork detection and first-pass recovery. When a same-epoch competing commit arrives, `ForkRecoveryManager` compares `(timestamp, message_id)` ordering keys. A better candidate rolls storage back to the pre-commit snapshot and replays; a losing candidate is marked stale. Successful rollback emits `GroupEvent::ForkRecovered`, which the harness records in `ScenarioTrace::recoveries`. `EngineError::ForkedEpoch` remains for unrecoverable cases, usually missing snapshots. Rationale: commit races must converge deterministically for portable CGKA test vectors.
- [x] Task 4.6. Build `CapabilityManager` module — `FeatureRegistry` construction, `feature_status`, `constructable_capabilities`, `upgradeable_capabilities`, `upgrade_group_capabilities`. Primary source of truth for a member's advertised capabilities is `LeafNode::capabilities()` via `group.public_group().leaf(idx)` (public API — see Risk #1 correction). `CapabilityStorage` layers on top as an optimization: avoids repeated tree walks, retains historical capabilities for removed members (useful for audit/replay), and gives `feature_status` a cheap local lookup. Rationale: the spike's `pub(crate)` claim was wrong; with capabilities readable directly, the cache is a clean optimization rather than a workaround.
- [x] Task 4.7. Populate `CapabilityStorage` on every `ingest` where a KeyPackage is consumed (group creation, invites, welcome acceptance). Write-through pattern: read capabilities from the validated `LeafNode`, store under `(group_id, member)`. Rationale: keeps the cache consistent with the tree state, enables capability lookup for members who subsequently leave, and avoids re-walking `public_group()` on every `feature_status` call.
- [x] Task 4.8. Build `KeyPackageManager` module — `fresh_key_package` only, with correct `Capabilities` derivation from the `FeatureRegistry`. No expiry scheduling per question-7 decision. Rationale: scheduler is a higher-layer concern.
- [x] Task 4.9. Implement MIP-03 policy checks as engine-layer guards before calling OpenMLS:
  - Admin-cannot-self-remove (MIP-03 §149)
  - Admin-depletion-before-commit (MIP-03 §150)
  - Remove-beats-SelfRemove (MIP-03 §151)
  - Committer-MUST-NOT-be-leaver (RFC 9420 §12.2)
  Rationale: listed in `docs/marmot-architecture/further-context/spike-findings.md:248-254` as required opinionated defaults; the OpenMLS layer doesn't enforce them.
- [x] Task 4.10. Keep `PURE_PLAINTEXT_WIRE_FORMAT_POLICY` as the spike chose. Add a prominent module-level doc comment at the policy's use-site explaining the tradeoff (per `docs/marmot-architecture/further-context/spike-findings.md:268-279`) and linking the three alternative paths to revisit. Add a compile-time `const WIRE_FORMAT_POLICY_REVIEW_REQUIRED: () = ();` style marker (or a tracking issue constant) so the decision surfaces. Rationale: question-5 decision plus the explicit "revisit" flag.
- [x] Task 4.11. Keep the lowest-index auto-committer rule for SelfRemove (same as spike), but factor it into a named `LowestIndexAutoCommitter` policy object injected into `EpochManager` so a future strategy (randomized delay, observer suppression) can replace it without touching the core. Rationale: `docs/learnings.md:141` flags this as a known-fragile shortcut; making the strategy pluggable is the cheap forward-compat move.
- [x] Task 4.12. Implement `drain_events` and `drain_auto_publish` exactly per spike-findings §1.7. Auto-publish queue is only populated by `MessageProcessor` / `EpochManager`; never by `send`. Rationale: matches the validated factoring from the spike.
- [x] Task 4.13. **[DONE 2026-04-25]** `PendingStateRef` → `EpochManager::PendingMeta { group_id, prior_epoch, kind }` → `do_confirm_published` (publish.rs) merges + mirrors Marmot + caches; `do_publish_failed` clears pending + rewinds Marmot from the still-unmerged MLS. Auto-commit retains merge-immediate (deliberate, see `auto_committer.rs` rustdoc) because there's no per-message confirm callback for `drain_auto_publish`. Publish rollback uses `clear_pending_commit`; fork recovery uses `MessageStorage` snapshots. Rationale: `target-architecture.md:79-88` publish-before-apply contract is the central state invariant.
- [x] Task 4.14. Pin the OpenMLS crate family with tilde constraints to specific minor versions (latest as of 2026-04-22): `openmls = "~0.8.1"`, `openmls_basic_credential = "~0.5"`, `openmls_traits = "~0.5"`, `openmls_rust_crypto = "~0.5"`, `tls_codec = "~0.4"`. Per `docs/learnings.md:32`, version skew inside this crate family is silent; tilde constraints catch unintended bumps. Rationale: reproducible builds + avoids the silent-skew class of footguns the spike hit.

### Phase 5 — Unit tests (inside each crate)

- [x] Task 5.1. Add compile-fail tests for the trait surface only if the `Box<dyn CgkaEngine + Send + Sync>` witness in Task 5.7 proves insufficient to catch async-lifetime regressions (per the spike's `E0195` finding at `docs/learnings.md:44`). Prefer `trybuild` if added. Rationale: the trait definition is load-bearing, but 5.7's witness is likely enough for 0.1.0 — avoid building test infra we don't yet need.
- [x] Task 5.2. In `crates/cgka-engine`, cover each `EpochState` transition with direct unit tests: `Stable → PendingPublish → Merging → Stable` (happy path), `Stable → PendingPublish → Stable` (publish fail rollback), `Stable → Recovering` (fork detection), `PendingPublish` ingest attempt rejection. Rationale: state-machine correctness is the central correctness claim of this refactor.
- [x] Task 5.3. Cover each `IngestOutcome::Stale` reason with a dedicated test: `AlreadySeen` (dedup), `AlreadyAtEpoch` (welcome-echoed-commit per `docs/learnings.md:66-70`), `NotForThisClient` (welcome to another recipient), `UnknownGroup` (message for unjoined group), `OwnEcho` (own commit bounce), `PeelFailed` (stale-epoch inbound). Rationale: each was a real production foot-gun in the spike; regression tests lock them down.
- [x] Task 5.4. **[DONE 2026-04-25]** Cover capability negotiation exhaustively: `Required` / `Optional` / `TransportRequired` × covered / partially-covered / uncovered × member counts 1..4. Assert `MissingRequiredCapabilities` is fired with the correct `required` / `had` pair. Implemented as `capability_matrix_36_cells` in `tests/capabilities.rs` — single parametrized test that walks all 36 cells with per-cell context in failure messages. Degenerate cells (`Required + Partial/None` at n>1) assert the rejection itself rather than a status query.
- [x] Task 5.5. Cover MIP-03 SelfRemove flow end-to-end from the engine's perspective using a single engine instance with a mock peeler: leaver produces proposal → SendResult::GroupEvolution → confirm → engine forgets group. Remaining-member behaviour (auto-commit) covered by harness tests in Phase 6. Rationale: the happy path through an engine boundary is cheap to test in-crate.
- [x] Task 5.6. Cover the capability-check rejection path in `invite` using a KeyPackage that omits a required proposal, replicating the `DM_DROP_CAPS=selfremove` scenario from `docs/learnings.md:103`. Rationale: direct port of a validated spike scenario.
- [x] Task 5.7. Assert every async trait method maintains `Send` bounds by compiling against a `Box<dyn CgkaEngine + Send + Sync>` witness. Rationale: prevents async-trait regressions across the `&dyn GroupContext` fault line the spike hit at `docs/learnings.md:44`.
- [x] Task 5.8. Snapshot-test (via `insta` or similar) the JSON/debug shape of every cross-boundary value type so wire-level / log-level regressions are caught loudly. Rationale: `TransportMessage` bytes already cross the network in the peeler's output; even though the engine is 0.1.0, shape drift should be visible.

### Phase 6 — Test harness

- [x] Task 6.1. Build `crates/cgka-conformance-simulator/src/bus.rs` — an in-memory `TransportBus` that N engine clients attach to. Supports: ordered delivery, reverse-ordered delivery, random delivery (seeded), partitioning (drop messages to subset), duplication (same MessageId twice), delay injection. No actual network. Rationale: multi-client harness per question-6 option (a); seed control makes every scenario deterministic.
- [x] Task 6.2. Build `crates/cgka-conformance-simulator/src/client.rs` — a `HarnessClient` wrapping `Engine<MemoryStorage>` + a `MockPeeler` that performs trivial ChaCha-free framing. The mock peeler still distinguishes group-message vs welcome paths but skips actual encryption so tests can assert on inner payloads directly. Rationale: mock peeler per question-6 option (e); keeps tests fast and lets invariants target engine behavior not crypto.
- [x] Task 6.3. Build scripted scenario helpers: `HarnessClient::send(...)`, `HarnessClient::tick()` (drain events), `TransportBus::step(n)` (deliver next N messages under the current scheduler). Rationale: makes scenario code imperative and readable without needing a DSL layer yet.
- [x] Task 6.4. Write the canonical 3-client happy-path scenario (A creates group with B, C; each sends one message; asserts all three converge on same epoch + same received messages) as the harness's first smoke test. Rationale: replicates `docs/learnings.md:62` end-to-end result without touching Nostr.
- [x] Task 6.5. Write the welcome-before-commit scenario reproducing `docs/learnings.md:66-70` — deliver welcome, then commit — and assert the commit is categorised as `StaleReason::AlreadyAtEpoch`, not an error. Rationale: validates the typed-outcome plumbing against the exact bug class the spike found.
- [x] Task 6.6. Write the add-then-self-remove scenario from `docs/learnings.md:100-104` — A invites B, C, D; A SelfRemoves; remaining members converge to epoch N+2 via the lowest-index-auto-committer policy. Assert member list, epoch, and no `ForkedEpoch` errors. Rationale: exercises the auto-commit pathway and the policy-object seam.
- [x] Task 6.7. Write a deliberate fork scenario: two members concurrently invite different KeyPackages at the same epoch. Assert both sides converge to one deterministic winner at epoch 2 and no `ForkedEpoch` escapes for recoverable races. Rationale: validates fork recovery under controlled partition/delivery timing.
- [x] Task 6.8. **[DONE 2026-04-25]** `proptest_support.rs` now generates `HarnessIntent` ∈ {Send, Leave} sequences plus a `DeliveryProfile` selector covering Ordered / Reverse / SeededRandom. The proptest in `tests/proptest_invariants.rs` drives both `prop_convergence_under_send_leave_sequence` (FIFO baseline) and `prop_convergence_under_varied_delivery` (random-policy convergence). Invite is intentionally excluded (minting fresh clients mid-strategy is awkward inside a proptest closure; integration tests cover Invite explicitly).
- [x] Task 6.9. **[DONE 2026-04-25]** All four invariants encoded as proptest properties:
  - **(a) True same-id replay** — `prop_true_same_id_replay`: captures a wrapped `TransportMessage` via `HarnessClient::send_app_capture`, re-injects it via `TransportBus::inject`, asserts second ingestion returns `Stale { AlreadySeen }` and engine state is unchanged.
  - **(b) Convergence** — `prop_convergence_under_send_leave_sequence` + `prop_convergence_under_varied_delivery`: undisturbed clients agree on epoch after any sequence of Send+Leave intents, under any `DeliveryProfile`.
  - **(c) Rollback** — `prop_upgrade_confirm_or_fail_round_trip`: `upgrade_group_capabilities` followed by random `confirm_published` / `publish_failed` choice; assert epoch advances on confirm, rolls back on fail, and a post-rollback retry succeeds.
  - **(d) Event conservation** — folded into (b) via the convergence harness.
- [x] Task 6.10. **[DONE 2026-04-25]** `cargo test -p cgka-conformance-simulator --features conformance-slow` lifts proptest case counts to 200–1000 per property. With the richer 6.8/6.9 surface in place, the slow run actually has new ground to cover (Send+Leave under three delivery profiles, true replay, rollback round trips). Confirmed runtime: ~28 s for the slow profile.

### Phase 7 — Documentation + loose ends

- [x] Task 7.1. Add module-level doc comments on every `crates/cgka-engine/src/*.rs` module explaining its responsibility, its invariants, and which design-doc section it realises. Rationale: "well commented" is a non-negotiable per the user; module-level comments are the highest-ROI place.
- [x] Task 7.2. Update `docs/learnings.md` with a new dated entry noting the refactor is underway and pointing to the new `crates/` tree. No new design docs. Rationale: `docs/learnings.md:1-5` is the running log; keep it current without creating net-new doc sprawl.
- [x] Task 7.3. Document the three test tiers (unit, harness-scripted, harness-proptest) and how to run each. Originally landed as `crates/cgka-engine/tests/README.md`; replaced 2026-04-25 with `crates/cgka-engine/tests/AGENTS.md` as part of the README/AGENTS split (per-crate human-facing README + agent-facing AGENTS.md). Rationale: the test plumbing is non-obvious and without it the tests become write-only.
- [x] Task 7.4. Run `cargo clippy --all-targets -- -D warnings` and `cargo fmt --all -- --check` across the new workspace. Add these as CI gates if a CI config exists. Rationale: baseline hygiene for a codebase that expects future contributors.
- [x] Task 7.5. Verify the archived spike workspace still builds (`cd spike && cargo check`) after all root-workspace changes are in. Rationale: archive integrity check; we don't want to break the reference material.

---

## Verification Criteria

- Root-level `cargo check`, `cargo test`, `cargo clippy -- -D warnings`, and `cargo fmt --check` all pass.
- `spike/` workspace independently `cargo check`-s green.
- Every `EpochState` transition, every `StaleReason` variant, and every `EngineError` variant is exercised by at least one unit test.
- The 3-client happy-path harness scenario passes. The welcome-before-commit scenario reproduces `StaleReason::AlreadyAtEpoch`. The SelfRemove scenario converges without `ForkedEpoch`. The concurrent-invite scenario recovers to one deterministic winner and leaves both active clients at the same epoch/member set.
- Proptest suite runs default (small-case) in < 30s and passes in CI; the `--features conformance-slow` suite (1000+ cases) passes locally.
- `feature_status()` returns `Available` / `Upgradeable` / `Unavailable` correctly differentiated for a group with mixed-capability members (validating the `CapabilityStorage` cache closes the OpenMLS pub(crate) gap from `docs/learnings.md:125`).
- `invite()` with a KeyPackage missing a required capability returns `EngineError::MissingRequiredCapabilities { required, had }` with populated sets — no stringly-typed error leaks.
- No Nostr types appear anywhere in `crates/traits/`, `crates/cgka-engine/`, or `crates/storage-memory/`. (grep for `nostr` in those crates returns zero hits outside of test names / comments.)
- No use of `leave_group()` (non-SelfRemove) anywhere in `crates/cgka-engine/`. (grep check.)
- The wire-format-policy site has the review marker in place and is findable by grep.

## Potential Risks and Mitigations

1. **Earlier spike claim that OpenMLS per-leaf `Capabilities` is `pub(crate)` was a mis-diagnosis — not a real risk.**
   `LeafNode::capabilities()` has been public since OpenMLS ≥ 0.7.0 and remains public in 0.8.1 (verified upstream 2026-04-22). Correct access path: `group.public_group().leaf(idx)?.capabilities()` — the spike used `MlsGroup::member_at(idx)` which returns `Member` without capabilities. No fork, no upstream PR, no version bump needed. `CapabilityStorage` (Task 4.7) remains valuable as an *optimization* (cheap lookups, retained capabilities for removed members, consistency across tree mutations) but is no longer load-bearing for correctness. Corresponding claims in `docs/learnings.md:125` and `docs/marmot-architecture/further-context/spike-findings.md:282-287` are corrected alongside this plan.

2. **Fork recovery depends on snapshot fidelity and transport ordering fidelity.**
   Mitigation: `storage-memory` now snapshots OpenMLS memory state as well as CGKA metadata, and the harness proves rollback/replay under a controlled same-epoch commit race. Production storage must snapshot group-scoped OpenMLS rows atomically and retain/prune snapshots. Transport adapters must provide canonical timestamp/id ordering values; if the peeler wraps before final publish, a publish receipt may need to update the incumbent ordering key.

3. **Async-trait + `&dyn GroupContext` lifetime regression (spike-findings §1.4 / `docs/learnings.md:44`).**
   Mitigation: Task 3.6 keeps the four-method peeler trait using `&GroupContextSnapshot` (value type); Task 5.7 adds a compile-time `Box<dyn CgkaEngine + Send + Sync>` witness that will fail CI if anyone reintroduces a `&dyn` across an `.await`.

4. **Wire-format-policy choice locks us out of pure-ciphertext MLS, which matters once external consumers appear.**
   Mitigation: Task 4.10 keeps the decision visible (module-level comment + grep-able marker) and the code is isolated to one site. Revisiting is a local change when we cross that threshold.

5. **State-machine refactor balloons into a rewrite of OpenMLS wrappers.**
   Mitigation: Phase-4 subsystem boundaries are copied from `cgka-engine-design.md:214-233` and explicitly keep OpenMLS's MLS state machine intact (MDK shouldn't re-implement MLS per `cgka-engine-design.md:52`). Our state machine sits *above* OpenMLS, governing commit sequencing, not MLS semantics.

6. **Proptest invariants (Task 6.9) may flake on timing-dependent convergence assertions.**
   Mitigation: the in-memory bus is deterministic under a seeded scheduler (Task 6.1); "bounded steps" in the convergence property is a function of scenario size, not wall-clock time. Any flakiness points to a real non-determinism in the engine and is worth investigating rather than suppressing.

7. **Spike archive goes stale (no one runs its `cargo check`) and silently rots.**
   Mitigation: Task 7.5 gates the archive step on a green build; the archive is sealed intentionally, and staleness is acceptable (it's a reference, not a live dep). Accept the drift.

8. **Storage-trait churn mid-implementation.**
   Mitigation: Phase 2 lands in full before Phase 4 depends on it. The trait shape is fixed by design-doc text (`cgka-engine-design.md:236-312`) we've already committed to; storage implementations are behind a single type parameter so changing the backend mid-work is a small local diff.

## Resumption notes (for the next session)

### Honest scope of remaining work

| Item | Effort | Blocking? | Notes |
|---|---|---|---|
| ~~Task 4.13 full publish-before-apply~~ | ~~3-4 hr~~ | DONE | Landed 2026-04-25. See per-task table above + `crates/cgka-engine/src/publish.rs`. |
| ~~Task 6.8 proptest scenarios beyond AppMessage~~ | ~~2 hr~~ | DONE 2026-04-25 | Send + Leave + `DeliveryProfile` strategies in `proptest_support.rs`. |
| ~~Task 6.9 invariant (a) true replay + (c) rollback~~ | ~~2 hr~~ | DONE 2026-04-25 | `prop_true_same_id_replay` (uses `TransportBus::inject`) + `prop_upgrade_confirm_or_fail_round_trip`. |
| ~~Task 5.4 exhaustive capability matrix~~ | ~~1 hr~~ | DONE 2026-04-25 | `capability_matrix_36_cells` in `tests/capabilities.rs`. |
| ~~Task 4.2 `update_group_data` impl~~ | ~~1 hr~~ | DONE | Landed 2026-04-25 in `crates/cgka-engine/src/update_group_data.rs`. 5 tests in `tests/update_group_data.rs`. |
| ~~Task 2.2 snapshot/rollback wiring into engine~~ | n/a | DONE | Publish rollback still uses `MlsGroup::clear_pending_commit`; fork recovery uses `MessageStorage` snapshots. |
| ~~Task 6.10 broader slow gate~~ | n/a | DONE 2026-04-25 | `--features conformance-slow` runs 200–1000 cases per property; ~28 s wall time. |
| ~~Recovery observations in test vectors~~ | ~~1-2 hr~~ | DONE 2026-05-04 | `GroupEvent::ForkRecovered` + `ScenarioTrace::recoveries` capture winner/incumbent ordering keys, invalidated message, source epoch, and recovered epoch. |

**Status as of 2026-05-04:** every original task in this plan is closed. Future-roadmap items (SQLite storage, KeyPackage refresh scheduling, external vector fixture packaging, transport adapters, FFI) live in their own plans or the next implementation slice.

### What's left

1. **External vector fixture packaging.** `ScenarioTrace` now records recovery observations, but vectors still live as Rust tests. Next step is a language-neutral fixture format plus a runner contract.
2. **Production snapshot backend.** Superseded: `storage-sqlite` now snapshots
   group-scoped OpenMLS rows and CGKA metadata atomically. The remaining
   production question is operational pruning/retention policy, not the backend
   shape.
3. **Fork recovery key history.** Superseded: the first recovery sketch used `(TransportMessage::timestamp, MessageId)`. The current engine uses a content-derived key, `SHA-256(mls_bytes)` scoped by source epoch, so transport receipt metadata is no longer part of the recovery winner rule.

### What's solid (don't churn)

- **State-machine types in `cgka-traits`.** `EpochState`, `WelcomeState`, all the value types — the contract is locked. Snapshot tests in `crates/traits/tests/snapshots.rs` will fail loudly on accidental shape drift, including the `ForkRecovered` event shape.
- **Storage trait surface.** Five traits + accessor for OpenMLS storage. 18 round-trip + concurrency tests. SQLite backend follows the same shape — single new crate, no trait changes.
- **Engine subsystems boundaries.** `epoch_manager`, `capability_manager`, `auto_committer`, `group_lifecycle`, `message_processor`, `key_package`, `upgrade`, `group_data`, `wire_format`, `provider`, `identity` — each has a single responsibility documented at the top of its file.
- **Test tier organization.** `crates/cgka-engine/tests/AGENTS.md` documents the three tiers (cgka-traits unit, cgka-engine integration, cgka-conformance-simulator scenarios+proptest). `cargo test --workspace` is the canonical command.

### Where to look for context

- **Plan as written:** this file, with `[STATUS]` annotations on each task.
- **Spike learnings + corrections:** `docs/learnings.md` (2026-04-25 entry summarizes the refactor).
- **Historical spike findings:** the dedicated spike-findings document was
  removed with the archived spike tree. Use `docs/learnings.md` for retained
  corrections and the current specs in `docs/marmot-architecture/` for
  normative behavior.
- **Test layout:** `crates/cgka-engine/tests/AGENTS.md`.
- **Per-crate maps:** `crates/cgka-engine/AGENTS.md` (subsystem map + design deviations), `crates/cgka-conformance-simulator/AGENTS.md` (bus model + scenario authoring).
- **MIP-01 wire format:** the canonical reference is the spec; our `crates/cgka-engine/src/group_data.rs` is the implementation.

### Memory files relevant to this work

- `project_openmls_capabilities_access` — public-API gotchas around `LeafNode::capabilities()` and `MlsGroup::public_group()`.
- `feedback_openmls_accessor_pattern` — when to prefer accessor-based composition over hand-forwarding OpenMLS traits.
- `project_two_layer_addressing` — why `StaleReason::NotForThisClient` is not defense-in-depth.

### Run the tests on resume

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
```

Expected: all workspace tests and hygiene gates green.

---

## Alternative Approaches

1. **Build the engine directly, skip the separate `traits` crate.** Would save one crate boundary today but forces a larger refactor later when peelers and adapters want to depend on only the traits. Trade-off: worse future ergonomics for marginally-less-ceremony now. Rejected per question 8.

2. **Land SQLite storage in this plan too.** Gives a production-ready persistence story immediately. Trade-off: doubles Phase 2's scope, introduces migrations and test fixtures, and competes for attention with the state-machine work that is the actual point of the refactor. Better as a separate plan once the trait shape is proven.

3. **Expose fork recovery only as final convergence.** Lower public surface area, but future implementations could converge for the wrong reason and still pass vectors. Rejected for the next slice: trace observations should record the recovery path.

4. **Use `stateright` or `loom` for exhaustive model-checking instead of (or in addition to) proptest.** Stronger correctness guarantees at the cost of significant setup work and a steeper mental-model hurdle for future contributors. Property tests catch the same bug classes at far lower cost for the problem sizes we care about. Revisit only if proptest proves insufficient.

5. **Keep the mock peeler out — test against a real `NostrMlsPeeler`.** Would give end-to-end coverage but couples the CGKA engine tests to Nostr crypto + nostr-sdk async behaviour. We want the engine testable without Nostr; the real peeler gets its own tests in its own (future) crate.

6. **Use the existing `crates/cgka-engine` crate in place and grow it, rather than moving to a new layout.** Minimal churn, but the spike's module layout was throwaway and the storage trait surface needs to land somewhere. Moving once now is cheaper than growing-then-moving later.
