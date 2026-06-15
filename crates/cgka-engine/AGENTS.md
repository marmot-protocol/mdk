# AGENTS.md — cgka-engine

Agent-facing map of this crate. Read [`README.md`](README.md) first if you want the human framing.

## Quick orientation

This crate implements `cgka_traits::CgkaEngine` over OpenMLS 0.8.x. The engine is a **thin coordinator** above OpenMLS,
not a re-implementation of MLS. The state machine layered on top governs commit sequencing, fork detection/recovery,
capability negotiation, and MIP-03 admin policy — everything that OpenMLS does not enforce on its own.

- **You want to...:** Find the public surface
  - **Open...:** `src/engine.rs` (`Engine<S>`, `EngineBuilder`) — every `CgkaEngine` trait method dispatches from here

- **You want to...:** Understand the state machine
  - **Open...:** `src/epoch_manager.rs` + `cgka_traits::engine_state`

- **You want to...:** Trace an inbound message
  - **Open...:** `src/message_processor/mod.rs::do_ingest` (dispatched from `CgkaEngine::ingest` in `engine.rs`), then
    `src/message_processor/ingest.rs::ingest_group_message` for the peel → classify → apply body

- **You want to...:** Trace an outbound intent
  - **Open...:** `src/message_processor/mod.rs::do_send`, then the matching `do_send_*` in
    `src/message_processor/send.rs` (or the `do_*` in `group_lifecycle.rs` / `upgrade.rs`)

- **You want to...:** Add a feature capability
  - **Open...:** `src/feature_registry.rs` + tests in `tests/capabilities.rs`

- **You want to...:** Understand fork handling
  - **Open...:** `src/fork_recovery.rs` + `src/epoch_manager.rs::we_committed_from` + the `WrongEpoch` branch in
    `src/message_processor/ingest.rs`

- **You want to...:** Figure out auto-commit policy
  - **Open...:** `src/auto_committer.rs`

- **You want to...:** Touch wire-format policy
  - **Open...:** `src/wire_format.rs` (read the module-level comment first; this is a known revisit point)

- **You want to...:** Walk the test layout
  - **Open...:** [`tests/AGENTS.md`](tests/AGENTS.md)

## Subsystem map (every `src/` module)

Each module has a one-paragraph rustdoc at the top explaining its responsibility and which design-doc section it
realises. Read those rustdocs as the source of truth — this table is just an index.

- **Module:** `engine.rs`
  - **Owns:** `Engine<S>` struct, `EngineBuilder`, `CgkaEngine` impl, `drain_events` / `drain_auto_publish` queues

- **Module:** `identity.rs`
  - **Owns:** local signer + credential bundle

- **Module:** `provider.rs`
  - **Owns:** ad-hoc `OpenMlsProvider` adapter composed from crypto + storage

- **Module:** `feature_registry.rs`
  - **Owns:** runtime feature → capability-requirement registry

- **Module:** `capabilities.rs`
  - **Owns:** translation between `cgka_traits::Capability` and OpenMLS `Capabilities`

- **Module:** `capability_manager.rs`
  - **Owns:** `feature_status`, `upgradeable_capabilities`, write-through cache population

- **Module:** `key_package.rs`
  - **Owns:** `fresh_key_package` (no expiry; that's a higher-layer concern)

- **Module:** `group_lifecycle.rs`
  - **Owns:** `do_create_group`, `do_join_welcome`

- **Module:** `message_processor/` (`mod.rs`, `ingest.rs`, `send.rs`, `store.rs`)
  - **Owns:** inbound peel → classify → apply and outbound `SendIntent` dispatch including `do_send_invite` and
    `do_send_leave`; MIP-03 guards. `mod.rs` keeps the entry points dispatched from `engine.rs` (`do_ingest`,
    `do_send`, convergence/queue drains, `replay_buffered_messages`) plus shared helpers and re-exports; `ingest.rs`
    holds the inbound path (`ingest_group_message`, peel/snapshot recovery, `convergence_ingest_outcome`); `send.rs`
    holds the `do_send_*` outbound methods; `store.rs` holds durable persistence / dedup classification / stored-message
    state transitions.

- **Module:** `epoch_manager.rs`
  - **Owns:** only place that mutates `EpochState`; owns `PendingMeta` (group_id + prior_epoch + kind),
    `committed_from`, fork detection state

- **Module:** `fork_recovery.rs`
  - **Owns:** deterministic same-epoch commit ordering, pre-commit snapshot metadata, rollback-to-winner recovery

- **Module:** `publish.rs`
  - **Owns:** `do_confirm_published` (merges staged commit + mirrors Marmot/cache post-merge) and `do_publish_failed`
    (`MlsGroup::clear_pending_commit` + Marmot re-derive). The publish-before-apply contract lives here.

- **Module:** `auto_committer.rs`
  - **Owns:** the free function `decide(mls_group, proposal) -> AutoCommitDecision` — lowest-index auto-commit policy
    for SelfRemove proposals

- **Module:** `upgrade.rs`
  - **Owns:** `do_upgrade_group_capabilities` — promotes upgradeable MLS primitives through
    `GroupContextExtensions` and app-component requirements through `AppDataUpdate`

- **Module:** `app_components.rs`
  - **Owns:** MLS `app_data_dictionary` helpers, LeafNode/group `app_components` negotiation bytes, group profile
    bytes, and admin-policy bytes

- **Module:** `group_context_view.rs`
  - **Owns:** snapshot view of `GroupContext` for trait callers; `exporter_secret(label, length)` returns `None` rather
    than truncating when callers ask for more bytes than were cached

- **Module:** `snapshot_guard.rs`
  - **Owns:** RAII guard that rolls back + releases a snapshot on Drop; used by snapshot-probing call sites so panics or
    async cancellation don't leave storage in mid-mutation state

- **Module:** `wire_format.rs`
  - **Owns:** `PURE_PLAINTEXT_WIRE_FORMAT_POLICY` + the `WIRE_FORMAT_POLICY_REVIEW_REQUIRED` grep marker

- **Module:** `account_identity_proof.rs`
  - **Owns:** the Marmot account identity-proof LeafNode extension binding the account key to the MLS signature key

- **Module:** `app_payload.rs`
  - **Owns:** `validate_app_payload_for_sender` — `MarmotAppEvent` sender validation for application messages

- **Module:** `audit_helpers.rs`
  - **Owns:** stringification/extraction helpers that produce stable, low-cardinality forensic audit-log strings

- **Module:** `canonicalization.rs`
  - **Owns:** the executable post-peeling canonicalization-contract model (symbolic branches/messages above OpenMLS)

- **Module:** `convergence.rs`
  - **Owns:** the candidate-state-graph deterministic branch-selection policy

- **Module:** `distributed_convergence.rs`
  - **Owns:** the engine entry point for stored-message distributed convergence

- **Module:** `engine_metrics.rs`
  - **Owns:** engine-side diagnostic telemetry for post-settle convergence reorgs

- **Module:** `openmls_projection.rs`
  - **Owns:** bytes-first OpenMLS projection + canonicalization helpers, including Marmot record refresh on replay

- **Module:** `update_group_data.rs`
  - **Owns:** `SendIntent::UpdateGroupData` — stages an `AppDataUpdate` commit for `marmot.group.profile.v1`

## Design deviations (read these before changing the contract)

These are the load-bearing departures from the original plan. Each is also documented inline at the deviation site.

1. **Storage aggregate uses accessor composition, not direct supertrait.** `cgka_traits::StorageProvider` exposes
   `type Mls; fn mls_storage(&self) -> &Self::Mls` instead of being
   `: openmls_traits::storage::StorageProvider<CURRENT_VERSION>`. Hand-forwarding 50+ OpenMLS trait methods is
   mechanical churn with zero functional value. Site: `crates/traits/src/storage.rs` (`StorageProvider` aggregate with
   `type Mls` / `fn mls_storage`).

2. **`SendResult::GroupCreated { welcomes, pending }` is its own variant.** `GroupEvolution` carries a
   `msg: TransportMessage` that has no consumer at create-time (every other initial member arrives via welcome with
   post-commit state). Splitting the variant also eliminates a welcome-before-commit `AlreadyAtEpoch` bounce at
   creation. Site: `crates/traits/src/engine.rs::SendResult`.

3. **`CreateGroupRequest::initial_admins: Vec<MemberId>`.** Bootstraps multi-admin groups so admins can subsequently
   self-remove (MIP-03 §149's "not the last admin" constraint). Creator is implicitly an admin; `initial_admins` adds
   co-admins.

4. **The per-leaf capability cache is required for correctness, not a pure optimization.** `LeafNode::capabilities()` is
   public on OpenMLS, but `MlsGroup::public_group()` is `pub(crate)`, so there is no public API to walk to a specific
   leaf. The cache is populated from KeyPackages we directly handle (invite-side parses, `StagedCommit::add_proposals`)
   plus `MlsGroup::own_leaf_node()` for self.

5. **Group state is app-component state.** New groups do not create or read the legacy `marmot_group_data` extension.
   The engine writes `app_data_dictionary`, advertises supported component ids in LeafNode `app_components`, records
   required component ids in GroupContext `app_components`, and reads admin/profile state from component bytes.

6. **Test identities are 32 bytes via `pad32`.** Admin-policy pubkeys MUST be 32-byte x-only secp256k1. The engine
   strict-fails non-32-byte member identities at admin-set time. Production identities (real Nostr pubkeys) flow through
   unchanged.

## Recent audit corrections (2026-05-09)

A line-by-line engine audit closed a batch of correctness, privacy, and hardening items. Each fix has a regression test
in `tests/`; this section exists so a future contributor can grep for the rule that was put in place.

- **Item:** **B1** Convergence-side recipient Marmot record
  - **What changed:** `openmls_projection::update_group_record_from_replay` now also refreshes `required_capabilities`,
    `name`, and `description` from the post-replay MlsGroup so a GCE commit accepted via convergence doesn't leave the
    recipient's record stale.
  - **Test:** `tests/update_group_data.rs::convergence_refreshes_recipient_marmot_record_name_and_description`,
    `tests/capabilities.rs::convergence_refreshes_recipient_required_capabilities_on_upgrade`

- **Item:** **B3** `GroupContextView::exporter_secret` length contract
  - **What changed:** Returns `None` when the caller asks for more bytes than the cached secret holds, instead of
    silently returning a too-short prefix.
  - **Test:** `tests/group_context_view.rs`

- **Item:** **P1** Snapshot names must not embed plaintext group ids
  - **What changed:** `fork_recovery::next_snapshot_name` and the peel-restore name in `message_processor` now hash the
    group id into an 8-byte digest instead of hex-encoding the full id.
  - **Test:** `tests/snapshot_privacy.rs`

- **Item:** **S2** `Resolving` convergence status emission
  - **What changed:** `canonicalization::convergence_status_for_result` now emits `Resolving` when the input window has
    closed but a pending message did not receive a disposition this pass (e.g. a child commit waiting for its parent).
    `Settled` strictly requires fixed-point.
  - **Test:** `quiescence_with_orphan_commit_in_input_is_resolving` in
    `crates/cgka-conformance-simulator/tests/canonicalization_contract.rs`

- **Item:** **S3** Unattributable application messages
  - **What changed:** `message_processor::ingest_group_message` no longer emits `MessageReceived` with an empty
    `MemberId` for senders whose leaf credential cannot be resolved. The message is marked `Failed`; a typed sender
    variant on `GroupEvent` would be a larger API change deferred to v0.2.
  - **Test:** implicit (no event leak — covered by existing tests)

- **Item:** **Sm1** Atomic state-machine transitions
  - **What changed:** `EpochManager::confirm_publish` / `rollback_publish` / `begin_pending` clone the prior
    `EpochState` and run the fallible inner transition BEFORE mutating `states` / `committed_from` / `pending`. A
    failing inner transition no longer orphans the group's state map entry. `begin_pending` got this treatment in
    darkmatter#146 (it previously removed-before-transition, orphaning the group to `UnknownGroup` when staged from a
    non-`Stable` state). The auto-commit ingest arm also now requires `Stable` (`EpochState::is_stable`) before staging,
    so a `Recovering` group — which still accepts ingest — leaves the SelfRemove proposal queued instead of staging a
    commit that `begin_pending` would reject.
  - **Test:** `epoch_manager::tests::begin_pending_failure_leaves_state_intact` +
    `begin_pending_success_records_all_bookkeeping`; existing publish-lifecycle tests

- **Item:** **Sm2** Convergence ingest outcome classification
  - **What changed:** `message_processor::convergence_ingest_outcome` now reports `Stale` for terminal dispositions
    (`BeyondAnchor`, `LosingBranch`, `BeyondAppRetention`, dropped) and only `Buffered` for retryable cases
    (`UndecryptableInCanonicalState` for future-epoch app messages). The stored-convergence persistence path
    (`openmls_projection::persist_openmls_canonicalization_dispositions`) honours the same split: a
    `UndecryptableInCanonicalState` app message is persisted `Retryable` (not terminal `EpochInvalidated`), and
    `distributed_convergence` neither marks it seen nor emits `AppMessageInvalidated`, so it re-enters convergence
    once the awaited commit advances the epoch (darkmatter#144).
  - **Test:** covered by distributed-convergence integration tests, incl.
    `future_epoch_app_message_stays_retryable_until_commit_arrives`

- **Item:** **Sm3** Capability-cache self-id assertion
  - **What changed:** `cache_self_capabilities` now errors with `EngineError::Backend` if `MlsGroup::own_leaf_node()`
    reports an identity that disagrees with the engine's `self_id`.
  - **Test:** implicit (existing cache tests guard the happy path)

- **Item:** **Sm4** Welcome dedup at the API surface
  - **What changed:** `do_join_welcome` rejects a re-call for the same welcome via `seen_message_ids` and stored-message
    state.
  - **Test:** `tests/group_creation.rs::join_welcome_called_twice_for_same_welcome_errors_on_second_call`

- **Item:** **Sm5** `FeatureRegistry::register` warn on conflicting duplicate
  - **What changed:** Same feature registered with a different requirement now emits a `tracing::warn!` so the conflict
    surfaces in audits. Last-write still wins.
  - **Test:** static — observed via tracing-audit infrastructure

- **Item:** **Sm6** Replay error classification
  - **What changed:** `process_openmls_messages_inner` swallows only `ProcessMessageError::ValidationError` for
    application messages during replay — `LibraryError` and other structural failures propagate.
  - **Test:** covered by existing replay tests

- **Item:** **Sm7** Auto-committer §150 fail-closed
  - **What changed:** `auto_committer::decide` now refuses to auto-commit a SelfRemove if the leaver's
    credential is malformed (length ≠ 32) instead of treating that as "no admin to compare against."
  - **Test:** covered by existing MIP-03 guard tests

- **Item:** **H1** Snapshot rollback panic safety
  - **What changed:** New `crates/cgka-engine/src/snapshot_guard.rs::SnapshotRollbackGuard` rolls back + releases on
    `Drop`. Used by `try_peel_group_message_from_available_snapshots` and `replay_openmls_messages` so panics or async
    cancellation cannot leave storage in mid-mutation state.
  - **Test:** structural — panics in async are hard to assert directly

Items deliberately deferred:

- **H2 (AAD binding to group_id + epoch on transport wraps)** — exporter secrets already differ per (group, epoch).
  Cross-context attacks on the outer ChaCha20Poly1305 wrap require the exporter key, which is already per-context. AAD
  binding would be defense-in-depth without a concrete threat it foils. Reconsider if a future transport reuses exporter
  material across contexts.
- **H3 (zeroize `SignatureKeyPair`)** — `openmls_basic_credential` does not expose private bytes for zeroization.
  Implementing this requires either an upstream change or wrapping the signer in a custom type that re-implements
  OpenMLS's `Signer` trait. Tracked as upstream dependency, not engine work.
- **S1 strict publish-before-apply for auto-commit** — closed. Auto-publish work now carries a `PendingStateRef`;
  callers publish it and then use the shared `confirm_published` / `publish_failed` lifecycle.

## Open structural items

None in the engine core. Remaining production work sits around adjacent layers: relay auth and relay-policy wiring, app
key-management integration, external vector runners, WAL checkpoint/rekey policy, and KeyPackage refresh scheduling.

### Done — Task 4.2 `update_group_data` (2026-04-25)

`crates/cgka-engine/src/update_group_data.rs` stages an `AppDataUpdate` commit for
`marmot.group.profile.v1`, defers merge to `do_confirm_published`, and rolls back via `do_publish_failed`.
Admin-policy and routing-component updates are deliberately out of scope. Tests live in `tests/update_group_data.rs`.

### Done — Task 4.13 publish-before-apply (2026-04-25)

`do_create_group` / `do_send_invite` / `do_upgrade_group_capabilities` / auto-commit stage their commits and defer merge
until `CgkaEngine::confirm_published`. `CgkaEngine::publish_failed` discards via `MlsGroup::clear_pending_commit` +
Marmot re-derive from the still-unmerged group. The Marmot record holds _projected post-merge_ `members` so `members()`
and `feature_status` reflect the pending group evolution during `PendingPublish`. See `tests/publish_lifecycle.rs` and
`tests/invite_leave.rs` for the contract.

OpenMLS 0.8.1 surface used: `MlsGroup::pending_commit() -> Option<&StagedCommit>` (`mod.rs:353`),
`StagedCommit::export_secret` (`staged_commit.rs:778`, identical signature to `MlsGroup::export_secret`),
`MlsGroup::merge_pending_commit` (`processing.rs:307`), `MlsGroup::clear_pending_commit` (`mod.rs:374`).

### Done — ForkRecoveryManager (2026-05-04)

`crates/cgka-engine/src/fork_recovery.rs` owns deterministic same-epoch commit recovery. The ordering key is
authenticated: source epoch, commit priority (`privileged` before `ordinary`), authenticated committer identity, then
`SHA-256(mls_bytes)` as the same-committer fallback. Local and inbound commits create pre-commit snapshots; a better
late candidate rolls storage back and replays, while a losing candidate is marked stale. Successful rollback emits
`GroupEvent::ForkRecovered` so harness vectors can compare recovery
trace, not just final state. `EngineError::ForkedEpoch` is now the fallback for missing snapshots or unrecoverable
shapes. Tests: `tests/fork_detection.rs` plus the harness `deliberate_fork_via_harness`.

## Conventions in this crate

- **Only `EpochManager` may construct non-`Stable` `EpochState` variants.** This is enforced by visibility — the
  variants' fields are private. Don't add a public constructor for `Recovering` etc. somewhere else.
- **No Nostr library/SDK dependency.** These crates do not depend on any Nostr crate and use no Nostr SDK types. They
  do reference the `marmot.transport.nostr.routing.v1` app-component by id (`NOSTR_ROUTING_COMPONENT_ID`,
  `NostrRoutingV1`) and name Nostr concepts in comments (e.g. the kind-445 exporter label), so
  `grep -ri nostr crates/cgka-engine/src/` is no longer zero — grep the `Cargo.toml` deps instead to enforce the
  no-dependency invariant.
- **No `leave_group()` (the legacy MLS path).** Always `leave_group_via_self_remove` per MIP-03. This is grep-banned.
- **OpenMLS family is tilde-pinned in workspace `Cargo.toml`.** Don't relax to caret; silent companion-crate skew has
  broken this stack before.
- **Wire format is `PURE_PLAINTEXT_WIRE_FORMAT_POLICY`.** This is a deliberate 0.1.0 choice. Before changing it, read
  the module comment in `src/wire_format.rs` and the three alternative paths it links.

## Historical notes reflected here

- OpenMLS capability access: read `capability_manager.rs` before changing the cache.
- OpenMLS storage access: keep `StorageProvider::mls_storage()` as accessor composition.
- Two-layer addressing: `StaleReason::NotForThisClient` is engine-layer identity filtering as well as transport defense.
