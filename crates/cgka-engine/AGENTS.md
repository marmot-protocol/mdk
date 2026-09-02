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
  - **Open...:** the convergence admission gate (`commit_should_enter_convergence`) in
    `src/message_processor/ingest.rs` + `src/distributed_convergence.rs` — same-epoch rivals are adjudicated by
    distributed convergence for every member; the `WrongEpoch` branch retains and schedules an in-horizon rival whose
    source anchor is gone, and the coordinator's `MissingRetainedAnchor` verdict owns the durable halt. Post-fork
    traffic on an unadopted branch is unreadable until `openmls_projection::candidate_branch_peel` gives
    `Engine::retry_deferred_peels` that branch's own state — see "Branch-relative peel" below

- **You want to...:** Figure out SelfRemove auto-commit eligibility
  - **Open...:** `src/auto_committer.rs`

- **You want to...:** Touch wire-format policy
  - **Open...:** `src/wire_format.rs` (read the module-level comment first; this is a known revisit point)

- **You want to...:** Walk the test layout
  - **Open...:** [`tests/AGENTS.md`](tests/AGENTS.md)

## Subsystem map (every `src/` module)

Each module has a one-paragraph rustdoc at the top explaining its responsibility and which design-doc section it
realises. Read those rustdocs as the source of truth — this table is just an index.

- **Module:** `engine.rs`
  - **Owns:** `Engine<S>` struct, `EngineBuilder`, `CgkaEngine` impl, `drain_events` / `drain_auto_publish` /
    `drain_auto_proposals` queues

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
  - **Owns:** `fresh_key_package` and KeyPackage parse-time lifetime validity / OpenMLS accepted-range checks; refresh
    scheduling remains a higher-layer concern.

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
  - **Owns:** only place that mutates `EpochState`; owns `PendingMeta` (group_id + prior_epoch + kind)

- **Module:** `group_state_changes.rs`
  - **Owns:** pure, MLS-free before/after diff helpers that turn an applied commit's effect on canonical group state
    (admin set, profile name, avatar bytes) into `GroupStateChange` values, later surfaced as
    `GroupEvent::GroupStateChanged`

- **Module:** `publish.rs`
  - **Owns:** `do_confirm_published` (merges staged commit + mirrors Marmot/cache post-merge) and `do_publish_failed`
    (`MlsGroup::clear_pending_commit` + Marmot re-derive). The publish-before-apply contract lives here.

- **Module:** `auto_committer.rs`
  - **Owns:** the free function `decide_with_reason(mls_group, proposal) -> AutoCommitDecisionReport` — SelfRemove
    auto-commit eligibility for remaining non-target members (the report wraps an `AutoCommitDecision` plus a stable
    `reason` string)

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

- **Module:** `pending_commit_guard.rs`
  - **Owns:** `PendingCommitCleanupGuard` — RAII cleanup that clears an orphaned OpenMLS pending commit if a
    commit-producing send path is dropped or returns early before handing off a `PendingStateRef`

- **Module:** `wire_format.rs`
  - **Owns:** `PURE_PLAINTEXT_WIRE_FORMAT_POLICY` + the `WIRE_FORMAT_POLICY_REVIEW_REQUIRED` grep marker

- **Module:** `account_identity_proof.rs`
  - **Owns:** legacy account identity-proof LeafNode extension plus the current app-data component; proof
    construction/validation and strict legacy/current profile classification (including mixed-profile rejection)

- **Module:** `app_payload.rs`
  - **Owns:** `validate_app_payload_for_sender` — `MarmotAppEvent` sender validation for application messages

- **Module:** `audit_helpers.rs`
  - **Owns:** stringification/extraction helpers that produce stable, low-cardinality forensic audit-log strings

- **Module:** `canonicalization.rs`
  - **Owns:** the executable post-peeling canonicalization-contract model (symbolic branches/messages above OpenMLS)

- **Module:** `convergence.rs`
  - **Owns:** the candidate-state-graph deterministic branch-selection policy

- **Module:** `convergence_input.rs`
  - **Owns:** role-aware convergence scheduling classification that distinguishes commit edges, proposal
    dependencies, and potential application-message witnesses for pass opening, quiescence, and outbound gating

- **Module:** `conformance_snapshot.rs` (feature `test-conformance-snapshot`)
  - **Owns:** privacy-safe exact canonical-state (live MLS state or authenticated terminal disband tombstone) and
    aggregate pending-work projections consumed only by the conformance simulator. Terminal equality excludes
    device-local authorship metadata. These diagnostics never feed protocol selection or production telemetry.

- **Module:** `distributed_convergence.rs`
  - **Owns:** the engine entry point for stored-message distributed convergence

- **Module:** `engine_metrics.rs`
  - **Owns:** engine-side diagnostic telemetry for post-settle convergence reorgs

- **Module:** `openmls_projection.rs`
  - **Owns:** bytes-first OpenMLS projection + canonicalization helpers, including Marmot record refresh on replay and
    `candidate_branch_peel` (whether the graph is contested, plus candidate branch tips captured as owned peel
    contexts)

- **Module:** `update_group_data.rs`
  - **Owns:** `SendIntent::UpdateGroupData` — stages an `AppDataUpdate` commit for `marmot.group.profile.v1`

## Design deviations (read these before changing the contract)

These are the load-bearing departures from the original plan. Each is also documented inline at the deviation site.

1. **Storage aggregate uses accessor composition, not direct supertrait.** `cgka_traits::StorageProvider` exposes
   `type Mls; fn mls_storage(&self) -> &Self::Mls` instead of being
   `: openmls_traits::storage::StorageProvider<CURRENT_VERSION>`. Hand-forwarding 50+ OpenMLS trait methods is
   mechanical churn with zero functional value. Site: `crates/traits/src/storage.rs` (`StorageProvider` aggregate with
   `type Mls` / `fn mls_storage`).

2. **Founding creation never invents a group-message publication.** Current-profile creation returns
   `SendResult::FoundingGroupCreated { welcomes }`: the epoch-0 group and optional founding Add are already canonical,
   and each Welcome is an independent delivery obligation. The temporary explicit-legacy path retains
   `SendResult::GroupCreated { welcomes, pending }`. Neither variant carries a `msg: TransportMessage`, because every
   initial invitee arrives through a Welcome containing the post-Add state. Site:
   `crates/traits/src/engine.rs::SendResult`.

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

- **Item:** **S2** Explicit frozen-batch deferral
  - **What changed:** every admitted message receives a current disposition. A child commit missing its parent from the
    frozen batch is explicitly `deferred`, and the completed pass reaches its local fixed point instead of returning
    `Resolving`. Deferred rows remain replayable when later evidence opens another pass, but do not immediately reopen
    the unchanged completed pass.
  - **Test:** `frozen_batch_defers_orphan_commit_and_settles_at_fixed_point` in
    `crates/cgka-conformance-simulator/tests/canonicalization_contract.rs`

- **Item:** **S3** Unattributable application messages
  - **What changed:** `message_processor::ingest_group_message` no longer emits `MessageReceived` with an empty
    `MemberId` for senders whose leaf credential cannot be resolved. The message is marked `Failed`; a typed sender
    variant on `GroupEvent` would be a larger API change deferred to v0.2. Mirrored on the stored-convergence/replay
    seam (mdk#383): the replay ApplicationMessage arm pushes `Ignored` for an unresolvable sender, both seams share
    `app_payload::validate_app_payload_for_sender` (which rejects an empty `MemberId` outright), and
    `emit_application_replay_events` skips empty-sender observations as a backstop.
  - **Test:** `app_payload::tests` (empty-sender and pubkey-mismatch rejection);
    `tests/distributed_convergence.rs::convergence_app_message_with_unresolvable_sender_emits_no_event_and_lands_terminal`

- **Item:** **Sm1** Atomic state-machine transitions
  - **What changed:** `EpochManager::confirm_publish` / `rollback_publish` / `begin_pending` clone the prior
    `EpochState` and run the fallible inner transition BEFORE mutating `states` / `committed_from` / `pending`. A
    failing inner transition no longer orphans the group's state map entry. `begin_pending` got this treatment in
    mdk#146 (it previously removed-before-transition, orphaning the group to `UnknownGroup` when staged from a
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
    future-epoch `UndecryptableInCanonicalState` app message is persisted `Retryable` (not terminal
    `EpochInvalidated`), and `distributed_convergence` neither marks it seen nor emits `AppMessageInvalidated`, so it
    re-enters convergence once the awaited commit advances the epoch (mdk#144). At or below the resulting tip, the
    same reason is terminal and does emit the invalidation (mdk#995).
  - **Test:** covered by distributed-convergence integration tests, incl.
    `future_epoch_app_message_stays_retryable_until_commit_arrives` and
    `terminal_undecryptable_app_emits_invalidation_without_message_received`

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
  - **What changed:** `auto_committer::decide_with_reason` now refuses to auto-commit a SelfRemove if the leaver's
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

`do_send_invite` / `do_upgrade_group_capabilities` / auto-commit stage their commits and defer merge until
`CgkaEngine::confirm_published`. `CgkaEngine::publish_failed` discards via `MlsGroup::clear_pending_commit` + Marmot
re-derive from the still-unmerged group. Current-profile `do_create_group` is the founding exception: it atomically
makes epoch 0 and the optional founding Add canonical locally, publishes no ordinary group commit, and persists each
Welcome as independent retryable work. The temporary explicit-legacy create path retains the older pending behavior.
For pending evolutions, the Marmot record holds _projected post-merge_ `members` so `members()` and `feature_status`
reflect the pending change. See `tests/publish_lifecycle.rs`, `tests/group_creation.rs`, and `tests/invite_leave.rs`.

OpenMLS 0.8.1 surface used: `MlsGroup::pending_commit() -> Option<&StagedCommit>` (`mod.rs:353`),
`StagedCommit::export_secret` (`staged_commit.rs:778`, identical signature to `MlsGroup::export_secret`),
`MlsGroup::merge_pending_commit` (`processing.rs:307`), `MlsGroup::clear_pending_commit` (`mod.rs:374`).

### Done — fork-resolution route unification (2026-08-06, supersedes ForkRecoveryManager 2026-05-04)

Same-epoch rival commits are adjudicated by distributed convergence for every member — committer, observer, or
restarted committer alike. The durable source-epoch anchor (`openmls-retained-anchor-{epoch}`, retained on every
canonical advance) admits an in-horizon rival into the pass; own commits materialize from their commit-addressed
checkpoints (#1285); a missing in-horizon anchor fails closed loudly, with ingest retaining and scheduling the
unadjudicable rival and the convergence coordinator issuing the durable `Unrecoverable` +
`GroupEvent::GroupUnrecoverable` from the authenticated pass. The former pairwise fast-path (`ForkRecoveryManager`, `committed_from` routing,
send/apply-time `fork-` snapshots, `GroupEvent::ForkRecovered`) is deleted. The deterministic ordering key
(source epoch, `privileged` before `ordinary`, authenticated committer identity, digest fallback) lives on inside
branch selection, where valid branch depth outranks it. Tests: `tests/fork_detection.rs`, the route-equivalence
family in the conformance simulator.

**Branch-relative peel — the unified route's visibility half.** Branch selection ranks on valid commit depth and app
witnesses counted over *stored* inputs, and a group message is sealed under the **sender's** current-epoch exporter
secret with no epoch hint on the wire. So once two members commit from the same epoch, each branch's later traffic is
opaque to every device that adopted the other branch: it sits retained as `PeelDeferred`, contributes neither depth nor
witnesses, every committer over-scores its own branch, and the fork never heals. Candidate branch states are therefore
part of a group's *peel context*, not a separate mechanism.
`openmls_projection::candidate_branch_peel` materializes each candidate branch under a
`SnapshotRollbackGuard` and captures its tip's owned `GroupContextSnapshot`; the exporter secret is derived while the
branch state exists, so the transient state is rolled back before any (async) peel runs against it.
`Engine::retry_deferred_peels` then offers those contexts to every retained row through the ordinary ingest seam.

Gating, so the uncontested path pays no replay: the sweep returns before any context work on an empty backlog; context
collection stops at the cheap "two commits share a source epoch" check before any replay; at most
`MAX_CANDIDATE_BRANCH_PEEL_CONTEXTS` branches are materialized, one bounded replay each under a fresh budget of the
pass's shape. That cap is applied to candidates ranked by tip epoch then branch id, never to the BFS's own
shallowest-first completion order: both keys are content-derived, so peers holding the same evidence keep the same
branches, and a wide shallow fork cannot evict the deep branch that actually carries the post-fork traffic. Branch
*selection* is uncapped — a branch past the prefix can still win a pass and peels natively once adopted. Finally,
failure to enumerate branches (missing anchor, missing own-commit checkpoint, exhausted budget) yields no contexts
rather than an error — the pass, not this helper, owns every verdict. Because candidate branch
states are part of the peel context, `deferred_peel_context_fingerprint` folds in the stored commit graph: a newly
retained rival commit adds a readable context even when the live epoch and retained-anchor set are unchanged, and
without that term the sweep gate would stay armed exactly where it must not.

**Contested-ness and contexts are separate answers.** That shared-source-epoch check is the *only* thing that decides
whether the graph is contested, and `CandidateBranchPeel` carries it independently of the captured contexts, because
every path after it — released anchor, missing own-commit checkpoint, exhausted budget, fewer than two surviving
candidate paths, no tip captured — loses contexts without saying anything about whether the graph is split. Reading
contested-ness off an empty context set would report a fork as healed exactly when this device stopped being able to
see it. The two then drive different decisions and must stay split: `DeferredPeelSweep::is_contested` gates only the
drain policy (a contested sweep's recovered rows are one evidence set, so the drain waits for the whole batch), while
routing live-readable application traffic into the convergence seam keys on `has_branch_contexts` — a sweep holding no
rival state would only feed evidence to a pass that, having halted on the same checkpoint or the same budget, almost
certainly cannot read the rival branch either.

**Provenance rule.** A message readable *only* under a candidate branch context belongs to a lineage this device has
not adopted, so `ingest_group_message` routes it to the convergence seam and never to the direct apply — canonical
OpenMLS cannot accept it anyway (same epoch number, different epoch secrets), and this seam must derive nothing from
it. The peeled bytes are evidence of nothing on their own: the next pass's OpenMLS replay is what authenticates them,
and a failed peel is silence, never a verdict. Tests: `tests/epoch_sealed_transport.rs` (Tier 2 opts into production
epoch visibility through `support::epoch_sealed_peeler`), plus the `convergence-e2e-delivery/v1` and
`adversarial-reliability/app-witness-value/v1` families in the conformance simulator.

## Conventions in this crate

- **Mirror every ingest invariant on every inbound seam.** An inbound MLS message reaches application-visible state
  through two seams — **direct ingest** (`message_processor/ingest.rs::ingest_group_message`) and
  **stored-convergence/replay** (`openmls_projection.rs::process_openmls_messages_inner`, materialization and apply;
  this is also the fork-resolution seam — same-epoch rivals are adjudicated inside the convergence pass). Every
  sender-authentication, admin/identity-proof, app-payload, and component-retention check MUST run identically on
  both, through the *same* shared helper — never a seam-local re-implementation. Shared chokepoints:
  `identity::member_id_of_sender` (MLS `Sender` → validated `MemberId`) and
  `app_payload::validate_app_payload_for_sender` (payload + `&MemberId` → validated `MarmotAppEvent`; rejects an empty
  id). An application message whose sender cannot resolve to a validated member id is never surfaced as
  `MessageReceived` and never accepted into canonical state on any seam (direct: `Failed`; replay: `Ignored` →
  terminal disposition). Fork-resolution paths fail closed with typed errors — never `unreachable!`/`panic!` — on
  attacker-influenced input. When you add a guard to one seam, add it to the shared
  helper (or both seams) and extend the parity tests; a guard that exists on one seam only is a bug (see mdk#707).
- **Never derive durable terminal group state from unauthenticated inbound bytes.** "Fail closed" means refuse the
  input, not punish the group. The `WrongEpoch` arm in `message_processor/ingest.rs` is the sharp case: OpenMLS raises
  it from `validate_framing`, the FIRST statement of `decrypt_message`, strictly upstream of membership-tag and
  signature verification — so the message's claimed epoch is raw attacker input there, and for a *past* epoch it is
  unverifiable in principle (the membership key and the serialized group context that would authenticate it live in the
  epoch snapshot this arm has already found missing). A durable `unrecoverable` marker written from that claim let any
  member freeze a group with one fire-and-forget datagram. Retention, an audit row, and a scheduled convergence pass are
  the correct response; the terminal verdict belongs to a seam that has authenticated material, which for missing
  recovery material is the convergence coordinator's `MissingRetainedAnchor` halt. The same rule applies to durable
  *inputs*: a stored row keyed by an unverified claimed epoch steers a later pass just as effectively as a flag. If a
  hard stop is ever wanted for a genuine local anchor gap, evaluate that gap on a seam that reads no inbound bytes —
  session open / per-group full hydration — not here.
- **The retained rival stays pass-opening, so the verified repair must retire it.** The corollary of the rule above:
  because ingest leaves the rival in `Created` for the coordinator to adjudicate, and the pass seeder re-derives every
  retained commit's source epoch from its own wire bytes, an anchor-less rival keeps steering
  `openmls_projection::historical_replay_start_epoch` (the `min` over unresolved rows) back into
  `MissingRetainedAnchor`. Exiting the halt without evicting that input just re-halts the group on the next drain. The
  eviction belongs to the authenticated Welcome join, which already discards this device's live MLS copy: alongside
  `delete_convergence_pass`, `do_join_welcome` calls
  `openmls_projection::retire_commits_superseded_by_replacement_welcome` in the same transaction, terminalizing
  unresolved *commits* below the new copy's own `MlsGroup::epoch()`. Bound that retirement by locally derived
  authenticated epochs only, keep it to commits (application messages from the prior interval may still decrypt, which
  is why a replacement Welcome records `join_epoch = 0`), and do not move it to a seam that reads inbound claims.
- **Commit-derived group records and capability caches are atomic with the MLS apply.** Every durable projection of
  an accepted commit must share the transaction that mutates OpenMLS state, and every projection read/write error
  must propagate. This includes the Marmot group record, capabilities extracted from added KeyPackages, and the
  post-path self-capability refresh. On a failed direct apply, release its unowned recovery snapshot and schedule the
  retained commit for stored convergence; redelivery deduplicates against the retained content row and cannot itself
  repair the apply.
- **Hydration quarantine is enforced through `Engine::ensure_group_live`.** A quarantined group vanishes from every
  live surface (mdk#364 / #365): every public accessor that reads durable or MLS group state (`members`,
  `group_record`, `group_context`, `admin_pubkeys`, `app_component`, `app_components`, `feature_status`, capability
  queries, the safe-export family, `own_leaf_index`) calls `ensure_group_live` first and returns `UnknownGroup`; `do_send` and
  `converge_and_drain_queued_outbound_intents` refuse to run; `ingest_group_message` retains inbound input as
  `PeelDeferred` and classifies it `Stale { reason: Quarantined }`; `converge_stored_openmls_messages` reports a
  `Blocked` run without touching state; `retry_deferred_peels` skips the group. When you add a new accessor or data
  path that reads group state, add the gate — a path that bypasses it can silently un-quarantine a group via
  `set_stable`. Quarantine clears only through `retry_hydrate_quarantined_group` or an authenticated re-join welcome,
  both of which schedule retained input for replay.
- **Two-phase hydration (mdk#1161): session open seeds, full hydration promotes.**
  `hydrate_stable_groups_from_storage` is the cheap seed pass: per stored group it reads only the durable record —
  no MLS load, snapshot list, or message scan — seeds a provisional `Stable(record.epoch)` entry so `live_group_ids`
  keeps listing the group, restores disband/unrecoverable terminal state, seeds the inbound routing index from the
  durable `transport_group_routes` table, and adds the group to `unhydrated_groups`. An unhydrated group fails closed
  through the same `ensure_group_live` chokepoint with the retryable `GroupNotHydrated` (never a partial view);
  `&mut` entry points (send, ingest, convergence drains) call `ensure_hydrated` first, which retracts the provisional
  seed, runs the full per-group hydration, and on failure quarantines with exact open-time parity (including removing
  the epoch entry — a quarantined group must never hold one). `hydrate_all_stored_groups` is the eager compatibility
  path (seed + drain-all) used by `AccountDeviceSession::open` until the app-layer background pipeline lands, and it
  drains every seeded group — including unrecoverable ones, whose halt re-emits from full hydration exactly once per
  open. Durable route rows carry a `source_epoch` stamp refreshed at every commit apply: the seed trusts a group's
  route set only when a stamp matches the record epoch (a lagging stamp means a crash or write failure between the
  commit and the route refresh), and stale/route-less groups sit in `route_backfill_pending`. Ingest probes at most
  `ROUTE_BACKFILL_PROBES_PER_MISS` pending groups per unknown route (bounded per event — mdk#408's O(groups)
  amplification stays closed), removing an id only on successful indexing or the terminal no-routing-component
  disposition; MLS-load failures stay owned by hydration/quarantine. Route refreshes also retire durable rows the
  retained-history window (pinned v1 `max_rewind_commits`) has moved past, per routing-v1's overlap rule.
- **The durable `Group::epoch` is a mirror of the epoch manager, and hydration seeds the epoch manager from it.**
  Because those two stores read each other across a restart, every mirror write belongs to the same durable unit as the
  MLS state change it projects, and every mirror failure propagates — never best-effort. Write the record inside the
  transaction that merges the commit (`publish::do_confirm_published`, the inbound apply in `message_processor/ingest.rs`)
  or compensate the in-memory transition explicitly (`stage_auto_commit_for_queued_proposals`). A swallowed mirror error
  splits the two stores silently and the split resurfaces as a wrong epoch on the next session open. Undoing the apply
  is only half the obligation: the failed inbound apply must also hand the still-retained commit back to stored
  convergence via `schedule_pending_convergence_group`. Otherwise the group parks one epoch behind holding a durable
  commit nothing will ever apply.
- **A branch-selection withdrawal is provisional, so it is announced once and can be taken back.** A losing commit is
  parked `ConvergenceDeferred` — still a canonicalization input — precisely so a later pass holding deeper evidence can
  re-adopt it. Both halves of `distributed_convergence.rs` therefore key on the commit's stored state as it was BEFORE
  the pass's own disposition persistence ran (`pre_apply_commit_states`, captured outside the apply transaction):
  `emit_rolled_back_commits` announces `CommitRolledBack` + `GroupStateInvalidated` only for a commit this pass is
  parking, and `emit_revalidated_commits` emits `GroupStateRevalidated` when an accepted commit entered the pass parked.
  Reading the state after the apply cannot tell those apart — the persistence has already written `ConvergenceDeferred`
  for every deferral. The app side must mirror the asymmetry: its tombstone is terminal by default (#1608), and only the
  explicitly evidenced `GroupStateRevalidated` path clears a `SupersededByBranchSelection` row. Withdrawals under every
  other reason stay terminal on both sides.
- **Only `NonSelectedEligibleBranch` may drive a withdrawal.** `MissingCandidateParent` is the other commit deferral and
  it does not mean "branch selection put this commit on the losing side": `handle_commit` also reaches it when the pass
  selected NO branch at all, which is the case that actually occurs in practice. Withdrawing there would tombstone a
  device's own applied history on a pass that decided nothing — the same hazard
  `emit_superseded_processed_commits` guards with its `selected_tip.is_none()` early return.
- **Announce-once is paid for by derived-state reconciliation, not by a durable event queue.** `events_buf` is
  in-memory, so a crash between the convergence apply transaction and the app's projection loses an announcement that
  announce-once will never repeat. The repair is not a queue: a commit's branch-selection tombstone state is fully
  derivable from `cgka_messages.state`, and engine messages and `app_events` share one account database.
  `SqliteAccountStorage::diverged_branch_selection_withdrawals` reports the disagreements (`ConvergenceDeferred` with
  live rows owes a withdrawal; `Processed` with a `SupersededByBranchSelection` tombstone owes a revival) and
  `AppClient::reconcile_branch_selection_withdrawals` applies them on every account open. Keep that derivation total:
  if a future change makes a withdrawal mean something the stored disposition cannot express, it needs its own durable
  evidence rather than a widened event.

  The app timeline is not the only consumer that can lose the announcement. `GroupStateInvalidated` also retires the
  maintenance `DurableGroupEvolution` behind a superseded commit, and that consumer sits *after* the account layer's
  awaited relay publishes, so the window is network-wide rather than instantaneous.
  `AccountDeviceRuntime::reconcile_superseded_maintenance_from_state` is the matching derived-state repair, keyed on the
  same durable field: an evolution whose `signed_message_id` reads `ConvergenceDeferred` (parked) or `EpochInvalidated`
  (retired) is superseded. Note that the *own-commit* emitter, `emit_superseded_processed_commits`, has always
  announced once — it durably flips its record to `EpochInvalidated`, so a later pass no longer sees it as previously
  applied. That half of the hole predates announce-once. Both repairs flip forward only; `GroupStateRevalidated` has no
  account-layer consumer and neither reconciler un-marks a supersession.
- **Only `EpochManager` may construct non-`Stable` `EpochState` variants.** This is enforced by visibility — the
  variants' fields are private. Don't add a public constructor for `Recovering` etc. somewhere else.
- **`EpochManager::set_stable` only overwrites `Stable` and `Recovering`.** Every other state owes its exit to a
  specific transition and `set_stable` refuses it: `Unrecoverable` → `repair_to_stable` after a verified repair path,
  `PendingPublish`/`Merging` → `confirm_publish` or `rollback_publish`, the only transitions that also retire the
  group's `pending` entry (a blind overwrite drops the staged commit handle and strands that entry with its rollback
  epoch, leaving both exits to fail `InvalidTransition` off the freshly written `Stable`), `Disbanded` → nothing.
  Callers reach it only from the two overwritable states or from no state at all (inbound apply behind `can_ingest`,
  the outbound drain behind its `Stable`-only re-check, hydration on fresh state, create/join on a group that cannot be
  holding a publication), so a fired refusal means a new caller lost that gate — fix the caller, don't relax the
  refusal.
- **A held publication and an unresolved convergence input are mutually exclusive.** This is why the convergence pass
  needs no held-publication gate of its own, and it is the non-obvious half of the invariant above — read it before
  concluding that `converge_stored_openmls_messages*` is missing one because it takes any `EpochState`. Outbound:
  `should_queue_outbound_intent` settles convergence *before* staging anything, so an unresolved input diverts the
  intent to the retention queue and the group never leaves `Stable` — `begin_pending` is never reached. Inbound: once a
  publication is held, `can_ingest` is false, so an arriving commit is persisted as `Retryable` transport bytes for
  deterministic replay, never buffered as a convergence input. A pass run at that moment therefore has no branch to
  select and cannot reach `set_stable` with one. Both halves are pinned by
  `tests/publish_lifecycle.rs::a_publication_is_never_staged_while_a_convergence_input_is_unresolved` and
  `::an_inbound_commit_under_a_held_publication_is_retained_not_converged`.
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
