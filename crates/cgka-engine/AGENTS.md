# AGENTS.md — cgka-engine

Agent-facing map of this crate. Read [`README.md`](README.md) first if you want the human framing.

## Quick orientation

This crate implements `cgka_traits::CgkaEngine` over OpenMLS 0.8.x. The engine is a **thin coordinator** above OpenMLS, not a re-implementation of MLS. The state machine layered on top governs commit sequencing, fork detection/recovery, capability negotiation, and MIP-03 admin policy — everything that OpenMLS does not enforce on its own.

| You want to... | Open... |
|---|---|
| Find the public surface | `src/engine.rs` (`Engine<S>`, `EngineBuilder`) — every `CgkaEngine` trait method dispatches from here |
| Understand the state machine | `src/epoch_manager.rs` + `cgka_traits::engine_state` |
| Trace an inbound message | `src/message_processor.rs::ingest_inbound` |
| Trace an outbound intent | `src/message_processor.rs::do_send` (then the matching `do_*` in `group_lifecycle.rs` / `upgrade.rs`) |
| Add a feature capability | `src/feature_registry.rs` + tests in `tests/capabilities.rs` |
| Understand fork handling | `src/fork_recovery.rs` + `src/epoch_manager.rs::we_committed_from` + the `WrongEpoch` branch in `message_processor.rs` |
| Figure out auto-commit policy | `src/auto_committer.rs` |
| Touch wire-format policy | `src/wire_format.rs` (read the module-level comment first; this is a known revisit point) |
| Walk the test layout | [`tests/AGENTS.md`](tests/AGENTS.md) |

## Subsystem map (every `src/` module)

Each module has a one-paragraph rustdoc at the top explaining its responsibility and which design-doc section it realises. Read those rustdocs as the source of truth — this table is just an index.

| Module | Owns |
|---|---|
| `engine.rs` | `Engine<S>` struct, `EngineBuilder`, `CgkaEngine` impl, `drain_events` / `drain_auto_publish` queues |
| `identity.rs` | local signer + credential bundle |
| `provider.rs` | ad-hoc `OpenMlsProvider` adapter composed from crypto + storage |
| `feature_registry.rs` | runtime feature → capability-requirement registry |
| `capabilities.rs` | translation between `cgka_traits::Capability` and OpenMLS `Capabilities` |
| `capability_manager.rs` | `feature_status`, `upgradeable_capabilities`, write-through cache population |
| `key_package.rs` | `fresh_key_package` (no expiry; that's a higher-layer concern) |
| `group_lifecycle.rs` | `do_create_group`, `do_join_welcome`, `do_send_invite`, `do_send_leave` |
| `message_processor.rs` | inbound peel → classify → apply; outbound `SendIntent` dispatch; MIP-03 guards |
| `epoch_manager.rs` | only place that mutates `EpochState`; owns `PendingMeta` (group_id + prior_epoch + kind), `committed_from`, fork detection state |
| `fork_recovery.rs` | deterministic same-epoch commit ordering, pre-commit snapshot metadata, rollback-to-winner recovery |
| `publish.rs` | `do_confirm_published` (merges staged commit + mirrors Marmot/cache post-merge) and `do_publish_failed` (`MlsGroup::clear_pending_commit` + Marmot re-derive). The publish-before-apply contract lives here. |
| `auto_committer.rs` | `LowestIndexAutoCommitter` policy for SelfRemove (future policy hook) |
| `upgrade.rs` | `do_upgrade_group_capabilities` — the only GCE-commit construction site today |
| `group_data.rs` | MIP-01 `marmot_group_data` (`0xF2EE`) extension construction; `nostr_group_id` is CSPRNG to avoid creator-correlation leaks |
| `group_context_view.rs` | snapshot view of `GroupContext` for trait callers; `exporter_secret(label, length)` returns `None` rather than truncating when callers ask for more bytes than were cached |
| `snapshot_guard.rs` | RAII guard that rolls back + releases a snapshot on Drop; used by snapshot-probing call sites so panics or async cancellation don't leave storage in mid-mutation state |
| `wire_format.rs` | `PURE_PLAINTEXT_WIRE_FORMAT_POLICY` + the `WIRE_FORMAT_POLICY_REVIEW_REQUIRED` grep marker |

## Design deviations (read these before changing the contract)

These are the load-bearing departures from the original plan. Each is also documented inline at the deviation site.

1. **Storage aggregate uses accessor composition, not direct supertrait.**
   `cgka_traits::StorageProvider` exposes `type Mls; fn mls_storage(&self) -> &Self::Mls` instead of being `: openmls_traits::storage::StorageProvider<CURRENT_VERSION>`. Hand-forwarding 50+ OpenMLS trait methods is mechanical churn with zero functional value. Site: `crates/traits/src/storage.rs:120-130`.

2. **`SendResult::GroupCreated { welcomes, pending }` is its own variant.**
   `GroupEvolution` carries a `msg: TransportMessage` that has no consumer at create-time (every other initial member arrives via welcome with post-commit state). Splitting the variant also eliminates a welcome-before-commit `AlreadyAtEpoch` bounce at creation. Site: `crates/traits/src/engine.rs::SendResult`.

3. **`CreateGroupRequest::initial_admins: Vec<MemberId>`.**
   Bootstraps multi-admin groups so admins can subsequently self-remove (MIP-03 §149's "not the last admin" constraint). Creator is implicitly an admin; `initial_admins` adds co-admins.

4. **The per-leaf capability cache is required for correctness, not a pure optimization.**
   `LeafNode::capabilities()` is public on OpenMLS, but `MlsGroup::public_group()` is `pub(crate)`, so there is no public API to walk to a specific leaf. The cache is populated from KeyPackages we directly handle (invite-side parses, `StagedCommit::add_proposals`) plus `MlsGroup::own_leaf_node()` for self.

5. **MIP-01 `marmot_group_data` (`0xF2EE`) is owned by the engine, not by a transport adapter.**
   §149 / §150 admin guards must fire at commit-construction time, which is inside the engine. Transport-y fields (relays, image_*, nostr_group_id) are populated with placeholders that a future transport adapter refines. A future component-based MIP-01 split will retire this monolithic module.

6. **Test identities are 32 bytes via `pad32`.**
   MIP-01 admin pubkeys MUST be 32-byte x-only secp256k1. The engine strict-fails non-32-byte member identities at admin-set time. Production identities (real Nostr pubkeys) flow through unchanged.

## Recent audit corrections (2026-05-09)

A line-by-line engine audit closed a batch of correctness, privacy, and
hardening items. Each fix has a regression test in `tests/`; this section
exists so a future contributor can grep for the rule that was put in
place.

| Item | What changed | Test |
|---|---|---|
| **B1** Convergence-side recipient Marmot record | `openmls_projection::update_group_record_from_replay` now also refreshes `required_capabilities`, `name`, and `description` from the post-replay MlsGroup so a GCE commit accepted via convergence doesn't leave the recipient's record stale. | `tests/update_group_data.rs::convergence_refreshes_recipient_marmot_record_name_and_description`, `tests/capabilities.rs::convergence_refreshes_recipient_required_capabilities_on_upgrade` |
| **B2** `marmot_group_data.nostr_group_id` privacy | Engine now generates `nostr_group_id` via CSPRNG instead of copying the creator's pubkey. Two groups by the same creator have distinct routing tags. | `tests/group_data_routing_id.rs` |
| **B3** `GroupContextView::exporter_secret` length contract | Returns `None` when the caller asks for more bytes than the cached secret holds, instead of silently returning a too-short prefix. | `tests/group_context_view.rs` |
| **P1** Snapshot names must not embed plaintext group ids | `fork_recovery::next_snapshot_name` and the peel-restore name in `message_processor` now hash the group id into an 8-byte digest instead of hex-encoding the full id. | `tests/snapshot_privacy.rs` |
| **S2** `Canonicalizing` sync state emission | `canonicalization::sync_state_for_result` now emits `Canonicalizing` when the input window has closed but a pending message did not receive a disposition this pass (e.g. a child commit waiting for its parent). `Stable` strictly requires fixed-point. | `crates/cgka-conformance-simulator/tests/canonicalization_contract.rs::quiescence_with_orphan_commit_in_input_is_canonicalizing` |
| **S3** Unattributable application messages | `message_processor::ingest_group_message` no longer emits `MessageReceived` with an empty `MemberId` for senders whose leaf credential cannot be resolved. The message is marked `Failed`; a typed sender variant on `GroupEvent` would be a larger API change deferred to v0.2. | implicit (no event leak — covered by existing tests) |
| **Sm1** Atomic state-machine transitions | `EpochManager::confirm_publish` / `rollback_publish` clone the prior `EpochState` + `PendingMeta` before transitioning. A failing inner transition no longer orphans the group's state map entry. | covered by existing publish-lifecycle tests |
| **Sm2** Convergence ingest outcome classification | `message_processor::convergence_ingest_outcome` now reports `Stale` for terminal dispositions (`BeyondAnchor`, `LosingBranch`, `BeyondAppRetention`, dropped) and only `Buffered` for retryable cases (`UndecryptableInCanonicalState` for future-epoch app messages). | covered by distributed-convergence integration tests |
| **Sm3** Capability-cache self-id assertion | `cache_self_capabilities` now errors with `EngineError::Backend` if `MlsGroup::own_leaf_node()` reports an identity that disagrees with the engine's `self_id`. | implicit (existing cache tests guard the happy path) |
| **Sm4** Welcome dedup at the API surface | `do_join_welcome` rejects a re-call for the same welcome via `seen_message_ids` and stored-message state. | `tests/group_creation.rs::join_welcome_called_twice_for_same_welcome_errors_on_second_call` |
| **Sm5** `FeatureRegistry::register` warn on conflicting duplicate | Same feature registered with a different requirement now emits a `tracing::warn!` so the conflict surfaces in audits. Last-write still wins. | static — observed via tracing-audit infrastructure |
| **Sm6** Replay error classification | `process_openmls_messages_inner` swallows only `ProcessMessageError::ValidationError` for application messages during replay — `LibraryError` and other structural failures propagate. | covered by existing replay tests |
| **Sm7** Auto-committer §150 fail-closed | `LowestIndexAutoCommitter::decide` now refuses to auto-commit a SelfRemove if the leaver's credential is malformed (length ≠ 32) instead of treating that as "no admin to compare against." | covered by existing MIP-03 guard tests |
| **H1** Snapshot rollback panic safety | New `crates/cgka-engine/src/snapshot_guard.rs::SnapshotRollbackGuard` rolls back + releases on `Drop`. Used by `try_peel_group_message_from_available_snapshots` and `replay_openmls_messages` so panics or async cancellation cannot leave storage in mid-mutation state. | structural — panics in async are hard to assert directly |

Items deliberately deferred:

- **H2 (AAD binding to group_id + epoch on transport wraps)** — exporter
  secrets already differ per (group, epoch). Cross-context attacks on
  the outer ChaCha20Poly1305 wrap require the exporter key, which is
  already per-context. AAD binding would be defense-in-depth without a
  concrete threat it foils. Reconsider if a future transport reuses
  exporter material across contexts.
- **H3 (zeroize `SignatureKeyPair`)** — `openmls_basic_credential` does
  not expose private bytes for zeroization. Implementing this requires
  either an upstream change or wrapping the signer in a custom type
  that re-implements OpenMLS's `Signer` trait. Tracked as upstream
  dependency, not engine work.
- **S1 strict publish-before-apply for auto-commit** — closed. Auto-publish
  work now carries a `PendingStateRef`; callers publish it and then use the
  shared `confirm_published` / `publish_failed` lifecycle.

## Open structural items

None in the engine core. Remaining production work sits around adjacent
layers: relay auth and relay-policy wiring, app key-management integration,
external vector runners, WAL checkpoint/rekey policy, and KeyPackage refresh
scheduling.

### Done — Task 4.2 `update_group_data` (2026-04-25)

`crates/cgka-engine/src/update_group_data.rs` mirrors the `do_upgrade_group_capabilities` shape: stages a GCE commit that overwrites the `marmot_group_data` extension's `name` / `description` fields, defers merge to `do_confirm_published`, rolls back via `do_publish_failed`. Other extension fields (admin set, relays, image_*, disappearing_message_secs, version, nostr_group_id) are preserved verbatim. Admin-set updates and relay updates are deliberately out of scope. Tests: 5 in `tests/update_group_data.rs`.

### Done — Task 4.13 publish-before-apply (2026-04-25)

`do_create_group` / `do_send_invite` / `do_upgrade_group_capabilities` / auto-commit stage their commits and defer merge until `CgkaEngine::confirm_published`. `CgkaEngine::publish_failed` discards via `MlsGroup::clear_pending_commit` + Marmot re-derive from the still-unmerged group. The Marmot record holds *projected post-merge* `members` so `members()` and `feature_status` reflect the pending group evolution during `PendingPublish`. See `tests/publish_lifecycle.rs` and `tests/invite_leave.rs` for the contract.

OpenMLS 0.8.1 surface used: `MlsGroup::pending_commit() -> Option<&StagedCommit>` (`mod.rs:353`), `StagedCommit::export_secret` (`staged_commit.rs:778`, identical signature to `MlsGroup::export_secret`), `MlsGroup::merge_pending_commit` (`processing.rs:307`), `MlsGroup::clear_pending_commit` (`mod.rs:374`).

### Done — ForkRecoveryManager (2026-05-04)

`crates/cgka-engine/src/fork_recovery.rs` owns deterministic same-epoch commit recovery. The ordering key is content-derived: `SHA-256(mls_bytes)` scoped by source epoch, with lexicographically lower digest winning. Local and inbound commits create pre-commit snapshots; a better late candidate rolls storage back and replays, while a losing candidate is marked stale. Successful rollback emits `GroupEvent::ForkRecovered` so harness vectors can compare recovery trace, not just final state. `EngineError::ForkedEpoch` is now the fallback for missing snapshots or unrecoverable shapes. Tests: `tests/fork_detection.rs` plus the harness `deliberate_fork_via_harness`.

## Conventions in this crate

- **Only `EpochManager` may construct non-`Stable` `EpochState` variants.** This is enforced by visibility — the variants' fields are private. Don't add a public constructor for `Recovering` etc. somewhere else.
- **No Nostr types anywhere.** Grep test: `grep -ri nostr crates/cgka-engine/src/` returns zero hits. Same for `crates/traits/`, `crates/storage-memory/`, and `crates/storage-sqlite/`.
- **No `leave_group()` (the legacy MLS path).** Always `leave_group_via_self_remove` per MIP-03. This is grep-banned.
- **OpenMLS family is tilde-pinned in workspace `Cargo.toml`.** Don't relax to caret; silent companion-crate skew has broken this stack before.
- **Wire format is `PURE_PLAINTEXT_WIRE_FORMAT_POLICY`.** This is a deliberate 0.1.0 choice. Before changing it, read the module comment in `src/wire_format.rs` and the three alternative paths it links.

## Historical notes reflected here

- OpenMLS capability access: read `capability_manager.rs` before changing the cache.
- OpenMLS storage access: keep `StorageProvider::mls_storage()` as accessor composition.
- Two-layer addressing: `StaleReason::NotForThisClient` is engine-layer identity filtering as well as transport defense.
