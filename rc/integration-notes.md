# MDK 0.19.0 → 0.20.0-rc.3 Integration Guide

## Scope and provenance

- **Baseline:** `v0.19.0` (`3fce95465cdea1edc8456dbd1c6691d1c8dc1f2e`)
- **Target:** `0.20.0-rc.3` (`7847b7f7ae761d41dc07784cd0308c29127b7ff9`)
- **Classified SemVer impact:** `minor`

## Impact triggers

- UniFFI breaking ABI changes (11): changed UniFFI type `LocalSendStatusFfi`, changed UniFFI type `MarmotEventFfi`, changed UniFFI type `MarmotKitError`, changed UniFFI type `MarmotOptions`, changed UniFFI type `NotificationTrafficClassFfi`
- C ABI breaking changes (11): changed C type `MarmotClientOptions`, changed C type `MarmotEvent`, changed C type `MarmotEvent_Tag`, changed C type `MarmotLocalSendStatus`, changed C type `MarmotNotificationTrafficClass`
- SQLite storage migrations (14): migrations.rs, migrations.rs, 0219_agent_item_order.rs, 0220_chat_activity_creation_fallback.rs, 0221_agent_item_expired_targets.rs
- Pending changelog.d fragment contains `### Breaking changes`
- Commit trailer `Release-Impact: minor` (8): 2376a640d (Start empty account databases from a migration baseline (#3609)), 3cb8e4a86 (Add unified opt-in onboarding flags across Rust, UniFFI, and C (#3775)), a3228a2c5 (Retire dead reconcile_subscription stack and bound dry-run NEG deadline (#3789))

## Storage migrations (required upgrade coordination)

This release advances the SQLite account schema. Downgrade across these migrations is unsupported; update all processes opening the account database together:

- `crates/nostr-directory/src/cache/migrations.rs`
- `crates/storage-sqlite/src/base/migrations.rs`
- `crates/storage-sqlite/src/base/migrations/0219_agent_item_order.rs`
- `crates/storage-sqlite/src/base/migrations/0220_chat_activity_creation_fallback.rs`
- `crates/storage-sqlite/src/base/migrations/0221_agent_item_expired_targets.rs`
- `crates/storage-sqlite/src/base/migrations/0222_small_state_broadcast_devices.rs`
- `crates/storage-sqlite/src/base/migrations/0223_local_deletion_invitation.rs`
- `crates/storage-sqlite/src/base/migrations/0224_epoch_gap_evidence_floor.rs`
- `crates/storage-sqlite/src/base/migrations/0225_welcome_delivery_ledger.rs`
- `crates/storage-sqlite/src/base/migrations/0226_local_submission_refused.rs`
- `crates/storage-sqlite/src/base/migrations/0227_welcome_expiry_mark.rs`
- `crates/storage-sqlite/src/base/migrations/0228_canonicalize_group_id_hex.rs`
- `crates/storage-sqlite/src/base/migrations/baseline.sql`
- `crates/storage-sqlite/src/shared/migrations.rs`

## Summary of changes

### Breaking changes

- Added explicit local queue-backpressure variants (`SliceReply::Busy`, `SecondReply::Busy`, `IdsReply::Busy`, `SweepEnd::LocalBusy`, `CompareEnd::LocalBusy`, `DirectoryInspectionError::LocalBusy`, and internal `FiniteEnd::Busy`) so local finite-request admission timeouts are never misclassified as relay `Unreachable`/`TimedOut` faults or silent record absence.
- Rust callers can inject an `EntropySource` for engine draws and kind-445 sealing and signing (mdk#3497).
  `NostrMlsPeeler::new` takes an entropy source and a wall clock. Use `Default` for system sources.
  Pass a clock to `NostrTransportEvent::new_unsigned`, or use `new_unsigned_at` with an explicit timestamp.
- Added `follows_created_at: u64` to `nostr_directory::UserDirectoryRecord` and `storage_sqlite::PublicDirectoryUserRecord`, and `created_at: u64` to `nostr_directory::FetchedFollowList`, backed by schema migrations `0004_follows_created_at` (directory cache) and `0006_directory_follows_created_at` (shared storage).
- `fs_private::create_dir_all_private` now routes Unix path creation through `prepare_directory_path`, refusing
  user-owned symlinked ancestors and world-writable aliases such as `/tmp` on macOS (allowing only trusted root-owned
  platform aliases and preserving the current directory `.` without altering its mode) (mdk#3799).
- `marmot_account::AccountHome` now rejects Windows-reserved device names (`CON`, `CONIN$`, `CONOUT$`, `PRN`, `AUX`,
  `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`, and superscript variants), leading/trailing spaces, trailing dots, and
  Windows-forbidden filename characters on newly created or imported account labels across all platforms (existing Unix
  account records remain readable, updatable, and removable), `AccountHome::account_dir` now panics on unsafe
  path-traversal labels (use `try_account_dir` for untrusted input), and local-file secret reads (`secret.json`) now
  refuse group/world/executable/special permission bits with `PermissionDenied` (fix with `chmod 600`) (mdk#3799).
- `MarmotAppEventError::Json` now carries a closed `MarmotAppEventJsonError` category instead of raw parser text,
  `SecretBytes` is now a redacted-`Debug` zeroizing newtype returned by `open_history` and `open_with_recovery_key`,
  `DeviceRosterV1::leaf_tag_key` is wrapped in `Zeroizing<[u8; 32]>`, and `GroupBlossomImageV1`,
  `AppGroupImageComponent`, and `RecoveryWords` implement `Drop` and `ZeroizeOnDrop` (mdk#3796).
- Removed the retired pre-#2660 `NostrSdkRelayClient::reconcile_subscription`, `NostrTransportAdapter::record_reconciliation`, and `NostrReconciliation*` types from `transport-nostr-adapter` (along with the doc-hidden `reconcile_inbox_history` / `reconcile_group_history` wrappers on `transport-nostr`). Account history recovery uses `sweep::run_sweep` and `compare::run_comparison` over `SdkSweepRelay`.
- `storage-sqlite` now enforces `SqliteStorageOptions::cipher_compatibility` and
  `SqlCipherHardening::cipher_compatibility` (`1..=4`) after `PRAGMA key` with no silent format fallback, and rejects
  unsupported values outside `1..=4` before keying. Default `cipher_compatibility = 4` databases are unaffected; callers
  that previously created a database with a non-default value (such as `3`) produced a SQLCipher v4 file on disk and
  must reopen it with `cipher_compatibility = 4` (or migrate/rekey it offline).
- `OutboundWelcomeStatus::PastDeadline` is a Welcome past its delivery deadline that is not marked expired yet;
  `Settled(WelcomeSettlement::Expired)` now means a Welcome marked expired, at any clock (mdk#3589).
- `Engine::own_account_leaves_tagged_by` returns each leaf's signature key with the slot its tag read as.
- `Engine::queue_app_message_with_audit_context` takes the intent's `only_to_members`.
- Implement `EntropySource::fill_bytes` to supply engine randomness. The system default is `OsEntropy`.
  Direct callers of `Identity::load_or_generate` pass the MLS crypto provider used to generate new signers (mdk#3497).
- `open_history`, `open_with_recovery_key`, and the corresponding `Engine` methods now return redacted-`Debug`
  zeroizing `SecretBytes` instead of `Vec<u8>` (mdk#3796).
- `LocalSendStatus` gains `RefusedNewMembers`, and `Queued` and `EngineOwned` carry the send's `message_id_hex`, so a
  host that lost the acceptance learns the event by asking rather than by handing the send again.
- Kinds 1201 and 1202 take the shape of marmot-agents D-076, and the old shape is gone (D-051): an agent item
  (kind 1201) and an answer or a control (kind 1202) are sent with `submit_custom_event` or `send_custom_event`, which
  check their shape and refuse one over `AGENT_EVENT_MAX_BYTES` (64 KiB). MDK names a turn's starting message with a
  `started_by` tag, not `e`. `send_agent_activity`, `send_agent_operation_event`, `AgentOperationEventRequest` and the
  `AppMessageIntent::AgentActivity` and `AgentOperation` variants are removed, and kinds 1201 and 1202 are no longer
  reserved app event kinds.
- `NotificationTrafficClass::AgentActivity` is removed. An agent item notifies on the standard class only while its
  latest version is a waiting approval or question, or a failed turn; other items, every kind 1202 and a chat message
  tagged `["phase", "commentary"]` do not notify. Each alerting version is delivered once, live or after the subscription
  catches up, under the key of the item's first event, so the host replaces the earlier notification; a reaction to an unreadable item previews nothing.
- A message's `NotificationUpdate::notification_key` names its chat (`message:<account>:<group>:<message id>`). Event
  ids carry no chat, so one chat's alert no longer replaces another's for the same id.
- Whether a send wakes the group's members is read from the sent event, so a send resumed after a restart wakes them
  exactly as the first attempt would: a chat message tagged `["phase", "commentary"]`, also as a reply, wakes nobody,
  and an agent item or a new version of one wakes members only while it needs a person or its turn failed.
- `TimelineUpdateTrigger::AgentActivity` becomes `AgentItem`, and `AgentOperation` is removed: a kind 1202 has no
  timeline row.
- `TimelineMessageRecord::canonical_order_key` gains the agent item `seq` before the message id.
- `AppError` gains `IncompatibleKeyPackage(Box<EngineError>)`. When a complete lookup finds only KeyPackages incompatible
  with a new direct chat's founding requirements, the start returns this variant in place of `AppError::Session`.
  Handle it in exhaustive matches. `as_engine_error` still exposes the cause (#3604).
- `RecoveryWords` and `AppGroupImageComponent` now implement `Drop` and `ZeroizeOnDrop` to erase secret buffers on
  drop; callers taking ownership of fields should borrow or use `std::mem::take` (mdk#3796).
- `MarmotLocalSendStatus::state` gains `4`: refused because the group gained a member account the send leaves out.
  The struct gains a nullable `message_id_hex` after `summary`, the send's event while MDK holds it (states 0 and 1).
  Rebuild clients with the matching header and library.
- `MarmotTimelineMessageRecord` gains a nullable `agent_item: MarmotAgentItem *` after `group_system`, and
  `agent_item_first_event_missing: bool` after it: true for an agent item whose first event this device does not
  hold, such as one that began before the member joined.
  `MarmotTimelineUpdateTrigger`'s `AgentActivity` becomes `AgentItem` and `AgentOperation` is removed, which
  renumbers the later variants; `MarmotNotificationTrafficClass` loses `AgentActivity`. Rebuild clients with the
  matching header and library.
- Add the public avatar acquisition option to `MarmotClientOptions`, changing its layout. Recompile C consumers with the matching header and library.
- Add pinned retention fields to `MarmotTimelineReplyPreview`. Rebuild consumers with the matching header and library.
- `LocalSendStatusFfi` gains `RefusedNewMembers`, for a send limited to member accounts that the group gained a member
  it leaves out. `Queued` and `EngineOwned` carry the send's `message_id_hex`.
- Swift: cancelling a `Task` that awaits a throwing async call, a command or a receive, now cancels its native future
  and throws `CancellationError` (mdk#3670). Before, the call ran to completion and returned its result. A call that
  completed first still returns its result, and calls whose work must finish, such as `shutdownAndClose()`,
  `removeAccount()`, `signOut()`, `signOutAndWipe()` and the `login*` calls, still wait. The four projection `nextCancellable()` adapters now report a native error that
  completed before the cancel instead of `CancellationError`.
- `TimelineUpdateTriggerFfi::AgentActivity` becomes `AgentItem` and `AgentOperation` is removed;
  `NotificationTrafficClassFfi::AgentActivity` is removed. An agent item notifies as `Standard` only while it is a
  waiting approval or question, or a failed turn.

- `MarmotKitError` gains `IncompatibleKeyPackage`. Update exhaustive Swift `switch` and Kotlin `when` expressions to
  handle it, and regenerate bindings with the matching native library. For this error, ask the recipient to update
  their client and publish a compatible KeyPackage (#3604).
- Schema migration 0227 gates the stored-message payload tag 16, which carries an owed outbound Welcome's expiry mark
  (mdk#3589). The migration changes no table; older binaries refuse schema 227, because they cannot decode that tag
  and would read a Welcome marked expired as withdrawn. Downgrade is not supported.
- `SqliteAppStorage::recovery_coverage_newest_released` takes the routes to read and returns each one's newest
  released second, from one look at the ledger. Callers that passed a `since` keep only a second at or after it.
- Account migration 0226 rebuilds `local_message_submissions` to admit state 4, a token send refused because the group
  gained a member account its member list leaves out, and indexes refused sends. It fences older binaries, which
  would send a retained member-limited send without its list. Older binaries refuse schema 226; downgrade is
  unsupported. `SqliteAppStorage::refuse_local_submission`, `invalidate_refused_local_sends_for_group` and
  `groups_with_refused_live_local_sends` are new, and retiring a queued application message refused for a new member
  settles its local send in the same transaction.
- Migration 0219 adds `message_timeline.timeline_order_seq`, rebuilds the canonical order index with it before the
  message id, and drops kind-1202 timeline rows. `TimelineMessageRecord` gains `agent_item` and
  `timeline_order_seq`, and `TimelineUpdateTrigger::AgentActivity`/`AgentOperation` become `AgentItem`.
- Account migration 0225 adds `cgka_welcome_delivery_ledger`, one record per outbound Welcome's delivery
  (mdk#1706). Older binaries refuse schema 225; downgrade is unsupported.
- Migration 0221 adds `agent_item_expired_targets`: the retention sweep records each agent item whose row it removed,
  so an edit of it that arrives later does not show it again. A sweep from before the migration is not recorded, so
  on a nightly build's database a late edit of an item removed then can still show it.
- Account migration 0223 adds the invitation standing (`pending_confirmation`, `welcomer_account_id_hex`,
  `via_welcome_message_id_hex`) to `local_group_deletion_frontiers`. Older binaries refuse schema 223; downgrade is
  unsupported.
- `StorageOpenProgress` is now `#[non_exhaustive]` and adds `StorageOpenProgress::MigrationBatchFinished`, which
  reports the number of ledger entries committed by the fresh-account baseline. Exhaustive matches outside
  `storage-sqlite` need a wildcard arm (and may handle `MigrationBatchFinished`).
- `MoveRejectedSlot` drops `tag_signature_key`: a move's carried `removed` records go into the destination with no
  key (marmot#520). Facts captured before keep reading; the stored key is ignored.
- `SqliteStorageOptions::cipher_compatibility` and `SqlCipherHardening::cipher_compatibility` (`1..=4`) are now
  enforced after `PRAGMA key` with no silent format fallback, and unsupported values outside `1..=4` are rejected before
  keying. Default `cipher_compatibility = 4` databases are unaffected; callers that previously created a database with a
  non-default value (such as `3`) produced a SQLCipher v4 file on disk and must reopen it with
  `cipher_compatibility = 4` (or migrate/rekey it offline).
- `StoredMessagePayload::OutboundWelcome` gains `expiry: Option<message::WelcomeExpiry>`, the durable expiry mark
  of an owed outbound Welcome (mdk#3589), stored as payload variant 16; a Welcome without one keeps its bytes, and a
  staged Welcome never carries one. `welcome_expiry` and `with_welcome_expiry` read and set it.
- `OpenMlsContentFilter::NoOpenMlsMessage` lets a listing read only rows whose payload carries no OpenMLS message,
  such as retained outbound Welcomes.
- `RosterTagKeyStorage` gains `renew_roster_tag_keys`, which moves the sighting time of a slot's unexpired keys in one
  step and keeps their order (mdk#3679).
- `SendIntent::AppMessage` gains `only_to_members`: the member accounts the payload may reach. The engine checks the
  group's member accounts when it encrypts, so a send queued while an Add merged is refused
  (`EngineError::AppMessageNewMembers`, new) rather than sent to the new member. `None` keeps today's behavior.
- `OutboundIntentStorage::retire_refused_queued_outbound_intent` (defaulting to a delete) retires a queued intent the
  settled state refused, given the refusal's kind, so a host's storage can settle its own state in the same
  transaction.
- `MARMOT_APP_EVENT_KIND_AGENT_ACTIVITY` and `MARMOT_APP_EVENT_KIND_AGENT_OPERATION` become
  `MARMOT_APP_EVENT_KIND_AGENT_ITEM` and `MARMOT_APP_EVENT_KIND_AGENT_REQUEST`, and the old shape's tag constants
  (`AGENT_ACTIVITY_STATUS_TAG`, `AGENT_OPERATION_*_TAG`) are removed.
- Implement `EntropySource::fill_bytes` to supply entropy (mdk#3497). The default `next_u64` reads eight
  little-endian bytes from that source.
- `RosterTagKeyStorage` gains `hold_roster_tag_keys_as_removed`, which marks a slot's unexpired keys as held as
  removed, unless one already is, without moving their sighting times or order: the engine calls it for a `removed`
  record that keeps no key (marmot#520). `SendIntent::RecordRemovedSlot` now carries a record with no `tag_signature_key`.
- `MarmotAppEventError::Json` now carries a closed `MarmotAppEventJsonError` category instead of a raw `String`,
  `SecretBytes` is now a zeroizing newtype with redacted `Debug` output, `DeviceRosterV1::leaf_tag_key` is
  `Zeroizing<[u8; 32]>` with redacted `Debug` output, and `GroupBlossomImageV1` implements `Drop` and
  `ZeroizeOnDrop` to erase key material on drop (mdk#3796).

### Added

- Hosts can tell a user that their published inbox list keeps invitations sent through it from reaching them:
  `account_relay_health` lists each relay of the account's inbox and NIP-65 lists with its roles and whether the relay
  policy allows it, and raises a `Critical` warning for a published inbox list that is empty or allows no relay
  (including the fallback to the default relays, which raised nothing before), a `Warning` for refused entries beside
  allowed ones and a `Notice` for a single allowed inbox relay, in MarmotKit and C. `RelayHealthChanged` reports changes
  that come from the relay lists only, never a relay connecting or disconnecting; connection changes come from the
  existing `subscribe_relay_liveness`. It reads only held data and never dials; an inbox list MDK does not hold yet
  raises no warning.
- C and MarmotKit can durably submit tagged text, inline replies, NIP-22 thread messages with attachments, and pack
  stickers. Retrying the same accepted request with its original client token after restart returns the original ID.
- Hosts can read whether each invite reached the invited account's inbox relays: `invite_deliveries` returns one
  durable answer per group and invited account (`Waiting`, `Sending` with the latest problem, `RelayAccepted`,
  `Undeliverable` or `Cancelled`, with device and relay counts), and `InviteDeliveryChanged` reports each change, in
  MarmotKit and C (mdk#1706). `RelayAccepted` means a relay stored the Welcome, not that the recipient received it.
  Only invites sent after the upgrade are listed; an older Welcome stays in `pending_welcome_deliveries`.
- Added `FiniteRequests::shutdown` in `transport-nostr-adapter` to reject new finite requests, retire active slots (suppressing unsent REQs and sending `CLOSE` for already-sent active requests on live clients), end active/waiting requests as `Disconnected`, and join tracked `send_msg(req)` and `CLOSE` cleanup tasks (also invoked by `NostrSdkRelayClient::shutdown`).
- Hosts can tell a user that an inbox relay refused to serve their invitations: `check_account_relays` asks each of the
  account's inbox relays once for its gift wraps, on a connection of its own, and marks a relay `Healthy` when it
  answers, `Failing` when it gives an explicit policy refusal to the account's own key (authentication refused as
  restricted, blocked or payment-required; payment required; restricted or blocked), and `Suspected` when the check
  could not verify it. A `Warning` names a failing inbox relay beside a usable one, and the existing `Critical` also
  fires once every inbox entry is refused or failing. The account worker runs the check, once at each start for an
  account whose own key signs and on request; results belong to the running account and are never stored. A check no
  relay answered changes nothing. A request while a check runs is refused at once with the new `RelayCheckRunning`
  error (MarmotKit) or `MARMOT_STATUS_RELAY_CHECK_RUNNING` (C). In MarmotKit and C.
- Added `fs_private::open_existing_regular_nofollow` to open existing regular files without following symlinks or
  blocking on FIFOs, `media_store::format::checked_file_bytes` for overflow-checked encrypted file-length calculation,
  and `marmot_account::AccountHome::try_account_dir` for fallible account-directory resolution (mdk#3799, mdk#2554).
- Added `NostrSdkRelayClient::from_builder_with_account_signer` in `transport-nostr-adapter` so authenticated publish and receive SDK clients share one factory path.
- `Engine::expire_sent_welcome` marks an outbound Welcome past its delivery deadline expired in one row write: the row
  becomes `Failed` with a `WelcomeExpiry` mark, so it reads `Settled(Expired)` whatever the clock, is never published
  or marked delivered, and is not re-owed when its commit confirms (mdk#3589). `record_sent_welcome_expiry` notes that
  its expiry was recorded, and `unrecorded_welcome_expiries` lists those a stop left unrecorded, reading only rows
  that carry no OpenMLS message and naming each group it could not read (`unrecorded_welcome_expiries_in` reads one
  again).
- `Engine::own_account_self_signed_tags` reads, for this account's other leaves, a device tag that verifies under
  that leaf's own signature key, with the slot it names (mdk#3679).
- An application message sent with `only_to_members` is encrypted only into an epoch whose member accounts it all
  lists, checked at encryption for direct sends and queued ones alike; otherwise it fails with
  `AppMessageNewMembers`, or, queued, is retired through `retire_refused_queued_outbound_intent` and announced as
  `QueuedIntentRefused`.
- `Engine::deferred_stall_evidence_since` returns deferred stall evidence for rows whose arrival epoch falls in
  `min_epoch..=group.epoch`, for active epoch-gap handoffs across partial advances.
- `Engine::stored_outbound_welcome_status`, an outbound Welcome's status read from its stored rows without the
  live-group gate, for the sender's invite delivery view (mdk#1706).
- Add NIP-46 remote-signing support to `wn` and `wnd`:
  - `wn login --bunker-stdin` / `wn accounts nip46 login --bunker-stdin` read `bunker://` URIs from stdin (rejecting NIP-46 URIs on argv), review and confirm permissions (interactively or via `--approve-permissions`), connect, and log in via `MarmotAppRuntime::nip46_login` with optional `--default-relays` and `--bootstrap-relays` (publishing missing relay lists to the default relays).
  - `wn login --nostrconnect` / `wn accounts nip46 login --nostrconnect` support client-initiated `nostrconnect://` pairing (printing the pairing offer URI before awaiting `connect` and login, both locally and streamed through `wnd`).
  - `wn accounts nip46 register`, `status`, and `remove` manage existing NIP-46 external-signing sessions.
  - `wn accounts list`, `wn accounts status`, and `wn whoami` report `external_signing` and `signing_mode` (`local`, `external`, or `public`).
  - `wnd` startup restores persisted NIP-46 accounts independently via `MarmotAppRuntime::start()` without blocking local accounts, and one-shot `wn` commands resume sessions on demand via `nip46_resume`.
  - All signing-capable `wn` and `wnd` operations (`messages`, `groups`, `chats`, `keys`, `profile`, `relays`, `sync`, `follows`, `media`, `devices`, and streaming subscriptions) now accept `external_signing` accounts while keeping `export-nsec` disabled.
- `MarmotAppRuntime::account_relay_health` and `MarmotAppEvent::RelayHealthChanged`: the account's relay rows (roles,
  `RelayHealthState`, policy fault, liveness) and its inbox warnings, from held relay lists and the dial policy only.
  Only the `Unchecked` and `NotAllowed` states are produced yet.
- `submit_custom_event_to_members` and `submit_tagged_edit_for_local_send_to_members` send only to the listed member
  accounts: if the group has another member account when MDK encrypts the send, including one that joined while the
  send was queued, it is not sent, its local row is retracted, and `local_send_status` reports `RefusedNewMembers`.
- `submit_thread_message` and `submit_tagged_sticker` accept a client token and return before relay publication.
- `MarmotAppRuntime::invite_deliveries` and `MarmotAppEvent::InviteDeliveryChanged` (mdk#1706): one `InviteDelivery`
  per group and invited account, rolled up from the session's per-Welcome delivery records. `RelayAccepted` means a
  relay stored the Welcome, not that the recipient received it or joined.
- A later version of an agent item is a kind-1009 edit carrying the whole item with a higher `v`, sent crash-safely
  with `submit_tagged_edit_for_local_send` on the item's token. The row keeps the highest version, ignores an older
  one that arrives late, applies an edit that arrived before its item, and is not marked edited.
- `TimelineMessageRecord::agent_item` holds the parsed latest version of an agent item, and `timeline_order_seq` the
  first event's `seq`, which orders a turn's rows within one second. `AgentItem`, `AgentItemState`, `AgentRequest`
  and the agent kind constants are re-exported.
- Agent items join threads for subagents (marmot-agents D-121): a kind 1201 may carry NIP-22's `E`/`K`/`P` (root)
  and `e`/`k`/`p` (parent), and `submit_custom_event` and `send_custom_event` take its `e` only beside an `E`. An edit
  of an item still carries no `e` but its target's. A thread message answering an item in a thread names that item's
  root and the item as its parent.
- An agent item whose first event this device never gets, such as one sent before the member joined, is shown from
  its edits in its place in the timeline and its thread (marmot-agents D-124), with
  `TimelineMessageRecord::agent_item_first_event_missing` set, and an alerting edit of it alerts.
- The agent's own words in a thread under one of its items, a kind 1111 with an `E` whose `K` is 1201 and whose `P`
  is its author, neither notify nor wake members (D-122), and never count as unread or raise the @-badge. Items in a
  thread keep their own alert rule.
- `MarmotAppRuntime::check_account_relays`, the account worker's inbox check behind the `Healthy`, `Suspected` and
  `Failing` relay states. `RelayHealthRow` gains `checked_at_unix` and `checking`, `RelayHealthFault` gains the
  check's faults, and `RelayWarningKind` gains `InboxRelayFailing`.
- `AppError::RelayCheckRunning`: a check requested while one of the account runs.
- Add `OnboardingOptions::create_missing_inbox_list` and `OnboardingOptions::pass_device_notice_when_none_found` (both default `false`) plus `OnboardingSnapshot::created_inbox_list` (`OnboardingCreatedInboxList`) for existing-key onboarding (#3720, #3729).
- Onboarding reports `OnboardingIssue::RateLimited` when a relay answers a lookup or publication with a `rate-limited:` refusal (#3721, #3723).
- Let hosts disable background acquisition of public avatar URLs.
- `WelcomeDeliveryProblem::InboxLookupFailed`: no usable inbox relay is known for the recipient and the latest lookup
  of their inbox relay list failed. `invite_deliveries` reports it as `last_problem`, and as `Undeliverable`'s cause
  when it was the last attempt's problem.
- `marmot_account_relay_health` and `marmot_account_relay_health_free`, the `MarmotAccountRelayHealth` record with
  its rows, warnings and enums, and the `MARMOT_EVENT_RELAY_HEALTH_CHANGED` event variant, appended after the existing
  variants. `MarmotEvent` gains a variant: rebuild against the matching header and library.
- `MarmotAgentItem` and `MarmotAgentItemState`: the latest version of a kind-1201 agent item on its timeline row.
- `marmot_invite_deliveries` and `marmot_invite_delivery_list_free`, the `MarmotInviteDelivery` records with a
  flattened `MarmotInviteDeliveryState`, and the `MARMOT_EVENT_INVITE_DELIVERY_CHANGED` event variant (mdk#1706).
  `MarmotEvent` gains a variant: rebuild against the matching header and library.
- `marmot_send_custom_event_with_client_token`: durable token admission of a custom application event, such as an
  answer or a control for an agent (kind 1202).
- `marmot_submit_tagged_text`, `marmot_submit_tagged_reply`, `marmot_submit_thread_message`, and
  `marmot_submit_tagged_sticker` return durable local acceptance before relay publication.
- `MARMOT_STATUS_INCOMPATIBLE_KEY_PACKAGE` identifies incompatible recipient chat keys that previously returned the generic runtime status.
- `marmot_check_account_relays`. `MarmotRelayHealthRow` gains `has_checked_at_unix`, `checked_at_unix` and `checking`
  at its end; `MarmotRelayHealthFault` and `MarmotRelayWarningKind` gain values appended after the existing ones.
  Rebuild against the matching header and library.
- `MARMOT_STATUS_RELAY_CHECK_RUNNING` (135), appended to `MarmotStatus`, for a check requested while one of the account
  runs.
- Add `marmot_begin_onboarding_with_options` with bitmask flags `MARMOT_ONBOARDING_CREATE_MISSING_INBOX_LIST` (`1`) and `MARMOT_ONBOARDING_PASS_DEVICE_NOTICE_WHEN_NONE_FOUND` (`2`), plus `MarmotOnboardingCreatedInboxList` (`created_inbox_list`) on `MarmotOnboardingSnapshot` (released by `marmot_onboarding_snapshot_free`) (#3720, #3729).
- `MarmotOnboardingIssue` appends `MARMOT_ONBOARDING_ISSUE_RATE_LIMITED` (`22`) for relay `rate-limited:` refusals during onboarding lookups and publication (#3721, #3723).
- `MARMOT_INVITE_DELIVERY_PROBLEM_INBOX_LOOKUP_FAILED` (mdk#2261), appended after the existing values: no usable inbox
  relay is known for the recipient and MDK's latest lookup of their inbox relay list failed. Requires the matching
  header and library.
- `Marmot::account_relay_health(account_ref)` and the `RelayHealthChanged` event, with `AccountRelayHealthFfi`,
  `RelayHealthRowFfi`, `AccountRelayWarningFfi`, `RelayListPresenceFfi`, `RelayRoleFfi`, `RelayHealthStateFfi`,
  `RelayHealthFaultFfi`, `RelayWarningKindFfi`, `RelayWarningSeverityFfi` and `RelayRepairActionFfi`. Only the
  `Unchecked` and `NotAllowed` states are produced yet; later versions add kinds, faults, actions and roles.
- Swift `nextCancellable()` / `nextUpdateCancellable()` adapters for the receives generated without `throws`:
  backup restore, chat list, chats, events, group state, messages, notifications, onboarding, timeline messages and
  user search subscriptions (mdk#3670).
- `TimelineMessageRecordFfi::agent_item_first_event_missing`: true for an agent item whose first event this device
  does not hold, such as one that began before the member joined; the row is built from its edits.
- `TimelineMessageRecordFfi::agent_item` (`AgentItemFfi`, `AgentItemStateFfi`): the latest version of a kind-1201
  agent item, with its type, fields JSON, `settles` and whether it alerts. A kind-1201 row without one is an
  unreadable item, such as the old shape.
- `Marmot::invite_deliveries(account_ref, group_id_hex)` and the `InviteDeliveryChanged` event (mdk#1706), with
  `InviteDeliveryFfi`, `InviteDeviceDeliveryFfi`, `InviteRelayCountsFfi`, `InviteDeliveryStateFfi`,
  `InviteDeliveryProblemFfi` and `InviteCancelReasonFfi`. `Undeliverable`, `TooLarge` and `KeyPackageRetired` are
  not produced for ordinary invites yet. Only invites sent after the upgrade are listed; an older Welcome stays in
  `pending_welcome_deliveries` and `WelcomeDeliveryPending`, which are unchanged.
- `send_custom_event_with_client_token`: durable token admission of an app-defined event, such as an answer or a
  control for an agent (kind 1202), so a retry after a restart does not send it twice.
- `submit_tagged_text`, `submit_tagged_reply`, `submit_thread_message`, and `submit_tagged_sticker` return durable
  local acceptance before relay publication.
- `Marmot::check_account_relays(account_ref)`. `RelayHealthRowFfi` gains `checked_at_unix` and `checking`;
  `RelayHealthFaultFfi` gains `AuthenticationRequired`, `PaymentRequired`, `Restricted`, `Unreachable`, `TimedOut` and
  `Unexplained`; `RelayWarningKindFfi` gains `InboxRelayFailing`. `Healthy`, `Suspected` and `Failing` are now
  produced. Rebuild against the matching library.
- `MarmotKitError::RelayCheckRunning`: a check requested while one of the account runs.
- Add `OnboardingOptionsFfi.create_missing_inbox_list` and `OnboardingOptionsFfi.pass_device_notice_when_none_found` (both default `false`) plus `OnboardingSnapshotFfi.created_inbox_list` (`OnboardingCreatedInboxListFfi`) for existing-key onboarding (#3720, #3729).
- `OnboardingIssueFfi` appends `RateLimited` for relay `rate-limited:` refusals during onboarding lookups and publication (#3721, #3723).
- Let hosts disable background acquisition of public avatar URLs.
- Expose pinned message retention in reply previews.
- `InviteDeliveryProblemFfi::InboxLookupFailed` (mdk#2261): no usable inbox relay is known for the recipient and MDK's
  latest lookup of their inbox relay list failed; MDK looks it up again at its next retry. A host that matches the enum
  exhaustively must handle it.
- `recovery_unit_debts` reads many units' debts, each with its unit state, and `staged_recovery_first_seconds`
  reads the oldest staged second in many ranges, each under one connection lock.
- `renew_roster_tag_keys` updates `last_seen_at` for a slot's unexpired roster tag keys in one statement and leaves
  `seen_seq` alone (mdk#3679).
- Kind-1009 edits apply to kind-1201 agent items: the highest `v` replaces the row's content and tags, an older
  version is ignored, and the row is not marked edited. Agent items have no edit history.
- A kind-1201 agent item with an `E` tag is placed in that thread, under the parent its `e` names or else the root,
  and `reply_to_message_id_hex` is that parent unless the item names a `started_by`. An edit keeps the thread tags
  of the item's first event, whatever thread tags it carries.
- An agent item whose first event this device does not hold, such as one sent before the member joined, gets a row
  from its edits: the earliest readable edit stands in for the first event, at its place, and the highest version
  shows. `TimelineMessageRecord::agent_item_first_event_missing` says so. The first event, if it arrives, takes the
  row back to its own place. If the id turns out to name an event that is no item, such as another edit, the row
  goes, and the replies quoting it lose the quote in the same change, as `ReplyPreviewChanged`. A nightly build from
  before this change stored such edits without a row: the item shows once another event of it arrives or the chat's
  timeline is rebuilt.
- A history import reports the rows it removed, such as an item whose only edit it deleted, as `Remove` changes, so
  an open timeline drops them.
- An agent's own words in a thread under one of its agent items (a kind 1111 with `E`, `K` 1201 and `P` its sender)
  never count as unread, in the projection, its rebuild and the retention sweep.
- `delete_local_group_data` keeps the deleted row's invitation standing on the group's deletion frontier, and
  `SqliteAppStorage::local_group_deletion_invitation` returns it as `LocalGroupDeletionInvitation` (mdk#3555). A
  frontier written before schema 223, or by a delete that found no row, returns `None`.
- Account migration 0224 adds `evidence_floor_epoch` to `account_recovery_obligations` and
  `SqliteAppStorage::active_epoch_gap_evidence_floor` so active epoch-gap handoffs keep their original arrival-epoch
  floor across multi-step partial advances and restarts while parked gaps retire cleanly (and explicit unparks reset
  the floor to `stalled_epoch`). Older binaries refuse schema 224; downgrade is unsupported.
- `hold_roster_tag_keys_as_removed` sets `held_as_removed` on a slot's unexpired roster tag keys unless one already
  has it, and leaves `last_seen_at` and `seen_seq` alone (marmot#520).
- Expose pinned message retention in reply previews.
- `agent_events`: the tags of kinds 1201 and 1202 (marmot-agents D-076), `AGENT_EVENT_MAX_BYTES`, and the parsers
  `AgentItem::from_tags` and `AgentRequest::from_tags` with the alert rule `AgentItem::alerts`.
  An item's `v` and `seq` are at most `i64::MAX`.
- `maintenance::WelcomeDeliveryRecord` and its `WelcomeDeliveryState`, `WelcomeDeliveryProblem`,
  `WelcomeCancelReason` and `WelcomeRelayCounts` (mdk#1706): the sender's durable record of one outbound Welcome's
  delivery.
- An agent item in a subagent's thread carries NIP-22's tags (marmot-agents D-121): `validate_agent_item_tags` takes
  one `e` beside an `E`, and `validate_agent_item_edit_tags` checks the item an edit carries, which has no `e`.
  `agent_item_thread_parent`, `agent_item_reply_target` and `is_agent_own_thread_comment` (D-122) read them.
- `OsEntropy` and `SystemWallClock` are available from `cgka_traits` for production random bytes and timestamps.
- `WelcomeDeliveryProblem::InboxLookupFailed` (mdk#2261): no usable inbox relay was known for the recipient and the
  latest lookup of their inbox relay list failed.

### Changed

- Linking a device now records the new device's signature key in its device-group roster entry in the Commit that adds
  it, instead of leaving the new device to write it later (marmot#521, mdk#3679). A key in an entry no longer means the
  link is made: a link counts as made once the new device's own first Commit in the device group lands. Until then the
  new device tags nothing outside the device group, and its first Commit there is a roster update writing its history
  key, or a self-update when the entry needs no change. A device refuses a device-group Welcome whose roster binds its
  entry to another key or another slot; a keyless entry from an approver that has not updated still joins. Removal,
  inactivity, sign-out, sibling chat gaps and the private KeyPackage hand-off read "made" the same way, and same-account
  sibling Adds are refused with the new `SiblingAddRefusal::LinkPending` until the sibling's link is made. Receivers
  do not enforce the new roster rules yet.
- Every device-group Commit is now held to the roster's key-binding rules (marmot#521, mdk#3679), whoever sends it:
  each added device gets a new entry, in that Commit, with its leaf's signature key; an entry's key never changes;
  a device's entry is removed only together with its leaf; a `removed` record keeps only the key its entry had; and no
  leaf changes its signature key. A Commit or proposal that breaks one is refused. Only new Commits are checked, so
  existing device groups keep working. One known interim gap: a late Commit that makes a device replay its last few
  device-group Commits re-checks them, so a link made before upgrading, by an Add that set no key, can lose to a rival
  branch while it is still among the last five Commits; that device then relinks. A device-group Welcome must record the joining device's key in its entry, and
  a device never writes its own key after its Add.
- Removing a linked device finds its device-group leaf by the key its entry carries and removes it with the entry.
  Removing the device that founded the device group now takes its leaf too, though OpenMLS built that leaf from a
  KeyPackage: the engine counts a founder's link as made.
  The fallback that also searched for a leaf tagged with a self-signed device tag is gone, from both removal and the
  cleanup of chat leaves (`Engine::own_account_self_signed_tags` is removed).
- Updated `DirectoryRelayPlane` in `transport-nostr` to track coalesced directory fetches with waiter-counted cancellation and bounded `MarmotRelayPlane::shutdown()` cleanup, and removed the unused idle `Client` from `NostrSdkDirectoryRelayFetcher::standalone()`.
- Maintenance queues an MLS self-update as soon as it detects stale chat capabilities, instead of scheduling it up to
  five days out. The quiet period, contention jitter, and commit safety checks still apply.
- `RelayHealthChanged` also fires when an inbox check changes a relay's state, never when one confirms it.
- Replaced dated nightly pre-releases (`*-nightly.YYYYMMDD`, `nightly-meta/latest.json`) with daily canary-gated SemVer Release Candidates (`<track>-vX.Y.Z-rc.N`, `rc-meta:rc/latest.json` schema 2, `rc/signature_delta.json`) and one-click Stable promotion (`promote-release.yml` / `just promote-rc`).
- Migrated strict directory reads (`fetch_directory_events_with_completion`) in `transport-nostr` onto chunked `FiniteRequests` using per-REQ raw-vs-admitted EVENT accounting (`raw_items == received_items`) and retired the duplicate `DirectoryWireTransport` wrapper.
- `SendIntent::UnlinkDevice` may keep the removed leaf's signature key in the slot's `removed` record once that leaf
  has committed since its Add, and refuses any `removed` record while the removed leaf is still its link's KeyPackage
  leaf (mdk#3679). Receivers are unchanged.
- An invite's and a founding create's Welcome record `deliver_until`: 7 days after
  staging, or the KeyPackage's `not_after` if sooner, and `outbound_welcome_status` reports them
  `Settled(Expired)` from then on (mdk#3589). A device link's deadline is unchanged. `sent_welcome_deliver_until` and
  the status hold a Welcome stored without a deadline to its transport timestamp plus the window.
- Budget-expired deferred-peel evictions delete the deferred row from `cgka_messages` directly instead of calling
  `release_message_for_replay`, so storage hosts are no longer notified via the release journal for budget-expired
  rows, avoiding false epoch-gap arms, `seen_events` retirement, and relay bounce-backs.
- `SendIntent::RecordRemovedSlot` stages the lone `removed` record with no tag signature key and refuses one that
  keeps a key: its Commit removes no leaf and the roster has no entry, so nothing proves one (marmot#520).
  `SendIntent::ImportDeviceGroupRejections` refuses a carried record that keeps a key. A roster state that records a
  slot as `removed` with no key holds the keys this device keeps for the slot as removed, unless one already is, so
  the app still knows the record was held. Receivers are unchanged.
- `wn messages send-event` accepts kinds 1201 (agent item) and 1202 (answer or control) in the marmot-agents shape,
  and refuses them in any other.
- Timeline JSON gains `agent_item_first_event_missing`, true for an agent item shown from its edits because its
  first event is not on this device.
- WN Agent refuses `send_agent_activity` and `send_agent_operation_event` with `retired_agent_event` and publishes
  nothing: MDK no longer builds the old shape of kinds 1201 and 1202.
- `wn messages timeline list` carries a kind-1201 row's parsed `agent_item` in `--json`, and shows an item MDK cannot
  read, such as the old shape, as `[unreadable agent item]` instead of its payload.
- `wn messages delete` by an admin of their own chat message sends an author kind 5 (empty content), not kind 4891,
  so it syncs as deleted by its author.
- Usage diagnostics count a Welcome naming another KeyPackage of this account (`NotAddressedToThisDevice`) as
  `mdk_welcome_summary` `process` `absent`, no longer `duplicate`: a device that sees only its siblings' Welcomes cannot
  join, and counting them as copies hid it. No outcome value is added, so saved consent stays accepted.
- Relay telemetry adds `app_runtime_member_key_package_read_*` and `app_runtime_member_key_package_relay_read_*`:
  for each member a create, invite or invite recovery selects, whether its KeyPackage read heard every relay it asked,
  and how many of those relays answered. `MemberKeyPackageResolutionStats::key_package_reads` carries the same counts.
  Selection is unchanged.
- Group creation, invites and direct-chat starts always discover the members' current relay routes after
  `prewarm_group_member_key_packages`; prewarmed outboxes only add hints to the KeyPackage read, so a prewarm no longer
  makes them skip discovery. An `IncompatibleKeyPackage` verdict needs that discovery to complete, and a completed read
  that finds no deletion request for the refused KeyPackage or its slot.
- A member lookup that finds no usable KeyPackage reports `DirectoryLookupIncomplete`, not a missing or incompatible
  KeyPackage, while this device's KeyPackage journal keeps a publication of that member that the lookup did not account
  for. The README's direct-chat section states what accounts for one and how long the journal keeps it.
- A member lookup that finds no KeyPackage reports `DirectoryLookupIncomplete`, not a missing KeyPackage, while a relay
  list tied with the member's named a usable outbox that no KeyPackage read covered.
- A member lookup treats a relay that the member's relay lists name twice, or with and without a trailing root slash, as
  one relay: it reads the relay once and counts it once toward a read's limit.
- `RelayWarningKind::NoAllowedInboxRelay` also fires when every inbox entry is refused or `Failing`, and names every
  entry. `RelayHealthChanged` also follows check results.
- The lone `removed` record a deciding device commits after a failed link's undo, and each `removed` record a device
  group move carries into its destination, keep no tag signature key (marmot#520). Neither Commit proves a key, so
  receivers that check `removed` records would refuse one that kept it. Devices that applied the slot's entry still
  clean up by the key they kept, and the lone record is still made once. Receivers are unchanged.
- A member's `MARMOT_MEMBER_RESOLUTION_STATUS_INCOMPATIBLE_KEY_PACKAGE` now requires completed relay-list discovery,
  complete KeyPackage reads and a completed read that finds no deletion request for the refused KeyPackage or its
  slot. If any is incomplete, the status is `MARMOT_MEMBER_RESOLUTION_STATUS_INCOMPLETE`.
- A member with no usable KeyPackage is `MARMOT_MEMBER_RESOLUTION_STATUS_INCOMPLETE`, not missing or incompatible, while
  this device's KeyPackage journal keeps a publication of theirs that the lookup did not account for. The shared API
  guidance for `marmot_start_direct_chat_with_options` states what accounts for one and how long the journal keeps
  it.
- A member with no KeyPackage is `MARMOT_MEMBER_RESOLUTION_STATUS_INCOMPLETE`, not missing, while a relay list tied with
  theirs named a usable outbox that no KeyPackage read covered.
- A member lookup treats a relay that the member's relay lists name twice, or with and without a trailing root slash, as
  one relay: it reads the relay once and counts it once toward a read's limit.
- Group creation, invites and direct-chat starts always discover the members' current relay routes after
  `marmot_prewarm_group_member_key_packages`; prewarmed outboxes only add hints to the KeyPackage read, so a prewarm
  no longer makes them skip discovery.
- A member's `MemberResolutionStatusFfi::IncompatibleKeyPackage` now requires completed relay-list discovery,
  complete KeyPackage reads and a completed read that finds no deletion request for the refused KeyPackage or its
  slot. If any is incomplete, the status is `MemberResolutionStatusFfi::Incomplete`.
- A member with no usable KeyPackage is `MemberResolutionStatusFfi::Incomplete`, not missing or incompatible, while
  this device's KeyPackage journal keeps a publication of theirs that the lookup did not account for. The API
  reference for `start_direct_conversation_with_options` states what accounts for one and how long the journal keeps
  it.
- A member with no KeyPackage is `MemberResolutionStatusFfi::Incomplete`, not missing, while a relay list tied with
  theirs named a usable outbox that no KeyPackage read covered.
- A member lookup treats a relay that the member's relay lists name twice, or with and without a trailing root slash, as
  one relay: it reads the relay once and counts it once toward a read's limit.
- Group creation, invites and direct-chat starts always discover the members' current relay routes after
  `prewarm_group_member_key_packages`; prewarmed outboxes only add hints to the KeyPackage read, so a prewarm no longer
  makes them skip discovery.
- A new account database applies its schema through migration 227 in one transaction from a checked-in baseline,
  then replays only later migrations. Opening a fresh account no longer replays every migration, which took seconds.
  Databases with any recorded migration are unchanged.

### Deprecated

- `wn messages timeline subscribe`, `wn chats subscribe-archived`, `wn groups subscribe-state` and
  `wn notifications subscribe` served the terminal UI. They still work unchanged and will be removed in a future
  release.

### Removed

- Retired the `nightly-releases.yml` workflow and `nightly-meta/latest.json` update stream; retention continues expiring legacy `*-nightly.*` pre-releases older than 30 days.
- The terminal UI is gone: `wn tui` no longer exists. This is a breaking change for anyone who used it; every chat,
  group and message action it offered is a `wn` command. A home the TUI ran in may keep a `tui-media-cache/`
  directory; after an unclean exit it can hold decrypted attachments. Delete it by hand.
- `wn settings theme` is removed. It was meant for the TUI, which never read it. `wn settings show` no longer prints a
  `theme` field, and a `theme` value in an existing `settings.json` is ignored.

### Fixed

- `marmot-app` account workers now track, cancel, and drain all worker-spawned async and blocking tasks (media HTTP transfers, attachment and avatar store completion, housekeeping/sweep/migration passes, retry timers, and post-create catch-up) before teardown evicts caches or removes account directories, and pass already-open storage handles instead of reopening databases in background tasks.
- `marmot-app` now acquires account teardown fences in one canonical order across `remove_account`, `deactivate_account`, and `reset_incomplete_account_setup`, preventing lock-order inversions and unfenced setup resets.
- `marmot-app` now splits host group-scoped and account-wide worker channels so parking account-wide commands at `PARKED_LIMIT` during `CheckSignIns` no longer starves group commands, and bounds in-memory deferred worker command queues with channel backpressure.
- `UnlinkedPublishGate` now caches per-account resolution without rescanning `account.json` on every call and always returns the shared account stop handle so recovery or `lift_failed_link_publish_stop` unblocks existing publishers after transient lookup errors.
- Dropping `subscribe_messages`, `subscribe_timeline_messages`, `subscribe_chats`, `subscribe_group_state`, or `subscribe_notifications` now exits its background forwarding task immediately instead of leaking broadcast receivers until runtime shutdown.
- Hardened low-level runtime hygiene in `marmot-app`: replaced unchecked mutex `.lock().unwrap()` calls in `client/sync.rs`, stopped emitting rejected or device-group-kind application messages into `SyncSummary.events`, and made reconnect `drain_deferred_hydration` cancellation-aware on shutdown.
- `wn-agent` answers a control request it cannot read with an `error` response instead of closing the connection
  silently (mdk#2242): `unsupported_protocol` for a missing or wrong `marmot_agent_control`, `unknown_request` for an
  unknown `type`, and `invalid_request` for anything else, naming a missing or repeated field and echoing the request
  `id` when it could be read.
- An invite's or new chat's Welcome that reaches its delivery deadline (mdk#3589) now ends for good the first time MDK
  sees the deadline passed while the Welcome is owed: a device clock set back afterwards no longer makes it sendable
  again, and `redeliver_welcome` publishes nothing for it. A Welcome still staged with its unconfirmed commit is read
  by the clock until that commit resolves, so a clock set back meanwhile can let it go out once the commit confirms. Its v5 `welcome_withdrawn` row with reason `expired` and its
  `InviteDeliveryChanged` are recorded once, also when the deadline passed while the app was closed: then on the next
  start. A relay attempt that started before the deadline and fails after it no longer reports
  `WelcomeDeliveryPending`. On the first start after this upgrade, every Welcome already past its deadline is recorded
  this way.
- An invite's or new chat's Welcome that no inbox relay stores is no longer retried for weeks (mdk#3589). It has a
  delivery deadline, 7 days after it was made or its KeyPackage's expiry if sooner; after that nothing sends it, not
  the startup retry, maintenance or `redeliver_welcome`, it leaves `pending_welcome_deliveries`, and
  `invite_deliveries` reads it `Undeliverable` with what its latest attempt found. When the deadline passes while the app runs, the v5
  audit records the end as `welcome_withdrawn` with reason `expired`. A Welcome owed from before this upgrade is held to 7 days from its gift
  wrap's timestamp, so the oldest end on the first start. The startup retry no longer skips relay backoff: it asks
  only relays never asked and those whose backoff has passed. The invitee stays a member.
- Cancelling a Swift task now cancels the throwing MarmotKit call it awaits, commands and subscription receives
  alike, and releases the native references that call holds without `shutdownAndClose()` (mdk#3670). Calls whose
  work must finish, such as `shutdownAndClose()`, `removeAccount()`, `signOut()`, `signOutAndWipe()` and the `login*`
  calls, still run to completion, and the receives generated without `throws` gain throwing `nextCancellable()`
  adapters. An audit of every async export found eight whose steps could be torn by a cancel; they now keep running
  when a Kotlin or Swift caller cancels them: sign-out, sign-in, account removal, the three logins, NIP-46 signer
  removal and the audit-log switch. Overlapping audit-log switch calls end with the last stored value.
- When the app's account worker publishes a Welcome (an invite's, a new chat's, or a retry of either), the first pass
  now reaches every inbox relay of its recipient, not only the first relay that acknowledged it. Each relay is asked
  on its own. The Welcome is still marked delivered at the first acknowledgement, and the host and the account worker
  do not wait for the other relays. Their answers are recorded once all of them have answered. If the worker stops
  waiting first (at the shutdown bound, a reconnect, sign-out or unlink), nothing more is recorded: those relays stay
  owed and are retried after their backoff, and one that already stored the Welcome answers duplicate. A Welcome whose
  only acknowledgement came from a relay that accepts gift wraps but cannot serve them back no longer depends on a
  retry 30 seconds later, which a closed app never ran. `redeliver_welcome` and runtimes that publish Welcomes inline
  still stop at the first acknowledgement.
- An invite's Welcome whose recipient has no usable inbox relay no longer retries, and records a routing failure, on
  every maintenance pass while it is owed (mdk#2261, in part). Its recipient is retried 10 minutes later, then at
  doubling intervals up to 6 hours; the pacing is kept in memory, so each app start still makes one attempt. Each
  retry uses the recipient's inbox route as the account last loaded it from the local directory cache: MDK does not
  look the recipient's relay list up again, so such a Welcome still goes out only once a new list reaches the cache
  and the route table, in practice through a new invite to that person. The audit records why no route was found:
  `no_eligible_route` for an empty or unusable list, `route_resolution_failed` for no list known.
- A device linked soon after another no longer shows the account's accepted chats as invitations for up to an hour,
  where a decline turned into a leave on every device (mdk#3556). Each device broadcasts its small state to a newly
  listed device at once, and adds it to a chat only after that chat's invitation decision went out. During a relay
  outage the chat can still show as an invitation until the decision is delivered. The account database advances to
  schema 222.
- Admitted finite requests in `transport-nostr-adapter` against a shared global queued-byte budget (192 MiB default, FIFO reservation with single-request exclusivity above capacity and sharing-group reservation so `FiniteRequests::sharing` reserves its shared budget once plus one private frame per active relay) so concurrent sweeps and directory reads bound queued frame memory without starving peer relays.
- Unified GroupContext admin-policy (`0x8003`) and group-lifecycle (`0x800c`) validation across Legacy and Current profiles, rejected caller-supplied `0x800c` overrides during group creation and `UpdateAppComponents`, rejected joining `Disbanded` Welcomes in both profiles, and tightened wire bounds on `DeviceRosterV1::devices` and `SiblingWelcome::decode` relay lists (#3795, #2455, #2456).
- `AccountDeviceRuntime::key_package_network_maintenance_due` and `maintenance_due` no longer report KeyPackage publication work as continuously owed when zero writable KeyPackage publication endpoints are configured, while keeping private-material expiry deadlines scheduled (follow-up to #3777).
- Expired KeyPackages can now be retired from local MLS storage after their lifetime elapses, and session maintenance no longer republishes, fans out, or retains expired pending or current KeyPackages (mdk#3730).
- Fallback KeyPackage relay routing now excludes relays that the account's NIP-65 list explicitly declared as read-only when declared write relays are empty or unsafe, and persisted KeyPackage retries honor current relay policy without stranding empty-route intents (mdk#3730).
- Background KeyPackage maintenance (startup cutover, worker maintenance, KeyPackage catch-up, and automatic group-recovery recipient Challenge publication) is now deferred while interactive onboarding is unfinished, unifying invite/group recovery and KeyPackage catch-up under `maintenance_passes` (mdk#3730).
- Switched `transport-nostr`'s live directory notification forwarder from SDK first-seen `ClientNotification::Event` to per-message `ClientNotification::Message(RelayMessage::Event)` with independent supplied-bytes verification on every copy so SDK pool deduplication cannot hide later relay copies or rebuild replays.
- Guarded `nostr-directory`'s cached KeyPackage and kind-3 contact-list ingestion against older or equal-second stale replays and existing KeyPackage deletion/replacement barriers, and cleared cached `entry.key_package` entries when live kind-5 deletions or newer malformed kind-30443 replacements fence them.
- Hardened `media-store` local file handling and concurrency invariants (mdk#3799, mdk#2554): in-flight file tracking
  now uses per-file reference counts so concurrent readers and sweeps do not drop active leases prematurely, cached
  readers check a revocation generation before re-insertion (invalidated both before and after loss commits) and mark
  missing files lost on reopen without swallowing catalog errors, reopen and trim paths reject symlinks and non-regular
  files (clearing invalid wire checkpoints and continuing sweeps without opening them), writer buffers zeroize on drop
  and honor poisoned state on flush, catalog sweeps verify regular files and valid layout sizes, and file-length/offset
  math uses checked arithmetic.
- Hardened `marmot-account` account-wipe cleanup and local secret I/O (mdk#3799, mdk#819, mdk#2145): account removal
  now resolves shared-credential checks before the tombstone rename commit and unconditionally scrubs tombstoned local
  secret files and removes the tombstone directory post-commit before propagating any independent secret-store deletion
  error; Windows secret reads verify live handle linkage so scrubbed or moved-aside handles are rejected and retried;
  tombstone roots use owner-only permissions; local secret reads reject symlinks and oversized files and pre-allocate
  the bounded zeroizing buffer; and zero-scrub overwrites use bounded fixed chunks.
- Hardened `fs-private` local directory, file, and Unix socket helpers (mdk#3799): directory and file opens pass
  `O_NONBLOCK`, private file helpers verify regular files and tighten permissions before truncating, and private Unix
  socket binds serialize staging within a process so concurrent same-PID binds cannot collide.
- Odin hosts can statically link the Markdown parser without duplicate runtime symbols. The parser also builds for
  GNU Windows targets with LLVM-MinGW.
- A finite history read whose caller stops polling it while its REQ waits to be queued no longer holds up live
  events on that relay connection. Before, the read could hold the SDK's subscription lock until it was polled
  again.
- Reconnecting a relay now immediately clears per-unit unreachable retry waits on that relay (while keeping timed
  probes for parked broken units intact), so live-fenced groups resume history recovery and message delivery without
  stalling for the 30-second unreachable retry wait.
- Engine audit error details use a closed classifier without forwarding free-form error text, projection error display
  omits raw message identifiers, symmetric key holders and group-image transfer types redact `Debug` output and erase
  keys on drop, and SQLCipher salt reads enforce a size limit without including account paths in errors (mdk#3796).
- `marmot-app`: Disappearing-message retention sweeps now query SQLite directly for groups with expiring rows instead of skipping groups whose current policy is `0` or omitting non-chat-list groups, so previously sent disappearing messages still expire after retention is turned off. `RetentionSweepReport.groups` now lists only visible groups that had expired rows at sweep time.
- `marmot-app`: Backup passes now require complete multi-relay pointer discovery before condemning blobs or replacing pointers, and bound replacement pointer timestamps (including persisted replaceable-record floors) against excessive future clock skew.
- `marmot-app`: Blossom uploads and deletions now complete host and dial-safety validation before signing BUD-01 authorization events.
- `marmot-app`: Host-facing Welcome redelivery now enforces group visibility so internal device-group Welcomes remain hidden from host redelivery calls.
- Bounded active dry-run NIP-77 comparisons in `transport-nostr-adapter` (`sync_watching_neg_cap_detailed`) by the caller's `deadline`, so a relay sending non-converging `NEG-MSG` frames that continually reset `idle_timeout` cannot hold a per-relay NEG permit indefinitely.
- Hardened `storage-sqlite` database opening, deletion, compaction, and directory/media-catalog operations: SQLCipher
  compatibility and busy-timeout pragmas now apply in the order SQLCipher requires, migration `0228` and all
  `storage-sqlite` read/write boundaries canonicalize persisted `group_id_hex` values and checkpoint scopes to lowercase
  ASCII, key-package eviction watermarks preserve stronger deletion barriers across batch evictions, read-then-write
  storage transactions acquire immediate write locks under WAL contention, media-catalog paging and compaction recovery
  handle limits, retries, and close interrupts cleanly, and secure pruning scrubs full UTF-8 byte lengths and removes
  invalidated edits targeting pruned messages.
- Swift bindings no longer deadlock when cancelling an async MarmotKit `Task` concurrently with a native `RustFuture::wake` (mdk#3821): `uniffiRustCallAsync` now dispatches native future cancellation off Swift's `onCancel` handler (avoiding lock-order inversion between `AsyncTask`'s `StatusRecordLock` and `uniffi_core::RustFuture`'s scheduler mutex) and checks `Task.isCancelled` before polling so a pre-cancelled or woken-after-cancel task does not issue another native poll.
- Switched live kind-1059 inbox delivery in `transport-nostr-adapter` from SDK first-seen `ClientNotification::Event` to per-message `ClientNotification::Message(RelayMessage::Event)` with independent supplied-bytes verification, preventing SDK pool deduplication from hiding later relay copies or replays after retired attempts or queue drops.
- Shut down authenticated publish SDK clients on eviction (once caller references drop), account deactivation, and `MarmotRelayPlane::shutdown()`, and shut down adapter-owned anonymous publish SDK clients when the last adapter clone drops or the account is deactivated (leaving held adapters usable across receive-plane shutdown); joined in-flight delivery spill writers and loss-marker persistence tasks during plane shutdown, and switched discarded NIP-46 signer transports from `disconnect()` to `shutdown()`.
- An invite's Welcome whose recipient has no usable inbox relay (no kind-10050 list known, an empty one, or none this
  device may dial) is now delivered once the recipient's list can be found, without a re-invite (mdk#2261). After each
  paced retry that finds no route (10 minutes, doubling, at most 6 hours, and once per app start), MDK looks the
  recipient's inbox relay list up again beside the account worker, at most four lookups per account at once and 30
  seconds each, and sends the Welcome as soon as the list gives a route. Whether an owed Welcome still needs the
  lookup is checked when it starts and at each worker turn. A failed lookup shows as the new `InboxLookupFailed`
  problem in `invite_deliveries`, and the next attempt that finds no route records the existing v5
  `route_resolution_failed` reason.
- `drain_events` no longer keeps the peak allocation of a large event backlog: a drain larger than one background
  replay sweep (128 events) hands its buffer to the caller and leaves a bounded one behind, while routine drains still
  reuse the buffer (mdk#3585).
- Re-deferring an unopenable `PeelDeferred` row across an epoch sweep preserves its original arrival epoch instead of
  restamping it to the tip epoch.
- Deferred-peel sweeps at the retry-budget or residence-budget cutoff attempt a newly arrived peel context once before
  deleting the row, so a commit that unlocks the row on the cutoff sweep decrypts instead of being discarded.
- Replaced raw-pointer RAII cleanup guards (`PendingCommitCleanupGuard`, `NewGroupCleanupGuard`, and
  `PreparingEvolutionGuard`) with `Arc<S>` stored on `Engine<S>`, eliminating raw-pointer aliasing UB and all `unsafe`
  blocks in `cgka-engine` without changing public API signatures.
- Validated and allocated pending-publish state before committing durable staging rows across all commit-staging paths,
  ran `PendingCommitCleanupGuard`'s pending-commit and stored-proposal cleanup inside one storage transaction, and
  retained ownership of failed `SelfRemove` staging cleanups across engine retries, outbound sends, and session-open
  hydration (quarantining the group with `PendingCommitRecoveryFailed` if a storage fault persists until hydration
  retry) so failed staging leaves neither orphaned SQLite records nor wedged proposal queues.
- Audit error details use a closed classifier rather than forwarding raw error display strings, and
  `OpenMlsProjectionError::Display` omits raw message identifiers (mdk#3796).
- An invite's Welcome past its delivery deadline (mdk#3589) reads `Undeliverable` in `invite_deliveries` for good once
  MDK has seen the deadline pass with the Welcome owed (its commit confirmed), even if the device clock is set back, with one `InviteDeliveryChanged`: on the next
  start when the deadline passed while the app was closed, sent before the account worker's first turn. A relay attempt that started before the deadline and fails
  after it no longer reports `WelcomeDeliveryPending`.
- Removing a linked device that rewrote or cleared its own roster entry's tag signature key removes its device-group
  leaf: removal and chat cleanup also find a committed leaf by a device tag that names the slot and verifies under that
  leaf's own key. A device that moved to another device group keeps its chat leaves whatever keys its slot had, and a
  removed device's leftover chat leaf is still counted past 30 days (mdk#3679).
- An invite's Welcome past its delivery deadline (mdk#3589) is no longer sent by the startup retry and leaves
  `pending_welcome_deliveries`; `invite_deliveries` reads it `Undeliverable`. The startup retry keeps relay backoff.
- A device removed from the account can no longer change its siblings' small state (mdk#3680). It kept its last
  device-group epoch's keys for the app-message window, so until the device group moved five more epochs it could
  still send updates and broadcast requests, and a decline or read position at the highest version could not be
  undone. A device now takes a small-state update or broadcast request only from a leaf whose device tag reads, at
  the message's epoch, as a device its roster lists, and sends its own only once its leaf is tagged: a newly linked
  device's first broadcast waits for its tag commit instead of going out untagged.
- When the app's account worker publishes a Welcome (an invite's, a new chat's, or a retry of either), the first pass
  now reaches every inbox relay of its recipient, not only the first relay that acknowledged it. Each relay is asked
  on its own. The Welcome is still marked delivered at the first acknowledgement, and the host and the account worker
  do not wait for the other relays. Their answers are recorded once all of them have answered. If the worker stops
  waiting first (at the shutdown bound, a reconnect, sign-out or unlink), nothing more is recorded: those relays stay
  owed and are retried after their backoff, and one that already stored the Welcome answers duplicate. A Welcome whose
  only acknowledgement came from a relay that accepts gift wraps but cannot serve them back no longer depends on a
  retry 30 seconds later, which a closed app never ran. `redeliver_welcome` and runtimes that publish Welcomes inline
  still stop at the first acknowledgement.
- An invite's Welcome whose recipient has no usable inbox relay no longer retries, and records a routing failure, on
  every maintenance pass while it is owed (mdk#2261, in part). Its recipient is retried 10 minutes later, then at
  doubling intervals up to 6 hours; the pacing is kept in memory, so each app start still makes one attempt. Each
  retry uses the recipient's inbox route as the account last loaded it from the local directory cache: MDK does not
  look the recipient's relay list up again, so such a Welcome still goes out only once a new list reaches the cache
  and the route table, in practice through a new invite to that person. The audit records why no route was found:
  `no_eligible_route` for an empty or unusable list, `route_resolution_failed` for no list known.
- A newly linked device no longer waits up to an hour for its siblings' small state, showing a chat the account already
  accepted as an invitation, with an "invited you" notification, when every sibling broadcast within the last hour
  (mdk#3556). A device whose trusted roster lists a device its last broadcast was not made for broadcasts at once, and
  adds that device to a chat only once it has sent the chat's invitation decision. A send that reaches no relay holds
  the Add for a later pass instead of letting the Welcome go first. Invitation decisions now go out before other small
  state, and a winning decision read from an update older than the last broadcast is sent again. While no relay
  acknowledges the decision's page, the Add can still go first and the chat shows as an invitation until the session's
  retry delivers it.
- An admin deleting their own chat message sends an author kind 5, so every client shows it as deleted by its author
  (`DeletionSource::Author`) rather than by an admin. Kind 4891 is for another account's content only.
- A member removed from a chat, or who left it, and then added back gets a kind-1210 "member added" row naming who
  added them, the same row the adder's timeline shows.
- The README now states that chat history imported from another device, and backups, leave out group system rows
  and deleted-message placeholders, and why.
- A locally deleted chat that a newer message brings back keeps the invitation standing it had (mdk#3555): an
  unanswered invitation comes back pending with its inviter, and a sibling Add forwards it as pending, instead of
  showing a chat the user never accepted. A sibling's accept or decline that arrived while the chat was deleted is
  re-applied when it comes back. A chat deleted before this release comes back accepted, as before.
- Existing-key onboarding searches public records without prompting external signers. An inbox relay can request one authenticated check if anonymous checks fail. A stalled signer pauses for reconnection and retry, and repair signing has a deadline (#3725).
- Existing-key setup offers signer reconnection when an external signer cannot authorize an inbox check. If a signed inbox check fails at a relay, Retry can try another relay already listed in the account's inbox declaration.
- Preserve verified relay-list records returned before an incomplete, NIP-67, or `CLOSED` inspection end, classify persistent NIP-67 `auth` hints as `AuthenticationRequired`, classify `rate-limited:` and bare `error:` `CLOSED` reasons as transient, retry transient relay-list lookups once within `CHECK_WAIT`, and fail fast on bare `auth-required:` `CLOSED` replies without an `AUTH` challenge (#3721, #3724).
- Reuse completed kind-10002 EOSE answers on the `Relays` step without redialing declared endpoints, and prevent incomplete lookups from overwriting a newer checkpointed relay list with an older copy or `None` (#3721, #3728).
- Lossless one-click relay repair preserves invalid URLs, unknown markers, and long (>16) NIP-65 lists (marking long previews inconclusive), and copies allowed `r`-tag URLs into `relay` tags on kind-10050 inbox lists while keeping the 16-relay inbox cap (#3727).
- Preserve an unapproved relay repair proposal as `inconclusive` under a bumped revision when one source fails during approval while an authoritative source still confirms the basis is newest (#3722).
- Surface per-relay refusal findings on repair publication and initial KeyPackage publication; offer `CancelRepair` and `EditRelays` after definitive all-target repair refusals, and offer `EditRelays` to update NIP-65 write relays when initial KeyPackage publication is refused (#3723, #3747).
- History-bundle file keys and group-image upload/download records redact `Debug` output and erase key material on
  drop, and SQLCipher salt reads enforce a size cap and omit account paths from errors (mdk#3796).
- An invitation answer refused while the device group's epoch settles goes out on the worker turn after it settles
  also when a maintenance pass in between ends early on a failed read, instead of waiting for the 15 s maintenance
  retry (mdk#3573).
- An invitation answer that a linked device must send again after a fork between linked devices goes out on the
  worker turn after the device group's epoch settles, instead of waiting up to 15 s for the next maintenance pass
  (mdk#3573).
- When a live receive's state save fails, the worker's short retry still runs if a route sync succeeds in between.
  Before, an activity delivered once by that receive waited up to 15 s for the next maintenance pass.
- A device-group message pinned to an epoch is refused before it writes its withdrawal record while this device's
  own device-group commit is still unpublished. Before, each retry in that window wrote a record that could push
  older ones out of the bounded record table.
- An owed invite Welcome with no usable inbox route is delivered once the account worker's lookup of the recipient's
  inbox relay list finds one (mdk#2261): the worker looks the list up after each paced retry that found no route, and
  sends the Welcome without a re-invite.
- `marmot_invite_deliveries` keeps reporting `MARMOT_INVITE_DELIVERY_STATE_KIND_UNDELIVERABLE` for an invite's Welcome
  that no relay acknowledged by its delivery deadline (7 days after it was staged with the invite, or its KeyPackage's
  expiry if sooner; mdk#3589), once its invite's commit is confirmed even if the device clock is set back, and the change is announced once: on the next start
  when the deadline passed while the app was closed.
- `marmot_invite_deliveries` now reports `MARMOT_INVITE_DELIVERY_STATE_KIND_UNDELIVERABLE` for an invite's Welcome
  that no relay stored by its delivery deadline, 7 days after the invite or its KeyPackage's expiry if sooner
  (mdk#3589); that Welcome is never sent again and leaves `marmot_pending_welcome_deliveries`.
- An invite's Welcome that no relay acknowledged by its delivery deadline (7 days after it was staged with the invite,
  or its KeyPackage's expiry if sooner; mdk#3589) reads `Undeliverable` in `invite_deliveries` for good once its
  invite's commit is confirmed, even if the device clock is set back, and `InviteDeliveryChanged` announces it once: on the next start when the deadline passed
  while the app was closed.
- An invite's Welcome that no inbox relay stores is no longer retried forever (mdk#3589). It is sent until its delivery
  deadline, 7 days after the invite or its KeyPackage's expiry if sooner, then reads `Undeliverable` in
  `invite_deliveries` with its latest attempt's problem, and leaves `pending_welcome_deliveries`. A Welcome owed from
  before this upgrade is held to 7 days from its gift wrap's timestamp. The startup retry now keeps each relay's
  backoff. The invitee stays a member.
- `sign_out`, `sign_in_account`, `remove_account`, `login`, `login_external_signer`,
  `login_recovering_incomplete_setup`, `set_audit_log_settings` and `nip46_remove` keep running when their call is
  cancelled, on Kotlin and Swift (mdk#3670). A cancel between their steps could leave a withdrawn KeyPackage slot on
  a signed-in account, a paused setup that sign-in never resumed, an account whose moderation reports were already
  purged, a half-imported account that a retry rejects as existing, a worker still using a removed signer, or running
  sessions that disagree with the stored audit-log switch. Running sessions now apply the stored audit-log switch, so
  overlapping `set_audit_log_settings` calls end with the last stored value.
- An admin's own message deletion now reports `deletionSource: Author`, and a member added back to a chat after being
  removed or leaving gets a "member added" `groupSystem` row naming who added them.
- Swift `uniffiRustCallAsync` no longer ABBA-deadlocks when `Task.cancel()` races with `RustFuture::wake` (mdk#3821): cancellation is dispatched off Swift's `onCancel` handler so `rust_future_cancel` never acquires `RustFuture`'s mutex while `libswift_Concurrency` holds `AsyncTask`'s `StatusRecordLock`, and the poll loop checks `Task.isCancelled` before each native poll.
- A chat's `activity_sort_at` is its latest message, read position or retained floor, and falls back to
  `conversation_created_at` only when it has none. A chat a linked device or a restore stored after it began, with
  older history imported, no longer sorts at the time this device stored it (mdk#3580). Migration 0220 re-sorts the
  rows the old rule anchored at creation.
- Migration 0222 adds `small_state_broadcast_devices`: the roster devices, slot and `linked_at`, that this device's
  last small-state broadcast was made for. `begin_small_state_broadcast` takes them and `SmallStateBroadcast` returns
  them as `devices`, so `SmallStateSchedule` and `SmallStateBroadcast` are no longer `Copy` (mdk#3556).
- An agent item whose first event this device lacks is shown from the first edit of it this device received, not the
  one with the earliest `created_at`. Any member can send such an edit and choose its timestamp, so a backdated one
  could take the item from its agent.
- Hardened SQLCipher open pragma ordering (`cipher_compatibility` after `PRAGMA key`, `busy_timeout` before keying),
  key-package eviction watermark dominance, malformed directory profile resilience, lowercase hex canonicalization of
  `group_id_hex` across migration `0228` and all read/write boundaries, immediate WAL write transactions, media-catalog
  paging and busy retries, compaction recovery and close classification, secret zeroization, saturating SQLite integer
  updates, chunked stale-component deletion, secure message pruning, and atomic multi-statement OpenMLS deletes.

### Security

- Enforced the local copy history floor (`join_epoch` and `local_copy_install_epoch`) before candidate-branch buffering and across convergence graph/pass seeding, atomically retained founding epoch anchors on group creation, and gated missing-anchor unrecoverable transitions on authenticated installed-copy lineage so unverified past-epoch headers outside a healthy group's retained history are rejected as stale instead of halting the group.
- Enforced the local copy history floor (`join_epoch` and `local_copy_install_epoch`) before candidate-branch buffering and across convergence graph/pass seeding, atomically retained founding epoch anchors on group creation, and gated missing-anchor unrecoverable transitions on authenticated installed-copy lineage so unverified past-epoch headers outside a healthy group's retained history are rejected as stale instead of halting the group.

## Binding surface delta

- **Baseline:** `v0.19.0` (`3fce95465cdea1edc8456dbd1c6691d1c8dc1f2e`)
- **Target:** `7847b7f7ae761d41dc07784cd0308c29127b7ff9` (classified `minor`, target `0.20.0`)

## UniFFI (`marmot-uniffi`)

### Removed or changed exported types (breaking)

- Changed `LocalSendStatusFfi`
- Changed `MarmotEventFfi`
- Changed `MarmotKitError`
- Changed `MarmotOptions`
- Changed `NotificationTrafficClassFfi`
- Changed `OnboardingIssueFfi`
- Changed `OnboardingOptionsFfi`
- Changed `OnboardingSnapshotFfi`
- Changed `TimelineMessageRecordFfi`
- Changed `TimelineReplyPreviewFfi`
- Changed `TimelineUpdateTriggerFfi`

### Added functions

- `Marmot::account_relay_health`: `pub async fn account_relay_health( &self, account_ref: String, ) -> Result<conversions::AccountRelayHealthFfi, MarmotKitError>`
- `Marmot::check_account_relays`: `pub async fn check_account_relays( &self, account_ref: String, ) -> Result<conversions::AccountRelayHealthFfi, MarmotKitError>`
- `Marmot::invite_deliveries`: `pub async fn invite_deliveries( &self, account_ref: String, group_id_hex: Option<String>, ) -> Result<Vec<crate::conversions::InviteDeliveryFfi>, MarmotKitError>`
- `Marmot::send_custom_event_with_client_token`: `pub async fn send_custom_event_with_client_token( &self, account_ref: String, group_id_hex: String, kind: u64, tags: Vec<Vec<String>>, content: String, client_token: String, ) -> Result<LocalSendAcceptanceFfi, MarmotKitError>`
- `Marmot::submit_tagged_reply`: `pub async fn submit_tagged_reply( &self, account_ref: String, group_id_hex: String, target_message_id: String, text: String, tags: Vec<Vec<String>>, client_token: String, ) -> Result<LocalSendAcceptanceFfi, MarmotKitError>`
- `Marmot::submit_tagged_sticker`: `pub async fn submit_tagged_sticker( &self, account_ref: String, group_id_hex: String, sticker_ref: StickerRefFfi, tags: Vec<Vec<String>>, client_token: String, ) -> Result<LocalSendAcceptanceFfi, MarmotKitError>`
- `Marmot::submit_tagged_text`: `pub async fn submit_tagged_text( &self, account_ref: String, group_id_hex: String, text: String, tags: Vec<Vec<String>>, client_token: String, ) -> Result<LocalSendAcceptanceFfi, MarmotKitError>`
- `Marmot::submit_thread_message`: `pub async fn submit_thread_message( &self, account_ref: String, group_id_hex: String, parent_message_id: String, text: String, attachments: Vec<MediaAttachmentReferenceFfi>, tags: Vec<Vec<String>>, client_token: String, ) -> Result<LocalSendAcceptanceFfi, MarmotKitError>`

### Added exported types

- `AccountRelayHealthFfi`
- `AccountRelayWarningFfi`
- `AgentItemFfi`
- `AgentItemStateFfi`
- `InviteCancelReasonFfi`
- `InviteDeliveryFfi`
- `InviteDeliveryProblemFfi`
- `InviteDeliveryStateFfi`
- `InviteDeviceDeliveryFfi`
- `InviteRelayCountsFfi`
- `OnboardingCreatedInboxListFfi`
- `RelayHealthFaultFfi`
- `RelayHealthRowFfi`
- `RelayHealthStateFfi`
- `RelayListPresenceFfi`
- `RelayRepairActionFfi`
- `RelayRoleFfi`
- `RelayWarningKindFfi`
- `RelayWarningSeverityFfi`

## C ABI (`marmot-c`)

### Removed or changed exported types (breaking)

- Changed `MarmotClientOptions`
- Changed `MarmotEvent`
- Changed `MarmotEvent_Tag`
- Changed `MarmotLocalSendStatus`
- Changed `MarmotNotificationTrafficClass`
- Changed `MarmotOnboardingIssue`
- Changed `MarmotOnboardingSnapshot`
- Changed `MarmotTimelineMessageRecord`
- Changed `MarmotTimelineReplyPreview`
- Changed `MarmotTimelineUpdateTrigger`
- Changed `enum MarmotStatus`

### Added functions

- `marmot_account_relay_health`: `MarmotStatus marmot_account_relay_health(const struct MarmotClient *client, const char *account_ref, struct MarmotAccountRelayHealth **out);`
- `marmot_account_relay_health_free`: `void marmot_account_relay_health_free(struct MarmotAccountRelayHealth *ptr);`
- `marmot_begin_onboarding_with_options`: `MarmotStatus marmot_begin_onboarding_with_options(const struct MarmotClient *client, const char *nsec, const char *const *default_relays, uintptr_t default_relays_len, const char *const *discovery_relays, uintptr_t discovery_relays_len, const char *const *inbox_relays, uintptr_t inbox_relays_len, uint32_t flags, struct MarmotOnboardingSnapshot **out);`
- `marmot_check_account_relays`: `MarmotStatus marmot_check_account_relays(const struct MarmotClient *client, const char *account_ref, struct MarmotAccountRelayHealth **out);`
- `marmot_invite_deliveries`: `MarmotStatus marmot_invite_deliveries(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotInviteDeliveryList **out);`
- `marmot_invite_delivery_list_free`: `void marmot_invite_delivery_list_free(struct MarmotInviteDeliveryList *list);`
- `marmot_send_custom_event_with_client_token`: `MarmotStatus marmot_send_custom_event_with_client_token(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, uint64_t kind, const struct MarmotStringArray *tags, uintptr_t tags_len, const char *content, const char *client_token, struct MarmotLocalSendAcceptance **out);`
- `marmot_submit_tagged_reply`: `MarmotStatus marmot_submit_tagged_reply(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *target_message_id, const char *text, const struct MarmotStringArray *tags, uintptr_t tags_len, const char *client_token, struct MarmotLocalSendAcceptance **out);`
- `marmot_submit_tagged_sticker`: `MarmotStatus marmot_submit_tagged_sticker(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *pack_coordinate, const char *shortcode, const char *plaintext_sha256, const struct MarmotStringArray *tags, uintptr_t tags_len, const char *client_token, struct MarmotLocalSendAcceptance **out);`
- `marmot_submit_tagged_text`: `MarmotStatus marmot_submit_tagged_text(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *text, const struct MarmotStringArray *tags, uintptr_t tags_len, const char *client_token, struct MarmotLocalSendAcceptance **out);`
- `marmot_submit_thread_message`: `MarmotStatus marmot_submit_thread_message(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *parent_message_id, const char *text, const struct MarmotMediaAttachmentReference *attachments, uintptr_t attachments_len, const struct MarmotStringArray *tags, uintptr_t tags_len, const char *client_token, struct MarmotLocalSendAcceptance **out);`

### Added exported types

- `MarmotAccountRelayHealth`
- `MarmotAccountRelayWarning`
- `MarmotAgentItem`
- `MarmotAgentItemState`
- `MarmotEvent_InviteDeliveryChanged_Body`
- `MarmotEvent_RelayHealthChanged_Body`
- `MarmotInviteCancelReason`
- `MarmotInviteDelivery`
- `MarmotInviteDeliveryList`
- `MarmotInviteDeliveryProblem`
- `MarmotInviteDeliveryState`
- `MarmotInviteDeliveryStateKind`
- `MarmotInviteDeviceDelivery`
- `MarmotInviteRelayCounts`
- `MarmotOnboardingCreatedInboxList`
- `MarmotRelayHealthFault`
- `MarmotRelayHealthRow`
- `MarmotRelayHealthState`
- `MarmotRelayListPresence`
- `MarmotRelayRepairAction`
- `MarmotRelayRole`
- `MarmotRelayWarningKind`
- `MarmotRelayWarningSeverity`

## SQLite Storage Migrations

Downgrade across these migrations is unsupported. Upgrade all processes sharing an account database together and keep a pre-upgrade backup/export.

- `crates/nostr-directory/src/cache/migrations.rs`
- `crates/storage-sqlite/src/base/migrations.rs`
- `crates/storage-sqlite/src/base/migrations/0219_agent_item_order.rs`
- `crates/storage-sqlite/src/base/migrations/0220_chat_activity_creation_fallback.rs`
- `crates/storage-sqlite/src/base/migrations/0221_agent_item_expired_targets.rs`
- `crates/storage-sqlite/src/base/migrations/0222_small_state_broadcast_devices.rs`
- `crates/storage-sqlite/src/base/migrations/0223_local_deletion_invitation.rs`
- `crates/storage-sqlite/src/base/migrations/0224_epoch_gap_evidence_floor.rs`
- `crates/storage-sqlite/src/base/migrations/0225_welcome_delivery_ledger.rs`
- `crates/storage-sqlite/src/base/migrations/0226_local_submission_refused.rs`
- `crates/storage-sqlite/src/base/migrations/0227_welcome_expiry_mark.rs`
- `crates/storage-sqlite/src/base/migrations/0228_canonicalize_group_id_hex.rs`
- `crates/storage-sqlite/src/base/migrations/baseline.sql`
- `crates/storage-sqlite/src/shared/migrations.rs`
