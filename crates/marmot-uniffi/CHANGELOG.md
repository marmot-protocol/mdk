# Changelog

## Unreleased

### Added

- `sticker_pack_share_link(account_ref, coordinate)` builds a canonical Sonar pack link locally with retained
  relay hints, falling back to current account outbox candidates for packs without hints (mdk#3283).

### Fixed

- Isolate Apple release-profile mock build outputs from inherited
  `CARGO_TARGET_DIR` values (mdk#2906).

## 0.16.0 - 2026-11-12

### Breaking changes

- `AppGroupHydrationQuarantineReasonFfi` adds `REWIND_RESTORE_FAILED` (Swift `.rewindRestoreFailed`), reported by the
  quarantined-groups read and `GroupEventKindFfi::GroupHydrationQuarantined` (mdk#3272): a read of past group state
  could not restore the live group. Neither a retry nor a re-join clears it: `retry_hydrate_quarantined_group` returns
  `false`, `group_recovery_status` omits the group's `rejoin_invitations`, and `confirm_group_rejoin` fails as
  `MarmotKitError::UnknownGroup` for them. The next account open tries to restore the live state. A group with two
  interrupted rewinds, which reported `GROUP_RECORD_LOAD_FAILED`, now reports this reason. Kotlin `when` and Swift
  `switch` statements that cover every case must add it. Use the matching native library with regenerated bindings.

- `GroupEventKindFfi::QueuedIntentRefused` adds `artifact: OversizedArtifactFfi?` and `size_class: EventSizeClassFfi?`
  (mdk#2334). With `reason` `event_too_large`, a queued send's commit or an invitee's Welcome fits none of its relays'
  known size limits, or every relay refused it for size: `artifact` names that event and `size_class` its coarse size.
  Both are `nil` for other reasons. Swift `case .queuedIntentRefused(...)` patterns that bind values positionally, and
  Kotlin `GroupEventKindFfi.QueuedIntentRefused(...)` constructors and destructuring declarations, add the two fields.
  Before, a queued commit that every group relay refused for size was re-sent on every drain; it is now dropped and
  announced once.

- `MarmotKitError` adds `Nip46 { reason: Nip46ErrorFfi }` (mdk#828), which carries a NIP-46 session failure's typed
  reason. Kotlin `when` and Swift `switch` statements that cover every case must add it.

### Added

- Add `Nip46SessionFfi`, typed permission/status/state/error records, and Marmot
  creation/login/register/resume/removal methods for Swift and Kotlin. MDK owns the
  transport and account-scoped credentials; no host signer callback is retained.
  New and imported sessions require explicit review and approval of the exact
  permission snapshot. Runtime startup restores persisted sessions before workers.
  Session operations include relay-ready pairing offers, ping, reconnectable disconnect, scoped cancellation,
  auth-challenge completion, export, terminal cancellation, and bounded logout.
  `MarmotKitError::Nip46` retains the typed session reason; exhaustive switches
  need the new case. Local-key and arbitrary host callback APIs are unchanged.
  Native login/register adoption remains runtime-owned after caller cancellation;
  only the wait ends. Pairing is a separate bounded, caller-cancellable connect call.
  Login requires an already-verified Ready session and rejects other states without
  connecting or creating an account. Unbound pairing never mutates an account.
  Explicit session cancel/disconnect/logout interrupts adoption; shutdown interrupts
  and settles owned work before returning. Failed completed-account Native rebind
  restores prior local callbacks, records, and activation, not published KeyPackages.
  Ordinary sign-out cleanup remains explicit; legacy host login is unchanged.

- Ship Swift `nextCancellable()` adapters for presented chat lists, chat-list
  windows, account attention, conversation windows, and block lists inside
  `MarmotKit.swift` (mdk#2760). MDK owns their native-pending cancellation
  integration checks. Remove the host's handwritten adapter when adopting
  the combined Swift asset to avoid duplicate method definitions.
  Task cancellation takes priority over completed native typed errors;
  active tasks retain those errors.

- `MarmotDeploymentFfi` adds `relay_event_limits: [RelayEventLimitFfi]`, empty by default in Swift and Kotlin: the
  largest event each listed relay accepts, for relays that do not advertise it (mdk#2334). MDK sends no group event,
  Welcome or account-signed event over a relay's known limit. For events over 64 KiB MDK also counts the WebSocket
  message size a relay's NIP-11 document advertises, with `marmot_deployment_neutral()` too. A send that fits none of
  its relays reaches none, and a call that returns relay errors then fails as `MarmotKitError::EventTooLarge`. A group
  create or invite whose Welcome fits none of an invitee's inbox relays fails that way before anything is created or
  sent. `marmot_deployment_white_noise()` sets 2 MiB on White Noise's two relays. Use the matching native library with
  regenerated bindings.

- `start_direct_conversation(account_ref, peer_account_id) -> String` (Swift
  `startDirectConversation(accountRef:peerAccountId:)`) reuses this account's direct conversation with a hex or npub
  peer, or creates an unnamed group with both accounts as founding admins, and returns the MLS group id as hex
  (mdk#464). Cancelling detaches the wait without cancelling creation, and a retry reuses the canonical group. A
  self-peer fails as `MarmotKitError::Runtime`. `create_group` and existing roles are unchanged.

- `account_relay_liveness(account_ref) -> [RelayLivenessFfi]`, `subscribe_relay_liveness(account_ref) ->
  RelayLivenessSubscription` and `reconnect_relay(account_ref, url) -> RelayLivenessFfi` (mdk#329).
  `RelayLivenessFfi` has `url`, `status: RelayStatusFfi` (`UNKNOWN`, `CONNECTING`, `CONNECTED`, `OFFLINE`; Swift
  `.unknown` …), `last_attempt_unix: UInt64?` and `last_error: String?`. `RelayLivenessSubscription.snapshot()`
  returns the first list once. `next()` returns later complete lists, or `nil` after `cancel()` or runtime shutdown.
  `cancel()` does not disconnect relays. `reconnect_relay` refuses relays the account has not configured
  (`MarmotKitError::Runtime`). Additive; aggregate relay health is unchanged.

- `audit_delivery_status_v5()` returns one `AuditDeliveryStatusV5Ffi` per account (mdk#3300): `last_success_at_ms`,
  `last_failure: AuditDeliveryFailureV5Ffi?` (`kind: AuditDeliveryFailureKindV5Ffi`, `http_status`, `at_ms`),
  `consecutive_failures`, `rejected_batches`, `paused` and `backlog: AuditDeliveryBacklogV5Ffi?`. It never dials.
  `ReceiverBlocked` pauses automatic delivery until `set_audit_otlp_config_v5` changes the destination, endpoint or
  token, or the host calls `post_audit_log_tracker_update_v5()`. Additive; use the matching native library.

- `audit_log_retention()` and `set_audit_log_retention(AuditLogRetentionFfi)` read and persist the local audit
  retention policy (mdk#3300): `max_age_days` (default 30, clamped to 1-30) and `max_bytes_per_account` (default
  256 MiB, at least 16 MiB). The setter returns the stored, clamped value. Additive.

- `app_performance_snapshot().runtime_operations` gains 17 `read_queue_*` rows: a host read's wait on its account
  worker (mdk#3273).

### Changed

- Local audit files are deleted above a 256 MiB per-account budget by default, oldest delivered or untracked sealed
  segments first; before, only the 30-day age limit applied (mdk#3300). Raise it with `set_audit_log_retention`.
  v5 delivery retries `409`, skips a record the receiver rejects with `400`, `413` or `422` after isolating it, and
  pauses on `401`, `403`, `404` or another unexpected response instead of retrying silently.

- `rotate_key_package`, `republish_key_package`, account setup's KeyPackage publish, `block_user`, `unblock_user` and
  `sync_sticker_packs` fail as `MarmotKitError::EventTooLarge { artifact: Other }` when every relay refuses their
  event for size, by its own answer or over its known limit (mdk#2334). Before, they failed as `Runtime`,
  `BlockListUnavailable` and `StickerNetwork`. A block edit retried after an uncertain attempt stays
  `BlockPublicationUncertain`, and a sticker install or uninstall still succeeds, its list owed to the next sync.
  Profile, follow-list and relay-list publishes (such as `publish_user_profile` and `publish_relay_lists`) whose event
  fits none of their relays' known limits also fail as `EventTooLarge { artifact: Other }`, sent nowhere.

### Fixed

- A `decline_group_invite` that timed out with `MarmotKitError::AccountWorkerResponseTimedOut`, or whose task was
  cancelled, no longer leaves the group later if it was still queued (#3031). An accept sent afterwards keeps the
  group. A decline the worker had already started still completes, so after a timeout read the group's state before
  accepting.

- Wiping or removing a generated identity whose setup was still publishing no longer creates a new, unrequested
  account (whitenoise-ios#1302). `sign_in_account` resumes a generated setup that its sign-out stopped.

- An offline account no longer repeats its full replay synchronization on every idle maintenance tick (#3238).

## 0.15.0 - 2026-11-09

Regenerate Swift/Kotlin bindings with the matching native library. The main
source breaks: `TimelineMessageQueryFfi` gains filter and cursor fields,
`MarmotDeploymentFfi` loses its two KeyPackage-client fields, `MarmotKitError`,
`MarmotEventFfi` and several other enums gain cases, and
`MarmotEventFfi::WelcomeDeliveryPending` gains `size_class`. Account storage
migrates on first open, and downgrade is unsupported. A new group whose
founding devices all run 0.15 requires the account-devices component, so
clients older than 0.15 cannot be invited into it. See the
[release notes](../../docs/release/0.15.0.md) and the
[client upgrade guide](../../docs/integration/0.15.0.md).

### Breaking changes

- `MarmotDeploymentFfi` drops `key_package_preferred_clients` and
  `key_package_last_clients` (mdk#2628, mdk#2649): the KeyPackage `client` tag
  no longer ranks invite candidates. Remove them from any record a host builds
  field by field; hosts that start from `marmot_deployment_white_noise()` or
  `marmot_deployment_neutral()` only regenerate.

- `TimelineMessageQueryFfi` adds `sender`, inclusive `since`, exclusive
  `until`, integer `attachment_type` (`0` Any, `1` Image, `2` Video, `3`
  Audio, `4` File, `5` Attachment; binding default `0`), `search_wall_clock`
  (binding default `false`) and `cursor_group_id` (mdk#3245). The optional
  fields have no binding default, and all of them come before `before`, so
  every Swift initializer and positional Kotlin constructor call must change.
  Filters combine before the page limit; explicit wall-clock order supports
  deterministic account-wide cursors with the anchor row's group id. Default
  queries keep canonical group ordering. See the README's "Advanced timeline
  search".

- `MarmotEventFfi::WelcomeDeliveryPending` adds `size_class:
  Option<EventSizeClassFfi>` (mdk#2999), a best-effort coarse diagnosis of a
  Welcome refused for size. Swift patterns and Kotlin destructuring that bind
  every associated value need the new field.

- Records hosts may build for previews, mocks or tests gain fields without a
  binding default: `AccountSummaryFfi.unlinked`; `leave_blocked` on
  `AppGroupRecordFfi`, `ChatListRowFfi` and `GroupManagementStateFfi`;
  `can_cancel_leave` on `GroupManagementStateFfi` and
  `ConversationCapabilitiesFfi`; `sticker: Option<StickerRefFfi>` on
  `AppMessageRecordFfi`, `ReceivedMessageFfi`, `NotificationUpdateFfi`,
  `ChatListMessagePreviewFfi`, `TimelineMessageRecordFfi` and
  `TimelineReplyPreviewFfi`; `recipient_confirmed`, `imported_from` and
  `history_import_provenance` on `TimelineMessageRecordFfi`; and
  `groups_left_to_siblings` and `siblings_not_reached` on `WipeOutcomeFfi`.
  Each is described below.

- `MarmotKitError` adds 22 cases; exhaustive Swift `switch` / Kotlin `when`
  handling needs them: `EventTooLarge`, `MediaReferenceStaleEpoch`,
  `MediaReferenceEpochUnsettled`, `GroupRecoveryUnsettled`,
  `GroupRecoverySourceMismatch`, `LeaveNotBlocked`,
  `AccountDevicesActivationRefused`, `InvalidChatListQuery`, `AccountUnlinked`,
  the sticker cases (`InvalidSticker`, `StickerNotFound`, `StickerNetwork`,
  `StickerImport`, `StickerImportUnsupported`) and the emoji-set cases
  (`InvalidEmojiSet`, `EmojiSetNotFound`, `EmojiSetNetwork`,
  `EmojiImageTooLarge`, `EmojiImageUnsupported`, `EmojiSetLimit`,
  `EmojiSetChanged { current_event_id_hex }`, `EmojiSetInstallCancelled`).
  The new APIs that return them are under Added.

- `MarmotKitError::EventTooLarge { artifact: OversizedArtifactFfi, size_class:
  EventSizeClassFfi }` replaces `Publish` or `Runtime` when every current
  target refused an event for size on the observed attempt (mdk#2993). It is
  not proof of non-delivery or a terminal outcome; native retries and
  confirmed state are kept, and no relay limit is inferred.

- `MarmotKitError` adds `MediaReferenceStaleEpoch { source_epoch,
  current_epoch }` and `MediaReferenceEpochUnsettled { source_epoch }`
  (mdk#2158). They replace the generic `InvalidMediaReference` for these two
  cases: the first means the group left the epoch the attachment was
  encrypted under, so upload the file again; the second means the epoch is
  settling, so sync and send again.

- `MediaAttachmentReferenceFfi` adds optional `source_epoch_identity`
  (mdk#2840; binding default none). Preserve it when saving an upload
  reference and sending it back, including custom emoji reactions. Outbound
  sends refuse a missing identity or a changed upload branch with
  `MediaReferenceStaleEpoch`, so an upload reference saved under 0.14 must be
  uploaded again from its retained bytes. The field is local metadata, never
  written to `imeta`. Received and legacy references remain downloadable.

- `MarmotKitError` now depends on what an error is, not on which MDK layers
  wrapped it (mdk#2602). Three answers change:
  - A busy, closed or full store that the account session reported itself now
    arrives as `StorageBusy`, `StorageClosed` or `StorageFull`, as it does when
    the engine reports it. Before, it arrived as `Runtime`.
  - An external-signer rejection now arrives as `ExternalSignerRejected` on
    every path, as it already did on transport publishes and at account open.
    Before, a rejection on other paths, such as signing an identity proof for
    a KeyPackage or a group change, arrived as `Runtime`.
  - Wipe outcome `reason` strings follow the same rule. An engine storage
    failure reads `local storage error`, an unknown engine group `unknown
    local group`, the admin refusals `AdminDepletion` and
    `AdminCannotSelfRemove` `account is the chat's last admin` and `account is
    an admin of the chat`, and any other engine failure `session error`.
    Account failures outside the engine still read `account error`.

- A blocked leave is shown and can be cancelled (mdk#3014). `leave_blocked`
  on `AppGroupRecordFfi`, `ChatListRowFfi` and `GroupManagementStateFfi`
  means this account is the group's last active admin, so its leave cannot
  finish; `can_cancel_leave` on `GroupManagementStateFfi` and
  `ConversationCapabilitiesFfi` says the user can cancel it. New
  `cancel_leave(account_ref, group_id_hex)` cancels it on this device only;
  the chat reads as joined again. Any other state returns the new
  `LeaveNotBlocked`.

- `TimelineMessageRecordFfi` adds `recipient_confirmed: bool` (mdk#1291):
  true when a peer reacted to an own send that failed with no relay
  acceptance on record, which proves the peer received it. It stays true if
  retention later prunes that reaction. Render the row as delivered:
  its `invalidation_status` is null and its `source_message_id_hex` stays
  null. The flip arrives with the `DeliveryOrSendStateChanged` trigger, and
  `ChatListMessageDeliveryStateFfi` reports `Delivered`. A host that derives
  "sending" from a null `source_message_id_hex` must also read
  `recipient_confirmed`, or a settled send shows as sending instead of
  failed. A row's change carries one trigger, so the reaction that settles
  or unsettles a send arrives as `DeliveryOrSendStateChanged`: recompute
  that row's reactions for this trigger too. Replies quoting the send arrive
  as `ReplyPreviewChanged`.

- `HistoryNoticeCauseFfi` adds `UnprovenHistory`, and `MarmotEventFfi` adds
  `RecoveryStatusChanged { account_id_hex, account_label }` (mdk#2660). Both
  are produced now that the recovery runner owns account history (see
  Changed). `HistoryNoticeCauseFfi` also adds `BeforeRejoin` (mdk#2660 row
  11): one notice per rejoin, when a Welcome installed a new copy of a group in
  place of this device's old one (an automatic rejoin after the old copy could
  not be repaired, a reentry after a trusted removal, or a consented fork
  discard). Messages from before the rejoin that it had not received are
  unavailable. Dismissing it retires nothing further.

- `GroupEventKindFfi` adds `QueuedIntentRefused { intent_id_hex, intent_kind,
  reason }` (mdk#2694): a send that waited for the group to settle was
  dropped because the settled state refused it; tell the user, who may try
  again. Such refused intents are retired instead of staying queued.

- `SelfMembershipFfi` and `ConversationParticipationFfi` add `DeviceRemoved`
  (mdk#2628 item 3.6b): this device's leaf was removed from a chat the account
  stays in through another of its devices. Show no "removed from group"
  notice for it.

- `MarmotEventFfi` adds `LinkedDevicesChanged`, `KeyPackageRefreshOverdueChanged`,
  `UnrecognizedSignInsChanged`, `CompromiseWarningChanged`,
  `DeviceLinkChanged`, `ChatHistoryImportsChanged` and `DeviceUnlinked`, each
  `{ account_id_hex, account_label }` (mdk#2628). Exhaustive handling needs
  the arms in every build; MDK sends them only with experimental device
  groups (see below), so ordinary hosts can ignore them.

### Added

- `pending_welcome_deliveries(account_ref)` lists, oldest first, the group
  creates and confirmed Adds whose Welcome is still owed, as
  `PendingWelcomeDeliveryFfi` records with repair handles and the same
  best-effort `size_class` (mdk#2999). The `WelcomeDeliveryPending` notice
  fires once per process and Welcome; re-read this query for later causes. A
  coarse legacy retry may replace a specific cause with none while the same
  repair handle and debt remain. A Welcome's `EventTooLarge` explains the
  observed attempt, not earlier non-delivery or a terminal outcome.

- `account_recovery_status(account_ref)` returns an `AccountRecoveryStatusFfi`:
  the groups whose history is still being fetched (`catching_up_group_ids_hex`),
  whether the inbox's is (`inbox_catching_up`), and every notice as
  `history_notices` lists them (mdk#2660). Re-read it on
  `RecoveryStatusChanged`.

- Select all over a whole chat-list view (mdk#2983):
  `chat_list_ids(account_ref, view)` returns every chat ID in display order,
  beyond the open window, and `revalidate_chat_list_ids(account_ref, view,
  group_ids)` returns the subset of a host selection still in the view. Hosts
  keep checkbox state, revalidate before a bulk action, then call the
  existing per-chat commands.

- Filtered chat-list queries (mdk#2983): `open_chat_list_query_window`,
  `chat_list_query_ids` and `revalidate_chat_list_query_ids` take a
  `ChatListViewQueryFfi` whose filter is a flat `ChatListFilterNodeFfi` list
  (node 0 is the root; children are later indices). `All`, `Any` and `Not`
  combine `Condition` leaves (`ChatListConditionFfi`, including `Direct`,
  `Group` and `Muted`), `GroupIds`, `Text` and `MessageText`. `Text` matches
  a chat's title, group name, description or direct-chat peer profile name;
  `MessageText` matches chats with a visible message containing the text,
  and only the ID queries accept it (a window fails with
  `InvalidChatListQuery` `MessageTextInWindow`). Both are trimmed and
  lowercased, at most 1024 bytes. A chat whose kind is still `Unknown`
  matches neither kind; a window filtered on `Muted` updates when a mute
  expires. Invalid queries fail with `InvalidChatListQuery { reason:
  ChatListQueryErrorFfi }`; while presentation or retained edits are still
  being prepared, text queries fail with `ChatPresentationNotReady`, so
  retry. Fixed-view methods are unchanged. See the README's "Chat-list select
  all and filtered queries".

- NIP-51 emoji sets (mdk#3022, mdk#3043): `sync_emoji_sets`, `emoji_sets`,
  `emoji_set`, `fetch_emoji_set`, `user_emoji_list`, `install_emoji_set`,
  `uninstall_emoji_set`, `fetch_emoji_set_asset`, `fetch_emoji_set_cover`,
  `installed_custom_emoji` and `read_installed_custom_emoji`, with their
  records and `EmojiSkipReasonFfi`. `install_emoji_set(account_ref,
  coordinate, expected_event_id_hex, control)` binds the install to the
  version the user was shown and takes an `EmojiSetInstallControlFfi`
  (`cancel()`, `is_cancelled()`, `progress()` returning
  `EmojiSetInstallProgressFfi`); the asset and cover fetches take the same
  `expected_event_id_hex`. Image fetches reveal the user's IP address to the
  set author's image host, so call them only after the user opens or installs
  a set. Any `image/*` response type is accepted. See the README's "Emoji
  sets".

- Sonar-compatible stickers (mdk#875): `sticker_packs`, `sticker_pack`,
  `sync_sticker_packs`, `fetch_sticker_pack`, `install_sticker_pack`,
  `uninstall_sticker_pack`, `fetch_sticker_asset`, `send_sticker` and
  `import_signal_sticker_pack` (which validates the link and then refuses
  before any network call), with `StickerRefFfi`, `StickerFfi`,
  `StickerPackFfi`, `StickerAssetFfi`, `StickerSyncResultFfi` and
  `StickerImportResultFfi`. Message, preview and timeline records carry the
  typed kind-9 reference in `sticker`; it is `None` for a deleted row.
  `StickerFfi.plaintext_sha256` is the exact hash a `StickerRefFfi` carries.
  See the README's "Stickers".

- `reaction_attachment(account_ref, group_id_hex, reaction_message_id_hex)`
  resolves one active custom-emoji reaction's matching encrypted image to its
  original attachment source slot (mdk#2151). Use ordinary host-managed
  acquisition and opaque local reads; no group-wide `list_media` scan or
  `download_media` fallback is required. The additive source migration backfills
  retained eligible reactions. See `ATTACHMENT-HISTORY.md` for adoption and
  reaction replacement/removal behavior.

- An admin can turn on account-devices in an existing group (mdk#2628):
  `enable_account_devices(account_ref, group_id_hex)` sends one admin Commit,
  only when the user asks, and the group can never turn it off.
  `account_devices_activation(account_ref, group_id_hex)` answers whether the
  group is eligible with an `AccountDevicesActivationFfi` (`Eligible`,
  `NotAdmin`, `AlreadyEnabled`, `LegacyGroup`, `MembersNeedUpdate`,
  `DevicesNeedReplacement`, `DeviceLimitExceeded`) that never names which
  members or devices hold it back. A call the group cannot take now returns
  `AccountDevicesActivationRefused { group_id_hex, reason }`. See the README's
  "Turning on account devices".

- `AppGroupMlsStateFfi.convergence_parked` (binding default `false`) reports a
  group whose convergence pass spent its failure budget (mdk#2684). Show it as
  stuck syncing; `retry_group_convergence` grants one more attempt.

- `MarmotKitError` adds `GroupRecoveryUnsettled { group_id_hex }` and
  `GroupRecoverySourceMismatch { group_id_hex }` (mdk#2683). The former waits
  for the source or local recovery state to settle. The latter requires
  checking local eligibility and authenticated authority again, not blindly
  retrying the same grant; a usable local copy must not recover.

- `AppPerformanceSnapshotFfi.runtime_operations` reports per-phase
  maintenance-tick operations (`worker_maintenance_*`, the presentation, avatar
  and attachment passes and blocking batches a tick sets off) and full native
  replay synchronizations by trigger (`replay_sync_*`) (mdk#2923).

- Experimental device groups (only with `new_with_experimental_device_groups`
  in a `dev-device-groups` build). These APIs exist in every build; without
  that constructor and build they return empty, false or zero, or refuse.
  Refusals arrive as `MarmotKitError::Runtime` with details `device group
  refused: <reason>` (for example `roster_unsupported`). Ordinary hosts can
  skip this list.
  - The `dev-device-groups` cargo feature and
    `new_with_experimental_device_groups` constructor are default-off. The
    packaging scripts take a leading `--dev-device-groups` flag and write to
    `output-dev-device-groups/`. Ordinary constructors stay disabled and no
    longer open an account that holds or is joining a device group: it fails
    with `Runtime` `experimental_device_groups_required` (mdk#3012). Use the
    experimental constructor in every opener of such a root, notification
    service extensions included.
  - `MarmotOptions.device_platform` (binding default none, after
    `client_name`) names the platform this device runs on, such as `iOS`; with
    `client_name`, each device writes it into its own roster entry (mdk#2628
    item 3.6). Positional Kotlin construction shifts.
  - Linked devices: `linked_devices(account_ref)` returns `LinkedDeviceFfi`
    records, this device first, including `last_active_at` and `inactive`
    (mdk#2628 items 3.1, 3.6); `rename_linked_device`,
    `update_linked_device_settings` (three optional booleans; omitted values
    stay current), `remove_linked_device(account_ref, slot_id_hex)`,
    `removed_device_leftover_chats` and `chats_closed_to_linked_devices`
    (mdk#2759, mdk#2761, mdk#2856). Re-read on `LinkedDevicesChanged`. Devices
    mark and remove inactive siblings themselves.
  - Device linking (mdk#2628 item 3.3b): `start_device_link`,
    `confirm_device_link_match` and `cancel_device_link` on the new device,
    `link_device` and `decline_device_link` on a device already signed in, and
    `device_link_snapshot`, each returning a `DeviceLinkSnapshotFfi` with
    `moves` (old-sibling recognition hints; `dismiss_device_group_move_sibling`
    dismisses one) and `device_group_stalled`. When stalled, offer
    `reset_device_group_for_repair`, a local reset before fresh code pairing.
    Linked-device status includes `Moved`. Re-read on `DeviceLinkChanged`.
  - `key_package_refresh_overdue(account_ref)` says when the device group has
    held this device's KeyPackage refresh back for a week (mdk#2628 item 3.4).
    Re-read it on `KeyPackageRefreshOverdueChanged`.
  - `unrecognized_sign_ins`, `answer_sign_in` with a `SignInResponseFfi`, and
    `check_sign_ins` (mdk#2628 item 3.2). Re-read on
    `UnrecognizedSignInsChanged`.
  - `compromise_warning`, `dismiss_compromise_warning`, `start_fresh` and
    `started_fresh` (mdk#2628 item 3.7a). `CompromiseWarningReasonFfi`
    includes `ForeignOwnSlotKeyPackage`: a KeyPackage in this device's own
    slot that it did not make (3.7b). Re-read on `CompromiseWarningChanged`.
    The device roster encoding changed during this cycle, so development
    device groups created earlier must be recreated.
  - `chat_history_imports(account_ref)` lists each held chat's history from
    another device as `ChatHistoryImportFfi` (`Receiving`, with `retrying`, or
    `Imported` with its source and time); `TimelineMessageRecordFfi` and
    conversation rows carry `imported_from` and typed
    `history_import_provenance` (Device or Backup) (mdk#2628 item 4.2d).
    Re-read on `ChatHistoryImportsChanged`.
  - Backups: `begin_recovery_words`, `confirm_recovery_words`,
    `cancel_recovery_words`, `turn_off_backups`, `backup_settings`,
    `set_runtime_backup_background_conditions`,
    `set_backup_background_conditions`, `run_due_backup_pass`,
    `begin_backup_restore`, `cancel_backup_restore`, `backup_restore_status`,
    `watch_backup_restore` (`BackupRestoreSubscription`) and
    `backup_history_availability`, with `RecoveryWordsFfi`,
    `BackupSettingsFfi`, `BackgroundBackupOutcomeFfi`,
    `BackupRestoreStatusFfi`, `BackupRestorePhaseFfi`,
    `BackupHistoryAvailabilityFfi`, `BackupHistorySourceFfi` and
    `HistoryImportProvenanceFfi`. Outside experimental device groups every
    call is refused with `roster_unsupported`, so ordinary hosts have nothing
    to do. Inside them, background passes need both Wi-Fi and charging
    reported, and closing a restore observer does not cancel work. Do not
    persist or log recovery words.
  - Signing out with linked devices (mdk#2628 item 3.6b): `sign_out_and_wipe`
    first records in the device group that it is leaving (about 30 seconds)
    and leaves the siblings the chats they can take it out of.
    `WipeOutcomeFfi.groups_left_to_siblings` counts those, and
    `siblings_not_reached` says it could not ask them in time and tried to
    leave every chat itself.
  - A device its device group removes after its link was made is unlinked
    (mdk#2628 item 3.6b): the account stops on that device and stays signed
    out. `DeviceUnlinked` is sent once, `AccountSummaryFfi.unlinked` is true,
    and signing in, logging in or importing the key returns `AccountUnlinked {
    account_ref }`. Offer `sign_out_and_wipe`; signing in again is a new link.
  - With the experimental constructor, Leave demotes a non-last admin account
    itself instead of requiring `self_demote_admin` first.

### Changed

- MDK advertises `marmot.group.account-devices.v1` (`0x800d`) in every build
  (mdk#2659). A new group whose founding devices all advertise it requires it,
  so clients older than 0.15 cannot be invited into it (mdk#2656). No API
  change.

- Creating a group or inviting adds every device of each recipient account
  (mdk#2628, mdk#1696, mdk#2649): every valid, compatible KeyPackage
  published in the last 30 days, at most 20, or the single best one when none
  is that recent. See the README's KeyPackage selection section.

- Group member rows are accounts, not devices (mdk#2634). `group_members`,
  `group_details`, `group_roster`, `group_member_ids_page` and
  `group_conversation_snapshot` list an account with several devices in the
  group once, and `AppGroupMemberRecordFfi` and `GroupMemberDetailsFfi` gain
  `device_count` (binding default 1). `member_count`, admin counts and
  `is_last_admin` count accounts, and a chat between two accounts stays direct
  whatever devices either person uses.

- New KeyPackages are valid for 30 days instead of 84, and each device
  replaces its own every 6 to 7 days while it runs and after a Welcome uses it
  (mdk#2643), so devices publish to relays more often. Sign-out and wipe delete
  only this device's KeyPackage slot, with one kind 5 deletion, instead of
  every KeyPackage the account published (mdk#2654); `key_packages_deleted` on
  `SignOutOutcomeFfi` and `WipeOutcomeFfi` is now 1 or 0. No API change.

- The recovery runner owns account history by default (mdk#2950). Newer live
  messages in a group wait until its fetched backlog is admitted, and
  notification wakes fetch only the history their messages wait on.
  `account_recovery_status` reports catching-up groups, and `UnprovenHistory`
  notices are produced. No API change.

- Account workers rejoin `Unrecoverable` group copies automatically through
  an authenticated handshake with an admin device (mdk#2700). Repair rearms a
  parked attempt; usable forks still need consent. No API change.

- `sign_out_and_wipe` leaves a chat the account administers with another
  account, where none of its other devices is in (mdk#2818): it steps the
  account down first and counts the chat in `groups_left` only once it sees
  its removal, waiting up to about 30 seconds more for all such chats. A chat
  this device was already leaving waits the same way. Otherwise
  `group_leave_failures` says why. The call keeps running when the host
  cancels it.

- `requires_self_demote_before_leave` is now also true for an admin invitee
  with a pending invitation (it was false in 0.14), whose
  `decline_group_invite` returns `AdminCannotSelfRemove` until
  `self_demote_admin` (mdk#3014). An admin's `leave_group` still returns
  `AdminCannotSelfRemove` until `self_demote_admin`, as in 0.14.

- Onboarding no longer reports `OnboardingIssueFfi::MultiDeviceUnsupported`,
  and the `SingleDevice` step explains what signing in alone restores
  (mdk#2894). Update the notice copy as the README's "Single-device notice"
  shows; the case remains for compatibility.

- Devices exchange push-token records inside each group (kinds 447, 448 and
  449) so members learn the tokens of members who were offline: tokens are
  re-shared when a merged Commit adds a member, and gaps an announce reveals
  are repaired (mdk#2611). No API change.

- `resolve_public_event_preview` also asks the deployment's discovery
  indexers and the author's NIP-65 write relays when relay hints and
  directory relays miss (mdk#3060). No API change.

- Timeline `search` lowercases non-ASCII text too, using the same rule as
  chat-list `MessageText` (mdk#2983).

- `send_custom_event` refuses the device-group kinds 457, 458, 459, 460, 461,
  473, 475 and 476 as reserved, and one received in a chat makes no timeline
  row, message or notification (mdk#2628). They are read only in the
  account's device group.

- `new_with_client_name` and `MarmotOptions.client_name` leave out a name
  longer than 64 bytes once trimmed instead of publishing it; the KeyPackage
  still publishes, untagged (mdk#2631).

- `AttachmentTransferSubscription.next()` returns a replacement that changes a
  row's transfer state as soon as the engine reports it; progress-only
  replacements still arrive at most four per second. A host that polled
  `attachmentTransferSnapshot` beside the feed to see `Ready` sooner can drop
  that poll (mdk#2157).

### Fixed

- Every text send queued while offline publishes as soon as the host reports
  restored connectivity, not only the first (mdk#2762). Later sends no longer
  wait out a retry clock of up to an hour behind it, also after a cold start
  that is already online or a transport reopen, which get no connectivity
  report from the host.

- Account startup is abandoned only after 45 seconds without progress, not
  after 45 seconds in total, so a second device's login on a slow device no
  longer fails while its database migrates (#3224).

- A device joins only through the Welcome rumor that names a KeyPackage it
  published; another device's Welcome for the same account is ignored instead
  of failing a join (#2633).

- Reopening an account reuses its stored, validated identity proof, so an
  external signer is asked for one only when no usable proof is stored, not on
  every open (#2703).

- Idle maintenance ticks do less repeated work (#2952, #3035), and a
  convergence pass that keeps failing after its decision is retried a bounded
  number of times (mdk#2684).

## 0.14.0 - 2026-10-23

Regenerate Swift/Kotlin bindings with the matching native library. Every
constructor now takes a deployment; White Noise apps pass
`marmotDeploymentWhiteNoise()`. Account storage upgrades on first open, and
downgrade is unsupported. See the
[release notes](../../docs/release/0.14.0.md) and the
[client upgrade guide](../../docs/integration/0.14.0.md).

### Breaking changes

- `OnboardingFindingFfi` adds `context`, `purpose`, `outcome`,
  `declared_capability`, `actions`, and `observed_revision` (mdk#2565).
  Update host record construction and use the typed provenance to distinguish
  discovery failures from declared-route checks. `OnboardingIssueFfi` adds
  `InspectionCompleted`; update exhaustive Swift `switch` / Kotlin `when`
  handling. A successful directory query does not establish write support.

- Every `Marmot` constructor requires a `MarmotDeploymentFfi`.
  `MarmotOptions.deployment` has no default, and `new`, `new_with_options`,
  `new_with_secret_store`, `new_with_cursor_persistence` and
  `new_with_client_name` take it as their last argument. It holds the
  deployment's recovery relays, discovery indexers, media and image servers,
  Open Ranking (`OpenRankingProviderFfi`), KeyPackage client preference,
  moderation label namespace and keychain service. Its fields have no binding
  defaults: start from `marmot_deployment_white_noise()` or
  `marmot_deployment_neutral()` and change what differs. White Noise apps pass
  the White Noise preset at every construction, including background and
  notification-extension runtimes, which keeps their behaviour and keychain
  unchanged. See [deployment](README.md#deployment).

- Without a `SecretStore`, the platform keychain opens under the deployment's
  `keychain_service`. 0.13.0 always used `com.marmot.whitenoise`; the neutral
  preset uses `org.marmot-protocol.mdk`. An app that relied on the 0.13.0
  default must keep `com.marmot.whitenoise`, or its existing account secrets
  are not found.

- Unset deployment values fall back to nothing. With the neutral preset, new
  groups are text-only, setting or fetching a group image fails with
  `Runtime`, `upload_profile_image` needs an explicit server, a moderation
  report destination is refused, account setup and onboarding search no public
  indexers, directory search has no Open Ranking tier and no KeyPackage client
  is preferred. The build-time `MARMOT_ENCRYPTED_MEDIA_BLOB_ENDPOINTS` override
  is gone; set `new_group_media_endpoints` instead.

- `MarmotKitError` adds `GroupCatchingUp { group_id_hex }` (mdk#2258) and
  `GroupCommitUndelivered { group_id_hex }` (mdk#2255). A group change (invite,
  remove, admin, profile, image, avatar URL, retention, media servers, app
  components, disbanding) is refused while the group may have moved past this
  device, or once its last change has been owed to a group relay for two
  minutes. Messages and leaving are not affected. See the acknowledgements
  under Added. Update exhaustive Swift `switch` / Kotlin `when` handling.

- `MarmotKitError` adds `DirectoryLookupIncomplete { account }` (mdk#2302): a
  recipient's or account's relay-list or KeyPackage lookup ran out of time or
  relay coverage, so nothing is known to be missing. Offer retry. These
  failures previously arrived as `Runtime`. The error message omits the
  account; read it from the field.

- `MarmotKitError::MissingKeyPackage` adds `reason: MissingKeyPackageReasonFfi`
  (mdk#1975). `ObsoleteOnly` means the recipient has published only obsolete
  KeyPackages and must update their app; these recipients previously surfaced
  as `InvalidKeyPackageEvent`. `NotFound` keeps the previous meaning. The
  message now ends with `[not_found]` or `[obsolete_only]`. Update Swift
  associated-value patterns.

- `MarmotKitError` adds `StorageFull { details }` (mdk#2314): the device has no
  room for the operation. `upload_media`, `upload_media_files` and their
  token-aware twins return it before anything is uploaded when an attachment
  cannot be stored locally beyond the disk reserve; such sends previously went
  out without a local copy. `open_attachment_handoff` returns it when the disk
  cannot hold the copy. A full disk or database elsewhere also maps here
  instead of `Runtime`. Ask the user to free space.

- `MarmotKitError` adds `InvalidEditTarget` (`edit_message`) and
  `FollowListTooLarge` (`follow_user`, `unfollow_user`), both described under
  Fixed, and `InvalidPublicEventReferences { max_references }`:
  `cached_public_event_previews` was given more than 16 references. Update
  exhaustive Swift `switch` / Kotlin `when` handling.

- `AttachmentTransferStateFfi` adds `StorageBlocked` and `CleanedBySetting`.
  `StorageBlocked`: free disk cannot cover the publication reserve for the
  body; checkpoints are kept, and the job readmits once space frees or on
  explicit Retry. Render a storage prompt rather than a retry timer.
  `CleanedBySetting`: the account's "Keep media" setting removed the body;
  download again is allowed, as for `Removed`. Update exhaustive Swift
  `switch` / Kotlin `when` handling. See
  [the attachment access contract](ATTACHMENT-ACCESS.md).

- `RetentionSweepStatusFfi::DeferredScanExhausted` is removed with the sweep's
  page scan (mdk#2425, see Fixed). Remove exhaustive Swift `switch` / Kotlin
  `when` arms for it.

### Added

- Manage storage (mdk#2314): `attachment_storage_usage` returns
  `AttachmentStorageUsageFfi`: media-store bytes, legacy database bytes, the
  retained attachment count, the database's size and free pages, `cache_bytes`
  for the avatar and group-image cache, and `migration` /
  `migration_bytes` (`AttachmentMigrationStateFfi`: `NotNeeded`, `Running`,
  `Paused`, `Complete`, `Compacting`) for the background move of legacy bodies.
  `attachment_storage_by_chat` and `largest_retained_attachments` page largest
  first, 1 to 256 per page, with opaque `ChatStorageCursor` /
  `RetainedAttachmentsCursor` handles. `remove_chat_attachments` and
  `remove_attachments_older_than` remove in bulk, as `control_attachment`
  Remove does, and return the count. Show `cache_bytes` next to a "Clear cache"
  action (`clear_avatar_cache`). See
  [Manage storage](ATTACHMENT-ACCESS.md#manage-storage).

- `attachment_keep_media` and `set_attachment_keep_media` with
  `AttachmentKeepMediaFfi` (`Forever`, `OneYear`, `SixMonths`, `ThirtyDays`):
  the opt-in, per-device "Keep media" setting. `Forever` is the default and
  removes nothing. Setting a window removes what is already past it and
  returns the count; the account worker then applies it at start and hourly.
  See [Manage storage](ATTACHMENT-ACCESS.md#manage-storage).

- `open_attachment_handoff` and `release_attachment_handoff`, with record
  `AttachmentHandoffFfi`: a private plaintext copy of a retained attachment,
  lent under a lease to an OS surface that needs a real file (package
  installer, share sheet, "open with", Quick Look). Release it when the
  surface is done, and cancel a copy only through its control, not by
  cancelling the awaiting coroutine. See
  [handoff leases](ATTACHMENT-ACCESS.md#handoff-leases).

- `cached_public_event_previews` and `resolve_public_event_preview` cache
  verified public Nostr events referenced from message content (mdk#1547).
  Cached reads take at most 16 references, are network-free and survive
  restarts; resolve fetches one missing or stale preview. The cache adds a
  directory-cache migration that older builds refuse. See
  [public event previews](README.md#public-event-previews).

- `account_attachment_history_page` and `account_attachment_history_version`
  browse local attachments across one account, filtered by group, sender and
  date (`AccountAttachmentQueryFfi`), at most 100 candidates per page, with
  opaque `AccountAttachmentCursor` / `AccountAttachmentVersion` handles and
  `AccountAttachmentVersion::change_since`. A filtered empty page can still
  continue. Reads start no acquisition. See
  [account attachment history](ACCOUNT-ATTACHMENT-HISTORY.md).

- `send_prepared_media_with_client_token` admits an uploaded ordinary-media
  snapshot and consumes its captured draft only if that draft is unchanged.
  Keep the original token and revision for live retries, and recover
  ownership by token after interruption. See
  [captured media drafts](LOCAL-SENDS.md#captured-ordinary-media-drafts).

- `acknowledge_group_catching_up`: after `GroupCatchingUp`, call it once the
  user accepts that the change may split the group, then retry.
  `group_commit_delivery` returns the relays still owed the group's last
  change (`GroupCommitDeliveryFfi`), and `acknowledge_group_commit_undelivered`
  lets one change through after `GroupCommitUndelivered` once the user accepts
  the risk. Each acknowledgement admits one attempt and is not persisted. See
  [the epoch-gap and delivery notes](README.md#history-may-be-incomplete-notices).

### Changed

- MarmotKit runs MDK on its own process-wide multi-thread Tokio runtime (half
  the CPUs, 2 to 4 `marmotkit-rt` workers) instead of UniFFI's single
  `async_compat` thread and the thread that polls each call. Awaiting from the
  main actor or `Dispatchers.Main` no longer runs MDK work there. Cancelling a
  Kotlin coroutine aborts its task; `shutdown_and_close` and
  `release_attachment_handoff` still complete. Subscription receives stay on
  the calling thread, so a cancelled wait never consumes an update. Host
  callbacks can run on runtime threads concurrently and must not wait for the
  main thread. Constructors return `Runtime` if the runtime cannot start. See
  [threading model](README.md#threading-model).

- Downloaded and sent attachment bodies are encrypted files in the account's
  `media/` directory instead of database rows (mdk#2314). Bodies and avatars
  stored by earlier releases move there in the background, and the account
  database is compacted once when enough of it is free; account reads and
  writes wait while it compacts, typically about a second. Exclude the
  account directory, including `media/` and `handoff/`, from iCloud and
  Android backups. `AttachmentDownloadPolicyFfi.retained_bytes` no longer
  limits downloads: free disk above `disk_reserve` is the only gate, and a
  download needs the reserve plus twice its body. Download checkpoints saved
  by earlier releases are discarded, so interrupted downloads start over.

- With 256 uploads already awaiting publication, `upload_media`,
  `upload_media_files` and their token-aware twins fail with
  `InvalidMediaReference` and publish nothing. Before, the send went out
  without a local copy.

- `control_attachment` Remove deletes the released media-store file before it
  returns, and fails before removing anything when the media store cannot
  open.

- `approve_onboarding_repair` and `approve_onboarding_repair_in_epoch` need a
  completed freshness query from every source, including relays in the
  account's own relay declaration. If one does not answer, the step is a
  retryable failure, even when another source returned a record.

### Fixed

- `follow_user` and `unfollow_user` change only the followed account's `p` tag
  in the current kind-3 contact list; petnames, relay hints, other tags and
  the content stay as published (mdk#2268). Before, every edit dropped them. A
  list with 2,048 follows or more, the most MDK reads from one list, returns
  `FollowListTooLarge` and publishes nothing, where it used to be republished
  cut to 2,048 follows.

- `edit_message` returns `InvalidEditTarget`, publishing nothing, unless the
  target is an available chat message this account sent. Before, an edit of
  another account's message, a reaction or a deleted message was published to
  the group and reported as sent, then ignored by every recipient. The check
  uses this device's view when the edit is requested; recipients stay
  authoritative.

- `open_agent_publisher` and `watch_agent_text_stream` verify QUIC brokers
  against bundled Mozilla roots instead of the OS trust store when no
  certificate is pinned. This fixes an Android process abort on the first
  handshake. Pin a broker behind a private CA with `server_cert_der`.

- `shutdown_and_close` closes every account engine's database connection
  before releasing the root lease, so `storage_is_closed()` no longer reports
  true while an engine still holds the database (iOS `0xdead10cc`).

- A generated identity's setup no longer advertises the app's configured
  relays before the relay lists the user chose, and its KeyPackages go to the
  chosen relays.

- The retention sweep no longer prunes a message the unread projection still
  counts unread (mdk#2425).

- An explicit download the device lacks room to publish parks as
  `StorageBlocked` instead of retrying forever, and receiving an attachment no
  longer holds several copies of it in native memory (mdk#2239, mdk#2241).

- Runtime fixes need no new calls: ordered offline catch-up (#2513), epoch-gap
  fallback history (#2298, #2500), a quarantined group no longer stalling every
  conversation's receives (#2327, #2328), notification-extension wakes arming
  stall detection (#2343), bounded reconciliation progress (#2490, #2503) and
  less redundant inbound work (#2547, #2548). See `marmot-app`'s 0.14.0 fixes.
  Dependency updates fix RUSTSEC-2026-0338 to -0342 (`quinn-proto`),
  RUSTSEC-2026-0346 to -0349 (`rustls`), RUSTSEC-2026-0365 (`negentropy`) and
  RUSTSEC-2026-0381 and -0382 (`webpki-roots`, `rustls-webpki`).

## 0.13.0 - 2026-10-12

Regenerate Swift/Kotlin bindings with the matching native library. See the
[release notes](../../docs/release/0.13.0.md) and the
[client upgrade guide](../../docs/integration/0.13.0.md).

### Breaking changes

- External-signer accounts move their device-local SQLCipher key from the
  plaintext `.external-sqlcipher-secret` file into the configured `SecretStore`
  (`.external-sqlcipher/<account label>`) on first open, then scrub and remove the
  file. Older binaries cannot open these databases; downgrade is unsupported.
  Opening a database with neither credential fails instead of generating a key.

- `MarmotKitError` adds `ModerationReportingNotConfigured`,
  `InvalidModerationReportConfig`, `InvalidReportedPublicKey`, `CannotReportSelf`
  and `ModerationReportRateLimited`. Regenerate bindings with the matching
  library and update exhaustive Swift `switch` / Kotlin `when` handling.

- `OnboardingRepairProposalFfi.relay_repair` is a new optional field without
  a binding default. Regenerate matching Swift/Kotlin bindings and pass `nil`
  (Swift) or `null` (Kotlin) in host record initializers without a typed preview.
- Native lifecycle events add `LocalGroupCopyTerminated`, `LocalGroupCopyRestored`,
  and `GroupMemberLeavesRemoved`. Update exhaustive Swift/Kotlin event handling
  and regenerate bindings with the matching native library. Restoration describes
  retained-history repair, not automatic scheduler restoration of removed copies.
- The optional opaque `ChatListDraftVersionFfi` object in
  `PresentedChatRowFfi.draft_version` correlates the presented row's draft
  metadata with a captured composer revision through
  `MessageDraftRevisionFfi::includes_chat_list_version`. Regenerate Swift/Kotlin
  bindings with the matching library. Host-constructed row records must pass
  `nil` (Swift), `null` (Kotlin), or a version for the new optional field. Keep
  these opaque versions device-local and use revision-checked draft cleanup
  after local send acceptance. Identical-text saves advance the draft revision
  and emit a complete replacement presented-list snapshot.
- Attachment history adds `AttachmentRoleFfi` and the required, defaultless
  `AttachmentEntryFfi.role` field. Regenerate Swift/Kotlin bindings with the
  matching native library and update host record constructors and fixtures.
  Gallery clients can exclude `InlineEmoji`; preserve slots and continue paging
  after filtered pages as described in [the handoff](ATTACHMENT-HISTORY.md).

### Added

- `set_startup_diagnostics_enabled` and `startup_diagnostics_snapshot`
  (`NativeStartupSnapshotFfi`) report fixed startup phases, outcomes and
  migration progress. Local capture is off by default and changes no upload
  consent or database state.

- The runtime follows the opt-in `WN_SOCKS5_*` proxy settings described in
  the marmot-app [SOCKS5 routing](../marmot-app/README.md#socks5-routing)
  section. With the variables unset, nothing changes. When they are invalid,
  `Marmot::new` and `Marmot::new_with_options` return an error instead of
  connecting directly. Agent preview publishing and watching are unavailable
  while SOCKS5 is on.

- `submit_moderation_report`, `moderation_reporting_available` and
  `configure_moderation_reporting` add private, NIP-59 gift-wrapped NIP-56
  reports to the deployment's moderation team (`ModerationReportOriginFfi`,
  `ModerationReportOutcomeFfi`). `MarmotOptions.moderation_report_config` is
  optional, defaults to unset, and is set per build flavor. This is additive:
  `report_message`, `content_reports` and `dismiss_reports` are unchanged.

- `create_identity_with_initial_profile` creates a generated identity whose
  first public kind-0 is the onboarding-selected profile. Prefer it over
  `create_identity_with_profile` followed by `publish_user_profile`, which
  exposes the generated default to contacts first.
- `Marmot::propose_onboarding_relay_repair` previews a lossless relay-list repair
  without signing or publishing. `OnboardingRepairProposalFfi.relay_repair` carries
  the typed before/after tags, exact diff, restored capabilities and ManualReview
  mode. Optional passed-step previews retain readiness when dismissed
  before approval.
- Markdown tokens expose local-time timestamps through
  `MarkdownInlineFfi::Timestamp { unix_seconds, style }` and all nine typed
  `MarkdownTimestampStyleFfi` variants. Seconds remain signed and unformatted;
  native renderers own locale/timezone formatting and visible relative-time
  refresh. Update exhaustive inline switches with matching generated bindings.
- `Marmot::message_reactions` returns complete local reaction details for one exact
  account/group/message, with one effective entry per sender/emoji and no
  conversation-preview cap. Missing, hidden, deleted, invalidated and
  retention-pruned targets return no participants; blocked reactors are excluded.
  The read performs no network work or conversation-history scan.
  Regenerate matching Swift/Kotlin bindings to call `messageReactions`.
- `Marmot::upload_media_files` and `upload_media_files_with_client_token`
  take `MediaFileUploadRequestFfi` (`source_path`, optional `expected_size`)
  and a `MediaFileTransferControlFfi` for cancellation and monotonic
  progress, so large attachments no longer cross the FFI as byte arrays.
  `max_file_media_ciphertext_bytes()` reports the batch bound. Existing
  `upload_media` APIs are unchanged. File-backed download is not yet
  exposed. (#2175)

### Changed

- Polls can be created in direct conversations as well as groups.

- `retired_relay_hosts()` no longer includes `relay.damus.io`, and
  `classify_relay_endpoints` now reports it as `Allowed`.

### Fixed

- File-transfer cancellation documentation identifies admission start as the
  last interruptible boundary, not the later durable acceptance.
- Android build preflight drains `rustup` output before accepting an installed
  target, avoiding false missing-target errors from a broken pipe.

- Group activity uses shared per-commit reaction targets for authors and peers,
  including commits preceding a disband. See `marmot-app`'s 0.13.0 fixes
  for projection and push-token behavior.

## 0.12.0 - 2026-10-02

Regenerate Swift/Kotlin bindings with the matching native library. See the
[release notes](../../docs/release/0.12.0.md) and the
[client upgrade guide](../../docs/integration/0.12.0.md).

### Breaking changes

- `MarmotKitError` gains `InvalidAppComponent { details }`; update exhaustive
  error switches.
- `ConversationReactionFfi` gains `reaction_message_id_hex` without a binding
  default; host-constructed reaction records (previews, fixtures) must set it.

### Added

- `Marmot::group_app_component` and `update_app_component` read and
  admin-update optional application-owned group components (ids at or above
  `0xf000`, up to 4096 bytes each) carried in MLS group state, so shared
  settings survive message expiry and reach new members in their Welcome.
  Returns `GroupAppComponentFfi`; invalid ids, required components and
  oversized state fail with `InvalidAppComponent`. (#1929)
- `Marmot::request_explicit_attachment` joins or promotes attachment demand to
  explicit priority without resetting retry budgets, backoff or active
  deadlines. Use it for ordinary taps; keep `control_attachment(Retry)` and
  `download_attachment_again` for deliberate recovery. (#2142)
- `create_identity`, `create_identity_with_profile`, `login`,
  `login_recovering_incomplete_setup`, `login_external_signer` and
  `publish_relay_lists` take a trailing `inbox_relays` argument, and
  `OnboardingOptionsFfi` an `inbox_relays` field, that set the kind-10050 inbox
  list separately from `default_relays`. Both default to empty, which declares
  `default_relays` in both lists as before, so existing Swift, Kotlin and
  Python callers keep working unchanged. (#2141)
- `Marmot::poll_votes` pages each voter's effective poll selection
  (`PollVoteFfi`: voter account id, option ids, vote time) for a "View votes"
  sheet, 1..=100 per `PollVotePageFfi` with a `(voted_at, voter)` cursor. It
  uses the same rules as the `PollProjectionFfi` tally, so all pages sum to
  `options[].votes` and `participants`. Blocked voters stay listed; hidden or
  deleted polls return an empty page. (#2091)
- `Marmot::send_tagged_text`, `send_tagged_media`, and `react_with_media` send
  NIP-30 custom emoji: upload the image with `upload_media(send = false)`, then
  name its first locator in an `["emoji", shortcode, url]` tag on a chat or a
  `:shortcode:` reaction. `MediaUploadRequestFfi.message_tags` (default empty)
  tags a sent upload. At most 64 tags and 16 KiB of values; `imeta` rows are
  rejected.
- Conversation window kind-9 rows now keep NIP-30 `["emoji", shortcode, url]`
  tags in `timeline.tags`, and `ConversationReactionFfi.reaction_message_id_hex`
  names the earliest active kind-7 for that emoji, whose custom image
  `list_media` returns under the same message id.

### Changed

- Sent attachments are staged locally after a successful upload and retained
  once the send is confirmed, so the sender reopens them without downloading
  them again. (#2142)
- `set_chat_muted` now allows direct mentions of the receiving account through
  the durable mute in notification subscriptions; ordinary traffic stays silent
  and blocked senders remain suppressed. Hosts still apply their own permission,
  channel, and foreground policy to `NotificationUpdateFfi`.
  (marmot-protocol/whitenoise-android#2984)
- Attachment downloads report `Failed` instead of staying `RetryScheduled`
  indefinitely when the blob is gone (404/410 everywhere) or its epoch key stays
  unavailable for about eight minutes. Hosts should offer Retry: it derives a
  missing key from retained epoch state, recovering attachments whose key was
  never cached. Retry budgets are unchanged. (#2106)

## 0.11.0 - 2026-09-29

### Changed

- Explicit catch-up ingests live input, then runs the account's recovery comparison in
  place. It no longer re-subscribes relays once the session is active; a route change
  still refreshes them.
- Generated identities and later relay-list or profile edits schedule
  best-effort copies of kind 10002, kind 10050, and kind 0 to the built-in
  public directory indexers. Development accounts using loopback relays skip
  these writes while retaining public indexer reads for existing identities.

### Fixed

- Keep native conversation-window paging usable during content-only refreshes.
  An older visible-anchor quote whose row has left the retained window now
  reports a stale window so hosts can reassess the visible row. (#2052)

- Keep native chat-list-window paging usable while account activity refreshes
  the window. An older visible-anchor quote whose row has left the retained
  window reports a stale window so hosts can reassess the visible row.

- Fetched kind:0 `about` text keeps normalized line breaks. Other known profile strings
  stay single-line, and unsafe controls are still removed. (#1973)

- Package Android `arm64-v8a` and `x86_64` MarmotKit libraries with 16 KB ELF load-segment alignment, and reject a release or exact-head candidate whose packaged libraries do not meet that alignment. The page-size flags are appended on the final library link so configured Cargo rustflags stay in effect.

### Breaking changes

- `HostPerformanceOperationFfi` gains 28 shared and nine Linux-specific stages.
  Regenerate Swift/Kotlin bindings with the matching native library and update
  exhaustive operation switches. `AppPerformanceSnapshotFfi` keeps its existing
  record fields; read every new stage through `runtime_operations`.
- `MarmotEventFfi` gains `HistoryNoticesChanged { account_id_hex, account_label }`; update
  exhaustive event switches. `GroupRecoveryStatusFfi` gains `history_may_be_incomplete` and
  `history_notice_ids`, with binding defaults for host-constructed records. Regenerate
  Swift/Kotlin bindings with the matching native library.

### Added

- Add bounded encrypted NIP-88 poll creation and replacement-vote methods. Timeline rows expose deterministic poll
  counts, participants, local selection and deadline state. Poll creation follows canonical group-conversation
  classification; an accepted open poll remains votable after reclassification. Regenerate Swift/Kotlin
  bindings with the matching library.
- Add `history_notices` and `dismiss_history_notice` with `HistoryNoticeFfi` and
  `HistoryNoticeCauseFfi`. Each notice is one parked recovery occurrence to show as "history may
  be incomplete"; dismissal is durable, is recorded as its own outcome rather than recovered
  history, and returns false for a stale id. Group-scoped occurrences also appear in
  `group_recovery_status`. See the README section "History may be incomplete notices". (#2068)

## 0.10.4 - 2026-09-20

### Fixed

- Classify host-managed configuration and signed-out permission errors separately from media errors; document opt-in retry budgets and revocation-safe publication. ([#1939](https://github.com/marmot-protocol/mdk/pull/1939))

### Breaking changes

- `MarmotOptions` gains an optional acquisition mode and transfer state gains three terminal variants. `MarmotKitError` adds attachment configuration/account variants. Regenerate Kotlin/Swift bindings with the matching library and update exhaustive state handling. ([#1939](https://github.com/marmot-protocol/mdk/pull/1939))

### Added

- Token-aware text, reply, draft and media-send methods return durable local acceptance and expose local submission
  status; timeline rows carry the opaque caller token. Existing send methods remain supported. ([#1943](https://github.com/marmot-protocol/mdk/pull/1943))

- `ChatListMessagePreviewFfi` exposes optional per-message retention duration and expiry so hosts can hide expired previews before pruning. Regenerate Swift/Kotlin bindings with the matching native library. ([#1942](https://github.com/marmot-protocol/mdk/pull/1942))

- Expose host-managed acquisition mode, generation-fenced permission updates and atomic automatic requests to Kotlin/Swift. Add terminal history/budget outcomes; regenerate bindings with matching native libraries. ([#1939](https://github.com/marmot-protocol/mdk/pull/1939))
