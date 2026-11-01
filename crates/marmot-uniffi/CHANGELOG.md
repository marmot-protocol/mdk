# Changelog

## Unreleased

### Breaking changes

- `sign_out_and_wipe` signs out through the account's other devices
  (mdk#2628 item 3.6b): with a linked device that is not signing out too, it
  first records in the device group that it is leaving, which can take about
  30 seconds, and leaves those devices the chats they can take it out of.
  `WipeOutcomeFfi` adds `groups_left_to_siblings` and `siblings_not_reached`,
  which says it could not ask them in time and left every chat itself; tell
  the user. The call now keeps running when the host cancels it, so a
  sign-out that has asked its siblings always finishes. Regenerate bindings
  with the matching native library.

- `CompromiseWarningReasonFfi::RejectedKeyPackage` is now
  `ForeignOwnSlotKeyPackage` (mdk#2628 D74, 3.7b): a KeyPackage this device
  found in its own slot that it did not make, which only this device warns
  of. Kind 462 is no longer reserved. The device roster changed its encoding,
  so existing development device groups must be recreated.

- A device that its device group removes after its link was made is
  unlinked (mdk#2628 item 3.6b): the account stops on that device and stays
  signed out. `MarmotEventFfi` adds `DeviceUnlinked { account_id_hex,
  account_label }`, sent once; `AccountSummaryFfi` adds `unlinked`; and
  `MarmotKitError` adds `AccountUnlinked { account_ref }`, which signing in,
  logging in or importing the key of such an account returns. Show that this
  device was unlinked and offer
  `sign_out_and_wipe`, which skips leaving chats and deleting the slot;
  signing in again is then a new link. Update exhaustive Swift/Kotlin
  handling and regenerate bindings with the matching native library.

- `SelfMembershipFfi` and `ConversationParticipationFfi` add `DeviceRemoved`
  (mdk#2628 item 3.6b): this device's leaf was removed from a chat the account
  stays in through another of its devices. Show no "removed from group"
  notice for it. Update exhaustive Swift/Kotlin handling and regenerate
  bindings with the matching native library.

- `GroupEventKindFfi` adds `QueuedIntentRefused { intent_id_hex, intent_kind,
  reason }` (mdk#2694): a send that waited for the group to settle was dropped
  because the settled state refused it; tell the user, who may try again.
  Update exhaustive Swift/Kotlin handling and regenerate bindings with the
  matching native library.

- `MarmotEventFfi` adds `LinkedDevicesChanged { account_id_hex, account_label }`
  (mdk#2628). Update exhaustive Swift/Kotlin handling and regenerate bindings
  with the matching native library.

- `MarmotEventFfi` adds `KeyPackageRefreshOverdueChanged { account_id_hex,
  account_label }` (mdk#2628). Update exhaustive Swift/Kotlin handling and
  regenerate bindings with the matching native library.
- `MarmotEventFfi` adds `DeviceLinkChanged { account_id_hex, account_label }`
  (mdk#2628 item 3.3b). Update exhaustive Swift/Kotlin handling and regenerate
  bindings with the matching native library.

- `MarmotEventFfi` adds `UnrecognizedSignInsChanged { account_id_hex,
  account_label }` (mdk#2628). Update exhaustive Swift/Kotlin handling and
  regenerate bindings with the matching native library.

- `MarmotEventFfi` adds `CompromiseWarningChanged { account_id_hex,
  account_label }` (mdk#2628). Update exhaustive Swift/Kotlin handling and
  regenerate bindings with the matching native library.
- `HistoryNoticeCauseFfi` adds `UnprovenHistory`, and `MarmotEventFfi` adds
  `RecoveryStatusChanged { account_id_hex, account_label }` (mdk#2660). Update
  exhaustive Swift/Kotlin handling and regenerate bindings with the matching
  native library. Neither is produced until the recovery runner owns history.

- `MarmotKitError` adds `AccountDevicesActivationRefused { group_id_hex, reason }`
  for an `enable_account_devices` call the group cannot take now (mdk#2628).
  Update exhaustive Swift/Kotlin handling and regenerate bindings with the
  matching native library.

- `MarmotDeploymentFfi` drops `key_package_preferred_clients` and
  `key_package_last_clients` (mdk#2628): the KeyPackage `client` tag no longer
  ranks invite candidates. Remove them from any record a host builds field by
  field and regenerate bindings with the matching native library; hosts that
  start from `marmot_deployment_white_noise()` or `marmot_deployment_neutral()`
  only regenerate.

- `MarmotKitError` adds `MediaReferenceStaleEpoch { source_epoch, current_epoch }`
  and `MediaReferenceEpochUnsettled { source_epoch }`. They replace the
  generic `InvalidMediaReference` for these two cases: the first means the
  group left the epoch the attachment was encrypted under, so upload the file
  again; the second means the epoch is settling, so sync and send again. Update
  exhaustive Swift/Kotlin handling and regenerate bindings with the matching
  native library (#2158).

- Sonar-compatible stickers. `MarmotKitError` adds `InvalidSticker`, `StickerNotFound`,
  `StickerNetwork`, `StickerImport` and `StickerImportUnsupported`; they previously had no
  sticker path. `AppMessageRecordFfi`, `ReceivedMessageFfi`, `NotificationUpdateFfi`,
  `ChatListMessagePreviewFfi`, `TimelineMessageRecordFfi` and `TimelineReplyPreviewFfi` add
  `sticker: Option<StickerRefFfi>`, the typed kind-9 sticker reference; it is `None` for a
  deleted row. Regenerate bindings and update exhaustive Swift `switch` / Kotlin `when`
  handling and code that constructs these records. New `Marmot` methods `sticker_packs`,
  `sticker_pack`, `sync_sticker_packs`, `fetch_sticker_pack`, `install_sticker_pack`,
  `uninstall_sticker_pack`, `fetch_sticker_asset`, `send_sticker` and
  `import_signal_sticker_pack` (which validates the link and then refuses before any
  network call) use the new `StickerRefFfi`, `StickerFfi`, `StickerPackFfi`,
  `StickerAssetFfi`, `StickerSyncResultFfi` and `StickerImportResultFfi` records.
  `StickerFfi.plaintext_sha256` is the exact hash a `StickerRefFfi` carries.

### Added

- `account_recovery_status(account_ref)` returns an `AccountRecoveryStatusFfi`:
  the groups whose history is still being fetched (`catching_up_group_ids_hex`),
  whether the inbox's is (`inbox_catching_up`), and every notice as
  `history_notices` lists them (mdk#2660). Re-read it on
  `RecoveryStatusChanged`. Until the recovery runner owns history nothing is
  ever catching up.

- `MarmotOptions.devicePlatform` names the platform this device runs on, such
  as `iOS`. With `clientName`, each device writes it into its own roster
  entry, so `linked_devices` shows every device's client and platform
  (mdk#2628 item 3.6). Defaults to none; written only where device groups are.

- `rename_linked_device(account_ref, slot_id_hex, label)` renames one of this
  account's devices, this one included, with one roster commit in the device
  group (mdk#2628 item 3.6). It is refused with nothing sent while the device
  group has an earlier change in flight (`device_group_busy`; retry later),
  and in release builds until the roster's spec lands. A rename whose commit
  loses a fork is made again later, unless another rename of that device
  won.

- `AppGroupMlsStateFfi.convergence_parked` (default `false`) reports a group
  whose convergence pass spent its failure budget (mdk#2684). Show it as stuck
  syncing; `retry_group_convergence` grants one more attempt. Regenerate
  bindings with the matching native library.
- Device linking (mdk#2628 item 3.3b): `start_device_link`,
  `confirm_device_link_match` and `cancel_device_link` on the new device,
  `link_device` and `decline_device_link` on a device already signed in, and
  `device_link_snapshot`, each returning a `DeviceLinkSnapshotFfi`. Re-read it
  on `DeviceLinkChanged`. Every call is refused in release builds until the
  pairing and device-group specs land.

- `linked_devices(account_ref)` returns this account's own devices as
  `LinkedDeviceFfi` records, from the roster of the device group this device
  trusts, this device first (mdk#2628 item 3.1). Re-read it on
  `LinkedDevicesChanged`. It is empty in release builds until the roster's
  spec lands.
- `LinkedDeviceFfi` adds `last_active_at`, when a heartbeat last showed a
  sibling running, and `inactive`, this device's own judgement 30 days after
  the later of that and when it first found the sibling in the roster
  (mdk#2628 item 3.6). Each device sends a heartbeat in the device group at
  most once an hour while it runs. Release builds show neither.

- `key_package_refresh_overdue(account_ref)` says when this device's device
  group has held its KeyPackage refresh back for a week (mdk#2628 item 3.4),
  so the app can tell the user before inviters stop treating the device as
  fresh at 30 days. Re-read it on `KeyPackageRefreshOverdueChanged`. It is
  false in release builds until the roster's spec lands.

- `unrecognized_sign_ins(account_ref)` returns sign-ins of this account that
  this device does not recognize as `UnrecognizedSignInFfi` records (mdk#2628
  item 3.2). `answer_sign_in(account_ref, slot_id_hex, response)` answers one
  with a `SignInResponseFfi`, and `check_sign_ins(account_ref)` checks now.
  Re-read the list on `UnrecognizedSignInsChanged`. It is empty in release
  builds until the roster's spec lands.

- `compromise_warning(account_ref)` returns the account's open compromise
  warning on this device as `CompromiseWarningItemFfi` records (mdk#2628 item
  3.7a), and `dismiss_compromise_warning(account_ref)` closes it on this
  device. Re-read it on `CompromiseWarningChanged`. `start_fresh(account_ref)`
  answers every sign-in from before this device Not now without rejecting
  any, and `started_fresh(account_ref)` says whether the device did so and
  still has no device group. All are empty or false in release builds until
  the roster's spec lands.

- An admin can turn on account-devices in an existing group (mdk#2628):
  `enable_account_devices(account_ref, group_id_hex)` sends one admin Commit,
  only when the user asks, and the group can never turn it off.
  `account_devices_activation(account_ref, group_id_hex)` answers whether the
  group is eligible with an `AccountDevicesActivationFfi` (`Eligible`,
  `NotAdmin`, `AlreadyEnabled`, `LegacyGroup`, `MembersNeedUpdate`,
  `DevicesNeedReplacement`, `DeviceLimitExceeded`) that never names which members or devices hold it
  back. See the README's "Turning on account devices".

### Changed

- `send_custom_event` refuses the device-group kinds 457, 459, 460, 461, 473,
  475 and 476 as reserved, and one received in a chat makes no timeline row,
  message or notification (mdk#2628). They are read only in the account's
  device group.
- Creating a group or inviting adds every device of each recipient account
  (mdk#2628, mdk#1696): every valid, compatible KeyPackage published in the
  last 30 days, at most 20, or the single best one when none is that recent.
  See the README's KeyPackage selection section.
- Group member rows are accounts, not devices (mdk#2628). `group_members`,
  `group_details`, `group_roster`, `group_member_ids_page` and
  `group_conversation_snapshot` list an account with several devices in the
  group once, and `AppGroupMemberRecordFfi` and `GroupMemberDetailsFfi` gain
  `device_count` (binding default 1). `member_count`, admin counts and
  `is_last_admin` count accounts, and a chat between two accounts stays direct
  whatever devices either person uses.
- `AttachmentTransferSubscription.next()` returns a replacement that changes a
  row's transfer state as soon as the engine reports it; progress-only
  replacements still arrive at most four per second. A host that polled
  `attachmentTransferSnapshot` beside the feed to see `Ready` sooner can drop
  that poll (#2157).
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
    local group`, and any other engine failure `session error`. Account
    failures outside the engine still read `account error`.
- `new_with_client_name` and `MarmotOptions.client_name` leave out a name
  longer than 64 bytes once trimmed instead of publishing it; the KeyPackage
  still publishes, untagged (mdk#2628).

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
