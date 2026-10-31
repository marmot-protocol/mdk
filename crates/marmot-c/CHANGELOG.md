# Changelog - marmot-c

All notable changes to the Marmot C bindings.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions track the workspace version; releases are tagged `marmotc-v<version>`.

## [Unreleased]

### Breaking changes

- `MarmotGroupEventKind` adds `QueuedIntentRefused { intent_id_hex,
  intent_kind, reason }` (mdk#2694), freed with its event. Handle the new tag
  and use matching regenerated headers and libraries.

- `marmot_deployment_set_key_package_client_preference` is removed
  (mdk#2628): the KeyPackage `client` tag no longer ranks invite candidates.
  Drop the call and use matching regenerated headers and libraries.

### Added

- `MarmotClientOptions` gains a trailing `device_platform`: the platform this
  device runs on, such as "iOS", which each device writes with its client
  label into its own roster entry (mdk#2628 item 3.6). NULL leaves it out.
  The struct layout changed: use matching regenerated headers and libraries.
- `marmot_rename_linked_device` renames one of this account's devices, this
  one included, by its `slot_id_hex`, with one roster commit in the device
  group (mdk#2628 item 3.6). It fails with nothing sent while the device group
  has an earlier change in flight, and in release builds until the roster's
  spec lands. A rename whose commit loses a fork is made again later, unless
  another rename of that device won. Use matching regenerated headers and
  libraries.
- `MarmotAppGroupMlsState` gains a trailing `convergence_parked` field for a
  group whose convergence pass spent its failure budget (mdk#2684). Show it as
  stuck syncing; `marmot_retry_group_convergence` grants one more attempt.
  The struct grows, so use matching regenerated headers and libraries.
- Device linking (mdk#2628 item 3.3b): `marmot_start_device_link`,
  `marmot_confirm_device_link_match`, `marmot_cancel_device_link`,
  `marmot_link_device`, `marmot_decline_device_link` and
  `marmot_device_link_snapshot` write a `MarmotDeviceLinkSnapshot` (free with
  `marmot_device_link_snapshot_free`). The new
  `MARMOT_EVENT_DEVICE_LINK_CHANGED` event says to re-read it. Every call is
  refused in release builds until the pairing and device-group specs land. Use
  matching regenerated headers and libraries.
- `marmot_linked_devices` writes this account's own devices as a
  `MarmotLinkedDeviceList` (free with `marmot_linked_device_list_free`), from
  the roster of the device group this device trusts, this device first
  (mdk#2628 item 3.1). The new `MARMOT_EVENT_LINKED_DEVICES_CHANGED` event says
  to re-read it. The list is empty in release builds until the roster's spec
  lands. Use matching regenerated headers and libraries.
- `MarmotLinkedDevice` adds `has_last_active_at`/`last_active_at`, when a
  heartbeat last showed a sibling running, and `inactive`, this device's own
  judgement 30 days after the later of that and when it first found the
  sibling in the roster (mdk#2628 item 3.6). Use matching regenerated headers
  and libraries.
- `marmot_key_package_refresh_overdue` writes whether this device's device
  group has held its KeyPackage refresh back for a week (mdk#2628 item 3.4),
  so the app can tell the user before inviters stop treating the device as
  fresh at 30 days. The new `MARMOT_EVENT_KEY_PACKAGE_REFRESH_OVERDUE_CHANGED`
  event says to re-read it. It is false in release builds until the roster's
  spec lands. Use matching regenerated headers and libraries.
- `marmot_unrecognized_sign_ins` and `marmot_check_sign_ins` write sign-ins of
  this account that this device does not recognize as a
  `MarmotUnrecognizedSignInList` (free with
  `marmot_unrecognized_sign_in_list_free`) (mdk#2628 item 3.2).
  `marmot_answer_sign_in` answers one with a `MarmotSignInResponse`
  discriminant. The new `MARMOT_EVENT_UNRECOGNIZED_SIGN_INS_CHANGED` event says
  to re-read the list. It is empty in release builds until the roster's spec
  lands. Use matching regenerated headers and libraries.
- `marmot_compromise_warning` writes the account's open compromise warning on
  this device as a `MarmotCompromiseWarningItemList` (free with
  `marmot_compromise_warning_item_list_free`) (mdk#2628 item 3.7a), whose
  `reason` is a `MarmotCompromiseWarningReason` discriminant as `uint32_t`.
  `marmot_dismiss_compromise_warning` closes it on this device, and the new
  `MARMOT_EVENT_COMPROMISE_WARNING_CHANGED` event says to re-read it.
  `marmot_start_fresh` answers every sign-in from before this device Not now
  without rejecting any, and `marmot_started_fresh` writes whether the device
  did so and still has no device group. All are empty or false in release
  builds until the roster's spec lands. Use matching regenerated headers and
  libraries.
- `marmot_account_devices_activation` and `marmot_enable_account_devices` let
  an admin turn on account-devices in an existing group, only when the user
  asks (mdk#2628). The first writes a `MarmotAccountDevicesActivation` that
  never names which members or devices hold the group back; a refused
  activation returns the new `MARMOT_STATUS_ACCOUNT_DEVICES_ACTIVATION_REFUSED`
  (110). Existing status values are unchanged. Use matching regenerated
  headers and libraries.
- Add `MARMOT_STATUS_MEDIA_REFERENCE_STALE_EPOCH` (108): the group left the
  epoch an attachment was encrypted under, so upload it again; and
  `MARMOT_STATUS_MEDIA_REFERENCE_EPOCH_UNSETTLED` (109): the group's epoch is
  settling, so sync and send again. Both previously returned
  `MARMOT_STATUS_INVALID_MEDIA_REFERENCE`. Existing status values are
  unchanged. Use matching regenerated headers and libraries (#2158).

- Sonar-compatible stickers: `marmot_sticker_packs`, `marmot_sticker_pack`,
  `marmot_sync_sticker_packs`, `marmot_fetch_sticker_pack`, `marmot_install_sticker_pack`,
  `marmot_uninstall_sticker_pack`, `marmot_fetch_sticker_asset`, `marmot_send_sticker` and
  `marmot_import_signal_sticker_pack` (validates the link, then refuses before any network
  call), with records `MarmotStickerRef`, `MarmotSticker`, `MarmotStickerPack`,
  `MarmotStickerAsset`, `MarmotStickerSyncResult` and `MarmotStickerImportResult` and their
  `*_free` functions. `MarmotSticker.plaintext_sha256` is the exact hash the fetch and send
  calls take; `MarmotStickerImportResult.skipped_signal_sticker_ids` is a `uint32_t` array,
  `(NULL, 0)` when empty. `MarmotAppMessageRecord`, `MarmotReceivedMessage`,
  `MarmotNotificationUpdate`, `MarmotChatListMessagePreview`, `MarmotTimelineMessageRecord`
  and `MarmotTimelineReplyPreview` add a nullable `sticker` at the position of the
  matching UniFFI field, so those layouts change. New status codes `MARMOT_STATUS_INVALID_STICKER` (111),
  `MARMOT_STATUS_STICKER_NOT_FOUND` (112), `MARMOT_STATUS_STICKER_NETWORK` (113),
  `MARMOT_STATUS_STICKER_IMPORT` (114) and `MARMOT_STATUS_STICKER_IMPORT_UNSUPPORTED` (115).
  Use matching regenerated headers and libraries.

### Changed

- `marmot_send_custom_event` refuses the device-group kinds 457, 459, 460,
  462, 475 and 476 as reserved, and one received in a chat makes no
  timeline row, message or notification (mdk#2628). They are read only in
  the account's device group.
- Creating a group or inviting adds every device of each recipient account
  (mdk#2628, mdk#1696): every valid, compatible KeyPackage published in the
  last 30 days, at most 20, or the single best one when none is that recent.
- Group member rows are accounts, not devices (mdk#2628).
  `MarmotAppGroupMemberRecord` and `MarmotGroupMemberDetails` gain
  `device_count`, and an account with several devices in the group is one
  row; `member_count`, admin counts and `is_last_admin` count accounts. Use
  matching regenerated headers and libraries.
- `marmot_attachment_transfer_subscription_next` returns a replacement that
  changes a row's transfer state as soon as the engine reports it; progress-only
  replacements still arrive at most four per second. A timeout no longer loses
  a replacement that was waiting out that window (#2157).
- The status a call returns now depends on what the error is, not on which MDK
  layers wrapped it (mdk#2602). Three answers change:
  - A busy, closed or full store that the account session reported itself now
    returns `MARMOT_STATUS_STORAGE_BUSY`, `MARMOT_STATUS_STORAGE_CLOSED` or
    `MARMOT_STATUS_STORAGE_FULL`, as it does when the engine reports it.
    Before, it returned `MARMOT_STATUS_RUNTIME`.
  - An external-signer rejection now returns
    `MARMOT_STATUS_EXTERNAL_SIGNER_REJECTED` on every path. Before, a rejection
    on paths other than transport publishes and account open, such as signing
    an identity proof, returned `MARMOT_STATUS_RUNTIME`.
  - Wipe outcome reasons follow the same rule. An engine storage failure reads
    `local storage error`, an unknown engine group `unknown local group`, and
    any other engine failure `session error`. Account failures outside the
    engine still read `account error`.
- `marmot_client_new_with_client_name` and `MarmotClientOptions.client_name`
  leave out a name longer than 64 bytes once trimmed instead of publishing it;
  the KeyPackage still publishes, untagged (mdk#2628).

## [0.14.0] - 2026-10-23

Recompile against the matching `marmot.h` and library: every `marmot_client_new*` constructor takes a required
`deployment`, `MarmotRetentionSweepStatus` values renumber, `MarmotOnboardingFinding` changes layout, and new
transfer-state, onboarding-issue and status values are appended. Every other existing record layout is unchanged. See the [release notes](../../docs/release/0.14.0.md) and the
[client upgrade guide](../../docs/integration/0.14.0.md).

### Breaking changes

- `MarmotOnboardingFinding` adds typed `context`, `purpose`, `outcome`,
  `declared_capability`, owned `actions`/`actions_len`, and optional
  `has_observed_revision`/`observed_revision` (mdk#2565). Rebuild consumers
  with the regenerated header and matching library; the finding layout and
  array stride changed. Snapshot deep-free releases finding actions.
  `MarmotOnboardingIssue` appends `InspectionCompleted` (21); all earlier
  discriminants are unchanged. Directory-query success does not establish
  write support or event publication.

- Every `marmot_client_new*` constructor takes a required
  `const MarmotDeployment *deployment` just before `out_client` (#2408,
  #2493). Create one with `marmot_deployment_white_noise(&deployment)` or
  `marmot_deployment_neutral(&deployment)`, change what differs with the
  `marmot_deployment_set_*` setters, construct, then free it with
  `marmot_deployment_free`; the client keeps its own copy. A NULL deployment
  returns `MARMOT_STATUS_NULL_POINTER` before anything opens and leaves a
  passed secret store with its owner. The deployment carries the recovery
  relays, discovery indexers, media and image servers, Open Ranking,
  KeyPackage client preference, moderation label namespace and keychain
  service. The White Noise preset keeps White Noise's services and keychain
  unchanged. Neutral configures none and nothing falls back to White Noise's:
  new groups are text-only, setting or loading a group image fails, a
  profile-image upload needs an explicit server, and
  `marmot_configure_moderation_reporting` returns
  `MARMOT_STATUS_INVALID_MODERATION_REPORT_CONFIG`. Its keychain service is
  `org.marmot-protocol.mdk`, whereas 0.13.0 used `com.marmot.whitenoise` for
  every host: a host off the White Noise preset that keeps account secrets in
  the platform keychain must set that name with
  `marmot_deployment_set_keychain_service`, or its existing secrets are
  stranded. The build-time
  `MARMOT_ENCRYPTED_MEDIA_BLOB_ENDPOINTS` override is gone; use
  `marmot_deployment_set_new_group_media_endpoints`. `MarmotClientOptions` is
  unchanged.
- `MarmotRetentionSweepStatus` drops `DEFERRED_SCAN_EXHAUSTED` with the
  sweep's page scan (#2469, mdk#2425), so
  `MARMOT_RETENTION_SWEEP_STATUS_FAILED` moves from 5 to 4. A host built
  against the 0.13.0 header reads a failed sweep as scan exhaustion.

### Added

- Add Manage storage calls (#2424, mdk#2314): `marmot_attachment_storage_usage`,
  `marmot_attachment_storage_by_chat`, `marmot_largest_retained_attachments`,
  `marmot_remove_chat_attachments` and `marmot_remove_attachments_older_than`,
  with records freed by `marmot_attachment_storage_usage_free`,
  `marmot_chat_storage_page_free` and `marmot_retained_attachments_page_free`.
  The two listings take 1..=256 rows per page. Page cursors are borrowed from
  their page: keep it alive while passing its `next_cursor`.
  `MarmotAttachmentStorageUsage` holds `media_bytes`, `legacy_bytes`,
  `attachment_count`, `database_bytes`, `database_free_bytes`, `migration`,
  `migration_bytes` and `cache_bytes` (the avatar and group-image cache, each
  image once). `migration` is a
  `MarmotAttachmentMigrationState` (`NOT_NEEDED` 0, `RUNNING` 1, `PAUSED` 2,
  `COMPLETE` 3, `COMPACTING` 4) for the background move of legacy database
  bodies into the media store and the compaction after it (#2467, #2496,
  #2527); `migration_bytes` is what remains to move while `RUNNING` and the
  free space needed while `PAUSED`, otherwise 0.

- `marmot_attachment_keep_media` and `marmot_set_attachment_keep_media` read
  and set the opt-in per-account "Keep media" window as a
  `MarmotAttachmentKeepMedia` discriminant (`FOREVER` 0, the default,
  `ONE_YEAR` 1, `SIX_MONTHS` 2, `THIRTY_DAYS` 3) (#2541, mdk#2314). Setting a
  window removes the retained attachments already past it before returning
  and writes their count; the runtime then applies it at start and hourly.

- Add `marmot_open_attachment_handoff` and `marmot_release_attachment_handoff`
  (record `MarmotAttachmentHandoff`, freed with `marmot_attachment_handoff_free`,
  which does not release the lease) for plaintext handoff copies of retained
  attachments (#2398, mdk#2314). Release every lease: removing the attachment
  does not revoke its copy. Copies are unsupported on Windows; an unsupported
  or cancelled copy returns `MARMOT_STATUS_INVALID_MEDIA_REFERENCE`.

- Add account-wide attachment history (#2233):
  `marmot_account_attachment_history_page` takes a borrowed
  `MarmotAccountAttachmentQuery` (group and sender arrays of at most 100
  entries, `uint8_t`-flagged timeline bounds), 1..=100 candidates and an
  optional borrowed cursor, and returns a `MarmotAccountAttachmentPageRead`
  freed with `marmot_account_attachment_page_read_free`. The page's `version`
  and `next_cursor` are borrowed from it; `marmot_account_attachment_version_clone`
  makes a baseline that outlives it, `marmot_account_attachment_history_version`
  reads the current one, `marmot_account_attachment_version_change_since`
  compares them and `marmot_account_attachment_version_free` frees standalone
  versions. Reads start no acquisition or relay work; group history remains
  supported.

- Add `marmot_cached_public_event_previews` (local cache only) and
  `marmot_resolve_public_event_preview` (fetches when missing or stale), with
  record `MarmotPublicEventPreview`, enum `MarmotPublicEventPreviewState` and
  frees `marmot_public_event_preview_free` /
  `marmot_public_event_preview_list_free`, for cached public Nostr event
  previews (#2304, mdk#1547). `MARMOT_STATUS_INVALID_PUBLIC_EVENT_REFERENCES`
  (103) reports a read of more than 16 references. The account's directory
  cache gains migration 2, which older libraries refuse.

- Add `MARMOT_STATUS_FOLLOW_LIST_TOO_LARGE` (107): `marmot_follow_user` and
  `marmot_unfollow_user` published nothing because the account's kind-3 list
  has 2,048 follows or more, the most MDK reads from one list (#2529,
  mdk#2268). Both now keep the list's petnames, relay hints, other tags and
  content; before, they rebuilt it from bare `p` tags.

- Add `MARMOT_STATUS_STORAGE_FULL` (106): the device has no room for the
  operation (#2384, mdk#2314). A media upload returns it before anything is
  uploaded when the disk cannot hold the body beyond the disk reserve, and so
  does a handoff copy; a full disk or database elsewhere also returns it
  instead of the generic runtime status.

- Add `MARMOT_STATUS_DIRECTORY_LOOKUP_INCOMPLETE` (104): a relay-list or
  KeyPackage lookup for an account ran out of time or relay coverage, so
  nothing is known to be missing (#2308, mdk#2302). Offer retry. These
  failures previously returned the generic runtime status.

- Add `marmot_send_prepared_media_with_client_token` for captured
  ordinary-media admission and conditional draft consumption (#2229). Inputs
  are borrowed; the nullable captured revision remains owned by its
  selected-draft root. The owned result uses the existing
  `marmot_local_send_acceptance_free`.

- Add `MARMOT_STATUS_GROUP_CATCHING_UP` (101): a group change was refused
  because unresolved epoch-gap recovery covers the group's current local
  epoch (#2273, mdk#2258). Retry after it syncs, or call the new
  `marmot_acknowledge_group_catching_up` once the user accepts that the change
  may split the group, then retry. Messages and `marmot_leave_group` are not
  held.

- Add `MARMOT_STATUS_GROUP_COMMIT_UNDELIVERED` (102): a group change was
  refused because the group's last change has been owed to a group relay for
  two minutes (#2288, mdk#2255). Add `marmot_group_commit_delivery` (record
  `MarmotGroupCommitDelivery`, freed with `marmot_group_commit_delivery_free`)
  to list the owed relays, and `marmot_acknowledge_group_commit_undelivered`
  to let one change through once the user accepts the risk.

- Add `MARMOT_STATUS_INVALID_EDIT_TARGET` (105), returned by
  `marmot_edit_message` unless its target is an available chat message this
  account sent, and by `marmot_edit_local_message_with_client_token` when the
  original was deleted or withdrawn (#2299). Nothing is published. Before, the
  edit was published and then ignored by every recipient.

### Changed

- `MarmotAttachmentTransferState` appends
  `MARMOT_ATTACHMENT_TRANSFER_STATE_STORAGE_BLOCKED` (17; #2249) and
  `MARMOT_ATTACHMENT_TRANSFER_STATE_CLEANED_BY_SETTING` (18; #2541); earlier
  discriminants keep their values. Handle `STORAGE_BLOCKED` as "free up
  storage", not as a retry timer; `CLEANED_BY_SETTING` marks an attachment
  "Keep media" removed, and downloading it again is allowed.
- Attachment bodies are encrypted files under the account's `media/`
  directory instead of account-database rows: downloads, their checkpoints
  and the bodies a send stages before uploading (#2329, #2349, #2353, #2384,
  mdk#2314). Avatars and group images follow as cache files (#2504, #2527),
  and legacy bodies move in the background. Exclude the whole account
  directory from cloud and device backups. `marmot_read_attachment_asset`
  reads either layout. Download checkpoints from 0.13.0 are discarded, so
  interrupted downloads restart. `MarmotAttachmentDownloadPolicy.retained_bytes`
  no longer gates downloads: a download needs the disk reserve plus twice the
  body. A full table of 256 uploads awaiting publication fails the send,
  publishing nothing.
- Account, cache and external-signer databases move to raw SQLCipher keys on
  first open through a one-time, crash-safe rekey (#2549, mdk#1791). Older
  libraries cannot open a migrated database. Keep the `.salt` sidecars and
  secret-store credentials; see the
  [offline downgrade](../../docs/marmot-architecture/storage-format-v2.md#offline-downgrade)
  procedure.
- `marmot_watch_agent_text_stream` and `marmot_agent_publisher_new` given no
  `server_cert_der` verify the QUIC broker against the bundled Mozilla roots
  (`webpki-roots`) instead of the OS trust store (#2331, mdk#2324). Pin a
  broker behind a private or enterprise CA by passing that CA's root
  certificate.
- `marmot_control_attachment` Remove unlinks the released media file before
  returning (#2410), and fails before removing anything when the media store
  cannot open (#2424).
- Account maintenance publishes a self-update for each group whose own leaf
  does not advertise every supported component, at a persisted random time
  within five days, so existing groups can adopt new components (#2292). These
  commits wait behind the same group-change holds.
- Recipients with only obsolete KeyPackages now return
  `MARMOT_STATUS_MISSING_KEY_PACKAGE` (15) instead of
  `MARMOT_STATUS_INVALID_KEY_PACKAGE_EVENT`; the error detail ends in
  `[obsolete_only]` (or `[not_found]`) (#2305, mdk#1975).
- On OpenBSD, `c-bindings.sh` builds SQLCipher without `mlock` and with
  concealed allocations, so hosts can run under `pledge(2)` (#2468). Other
  platforms are unchanged.

### Fixed

- `marmot_sweep_expired_retention` no longer prunes an expired message the
  unread count still shows (#2469, mdk#2425).
- `marmot_approve_onboarding_repair` and its `_in_epoch` form approve a
  replacement only once every onboarding source, including the relays in the
  signed relay declaration, has completed its freshness query; otherwise the
  step reports a retryable failure (#2545).
- C hosts receive `marmot-app`'s 0.14.0 runtime fixes without code changes,
  among them batched live group REQs (#2310), closed leaked REQs and paged
  relay-clamped replays (#2274), ordered offline catch-up (#2513), epoch-gap
  fallback paging (#2298, #2500), self-update fanout retries (#2275),
  storage-blocked downloads that no longer retry forever (#2249) and stall
  detection after notification wakes (#2343). Events a relay rejected
  terminally are not resent (#2523), and strict directory fetches use at most
  three filters per REQ (#2525). See the
  [marmot-app changelog](../marmot-app/CHANGELOG.md).
- Dependency updates fix RUSTSEC-2026-0365 in `negentropy` (#2377) and
  RUSTSEC-2026-0381/0382 in `webpki-roots` and `rustls-webpki` (#2516).

## [0.13.0] - 2026-10-12

Recompile against the matching `marmot.h` and library: several record layouts changed and new event, Markdown and
status values are appended. See the [client upgrade guide](../../docs/integration/0.13.0.md).

### Added

- `marmot_set_startup_diagnostics_enabled`, `marmot_startup_diagnostics_snapshot`
  and `marmot_native_startup_snapshot_free` mirror opt-in native startup
  progress (`MarmotNativeStartupSnapshot`). The snapshot remains usable before
  native startup completes.

- NIP-46 signer sessions and the runtime follow the opt-in `WN_SOCKS5_*`
  proxy settings described in the marmot-app
  [SOCKS5 routing](../marmot-app/README.md#socks5-routing) section. With the
  variables unset, nothing changes. When they are invalid,
  `marmot_nip46_new` returns `MARMOT_STATUS_INVALID_ARGUMENT` and
  `marmot_client_new` fails instead of connecting directly. Agent preview
  publishing and watching are unavailable while SOCKS5 is on.

- `marmot_submit_moderation_report`, `marmot_moderation_reporting_available`,
  `marmot_configure_moderation_reporting` and
  `marmot_moderation_report_outcome_free` mirror the private moderation-report
  calls. `MarmotModerationReportOrigin` and `MarmotModerationReportOutcome` are new
  types, and statuses 96–100 cover the new errors. `MarmotClientOptions` is
  unchanged; configure the destination with the new call. These are new symbols,
  so use the matching header and library.

- `marmot_create_identity_with_initial_profile` creates a generated identity
  whose first public kind-0 is the borrowed onboarding profile. New symbol;
  use the matching header and library.
- File-backed media upload inputs, token-aware upload calls and operation
  cancellation/progress handles: `marmot_upload_media_files`,
  `marmot_upload_media_files_with_client_token`,
  `marmot_media_file_transfer_control_*` and
  `marmot_max_file_media_ciphertext_bytes`. New symbols and borrowed input records require
  matching headers/libraries; existing byte-array APIs retain their bounds.
- Add `marmot_propose_onboarding_relay_repair` and nested typed relay-repair
  preview records. `MarmotOnboardingRepairProposal` gains an optional
  `relay_repair` pointer; regenerate and recompile with the matching header
  and library. The preview is non-publishing, and `ManualReview` has no
  approvable action.
- The C event surface appends local-copy termination/restoration and removed-device-leaf
  events; existing discriminants remain unchanged. Recompile with the matching
  header and native library and handle the new event kinds. Restoration describes
  retained-history repair, not automatic scheduler restoration of removed copies.
- `MarmotPresentedChatRow` gains a nullable row-owned `MarmotChatListDraftVersion` handle and
  `marmot_message_draft_revision_includes_chat_list_version` compares it against
  a borrowed selected revision. Both inputs are opaque read-only borrows; only
  the selected revision authorizes revision-checked mutation.
  Newer identical drafts remain distinguishable. Rebuild with matching generated
  headers/libraries; the row layout and comparison signature change. Identical-text
  saves emit a replacement snapshot because their draft revision changes. See the
  shared chat-list contract.
- Append the `MARMOT_MARKDOWN_INLINE_TIMESTAMP` inline tag with signed `int64_t` Unix seconds
  and `MarmotMarkdownTimestampStyle` for local-time timestamp display nodes.
  Existing inline discriminants are unchanged; the new payload owns no
  allocations. Recompile consumers against the regenerated `marmot.h` and ship
  the matching library; older headers cannot handle the new tag. Hosts format
  labels with the device locale/time zone and refresh visible relative labels.
- Add `marmot_message_reactions` and the owned
  `MarmotTimelineUserReactionList` root/free for complete exact-message details.
  Existing record layouts are unchanged; the new symbols require matching
  generated headers and native libraries.
- Per-account NIP-46 sessions for bunker links and client-initiated pairing,
  with identity pinning, approval URLs, relay switching, cancellation and logout.
  Local-key accounts and separate remote signers can run in the same client.

### Changed

- Relay-repair C preview content, tag fields and optional endpoints use JSON
  string literals to preserve embedded NULs and all UTF-8 bytes. Decode once
  with a length-aware parser before consent or editing. Pointer layouts and
  snapshot frees are unchanged, but consumers must adopt the new encoding.

- `MarmotAttachmentEntry` adds `role: MarmotAttachmentRole` (`Shared` or
  `InlineEmoji`) for gallery filtering without changing slot or acquisition identity.
  This changes the record layout; rebuild clients with the matching header/library.
- External account SQLCipher keys use the configured host secret store. Existing
  plaintext key files migrate only after a verified secret-store write. Older
  binaries cannot open migrated databases; downgrade is unsupported.
- `marmot_create_poll` accepts direct conversations as well as groups.
- `marmot_retired_relay_hosts` no longer returns `relay.damus.io`, and endpoint
  classification reports it allowed.

### Fixed

- NIP-46 signing requests contain only `kind`, `content`, `tags`, and `created_at`.
  SDK-only event IDs and public keys stay local for response verification.
- Publication signing failures report the event kind. Signer error text stays
  out of the message because it can carry relay URLs.
- NIP-46 request publication failures report how many relays rejected the
  request, without relay URLs or relay-supplied text.
- Account onboarding can establish inbox-list absence from a completed read of
  freshly discovered outboxes even when a discovery indexer is unavailable.

- Group activity preserves per-commit reaction targets across author and peer
  replay, including before disband. See `marmot-app`'s 0.13.0 fixes for
  projection and push-token behavior.

## [0.12.0] - 2026-10-02

Recompile against the matching `marmot.h` and library: several signatures and
record layouts changed. See the [client upgrade guide](../../docs/integration/0.12.0.md).

### Added

- `marmot_group_app_component` / `marmot_group_app_component_free` and
  `marmot_update_app_component` read and admin-update optional
  application-owned group components. `MARMOT_STATUS_INVALID_APP_COMPONENT`
  (95) reports invalid ids, required components and oversized state. (#1929)

- `marmot_request_explicit_attachment` joins/promotes eligible attachment demand without resetting retry budgets, backoff or active deadlines. Requires the matching header and library; deliberate Retry/Download again remain separate operations.

- `marmot_create_identity`, `marmot_create_identity_with_profile`,
  `marmot_login`, `marmot_login_recovering_incomplete_setup`,
  `marmot_publish_relay_lists` and `marmot_begin_onboarding` take a trailing
  `inbox_relays`/`inbox_relays_len` array that sets the kind-10050 inbox list
  separately from `default_relays`. Pass `NULL, 0` to keep declaring
  `default_relays` in both lists. The signatures changed: recompile against the
  matching header and library.
- `marmot_poll_votes` returns a `MarmotPollVotePage` of each voter's effective
  poll selection, 1..=100 per page with a `(voted_at, voter)` cursor; all pages
  sum to the `MarmotPollProjection` tally. Free it with
  `marmot_poll_vote_page_free`; requires the matching regenerated header and
  library. (#2091)
- `marmot_send_tagged_text`, `marmot_send_tagged_media`, and
  `marmot_react_with_media` add application tags such as NIP-30 `emoji` to a
  chat, media chat, or reaction. `MarmotMediaUploadRequest` gains trailing
  `message_tags`/`message_tags_len` (NULL/0 for none), which changes its
  layout; requires the matching regenerated header and library.
- `MarmotConversationReaction` gains trailing nullable
  `reaction_message_id_hex`, the earliest active kind-7 for that emoji; a
  NIP-30 reaction's image is listed under it by `marmot_list_media`. Kind-9
  conversation rows also keep NIP-30 `emoji` tags. Requires the matching
  regenerated header and library.

### Changed

- `marmot_set_chat_muted` now allows direct mentions of the receiving account
  through the durable mute in notification subscriptions. Ordinary traffic
  stays silent and blocked senders remain suppressed; C hosts still apply
  their own notification permission, channel, and foreground policy. No C ABI
  layout changes. (marmot-protocol/whitenoise-android#2984)

## [0.11.0] - 2026-09-29

### Added

- `marmot_edit_local_message_with_client_token` durably queues a revision of a
  token-aware local text or reply. It returns local acceptance before delivery;
  use `marmot_local_send_status` and the matching generated header/library.

- Stateless `marmot_verify_public_nostr_event_json` C API backed by the same
  Nostr/libsecp256k1 verifier as the UniFFI bindings. It checks canonical event
  IDs and signatures without client state, and requires the matching regenerated
  header and library. Invalid events return zero; invalid pointers return an
  argument status.

- Add 28 shared and nine Linux-specific host-performance operations. Read every
  stage through the existing `MarmotAppPerformanceSnapshot.runtime_operations`
  array; the C snapshot layout and existing operation values are unchanged.
  New operations require the matching generated header and library. The existing
  snapshot deep-free releases their names and histograms.

- Add `marmot_create_poll`, `marmot_cast_poll_vote`, and structured poll projection records. This adds a nullable field
  to `MarmotTimelineMessageRecord`; poll creation follows canonical group-conversation classification, while an
  accepted open poll remains votable after reclassification. Regenerate and recompile with the matching header and
  library.

- Add "history may be incomplete" notices: `marmot_history_notices` (free with
  `marmot_history_notice_list_free`), `marmot_dismiss_history_notice`, `MarmotHistoryNotice`,
  `MarmotHistoryNoticeList` and `MarmotHistoryNoticeCause`. Dismissal is durable, is recorded as
  its own outcome rather than recovered history, and writes false for a stale id; a malformed id
  returns `MARMOT_STATUS_INVALID_HEX`. This changes layouts: `MarmotGroupRecoveryStatus` appends
  `history_may_be_incomplete` and the `history_notice_ids` array (released by its existing deep
  free), and `MarmotEvent` appends the `MARMOT_EVENT_HISTORY_NOTICES_CHANGED` tag and body.
  Existing tag values are unchanged. Recompile with the matching header and library. (#2068)

### Fixed

- Chat-list-window commands quoting a sequence replaced only by background
  content changes now apply to the current viewport instead of returning
  `MARMOT_STATUS_CHAT_WINDOW_STALE`. An older visible-anchor quote naming a row a
  background replacement dropped still returns it. The header and library
  signatures are unchanged.

## [0.10.4] - 2026-09-20

### Added

- Host-managed attachment acquisition mode on `MarmotClientOptions`, generation-fenced
  permission and automatic-request commands, and acquired-unavailable/completed-unretained/
  retry-exhausted states. This changes the options layout: recompile with matching
  generated headers and libraries. See the [attachment migration](../marmot-uniffi/ATTACHMENT-ACCESS.md#host-managed-automatic-acquisition-0104). ([#1939](https://github.com/marmot-protocol/mdk/pull/1939))

- `MarmotChatListMessagePreview` exposes optional per-message `retention_seconds`
  and `retention_expires_at` so hosts can hide expired previews before pruning.
  This changes record layout: rebuild with matching headers and libraries. See
  [preview expiry handling](../marmot-uniffi/CHAT-LIST-ROWS.md#disappearing-message-previews-0104).
  ([#1942](https://github.com/marmot-protocol/mdk/pull/1942))

- Token-aware send/reply/draft/upload methods, durable local acceptance records and
  local submission status lookup. `MarmotTimelineMessageRecord` gains nullable
  `client_token`; regenerate and recompile with matching headers/libraries. See
  [local sends](../marmot-uniffi/LOCAL-SENDS.md) for ownership and retry semantics.

### Fixed

- Expose distinct attachment-mode and signed-out-account status codes with the matching regenerated header. ([#1939](https://github.com/marmot-protocol/mdk/pull/1939))

## [0.10.3] - 2026-09-19

### Fixed

- 0.10.3 release preflight: ordinary host-thread client free waits for embedded
  runtime workers to release resources, preventing pending SQLCipher connection
  destructors from racing process-exit cleanup. Tokio-context free remains
  nonblocking to avoid deadlock; final process teardown belongs on a host thread.

### Added

- `MarmotPresentedChatRow` gains selected draft/message/invitation/empty preview and row-action records. Draft text is owned and deep-freed with the row. This changes record layout: regenerate and recompile with matching headers/libraries. See [C3 integration](../marmot-uniffi/CHAT-LIST-ROWS.md).

### Documentation

- Clarify that retry safety for invalid required out-pointers does not cover all errors:
  a mutation can have recorded durable intent or external effects before another failure.
  Clients using blanket retry-on-error should inspect authoritative state and the method's
  retry contract. This corrects earlier wording, not runtime behavior.
- Clarify the existing exact header/library pairing requirement: “versioned C ABI” does
  not promise cross-release record-layout compatibility. No declaration or ABI change is
  introduced by this documentation correction. See the
  [0.10.2 integration supplement](../../docs/integration/0.10.2.md#c-compatibility-and-retry-guidance-corrections).

### Fixed

- macOS C bundle and optimized smoke builds disable debug stripping, avoiding
  misaligned Mach-O shared libraries rejected by Xcode 27. No ABI change;
  optimization and Linux packaging are unchanged.

### Added

- `marmot_group_app_component` and admin-only `marmot_update_app_component`
  expose opaque optional group state for application-owned component IDs.
  Applications allocate IDs at or above `0xf000`; every ID below that is
  protocol space and is rejected, so a component the registry assigns later
  can never collide with one an application already committed. Required
  components cannot be updated through this API, and `data_len` is capped at
  4096 bytes because the value is re-encoded into every later commit and every
  Welcome. An absent component writes NULL to `*out` and still returns OK;
  present empty data writes a record with zero length.
  Release records with `marmot_group_app_component_free`. Invalid component IDs
  return the appended `MARMOT_STATUS_INVALID_APP_COMPONENT` status (95).
  Existing record layouts and status values are unchanged.

- `MarmotClientOptions` and `marmot_client_new_with_configuration` combine relay
  policy, cursor persistence, client label and optional host secret storage.
  Zero-initialized options preserve the existing defaults. Use matching headers
  and libraries; existing constructor signatures remain available.

- `marmot_client_new_with_client_name` configures an optional public KeyPackage
  client tag, with cursor policy and optional host secret store. Existing
  constructors remain untagged. Use the matching header and library.

- Attachment transfer snapshot/subscription, durable cancel/retry/remove/download-again,
  and per-account download policy APIs. The subscription uses blocking next, cancel and free;
  results have a dedicated deep-free. Automatic acquisition now defaults on with the approved
  bounded policy. Regenerate the header and use its matching library.

- `marmot_attachment_local_assets` resolves up to 64 source slots to opaque local
  references without fetching or registering demand. `marmot_read_attachment_asset`
  returns verified plaintext ranges of at most 1 MiB, with unavailable distinct from
  empty EOF. Free results with `marmot_attachment_local_asset_list_free` and
  `marmot_attachment_local_bytes_free`. Additive API; regenerate headers and use
  the matching library. Acquisition policy is controlled through the additive C8-D2 APIs.

- Runtime performance snapshots with bounded operation names, terminal outcomes,
  duration histograms and unfinished-work gauges. Host timing enums add conversation
  local-visible/composer-ready milestones and cancelled/timeout/unavailable outcomes.
  `MarmotAppPerformanceSnapshot` gains an owned runtime-operation array; its existing
  free function releases the array and nested records. Use matching regenerated
  headers and libraries because the output record layout changed.

- `MarmotDeletionSource` and `deletion_source` on `MarmotTimelineMessageRecord`,
  `MarmotTimelineReplyPreview`, and `MarmotChatListMessagePreview` distinguish
  accepted author/admin deletions with an unknown fallback for legacy evidence.
  Regenerate headers and use the matching library: these output record layouts
  have changed. Custom-event conversation windows also retain undeleted tags.

- Bounded local attachment discovery via `marmot_attachment_history_page` and
  `marmot_attachment_history_version`, with typed page results, categories and
  opaque cursor/version handles. Compare refresh versions with
  `marmot_attachment_history_version_change_since`; retain an independent baseline
  with `marmot_attachment_history_version_clone`. Release owned results with
  `marmot_attachment_page_read_free` and `marmot_attachment_history_version_free`.
  Reads do not require an engine or start downloads. Regenerate headers and use
  the matching library.

- `MarmotAccountKeyPackageLocalState`, `MarmotAccountKeyPackageInventoryEntry`,
  `MarmotAccountKeyPackageInventoryEntryList`,
  `marmot_account_key_package_inventory_entry_list_free`,
  `marmot_local_account_key_packages`, and
  `marmot_refresh_account_key_packages` for local-first KeyPackage inventory
  with typed durable provenance from a consistent local storage snapshot.
  Existing `MarmotAccountKeyPackage` layout is unchanged. Regenerate headers and
  use a matching library.

- `marmot_report_message` and `marmot_dismiss_reports`, paginated `marmot_content_reports`
  and `marmot_report_dismissals`, and the deletion-masked `marmot_reported_message` lookup.
  Report records expose `MarmotReportReason` and individual dismissal state; timeline records
  gain `has_reports`. Use existing projection subscriptions to refresh report views.
  Regenerate headers with the matching library for the changed output layouts.

- Typed group-system chat previews and explicit `MarmotGroupSystemEventProvenance`
  on timeline and preview events. Authenticated actor/subject IDs remain distinct;
  chat previews include locally prepared names, while clients localize wording.
  Regenerate headers and use the matching library: both output record layouts changed.

- Accepted-edit presentation: `MarmotTimelineMessageRecord.edit` carries a nullable
  `MarmotTimelineEditSummary`; `marmot_message_edit_history` returns a
  `MarmotTimelineEditHistoryPage`, released with
  `marmot_timeline_edit_history_page_free`. Chat-list triggers append
  `LastMessageContentChanged`. The timeline record layout has changed: regenerate
  headers and use the matching library. Raw edit events remain accessible while
  transcript rows expose effective content on the original message.

- `MarmotConversationReaction.viewer_reacted` identifies the viewing account's
  active reaction independently of the bounded reactor preview. Regenerate headers
  and use the matching library: the output record layout has changed.

- Prepared conversation windows with initial/live history, header/capabilities, visible
  identities, read state and revisioned draft descriptors. Add independent paging,
  anchor/jump/tail commands, finite operation deadlines, explicit cancellation and
  conditional draft save/clear/attachment/send operations. New statuses append 81–92;
  use matching regenerated headers/libraries. Publication and client adoption are separate.

- Additive bounded live chat-list windows (Chats, Unread, Archived, Left), paging/anchor
  commands and independent live account-attention summaries across Swift/Kotlin and C.
  Existing list/read APIs and C record layouts remain; new typed window errors append
  status codes 73–77. Regenerate bindings and use matching libraries.

- `MarmotAccountKeyPackageRelayEvent`, `MarmotAccountKeyPackageRelayEventList`,
  `marmot_account_key_package_relay_events`, and
  `marmot_account_key_package_relay_event_list_free` for observed KeyPackage
  relay history, including superseded same-slot events. Existing
  `MarmotAccountKeyPackage` layout is unchanged.
- `marmot_forget_group_local` deletes local chat and MLS state without publishing a leave,
  stops group work, and permits a fresh authenticated invitation to rejoin. Rebuild with
  matching headers/libraries; hosts must clear their own media caches and close group views.
- `marmot_default_profile_pseudonym` and `marmot_random_profile_pseudonym`
  for the shared cosmetic display-name helpers. Free the owned UTF-8
  strings with `marmot_string_free`. These functions add no status values or
  struct layouts.
- `MarmotMediaAttachmentOutcome` (tagged union: `Accepted { attachment_index, reference }` /
  `Rejected { attachment_index, rejection }`), `MarmotMediaAttachmentRejection`, and
  `MarmotMediaAttachmentRejectionKind` for per-attachment parse outcomes (#1787).
- `MARMOT_STATUS_MEDIA_ATTACHMENT_REJECTED` (70), `MARMOT_STATUS_MEDIA_UNFETCHABLE` (71), and
  `MARMOT_STATUS_MEDIA_DOWNLOAD_FAILED` (72), appended after the existing codes.

### Changed

- `marmot_account_unread_summary` and live account-attention totals count each active,
  unarchived pending invitation as one `attention_only_conversations` item. Invitation
  message/mention counts remain suppressed until acceptance; retained messages or a
  manual reminder do not multiply the invitation item. The application badge is
  `unread_count + attention_only_conversations`; do not add invitations separately.
  Archived and departed/departing groups, including queued leave/disband requests,
  contribute nothing. Muted active chats and accepted manual-only reminders still
  count. The Unread filtered list continues to exclude invites; struct layouts are unchanged.

- Account storage advances through migrations 70–74 for local group reset boundaries,
  chat navigation, revisioned drafts and invitation attention.
  Back up before upgrading; downgrade is unsupported. See the cohort upgrade notes in
  [the CLI changelog](../cli/CHANGELOG.md#unreleased).
- `marmot_account_id_hex` now decodes `nprofile` / `nostr:nprofile`
  references and discards relay hints. Existing hex, `npub`, and
  `marmot://profile/` forms keep their established OK-plus-NULL contract.
  Duplicate type-0 TLV entries keep the first key. After wrapper
  normalization, encoded tokens longer than 1023 UTF-8 bytes are
  rejected; a valid 1023-byte token still decodes when wrapped.
- `marmot_normalize_member_ref` documents the same nprofile spellings,
  first-wins type-0 rule, and 1023-byte encoded-token limit.
- **In-place ABI break, recompile required.** `MarmotTimelineMessageRecord.media` and
  `MarmotTimelineReplyPreview.media` hold `MarmotMediaAttachmentOutcome` items rather than
  `MarmotMediaAttachmentReference`, so the element type and array stride change; a binary built
  against the previous header would misread the array. This is an Unreleased 0.9 change with no
  in-place dylib swap supported: rebuild C consumers against the new `include/marmot.h` and
  switch on the outcome tag. No `…V2` compatibility mirror is provided because no shipped C
  consumer upgrades the library without a rebuild. A malformed or unsupported attachment now keeps
  its position with a typed reason instead of disappearing; the parent record's deep-free releases
  either payload.
- `MarmotMediaRecord.attachment_index` counts the position among the message's `imeta` tags,
  rejected siblings included, matching the timeline outcome index.
- `marmot_download_media` returns `MARMOT_STATUS_MEDIA_UNFETCHABLE` when no locator may be
  fetched under the current policy and `MARMOT_STATUS_MEDIA_DOWNLOAD_FAILED` for transport,
  integrity, and decryption failures. Structurally invalid host-supplied references return
  `MARMOT_STATUS_MEDIA_ATTACHMENT_REJECTED` from every media command instead of
  `MARMOT_STATUS_INVALID_MEDIA_REFERENCE`, which now covers group-profile/policy mismatches
  and unusable upload requests.

## [0.9.21] - 2026-09-10

This cohort also exposes host-driven agent stream publishing and the v4 audit
tracker configuration. Rebuild with the matching header and library. Account
storage advances through migrations 68–69; back up before upgrading because
downgrade is unsupported. See the [cohort upgrade notes](../cli/CHANGELOG.md#0921---2026-09-10).

### Added

- Additive `MarmotMarkdownBlock::Details` with an indirect `MarmotMarkdownDetails`
  payload for bounded `<details>` / `<summary>` display blocks. Existing block
  discriminants and union stride are unchanged; C consumers must regenerate
  compatible bindings to render the new tag.
- `marmot_search_cached_users`, `MarmotUserDirectorySearchResultList`, and
  `marmot_user_directory_search_result_list_free` for network-free public cache search across connected accounts.

### Changed

- Group creation, invites, and composition prewarming fetch current KeyPackages from relays, including for local
  sibling accounts; cached packages no longer substitute when resolution fails. Prewarm retains discovery routes
  only, and `MarmotMemberKeyPackagePrewarmSummary::reused_members` remains present but always returns zero.
- Create and Invite reject KeyPackages that explicitly advertise RFC 9420 default extension/proposal capabilities.
  **Compatibility:** inviting a peer still publishing an affected package fails (`InvalidKeyPackageCapabilities` in
  the Rust engine) until that peer generates and publishes a conforming package. Upgraded recipients automatically
  regenerate once on account activation; the durable generator revision advances only after a relay ACK, with
  retries across restarts. Peers that have not upgraded are not repaired by a sender's upgrade. This deliberately
  keeps nonconforming signed leaves out of new membership state. Previous unused private bundles retain their
  expiry/consumption policy and historical Welcome processing is unchanged.

- Search results include `is_followed_by_searcher`; streaming updates include keyed `updated_results` replacements
  and a `CachedResultsFound` trigger. Consumers must merge by account ID, including across radius pages, and use
  the explicit follow flag instead of radius 1 for badges. C consumers must rebuild against the matching generated
  header and library because both search-result and search-update struct layouts changed.

## [0.9.20] - 2026-09-08

### Added

- Presented chat-list reads and subscriptions, chat presentation records, and
  unified usage-diagnostics consent and settings APIs.
- Explicit onboarding recovery/query and epoch-aware approval/acknowledgment
  commands. `MarmotOnboardingSnapshot` includes `recovery_epoch`; C consumers
  must rebuild against the matching generated header and library.

### Changed

- `marmot_cancel_onboarding` documentation now matches the runtime: approved or
  ready attempts may be cancelled without first resuming a repair.

## [0.9.16] - 2026-09-01

### Added

- `marmot_notify_connectivity_restored`, allowing C hosts to wake durable
  outbound retries immediately after usable connectivity returns.
- Initial C ABI over `marmot-uniffi`: client lifecycle, accounts, groups,
  messaging, media, notifications, push, relays/telemetry, audit logs,
  timeline reads, Markdown parsing, and the 8 subscription surfaces with
  blocking reads and callback pumps. ([#1545](https://github.com/marmot-protocol/mdk/pull/1545))
- cbindgen-generated `include/marmot.h` (checked in, CI diff-gated),
  cdylib + staticlib build, pkg-config file, and the `marmotc-v*` release
  bundle. ([#1545](https://github.com/marmot-protocol/mdk/pull/1545))
- `alloc-audit` test feature proving deep-free completeness; C smoke
  example run under gcc, clang, and valgrind in CI. ([#1545](https://github.com/marmot-protocol/mdk/pull/1545))
- `marmot_client_new_with_secret_store` plus the `MarmotSecretStore`
  callback vtable and `MarmotSecretStoreStatus`: a host can hold account
  signing keys in its own storage (an encrypted vault, a custom keystore)
  instead of the platform keychain. `marmot_client_new` is unchanged.
  ([#1575](https://github.com/marmot-protocol/mdk/pull/1575))
- `marmot_rotate_key_package`: rotate the account's KeyPackage under its
  proper name (with a matching `rotate_key_package` on the UniFFI
  surface); `marmot_publish_new_key_package` stays as the legacy alias.
  ([#1545](https://github.com/marmot-protocol/mdk/pull/1545))

  Closes [#328](https://github.com/marmot-protocol/mdk/issues/328)
- `marmot_user_relay_lists` and `marmot_refresh_user_relay_lists`: read or
  fetch the NIP-65 and inbox relay lists any account id has published, not
  just a local account's. Both return `MarmotAccountRelayLists`.
  ([#1605](https://github.com/marmot-protocol/mdk/pull/1605))

[Unreleased]: https://github.com/marmot-protocol/mdk/compare/marmotc-v0.14.0...HEAD
[0.14.0]: https://github.com/marmot-protocol/mdk/compare/marmotc-v0.13.0...marmotc-v0.14.0
[0.13.0]: https://github.com/marmot-protocol/mdk/compare/marmotc-v0.12.0...marmotc-v0.13.0
[0.12.0]: https://github.com/marmot-protocol/mdk/compare/marmotc-v0.11.0...marmotc-v0.12.0
[0.11.0]: https://github.com/marmot-protocol/mdk/compare/marmotc-v0.10.4...marmotc-v0.11.0
[0.9.20]: https://github.com/marmot-protocol/mdk/compare/marmotc-v0.9.19...marmotc-v0.9.20
[0.9.16]: https://github.com/marmot-protocol/mdk/releases/tag/marmotc-v0.9.16
