# Changelog - marmot-c

All notable changes to the Marmot C bindings.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions track the workspace version; releases are tagged `marmotc-v<version>`.

## [Unreleased]

### Added

- Stateless `marmot_verify_public_nostr_event_json` and
  `marmot_verify_bip340_signature` C APIs backed by the same Nostr/libsecp256k1
  verifier as the UniFFI bindings. They add no client state, but require the
  matching regenerated header and library. Invalid signatures return zero;
  invalid pointers return an argument status.

- Add `marmot_create_poll`, `marmot_cast_poll_vote`, and structured poll projection records. This adds a nullable field
  to `MarmotTimelineMessageRecord`; poll creation follows canonical group-conversation classification, while an
  accepted open poll remains votable after reclassification. Regenerate and recompile with the matching header and
  library.

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

[Unreleased]: https://github.com/marmot-protocol/mdk/compare/marmotc-v0.9.20...HEAD
[0.9.20]: https://github.com/marmot-protocol/mdk/compare/marmotc-v0.9.19...marmotc-v0.9.20
[0.9.16]: https://github.com/marmot-protocol/mdk/releases/tag/marmotc-v0.9.16
