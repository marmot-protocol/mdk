# Changelog

## Unreleased

### Breaking changes

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

### Changed

- `retired_relay_hosts()` no longer includes `relay.damus.io`, and
  `classify_relay_endpoints` now reports it as `Allowed`.

### Fixed

- Group activity uses shared per-commit reaction targets for authors and peers,
  including commits preceding a disband. See `marmot-app`'s Unreleased fixes
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
