# Complete MarmotKit method reference

This reference inventories the UniFFI exports and is maintained alongside source changes.
Start with the [integration guide](README.md#integration-guide-and-api-reference)
for API selection, lifecycle, localization and ownership. For the 0.14.0 changes, read
[0.13.0 → 0.14.0](../../docs/integration/0.14.0.md).

The [native-host test recipe](NATIVE-HOST-TESTS.md) exercises generated Swift against a local MockRelay
with an injected thread-safe `SecretStore`, bounded delivery assertions, and same-root reopening.
It also gives the corresponding Android configuration and callback signatures.

This inventories runtime/object methods, free functions and host callback methods. `AttachmentHistoryCursor`,
`AccountAttachmentCursor`, `ChatStorageCursor`, `RetainedAttachmentsCursor` and `ChatListDraftVersionFfi` are opaque
objects with no exported methods. Generated disposal/concurrency helpers are platform scaffolding, not additional
MDK commands. C has a separate [complete symbol index](../marmot-c/API-GUIDE.md), including
its lifetime helpers and compatibility-only entry points.

## Reading the reference

- The generated reference uses Rust export spelling and types. Swift and Kotlin normally expose
  lowerCamelCase names (`attachment_local_assets` → `attachmentLocalAssets`). Constructors
  and native integer/optional/list/error syntax follow generated code from your cohort.
- `async fn` becomes Swift async / Kotlin suspend. A synchronous `fn` can perform storage
  I/O; run blocking operations off the UI thread. `Result` becomes the generated error path;
  `Option` is successful absence/stream closure as specified by the individual contract.
- **Current** means supported for its stated purpose, not that every app needs it.
  **Lower-level** means an intentional custom-client/primitive surface.
  **Compatibility** means a newer path is recommended for that listed use case; it is not
  a formal deprecation annotation, removal promise or requirement to rewrite custom clients.
  **Host callback** means implement it in the host, not call it as a runtime command.
- In the generated reference, source links lead to the Rust definitions. DTO field and variant
  definitions live in [conversions](src/conversions/), [errors](src/errors.rs),
  [Markdown types](src/markdown.rs) and the generated binding from the same release.
  Per-feature contracts in the README override no source behavior; report discrepancies.
- Object methods use their owning type explicitly. Distinguish each `next`/`snapshot` contract:
  a transfer subscription delivers its initial value from `next`, while a screen window
  has a separate initial snapshot. Do not infer cancellation support from another handle.

## Maintaining the reference

Add guidance here for each new export and remove entries for deleted exports.
`just binding-docs-gate` generates both references with exact signatures and source links.
It requires one entry per export; review the prose against the implementation separately.

## Swift cancellation adapters

The published `MarmotKit.swift` includes these Swift-only methods from
[`CancellableSubscriptions.swift`](swift-support/CancellableSubscriptions.swift).
Each has the same result as the generated receive it names, but forwards Swift task cancellation to the
native future and throws `CancellationError`; those receives are generated without `throws`, so they cannot.
The last four generated `next()` methods throw and already forward cancellation; their adapters are the
same call, kept for existing hosts. Cancellation does not close the subscription.
These are not new Rust exports or Kotlin methods. See
[subscription ownership](README.md#screen-snapshots-paging-and-ownership) for concurrent receive and cancellation races.

| Subscription | Swift signature |
| --- | --- |
| `BackupRestoreSubscription` | `func nextCancellable() async throws -> BackupRestoreStatusFfi?` |
| `BlockListSubscription` | `func nextCancellable() async throws -> BlockListSnapshotFfi?` |
| `ChatListSubscription` | `func nextCancellable() async throws -> ChatListRowFfi?` |
| `ChatListSubscription` | `func nextUpdateCancellable() async throws -> ChatListSubscriptionUpdateFfi?` |
| `ChatsSubscription` | `func nextCancellable() async throws -> AppGroupRecordFfi?` |
| `EventsSubscription` | `func nextCancellable() async throws -> MarmotEventFfi?` |
| `GroupStateSubscription` | `func nextCancellable() async throws -> AppGroupRecordFfi?` |
| `MessagesSubscription` | `func nextCancellable() async throws -> MessageUpdateFfi?` |
| `NotificationsSubscription` | `func nextCancellable() async throws -> NotificationUpdateFfi?` |
| `OnboardingSubscription` | `func nextCancellable() async throws -> OnboardingSnapshotFfi?` |
| `TimelineMessagesSubscription` | `func nextCancellable() async throws -> TimelinePageFfi?` |
| `TimelineMessagesSubscription` | `func nextUpdateCancellable() async throws -> TimelineSubscriptionUpdateFfi?` |
| `UserSearchSubscription` | `func nextUpdateCancellable() async throws -> UserSearchUpdateFfi?` |
| `PresentedChatListSubscription` | `func nextCancellable() async throws -> PresentedChatListUpdateFfi?` |
| `ChatListWindowSubscription` | `func nextCancellable() async throws -> ChatListWindowSnapshotFfi?` |
| `AccountAttentionSubscription` | `func nextCancellable() async throws -> AccountAttentionSnapshotFfi?` |
| `ConversationWindowSubscription` | `func nextCancellable() async throws -> ConversationWindowSnapshotFfi?` |

## Methods by source module

Each expandable section lists every export in that module. Search this page for the exact
Rust or owning-type method name.

<details>
<summary>commands/account.rs</summary>

### `Marmot::list_accounts`

**Current.**

All accounts known to the runtime, in stable order. `running` is `false` for accounts that haven't been brought up by the current process yet.

### `Marmot::account_unread_summary`

**Lower-level.** One-shot unread query; prepared account badges use subscribe_account_attention.

Per-account unread aggregate for the account-switcher and application badge (mdk#461, mdk#1460). Each entry is read from that account's materialized chat-list projection, so this does not require switching into, or loading a full session/timeline for, any account — non-active (not-`running`) local-signing accounts are reported too. This legacy getter omits accounts whose projection read fails. `attention_only_conversations` counts each active pending invitation once and accepted manual-only reminders, without overlapping message totals. Archived chats and departed or departing groups contribute nothing.

### `Marmot::remove_account`

**Current.**

Remove a local-signing account from this device. The call keeps running when it is cancelled (mdk#3670).

### `Marmot::sign_out_and_wipe`

**Current.**

Destructive sign-out: leave every active MLS group (best-effort), delete this device's relay-published KeyPackage slot, then wipe all local state for this account (MLS state DB, cached media/secrets, SQL account row, and the secret-store nsec). After this returns the account ref is no longer valid for any further FFI call. The returned `WipeOutcomeFfi` reports each stage independently so the app can show progress and a partial-failure sheet (mdk#478).

With linked devices, it first asks the account's other devices to take it out, which can take about 30 seconds: show progress meanwhile. It leaves them the chats they can take it out of, counted in `groups_left_to_siblings`, and leaves the rest itself. When it could not ask them in time it tries to leave every chat itself, reporting any it cannot in `group_leave_failures`, and sets `siblings_not_reached`: tell the user its other devices may still list it until the user removes it from one of them. A chat this device is no longer in is neither left nor reported. In a chat its account administers with another account, and no other of its devices is in, it steps the account down first and counts the chat as left only once it sees its removal, waiting up to about 30 seconds more for all such chats (mdk#2818). Queued new member Leaves appear in `group_leave_failures`. Local cleanup still runs. The call keeps running when it is cancelled (mdk#2628).

### `Marmot::sign_out`

**Current.**

Non-destructive sign-out: deactivate the account on this device and, when `delete_key_packages` is `true` (the default behavior in the UI), publish one kind:5 deletion for this device's KeyPackage slot so nobody can add this device to a new group while it is signed out. The account's other devices keep their KeyPackages. The call keeps running when it is cancelled (mdk#3670).

### `Marmot::create_identity`

**Current.**

Compatibility entry point for creating a brand-new Nostr identity. This retains the historical terminal-success contract: relay lists and the initial KeyPackage are published when it returns. New callers may use `create_identity_with_profile` for the earlier local-ready boundary and an explicit readiness state. Public indexers receive best-effort copies of both relay lists and kind-0 metadata; KeyPackages remain on the advertised write relays. `inbox_relays` (default empty) sets the kind-10050 inbox list separately; empty declares `default_relays` in both lists.

### `Marmot::create_identity_with_profile`

**Current.**

Create a generated identity and return at durable local readiness with the exact locally persisted default profile. `readiness` remains the authority for whether relay publication has completed; `LocalReady` must not be presented as invite-receivable. Account setup sends best-effort copies of both relay lists and the default kind-0 profile to public indexers. `inbox_relays` (default empty) sets the kind-10050 inbox list separately; empty declares `default_relays` in both lists.

### `Marmot::create_identity_with_initial_profile`

**Current.**

Create a generated identity whose first public kind-0 is the caller's `profile`, returning at durable local readiness like `create_identity_with_profile`. Use it whenever onboarding collects a name: creating with the generated default and then calling `publish_user_profile` exposes the default to relays first, and contacts can keep seeing it. The returned `profile` is the stamped copy that setup publishes and caches; `readiness` remains the authority for relay publication. A setup resumed past its first local step ignores `profile` and returns the profile its bootstrap publishes; change it afterwards with `publish_user_profile`. `inbox_relays` (default empty) sets the kind-10050 inbox list separately; empty declares `default_relays` in both lists.

### `Marmot::account_setup_readiness`

**Current.**

Read setup readiness without performing network I/O.

### `Marmot::login`

**Compatibility.** Prefer begin_onboarding for an interactive imported-account workflow.

Log in with an existing identity. `identity` can be an `nsec` (private key) for a local-signing account, or an `npub` to track a public identity without local signing. `inbox_relays` (default empty) sets the kind-10050 inbox list separately; empty declares `default_relays` in both lists. The call keeps running when it is cancelled (mdk#3670).

### `Marmot::reset_incomplete_account_setup`

**Current.**

Remove only the legacy ambiguous partial-account shape so a subsequent `login` with the same nsec can recreate it. The acknowledgement is required because old local state cannot prove that no KeyPackage was exposed before its stable slot was lost.

### `Marmot::login_recovering_incomplete_setup`

**Current.**

Consent-gated one-call recovery for installations stranded before MDK had durable account-setup journals. This validates the same nsec, removes only the recognized ambiguous partial shape, preserves an existing account-id Keychain credential, and immediately retries login. `inbox_relays` (default empty) sets the kind-10050 inbox list separately; empty declares `default_relays` in both lists. The call keeps running when it is cancelled (mdk#3670).

### `Marmot::login_external_signer`

**Compatibility.** Prefer begin_external_signer_onboarding for an interactive imported-account workflow. **C:** not exposed; external-signer callback vtable is not implemented.

Log in with an external account signer such as Amber/NIP-55. `inbox_relays` (default empty) sets the kind-10050 inbox list separately; empty declares `default_relays` in both lists. The call keeps running when it is cancelled, so it can still ask the signer to sign; declining rolls the setup back (mdk#3670).

### `Marmot::register_external_signer`

**Current.**  **C:** not exposed; external-signer callback vtable is not implemented.

Re-register an external signer for an already-known external account.

### `Marmot::sign_in_account`

**Current.**

Re-activate a non-destructively signed-out local account. This clears the durable signed-out marker and starts the account worker again; relay list/key-package repair can still be driven by the existing publish commands after sign-in. The call keeps running when it is cancelled (mdk#3670).

### `Marmot::publish_relay_lists`

**Current.**

Publish (or re-publish) the NIP-65 and inbox relay lists for `account_ref`. Each call writes fresh replaceable events to the account relays and schedules best-effort public indexer copies when eligible; call when the lists need publication rather than on every launch. Indexers are not advertised as account relays. `inbox_relays` (default empty) sets the kind-10050 inbox list separately; empty declares `default_relays` in both lists.

### `Marmot::account_nip65_relays`

**Current.**

Read the account NIP-65 relay list.

### `Marmot::account_inbox_relays`

**Current.**

Read the account inbox relay list.

### `Marmot::account_key_packages`

**Compatibility.** Prefer local_account_key_packages then refresh_account_key_packages for settings UI.

List the local and relay-discovered Marmot KeyPackage publications for `account_ref`. Relay-backed rows are the current winner per addressable slot in the validated fetch window.

### `Marmot::local_account_key_packages`

**Current.**

Local-storage KeyPackage inventory with typed durable provenance. Does not wait for network startup or issue a directory query. Synchronous SQLCipher I/O on the calling thread; keep it off a UI or main thread.

### `Marmot::refresh_account_key_packages`

**Current.**

Fetch validated relay observations, then merge a fresh local snapshot. Empty `bootstrap_relays` remains network-enabled. On failure, keep the previously rendered local result.

### `Marmot::account_key_package_relay_events`

**Current.**

Observed relay history for `account_ref`: current and superseded kind-30443 events from one validated fetch window. Clients can pass a superseded event id and its source relays to the existing deletion API.

### `Marmot::publish_new_key_package`

**Current.**

Publish a new fresh KeyPackage for `account_ref`.

### `Marmot::rotate_key_package`

**Current.**

Rotate the account's KeyPackage: mint and publish a fresh one, superseding the current slot. This is the sanctioned repair for an epoch-stalled group. `publish_new_key_package` is the same operation under its legacy name.

### `Marmot::republish_key_package`

**Current.**

Re-publish the latest cached KeyPackage when possible, otherwise publish a fresh one.

### `Marmot::delete_account_key_package`

**Current.**

Publish a NIP-09 deletion for a KeyPackage event.

### `Marmot::set_account_nip65_relays`

**Current.**

Publish the account read/write relay selection to its operational relays and copy it to public indexers.

### `Marmot::set_account_inbox_relays`

**Current.**

Publish the account inbox relay selection to its operational relays and copy it to public indexers.

### `Marmot::account_follows`

**Current.**

Return the complete locally cached kind-3 follow list for `account_ref` as canonical lowercase public-key hex strings.

### `Marmot::is_following`

**Current.**

Return whether `account_ref` currently follows `user_ref`, using the same local cache as `Self::account_follows`. `user_ref` accepts npub, hex, `nostr:npub…`, and Marmot profile links.

### `Marmot::follow_user`

**Current.**

Follow `user_ref` while preserving every other entry in the account's current kind-3 contact list. Returns the complete updated list. Appends one `p` tag and republishes petnames, relay hints, other tags and the content unchanged. Returns `FollowListUnavailable` when no current list is found, and `FollowListTooLarge`, publishing nothing, when the list has 2,048 follows or more (the most MDK reads from one list).

### `Marmot::unfollow_user`

**Current.**

Unfollow `user_ref` while preserving every other entry in the account's current kind-3 contact list. Returns the complete updated list. Removes only `user_ref`'s `p` tags; errors as `follow_user`.

### `Marmot::reveal_nsec`

**Current.**

Export the active account's raw private key in canonical `nsec1...` bech32 form for an in-app key-backup display (mdk#543).

### `Marmot::export_encrypted_secret_key`

**Current.**

Export the active account's private key as a password-encrypted NIP-49 `ncryptsec1...` bech32 backup string (mdk#544).

### `Marmot::publish_user_profile`

**Current.**

Publish Nostr kind:0 metadata with explicit caller-supplied relay overrides. Most app clients should use `publish_user_profile_using_account_relays` so relay selection remains owned by MDK. This override remains for diagnostics, tests, and specialized clients. Public indexers receive a best-effort copy of the same event.

### `Marmot::publish_user_profile_using_account_relays`

**Current.**

Publish Nostr kind:0 metadata using one coherent snapshot of the selected account's MDK-owned relay configuration. Public indexers receive a best-effort copy of the same event.

### `Marmot::upload_profile_image`

**Current.**

Upload a public raster profile image to Blossom with the account's signer. The returned HTTPS URL can be published as kind:0 `picture`.

### `Marmot::download_profile_image`

**Compatibility.** Prefer avatar asset request/read for visible screen metadata.

Fetch one untrusted kind:0 profile `picture` URL with MDK dial-safe HTTPS policy, address pinning, and bounded streaming.

</details>

<details>
<summary>commands/attachment_access.rs</summary>

### `Marmot::attachment_local_assets`

**Current.**

Local-only metadata for up to 64 original source slots in one group. Results preserve input order/duplicates. No bytes are loaded, jobs queued, downloads started or engine state hydrated. Requires no runtime start.

### `Marmot::read_attachment_asset`

**Current.**

Read 1..=1048576 bytes at an offset from an opaque local asset reference. Unavailable is distinct from available/empty EOF. Every call rechecks source visibility, expiry and account/store identity. No network fallback. Hosts own decoding and must discard assembled bytes if a chunk is unavailable.

### `Marmot::open_attachment_handoff`

**Current.**

Write a plaintext copy of one retained attachment for an OS surface that needs a real file (the Android package installer, the share sheet, "open with", Quick Look) and lend it under a lease. Use it only for those surfaces; in-app display and playback keep using `read_attachment_asset`. `None` means the attachment is not held locally, exactly as `attachment_local_assets` reports it; no download is started. The copy is `<account>/handoff/<lease>/<file_name>`, created owner-only, where `file_name` is the attachment's own name made safe (basename only, no separators, control characters or edge dots, at most 128 bytes) with an extension from the media type when it had none. It stays until `release_attachment_handoff`, account removal, or the account worker's next start in a new process; `shutdown_and_close` refuses new handoffs but keeps existing copies, and removing the attachment does not revoke a lease. Each call makes a separate copy. `control` reports copied bytes and cancels the copy, which then leaves nothing. Cancel only through `control`, never by cancelling the awaiting coroutine or task: a call cancelled just as it completes can drop the lease before the host sees it, leaving the copy until the account worker's next start in a new process deletes it. A copy the disk cannot hold beyond the attachment policy's `disk_reserve` fails with `StorageFull`. Works for bodies in the media store and in the legacy database layout. See [the handoff contract](ATTACHMENT-ACCESS.md#handoff-leases).

### `Marmot::release_attachment_handoff`

**Current.**

Delete a handoff copy once the OS surface is done with it (the installer or share activity returned, the controller was dismissed). Idempotent: an unknown or already released lease succeeds; a malformed one is rejected with `InvalidMediaReference`, which no retry fixes. A copy that cannot be deleted returns `Io` and stays leased, so retry the release. Do not use the path afterwards.

</details>

<details>
<summary>commands/attachment_controls.rs</summary>

### `AttachmentTransferSubscription::next`

**Current.**

Initial snapshot, then replacements: a transfer state change at once, progress-only changes at most four per second. None means closed. Errors terminate this observation; close/drop never cancels acquisition.

### `AttachmentTransferSubscription::cancel`

**Current.**

Stop observation and wake receivers; does not cancel acquisition.

### `Marmot::attachment_download_policy`

**Current.**

Read the durable per-account automatic acquisition, quota, disk-reserve and transfer-cap policy.

### `Marmot::set_attachment_download_policy`

**Current.**

Validate and persist acquisition policy; disabling automatic work preserves explicit work and retained files.

### `Marmot::request_explicit_attachment`

Join a current source or promote automatic demand to explicit priority without resetting retry budgets or scheduled backoff. Use this for ordinary interactive demand; reserve `control_attachment(Retry)` and `download_attachment_again` for deliberate recovery. A returned opaque reference does not promise readiness: inspect transfer state and prefer local assets first. Active attempts retain their original size limit and deadline; promotion changes subsequent admission, not the existing transport budget. Cancelled, removed, exhausted and failed sources are not rearmed.

### `Marmot::control_attachment`

**Current.**

Cancel durably, retry explicitly, or remove local bytes. Returns false for obsolete references or ineligible operations; cancellation preserves ready bytes.

### `Marmot::download_attachment_again`

**Current.**

Queue explicit acquisition for a current original source slot, clearing removal/cancellation; no reference means unavailable or obsolete.

### `Marmot::attachment_transfer_snapshot`

**Current.**

Read bounded transfer state for up to 64 source slots in one group without requesting a transfer.

### `Marmot::subscribe_attachment_transfers`

**Current.**

Observe initial transfer state and complete replacements for bounded source slots: a row that appears, disappears or changes transfer state arrives as soon as the engine reports it, while progress-only replacements stay coalesced to at most four per second. Observation does not request a transfer.

</details>

<details>
<summary>commands/attachment_history.rs</summary>

### `Marmot::reaction_attachment`

**Current.**

Bounded local lookup for one active custom-emoji reaction, keyed by its `reactionMessageIdHex` within the account and chat. Returns the validated image attachment matching that reaction's shortcode, with its original message/source IDs and attachment index, or `None` when unavailable or unmatched. Starts no download. Use the target with ordinary automatic or explicit attachment acquisition and opaque local reads; re-resolve when the earliest active reaction ID changes. Never fetch an emoji tag URL directly. See [reaction artwork](ATTACHMENT-HISTORY.md#reaction-artwork).

The reaction ID must contain exactly 64 hexadecimal characters; malformed IDs return `InvalidMediaReference`. The lookup considers original `imeta` indices 0–99 only, source tag JSON and each candidate slot up to 16 KiB, and reaction content up to 64 UTF-8 bytes including colons. Oversized metadata, artwork outside those indices, or no eligible match returns `None`. The first well-formed definition of the exact content shortcode wins; later duplicates cannot replace an unmatched first definition.

### `Marmot::attachment_history_page`

**Current.**

Read 1..=100 attachment slots in canonical newest-first order. Rejected slots consume the limit. Filter categories within returned pages; an empty filtered page is not exhaustion while has_more is true. No downloads are started. Keep cursors/versions in memory only and restart after runtime reconstruction.

### `Marmot::attachment_history_version`

**Current.**

Cheap local refresh signal, including for a fully loaded or empty library. Compare against the baseline version captured when the current collection began: replacing that baseline with a newer page can hide a destructive change to earlier rows.

</details>

<details>
<summary>commands/attachment_storage.rs</summary>

### `Marmot::attachment_removals`

**Current.**

Read up to 1..=256 durable account-scoped attachment-body removal identities for
host-owned derivative eviction. The page contains `removals`, `next_cursor`,
`reset_required`, and `has_more`. Each removal carries the original
`group_id_hex`, `message_id_hex`, `source_message_id_hex`, `attachment_index`,
and historical `state` (`CleanedBySetting`, `Removed`, `CompletedUnretained`,
or `Unavailable`), not current byte-read authorization.

A missing cursor captures the current high water with no records and
`reset_required=true`. Reconcile the entire derivative cache before persisting
that captured cursor. Trimmed or unrecognized cursors, including another
store/incarnation's cursor, require the same reset; malformed cursors can fail.
Otherwise evict returned identities idempotently before persisting `next_cursor`
and continue while `has_more`. Cursors are durable strings and must not be logged.
The journal retains at most 4,096 records. This local query neither downloads nor
reads bodies. See the [reconciliation contract](ATTACHMENT-ACCESS.md#derivative-cache-removal-journal).

### `Marmot::attachment_storage_usage`

**Current.**

Account-wide attachment storage for a Manage storage screen: `media_bytes` (media-store files, a file shared by several attachments counted once), `legacy_bytes` (bodies still in the account database; they move to the media store in the background), `attachment_count`, the database's `database_bytes` and `database_free_bytes`, and `migration` with `migration_bytes`: where moving legacy bodies into the media store stands (`Running` with the bytes left, `Paused` with the free space it still needs, `NotNeeded`, `Complete`, or `Compacting` while the database returns its free pages to the filesystem, with the other figures from just before), and `cache_bytes`: the avatar and group-image cache, which `clear_avatar_cache` empties and which is fetched again on demand. Reads no bodies and starts no worker. See [Manage storage](ATTACHMENT-ACCESS.md#manage-storage).

### `Marmot::attachment_storage_by_chat`

**Current.**

Chats by retained attachment bytes, largest first, `limit` 1..=256 per page; pass the page's `next_cursor` to continue, and stop when it is absent (the last page may be empty). A stored file counts once per chat however many of its attachments share it; content shared with other chats counts in each, so per-chat totals can add up to more than `media_bytes`. Cursors are opaque handles: never persist them, and start over after a removal.

### `Marmot::largest_retained_attachments`

**Current.**

Retained attachments, largest first, `limit` 1..=256 per page, optionally within one chat (`group_id_hex`); continue with `next_cursor` as for `attachment_storage_by_chat`. Each entry's `target` works with `attachment_local_assets` (for an opaque reference to pass to `control_attachment` Remove) and `open_attachment_handoff`; `media_type` and `file_name` come from the published descriptor and are empty when it does not parse.

### `Marmot::remove_chat_attachments`

**Current.**

Removes every retained attachment in one chat and returns how many it removed. Each removal is exactly `control_attachment` Remove: the attachment shows as removed and download-again stays allowed. Media-store files the removal releases are deleted before this returns, so their space frees at once; legacy database bodies free database pages, which return to the filesystem only when the database is compacted. Refresh usage and listings afterwards.

### `Marmot::remove_attachments_older_than`

**Current.**

Removes retained attachments of messages received before `received_before` (Unix seconds, the message's received time), across the account or within one chat (`group_id_hex`), with the same semantics and immediate reclaim as `remove_chat_attachments`. Returns how many it removed.

### `Marmot::attachment_keep_media`

**Current.**

Reads the account's "Keep media" setting for a settings screen: `Forever` (the default) unless the user chose `OneYear`, `SixMonths` or `ThirtyDays`. The setting is per account on this device and is not synced to the account's other devices. Local read; needs no started runtime.

### `Marmot::set_attachment_keep_media`

**Current.**

Stores the account's "Keep media" setting, then removes every retained attachment already past the new window before returning, and returns how many it removed so the host can confirm what was freed. Age is the message's received time, or the user's last explicit download of that attachment when later. Removed attachments read `CleanedBySetting` in transfer snapshots, distinct from `Removed` (removed by you); `download_attachment_again` works for both. Media-store space is freed before this returns. While the runtime runs, the account worker applies the window at start and hourly as attachments age, and automatic downloads of attachments past it are skipped, or dropped if already queued but unfinished (they count toward the returned number and read `CleanedBySetting` too). `Forever` removes nothing. Ask the user to confirm before shortening the window: Blossom servers may no longer hold old media, so a removed attachment may not download again.

</details>

<details>
<summary>commands/audit.rs</summary>

### `Marmot::audit_log_settings`

**Current.**

Local forensic audit-log recording settings. Recording is opt-in and only applies to account sessions opened after the setting is enabled.

### `Marmot::set_audit_log_settings`

**Current.**

Persist local forensic audit-log recording settings and return the stored value. Running sessions follow the stored value. The call keeps running when it is cancelled (mdk#3670).

### `Marmot::audit_log_retention`

**Current.**

Read the persisted local audit retention policy: maximum file age in days and per-account size budget in bytes. Defaults to 30 days and 256 MiB.

### `Marmot::set_audit_log_retention`

**Current.**

Persist the local audit retention policy and return the stored value, with `max_age_days` clamped to 1-30 and `max_bytes_per_account` to at least 16 MiB. Files past the age are deleted whether or not v5 delivery accepted them; deleting undelivered data records an `ExpiredUndelivered` gap. Above the budget, only the oldest sealed segments that v5 delivery accepted, or that no v5 delivery will send, are deleted. A running app sweeps under the new policy shortly after; explicit delete and clear calls are unaffected.

### `Marmot::set_audit_log_source`

**Current.**

Set the in-memory source metadata (system hardware model, platform, app version) that each audit recorder opened afterwards writes into its `source_context` row, and return the trimmed stored value; a blank field becomes absent. Call it on every launch before opening accounts: recorders already open keep the source they started with. The hardware model must come from system model information, never a device name, hostname or serial number.

### `Marmot::audit_log_files`

**Current.**

Local JSONL audit log files, including historical v4 files until retention expires them.

### `Marmot::delete_audit_log_file`

**Current.**

Delete one local JSONL audit log file (e.g. behind a "clear audit log" button).

</details>

<details>
<summary>commands/avatar.rs</summary>

### `Marmot::request_avatar_assets`

**Current.**

Pass up to 16 opaque targets from visible screen metadata. Does not await HTTP.

### `Marmot::read_avatar_assets`

**Current.**

Local-only read, up to 16 references and a 1-byte..16-MiB aggregate byte budget. Results preserve input order; deferred entries can be retried in a later batch.

### `Marmot::clear_avatar_cache`

**Current.**

Clear durable avatar bytes and demand; later visible requests can acquire again.

</details>

<details>
<summary>commands/chat_list.rs</summary>

### `Marmot::chat_list`

**Lower-level.** Raw full list; prepared bounded screens use open_chat_list_window.

Durable chat-list rows for fast app launch. Rows include the group title/avatar, last kind-9 preview, unread count, and read anchors.

### `Marmot::chat_list_row`

**Lower-level.** Raw keyed row; selected presentation uses presented_chat_list_row.

Read one hydrated chat-list row for a known group.

### `Marmot::existing_direct_conversation`

**Current.**

Look up the reusable existing direct conversation with `peer_account_id`.

### `Marmot::initialize_chat_read_state`

**Current.**

Establish the unread baseline the first time a user opens a group. Existing kind-9 history remains read; later remote kind-9 messages count until marked visible via `mark_timeline_message_read`.

### `Marmot::mark_timeline_message_read`

**Current.**

Mark a kind-9 timeline message visible/read. Own kind-9 messages can advance the marker too, which clears any earlier unread messages.

### `Marmot::set_chat_manually_unread`

**Current.**

Set or clear a manual unread reminder without moving the durable timeline read marker backwards.

### `Marmot::set_chat_pinned`

**Current.**

Pin or unpin one local chat. Newly pinned chats enter at the top of the manually ordered pinned section.

### `Marmot::set_pinned_chat_order`

**Current.**

Atomically replace the order of the current pinned set. The input must contain every currently pinned group exactly once.

### `Marmot::chat_notification_settings`

**Current.**

Read the current MDK timed/indefinite mute state for one chat.

### `Marmot::set_chat_muted`

**Current.**

Mute one chat until an absolute Unix epoch millisecond timestamp, or indefinitely when `muted_until_ms` is `None`.
Ordinary notification updates stay suppressed, while direct mentions of the receiving account reach subscriptions with `NotificationUpdateFfi.is_mention = true`; blocked senders remain suppressed. Hosts apply their own notification permission and channel settings.

### `Marmot::clear_chat_muted`

**Current.**

Clear either a finite or indefinite MDK chat mute.

</details>

<details>
<summary>commands/chat_window.rs</summary>

### `Marmot::open_chat_list_window`

**Current.**

Bind to one account/view. None defaults to 50; explicit sizes must be 1–100.

### `Marmot::chat_list_ids`

**Current.**

Select all: every chat ID in the view, in display order, including chats beyond the open window. The count is the list length. Use it for "select all" and bulk-action counts instead of the window's rows, which are bounded. While base rows are still being prepared it fails with `ChatPresentationNotReady` rather than returning a partial list; keep the action disabled and retry. The list is a snapshot: keep it as host checkbox state and call `revalidate_chat_list_ids` before acting.

### `Marmot::revalidate_chat_list_ids`

**Current.**

The subset of a host selection still in the view, in the caller's order with duplicates dropped. It only removes: chats that joined the view after the selection was read are never added. IDs are normalized to lowercase hex, and a malformed ID fails the call with `InvalidHex`. Call it right before a bulk action, then run the existing per-chat commands (archive, local delete, leave), which still check their own preconditions; this read does not lock the selection.

### `Marmot::open_chat_list_query_window`

**Current.**

`open_chat_list_window` narrowed by a filter: the same subscription, window policy and commands over the chats a `ChatListViewQueryFfi` matches. The query is a base `view` plus `filter`, a flat node list where node 0 is the root and every other node is the child of exactly one node listed before it; an empty list means no filter. `All`, `Any` and `Not` combine `Condition` leaves (scope, unread, manual unread, mention, pinned, pending leave, disbanding, has draft, pending or failed send, direct or group kind, muted), `GroupIds`, `Text` and `MessageText`; an empty `All` matches every chat in the view and an empty `Any` none. A chat whose kind is still `Unknown` matches neither kind leaf. `Muted` is evaluated at each read, and a window testing it updates when a mute expires, even for a chat it does not show. `Text` matches the title, group name, description or a direct chat's peer profile name as a literal substring after trimming and lowercasing both, like user directory search; localized fallback titles are not searchable and blank text matches nothing. While any chat in the view still has presentation pending, a query with `Text` fails with `ChatPresentationNotReady` (an open window publishes it and retries) instead of returning part of the set. `MessageText` matches chats with a visible message containing the text by the same rule: a chat message or poll question the timeline shows, in its latest edit, not deleted, expired or from a blocked account, and not invalidated unless it is an own send shown as failed. Timeline `search` uses the same rule. It scans message history, so a window refuses it: this call fails with `InvalidChatListQuery` (`MessageTextInWindow`) before any read, and only `chat_list_query_ids` and `revalidate_chat_list_query_ids` accept it. Folder include/exclude lists are ordinary nodes, for example `All[Not(GroupIds(excluded)), Any[GroupIds(included), rule]]`. A malformed node list or a query over 8 levels, 64 nodes, 500 group IDs or 1024 bytes of text fails with `InvalidChatListQuery` before any read; a malformed group ID fails with `InvalidHex`. Use the same query value for the window, `chat_list_query_ids` and `revalidate_chat_list_query_ids` so list, count and selection agree; a query with `MessageText` has no window.

### `Marmot::chat_list_query_ids`

**Current.**

Select all for a filtered query: every chat ID the query matches, in display order, beyond the open window, from the same compiled condition the window pages through. Same readiness and snapshot rules as `chat_list_ids`, and the same query validation as `open_chat_list_query_window`, except that it accepts `MessageText`, whose cost grows with message history. A query with `MessageText` also fails with `ChatPresentationNotReady` while retained deletions and edits are still being backfilled into the timeline.

### `Marmot::revalidate_chat_list_query_ids`

**Current.**

`revalidate_chat_list_ids` for a filtered query: the subset of a host selection that still matches, in the caller's order with duplicates dropped, never adding chats. Call it with the query the selection was read under, right before a bulk action.

### `Marmot::subscribe_account_attention`

**Current.**

Signed-in local/external accounts, independent of any list or active worker.

</details>

<details>
<summary>commands/compromise_warning.rs</summary>

### `Marmot::compromise_warning`

**Current.**

List the account's open compromise warning on this device: each item the user has not seen here, the earliest gathered first. An empty list means no warning is open. An item means someone holding the account's signing key, or a session with its remote signer, published where the account's devices did not: a sign-in answered This wasn't me (`RejectedSignIn`), or a KeyPackage this device found in its own slot that it did not make (`ForeignOwnSlotKeyPackage`, with its `key_package_ref_hex`; only the device that found it warns of it). Later releases add reasons; show one the app does not know as a generic one. The warning gathers this device's rejections and those in its device group's roster, so a rejection made on another device warns here too; rejections already in the first roster this device trusts count as seen. A rejected sign-in leaves the warning once its slot is linked as a device. The app writes the wording, and never says the account's devices stopped them. Read from local state with no network I/O. Always empty unless the host turns device groups on. Refresh on `MarmotEventFfi::CompromiseWarningChanged`, which also fires once each time the account's worker opens, so it may fire with no visible change. Runs on the account worker.

### `Marmot::dismiss_compromise_warning`

**Current.**

Dismiss the compromise warning on this device: everything it gathers now is marked seen here, and it stays closed until a new rejection arrives. Other devices' warnings are unchanged, and a rejection that branch selection drops and brings back stays seen. A refusal is `MarmotKitError::Runtime` whose details read `device group refused: roster_unsupported`, while device groups are off. Raises `CompromiseWarningChanged` when something was marked seen. Runs on the account worker.

</details>

<details>
<summary>commands/conversation_window.rs</summary>

### `Marmot::open_conversation_window`

**Current.**

Open first unread/latest or an explicit message. No implicit mark-read. Zero timeout uses 30 seconds; timeout/cancellation abandons the opening. Mode Message requires a message id; other modes reject one. None rows uses 50.

### `Marmot::send_message_draft`

**Current.**

Submit exactly the selected draft revision. Prepared media must match its descriptors. Clears only on durable acceptance; do not clear again in the host after delivery.

### `Marmot::selected_message_draft`

**Current.**

Descriptor-only selected draft with an opaque store/group-scoped revision.

### `Marmot::clear_message_draft_if_revision`

**Current.**

Clear only the exact revision the caller observed; handle conflict instead of erasing a newer draft.

### `Marmot::save_message_draft_if_revision`

**Current.**

Save composer state conditional on the observed revision; use the returned result/revision for subsequent edits.

### `Marmot::message_draft_attachment_if_revision`

**Current.**

Read only the requested local attachment, rejecting a changed selected draft. A file-backed attachment is `InvalidMessageDraft`: read it with `read_message_draft_attachment`.

### `Marmot::save_message_draft_inputs_if_revision`

**Current.** **C:** `marmot_save_message_draft_inputs_if_revision`.

The save to use once a draft can hold file-backed attachments. Each input is a new inline body (`Inline`), an attachment the draft already holds, kept by id (`Retained`) without reading or copying its body, so typing a caption next to a large video stays cheap, or the id of an attachment to remove (`Removed`). Every attachment the draft holds that the save does not name stays: a save from a composer that has not loaded the draft, or that races a staging copy, never drops a file it did not know about. `Removed` deletes an attachment, and its staged file before this returns; removing an id the draft does not hold changes nothing. An `Inline` input with an id the draft holds replaces that attachment's body, releasing a staged file it had. The named attachments come first, in the inputs' order, then the kept ones in their stored order. A retained id the draft does not hold is `InvalidMessageDraft`; a stale revision is `MessageDraftRevisionConflict`. `save_message_draft_if_revision` remains for drafts with inline bodies only, and still replaces the whole attachment list.

### `Marmot::stage_message_draft_attachment_file`

**Current.** **C:** `marmot_stage_message_draft_attachment_file`.

Add a large attachment to a draft from a host file instead of a byte array. The file (a regular file, not a symlink; `expected_size` must match when set, and it must not change while it is read) is copied with bounded buffers into the account's encrypted media store, and the draft owns that copy: it survives text saves and restarts and is released when the draft drops it, is cleared or is sent. The host may delete its own file once this returns. Attachments may reach the encrypted-media blob limit (the limit less the 16-byte AEAD tag), with at most 64 per draft and the draft within one upload batch (`max_file_media_ciphertext_bytes()`). These limits, a duplicate id and a copy the disk cannot hold beyond the attachment policy's `disk_reserve` (`StorageFull`) are refused before anything is copied. The media type is stored in its canonical form (lowercase, parameters dropped), as the upload will describe it; a type with no canonical form is refused before copying too. `revision` must be current when the call starts; text saves made while the file copies do not lose it, but the next save with an older revision conflicts, so reload with `selected_message_draft` after this returns. A draft cleared, deleted or sent during the copy stays so, and the copy is discarded with `MessageDraftRevisionConflict`. `control` reports copied bytes and cancels; a cancelled or failed copy leaves no file and no change to the draft.

### `Marmot::read_message_draft_attachment`

**Current.** **C:** `marmot_read_message_draft_attachment`.

Read 1..=1048576 bytes at `offset` from one draft attachment, inline or file-backed, for previews and thumbnails without hydrating the whole body. `None` means the draft holds no such attachment; an empty result is the end. Every call rechecks `revision`, so a draft edited between chunks conflicts and the host must restart from a fresh revision; for long reads or OS surfaces that need a file, prefer `open_message_draft_attachment_handoff`. `message_draft_attachment_if_revision` refuses file-backed attachments.

### `Marmot::open_message_draft_attachment_handoff`

**Current.** **C:** `marmot_open_message_draft_attachment_handoff`.

`open_attachment_handoff` for a draft attachment: writes a plaintext copy under the account's `handoff/` directory for an OS surface that needs a real file (AVFoundation thumbnails, playback, share sheets) and lends it under a lease. The revision is checked once, before the copy; later draft edits neither interrupt it nor revoke the lease. `None` means the draft holds no such attachment. Release the copy with `release_attachment_handoff`. `StorageFull`, the `control` contract and the cancellation rules are those of `open_attachment_handoff`: cancel only through `control`, never by cancelling the awaiting task.

</details>

<details>
<summary>commands/device_link.rs</summary>

### `Marmot::cancel_device_link`

**Current.**

On the new device, request cancellation of the link. This does not guarantee notification of the other device: cancellation while waiting in `Joining` can end locally without sending a cancellation message. Before an authenticated Welcome is admitted, successful cancellation ends `new_device` as `Ended { reason: Cancelled }`. Cancelling while still waiting in `Joining` first withdraws this device's Welcome expectation; if withdrawal fails, the call returns an error and the current worker retries while that in-memory link remains active. After restart, a failed cancellation is not durably retried; its stored Welcome wait can remain active until its deadline. While that wait remains, a new ordinary link can reach confirmation and then end as `LinkFailed`. Cancellation does not undo an already-admitted Welcome: an ordinary link can resolve as `Linked`; for a move, inspect `moves` for the durable outcome. Refused as `MarmotKitError::Runtime` with details `device group refused: pairing_unsupported` with device groups off, or `device group refused: no_link_in_progress` when no link is in progress.

### `Marmot::confirm_device_link_match`

**Current.**

On the new device, record that the user says both screens show the same emoji. `new_device` moves to `WaitingForOtherDevice` until the other device's user chooses Link device, then `Joining` while that device adds this one, then `Linked` once its Welcome arrives. This device joins only through a Welcome into the device group the other device's verified confirmation named, sent by the leaf that confirmation named, and only while the link waits for it. A mismatch is the user's to report: cancel instead. Refused with `no_link_in_progress` when there is no link to confirm, and ends the link with a reason when the exchange fails a check or time ran out.

### `Marmot::decline_device_link`

**Current.**

On a device already signed in, Not now for the prompt `prompt_id`: the prompt goes and the new device's link ends with `CancelledElsewhere`. Refused with `unknown_prompt` for a stale prompt.

### `Marmot::device_link_snapshot`

**Current.**

Current linking and durable move progress: `new_device` while this device asked to be linked, `prompts` for the sign-ins it can link, newest last, and `moves` as described in [move guidance](README.md#moving-this-device-to-another-device-group). Each prompt's state says what to show: `Preparing` while the sign-in's KeyPackage is checked, `Comparing` with the code, `CompetingRequests`, `RateLimited` until `retry_at`, `CannotLink` with what its client lacks, `TooManyDevices`, `Linking`, `Linked`, `AddedElsewhere` ("<device_label> was added by <added_by_label>") or `Ended` with a reason. Re-read on `MarmotEventFfi::DeviceLinkChanged`, which also fires each time the account's worker opens or reconnects; unconfirmed comparisons end because their secrets are memory-only, while admitted native/move work keeps its durable owner. Refused with device groups off (`pairing_unsupported`). Runs on the account worker and sends what linking owes. The snapshot's `chat_progress` gives the approver's remaining Adds or, on the new device, the remaining local joins among the reported chats. An absent entry means unavailable.

### `Marmot::dismiss_device_group_move_sibling`

End one local old-sibling recognition hint from `device_link_snapshot().moves`. Pass its opaque `move_id` and the
hint's `slot_id_hex`; this neither links, removes nor trusts the sibling. The returned snapshot reflects the hint.
Refused when device linking is disabled or the move/sibling is unknown. Refresh on `DeviceLinkChanged`; see
[move guidance](README.md#moving-this-device-to-another-device-group).

### `Marmot::link_device`

**Current.**

On a device already signed in, Link device for the prompt `prompt_id`, offered while its state is `Comparing`. `label` is the name the user gave the new device: not blank, at most 64 bytes (`label_invalid`). Offer `add_to_all_chats` and `bring_history` as toggles, both on by default. The prompt moves to `Linking` until the new device's confirmation verifies; then this device creates the account's device group on a first link, or adds the new device to the one it trusts, in one commit that also writes its roster entry. That commit is the approval. Its Welcome goes out only once relays confirm the commit, and the prompt remains `Linking` until the new device's first selected own change is present; a Welcome not taken by relays remains under its existing bounded delivery owner. A commit whose publish is retried keeps the prompt `Linking`. A device group that is still settling makes this device retry while the new device waits for its Welcome. A commit that rolls back, or a link not confirmed before the new device stops waiting, ends the prompt with `LinkFailed`. Refused with `unknown_prompt` for a stale prompt, including one from before the client reopened, `link_unavailable` while more than one sign-in competes or the code is not shown, `device_already_linked`, `sign_in_rejected` when its sign-in was rejected after the prompt appeared (the prompt then ends `Rejected`), or `too_many_devices` at 20 devices (remove one first).

### `Marmot::reset_device_group_for_repair`

**Current.**

After explicit user confirmation, discard only this device's quiet trusted hidden device-group copy before fresh code pairing. Keeps ordinary chat data, drafts/settings, account credentials and stable slot; abandons old link-bound preparations, while shared values and security decisions retain their ordinary synchronization rules. This sends no removal, authenticates no device and repairs no chat membership. Active pairing/Move or unsettled native work returns `device_group_busy` without a deadline; no trusted copy returns `no_device_group`. An unlinked device cannot bypass removal. Cancellation after reset restores nothing, while a fresh already-confirmed link keeps its ordinary durable Welcome wait. Duplicate membership, rejection and capacity can still refuse the new link. Refused with device groups off; see [the shared reset contract](README.md#explicit-local-device-group-reset-before-fresh-pairing).

### `Marmot::start_device_link`

**Current.**

Ask a device of this account already signed in to link this one, returning its current comparison state. If this device already trusts a different device group, the same flow moves only this device; keep showing the old trust until `snapshot.moves` reports Made, as described in [move guidance](README.md#moving-this-device-to-another-device-group). The request names this device's published KeyPackage, never one this device already joined a group by, so publish one first, and again after such a join (`key_package_not_published`). `new_device` starts at `WaitingForAnswer`: ask the user to open the app on a device already signed in. Once one answers it moves to `Comparing` with the seven emoji both screens show, each with an English `description` for screen readers; offer "They match" (`confirm_device_link_match`) and cancel (`cancel_device_link`). Refresh on `MarmotEventFfi::DeviceLinkChanged`. Refused with `MarmotKitError::Runtime` (details `device group refused: <reason>`) while a link is in progress (`pairing_in_progress`) or device groups are off (`pairing_unsupported`). Runs on the account worker and sends one gift-wrapped request to the account's relays.

</details>

<details>
<summary>commands/directory.rs</summary>

### `Marmot::display_name`

**Current.**

Best-effort cached display name for an account id. Returns the Nostr kind:0 display_name/name when the runtime has projected one, or the local account label if the id refers to one of our own accounts. `None` when nothing is known yet — call `refresh_profile` to fetch.

### `Marmot::npub`

**Current.**

Convert a hex account id (Nostr public key) into its `npub…` bech32 form for display. `None` if the hex isn't a valid public key.

### `Marmot::account_id_hex`

**Current.**

Normalize a public-key reference (hex, `npub`, `nostr:npub`, `nprofile`, `nostr:nprofile`, or a `marmot://profile/` link) to canonical hex. `None` if it isn't a valid public identity reference. nprofile relay hints are discarded. Duplicate type-0 TLV entries keep the first key. After wrapper normalization, the nprofile fallback rejects encoded tokens longer than 1023 UTF-8 bytes; a valid 1023-byte token still decodes when wrapped. Used to resolve a scanned or deep-linked mention back to the account id the rest of the API expects.

### `Marmot::default_profile_pseudonym`

**Current.**

Deterministic cosmetic display name for a canonical hex account id.

### `Marmot::random_profile_pseudonym`

**Current.**

Random cosmetic display name from the shared wordlists.

### `Marmot::parse_markdown`

**Current.**

Parse plaintext message content into the same Markdown AST returned on message and timeline records. Useful for draft previews and host-side fallback rendering.

Local-time timestamps are `MarkdownInlineFfi::Timestamp { unix_seconds: i64, style:
MarkdownTimestampStyleFfi }`, preserving signed seconds and a typed style rather
than formatted text. The nine styles are `ShortTime`, `LongTime`, `ShortDate`,
`LongDate`, `ShortDateTime` (the parser's default), `LongDateTime`, `CompactDateTime`,
`CompactDateTimeSeconds` and `Relative`. Invalid syntax remains literal text.
Hosts format using the device locale/timezone at render time, refresh after
locale/timezone/clock changes and resume, and refresh visible `Relative` nodes as
time passes. See [Markdown rendering](README.md#markdown-rendering) for the style
mapping and optional absolute-time tooltip/accessibility guidance.

### `Marmot::user_profile`

**Current.**

Full cached Nostr kind:0 profile for an account id (name, display name, about, picture, nip05, lud16), if the runtime has one projected. The local account's own profile is cached immediately after `publish_user_profile` from the submitted value, without reparsing it. Other accounts' profiles populate via `refresh_profile` / `refresh_directory` and are sanitized on ingest: `about` keeps normalized LF line breaks, and every other known string stays single-line. Tab and other controls (NUL, ESC, BEL, DEL, C1) are removed. A cached bio flattened by an older build stays until a newer event replaces it; an equal timestamp does not. Returns `None` when nothing is cached yet.

### `Marmot::cached_identity_projections`

**Current.**

Bounded local cached-identity page for many account IDs.

### `Marmot::follow_availability_page`

**Current.**

Read the selected account's direct follows from its encrypted cache without networking. Results use canonical account ids in keyset order. Pass `next_cursor` as `after` for the next page; `limit` clamps to 1 through 100. Keep this synchronous SQLCipher read off the UI thread. `ready` means a current compatible KeyPackage has not expired, not that a particular client is installed. `unknown` covers missing, stale, incomplete, malformed, replaced, and expired results. A completed clean, deleted, or obsolete miss is `not_found` for 15 minutes.

### `Marmot::refresh_follow_availability`

**Current.**

Refresh at most 100 direct follows with four concurrent target lookups, a 10-second target deadline, a five-minute overall deadline, and at most two relay fetches per target. Results persist per target and can be paged while the call runs. Concurrent calls share one refresh and completed refreshes have a 60-second cadence. The returned aggregate distinguishes complete, partial, cancelled, throttled, and failed outcomes without exposing followed identities in telemetry.

### `Marmot::follow_availability_status`

**Current.**

Return the current or last direct-follow refresh status for this account, including its operation id, phase, aggregate result counts, and truncation flag. Poll this method while a refresh runs; page the projection for per-account states. An account with no refresh returns `Idle` without an operation id.

### `Marmot::cancel_follow_availability`

**Current.**

Cancel the running refresh identified by `operation_id`. Returns `false` when that operation already finished or a newer operation replaced it, so a stale status cannot cancel newer work. Committed results remain readable. Use the operation id from `follow_availability_status` or the refresh result.

### `Marmot::user_profile_website`

**Current.**

Cached Nostr kind:0 `website` metadata for an account id, when it is a string. The generic profile record intentionally exposes the fields the host can publish; this read-only accessor preserves arbitrary kind:0 metadata while still making the standard website field available to profile presentation surfaces.

### `Marmot::refresh_profile`

**Current.**

Fetch and cache an account's own Nostr kind:0 profile from `relays`. After this resolves, `user_profile` / `display_name` return the freshly-fetched metadata (name, picture, etc.) for that account.

### `Marmot::user_relay_lists`

**Current.**

Cached NIP-65 and inbox relay lists for any account id — no network. An account with nothing cached yet returns an empty status with both kinds in `missing` rather than erroring; call `refresh_user_relay_lists` to fetch.

### `Marmot::refresh_user_relay_lists`

**Current.**

Fetch an account's published NIP-65 and inbox relay lists from `relays`, updating the cache. An account with nothing published reports both kinds in `missing` rather than erroring.

### `Marmot::search_cached_users`

**Current.**

Search public identities cached through any connected account, without network or group-membership work. Follow flags refer only to the selected searcher. Call off the UI thread; zero limit returns no rows.

### `Marmot::search_users`

**Current.**

Stream cached public identities across accounts, then independent provider and graph results. The radius window bounds known social distances; cached/provider identities without a known distance remain discoverable. Those identities can recur when paging radii: deduplicate by account id across pages as well as within each subscription.

</details>

<details>
<summary>commands/draft.rs</summary>

### `Marmot::message_drafts`

**Current.**

Metadata-only saved composer drafts for an account, newest-updated first. Attachment plaintext is intentionally omitted from this list; call `messageDraft` when restoring one selected composer. Hosts must delete empty or sent drafts; deleting a group also removes its draft.

### `Marmot::message_draft`

**Compatibility.** Prefer selected_message_draft for the revisioned composer.

The saved composer draft for an account and MLS group, if one exists.

### `Marmot::save_message_draft`

**Compatibility.** Prefer save_message_draft_if_revision for concurrent composer safety.

Upsert a composer draft into the account's encrypted SQLCipher store.

### `Marmot::delete_message_draft`

**Compatibility.** Prefer clear_message_draft_if_revision for concurrent composer safety.

Delete a saved composer draft. This is a no-op when no draft exists.

</details>

<details>
<summary>commands/group.rs</summary>

### `Marmot::prewarm_group_member_key_packages`

**Current.**

Resolve the current composition roster before Create is tapped. The result is aggregate-only; no package is reserved or consumed, and the later create call discovers routes and fetches packages again.

### `Marmot::start_direct_conversation`

**Current.** Recommended for an explicit direct-chat start.

Accepts a hex or npub peer identity. The account worker serializes lookup and creation, reusing the deterministic local direct-conversation selection or creating an unnamed group with both accounts as founding admins. Reuse preserves existing roles without an admin-policy commit.

The returned string encodes the canonical opaque MLS group id as hex. Success confirms local creation or reuse, not Welcome delivery. Retained Welcome delivery continues independently. Cancellation detaches the wait without cancelling admitted work. Retry after response loss or delayed projection recovers and reuses the canonical engine group. If a matching canonical group is eligible for reuse but cannot hydrate, retry returns an error rather than creating another group. Removed and disbanded copies do not block a fresh start. Same-account concurrent starts return one local group. Simultaneous starts by different accounts can produce two groups, each with both accounts as admins.

No immutable cross-client DM provenance exists, so legacy and generic groups keep their authoritative roles. An unnamed two-member roster does not authorize automatic repair. Generic creator-only clients remain interoperable but produce asymmetric groups until they adopt this operation. A non-admin recipient cannot self-promote.

### `Marmot::start_direct_conversation_with_options`

**Current.** Use when the new direct chat should found with a disappearing-message duration, such as the user's default.

`start_direct_conversation` with founding options. `DirectConversationOptionsFfi.disappearingMessageSecs` uses the same values as `CreateGroupOptionsFfi`: `0` disables expiry and adds no founding requirement. A nonzero value is written into the founding MLS state and Welcome, so the recipient joins with the same duration and no follow-up retention commit is sent. Do not emulate this with `updateMessageRetention` after the start: a reused chat would have its policy overwritten.

Options apply only when the call creates the group. Reuse, retry and same-account concurrent starts return the existing canonical group with its founding duration and roles, even when they propose a different duration. A nonzero duration requires message retention support, as in `create_group_with_options`.

When a lookup finds only KeyPackages incompatible with the chat's founding requirements, it returns `MarmotKitError::IncompatibleKeyPackage` (`MARMOT_STATUS_INCOMPATIBLE_KEY_PACKAGE` in C) if relay-list discovery, the KeyPackage reads and one more read all completed. KeyPackage reads return only the deletion requests tagged with the KeyPackage kind, so on every relay they covered the lookup also asks for a deletion request naming the newest refused KeyPackage or its `d` slot. If it finds one, that KeyPackage is dropped and the recipient's remaining KeyPackages decide the result. If any of the three did not complete, it returns `MarmotKitError::DirectoryLookupIncomplete`. Either refusal creates no chat. The lookup is bounded: complete discovery requires reading relay lists on the configured directory relays and on every eligible outbox the newest list names. KeyPackage reads cover those outboxes, a tied list's outboxes when one read admits them, and at most eight more configured directory relays. A relay that a list names twice, or with and without a trailing root slash, is one relay: it is read once and counts once toward a read's limit. A compatible KeyPackage published only elsewhere is not seen.

If the newest list names an eligible outbox not queried for relay lists, finding no usable KeyPackage returns `MarmotKitError::DirectoryLookupIncomplete`, even after a deletion removes the last known slot. Finding no usable KeyPackage also returns this error while this device's journal keeps a publication of the recipient in a `d` slot that the lookup did not account for: its reads returned neither that publication nor a newer one in the same slot (not counting one dated past the clock-skew allowance), the journal knows no newer one there either, and no deletion request covers it. The journal keeps a publication for 30 days and five minutes from its creation and holds a bounded number of publications and deletion requests. A publication it has dropped no longer blocks a verdict, and a deletion request it has dropped no longer accounts for one. A relay list published in the same second as the recipient's and naming other relays never supports an incompatibility. If a tied list names an eligible outbox that no KeyPackage read covered, the start reports an incomplete lookup rather than a missing KeyPackage. This can happen when the two lists together name more outboxes than one read admits. The same rules apply to `start_direct_conversation`.

### `Marmot::create_group`

**Current.**

Create an MLS group with `name` and the available members (`npub` or hex account id). Returns an optional `group_id_hex` and ordered per-account outcomes. A nonempty request with no available members returns no group id and creates no group; empty member input still creates a creator-only group. A present id confirms local canonicalization, not Welcome delivery. `WelcomeDeliveryPending` is a delivery-failure signal, not an acknowledgement. Subscribe before creation and/or query `pending_welcome_deliveries` afterward before presenting invitation success.

### `Marmot::create_group_with_options`

**Current.**

Create a group with founding options, returning the same optional group id and ordered member outcomes as `create_group`. A nonzero retention value is written into the founding MLS state and Welcome; it does not emit a follow-up retention commit or publication.

### `Marmot::create_group_detailed`

**Current.**

Return ordered member outcomes and an optional created group containing the exact durable chat-list row available at the response boundary. `created` is absent when a nonempty request has no available members.

### `Marmot::create_group_with_options_detailed`

**Current.**

Create a group with founding options, returning ordered member outcomes and an optional created group with the durable chat-list row. No group is created when a nonempty request has no available members.

### `Marmot::create_group_with_initial_image`

**Current.**

Create a group with an optional initial avatar, returning the same optional group id and ordered member outcomes as `create_group`. MDK prefers an encrypted Blossom image and uses `source_url` only when the selected founding members do not all support that component but do support URL avatars.

### `Marmot::stage_prepared_group_image`

**Current.**

Validate and durably encrypt a founding image without performing any network transfer. The opaque id survives process restart; keys, ciphertext, and the content hash stay inside MDK's SQLCipher database.

### `Marmot::upload_prepared_group_image`

**Current.**

Upload a staged founding image. A transfer failure is returned as an error after its failed status is durably recorded, and can be retried with the same id; an already uploaded id performs no duplicate HTTP transfer.

### `Marmot::prepared_group_image_status`

**Current.**

Read one prepared group-image operation status.

### `Marmot::prepared_group_images`

**Current.**

List prepared group-image operations.

### `Marmot::create_group_with_prepared_initial_image`

**Current.**

Create with an already-uploaded `upload_id`; the image component is present in epoch-zero metadata and no Blossom request occurs on this call. Returns an optional group id and ordered member outcomes. Reusing a consumed id returns its original canonical group and stored selection report, not newly resolved input. A legacy, corrupt, or unsupported report returns `CreatedGroupMemberReportUnavailable` with the canonical group id rather than inventing outcomes or creating a duplicate.

### `Marmot::create_group_with_initial_image_detailed`

**Current.**

Create a group with an initial image, returning ordered member outcomes and an optional created group with the durable chat-list row. No group is created when a nonempty request has no available members.

### `Marmot::normalize_member_ref`

**Current.**

Normalize a member reference for group-management UI. Accepts hex, `npub`, `nostr:npub...`, `nprofile`, `nostr:nprofile...`, and `marmot://profile/...` references. nprofile relay hints are discarded and never used for routing or membership authorization. Duplicate type-0 TLV entries keep the first key. After wrapper normalization, the nprofile fallback rejects encoded tokens longer than 1023 UTF-8 bytes; a valid 1023-byte token still decodes when wrapped.

### `Marmot::group_members`

**Current.**

Membership roster for `group_id_hex`: one row per member account, with how many of its devices are in the group (`device_count`). An account with several devices is one member.

### `Marmot::group_member_ids_page`

**Current.**

Identifier-only rosters for a bounded page of groups. Each member account appears once, however many devices it has in the group.

### `Marmot::group_details`

**Current.**

Group plus enriched member rows for detail screens, one per member account with its `device_count`. Admin counts and last-admin checks therefore count accounts.

### `Marmot::group_conversation_snapshot`

**Current.**

Group details and management state captured for conversation loading in one worker command. The authoritative group record, roster, and MLS state share one session/snapshot frontier; management state is derived from those exact returned details without another await.

### `Marmot::group_roster`

**Current.**

Lightweight membership roster projection for membership screens: one entry per member account with its `device_count`, and `member_count` counts accounts.

### `Marmot::group_management_state`

**Current.**

Current caller permissions plus per-member action availability.

### `Marmot::enable_group_disbanding`

**Current.**

Install lifecycle-v1 and require it in one admin Commit.

### `Marmot::account_devices_activation`

**Current.**

Whether the account can turn on account-devices in the group now, so its own devices can later add and remove each other there without an admin. Ask before offering `enable_account_devices`, and show the reason when it is not `Eligible`. The answer is about the whole group and never names the members or devices that hold it back; a non-admin only learns `NotAdmin`. It is advisory: `enable_account_devices` checks again.

### `Marmot::enable_account_devices`

**Current.**

Turn on account-devices (`marmot.group.account-devices.v1`) in one admin Commit. Call it only when the user asks: MDK never turns it on by itself, and a group can never turn it off. Refused before anything is published with `AccountDevicesActivationRefused`, carrying the same aggregate reason, unless `account_devices_activation` would answer `Eligible`.

### `Marmot::disband_group`

**Current.**

Durably accept an irreversible disband request. Completion is observed through normal group state updates after bounded convergence.

### `Marmot::acknowledge_disband_failure`

**Current.**

Acknowledge the recorded group-disband failure.

### `Marmot::invite_members`

**Current.**

Invite the available accounts in `member_refs` into one Commit, returning ordered per-account outcomes. `summary` is absent for nonempty all-unavailable input; no Commit is created. Selection is not Welcome delivery. Empty input, native membership-edit refusals, authorization, and global runtime failures remain errors.

### `Marmot::invite_members_with_initial_admins`

**Current.**

Invite available accounts in `member_refs` and grant admin to selected accounts named in `initial_admin_refs` in the same Commit. Every initial admin must be a requested invitee; unavailable invitees receive no role. Returns the same optional summary and ordered member outcomes as `invite_members`.

### `Marmot::remove_members`

**Current.**

Request removal of selected members; use the detailed variant for operation outcomes.

### `Marmot::leave_group`

**Current.**

Queue leaving a group; retained local history is separate from membership. An admin gets `AdminCannotSelfRemove` until `self_demote_admin` (`requires_self_demote_before_leave`); with device groups on (the default), core demotes a nonlast admin itself.

### `Marmot::cancel_leave`

**Current.**

Cancel this account's blocked leave, on this device only. A leave is blocked when the selected branch makes the account the group's last active admin, so no Commit can finish it; the chat keeps reading as leaving (`leave_request_pending`) with `leave_blocked` set, and hosts offer Cancel while `GroupManagementStateFfi::can_cancel_leave` holds. Cancel makes the chat joined again and the account can send. While the group is still settling, or in any other state, it returns `LeaveNotBlocked`; read the state again before offering Cancel. With device groups on, it leaves the shared Decline alone, so each linked device cancels its own leave.

### `Marmot::forget_group_local`

**Current.**

Reset a group on this account-device, without sending an MLS leave or disband. Erases local history and protocol state, cancels group work, and rejects old welcomes. A valid Welcome whose authenticated inner creation time is strictly newer than the reset's Unix-second cutoff can join the same group with fresh state. Equal-second invitations are rejected; receipt time and outer wrapper time do not establish freshness. Hosts should close the group's UI subscriptions and clear their media caches. Returns true when resetting, false when already awaiting a fresh Welcome.

### `Marmot::delete_group_local`

**Current.**

Delete this group's local app data without performing an MLS leave. The caller should cancel any active UI subscriptions for the group before invoking the wipe. The runtime removes the active transport route, then transactionally drops the chat-list/account projection, plaintext app events, timeline rows, push-token rows, and cached encrypted-media epoch secrets. MLS/OpenMLS group state is left intact; a future fresh group delivery can recreate a local chat row. Returns true if any local rows or a live route were removed.

### `Marmot::group_app_component`

**Current.**

Read one application-owned group component from local committed MLS state. `None` is absence; a record with empty `data` is present empty state. `component_id` must be at or above `APP_OWNED_APP_COMPONENT_ID_START` (`0xf000`), otherwise `InvalidAppComponent` is returned; use the typed profile, image, retention and policy APIs for protocol settings. The protocol registry allocates upward from `0x8001`, so an id picked merely because it is unassigned today can be taken by a later registry entry — applications allocate inside the application range instead, and version their own payloads. Reads are serialized through the account worker and may wait behind an in-flight mutation, so refresh after group events (including `EpochChanged` and convergence) and after local updates.

### `Marmot::update_app_component`

**Current.**

Replace one optional application-owned component through an admin-authorized MLS commit. Ids below `APP_OWNED_APP_COMPONENT_ID_START` (`0xf000`), components the group requires, and `data` longer than `APP_COMPONENT_DATA_MAX_LEN` (4096 bytes) are rejected with `InvalidAppComponent`. Before staging, the engine rejects updates whose resulting application-owned state exceeds 32 entries or 8192 encoded bytes (including entry ids and TLS payload length prefixes). Replacements count once; empty values still occupy a slot. The value is re-encoded into the GroupContext of every later commit and into every Welcome, so this is a settings channel rather than a blob store. Empty `data` stores an empty payload; it does not remove the component. The value survives message expiry and reaches newly invited members in their Welcome without sharing earlier application-message history, and unsupported clients preserve the bytes without interpreting them. Publication and convergence semantics match other group mutations: handle publication uncertainty and `GroupChangeSuperseded` rather than assuming a local change wins every later concurrent commit. The runtime does not retry an application's desired value.

### `Marmot::update_message_retention`

**Current.**

Set the per-group disappearing-message retention, wrapping the engine's `update_message_retention`. `disappearing_message_secs` of `0` disables expiry; any positive value is the retention window in seconds. Thin passthrough over the already-public engine API (mdk#571).

### `Marmot::acknowledge_group_catching_up`

**Current.**

Call only after a group change failed with `GroupCatchingUp` and the user chose to continue anyway. The group may have moved past this device, so the change can split the group for everyone (mdk#2258). Records the acknowledgement for the group at the device's current epoch, then retry the original change. It admits exactly one change attempt and is consumed even if that attempt fails, so a different change asks again. It is not persisted, so a restarted app asks again too. Returns `false`, recording nothing, when the group is not catching up. It is a separate call rather than a flag on every group-change method, and it is distinct from `dismiss_history_notice`, which accepts missing history, not fork risk. Runs on the account worker; no network I/O.

### `Marmot::acknowledge_group_commit_undelivered`

**Current.**

Call only after a group change failed with `GroupCommitUndelivered` and the user chose to continue anyway. A change of yours confirmed on its first relay acknowledgement but some group relays have not accepted it, or a group relay refused it for good, so members who read only those relays may not have it, or the new change built on it (mdk#2255, mdk#2333). Dismisses every relay refusal in the group for good: `group_commit_delivery` stops listing them and they no longer gate, across restarts too. It also records the acknowledgement for the changes owed or refused now; retry the original change. That admits exactly one change attempt and is consumed even if that attempt fails, so a different change asks again, and it is not persisted. A change that starts gating afterwards, such as a new refusal, asks again. Returns `false`, recording nothing, when no relay is owed or has refused a change of yours. Distinct from `acknowledge_group_catching_up`; a change can need both. Hosts can also call it from a "dismiss" action on the refusal warning. Runs on the account worker; no network I/O.

### `Marmot::group_commit_delivery`

**Current.**

Returns the group's oldest change of yours that a group relay refused, until the user acknowledges it, or else the oldest change some group relays have not accepted yet; `None` once no relay is owed a change of yours and every relay refusal has been acknowledged (mdk#2255, mdk#2333). `owed_relay_urls` lists the relays MDK is still retrying with the exact event. `refused_relays` lists the relays that refused the change for good, each with its `cause`: `TooLarge` (the relay's size answer, its known limit, or the 64 KiB commit floor at a relay of unknown limit; `size_class` when known) or `Rejected` (any other final answer). MDK will not deliver it there, and members who read only those relays may not have it; a refusal never says the relay lacks the change. Say, for example, "relay X refused a change of yours: too large". `since` is when the first relay accepted the change, in Unix seconds. A newer change can be owed to other relays as well. Both are reported immediately, so use it to show the warning proactively. A refusal makes group changes fail with `GroupCommitUndelivered` at once, until acknowledged. With only owed relays, `Some` alone does not mean the next change fails: group changes fail only once `since` is two minutes old, because a healthy relay cut off at the first acknowledgement is retried after 30 seconds. What a host can offer: proceed (`acknowledge_group_commit_undelivered`), or ask an admin to change the group's relays. No event announces delivery completing, so poll while the indicator is visible. Local read on the account worker; no network I/O.

### `Marmot::group_pending_commit`

**Current.**

Returns the group's own commit that has not confirmed yet, or `None` (mdk#2332). The group takes one commit at a time, so while this one is pending, group changes fail with `GroupCommitPending`, which wins over `GroupCatchingUp` and `GroupCommitUndelivered`; disbanding and an admin's leave are still accepted. Messages still send. The record names the commit by `commit_id_hex`, the change it carries by `intent_kind` (plus `queued_intent_id_hex` for a queued one; both absent for a commit MDK made on its own), and `first_attempt_at` (Unix seconds, absent before any attempt). `Sending` covers its first ten minutes, and any time no relay may hold it. `Stuck` means ten minutes have passed, some relay may hold it, and none has acknowledged it: MDK keeps resending it and reading it back, and never gives it up, because members may have seen it. `unconfirmed_relay_urls` may hold it without acknowledging, `owed_relay_urls` never received it, and `refused_relays` gave a final latest answer with its cause; a relay refusing a later attempt can stay unconfirmed from an earlier one. A pending commit ends by confirming, which no event announces, or by being given up, which `group_changes_not_delivered` reports for a change of yours. Poll while showing it. See [A group change still being sent](README.md#a-group-change-still-being-sent). Local read on the account worker; no network I/O.

### `Marmot::group_changes_not_delivered`

**Current.**

Returns the group's changes of yours that were not applied, oldest first (mdk#2332). Each one's call answered `CompletionUnknown` (a direct change) or `AcceptedPending` (a queued one), and MDK later gave its commit up: no relay received it (`not_delivered`), it fits none of the group's relays (`event_too_large`), or every relay refused it (`refused`). Nothing reached members and MDK never sends it again; the user may make the change again. A record carries the group, the change's `intent_kind`, the `reason` and `at` (Unix seconds), and names the change only by `commit_id_hex` (plus `queued_intent_id_hex` for a queued one): a direct change's send result carries no id, so say which kind of change failed, in which group, and when. A record stays across restarts and later changes until `acknowledge_change_not_delivered`. `GroupChangeNotDelivered` and `QueuedIntentRefused` events only notify, so read this on start. A change rolled back inside its own call is that call's error and is never recorded, nor is one MDK makes on its own, nor a direct change staged by an earlier MDK release and given up after the upgrade: an empty list does not cover those. See [Group changes that were not applied](README.md#group-changes-that-were-not-applied). Local read on the account worker; no network I/O.

### `Marmot::acknowledge_change_not_delivered`

**Current.**

Delete one record of `group_changes_not_delivered` by its `commit_id_hex` once the user has seen it (mdk#2332). Returns `false`, changing nothing, when the group holds no such record, so a repeated call is harmless. A malformed id is an error. Nothing else clears a record except removing the group's local state. Local write on the account worker; no network I/O.

### `Marmot::pending_welcome_deliveries`

**Current.**

Return the account's retained Welcome repair handles in oldest-first order after a locally canonical create or confirmed Add. This is a local account-worker read, not a new invitation or network retry. `size_class` explains an observed all-target refusal; earlier legacy exposure can be unknown after a crash or expired bookkeeping. Neither a present class nor None proves delivery or non-delivery; None means Unknown, including legacy rows or a later coarse legacy retry. A specific cause can disappear while the same debt remains. `recorded_at` is the local repair-index timestamp in Unix seconds, not proof that the recipient joined. The pending event stays once per process/Welcome; re-read this query for later causes. Use the matching regenerated bindings/native library. See [Welcome delivery and compatibility](README.md#undelivered-welcomes).

### `Marmot::invite_deliveries`

Whether each of the account's invites reached the invited account's inbox relays (mdk#1706): one `InviteDeliveryFfi` per group and invited account, as its newest invite left it, for `group_id_hex` or every group when `None`. `RelayAccepted` means a relay stored the Welcome, not that the recipient received it or joined; an account reads `RelayAccepted` once any of its devices' Welcomes was stored, so show `accepted_device_count` of `device_count`. A local account-worker read of durable records: it answers after a restart and for a group not loaded yet, and sends nothing. `InviteDeliveryChanged` reports each change of state. Relays appear only as counts. A Welcome no relay acknowledged by its delivery deadline (7 days after it was staged with the invite, or its KeyPackage's expiry if sooner) reads `Undeliverable` with its latest attempt's problem, and is never sent again, whatever the device clock later reads. Only invites sent after this device upgraded are listed; an older Welcome stays in `pending_welcome_deliveries` until its delivery deadline. A Welcome whose deadline passes while the app is closed is announced once, on the next start, while its invite is still listed. Use the matching regenerated bindings/native library. See [Invite delivery](README.md#invite-delivery).

### `Marmot::group_recovery_status`

**Current.**

Re-read on GroupStateUpdated; display uncertainty separately from whether the user accepted the original invitation. `history_may_be_incomplete` and `history_notice_ids` report recovery parked on this group's own history; account-wide occurrences are listed only by `history_notices`, and each id can be passed to `dismiss_history_notice`.

### `Marmot::confirm_group_rejoin`

**Current.**

Call only after explicit user consent to replace the active copy. Show the offer's authenticated inviter and pass its exact id and state token.

### `Marmot::decline_group_rejoin`

**Current.**

Decline a proposed recovery rejoin.

### `Marmot::accept_group_invite`

**Current.**

Accept a pending group invitation.

### `Marmot::decline_group_invite`

**Current.**

Decline a pending group invitation. An invitee the invite made an admin gets `AdminCannotSelfRemove` until `self_demote_admin` (`requires_self_demote_before_leave`), unless device groups are on (the default).

### `Marmot::update_group_profile`

**Current.**

Update the group name and description.

### `Marmot::update_group_image`

**Current.**

Encrypt and upload a group avatar to Blossom, then commit the `marmot.group.blossom.image.v1` component. `plaintext` must contain the decoded image bytes; use `clear_group_image` to remove an existing encrypted Blossom avatar.

### `Marmot::clear_group_image`

**Current.**

Clear the group's encrypted Blossom avatar by committing the absent `marmot.group.blossom.image.v1` component state.

### `Marmot::download_group_blossom_image`

**Compatibility.** Prefer avatar asset request/read for visible screen metadata.

Fetch and decrypt the group's encrypted Blossom avatar (`marmot.group.blossom.image.v1`) into raw image bytes (PNG/JPEG/…). Errors when the group has no Blossom image set. Presence and the content hash (for caching) are on `AppGroupRecordFfi::image_hash_hex`; when the group also carries a URL avatar, the URL takes precedence for rendering.

### `Marmot::update_group_avatar_url`

**Current.**

Set (or clear, with `url = None`) the group's URL-based avatar (`marmot.group.avatar-url.v1`). The URL is validated (https-only, no localhost/private hosts) and normalized before it is committed.

### `Marmot::replace_encrypted_media_blob_endpoints`

**Current.**

Replace the group's encrypted-media default blob endpoints as a full `marmot.group.encrypted-media.v1` component update. Requires the caller to be an admin.

### `Marmot::promote_admin`

**Current.**

Grant admin rights to `member_ref` (npub or hex). Requires the caller to be an admin; publishes a group state update.

### `Marmot::demote_admin`

**Current.**

Revoke `member_ref`'s admin rights.

### `Marmot::self_demote_admin`

**Current.**

Step down as an admin of `group_id_hex` (demote the active account).

### `Marmot::invite_members_detailed`

**Current.**

Return the optional invitation summary and ordered member outcomes together with refreshed group details and management state. The snapshots remain available when the invitation is a no-op.

### `Marmot::invite_members_detailed_with_initial_admins`

**Current.**

Return the same invitation result as `invite_members_with_initial_admins`, plus refreshed group details and management state, including when the invitation is a no-op.

### `Marmot::remove_members_detailed`

**Current.**

Remove selected members and return detailed operation outcome.

### `Marmot::promote_admin_detailed`

**Current.**

Promote selected members and return detailed operation outcome.

### `Marmot::demote_admin_detailed`

**Current.**

Demote selected administrators and return detailed operation outcome.

### `Marmot::self_demote_admin_detailed`

**Current.**

Demote the current account and return detailed operation outcome.

### `Marmot::group_mls_state`

**Current.**

Current MLS state (epoch, member count, required components) for the conversation developer/debug view.

### `Marmot::quarantined_groups`

**Current.**

Stored groups that failed session-open hydration and were skipped so the rest of the account could open (mdk#151 / #417). These groups are not in the live roster and otherwise vanish from the account with no explanation; surface them in a per-group recovery flow (mdk#426) distinct from healthy and archived groups, using `reason` to pick the per-reason guidance, and offer `Self::retry_hydrate_quarantined_group`.

### `Marmot::retry_hydrate_quarantined_group`

**Current.**

Re-attempt hydration of a single quarantined group (mdk#426).

### `Marmot::set_group_archived`

**Current.**

Flag a group archived (or restore it). Local-only projection state — it does not change membership or publish anything. The chats list filters archived groups unless `include_archived` is set.

### `Marmot::group_maintenance_status`

**Current.**

Inspect maintenance status for a group.

### `Marmot::key_package_maintenance_status`

**Current.**

Inspect account KeyPackage maintenance status.

### `Marmot::schedule_group_self_update`

**Current.**

Schedule a group self-update.

### `Marmot::periodic_maintenance_policy`

**Current.**

Read periodic maintenance policy.

### `Marmot::set_periodic_maintenance_policy`

**Current.**

Set periodic maintenance policy.

### `Marmot::pause_maintenance`

**Current.**

Pause maintenance for an account.

### `Marmot::resume_maintenance`

**Current.**

Resume maintenance for an account.

### `Marmot::run_due_maintenance`

**Current.**

Run due maintenance for an account.

</details>

<details>
<summary>commands/history_notice.rs</summary>

### `Marmot::history_notices`

**Current.**

List the account's "history may be incomplete" notices, oldest first. Each is one parked recovery occurrence: automatic recovery stopped retrying because it could not prove some history complete. `cause` picks the host's wording; `group_id_hex` names the affected group for a group-scoped occurrence (an epoch gap) and is `None` when the account's history as a whole may be incomplete (delivery or notification loss, incremental or explicit history). The list is local and durable, needs no network, and is cheap to re-read: refresh it on `MarmotEventFfi::HistoryNoticesChanged`. A group's own occurrences also appear in `group_recovery_status` as `history_may_be_incomplete` and `history_notice_ids`. Treat `notice_id` as opaque; it changes when new evidence re-arms recovery, so never store it as an identity of a group or account.

### `Marmot::account_recovery_status`

**Current.**

Read the account's recovery in one call: `catching_up_group_ids_hex` lists the groups whose history is still being fetched (lowercase hex, sorted), `inbox_catching_up` says whether the inbox's is, and `notices` holds every notice exactly as `history_notices` lists them. Show the first two as "catching up" and the notices as "history may be incomplete". It reads local state on the account worker, needs no network, and is cheap to re-read: refresh it on `MarmotEventFfi::RecoveryStatusChanged`. The recovery runner supplies the catching-up fields.

### `Marmot::dismiss_history_notice`

**Current.**

Dismiss one notice after the user accepts that this history may be incomplete. The dismissal is durable and is recorded as its own outcome, never as recovered history. It retires exactly that occurrence; for delivery or notification loss the transport cursor may advance again once no loss recovery remains pending. Returns `false`, changing nothing, for a stale id (new evidence re-armed recovery, or it was already dismissed); re-read the list and show the current notices. A malformed id is `InvalidHex`. New loss, a higher missing epoch, a later startup comparison or a new explicit repair can raise a new notice with a new id. Runs on the account worker in order with other mutations; it performs no network I/O.

</details>

<details>
<summary>commands/linked_device.rs</summary>

### `Marmot::linked_devices`

**Current.**

List this account's own devices for a Devices screen, from the roster of the device group this device trusts: this device first (`is_this_device`), then by `linked_at`. Every entry is this account's own device, never another account's, and it is read from local group state with no network I/O, so it is cheap to re-read. `slot_id_hex` is the device's KeyPackage slot and the handle later device actions take; `label`, `client` and `platform` are empty until set, and `linked_by_slot_id_hex` is `None` for the device that founded the group. `last_active_at` is when a heartbeat last showed a sibling running, in Unix seconds: each device sends one in the device group at most hourly while it runs, and each is dated when it was created or, if earlier, when this device read it. It is `None` for this device and for a sibling none of whose heartbeats has counted. `inactive` is this device's own judgement for showing the user, 30 days after the later of that and when this device first found the sibling in the roster; it is never set for this device, and `status` `Inactive` is the roster's separate mark. The list is empty until this device trusts a device group (a single-device account has none), once that group is terminal, and always unless the host turns device groups on. The device group's own events never reach hosts: refresh on `MarmotEventFfi::LinkedDevicesChanged`, which may fire with no visible change. A roster that cannot be read fails with `MarmotKitError::Runtime` (details `device group refused: roster_unavailable`). Runs on the account worker.

### `Marmot::chat_history_imports`

**Current.**

List the held chats whose history from another of this account's devices is arriving or has arrived, for progress beside each chat after a link ("Book club: history imported"). `Receiving` means a delivery arrived and waits to be imported, as while its bundle is fetched from the chat's media server; `retrying` turns on once an attempt to get its bundle failed, and it is tried again later. `Imported` names the device the latest import came from (`device_slot_id_hex`, and `device_label`, its name now) and when, in Unix seconds. A chat with a delivery still waiting reads `Receiving` even after an earlier import. Only facts are listed: a chat with no history to bring sends nothing, so no chat ever waits for one, and a delivery that expired after a week leaves nothing behind. A delivery for a chat this device does not hold yet is left out until it joins, since a host cannot name that chat. Empty while device groups are off. Refresh on `MarmotEventFfi::ChatHistoryImportsChanged`, which fires whenever this answer changes: a delivery arriving, importing, first failing or going, imported rows pruned or deleted with their chat, a source device renamed or removed, or a chat joined after its delivery arrived. It also fires once each time the account's worker opens or reconnects. An empty `device_label` means "another device". The same source names each imported row in `TimelineMessageRecordFfi.imported_from`: draw "Imported from <device>" where rows change from imported to live. Runs on the account worker, with no network I/O.

### `Marmot::key_package_refresh_overdue`

**Current.**

Whether this device's device group has held its KeyPackage refresh back for a week, so the app warns the user. While this device trusts a device group, each KeyPackage it publishes is first announced in its own roster entry; if the device group can't take that Commit, the old KeyPackage stays in the slot, and at 30 days inviters stop treating the device as fresh. True once the KeyPackage this device would publish is still unannounced and its slot's newest publication is a week old, or there is none. A routine refresh never shows, and neither does one that is announced but failing at the relays. Always false until this device trusts a device group, and unless the host turns device groups on. Re-read on `MarmotEventFfi::KeyPackageRefreshOverdueChanged`, which carries no device or group identities and may fire with no visible change. Reads local state with no network I/O; runs on the account worker.

### `Marmot::rename_linked_device`

**Current.**

Rename one of this account's devices, this one included, by its `slot_id_hex` from `linked_devices`: one roster commit in the device group that sets only that device's label. The label is at most 64 bytes of UTF-8, and an empty label clears it. It is refused with `MarmotKitError::Runtime` (details `device group refused: <reason>`) and nothing sent unless the host turns device groups on (`roster_unsupported`), for a label that is too long (`label_too_long`), without a device group (`no_device_group`), for a slot the roster doesn't list (`unknown_device`), and while the device group has an earlier change of this device's in flight (`device_group_busy`, retry later). A rename whose commit loses a fork is made again on a later maintenance pass, unless another user edit of that device won; that one stands. Show the label `linked_devices` returns after `LinkedDevicesChanged`. Runs on the account worker.

### `Marmot::update_linked_device_settings`

**Current.**

Patch the supplied settings of any linked device, this one included; `None` preserves the value from the current account-worker roster. Earlier lost label/settings edits recover first; a patch that still matches afterwards sends no new edit. Retry `device_group_busy` while one remains unsettled. Other refusals are `roster_unsupported`, `no_device_group`, `unknown_device` and `roster_unavailable`. A competing user edit wins as a whole; re-read `linked_devices` on `LinkedDevicesChanged`. Add-to-all permits the available linked-device Add flow and off never leaves joined chats. History affects future sibling Adds and remaining transfers owed, without retroactive backfill; keep is stored for inactivity removal and does not cancel explicit removal or sign-out. See the [shared contract](README.md#linked-devices).

### `Marmot::remove_linked_device`

**Current.**

Remove another of this account's devices, by its `slot_id_hex` from `linked_devices`: from the device group and from every chat, and delete its KeyPackage slot so inviters stop adding it. The decision is recorded at once and carried out as the device group allows, so a busy device group only delays it; `linked_devices` lists the device with `removal_pending` until the device group takes the removal, then no longer lists it. Chats that can't take a same-account removal keep the device; `removed_device_leftover_chats` counts them. It is refused with `MarmotKitError::Runtime` (details `device group refused: <reason>`) and nothing recorded unless the host turns device groups on (`roster_unsupported`), without a device group (`no_device_group`), for a slot the roster doesn't list (`unknown_device`), for this device (`this_device`: sign out instead), and for a device whose link may still fail (`device_link_pending`). Refresh on `LinkedDevicesChanged`. Runs on the account worker.

### `Marmot::removed_device_leftover_chats`

**Current.**

How many chats this device is in still hold a device this account no longer has, because the chat does not take a same-account removal. That device is one this account removed, or one its device group stopped listing, as after a failed link. A chat admin can remove it; show the count beside the device list so the user knows to ask. Zero until this device trusts a device group, and always zero unless the host turns device groups on. It is not evented: read it when showing the device list. Runs on the account worker.

### `Marmot::chats_closed_to_linked_devices`

**Current.**

How many chats this device is in can't take any device of this account: they don't require `marmot.group.account-devices.v1`, name no relays a sibling Welcome can carry, or already hold this account's limit of 20 leaves. Once a link this device approved is made, MDK adds the new device to this device's other chats by itself when its "add to all my chats" setting is on, for a week after the link; these chats are passed over, and so, uncounted, is a chat that can take this account's devices but whose requirements the new device's KeyPackages don't meet, so zero does not mean the new device reaches every chat. A chat admin can turn the component on; removing a device frees its leaves. Show the count beside the device list, as "N chats can't add your other devices". Zero until this device trusts a device group, and always zero unless the host turns device groups on. It is not evented: read it when showing the device list. Runs on the account worker.

</details>

<details>
<summary>commands/media.rs</summary>

### `parse_media_imeta_tag`

**Current free function.** Generated Swift/Kotlin name: `parseMediaImetaTag`.

Parse one authenticated encrypted-media `imeta` tag using MDK's frozen V1 or current V2 validation rules.

### `Marmot::build_media_imeta_tag`

**Current.**

Build one outbound encrypted-media `imeta` tag without publishing it.

### `Marmot::send_media_attachments`

**Current.**

Send already-uploaded encrypted media attachments as a kind-9 chat carrying ordered NIP-92 `imeta` tags. Preserve each upload's local `source_epoch_identity`; missing provenance or a changed upload branch requires a fresh upload.

### `Marmot::send_tagged_media`

**Current.**

`send_media_attachments` plus application tags on the same kind-9. For NIP-30 custom emoji, upload the image with `upload_media(send = false)`, then send its reference with an `["emoji", shortcode, reference.locators[0].value]` tag; receivers match the tag URL to the `imeta` locator and render that attachment inline. Preserve the returned reference's `source_epoch_identity`: sending requires the upload's exact branch, not only its epoch number. Missing provenance requires a fresh upload. Same tag limits as `send_tagged_text`. `upload_media` with `MediaUploadRequestFfi.message_tags` and `send = true` is the one-call equivalent.

### `Marmot::send_media_reference`

**Current.**

Backward-compatible single-attachment send helper. Prefer `send_media_attachments` for new callers so one chat can carry ordered mixed media attachments.

### `Marmot::upload_media`

**Current.**

Encrypt plaintext attachments, upload the ciphertext blobs, and optionally send the resulting media references into the group. Upload references include local `source_epoch_identity`; preserve it unchanged when saving or sending them. Each body is first kept in the account's encrypted media store, so the sender reads its own attachments locally once the message is confirmed; a body the disk cannot hold beyond the attachment policy's `disk_reserve` fails with `StorageFull` before anything is uploaded.

### `Marmot::upload_media_files`

**Current.** **C:** `marmot_upload_media_files`.

File-backed `upload_media` for large attachments. Each `source_path` (a regular file, not a symlink; `expected_size` must match when set, and the file must not change while it is read) is copied into the account's encrypted media store with 64 KiB buffers before the first PUT, so plaintext never crosses the FFI as a byte array. A source the disk cannot hold beyond the attachment policy's `disk_reserve` fails with `StorageFull` before anything is uploaded. The ciphertext is never written to disk: one pass over the stored copy computes its digest, and each PUT streams it again. Ordered server fallback re-sends identical ciphertext from offset 0; a server whose descriptor omits or mismatches `sha256`/`size` fails over. The batch ciphertext ceiling is `max_file_media_ciphertext_bytes()`, including each 16-byte AEAD tag. The stored copy becomes the sender's local attachment once the message is confirmed; no retention budget applies. Explicit large acquisitions stream ciphertext into private files and authenticate it before bounded local publication; resumable ciphertext checkpoints never grant readable plaintext. Legacy array APIs retain their smaller bounds. `control` reports monotonic `processed_bytes` and cancels preparation, transfer and fallback. There is no dedicated cancellation error variant: after an error, `control.is_cancelled()` distinguishes requested cancellation (`InvalidMediaReference`, detail `media transfer cancelled`). A failed or cancelled upload deletes its stored copies; after a crash, the account worker's media sweep removes copies no upload owns, and an upload that is never sent expires after seven days. `processed_bytes` covers the copy, the digest pass and the transfer.

File-backed uploads have no fixed worker-response timeout; per-endpoint network deadlines still apply. Cancellation observed before message admission starts prevents publication. Admission is not interruptible once started, including while durable acceptance is pending.

### `Marmot::upload_message_draft_attachments`

**Current.** **C:** `marmot_upload_message_draft_attachments`.

`upload_media_files` for a draft's own attachments: encrypts and uploads the attachments `attachment_ids` names (1..=64 distinct ids, in that order) from the copies the draft holds, inline or file-backed, so the host never re-reads or re-sends large bodies. Upload only: pass the returned references, in order, to `send_message_draft` with the same revision; they carry the draft's descriptors and the staged bodies' `plaintext_sha256`, and durable acceptance clears the draft, releasing its files. `revision` must be current when the bodies are read. `blossom_server` overrides the group's endpoints. Progress, cancellation, the batch bound, `StorageFull` and server fallback are as for `upload_media_files`; the draft and its files are untouched by the upload.

### `Marmot::download_media`

**Compatibility.** Prefer retained local access plus transfer controls for received chat media. Explicit one-shot fetch remains supported.

Fetch an encrypted media blob and decrypt it using the group's encrypted media component secret.

### `Marmot::list_media`

**Compatibility.** Prefer attachment_history_page/version for new media-library screens.

Typed media references projected from group message history. Host apps can pass a returned `reference` back to `download_media`.

</details>

<details>
<summary>commands/message.rs</summary>

### `Marmot::send_text`

**Current.**

Send a plain UTF-8 text message. Structured payloads (reactions, replies, deletes, media) go through dedicated methods.

### `Marmot::send_tagged_text`

**Current.**

Send `send_text` content plus application tags on the same kind-9, e.g. NIP-30 `["emoji", shortcode, url]`. At most 64 tags and 16 KiB of tag values; `imeta` rows are rejected, and `e`/`q` rows need a non-empty target. Name custom emoji images through `send_tagged_media` instead: an `emoji` URL alone is not a decryptable Marmot media reference.

### `Marmot::send_tagged_sticker`

**Current.**

Send an authorized exact sticker reference with reply `e`, NIP-22 `E`/`K`/`P`, or effect tags on the same kind-9 message. Rejects `imeta` and extra `sticker` rows. Context is bounded to 64 tags and 16 KiB of tag values. Native sticker authorization and normal send admission still apply; this does not upload media. `send_sticker` keeps its existing signature and sends without context.

### `Marmot::send_sticker`

**Current.**

Sends a kind-9 message carrying one exact sticker reference. The account must already have that reference in its projection, so a host cannot send an arbitrary URL.

### `Marmot::retry_group_convergence`

**Current.**

Re-attempt publishing a group's pending (committed-but-undelivered) commit(s) without minting a new event.

### `Marmot::react_to_message`

**Current.**

React to `target_message_id` with `emoji` (an "add" reaction).

### `Marmot::react_with_media`

**Current.**

React with a custom emoji image. `emoji` is the reaction content (e.g. `:shortcode:`), `attachments` are already-uploaded references emitted as `imeta` on the kind-7, and `tags` name them (NIP-30 `["emoji", shortcode, url]`). The reaction retains its media epoch secret like a chat, so the image stays decryptable after the group advances. Preserve the returned reference's `source_epoch_identity`; missing provenance or a changed upload branch requires a fresh upload. Same tag limits as `send_tagged_text`; repeating an existing reaction with the same content is a no-op.

### `Marmot::unreact_from_message`

**Current.**

Remove all of this account's active reactions from `target_message_id`.

### `Marmot::unreact_from_message_matching`

**Current.**

Remove every locally observed active reaction event by the account whose content
exactly matches `emoji`, including duplicate events from its other devices.
Other emoji and other accounts' reactions remain. `ReactionNotFound` means the
local projection has no match; refresh authoritative state before treating
absence as an idempotent convergence outcome. It does not establish that other
devices or pending deliveries have caught up. An admitted runtime command may
finish after cancellation, so refresh before retrying.

### `Marmot::reply_to_message`

**Current.**

Send `text` as a reply that quotes `target_message_id`.

### `Marmot::send_thread_message`

**Current.**

Send a NIP-22 thread message (kind 1111) that answers `parent_message_id`: text, already-uploaded attachments (keep each upload's `source_epoch_identity`), or both, plus application tags such as NIP-30 `emoji`. MDK finds the parent's thread in this device's timeline and builds the `E`/`K`/`P` root and `e`/`k` parent tags; `tags` must not carry those, or `imeta`. The parent must be stored and not deleted. Use it only from a thread view. A client without one answers any message, a thread message included, with `reply_to_message` (kind 9). Rows expose the result as `thread` and `reply_to_message_id_hex`; see [the thread-message contract](../../docs/marmot-architecture/overview/thread-messages.md).

### `Marmot::delete_message`

**Current.**

Mark `target_message_id` deleted for the whole group. This is a tombstone — the original stays in everyone's store; clients render a "message deleted" placeholder.

### `Marmot::discard_failed_send`

**Current.**

Remove a failed own send from this device without publishing anything. Offer it, instead of `delete_message`, on a row whose `invalidation_status` is `local_publish_failed`: a delete would tell the group about a message nobody received. `Discarded` securely deletes the row, its edits and its media references, and timeline subscribers receive the row's removal with reason `Cleared`; purge `media_ciphertext_sha256` from any decrypted-media cache. `erasure_pending` means secure WAL truncation is still owed; the next secure delete in the group retries it. `StillSending` means the group has a send the engine may still publish, which could be this one, so nothing changed: keep the row and offer the action again later. `NotFailedSend` means the row was delivered, is still pending, was confirmed by a peer's reaction, or is already gone.

### `Marmot::secure_delete_expired`

**Current.**

Securely scrub and prune expired disappearing-message plaintext for a group according to its active retention component. The media hash list identifies pruned encrypted-media blobs so host apps can purge their own decrypted-media disk caches keyed by ciphertext hash.

### `Marmot::sweep_expired_retention`

**Current.**

Run the engine-owned disappearing-message sweep for one account using the supplied Unix wall-clock time in milliseconds. Each group reports pruning, a fail-closed deferral, or a privacy-safe failure category.

### `Marmot::edit_message`

**Current.**

Edit `target_message_id` by publishing a kind-1009 event that references it and carries the replacement plaintext in `content`. Recipients honour the edit only when its authenticated author matches the target's author; MDK ignores mismatched edits. It returns `InvalidEditTarget`, publishing nothing, unless the target is an available chat message this account sent. Competing edits resolve by `created_at`, then the larger event id.

### `Marmot::send_custom_event`

**Current.**

Send an app-defined event with an arbitrary non-reserved kind. `tags` and `content` pass through verbatim; kinds MDK owns (chat, reaction, edit, delete, agent, group system, push token, device group: 457, 458, 459, 460, 461, 473, 475, 476) are rejected so an app cannot forge protocol events. Custom events appear in the timeline as standalone rows and can be fetched via `Marmot::messages` with a `kinds` filter.

### `Marmot::create_tagged_poll`

**Current.**

Create the same encrypted NIP-88 poll as `create_poll`, adding reply `e`, NIP-22 `E`/`K`/`P`, or effect context on the same event. Rejects `imeta`, `option`, `polltype`, `endsAt`, and `response` context rows. Generated poll tags plus context must total at most 32; context also follows the tagged-text bounds of 64 tags and 16 KiB of values. Poll replies project the same reply target and preview as chat messages. See [Polls](POLLS.md) for question, option, deadline and vote semantics. The original `create_poll` remains available without context.

### `Marmot::create_poll`

**Current.** Typed API for an encrypted NIP-88 group poll; do not build kinds 1068/1018 through `send_custom_event`.

Pass two through ten option labels and an optional Unix-seconds deadline no more than 30 days after creation. MDK
validates bounded display text, assigns stable option ids in display order, and exposes results through the timeline
poll projection. Creation follows MDK's canonical conversation classification: named two-member conversations are
groups, while unnamed two-member conversations are direct. Polls are neither anonymous nor election-grade. See
[Polls](POLLS.md).

### `Marmot::cast_poll_vote`

**Current.** Use for a complete replacement selection on an existing encrypted group poll.

The poll must already be a valid local timeline row in this group and remain open. Pass one option id for single choice
or one through ten unique ids for multiple choice; use the ids from `TimelineMessageRecordFfi.poll`, not option labels.
This is a replacement, not a delta or unvote. MDK revalidates the poll against the response event's actual timestamp at
send time, and an accepted open poll remains votable after conversation reclassification. See [Polls](POLLS.md).

### `Marmot::message_reactions`

Read every effective user/emoji pair for an exact account/group/message. Use for reaction details, because conversation references contain only a bounded preview. Returns one local snapshot, ordered by timestamp/sender/emoji, with duplicate events collapsed to the latest pair. Blocked reactors and hidden, deleted, invalidated or retention-pruned targets are excluded. Run off the UI thread, refresh on installed conversation revisions, and discard results when the owning screen closes. No network work, localization or durable client cache is involved; records are caller-owned. See [conversation details](CONVERSATION-WINDOW.md#complete-reaction-details).

### `Marmot::poll_votes`

**Current.** Use for a "View votes" sheet that lists who chose each option.

Returns one page of each voter's effective selection, resolved by the same rules as `TimelineMessageRecordFfi.poll`:
all pages together hold `participants` entries whose selections sum to each option's `votes`. Polls are not anonymous;
every member can already read each response and its sender. Blocked voters stay listed because the shared tally still
counts them; mark them with the account's block list. A missing, deleted, hidden, or non-poll row returns an empty
page. Votes are ordered by `(voted_at, voter_account_id_hex)`. Omit both cursor fields for the first page, then pass the
last vote's `voted_at` and `voter_account_id_hex` while `has_more_after` is true. `limit` is 1..=100 because retained
votes from former members are not bounded by the current group size. Re-read from the start when the poll row is
reprojected, and run this synchronous query off the UI thread. See [Polls](POLLS.md).

### `Marmot::messages`

**Lower-level.** Raw stored messages; complete conversation screens use open_conversation_window.

Initial history fetch for a group (or, when `group_id_hex` is None, the account-wide tail). Used to populate the conversation view before the subscription stream takes over.

</details>

<details>
<summary>commands/moderation.rs</summary>

### `Marmot::report_message`

**Current.**

Publish a report with a typed reason and explanation for a target message.

### `Marmot::dismiss_reports`

**Current.**

Publish an admin dismissal label for selected reports.

### `Marmot::content_reports`

**Current.**

Read a bounded page of reports with per-report dismissal state.

### `Marmot::reported_message`

**Current.**

Read the report target through deletion-masked timeline presentation.

### `Marmot::report_dismissals`

**Current.**

Read a bounded page of dismissal labels.

### `Marmot::submit_moderation_report`

**Current.**

Privately report a user to the deployment's moderation team: a NIP-56 kind-1984 report about `reported_pubkey` (hex or `npub`), sealed by the account key and gift-wrapped per NIP-59 to the configured reports key, published only to the configured relays. It carries the reported key, the NIP-56 type mapped from `reason`, an origin label and the trimmed explanation (at most 1,000 characters; empty is omitted), and never message content, message ids, group ids or relay metadata. Additive to `report_message`, which stays the in-group path and is unchanged; "Block and Report" still calls `block_user` separately. `Published`, `AcceptedPending` and `CompletionUnknown` follow send summaries: the two retained states are queued, retried on catch-up and must not be resubmitted. A repeat of the same reported key, reason and origin within 10 minutes returns the existing outcome. Typed errors: `ModerationReportingNotConfigured`, `InvalidReportedPublicKey`, `CannotReportSelf`, `ModerationReportRateLimited` (20 per account per hour). Sign-out and wipe delete the account's queued reports. See [moderation reports](../../docs/marmot-architecture/moderation-reports.md).

### `Marmot::moderation_reporting_available`

**Current.**

True when a valid moderation-report destination is installed (from `MarmotOptions.moderation_report_config` or `configure_moderation_reporting`). Gate the report-to-operator affordance on it.

### `Marmot::configure_moderation_reporting`

**Current.**

Install (`Some`) or clear (`None`) the moderation-report destination at runtime and learn why one was rejected. The recipient is 64-character hex or `npub`; every relay must pass the relay safety policy. One bad entry rejects the whole destination with `InvalidModerationReportConfig` and leaves reporting unconfigured; nothing is partially applied. Prefer `MarmotOptions.moderation_report_config` set per build flavor so production and staging never mix.

</details>

<details>
<summary>commands/notification.rs</summary>

### `Marmot::notification_settings`

**Current.**

Read account notification settings.

### `Marmot::set_local_notifications_enabled`

**Current.**

Set local notification generation preference.

### `Marmot::set_native_push_enabled`

**Current.**

Set native push preference.

### `Marmot::catch_up_accounts`

**Current.**

Run bounded account catch-up work.

### `Marmot::notify_connectivity_restored`

**Current.**

Interrupt retry backoff for durable outbound work after the host has observed usable connectivity. This is a scheduling signal only; it does not recreate application events or weaken exact-replay guarantees.

### `Marmot::collect_notifications_after_wake`

**Current.**

Collect notifications after bounded wake/catch-up processing.

</details>

<details>
<summary>commands/onboarding.rs</summary>

### `OnboardingSubscription::snapshot`

**Current.**

Read the initial/current snapshot for this handle; follow its feature contract for one-shot versus repeatable reads.

Each finding preserves typed context, check purpose/outcome, declared capability,
allowed finding actions, and optional original observation revision. Keep rows
with the same endpoint separate. See the [evidence limits](README.md#interactive-account-onboarding);
`InspectionCompleted` directory-query success is not event-publication evidence.

### `OnboardingSubscription::next`

**Current.**

Wait for the next value; None means the observation ended. Bind one receive loop to this handle.

### `Marmot::onboarding_recovery_required`

**Current.**

Whether an unreadable or exhausted checkpoint needs explicit recovery.

### `Marmot::recover_onboarding`

**Current.**

Preserve opaque evidence, sign out, and retire the old attempt. Hosts invalidate old UI callbacks first, acknowledge latest-only retention, then explicitly begin again and use the snapshot's recovery_epoch.

### `Marmot::propose_onboarding_relay_repair`

**Current.**

Preview an exact, minimal general or inbox relay-list repair. The returned `proposal.relay_repair` carries the source event ID, ordered before/after tags, unchanged content, typed occurrence diff, and repair mode. This method only persists a revision-bound proposal; it never signs or publishes. Show the diff and use `approve_onboarding_repair` (or its epoch-aware variant) only when `ApproveRepair` is offered. `ManualReview` deliberately has no approval action; prefill an editor from `before_tags` or offer a separately labeled full reset. Offered as `RemoveUnusableRelays` when the preview is approvable and removes declared relays the check showed cannot serve their role; each removed change carries `removal_reason`. Preserve the account, attempt, recovery epoch, source event, and snapshot revision until approval.

### `Marmot::approve_onboarding_repair_in_epoch`

**Current.**

Approve with the epoch and revision from the same displayed snapshot.

### `Marmot::acknowledge_onboarding_single_device_in_epoch`

**Current.**

Acknowledge with the epoch and revision from the displayed device notice.

### `Marmot::cancel_onboarding`

**Current.**

Cancel the current interactive onboarding attempt at any step, including approved or ready checkpoints. The identity stays signed out. Already journaled evidence is retained in the latest cancellation checkpoint; later cancellations replace it even if publication remains uncertain. A later explicit `begin_*_onboarding` starts a new attempt. Hosts should invalidate the UI attempt, ignore the old subscription, and await this call before beginning again. Open Chats stays host-owned.

### `Marmot::acknowledge_onboarding_single_device`

**Current.**

Record Continue anyway for the displayed notice, then resume setup.

### `Marmot::begin_onboarding`

**Current.**

Persist the identity and return before any network preflight or publication.

### `Marmot::begin_external_signer_onboarding`

**Current.**  **C:** not exposed; external-signer callback vtable is not implemented.

Begin interactive identity-only onboarding with a host signer; signer remains host-owned and must be registered after reconstruction.

### `Marmot::onboarding_snapshot`

**Current.**

Read the persisted onboarding state.

### `Marmot::subscribe_onboarding`

**Current.**

Observe onboarding snapshots for one account.

### `Marmot::set_onboarding_discovery_relays`

**Current.**

Change discovery sources for the workflow without modifying existing published account relay lists. When `OnboardingOptionsFfi.create_missing_inbox_list` is enabled, a complete lookup that confirms no kind-10050 inbox list exists can trigger automatic creation of the recommended inbox list.

### `Marmot::run_onboarding`

**Current.**

Run/resume the durable onboarding workflow until ready or user input is required.

### `Marmot::retry_onboarding_step`

**Current.**

Retry a step whose current snapshot offers Retry.

### `Marmot::continue_onboarding_without`

**Current.**

Explicitly skip an optional step where the current snapshot permits it.

### `Marmot::propose_onboarding_recommended_relays`

**Current.**

Append missing recommended relays while preserving all original relay tags and
NIP-65 roles, including declarations this runtime cannot use. Dial policy filters
connection attempts without deleting published entries. A policy-allowed outbox
or inbox route is required; proposal alone is not publication. After an
inconclusive check, call it only while the step offers `UseRecommendedRelays`; the
proposal then has `inconclusive` set.

### `Marmot::propose_onboarding_relays`

**Current.**

Prepare explicit relay changes for approval. Accepted while the step offers `EditRelays`, including a `RetryableFailure` whose check was inconclusive; such a proposal has `inconclusive` set and needs an explicit at-your-own-risk confirmation before approval.

### `Marmot::propose_onboarding_profile`

**Current.**

Prepare profile changes for approval.

### `Marmot::propose_onboarding_follows`

**Current.**

Prepare follow-list changes for approval.

### `Marmot::approve_onboarding_repair`

**Current.**

Approve the displayed revision for a non-recovered attempt; recovered attempts require the epoch-aware method.

### `Marmot::cancel_onboarding_repair`

**Current.**

Dismiss an unapproved repair proposal; this cannot undo already-approved publication intent.

</details>

<details>
<summary>commands/presentation.rs</summary>

### `Marmot::presented_chat_list`

**Lower-level.** Selected full list; default paged screens use open_chat_list_window.

Local whole rows, including selected title/avatar. First use may await local preparation.

### `Marmot::presented_chat_list_row`

**Current.**

One complete row for creation/rebind; missing local groups return None.

### `Marmot::open_presented_chat_list`

**Lower-level.** Live selected full list; default paged screens use open_chat_list_window.

Returns an attached handle containing the initial snapshot. Take its snapshot once, then consume whole replacement updates; dispose the old handle on account switch.

</details>

<details>
<summary>commands/product_analytics.rs</summary>

### `Marmot::usage_diagnostics_settings`

**Current.**

Read durable diagnostics-consent settings.

### `Marmot::set_usage_diagnostics_consent`

**Current.**

Persist the user diagnostics-consent choice.

### `Marmot::usage_diagnostics_status`

**Current.**

Read diagnostics configuration/delivery status.

### `Marmot::set_product_analytics_runtime_config`

**Current.**

Configure the consent-gated product-event pipeline.

### `Marmot::record_product_event`

**Current.**

Record an event accepted by the configured closed product-event schema and consent policy.

### `Marmot::set_product_analytics_activity`

**Current.**

Update host activity state for product analytics.

### `Marmot::flush_product_analytics`

**Current.**

Flush pending eligible product analytics work.

</details>

<details>
<summary>commands/push.rs</summary>

### `Marmot::push_registration`

**Current.**

Read an account native-push registration.

### `Marmot::upsert_push_registration`

**Current.**

Register/update native push configuration with account ownership proof.

### `Marmot::clear_push_registration`

**Current.**

Clear the account native-push registration.

### `Marmot::group_push_debug_info`

**Current.**

Inspect group push-routing debug information; do not log sensitive identifiers indiscriminately.

</details>

<details>
<summary>commands/relay.rs</summary>

### `Marmot::retired_relay_hosts`

**Current.**

Hostnames the relay plane will never dial or adopt.

### `Marmot::classify_relay_endpoints`

**Current.**

Classify relay URLs using the same policy enforced at the dial boundary.

### `Marmot::account_relay_lists`

**Current.**

Per-account relay lists: the NIP-65 and inbox lists the account has published, plus the configured default/bootstrap sets.

### `Marmot::relay_health`

**Current.**

Live relay-plane connection health (connected / connecting / disconnected counts, etc.) for the relay diagnostics view.

### `Marmot::relay_telemetry_settings`

**Current.**

Device-wide relay telemetry export settings. Export is opt-in and stays inert until `export_enabled` is true and runtime/default config supplies a valid OTLP endpoint, bearer token, and resource attributes.

### `Marmot::telemetry_install_id`

**Current.**

Consent-bound random OTLP identifier, stable until revocation. Requires a current combined grant; never use this value in product events.

### `Marmot::set_relay_telemetry_runtime_config`

**Current.**

Supply non-persisted OTLP runtime metadata: optional metrics URL override, bearer token from the host app's build-time secret, and resource attributes from the platform shell.

### `Marmot::set_relay_telemetry_settings`

**Current.**

Deprecated consent control. Use `set_usage_diagnostics_consent` instead. Enable requires a combined grant; disable revokes both exporters. This compatibility setter still updates the telemetry interval.

</details>

<details>
<summary>commands/sign_in.rs</summary>

### `Marmot::answer_sign_in`

**Current.**

Answer the unrecognized sign-in in `slot_id_hex`. `NotNow` keeps it listed without a prompt. `Reject` records that it was not the user: it leaves this device's list, and its slot goes into the device group's roster as rejected, in one commit once that group is quiet. Another device that still shows it as a new sign-in's waiting prompt lists it as `RejectedElsewhere` until `Dismiss`; one there that was put off with `NotNow`, or found before that device, leaves its list. With no device group yet, the rejection stays on this device and goes into the roster of the group it later creates or joins. `Dismiss` only ends a prompt another device already answered. A refusal is `MarmotKitError::Runtime` whose details read `device group refused: <reason>`, the reason being `sign_in_unknown` (not listed), `sign_in_answered`, `sign_in_answered_elsewhere` (only Dismiss applies), `sign_in_unanswered` (Dismiss before any device answered), or `roster_unsupported`; re-read the list after one. An answer raises `UnrecognizedSignInsChanged`. Runs on the account worker.

### `Marmot::check_sign_ins`

**Current.**

Check the account's KeyPackage slots for new sign-ins now, for a pull-to-refresh or a Check now action, and return the list after the check. The check reads every slot from each of the account's KeyPackage relays, and restarts the six-hour schedule. Only a complete read marks a sign-in as signed out. A read that reached no relay fails with `MarmotKitError::Runtime` (`device group refused: key_packages_unreachable`), and the list is unchanged. Runs on the account worker and waits on the network.

### `Marmot::start_fresh`

**Current.**

Start this device without the devices its first sign-in check found, for "No, start fresh" when the user no longer has them: every sign-in from before this device is answered `NotNow`, now and when one is listed later, so none prompts. It rejects nothing and raises no compromise warning, so one of those devices can still link this one. A refusal is `MarmotKitError::Runtime` whose details read `device group refused: <reason>`, the reason being `sign_ins_unchecked` (before the first check), `device_group_exists` (this device trusts a device group), or `roster_unsupported`. Raises `UnrecognizedSignInsChanged` when a listed sign-in changed. Runs on the account worker.

### `Marmot::started_fresh`

**Current.**

Whether this device started fresh and still trusts no device group, so the app can say that only chats it is invited to from now on are here. It turns false once the device trusts a device group; re-read after `start_fresh` and on `LinkedDevicesChanged`. Read from local state with no network I/O. Always false unless the host turns device groups on. Runs on the account worker.

### `Marmot::unrecognized_sign_ins`

**Current.**

List the sign-ins of this account that this device does not recognize, the earliest to appear first. Each is a fresh, valid KeyPackage of this account in a slot that neither this device nor the roster of its device group knows: someone holding the account's key signed in there. An entry with `before_this_device` was found by this device's first check, so it was signed in before this device: ask whether the user still has it, with `last_seen_at`. Any other is new: ask whether it was them, with `client` and `appeared_at`. A `LinkedElsewhere` or `RejectedElsewhere` entry was answered on another device while its prompt waited here; offer Dismiss. A sign-in whose slot empties stays listed with `signed_in` false. Linking one is device pairing's, started from its `slot_id_hex`. Read from local state with no network I/O; the account checks its slots at open, every six hours, and soon after one of its KeyPackages arrives live. Always empty unless the host turns device groups on. Refresh on `MarmotEventFfi::UnrecognizedSignInsChanged`, which may fire with no visible change. Runs on the account worker.

</details>

<details>
<summary>commands/sticker.rs</summary>

### `Marmot::sticker_packs`

**Current.**

Reads the encrypted sticker projection off the UI thread. `installed_only` selects the installed list; search matches public title and description only.

### `Marmot::sticker_pack`

**Current.**

Reads one cached pack without network I/O. Returns none when the coordinate is absent; use `fetch_sticker_pack` for an explicit network fetch.

### `Marmot::sticker_pack_share_link`

**Current.**

Builds `https://sonarprivacy.xyz/stickers?a=...` from a valid pack coordinate without network I/O. Call off the UI thread because it reads local storage. Includes up to eight normalized, unique relay candidates retained by pack fetches, or current account relays when none remain usable. Both sources pass the current relay safety policy. New fetch candidates displace older hints. Hints are candidates, not confirmed event locations; oversized hints are omitted to keep links within the parser's 2048-character limit. An uncached coordinate can be shared. Invalid coordinates return `InvalidSticker`.

### `Marmot::sync_sticker_packs`

**Current.**

Refreshes at most `MAX_DISCOVERY_PACKS` recent public packs and separately refreshes cached installed packs. Pending install changes are published only after a complete installed-list read. Uninstalled discovery above that bound is pruned; installed packs, pending operations, and message-referenced assets stay.

### `Marmot::fetch_sticker_pack`

**Current.**

Fetches one pack by coordinate or trusted Sonar link, querying the link's relay hints and the account relays; the newest version wins NIP-01 ordering, so a hint cannot hide a newer pack. The requested coordinate is protected from discovery eviction. Call this when the user opens a shared pack, not from a background crawl.

### `Marmot::install_sticker_pack`

**Current.**

After a complete installed-list read, signs the proposed list before saving local install intent. A signing refusal does not queue this install. Without a complete read, intent stays pending for a later `sync_sticker_packs`. This is the user action after previewing a pack; it does not upload sticker bytes.

### `Marmot::uninstall_sticker_pack`

**Current.**

After a complete installed-list read, signs the proposed list before saving local uninstall intent. A signing refusal does not queue this uninstall. Without a complete read, intent stays pending for a later `sync_sticker_packs`. Previously received messages can still resolve their exact historical asset.

### `Marmot::import_signal_sticker_pack`

**Current.**

Validates a canonical HTTPS Signal pack link, then refuses before any network call. The pinned importer dials Signal's CDN without address pinning, so this command does not download, upload, or publish until that fetch can be injected. The Signal key stays in memory only and is not persisted.

### `Marmot::fetch_sticker_asset`

**Current.**

Downloads one exact sticker after the account has its `(coordinate, shortcode, hash)` mapping. Hosts pass the typed reference from a timeline row; MDK never asks the host to parse tags. A missing mapping returns `StickerNotFound` rather than fetching an unvalidated URL.

</details>

<details>
<summary>commands/subscription.rs</summary>

### `Marmot::subscribe_events`

**Current.**

Top-level event firehose. One subscription, every account, every event type. Useful for global diagnostics; specific UIs prefer the per-account chats/messages/group-state subscriptions below.

### `Marmot::subscribe_notifications`

**Current.**

Observe prepared runtime notification events.

### `Marmot::subscribe_chats`

**Lower-level.** Raw chat/group subscription; prepared screens use open_chat_list_window.

Per-account chats list. Emits whenever a group's projection changes.

### `Marmot::subscribe_chat_list`

**Lower-level.** Raw list subscription; prepared screens use open_chat_list_window.

Per-account durable chat-list projection. Async for the same tokio-runtime reason as `Marmot::subscribe_chats`.

### `Marmot::subscribe_messages`

**Lower-level.** Raw message subscription; complete screens use open_conversation_window.

Messages for a specific group (when `group_id_hex` is `Some`) or every message across the account (when `None`). `limit` caps the initial snapshot to the latest N rows; live updates continue after the snapshot. `kinds` restricts to the listed inner app-event kinds (e.g. an app-defined custom kind); `None` or an empty list streams all kinds. Async for the same tokio-runtime reason as `Marmot::subscribe_chats`.

### `Marmot::subscribe_timeline_messages`

**Lower-level.** Custom timeline subscription; complete screens use open_conversation_window.

Live materialized timeline updates for a group or account-wide tail. The snapshot
and each `next()` result replace the retained window in ascending display order.
Use the handle's `paginate_backwards` and `paginate_forwards` methods rather than
merging cursor pages. The lower-level
[`timeline_messages` contract](#marmottimeline_messages) describes selection order
and cursor boundaries; complete chat screens use the
[conversation window](CONVERSATION-WINDOW.md#open-and-render).

### `Marmot::subscribe_group_state`

**Current.**

Member/profile/roster changes for one group. Async for the same tokio-runtime reason as `Marmot::subscribe_chats`.

</details>

<details>
<summary>commands/telemetry.rs</summary>

### `Marmot::record_host_timing`

**Current.**

Record an app-defined timing in the consent-gated product event pipeline. Register `name` with `elapsed: DurationBucket` and `outcome: Enum` choices `success`/`failure` in the product analytics config. Milliseconds are bucketed before recording; this does not add an OTLP performance metric.

### `Marmot::record_host_performance`

**Current.**

Record one approved host-app milestone.

### `Marmot::app_performance_snapshot`

**Current.**

Read the process-wide app-performance snapshot for debug/diagnostics surfaces and on-demand support dumps.

</details>

<details>
<summary>commands/timeline.rs</summary>

### `Marmot::message_edit_history`

**Current.**

Accepted edit versions, oldest first within a latest-first page (1..=100). Supply both cursor fields from the first version to load older versions. Run this synchronous details query off the UI thread; screens already carry effective content.

### `Marmot::timeline_messages`

**Lower-level.** Supported custom timeline page. Complete chat screens start from
[`open_conversation_window`](#marmotopen_conversation_window) and use the
[conversation window paging and lifetime contract](CONVERSATION-WINDOW.md#paging-and-lifetime).

Materialized conversation timeline for a group or account-wide tail. This read is
synchronous and local; run it off the UI thread. Custom live timelines can use
[`subscribe_timeline_messages`](#marmotsubscribe_timeline_messages) and its
[`paginate_backwards`](#timelinemessagessubscriptionpaginate_backwards) and
[`paginate_forwards`](#timelinemessagessubscriptionpaginate_forwards) methods.
Those methods return a bounded replacement window, not a page to merge.

`TimelinePageFfi.messages` is always in ascending display order, including initial
and Before pages. Selection direction does not change returned order:

- No cursor selects the last `limit` matching rows (default 50, capped at 200).
- `before` selects the nearest preceding rows, excluding the boundary row.
- `after` selects the nearest following rows, excluding the boundary row.

`TimelineMessageQueryFfi` carries the cursor directly, without a separate cursor
DTO. Older-page queries copy the **first** row's `timeline_at` and `message_id_hex`
into `before` and `before_message_id`. Newer-page queries copy the **last** row into
`after` and `after_message_id`. Both fields in a pair are required; half cursors
and requests with both directions fail. Keep the group scope and filters unchanged.

Group queries use canonical display order unless `search_wall_clock` is true.
An epoch-establishing system row precedes the authenticated application rows in
that epoch, which precede the next epoch boundary. For example, an epoch-7 message
at time 200 precedes an epoch-8 message at time 150. Storage resolves the cursor's
canonical key by message id. Keep the returned order and cursor fields rather than
sorting by timestamp or inventing a timestamp-only cursor. If the cursor row is no
longer retained, the query fails; restart without a cursor.

Account-wide and wall-clock queries order by `(timeline_at, message_id_hex)`.
Equal timestamps still require the message-id tie-breaker. Account-wide queries
with `search_wall_clock = true` add `group_id_hex` as the final tie-breaker;
paging also requires the boundary row's group in `cursor_group_id`.

Flags describe locally stored matching rows, not remote history completeness.
The cursor-facing flag records navigation context, even when the page is empty:

| Query | `has_more_before` | `has_more_after` |
| --- | --- | --- |
| No cursor | More older matching rows than fit in the tail | `false` |
| Before | More older matching rows than fit before the cursor | `true` (cursor-side context) |
| After | `true` (cursor-side context) | More newer matching rows than fit after the cursor |

This Rust example uses the actual binding DTO. `kit`, `account`, and `group` are
an open `Marmot`, an account reference, and an MLS group id in hex. The enclosing
function returns `Result<(), MarmotKitError>`. Run it off the UI thread:

```rs
let query = TimelineMessageQueryFfi {
    group_id_hex: Some(group),
    limit: Some(50),
    ..Default::default()
};
let initial = kit.timeline_messages(account.clone(), query.clone())?;
if !initial.has_more_before {
    return Ok(());
}
let Some(first) = initial.messages.first() else { return Ok(()); };
let older = kit.timeline_messages(account.clone(), TimelineMessageQueryFfi {
    before: Some(first.timeline_at),
    before_message_id: Some(first.message_id_hex.clone()),
    ..query.clone()
})?;
let Some(last) = older.messages.last() else { return Ok(()); };
let newer = kit.timeline_messages(account, TimelineMessageQueryFfi {
    after: Some(last.timeline_at),
    after_message_id: Some(last.message_id_hex.clone()),
    ..query
})?;
```

`initial`, `older`, and `newer` each remain in ascending display order. `newer`
starts after `older`'s last row; it can revisit the initial page but does not
repeat its cursor row. Each request starts from the cursor-free `query`, so the
After request does not accidentally retain a Before pair. Equal timestamps and
different canonical epochs use the same boundary-row selection.

</details>

<details>
<summary>commands/user_blocks.rs</summary>

### `BlockListSubscription::snapshot`

**Current.**

Read the initial/current snapshot for this handle; follow its feature contract for one-shot versus repeatable reads.

### `BlockListSubscription::next`

**Current.**

Wait for the next value; None means the observation ended. Bind one receive loop to this handle.

### `Marmot::block_user`

**Current.**

Block a user for the account.

### `Marmot::unblock_user`

**Current.**

Remove a user block.

### `Marmot::get_blocked_users`

**Current.**

Read the current blocked-user collection.

### `Marmot::is_user_blocked`

**Current.**

Check one user block.

### `Marmot::subscribe_blocked_users`

**Current.**

Observe block-list snapshots.

</details>

<details>
<summary>conversions/conversation_window.rs</summary>

### `MessageDraftRevisionFfi::includes_chat_list_version`

Compare a chat-list row’s opaque `draft_version` with this captured composer revision. True means the same account store/group and a version no newer than this revision; false includes foreign store/group metadata and newer identical edits. This is presentation correlation, not mutation authorization. Keep both values device-local and use revision-checked cleanup. See [pending-send draft presentation](CHAT-LIST-ROWS.md#pending-send-draft-presentation-0130).

</details>

<details>
<summary>conversions/attachment_history.rs</summary>

### `AttachmentHistoryVersion::change_since`

**Current.**

Compare current with an older version, including after the last page. RestartRequired means discard all loaded rows before restarting at the head.

</details>

<details>
<summary>conversions/emoji_set.rs</summary>

### `EmojiSetInstallControlFfi::new`

**Current constructor.** **C:** `marmot_emoji_set_install_control_new`.

Create one control per `install_emoji_set` call and pass it in; it is never reused across installs. A control that is already cancelled makes the install fail with `EmojiSetInstallCancelled` before any download.

### `EmojiSetInstallControlFfi::cancel`

**Current.** **C:** `marmot_emoji_set_install_control_cancel`.

Request cancellation from any thread. The install starts no new download, drops those in flight, stores nothing and fails promptly with `EmojiSetInstallCancelled`; a cancelled reinstall leaves the previous snapshot readable. Install is all-or-nothing: the final atomic write is not interruptible, so a cancellation that arrives once it has started is too late and the install succeeds. Needed because cancelling the host's task does not reach the Rust future under UniFFI 0.29.

### `EmojiSetInstallControlFfi::is_cancelled`

**Current.** **C:** `marmot_emoji_set_install_control_is_cancelled`.

Whether cancellation was requested, by `cancel()` or by the runtime: `shutdown` and `shutdown_and_close` cancel every running install the same way, so a backgrounded app never keeps downloading or writes after close.

### `EmojiSetInstallControlFfi::progress`

**Current.** **C:** `marmot_emoji_set_install_control_progress`.

Poll for a determinate progress bar: `completed_emoji` of `total_emoji` entries finished (stored, skipped or given up on), and `transferred_bytes` received from image hosts. `total_emoji` is the stored version's valid emoji count and stays 0 until the install has read it; `completed_emoji` reaches it when an install succeeds. Bytes are counted as each download finishes, not while it streams.

</details>

<details>
<summary>conversions/media.rs</summary>

### `MediaFileTransferControlFfi::new`

**Current constructor.** **C:** `marmot_media_file_transfer_control_new`.

Create one control per file-backed operation; it is never reused across operations.

### `MediaFileTransferControlFfi::cancel`

**Current.** **C:** `marmot_media_file_transfer_control_cancel`.

Request cancellation. Preparation, body transfer and server fallback stop at the next chunk; nothing is published when cancellation is observed before message admission starts. Admission is not interruptible once started, even before durable acceptance returns; cancellation cannot retract an admitted message.

### `MediaFileTransferControlFfi::is_cancelled`

**Current.** **C:** `marmot_media_file_transfer_control_is_cancelled`.

Whether `cancel` was called. It is not an outcome: await the operation's result.

### `MediaFileTransferControlFfi::processed_bytes`

**Current.** **C:** `marmot_media_file_transfer_control_processed_bytes`.

Monotonic local work counter across the copy into the encrypted media store, the digest pass and the transfer of the current attachment. Not a percentage or a delivery signal.

### `max_file_media_ciphertext_bytes`

**Current free function.** Generated Swift/Kotlin name: `maxFileMediaCiphertextBytes`. **C:** `marmot_max_file_media_ciphertext_bytes`.

Per-batch ciphertext ceiling for file-backed uploads (an implementation resource bound, not protocol).

</details>

<details>
<summary>external_signer.rs</summary>

### `ExternalAccountSignerFfi::public_key`

**Host callback.**  **C:** not exposed; external-signer callback vtable is not implemented.

Return the signer account public key as hex or npub.

### `ExternalAccountSignerFfi::sign_event`

**Host callback.**  **C:** not exposed; external-signer callback vtable is not implemented.

Sign a serialized unsigned Nostr event and return the signed event JSON.

### `ExternalAccountSignerFfi::nip04_encrypt`

**Host callback.**  **C:** not exposed; external-signer callback vtable is not implemented.

NIP-04 encrypt/decrypt support for legacy Nostr surfaces.

### `ExternalAccountSignerFfi::nip04_decrypt`

**Host callback.**  **C:** not exposed; external-signer callback vtable is not implemented.

Host callback for legacy NIP-04 decryption; return an unsupported error if not implemented.

### `ExternalAccountSignerFfi::nip44_encrypt`

**Host callback.**  **C:** not exposed; external-signer callback vtable is not implemented.

NIP-44 encrypt/decrypt support for gift-wrap and encrypted app data.

### `ExternalAccountSignerFfi::nip44_decrypt`

**Host callback.**  **C:** not exposed; external-signer callback vtable is not implemented.

Host callback for NIP-44 payload decryption.

</details>

<details>
<summary>lib.rs</summary>

### `Marmot::new_with_configuration`

**Current.**

Open with any combination of runtime options, including the required deployment. The other constructors are wrappers around this entry point and take the deployment as their last argument.

### `Marmot::new_with_experimental_device_groups`

The same open as `new_with_configuration`: every constructor opens with [device groups](README.md#device-groups) on. Kept so existing hosts keep compiling.

### `Marmot::new_with_options`

**Compatibility.** Prefer new_with_configuration when combining settings.

Open with an explicit relay policy and optional host-owned key storage. Existing constructors retain their public-only relay policy.

### `Marmot::new`

**Current.**

Open the Marmot app at `root_path`, configured with the given default relay URLs and `deployment`. Account secrets (Nostr private keys) are stored in the platform keyring (Keychain on Apple platforms, Android's native keyring on Android) under the deployment's `keychain_service` — not in a plaintext file. Fallible because initializing the platform secret store can fail or another process may own the same root (`MarmotKitError::RuntimeBusy`). Root ownership is nonblocking and remains held until the final `Marmot`/runtime handle is dropped, even after `Marmot::shutdown`. Call `Marmot::start` before subscribing to events.

### `Marmot::new_with_secret_store`

**Compatibility.** Prefer new_with_configuration when combining settings.

Open the Marmot app with host-supplied account-secret storage instead of the platform keychain. Identical to `Marmot::new` except that every read, write, and removal of an account signing key goes through `secret_store`.

### `Marmot::new_with_cursor_persistence`

**Compatibility.** Prefer new_with_configuration when combining settings.

Construct with explicit advancing/frozen relay cursor behavior; new_with_configuration composes this with other options.

### `Marmot::new_with_client_name`

**Compatibility.** Prefer new_with_configuration when combining settings.

Open with an optional public client label for new KeyPackage publications. Existing constructors remain untagged. Whitespace-only labels, and labels longer than 64 bytes once trimmed, are omitted rather than truncated. Hosts must supply this on every foreground/background runtime construction.

### `Marmot::start`

**Current.**

Bring the runtime to local readiness.

### `Marmot::shutdown`

**Current.**

Tear the runtime down. Drops all subscriptions; long-lived `EventsSubscription` / `ChatsSubscription` / etc. instances on the host side will see their `next()` return `None` shortly after.

### `Marmot::shutdown_and_close`

**Current.**

Terminally stop work, close storage and release root ownership; reconstruct before further reads/work.

### `Marmot::storage_is_closed`

**Current.**

True once `Marmot::shutdown_and_close` has closed the store. A host can check this to confirm it is safe to be suspended, or to notice it is holding a spent handle and needs a fresh one.

### `Marmot::is_stopping`

**Current.**

True once shutdown has started. Host apps can use this to avoid launching more subscriptions or account work while they are moving to the background.

</details>

<details>
<summary>secret_store.rs</summary>

### `SecretStore::has_secret_for_label`

**Host callback.**

Whether a credential is stored under `label`.

### `SecretStore::has_secret_for_account_id`

**Host callback.**

Whether a credential is stored under `account_id_hex`. Stores that key one credential per label report `false`.

### `SecretStore::write_secret`

**Host callback.**

Persist `secret_key_hex` for this account, replacing any existing credential.

### `SecretStore::load_secret`

**Host callback.**

Return the stored secret-key hex, or `MarmotKitError::SecretNotFound` when this account has no credential.

### `SecretStore::remove_secret`

**Host callback.**

Remove this account's credential. Removing a missing credential succeeds.

</details>

<details>
<summary>subscriptions/chat_window.rs</summary>

### `ChatListWindowSubscription::snapshot`

**Current.**

Take the initial complete replacement once, before driving next().

### `ChatListWindowSubscription::next`

**Current.**

One receiver per handle. Cancellation does not consume an update.

### `ChatListWindowSubscription::page`

**Current.**

1–100 rows, at most 200 retained. Uses the installed snapshot's sequence. This can run while next() waits; accepted commands survive caller cancellation.

### `ChatListWindowSubscription::set_visible_anchor`

**Current.**

Stable row identity, not pixel offset. A missing/outside anchor is rejected.

### `ChatListWindowSubscription::return_to_top`

**Current.**

Navigate the prepared chat list back to its current head with sequence validation.

### `AccountAttentionSubscription::snapshot`

**Current.**

Take the initial account set once. Unavailable entries never contain invented totals.

### `AccountAttentionSubscription::next`

**Current.**

Wait for the next value; None means the observation ended. Bind one receive loop to this handle.

</details>

<details>
<summary>subscriptions/conversation_window.rs</summary>

### `ConversationWindowSubscription::snapshot`

**Current.**

Take once before next(). Complete replacements include every visible identity.

### `ConversationWindowSubscription::next`

**Current.**

One receiver; cancellation leaves pending replacements available. Worker replacement is terminal: reopen the conversation after Closed/None with a fresh generation.

### `ConversationWindowSubscription::cancel`

**Current.**

Wake receivers/commands and release the retained runtime window. Idempotent. Drop the native object too when finished. Previously returned snapshots stay valid.

### `ConversationWindowSubscription::page`

**Current.**

1–200 rows, at most 200 retained; report a new visible anchor to page beyond saturated context. Zero timeout uses 30 seconds. After timeout/cancellation an accepted command may still complete through next(); refresh before retrying.

### `ConversationWindowSubscription::set_visible_anchor`

**Current.**

Report a row in the installed replacement, not a pixel offset. No read acknowledgement.

### `ConversationWindowSubscription::return_to_latest`

**Current.**

Resume following new arrivals. Retains the current row budget (up to 200).

### `ConversationWindowSubscription::jump_to_message`

**Current.**

Missing targets fail explicitly. Commands may run while next() waits.

</details>

<details>
<summary>subscriptions.rs</summary>

### `ChatsSubscription::snapshot`

**Lower-level.** For the corresponding lower-level subscription; use prepared screen windows for default chat UI.

Read the initial/current snapshot for this handle; follow its feature contract for one-shot versus repeatable reads.

### `ChatsSubscription::next`

**Lower-level.** For the corresponding lower-level subscription; use prepared screen windows for default chat UI.

Wait for the next value; None means the observation ended. Bind one receive loop to this handle.

### `ChatListSubscription::snapshot`

**Lower-level.** For the corresponding lower-level subscription; use prepared screen windows for default chat UI.

Read the initial/current snapshot for this handle; follow its feature contract for one-shot versus repeatable reads.

### `ChatListSubscription::next`

**Lower-level.** For the corresponding lower-level subscription; use prepared screen windows for default chat UI.

Legacy row-only update stream.

### `ChatListSubscription::next_update`

**Lower-level.** For the corresponding lower-level subscription; use prepared screen windows for default chat UI.

Typed update stream, including atomic full-list replacement snapshots.

### `MessagesSubscription::snapshot`

**Lower-level.** For the corresponding lower-level subscription; use prepared screen windows for default chat UI.

Read the initial/current snapshot for this handle; follow its feature contract for one-shot versus repeatable reads.

### `MessagesSubscription::next`

**Lower-level.** For the corresponding lower-level subscription; use prepared screen windows for default chat UI.

Wait for the next value; None means the observation ended. Bind one receive loop to this handle.

### `TimelineMessagesSubscription::snapshot`

**Lower-level.** For the corresponding lower-level subscription; use prepared screen windows for default chat UI.

Read the initial/current snapshot for this handle; follow its feature contract for one-shot versus repeatable reads.

### `TimelineMessagesSubscription::next`

**Lower-level.** For the corresponding lower-level subscription; use prepared screen windows for default chat UI.

Await the next live update and return the resulting authoritative window. Windowing (ordering, dedup, head-anchoring while scrolled back, and the cap) is owned by the runtime, so this returns exactly the bounded window pagination operates on — render it directly. Use `next_update`(Self::next_update) instead to receive the raw delta.

### `TimelineMessagesSubscription::next_update`

**Lower-level.** For the corresponding lower-level subscription; use prepared screen windows for default chat UI.

Consume raw timeline deltas or a replacement page. Use either next or next_update, not both; the host maintains delta ordering and bounds.

### `TimelineMessagesSubscription::paginate_backwards`

**Lower-level.** For the corresponding lower-level subscription; use prepared screen windows for default chat UI.

Extend the materialized window toward older history by up to `count` messages and return the new window. The returned page is already sorted, deduplicated, capped, and carries correct `has_more_before` / `has_more_after` flags — render it directly; no client-side merging or windowing is required. The store read runs off the caller thread and uses a different lock than `next()`, so a host driving `next()` on a background task can paginate without blocking (and this never blocks the UI thread, unlike the synchronous `Marmot::timeline_messages`).

### `TimelineMessagesSubscription::paginate_forwards`

**Lower-level.** For the corresponding lower-level subscription; use prepared screen windows for default chat UI.

Extend the materialized window toward the live head by up to `count` messages and return the new window. Reaching the head re-anchors the window (`has_more_after` becomes false). Same windowing/threading guarantees as `paginate_backwards`(Self::paginate_backwards).

### `GroupStateSubscription::snapshot`

**Current.**

Read the initial/current snapshot for this handle; follow its feature contract for one-shot versus repeatable reads.

### `GroupStateSubscription::next`

**Current.**

Wait for the next value; None means the observation ended. Bind one receive loop to this handle.

### `EventsSubscription::next`

**Current.**

Wait for the next value; None means the observation ended. Bind one receive loop to this handle.

### `NotificationsSubscription::next`

**Current.**

Wait for the next value; None means the observation ended. Bind one receive loop to this handle.

### `UserSearchSubscription::next_update`

**Current.**

Await the next step of the search, or `None` once it is over.

### `PresentedChatListSubscription::snapshot`

**Lower-level.** For the corresponding lower-level subscription; use prepared screen windows for default chat UI.

Take the initial snapshot once, with generation and sequence zero.

### `PresentedChatListSubscription::next`

**Lower-level.** For the corresponding lower-level subscription; use prepared screen windows for default chat UI.

Wait for the next value; None means the observation ended. Bind one receive loop to this handle.

</details>

<details>
<summary>Host-managed automatic attachment acquisition</summary>

### `Marmot::begin_attachment_permission_update`

Revoke automatic permission for this account before asynchronous network/preference evaluation. Returns a single-use runtime/account generation. Requires HostManaged construction; do not persist the token or mint a new one from a stale callback. See the [host-managed contract](ATTACHMENT-ACCESS.md#host-managed-automatic-acquisition-0104).

### `Marmot::request_automatic_attachment`

Submit idempotent automatic demand for an authoritative original source slot. Returns current status plus whether work was newly queued; preserves suppression, history, deadlines and retry budgets. Use from foreground and restored workers; never substitute explicit download-again or legacy downloadMedia after a local miss. See [Android migration](ATTACHMENT-ACCESS.md#android-migration).

### `Marmot::set_attachment_automatic_permission`

Apply media-category permission using the generation captured before evaluating host policy. False means stale, foreign or already consumed; it is not permission to retry with a fresh token. Approval is runtime-only and cannot override the durable automatic policy. See the [permission lifecycle](ATTACHMENT-ACCESS.md#host-managed-automatic-acquisition-0104).

</details>

<details>
<summary>Durable local sends and caller correlation</summary>

### `Marmot::local_send_status`

Read a retained submission's local state without relay I/O. `None` means no retained
association. `Completed` describes the worker attempt; inspect its summary disposition
and follow timeline updates for later delivery. `Queued` and `EngineOwned` name the
send's event (`message_id_hex`), so a host that lost the acceptance learns it by asking
rather than by submitting again. `RefusedNewMembers` is final: a send
limited to member accounts was not sent because the group has a member it leaves out.
See [local sends](LOCAL-SENDS.md).

### `Marmot::edit_local_message_with_client_token`

Durably admit a revision of an original text or reply submitted with a client
token, even while the original awaits relay publication. Use a new edit token
for each submitted revision. The return value is local acceptance, not
delivery; follow the edit token with `local_send_status` and preserve rejected
text for retry. The original token must belong to the same account and group.
See [pending edits](LOCAL-SENDS.md#edits-of-a-pending-local-send-0110).

### `Marmot::reply_to_message_with_client_token`

Durably admit a reply and bind its optimistic bubble to an opaque local token.
Returns local acceptance before relay publication. Repeating the original request
and token returns the same identity; changed requests are rejected. See [local sends](LOCAL-SENDS.md).

### `Marmot::send_message_draft_with_client_token`

Atomically consume exactly the supplied draft revision and retain its token-bound
message. Prepared attachments must match selected descriptors. Returns local
acceptance, not delivery; never clear a newer composer on completion. See [local sends](LOCAL-SENDS.md).

### `Marmot::send_prepared_media_with_client_token`

Admit an uploaded ordinary-media snapshot with its stable client token and optional captured draft revision. Conditional consumption is transactional, bound to ordered plaintext SHA-256 hashes, and preserves newer drafts. The method has no reply target. See the [captured-media contract](LOCAL-SENDS.md#captured-ordinary-media-drafts) for token replay, interruption recovery and matching bindings.

### `Marmot::send_custom_event_with_client_token`

Admit an app-defined event durably under `send_custom_event`'s rules, with the same
token correlation and status reporting as `send_text_with_client_token`. Use it for an
answer or a control sent to an agent (kind 1202): the same token after a restart returns
the same event and sends nothing, so a retried interrupt is not sent twice. See [local sends](LOCAL-SENDS.md).

### `Marmot::send_text_with_client_token`

Admit text durably outside the account publication queue. Use one token per logical
submission and reconcile by the exact token on timeline rows. Acceptance survives
caller cancellation and restart; delivery uses ordinary subscriptions. See [local sends](LOCAL-SENDS.md).

### `Marmot::submit_tagged_reply`

Durably admit a kind-9 inline reply with application tags. MDK supplies the
`e` and `q` tags from `target_message_id`. Use `submit_thread_message` for a
NIP-22 comment. See [retry and delivery status](LOCAL-SENDS.md).

### `Marmot::submit_tagged_sticker`

Durably admit a pack sticker with context tags. MDK checks the coordinate,
shortcode, and hash against the account's catalog. Do not supply a `sticker`
or `imeta` tag. See [retry and delivery status](LOCAL-SENDS.md).

### `Marmot::submit_tagged_text`

Durably admit a kind-9 text message with application tags. Do not pass
`imeta` tags. See [retry and delivery status](LOCAL-SENDS.md).

### `Marmot::submit_thread_message`

Durably admit a NIP-22 comment with text, uploaded attachments, or both.
MDK resolves `parent_message_id` in the local timeline and builds the placement
tags. Pass the attachment references with their upload epoch identity and in
display order. See [retry and delivery status](LOCAL-SENDS.md).

### `Marmot::upload_media_with_client_token`

Upload encrypted attachments and optionally admit the resulting token-bound message.
The result includes uploaded references and optional local acceptance. Uploads themselves
are not idempotent or restart-resumable; query token status after unknown outcomes.
See [local sends](LOCAL-SENDS.md) for cancellation and epoch-bound media handling.

### `Marmot::upload_media_files_with_client_token`

**C:** `marmot_upload_media_files_with_client_token`.

File-backed `upload_media_with_client_token`: every attachment is stored locally and uploaded before durable token admission; a source the disk cannot hold fails with `StorageFull` before anything is uploaded. Cancellation observed before admission starts returns an error and admits nothing. Once admission starts it is not interruptible, even before durable acceptance returns; follow `local_send_status` and timeline delivery, including uncertain-delivery handling. Admission rejects references from a source epoch that is no longer current with `MediaReferenceStaleEpoch` (upload again), and refuses while the group's epoch is unsettled with `MediaReferenceEpochUnsettled` (sync and send again). There is no fixed worker-response timeout; per-endpoint network deadlines still apply.

</details>

<details>
<summary>Stateless public-event verification</summary>

### `verify_public_nostr_event_json`

Verify both the canonical ID and BIP-340 signature of a public Nostr event.
This stateless helper needs no `Marmot` object or account and returns `false`
for malformed JSON or failed verification. It does not establish an allowed
author, kind, tag, relay provenance, or MLS group-membership policy; the host
must enforce those separately and bound any untrusted JSON before passing it.

</details>

<details>
<summary>Audit v5 tracker and configuration</summary>

### `Marmot::audit_delivery_status_v5`

Read each account's persisted v5 OTLP delivery status without dialing or touching the delivery cursor. Use it to show "audit delivery stalled since X: reason": `last_success_at_ms` against `last_failure`, whose `kind` separates local failures (`StateOverLimit`, `TooManyOpenFiles`, `LocalIo`, `LocalBlocked`) from receiver verdicts and whose `http_status` is set when the receiver answered. `paused` is true after `ReceiverBlocked` (for example `401`) for the configured destination; changing the destination, endpoint or token, or calling `post_audit_log_tracker_update_v5`, retries it. `ReceiverRejected` counts rows the receiver refused in `rejected_batches` while delivery continues. `backlog` is the last measured undelivered bytes, segments, gaps and oldest undelivered record time, as of `observed_at_ms`. Accounts that never ran a v5 pass report no failure and no backlog.

### `Marmot::post_audit_log_tracker_update_v5`

Run an immediate v5 OTLP delivery pass. Safe to call unconditionally: `enabled` reports the audit recording switch, and `v5` is absent when no dedicated sender is configured; when present, accepted batches, pending accounts, blocked accounts, and idle accounts report the delivery state. A manual pass also retries accounts whose automatic delivery is paused. Automatic activity triggers use the same v5 sender and retry policy.

### `Marmot::set_audit_otlp_config_v5`

Install or remove an in-memory v5 OTLP audit destination. With `enabled: true`, provide a stable destination identity, an HTTPS `/v1/logs` endpoint, and a bearer token; local loopback testing additionally requires `allow_loopback_dev: true`. The returned configuration always omits the token. With `enabled: false`, the runtime clears the sender. This does not enable recording or persist credentials. A configuration change fences in-flight acknowledgments.

</details>

<details>
<summary>Account attachment history</summary>

### `AccountAttachmentVersion::change_since`

Compare a freshly read account version with the original loaded-page baseline. RestartRequired discards loaded rows; Additions offers a head refresh while old-page cursors remain valid. The opaque value is not a row count; retain it in memory only.

### `Marmot::account_attachment_history_page`

Read at most 100 indexed attachment candidates across one local account with group, sender and inclusive date constraints. Empty filtered pages can have a continuation. Keep handles in memory, replace pages on RestartRequired, and use the typed metadata with the existing on-demand open/download APIs. See [Account attachment history](ACCOUNT-ATTACHMENT-HISTORY.md) for bounds and ownership.

### `Marmot::account_attachment_history_version`

Read the constant-work local account attachment change token, including after exhaustion. No network, acquisition or decryption starts. Keep the original loaded-page baseline and compare it using change_since; replace rows on RestartRequired and offer refresh on Additions.

</details>

<details>
<summary>Native startup diagnostics</summary>

### `Marmot::set_startup_diagnostics_enabled`

Explicitly enable or revoke bounded native progress for a diagnostic investigation. Capture is off by default and shared by clones of this app handle. It does not change database content, diagnostic-sharing/upload consent, network behavior or cryptographic settings. Re-enabling an already-enabled capture preserves its history; disabling clears it and fences in-flight observations from later captures. Enable before the first account policy read when diagnosing account opening.

### `Marmot::startup_diagnostics_snapshot`

Synchronously clone fixed native phases, monotonic durations and migration progress from independent memory. This does not query account storage or the keystore, and remains usable before `start` or while an account-opening future is blocked. At most 16 active scopes and 96 events are retained; drop counters expose truncation. Tokens are anonymous process-local scope numbers. No identifiers, paths, call arguments/results, keys or error messages are returned. Bound serialized host exports separately and collect only in an explicitly enabled diagnostic flow.

</details>

<details>
<summary>Public event previews</summary>

### `Marmot::cached_public_event_previews`

Network-free read of cached public Nostr events referenced from message content, for first-frame rendering of event cards. Pass up to 16 `note`, `nevent`, `naddr` or hex event-ID references, with or without `nostr:`; each gets one row in input order, duplicates included, echoing the reference. `Present` rows carry the signature-verified event JSON. `Deleted` means the author published a NIP-09 deletion; `Missing` is not durable, so call `resolve_public_event_preview`; `Unsupported` rows never resolve. More than 16 references fails with `InvalidPublicEventReferences`; split the batch. The cache is per account and survives restarts. A cold call may open the account's encrypted cache, so warm it off the UI thread. Read author names and avatars from `cached_identity_projections`.

### `Marmot::resolve_public_event_preview`

Keep this synchronous SQLCipher read off the UI thread. `ready` means a current compatible KeyPackage has not expired, not that a particular client is installed. `unknown` covers missing, stale, incomplete, malformed, replaced, and expired results. A completed clean, deleted, or obsolete miss is `not_found` for 15 minutes.
Fetch one referenced event from at most two safe relay hints plus the configured directory relays when it is missing or stale, store it if it verifies and matches, and return the resulting local state. An event-ID preview never refetches once every relay answered the fetch that cached it; otherwise, and for `naddr` previews, it refetches after 30 minutes. `naddr` keeps the newest version. Author-signed NIP-09 deletions apply in either tag form: an `e` tag removes that event (an `naddr` falls back to the previous version), an `a` tag removes every version up to its timestamp. Calls within 30 seconds of a finished fetch for the same reference return local state without network I/O, as does any call while the row is fresh, so call it for every reference a screen shows. A failed or empty fetch keeps prior content and stores no miss.

</details>

<details>
<summary>deployment.rs</summary>

### `marmot_deployment_neutral`

**Current free function.** Generated Swift/Kotlin name: `marmotDeploymentNeutral`. **C:** `marmot_deployment_neutral`.

A deployment with no services: recovery requires every relay on a route, onboarding searches only the host's discovery relays, there is no Open Ranking tier, moderation reporting refuses a destination, and the keychain service is `org.marmot-protocol.mdk`. With no media servers new groups stay text-only, and with no group-image server group images are refused. Start here and fill in the services your deployment operates.

### `marmot_deployment_white_noise`

**Current free function.** Generated Swift/Kotlin name: `marmotDeploymentWhiteNoise`. **C:** `marmot_deployment_white_noise`.

White Noise's deployment: its recovery relays, discovery indexers, media and image servers, Vertex Open Ranking, moderation label namespace and keychain service `com.marmot.whitenoise`. White Noise apps pass it to every constructor. Keep `keychain_service` unchanged for an existing install, or its account secrets are stranded.

</details>

<details>
<summary>Backup recovery and observation</summary>

### `BackupRestoreSubscription::next`

Wait for the next aggregate progress or availability revision; `None` means the worker closed. This receive is cancellation-safe. Closing the observer does not cancel restore; use the named operation command.

### `BackupRestoreSubscription::snapshot`

Take the initial status exactly once; later calls return `None`. Use `next` for changes or `backupRestoreStatus` for a fresh read. This observer owns neither recovery words nor the operation.

### `Marmot::backup_history_availability`

Read private words-again hints for a currently joined chat, using its variable-length MLS group id. A hint does not prove downloadable content or create membership. Re-read after a restore-watch revision or real join.

### `Marmot::backup_restore_status`

Read aggregate status without changing the operation. `Complete` means eligible work settled, not global completeness or proof that a pointer existed. Counts retain committed prefixes after cancellation.

### `Marmot::backup_settings`

Read the selected account backup settings, including whether this device writes. Use this authoritative read after setup or a concurrent setting change; submitting a change is not proof it remains selected.

### `Marmot::begin_backup_restore`

Start one ephemeral manual history-only restore per account from old recovery words. Only current own-leaf member chats can receive history; current keys and archived preferences stay unchanged. Keep the returned opaque operation token for cancellation. Clear host-owned word copies promptly; generated strings are not secure buffers.

### `Marmot::begin_recovery_words`

Generate twelve new words for backup setup and two 1-based confirmation positions. Show once and confirm answers in that order. Never persist or log the words; this is separate from restoring with existing words.

### `Marmot::cancel_backup_restore`

Cancel only the named account-scoped operation. A stale valid token returns false; a malformed token is rejected. Committed history remains. Retry requires words again; dropping a watch does not call this command.

### `Marmot::cancel_recovery_words`

Forget a pending recovery-word confirmation without changing existing account backups. Clear host-managed display/input copies separately.

### `Marmot::confirm_recovery_words`

Confirm the two requested words in position order. Busy or error results keep the core setup for another try. MDK guards its owned queued answers; caller/generated copies still need host handling. Read backup settings again to render the selected outcome.

### `Marmot::run_due_backup_pass`

Await one current or newly admitted due pass through serialized settlement and credit release. NotStarted means this call joined/admitted none; FinishedAttempt includes failed attempts and does not prove pointer publication. This neither forces work nor waits for future due work or global idleness. Cancelling the host await detaches only the waiter; worker stop/replacement returns TransportClosed. The host bounds its OS task lifetime; disabled device groups return NotStarted without starting a worker.

### `Marmot::set_runtime_backup_background_conditions`

Report the runtime-wide current Wi-Fi and charging facts before workers exist and on changes; both are required for background admission. The latest report survives account-worker replacement and intervals with no workers, while a new runtime starts closed. This requires no account and starts no worker; eligible reports wake existing due dispatchers. An admitted pass settles after false. Manual restore remains independent.

### `Marmot::set_backup_background_conditions`

Compatibility wrapper for the runtime-wide platform report. It validates the existing active, signable, fully onboarded account before changing the shared facts and never starts that account worker. Prefer the account-free runtime setter; no parameter or return layout changed. Admitted passes settle after false; manual restore is independent.

### `Marmot::turn_off_backups`

Disable future account backups through the selected account setting. Existing archives remain; this is not archive deletion or cancellation of an already admitted pass.

### `Marmot::watch_backup_restore`

Observe one initial snapshot and later progress/availability revisions. Closing the watch stops observation only. Keep its account context and cancel explicitly with the operation token when desired.

</details>

<details>
<summary>commands/emoji_set.rs</summary>

### `Marmot::emoji_set`

Reads one stored set by coordinate (`30030:<pubkey>:<d>`) or `naddr` without network I/O, on the blocking pool. Returns none when it is not stored; use `fetch_emoji_set` for an explicit network fetch.

### `Marmot::emoji_sets`

Reads the encrypted emoji set projection on the blocking pool, off the caller's thread. `installed_only` returns installed snapshots in install order; otherwise the newest discovered sets first. `search` matches title, description, author (hex or `npub`) and shortcodes. No network I/O.

### `Marmot::fetch_emoji_set`

Fetches one set from a pasted coordinate or `naddr`, trying up to 8 of the `naddr`'s relay hints and then the account relays, and stores it. Text only. Refused with `InvalidEmojiSet` for malformed input or a set with no valid emoji, `EmojiSetNotFound` when no relay has it.

### `Marmot::fetch_emoji_set_asset`

Downloads and validates one emoji of a stored set for a preview, with the same limits as install. Nothing is stored. Kept as its own call so the host can disclose it: it reveals the user's IP address to the image host the set's author chose, so call it only after the user opens the set. `expected_event_id_hex` is the `event_id_hex` of the version shown: when a sync or fetch has stored another version since, the call fails with `EmojiSetChanged` before any download.

### `Marmot::fetch_emoji_set_cover`

Downloads and validates a stored set's cover image (`image_url`, its `image` tag) under the emoji image limits, through the same hardened public fetch as `fetch_emoji_set_asset`. Nothing is stored. It reveals the user's IP address to the host the set's author chose, so call it only after the user opens the set, never from a list; MDK loads it so the host never fetches set images itself. `expected_event_id_hex` is the version shown: another stored version fails with `EmojiSetChanged` before any download. A set without a cover fails with `EmojiSetNotFound`.

### `Marmot::install_emoji_set`

Snapshots the stored set version (its event id), downloads each emoji once over hardened HTTPS (public hosts only, redirects re-checked), validates it (4 MiB, 4096 px per side, 200 frames, PNG/APNG, GIF, WebP or JPEG decided by the bytes; a response typed as a non-image such as `text/html` is refused, any `image/*` type is accepted) and stores the bytes and SHA-256 under the account. `expected_event_id_hex` binds the install to the version the user was shown, including a reinstall for `update_available`: another stored version fails with `EmojiSetChanged` (carrying `current_event_id_hex`) before any download, and nothing stored fails with `EmojiSetNotFound`; install never fetches the set itself. `control` (`EmojiSetInstallControlFfi`) reports progress and cancels; a cancelled install, or one stopped by runtime shutdown or close, fails with `EmojiSetInstallCancelled` and stores nothing, leaving any previous snapshot as it was. Invalid, duplicate, failed and over-cap entries are reported in `skipped`, not fatal. Reinstalling the installed version keeps each verified image whose refresh fails or does not fit; that entry stays installed, counts in `installed_count` and is not in `skipped`. A later change to the set's URLs or images never reaches the stored bytes until the user reinstalls. Caps: 50 installed sets, 500 emoji and 32 MiB per set, 128 MiB in all (`EmojiSetLimit`). Reveals the user's IP address to every image host in the set: call only after the user taps Install.

### `Marmot::installed_custom_emoji`

Every installed emoji, flattened in set install order then set order, for a picker: set coordinate and title, author, shortcode, MIME, dimensions, frames, SHA-256 and size. No URL. Shortcode collisions between installed sets are flagged with `shortcode_collision`, not resolved; host built-ins such as `marmot` and `wn` win in the host. No network I/O; the read runs on the blocking pool.

### `Marmot::read_installed_custom_emoji`

Reads an installed emoji's stored bytes (up to 4 MiB), checked against the SHA-256 recorded at install; a mismatch is an error, never other bytes. No network I/O; the read and hash run on the blocking pool. To use an emoji in a chat, upload these bytes as an encrypted attachment (`send_tagged_media`); never put the set's image URL or address in a message.

### `Marmot::sync_emoji_sets`

Fetches up to 60 of the newest kind-30030 sets from the account's relays (the sticker discovery relays), keeping only the newest version of each address and at most 16 versions per fetch. Sets with no valid emoji are hidden. A `search` that is an `npub` or hex public key narrows the fetch to that author. Text only: never fetches an image.

### `Marmot::uninstall_emoji_set`

Removes an installed snapshot and its stored bytes. Returns whether the set was installed. The discovered set stays in the projection. No network I/O.

### `Marmot::user_emoji_list`

Reads the account's own kind-10030 emoji list and the kind-30030 sets its `a` tags point to (at most 64), for suggestions. Its loose `emoji` tags come back as `own_emoji`, installable as the pseudo-set `10030:<pubkey>:`. Text only. MDK never publishes or edits kind 10030; it is a public list shared with other clients.

</details>

## Relay liveness

### `Marmot::account_relay_liveness`

Read every configured relay's canonical URL and current account-pool state without dialing.
Unobserved sessions are `Unknown`; closed configured sessions retain `Offline`. Optional attempt times and
bounded connection-error categories are session-local. See the [state and privacy contract](README.md#relay-liveness);
aggregate `relay_health` is unchanged.

### `Marmot::reconnect_relay`

Reconnect one configured relay through its running account worker after the normal dial-safety check, preserving existing
socket roles and ownership. New manual connections follow configured membership, independently of UI observers.
After dispatch, wait up to five seconds for the next observed attempt state, which may be `Connecting` rather than a successful
connection. Use the liveness subscription for the eventual outcome; this does not establish message delivery.

### `Marmot::subscribe_relay_liveness`

Open an account-scoped observer before reading its initial snapshot. Take `snapshot()` once, then apply each
`next()` list as a complete replacement. Updates follow socket, account-pool, and configured-list changes without
polling and may coalesce intermediate states. Close the observer when leaving the settings screen.

### `RelayLivenessSubscription::cancel`

Stop this observer and wake pending receives with `None`. Future receives also return `None`.
The call does not disconnect the account's relays; release the foreign handle separately.

### `RelayLivenessSubscription::next`

Wait for a complete replacement list. Slow consumers may skip intermediate states; cancellation does not consume
an update. `None` ends the stream after close or runtime shutdown. A read failure propagates as `MarmotKitError`
and ends this observer. Snapshot production runs on MDK's runtime, not the calling host thread.

### `RelayLivenessSubscription::snapshot`

Take the initial list once; subsequent calls return an empty list. An empty first list is valid for an account
without configured relay entries. This method does not consume a later update or initiate a connection.

## Account relay health

### `Marmot::account_relay_health`

Read the account's relay health from its cached inbox and NIP-65 lists, the dial policy and this process's inbox checks: one row per relay with its
roles, state, policy fault and liveness, and warnings about invitations sent through the published inbox list, each
with a severity, the relays it concerns and the actions that would fix it. Never dials. An inbox list MDK does not hold reads as
`inbox_list: Unknown` and raises no warning. Re-read on `RelayHealthChanged`. See the
[conditions for each warning](README.md#account-relay-health); keep a default branch over its enums.

### `Marmot::check_account_relays`

Ask the account's worker to check whether its inbox relays serve the account's inbox, then return
`account_relay_health` as it reads after the check. The worker gives each allowed inbox relay (the first 16 by URL) one
bounded read of the account's gift wraps (kind 1059 addressed to it) on a connection of its own, answered with the
signer it holds, within 15 seconds; a relay the policy refuses is never dialed. A remote or host signer may be asked to
sign a relay's authentication challenge, so call it from a user action for such an account. While a check of the
account runs it is refused at once with `RelayCheckRunning`; without a running account worker it fails as the account
not being active and dials nothing. A check in which no relay answered changes nothing. The returned health is the
answer; `RelayHealthChanged` follows a changed answer from the worker. See
[what each state means](README.md#account-relay-health).

<details>
<summary>nip46.rs</summary>

### `Marmot::nip46_new`

Create an offline MDK-owned session from a bunker URI, pairing config, or secret export. Review and approve permissions before URI access or connection. Imports do not silently approve grants. No host signer callback is retained; the handle belongs to its creating Marmot object.

[Session lifecycle](README.md#nip-46-accounts)

### `Marmot::nip46_login`

Create or reopen the external account using the verified shared signer and persist its communication credentials through MDK's configured secret store. Requires a successful explicit `connect` and an already-verified `Ready` session; other states are rejected without connecting, discovering relays, or creating an account. Messaging relay-list discovery and default publication follow external-signer login. Empty inbox relays reuse defaults. A session from another Marmot object returns `ExternalSignerMismatch` before network work.

Once Native adoption is admitted, caller cancellation only stops waiting; runtime-owned work continues. Pairing is a separate bounded, caller-cancellable `connect` call and makes no account changes while unbound. Explicit session cancel, disconnect, or logout interrupts adoption; shutdown interrupts and settles owned work before returning.

Adoption retains its admission generation through binding and network waits. A later explicit reconnect cannot resume adoption retired by disconnect.

Rollback does not reset newer-generation transport state or cancel its pending requests.

Before commit, a failed Native handoff restores the previous local callback and grant record without deleting pre-existing credentials. Completed accounts rebind without reopening setup and restore prior activation on failure. Already-published KeyPackages are not retracted. New and incomplete accounts retain pairing for possibly exposed publication retries. Post-commit journal cleanup errors do not revoke a network-ready account. Account sign-out cleanup remains explicit; legacy host login behavior is unchanged.

[Session lifecycle](README.md#nip-46-accounts)

### `Marmot::nip46_register`

Attach a verified imported session to an existing account, persist credentials, and activate the worker. A different attached session must be removed before replacement. A foreign-owner handle returns `ExternalSignerMismatch`. Ordinary cold startup restores MDK-owned sessions without this import path.

Admitted adoption outlives caller cancellation and is interrupted and settled by shutdown, as with `nip46_login`. If no prior callback exists, a verified pairing remains attached for recovery when worker startup fails.

[Session lifecycle](README.md#nip-46-accounts)

### `Marmot::nip46_resume`

Obtain the account's shared session from MDK-owned credentials, without a host descriptor or signer callback. Persisted approval is retained unchanged; changed required grants need explicit review. Startup restores local credentials before workers; a missing account-identity proof can require bounded remote signing.

[Session lifecycle](README.md#nip-46-accounts)

### `Marmot::nip46_remove`

Detach the account's shared session and remove its persisted communication credentials. This does not replace account sign-out or data wiping. The call keeps running when it is cancelled (mdk#3670).

[Session lifecycle](README.md#nip-46-accounts)

### `Nip46SessionFfi::permissions`

Read the currently required version and grants without recording review, approving access, or doing network work.

### `Nip46SessionFfi::review_permissions`

Record the exact required snapshot for user review. Review does not approve; display its version and grants before calling approval.

### `Nip46SessionFfi::approve_permissions`

Approve only the previously reviewed version and exact grant set after user consent. Missing review or changed grants return `PermissionApprovalRequired`. An imported descriptor, including one exported with approval metadata, does not grant access by itself. Bound account credential persistence runs on a blocking worker and finishes even if the foreign caller cancels its wait.

### `Nip46SessionFfi::connect`

Pair or reconnect, verify the pinned account public key, and adopt policy-checked signer relay changes. Returns user hex; messaging relays are unchanged. Requires permission approval. The independently driven native transport does not block the host or Tokio async workers. Cancelling a pending foreign call cancels its scoped request.

### `Nip46SessionFfi::pairing_offer`

Install the client-pairing listener and await relay subscription acknowledgements before returning the credential-bearing URI. Display that URI only after this call succeeds, then await connect while the pairing UI remains visible. Requires explicit permission approval and an unpaired client-initiated session. Cancellation retires the offer; obtain and display a fresh one before retrying.

### `Nip46SessionFfi::uri`

Return the credential-bearing pairing URI locally after permission approval. This accessor does not install a listener; use `pairing_offer` before displaying a client-initiated QR code. Never log or persist either URI as ordinary settings.

### `Nip46SessionFfi::export`

Export secret communication credentials and pinned identities as compatibility JSON for an optional encrypted-vault backup. MDK-owned resume does not require this export. Logged-out credentials cannot be exported.

### `Nip46SessionFfi::status`

Read local typed state, optional privacy-safe error, auth URL, request ID, and generation. No keys, pairing URI, or signer request payload is included. `Approval` is an intermediate challenge, not successful RPC completion.

### `Nip46SessionFfi::state_json`

Read the compatibility JSON status used by C. Existing state/detail/auth-url fields are retained with request, generation, and typed-error metadata. No network work.

### `Nip46SessionFfi::ping`

Check the remote signer through the independently driven shared transport. Failures retain the typed session reason. Cancelling a pending foreign call cancels its scoped request without terminally cancelling the session.

### `Nip46SessionFfi::disconnect`

Interrupt transport work and advance its generation while permitting explicit reconnection. Does not remove persisted credentials.

### `Nip46SessionFfi::cancel_request`

Cancel one matching pending request without cancelling the session. Stale IDs return `RequestNotFound`; other sessions are unaffected.

### `Nip46SessionFfi::complete_auth`

Acknowledge a matching auth challenge after reviewing its URL. The pending RPC still needs its final remote response. Stale IDs return `RequestNotFound`.

### `Nip46SessionFfi::cancel`

Permanently cancel this session and interrupt pending work, including synchronous identity-proof callbacks. Does not remove persisted credentials or revoke an optional saved export.

### `Nip46SessionFfi::logout`

Attempt bounded remote courtesy logout and erase the session's communication credentials even when no acknowledgement arrives or the foreign caller cancels its wait. Successful local erasure detaches the revoked signer so a fresh pairing can be registered in the same process. A vault deletion error stops signing but retains cleanup ownership; retry logout or account-level removal after the vault recovers. This does not sign out the MDK account; account sign-out already leaves attached handles logged out.

</details>

