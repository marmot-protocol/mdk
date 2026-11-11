# Complete Marmot C symbol reference

All **C functions declared in the generated header** are indexed below, including constructors,
commands, opaque-object operations, callbacks, free functions and compatibility shims.
Read [the C integration guide](README.md) first; this index does not replace its memory,
threading or error rules. The [shared method reference](../marmot-uniffi/API-REFERENCE.md)
provides runtime purposes and preferred/compatibility API selection. Use the exact header
from the same release as the library; signatures here use C spelling, not a guessed mapping
from camelCase. Full records, discriminants, callback typedefs and safety comments are in
[include/marmot.h](include/marmot.h).

C-only helpers manage allocation and object lifetime. A `*_free` takes ownership only as
specified by its header contract; do not free embedded members separately. `*_next` calls
block and use timeout/closed status values. Not all subscriptions expose callbacks or an
explicit cancel operation. The source parity allowlist deliberately excludes UniFFI's
three external-signer entry points: `register_external_signer`, `login_external_signer`,
and `begin_external_signer_onboarding`.

The concrete `marmot_nip46_*` session adapter exposes NIP-46 login and registration
without a general C signer callback interface. See the
[session lifecycle](README.md#nip-46-accounts) for mixed accounts and restart.

Prefer `marmot_client_new_with_configuration` when combining options, prepared chat and
conversation windows for standard screens, and attachment history/access/controls for
new media UI. Older primitives remain supported. `marmot_set_audit_log_tracker_config`
is a compatibility-only C shim: its old device-label field is ignored; new integrations
use `marmot_set_audit_log_tracker_config_v4` and system hardware-model metadata.

Each declaration links directly to its generated header documentation. Run
`just binding-docs-update` to refresh signatures and source anchors while preserving authored
prose, then review descriptions against the changed behavior. New methods require authored
guidance before their scaffold can pass. Removed/duplicate entries require explicit cleanup.
`just binding-docs-gate` checks names, signatures and source anchors and runs regression tests;
it does not validate prose. Counts are reported by the tool rather than duplicated here.

<details>
<summary>marmot_a…</summary>

### `marmot_answer_sign_in`

```c
MarmotStatus marmot_answer_sign_in(const struct MarmotClient *client, const char *account_ref, const char *slot_id_hex, uint32_t response);
```

Answer the unrecognized sign-in in `slot_id_hex`. `response` is a `MarmotSignInResponse` discriminant passed as `uint32_t`: `NotNow` keeps it listed with no prompt, `Reject` records it as rejected in the device group's roster (now, or once this device has a quiet device group), and `Dismiss` only ends a prompt another device already answered. An out-of-range `response` is `MARMOT_STATUS_INVALID_ARGUMENT`; refusals such as an unknown or already answered sign-in are device-group errors. Blocks on the account worker; a rejection may commit to the device group.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotanswer_sign_in) · [Header contract](include/marmot.h#L11410)

### `marmot_attachment_handoff_free`

```c
void marmot_attachment_handoff_free(struct MarmotAttachmentHandoff *ptr);
```

Free a `MarmotAttachmentHandoff` record and its strings. This frees memory only: it does not release the lease or delete the copy; call `marmot_release_attachment_handoff` for that. NULL is a no-op.

[Header contract](include/marmot.h#L7875)

### `marmot_attachment_local_asset_list_free`

```c
void marmot_attachment_local_asset_list_free(struct MarmotAttachmentLocalAssetList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L7855)

### `marmot_attachment_local_bytes_free`

```c
void marmot_attachment_local_bytes_free(struct MarmotAttachmentLocalBytes *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L7865)

### `marmot_attachment_local_assets`

```c
MarmotStatus marmot_attachment_local_assets(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const struct MarmotAttachmentLocalTarget *targets, uintptr_t targets_len, struct MarmotAttachmentLocalAssetList **out);
```

Look up up to 64 original slots in one group, preserving input order/duplicates. Does not load bytes, enqueue demand, start a worker or perform network work. # Safety Client/strings and targets[0..targets_len] must be live. Targets may be NULL only with zero length. Out must be writable. Inputs are borrowed, outputs owned.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotattachment_local_assets) · [Header contract](include/marmot.h#L7916)

### `marmot_attachment_entry_free`

```c
void marmot_attachment_entry_free(struct MarmotAttachmentEntry *ptr);
```

Deep-free one standalone owned entry returned by `marmot_reaction_attachment`, including all nested metadata. NULL is a no-op. Never pass a borrowed entry from an attachment page; the page owns those entries. The pointer must be NULL or an unfreed standalone result returned by this library.

[Header contract](include/marmot.h#L7931)

### `marmot_reaction_attachment`

```c
MarmotStatus marmot_reaction_attachment(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *reaction_message_id_hex, struct MarmotAttachmentEntry **out);
```

Bounded local lookup of one active custom-emoji reaction's matching encrypted artwork, keyed by the exact reaction event ID within the account and chat. Call off the UI thread. Writes an owned `MarmotAttachmentEntry`, or NULL with `MARMOT_STATUS_OK` when unavailable or unmatched. Use its original source target with ordinary attachment acquisition and opaque local reads, then free the standalone result with `marmot_attachment_entry_free`. Inputs are borrowed; the required out-pointer is cleared before work. The reaction ID is exactly 64 hexadecimal characters; malformed IDs return `MARMOT_STATUS_INVALID_MEDIA_REFERENCE`. See the [shared reaction lookup limits and adoption contract](../marmot-uniffi/ATTACHMENT-HISTORY.md#reaction-artwork).

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotreaction_attachment) · [Header contract](include/marmot.h#L7941)

### `marmot_attachment_page_read_free`

```c
void marmot_attachment_page_read_free(struct MarmotAttachmentPageRead *value);
```

Deep-free a page result and its cursor/version. NULL is a no-op. # Safety Value must be NULL or an owned result, not freed or borrowed by an active call.

[Header contract](include/marmot.h#L7952)

### `marmot_attachment_history_version_free`

```c
void marmot_attachment_history_version_free(struct MarmotAttachmentHistoryVersion *value);
```

Free a standalone version returned by a version read or clone, not a page field. # Safety Value must be NULL or a standalone owned version, with no active borrows.

[Header contract](include/marmot.h#L7959)

### `marmot_attachment_history_version_clone`

```c
MarmotStatus marmot_attachment_history_version_clone(const struct MarmotAttachmentHistoryVersion *value, struct MarmotAttachmentHistoryVersion **out);
```

Retain a standalone baseline version without retaining its owning page. Free the result with marmot_attachment_history_version_free. # Safety Value must be a live standalone version or borrowed page field; out must be writable.

[Header contract](include/marmot.h#L7967)

### `marmot_attachment_history_page`

```c
MarmotStatus marmot_attachment_history_page(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, uint32_t limit, const struct MarmotAttachmentHistoryCursor *cursor, struct MarmotAttachmentPageRead **out);
```

Blocking local read. Call off the UI thread; limit is 1..=100 slots. NULL cursor starts at the head. Cursor is borrowed for this call; no network work starts. # Safety Client and strings must be live; cursor must be NULL or live; out must be writable.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotattachment_history_page) · [Header contract](include/marmot.h#L7976)

### `marmot_attachment_history_version`

```c
MarmotStatus marmot_attachment_history_version(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotAttachmentHistoryVersion **out);
```

Blocking local revision read, including after exhaustion. Free the standalone result. # Safety Client/strings must be live and out writable.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotattachment_history_version) · [Header contract](include/marmot.h#L7988)

### `marmot_attachment_history_version_change_since`

```c
MarmotStatus marmot_attachment_history_version_change_since(const struct MarmotAttachmentHistoryVersion *current, const struct MarmotAttachmentHistoryVersion *previous, uint32_t *out);
```

Compare a current version with the retained baseline. Output is a MarmotAttachmentHistoryChange discriminant. # Safety Both versions must be live (standalone or borrowed page fields); out must be writable.

[Header contract](include/marmot.h#L7998)

### `marmot_account_unread_summary`

```c
MarmotStatus marmot_account_unread_summary(const struct MarmotClient *client, struct MarmotAccountUnreadList **out);
```

Per-account unread aggregates for the account-switcher badge. Free with `marmot_account_unread_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotaccount_unread_summary) · [Header contract](include/marmot.h#L8216)

### `marmot_approve_onboarding_repair_in_epoch`

```c
MarmotStatus marmot_approve_onboarding_repair_in_epoch(const struct MarmotClient *client, const char *account_ref, uint64_t revision, const char *recovery_epoch, struct MarmotOnboardingSnapshot **out);
```

Approve using the epoch and revision from the same displayed snapshot.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotapprove_onboarding_repair_in_epoch) · [Header contract](include/marmot.h#L8301)

### `marmot_acknowledge_onboarding_single_device_in_epoch`

```c
MarmotStatus marmot_acknowledge_onboarding_single_device_in_epoch(const struct MarmotClient *client, const char *account_ref, uint64_t revision, const char *recovery_epoch, struct MarmotOnboardingSnapshot **out);
```

Acknowledge the displayed device notice in a recovered attempt.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotacknowledge_onboarding_single_device_in_epoch) · [Header contract](include/marmot.h#L8316)

### `marmot_acknowledge_onboarding_single_device`

```c
MarmotStatus marmot_acknowledge_onboarding_single_device(const struct MarmotClient *client, const char *account_ref, uint64_t revision, struct MarmotOnboardingSnapshot **out);
```

Acknowledge the displayed one-device notice and resume setup.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotacknowledge_onboarding_single_device) · [Header contract](include/marmot.h#L8345)

### `marmot_account_nip65_relays`

```c
MarmotStatus marmot_account_nip65_relays(const struct MarmotClient *client, const char *account_ref, struct MarmotStringList **out);
```

The account's NIP-65 relay list. Free with `marmot_string_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotaccount_nip65_relays) · [Header contract](include/marmot.h#L8446)

### `marmot_account_inbox_relays`

```c
MarmotStatus marmot_account_inbox_relays(const struct MarmotClient *client, const char *account_ref, struct MarmotStringList **out);
```

The account's inbox relay list. Free with `marmot_string_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotaccount_inbox_relays) · [Header contract](include/marmot.h#L8460)

### `marmot_account_key_packages`

```c
MarmotStatus marmot_account_key_packages(const struct MarmotClient *client, const char *account_ref, const char *const *bootstrap_relays, uintptr_t bootstrap_relays_len, struct MarmotAccountKeyPackageList **out);
```

Local + current-slot relay-published KeyPackages for the account. Free with `marmot_account_key_package_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotaccount_key_packages) · [Header contract](include/marmot.h#L8474)

### `marmot_account_key_package_relay_events`

```c
MarmotStatus marmot_account_key_package_relay_events(const struct MarmotClient *client, const char *account_ref, const char *const *bootstrap_relays, uintptr_t bootstrap_relays_len, struct MarmotAccountKeyPackageRelayEventList **out);
```

Observed relay KeyPackage history, including superseded events. Free with `marmot_account_key_package_relay_event_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotaccount_key_package_relay_events) · [Header contract](include/marmot.h#L8523)

### `marmot_accept_group_invite`

```c
MarmotStatus marmot_accept_group_invite(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotAppGroupRecord **out);
```

Accept a pending group invite; writes the now-confirmed group record. Free with `marmot_app_group_record_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotaccept_group_invite) · [Header contract](include/marmot.h#L9617)

### `marmot_account_relay_lists`

```c
MarmotStatus marmot_account_relay_lists(const struct MarmotClient *client, const char *account_ref, struct MarmotAccountRelayLists **out);
```

The account's full relay-list state. Free with `marmot_account_relay_lists_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotaccount_relay_lists) · [Header contract](include/marmot.h#L10203)

### `marmot_attachment_storage_by_chat`

```c
MarmotStatus marmot_attachment_storage_by_chat(const struct MarmotClient *client, const char *account_ref, uint32_t limit, const struct MarmotChatStorageCursor *cursor, struct MarmotChatStoragePage **out);
```

Blocking largest-first chat listing, `limit` 1..=256. Pass NULL for the first page, then the previous page's `next_cursor`, keeping that page alive for the call; stop when it is NULL. Free each page with `marmot_chat_storage_page_free`, which frees its cursor too. See the [shared contract](../marmot-uniffi/API-REFERENCE.md#marmotattachment_storage_by_chat).

[Header contract](include/marmot.h#L8043)

### `marmot_attachment_storage_usage`

```c
MarmotStatus marmot_attachment_storage_usage(const struct MarmotClient *client, const char *account_ref, struct MarmotAttachmentStorageUsage **out);
```

Blocking account-wide storage summary; call off the UI thread. Free the result with `marmot_attachment_storage_usage_free`. See the [shared contract](../marmot-uniffi/API-REFERENCE.md#marmotattachment_storage_usage).

[Header contract](include/marmot.h#L8032)

### `marmot_attachment_storage_usage_free`

```c
void marmot_attachment_storage_usage_free(struct MarmotAttachmentStorageUsage *ptr);
```

Free a `MarmotAttachmentStorageUsage`. NULL is a no-op.

[Header contract](include/marmot.h#L8010)

### `marmot_audit_log_settings`

```c
MarmotStatus marmot_audit_log_settings(const struct MarmotClient *client, struct MarmotAuditLogSettings **out);
```

Current audit-log recorder settings. Free with `marmot_audit_log_settings_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotaudit_log_settings) · [Header contract](include/marmot.h#L10270)

### `marmot_audit_log_retention`

```c
MarmotStatus marmot_audit_log_retention(const struct MarmotClient *client, struct MarmotAuditLogRetention **out);
```

Current local audit-log retention policy. Free with `marmot_audit_log_retention_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotaudit_log_retention) · [Header contract](include/marmot.h#L10283)

### `marmot_audit_log_files`

```c
MarmotStatus marmot_audit_log_files(const struct MarmotClient *client, struct MarmotAuditLogFileList **out);
```

On-disk audit-log files. Free with `marmot_audit_log_file_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotaudit_log_files) · [Header contract](include/marmot.h#L10296)

### `marmot_account_follows`

```c
MarmotStatus marmot_account_follows(const struct MarmotClient *client, const char *account_ref, struct MarmotStringList **out);
```

The account ids this account follows (NIP-02). Free with `marmot_string_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotaccount_follows) · [Header contract](include/marmot.h#L10700)

### `marmot_acknowledge_disband_failure`

```c
MarmotStatus marmot_acknowledge_disband_failure(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, bool *out);
```

Acknowledge a failed disband request so the UI can stop surfacing it. Writes whether a request was actually cleared.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotacknowledge_disband_failure) · [Header contract](include/marmot.h#L10940)

### `marmot_account_setup_readiness`

```c
MarmotStatus marmot_account_setup_readiness(const struct MarmotClient *client, const char *account_ref, enum MarmotAccountSetupReadiness *out);
```

How far the account's setup has progressed.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotaccount_setup_readiness) · [Header contract](include/marmot.h#L11043)

### `marmot_account_id_hex`

```c
MarmotStatus marmot_account_id_hex(const struct MarmotClient *client, const char *reference, char **out);
```

Hex account id for an `npub`/hex/`nprofile` reference; NULL with `MARMOT_STATUS_OK` when the input does not decode. Accepts hex, `npub`, `nostr:npub`, `nprofile`, `nostr:nprofile`, and `marmot://profile/` links. nprofile relay hints are discarded. Duplicate type-0 TLV entries keep the first key. After wrapper normalization, encoded tokens longer than 1023 UTF-8 bytes are rejected; a valid 1023-byte token still decodes when wrapped. Free with `marmot_string_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotaccount_id_hex) · [Header contract](include/marmot.h#L11463)

### `marmot_app_performance_snapshot`

```c
MarmotStatus marmot_app_performance_snapshot(const struct MarmotClient *client, struct MarmotAppPerformanceSnapshot **out);
```

Process-wide performance counters. Aggregates only — no account, group, relay, or path information. Free with `marmot_app_performance_snapshot_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotapp_performance_snapshot) · [Header contract](include/marmot.h#L12160)

### `marmot_approve_onboarding_repair`

```c
MarmotStatus marmot_approve_onboarding_repair(const struct MarmotClient *client, const char *account_ref, uint64_t revision, struct MarmotOnboardingSnapshot **out);
```

Approve the proposal at the current snapshot revision and resume publication; stale revisions are rejected. Free the returned snapshot with `marmot_onboarding_snapshot_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotapprove_onboarding_repair) · [Header contract](include/marmot.h#L12332)

### `marmot_agent_publisher_new`

```c
MarmotStatus marmot_agent_publisher_new(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const struct MarmotPublisherOptions *options, struct MarmotAgentPublisher **out);
```

Anchor a new stream and return its publisher. Broker connection happens in the background. Invalid inputs/out-pointers fail before anchoring.

[Header contract](include/marmot.h#L13326)

### `marmot_agent_publisher_info`

```c
MarmotStatus marmot_agent_publisher_info(const struct MarmotAgentPublisher *publisher, struct MarmotPublisherInfo **out);
```

Read stream identifiers. Free with `marmot_publisher_info_free`.

[Header contract](include/marmot.h#L13338)

### `marmot_agent_publisher_append`

```c
MarmotStatus marmot_agent_publisher_append(const struct MarmotAgentPublisher *publisher, uint32_t kind, const char *text, struct MarmotPublisherAck **out);
```

Append one text/status/progress record; free the receipt with `marmot_publisher_ack_free`. Unknown record types fail before appending.

[Header contract](include/marmot.h#L13348)

### `marmot_agent_publisher_finish`

```c
MarmotStatus marmot_agent_publisher_finish(const struct MarmotAgentPublisher *publisher, struct MarmotSendSummary **out);
```

Seal and send the final transcript. Failed sends retain the sealed request for retry; a successful repeated call returns the original receipt. Free with `marmot_send_summary_free`. Inspect its delivery disposition.

[Header contract](include/marmot.h#L13361)

### `marmot_agent_publisher_cancel`

```c
MarmotStatus marmot_agent_publisher_cancel(const struct MarmotAgentPublisher *publisher);
```

Cancel the preview. Does not retract a final already being published.

[Header contract](include/marmot.h#L13370)

### `marmot_agent_publisher_free`

```c
void marmot_agent_publisher_free(struct MarmotAgentPublisher *publisher);
```

Release a publisher, requesting preview cancellation. NULL is a no-op.

[Header contract](include/marmot.h#L13379)

### `marmot_agent_stream_subscription_next`

```c
MarmotStatus marmot_agent_stream_subscription_next(const struct MarmotAgentStreamSubscription *sub, uint32_t timeout_ms, struct MarmotAgentStreamUpdate **out);
```

Block until the next item, the timeout, or stream close. `timeout_ms == 0` waits indefinitely. Returns `MARMOT_STATUS_OK` (out set; free with `marmot_agent_stream_update_free`), `MARMOT_STATUS_TIMEOUT`, or `MARMOT_STATUS_CLOSED` (out NULL for both).

[Header contract](include/marmot.h#L13930)

### `marmot_agent_stream_subscription_set_callback`

```c
MarmotStatus marmot_agent_stream_subscription_set_callback(const struct MarmotAgentStreamSubscription *sub, MarmotAgentStreamUpdateCallback callback, void *user_data);
```

Install a callback pump for this subscription. `callback` runs on a runtime worker thread with a borrowed item pointer (valid only during the call; do not store or free it) and a final NULL item on close. `callback` and `user_data` access must be thread-safe. Fails if a callback is already installed.

[Header contract](include/marmot.h#L13947)

### `marmot_agent_stream_subscription_clear_callback`

```c
MarmotStatus marmot_agent_stream_subscription_clear_callback(const struct MarmotAgentStreamSubscription *sub);
```

Request cancellation of this subscription's callback pump, if any. Non-blocking: a callback already running keeps executing after this returns (see the module docs).

[Header contract](include/marmot.h#L13959)

### `marmot_agent_stream_subscription_free`

```c
void marmot_agent_stream_subscription_free(struct MarmotAgentStreamSubscription *sub);
```

Free the subscription handle. Requests callback-pump cancellation without waiting (a callback may still be running after this returns — do not free `user_data` on that basis). NULL is a no-op. Free every handle before the client that created it.

[Header contract](include/marmot.h#L13971)

### `marmot_agent_stream_subscription_stream_id_hex`

```c
MarmotStatus marmot_agent_stream_subscription_stream_id_hex(const struct MarmotAgentStreamSubscription *sub, char **out_stream_id_hex);
```

The resolved stream id this watch is following (hex). Writes an owned copy: free it with `marmot_string_free`.

[Header contract](include/marmot.h#L14005)

### `marmot_attachment_transfer_subscription_next`

```c
MarmotStatus marmot_attachment_transfer_subscription_next(const struct MarmotAttachmentTransferSubscription *sub, uint32_t timeout_ms, struct MarmotAttachmentTransferSnapshot **out);
```

Initial snapshot then replacements, at most four per second. Zero timeout waits indefinitely. Timeout does not consume updates. Free results with marmot_attachment_transfer_snapshot_free. # Safety Sub must be live and out writable. Use one receiver per handle.

[Header contract](include/marmot.h#L14396)

### `marmot_attachment_transfer_subscription_cancel`

```c
MarmotStatus marmot_attachment_transfer_subscription_cancel(const struct MarmotAttachmentTransferSubscription *sub);
```

Close observation and wake receivers. Does not cancel downloads. # Safety Sub must remain live throughout the call.

[Header contract](include/marmot.h#L14405)

### `marmot_attachment_transfer_subscription_free`

```c
void marmot_attachment_transfer_subscription_free(struct MarmotAttachmentTransferSubscription *sub);
```

NULL-safe free. Already returned snapshots remain separately owned. # Safety Sub must be NULL or library-owned with no active calls.

[Header contract](include/marmot.h#L14412)

### `marmot_account_attention_subscription_snapshot`

```c
MarmotStatus marmot_account_attention_subscription_snapshot(const struct MarmotAccountAttentionSubscription *sub, struct MarmotAccountAttentionSnapshot **out);
```

Take the initial snapshot once; a second call returns CLOSED. Result must be deep-freed. # Safety sub must be live and out writable.

[Header contract](include/marmot.h#L14444)

### `marmot_account_attention_subscription_next`

```c
MarmotStatus marmot_account_attention_subscription_next(const struct MarmotAccountAttentionSubscription *sub, uint32_t timeout_ms, struct MarmotAccountAttentionSnapshot **out);
```

Receive a complete replacement. Zero timeout waits indefinitely. Timeout/error/closed leaves out NULL. Timeout does not consume an update. Free results with the matching snapshot_free. # Safety sub must remain live throughout the call; out must be writable. Use one receiver per handle.

[Header contract](include/marmot.h#L14453)

### `marmot_account_attention_subscription_free`

```c
void marmot_account_attention_subscription_free(struct MarmotAccountAttentionSubscription *sub);
```

Cancel and free. NULL is a no-op; does not free previously returned snapshots. # Safety sub must be NULL or a library-owned handle with no active calls.

[Header contract](include/marmot.h#L14462)

### `marmot_account_summary_free`

```c
void marmot_account_summary_free(struct MarmotAccountSummary *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L14739)

### `marmot_account_summary_list_free`

```c
void marmot_account_summary_list_free(struct MarmotAccountSummaryList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L14748)

### `marmot_account_unread_list_free`

```c
void marmot_account_unread_list_free(struct MarmotAccountUnreadList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L14757)

### `marmot_account_key_package_list_free`

```c
void marmot_account_key_package_list_free(struct MarmotAccountKeyPackageList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L14776)

### `marmot_account_key_package_inventory_entry_list_free`

```c
void marmot_account_key_package_inventory_entry_list_free(struct MarmotAccountKeyPackageInventoryEntryList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L14785)

### `marmot_account_key_package_relay_event_list_free`

```c
void marmot_account_key_package_relay_event_list_free(struct MarmotAccountKeyPackageRelayEventList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L14794)

### `marmot_agent_stream_start_free`

```c
void marmot_agent_stream_start_free(struct MarmotAgentStreamStart *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L14844)

### `marmot_agent_stream_update_free`

```c
void marmot_agent_stream_update_free(struct MarmotAgentStreamUpdate *update);
```

Free an agent-stream update returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L14852)

### `marmot_audit_log_settings_free`

```c
void marmot_audit_log_settings_free(struct MarmotAuditLogSettings *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L14862)

### `marmot_audit_log_retention_free`

```c
void marmot_audit_log_retention_free(struct MarmotAuditLogRetention *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L14872)

### `marmot_audit_log_tracker_config_v4_free`

```c
void marmot_audit_log_tracker_config_v4_free(struct MarmotAuditLogTrackerConfigV4 *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L14882)

### `marmot_audit_log_tracker_config_free`

```c
void marmot_audit_log_tracker_config_free(struct MarmotAuditLogTrackerConfig *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L14892)

### `marmot_audit_log_file_free`

```c
void marmot_audit_log_file_free(struct MarmotAuditLogFile *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L14902)

### `marmot_audit_log_file_list_free`

```c
void marmot_audit_log_file_list_free(struct MarmotAuditLogFileList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L14911)

### `marmot_audit_log_upload_result_free`

```c
void marmot_audit_log_upload_result_free(struct MarmotAuditLogUploadResult *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L14921)

### `marmot_audit_log_delete_result_free`

```c
void marmot_audit_log_delete_result_free(struct MarmotAuditLogDeleteResult *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L14931)

### `marmot_audit_log_tracker_update_result_free`

```c
void marmot_audit_log_tracker_update_result_free(struct MarmotAuditLogTrackerUpdateResult *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L14941)

### `marmot_app_group_record_free`

```c
void marmot_app_group_record_free(struct MarmotAppGroupRecord *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15334)

### `marmot_app_group_record_list_free`

```c
void marmot_app_group_record_list_free(struct MarmotAppGroupRecordList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15343)

### `marmot_app_group_member_record_list_free`

```c
void marmot_app_group_member_record_list_free(struct MarmotAppGroupMemberRecordList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15352)

### `marmot_app_group_mls_state_free`

```c
void marmot_app_group_mls_state_free(struct MarmotAppGroupMlsState *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15372)

### `marmot_app_quarantined_group_list_free`

```c
void marmot_app_quarantined_group_list_free(struct MarmotAppQuarantinedGroupList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15421)

### `marmot_app_group_member_ids_free`

```c
void marmot_app_group_member_ids_free(struct MarmotAppGroupMemberIds *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15451)

### `marmot_app_group_member_ids_list_free`

```c
void marmot_app_group_member_ids_list_free(struct MarmotAppGroupMemberIdsList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15460)

### `marmot_app_message_record_free`

```c
void marmot_app_message_record_free(struct MarmotAppMessageRecord *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15655)

### `marmot_app_message_record_list_free`

```c
void marmot_app_message_record_list_free(struct MarmotAppMessageRecordList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15664)

### `marmot_account_relay_lists_free`

```c
void marmot_account_relay_lists_free(struct MarmotAccountRelayLists *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15801)

### `marmot_app_performance_snapshot_free`

```c
void marmot_app_performance_snapshot_free(struct MarmotAppPerformanceSnapshot *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15936)

### `marmot_account_attention_snapshot_free`

```c
void marmot_account_attention_snapshot_free(struct MarmotAccountAttentionSnapshot *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L16074)

### `marmot_avatar_asset_free`

```c
void marmot_avatar_asset_free(struct MarmotAvatarAsset *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L16123)

### `marmot_avatar_asset_list_free`

```c
void marmot_avatar_asset_list_free(struct MarmotAvatarAssetList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L16132)

### `marmot_avatar_bytes_free`

```c
void marmot_avatar_bytes_free(struct MarmotAvatarBytes *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L16142)

### `marmot_avatar_bytes_list_free`

```c
void marmot_avatar_bytes_list_free(struct MarmotAvatarBytesList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L16151)

### `marmot_attachment_download_policy_free`

```c
void marmot_attachment_download_policy_free(struct MarmotAttachmentDownloadPolicy *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L16220)

### `marmot_attachment_transfer_snapshot_free`

```c
void marmot_attachment_transfer_snapshot_free(struct MarmotAttachmentTransferSnapshot *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L16230)

### `marmot_attachment_download_policy`

```c
MarmotStatus marmot_attachment_download_policy(const struct MarmotClient *client, const char *account_ref, struct MarmotAttachmentDownloadPolicy **out);
```

Read the effective durable policy. # Safety Client and strings must be live, out writable. Free the returned record.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotattachment_download_policy) · [Header contract](include/marmot.h#L16237)

### `marmot_attachment_transfer_snapshot`

```c
MarmotStatus marmot_attachment_transfer_snapshot(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const struct MarmotAttachmentLocalTarget *targets, uintptr_t targets_len, struct MarmotAttachmentTransferSnapshot **out);
```

Read up to 64 progress entries in input order. No network demand is created. # Safety Inputs must be live; targets may be NULL only for zero length; out writable.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotattachment_transfer_snapshot) · [Header contract](include/marmot.h#L16289)

### `marmot_group_app_component_free`

```c
void marmot_group_app_component_free(struct MarmotGroupAppComponent *ptr);
```

Free a record returned by `marmot_group_app_component`. NULL is a no-op.

[Header contract](include/marmot.h#L15305)

### `marmot_group_commit_delivery_free`

```c
void marmot_group_commit_delivery_free(struct MarmotGroupCommitDelivery *ptr);
```

Free a record returned by `marmot_group_commit_delivery`. NULL is a no-op.

[Header contract](include/marmot.h#L15315)

</details>

<details>
<summary>marmot_b…</summary>

### `marmot_bytes_free`

```c
void marmot_bytes_free(uint8_t *data, uintptr_t len);
```

Free a byte buffer returned by this library as a `(data, len)` pair (e.g. `marmot_download_group_blossom_image`). `(NULL, 0)` is a no-op.

[Header contract](include/marmot.h#L7794)

### `marmot_block_user`

```c
MarmotStatus marmot_block_user(const struct MarmotClient *client, const char *account_ref, const char *user_account_id_hex);
```

Block a user privately and publish the updated list. Requires relay synchronization.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotblock_user) · [Header contract](include/marmot.h#L10646)

### `marmot_build_media_imeta_tag`

```c
MarmotStatus marmot_build_media_imeta_tag(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const struct MarmotMediaAttachmentReference *reference, struct MarmotMessageTag **out);
```

Build the NIP-92 `imeta` tag for an already-uploaded attachment, so a host can compose the outgoing event itself. Free with `marmot_message_tag_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotbuild_media_imeta_tag) · [Header contract](include/marmot.h#L12036)

### `marmot_begin_onboarding`

```c
MarmotStatus marmot_begin_onboarding(const struct MarmotClient *client, const char *nsec, const char *const *default_relays, uintptr_t default_relays_len, const char *const *discovery_relays, uintptr_t discovery_relays_len, const char *const *inbox_relays, uintptr_t inbox_relays_len, struct MarmotOnboardingSnapshot **out);
```

Import an identity and persist its onboarding gate without publishing. Free the returned snapshot with `marmot_onboarding_snapshot_free`.

Snapshot findings include typed context, purpose, outcome, declared capability,
owned actions and optional observation revision. The snapshot free releases
those nested arrays. See [C diagnostic ownership](README.md#onboarding-relay-repair)
and the shared evidence limits before interpreting directory-query success.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotbegin_onboarding) · [Header contract](include/marmot.h#L12202)

### `marmot_block_list_subscription_next`

```c
MarmotStatus marmot_block_list_subscription_next(const struct MarmotBlockListSubscription *sub, uint32_t timeout_ms, struct MarmotBlockListSnapshot **out);
```

Block until the next item, the timeout, or stream close. `timeout_ms == 0` waits indefinitely. Returns `MARMOT_STATUS_OK` (out set; free with `marmot_block_list_snapshot_free`), `MARMOT_STATUS_TIMEOUT`, or `MARMOT_STATUS_CLOSED` (out NULL for both).

[Header contract](include/marmot.h#L14247)

### `marmot_block_list_subscription_set_callback`

```c
MarmotStatus marmot_block_list_subscription_set_callback(const struct MarmotBlockListSubscription *sub, MarmotBlockListCallback callback, void *user_data);
```

Install a callback pump for this subscription. `callback` runs on a runtime worker thread with a borrowed item pointer (valid only during the call; do not store or free it) and a final NULL item on close. `callback` and `user_data` access must be thread-safe. Fails if a callback is already installed.

[Header contract](include/marmot.h#L14264)

### `marmot_block_list_subscription_clear_callback`

```c
MarmotStatus marmot_block_list_subscription_clear_callback(const struct MarmotBlockListSubscription *sub);
```

Request cancellation of this subscription's callback pump, if any. Non-blocking: a callback already running keeps executing after this returns (see the module docs).

[Header contract](include/marmot.h#L14276)

### `marmot_block_list_subscription_free`

```c
void marmot_block_list_subscription_free(struct MarmotBlockListSubscription *sub);
```

Free the subscription handle. Requests callback-pump cancellation without waiting (a callback may still be running after this returns — do not free `user_data` on that basis). NULL is a no-op. Free every handle before the client that created it.

[Header contract](include/marmot.h#L14288)

### `marmot_block_list_subscription_snapshot`

```c
MarmotStatus marmot_block_list_subscription_snapshot(const struct MarmotBlockListSubscription *sub, struct MarmotBlockListSnapshot **out);
```

Take the initial snapshot once; subsequent calls return NULL. # Safety Subscription and output pointer must be valid.

[Header contract](include/marmot.h#L14304)

### `marmot_background_notification_collection_free`

```c
void marmot_background_notification_collection_free(struct MarmotBackgroundNotificationCollection *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15732)

### `marmot_blocked_user_list_free`

```c
void marmot_blocked_user_list_free(struct MarmotBlockedUserList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L16103)

### `marmot_block_list_snapshot_free`

```c
void marmot_block_list_snapshot_free(struct MarmotBlockListSnapshot *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L16113)

</details>

<details>
<summary>marmot_c…</summary>

### `marmot_chat_storage_page_free`

```c
void marmot_chat_storage_page_free(struct MarmotChatStoragePage *value);
```

Deep-free a chat storage page, its rows and its borrowed cursor. NULL is a no-op.

[Header contract](include/marmot.h#L8017)

### `marmot_check_sign_ins`

```c
MarmotStatus marmot_check_sign_ins(const struct MarmotClient *client, const char *account_ref, struct MarmotUnrecognizedSignInList **out);
```

Check the account's KeyPackage slots for new sign-ins now and write the list after the check; blocks on the account worker and the network. A read that reached no relay fails and leaves the list unchanged. Free the list with `marmot_unrecognized_sign_in_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotcheck_sign_ins) · [Header contract](include/marmot.h#L9410)

### `marmot_client_new_with_options`

```c
MarmotStatus marmot_client_new_with_options(const char *root_path, const char *const *relay_urls, uintptr_t relay_urls_len, uint32_t relay_policy, const struct MarmotSecretStore *store, const struct MarmotDeployment *deployment, struct MarmotClient **out_client);
```

Create a client with an explicit relay policy, optional host secret store and the required deployment. `store == NULL` selects the platform keychain. Loopback opt-in does not permit private/link-local relays or plaintext public endpoints. Ownership of the store transfers only on success, as with `marmot_client_new_with_secret_store`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotnew_with_options) · [Header contract](include/marmot.h#L7585)

### `marmot_client_new`

```c
MarmotStatus marmot_client_new(const char *root_path, const char *const *relay_urls, uintptr_t relay_urls_len, const struct MarmotDeployment *deployment, struct MarmotClient **out_client);
```

Create a Marmot client rooted at `root_path`, connected to `relay_urls` (`relay_urls_len` entries), for the required `deployment`, which is copied during the call. A NULL deployment returns `MARMOT_STATUS_NULL_POINTER` before anything opens. On success writes the new handle to `out_client`. Uses the platform keychain under the deployment's keychain service, matching the UniFFI constructor.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotnew) · [Header contract](include/marmot.h#L7608)

### `marmot_client_new_with_cursor_persistence`

```c
MarmotStatus marmot_client_new_with_cursor_persistence(const char *root_path, const char *const *relay_urls, uintptr_t relay_urls_len, uint32_t cursor_persistence, const struct MarmotDeployment *deployment, struct MarmotClient **out_client);
```

Create a Marmot client with an explicit durable transport-cursor policy. Identical to `marmot_client_new`, which is `MARMOT_CURSOR_PERSISTENCE_ADVANCE`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotnew_with_cursor_persistence) · [Header contract](include/marmot.h#L7631)

### `marmot_client_new_with_secret_store`

```c
MarmotStatus marmot_client_new_with_secret_store(const char *root_path, const char *const *relay_urls, uintptr_t relay_urls_len, const struct MarmotSecretStore *store, const struct MarmotDeployment *deployment, struct MarmotClient **out_client);
```

Create a Marmot client whose account signing keys live in caller-owned storage instead of the platform keychain. Otherwise identical to `marmot_client_new`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotnew_with_secret_store) · [Header contract](include/marmot.h#L7661)

### `marmot_client_new_with_client_name`

```c
MarmotStatus marmot_client_new_with_client_name(const char *root_path, const char *const *relay_urls, uintptr_t relay_urls_len, const char *client_name, uint32_t cursor_persistence, const struct MarmotSecretStore *store, const struct MarmotDeployment *deployment, struct MarmotClient **out_client);
```

Open with an optional public client name for newly prepared KeyPackages and the required deployment. NULL, whitespace-only or over-long (more than 64 bytes once trimmed) `client_name` omits the tag; it is never truncated. Signed retries keep their original tags. NULL `store` selects the platform keychain. Store ownership transfers only on success, as with `marmot_client_new_with_secret_store`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotnew_with_client_name) · [Header contract](include/marmot.h#L7682)

### `marmot_client_new_with_configuration`

```c
MarmotStatus marmot_client_new_with_configuration(const char *root_path, const char *const *relay_urls, uintptr_t relay_urls_len, const struct MarmotClientOptions *options, const struct MarmotDeployment *deployment, struct MarmotClient **out_client);
```

Create a client with combined relay, cursor, label and secret-storage options and the required deployment, copied during the call. NULL options uses defaults; a NULL deployment is refused, as with `marmot_client_new`. Store ownership transfers only on success, with the same callback lifetime contract as marmot_client_new_with_secret_store.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotnew_with_configuration) · [Header contract](include/marmot.h#L7706)

### `marmot_client_new_with_experimental_device_groups`

```c
MarmotStatus marmot_client_new_with_experimental_device_groups(const char *root_path, const char *const *relay_urls, uintptr_t relay_urls_len, const struct MarmotClientOptions *options, const struct MarmotDeployment *deployment, struct MarmotClient **out_client);
```

C entry point for the [explicit host test-build constructor](../marmot-uniffi/README.md#experimental-device-group-test-builds), with the same arguments and unchanged `MarmotClientOptions` layout as `marmot_client_new_with_configuration`. Required output validation and clearing happen first. A library without `dev-device-groups` returns `MARMOT_STATUS_RUNTIME` with `experimental_device_groups_unavailable` before reading other inputs, opening the root or taking callback ownership. Callback ownership transfers only on successful construction. Every opener of the experimental root needs this constructor: under `marmot_client_new_with_configuration`, an account that holds or is joining a device group does not open and returns `MARMOT_STATUS_RUNTIME` with `experimental_device_groups_required`. Follow the [C build and ownership guidance](README.md#experimental-device-group-test-builds); use matching generated headers/libraries.

[Header contract](include/marmot.h#L7723)

### `marmot_client_start`

```c
MarmotStatus marmot_client_start(const struct MarmotClient *client);
```

Start the runtime (reconcile accounts, start workers, subscribe transport). Must be called before subscribing.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotstart) · [Header contract](include/marmot.h#L7737)

### `marmot_client_shutdown`

```c
MarmotStatus marmot_client_shutdown(const struct MarmotClient *client);
```

Shut the runtime down. Open subscriptions drain and report `MARMOT_STATUS_CLOSED` from their next read.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotshutdown) · [Header contract](include/marmot.h#L7746)

### `marmot_client_is_stopping`

```c
MarmotStatus marmot_client_is_stopping(const struct MarmotClient *client, bool *out_stopping);
```

Whether the runtime is currently shutting down. Writes to `out_stopping`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotis_stopping) · [Header contract](include/marmot.h#L7754)

### `marmot_client_free`

```c
void marmot_client_free(struct MarmotClient *client);
```

Destroy a client handle. Call `marmot_client_shutdown` first for a graceful stop. NULL is a no-op. The handle must not be used afterwards.

[Header contract](include/marmot.h#L7767)

### `marmot_clear_avatar_cache`

```c
MarmotStatus marmot_clear_avatar_cache(const struct MarmotClient *client, const char *account_ref);
```

Remove this account's local avatar bytes and demand. Later visible requests may reacquire them.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotclear_avatar_cache) · [Header contract](include/marmot.h#L8191)

### `marmot_cancel_onboarding`

```c
MarmotStatus marmot_cancel_onboarding(const struct MarmotClient *client, const char *account_ref);
```

Cancel unfinished onboarding, retaining the signed-out identity and private state. Cancellation is valid at every interactive step, including approved or ready attempts. It performs no relay deletion.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotcancel_onboarding) · [Header contract](include/marmot.h#L8361)

### `marmot_create_identity`

```c
MarmotStatus marmot_create_identity(const struct MarmotClient *client, const char *const *default_relays, uintptr_t default_relays_len, const char *const *bootstrap_relays, uintptr_t bootstrap_relays_len, const char *const *inbox_relays, uintptr_t inbox_relays_len, struct MarmotAccountSummary **out);
```

Create a brand-new Nostr identity, store its secret in the account secret store, and publish initial relay lists + key package. Free with `marmot_account_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotcreate_identity) · [Header contract](include/marmot.h#L8374)

### `marmot_start_direct_chat`

```c
MarmotStatus marmot_start_direct_chat(const struct MarmotClient *client, const char *account_ref, const char *peer_account_id, char **out);
```

Blocks on the shared explicit direct-conversation start operation. `account_ref` and the hex or npub `peer_account_id` are borrowed NUL-terminated UTF-8 strings. `out` is required and receives an owned hex MLS group id on success; free it with `marmot_string_free`. Success confirms canonical local state, not Welcome delivery. Local reuse, retry recovery, founding admins, concurrent starts, and legacy role limits follow the shared contract.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotstart_direct_conversation)

[Header contract](include/marmot.h#L8669)

### `marmot_create_group`

```c
MarmotStatus marmot_create_group(const struct MarmotClient *client, const char *account_ref, const char *name, const char *const *member_refs, uintptr_t member_refs_len, const char *description, char **out);
```

Create a new MLS group with `name` and the given members (referenced by `npub` or hex account id). Writes the new group id as a hex string; free it with `marmot_string_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotcreate_group) · [Header contract](include/marmot.h#L8685)

### `marmot_confirm_group_rejoin`

```c
MarmotStatus marmot_confirm_group_rejoin(const struct MarmotClient *client, const char *account_ref, const char *welcome_id_hex, const char *local_state_token, struct MarmotGroupRecoveryStatus **out);
```

Only after explicit recipient consent. Free with marmot_group_recovery_status_free.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotconfirm_group_rejoin) · [Header contract](include/marmot.h#L8988)

### `marmot_catch_up_accounts`

```c
MarmotStatus marmot_catch_up_accounts(const struct MarmotClient *client);
```

One-time catch-up across every running account (e.g. after a push wake).

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotcatch_up_accounts) · [Header contract](include/marmot.h#L10103)

### `marmot_clear_push_registration`

```c
MarmotStatus marmot_clear_push_registration(const struct MarmotClient *client, const char *account_ref, struct MarmotPushRegistrationShareOutcome **out);
```

Remove the account's push registration and share the removal. Free with `marmot_push_registration_share_outcome_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotclear_push_registration) · [Header contract](include/marmot.h#L10174)

### `marmot_chat_list`

```c
MarmotStatus marmot_chat_list(const struct MarmotClient *client, const char *account_ref, uint8_t include_archived, struct MarmotChatListRowList **out);
```

The account's chat list rows. Free with `marmot_chat_list_row_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotchat_list) · [Header contract](include/marmot.h#L10376)

### `marmot_chat_notification_settings`

```c
MarmotStatus marmot_chat_notification_settings(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotChatNotificationSettings **out);
```

The conversation's local mute state. Free with `marmot_chat_notification_settings_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotchat_notification_settings) · [Header contract](include/marmot.h#L10501)

### `marmot_clear_chat_muted`

```c
MarmotStatus marmot_clear_chat_muted(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotChatNotificationSettings **out);
```

Unmute a conversation. Free with `marmot_chat_notification_settings_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotclear_chat_muted) · [Header contract](include/marmot.h#L10534)

### `marmot_chat_list_row`

```c
MarmotStatus marmot_chat_list_row(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotChatListRow **out);
```

The durable chat-list row for one group; writes NULL with `MARMOT_STATUS_OK` when the group has no row. Free with `marmot_chat_list_row_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotchat_list_row) · [Header contract](include/marmot.h#L10815)

### `marmot_clear_group_image`

```c
MarmotStatus marmot_clear_group_image(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotSendSummary **out);
```

Clear the group's encrypted Blossom avatar by committing the absent image component. Requires admin. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotclear_group_image) · [Header contract](include/marmot.h#L10859)

### `marmot_client_shutdown_and_close`

```c
MarmotStatus marmot_client_shutdown_and_close(const struct MarmotClient *client);
```

Shut the runtime down and release every local file lock, so a host can suspend without leaving the database leased. The client handle stays valid but the runtime is finished.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotshutdown_and_close) · [Header contract](include/marmot.h#L11032)

### `marmot_create_identity_with_profile`

```c
MarmotStatus marmot_create_identity_with_profile(const struct MarmotClient *client, const char *const *default_relays, uintptr_t default_relays_len, const char *const *bootstrap_relays, uintptr_t bootstrap_relays_len, const char *const *inbox_relays, uintptr_t inbox_relays_len, struct MarmotIdentityCreationResult **out);
```

Create a fresh identity and publish a default profile in one step. Free with `marmot_identity_creation_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotcreate_identity_with_profile) · [Header contract](include/marmot.h#L11057)

### `marmot_create_identity_with_initial_profile`

```c
MarmotStatus marmot_create_identity_with_initial_profile(const struct MarmotClient *client, const struct MarmotUserProfileMetadata *profile, const char *const *default_relays, uintptr_t default_relays_len, const char *const *bootstrap_relays, uintptr_t bootstrap_relays_len, const char *const *inbox_relays, uintptr_t inbox_relays_len, struct MarmotIdentityCreationResult **out);
```

Create a fresh identity whose first public kind-0 is `profile`, returning at durable local readiness. Prefer it over `marmot_create_identity_with_profile` plus `marmot_publish_user_profile` when onboarding collects a name, so contacts never see the generated default. `profile` is borrowed and never freed by the library. Free the result with `marmot_identity_creation_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotcreate_identity_with_initial_profile) · [Header contract](include/marmot.h#L11615)

### `marmot_cached_identity_projections`

```c
MarmotStatus marmot_cached_identity_projections(const struct MarmotClient *client, const char *const *account_id_hexes, uintptr_t account_id_hexes_len, struct MarmotCachedIdentityProjectionList **out);
```

What the local directory cache holds for each requested id, one row per request in order. Free with `marmot_cached_identity_projection_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotcached_identity_projections) · [Header contract](include/marmot.h#L11111)

### `marmot_create_group_detailed`

```c
MarmotStatus marmot_create_group_detailed(const struct MarmotClient *client, const char *account_ref, const char *name, const char *const *member_refs, uintptr_t member_refs_len, const char *description, struct MarmotCreatedGroup **out);
```

`marmot_create_group` plus the new chat-list row in one round trip. Free with `marmot_created_group_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotcreate_group_detailed) · [Header contract](include/marmot.h#L11206)

### `marmot_create_group_with_prepared_initial_image`

```c
MarmotStatus marmot_create_group_with_prepared_initial_image(const struct MarmotClient *client, const char *account_ref, const char *name, const char *const *member_refs, uintptr_t member_refs_len, const char *description, const char *upload_id, char **out);
```

Create a group whose avatar is an already-staged prepared image. Writes the new group id as a hex string; free it with `marmot_string_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotcreate_group_with_prepared_initial_image) · [Header contract](include/marmot.h#L11316)

### `marmot_collect_notifications_after_wake`

```c
MarmotStatus marmot_collect_notifications_after_wake(const struct MarmotClient *client, uint32_t max_wait_ms, uint32_t source, struct MarmotBackgroundNotificationCollection **out);
```

Run a bounded background collection pass after a push wake. `source` is a `MarmotNotificationWakeSource` discriminant; out-of-range values are rejected with `MARMOT_STATUS_INVALID_ARGUMENT`. Free with `marmot_background_notification_collection_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotcollect_notifications_after_wake) · [Header contract](include/marmot.h#L11816)

### `marmot_create_group_with_options`

```c
MarmotStatus marmot_create_group_with_options(const struct MarmotClient *client, const char *account_ref, const char *name, const char *const *member_refs, uintptr_t member_refs_len, const struct MarmotCreateGroupOptions *options, char **out);
```

Create a group with the options struct: description, an optional initial avatar, and disappearing-message retention. Writes the new group id as a hex string; free it with `marmot_string_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotcreate_group_with_options) · [Header contract](include/marmot.h#L11940)

### `marmot_create_group_with_options_detailed`

```c
MarmotStatus marmot_create_group_with_options_detailed(const struct MarmotClient *client, const char *account_ref, const char *name, const char *const *member_refs, uintptr_t member_refs_len, const struct MarmotCreateGroupOptions *options, struct MarmotCreatedGroup **out);
```

`marmot_create_group_with_options` plus the new chat-list row in one round trip. Free with `marmot_created_group_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotcreate_group_with_options_detailed) · [Header contract](include/marmot.h#L11955)

### `marmot_create_group_with_initial_image`

```c
MarmotStatus marmot_create_group_with_initial_image(const struct MarmotClient *client, const char *account_ref, const char *name, const char *const *member_refs, uintptr_t member_refs_len, const char *description, const struct MarmotInitialGroupImage *initial_image, char **out);
```

Create a group with an inline initial avatar. `initial_image` may be NULL for no image. Writes the new group id as a hex string; free it with `marmot_string_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotcreate_group_with_initial_image) · [Header contract](include/marmot.h#L11974)

### `marmot_create_group_with_initial_image_detailed`

```c
MarmotStatus marmot_create_group_with_initial_image_detailed(const struct MarmotClient *client, const char *account_ref, const char *name, const char *const *member_refs, uintptr_t member_refs_len, const char *description, const struct MarmotInitialGroupImage *initial_image, struct MarmotCreatedGroup **out);
```

`marmot_create_group_with_initial_image` plus the new chat-list row in one round trip. Free with `marmot_created_group_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotcreate_group_with_initial_image_detailed) · [Header contract](include/marmot.h#L11990)

### `marmot_classify_relay_endpoints`

```c
MarmotStatus marmot_classify_relay_endpoints(const struct MarmotClient *client, const char *const *endpoints, uintptr_t endpoints_len, struct MarmotRelayEndpointClassificationList **out);
```

Classify relay endpoints against the dial-safety and retired-relay policies without dialing any of them. Free with `marmot_relay_endpoint_classification_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotclassify_relay_endpoints) · [Header contract](include/marmot.h#L12147)

### `marmot_continue_onboarding_without`

```c
MarmotStatus marmot_continue_onboarding_without(const struct MarmotClient *client, const char *account_ref, uint32_t step, struct MarmotOnboardingSnapshot **out);
```

Explicitly skip an optional profile or follows step when offered. `step` is a MarmotOnboardingStep discriminant; out-of-range values return MARMOT_STATUS_INVALID_ARGUMENT. Free the returned snapshot with `marmot_onboarding_snapshot_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotcontinue_onboarding_without) · [Header contract](include/marmot.h#L12252)

### `marmot_cancel_onboarding_repair`

```c
MarmotStatus marmot_cancel_onboarding_repair(const struct MarmotClient *client, const char *account_ref, struct MarmotOnboardingSnapshot **out);
```

Dismiss an unapproved repair proposal; an approved repair must be resumed. Free the returned snapshot with `marmot_onboarding_snapshot_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotcancel_onboarding_repair) · [Header contract](include/marmot.h#L12343)

### `marmot_content_reports`

```c
MarmotStatus marmot_content_reports(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *message_id, const char *after, uint32_t limit, struct MarmotContentReportPage **out);
```

# Safety `client` must be a live handle; string arguments must be valid NUL-terminated strings (nullable ones may be NULL); array arguments must hold their stated length (or be NULL with length 0); out-pointers must be valid.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotcontent_reports) · [Header contract](include/marmot.h#L12784)

### `marmot_chats_subscription_next`

```c
MarmotStatus marmot_chats_subscription_next(const struct MarmotChatsSubscription *sub, uint32_t timeout_ms, struct MarmotAppGroupRecord **out);
```

Block until the next item, the timeout, or stream close. `timeout_ms == 0` waits indefinitely. Returns `MARMOT_STATUS_OK` (out set; free with `marmot_app_group_record_free`), `MARMOT_STATUS_TIMEOUT`, or `MARMOT_STATUS_CLOSED` (out NULL for both).

[Header contract](include/marmot.h#L13618)

### `marmot_chats_subscription_set_callback`

```c
MarmotStatus marmot_chats_subscription_set_callback(const struct MarmotChatsSubscription *sub, MarmotAppGroupRecordCallback callback, void *user_data);
```

Install a callback pump for this subscription. `callback` runs on a runtime worker thread with a borrowed item pointer (valid only during the call; do not store or free it) and a final NULL item on close. `callback` and `user_data` access must be thread-safe. Fails if a callback is already installed.

[Header contract](include/marmot.h#L13635)

### `marmot_chats_subscription_clear_callback`

```c
MarmotStatus marmot_chats_subscription_clear_callback(const struct MarmotChatsSubscription *sub);
```

Request cancellation of this subscription's callback pump, if any. Non-blocking: a callback already running keeps executing after this returns (see the module docs).

[Header contract](include/marmot.h#L13647)

### `marmot_chats_subscription_free`

```c
void marmot_chats_subscription_free(struct MarmotChatsSubscription *sub);
```

Free the subscription handle. Requests callback-pump cancellation without waiting (a callback may still be running after this returns — do not free `user_data` on that basis). NULL is a no-op. Free every handle before the client that created it.

[Header contract](include/marmot.h#L13659)

### `marmot_chats_subscription_snapshot`

```c
MarmotStatus marmot_chats_subscription_snapshot(const struct MarmotChatsSubscription *sub, struct MarmotAppGroupRecordList **out_list);
```

Take the initial chats snapshot. Yields the populated list exactly once: later calls write an EMPTY list, still with `MARMOT_STATUS_OK`. Free the list with `marmot_app_group_record_list_free`.

[Header contract](include/marmot.h#L13683)

### `marmot_chat_list_subscription_next`

```c
MarmotStatus marmot_chat_list_subscription_next(const struct MarmotChatListSubscription *sub, uint32_t timeout_ms, struct MarmotChatListRow **out);
```

Block until the next item, the timeout, or stream close. `timeout_ms == 0` waits indefinitely. Returns `MARMOT_STATUS_OK` (out set; free with `marmot_chat_list_row_free`), `MARMOT_STATUS_TIMEOUT`, or `MARMOT_STATUS_CLOSED` (out NULL for both).

[Header contract](include/marmot.h#L13692)

### `marmot_chat_list_subscription_set_callback`

```c
MarmotStatus marmot_chat_list_subscription_set_callback(const struct MarmotChatListSubscription *sub, MarmotChatListRowCallback callback, void *user_data);
```

Install a callback pump for this subscription. `callback` runs on a runtime worker thread with a borrowed item pointer (valid only during the call; do not store or free it) and a final NULL item on close. `callback` and `user_data` access must be thread-safe. Fails if a callback is already installed.

[Header contract](include/marmot.h#L13709)

### `marmot_chat_list_subscription_clear_callback`

```c
MarmotStatus marmot_chat_list_subscription_clear_callback(const struct MarmotChatListSubscription *sub);
```

Request cancellation of this subscription's callback pump, if any. Non-blocking: a callback already running keeps executing after this returns (see the module docs).

[Header contract](include/marmot.h#L13721)

### `marmot_chat_list_subscription_free`

```c
void marmot_chat_list_subscription_free(struct MarmotChatListSubscription *sub);
```

Free the subscription handle. Requests callback-pump cancellation without waiting (a callback may still be running after this returns — do not free `user_data` on that basis). NULL is a no-op. Free every handle before the client that created it.

[Header contract](include/marmot.h#L13733)

### `marmot_chat_list_subscription_snapshot`

```c
MarmotStatus marmot_chat_list_subscription_snapshot(const struct MarmotChatListSubscription *sub, struct MarmotChatListRowList **out_list);
```

Take the initial chat-list snapshot. Yields the populated list exactly once: later calls write an EMPTY list, still with `MARMOT_STATUS_OK`. Free with `marmot_chat_list_row_list_free`.

[Header contract](include/marmot.h#L13756)

### `marmot_chat_list_subscription_next_update`

```c
MarmotStatus marmot_chat_list_subscription_next_update(const struct MarmotChatListSubscription *sub, uint32_t timeout_ms, struct MarmotChatListSubscriptionUpdate **out_update);
```

Block until the next raw chat-list delta (row upsert or removal). Free with `marmot_chat_list_subscription_update_free`.

[Header contract](include/marmot.h#L13766)

### `marmot_chat_list_window_subscription_snapshot`

```c
MarmotStatus marmot_chat_list_window_subscription_snapshot(const struct MarmotChatListWindowSubscription *sub, struct MarmotChatListWindowSnapshot **out);
```

Take the initial snapshot once; a second call returns CLOSED. Result must be deep-freed. # Safety sub must be live and out writable.

[Header contract](include/marmot.h#L14419)

### `marmot_chat_list_window_subscription_next`

```c
MarmotStatus marmot_chat_list_window_subscription_next(const struct MarmotChatListWindowSubscription *sub, uint32_t timeout_ms, struct MarmotChatListWindowSnapshot **out);
```

Receive a complete replacement. Zero timeout waits indefinitely. Timeout/error/closed leaves out NULL. Timeout does not consume an update. Free results with the matching snapshot_free. # Safety sub must remain live throughout the call; out must be writable. Use one receiver per handle.

[Header contract](include/marmot.h#L14428)

### `marmot_chat_list_window_subscription_free`

```c
void marmot_chat_list_window_subscription_free(struct MarmotChatListWindowSubscription *sub);
```

Cancel and free. NULL is a no-op; does not free previously returned snapshots. # Safety sub must be NULL or a library-owned handle with no active calls.

[Header contract](include/marmot.h#L14437)

### `marmot_chat_list_window_subscription_page`

```c
MarmotStatus marmot_chat_list_window_subscription_page(const struct MarmotChatListWindowSubscription *sub, uint64_t sequence, uint32_t direction, uint32_t count, struct MarmotChatListWindowSnapshot **out);
```

Apply a window command to the current viewport, returning a complete replacement. May run while next waits. Background content changes keep a sequence usable; one older than a published viewport move, or not yet published, returns CHAT_WINDOW_STALE. The same completion also arrives through next; deduplicate by generation/sequence. # Safety sub must be live, any input string valid, and out writable. Never free during a call.

[Header contract](include/marmot.h#L14507)

### `marmot_chat_list_window_subscription_set_visible_anchor`

```c
MarmotStatus marmot_chat_list_window_subscription_set_visible_anchor(const struct MarmotChatListWindowSubscription *sub, uint64_t sequence, const char *group_id_hex, struct MarmotChatListWindowSnapshot **out);
```

Apply a window command to the current viewport, returning a complete replacement. May run while next waits. Background content changes keep a sequence usable; one older than a published viewport move, or not yet published, returns CHAT_WINDOW_STALE, as does an older sequence whose anchor row a background replacement dropped. The same completion also arrives through next; deduplicate by generation/sequence. # Safety sub must be live, any input string valid, and out writable. Never free during a call.

[Header contract](include/marmot.h#L14522)

### `marmot_chat_list_window_subscription_return_to_top`

```c
MarmotStatus marmot_chat_list_window_subscription_return_to_top(const struct MarmotChatListWindowSubscription *sub, uint64_t sequence, struct MarmotChatListWindowSnapshot **out);
```

Apply a window command to the current viewport, returning a complete replacement. May run while next waits. Background content changes keep a sequence usable; one older than a published viewport move, or not yet published, returns CHAT_WINDOW_STALE. The same completion also arrives through next; deduplicate by generation/sequence. # Safety sub must be live, any input string valid, and out writable. Never free during a call.

[Header contract](include/marmot.h#L14535)

### `marmot_conversation_window_subscription_snapshot`

```c
MarmotStatus marmot_conversation_window_subscription_snapshot(const struct MarmotConversationWindowSubscription *sub, struct MarmotConversationWindowSnapshot **out);
```

Take the initial snapshot once; a second call returns CLOSED. Result must be deep-freed. # Safety sub must be live and out writable.

[Header contract](include/marmot.h#L14544)

### `marmot_conversation_window_subscription_next`

```c
MarmotStatus marmot_conversation_window_subscription_next(const struct MarmotConversationWindowSubscription *sub, uint32_t timeout_ms, struct MarmotConversationWindowSnapshot **out);
```

Receive a complete replacement. Zero timeout waits indefinitely. Timeout/error/closed leaves out NULL. Timeout does not consume an update. Free results with the matching snapshot_free. # Safety sub must remain live throughout the call; out must be writable. Use one receiver per handle.

[Header contract](include/marmot.h#L14553)

### `marmot_conversation_window_subscription_free`

```c
void marmot_conversation_window_subscription_free(struct MarmotConversationWindowSubscription *sub);
```

Cancel and free. NULL is a no-op; does not free previously returned snapshots. # Safety sub must be NULL or a library-owned handle with no active calls.

[Header contract](include/marmot.h#L14562)

### `marmot_conversation_window_subscription_cancel`

```c
MarmotStatus marmot_conversation_window_subscription_cancel(const struct MarmotConversationWindowSubscription *sub);
```

Close and wake pending receivers/commands. Idempotent; does not free this handle or snapshots. # Safety sub must remain live throughout all calls; free only after active calls return.

[Header contract](include/marmot.h#L14569)

### `marmot_conversation_window_subscription_page`

```c
MarmotStatus marmot_conversation_window_subscription_page(const struct MarmotConversationWindowSubscription *sub, const struct MarmotConversationWindowRevision *revision, uint32_t direction, uint32_t count, uint32_t timeout_ms, struct MarmotConversationWindowSnapshot **out);
```

Apply against the installed revision. May run while next waits; deduplicate completions by generation/sequence. Zero timeout uses 30 seconds. Accepted commands may complete after timeout through next; refresh before retrying. Extend history around the visible anchor; paging preserves that anchor at the retained-row cap. # Safety sub and borrowed revision/strings must remain live; out writable. Never free during a call.

[Header contract](include/marmot.h#L14595)

### `marmot_conversation_window_subscription_set_visible_anchor`

```c
MarmotStatus marmot_conversation_window_subscription_set_visible_anchor(const struct MarmotConversationWindowSubscription *sub, const struct MarmotConversationWindowRevision *revision, const char *message_id_hex, uint32_t timeout_ms, struct MarmotConversationWindowSnapshot **out);
```

Apply against the installed revision. May run while next waits; deduplicate completions by generation/sequence. Zero timeout uses 30 seconds. Accepted commands may complete after timeout through next; refresh before retrying. Report a row in the installed window as the visible anchor; this does not acknowledge reads or encode pixel offsets. # Safety sub and borrowed revision/strings must remain live; out writable. Never free during a call.

[Header contract](include/marmot.h#L14610)

### `marmot_conversation_window_subscription_jump_to_message`

```c
MarmotStatus marmot_conversation_window_subscription_jump_to_message(const struct MarmotConversationWindowSubscription *sub, const struct MarmotConversationWindowRevision *revision, const char *message_id_hex, uint32_t timeout_ms, struct MarmotConversationWindowSnapshot **out);
```

Apply against the installed revision. May run while next waits; deduplicate completions by generation/sequence. Zero timeout uses 30 seconds. Accepted commands may complete after timeout through next; refresh before retrying. Center the window on a retained message; a missing target fails explicitly. # Safety sub and borrowed revision/strings must remain live; out writable. Never free during a call.

[Header contract](include/marmot.h#L14624)

### `marmot_conversation_window_subscription_return_to_latest`

```c
MarmotStatus marmot_conversation_window_subscription_return_to_latest(const struct MarmotConversationWindowSubscription *sub, const struct MarmotConversationWindowRevision *revision, uint32_t timeout_ms, struct MarmotConversationWindowSnapshot **out);
```

Apply against the installed revision. May run while next waits; deduplicate completions by generation/sequence. Zero timeout uses 30 seconds. Accepted commands may complete after timeout through next; refresh before retrying. Move to the latest message and resume following arrivals, retaining the current row budget. # Safety sub and borrowed revision/strings must remain live; out writable. Never free during a call.

[Header contract](include/marmot.h#L14638)

### `marmot_clear_message_draft_if_revision`

```c
MarmotStatus marmot_clear_message_draft_if_revision(const struct MarmotClient *client, const char *account_ref, const struct MarmotMessageDraftRevision *revision, struct MarmotSelectedMessageDraft **out);
```

Clear only this selected revision; later edits are preserved. # Safety client, account and revision valid; revision's owning snapshot/draft must remain live; out writable.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotclear_message_draft_if_revision) · [Header contract](include/marmot.h#L14669)

### `marmot_chat_pin_state_free`

```c
void marmot_chat_pin_state_free(struct MarmotChatPinState *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15039)

### `marmot_chat_notification_settings_free`

```c
void marmot_chat_notification_settings_free(struct MarmotChatNotificationSettings *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15049)

### `marmot_chat_list_row_free`

```c
void marmot_chat_list_row_free(struct MarmotChatListRow *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15059)

### `marmot_chat_list_row_list_free`

```c
void marmot_chat_list_row_list_free(struct MarmotChatListRowList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15068)

### `marmot_chat_list_subscription_update_free`

```c
void marmot_chat_list_subscription_update_free(struct MarmotChatListSubscriptionUpdate *update);
```

Free a chat-list delta returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15076)

### `marmot_cached_identity_projection_free`

```c
void marmot_cached_identity_projection_free(struct MarmotCachedIdentityProjection *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15123)

### `marmot_cached_identity_projection_list_free`

```c
void marmot_cached_identity_projection_list_free(struct MarmotCachedIdentityProjectionList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15132)

### `marmot_created_group_free`

```c
void marmot_created_group_free(struct MarmotCreatedGroup *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15441)

### `marmot_chat_list_window_snapshot_free`

```c
void marmot_chat_list_window_snapshot_free(struct MarmotChatListWindowSnapshot *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L16064)

### `marmot_conversation_window_snapshot_free`

```c
void marmot_conversation_window_snapshot_free(struct MarmotConversationWindowSnapshot *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L16094)

### `marmot_content_report_page_free`

```c
void marmot_content_report_page_free(struct MarmotContentReportPage *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L16171)

### `marmot_request_explicit_attachment`

```c
MarmotStatus marmot_request_explicit_attachment(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const struct MarmotAttachmentLocalTarget *target, char **out);
```

Blocking equivalent of [explicit demand](../marmot-uniffi/API-REFERENCE.md#marmotrequest_explicit_attachment). Joins/promotes without resetting budgets, backoff or active deadlines. Inputs are borrowed; free the optional opaque result with `marmot_string_free`. NULL means unavailable/suppressed, not a transfer failure. Use separate Retry/Download again operations for deliberate recovery.

[Header contract](include/marmot.h#L16267)

### `marmot_control_attachment`

```c
MarmotStatus marmot_control_attachment(const struct MarmotClient *client, const char *account_ref, const char *reference, uint32_t control, bool *out);
```

Apply a MarmotAttachmentControl discriminant to an opaque reference. # Safety Client/strings must be live and out writable. No inputs are retained.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotcontrol_attachment) · [Header contract](include/marmot.h#L16255)

### `marmot_cancel_device_link`

```c
MarmotStatus marmot_cancel_device_link(const struct MarmotClient *client, const char *account_ref, struct MarmotDeviceLinkSnapshot **out);
```

On the new device, request cancellation of the link. This does not guarantee notification of the other device: cancellation while waiting in `Joining` can end locally without sending a cancellation message. Free the snapshot with `marmot_device_link_snapshot_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotcancel_device_link) · [Header contract](include/marmot.h#L9535)

### `marmot_compromise_warning`

```c
MarmotStatus marmot_compromise_warning(const struct MarmotClient *client, const char *account_ref, struct MarmotCompromiseWarningItemList **out);
```

List the account's open compromise warning on this device, each item the user has not seen here, the earliest gathered first; blocks on the account worker without network I/O. An empty list means no warning is open. Each `MarmotCompromiseWarningItem` carries its `reason`, the `slot_id_hex` the item names, `key_package_ref_hex` (set only for `MARMOT_COMPROMISE_WARNING_REASON_FOREIGN_OWN_SLOT_KEY_PACKAGE`) and `occurred_at`. `reason` is a `MarmotCompromiseWarningReason` discriminant carried as `uint32_t`: later releases add values, so show one the host does not know as a generic reason. Always empty without explicit dev capability and runtime intent. Re-read on `MARMOT_EVENT_COMPROMISE_WARNING_CHANGED`. Free the list with `marmot_compromise_warning_item_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotcompromise_warning) · [Header contract](include/marmot.h#L9459)

### `marmot_compromise_warning_item_list_free`

```c
void marmot_compromise_warning_item_list_free(struct MarmotCompromiseWarningItemList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15103)

### `marmot_confirm_device_link_match`

```c
MarmotStatus marmot_confirm_device_link_match(const struct MarmotClient *client, const char *account_ref, struct MarmotDeviceLinkSnapshot **out);
```

On the new device, record that the user says both screens show the same emoji. Free the snapshot with `marmot_device_link_snapshot_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotconfirm_device_link_match) · [Header contract](include/marmot.h#L9521)

</details>

<details>
<summary>marmot_d…</summary>

### `marmot_delete_account_key_package`

```c
MarmotStatus marmot_delete_account_key_package(const struct MarmotClient *client, const char *account_ref, const char *event_id_hex, const char *const *relays, uintptr_t relays_len, uint64_t *out);
```

Publish a NIP-09 deletion for a KeyPackage event. Writes the accepting-relay count.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotdelete_account_key_package) · [Header contract](include/marmot.h#L8583)

### `marmot_delete_group_local`

```c
MarmotStatus marmot_delete_group_local(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, bool *out);
```

Delete this group's local app data without an MLS leave. Cancel active UI subscriptions for the group first. MLS state stays intact; a future fresh delivery can recreate a chat row. Writes true if any local rows or a live route were removed.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotdelete_group_local) · [Header contract](include/marmot.h#L8836)

### `marmot_decline_group_rejoin`

```c
MarmotStatus marmot_decline_group_rejoin(const struct MarmotClient *client, const char *account_ref, const char *welcome_id_hex);
```

Decline the selected replacement offer without changing active group state.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotdecline_group_rejoin) · [Header contract](include/marmot.h#L9003)

### `marmot_dismiss_compromise_warning`

```c
MarmotStatus marmot_dismiss_compromise_warning(const struct MarmotClient *client, const char *account_ref);
```

Dismiss the compromise warning on this device: everything it gathers now is marked seen here, and it stays closed until a new rejection arrives; blocks on the account worker. Other devices' warnings are unchanged. While device groups are off it is refused with a device-group error.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotdismiss_compromise_warning) · [Header contract](include/marmot.h#L9474)

### `marmot_dismiss_history_notice`

```c
MarmotStatus marmot_dismiss_history_notice(const struct MarmotClient *client, const char *account_ref, const char *notice_id, bool *out);
```

Dismiss one "history may be incomplete" notice after the user accepts it; blocks until the account worker has durably retired that occurrence as its own outcome, never as recovered history. Writes true on retirement and false for a stale id (new evidence re-armed recovery, or it was already dismissed). A malformed id returns `MARMOT_STATUS_INVALID_HEX`. No network I/O.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotdismiss_history_notice) · [Header contract](include/marmot.h#L9049)

### `marmot_decline_group_invite`

```c
MarmotStatus marmot_decline_group_invite(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotGroupInviteDeclineResult **out);
```

Decline a pending group invite; writes the updated group record plus the decline publish summary. An invitee the invite made an admin fails with `MARMOT_STATUS_ADMIN_CANNOT_SELF_REMOVE` until `marmot_self_demote_admin`, unless experimental device groups are on. Free with `marmot_group_invite_decline_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotdecline_group_invite) · [Header contract](include/marmot.h#L9635)

### `marmot_download_group_blossom_image`

```c
MarmotStatus marmot_download_group_blossom_image(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, uint8_t **out_data, uintptr_t *out_len);
```

Fetch, verify, and decrypt the group's Blossom-hosted encrypted image. Needs a relay/Blossom, so it fails offline. Free the buffer with `marmot_bytes_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotdownload_group_blossom_image) · [Header contract](include/marmot.h#L9687)

### `marmot_demote_admin`

```c
MarmotStatus marmot_demote_admin(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *member_ref, struct MarmotSendSummary **out);
```

Revoke `member_ref`'s admin rights. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotdemote_admin) · [Header contract](include/marmot.h#L9719)

### `marmot_demote_admin_detailed`

```c
MarmotStatus marmot_demote_admin_detailed(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *member_ref, struct MarmotGroupMutationResult **out);
```

`marmot_demote_admin` plus refreshed details and management state. Free with `marmot_group_mutation_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotdemote_admin_detailed) · [Header contract](include/marmot.h#L9801)

### `marmot_delete_message`

```c
MarmotStatus marmot_delete_message(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *target_message_id, struct MarmotSendSummary **out);
```

Request deletion of an own message. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotdelete_message) · [Header contract](include/marmot.h#L10054)

### `marmot_delete_audit_log_file`

```c
MarmotStatus marmot_delete_audit_log_file(const struct MarmotClient *client, const char *path, struct MarmotAuditLogDeleteResult **out);
```

Delete one on-disk audit-log file. Free with `marmot_audit_log_delete_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotdelete_audit_log_file) · [Header contract](include/marmot.h#L10324)

### `marmot_download_profile_image`

```c
MarmotStatus marmot_download_profile_image(const struct MarmotClient *client, const char *url, uint64_t max_bytes, uint8_t **out_data, uintptr_t *out_len);
```

Fetch a profile image by URL, refusing anything over `max_bytes`. Free the buffer with `marmot_bytes_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotdownload_profile_image) · [Header contract](include/marmot.h#L10798)

### `marmot_delete_message_draft`

```c
MarmotStatus marmot_delete_message_draft(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex);
```

Discard the stored draft for a conversation. Absent is not an error.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotdelete_message_draft) · [Header contract](include/marmot.h#L10844)

### `marmot_disband_group`

```c
MarmotStatus marmot_disband_group(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotDisbandRequest **out);
```

Request terminal disbanding of the group. Writes this account's durable request outcome; free it with `marmot_disband_request_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotdisband_group) · [Header contract](include/marmot.h#L10925)

### `marmot_display_name`

```c
MarmotStatus marmot_display_name(const struct MarmotClient *client, const char *account_id_hex, char **out);
```

Best-effort display name for an account id from the local directory cache; writes NULL with `MARMOT_STATUS_OK` when unknown. Free with `marmot_string_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotdisplay_name) · [Header contract](include/marmot.h#L11436)

### `marmot_default_profile_pseudonym`

```c
MarmotStatus marmot_default_profile_pseudonym(const struct MarmotClient *client, const char *account_id_hex, char **out);
```

Deterministic cosmetic display name for a canonical hex account id. Free with `marmot_string_free`. Decode a scanned reference with `marmot_account_id_hex` first; the seed is hashed as supplied text.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotdefault_profile_pseudonym) · [Header contract](include/marmot.h#L11475)

### `marmot_download_media`

```c
MarmotStatus marmot_download_media(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const struct MarmotMediaAttachmentReference *reference, struct MarmotMediaDownloadResult **out);
```

Download, verify, and decrypt one attachment. Free with `marmot_media_download_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotdownload_media) · [Header contract](include/marmot.h#L11770)

### `marmot_dismiss_reports`

```c
MarmotStatus marmot_dismiss_reports(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *const *report_ids, uintptr_t report_ids_len, const char *explanation, struct MarmotSendSummary **out);
```

# Safety `client` must be a live handle; string arguments must be valid NUL-terminated strings (nullable ones may be NULL); array arguments must hold their stated length (or be NULL with length 0); out-pointers must be valid.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotdismiss_reports) · [Header contract](include/marmot.h#L12754)

### `marmot_disband_request_free`

```c
void marmot_disband_request_free(struct MarmotDisbandRequest *request);
```

Free a disband request returned by `marmot_disband_group`. NULL is a no-op. (Embedded copies inside a chat row are released by the row.)

[Header contract](include/marmot.h#L15324)

### `marmot_download_attachment_again`

```c
MarmotStatus marmot_download_attachment_again(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const struct MarmotAttachmentLocalTarget *target, char **out);
```

Explicitly request the current slot, including after cancellation/removal. NULL result is unavailable. # Safety Client, strings and target must be live; out writable. Free returned string with marmot_string_free.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotdownload_attachment_again) · [Header contract](include/marmot.h#L16278)

### `marmot_decline_device_link`

```c
MarmotStatus marmot_decline_device_link(const struct MarmotClient *client, const char *account_ref, const char *prompt_id, struct MarmotDeviceLinkSnapshot **out);
```

On a device already signed in, Not now for the prompt `prompt_id`. Free the snapshot with `marmot_device_link_snapshot_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotdecline_device_link) · [Header contract](include/marmot.h#L9586)

### `marmot_device_link_snapshot`

```c
MarmotStatus marmot_device_link_snapshot(const struct MarmotClient *client, const char *account_ref, struct MarmotDeviceLinkSnapshot **out);
```

Linking as this device shows it now, changing nothing. `new_device` is NULL unless this device asked to be linked; `prompts` lists the sign-ins it can link. The states are C tagged unions: `Comparing` carries `code`/`code_len` emoji, `CannotLink` carries `missing`/`missing_len` strings, and `AddedElsewhere` carries both labels. Re-read on `MARMOT_EVENT_DEVICE_LINK_CHANGED`. Free with `marmot_device_link_snapshot_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotdevice_link_snapshot) · [Header contract](include/marmot.h#L9603)

### `marmot_device_link_snapshot_free`

```c
void marmot_device_link_snapshot_free(struct MarmotDeviceLinkSnapshot *ptr);
```

Free a snapshot returned by this library, with every nested emoji, string and prompt. NULL is a no-op.

[Header contract](include/marmot.h#L15113)

</details>

<details>
<summary>marmot_e…</summary>

### `marmot_export_encrypted_secret_key`

```c
MarmotStatus marmot_export_encrypted_secret_key(const struct MarmotClient *client, const char *account_ref, const char *passphrase, char **out);
```

Export the account's private key NIP-49-encrypted under `passphrase`. Free with `marmot_string_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotexport_encrypted_secret_key) · [Header contract](include/marmot.h#L8652)

### `marmot_edit_message`

```c
MarmotStatus marmot_edit_message(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *target_message_id, const char *content, struct MarmotSendSummary **out);
```

Edit an own message's content. Returns `MARMOT_STATUS_INVALID_EDIT_TARGET` unless the target is an available chat message this account sent. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotedit_message) · [Header contract](include/marmot.h#L10071)

### `marmot_account_devices_activation`

```c
MarmotStatus marmot_account_devices_activation(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, enum MarmotAccountDevicesActivation *out);
```

Whether the account can turn on account-devices in the group now, written to `out`. Ask before offering `marmot_enable_account_devices`. The answer is about the whole group, never which members or devices hold it back.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotaccount_devices_activation) · [Header contract](include/marmot.h#L10891)

### `marmot_enable_account_devices`

```c
MarmotStatus marmot_enable_account_devices(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotGroupMutationResult **out);
```

Turn on account-devices in one admin Commit, only when the user asks; it can never be turned off. Returns `MARMOT_STATUS_ACCOUNT_DEVICES_ACTIVATION_REFUSED` unless `marmot_account_devices_activation` would answer `ELIGIBLE`. Free with `marmot_group_mutation_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotenable_account_devices) · [Header contract](include/marmot.h#L10909)

### `marmot_enable_group_disbanding`

```c
MarmotStatus marmot_enable_group_disbanding(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotGroupMutationResult **out);
```

Opt the group into disbanding, so a later `marmot_disband_group` is accepted. Requires admin. Free with `marmot_group_mutation_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotenable_group_disbanding) · [Header contract](include/marmot.h#L10875)

### `marmot_existing_direct_conversation`

```c
MarmotStatus marmot_existing_direct_conversation(const struct MarmotClient *client, const char *account_ref, const char *peer_account_id, struct MarmotExistingDirectConversation **out);
```

The existing one-to-one conversation with `peer_account_id`, or NULL with `MARMOT_STATUS_OK` when there is none. Check `reusable` before opening it. Free with `marmot_existing_direct_conversation_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotexisting_direct_conversation) · [Header contract](include/marmot.h#L11078)

### `marmot_events_subscription_next`

```c
MarmotStatus marmot_events_subscription_next(const struct MarmotEventsSubscription *sub, uint32_t timeout_ms, struct MarmotEvent **out);
```

Block until the next item, the timeout, or stream close. `timeout_ms == 0` waits indefinitely. Returns `MARMOT_STATUS_OK` (out set; free with `marmot_event_free`), `MARMOT_STATUS_TIMEOUT`, or `MARMOT_STATUS_CLOSED` (out NULL for both).

[Header contract](include/marmot.h#L13387)

### `marmot_events_subscription_set_callback`

```c
MarmotStatus marmot_events_subscription_set_callback(const struct MarmotEventsSubscription *sub, MarmotEventCallback callback, void *user_data);
```

Install a callback pump for this subscription. `callback` runs on a runtime worker thread with a borrowed item pointer (valid only during the call; do not store or free it) and a final NULL item on close. `callback` and `user_data` access must be thread-safe. Fails if a callback is already installed.

[Header contract](include/marmot.h#L13404)

### `marmot_events_subscription_clear_callback`

```c
MarmotStatus marmot_events_subscription_clear_callback(const struct MarmotEventsSubscription *sub);
```

Request cancellation of this subscription's callback pump, if any. Non-blocking: a callback already running keeps executing after this returns (see the module docs).

[Header contract](include/marmot.h#L13416)

### `marmot_events_subscription_free`

```c
void marmot_events_subscription_free(struct MarmotEventsSubscription *sub);
```

Free the subscription handle. Requests callback-pump cancellation without waiting (a callback may still be running after this returns — do not free `user_data` on that basis). NULL is a no-op. Free every handle before the client that created it.

[Header contract](include/marmot.h#L13428)

### `marmot_existing_direct_conversation_free`

```c
void marmot_existing_direct_conversation_free(struct MarmotExistingDirectConversation *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15029)

### `marmot_event_free`

```c
void marmot_event_free(struct MarmotEvent *event);
```

Free an event returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15286)

</details>

<details>
<summary>marmot_f…</summary>

### `marmot_fetch_sticker_asset`

```c
MarmotStatus marmot_fetch_sticker_asset(const struct MarmotClient *client, const char *account_ref, const char *pack_coordinate, const char *shortcode, const char *plaintext_sha256, struct MarmotStickerAsset **out);
```

Downloads one exact sticker after its reference is authorized. Free with `marmot_sticker_asset_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotfetch_sticker_asset) · [Header contract](include/marmot.h#L12725)

### `marmot_fetch_sticker_pack`

```c
MarmotStatus marmot_fetch_sticker_pack(const struct MarmotClient *client, const char *account_ref, const char *input, struct MarmotStickerPack **out);
```

Fetches one pack and protects that coordinate from discovery eviction. Free with `marmot_sticker_pack_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotfetch_sticker_pack) · [Header contract](include/marmot.h#L12501)

### `marmot_forget_group_local`

```c
MarmotStatus marmot_forget_group_local(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, bool *out);
```

Reset this group on this account-device without publishing. Deletes local app and MLS state; only a valid Welcome created after the reset can rejoin. Close group UI subscriptions and clear host-owned media caches first. Writes true for a new forget, false if already forgotten.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotforget_group_local) · [Header contract](include/marmot.h#L8853)

### `marmot_follow_user`

```c
MarmotStatus marmot_follow_user(const struct MarmotClient *client, const char *account_ref, const char *user_ref, struct MarmotStringList **out);
```

Follow `user_ref` and publish the updated list, keeping its other tags and content. Writes the new follow set. Returns `MARMOT_STATUS_FOLLOW_LIST_TOO_LARGE`, publishing nothing, when the list has 2,048 follows or more. Free with `marmot_string_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotfollow_user) · [Header contract](include/marmot.h#L10730)

### `marmot_flush_product_analytics`

```c
MarmotStatus marmot_flush_product_analytics(const struct MarmotClient *client);
```

# Safety `client` must be a live handle; string arguments must be valid NUL-terminated strings (nullable ones may be NULL); array arguments must hold their stated length (or be NULL with length 0); out-pointers must be valid.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotflush_product_analytics) · [Header contract](include/marmot.h#L12389)

</details>

<details>
<summary>marmot_g…</summary>

### `marmot_group_members`

```c
MarmotStatus marmot_group_members(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotAppGroupMemberRecordList **out);
```

Membership roster for `group_id_hex`, one row per member account with its `device_count`. Free with `marmot_app_group_member_record_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotgroup_members) · [Header contract](include/marmot.h#L8722)

### `marmot_group_details`

```c
MarmotStatus marmot_group_details(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotGroupDetails **out);
```

Group plus enriched member rows for detail screens, one per member account with its `device_count`. Free with `marmot_group_details_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotgroup_details) · [Header contract](include/marmot.h#L8737)

### `marmot_group_management_state`

```c
MarmotStatus marmot_group_management_state(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotGroupManagementState **out);
```

Current caller permissions plus per-member action availability. Free with `marmot_group_management_state_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotgroup_management_state) · [Header contract](include/marmot.h#L8752)

### `marmot_acknowledge_group_catching_up`

```c
MarmotStatus marmot_acknowledge_group_catching_up(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, bool *out);
```

After a group change returns `MARMOT_STATUS_GROUP_CATCHING_UP` and the user chooses to continue, record that they accept the change may split the group, then retry the change. Admits one change attempt at the device's current epoch, consumed even if it fails, and is not persisted. Writes false, recording nothing, when the group is not catching up. No network I/O.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotacknowledge_group_catching_up) · [Header contract](include/marmot.h#L8906)

### `marmot_acknowledge_group_commit_undelivered`

```c
MarmotStatus marmot_acknowledge_group_commit_undelivered(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, bool *out);
```

After a group change returns `MARMOT_STATUS_GROUP_COMMIT_UNDELIVERED` and the user chooses to continue, record that they accept members on relays still owed the group's last change may not follow, then retry the change. Admits one change attempt, consumed even if it fails, and is not persisted. Writes false, recording nothing, when no relay is owed the group's last change. No network I/O.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotacknowledge_group_commit_undelivered) · [Header contract](include/marmot.h#L8924)

### `marmot_group_commit_delivery`

```c
MarmotStatus marmot_group_commit_delivery(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotGroupCommitDelivery **out);
```

The group's oldest change that some group relays have not accepted yet; writes NULL once every relay has accepted or definitively rejected it. Non-NULL is not a refusal: group changes return `MARMOT_STATUS_GROUP_COMMIT_UNDELIVERED` only once `since` is two minutes old. Poll while showing it. Free with `marmot_group_commit_delivery_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotgroup_commit_delivery) · [Header contract](include/marmot.h#L8942)

### `marmot_pending_welcome_deliveries`

```c
MarmotStatus marmot_pending_welcome_deliveries(const struct MarmotClient *client, const char *account_ref, struct MarmotPendingWelcomeDeliveryList **out);
```

Write the account's current pending Welcome repair handles to required `out`, which is cleared before input/client work. This local query preserves native filtering and oldest-first order; it does not send another invitation or end delivery debt. Read `size_class` only when `has_size_class` is true; otherwise the cause is Unknown. A class explains the observed refusal, not delivery or non-delivery; earlier legacy exposure can be unknown. `recorded_at` is the local repair-index timestamp in Unix seconds. The pending event remains once per process/Welcome; query for later cause changes, including a specific cause becoming Unknown after a coarse legacy retry. The returned list owns its strings: release the entire result exactly once with `marmot_pending_welcome_delivery_list_free`. Use the matching header/library. See the [shared method guidance](../marmot-uniffi/API-REFERENCE.md#marmotpending_welcome_deliveries).

[Header contract](include/marmot.h#L8960)

### `marmot_group_recovery_status`

```c
MarmotStatus marmot_group_recovery_status(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotGroupRecoveryStatus **out);
```

Query advisory membership health and pending rejoin offers. Free with `marmot_group_recovery_status_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotgroup_recovery_status) · [Header contract](include/marmot.h#L8974)

### `marmot_group_mls_state`

```c
MarmotStatus marmot_group_mls_state(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotAppGroupMlsState **out);
```

Current MLS state (epoch, member count, required components) for the conversation developer/debug view. Free with `marmot_app_group_mls_state_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotgroup_mls_state) · [Header contract](include/marmot.h#L9833)

### `marmot_group_push_debug_info`

```c
MarmotStatus marmot_group_push_debug_info(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotGroupPushDebugInfo **out);
```

Per-group push token debug info. Free with `marmot_group_push_debug_info_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotgroup_push_debug_info) · [Header contract](include/marmot.h#L10188)

### `marmot_get_blocked_users`

```c
MarmotStatus marmot_get_blocked_users(const struct MarmotClient *client, const char *account_ref, struct MarmotBlockedUserList **out);
```

Read the local blocked-user list, newest first. Free with `marmot_blocked_user_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotget_blocked_users) · [Header contract](include/marmot.h#L10672)

### `marmot_group_member_ids_page`

```c
MarmotStatus marmot_group_member_ids_page(const struct MarmotClient *client, const char *account_ref, const char *const *group_ids_hex, uintptr_t group_ids_hex_len, struct MarmotAppGroupMemberIdsList **out);
```

Member account and admin ids for several groups in one read, each account once. Free with `marmot_app_group_member_ids_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotgroup_member_ids_page) · [Header contract](include/marmot.h#L11224)

### `marmot_group_conversation_snapshot`

```c
MarmotStatus marmot_group_conversation_snapshot(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotGroupConversationSnapshot **out);
```

Group details and management state in one read. Free with `marmot_group_conversation_snapshot_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotgroup_conversation_snapshot) · [Header contract](include/marmot.h#L11240)

### `marmot_group_roster`

```c
MarmotStatus marmot_group_roster(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotGroupRoster **out);
```

The group's member roster at the current MLS epoch, one entry per member account with its `device_count`; `member_count` counts accounts. Free with `marmot_group_roster_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotgroup_roster) · [Header contract](include/marmot.h#L11255)

### `marmot_group_maintenance_status`

```c
MarmotStatus marmot_group_maintenance_status(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotGroupMaintenanceStatus **out);
```

One group's maintenance state. Free with `marmot_group_maintenance_status_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotgroup_maintenance_status) · [Header contract](include/marmot.h#L11335)

### `marmot_group_app_component`

```c
MarmotStatus marmot_group_app_component(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, uint16_t component_id, struct MarmotGroupAppComponent **out);
```

Read application-owned group state for `component_id`. `out` must be a writable pointer-to-pointer. An absent component writes NULL to `*out` and still returns `MARMOT_STATUS_OK`; a written record with `data_len` of `0` is present empty state. Applications allocate ids at or above `0xf000`; every id below that is protocol space and returns `MARMOT_STATUS_INVALID_APP_COMPONENT`. Free with `marmot_group_app_component_free`.

[Header contract](include/marmot.h#L8888)

### `marmot_group_state_subscription_next`

```c
MarmotStatus marmot_group_state_subscription_next(const struct MarmotGroupStateSubscription *sub, uint32_t timeout_ms, struct MarmotAppGroupRecord **out);
```

Block until the next item, the timeout, or stream close. `timeout_ms == 0` waits indefinitely. Returns `MARMOT_STATUS_OK` (out set; free with `marmot_app_group_record_free`), `MARMOT_STATUS_TIMEOUT`, or `MARMOT_STATUS_CLOSED` (out NULL for both).

[Header contract](include/marmot.h#L13857)

### `marmot_group_state_subscription_set_callback`

```c
MarmotStatus marmot_group_state_subscription_set_callback(const struct MarmotGroupStateSubscription *sub, MarmotGroupStateRecordCallback callback, void *user_data);
```

Install a callback pump for this subscription. `callback` runs on a runtime worker thread with a borrowed item pointer (valid only during the call; do not store or free it) and a final NULL item on close. `callback` and `user_data` access must be thread-safe. Fails if a callback is already installed.

[Header contract](include/marmot.h#L13874)

### `marmot_group_state_subscription_clear_callback`

```c
MarmotStatus marmot_group_state_subscription_clear_callback(const struct MarmotGroupStateSubscription *sub);
```

Request cancellation of this subscription's callback pump, if any. Non-blocking: a callback already running keeps executing after this returns (see the module docs).

[Header contract](include/marmot.h#L13886)

### `marmot_group_state_subscription_free`

```c
void marmot_group_state_subscription_free(struct MarmotGroupStateSubscription *sub);
```

Free the subscription handle. Requests callback-pump cancellation without waiting (a callback may still be running after this returns — do not free `user_data` on that basis). NULL is a no-op. Free every handle before the client that created it.

[Header contract](include/marmot.h#L13898)

### `marmot_group_state_subscription_snapshot`

```c
MarmotStatus marmot_group_state_subscription_snapshot(const struct MarmotGroupStateSubscription *sub, struct MarmotAppGroupRecord **out_record);
```

Take the initial group-record snapshot. Yields the record exactly once: later calls write NULL with `MARMOT_STATUS_OK`. Free with `marmot_app_group_record_free`.

[Header contract](include/marmot.h#L13921)

### `marmot_group_details_free`

```c
void marmot_group_details_free(struct MarmotGroupDetails *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15382)

### `marmot_group_management_state_free`

```c
void marmot_group_management_state_free(struct MarmotGroupManagementState *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15392)

### `marmot_group_mutation_result_free`

```c
void marmot_group_mutation_result_free(struct MarmotGroupMutationResult *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15402)

### `marmot_group_invite_decline_result_free`

```c
void marmot_group_invite_decline_result_free(struct MarmotGroupInviteDeclineResult *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15412)

### `marmot_group_conversation_snapshot_free`

```c
void marmot_group_conversation_snapshot_free(struct MarmotGroupConversationSnapshot *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15470)

### `marmot_group_roster_free`

```c
void marmot_group_roster_free(struct MarmotGroupRoster *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15480)

### `marmot_group_recovery_status_free`

```c
void marmot_group_recovery_status_free(struct MarmotGroupRecoveryStatus *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15509)

### `marmot_group_maintenance_status_free`

```c
void marmot_group_maintenance_status_free(struct MarmotGroupMaintenanceStatus *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15586)

### `marmot_group_push_debug_info_free`

```c
void marmot_group_push_debug_info_free(struct MarmotGroupPushDebugInfo *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15772)

</details>

<details>
<summary>marmot_h…</summary>

### `marmot_history_notices`

```c
MarmotStatus marmot_history_notices(const struct MarmotClient *client, const char *account_ref, struct MarmotHistoryNoticeList **out);
```

List the account's durable "history may be incomplete" notices, oldest first, from local storage; blocks on the account worker without network I/O. Re-read on `MARMOT_EVENT_HISTORY_NOTICES_CHANGED`. Each `MarmotHistoryNotice` carries an opaque `notice_id`, its `cause`, a nullable `group_id_hex` (NULL for an account-wide occurrence) and an optional parking time. Free the list with `marmot_history_notice_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmothistory_notices) · [Header contract](include/marmot.h#L9018)

### `marmot_history_notice_list_free`

```c
void marmot_history_notice_list_free(struct MarmotHistoryNoticeList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15527)

### `marmot_account_recovery_status`

**Current.**

```c
MarmotStatus marmot_account_recovery_status(const struct MarmotClient *client, const char *account_ref, struct MarmotAccountRecoveryStatus **out);
```

Read the account's recovery from local state; blocks on the account worker without network I/O. The owned `MarmotAccountRecoveryStatus` lists the groups still catching up (`catching_up_group_ids_hex`/`catching_up_group_ids_hex_len`, lowercase hex, sorted), `inbox_catching_up`, and every notice (`notices`/`notices_len`) as `marmot_history_notices` lists them. Re-read on `MARMOT_EVENT_RECOVERY_STATUS_CHANGED`; the recovery runner supplies the catching-up fields. Free it with `marmot_account_recovery_status_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotaccount_recovery_status) · [Header contract](include/marmot.h#L9034)

### `marmot_account_recovery_status_free`

**Current.**

```c
void marmot_account_recovery_status_free(struct MarmotAccountRecoveryStatus *ptr);
```

Free a status returned by `marmot_account_recovery_status`, its group ids and notices included. NULL is a no-op.

[Header contract](include/marmot.h#L15537)

</details>

<details>
<summary>marmot_i…</summary>

### `marmot_import_signal_sticker_pack`

```c
MarmotStatus marmot_import_signal_sticker_pack(const struct MarmotClient *client, const char *account_ref, const char *signal_link, const char *blossom_server, struct MarmotStickerImportResult **out);
```

Validates a canonical Signal pack link, then refuses before any network call. The pinned importer cannot be address-pinned, so this command does not download or upload. Free with `marmot_sticker_import_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotimport_signal_sticker_pack) · [Header contract](include/marmot.h#L12546)

### `marmot_install_sticker_pack`

```c
MarmotStatus marmot_install_sticker_pack(const struct MarmotClient *client, const char *account_ref, const char *input, struct MarmotStickerPack **out);
```

After a complete installed-list read, signs the proposed list before saving install intent. A signing refusal does not queue this install. Without a complete read, intent stays pending for a later `marmot_sync_sticker_packs`. Free with `marmot_sticker_pack_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotinstall_sticker_pack) · [Header contract](include/marmot.h#L12516)

### `marmot_invite_members`

```c
MarmotStatus marmot_invite_members(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *const *member_refs, uintptr_t member_refs_len, struct MarmotSendSummary **out);
```

Invite members (by `npub` or hex account id) into the group. Requires admin. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotinvite_members) · [Header contract](include/marmot.h#L8767)

### `marmot_invite_members_detailed`

```c
MarmotStatus marmot_invite_members_detailed(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *const *member_refs, uintptr_t member_refs_len, struct MarmotGroupMutationResult **out);
```

`marmot_invite_members` plus refreshed details and management state in one round trip. Free with `marmot_group_mutation_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotinvite_members_detailed) · [Header contract](include/marmot.h#L9751)

### `marmot_initialize_chat_read_state`

```c
MarmotStatus marmot_initialize_chat_read_state(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotChatListRow **out);
```

Initialize read state for a conversation being opened; writes the refreshed row, or NULL with `MARMOT_STATUS_OK` when the group has no row. Free with `marmot_chat_list_row_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotinitialize_chat_read_state) · [Header contract](include/marmot.h#L10420)

### `marmot_is_user_blocked`

```c
MarmotStatus marmot_is_user_blocked(const struct MarmotClient *client, const char *account_ref, const char *user_account_id_hex, bool *out);
```

Whether the local account currently blocks this public key.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotis_user_blocked) · [Header contract](include/marmot.h#L10685)

### `marmot_is_following`

```c
MarmotStatus marmot_is_following(const struct MarmotClient *client, const char *account_ref, const char *user_ref, bool *out);
```

Whether `user_ref` (`npub` or hex account id) is followed.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotis_following) · [Header contract](include/marmot.h#L10713)

### `marmot_invite_members_with_initial_admins`

```c
MarmotStatus marmot_invite_members_with_initial_admins(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *const *member_refs, uintptr_t member_refs_len, const char *const *initial_admin_refs, uintptr_t initial_admin_refs_len, struct MarmotSendSummary **out);
```

`marmot_invite_members` where some invitees join as admins. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotinvite_members_with_initial_admins) · [Header contract](include/marmot.h#L10955)

### `marmot_invite_members_detailed_with_initial_admins`

```c
MarmotStatus marmot_invite_members_detailed_with_initial_admins(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *const *member_refs, uintptr_t member_refs_len, const char *const *initial_admin_refs, uintptr_t initial_admin_refs_len, struct MarmotGroupMutationResult **out);
```

`marmot_invite_members_with_initial_admins` plus refreshed details and management state in one round trip. Free with `marmot_group_mutation_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotinvite_members_detailed_with_initial_admins) · [Header contract](include/marmot.h#L10975)

### `marmot_identity_creation_result_free`

```c
void marmot_identity_creation_result_free(struct MarmotIdentityCreationResult *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L14814)

</details>

<details>
<summary>marmot_k…</summary>

### `marmot_key_package_maintenance_status`

```c
MarmotStatus marmot_key_package_maintenance_status(const struct MarmotClient *client, const char *account_ref, struct MarmotKeyPackageMaintenanceStatus **out);
```

The account's KeyPackage slot state; writes NULL with `MARMOT_STATUS_OK` when no slot exists yet. Free with `marmot_key_package_maintenance_status_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotkey_package_maintenance_status) · [Header contract](include/marmot.h#L11351)

### `marmot_key_package_maintenance_status_free`

```c
void marmot_key_package_maintenance_status_free(struct MarmotKeyPackageMaintenanceStatus *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15596)

</details>

<details>
<summary>marmot_l…</summary>

### `marmot_key_package_refresh_overdue`

```c
MarmotStatus marmot_key_package_refresh_overdue(const struct MarmotClient *client, const char *account_ref, bool *out);
```

Write whether this device's device group has held its KeyPackage refresh back for a week, so the app warns the user before inviters stop treating the device as fresh at 30 days; blocks on the account worker without network I/O. Always false until this device trusts a device group, and without explicit dev capability and runtime intent. Re-read on `MARMOT_EVENT_KEY_PACKAGE_REFRESH_OVERDUE_CHANGED`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotkey_package_refresh_overdue) · [Header contract](include/marmot.h#L9270)

</details>

<details>
<summary>marmot_l…</summary>

### `marmot_largest_retained_attachments`

```c
MarmotStatus marmot_largest_retained_attachments(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, uint32_t limit, const struct MarmotRetainedAttachmentsCursor *cursor, struct MarmotRetainedAttachmentsPage **out);
```

Blocking largest-first attachment listing, `limit` 1..=256; `group_id_hex` NULL lists the whole account. Paging and cursor ownership as for `marmot_attachment_storage_by_chat`; free each page with `marmot_retained_attachments_page_free`. See the [shared contract](../marmot-uniffi/API-REFERENCE.md#marmotlargest_retained_attachments).

[Header contract](include/marmot.h#L8057)

### `marmot_last_error_message`

```c
char *marmot_last_error_message(void);
```

Return the detail message for the current thread's most recent failed `marmot_*` call, or NULL if there is none. The returned string is an owned copy: free it with `marmot_string_free`. Reading clears the slot.

[Header contract](include/marmot.h#L7774)

### `marmot_list_accounts`

```c
MarmotStatus marmot_list_accounts(const struct MarmotClient *client, struct MarmotAccountSummaryList **out);
```

List every account known to this device. Free the result with `marmot_account_summary_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotlist_accounts) · [Header contract](include/marmot.h#L8203)

### `marmot_login`

```c
MarmotStatus marmot_login(const struct MarmotClient *client, const char *identity, const char *const *default_relays, uintptr_t default_relays_len, const char *const *bootstrap_relays, uintptr_t bootstrap_relays_len, const char *const *inbox_relays, uintptr_t inbox_relays_len, struct MarmotAccountSummary **out);
```

Log in with an existing identity: an `nsec` (private key) for a local-signing account, or an `npub` to track a public identity. Free with `marmot_account_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotlogin) · [Header contract](include/marmot.h#L8394)

### `marmot_local_account_key_packages`

```c
MarmotStatus marmot_local_account_key_packages(const struct MarmotClient *client, const char *account_ref, struct MarmotAccountKeyPackageInventoryEntryList **out);
```

Local-storage KeyPackage inventory with typed durable provenance. Synchronous SQLCipher I/O on the calling thread; keep it off a UI or main thread. Free with `marmot_account_key_package_inventory_entry_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotlocal_account_key_packages) · [Header contract](include/marmot.h#L8492)

### `marmot_leave_group`

```c
MarmotStatus marmot_leave_group(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotSendSummary **out);
```

Leave as the active account. An admin fails with `MARMOT_STATUS_ADMIN_CANNOT_SELF_REMOVE` until `marmot_self_demote_admin`; with experimental device groups core demotes eligible admins, leaves matching linked copies and refuses the last admin, and failure can retain a recorded Decline or committed demotion. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotleave_group) · [Header contract](include/marmot.h#L8803)

### `marmot_cancel_leave`

```c
MarmotStatus marmot_cancel_leave(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex);
```

Cancel this account's blocked leave on this device. Offer it while `MarmotGroupManagementState.can_cancel_leave`: the account is the group's last active admin, so the leave cannot finish. The chat reads as joined again. While the group is still settling, or in any other state, it fails with `MARMOT_STATUS_LEAVE_NOT_BLOCKED`. Blocks on the account worker; nothing is published.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotcancel_leave) · [Header contract](include/marmot.h#L8820)

### `marmot_list_media`

```c
MarmotStatus marmot_list_media(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, uint8_t has_limit, uint32_t limit, struct MarmotMediaRecordList **out);
```

Stored media records for the group, capped by `limit` when `has_limit`. Free with `marmot_media_record_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotlist_media) · [Header contract](include/marmot.h#L10571)

### `marmot_login_recovering_incomplete_setup`

```c
MarmotStatus marmot_login_recovering_incomplete_setup(const struct MarmotClient *client, const char *nsec, const char *const *default_relays, uintptr_t default_relays_len, const char *const *bootstrap_relays, uintptr_t bootstrap_relays_len, uint8_t acknowledge_possible_key_package_orphan, const char *const *inbox_relays, uintptr_t inbox_relays_len, struct MarmotAccountSummary **out);
```

Sign in and finish a setup that was interrupted partway. Free with `marmot_account_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotlogin_recovering_incomplete_setup) · [Header contract](include/marmot.h#L10777)

### `marmot_linked_devices`

```c
MarmotStatus marmot_linked_devices(const struct MarmotClient *client, const char *account_ref, struct MarmotLinkedDeviceList **out);
```

List this account's own devices from the roster of the device group this device trusts, this device first, then by `linked_at`; blocks on the account worker without network I/O. Empty until this device trusts a device group, and always empty without explicit dev capability and runtime intent. Re-read on `MARMOT_EVENT_LINKED_DEVICES_CHANGED`. Each `MarmotLinkedDevice` carries its `slot_id_hex` handle, `is_this_device`, `label`, `client` and `platform` (empty until set), `linked_at`, a nullable `linked_by_slot_id_hex` (NULL for the founder), its `status`, its three settings, `last_active_at` (Unix seconds, valid when `has_last_active_at`: when a heartbeat last showed it running, never for this device) and `inactive` (this device's own judgement, 30 days after the later of that and when it first found the device in the roster). Free the list with `marmot_linked_device_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotlinked_devices) · [Header contract](include/marmot.h#L9067)

### `marmot_linked_device_list_free`

```c
void marmot_linked_device_list_free(struct MarmotLinkedDeviceList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15546)

### `marmot_chat_history_imports`

```c
MarmotStatus marmot_chat_history_imports(const struct MarmotClient *client, const char *account_ref, struct MarmotChatHistoryImportList **out);
```

List the held chats whose history from another of this account's devices is arriving or has arrived; blocks on the account worker without network I/O. Each `MarmotChatHistoryImport` carries its `group_id_hex` and a tagged `state`: `Receiving` (with `retrying` once an attempt to get its bundle failed) while a delivery waits to be imported, or `Imported` with the `MarmotHistoryImportSource` the latest import came from and `at`, in Unix seconds. An empty `device_label` means "another device". Each imported `MarmotTimelineMessageRecord` names the same source in its nullable `imported_from`. Empty while device groups are off. Re-read on `MARMOT_EVENT_CHAT_HISTORY_IMPORTS_CHANGED`, which fires whenever this answer changes, a source device's rename or removal included. Free the list with `marmot_chat_history_import_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotchat_history_imports) · [Header contract](include/marmot.h#L9087)

### `marmot_chat_history_import_list_free`

```c
void marmot_chat_history_import_list_free(struct MarmotChatHistoryImportList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15518)

### `marmot_link_device`

```c
MarmotStatus marmot_link_device(const struct MarmotClient *client, const char *account_ref, const char *prompt_id, const char *label, uint8_t add_to_all_chats, uint8_t bring_history, struct MarmotDeviceLinkSnapshot **out);
```

On a device already signed in, Link device for the prompt `prompt_id`, with the new device's `label` (not blank, at most 64 bytes) and its two settings, both offered on by default. `add_to_all_chats` and `bring_history` are `uint8_t` flags. Free the snapshot with `marmot_device_link_snapshot_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotlink_device) · [Header contract](include/marmot.h#L9568)

</details>

<details>
<summary>marmot_m…</summary>

### `marmot_mark_timeline_message_read`

```c
MarmotStatus marmot_mark_timeline_message_read(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *message_id_hex, struct MarmotChatListRow **out);
```

Mark a timeline message read; writes the refreshed row, or NULL with `MARMOT_STATUS_OK`. Free with `marmot_chat_list_row_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotmark_timeline_message_read) · [Header contract](include/marmot.h#L10435)

### `marmot_messages`

```c
MarmotStatus marmot_messages(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, uint8_t has_limit, uint32_t limit, const uint64_t *kinds, uintptr_t kinds_len, struct MarmotAppMessageRecordList **out);
```

Stored raw app messages for a group (`group_id_hex` non-NULL) or the whole account (NULL), newest-last, capped by `limit` when `has_limit`. `kinds` restricts the result to those Nostr event kinds; pass NULL with length 0 for every kind. Free with `marmot_app_message_record_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotmessages) · [Header contract](include/marmot.h#L10552)

### `marmot_message_drafts`

```c
MarmotStatus marmot_message_drafts(const struct MarmotClient *client, const char *account_ref, struct MarmotMessageDraftSummaryList **out);
```

Every stored draft for the account, attachment metadata only. Free with `marmot_message_draft_summary_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotmessage_drafts) · [Header contract](include/marmot.h#L11158)

### `marmot_message_draft`

```c
MarmotStatus marmot_message_draft(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotMessageDraft **out);
```

The stored draft for one conversation, with attachment bytes; writes NULL with `MARMOT_STATUS_OK` when there is none. Free with `marmot_message_draft_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotmessage_draft) · [Header contract](include/marmot.h#L11173)

### `marmot_message_edit_history`

```c
MarmotStatus marmot_message_edit_history(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *target_message_id_hex, uint8_t has_before, uint64_t before_edited_at, const char *before_message_id_hex, uint32_t limit, struct MarmotTimelineEditHistoryPage **out);
```

Read accepted edit versions separately from screen snapshots. Supply both cursor values, or has_before=0 and a NULL id for the newest page. Limit 1..=100. Free with marmot_timeline_edit_history_page_free. # Safety Client and strings must be valid, before_message_id nullable, out writable.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotmessage_edit_history) · [Header contract](include/marmot.h#L12436)

### `marmot_messages_subscription_next`

```c
MarmotStatus marmot_messages_subscription_next(const struct MarmotMessagesSubscription *sub, uint32_t timeout_ms, struct MarmotMessageUpdate **out);
```

Block until the next item, the timeout, or stream close. `timeout_ms == 0` waits indefinitely. Returns `MARMOT_STATUS_OK` (out set; free with `marmot_message_update_free`), `MARMOT_STATUS_TIMEOUT`, or `MARMOT_STATUS_CLOSED` (out NULL for both).

[Header contract](include/marmot.h#L13776)

### `marmot_messages_subscription_set_callback`

```c
MarmotStatus marmot_messages_subscription_set_callback(const struct MarmotMessagesSubscription *sub, MarmotMessageUpdateCallback callback, void *user_data);
```

Install a callback pump for this subscription. `callback` runs on a runtime worker thread with a borrowed item pointer (valid only during the call; do not store or free it) and a final NULL item on close. `callback` and `user_data` access must be thread-safe. Fails if a callback is already installed.

[Header contract](include/marmot.h#L13793)

### `marmot_messages_subscription_clear_callback`

```c
MarmotStatus marmot_messages_subscription_clear_callback(const struct MarmotMessagesSubscription *sub);
```

Request cancellation of this subscription's callback pump, if any. Non-blocking: a callback already running keeps executing after this returns (see the module docs).

[Header contract](include/marmot.h#L13805)

### `marmot_messages_subscription_free`

```c
void marmot_messages_subscription_free(struct MarmotMessagesSubscription *sub);
```

Free the subscription handle. Requests callback-pump cancellation without waiting (a callback may still be running after this returns — do not free `user_data` on that basis). NULL is a no-op. Free every handle before the client that created it.

[Header contract](include/marmot.h#L13817)

### `marmot_messages_subscription_snapshot`

```c
MarmotStatus marmot_messages_subscription_snapshot(const struct MarmotMessagesSubscription *sub, struct MarmotAppMessageRecordList **out_list);
```

Take the initial message-record snapshot. Yields the populated list exactly once: later calls write an EMPTY list, still with `MARMOT_STATUS_OK`. Free with `marmot_app_message_record_list_free`.

[Header contract](include/marmot.h#L13848)

### `marmot_message_draft_attachment_if_revision`

```c
MarmotStatus marmot_message_draft_attachment_if_revision(const struct MarmotClient *client, const char *account_ref, const struct MarmotMessageDraftRevision *revision, const char *attachment_id, uint8_t *out_found, uint8_t **out_data, uintptr_t *out_len);
```

Read one selected attachment. found=0 distinguishes absence from an empty acquired attachment. Free returned bytes with marmot_bytes_free; revision conflicts return an error. # Safety client, strings, revision valid; revision's owning draft stays live; all out pointers writable.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotmessage_draft_attachment_if_revision) · [Header contract](include/marmot.h#L14695)

### `marmot_message_tag_free`

```c
void marmot_message_tag_free(struct MarmotMessageTag *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15094)

### `marmot_message_draft_free`

```c
void marmot_message_draft_free(struct MarmotMessageDraft *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15161)

### `marmot_message_draft_summary_free`

```c
void marmot_message_draft_summary_free(struct MarmotMessageDraftSummary *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15171)

### `marmot_message_draft_summary_list_free`

```c
void marmot_message_draft_summary_list_free(struct MarmotMessageDraftSummaryList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15180)

### `marmot_member_ref_free`

```c
void marmot_member_ref_free(struct MarmotMemberRef *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15362)

### `marmot_member_key_package_prewarm_summary_free`

```c
void marmot_member_key_package_prewarm_summary_free(struct MarmotMemberKeyPackagePrewarmSummary *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15431)

### `marmot_maintenance_run_summary_free`

```c
void marmot_maintenance_run_summary_free(struct MarmotMaintenanceRunSummary *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15606)

### `marmot_markdown_document_free`

```c
void marmot_markdown_document_free(struct MarmotMarkdownDocument *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15616)

### `marmot_media_upload_result_free`

```c
void marmot_media_upload_result_free(struct MarmotMediaUploadResult *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15626)

### `marmot_media_download_result_free`

```c
void marmot_media_download_result_free(struct MarmotMediaDownloadResult *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15636)

### `marmot_media_record_list_free`

```c
void marmot_media_record_list_free(struct MarmotMediaRecordList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15645)

### `marmot_message_update_free`

```c
void marmot_message_update_free(struct MarmotMessageUpdate *update);
```

Free a message update returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15692)

</details>

<details>
<summary>marmot_n…</summary>

### `marmot_nip46_pairing_offer`

```c
MarmotStatus marmot_nip46_pairing_offer(const struct MarmotNip46Session *session, char **out);
```

Install the client-pairing listener and await relay subscription acknowledgements before returning its credential-bearing URI. Display the URI only after this call succeeds, then connect while the pairing UI is visible. Requires explicit permission approval and an unpaired client-initiated session. Blocks; run off the UI thread. Free the URI with `marmot_string_free`.

[Session contract](README.md#nip-46-accounts)

[Header contract](include/marmot.h#L13057)

### `marmot_nip46_approve_grants`

```c
MarmotStatus marmot_nip46_approve_grants(const struct MarmotNip46Session *session, uint32_t version, const char *const *grants, uintptr_t grants_len);
```

Approve the exact version and grants previously returned by review, after user consent. Inputs are borrowed for the call. Missing review or changed grants return `MARMOT_STATUS_EXTERNAL_SIGNER_REJECTED`; no network request starts.

[Session contract](README.md#nip-46-accounts)

[Header contract](include/marmot.h#L13125)

### `marmot_nip46_cancel_request`

```c
MarmotStatus marmot_nip46_cancel_request(const struct MarmotNip46Session *session, const char *request_id);
```

Cancel one matching pending request without terminally cancelling the session. Stale IDs return `MARMOT_STATUS_INVALID_ARGUMENT`. The string is borrowed for the call.

[Session contract](README.md#nip-46-accounts)

[Header contract](include/marmot.h#L13149)

### `marmot_nip46_complete_auth`

```c
MarmotStatus marmot_nip46_complete_auth(const struct MarmotNip46Session *session, const char *request_id);
```

Acknowledge the auth challenge identified by the current status request ID. This does not complete its RPC, which still requires the signer's final response. Stale IDs return `MARMOT_STATUS_INVALID_ARGUMENT`.

[Session contract](README.md#nip-46-accounts)

[Header contract](include/marmot.h#L13157)

### `marmot_nip46_disconnect`

```c
MarmotStatus marmot_nip46_disconnect(const struct MarmotNip46Session *session);
```

Interrupt transport work and advance the session generation. A later explicit connect can reconnect; persisted credentials are not removed. May race operations, but never handle free.

[Session contract](README.md#nip-46-accounts)

[Header contract](include/marmot.h#L13142)

### `marmot_nip46_ping`

```c
MarmotStatus marmot_nip46_ping(const struct MarmotNip46Session *session);
```

Check the remote signer through the shared transport. Blocks; run off the UI thread. Transport and signer failures use the existing timeout/external-signer status codes.

[Session contract](README.md#nip-46-accounts)

[Header contract](include/marmot.h#L13135)

### `marmot_nip46_remove`

```c
MarmotStatus marmot_nip46_remove(const struct MarmotClient *client, const char *account_ref);
```

Detach the account-scoped shared signer and remove its persisted communication credentials. This does not replace account sign-out or account data wiping. Account input is borrowed; blocks on the runtime.

[Session contract](README.md#nip-46-accounts)

[Header contract](include/marmot.h#L13174)

### `marmot_nip46_resume`

```c
MarmotStatus marmot_nip46_resume(const struct MarmotClient *client, const char *account_ref, struct MarmotNip46Session **out);
```

Obtain the shared session restored from MDK-owned account credentials, without a host descriptor or callback. Persisted permission approval is retained. Out is cleared before runtime work; free the handle with `marmot_nip46_free` before its creating client. Freeing this handle leaves the account signer and other handles usable.

[Session contract](README.md#nip-46-accounts)

[Header contract](include/marmot.h#L13165)

### `marmot_nip46_review_grants`

```c
MarmotStatus marmot_nip46_review_grants(const struct MarmotNip46Session *session, char **out);
```

Record the required permission snapshot and return JSON `version` and `grants` for display. Review does not approve. No network access; free the JSON string with `marmot_string_free`. A NULL out pointer refuses the operation before recording review.

[Session contract](README.md#nip-46-accounts)

[Header contract](include/marmot.h#L13118)

### `marmot_nip46_cancel`
 

```c
void marmot_nip46_cancel(const struct MarmotNip46Session *session);
```

Permanently cancel the shared session's pending work, including its account signer and other handles, without removing MDK-owned credentials or revoking a saved export. Nonblocking and NULL-safe; may race calls, never free.

[Header contract](include/marmot.h#L13279)

### `marmot_nip46_connect`

```c
MarmotStatus marmot_nip46_connect(const struct MarmotNip46Session *session, char **out);
```

Connect, verify the pinned user key, and adopt allowed signer relay changes. Run off UI. Free the returned user hex with `marmot_string_free`.

[Header contract](include/marmot.h#L13228)

### `marmot_nip46_export`

```c
MarmotStatus marmot_nip46_export(const struct MarmotNip46Session *session, char **out);
```

Return durable client credentials and pinned identities as JSON. Store only in an encrypted vault; never log it. Free with `marmot_string_free`.

[Header contract](include/marmot.h#L13235)

### `marmot_nip46_free`

```c
void marmot_nip46_free(struct MarmotNip46Session *session);
```

Release only this C handle without cancelling the shared session, remote logout, or removing persisted credentials. MDK retains attached sessions, so account signing and other handles remain usable. An unbound session stops when its final owner drops. Explicit `marmot_nip46_cancel` remains terminal. Join all callers first and free before the creating client. NULL is a no-op.

[Header contract](include/marmot.h#L13295)

### `marmot_nip46_login`

```c
MarmotStatus marmot_nip46_login(const struct MarmotClient *client, const struct MarmotNip46Session *session, const char *const *default_relays, uintptr_t default_len, const char *const *bootstrap_relays, uintptr_t bootstrap_len, const char *const *inbox_relays, uintptr_t inbox_len, struct MarmotAccountSummary **out);
```

Create or reopen an external account using the verified session signer. Run off UI; free the returned summary with `marmot_account_summary_free`.
Set `inbox_relays` independently, or pass `NULL, 0` to reuse the default relays.

Admitted Native adoption is runtime-owned: loss of the waiter does not cancel it. The preceding handshake remains bounded and cancellable. Explicit session cancel, disconnect, or logout interrupts adoption; shutdown interrupts and settles owned work before returning. Never free handles during active calls.

Completed accounts rebind without opening initial setup. Failed Native adoption restores prior local callbacks, records, and activation while preserving setup readiness. Already-published KeyPackages are not retracted. Account sign-out cleanup remains explicit; legacy host login is unchanged.

[Header contract](include/marmot.h#L13079)

### `marmot_nip46_logout`

```c
MarmotStatus marmot_nip46_logout(const struct MarmotNip46Session *session);
```

Attempt bounded remote logout and clear local session keys even without acknowledgement. This directly revokes a session, not the MDK account. Account signout already erases owned credentials, so a later logout reports an already logged-out session without another remote request. Run off UI; remove any optional host vault export when revoking credentials.

A vault deletion error leaves signing stopped and retains cleanup ownership. Retry logout or `marmot_nip46_remove` after the vault recovers; a failed deletion does not authorize a fresh pairing over the pending credential.

[Header contract](include/marmot.h#L13189)

### `marmot_nip46_new`

```c
MarmotStatus marmot_nip46_new(const struct MarmotClient *client, const char *config_json, struct MarmotNip46Session **out);
```

Create an offline shared session from a bunker URI, pairing configuration, or exported descriptor. The client must outlive the handle. Review and approve permissions before URI access or connection; imports never silently approve grants. See the session lifecycle for configuration fields.

[Header contract](include/marmot.h#L13212)

### `marmot_nip46_register`

```c
MarmotStatus marmot_nip46_register(const struct MarmotClient *client, const char *account_ref, const struct MarmotNip46Session *session);
```

Attach an explicitly approved imported descriptor to an existing account, persist its verified credentials, and activate its worker. Ordinary cold startup restores owned sessions automatically; use `marmot_nip46_resume` for their handles. A different attached session must be removed before replacement.

Admitted adoption follows the runtime-owned cancellation and shutdown contract of `marmot_nip46_login`; handles must remain live throughout active C calls. If no prior callback exists, a verified pairing remains attached for recovery when worker startup fails.

[Header contract](include/marmot.h#L13094)

### `marmot_nip46_state`

```c
MarmotStatus marmot_nip46_state(const struct MarmotNip46Session *session, char **out);
```

Read nonblocking JSON status and any intermediate approval URL, without session keys or RPC payloads. Free with `marmot_string_free`.

[Header contract](include/marmot.h#L13272)

### `marmot_nip46_status`

```c
MarmotStatus marmot_nip46_status(const struct MarmotNip46Session *session, struct MarmotNip46Status **out);
```

Read local typed state/error vocabulary, optional auth URL and request ID, and generation without keys or request payloads. `last_error` is valid only when `has_last_error` is true. Distinguishes cancellation from remote rejection independently of legacy status-code compatibility. Out is cleared before work; no network access.

[Session contract](README.md#nip-46-accounts)

[Header contract](include/marmot.h#L13110)

### `marmot_nip46_status_free`

```c
void marmot_nip46_status_free(struct MarmotNip46Status *ptr);
```

Deep-free the status record and its optional strings. NULL is a no-op. Embedded strings are owned by the record and must not be freed separately.

[Session contract](README.md#nip-46-accounts)

[Header contract](include/marmot.h#L13033)

### `marmot_nip46_uri`

```c
MarmotStatus marmot_nip46_uri(const struct MarmotNip46Session *session, char **out);
```

Read the credential-bearing pairing link locally after permission approval. This accessor does not install a listener; use `marmot_nip46_pairing_offer` before displaying a client-initiated QR code. Never log either URI; free it with `marmot_string_free`.

[Header contract](include/marmot.h#L13221)

### `marmot_normalize_member_ref`

```c
MarmotStatus marmot_normalize_member_ref(const struct MarmotClient *client, const char *member_ref, struct MarmotMemberRef **out);
```

Normalize a member reference (hex, `npub`, `nostr:npub...`, `nprofile`, `nostr:nprofile...`, and `marmot://profile/...`). nprofile relay hints are discarded. Duplicate type-0 TLV entries keep the first key. After wrapper normalization, encoded tokens longer than 1023 UTF-8 bytes are rejected; a valid 1023-byte token still decodes when wrapped. Free with `marmot_member_ref_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotnormalize_member_ref) · [Header contract](include/marmot.h#L8708)

### `marmot_notify_connectivity_restored`

```c
MarmotStatus marmot_notify_connectivity_restored(const struct MarmotClient *client);
```

Interrupt retry backoff for durable outbound work after the host has observed usable connectivity.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotnotify_connectivity_restored) · [Header contract](include/marmot.h#L9880)

### `marmot_notification_settings`

```c
MarmotStatus marmot_notification_settings(const struct MarmotClient *client, const char *account_ref, struct MarmotNotificationSettings **out);
```

Per-account notification switches. Free with `marmot_notification_settings_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotnotification_settings) · [Header contract](include/marmot.h#L10115)

### `marmot_npub`

```c
MarmotStatus marmot_npub(const struct MarmotClient *client, const char *account_id_hex, char **out);
```

`npub` encoding of a hex account id; NULL with `MARMOT_STATUS_OK` when the input does not decode. Free with `marmot_string_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotnpub) · [Header contract](include/marmot.h#L11447)

### `marmot_notifications_subscription_next`

```c
MarmotStatus marmot_notifications_subscription_next(const struct MarmotNotificationsSubscription *sub, uint32_t timeout_ms, struct MarmotNotificationUpdate **out);
```

Block until the next item, the timeout, or stream close. `timeout_ms == 0` waits indefinitely. Returns `MARMOT_STATUS_OK` (out set; free with `marmot_notification_update_free`), `MARMOT_STATUS_TIMEOUT`, or `MARMOT_STATUS_CLOSED` (out NULL for both).

[Header contract](include/marmot.h#L13559)

### `marmot_notifications_subscription_set_callback`

```c
MarmotStatus marmot_notifications_subscription_set_callback(const struct MarmotNotificationsSubscription *sub, MarmotNotificationUpdateCallback callback, void *user_data);
```

Install a callback pump for this subscription. `callback` runs on a runtime worker thread with a borrowed item pointer (valid only during the call; do not store or free it) and a final NULL item on close. `callback` and `user_data` access must be thread-safe. Fails if a callback is already installed.

[Header contract](include/marmot.h#L13576)

### `marmot_notifications_subscription_clear_callback`

```c
MarmotStatus marmot_notifications_subscription_clear_callback(const struct MarmotNotificationsSubscription *sub);
```

Request cancellation of this subscription's callback pump, if any. Non-blocking: a callback already running keeps executing after this returns (see the module docs).

[Header contract](include/marmot.h#L13588)

### `marmot_notifications_subscription_free`

```c
void marmot_notifications_subscription_free(struct MarmotNotificationsSubscription *sub);
```

Free the subscription handle. Requests callback-pump cancellation without waiting (a callback may still be running after this returns — do not free `user_data` on that basis). NULL is a no-op. Free every handle before the client that created it.

[Header contract](include/marmot.h#L13600)

### `marmot_notification_settings_free`

```c
void marmot_notification_settings_free(struct MarmotNotificationSettings *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15712)

### `marmot_notification_update_free`

```c
void marmot_notification_update_free(struct MarmotNotificationUpdate *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15722)

</details>

<details>
<summary>marmot_o…</summary>

### `marmot_onboarding_recovery_required`

```c
MarmotStatus marmot_onboarding_recovery_required(const struct MarmotClient *client, const char *account_ref, bool *out);
```

Retry onboarding against explicitly selected discovery relays. Query whether unreadable/exhausted checkpoints require explicit recovery.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotonboarding_recovery_required) · [Header contract](include/marmot.h#L8272)

### `marmot_onboarding_snapshot`

```c
MarmotStatus marmot_onboarding_snapshot(const struct MarmotClient *client, const char *account_ref, struct MarmotOnboardingSnapshot **out);
```

Read the persisted onboarding snapshot. Writes NULL with MARMOT_STATUS_OK when no checkpoint exists. Free the returned snapshot with `marmot_onboarding_snapshot_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotonboarding_snapshot) · [Header contract](include/marmot.h#L12219)

### `marmot_onboarding_subscription_next`

```c
MarmotStatus marmot_onboarding_subscription_next(const struct MarmotOnboardingSubscription *sub, uint32_t timeout_ms, struct MarmotOnboardingSnapshot **out);
```

Block until the next item, the timeout, or stream close. `timeout_ms == 0` waits indefinitely. Returns `MARMOT_STATUS_OK` (out set; free with `marmot_onboarding_snapshot_free`), `MARMOT_STATUS_TIMEOUT`, or `MARMOT_STATUS_CLOSED` (out NULL for both).

[Header contract](include/marmot.h#L14080)

### `marmot_onboarding_subscription_set_callback`

```c
MarmotStatus marmot_onboarding_subscription_set_callback(const struct MarmotOnboardingSubscription *sub, MarmotOnboardingCallback callback, void *user_data);
```

Install a callback pump for this subscription. `callback` runs on a runtime worker thread with a borrowed item pointer (valid only during the call; do not store or free it) and a final NULL item on close. `callback` and `user_data` access must be thread-safe. Fails if a callback is already installed.

[Header contract](include/marmot.h#L14097)

### `marmot_onboarding_subscription_clear_callback`

```c
MarmotStatus marmot_onboarding_subscription_clear_callback(const struct MarmotOnboardingSubscription *sub);
```

Request cancellation of this subscription's callback pump, if any. Non-blocking: a callback already running keeps executing after this returns (see the module docs).

[Header contract](include/marmot.h#L14109)

### `marmot_onboarding_subscription_free`

```c
void marmot_onboarding_subscription_free(struct MarmotOnboardingSubscription *sub);
```

Free the subscription handle. Requests callback-pump cancellation without waiting (a callback may still be running after this returns — do not free `user_data` on that basis). NULL is a no-op. Free every handle before the client that created it.

[Header contract](include/marmot.h#L14121)

### `marmot_onboarding_subscription_snapshot`

```c
MarmotStatus marmot_onboarding_subscription_snapshot(const struct MarmotOnboardingSubscription *sub, struct MarmotOnboardingSnapshot **out);
```

Return the initial snapshot. Free with marmot_onboarding_snapshot_free.

[Header contract](include/marmot.h#L14139)

### `marmot_open_attachment_handoff`

```c
MarmotStatus marmot_open_attachment_handoff(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const struct MarmotAttachmentLocalTarget *target, const struct MarmotMediaFileTransferControl *control, struct MarmotAttachmentHandoff **out);
```

Blocking handoff copy that holds the calling thread until the copy finishes: call it off the UI thread. Writes NULL with `MARMOT_STATUS_OK` when the attachment is not held locally, and `MARMOT_STATUS_STORAGE_FULL` when the disk cannot hold the copy beyond the reserve. Inputs are borrowed for the call; the control may be queried or cancelled from another thread. Free the record with `marmot_attachment_handoff_free`. See the [shared contract](../marmot-uniffi/API-REFERENCE.md#marmotopen_attachment_handoff).

[Header contract](include/marmot.h#L7890)

### `marmot_open_presented_chat_list`

```c
MarmotStatus marmot_open_presented_chat_list(const struct MarmotClient *client, const char *account_ref, uint8_t include_archived, struct MarmotPresentedChatListSubscription **out_sub);
```

Open a complete chat list with both invalidation sources already attached. Take the initial snapshot once, then call next. Free with marmot_presented_chat_list_subscription_free. # Safety Client and string must be valid; out_sub must be writable.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotopen_presented_chat_list) · [Header contract](include/marmot.h#L14148)

### `marmot_open_chat_list_window`

```c
MarmotStatus marmot_open_chat_list_window(const struct MarmotClient *client, const char *account_ref, uint32_t view, const uint32_t *initial_rows, struct MarmotChatListWindowSubscription **out_sub);
```

Open one account/view. A NULL initial_rows uses 50; otherwise requires 1–100. View is a MarmotChatListView discriminant. Take snapshot once, then receive replacements. # Safety client/string must be valid; initial_rows must be NULL or readable, out_sub writable.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotopen_chat_list_window) · [Header contract](include/marmot.h#L14470)

### `marmot_open_chat_list_query_window`

```c
MarmotStatus marmot_open_chat_list_query_window(const struct MarmotClient *client, const char *account_ref, const struct MarmotChatListViewQuery *query, const uint32_t *initial_rows, struct MarmotChatListWindowSubscription **out_sub);
```

`marmot_open_chat_list_window` narrowed by a filter. `query->view` is a MarmotChatListView discriminant; `query->filter[0..filter_len]` is the node list (NULL only with zero length, meaning no filter). Each `MarmotChatListFilterNode` sets `kind` and only that kind's fields: `children` for `All`/`Any`, exactly one child for `Not`, `condition` for `Condition`, `group_ids` for `GroupIds`, `text` for `Text` and `MessageText`. Node 0 is the root and every other node is the child of exactly one earlier node. A `Text` node matches chats whose title, group name, description or direct-chat peer profile name contains `text`, trimmed and lowercased, as a literal substring; a NULL `text` returns `MARMOT_STATUS_NULL_POINTER`. While any chat in the view still has presentation pending, a query with a `Text` node returns `MARMOT_STATUS_CHAT_PRESENTATION_NOT_READY` (an open window delivers it and retries), never part of the set. A `MessageText` node matches chats with a visible message containing `text` by the same rule; a window refuses it with `MARMOT_STATUS_INVALID_CHAT_LIST_QUERY` (`MARMOT_CHAT_LIST_QUERY_ERROR_MESSAGE_TEXT_IN_WINDOW`) before any read. Shape or bound violations (8 levels, 64 nodes, 500 group IDs, 1024 bytes of text) return `MARMOT_STATUS_INVALID_CHAT_LIST_QUERY`; an out-of-range discriminant or a `Not` without exactly one child returns `MARMOT_STATUS_INVALID_ARGUMENT`. The query and its arrays are borrowed for the call. Free with `marmot_chat_list_window_subscription_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotopen_chat_list_query_window) · [Header contract](include/marmot.h#L14485)

### `marmot_chat_list_query_ids`

```c
MarmotStatus marmot_chat_list_query_ids(const struct MarmotClient *client, const char *account_ref, const struct MarmotChatListViewQuery *query, struct MarmotStringList **out);
```

Select all for a filtered query: every chat ID it matches, in display order; `len` is the count. Same readiness rules as `marmot_chat_list_ids` and the same query rules as `marmot_open_chat_list_query_window`, except that it accepts a `MessageText` node; such a query returns `MARMOT_STATUS_CHAT_PRESENTATION_NOT_READY` while retained deletions and edits are still being backfilled. Free with `marmot_string_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotchat_list_query_ids) · [Header contract](include/marmot.h#L12935)

### `marmot_revalidate_chat_list_query_ids`

```c
MarmotStatus marmot_revalidate_chat_list_query_ids(const struct MarmotClient *client, const char *account_ref, const struct MarmotChatListViewQuery *query, const char *const *group_ids, uintptr_t group_ids_len, struct MarmotStringList **out);
```

The subset of a host selection that still matches a filtered query, in the caller's order with duplicates dropped; never adds chats. Inputs are borrowed. Free the result with `marmot_string_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotrevalidate_chat_list_query_ids) · [Header contract](include/marmot.h#L12951)

### `marmot_open_conversation_window`

```c
MarmotStatus marmot_open_conversation_window(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, uint32_t mode, const char *message_id_hex, const uint32_t *initial_rows, uint32_t timeout_ms, struct MarmotConversationWindowSubscription **out_sub);
```

Open one account/group. mode is a MarmotConversationOpenMode discriminant. Message mode requires message_id_hex; other modes require NULL. initial_rows NULL uses 50. Zero timeout uses 30 seconds; opening timeout abandons the opening. No mark-read occurs. # Safety client/strings must be valid; optional pointers readable or NULL, out_sub writable.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotopen_conversation_window) · [Header contract](include/marmot.h#L14578)

### `marmot_onboarding_snapshot_free`

```c
void marmot_onboarding_snapshot_free(struct MarmotOnboardingSnapshot *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L16004)

</details>

<details>
<summary>marmot_p…</summary>

### `marmot_publish_relay_lists`

```c
MarmotStatus marmot_publish_relay_lists(const struct MarmotClient *client, const char *account_ref, const char *const *default_relays, uintptr_t default_relays_len, const char *const *bootstrap_relays, uintptr_t bootstrap_relays_len, const char *const *inbox_relays, uintptr_t inbox_relays_len);
```

Publish NIP-65 + inbox relay lists for the account. Idempotent.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotpublish_relay_lists) · [Header contract](include/marmot.h#L8427)

### `marmot_publish_new_key_package`

```c
MarmotStatus marmot_publish_new_key_package(const struct MarmotClient *client, const char *account_ref, uint64_t *out);
```

Publish a fresh KeyPackage. Writes the accepting-relay count.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotpublish_new_key_package) · [Header contract](include/marmot.h#L8538)

### `marmot_promote_admin`

```c
MarmotStatus marmot_promote_admin(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *member_ref, struct MarmotSendSummary **out);
```

Grant admin rights to `member_ref` (npub or hex). Requires admin. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotpromote_admin) · [Header contract](include/marmot.h#L9703)

### `marmot_promote_admin_detailed`

```c
MarmotStatus marmot_promote_admin_detailed(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *member_ref, struct MarmotGroupMutationResult **out);
```

`marmot_promote_admin` plus refreshed details and management state. Free with `marmot_group_mutation_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotpromote_admin_detailed) · [Header contract](include/marmot.h#L9785)

### `marmot_push_registration`

```c
MarmotStatus marmot_push_registration(const struct MarmotClient *client, const char *account_ref, struct MarmotPushRegistration **out);
```

The account's current push registration; writes NULL with `MARMOT_STATUS_OK` when there is none. Free with `marmot_push_registration_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotpush_registration) · [Header contract](include/marmot.h#L10160)

### `marmot_post_audit_log_file`

```c
MarmotStatus marmot_post_audit_log_file(const struct MarmotClient *client, const char *path, const char *endpoint, struct MarmotAuditLogUploadResult **out);
```

Upload one audit-log file to `endpoint`. Free with `marmot_audit_log_upload_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotpost_audit_log_file) · [Header contract](include/marmot.h#L10309)

### `marmot_post_audit_log_tracker_update`

```c
MarmotStatus marmot_post_audit_log_tracker_update(const struct MarmotClient *client, struct MarmotAuditLogTrackerUpdateResult **out);
```

Run one tracker-driven upload pass with the configured tracker. Free with `marmot_audit_log_tracker_update_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotpost_audit_log_tracker_update) · [Header contract](include/marmot.h#L10338)

### `marmot_presented_chat_list`

```c
MarmotStatus marmot_presented_chat_list(const struct MarmotClient *client, const char *account_ref, uint8_t include_archived, struct MarmotPresentedChatListSnapshot **out);
```

Complete local rows with selected title/avatar. Free with marmot_presented_chat_list_snapshot_free.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotpresented_chat_list) · [Header contract](include/marmot.h#L10390)

### `marmot_presented_chat_list_row`

```c
MarmotStatus marmot_presented_chat_list_row(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotPresentedChatRow **out);
```

Keyed complete row; missing groups return NULL. Free with marmot_presented_chat_row_free.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotpresented_chat_list_row) · [Header contract](include/marmot.h#L10404)

### `marmot_pause_maintenance`

```c
MarmotStatus marmot_pause_maintenance(const struct MarmotClient *client, const char *account_ref);
```

Pause the account's periodic maintenance loop.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotpause_maintenance) · [Header contract](include/marmot.h#L11008)

### `marmot_prewarm_group_member_key_packages`

```c
MarmotStatus marmot_prewarm_group_member_key_packages(const struct MarmotClient *client, const char *account_ref, const char *const *member_refs, uintptr_t member_refs_len, struct MarmotMemberKeyPackagePrewarmSummary **out);
```

Resolve and cache KeyPackages for prospective members ahead of a group creation, so the create itself does not wait on the network. Free with `marmot_member_key_package_prewarm_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotprewarm_group_member_key_packages) · [Header contract](include/marmot.h#L11190)

### `marmot_prepared_group_image_status`

```c
MarmotStatus marmot_prepared_group_image_status(const struct MarmotClient *client, const char *account_ref, const char *upload_id, struct MarmotPreparedGroupImageUpload **out);
```

Where one staged group image sits in its upload lifecycle. Free with `marmot_prepared_group_image_upload_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotprepared_group_image_status) · [Header contract](include/marmot.h#L11286)

### `marmot_prepared_group_images`

```c
MarmotStatus marmot_prepared_group_images(const struct MarmotClient *client, const char *account_ref, struct MarmotPreparedGroupImageUploadList **out);
```

Every staged group image for the account. Free with `marmot_prepared_group_image_upload_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotprepared_group_images) · [Header contract](include/marmot.h#L11301)

### `marmot_periodic_maintenance_policy`

```c
MarmotStatus marmot_periodic_maintenance_policy(const struct MarmotClient *client, const char *account_ref, enum MarmotPeriodicMaintenancePolicy *out);
```

Whether new groups enroll in periodic maintenance.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotperiodic_maintenance_policy) · [Header contract](include/marmot.h#L11378)

### `marmot_parse_markdown`

```c
MarmotStatus marmot_parse_markdown(const struct MarmotClient *client, const char *text, struct MarmotMarkdownDocument **out);
```

Parse Markdown text into the display token tree. Infallible: malformed input degrades inside the parser. Free with `marmot_markdown_document_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotparse_markdown) · [Header contract](include/marmot.h#L11423)

### `marmot_publish_user_profile`

```c
MarmotStatus marmot_publish_user_profile(const struct MarmotClient *client, const char *account_ref, const struct MarmotUserProfileMetadata *profile, const char *const *default_relays, uintptr_t default_relays_len, const char *const *bootstrap_relays, uintptr_t bootstrap_relays_len, struct MarmotUserProfileMetadata **out);
```

Publish the account's kind:0 profile metadata. The returned profile is what was actually published. Free with `marmot_user_profile_metadata_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotpublish_user_profile) · [Header contract](include/marmot.h#L11593)

### `marmot_publish_user_profile_using_account_relays`

```c
MarmotStatus marmot_publish_user_profile_using_account_relays(const struct MarmotClient *client, const char *account_ref, const struct MarmotUserProfileMetadata *profile, struct MarmotUserProfileMetadata **out);
```

Publish the account's kind:0 profile using the account's own relay lists rather than caller-supplied ones. Free with `marmot_user_profile_metadata_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotpublish_user_profile_using_account_relays) · [Header contract](include/marmot.h#L11866)

### `marmot_propose_onboarding_recommended_relays`

```c
MarmotStatus marmot_propose_onboarding_recommended_relays(const struct MarmotClient *client, const char *account_ref, uint32_t step, struct MarmotOnboardingSnapshot **out);
```

Prepare the configured default relay proposal without publishing. `step` is a MarmotOnboardingStep discriminant; out-of-range values return MARMOT_STATUS_INVALID_ARGUMENT. Free the returned snapshot with `marmot_onboarding_snapshot_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotpropose_onboarding_recommended_relays) · [Header contract](include/marmot.h#L12264)

### `marmot_propose_onboarding_relay_repair`

```c
MarmotStatus marmot_propose_onboarding_relay_repair(const struct MarmotClient *client, const char *account_ref, uint32_t step, struct MarmotOnboardingSnapshot **out);
```

Return an owned snapshot with a non-publishing, exact relay-repair preview in `proposal->relay_repair`. Its content, tag fields and non-NULL tag/change endpoints are JSON string literals: decode once with embedded-NUL/UTF-8-length preservation before consent or manual editing, following [the C encoding contract](README.md#onboarding-relay-repair). Inspect its ordered source and proposed tags, unchanged content, typed occurrence diff, and mode before asking for approval. `MARMOT_ONBOARDING_RELAY_REPAIR_MODE_MANUAL_REVIEW` has no approval action; use a separate manual editor or explicitly labeled full reset. The borrowed `account_ref` and validated `step` must identify the current onboarding attempt; free the result with `marmot_onboarding_snapshot_free` and approve only the displayed revision (and recovery epoch where present).

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotpropose_onboarding_relay_repair) · [Header contract](include/marmot.h#L12298)

### `marmot_propose_onboarding_relays`

```c
MarmotStatus marmot_propose_onboarding_relays(const struct MarmotClient *client, const char *account_ref, uint32_t step, const char *const *read_relays, uintptr_t read_relays_len, const char *const *write_relays, uintptr_t write_relays_len, struct MarmotOnboardingSnapshot **out);
```

Prepare a relay proposal without publishing; inbox proposals require an empty write list. `step` is a MarmotOnboardingStep discriminant; out-of-range values return MARMOT_STATUS_INVALID_ARGUMENT. Free the returned snapshot with `marmot_onboarding_snapshot_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotpropose_onboarding_relays) · [Header contract](include/marmot.h#L12276)

### `marmot_propose_onboarding_profile`

```c
MarmotStatus marmot_propose_onboarding_profile(const struct MarmotClient *client, const char *account_ref, const struct MarmotUserProfileMetadata *profile, struct MarmotOnboardingSnapshot **out);
```

Prepare profile edits without publishing; NULL fields preserve existing values and empty strings clear them. Free the returned snapshot with `marmot_onboarding_snapshot_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotpropose_onboarding_profile) · [Header contract](include/marmot.h#L12309)

### `marmot_propose_onboarding_follows`

```c
MarmotStatus marmot_propose_onboarding_follows(const struct MarmotClient *client, const char *account_ref, const char *const *follows, uintptr_t follows_len, struct MarmotOnboardingSnapshot **out);
```

Prepare a follow-list replacement without publishing; an empty list is valid. Free the returned snapshot with `marmot_onboarding_snapshot_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotpropose_onboarding_follows) · [Header contract](include/marmot.h#L12320)

### `marmot_pending_welcome_delivery_list_free`

```c
void marmot_pending_welcome_delivery_list_free(struct MarmotPendingWelcomeDeliveryList *list);
```

Deep-free the complete list returned by `marmot_pending_welcome_deliveries`, including each repair handle's owned strings. NULL is a no-op. Do not free individual items/fields, pass a borrowed pointer, or reuse the list after this call.

[Header contract](include/marmot.h#L15295)

### `marmot_publisher_info_free`

```c
void marmot_publisher_info_free(struct MarmotPublisherInfo *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L13305)

### `marmot_publisher_ack_free`

```c
void marmot_publisher_ack_free(struct MarmotPublisherAck *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L13315)

### `marmot_presented_chat_list_subscription_snapshot`

```c
MarmotStatus marmot_presented_chat_list_subscription_snapshot(const struct MarmotPresentedChatListSubscription *sub, struct MarmotPresentedChatListUpdate **out);
```

Take the initial snapshot with sequence zero. A second call returns CLOSED and NULL. Free the result with marmot_presented_chat_list_update_free. # Safety sub must be live; out must be writable.

[Header contract](include/marmot.h#L14159)

### `marmot_presented_chat_list_subscription_next`

```c
MarmotStatus marmot_presented_chat_list_subscription_next(const struct MarmotPresentedChatListSubscription *sub, uint32_t timeout_ms, struct MarmotPresentedChatListUpdate **out);
```

Read a whole replacement. timeout_ms zero waits indefinitely. Timeout/closed/error leave out NULL; timeout or a storage error does not discard the pending refresh. Retry according to the typed status. Free results with marmot_presented_chat_list_update_free. # Safety sub must be live; out must be writable.

[Header contract](include/marmot.h#L14169)

### `marmot_presented_chat_list_subscription_free`

```c
void marmot_presented_chat_list_subscription_free(struct MarmotPresentedChatListSubscription *sub);
```

Cancel and free a presented-list handle. NULL is a no-op. # Safety sub must be NULL or a live library-owned handle not in use by another call.

[Header contract](include/marmot.h#L14178)

### `marmot_prepared_group_image_upload_free`

```c
void marmot_prepared_group_image_upload_free(struct MarmotPreparedGroupImageUpload *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15490)

### `marmot_prepared_group_image_upload_list_free`

```c
void marmot_prepared_group_image_upload_list_free(struct MarmotPreparedGroupImageUploadList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15499)

### `marmot_push_registration_free`

```c
void marmot_push_registration_free(struct MarmotPushRegistration *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15742)

### `marmot_push_registration_share_outcome_free`

```c
void marmot_push_registration_share_outcome_free(struct MarmotPushRegistrationShareOutcome *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15752)

### `marmot_push_registration_sync_result_free`

```c
void marmot_push_registration_sync_result_free(struct MarmotPushRegistrationSyncResult *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15762)

### `marmot_presented_chat_row_free`

```c
void marmot_presented_chat_row_free(struct MarmotPresentedChatRow *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L16034)

### `marmot_presented_chat_list_snapshot_free`

```c
void marmot_presented_chat_list_snapshot_free(struct MarmotPresentedChatListSnapshot *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L16044)

### `marmot_presented_chat_list_update_free`

```c
void marmot_presented_chat_list_update_free(struct MarmotPresentedChatListUpdate *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L16054)

</details>

<details>
<summary>marmot_q…</summary>

### `marmot_quarantined_groups`

```c
MarmotStatus marmot_quarantined_groups(const struct MarmotClient *client, const char *account_ref, struct MarmotAppQuarantinedGroupList **out);
```

Stored groups that failed session-open hydration and were skipped. Surface them in a per-group recovery flow and offer `marmot_retry_hydrate_quarantined_group`. Free with `marmot_app_quarantined_group_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotquarantined_groups) · [Header contract](include/marmot.h#L9850)

</details>

<details>
<summary>marmot_r…</summary>

### `marmot_read_attachment_asset`

```c
MarmotStatus marmot_read_attachment_asset(const struct MarmotClient *client, const char *account_ref, const char *reference, uint64_t offset, uint32_t limit, struct MarmotAttachmentLocalBytes **out);
```

Read a bounded range (1..=1048576 bytes) from a local reference. No network fallback. Rechecks source visibility/expiry on every call. Offset at/beyond EOF returns available=true and empty bytes. An obsolete or wrong-account reference is unavailable. Free the result with `marmot_attachment_local_bytes_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotread_attachment_asset) · [Header contract](include/marmot.h#L8142)

### `marmot_release_attachment_handoff`

```c
MarmotStatus marmot_release_attachment_handoff(const struct MarmotClient *client, const char *lease);
```

Blocking release of a handoff lease: deletes its copy. An unknown or already released lease returns `MARMOT_STATUS_OK`; a malformed lease returns `MARMOT_STATUS_INVALID_MEDIA_REFERENCE`; a copy that cannot be deleted returns `MARMOT_STATUS_IO` and stays leased, so retry. See the [shared contract](../marmot-uniffi/API-REFERENCE.md#marmotrelease_attachment_handoff).

[Header contract](include/marmot.h#L7906)

### `marmot_remove_attachments_older_than`

```c
MarmotStatus marmot_remove_attachments_older_than(const struct MarmotClient *client, const char *account_ref, uint64_t received_before, const char *group_id_hex, uint64_t *out_removed);
```

Blocking bulk removal of retained attachments received before `received_before` (Unix seconds), account-wide when `group_id_hex` is NULL, writing the count to `out_removed`. Same semantics as `marmot_remove_chat_attachments`.

[Header contract](include/marmot.h#L8083)

### `marmot_remove_chat_attachments`

```c
MarmotStatus marmot_remove_chat_attachments(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, uint64_t *out_removed);
```

Blocking bulk removal of one chat's retained attachments, writing the count to `out_removed`. Each is a Remove (shown as removed, download-again allowed); released media-store files are deleted before the call returns. See the [shared contract](../marmot-uniffi/API-REFERENCE.md#marmotremove_chat_attachments).

[Header contract](include/marmot.h#L8071)

### `marmot_attachment_keep_media`

```c
MarmotStatus marmot_attachment_keep_media(const struct MarmotClient *client, const char *account_ref, uint32_t *out_keep);
```

Blocking read of the account's "Keep media" setting, written to `out_keep` as a `MarmotAttachmentKeepMedia` discriminant (`Forever` by default).

[Header contract](include/marmot.h#L8095)

### `marmot_set_attachment_keep_media`

```c
MarmotStatus marmot_set_attachment_keep_media(const struct MarmotClient *client, const char *account_ref, uint32_t keep, uint64_t *out_removed);
```

Blocking: stores the setting (`keep` is a `MarmotAttachmentKeepMedia` discriminant; out of range is `MARMOT_STATUS_INVALID_ARGUMENT` before any work), then removes every retained attachment already past the new window, and drops unfinished automatic downloads past it, writing the count to `out_removed`. Removed attachments read `CleanedBySetting`. Media-store space is freed before this returns.

[Header contract](include/marmot.h#L8108)

### `marmot_request_avatar_assets`

```c
MarmotStatus marmot_request_avatar_assets(const struct MarmotClient *client, const char *account_ref, const char *const *targets, uintptr_t targets_len, struct MarmotAvatarAssetList **out);
```

Register up to 16 visible avatar targets without awaiting HTTP. Free the returned list with `marmot_avatar_asset_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotrequest_avatar_assets) · [Header contract](include/marmot.h#L8159)

### `marmot_read_avatar_assets`

```c
MarmotStatus marmot_read_avatar_assets(const struct MarmotClient *client, const char *account_ref, const char *const *references, uintptr_t references_len, uint64_t max_bytes, struct MarmotAvatarBytesList **out);
```

Read up to 16 local avatar references with a 1-byte..16-MiB aggregate byte budget. Budget-deferred entries are explicit. Free with `marmot_avatar_bytes_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotread_avatar_assets) · [Header contract](include/marmot.h#L8175)

### `marmot_remove_account`

```c
MarmotStatus marmot_remove_account(const struct MarmotClient *client, const char *account_ref);
```

Remove an account and its local state from this device.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotremove_account) · [Header contract](include/marmot.h#L8228)

### `marmot_rename_linked_device`

```c
MarmotStatus marmot_rename_linked_device(const struct MarmotClient *client, const char *account_ref, const char *slot_id_hex, const char *label);
```

Rename one of this account's devices, this one included, by its `slot_id_hex` from `marmot_linked_devices`: one roster commit in the device group that sets only that device's label (at most 64 bytes of UTF-8; empty clears it). Refused with nothing sent when device groups are unavailable for this client, for a label that is too long, without a device group, for an unknown slot, while its roster cannot be read (`roster_unavailable`), and while an earlier change of this device's is still in flight there (retry later). A rename whose commit loses a fork is made again later, unless another user edit of that device won; show the label `marmot_linked_devices` returns after `MARMOT_EVENT_LINKED_DEVICES_CHANGED`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotrename_linked_device) · [Header contract](include/marmot.h#L9290)

### `marmot_update_linked_device_settings`

```c
MarmotStatus marmot_update_linked_device_settings(const struct MarmotClient *client, const char *account_ref, const char *slot_id_hex, uint8_t has_add_to_all_chats, uint8_t add_to_all_chats, uint8_t has_bring_history, uint8_t bring_history, uint8_t has_keep_while_inactive, uint8_t keep_while_inactive);
```

Patch a linked device's settings on the account worker. Each `has_`/value pair is `uint8_t`: zero presence leaves that setting unchanged; nonzero presence supplies the value, with zero false and nonzero true. The call has no returned allocation. Refused with nothing sent while device groups are off (`roster_unsupported`), without a trusted device group (`no_device_group`), for an unknown slot (`unknown_device`), or while its roster cannot be read (`roster_unavailable`). Earlier lost label/settings edits recover first; retry `device_group_busy` while one remains unsettled. Refresh `marmot_linked_devices` on `MARMOT_EVENT_LINKED_DEVICES_CHANGED`. See the [shared settings contract](../marmot-uniffi/README.md#linked-devices) for history and removal limits.

[Header contract](include/marmot.h#L9313)


### `marmot_remove_linked_device`

```c
MarmotStatus marmot_remove_linked_device(const struct MarmotClient *client, const char *account_ref, const char *slot_id_hex);
```

Remove another of this account's devices, by its `slot_id_hex` from `marmot_linked_devices`, from the device group and every chat, and delete its KeyPackage slot. The removal is recorded at once and carried out as the device group allows; the device shows `removal_pending` until the device group takes it. Refused with nothing recorded when device groups are unavailable for this client, without a device group, for an unknown slot, for this device (sign out instead), while its roster cannot be read (`roster_unavailable`), and for a device whose link may still fail. Re-read `marmot_linked_devices` after `MARMOT_EVENT_LINKED_DEVICES_CHANGED`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotremove_linked_device) · [Header contract](include/marmot.h#L9339)

### `marmot_removed_device_leftover_chats`

```c
MarmotStatus marmot_removed_device_leftover_chats(const struct MarmotClient *client, const char *account_ref, uint32_t *out);
```

How many chats this device is in still hold a device this account no longer has, because the chat does not take a same-account removal; a chat admin can remove it. That device is one this account removed, or one its device group stopped listing, as after a failed link. Zero while device groups are off. Not evented: read it when showing the device list.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotremoved_device_leftover_chats) · [Header contract](include/marmot.h#L9355)

### `marmot_chats_closed_to_linked_devices`

```c
MarmotStatus marmot_chats_closed_to_linked_devices(const struct MarmotClient *client, const char *account_ref, uint32_t *out);
```

How many chats this device is in can't take any device of this account: they don't require `marmot.group.account-devices.v1`, name no relays a sibling Welcome can carry, or already hold this account's limit of 20 leaves. Once a link this device approved is made, the new device is added to this device's other chats when its "add to all my chats" setting is on, for a week after the link; a chat admin can turn the component on in these, and removing a device frees its leaves. A chat that can take this account's devices but whose requirements the new device's KeyPackages don't meet is passed over and not counted, so zero does not mean the new device reaches every chat. Zero while device groups are off. Not evented: read it when showing the device list.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotchats_closed_to_linked_devices) · [Header contract](include/marmot.h#L9379)

### `marmot_recover_onboarding`

```c
MarmotStatus marmot_recover_onboarding(const struct MarmotClient *client, const char *account_ref, uint8_t acknowledge_latest_only_evidence, char **out);
```

Retain opaque evidence, retire the old attempt, and return a new epoch. Requires explicit acknowledgment of latest-only evidence retention. Hosts invalidate old UI callbacks first, then explicitly begin again.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotrecover_onboarding) · [Header contract](include/marmot.h#L8287)

### `marmot_refresh_account_key_packages`

```c
MarmotStatus marmot_refresh_account_key_packages(const struct MarmotClient *client, const char *account_ref, const char *const *bootstrap_relays, uintptr_t bootstrap_relays_len, struct MarmotAccountKeyPackageInventoryEntryList **out);
```

Fetch validated relay observations, then merge a fresh local snapshot. Empty bootstrap relays remain network-enabled. Free with `marmot_account_key_package_inventory_entry_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotrefresh_account_key_packages) · [Header contract](include/marmot.h#L8507)

### `marmot_republish_key_package`

```c
MarmotStatus marmot_republish_key_package(const struct MarmotClient *client, const char *account_ref, uint64_t *out);
```

Re-publish the latest cached KeyPackage when possible, otherwise publish a fresh one. Writes the accepting-relay count.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotrepublish_key_package) · [Header contract](include/marmot.h#L8552)

### `marmot_retained_attachments_page_free`

```c
void marmot_retained_attachments_page_free(struct MarmotRetainedAttachmentsPage *value);
```

Deep-free a retained attachments page, its rows and its borrowed cursor. NULL is a no-op.

[Header contract](include/marmot.h#L8025)

### `marmot_rotate_key_package`

```c
MarmotStatus marmot_rotate_key_package(const struct MarmotClient *client, const char *account_ref, uint64_t *out);
```

Rotate the account's KeyPackage: mint and publish a fresh one, superseding the current slot (the sanctioned repair for an epoch-stalled group; see `MARMOT_EVENT_EPOCH_STALL_ESCALATED`). Writes the accepting-relay count. `marmot_publish_new_key_package` is the same operation under its legacy name.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotrotate_key_package) · [Header contract](include/marmot.h#L8569)

### `marmot_reveal_nsec`

```c
MarmotStatus marmot_reveal_nsec(const struct MarmotClient *client, const char *account_ref, char **out);
```

Export the account's raw private key as `nsec1…` bech32. SENSITIVE: the reveal is audit-logged and permanently marks the account's key-security byte as handled-insecurely. Free the string with `marmot_string_free` as soon as it has been displayed.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotreveal_nsec) · [Header contract](include/marmot.h#L8638)

### `marmot_remove_members`

```c
MarmotStatus marmot_remove_members(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *const *member_refs, uintptr_t member_refs_len, struct MarmotSendSummary **out);
```

Remove members from the group. Requires admin; preflight rejects self-removal and removing the last admin. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotremove_members) · [Header contract](include/marmot.h#L8785)

### `marmot_remove_members_detailed`

```c
MarmotStatus marmot_remove_members_detailed(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *const *member_refs, uintptr_t member_refs_len, struct MarmotGroupMutationResult **out);
```

`marmot_remove_members` plus refreshed details and management state. Free with `marmot_group_mutation_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotremove_members_detailed) · [Header contract](include/marmot.h#L9768)

### `marmot_retry_hydrate_quarantined_group`

```c
MarmotStatus marmot_retry_hydrate_quarantined_group(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, bool *out);
```

Re-attempt hydration of a single quarantined group. Writes true if the group recovered and is now a live chat, false if it stays quarantined. Unknown-group status if the id is not quarantined.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotretry_hydrate_quarantined_group) · [Header contract](include/marmot.h#L9865)

### `marmot_retry_group_convergence`

```c
MarmotStatus marmot_retry_group_convergence(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotSendSummary **out);
```

Re-drive delivery/convergence for the group (e.g. a stuck pending own message) without minting duplicates. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotretry_group_convergence) · [Header contract](include/marmot.h#L9990)

### `marmot_react_to_message`

```c
MarmotStatus marmot_react_to_message(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *target_message_id, const char *emoji, struct MarmotSendSummary **out);
```

React to a message with `emoji`. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotreact_to_message) · [Header contract](include/marmot.h#L10005)

### `marmot_react_with_media`

```c
MarmotStatus marmot_react_with_media(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *target_message_id, const char *emoji, const struct MarmotMediaAttachmentReference *attachments, uintptr_t attachments_len, const struct MarmotStringArray *tags, uintptr_t tags_len, struct MarmotSendSummary **out);
```

React with a custom emoji image: uploaded `attachments` become `imeta` tags on the kind-7 and `tags` name them (NIP-30 `emoji`). Preserve each reference's local `source_epoch_identity`; missing provenance or a changed upload branch requires a fresh upload. `imeta` rows in `tags` are rejected. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotreact_with_media) · [Header contract](include/marmot.h#L11710)

### `marmot_reply_to_message`

```c
MarmotStatus marmot_reply_to_message(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *target_message_id, const char *text, struct MarmotSendSummary **out);
```

Reply to a message. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotreply_to_message) · [Header contract](include/marmot.h#L10037)

### `marmot_relay_telemetry_settings`

```c
MarmotStatus marmot_relay_telemetry_settings(const struct MarmotClient *client, struct MarmotRelayTelemetrySettings **out);
```

Current relay-telemetry export settings. Free with `marmot_relay_telemetry_settings_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotrelay_telemetry_settings) · [Header contract](include/marmot.h#L10245)

### `marmot_refresh_profile`

```c
MarmotStatus marmot_refresh_profile(const struct MarmotClient *client, const char *account_id_hex, const char *const *relays, uintptr_t relays_len);
```

Refresh the cached profile for an account id from `relays`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotrefresh_profile) · [Header contract](include/marmot.h#L10602)

### `marmot_refresh_user_relay_lists`

```c
MarmotStatus marmot_refresh_user_relay_lists(const struct MarmotClient *client, const char *account_id_hex, const char *const *relays, uintptr_t relays_len, struct MarmotAccountRelayLists **out);
```

Fetch an account's published relay lists from `relays`, updating the cache. Free with `marmot_account_relay_lists_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotrefresh_user_relay_lists) · [Header contract](include/marmot.h#L10631)

### `marmot_reset_incomplete_account_setup`

```c
MarmotStatus marmot_reset_incomplete_account_setup(const struct MarmotClient *client, const char *nsec, uint8_t acknowledge_possible_key_package_orphan);
```

Discard the local state of an account whose setup never completed. `acknowledge_possible_key_package_orphan` confirms the caller accepts that a published KeyPackage may be left orphaned.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotreset_incomplete_account_setup) · [Header contract](include/marmot.h#L10763)

### `marmot_resume_maintenance`

```c
MarmotStatus marmot_resume_maintenance(const struct MarmotClient *client, const char *account_ref);
```

Resume the account's periodic maintenance loop.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotresume_maintenance) · [Header contract](include/marmot.h#L11019)

### `marmot_run_due_maintenance`

```c
MarmotStatus marmot_run_due_maintenance(const struct MarmotClient *client, const char *account_ref, struct MarmotMaintenanceRunSummary **out);
```

Run every maintenance obligation that is due now. Free with `marmot_maintenance_run_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotrun_due_maintenance) · [Header contract](include/marmot.h#L11365)

### `marmot_random_profile_pseudonym`

```c
MarmotStatus marmot_random_profile_pseudonym(const struct MarmotClient *client, char **out);
```

Random cosmetic display name from the shared wordlists. Free with `marmot_string_free`. This does not create an account or generate a signing key.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotrandom_profile_pseudonym) · [Header contract](include/marmot.h#L11487)

### `marmot_relay_health`

```c
MarmotStatus marmot_relay_health(const struct MarmotClient *client, struct MarmotRelayHealth **out);
```

Aggregate relay-pool health. Free with `marmot_relay_health_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotrelay_health) · [Header contract](include/marmot.h#L11495)

### `marmot_replace_encrypted_media_blob_endpoints`

```c
MarmotStatus marmot_replace_encrypted_media_blob_endpoints(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const struct MarmotAppBlobEndpoint *endpoints, uintptr_t endpoints_len, struct MarmotSendSummary **out);
```

Replace the group's encrypted-media default blob endpoints as a full component update. Requires admin. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotreplace_encrypted_media_blob_endpoints) · [Header contract](include/marmot.h#L11635)

### `marmot_retired_relay_hosts`

```c
MarmotStatus marmot_retired_relay_hosts(const struct MarmotClient *client, struct MarmotStringList **out);
```

The centralized retired-relay denylist. These hosts must never be dialed or adopted. Free with `marmot_string_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotretired_relay_hosts) · [Header contract](include/marmot.h#L11907)

### `marmot_record_host_performance`

```c
MarmotStatus marmot_record_host_performance(const struct MarmotClient *client, uint32_t operation, uint64_t duration_ms, uint32_t outcome);
```

Record how long a host-side operation took, so it joins the runtime's own timings in `marmot_app_performance_snapshot`. `operation` and `outcome` are discriminants; out-of-range values are rejected with `MARMOT_STATUS_INVALID_ARGUMENT`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotrecord_host_performance) · [Header contract](include/marmot.h#L12172)

### `marmot_run_onboarding`

```c
MarmotStatus marmot_run_onboarding(const struct MarmotClient *client, const char *account_ref, struct MarmotOnboardingSnapshot **out);
```

Resume pending checks until user input or a retry is needed. Free the returned snapshot with `marmot_onboarding_snapshot_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotrun_onboarding) · [Header contract](include/marmot.h#L12229)

### `marmot_retry_onboarding_step`

```c
MarmotStatus marmot_retry_onboarding_step(const struct MarmotClient *client, const char *account_ref, uint32_t step, struct MarmotOnboardingSnapshot **out);
```

Retry an offered step; earlier checks invalidate downstream readiness. `step` is a MarmotOnboardingStep discriminant; out-of-range values return MARMOT_STATUS_INVALID_ARGUMENT. Free the returned snapshot with `marmot_onboarding_snapshot_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotretry_onboarding_step) · [Header contract](include/marmot.h#L12240)

### `marmot_record_product_event`

```c
MarmotStatus marmot_record_product_event(const struct MarmotClient *client, const struct MarmotProductEvent *input, enum MarmotProductRecordResult *out);
```

Forward a validated product analytics input. # Safety Client and borrowed input must be valid; output, when present, must be writable.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotrecord_product_event) · [Header contract](include/marmot.h#L12404)

### `marmot_record_host_timing`

```c
MarmotStatus marmot_record_host_timing(const struct MarmotClient *client, const char *name, uint64_t duration_ms, uint32_t outcome, enum MarmotProductRecordResult *out);
```

Record an app-defined timing through the consent-gated product exporter. Register `name` with `elapsed: DurationBucket` and `outcome: Enum` choices `success`/`failure`. Milliseconds are bucketed before recording. # Safety Client and borrowed name must be valid; out must be writable.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotrecord_host_timing) · [Header contract](include/marmot.h#L12415)

### `marmot_reported_message`

```c
MarmotStatus marmot_reported_message(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *message_id, struct MarmotTimelineMessageRecord **out);
```

# Safety `client` must be a live handle; string arguments must be valid NUL-terminated strings (nullable ones may be NULL); array arguments must hold their stated length (or be NULL with length 0); out-pointers must be valid.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotreported_message) · [Header contract](include/marmot.h#L12770)

### `marmot_report_dismissals`

```c
MarmotStatus marmot_report_dismissals(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *report_id, const char *after, uint32_t limit, struct MarmotReportDismissalPage **out);
```

# Safety `client` must be a live handle; string arguments must be valid NUL-terminated strings (nullable ones may be NULL); array arguments must hold their stated length (or be NULL with length 0); out-pointers must be valid.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotreport_dismissals) · [Header contract](include/marmot.h#L12800)

### `marmot_report_message`

```c
MarmotStatus marmot_report_message(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *message_id, uint32_t reason, const char *explanation, struct MarmotSendSummary **out);
```

Report one group message. Reason is a MarmotReportReason discriminant. # Safety Client, strings and output pointer must be valid. Inputs are borrowed.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotreport_message) · [Header contract](include/marmot.h#L12813)

### `marmot_runtime_message_received_free`

```c
void marmot_runtime_message_received_free(struct MarmotRuntimeMessageReceived *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15684)

### `marmot_retention_sweep_report_free`

```c
void marmot_retention_sweep_report_free(struct MarmotRetentionSweepReport *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15702)

### `marmot_relay_health_free`

```c
void marmot_relay_health_free(struct MarmotRelayHealth *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15811)

### `marmot_relay_telemetry_settings_free`

```c
void marmot_relay_telemetry_settings_free(struct MarmotRelayTelemetrySettings *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15821)

### `marmot_relay_endpoint_classification_free`

```c
void marmot_relay_endpoint_classification_free(struct MarmotRelayEndpointClassification *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15831)

### `marmot_relay_endpoint_classification_list_free`

```c
void marmot_relay_endpoint_classification_list_free(struct MarmotRelayEndpointClassificationList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15840)

### `marmot_report_dismissal_page_free`

```c
void marmot_report_dismissal_page_free(struct MarmotReportDismissalPage *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L16181)

</details>

<details>
<summary>marmot_s…</summary>

### `marmot_send_sticker`

```c
MarmotStatus marmot_send_sticker(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *pack_coordinate, const char *shortcode, const char *plaintext_sha256, struct MarmotSendSummary **out);
```

Sends one exact sticker reference. Preflights the output pointer before any send. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsend_sticker) · [Header contract](include/marmot.h#L12738)

### `marmot_sticker_asset_free`

```c
void marmot_sticker_asset_free(struct MarmotStickerAsset *ptr);
```

Frees a sticker asset and its owned bytes. NULL is safe.

[Header contract](include/marmot.h#L15907)

### `marmot_sticker_free`

```c
void marmot_sticker_free(struct MarmotSticker *ptr);
```

Frees one embedded sticker record returned as a root. NULL is safe.

[Header contract](include/marmot.h#L15869)

### `marmot_sticker_import_result_free`

```c
void marmot_sticker_import_result_free(struct MarmotStickerImportResult *value);
```

Frees an import result, its pack, and skipped-id strings. NULL is safe.

[Header contract](include/marmot.h#L15926)

### `marmot_sticker_list_free`

```c
void marmot_sticker_list_free(struct MarmotStickerList *list);
```

Frees a sticker list and every owned element. NULL is safe.

[Header contract](include/marmot.h#L15878)

### `marmot_sticker_pack`

```c
MarmotStatus marmot_sticker_pack(const struct MarmotClient *client, const char *account_ref, const char *input, struct MarmotStickerPack **out);
```

Reads one cached pack by coordinate or trusted link without network I/O. Returns NULL when absent. Free with `marmot_sticker_pack_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsticker_pack) · [Header contract](include/marmot.h#L12472)

### `marmot_sticker_pack_free`

```c
void marmot_sticker_pack_free(struct MarmotStickerPack *ptr);
```

Frees one pack, its cover, and sticker vector. NULL is safe.

[Header contract](include/marmot.h#L15888)

### `marmot_sticker_pack_list_free`

```c
void marmot_sticker_pack_list_free(struct MarmotStickerPackList *list);
```

Frees a pack list and every owned pack. NULL is safe.

[Header contract](include/marmot.h#L15897)

### `marmot_sticker_packs`

```c
MarmotStatus marmot_sticker_packs(const struct MarmotClient *client, const char *account_ref, uint8_t installed_only, const char *search, uint8_t has_limit, uint32_t limit, struct MarmotStickerPackList **out);
```

Reads the encrypted sticker projection off the UI thread. installed_only is a uint8_t flag; has_limit 0 leaves the storage default. Free with `marmot_sticker_pack_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsticker_packs) · [Header contract](include/marmot.h#L12454)

### `marmot_sticker_ref_free`

```c
void marmot_sticker_ref_free(struct MarmotStickerRef *ptr);
```

Frees one exact sticker reference. NULL is safe.

[Header contract](include/marmot.h#L15859)

### `marmot_sticker_sync_result_free`

```c
void marmot_sticker_sync_result_free(struct MarmotStickerSyncResult *ptr);
```

Frees a sync result. NULL is safe.

[Header contract](include/marmot.h#L15917)

### `marmot_string_free`

```c
void marmot_string_free(char *s);
```

Free a string returned by this library (`marmot_last_error_message`, string out-params). NULL is a no-op.

[Header contract](include/marmot.h#L7784)

### `marmot_sign_out_and_wipe`

```c
MarmotStatus marmot_sign_out_and_wipe(const struct MarmotClient *client, const char *account_ref, struct MarmotWipeOutcome **out);
```

Destructive sign-out: leave groups, delete relay KeyPackages, wipe local state. With linked devices it first asks them to take it out, which can take about 30 seconds; `groups_left_to_siblings` and `siblings_not_reached` report how that went. Every stage is reported in the outcome. Free with `marmot_wipe_outcome_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsign_out_and_wipe) · [Header contract](include/marmot.h#L8241)

### `marmot_sign_out`

```c
MarmotStatus marmot_sign_out(const struct MarmotClient *client, const char *account_ref, uint8_t delete_key_packages, struct MarmotSignOutOutcome **out);
```

Non-destructive sign-out: deactivate the account on this device, keeping local state so it can sign back in later. When `delete_key_packages` is true, this device's KeyPackage slot gets a NIP-09 deletion. Free with `marmot_sign_out_outcome_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsign_out) · [Header contract](include/marmot.h#L8257)

### `marmot_set_onboarding_discovery_relays`

```c
MarmotStatus marmot_set_onboarding_discovery_relays(const struct MarmotClient *client, const char *account_ref, const char *const *discovery_relays, uintptr_t discovery_relays_len, struct MarmotOnboardingSnapshot **out);
```

# Safety `client` must be a live handle; string arguments must be valid NUL-terminated strings (nullable ones may be NULL); array arguments must hold their stated length (or be NULL with length 0); out-pointers must be valid.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotset_onboarding_discovery_relays) · [Header contract](include/marmot.h#L8330)

### `marmot_start_fresh`

```c
MarmotStatus marmot_start_fresh(const struct MarmotClient *client, const char *account_ref);
```

Start this device without the devices its first sign-in check found ("No, start fresh"): every sign-in from before this device is answered Not now, now and when one is listed later; blocks on the account worker. It rejects nothing and raises no compromise warning. Before the first check, once this device trusts a device group, and while device groups are off, it is refused with a device-group error.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotstart_fresh) · [Header contract](include/marmot.h#L9427)

### `marmot_started_fresh`

```c
MarmotStatus marmot_started_fresh(const struct MarmotClient *client, const char *account_ref, bool *out);
```

Write whether this device started fresh and still trusts no device group, so the app can say that only chats it is invited to from now on are here; blocks on the account worker without network I/O. Re-read after `marmot_start_fresh` and on `MARMOT_EVENT_LINKED_DEVICES_CHANGED`. Always false without explicit dev capability and runtime intent.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotstarted_fresh) · [Header contract](include/marmot.h#L9440)

### `marmot_sign_in_account`

```c
MarmotStatus marmot_sign_in_account(const struct MarmotClient *client, const char *account_ref, struct MarmotAccountSummary **out);
```

Re-activate a non-destructively signed-out local account. Free with `marmot_account_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsign_in_account) · [Header contract](include/marmot.h#L8414)

### `marmot_set_account_nip65_relays`

```c
MarmotStatus marmot_set_account_nip65_relays(const struct MarmotClient *client, const char *account_ref, const char *const *relays, uintptr_t relays_len, const char *const *bootstrap_relays, uintptr_t bootstrap_relays_len, struct MarmotAccountRelayLists **out);
```

Replace the account's NIP-65 relay list and publish it. Free with `marmot_account_relay_lists_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotset_account_nip65_relays) · [Header contract](include/marmot.h#L8600)

### `marmot_set_account_inbox_relays`

```c
MarmotStatus marmot_set_account_inbox_relays(const struct MarmotClient *client, const char *account_ref, const char *const *relays, uintptr_t relays_len, const char *const *bootstrap_relays, uintptr_t bootstrap_relays_len, struct MarmotAccountRelayLists **out);
```

Replace the account's inbox relay list and publish it. Free with `marmot_account_relay_lists_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotset_account_inbox_relays) · [Header contract](include/marmot.h#L8618)

### `marmot_self_demote_admin`

```c
MarmotStatus marmot_self_demote_admin(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotSendSummary **out);
```

Step down as an admin (demote the active account). Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotself_demote_admin) · [Header contract](include/marmot.h#L9735)

### `marmot_self_demote_admin_detailed`

```c
MarmotStatus marmot_self_demote_admin_detailed(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotGroupMutationResult **out);
```

`marmot_self_demote_admin` plus refreshed details and management state. Free with `marmot_group_mutation_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotself_demote_admin_detailed) · [Header contract](include/marmot.h#L9817)

### `marmot_set_group_archived`

```c
MarmotStatus marmot_set_group_archived(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, uint8_t archived, struct MarmotAppGroupRecord **out);
```

Flag a group archived (or restore it). Local-only projection state. Free with `marmot_app_group_record_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotset_group_archived) · [Header contract](include/marmot.h#L9892)

### `marmot_send_text`

```c
MarmotStatus marmot_send_text(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *text, struct MarmotSendSummary **out);
```

Send a chat text message to the group. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsend_text) · [Header contract](include/marmot.h#L9908)

### `marmot_send_tagged_text`

```c
MarmotStatus marmot_send_tagged_text(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const struct MarmotStringArray *tags, uintptr_t tags_len, const char *content, struct MarmotSendSummary **out);
```

Send kind-9 text with application tags (for example NIP-30 `emoji`). `tags` follows `marmot_send_custom_event` row ownership; `imeta` rows are rejected. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsend_tagged_text) · [Header contract](include/marmot.h#L12052)

### `marmot_secure_delete_expired`

```c
MarmotStatus marmot_secure_delete_expired(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotSecureDeleteExpiredResult **out);
```

Securely delete this group's expired disappearing messages now. Free with `marmot_secure_delete_expired_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsecure_delete_expired) · [Header contract](include/marmot.h#L10088)

### `marmot_set_local_notifications_enabled`

```c
MarmotStatus marmot_set_local_notifications_enabled(const struct MarmotClient *client, const char *account_ref, uint8_t enabled, struct MarmotNotificationSettings **out);
```

Toggle local notifications for the account. Free with `marmot_notification_settings_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotset_local_notifications_enabled) · [Header contract](include/marmot.h#L10129)

### `marmot_set_native_push_enabled`

```c
MarmotStatus marmot_set_native_push_enabled(const struct MarmotClient *client, const char *account_ref, uint8_t enabled, struct MarmotNotificationSettings **out);
```

Toggle native push for the account. Free with `marmot_notification_settings_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotset_native_push_enabled) · [Header contract](include/marmot.h#L10144)

### `marmot_set_chat_manually_unread`

```c
MarmotStatus marmot_set_chat_manually_unread(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, uint8_t manually_unread, struct MarmotChatListRow **out);
```

Mark a conversation manually unread (or clear that mark); writes the refreshed row, or NULL with `MARMOT_STATUS_OK` when the group has no row. Free with `marmot_chat_list_row_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotset_chat_manually_unread) · [Header contract](include/marmot.h#L10452)

### `marmot_set_chat_pinned`

```c
MarmotStatus marmot_set_chat_pinned(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, uint8_t pinned, struct MarmotChatPinState **out);
```

Pin or unpin a conversation. Writes the account's full pin state. Free with `marmot_chat_pin_state_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotset_chat_pinned) · [Header contract](include/marmot.h#L10468)

### `marmot_set_pinned_chat_order`

```c
MarmotStatus marmot_set_pinned_chat_order(const struct MarmotClient *client, const char *account_ref, const char *const *ordered_group_ids, uintptr_t ordered_group_ids_len, struct MarmotChatPinState **out);
```

Replace the pinned-section order. `ordered_group_ids` lists every pinned group in display order. Free with `marmot_chat_pin_state_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotset_pinned_chat_order) · [Header contract](include/marmot.h#L10485)

### `marmot_set_chat_muted`

```c
MarmotStatus marmot_set_chat_muted(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, uint8_t has_muted_until_ms, int64_t muted_until_ms, struct MarmotChatNotificationSettings **out);
```

Mute a conversation. `has_muted_until_ms` plus `muted_until_ms` set a timed mute; leaving the flag unset mutes indefinitely. Free with `marmot_chat_notification_settings_free`.
Ordinary notification updates stay suppressed, while direct mentions of the receiving account reach subscriptions with `MarmotNotificationUpdate.is_mention` set; blocked senders remain suppressed. Hosts apply their own notification permission and channel settings.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotset_chat_muted) · [Header contract](include/marmot.h#L10517)

### `marmot_schedule_group_self_update`

```c
MarmotStatus marmot_schedule_group_self_update(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, char **out);
```

Queue an MLS self-update commit for the group. Writes the scheduled job id; free it with `marmot_string_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotschedule_group_self_update) · [Header contract](include/marmot.h#L10994)

### `marmot_search_cached_users`

```c
MarmotStatus marmot_search_cached_users(const struct MarmotClient *client, const char *account_id_hex, const char *query, uint32_t limit, struct MarmotUserDirectorySearchResultList **out);
```

Search public identities cached through any connected account. Follow flags refer to the selected account. Call off the UI thread and free with `marmot_user_directory_search_result_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsearch_cached_users) · [Header contract](include/marmot.h#L11094)

### `marmot_sweep_expired_retention`

```c
MarmotStatus marmot_sweep_expired_retention(const struct MarmotClient *client, const char *account_ref, uint64_t now_ms, struct MarmotRetentionSweepReport **out);
```

Prune messages past their disappearing-message retention. `now_ms` is the caller's wall clock. Free with `marmot_retention_sweep_report_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsweep_expired_retention) · [Header contract](include/marmot.h#L11393)

### `marmot_set_relay_telemetry_settings`

```c
MarmotStatus marmot_set_relay_telemetry_settings(const struct MarmotClient *client, const struct MarmotRelayTelemetrySettings *settings, struct MarmotRelayTelemetrySettings **out);
```

Deprecated consent control: use `marmot_set_usage_diagnostics_consent`. Enable requires a combined grant; disable revokes both exporters. The telemetry interval remains configurable. Free the result with `marmot_relay_telemetry_settings_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotset_relay_telemetry_settings) · [Header contract](include/marmot.h#L11507)

### `marmot_set_relay_telemetry_runtime_config`

```c
MarmotStatus marmot_set_relay_telemetry_runtime_config(const struct MarmotClient *client, const struct MarmotRelayTelemetryRuntimeConfig *config);
```

Set the runtime OTLP route for relay telemetry.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotset_relay_telemetry_runtime_config) · [Header contract](include/marmot.h#L11517)

### `marmot_set_audit_log_settings`

```c
MarmotStatus marmot_set_audit_log_settings(const struct MarmotClient *client, const struct MarmotAuditLogSettings *settings, struct MarmotAuditLogSettings **out);
```

Replace the audit-log recorder settings. Free the result with `marmot_audit_log_settings_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotset_audit_log_settings) · [Header contract](include/marmot.h#L11528)

### `marmot_set_audit_log_retention`

```c
MarmotStatus marmot_set_audit_log_retention(const struct MarmotClient *client, const struct MarmotAuditLogRetention *retention, struct MarmotAuditLogRetention **out);
```

Replace the local audit-log retention policy. `retention` is borrowed. The stored value, clamped to 1-30 days and at least 16 MiB per account, is returned; free it with `marmot_audit_log_retention_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotset_audit_log_retention) · [Header contract](include/marmot.h#L11541)

### `marmot_set_audit_log_tracker_config`

```c
MarmotStatus marmot_set_audit_log_tracker_config(const struct MarmotClient *client, const struct MarmotAuditLogTrackerConfig *config, struct MarmotAuditLogTrackerConfig **out);
```

Replace the audit-log tracker endpoint config. Free the result with `marmot_audit_log_tracker_config_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotset_audit_log_tracker_config) · [Header contract](include/marmot.h#L11553)

### `marmot_set_audit_log_tracker_config_v4`

```c
MarmotStatus marmot_set_audit_log_tracker_config_v4(const struct MarmotClient *client, const struct MarmotAuditLogTrackerConfigV4 *config, struct MarmotAuditLogTrackerConfigV4 **out);
```

Replace the audit-log tracker endpoint config. Free the result with `marmot_audit_log_tracker_config_v4_free`.

[Header contract](include/marmot.h#L11565)

### `marmot_send_media_attachments`

```c
MarmotStatus marmot_send_media_attachments(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const struct MarmotMediaAttachmentReference *attachments, uintptr_t attachments_len, const char *caption, struct MarmotSendSummary **out);
```

Send previously uploaded attachments as one message, preserving their local `source_epoch_identity`. Missing provenance or a changed upload branch requires a fresh upload. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsend_media_attachments) · [Header contract](include/marmot.h#L11651)

### `marmot_send_tagged_media`

```c
MarmotStatus marmot_send_tagged_media(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const struct MarmotMediaAttachmentReference *attachments, uintptr_t attachments_len, const struct MarmotStringArray *tags, uintptr_t tags_len, const char *caption, struct MarmotSendSummary **out);
```

Send previously uploaded attachments as one kind-9 message that also carries application tags (for example NIP-30 `emoji` naming an attachment's locator). Preserve each upload reference's local `source_epoch_identity`; missing provenance or a changed upload branch requires a fresh upload. `imeta` rows in `tags` are rejected. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsend_tagged_media) · [Header contract](include/marmot.h#L11689)

### `marmot_send_media_reference`

```c
MarmotStatus marmot_send_media_reference(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const struct MarmotMediaAttachmentReference *reference, const char *caption, struct MarmotSendSummary **out);
```

Send one previously uploaded attachment as a message. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsend_media_reference) · [Header contract](include/marmot.h#L11729)

### `marmot_start_agent_text_stream`

```c
MarmotStatus marmot_start_agent_text_stream(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *stream_id_hex, const char *const *quic_candidates, uintptr_t quic_candidates_len, struct MarmotAgentStreamStart **out);
```

Publish a kind-1200 agent text stream start (anchor) for the group. `stream_id_hex` NULL mints a fresh id; `quic_candidates` are the broker route candidates. Free with `marmot_agent_stream_start_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotstart_agent_text_stream) · [Header contract](include/marmot.h#L11830)

### `marmot_storage_is_closed`

```c
MarmotStatus marmot_storage_is_closed(const struct MarmotClient *client, bool *out_closed);
```

Whether this client's storage has been closed (by `marmot_client_shutdown_and_close`). Writes to `out_closed`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotstorage_is_closed) · [Header contract](include/marmot.h#L11898)

### `marmot_save_message_draft`

```c
MarmotStatus marmot_save_message_draft(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *content, const char *reply_to_message_id_hex, const struct MarmotMessageDraftAttachmentInput *attachments, uintptr_t attachments_len, struct MarmotMessageDraft **out);
```

Store (or replace) the draft for a conversation. `attachments` are copied — the caller keeps ownership of every buffer. Free the result with `marmot_message_draft_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsave_message_draft) · [Header contract](include/marmot.h#L11921)

### `marmot_stage_prepared_group_image`

```c
MarmotStatus marmot_stage_prepared_group_image(const struct MarmotClient *client, const char *account_ref, const uint8_t *plaintext, uintptr_t plaintext_len, const char *media_type, struct MarmotPreparedGroupImageUpload **out);
```

Encrypt and stage a group image without attaching it to a group yet, so the upload can finish before the caller commits to creating one. The bytes are copied — the caller keeps ownership. Free with `marmot_prepared_group_image_upload_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotstage_prepared_group_image) · [Header contract](include/marmot.h#L12010)

### `marmot_set_periodic_maintenance_policy`

```c
MarmotStatus marmot_set_periodic_maintenance_policy(const struct MarmotClient *client, const char *account_ref, uint32_t policy);
```

Set whether new groups enroll in periodic maintenance.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotset_periodic_maintenance_policy) · [Header contract](include/marmot.h#L12023)

### `marmot_send_custom_event`

```c
MarmotStatus marmot_send_custom_event(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, uint64_t kind, const struct MarmotStringArray *tags, uintptr_t tags_len, const char *content, struct MarmotSendSummary **out);
```

Send a custom application event into the group. `tags` is a flat array of `tags_len` tag rows, each row a `(char **, len)` pair of string values. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsend_custom_event) · [Header contract](include/marmot.h#L12070)

### `marmot_create_poll`

**Current.** Create an encrypted NIP-88 group poll through the bounded typed surface.

```c
MarmotStatus marmot_create_poll(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *question, const char *const *options, uintptr_t options_len, uint32_t poll_type, uint8_t has_ends_at, uint64_t ends_at, struct MarmotSendSummary **out);
```

Pass two through ten labels, a valid `MarmotPollType` discriminant, and use `has_ends_at` to distinguish no deadline
from the Unix-seconds `ends_at` value. Creation follows MDK's canonical conversation classification: named two-member
conversations are groups, while unnamed two-member conversations are direct. MDK assigns stable option ids. The call
blocks and `out` is released with `marmot_send_summary_free`; recompile for the added timeline poll record. See
[the shared poll contract](../marmot-uniffi/POLLS.md).

[Header contract](include/marmot.h#L12088)

### `marmot_cast_poll_vote`

**Current.** C mirror of the typed replacement-vote API.

```c
MarmotStatus marmot_cast_poll_vote(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *poll_event_id, const char *const *option_ids, uintptr_t option_ids_len, struct MarmotSendSummary **out);
```

Pass the complete option-id selection from the poll projection; an empty selection is not an unvote. The poll must be
valid, local to the named group, and open. MDK revalidates it against the response event's actual timestamp at send
time, and it remains votable after conversation reclassification. The call blocks and `out` is released with
`marmot_send_summary_free`. See
[the shared poll contract](../marmot-uniffi/POLLS.md).

[Header contract](include/marmot.h#L12106)

### `marmot_message_reactions`

```c
MarmotStatus marmot_message_reactions(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *message_id_hex, struct MarmotTimelineUserReactionList **out);
```

Read a complete local snapshot of effective sender/emoji participants for one message; see [shared details semantics](../marmot-uniffi/CONVERSATION-WINDOW.md#complete-reaction-details). Call off the UI thread. Inputs are borrowed valid NUL-terminated strings; the required out pointer is cleared before validation. On success the caller owns the result and releases it with `marmot_timeline_user_reaction_list_free`.

[Header contract](include/marmot.h#L8124)

### `marmot_sync_sticker_packs`

```c
MarmotStatus marmot_sync_sticker_packs(const struct MarmotClient *client, const char *account_ref, struct MarmotStickerSyncResult **out);
```

Refreshes public discovery and cached installed packs. Pending install changes are published only after a complete installed-list read; incomplete reads leave them pending. Free with `marmot_sticker_sync_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsync_sticker_packs) · [Header contract](include/marmot.h#L12487)

### `marmot_timeline_user_reaction_list_free`

```c
void marmot_timeline_user_reaction_list_free(struct MarmotTimelineUserReactionList *list);
```

Deep-free a root reaction list returned by `marmot_message_reactions`, including strings and items. NULL is a no-op; never free embedded items separately, and never use the list after freeing it.

[Header contract](include/marmot.h#L15955)

### `marmot_poll_votes`

**Current.** C mirror of the per-voter poll read.

```c
MarmotStatus marmot_poll_votes(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *poll_event_id, uint8_t has_after, uint64_t after_voted_at, const char *after_voter_account_id_hex, uint32_t limit, struct MarmotPollVotePage **out);
```

Returns one page of each voter's effective selection by the same rules as `MarmotTimelineMessageRecord.poll`; all pages
together sum to the tally. Blocked voters stay listed; a missing, deleted, hidden, or non-poll row gives an empty page.
Votes are ordered by `(voted_at, voter_account_id_hex)`. Pass `has_after = 0` and a NULL voter for the first page, then
the last vote's `voted_at` and `voter_account_id_hex` while `has_more_after` is set. `limit` is 1..=100 because
retained votes from former members are not bounded by the current group size. The call blocks, and `out` is released
with `marmot_poll_vote_page_free`. See [the shared poll contract](../marmot-uniffi/POLLS.md).

[Header contract](include/marmot.h#L12127)

### `marmot_poll_vote_page_free`

```c
void marmot_poll_vote_page_free(struct MarmotPollVotePage *ptr);
```

Free a page returned by `marmot_poll_votes`, including its votes. NULL is a no-op.

[Header contract](include/marmot.h#L15946)

### `marmot_set_usage_diagnostics_consent`

```c
MarmotStatus marmot_set_usage_diagnostics_consent(const struct MarmotClient *client, uint8_t enabled, struct MarmotUsageDiagnosticsSettings **out);
```

# Safety `client` must be a live handle; string arguments must be valid NUL-terminated strings (nullable ones may be NULL); array arguments must hold their stated length (or be NULL with length 0); out-pointers must be valid.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotset_usage_diagnostics_consent) · [Header contract](include/marmot.h#L12366)

### `marmot_set_product_analytics_runtime_config`

```c
MarmotStatus marmot_set_product_analytics_runtime_config(const struct MarmotClient *client, const struct MarmotProductAnalyticsRuntimeConfig *input);
```

Forward a validated product analytics input. # Safety Client and borrowed input must be valid; output, when present, must be writable.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotset_product_analytics_runtime_config) · [Header contract](include/marmot.h#L12396)

### `marmot_set_product_analytics_activity`

```c
MarmotStatus marmot_set_product_analytics_activity(const struct MarmotClient *client, uint32_t activity);
```

Signal host activity. Discriminants are validated before conversion. # Safety Client must be a live handle.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotset_product_analytics_activity) · [Header contract](include/marmot.h#L12426)

### `marmot_subscribe_events`

```c
MarmotStatus marmot_subscribe_events(const struct MarmotClient *client, struct MarmotEventsSubscription **out_sub);
```

Subscribe to the event firehose. Free with `marmot_events_subscription_free` (before freeing the client).

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsubscribe_events) · [Header contract](include/marmot.h#L13437)

### `marmot_subscribe_timeline_messages`

```c
MarmotStatus marmot_subscribe_timeline_messages(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, uint8_t has_limit, uint32_t limit, struct MarmotTimelineSubscription **out_sub);
```

Subscribe to live materialized timeline updates for a group (`group_id_hex` non-NULL) or the account-wide tail (NULL). `has_limit` plus `limit` cap the initial window. Free with `marmot_timeline_subscription_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsubscribe_timeline_messages) · [Header contract](include/marmot.h#L13499)

### `marmot_subscribe_notifications`

```c
MarmotStatus marmot_subscribe_notifications(const struct MarmotClient *client, struct MarmotNotificationsSubscription **out_sub);
```

Subscribe to notification updates. Free with `marmot_notifications_subscription_free` (before freeing the client).

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsubscribe_notifications) · [Header contract](include/marmot.h#L13609)

### `marmot_subscribe_chats`

```c
MarmotStatus marmot_subscribe_chats(const struct MarmotClient *client, const char *account_ref, uint8_t include_archived, struct MarmotChatsSubscription **out_sub);
```

Subscribe to one account's chats list. Emits whenever a group's projection changes; `include_archived` widens the filter. Free with `marmot_chats_subscription_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsubscribe_chats) · [Header contract](include/marmot.h#L13670)

### `marmot_subscribe_chat_list`

```c
MarmotStatus marmot_subscribe_chat_list(const struct MarmotClient *client, const char *account_ref, uint8_t include_archived, struct MarmotChatListSubscription **out_sub);
```

Subscribe to one account's durable chat-list projection. Free with `marmot_chat_list_subscription_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsubscribe_chat_list) · [Header contract](include/marmot.h#L13743)

### `marmot_subscribe_messages`

```c
MarmotStatus marmot_subscribe_messages(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, uint8_t has_limit, uint32_t limit, const uint64_t *kinds, uintptr_t kinds_len, struct MarmotMessagesSubscription **out_sub);
```

Subscribe to messages for a specific group (`group_id_hex` non-NULL) or every message across the account (NULL). `has_limit` + `limit` cap the initial snapshot to the latest N rows. `kinds` restricts the stream to those Nostr event kinds; pass NULL with length 0 for every kind. Free with `marmot_messages_subscription_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsubscribe_messages) · [Header contract](include/marmot.h#L13831)

### `marmot_subscribe_group_state`

```c
MarmotStatus marmot_subscribe_group_state(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotGroupStateSubscription **out_sub);
```

Subscribe to member/profile/roster changes for one group. Free with `marmot_group_state_subscription_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsubscribe_group_state) · [Header contract](include/marmot.h#L13908)

### `marmot_search_users`

```c
MarmotStatus marmot_search_users(const struct MarmotClient *client, const char *account_id_hex, const char *query, uint8_t radius_start, uint8_t radius_end, struct MarmotUserSearchSubscription **out_sub);
```

Search the identity directory outward from `account_id_hex`, widening from `radius_start` to `radius_end` social hops. Results stream in through the returned handle. Free it with `marmot_user_search_subscription_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsearch_users) · [Header contract](include/marmot.h#L14067)

### `marmot_subscribe_onboarding`

```c
MarmotStatus marmot_subscribe_onboarding(const struct MarmotClient *client, const char *account_ref, struct MarmotOnboardingSubscription **out_sub);
```

Subscribe to durable onboarding state for an account.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsubscribe_onboarding) · [Header contract](include/marmot.h#L14129)

### `marmot_subscribe_blocked_users`

```c
MarmotStatus marmot_subscribe_blocked_users(const struct MarmotClient *client, const char *account_ref, struct MarmotBlockListSubscription **out_sub);
```

Subscribe to an account's block list. # Safety Client, account string and output pointer must be valid.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsubscribe_blocked_users) · [Header contract](include/marmot.h#L14295)

### `marmot_subscribe_attachment_transfers`

```c
MarmotStatus marmot_subscribe_attachment_transfers(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const struct MarmotAttachmentLocalTarget *targets, uintptr_t targets_len, struct MarmotAttachmentTransferSubscription **out);
```

Open a bounded progress stream. First next returns the initial snapshot. # Safety Inputs must be live, targets NULL only with zero length, out writable.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsubscribe_attachment_transfers) · [Header contract](include/marmot.h#L14382)

### `marmot_subscribe_account_attention`

```c
MarmotStatus marmot_subscribe_account_attention(const struct MarmotClient *client, struct MarmotAccountAttentionSubscription **out_sub);
```

Open independent signed-in account summaries; requires no active chat-list handle. # Safety client must be valid; out_sub writable.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsubscribe_account_attention) · [Header contract](include/marmot.h#L14496)

### `marmot_selected_message_draft`

```c
MarmotStatus marmot_selected_message_draft(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotSelectedMessageDraft **out);
```

Descriptor-only draft; result owns the revision handle and must be deep-freed. # Safety client and strings valid; out writable.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotselected_message_draft) · [Header contract](include/marmot.h#L14648)

### `marmot_save_message_draft_if_revision`

```c
MarmotStatus marmot_save_message_draft_if_revision(const struct MarmotClient *client, const char *account_ref, const struct MarmotMessageDraftRevision *revision, const char *content, const char *reply, const struct MarmotMessageDraftAttachmentInput *attachments, uintptr_t attachments_len, struct MarmotSelectedMessageDraft **out);
```

Save only if the selected revision still matches. Attachment inputs are copied, never retained. # Safety client, account, content and revision valid; reply nullable; attachments points to len readable items (or NULL with zero len). Revision's owner stays live; out writable.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsave_message_draft_if_revision) · [Header contract](include/marmot.h#L14680)

### `marmot_send_message_draft`

```c
MarmotStatus marmot_send_message_draft(const struct MarmotClient *client, const char *account_ref, const struct MarmotMessageDraftRevision *revision, const struct MarmotMediaAttachmentReference *attachments, uintptr_t attachments_len, struct MarmotSendSummary **out);
```

Send the exact selected revision; successful durable acceptance clears it atomically. Hosts must not independently delete the draft on delivery. Prepared media must match descriptors. # Safety client, account, revision valid; revision owner stays live; attachments readable for length, or NULL with zero length; out writable. Free result with marmot_send_summary_free.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsend_message_draft) · [Header contract](include/marmot.h#L14710)

### `marmot_send_summary_free`

```c
void marmot_send_summary_free(struct MarmotSendSummary *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L14767)

### `marmot_sign_out_outcome_free`

```c
void marmot_sign_out_outcome_free(struct MarmotSignOutOutcome *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L14834)

### `marmot_string_list_free`

```c
void marmot_string_list_free(struct MarmotStringList *list);
```

Free a string list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15084)

### `marmot_secure_delete_expired_result_free`

```c
void marmot_secure_delete_expired_result_free(struct MarmotSecureDeleteExpiredResult *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15674)

### `marmot_selected_message_draft_free`

```c
void marmot_selected_message_draft_free(struct MarmotSelectedMessageDraft *p);
```

Deep-free a selected draft and its opaque revision. NULL is allowed. Only for drafts returned directly by this library. A snapshot's embedded draft is freed by `marmot_conversation_window_snapshot_free`. # Safety p must be NULL or a library-owned unfreed selected-draft root pointer, never the address of a snapshot's embedded draft.

[Header contract](include/marmot.h#L16084)

### `marmot_set_attachment_download_policy`

```c
MarmotStatus marmot_set_attachment_download_policy(const struct MarmotClient *client, const char *account_ref, const struct MarmotAttachmentDownloadPolicyInput *policy);
```

Persist policy. Disable pauses automatic work but preserves explicit transfers and cached bytes. # Safety Client, strings and policy must be live throughout this call. Inputs are borrowed.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotset_attachment_download_policy) · [Header contract](include/marmot.h#L16246)

### `marmot_submit_moderation_report`

```c
MarmotStatus marmot_submit_moderation_report(const struct MarmotClient *client, const char *account_ref, const char *reported_pubkey, uint32_t reason, const char *explanation, uint32_t origin, struct MarmotModerationReportOutcome **out);
```

Privately report a user to the configured moderation team as a NIP-59 gift wrap of a NIP-56 report. `reason` is a `MarmotReportReason` and `origin` a `MarmotModerationReportOrigin` discriminant. Additive to `marmot_report_message`, which is unchanged. Release `*out` with `marmot_moderation_report_outcome_free`; a queued `AcceptedPending` or `CompletionUnknown` outcome is retried on catch-up and must not be resubmitted.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsubmit_moderation_report) · [Header contract](include/marmot.h#L12829)

### `marmot_dismiss_device_group_move_sibling`

```c
MarmotStatus marmot_dismiss_device_group_move_sibling(const struct MarmotClient *client, const char *account_ref, const char *move_id, const char *slot_id_hex, struct MarmotDeviceLinkSnapshot **out);
```

Block on the account worker to dismiss one old-sibling hint from a move view. Borrow `account_ref`, the opaque
`move_id` and `slot_id_hex`; supply a non-NULL `out`. Free the owned returned snapshot, including its nested move
strings/lists, with `marmot_device_link_snapshot_free`. This does not link or remove a device. Disabled linking or an
unknown move/sibling is refused. See [shared move behavior](../marmot-uniffi/README.md#moving-this-device-to-another-device-group).

[Header contract](include/marmot.h#L9549)

### `marmot_reset_device_group_for_repair`

**Current.**

```c
MarmotStatus marmot_reset_device_group_for_repair(const struct MarmotClient *client, const char *account_ref, struct MarmotDeviceLinkSnapshot **out);
```

Run the shared explicit local device-group reset on the account worker after user confirmation. Ordinary opens refuse the experimental capability. On success `out` owns a snapshot; release it with `marmot_device_link_snapshot_free`. Follow the [shared reset, data-retention and admission contract](../marmot-uniffi/README.md#explicit-local-device-group-reset-before-fresh-pairing); this action neither removes remote members nor guarantees fresh admission.

[Header contract](include/marmot.h#L9507)


### `marmot_start_device_link`

```c
MarmotStatus marmot_start_device_link(const struct MarmotClient *client, const char *account_ref, struct MarmotDeviceLinkSnapshot **out);
```

Block on the account worker to start the shared compared-code link/move flow. Supply a non-NULL `out` and free the returned owned snapshot with `marmot_device_link_snapshot_free`, including its nested move views. Re-read on `MARMOT_EVENT_DEVICE_LINK_CHANGED`; see the [shared move contract](../marmot-uniffi/README.md#moving-this-device-to-another-device-group) and method guidance below for gates and progress.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotstart_device_link) · [Header contract](include/marmot.h#L9490)

</details>

<details>
<summary>marmot_t…</summary>

### `marmot_telemetry_install_id`

```c
MarmotStatus marmot_telemetry_install_id(const struct MarmotClient *client, char **out);
```

Stable anonymous install id for telemetry. Free with `marmot_string_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmottelemetry_install_id) · [Header contract](include/marmot.h#L10258)

### `marmot_timeline_messages`

```c
MarmotStatus marmot_timeline_messages(const struct MarmotClient *client, const char *account_ref, const struct MarmotTimelineMessageQuery *query, struct MarmotTimelinePage **out);
```

Materialized timeline read. Free the page with `marmot_timeline_page_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmottimeline_messages) · [Header contract](include/marmot.h#L11784)

### `marmot_timeline_subscription_next`

```c
MarmotStatus marmot_timeline_subscription_next(const struct MarmotTimelineSubscription *sub, uint32_t timeout_ms, struct MarmotTimelinePage **out);
```

Block until the next item, the timeout, or stream close. `timeout_ms == 0` waits indefinitely. Returns `MARMOT_STATUS_OK` (out set; free with `marmot_timeline_page_free`), `MARMOT_STATUS_TIMEOUT`, or `MARMOT_STATUS_CLOSED` (out NULL for both).

[Header contract](include/marmot.h#L13446)

### `marmot_timeline_subscription_set_callback`

```c
MarmotStatus marmot_timeline_subscription_set_callback(const struct MarmotTimelineSubscription *sub, MarmotTimelinePageCallback callback, void *user_data);
```

Install a callback pump for this subscription. `callback` runs on a runtime worker thread with a borrowed item pointer (valid only during the call; do not store or free it) and a final NULL item on close. `callback` and `user_data` access must be thread-safe. Fails if a callback is already installed.

[Header contract](include/marmot.h#L13463)

### `marmot_timeline_subscription_clear_callback`

```c
MarmotStatus marmot_timeline_subscription_clear_callback(const struct MarmotTimelineSubscription *sub);
```

Request cancellation of this subscription's callback pump, if any. Non-blocking: a callback already running keeps executing after this returns (see the module docs).

[Header contract](include/marmot.h#L13475)

### `marmot_timeline_subscription_free`

```c
void marmot_timeline_subscription_free(struct MarmotTimelineSubscription *sub);
```

Free the subscription handle. Requests callback-pump cancellation without waiting (a callback may still be running after this returns — do not free `user_data` on that basis). NULL is a no-op. Free every handle before the client that created it.

[Header contract](include/marmot.h#L13487)

### `marmot_timeline_subscription_snapshot`

```c
MarmotStatus marmot_timeline_subscription_snapshot(const struct MarmotTimelineSubscription *sub, struct MarmotTimelinePage **out_page);
```

Take the initial window snapshot. Yields the page exactly once: later calls write NULL with `MARMOT_STATUS_OK`. Free the page with `marmot_timeline_page_free`.

[Header contract](include/marmot.h#L13514)

### `marmot_timeline_subscription_next_update`

```c
MarmotStatus marmot_timeline_subscription_next_update(const struct MarmotTimelineSubscription *sub, uint32_t timeout_ms, struct MarmotTimelineSubscriptionUpdate **out_update);
```

Block until the next raw delta (page replacement or projection update). Free with `marmot_timeline_subscription_update_free`.

[Header contract](include/marmot.h#L13524)

### `marmot_timeline_subscription_paginate_backwards`

```c
MarmotStatus marmot_timeline_subscription_paginate_backwards(const struct MarmotTimelineSubscription *sub, uint32_t count, struct MarmotTimelinePage **out_page);
```

Extend the window toward older history by up to `count` messages and return the new window. Runs on the runtime off the caller's lock, so a concurrent blocking `next` on another thread is not blocked. Free with `marmot_timeline_page_free`.

[Header contract](include/marmot.h#L13537)

### `marmot_timeline_subscription_paginate_forwards`

```c
MarmotStatus marmot_timeline_subscription_paginate_forwards(const struct MarmotTimelineSubscription *sub, uint32_t count, struct MarmotTimelinePage **out_page);
```

Extend the window toward the live head by up to `count` messages and return the new window. Reaching the head re-anchors the window. Free with `marmot_timeline_page_free`.

[Header contract](include/marmot.h#L13549)

### `marmot_timeline_message_record_free`

```c
void marmot_timeline_message_record_free(struct MarmotTimelineMessageRecord *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15965)

### `marmot_timeline_page_free`

```c
void marmot_timeline_page_free(struct MarmotTimelinePage *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15975)

### `marmot_timeline_subscription_update_free`

```c
void marmot_timeline_subscription_update_free(struct MarmotTimelineSubscriptionUpdate *update);
```

Free a timeline-subscription delta returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15984)

### `marmot_timeline_edit_history_page_free`

```c
void marmot_timeline_edit_history_page_free(struct MarmotTimelineEditHistoryPage *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15994)

</details>

<details>
<summary>marmot_u…</summary>

### `marmot_uninstall_sticker_pack`

```c
MarmotStatus marmot_uninstall_sticker_pack(const struct MarmotClient *client, const char *account_ref, const char *input);
```

After a complete installed-list read, signs the proposed list before saving uninstall intent. A signing refusal does not queue this uninstall. Without a complete read, intent stays pending for a later `marmot_sync_sticker_packs`. Historical message references remain resolvable.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotuninstall_sticker_pack) · [Header contract](include/marmot.h#L12530)

### `marmot_unrecognized_sign_in_list_free`

```c
void marmot_unrecognized_sign_in_list_free(struct MarmotUnrecognizedSignInList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15849)

### `marmot_unrecognized_sign_ins`

```c
MarmotStatus marmot_unrecognized_sign_ins(const struct MarmotClient *client, const char *account_ref, struct MarmotUnrecognizedSignInList **out);
```

List the sign-ins of this account that this device does not recognize, the earliest to appear first; blocks on the account worker without network I/O. Each `MarmotUnrecognizedSignIn` carries its `slot_id_hex` handle, the `client` it reports (empty when none), `appeared_at`, `last_seen_at`, `before_this_device` (ask whether the user still has it rather than whether it was them), `signed_in`, its `state`, and `linked_by_slot_id_hex`, set only for `LinkedElsewhere`. Always empty without explicit dev capability and runtime intent. Re-read on `MARMOT_EVENT_UNRECOGNIZED_SIGN_INS_CHANGED`. Free the list with `marmot_unrecognized_sign_in_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotunrecognized_sign_ins) · [Header contract](include/marmot.h#L9395)

### `marmot_update_app_component`

```c
MarmotStatus marmot_update_app_component(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, uint16_t component_id, const uint8_t *data, uintptr_t data_len, struct MarmotSendSummary **out);
```

Admin-only replacement of one optional application-owned component. `data` may be NULL with `data_len` of `0`; empty bytes are stored, not removed. Ids below `0xf000`, group-required components, and a `data_len` above 4096 return `MARMOT_STATUS_INVALID_APP_COMPONENT`. Before staging, the engine rejects updates whose resulting application-owned state exceeds 32 entries or 8192 encoded bytes (including entry ids and TLS payload length prefixes). Replacements count once; empty values still occupy a slot. The value is re-encoded into the GroupContext of every later commit and into every Welcome, so keep it small. Free with `marmot_send_summary_free`.

[Header contract](include/marmot.h#L12188)

### `marmot_update_message_retention`

```c
MarmotStatus marmot_update_message_retention(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, uint64_t disappearing_message_secs, struct MarmotSendSummary **out);
```

Set the per-group disappearing-message retention. `disappearing_message_secs` of `0` disables expiry. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotupdate_message_retention) · [Header contract](include/marmot.h#L8869)

### `marmot_update_group_profile`

```c
MarmotStatus marmot_update_group_profile(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *name, const char *description, struct MarmotSendSummary **out);
```

Update the group's name and/or description. NULL leaves a field unchanged. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotupdate_group_profile) · [Header contract](include/marmot.h#L9650)

### `marmot_update_group_avatar_url`

```c
MarmotStatus marmot_update_group_avatar_url(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *url, const char *dim, const char *thumbhash, struct MarmotSendSummary **out);
```

Set (or clear, with `url` NULL) the group's URL-based avatar. The URL is validated (https-only, no localhost/private hosts) and normalized before commit. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotupdate_group_avatar_url) · [Header contract](include/marmot.h#L9668)

### `marmot_unreact_from_message`

```c
MarmotStatus marmot_unreact_from_message(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *target_message_id, struct MarmotSendSummary **out);
```

Remove this account's reaction from a message. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotunreact_from_message) · [Header contract](include/marmot.h#L10022)

### `marmot_user_profile`

```c
MarmotStatus marmot_user_profile(const struct MarmotClient *client, const char *account_id_hex, struct MarmotUserProfileMetadata **out);
```

Cached kind-0 profile for an account id; writes NULL with `MARMOT_STATUS_OK` when unknown. Free with `marmot_user_profile_metadata_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotuser_profile) · [Header contract](include/marmot.h#L10589)

### `marmot_user_relay_lists`

```c
MarmotStatus marmot_user_relay_lists(const struct MarmotClient *client, const char *account_id_hex, struct MarmotAccountRelayLists **out);
```

Cached NIP-65 and inbox relay lists for any account id; no network. Free with `marmot_account_relay_lists_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotuser_relay_lists) · [Header contract](include/marmot.h#L10617)

### `marmot_unblock_user`

```c
MarmotStatus marmot_unblock_user(const struct MarmotClient *client, const char *account_ref, const char *user_account_id_hex);
```

Unblock a user and publish the updated list. Requires relay synchronization.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotunblock_user) · [Header contract](include/marmot.h#L10659)

### `marmot_unfollow_user`

```c
MarmotStatus marmot_unfollow_user(const struct MarmotClient *client, const char *account_ref, const char *user_ref, struct MarmotStringList **out);
```

Unfollow `user_ref` and publish the updated list, keeping its other tags and content. Returns `MARMOT_STATUS_FOLLOW_LIST_TOO_LARGE`, publishing nothing, when the list has 2,048 follows or more. Free with `marmot_string_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotunfollow_user) · [Header contract](include/marmot.h#L10747)

### `marmot_user_profile_website`

```c
MarmotStatus marmot_user_profile_website(const struct MarmotClient *client, const char *account_id_hex, char **out);
```

The `website` field of a cached kind-0 profile; writes NULL with `MARMOT_STATUS_OK` when unknown. Free with `marmot_string_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotuser_profile_website) · [Header contract](include/marmot.h#L10830)

### `marmot_upload_prepared_group_image`

```c
MarmotStatus marmot_upload_prepared_group_image(const struct MarmotClient *client, const char *account_ref, const char *upload_id, struct MarmotPreparedGroupImageUpload **out);
```

Upload a staged group image now, so a later group creation can consume it without waiting. Free with `marmot_prepared_group_image_upload_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotupload_prepared_group_image) · [Header contract](include/marmot.h#L11271)

### `marmot_upload_media`

```c
MarmotStatus marmot_upload_media(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const struct MarmotMediaUploadRequest *request, struct MarmotMediaUploadResult **out);
```

Encrypt and upload attachments (optionally sending them). Free with `marmot_media_upload_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotupload_media) · [Header contract](include/marmot.h#L11744)

### `marmot_upsert_push_registration`

```c
MarmotStatus marmot_upsert_push_registration(const struct MarmotClient *client, const char *account_ref, uint32_t platform, const char *raw_token, const char *server_pubkey_hex, const char *relay_hint, struct MarmotPushRegistrationSyncResult **out);
```

Register (or update) the account's native push token and share it. `platform` is a `MarmotPushPlatform` discriminant; out-of-range values are rejected with `MARMOT_STATUS_INVALID_ARGUMENT`. Free with `marmot_push_registration_sync_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotupsert_push_registration) · [Header contract](include/marmot.h#L11799)

### `marmot_update_group_image`

```c
MarmotStatus marmot_update_group_image(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const uint8_t *plaintext, uintptr_t plaintext_len, const char *media_type, struct MarmotSendSummary **out);
```

Encrypt `plaintext` (the raw image bytes, `media_type` e.g. `"image/jpeg"`), upload it to Blossom, and commit it as the group's avatar. Requires admin. The bytes are copied — the caller keeps ownership. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotupdate_group_image) · [Header contract](include/marmot.h#L11849)

### `marmot_upload_profile_image`

```c
MarmotStatus marmot_upload_profile_image(const struct MarmotClient *client, const char *account_ref, const uint8_t *data, uintptr_t data_len, const char *media_type, const char *blossom_server, char **out);
```

Upload `data` (raw image bytes, `media_type` e.g. `"image/jpeg"`) to Blossom as the account's profile image. `blossom_server` overrides the default server; pass NULL to use it. The bytes are copied — the caller keeps ownership. Writes the image URL; free it with `marmot_string_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotupload_profile_image) · [Header contract](include/marmot.h#L11883)

### `marmot_usage_diagnostics_settings`

```c
MarmotStatus marmot_usage_diagnostics_settings(const struct MarmotClient *client, struct MarmotUsageDiagnosticsSettings **out);
```

# Safety `client` must be a live handle; string arguments must be valid NUL-terminated strings (nullable ones may be NULL); array arguments must hold their stated length (or be NULL with length 0); out-pointers must be valid.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotusage_diagnostics_settings) · [Header contract](include/marmot.h#L12355)

### `marmot_usage_diagnostics_status`

```c
MarmotStatus marmot_usage_diagnostics_status(const struct MarmotClient *client, struct MarmotUsageDiagnosticsStatus **out);
```

# Safety `client` must be a live handle; string arguments must be valid NUL-terminated strings (nullable ones may be NULL); array arguments must hold their stated length (or be NULL with length 0); out-pointers must be valid.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotusage_diagnostics_status) · [Header contract](include/marmot.h#L12378)

### `marmot_user_search_subscription_next`

```c
MarmotStatus marmot_user_search_subscription_next(const struct MarmotUserSearchSubscription *sub, uint32_t timeout_ms, struct MarmotUserSearchUpdate **out);
```

Block until the next item, the timeout, or stream close. `timeout_ms == 0` waits indefinitely. Returns `MARMOT_STATUS_OK` (out set; free with `marmot_user_search_update_free`), `MARMOT_STATUS_TIMEOUT`, or `MARMOT_STATUS_CLOSED` (out NULL for both).

[Header contract](include/marmot.h#L14014)

### `marmot_user_search_subscription_set_callback`

```c
MarmotStatus marmot_user_search_subscription_set_callback(const struct MarmotUserSearchSubscription *sub, MarmotUserSearchUpdateCallback callback, void *user_data);
```

Install a callback pump for this subscription. `callback` runs on a runtime worker thread with a borrowed item pointer (valid only during the call; do not store or free it) and a final NULL item on close. `callback` and `user_data` access must be thread-safe. Fails if a callback is already installed.

[Header contract](include/marmot.h#L14031)

### `marmot_user_search_subscription_clear_callback`

```c
MarmotStatus marmot_user_search_subscription_clear_callback(const struct MarmotUserSearchSubscription *sub);
```

Request cancellation of this subscription's callback pump, if any. Non-blocking: a callback already running keeps executing after this returns (see the module docs).

[Header contract](include/marmot.h#L14043)

### `marmot_user_search_subscription_free`

```c
void marmot_user_search_subscription_free(struct MarmotUserSearchSubscription *sub);
```

Free the subscription handle. Requests callback-pump cancellation without waiting (a callback may still be running after this returns — do not free `user_data` on that basis). NULL is a no-op. Free every handle before the client that created it.

[Header contract](include/marmot.h#L14055)

### `marmot_user_profile_metadata_free`

```c
void marmot_user_profile_metadata_free(struct MarmotUserProfileMetadata *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L14804)

### `marmot_user_directory_search_result_list_free`

```c
void marmot_user_directory_search_result_list_free(struct MarmotUserDirectorySearchResultList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15141)

### `marmot_user_search_update_free`

```c
void marmot_user_search_update_free(struct MarmotUserSearchUpdate *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L15151)

### `marmot_usage_diagnostics_settings_free`

```c
void marmot_usage_diagnostics_settings_free(struct MarmotUsageDiagnosticsSettings *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L16014)

### `marmot_usage_diagnostics_status_free`

```c
void marmot_usage_diagnostics_status_free(struct MarmotUsageDiagnosticsStatus *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L16024)

</details>

<details>
<summary>marmot_w…</summary>

### `marmot_watch_agent_text_stream`

```c
MarmotStatus marmot_watch_agent_text_stream(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *stream_id_hex, const uint8_t *server_cert_der, uintptr_t server_cert_der_len, uint8_t insecure_local, struct MarmotAgentStreamSubscription **out_sub);
```

Watch a live agent text stream over the brokered QUIC channel. Pass `stream_id_hex = NULL` to follow the latest stream in the group. `server_cert_der` (+ `server_cert_der_len`) pins a self-signed broker certificate; pass NULL with length 0 to use the bundled public-CA roots (not the OS trust store). The bytes are copied — the caller keeps ownership. `insecure_local` is loopback-only for testing. Free with `marmot_agent_stream_subscription_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotwatch_agent_text_stream) · [Header contract](include/marmot.h#L13989)

### `marmot_wipe_outcome_free`

```c
void marmot_wipe_outcome_free(struct MarmotWipeOutcome *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L14824)

</details>

<details>
<summary>Host-managed automatic attachment acquisition</summary>

### `marmot_automatic_attachment_request_free`

```c
void marmot_automatic_attachment_request_free(struct MarmotAutomaticAttachmentRequest *ptr);
```

Deep-free the returned automatic-request record and its nested status/reference. NULL is a no-op; do not free nested fields separately.

[Header contract](include/marmot.h#L16304)

### `marmot_begin_attachment_permission_update`

```c
MarmotStatus marmot_begin_attachment_permission_update(const struct MarmotClient *client, const char *account_ref, char **out);
```

Blocking revocation and generation issuance for HostManaged mode. Inputs are borrowed; free the returned generation with marmot_string_free. Call before asynchronous policy evaluation and keep the token with that evaluation. See the [shared permission contract](../marmot-uniffi/ATTACHMENT-ACCESS.md#host-managed-automatic-acquisition-0104).

[Header contract](include/marmot.h#L16311)

### `marmot_request_automatic_attachment`

```c
MarmotStatus marmot_request_automatic_attachment(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const struct MarmotAttachmentLocalTarget *target, struct MarmotAutomaticAttachmentRequest **out);
```

Blocking, idempotent automatic demand for the exact source slot. Inputs are borrowed; free the returned status/result with marmot_automatic_attachment_request_free. Repeated requests preserve suppression, acquisition history and retry budgets. See the [migration contract](../marmot-uniffi/ATTACHMENT-ACCESS.md#android-migration).

[Header contract](include/marmot.h#L16331)

### `marmot_set_attachment_automatic_permission`

```c
MarmotStatus marmot_set_attachment_automatic_permission(const struct MarmotClient *client, const char *account_ref, const char *generation, const struct MarmotAttachmentAutomaticPermissionInput *permission, bool *out);
```

Blocking application of runtime-only category permission. All inputs are borrowed; boolean input integers use nonzero for true. False output means the generation was stale, foreign or already consumed. Required output validation occurs before mutation. See the [shared permission contract](../marmot-uniffi/ATTACHMENT-ACCESS.md#host-managed-automatic-acquisition-0104).

[Header contract](include/marmot.h#L16320)

</details>

<details>
<summary>Durable local sends and caller correlation</summary>

### `marmot_local_send_acceptance_free`

```c
void marmot_local_send_acceptance_free(struct MarmotLocalSendAcceptance *ptr);
```

Deep-free a returned local acceptance, including its token and message identity.
NULL is permitted; embedded acceptances belong to their parent upload result.

[Header contract](include/marmot.h#L15556)

### `marmot_local_send_status`

```c
MarmotStatus marmot_local_send_status(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *client_token, struct MarmotLocalSendStatus **out);
```

Look up a retained token's local state without relay I/O. A NULL result means no
association. Free a non-NULL result with `marmot_local_send_status_free`. Follow
timeline updates for subsequent delivery; see [local sends](../marmot-uniffi/LOCAL-SENDS.md).

[Header contract](include/marmot.h#L9973)

### `marmot_local_send_status_free`

```c
void marmot_local_send_status_free(struct MarmotLocalSendStatus *ptr);
```

Deep-free a local status result and its optional completion summary. NULL is permitted.

[Header contract](include/marmot.h#L15576)

### `marmot_media_upload_submission_free`

```c
void marmot_media_upload_submission_free(struct MarmotMediaUploadSubmission *ptr);
```

Deep-free an upload/submission result, including references and its optional token-bound
acceptance. NULL is permitted; never free its embedded records separately.

[Header contract](include/marmot.h#L15566)

### `marmot_edit_local_message_with_client_token`

```c
MarmotStatus marmot_edit_local_message_with_client_token(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *original_client_token, const char *content, const char *edit_client_token, struct MarmotLocalSendAcceptance **out);
```

Block until MDK durably admits a revision of an original token-aware text or
reply in the same account and group. Give each submitted revision a new edit
token. This call returns local acceptance, not delivery; use
`marmot_local_send_status` for recovery and free the result with
`marmot_local_send_acceptance_free`. All string inputs are borrowed. Pair the
generated header with the matching library. See [pending edits](../marmot-uniffi/LOCAL-SENDS.md#edits-of-a-pending-local-send-0110).

[Header contract](include/marmot.h#L9939)

### `marmot_reply_to_message_with_client_token`

```c
MarmotStatus marmot_reply_to_message_with_client_token(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *target_message_id, const char *text, const char *client_token, struct MarmotLocalSendAcceptance **out);
```

Block until durable local reply acceptance, independently of relay publication.
Inputs are borrowed. Free the result with `marmot_local_send_acceptance_free` and
reconcile the optimistic bubble by timeline token. See [local sends](../marmot-uniffi/LOCAL-SENDS.md).

[Header contract](include/marmot.h#L9956)

### `marmot_send_message_draft_with_client_token`

```c
MarmotStatus marmot_send_message_draft_with_client_token(const struct MarmotClient *client, const char *account_ref, const struct MarmotMessageDraftRevision *revision, const struct MarmotMediaAttachmentReference *attachments, uintptr_t attachments_len, const char *client_token, struct MarmotLocalSendAcceptance **out);
```

Atomically consume the borrowed draft revision and admit a correlated message.
Keep its revision owner alive during the call; attachment inputs are borrowed.
Free acceptance with `marmot_local_send_acceptance_free`; do not clear the composer
on delivery. See [local sends](../marmot-uniffi/LOCAL-SENDS.md).

[Header contract](include/marmot.h#L14723)

### `marmot_send_text_with_client_token`

```c
MarmotStatus marmot_send_text_with_client_token(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *text, const char *client_token, struct MarmotLocalSendAcceptance **out);
```

Block until text is durably admitted, without waiting for relay publication.
Use a unique token per logical submission; repeating its original request returns
the same identity. Free with `marmot_local_send_acceptance_free`.
See [local sends](../marmot-uniffi/LOCAL-SENDS.md).

[Header contract](include/marmot.h#L9923)

### `marmot_upload_media_with_client_token`

```c
MarmotStatus marmot_upload_media_with_client_token(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const struct MarmotMediaUploadRequest *request, const char *client_token, struct MarmotMediaUploadSubmission **out);
```

Block for upload and optional durable message admission. Inputs are borrowed;
free the result with `marmot_media_upload_submission_free`. Uploads are not
idempotent: query token status after an unknown outcome before repeating them.
See [local sends](../marmot-uniffi/LOCAL-SENDS.md) for epoch and cancellation semantics.

[Header contract](include/marmot.h#L11755)

</details>

<details>
<summary>Stateless public-event verification</summary>

### `marmot_verify_public_nostr_event_json`

```c
MarmotStatus marmot_verify_public_nostr_event_json(const char *event_json, uint8_t *out);
```

Verify both the canonical ID and BIP-340 signature of a public Nostr event.
No client, account, or secret key is required. The borrowed UTF-8 JSON input
is not retained; the required `out` pointer is cleared before validation.
Malformed JSON or failed verification yields `MARMOT_STATUS_OK` with zero,
while null or invalid-UTF-8 arguments return a status error. The caller must
bound untrusted JSON and separately enforce author, kind, tag, relay provenance,
and MLS membership policy. Pair this header with the exact matching library.

[Header contract](include/marmot.h#L12866)

</details>

<details>
<summary>Audit v5 configuration, results and subscription errors</summary>

### `marmot_audit_delivery_status_v5`

```c
MarmotStatus marmot_audit_delivery_status_v5(const struct MarmotClient *client, struct MarmotAuditDeliveryStatusV5List **out);
```

Read each account's persisted v5 OTLP delivery status: last success, last typed failure with the receiver's HTTP status when it answered (`has_http_status`), consecutive failed passes, rejected batches, whether automatic delivery is paused after a receiver block, and the last measured backlog. Local read only; it never dials. `last_failure` and `backlog` are NULL until a v5 pass records them. Free the list with `marmot_audit_delivery_status_v5_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotaudit_delivery_status_v5) · [Header contract](include/marmot.h#L10363)

### `marmot_audit_delivery_status_v5_free`

```c
void marmot_audit_delivery_status_v5_free(struct MarmotAuditDeliveryStatusV5 *ptr);
```

Free one `MarmotAuditDeliveryStatusV5` row and its nullable `last_failure` and `backlog`. Rows inside a list are released by the list free instead. NULL is a no-op.

[Header contract](include/marmot.h#L14971)

### `marmot_audit_delivery_status_v5_list_free`

```c
void marmot_audit_delivery_status_v5_list_free(struct MarmotAuditDeliveryStatusV5List *list);
```

Free the list returned by `marmot_audit_delivery_status_v5`, including every row's strings and nested records. NULL is a no-op.

[Header contract](include/marmot.h#L14980)

### `marmot_audit_log_tracker_update_result_v5_free`

```c
void marmot_audit_log_tracker_update_result_v5_free(struct MarmotAuditLogTrackerUpdateResultV5 *ptr);
```

Free the additive v5-aware tracker result returned by `marmot_post_audit_log_tracker_update_v5`, including its nested v5 summary and v4 upload list. NULL is a no-op. The historical result keeps its existing layout and free function.

[Header contract](include/marmot.h#L14961)

### `marmot_audit_otlp_config_v5_free`

```c
void marmot_audit_otlp_config_v5_free(struct MarmotAuditOtlpConfigV5 *ptr);
```

Free the redacted configuration returned by `marmot_set_audit_otlp_config_v5`. The returned bearer token pointer is NULL; the host remains responsible for its borrowed input strings. NULL is a no-op.

[Header contract](include/marmot.h#L14951)

### `marmot_post_audit_log_tracker_update_v5`

```c
MarmotStatus marmot_post_audit_log_tracker_update_v5(const struct MarmotClient *client, struct MarmotAuditLogTrackerUpdateResultV5 **out);
```

Run one manual audit tracker pass with separate v4 whole-file and v5 OTLP outcomes. Configure recording and the v5 sender separately. The optional v5 result is absent when no sender is configured; accepted, pending, blocked, and idle counts distinguish a complete receiver acknowledgment from work that remains local. Free the result with `marmot_audit_log_tracker_update_result_v5_free`.

[Header contract](include/marmot.h#L10350)

### `marmot_set_audit_otlp_config_v5`

```c
MarmotStatus marmot_set_audit_otlp_config_v5(const struct MarmotClient *client, const struct MarmotAuditOtlpConfigV5 *config, struct MarmotAuditOtlpConfigV5 **out);
```

Configure or disable the dedicated v5 OTLP sender in memory. To enable, supply a stable destination identity, HTTPS `/v1/logs` endpoint, and bearer token; exact loopback development endpoints require `allow_loopback_dev`. To disable, set `enabled` false. The returned copy omits the token and is freed with `marmot_audit_otlp_config_v5_free`. This does not enable audit recording or alter the legacy v4 endpoint.

[Header contract](include/marmot.h#L11578)

</details>

<details>
<summary>File-backed media transfers</summary>

### `marmot_max_file_media_ciphertext_bytes`

```c
uint64_t marmot_max_file_media_ciphertext_bytes(void);
```

Return the finite per-batch ciphertext implementation bound, including a 16-byte AEAD tag for each attachment. It is not a server maximum or a preview/heap limit. No allocation is returned.

[Header contract](include/marmot.h#L13177)

### `marmot_media_file_transfer_control_cancel`

```c
MarmotStatus marmot_media_file_transfer_control_cancel(const struct MarmotMediaFileTransferControl *control);
```

Cancel snapshot preparation, transfer or fallback. Cancellation observed before message admission starts prevents publication; admission is not interruptible once started, even before durable acceptance returns. Delivery then belongs to the local-send queue. May run concurrently with the upload; never free the control while any call on it is active.

[Header contract](include/marmot.h#L13149)

### `marmot_media_file_transfer_control_free`

```c
void marmot_media_file_transfer_control_free(struct MarmotMediaFileTransferControl *control);
```

Release the control after upload and all query/cancel calls return. NULL is accepted. Freeing is not cancellation; use the explicit cancel method before releasing an active operation.

[Header contract](include/marmot.h#L13172)

### `marmot_media_file_transfer_control_is_cancelled`

```c
MarmotStatus marmot_media_file_transfer_control_is_cancelled(const struct MarmotMediaFileTransferControl *control, uint8_t *out);
```

Read cancellation into a required output (0 or 1). The output is cleared before input validation. May run concurrently with upload; the handle must remain live throughout the call.

[Header contract](include/marmot.h#L13156)

### `marmot_media_file_transfer_control_new`

```c
MarmotStatus marmot_media_file_transfer_control_new(struct MarmotMediaFileTransferControl **out);
```

Create one owned control per file upload. The required output is checked and cleared before allocation. Keep it live through the blocking upload, and release it with `marmot_media_file_transfer_control_free` after all calls return; do not reuse a cancelled control.

[Header contract](include/marmot.h#L13141)

### `marmot_media_file_transfer_control_processed_bytes`

```c
MarmotStatus marmot_media_file_transfer_control_processed_bytes(const struct MarmotMediaFileTransferControl *control, uint64_t *out);
```

Read monotonic processed bytes into a required cleared output. It counts the copy into the encrypted media store, the digest pass and the transfer, including retries, so it can exceed the source length; this is not a percentage. Query concurrently without freeing the handle.

[Header contract](include/marmot.h#L13164)

### `marmot_upload_media_files`

```c
MarmotStatus marmot_upload_media_files(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const struct MarmotMediaFileUploadRequest *request, const struct MarmotMediaFileTransferControl *control, struct MarmotMediaUploadResult **out);
```

Blocking file-backed upload using borrowed regular-file inputs, copied into the account's encrypted media store before PUT; `MARMOT_STATUS_STORAGE_FULL` when the disk cannot hold a source beyond its reserve, before anything is uploaded. Use off the UI thread and keep strings, request and source paths valid until return. Required output preflight precedes work. Ordered fallback preserves identical ciphertext; signer denial/cancellation stops. Free the owned result with `marmot_media_upload_result_free`. See the [shared contract](../marmot-uniffi/README.md#file-backed-media-upload).

[Header contract](include/marmot.h#L13184)

### `marmot_upload_media_files_with_client_token`

```c
MarmotStatus marmot_upload_media_files_with_client_token(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const struct MarmotMediaFileUploadRequest *request, const struct MarmotMediaFileTransferControl *control, const char *client_token, struct MarmotMediaUploadSubmission **out);
```

Token-aware blocking twin: upload all files, then optionally admit the resulting message when `send` is set. Keep one token for the logical submission and probe `marmot_local_send_status` after an interrupted/unknown outcome before reuploading. Input and control lifetimes match `marmot_upload_media_files`; free the result with `marmot_media_upload_submission_free`. Admission is not interruptible once started and does not certify relay delivery. There is no fixed worker-response timeout; per-endpoint network deadlines still apply.

[Header contract](include/marmot.h#L13197)

</details>

### `marmot_message_draft_revision_includes_chat_list_version`

```c
MarmotStatus marmot_message_draft_revision_includes_chat_list_version(const struct MarmotMessageDraftRevision *revision, const struct MarmotChatListDraftVersion *version, uint8_t *out);
```

Compare the opaque `draft_version` from a presented chat-list row with a live captured draft revision. Returns 1 only for the same account-store/group scope at or before that captured revision; foreign and newer versions return 0. Borrow both opaque handles for the call while their owning selected draft and presented row remain live and supply a non-NULL output byte, which is reset on errors. Treat the version as private presentation correlation: never parse, log or persist it, and never use it to select a newer draft for deletion. Revision-checked draft cleanup remains authoritative. Regenerate bindings and consume the matching native binary before adopting this added row field.

[Header contract](include/marmot.h#L14660)

<details>
<summary>Account attachment history</summary>

### `marmot_account_attachment_history_page`

```c
MarmotStatus marmot_account_attachment_history_page(const struct MarmotClient *client, const char *account_ref, const struct MarmotAccountAttachmentQuery *query, uint32_t limit, const struct MarmotAccountAttachmentCursor *cursor, struct MarmotAccountAttachmentPageRead **out);
```

Blocking account-local candidate paging; call off the UI thread. Borrow query arrays and an optional cursor only for the call. Empty filtered pages can have a continuation; deep-free the root result once and keep its cursor/version fields borrowed. See [Account attachment history](../marmot-uniffi/ACCOUNT-ATTACHMENT-HISTORY.md).

[Header contract](include/marmot.h#L7823)

### `marmot_account_attachment_history_version`

```c
MarmotStatus marmot_account_attachment_history_version(const struct MarmotClient *client, const char *account_ref, struct MarmotAccountAttachmentVersion **out);
```

Read a constant-work local account change token, without acquisition or decryption. The returned version is independently owned and is released by marmot_account_attachment_version_free.

[Header contract](include/marmot.h#L7835)

### `marmot_account_attachment_page_read_free`

```c
void marmot_account_attachment_page_read_free(struct MarmotAccountAttachmentPageRead *value);
```

Deep-free the root page result, including entries and its opaque cursor/version fields. NULL is harmless. Do not free fields separately or free a result while a call borrows its cursor.

[Header contract](include/marmot.h#L7801)

### `marmot_account_attachment_version_change_since`

```c
MarmotStatus marmot_account_attachment_version_change_since(const struct MarmotAccountAttachmentVersion *current, const struct MarmotAccountAttachmentVersion *previous, uint32_t *out);
```

Compare the current version with a retained original baseline. The output is a MarmotAttachmentHistoryChange discriminant: Unchanged, Additions or RestartRequired. Replace loaded rows after destructive changes; additions leave older seeks valid and offer a head refresh.

[Header contract](include/marmot.h#L7844)

### `marmot_account_attachment_version_clone`

```c
MarmotStatus marmot_account_attachment_version_clone(const struct MarmotAccountAttachmentVersion *value, struct MarmotAccountAttachmentVersion **out);
```

Clone a borrowed page version into an independently owned baseline so it can outlive the page. Release the clone with marmot_account_attachment_version_free; the original remains owned by its root result.

[Header contract](include/marmot.h#L7815)

### `marmot_account_attachment_version_free`

```c
void marmot_account_attachment_version_free(struct MarmotAccountAttachmentVersion *value);
```

Release a standalone version returned by a version read or clone. NULL is harmless. Never pass a borrowed version field whose root page owns it.

[Header contract](include/marmot.h#L7808)

</details>

<details>
<summary>Moderation reporting</summary>

### `marmot_configure_moderation_reporting`

```c
MarmotStatus marmot_configure_moderation_reporting(const struct MarmotClient *client, const char *recipient_pubkey, const char *const *relays, uintptr_t relays_len);
```

Install the private moderation-report destination at runtime, or clear it when `recipient_pubkey` is NULL. C hosts use this instead of a `MarmotClientOptions` field so the borrowed options layout stays unchanged. The recipient is 64-character hex or `npub`; every relay must pass the relay safety policy. One bad entry rejects the whole destination with `MARMOT_STATUS_INVALID_MODERATION_REPORT_CONFIG` and leaves reporting unconfigured.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotconfigure_moderation_reporting) · [Header contract](include/marmot.h#L12852)

### `marmot_moderation_report_outcome_free`

```c
void marmot_moderation_report_outcome_free(struct MarmotModerationReportOutcome *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L16161)

### `marmot_moderation_reporting_available`

```c
MarmotStatus marmot_moderation_reporting_available(const struct MarmotClient *client, bool *out);
```

Write whether a valid moderation-report destination is installed. Hosts gate the "Report to White Noise" affordance on it; submitting without one fails with `MARMOT_STATUS_MODERATION_REPORTING_NOT_CONFIGURED` and publishes nothing.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotmoderation_reporting_available) · [Header contract](include/marmot.h#L12842)

</details>

<details>
<summary>Native startup diagnostics</summary>

### `marmot_native_startup_snapshot_free`

```c
void marmot_native_startup_snapshot_free(struct MarmotNativeStartupSnapshot *ptr);
```

Release the owned native-startup snapshot and both record arrays returned by `marmot_startup_diagnostics_snapshot`. Passing NULL is safe. Do not free embedded records separately or retain pointers after this call.

[Header contract](include/marmot.h#L16210)

### `marmot_set_startup_diagnostics_enabled`

```c
MarmotStatus marmot_set_startup_diagnostics_enabled(const struct MarmotClient *client, uint8_t enabled);
```

Enable or revoke the opt-in native memory capture exposed by MarmotKit. Nonzero `enabled` enables recording; normal clients leave it disabled. Disabling clears capture and fences older scopes. This changes no database, upload consent, network or cryptographic policy. The client must remain live for the call.

[Header contract](include/marmot.h#L12876)

### `marmot_startup_diagnostics_snapshot`

```c
MarmotStatus marmot_startup_diagnostics_snapshot(const struct MarmotClient *client, struct MarmotNativeStartupSnapshot **out);
```

Read bounded fixed phases and migration progress without database or keystore queries, before or during native startup. `out` must be writable; release the returned snapshot and its owned active/event arrays with `marmot_native_startup_snapshot_free`. Only anonymous scope tokens, timings/schema progress and fixed enums are returned. Serialization and export remain explicit host actions.

[Header contract](include/marmot.h#L12887)

</details>

<details>
<summary>Captured media admission</summary>

### `marmot_send_prepared_media_with_client_token`

```c
MarmotStatus marmot_send_prepared_media_with_client_token(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const struct MarmotMediaAttachmentReference *attachments, uintptr_t attachments_len, const char *caption, const char *client_token, const struct MarmotMessageDraftRevision *consuming_draft, struct MarmotLocalSendAcceptance **out);
```

C binding for [captured ordinary-media admission](../marmot-uniffi/LOCAL-SENDS.md#captured-ordinary-media-drafts). Inputs and the nullable captured revision are borrowed; free the owned result with `marmot_local_send_acceptance_free`. Use the matching generated header and native library.

[Header contract](include/marmot.h#L11668)

</details>

<details>
<summary>Public event previews</summary>

### `marmot_cached_public_event_previews`

```c
MarmotStatus marmot_cached_public_event_previews(const struct MarmotClient *client, const char *account_ref, const char *const *references, uintptr_t references_len, struct MarmotPublicEventPreviewList **out);
```

Blocking, network-free read of cached public event previews: one row per reference (at most 16, else `MARMOT_STATUS_INVALID_PUBLIC_EVENT_REFERENCES`) in request order, echoing each reference. `event_json` is non-NULL only for `Present`. Call off the UI thread and free the list with `marmot_public_event_preview_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotcached_public_event_previews) · [Header contract](include/marmot.h#L11127)

### `marmot_public_event_preview_free`

```c
void marmot_public_event_preview_free(struct MarmotPublicEventPreview *ptr);
```

Free one `MarmotPublicEventPreview` returned by `marmot_resolve_public_event_preview`, including its strings. NULL is a no-op.

[Header contract](include/marmot.h#L16191)

### `marmot_public_event_preview_list_free`

```c
void marmot_public_event_preview_list_free(struct MarmotPublicEventPreviewList *list);
```

Free a `MarmotPublicEventPreviewList` and every row in it. Do not free individual rows. NULL is a no-op.

[Header contract](include/marmot.h#L16200)

### `marmot_resolve_public_event_preview`

```c
MarmotStatus marmot_resolve_public_event_preview(const struct MarmotClient *client, const char *account_ref, const char *reference, struct MarmotPublicEventPreview **out);
```

Blocking relay refresh of one reference when it is missing or stale, then its local state. Free with `marmot_public_event_preview_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotresolve_public_event_preview) · [Header contract](include/marmot.h#L11143)

</details>

<details>
<summary>Deployment configuration</summary>

Deployment services a host configures at construction: start from a preset, change what differs, pass it to any `marmot_client_new*` constructor, then free it.

### `marmot_deployment_white_noise`

```c
MarmotStatus marmot_deployment_white_noise(struct MarmotDeployment **out);
```

Create White Noise's deployment, the one White Noise hosts pass to every constructor. Free it with `marmot_deployment_free`; a client constructed with it keeps its own copy.

[Header contract](include/marmot.h#L12965)

### `marmot_deployment_neutral`

```c
MarmotStatus marmot_deployment_neutral(struct MarmotDeployment **out);
```

Create a deployment with no services and the neutral keychain service `org.marmot-protocol.mdk`, then fill in what your deployment operates with the setters. Free it with `marmot_deployment_free`. Unset values fall back to nothing: with no new-group media servers new groups stay text-only, and with no group-image server group images are refused.

[Header contract](include/marmot.h#L12975)

### `marmot_deployment_free`

```c
void marmot_deployment_free(struct MarmotDeployment *deployment);
```

Free a deployment. NULL is a no-op. Clients constructed with it are unaffected.

[Header contract](include/marmot.h#L12983)

### `marmot_deployment_set_recovery_operated_relays`

```c
MarmotStatus marmot_deployment_set_recovery_operated_relays(struct MarmotDeployment *deployment, const char *const *relays, uintptr_t relays_len);
```

Replace the relays the deployment operates. A route's history certifies once these finish a full comparison; a route with none of them requires all of its relays. Changing the set rebuilds pending recovery scopes once.

[Header contract](include/marmot.h#L12990)

### `marmot_deployment_set_discovery_indexer_relays`

```c
MarmotStatus marmot_deployment_set_discovery_indexer_relays(struct MarmotDeployment *deployment, const char *const *relays, uintptr_t relays_len);
```

Replace the public indexers that onboarding and account setup also search for an account's relay list and profile. They are never adopted as messaging relays. `(NULL, 0)` clears the list.

[Header contract](include/marmot.h#L12999)

### `marmot_deployment_set_new_group_media_endpoints`

```c
MarmotStatus marmot_deployment_set_new_group_media_endpoints(struct MarmotDeployment *deployment, const char *const *endpoints, uintptr_t endpoints_len);
```

Replace the Blossom servers signed into a new group's encrypted-media component. Each must accept opaque `application/octet-stream` blobs. Existing groups keep their signed list. With an empty list new groups carry no encrypted-media component and stay text-only.

[Header contract](include/marmot.h#L13008)

### `marmot_deployment_set_group_image_endpoint`

```c
MarmotStatus marmot_deployment_set_group_image_endpoint(struct MarmotDeployment *deployment, const char *endpoint);
```

Set the Blossom server for encrypted group images, or unset it with NULL. Group state records no server, so every client sharing a group must use the same one. With no server, setting or fetching a group image is refused.

[Header contract](include/marmot.h#L13017)

### `marmot_deployment_set_profile_image_endpoint`

```c
MarmotStatus marmot_deployment_set_profile_image_endpoint(struct MarmotDeployment *deployment, const char *endpoint);
```

Set the public profile-image upload server, or unset it with NULL. Peers' avatars load from the URL in their profile, never from here. With no server, a profile-image upload needs an explicit one.

[Header contract](include/marmot.h#L13025)

### `marmot_deployment_set_open_ranking`

```c
MarmotStatus marmot_deployment_set_open_ranking(struct MarmotDeployment *deployment, const char *search_endpoint, const char *const *profile_relays, uintptr_t profile_relays_len);
```

Set the Open Ranking search endpoint and the relays that hydrate its results. A NULL endpoint or no profile relay turns the tier off; personal graph search is unaffected.

[Header contract](include/marmot.h#L13035)

### `marmot_deployment_set_moderation_label_namespace`

```c
MarmotStatus marmot_deployment_set_moderation_label_namespace(struct MarmotDeployment *deployment, const char *namespace_);
```

Set the NIP-32 namespace on moderation report labels, which the operator's report parser matches, or unset it with NULL. With no namespace, `marmot_configure_moderation_reporting` refuses a destination.

[Header contract](include/marmot.h#L13063)

### `marmot_deployment_set_keychain_service`

```c
MarmotStatus marmot_deployment_set_keychain_service(struct MarmotDeployment *deployment, const char *name);
```

Set the platform keychain service used for account secrets when no secret store is supplied. A blank name is the neutral one. Changing it for an existing install strands the secrets stored under the old name.

[Header contract](include/marmot.h#L13073)

### `marmot_deployment_set_relay_event_limits`

```c
MarmotStatus marmot_deployment_set_relay_event_limits(struct MarmotDeployment *deployment, const char *const *relays, const uint64_t *max_event_bytes, uintptr_t len);
```

Replace the largest event, in bytes of serialized event JSON, each listed relay accepts when it does not advertise it: `relays[i]` takes `max_event_bytes[i]`. MDK sends no group event or Welcome over a relay's known limit, and a send that fits none of its relays fails as `MARMOT_STATUS_EVENT_TOO_LARGE`. A blank relay or a zero limit is ignored, a relay listed twice keeps the smaller limit, and NULL with 0 clears the list.

[Header contract](include/marmot.h#L13052)

</details>

<details>
<summary>Backup recovery and observation</summary>

### `marmot_backup_history_availability`

```c
MarmotStatus marmot_backup_history_availability(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotBackupHistoryAvailabilityList **out);
```

Read current-chat private availability hints. The MLS id is variable-length; no hint creates membership or proves content is downloadable. Free the returned list with `marmot_backup_history_availability_list_free`.

[Header contract](include/marmot.h#L9252)

### `marmot_backup_history_availability_list_free`

```c
void marmot_backup_history_availability_list_free(struct MarmotBackupHistoryAvailabilityList *list);
```

Deep-free the owned availability list and its strings; NULL is allowed. Do not free its embedded elements separately.

[Header contract](include/marmot.h#L15019)

### `marmot_backup_restore_status`

```c
MarmotStatus marmot_backup_restore_status(const struct MarmotClient *client, const char *account_ref, struct MarmotBackupRestoreStatus **out);
```

Read aggregate restore progress. Complete does not prove global history completeness or pointer existence. Free the returned status with `marmot_backup_restore_status_free`.

[Header contract](include/marmot.h#L9238)

### `marmot_backup_restore_status_free`

```c
void marmot_backup_restore_status_free(struct MarmotBackupRestoreStatus *ptr);
```

Deep-free an owned status and its optional operation token. NULL is allowed. Do not free callback-borrowed status pointers.

[Header contract](include/marmot.h#L15010)

### `marmot_backup_restore_subscription_clear_callback`

```c
MarmotStatus marmot_backup_restore_subscription_clear_callback(const struct MarmotBackupRestoreSubscription *sub);
```

Stop future observer callbacks; an already running callback may still use user_data. This does not cancel restore or wait for that callback. Preserve user_data until all invocations finish.

[Header contract](include/marmot.h#L14342)

### `marmot_backup_restore_subscription_free`

```c
void marmot_backup_restore_subscription_free(struct MarmotBackupRestoreSubscription *sub);
```

Release the observer handle before its client, with no concurrent calls using it. Restore continues until explicit cancellation, terminal completion or worker shutdown; running callbacks retain the usual lifetime obligations.

[Header contract](include/marmot.h#L14354)

### `marmot_backup_restore_subscription_next`

```c
MarmotStatus marmot_backup_restore_subscription_next(const struct MarmotBackupRestoreSubscription *sub, uint32_t timeout_ms, struct MarmotBackupRestoreStatus **out);
```

Wait for a progress/availability revision. Zero timeout waits indefinitely; TIMEOUT or CLOSED returns no item. On OK, free the owned status with `marmot_backup_restore_status_free`. Closing observation never cancels the job.

[Header contract](include/marmot.h#L14313)

### `marmot_backup_restore_subscription_set_callback`

```c
MarmotStatus marmot_backup_restore_subscription_set_callback(const struct MarmotBackupRestoreSubscription *sub, MarmotBackupRestoreCallback callback, void *user_data);
```

Install a progress observer. Item pointers are borrowed only during the callback and must not be freed. Keep user_data alive through any running callback; clear/free does not cancel restore or join callbacks.

[Header contract](include/marmot.h#L14330)

### `marmot_backup_restore_subscription_snapshot`

```c
MarmotStatus marmot_backup_restore_subscription_snapshot(const struct MarmotBackupRestoreSubscription *sub, struct MarmotBackupRestoreStatus **out);
```

Take the initial status once. OK with NULL means already consumed; free a non-NULL status with `marmot_backup_restore_status_free`. Use next or callbacks for subsequent revisions.

[Header contract](include/marmot.h#L14374)

### `marmot_backup_settings`

```c
MarmotStatus marmot_backup_settings(const struct MarmotClient *client, const char *account_ref, struct MarmotBackupSettings **out);
```

Read selected account backup settings, not a publication receipt. Free the result with `marmot_backup_settings_free`; re-read after submitted/concurrent setting changes.

[Header contract](include/marmot.h#L9151)

### `marmot_backup_settings_free`

```c
void marmot_backup_settings_free(struct MarmotBackupSettings *ptr);
```

Deep-free an owned settings record; NULL is allowed. This changes no backup settings.

[Header contract](include/marmot.h#L15000)

### `marmot_begin_backup_restore`

```c
MarmotStatus marmot_begin_backup_restore(const struct MarmotClient *client, const char *account_ref, const char *words, struct MarmotBackupRestoreStatus **out);
```

Start one manual current-membership history restore with borrowed recovery words. Keep input valid until this blocking call returns, then clear host copies; MDK never retains its pointer. Free the returned status and retain its opaque account-scoped token if cancellation is needed. This never joins chats or changes the current recovery key.

[Header contract](include/marmot.h#L9209)

### `marmot_begin_recovery_words`

```c
MarmotStatus marmot_begin_recovery_words(const struct MarmotClient *client, const char *account_ref, struct MarmotRecoveryWords **out);
```

Generate twelve setup words and two 1-based confirmation positions. Display once, never log/persist, and free output with `marmot_recovery_words_free`, which erases the returned word buffers before release. Clear host copies separately; earlier managed/FFI copies are outside that free's scope.

[Header contract](include/marmot.h#L9100)

### `marmot_cancel_backup_restore`

```c
MarmotStatus marmot_cancel_backup_restore(const struct MarmotClient *client, const char *account_ref, const char *operation, bool *out);
```

Cancel only the operation named by the borrowed token. OK with false means stale, not cancellation of the current job; malformed tokens are rejected. Committed history stays. This is separate from freeing an observer.

[Header contract](include/marmot.h#L9224)

### `marmot_cancel_recovery_words`

```c
MarmotStatus marmot_cancel_recovery_words(const struct MarmotClient *client, const char *account_ref);
```

Forget pending setup words without changing current backups. Clear caller-owned copies separately.

[Header contract](include/marmot.h#L9128)

### `marmot_confirm_recovery_words`

```c
MarmotStatus marmot_confirm_recovery_words(const struct MarmotClient *client, const char *account_ref, const char *const *answers, uintptr_t answers_len);
```

Pass the two answers in requested position order as borrowed strings. Keep the array/strings live for the call and clear host buffers afterward. Busy/error keeps the core setup available; read selected settings again after success.

[Header contract](include/marmot.h#L9114)

### `marmot_recovery_words_free`

```c
void marmot_recovery_words_free(struct MarmotRecoveryWords *ptr);
```

Erase the returned word buffers, then deep-free the record and confirmation positions; NULL is allowed. It does not erase host copies or earlier managed/FFI copies. This is not the pending setup cancel command.

[Header contract](include/marmot.h#L14990)

### `marmot_run_due_backup_pass`

```c
MarmotStatus marmot_run_due_backup_pass(const struct MarmotClient *client, const char *account_ref, enum MarmotBackgroundBackupOutcome *out);
```

Block for one current/newly admitted due pass through serialized settlement and credit release, writing the two-value outcome by value to a required out pointer; no free is needed. FinishedAttempt includes failed attempts and is not pointer-publication success. NotStarted means this call joined/admitted none, including disabled device-group support. Call off the UI thread; stopping the worker/runtime from another thread ends the wait with MARMOT_STATUS_TRANSPORT_CLOSED. This does not force a backup, wait for future due work, or drain all runtime work.

[Header contract](include/marmot.h#L9195)

### `marmot_set_runtime_backup_background_conditions`

```c
MarmotStatus marmot_set_runtime_backup_background_conditions(const struct MarmotClient *client, uint8_t wifi, uint8_t charging);
```

Report the runtime-wide current Wi-Fi and charging facts before workers exist and on changes; both are required for background admission. The latest report survives account-worker replacement and intervals with no workers, while a new runtime starts closed. This requires no account and starts no worker; eligible reports wake existing due dispatchers. An admitted pass settles after false. Manual restore remains independent. Boolean inputs are uint8_t: zero is false and nonzero is true.

[Header contract](include/marmot.h#L9165)

### `marmot_set_backup_background_conditions`

```c
MarmotStatus marmot_set_backup_background_conditions(const struct MarmotClient *client, const char *account_ref, uint8_t wifi, uint8_t charging);
```

Compatibility wrapper for the runtime-wide platform report. It validates the existing active, signable, fully onboarded account before changing the shared facts and never starts that account worker. Prefer the account-free runtime setter; no parameter or return layout changed. Admitted passes settle after false; manual restore is independent.

[Header contract](include/marmot.h#L9179)

### `marmot_turn_off_backups`

```c
MarmotStatus marmot_turn_off_backups(const struct MarmotClient *client, const char *account_ref);
```

Disable future account backups without deleting stored archives or cancelling an admitted pass. Re-read selected settings to display the outcome.

[Header contract](include/marmot.h#L9140)

### `marmot_watch_backup_restore`

```c
MarmotStatus marmot_watch_backup_restore(const struct MarmotClient *client, const char *account_ref, struct MarmotBackupRestoreSubscription **out_sub);
```

Create an observer for initial snapshot and later aggregate revisions. Free the handle before the client; freeing it does not cancel restore. Read snapshot once, then use next or callbacks with their usual ownership rules.

[Header contract](include/marmot.h#L14363)

</details>

<details>
<summary>Chat-list selection</summary>

### `marmot_chat_list_ids`

```c
MarmotStatus marmot_chat_list_ids(const struct MarmotClient *client, const char *account_ref, uint32_t view, struct MarmotStringList **out);
```

Select all: every chat ID in a MarmotChatListView, in display order, beyond any open window; `len` is the count. Returns `MARMOT_STATUS_CHAT_PRESENTATION_NOT_READY`, never a partial list, while base rows are being prepared. Free with `marmot_string_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotchat_list_ids) · [Header contract](include/marmot.h#L12900)

### `marmot_revalidate_chat_list_ids`

```c
MarmotStatus marmot_revalidate_chat_list_ids(const struct MarmotClient *client, const char *account_ref, uint32_t view, const char *const *group_ids, uintptr_t group_ids_len, struct MarmotStringList **out);
```

The subset of a host selection still in the view, in the caller's order with duplicates dropped; never adds chats. Call before a bulk action, then use the per-chat commands. The input array is borrowed. Free the result with `marmot_string_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotrevalidate_chat_list_ids) · [Header contract](include/marmot.h#L12916)

</details>

<details>
<summary>NIP-51 emoji sets</summary>

### `marmot_emoji_set`

```c
MarmotStatus marmot_emoji_set(const struct MarmotClient *client, const char *account_ref, const char *coordinate, struct MarmotEmojiSet **out);
```

Reads one stored set by coordinate or `naddr` without network I/O. Returns NULL when absent. Free with `marmot_emoji_set_free`.

[Header contract](include/marmot.h#L12580)

### `marmot_emoji_set_asset_free`

```c
void marmot_emoji_set_asset_free(struct MarmotEmojiSetAsset *ptr);
```

Frees a preview asset and its bytes. NULL is safe.

[Header contract](include/marmot.h#L15239)

### `marmot_emoji_set_cover_free`

```c
void marmot_emoji_set_cover_free(struct MarmotEmojiSetCover *ptr);
```

Frees a cover image and its bytes. NULL is safe.

[Header contract](include/marmot.h#L15249)

### `marmot_emoji_set_free`

```c
void marmot_emoji_set_free(struct MarmotEmojiSet *ptr);
```

Frees one emoji set, its entries, skips and installed state. NULL is safe.

[Header contract](include/marmot.h#L15190)

### `marmot_emoji_set_install_control_cancel`

```c
MarmotStatus marmot_emoji_set_install_control_cancel(const struct MarmotEmojiSetInstallControl *control);
```

Cancel the install from any thread: no new download starts, those in flight are dropped, nothing is stored and `marmot_install_emoji_set` returns `MARMOT_STATUS_EMOJI_SET_INSTALL_CANCELLED`; a cancelled reinstall leaves the previous snapshot readable. Too late once the final atomic write has started. Never free the control while any call on it is active.

[Header contract](include/marmot.h#L13092)

### `marmot_emoji_set_install_control_free`

```c
void marmot_emoji_set_install_control_free(struct MarmotEmojiSetInstallControl *control);
```

Release the control after the install and all query/cancel calls return. NULL is accepted. Freeing is not cancellation.

[Header contract](include/marmot.h#L13116)

### `marmot_emoji_set_install_control_is_cancelled`

```c
MarmotStatus marmot_emoji_set_install_control_is_cancelled(const struct MarmotEmojiSetInstallControl *control, uint8_t *out);
```

Writes 1 when cancellation was requested, by the host or by runtime shutdown or close (which cancel every running install), else 0.

[Header contract](include/marmot.h#L13099)

### `marmot_emoji_set_install_control_new`

```c
MarmotStatus marmot_emoji_set_install_control_new(struct MarmotEmojiSetInstallControl **out);
```

Create one control per `marmot_install_emoji_set` call; it is never reused across installs. Free with `marmot_emoji_set_install_control_free`.

[Header contract](include/marmot.h#L13082)

### `marmot_emoji_set_install_control_progress`

```c
MarmotStatus marmot_emoji_set_install_control_progress(const struct MarmotEmojiSetInstallControl *control, struct MarmotEmojiSetInstallProgress *out);
```

Writes entries finished (`completed_emoji`), entries to try (`total_emoji`, 0 until the install has read the stored version) and response bytes received (`transferred_bytes`, counted as each download finishes). A plain value: nothing to free.

[Header contract](include/marmot.h#L13108)

### `marmot_emoji_set_install_result_free`

```c
void marmot_emoji_set_install_result_free(struct MarmotEmojiSetInstallResult *ptr);
```

Frees an install result, its set and skips. NULL is safe.

[Header contract](include/marmot.h#L15219)

### `marmot_emoji_set_list_free`

```c
void marmot_emoji_set_list_free(struct MarmotEmojiSetList *list);
```

Frees an emoji set list and every set in it. NULL is safe.

[Header contract](include/marmot.h#L15199)

### `marmot_emoji_set_sync_result_free`

```c
void marmot_emoji_set_sync_result_free(struct MarmotEmojiSetSyncResult *ptr);
```

Frees an emoji set sync result. NULL is safe.

[Header contract](include/marmot.h#L15209)

### `marmot_emoji_sets`

```c
MarmotStatus marmot_emoji_sets(const struct MarmotClient *client, const char *account_ref, uint8_t installed_only, const char *search, uint8_t has_limit, uint32_t limit, struct MarmotEmojiSetList **out);
```

Reads stored emoji sets; the read runs off the embedded runtime's workers while this call blocks. `installed_only` returns installed snapshots in install order. `search` may be NULL. No network I/O. Free with `marmot_emoji_set_list_free`.

[Header contract](include/marmot.h#L12562)

### `marmot_fetch_emoji_set`

```c
MarmotStatus marmot_fetch_emoji_set(const struct MarmotClient *client, const char *account_ref, const char *input, struct MarmotEmojiSet **out);
```

Fetches one set from a pasted coordinate or `naddr`, trying up to 8 relay hints and then the account relays. Text only. Free with `marmot_emoji_set_free`.

[Header contract](include/marmot.h#L12612)

### `marmot_fetch_emoji_set_asset`

```c
MarmotStatus marmot_fetch_emoji_set_asset(const struct MarmotClient *client, const char *account_ref, const char *coordinate, const char *expected_event_id_hex, const char *shortcode, struct MarmotEmojiSetAsset **out);
```

Downloads and validates one emoji for a preview; nothing is stored. Reveals the user's IP address to the image host: call only after the user opens the set, with the shown version's `event_id_hex` (`MARMOT_STATUS_EMOJI_SET_CHANGED` otherwise, before any download). Free with `marmot_emoji_set_asset_free`.

[Header contract](include/marmot.h#L12660)

### `marmot_fetch_emoji_set_cover`

```c
MarmotStatus marmot_fetch_emoji_set_cover(const struct MarmotClient *client, const char *account_ref, const char *coordinate, const char *expected_event_id_hex, struct MarmotEmojiSetCover **out);
```

Downloads and validates a stored set's cover image (`image_url`) under the emoji image limits; nothing is stored. Reveals the user's IP address to its host: call only after the user opens the set, with the shown version's `event_id_hex` (`MARMOT_STATUS_EMOJI_SET_CHANGED` otherwise, before any download). A set without a cover is `MARMOT_STATUS_EMOJI_SET_NOT_FOUND`. Free with `marmot_emoji_set_cover_free`.

[Header contract](include/marmot.h#L12681)

### `marmot_install_emoji_set`

```c
MarmotStatus marmot_install_emoji_set(const struct MarmotClient *client, const char *account_ref, const char *coordinate, const char *expected_event_id_hex, const struct MarmotEmojiSetInstallControl *control, struct MarmotEmojiSetInstallResult **out);
```

Snapshots the stored set version, downloads and validates each emoji once, and stores the bytes and SHA-256. Skipped entries are listed, not fatal. Reveals the user's IP address to the set's image hosts: call only after the user taps Install. `expected_event_id_hex` is the version the user was shown: another stored version is `MARMOT_STATUS_EMOJI_SET_CHANGED` (detail names the current id) and nothing stored is `MARMOT_STATUS_EMOJI_SET_NOT_FOUND`, both before any download. `control` (from `marmot_emoji_set_install_control_new`) reports progress and cancels; a cancelled install, or one stopped by runtime shutdown or close, is `MARMOT_STATUS_EMOJI_SET_INSTALL_CANCELLED` and stores nothing. Free with `marmot_emoji_set_install_result_free`.

[Header contract](include/marmot.h#L13129)

### `marmot_installed_custom_emoji`

```c
MarmotStatus marmot_installed_custom_emoji(const struct MarmotClient *client, const char *account_ref, struct MarmotInstalledCustomEmojiList **out);
```

Every installed emoji for a picker, with no URL; shortcode collisions are flagged, not resolved. No network I/O. Free with `marmot_installed_custom_emoji_list_free`.

[Header contract](include/marmot.h#L12697)

### `marmot_installed_custom_emoji_asset_free`

```c
void marmot_installed_custom_emoji_asset_free(struct MarmotInstalledCustomEmojiAsset *ptr);
```

Frees an installed emoji asset and its bytes. NULL is safe.

[Header contract](include/marmot.h#L15278)

### `marmot_installed_custom_emoji_free`

```c
void marmot_installed_custom_emoji_free(struct MarmotInstalledCustomEmoji *ptr);
```

Frees one installed emoji record. NULL is safe.

[Header contract](include/marmot.h#L15259)

### `marmot_installed_custom_emoji_list_free`

```c
void marmot_installed_custom_emoji_list_free(struct MarmotInstalledCustomEmojiList *list);
```

Frees an installed emoji list. NULL is safe.

[Header contract](include/marmot.h#L15268)

### `marmot_read_installed_custom_emoji`

```c
MarmotStatus marmot_read_installed_custom_emoji(const struct MarmotClient *client, const char *account_ref, const char *coordinate, const char *shortcode, struct MarmotInstalledCustomEmojiAsset **out);
```

Reads an installed emoji's stored bytes, checked against their SHA-256. No network I/O. Send them only as an encrypted attachment. Free with `marmot_installed_custom_emoji_asset_free`.

[Header contract](include/marmot.h#L12712)

### `marmot_sync_emoji_sets`

```c
MarmotStatus marmot_sync_emoji_sets(const struct MarmotClient *client, const char *account_ref, const char *search, struct MarmotEmojiSetSyncResult **out);
```

Fetches up to 60 of the newest kind-30030 sets from the account's relays. Text only: never fetches an image. Free with `marmot_emoji_set_sync_result_free`.

[Header contract](include/marmot.h#L12597)

### `marmot_uninstall_emoji_set`

```c
MarmotStatus marmot_uninstall_emoji_set(const struct MarmotClient *client, const char *account_ref, const char *coordinate, bool *out);
```

Removes an installed snapshot and its stored bytes; writes whether it was installed. No network I/O.

[Header contract](include/marmot.h#L12642)

### `marmot_user_emoji_list`

```c
MarmotStatus marmot_user_emoji_list(const struct MarmotClient *client, const char *account_ref, struct MarmotUserEmojiList **out);
```

Reads the account's kind-10030 emoji list and the sets it points to, for suggestions. Text only; MDK never publishes or edits kind 10030. Free with `marmot_user_emoji_list_free`.

[Header contract](include/marmot.h#L12628)

### `marmot_user_emoji_list_free`

```c
void marmot_user_emoji_list_free(struct MarmotUserEmojiList *ptr);
```

Frees a user emoji list, its sets and missing coordinates. NULL is safe.

[Header contract](include/marmot.h#L15229)

</details>

## Relay liveness

### `marmot_account_relay_liveness`

```c
MarmotStatus marmot_account_relay_liveness(const struct MarmotClient *client, const char *account_ref, struct MarmotRelayLivenessList **out);
```

Read an account's configured relay states without dialing. `out` receives an owned list on success;
release it with `marmot_relay_liveness_list_free`. Unknown entries and optional attempt/error fields follow the
[shared relay contract](../marmot-uniffi/README.md#relay-liveness). Inputs are borrowed.

[Header contract](include/marmot.h#L10216)

### `marmot_reconnect_relay`

```c
MarmotStatus marmot_reconnect_relay(const struct MarmotClient *client, const char *account_ref, const char *url, struct MarmotRelayLiveness **out);
```

Dispatch through the running account worker; once handled, the dial wait is capped at five seconds.
Normal dial safety applies. The returned owned record may still report `Connecting`; free it with
`marmot_relay_liveness_free` and use the subscription for later outcomes. Inputs remain borrowed.

[Header contract](include/marmot.h#L10230)

### `marmot_relay_liveness_free`

```c
void marmot_relay_liveness_free(struct MarmotRelayLiveness *ptr);
```

Deep-free a record returned by `marmot_reconnect_relay`, including its URL and optional error string.
NULL is a no-op. Never free a record embedded in a list or borrowed by a callback separately.

[Header contract](include/marmot.h#L15782)

### `marmot_relay_liveness_list_free`

```c
void marmot_relay_liveness_list_free(struct MarmotRelayLivenessList *list);
```

Deep-free a snapshot list and all its nested records and strings. NULL is a no-op.
Use only for owned getter, snapshot, or blocking-next results, never callback payloads.

[Header contract](include/marmot.h#L15791)

### `marmot_relay_liveness_subscription_clear_callback`

```c
MarmotStatus marmot_relay_liveness_subscription_clear_callback(const struct MarmotRelayLivenessSubscription *sub);
```

Request cancellation of the installed callback pump without closing the observer. The call does not wait for an
executing callback and does not guarantee a terminal callback. Keep `user_data` live until callbacks are quiescent.

[Header contract](include/marmot.h#L14207)

### `marmot_relay_liveness_subscription_cancel`

```c
MarmotStatus marmot_relay_liveness_subscription_cancel(const struct MarmotRelayLivenessSubscription *sub);
```

Close only this observer; pending and future reads return `MARMOT_STATUS_CLOSED`. The account's connections
remain unchanged. Free the handle separately after all concurrent calls have ended.

[Header contract](include/marmot.h#L14239)

### `marmot_relay_liveness_subscription_free`

```c
void marmot_relay_liveness_subscription_free(struct MarmotRelayLivenessSubscription *sub);
```

Free the observer handle before freeing its client. NULL is a no-op. No calls may still be using the handle.
Callback cancellation does not wait for an already executing callback; its context must remain valid.

[Header contract](include/marmot.h#L14214)

### `marmot_relay_liveness_subscription_next`

```c
MarmotStatus marmot_relay_liveness_subscription_next(const struct MarmotRelayLivenessSubscription *sub, uint32_t timeout_ms, struct MarmotRelayLivenessList **out);
```

Block for the next complete replacement list. Zero timeout waits indefinitely; a positive timeout is milliseconds.
Success returns an owned list to free with `marmot_relay_liveness_list_free`. Timeout, close, and mapped read errors
leave `out` NULL. A timed-out call consumes no update. Do not mix blocking reads with an installed callback.

[Header contract](include/marmot.h#L14187)

### `marmot_relay_liveness_subscription_set_callback`

```c
MarmotStatus marmot_relay_liveness_subscription_set_callback(const struct MarmotRelayLivenessSubscription *sub, MarmotRelayLivenessCallback callback, void *user_data);
```

Install one callback pump instead of blocking reads. `MARMOT_STATUS_OK` accompanies a borrowed list valid only
during the callback; the pump deep-frees it afterward. Terminal NULL carries `MARMOT_STATUS_CLOSED` or a mapped
read-error status. Callbacks run on runtime workers. `user_data` must outlive every executing callback.

[Header contract](include/marmot.h#L14198)

### `marmot_relay_liveness_subscription_snapshot`

```c
MarmotStatus marmot_relay_liveness_subscription_snapshot(const struct MarmotRelayLivenessSubscription *sub, struct MarmotRelayLivenessList **out);
```

Take the initial owned snapshot once; subsequent calls return owned empty lists. Free each result with
`marmot_relay_liveness_list_free`. Reading the initial snapshot does not consume a later update.

[Header contract](include/marmot.h#L14231)

### `marmot_subscribe_relay_liveness`

```c
MarmotStatus marmot_subscribe_relay_liveness(const struct MarmotClient *client, const char *account_ref, struct MarmotRelayLivenessSubscription **out_sub);
```

Create an account-scoped relay observer. Take its initial snapshot, then use blocking `next` or install a callback
for complete replacement lists. Intermediate states may coalesce. Close the watch when it is no longer needed,
then free its handle before freeing the client. Client and account inputs remain borrowed.

[Header contract](include/marmot.h#L14221)
