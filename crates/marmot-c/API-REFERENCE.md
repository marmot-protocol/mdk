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

### `marmot_attachment_local_asset_list_free`

```c
void marmot_attachment_local_asset_list_free(struct MarmotAttachmentLocalAssetList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L5479)

### `marmot_attachment_local_bytes_free`

```c
void marmot_attachment_local_bytes_free(struct MarmotAttachmentLocalBytes *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L5489)

### `marmot_attachment_local_assets`

```c
MarmotStatus marmot_attachment_local_assets(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const struct MarmotAttachmentLocalTarget *targets, uintptr_t targets_len, struct MarmotAttachmentLocalAssetList **out);
```

Look up up to 64 original slots in one group, preserving input order/duplicates. Does not load bytes, enqueue demand, start a worker or perform network work. # Safety Client/strings and targets[0..targets_len] must be live. Targets may be NULL only with zero length. Out must be writable. Inputs are borrowed, outputs owned.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotattachment_local_assets) · [Header contract](include/marmot.h#L5498)

### `marmot_attachment_page_read_free`

```c
void marmot_attachment_page_read_free(struct MarmotAttachmentPageRead *value);
```

Deep-free a page result and its cursor/version. NULL is a no-op. # Safety Value must be NULL or an owned result, not freed or borrowed by an active call.

[Header contract](include/marmot.h#L5510)

### `marmot_attachment_history_version_free`

```c
void marmot_attachment_history_version_free(struct MarmotAttachmentHistoryVersion *value);
```

Free a standalone version returned by a version read or clone, not a page field. # Safety Value must be NULL or a standalone owned version, with no active borrows.

[Header contract](include/marmot.h#L5517)

### `marmot_attachment_history_version_clone`

```c
MarmotStatus marmot_attachment_history_version_clone(const struct MarmotAttachmentHistoryVersion *value, struct MarmotAttachmentHistoryVersion **out);
```

Retain a standalone baseline version without retaining its owning page. Free the result with marmot_attachment_history_version_free. # Safety Value must be a live standalone version or borrowed page field; out must be writable.

[Header contract](include/marmot.h#L5525)

### `marmot_attachment_history_page`

```c
MarmotStatus marmot_attachment_history_page(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, uint32_t limit, const struct MarmotAttachmentHistoryCursor *cursor, struct MarmotAttachmentPageRead **out);
```

Blocking local read. Call off the UI thread; limit is 1..=100 slots. NULL cursor starts at the head. Cursor is borrowed for this call; no network work starts. # Safety Client and strings must be live; cursor must be NULL or live; out must be writable.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotattachment_history_page) · [Header contract](include/marmot.h#L5534)

### `marmot_attachment_history_version`

```c
MarmotStatus marmot_attachment_history_version(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotAttachmentHistoryVersion **out);
```

Blocking local revision read, including after exhaustion. Free the standalone result. # Safety Client/strings must be live and out writable.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotattachment_history_version) · [Header contract](include/marmot.h#L5546)

### `marmot_attachment_history_version_change_since`

```c
MarmotStatus marmot_attachment_history_version_change_since(const struct MarmotAttachmentHistoryVersion *current, const struct MarmotAttachmentHistoryVersion *previous, uint32_t *out);
```

Compare a current version with the retained baseline. Output is a MarmotAttachmentHistoryChange discriminant. # Safety Both versions must be live (standalone or borrowed page fields); out must be writable.

[Header contract](include/marmot.h#L5556)

### `marmot_account_unread_summary`

```c
MarmotStatus marmot_account_unread_summary(const struct MarmotClient *client, struct MarmotAccountUnreadList **out);
```

Per-account unread aggregates for the account-switcher badge. Free with `marmot_account_unread_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotaccount_unread_summary) · [Header contract](include/marmot.h#L5646)

### `marmot_approve_onboarding_repair_in_epoch`

```c
MarmotStatus marmot_approve_onboarding_repair_in_epoch(const struct MarmotClient *client, const char *account_ref, uint64_t revision, const char *recovery_epoch, struct MarmotOnboardingSnapshot **out);
```

Approve using the epoch and revision from the same displayed snapshot.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotapprove_onboarding_repair_in_epoch) · [Header contract](include/marmot.h#L5731)

### `marmot_acknowledge_onboarding_single_device_in_epoch`

```c
MarmotStatus marmot_acknowledge_onboarding_single_device_in_epoch(const struct MarmotClient *client, const char *account_ref, uint64_t revision, const char *recovery_epoch, struct MarmotOnboardingSnapshot **out);
```

Acknowledge the displayed device notice in a recovered attempt.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotacknowledge_onboarding_single_device_in_epoch) · [Header contract](include/marmot.h#L5746)

### `marmot_acknowledge_onboarding_single_device`

```c
MarmotStatus marmot_acknowledge_onboarding_single_device(const struct MarmotClient *client, const char *account_ref, uint64_t revision, struct MarmotOnboardingSnapshot **out);
```

Acknowledge the displayed one-device notice and resume setup.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotacknowledge_onboarding_single_device) · [Header contract](include/marmot.h#L5775)

### `marmot_account_nip65_relays`

```c
MarmotStatus marmot_account_nip65_relays(const struct MarmotClient *client, const char *account_ref, struct MarmotStringList **out);
```

The account's NIP-65 relay list. Free with `marmot_string_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotaccount_nip65_relays) · [Header contract](include/marmot.h#L5870)

### `marmot_account_inbox_relays`

```c
MarmotStatus marmot_account_inbox_relays(const struct MarmotClient *client, const char *account_ref, struct MarmotStringList **out);
```

The account's inbox relay list. Free with `marmot_string_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotaccount_inbox_relays) · [Header contract](include/marmot.h#L5884)

### `marmot_account_key_packages`

```c
MarmotStatus marmot_account_key_packages(const struct MarmotClient *client, const char *account_ref, const char *const *bootstrap_relays, uintptr_t bootstrap_relays_len, struct MarmotAccountKeyPackageList **out);
```

Local + current-slot relay-published KeyPackages for the account. Free with `marmot_account_key_package_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotaccount_key_packages) · [Header contract](include/marmot.h#L5898)

### `marmot_account_key_package_relay_events`

```c
MarmotStatus marmot_account_key_package_relay_events(const struct MarmotClient *client, const char *account_ref, const char *const *bootstrap_relays, uintptr_t bootstrap_relays_len, struct MarmotAccountKeyPackageRelayEventList **out);
```

Observed relay KeyPackage history, including superseded events. Free with `marmot_account_key_package_relay_event_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotaccount_key_package_relay_events) · [Header contract](include/marmot.h#L5947)

### `marmot_accept_group_invite`

```c
MarmotStatus marmot_accept_group_invite(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotAppGroupRecord **out);
```

Accept a pending group invite; writes the now-confirmed group record. Free with `marmot_app_group_record_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotaccept_group_invite) · [Header contract](include/marmot.h#L6318)

### `marmot_account_relay_lists`

```c
MarmotStatus marmot_account_relay_lists(const struct MarmotClient *client, const char *account_ref, struct MarmotAccountRelayLists **out);
```

The account's full relay-list state. Free with `marmot_account_relay_lists_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotaccount_relay_lists) · [Header contract](include/marmot.h#L6884)

### `marmot_audit_log_settings`

```c
MarmotStatus marmot_audit_log_settings(const struct MarmotClient *client, struct MarmotAuditLogSettings **out);
```

Current audit-log recorder settings. Free with `marmot_audit_log_settings_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotaudit_log_settings) · [Header contract](include/marmot.h#L6923)

### `marmot_audit_log_files`

```c
MarmotStatus marmot_audit_log_files(const struct MarmotClient *client, struct MarmotAuditLogFileList **out);
```

On-disk audit-log files. Free with `marmot_audit_log_file_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotaudit_log_files) · [Header contract](include/marmot.h#L6936)

### `marmot_account_follows`

```c
MarmotStatus marmot_account_follows(const struct MarmotClient *client, const char *account_ref, struct MarmotStringList **out);
```

The account ids this account follows (NIP-02). Free with `marmot_string_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotaccount_follows) · [Header contract](include/marmot.h#L7315)

### `marmot_acknowledge_disband_failure`

```c
MarmotStatus marmot_acknowledge_disband_failure(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, bool *out);
```

Acknowledge a failed disband request so the UI can stop surfacing it. Writes whether a request was actually cleared.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotacknowledge_disband_failure) · [Header contract](include/marmot.h#L7515)

### `marmot_account_setup_readiness`

```c
MarmotStatus marmot_account_setup_readiness(const struct MarmotClient *client, const char *account_ref, enum MarmotAccountSetupReadiness *out);
```

How far the account's setup has progressed.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotaccount_setup_readiness) · [Header contract](include/marmot.h#L7618)

### `marmot_account_id_hex`

```c
MarmotStatus marmot_account_id_hex(const struct MarmotClient *client, const char *reference, char **out);
```

Hex account id for an `npub`/hex/`nprofile` reference; NULL with `MARMOT_STATUS_OK` when the input does not decode. Accepts hex, `npub`, `nostr:npub`, `nprofile`, `nostr:nprofile`, and `marmot://profile/` links. nprofile relay hints are discarded. Duplicate type-0 TLV entries keep the first key. After wrapper normalization, encoded tokens longer than 1023 UTF-8 bytes are rejected; a valid 1023-byte token still decodes when wrapped. Free with `marmot_string_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotaccount_id_hex) · [Header contract](include/marmot.h#L7987)

### `marmot_app_performance_snapshot`

```c
MarmotStatus marmot_app_performance_snapshot(const struct MarmotClient *client, struct MarmotAppPerformanceSnapshot **out);
```

Process-wide performance counters. Aggregates only — no account, group, relay, or path information. Free with `marmot_app_performance_snapshot_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotapp_performance_snapshot) · [Header contract](include/marmot.h#L8532)

### `marmot_approve_onboarding_repair`

```c
MarmotStatus marmot_approve_onboarding_repair(const struct MarmotClient *client, const char *account_ref, uint64_t revision, struct MarmotOnboardingSnapshot **out);
```

Approve the proposal at the current snapshot revision and resume publication; stale revisions are rejected. Free the returned snapshot with `marmot_onboarding_snapshot_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotapprove_onboarding_repair) · [Header contract](include/marmot.h#L8679)

### `marmot_agent_publisher_new`

```c
MarmotStatus marmot_agent_publisher_new(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const struct MarmotPublisherOptions *options, struct MarmotAgentPublisher **out);
```

Anchor a new stream and return its publisher. Broker connection happens in the background. Invalid inputs/out-pointers fail before anchoring.

[Header contract](include/marmot.h#L8908)

### `marmot_agent_publisher_info`

```c
MarmotStatus marmot_agent_publisher_info(const struct MarmotAgentPublisher *publisher, struct MarmotPublisherInfo **out);
```

Read stream identifiers. Free with `marmot_publisher_info_free`.

[Header contract](include/marmot.h#L8920)

### `marmot_agent_publisher_append`

```c
MarmotStatus marmot_agent_publisher_append(const struct MarmotAgentPublisher *publisher, uint32_t kind, const char *text, struct MarmotPublisherAck **out);
```

Append one text/status/progress record; free the receipt with `marmot_publisher_ack_free`. Unknown record types fail before appending.

[Header contract](include/marmot.h#L8930)

### `marmot_agent_publisher_finish`

```c
MarmotStatus marmot_agent_publisher_finish(const struct MarmotAgentPublisher *publisher, struct MarmotSendSummary **out);
```

Seal and send the final transcript. Failed sends retain the sealed request for retry; a successful repeated call returns the original receipt. Free with `marmot_send_summary_free`. Inspect its delivery disposition.

[Header contract](include/marmot.h#L8943)

### `marmot_agent_publisher_cancel`

```c
MarmotStatus marmot_agent_publisher_cancel(const struct MarmotAgentPublisher *publisher);
```

Cancel the preview. Does not retract a final already being published.

[Header contract](include/marmot.h#L8952)

### `marmot_agent_publisher_free`

```c
void marmot_agent_publisher_free(struct MarmotAgentPublisher *publisher);
```

Release a publisher, requesting preview cancellation. NULL is a no-op.

[Header contract](include/marmot.h#L8961)

### `marmot_agent_stream_subscription_next`

```c
MarmotStatus marmot_agent_stream_subscription_next(const struct MarmotAgentStreamSubscription *sub, uint32_t timeout_ms, struct MarmotAgentStreamUpdate **out);
```

Block until the next item, the timeout, or stream close. `timeout_ms == 0` waits indefinitely. Returns `MARMOT_STATUS_OK` (out set; free with `marmot_agent_stream_update_free`), `MARMOT_STATUS_TIMEOUT`, or `MARMOT_STATUS_CLOSED` (out NULL for both).

[Header contract](include/marmot.h#L9512)

### `marmot_agent_stream_subscription_set_callback`

```c
MarmotStatus marmot_agent_stream_subscription_set_callback(const struct MarmotAgentStreamSubscription *sub, MarmotAgentStreamUpdateCallback callback, void *user_data);
```

Install a callback pump for this subscription. `callback` runs on a runtime worker thread with a borrowed item pointer (valid only during the call; do not store or free it) and a final NULL item on close. `callback` and `user_data` access must be thread-safe. Fails if a callback is already installed.

[Header contract](include/marmot.h#L9529)

### `marmot_agent_stream_subscription_clear_callback`

```c
MarmotStatus marmot_agent_stream_subscription_clear_callback(const struct MarmotAgentStreamSubscription *sub);
```

Request cancellation of this subscription's callback pump, if any. Non-blocking: a callback already running keeps executing after this returns (see the module docs).

[Header contract](include/marmot.h#L9541)

### `marmot_agent_stream_subscription_free`

```c
void marmot_agent_stream_subscription_free(struct MarmotAgentStreamSubscription *sub);
```

Free the subscription handle. Requests callback-pump cancellation without waiting (a callback may still be running after this returns — do not free `user_data` on that basis). NULL is a no-op. Free every handle before the client that created it.

[Header contract](include/marmot.h#L9553)

### `marmot_agent_stream_subscription_stream_id_hex`

```c
MarmotStatus marmot_agent_stream_subscription_stream_id_hex(const struct MarmotAgentStreamSubscription *sub, char **out_stream_id_hex);
```

The resolved stream id this watch is following (hex). Writes an owned copy: free it with `marmot_string_free`.

[Header contract](include/marmot.h#L9586)

### `marmot_attachment_transfer_subscription_next`

```c
MarmotStatus marmot_attachment_transfer_subscription_next(const struct MarmotAttachmentTransferSubscription *sub, uint32_t timeout_ms, struct MarmotAttachmentTransferSnapshot **out);
```

Initial snapshot then replacements, at most four per second. Zero timeout waits indefinitely. Timeout does not consume updates. Free results with marmot_attachment_transfer_snapshot_free. # Safety Sub must be live and out writable. Use one receiver per handle.

[Header contract](include/marmot.h#L9845)

### `marmot_attachment_transfer_subscription_cancel`

```c
MarmotStatus marmot_attachment_transfer_subscription_cancel(const struct MarmotAttachmentTransferSubscription *sub);
```

Close observation and wake receivers. Does not cancel downloads. # Safety Sub must remain live throughout the call.

[Header contract](include/marmot.h#L9854)

### `marmot_attachment_transfer_subscription_free`

```c
void marmot_attachment_transfer_subscription_free(struct MarmotAttachmentTransferSubscription *sub);
```

NULL-safe free. Already returned snapshots remain separately owned. # Safety Sub must be NULL or library-owned with no active calls.

[Header contract](include/marmot.h#L9861)

### `marmot_account_attention_subscription_snapshot`

```c
MarmotStatus marmot_account_attention_subscription_snapshot(const struct MarmotAccountAttentionSubscription *sub, struct MarmotAccountAttentionSnapshot **out);
```

Take the initial snapshot once; a second call returns CLOSED. Result must be deep-freed. # Safety sub must be live and out writable.

[Header contract](include/marmot.h#L9893)

### `marmot_account_attention_subscription_next`

```c
MarmotStatus marmot_account_attention_subscription_next(const struct MarmotAccountAttentionSubscription *sub, uint32_t timeout_ms, struct MarmotAccountAttentionSnapshot **out);
```

Receive a complete replacement. Zero timeout waits indefinitely. Timeout/error/closed leaves out NULL. Timeout does not consume an update. Free results with the matching snapshot_free. # Safety sub must remain live throughout the call; out must be writable. Use one receiver per handle.

[Header contract](include/marmot.h#L9902)

### `marmot_account_attention_subscription_free`

```c
void marmot_account_attention_subscription_free(struct MarmotAccountAttentionSubscription *sub);
```

Cancel and free. NULL is a no-op; does not free previously returned snapshots. # Safety sub must be NULL or a library-owned handle with no active calls.

[Header contract](include/marmot.h#L9911)

### `marmot_account_summary_free`

```c
void marmot_account_summary_free(struct MarmotAccountSummary *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10158)

### `marmot_account_summary_list_free`

```c
void marmot_account_summary_list_free(struct MarmotAccountSummaryList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10167)

### `marmot_account_unread_list_free`

```c
void marmot_account_unread_list_free(struct MarmotAccountUnreadList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10176)

### `marmot_account_key_package_list_free`

```c
void marmot_account_key_package_list_free(struct MarmotAccountKeyPackageList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10195)

### `marmot_account_key_package_inventory_entry_list_free`

```c
void marmot_account_key_package_inventory_entry_list_free(struct MarmotAccountKeyPackageInventoryEntryList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10204)

### `marmot_account_key_package_relay_event_list_free`

```c
void marmot_account_key_package_relay_event_list_free(struct MarmotAccountKeyPackageRelayEventList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10213)

### `marmot_agent_stream_start_free`

```c
void marmot_agent_stream_start_free(struct MarmotAgentStreamStart *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10263)

### `marmot_agent_stream_update_free`

```c
void marmot_agent_stream_update_free(struct MarmotAgentStreamUpdate *update);
```

Free an agent-stream update returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10271)

### `marmot_audit_log_settings_free`

```c
void marmot_audit_log_settings_free(struct MarmotAuditLogSettings *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10281)

### `marmot_audit_log_tracker_config_v4_free`

```c
void marmot_audit_log_tracker_config_v4_free(struct MarmotAuditLogTrackerConfigV4 *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10291)

### `marmot_audit_log_tracker_config_free`

```c
void marmot_audit_log_tracker_config_free(struct MarmotAuditLogTrackerConfig *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10301)

### `marmot_audit_log_file_free`

```c
void marmot_audit_log_file_free(struct MarmotAuditLogFile *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10311)

### `marmot_audit_log_file_list_free`

```c
void marmot_audit_log_file_list_free(struct MarmotAuditLogFileList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10320)

### `marmot_audit_log_upload_result_free`

```c
void marmot_audit_log_upload_result_free(struct MarmotAuditLogUploadResult *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10330)

### `marmot_audit_log_delete_result_free`

```c
void marmot_audit_log_delete_result_free(struct MarmotAuditLogDeleteResult *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10340)

### `marmot_audit_log_tracker_update_result_free`

```c
void marmot_audit_log_tracker_update_result_free(struct MarmotAuditLogTrackerUpdateResult *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10350)

### `marmot_app_group_record_free`

```c
void marmot_app_group_record_free(struct MarmotAppGroupRecord *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10519)

### `marmot_app_group_record_list_free`

```c
void marmot_app_group_record_list_free(struct MarmotAppGroupRecordList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10528)

### `marmot_app_group_member_record_list_free`

```c
void marmot_app_group_member_record_list_free(struct MarmotAppGroupMemberRecordList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10537)

### `marmot_app_group_mls_state_free`

```c
void marmot_app_group_mls_state_free(struct MarmotAppGroupMlsState *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10557)

### `marmot_app_quarantined_group_list_free`

```c
void marmot_app_quarantined_group_list_free(struct MarmotAppQuarantinedGroupList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10606)

### `marmot_app_group_member_ids_free`

```c
void marmot_app_group_member_ids_free(struct MarmotAppGroupMemberIds *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10636)

### `marmot_app_group_member_ids_list_free`

```c
void marmot_app_group_member_ids_list_free(struct MarmotAppGroupMemberIdsList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10645)

### `marmot_app_message_record_free`

```c
void marmot_app_message_record_free(struct MarmotAppMessageRecord *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10803)

### `marmot_app_message_record_list_free`

```c
void marmot_app_message_record_list_free(struct MarmotAppMessageRecordList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10812)

### `marmot_account_relay_lists_free`

```c
void marmot_account_relay_lists_free(struct MarmotAccountRelayLists *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10930)

### `marmot_app_performance_snapshot_free`

```c
void marmot_app_performance_snapshot_free(struct MarmotAppPerformanceSnapshot *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10979)

### `marmot_account_attention_snapshot_free`

```c
void marmot_account_attention_snapshot_free(struct MarmotAccountAttentionSnapshot *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L11098)

### `marmot_avatar_asset_free`

```c
void marmot_avatar_asset_free(struct MarmotAvatarAsset *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L11147)

### `marmot_avatar_asset_list_free`

```c
void marmot_avatar_asset_list_free(struct MarmotAvatarAssetList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L11156)

### `marmot_avatar_bytes_free`

```c
void marmot_avatar_bytes_free(struct MarmotAvatarBytes *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L11166)

### `marmot_avatar_bytes_list_free`

```c
void marmot_avatar_bytes_list_free(struct MarmotAvatarBytesList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L11175)

### `marmot_attachment_download_policy_free`

```c
void marmot_attachment_download_policy_free(struct MarmotAttachmentDownloadPolicy *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L11205)

### `marmot_attachment_transfer_snapshot_free`

```c
void marmot_attachment_transfer_snapshot_free(struct MarmotAttachmentTransferSnapshot *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L11215)

### `marmot_attachment_download_policy`

```c
MarmotStatus marmot_attachment_download_policy(const struct MarmotClient *client, const char *account_ref, struct MarmotAttachmentDownloadPolicy **out);
```

Read the effective durable policy. # Safety Client and strings must be live, out writable. Free the returned record.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotattachment_download_policy) · [Header contract](include/marmot.h#L11222)

### `marmot_attachment_transfer_snapshot`

```c
MarmotStatus marmot_attachment_transfer_snapshot(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const struct MarmotAttachmentLocalTarget *targets, uintptr_t targets_len, struct MarmotAttachmentTransferSnapshot **out);
```

Read up to 64 progress entries in input order. No network demand is created. # Safety Inputs must be live; targets may be NULL only for zero length; out writable.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotattachment_transfer_snapshot) · [Header contract](include/marmot.h#L11262)

</details>

<details>
<summary>marmot_b…</summary>

### `marmot_bytes_free`

```c
void marmot_bytes_free(uint8_t *data, uintptr_t len);
```

Free a byte buffer returned by this library as a `(data, len)` pair (e.g. `marmot_download_group_blossom_image`). `(NULL, 0)` is a no-op.

[Header contract](include/marmot.h#L5470)

### `marmot_block_user`

```c
MarmotStatus marmot_block_user(const struct MarmotClient *client, const char *account_ref, const char *user_account_id_hex);
```

Block a user privately and publish the updated list. Requires relay synchronization.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotblock_user) · [Header contract](include/marmot.h#L7261)

### `marmot_build_media_imeta_tag`

```c
MarmotStatus marmot_build_media_imeta_tag(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const struct MarmotMediaAttachmentReference *reference, struct MarmotMessageTag **out);
```

Build the NIP-92 `imeta` tag for an already-uploaded attachment, so a host can compose the outgoing event itself. Free with `marmot_message_tag_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotbuild_media_imeta_tag) · [Header contract](include/marmot.h#L8449)

### `marmot_begin_onboarding`

```c
MarmotStatus marmot_begin_onboarding(const struct MarmotClient *client, const char *nsec, const char *const *default_relays, uintptr_t default_relays_len, const char *const *discovery_relays, uintptr_t discovery_relays_len, struct MarmotOnboardingSnapshot **out);
```

Import an identity and persist its onboarding gate without publishing. Free the returned snapshot with `marmot_onboarding_snapshot_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotbegin_onboarding) · [Header contract](include/marmot.h#L8555)

### `marmot_block_list_subscription_next`

```c
MarmotStatus marmot_block_list_subscription_next(const struct MarmotBlockListSubscription *sub, uint32_t timeout_ms, struct MarmotBlockListSnapshot **out);
```

Block until the next item, the timeout, or stream close. `timeout_ms == 0` waits indefinitely. Returns `MARMOT_STATUS_OK` (out set; free with `marmot_block_list_snapshot_free`), `MARMOT_STATUS_TIMEOUT`, or `MARMOT_STATUS_CLOSED` (out NULL for both).

[Header contract](include/marmot.h#L9767)

### `marmot_block_list_subscription_set_callback`

```c
MarmotStatus marmot_block_list_subscription_set_callback(const struct MarmotBlockListSubscription *sub, MarmotBlockListCallback callback, void *user_data);
```

Install a callback pump for this subscription. `callback` runs on a runtime worker thread with a borrowed item pointer (valid only during the call; do not store or free it) and a final NULL item on close. `callback` and `user_data` access must be thread-safe. Fails if a callback is already installed.

[Header contract](include/marmot.h#L9784)

### `marmot_block_list_subscription_clear_callback`

```c
MarmotStatus marmot_block_list_subscription_clear_callback(const struct MarmotBlockListSubscription *sub);
```

Request cancellation of this subscription's callback pump, if any. Non-blocking: a callback already running keeps executing after this returns (see the module docs).

[Header contract](include/marmot.h#L9796)

### `marmot_block_list_subscription_free`

```c
void marmot_block_list_subscription_free(struct MarmotBlockListSubscription *sub);
```

Free the subscription handle. Requests callback-pump cancellation without waiting (a callback may still be running after this returns — do not free `user_data` on that basis). NULL is a no-op. Free every handle before the client that created it.

[Header contract](include/marmot.h#L9808)

### `marmot_block_list_subscription_snapshot`

```c
MarmotStatus marmot_block_list_subscription_snapshot(const struct MarmotBlockListSubscription *sub, struct MarmotBlockListSnapshot **out);
```

Take the initial snapshot once; subsequent calls return NULL. # Safety Subscription and output pointer must be valid.

[Header contract](include/marmot.h#L9824)

### `marmot_background_notification_collection_free`

```c
void marmot_background_notification_collection_free(struct MarmotBackgroundNotificationCollection *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10880)

### `marmot_blocked_user_list_free`

```c
void marmot_blocked_user_list_free(struct MarmotBlockedUserList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L11127)

### `marmot_block_list_snapshot_free`

```c
void marmot_block_list_snapshot_free(struct MarmotBlockListSnapshot *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L11137)

</details>

<details>
<summary>marmot_c…</summary>

### `marmot_client_new_with_options`

```c
MarmotStatus marmot_client_new_with_options(const char *root_path, const char *const *relay_urls, uintptr_t relay_urls_len, uint32_t relay_policy, const struct MarmotSecretStore *store, struct MarmotClient **out_client);
```

Create a client with an explicit relay policy and optional host secret store. `store == NULL` selects the platform keychain. Loopback opt-in does not permit private/link-local relays or plaintext public endpoints. Ownership of the store transfers only on success, as with `marmot_client_new_with_secret_store`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotnew_with_options) · [Header contract](include/marmot.h#L5297)

### `marmot_client_new`

```c
MarmotStatus marmot_client_new(const char *root_path, const char *const *relay_urls, uintptr_t relay_urls_len, struct MarmotClient **out_client);
```

Create a Marmot client rooted at `root_path`, connected to `relay_urls` (`relay_urls_len` entries). On success writes the new handle to `out_client`. Uses the platform keychain-backed account store, matching the UniFFI constructor.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotnew) · [Header contract](include/marmot.h#L5315)

### `marmot_client_new_with_cursor_persistence`

```c
MarmotStatus marmot_client_new_with_cursor_persistence(const char *root_path, const char *const *relay_urls, uintptr_t relay_urls_len, uint32_t cursor_persistence, struct MarmotClient **out_client);
```

Create a Marmot client with an explicit durable transport-cursor policy. Identical to `marmot_client_new`, which is `MARMOT_CURSOR_PERSISTENCE_ADVANCE`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotnew_with_cursor_persistence) · [Header contract](include/marmot.h#L5337)

### `marmot_client_new_with_secret_store`

```c
MarmotStatus marmot_client_new_with_secret_store(const char *root_path, const char *const *relay_urls, uintptr_t relay_urls_len, const struct MarmotSecretStore *store, struct MarmotClient **out_client);
```

Create a Marmot client whose account signing keys live in caller-owned storage instead of the platform keychain. Otherwise identical to `marmot_client_new`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotnew_with_secret_store) · [Header contract](include/marmot.h#L5365)

### `marmot_client_new_with_client_name`

```c
MarmotStatus marmot_client_new_with_client_name(const char *root_path, const char *const *relay_urls, uintptr_t relay_urls_len, const char *client_name, uint32_t cursor_persistence, const struct MarmotSecretStore *store, struct MarmotClient **out_client);
```

Open with an optional public client name for newly prepared KeyPackages. NULL or whitespace-only `client_name` omits the tag. Signed retries keep their original tags. NULL `store` selects the platform keychain. Store ownership transfers only on success, as with `marmot_client_new_with_secret_store`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotnew_with_client_name) · [Header contract](include/marmot.h#L5382)

### `marmot_client_new_with_configuration`

```c
MarmotStatus marmot_client_new_with_configuration(const char *root_path, const char *const *relay_urls, uintptr_t relay_urls_len, const struct MarmotClientOptions *options, struct MarmotClient **out_client);
```

Create a client with combined relay, cursor, label and secret-storage options. NULL options uses defaults. Store ownership transfers only on success, with the same callback lifetime contract as marmot_client_new_with_secret_store.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotnew_with_configuration) · [Header contract](include/marmot.h#L5400)

### `marmot_client_start`

```c
MarmotStatus marmot_client_start(const struct MarmotClient *client);
```

Start the runtime (reconcile accounts, start workers, subscribe transport). Must be called before subscribing.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotstart) · [Header contract](include/marmot.h#L5413)

### `marmot_client_shutdown`

```c
MarmotStatus marmot_client_shutdown(const struct MarmotClient *client);
```

Shut the runtime down. Open subscriptions drain and report `MARMOT_STATUS_CLOSED` from their next read.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotshutdown) · [Header contract](include/marmot.h#L5422)

### `marmot_client_is_stopping`

```c
MarmotStatus marmot_client_is_stopping(const struct MarmotClient *client, bool *out_stopping);
```

Whether the runtime is currently shutting down. Writes to `out_stopping`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotis_stopping) · [Header contract](include/marmot.h#L5430)

### `marmot_client_free`

```c
void marmot_client_free(struct MarmotClient *client);
```

Destroy a client handle. Call `marmot_client_shutdown` first for a graceful stop. NULL is a no-op. The handle must not be used afterwards.

[Header contract](include/marmot.h#L5443)

### `marmot_clear_avatar_cache`

```c
MarmotStatus marmot_clear_avatar_cache(const struct MarmotClient *client, const char *account_ref);
```

Remove this account's local avatar bytes and demand. Later visible requests may reacquire them.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotclear_avatar_cache) · [Header contract](include/marmot.h#L5621)

### `marmot_cancel_onboarding`

```c
MarmotStatus marmot_cancel_onboarding(const struct MarmotClient *client, const char *account_ref);
```

Cancel unfinished onboarding, retaining the signed-out identity and private state. Cancellation is valid at every interactive step, including approved or ready attempts. It performs no relay deletion.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotcancel_onboarding) · [Header contract](include/marmot.h#L5791)

### `marmot_create_identity`

```c
MarmotStatus marmot_create_identity(const struct MarmotClient *client, const char *const *default_relays, uintptr_t default_relays_len, const char *const *bootstrap_relays, uintptr_t bootstrap_relays_len, struct MarmotAccountSummary **out);
```

Create a brand-new Nostr identity, store its secret in the account secret store, and publish initial relay lists + key package. Free with `marmot_account_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotcreate_identity) · [Header contract](include/marmot.h#L5804)

### `marmot_create_group`

```c
MarmotStatus marmot_create_group(const struct MarmotClient *client, const char *account_ref, const char *name, const char *const *member_refs, uintptr_t member_refs_len, const char *description, char **out);
```

Create a new MLS group with `name` and the given members (referenced by `npub` or hex account id). Writes the new group id as a hex string; free it with `marmot_string_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotcreate_group) · [Header contract](include/marmot.h#L6092)

### `marmot_confirm_group_rejoin`

```c
MarmotStatus marmot_confirm_group_rejoin(const struct MarmotClient *client, const char *account_ref, const char *welcome_id_hex, const char *local_state_token, struct MarmotGroupRecoveryStatus **out);
```

Only after explicit recipient consent. Free with marmot_group_recovery_status_free.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotconfirm_group_rejoin) · [Header contract](include/marmot.h#L6289)

### `marmot_catch_up_accounts`

```c
MarmotStatus marmot_catch_up_accounts(const struct MarmotClient *client);
```

One-time catch-up across every running account (e.g. after a push wake).

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotcatch_up_accounts) · [Header contract](include/marmot.h#L6784)

### `marmot_clear_push_registration`

```c
MarmotStatus marmot_clear_push_registration(const struct MarmotClient *client, const char *account_ref, struct MarmotPushRegistrationShareOutcome **out);
```

Remove the account's push registration and share the removal. Free with `marmot_push_registration_share_outcome_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotclear_push_registration) · [Header contract](include/marmot.h#L6855)

### `marmot_chat_list`

```c
MarmotStatus marmot_chat_list(const struct MarmotClient *client, const char *account_ref, uint8_t include_archived, struct MarmotChatListRowList **out);
```

The account's chat list rows. Free with `marmot_chat_list_row_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotchat_list) · [Header contract](include/marmot.h#L6991)

### `marmot_chat_notification_settings`

```c
MarmotStatus marmot_chat_notification_settings(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotChatNotificationSettings **out);
```

The conversation's local mute state. Free with `marmot_chat_notification_settings_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotchat_notification_settings) · [Header contract](include/marmot.h#L7116)

### `marmot_clear_chat_muted`

```c
MarmotStatus marmot_clear_chat_muted(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotChatNotificationSettings **out);
```

Unmute a conversation. Free with `marmot_chat_notification_settings_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotclear_chat_muted) · [Header contract](include/marmot.h#L7149)

### `marmot_chat_list_row`

```c
MarmotStatus marmot_chat_list_row(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotChatListRow **out);
```

The durable chat-list row for one group; writes NULL with `MARMOT_STATUS_OK` when the group has no row. Free with `marmot_chat_list_row_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotchat_list_row) · [Header contract](include/marmot.h#L7424)

### `marmot_clear_group_image`

```c
MarmotStatus marmot_clear_group_image(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotSendSummary **out);
```

Clear the group's encrypted Blossom avatar by committing the absent image component. Requires admin. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotclear_group_image) · [Header contract](include/marmot.h#L7468)

### `marmot_client_shutdown_and_close`

```c
MarmotStatus marmot_client_shutdown_and_close(const struct MarmotClient *client);
```

Shut the runtime down and release every local file lock, so a host can suspend without leaving the database leased. The client handle stays valid but the runtime is finished.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotshutdown_and_close) · [Header contract](include/marmot.h#L7607)

### `marmot_create_identity_with_profile`

```c
MarmotStatus marmot_create_identity_with_profile(const struct MarmotClient *client, const char *const *default_relays, uintptr_t default_relays_len, const char *const *bootstrap_relays, uintptr_t bootstrap_relays_len, struct MarmotIdentityCreationResult **out);
```

Create a fresh identity and publish a default profile in one step. Free with `marmot_identity_creation_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotcreate_identity_with_profile) · [Header contract](include/marmot.h#L7632)

### `marmot_cached_identity_projections`

```c
MarmotStatus marmot_cached_identity_projections(const struct MarmotClient *client, const char *const *account_id_hexes, uintptr_t account_id_hexes_len, struct MarmotCachedIdentityProjectionList **out);
```

What the local directory cache holds for each requested id, one row per request in order. Free with `marmot_cached_identity_projection_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotcached_identity_projections) · [Header contract](include/marmot.h#L7684)

### `marmot_create_group_detailed`

```c
MarmotStatus marmot_create_group_detailed(const struct MarmotClient *client, const char *account_ref, const char *name, const char *const *member_refs, uintptr_t member_refs_len, const char *description, struct MarmotCreatedGroup **out);
```

`marmot_create_group` plus the new chat-list row in one round trip. Free with `marmot_created_group_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotcreate_group_detailed) · [Header contract](include/marmot.h#L7747)

### `marmot_create_group_with_prepared_initial_image`

```c
MarmotStatus marmot_create_group_with_prepared_initial_image(const struct MarmotClient *client, const char *account_ref, const char *name, const char *const *member_refs, uintptr_t member_refs_len, const char *description, const char *upload_id, char **out);
```

Create a group whose avatar is an already-staged prepared image. Writes the new group id as a hex string; free it with `marmot_string_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotcreate_group_with_prepared_initial_image) · [Header contract](include/marmot.h#L7857)

### `marmot_collect_notifications_after_wake`

```c
MarmotStatus marmot_collect_notifications_after_wake(const struct MarmotClient *client, uint32_t max_wait_ms, uint32_t source, struct MarmotBackgroundNotificationCollection **out);
```

Run a bounded background collection pass after a push wake. `source` is a `MarmotNotificationWakeSource` discriminant; out-of-range values are rejected with `MARMOT_STATUS_INVALID_ARGUMENT`. Free with `marmot_background_notification_collection_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotcollect_notifications_after_wake) · [Header contract](include/marmot.h#L8229)

### `marmot_create_group_with_options`

```c
MarmotStatus marmot_create_group_with_options(const struct MarmotClient *client, const char *account_ref, const char *name, const char *const *member_refs, uintptr_t member_refs_len, const struct MarmotCreateGroupOptions *options, char **out);
```

Create a group with the options struct: description, an optional initial avatar, and disappearing-message retention. Writes the new group id as a hex string; free it with `marmot_string_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotcreate_group_with_options) · [Header contract](include/marmot.h#L8353)

### `marmot_create_group_with_options_detailed`

```c
MarmotStatus marmot_create_group_with_options_detailed(const struct MarmotClient *client, const char *account_ref, const char *name, const char *const *member_refs, uintptr_t member_refs_len, const struct MarmotCreateGroupOptions *options, struct MarmotCreatedGroup **out);
```

`marmot_create_group_with_options` plus the new chat-list row in one round trip. Free with `marmot_created_group_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotcreate_group_with_options_detailed) · [Header contract](include/marmot.h#L8368)

### `marmot_create_group_with_initial_image`

```c
MarmotStatus marmot_create_group_with_initial_image(const struct MarmotClient *client, const char *account_ref, const char *name, const char *const *member_refs, uintptr_t member_refs_len, const char *description, const struct MarmotInitialGroupImage *initial_image, char **out);
```

Create a group with an inline initial avatar. `initial_image` may be NULL for no image. Writes the new group id as a hex string; free it with `marmot_string_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotcreate_group_with_initial_image) · [Header contract](include/marmot.h#L8387)

### `marmot_create_group_with_initial_image_detailed`

```c
MarmotStatus marmot_create_group_with_initial_image_detailed(const struct MarmotClient *client, const char *account_ref, const char *name, const char *const *member_refs, uintptr_t member_refs_len, const char *description, const struct MarmotInitialGroupImage *initial_image, struct MarmotCreatedGroup **out);
```

`marmot_create_group_with_initial_image` plus the new chat-list row in one round trip. Free with `marmot_created_group_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotcreate_group_with_initial_image_detailed) · [Header contract](include/marmot.h#L8403)

### `marmot_classify_relay_endpoints`

```c
MarmotStatus marmot_classify_relay_endpoints(const struct MarmotClient *client, const char *const *endpoints, uintptr_t endpoints_len, struct MarmotRelayEndpointClassificationList **out);
```

Classify relay endpoints against the dial-safety and retired-relay policies without dialing any of them. Free with `marmot_relay_endpoint_classification_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotclassify_relay_endpoints) · [Header contract](include/marmot.h#L8519)

### `marmot_continue_onboarding_without`

```c
MarmotStatus marmot_continue_onboarding_without(const struct MarmotClient *client, const char *account_ref, uint32_t step, struct MarmotOnboardingSnapshot **out);
```

Explicitly skip an optional profile or follows step when offered. `step` is a MarmotOnboardingStep discriminant; out-of-range values return MARMOT_STATUS_INVALID_ARGUMENT. Free the returned snapshot with `marmot_onboarding_snapshot_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotcontinue_onboarding_without) · [Header contract](include/marmot.h#L8603)

### `marmot_cancel_onboarding_repair`

```c
MarmotStatus marmot_cancel_onboarding_repair(const struct MarmotClient *client, const char *account_ref, struct MarmotOnboardingSnapshot **out);
```

Dismiss an unapproved repair proposal; an approved repair must be resumed. Free the returned snapshot with `marmot_onboarding_snapshot_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotcancel_onboarding_repair) · [Header contract](include/marmot.h#L8690)

### `marmot_content_reports`

```c
MarmotStatus marmot_content_reports(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *message_id, const char *after, uint32_t limit, struct MarmotContentReportPage **out);
```

# Safety `client` must be a live handle; string arguments must be valid NUL-terminated strings (nullable ones may be NULL); array arguments must hold their stated length (or be NULL with length 0); out-pointers must be valid.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotcontent_reports) · [Header contract](include/marmot.h#L8831)

### `marmot_chats_subscription_next`

```c
MarmotStatus marmot_chats_subscription_next(const struct MarmotChatsSubscription *sub, uint32_t timeout_ms, struct MarmotAppGroupRecord **out);
```

Block until the next item, the timeout, or stream close. `timeout_ms == 0` waits indefinitely. Returns `MARMOT_STATUS_OK` (out set; free with `marmot_app_group_record_free`), `MARMOT_STATUS_TIMEOUT`, or `MARMOT_STATUS_CLOSED` (out NULL for both).

[Header contract](include/marmot.h#L9200)

### `marmot_chats_subscription_set_callback`

```c
MarmotStatus marmot_chats_subscription_set_callback(const struct MarmotChatsSubscription *sub, MarmotAppGroupRecordCallback callback, void *user_data);
```

Install a callback pump for this subscription. `callback` runs on a runtime worker thread with a borrowed item pointer (valid only during the call; do not store or free it) and a final NULL item on close. `callback` and `user_data` access must be thread-safe. Fails if a callback is already installed.

[Header contract](include/marmot.h#L9217)

### `marmot_chats_subscription_clear_callback`

```c
MarmotStatus marmot_chats_subscription_clear_callback(const struct MarmotChatsSubscription *sub);
```

Request cancellation of this subscription's callback pump, if any. Non-blocking: a callback already running keeps executing after this returns (see the module docs).

[Header contract](include/marmot.h#L9229)

### `marmot_chats_subscription_free`

```c
void marmot_chats_subscription_free(struct MarmotChatsSubscription *sub);
```

Free the subscription handle. Requests callback-pump cancellation without waiting (a callback may still be running after this returns — do not free `user_data` on that basis). NULL is a no-op. Free every handle before the client that created it.

[Header contract](include/marmot.h#L9241)

### `marmot_chats_subscription_snapshot`

```c
MarmotStatus marmot_chats_subscription_snapshot(const struct MarmotChatsSubscription *sub, struct MarmotAppGroupRecordList **out_list);
```

Take the initial chats snapshot. Yields the populated list exactly once: later calls write an EMPTY list, still with `MARMOT_STATUS_OK`. Free the list with `marmot_app_group_record_list_free`.

[Header contract](include/marmot.h#L9265)

### `marmot_chat_list_subscription_next`

```c
MarmotStatus marmot_chat_list_subscription_next(const struct MarmotChatListSubscription *sub, uint32_t timeout_ms, struct MarmotChatListRow **out);
```

Block until the next item, the timeout, or stream close. `timeout_ms == 0` waits indefinitely. Returns `MARMOT_STATUS_OK` (out set; free with `marmot_chat_list_row_free`), `MARMOT_STATUS_TIMEOUT`, or `MARMOT_STATUS_CLOSED` (out NULL for both).

[Header contract](include/marmot.h#L9274)

### `marmot_chat_list_subscription_set_callback`

```c
MarmotStatus marmot_chat_list_subscription_set_callback(const struct MarmotChatListSubscription *sub, MarmotChatListRowCallback callback, void *user_data);
```

Install a callback pump for this subscription. `callback` runs on a runtime worker thread with a borrowed item pointer (valid only during the call; do not store or free it) and a final NULL item on close. `callback` and `user_data` access must be thread-safe. Fails if a callback is already installed.

[Header contract](include/marmot.h#L9291)

### `marmot_chat_list_subscription_clear_callback`

```c
MarmotStatus marmot_chat_list_subscription_clear_callback(const struct MarmotChatListSubscription *sub);
```

Request cancellation of this subscription's callback pump, if any. Non-blocking: a callback already running keeps executing after this returns (see the module docs).

[Header contract](include/marmot.h#L9303)

### `marmot_chat_list_subscription_free`

```c
void marmot_chat_list_subscription_free(struct MarmotChatListSubscription *sub);
```

Free the subscription handle. Requests callback-pump cancellation without waiting (a callback may still be running after this returns — do not free `user_data` on that basis). NULL is a no-op. Free every handle before the client that created it.

[Header contract](include/marmot.h#L9315)

### `marmot_chat_list_subscription_snapshot`

```c
MarmotStatus marmot_chat_list_subscription_snapshot(const struct MarmotChatListSubscription *sub, struct MarmotChatListRowList **out_list);
```

Take the initial chat-list snapshot. Yields the populated list exactly once: later calls write an EMPTY list, still with `MARMOT_STATUS_OK`. Free with `marmot_chat_list_row_list_free`.

[Header contract](include/marmot.h#L9338)

### `marmot_chat_list_subscription_next_update`

```c
MarmotStatus marmot_chat_list_subscription_next_update(const struct MarmotChatListSubscription *sub, uint32_t timeout_ms, struct MarmotChatListSubscriptionUpdate **out_update);
```

Block until the next raw chat-list delta (row upsert or removal). Free with `marmot_chat_list_subscription_update_free`.

[Header contract](include/marmot.h#L9348)

### `marmot_chat_list_window_subscription_snapshot`

```c
MarmotStatus marmot_chat_list_window_subscription_snapshot(const struct MarmotChatListWindowSubscription *sub, struct MarmotChatListWindowSnapshot **out);
```

Take the initial snapshot once; a second call returns CLOSED. Result must be deep-freed. # Safety sub must be live and out writable.

[Header contract](include/marmot.h#L9868)

### `marmot_chat_list_window_subscription_next`

```c
MarmotStatus marmot_chat_list_window_subscription_next(const struct MarmotChatListWindowSubscription *sub, uint32_t timeout_ms, struct MarmotChatListWindowSnapshot **out);
```

Receive a complete replacement. Zero timeout waits indefinitely. Timeout/error/closed leaves out NULL. Timeout does not consume an update. Free results with the matching snapshot_free. # Safety sub must remain live throughout the call; out must be writable. Use one receiver per handle.

[Header contract](include/marmot.h#L9877)

### `marmot_chat_list_window_subscription_free`

```c
void marmot_chat_list_window_subscription_free(struct MarmotChatListWindowSubscription *sub);
```

Cancel and free. NULL is a no-op; does not free previously returned snapshots. # Safety sub must be NULL or a library-owned handle with no active calls.

[Header contract](include/marmot.h#L9886)

### `marmot_chat_list_window_subscription_page`

```c
MarmotStatus marmot_chat_list_window_subscription_page(const struct MarmotChatListWindowSubscription *sub, uint64_t sequence, uint32_t direction, uint32_t count, struct MarmotChatListWindowSnapshot **out);
```

Apply a window command against the installed sequence, returning a complete replacement. May run while next waits. Stale sequence returns CHAT_WINDOW_STALE; refresh before retrying. The same completion also arrives through next; deduplicate by generation/sequence. # Safety sub must be live, any input string valid, and out writable. Never free during a call.

[Header contract](include/marmot.h#L9940)

### `marmot_chat_list_window_subscription_set_visible_anchor`

```c
MarmotStatus marmot_chat_list_window_subscription_set_visible_anchor(const struct MarmotChatListWindowSubscription *sub, uint64_t sequence, const char *group_id_hex, struct MarmotChatListWindowSnapshot **out);
```

Apply a window command against the installed sequence, returning a complete replacement. May run while next waits. Stale sequence returns CHAT_WINDOW_STALE; refresh before retrying. The same completion also arrives through next; deduplicate by generation/sequence. # Safety sub must be live, any input string valid, and out writable. Never free during a call.

[Header contract](include/marmot.h#L9953)

### `marmot_chat_list_window_subscription_return_to_top`

```c
MarmotStatus marmot_chat_list_window_subscription_return_to_top(const struct MarmotChatListWindowSubscription *sub, uint64_t sequence, struct MarmotChatListWindowSnapshot **out);
```

Apply a window command against the installed sequence, returning a complete replacement. May run while next waits. Stale sequence returns CHAT_WINDOW_STALE; refresh before retrying. The same completion also arrives through next; deduplicate by generation/sequence. # Safety sub must be live, any input string valid, and out writable. Never free during a call.

[Header contract](include/marmot.h#L9965)

### `marmot_conversation_window_subscription_snapshot`

```c
MarmotStatus marmot_conversation_window_subscription_snapshot(const struct MarmotConversationWindowSubscription *sub, struct MarmotConversationWindowSnapshot **out);
```

Take the initial snapshot once; a second call returns CLOSED. Result must be deep-freed. # Safety sub must be live and out writable.

[Header contract](include/marmot.h#L9974)

### `marmot_conversation_window_subscription_next`

```c
MarmotStatus marmot_conversation_window_subscription_next(const struct MarmotConversationWindowSubscription *sub, uint32_t timeout_ms, struct MarmotConversationWindowSnapshot **out);
```

Receive a complete replacement. Zero timeout waits indefinitely. Timeout/error/closed leaves out NULL. Timeout does not consume an update. Free results with the matching snapshot_free. # Safety sub must remain live throughout the call; out must be writable. Use one receiver per handle.

[Header contract](include/marmot.h#L9983)

### `marmot_conversation_window_subscription_free`

```c
void marmot_conversation_window_subscription_free(struct MarmotConversationWindowSubscription *sub);
```

Cancel and free. NULL is a no-op; does not free previously returned snapshots. # Safety sub must be NULL or a library-owned handle with no active calls.

[Header contract](include/marmot.h#L9992)

### `marmot_conversation_window_subscription_cancel`

```c
MarmotStatus marmot_conversation_window_subscription_cancel(const struct MarmotConversationWindowSubscription *sub);
```

Close and wake pending receivers/commands. Idempotent; does not free this handle or snapshots. # Safety sub must remain live throughout all calls; free only after active calls return.

[Header contract](include/marmot.h#L9999)

### `marmot_conversation_window_subscription_page`

```c
MarmotStatus marmot_conversation_window_subscription_page(const struct MarmotConversationWindowSubscription *sub, const struct MarmotConversationWindowRevision *revision, uint32_t direction, uint32_t count, uint32_t timeout_ms, struct MarmotConversationWindowSnapshot **out);
```

Apply against the installed revision. May run while next waits; deduplicate completions by generation/sequence. Zero timeout uses 30 seconds. Accepted commands may complete after timeout through next; refresh before retrying. Extend history around the visible anchor; paging preserves that anchor at the retained-row cap. # Safety sub and borrowed revision/strings must remain live; out writable. Never free during a call.

[Header contract](include/marmot.h#L10025)

### `marmot_conversation_window_subscription_set_visible_anchor`

```c
MarmotStatus marmot_conversation_window_subscription_set_visible_anchor(const struct MarmotConversationWindowSubscription *sub, const struct MarmotConversationWindowRevision *revision, const char *message_id_hex, uint32_t timeout_ms, struct MarmotConversationWindowSnapshot **out);
```

Apply against the installed revision. May run while next waits; deduplicate completions by generation/sequence. Zero timeout uses 30 seconds. Accepted commands may complete after timeout through next; refresh before retrying. Report a row in the installed window as the visible anchor; this does not acknowledge reads or encode pixel offsets. # Safety sub and borrowed revision/strings must remain live; out writable. Never free during a call.

[Header contract](include/marmot.h#L10040)

### `marmot_conversation_window_subscription_jump_to_message`

```c
MarmotStatus marmot_conversation_window_subscription_jump_to_message(const struct MarmotConversationWindowSubscription *sub, const struct MarmotConversationWindowRevision *revision, const char *message_id_hex, uint32_t timeout_ms, struct MarmotConversationWindowSnapshot **out);
```

Apply against the installed revision. May run while next waits; deduplicate completions by generation/sequence. Zero timeout uses 30 seconds. Accepted commands may complete after timeout through next; refresh before retrying. Center the window on a retained message; a missing target fails explicitly. # Safety sub and borrowed revision/strings must remain live; out writable. Never free during a call.

[Header contract](include/marmot.h#L10054)

### `marmot_conversation_window_subscription_return_to_latest`

```c
MarmotStatus marmot_conversation_window_subscription_return_to_latest(const struct MarmotConversationWindowSubscription *sub, const struct MarmotConversationWindowRevision *revision, uint32_t timeout_ms, struct MarmotConversationWindowSnapshot **out);
```

Apply against the installed revision. May run while next waits; deduplicate completions by generation/sequence. Zero timeout uses 30 seconds. Accepted commands may complete after timeout through next; refresh before retrying. Move to the latest message and resume following arrivals, retaining the current row budget. # Safety sub and borrowed revision/strings must remain live; out writable. Never free during a call.

[Header contract](include/marmot.h#L10068)

### `marmot_clear_message_draft_if_revision`

```c
MarmotStatus marmot_clear_message_draft_if_revision(const struct MarmotClient *client, const char *account_ref, const struct MarmotMessageDraftRevision *revision, struct MarmotSelectedMessageDraft **out);
```

Clear only this selected revision; later edits are preserved. # Safety client, account and revision valid; revision's owning snapshot/draft must remain live; out writable.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotclear_message_draft_if_revision) · [Header contract](include/marmot.h#L10088)

### `marmot_chat_pin_state_free`

```c
void marmot_chat_pin_state_free(struct MarmotChatPinState *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10370)

### `marmot_chat_notification_settings_free`

```c
void marmot_chat_notification_settings_free(struct MarmotChatNotificationSettings *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10380)

### `marmot_chat_list_row_free`

```c
void marmot_chat_list_row_free(struct MarmotChatListRow *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10390)

### `marmot_chat_list_row_list_free`

```c
void marmot_chat_list_row_list_free(struct MarmotChatListRowList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10399)

### `marmot_chat_list_subscription_update_free`

```c
void marmot_chat_list_subscription_update_free(struct MarmotChatListSubscriptionUpdate *update);
```

Free a chat-list delta returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10407)

### `marmot_cached_identity_projection_free`

```c
void marmot_cached_identity_projection_free(struct MarmotCachedIdentityProjection *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10435)

### `marmot_cached_identity_projection_list_free`

```c
void marmot_cached_identity_projection_list_free(struct MarmotCachedIdentityProjectionList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10444)

### `marmot_created_group_free`

```c
void marmot_created_group_free(struct MarmotCreatedGroup *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10626)

### `marmot_chat_list_window_snapshot_free`

```c
void marmot_chat_list_window_snapshot_free(struct MarmotChatListWindowSnapshot *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L11088)

### `marmot_conversation_window_snapshot_free`

```c
void marmot_conversation_window_snapshot_free(struct MarmotConversationWindowSnapshot *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L11118)

### `marmot_content_report_page_free`

```c
void marmot_content_report_page_free(struct MarmotContentReportPage *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L11185)

### `marmot_control_attachment`

```c
MarmotStatus marmot_control_attachment(const struct MarmotClient *client, const char *account_ref, const char *reference, uint32_t control, bool *out);
```

Apply a MarmotAttachmentControl discriminant to an opaque reference. # Safety Client/strings must be live and out writable. No inputs are retained.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotcontrol_attachment) · [Header contract](include/marmot.h#L11240)

</details>

<details>
<summary>marmot_d…</summary>

### `marmot_delete_account_key_package`

```c
MarmotStatus marmot_delete_account_key_package(const struct MarmotClient *client, const char *account_ref, const char *event_id_hex, const char *const *relays, uintptr_t relays_len, uint64_t *out);
```

Publish a NIP-09 deletion for a KeyPackage event. Writes the accepting-relay count.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotdelete_account_key_package) · [Header contract](include/marmot.h#L6007)

### `marmot_delete_group_local`

```c
MarmotStatus marmot_delete_group_local(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, bool *out);
```

Delete this group's local app data without an MLS leave. Cancel active UI subscriptions for the group first. MLS state stays intact; a future fresh delivery can recreate a chat row. Writes true if any local rows or a live route were removed.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotdelete_group_local) · [Header contract](include/marmot.h#L6226)

### `marmot_decline_group_rejoin`

```c
MarmotStatus marmot_decline_group_rejoin(const struct MarmotClient *client, const char *account_ref, const char *welcome_id_hex);
```

Decline the selected replacement offer without changing active group state.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotdecline_group_rejoin) · [Header contract](include/marmot.h#L6304)

### `marmot_decline_group_invite`

```c
MarmotStatus marmot_decline_group_invite(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotGroupInviteDeclineResult **out);
```

Decline a pending group invite; writes the updated group record plus the decline publish summary. Free with `marmot_group_invite_decline_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotdecline_group_invite) · [Header contract](include/marmot.h#L6334)

### `marmot_download_group_blossom_image`

```c
MarmotStatus marmot_download_group_blossom_image(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, uint8_t **out_data, uintptr_t *out_len);
```

Fetch, verify, and decrypt the group's Blossom-hosted encrypted image. Needs a relay/Blossom, so it fails offline. Free the buffer with `marmot_bytes_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotdownload_group_blossom_image) · [Header contract](include/marmot.h#L6386)

### `marmot_demote_admin`

```c
MarmotStatus marmot_demote_admin(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *member_ref, struct MarmotSendSummary **out);
```

Revoke `member_ref`'s admin rights. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotdemote_admin) · [Header contract](include/marmot.h#L6418)

### `marmot_demote_admin_detailed`

```c
MarmotStatus marmot_demote_admin_detailed(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *member_ref, struct MarmotGroupMutationResult **out);
```

`marmot_demote_admin` plus refreshed details and management state. Free with `marmot_group_mutation_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotdemote_admin_detailed) · [Header contract](include/marmot.h#L6500)

### `marmot_delete_message`

```c
MarmotStatus marmot_delete_message(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *target_message_id, struct MarmotSendSummary **out);
```

Request deletion of an own message. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotdelete_message) · [Header contract](include/marmot.h#L6736)

### `marmot_delete_audit_log_file`

```c
MarmotStatus marmot_delete_audit_log_file(const struct MarmotClient *client, const char *path, struct MarmotAuditLogDeleteResult **out);
```

Delete one on-disk audit-log file. Free with `marmot_audit_log_delete_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotdelete_audit_log_file) · [Header contract](include/marmot.h#L6964)

### `marmot_download_profile_image`

```c
MarmotStatus marmot_download_profile_image(const struct MarmotClient *client, const char *url, uint64_t max_bytes, uint8_t **out_data, uintptr_t *out_len);
```

Fetch a profile image by URL, refusing anything over `max_bytes`. Free the buffer with `marmot_bytes_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotdownload_profile_image) · [Header contract](include/marmot.h#L7407)

### `marmot_delete_message_draft`

```c
MarmotStatus marmot_delete_message_draft(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex);
```

Discard the stored draft for a conversation. Absent is not an error.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotdelete_message_draft) · [Header contract](include/marmot.h#L7453)

### `marmot_disband_group`

```c
MarmotStatus marmot_disband_group(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotDisbandRequest **out);
```

Request terminal disbanding of the group. Writes this account's durable request outcome; free it with `marmot_disband_request_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotdisband_group) · [Header contract](include/marmot.h#L7500)

### `marmot_display_name`

```c
MarmotStatus marmot_display_name(const struct MarmotClient *client, const char *account_id_hex, char **out);
```

Best-effort display name for an account id from the local directory cache; writes NULL with `MARMOT_STATUS_OK` when unknown. Free with `marmot_string_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotdisplay_name) · [Header contract](include/marmot.h#L7960)

### `marmot_default_profile_pseudonym`

```c
MarmotStatus marmot_default_profile_pseudonym(const struct MarmotClient *client, const char *account_id_hex, char **out);
```

Deterministic cosmetic display name for a canonical hex account id. Free with `marmot_string_free`. Decode a scanned reference with `marmot_account_id_hex` first; the seed is hashed as supplied text.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotdefault_profile_pseudonym) · [Header contract](include/marmot.h#L7999)

### `marmot_download_media`

```c
MarmotStatus marmot_download_media(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const struct MarmotMediaAttachmentReference *reference, struct MarmotMediaDownloadResult **out);
```

Download, verify, and decrypt one attachment. Free with `marmot_media_download_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotdownload_media) · [Header contract](include/marmot.h#L8183)

### `marmot_dismiss_reports`

```c
MarmotStatus marmot_dismiss_reports(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *const *report_ids, uintptr_t report_ids_len, const char *explanation, struct MarmotSendSummary **out);
```

# Safety `client` must be a live handle; string arguments must be valid NUL-terminated strings (nullable ones may be NULL); array arguments must hold their stated length (or be NULL with length 0); out-pointers must be valid.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotdismiss_reports) · [Header contract](include/marmot.h#L8801)

### `marmot_disband_request_free`

```c
void marmot_disband_request_free(struct MarmotDisbandRequest *request);
```

Free a disband request returned by `marmot_disband_group`. NULL is a no-op. (Embedded copies inside a chat row are released by the row.)

[Header contract](include/marmot.h#L10509)

### `marmot_download_attachment_again`

```c
MarmotStatus marmot_download_attachment_again(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const struct MarmotAttachmentLocalTarget *target, char **out);
```

Explicitly request the current slot, including after cancellation/removal. NULL result is unavailable. # Safety Client, strings and target must be live; out writable. Free returned string with marmot_string_free.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotdownload_attachment_again) · [Header contract](include/marmot.h#L11251)

</details>

<details>
<summary>marmot_e…</summary>

### `marmot_export_encrypted_secret_key`

```c
MarmotStatus marmot_export_encrypted_secret_key(const struct MarmotClient *client, const char *account_ref, const char *passphrase, char **out);
```

Export the account's private key NIP-49-encrypted under `passphrase`. Free with `marmot_string_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotexport_encrypted_secret_key) · [Header contract](include/marmot.h#L6076)

### `marmot_edit_message`

```c
MarmotStatus marmot_edit_message(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *target_message_id, const char *content, struct MarmotSendSummary **out);
```

Edit an own message's content. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotedit_message) · [Header contract](include/marmot.h#L6752)

### `marmot_enable_group_disbanding`

```c
MarmotStatus marmot_enable_group_disbanding(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotGroupMutationResult **out);
```

Opt the group into disbanding, so a later `marmot_disband_group` is accepted. Requires admin. Free with `marmot_group_mutation_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotenable_group_disbanding) · [Header contract](include/marmot.h#L7484)

### `marmot_existing_direct_conversation`

```c
MarmotStatus marmot_existing_direct_conversation(const struct MarmotClient *client, const char *account_ref, const char *peer_account_id, struct MarmotExistingDirectConversation **out);
```

The existing one-to-one conversation with `peer_account_id`, or NULL with `MARMOT_STATUS_OK` when there is none. Check `reusable` before opening it. Free with `marmot_existing_direct_conversation_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotexisting_direct_conversation) · [Header contract](include/marmot.h#L7651)

### `marmot_events_subscription_next`

```c
MarmotStatus marmot_events_subscription_next(const struct MarmotEventsSubscription *sub, uint32_t timeout_ms, struct MarmotEvent **out);
```

Block until the next item, the timeout, or stream close. `timeout_ms == 0` waits indefinitely. Returns `MARMOT_STATUS_OK` (out set; free with `marmot_event_free`), `MARMOT_STATUS_TIMEOUT`, or `MARMOT_STATUS_CLOSED` (out NULL for both).

[Header contract](include/marmot.h#L8969)

### `marmot_events_subscription_set_callback`

```c
MarmotStatus marmot_events_subscription_set_callback(const struct MarmotEventsSubscription *sub, MarmotEventCallback callback, void *user_data);
```

Install a callback pump for this subscription. `callback` runs on a runtime worker thread with a borrowed item pointer (valid only during the call; do not store or free it) and a final NULL item on close. `callback` and `user_data` access must be thread-safe. Fails if a callback is already installed.

[Header contract](include/marmot.h#L8986)

### `marmot_events_subscription_clear_callback`

```c
MarmotStatus marmot_events_subscription_clear_callback(const struct MarmotEventsSubscription *sub);
```

Request cancellation of this subscription's callback pump, if any. Non-blocking: a callback already running keeps executing after this returns (see the module docs).

[Header contract](include/marmot.h#L8998)

### `marmot_events_subscription_free`

```c
void marmot_events_subscription_free(struct MarmotEventsSubscription *sub);
```

Free the subscription handle. Requests callback-pump cancellation without waiting (a callback may still be running after this returns — do not free `user_data` on that basis). NULL is a no-op. Free every handle before the client that created it.

[Header contract](include/marmot.h#L9010)

### `marmot_existing_direct_conversation_free`

```c
void marmot_existing_direct_conversation_free(struct MarmotExistingDirectConversation *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10360)

### `marmot_event_free`

```c
void marmot_event_free(struct MarmotEvent *event);
```

Free an event returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10500)

</details>

<details>
<summary>marmot_f…</summary>

### `marmot_forget_group_local`

```c
MarmotStatus marmot_forget_group_local(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, bool *out);
```

Reset this group on this account-device without publishing. Deletes local app and MLS state; only a valid Welcome created after the reset can rejoin. Close group UI subscriptions and clear host-owned media caches first. Writes true for a new forget, false if already forgotten.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotforget_group_local) · [Header contract](include/marmot.h#L6243)

### `marmot_follow_user`

```c
MarmotStatus marmot_follow_user(const struct MarmotClient *client, const char *account_ref, const char *user_ref, struct MarmotStringList **out);
```

Follow `user_ref` and publish the updated list. Writes the new follow set. Free with `marmot_string_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotfollow_user) · [Header contract](include/marmot.h#L7343)

### `marmot_flush_product_analytics`

```c
MarmotStatus marmot_flush_product_analytics(const struct MarmotClient *client);
```

# Safety `client` must be a live handle; string arguments must be valid NUL-terminated strings (nullable ones may be NULL); array arguments must hold their stated length (or be NULL with length 0); out-pointers must be valid.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotflush_product_analytics) · [Header contract](include/marmot.h#L8736)

</details>

<details>
<summary>marmot_g…</summary>

### `marmot_group_members`

```c
MarmotStatus marmot_group_members(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotAppGroupMemberRecordList **out);
```

Membership roster for `group_id_hex`. Free with `marmot_app_group_member_record_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotgroup_members) · [Header contract](include/marmot.h#L6129)

### `marmot_group_details`

```c
MarmotStatus marmot_group_details(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotGroupDetails **out);
```

Group plus enriched member rows for detail screens. Free with `marmot_group_details_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotgroup_details) · [Header contract](include/marmot.h#L6144)

### `marmot_group_management_state`

```c
MarmotStatus marmot_group_management_state(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotGroupManagementState **out);
```

Current caller permissions plus per-member action availability. Free with `marmot_group_management_state_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotgroup_management_state) · [Header contract](include/marmot.h#L6159)

### `marmot_group_recovery_status`

```c
MarmotStatus marmot_group_recovery_status(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotGroupRecoveryStatus **out);
```

Query advisory membership health and pending rejoin offers. Free with `marmot_group_recovery_status_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotgroup_recovery_status) · [Header contract](include/marmot.h#L6275)

### `marmot_group_mls_state`

```c
MarmotStatus marmot_group_mls_state(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotAppGroupMlsState **out);
```

Current MLS state (epoch, member count, required components) for the conversation developer/debug view. Free with `marmot_app_group_mls_state_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotgroup_mls_state) · [Header contract](include/marmot.h#L6532)

### `marmot_group_push_debug_info`

```c
MarmotStatus marmot_group_push_debug_info(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotGroupPushDebugInfo **out);
```

Per-group push token debug info. Free with `marmot_group_push_debug_info_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotgroup_push_debug_info) · [Header contract](include/marmot.h#L6869)

### `marmot_get_blocked_users`

```c
MarmotStatus marmot_get_blocked_users(const struct MarmotClient *client, const char *account_ref, struct MarmotBlockedUserList **out);
```

Read the local blocked-user list, newest first. Free with `marmot_blocked_user_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotget_blocked_users) · [Header contract](include/marmot.h#L7287)

### `marmot_group_member_ids_page`

```c
MarmotStatus marmot_group_member_ids_page(const struct MarmotClient *client, const char *account_ref, const char *const *group_ids_hex, uintptr_t group_ids_hex_len, struct MarmotAppGroupMemberIdsList **out);
```

Member and admin ids for several groups in one read. Free with `marmot_app_group_member_ids_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotgroup_member_ids_page) · [Header contract](include/marmot.h#L7765)

### `marmot_group_conversation_snapshot`

```c
MarmotStatus marmot_group_conversation_snapshot(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotGroupConversationSnapshot **out);
```

Group details and management state in one read. Free with `marmot_group_conversation_snapshot_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotgroup_conversation_snapshot) · [Header contract](include/marmot.h#L7781)

### `marmot_group_roster`

```c
MarmotStatus marmot_group_roster(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotGroupRoster **out);
```

The group's member roster at the current MLS epoch. Free with `marmot_group_roster_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotgroup_roster) · [Header contract](include/marmot.h#L7796)

### `marmot_group_maintenance_status`

```c
MarmotStatus marmot_group_maintenance_status(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotGroupMaintenanceStatus **out);
```

One group's maintenance state. Free with `marmot_group_maintenance_status_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotgroup_maintenance_status) · [Header contract](include/marmot.h#L7876)

### `marmot_group_state_subscription_next`

```c
MarmotStatus marmot_group_state_subscription_next(const struct MarmotGroupStateSubscription *sub, uint32_t timeout_ms, struct MarmotAppGroupRecord **out);
```

Block until the next item, the timeout, or stream close. `timeout_ms == 0` waits indefinitely. Returns `MARMOT_STATUS_OK` (out set; free with `marmot_app_group_record_free`), `MARMOT_STATUS_TIMEOUT`, or `MARMOT_STATUS_CLOSED` (out NULL for both).

[Header contract](include/marmot.h#L9439)

### `marmot_group_state_subscription_set_callback`

```c
MarmotStatus marmot_group_state_subscription_set_callback(const struct MarmotGroupStateSubscription *sub, MarmotGroupStateRecordCallback callback, void *user_data);
```

Install a callback pump for this subscription. `callback` runs on a runtime worker thread with a borrowed item pointer (valid only during the call; do not store or free it) and a final NULL item on close. `callback` and `user_data` access must be thread-safe. Fails if a callback is already installed.

[Header contract](include/marmot.h#L9456)

### `marmot_group_state_subscription_clear_callback`

```c
MarmotStatus marmot_group_state_subscription_clear_callback(const struct MarmotGroupStateSubscription *sub);
```

Request cancellation of this subscription's callback pump, if any. Non-blocking: a callback already running keeps executing after this returns (see the module docs).

[Header contract](include/marmot.h#L9468)

### `marmot_group_state_subscription_free`

```c
void marmot_group_state_subscription_free(struct MarmotGroupStateSubscription *sub);
```

Free the subscription handle. Requests callback-pump cancellation without waiting (a callback may still be running after this returns — do not free `user_data` on that basis). NULL is a no-op. Free every handle before the client that created it.

[Header contract](include/marmot.h#L9480)

### `marmot_group_state_subscription_snapshot`

```c
MarmotStatus marmot_group_state_subscription_snapshot(const struct MarmotGroupStateSubscription *sub, struct MarmotAppGroupRecord **out_record);
```

Take the initial group-record snapshot. Yields the record exactly once: later calls write NULL with `MARMOT_STATUS_OK`. Free with `marmot_app_group_record_free`.

[Header contract](include/marmot.h#L9503)

### `marmot_group_details_free`

```c
void marmot_group_details_free(struct MarmotGroupDetails *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10567)

### `marmot_group_management_state_free`

```c
void marmot_group_management_state_free(struct MarmotGroupManagementState *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10577)

### `marmot_group_mutation_result_free`

```c
void marmot_group_mutation_result_free(struct MarmotGroupMutationResult *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10587)

### `marmot_group_invite_decline_result_free`

```c
void marmot_group_invite_decline_result_free(struct MarmotGroupInviteDeclineResult *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10597)

### `marmot_group_conversation_snapshot_free`

```c
void marmot_group_conversation_snapshot_free(struct MarmotGroupConversationSnapshot *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10655)

### `marmot_group_roster_free`

```c
void marmot_group_roster_free(struct MarmotGroupRoster *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10665)

### `marmot_group_recovery_status_free`

```c
void marmot_group_recovery_status_free(struct MarmotGroupRecoveryStatus *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10694)

### `marmot_group_maintenance_status_free`

```c
void marmot_group_maintenance_status_free(struct MarmotGroupMaintenanceStatus *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10734)

### `marmot_group_push_debug_info_free`

```c
void marmot_group_push_debug_info_free(struct MarmotGroupPushDebugInfo *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10920)

</details>

<details>
<summary>marmot_i…</summary>

### `marmot_invite_members`

```c
MarmotStatus marmot_invite_members(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *const *member_refs, uintptr_t member_refs_len, struct MarmotSendSummary **out);
```

Invite members (by `npub` or hex account id) into the group. Requires admin. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotinvite_members) · [Header contract](include/marmot.h#L6174)

### `marmot_invite_members_detailed`

```c
MarmotStatus marmot_invite_members_detailed(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *const *member_refs, uintptr_t member_refs_len, struct MarmotGroupMutationResult **out);
```

`marmot_invite_members` plus refreshed details and management state in one round trip. Free with `marmot_group_mutation_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotinvite_members_detailed) · [Header contract](include/marmot.h#L6450)

### `marmot_initialize_chat_read_state`

```c
MarmotStatus marmot_initialize_chat_read_state(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotChatListRow **out);
```

Initialize read state for a conversation being opened; writes the refreshed row, or NULL with `MARMOT_STATUS_OK` when the group has no row. Free with `marmot_chat_list_row_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotinitialize_chat_read_state) · [Header contract](include/marmot.h#L7035)

### `marmot_is_user_blocked`

```c
MarmotStatus marmot_is_user_blocked(const struct MarmotClient *client, const char *account_ref, const char *user_account_id_hex, bool *out);
```

Whether the local account currently blocks this public key.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotis_user_blocked) · [Header contract](include/marmot.h#L7300)

### `marmot_is_following`

```c
MarmotStatus marmot_is_following(const struct MarmotClient *client, const char *account_ref, const char *user_ref, bool *out);
```

Whether `user_ref` (`npub` or hex account id) is followed.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotis_following) · [Header contract](include/marmot.h#L7328)

### `marmot_invite_members_with_initial_admins`

```c
MarmotStatus marmot_invite_members_with_initial_admins(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *const *member_refs, uintptr_t member_refs_len, const char *const *initial_admin_refs, uintptr_t initial_admin_refs_len, struct MarmotSendSummary **out);
```

`marmot_invite_members` where some invitees join as admins. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotinvite_members_with_initial_admins) · [Header contract](include/marmot.h#L7530)

### `marmot_invite_members_detailed_with_initial_admins`

```c
MarmotStatus marmot_invite_members_detailed_with_initial_admins(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *const *member_refs, uintptr_t member_refs_len, const char *const *initial_admin_refs, uintptr_t initial_admin_refs_len, struct MarmotGroupMutationResult **out);
```

`marmot_invite_members_with_initial_admins` plus refreshed details and management state in one round trip. Free with `marmot_group_mutation_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotinvite_members_detailed_with_initial_admins) · [Header contract](include/marmot.h#L7550)

### `marmot_identity_creation_result_free`

```c
void marmot_identity_creation_result_free(struct MarmotIdentityCreationResult *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10233)

</details>

<details>
<summary>marmot_k…</summary>

### `marmot_key_package_maintenance_status`

```c
MarmotStatus marmot_key_package_maintenance_status(const struct MarmotClient *client, const char *account_ref, struct MarmotKeyPackageMaintenanceStatus **out);
```

The account's KeyPackage slot state; writes NULL with `MARMOT_STATUS_OK` when no slot exists yet. Free with `marmot_key_package_maintenance_status_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotkey_package_maintenance_status) · [Header contract](include/marmot.h#L7892)

### `marmot_key_package_maintenance_status_free`

```c
void marmot_key_package_maintenance_status_free(struct MarmotKeyPackageMaintenanceStatus *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10744)

</details>

<details>
<summary>marmot_l…</summary>

### `marmot_last_error_message`

```c
char *marmot_last_error_message(void);
```

Return the detail message for the current thread's most recent failed `marmot_*` call, or NULL if there is none. The returned string is an owned copy: free it with `marmot_string_free`. Reading clears the slot.

[Header contract](include/marmot.h#L5450)

### `marmot_list_accounts`

```c
MarmotStatus marmot_list_accounts(const struct MarmotClient *client, struct MarmotAccountSummaryList **out);
```

List every account known to this device. Free the result with `marmot_account_summary_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotlist_accounts) · [Header contract](include/marmot.h#L5633)

### `marmot_login`

```c
MarmotStatus marmot_login(const struct MarmotClient *client, const char *identity, const char *const *default_relays, uintptr_t default_relays_len, const char *const *bootstrap_relays, uintptr_t bootstrap_relays_len, struct MarmotAccountSummary **out);
```

Log in with an existing identity: an `nsec` (private key) for a local-signing account, or an `npub` to track a public identity. Free with `marmot_account_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotlogin) · [Header contract](include/marmot.h#L5822)

### `marmot_local_account_key_packages`

```c
MarmotStatus marmot_local_account_key_packages(const struct MarmotClient *client, const char *account_ref, struct MarmotAccountKeyPackageInventoryEntryList **out);
```

Local-storage KeyPackage inventory with typed durable provenance. Synchronous SQLCipher I/O on the calling thread; keep it off a UI or main thread. Free with `marmot_account_key_package_inventory_entry_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotlocal_account_key_packages) · [Header contract](include/marmot.h#L5916)

### `marmot_leave_group`

```c
MarmotStatus marmot_leave_group(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotSendSummary **out);
```

Leave the group as the active account. Admins must self-demote first. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotleave_group) · [Header contract](include/marmot.h#L6209)

### `marmot_list_media`

```c
MarmotStatus marmot_list_media(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, uint8_t has_limit, uint32_t limit, struct MarmotMediaRecordList **out);
```

Stored media records for the group, capped by `limit` when `has_limit`. Free with `marmot_media_record_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotlist_media) · [Header contract](include/marmot.h#L7186)

### `marmot_login_recovering_incomplete_setup`

```c
MarmotStatus marmot_login_recovering_incomplete_setup(const struct MarmotClient *client, const char *nsec, const char *const *default_relays, uintptr_t default_relays_len, const char *const *bootstrap_relays, uintptr_t bootstrap_relays_len, uint8_t acknowledge_possible_key_package_orphan, struct MarmotAccountSummary **out);
```

Sign in and finish a setup that was interrupted partway. Free with `marmot_account_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotlogin_recovering_incomplete_setup) · [Header contract](include/marmot.h#L7388)

</details>

<details>
<summary>marmot_m…</summary>

### `marmot_mark_timeline_message_read`

```c
MarmotStatus marmot_mark_timeline_message_read(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *message_id_hex, struct MarmotChatListRow **out);
```

Mark a timeline message read; writes the refreshed row, or NULL with `MARMOT_STATUS_OK`. Free with `marmot_chat_list_row_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotmark_timeline_message_read) · [Header contract](include/marmot.h#L7050)

### `marmot_messages`

```c
MarmotStatus marmot_messages(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, uint8_t has_limit, uint32_t limit, const uint64_t *kinds, uintptr_t kinds_len, struct MarmotAppMessageRecordList **out);
```

Stored raw app messages for a group (`group_id_hex` non-NULL) or the whole account (NULL), newest-last, capped by `limit` when `has_limit`. `kinds` restricts the result to those Nostr event kinds; pass NULL with length 0 for every kind. Free with `marmot_app_message_record_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotmessages) · [Header contract](include/marmot.h#L7167)

### `marmot_message_drafts`

```c
MarmotStatus marmot_message_drafts(const struct MarmotClient *client, const char *account_ref, struct MarmotMessageDraftSummaryList **out);
```

Every stored draft for the account, attachment metadata only. Free with `marmot_message_draft_summary_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotmessage_drafts) · [Header contract](include/marmot.h#L7699)

### `marmot_message_draft`

```c
MarmotStatus marmot_message_draft(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotMessageDraft **out);
```

The stored draft for one conversation, with attachment bytes; writes NULL with `MARMOT_STATUS_OK` when there is none. Free with `marmot_message_draft_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotmessage_draft) · [Header contract](include/marmot.h#L7714)

### `marmot_message_edit_history`

```c
MarmotStatus marmot_message_edit_history(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *target_message_id_hex, uint8_t has_before, uint64_t before_edited_at, const char *before_message_id_hex, uint32_t limit, struct MarmotTimelineEditHistoryPage **out);
```

Read accepted edit versions separately from screen snapshots. Supply both cursor values, or has_before=0 and a NULL id for the newest page. Limit 1..=100. Free with marmot_timeline_edit_history_page_free. # Safety Client and strings must be valid, before_message_id nullable, out writable.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotmessage_edit_history) · [Header contract](include/marmot.h#L8783)

### `marmot_messages_subscription_next`

```c
MarmotStatus marmot_messages_subscription_next(const struct MarmotMessagesSubscription *sub, uint32_t timeout_ms, struct MarmotMessageUpdate **out);
```

Block until the next item, the timeout, or stream close. `timeout_ms == 0` waits indefinitely. Returns `MARMOT_STATUS_OK` (out set; free with `marmot_message_update_free`), `MARMOT_STATUS_TIMEOUT`, or `MARMOT_STATUS_CLOSED` (out NULL for both).

[Header contract](include/marmot.h#L9358)

### `marmot_messages_subscription_set_callback`

```c
MarmotStatus marmot_messages_subscription_set_callback(const struct MarmotMessagesSubscription *sub, MarmotMessageUpdateCallback callback, void *user_data);
```

Install a callback pump for this subscription. `callback` runs on a runtime worker thread with a borrowed item pointer (valid only during the call; do not store or free it) and a final NULL item on close. `callback` and `user_data` access must be thread-safe. Fails if a callback is already installed.

[Header contract](include/marmot.h#L9375)

### `marmot_messages_subscription_clear_callback`

```c
MarmotStatus marmot_messages_subscription_clear_callback(const struct MarmotMessagesSubscription *sub);
```

Request cancellation of this subscription's callback pump, if any. Non-blocking: a callback already running keeps executing after this returns (see the module docs).

[Header contract](include/marmot.h#L9387)

### `marmot_messages_subscription_free`

```c
void marmot_messages_subscription_free(struct MarmotMessagesSubscription *sub);
```

Free the subscription handle. Requests callback-pump cancellation without waiting (a callback may still be running after this returns — do not free `user_data` on that basis). NULL is a no-op. Free every handle before the client that created it.

[Header contract](include/marmot.h#L9399)

### `marmot_messages_subscription_snapshot`

```c
MarmotStatus marmot_messages_subscription_snapshot(const struct MarmotMessagesSubscription *sub, struct MarmotAppMessageRecordList **out_list);
```

Take the initial message-record snapshot. Yields the populated list exactly once: later calls write an EMPTY list, still with `MARMOT_STATUS_OK`. Free with `marmot_app_message_record_list_free`.

[Header contract](include/marmot.h#L9430)

### `marmot_message_draft_attachment_if_revision`

```c
MarmotStatus marmot_message_draft_attachment_if_revision(const struct MarmotClient *client, const char *account_ref, const struct MarmotMessageDraftRevision *revision, const char *attachment_id, uint8_t *out_found, uint8_t **out_data, uintptr_t *out_len);
```

Read one selected attachment. found=0 distinguishes absence from an empty acquired attachment. Free returned bytes with marmot_bytes_free; revision conflicts return an error. # Safety client, strings, revision valid; revision's owning draft stays live; all out pointers writable.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotmessage_draft_attachment_if_revision) · [Header contract](include/marmot.h#L10114)

### `marmot_message_tag_free`

```c
void marmot_message_tag_free(struct MarmotMessageTag *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10425)

### `marmot_message_draft_free`

```c
void marmot_message_draft_free(struct MarmotMessageDraft *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10473)

### `marmot_message_draft_summary_free`

```c
void marmot_message_draft_summary_free(struct MarmotMessageDraftSummary *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10483)

### `marmot_message_draft_summary_list_free`

```c
void marmot_message_draft_summary_list_free(struct MarmotMessageDraftSummaryList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10492)

### `marmot_member_ref_free`

```c
void marmot_member_ref_free(struct MarmotMemberRef *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10547)

### `marmot_member_key_package_prewarm_summary_free`

```c
void marmot_member_key_package_prewarm_summary_free(struct MarmotMemberKeyPackagePrewarmSummary *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10616)

### `marmot_maintenance_run_summary_free`

```c
void marmot_maintenance_run_summary_free(struct MarmotMaintenanceRunSummary *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10754)

### `marmot_markdown_document_free`

```c
void marmot_markdown_document_free(struct MarmotMarkdownDocument *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10764)

### `marmot_media_upload_result_free`

```c
void marmot_media_upload_result_free(struct MarmotMediaUploadResult *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10774)

### `marmot_media_download_result_free`

```c
void marmot_media_download_result_free(struct MarmotMediaDownloadResult *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10784)

### `marmot_media_record_list_free`

```c
void marmot_media_record_list_free(struct MarmotMediaRecordList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10793)

### `marmot_message_update_free`

```c
void marmot_message_update_free(struct MarmotMessageUpdate *update);
```

Free a message update returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10840)

</details>

<details>
<summary>marmot_n…</summary>

### `marmot_normalize_member_ref`

```c
MarmotStatus marmot_normalize_member_ref(const struct MarmotClient *client, const char *member_ref, struct MarmotMemberRef **out);
```

Normalize a member reference (hex, `npub`, `nostr:npub...`, `nprofile`, `nostr:nprofile...`, and `marmot://profile/...`). nprofile relay hints are discarded. Duplicate type-0 TLV entries keep the first key. After wrapper normalization, encoded tokens longer than 1023 UTF-8 bytes are rejected; a valid 1023-byte token still decodes when wrapped. Free with `marmot_member_ref_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotnormalize_member_ref) · [Header contract](include/marmot.h#L6115)

### `marmot_notify_connectivity_restored`

```c
MarmotStatus marmot_notify_connectivity_restored(const struct MarmotClient *client);
```

Interrupt retry backoff for durable outbound work after the host has observed usable connectivity.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotnotify_connectivity_restored) · [Header contract](include/marmot.h#L6579)

### `marmot_notification_settings`

```c
MarmotStatus marmot_notification_settings(const struct MarmotClient *client, const char *account_ref, struct MarmotNotificationSettings **out);
```

Per-account notification switches. Free with `marmot_notification_settings_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotnotification_settings) · [Header contract](include/marmot.h#L6796)

### `marmot_npub`

```c
MarmotStatus marmot_npub(const struct MarmotClient *client, const char *account_id_hex, char **out);
```

`npub` encoding of a hex account id; NULL with `MARMOT_STATUS_OK` when the input does not decode. Free with `marmot_string_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotnpub) · [Header contract](include/marmot.h#L7971)

### `marmot_notifications_subscription_next`

```c
MarmotStatus marmot_notifications_subscription_next(const struct MarmotNotificationsSubscription *sub, uint32_t timeout_ms, struct MarmotNotificationUpdate **out);
```

Block until the next item, the timeout, or stream close. `timeout_ms == 0` waits indefinitely. Returns `MARMOT_STATUS_OK` (out set; free with `marmot_notification_update_free`), `MARMOT_STATUS_TIMEOUT`, or `MARMOT_STATUS_CLOSED` (out NULL for both).

[Header contract](include/marmot.h#L9141)

### `marmot_notifications_subscription_set_callback`

```c
MarmotStatus marmot_notifications_subscription_set_callback(const struct MarmotNotificationsSubscription *sub, MarmotNotificationUpdateCallback callback, void *user_data);
```

Install a callback pump for this subscription. `callback` runs on a runtime worker thread with a borrowed item pointer (valid only during the call; do not store or free it) and a final NULL item on close. `callback` and `user_data` access must be thread-safe. Fails if a callback is already installed.

[Header contract](include/marmot.h#L9158)

### `marmot_notifications_subscription_clear_callback`

```c
MarmotStatus marmot_notifications_subscription_clear_callback(const struct MarmotNotificationsSubscription *sub);
```

Request cancellation of this subscription's callback pump, if any. Non-blocking: a callback already running keeps executing after this returns (see the module docs).

[Header contract](include/marmot.h#L9170)

### `marmot_notifications_subscription_free`

```c
void marmot_notifications_subscription_free(struct MarmotNotificationsSubscription *sub);
```

Free the subscription handle. Requests callback-pump cancellation without waiting (a callback may still be running after this returns — do not free `user_data` on that basis). NULL is a no-op. Free every handle before the client that created it.

[Header contract](include/marmot.h#L9182)

### `marmot_notification_settings_free`

```c
void marmot_notification_settings_free(struct MarmotNotificationSettings *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10860)

### `marmot_notification_update_free`

```c
void marmot_notification_update_free(struct MarmotNotificationUpdate *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10870)

</details>

<details>
<summary>marmot_o…</summary>

### `marmot_onboarding_recovery_required`

```c
MarmotStatus marmot_onboarding_recovery_required(const struct MarmotClient *client, const char *account_ref, bool *out);
```

Retry onboarding against explicitly selected discovery relays. Query whether unreadable/exhausted checkpoints require explicit recovery.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotonboarding_recovery_required) · [Header contract](include/marmot.h#L5702)

### `marmot_onboarding_snapshot`

```c
MarmotStatus marmot_onboarding_snapshot(const struct MarmotClient *client, const char *account_ref, struct MarmotOnboardingSnapshot **out);
```

Read the persisted onboarding snapshot. Writes NULL with MARMOT_STATUS_OK when no checkpoint exists. Free the returned snapshot with `marmot_onboarding_snapshot_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotonboarding_snapshot) · [Header contract](include/marmot.h#L8570)

### `marmot_onboarding_subscription_next`

```c
MarmotStatus marmot_onboarding_subscription_next(const struct MarmotOnboardingSubscription *sub, uint32_t timeout_ms, struct MarmotOnboardingSnapshot **out);
```

Block until the next item, the timeout, or stream close. `timeout_ms == 0` waits indefinitely. Returns `MARMOT_STATUS_OK` (out set; free with `marmot_onboarding_snapshot_free`), `MARMOT_STATUS_TIMEOUT`, or `MARMOT_STATUS_CLOSED` (out NULL for both).

[Header contract](include/marmot.h#L9661)

### `marmot_onboarding_subscription_set_callback`

```c
MarmotStatus marmot_onboarding_subscription_set_callback(const struct MarmotOnboardingSubscription *sub, MarmotOnboardingCallback callback, void *user_data);
```

Install a callback pump for this subscription. `callback` runs on a runtime worker thread with a borrowed item pointer (valid only during the call; do not store or free it) and a final NULL item on close. `callback` and `user_data` access must be thread-safe. Fails if a callback is already installed.

[Header contract](include/marmot.h#L9678)

### `marmot_onboarding_subscription_clear_callback`

```c
MarmotStatus marmot_onboarding_subscription_clear_callback(const struct MarmotOnboardingSubscription *sub);
```

Request cancellation of this subscription's callback pump, if any. Non-blocking: a callback already running keeps executing after this returns (see the module docs).

[Header contract](include/marmot.h#L9690)

### `marmot_onboarding_subscription_free`

```c
void marmot_onboarding_subscription_free(struct MarmotOnboardingSubscription *sub);
```

Free the subscription handle. Requests callback-pump cancellation without waiting (a callback may still be running after this returns — do not free `user_data` on that basis). NULL is a no-op. Free every handle before the client that created it.

[Header contract](include/marmot.h#L9702)

### `marmot_onboarding_subscription_snapshot`

```c
MarmotStatus marmot_onboarding_subscription_snapshot(const struct MarmotOnboardingSubscription *sub, struct MarmotOnboardingSnapshot **out);
```

Return the initial snapshot. Free with marmot_onboarding_snapshot_free.

[Header contract](include/marmot.h#L9720)

### `marmot_open_presented_chat_list`

```c
MarmotStatus marmot_open_presented_chat_list(const struct MarmotClient *client, const char *account_ref, uint8_t include_archived, struct MarmotPresentedChatListSubscription **out_sub);
```

Open a complete chat list with both invalidation sources already attached. Take the initial snapshot once, then call next. Free with marmot_presented_chat_list_subscription_free. # Safety Client and string must be valid; out_sub must be writable.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotopen_presented_chat_list) · [Header contract](include/marmot.h#L9729)

### `marmot_open_chat_list_window`

```c
MarmotStatus marmot_open_chat_list_window(const struct MarmotClient *client, const char *account_ref, uint32_t view, const uint32_t *initial_rows, struct MarmotChatListWindowSubscription **out_sub);
```

Open one account/view. A NULL initial_rows uses 50; otherwise requires 1–100. View is a MarmotChatListView discriminant. Take snapshot once, then receive replacements. # Safety client/string must be valid; initial_rows must be NULL or readable, out_sub writable.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotopen_chat_list_window) · [Header contract](include/marmot.h#L9919)

### `marmot_open_conversation_window`

```c
MarmotStatus marmot_open_conversation_window(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, uint32_t mode, const char *message_id_hex, const uint32_t *initial_rows, uint32_t timeout_ms, struct MarmotConversationWindowSubscription **out_sub);
```

Open one account/group. mode is a MarmotConversationOpenMode discriminant. Message mode requires message_id_hex; other modes require NULL. initial_rows NULL uses 50. Zero timeout uses 30 seconds; opening timeout abandons the opening. No mark-read occurs. # Safety client/strings must be valid; optional pointers readable or NULL, out_sub writable.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotopen_conversation_window) · [Header contract](include/marmot.h#L10008)

### `marmot_onboarding_snapshot_free`

```c
void marmot_onboarding_snapshot_free(struct MarmotOnboardingSnapshot *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L11028)

</details>

<details>
<summary>marmot_p…</summary>

### `marmot_publish_relay_lists`

```c
MarmotStatus marmot_publish_relay_lists(const struct MarmotClient *client, const char *account_ref, const char *const *default_relays, uintptr_t default_relays_len, const char *const *bootstrap_relays, uintptr_t bootstrap_relays_len);
```

Publish NIP-65 + inbox relay lists for the account. Idempotent.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotpublish_relay_lists) · [Header contract](include/marmot.h#L5853)

### `marmot_publish_new_key_package`

```c
MarmotStatus marmot_publish_new_key_package(const struct MarmotClient *client, const char *account_ref, uint64_t *out);
```

Publish a fresh KeyPackage. Writes the accepting-relay count.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotpublish_new_key_package) · [Header contract](include/marmot.h#L5962)

### `marmot_promote_admin`

```c
MarmotStatus marmot_promote_admin(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *member_ref, struct MarmotSendSummary **out);
```

Grant admin rights to `member_ref` (npub or hex). Requires admin. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotpromote_admin) · [Header contract](include/marmot.h#L6402)

### `marmot_promote_admin_detailed`

```c
MarmotStatus marmot_promote_admin_detailed(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *member_ref, struct MarmotGroupMutationResult **out);
```

`marmot_promote_admin` plus refreshed details and management state. Free with `marmot_group_mutation_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotpromote_admin_detailed) · [Header contract](include/marmot.h#L6484)

### `marmot_push_registration`

```c
MarmotStatus marmot_push_registration(const struct MarmotClient *client, const char *account_ref, struct MarmotPushRegistration **out);
```

The account's current push registration; writes NULL with `MARMOT_STATUS_OK` when there is none. Free with `marmot_push_registration_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotpush_registration) · [Header contract](include/marmot.h#L6841)

### `marmot_post_audit_log_file`

```c
MarmotStatus marmot_post_audit_log_file(const struct MarmotClient *client, const char *path, const char *endpoint, struct MarmotAuditLogUploadResult **out);
```

Upload one audit-log file to `endpoint`. Free with `marmot_audit_log_upload_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotpost_audit_log_file) · [Header contract](include/marmot.h#L6949)

### `marmot_post_audit_log_tracker_update`

```c
MarmotStatus marmot_post_audit_log_tracker_update(const struct MarmotClient *client, struct MarmotAuditLogTrackerUpdateResult **out);
```

Run one tracker-driven upload pass with the configured tracker. Free with `marmot_audit_log_tracker_update_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotpost_audit_log_tracker_update) · [Header contract](include/marmot.h#L6978)

### `marmot_presented_chat_list`

```c
MarmotStatus marmot_presented_chat_list(const struct MarmotClient *client, const char *account_ref, uint8_t include_archived, struct MarmotPresentedChatListSnapshot **out);
```

Complete local rows with selected title/avatar. Free with marmot_presented_chat_list_snapshot_free.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotpresented_chat_list) · [Header contract](include/marmot.h#L7005)

### `marmot_presented_chat_list_row`

```c
MarmotStatus marmot_presented_chat_list_row(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotPresentedChatRow **out);
```

Keyed complete row; missing groups return NULL. Free with marmot_presented_chat_row_free.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotpresented_chat_list_row) · [Header contract](include/marmot.h#L7019)

### `marmot_pause_maintenance`

```c
MarmotStatus marmot_pause_maintenance(const struct MarmotClient *client, const char *account_ref);
```

Pause the account's periodic maintenance loop.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotpause_maintenance) · [Header contract](include/marmot.h#L7583)

### `marmot_prewarm_group_member_key_packages`

```c
MarmotStatus marmot_prewarm_group_member_key_packages(const struct MarmotClient *client, const char *account_ref, const char *const *member_refs, uintptr_t member_refs_len, struct MarmotMemberKeyPackagePrewarmSummary **out);
```

Resolve and cache KeyPackages for prospective members ahead of a group creation, so the create itself does not wait on the network. Free with `marmot_member_key_package_prewarm_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotprewarm_group_member_key_packages) · [Header contract](include/marmot.h#L7731)

### `marmot_prepared_group_image_status`

```c
MarmotStatus marmot_prepared_group_image_status(const struct MarmotClient *client, const char *account_ref, const char *upload_id, struct MarmotPreparedGroupImageUpload **out);
```

Where one staged group image sits in its upload lifecycle. Free with `marmot_prepared_group_image_upload_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotprepared_group_image_status) · [Header contract](include/marmot.h#L7827)

### `marmot_prepared_group_images`

```c
MarmotStatus marmot_prepared_group_images(const struct MarmotClient *client, const char *account_ref, struct MarmotPreparedGroupImageUploadList **out);
```

Every staged group image for the account. Free with `marmot_prepared_group_image_upload_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotprepared_group_images) · [Header contract](include/marmot.h#L7842)

### `marmot_periodic_maintenance_policy`

```c
MarmotStatus marmot_periodic_maintenance_policy(const struct MarmotClient *client, const char *account_ref, enum MarmotPeriodicMaintenancePolicy *out);
```

Whether new groups enroll in periodic maintenance.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotperiodic_maintenance_policy) · [Header contract](include/marmot.h#L7919)

### `marmot_parse_markdown`

```c
MarmotStatus marmot_parse_markdown(const struct MarmotClient *client, const char *text, struct MarmotMarkdownDocument **out);
```

Parse Markdown text into the display token tree. Infallible: malformed input degrades inside the parser. Free with `marmot_markdown_document_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotparse_markdown) · [Header contract](include/marmot.h#L7947)

### `marmot_publish_user_profile`

```c
MarmotStatus marmot_publish_user_profile(const struct MarmotClient *client, const char *account_ref, const struct MarmotUserProfileMetadata *profile, const char *const *default_relays, uintptr_t default_relays_len, const char *const *bootstrap_relays, uintptr_t bootstrap_relays_len, struct MarmotUserProfileMetadata **out);
```

Publish the account's kind:0 profile metadata. The returned profile is what was actually published. Free with `marmot_user_profile_metadata_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotpublish_user_profile) · [Header contract](include/marmot.h#L8091)

### `marmot_publish_user_profile_using_account_relays`

```c
MarmotStatus marmot_publish_user_profile_using_account_relays(const struct MarmotClient *client, const char *account_ref, const struct MarmotUserProfileMetadata *profile, struct MarmotUserProfileMetadata **out);
```

Publish the account's kind:0 profile using the account's own relay lists rather than caller-supplied ones. Free with `marmot_user_profile_metadata_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotpublish_user_profile_using_account_relays) · [Header contract](include/marmot.h#L8279)

### `marmot_propose_onboarding_recommended_relays`

```c
MarmotStatus marmot_propose_onboarding_recommended_relays(const struct MarmotClient *client, const char *account_ref, uint32_t step, struct MarmotOnboardingSnapshot **out);
```

Prepare the configured default relay proposal without publishing. `step` is a MarmotOnboardingStep discriminant; out-of-range values return MARMOT_STATUS_INVALID_ARGUMENT. Free the returned snapshot with `marmot_onboarding_snapshot_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotpropose_onboarding_recommended_relays) · [Header contract](include/marmot.h#L8615)

### `marmot_propose_onboarding_relays`

```c
MarmotStatus marmot_propose_onboarding_relays(const struct MarmotClient *client, const char *account_ref, uint32_t step, const char *const *read_relays, uintptr_t read_relays_len, const char *const *write_relays, uintptr_t write_relays_len, struct MarmotOnboardingSnapshot **out);
```

Prepare a relay proposal without publishing; inbox proposals require an empty write list. `step` is a MarmotOnboardingStep discriminant; out-of-range values return MARMOT_STATUS_INVALID_ARGUMENT. Free the returned snapshot with `marmot_onboarding_snapshot_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotpropose_onboarding_relays) · [Header contract](include/marmot.h#L8627)

### `marmot_propose_onboarding_relay_repair`

```c
MarmotStatus marmot_propose_onboarding_relay_repair(const struct MarmotClient *client, const char *account_ref, uint32_t step, struct MarmotOnboardingSnapshot **out);
```

Return an owned snapshot with a non-publishing, exact relay-repair preview in `proposal->relay_repair`. Inspect its ordered source and proposed tags, unchanged content, typed occurrence diff, and mode before asking for approval. `MARMOT_ONBOARDING_RELAY_REPAIR_MODE_MANUAL_REVIEW` has no approval action; use a separate manual editor or explicitly labeled full reset. The borrowed `account_ref` and validated `step` must identify the current onboarding attempt; free the result with `marmot_onboarding_snapshot_free` and approve only the displayed revision (and recovery epoch where present).

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotpropose_onboarding_relay_repair) · [Header contract](include/marmot.h#L8645)

### `marmot_propose_onboarding_profile`

```c
MarmotStatus marmot_propose_onboarding_profile(const struct MarmotClient *client, const char *account_ref, const struct MarmotUserProfileMetadata *profile, struct MarmotOnboardingSnapshot **out);
```

Prepare profile edits without publishing; NULL fields preserve existing values and empty strings clear them. Free the returned snapshot with `marmot_onboarding_snapshot_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotpropose_onboarding_profile) · [Header contract](include/marmot.h#L8656)

### `marmot_propose_onboarding_follows`

```c
MarmotStatus marmot_propose_onboarding_follows(const struct MarmotClient *client, const char *account_ref, const char *const *follows, uintptr_t follows_len, struct MarmotOnboardingSnapshot **out);
```

Prepare a follow-list replacement without publishing; an empty list is valid. Free the returned snapshot with `marmot_onboarding_snapshot_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotpropose_onboarding_follows) · [Header contract](include/marmot.h#L8667)

### `marmot_publisher_info_free`

```c
void marmot_publisher_info_free(struct MarmotPublisherInfo *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L8887)

### `marmot_publisher_ack_free`

```c
void marmot_publisher_ack_free(struct MarmotPublisherAck *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L8897)

### `marmot_presented_chat_list_subscription_snapshot`

```c
MarmotStatus marmot_presented_chat_list_subscription_snapshot(const struct MarmotPresentedChatListSubscription *sub, struct MarmotPresentedChatListUpdate **out);
```

Take the initial snapshot with sequence zero. A second call returns CLOSED and NULL. Free the result with marmot_presented_chat_list_update_free. # Safety sub must be live; out must be writable.

[Header contract](include/marmot.h#L9740)

### `marmot_presented_chat_list_subscription_next`

```c
MarmotStatus marmot_presented_chat_list_subscription_next(const struct MarmotPresentedChatListSubscription *sub, uint32_t timeout_ms, struct MarmotPresentedChatListUpdate **out);
```

Read a whole replacement. timeout_ms zero waits indefinitely. Timeout/closed/error leave out NULL; timeout or a storage error does not discard the pending refresh. Retry according to the typed status. Free results with marmot_presented_chat_list_update_free. # Safety sub must be live; out must be writable.

[Header contract](include/marmot.h#L9750)

### `marmot_presented_chat_list_subscription_free`

```c
void marmot_presented_chat_list_subscription_free(struct MarmotPresentedChatListSubscription *sub);
```

Cancel and free a presented-list handle. NULL is a no-op. # Safety sub must be NULL or a live library-owned handle not in use by another call.

[Header contract](include/marmot.h#L9759)

### `marmot_prepared_group_image_upload_free`

```c
void marmot_prepared_group_image_upload_free(struct MarmotPreparedGroupImageUpload *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10675)

### `marmot_prepared_group_image_upload_list_free`

```c
void marmot_prepared_group_image_upload_list_free(struct MarmotPreparedGroupImageUploadList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10684)

### `marmot_push_registration_free`

```c
void marmot_push_registration_free(struct MarmotPushRegistration *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10890)

### `marmot_push_registration_share_outcome_free`

```c
void marmot_push_registration_share_outcome_free(struct MarmotPushRegistrationShareOutcome *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10900)

### `marmot_push_registration_sync_result_free`

```c
void marmot_push_registration_sync_result_free(struct MarmotPushRegistrationSyncResult *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10910)

### `marmot_presented_chat_row_free`

```c
void marmot_presented_chat_row_free(struct MarmotPresentedChatRow *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L11058)

### `marmot_presented_chat_list_snapshot_free`

```c
void marmot_presented_chat_list_snapshot_free(struct MarmotPresentedChatListSnapshot *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L11068)

### `marmot_presented_chat_list_update_free`

```c
void marmot_presented_chat_list_update_free(struct MarmotPresentedChatListUpdate *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L11078)

</details>

<details>
<summary>marmot_q…</summary>

### `marmot_quarantined_groups`

```c
MarmotStatus marmot_quarantined_groups(const struct MarmotClient *client, const char *account_ref, struct MarmotAppQuarantinedGroupList **out);
```

Stored groups that failed session-open hydration and were skipped. Surface them in a per-group recovery flow and offer `marmot_retry_hydrate_quarantined_group`. Free with `marmot_app_quarantined_group_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotquarantined_groups) · [Header contract](include/marmot.h#L6549)

</details>

<details>
<summary>marmot_r…</summary>

### `marmot_read_attachment_asset`

```c
MarmotStatus marmot_read_attachment_asset(const struct MarmotClient *client, const char *account_ref, const char *reference, uint64_t offset, uint32_t limit, struct MarmotAttachmentLocalBytes **out);
```

Read a bounded range (1..=1048576 bytes) from a local reference. No network fallback. Rechecks source visibility/expiry on every call. Offset at/beyond EOF returns available=true and empty bytes. An obsolete or wrong-account reference is unavailable. Free the result with `marmot_attachment_local_bytes_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotread_attachment_asset) · [Header contract](include/marmot.h#L5572)

### `marmot_request_avatar_assets`

```c
MarmotStatus marmot_request_avatar_assets(const struct MarmotClient *client, const char *account_ref, const char *const *targets, uintptr_t targets_len, struct MarmotAvatarAssetList **out);
```

Register up to 16 visible avatar targets without awaiting HTTP. Free the returned list with `marmot_avatar_asset_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotrequest_avatar_assets) · [Header contract](include/marmot.h#L5589)

### `marmot_read_avatar_assets`

```c
MarmotStatus marmot_read_avatar_assets(const struct MarmotClient *client, const char *account_ref, const char *const *references, uintptr_t references_len, uint64_t max_bytes, struct MarmotAvatarBytesList **out);
```

Read up to 16 local avatar references with a 1-byte..16-MiB aggregate byte budget. Budget-deferred entries are explicit. Free with `marmot_avatar_bytes_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotread_avatar_assets) · [Header contract](include/marmot.h#L5605)

### `marmot_remove_account`

```c
MarmotStatus marmot_remove_account(const struct MarmotClient *client, const char *account_ref);
```

Remove an account and its local state from this device.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotremove_account) · [Header contract](include/marmot.h#L5658)

### `marmot_recover_onboarding`

```c
MarmotStatus marmot_recover_onboarding(const struct MarmotClient *client, const char *account_ref, uint8_t acknowledge_latest_only_evidence, char **out);
```

Retain opaque evidence, retire the old attempt, and return a new epoch. Requires explicit acknowledgment of latest-only evidence retention. Hosts invalidate old UI callbacks first, then explicitly begin again.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotrecover_onboarding) · [Header contract](include/marmot.h#L5717)

### `marmot_refresh_account_key_packages`

```c
MarmotStatus marmot_refresh_account_key_packages(const struct MarmotClient *client, const char *account_ref, const char *const *bootstrap_relays, uintptr_t bootstrap_relays_len, struct MarmotAccountKeyPackageInventoryEntryList **out);
```

Fetch validated relay observations, then merge a fresh local snapshot. Empty bootstrap relays remain network-enabled. Free with `marmot_account_key_package_inventory_entry_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotrefresh_account_key_packages) · [Header contract](include/marmot.h#L5931)

### `marmot_republish_key_package`

```c
MarmotStatus marmot_republish_key_package(const struct MarmotClient *client, const char *account_ref, uint64_t *out);
```

Re-publish the latest cached KeyPackage when possible, otherwise publish a fresh one. Writes the accepting-relay count.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotrepublish_key_package) · [Header contract](include/marmot.h#L5976)

### `marmot_rotate_key_package`

```c
MarmotStatus marmot_rotate_key_package(const struct MarmotClient *client, const char *account_ref, uint64_t *out);
```

Rotate the account's KeyPackage: mint and publish a fresh one, superseding the current slot (the sanctioned repair for an epoch-stalled group; see `MARMOT_EVENT_EPOCH_STALL_ESCALATED`). Writes the accepting-relay count. `marmot_publish_new_key_package` is the same operation under its legacy name.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotrotate_key_package) · [Header contract](include/marmot.h#L5993)

### `marmot_reveal_nsec`

```c
MarmotStatus marmot_reveal_nsec(const struct MarmotClient *client, const char *account_ref, char **out);
```

Export the account's raw private key as `nsec1…` bech32. SENSITIVE: the reveal is audit-logged and permanently marks the account's key-security byte as handled-insecurely. Free the string with `marmot_string_free` as soon as it has been displayed.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotreveal_nsec) · [Header contract](include/marmot.h#L6062)

### `marmot_remove_members`

```c
MarmotStatus marmot_remove_members(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *const *member_refs, uintptr_t member_refs_len, struct MarmotSendSummary **out);
```

Remove members from the group. Requires admin; preflight rejects self-removal and removing the last admin. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotremove_members) · [Header contract](include/marmot.h#L6192)

### `marmot_remove_members_detailed`

```c
MarmotStatus marmot_remove_members_detailed(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *const *member_refs, uintptr_t member_refs_len, struct MarmotGroupMutationResult **out);
```

`marmot_remove_members` plus refreshed details and management state. Free with `marmot_group_mutation_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotremove_members_detailed) · [Header contract](include/marmot.h#L6467)

### `marmot_retry_hydrate_quarantined_group`

```c
MarmotStatus marmot_retry_hydrate_quarantined_group(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, bool *out);
```

Re-attempt hydration of a single quarantined group. Writes true if the group recovered and is now a live chat, false if it stays quarantined. Unknown-group status if the id is not quarantined.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotretry_hydrate_quarantined_group) · [Header contract](include/marmot.h#L6564)

### `marmot_retry_group_convergence`

```c
MarmotStatus marmot_retry_group_convergence(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotSendSummary **out);
```

Re-drive delivery/convergence for the group (e.g. a stuck pending own message) without minting duplicates. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotretry_group_convergence) · [Header contract](include/marmot.h#L6672)

### `marmot_react_to_message`

```c
MarmotStatus marmot_react_to_message(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *target_message_id, const char *emoji, struct MarmotSendSummary **out);
```

React to a message with `emoji`. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotreact_to_message) · [Header contract](include/marmot.h#L6687)

### `marmot_reply_to_message`

```c
MarmotStatus marmot_reply_to_message(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *target_message_id, const char *text, struct MarmotSendSummary **out);
```

Reply to a message. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotreply_to_message) · [Header contract](include/marmot.h#L6719)

### `marmot_relay_telemetry_settings`

```c
MarmotStatus marmot_relay_telemetry_settings(const struct MarmotClient *client, struct MarmotRelayTelemetrySettings **out);
```

Current relay-telemetry export settings. Free with `marmot_relay_telemetry_settings_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotrelay_telemetry_settings) · [Header contract](include/marmot.h#L6898)

### `marmot_refresh_profile`

```c
MarmotStatus marmot_refresh_profile(const struct MarmotClient *client, const char *account_id_hex, const char *const *relays, uintptr_t relays_len);
```

Refresh the cached profile for an account id from `relays`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotrefresh_profile) · [Header contract](include/marmot.h#L7217)

### `marmot_refresh_user_relay_lists`

```c
MarmotStatus marmot_refresh_user_relay_lists(const struct MarmotClient *client, const char *account_id_hex, const char *const *relays, uintptr_t relays_len, struct MarmotAccountRelayLists **out);
```

Fetch an account's published relay lists from `relays`, updating the cache. Free with `marmot_account_relay_lists_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotrefresh_user_relay_lists) · [Header contract](include/marmot.h#L7246)

### `marmot_reset_incomplete_account_setup`

```c
MarmotStatus marmot_reset_incomplete_account_setup(const struct MarmotClient *client, const char *nsec, uint8_t acknowledge_possible_key_package_orphan);
```

Discard the local state of an account whose setup never completed. `acknowledge_possible_key_package_orphan` confirms the caller accepts that a published KeyPackage may be left orphaned.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotreset_incomplete_account_setup) · [Header contract](include/marmot.h#L7374)

### `marmot_resume_maintenance`

```c
MarmotStatus marmot_resume_maintenance(const struct MarmotClient *client, const char *account_ref);
```

Resume the account's periodic maintenance loop.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotresume_maintenance) · [Header contract](include/marmot.h#L7594)

### `marmot_run_due_maintenance`

```c
MarmotStatus marmot_run_due_maintenance(const struct MarmotClient *client, const char *account_ref, struct MarmotMaintenanceRunSummary **out);
```

Run every maintenance obligation that is due now. Free with `marmot_maintenance_run_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotrun_due_maintenance) · [Header contract](include/marmot.h#L7906)

### `marmot_random_profile_pseudonym`

```c
MarmotStatus marmot_random_profile_pseudonym(const struct MarmotClient *client, char **out);
```

Random cosmetic display name from the shared wordlists. Free with `marmot_string_free`. This does not create an account or generate a signing key.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotrandom_profile_pseudonym) · [Header contract](include/marmot.h#L8011)

### `marmot_relay_health`

```c
MarmotStatus marmot_relay_health(const struct MarmotClient *client, struct MarmotRelayHealth **out);
```

Aggregate relay-pool health. Free with `marmot_relay_health_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotrelay_health) · [Header contract](include/marmot.h#L8019)

### `marmot_replace_encrypted_media_blob_endpoints`

```c
MarmotStatus marmot_replace_encrypted_media_blob_endpoints(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const struct MarmotAppBlobEndpoint *endpoints, uintptr_t endpoints_len, struct MarmotSendSummary **out);
```

Replace the group's encrypted-media default blob endpoints as a full component update. Requires admin. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotreplace_encrypted_media_blob_endpoints) · [Header contract](include/marmot.h#L8110)

### `marmot_retired_relay_hosts`

```c
MarmotStatus marmot_retired_relay_hosts(const struct MarmotClient *client, struct MarmotStringList **out);
```

The centralized retired-relay denylist. These hosts must never be dialed or adopted. Free with `marmot_string_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotretired_relay_hosts) · [Header contract](include/marmot.h#L8320)

### `marmot_record_host_performance`

```c
MarmotStatus marmot_record_host_performance(const struct MarmotClient *client, uint32_t operation, uint64_t duration_ms, uint32_t outcome);
```

Record how long a host-side operation took, so it joins the runtime's own timings in `marmot_app_performance_snapshot`. `operation` and `outcome` are discriminants; out-of-range values are rejected with `MARMOT_STATUS_INVALID_ARGUMENT`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotrecord_host_performance) · [Header contract](include/marmot.h#L8544)

### `marmot_run_onboarding`

```c
MarmotStatus marmot_run_onboarding(const struct MarmotClient *client, const char *account_ref, struct MarmotOnboardingSnapshot **out);
```

Resume pending checks until user input or a retry is needed. Free the returned snapshot with `marmot_onboarding_snapshot_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotrun_onboarding) · [Header contract](include/marmot.h#L8580)

### `marmot_retry_onboarding_step`

```c
MarmotStatus marmot_retry_onboarding_step(const struct MarmotClient *client, const char *account_ref, uint32_t step, struct MarmotOnboardingSnapshot **out);
```

Retry an offered step; earlier checks invalidate downstream readiness. `step` is a MarmotOnboardingStep discriminant; out-of-range values return MARMOT_STATUS_INVALID_ARGUMENT. Free the returned snapshot with `marmot_onboarding_snapshot_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotretry_onboarding_step) · [Header contract](include/marmot.h#L8591)

### `marmot_record_product_event`

```c
MarmotStatus marmot_record_product_event(const struct MarmotClient *client, const struct MarmotProductEvent *input, enum MarmotProductRecordResult *out);
```

Forward a validated product analytics input. # Safety Client and borrowed input must be valid; output, when present, must be writable.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotrecord_product_event) · [Header contract](include/marmot.h#L8751)

### `marmot_record_host_timing`

```c
MarmotStatus marmot_record_host_timing(const struct MarmotClient *client, const char *name, uint64_t duration_ms, uint32_t outcome, enum MarmotProductRecordResult *out);
```

Record an app-defined timing through the consent-gated product exporter. Register `name` with `elapsed: DurationBucket` and `outcome: Enum` choices `success`/`failure`. Milliseconds are bucketed before recording. # Safety Client and borrowed name must be valid; out must be writable.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotrecord_host_timing) · [Header contract](include/marmot.h#L8762)

### `marmot_reported_message`

```c
MarmotStatus marmot_reported_message(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *message_id, struct MarmotTimelineMessageRecord **out);
```

# Safety `client` must be a live handle; string arguments must be valid NUL-terminated strings (nullable ones may be NULL); array arguments must hold their stated length (or be NULL with length 0); out-pointers must be valid.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotreported_message) · [Header contract](include/marmot.h#L8817)

### `marmot_report_dismissals`

```c
MarmotStatus marmot_report_dismissals(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *report_id, const char *after, uint32_t limit, struct MarmotReportDismissalPage **out);
```

# Safety `client` must be a live handle; string arguments must be valid NUL-terminated strings (nullable ones may be NULL); array arguments must hold their stated length (or be NULL with length 0); out-pointers must be valid.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotreport_dismissals) · [Header contract](include/marmot.h#L8847)

### `marmot_report_message`

```c
MarmotStatus marmot_report_message(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *message_id, uint32_t reason, const char *explanation, struct MarmotSendSummary **out);
```

Report one group message. Reason is a MarmotReportReason discriminant. # Safety Client, strings and output pointer must be valid. Inputs are borrowed.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotreport_message) · [Header contract](include/marmot.h#L8860)

### `marmot_runtime_message_received_free`

```c
void marmot_runtime_message_received_free(struct MarmotRuntimeMessageReceived *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10832)

### `marmot_retention_sweep_report_free`

```c
void marmot_retention_sweep_report_free(struct MarmotRetentionSweepReport *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10850)

### `marmot_relay_health_free`

```c
void marmot_relay_health_free(struct MarmotRelayHealth *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10940)

### `marmot_relay_telemetry_settings_free`

```c
void marmot_relay_telemetry_settings_free(struct MarmotRelayTelemetrySettings *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10950)

### `marmot_relay_endpoint_classification_free`

```c
void marmot_relay_endpoint_classification_free(struct MarmotRelayEndpointClassification *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10960)

### `marmot_relay_endpoint_classification_list_free`

```c
void marmot_relay_endpoint_classification_list_free(struct MarmotRelayEndpointClassificationList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10969)

### `marmot_report_dismissal_page_free`

```c
void marmot_report_dismissal_page_free(struct MarmotReportDismissalPage *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L11195)

</details>

<details>
<summary>marmot_s…</summary>

### `marmot_string_free`

```c
void marmot_string_free(char *s);
```

Free a string returned by this library (`marmot_last_error_message`, string out-params). NULL is a no-op.

[Header contract](include/marmot.h#L5460)

### `marmot_sign_out_and_wipe`

```c
MarmotStatus marmot_sign_out_and_wipe(const struct MarmotClient *client, const char *account_ref, struct MarmotWipeOutcome **out);
```

Destructive sign-out: leave groups, delete relay KeyPackages, wipe local state. Every stage is reported in the outcome. Free with `marmot_wipe_outcome_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsign_out_and_wipe) · [Header contract](include/marmot.h#L5671)

### `marmot_sign_out`

```c
MarmotStatus marmot_sign_out(const struct MarmotClient *client, const char *account_ref, uint8_t delete_key_packages, struct MarmotSignOutOutcome **out);
```

Non-destructive sign-out: deactivate the account on this device, keeping local state so it can sign back in later. When `delete_key_packages` is true, relay-published KeyPackages get NIP-09 deletions. Free with `marmot_sign_out_outcome_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsign_out) · [Header contract](include/marmot.h#L5687)

### `marmot_set_onboarding_discovery_relays`

```c
MarmotStatus marmot_set_onboarding_discovery_relays(const struct MarmotClient *client, const char *account_ref, const char *const *discovery_relays, uintptr_t discovery_relays_len, struct MarmotOnboardingSnapshot **out);
```

# Safety `client` must be a live handle; string arguments must be valid NUL-terminated strings (nullable ones may be NULL); array arguments must hold their stated length (or be NULL with length 0); out-pointers must be valid.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotset_onboarding_discovery_relays) · [Header contract](include/marmot.h#L5760)

### `marmot_sign_in_account`

```c
MarmotStatus marmot_sign_in_account(const struct MarmotClient *client, const char *account_ref, struct MarmotAccountSummary **out);
```

Re-activate a non-destructively signed-out local account. Free with `marmot_account_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsign_in_account) · [Header contract](include/marmot.h#L5840)

### `marmot_set_account_nip65_relays`

```c
MarmotStatus marmot_set_account_nip65_relays(const struct MarmotClient *client, const char *account_ref, const char *const *relays, uintptr_t relays_len, const char *const *bootstrap_relays, uintptr_t bootstrap_relays_len, struct MarmotAccountRelayLists **out);
```

Replace the account's NIP-65 relay list and publish it. Free with `marmot_account_relay_lists_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotset_account_nip65_relays) · [Header contract](include/marmot.h#L6024)

### `marmot_set_account_inbox_relays`

```c
MarmotStatus marmot_set_account_inbox_relays(const struct MarmotClient *client, const char *account_ref, const char *const *relays, uintptr_t relays_len, const char *const *bootstrap_relays, uintptr_t bootstrap_relays_len, struct MarmotAccountRelayLists **out);
```

Replace the account's inbox relay list and publish it. Free with `marmot_account_relay_lists_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotset_account_inbox_relays) · [Header contract](include/marmot.h#L6042)

### `marmot_self_demote_admin`

```c
MarmotStatus marmot_self_demote_admin(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotSendSummary **out);
```

Step down as an admin (demote the active account). Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotself_demote_admin) · [Header contract](include/marmot.h#L6434)

### `marmot_self_demote_admin_detailed`

```c
MarmotStatus marmot_self_demote_admin_detailed(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotGroupMutationResult **out);
```

`marmot_self_demote_admin` plus refreshed details and management state. Free with `marmot_group_mutation_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotself_demote_admin_detailed) · [Header contract](include/marmot.h#L6516)

### `marmot_set_group_archived`

```c
MarmotStatus marmot_set_group_archived(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, uint8_t archived, struct MarmotAppGroupRecord **out);
```

Flag a group archived (or restore it). Local-only projection state. Free with `marmot_app_group_record_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotset_group_archived) · [Header contract](include/marmot.h#L6591)

### `marmot_send_text`

```c
MarmotStatus marmot_send_text(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *text, struct MarmotSendSummary **out);
```

Send a chat text message to the group. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsend_text) · [Header contract](include/marmot.h#L6607)

### `marmot_secure_delete_expired`

```c
MarmotStatus marmot_secure_delete_expired(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotSecureDeleteExpiredResult **out);
```

Securely delete this group's expired disappearing messages now. Free with `marmot_secure_delete_expired_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsecure_delete_expired) · [Header contract](include/marmot.h#L6769)

### `marmot_set_local_notifications_enabled`

```c
MarmotStatus marmot_set_local_notifications_enabled(const struct MarmotClient *client, const char *account_ref, uint8_t enabled, struct MarmotNotificationSettings **out);
```

Toggle local notifications for the account. Free with `marmot_notification_settings_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotset_local_notifications_enabled) · [Header contract](include/marmot.h#L6810)

### `marmot_set_native_push_enabled`

```c
MarmotStatus marmot_set_native_push_enabled(const struct MarmotClient *client, const char *account_ref, uint8_t enabled, struct MarmotNotificationSettings **out);
```

Toggle native push for the account. Free with `marmot_notification_settings_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotset_native_push_enabled) · [Header contract](include/marmot.h#L6825)

### `marmot_set_chat_manually_unread`

```c
MarmotStatus marmot_set_chat_manually_unread(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, uint8_t manually_unread, struct MarmotChatListRow **out);
```

Mark a conversation manually unread (or clear that mark); writes the refreshed row, or NULL with `MARMOT_STATUS_OK` when the group has no row. Free with `marmot_chat_list_row_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotset_chat_manually_unread) · [Header contract](include/marmot.h#L7067)

### `marmot_set_chat_pinned`

```c
MarmotStatus marmot_set_chat_pinned(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, uint8_t pinned, struct MarmotChatPinState **out);
```

Pin or unpin a conversation. Writes the account's full pin state. Free with `marmot_chat_pin_state_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotset_chat_pinned) · [Header contract](include/marmot.h#L7083)

### `marmot_set_pinned_chat_order`

```c
MarmotStatus marmot_set_pinned_chat_order(const struct MarmotClient *client, const char *account_ref, const char *const *ordered_group_ids, uintptr_t ordered_group_ids_len, struct MarmotChatPinState **out);
```

Replace the pinned-section order. `ordered_group_ids` lists every pinned group in display order. Free with `marmot_chat_pin_state_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotset_pinned_chat_order) · [Header contract](include/marmot.h#L7100)

### `marmot_set_chat_muted`

```c
MarmotStatus marmot_set_chat_muted(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, uint8_t has_muted_until_ms, int64_t muted_until_ms, struct MarmotChatNotificationSettings **out);
```

Mute a conversation. `has_muted_until_ms` plus `muted_until_ms` set a timed mute; leaving the flag unset mutes indefinitely. Free with `marmot_chat_notification_settings_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotset_chat_muted) · [Header contract](include/marmot.h#L7132)

### `marmot_schedule_group_self_update`

```c
MarmotStatus marmot_schedule_group_self_update(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, char **out);
```

Queue an MLS self-update commit for the group. Writes the scheduled job id; free it with `marmot_string_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotschedule_group_self_update) · [Header contract](include/marmot.h#L7569)

### `marmot_search_cached_users`

```c
MarmotStatus marmot_search_cached_users(const struct MarmotClient *client, const char *account_id_hex, const char *query, uint32_t limit, struct MarmotUserDirectorySearchResultList **out);
```

Search public identities cached through any connected account. Follow flags refer to the selected account. Call off the UI thread and free with `marmot_user_directory_search_result_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsearch_cached_users) · [Header contract](include/marmot.h#L7667)

### `marmot_sweep_expired_retention`

```c
MarmotStatus marmot_sweep_expired_retention(const struct MarmotClient *client, const char *account_ref, uint64_t now_ms, struct MarmotRetentionSweepReport **out);
```

Prune messages past their disappearing-message retention. `now_ms` is the caller's wall clock. Free with `marmot_retention_sweep_report_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsweep_expired_retention) · [Header contract](include/marmot.h#L7934)

### `marmot_set_relay_telemetry_settings`

```c
MarmotStatus marmot_set_relay_telemetry_settings(const struct MarmotClient *client, const struct MarmotRelayTelemetrySettings *settings, struct MarmotRelayTelemetrySettings **out);
```

Deprecated consent control: use `marmot_set_usage_diagnostics_consent`. Enable requires a combined grant; disable revokes both exporters. The telemetry interval remains configurable. Free the result with `marmot_relay_telemetry_settings_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotset_relay_telemetry_settings) · [Header contract](include/marmot.h#L8031)

### `marmot_set_relay_telemetry_runtime_config`

```c
MarmotStatus marmot_set_relay_telemetry_runtime_config(const struct MarmotClient *client, const struct MarmotRelayTelemetryRuntimeConfig *config);
```

Set the runtime OTLP route for relay telemetry.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotset_relay_telemetry_runtime_config) · [Header contract](include/marmot.h#L8041)

### `marmot_set_audit_log_settings`

```c
MarmotStatus marmot_set_audit_log_settings(const struct MarmotClient *client, const struct MarmotAuditLogSettings *settings, struct MarmotAuditLogSettings **out);
```

Replace the audit-log recorder settings. Free the result with `marmot_audit_log_settings_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotset_audit_log_settings) · [Header contract](include/marmot.h#L8052)

### `marmot_set_audit_log_tracker_config`

```c
MarmotStatus marmot_set_audit_log_tracker_config(const struct MarmotClient *client, const struct MarmotAuditLogTrackerConfig *config, struct MarmotAuditLogTrackerConfig **out);
```

Replace the audit-log tracker endpoint config. Free the result with `marmot_audit_log_tracker_config_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotset_audit_log_tracker_config) · [Header contract](include/marmot.h#L8064)

### `marmot_set_audit_log_tracker_config_v4`

```c
MarmotStatus marmot_set_audit_log_tracker_config_v4(const struct MarmotClient *client, const struct MarmotAuditLogTrackerConfigV4 *config, struct MarmotAuditLogTrackerConfigV4 **out);
```

Replace the audit-log tracker endpoint config. Free the result with `marmot_audit_log_tracker_config_v4_free`.

[Header contract](include/marmot.h#L8076)

### `marmot_send_media_attachments`

```c
MarmotStatus marmot_send_media_attachments(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const struct MarmotMediaAttachmentReference *attachments, uintptr_t attachments_len, const char *caption, struct MarmotSendSummary **out);
```

Send previously uploaded attachments as one message. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsend_media_attachments) · [Header contract](include/marmot.h#L8126)

### `marmot_send_media_reference`

```c
MarmotStatus marmot_send_media_reference(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const struct MarmotMediaAttachmentReference *reference, const char *caption, struct MarmotSendSummary **out);
```

Send one previously uploaded attachment as a message. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsend_media_reference) · [Header contract](include/marmot.h#L8142)

### `marmot_start_agent_text_stream`

```c
MarmotStatus marmot_start_agent_text_stream(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *stream_id_hex, const char *const *quic_candidates, uintptr_t quic_candidates_len, struct MarmotAgentStreamStart **out);
```

Publish a kind-1200 agent text stream start (anchor) for the group. `stream_id_hex` NULL mints a fresh id; `quic_candidates` are the broker route candidates. Free with `marmot_agent_stream_start_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotstart_agent_text_stream) · [Header contract](include/marmot.h#L8243)

### `marmot_storage_is_closed`

```c
MarmotStatus marmot_storage_is_closed(const struct MarmotClient *client, bool *out_closed);
```

Whether this client's storage has been closed (by `marmot_client_shutdown_and_close`). Writes to `out_closed`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotstorage_is_closed) · [Header contract](include/marmot.h#L8311)

### `marmot_save_message_draft`

```c
MarmotStatus marmot_save_message_draft(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *content, const char *reply_to_message_id_hex, const struct MarmotMessageDraftAttachmentInput *attachments, uintptr_t attachments_len, struct MarmotMessageDraft **out);
```

Store (or replace) the draft for a conversation. `attachments` are copied — the caller keeps ownership of every buffer. Free the result with `marmot_message_draft_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsave_message_draft) · [Header contract](include/marmot.h#L8334)

### `marmot_stage_prepared_group_image`

```c
MarmotStatus marmot_stage_prepared_group_image(const struct MarmotClient *client, const char *account_ref, const uint8_t *plaintext, uintptr_t plaintext_len, const char *media_type, struct MarmotPreparedGroupImageUpload **out);
```

Encrypt and stage a group image without attaching it to a group yet, so the upload can finish before the caller commits to creating one. The bytes are copied — the caller keeps ownership. Free with `marmot_prepared_group_image_upload_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotstage_prepared_group_image) · [Header contract](include/marmot.h#L8423)

### `marmot_set_periodic_maintenance_policy`

```c
MarmotStatus marmot_set_periodic_maintenance_policy(const struct MarmotClient *client, const char *account_ref, uint32_t policy);
```

Set whether new groups enroll in periodic maintenance.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotset_periodic_maintenance_policy) · [Header contract](include/marmot.h#L8436)

### `marmot_send_custom_event`

```c
MarmotStatus marmot_send_custom_event(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, uint64_t kind, const struct MarmotStringArray *tags, uintptr_t tags_len, const char *content, struct MarmotSendSummary **out);
```

Send a custom application event into the group. `tags` is a flat array of `tags_len` tag rows, each row a `(char **, len)` pair of string values. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsend_custom_event) · [Header contract](include/marmot.h#L8465)

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

[Header contract](include/marmot.h#L8483)

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

[Header contract](include/marmot.h#L8501)

### `marmot_set_usage_diagnostics_consent`

```c
MarmotStatus marmot_set_usage_diagnostics_consent(const struct MarmotClient *client, uint8_t enabled, struct MarmotUsageDiagnosticsSettings **out);
```

# Safety `client` must be a live handle; string arguments must be valid NUL-terminated strings (nullable ones may be NULL); array arguments must hold their stated length (or be NULL with length 0); out-pointers must be valid.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotset_usage_diagnostics_consent) · [Header contract](include/marmot.h#L8713)

### `marmot_set_product_analytics_runtime_config`

```c
MarmotStatus marmot_set_product_analytics_runtime_config(const struct MarmotClient *client, const struct MarmotProductAnalyticsRuntimeConfig *input);
```

Forward a validated product analytics input. # Safety Client and borrowed input must be valid; output, when present, must be writable.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotset_product_analytics_runtime_config) · [Header contract](include/marmot.h#L8743)

### `marmot_set_product_analytics_activity`

```c
MarmotStatus marmot_set_product_analytics_activity(const struct MarmotClient *client, uint32_t activity);
```

Signal host activity. Discriminants are validated before conversion. # Safety Client must be a live handle.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotset_product_analytics_activity) · [Header contract](include/marmot.h#L8773)

### `marmot_subscribe_events`

```c
MarmotStatus marmot_subscribe_events(const struct MarmotClient *client, struct MarmotEventsSubscription **out_sub);
```

Subscribe to the event firehose. Free with `marmot_events_subscription_free` (before freeing the client).

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsubscribe_events) · [Header contract](include/marmot.h#L9019)

### `marmot_subscribe_timeline_messages`

```c
MarmotStatus marmot_subscribe_timeline_messages(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, uint8_t has_limit, uint32_t limit, struct MarmotTimelineSubscription **out_sub);
```

Subscribe to live materialized timeline updates for a group (`group_id_hex` non-NULL) or the account-wide tail (NULL). `has_limit` plus `limit` cap the initial window. Free with `marmot_timeline_subscription_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsubscribe_timeline_messages) · [Header contract](include/marmot.h#L9081)

### `marmot_subscribe_notifications`

```c
MarmotStatus marmot_subscribe_notifications(const struct MarmotClient *client, struct MarmotNotificationsSubscription **out_sub);
```

Subscribe to notification updates. Free with `marmot_notifications_subscription_free` (before freeing the client).

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsubscribe_notifications) · [Header contract](include/marmot.h#L9191)

### `marmot_subscribe_chats`

```c
MarmotStatus marmot_subscribe_chats(const struct MarmotClient *client, const char *account_ref, uint8_t include_archived, struct MarmotChatsSubscription **out_sub);
```

Subscribe to one account's chats list. Emits whenever a group's projection changes; `include_archived` widens the filter. Free with `marmot_chats_subscription_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsubscribe_chats) · [Header contract](include/marmot.h#L9252)

### `marmot_subscribe_chat_list`

```c
MarmotStatus marmot_subscribe_chat_list(const struct MarmotClient *client, const char *account_ref, uint8_t include_archived, struct MarmotChatListSubscription **out_sub);
```

Subscribe to one account's durable chat-list projection. Free with `marmot_chat_list_subscription_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsubscribe_chat_list) · [Header contract](include/marmot.h#L9325)

### `marmot_subscribe_messages`

```c
MarmotStatus marmot_subscribe_messages(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, uint8_t has_limit, uint32_t limit, const uint64_t *kinds, uintptr_t kinds_len, struct MarmotMessagesSubscription **out_sub);
```

Subscribe to messages for a specific group (`group_id_hex` non-NULL) or every message across the account (NULL). `has_limit` + `limit` cap the initial snapshot to the latest N rows. `kinds` restricts the stream to those Nostr event kinds; pass NULL with length 0 for every kind. Free with `marmot_messages_subscription_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsubscribe_messages) · [Header contract](include/marmot.h#L9413)

### `marmot_subscribe_group_state`

```c
MarmotStatus marmot_subscribe_group_state(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotGroupStateSubscription **out_sub);
```

Subscribe to member/profile/roster changes for one group. Free with `marmot_group_state_subscription_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsubscribe_group_state) · [Header contract](include/marmot.h#L9490)

### `marmot_search_users`

```c
MarmotStatus marmot_search_users(const struct MarmotClient *client, const char *account_id_hex, const char *query, uint8_t radius_start, uint8_t radius_end, struct MarmotUserSearchSubscription **out_sub);
```

Search the identity directory outward from `account_id_hex`, widening from `radius_start` to `radius_end` social hops. Results stream in through the returned handle. Free it with `marmot_user_search_subscription_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsearch_users) · [Header contract](include/marmot.h#L9648)

### `marmot_subscribe_onboarding`

```c
MarmotStatus marmot_subscribe_onboarding(const struct MarmotClient *client, const char *account_ref, struct MarmotOnboardingSubscription **out_sub);
```

Subscribe to durable onboarding state for an account.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsubscribe_onboarding) · [Header contract](include/marmot.h#L9710)

### `marmot_subscribe_blocked_users`

```c
MarmotStatus marmot_subscribe_blocked_users(const struct MarmotClient *client, const char *account_ref, struct MarmotBlockListSubscription **out_sub);
```

Subscribe to an account's block list. # Safety Client, account string and output pointer must be valid.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsubscribe_blocked_users) · [Header contract](include/marmot.h#L9815)

### `marmot_subscribe_attachment_transfers`

```c
MarmotStatus marmot_subscribe_attachment_transfers(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const struct MarmotAttachmentLocalTarget *targets, uintptr_t targets_len, struct MarmotAttachmentTransferSubscription **out);
```

Open a bounded progress stream. First next returns the initial snapshot. # Safety Inputs must be live, targets NULL only with zero length, out writable.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsubscribe_attachment_transfers) · [Header contract](include/marmot.h#L9832)

### `marmot_subscribe_account_attention`

```c
MarmotStatus marmot_subscribe_account_attention(const struct MarmotClient *client, struct MarmotAccountAttentionSubscription **out_sub);
```

Open independent signed-in account summaries; requires no active chat-list handle. # Safety client must be valid; out_sub writable.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsubscribe_account_attention) · [Header contract](include/marmot.h#L9930)

### `marmot_selected_message_draft`

```c
MarmotStatus marmot_selected_message_draft(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, struct MarmotSelectedMessageDraft **out);
```

Descriptor-only draft; result owns the revision handle and must be deep-freed. # Safety client and strings valid; out writable.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotselected_message_draft) · [Header contract](include/marmot.h#L10078)

### `marmot_save_message_draft_if_revision`

```c
MarmotStatus marmot_save_message_draft_if_revision(const struct MarmotClient *client, const char *account_ref, const struct MarmotMessageDraftRevision *revision, const char *content, const char *reply, const struct MarmotMessageDraftAttachmentInput *attachments, uintptr_t attachments_len, struct MarmotSelectedMessageDraft **out);
```

Save only if the selected revision still matches. Attachment inputs are copied, never retained. # Safety client, account, content and revision valid; reply nullable; attachments points to len readable items (or NULL with zero len). Revision's owner stays live; out writable.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsave_message_draft_if_revision) · [Header contract](include/marmot.h#L10099)

### `marmot_send_message_draft`

```c
MarmotStatus marmot_send_message_draft(const struct MarmotClient *client, const char *account_ref, const struct MarmotMessageDraftRevision *revision, const struct MarmotMediaAttachmentReference *attachments, uintptr_t attachments_len, struct MarmotSendSummary **out);
```

Send the exact selected revision; successful durable acceptance clears it atomically. Hosts must not independently delete the draft on delivery. Prepared media must match descriptors. # Safety client, account, revision valid; revision owner stays live; attachments readable for length, or NULL with zero length; out writable. Free result with marmot_send_summary_free.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotsend_message_draft) · [Header contract](include/marmot.h#L10129)

### `marmot_send_summary_free`

```c
void marmot_send_summary_free(struct MarmotSendSummary *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10186)

### `marmot_sign_out_outcome_free`

```c
void marmot_sign_out_outcome_free(struct MarmotSignOutOutcome *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10253)

### `marmot_string_list_free`

```c
void marmot_string_list_free(struct MarmotStringList *list);
```

Free a string list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10415)

### `marmot_secure_delete_expired_result_free`

```c
void marmot_secure_delete_expired_result_free(struct MarmotSecureDeleteExpiredResult *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10822)

### `marmot_selected_message_draft_free`

```c
void marmot_selected_message_draft_free(struct MarmotSelectedMessageDraft *p);
```

Deep-free a selected draft and its opaque revision. NULL is allowed. Only for drafts returned directly by this library. A snapshot's embedded draft is freed by `marmot_conversation_window_snapshot_free`. # Safety p must be NULL or a library-owned unfreed selected-draft root pointer, never the address of a snapshot's embedded draft.

[Header contract](include/marmot.h#L11108)

### `marmot_set_attachment_download_policy`

```c
MarmotStatus marmot_set_attachment_download_policy(const struct MarmotClient *client, const char *account_ref, const struct MarmotAttachmentDownloadPolicyInput *policy);
```

Persist policy. Disable pauses automatic work but preserves explicit transfers and cached bytes. # Safety Client, strings and policy must be live throughout this call. Inputs are borrowed.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotset_attachment_download_policy) · [Header contract](include/marmot.h#L11231)

</details>

<details>
<summary>marmot_t…</summary>

### `marmot_telemetry_install_id`

```c
MarmotStatus marmot_telemetry_install_id(const struct MarmotClient *client, char **out);
```

Stable anonymous install id for telemetry. Free with `marmot_string_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmottelemetry_install_id) · [Header contract](include/marmot.h#L6911)

### `marmot_timeline_messages`

```c
MarmotStatus marmot_timeline_messages(const struct MarmotClient *client, const char *account_ref, const struct MarmotTimelineMessageQuery *query, struct MarmotTimelinePage **out);
```

Materialized timeline read. Free the page with `marmot_timeline_page_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmottimeline_messages) · [Header contract](include/marmot.h#L8197)

### `marmot_timeline_subscription_next`

```c
MarmotStatus marmot_timeline_subscription_next(const struct MarmotTimelineSubscription *sub, uint32_t timeout_ms, struct MarmotTimelinePage **out);
```

Block until the next item, the timeout, or stream close. `timeout_ms == 0` waits indefinitely. Returns `MARMOT_STATUS_OK` (out set; free with `marmot_timeline_page_free`), `MARMOT_STATUS_TIMEOUT`, or `MARMOT_STATUS_CLOSED` (out NULL for both).

[Header contract](include/marmot.h#L9028)

### `marmot_timeline_subscription_set_callback`

```c
MarmotStatus marmot_timeline_subscription_set_callback(const struct MarmotTimelineSubscription *sub, MarmotTimelinePageCallback callback, void *user_data);
```

Install a callback pump for this subscription. `callback` runs on a runtime worker thread with a borrowed item pointer (valid only during the call; do not store or free it) and a final NULL item on close. `callback` and `user_data` access must be thread-safe. Fails if a callback is already installed.

[Header contract](include/marmot.h#L9045)

### `marmot_timeline_subscription_clear_callback`

```c
MarmotStatus marmot_timeline_subscription_clear_callback(const struct MarmotTimelineSubscription *sub);
```

Request cancellation of this subscription's callback pump, if any. Non-blocking: a callback already running keeps executing after this returns (see the module docs).

[Header contract](include/marmot.h#L9057)

### `marmot_timeline_subscription_free`

```c
void marmot_timeline_subscription_free(struct MarmotTimelineSubscription *sub);
```

Free the subscription handle. Requests callback-pump cancellation without waiting (a callback may still be running after this returns — do not free `user_data` on that basis). NULL is a no-op. Free every handle before the client that created it.

[Header contract](include/marmot.h#L9069)

### `marmot_timeline_subscription_snapshot`

```c
MarmotStatus marmot_timeline_subscription_snapshot(const struct MarmotTimelineSubscription *sub, struct MarmotTimelinePage **out_page);
```

Take the initial window snapshot. Yields the page exactly once: later calls write NULL with `MARMOT_STATUS_OK`. Free the page with `marmot_timeline_page_free`.

[Header contract](include/marmot.h#L9096)

### `marmot_timeline_subscription_next_update`

```c
MarmotStatus marmot_timeline_subscription_next_update(const struct MarmotTimelineSubscription *sub, uint32_t timeout_ms, struct MarmotTimelineSubscriptionUpdate **out_update);
```

Block until the next raw delta (page replacement or projection update). Free with `marmot_timeline_subscription_update_free`.

[Header contract](include/marmot.h#L9106)

### `marmot_timeline_subscription_paginate_backwards`

```c
MarmotStatus marmot_timeline_subscription_paginate_backwards(const struct MarmotTimelineSubscription *sub, uint32_t count, struct MarmotTimelinePage **out_page);
```

Extend the window toward older history by up to `count` messages and return the new window. Runs on the runtime off the caller's lock, so a concurrent blocking `next` on another thread is not blocked. Free with `marmot_timeline_page_free`.

[Header contract](include/marmot.h#L9119)

### `marmot_timeline_subscription_paginate_forwards`

```c
MarmotStatus marmot_timeline_subscription_paginate_forwards(const struct MarmotTimelineSubscription *sub, uint32_t count, struct MarmotTimelinePage **out_page);
```

Extend the window toward the live head by up to `count` messages and return the new window. Reaching the head re-anchors the window. Free with `marmot_timeline_page_free`.

[Header contract](include/marmot.h#L9131)

### `marmot_timeline_message_record_free`

```c
void marmot_timeline_message_record_free(struct MarmotTimelineMessageRecord *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10989)

### `marmot_timeline_page_free`

```c
void marmot_timeline_page_free(struct MarmotTimelinePage *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10999)

### `marmot_timeline_subscription_update_free`

```c
void marmot_timeline_subscription_update_free(struct MarmotTimelineSubscriptionUpdate *update);
```

Free a timeline-subscription delta returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L11008)

### `marmot_timeline_edit_history_page_free`

```c
void marmot_timeline_edit_history_page_free(struct MarmotTimelineEditHistoryPage *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L11018)

</details>

<details>
<summary>marmot_u…</summary>

### `marmot_update_message_retention`

```c
MarmotStatus marmot_update_message_retention(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, uint64_t disappearing_message_secs, struct MarmotSendSummary **out);
```

Set the per-group disappearing-message retention. `disappearing_message_secs` of `0` disables expiry. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotupdate_message_retention) · [Header contract](include/marmot.h#L6259)

### `marmot_update_group_profile`

```c
MarmotStatus marmot_update_group_profile(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *name, const char *description, struct MarmotSendSummary **out);
```

Update the group's name and/or description. NULL leaves a field unchanged. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotupdate_group_profile) · [Header contract](include/marmot.h#L6349)

### `marmot_update_group_avatar_url`

```c
MarmotStatus marmot_update_group_avatar_url(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *url, const char *dim, const char *thumbhash, struct MarmotSendSummary **out);
```

Set (or clear, with `url` NULL) the group's URL-based avatar. The URL is validated (https-only, no localhost/private hosts) and normalized before commit. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotupdate_group_avatar_url) · [Header contract](include/marmot.h#L6367)

### `marmot_unreact_from_message`

```c
MarmotStatus marmot_unreact_from_message(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *target_message_id, struct MarmotSendSummary **out);
```

Remove this account's reaction from a message. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotunreact_from_message) · [Header contract](include/marmot.h#L6704)

### `marmot_user_profile`

```c
MarmotStatus marmot_user_profile(const struct MarmotClient *client, const char *account_id_hex, struct MarmotUserProfileMetadata **out);
```

Cached kind-0 profile for an account id; writes NULL with `MARMOT_STATUS_OK` when unknown. Free with `marmot_user_profile_metadata_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotuser_profile) · [Header contract](include/marmot.h#L7204)

### `marmot_user_relay_lists`

```c
MarmotStatus marmot_user_relay_lists(const struct MarmotClient *client, const char *account_id_hex, struct MarmotAccountRelayLists **out);
```

Cached NIP-65 and inbox relay lists for any account id; no network. Free with `marmot_account_relay_lists_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotuser_relay_lists) · [Header contract](include/marmot.h#L7232)

### `marmot_unblock_user`

```c
MarmotStatus marmot_unblock_user(const struct MarmotClient *client, const char *account_ref, const char *user_account_id_hex);
```

Unblock a user and publish the updated list. Requires relay synchronization.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotunblock_user) · [Header contract](include/marmot.h#L7274)

### `marmot_unfollow_user`

```c
MarmotStatus marmot_unfollow_user(const struct MarmotClient *client, const char *account_ref, const char *user_ref, struct MarmotStringList **out);
```

Unfollow `user_ref` and publish the updated list. Free with `marmot_string_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotunfollow_user) · [Header contract](include/marmot.h#L7358)

### `marmot_user_profile_website`

```c
MarmotStatus marmot_user_profile_website(const struct MarmotClient *client, const char *account_id_hex, char **out);
```

The `website` field of a cached kind-0 profile; writes NULL with `MARMOT_STATUS_OK` when unknown. Free with `marmot_string_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotuser_profile_website) · [Header contract](include/marmot.h#L7439)

### `marmot_upload_prepared_group_image`

```c
MarmotStatus marmot_upload_prepared_group_image(const struct MarmotClient *client, const char *account_ref, const char *upload_id, struct MarmotPreparedGroupImageUpload **out);
```

Upload a staged group image now, so a later group creation can consume it without waiting. Free with `marmot_prepared_group_image_upload_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotupload_prepared_group_image) · [Header contract](include/marmot.h#L7812)

### `marmot_upload_media`

```c
MarmotStatus marmot_upload_media(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const struct MarmotMediaUploadRequest *request, struct MarmotMediaUploadResult **out);
```

Encrypt and upload attachments (optionally sending them). Free with `marmot_media_upload_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotupload_media) · [Header contract](include/marmot.h#L8157)

### `marmot_upsert_push_registration`

```c
MarmotStatus marmot_upsert_push_registration(const struct MarmotClient *client, const char *account_ref, uint32_t platform, const char *raw_token, const char *server_pubkey_hex, const char *relay_hint, struct MarmotPushRegistrationSyncResult **out);
```

Register (or update) the account's native push token and share it. `platform` is a `MarmotPushPlatform` discriminant; out-of-range values are rejected with `MARMOT_STATUS_INVALID_ARGUMENT`. Free with `marmot_push_registration_sync_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotupsert_push_registration) · [Header contract](include/marmot.h#L8212)

### `marmot_update_group_image`

```c
MarmotStatus marmot_update_group_image(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const uint8_t *plaintext, uintptr_t plaintext_len, const char *media_type, struct MarmotSendSummary **out);
```

Encrypt `plaintext` (the raw image bytes, `media_type` e.g. `"image/jpeg"`), upload it to Blossom, and commit it as the group's avatar. Requires admin. The bytes are copied — the caller keeps ownership. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotupdate_group_image) · [Header contract](include/marmot.h#L8262)

### `marmot_upload_profile_image`

```c
MarmotStatus marmot_upload_profile_image(const struct MarmotClient *client, const char *account_ref, const uint8_t *data, uintptr_t data_len, const char *media_type, const char *blossom_server, char **out);
```

Upload `data` (raw image bytes, `media_type` e.g. `"image/jpeg"`) to Blossom as the account's profile image. `blossom_server` overrides the default server; pass NULL to use it. The bytes are copied — the caller keeps ownership. Writes the image URL; free it with `marmot_string_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotupload_profile_image) · [Header contract](include/marmot.h#L8296)

### `marmot_usage_diagnostics_settings`

```c
MarmotStatus marmot_usage_diagnostics_settings(const struct MarmotClient *client, struct MarmotUsageDiagnosticsSettings **out);
```

# Safety `client` must be a live handle; string arguments must be valid NUL-terminated strings (nullable ones may be NULL); array arguments must hold their stated length (or be NULL with length 0); out-pointers must be valid.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotusage_diagnostics_settings) · [Header contract](include/marmot.h#L8702)

### `marmot_usage_diagnostics_status`

```c
MarmotStatus marmot_usage_diagnostics_status(const struct MarmotClient *client, struct MarmotUsageDiagnosticsStatus **out);
```

# Safety `client` must be a live handle; string arguments must be valid NUL-terminated strings (nullable ones may be NULL); array arguments must hold their stated length (or be NULL with length 0); out-pointers must be valid.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotusage_diagnostics_status) · [Header contract](include/marmot.h#L8725)

### `marmot_user_search_subscription_next`

```c
MarmotStatus marmot_user_search_subscription_next(const struct MarmotUserSearchSubscription *sub, uint32_t timeout_ms, struct MarmotUserSearchUpdate **out);
```

Block until the next item, the timeout, or stream close. `timeout_ms == 0` waits indefinitely. Returns `MARMOT_STATUS_OK` (out set; free with `marmot_user_search_update_free`), `MARMOT_STATUS_TIMEOUT`, or `MARMOT_STATUS_CLOSED` (out NULL for both).

[Header contract](include/marmot.h#L9595)

### `marmot_user_search_subscription_set_callback`

```c
MarmotStatus marmot_user_search_subscription_set_callback(const struct MarmotUserSearchSubscription *sub, MarmotUserSearchUpdateCallback callback, void *user_data);
```

Install a callback pump for this subscription. `callback` runs on a runtime worker thread with a borrowed item pointer (valid only during the call; do not store or free it) and a final NULL item on close. `callback` and `user_data` access must be thread-safe. Fails if a callback is already installed.

[Header contract](include/marmot.h#L9612)

### `marmot_user_search_subscription_clear_callback`

```c
MarmotStatus marmot_user_search_subscription_clear_callback(const struct MarmotUserSearchSubscription *sub);
```

Request cancellation of this subscription's callback pump, if any. Non-blocking: a callback already running keeps executing after this returns (see the module docs).

[Header contract](include/marmot.h#L9624)

### `marmot_user_search_subscription_free`

```c
void marmot_user_search_subscription_free(struct MarmotUserSearchSubscription *sub);
```

Free the subscription handle. Requests callback-pump cancellation without waiting (a callback may still be running after this returns — do not free `user_data` on that basis). NULL is a no-op. Free every handle before the client that created it.

[Header contract](include/marmot.h#L9636)

### `marmot_user_profile_metadata_free`

```c
void marmot_user_profile_metadata_free(struct MarmotUserProfileMetadata *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10223)

### `marmot_user_directory_search_result_list_free`

```c
void marmot_user_directory_search_result_list_free(struct MarmotUserDirectorySearchResultList *list);
```

Free a list returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10453)

### `marmot_user_search_update_free`

```c
void marmot_user_search_update_free(struct MarmotUserSearchUpdate *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10463)

### `marmot_usage_diagnostics_settings_free`

```c
void marmot_usage_diagnostics_settings_free(struct MarmotUsageDiagnosticsSettings *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L11038)

### `marmot_usage_diagnostics_status_free`

```c
void marmot_usage_diagnostics_status_free(struct MarmotUsageDiagnosticsStatus *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L11048)

</details>

<details>
<summary>marmot_w…</summary>

### `marmot_watch_agent_text_stream`

```c
MarmotStatus marmot_watch_agent_text_stream(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *stream_id_hex, const uint8_t *server_cert_der, uintptr_t server_cert_der_len, uint8_t insecure_local, struct MarmotAgentStreamSubscription **out_sub);
```

Watch a live agent text stream over the brokered QUIC channel. Pass `stream_id_hex = NULL` to follow the latest stream in the group. `server_cert_der` (+ `server_cert_der_len`) pins a self-signed broker certificate; pass NULL with length 0 to use platform trust. The bytes are copied — the caller keeps ownership. `insecure_local` is loopback-only for testing. Free with `marmot_agent_stream_subscription_free`.

[Shared method and API guidance](../marmot-uniffi/API-REFERENCE.md#marmotwatch_agent_text_stream) · [Header contract](include/marmot.h#L9570)

### `marmot_wipe_outcome_free`

```c
void marmot_wipe_outcome_free(struct MarmotWipeOutcome *ptr);
```

Free a value of this type returned by this library. NULL is a no-op.

[Header contract](include/marmot.h#L10243)

</details>

<details>
<summary>Host-managed automatic attachment acquisition</summary>

### `marmot_automatic_attachment_request_free`

```c
void marmot_automatic_attachment_request_free(struct MarmotAutomaticAttachmentRequest *ptr);
```

Deep-free the returned automatic-request record and its nested status/reference. NULL is a no-op; do not free nested fields separately.

[Header contract](include/marmot.h#L11277)

### `marmot_begin_attachment_permission_update`

```c
MarmotStatus marmot_begin_attachment_permission_update(const struct MarmotClient *client, const char *account_ref, char **out);
```

Blocking revocation and generation issuance for HostManaged mode. Inputs are borrowed; free the returned generation with marmot_string_free. Call before asynchronous policy evaluation and keep the token with that evaluation. See the [shared permission contract](../marmot-uniffi/ATTACHMENT-ACCESS.md#host-managed-automatic-acquisition-0104).

[Header contract](include/marmot.h#L11284)

### `marmot_request_automatic_attachment`

```c
MarmotStatus marmot_request_automatic_attachment(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const struct MarmotAttachmentLocalTarget *target, struct MarmotAutomaticAttachmentRequest **out);
```

Blocking, idempotent automatic demand for the exact source slot. Inputs are borrowed; free the returned status/result with marmot_automatic_attachment_request_free. Repeated requests preserve suppression, acquisition history and retry budgets. See the [migration contract](../marmot-uniffi/ATTACHMENT-ACCESS.md#android-migration).

[Header contract](include/marmot.h#L11304)

### `marmot_set_attachment_automatic_permission`

```c
MarmotStatus marmot_set_attachment_automatic_permission(const struct MarmotClient *client, const char *account_ref, const char *generation, const struct MarmotAttachmentAutomaticPermissionInput *permission, bool *out);
```

Blocking application of runtime-only category permission. All inputs are borrowed; boolean input integers use nonzero for true. False output means the generation was stale, foreign or already consumed. Required output validation occurs before mutation. See the [shared permission contract](../marmot-uniffi/ATTACHMENT-ACCESS.md#host-managed-automatic-acquisition-0104).

[Header contract](include/marmot.h#L11293)

</details>

<details>
<summary>Durable local sends and caller correlation</summary>

### `marmot_local_send_acceptance_free`

```c
void marmot_local_send_acceptance_free(struct MarmotLocalSendAcceptance *ptr);
```

Deep-free a returned local acceptance, including its token and message identity.
NULL is permitted; embedded acceptances belong to their parent upload result.

[Header contract](include/marmot.h#L10704)

### `marmot_local_send_status`

```c
MarmotStatus marmot_local_send_status(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *client_token, struct MarmotLocalSendStatus **out);
```

Look up a retained token's local state without relay I/O. A NULL result means no
association. Free a non-NULL result with `marmot_local_send_status_free`. Follow
timeline updates for subsequent delivery; see [local sends](../marmot-uniffi/LOCAL-SENDS.md).

[Header contract](include/marmot.h#L6655)

### `marmot_local_send_status_free`

```c
void marmot_local_send_status_free(struct MarmotLocalSendStatus *ptr);
```

Deep-free a local status result and its optional completion summary. NULL is permitted.

[Header contract](include/marmot.h#L10724)

### `marmot_media_upload_submission_free`

```c
void marmot_media_upload_submission_free(struct MarmotMediaUploadSubmission *ptr);
```

Deep-free an upload/submission result, including references and its optional token-bound
acceptance. NULL is permitted; never free its embedded records separately.

[Header contract](include/marmot.h#L10714)

### `marmot_reply_to_message_with_client_token`

```c
MarmotStatus marmot_reply_to_message_with_client_token(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *target_message_id, const char *text, const char *client_token, struct MarmotLocalSendAcceptance **out);
```

Block until durable local reply acceptance, independently of relay publication.
Inputs are borrowed. Free the result with `marmot_local_send_acceptance_free` and
reconcile the optimistic bubble by timeline token. See [local sends](../marmot-uniffi/LOCAL-SENDS.md).

[Header contract](include/marmot.h#L6638)

### `marmot_send_message_draft_with_client_token`

```c
MarmotStatus marmot_send_message_draft_with_client_token(const struct MarmotClient *client, const char *account_ref, const struct MarmotMessageDraftRevision *revision, const struct MarmotMediaAttachmentReference *attachments, uintptr_t attachments_len, const char *client_token, struct MarmotLocalSendAcceptance **out);
```

Atomically consume the borrowed draft revision and admit a correlated message.
Keep its revision owner alive during the call; attachment inputs are borrowed.
Free acceptance with `marmot_local_send_acceptance_free`; do not clear the composer
on delivery. See [local sends](../marmot-uniffi/LOCAL-SENDS.md).

[Header contract](include/marmot.h#L10142)

### `marmot_send_text_with_client_token`

```c
MarmotStatus marmot_send_text_with_client_token(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const char *text, const char *client_token, struct MarmotLocalSendAcceptance **out);
```

Block until text is durably admitted, without waiting for relay publication.
Use a unique token per logical submission; repeating its original request returns
the same identity. Free with `marmot_local_send_acceptance_free`.
See [local sends](../marmot-uniffi/LOCAL-SENDS.md).

[Header contract](include/marmot.h#L6622)

### `marmot_upload_media_with_client_token`

```c
MarmotStatus marmot_upload_media_with_client_token(const struct MarmotClient *client, const char *account_ref, const char *group_id_hex, const struct MarmotMediaUploadRequest *request, const char *client_token, struct MarmotMediaUploadSubmission **out);
```

Block for upload and optional durable message admission. Inputs are borrowed;
free the result with `marmot_media_upload_submission_free`. Uploads are not
idempotent: query token status after an unknown outcome before repeating them.
See [local sends](../marmot-uniffi/LOCAL-SENDS.md) for epoch and cancellation semantics.

[Header contract](include/marmot.h#L8168)

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

[Header contract](include/marmot.h#L8877)

</details>
