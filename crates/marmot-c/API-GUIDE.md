# Complete Marmot C symbol reference

All **C functions declared in the generated header** are indexed below, including constructors,
commands, opaque-object operations, callbacks, free functions and compatibility shims.
Read [the C integration guide](README.md) first; this index does not replace its memory,
threading or error rules. The [shared method reference](../marmot-uniffi/API-GUIDE.md)
explains which runtime methods to use. The generated reference adds C declarations and
links to `include/marmot.h`. Use the header from the same release as the library for
record layouts, discriminants, callback typedefs, and safety comments.

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
new media UI. Older primitives remain supported.

Add guidance here for each new C function and remove entries for deleted functions.
`just binding-docs-gate` generates the header and both references. It requires one entry
per exported function; review the prose against the implementation separately.

<details>
<summary>marmot_a…</summary>

### `marmot_answer_sign_in`

Answer the unrecognized sign-in in `slot_id_hex`. `response` is a `MarmotSignInResponse` discriminant passed as `uint32_t`: `NotNow` keeps it listed with no prompt, `Reject` records it as rejected in the device group's roster (now, or once this device has a quiet device group), and `Dismiss` only ends a prompt another device already answered. An out-of-range `response` is `MARMOT_STATUS_INVALID_ARGUMENT`; refusals such as an unknown or already answered sign-in are device-group errors. Blocks on the account worker; a rejection may commit to the device group.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotanswer_sign_in)

### `marmot_attachment_handoff_free`

Free a `MarmotAttachmentHandoff` record and its strings. This frees memory only: it does not release the lease or delete the copy; call `marmot_release_attachment_handoff` for that. NULL is a no-op.

### `marmot_attachment_local_asset_list_free`

Free a list returned by this library. NULL is a no-op.

### `marmot_attachment_local_bytes_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_attachment_local_assets`

Look up up to 64 original slots in one group, preserving input order/duplicates. Does not load bytes, enqueue demand, start a worker or perform network work. # Safety Client/strings and targets[0..targets_len] must be live. Targets may be NULL only with zero length. Out must be writable. Inputs are borrowed, outputs owned.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotattachment_local_assets)

### `marmot_attachment_entry_free`

Deep-free one standalone owned entry returned by `marmot_reaction_attachment`, including all nested metadata. NULL is a no-op. Never pass a borrowed entry from an attachment page; the page owns those entries. The pointer must be NULL or an unfreed standalone result returned by this library.

### `marmot_reaction_attachment`

Bounded local lookup of one active custom-emoji reaction's matching encrypted artwork, keyed by the exact reaction event ID within the account and chat. Call off the UI thread. Writes an owned `MarmotAttachmentEntry`, or NULL with `MARMOT_STATUS_OK` when unavailable or unmatched. Use its original source target with ordinary attachment acquisition and opaque local reads, then free the standalone result with `marmot_attachment_entry_free`. Inputs are borrowed; the required out-pointer is cleared before work. The reaction ID is exactly 64 hexadecimal characters; malformed IDs return `MARMOT_STATUS_INVALID_MEDIA_REFERENCE`. See the [shared reaction lookup limits and adoption contract](../marmot-uniffi/ATTACHMENT-HISTORY.md#reaction-artwork).

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotreaction_attachment)

### `marmot_attachment_page_read_free`

Deep-free a page result and its cursor/version. NULL is a no-op. # Safety Value must be NULL or an owned result, not freed or borrowed by an active call.

### `marmot_attachment_history_version_free`

Free a standalone version returned by a version read or clone, not a page field. # Safety Value must be NULL or a standalone owned version, with no active borrows.

### `marmot_attachment_history_version_clone`

Retain a standalone baseline version without retaining its owning page. Free the result with marmot_attachment_history_version_free. # Safety Value must be a live standalone version or borrowed page field; out must be writable.

### `marmot_attachment_history_page`

Blocking local read. Call off the UI thread; limit is 1..=100 slots. NULL cursor starts at the head. Cursor is borrowed for this call; no network work starts. # Safety Client and strings must be live; cursor must be NULL or live; out must be writable.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotattachment_history_page)

### `marmot_attachment_history_version`

Blocking local revision read, including after exhaustion. Free the standalone result. # Safety Client/strings must be live and out writable.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotattachment_history_version)

### `marmot_attachment_history_version_change_since`

Compare a current version with the retained baseline. Output is a MarmotAttachmentHistoryChange discriminant. # Safety Both versions must be live (standalone or borrowed page fields); out must be writable.

### `marmot_account_unread_summary`

Per-account unread aggregates for the account-switcher badge. Free with `marmot_account_unread_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotaccount_unread_summary)

### `marmot_approve_onboarding_repair_in_epoch`

Approve using the epoch and revision from the same displayed snapshot.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotapprove_onboarding_repair_in_epoch)

### `marmot_acknowledge_onboarding_single_device_in_epoch`

Acknowledge the displayed device notice in a recovered attempt.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotacknowledge_onboarding_single_device_in_epoch)

### `marmot_acknowledge_onboarding_single_device`

Acknowledge the displayed one-device notice and resume setup.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotacknowledge_onboarding_single_device)

### `marmot_account_nip65_relays`

The account's NIP-65 relay list. Free with `marmot_string_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotaccount_nip65_relays)

### `marmot_account_inbox_relays`

The account's inbox relay list. Free with `marmot_string_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotaccount_inbox_relays)

### `marmot_account_key_packages`

Local + current-slot relay-published KeyPackages for the account. Free with `marmot_account_key_package_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotaccount_key_packages)

### `marmot_account_key_package_relay_events`

Observed relay KeyPackage history, including superseded events. Free with `marmot_account_key_package_relay_event_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotaccount_key_package_relay_events)

### `marmot_accept_group_invite`

Accept a pending group invite; writes the now-confirmed group record. Free with `marmot_app_group_record_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotaccept_group_invite)

### `marmot_account_relay_lists`

The account's full relay-list state. Free with `marmot_account_relay_lists_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotaccount_relay_lists)

### `marmot_attachment_storage_by_chat`

Blocking largest-first chat listing, `limit` 1..=256. Pass NULL for the first page, then the previous page's `next_cursor`, keeping that page alive for the call; stop when it is NULL. Free each page with `marmot_chat_storage_page_free`, which frees its cursor too. See the [shared contract](../marmot-uniffi/API-GUIDE.md#marmotattachment_storage_by_chat).

### `marmot_attachment_storage_usage`

Blocking account-wide storage summary; call off the UI thread. Free the result with `marmot_attachment_storage_usage_free`. See the [shared contract](../marmot-uniffi/API-GUIDE.md#marmotattachment_storage_usage).

### `marmot_attachment_storage_usage_free`

Free a `MarmotAttachmentStorageUsage`. NULL is a no-op.

### `marmot_audit_log_settings`

Current audit-log recorder settings. Free with `marmot_audit_log_settings_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotaudit_log_settings)

### `marmot_audit_log_retention`

Current local audit-log retention policy. Free with `marmot_audit_log_retention_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotaudit_log_retention)

### `marmot_audit_log_files`

On-disk audit-log files. Free with `marmot_audit_log_file_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotaudit_log_files)

### `marmot_account_follows`

The account ids this account follows (NIP-02). Free with `marmot_string_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotaccount_follows)

### `marmot_acknowledge_disband_failure`

Acknowledge a failed disband request so the UI can stop surfacing it. Writes whether a request was actually cleared.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotacknowledge_disband_failure)

### `marmot_account_setup_readiness`

How far the account's setup has progressed.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotaccount_setup_readiness)

### `marmot_account_id_hex`

Hex account id for an `npub`/hex/`nprofile` reference; NULL with `MARMOT_STATUS_OK` when the input does not decode. Accepts hex, `npub`, `nostr:npub`, `nprofile`, `nostr:nprofile`, and `marmot://profile/` links. nprofile relay hints are discarded. Duplicate type-0 TLV entries keep the first key. After wrapper normalization, encoded tokens longer than 1023 UTF-8 bytes are rejected; a valid 1023-byte token still decodes when wrapped. Free with `marmot_string_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotaccount_id_hex)

### `marmot_app_performance_snapshot`

Process-wide performance counters. Aggregates only — no account, group, relay, or path information. Free with `marmot_app_performance_snapshot_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotapp_performance_snapshot)

### `marmot_approve_onboarding_repair`

Approve the proposal at the current snapshot revision and resume publication; stale revisions are rejected. Free the returned snapshot with `marmot_onboarding_snapshot_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotapprove_onboarding_repair)

### `marmot_attachment_transfer_subscription_next`

Initial snapshot then replacements, at most four per second. Zero timeout waits indefinitely. Timeout does not consume updates. Free results with marmot_attachment_transfer_snapshot_free. # Safety Sub must be live and out writable. Use one receiver per handle.

### `marmot_attachment_transfer_subscription_cancel`

Close observation and wake receivers. Does not cancel downloads. # Safety Sub must remain live throughout the call.

### `marmot_attachment_transfer_subscription_free`

NULL-safe free. Already returned snapshots remain separately owned. # Safety Sub must be NULL or library-owned with no active calls.

### `marmot_account_attention_subscription_snapshot`

Take the initial snapshot once; a second call returns CLOSED. Result must be deep-freed. # Safety sub must be live and out writable.

### `marmot_account_attention_subscription_next`

Receive a complete replacement. Zero timeout waits indefinitely. Timeout/error/closed leaves out NULL. Timeout does not consume an update. Free results with the matching snapshot_free. # Safety sub must remain live throughout the call; out must be writable. Use one receiver per handle.

### `marmot_account_attention_subscription_free`

Cancel and free. NULL is a no-op; does not free previously returned snapshots. # Safety sub must be NULL or a library-owned handle with no active calls.

### `marmot_account_summary_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_account_summary_list_free`

Free a list returned by this library. NULL is a no-op.

### `marmot_account_unread_list_free`

Free a list returned by this library. NULL is a no-op.

### `marmot_account_key_package_list_free`

Free a list returned by this library. NULL is a no-op.

### `marmot_account_key_package_inventory_entry_list_free`

Free a list returned by this library. NULL is a no-op.

### `marmot_account_key_package_relay_event_list_free`

Free a list returned by this library. NULL is a no-op.

### `marmot_audit_log_settings_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_audit_log_retention_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_audit_log_source_free`

Free the stored source copy returned by `marmot_set_audit_log_source`. NULL is a no-op.

### `marmot_audit_log_file_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_audit_log_file_list_free`

Free a list returned by this library. NULL is a no-op.

### `marmot_audit_log_delete_result_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_app_group_record_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_app_group_record_list_free`

Free a list returned by this library. NULL is a no-op.

### `marmot_app_group_member_record_list_free`

Free a list returned by this library. NULL is a no-op.

### `marmot_app_group_mls_state_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_app_quarantined_group_list_free`

Free a list returned by this library. NULL is a no-op.

### `marmot_app_group_member_ids_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_app_group_member_ids_list_free`

Free a list returned by this library. NULL is a no-op.

### `marmot_app_message_record_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_app_message_record_list_free`

Free a list returned by this library. NULL is a no-op.

### `marmot_account_relay_lists_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_app_performance_snapshot_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_account_attention_snapshot_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_avatar_asset_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_avatar_asset_list_free`

Free a list returned by this library. NULL is a no-op.

### `marmot_avatar_bytes_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_avatar_bytes_list_free`

Free a list returned by this library. NULL is a no-op.

### `marmot_attachment_download_policy_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_attachment_transfer_snapshot_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_attachment_download_policy`

Read the effective durable policy. # Safety Client and strings must be live, out writable. Free the returned record.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotattachment_download_policy)

### `marmot_attachment_transfer_snapshot`

Read up to 64 progress entries in input order. No network demand is created. # Safety Inputs must be live; targets may be NULL only for zero length; out writable.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotattachment_transfer_snapshot)

### `marmot_group_app_component_free`

Free a record returned by `marmot_group_app_component`. NULL is a no-op.

### `marmot_group_commit_delivery_free`

Free a record returned by `marmot_group_commit_delivery`. NULL is a no-op.

### `marmot_group_pending_commit_free`

Free a record returned by `marmot_group_pending_commit`, with its relay lists. NULL is a no-op.

</details>

<details>
<summary>marmot_b…</summary>

### `marmot_bytes_free`

Free a byte buffer returned by this library as a `(data, len)` pair (e.g. `marmot_download_group_blossom_image`). `(NULL, 0)` is a no-op.

### `marmot_block_user`

Block a user privately and publish the updated list. Requires relay synchronization.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotblock_user)

### `marmot_build_media_imeta_tag`

Build the NIP-92 `imeta` tag for an already-uploaded attachment, so a host can compose the outgoing event itself. Free with `marmot_message_tag_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotbuild_media_imeta_tag)

### `marmot_begin_onboarding`

Import an identity and persist its onboarding gate without publishing. Free the returned snapshot with `marmot_onboarding_snapshot_free`.

Snapshot findings include typed context, purpose, outcome, declared capability,
owned actions and optional observation revision. The snapshot free releases
those nested arrays. See [C diagnostic ownership](README.md#onboarding-relay-repair)
and the shared evidence limits before interpreting directory-query success.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotbegin_onboarding)

### `marmot_block_list_subscription_next`

Block until the next item, the timeout, or stream close. `timeout_ms == 0` waits indefinitely. Returns `MARMOT_STATUS_OK` (out set; free with `marmot_block_list_snapshot_free`), `MARMOT_STATUS_TIMEOUT`, or `MARMOT_STATUS_CLOSED` (out NULL for both).

### `marmot_block_list_subscription_set_callback`

Install a callback pump for this subscription. `callback` runs on a runtime worker thread with a borrowed item pointer (valid only during the call; do not store or free it) and a final NULL item on close. `callback` and `user_data` access must be thread-safe. Fails if a callback is already installed.

### `marmot_block_list_subscription_clear_callback`

Request cancellation of this subscription's callback pump, if any. Non-blocking: a callback already running keeps executing after this returns (see the module docs).

### `marmot_block_list_subscription_free`

Free the subscription handle. Requests callback-pump cancellation without waiting (a callback may still be running after this returns — do not free `user_data` on that basis). NULL is a no-op. Free every handle before the client that created it.

### `marmot_block_list_subscription_snapshot`

Take the initial snapshot once; subsequent calls return NULL. # Safety Subscription and output pointer must be valid.

### `marmot_background_notification_collection_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_blocked_user_list_free`

Free a list returned by this library. NULL is a no-op.

### `marmot_block_list_snapshot_free`

Free a value of this type returned by this library. NULL is a no-op.

</details>

<details>
<summary>marmot_c…</summary>

### `marmot_chat_storage_page_free`

Deep-free a chat storage page, its rows and its borrowed cursor. NULL is a no-op.

### `marmot_check_sign_ins`

Check the account's KeyPackage slots for new sign-ins now and write the list after the check; blocks on the account worker and the network. A read that reached no relay fails and leaves the list unchanged. Free the list with `marmot_unrecognized_sign_in_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotcheck_sign_ins)

### `marmot_client_new_with_options`

Create a client with an explicit relay policy, optional host secret store and the required deployment. `store == NULL` selects the platform keychain. Loopback opt-in does not permit private/link-local relays or plaintext public endpoints. Ownership of the store transfers only on success, as with `marmot_client_new_with_secret_store`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotnew_with_options)

### `marmot_client_new`

Create a Marmot client rooted at `root_path`, connected to `relay_urls` (`relay_urls_len` entries), for the required `deployment`, which is copied during the call. A NULL deployment returns `MARMOT_STATUS_NULL_POINTER` before anything opens. On success writes the new handle to `out_client`. Uses the platform keychain under the deployment's keychain service, matching the UniFFI constructor.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotnew)

### `marmot_client_new_with_cursor_persistence`

Create a Marmot client with an explicit durable transport-cursor policy. Identical to `marmot_client_new`, which is `MARMOT_CURSOR_PERSISTENCE_ADVANCE`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotnew_with_cursor_persistence)

### `marmot_client_new_with_secret_store`

Create a Marmot client whose account signing keys live in caller-owned storage instead of the platform keychain. Otherwise identical to `marmot_client_new`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotnew_with_secret_store)

### `marmot_client_new_with_client_name`

Open with an optional public client name for newly prepared KeyPackages and the required deployment. NULL, whitespace-only or over-long (more than 64 bytes once trimmed) `client_name` omits the tag; it is never truncated. Signed retries keep their original tags. NULL `store` selects the platform keychain. Store ownership transfers only on success, as with `marmot_client_new_with_secret_store`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotnew_with_client_name)

### `marmot_client_new_with_configuration`

Create a client with combined relay, cursor, label and secret-storage options and the required deployment, copied during the call. NULL options uses defaults; a NULL deployment is refused, as with `marmot_client_new`. Store ownership transfers only on success, with the same callback lifetime contract as marmot_client_new_with_secret_store.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotnew_with_configuration)

### `marmot_client_new_with_experimental_device_groups`

The same open as `marmot_client_new_with_configuration`, with the same arguments and `MarmotClientOptions` layout: every constructor opens with [device groups](README.md#device-groups) on. Kept so existing hosts keep linking.

### `marmot_client_start`

Start the runtime (reconcile accounts, start workers, subscribe transport). Must be called before subscribing.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotstart)

### `marmot_client_shutdown`

Shut the runtime down. Open subscriptions drain and report `MARMOT_STATUS_CLOSED` from their next read.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotshutdown)

### `marmot_client_is_stopping`

Whether the runtime is currently shutting down. Writes to `out_stopping`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotis_stopping)

### `marmot_client_free`

Destroy a client handle. Call `marmot_client_shutdown` first for a graceful stop. NULL is a no-op. The handle must not be used afterwards.

### `marmot_clear_avatar_cache`

Remove this account's local avatar bytes and demand. Later visible requests may reacquire them.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotclear_avatar_cache)

### `marmot_cancel_onboarding`

Cancel unfinished onboarding, retaining the signed-out identity and private state. Cancellation is valid at every interactive step, including approved or ready attempts. It performs no relay deletion.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotcancel_onboarding)

### `marmot_create_identity`

Create a brand-new Nostr identity, store its secret in the account secret store, and publish initial relay lists + key package. Free with `marmot_account_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotcreate_identity)

### `marmot_start_direct_chat`

Blocks on the shared explicit direct-conversation start operation. `account_ref` and the hex or npub `peer_account_id` are borrowed NUL-terminated UTF-8 strings. `out` is required and receives an owned hex MLS group id on success; free it with `marmot_string_free`. Success confirms canonical local state, not Welcome delivery. Local reuse, retry recovery, founding admins, concurrent starts, and legacy role limits follow the shared contract.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotstart_direct_conversation)

### `marmot_start_direct_chat_with_options`

`marmot_start_direct_chat` with a borrowed `MarmotDirectConversationOptions` carrying the founding `disappearing_message_secs`; `0` behaves exactly like `marmot_start_direct_chat`. `options` and `out` are required. The duration applies only when the call creates the group: reuse, retry and concurrent starts return the existing group with its founding duration and roles, whatever duration they propose.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotstart_direct_conversation_with_options)

### `marmot_create_group`

Create an MLS group with the available members (`npub` or hex account id), returning ordered per-account outcomes. The result's `group_id_hex` is NULL when a nonempty request has no available members; no group is created. Empty member input still creates a creator-only group. Free the whole result with `marmot_group_creation_free`, not its nested fields.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotcreate_group)

### `marmot_confirm_group_rejoin`

Only after explicit recipient consent. Free with marmot_group_recovery_status_free.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotconfirm_group_rejoin)

### `marmot_catch_up_accounts`

One-time catch-up across every running account (e.g. after a push wake).

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotcatch_up_accounts)

### `marmot_clear_push_registration`

Remove the account's push registration and share the removal. Free with `marmot_push_registration_share_outcome_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotclear_push_registration)

### `marmot_chat_list`

The account's chat list rows. Free with `marmot_chat_list_row_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotchat_list)

### `marmot_chat_notification_settings`

The conversation's local mute state. Free with `marmot_chat_notification_settings_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotchat_notification_settings)

### `marmot_clear_chat_muted`

Unmute a conversation. Free with `marmot_chat_notification_settings_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotclear_chat_muted)

### `marmot_chat_list_row`

The durable chat-list row for one group; writes NULL with `MARMOT_STATUS_OK` when the group has no row. Free with `marmot_chat_list_row_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotchat_list_row)

### `marmot_clear_group_image`

Clear the group's encrypted Blossom avatar by committing the absent image component. Requires admin. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotclear_group_image)

### `marmot_client_shutdown_and_close`

Shut the runtime down and release every local file lock, so a host can suspend without leaving the database leased. The client handle stays valid but the runtime is finished.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotshutdown_and_close)

### `marmot_create_identity_with_profile`

Create a fresh identity and publish a default profile in one step. Free with `marmot_identity_creation_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotcreate_identity_with_profile)

### `marmot_create_identity_with_initial_profile`

Create a fresh identity whose first public kind-0 is `profile`, returning at durable local readiness. Prefer it over `marmot_create_identity_with_profile` plus `marmot_publish_user_profile` when onboarding collects a name, so contacts never see the generated default. `profile` is borrowed and never freed by the library. Free the result with `marmot_identity_creation_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotcreate_identity_with_initial_profile)

### `marmot_cached_identity_projections`

What the local directory cache holds for each requested id, one row per request in order. Free with `marmot_cached_identity_projection_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotcached_identity_projections)

### `marmot_create_group_detailed`

`marmot_create_group` plus the durable chat-list row when a group is created. `created` may be NULL; `member_outcomes` remains available. Free the whole result with `marmot_detailed_creation_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotcreate_group_detailed)

### `marmot_create_group_with_prepared_initial_image`

Create a group whose avatar is an already-staged prepared image, returning an optional group id and ordered member outcomes. A consumed upload returns its original group and stored selection report. A legacy or unreadable report returns `MARMOT_STATUS_CREATED_GROUP_MEMBER_REPORT_UNAVAILABLE` with the canonical group id in the error detail. Free successful results with `marmot_group_creation_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotcreate_group_with_prepared_initial_image)

### `marmot_collect_notifications_after_wake`

Run a bounded background collection pass after a push wake. `source` is a `MarmotNotificationWakeSource` discriminant; out-of-range values are rejected with `MARMOT_STATUS_INVALID_ARGUMENT`. Free with `marmot_background_notification_collection_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotcollect_notifications_after_wake)

### `marmot_create_group_with_options`

Create a group with description, an optional initial avatar, and disappearing-message retention. Returns the same optional group id and ordered member outcomes as `marmot_create_group`. Free with `marmot_group_creation_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotcreate_group_with_options)

### `marmot_create_group_with_options_detailed`

`marmot_create_group_with_options` plus the durable chat-list row when a group is created. The optional `created` field and member outcomes share one owned root; free it with `marmot_detailed_creation_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotcreate_group_with_options_detailed)

### `marmot_create_group_with_initial_image`

Create a group with an inline initial avatar; `initial_image` may be NULL. Returns the same optional group id and ordered member outcomes as `marmot_create_group`. Free with `marmot_group_creation_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotcreate_group_with_initial_image)

### `marmot_create_group_with_initial_image_detailed`

`marmot_create_group_with_initial_image` plus the durable chat-list row when a group is created. Free the optional `created` field and member outcomes together with `marmot_detailed_creation_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotcreate_group_with_initial_image_detailed)

### `marmot_classify_relay_endpoints`

Classify relay endpoints against the dial-safety and retired-relay policies without dialing any of them. Free with `marmot_relay_endpoint_classification_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotclassify_relay_endpoints)

### `marmot_continue_onboarding_without`

Explicitly skip an optional profile or follows step when offered. `step` is a MarmotOnboardingStep discriminant; out-of-range values return MARMOT_STATUS_INVALID_ARGUMENT. Free the returned snapshot with `marmot_onboarding_snapshot_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotcontinue_onboarding_without)

### `marmot_cancel_onboarding_repair`

Dismiss an unapproved repair proposal; an approved repair must be resumed. Free the returned snapshot with `marmot_onboarding_snapshot_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotcancel_onboarding_repair)

### `marmot_content_reports`

# Safety `client` must be a live handle; string arguments must be valid NUL-terminated strings (nullable ones may be NULL); array arguments must hold their stated length (or be NULL with length 0); out-pointers must be valid.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotcontent_reports)

### `marmot_chats_subscription_next`

Block until the next item, the timeout, or stream close. `timeout_ms == 0` waits indefinitely. Returns `MARMOT_STATUS_OK` (out set; free with `marmot_app_group_record_free`), `MARMOT_STATUS_TIMEOUT`, or `MARMOT_STATUS_CLOSED` (out NULL for both).

### `marmot_chats_subscription_set_callback`

Install a callback pump for this subscription. `callback` runs on a runtime worker thread with a borrowed item pointer (valid only during the call; do not store or free it) and a final NULL item on close. `callback` and `user_data` access must be thread-safe. Fails if a callback is already installed.

### `marmot_chats_subscription_clear_callback`

Request cancellation of this subscription's callback pump, if any. Non-blocking: a callback already running keeps executing after this returns (see the module docs).

### `marmot_chats_subscription_free`

Free the subscription handle. Requests callback-pump cancellation without waiting (a callback may still be running after this returns — do not free `user_data` on that basis). NULL is a no-op. Free every handle before the client that created it.

### `marmot_chats_subscription_snapshot`

Take the initial chats snapshot. Yields the populated list exactly once: later calls write an EMPTY list, still with `MARMOT_STATUS_OK`. Free the list with `marmot_app_group_record_list_free`.

### `marmot_chat_list_subscription_next`

Block until the next item, the timeout, or stream close. `timeout_ms == 0` waits indefinitely. Returns `MARMOT_STATUS_OK` (out set; free with `marmot_chat_list_row_free`), `MARMOT_STATUS_TIMEOUT`, or `MARMOT_STATUS_CLOSED` (out NULL for both).

### `marmot_chat_list_subscription_set_callback`

Install a callback pump for this subscription. `callback` runs on a runtime worker thread with a borrowed item pointer (valid only during the call; do not store or free it) and a final NULL item on close. `callback` and `user_data` access must be thread-safe. Fails if a callback is already installed.

### `marmot_chat_list_subscription_clear_callback`

Request cancellation of this subscription's callback pump, if any. Non-blocking: a callback already running keeps executing after this returns (see the module docs).

### `marmot_chat_list_subscription_free`

Free the subscription handle. Requests callback-pump cancellation without waiting (a callback may still be running after this returns — do not free `user_data` on that basis). NULL is a no-op. Free every handle before the client that created it.

### `marmot_chat_list_subscription_snapshot`

Take the initial chat-list snapshot. Yields the populated list exactly once: later calls write an EMPTY list, still with `MARMOT_STATUS_OK`. Free with `marmot_chat_list_row_list_free`.

### `marmot_chat_list_subscription_next_update`

Block until the next raw chat-list delta (row upsert or removal). Free with `marmot_chat_list_subscription_update_free`.

### `marmot_chat_list_window_subscription_snapshot`

Take the initial snapshot once; a second call returns CLOSED. Result must be deep-freed. # Safety sub must be live and out writable.

### `marmot_chat_list_window_subscription_next`

Receive a complete replacement. Zero timeout waits indefinitely. Timeout/error/closed leaves out NULL. Timeout does not consume an update. Free results with the matching snapshot_free. # Safety sub must remain live throughout the call; out must be writable. Use one receiver per handle.

### `marmot_chat_list_window_subscription_free`

Cancel and free. NULL is a no-op; does not free previously returned snapshots. # Safety sub must be NULL or a library-owned handle with no active calls.

### `marmot_chat_list_window_subscription_page`

Apply a window command to the current viewport, returning a complete replacement. May run while next waits. Background content changes keep a sequence usable; one older than a published viewport move, or not yet published, returns CHAT_WINDOW_STALE. The same completion also arrives through next; deduplicate by generation/sequence. # Safety sub must be live, any input string valid, and out writable. Never free during a call.

### `marmot_chat_list_window_subscription_set_visible_anchor`

Apply a window command to the current viewport, returning a complete replacement. May run while next waits. Background content changes keep a sequence usable; one older than a published viewport move, or not yet published, returns CHAT_WINDOW_STALE, as does an older sequence whose anchor row a background replacement dropped. The same completion also arrives through next; deduplicate by generation/sequence. # Safety sub must be live, any input string valid, and out writable. Never free during a call.

### `marmot_chat_list_window_subscription_return_to_top`

Apply a window command to the current viewport, returning a complete replacement. May run while next waits. Background content changes keep a sequence usable; one older than a published viewport move, or not yet published, returns CHAT_WINDOW_STALE. The same completion also arrives through next; deduplicate by generation/sequence. # Safety sub must be live, any input string valid, and out writable. Never free during a call.

### `marmot_conversation_window_subscription_snapshot`

Take the initial snapshot once; a second call returns CLOSED. Result must be deep-freed. # Safety sub must be live and out writable.

### `marmot_conversation_window_subscription_next`

Receive a complete replacement. Zero timeout waits indefinitely. Timeout/error/closed leaves out NULL. Timeout does not consume an update. Free results with the matching snapshot_free. # Safety sub must remain live throughout the call; out must be writable. Use one receiver per handle.

### `marmot_conversation_window_subscription_free`

Cancel and free. NULL is a no-op; does not free previously returned snapshots. # Safety sub must be NULL or a library-owned handle with no active calls.

### `marmot_conversation_window_subscription_cancel`

Close and wake pending receivers/commands. Idempotent; does not free this handle or snapshots. # Safety sub must remain live throughout all calls; free only after active calls return.

### `marmot_conversation_window_subscription_page`

Apply against the installed revision. May run while next waits; deduplicate completions by generation/sequence. Zero timeout uses 30 seconds. Accepted commands may complete after timeout through next; refresh before retrying. Extend history around the visible anchor; paging preserves that anchor at the retained-row cap. # Safety sub and borrowed revision/strings must remain live; out writable. Never free during a call.

### `marmot_conversation_window_subscription_set_visible_anchor`

Apply against the installed revision. May run while next waits; deduplicate completions by generation/sequence. Zero timeout uses 30 seconds. Accepted commands may complete after timeout through next; refresh before retrying. Report a row in the installed window as the visible anchor; this does not acknowledge reads or encode pixel offsets. # Safety sub and borrowed revision/strings must remain live; out writable. Never free during a call.

### `marmot_conversation_window_subscription_jump_to_message`

Apply against the installed revision. May run while next waits; deduplicate completions by generation/sequence. Zero timeout uses 30 seconds. Accepted commands may complete after timeout through next; refresh before retrying. Center the window on a retained message; a missing target fails explicitly. # Safety sub and borrowed revision/strings must remain live; out writable. Never free during a call.

### `marmot_conversation_window_subscription_return_to_latest`

Apply against the installed revision. May run while next waits; deduplicate completions by generation/sequence. Zero timeout uses 30 seconds. Accepted commands may complete after timeout through next; refresh before retrying. Move to the latest message and resume following arrivals, retaining the current row budget. # Safety sub and borrowed revision/strings must remain live; out writable. Never free during a call.

### `marmot_clear_message_draft_if_revision`

Clear only this selected revision; later edits are preserved. # Safety client, account and revision valid; revision's owning snapshot/draft must remain live; out writable.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotclear_message_draft_if_revision)

### `marmot_chat_pin_state_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_chat_notification_settings_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_chat_list_row_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_chat_list_row_list_free`

Free a list returned by this library. NULL is a no-op.

### `marmot_chat_list_subscription_update_free`

Free a chat-list delta returned by this library. NULL is a no-op.

### `marmot_cached_identity_projection_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_cached_identity_projection_list_free`

Free a list returned by this library. NULL is a no-op.

### `marmot_chat_list_window_snapshot_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_conversation_window_snapshot_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_content_report_page_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_request_explicit_attachment`

Blocking equivalent of [explicit demand](../marmot-uniffi/API-GUIDE.md#marmotrequest_explicit_attachment). Joins/promotes without resetting budgets, backoff or active deadlines. Inputs are borrowed; free the optional opaque result with `marmot_string_free`. NULL means unavailable/suppressed, not a transfer failure. Use separate Retry/Download again operations for deliberate recovery.

### `marmot_control_attachment`

Apply a MarmotAttachmentControl discriminant to an opaque reference. # Safety Client/strings must be live and out writable. No inputs are retained.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotcontrol_attachment)

### `marmot_cancel_device_link`

On the new device, request cancellation of the link. This does not guarantee notification of the other device: cancellation while waiting in `Joining` can end locally without sending a cancellation message. Free the snapshot with `marmot_device_link_snapshot_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotcancel_device_link)

### `marmot_compromise_warning`

List the account's open compromise warning on this device, each item the user has not seen here, the earliest gathered first; blocks on the account worker without network I/O. An empty list means no warning is open. Each `MarmotCompromiseWarningItem` carries its `reason`, the `slot_id_hex` the item names, `key_package_ref_hex` (set only for `MARMOT_COMPROMISE_WARNING_REASON_FOREIGN_OWN_SLOT_KEY_PACKAGE`) and `occurred_at`. `reason` is a `MarmotCompromiseWarningReason` discriminant carried as `uint32_t`: later releases add values, so show one the host does not know as a generic reason. Always empty unless the host turns device groups on. Re-read on `MARMOT_EVENT_COMPROMISE_WARNING_CHANGED`. Free the list with `marmot_compromise_warning_item_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotcompromise_warning)

### `marmot_compromise_warning_item_list_free`

Free a list returned by this library. NULL is a no-op.

### `marmot_confirm_device_link_match`

On the new device, record that the user says both screens show the same emoji. Free the snapshot with `marmot_device_link_snapshot_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotconfirm_device_link_match)

</details>

<details>
<summary>marmot_d…</summary>

### `marmot_delete_account_key_package`

Publish a NIP-09 deletion for a KeyPackage event. Writes the accepting-relay count.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotdelete_account_key_package)

### `marmot_delete_group_local`

Delete this group's local app data without an MLS leave. Cancel active UI subscriptions for the group first. MLS state stays intact; a future fresh delivery can recreate a chat row. Writes true if any local rows or a live route were removed.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotdelete_group_local)

### `marmot_decline_group_rejoin`

Decline the selected replacement offer without changing active group state.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotdecline_group_rejoin)

### `marmot_dismiss_compromise_warning`

Dismiss the compromise warning on this device: everything it gathers now is marked seen here, and it stays closed until a new rejection arrives; blocks on the account worker. Other devices' warnings are unchanged. While device groups are off it is refused with a device-group error.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotdismiss_compromise_warning)

### `marmot_dismiss_history_notice`

Dismiss one "history may be incomplete" notice after the user accepts it; blocks until the account worker has durably retired that occurrence as its own outcome, never as recovered history. Writes true on retirement and false for a stale id (new evidence re-armed recovery, or it was already dismissed). A malformed id returns `MARMOT_STATUS_INVALID_HEX`. No network I/O.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotdismiss_history_notice)

### `marmot_decline_group_invite`

Decline a pending group invite; writes the updated group record plus the decline publish summary. An invitee the invite made an admin fails with `MARMOT_STATUS_ADMIN_CANNOT_SELF_REMOVE` until `marmot_self_demote_admin`, unless device groups are on (the default). Free with `marmot_group_invite_decline_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotdecline_group_invite)

### `marmot_download_group_blossom_image`

Fetch, verify, and decrypt the group's Blossom-hosted encrypted image. Needs a relay/Blossom, so it fails offline. Free the buffer with `marmot_bytes_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotdownload_group_blossom_image)

### `marmot_demote_admin`

Revoke `member_ref`'s admin rights. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotdemote_admin)

### `marmot_demote_admin_detailed`

`marmot_demote_admin` plus refreshed details and management state. Free with `marmot_group_mutation_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotdemote_admin_detailed)

### `marmot_delete_message`

Request deletion of an own message. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotdelete_message)

### `marmot_delete_audit_log_file`

Delete one on-disk audit-log file. Free with `marmot_audit_log_delete_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotdelete_audit_log_file)

### `marmot_download_profile_image`

Fetch a profile image by URL, refusing anything over `max_bytes`. Free the buffer with `marmot_bytes_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotdownload_profile_image)

### `marmot_delete_message_draft`

Discard the stored draft for a conversation. Absent is not an error.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotdelete_message_draft)

### `marmot_disband_group`

Request terminal disbanding of the group. Writes this account's durable request outcome; free it with `marmot_disband_request_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotdisband_group)

### `marmot_display_name`

Best-effort display name for an account id from the local directory cache; writes NULL with `MARMOT_STATUS_OK` when unknown. Free with `marmot_string_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotdisplay_name)

### `marmot_default_profile_pseudonym`

Deterministic cosmetic display name for a canonical hex account id. Free with `marmot_string_free`. Decode a scanned reference with `marmot_account_id_hex` first; the seed is hashed as supplied text.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotdefault_profile_pseudonym)

### `marmot_download_media`

Download, verify, and decrypt one attachment. Free with `marmot_media_download_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotdownload_media)

### `marmot_dismiss_reports`

# Safety `client` must be a live handle; string arguments must be valid NUL-terminated strings (nullable ones may be NULL); array arguments must hold their stated length (or be NULL with length 0); out-pointers must be valid.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotdismiss_reports)

### `marmot_disband_request_free`

Free a disband request returned by `marmot_disband_group`. NULL is a no-op. (Embedded copies inside a chat row are released by the row.)

### `marmot_download_attachment_again`

Explicitly request the current slot, including after cancellation/removal. NULL result is unavailable. # Safety Client, strings and target must be live; out writable. Free returned string with marmot_string_free.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotdownload_attachment_again)

### `marmot_decline_device_link`

On a device already signed in, Not now for the prompt `prompt_id`. Free the snapshot with `marmot_device_link_snapshot_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotdecline_device_link)

### `marmot_device_link_snapshot`

Linking as this device shows it now, changing nothing. `new_device` is NULL unless this device asked to be linked; `prompts` lists the sign-ins it can link. The states are C tagged unions: `Comparing` carries `code`/`code_len` emoji, `CannotLink` carries `missing`/`missing_len` strings, and `AddedElsewhere` carries both labels. Re-read on `MARMOT_EVENT_DEVICE_LINK_CHANGED`. Free with `marmot_device_link_snapshot_free`. The snapshot's `chat_progress` gives the approver's remaining Adds or, on the new device, the remaining local joins among the reported chats. An absent entry means unavailable.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotdevice_link_snapshot)

### `marmot_device_link_snapshot_free`

Free a snapshot returned by this library, with every nested emoji, string and prompt. NULL is a no-op.

</details>

<details>
<summary>marmot_e…</summary>

### `marmot_export_encrypted_secret_key`

Export the account's private key NIP-49-encrypted under `passphrase`. Free with `marmot_string_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotexport_encrypted_secret_key)

### `marmot_discard_failed_send`

Remove a failed own send from this device without publishing anything; use it instead of `marmot_delete_message` for a row whose invalidation status is `local_publish_failed`. Read `outcome` before acting: only `Discarded` removed the row. Free with `marmot_discard_failed_send_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotdiscard_failed_send)

### `marmot_discard_failed_send_result_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_edit_message`

Edit an own message's content. Returns `MARMOT_STATUS_INVALID_EDIT_TARGET` unless the target is an available chat message this account sent. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotedit_message)

### `marmot_account_devices_activation`

Whether the account can turn on account-devices in the group now, written to `out`. Ask before offering `marmot_enable_account_devices`. The answer is about the whole group, never which members or devices hold it back.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotaccount_devices_activation)

### `marmot_enable_account_devices`

Turn on account-devices in one admin Commit, only when the user asks; it can never be turned off. Returns `MARMOT_STATUS_ACCOUNT_DEVICES_ACTIVATION_REFUSED` unless `marmot_account_devices_activation` would answer `ELIGIBLE`. Free with `marmot_group_mutation_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotenable_account_devices)

### `marmot_enable_group_disbanding`

Opt the group into disbanding, so a later `marmot_disband_group` is accepted. Requires admin. Free with `marmot_group_mutation_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotenable_group_disbanding)

### `marmot_existing_direct_conversation`

The existing one-to-one conversation with `peer_account_id`, or NULL with `MARMOT_STATUS_OK` when there is none. Check `reusable` before opening it. Free with `marmot_existing_direct_conversation_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotexisting_direct_conversation)

### `marmot_events_subscription_next`

Block until the next item, the timeout, or stream close. `timeout_ms == 0` waits indefinitely. Returns `MARMOT_STATUS_OK` (out set; free with `marmot_event_free`), `MARMOT_STATUS_TIMEOUT`, or `MARMOT_STATUS_CLOSED` (out NULL for both).

### `marmot_events_subscription_set_callback`

Install a callback pump for this subscription. `callback` runs on a runtime worker thread with a borrowed item pointer (valid only during the call; do not store or free it) and a final NULL item on close. `callback` and `user_data` access must be thread-safe. Fails if a callback is already installed.

### `marmot_events_subscription_clear_callback`

Request cancellation of this subscription's callback pump, if any. Non-blocking: a callback already running keeps executing after this returns (see the module docs).

### `marmot_events_subscription_free`

Free the subscription handle. Requests callback-pump cancellation without waiting (a callback may still be running after this returns — do not free `user_data` on that basis). NULL is a no-op. Free every handle before the client that created it.

### `marmot_existing_direct_conversation_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_event_free`

Free an event returned by this library. NULL is a no-op.

</details>

<details>
<summary>marmot_f…</summary>

### `marmot_fetch_sticker_asset`

Downloads one exact sticker after its reference is authorized. Free with `marmot_sticker_asset_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotfetch_sticker_asset)

### `marmot_fetch_sticker_pack`

Fetches one pack and protects that coordinate from discovery eviction. Free with `marmot_sticker_pack_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotfetch_sticker_pack)

### `marmot_forget_group_local`

Reset this group on this account-device without publishing. Deletes local app and MLS state; only a valid Welcome created after the reset can rejoin. Close group UI subscriptions and clear host-owned media caches first. Writes true for a new forget, false if already forgotten.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotforget_group_local)

### `marmot_follow_user`

Follow `user_ref` and publish the updated list, keeping its other tags and content. Writes the new follow set. Returns `MARMOT_STATUS_FOLLOW_LIST_TOO_LARGE`, publishing nothing, when the list has 2,048 follows or more. Free with `marmot_string_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotfollow_user)

### `marmot_flush_product_analytics`

# Safety `client` must be a live handle; string arguments must be valid NUL-terminated strings (nullable ones may be NULL); array arguments must hold their stated length (or be NULL with length 0); out-pointers must be valid.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotflush_product_analytics)

</details>

<details>
<summary>marmot_g…</summary>

### `marmot_group_members`

Membership roster for `group_id_hex`, one row per member account with its `device_count`. Free with `marmot_app_group_member_record_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotgroup_members)

### `marmot_group_details`

Group plus enriched member rows for detail screens, one per member account with its `device_count`. Free with `marmot_group_details_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotgroup_details)

### `marmot_group_management_state`

Current caller permissions plus per-member action availability. Free with `marmot_group_management_state_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotgroup_management_state)

### `marmot_acknowledge_group_catching_up`

After a group change returns `MARMOT_STATUS_GROUP_CATCHING_UP` and the user chooses to continue, record that they accept the change may split the group, then retry the change. Admits one change attempt at the device's current epoch, consumed even if it fails, and is not persisted. Writes false, recording nothing, when the group is not catching up. No network I/O.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotacknowledge_group_catching_up)

### `marmot_acknowledge_group_commit_undelivered`

After a group change returns `MARMOT_STATUS_GROUP_COMMIT_UNDELIVERED` and the user chooses to continue, record that they accept members on relays still owed, or that refused, the group's changes may not follow, then retry the change. Dismisses every relay refusal in the group for good, across restarts too. Admits one change attempt, consumed even if it fails and not persisted, while only the changes owed or refused now gate. Writes false, recording nothing, when no relay is owed or has refused a change of yours. No network I/O.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotacknowledge_group_commit_undelivered)

### `marmot_group_commit_delivery`

The group's oldest change of yours that a group relay refused, until acknowledged, or else the oldest change some group relays have not accepted yet; writes NULL once no relay is owed a change of yours and every relay refusal has been acknowledged. `refused_relays` (`refused_relays_len` entries) lists each refusing relay with its `cause` (`MARMOT_GROUP_COMMIT_REFUSAL_CAUSE_TOO_LARGE`, with `size_class` when `has_size_class`, or `MARMOT_GROUP_COMMIT_REFUSAL_CAUSE_REJECTED`). Group changes return `MARMOT_STATUS_GROUP_COMMIT_UNDELIVERED` at once while it is non-empty; with only owed relays, only once `since` is two minutes old. Poll while showing it. Free with `marmot_group_commit_delivery_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotgroup_commit_delivery)

### `marmot_group_pending_commit`

The group's own commit that has not confirmed yet, or NULL (mdk#2332). While it is pending, group changes return `MARMOT_STATUS_GROUP_COMMIT_PENDING`; disbanding and an admin's leave are still accepted. `state` is `MARMOT_GROUP_PENDING_COMMIT_STATE_SENDING` for its first ten minutes and while no relay may hold it, and `MARMOT_GROUP_PENDING_COMMIT_STATE_STUCK` once some relay may hold it and none has acknowledged it: MDK never gives that up. `queued_intent_id_hex` is NULL unless it carries a queued change of yours; `intent_kind` is NULL for a commit MDK made on its own; read `first_attempt_at` only when `has_first_attempt_at` is true. Poll while showing it. Free with `marmot_group_pending_commit_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotgroup_pending_commit)

### `marmot_group_changes_not_delivered`

The group's changes of yours that were not applied, oldest first (mdk#2332): each one's call answered `CompletionUnknown` (or `AcceptedPending`, queued) and MDK then gave its commit up. A record carries the group, `intent_kind`, `reason` (`not_delivered`, `event_too_large` or `refused`) and `at` (Unix seconds); `queued_intent_id_hex` is NULL for a direct change. Records stay across restarts and later changes until `marmot_acknowledge_change_not_delivered`; `MARMOT_GROUP_EVENT_KIND_GROUP_CHANGE_NOT_DELIVERED` only notifies, so read this on start. A direct change staged by an earlier MDK release and given up after the upgrade is not recorded, so an empty list does not cover those. Free with `marmot_group_change_not_delivered_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotgroup_changes_not_delivered)

### `marmot_acknowledge_change_not_delivered`

Delete one record of `marmot_group_changes_not_delivered` by its `commit_id_hex` once the user has seen it (mdk#2332). Writes false, changing nothing, when the group holds no such record. No network I/O.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotacknowledge_change_not_delivered)

### `marmot_pending_welcome_deliveries`

Write the account's current pending Welcome repair handles to required `out`, which is cleared before input/client work. This local query preserves native filtering and oldest-first order; it does not send another invitation or end delivery debt. Read `size_class` only when `has_size_class` is true; otherwise the cause is Unknown. A class explains the observed refusal, not delivery or non-delivery; earlier legacy exposure can be unknown. `recorded_at` is the local repair-index timestamp in Unix seconds. The pending event remains once per process/Welcome; query for later cause changes, including a specific cause becoming Unknown after a coarse legacy retry. The returned list owns its strings: release the entire result exactly once with `marmot_pending_welcome_delivery_list_free`. Use the matching header/library. See the [shared method guidance](../marmot-uniffi/API-GUIDE.md#marmotpending_welcome_deliveries).

### `marmot_invite_deliveries`

Write the account's invite deliveries (mdk#1706) to required `out`, which is cleared before input/client work: one `MarmotInviteDelivery` per group and invited account, for `group_id_hex` or every group when it is NULL. A local read of durable records; it sends nothing. Only invites sent after this device upgraded are listed; an older Welcome stays in `marmot_pending_welcome_deliveries`. In `MarmotInviteDeliveryState`, read `problem` only when `has_problem` is true and `cancel_reason` only when `kind` is `Cancelled`. `RelayAccepted` means a relay stored the Welcome, not that the recipient received it or joined. The list owns its strings and device arrays: release the entire result exactly once with `marmot_invite_delivery_list_free`. Use the matching header/library. See the [shared method guidance](../marmot-uniffi/API-GUIDE.md#marmotinvite_deliveries).

### `marmot_group_recovery_status`

Query advisory membership health and pending rejoin offers. Free with `marmot_group_recovery_status_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotgroup_recovery_status)

### `marmot_group_mls_state`

Current MLS state (epoch, member count, required components) for the conversation developer/debug view. Free with `marmot_app_group_mls_state_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotgroup_mls_state)

### `marmot_group_push_debug_info`

Per-group push token debug info. Free with `marmot_group_push_debug_info_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotgroup_push_debug_info)

### `marmot_get_blocked_users`

Read the local blocked-user list, newest first. Free with `marmot_blocked_user_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotget_blocked_users)

### `marmot_group_member_ids_page`

Member account and admin ids for several groups in one read, each account once. Free with `marmot_app_group_member_ids_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotgroup_member_ids_page)

### `marmot_group_conversation_snapshot`

Group details and management state in one read. Free with `marmot_group_conversation_snapshot_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotgroup_conversation_snapshot)

### `marmot_group_roster`

The group's member roster at the current MLS epoch, one entry per member account with its `device_count`; `member_count` counts accounts. Free with `marmot_group_roster_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotgroup_roster)

### `marmot_group_maintenance_status`

One group's maintenance state. Free with `marmot_group_maintenance_status_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotgroup_maintenance_status)

### `marmot_group_app_component`

Read application-owned group state for `component_id`. `out` must be a writable pointer-to-pointer. An absent component writes NULL to `*out` and still returns `MARMOT_STATUS_OK`; a written record with `data_len` of `0` is present empty state. Applications allocate ids at or above `0xf000`; every id below that is protocol space and returns `MARMOT_STATUS_INVALID_APP_COMPONENT`. Free with `marmot_group_app_component_free`.

### `marmot_group_state_subscription_next`

Block until the next item, the timeout, or stream close. `timeout_ms == 0` waits indefinitely. Returns `MARMOT_STATUS_OK` (out set; free with `marmot_app_group_record_free`), `MARMOT_STATUS_TIMEOUT`, or `MARMOT_STATUS_CLOSED` (out NULL for both).

### `marmot_group_state_subscription_set_callback`

Install a callback pump for this subscription. `callback` runs on a runtime worker thread with a borrowed item pointer (valid only during the call; do not store or free it) and a final NULL item on close. `callback` and `user_data` access must be thread-safe. Fails if a callback is already installed.

### `marmot_group_state_subscription_clear_callback`

Request cancellation of this subscription's callback pump, if any. Non-blocking: a callback already running keeps executing after this returns (see the module docs).

### `marmot_group_state_subscription_free`

Free the subscription handle. Requests callback-pump cancellation without waiting (a callback may still be running after this returns — do not free `user_data` on that basis). NULL is a no-op. Free every handle before the client that created it.

### `marmot_group_state_subscription_snapshot`

Take the initial group-record snapshot. Yields the record exactly once: later calls write NULL with `MARMOT_STATUS_OK`. Free with `marmot_app_group_record_free`.

### `marmot_group_details_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_group_management_state_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_group_mutation_result_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_group_invite_decline_result_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_group_conversation_snapshot_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_group_roster_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_group_recovery_status_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_group_maintenance_status_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_group_push_debug_info_free`

Free a value of this type returned by this library. NULL is a no-op.

</details>

<details>
<summary>marmot_h…</summary>

### `marmot_history_notices`

List the account's durable "history may be incomplete" notices, oldest first, from local storage; blocks on the account worker without network I/O. Re-read on `MARMOT_EVENT_HISTORY_NOTICES_CHANGED`. Each `MarmotHistoryNotice` carries an opaque `notice_id`, its `cause`, a nullable `group_id_hex` (NULL for an account-wide occurrence) and an optional parking time. Free the list with `marmot_history_notice_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmothistory_notices)

### `marmot_history_notice_list_free`

Free a list returned by this library. NULL is a no-op.

### `marmot_account_recovery_status`

**Current.**

Read the account's recovery from local state; blocks on the account worker without network I/O. The owned `MarmotAccountRecoveryStatus` lists the groups still catching up (`catching_up_group_ids_hex`/`catching_up_group_ids_hex_len`, lowercase hex, sorted), `inbox_catching_up`, and every notice (`notices`/`notices_len`) as `marmot_history_notices` lists them. Re-read on `MARMOT_EVENT_RECOVERY_STATUS_CHANGED`; the recovery runner supplies the catching-up fields. Free it with `marmot_account_recovery_status_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotaccount_recovery_status)

### `marmot_account_recovery_status_free`

**Current.**

Free a status returned by `marmot_account_recovery_status`, its group ids and notices included. NULL is a no-op.

</details>

<details>
<summary>marmot_i…</summary>

### `marmot_import_signal_sticker_pack`

Validates a canonical Signal pack link, then refuses before any network call. The pinned importer cannot be address-pinned, so this command does not download or upload. Free with `marmot_sticker_import_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotimport_signal_sticker_pack)

### `marmot_install_sticker_pack`

After a complete installed-list read, signs the proposed list before saving install intent. A signing refusal does not queue this install. Without a complete read, intent stays pending for a later `marmot_sync_sticker_packs`. Free with `marmot_sticker_pack_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotinstall_sticker_pack)

### `marmot_invite_members`

Invite available members (`npub` or hex account id) into one group Commit. Requires admin. Ordered outcomes report selection, not Welcome delivery. `summary` is NULL and no Commit is created for nonempty all-unavailable input. Empty input and native membership-edit refusals remain errors. Free the whole result with `marmot_invite_members_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotinvite_members)

### `marmot_invite_members_detailed`

`marmot_invite_members` plus refreshed details and management state, including when the invitation is a no-op. Free the whole result with `marmot_group_invite_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotinvite_members_detailed)

### `marmot_initialize_chat_read_state`

Initialize read state for a conversation being opened; writes the refreshed row, or NULL with `MARMOT_STATUS_OK` when the group has no row. Free with `marmot_chat_list_row_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotinitialize_chat_read_state)

### `marmot_is_user_blocked`

Whether the local account currently blocks this public key.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotis_user_blocked)

### `marmot_is_following`

Whether `user_ref` (`npub` or hex account id) is followed.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotis_following)

### `marmot_invite_members_with_initial_admins`

`marmot_invite_members` where selected invitees named in `initial_admin_refs` join as admins in the same Commit. Admin intent must name requested invitees; unavailable invitees receive no role. Free with `marmot_invite_members_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotinvite_members_with_initial_admins)

### `marmot_invite_members_detailed_with_initial_admins`

`marmot_invite_members_with_initial_admins` plus refreshed details and management state. Free the whole result, including its nested invitation outcome, with `marmot_group_invite_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotinvite_members_detailed_with_initial_admins)

### `marmot_identity_creation_result_free`

Free a value of this type returned by this library. NULL is a no-op.

</details>

<details>
<summary>marmot_k…</summary>

### `marmot_key_package_maintenance_status`

The account's KeyPackage slot state; writes NULL with `MARMOT_STATUS_OK` when no slot exists yet. Free with `marmot_key_package_maintenance_status_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotkey_package_maintenance_status)

### `marmot_key_package_maintenance_status_free`

Free a value of this type returned by this library. NULL is a no-op.

</details>

<details>
<summary>marmot_l…</summary>

### `marmot_key_package_refresh_overdue`

Write whether this device's device group has held its KeyPackage refresh back for a week, so the app warns the user before inviters stop treating the device as fresh at 30 days; blocks on the account worker without network I/O. Always false until this device trusts a device group, and unless the host turns device groups on. Re-read on `MARMOT_EVENT_KEY_PACKAGE_REFRESH_OVERDUE_CHANGED`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotkey_package_refresh_overdue)

</details>

<details>
<summary>marmot_l…</summary>

### `marmot_largest_retained_attachments`

Blocking largest-first attachment listing, `limit` 1..=256; `group_id_hex` NULL lists the whole account. Paging and cursor ownership as for `marmot_attachment_storage_by_chat`; free each page with `marmot_retained_attachments_page_free`. See the [shared contract](../marmot-uniffi/API-GUIDE.md#marmotlargest_retained_attachments).

### `marmot_last_error_message`

Return the detail message for the current thread's most recent failed `marmot_*` call, or NULL if there is none. The returned string is an owned copy: free it with `marmot_string_free`. Reading clears the slot.

### `marmot_list_accounts`

List every account known to this device. Free the result with `marmot_account_summary_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotlist_accounts)

### `marmot_login`

Log in with an existing identity: an `nsec` (private key) for a local-signing account, or an `npub` to track a public identity. Free with `marmot_account_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotlogin)

### `marmot_local_account_key_packages`

Local-storage KeyPackage inventory with typed durable provenance. Synchronous SQLCipher I/O on the calling thread; keep it off a UI or main thread. Free with `marmot_account_key_package_inventory_entry_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotlocal_account_key_packages)

### `marmot_leave_group`

Leave as the active account. An admin fails with `MARMOT_STATUS_ADMIN_CANNOT_SELF_REMOVE` until `marmot_self_demote_admin`; with device groups on (the default) core demotes eligible admins, leaves matching linked copies and refuses the last admin, and failure can retain a recorded Decline or committed demotion. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotleave_group)

### `marmot_cancel_leave`

Cancel this account's blocked leave on this device. Offer it while `MarmotGroupManagementState.can_cancel_leave`: the account is the group's last active admin, so the leave cannot finish. The chat reads as joined again. While the group is still settling, or in any other state, it fails with `MARMOT_STATUS_LEAVE_NOT_BLOCKED`. Blocks on the account worker; nothing is published.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotcancel_leave)

### `marmot_list_media`

Stored media records for the group, capped by `limit` when `has_limit`. Free with `marmot_media_record_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotlist_media)

### `marmot_login_recovering_incomplete_setup`

Sign in and finish a setup that was interrupted partway. Free with `marmot_account_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotlogin_recovering_incomplete_setup)

### `marmot_linked_devices`

List this account's own devices from the roster of the device group this device trusts, this device first, then by `linked_at`; blocks on the account worker without network I/O. Empty until this device trusts a device group, and always empty unless the host turns device groups on. Re-read on `MARMOT_EVENT_LINKED_DEVICES_CHANGED`. Each `MarmotLinkedDevice` carries its `slot_id_hex` handle, `is_this_device`, `label`, `client` and `platform` (empty until set), `linked_at`, a nullable `linked_by_slot_id_hex` (NULL for the founder), its `status`, its three settings, `last_active_at` (Unix seconds, valid when `has_last_active_at`: when a heartbeat last showed it running, never for this device) and `inactive` (this device's own judgement, 30 days after the later of that and when it first found the device in the roster). Free the list with `marmot_linked_device_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotlinked_devices)

### `marmot_linked_device_list_free`

Free a list returned by this library. NULL is a no-op.

### `marmot_chat_history_imports`

List the held chats whose history from another of this account's devices is arriving or has arrived; blocks on the account worker without network I/O. Each `MarmotChatHistoryImport` carries its `group_id_hex` and a tagged `state`: `Receiving` (with `retrying` once an attempt to get its bundle failed) while a delivery waits to be imported, or `Imported` with the `MarmotHistoryImportSource` the latest import came from and `at`, in Unix seconds. An empty `device_label` means "another device". Each imported `MarmotTimelineMessageRecord` names the same source in its nullable `imported_from`. Empty while device groups are off. Re-read on `MARMOT_EVENT_CHAT_HISTORY_IMPORTS_CHANGED`, which fires whenever this answer changes, a source device's rename or removal included. Free the list with `marmot_chat_history_import_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotchat_history_imports)

### `marmot_chat_history_import_list_free`

Free a list returned by this library. NULL is a no-op.

### `marmot_link_device`

On a device already signed in, Link device for the prompt `prompt_id`, with the new device's `label` (not blank, at most 64 bytes) and its two settings, both offered on by default. `add_to_all_chats` and `bring_history` are `uint8_t` flags. Free the snapshot with `marmot_device_link_snapshot_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotlink_device)

</details>

<details>
<summary>marmot_m…</summary>

### `marmot_mark_timeline_message_read`

Mark a timeline message read; writes the refreshed row, or NULL with `MARMOT_STATUS_OK`. Free with `marmot_chat_list_row_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotmark_timeline_message_read)

### `marmot_messages`

Stored raw app messages for a group (`group_id_hex` non-NULL) or the whole account (NULL), newest-last, capped by `limit` when `has_limit`. `kinds` restricts the result to those Nostr event kinds; pass NULL with length 0 for every kind. Free with `marmot_app_message_record_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotmessages)

### `marmot_message_drafts`

Every stored draft for the account, attachment metadata only. Free with `marmot_message_draft_summary_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotmessage_drafts)

### `marmot_message_draft`

The stored draft for one conversation, with attachment bytes; writes NULL with `MARMOT_STATUS_OK` when there is none. Free with `marmot_message_draft_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotmessage_draft)

### `marmot_message_edit_history`

Read accepted edit versions separately from screen snapshots. Supply both cursor values, or has_before=0 and a NULL id for the newest page. Limit 1..=100. Free with marmot_timeline_edit_history_page_free. # Safety Client and strings must be valid, before_message_id nullable, out writable.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotmessage_edit_history)

### `marmot_messages_subscription_next`

Block until the next item, the timeout, or stream close. `timeout_ms == 0` waits indefinitely. Returns `MARMOT_STATUS_OK` (out set; free with `marmot_message_update_free`), `MARMOT_STATUS_TIMEOUT`, or `MARMOT_STATUS_CLOSED` (out NULL for both).

### `marmot_messages_subscription_set_callback`

Install a callback pump for this subscription. `callback` runs on a runtime worker thread with a borrowed item pointer (valid only during the call; do not store or free it) and a final NULL item on close. `callback` and `user_data` access must be thread-safe. Fails if a callback is already installed.

### `marmot_messages_subscription_clear_callback`

Request cancellation of this subscription's callback pump, if any. Non-blocking: a callback already running keeps executing after this returns (see the module docs).

### `marmot_messages_subscription_free`

Free the subscription handle. Requests callback-pump cancellation without waiting (a callback may still be running after this returns — do not free `user_data` on that basis). NULL is a no-op. Free every handle before the client that created it.

### `marmot_messages_subscription_snapshot`

Take the initial message-record snapshot. Yields the populated list exactly once: later calls write an EMPTY list, still with `MARMOT_STATUS_OK`. Free with `marmot_app_message_record_list_free`.

### `marmot_message_draft_attachment_if_revision`

Read one selected attachment. found=0 distinguishes absence from an empty acquired attachment. Free returned bytes with marmot_bytes_free; revision conflicts return an error. A file-backed attachment is `MARMOT_STATUS_INVALID_MESSAGE_DRAFT`: read it with `marmot_read_message_draft_attachment`. # Safety client, strings, revision valid; revision's owning draft stays live; all out pointers writable.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotmessage_draft_attachment_if_revision)

### `marmot_message_tag_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_message_draft_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_message_draft_summary_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_message_draft_summary_list_free`

Free a list returned by this library. NULL is a no-op.

### `marmot_member_ref_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_member_key_package_prewarm_summary_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_maintenance_run_summary_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_markdown_document_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_media_upload_result_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_media_download_result_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_media_record_list_free`

Free a list returned by this library. NULL is a no-op.

### `marmot_message_update_free`

Free a message update returned by this library. NULL is a no-op.

</details>

<details>
<summary>marmot_n…</summary>

### `marmot_nip46_pairing_offer`

Install the client-pairing listener and await relay subscription acknowledgements before returning its credential-bearing URI. Display the URI only after this call succeeds, then connect while the pairing UI is visible. Requires explicit permission approval and an unpaired client-initiated session. Blocks; run off the UI thread. Free the URI with `marmot_string_free`.

[Session contract](README.md#nip-46-accounts)

### `marmot_nip46_approve_grants`

Approve the exact version and grants previously returned by review, after user consent. Inputs are borrowed for the call. Missing review or changed grants return `MARMOT_STATUS_EXTERNAL_SIGNER_REJECTED`; no network request starts.

[Session contract](README.md#nip-46-accounts)

### `marmot_nip46_cancel_request`

Cancel one matching pending request without terminally cancelling the session. Stale IDs return `MARMOT_STATUS_INVALID_ARGUMENT`. The string is borrowed for the call.

[Session contract](README.md#nip-46-accounts)

### `marmot_nip46_complete_auth`

Acknowledge the auth challenge identified by the current status request ID. This does not complete its RPC, which still requires the signer's final response. Stale IDs return `MARMOT_STATUS_INVALID_ARGUMENT`.

[Session contract](README.md#nip-46-accounts)

### `marmot_nip46_disconnect`

Interrupt transport work and advance the session generation. A later explicit connect can reconnect; persisted credentials are not removed. May race operations, but never handle free.

[Session contract](README.md#nip-46-accounts)

### `marmot_nip46_ping`

Check the remote signer through the shared transport. Blocks; run off the UI thread. Transport and signer failures use the existing timeout/external-signer status codes.

[Session contract](README.md#nip-46-accounts)

### `marmot_nip46_remove`

Detach the account-scoped shared signer and remove its persisted communication credentials. This does not replace account sign-out or account data wiping. Account input is borrowed; blocks on the runtime.

[Session contract](README.md#nip-46-accounts)

### `marmot_nip46_resume`

Obtain the shared session restored from MDK-owned account credentials, without a host descriptor or callback. Persisted permission approval is retained. Out is cleared before runtime work; free the handle with `marmot_nip46_free` before its creating client. Freeing this handle leaves the account signer and other handles usable.

[Session contract](README.md#nip-46-accounts)

### `marmot_nip46_review_grants`

Record the required permission snapshot and return JSON `version` and `grants` for display. Review does not approve. No network access; free the JSON string with `marmot_string_free`. A NULL out pointer refuses the operation before recording review.

[Session contract](README.md#nip-46-accounts)

### `marmot_nip46_cancel`
 

Permanently cancel the shared session's pending work, including its account signer and other handles, without removing MDK-owned credentials or revoking a saved export. Nonblocking and NULL-safe; may race calls, never free.

### `marmot_nip46_connect`

Connect, verify the pinned user key, and adopt allowed signer relay changes. Run off UI. Free the returned user hex with `marmot_string_free`.

### `marmot_nip46_export`

Return durable client credentials and pinned identities as JSON. Store only in an encrypted vault; never log it. Free with `marmot_string_free`.

### `marmot_nip46_free`

Release only this C handle without cancelling the shared session, remote logout, or removing persisted credentials. MDK retains attached sessions, so account signing and other handles remain usable. An unbound session stops when its final owner drops. Explicit `marmot_nip46_cancel` remains terminal. Join all callers first and free before the creating client. NULL is a no-op.

### `marmot_nip46_login`

Create or reopen an external account using the verified session signer. Requires successful explicit `marmot_nip46_connect` and an already-verified `Ready` session; other states are rejected without connecting, discovering relays, or creating an account. Run off UI; free the returned summary with `marmot_account_summary_free`.
Set `inbox_relays` independently, or pass `NULL, 0` to reuse the default relays.

Admitted Native adoption is runtime-owned: loss of the waiter does not cancel it. Pairing is a separate bounded, caller-cancellable connect call and makes no account changes while unbound. Explicit session cancel, disconnect, or logout interrupts adoption; shutdown interrupts and settles owned work before returning. Never free handles during active calls.

Adoption retains its admission generation through binding and network waits. A later explicit reconnect cannot resume adoption retired by disconnect.

Rollback does not reset newer-generation transport state or cancel its pending requests.

Completed accounts rebind without opening initial setup. Failed Native adoption restores prior local callbacks, records, and activation while preserving setup readiness. Already-published KeyPackages are not retracted. Account sign-out cleanup remains explicit; legacy host login is unchanged.

### `marmot_nip46_logout`

Attempt bounded remote logout and clear local session keys even without acknowledgement. This directly revokes a session, not the MDK account. Account signout already erases owned credentials, so a later logout reports an already logged-out session without another remote request. Run off UI; remove any optional host vault export when revoking credentials.

A vault deletion error leaves signing stopped and retains cleanup ownership. Retry logout or `marmot_nip46_remove` after the vault recovers; a failed deletion does not authorize a fresh pairing over the pending credential.

### `marmot_nip46_new`

Create an offline shared session from a bunker URI, pairing configuration, or exported descriptor. The client must outlive the handle. Review and approve permissions before URI access or connection; imports never silently approve grants. See the session lifecycle for configuration fields.

### `marmot_nip46_register`

Attach an explicitly approved imported descriptor to an existing account, persist its verified credentials, and activate its worker. Ordinary cold startup restores owned sessions automatically; use `marmot_nip46_resume` for their handles. A different attached session must be removed before replacement.

Admitted adoption follows the runtime-owned cancellation and shutdown contract of `marmot_nip46_login`; handles must remain live throughout active C calls. If no prior callback exists, a verified pairing remains attached for recovery when worker startup fails.

### `marmot_nip46_state`

Read nonblocking JSON status and any intermediate approval URL, without session keys or RPC payloads. Free with `marmot_string_free`.

### `marmot_nip46_status`

Read local typed state/error vocabulary, optional auth URL and request ID, and generation without keys or request payloads. `last_error` is valid only when `has_last_error` is true. Distinguishes cancellation from remote rejection independently of legacy status-code compatibility. Out is cleared before work; no network access.

[Session contract](README.md#nip-46-accounts)

### `marmot_nip46_status_free`

Deep-free the status record and its optional strings. NULL is a no-op. Embedded strings are owned by the record and must not be freed separately.

[Session contract](README.md#nip-46-accounts)

### `marmot_nip46_uri`

Read the credential-bearing pairing link locally after permission approval. This accessor does not install a listener; use `marmot_nip46_pairing_offer` before displaying a client-initiated QR code. Never log either URI; free it with `marmot_string_free`.

### `marmot_normalize_member_ref`

Normalize a member reference (hex, `npub`, `nostr:npub...`, `nprofile`, `nostr:nprofile...`, and `marmot://profile/...`). nprofile relay hints are discarded. Duplicate type-0 TLV entries keep the first key. After wrapper normalization, encoded tokens longer than 1023 UTF-8 bytes are rejected; a valid 1023-byte token still decodes when wrapped. Free with `marmot_member_ref_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotnormalize_member_ref)

### `marmot_notify_connectivity_restored`

Interrupt retry backoff for durable outbound work after the host has observed usable connectivity.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotnotify_connectivity_restored)

### `marmot_notification_settings`

Per-account notification switches. Free with `marmot_notification_settings_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotnotification_settings)

### `marmot_npub`

`npub` encoding of a hex account id; NULL with `MARMOT_STATUS_OK` when the input does not decode. Free with `marmot_string_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotnpub)

### `marmot_notifications_subscription_next`

Block until the next item, the timeout, or stream close. `timeout_ms == 0` waits indefinitely. Returns `MARMOT_STATUS_OK` (out set; free with `marmot_notification_update_free`), `MARMOT_STATUS_TIMEOUT`, or `MARMOT_STATUS_CLOSED` (out NULL for both).

### `marmot_notifications_subscription_set_callback`

Install a callback pump for this subscription. `callback` runs on a runtime worker thread with a borrowed item pointer (valid only during the call; do not store or free it) and a final NULL item on close. `callback` and `user_data` access must be thread-safe. Fails if a callback is already installed.

### `marmot_notifications_subscription_clear_callback`

Request cancellation of this subscription's callback pump, if any. Non-blocking: a callback already running keeps executing after this returns (see the module docs).

### `marmot_notifications_subscription_free`

Free the subscription handle. Requests callback-pump cancellation without waiting (a callback may still be running after this returns — do not free `user_data` on that basis). NULL is a no-op. Free every handle before the client that created it.

### `marmot_notification_settings_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_notification_update_free`

Free a value of this type returned by this library. NULL is a no-op.

</details>

<details>
<summary>marmot_o…</summary>

### `marmot_onboarding_recovery_required`

Retry onboarding against explicitly selected discovery relays. Query whether unreadable/exhausted checkpoints require explicit recovery.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotonboarding_recovery_required)

### `marmot_onboarding_snapshot`

Read the persisted onboarding snapshot. Writes NULL with MARMOT_STATUS_OK when no checkpoint exists. Free the returned snapshot with `marmot_onboarding_snapshot_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotonboarding_snapshot)

### `marmot_onboarding_subscription_next`

Block until the next item, the timeout, or stream close. `timeout_ms == 0` waits indefinitely. Returns `MARMOT_STATUS_OK` (out set; free with `marmot_onboarding_snapshot_free`), `MARMOT_STATUS_TIMEOUT`, or `MARMOT_STATUS_CLOSED` (out NULL for both).

### `marmot_onboarding_subscription_set_callback`

Install a callback pump for this subscription. `callback` runs on a runtime worker thread with a borrowed item pointer (valid only during the call; do not store or free it) and a final NULL item on close. `callback` and `user_data` access must be thread-safe. Fails if a callback is already installed.

### `marmot_onboarding_subscription_clear_callback`

Request cancellation of this subscription's callback pump, if any. Non-blocking: a callback already running keeps executing after this returns (see the module docs).

### `marmot_onboarding_subscription_free`

Free the subscription handle. Requests callback-pump cancellation without waiting (a callback may still be running after this returns — do not free `user_data` on that basis). NULL is a no-op. Free every handle before the client that created it.

### `marmot_onboarding_subscription_snapshot`

Return the initial snapshot. Free with marmot_onboarding_snapshot_free.

### `marmot_open_attachment_handoff`

Blocking handoff copy that holds the calling thread until the copy finishes: call it off the UI thread. Writes NULL with `MARMOT_STATUS_OK` when the attachment is not held locally, and `MARMOT_STATUS_STORAGE_FULL` when the disk cannot hold the copy beyond the reserve. Inputs are borrowed for the call; the control may be queried or cancelled from another thread. Free the record with `marmot_attachment_handoff_free`. See the [shared contract](../marmot-uniffi/API-GUIDE.md#marmotopen_attachment_handoff).

### `marmot_open_presented_chat_list`

Open a complete chat list with both invalidation sources already attached. Take the initial snapshot once, then call next. Free with marmot_presented_chat_list_subscription_free. # Safety Client and string must be valid; out_sub must be writable.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotopen_presented_chat_list)

### `marmot_open_chat_list_window`

Open one account/view. A NULL initial_rows uses 50; otherwise requires 1–100. View is a MarmotChatListView discriminant. Take snapshot once, then receive replacements. # Safety client/string must be valid; initial_rows must be NULL or readable, out_sub writable.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotopen_chat_list_window)

### `marmot_open_chat_list_query_window`

`marmot_open_chat_list_window` narrowed by a filter. `query->view` is a MarmotChatListView discriminant; `query->filter[0..filter_len]` is the node list (NULL only with zero length, meaning no filter). Each `MarmotChatListFilterNode` sets `kind` and only that kind's fields: `children` for `All`/`Any`, exactly one child for `Not`, `condition` for `Condition`, `group_ids` for `GroupIds`, `text` for `Text` and `MessageText`. Node 0 is the root and every other node is the child of exactly one earlier node. A `Text` node matches chats whose title, group name, description or direct-chat peer profile name contains `text`, trimmed and lowercased, as a literal substring; a NULL `text` returns `MARMOT_STATUS_NULL_POINTER`. While any chat in the view still has presentation pending, a query with a `Text` node returns `MARMOT_STATUS_CHAT_PRESENTATION_NOT_READY` (an open window delivers it and retries), never part of the set. A `MessageText` node matches chats with a visible message containing `text` by the same rule; a window refuses it with `MARMOT_STATUS_INVALID_CHAT_LIST_QUERY` (`MARMOT_CHAT_LIST_QUERY_ERROR_MESSAGE_TEXT_IN_WINDOW`) before any read. Shape or bound violations (8 levels, 64 nodes, 500 group IDs, 1024 bytes of text) return `MARMOT_STATUS_INVALID_CHAT_LIST_QUERY`; an out-of-range discriminant or a `Not` without exactly one child returns `MARMOT_STATUS_INVALID_ARGUMENT`. The query and its arrays are borrowed for the call. Free with `marmot_chat_list_window_subscription_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotopen_chat_list_query_window)

### `marmot_chat_list_query_ids`

Select all for a filtered query: every chat ID it matches, in display order; `len` is the count. Same readiness rules as `marmot_chat_list_ids` and the same query rules as `marmot_open_chat_list_query_window`, except that it accepts a `MessageText` node; such a query returns `MARMOT_STATUS_CHAT_PRESENTATION_NOT_READY` while retained deletions and edits are still being backfilled. Free with `marmot_string_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotchat_list_query_ids)

### `marmot_revalidate_chat_list_query_ids`

The subset of a host selection that still matches a filtered query, in the caller's order with duplicates dropped; never adds chats. Inputs are borrowed. Free the result with `marmot_string_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotrevalidate_chat_list_query_ids)

### `marmot_open_conversation_window`

Open one account/group. mode is a MarmotConversationOpenMode discriminant. Message mode requires message_id_hex; other modes require NULL. initial_rows NULL uses 50. Zero timeout uses 30 seconds; opening timeout abandons the opening. No mark-read occurs. # Safety client/strings must be valid; optional pointers readable or NULL, out_sub writable.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotopen_conversation_window)

### `marmot_onboarding_snapshot_free`

Free a value of this type returned by this library. NULL is a no-op.

</details>

<details>
<summary>marmot_p…</summary>

### `marmot_publish_relay_lists`

Publish NIP-65 + inbox relay lists for the account. Idempotent.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotpublish_relay_lists)

### `marmot_publish_new_key_package`

Publish a fresh KeyPackage. Writes the accepting-relay count.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotpublish_new_key_package)

### `marmot_promote_admin`

Grant admin rights to `member_ref` (npub or hex). Requires admin. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotpromote_admin)

### `marmot_promote_admin_detailed`

`marmot_promote_admin` plus refreshed details and management state. Free with `marmot_group_mutation_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotpromote_admin_detailed)

### `marmot_push_registration`

The account's current push registration; writes NULL with `MARMOT_STATUS_OK` when there is none. Free with `marmot_push_registration_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotpush_registration)

### `marmot_presented_chat_list`

Complete local rows with selected title/avatar. Free with marmot_presented_chat_list_snapshot_free.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotpresented_chat_list)

### `marmot_presented_chat_list_row`

Keyed complete row; missing groups return NULL. Free with marmot_presented_chat_row_free.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotpresented_chat_list_row)

### `marmot_pause_maintenance`

Pause the account's periodic maintenance loop.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotpause_maintenance)

### `marmot_prewarm_group_member_key_packages`

Check prospective members' KeyPackage readiness ahead of a group creation. The create still discovers routes and fetches KeyPackages from relays. Free with `marmot_member_key_package_prewarm_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotprewarm_group_member_key_packages)

### `marmot_prepared_group_image_status`

Where one staged group image sits in its upload lifecycle. Free with `marmot_prepared_group_image_upload_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotprepared_group_image_status)

### `marmot_prepared_group_images`

Every staged group image for the account. Free with `marmot_prepared_group_image_upload_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotprepared_group_images)

### `marmot_periodic_maintenance_policy`

Whether new groups enroll in periodic maintenance.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotperiodic_maintenance_policy)

### `marmot_parse_markdown`

Parse Markdown text into the display token tree. Infallible: malformed input degrades inside the parser. Free with `marmot_markdown_document_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotparse_markdown)

### `marmot_publish_user_profile`

Publish the account's kind:0 profile metadata. The returned profile is what was actually published. Free with `marmot_user_profile_metadata_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotpublish_user_profile)

### `marmot_publish_user_profile_using_account_relays`

Publish the account's kind:0 profile using the account's own relay lists rather than caller-supplied ones. Free with `marmot_user_profile_metadata_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotpublish_user_profile_using_account_relays)

### `marmot_propose_onboarding_recommended_relays`

Prepare the configured default relay proposal without publishing. `step` is a MarmotOnboardingStep discriminant; out-of-range values return MARMOT_STATUS_INVALID_ARGUMENT. Free the returned snapshot with `marmot_onboarding_snapshot_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotpropose_onboarding_recommended_relays)

### `marmot_propose_onboarding_relay_repair`

Return an owned snapshot with a non-publishing, exact relay-repair preview in `proposal->relay_repair`. Its content, tag fields and non-NULL tag/change endpoints are JSON string literals: decode once with embedded-NUL/UTF-8-length preservation before consent or manual editing, following [the C encoding contract](README.md#onboarding-relay-repair). Inspect its ordered source and proposed tags, unchanged content, typed occurrence diff, and mode before asking for approval. `MARMOT_ONBOARDING_RELAY_REPAIR_MODE_MANUAL_REVIEW` has no approval action; use a separate manual editor or explicitly labeled full reset. The borrowed `account_ref` and validated `step` must identify the current onboarding attempt; free the result with `marmot_onboarding_snapshot_free` and approve only the displayed revision (and recovery epoch where present).

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotpropose_onboarding_relay_repair)

### `marmot_propose_onboarding_relays`

Prepare a relay proposal without publishing; inbox proposals require an empty write list. `step` is a MarmotOnboardingStep discriminant; out-of-range values return MARMOT_STATUS_INVALID_ARGUMENT. Free the returned snapshot with `marmot_onboarding_snapshot_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotpropose_onboarding_relays)

### `marmot_propose_onboarding_profile`

Prepare profile edits without publishing; NULL fields preserve existing values and empty strings clear them. Free the returned snapshot with `marmot_onboarding_snapshot_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotpropose_onboarding_profile)

### `marmot_propose_onboarding_follows`

Prepare a follow-list replacement without publishing; an empty list is valid. Free the returned snapshot with `marmot_onboarding_snapshot_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotpropose_onboarding_follows)

### `marmot_group_change_not_delivered_list_free`

Deep-free the complete list returned by `marmot_group_changes_not_delivered`, including each record's owned strings. NULL is a no-op. Do not free individual items/fields, pass a borrowed pointer, or reuse the list after this call.

### `marmot_pending_welcome_delivery_list_free`

Deep-free the complete list returned by `marmot_pending_welcome_deliveries`, including each repair handle's owned strings. NULL is a no-op. Do not free individual items/fields, pass a borrowed pointer, or reuse the list after this call.

### `marmot_invite_delivery_list_free`

Release a `MarmotInviteDeliveryList` returned by `marmot_invite_deliveries`, with every record's strings and device array. NULL is a no-op; never free a field on its own.

### `marmot_presented_chat_list_subscription_snapshot`

Take the initial snapshot with sequence zero. A second call returns CLOSED and NULL. Free the result with marmot_presented_chat_list_update_free. # Safety sub must be live; out must be writable.

### `marmot_presented_chat_list_subscription_next`

Read a whole replacement. timeout_ms zero waits indefinitely. Timeout/closed/error leave out NULL; timeout or a storage error does not discard the pending refresh. Retry according to the typed status. Free results with marmot_presented_chat_list_update_free. # Safety sub must be live; out must be writable.

### `marmot_presented_chat_list_subscription_free`

Cancel and free a presented-list handle. NULL is a no-op. # Safety sub must be NULL or a live library-owned handle not in use by another call.

### `marmot_prepared_group_image_upload_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_prepared_group_image_upload_list_free`

Free a list returned by this library. NULL is a no-op.

### `marmot_push_registration_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_push_registration_share_outcome_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_push_registration_sync_result_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_presented_chat_row_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_presented_chat_list_snapshot_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_presented_chat_list_update_free`

Free a value of this type returned by this library. NULL is a no-op.

</details>

<details>
<summary>marmot_q…</summary>

### `marmot_quarantined_groups`

Stored groups that failed session-open hydration and were skipped. Surface them in a per-group recovery flow and offer `marmot_retry_hydrate_quarantined_group`. Free with `marmot_app_quarantined_group_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotquarantined_groups)

</details>

<details>
<summary>marmot_r…</summary>

### `marmot_read_attachment_asset`

Read a bounded range (1..=1048576 bytes) from a local reference. No network fallback. Rechecks source visibility/expiry on every call. Offset at/beyond EOF returns available=true and empty bytes. An obsolete or wrong-account reference is unavailable. Free the result with `marmot_attachment_local_bytes_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotread_attachment_asset)

### `marmot_release_attachment_handoff`

Blocking release of a handoff lease: deletes its copy. An unknown or already released lease returns `MARMOT_STATUS_OK`; a malformed lease returns `MARMOT_STATUS_INVALID_MEDIA_REFERENCE`; a copy that cannot be deleted returns `MARMOT_STATUS_IO` and stays leased, so retry. See the [shared contract](../marmot-uniffi/API-GUIDE.md#marmotrelease_attachment_handoff).

### `marmot_remove_attachments_older_than`

Blocking bulk removal of retained attachments received before `received_before` (Unix seconds), account-wide when `group_id_hex` is NULL, writing the count to `out_removed`. Same semantics as `marmot_remove_chat_attachments`.

### `marmot_remove_chat_attachments`

Blocking bulk removal of one chat's retained attachments, writing the count to `out_removed`. Each is a Remove (shown as removed, download-again allowed); released media-store files are deleted before the call returns. See the [shared contract](../marmot-uniffi/API-GUIDE.md#marmotremove_chat_attachments).

### `marmot_attachment_keep_media`

Blocking read of the account's "Keep media" setting, written to `out_keep` as a `MarmotAttachmentKeepMedia` discriminant (`Forever` by default).

### `marmot_set_attachment_keep_media`

Blocking: stores the setting (`keep` is a `MarmotAttachmentKeepMedia` discriminant; out of range is `MARMOT_STATUS_INVALID_ARGUMENT` before any work), then removes every retained attachment already past the new window, and drops unfinished automatic downloads past it, writing the count to `out_removed`. Removed attachments read `CleanedBySetting`. Media-store space is freed before this returns.

### `marmot_request_avatar_assets`

Register up to 16 visible avatar targets without awaiting HTTP. Free the returned list with `marmot_avatar_asset_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotrequest_avatar_assets)

### `marmot_read_avatar_assets`

Read up to 16 local avatar references with a 1-byte..16-MiB aggregate byte budget. Budget-deferred entries are explicit. Free with `marmot_avatar_bytes_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotread_avatar_assets)

### `marmot_remove_account`

Remove an account and its local state from this device.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotremove_account)

### `marmot_rename_linked_device`

Rename one of this account's devices, this one included, by its `slot_id_hex` from `marmot_linked_devices`: one roster commit in the device group that sets only that device's label (at most 64 bytes of UTF-8; empty clears it). Refused with nothing sent when device groups are unavailable for this client, for a label that is too long, without a device group, for an unknown slot, while its roster cannot be read (`roster_unavailable`), and while an earlier change of this device's is still in flight there (retry later). A rename whose commit loses a fork is made again later, unless another user edit of that device won; show the label `marmot_linked_devices` returns after `MARMOT_EVENT_LINKED_DEVICES_CHANGED`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotrename_linked_device)

### `marmot_update_linked_device_settings`

Patch a linked device's settings on the account worker. Each `has_`/value pair is `uint8_t`: zero presence leaves that setting unchanged; nonzero presence supplies the value, with zero false and nonzero true. The call has no returned allocation. Refused with nothing sent while device groups are off (`roster_unsupported`), without a trusted device group (`no_device_group`), for an unknown slot (`unknown_device`), or while its roster cannot be read (`roster_unavailable`). Earlier lost label/settings edits recover first; retry `device_group_busy` while one remains unsettled. Refresh `marmot_linked_devices` on `MARMOT_EVENT_LINKED_DEVICES_CHANGED`. See the [shared settings contract](../marmot-uniffi/README.md#linked-devices) for history and removal limits.

### `marmot_remove_linked_device`

Remove another of this account's devices, by its `slot_id_hex` from `marmot_linked_devices`, from the device group and every chat, and delete its KeyPackage slot. The removal is recorded at once and carried out as the device group allows; the device shows `removal_pending` until the device group takes it. Refused with nothing recorded when device groups are unavailable for this client, without a device group, for an unknown slot, for this device (sign out instead), while its roster cannot be read (`roster_unavailable`), and for a device whose link may still fail. Re-read `marmot_linked_devices` after `MARMOT_EVENT_LINKED_DEVICES_CHANGED`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotremove_linked_device)

### `marmot_removed_device_leftover_chats`

How many chats this device is in still hold a device this account no longer has, because the chat does not take a same-account removal; a chat admin can remove it. That device is one this account removed, or one its device group stopped listing, as after a failed link. Zero while device groups are off. Not evented: read it when showing the device list.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotremoved_device_leftover_chats)

### `marmot_chats_closed_to_linked_devices`

How many chats this device is in can't take any device of this account: they don't require `marmot.group.account-devices.v1`, name no relays a sibling Welcome can carry, or already hold this account's limit of 20 leaves. Once a link this device approved is made, the new device is added to this device's other chats when its "add to all my chats" setting is on, for a week after the link; a chat admin can turn the component on in these, and removing a device frees its leaves. A chat that can take this account's devices but whose requirements the new device's KeyPackages don't meet is passed over and not counted, so zero does not mean the new device reaches every chat. Zero while device groups are off. Not evented: read it when showing the device list.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotchats_closed_to_linked_devices)

### `marmot_recover_onboarding`

Retain opaque evidence, retire the old attempt, and return a new epoch. Requires explicit acknowledgment of latest-only evidence retention. Hosts invalidate old UI callbacks first, then explicitly begin again.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotrecover_onboarding)

### `marmot_refresh_account_key_packages`

Fetch validated relay observations, then merge a fresh local snapshot. Empty bootstrap relays remain network-enabled. Free with `marmot_account_key_package_inventory_entry_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotrefresh_account_key_packages)

### `marmot_republish_key_package`

Re-publish the latest cached KeyPackage when possible, otherwise publish a fresh one. Writes the accepting-relay count.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotrepublish_key_package)

### `marmot_retained_attachments_page_free`

Deep-free a retained attachments page, its rows and its borrowed cursor. NULL is a no-op.

### `marmot_body_removal_page_free`

Deep-free an owned removal page, including its removal array, identity strings,
and cursor. NULL is a no-op. Embedded records and strings must not be freed
separately; copy the cursor before freeing if it will be reused or persisted.

### `marmot_attachment_removals`

Blocking local durable body-removal query, `limit` 1..=256. Inputs are borrowed
for the call; `cursor` is a nullable string, not an opaque listing handle. NULL
captures the high water with `reset_required=true` and no removals. Follow the
[shared reconciliation contract](../marmot-uniffi/ATTACHMENT-ACCESS.md#derivative-cache-removal-journal)
before saving that cursor; invalidated cursors also require reset. Historical
states do not authorize byte reads. Run off the UI thread and free the result
with `marmot_body_removal_page_free`, which owns all nested fields.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotattachment_removals)

### `marmot_rotate_key_package`

Rotate the account's KeyPackage: mint and publish a fresh one, superseding the current slot (the sanctioned repair for an epoch-stalled group; see `MARMOT_EVENT_EPOCH_STALL_ESCALATED`). Writes the accepting-relay count. `marmot_publish_new_key_package` is the same operation under its legacy name.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotrotate_key_package)

### `marmot_reveal_nsec`

Export the account's raw private key as `nsec1…` bech32. SENSITIVE: the reveal is audit-logged and permanently marks the account's key-security byte as handled-insecurely. Free the string with `marmot_string_free` as soon as it has been displayed.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotreveal_nsec)

### `marmot_remove_members`

Remove members from the group. Requires admin; preflight rejects self-removal and removing the last admin. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotremove_members)

### `marmot_remove_members_detailed`

`marmot_remove_members` plus refreshed details and management state. Free with `marmot_group_mutation_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotremove_members_detailed)

### `marmot_retry_hydrate_quarantined_group`

Re-attempt hydration of a single quarantined group. Writes true if the group recovered and is now a live chat, false if it stays quarantined. Unknown-group status if the id is not quarantined.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotretry_hydrate_quarantined_group)

### `marmot_retry_group_convergence`

Re-drive delivery/convergence for the group (e.g. a stuck pending own message) without minting duplicates. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotretry_group_convergence)

### `marmot_react_to_message`

React to a message with `emoji`. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotreact_to_message)

### `marmot_react_with_media`

React with a custom emoji image: uploaded `attachments` become `imeta` tags on the kind-7 and `tags` name them (NIP-30 `emoji`). Preserve each reference's local `source_epoch_identity`; missing provenance or a changed upload branch requires a fresh upload. `imeta` rows in `tags` are rejected. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotreact_with_media)

### `marmot_reply_to_message`

Reply to a message. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotreply_to_message)

### `marmot_relay_telemetry_settings`

Current relay-telemetry export settings. Free with `marmot_relay_telemetry_settings_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotrelay_telemetry_settings)

### `marmot_refresh_profile`

Refresh the cached profile for an account id from `relays`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotrefresh_profile)

### `marmot_refresh_user_relay_lists`

Fetch an account's published relay lists from `relays`, updating the cache. Free with `marmot_account_relay_lists_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotrefresh_user_relay_lists)

### `marmot_reset_incomplete_account_setup`

Discard the local state of an account whose setup never completed. `acknowledge_possible_key_package_orphan` confirms the caller accepts that a published KeyPackage may be left orphaned.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotreset_incomplete_account_setup)

### `marmot_resume_maintenance`

Resume the account's periodic maintenance loop.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotresume_maintenance)

### `marmot_run_due_maintenance`

Run every maintenance obligation that is due now. Free with `marmot_maintenance_run_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotrun_due_maintenance)

### `marmot_random_profile_pseudonym`

Random cosmetic display name from the shared wordlists. Free with `marmot_string_free`. This does not create an account or generate a signing key.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotrandom_profile_pseudonym)

### `marmot_relay_health`

Aggregate relay-pool health. Free with `marmot_relay_health_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotrelay_health)

### `marmot_replace_encrypted_media_blob_endpoints`

Replace the group's encrypted-media default blob endpoints as a full component update. Requires admin. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotreplace_encrypted_media_blob_endpoints)

### `marmot_retired_relay_hosts`

The centralized retired-relay denylist. These hosts must never be dialed or adopted. Free with `marmot_string_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotretired_relay_hosts)

### `marmot_record_host_performance`

Record how long a host-side operation took, so it joins the runtime's own timings in `marmot_app_performance_snapshot`. `operation` and `outcome` are discriminants; out-of-range values are rejected with `MARMOT_STATUS_INVALID_ARGUMENT`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotrecord_host_performance)

### `marmot_run_onboarding`

Resume pending checks until user input or a retry is needed. Free the returned snapshot with `marmot_onboarding_snapshot_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotrun_onboarding)

### `marmot_retry_onboarding_step`

Retry an offered step; earlier checks invalidate downstream readiness. `step` is a MarmotOnboardingStep discriminant; out-of-range values return MARMOT_STATUS_INVALID_ARGUMENT. Free the returned snapshot with `marmot_onboarding_snapshot_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotretry_onboarding_step)

### `marmot_record_product_event`

Forward a validated product analytics input. # Safety Client and borrowed input must be valid; output, when present, must be writable.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotrecord_product_event)

### `marmot_record_host_timing`

Record an app-defined timing through the consent-gated product exporter. Register `name` with `elapsed: DurationBucket` and `outcome: Enum` choices `success`/`failure`. Milliseconds are bucketed before recording. # Safety Client and borrowed name must be valid; out must be writable.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotrecord_host_timing)

### `marmot_reported_message`

# Safety `client` must be a live handle; string arguments must be valid NUL-terminated strings (nullable ones may be NULL); array arguments must hold their stated length (or be NULL with length 0); out-pointers must be valid.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotreported_message)

### `marmot_report_dismissals`

# Safety `client` must be a live handle; string arguments must be valid NUL-terminated strings (nullable ones may be NULL); array arguments must hold their stated length (or be NULL with length 0); out-pointers must be valid.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotreport_dismissals)

### `marmot_report_message`

Report one group message. Reason is a MarmotReportReason discriminant. # Safety Client, strings and output pointer must be valid. Inputs are borrowed.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotreport_message)

### `marmot_runtime_message_received_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_retention_sweep_report_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_relay_health_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_relay_telemetry_settings_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_relay_endpoint_classification_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_relay_endpoint_classification_list_free`

Free a list returned by this library. NULL is a no-op.

### `marmot_report_dismissal_page_free`

Free a value of this type returned by this library. NULL is a no-op.

</details>

<details>
<summary>marmot_s…</summary>

### `marmot_send_tagged_sticker`

Send an authorized sticker reference with reply `e`, NIP-22 `E`/`K`/`P`, or effect tags. Rejects `imeta` and extra `sticker` rows; context is bounded to 64 tags and 16 KiB of values. Tag rows and their strings are borrowed for the blocking call; NULL/0 supplies no context. The output pointer is preflighted before any send. Free the owned summary with `marmot_send_summary_free`. The original `marmot_send_sticker` signature is unchanged.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotsend_tagged_sticker)

### `marmot_send_sticker`

Sends one exact sticker reference. Preflights the output pointer before any send. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotsend_sticker)

### `marmot_sticker_asset_free`

Frees a sticker asset and its owned bytes. NULL is safe.

### `marmot_sticker_free`

Frees one embedded sticker record returned as a root. NULL is safe.

### `marmot_sticker_import_result_free`

Frees an import result, its pack, and skipped-id strings. NULL is safe.

### `marmot_sticker_list_free`

Frees a sticker list and every owned element. NULL is safe.

### `marmot_sticker_pack`

Reads one cached pack by coordinate or trusted link without network I/O. Returns NULL when absent. Free with `marmot_sticker_pack_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotsticker_pack)

### `marmot_sticker_pack_share_link`

Builds a canonical share link from local relay candidates without network I/O. This synchronous call reads storage; keep it off the UI thread. Inputs are borrowed. On success, free the owned output with `marmot_string_free`; on failure, `out` is NULL. See the shared method for hint limits, fallback behavior, and coordinate validation.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotsticker_pack_share_link)

### `marmot_sticker_pack_free`

Frees one pack, its cover, and sticker vector. NULL is safe.

### `marmot_sticker_pack_list_free`

Frees a pack list and every owned pack. NULL is safe.

### `marmot_sticker_packs`

Reads the encrypted sticker projection off the UI thread. installed_only is a uint8_t flag; has_limit 0 leaves the storage default. Free with `marmot_sticker_pack_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotsticker_packs)

### `marmot_sticker_ref_free`

Frees one exact sticker reference. NULL is safe.

### `marmot_sticker_sync_result_free`

Frees a sync result. NULL is safe.

### `marmot_string_free`

Free a string returned by this library (`marmot_last_error_message`, string out-params). NULL is a no-op.

### `marmot_sign_out_and_wipe`

Destructive sign-out: leave groups, delete relay KeyPackages, wipe local state. With linked devices it first asks them to take it out, which can take about 30 seconds; `groups_left_to_siblings` and `siblings_not_reached` report how that went. Queued new member leaves appear in `group_leave_failures`. Local cleanup still runs. Every stage is reported in the outcome. Free with `marmot_wipe_outcome_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotsign_out_and_wipe)

### `marmot_sign_out`

Non-destructive sign-out: deactivate the account on this device, keeping local state so it can sign back in later. When `delete_key_packages` is true, this device's KeyPackage slot gets a NIP-09 deletion. Free with `marmot_sign_out_outcome_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotsign_out)

### `marmot_set_onboarding_discovery_relays`

# Safety `client` must be a live handle; string arguments must be valid NUL-terminated strings (nullable ones may be NULL); array arguments must hold their stated length (or be NULL with length 0); out-pointers must be valid.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotset_onboarding_discovery_relays)

### `marmot_start_fresh`

Start this device without the devices its first sign-in check found ("No, start fresh"): every sign-in from before this device is answered Not now, now and when one is listed later; blocks on the account worker. It rejects nothing and raises no compromise warning. Before the first check, once this device trusts a device group, and while device groups are off, it is refused with a device-group error.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotstart_fresh)

### `marmot_started_fresh`

Write whether this device started fresh and still trusts no device group, so the app can say that only chats it is invited to from now on are here; blocks on the account worker without network I/O. Re-read after `marmot_start_fresh` and on `MARMOT_EVENT_LINKED_DEVICES_CHANGED`. Always false unless the host turns device groups on.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotstarted_fresh)

### `marmot_sign_in_account`

Re-activate a non-destructively signed-out local account. Free with `marmot_account_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotsign_in_account)

### `marmot_set_account_nip65_relays`

Replace the account's NIP-65 relay list and publish it. Free with `marmot_account_relay_lists_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotset_account_nip65_relays)

### `marmot_set_account_inbox_relays`

Replace the account's inbox relay list and publish it. Free with `marmot_account_relay_lists_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotset_account_inbox_relays)

### `marmot_self_demote_admin`

Step down as an admin (demote the active account). Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotself_demote_admin)

### `marmot_self_demote_admin_detailed`

`marmot_self_demote_admin` plus refreshed details and management state. Free with `marmot_group_mutation_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotself_demote_admin_detailed)

### `marmot_set_group_archived`

Flag a group archived (or restore it). Local-only projection state. Free with `marmot_app_group_record_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotset_group_archived)

### `marmot_send_text`

Send a chat text message to the group. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotsend_text)

### `marmot_send_tagged_text`

Send kind-9 text with application tags (for example NIP-30 `emoji`). `tags` follows `marmot_send_custom_event` row ownership; `imeta` rows are rejected. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotsend_tagged_text)

### `marmot_secure_delete_expired`

Securely delete this group's expired disappearing messages now. Free with `marmot_secure_delete_expired_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotsecure_delete_expired)

### `marmot_set_local_notifications_enabled`

Toggle local notifications for the account. Free with `marmot_notification_settings_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotset_local_notifications_enabled)

### `marmot_set_native_push_enabled`

Toggle native push for the account. Free with `marmot_notification_settings_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotset_native_push_enabled)

### `marmot_set_chat_manually_unread`

Mark a conversation manually unread (or clear that mark); writes the refreshed row, or NULL with `MARMOT_STATUS_OK` when the group has no row. Free with `marmot_chat_list_row_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotset_chat_manually_unread)

### `marmot_set_chat_pinned`

Pin or unpin a conversation. Writes the account's full pin state. Free with `marmot_chat_pin_state_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotset_chat_pinned)

### `marmot_set_pinned_chat_order`

Replace the pinned-section order. `ordered_group_ids` lists every pinned group in display order. Free with `marmot_chat_pin_state_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotset_pinned_chat_order)

### `marmot_set_chat_muted`

Mute a conversation. `has_muted_until_ms` plus `muted_until_ms` set a timed mute; leaving the flag unset mutes indefinitely. Free with `marmot_chat_notification_settings_free`.
Ordinary notification updates stay suppressed, while direct mentions of the receiving account reach subscriptions with `MarmotNotificationUpdate.is_mention` set; blocked senders remain suppressed. Hosts apply their own notification permission and channel settings.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotset_chat_muted)

### `marmot_schedule_group_self_update`

Queue an MLS self-update commit for the group. Writes the scheduled job id; free it with `marmot_string_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotschedule_group_self_update)

### `marmot_search_cached_users`

Search public identities cached through any connected account. Follow flags refer to the selected account. Call off the UI thread and free with `marmot_user_directory_search_result_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotsearch_cached_users)

### `marmot_sweep_expired_retention`

Prune messages past their disappearing-message retention. `now_ms` is the caller's wall clock. Free with `marmot_retention_sweep_report_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotsweep_expired_retention)

### `marmot_set_relay_telemetry_settings`

Deprecated consent control: use `marmot_set_usage_diagnostics_consent`. Enable requires a combined grant; disable revokes both exporters. The telemetry interval remains configurable. Free the result with `marmot_relay_telemetry_settings_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotset_relay_telemetry_settings)

### `marmot_set_relay_telemetry_runtime_config`

Set the runtime OTLP route for relay telemetry.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotset_relay_telemetry_runtime_config)

### `marmot_set_audit_log_settings`

Replace the audit-log recorder settings. Free the result with `marmot_audit_log_settings_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotset_audit_log_settings)

### `marmot_set_audit_log_retention`

Replace the local audit-log retention policy. `retention` is borrowed. The stored value, clamped to 1-30 days and at least 16 MiB per account, is returned; free it with `marmot_audit_log_retention_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotset_audit_log_retention)

### `marmot_set_audit_log_source`

Set the in-memory audit source metadata (system hardware model, platform, app version) that audit recorders opened afterwards record, from a borrowed `MarmotAuditLogSource`. Call it on every launch before opening accounts. Returns the trimmed stored copy; free it with `marmot_audit_log_source_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotset_audit_log_source)

### `marmot_send_media_attachments`

Send previously uploaded attachments as one message, preserving their local `source_epoch_identity`. Missing provenance or a changed upload branch requires a fresh upload. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotsend_media_attachments)

### `marmot_send_tagged_media`

Send previously uploaded attachments as one kind-9 message that also carries application tags (for example NIP-30 `emoji` naming an attachment's locator). Preserve each upload reference's local `source_epoch_identity`; missing provenance or a changed upload branch requires a fresh upload. `imeta` rows in `tags` are rejected. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotsend_tagged_media)

### `marmot_send_thread_message`

Send a NIP-22 thread message from a thread view; `text` may be empty when `attachments` is not. MDK builds the thread tags and rejects them in `tags`. A client without a thread view uses `marmot_reply_to_message`. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotsend_thread_message)

### `marmot_send_media_reference`

Send one previously uploaded attachment as a message. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotsend_media_reference)

### `marmot_storage_is_closed`

Whether this client's storage has been closed (by `marmot_client_shutdown_and_close`). Writes to `out_closed`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotstorage_is_closed)

### `marmot_save_message_draft`

Store (or replace) the draft for a conversation. `attachments` are copied — the caller keeps ownership of every buffer. Free the result with `marmot_message_draft_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotsave_message_draft)

### `marmot_stage_prepared_group_image`

Encrypt and stage a group image without attaching it to a group yet, so the upload can finish before the caller commits to creating one. The bytes are copied — the caller keeps ownership. Free with `marmot_prepared_group_image_upload_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotstage_prepared_group_image)

### `marmot_set_periodic_maintenance_policy`

Set whether new groups enroll in periodic maintenance.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotset_periodic_maintenance_policy)

### `marmot_send_custom_event`

Send a custom application event into the group. `tags` is a flat array of `tags_len` tag rows, each row a `(char **, len)` pair of string values. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotsend_custom_event)

### `marmot_create_tagged_poll`

Create a typed encrypted poll with reply `e`, NIP-22 `E`/`K`/`P`, or effect context. Generated poll tags plus supplied context must total at most 32. Rejects `imeta`, `option`, `polltype`, `endsAt`, and `response` context rows; tagged-text context bounds also apply. Options, tag rows and strings are borrowed for the blocking call; NULL/0 supplies no context. `has_ends_at == 0` omits the deadline. The output pointer is preflighted before any send. Free the owned summary with `marmot_send_summary_free`. The original `marmot_create_poll` signature is unchanged.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotcreate_tagged_poll)

### `marmot_create_poll`

**Current.** Create an encrypted NIP-88 group poll through the bounded typed surface.

Pass two through ten labels, a valid `MarmotPollType` discriminant, and use `has_ends_at` to distinguish no deadline
from the Unix-seconds `ends_at` value. Creation follows MDK's canonical conversation classification: named two-member
conversations are groups, while unnamed two-member conversations are direct. MDK assigns stable option ids. The call
blocks and `out` is released with `marmot_send_summary_free`; recompile for the added timeline poll record. See
[the shared poll contract](../marmot-uniffi/POLLS.md).

### `marmot_cast_poll_vote`

**Current.** C mirror of the typed replacement-vote API.

Pass the complete option-id selection from the poll projection; an empty selection is not an unvote. The poll must be
valid, local to the named group, and open. MDK revalidates it against the response event's actual timestamp at send
time, and it remains votable after conversation reclassification. The call blocks and `out` is released with
`marmot_send_summary_free`. See
[the shared poll contract](../marmot-uniffi/POLLS.md).

### `marmot_message_reactions`

Read a complete local snapshot of effective sender/emoji participants for one message; see [shared details semantics](../marmot-uniffi/CONVERSATION-WINDOW.md#complete-reaction-details). Call off the UI thread. Inputs are borrowed valid NUL-terminated strings; the required out pointer is cleared before validation. On success the caller owns the result and releases it with `marmot_timeline_user_reaction_list_free`.

### `marmot_sync_sticker_packs`

Refreshes public discovery and cached installed packs. Pending install changes are published only after a complete installed-list read; incomplete reads leave them pending. Free with `marmot_sticker_sync_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotsync_sticker_packs)

### `marmot_timeline_user_reaction_list_free`

Deep-free a root reaction list returned by `marmot_message_reactions`, including strings and items. NULL is a no-op; never free embedded items separately, and never use the list after freeing it.

### `marmot_poll_votes`

**Current.** C mirror of the per-voter poll read.

Returns one page of each voter's effective selection by the same rules as `MarmotTimelineMessageRecord.poll`; all pages
together sum to the tally. Blocked voters stay listed; a missing, deleted, hidden, or non-poll row gives an empty page.
Votes are ordered by `(voted_at, voter_account_id_hex)`. Pass `has_after = 0` and a NULL voter for the first page, then
the last vote's `voted_at` and `voter_account_id_hex` while `has_more_after` is set. `limit` is 1..=100 because
retained votes from former members are not bounded by the current group size. The call blocks, and `out` is released
with `marmot_poll_vote_page_free`. See [the shared poll contract](../marmot-uniffi/POLLS.md).

### `marmot_poll_vote_page_free`

Free a page returned by `marmot_poll_votes`, including its votes. NULL is a no-op.

### `marmot_set_usage_diagnostics_consent`

# Safety `client` must be a live handle; string arguments must be valid NUL-terminated strings (nullable ones may be NULL); array arguments must hold their stated length (or be NULL with length 0); out-pointers must be valid.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotset_usage_diagnostics_consent)

### `marmot_set_product_analytics_runtime_config`

Forward a validated product analytics input. # Safety Client and borrowed input must be valid; output, when present, must be writable.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotset_product_analytics_runtime_config)

### `marmot_set_product_analytics_activity`

Signal host activity. Discriminants are validated before conversion. # Safety Client must be a live handle.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotset_product_analytics_activity)

### `marmot_subscribe_events`

Subscribe to the event firehose. Free with `marmot_events_subscription_free` (before freeing the client).

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotsubscribe_events)

### `marmot_subscribe_timeline_messages`

Subscribe to live materialized timeline updates for a group (`group_id_hex` non-NULL) or the account-wide tail (NULL). `has_limit` plus `limit` cap the initial window. Free with `marmot_timeline_subscription_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotsubscribe_timeline_messages)

### `marmot_subscribe_notifications`

Subscribe to notification updates. Free with `marmot_notifications_subscription_free` (before freeing the client).

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotsubscribe_notifications)

### `marmot_subscribe_chats`

Subscribe to one account's chats list. Emits whenever a group's projection changes; `include_archived` widens the filter. Free with `marmot_chats_subscription_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotsubscribe_chats)

### `marmot_subscribe_chat_list`

Subscribe to one account's durable chat-list projection. Free with `marmot_chat_list_subscription_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotsubscribe_chat_list)

### `marmot_subscribe_messages`

Subscribe to messages for a specific group (`group_id_hex` non-NULL) or every message across the account (NULL). `has_limit` + `limit` cap the initial snapshot to the latest N rows. `kinds` restricts the stream to those Nostr event kinds; pass NULL with length 0 for every kind. Free with `marmot_messages_subscription_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotsubscribe_messages)

### `marmot_subscribe_group_state`

Subscribe to member/profile/roster changes for one group. Free with `marmot_group_state_subscription_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotsubscribe_group_state)

### `marmot_search_users`

Search the identity directory outward from `account_id_hex`, widening from `radius_start` to `radius_end` social hops. Results stream in through the returned handle. Free it with `marmot_user_search_subscription_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotsearch_users)

### `marmot_subscribe_onboarding`

Subscribe to durable onboarding state for an account.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotsubscribe_onboarding)

### `marmot_subscribe_blocked_users`

Subscribe to an account's block list. # Safety Client, account string and output pointer must be valid.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotsubscribe_blocked_users)

### `marmot_subscribe_attachment_transfers`

Open a bounded progress stream. First next returns the initial snapshot. # Safety Inputs must be live, targets NULL only with zero length, out writable.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotsubscribe_attachment_transfers)

### `marmot_subscribe_account_attention`

Open independent signed-in account summaries; requires no active chat-list handle. # Safety client must be valid; out_sub writable.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotsubscribe_account_attention)

### `marmot_selected_message_draft`

Descriptor-only draft; result owns the revision handle and must be deep-freed. # Safety client and strings valid; out writable.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotselected_message_draft)

### `marmot_save_message_draft_if_revision`

Save only if the selected revision still matches. Attachment inputs are copied, never retained. # Safety client, account, content and revision valid; reply nullable; attachments points to len readable items (or NULL with zero len). Revision's owner stays live; out writable.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotsave_message_draft_if_revision)

### `marmot_send_message_draft`

Send the exact selected revision; successful durable acceptance clears it atomically. Hosts must not independently delete the draft on delivery. Prepared media must match descriptors. # Safety client, account, revision valid; revision owner stays live; attachments readable for length, or NULL with zero length; out writable. Free result with marmot_send_summary_free.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotsend_message_draft)

### `marmot_send_summary_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_sign_out_outcome_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_string_list_free`

Free a string list returned by this library. NULL is a no-op.

### `marmot_secure_delete_expired_result_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_selected_message_draft_free`

Deep-free a selected draft and its opaque revision. NULL is allowed. Only for drafts returned directly by this library. A snapshot's embedded draft is freed by `marmot_conversation_window_snapshot_free`. # Safety p must be NULL or a library-owned unfreed selected-draft root pointer, never the address of a snapshot's embedded draft.

### `marmot_set_attachment_download_policy`

Persist policy. Disable pauses automatic work but preserves explicit transfers and cached bytes. # Safety Client, strings and policy must be live throughout this call. Inputs are borrowed.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotset_attachment_download_policy)

### `marmot_submit_moderation_report`

Privately report a user to the configured moderation team as a NIP-59 gift wrap of a NIP-56 report. `reason` is a `MarmotReportReason` and `origin` a `MarmotModerationReportOrigin` discriminant. Additive to `marmot_report_message`, which is unchanged. Release `*out` with `marmot_moderation_report_outcome_free`; a queued `AcceptedPending` or `CompletionUnknown` outcome is retried on catch-up and must not be resubmitted.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotsubmit_moderation_report)

### `marmot_dismiss_device_group_move_sibling`

Block on the account worker to dismiss one old-sibling hint from a move view. Borrow `account_ref`, the opaque
`move_id` and `slot_id_hex`; supply a non-NULL `out`. Free the owned returned snapshot, including its nested move
strings/lists, with `marmot_device_link_snapshot_free`. This does not link or remove a device. Disabled linking or an
unknown move/sibling is refused. See [shared move behavior](../marmot-uniffi/README.md#moving-this-device-to-another-device-group).

### `marmot_reset_device_group_for_repair`

**Current.**

Run the shared explicit local device-group reset on the account worker after user confirmation. Refused with device groups off. On success `out` owns a snapshot; release it with `marmot_device_link_snapshot_free`. Follow the [shared reset, data-retention and admission contract](../marmot-uniffi/README.md#explicit-local-device-group-reset-before-fresh-pairing); this action neither removes remote members nor guarantees fresh admission.

### `marmot_start_device_link`

Block on the account worker to start the shared compared-code link/move flow. Supply a non-NULL `out` and free the returned owned snapshot with `marmot_device_link_snapshot_free`, including its nested move views. Re-read on `MARMOT_EVENT_DEVICE_LINK_CHANGED`; see the [shared move contract](../marmot-uniffi/README.md#moving-this-device-to-another-device-group) and method guidance below for gates and progress.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotstart_device_link)

</details>

<details>
<summary>marmot_t…</summary>

### `marmot_telemetry_install_id`

Stable anonymous install id for telemetry. Free with `marmot_string_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmottelemetry_install_id)

### `marmot_timeline_messages`

Materialized timeline read. Free the page with `marmot_timeline_page_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmottimeline_messages)

### `marmot_timeline_subscription_next`

Block until the next item, the timeout, or stream close. `timeout_ms == 0` waits indefinitely. Returns `MARMOT_STATUS_OK` (out set; free with `marmot_timeline_page_free`), `MARMOT_STATUS_TIMEOUT`, or `MARMOT_STATUS_CLOSED` (out NULL for both).

### `marmot_timeline_subscription_set_callback`

Install a callback pump for this subscription. `callback` runs on a runtime worker thread with a borrowed item pointer (valid only during the call; do not store or free it) and a final NULL item on close. `callback` and `user_data` access must be thread-safe. Fails if a callback is already installed.

### `marmot_timeline_subscription_clear_callback`

Request cancellation of this subscription's callback pump, if any. Non-blocking: a callback already running keeps executing after this returns (see the module docs).

### `marmot_timeline_subscription_free`

Free the subscription handle. Requests callback-pump cancellation without waiting (a callback may still be running after this returns — do not free `user_data` on that basis). NULL is a no-op. Free every handle before the client that created it.

### `marmot_timeline_subscription_snapshot`

Take the initial window snapshot. Yields the page exactly once: later calls write NULL with `MARMOT_STATUS_OK`. Free the page with `marmot_timeline_page_free`.

### `marmot_timeline_subscription_next_update`

Block until the next raw delta (page replacement or projection update). Free with `marmot_timeline_subscription_update_free`.

### `marmot_timeline_subscription_paginate_backwards`

Extend the window toward older history by up to `count` messages and return the new window. Runs on the runtime off the caller's lock, so a concurrent blocking `next` on another thread is not blocked. Free with `marmot_timeline_page_free`.

### `marmot_timeline_subscription_paginate_forwards`

Extend the window toward the live head by up to `count` messages and return the new window. Reaching the head re-anchors the window. Free with `marmot_timeline_page_free`.

### `marmot_timeline_message_record_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_timeline_page_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_timeline_subscription_update_free`

Free a timeline-subscription delta returned by this library. NULL is a no-op.

### `marmot_timeline_edit_history_page_free`

Free a value of this type returned by this library. NULL is a no-op.

</details>

<details>
<summary>marmot_u…</summary>

### `marmot_uninstall_sticker_pack`

After a complete installed-list read, signs the proposed list before saving uninstall intent. A signing refusal does not queue this uninstall. Without a complete read, intent stays pending for a later `marmot_sync_sticker_packs`. Historical message references remain resolvable.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotuninstall_sticker_pack)

### `marmot_unrecognized_sign_in_list_free`

Free a list returned by this library. NULL is a no-op.

### `marmot_unrecognized_sign_ins`

List the sign-ins of this account that this device does not recognize, the earliest to appear first; blocks on the account worker without network I/O. Each `MarmotUnrecognizedSignIn` carries its `slot_id_hex` handle, the `client` it reports (empty when none), `appeared_at`, `last_seen_at`, `before_this_device` (ask whether the user still has it rather than whether it was them), `signed_in`, its `state`, and `linked_by_slot_id_hex`, set only for `LinkedElsewhere`. Always empty unless the host turns device groups on. Re-read on `MARMOT_EVENT_UNRECOGNIZED_SIGN_INS_CHANGED`. Free the list with `marmot_unrecognized_sign_in_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotunrecognized_sign_ins)

### `marmot_update_app_component`

Admin-only replacement of one optional application-owned component. `data` may be NULL with `data_len` of `0`; empty bytes are stored, not removed. Ids below `0xf000`, group-required components, and a `data_len` above 4096 return `MARMOT_STATUS_INVALID_APP_COMPONENT`. Before staging, the engine rejects updates whose resulting application-owned state exceeds 32 entries or 8192 encoded bytes (including entry ids and TLS payload length prefixes). Replacements count once; empty values still occupy a slot. The value is re-encoded into the GroupContext of every later commit and into every Welcome, so keep it small. Free with `marmot_send_summary_free`.

### `marmot_update_message_retention`

Set the per-group disappearing-message retention. `disappearing_message_secs` of `0` disables expiry. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotupdate_message_retention)

### `marmot_update_group_profile`

Update the group's name and/or description. NULL leaves a field unchanged. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotupdate_group_profile)

### `marmot_update_group_avatar_url`

Set (or clear, with `url` NULL) the group's URL-based avatar. The URL is validated (https-only, no localhost/private hosts) and normalized before commit. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotupdate_group_avatar_url)

### `marmot_unreact_from_message`

Remove all of this account's active reactions from a message. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotunreact_from_message)

### `marmot_unreact_matching`

Remove the account's active reactions matching the exact emoji. A local no-match
returns `MARMOT_STATUS_REACTION_NOT_FOUND` (132). Refresh authoritative state
before treating absence as convergence. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotunreact_from_message_matching)

### `marmot_user_profile`

Cached kind-0 profile for an account id; writes NULL with `MARMOT_STATUS_OK` when unknown. Free with `marmot_user_profile_metadata_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotuser_profile)

### `marmot_user_relay_lists`

Cached NIP-65 and inbox relay lists for any account id; no network. Free with `marmot_account_relay_lists_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotuser_relay_lists)

### `marmot_unblock_user`

Unblock a user and publish the updated list. Requires relay synchronization.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotunblock_user)

### `marmot_unfollow_user`

Unfollow `user_ref` and publish the updated list, keeping its other tags and content. Returns `MARMOT_STATUS_FOLLOW_LIST_TOO_LARGE`, publishing nothing, when the list has 2,048 follows or more. Free with `marmot_string_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotunfollow_user)

### `marmot_user_profile_website`

The `website` field of a cached kind-0 profile; writes NULL with `MARMOT_STATUS_OK` when unknown. Free with `marmot_string_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotuser_profile_website)

### `marmot_upload_prepared_group_image`

Upload a staged group image now, so a later group creation can consume it without waiting. Free with `marmot_prepared_group_image_upload_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotupload_prepared_group_image)

### `marmot_upload_media`

Encrypt and upload attachments (optionally sending them). Free with `marmot_media_upload_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotupload_media)

### `marmot_upsert_push_registration`

Register (or update) the account's native push token and share it. `platform` is a `MarmotPushPlatform` discriminant; out-of-range values are rejected with `MARMOT_STATUS_INVALID_ARGUMENT`. Free with `marmot_push_registration_sync_result_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotupsert_push_registration)

### `marmot_update_group_image`

Encrypt `plaintext` (the raw image bytes, `media_type` e.g. `"image/jpeg"`), upload it to Blossom, and commit it as the group's avatar. Requires admin. The bytes are copied — the caller keeps ownership. Free with `marmot_send_summary_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotupdate_group_image)

### `marmot_upload_profile_image`

Upload `data` (raw image bytes, `media_type` e.g. `"image/jpeg"`) to Blossom as the account's profile image. `blossom_server` overrides the default server; pass NULL to use it. The bytes are copied — the caller keeps ownership. Writes the image URL; free it with `marmot_string_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotupload_profile_image)

### `marmot_usage_diagnostics_settings`

# Safety `client` must be a live handle; string arguments must be valid NUL-terminated strings (nullable ones may be NULL); array arguments must hold their stated length (or be NULL with length 0); out-pointers must be valid.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotusage_diagnostics_settings)

### `marmot_usage_diagnostics_status`

# Safety `client` must be a live handle; string arguments must be valid NUL-terminated strings (nullable ones may be NULL); array arguments must hold their stated length (or be NULL with length 0); out-pointers must be valid.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotusage_diagnostics_status)

### `marmot_user_search_subscription_next`

Block until the next item, the timeout, or stream close. `timeout_ms == 0` waits indefinitely. Returns `MARMOT_STATUS_OK` (out set; free with `marmot_user_search_update_free`), `MARMOT_STATUS_TIMEOUT`, or `MARMOT_STATUS_CLOSED` (out NULL for both).

### `marmot_user_search_subscription_set_callback`

Install a callback pump for this subscription. `callback` runs on a runtime worker thread with a borrowed item pointer (valid only during the call; do not store or free it) and a final NULL item on close. `callback` and `user_data` access must be thread-safe. Fails if a callback is already installed.

### `marmot_user_search_subscription_clear_callback`

Request cancellation of this subscription's callback pump, if any. Non-blocking: a callback already running keeps executing after this returns (see the module docs).

### `marmot_user_search_subscription_free`

Free the subscription handle. Requests callback-pump cancellation without waiting (a callback may still be running after this returns — do not free `user_data` on that basis). NULL is a no-op. Free every handle before the client that created it.

### `marmot_user_profile_metadata_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_user_directory_search_result_list_free`

Free a list returned by this library. NULL is a no-op.

### `marmot_user_search_update_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_usage_diagnostics_settings_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_usage_diagnostics_status_free`

Free a value of this type returned by this library. NULL is a no-op.

</details>

<details>
<summary>marmot_w…</summary>

### `marmot_wipe_outcome_free`

Free a value of this type returned by this library. NULL is a no-op.

</details>

<details>
<summary>Host-managed automatic attachment acquisition</summary>

### `marmot_automatic_attachment_request_free`

Deep-free the returned automatic-request record and its nested status/reference. NULL is a no-op; do not free nested fields separately.

### `marmot_begin_attachment_permission_update`

Blocking revocation and generation issuance for HostManaged mode. Inputs are borrowed; free the returned generation with marmot_string_free. Call before asynchronous policy evaluation and keep the token with that evaluation. See the [shared permission contract](../marmot-uniffi/ATTACHMENT-ACCESS.md#host-managed-automatic-acquisition-0104).

### `marmot_request_automatic_attachment`

Blocking, idempotent automatic demand for the exact source slot. Inputs are borrowed; free the returned status/result with marmot_automatic_attachment_request_free. Repeated requests preserve suppression, acquisition history and retry budgets. See the [migration contract](../marmot-uniffi/ATTACHMENT-ACCESS.md#android-migration).

### `marmot_set_attachment_automatic_permission`

Blocking application of runtime-only category permission. All inputs are borrowed; boolean input integers use nonzero for true. False output means the generation was stale, foreign or already consumed. Required output validation occurs before mutation. See the [shared permission contract](../marmot-uniffi/ATTACHMENT-ACCESS.md#host-managed-automatic-acquisition-0104).

</details>

<details>
<summary>Durable local sends and caller correlation</summary>

### `marmot_local_send_acceptance_free`

Deep-free a returned local acceptance, including its token and message identity.
NULL is permitted; embedded acceptances belong to their parent upload result.

### `marmot_local_send_status`

Look up a retained token's local state without relay I/O. A NULL result means no
association. While MDK holds the send (state `0` or `1`), `message_id_hex` names its
event. State `4` means a send limited to member accounts was refused because the
group has a member it leaves out. Free a non-NULL result with `marmot_local_send_status_free`. Follow
timeline updates for subsequent delivery; see [local sends](../marmot-uniffi/LOCAL-SENDS.md).

### `marmot_local_send_status_free`

Deep-free a local status result and its optional completion summary. NULL is permitted.

### `marmot_media_upload_submission_free`

Deep-free an upload/submission result, including references and its optional token-bound
acceptance. NULL is permitted; never free its embedded records separately.

### `marmot_edit_local_message_with_client_token`

Block until MDK durably admits a revision of an original token-aware text or
reply in the same account and group. Give each submitted revision a new edit
token. This call returns local acceptance, not delivery; use
`marmot_local_send_status` for recovery and free the result with
`marmot_local_send_acceptance_free`. All string inputs are borrowed. Pair the
generated header with the matching library. See [pending edits](../marmot-uniffi/LOCAL-SENDS.md#edits-of-a-pending-local-send-0110).

### `marmot_reply_to_message_with_client_token`

Block until durable local reply acceptance, independently of relay publication.
Inputs are borrowed. Free the result with `marmot_local_send_acceptance_free` and
reconcile the optimistic bubble by timeline token. See [local sends](../marmot-uniffi/LOCAL-SENDS.md).

### `marmot_send_message_draft_with_client_token`

Atomically consume the borrowed draft revision and admit a correlated message.
Keep its revision owner alive during the call; attachment inputs are borrowed.
Free acceptance with `marmot_local_send_acceptance_free`; do not clear the composer
on delivery. See [local sends](../marmot-uniffi/LOCAL-SENDS.md).

### `marmot_send_custom_event_with_client_token`

Block until a custom application event is durably admitted under
`marmot_send_custom_event`'s rules, without waiting for relay publication. Use it for an
answer or a control sent to an agent (kind 1202): repeating the token after a restart
returns the same event and sends nothing. Free with `marmot_local_send_acceptance_free`.
See [local sends](../marmot-uniffi/LOCAL-SENDS.md).

### `marmot_send_text_with_client_token`

Block until text is durably admitted, without waiting for relay publication.
Use a unique token per logical submission; repeating its original request returns
the same identity. Free with `marmot_local_send_acceptance_free`.
See [local sends](../marmot-uniffi/LOCAL-SENDS.md).

### `marmot_submit_tagged_reply`

Admit a kind-9 inline reply with application tags. MDK supplies its `e` and
`q` tags. Free the local receipt with `marmot_local_send_acceptance_free`.
See [local sends](README.md#local-sends).

### `marmot_submit_tagged_sticker`

Admit a pack sticker with context tags. The coordinate, shortcode, and hash
must identify a sticker known to this account. Free the local receipt with
`marmot_local_send_acceptance_free`. See [local sends](README.md#local-sends).

### `marmot_submit_tagged_text`

Admit a kind-9 text message with application tags, excluding `imeta`. Free
the local receipt with `marmot_local_send_acceptance_free`. See
[local sends](README.md#local-sends).

### `marmot_submit_thread_message`

Admit a NIP-22 comment. Pass uploaded attachments in display order, with
their upload epoch identity. MDK builds placement and `imeta` tags. Free the
local receipt with `marmot_local_send_acceptance_free`. See
[local sends](README.md#local-sends).

### `marmot_upload_media_with_client_token`

Block for upload and optional durable message admission. Inputs are borrowed;
free the result with `marmot_media_upload_submission_free`. Uploads are not
idempotent: query token status after an unknown outcome before repeating them.
See [local sends](../marmot-uniffi/LOCAL-SENDS.md) for epoch and cancellation semantics.

</details>

<details>
<summary>Stateless public-event verification</summary>

### `marmot_verify_public_nostr_event_json`

Verify both the canonical ID and BIP-340 signature of a public Nostr event.
No client, account, or secret key is required. The borrowed UTF-8 JSON input
is not retained; the required `out` pointer is cleared before validation.
Malformed JSON or failed verification yields `MARMOT_STATUS_OK` with zero,
while null or invalid-UTF-8 arguments return a status error. The caller must
bound untrusted JSON and separately enforce author, kind, tag, relay provenance,
and MLS membership policy. Pair this header with the exact matching library.

</details>

<details>
<summary>Audit v5 configuration, results and subscription errors</summary>

### `marmot_audit_delivery_status_v5`

Read each account's persisted v5 OTLP delivery status: last success, last typed failure with the receiver's HTTP status when it answered (`has_http_status`), consecutive failed passes, rejected batches, whether automatic delivery is paused after a receiver block, and the last measured backlog. Local read only; it never dials. `last_failure` and `backlog` are NULL until a v5 pass records them. Free the list with `marmot_audit_delivery_status_v5_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotaudit_delivery_status_v5)

### `marmot_audit_delivery_status_v5_free`

Free one `MarmotAuditDeliveryStatusV5` row and its nullable `last_failure` and `backlog`. Rows inside a list are released by the list free instead. NULL is a no-op.

### `marmot_audit_delivery_status_v5_list_free`

Free the list returned by `marmot_audit_delivery_status_v5`, including every row's strings and nested records. NULL is a no-op.

### `marmot_audit_log_tracker_update_result_v5_free`

Free the tracker result returned by `marmot_post_audit_log_tracker_update_v5`, including its nested v5 summary. NULL is a no-op.

### `marmot_audit_otlp_config_v5_free`

Free the redacted configuration returned by `marmot_set_audit_otlp_config_v5`. The returned bearer token pointer is NULL; the host remains responsible for its borrowed input strings. NULL is a no-op.

### `marmot_post_audit_log_tracker_update_v5`

Run one manual v5 OTLP delivery pass. Configure recording and the v5 sender separately. The optional v5 result is NULL when no sender is configured; accepted, pending, blocked, and idle counts distinguish a complete receiver acknowledgment from work that remains local. Free the result with `marmot_audit_log_tracker_update_result_v5_free`.

### `marmot_set_audit_otlp_config_v5`

Configure or disable the dedicated v5 OTLP sender in memory. To enable, supply a stable destination identity, HTTPS `/v1/logs` endpoint, and bearer token; exact loopback development endpoints require `allow_loopback_dev`. To disable, set `enabled` false. The returned copy omits the token and is freed with `marmot_audit_otlp_config_v5_free`. This does not enable audit recording or alter the legacy v4 endpoint.

</details>

<details>
<summary>File-backed media transfers</summary>

### `marmot_max_file_media_ciphertext_bytes`

Return the finite per-batch ciphertext implementation bound, including a 16-byte AEAD tag for each attachment. It is not a server maximum or a preview/heap limit. No allocation is returned.

### `marmot_media_file_transfer_control_cancel`

Cancel snapshot preparation, transfer or fallback. Cancellation observed before message admission starts prevents publication; admission is not interruptible once started, even before durable acceptance returns. Delivery then belongs to the local-send queue. May run concurrently with the upload; never free the control while any call on it is active.

### `marmot_media_file_transfer_control_free`

Release the control after upload and all query/cancel calls return. NULL is accepted. Freeing is not cancellation; use the explicit cancel method before releasing an active operation.

### `marmot_media_file_transfer_control_is_cancelled`

Read cancellation into a required output (0 or 1). The output is cleared before input validation. May run concurrently with upload; the handle must remain live throughout the call.

### `marmot_media_file_transfer_control_new`

Create one owned control per file upload. The required output is checked and cleared before allocation. Keep it live through the blocking upload, and release it with `marmot_media_file_transfer_control_free` after all calls return; do not reuse a cancelled control.

### `marmot_media_file_transfer_control_processed_bytes`

Read monotonic processed bytes into a required cleared output. It counts the copy into the encrypted media store, the digest pass and the transfer, including retries, so it can exceed the source length; this is not a percentage. Query concurrently without freeing the handle.

### `marmot_upload_media_files`

Blocking file-backed upload using borrowed regular-file inputs, copied into the account's encrypted media store before PUT; `MARMOT_STATUS_STORAGE_FULL` when the disk cannot hold a source beyond its reserve, before anything is uploaded. Use off the UI thread and keep strings, request and source paths valid until return. Required output preflight precedes work. Ordered fallback preserves identical ciphertext; signer denial/cancellation stops. Free the owned result with `marmot_media_upload_result_free`. See the [shared contract](../marmot-uniffi/README.md#file-backed-media-upload).

### `marmot_upload_media_files_with_client_token`

Token-aware blocking twin: upload all files, then optionally admit the resulting message when `send` is set. Keep one token for the logical submission and probe `marmot_local_send_status` after an interrupted/unknown outcome before reuploading. Input and control lifetimes match `marmot_upload_media_files`; free the result with `marmot_media_upload_submission_free`. Admission is not interruptible once started and does not certify relay delivery. There is no fixed worker-response timeout; per-endpoint network deadlines still apply.

</details>

<details>
<summary>File-backed draft attachments</summary>

### `marmot_save_message_draft_inputs_if_revision`

Save only if the selected revision still matches, keeping attachments the draft already holds by id, copying new inline ones and removing those named by `removed_id`. Each `MarmotMessageDraftAttachmentSaveInput` with a non-NULL `retained_id` keeps that attachment, body untouched; one with a non-NULL `removed_id` removes that attachment and its file; either way its `attachment` is ignored. One with both NULL copies `attachment` as a new inline body, replacing (and releasing the file of) an attachment the draft holds with the same id; both non-NULL is `MARMOT_STATUS_INVALID_ARGUMENT`. Every attachment the save does not name stays, after the named ones in their stored order. A retained id the draft does not hold is `MARMOT_STATUS_INVALID_MESSAGE_DRAFT`; removing one changes nothing. # Safety As `marmot_save_message_draft_if_revision`, with `inputs` pointing to `inputs_len` readable items (or NULL with zero length). Inputs are borrowed.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotsave_message_draft_inputs_if_revision)

### `marmot_stage_message_draft_attachment_file`

Copy a host file into the encrypted media store and append it to the draft `revision` selects; `out` gets the new selected draft (free with `marmot_selected_message_draft_free`). The host may delete its file once this returns. Refused before copying: over the blob limit, past 64 attachments or one upload batch, a duplicate id, or a copy the disk cannot hold beyond its reserve (`MARMOT_STATUS_STORAGE_FULL`). Text saves during the copy keep it; the next save with an older revision conflicts, so reload. A draft cleared, deleted or sent during the copy discards it (`MARMOT_STATUS_MESSAGE_DRAFT_REVISION_CONFLICT`). `control` reports copied bytes and cancels; a cancelled copy leaves nothing. Blocking for the whole copy: call off the UI thread. # Safety Client, control, strings, request and revision valid until return; out writable.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotstage_message_draft_attachment_file)

### `marmot_read_message_draft_attachment`

Read 1..=1048576 bytes at `offset` from one draft attachment, inline or file-backed. `out_found` 0 means the draft holds no such attachment; 1 with zero bytes is the end. Revision conflicts return an error. Free returned bytes with `marmot_bytes_free`. Blocking local read. # Safety Client, strings and revision valid; the revision's owning draft stays live; all out pointers writable.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotread_message_draft_attachment)

### `marmot_open_message_draft_attachment_handoff`

`marmot_open_attachment_handoff` for one draft attachment: a plaintext copy for an OS surface that needs a real file, released with `marmot_release_attachment_handoff`. The revision is checked once, before the copy. `out` stays NULL when the draft holds no such attachment. Free the record with `marmot_attachment_handoff_free`; that does not release the lease. Blocking for the whole copy; cancel through `control`. # Safety Client, control, strings and revision valid until return; out writable.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotopen_message_draft_attachment_handoff)

### `marmot_upload_message_draft_attachments`

`marmot_upload_media_files` for the draft attachments `ids` names (1..=64, in order), read from the draft's own copies. Upload only: pass the returned references, in order, to `marmot_send_message_draft` with the same revision. `blossom_server` (nullable) overrides the group's endpoints. Free with `marmot_media_upload_result_free`. Blocking. # Safety Client, control, strings, `ids` (`ids_len` readable strings) and revision valid until return; out writable.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotupload_message_draft_attachments)

</details>

### `marmot_message_draft_revision_includes_chat_list_version`

Compare the opaque `draft_version` from a presented chat-list row with a live captured draft revision. Returns 1 only for the same account-store/group scope at or before that captured revision; foreign and newer versions return 0. Borrow both opaque handles for the call while their owning selected draft and presented row remain live and supply a non-NULL output byte, which is reset on errors. Treat the version as private presentation correlation: never parse, log or persist it, and never use it to select a newer draft for deletion. Revision-checked draft cleanup remains authoritative. Regenerate bindings and consume the matching native binary before adopting this added row field.

<details>
<summary>Account attachment history</summary>

### `marmot_account_attachment_history_page`

Blocking account-local candidate paging; call off the UI thread. Borrow query arrays and an optional cursor only for the call. Empty filtered pages can have a continuation; deep-free the root result once and keep its cursor/version fields borrowed. See [Account attachment history](../marmot-uniffi/ACCOUNT-ATTACHMENT-HISTORY.md).

### `marmot_account_attachment_history_version`

Read a constant-work local account change token, without acquisition or decryption. The returned version is independently owned and is released by marmot_account_attachment_version_free.

### `marmot_account_attachment_page_read_free`

Deep-free the root page result, including entries and its opaque cursor/version fields. NULL is harmless. Do not free fields separately or free a result while a call borrows its cursor.

### `marmot_account_attachment_version_change_since`

Compare the current version with a retained original baseline. The output is a MarmotAttachmentHistoryChange discriminant: Unchanged, Additions or RestartRequired. Replace loaded rows after destructive changes; additions leave older seeks valid and offer a head refresh.

### `marmot_account_attachment_version_clone`

Clone a borrowed page version into an independently owned baseline so it can outlive the page. Release the clone with marmot_account_attachment_version_free; the original remains owned by its root result.

### `marmot_account_attachment_version_free`

Release a standalone version returned by a version read or clone. NULL is harmless. Never pass a borrowed version field whose root page owns it.

</details>

<details>
<summary>Moderation reporting</summary>

### `marmot_configure_moderation_reporting`

Install the private moderation-report destination at runtime, or clear it when `recipient_pubkey` is NULL. C hosts use this instead of a `MarmotClientOptions` field so the borrowed options layout stays unchanged. The recipient is 64-character hex or `npub`; every relay must pass the relay safety policy. One bad entry rejects the whole destination with `MARMOT_STATUS_INVALID_MODERATION_REPORT_CONFIG` and leaves reporting unconfigured.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotconfigure_moderation_reporting)

### `marmot_moderation_report_outcome_free`

Free a value of this type returned by this library. NULL is a no-op.

### `marmot_moderation_reporting_available`

Write whether a valid moderation-report destination is installed. Hosts gate the "Report to White Noise" affordance on it; submitting without one fails with `MARMOT_STATUS_MODERATION_REPORTING_NOT_CONFIGURED` and publishes nothing.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotmoderation_reporting_available)

</details>

<details>
<summary>Native startup diagnostics</summary>

### `marmot_native_startup_snapshot_free`

Release the owned native-startup snapshot and both record arrays returned by `marmot_startup_diagnostics_snapshot`. Passing NULL is safe. Do not free embedded records separately or retain pointers after this call.

### `marmot_set_startup_diagnostics_enabled`

Enable or revoke the opt-in native memory capture exposed by MarmotKit. Nonzero `enabled` enables recording; normal clients leave it disabled. Disabling clears capture and fences older scopes. This changes no database, upload consent, network or cryptographic policy. The client must remain live for the call.

### `marmot_startup_diagnostics_snapshot`

Read bounded fixed phases and migration progress without database or keystore queries, before or during native startup. `out` must be writable; release the returned snapshot and its owned active/event arrays with `marmot_native_startup_snapshot_free`. Only anonymous scope tokens, timings/schema progress and fixed enums are returned. Serialization and export remain explicit host actions.

</details>

<details>
<summary>Captured media admission</summary>

### `marmot_send_prepared_media_with_client_token`

C binding for [captured ordinary-media admission](../marmot-uniffi/LOCAL-SENDS.md#captured-ordinary-media-drafts). Inputs and the nullable captured revision are borrowed; free the owned result with `marmot_local_send_acceptance_free`. Use the matching generated header and native library.

</details>

<details>
<summary>Public event previews</summary>

### `marmot_cached_public_event_previews`

Blocking, network-free read of cached public event previews: one row per reference (at most 16, else `MARMOT_STATUS_INVALID_PUBLIC_EVENT_REFERENCES`) in request order, echoing each reference. `event_json` is non-NULL only for `Present`. Call off the UI thread and free the list with `marmot_public_event_preview_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotcached_public_event_previews)

### `marmot_public_event_preview_free`

Free one `MarmotPublicEventPreview` returned by `marmot_resolve_public_event_preview`, including its strings. NULL is a no-op.

### `marmot_public_event_preview_list_free`

Free a `MarmotPublicEventPreviewList` and every row in it. Do not free individual rows. NULL is a no-op.

### `marmot_resolve_public_event_preview`

Blocking relay refresh of one reference when it is missing or stale, then its local state. Free with `marmot_public_event_preview_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotresolve_public_event_preview)

</details>

<details>
<summary>Deployment configuration</summary>

Deployment services a host configures at construction: start from a preset, change what differs, pass it to any `marmot_client_new*` constructor, then free it.

### `marmot_deployment_white_noise`

Create White Noise's deployment, the one White Noise hosts pass to every constructor. Free it with `marmot_deployment_free`; a client constructed with it keeps its own copy.

### `marmot_deployment_neutral`

Create a deployment with no services and the neutral keychain service `org.marmot-protocol.mdk`, then fill in what your deployment operates with the setters. Free it with `marmot_deployment_free`. Unset values fall back to nothing: with no new-group media servers new groups stay text-only, and with no group-image server group images are refused.

### `marmot_deployment_free`

Free a deployment. NULL is a no-op. Clients constructed with it are unaffected.

### `marmot_deployment_set_recovery_operated_relays`

Replace the relays the deployment operates. A route's history certifies once these finish a full comparison; a route with none of them requires all of its relays. Changing the set rebuilds pending recovery scopes once.

### `marmot_deployment_set_discovery_indexer_relays`

Replace the public indexers that onboarding and account setup also search for an account's relay list and profile. They are never adopted as messaging relays. `(NULL, 0)` clears the list.

### `marmot_deployment_set_new_group_media_endpoints`

Replace the Blossom servers signed into a new group's encrypted-media component. Each must accept opaque `application/octet-stream` blobs. Existing groups keep their signed list. With an empty list new groups carry no encrypted-media component and stay text-only.

### `marmot_deployment_set_group_image_endpoint`

Set the Blossom server for encrypted group images, or unset it with NULL. Group state records no server, so every client sharing a group must use the same one. With no server, setting or fetching a group image is refused.

### `marmot_deployment_set_profile_image_endpoint`

Set the public profile-image upload server, or unset it with NULL. Peers' avatars load from the URL in their profile, never from here. With no server, a profile-image upload needs an explicit one.

### `marmot_deployment_set_open_ranking`

Set the Open Ranking search endpoint and the relays that hydrate its results. A NULL endpoint or no profile relay turns the tier off; personal graph search is unaffected.

### `marmot_deployment_set_moderation_label_namespace`

Set the NIP-32 namespace on moderation report labels, which the operator's report parser matches, or unset it with NULL. With no namespace, `marmot_configure_moderation_reporting` refuses a destination.

### `marmot_deployment_set_keychain_service`

Set the platform keychain service used for account secrets when no secret store is supplied. A blank name is the neutral one. Changing it for an existing install strands the secrets stored under the old name.

### `marmot_deployment_set_relay_event_limits`

Replace the largest event, in bytes of serialized event JSON, each listed relay accepts when it does not advertise it: `relays[i]` takes `max_event_bytes[i]`. MDK sends no group event or Welcome over a relay's known limit, and a send that fits none of its relays fails as `MARMOT_STATUS_EVENT_TOO_LARGE`. A blank relay or a zero limit is ignored, a relay listed twice keeps the smaller limit, and NULL with 0 clears the list.

</details>

<details>
<summary>Backup recovery and observation</summary>

### `marmot_backup_history_availability`

Read current-chat private availability hints. The MLS id is variable-length; no hint creates membership or proves content is downloadable. Free the returned list with `marmot_backup_history_availability_list_free`.

### `marmot_backup_history_availability_list_free`

Deep-free the owned availability list and its strings; NULL is allowed. Do not free its embedded elements separately.

### `marmot_backup_restore_status`

Read aggregate restore progress. Complete does not prove global history completeness or pointer existence. Free the returned status with `marmot_backup_restore_status_free`.

### `marmot_backup_restore_status_free`

Deep-free an owned status and its optional operation token. NULL is allowed. Do not free callback-borrowed status pointers.

### `marmot_backup_restore_subscription_clear_callback`

Stop future observer callbacks; an already running callback may still use user_data. This does not cancel restore or wait for that callback. Preserve user_data until all invocations finish.

### `marmot_backup_restore_subscription_free`

Release the observer handle before its client, with no concurrent calls using it. Restore continues until explicit cancellation, terminal completion or worker shutdown; running callbacks retain the usual lifetime obligations.

### `marmot_backup_restore_subscription_next`

Wait for a progress/availability revision. Zero timeout waits indefinitely; TIMEOUT or CLOSED returns no item. On OK, free the owned status with `marmot_backup_restore_status_free`. Closing observation never cancels the job.

### `marmot_backup_restore_subscription_set_callback`

Install a progress observer. Item pointers are borrowed only during the callback and must not be freed. Keep user_data alive through any running callback; clear/free does not cancel restore or join callbacks.

### `marmot_backup_restore_subscription_snapshot`

Take the initial status once. OK with NULL means already consumed; free a non-NULL status with `marmot_backup_restore_status_free`. Use next or callbacks for subsequent revisions.

### `marmot_backup_settings`

Read selected account backup settings, not a publication receipt. Free the result with `marmot_backup_settings_free`; re-read after submitted/concurrent setting changes.

### `marmot_backup_settings_free`

Deep-free an owned settings record; NULL is allowed. This changes no backup settings.

### `marmot_begin_backup_restore`

Start one manual current-membership history restore with borrowed recovery words. Keep input valid until this blocking call returns, then clear host copies; MDK never retains its pointer. Free the returned status and retain its opaque account-scoped token if cancellation is needed. This never joins chats or changes the current recovery key.

### `marmot_begin_recovery_words`

Generate twelve setup words and two 1-based confirmation positions. Display once, never log/persist, and free output with `marmot_recovery_words_free`, which erases the returned word buffers before release. Clear host copies separately; earlier managed/FFI copies are outside that free's scope.

### `marmot_cancel_backup_restore`

Cancel only the operation named by the borrowed token. OK with false means stale, not cancellation of the current job; malformed tokens are rejected. Committed history stays. This is separate from freeing an observer.

### `marmot_cancel_recovery_words`

Forget pending setup words without changing current backups. Clear caller-owned copies separately.

### `marmot_confirm_recovery_words`

Pass the two answers in requested position order as borrowed strings. Keep the array/strings live for the call and clear host buffers afterward. Busy/error keeps the core setup available; read selected settings again after success.

### `marmot_recovery_words_free`

Erase the returned word buffers, then deep-free the record and confirmation positions; NULL is allowed. It does not erase host copies or earlier managed/FFI copies. This is not the pending setup cancel command.

### `marmot_run_due_backup_pass`

Block for one current/newly admitted due pass through serialized settlement and credit release, writing the two-value outcome by value to a required out pointer; no free is needed. FinishedAttempt includes failed attempts and is not pointer-publication success. NotStarted means this call joined/admitted none, including disabled device-group support. Call off the UI thread; stopping the worker/runtime from another thread ends the wait with MARMOT_STATUS_TRANSPORT_CLOSED. This does not force a backup, wait for future due work, or drain all runtime work.

### `marmot_set_runtime_backup_background_conditions`

Report the runtime-wide current Wi-Fi and charging facts before workers exist and on changes; both are required for background admission. The latest report survives account-worker replacement and intervals with no workers, while a new runtime starts closed. This requires no account and starts no worker; eligible reports wake existing due dispatchers. An admitted pass settles after false. Manual restore remains independent. Boolean inputs are uint8_t: zero is false and nonzero is true.

### `marmot_set_backup_background_conditions`

Compatibility wrapper for the runtime-wide platform report. It validates the existing active, signable, fully onboarded account before changing the shared facts and never starts that account worker. Prefer the account-free runtime setter; no parameter or return layout changed. Admitted passes settle after false; manual restore is independent.

### `marmot_turn_off_backups`

Disable future account backups without deleting stored archives or cancelling an admitted pass. Re-read selected settings to display the outcome.

### `marmot_watch_backup_restore`

Create an observer for initial snapshot and later aggregate revisions. Free the handle before the client; freeing it does not cancel restore. Read snapshot once, then use next or callbacks with their usual ownership rules.

</details>

<details>
<summary>Chat-list selection</summary>

### `marmot_chat_list_ids`

Select all: every chat ID in a MarmotChatListView, in display order, beyond any open window; `len` is the count. Returns `MARMOT_STATUS_CHAT_PRESENTATION_NOT_READY`, never a partial list, while base rows are being prepared. Free with `marmot_string_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotchat_list_ids)

### `marmot_revalidate_chat_list_ids`

The subset of a host selection still in the view, in the caller's order with duplicates dropped; never adds chats. Call before a bulk action, then use the per-chat commands. The input array is borrowed. Free the result with `marmot_string_list_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotrevalidate_chat_list_ids)

</details>

<details>
<summary>NIP-51 emoji sets</summary>

### `marmot_emoji_set`

Reads one stored set by coordinate or `naddr` without network I/O. Returns NULL when absent. Free with `marmot_emoji_set_free`.

### `marmot_emoji_set_asset_free`

Frees a preview asset and its bytes. NULL is safe.

### `marmot_emoji_set_cover_free`

Frees a cover image and its bytes. NULL is safe.

### `marmot_emoji_set_free`

Frees one emoji set, its entries, skips and installed state. NULL is safe.

### `marmot_emoji_set_install_control_cancel`

Cancel the install from any thread: no new download starts, those in flight are dropped, nothing is stored and `marmot_install_emoji_set` returns `MARMOT_STATUS_EMOJI_SET_INSTALL_CANCELLED`; a cancelled reinstall leaves the previous snapshot readable. Too late once the final atomic write has started. Never free the control while any call on it is active.

### `marmot_emoji_set_install_control_free`

Release the control after the install and all query/cancel calls return. NULL is accepted. Freeing is not cancellation.

### `marmot_emoji_set_install_control_is_cancelled`

Writes 1 when cancellation was requested, by the host or by runtime shutdown or close (which cancel every running install), else 0.

### `marmot_emoji_set_install_control_new`

Create one control per `marmot_install_emoji_set` call; it is never reused across installs. Free with `marmot_emoji_set_install_control_free`.

### `marmot_emoji_set_install_control_progress`

Writes entries finished (`completed_emoji`), entries to try (`total_emoji`, 0 until the install has read the stored version) and response bytes received (`transferred_bytes`, counted as each download finishes). A plain value: nothing to free.

### `marmot_emoji_set_install_result_free`

Frees an install result, its set and skips. NULL is safe.

### `marmot_emoji_set_list_free`

Frees an emoji set list and every set in it. NULL is safe.

### `marmot_emoji_set_sync_result_free`

Frees an emoji set sync result. NULL is safe.

### `marmot_emoji_sets`

Reads stored emoji sets; the read runs off the embedded runtime's workers while this call blocks. `installed_only` returns installed snapshots in install order. `search` may be NULL. No network I/O. Free with `marmot_emoji_set_list_free`.

### `marmot_fetch_emoji_set`

Fetches one set from a pasted coordinate or `naddr`, trying up to 8 relay hints and then the account relays. Text only. Free with `marmot_emoji_set_free`.

### `marmot_fetch_emoji_set_asset`

Downloads and validates one emoji for a preview; nothing is stored. Reveals the user's IP address to the image host: call only after the user opens the set, with the shown version's `event_id_hex` (`MARMOT_STATUS_EMOJI_SET_CHANGED` otherwise, before any download). Free with `marmot_emoji_set_asset_free`.

### `marmot_fetch_emoji_set_cover`

Downloads and validates a stored set's cover image (`image_url`) under the emoji image limits; nothing is stored. Reveals the user's IP address to its host: call only after the user opens the set, with the shown version's `event_id_hex` (`MARMOT_STATUS_EMOJI_SET_CHANGED` otherwise, before any download). A set without a cover is `MARMOT_STATUS_EMOJI_SET_NOT_FOUND`. Free with `marmot_emoji_set_cover_free`.

### `marmot_install_emoji_set`

Snapshots the stored set version, downloads and validates each emoji once, and stores the bytes and SHA-256. Skipped entries are listed, not fatal. Reinstalling the installed version keeps each verified image whose refresh fails or does not fit; that entry stays installed and is not listed as skipped. Reveals the user's IP address to the set's image hosts: call only after the user taps Install. `expected_event_id_hex` is the version the user was shown: another stored version is `MARMOT_STATUS_EMOJI_SET_CHANGED` (detail names the current id) and nothing stored is `MARMOT_STATUS_EMOJI_SET_NOT_FOUND`, both before any download. `control` (from `marmot_emoji_set_install_control_new`) reports progress and cancels; a cancelled install, or one stopped by runtime shutdown or close, is `MARMOT_STATUS_EMOJI_SET_INSTALL_CANCELLED` and stores nothing. Free with `marmot_emoji_set_install_result_free`.

### `marmot_installed_custom_emoji`

Every installed emoji for a picker, with no URL; shortcode collisions are flagged, not resolved. No network I/O. Free with `marmot_installed_custom_emoji_list_free`.

### `marmot_installed_custom_emoji_asset_free`

Frees an installed emoji asset and its bytes. NULL is safe.

### `marmot_installed_custom_emoji_free`

Frees one installed emoji record. NULL is safe.

### `marmot_installed_custom_emoji_list_free`

Frees an installed emoji list. NULL is safe.

### `marmot_read_installed_custom_emoji`

Reads an installed emoji's stored bytes, checked against their SHA-256. No network I/O. Send them only as an encrypted attachment. Free with `marmot_installed_custom_emoji_asset_free`.

### `marmot_sync_emoji_sets`

Fetches up to 60 of the newest kind-30030 sets from the account's relays. Text only: never fetches an image. Free with `marmot_emoji_set_sync_result_free`.

### `marmot_uninstall_emoji_set`

Removes an installed snapshot and its stored bytes; writes whether it was installed. No network I/O.

### `marmot_user_emoji_list`

Reads the account's kind-10030 emoji list and the sets it points to, for suggestions. Text only; MDK never publishes or edits kind 10030. Free with `marmot_user_emoji_list_free`.

### `marmot_user_emoji_list_free`

Frees a user emoji list, its sets and missing coordinates. NULL is safe.

</details>

## Account relay health

### `marmot_account_relay_health`

Write the account's relay health from its cached lists and the dial policy: `rows` (`roles`, `state`, `fault` read only when
`has_fault`, `liveness`), `warnings` about invitations sent through the published inbox list, ordered from the most severe, `highest_severity` read only when
`has_highest_severity`, `inbox_list` and `falls_back_to_defaults`. A local read that never dials; the call blocks the
calling thread. Re-read on `MARMOT_EVENT_RELAY_HEALTH_CHANGED`. Keep a default case over the warning kind, fault,
action, role and state enums. Free the result with `marmot_account_relay_health_free`.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotaccount_relay_health)

### `marmot_account_relay_health_free`

Deep-free a record returned by `marmot_account_relay_health`, including its rows, warnings, URLs, role and action arrays. NULL is a no-op.

## Relay liveness

### `marmot_account_relay_liveness`

Read an account's configured relay states without dialing. `out` receives an owned list on success;
release it with `marmot_relay_liveness_list_free`. Unknown entries and optional attempt/error fields follow the
[shared relay contract](../marmot-uniffi/README.md#relay-liveness). Inputs are borrowed.

### `marmot_reconnect_relay`

Dispatch through the running account worker; once handled, the dial wait is capped at five seconds.
Normal dial safety applies. The returned owned record may still report `Connecting`; free it with
`marmot_relay_liveness_free` and use the subscription for later outcomes. Inputs remain borrowed.

### `marmot_relay_liveness_free`

Deep-free a record returned by `marmot_reconnect_relay`, including its URL and optional error string.
NULL is a no-op. Never free a record embedded in a list or borrowed by a callback separately.

### `marmot_relay_liveness_list_free`

Deep-free a snapshot list and all its nested records and strings. NULL is a no-op.
Use only for owned getter, snapshot, or blocking-next results, never callback payloads.

### `marmot_relay_liveness_subscription_clear_callback`

Request cancellation of the installed callback pump without closing the observer. The call does not wait for an
executing callback and does not guarantee a terminal callback. Keep `user_data` live until callbacks are quiescent.

### `marmot_relay_liveness_subscription_cancel`

Close only this observer; pending and future reads return `MARMOT_STATUS_CLOSED`. The account's connections
remain unchanged. Free the handle separately after all concurrent calls have ended.

### `marmot_relay_liveness_subscription_free`

Free the observer handle before freeing its client. NULL is a no-op. No calls may still be using the handle.
Callback cancellation does not wait for an already executing callback; its context must remain valid.

### `marmot_relay_liveness_subscription_next`

Block for the next complete replacement list. Zero timeout waits indefinitely; a positive timeout is milliseconds.
Success returns an owned list to free with `marmot_relay_liveness_list_free`. Timeout, close, and mapped read errors
leave `out` NULL. A timed-out call consumes no update. Do not mix blocking reads with an installed callback.

### `marmot_relay_liveness_subscription_set_callback`

Install one callback pump instead of blocking reads. `MARMOT_STATUS_OK` accompanies a borrowed list valid only
during the callback; the pump deep-frees it afterward. Terminal NULL carries `MARMOT_STATUS_CLOSED` or a mapped
read-error status. Callbacks run on runtime workers. `user_data` must outlive every executing callback.

### `marmot_relay_liveness_subscription_snapshot`

Take the initial owned snapshot once; subsequent calls return owned empty lists. Free each result with
`marmot_relay_liveness_list_free`. Reading the initial snapshot does not consume a later update.

### `marmot_subscribe_relay_liveness`

Create an account-scoped relay observer. Take its initial snapshot, then use blocking `next` or install a callback
for complete replacement lists. Intermediate states may coalesce. Close the watch when it is no longer needed,
then free its handle before freeing the client. Client and account inputs remain borrowed.

## Group member result ownership

### `marmot_detailed_creation_free`

Free a detailed creation result, its optional created-group row, and all member outcomes. NULL is a no-op. Nested fields are borrowed from this root; do not free them separately.

### `marmot_group_creation_free`

Free a creation result, its optional group id, and all member outcomes. Call this for successful all-unavailable results too. NULL is a no-op; nested fields must not be freed separately.

### `marmot_group_invite_free`

Free a detailed invitation result, including its nested invitation, details, and management state. NULL is a no-op. Do not free the embedded invitation or any nested fields separately.

### `marmot_invite_members_free`

Free an invitation result, its optional send summary, and all member outcomes. Call this even when `summary` is NULL. NULL is a no-op; nested fields must not be freed separately.

<details>
<summary>Direct-follow availability</summary>

### `marmot_cancel_follow_availability`

Cancel only the operation identified by the status `operation_id`. Writes `false` when that operation already finished or a newer one replaced it; committed per-target results remain readable. The call blocks the calling thread.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotcancel_follow_availability)

### `marmot_follow_availability_page`

Read the selected account's direct follows from its encrypted cache without networking. Pass `next_cursor` as `after` for the next page; `limit` clamps to 1 through 100. `ready` describes a usable KeyPackage, not which app the account installed. Keep the blocking read off the UI thread and free the returned page.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotfollow_availability_page)

### `marmot_follow_availability_page_free`

Free one availability page, including every embedded row and optional string. NULL is a no-op. Do not free embedded fields separately.

### `marmot_follow_availability_refresh_status_free`

Free one refresh status record. NULL is a no-op.

### `marmot_follow_availability_status`

Read current or last refresh progress without starting another refresh. Use its `operation_id` for operation-matched cancellation. Keep the blocking read off the UI thread and free the returned status.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotfollow_availability_status)

### `marmot_refresh_follow_availability`

Refresh at most 100 direct follows with bounded relay work and persist each completed target. Page committed results while the call runs; concurrent callers share one refresh. The call blocks the calling thread. Free the returned status.

[Shared method and API guidance](../marmot-uniffi/API-GUIDE.md#marmotrefresh_follow_availability)

</details>

