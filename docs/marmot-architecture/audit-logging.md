---
title: "Forensic Audit Logging Inventory"
created: 2026-06-10
updated: 2026-06-10
tags: [marmot, architecture, audit, forensics, jsonl, privacy]
status: current
---

# Forensic Audit Logging Inventory

This is a source-grounded inventory of the append-only JSONL audit logging used for Marmot forensic incident capture.
It is intentionally separate from the privacy-safe telemetry/tracing surface described in
[`telemetry.md`](./telemetry.md).

Audit logs are sensitive local artifacts. They are opt-in, raw enough for incident reconstruction, and should not be
treated like telemetry.

## Current status

| Surface | Current state |
| --- | --- |
| Local JSONL recording | Implemented by `marmot-forensics::JsonlRecorder`, installed into each `AccountDeviceSession` only when app-level `AuditLogSettings.enabled` is true before that account session opens. |
| Default behavior | Off. Without an installed recorder, the engine uses `NoopRecorder` and emits no JSONL records. |
| File shape | Append-only JSONL/NDJSON, one `AuditEvent` per line, schema version `marmot-forensics-audit/v1`. |
| Local file location | `<account_dir>/audit-<engine_id>.jsonl` for app-opened account sessions. |
| Upload/listing | App and UniFFI expose listing and explicit upload of local `audit-*.jsonl` files. Runtime can also post all local audit files to a configured tracker. |
| Static bundle analyzer | Not present in the current repo path. The current artifact model is raw append-only JSONL audit logs. |

## Source map

| Area | Files |
| --- | --- |
| Schema and recorder trait | [`crates/marmot-forensics/src/audit.rs`](../../crates/marmot-forensics/src/audit.rs) |
| Engine recorder installation point | [`crates/cgka-engine/src/engine.rs`](../../crates/cgka-engine/src/engine.rs), [`crates/cgka-session/src/lib.rs`](../../crates/cgka-session/src/lib.rs) |
| Stable audit string helpers | [`crates/cgka-engine/src/audit_helpers.rs`](../../crates/cgka-engine/src/audit_helpers.rs) |
| Engine audit call sites | [`engine.rs`](../../crates/cgka-engine/src/engine.rs), [`message_processor.rs`](../../crates/cgka-engine/src/message_processor.rs), [`publish.rs`](../../crates/cgka-engine/src/publish.rs), [`fork_recovery.rs`](../../crates/cgka-engine/src/fork_recovery.rs), [`distributed_convergence.rs`](../../crates/cgka-engine/src/distributed_convergence.rs), [`update_group_data.rs`](../../crates/cgka-engine/src/update_group_data.rs), [`upgrade.rs`](../../crates/cgka-engine/src/upgrade.rs) |
| Account publish audit call sites | [`crates/marmot-account/src/lib.rs`](../../crates/marmot-account/src/lib.rs) |
| App settings, file identities, listing, upload | [`crates/marmot-app/src/lib.rs`](../../crates/marmot-app/src/lib.rs), [`crates/marmot-app/src/config.rs`](../../crates/marmot-app/src/config.rs), [`crates/storage-sqlite/src/shared.rs`](../../crates/storage-sqlite/src/shared.rs) |
| Runtime tracker scheduling | [`crates/marmot-app/src/runtime.rs`](../../crates/marmot-app/src/runtime.rs) |
| UniFFI bridge | [`crates/marmot-uniffi/src/lib.rs`](../../crates/marmot-uniffi/src/lib.rs), [`crates/marmot-uniffi/src/conversions.rs`](../../crates/marmot-uniffi/src/conversions.rs) |
| Tests | [`crates/marmot-forensics/src/audit.rs`](../../crates/marmot-forensics/src/audit.rs), [`crates/cgka-engine/tests/audit_log.rs`](../../crates/cgka-engine/tests/audit_log.rs), [`crates/marmot-app/tests/audit_logs.rs`](../../crates/marmot-app/tests/audit_logs.rs) |

## Enablement and lifecycle

Audit logging is controlled by `AuditLogSettings`:

| Field | Meaning |
| --- | --- |
| `enabled` | Whether future account sessions should install a JSONL recorder. Default `false`. |

The setting is persisted in shared SQLite:

| Table | Field | Meaning |
| --- | --- | --- |
| `audit_log_settings` | `enabled` | Persisted opt-in flag. |
| `audit_log_settings` | `updated_at_ms` | Local wall-clock update time in milliseconds. |

Important lifecycle behavior:

- The setting applies when `MarmotApp::open_account()` opens an account session.
- Enabling the setting does not retroactively attach a recorder to an already-open `AccountDeviceSession`.
- If reading the setting fails, the app logs a warning and continues without audit logging.
- If preparing the audit identity or opening the JSONL file fails, the app logs a warning and continues without audit
  logging.
- Once a recorder is open, write/serialization/flush failures are swallowed by design. The forensic recorder must never
  break the engine hot path.
- The recorder opens files with append mode and does not truncate existing logs.
- Each recorder opening emits a `recorder_started` row. Session open also emits `engine_context` and
  `recorder_health` rows once the convergence policy has been installed.

The UniFFI bridge exposes:

- `audit_log_settings()`;
- `set_audit_log_settings(...)`;
- `audit_log_files()`;
- `post_audit_log_file(path, endpoint)`;
- `set_audit_log_tracker_config(...)`;
- `post_audit_log_tracker_update()`.

## Files and identities

When audit logging is enabled for an account session, `MarmotApp::open_account()` creates these values:

| Value | How it is produced | Where it appears |
| --- | --- | --- |
| `audit-device-id` | Random 16 bytes, hex encoded, generated once per account directory and stored in `<account_dir>/audit-device-id`. | Input to `engine_id`; not included in JSONL events directly. |
| `account_ref` | First 16 bytes of `SHA-256("marmot-audit-account-ref/v1" + account_id)`, hex encoded. | Top-level JSONL `account_ref`. |
| `engine_id` | First 16 bytes of `SHA-256("marmot-audit-engine-id/v2" + account_id + device_id_hex)`, hex encoded. | Top-level JSONL `engine_id` and the file name. |
| File path | `<account_dir>/audit-<engine_id>.jsonl`. | Listed and uploaded by app APIs. |

The generic schema helper `default_jsonl_path(dir, engine_id)` also returns `<dir>/audit-<engine_id>.jsonl`.

Identity properties:

- `account_ref` is stable for the same account id.
- `engine_id` is stable for the same account id plus the account directory's stored `audit-device-id`.
- Both are 16-byte hex strings derived from hashes/randomness, not raw account ids.
- `group_ref` and `msg_id` fields are raw hex forms of group/message identifiers. The log is local-only and sensitive.

## JSONL envelope

Each line serializes an `AuditEvent`:

| Top-level field | Type | Present when | Meaning |
| --- | --- | --- | --- |
| `schema_version` | string | Always | Current value: `marmot-forensics-audit/v1`. |
| `seq` | u64 | Always | Recorder-local sequence number. Starts at `0` for each `JsonlRecorder` opening and uses wrapping increment. |
| `wall_time_ms` | u64 | Always | `SystemTime::now()` milliseconds since Unix epoch at record time. Falls back to `0` if system time is before epoch. |
| `recorder_session_id` | string | Optional | Locally generated id for this recorder opening. Present for `JsonlRecorder` rows. |
| `account_ref` | string | Optional | Recorder-assigned 16-byte account hash when supplied by the app. Omitted for recorders opened without it. |
| `engine_id` | string | Always | Recorder-assigned engine id. |
| `group_ref` | string | Optional | Hex group id supplied by the engine for group-attributed events. Omitted for unscoped events. |
| `context` | object | Optional | Operation, human-action, transport, engine, and/or group context attached by the caller. |
| `kind` | object | Always | Event-specific object tagged by `kind.type`. |

`kind` uses serde's internally tagged shape, so each event has a `type` field:

```json
{
  "schema_version": "marmot-forensics-audit/v1",
  "seq": 0,
  "wall_time_ms": 1700000000000,
  "recorder_session_id": "00000000000000000000018f2d0c1e2f000012340000000000000000",
  "account_ref": "0123456789abcdef0123456789abcdef",
  "engine_id": "11111111111111111111111111111111",
  "group_ref": "22222222222222222222222222222222",
  "context": {
    "operation_id": "op-7",
    "human_action": {
      "action": "update_group_profile",
      "origin": "local_user",
      "fields": ["name"],
      "component_ids": [32769]
    },
    "transport": {
      "transport_source": "nostr",
      "delivery_plane": "group",
      "relay_url": "wss://relay.example",
      "subscription_id": "group-abcd"
    }
  },
  "kind": {
    "type": "message_state_changed",
    "msg_id": "33333333333333333333333333333333",
    "previous_state": "created",
    "new_state": "processed",
    "epoch": 2,
    "reason": "publish_confirmed"
  }
}
```

Optional fields are omitted when `None`. Empty vectors such as `outbound_welcome_msg_ids`, `relay_urls`,
`accepted_relay_urls`, and `failed_relays` are omitted when empty.

Do not treat `seq` as globally unique. It is recorder-local and can reset after reopening. For ingest/storage tooling,
prefer file hash plus line number, or raw line hash plus line number, for dedupe and indexing.

### `context`

`context` is sparse and event-local. The recorder also writes top-level context rows (`recorder_started`,
`engine_context`, and `group_context`) when static or semi-static settings change.

| Field | Subfield | Meaning |
| --- | --- | --- |
| `operation_id` | | Local operation id linking entry/outcome/error rows. Engine operations use `op-N`; account publish rows use `publish-<msg_id>`. |
| `human_action` | `action` | App-level action label, for example `update_group_profile`, `invite_members`, or `remove_members`. |
| `human_action` | `origin` | Whether the action was initiated locally (`local_user`) or inferred from an inbound group event (`observed_group_event`). |
| `human_action` | `fields` | Stable changed-field labels such as `name`, `description`, `admins`, `avatar_url`, `image`, or `members`. Raw values are not included. |
| `human_action` | `component_ids` | App component ids touched by the action, when known. |
| `human_action` | `target_count` | Count of targets/endpoints when useful, for example member count for invite/remove or endpoint count for encrypted media settings. |
| `transport` | `transport_source` | Transport source label from the delivered `TransportMessage` or delivery source, for example `nostr`. |
| `transport` | `delivery_plane` | Delivery plane: `discovery`, `account_inbox`, `group`, or `ephemeral`. |
| `transport` | `relay_url` | Full transport endpoint string when supplied by the adapter. For Nostr this is the relay URL. |
| `transport` | `subscription_id` | Adapter subscription id when supplied by the delivery source. |
| `engine` | `ciphersuite` | OpenMLS ciphersuite numeric id. |
| `engine` | `max_past_epochs` | Engine retained-history limit. |
| `engine` | `convergence_max_rewind_commits` | Current convergence rewind policy. |
| `engine` | `supported_app_component_count` | Number of supported app components on this engine. |
| `engine` | `feature_count` | Number of registered engine features. |
| `group` | `epoch` | Current known group epoch. |
| `group` | `member_count` | Current known member count. |
| `group` | `required_app_component_count` | Number of required app components mirrored from group state. |
| `group` | `admin_count` | Current admin count when readable. |
| `group` | `convergence_max_rewind_commits` | Group-specific convergence rewind policy when set, otherwise current default context. |

## Event catalogue

### `recorder_started`

Emitted by `JsonlRecorder::open_with_account_ref()` as the first row for each local recorder opening.

| Field | Meaning |
| --- | --- |
| `recorder_session_id` | Same value also attached to the top-level row. |
| `recorder` | Recorder implementation string. |

### `engine_context`

Emitted when engine/session settings enter the engine, including session open and `set_convergence_policy()`.

| Field | Meaning |
| --- | --- |
| `context` | `AuditEngineContext` snapshot. |

### `group_context`

Emitted when group-scoped settings/state should be explicit in the timeline, including group creation and
`set_group_convergence_policy()`.

| Field | Meaning |
| --- | --- |
| `reason` | Stable reason such as `create_group` or `set_group_convergence_policy`. |
| `context` | `AuditGroupContext` snapshot. |

### `recorder_health`

Emitted by the session at open and available through `audit_recorder_health()`.

| Field | Meaning |
| --- | --- |
| `serialization_failures` | Number of audit rows that failed JSON serialization. |
| `write_failures` | Number of write failures swallowed by the recorder. |
| `flush_failures` | Number of flush failures swallowed by the recorder. |

### `human_action`

Emitted by the app layer as a sparse marker for a user-intent-level action. The same `context.human_action` object is
also copied onto the lower-level `send_*`, `create_group_*`, and `publish_*` rows produced by that action, so analysts can
join from "what the human did" to "what the engine and relays did."

| Field | Meaning |
| --- | --- |
| `action` | Stable app-level action label. |
| `origin` | `local_user` for actions initiated by this device, or `observed_group_event` for actions inferred from inbound group state. |
| `phase` | `succeeded` for local actions after publish success, or `observed` for inbound actions inferred from received group events. |
| `fields` | Stable field labels affected by the action. Raw names, descriptions, URLs, pubkeys, member ids, and payloads are not written here. |
| `component_ids` | App component ids touched by the action, when the action maps to app component data. |
| `target_count` | Count of targets, members, or endpoints when useful. |
| `message_ids` | Outbound or inbound message ids that carried the action. |
| `from_epoch` | Previous group epoch when the action is inferred from an epoch transition. |
| `to_epoch` | New group epoch when the action is inferred from an epoch transition. |
| `error_kind` | Reserved for future failed human-action markers. Currently omitted. |
| `detail` | Reserved for future safe action detail. Currently omitted. |

Current local-user action labels:

- `create_group`
- `invite_members`
- `remove_members`
- `leave_group`
- `decline_group_invite`
- `promote_admin`
- `demote_admin`
- `self_demote_admin`
- `update_admin_policy`
- `update_message_retention`
- `replace_encrypted_media_blob_endpoints`
- `update_group_avatar_url`
- `update_group_profile`

Current observed action labels:

- `create_group`
- `group_joined`
- `invite_members`
- `remove_members`
- `update_group_profile`
- `promote_admin`
- `demote_admin`
- `update_admin_policy`
- `update_message_retention`
- `update_group_avatar_url`
- `update_group_image`
- `replace_encrypted_media_blob_endpoints`
- `epoch_changed`

Group-state coverage:

- name changes are recorded as `update_group_profile` with field `name`;
- description changes are recorded as `update_group_profile` with field `description`;
- admin additions/removals are recorded as `promote_admin`, `demote_admin`, or `update_admin_policy` with field
  `admins`;
- URL avatar changes are recorded as `update_group_avatar_url` with field `avatar_url`;
- Blossom image component changes are recorded as `update_group_image` with field `image` when observed from group
  projection deltas;
- member joins/adds/removes are recorded as `group_joined`, `invite_members`, or `remove_members` with membership/member
  field labels;
- encrypted media endpoint policy changes are recorded as `replace_encrypted_media_blob_endpoints`;
- message retention changes are recorded as `update_message_retention`.

### `ingest_entry`

Emitted at `Engine::ingest()` entry before `do_ingest()`.

| Field | Meaning |
| --- | --- |
| `msg_id` | Hex `MessageId` of the inbound `TransportMessage`. |
| `envelope_kind` | `welcome` or `group_message`. |
| `transport_source` | Source label from the `TransportMessage`, for example `nostr`. |
| `payload_len` | Raw transport payload length in bytes. |
| `payload_digest` | SHA-256 digest of the raw transport payload, hex encoded. |

Metadata notes:

- No `group_ref` is attached at this call site because the envelope has not yet been processed by the engine.
- The payload itself is not written, only length and digest.
- When ingest entered through `AccountDeviceSession::ingest_delivery`, the event context includes delivery plane, relay
  URL, and subscription id when supplied by the adapter.

### `ingest_outcome`

Emitted after `do_ingest()` returns `Ok(outcome)`.

| Field | Meaning |
| --- | --- |
| `msg_id` | Hex `MessageId` of the inbound message. |
| `outcome_kind` | `processed`, `buffered`, or `stale`. |
| `stale_reason` | Present only when `outcome_kind == "stale"`. |
| `epoch` | Present for buffered outcomes and `already_at_epoch` stale outcomes. |

`stale_reason` values:

| Value | Meaning |
| --- | --- |
| `already_seen` | Message id was already ingested. |
| `already_at_epoch` | Engine is already at or beyond the message epoch; `epoch` records the current epoch. |
| `not_for_this_client` | Welcome/inbox message was not addressed to this client. |
| `unknown_group` | Message referenced a group the engine does not know. |
| `own_echo` | Message was produced by this engine and bounced back through ingest. |
| `peel_failed` | MLS/transport peeling failed or could not be recovered. |

Metadata notes:

- This event is not emitted if `do_ingest()` returns an `Err`.
- It has `group_ref` when the outcome is `buffered`, because that outcome carries the group id.

### `ingest_error`

Emitted after `do_ingest()` returns `Err(err)`.

| Field | Meaning |
| --- | --- |
| `msg_id` | Hex `MessageId` of the inbound message. |
| `error_kind` | Stable `EngineError` bucket. |
| `detail` | Optional human-readable error string. |

Metadata notes:

- The event context includes the ingest operation id and any transport delivery context. It also includes an engine
  context snapshot when the error is recorded.

### `send_entry`

Emitted at `Engine::send()` entry before `do_send()`.

| Field | Meaning |
| --- | --- |
| `intent_kind` | Stable string for the `SendIntent` variant. |

`intent_kind` values:

- `app_message`
- `invite`
- `remove_members`
- `leave`
- `update_app_components`
- `update_group_data`

Metadata notes:

- This is emitted only for the `send` trait method. The separate `create_group` trait method does not currently emit
  `send_entry`; it has dedicated create-group events.
- `group_ref` is attached for all group-scoped send intents.
- The event context includes the local engine operation id.

### `send_outcome`

Emitted after `do_send()` returns `Ok(send_result)`.

| Field | Meaning |
| --- | --- |
| `intent_kind` | Same value recorded in `send_entry`. |
| `result_kind` | Stable string for the `SendResult` variant. |
| `outbound_msg_id` | Optional hex id of the outbound application/proposal/commit message. |
| `outbound_welcome_msg_ids` | Hex ids of outbound welcome messages, omitted when empty. |

`result_kind` values:

- `application_message`
- `queued`
- `proposal`
- `group_evolution`
- `group_created`

Metadata notes:

- This event is not emitted if `do_send()` returns an `Err`.
- `queued` has no outbound ids.
- `group_evolution` can include both `outbound_msg_id` and welcome ids.
- `group_created` carries welcome ids but no commit `outbound_msg_id` in the helper.

### `send_error`

Emitted after `do_send()` returns `Err(err)`.

| Field | Meaning |
| --- | --- |
| `intent_kind` | Same value recorded in `send_entry`. |
| `error_kind` | Stable `EngineError` bucket. |
| `detail` | Optional human-readable error string. |

### `create_group_entry`

Emitted at `Engine::create_group()` entry.

| Field | Meaning |
| --- | --- |
| `member_count` | Number of invited members in the request. |
| `required_feature_count` | Number of required feature ids in the request. |
| `app_component_count` | Number of app components supplied in the request. |
| `initial_admin_count` | Number of initial admins in the request. |

Metadata notes:

- The event context includes the local engine operation id and engine context snapshot.

### `create_group_outcome`

Emitted after `do_create_group()` succeeds.

| Field | Meaning |
| --- | --- |
| `result_kind` | Stable `SendResult` kind, currently `group_created` for successful create-group. |
| `outbound_welcome_msg_ids` | Hex ids of outbound welcome messages, omitted when empty. |

Metadata notes:

- This event has `group_ref`.
- The event context includes the create-group operation id plus a group context snapshot.
- A separate `group_context` row with `reason = "create_group"` is emitted after success.

### `create_group_error`

Emitted after `do_create_group()` returns `Err(err)`.

| Field | Meaning |
| --- | --- |
| `error_kind` | Stable `EngineError` bucket. |
| `detail` | Optional human-readable error string. |

### `publish_attempt`

Emitted by the account runtime before calling the transport adapter for one outbound transport message.

| Field | Meaning |
| --- | --- |
| `msg_id` | Hex id of the outbound transport message. |
| `target_kind` | `group` or `inbox`. |
| `relay_urls` | Full endpoint strings selected by routing. For Nostr these are relay URLs. |
| `required_acks` | Adapter quorum target for this publish attempt. |

Metadata notes:

- Group publishes have `group_ref`; inbox publishes do not.
- The event context includes `operation_id = "publish-<msg_id>"`.

### `publish_outcome`

Emitted after the transport adapter returns endpoint-level results.

| Field | Meaning |
| --- | --- |
| `msg_id` | Hex id of the published transport message. |
| `target_kind` | `group` or `inbox`. |
| `accepted_relay_urls` | Endpoints that accepted the message. |
| `failed_relays` | Endpoint failure objects with `relay_url` and `reason`. |
| `required_acks` | Adapter quorum target. |
| `met_required_acks` | Whether accepted endpoint count satisfied `required_acks`. |

### `publish_failure`

Emitted when publish cannot complete or does not satisfy the required acknowledgement count.

| Field | Meaning |
| --- | --- |
| `msg_id` | Hex id of the transport message. |
| `stage` | `routing`, `adapter`, or `required_acks`. |
| `target_kind` | `unknown`, `group`, or `inbox`. |
| `relay_urls` | Routed endpoint strings when known. |
| `reason` | Human-readable failure reason. |

### `epoch_confirmed`

Emitted when `EpochManager::confirm_publish` transitions a group forward.

| Field | Meaning |
| --- | --- |
| `from_epoch` | Prior epoch. |
| `to_epoch` | Confirmed new epoch. |
| `pending_kind` | Pending publish kind. |

`pending_kind` values:

- `create_group`
- `group_evolution`

Metadata notes:

- This event has `group_ref`.
- If a pending commit message is promoted to processed during confirmation, a `message_state_changed` event with
  `reason = "publish_confirmed"` is emitted as well.

### `epoch_rolled_back`

Emitted when `EpochManager::rollback_publish` rewinds a failed pending publish.

| Field | Meaning |
| --- | --- |
| `pending_epoch` | Epoch of the staged pending commit before rollback. |
| `restored_epoch` | Epoch restored by rollback. |
| `pending_kind` | `create_group` or `group_evolution`. |

Metadata notes:

- This event has `group_ref`.
- After rollback the engine clears pending recovery state and replays buffered messages.

### `snapshot_created`

Emitted after fork-recovery snapshot creation succeeds.

| Field | Meaning |
| --- | --- |
| `snapshot_name` | Snapshot name returned by `ForkRecoveryManager::create_snapshot`. |
| `source_epoch` | Epoch the snapshot represents. |
| `reason` | Stable reason string from the call site. |

Current `reason` values found in production call sites:

- `pre_inbound_commit_apply`
- `pre_auto_commit`
- `pre_invite_commit`
- `pre_remove_members_commit`
- `pre_update_group_data_commit`
- `pre_upgrade_commit`

Metadata notes:

- This event has `group_ref`.
- Snapshot creation itself is still storage-local; the audit event records the name/epoch/reason for reconstruction.

### `fork_resolution`

Emitted when `ForkRecoveryManager::resolve` returns a verdict for a same-epoch candidate commit.

| Field | Meaning |
| --- | --- |
| `source_epoch` | Epoch where the competing commit originated. |
| `candidate_digest` | SHA-256 digest of the candidate MLS bytes, hex encoded. |
| `incumbent_digest` | Digest of the incumbent commit when available. |
| `winner` | `candidate`, `incumbent`, or `missing_snapshot`. |
| `invalidated_msg_id` | Message id invalidated when the candidate wins. |

Metadata notes:

- This event has `group_ref`.
- If the candidate wins, the engine also updates the invalidated stored message to `epoch_invalidated` and emits
  `message_state_changed` with `reason = "fork_loser"`.

### `convergence_decision`

Emitted when `select_canonical_branch` / canonicalization evaluates stored candidate state during convergence advance.

| Field | Meaning |
| --- | --- |
| `current_tip_epoch` | Stable tip before canonicalization. |
| `candidate_count` | Number of candidate branches considered by canonicalization. |
| `eligible_count` | Number of candidates eligible under retained-history and policy bounds. |
| `max_rewind_commits` | Policy horizon used for retained-history/fork eligibility. |
| `selected_branch_id` | Optional id of the selected branch. |
| `selected_fork_epoch` | Optional fork epoch of the selected branch. |
| `selected_tip_epoch` | Optional tip epoch of the selected branch. |

Metadata notes:

- This event has `group_ref`.
- `candidate_count` and `eligible_count` are copied from the canonicalization result that drove the decision.

### `peeler_outcome`

Emitted around transport peeler results at the engine boundary.

| Field | Meaning |
| --- | --- |
| `msg_id` | Hex message id. |
| `outcome` | `success`, `decrypt_failed`, `stale_epoch`, `malformed`, or `other`. |
| `fallback_snapshot_used` | Whether the successful peel came from a retained fallback snapshot. |
| `fallback_snapshot_name` | Snapshot name that recovered the peel, present only for successful fallback peels. |
| `fallback_snapshot_source_epoch` | Epoch represented by the fallback snapshot. |
| `fallback_attempt_count` | Number of historical snapshots attempted before success. |
| `error_kind` | Stable peeler error bucket for raw peeler errors. |
| `detail` | Optional detail string. |

Current `detail` behavior:

- Successful raw peels have no detail.
- Raw `stale_epoch`, `malformed`, and `other` peeler errors record `detail = format!("{err}")`.
- Raw `decrypt_failed` peeler errors are not emitted as standalone `peeler_outcome` rows. They are expected for
  future-epoch messages, pre-join messages, and retained-snapshot fallback; the eventual fallback success or deferred
  message-state transition records the useful forensic breadcrumb.
- A recovered decrypt failure records `detail = "recovered_after_decrypt_failed"` with `fallback_snapshot_used = true`.
- A recovered stale epoch records `detail = "recovered_after_stale_epoch"` with `fallback_snapshot_used = true`.

Metadata notes:

- This event has `group_ref`.
- Error details live in the sensitive audit log, not normal telemetry.
- `error_kind` values are `malformed`, `decrypt_failed`, `stale_epoch`, `missing_context`, `wrap_failed`, and
  `backend`.

### `auto_commit_decision`

Emitted after `LowestIndexAutoCommitter::decide` returns a decision for a queued proposal.

| Field | Meaning |
| --- | --- |
| `proposal_kind` | Stable string for the OpenMLS proposal kind. |
| `decision` | `commit` or `observe`. |
| `reason` | Stable reason for the decision. |

`proposal_kind` values:

- `add`
- `update`
- `remove`
- `pre_shared_key`
- `re_init`
- `external_init`
- `group_context_extensions`
- `self_remove`
- `app_ephemeral`
- `app_data_update`
- `custom`

Metadata notes:

- This event has `group_ref`.
- The current policy commits only when the proposal is `self_remove`, this client is the lowest-index eligible
  non-target member, and admin constraints are safe. The audit event still records every queued proposal decision.

### `message_state_changed`

Emitted when a stored message is inserted or changes `MessageState`.

| Field | Meaning |
| --- | --- |
| `msg_id` | Hex message id. |
| `previous_state` | Previous stored state when the transition path can read the existing record. |
| `new_state` | Stable string for the new `MessageState`. |
| `epoch` | Message epoch when known. |
| `reason` | Stable call-site reason. |

`new_state` values:

- `sent`
- `created`
- `processed`
- `failed`
- `retryable`
- `peel_deferred`
- `epoch_invalidated`

Current `reason` values found in production call sites:

| Reason | When emitted |
| --- | --- |
| `persist` | `persist_transport_message` inserts a stored message with the supplied state. |
| `state_update` | Generic `update_stored_message_state` path updates a stored message. |
| `publish_confirmed` | A pending commit message is promoted to processed after publish confirmation. |
| `fork_loser` | A same-epoch incumbent branch loses fork resolution and its message is invalidated. |
| `peel_failed_no_snapshot` | Group-message peel failed and no fallback snapshot could recover it; state becomes `peel_deferred`. |
| `stale_epoch_no_snapshot` | Stale-epoch peel failed and no fallback snapshot could recover it; state becomes `failed`. |
| `too_distant_in_the_past` | A deferred raw transport message peeled to MLS bytes, but OpenMLS proved the application ciphertext is outside the retained past-epoch window; state becomes `failed`. |

Metadata notes:

- Some events have `group_ref` (`persist`, fork/publish/peeler paths). The generic `state_update` helper emits without
  group attribution only when the existing message record cannot be read; otherwise it uses that record's `group_id`.
- Re-persisting a message with the same `group_id`, `epoch`, and `MessageState` does not emit another
  `message_state_changed` row; this keeps repeated deferred-peel retries from producing duplicate diagnostics.

### `rejection`

Defined in the schema for structured message/intent rejection:

| Field | Meaning |
| --- | --- |
| `msg_id` | Hex message id. |
| `reason` | Structured rejection reason. |

Current production status:

- No production call site currently emits `AuditEventKind::Rejection`.
- The variant is covered by serde round-trip tests and should be handled by downstream tooling for forward
  compatibility.

## Stable string catalog

These strings are produced by `crates/cgka-engine/src/audit_helpers.rs` and should be treated as low-cardinality
metadata keys for indexing.

| Category | Values |
| --- | --- |
| `envelope_kind` | `welcome`, `group_message` |
| `outcome_kind` | `processed`, `buffered`, `stale` |
| `stale_reason` | `already_seen`, `already_at_epoch`, `not_for_this_client`, `unknown_group`, `own_echo`, `peel_failed` |
| `engine error_kind` | `unknown_group`, `unknown_pending`, `not_a_member`, `not_group_admin`, `unknown_member`, `invalid_credential_identity`, `admin_cannot_self_remove`, `admin_depletion`, `missing_required_capabilities`, `unsupported_ciphersuite`, `invalid_app_message_payload`, `invalid_account_identity_proof`, `forked_epoch`, `invalid_transition`, `storage`, `peeler`, `serialize`, `backend`, `other` |
| `peeler error_kind` | `malformed`, `decrypt_failed`, `stale_epoch`, `missing_context`, `wrap_failed`, `backend` |
| `intent_kind` | `app_message`, `invite`, `remove_members`, `leave`, `update_app_components`, `update_group_data` |
| `result_kind` | `application_message`, `queued`, `proposal`, `group_evolution`, `group_created` |
| `target_kind` | `group`, `inbox`, `unknown` |
| `publish stage` | `routing`, `adapter`, `required_acks` |
| `delivery_plane` | `discovery`, `account_inbox`, `group`, `ephemeral` |
| `human_action.origin` | `local_user`, `observed_group_event` |
| `human_action.phase` | `succeeded`, `observed` |
| `human_action.action` | `create_group`, `invite_members`, `remove_members`, `leave_group`, `decline_group_invite`, `promote_admin`, `demote_admin`, `self_demote_admin`, `update_admin_policy`, `update_message_retention`, `replace_encrypted_media_blob_endpoints`, `update_group_avatar_url`, `update_group_profile`, `group_joined`, `update_group_image`, `epoch_changed` |
| `human_action.fields` | `name`, `description`, `admins`, `members`, `membership`, `avatar_url`, `image`, `message_retention`, `encrypted_media` |
| `pending_kind` | `create_group`, `group_evolution` |
| `proposal_kind` | `add`, `update`, `remove`, `pre_shared_key`, `re_init`, `external_init`, `group_context_extensions`, `self_remove`, `app_ephemeral`, `app_data_update`, `custom` |
| `new_state` | `sent`, `created`, `processed`, `failed`, `retryable`, `peel_deferred`, `epoch_invalidated` |
| `ForkWinner` | `candidate`, `incumbent`, `missing_snapshot` |
| `PeelerOutcomeKind` | `success`, `decrypt_failed`, `stale_epoch`, `malformed`, `other` |

## Upload and tracker path

The app can list and upload audit logs, but upload is separate from local recording.

### Listing

`MarmotApp::audit_log_files()` scans every local account directory and returns files whose names match
`audit-*.jsonl`.

`AuditLogFile` fields:

| Field | Meaning |
| --- | --- |
| `account_ref` | App account label for the account directory containing the file. This is not the hashed JSONL `account_ref`. |
| `path` | Full local path as a string. |
| `file_name` | Basename matching `audit-*.jsonl`. |
| `size_bytes` | File size. |
| `modified_at_ms` | Optional filesystem modified time in milliseconds since Unix epoch. |

Files are sorted by app account label, then file name.

### Explicit upload

`MarmotApp::post_audit_log_file(path, endpoint)` / `post_audit_log_file_with_tracker_config(...)` upload one selected
file.

Validation:

- path must be non-empty;
- basename must match `audit-*.jsonl`;
- canonical path must be inside the app root;
- file must be at most `64 MiB`;
- endpoint must be `https`, or loopback `http` for local testing;
- non-loopback endpoints require a bearer token.

HTTP request:

| Property | Value |
| --- | --- |
| Method | `POST` |
| Body | Raw JSONL file stream |
| `Content-Type` | `application/x-ndjson` |
| `Content-Length` | File size |
| Authorization | Optional bearer token, required for non-loopback endpoints |
| Timeout | `10s` connect, `60s` total request |

Optional source headers:

- `X-Goggles-Account-Label`
- `X-Goggles-Device-Label`
- `X-Goggles-Platform`
- `X-Goggles-App-Version`

`AuditLogUploadResult` fields:

| Field | Meaning |
| --- | --- |
| `path` | Uploaded local path. |
| `status` | HTTP success status code. |
| `bytes_sent` | File size sent. |

Upload errors are normalized to safe messages such as `HTTP <status>`, `request timed out`, `connection failed`,
`invalid response body`, or `request failed`.

### Tracker config

`AuditLogTrackerConfig` is runtime-only:

| Field | Meaning |
| --- | --- |
| `endpoint` | Optional tracker endpoint override. If absent, the app can use the compiled/default endpoint. |
| `authorization_bearer_token` | Bearer token supplied by the host app. |
| `source` | Optional upload source labels. |

Compiled/default endpoint source:

- `MarmotServiceEndpoints.audit_log_tracker_endpoint`;
- default reads `MARMOT_AUDIT_LOG_TRACKER_ENDPOINT` at compile time if present.

### Tracker update

`post_audit_log_tracker_update_for_app()` uploads every listed audit file only when:

- audit logging is enabled;
- a resolved tracker endpoint exists;
- a bearer token exists;
- endpoint transport validation passes;
- at least one `audit-*.jsonl` file exists.

Structured skip reasons:

- `audit logging disabled`
- `audit log tracker endpoint missing`
- `audit log tracker authorization token missing`
- `audit log tracker not configured`
- `audit log files missing`

`AuditLogTrackerUpdateResult` fields:

| Field | Meaning |
| --- | --- |
| `enabled` | Whether local audit logging was enabled at update time. |
| `uploaded` | Per-file upload results. |
| `skipped_reason` | Optional reason the update did not upload. |

The runtime has a coalescing uploader queue of size `1`. It schedules tracker updates after these triggers:

- `create_group`
- `invite_members`
- `remove_members`
- `leave_group`
- `decline_group_invite`
- `update_message_retention`
- `replace_encrypted_media_blob_endpoints`
- `update_group_avatar_url`
- `promote_admin`
- `demote_admin`
- `self_demote_admin`
- `update_group_profile`
- `send_message`
- `share_push_registration`
- `remove_push_registration`
- `send_app_event`
- `upload_media_send`
- `start_agent_text_stream`
- `finish_agent_text_stream`
- `retry_group_convergence`
- `startup_sync`
- `catch_up`
- `receive`

Tracker scheduling itself logs only the trigger, skip reason, uploaded count, failed count, and file index for failed
uploads. It does not log audit file contents.

## Data sensitivity

Audit JSONL can include:

- raw hex group ids (`group_ref`);
- raw hex message ids (`msg_id`, `outbound_msg_id`, `outbound_welcome_msg_ids`, `invalidated_msg_id`);
- stable account/device-derived audit identities (`account_ref`, `engine_id`);
- payload length and SHA-256 digest for inbound transport payloads;
- transport source, delivery plane, subscription id, and full relay URL for inbound delivery context when supplied;
- full relay URLs selected for publish attempts, successful publish acknowledgements, and endpoint failures;
- commit digests and snapshot names;
- epoch numbers, branch ids, fork epochs, and convergence policy values;
- engine and group context snapshots such as ciphersuite, retained-history limit, component counts, member count, admin
  count, and convergence rewind policy;
- human-action labels, changed-field labels, touched app component ids, target counts, and linked message ids;
- peeler error strings in `peeler_outcome.detail`;
- local wall-clock timestamps.

Audit JSONL does not currently include:

- plaintext message content;
- ciphertext or raw MLS bytes;
- raw account ids or Nostr pubkeys as top-level fields;
- raw changed group-profile values such as group name, description, avatar URL, image keys, admin pubkeys, or member ids
  in `human_action`;
- upload endpoint, upload token, or upload source headers;
- normal telemetry export resource attributes.

Even without plaintext/ciphertext, these logs are sensitive because they reveal group/message identifiers, timing, and
engine and relay behavior. Treat them as local forensic artifacts and upload only to trusted internal tooling.

## Tooling guidance

Recommended indexes for downstream ingestion:

- file hash;
- line number;
- raw line hash;
- `schema_version`;
- `seq`;
- `wall_time_ms`;
- `account_ref`;
- `engine_id`;
- `group_ref`;
- `kind.type`;
- event-specific fields such as `msg_id`, `outcome_kind`, `stale_reason`, `new_state`, `reason`, `selected_branch_id`,
  `selected_fork_epoch`, and `winner`.

Recommended parser behavior:

- Require `schema_version == "marmot-forensics-audit/v1"` for the current parser.
- Preserve the raw JSON line even when normalizing fields into columns.
- Do not assume the following:
  - `seq` is globally unique.
  - every line has `account_ref` or `group_ref`.
  - every schema variant is currently emitted in production; `rejection` is defined but inactive today.
- Treat unknown future `kind.type` values as parser-version mismatches unless the analyzer is explicitly designed for
  forward-compatible raw retention.

## Verification commands

Focused checks for this surface:

```sh
cargo test -p marmot-forensics
cargo test -p cgka-engine --test audit_log
cargo test -p marmot-app --test audit_logs
```

The wider repo checks are still:

```sh
just fmt-check
just check
just test
```
