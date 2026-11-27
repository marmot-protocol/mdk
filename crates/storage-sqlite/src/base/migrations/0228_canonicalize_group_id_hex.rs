//! Migration 0228: canonicalize persisted hex group ids to lowercase ASCII.
//!
//! Direct `storage-sqlite` callers could previously store mixed-case or
//! uppercase `group_id_hex` values (and pre-upgrade `secure_delete_checkpoint_intents`
//! scopes), leaving rows outside exact-match lowercase queries, wipes, and
//! media-secret retirement fences. Starting with this schema version, every
//! `storage-sqlite` read and write boundary canonicalizes group ids to lowercase
//! ASCII, and this one-time migration folds any pre-existing non-lowercase rows
//! (including case-colliding duplicates) deterministically into canonical
//! lowercase form.
//!
//! Tie-break and merge rules on case-colliding rows:
//! - Security/fence tables merge conservatively so barriers never weaken:
//!   - `encrypted_media_epoch_secret_retirement_watermarks`: `MAX(retired_through_epoch)`,
//!     `MAX(retired_at_unix_seconds)`.
//!   - `encrypted_media_epoch_secrets`: highest `created_at_unix_seconds` wins secret bytes,
//!     `MAX(retention_managed)` preserves retention management, and losing duplicates are
//!     zero-scrubbed before deletion.
//!   - `local_group_deletion_frontiers`: `MAX(message_insert_order)` plus newest non-empty
//!     prior routes and invitation standing.
//!   - `secure_delete_checkpoint_intents`: saturating merge of persisted JSON counts and
//!     sorted union of `media_ciphertext_sha256` across colliding scopes.
//!   - `attachment_removal_suppression`: `MIN(reason)` (`0 = ByYou` beats `1 = BySetting`).
//!   - `imported_media_file_keys`: losing duplicate `file_key` is zero-scrubbed before deletion.
//! - Monotonic/set tables merge via `MAX`/`MIN`/bitwise-OR (`attachment_history_versions`,
//!   `chat_presentation_dependencies`, `device_group_joins`, `device_removals`,
//!   `group_push_gossip_state`, `message_draft_revisions`).
//! - State/projection tables pick one deterministic winner by recency/priority (documented
//!   per table), breaking ties by preferring an existing canonical lowercase row first and
//!   then the lexicographically smallest spelling. Existing canonical lowercase parent rows
//!   are updated in place rather than deleted so `AFTER DELETE` triggers never drop migrated
//!   canonical children.
//! - On databases whose group ids are already lowercase (including every fresh database),
//!   each table short-circuits after a single existence check and performs zero writes.

use crate::SqliteResultExt;
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::types::Value;
use rusqlite::{Connection, Transaction, params, params_from_iter};
use std::collections::{BTreeMap, BTreeSet};

/// Every `(table, column)` pair canonicalized by this migration. Checked for
/// completeness against `sqlite_schema` in unit tests.
#[cfg(test)]
const HANDLED_COLUMNS: &[(&str, &str)] = &[
    ("account_compromise_warning_baseline", "device_group_id_hex"),
    ("account_group_app_components", "group_id_hex"),
    ("account_groups", "group_id_hex"),
    ("agent_item_expired_targets", "group_id_hex"),
    ("app_event_imports", "group_id_hex"),
    ("app_events", "group_id_hex"),
    ("app_pending_welcome_delivery", "group_id_hex"),
    ("app_prepared_group_image_upload", "group_id_hex"),
    ("attachment_acquisition", "group_id_hex"),
    ("attachment_body_removals", "group_id_hex"),
    ("attachment_history", "group_id_hex"),
    ("attachment_history_versions", "group_id_hex"),
    ("attachment_removal_suppression", "group_id_hex"),
    ("attachment_worker_demand", "group_id_hex"),
    ("avatar_acquisition_bootstrap", "group_id_hex"),
    ("avatar_identity_demand", "group_id_hex"),
    ("blocked_notification_suppressions", "group_id"),
    ("blocked_pending_invites", "group_id_hex"),
    ("chat_list_rows", "group_id_hex"),
    ("chat_list_unread_dirty_messages", "group_id_hex"),
    ("chat_list_unread_messages", "group_id_hex"),
    ("chat_list_unread_ready_groups", "group_id_hex"),
    ("chat_notification_settings", "group_id_hex"),
    ("chat_pin_positions", "group_id_hex"),
    ("chat_presentation_dependencies", "group_id_hex"),
    ("chat_presentation_members", "group_id_hex"),
    ("chat_presentation_row_work", "group_id_hex"),
    ("content_expired_targets", "group_id_hex"),
    ("content_pruned_controls", "group_id_hex"),
    ("content_removal_legacy_holds", "group_id_hex"),
    ("content_removal_validation", "group_id_hex"),
    ("content_reports", "group_id_hex"),
    ("conversation_read_state", "group_id_hex"),
    ("device_group_joins", "group_id_hex"),
    ("device_group_messages", "group_id_hex"),
    ("device_groups", "group_id_hex"),
    ("device_heartbeat_sent", "group_id_hex"),
    ("device_links", "group_id_hex"),
    ("device_removals", "group_id_hex"),
    ("direct_conversation_members", "group_id_hex"),
    ("encrypted_media_epoch_secret_references", "group_id_hex"),
    (
        "encrypted_media_epoch_secret_retirement_watermarks",
        "group_id_hex",
    ),
    ("encrypted_media_epoch_secrets", "group_id_hex"),
    ("group_push_gossip_state", "group_id_hex"),
    ("group_push_token_tombstones", "group_id_hex"),
    ("group_push_tokens", "group_id_hex"),
    ("history_deliveries_owed", "group_id_hex"),
    ("history_deliveries_parked", "group_id_hex"),
    ("history_delivery_sends", "group_id_hex"),
    ("imported_media_file_keys", "group_id_hex"),
    ("invitation_decisions", "group_id_hex"),
    ("kept_recipient_receipts", "group_id_hex"),
    ("link_chat_report_pages", "group_id"),
    ("link_chat_reports", "group_id"),
    ("local_group_deletion_frontiers", "group_id_hex"),
    ("local_message_submissions", "group_id_hex"),
    ("message_draft_attachments", "group_id_hex"),
    ("message_draft_revisions", "group_id_hex"),
    ("message_draft_submissions", "group_id_hex"),
    ("message_drafts", "group_id_hex"),
    ("message_modifier_edges", "group_id_hex"),
    ("message_timeline", "group_id_hex"),
    ("outgoing_attachment_recovery_cursor", "group_id_hex"),
    ("outgoing_attachment_upload_owners", "group_id_hex"),
    ("outgoing_attachment_uploads", "group_id_hex"),
    ("pending_push_registration_removals", "group_id_hex"),
    ("pending_push_registration_shares", "group_id_hex"),
    ("secure_delete_checkpoint_intents", "scope"),
    ("sibling_welcomes_received", "held_group_id_hex"),
    ("small_state_items", "group_id_hex"),
];

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    // Defer FK constraint checks until transaction commit while keeping
    // `PRAGMA foreign_keys` enabled. Every child table is canonicalized before
    // its parent so deleting a colliding non-lowercase parent row never
    // cascades onto already-canonicalized children, while SQLite verifies FK
    // integrity for every modified row on commit without scanning untouched
    // pre-existing rows in unrelated tables. SQLite resets `defer_foreign_keys`
    // automatically at commit or rollback.
    tx.pragma_update(None, "defer_foreign_keys", true)
        .storage()?;

    // Phase 1: Non-key columns (zero PK/UNIQUE collision possible).
    // (`attachment_body_removals` runs after Phase 4 so any trigger-generated
    // journal rows are also canonicalized.)
    for (table, column) in [
        ("account_compromise_warning_baseline", "device_group_id_hex"),
        ("app_pending_welcome_delivery", "group_id_hex"),
        ("app_prepared_group_image_upload", "group_id_hex"),
        ("avatar_identity_demand", "group_id_hex"),
        ("device_heartbeat_sent", "group_id_hex"),
        ("history_deliveries_parked", "group_id_hex"),
        ("history_delivery_sends", "group_id_hex"),
        ("outgoing_attachment_recovery_cursor", "group_id_hex"),
        ("outgoing_attachment_uploads", "group_id_hex"),
        ("sibling_welcomes_received", "held_group_id_hex"),
    ] {
        canonicalize_non_key_column(tx, table, column)?;
    }

    // Phase 2: Leaf/child tables of `content_removal_validation`, `app_events`,
    // `account_groups`, and `chat_list_rows` (canonicalized BEFORE parents so
    // deleting a non-lowercase parent duplicate never cascades or triggers a
    // delete against migrated canonical children).
    canonicalize_dedup_table(
        tx,
        "content_removal_legacy_holds",
        "group_id_hex",
        &["message_id_hex", "target_message_id_hex"],
        "",
        None,
    )?;
    canonicalize_dedup_table(
        tx,
        "content_removal_validation",
        "group_id_hex",
        &["message_id_hex"],
        "state DESC",
        None,
    )?;
    canonicalize_dedup_table(
        tx,
        "content_reports",
        "group_id_hex",
        &["report_id_hex"],
        "reported_at DESC",
        None,
    )?;
    canonicalize_dedup_table(
        tx,
        "app_event_imports",
        "group_id_hex",
        &["message_id_hex"],
        "imported_at DESC",
        None,
    )?;
    canonicalize_dedup_table(
        tx,
        "encrypted_media_epoch_secret_references",
        "group_id_hex",
        &["message_id_hex", "component_id", "source_epoch"],
        "",
        None,
    )?;
    canonicalize_dedup_table(
        tx,
        "imported_media_file_keys",
        "group_id_hex",
        &["message_id_hex", "ciphertext_sha256"],
        "",
        Some("file_key"),
    )?;
    canonicalize_dedup_table(
        tx,
        "kept_recipient_receipts",
        "group_id_hex",
        &["message_id_hex"],
        "",
        None,
    )?;
    canonicalize_dedup_table(
        tx,
        "message_modifier_edges",
        "group_id_hex",
        &["modifier_message_id_hex", "target_message_id_hex"],
        "recorded_at DESC",
        None,
    )?;
    canonicalize_dedup_table(
        tx,
        "outgoing_attachment_upload_owners",
        "group_id_hex",
        &["token", "message_id_hex"],
        "",
        None,
    )?;
    canonicalize_attachment_removal_suppression(tx)?;
    canonicalize_dedup_table(
        tx,
        "blocked_notification_suppressions",
        "group_id",
        &["message_id"],
        "",
        None,
    )?;
    canonicalize_dedup_table(
        tx,
        "agent_item_expired_targets",
        "group_id_hex",
        &["message_id_hex"],
        "",
        None,
    )?;
    canonicalize_dedup_table(
        tx,
        "content_expired_targets",
        "group_id_hex",
        &["message_id_hex"],
        "",
        None,
    )?;
    canonicalize_dedup_table(
        tx,
        "content_pruned_controls",
        "group_id_hex",
        &["message_id_hex"],
        "",
        None,
    )?;
    canonicalize_local_message_submissions(tx)?;
    canonicalize_dedup_table(
        tx,
        "chat_list_unread_dirty_messages",
        "group_id_hex",
        &["message_id_hex"],
        "",
        None,
    )?;
    canonicalize_dedup_table(
        tx,
        "chat_list_unread_messages",
        "group_id_hex",
        &["message_id_hex"],
        "mentions_local DESC, timeline_order_class DESC, timeline_order_primary DESC, timeline_order_phase DESC, timeline_order_at DESC",
        None,
    )?;
    canonicalize_dedup_table(
        tx,
        "chat_list_unread_ready_groups",
        "group_id_hex",
        &[],
        "",
        None,
    )?;
    canonicalize_dedup_table(
        tx,
        "chat_notification_settings",
        "group_id_hex",
        &[],
        "updated_at_ms DESC",
        None,
    )?;
    canonicalize_chat_presentation_dependencies(tx)?;
    canonicalize_dedup_table(
        tx,
        "chat_presentation_members",
        "group_id_hex",
        &["member_id_hex"],
        "",
        None,
    )?;
    canonicalize_dedup_table(
        tx,
        "chat_presentation_row_work",
        "group_id_hex",
        &[],
        "",
        None,
    )?;
    canonicalize_dedup_table(
        tx,
        "conversation_read_state",
        "group_id_hex",
        &[],
        "updated_at DESC, last_read_timeline_at DESC",
        None,
    )?;
    canonicalize_dedup_table(
        tx,
        "direct_conversation_members",
        "group_id_hex",
        &["member_id_hex"],
        "",
        None,
    )?;
    canonicalize_group_push_gossip_state(tx)?;
    canonicalize_dedup_table(
        tx,
        "pending_push_registration_shares",
        "group_id_hex",
        &[],
        "registration_updated_at_ms DESC, queued_at_ms DESC",
        None,
    )?;
    canonicalize_dedup_table(
        tx,
        "avatar_acquisition_bootstrap",
        "group_id_hex",
        &[],
        "",
        None,
    )?;
    canonicalize_dedup_table(
        tx,
        "account_group_app_components",
        "group_id_hex",
        &["component_id"],
        "updated_at DESC",
        None,
    )?;
    canonicalize_message_draft_revisions(tx)?;
    canonicalize_dedup_table(
        tx,
        "message_draft_submissions",
        "group_id_hex",
        &[],
        "revision DESC",
        None,
    )?;
    canonicalize_message_drafts_and_attachments(tx)?;

    // Phase 3: Remaining FK children of `app_events` and `account_groups`
    // (`attachment_worker_demand`, `attachment_acquisition`, `chat_pin_positions`,
    // `chat_list_rows`), followed by their parents `app_events` and
    // `account_groups`. Doing every child before its parent ensures deleting a
    // colliding non-lowercase parent duplicate cascades zero rows.
    canonicalize_dedup_table(
        tx,
        "attachment_worker_demand",
        "group_id_hex",
        &["message_id_hex", "attachment_index"],
        "",
        None,
    )?;
    canonicalize_attachment_acquisition(tx)?;
    canonicalize_dedup_table(tx, "blocked_pending_invites", "group_id_hex", &[], "", None)?;

    let pins_changed = canonicalize_chat_pin_positions(tx)?;
    let chat_list_changed = canonicalize_dedup_table(
        tx,
        "chat_list_rows",
        "group_id_hex",
        &[],
        "updated_at DESC, activity_sort_at DESC",
        None,
    )?;
    canonicalize_dedup_table(
        tx,
        "app_events",
        "group_id_hex",
        &["message_id_hex"],
        "insert_order DESC",
        None,
    )?;
    let account_groups_changed = canonicalize_dedup_table(
        tx,
        "account_groups",
        "group_id_hex",
        &[],
        "updated_at DESC",
        None,
    )?;
    if account_groups_changed || pins_changed || chat_list_changed {
        refresh_chat_list_pin_columns(tx)?;
    }

    // Phase 4: Timeline and attachment derivation chain.
    // `app_events`, `app_event_imports`, `blocked_pending_invites`,
    // `message_modifier_edges`, `attachment_worker_demand`,
    // `attachment_acquisition`, and `account_groups` are already lowercase, so
    // `message_timeline`'s `attachment_source_update` trigger computes
    // canonical `attachment_history` rows and validates canonical
    // `attachment_acquisition` rows.
    let timeline_changed = canonicalize_message_timeline(tx)?;
    canonicalize_dedup_table(
        tx,
        "attachment_history",
        "group_id_hex",
        &["message_id_hex", "attachment_index"],
        "visible DESC, received_at DESC",
        None,
    )?;
    canonicalize_attachment_history_versions(tx)?;
    // Drop any worker demand rows left orphaned after deduplicating colliding
    // `message_timeline` / `attachment_history` rows.
    if has_orphaned_attachment_worker_demand(tx)? {
        tx.execute(
            "DELETE FROM attachment_worker_demand
             WHERE NOT EXISTS (
                 SELECT 1 FROM attachment_history h
                 WHERE h.group_id_hex = attachment_worker_demand.group_id_hex
                   AND h.message_id_hex = attachment_worker_demand.message_id_hex
                   AND h.attachment_index = attachment_worker_demand.attachment_index
             )",
            [],
        )
        .storage()?;
    }
    if timeline_changed {
        // When `PRAGMA foreign_keys = OFF` on a caller-configured connection,
        // `attachment_acquisition_source_UPDATE` deleting an incompatible
        // acquisition row does not cascade to its token-keyed children.
        for child_table in [
            "attachment_partial_chunk",
            "attachment_partial",
            "media_file_refs",
            "retained_attachment_files",
            "retained_attachment_bytes",
        ] {
            tx.execute(
                &format!(
                    "DELETE FROM \"{child_table}\"
                     WHERE token NOT IN (SELECT token FROM attachment_acquisition)"
                ),
                [],
            )
            .storage()?;
        }
    }
    canonicalize_non_key_column(tx, "attachment_body_removals", "group_id_hex")?;

    // Phase 5: Security/fence and standalone group-scoped tables.
    canonicalize_encrypted_media_watermarks(tx)?;
    canonicalize_encrypted_media_secrets(tx)?;
    canonicalize_local_group_deletion_frontiers(tx)?;
    canonicalize_secure_delete_checkpoint_intents(tx)?;
    canonicalize_dedup_table(
        tx,
        "group_push_tokens",
        "group_id_hex",
        &[
            "member_id_hex",
            "leaf_index",
            "platform",
            "server_pubkey_hex",
        ],
        "owner_ts DESC, updated_at_ms DESC",
        None,
    )?;
    canonicalize_dedup_table(
        tx,
        "group_push_token_tombstones",
        "group_id_hex",
        &[
            "member_id_hex",
            "leaf_index",
            "platform",
            "server_pubkey_hex",
        ],
        "owner_ts DESC, created_at_ms DESC",
        None,
    )?;
    canonicalize_dedup_table(
        tx,
        "pending_push_registration_removals",
        "group_id_hex",
        &[
            "platform",
            "server_pubkey_hex",
            "token_fingerprint",
            "registration_updated_at_ms",
        ],
        "queued_at_ms DESC",
        None,
    )?;
    canonicalize_dedup_table(
        tx,
        "device_groups",
        "group_id_hex",
        &[],
        "CASE WHEN trust IN ('created', 'linked') THEN 0 WHEN trust IN ('creating', 'awaiting_welcome') THEN 1 ELSE 2 END, recorded_at DESC",
        None,
    )?;
    canonicalize_device_group_joins(tx)?;
    canonicalize_dedup_table(
        tx,
        "device_group_messages",
        "group_id_hex",
        &["app_event_id"],
        "recorded_at DESC, CASE WHEN message_id_hex IS NOT NULL THEN 0 ELSE 1 END",
        None,
    )?;
    canonicalize_dedup_table(
        tx,
        "device_links",
        "group_id_hex",
        &["slot_hex"],
        "COALESCE(decided_at, linked_at) DESC, linked_at DESC",
        None,
    )?;
    canonicalize_device_removals(tx)?;
    canonicalize_dedup_table(
        tx,
        "history_deliveries_owed",
        "group_id_hex",
        &["receiver_slot_hex"],
        "revision DESC, owed_at DESC",
        None,
    )?;
    canonicalize_dedup_table(
        tx,
        "invitation_decisions",
        "group_id_hex",
        &["generation"],
        "version DESC, declined DESC",
        None,
    )?;
    canonicalize_dedup_table(
        tx,
        "link_chat_reports",
        "group_id",
        &["slot"],
        "revision DESC, expires_at DESC",
        None,
    )?;
    canonicalize_link_chat_report_pages(tx)?;
    canonicalize_dedup_table(
        tx,
        "small_state_items",
        "group_id_hex",
        &["item"],
        "COALESCE(version, -1) DESC, updated_at DESC",
        None,
    )?;

    Ok(())
}

#[derive(Clone, PartialEq)]
enum ValueKey {
    Null,
    Integer(i64),
    Real(u64),
    Text(String),
    Blob(Vec<u8>),
}

impl Eq for ValueKey {}

impl PartialOrd for ValueKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ValueKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        fn tag(v: &ValueKey) -> u8 {
            match v {
                ValueKey::Null => 0,
                ValueKey::Integer(_) => 1,
                ValueKey::Real(_) => 2,
                ValueKey::Text(_) => 3,
                ValueKey::Blob(_) => 4,
            }
        }
        tag(self)
            .cmp(&tag(other))
            .then_with(|| match (self, other) {
                (ValueKey::Null, ValueKey::Null) => std::cmp::Ordering::Equal,
                (ValueKey::Integer(a), ValueKey::Integer(b)) => a.cmp(b),
                (ValueKey::Real(a), ValueKey::Real(b)) => a.cmp(b),
                (ValueKey::Text(a), ValueKey::Text(b)) => a.cmp(b),
                (ValueKey::Blob(a), ValueKey::Blob(b)) => a.cmp(b),
                _ => std::cmp::Ordering::Equal,
            })
    }
}

impl From<&Value> for ValueKey {
    fn from(value: &Value) -> Self {
        match value {
            Value::Null => Self::Null,
            Value::Integer(v) => Self::Integer(*v),
            Value::Real(v) => Self::Real(v.to_bits()),
            Value::Text(v) => Self::Text(v.clone()),
            Value::Blob(v) => Self::Blob(v.clone()),
        }
    }
}

fn has_non_lowercase(conn: &Connection, table: &str, column: &str) -> StorageResult<bool> {
    conn.query_row(
        &format!(
            "SELECT EXISTS(SELECT 1 FROM \"{table}\" WHERE \"{column}\" != lower(\"{column}\"))"
        ),
        [],
        |row| row.get(0),
    )
    .storage()
}

fn non_lowercase_targets(
    conn: &Connection,
    table: &str,
    column: &str,
) -> StorageResult<Vec<String>> {
    let mut stmt = conn
        .prepare(&format!(
            "SELECT DISTINCT lower(\"{column}\")
             FROM \"{table}\"
             WHERE \"{column}\" != lower(\"{column}\")
             ORDER BY 1"
        ))
        .storage()?;
    stmt.query_map([], |row| row.get(0))
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()
}

fn canonicalize_non_key_column(conn: &Connection, table: &str, column: &str) -> StorageResult<()> {
    if !has_non_lowercase(conn, table, column)? {
        return Ok(());
    }
    conn.execute(
        &format!(
            "UPDATE \"{table}\" SET \"{column}\" = lower(\"{column}\")
             WHERE \"{column}\" != lower(\"{column}\")"
        ),
        [],
    )
    .storage()?;
    Ok(())
}

/// Non-generated columns of `table` from `PRAGMA table_info`, along with each
/// column's `pk` ordinal (0 if not part of the primary key).
fn table_columns(conn: &Connection, table: &str) -> StorageResult<Vec<(String, i64)>> {
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info(\"{table}\")"))
        .storage()?;
    stmt.query_map([], |row| {
        Ok((row.get::<_, String>(1)?, row.get::<_, i64>(5)?))
    })
    .storage()?
    .collect::<Result<Vec<_>, _>>()
    .storage()
}

fn key_where_clause(group_col: &str, other_key_cols: &[&str]) -> String {
    let mut clauses = Vec::with_capacity(1 + other_key_cols.len());
    clauses.push(format!("\"{group_col}\" = ?"));
    for col in other_key_cols {
        clauses.push(format!("\"{col}\" IS ?"));
    }
    clauses.join(" AND ")
}

/// Canonicalize `group_col` in `table` where `(group_col, other_key_cols...)`
/// is a primary key or unique constraint.
///
/// For each colliding normalized key, the first row under
/// `ORDER BY {winner_order_sql}, CASE WHEN {group_col} = lower({group_col}) THEN 0 ELSE 1 END, {group_col} ASC`
/// wins. If a canonical lowercase row already exists, it is updated in place
/// (never deleted) and only non-lowercase duplicates are deleted so `DELETE`
/// triggers never drop already-migrated canonical children.
fn canonicalize_dedup_table(
    conn: &Connection,
    table: &str,
    group_col: &str,
    other_key_cols: &[&str],
    winner_order_sql: &str,
    scrub_blob_col: Option<&str>,
) -> StorageResult<bool> {
    let targets = non_lowercase_targets(conn, table, group_col)?;
    if targets.is_empty() {
        return Ok(false);
    }

    let cols = table_columns(conn, table)?;
    let pk_count = cols.iter().filter(|(_, pk)| *pk > 0).count();
    let payload_cols: Vec<String> = cols
        .iter()
        .filter(|(name, pk)| {
            if name == group_col || other_key_cols.contains(&name.as_str()) {
                return false;
            }
            // Exclude surrogate single-column PKs (such as `app_events.insert_order`)
            // when updating an existing canonical row in place.
            !(pk_count == 1 && *pk == 1)
        })
        .map(|(name, _)| name.clone())
        .collect();

    let mut select_cols = Vec::with_capacity(1 + other_key_cols.len() + payload_cols.len());
    select_cols.push(format!("\"{group_col}\""));
    for col in other_key_cols {
        select_cols.push(format!("\"{col}\""));
    }
    for col in &payload_cols {
        select_cols.push(format!("\"{col}\""));
    }
    let order_prefix = if winner_order_sql.is_empty() {
        String::new()
    } else {
        format!("{winner_order_sql}, ")
    };
    let select_sql = format!(
        "SELECT {} FROM \"{table}\" WHERE lower(\"{group_col}\") = ?1
         ORDER BY {order_prefix}CASE WHEN \"{group_col}\" = ?1 THEN 0 ELSE 1 END, \"{group_col}\" ASC",
        select_cols.join(", ")
    );
    let where_clause = key_where_clause(group_col, other_key_cols);
    let delete_sql = format!("DELETE FROM \"{table}\" WHERE {where_clause}");
    let rename_sql = format!("UPDATE \"{table}\" SET \"{group_col}\" = ? WHERE {where_clause}");
    let scrub_sql = scrub_blob_col.map(|col| {
        format!(
            "UPDATE \"{table}\" SET \"{col}\" = zeroblob(length(\"{col}\")) WHERE {where_clause}"
        )
    });
    let update_payload_sql = (!payload_cols.is_empty()).then(|| {
        let assignments = payload_cols
            .iter()
            .map(|col| format!("\"{col}\" = ?"))
            .collect::<Vec<_>>()
            .join(", ");
        format!("UPDATE \"{table}\" SET {assignments} WHERE {where_clause}")
    });

    struct RowData {
        spelling: String,
        other_keys: Vec<Value>,
        payload: Vec<Value>,
    }

    let other_len = other_key_cols.len();
    let total_len = 1 + other_len + payload_cols.len();
    for lower_id in targets {
        let rows: Vec<RowData> = {
            let mut stmt = conn.prepare(&select_sql).storage()?;
            stmt.query_map([&lower_id], |row| {
                let spelling: String = row.get(0)?;
                let mut other_keys = Vec::with_capacity(other_len);
                for idx in 1..=other_len {
                    other_keys.push(row.get::<_, Value>(idx)?);
                }
                let mut payload = Vec::with_capacity(payload_cols.len());
                for idx in (1 + other_len)..total_len {
                    payload.push(row.get::<_, Value>(idx)?);
                }
                Ok(RowData {
                    spelling,
                    other_keys,
                    payload,
                })
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?
        };

        let mut grouped: BTreeMap<Vec<ValueKey>, Vec<RowData>> = BTreeMap::new();
        for row in rows {
            let key: Vec<ValueKey> = row.other_keys.iter().map(ValueKey::from).collect();
            grouped.entry(key).or_default().push(row);
        }

        for (_key, group_rows) in grouped {
            let has_canonical = group_rows.iter().any(|row| row.spelling == lower_id);
            if has_canonical {
                let winner = &group_rows[0];
                let winner_needs_copy = winner.spelling != lower_id && !payload_cols.is_empty();
                let winner_payload = winner_needs_copy.then(|| winner.payload.clone());
                let other_keys = winner.other_keys.clone();

                // Delete every non-lowercase duplicate first so updating the
                // canonical row cannot trip secondary UNIQUE constraints (e.g.
                // `app_events.source_message_id_hex`, `chat_pin_positions.ordinal`).
                for row in &group_rows {
                    if row.spelling == lower_id {
                        continue;
                    }
                    let mut key_params = Vec::with_capacity(1 + other_len);
                    key_params.push(Value::Text(row.spelling.clone()));
                    key_params.extend(row.other_keys.iter().cloned());
                    if let Some(ref sql) = scrub_sql {
                        conn.execute(sql, params_from_iter(key_params.iter()))
                            .storage()?;
                    }
                    conn.execute(&delete_sql, params_from_iter(key_params.iter()))
                        .storage()?;
                }

                if let (Some(payload), Some(sql)) = (winner_payload, update_payload_sql.as_ref()) {
                    let mut update_params =
                        Vec::with_capacity(payload.len() + 1 + other_keys.len());
                    update_params.extend(payload);
                    update_params.push(Value::Text(lower_id.clone()));
                    update_params.extend(other_keys);
                    conn.execute(sql, params_from_iter(update_params.iter()))
                        .storage()?;
                }
            } else {
                let winner = &group_rows[0];
                for loser in &group_rows[1..] {
                    let mut key_params = Vec::with_capacity(1 + other_len);
                    key_params.push(Value::Text(loser.spelling.clone()));
                    key_params.extend(loser.other_keys.iter().cloned());
                    if let Some(ref sql) = scrub_sql {
                        conn.execute(sql, params_from_iter(key_params.iter()))
                            .storage()?;
                    }
                    conn.execute(&delete_sql, params_from_iter(key_params.iter()))
                        .storage()?;
                }
                let mut rename_params = Vec::with_capacity(2 + other_len);
                rename_params.push(Value::Text(lower_id.clone()));
                rename_params.push(Value::Text(winner.spelling.clone()));
                rename_params.extend(winner.other_keys.iter().cloned());
                conn.execute(&rename_sql, params_from_iter(rename_params.iter()))
                    .storage()?;
            }
        }
    }
    Ok(true)
}

fn canonicalize_attachment_removal_suppression(conn: &Connection) -> StorageResult<()> {
    let targets = non_lowercase_targets(conn, "attachment_removal_suppression", "group_id_hex")?;
    if targets.is_empty() {
        return Ok(());
    }
    for lower_id in targets {
        // `reason = 0` (`ByYou`) always dominates `reason = 1` (`BySetting`).
        let merged: Vec<(String, i64, i64)> = {
            let mut stmt = conn
                .prepare(
                    "SELECT message_id_hex, attachment_index, MIN(reason)
                     FROM attachment_removal_suppression
                     WHERE lower(group_id_hex) = ?1
                     GROUP BY message_id_hex, attachment_index",
                )
                .storage()?;
            stmt.query_map([&lower_id], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?
        };
        conn.execute(
            "DELETE FROM attachment_removal_suppression
             WHERE lower(group_id_hex) = ?1 AND group_id_hex != ?1",
            [&lower_id],
        )
        .storage()?;
        for (message_id_hex, attachment_index, reason) in merged {
            conn.execute(
                "INSERT INTO attachment_removal_suppression (
                     group_id_hex, message_id_hex, attachment_index, reason
                 ) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(group_id_hex, message_id_hex, attachment_index) DO UPDATE SET
                     reason = MIN(attachment_removal_suppression.reason, excluded.reason)",
                params![&lower_id, message_id_hex, attachment_index, reason],
            )
            .storage()?;
        }
    }
    Ok(())
}

fn canonicalize_chat_presentation_dependencies(conn: &Connection) -> StorageResult<()> {
    let targets = non_lowercase_targets(conn, "chat_presentation_dependencies", "group_id_hex")?;
    if targets.is_empty() {
        return Ok(());
    }
    for lower_id in targets {
        let rows: Vec<(String, i64)> = {
            let mut stmt = conn
                .prepare(
                    "SELECT member_id_hex, roles
                     FROM chat_presentation_dependencies
                     WHERE lower(group_id_hex) = ?1",
                )
                .storage()?;
            stmt.query_map([&lower_id], |row| Ok((row.get(0)?, row.get(1)?)))
                .storage()?
                .collect::<Result<Vec<_>, _>>()
                .storage()?
        };
        let mut merged_roles: BTreeMap<String, i64> = BTreeMap::new();
        for (member_id_hex, roles) in rows {
            *merged_roles.entry(member_id_hex).or_insert(0) |= roles;
        }
        conn.execute(
            "DELETE FROM chat_presentation_dependencies
             WHERE lower(group_id_hex) = ?1 AND group_id_hex != ?1",
            [&lower_id],
        )
        .storage()?;
        for (member_id_hex, roles) in merged_roles {
            conn.execute(
                "INSERT INTO chat_presentation_dependencies (group_id_hex, member_id_hex, roles)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(group_id_hex, member_id_hex) DO UPDATE SET
                     roles = chat_presentation_dependencies.roles | excluded.roles",
                params![&lower_id, member_id_hex, roles],
            )
            .storage()?;
        }
    }
    Ok(())
}

fn canonicalize_group_push_gossip_state(conn: &Connection) -> StorageResult<()> {
    let targets = non_lowercase_targets(conn, "group_push_gossip_state", "group_id_hex")?;
    if targets.is_empty() {
        return Ok(());
    }
    for lower_id in targets {
        let (
            joined_at_ms,
            last_announced_at_ms,
            snapshot_owed_after_epoch,
            joining_since_ms,
            join_window_counted_ms,
            announce_owed_at_ms,
        ): (i64, Option<i64>, Option<i64>, Option<i64>, i64, Option<i64>) = conn
            .query_row(
                "SELECT
                     MAX(joined_at_ms),
                     MAX(last_announced_at_ms),
                     MAX(snapshot_owed_after_epoch),
                     MIN(joining_since_ms),
                     MAX(join_window_counted_ms),
                     MIN(announce_owed_at_ms)
                 FROM group_push_gossip_state
                 WHERE lower(group_id_hex) = ?1",
                [&lower_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .storage()?;
        conn.execute(
            "DELETE FROM group_push_gossip_state
             WHERE lower(group_id_hex) = ?1 AND group_id_hex != ?1",
            [&lower_id],
        )
        .storage()?;
        conn.execute(
            "INSERT INTO group_push_gossip_state (
                 group_id_hex, joined_at_ms, last_announced_at_ms,
                 snapshot_owed_after_epoch, joining_since_ms,
                 join_window_counted_ms, announce_owed_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(group_id_hex) DO UPDATE SET
                 joined_at_ms = excluded.joined_at_ms,
                 last_announced_at_ms = excluded.last_announced_at_ms,
                 snapshot_owed_after_epoch = excluded.snapshot_owed_after_epoch,
                 joining_since_ms = excluded.joining_since_ms,
                 join_window_counted_ms = excluded.join_window_counted_ms,
                 announce_owed_at_ms = excluded.announce_owed_at_ms",
            params![
                &lower_id,
                joined_at_ms,
                last_announced_at_ms,
                snapshot_owed_after_epoch,
                joining_since_ms,
                join_window_counted_ms,
                announce_owed_at_ms,
            ],
        )
        .storage()?;
    }
    Ok(())
}

fn canonicalize_message_draft_revisions(conn: &Connection) -> StorageResult<()> {
    let targets = non_lowercase_targets(conn, "message_draft_revisions", "group_id_hex")?;
    if targets.is_empty() {
        return Ok(());
    }
    for lower_id in targets {
        let (revision, composition): (i64, i64) = conn
            .query_row(
                "SELECT MAX(revision), MAX(composition)
                 FROM message_draft_revisions
                 WHERE lower(group_id_hex) = ?1",
                [&lower_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .storage()?;
        conn.execute(
            "DELETE FROM message_draft_revisions
             WHERE lower(group_id_hex) = ?1 AND group_id_hex != ?1",
            [&lower_id],
        )
        .storage()?;
        conn.execute(
            "INSERT INTO message_draft_revisions (group_id_hex, revision, composition)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(group_id_hex) DO UPDATE SET
                 revision = MAX(message_draft_revisions.revision, excluded.revision),
                 composition = MAX(message_draft_revisions.composition, excluded.composition)",
            params![&lower_id, revision, composition],
        )
        .storage()?;
    }
    Ok(())
}

fn canonicalize_message_drafts_and_attachments(conn: &Connection) -> StorageResult<()> {
    let draft_targets = non_lowercase_targets(conn, "message_drafts", "group_id_hex")?;
    let attachment_targets =
        non_lowercase_targets(conn, "message_draft_attachments", "group_id_hex")?;
    if draft_targets.is_empty() && attachment_targets.is_empty() {
        return Ok(());
    }

    // When colliding drafts exist for one group, keep only the attachments
    // belonging to the winning draft spelling (`updated_at_ms DESC, created_at_ms DESC`)
    // so attachments from distinct drafts are never mixed and staged files of
    // discarded drafts are cleanly released by `message_draft_attachment_file_released`.
    for lower_id in &draft_targets {
        let spellings: Vec<String> = {
            let mut stmt = conn
                .prepare(
                    "SELECT group_id_hex
                     FROM message_drafts
                     WHERE lower(group_id_hex) = ?1
                     ORDER BY updated_at_ms DESC, created_at_ms DESC,
                              CASE WHEN group_id_hex = ?1 THEN 0 ELSE 1 END,
                              group_id_hex ASC",
                )
                .storage()?;
            stmt.query_map([lower_id], |row| row.get(0))
                .storage()?
                .collect::<Result<Vec<_>, _>>()
                .storage()?
        };
        if spellings.len() > 1 {
            for loser in &spellings[1..] {
                conn.execute(
                    "DELETE FROM message_draft_attachments WHERE group_id_hex = ?1",
                    [loser],
                )
                .storage()?;
            }
        }
    }

    // Deduplicate any remaining attachment collisions on both
    // `PRIMARY KEY (group_id_hex, position)` and `UNIQUE (group_id_hex, attachment_id)`.
    if has_non_lowercase(conn, "message_draft_attachments", "group_id_hex")? {
        dedup_rows_by_key_column(
            conn,
            "message_draft_attachments",
            "group_id_hex",
            "attachment_id",
            "position",
        )?;
        canonicalize_dedup_table(
            conn,
            "message_draft_attachments",
            "group_id_hex",
            &["position"],
            "",
            None,
        )?;
    }

    canonicalize_dedup_table(
        conn,
        "message_drafts",
        "group_id_hex",
        &[],
        "updated_at_ms DESC, created_at_ms DESC",
        None,
    )?;
    Ok(())
}

/// Remove lower-priority rows that would collide on `(lower(group_col), unique_col)`
/// while preserving canonical lowercase rows first, then smallest `tie_col`.
fn dedup_rows_by_key_column(
    conn: &Connection,
    table: &str,
    group_col: &str,
    unique_col: &str,
    tie_col: &str,
) -> StorageResult<()> {
    let targets = non_lowercase_targets(conn, table, group_col)?;
    for lower_id in targets {
        let rows: Vec<(String, Value, Value)> = {
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT \"{group_col}\", \"{unique_col}\", \"{tie_col}\"
                     FROM \"{table}\"
                     WHERE lower(\"{group_col}\") = ?1 AND \"{unique_col}\" IS NOT NULL
                     ORDER BY CASE WHEN \"{group_col}\" = ?1 THEN 0 ELSE 1 END,
                              \"{tie_col}\" ASC, \"{group_col}\" ASC"
                ))
                .storage()?;
            stmt.query_map([&lower_id], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?
        };
        let mut seen = BTreeSet::new();
        for (spelling, unique_val, tie_val) in rows {
            if !seen.insert(ValueKey::from(&unique_val)) {
                conn.execute(
                    &format!(
                        "DELETE FROM \"{table}\"
                         WHERE \"{group_col}\" = ?1 AND \"{unique_col}\" = ?2 AND \"{tie_col}\" IS ?3"
                    ),
                    params![spelling, unique_val, tie_val],
                )
                .storage()?;
            }
        }
    }
    Ok(())
}

fn canonicalize_local_message_submissions(conn: &Connection) -> StorageResult<()> {
    let targets = non_lowercase_targets(conn, "local_message_submissions", "group_id_hex")?;
    if targets.is_empty() {
        return Ok(());
    }
    for lower_id in targets {
        // Resolve both UNIQUE constraints (`(group_id_hex, client_token)` and
        // `(group_id_hex, message_id_hex)`) keeping the newest `sequence DESC`.
        let rows: Vec<(i64, String, String, Option<String>)> = {
            let mut stmt = conn
                .prepare(
                    "SELECT sequence, group_id_hex, client_token, message_id_hex
                     FROM local_message_submissions
                     WHERE lower(group_id_hex) = ?1
                     ORDER BY sequence DESC,
                              CASE WHEN group_id_hex = ?1 THEN 0 ELSE 1 END,
                              group_id_hex ASC",
                )
                .storage()?;
            stmt.query_map([&lower_id], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?
        };
        let mut seen_tokens = BTreeSet::new();
        let mut seen_messages = BTreeSet::new();
        for (sequence, _spelling, client_token, message_id_hex) in rows {
            let token_conflict = seen_tokens.contains(&client_token);
            let message_conflict = message_id_hex
                .as_ref()
                .is_some_and(|message_id| seen_messages.contains(message_id));
            if token_conflict || message_conflict {
                conn.execute(
                    "DELETE FROM local_message_submissions WHERE sequence = ?1",
                    [sequence],
                )
                .storage()?;
            } else {
                seen_tokens.insert(client_token);
                if let Some(message_id) = message_id_hex {
                    seen_messages.insert(message_id);
                }
            }
        }
        conn.execute(
            "UPDATE local_message_submissions
             SET group_id_hex = ?1
             WHERE lower(group_id_hex) = ?1 AND group_id_hex != ?1",
            [&lower_id],
        )
        .storage()?;
    }
    Ok(())
}

fn canonicalize_chat_pin_positions(conn: &Connection) -> StorageResult<bool> {
    if !has_non_lowercase(conn, "chat_pin_positions", "group_id_hex")? {
        return Ok(false);
    }
    // Suppress per-row pin-rank triggers during rewrite and recompute pin
    // columns once after both `chat_pin_positions` and `chat_list_rows` finish.
    conn.execute(
        "UPDATE chat_list_navigation_meta SET pin_rewrite_in_progress = 1 WHERE id = 1",
        [],
    )
    .storage()?;
    let result = canonicalize_dedup_table(
        conn,
        "chat_pin_positions",
        "group_id_hex",
        &[],
        "ordinal ASC",
        None,
    );
    let reset = conn
        .execute(
            "UPDATE chat_list_navigation_meta SET pin_rewrite_in_progress = 0 WHERE id = 1",
            [],
        )
        .storage();
    result.and_then(|changed| reset.map(|_| changed))
}

fn refresh_chat_list_pin_columns(conn: &Connection) -> StorageResult<()> {
    conn.execute(
        "UPDATE chat_list_rows
         SET list_pin_ordinal = COALESCE(
                 (SELECT ordinal FROM chat_pin_positions WHERE group_id_hex = chat_list_rows.group_id_hex),
                 -1
             ),
             list_pin_position = (
                 SELECT (
                     SELECT count(*) FROM chat_pin_positions earlier
                     WHERE earlier.ordinal < pin.ordinal
                 )
                 FROM chat_pin_positions pin
                 WHERE pin.group_id_hex = chat_list_rows.group_id_hex
             )
         WHERE list_pin_ordinal >= 0
            OR group_id_hex IN (SELECT group_id_hex FROM chat_pin_positions)",
        [],
    )
    .storage()?;
    Ok(())
}

fn canonicalize_message_timeline(conn: &Connection) -> StorageResult<bool> {
    let targets = non_lowercase_targets(conn, "message_timeline", "group_id_hex")?;
    if targets.is_empty() {
        return Ok(false);
    }
    // Before `canonicalize_dedup_table` renames a non-lowercase timeline row to
    // `lower(group_id_hex)` (when no canonical timeline row exists yet), clear
    // any pre-existing orphaned `attachment_history` rows at the canonical key
    // so `attachment_source_update`'s `INSERT INTO attachment_history` cannot
    // collide on its primary key.
    for lower_id in &targets {
        conn.execute(
            "DELETE FROM attachment_history
             WHERE group_id_hex = ?1
               AND message_id_hex IN (
                   SELECT message_id_hex FROM message_timeline
                   WHERE lower(group_id_hex) = ?1 AND group_id_hex != ?1
               )
               AND NOT EXISTS (
                   SELECT 1 FROM message_timeline canonical
                   WHERE canonical.group_id_hex = ?1
                     AND canonical.message_id_hex = attachment_history.message_id_hex
               )",
            [lower_id],
        )
        .storage()?;
    }
    canonicalize_dedup_table(
        conn,
        "message_timeline",
        "group_id_hex",
        &["message_id_hex"],
        "timeline_order_seq DESC, received_at DESC",
        None,
    )
}

fn canonicalize_attachment_history_versions(conn: &Connection) -> StorageResult<()> {
    let targets = non_lowercase_targets(conn, "attachment_history_versions", "group_id_hex")?;
    if targets.is_empty() {
        return Ok(());
    }
    for lower_id in targets {
        let rows: Vec<(String, Vec<u8>, i64, i64)> = {
            let mut stmt = conn
                .prepare(
                    "SELECT group_id_hex, generation, revision, additions
                     FROM attachment_history_versions
                     WHERE lower(group_id_hex) = ?1
                     ORDER BY CASE WHEN group_id_hex = ?1 THEN 0 ELSE 1 END,
                              revision DESC, group_id_hex ASC",
                )
                .storage()?;
            stmt.query_map([&lower_id], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?
        };
        let generation = rows[0].1.clone();
        let max_revision = rows.iter().map(|r| r.2).max().unwrap_or(0);
        let revision = if rows.len() > 1 {
            max_revision.saturating_add(1)
        } else {
            max_revision
        };
        let additions = rows.iter().map(|r| r.3).max().unwrap_or(0);
        conn.execute(
            "DELETE FROM attachment_history_versions
             WHERE lower(group_id_hex) = ?1 AND group_id_hex != ?1",
            [&lower_id],
        )
        .storage()?;
        conn.execute(
            "INSERT INTO attachment_history_versions (group_id_hex, generation, revision, additions)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(group_id_hex) DO UPDATE SET
                 revision = excluded.revision,
                 additions = excluded.additions",
            params![&lower_id, generation, revision, additions],
        )
        .storage()?;
    }
    Ok(())
}

fn has_orphaned_attachment_worker_demand(conn: &Connection) -> StorageResult<bool> {
    conn.query_row(
        "SELECT EXISTS (
             SELECT 1 FROM attachment_worker_demand d
             WHERE NOT EXISTS (
                 SELECT 1 FROM attachment_history h
                 WHERE h.group_id_hex = d.group_id_hex
                   AND h.message_id_hex = d.message_id_hex
                   AND h.attachment_index = d.attachment_index
             )
         )",
        [],
        |row| row.get(0),
    )
    .storage()
}

fn canonicalize_attachment_acquisition(conn: &Connection) -> StorageResult<()> {
    let targets = non_lowercase_targets(conn, "attachment_acquisition", "group_id_hex")?;
    if targets.is_empty() {
        return Ok(());
    }
    for lower_id in targets {
        let rows: Vec<(Vec<u8>, String, i64)> = {
            let mut stmt = conn
                .prepare(
                    "SELECT token, message_id_hex, attachment_index
                     FROM attachment_acquisition
                     WHERE lower(group_id_hex) = ?1
                     ORDER BY CASE WHEN state = 3 THEN 0 ELSE 1 END,
                              body_completed DESC,
                              explicit_request DESC,
                              priority_at DESC,
                              CASE WHEN group_id_hex = ?1 THEN 0 ELSE 1 END,
                              group_id_hex ASC,
                              token ASC",
                )
                .storage()?;
            stmt.query_map([&lower_id], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?
        };
        let mut seen = BTreeSet::new();
        for (token, message_id_hex, attachment_index) in rows {
            if !seen.insert((message_id_hex, attachment_index)) {
                // Move the losing duplicate out of completed state before
                // deleting its body/row so `attachment_body_*` triggers do not
                // emit spurious removal journal entries during consolidation.
                conn.execute(
                    "UPDATE attachment_acquisition
                     SET state = 0, due = 0, attempt = NULL, body_completed = 0, cancelled = 1
                     WHERE token = ?1",
                    [&token],
                )
                .storage()?;
                for child_table in [
                    "attachment_partial_chunk",
                    "attachment_partial",
                    "media_file_refs",
                    "retained_attachment_files",
                    "retained_attachment_bytes",
                ] {
                    conn.execute(
                        &format!("DELETE FROM \"{child_table}\" WHERE token = ?1"),
                        [&token],
                    )
                    .storage()?;
                }
                conn.execute(
                    "DELETE FROM attachment_acquisition WHERE token = ?1",
                    [&token],
                )
                .storage()?;
            }
        }
        conn.execute(
            "UPDATE attachment_acquisition
             SET group_id_hex = ?1
             WHERE lower(group_id_hex) = ?1 AND group_id_hex != ?1",
            [&lower_id],
        )
        .storage()?;
    }
    Ok(())
}

fn canonicalize_encrypted_media_watermarks(conn: &Connection) -> StorageResult<()> {
    let targets = non_lowercase_targets(
        conn,
        "encrypted_media_epoch_secret_retirement_watermarks",
        "group_id_hex",
    )?;
    if targets.is_empty() {
        return Ok(());
    }
    for lower_id in targets {
        let (retired_through_epoch, retired_at_unix_seconds): (i64, i64) = conn
            .query_row(
                "SELECT MAX(retired_through_epoch), MAX(retired_at_unix_seconds)
                 FROM encrypted_media_epoch_secret_retirement_watermarks
                 WHERE lower(group_id_hex) = ?1",
                [&lower_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .storage()?;
        conn.execute(
            "DELETE FROM encrypted_media_epoch_secret_retirement_watermarks
             WHERE lower(group_id_hex) = ?1 AND group_id_hex != ?1",
            [&lower_id],
        )
        .storage()?;
        conn.execute(
            "INSERT INTO encrypted_media_epoch_secret_retirement_watermarks (
                 group_id_hex, retired_through_epoch, retired_at_unix_seconds
             ) VALUES (?1, ?2, ?3)
             ON CONFLICT(group_id_hex) DO UPDATE SET
                 retired_through_epoch = MAX(
                     encrypted_media_epoch_secret_retirement_watermarks.retired_through_epoch,
                     excluded.retired_through_epoch
                 ),
                 retired_at_unix_seconds = MAX(
                     encrypted_media_epoch_secret_retirement_watermarks.retired_at_unix_seconds,
                     excluded.retired_at_unix_seconds
                 )",
            params![&lower_id, retired_through_epoch, retired_at_unix_seconds],
        )
        .storage()?;
    }
    Ok(())
}

fn canonicalize_encrypted_media_secrets(conn: &Connection) -> StorageResult<()> {
    let targets = non_lowercase_targets(conn, "encrypted_media_epoch_secrets", "group_id_hex")?;
    if targets.is_empty() {
        return Ok(());
    }
    struct SecretRow {
        spelling: String,
        component_id: i64,
        source_epoch: i64,
        secret: zeroize::Zeroizing<Vec<u8>>,
        created_at: i64,
        retention_managed: i64,
    }
    for lower_id in targets {
        let rows: Vec<SecretRow> = {
            let mut stmt = conn
                .prepare(
                    "SELECT group_id_hex, component_id, source_epoch, secret,
                            created_at_unix_seconds, retention_managed
                     FROM encrypted_media_epoch_secrets
                     WHERE lower(group_id_hex) = ?1
                     ORDER BY created_at_unix_seconds DESC,
                              CASE WHEN group_id_hex = ?1 THEN 0 ELSE 1 END,
                              group_id_hex ASC",
                )
                .storage()?;
            stmt.query_map([&lower_id], |row| {
                Ok(SecretRow {
                    spelling: row.get(0)?,
                    component_id: row.get(1)?,
                    source_epoch: row.get(2)?,
                    secret: zeroize::Zeroizing::new(row.get(3)?),
                    created_at: row.get(4)?,
                    retention_managed: row.get(5)?,
                })
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?
        };
        let mut grouped: BTreeMap<(i64, i64), Vec<SecretRow>> = BTreeMap::new();
        for row in rows {
            grouped
                .entry((row.component_id, row.source_epoch))
                .or_default()
                .push(row);
        }
        for ((component_id, source_epoch), group_rows) in grouped {
            let retention_managed = group_rows
                .iter()
                .map(|row| row.retention_managed)
                .max()
                .unwrap_or(0);
            let winner = &group_rows[0];
            let has_canonical = group_rows.iter().any(|row| row.spelling == lower_id);
            if has_canonical {
                for row in &group_rows {
                    if row.spelling == lower_id {
                        continue;
                    }
                    conn.execute(
                        "UPDATE encrypted_media_epoch_secrets
                         SET secret = zeroblob(length(secret))
                         WHERE group_id_hex = ?1 AND component_id = ?2 AND source_epoch = ?3",
                        params![&row.spelling, component_id, source_epoch],
                    )
                    .storage()?;
                    conn.execute(
                        "DELETE FROM encrypted_media_epoch_secrets
                         WHERE group_id_hex = ?1 AND component_id = ?2 AND source_epoch = ?3",
                        params![&row.spelling, component_id, source_epoch],
                    )
                    .storage()?;
                }
                conn.execute(
                    "UPDATE encrypted_media_epoch_secrets
                     SET secret = ?1, created_at_unix_seconds = ?2, retention_managed = ?3
                     WHERE group_id_hex = ?4 AND component_id = ?5 AND source_epoch = ?6",
                    params![
                        winner.secret.as_slice(),
                        winner.created_at,
                        retention_managed,
                        &lower_id,
                        component_id,
                        source_epoch,
                    ],
                )
                .storage()?;
            } else {
                for loser in &group_rows[1..] {
                    conn.execute(
                        "UPDATE encrypted_media_epoch_secrets
                         SET secret = zeroblob(length(secret))
                         WHERE group_id_hex = ?1 AND component_id = ?2 AND source_epoch = ?3",
                        params![&loser.spelling, component_id, source_epoch],
                    )
                    .storage()?;
                    conn.execute(
                        "DELETE FROM encrypted_media_epoch_secrets
                         WHERE group_id_hex = ?1 AND component_id = ?2 AND source_epoch = ?3",
                        params![&loser.spelling, component_id, source_epoch],
                    )
                    .storage()?;
                }
                conn.execute(
                    "UPDATE encrypted_media_epoch_secrets
                     SET group_id_hex = ?1, retention_managed = ?2
                     WHERE group_id_hex = ?3 AND component_id = ?4 AND source_epoch = ?5",
                    params![
                        &lower_id,
                        retention_managed,
                        &winner.spelling,
                        component_id,
                        source_epoch,
                    ],
                )
                .storage()?;
            }
        }
    }
    Ok(())
}

fn canonicalize_local_group_deletion_frontiers(conn: &Connection) -> StorageResult<()> {
    let targets = non_lowercase_targets(conn, "local_group_deletion_frontiers", "group_id_hex")?;
    if targets.is_empty() {
        return Ok(());
    }
    for lower_id in targets {
        let message_insert_order: i64 = conn
            .query_row(
                "SELECT MAX(message_insert_order)
                 FROM local_group_deletion_frontiers
                 WHERE lower(group_id_hex) = ?1",
                [&lower_id],
                |row| row.get(0),
            )
            .storage()?;
        let prior_nostr_routes_json: String = conn
            .query_row(
                "SELECT prior_nostr_routes_json
                 FROM local_group_deletion_frontiers
                 WHERE lower(group_id_hex) = ?1
                 ORDER BY CASE WHEN prior_nostr_routes_json != '[]' THEN 0 ELSE 1 END,
                          message_insert_order DESC,
                          CASE WHEN group_id_hex = ?1 THEN 0 ELSE 1 END,
                          group_id_hex ASC
                 LIMIT 1",
                [&lower_id],
                |row| row.get(0),
            )
            .storage()?;
        let (pending_confirmation, welcomer_account_id_hex, via_welcome_message_id_hex): (
            Option<i64>,
            Option<String>,
            Option<String>,
        ) = conn
            .query_row(
                "SELECT pending_confirmation, welcomer_account_id_hex, via_welcome_message_id_hex
                 FROM local_group_deletion_frontiers
                 WHERE lower(group_id_hex) = ?1
                 ORDER BY CASE WHEN pending_confirmation IS NOT NULL THEN 0 ELSE 1 END,
                          message_insert_order DESC,
                          CASE WHEN group_id_hex = ?1 THEN 0 ELSE 1 END,
                          group_id_hex ASC
                 LIMIT 1",
                [&lower_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .storage()?;
        conn.execute(
            "DELETE FROM local_group_deletion_frontiers
             WHERE lower(group_id_hex) = ?1 AND group_id_hex != ?1",
            [&lower_id],
        )
        .storage()?;
        conn.execute(
            "INSERT INTO local_group_deletion_frontiers (
                 group_id_hex, message_insert_order, prior_nostr_routes_json,
                 pending_confirmation, welcomer_account_id_hex, via_welcome_message_id_hex
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(group_id_hex) DO UPDATE SET
                 message_insert_order = excluded.message_insert_order,
                 prior_nostr_routes_json = excluded.prior_nostr_routes_json,
                 pending_confirmation = excluded.pending_confirmation,
                 welcomer_account_id_hex = excluded.welcomer_account_id_hex,
                 via_welcome_message_id_hex = excluded.via_welcome_message_id_hex",
            params![
                &lower_id,
                message_insert_order,
                prior_nostr_routes_json,
                pending_confirmation,
                welcomer_account_id_hex,
                via_welcome_message_id_hex,
            ],
        )
        .storage()?;
    }
    Ok(())
}

fn canonicalize_secure_delete_checkpoint_intents(conn: &Connection) -> StorageResult<()> {
    if !has_non_lowercase(conn, "secure_delete_checkpoint_intents", "scope")? {
        return Ok(());
    }
    let targets: Vec<(String, String)> = {
        let mut stmt = conn
            .prepare(
                "SELECT DISTINCT operation_kind, lower(scope)
                 FROM secure_delete_checkpoint_intents
                 WHERE scope != lower(scope)
                 ORDER BY 1, 2",
            )
            .storage()?;
        stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?
    };

    for (operation_kind, lower_scope) in targets {
        let rows: Vec<(String, String)> = {
            let mut stmt = conn
                .prepare(
                    "SELECT scope, result_json
                     FROM secure_delete_checkpoint_intents
                     WHERE operation_kind = ?1 AND lower(scope) = ?2
                     ORDER BY CASE WHEN scope = ?2 THEN 0 ELSE 1 END, scope ASC",
                )
                .storage()?;
            stmt.query_map(params![&operation_kind, &lower_scope], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?
        };
        if rows.len() == 1 {
            conn.execute(
                "UPDATE secure_delete_checkpoint_intents
                 SET scope = ?1
                 WHERE operation_kind = ?2 AND scope = ?3",
                params![&lower_scope, &operation_kind, &rows[0].0],
            )
            .storage()?;
            continue;
        }
        let merged_json = merge_checkpoint_intent_json(
            &operation_kind,
            rows.iter().map(|(_, json)| json.as_str()),
        )?;
        conn.execute(
            "DELETE FROM secure_delete_checkpoint_intents
             WHERE operation_kind = ?1 AND lower(scope) = ?2 AND scope != ?2",
            params![&operation_kind, &lower_scope],
        )
        .storage()?;
        conn.execute(
            "INSERT INTO secure_delete_checkpoint_intents (
                 operation_kind, scope, intent_nonce, result_json
             ) VALUES (?1, ?2, randomblob(16), ?3)
             ON CONFLICT(operation_kind, scope) DO UPDATE SET
                 intent_nonce = randomblob(16),
                 result_json = excluded.result_json",
            params![&operation_kind, &lower_scope, merged_json],
        )
        .storage()?;
    }
    Ok(())
}

fn merge_checkpoint_intent_json<'a>(
    operation_kind: &str,
    payloads: impl Iterator<Item = &'a str>,
) -> StorageResult<String> {
    let payloads: Vec<&str> = payloads.collect();
    match operation_kind {
        "local_group" => {
            let mut deleted_rows: u64 = 0;
            for raw in payloads {
                let value: serde_json::Value = serde_json::from_str(raw)
                    .map_err(|error| StorageError::Serialization(error.to_string()))?;
                if let Some(count) = value
                    .get("deleted_rows")
                    .and_then(serde_json::Value::as_u64)
                {
                    deleted_rows = deleted_rows.saturating_add(count);
                }
            }
            serde_json::to_string(&serde_json::json!({
                "deleted_rows": deleted_rows,
                "completed_pending_checkpoint": false,
                "erasure_pending": false,
            }))
            .map_err(|error| StorageError::Serialization(error.to_string()))
        }
        "retention" => {
            let mut pruned_messages: u64 = 0;
            let mut pruned_media_epoch_secrets: u64 = 0;
            let mut media_hashes: BTreeSet<String> = BTreeSet::new();
            for raw in payloads {
                let value: serde_json::Value = serde_json::from_str(raw)
                    .map_err(|error| StorageError::Serialization(error.to_string()))?;
                if let Some(count) = value
                    .get("pruned_messages")
                    .and_then(serde_json::Value::as_u64)
                {
                    pruned_messages = pruned_messages.saturating_add(count);
                }
                if let Some(count) = value
                    .get("pruned_media_epoch_secrets")
                    .and_then(serde_json::Value::as_u64)
                {
                    pruned_media_epoch_secrets = pruned_media_epoch_secrets.saturating_add(count);
                }
                if let Some(hashes) = value
                    .get("media_ciphertext_sha256")
                    .and_then(serde_json::Value::as_array)
                {
                    for hash in hashes.iter().filter_map(serde_json::Value::as_str) {
                        media_hashes.insert(hash.to_owned());
                    }
                }
            }
            let media_ciphertext_sha256: Vec<String> = media_hashes.into_iter().collect();
            serde_json::to_string(&serde_json::json!({
                "pruned_messages": pruned_messages,
                "pruned_media_epoch_secrets": pruned_media_epoch_secrets,
                "media_ciphertext_sha256": media_ciphertext_sha256,
                "erasure_pending": false,
            }))
            .map_err(|error| StorageError::Serialization(error.to_string()))
        }
        _ => Ok(payloads.first().copied().unwrap_or("{}").to_owned()),
    }
}

fn canonicalize_device_group_joins(conn: &Connection) -> StorageResult<()> {
    let targets = non_lowercase_targets(conn, "device_group_joins", "group_id_hex")?;
    if targets.is_empty() {
        return Ok(());
    }
    for lower_id in targets {
        let joined_at: i64 = conn
            .query_row(
                "SELECT MAX(joined_at) FROM device_group_joins WHERE lower(group_id_hex) = ?1",
                [&lower_id],
                |row| row.get(0),
            )
            .storage()?;
        conn.execute(
            "DELETE FROM device_group_joins WHERE lower(group_id_hex) = ?1 AND group_id_hex != ?1",
            [&lower_id],
        )
        .storage()?;
        conn.execute(
            "INSERT INTO device_group_joins (group_id_hex, joined_at)
             VALUES (?1, ?2)
             ON CONFLICT(group_id_hex) DO UPDATE SET
                 joined_at = MAX(device_group_joins.joined_at, excluded.joined_at)",
            params![&lower_id, joined_at],
        )
        .storage()?;
    }
    Ok(())
}

fn canonicalize_device_removals(conn: &Connection) -> StorageResult<()> {
    let targets = non_lowercase_targets(conn, "device_removals", "group_id_hex")?;
    if targets.is_empty() {
        return Ok(());
    }
    for lower_id in targets {
        let merged: Vec<(String, i64, Option<i64>)> = {
            let mut stmt = conn
                .prepare(
                    "SELECT slot_hex, MAX(requested_at), MAX(slot_withdrawn_at)
                     FROM device_removals
                     WHERE lower(group_id_hex) = ?1
                     GROUP BY slot_hex",
                )
                .storage()?;
            stmt.query_map([&lower_id], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?
        };
        conn.execute(
            "DELETE FROM device_removals WHERE lower(group_id_hex) = ?1 AND group_id_hex != ?1",
            [&lower_id],
        )
        .storage()?;
        for (slot_hex, requested_at, slot_withdrawn_at) in merged {
            conn.execute(
                "INSERT INTO device_removals (group_id_hex, slot_hex, requested_at, slot_withdrawn_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(group_id_hex, slot_hex) DO UPDATE SET
                     requested_at = MAX(device_removals.requested_at, excluded.requested_at),
                     slot_withdrawn_at = CASE
                         WHEN device_removals.slot_withdrawn_at IS NULL THEN excluded.slot_withdrawn_at
                         WHEN excluded.slot_withdrawn_at IS NULL THEN device_removals.slot_withdrawn_at
                         ELSE MAX(device_removals.slot_withdrawn_at, excluded.slot_withdrawn_at)
                     END",
                params![&lower_id, slot_hex, requested_at, slot_withdrawn_at],
            )
            .storage()?;
        }
    }
    Ok(())
}

fn canonicalize_link_chat_report_pages(conn: &Connection) -> StorageResult<()> {
    let targets = non_lowercase_targets(conn, "link_chat_report_pages", "group_id")?;
    if targets.is_empty() {
        return Ok(());
    }
    for lower_id in targets {
        // Every page row for a group belongs to one `(link_ref, revision)`
        // inventory; keep only the single winning spelling's pages so pages
        // from distinct revisions are never mixed.
        let winner: String = conn
            .query_row(
                "SELECT group_id
                 FROM link_chat_report_pages
                 WHERE lower(group_id) = ?1
                 ORDER BY revision DESC, expires_at DESC,
                          CASE WHEN group_id = ?1 THEN 0 ELSE 1 END,
                          group_id ASC
                 LIMIT 1",
                [&lower_id],
                |row| row.get(0),
            )
            .storage()?;
        conn.execute(
            "DELETE FROM link_chat_report_pages
             WHERE lower(group_id) = ?1 AND group_id != ?2",
            params![&lower_id, &winner],
        )
        .storage()?;
        if winner != lower_id {
            conn.execute(
                "UPDATE link_chat_report_pages
                 SET group_id = ?1
                 WHERE group_id = ?2",
                params![&lower_id, &winner],
            )
            .storage()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::HANDLED_COLUMNS;
    use crate::base::migrations::run_through;
    use rusqlite::Connection;
    use std::collections::BTreeSet;

    fn open_pre_228_fk() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", true).unwrap();
        run_through(&mut conn, 227).unwrap();
        conn
    }

    #[test]
    fn migration_0228_covers_every_text_group_id_column_in_schema() {
        let mut conn = open_pre_228_fk();
        run_through(&mut conn, 228).unwrap();

        let tables: Vec<String> = {
            let mut stmt = conn
                .prepare(
                    "SELECT name FROM sqlite_schema
                     WHERE type = 'table' AND name NOT GLOB 'sqlite_*'
                     ORDER BY name",
                )
                .unwrap();
            stmt.query_map([], |row| row.get(0))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
        };
        let mut schema_columns = BTreeSet::new();
        for table in tables {
            let mut stmt = conn
                .prepare(&format!("PRAGMA table_info(\"{table}\")"))
                .unwrap();
            let cols = stmt
                .query_map([], |row| {
                    Ok((row.get::<_, String>(1)?, row.get::<_, String>(2)?))
                })
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            for (col_name, col_type) in cols {
                if col_type.eq_ignore_ascii_case("BLOB") {
                    continue;
                }
                if col_name.to_ascii_lowercase().contains("group_id")
                    || (table == "secure_delete_checkpoint_intents" && col_name == "scope")
                {
                    schema_columns.insert((table.clone(), col_name));
                }
            }
        }
        let handled: BTreeSet<(String, String)> = HANDLED_COLUMNS
            .iter()
            .map(|(t, c)| ((*t).to_owned(), (*c).to_owned()))
            .collect();
        assert_eq!(
            schema_columns, handled,
            "migration 0228 must cover every TEXT group_id* / checkpoint-scope column in schema 228"
        );
    }

    #[test]
    fn migration_0228_canonicalizes_mixed_case_rows_and_is_idempotent() {
        let mut conn = open_pre_228_fk();
        let gid = "AbCdEf01";
        let lower = "abcdef01";
        let digest = vec![0x11u8; 32];
        let token = vec![0x22u8; 16];
        let nonce = vec![0x33u8; 16];

        conn.execute(
            "INSERT INTO account_groups (group_id_hex, endpoint, profile_name, updated_at)
             VALUES (?1, 'ep', 'Mixed Case', 100)",
            [gid],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO chat_list_rows (group_id_hex, updated_at, unread_count)
             VALUES (?1, 100, 3)",
            [gid],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO chat_pin_positions (group_id_hex, ordinal) VALUES (?1, 0)",
            [gid],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO app_events (
                 group_id_hex, message_id_hex, source_message_id_hex, direction,
                 sender, plaintext, kind, tags_json, recorded_at, received_at, source_epoch
             ) VALUES (?1, 'm1', 'src1', 'received', 'alice', 'hi', 9, '[]', 10, 10, 4)",
            [gid],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO message_timeline (
                 group_id_hex, message_id_hex, source_message_id_hex, direction,
                 sender, plaintext, kind, tags_json, timeline_at, received_at, source_epoch,
                 media_json, reactions_json
             ) VALUES (?1, 'm1', 'src1', 'received', 'alice', 'hi', 9, '[]', 10, 10, 4,
                       '{\"imeta\":[[\"imeta\",\"m image/png\"]]}', '[]')",
            [gid],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO attachment_acquisition (
                 token, group_id_hex, message_id_hex, attachment_index, source_message_id_hex,
                 source_epoch, slot_json, plaintext_digest, state, due
             ) VALUES (?1, ?2, 'm1', 0, 'src1', 4, '[\"imeta\",\"m image/png\"]', ?3, 0, 0)",
            rusqlite::params![&token, gid, &digest],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO encrypted_media_epoch_secrets (
                 group_id_hex, component_id, source_epoch, secret,
                 created_at_unix_seconds, retention_managed
             ) VALUES (?1, 32776, 4, x'deadbeef', 10, 1)",
            [gid],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO encrypted_media_epoch_secret_references (
                 group_id_hex, message_id_hex, component_id, source_epoch
             ) VALUES (?1, 'm1', 32776, 4)",
            [gid],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO encrypted_media_epoch_secret_retirement_watermarks (
                 group_id_hex, retired_through_epoch, retired_at_unix_seconds
             ) VALUES (?1, 3, 50)",
            [gid],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO local_group_deletion_frontiers (group_id_hex, message_insert_order)
             VALUES (?1, 12)",
            [gid],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO secure_delete_checkpoint_intents (
                 operation_kind, scope, intent_nonce, result_json
             ) VALUES ('local_group', ?1, ?2, '{\"deleted_rows\":5,\"completed_pending_checkpoint\":false,\"erasure_pending\":false}')",
            rusqlite::params![gid, &nonce],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO message_drafts (group_id_hex, content, created_at_ms, updated_at_ms)
             VALUES (?1, 'draft text', 1, 2)",
            [gid],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO message_draft_attachments (
                 group_id_hex, position, attachment_id, file_name, media_type, plaintext
             ) VALUES (?1, 0, 'att-1', 'a.txt', 'text/plain', x'0102')",
            [gid],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO link_chat_reports (
                 group_id, slot, link_ref, digest, revision, total, remaining, expires_at
             ) VALUES (?1, 'slot1', 'ref1', ?2, 1, 2, 1, 999)",
            rusqlite::params![gid, &digest],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO sibling_welcomes_received (
                 message_id_hex, content, created_at, received_at, held_group_id_hex
             ) VALUES ('w1', x'01', 1, 2, ?1)",
            [gid],
        )
        .unwrap();

        run_through(&mut conn, 228).unwrap();

        let fk_violations: i64 = conn
            .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(fk_violations, 0);

        // Verify all rows are now lowercase and intact.
        for (table, column) in [
            ("account_groups", "group_id_hex"),
            ("chat_list_rows", "group_id_hex"),
            ("chat_pin_positions", "group_id_hex"),
            ("app_events", "group_id_hex"),
            ("message_timeline", "group_id_hex"),
            ("attachment_history", "group_id_hex"),
            ("attachment_acquisition", "group_id_hex"),
            ("encrypted_media_epoch_secrets", "group_id_hex"),
            ("encrypted_media_epoch_secret_references", "group_id_hex"),
            (
                "encrypted_media_epoch_secret_retirement_watermarks",
                "group_id_hex",
            ),
            ("local_group_deletion_frontiers", "group_id_hex"),
            ("secure_delete_checkpoint_intents", "scope"),
            ("message_drafts", "group_id_hex"),
            ("message_draft_attachments", "group_id_hex"),
            ("link_chat_reports", "group_id"),
            ("sibling_welcomes_received", "held_group_id_hex"),
        ] {
            let count: i64 = conn
                .query_row(
                    &format!("SELECT count(*) FROM \"{table}\" WHERE \"{column}\" = ?1"),
                    [lower],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(
                count, 1,
                "{table}.{column} should hold canonical lowercase row"
            );
            let remaining_upper: i64 = conn
                .query_row(
                    &format!(
                        "SELECT count(*) FROM \"{table}\" WHERE \"{column}\" != lower(\"{column}\")"
                    ),
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(
                remaining_upper, 0,
                "{table}.{column} must have no uppercase rows"
            );
        }

        // Verify chat_list_rows derived pin columns stayed consistent.
        let (pin_ord, pin_pos): (i64, Option<i64>) = conn
            .query_row(
                "SELECT list_pin_ordinal, list_pin_position FROM chat_list_rows WHERE group_id_hex = ?1",
                [lower],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((pin_ord, pin_pos), (0, Some(0)));

        // Re-running migration body on already-canonical DB is an exact no-op.
        let before = conn.total_changes();
        {
            let tx = conn.transaction().unwrap();
            super::apply(&tx).unwrap();
            tx.commit().unwrap();
        }
        assert_eq!(conn.total_changes(), before);
    }

    #[test]
    fn migration_0228_merges_colliding_case_duplicates_deterministically() {
        let mut conn = open_pre_228_fk();
        let digest = vec![0x44u8; 32];
        let hash32 = vec![0x55u8; 32];
        let token_low = vec![0x01u8; 16];
        let token_hi = vec![0x02u8; 16];
        let token_done_low = vec![0x03u8; 16];
        let token_done_upper = vec![0x04u8; 16];
        let nonce_a = vec![0x0au8; 16];
        let nonce_b = vec![0x0bu8; 16];

        // Colliding account_groups: uppercase is newer (updated_at = 200 vs 100 / 150).
        conn.execute(
            "INSERT INTO account_groups (group_id_hex, endpoint, profile_name, updated_at)
             VALUES ('aabb', 'ep', 'Old Name', 100), ('AABB', 'ep', 'New Name', 200), ('AaBb', 'ep', 'Mid Name', 150)",
            [],
        )
        .unwrap();
        // Child row under both spellings + canonical child that must survive parent merge.
        conn.execute(
            "INSERT INTO agent_item_expired_targets (group_id_hex, message_id_hex)
             VALUES ('aabb', 'keep-me'), ('AABB', 'from-upper')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO chat_list_rows (group_id_hex, updated_at, title)
             VALUES ('aabb', 100, 'Old'), ('AABB', 250, 'New')",
            [],
        )
        .unwrap();
        // Colliding pins: uppercase has higher priority (ordinal 1 < 5).
        conn.execute(
            "INSERT INTO chat_pin_positions (group_id_hex, ordinal)
             VALUES ('aabb', 5), ('AABB', 1)",
            [],
        )
        .unwrap();
        // Colliding app_events with distinct UNIQUE source_message_id_hex (uppercase inserted later).
        conn.execute(
            "INSERT INTO app_events (
                 group_id_hex, message_id_hex, source_message_id_hex, direction,
                 sender, plaintext, kind, tags_json, recorded_at, received_at, source_epoch
             ) VALUES
                 ('aabb', 'm1', 'src-old', 'received', 'alice', 'old', 9, '[]', 10, 10, 4),
                 ('AABB', 'm1', 'src-new', 'received', 'alice', 'new', 9, '[]', 20, 20, 4),
                 ('aabb', 'm2', 'src-m2-lo', 'received', 'alice', 'm2-lo', 9, '[]', 11, 11, 4),
                 ('AABB', 'm2', 'src-m2-hi', 'received', 'alice', 'm2-hi', 9, '[]', 12, 12, 4)",
            [],
        )
        .unwrap();
        // Colliding attachment_acquisition with token-keyed children:
        // - m1: uppercase is completed (state=3) vs lowercase pending (state=0).
        // - m2: BOTH lowercase and uppercase are completed (state=3) with retained
        //   bytes; consolidating them must not emit spurious `attachment_body_removals` rows.
        conn.execute(
            "INSERT INTO attachment_acquisition (
                 token, group_id_hex, message_id_hex, attachment_index, source_message_id_hex,
                 source_epoch, slot_json, plaintext_digest, state, due, body_completed
             ) VALUES
                 (?1, 'aabb', 'm1', 0, 'src-old', 4, '[]', ?5, 0, 0, 0),
                 (?2, 'AABB', 'm1', 0, 'src-new', 4, '[]', ?5, 3, NULL, 1),
                 (?3, 'aabb', 'm2', 0, 'src-m2-lo', 4, '[]', ?5, 3, NULL, 1),
                 (?4, 'AABB', 'm2', 0, 'src-m2-hi', 4, '[]', ?5, 3, NULL, 1)",
            rusqlite::params![
                &token_low,
                &token_hi,
                &token_done_low,
                &token_done_upper,
                &digest
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO retained_attachment_bytes (token, bytes)
             VALUES (?1, x'aa'), (?2, x'bbbb'), (?3, x'cccc'), (?4, x'dddd')",
            rusqlite::params![&token_low, &token_hi, &token_done_low, &token_done_upper],
        )
        .unwrap();
        // Colliding device_groups: older trusted (`linked`) must beat newer `untrusted`.
        conn.execute(
            "INSERT INTO device_groups (group_id_hex, trust, key_package_ref_hex, recorded_at)
             VALUES ('aabb', 'linked', 'kp-1', 100), ('AABB', 'untrusted', NULL, 200)",
            [],
        )
        .unwrap();
        // Colliding attachment_removal_suppression: ByYou (0) under uppercase beats BySetting (1).
        conn.execute(
            "INSERT INTO attachment_removal_suppression (group_id_hex, message_id_hex, attachment_index, reason)
             VALUES ('aabb', 'm1', 0, 1), ('AABB', 'm1', 0, 0)",
            [],
        )
        .unwrap();
        // Colliding local_message_submissions on BOTH unique constraints.
        conn.execute(
            "INSERT INTO local_message_submissions (
                 group_id_hex, client_token, message_id_hex, request_hash, payload_hash, state
             ) VALUES
                 ('aabb', 'tok-1', 'msg-a', ?1, ?1, 0),
                 ('AABB', 'tok-1', 'msg-b', ?1, ?1, 1),
                 ('AaBb', 'tok-2', 'msg-b', ?1, ?1, 3)",
            [&hash32],
        )
        .unwrap();
        // Colliding drafts & attachments: uppercase draft is newer.
        conn.execute(
            "INSERT INTO message_drafts (group_id_hex, content, created_at_ms, updated_at_ms)
             VALUES ('aabb', 'old draft', 1, 10), ('AABB', 'new draft', 1, 20)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO message_draft_attachments (
                 group_id_hex, position, attachment_id, file_name, media_type, plaintext
             ) VALUES
                 ('aabb', 0, 'att-old', 'old.txt', 'text/plain', x'01'),
                 ('AABB', 0, 'att-new', 'new.txt', 'text/plain', x'02')",
            [],
        )
        .unwrap();
        // Colliding media-secret watermarks (3-way mixed-case): MAX must win.
        conn.execute(
            "INSERT INTO encrypted_media_epoch_secret_retirement_watermarks (
                 group_id_hex, retired_through_epoch, retired_at_unix_seconds
             ) VALUES ('aabb', 4, 100), ('AABB', 9, 150), ('AaBb', 7, 200)",
            [],
        )
        .unwrap();
        // Colliding media secrets: newer secret bytes win, retention_managed merges via MAX.
        conn.execute(
            "INSERT INTO encrypted_media_epoch_secrets (
                 group_id_hex, component_id, source_epoch, secret,
                 created_at_unix_seconds, retention_managed
             ) VALUES
                 ('aabb', 32776, 12, x'1111', 100, 1),
                 ('AABB', 32776, 12, x'2222', 200, 0)",
            [],
        )
        .unwrap();
        // Colliding deletion frontiers: MAX order + non-empty routes + invitation standing preserved.
        conn.execute(
            "INSERT INTO local_group_deletion_frontiers (
                 group_id_hex, message_insert_order, prior_nostr_routes_json, pending_confirmation
             ) VALUES
                 ('aabb', 5, '[{\"nostr_group_id_hex\":\"11\"}]', NULL),
                 ('AABB', 15, '[]', 1)",
            [],
        )
        .unwrap();
        // Colliding checkpoint intents: counts sum and retention media hashes union.
        conn.execute(
            "INSERT INTO secure_delete_checkpoint_intents (operation_kind, scope, intent_nonce, result_json)
             VALUES
                 ('local_group', 'aabb', ?1, '{\"deleted_rows\":3,\"completed_pending_checkpoint\":false,\"erasure_pending\":false}'),
                 ('local_group', 'AABB', ?2, '{\"deleted_rows\":7,\"completed_pending_checkpoint\":false,\"erasure_pending\":false}'),
                 ('retention', 'aabb', ?1, '{\"pruned_messages\":2,\"pruned_media_epoch_secrets\":1,\"media_ciphertext_sha256\":[\"bb\"],\"erasure_pending\":false}'),
                 ('retention', 'AaBb', ?2, '{\"pruned_messages\":4,\"pruned_media_epoch_secrets\":2,\"media_ciphertext_sha256\":[\"aa\",\"bb\"],\"erasure_pending\":false}')",
            rusqlite::params![&nonce_a, &nonce_b],
        )
        .unwrap();

        run_through(&mut conn, 228).unwrap();

        let fk_violations: i64 = conn
            .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(fk_violations, 0);

        let profile_name: String = conn
            .query_row(
                "SELECT profile_name FROM account_groups WHERE group_id_hex = 'aabb'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(profile_name, "New Name");

        // Both canonical and migrated children survived parent dedup.
        let expired_count: i64 = conn
            .query_row(
                "SELECT count(*) FROM agent_item_expired_targets WHERE group_id_hex = 'aabb'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(expired_count, 2);

        let pin_ordinal: i64 = conn
            .query_row(
                "SELECT ordinal FROM chat_pin_positions WHERE group_id_hex = 'aabb'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(pin_ordinal, 1);

        let (plaintext, source_id): (String, String) = conn
            .query_row(
                "SELECT plaintext, source_message_id_hex FROM app_events WHERE group_id_hex = 'aabb' AND message_id_hex = 'm1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((plaintext.as_str(), source_id.as_str()), ("new", "src-new"));

        // Completed acquisition row won and kept its retained bytes; loser's child row was cleaned up.
        let (acq_token, acq_state): (Vec<u8>, i64) = conn
            .query_row(
                "SELECT token, state FROM attachment_acquisition WHERE group_id_hex = 'aabb' AND message_id_hex = 'm1' AND attachment_index = 0",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(acq_token, token_hi);
        assert_eq!(acq_state, 3);
        let retained_count: i64 = conn
            .query_row("SELECT count(*) FROM retained_attachment_bytes", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(retained_count, 2);

        // Consolidating colliding completed attachment rows must not emit
        // spurious `attachment_body_removals` entries.
        let body_removals: i64 = conn
            .query_row("SELECT count(*) FROM attachment_body_removals", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(
            body_removals, 0,
            "duplicate attachment consolidation must not emit body-removal journal entries"
        );

        // Trusted (`linked`) device group must beat a newer `untrusted` duplicate.
        let (dg_trust, dg_kp): (String, Option<String>) = conn
            .query_row(
                "SELECT trust, key_package_ref_hex FROM device_groups WHERE group_id_hex = 'aabb'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(dg_trust, "linked");
        assert_eq!(dg_kp.as_deref(), Some("kp-1"));

        // Rejected middle submission (`tok-1`, `msg-b`) must not cause the
        // independent older submission (`tok-1`, `msg-a`) to be deleted.
        let submissions: Vec<(String, Option<String>)> = {
            let mut stmt = conn
                .prepare(
                    "SELECT client_token, message_id_hex
                     FROM local_message_submissions
                     WHERE group_id_hex = 'aabb'
                     ORDER BY client_token ASC",
                )
                .unwrap();
            stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
        };
        assert_eq!(
            submissions,
            vec![
                ("tok-1".to_owned(), Some("msg-a".to_owned())),
                ("tok-2".to_owned(), Some("msg-b".to_owned())),
            ],
            "discarded colliding submission must not reserve client_token and drop unrelated msg-a"
        );

        // ByYou (0) beat BySetting (1).
        let suppression_reason: i64 = conn
            .query_row(
                "SELECT reason FROM attachment_removal_suppression WHERE group_id_hex = 'aabb' AND message_id_hex = 'm1' AND attachment_index = 0",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(suppression_reason, 0);

        // Winning draft and its attachment kept; losing draft's attachment removed.
        let draft_content: String = conn
            .query_row(
                "SELECT content FROM message_drafts WHERE group_id_hex = 'aabb'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(draft_content, "new draft");
        let draft_att_id: String = conn
            .query_row(
                "SELECT attachment_id FROM message_draft_attachments WHERE group_id_hex = 'aabb'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(draft_att_id, "att-new");

        // Watermark merged MAX(retired_through_epoch) and MAX(retired_at_unix_seconds).
        let (wm_epoch, wm_at): (i64, i64) = conn
            .query_row(
                "SELECT retired_through_epoch, retired_at_unix_seconds
                 FROM encrypted_media_epoch_secret_retirement_watermarks
                 WHERE group_id_hex = 'aabb'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((wm_epoch, wm_at), (9, 200));

        // Secret took newer bytes while preserving retention_managed = 1.
        let (secret, retention_managed): (Vec<u8>, i64) = conn
            .query_row(
                "SELECT secret, retention_managed
                 FROM encrypted_media_epoch_secrets
                 WHERE group_id_hex = 'aabb' AND component_id = 32776 AND source_epoch = 12",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(secret, vec![0x22, 0x22]);
        assert_eq!(retention_managed, 1);

        // Deletion frontier kept MAX insert order, non-empty routes, and invitation standing.
        let (frontier_order, routes, pending): (i64, String, Option<i64>) = conn
            .query_row(
                "SELECT message_insert_order, prior_nostr_routes_json, pending_confirmation
                 FROM local_group_deletion_frontiers WHERE group_id_hex = 'aabb'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(frontier_order, 15);
        assert_eq!(routes, "[{\"nostr_group_id_hex\":\"11\"}]");
        assert_eq!(pending, Some(1));

        // Checkpoint intents merged cleanly into single lowercase rows.
        let local_intent_json: String = conn
            .query_row(
                "SELECT result_json FROM secure_delete_checkpoint_intents
                 WHERE operation_kind = 'local_group' AND scope = 'aabb'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let local_intent: serde_json::Value = serde_json::from_str(&local_intent_json).unwrap();
        assert_eq!(local_intent["deleted_rows"], 10);

        let retention_intent_json: String = conn
            .query_row(
                "SELECT result_json FROM secure_delete_checkpoint_intents
                 WHERE operation_kind = 'retention' AND scope = 'aabb'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let retention_intent: serde_json::Value =
            serde_json::from_str(&retention_intent_json).unwrap();
        assert_eq!(retention_intent["pruned_messages"], 6);
        assert_eq!(retention_intent["pruned_media_epoch_secrets"], 3);
        assert_eq!(
            retention_intent["media_ciphertext_sha256"],
            serde_json::json!(["aa", "bb"])
        );

        // Every handled TEXT group-id column across the schema must be
        // strictly canonical lowercase after migration 0228.
        for &(table, column) in HANDLED_COLUMNS {
            let non_lower: i64 = conn
                .query_row(
                    &format!(
                        "SELECT count(*) FROM \"{table}\" WHERE \"{column}\" IS NOT NULL AND \"{column}\" != lower(\"{column}\")"
                    ),
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(
                non_lower, 0,
                "{table}.{column} must contain no non-lowercase rows after migration 0228"
            );
        }
    }
}
