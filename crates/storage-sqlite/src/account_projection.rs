use crate::{
    SqliteAccountStorage, SqliteResultExt, bool_i64, connection::retry_on_busy, tags_from_json,
    unix_now_ms, unix_now_seconds_i64, usize_to_i64,
};
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{
    Connection, OptionalExtension, params, params_from_iter,
    types::{Type, Value},
};
use serde::{Deserialize, Serialize};

/// The local account's own membership in a projected group.
///
/// `Member` is the default and the fallback for unknown/forward-incompatible
/// state: uncertainty must never hide a conversation. `Left` and `Removed` are
/// both terminal "no longer a member" states that suppress the account's unread
/// aggregate; they differ only in *why* membership ended — `Left` is a
/// voluntary self-removal (including declining an invite), `Removed` is an
/// eviction by another member.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum SelfMembership {
    #[default]
    Member,
    Left,
    Removed,
}

impl SelfMembership {
    /// The persisted `account_groups.self_membership` text for this state.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            SelfMembership::Member => "member",
            SelfMembership::Left => "left",
            SelfMembership::Removed => "removed",
        }
    }

    /// Reads persisted membership text. Unknown values fall back to `Member` so
    /// a row written by a newer schema never suppresses its unread here.
    pub(crate) fn from_storage(value: &str) -> Self {
        match value {
            "left" => SelfMembership::Left,
            "removed" => SelfMembership::Removed,
            _ => SelfMembership::Member,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StoredAccountState {
    pub label: String,
    pub seen_events: Vec<String>,
    pub last_transport_timestamp: Option<u64>,
    pub groups: Vec<StoredAccountGroup>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredAccountGroup {
    pub group_id_hex: String,
    pub endpoint: String,
    pub profile_name: String,
    pub profile_description: String,
    pub image_hash_hex: String,
    pub image_key_hex: String,
    pub image_nonce_hex: String,
    pub image_upload_key_hex: String,
    pub image_media_type: Option<String>,
    pub admin_keys_hex: String,
    pub archived: bool,
    pub pending_confirmation: bool,
    pub welcomer_account_id_hex: Option<String>,
    pub via_welcome_message_id_hex: Option<String>,
    /// The local account's membership in this group. Read-only on this struct:
    /// it is loaded from `account_groups` but owned exclusively by
    /// [`SqliteAccountStorage::set_group_self_membership`], so the projection
    /// save deliberately ignores it (a routine resave must not clobber a
    /// membership change). New rows take the schema default `Member`.
    pub self_membership: SelfMembership,
    pub components: Vec<StoredAccountGroupComponent>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredAccountGroupComponent {
    pub component_id: u16,
    pub component_name: String,
    pub component_data_hex: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StoredAppMessageQuery {
    pub group_id_hex: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredAppMessageRecord {
    pub message_id_hex: String,
    pub direction: String,
    pub group_id_hex: String,
    pub sender: String,
    pub plaintext: String,
    pub kind: u64,
    pub tags: Vec<Vec<String>>,
    pub source_epoch: Option<u64>,
    pub recorded_at: u64,
    pub received_at: u64,
    /// Local `app_events` insert order (rowid). The final, LOCAL tiebreak of the
    /// raw-event replay ordering; see [`AppEventReplayCursor`]. Never used for
    /// cross-client display order (that is the materialized-timeline surface).
    pub insert_order: i64,
}

impl StoredAppMessageRecord {
    /// The raw-event replay cursor for this row (recovery ordering only).
    pub fn replay_cursor(&self) -> AppEventReplayCursor {
        AppEventReplayCursor {
            recorded_at: self.recorded_at,
            message_id_hex: self.message_id_hex.clone(),
            insert_order: self.insert_order,
        }
    }
}

/// Column list for [`SqliteAccountStorage::app_messages`], ending in
/// `insert_order` (column index 10, read by `app_message_from_row`).
const APP_EVENT_REPLAY_COLUMNS: &str = "message_id_hex, direction, group_id_hex, sender, plaintext, \
     kind, tags_json, source_epoch, recorded_at, received_at, insert_order";

/// The ONE ascending order for the raw-event replay surface (recovery / lag
/// replay), shared by [`SqliteAccountStorage::app_messages`] and — via
/// [`AppEventReplayCursor`]'s `Ord` — the runtime recovery watermark and
/// suppression, so the query order and the watermark cut-point can never drift
/// (#630, #736 boundary contract 1). This is the RAW-EVENT surface only: it is
/// NOT the materialized-timeline `(timeline_at, message_id_hex)` display order.
pub(crate) const APP_EVENT_REPLAY_ORDER_ASC: &str = "recorded_at, message_id_hex, insert_order";
/// Descending variant of [`APP_EVENT_REPLAY_ORDER_ASC`] for the newest-first
/// `LIMIT` window that a bounded replay materializes before re-sorting ascending.
pub(crate) const APP_EVENT_REPLAY_ORDER_DESC: &str =
    "recorded_at DESC, message_id_hex DESC, insert_order DESC";

/// Total order over the RAW-EVENT replay surface: `(recorded_at, message_id_hex,
/// insert_order)`. `insert_order` is a LOCAL rowid, which is correct here because
/// this cursor is only ever a per-client recovery cut-point (the lag-recovery
/// watermark + suppression), never the cross-client user-visible timeline order.
/// The third field is load-bearing for unscoped (all-groups) recovery: the same
/// `message_id_hex` can appear in two groups (it is unique only per group — e.g.
/// a sender posting identical content to two groups in the same second), so a
/// two-field cut-point could wrongly suppress a genuinely-new same-second row.
/// This is the single canonical comparator behind #630; keep it byte-identical
/// to [`APP_EVENT_REPLAY_ORDER_ASC`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppEventReplayCursor {
    pub recorded_at: u64,
    pub message_id_hex: String,
    pub insert_order: i64,
}

impl Ord for AppEventReplayCursor {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.recorded_at
            .cmp(&other.recorded_at)
            .then_with(|| self.message_id_hex.cmp(&other.message_id_hex))
            .then_with(|| self.insert_order.cmp(&other.insert_order))
    }
}

impl PartialOrd for AppEventReplayCursor {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountNotificationSettings {
    pub account_label: String,
    pub account_id_hex: String,
    pub local_notifications_enabled: bool,
    pub native_push_enabled: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountPushRegistration {
    pub account_label: String,
    pub account_id_hex: String,
    pub platform: u8,
    pub token_fingerprint: String,
    pub server_pubkey_hex: String,
    pub relay_hint: Option<String>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub last_shared_at_ms: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountStoredPushRegistration {
    pub registration: AccountPushRegistration,
    pub token_bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountGroupPushToken {
    pub group_id_hex: String,
    pub member_id_hex: String,
    pub leaf_index: u32,
    pub platform: u8,
    pub token_fingerprint: String,
    pub server_pubkey_hex: String,
    pub relay_hint: Option<String>,
    pub encrypted_token: Vec<u8>,
    /// Owner-signed millisecond ordering stamp (high half of the primitive).
    pub owner_ts: i64,
    /// 128-hex BIP-340 signature by `member_id_hex` over the canonical record.
    pub owner_sig: String,
    /// `SHA-256(SignedRecord)` hex — the ordering tie-breaker. Stored so the
    /// engine-free storage layer can compare stamps without the crypto code.
    pub record_digest: String,
    pub updated_at_ms: i64,
}

struct RawStoredAccountGroup {
    group_id_hex: String,
    endpoint: String,
    profile_name: String,
    profile_description: String,
    image_hash_hex: String,
    image_key_hex: String,
    image_nonce_hex: String,
    image_upload_key_hex: String,
    image_media_type: Option<String>,
    admin_keys_hex: String,
    archived: bool,
    pending_confirmation: bool,
    welcomer_account_id_hex: Option<String>,
    via_welcome_message_id_hex: Option<String>,
    self_membership: SelfMembership,
}

impl SqliteAccountStorage {
    pub fn ensure_account_projection(&self, label: &str) -> StorageResult<()> {
        self.lock()?
            .execute(
                "INSERT INTO account_state (label, updated_at)
                 VALUES (?1, ?2)
                 ON CONFLICT(label) DO NOTHING",
                params![label, unix_now_seconds_i64()],
            )
            .storage()?;
        Ok(())
    }

    pub fn load_account_projection_state(
        &self,
        label: &str,
        max_seen_events: usize,
    ) -> StorageResult<StoredAccountState> {
        self.ensure_account_projection(label)?;
        let conn = self.lock()?;
        let last_transport_timestamp = conn
            .query_row(
                "SELECT last_transport_timestamp FROM account_state WHERE label = ?1",
                params![label],
                |row| row.get::<_, Option<i64>>(0),
            )
            .storage()?
            .and_then(|value| u64::try_from(value).ok());

        let mut seen_statement = conn
            .prepare(
                "SELECT event_id FROM (
                    SELECT event_id, seen_at, rowid FROM seen_events
                    ORDER BY seen_at DESC, rowid DESC
                    LIMIT ?1
                 )
                 ORDER BY seen_at, rowid",
            )
            .storage()?;
        let seen_events = seen_statement
            .query_map(params![usize_to_i64(max_seen_events)?], |row| {
                row.get::<_, String>(0)
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;

        let mut group_statement = conn
            .prepare(
                "SELECT group_id_hex, endpoint, profile_name, profile_description,
                        image_hash_hex, image_key_hex, image_nonce_hex,
                        image_upload_key_hex, image_media_type, admin_keys_hex,
                        archived, pending_confirmation, welcomer_account_id_hex,
                        via_welcome_message_id_hex, self_membership
                 FROM account_groups
                 ORDER BY updated_at, group_id_hex",
            )
            .storage()?;
        let raw_groups = group_statement
            .query_map([], |row| {
                Ok(RawStoredAccountGroup {
                    group_id_hex: row.get(0)?,
                    endpoint: row.get(1)?,
                    profile_name: row.get(2)?,
                    profile_description: row.get(3)?,
                    image_hash_hex: row.get(4)?,
                    image_key_hex: row.get(5)?,
                    image_nonce_hex: row.get(6)?,
                    image_upload_key_hex: row.get(7)?,
                    image_media_type: row.get(8)?,
                    admin_keys_hex: row.get(9)?,
                    archived: row.get::<_, i64>(10)? != 0,
                    pending_confirmation: row.get::<_, i64>(11)? != 0,
                    welcomer_account_id_hex: row.get(12)?,
                    via_welcome_message_id_hex: row.get(13)?,
                    self_membership: SelfMembership::from_storage(&row.get::<_, String>(14)?),
                })
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        drop(group_statement);

        let mut components_by_group = all_account_group_components(&conn)?;
        let mut groups = Vec::with_capacity(raw_groups.len());
        for raw in raw_groups {
            let components = components_by_group
                .remove(&raw.group_id_hex)
                .unwrap_or_default();
            groups.push(StoredAccountGroup {
                group_id_hex: raw.group_id_hex,
                endpoint: raw.endpoint,
                profile_name: raw.profile_name,
                profile_description: raw.profile_description,
                image_hash_hex: raw.image_hash_hex,
                image_key_hex: raw.image_key_hex,
                image_nonce_hex: raw.image_nonce_hex,
                image_upload_key_hex: raw.image_upload_key_hex,
                image_media_type: raw.image_media_type,
                admin_keys_hex: raw.admin_keys_hex,
                archived: raw.archived,
                pending_confirmation: raw.pending_confirmation,
                welcomer_account_id_hex: raw.welcomer_account_id_hex,
                via_welcome_message_id_hex: raw.via_welcome_message_id_hex,
                self_membership: raw.self_membership,
                components,
            });
        }

        Ok(StoredAccountState {
            label: label.to_owned(),
            seen_events,
            last_transport_timestamp,
            groups,
        })
    }

    pub fn save_account_projection_state(
        &self,
        state: &StoredAccountState,
        max_seen_events: usize,
    ) -> StorageResult<()> {
        let now = unix_now_seconds_i64();
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            conn.execute(
                "INSERT INTO account_state (label, updated_at, last_transport_timestamp)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(label) DO UPDATE SET
                    updated_at = excluded.updated_at,
                    last_transport_timestamp = excluded.last_transport_timestamp",
                params![
                    &state.label,
                    now,
                    state
                        .last_transport_timestamp
                        .and_then(|value| i64::try_from(value).ok()),
                ],
            )
            .storage()?;

            let retained_start = state.seen_events.len().saturating_sub(max_seen_events);
            for event_id in &state.seen_events[retained_start..] {
                conn.execute(
                    "INSERT INTO seen_events (event_id, seen_at)
                     VALUES (?1, ?2)
                     ON CONFLICT(event_id) DO UPDATE SET
                        seen_at = excluded.seen_at",
                    params![event_id, now],
                )
                .storage()?;
            }
            conn.execute(
                "DELETE FROM seen_events
                 WHERE event_id NOT IN (
                    SELECT event_id FROM seen_events
                    ORDER BY seen_at DESC, rowid DESC
                    LIMIT ?1
                 )",
                params![usize_to_i64(max_seen_events)?],
            )
            .storage()?;

            if state.groups.is_empty() {
                conn.execute("DELETE FROM account_groups", []).storage()?;
            } else {
                let retained_group_ids = state
                    .groups
                    .iter()
                    .map(|group| Value::Text(group.group_id_hex.clone()))
                    .collect::<Vec<_>>();
                let placeholders = (0..retained_group_ids.len())
                    .map(|_| "?")
                    .collect::<Vec<_>>()
                    .join(", ");
                conn.execute(
                    &format!("DELETE FROM account_groups WHERE group_id_hex NOT IN ({placeholders})"),
                    params_from_iter(retained_group_ids),
                )
                .storage()?;
            }

            for group in &state.groups {
                conn.execute(
                    "INSERT INTO account_groups (
                        group_id_hex, endpoint, profile_name, profile_description,
                        image_hash_hex, image_key_hex, image_nonce_hex,
                        image_upload_key_hex, image_media_type, admin_keys_hex, archived,
                        pending_confirmation, welcomer_account_id_hex, via_welcome_message_id_hex,
                        updated_at
                     )
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
                     ON CONFLICT(group_id_hex) DO UPDATE SET
                        endpoint = excluded.endpoint,
                        profile_name = excluded.profile_name,
                        profile_description = excluded.profile_description,
                        image_hash_hex = excluded.image_hash_hex,
                        image_key_hex = excluded.image_key_hex,
                        image_nonce_hex = excluded.image_nonce_hex,
                        image_upload_key_hex = excluded.image_upload_key_hex,
                        image_media_type = excluded.image_media_type,
                        admin_keys_hex = excluded.admin_keys_hex,
                        archived = excluded.archived,
                        pending_confirmation = excluded.pending_confirmation,
                        welcomer_account_id_hex = excluded.welcomer_account_id_hex,
                        via_welcome_message_id_hex = excluded.via_welcome_message_id_hex,
                        updated_at = excluded.updated_at
                     WHERE account_groups.endpoint IS NOT excluded.endpoint
                        OR account_groups.profile_name IS NOT excluded.profile_name
                        OR account_groups.profile_description IS NOT excluded.profile_description
                        OR account_groups.image_hash_hex IS NOT excluded.image_hash_hex
                        OR account_groups.image_key_hex IS NOT excluded.image_key_hex
                        OR account_groups.image_nonce_hex IS NOT excluded.image_nonce_hex
                        OR account_groups.image_upload_key_hex IS NOT excluded.image_upload_key_hex
                        OR account_groups.image_media_type IS NOT excluded.image_media_type
                        OR account_groups.admin_keys_hex IS NOT excluded.admin_keys_hex
                        OR account_groups.archived IS NOT excluded.archived
                        OR account_groups.pending_confirmation IS NOT excluded.pending_confirmation
                        OR account_groups.welcomer_account_id_hex IS NOT excluded.welcomer_account_id_hex
                        OR account_groups.via_welcome_message_id_hex IS NOT excluded.via_welcome_message_id_hex",
                    params![
                        &group.group_id_hex,
                        &group.endpoint,
                        &group.profile_name,
                        &group.profile_description,
                        &group.image_hash_hex,
                        &group.image_key_hex,
                        &group.image_nonce_hex,
                        &group.image_upload_key_hex,
                        &group.image_media_type,
                        &group.admin_keys_hex,
                        bool_i64(group.archived),
                        bool_i64(group.pending_confirmation),
                        &group.welcomer_account_id_hex,
                        &group.via_welcome_message_id_hex,
                        now
                    ],
                )
                .storage()?;

                delete_stale_group_components(&conn, &group.group_id_hex, &group.components)?;
                for component in &group.components {
                    upsert_group_component(&conn, &group.group_id_hex, component, now)?;
                }
            }
            Ok(())
        })
    }

    /// Transactionally removes all app-local data for one group without touching
    /// the stored MLS/OpenMLS group state. This is the storage primitive for the
    /// local delete/wipe UX: it drops the chat-list/account projection, plaintext
    /// app events, timeline rows, agent-stream start projection rows, cached
    /// encrypted-media epoch secrets, and group push-token rows keyed by
    /// `group_id_hex`. `seen_events` and protocol/MLS tables are intentionally
    /// left intact so old relay deliveries stay suppressed while a future fresh
    /// group message can re-create the app projection.
    pub fn delete_local_group_data(&self, group_id_hex: &str) -> StorageResult<bool> {
        if group_id_hex.trim().is_empty() {
            return Err(StorageError::Backend(
                "local group delete id must not be empty".to_owned(),
            ));
        }

        self.connection.with_transaction(|| -> StorageResult<bool> {
            let conn = self.lock()?;
            let mut deleted = 0usize;
            for table in [
                "app_events",
                "message_timeline",
                "agent_stream_starts",
                "conversation_read_state",
                "chat_list_rows",
                "account_group_app_components",
                "group_push_tokens",
                "group_push_token_tombstones",
                "encrypted_media_epoch_secrets",
                "account_groups",
            ] {
                deleted = deleted.saturating_add(
                    conn.execute(
                        &format!("DELETE FROM {table} WHERE group_id_hex = ?1"),
                        params![group_id_hex],
                    )
                    .storage()?,
                );
            }
            Ok(deleted > 0)
        })
    }

    /// Record the local account's own membership in `group_id_hex` so the
    /// chat list and removed-group-suppressed unread aggregate reflect whether
    /// the account is still in the group and, if not, how it left. `Left` and
    /// `Removed` both suppress the group's unread; `Member` re-affirms it
    /// (preserve / un-suppress on re-add). No-op when the group has no
    /// `account_groups` row yet, so this never resurrects pruned projection
    /// state.
    pub fn set_group_self_membership(
        &self,
        group_id_hex: &str,
        membership: SelfMembership,
    ) -> StorageResult<()> {
        self.lock()?
            .execute(
                "UPDATE account_groups
                 SET self_membership = ?2
                 WHERE group_id_hex = ?1",
                params![group_id_hex, membership.as_str()],
            )
            .storage()?;
        Ok(())
    }

    /// `group_id_hex` of every `account_groups` row whose `self_membership` is
    /// still the migration default `'member'`. Used by the one-time
    /// open/upgrade backfill to decide which legacy rows need their membership
    /// derived from current engine state — rows already explicitly flipped to
    /// `'removed'` (or re-affirmed `'member'` by a live event) are skipped, so
    /// the backfill stays idempotent and the hot path keeps reading the
    /// projection only.
    pub fn account_group_ids_defaulting_to_member(&self) -> StorageResult<Vec<String>> {
        let conn = self.lock()?;
        let mut statement = conn
            .prepare(
                "SELECT group_id_hex
                 FROM account_groups
                 WHERE self_membership = 'member'
                 ORDER BY group_id_hex",
            )
            .storage()?;
        let ids = statement
            .query_map([], |row| row.get::<_, String>(0))
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        Ok(ids)
    }

    pub fn app_messages(
        &self,
        query: StoredAppMessageQuery,
    ) -> StorageResult<Vec<StoredAppMessageRecord>> {
        // Single-source the column list + replay ordering so the query order and
        // the runtime recovery watermark/suppression (via `AppEventReplayCursor`)
        // cannot drift (#630, #736). The limited variants take the newest-first
        // `LIMIT` window, then re-sort ascending into replay order.
        let cols = APP_EVENT_REPLAY_COLUMNS;
        let asc = APP_EVENT_REPLAY_ORDER_ASC;
        let desc = APP_EVENT_REPLAY_ORDER_DESC;
        let sql = match (&query.group_id_hex, query.limit) {
            (Some(_), Some(_)) => format!(
                "SELECT {cols} FROM (
                    SELECT {cols} FROM app_events
                    WHERE group_id_hex = ?1
                    ORDER BY {desc} LIMIT ?2
                 ) ORDER BY {asc}"
            ),
            (Some(_), None) => {
                format!("SELECT {cols} FROM app_events WHERE group_id_hex = ?1 ORDER BY {asc}")
            }
            (None, Some(_)) => format!(
                "SELECT {cols} FROM (
                    SELECT {cols} FROM app_events
                    ORDER BY {desc} LIMIT ?1
                 ) ORDER BY {asc}"
            ),
            (None, None) => format!("SELECT {cols} FROM app_events ORDER BY {asc}"),
        };
        let conn = self.lock()?;
        let mut statement = conn.prepare(&sql).storage()?;
        let rows = match (&query.group_id_hex, query.limit) {
            (Some(group_id_hex), Some(limit)) => statement
                .query_map(
                    params![group_id_hex, usize_to_i64(limit)?],
                    app_message_from_row,
                )
                .storage()?,
            (Some(group_id_hex), None) => statement
                .query_map(params![group_id_hex], app_message_from_row)
                .storage()?,
            (None, Some(limit)) => statement
                .query_map(params![usize_to_i64(limit)?], app_message_from_row)
                .storage()?,
            (None, None) => statement.query_map([], app_message_from_row).storage()?,
        };
        rows.collect::<Result<Vec<_>, _>>().storage()
    }

    pub fn app_message_count(&self) -> StorageResult<usize> {
        let count = self
            .lock()?
            .query_row("SELECT count(*) FROM app_events", [], |row| {
                row.get::<_, i64>(0)
            })
            .storage()?;
        Ok(count.try_into().unwrap_or_default())
    }

    pub fn prune_app_events_before(
        &self,
        group_id_hex: &str,
        cutoff_recorded_at: u64,
    ) -> StorageResult<usize> {
        self.secure_prune_app_events_before(group_id_hex, cutoff_recorded_at)
            .map(|outcome| outcome.pruned_messages)
    }

    pub fn secure_prune_app_events_before(
        &self,
        group_id_hex: &str,
        cutoff_recorded_at: u64,
    ) -> StorageResult<crate::timeline::SecurePruneAppEventsResult> {
        let outcome = self.connection.with_transaction(|| {
            let conn = self.lock()?;
            crate::timeline::secure_prune_app_events_before_tx(
                &conn,
                group_id_hex,
                cutoff_recorded_at,
            )
        })?;
        if outcome.pruned_messages > 0 {
            let conn = self.lock()?;
            if let Err(error) = checkpoint_wal_truncate_after_secure_prune(&conn) {
                tracing::warn!(
                    target: "storage_sqlite::retention",
                    method = "secure_prune_app_events_before",
                    pruned_messages = outcome.pruned_messages,
                    error = %error,
                    "retention secure-delete WAL checkpoint failed after committed prune"
                );
            }
        }
        Ok(outcome)
    }

    pub fn account_import_marker(&self, name: &str) -> StorageResult<bool> {
        let exists = self
            .lock()?
            .query_row(
                "SELECT 1 FROM account_import_markers WHERE name = ?1",
                params![name],
                |_| Ok(()),
            )
            .optional()
            .storage()?
            .is_some();
        Ok(exists)
    }

    pub fn mark_account_import_complete(&self, name: &str) -> StorageResult<()> {
        self.lock()?
            .execute(
                "INSERT INTO account_import_markers (name, completed_at_unix_seconds)
                 VALUES (?1, ?2)
                 ON CONFLICT(name) DO UPDATE SET
                    completed_at_unix_seconds = excluded.completed_at_unix_seconds",
                params![name, unix_now_seconds_i64()],
            )
            .storage()?;
        Ok(())
    }

    pub fn notification_settings(
        &self,
        account_label: &str,
        account_id_hex: &str,
    ) -> StorageResult<AccountNotificationSettings> {
        self.ensure_notification_settings(account_label, account_id_hex)?;
        self.lock()?
            .query_row(
                "SELECT account_label, account_id_hex, local_notifications_enabled,
                        native_push_enabled
                 FROM notification_settings
                 WHERE account_label = ?1",
                params![account_label],
                |row| {
                    Ok(AccountNotificationSettings {
                        account_label: row.get(0)?,
                        account_id_hex: row.get(1)?,
                        local_notifications_enabled: row.get::<_, i64>(2)? != 0,
                        native_push_enabled: row.get::<_, i64>(3)? != 0,
                    })
                },
            )
            .storage()
    }

    pub fn set_local_notifications_enabled(
        &self,
        account_label: &str,
        account_id_hex: &str,
        enabled: bool,
    ) -> StorageResult<AccountNotificationSettings> {
        self.ensure_notification_settings(account_label, account_id_hex)?;
        self.lock()?
            .execute(
                "UPDATE notification_settings
                 SET local_notifications_enabled = ?2, updated_at_ms = ?3
                 WHERE account_label = ?1",
                params![account_label, bool_i64(enabled), unix_now_ms()],
            )
            .storage()?;
        self.notification_settings(account_label, account_id_hex)
    }

    pub fn set_native_push_enabled(
        &self,
        account_label: &str,
        account_id_hex: &str,
        enabled: bool,
    ) -> StorageResult<AccountNotificationSettings> {
        self.ensure_notification_settings(account_label, account_id_hex)?;
        self.lock()?
            .execute(
                "UPDATE notification_settings
                 SET native_push_enabled = ?2, updated_at_ms = ?3
                 WHERE account_label = ?1",
                params![account_label, bool_i64(enabled), unix_now_ms()],
            )
            .storage()?;
        self.notification_settings(account_label, account_id_hex)
    }

    pub fn push_registration(
        &self,
        account_label: &str,
    ) -> StorageResult<Option<AccountStoredPushRegistration>> {
        let conn = self.lock()?;
        let mut statement = conn
            .prepare(
                "SELECT account_label, account_id_hex, platform, token_fingerprint,
                        token_bytes, server_pubkey_hex, relay_hint, created_at_ms,
                        updated_at_ms, last_shared_at_ms
                 FROM push_registration
                 WHERE account_label = ?1",
            )
            .storage()?;
        statement
            .query_row(params![account_label], stored_push_registration_from_row)
            .optional()
            .storage()
    }

    pub fn upsert_push_registration(
        &self,
        registration: AccountPushRegistration,
        token_bytes: Vec<u8>,
    ) -> StorageResult<AccountStoredPushRegistration> {
        let existing = self.push_registration(&registration.account_label)?;
        let created_at_ms = existing
            .as_ref()
            .map(|existing| existing.registration.created_at_ms)
            .unwrap_or(registration.created_at_ms);
        let last_shared_at_ms = existing
            .as_ref()
            .filter(|existing| {
                existing.registration.token_fingerprint == registration.token_fingerprint
                    && existing.registration.server_pubkey_hex == registration.server_pubkey_hex
                    && existing.registration.platform == registration.platform
            })
            .and_then(|existing| existing.registration.last_shared_at_ms);
        self.lock()?
            .execute(
                "INSERT INTO push_registration (
                    account_label, account_id_hex, platform, token_fingerprint,
                    token_bytes, server_pubkey_hex, relay_hint, created_at_ms,
                    updated_at_ms, last_shared_at_ms
                 )
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                 ON CONFLICT(account_label) DO UPDATE SET
                    account_id_hex = excluded.account_id_hex,
                    platform = excluded.platform,
                    token_fingerprint = excluded.token_fingerprint,
                    token_bytes = excluded.token_bytes,
                    server_pubkey_hex = excluded.server_pubkey_hex,
                    relay_hint = excluded.relay_hint,
                    updated_at_ms = excluded.updated_at_ms,
                    last_shared_at_ms = excluded.last_shared_at_ms",
                params![
                    &registration.account_label,
                    &registration.account_id_hex,
                    i64::from(registration.platform),
                    &registration.token_fingerprint,
                    token_bytes,
                    &registration.server_pubkey_hex,
                    &registration.relay_hint,
                    created_at_ms,
                    registration.updated_at_ms,
                    last_shared_at_ms,
                ],
            )
            .storage()?;
        self.push_registration(&registration.account_label)?
            .ok_or_else(|| StorageError::Backend("push registration was not stored".to_owned()))
    }

    pub fn mark_push_registration_shared(
        &self,
        account_label: &str,
        shared_at_ms: i64,
    ) -> StorageResult<()> {
        self.lock()?
            .execute(
                "UPDATE push_registration
                 SET last_shared_at_ms = ?2, updated_at_ms = ?2
                 WHERE account_label = ?1",
                params![account_label, shared_at_ms],
            )
            .storage()?;
        Ok(())
    }

    pub fn clear_push_registration(
        &self,
        account_label: &str,
    ) -> StorageResult<Option<AccountStoredPushRegistration>> {
        let existing = self.push_registration(account_label)?;
        self.lock()?
            .execute(
                "DELETE FROM push_registration WHERE account_label = ?1",
                params![account_label],
            )
            .storage()?;
        Ok(existing)
    }

    /// Unconditional upsert keyed on `(group, member, leaf, platform, server)`.
    /// Used for the local account's own self-update (always its newest token) and
    /// legacy import. Inbound gossip from other members goes through
    /// [`Self::apply_group_push_token`], which enforces the ordering primitive and
    /// tombstones.
    pub fn upsert_group_push_token(&self, token: &AccountGroupPushToken) -> StorageResult<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO group_push_tokens (
                    group_id_hex, member_id_hex, leaf_index, platform, token_fingerprint,
                    server_pubkey_hex, relay_hint, encrypted_token, owner_ts, owner_sig,
                    record_digest, updated_at_ms
                 )
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
                 ON CONFLICT(group_id_hex, member_id_hex, leaf_index, platform, server_pubkey_hex)
                 DO UPDATE SET
                    token_fingerprint = excluded.token_fingerprint,
                    relay_hint = excluded.relay_hint,
                    encrypted_token = excluded.encrypted_token,
                    owner_ts = excluded.owner_ts,
                    owner_sig = excluded.owner_sig,
                    record_digest = excluded.record_digest,
                    updated_at_ms = excluded.updated_at_ms",
            params![
                &token.group_id_hex,
                &token.member_id_hex,
                u32_to_i64(token.leaf_index),
                i64::from(token.platform),
                &token.token_fingerprint,
                &token.server_pubkey_hex,
                &token.relay_hint,
                &token.encrypted_token,
                token.owner_ts,
                &token.owner_sig,
                &token.record_digest,
                token.updated_at_ms,
            ],
        )
        .storage()?;
        Ok(())
    }

    /// Apply an owner-verified inbound token record under the spec's ordering
    /// primitive: store it only when its `(owner_ts, record_digest)` stamp is
    /// strictly greater than both the existing live record and any tombstone for
    /// the same record key, and clear the tombstone when it does. Returns whether
    /// the record was applied. Callers verify `owner_sig` and group membership
    /// before calling.
    pub fn apply_group_push_token(&self, token: &AccountGroupPushToken) -> StorageResult<bool> {
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
        let incoming = (token.owner_ts, token.record_digest.as_str());
        let key = PushTokenKey {
            group_id_hex: &token.group_id_hex,
            member_id_hex: &token.member_id_hex,
            leaf_index: token.leaf_index,
            platform: token.platform,
            server_pubkey_hex: &token.server_pubkey_hex,
        };
        let tombstone = read_push_tombstone_stamp(&tx, key)?;
        let live = read_push_token_stamp(&tx, key)?;
        let strictly_newer = |stored: &Option<(i64, String)>| {
            push_stamp_strictly_newer(incoming, stored.as_ref().map(|(t, d)| (*t, d.as_str())))
        };
        if !strictly_newer(&tombstone) || !strictly_newer(&live) {
            return Ok(false);
        }
        tx.execute(
            "INSERT INTO group_push_tokens (
                    group_id_hex, member_id_hex, leaf_index, platform, token_fingerprint,
                    server_pubkey_hex, relay_hint, encrypted_token, owner_ts, owner_sig,
                    record_digest, updated_at_ms
                 )
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
                 ON CONFLICT(group_id_hex, member_id_hex, leaf_index, platform, server_pubkey_hex)
                 DO UPDATE SET
                    token_fingerprint = excluded.token_fingerprint,
                    relay_hint = excluded.relay_hint,
                    encrypted_token = excluded.encrypted_token,
                    owner_ts = excluded.owner_ts,
                    owner_sig = excluded.owner_sig,
                    record_digest = excluded.record_digest,
                    updated_at_ms = excluded.updated_at_ms",
            params![
                &token.group_id_hex,
                &token.member_id_hex,
                u32_to_i64(token.leaf_index),
                i64::from(token.platform),
                &token.token_fingerprint,
                &token.server_pubkey_hex,
                &token.relay_hint,
                &token.encrypted_token,
                token.owner_ts,
                &token.owner_sig,
                &token.record_digest,
                token.updated_at_ms,
            ],
        )
        .storage()?;
        delete_push_tombstone(&tx, key)?;
        tx.commit().storage()?;
        Ok(true)
    }

    /// Apply an owner-verified removal: when its `(owner_ts, record_digest)` stamp
    /// is strictly greater than both the live record and any existing tombstone
    /// for the key, delete the live record and write/refresh the durable
    /// tombstone. Returns whether the removal was applied.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_group_push_token_tombstone(
        &self,
        group_id_hex: &str,
        member_id_hex: &str,
        leaf_index: u32,
        platform: u8,
        server_pubkey_hex: &str,
        owner_ts: i64,
        record_digest: &str,
        created_at_ms: i64,
    ) -> StorageResult<bool> {
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
        let incoming = (owner_ts, record_digest);
        let key = PushTokenKey {
            group_id_hex,
            member_id_hex,
            leaf_index,
            platform,
            server_pubkey_hex,
        };
        let tombstone = read_push_tombstone_stamp(&tx, key)?;
        let live = read_push_token_stamp(&tx, key)?;
        let strictly_newer = |stored: &Option<(i64, String)>| {
            push_stamp_strictly_newer(incoming, stored.as_ref().map(|(t, d)| (*t, d.as_str())))
        };
        if !strictly_newer(&tombstone) || !strictly_newer(&live) {
            return Ok(false);
        }
        delete_push_token(&tx, key)?;
        tx.execute(
            "INSERT INTO group_push_token_tombstones (
                    group_id_hex, member_id_hex, leaf_index, platform, server_pubkey_hex,
                    owner_ts, record_digest, created_at_ms
                 )
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(group_id_hex, member_id_hex, leaf_index, platform, server_pubkey_hex)
                 DO UPDATE SET
                    owner_ts = excluded.owner_ts,
                    record_digest = excluded.record_digest,
                    created_at_ms = excluded.created_at_ms",
            params![
                group_id_hex,
                member_id_hex,
                u32_to_i64(leaf_index),
                i64::from(platform),
                server_pubkey_hex,
                owner_ts,
                record_digest,
                created_at_ms,
            ],
        )
        .storage()?;
        tx.commit().storage()?;
        Ok(true)
    }

    pub fn group_push_tokens(
        &self,
        group_id_hex: &str,
    ) -> StorageResult<Vec<AccountGroupPushToken>> {
        let conn = self.lock()?;
        let mut statement = conn
            .prepare(
                "SELECT group_id_hex, member_id_hex, leaf_index, platform,
                        token_fingerprint, server_pubkey_hex, relay_hint,
                        encrypted_token, owner_ts, owner_sig, record_digest, updated_at_ms
                 FROM group_push_tokens
                 WHERE group_id_hex = ?1
                 ORDER BY member_id_hex, leaf_index, platform, server_pubkey_hex",
            )
            .storage()?;
        statement
            .query_map(params![group_id_hex], group_push_token_from_row)
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()
    }

    pub fn remove_group_push_token(
        &self,
        group_id_hex: &str,
        member_id_hex: &str,
        platform: u8,
        token_fingerprint: &str,
        server_pubkey_hex: &str,
    ) -> StorageResult<()> {
        self.lock()?
            .execute(
                "DELETE FROM group_push_tokens
                 WHERE group_id_hex = ?1
                   AND member_id_hex = ?2
                   AND platform = ?3
                   AND token_fingerprint = ?4
                   AND server_pubkey_hex = ?5",
                params![
                    group_id_hex,
                    member_id_hex,
                    i64::from(platform),
                    token_fingerprint,
                    server_pubkey_hex,
                ],
            )
            .storage()?;
        Ok(())
    }

    /// Local cleanup when a member leaves the group: drop every live record and
    /// every tombstone for that member, per the spec's member-cleanup rule. The
    /// member is gone, so no relayed record for them can ever verify against
    /// current membership again, which is why the durable tombstones are safe to
    /// clear here (and only here).
    pub fn remove_group_push_tokens_for_member(
        &self,
        group_id_hex: &str,
        member_id_hex: &str,
    ) -> StorageResult<()> {
        self.connection.with_transaction(|| -> StorageResult<()> {
            let conn = self.lock()?;
            conn.execute(
                "DELETE FROM group_push_tokens
                 WHERE group_id_hex = ?1 AND member_id_hex = ?2",
                params![group_id_hex, member_id_hex],
            )
            .storage()?;
            conn.execute(
                "DELETE FROM group_push_token_tombstones
                 WHERE group_id_hex = ?1 AND member_id_hex = ?2",
                params![group_id_hex, member_id_hex],
            )
            .storage()?;
            Ok(())
        })
    }

    pub fn remove_stale_group_push_tokens(
        &self,
        group_id_hex: &str,
        active_members: &[String],
    ) -> StorageResult<usize> {
        self.connection
            .with_transaction(|| -> StorageResult<usize> {
                let conn = self.lock()?;
                if active_members.is_empty() {
                    conn.execute(
                        "DELETE FROM group_push_token_tombstones WHERE group_id_hex = ?1",
                        params![group_id_hex],
                    )
                    .storage()?;
                    return conn
                        .execute(
                            "DELETE FROM group_push_tokens WHERE group_id_hex = ?1",
                            params![group_id_hex],
                        )
                        .storage();
                }
                let placeholders = std::iter::repeat_n("?", active_members.len())
                    .collect::<Vec<_>>()
                    .join(",");
                let mut values = Vec::with_capacity(active_members.len() + 1);
                values.push(Value::Text(group_id_hex.to_owned()));
                values.extend(active_members.iter().cloned().map(Value::Text));
                // Clear tombstones for departed members too: once a member is gone, no
                // relayed record for them can verify against current membership, so their
                // tombstones are no longer load-bearing.
                conn.execute(
                    &format!(
                        "DELETE FROM group_push_token_tombstones
                 WHERE group_id_hex = ?
                   AND member_id_hex NOT IN ({placeholders})"
                    ),
                    params_from_iter(values.iter()),
                )
                .storage()?;
                conn.execute(
                    &format!(
                        "DELETE FROM group_push_tokens
                 WHERE group_id_hex = ?
                   AND member_id_hex NOT IN ({placeholders})"
                    ),
                    params_from_iter(values.iter()),
                )
                .storage()
            })
    }

    fn ensure_notification_settings(
        &self,
        account_label: &str,
        account_id_hex: &str,
    ) -> StorageResult<()> {
        self.lock()?
            .execute(
                "INSERT INTO notification_settings (
                    account_label, account_id_hex, local_notifications_enabled,
                    native_push_enabled, updated_at_ms
                 )
                 VALUES (?1, ?2, 1, 0, ?3)
                 ON CONFLICT(account_label) DO UPDATE SET
                    account_id_hex = excluded.account_id_hex",
                params![account_label, account_id_hex, unix_now_ms()],
            )
            .storage()?;
        Ok(())
    }
}

fn checkpoint_wal_truncate_after_secure_prune(conn: &Connection) -> StorageResult<()> {
    retry_on_busy(|| {
        let (busy, _log_frames, _checkpointed_frames): (i64, i64, i64) = conn
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .storage()?;
        if busy == 0 {
            Ok(())
        } else {
            Err(StorageError::Busy(
                "retention secure-delete WAL checkpoint could not truncate while readers are active"
                    .to_owned(),
            ))
        }
    })
}

/// #762: load ALL account-group components in one ordered query, bucketed by
/// group in Rust, instead of an N+1 per-group query during full-projection load.
/// Ordered by `(group_id_hex, component_id)` so each group's components keep
/// `component_id` order (matching the prior per-group `ORDER BY component_id`).
fn all_account_group_components(
    conn: &rusqlite::Connection,
) -> StorageResult<std::collections::HashMap<String, Vec<StoredAccountGroupComponent>>> {
    let mut statement = conn
        .prepare(
            "SELECT group_id_hex, component_id, component_name, component_data_hex
             FROM account_group_app_components
             ORDER BY group_id_hex, component_id",
        )
        .storage()?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                StoredAccountGroupComponent {
                    component_id: i64_to_u16(row.get(1)?, 1)?,
                    component_name: row.get(2)?,
                    component_data_hex: row.get(3)?,
                },
            ))
        })
        .storage()?;
    let mut by_group: std::collections::HashMap<String, Vec<StoredAccountGroupComponent>> =
        std::collections::HashMap::new();
    for row in rows {
        let (group_id_hex, component) = row.storage()?;
        by_group.entry(group_id_hex).or_default().push(component);
    }
    Ok(by_group)
}

fn delete_stale_group_components(
    tx: &Connection,
    group_id_hex: &str,
    components: &[StoredAccountGroupComponent],
) -> StorageResult<()> {
    if components.is_empty() {
        tx.execute(
            "DELETE FROM account_group_app_components WHERE group_id_hex = ?1",
            params![group_id_hex],
        )
        .storage()?;
        return Ok(());
    }
    let placeholders = std::iter::repeat_n("?", components.len())
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!(
        "DELETE FROM account_group_app_components
         WHERE group_id_hex = ?
           AND component_id NOT IN ({placeholders})"
    );
    let mut values = Vec::with_capacity(components.len() + 1);
    values.push(Value::Text(group_id_hex.to_owned()));
    for component in components {
        values.push(Value::Integer(i64::from(component.component_id)));
    }
    tx.execute(&sql, params_from_iter(values.iter()))
        .storage()?;
    Ok(())
}

fn upsert_group_component(
    tx: &Connection,
    group_id_hex: &str,
    component: &StoredAccountGroupComponent,
    now: i64,
) -> StorageResult<()> {
    tx.execute(
        "INSERT INTO account_group_app_components (
            group_id_hex, component_id, component_name, component_data_hex, updated_at
         )
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(group_id_hex, component_id) DO UPDATE SET
            component_name = excluded.component_name,
            component_data_hex = excluded.component_data_hex,
            updated_at = excluded.updated_at
         WHERE account_group_app_components.component_name IS NOT excluded.component_name
            OR account_group_app_components.component_data_hex IS NOT excluded.component_data_hex",
        params![
            group_id_hex,
            i64::from(component.component_id),
            &component.component_name,
            &component.component_data_hex,
            now
        ],
    )
    .storage()?;
    Ok(())
}

fn app_message_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredAppMessageRecord> {
    Ok(StoredAppMessageRecord {
        message_id_hex: row.get(0)?,
        direction: row.get(1)?,
        group_id_hex: row.get(2)?,
        sender: row.get(3)?,
        plaintext: row.get(4)?,
        kind: row.get::<_, i64>(5)?.try_into().unwrap_or_default(),
        tags: tags_from_json(row.get::<_, String>(6)?).map_err(|err| {
            rusqlite::Error::FromSqlConversionFailure(6, Type::Text, Box::new(err))
        })?,
        source_epoch: row
            .get::<_, Option<i64>>(7)?
            .and_then(|value| value.try_into().ok()),
        recorded_at: row.get::<_, i64>(8)?.try_into().unwrap_or_default(),
        received_at: row.get::<_, i64>(9)?.try_into().unwrap_or_default(),
        insert_order: row.get::<_, i64>(10)?,
    })
}

fn stored_push_registration_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<AccountStoredPushRegistration> {
    Ok(AccountStoredPushRegistration {
        registration: AccountPushRegistration {
            account_label: row.get(0)?,
            account_id_hex: row.get(1)?,
            platform: i64_to_u8(row.get(2)?, 2)?,
            token_fingerprint: row.get(3)?,
            server_pubkey_hex: row.get(5)?,
            relay_hint: row.get(6)?,
            created_at_ms: row.get(7)?,
            updated_at_ms: row.get(8)?,
            last_shared_at_ms: row.get(9)?,
        },
        token_bytes: row.get(4)?,
    })
}

fn group_push_token_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AccountGroupPushToken> {
    Ok(AccountGroupPushToken {
        group_id_hex: row.get(0)?,
        member_id_hex: row.get(1)?,
        leaf_index: i64_to_u32(row.get(2)?, 2)?,
        platform: i64_to_u8(row.get(3)?, 3)?,
        token_fingerprint: row.get(4)?,
        server_pubkey_hex: row.get(5)?,
        relay_hint: row.get(6)?,
        encrypted_token: row.get(7)?,
        owner_ts: row.get(8)?,
        owner_sig: row.get(9)?,
        record_digest: row.get(10)?,
        updated_at_ms: row.get(11)?,
    })
}

/// Identifies one push record key `(group, member, leaf, platform, server)`,
/// shared by the live `group_push_tokens` table and the tombstone table.
#[derive(Clone, Copy)]
struct PushTokenKey<'a> {
    group_id_hex: &'a str,
    member_id_hex: &'a str,
    leaf_index: u32,
    platform: u8,
    server_pubkey_hex: &'a str,
}

/// True when `incoming` is strictly greater than `stored` under the
/// `(owner_ts, record_digest)` ordering primitive (and always when there is no
/// stored stamp).
fn push_stamp_strictly_newer(incoming: (i64, &str), stored: Option<(i64, &str)>) -> bool {
    match stored {
        None => true,
        Some((ts, digest)) => incoming.0 > ts || (incoming.0 == ts && incoming.1 > digest),
    }
}

fn read_push_token_stamp(
    tx: &rusqlite::Transaction<'_>,
    key: PushTokenKey<'_>,
) -> StorageResult<Option<(i64, String)>> {
    tx.query_row(
        "SELECT owner_ts, record_digest FROM group_push_tokens
         WHERE group_id_hex = ?1 AND member_id_hex = ?2 AND leaf_index = ?3
           AND platform = ?4 AND server_pubkey_hex = ?5",
        params![
            key.group_id_hex,
            key.member_id_hex,
            u32_to_i64(key.leaf_index),
            i64::from(key.platform),
            key.server_pubkey_hex,
        ],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .optional()
    .storage()
}

fn read_push_tombstone_stamp(
    tx: &rusqlite::Transaction<'_>,
    key: PushTokenKey<'_>,
) -> StorageResult<Option<(i64, String)>> {
    tx.query_row(
        "SELECT owner_ts, record_digest FROM group_push_token_tombstones
         WHERE group_id_hex = ?1 AND member_id_hex = ?2 AND leaf_index = ?3
           AND platform = ?4 AND server_pubkey_hex = ?5",
        params![
            key.group_id_hex,
            key.member_id_hex,
            u32_to_i64(key.leaf_index),
            i64::from(key.platform),
            key.server_pubkey_hex,
        ],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .optional()
    .storage()
}

fn delete_push_token(tx: &rusqlite::Transaction<'_>, key: PushTokenKey<'_>) -> StorageResult<()> {
    tx.execute(
        "DELETE FROM group_push_tokens
         WHERE group_id_hex = ?1 AND member_id_hex = ?2 AND leaf_index = ?3
           AND platform = ?4 AND server_pubkey_hex = ?5",
        params![
            key.group_id_hex,
            key.member_id_hex,
            u32_to_i64(key.leaf_index),
            i64::from(key.platform),
            key.server_pubkey_hex,
        ],
    )
    .storage()?;
    Ok(())
}

fn delete_push_tombstone(
    tx: &rusqlite::Transaction<'_>,
    key: PushTokenKey<'_>,
) -> StorageResult<()> {
    tx.execute(
        "DELETE FROM group_push_token_tombstones
         WHERE group_id_hex = ?1 AND member_id_hex = ?2 AND leaf_index = ?3
           AND platform = ?4 AND server_pubkey_hex = ?5",
        params![
            key.group_id_hex,
            key.member_id_hex,
            u32_to_i64(key.leaf_index),
            i64::from(key.platform),
            key.server_pubkey_hex,
        ],
    )
    .storage()?;
    Ok(())
}

fn u32_to_i64(value: u32) -> i64 {
    i64::from(value)
}

fn i64_to_u8(value: i64, column: usize) -> rusqlite::Result<u8> {
    u8::try_from(value).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(column, Type::Integer, Box::new(err))
    })
}

fn i64_to_u16(value: i64, column: usize) -> rusqlite::Result<u16> {
    u16::try_from(value).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(column, Type::Integer, Box::new(err))
    })
}

fn i64_to_u32(value: i64, column: usize) -> rusqlite::Result<u32> {
    u32::try_from(value).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(column, Type::Integer, Box::new(err))
    })
}

#[cfg(test)]
mod tests;
