use crate::{
    SqliteAccountStorage, SqliteResultExt, bool_i64, connection::retry_on_busy, tags_from_json,
    unix_now_ms, unix_now_seconds_i64, usize_to_i64,
};
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{
    Connection, OptionalExtension, params, params_from_iter,
    types::{Type, Value},
};

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
                        via_welcome_message_id_hex
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
                })
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        drop(group_statement);

        let mut groups = Vec::with_capacity(raw_groups.len());
        for raw in raw_groups {
            let components = account_group_components(&conn, &raw.group_id_hex)?;
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
                    "INSERT OR IGNORE INTO seen_events (event_id, seen_at)
                     VALUES (?1, ?2)",
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
    /// removed-group-suppressed unread aggregate can exclude groups the account
    /// has left or been removed from. `removed = true` marks the group
    /// `'removed'` (suppress its unread); `removed = false` re-affirms `'member'`
    /// (preserve / un-suppress on re-add). No-op when the group has no
    /// `account_groups` row yet, so this never resurrects pruned projection
    /// state.
    pub fn set_group_self_membership(
        &self,
        group_id_hex: &str,
        removed: bool,
    ) -> StorageResult<()> {
        let self_membership = if removed { "removed" } else { "member" };
        self.lock()?
            .execute(
                "UPDATE account_groups
                 SET self_membership = ?2
                 WHERE group_id_hex = ?1",
                params![group_id_hex, self_membership],
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
        let sql = match (&query.group_id_hex, query.limit) {
            (Some(_), Some(_)) => {
                "SELECT message_id_hex, direction, group_id_hex, sender, plaintext,
                        kind, tags_json, source_epoch, recorded_at, received_at
                 FROM (
                    SELECT insert_order, message_id_hex, direction, group_id_hex, sender,
                           plaintext, kind, tags_json, source_epoch, recorded_at, received_at
                    FROM app_events
                    WHERE group_id_hex = ?1
                    ORDER BY recorded_at DESC, message_id_hex DESC, insert_order DESC
                    LIMIT ?2
                 )
                 ORDER BY recorded_at, message_id_hex, insert_order"
            }
            (Some(_), None) => {
                "SELECT message_id_hex, direction, group_id_hex, sender, plaintext,
                        kind, tags_json, source_epoch, recorded_at, received_at
                 FROM app_events
                 WHERE group_id_hex = ?1
                 ORDER BY recorded_at, message_id_hex, insert_order"
            }
            (None, Some(_)) => {
                "SELECT message_id_hex, direction, group_id_hex, sender, plaintext,
                        kind, tags_json, source_epoch, recorded_at, received_at
                 FROM (
                    SELECT insert_order, message_id_hex, direction, group_id_hex, sender,
                           plaintext, kind, tags_json, source_epoch, recorded_at, received_at
                    FROM app_events
                    ORDER BY recorded_at DESC, message_id_hex DESC, insert_order DESC
                    LIMIT ?1
                 )
                 ORDER BY recorded_at, message_id_hex, insert_order"
            }
            (None, None) => {
                "SELECT message_id_hex, direction, group_id_hex, sender, plaintext,
                        kind, tags_json, source_epoch, recorded_at, received_at
                 FROM app_events
                 ORDER BY recorded_at, message_id_hex, insert_order"
            }
        };
        let conn = self.lock()?;
        let mut statement = conn.prepare(sql).storage()?;
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

    pub fn upsert_group_push_token(&self, token: &AccountGroupPushToken) -> StorageResult<()> {
        self.lock()?
            .execute(
                "INSERT INTO group_push_tokens (
                    group_id_hex, member_id_hex, leaf_index, platform, token_fingerprint,
                    server_pubkey_hex, relay_hint, encrypted_token, updated_at_ms
                 )
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT(group_id_hex, member_id_hex, platform, server_pubkey_hex)
                 DO UPDATE SET
                    leaf_index = excluded.leaf_index,
                    token_fingerprint = excluded.token_fingerprint,
                    relay_hint = excluded.relay_hint,
                    encrypted_token = excluded.encrypted_token,
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
                    token.updated_at_ms,
                ],
            )
            .storage()?;
        Ok(())
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
                        encrypted_token, updated_at_ms
                 FROM group_push_tokens
                 WHERE group_id_hex = ?1
                 ORDER BY member_id_hex, platform, server_pubkey_hex",
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

    pub fn remove_group_push_tokens_for_member(
        &self,
        group_id_hex: &str,
        member_id_hex: &str,
    ) -> StorageResult<()> {
        self.lock()?
            .execute(
                "DELETE FROM group_push_tokens
                 WHERE group_id_hex = ?1 AND member_id_hex = ?2",
                params![group_id_hex, member_id_hex],
            )
            .storage()?;
        Ok(())
    }

    pub fn remove_stale_group_push_tokens(
        &self,
        group_id_hex: &str,
        active_members: &[String],
    ) -> StorageResult<usize> {
        if active_members.is_empty() {
            return self
                .lock()?
                .execute(
                    "DELETE FROM group_push_tokens WHERE group_id_hex = ?1",
                    params![group_id_hex],
                )
                .storage();
        }
        let placeholders = std::iter::repeat_n("?", active_members.len())
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "DELETE FROM group_push_tokens
             WHERE group_id_hex = ?
               AND member_id_hex NOT IN ({placeholders})"
        );
        let mut values = Vec::with_capacity(active_members.len() + 1);
        values.push(Value::Text(group_id_hex.to_owned()));
        values.extend(active_members.iter().cloned().map(Value::Text));
        self.lock()?
            .execute(&sql, params_from_iter(values.iter()))
            .storage()
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

fn account_group_components(
    conn: &rusqlite::Connection,
    group_id_hex: &str,
) -> StorageResult<Vec<StoredAccountGroupComponent>> {
    let mut statement = conn
        .prepare(
            "SELECT component_id, component_name, component_data_hex
             FROM account_group_app_components
             WHERE group_id_hex = ?1
             ORDER BY component_id",
        )
        .storage()?;
    statement
        .query_map(params![group_id_hex], |row| {
            Ok(StoredAccountGroupComponent {
                component_id: i64_to_u16(row.get(0)?, 0)?,
                component_name: row.get(1)?,
                component_data_hex: row.get(2)?,
            })
        })
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()
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
        updated_at_ms: row.get(8)?,
    })
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
