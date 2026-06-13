#![allow(dead_code)]

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, Transaction, params, types::Type};
use storage_sqlite::{SqlCipherHardening, SqlCipherKey, open_hardened_sqlcipher};

use crate::notifications::StoredPushRegistration;
use crate::{
    AGENT_TEXT_STREAM_COMPONENT_ID, AccountState, AppAgentTextStreamComponent, AppError,
    AppGroupAdminPolicyComponent, AppGroupImageInput, AppGroupMessageRetentionComponent,
    AppGroupNostrRoutingComponent, AppGroupRecord, AppMessageProjection, AppMessageQuery,
    AppMessageRecord, GroupPushTokenRecord, NOSTR_ROUTING_COMPONENT_ID, NotificationSettings,
    PushPlatform, PushRegistration,
};

pub(crate) struct LegacyAccountProjectionDb {
    conn: Connection,
}

struct RawGroupRow {
    group_id_hex: String,
    profile_name: String,
    profile_description: String,
    image: AppGroupImageInput,
    admin_keys_hex: String,
    archived: bool,
    pending_confirmation: bool,
    welcomer_account_id_hex: Option<String>,
    via_welcome_message_id_hex: Option<String>,
    nostr_routing_data_hex: String,
    agent_text_stream_data_hex: String,
}

impl LegacyAccountProjectionDb {
    pub(crate) fn open(path: PathBuf, key: &SqlCipherKey) -> Result<Self, AppError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        // Harden this legacy migration source the same way as storage-sqlite:
        // pin cipher_compatibility and enable cipher_memory_security before
        // keying so key/page material is wiped from the SQLCipher heap.
        open_hardened_sqlcipher(&conn, key, SqlCipherHardening::cipher_only())?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS account_state (
                label TEXT PRIMARY KEY NOT NULL,
                updated_at INTEGER NOT NULL,
                last_transport_timestamp INTEGER
            );
            CREATE TABLE IF NOT EXISTS seen_events (
                event_id TEXT PRIMARY KEY NOT NULL,
                seen_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS groups (
                group_id_hex TEXT PRIMARY KEY NOT NULL,
                endpoint TEXT NOT NULL,
                profile_name TEXT NOT NULL DEFAULT '',
                profile_description TEXT NOT NULL DEFAULT '',
                image_hash_hex TEXT NOT NULL DEFAULT '',
                image_key_hex TEXT NOT NULL DEFAULT '',
                image_nonce_hex TEXT NOT NULL DEFAULT '',
                image_upload_key_hex TEXT NOT NULL DEFAULT '',
                image_media_type TEXT,
                admin_keys_hex TEXT NOT NULL DEFAULT '',
                archived INTEGER NOT NULL DEFAULT 0,
                pending_confirmation INTEGER NOT NULL DEFAULT 0,
                welcomer_account_id_hex TEXT,
                via_welcome_message_id_hex TEXT,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS group_app_components (
                group_id_hex TEXT NOT NULL,
                component_id INTEGER NOT NULL,
                component_name TEXT NOT NULL,
                component_data_hex TEXT NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (group_id_hex, component_id)
            );
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id_hex TEXT,
                direction TEXT NOT NULL DEFAULT 'received',
                group_id_hex TEXT NOT NULL,
                sender TEXT NOT NULL,
                plaintext TEXT NOT NULL,
                kind INTEGER NOT NULL DEFAULT 9,
                tags_json TEXT,
                source_epoch INTEGER,
                recorded_at INTEGER,
                received_at INTEGER NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS messages_message_id_hex_idx
                ON messages(message_id_hex)
                WHERE message_id_hex IS NOT NULL;
            CREATE TABLE IF NOT EXISTS notification_settings (
                account_label TEXT PRIMARY KEY NOT NULL,
                account_id_hex TEXT NOT NULL,
                local_notifications_enabled INTEGER NOT NULL DEFAULT 0,
                native_push_enabled INTEGER NOT NULL DEFAULT 0,
                updated_at_ms INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS push_registration (
                account_label TEXT PRIMARY KEY NOT NULL,
                account_id_hex TEXT NOT NULL,
                platform INTEGER NOT NULL,
                token_fingerprint TEXT NOT NULL,
                token_bytes BLOB NOT NULL,
                server_pubkey_hex TEXT NOT NULL,
                relay_hint TEXT,
                created_at_ms INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL,
                last_shared_at_ms INTEGER
            );
            CREATE TABLE IF NOT EXISTS group_push_tokens (
                group_id_hex TEXT NOT NULL,
                member_id_hex TEXT NOT NULL,
                leaf_index INTEGER NOT NULL,
                platform INTEGER NOT NULL,
                token_fingerprint TEXT NOT NULL,
                server_pubkey_hex TEXT NOT NULL,
                relay_hint TEXT,
                encrypted_token BLOB NOT NULL,
                updated_at_ms INTEGER NOT NULL,
                PRIMARY KEY (group_id_hex, member_id_hex, platform, server_pubkey_hex)
            );",
        )?;
        ensure_column(&conn, "groups", "profile_name", "TEXT NOT NULL DEFAULT ''")?;
        ensure_column(
            &conn,
            "groups",
            "profile_description",
            "TEXT NOT NULL DEFAULT ''",
        )?;
        ensure_column(
            &conn,
            "groups",
            "image_hash_hex",
            "TEXT NOT NULL DEFAULT ''",
        )?;
        ensure_column(&conn, "groups", "image_key_hex", "TEXT NOT NULL DEFAULT ''")?;
        ensure_column(
            &conn,
            "groups",
            "image_nonce_hex",
            "TEXT NOT NULL DEFAULT ''",
        )?;
        ensure_column(
            &conn,
            "groups",
            "image_upload_key_hex",
            "TEXT NOT NULL DEFAULT ''",
        )?;
        ensure_column(&conn, "groups", "image_media_type", "TEXT")?;
        ensure_column(
            &conn,
            "groups",
            "admin_keys_hex",
            "TEXT NOT NULL DEFAULT ''",
        )?;
        ensure_column(&conn, "groups", "archived", "INTEGER NOT NULL DEFAULT 0")?;
        ensure_column(
            &conn,
            "groups",
            "pending_confirmation",
            "INTEGER NOT NULL DEFAULT 0",
        )?;
        ensure_column(&conn, "groups", "welcomer_account_id_hex", "TEXT")?;
        ensure_column(&conn, "groups", "via_welcome_message_id_hex", "TEXT")?;
        ensure_column(&conn, "messages", "message_id_hex", "TEXT")?;
        ensure_column(
            &conn,
            "messages",
            "direction",
            "TEXT NOT NULL DEFAULT 'received'",
        )?;
        ensure_column(&conn, "messages", "recorded_at", "INTEGER")?;
        ensure_column(&conn, "messages", "kind", "INTEGER NOT NULL DEFAULT 9")?;
        ensure_column(&conn, "messages", "tags_json", "TEXT")?;
        ensure_column(&conn, "messages", "source_epoch", "INTEGER")?;
        ensure_column(
            &conn,
            "account_state",
            "last_transport_timestamp",
            "INTEGER",
        )?;
        Ok(Self { conn })
    }

    pub(crate) fn ensure_account(&self, label: &str) -> Result<(), AppError> {
        self.conn.execute(
            "INSERT INTO account_state (label, updated_at)
             VALUES (?1, ?2)
             ON CONFLICT(label) DO NOTHING",
            params![label, unix_now_seconds() as i64],
        )?;
        Ok(())
    }

    pub(crate) fn load_state(&self, label: &str) -> Result<AccountState, AppError> {
        self.ensure_account(label)?;
        let last_transport_timestamp = self
            .conn
            .query_row(
                "SELECT last_transport_timestamp FROM account_state WHERE label = ?1",
                params![label],
                |row| row.get::<_, Option<i64>>(0),
            )?
            .and_then(|value| u64::try_from(value).ok());
        let mut seen_statement = self.conn.prepare(
            "SELECT event_id FROM (
                SELECT event_id, seen_at, rowid FROM seen_events
                ORDER BY seen_at DESC, rowid DESC
                LIMIT ?1
             )
             ORDER BY seen_at, rowid",
        )?;
        let seen_rows = seen_statement
            .query_map(params![limit_to_i64(crate::MAX_SEEN_EVENT_IDS)], |row| {
                row.get::<_, String>(0)
            })?;
        let mut seen_events = Vec::new();
        for row in seen_rows {
            seen_events.push(row?);
        }

        let mut group_statement = self.conn.prepare(
            "SELECT group_id_hex, endpoint, profile_name, profile_description,
                    image_hash_hex, image_key_hex, image_nonce_hex,
                    image_upload_key_hex, image_media_type, admin_keys_hex, archived,
                    pending_confirmation, welcomer_account_id_hex, via_welcome_message_id_hex,
                    COALESCE((
                        SELECT component_data_hex FROM group_app_components c
                        WHERE c.group_id_hex = groups.group_id_hex
                          AND c.component_id = ?1
                    ), '') AS nostr_routing_data_hex,
                    COALESCE((
                        SELECT component_data_hex FROM group_app_components c
                        WHERE c.group_id_hex = groups.group_id_hex
                          AND c.component_id = ?2
                    ), '') AS agent_text_stream_data_hex
             FROM groups
             ORDER BY updated_at, group_id_hex",
        )?;
        let group_rows = group_statement.query_map(
            params![
                i64::from(NOSTR_ROUTING_COMPONENT_ID),
                i64::from(AGENT_TEXT_STREAM_COMPONENT_ID)
            ],
            |row| {
                Ok(RawGroupRow {
                    group_id_hex: row.get(0)?,
                    profile_name: row.get(2)?,
                    profile_description: row.get(3)?,
                    image: AppGroupImageInput {
                        image_hash_hex: row.get(4)?,
                        image_key_hex: row.get(5)?,
                        image_nonce_hex: row.get(6)?,
                        image_upload_key_hex: row.get(7)?,
                        media_type: row.get(8)?,
                    },
                    admin_keys_hex: row.get(9)?,
                    archived: row.get::<_, i64>(10)? != 0,
                    pending_confirmation: row.get::<_, i64>(11)? != 0,
                    welcomer_account_id_hex: row.get(12)?,
                    via_welcome_message_id_hex: row.get(13)?,
                    nostr_routing_data_hex: row.get(14)?,
                    agent_text_stream_data_hex: row.get(15)?,
                })
            },
        )?;
        let mut groups = Vec::new();
        for row in group_rows {
            let row = row?;
            let routing_bytes = hex::decode(&row.nostr_routing_data_hex)?;
            let mut group = AppGroupRecord::new(
                row.group_id_hex,
                AppGroupNostrRoutingComponent::from_bytes(&routing_bytes)?,
                row.profile_name,
                row.profile_description,
                row.image,
                AppGroupAdminPolicyComponent::new(parse_admin_keys_hex(&row.admin_keys_hex)),
                AppGroupMessageRetentionComponent::disabled(),
            );
            if !row.agent_text_stream_data_hex.is_empty() {
                let agent_text_stream_bytes = hex::decode(&row.agent_text_stream_data_hex)?;
                group.agent_text_stream =
                    AppAgentTextStreamComponent::from_bytes(&agent_text_stream_bytes);
            }
            group.archived = row.archived;
            group.pending_confirmation = row.pending_confirmation;
            group.welcomer_account_id_hex = row.welcomer_account_id_hex;
            group.via_welcome_message_id_hex = row.via_welcome_message_id_hex;
            groups.push(group);
        }

        Ok(AccountState {
            label: label.to_owned(),
            seen_events,
            last_transport_timestamp,
            groups,
        })
    }

    pub(crate) fn save_state(&mut self, state: &AccountState) -> Result<(), AppError> {
        let now = unix_now_seconds() as i64;
        let tx = self.conn.transaction()?;
        tx.execute(
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
        )?;

        let retained_start = state
            .seen_events
            .len()
            .saturating_sub(crate::MAX_SEEN_EVENT_IDS);
        for event_id in &state.seen_events[retained_start..] {
            tx.execute(
                "INSERT OR IGNORE INTO seen_events (event_id, seen_at)
                 VALUES (?1, ?2)",
                params![event_id, now],
            )?;
        }
        tx.execute(
            "DELETE FROM seen_events
             WHERE event_id NOT IN (
                SELECT event_id FROM seen_events
                ORDER BY seen_at DESC, rowid DESC
                LIMIT ?1
             )",
            params![limit_to_i64(crate::MAX_SEEN_EVENT_IDS)],
        )?;

        for group in &state.groups {
            let admin_keys_hex = group.admin_policy.admins.join(",");
            tx.execute(
                "INSERT INTO groups (
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
                 WHERE groups.endpoint IS NOT excluded.endpoint
                    OR groups.profile_name IS NOT excluded.profile_name
                    OR groups.profile_description IS NOT excluded.profile_description
                    OR groups.image_hash_hex IS NOT excluded.image_hash_hex
                    OR groups.image_key_hex IS NOT excluded.image_key_hex
                    OR groups.image_nonce_hex IS NOT excluded.image_nonce_hex
                    OR groups.image_upload_key_hex IS NOT excluded.image_upload_key_hex
                    OR groups.image_media_type IS NOT excluded.image_media_type
                    OR groups.admin_keys_hex IS NOT excluded.admin_keys_hex
                    OR groups.archived IS NOT excluded.archived
                    OR groups.pending_confirmation IS NOT excluded.pending_confirmation
                    OR groups.welcomer_account_id_hex IS NOT excluded.welcomer_account_id_hex
                    OR groups.via_welcome_message_id_hex IS NOT excluded.via_welcome_message_id_hex",
                params![
                    &group.group_id_hex,
                    &group.endpoint,
                    &group.profile.name,
                    &group.profile.description,
                    &group.image.image_hash_hex,
                    &group.image.image_key_hex,
                    &group.image.image_nonce_hex,
                    &group.image.image_upload_key_hex,
                    &group.image.media_type,
                    admin_keys_hex,
                    if group.archived { 1_i64 } else { 0_i64 },
                    if group.pending_confirmation {
                        1_i64
                    } else {
                        0_i64
                    },
                    &group.welcomer_account_id_hex,
                    &group.via_welcome_message_id_hex,
                    now
                ],
            )?;

            if group.agent_text_stream.required {
                tx.execute(
                    "DELETE FROM group_app_components
                     WHERE group_id_hex = ?1
                       AND component_id NOT IN (?2, ?3, ?4, ?5, ?6)",
                    params![
                        &group.group_id_hex,
                        i64::from(group.profile.component_id),
                        i64::from(group.image.component_id),
                        i64::from(group.admin_policy.component_id),
                        i64::from(group.nostr_routing.component_id),
                        i64::from(group.agent_text_stream.component_id),
                    ],
                )?;
            } else {
                tx.execute(
                    "DELETE FROM group_app_components
                     WHERE group_id_hex = ?1
                       AND component_id NOT IN (?2, ?3, ?4, ?5)",
                    params![
                        &group.group_id_hex,
                        i64::from(group.profile.component_id),
                        i64::from(group.image.component_id),
                        i64::from(group.admin_policy.component_id),
                        i64::from(group.nostr_routing.component_id),
                    ],
                )?;
            }

            upsert_group_component(
                &tx,
                &group.group_id_hex,
                group.profile.component_id,
                &group.profile.component,
                &group.profile.data_hex,
                now,
            )?;
            upsert_group_component(
                &tx,
                &group.group_id_hex,
                group.image.component_id,
                &group.image.component,
                &group.image.data_hex,
                now,
            )?;
            upsert_group_component(
                &tx,
                &group.group_id_hex,
                group.admin_policy.component_id,
                &group.admin_policy.component,
                &group.admin_policy.data_hex,
                now,
            )?;
            upsert_group_component(
                &tx,
                &group.group_id_hex,
                group.nostr_routing.component_id,
                &group.nostr_routing.component,
                &group.nostr_routing.data_hex,
                now,
            )?;
            if group.agent_text_stream.required {
                upsert_group_component(
                    &tx,
                    &group.group_id_hex,
                    group.agent_text_stream.component_id,
                    &group.agent_text_stream.component,
                    &group.agent_text_stream.data_hex,
                    now,
                )?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn record_message(&self, message: &AppMessageProjection) -> Result<(), AppError> {
        let now = unix_now_seconds() as i64;
        let recorded_at = message
            .recorded_at
            .and_then(|value| i64::try_from(value).ok())
            .unwrap_or(now);
        self.conn.execute(
            "INSERT OR IGNORE INTO messages (
                message_id_hex, direction, group_id_hex, sender, plaintext,
                kind, tags_json, source_epoch, received_at, recorded_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                &message.message_id_hex,
                &message.direction,
                &message.group_id_hex,
                &message.sender,
                &message.plaintext,
                message.kind as i64,
                serialize_tags(&message.tags)?,
                message
                    .source_epoch
                    .and_then(|value| i64::try_from(value).ok()),
                now,
                recorded_at,
            ],
        )?;
        Ok(())
    }

    pub(crate) fn messages(
        &self,
        query: AppMessageQuery,
    ) -> Result<Vec<AppMessageRecord>, AppError> {
        let sql = match (&query.group_id_hex, query.limit) {
            (Some(_), Some(_)) => {
                "SELECT message_id_hex, direction, group_id_hex, sender, plaintext,
                        kind, tags_json, source_epoch,
                        COALESCE(recorded_at, received_at) AS recorded_at, received_at
                 FROM (
                    SELECT id, message_id_hex, direction, group_id_hex, sender, plaintext,
                           kind, tags_json, source_epoch,
                           recorded_at, received_at FROM messages
                    WHERE group_id_hex = ?1
                    ORDER BY COALESCE(recorded_at, received_at) DESC, received_at DESC, id DESC
                    LIMIT ?2
                ) ORDER BY COALESCE(recorded_at, received_at), received_at, id"
            }
            (Some(_), None) => {
                "SELECT message_id_hex, direction, group_id_hex, sender, plaintext,
                        kind, tags_json, source_epoch,
                        COALESCE(recorded_at, received_at), received_at FROM messages
                 WHERE group_id_hex = ?1
                 ORDER BY COALESCE(recorded_at, received_at), received_at, id"
            }
            (None, Some(_)) => {
                "SELECT message_id_hex, direction, group_id_hex, sender, plaintext,
                        kind, tags_json, source_epoch,
                        COALESCE(recorded_at, received_at) AS recorded_at, received_at
                 FROM (
                    SELECT id, message_id_hex, direction, group_id_hex, sender, plaintext,
                           kind, tags_json, source_epoch,
                           recorded_at, received_at FROM messages
                    ORDER BY COALESCE(recorded_at, received_at) DESC, received_at DESC, id DESC
                    LIMIT ?1
                ) ORDER BY COALESCE(recorded_at, received_at), received_at, id"
            }
            (None, None) => {
                "SELECT message_id_hex, direction, group_id_hex, sender, plaintext,
                        kind, tags_json, source_epoch,
                        COALESCE(recorded_at, received_at), received_at FROM messages
                 ORDER BY COALESCE(recorded_at, received_at), received_at, id"
            }
        };
        let mut statement = self.conn.prepare(sql)?;
        let map_row = |row: &rusqlite::Row<'_>| {
            let recorded_at = row.get::<_, i64>(8)?;
            let received_at = row.get::<_, i64>(9)?;
            Ok(AppMessageRecord {
                message_id_hex: row.get::<_, Option<String>>(0)?.unwrap_or_default(),
                direction: row.get(1)?,
                group_id_hex: row.get(2)?,
                sender: row.get(3)?,
                plaintext: row.get(4)?,
                kind: row.get::<_, i64>(5)?.try_into().unwrap_or_default(),
                tags: deserialize_tags_row(row.get::<_, Option<String>>(6)?, 6)?,
                source_epoch: row
                    .get::<_, Option<i64>>(7)?
                    .and_then(|value| value.try_into().ok()),
                recorded_at: recorded_at.try_into().unwrap_or_default(),
                received_at: received_at.try_into().unwrap_or_default(),
            })
        };
        let rows = match (&query.group_id_hex, query.limit) {
            (Some(group_id_hex), Some(limit)) => {
                statement.query_map(params![group_id_hex, limit_to_i64(limit)], map_row)?
            }
            (Some(group_id_hex), None) => statement.query_map(params![group_id_hex], map_row)?,
            (None, Some(limit)) => statement.query_map(params![limit_to_i64(limit)], map_row)?,
            (None, None) => statement.query_map([], map_row)?,
        };
        let mut messages = Vec::new();
        for row in rows {
            messages.push(row?);
        }
        Ok(messages)
    }

    pub(crate) fn message_count(&self) -> Result<usize, AppError> {
        let count = self
            .conn
            .query_row("SELECT count(*) FROM messages", [], |row| {
                row.get::<_, i64>(0)
            })?;
        Ok(count.try_into().unwrap_or_default())
    }

    pub(crate) fn notification_settings(
        &self,
        account_label: &str,
        account_id_hex: &str,
    ) -> Result<NotificationSettings, AppError> {
        self.ensure_notification_settings(account_label, account_id_hex)?;
        self.conn
            .query_row(
                "SELECT account_label, account_id_hex, local_notifications_enabled,
                        native_push_enabled
                 FROM notification_settings
                 WHERE account_label = ?1",
                params![account_label],
                |row| {
                    Ok(NotificationSettings {
                        account_ref: row.get(0)?,
                        account_id_hex: row.get(1)?,
                        local_notifications_enabled: row.get::<_, i64>(2)? != 0,
                        native_push_enabled: row.get::<_, i64>(3)? != 0,
                    })
                },
            )
            .map_err(Into::into)
    }

    pub(crate) fn existing_notification_settings(
        &self,
        account_label: &str,
    ) -> Result<Option<NotificationSettings>, AppError> {
        let mut statement = self.conn.prepare(
            "SELECT account_label, account_id_hex, local_notifications_enabled,
                    native_push_enabled
             FROM notification_settings
             WHERE account_label = ?1",
        )?;
        let mut rows = statement.query(params![account_label])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        Ok(Some(NotificationSettings {
            account_ref: row.get(0)?,
            account_id_hex: row.get(1)?,
            local_notifications_enabled: row.get::<_, i64>(2)? != 0,
            native_push_enabled: row.get::<_, i64>(3)? != 0,
        }))
    }

    pub(crate) fn set_local_notifications_enabled(
        &self,
        account_label: &str,
        account_id_hex: &str,
        enabled: bool,
    ) -> Result<NotificationSettings, AppError> {
        self.ensure_notification_settings(account_label, account_id_hex)?;
        self.conn.execute(
            "UPDATE notification_settings
             SET local_notifications_enabled = ?2, updated_at_ms = ?3
             WHERE account_label = ?1",
            params![account_label, bool_i64(enabled), unix_now_ms()],
        )?;
        self.notification_settings(account_label, account_id_hex)
    }

    pub(crate) fn set_native_push_enabled(
        &self,
        account_label: &str,
        account_id_hex: &str,
        enabled: bool,
    ) -> Result<NotificationSettings, AppError> {
        self.ensure_notification_settings(account_label, account_id_hex)?;
        self.conn.execute(
            "UPDATE notification_settings
             SET native_push_enabled = ?2, updated_at_ms = ?3
             WHERE account_label = ?1",
            params![account_label, bool_i64(enabled), unix_now_ms()],
        )?;
        self.notification_settings(account_label, account_id_hex)
    }

    fn ensure_notification_settings(
        &self,
        account_label: &str,
        account_id_hex: &str,
    ) -> Result<(), AppError> {
        self.conn.execute(
            "INSERT INTO notification_settings (
                account_label, account_id_hex, local_notifications_enabled,
                native_push_enabled, updated_at_ms
             )
             VALUES (?1, ?2, 0, 0, ?3)
             ON CONFLICT(account_label) DO UPDATE SET
                account_id_hex = excluded.account_id_hex",
            params![account_label, account_id_hex, unix_now_ms()],
        )?;
        Ok(())
    }

    pub(crate) fn push_registration(
        &self,
        account_label: &str,
    ) -> Result<Option<StoredPushRegistration>, AppError> {
        let mut statement = self.conn.prepare(
            "SELECT account_label, account_id_hex, platform, token_fingerprint,
                    token_bytes, server_pubkey_hex, relay_hint, created_at_ms,
                    updated_at_ms, last_shared_at_ms
             FROM push_registration
             WHERE account_label = ?1",
        )?;
        let mut rows = statement.query(params![account_label])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        Ok(Some(stored_push_registration_from_row(row)?))
    }

    pub(crate) fn upsert_push_registration(
        &self,
        registration: PushRegistration,
        token_bytes: Vec<u8>,
    ) -> Result<StoredPushRegistration, AppError> {
        let existing = self.push_registration(&registration.account_ref)?;
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
        self.conn.execute(
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
                &registration.account_ref,
                &registration.account_id_hex,
                platform_i64(registration.platform),
                &registration.token_fingerprint,
                token_bytes,
                &registration.server_pubkey_hex,
                &registration.relay_hint,
                created_at_ms,
                registration.updated_at_ms,
                last_shared_at_ms,
            ],
        )?;
        self.push_registration(&registration.account_ref)?
            .ok_or_else(|| AppError::InvalidPushToken("push registration was not stored".into()))
    }

    pub(crate) fn mark_push_registration_shared(
        &self,
        account_label: &str,
        shared_at_ms: i64,
    ) -> Result<(), AppError> {
        self.conn.execute(
            "UPDATE push_registration
             SET last_shared_at_ms = ?2, updated_at_ms = ?2
             WHERE account_label = ?1",
            params![account_label, shared_at_ms],
        )?;
        Ok(())
    }

    pub(crate) fn clear_push_registration(
        &self,
        account_label: &str,
    ) -> Result<Option<StoredPushRegistration>, AppError> {
        let existing = self.push_registration(account_label)?;
        self.conn.execute(
            "DELETE FROM push_registration WHERE account_label = ?1",
            params![account_label],
        )?;
        Ok(existing)
    }

    pub(crate) fn upsert_group_push_token(
        &self,
        token: &GroupPushTokenRecord,
    ) -> Result<(), AppError> {
        self.conn.execute(
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
                u32_i64(token.leaf_index),
                platform_i64(token.platform),
                &token.token_fingerprint,
                &token.server_pubkey_hex,
                &token.relay_hint,
                &token.encrypted_token,
                token.updated_at_ms,
            ],
        )?;
        Ok(())
    }

    pub(crate) fn group_push_tokens(
        &self,
        group_id_hex: &str,
    ) -> Result<Vec<GroupPushTokenRecord>, AppError> {
        let mut statement = self.conn.prepare(
            "SELECT group_id_hex, member_id_hex, leaf_index, platform,
                    token_fingerprint, server_pubkey_hex, relay_hint,
                    encrypted_token, updated_at_ms
             FROM group_push_tokens
             WHERE group_id_hex = ?1
             ORDER BY member_id_hex, platform, server_pubkey_hex",
        )?;
        let rows = statement.query_map(params![group_id_hex], group_push_token_from_row)?;
        let mut tokens = Vec::new();
        for row in rows {
            tokens.push(row?);
        }
        Ok(tokens)
    }

    pub(crate) fn all_group_push_tokens(&self) -> Result<Vec<GroupPushTokenRecord>, AppError> {
        let mut statement = self.conn.prepare(
            "SELECT group_id_hex, member_id_hex, leaf_index, platform,
                    token_fingerprint, server_pubkey_hex, relay_hint,
                    encrypted_token, updated_at_ms
             FROM group_push_tokens
             ORDER BY group_id_hex, member_id_hex, platform, server_pubkey_hex",
        )?;
        let rows = statement.query_map([], group_push_token_from_row)?;
        let mut tokens = Vec::new();
        for row in rows {
            tokens.push(row?);
        }
        Ok(tokens)
    }

    pub(crate) fn remove_group_push_token(
        &self,
        group_id_hex: &str,
        member_id_hex: &str,
        platform: PushPlatform,
        token_fingerprint: &str,
        server_pubkey_hex: &str,
    ) -> Result<(), AppError> {
        self.conn.execute(
            "DELETE FROM group_push_tokens
             WHERE group_id_hex = ?1
               AND member_id_hex = ?2
               AND platform = ?3
               AND token_fingerprint = ?4
               AND server_pubkey_hex = ?5",
            params![
                group_id_hex,
                member_id_hex,
                platform_i64(platform),
                token_fingerprint,
                server_pubkey_hex,
            ],
        )?;
        Ok(())
    }

    pub(crate) fn remove_group_push_tokens_for_member(
        &self,
        group_id_hex: &str,
        member_id_hex: &str,
    ) -> Result<(), AppError> {
        self.conn.execute(
            "DELETE FROM group_push_tokens
             WHERE group_id_hex = ?1 AND member_id_hex = ?2",
            params![group_id_hex, member_id_hex],
        )?;
        Ok(())
    }

    pub(crate) fn remove_stale_group_push_tokens(
        &self,
        group_id_hex: &str,
        active_members: &[String],
    ) -> Result<usize, AppError> {
        if active_members.is_empty() {
            let removed = self.conn.execute(
                "DELETE FROM group_push_tokens WHERE group_id_hex = ?1",
                params![group_id_hex],
            )?;
            return Ok(removed);
        }
        let active = active_members
            .iter()
            .map(|member| format!("'{}'", member.replace('\'', "''")))
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "DELETE FROM group_push_tokens
             WHERE group_id_hex = ?1
               AND member_id_hex NOT IN ({active})"
        );
        let removed = self.conn.execute(&sql, params![group_id_hex])?;
        Ok(removed)
    }

    pub(crate) fn prune_group_messages_before(
        &self,
        group_id_hex: &str,
        cutoff_recorded_at: u64,
    ) -> Result<usize, AppError> {
        let pruned = self.conn.execute(
            "DELETE FROM messages
             WHERE group_id_hex = ?1
               AND COALESCE(recorded_at, received_at) < ?2",
            params![
                group_id_hex,
                i64::try_from(cutoff_recorded_at).unwrap_or(i64::MAX)
            ],
        )?;
        Ok(pruned)
    }
}

fn upsert_group_component(
    tx: &Transaction<'_>,
    group_id_hex: &str,
    component_id: u16,
    component_name: &str,
    component_data_hex: &str,
    now: i64,
) -> Result<(), AppError> {
    tx.execute(
        "INSERT INTO group_app_components (
            group_id_hex, component_id, component_name, component_data_hex, updated_at
         )
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(group_id_hex, component_id) DO UPDATE SET
            component_name = excluded.component_name,
            component_data_hex = excluded.component_data_hex,
            updated_at = excluded.updated_at
         WHERE group_app_components.component_name IS NOT excluded.component_name
            OR group_app_components.component_data_hex IS NOT excluded.component_data_hex",
        params![
            group_id_hex,
            i64::from(component_id),
            component_name,
            component_data_hex,
            now
        ],
    )?;
    Ok(())
}

fn unix_now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn limit_to_i64(limit: usize) -> i64 {
    i64::try_from(limit).unwrap_or(i64::MAX)
}

fn unix_now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(i64::MAX)
}

fn bool_i64(value: bool) -> i64 {
    if value { 1 } else { 0 }
}

fn u32_i64(value: u32) -> i64 {
    i64::from(value)
}

fn platform_i64(platform: PushPlatform) -> i64 {
    i64::from(platform.platform_byte())
}

fn platform_from_i64(value: i64) -> Result<PushPlatform, rusqlite::Error> {
    let byte = u8::try_from(value).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(0, Type::Integer, Box::new(err))
    })?;
    PushPlatform::from_platform_byte(byte)
        .map_err(|err| rusqlite::Error::FromSqlConversionFailure(0, Type::Integer, Box::new(err)))
}

fn stored_push_registration_from_row(
    row: &rusqlite::Row<'_>,
) -> Result<StoredPushRegistration, rusqlite::Error> {
    let platform = platform_from_i64(row.get(2)?)?;
    Ok(StoredPushRegistration {
        registration: PushRegistration {
            account_ref: row.get(0)?,
            account_id_hex: row.get(1)?,
            platform,
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

fn group_push_token_from_row(
    row: &rusqlite::Row<'_>,
) -> Result<GroupPushTokenRecord, rusqlite::Error> {
    let leaf_index = row.get::<_, i64>(2)?;
    let leaf_index = u32::try_from(leaf_index).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(2, Type::Integer, Box::new(err))
    })?;
    Ok(GroupPushTokenRecord {
        group_id_hex: row.get(0)?,
        member_id_hex: row.get(1)?,
        leaf_index,
        platform: platform_from_i64(row.get(3)?)?,
        token_fingerprint: row.get(4)?,
        server_pubkey_hex: row.get(5)?,
        relay_hint: row.get(6)?,
        encrypted_token: row.get(7)?,
        updated_at_ms: row.get(8)?,
    })
}

fn parse_admin_keys_hex(value: &str) -> Vec<[u8; 32]> {
    value
        .split(',')
        .filter_map(|key| {
            let bytes = hex::decode(key).ok()?;
            let array: [u8; 32] = bytes.try_into().ok()?;
            Some(array)
        })
        .collect()
}

fn serialize_tags(tags: &[Vec<String>]) -> Result<Option<String>, AppError> {
    if tags.is_empty() {
        return Ok(None);
    }
    serde_json::to_string(tags)
        .map(Some)
        .map_err(|err| AppError::InvalidAppMessagePayload(err.to_string()))
}

fn deserialize_tags_row(
    tags: Option<String>,
    column: usize,
) -> Result<Vec<Vec<String>>, rusqlite::Error> {
    match tags.filter(|tags| !tags.is_empty()) {
        Some(tags) => serde_json::from_str(&tags).map_err(|err| {
            rusqlite::Error::FromSqlConversionFailure(column, Type::Text, Box::new(err))
        }),
        None => Ok(Vec::new()),
    }
}

fn ensure_column(
    conn: &Connection,
    table: &str,
    column: &str,
    definition: &str,
) -> Result<(), AppError> {
    let pragma = format!("PRAGMA table_info({table})");
    let mut statement = conn.prepare(&pragma)?;
    let rows = statement.query_map([], |row| row.get::<_, String>(1))?;
    for row in rows {
        if row? == column {
            return Ok(());
        }
    }
    conn.execute(
        &format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"),
        [],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_state_rolls_back_all_tables_when_component_write_fails() {
        let dir = tempfile::tempdir().unwrap();
        let key = SqlCipherKey::new("test-key").unwrap();
        let mut db = LegacyAccountProjectionDb::open(dir.path().join("app.sqlite3"), &key).unwrap();
        let original = AccountState {
            label: "alice".to_owned(),
            seen_events: vec!["event-before".to_owned()],
            last_transport_timestamp: Some(1_700_000_001),
            groups: vec![AppGroupRecord::new(
                "aa".to_owned(),
                test_routing([0xAA; 32], "ws://127.0.0.1:18080"),
                "before".to_owned(),
                "".to_owned(),
                AppGroupImageInput::default(),
                AppGroupAdminPolicyComponent::new(Vec::new()),
                AppGroupMessageRetentionComponent::disabled(),
            )],
        };
        db.save_state(&original).unwrap();
        db.conn
            .execute_batch(
                "CREATE TRIGGER fail_image_component_insert
                 BEFORE INSERT ON group_app_components
                 WHEN NEW.component_id = 32770
                 BEGIN
                    SELECT RAISE(FAIL, 'image component write failed');
                 END;",
            )
            .unwrap();

        let updated = AccountState {
            label: "alice".to_owned(),
            seen_events: vec!["event-after".to_owned()],
            last_transport_timestamp: Some(1_700_000_002),
            groups: vec![AppGroupRecord::new(
                "bb".to_owned(),
                test_routing([0xBB; 32], "ws://127.0.0.1:18081"),
                "after".to_owned(),
                "".to_owned(),
                AppGroupImageInput::default(),
                AppGroupAdminPolicyComponent::new(Vec::new()),
                AppGroupMessageRetentionComponent::disabled(),
            )],
        };

        assert!(db.save_state(&updated).is_err());

        let restored = db.load_state("alice").unwrap();
        assert_eq!(restored.seen_events, original.seen_events);
        assert_eq!(
            restored.last_transport_timestamp,
            original.last_transport_timestamp
        );
        assert_eq!(restored.groups[0].group_id_hex, "aa");
        assert_eq!(restored.groups[0].profile.name, "before");
    }

    #[test]
    fn load_state_uses_agent_text_stream_component_row() {
        let dir = tempfile::tempdir().unwrap();
        let key = SqlCipherKey::new("test-key").unwrap();
        let mut db = LegacyAccountProjectionDb::open(dir.path().join("app.sqlite3"), &key).unwrap();
        let mut group = AppGroupRecord::new(
            "aa".to_owned(),
            test_routing([0xAA; 32], "ws://127.0.0.1:18080"),
            "agent".to_owned(),
            "".to_owned(),
            AppGroupImageInput::default(),
            AppGroupAdminPolicyComponent::new(Vec::new()),
            AppGroupMessageRetentionComponent::disabled(),
        );
        group.agent_text_stream = AppAgentTextStreamComponent::from_bytes(&[
            0x01, 0x03, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        let state = AccountState {
            label: "alice".to_owned(),
            seen_events: Vec::new(),
            last_transport_timestamp: Some(1_700_000_003),
            groups: vec![group],
        };

        db.save_state(&state).unwrap();
        let restored = db.load_state("alice").unwrap();

        assert!(restored.groups[0].agent_text_stream.required);
        assert_eq!(restored.last_transport_timestamp, Some(1_700_000_003));
        assert_eq!(
            restored.groups[0].agent_text_stream.data_hex,
            "010300001000000000000000"
        );
    }

    #[test]
    fn save_state_does_not_rewrite_unchanged_group_rows() {
        let dir = tempfile::tempdir().unwrap();
        let key = SqlCipherKey::new("test-key").unwrap();
        let mut db = LegacyAccountProjectionDb::open(dir.path().join("app.sqlite3"), &key).unwrap();
        let state = AccountState {
            label: "alice".to_owned(),
            seen_events: Vec::new(),
            last_transport_timestamp: Some(1_700_000_003),
            groups: vec![
                AppGroupRecord::new(
                    "aa".to_owned(),
                    test_routing([0xAA; 32], "ws://127.0.0.1:18080"),
                    "alpha".to_owned(),
                    "".to_owned(),
                    AppGroupImageInput::default(),
                    AppGroupAdminPolicyComponent::new(Vec::new()),
                    AppGroupMessageRetentionComponent::disabled(),
                ),
                AppGroupRecord::new(
                    "bb".to_owned(),
                    test_routing([0xBB; 32], "ws://127.0.0.1:18081"),
                    "beta".to_owned(),
                    "".to_owned(),
                    AppGroupImageInput::default(),
                    AppGroupAdminPolicyComponent::new(Vec::new()),
                    AppGroupMessageRetentionComponent::disabled(),
                ),
            ],
        };
        db.save_state(&state).unwrap();
        db.conn
            .execute_batch(
                "CREATE TABLE write_audit (table_name TEXT NOT NULL);
                 CREATE TRIGGER audit_groups_insert
                 AFTER INSERT ON groups
                 BEGIN
                    INSERT INTO write_audit (table_name) VALUES ('groups');
                 END;
                 CREATE TRIGGER audit_groups_update
                 AFTER UPDATE ON groups
                 BEGIN
                    INSERT INTO write_audit (table_name) VALUES ('groups');
                 END;
                 CREATE TRIGGER audit_components_insert
                 AFTER INSERT ON group_app_components
                 BEGIN
                    INSERT INTO write_audit (table_name) VALUES ('group_app_components');
                 END;
                 CREATE TRIGGER audit_components_update
                 AFTER UPDATE ON group_app_components
                 BEGIN
                    INSERT INTO write_audit (table_name) VALUES ('group_app_components');
                 END;
                 CREATE TRIGGER audit_components_delete
                 AFTER DELETE ON group_app_components
                 BEGIN
                    INSERT INTO write_audit (table_name) VALUES ('group_app_components');
                 END;",
            )
            .unwrap();

        let mut state_with_seen_event = state.clone();
        state_with_seen_event
            .seen_events
            .push("event-after".to_owned());
        db.save_state(&state_with_seen_event).unwrap();

        let group_rewrites: i64 = db
            .conn
            .query_row("SELECT count(*) FROM write_audit", [], |row| row.get(0))
            .unwrap();
        assert_eq!(group_rewrites, 0);
    }

    #[test]
    fn save_state_retains_only_recent_seen_events() {
        let dir = tempfile::tempdir().unwrap();
        let key = SqlCipherKey::new("test-key").unwrap();
        let mut db = LegacyAccountProjectionDb::open(dir.path().join("app.sqlite3"), &key).unwrap();
        let seen_events = (0..(crate::MAX_SEEN_EVENT_IDS + 2))
            .map(|index| format!("event-{index:05}"))
            .collect::<Vec<_>>();
        let state = AccountState {
            label: "alice".to_owned(),
            seen_events,
            last_transport_timestamp: Some(1_700_000_004),
            groups: vec![AppGroupRecord::new(
                "aa".to_owned(),
                test_routing([0xAA; 32], "ws://127.0.0.1:18080"),
                "chat".to_owned(),
                "".to_owned(),
                AppGroupImageInput::default(),
                AppGroupAdminPolicyComponent::new(Vec::new()),
                AppGroupMessageRetentionComponent::disabled(),
            )],
        };

        db.save_state(&state).unwrap();

        let restored = db.load_state("alice").unwrap();
        assert_eq!(restored.seen_events.len(), crate::MAX_SEEN_EVENT_IDS);
        assert_eq!(
            restored.seen_events.first().map(String::as_str),
            Some("event-00002")
        );
        let expected_last = format!("event-{:05}", crate::MAX_SEEN_EVENT_IDS + 1);
        assert_eq!(
            restored.seen_events.last().map(String::as_str),
            Some(expected_last.as_str())
        );
    }

    #[test]
    fn prune_group_messages_before_removes_only_expired_group_rows() {
        let dir = tempfile::tempdir().unwrap();
        let key = SqlCipherKey::new("test-key").unwrap();
        let db = LegacyAccountProjectionDb::open(dir.path().join("app.sqlite3"), &key).unwrap();
        for (message_id_hex, group_id_hex, recorded_at) in [
            ("old-aa", "aa", 10),
            ("new-aa", "aa", 20),
            ("old-bb", "bb", 10),
        ] {
            db.record_message(&AppMessageProjection {
                message_id_hex: message_id_hex.to_owned(),
                source_message_id_hex: None,
                direction: "received".to_owned(),
                group_id_hex: group_id_hex.to_owned(),
                sender: "sender".to_owned(),
                plaintext: message_id_hex.to_owned(),
                kind: 9,
                tags: Vec::new(),
                source_epoch: None,
                recorded_at: Some(recorded_at),
                origin_commit_id: None,
            })
            .unwrap();
        }

        assert_eq!(db.prune_group_messages_before("aa", 15).unwrap(), 1);

        let aa = db
            .messages(AppMessageQuery {
                group_id_hex: Some("aa".to_owned()),
                limit: None,
            })
            .unwrap();
        assert_eq!(aa.len(), 1);
        assert_eq!(aa[0].message_id_hex, "new-aa");
        let bb = db
            .messages(AppMessageQuery {
                group_id_hex: Some("bb".to_owned()),
                limit: None,
            })
            .unwrap();
        assert_eq!(bb.len(), 1);
        assert_eq!(bb[0].message_id_hex, "old-bb");
    }

    fn test_routing(nostr_group_id: [u8; 32], relay: &str) -> AppGroupNostrRoutingComponent {
        AppGroupNostrRoutingComponent::new(
            crate::NostrRoutingV1::new(nostr_group_id, vec![relay.to_owned()]).unwrap(),
        )
        .unwrap()
    }
}
