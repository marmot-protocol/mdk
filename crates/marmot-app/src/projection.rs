use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, Transaction, params, types::Type};

use crate::{
    AGENT_TEXT_STREAM_COMPONENT_ID, AccountState, AppAgentTextStreamComponent, AppError,
    AppGroupAdminPolicyComponent, AppGroupImageInput, AppGroupMessageRetentionComponent,
    AppGroupNostrRoutingComponent, AppGroupRecord, AppMessageProjection, AppMessageQuery,
    AppMessageRecord, NOSTR_ROUTING_COMPONENT_ID,
};

pub(crate) struct AccountProjectionDb {
    conn: Connection,
}

struct RawGroupRow {
    group_id_hex: String,
    profile_name: String,
    profile_description: String,
    image: AppGroupImageInput,
    admin_keys_hex: String,
    archived: bool,
    nostr_routing_data_hex: String,
    agent_text_stream_data_hex: String,
}

impl AccountProjectionDb {
    pub(crate) fn open(path: PathBuf, key_material: &str) -> Result<Self, AppError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "key", key_material)?;
        let _: i64 = conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))?;
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
                recorded_at INTEGER,
                received_at INTEGER NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS messages_message_id_hex_idx
                ON messages(message_id_hex)
                WHERE message_id_hex IS NOT NULL;",
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
                    nostr_routing_data_hex: row.get(11)?,
                    agent_text_stream_data_hex: row.get(12)?,
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
                    image_upload_key_hex, image_media_type, admin_keys_hex, archived, updated_at
                 )
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
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
                    OR groups.archived IS NOT excluded.archived",
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
                kind, tags_json, received_at, recorded_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                &message.message_id_hex,
                &message.direction,
                &message.group_id_hex,
                &message.sender,
                &message.plaintext,
                message.kind as i64,
                serialize_tags(&message.tags)?,
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
                        kind, tags_json,
                        COALESCE(recorded_at, received_at) AS recorded_at, received_at
                 FROM (
                    SELECT id, message_id_hex, direction, group_id_hex, sender, plaintext,
                           kind, tags_json,
                           recorded_at, received_at FROM messages
                    WHERE group_id_hex = ?1
                    ORDER BY COALESCE(recorded_at, received_at) DESC, received_at DESC, id DESC
                    LIMIT ?2
                ) ORDER BY COALESCE(recorded_at, received_at), received_at, id"
            }
            (Some(_), None) => {
                "SELECT message_id_hex, direction, group_id_hex, sender, plaintext,
                        kind, tags_json,
                        COALESCE(recorded_at, received_at), received_at FROM messages
                 WHERE group_id_hex = ?1
                 ORDER BY COALESCE(recorded_at, received_at), received_at, id"
            }
            (None, Some(_)) => {
                "SELECT message_id_hex, direction, group_id_hex, sender, plaintext,
                        kind, tags_json,
                        COALESCE(recorded_at, received_at) AS recorded_at, received_at
                 FROM (
                    SELECT id, message_id_hex, direction, group_id_hex, sender, plaintext,
                           kind, tags_json,
                           recorded_at, received_at FROM messages
                    ORDER BY COALESCE(recorded_at, received_at) DESC, received_at DESC, id DESC
                    LIMIT ?1
                ) ORDER BY COALESCE(recorded_at, received_at), received_at, id"
            }
            (None, None) => {
                "SELECT message_id_hex, direction, group_id_hex, sender, plaintext,
                        kind, tags_json,
                        COALESCE(recorded_at, received_at), received_at FROM messages
                 ORDER BY COALESCE(recorded_at, received_at), received_at, id"
            }
        };
        let mut statement = self.conn.prepare(sql)?;
        let map_row = |row: &rusqlite::Row<'_>| {
            let recorded_at = row.get::<_, i64>(7)?;
            let received_at = row.get::<_, i64>(8)?;
            Ok(AppMessageRecord {
                message_id_hex: row.get::<_, Option<String>>(0)?.unwrap_or_default(),
                direction: row.get(1)?,
                group_id_hex: row.get(2)?,
                sender: row.get(3)?,
                plaintext: row.get(4)?,
                kind: row.get::<_, i64>(5)?.try_into().unwrap_or_default(),
                tags: deserialize_tags_row(row.get::<_, Option<String>>(6)?, 6)?,
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
        let mut db = AccountProjectionDb::open(dir.path().join("app.sqlite3"), "test-key").unwrap();
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
        let mut db = AccountProjectionDb::open(dir.path().join("app.sqlite3"), "test-key").unwrap();
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
        let mut db = AccountProjectionDb::open(dir.path().join("app.sqlite3"), "test-key").unwrap();
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
        let mut db = AccountProjectionDb::open(dir.path().join("app.sqlite3"), "test-key").unwrap();
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
        let db = AccountProjectionDb::open(dir.path().join("app.sqlite3"), "test-key").unwrap();
        for (message_id_hex, group_id_hex, recorded_at) in [
            ("old-aa", "aa", 10),
            ("new-aa", "aa", 20),
            ("old-bb", "bb", 10),
        ] {
            db.record_message(&AppMessageProjection {
                message_id_hex: message_id_hex.to_owned(),
                direction: "received".to_owned(),
                group_id_hex: group_id_hex.to_owned(),
                sender: "sender".to_owned(),
                plaintext: message_id_hex.to_owned(),
                kind: 9,
                tags: Vec::new(),
                recorded_at: Some(recorded_at),
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
