use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, params};

use crate::{
    AccountState, AppError, AppGroupAdminPolicyComponent, AppGroupImageInput,
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
                updated_at INTEGER NOT NULL
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
        let mut seen_statement = self.conn.prepare(
            "SELECT event_id FROM seen_events
             ORDER BY seen_at, event_id",
        )?;
        let seen_rows = seen_statement.query_map([], |row| row.get::<_, String>(0))?;
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
                    ), '') AS nostr_routing_data_hex
             FROM groups
             ORDER BY updated_at, group_id_hex",
        )?;
        let group_rows =
            group_statement.query_map([i64::from(NOSTR_ROUTING_COMPONENT_ID)], |row| {
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
                })
            })?;
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
            );
            group.archived = row.archived;
            groups.push(group);
        }

        Ok(AccountState {
            label: label.to_owned(),
            seen_events,
            groups,
        })
    }

    pub(crate) fn save_state(&mut self, state: &AccountState) -> Result<(), AppError> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO account_state (label, updated_at)
             VALUES (?1, ?2)
             ON CONFLICT(label) DO NOTHING",
            params![&state.label, unix_now_seconds() as i64],
        )?;

        tx.execute("DELETE FROM seen_events", [])?;
        for event_id in &state.seen_events {
            tx.execute(
                "INSERT OR IGNORE INTO seen_events (event_id, seen_at)
                 VALUES (?1, ?2)",
                params![event_id, unix_now_seconds() as i64],
            )?;
        }

        tx.execute("DELETE FROM groups", [])?;
        tx.execute("DELETE FROM group_app_components", [])?;
        for group in &state.groups {
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
                    updated_at = excluded.updated_at",
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
                    group.admin_policy.admins.join(","),
                    if group.archived { 1_i64 } else { 0_i64 },
                    unix_now_seconds() as i64
                ],
            )?;
            tx.execute(
                "INSERT INTO group_app_components (
                    group_id_hex, component_id, component_name, component_data_hex, updated_at
                 )
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(group_id_hex, component_id) DO UPDATE SET
                    component_name = excluded.component_name,
                    component_data_hex = excluded.component_data_hex,
                    updated_at = excluded.updated_at",
                params![
                    &group.group_id_hex,
                    i64::from(group.profile.component_id),
                    &group.profile.component,
                    &group.profile.data_hex,
                    unix_now_seconds() as i64
                ],
            )?;
            tx.execute(
                "INSERT INTO group_app_components (
                    group_id_hex, component_id, component_name, component_data_hex, updated_at
                 )
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(group_id_hex, component_id) DO UPDATE SET
                    component_name = excluded.component_name,
                    component_data_hex = excluded.component_data_hex,
                    updated_at = excluded.updated_at",
                params![
                    &group.group_id_hex,
                    i64::from(group.image.component_id),
                    &group.image.component,
                    &group.image.data_hex,
                    unix_now_seconds() as i64
                ],
            )?;
            tx.execute(
                "INSERT INTO group_app_components (
                    group_id_hex, component_id, component_name, component_data_hex, updated_at
                 )
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(group_id_hex, component_id) DO UPDATE SET
                    component_name = excluded.component_name,
                    component_data_hex = excluded.component_data_hex,
                    updated_at = excluded.updated_at",
                params![
                    &group.group_id_hex,
                    i64::from(group.admin_policy.component_id),
                    &group.admin_policy.component,
                    &group.admin_policy.data_hex,
                    unix_now_seconds() as i64
                ],
            )?;
            tx.execute(
                "INSERT INTO group_app_components (
                    group_id_hex, component_id, component_name, component_data_hex, updated_at
                 )
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(group_id_hex, component_id) DO UPDATE SET
                    component_name = excluded.component_name,
                    component_data_hex = excluded.component_data_hex,
                    updated_at = excluded.updated_at",
                params![
                    &group.group_id_hex,
                    i64::from(group.nostr_routing.component_id),
                    &group.nostr_routing.component,
                    &group.nostr_routing.data_hex,
                    unix_now_seconds() as i64
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn record_message(&self, message: &AppMessageProjection) -> Result<(), AppError> {
        let now = unix_now_seconds() as i64;
        self.conn.execute(
            "INSERT OR IGNORE INTO messages (
                message_id_hex, direction, group_id_hex, sender, plaintext, received_at, recorded_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                &message.message_id_hex,
                &message.direction,
                &message.group_id_hex,
                &message.sender,
                &message.plaintext,
                now,
                now,
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
                        COALESCE(recorded_at, received_at) AS recorded_at, received_at
                 FROM (
                    SELECT id, message_id_hex, direction, group_id_hex, sender, plaintext,
                           recorded_at, received_at FROM messages
                    WHERE group_id_hex = ?1
                    ORDER BY id DESC
                    LIMIT ?2
                ) ORDER BY id"
            }
            (Some(_), None) => {
                "SELECT message_id_hex, direction, group_id_hex, sender, plaintext,
                        COALESCE(recorded_at, received_at), received_at FROM messages
                 WHERE group_id_hex = ?1
                 ORDER BY id"
            }
            (None, Some(_)) => {
                "SELECT message_id_hex, direction, group_id_hex, sender, plaintext,
                        COALESCE(recorded_at, received_at) AS recorded_at, received_at
                 FROM (
                    SELECT id, message_id_hex, direction, group_id_hex, sender, plaintext,
                           recorded_at, received_at FROM messages
                    ORDER BY id DESC
                    LIMIT ?1
                ) ORDER BY id"
            }
            (None, None) => {
                "SELECT message_id_hex, direction, group_id_hex, sender, plaintext,
                        COALESCE(recorded_at, received_at), received_at FROM messages
                 ORDER BY id"
            }
        };
        let mut statement = self.conn.prepare(sql)?;
        let map_row = |row: &rusqlite::Row<'_>| {
            let recorded_at = row.get::<_, i64>(5)?;
            let received_at = row.get::<_, i64>(6)?;
            Ok(AppMessageRecord {
                message_id_hex: row.get::<_, Option<String>>(0)?.unwrap_or_default(),
                direction: row.get(1)?,
                group_id_hex: row.get(2)?,
                sender: row.get(3)?,
                plaintext: row.get(4)?,
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
            groups: vec![AppGroupRecord::new(
                "aa".to_owned(),
                test_routing([0xAA; 32], "marmot-local://group/aa"),
                "before".to_owned(),
                "".to_owned(),
                AppGroupImageInput::default(),
                AppGroupAdminPolicyComponent::new(Vec::new()),
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
            groups: vec![AppGroupRecord::new(
                "bb".to_owned(),
                test_routing([0xBB; 32], "marmot-local://group/bb"),
                "after".to_owned(),
                "".to_owned(),
                AppGroupImageInput::default(),
                AppGroupAdminPolicyComponent::new(Vec::new()),
            )],
        };

        assert!(db.save_state(&updated).is_err());

        let restored = db.load_state("alice").unwrap();
        assert_eq!(restored.seen_events, original.seen_events);
        assert_eq!(restored.groups[0].group_id_hex, "aa");
        assert_eq!(restored.groups[0].profile.name, "before");
    }

    fn test_routing(nostr_group_id: [u8; 32], relay: &str) -> AppGroupNostrRoutingComponent {
        AppGroupNostrRoutingComponent::new(
            crate::NostrRoutingV1::new(nostr_group_id, vec![relay.to_owned()]).unwrap(),
        )
        .unwrap()
    }
}
