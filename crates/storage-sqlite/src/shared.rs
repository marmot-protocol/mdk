use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::SqliteResultExt;
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{OptionalExtension, params};

const SHARED_BUSY_TIMEOUT_MS: u64 = 5_000;

#[derive(Clone, Debug)]
pub struct SqliteSharedStorage {
    conn: Arc<Mutex<rusqlite::Connection>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicDirectoryUserRecord {
    pub account_id_hex: String,
    pub npub: String,
    pub profile_json: Option<String>,
    pub relay_lists_json: String,
    pub key_package_json: Option<String>,
    pub event_id_hex: Option<String>,
    pub event_kind: Option<u64>,
    pub event_created_at: Option<u64>,
    pub follows: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredRelayTelemetrySettings {
    pub export_enabled: bool,
    pub export_interval_seconds: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredAuditLogSettings {
    pub enabled: bool,
}

impl SqliteSharedStorage {
    pub fn open(path: impl AsRef<Path>) -> StorageResult<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|err| StorageError::Backend(err.to_string()))?;
        }
        let conn = rusqlite::Connection::open(path).storage()?;
        Self::from_connection(conn)
    }

    pub fn in_memory() -> StorageResult<Self> {
        Self::from_connection(rusqlite::Connection::open_in_memory().storage()?)
    }

    fn from_connection(conn: rusqlite::Connection) -> StorageResult<Self> {
        conn.busy_timeout(Duration::from_millis(SHARED_BUSY_TIMEOUT_MS))
            .storage()?;
        conn.pragma_update(None, "foreign_keys", true).storage()?;
        conn.pragma_update(None, "trusted_schema", false)
            .storage()?;
        conn.execute_batch(
            r#"
CREATE TABLE IF NOT EXISTS directory_users (
    account_id_hex TEXT PRIMARY KEY NOT NULL,
    npub TEXT NOT NULL,
    profile_json TEXT,
    relay_lists_json TEXT NOT NULL,
    key_package_json TEXT,
    event_id_hex TEXT,
    event_kind INTEGER,
    event_created_at INTEGER
);
CREATE TABLE IF NOT EXISTS directory_user_follows (
    account_id_hex TEXT NOT NULL REFERENCES directory_users(account_id_hex) ON DELETE CASCADE,
    follow_account_id_hex TEXT NOT NULL,
    position INTEGER NOT NULL,
    event_id_hex TEXT,
    event_created_at INTEGER,
    PRIMARY KEY (account_id_hex, follow_account_id_hex)
);
CREATE TABLE IF NOT EXISTS directory_events (
    event_id_hex TEXT PRIMARY KEY NOT NULL,
    author_account_id_hex TEXT NOT NULL,
    kind INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS directory_key_packages (
    account_id_hex TEXT PRIMARY KEY NOT NULL REFERENCES directory_users(account_id_hex) ON DELETE CASCADE,
    key_package_ref_hex TEXT,
    key_package_event_id_hex TEXT,
    key_package_json TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS directory_search_graph_users (
    account_id_hex TEXT PRIMARY KEY NOT NULL,
    npub TEXT NOT NULL,
    profile_json TEXT,
    relay_lists_json TEXT,
    key_package_json TEXT,
    event_id_hex TEXT,
    event_kind INTEGER,
    event_created_at INTEGER
);
CREATE TABLE IF NOT EXISTS directory_search_graph_follows (
    account_id_hex TEXT NOT NULL,
    follow_account_id_hex TEXT NOT NULL,
    position INTEGER NOT NULL,
    event_id_hex TEXT,
    event_created_at INTEGER,
    PRIMARY KEY (account_id_hex, follow_account_id_hex)
);
	CREATE TABLE IF NOT EXISTS relay_telemetry_settings (
	    id INTEGER PRIMARY KEY CHECK (id = 1),
	    export_enabled INTEGER NOT NULL DEFAULT 0,
	    export_interval_seconds INTEGER NOT NULL DEFAULT 60,
	    updated_at_ms INTEGER NOT NULL
	);
		CREATE TABLE IF NOT EXISTS audit_log_settings (
		    id INTEGER PRIMARY KEY CHECK (id = 1),
		    enabled INTEGER NOT NULL DEFAULT 0,
		    updated_at_ms INTEGER NOT NULL
		);
		CREATE TABLE IF NOT EXISTS telemetry_install (
		    id INTEGER PRIMARY KEY CHECK (id = 1),
		    install_id TEXT NOT NULL,
		    updated_at_ms INTEGER NOT NULL
		);
		"#,
        )
        .storage()?;
        Self::clear_legacy_relay_telemetry_endpoint(&conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn put_public_directory_user(
        &self,
        record: &PublicDirectoryUserRecord,
    ) -> StorageResult<()> {
        let mut conn = self.lock();
        let tx = conn.transaction().storage()?;
        tx.execute(
            "INSERT INTO directory_users (
                account_id_hex, npub, profile_json, relay_lists_json, key_package_json,
                event_id_hex, event_kind, event_created_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(account_id_hex) DO UPDATE SET
                npub = excluded.npub,
                profile_json = excluded.profile_json,
                relay_lists_json = excluded.relay_lists_json,
                key_package_json = excluded.key_package_json,
                event_id_hex = excluded.event_id_hex,
                event_kind = excluded.event_kind,
                event_created_at = excluded.event_created_at",
            params![
                &record.account_id_hex,
                &record.npub,
                &record.profile_json,
                &record.relay_lists_json,
                &record.key_package_json,
                &record.event_id_hex,
                optional_u64_to_i64(record.event_kind)?,
                optional_u64_to_i64(record.event_created_at)?,
            ],
        )
        .storage()?;
        tx.execute(
            "DELETE FROM directory_user_follows WHERE account_id_hex = ?1",
            params![&record.account_id_hex],
        )
        .storage()?;
        for (position, follow) in record.follows.iter().enumerate() {
            tx.execute(
                "INSERT INTO directory_user_follows (
                    account_id_hex, follow_account_id_hex, position, event_id_hex, event_created_at
                 )
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    &record.account_id_hex,
                    follow,
                    usize_to_i64(position)?,
                    &record.event_id_hex,
                    optional_u64_to_i64(record.event_created_at)?,
                ],
            )
            .storage()?;
        }
        tx.commit().storage()
    }

    pub fn public_directory_user(
        &self,
        account_id_hex: &str,
    ) -> StorageResult<Option<PublicDirectoryUserRecord>> {
        let conn = self.lock();
        let Some(mut record) = self
            .conn_ref(&conn)
            .query_row(
                "SELECT account_id_hex, npub, profile_json, relay_lists_json,
                        key_package_json, event_id_hex, event_kind, event_created_at
                 FROM directory_users
                 WHERE account_id_hex = ?1",
                params![account_id_hex],
                |row| {
                    Ok(PublicDirectoryUserRecord {
                        account_id_hex: row.get(0)?,
                        npub: row.get(1)?,
                        profile_json: row.get(2)?,
                        relay_lists_json: row.get(3)?,
                        key_package_json: row.get(4)?,
                        event_id_hex: row.get(5)?,
                        event_kind: optional_i64_to_u64(row.get::<_, Option<i64>>(6)?),
                        event_created_at: optional_i64_to_u64(row.get::<_, Option<i64>>(7)?),
                        follows: Vec::new(),
                    })
                },
            )
            .optional()
            .storage()?
        else {
            return Ok(None);
        };
        let mut stmt = self
            .conn_ref(&conn)
            .prepare(
                "SELECT follow_account_id_hex FROM directory_user_follows
                 WHERE account_id_hex = ?1
                 ORDER BY position, follow_account_id_hex",
            )
            .storage()?;
        record.follows = stmt
            .query_map(params![account_id_hex], |row| row.get::<_, String>(0))
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        Ok(Some(record))
    }

    pub fn public_directory_users(&self) -> StorageResult<Vec<PublicDirectoryUserRecord>> {
        let ids = {
            let conn = self.lock();
            let mut stmt = self
                .conn_ref(&conn)
                .prepare("SELECT account_id_hex FROM directory_users ORDER BY account_id_hex")
                .storage()?;
            stmt.query_map([], |row| row.get::<_, String>(0))
                .storage()?
                .collect::<Result<Vec<_>, _>>()
                .storage()?
        };
        let mut records = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(record) = self.public_directory_user(&id)? {
                records.push(record);
            }
        }
        Ok(records)
    }

    pub fn relay_telemetry_settings(&self) -> StorageResult<StoredRelayTelemetrySettings> {
        self.ensure_relay_telemetry_settings()?;
        self.lock()
            .query_row(
                "SELECT export_enabled, export_interval_seconds
                 FROM relay_telemetry_settings
                 WHERE id = 1",
                [],
                |row| {
                    let interval: i64 = row.get(1)?;
                    Ok(StoredRelayTelemetrySettings {
                        export_enabled: row.get::<_, i64>(0)? != 0,
                        export_interval_seconds: u64::try_from(interval).unwrap_or(60),
                    })
                },
            )
            .storage()
    }

    pub fn set_relay_telemetry_settings(
        &self,
        settings: &StoredRelayTelemetrySettings,
    ) -> StorageResult<()> {
        self.lock()
            .execute(
                "INSERT INTO relay_telemetry_settings (
                    id, export_enabled, export_interval_seconds, updated_at_ms
                 )
                 VALUES (1, ?1, ?2, ?3)
                 ON CONFLICT(id) DO UPDATE SET
                    export_enabled = excluded.export_enabled,
                    export_interval_seconds = excluded.export_interval_seconds,
                    updated_at_ms = excluded.updated_at_ms",
                params![
                    bool_i64(settings.export_enabled),
                    u64_to_i64(settings.export_interval_seconds)?,
                    unix_now_ms(),
                ],
            )
            .storage()?;
        Ok(())
    }

    pub fn telemetry_install_id(&self) -> StorageResult<Option<String>> {
        self.lock()
            .query_row(
                "SELECT install_id
                 FROM telemetry_install
                 WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .storage()
    }

    pub fn set_telemetry_install_id(&self, install_id: &str) -> StorageResult<()> {
        self.lock()
            .execute(
                "INSERT INTO telemetry_install (id, install_id, updated_at_ms)
                 VALUES (1, ?1, ?2)
                 ON CONFLICT(id) DO UPDATE SET
                    install_id = excluded.install_id,
                    updated_at_ms = excluded.updated_at_ms",
                params![install_id, unix_now_ms()],
            )
            .storage()?;
        Ok(())
    }

    pub fn audit_log_settings(&self) -> StorageResult<StoredAuditLogSettings> {
        self.ensure_audit_log_settings()?;
        self.lock()
            .query_row(
                "SELECT enabled
                 FROM audit_log_settings
                 WHERE id = 1",
                [],
                |row| {
                    Ok(StoredAuditLogSettings {
                        enabled: row.get::<_, i64>(0)? != 0,
                    })
                },
            )
            .storage()
    }

    pub fn set_audit_log_settings(&self, settings: &StoredAuditLogSettings) -> StorageResult<()> {
        self.lock()
            .execute(
                "INSERT INTO audit_log_settings (
                    id, enabled, updated_at_ms
                 )
                 VALUES (1, ?1, ?2)
                 ON CONFLICT(id) DO UPDATE SET
                    enabled = excluded.enabled,
                    updated_at_ms = excluded.updated_at_ms",
                params![bool_i64(settings.enabled), unix_now_ms()],
            )
            .storage()?;
        Ok(())
    }

    #[cfg(test)]
    fn table_columns(&self, table: &str) -> Vec<String> {
        let conn = self.lock();
        let mut stmt = self
            .conn_ref(&conn)
            .prepare(&format!("PRAGMA table_info({table})"))
            .unwrap();
        stmt.query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    fn lock(&self) -> MutexGuard<'_, rusqlite::Connection> {
        self.conn
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn conn_ref<'a>(
        &self,
        conn: &'a MutexGuard<'_, rusqlite::Connection>,
    ) -> &'a rusqlite::Connection {
        conn
    }

    fn ensure_relay_telemetry_settings(&self) -> StorageResult<()> {
        self.lock()
            .execute(
                "INSERT INTO relay_telemetry_settings (
                    id, export_enabled, export_interval_seconds, updated_at_ms
                 )
                 VALUES (1, 0, 60, ?1)
                 ON CONFLICT(id) DO NOTHING",
                params![unix_now_ms()],
            )
            .storage()?;
        Ok(())
    }

    fn clear_legacy_relay_telemetry_endpoint(conn: &rusqlite::Connection) -> StorageResult<()> {
        let columns = {
            let mut stmt = conn
                .prepare("PRAGMA table_info(relay_telemetry_settings)")
                .storage()?;
            stmt.query_map([], |row| row.get::<_, String>(1))
                .storage()?
                .collect::<Result<Vec<_>, _>>()
                .storage()?
        };
        if columns.iter().any(|column| column == "otlp_endpoint") {
            conn.execute(
                "UPDATE relay_telemetry_settings SET otlp_endpoint = NULL",
                [],
            )
            .storage()?;
        }
        Ok(())
    }

    fn ensure_audit_log_settings(&self) -> StorageResult<()> {
        self.lock()
            .execute(
                "INSERT INTO audit_log_settings (
                    id, enabled, updated_at_ms
                 )
                 VALUES (1, 0, ?1)
                 ON CONFLICT(id) DO NOTHING",
                params![unix_now_ms()],
            )
            .storage()?;
        Ok(())
    }
}

fn bool_i64(value: bool) -> i64 {
    if value { 1 } else { 0 }
}

fn u64_to_i64(value: u64) -> StorageResult<i64> {
    i64::try_from(value).map_err(|_| {
        cgka_traits::storage::StorageError::Backend(
            "u64 value does not fit in sqlite INTEGER".to_owned(),
        )
    })
}

fn optional_u64_to_i64(value: Option<u64>) -> StorageResult<Option<i64>> {
    value
        .map(|value| {
            i64::try_from(value).map_err(|_| {
                cgka_traits::storage::StorageError::Backend(
                    "u64 value does not fit in sqlite INTEGER".to_owned(),
                )
            })
        })
        .transpose()
}

fn optional_i64_to_u64(value: Option<i64>) -> Option<u64> {
    value.and_then(|value| u64::try_from(value).ok())
}

fn usize_to_i64(value: usize) -> StorageResult<i64> {
    i64::try_from(value).map_err(|_| {
        cgka_traits::storage::StorageError::Backend(
            "usize value does not fit in sqlite INTEGER".to_owned(),
        )
    })
}

fn unix_now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_storage_is_plaintext_public_directory_only() {
        let storage = SqliteSharedStorage::in_memory().unwrap();
        let user_columns = storage.table_columns("directory_users");

        assert!(user_columns.contains(&"profile_json".to_owned()));
        assert!(user_columns.contains(&"relay_lists_json".to_owned()));
        assert!(!user_columns.contains(&"local_account_json".to_owned()));
        assert!(!user_columns.contains(&"private_discovery_reason".to_owned()));
        assert!(!user_columns.contains(&"local_fetch_timestamp".to_owned()));
    }

    #[test]
    fn stores_public_directory_record_and_follows() {
        let storage = SqliteSharedStorage::in_memory().unwrap();
        let record = PublicDirectoryUserRecord {
            account_id_hex: "aa".repeat(32),
            npub: "npub1example".to_owned(),
            profile_json: Some(r#"{"name":"Alice"}"#.to_owned()),
            relay_lists_json: r#"{"nip65":["wss://relay.example"]}"#.to_owned(),
            key_package_json: Some(r#"{"id":"kp"}"#.to_owned()),
            event_id_hex: Some("bb".repeat(32)),
            event_kind: Some(0),
            event_created_at: Some(1_700_000_000),
            follows: vec!["cc".repeat(32), "dd".repeat(32)],
        };

        storage.put_public_directory_user(&record).unwrap();

        assert_eq!(
            storage
                .public_directory_user(&record.account_id_hex)
                .unwrap()
                .unwrap(),
            record
        );
    }

    #[test]
    fn relay_telemetry_settings_default_and_persist() {
        let storage = SqliteSharedStorage::in_memory().unwrap();

        assert_eq!(
            storage.relay_telemetry_settings().unwrap(),
            StoredRelayTelemetrySettings {
                export_enabled: false,
                export_interval_seconds: 60,
            }
        );

        let updated = StoredRelayTelemetrySettings {
            export_enabled: true,
            export_interval_seconds: 30,
        };
        storage.set_relay_telemetry_settings(&updated).unwrap();

        assert_eq!(storage.relay_telemetry_settings().unwrap(), updated);
    }

    #[test]
    fn clears_legacy_plaintext_relay_telemetry_endpoint() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shared.sqlite3");
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch(
                r#"
                CREATE TABLE relay_telemetry_settings (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    export_enabled INTEGER NOT NULL DEFAULT 0,
                    otlp_endpoint TEXT,
                    export_interval_seconds INTEGER NOT NULL DEFAULT 60,
                    updated_at_ms INTEGER NOT NULL
                );
                INSERT INTO relay_telemetry_settings (
                    id, export_enabled, otlp_endpoint, export_interval_seconds, updated_at_ms
                )
                VALUES (1, 1, 'https://collector.example/v1/metrics?token=secret', 30, 1);
                "#,
            )
            .unwrap();
        }

        let storage = SqliteSharedStorage::open(&path).unwrap();

        assert_eq!(
            storage.relay_telemetry_settings().unwrap(),
            StoredRelayTelemetrySettings {
                export_enabled: true,
                export_interval_seconds: 30,
            }
        );
        drop(storage);

        let conn = rusqlite::Connection::open(&path).unwrap();
        let endpoint: Option<String> = conn
            .query_row(
                "SELECT otlp_endpoint FROM relay_telemetry_settings WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(endpoint, None);
    }

    #[test]
    fn audit_log_settings_default_and_persist() {
        let storage = SqliteSharedStorage::in_memory().unwrap();

        assert_eq!(
            storage.audit_log_settings().unwrap(),
            StoredAuditLogSettings { enabled: false }
        );

        let updated = StoredAuditLogSettings { enabled: true };
        storage.set_audit_log_settings(&updated).unwrap();

        assert_eq!(storage.audit_log_settings().unwrap(), updated);
    }
}
