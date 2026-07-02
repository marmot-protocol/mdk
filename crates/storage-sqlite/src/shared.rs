use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use crate::{
    SqliteResultExt, bool_i64, optional_u64_to_i64, u64_to_i64, unix_now_ms, usize_to_i64,
};
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{OptionalExtension, params};

const SHARED_BUSY_TIMEOUT_MS: u64 = 5_000;

/// Defensive upper bound on how many public-directory users
/// [`SqliteSharedStorage::public_directory_users`] materializes at once (#761).
/// The public directory is populated from network data, so without a cap a
/// hostile or simply large cache could be loaded unboundedly into memory. Set
/// well above the app-layer directory-search reachability
/// (`USER_DIRECTORY_SEARCH_MAX_VISITED` == 8192) so it never truncates a
/// realistic result set; a warn fires if it is ever hit.
const PUBLIC_DIRECTORY_USERS_MAX: usize = 10_000;

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
    /// Audit data-mode token, stored as the forensics enum's serde string
    /// (`obfuscated_sensitive_data` | `full_data`). Kept as an opaque string at
    /// this layer so storage does not depend on the forensics crate; the app
    /// layer parses it. Unknown/legacy values map back to the safe default.
    pub data_mode: String,
}

/// Canonical default audit data-mode token (the safe, obfuscated posture).
/// Mirrors `marmot_forensics::AuditDataMode::ObfuscatedSensitiveData`'s serde
/// string without taking a dependency on that crate.
pub const AUDIT_DATA_MODE_DEFAULT: &str = "obfuscated_sensitive_data";

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
		    data_mode TEXT NOT NULL DEFAULT 'obfuscated_sensitive_data',
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
        Self::ensure_audit_log_data_mode_column(&conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Additively add the `data_mode` column to a pre-existing
    /// `audit_log_settings` table created before audit v2 (the table is created
    /// with `CREATE TABLE IF NOT EXISTS`, so older databases keep the v1 shape
    /// until this runs). New databases already have the column from the create
    /// statement above; this is a no-op for them.
    fn ensure_audit_log_data_mode_column(conn: &rusqlite::Connection) -> StorageResult<()> {
        let has_column = {
            let mut stmt = conn
                .prepare("PRAGMA table_info(audit_log_settings)")
                .storage()?;
            stmt.query_map([], |row| row.get::<_, String>(1))
                .storage()?
                .collect::<Result<Vec<_>, _>>()
                .storage()?
                .iter()
                .any(|column| column == "data_mode")
        };
        if !has_column {
            conn.execute(
                &format!(
                    "ALTER TABLE audit_log_settings \
                     ADD COLUMN data_mode TEXT NOT NULL DEFAULT '{AUDIT_DATA_MODE_DEFAULT}'"
                ),
                [],
            )
            .storage()?;
        }
        Ok(())
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
        self.public_directory_users_capped(PUBLIC_DIRECTORY_USERS_MAX)
    }

    fn public_directory_users_capped(
        &self,
        max: usize,
    ) -> StorageResult<Vec<PublicDirectoryUserRecord>> {
        // #761: two batched queries + Rust bucketing instead of a 2N+1 (one user
        // row query plus one follows query per user), AND a defensive `max` cap
        // so a large network-populated directory cache cannot be materialized
        // unboundedly into memory. The cap sits well above the app-layer
        // directory-search reachability, so it does not truncate realistic
        // results; a warn fires if it ever bites. The follows query is scoped to
        // the SAME capped user set (matching subquery LIMIT) so neither query
        // loads the whole cache. Ordering preserved (users by account_id_hex;
        // each user's follows by position then follow id).
        let cap = i64::try_from(max).unwrap_or(i64::MAX);
        let conn = self.lock();
        let mut follows_by_account: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        {
            let mut stmt = self
                .conn_ref(&conn)
                .prepare(
                    "SELECT account_id_hex, follow_account_id_hex FROM directory_user_follows
                     WHERE account_id_hex IN (
                         SELECT account_id_hex FROM directory_users
                         ORDER BY account_id_hex LIMIT ?1
                     )
                     ORDER BY account_id_hex, position, follow_account_id_hex",
                )
                .storage()?;
            let rows = stmt
                .query_map(params![cap], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .storage()?;
            for row in rows {
                let (account_id_hex, follow) = row.storage()?;
                follows_by_account
                    .entry(account_id_hex)
                    .or_default()
                    .push(follow);
            }
        }
        let mut stmt = self
            .conn_ref(&conn)
            .prepare(
                "SELECT account_id_hex, npub, profile_json, relay_lists_json,
                        key_package_json, event_id_hex, event_kind, event_created_at
                 FROM directory_users
                 ORDER BY account_id_hex
                 LIMIT ?1",
            )
            .storage()?;
        let records = stmt
            .query_map(params![cap], |row| {
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
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        if records.len() >= max {
            // no silent caps: surface (aggregate count only, privacy-safe) that
            // the listing was truncated so an operator can tell the bound bit.
            tracing::warn!(
                target: "storage_sqlite::shared",
                method = "public_directory_users",
                cap = max,
                "public directory listing hit the defensive cap; results truncated",
            );
        }
        Ok(records
            .into_iter()
            .map(|mut record| {
                record.follows = follows_by_account
                    .remove(&record.account_id_hex)
                    .unwrap_or_default();
                record
            })
            .collect())
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
                "SELECT enabled, data_mode
                 FROM audit_log_settings
                 WHERE id = 1",
                [],
                |row| {
                    Ok(StoredAuditLogSettings {
                        enabled: row.get::<_, i64>(0)? != 0,
                        data_mode: row.get::<_, String>(1)?,
                    })
                },
            )
            .storage()
    }

    pub fn set_audit_log_settings(&self, settings: &StoredAuditLogSettings) -> StorageResult<()> {
        self.lock()
            .execute(
                "INSERT INTO audit_log_settings (
                    id, enabled, data_mode, updated_at_ms
                 )
                 VALUES (1, ?1, ?2, ?3)
                 ON CONFLICT(id) DO UPDATE SET
                    enabled = excluded.enabled,
                    data_mode = excluded.data_mode,
                    updated_at_ms = excluded.updated_at_ms",
                params![
                    bool_i64(settings.enabled),
                    settings.data_mode,
                    unix_now_ms()
                ],
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

fn optional_i64_to_u64(value: Option<i64>) -> Option<u64> {
    value.and_then(|value| u64::try_from(value).ok())
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

    // #761: the batched listing is defensively bounded. The uncapped path still
    // returns every user; the cap bounds the materialized set to the
    // lowest-ordered users and attaches only their (subquery-scoped) follows,
    // never loading the whole network-populated cache.
    #[test]
    fn public_directory_users_capped_bounds_result_and_scopes_follows() {
        let storage = SqliteSharedStorage::in_memory().unwrap();
        for (i, prefix) in ["01", "02", "03"].iter().enumerate() {
            storage
                .put_public_directory_user(&PublicDirectoryUserRecord {
                    account_id_hex: prefix.repeat(32),
                    npub: format!("npub{i}"),
                    profile_json: None,
                    relay_lists_json: "{}".to_owned(),
                    key_package_json: None,
                    event_id_hex: None,
                    event_kind: None,
                    event_created_at: None,
                    follows: vec!["ff".repeat(32)],
                })
                .unwrap();
        }

        // Uncapped path returns every user with its follows.
        assert_eq!(storage.public_directory_users().unwrap().len(), 3);

        // Capped at 2: only the two lowest-ordered users, each with its follows.
        let capped = storage.public_directory_users_capped(2).unwrap();
        assert_eq!(capped.len(), 2);
        assert_eq!(capped[0].account_id_hex, "01".repeat(32));
        assert_eq!(capped[1].account_id_hex, "02".repeat(32));
        assert!(
            capped
                .iter()
                .all(|user| user.follows == vec!["ff".repeat(32)])
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
            StoredAuditLogSettings {
                enabled: false,
                data_mode: AUDIT_DATA_MODE_DEFAULT.to_owned(),
            }
        );

        let updated = StoredAuditLogSettings {
            enabled: true,
            data_mode: "full_data".to_owned(),
        };
        storage.set_audit_log_settings(&updated).unwrap();

        assert_eq!(storage.audit_log_settings().unwrap(), updated);
    }

    #[test]
    fn audit_log_settings_data_mode_column_is_added_to_legacy_table() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shared.db");

        // Simulate a pre-v2 database: an `audit_log_settings` table without the
        // `data_mode` column, with audit logging already enabled.
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE audit_log_settings (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    enabled INTEGER NOT NULL DEFAULT 0,
                    updated_at_ms INTEGER NOT NULL
                 );
                 INSERT INTO audit_log_settings (id, enabled, updated_at_ms)
                 VALUES (1, 1, 0);",
            )
            .unwrap();
        }

        // Opening the shared storage migrates the column in additively and the
        // pre-existing row keeps its enabled flag while defaulting the mode.
        let storage = SqliteSharedStorage::open(&path).unwrap();
        assert_eq!(
            storage.audit_log_settings().unwrap(),
            StoredAuditLogSettings {
                enabled: true,
                data_mode: AUDIT_DATA_MODE_DEFAULT.to_owned(),
            }
        );

        // The migrated column round-trips a new value.
        storage
            .set_audit_log_settings(&StoredAuditLogSettings {
                enabled: true,
                data_mode: "full_data".to_owned(),
            })
            .unwrap();
        assert_eq!(storage.audit_log_settings().unwrap().data_mode, "full_data");
    }
}
