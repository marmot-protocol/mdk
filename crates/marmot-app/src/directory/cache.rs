use std::fs;
use std::path::PathBuf;
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use serde::de::DeserializeOwned;
use storage_sqlite::{SqlCipherHardening, SqlCipherKey, open_hardened_sqlcipher};

use crate::{AccountRelayListStatus, AppError, UserDirectoryRecord, UserProfileMetadata};

#[derive(Clone)]
pub(crate) struct DirectoryCache {
    conn: Arc<Mutex<Connection>>,
    #[cfg(test)]
    put_count: Arc<AtomicUsize>,
}

impl DirectoryCache {
    pub(crate) fn open(path: PathBuf, key: &SqlCipherKey) -> Result<Self, AppError> {
        record_directory_cache_open();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        // Mirror storage-sqlite's hardened open: pin cipher_compatibility and
        // enable cipher_memory_security before keying, and scrub deleted rows /
        // keep temp state in memory for this long-lived encrypted cache.
        open_hardened_sqlcipher(&conn, key, SqlCipherHardening::live_cache())?;
        Self::from_connection(conn)
    }

    pub(crate) fn open_legacy_plaintext(path: PathBuf) -> Result<Option<Self>, AppError> {
        if !path.exists() {
            return Ok(None);
        }
        record_directory_cache_open();
        let conn = Connection::open(path)?;
        let _: i64 = conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))?;
        Self::from_connection(conn).map(Some)
    }

    fn from_connection(conn: Connection) -> Result<Self, AppError> {
        initialize_schema(&conn)?;
        let cache = Self {
            conn: Arc::new(Mutex::new(conn)),
            #[cfg(test)]
            put_count: Arc::new(AtomicUsize::new(0)),
        };
        cache.migrate_legacy_json_records()?;
        Ok(cache)
    }

    #[cfg(test)]
    pub(crate) fn put_count_for_test(&self) -> usize {
        self.put_count.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    pub(crate) fn reset_put_count_for_test(&self) {
        self.put_count.store(0, Ordering::SeqCst);
    }

    fn lock(&self) -> MutexGuard<'_, Connection> {
        self.conn
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn entry(
        &self,
        account_id_hex: &str,
    ) -> Result<Option<UserDirectoryRecord>, AppError> {
        let conn = self.lock();
        let Some(row) = Self::directory_user_row(&conn, account_id_hex)? else {
            return Ok(None);
        };
        Self::record_from_directory_user_row(&conn, row).map(Some)
    }

    pub(crate) fn entries(&self) -> Result<Vec<UserDirectoryRecord>, AppError> {
        let conn = self.lock();
        let mut statement = conn.prepare(
            "SELECT account_id_hex, npub, local_account_json, profile_json,
                    relay_lists_json, key_package_json
             FROM directory_users
             ORDER BY account_id_hex",
        )?;
        let rows = statement.query_map([], directory_user_row_from_row)?;
        let mut entries = Vec::new();
        for row in rows {
            entries.push(Self::record_from_directory_user_row(&conn, row?)?);
        }
        Ok(entries)
    }

    pub(crate) fn search_record(
        &self,
        account_id_hex: &str,
    ) -> Result<Option<UserDirectoryRecord>, AppError> {
        if let Some(record) = self.entry(account_id_hex)? {
            return Ok(Some(record));
        }
        self.search_graph_record(account_id_hex)
    }

    pub(crate) fn put(&self, entry: &UserDirectoryRecord) -> Result<(), AppError> {
        self.put_with_reason(entry, "directory")
    }

    pub(crate) fn put_with_reason(
        &self,
        entry: &UserDirectoryRecord,
        reason: &str,
    ) -> Result<(), AppError> {
        #[cfg(test)]
        self.put_count.fetch_add(1, Ordering::SeqCst);
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        Self::put_with_reason_locked(&tx, entry, reason)?;
        tx.commit()?;
        Ok(())
    }

    fn put_with_reason_locked(
        conn: &Connection,
        entry: &UserDirectoryRecord,
        reason: &str,
    ) -> Result<(), AppError> {
        let now = unix_now_seconds() as i64;
        conn.execute(
            "INSERT INTO directory_users (
                account_id_hex,
                npub,
                local_account_json,
                profile_json,
                relay_lists_json,
                key_package_json,
                updated_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(account_id_hex) DO UPDATE SET
                npub = excluded.npub,
                local_account_json = excluded.local_account_json,
                profile_json = excluded.profile_json,
                relay_lists_json = excluded.relay_lists_json,
                key_package_json = excluded.key_package_json,
                updated_at = excluded.updated_at",
            params![
                &entry.account_id_hex,
                &entry.npub,
                optional_json(&entry.local_account)?,
                optional_json(&entry.profile)?,
                serde_json::to_string(&entry.relay_lists)?,
                optional_json(&entry.key_package)?,
                now,
            ],
        )?;
        Self::replace_follow_rows(
            conn,
            "directory_user_follows",
            &entry.account_id_hex,
            &entry.follows,
            now,
        )?;
        Self::replace_follow_source_rows(
            conn,
            &entry.account_id_hex,
            &entry.follow_source_relays,
            now,
        )?;
        Self::remember_known_reason(conn, &entry.account_id_hex, reason, now)?;
        Self::put_search_graph_snapshot(conn, entry, now)?;
        Ok(())
    }

    fn directory_user_row(
        conn: &Connection,
        account_id_hex: &str,
    ) -> Result<Option<DirectoryUserRow>, AppError> {
        conn.query_row(
            "SELECT account_id_hex, npub, local_account_json, profile_json,
                    relay_lists_json, key_package_json
             FROM directory_users
             WHERE account_id_hex = ?1",
            [account_id_hex],
            directory_user_row_from_row,
        )
        .optional()
        .map_err(AppError::from)
    }

    fn record_from_directory_user_row(
        conn: &Connection,
        row: DirectoryUserRow,
    ) -> Result<UserDirectoryRecord, AppError> {
        let follows = Self::follow_rows(conn, "directory_user_follows", &row.account_id_hex)?;
        let follow_source_relays = Self::follow_source_rows(conn, &row.account_id_hex)?;
        Ok(UserDirectoryRecord {
            account_id_hex: row.account_id_hex,
            npub: row.npub,
            local_account: optional_value(row.local_account_json)?,
            profile: optional_value(row.profile_json)?,
            follows,
            follow_source_relays,
            relay_lists: serde_json::from_str(&row.relay_lists_json)?,
            key_package: optional_value(row.key_package_json)?,
        })
    }

    fn search_graph_record(
        &self,
        account_id_hex: &str,
    ) -> Result<Option<UserDirectoryRecord>, AppError> {
        let conn = self.lock();
        let Some(row) = conn
            .query_row(
                "SELECT account_id_hex, npub, profile_json, follows_known
             FROM directory_search_graph_users
             WHERE account_id_hex = ?1",
                [account_id_hex],
                |row| {
                    Ok(SearchGraphUserRow {
                        account_id_hex: row.get(0)?,
                        npub: row.get(1)?,
                        profile_json: row.get(2)?,
                        follows_known: row.get::<_, i64>(3)? != 0,
                    })
                },
            )
            .optional()?
        else {
            return Ok(None);
        };
        let follows = if row.follows_known {
            Self::follow_rows(&conn, "directory_search_graph_follows", &row.account_id_hex)?
        } else {
            Vec::new()
        };
        Ok(Some(UserDirectoryRecord {
            account_id_hex: row.account_id_hex,
            npub: row.npub,
            local_account: None,
            profile: optional_value(row.profile_json)?,
            follows,
            follow_source_relays: Vec::new(),
            relay_lists: AccountRelayListStatus::empty(),
            key_package: None,
        }))
    }

    fn put_search_graph_snapshot(
        conn: &Connection,
        entry: &UserDirectoryRecord,
        now: i64,
    ) -> Result<(), AppError> {
        Self::put_search_graph_record_locked(
            conn,
            &DirectorySearchGraphRecord {
                account_id_hex: entry.account_id_hex.clone(),
                npub: entry.npub.clone(),
                profile: entry.profile.clone(),
                follows: Some(entry.follows.clone()),
                metadata_updated_at: entry.profile.as_ref().map(|profile| profile.created_at),
                metadata_expires_at: None,
            },
            now,
        )
    }

    #[cfg(test)]
    pub(crate) fn put_search_graph_record(
        &self,
        record: &DirectorySearchGraphRecord,
        now: i64,
    ) -> Result<(), AppError> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        Self::put_search_graph_record_locked(&tx, record, now)?;
        tx.commit()?;
        Ok(())
    }

    fn put_search_graph_record_locked(
        conn: &Connection,
        record: &DirectorySearchGraphRecord,
        now: i64,
    ) -> Result<(), AppError> {
        let metadata_updated_at = record
            .metadata_updated_at
            .and_then(|value| i64::try_from(value).ok());
        let metadata_expires_at = record
            .metadata_expires_at
            .and_then(|value| i64::try_from(value).ok());
        let follows_known = record.follows.is_some();
        let follows_updated_at = follows_known.then_some(now);
        conn.execute(
            "INSERT INTO directory_search_graph_users (
                account_id_hex,
                npub,
                profile_json,
                metadata_updated_at,
                metadata_expires_at,
                follows_known,
                follows_updated_at,
                created_at,
                updated_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)
             ON CONFLICT(account_id_hex) DO UPDATE SET
                npub = excluded.npub,
                profile_json = excluded.profile_json,
                metadata_updated_at = excluded.metadata_updated_at,
                metadata_expires_at = excluded.metadata_expires_at,
                follows_known = excluded.follows_known,
                follows_updated_at = excluded.follows_updated_at,
                updated_at = excluded.updated_at",
            params![
                &record.account_id_hex,
                &record.npub,
                optional_json(&record.profile)?,
                metadata_updated_at,
                metadata_expires_at,
                i64::from(follows_known),
                follows_updated_at,
                now,
            ],
        )?;
        if let Some(follows) = &record.follows {
            Self::replace_follow_rows(
                conn,
                "directory_search_graph_follows",
                &record.account_id_hex,
                follows,
                now,
            )
        } else {
            conn.execute(
                "DELETE FROM directory_search_graph_follows WHERE account_id_hex = ?1",
                [&record.account_id_hex],
            )?;
            Ok(())
        }
    }

    fn replace_follow_rows(
        conn: &Connection,
        table: &str,
        account_id_hex: &str,
        follows: &[String],
        now: i64,
    ) -> Result<(), AppError> {
        conn.execute(
            &format!("DELETE FROM {table} WHERE account_id_hex = ?1"),
            [account_id_hex],
        )?;
        for (position, follow) in follows.iter().enumerate() {
            conn.execute(
                &format!(
                    "INSERT INTO {table} (
                        account_id_hex,
                        follow_account_id_hex,
                        position,
                        updated_at
                     )
                     VALUES (?1, ?2, ?3, ?4)"
                ),
                params![
                    account_id_hex,
                    follow,
                    i64::try_from(position).unwrap_or(i64::MAX),
                    now,
                ],
            )?;
        }
        Ok(())
    }

    fn replace_follow_source_rows(
        conn: &Connection,
        account_id_hex: &str,
        source_relays: &[String],
        now: i64,
    ) -> Result<(), AppError> {
        conn.execute(
            "DELETE FROM directory_follow_source_relays WHERE account_id_hex = ?1",
            [account_id_hex],
        )?;
        for (position, relay_url) in source_relays.iter().enumerate() {
            conn.execute(
                "INSERT INTO directory_follow_source_relays (
                    account_id_hex,
                    relay_url,
                    position,
                    updated_at
                 )
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    account_id_hex,
                    relay_url,
                    i64::try_from(position).unwrap_or(i64::MAX),
                    now,
                ],
            )?;
        }
        Ok(())
    }

    fn remember_known_reason(
        conn: &Connection,
        account_id_hex: &str,
        reason: &str,
        now: i64,
    ) -> Result<(), AppError> {
        conn.execute(
            "INSERT INTO directory_known_user_reasons (
                account_id_hex,
                reason,
                first_seen_at,
                last_seen_at
             )
             VALUES (?1, ?2, ?3, ?3)
             ON CONFLICT(account_id_hex, reason) DO UPDATE SET
                last_seen_at = excluded.last_seen_at",
            params![account_id_hex, reason, now],
        )?;
        Ok(())
    }

    fn follow_rows(
        conn: &Connection,
        table: &str,
        account_id_hex: &str,
    ) -> Result<Vec<String>, AppError> {
        let mut statement = conn.prepare(&format!(
            "SELECT follow_account_id_hex FROM {table}
             WHERE account_id_hex = ?1
             ORDER BY position, follow_account_id_hex"
        ))?;
        let rows = statement.query_map([account_id_hex], |row| row.get::<_, String>(0))?;
        let mut follows = Vec::new();
        for row in rows {
            follows.push(row?);
        }
        Ok(follows)
    }

    fn follow_source_rows(
        conn: &Connection,
        account_id_hex: &str,
    ) -> Result<Vec<String>, AppError> {
        let mut statement = conn.prepare(
            "SELECT relay_url FROM directory_follow_source_relays
             WHERE account_id_hex = ?1
             ORDER BY position, relay_url",
        )?;
        let rows = statement.query_map([account_id_hex], |row| row.get::<_, String>(0))?;
        let mut relays = Vec::new();
        for row in rows {
            relays.push(row?);
        }
        Ok(relays)
    }

    fn migrate_legacy_json_records(&self) -> Result<(), AppError> {
        let mut conn = self.lock();
        if !Self::table_exists_locked(&conn, "user_directory_records")? {
            return Ok(());
        }
        let tx = conn.transaction()?;
        let mut statement =
            tx.prepare("SELECT entry_json FROM user_directory_records ORDER BY account_id_hex")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut json_entries = Vec::new();
        for row in rows {
            json_entries.push(row?);
        }
        drop(statement);

        for json in json_entries {
            let entry = serde_json::from_str::<UserDirectoryRecord>(&json)?;
            Self::put_with_reason_locked(&tx, &entry, "directory")?;
        }
        tx.execute_batch("DROP TABLE IF EXISTS user_directory_records;")?;
        tx.commit()?;
        Ok(())
    }

    #[cfg(test)]
    fn table_exists(&self, table: &str) -> Result<bool, AppError> {
        let conn = self.lock();
        Self::table_exists_locked(&conn, table)
    }

    fn table_exists_locked(conn: &Connection, table: &str) -> Result<bool, AppError> {
        conn.query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [table],
            |_| Ok(()),
        )
        .optional()
        .map(|value| value.is_some())
        .map_err(AppError::from)
    }
}

fn record_directory_cache_open() {
    tracing::debug!(
        target: "marmot_app::directory",
        method = "directory_cache_open",
        "opening directory cache"
    );
}

struct DirectoryUserRow {
    account_id_hex: String,
    npub: String,
    local_account_json: Option<String>,
    profile_json: Option<String>,
    relay_lists_json: String,
    key_package_json: Option<String>,
}

struct SearchGraphUserRow {
    account_id_hex: String,
    npub: String,
    profile_json: Option<String>,
    follows_known: bool,
}

pub(crate) struct DirectorySearchGraphRecord {
    pub(crate) account_id_hex: String,
    pub(crate) npub: String,
    pub(crate) profile: Option<UserProfileMetadata>,
    pub(crate) follows: Option<Vec<String>>,
    pub(crate) metadata_updated_at: Option<u64>,
    pub(crate) metadata_expires_at: Option<u64>,
}

fn initialize_schema(conn: &Connection) -> Result<(), AppError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS directory_users (
            account_id_hex TEXT PRIMARY KEY NOT NULL,
            npub TEXT NOT NULL,
            local_account_json TEXT,
            profile_json TEXT,
            relay_lists_json TEXT NOT NULL,
            key_package_json TEXT,
            updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS directory_user_follows (
            account_id_hex TEXT NOT NULL,
            follow_account_id_hex TEXT NOT NULL,
            position INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            PRIMARY KEY (account_id_hex, follow_account_id_hex)
        );
        CREATE INDEX IF NOT EXISTS directory_user_follows_follow_idx
            ON directory_user_follows(follow_account_id_hex);
        CREATE TABLE IF NOT EXISTS directory_follow_source_relays (
            account_id_hex TEXT NOT NULL,
            relay_url TEXT NOT NULL,
            position INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            PRIMARY KEY (account_id_hex, relay_url)
        );
        CREATE TABLE IF NOT EXISTS directory_known_user_reasons (
            account_id_hex TEXT NOT NULL,
            reason TEXT NOT NULL,
            first_seen_at INTEGER NOT NULL,
            last_seen_at INTEGER NOT NULL,
            PRIMARY KEY (account_id_hex, reason)
        );
        CREATE TABLE IF NOT EXISTS directory_search_graph_users (
            account_id_hex TEXT PRIMARY KEY NOT NULL,
            npub TEXT NOT NULL,
            profile_json TEXT,
            metadata_updated_at INTEGER,
            metadata_expires_at INTEGER,
            follows_known INTEGER NOT NULL DEFAULT 0,
            follows_updated_at INTEGER,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS directory_search_graph_follows (
            account_id_hex TEXT NOT NULL,
            follow_account_id_hex TEXT NOT NULL,
            position INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            PRIMARY KEY (account_id_hex, follow_account_id_hex)
        );
        CREATE INDEX IF NOT EXISTS directory_search_graph_follows_follow_idx
            ON directory_search_graph_follows(follow_account_id_hex);",
    )?;
    Ok(())
}

fn directory_user_row_from_row(
    row: &rusqlite::Row<'_>,
) -> Result<DirectoryUserRow, rusqlite::Error> {
    Ok(DirectoryUserRow {
        account_id_hex: row.get(0)?,
        npub: row.get(1)?,
        local_account_json: row.get(2)?,
        profile_json: row.get(3)?,
        relay_lists_json: row.get(4)?,
        key_package_json: row.get(5)?,
    })
}

fn optional_json<T>(value: &Option<T>) -> Result<Option<String>, AppError>
where
    T: Serialize,
{
    value
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(AppError::from)
}

fn optional_value<T>(json: Option<String>) -> Result<Option<T>, AppError>
where
    T: DeserializeOwned,
{
    json.map(|json| serde_json::from_str(&json))
        .transpose()
        .map_err(AppError::from)
}

fn unix_now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::npub_for_account_id_lossy;
    use crate::{AccountRelayListStatus, UserProfileMetadata};

    fn test_cache() -> (tempfile::TempDir, DirectoryCache) {
        let dir = tempfile::tempdir().unwrap();
        let key = SqlCipherKey::new("test-key").unwrap();
        let cache = DirectoryCache::open(dir.path().join("directory.sqlite3"), &key).unwrap();
        (dir, cache)
    }

    fn account_id(value: u8) -> String {
        format!("{value:064x}")
    }

    fn directory_record(account_id_hex: String, follows: Vec<String>) -> UserDirectoryRecord {
        UserDirectoryRecord {
            npub: npub_for_account_id_lossy(&account_id_hex),
            account_id_hex,
            local_account: None,
            profile: Some(UserProfileMetadata {
                name: Some("alice".to_owned()),
                display_name: None,
                about: None,
                picture: None,
                nip05: None,
                lud16: None,
                created_at: 1_700_000_001,
                source_relays: vec!["wss://profiles.example".to_owned()],
            }),
            follows,
            follow_source_relays: vec!["wss://follows.example".to_owned()],
            relay_lists: AccountRelayListStatus::empty(),
            key_package: None,
        }
    }

    #[test]
    fn put_persists_directory_record_in_structured_tables() {
        let (_dir, cache) = test_cache();
        let alice = account_id(1);
        let bob = account_id(2);

        cache
            .put(&directory_record(alice.clone(), vec![bob.clone()]))
            .unwrap();

        let conn = cache.lock();
        let user_count: i64 = conn
            .query_row(
                "SELECT count(*) FROM directory_users WHERE account_id_hex = ?1",
                [&alice],
                |row| row.get(0),
            )
            .unwrap();
        let follows = conn
            .prepare(
                "SELECT follow_account_id_hex FROM directory_user_follows
                 WHERE account_id_hex = ?1
                 ORDER BY position",
            )
            .unwrap()
            .query_map([&alice], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(user_count, 1);
        assert_eq!(follows, vec![bob]);
    }

    #[test]
    fn search_graph_record_does_not_create_known_directory_entry() {
        let (_dir, cache) = test_cache();
        let carol = account_id(3);
        let dave = account_id(4);

        cache
            .put_search_graph_record(
                &DirectorySearchGraphRecord {
                    npub: npub_for_account_id_lossy(&carol),
                    account_id_hex: carol.clone(),
                    profile: Some(UserProfileMetadata {
                        name: Some("carol".to_owned()),
                        display_name: None,
                        about: None,
                        picture: None,
                        nip05: None,
                        lud16: None,
                        created_at: 1_700_000_002,
                        source_relays: Vec::new(),
                    }),
                    follows: Some(vec![dave.clone()]),
                    metadata_updated_at: Some(1_700_000_002),
                    metadata_expires_at: None,
                },
                1_700_000_003,
            )
            .unwrap();

        assert!(cache.entry(&carol).unwrap().is_none());
        let search_record = cache.search_record(&carol).unwrap().unwrap();
        assert_eq!(
            search_record.profile.and_then(|profile| profile.name),
            Some("carol".to_owned())
        );
        assert_eq!(search_record.follows, vec![dave]);
    }

    #[test]
    fn open_migrates_legacy_json_records_into_structured_tables() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("directory.sqlite3");
        let key = SqlCipherKey::new("test-key").unwrap();
        let conn = Connection::open(&path).unwrap();
        conn.pragma_update(None, "key", key.as_secret_str())
            .unwrap();
        let _: i64 = conn
            .query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))
            .unwrap();
        let alice = account_id(1);
        let bob = account_id(2);
        conn.execute_batch(
            "CREATE TABLE user_directory_records (
                account_id_hex TEXT PRIMARY KEY NOT NULL,
                entry_json TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO user_directory_records (account_id_hex, entry_json, updated_at)
             VALUES (?1, ?2, ?3)",
            params![
                &alice,
                serde_json::to_string(&directory_record(alice.clone(), vec![bob.clone()])).unwrap(),
                1_700_000_001_i64,
            ],
        )
        .unwrap();
        drop(conn);

        let cache = DirectoryCache::open(path, &key).unwrap();
        let entry = cache.entry(&alice).unwrap().unwrap();
        let conn = cache.lock();
        let user_count: i64 = conn
            .query_row("SELECT count(*) FROM directory_users", [], |row| row.get(0))
            .unwrap();
        drop(conn);
        let legacy_table_exists = cache.table_exists("user_directory_records").unwrap();

        assert_eq!(entry.follows, vec![bob]);
        assert_eq!(user_count, 1);
        assert!(!legacy_table_exists);
    }
}
