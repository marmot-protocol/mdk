mod migrations;

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use serde::de::DeserializeOwned;
use storage_sqlite::{
    CloseableConnection, ConnectionGuard, SqlCipherHardening, SqlCipherKey, open_hardened_sqlcipher,
};

use crate::{AccountRelayListStatus, AppError, UserDirectoryRecord, UserProfileMetadata};

/// How long a `kind:0` profile resolved by web-of-trust search stays usable
/// before search re-fetches it.
///
/// Only profiles that were actually *found* are cached. A fetch that comes back
/// empty is deliberately not recorded as "this account publishes no profile":
/// the directory fetch cannot currently distinguish every relay cleanly
/// answering "nothing here" from relays that failed to answer at all, so
/// caching that ambiguity would make someone unfindable for a day after a
/// transient outage. The price is re-querying accounts that genuinely have no
/// profile; the alternative risks hiding accounts that do.
pub(crate) const SEARCH_GRAPH_PROFILE_TTL_SECONDS: i64 = 24 * 60 * 60;

/// Message carried by every storage error this cache raises after a close.
const CLOSED_DETAIL: &str = "directory cache is closed";

#[cfg(test)]
thread_local! {
    // Count successful writes before an injected failure, even if SQLite has
    // already rolled back the transaction when it returns SQLITE_FULL.
    static LEGACY_RECORDS_CONVERTED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[derive(Clone, Debug)]
pub(crate) struct DirectoryCache {
    conn: Arc<CloseableConnection>,
    #[cfg(test)]
    put_count: Arc<AtomicUsize>,
}

impl DirectoryCache {
    pub(crate) fn open(path: PathBuf, key: &SqlCipherKey) -> Result<Self, AppError> {
        record_directory_cache_open();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        // Pre-create 0600 so SQLite's -wal/-shm sidecars (which copy the main
        // file's mode) never appear at umask-default permissions, and tighten
        // sidecars left behind by earlier permissive builds.
        fs_private::ensure_private_db_files(&path)?;
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
        // Legacy plaintext caches (and their sidecars) predate the owner-only
        // creation policy; tighten them before reading.
        fs_private::ensure_private_db_files(&path)?;
        let conn = Connection::open(path)?;
        let _: i64 = conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))?;
        Self::from_connection(conn).map(Some)
    }

    fn from_connection(mut conn: Connection) -> Result<Self, AppError> {
        migrations::run_all(&mut conn)?;
        let cache = Self {
            conn: Arc::new(CloseableConnection::new(conn, CLOSED_DETAIL)),
            #[cfg(test)]
            put_count: Arc::new(AtomicUsize::new(0)),
        };
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

    /// Close this cache's database, releasing its file handle and any locks.
    /// Terminal and idempotent: later reads and writes fail with a closed
    /// storage error and nothing reopens.
    pub(crate) fn close(&self) -> Result<(), AppError> {
        Ok(self.conn.close()?)
    }

    fn lock(&self) -> Result<ConnectionGuard<'_>, AppError> {
        Ok(self.conn.lock()?)
    }

    pub(crate) fn entry(
        &self,
        account_id_hex: &str,
    ) -> Result<Option<UserDirectoryRecord>, AppError> {
        let conn = self.lock()?;
        let Some(row) = Self::directory_user_row(&conn, account_id_hex)? else {
            return Ok(None);
        };
        Self::record_from_directory_user_row(&conn, row).map(Some)
    }

    pub(crate) fn entries(&self) -> Result<Vec<UserDirectoryRecord>, AppError> {
        let conn = self.lock()?;
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

    /// Look an account up for search: the promoted directory tier first, then
    /// the un-promoted search graph.
    ///
    /// `now` is Unix seconds and decides whether a cached search-graph profile
    /// has expired. It is a parameter rather than read from the clock here so
    /// one traversal resolves a whole layer against a single instant, and so
    /// expiry is directly testable.
    pub(crate) fn search_record(
        &self,
        account_id_hex: &str,
        now: i64,
    ) -> Result<Option<UserDirectoryRecord>, AppError> {
        if let Some(record) = self.entry(account_id_hex)? {
            return Ok(Some(record));
        }
        self.search_graph_record(account_id_hex, now)
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
        let mut conn = self.lock()?;
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

    /// The un-promoted search-graph record for an account, ignoring the
    /// promoted directory entirely.
    ///
    /// Callers that have already consulted the promoted tier want this rather
    /// than [`Self::search_record`]: a promoted row exists for reasons that
    /// carry no profile, and letting it answer would hide the profile cached
    /// here.
    pub(crate) fn search_graph_record(
        &self,
        account_id_hex: &str,
        now: i64,
    ) -> Result<Option<UserDirectoryRecord>, AppError> {
        let conn = self.lock()?;
        let Some(row) = conn
            .query_row(
                "SELECT account_id_hex, npub, profile_json, follows_known, metadata_expires_at
             FROM directory_search_graph_users
             WHERE account_id_hex = ?1",
                [account_id_hex],
                |row| {
                    Ok(SearchGraphUserRow {
                        account_id_hex: row.get(0)?,
                        npub: row.get(1)?,
                        profile_json: row.get(2)?,
                        follows_known: row.get::<_, i64>(3)? != 0,
                        metadata_expires_at: row.get(4)?,
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
        // Only the profile expires. Follow edges keep their own freshness, so a
        // stale profile must not take the account's graph edges down with it.
        let profile = match row.metadata_expires_at {
            Some(expires_at) if expires_at <= now => None,
            _ => optional_value(row.profile_json)?,
        };
        Ok(Some(UserDirectoryRecord {
            account_id_hex: row.account_id_hex,
            npub: row.npub,
            local_account: None,
            profile,
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
                // An empty `directory_users` follow list often means this
                // promotion path has not observed a contact list. Do not let
                // that absence erase independently discovered search-graph
                // edges; an explicit `Some([])` from the graph writer still
                // records a known-empty contact list.
                follows: (!entry.follows.is_empty()).then(|| entry.follows.clone()),
                metadata_updated_at: entry.profile.as_ref().map(|profile| profile.created_at),
                metadata_expires_at: None,
            },
            now,
        )
    }

    /// Follow edges recorded for `account_id_hex` in the un-promoted search
    /// graph.
    ///
    /// `None` means no contact list has been observed for them yet, which is
    /// different from `Some(vec![])` -- an observed list that follows nobody.
    /// Traversal needs the distinction: the first is a candidate to fetch, the
    /// second is a settled dead end.
    pub(crate) fn search_graph_follows(
        &self,
        account_id_hex: &str,
    ) -> Result<Option<Vec<String>>, AppError> {
        let conn = self.lock()?;
        let known = conn
            .query_row(
                "SELECT follows_known FROM directory_search_graph_users WHERE account_id_hex = ?1",
                [account_id_hex],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some_and(|known| known != 0);
        if !known {
            return Ok(None);
        }
        Self::follow_rows(&conn, "directory_search_graph_follows", account_id_hex).map(Some)
    }

    /// Record one account in the un-promoted search graph.
    ///
    /// The counterpart to [`Self::remember_search_graph_follows`] for profile
    /// metadata: it never touches `directory_users`, so an account cached here
    /// stays invisible to `directory_sync_plan` and can never become a live
    /// per-author subscription (mdk#687).
    pub(crate) fn put_search_graph_record(
        &self,
        record: &DirectorySearchGraphRecord,
        now: i64,
    ) -> Result<(), AppError> {
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        Self::put_search_graph_record_locked(&tx, record, now)?;
        tx.commit()?;
        Ok(())
    }

    /// Record a remote contact list's follow edges in the search graph without
    /// promoting the author or its follows into known directory entries
    /// (`directory_users`). This keeps follow edges available for bounded
    /// directory search while avoiding the unbounded social-graph crawl that
    /// promoting every follow would trigger (mdk#687). The author's
    /// cached profile metadata in the search graph is preserved; only the
    /// follow edges are replaced.
    pub(crate) fn remember_search_graph_follows(
        &self,
        account_id_hex: &str,
        npub: &str,
        follows: &[String],
    ) -> Result<(), AppError> {
        let now = unix_now_seconds() as i64;
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO directory_search_graph_users (
                account_id_hex,
                npub,
                follows_known,
                follows_updated_at,
                created_at,
                updated_at
             )
             VALUES (?1, ?2, 1, ?3, ?3, ?3)
             ON CONFLICT(account_id_hex) DO UPDATE SET
                npub = excluded.npub,
                follows_known = 1,
                follows_updated_at = excluded.follows_updated_at,
                updated_at = excluded.updated_at",
            params![account_id_hex, npub, now],
        )?;
        Self::replace_follow_rows(
            &tx,
            "directory_search_graph_follows",
            account_id_hex,
            follows,
            now,
        )?;
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
                follows_known = CASE
                    WHEN ?9 THEN excluded.follows_known
                    ELSE directory_search_graph_users.follows_known
                END,
                follows_updated_at = CASE
                    WHEN ?9 THEN excluded.follows_updated_at
                    ELSE directory_search_graph_users.follows_updated_at
                END,
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
                follows_known,
            ],
        )?;
        if let Some(follows) = &record.follows {
            Self::replace_follow_rows(
                conn,
                "directory_search_graph_follows",
                &record.account_id_hex,
                follows,
                now,
            )?;
        }
        Ok(())
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

    fn migrate_legacy_json_records(conn: &Connection) -> Result<(), AppError> {
        if !Self::table_exists_locked(conn, "user_directory_records")? {
            return Ok(());
        }
        let mut statement =
            conn.prepare("SELECT entry_json FROM user_directory_records ORDER BY account_id_hex")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut json_entries = Vec::new();
        for row in rows {
            json_entries.push(row?);
        }
        drop(statement);

        for json in json_entries {
            let entry = serde_json::from_str::<UserDirectoryRecord>(&json)?;
            Self::put_with_reason_locked(conn, &entry, "directory")?;
            #[cfg(test)]
            LEGACY_RECORDS_CONVERTED.with(|count| count.set(count.get() + 1));
        }
        conn.execute_batch("DROP TABLE user_directory_records;")?;
        Ok(())
    }

    #[cfg(test)]
    fn table_exists(&self, table: &str) -> Result<bool, AppError> {
        let conn = self.lock()?;
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
    metadata_expires_at: Option<i64>,
}

pub(crate) struct DirectorySearchGraphRecord {
    pub(crate) account_id_hex: String,
    pub(crate) npub: String,
    pub(crate) profile: Option<UserProfileMetadata>,
    pub(crate) follows: Option<Vec<String>>,
    pub(crate) metadata_updated_at: Option<u64>,
    pub(crate) metadata_expires_at: Option<u64>,
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
                banner: None,
                nip05: None,
                lud16: None,
                created_at: 1_700_000_001,
                source_relays: vec!["wss://profiles.example".to_owned()],
                extra: Default::default(),
            }),
            follows,
            follow_source_relays: vec!["wss://follows.example".to_owned()],
            relay_lists: AccountRelayListStatus::empty(),
            key_package: None,
        }
    }

    fn migration_rows(conn: &Connection) -> Vec<(i64, String)> {
        conn.prepare("SELECT version, name FROM app_cache_schema_migrations ORDER BY version")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    #[test]
    fn migration_fresh_encrypted_cache_and_reopen_are_idempotent() {
        let (dir, cache) = test_cache();
        {
            let conn = cache.lock().unwrap();
            assert_eq!(
                migration_rows(&conn),
                vec![(1, "0001_directory_cache".into())]
            );
            let count: i64 = conn.query_row(
                "SELECT count(*) FROM sqlite_master WHERE name LIKE 'directory_%' AND type IN ('table', 'index')",
                [], |row| row.get(0)).unwrap();
            assert_eq!(count, 8);
            // A repeated migration would attempt to insert or update this ledger.
            conn.execute_batch("CREATE TRIGGER prevent_migration_insert BEFORE INSERT ON app_cache_schema_migrations BEGIN SELECT RAISE(ABORT, 'rerun'); END;
                CREATE TRIGGER prevent_migration_update BEFORE UPDATE ON app_cache_schema_migrations BEGIN SELECT RAISE(ABORT, 'rerun'); END;").unwrap();
        }
        cache.close().unwrap();
        let key = SqlCipherKey::new("test-key").unwrap();
        let cache = DirectoryCache::open(dir.path().join("directory.sqlite3"), &key).unwrap();
        assert_eq!(
            migration_rows(&cache.lock().unwrap()),
            vec![(1, "0001_directory_cache".into())]
        );
    }

    #[test]
    fn migration_adopts_unversioned_cache_preserving_both_tiers() {
        let (dir, cache) = test_cache();
        let record = directory_record(account_id(1), vec![account_id(2)]);
        cache.put(&record).unwrap();
        cache
            .remember_search_graph_follows(&account_id(3), "search-only", &[account_id(4)])
            .unwrap();
        cache
            .lock()
            .unwrap()
            .execute_batch("DROP TABLE app_cache_schema_migrations")
            .unwrap();
        cache.close().unwrap();
        let key = SqlCipherKey::new("test-key").unwrap();
        let cache = DirectoryCache::open(dir.path().join("directory.sqlite3"), &key).unwrap();
        assert_eq!(
            cache.entry(&record.account_id_hex).unwrap().unwrap(),
            record
        );
        assert!(cache.entry(&account_id(3)).unwrap().is_none());
        assert_eq!(
            cache.search_graph_follows(&account_id(3)).unwrap(),
            Some(vec![account_id(4)])
        );
        assert_eq!(migration_rows(&cache.lock().unwrap()).len(), 1);
    }

    #[test]
    fn migration_refuses_future_version_and_unexpected_name() {
        let (dir, cache) = test_cache();
        cache
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO app_cache_schema_migrations VALUES (2, 'private-name', 0)",
                [],
            )
            .unwrap();
        cache.close().unwrap();
        let key = SqlCipherKey::new("test-key").unwrap();
        let path = dir.path().join("directory.sqlite3");
        assert!(matches!(
            DirectoryCache::open(path.clone(), &key),
            Err(AppError::Storage(
                cgka_traits::storage::StorageError::UnsupportedSchemaVersion {
                    found: 2,
                    latest_supported: 1
                }
            ))
        ));
        let conn = Connection::open(&path).unwrap();
        open_hardened_sqlcipher(&conn, &key, SqlCipherHardening::live_cache()).unwrap();
        conn.execute_batch(
            "DELETE FROM app_cache_schema_migrations WHERE version = 2;
            UPDATE app_cache_schema_migrations SET name = 'private-name'",
        )
        .unwrap();
        drop(conn);
        let error = DirectoryCache::open(path, &key).unwrap_err();
        assert!(!error.to_string().contains("private-name"));
    }

    #[test]
    fn migration_partial_schema_is_not_adopted() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE directory_users (account_id_hex TEXT PRIMARY KEY NOT NULL)",
        )
        .unwrap();
        assert!(migrations::run_all(&mut conn).is_err());
        assert!(
            !DirectoryCache::table_exists_locked(&conn, "directory_search_graph_users").unwrap()
        );
        assert!(
            !DirectoryCache::table_exists_locked(&conn, "app_cache_schema_migrations").unwrap()
        );
    }

    #[test]
    fn migration_legacy_failure_rolls_back_schema_and_data() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE user_directory_records (account_id_hex TEXT PRIMARY KEY, entry_json TEXT NOT NULL)").unwrap();
        conn.execute(
            "INSERT INTO user_directory_records VALUES ('a', ?1)",
            [
                serde_json::to_string(&directory_record(account_id(1), vec![account_id(2)]))
                    .unwrap(),
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO user_directory_records VALUES ('b', ?1)",
            [r#"{"account_id_hex": "private-profile", "npub": 123}"#],
        )
        .unwrap();
        let error = migrations::run_all(&mut conn).unwrap_err();
        assert!(!error.to_string().contains("private-profile"));
        assert!(!DirectoryCache::table_exists_locked(&conn, "directory_users").unwrap());
        assert!(
            !DirectoryCache::table_exists_locked(&conn, "app_cache_schema_migrations").unwrap()
        );
        let count: i64 = conn
            .query_row("SELECT count(*) FROM user_directory_records", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(count, 2);
        conn.execute(
            "DELETE FROM user_directory_records WHERE account_id_hex = 'b'",
            [],
        )
        .unwrap();
        migrations::run_all(&mut conn).unwrap();
        assert_eq!(migration_rows(&conn).len(), 1);
        assert!(!DirectoryCache::table_exists_locked(&conn, "user_directory_records").unwrap());
    }

    #[test]
    #[cfg(unix)]
    fn directory_cache_db_is_owner_only_on_disk() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let key = SqlCipherKey::new("test-key").unwrap();
        let path = dir.path().join("directory.sqlite3");
        let _cache = DirectoryCache::open(path.clone(), &key).unwrap();

        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    #[cfg(unix)]
    fn stale_permissive_cache_db_and_sidecars_are_tightened_on_open() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let key = SqlCipherKey::new("test-key").unwrap();
        let path = dir.path().join("directory.sqlite3");
        drop(DirectoryCache::open(path.clone(), &key).unwrap());

        // Simulate artifacts from a permissive build: loosen the main DB and
        // plant loose-mode sidecars. SQLite does not rewrite pre-existing
        // sidecar modes just because the main file is tightened.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        for suffix in ["-wal", "-shm", "-journal"] {
            let sidecar = dir.path().join(format!("directory.sqlite3{suffix}"));
            std::fs::write(&sidecar, b"stale").unwrap();
            std::fs::set_permissions(&sidecar, std::fs::Permissions::from_mode(0o644)).unwrap();
        }

        drop(DirectoryCache::open(path.clone(), &key).unwrap());

        for suffix in ["", "-wal", "-shm", "-journal"] {
            let file = dir.path().join(format!("directory.sqlite3{suffix}"));
            if let Ok(metadata) = std::fs::metadata(&file) {
                assert_eq!(
                    metadata.permissions().mode() & 0o777,
                    0o600,
                    "suffix {suffix:?} must be owner-only after reopen"
                );
            }
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

        let conn = cache.lock().unwrap();
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
                        banner: None,
                        nip05: None,
                        lud16: None,
                        created_at: 1_700_000_002,
                        source_relays: Vec::new(),
                        extra: Default::default(),
                    }),
                    follows: Some(vec![dave.clone()]),
                    metadata_updated_at: Some(1_700_000_002),
                    metadata_expires_at: None,
                },
                1_700_000_003,
            )
            .unwrap();

        assert!(cache.entry(&carol).unwrap().is_none());
        let search_record = cache.search_record(&carol, 1_700_000_003).unwrap().unwrap();
        assert_eq!(
            search_record.profile.and_then(|profile| profile.name),
            Some("carol".to_owned())
        );
        assert_eq!(search_record.follows, vec![dave]);
    }

    /// A profile the search graph resolved is usable until it expires, and
    /// invisible afterwards, so a warm search never serves a stale profile and
    /// a cold one re-fetches instead of trusting the cache forever.
    #[test]
    fn an_expired_search_graph_profile_stops_being_served() {
        let (_dir, cache) = test_cache();
        let carol = account_id(3);
        let dave = account_id(4);
        let cached_at = 1_700_000_000;
        let expires_at = cached_at + SEARCH_GRAPH_PROFILE_TTL_SECONDS;

        cache
            .put_search_graph_record(
                &DirectorySearchGraphRecord {
                    npub: npub_for_account_id_lossy(&carol),
                    account_id_hex: carol.clone(),
                    profile: Some(UserProfileMetadata {
                        name: Some("carol".to_owned()),
                        created_at: cached_at as u64,
                        ..UserProfileMetadata::default()
                    }),
                    follows: Some(vec![dave.clone()]),
                    metadata_updated_at: Some(cached_at as u64),
                    metadata_expires_at: Some(expires_at as u64),
                },
                cached_at,
            )
            .unwrap();

        let fresh = cache
            .search_record(&carol, expires_at - 1)
            .unwrap()
            .expect("a record cached inside its TTL is still known");
        assert_eq!(
            fresh.profile.and_then(|profile| profile.name),
            Some("carol".to_owned())
        );

        let stale = cache
            .search_record(&carol, expires_at + 1)
            .unwrap()
            .expect("expiry hides the profile, it does not erase the account");
        assert!(
            stale.profile.is_none(),
            "an expired profile must fall through to a fresh fetch"
        );
        // Follow edges carry their own freshness and are not collateral of a
        // profile expiring -- dropping them would silently shrink the graph.
        assert_eq!(stale.follows, vec![dave]);
    }

    /// Traversal must tell "we have never seen this account's contact list"
    /// from "we have, and they follow nobody". Collapsing the two either
    /// re-fetches a known-empty list on every search, or treats a never-fetched
    /// account as a dead end and silently truncates the graph.
    #[test]
    fn search_graph_follows_separate_unknown_from_known_empty() {
        let (_dir, cache) = test_cache();
        let never_seen = account_id(1);
        let follows_nobody = account_id(2);
        let follows_someone = account_id(3);
        let friend = account_id(4);

        cache
            .remember_search_graph_follows(
                &follows_nobody,
                &npub_for_account_id_lossy(&follows_nobody),
                &[],
            )
            .unwrap();
        cache
            .remember_search_graph_follows(
                &follows_someone,
                &npub_for_account_id_lossy(&follows_someone),
                std::slice::from_ref(&friend),
            )
            .unwrap();

        assert_eq!(cache.search_graph_follows(&never_seen).unwrap(), None);
        assert_eq!(
            cache.search_graph_follows(&follows_nobody).unwrap(),
            Some(Vec::new())
        );
        assert_eq!(
            cache.search_graph_follows(&follows_someone).unwrap(),
            Some(vec![friend])
        );
    }

    #[test]
    fn directory_user_promotion_preserves_search_graph_only_follows() {
        let (_dir, cache) = test_cache();
        let alice = account_id(1);
        let bob = account_id(2);

        cache
            .remember_search_graph_follows(
                &alice,
                &npub_for_account_id_lossy(&alice),
                std::slice::from_ref(&bob),
            )
            .unwrap();
        cache
            .put(&directory_record(alice.clone(), Vec::new()))
            .unwrap();

        let graph_record = cache
            .search_graph_record(&alice, unix_now_seconds() as i64)
            .unwrap()
            .unwrap();
        assert_eq!(graph_record.follows, vec![bob]);
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
        let conn = cache.lock().unwrap();
        let user_count: i64 = conn
            .query_row("SELECT count(*) FROM directory_users", [], |row| row.get(0))
            .unwrap();
        drop(conn);
        let legacy_table_exists = cache.table_exists("user_directory_records").unwrap();

        assert_eq!(entry.follows, vec![bob]);
        assert_eq!(user_count, 1);
        assert!(!legacy_table_exists);
        assert_eq!(migration_rows(&cache.lock().unwrap()).len(), 1);
    }
}
