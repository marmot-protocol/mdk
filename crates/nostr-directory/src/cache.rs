mod migrations;

use super::unix_now_seconds;
use crate::error::DirectoryError;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
#[cfg(any(test, feature = "test-support"))]
use std::sync::atomic::{AtomicUsize, Ordering};

use rusqlite::functions::FunctionFlags;
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OptionalExtension, params, params_from_iter};
use serde::Serialize;
use serde::de::DeserializeOwned;
use storage_sqlite::{
    CloseableConnection, ConnectionGuard, SqlCipherHardening, SqlCipherKey, open_hardened_sqlcipher,
};

use crate::{AccountRelayListStatus, UserDirectoryRecord, UserProfileMetadata};

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
pub const SEARCH_GRAPH_PROFILE_TTL_SECONDS: i64 = 24 * 60 * 60;

/// Message carried by every storage error this cache raises after a close.
const CLOSED_DETAIL: &str = "directory cache is closed";
// Stay below SQLite's historical 999-variable limit.
const PROFILE_QUERY_BATCH_SIZE: usize = 900;

type SearchProfile = (
    storage_sqlite::PublicDirectoryProfileRecord,
    Option<u64>,
    u8,
);

#[cfg(test)]
thread_local! {
    // Count successful writes before an injected failure, even if SQLite has
    // already rolled back the transaction when it returns SQLITE_FULL.
    static LEGACY_RECORDS_CONVERTED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[derive(Clone, Debug)]
pub struct DirectoryCache {
    conn: Arc<CloseableConnection>,
    #[cfg(any(test, feature = "test-support"))]
    put_count: Arc<AtomicUsize>,
}

impl DirectoryCache {
    pub fn open(path: PathBuf, key: &SqlCipherKey) -> Result<Self, DirectoryError> {
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

    pub fn open_legacy_plaintext(path: PathBuf) -> Result<Option<Self>, DirectoryError> {
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

    fn from_connection(mut conn: Connection) -> Result<Self, DirectoryError> {
        migrations::run_all(&mut conn)?;
        conn.create_scalar_function(
            "marmot_search_rank",
            2,
            FunctionFlags::SQLITE_UTF8
                | FunctionFlags::SQLITE_DETERMINISTIC
                | FunctionFlags::SQLITE_INNOCUOUS,
            |ctx| {
                let (ValueRef::Text(haystack), ValueRef::Text(query)) =
                    (ctx.get_raw(0), ctx.get_raw(1))
                else {
                    return Ok(3_u8);
                };
                let (Ok(haystack), Ok(query)) =
                    (std::str::from_utf8(haystack), std::str::from_utf8(query))
                else {
                    return Ok(3_u8);
                };
                Ok(search_match_quality(haystack, query))
            },
        )?;
        let cache = Self {
            conn: Arc::new(CloseableConnection::new(conn, CLOSED_DETAIL)),
            #[cfg(any(test, feature = "test-support"))]
            put_count: Arc::new(AtomicUsize::new(0)),
        };
        Ok(cache)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn put_count_for_test(&self) -> usize {
        self.put_count.load(Ordering::SeqCst)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn reset_put_count_for_test(&self) {
        self.put_count.store(0, Ordering::SeqCst);
    }

    /// Close this cache's database, releasing its file handle and any locks.
    /// Terminal and idempotent: later reads and writes fail with a closed
    /// storage error and nothing reopens. `MarmotApp::close_storage` closes
    /// caches through [`Self::closer`].
    #[cfg(test)]
    pub(crate) fn close(&self) -> Result<(), DirectoryError> {
        Ok(self.conn.close()?)
    }

    /// A closer for this cache's database that does not keep it open.
    pub fn closer(&self) -> storage_sqlite::DatabaseCloser {
        self.conn.closer()
    }

    pub(crate) fn lock(&self) -> Result<ConnectionGuard<'_>, DirectoryError> {
        Ok(self.conn.lock()?)
    }

    pub fn entry(
        &self,
        account_id_hex: &str,
    ) -> Result<Option<UserDirectoryRecord>, DirectoryError> {
        let conn = self.lock()?;
        let Some(row) = Self::directory_user_row(&conn, account_id_hex)? else {
            return Ok(None);
        };
        Self::record_from_directory_user_row(&conn, row).map(Some)
    }

    pub fn entries(&self) -> Result<Vec<UserDirectoryRecord>, DirectoryError> {
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

    pub(crate) fn profiles_for_ids(
        &self,
        account_ids: &[String],
    ) -> Result<Vec<(String, Option<UserProfileMetadata>)>, DirectoryError> {
        let conn = self.lock()?;
        let mut profiles = Vec::new();
        for ids in account_ids.chunks(PROFILE_QUERY_BATCH_SIZE) {
            let placeholders = std::iter::repeat_n("?", ids.len())
                .collect::<Vec<_>>()
                .join(",");
            let mut statement = conn.prepare_cached(&format!(
                "SELECT account_id_hex, profile_json FROM directory_users
                 WHERE account_id_hex IN ({placeholders})"
            ))?;
            let rows = statement.query_map(params_from_iter(ids), |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
            })?;
            for row in rows {
                let (id, json) = row?;
                profiles.push((id, optional_value(json)?));
            }
        }
        Ok(profiles)
    }

    /// Public identity/profile fields only: no follow, key-package, or local-label reads.
    /// Profile-less promoted identities remain searchable by npub or pubkey.
    /// Search includes un-promoted profiles without making them sync candidates.
    /// Empty IDs return up to 10,000 matching identities; requested IDs also return nonmatches.
    /// Rank is quality * 6 + field (name, nip05, display_name, about, npub, pubkey);
    /// exact, prefix, and contains qualities are 0, 1, and 2. Ranks >= 18 do not match.
    /// The caller normalizes `query`; haystacks are Unicode-lowercased without trimming.
    pub(crate) fn public_search_records(
        &self,
        now: i64,
        query: &str,
        account_ids: &[String],
    ) -> Result<Vec<SearchProfile>, DirectoryError> {
        let conn = self.lock()?;
        let mut records = Vec::new();
        let mut read_batch = |ids: &[String]| -> Result<(), DirectoryError> {
            let id_filter = if ids.is_empty() {
                String::new()
            } else {
                let placeholders = (3..ids.len() + 3)
                    .map(|index| format!("?{index}"))
                    .collect::<Vec<_>>()
                    .join(",");
                format!("AND account_id_hex IN ({placeholders})")
            };
            let scan_filter = if ids.is_empty() {
                "WHERE search_rank < 18 ORDER BY account_id_hex LIMIT 10000"
            } else {
                "ORDER BY account_id_hex"
            };
            // Select the current winner before testing its text. A newer,
            // nonmatching profile must suppress an older matching tier.
            let mut statement = conn.prepare_cached(&format!(
                "WITH candidates AS (
                     SELECT account_id_hex, npub, profile_json
                     FROM directory_users AS promoted
                     WHERE NOT EXISTS (
                         SELECT 1 FROM directory_search_graph_users AS graph
                         WHERE graph.account_id_hex = promoted.account_id_hex
                           AND graph.profile_json IS NOT NULL
                           AND (graph.metadata_expires_at IS NULL OR graph.metadata_expires_at > ?1)
                           AND COALESCE(json_extract(graph.profile_json, '$.created_at'), 0)
                             > CASE WHEN promoted.profile_json IS NULL THEN -1
                               ELSE COALESCE(json_extract(promoted.profile_json, '$.created_at'), 0) END
                     ) {id_filter}
                     UNION ALL
                     SELECT account_id_hex, npub, profile_json
                     FROM directory_search_graph_users AS graph
                     WHERE profile_json IS NOT NULL
                       AND (metadata_expires_at IS NULL OR metadata_expires_at > ?1)
                       AND NOT EXISTS (
                           SELECT 1 FROM directory_users AS promoted
                           WHERE promoted.account_id_hex = graph.account_id_hex
                             AND CASE WHEN promoted.profile_json IS NULL THEN -1
                                 ELSE COALESCE(json_extract(promoted.profile_json, '$.created_at'), 0) END
                               >= COALESCE(json_extract(graph.profile_json, '$.created_at'), 0)
                       ) {id_filter}
                 ), ranked AS (
                     SELECT account_id_hex, npub, profile_json,
                         CASE WHEN profile_json IS NULL THEN NULL
                             ELSE COALESCE(profile_json -> '$.created_at', '0') END AS created_at,
                         min(
                             marmot_search_rank(json_extract(profile_json, '$.name'), ?2) * 6,
                             marmot_search_rank(json_extract(profile_json, '$.nip05'), ?2) * 6 + 1,
                             marmot_search_rank(json_extract(profile_json, '$.display_name'), ?2) * 6 + 2,
                             marmot_search_rank(json_extract(profile_json, '$.about'), ?2) * 6 + 3,
                             marmot_search_rank(npub, ?2) * 6 + 4,
                             marmot_search_rank(account_id_hex, ?2) * 6 + 5
                         ) AS search_rank
                     FROM candidates
                 )
                 SELECT account_id_hex, npub, profile_json, created_at, search_rank
                 FROM ranked {scan_filter}"
            ))?;
            let parameters = [ValueRef::Integer(now), ValueRef::Text(query.as_bytes())];
            let rows = statement.query_map(
                params_from_iter(
                    parameters
                        .into_iter()
                        .chain(ids.iter().map(|id| ValueRef::Text(id.as_bytes())))
                        .map(rusqlite::types::ToSqlOutput::Borrowed),
                ),
                |row| {
                    Ok((
                        storage_sqlite::PublicDirectoryProfileRecord {
                            account_id_hex: row.get(0)?,
                            npub: row.get(1)?,
                            profile_json: row.get(2)?,
                        },
                        row.get::<_, Option<String>>(3)?
                            .map(|value| {
                                value.parse::<u64>().map_err(|error| {
                                    rusqlite::Error::FromSqlConversionFailure(
                                        3,
                                        rusqlite::types::Type::Text,
                                        Box::new(error),
                                    )
                                })
                            })
                            .transpose()?,
                        row.get(4)?,
                    ))
                },
            )?;
            for row in rows {
                records.push(row?);
            }
            Ok(())
        };
        if account_ids.is_empty() {
            read_batch(account_ids)?;
        } else {
            for ids in account_ids.chunks(PROFILE_QUERY_BATCH_SIZE) {
                read_batch(ids)?;
            }
        }
        Ok(records)
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
    ) -> Result<Option<UserDirectoryRecord>, DirectoryError> {
        if let Some(record) = self.entry(account_id_hex)? {
            return Ok(Some(record));
        }
        self.search_graph_record(account_id_hex, now)
    }

    pub fn put(&self, entry: &UserDirectoryRecord) -> Result<(), DirectoryError> {
        self.put_with_reason(entry, "directory")
    }

    pub(crate) fn put_with_reason(
        &self,
        entry: &UserDirectoryRecord,
        reason: &str,
    ) -> Result<(), DirectoryError> {
        #[cfg(any(test, feature = "test-support"))]
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
    ) -> Result<(), DirectoryError> {
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
    ) -> Result<Option<DirectoryUserRow>, DirectoryError> {
        conn.query_row(
            "SELECT account_id_hex, npub, local_account_json, profile_json,
                    relay_lists_json, key_package_json
             FROM directory_users
             WHERE account_id_hex = ?1",
            [account_id_hex],
            directory_user_row_from_row,
        )
        .optional()
        .map_err(DirectoryError::from)
    }

    fn record_from_directory_user_row(
        conn: &Connection,
        row: DirectoryUserRow,
    ) -> Result<UserDirectoryRecord, DirectoryError> {
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
    ) -> Result<Option<UserDirectoryRecord>, DirectoryError> {
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
    ) -> Result<(), DirectoryError> {
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
    ) -> Result<Option<Vec<String>>, DirectoryError> {
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
    ) -> Result<(), DirectoryError> {
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
    ) -> Result<(), DirectoryError> {
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
    ) -> Result<(), DirectoryError> {
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
    ) -> Result<(), DirectoryError> {
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
    ) -> Result<(), DirectoryError> {
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
    ) -> Result<(), DirectoryError> {
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
    ) -> Result<Vec<String>, DirectoryError> {
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
    ) -> Result<Vec<String>, DirectoryError> {
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

    fn migrate_legacy_json_records(conn: &Connection) -> Result<(), DirectoryError> {
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
    fn table_exists(&self, table: &str) -> Result<bool, DirectoryError> {
        let conn = self.lock()?;
        Self::table_exists_locked(&conn, table)
    }

    fn table_exists_locked(conn: &Connection, table: &str) -> Result<bool, DirectoryError> {
        conn.query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [table],
            |_| Ok(()),
        )
        .optional()
        .map(|value| value.is_some())
        .map_err(DirectoryError::from)
    }
}

fn search_match_quality(haystack: &str, query: &str) -> u8 {
    if query.is_empty() {
        return 3;
    }
    if haystack.is_ascii() {
        if !query.is_ascii() {
            return 3;
        }
        let haystack = haystack.as_bytes();
        let query = query.as_bytes();
        if haystack.eq_ignore_ascii_case(query) {
            0
        } else if haystack
            .get(..query.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(query))
        {
            1
        } else if haystack
            .windows(query.len())
            .any(|part| part.eq_ignore_ascii_case(query))
        {
            2
        } else {
            3
        }
    } else {
        let haystack = haystack.to_lowercase();
        if haystack == query {
            0
        } else if haystack.starts_with(query) {
            1
        } else if haystack.contains(query) {
            2
        } else {
            3
        }
    }
}

fn record_directory_cache_open() {
    tracing::debug!(
        target: "nostr_directory::cache",
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

pub struct DirectorySearchGraphRecord {
    pub account_id_hex: String,
    pub npub: String,
    pub profile: Option<UserProfileMetadata>,
    pub follows: Option<Vec<String>>,
    pub metadata_updated_at: Option<u64>,
    pub metadata_expires_at: Option<u64>,
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

fn optional_json<T>(value: &Option<T>) -> Result<Option<String>, DirectoryError>
where
    T: Serialize,
{
    value
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(DirectoryError::from)
}

fn optional_value<T>(json: Option<String>) -> Result<Option<T>, DirectoryError>
where
    T: DeserializeOwned,
{
    json.map(|json| serde_json::from_str(&json))
        .transpose()
        .map_err(DirectoryError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::npub_for_account_id_lossy;
    use crate::{AccountRelayListStatus, UserProfileMetadata};

    #[test]
    fn profile_batch_skips_metadata() {
        use rusqlite::trace::{TraceEvent, TraceEventCodes};
        thread_local! {
            static SELECTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
        }
        let (_root, cache) = test_cache();
        cache.lock().unwrap().execute(
            "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<1000)
             INSERT INTO directory_users(account_id_hex,npub,profile_json,relay_lists_json,updated_at)
             SELECT printf('%064x',x),'npub',NULL,?1,0 FROM n;",
            [serde_json::to_string(&AccountRelayListStatus::empty()).unwrap()],
        ).unwrap();
        let ids = (1..=1000)
            .map(|id| format!("{id:064x}"))
            .collect::<Vec<_>>();
        cache.lock().unwrap().trace_v2(
            TraceEventCodes::SQLITE_TRACE_STMT,
            Some(|event| {
                if let TraceEvent::Stmt(_, sql) = event
                    && sql.starts_with("SELECT")
                {
                    SELECTS.set(SELECTS.get() + 1);
                }
            }),
        );
        for id in &ids {
            assert!(cache.entry(id).unwrap().is_some());
        }
        assert_eq!(SELECTS.replace(0), 3000);
        assert_eq!(cache.profiles_for_ids(&ids).unwrap().len(), ids.len());
        assert_eq!(SELECTS.replace(0), 2);
        cache
            .lock()
            .unwrap()
            .trace_v2(TraceEventCodes::empty(), None);
        cache
            .lock()
            .unwrap()
            .execute("UPDATE directory_users SET relay_lists_json = 'broken'", [])
            .unwrap();
        assert!(cache.entry(&ids[0]).is_err());
        assert!(cache.profiles_for_ids(&[]).unwrap().is_empty());
        assert_eq!(cache.profiles_for_ids(&ids).unwrap().len(), ids.len());
        let selected = cache.profiles_for_ids(&ids[10..12]).unwrap();
        assert_eq!(selected.len(), 2);
        assert!(selected.iter().all(|(id, _)| ids[10..12].contains(id)));
    }

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
    fn public_search_materialization_stops_at_its_cap() {
        let (_dir, cache) = test_cache();
        {
            let conn = cache.lock().unwrap();
            // Deliberately not deserializable as UserProfileMetadata: the raw
            // projection must not decode even a matching profile.
            conn.execute(
                "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<10002)
                 INSERT INTO directory_users(account_id_hex,npub,profile_json,relay_lists_json,updated_at)
                 SELECT printf('%064x',x),'npub',
                     json_object('created_at',1,'name',CASE WHEN x=1 THEN 'other' ELSE 'alice' END,
                                 'source_relays',42), '{}', 0 FROM n",
                [],
            ).unwrap();
            conn.execute(
                "INSERT INTO directory_search_graph_users
                     (account_id_hex,npub,profile_json,created_at,updated_at)
                 SELECT account_id_hex,npub,profile_json,0,0 FROM directory_users",
                [],
            )
            .unwrap();
        }
        // Mirrored rows consume one identity slot, not two.
        let rows = cache.public_search_records(i64::MAX, "alice", &[]).unwrap();
        assert_eq!(rows.len(), 10000);
        assert_eq!(rows[0].0.account_id_hex, format!("{:064x}", 2));
        assert_eq!(rows[9999].0.account_id_hex, format!("{:064x}", 10001));
        assert!(
            rows.iter()
                .all(|(_, timestamp, rank)| *timestamp == Some(1) && *rank == 0)
        );

        // Requested IDs bypass the candidate cap and matching predicate, and
        // cross SQLite's historical variable bound without losing winners.
        let ids = (1..=10002)
            .map(|id| format!("{id:064x}"))
            .collect::<Vec<_>>();
        let rows = cache.public_search_records(0, "alice", &ids).unwrap();
        assert_eq!(rows.len(), ids.len());
        assert_eq!(rows[0].0.account_id_hex, ids[0]);
        assert_eq!(rows[0].2, 18);
        assert_eq!(rows.last().unwrap().0.account_id_hex, ids[10001]);
    }

    #[test]
    fn public_search_uses_current_profile_across_tiers() {
        let (_dir, cache) = test_cache();
        let mut promoted = directory_record(account_id(1), vec![]);
        cache.put(&promoted).unwrap();
        let mut newer = promoted.profile.clone().unwrap();
        newer.created_at += 1;
        newer.name = Some("new name".into());
        let mut graph = DirectorySearchGraphRecord {
            account_id_hex: account_id(1),
            npub: "npub-new".into(),
            profile: Some(newer.clone()),
            follows: None,
            metadata_updated_at: Some(newer.created_at),
            metadata_expires_at: Some(10),
        };
        cache.put_search_graph_record(&graph, 0).unwrap();
        assert!(
            cache
                .public_search_records(0, "alice", &[])
                .unwrap()
                .is_empty()
        );
        let ids = [account_id(1)];
        let rows = cache.public_search_records(0, "alice", &ids).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].0.profile_json,
            optional_json(&Some(newer.clone())).unwrap()
        );
        assert_eq!(rows[0].1, Some(newer.created_at));
        assert_eq!(rows[0].2, 18);

        // Expiry makes the promoted profile current again at the exact bound.
        let rows = cache.public_search_records(10, "alice", &[]).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].2, 0);

        // The promoted tier wins ties, and a newer nonmatch there likewise
        // suppresses an older matching graph profile.
        promoted.profile = Some(newer.clone());
        cache.put(&promoted).unwrap();
        let mut older = newer.clone();
        older.name = Some("alice".into());
        graph.profile = Some(older.clone());
        graph.metadata_expires_at = None;
        cache.put_search_graph_record(&graph, 0).unwrap();
        assert!(
            cache
                .public_search_records(0, "alice", &[])
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            cache.public_search_records(0, "new name", &[]).unwrap()[0]
                .0
                .npub,
            promoted.npub
        );
        older.created_at -= 1;
        graph.profile = Some(older);
        cache.put_search_graph_record(&graph, 0).unwrap();
        assert!(
            cache
                .public_search_records(0, "alice", &[])
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            cache.public_search_records(0, "alice", &ids).unwrap()[0]
                .0
                .profile_json,
            optional_json(&promoted.profile).unwrap()
        );
    }

    #[test]
    fn public_search_ranks_unicode_and_literal_fields_without_trimming() {
        let (_dir, cache) = test_cache();
        let mut promoted = directory_record(account_id(1), vec![]);
        promoted.profile = None;
        promoted.npub = "npub-IDENTITY".into();
        cache.put(&promoted).unwrap();
        let rows = cache
            .public_search_records(0, "npub-identity", &[])
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!((rows[0].1, rows[0].2), (None, 4));
        assert_eq!(
            cache.public_search_records(0, &account_id(1), &[]).unwrap()[0].2,
            5
        );

        for (field, value, query, expected) in [
            ("name", "ÉCOLE", "école", Some(0)),
            ("name", "\u{212a}elvin", "kelvin", Some(0)),
            ("name", "İ", "i\u{307}", Some(0)),
            ("name", "ÉCOLE du soir", "école", Some(6)),
            ("name", "une ÉCOLE ici", "école", Some(12)),
            ("name", " ÉCOLE ", "école", Some(12)),
            ("name", "50%_done", "50%_", Some(6)),
            ("name", "500xdone", "50%_", None),
            ("nip05", "ÉCOLE", "école", Some(1)),
            ("display_name", "ÉCOLE", "école", Some(2)),
            ("about", "ÉCOLE", "école", Some(3)),
        ] {
            let json = serde_json::json!({field: value});
            cache
                .lock()
                .unwrap()
                .execute(
                    "UPDATE directory_users SET profile_json = ?1",
                    [json.to_string()],
                )
                .unwrap();
            let rows = cache.public_search_records(0, query, &[]).unwrap();
            assert_eq!(
                rows.first().map(|row| row.2),
                expected,
                "{field}: {value:?}"
            );
            if let Some(row) = rows.first() {
                assert_eq!(row.1, Some(0));
            }
        }
    }

    #[test]
    fn migration_fresh_encrypted_cache_and_reopen_are_idempotent() {
        let (dir, cache) = test_cache();
        {
            let conn = cache.lock().unwrap();
            assert_eq!(
                migration_rows(&conn),
                vec![
                    (1, "0001_directory_cache".into()),
                    (2, "0002_public_event_previews".into())
                ]
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
        assert_eq!(migration_rows(&cache.lock().unwrap()).len(), 2);
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
            // An unversioned cache predates every later migration.
            .execute_batch(
                "DROP TABLE app_cache_schema_migrations; DROP TABLE public_event_previews",
            )
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
        assert_eq!(migration_rows(&cache.lock().unwrap()).len(), 2);
    }

    #[test]
    fn migration_refuses_future_version_and_unexpected_name() {
        let (dir, cache) = test_cache();
        cache
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO app_cache_schema_migrations VALUES (3, 'private-name', 0)",
                [],
            )
            .unwrap();
        cache.close().unwrap();
        let key = SqlCipherKey::new("test-key").unwrap();
        let path = dir.path().join("directory.sqlite3");
        assert!(matches!(
            DirectoryCache::open(path.clone(), &key),
            Err(DirectoryError::Storage(
                cgka_traits::storage::StorageError::UnsupportedSchemaVersion {
                    found: 3,
                    latest_supported: 2
                }
            ))
        ));
        let conn = Connection::open(&path).unwrap();
        open_hardened_sqlcipher(&conn, &key, SqlCipherHardening::live_cache()).unwrap();
        conn.execute_batch(
            "DELETE FROM app_cache_schema_migrations WHERE version = 3;
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
        assert_eq!(migration_rows(&conn).len(), 2);
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
        assert_eq!(migration_rows(&cache.lock().unwrap()).len(), 2);
    }
}
