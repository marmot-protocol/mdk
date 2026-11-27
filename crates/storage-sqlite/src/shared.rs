mod error;
mod migrations;
mod presentation;
pub use presentation::{DirectoryPresentation, DirectoryPresentationChanges};

use error::SharedSqliteResultExt;

use crate::base::codec::unix_now_seconds_i64;
use crate::base::connection::CachedSql;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use crate::base::connection::{CloseableConnection, ConnectionGuard};
use crate::{
    base::connection::retry_on_busy, bool_i64, optional_u64_to_i64, u64_to_i64, unix_now_ms,
    usize_to_i64,
};
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{
    Connection, OptionalExtension, Transaction, TransactionBehavior, params, params_from_iter,
};

const SHARED_BUSY_TIMEOUT_MS: u64 = 5_000;

/// Defensive upper bound on how many public-directory users
/// [`SqliteSharedStorage::public_directory_users`] materializes at once (#761).
/// The public directory is populated from network data, so without a cap a
/// hostile or simply large cache could be loaded unboundedly into memory. Set
/// well above the app-layer directory-search reachability
/// (`USER_DIRECTORY_SEARCH_MAX_VISITED` == 8192) so it never truncates a
/// realistic result set; a warn fires if it is ever hit.
const PUBLIC_DIRECTORY_USERS_MAX: usize = 10_000;

type SearchProfile = (PublicDirectoryProfileRecord, Option<u64>, u8);

/// Message carried by every [`StorageError::Closed`] this module raises.
const CLOSED_DETAIL: &str = "sqlite shared storage is closed";

#[derive(Clone, Debug)]
pub struct SqliteSharedStorage {
    /// Closeable because this database is opened in WAL mode: an open
    /// connection holds a persistent lock on its `-shm` sidecar, so a host that
    /// must be lock-free at suspension needs an explicit close, not a dropped
    /// clone.
    conn: Arc<CloseableConnection>,
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
    /// Event `created_at` of the kind-3 contact list backing `follows`.
    /// Zero denotes unknown or legacy recency.
    pub follows_created_at: u64,
}

/// Public identity/profile projection for search; excludes follows, relay lists,
/// key packages, and event provenance that search does not consume.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicDirectoryProfileRecord {
    pub account_id_hex: String,
    pub npub: String,
    pub profile_json: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKeyPackageReplacementRecord {
    pub account_id_hex: String,
    pub key_package_id: String,
    pub event_id_hex: String,
    pub event_created_at: u64,
    pub observed_at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicKeyPackageBarrierKind {
    Replacement,
    Deletion,
    ExactDeletion,
}

impl PublicKeyPackageBarrierKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Replacement => "replacement",
            Self::Deletion => "deletion",
            Self::ExactDeletion => "exact_deletion",
        }
    }
}

/// Supersession metadata without KeyPackage bytes. A target fences that exact
/// publication; no target fences the slot through `event_created_at`.
/// All timestamps are Unix seconds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKeyPackageBarrierRecord {
    pub account_id_hex: String,
    pub key_package_id: String,
    pub event_id_hex: String,
    pub deleted_event_id: Option<String>,
    pub event_created_at: u64,
    pub observed_at: u64,
    pub kind: PublicKeyPackageBarrierKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKeyPackageEvidenceSnapshot {
    pub replacements: Vec<PublicKeyPackageReplacementRecord>,
    pub global_eviction: Option<PublicKeyPackageBarrierRecord>,
    pub barriers: Vec<PublicKeyPackageBarrierRecord>,
    pub watermark: Option<PublicKeyPackageBarrierRecord>,
    pub revision: i64,
}

const KEY_PACKAGE_REPLACEMENT_GLOBAL_CAP: i64 = 1_000;
const KEY_PACKAGE_REPLACEMENT_CAP: i64 = 500;
const KEY_PACKAGE_EVIDENCE_MAX_AGE_SECS: i64 = 30 * 24 * 60 * 60;
const KEY_PACKAGE_EVIDENCE_FUTURE_SKEW_SECS: i64 = 5 * 60;

/// The newest creation time whose KeyPackage evidence a prune at `now` drops.
fn key_package_evidence_stale_before(now: i64) -> i64 {
    now.saturating_sub(KEY_PACKAGE_EVIDENCE_MAX_AGE_SECS + KEY_PACKAGE_EVIDENCE_FUTURE_SKEW_SECS)
}

/// Whether the KeyPackage journal still keeps evidence of a publication
/// created at `event_created_at`. Only a write prunes what this rejects, so a
/// reader can meet a row past the bound and must not count it.
pub fn public_key_package_evidence_retained(event_created_at: u64, now: u64) -> bool {
    let stale_before = key_package_evidence_stale_before(i64::try_from(now).unwrap_or(i64::MAX));
    i64::try_from(event_created_at).is_ok_and(|created_at| created_at > stale_before)
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

/// Host-configured local audit retention. The app owns defaults and bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoredAuditLogRetention {
    pub max_age_days: u32,
    pub max_bytes_per_account: u64,
}

/// Installation-local consent receipt. 0 = acceptance required, 1 = declined, 2 = granted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StoredUsageDiagnosticsSettings {
    pub decision: u8,
    pub policy_revision: String,
    pub registry_revision: String,
    pub scope_revision: String,
    pub updated_at_ms: i64,
    /// Immutable migration history, retained even after a new consent decision.
    pub previously_enabled: bool,
}

impl SqliteSharedStorage {
    pub fn usage_diagnostics_settings(&self) -> StorageResult<StoredUsageDiagnosticsSettings> {
        self.lock()?
            .query_row_cached(
                "SELECT decision, policy_revision, registry_revision, scope_revision,
                        updated_at_ms, previously_enabled
                 FROM usage_diagnostics_settings WHERE id = 1",
                [],
                |r| {
                    Ok(StoredUsageDiagnosticsSettings {
                        decision: r.get(0)?,
                        policy_revision: r.get(1)?,
                        registry_revision: r.get(2)?,
                        scope_revision: r.get(3)?,
                        updated_at_ms: r.get(4)?,
                        previously_enabled: r.get(5)?,
                    })
                },
            )
            .storage()
    }

    /// Consent and diagnostic identity change in one transaction. No key is stored here.
    pub fn set_usage_diagnostics_settings(
        &self,
        settings: &StoredUsageDiagnosticsSettings,
        install_id: Option<&str>,
    ) -> StorageResult<()> {
        retry_on_busy(|| {
            let mut conn = self.lock()?;
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .storage()?;
            tx.execute(
                "UPDATE usage_diagnostics_settings
                 SET decision=?1, policy_revision=?2, registry_revision=?3,
                     scope_revision=?4, updated_at_ms=?5
                 WHERE id=1",
                params![
                    settings.decision,
                    settings.policy_revision,
                    settings.registry_revision,
                    settings.scope_revision,
                    settings.updated_at_ms
                ],
            )
            .storage()?;
            tx.execute("DELETE FROM telemetry_install", []).storage()?;
            if let Some(id) = install_id {
                tx.execute(
                    "INSERT INTO telemetry_install (id, install_id, updated_at_ms)
                     VALUES (1, ?1, ?2)",
                    params![id, settings.updated_at_ms],
                )
                .storage()?;
            }
            tx.commit().storage()
        })
    }

    pub fn open(path: impl AsRef<Path>) -> StorageResult<Self> {
        let path = path.as_ref();
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs_private::create_dir_all_private(parent)
                .map_err(|err| StorageError::Backend(err.to_string()))?;
        }
        // The shared cache is unencrypted, so file-level 0600 (including
        // sidecars) is the only thing keeping it from other local users.
        crate::base::connection::ensure_private_db_files(path)?;
        let conn = rusqlite::Connection::open(path).storage()?;
        Self::from_connection(conn)
    }

    pub fn in_memory() -> StorageResult<Self> {
        Self::from_connection(rusqlite::Connection::open_in_memory().storage()?)
    }

    /// Checkpoint the WAL and close this shared database, releasing its file
    /// locks. Terminal and idempotent, with the same contract as
    /// [`SqliteAccountStorage::close`][crate::SqliteAccountStorage::close]:
    /// surviving clones fail with [`StorageError::Closed`] and nothing
    /// reopens.
    pub fn close(&self) -> StorageResult<()> {
        self.conn.close()
    }

    /// Whether [`Self::close`] has run on this database.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.conn.is_closed()
    }

    /// A [`DatabaseCloser`][crate::DatabaseCloser] for this database, shared
    /// by every clone.
    #[must_use]
    pub fn closer(&self) -> crate::DatabaseCloser {
        self.conn.closer()
    }

    fn from_connection(mut conn: rusqlite::Connection) -> StorageResult<Self> {
        conn.busy_timeout(Duration::from_millis(SHARED_BUSY_TIMEOUT_MS))
            .storage()?;
        conn.pragma_update(None, "foreign_keys", true).storage()?;
        conn.pragma_update(None, "trusted_schema", false)
            .storage()?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA temp_store = MEMORY;",
        )
        .storage()?;
        migrations::run_all(&mut conn)?;
        crate::base::text_search::register_search_functions(&conn).storage()?;
        conn.create_scalar_function(
            "marmot_is_valid_u64",
            1,
            rusqlite::functions::FunctionFlags::SQLITE_UTF8
                | rusqlite::functions::FunctionFlags::SQLITE_DETERMINISTIC
                | rusqlite::functions::FunctionFlags::SQLITE_INNOCUOUS,
            |ctx| match ctx.get_raw(0) {
                rusqlite::types::ValueRef::Text(bytes) => Ok(std::str::from_utf8(bytes)
                    .ok()
                    .is_some_and(|s| s.parse::<u64>().is_ok())),
                _ => Ok(false),
            },
        )
        .storage()?;
        Ok(Self {
            conn: Arc::new(CloseableConnection::new(conn, CLOSED_DETAIL)),
        })
    }

    pub fn put_public_key_package_replacement(
        &self,
        record: &PublicKeyPackageReplacementRecord,
    ) -> StorageResult<()> {
        retry_on_busy(|| {
            let mut conn = self.lock()?;
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .storage()?;
            let changed = tx.execute_cached(
                    "INSERT INTO directory_key_package_replacements (
                        account_id_hex, key_package_id, event_id_hex,
                        event_created_at, observed_at
                     )
                     VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT(account_id_hex, key_package_id) DO UPDATE SET
                        event_id_hex = excluded.event_id_hex,
                        event_created_at = excluded.event_created_at,
                        observed_at = CASE
                            WHEN directory_key_package_replacements.event_id_hex = excluded.event_id_hex
                            THEN directory_key_package_replacements.observed_at
                            ELSE excluded.observed_at
                        END
                     WHERE excluded.event_created_at >
                           directory_key_package_replacements.event_created_at
                        OR (excluded.event_created_at =
                            directory_key_package_replacements.event_created_at
                            AND excluded.event_id_hex <
                                directory_key_package_replacements.event_id_hex)",
                    params![
                        &record.account_id_hex,
                        &record.key_package_id,
                        &record.event_id_hex,
                        u64_to_i64(record.event_created_at)?,
                        u64_to_i64(record.observed_at)?,
                    ],
                )
                .storage()?;
            if changed != 0 {
                bump_key_package_revision(&tx, &record.account_id_hex)?;
            }
            prune_key_package_replacements(&tx)?;
            prune_key_package_barriers(&tx, unix_now_seconds_i64())?;
            tx.commit().storage()
        })
    }

    pub fn public_key_package_replacements(
        &self,
        account_id_hex: &str,
    ) -> StorageResult<Vec<PublicKeyPackageReplacementRecord>> {
        Self::read_key_package_replacements(&*self.lock()?, account_id_hex)
    }

    fn read_key_package_replacements(
        conn: &Connection,
        account_id_hex: &str,
    ) -> StorageResult<Vec<PublicKeyPackageReplacementRecord>> {
        let mut statement = conn
            .prepare_cached(
                "SELECT account_id_hex, key_package_id, event_id_hex,
                        event_created_at, observed_at
                 FROM directory_key_package_replacements
                 WHERE account_id_hex = ?1
                 ORDER BY key_package_id",
            )
            .storage()?;
        statement
            .query_map(params![account_id_hex], |row| {
                Ok(PublicKeyPackageReplacementRecord {
                    account_id_hex: row.get(0)?,
                    key_package_id: row.get(1)?,
                    event_id_hex: row.get(2)?,
                    event_created_at: u64::try_from(row.get::<_, i64>(3)?).unwrap_or(0),
                    observed_at: u64::try_from(row.get::<_, i64>(4)?).unwrap_or(0),
                })
            })
            .storage()?
            .map(|row| row.storage())
            .collect()
    }

    pub fn key_package_evidence_revision(&self, account_id_hex: &str) -> StorageResult<i64> {
        Self::read_key_package_evidence_revision(&*self.lock()?, account_id_hex)
    }

    fn read_key_package_evidence_revision(
        conn: &Connection,
        account_id_hex: &str,
    ) -> StorageResult<i64> {
        conn.query_row_cached(
            "SELECT revision FROM public_key_package_evidence_revisions
             WHERE account_id_hex = ?1",
            params![account_id_hex],
            |row| row.get(0),
        )
        .optional()
        .storage()
        .map(|revision| revision.unwrap_or(0))
    }

    pub fn key_package_evidence_snapshot(
        &self,
        account_id_hex: &str,
    ) -> StorageResult<PublicKeyPackageEvidenceSnapshot> {
        let mut conn = self.lock()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .storage()?;
        Ok(PublicKeyPackageEvidenceSnapshot {
            replacements: Self::read_key_package_replacements(&tx, account_id_hex)?,
            global_eviction: Self::read_key_package_global_eviction(&tx)?,
            barriers: Self::read_key_package_barriers(&tx, account_id_hex)?,
            watermark: Self::read_key_package_eviction_watermark(&tx, account_id_hex)?,
            revision: Self::read_key_package_evidence_revision(&tx, account_id_hex)?,
        })
    }

    pub fn put_public_key_package_barrier(
        &self,
        record: &PublicKeyPackageBarrierRecord,
    ) -> StorageResult<()> {
        retry_on_busy(|| {
            let mut conn = self.lock()?;
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .storage()?;
            if write_key_package_barrier(&tx, record)? {
                bump_key_package_revision(&tx, &record.account_id_hex)?;
            }
            prune_key_package_barriers(&tx, unix_now_seconds_i64())?;
            tx.commit().storage()
        })
    }

    pub fn public_key_package_barriers(
        &self,
        account_id_hex: &str,
    ) -> StorageResult<Vec<PublicKeyPackageBarrierRecord>> {
        Self::read_key_package_barriers(&*self.lock()?, account_id_hex)
    }

    fn read_key_package_barriers(
        conn: &Connection,
        account_id_hex: &str,
    ) -> StorageResult<Vec<PublicKeyPackageBarrierRecord>> {
        let mut statement = conn
            .prepare_cached(
                "SELECT account_id_hex, key_package_id, event_id_hex,
                        deleted_event_id, event_created_at, observed_at, kind
                 FROM public_key_package_barriers
                 WHERE account_id_hex = ?1
                 ORDER BY key_package_id, deleted_event_id",
            )
            .storage()?;
        statement
            .query_map(params![account_id_hex], key_package_barrier_from_row)
            .storage()?
            .map(|row| row.storage())
            .collect()
    }

    /// Latest retained observation, falling back to account or global eviction metadata.
    /// A global fallback does not prove freshness for an account without a watermark.
    pub fn public_key_package_evicted_at(
        &self,
        account_id_hex: &str,
    ) -> StorageResult<Option<u64>> {
        self.lock()?
                .query_row_cached(
                    "SELECT COALESCE(
                        (SELECT MAX(observed_at) FROM public_key_package_barriers
                     WHERE account_id_hex = ?1),
                        (SELECT evicted_at FROM public_key_package_eviction_watermarks
                         WHERE account_id_hex = ?1),
                        (SELECT evicted_at FROM public_key_package_eviction_fallback WHERE id = 1))",
                    params![account_id_hex],
                    |row| {
                        Ok(row
                            .get::<_, Option<i64>>(0)?
                            .map(|value| u64::try_from(value).unwrap_or(0)))
                    },
                )
                .storage()
    }

    pub fn key_package_global_eviction(
        &self,
    ) -> StorageResult<Option<PublicKeyPackageBarrierRecord>> {
        Self::read_key_package_global_eviction(&*self.lock()?)
    }

    fn read_key_package_global_eviction(
        conn: &Connection,
    ) -> StorageResult<Option<PublicKeyPackageBarrierRecord>> {
        conn.query_row_cached(
            "SELECT '', '', event_id_hex, NULL, event_created_at, evicted_at, kind
             FROM public_key_package_eviction_fallback WHERE id = 1",
            [],
            key_package_barrier_from_row,
        )
        .optional()
        .storage()
    }

    pub fn public_key_package_replacement_evicted_at(
        &self,
        account_id_hex: &str,
    ) -> StorageResult<Option<u64>> {
        self.public_key_package_evicted_at(account_id_hex)
    }

    /// Newest pruned barrier in NIP-01 order. `observed_at` is its eviction time.
    pub fn public_key_package_eviction_watermark(
        &self,
        account_id_hex: &str,
    ) -> StorageResult<Option<PublicKeyPackageBarrierRecord>> {
        Self::read_key_package_eviction_watermark(&*self.lock()?, account_id_hex)
    }

    fn read_key_package_eviction_watermark(
        conn: &Connection,
        account_id_hex: &str,
    ) -> StorageResult<Option<PublicKeyPackageBarrierRecord>> {
        conn.query_row_cached(
            "SELECT account_id_hex, key_package_id, event_id_hex,
                    deleted_event_id, event_created_at, evicted_at, kind
             FROM public_key_package_eviction_watermarks
             WHERE account_id_hex = ?1",
            params![account_id_hex],
            key_package_barrier_from_row,
        )
        .optional()
        .storage()
    }

    pub fn put_public_directory_user(
        &self,
        record: &PublicDirectoryUserRecord,
    ) -> StorageResult<()> {
        retry_on_busy(|| {
            let mut conn = self.lock()?;
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .storage()?;
            tx.execute_cached(
                "INSERT INTO directory_users (
                account_id_hex, npub, profile_json, relay_lists_json, key_package_json,
                event_id_hex, event_kind, event_created_at, follows_created_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(account_id_hex) DO UPDATE SET
                npub = excluded.npub,
                profile_json = excluded.profile_json,
                relay_lists_json = excluded.relay_lists_json,
                key_package_json = excluded.key_package_json,
                event_id_hex = excluded.event_id_hex,
                event_kind = excluded.event_kind,
                event_created_at = excluded.event_created_at,
                follows_created_at = excluded.follows_created_at",
                params![
                    &record.account_id_hex,
                    &record.npub,
                    &record.profile_json,
                    &record.relay_lists_json,
                    &record.key_package_json,
                    &record.event_id_hex,
                    optional_u64_to_i64(record.event_kind)?,
                    optional_u64_to_i64(record.event_created_at)?,
                    u64_to_i64(record.follows_created_at)?,
                ],
            )
            .storage()?;
            tx.execute_cached(
                "DELETE FROM directory_user_follows WHERE account_id_hex = ?1",
                params![&record.account_id_hex],
            )
            .storage()?;
            for (position, follow) in record.follows.iter().enumerate() {
                tx.execute_cached(
                    "INSERT OR IGNORE INTO directory_user_follows (
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
        })
    }

    pub fn public_directory_user(
        &self,
        account_id_hex: &str,
    ) -> StorageResult<Option<PublicDirectoryUserRecord>> {
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
        let Some(mut record) = tx
            .query_row_cached(
                "SELECT account_id_hex, npub, profile_json, relay_lists_json,
                        key_package_json, event_id_hex, event_kind, event_created_at,
                        follows_created_at
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
                        follows_created_at: u64::try_from(row.get::<_, i64>(8)?).unwrap_or(0),
                    })
                },
            )
            .optional()
            .storage()?
        else {
            tx.commit().storage()?;
            return Ok(None);
        };
        let mut stmt = tx
            .prepare_cached(
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
        drop(stmt);
        tx.commit().storage()?;
        Ok(Some(record))
    }

    pub fn public_directory_users(&self) -> StorageResult<Vec<PublicDirectoryUserRecord>> {
        self.public_directory_users_capped(PUBLIC_DIRECTORY_USERS_MAX)
    }

    /// Read raw profiles, their timestamps, and ranks for a normalized query.
    /// Empty IDs scan at most 10,000 matching identities in account-ID order.
    /// Requested IDs include nonmatches so newer profiles suppress stale matches
    /// in other caches. Follow edges and unrelated JSON are not read.
    pub fn public_directory_profiles(
        &self,
        query: &str,
        account_ids: &[String],
    ) -> StorageResult<Vec<SearchProfile>> {
        // Evaluate profile validity and effective search rank inside SQL so
        // malformed `profile_json` rows (invalid JSON, non-object JSON, or
        // non-u64 `created_at`) degrade to identity-only rank *before*
        // `WHERE search_rank < 18 ... LIMIT` applies.
        let build_query = |inner_where: &str, outer_suffix: &str| {
            format!(
                "SELECT account_id_hex, npub, profile_json, created_at_token,
                        search_rank, malformed_profile
                 FROM (
                     SELECT account_id_hex,
                            npub,
                            CASE WHEN created_at_token IS NOT NULL
                                   AND marmot_is_valid_u64(created_at_token)
                                 THEN profile_json
                                 ELSE NULL
                            END AS profile_json,
                            CASE WHEN created_at_token IS NOT NULL
                                   AND marmot_is_valid_u64(created_at_token)
                                 THEN created_at_token
                                 ELSE NULL
                            END AS created_at_token,
                            CASE WHEN created_at_token IS NOT NULL
                                   AND marmot_is_valid_u64(created_at_token)
                                 THEN min(
                                     marmot_search_rank(json_extract(profile_json, '$.name'), ?1) * 6,
                                     marmot_search_rank(json_extract(profile_json, '$.nip05'), ?1) * 6 + 1,
                                     marmot_search_rank(json_extract(profile_json, '$.display_name'), ?1) * 6 + 2,
                                     marmot_search_rank(json_extract(profile_json, '$.about'), ?1) * 6 + 3,
                                     identity_rank
                                 )
                                 ELSE identity_rank
                            END AS search_rank,
                            (profile_json IS NOT NULL
                             AND (created_at_token IS NULL
                                  OR NOT marmot_is_valid_u64(created_at_token))) AS malformed_profile
                     FROM (
                         SELECT account_id_hex,
                                npub,
                                profile_json,
                                CASE
                                    WHEN profile_json IS NULL THEN NULL
                                    WHEN NOT json_valid(profile_json) THEN 'invalid'
                                    WHEN json_type(profile_json) != 'object' THEN 'invalid'
                                    ELSE COALESCE(profile_json -> '$.created_at', '0')
                                END AS created_at_token,
                                min(
                                    marmot_search_rank(npub, ?1) * 6 + 4,
                                    marmot_search_rank(account_id_hex, ?1) * 6 + 5
                                ) AS identity_rank
                         FROM directory_users
                         {inner_where}
                     )
                 )
                 {outer_suffix}"
            )
        };
        let conn = self.lock()?;
        let read_row = |row: &rusqlite::Row<'_>| -> rusqlite::Result<(SearchProfile, bool)> {
            let created_at = row
                .get::<_, Option<String>>(3)?
                .and_then(|value| value.parse::<u64>().ok());
            let malformed = row.get::<_, i64>(5)? != 0;
            Ok((
                (
                    PublicDirectoryProfileRecord {
                        account_id_hex: row.get(0)?,
                        npub: row.get(1)?,
                        profile_json: row.get(2)?,
                    },
                    created_at,
                    row.get(4)?,
                ),
                malformed,
            ))
        };
        let mut profiles = Vec::new();
        let mut malformed_profiles = 0usize;
        if account_ids.is_empty() {
            let sql = build_query(
                "",
                &format!(
                    "WHERE search_rank < 18
                     ORDER BY account_id_hex LIMIT {PUBLIC_DIRECTORY_USERS_MAX}"
                ),
            );
            let mut statement = conn.prepare_cached(&sql).storage()?;
            let rows = statement.query_map([query], read_row).storage()?;
            for row in rows {
                let (profile, malformed) = row.storage()?;
                if malformed {
                    malformed_profiles += 1;
                }
                profiles.push(profile);
            }
        } else {
            for ids in account_ids.chunks(crate::SQLITE_BIND_PARAMETER_CHUNK - 1) {
                let placeholders = std::iter::repeat_n("?", ids.len())
                    .collect::<Vec<_>>()
                    .join(",");
                let sql = build_query(&format!("WHERE account_id_hex IN ({placeholders})"), "");
                let mut statement = conn.prepare_cached(&sql).storage()?;
                let rows = statement
                    .query_map(
                        params_from_iter(
                            std::iter::once(query).chain(ids.iter().map(String::as_str)),
                        ),
                        read_row,
                    )
                    .storage()?;
                for row in rows {
                    let (profile, malformed) = row.storage()?;
                    if malformed {
                        malformed_profiles += 1;
                    }
                    profiles.push(profile);
                }
            }
        }
        if malformed_profiles > 0 {
            tracing::warn!(
                target: "storage_sqlite::shared",
                method = "public_directory_profiles",
                malformed_profiles,
                "ignored malformed profile_json on directory profile rows"
            );
        }
        Ok(profiles)
    }

    /// Read only requested profiles, without follow, relay-list, or key-package rows.
    pub fn directory_profiles_for_ids(
        &self,
        account_ids: &[String],
    ) -> StorageResult<Vec<PublicDirectoryProfileRecord>> {
        let conn = self.lock()?;
        let mut profiles = Vec::new();
        for ids in account_ids.chunks(crate::SQLITE_BIND_PARAMETER_CHUNK) {
            let placeholders = std::iter::repeat_n("?", ids.len())
                .collect::<Vec<_>>()
                .join(",");
            let mut statement = conn
                .prepare_cached(&format!(
                    "SELECT account_id_hex, npub, profile_json FROM directory_users
                 WHERE account_id_hex IN ({placeholders})"
                ))
                .storage()?;
            let rows = statement
                .query_map(params_from_iter(ids), |row| {
                    Ok(PublicDirectoryProfileRecord {
                        account_id_hex: row.get(0)?,
                        npub: row.get(1)?,
                        profile_json: row.get(2)?,
                    })
                })
                .storage()?;
            for row in rows {
                profiles.push(row.storage()?);
            }
        }
        Ok(profiles)
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
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
        let mut follows_by_account: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        {
            let mut stmt = tx
                .prepare_cached(
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
        let mut stmt = tx
            .prepare_cached(
                "SELECT account_id_hex, npub, profile_json, relay_lists_json,
                        key_package_json, event_id_hex, event_kind, event_created_at,
                        follows_created_at
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
                    follows_created_at: u64::try_from(row.get::<_, i64>(8)?).unwrap_or(0),
                })
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        drop(stmt);
        tx.commit().storage()?;
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
        self.lock()?
            .query_row_cached(
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
        retry_on_busy(|| {
            self.lock()?
                .execute_cached(
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
        })
    }

    pub fn telemetry_install_id(&self) -> StorageResult<Option<String>> {
        self.lock()?
            .query_row_cached(
                "SELECT install_id
                 FROM telemetry_install
                 WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .storage()
    }

    pub fn audit_log_settings(&self) -> StorageResult<StoredAuditLogSettings> {
        self.ensure_audit_log_settings()?;
        self.lock()?
            .query_row_cached(
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
        retry_on_busy(|| {
            self.lock()?
                .execute_cached(
                    "INSERT INTO audit_log_settings (id, enabled, updated_at_ms)
                 VALUES (1, ?1, ?2)
                 ON CONFLICT(id) DO UPDATE SET
                    enabled = excluded.enabled,
                    updated_at_ms = excluded.updated_at_ms",
                    params![bool_i64(settings.enabled), unix_now_ms()],
                )
                .storage()?;
            Ok(())
        })
    }

    /// `None` until a host stores a retention policy.
    pub fn audit_log_retention(&self) -> StorageResult<Option<StoredAuditLogRetention>> {
        self.lock()?
            .query_row_cached(
                "SELECT max_age_days, max_bytes_per_account
                 FROM audit_log_retention_settings
                 WHERE id = 1",
                [],
                |row| {
                    Ok(StoredAuditLogRetention {
                        max_age_days: row.get(0)?,
                        max_bytes_per_account: row.get::<_, i64>(1)?.try_into().unwrap_or(0),
                    })
                },
            )
            .optional()
            .storage()
    }

    pub fn set_audit_log_retention(&self, retention: StoredAuditLogRetention) -> StorageResult<()> {
        let max_bytes = i64::try_from(retention.max_bytes_per_account).unwrap_or(i64::MAX);
        retry_on_busy(|| {
            self.lock()?
                .execute_cached(
                    "INSERT INTO audit_log_retention_settings
                        (id, max_age_days, max_bytes_per_account, updated_at_ms)
                     VALUES (1, ?1, ?2, ?3)
                     ON CONFLICT(id) DO UPDATE SET
                        max_age_days = excluded.max_age_days,
                        max_bytes_per_account = excluded.max_bytes_per_account,
                        updated_at_ms = excluded.updated_at_ms",
                    params![retention.max_age_days, max_bytes, unix_now_ms()],
                )
                .storage()?;
            Ok(())
        })
    }

    #[cfg(test)]
    fn table_columns(&self, table: &str) -> Vec<String> {
        let conn = self.lock().unwrap();
        let mut stmt = conn
            .prepare_cached(&format!("PRAGMA table_info({table})"))
            .unwrap();
        stmt.query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    fn lock(&self) -> StorageResult<ConnectionGuard<'_>> {
        self.conn.lock()
    }

    fn ensure_relay_telemetry_settings(&self) -> StorageResult<()> {
        retry_on_busy(|| {
            self.lock()?
                .execute_cached(
                    "INSERT INTO relay_telemetry_settings (
                    id, export_enabled, export_interval_seconds, updated_at_ms
                 )
                 VALUES (1, 0, 60, ?1)
                 ON CONFLICT(id) DO NOTHING",
                    params![unix_now_ms()],
                )
                .storage()?;
            Ok(())
        })
    }

    fn ensure_audit_log_settings(&self) -> StorageResult<()> {
        retry_on_busy(|| {
            self.lock()?
                .execute_cached(
                    "INSERT INTO audit_log_settings (
                    id, enabled, updated_at_ms
                 )
                 VALUES (1, 0, ?1)
                 ON CONFLICT(id) DO NOTHING",
                    params![unix_now_ms()],
                )
                .storage()?;
            Ok(())
        })
    }
}

fn key_package_barrier_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<PublicKeyPackageBarrierRecord> {
    Ok(PublicKeyPackageBarrierRecord {
        account_id_hex: row.get(0)?,
        key_package_id: row.get(1)?,
        event_id_hex: row.get(2)?,
        deleted_event_id: row.get(3)?,
        event_created_at: u64::try_from(row.get::<_, i64>(4)?).unwrap_or(0),
        observed_at: u64::try_from(row.get::<_, i64>(5)?).unwrap_or(0),
        kind: match row.get::<_, String>(6)?.as_str() {
            "replacement" => PublicKeyPackageBarrierKind::Replacement,
            "deletion" => PublicKeyPackageBarrierKind::Deletion,
            "exact_deletion" => PublicKeyPackageBarrierKind::ExactDeletion,
            _ => return Err(rusqlite::Error::InvalidQuery),
        },
    })
}

fn write_key_package_barrier(
    tx: &Transaction<'_>,
    record: &PublicKeyPackageBarrierRecord,
) -> StorageResult<bool> {
    let changed = tx
        .execute_cached(
            "INSERT INTO public_key_package_barriers (
            account_id_hex, key_package_id, event_id_hex, deleted_event_id,
            event_created_at, observed_at, kind
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT DO UPDATE SET
            event_id_hex = excluded.event_id_hex,
            event_created_at = excluded.event_created_at,
            observed_at = excluded.observed_at
         WHERE (excluded.event_created_at > public_key_package_barriers.event_created_at
            OR (excluded.event_created_at = public_key_package_barriers.event_created_at
                AND excluded.event_id_hex <= public_key_package_barriers.event_id_hex))
            AND excluded.event_id_hex <> public_key_package_barriers.event_id_hex",
            params![
                &record.account_id_hex,
                &record.key_package_id,
                &record.event_id_hex,
                &record.deleted_event_id,
                u64_to_i64(record.event_created_at)?,
                u64_to_i64(record.observed_at)?,
                record.kind.as_str(),
            ],
        )
        .storage()?;
    Ok(changed != 0)
}

fn bump_key_package_revision(tx: &Transaction<'_>, account_id_hex: &str) -> StorageResult<()> {
    tx.execute_cached(
        "INSERT INTO public_key_package_evidence_clock (id, revision)
         VALUES (1, 1)
         ON CONFLICT(id) DO UPDATE SET revision = revision + 1",
        [],
    )
    .storage()?;
    tx.execute_cached(
        "INSERT INTO public_key_package_evidence_revisions (account_id_hex, revision)
         SELECT ?1, revision FROM public_key_package_evidence_clock WHERE id = 1
         ON CONFLICT(account_id_hex) DO UPDATE SET revision = excluded.revision",
        params![account_id_hex],
    )
    .storage()?;
    Ok(())
}

fn prune_key_package_replacements(tx: &Transaction<'_>) -> StorageResult<()> {
    let stale_before = key_package_evidence_stale_before(unix_now_seconds_i64());
    tx.execute_cached(
        "DELETE FROM directory_key_package_replacements WHERE event_created_at <= ?1",
        [stale_before],
    )
    .storage()?;
    for (query, cap) in [
        (
            "SELECT account_id_hex, key_package_id, event_id_hex, event_created_at, observed_at
         FROM (
            SELECT *, ROW_NUMBER() OVER (
                PARTITION BY account_id_hex
                ORDER BY observed_at DESC, event_created_at DESC, event_id_hex, key_package_id
            ) AS retention_position
            FROM directory_key_package_replacements
         ) WHERE retention_position > ?1",
            KEY_PACKAGE_REPLACEMENT_CAP,
        ),
        (
            "SELECT account_id_hex, key_package_id, event_id_hex, event_created_at, observed_at
         FROM directory_key_package_replacements
         ORDER BY observed_at DESC, event_created_at DESC, event_id_hex,
                  account_id_hex, key_package_id
         LIMIT -1 OFFSET ?1",
            KEY_PACKAGE_REPLACEMENT_GLOBAL_CAP,
        ),
    ] {
        let pruned = {
            let mut statement = tx.prepare_cached(query).storage()?;
            statement
                .query_map([cap], |row| {
                    Ok(PublicKeyPackageBarrierRecord {
                        account_id_hex: row.get(0)?,
                        key_package_id: row.get(1)?,
                        event_id_hex: row.get(2)?,
                        deleted_event_id: None,
                        event_created_at: u64::try_from(row.get::<_, i64>(3)?).unwrap_or(0),
                        observed_at: u64::try_from(row.get::<_, i64>(4)?).unwrap_or(0),
                        kind: PublicKeyPackageBarrierKind::Replacement,
                    })
                })
                .storage()?
                .map(|row| row.storage())
                .collect::<StorageResult<Vec<_>>>()?
        };
        for record in pruned {
            write_key_package_barrier(tx, &record)?;
            tx.execute_cached(
                "DELETE FROM directory_key_package_replacements
                 WHERE account_id_hex = ?1 AND key_package_id = ?2",
                params![&record.account_id_hex, &record.key_package_id],
            )
            .storage()?;
        }
    }
    Ok(())
}

fn prune_key_package_barriers(tx: &Transaction<'_>, now: i64) -> StorageResult<()> {
    let stale_before = key_package_evidence_stale_before(now);
    for statement in [
        "DELETE FROM public_key_package_barriers
         WHERE (deleted_event_id IS NOT NULL AND observed_at <= ?1)
            OR (deleted_event_id IS NULL AND event_created_at <= ?1)",
        "DELETE FROM public_key_package_eviction_watermarks
         WHERE (kind = 'exact_deletion' AND evicted_at <= ?1)
            OR (kind <> 'exact_deletion' AND event_created_at <= ?1)",
        "DELETE FROM public_key_package_eviction_fallback
         WHERE (kind = 'exact_deletion' AND evicted_at <= ?1)
            OR (kind <> 'exact_deletion' AND event_created_at <= ?1)",
    ] {
        tx.execute_cached(statement, [stale_before]).storage()?;
    }
    for query in [
        "SELECT account_id_hex, key_package_id, event_id_hex,
                        deleted_event_id, event_created_at, observed_at, kind
                 FROM (
                    SELECT *, ROW_NUMBER() OVER (
                        PARTITION BY account_id_hex
                        ORDER BY observed_at DESC, event_created_at DESC, event_id_hex,
                                 key_package_id, deleted_event_id
                    ) AS retention_position
                    FROM public_key_package_barriers
                 ) WHERE retention_position > 500",
        "SELECT account_id_hex, key_package_id, event_id_hex,
                        deleted_event_id, event_created_at, observed_at, kind
                 FROM public_key_package_barriers
                 ORDER BY observed_at DESC, event_created_at DESC, event_id_hex,
                          account_id_hex, key_package_id, deleted_event_id
                 LIMIT -1 OFFSET 1000",
    ] {
        let pruned = {
            let mut statement = tx.prepare_cached(query).storage()?;
            statement
                .query_map([], key_package_barrier_from_row)
                .storage()?
                .map(|row| row.storage())
                .collect::<StorageResult<Vec<_>>>()?
        };
        for record in pruned {
            let (watermark_kind, watermark_deleted_event_id) = match record.kind {
                PublicKeyPackageBarrierKind::Deletion if record.deleted_event_id.is_some() => {
                    (PublicKeyPackageBarrierKind::ExactDeletion, None)
                }
                _ => (record.kind, record.deleted_event_id.clone()),
            };
            tx.execute_cached(
                "INSERT INTO public_key_package_eviction_watermarks (
                    account_id_hex, key_package_id, event_id_hex, deleted_event_id,
                    event_created_at, evicted_at, kind
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(account_id_hex) DO UPDATE SET
                    key_package_id = excluded.key_package_id,
                    event_id_hex = excluded.event_id_hex,
                    deleted_event_id = excluded.deleted_event_id,
                    event_created_at = excluded.event_created_at,
                    kind = excluded.kind,
                    evicted_at = MAX(public_key_package_eviction_watermarks.evicted_at, excluded.evicted_at)
                 WHERE excluded.kind = 'exact_deletion'
                    OR (public_key_package_eviction_watermarks.kind != 'exact_deletion'
                        AND (excluded.event_created_at >
                                 public_key_package_eviction_watermarks.event_created_at
                             OR (excluded.event_created_at =
                                 public_key_package_eviction_watermarks.event_created_at
                                 AND ((excluded.kind = 'deletion'
                                       AND public_key_package_eviction_watermarks.kind = 'replacement')
                                      OR (excluded.kind = public_key_package_eviction_watermarks.kind
                                          AND excluded.event_id_hex <=
                                              public_key_package_eviction_watermarks.event_id_hex)))))",
                params![
                    &record.account_id_hex,
                    &record.key_package_id,
                    &record.event_id_hex,
                    &watermark_deleted_event_id,
                    u64_to_i64(record.event_created_at)?,
                    now,
                    watermark_kind.as_str(),
                ],
            )
            .storage()?;
            tx.execute_cached(
                "UPDATE public_key_package_eviction_watermarks
                 SET evicted_at = MAX(evicted_at, ?2) WHERE account_id_hex = ?1",
                params![&record.account_id_hex, now],
            )
            .storage()?;
            tx.execute_cached(
                "DELETE FROM public_key_package_barriers
                 WHERE account_id_hex = ?1 AND key_package_id = ?2
                   AND deleted_event_id IS ?3 AND kind = ?4",
                params![
                    &record.account_id_hex,
                    &record.key_package_id,
                    &record.deleted_event_id,
                    record.kind.as_str(),
                ],
            )
            .storage()?;
        }
    }
    tx.execute_cached(
        "INSERT INTO public_key_package_eviction_fallback (
            id, event_id_hex, event_created_at, evicted_at, kind
         )
         SELECT 1, event_id_hex, event_created_at, evicted_at, kind
         FROM public_key_package_eviction_watermarks
         WHERE account_id_hex IN (
            SELECT account_id_hex FROM public_key_package_eviction_watermarks
            ORDER BY evicted_at DESC, event_created_at DESC, event_id_hex, account_id_hex
            LIMIT -1 OFFSET 1000
         )
         ORDER BY
            CASE WHEN kind = 'exact_deletion' THEN 0 ELSE 1 END,
            event_created_at DESC,
            CASE WHEN kind = 'deletion' THEN 0 ELSE 1 END,
            event_id_hex,
            evicted_at DESC
         LIMIT 1
         ON CONFLICT(id) DO UPDATE SET
            event_id_hex = excluded.event_id_hex,
            event_created_at = excluded.event_created_at,
            kind = excluded.kind,
            evicted_at = MAX(public_key_package_eviction_fallback.evicted_at, excluded.evicted_at)
         WHERE excluded.kind = 'exact_deletion'
            OR (public_key_package_eviction_fallback.kind != 'exact_deletion'
                AND (excluded.event_created_at > public_key_package_eviction_fallback.event_created_at
                     OR (excluded.event_created_at = public_key_package_eviction_fallback.event_created_at
                         AND ((excluded.kind = 'deletion'
                               AND public_key_package_eviction_fallback.kind = 'replacement')
                              OR (excluded.kind = public_key_package_eviction_fallback.kind
                                  AND excluded.event_id_hex <= public_key_package_eviction_fallback.event_id_hex)))))",
        [],
    )
    .storage()?;
    tx.execute_cached(
        "UPDATE public_key_package_eviction_fallback
         SET evicted_at = MAX(evicted_at, COALESCE((
            SELECT MAX(evicted_at) FROM public_key_package_eviction_watermarks
            WHERE account_id_hex IN (
                SELECT account_id_hex FROM public_key_package_eviction_watermarks
                ORDER BY evicted_at DESC, event_created_at DESC, event_id_hex, account_id_hex
                LIMIT -1 OFFSET 1000
            )), 0))
         WHERE id = 1 AND EXISTS (
            SELECT 1 FROM public_key_package_eviction_watermarks
            WHERE account_id_hex IN (
                SELECT account_id_hex FROM public_key_package_eviction_watermarks
                ORDER BY evicted_at DESC, event_created_at DESC, event_id_hex, account_id_hex
                LIMIT -1 OFFSET 1000
            ))",
        [],
    )
    .storage()?;
    tx.execute_cached(
        "DELETE FROM public_key_package_eviction_watermarks
         WHERE account_id_hex IN (
            SELECT account_id_hex FROM public_key_package_eviction_watermarks
            ORDER BY evicted_at DESC, event_created_at DESC, event_id_hex, account_id_hex
            LIMIT -1 OFFSET 1000
         )",
        [],
    )
    .storage()?;
    tx.execute_cached(
        "DELETE FROM public_key_package_evidence_revisions
         WHERE NOT EXISTS (
             SELECT 1 FROM directory_key_package_replacements
             WHERE account_id_hex = public_key_package_evidence_revisions.account_id_hex)
           AND NOT EXISTS (
             SELECT 1 FROM public_key_package_barriers
             WHERE account_id_hex = public_key_package_evidence_revisions.account_id_hex)
           AND NOT EXISTS (
             SELECT 1 FROM public_key_package_eviction_watermarks
             WHERE account_id_hex = public_key_package_evidence_revisions.account_id_hex)",
        [],
    )
    .storage()?;
    Ok(())
}

fn optional_i64_to_u64(value: Option<i64>) -> Option<u64> {
    value.and_then(|value| u64::try_from(value).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_batch_is_scoped() {
        use rusqlite::trace::{TraceEvent, TraceEventCodes};
        thread_local! {
            static SELECTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
        }
        let storage = SqliteSharedStorage::in_memory().unwrap();
        storage
            .lock()
            .unwrap()
            .execute_batch(
                "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<1000)
             INSERT INTO directory_users(account_id_hex,npub,profile_json,relay_lists_json)
             SELECT printf('%064x',x),'npub',NULL,'broken' FROM n;",
            )
            .unwrap();
        let ids = (1..=1000)
            .map(|id| format!("{id:064x}"))
            .collect::<Vec<_>>();
        storage.lock().unwrap().trace_v2(
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
            assert!(storage.public_directory_user(id).unwrap().is_some());
        }
        assert_eq!(SELECTS.replace(0), 2000);
        assert!(storage.directory_profiles_for_ids(&[]).unwrap().is_empty());
        assert_eq!(
            storage.directory_profiles_for_ids(&ids).unwrap().len(),
            ids.len()
        );
        assert_eq!(SELECTS.replace(0), 2);
        storage
            .lock()
            .unwrap()
            .trace_v2(TraceEventCodes::empty(), None);
        let selected = storage.directory_profiles_for_ids(&ids[10..12]).unwrap();
        assert_eq!(selected.len(), 2);
        assert!(
            selected
                .iter()
                .all(|row| ids[10..12].contains(&row.account_id_hex))
        );
    }

    #[test]
    fn shared_storage_is_plaintext_public_directory_only() {
        let storage = SqliteSharedStorage::in_memory().unwrap();
        let user_columns = storage.table_columns("directory_users");

        assert!(user_columns.contains(&"profile_json".to_owned()));
        assert!(user_columns.contains(&"relay_lists_json".to_owned()));
        assert!(!user_columns.contains(&"local_account_json".to_owned()));
        assert!(!user_columns.contains(&"private_discovery_reason".to_owned()));
        assert!(!user_columns.contains(&"local_fetch_timestamp".to_owned()));
        for dead_table in [
            "directory_events",
            "directory_key_packages",
            "directory_search_graph_users",
            "directory_search_graph_follows",
        ] {
            assert!(storage.table_columns(dead_table).is_empty(), "{dead_table}");
        }
    }

    #[test]
    #[cfg(unix)]
    fn shared_cache_db_is_owner_only_on_disk() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shared").join("directory.sqlite");
        drop(SqliteSharedStorage::open(&path).unwrap());
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        assert_eq!(mode(&path), 0o600);

        // A pre-existing permissive cache (from builds that created it at the
        // umask) is tightened on reopen.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        drop(SqliteSharedStorage::open(&path).unwrap());
        assert_eq!(mode(&path), 0o600);
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
            follows_created_at: 1_700_000_042,
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

    /// Commits `write` through a second connection to the store's file
    /// when the store starts a statement whose SQL contains `marker`, once.
    /// A read that spans one snapshot does not see the write.
    fn interleave(storage: &SqliteSharedStorage, path: &Path, marker: &str, write: String) {
        use rusqlite::trace::{TraceEvent, TraceEventCodes};
        thread_local! {
            static WRITE: std::cell::RefCell<Option<(String, rusqlite::Connection, String)>> =
                const { std::cell::RefCell::new(None) };
        }
        fn on_statement(event: TraceEvent<'_>) {
            let TraceEvent::Stmt(_, sql) = event else {
                return;
            };
            WRITE.with_borrow_mut(|pending| {
                if pending
                    .as_ref()
                    .is_some_and(|(marker, ..)| sql.contains(marker.as_str()))
                    && let Some((_, writer, write)) = pending.take()
                {
                    // A failed write shows as the later read not seeing it.
                    let _ = writer.execute_batch(&write);
                }
            });
        }
        let writer = rusqlite::Connection::open(path).unwrap();
        WRITE.set(Some((marker.to_owned(), writer, write)));
        storage
            .lock()
            .unwrap()
            .trace_v2(TraceEventCodes::SQLITE_TRACE_STMT, Some(on_statement));
    }

    fn directory_user(prefix: &str, follows: &[&str]) -> PublicDirectoryUserRecord {
        PublicDirectoryUserRecord {
            account_id_hex: prefix.repeat(32),
            npub: format!("npub{prefix}"),
            profile_json: None,
            relay_lists_json: "{}".to_owned(),
            key_package_json: None,
            event_id_hex: None,
            event_kind: None,
            event_created_at: None,
            follows: follows.iter().map(|follow| follow.repeat(32)).collect(),
            follows_created_at: 0,
        }
    }

    #[test]
    fn public_directory_user_reads_user_and_follows_from_one_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shared.sqlite3");
        let storage = SqliteSharedStorage::open(&path).unwrap();
        let record = directory_user("aa", &["bb"]);
        storage.put_public_directory_user(&record).unwrap();
        interleave(
            &storage,
            &path,
            "FROM directory_user_follows",
            format!(
                "INSERT INTO directory_user_follows
                     (account_id_hex, follow_account_id_hex, position)
                 VALUES ('{}', '{}', 1)",
                "aa".repeat(32),
                "cc".repeat(32)
            ),
        );
        assert_eq!(
            storage
                .public_directory_user(&record.account_id_hex)
                .unwrap()
                .unwrap(),
            record
        );
        assert_eq!(
            storage
                .public_directory_user(&record.account_id_hex)
                .unwrap()
                .unwrap()
                .follows,
            ["bb".repeat(32), "cc".repeat(32)],
            "the interleaved write committed"
        );
    }

    #[test]
    fn duplicate_public_directory_follows_do_not_abort_the_record_upsert() {
        let storage = SqliteSharedStorage::in_memory().unwrap();
        let follow = "cc".repeat(32);
        let record = PublicDirectoryUserRecord {
            account_id_hex: "aa".repeat(32),
            npub: "npub1example".to_owned(),
            profile_json: Some(r#"{"name":"Alice"}"#.to_owned()),
            relay_lists_json: "{}".to_owned(),
            key_package_json: None,
            event_id_hex: Some("bb".repeat(32)),
            event_kind: Some(3),
            event_created_at: Some(1_700_000_000),
            follows: vec![follow.clone(), follow.clone()],
            follows_created_at: 1_700_000_000,
        };

        storage.put_public_directory_user(&record).unwrap();

        let stored = storage
            .public_directory_user(&record.account_id_hex)
            .unwrap()
            .unwrap();
        assert_eq!(stored.npub, record.npub);
        assert_eq!(stored.follows, vec![follow]);
    }

    #[test]
    fn public_directory_profiles_do_not_read_follow_edges_or_unrelated_json() {
        let storage = SqliteSharedStorage::in_memory().unwrap();
        let record = PublicDirectoryUserRecord {
            account_id_hex: "aa".repeat(32),
            npub: "npub1test".into(),
            profile_json: Some(r#"{"name":"Alice"}"#.into()),
            relay_lists_json: "not parsed by profile projection".into(),
            key_package_json: Some("also not parsed".into()),
            event_id_hex: None,
            event_kind: None,
            event_created_at: None,
            follows: vec!["bb".repeat(32)],
            follows_created_at: 0,
        };
        storage.put_public_directory_user(&record).unwrap();
        storage
            .lock()
            .unwrap()
            .execute_batch("DROP TABLE directory_user_follows")
            .unwrap();
        assert_eq!(
            storage.public_directory_profiles("alice", &[]).unwrap(),
            vec![(
                PublicDirectoryProfileRecord {
                    account_id_hex: record.account_id_hex,
                    npub: record.npub,
                    profile_json: record.profile_json,
                },
                Some(0),
                0
            )]
        );
    }

    #[test]
    fn public_directory_profile_search_ranks_fields_and_preserves_nonmatching_winners() {
        let storage = SqliteSharedStorage::in_memory().unwrap();
        let mut record = PublicDirectoryUserRecord {
            account_id_hex: "aa".repeat(32),
            npub: "npub1unrelated".into(),
            profile_json: None,
            relay_lists_json: "{}".into(),
            key_package_json: None,
            event_id_hex: None,
            event_kind: None,
            event_created_at: None,
            follows: Vec::new(),
            follows_created_at: 0,
        };
        for (field, rank) in [("name", 0), ("nip05", 1), ("display_name", 2), ("about", 3)] {
            record.profile_json = Some(format!(r#"{{"{field}":"ÉCOLE %_","created_at":42}}"#));
            storage.put_public_directory_user(&record).unwrap();
            for (query, quality) in [("école %_", 0), ("école", 1), ("%_", 2)] {
                let rows = storage.public_directory_profiles(query, &[]).unwrap();
                assert_eq!(rows.len(), 1, "{field}: {query}");
                assert_eq!(rows[0].1, Some(42));
                assert_eq!(rows[0].2, quality * 6 + rank, "{field}: {query}");
            }
            assert!(
                storage
                    .public_directory_profiles("%x", &[])
                    .unwrap()
                    .is_empty()
            );
        }
        record.profile_json = Some(r#"{"name":"ÉCOLE prefix","nip05":"école"}"#.into());
        storage.put_public_directory_user(&record).unwrap();
        let rows = storage.public_directory_profiles("école", &[]).unwrap();
        assert_eq!((rows[0].1, rows[0].2), (Some(0), 1));
        record.profile_json = None;
        storage.put_public_directory_user(&record).unwrap();
        let rows = storage
            .public_directory_profiles("npub1unrelated", &[])
            .unwrap();
        assert_eq!((rows[0].1, rows[0].2), (None, 4));
        let rows = storage
            .public_directory_profiles(&record.account_id_hex, &[])
            .unwrap();
        assert_eq!((rows[0].1, rows[0].2), (None, 5));

        record.profile_json = Some(r#"{"name":"new name","created_at":99}"#.into());
        storage.put_public_directory_user(&record).unwrap();
        assert!(
            storage
                .public_directory_profiles("école", &[])
                .unwrap()
                .is_empty()
        );
        let mut ids = (0..crate::SQLITE_BIND_PARAMETER_CHUNK)
            .map(|id| format!("{id:064x}"))
            .collect::<Vec<_>>();
        ids.push(record.account_id_hex.clone());
        let rows = storage.public_directory_profiles("école", &ids).unwrap();
        assert_eq!(
            rows,
            vec![(
                PublicDirectoryProfileRecord {
                    account_id_hex: record.account_id_hex,
                    npub: record.npub,
                    profile_json: record.profile_json,
                },
                Some(99),
                18
            )]
        );
    }

    #[test]
    fn public_directory_profile_search_filters_before_the_candidate_cap() {
        let storage = SqliteSharedStorage::in_memory().unwrap();
        storage
            .lock()
            .unwrap()
            .execute_batch(
                "WITH RECURSIVE ids(id) AS (
                 VALUES(0) UNION ALL SELECT id + 1 FROM ids WHERE id < 10000
             )
             INSERT INTO directory_users (account_id_hex, npub, profile_json, relay_lists_json)
             SELECT printf('%064x', id), 'npub1unrelated',
                    CASE WHEN id = 10000 THEN '{\"about\":\"needle\"}' ELSE NULL END,
                    '{}'
             FROM ids;",
            )
            .unwrap();
        let rows = storage.public_directory_profiles("needle", &[]).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0.account_id_hex, format!("{:064x}", 10000));
        assert_eq!((rows[0].1, rows[0].2), (Some(0), 3));
        storage
            .lock()
            .unwrap()
            .execute(
                "UPDATE directory_users SET profile_json = '{\"about\":\"needle\"}'",
                [],
            )
            .unwrap();
        let rows = storage.public_directory_profiles("needle", &[]).unwrap();
        assert_eq!(rows.len(), PUBLIC_DIRECTORY_USERS_MAX);
        assert_eq!(
            rows.first().unwrap().0.account_id_hex,
            format!("{:064x}", 0)
        );
        assert_eq!(
            rows.last().unwrap().0.account_id_hex,
            format!("{:064x}", 9999)
        );
    }

    /// Regression for #3798: malformed `created_at` values or invalid JSON in
    /// one row's `profile_json` must not abort `public_directory_profiles`,
    /// while keeping affected users discoverable by `npub`/account id with
    /// `profile_json: None, created_at: None`.
    #[test]
    fn public_directory_profiles_tolerates_malformed_created_at_or_json() {
        let storage = SqliteSharedStorage::in_memory().unwrap();
        let valid_id = "11".repeat(32);
        let null_profile_id = "12".repeat(32);
        let negative_id = "21".repeat(32);
        let string_id = "22".repeat(32);
        let null_ts_id = "23".repeat(32);
        let float_id = "24".repeat(32);
        let broken_json_id = "25".repeat(32);

        let put = |account_id_hex: &str, npub: &str, profile_json: Option<&str>| {
            storage
                .put_public_directory_user(&PublicDirectoryUserRecord {
                    account_id_hex: account_id_hex.to_owned(),
                    npub: npub.to_owned(),
                    profile_json: profile_json.map(str::to_owned),
                    relay_lists_json: "{}".into(),
                    key_package_json: None,
                    event_id_hex: None,
                    event_kind: None,
                    event_created_at: None,
                    follows: Vec::new(),
                    follows_created_at: 0,
                })
                .unwrap();
        };

        put(
            &valid_id,
            "npub1valid",
            Some(r#"{"name":"Alice","created_at":42}"#),
        );
        put(&null_profile_id, "npub1alice", None);
        put(
            &negative_id,
            "npub1neg",
            Some(r#"{"name":"Alice Neg","created_at":-1}"#),
        );
        put(
            &string_id,
            "npub1str",
            Some(r#"{"name":"Alice Str","created_at":"bad"}"#),
        );
        put(
            &null_ts_id,
            "npub1null",
            Some(r#"{"name":"Alice Null","created_at":null}"#),
        );
        put(
            &float_id,
            "npub1flt",
            Some(r#"{"name":"Alice Flt","created_at":1.5}"#),
        );
        put(&broken_json_id, "npub1alicebroken", Some("{not valid json"));

        // Unscoped scan returns valid matches plus malformed-profile users
        // whose `npub` still matches (with `profile_json: None, created_at: None`),
        // and excludes rows that only matched through discarded malformed JSON.
        let scanned = storage.public_directory_profiles("alice", &[]).unwrap();
        assert_eq!(
            scanned,
            vec![
                (
                    PublicDirectoryProfileRecord {
                        account_id_hex: valid_id.clone(),
                        npub: "npub1valid".into(),
                        profile_json: Some(r#"{"name":"Alice","created_at":42}"#.into()),
                    },
                    Some(42),
                    0
                ),
                (
                    PublicDirectoryProfileRecord {
                        account_id_hex: null_profile_id.clone(),
                        npub: "npub1alice".into(),
                        profile_json: None,
                    },
                    None,
                    16
                ),
                (
                    PublicDirectoryProfileRecord {
                        account_id_hex: broken_json_id.clone(),
                        npub: "npub1alicebroken".into(),
                        profile_json: None,
                    },
                    None,
                    16
                ),
            ]
        );

        // Explicit ID lookup keeps every requested user row, degrading
        // malformed profiles to `profile_json: None, created_at: None` with
        // identity-only rank so a valid copy in another cache still wins.
        let ids = vec![
            valid_id.clone(),
            null_profile_id.clone(),
            negative_id.clone(),
            string_id.clone(),
            null_ts_id.clone(),
            float_id.clone(),
            broken_json_id.clone(),
        ];
        let mut by_ids = storage.public_directory_profiles("alice", &ids).unwrap();
        by_ids.sort_by(|a, b| a.0.account_id_hex.cmp(&b.0.account_id_hex));
        assert_eq!(by_ids.len(), 7);
        assert_eq!(by_ids[0].1, Some(42));
        assert_eq!(by_ids[1].1, None);
        for degraded in &by_ids[2..6] {
            assert_eq!(degraded.0.profile_json, None);
            assert_eq!(degraded.1, None);
            assert!(
                degraded.2 >= 18,
                "only discarded JSON matched: {degraded:?}"
            );
        }
        assert_eq!(by_ids[6].0.account_id_hex, broken_json_id);
        assert_eq!(by_ids[6].0.profile_json, None);
        assert_eq!(by_ids[6].1, None);
        assert_eq!(by_ids[6].2, 16);
    }

    /// Regression for PR #3818 review: malformed profile rows whose corrupt JSON
    /// text matches the query must be ranked identity-only *before* SQL applies
    /// `WHERE search_rank < 18 ... LIMIT 10000` so they cannot displace valid
    /// trailing matches.
    #[test]
    fn public_directory_profiles_malformed_rows_do_not_consume_scan_cap() {
        let storage = SqliteSharedStorage::in_memory().unwrap();
        let mut conn = storage.lock().unwrap();
        let tx = conn.transaction().unwrap();
        {
            let mut stmt = tx
                .prepare(
                    "INSERT INTO directory_users (
                        account_id_hex, npub, profile_json, relay_lists_json
                     ) VALUES (?1, ?2, ?3, '{}')",
                )
                .unwrap();
            // Five malformed profiles with `account_id_hex` sorting before all
            // valid rows and `name: "Alice"` inside corrupt/invalid JSON.
            for (idx, bad_json) in [
                r#"{"name":"Alice","created_at":-1}"#,
                r#"{"name":"Alice","created_at":"bad"}"#,
                r#"{"name":"Alice","created_at":null}"#,
                r#"{"name":"Alice","created_at":1.5}"#,
                r#"{"name":"Alice","created_at":18446744073709551616}"#,
            ]
            .into_iter()
            .enumerate()
            {
                let id = format!("0000{idx:060x}");
                stmt.execute(params![id, format!("npub1bad{idx}"), bad_json])
                    .unwrap();
            }
            for idx in 0..PUBLIC_DIRECTORY_USERS_MAX {
                let id = format!("1000{idx:060x}");
                stmt.execute(params![
                    id,
                    format!("npub1ok{idx}"),
                    r#"{"name":"Alice","created_at":42}"#
                ])
                .unwrap();
            }
        }
        tx.commit().unwrap();
        drop(conn);

        let last_valid_id = format!("1000{:060x}", PUBLIC_DIRECTORY_USERS_MAX - 1);
        let results = storage.public_directory_profiles("alice", &[]).unwrap();
        assert_eq!(
            results.len(),
            PUBLIC_DIRECTORY_USERS_MAX,
            "malformed rows must not consume slots from the {PUBLIC_DIRECTORY_USERS_MAX}-row scan cap"
        );
        assert_eq!(
            results.last().unwrap().0.account_id_hex,
            last_valid_id,
            "the last valid matching user must not be pushed past the SQL cap"
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
                    follows_created_at: 0,
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
    fn public_directory_users_read_users_and_follows_from_one_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shared.sqlite3");
        let storage = SqliteSharedStorage::open(&path).unwrap();
        let record = directory_user("aa", &["bb"]);
        storage.put_public_directory_user(&record).unwrap();
        // The follows are read first; a user who arrives before the users
        // are read must not join a listing whose follows missed it.
        interleave(
            &storage,
            &path,
            "npub, profile_json",
            format!(
                "INSERT INTO directory_users (account_id_hex, npub, relay_lists_json)
                 VALUES ('{}', 'npub01', '{{}}')",
                "01".repeat(32)
            ),
        );
        assert_eq!(
            storage.public_directory_users().unwrap(),
            std::slice::from_ref(&record)
        );
        assert_eq!(
            storage.public_directory_users().unwrap(),
            [directory_user("01", &[]), record],
            "the interleaved write committed"
        );
    }

    fn fresh_timestamp(offset: u64) -> u64 {
        static BASE: std::sync::LazyLock<u64> =
            std::sync::LazyLock::new(|| unix_now_seconds_i64().max(0) as u64);
        *BASE + offset
    }

    fn key_package_barrier(account: &str, index: u64) -> PublicKeyPackageBarrierRecord {
        PublicKeyPackageBarrierRecord {
            account_id_hex: account.into(),
            key_package_id: format!("slot-{index:04}"),
            event_id_hex: format!("{index:064x}"),
            deleted_event_id: None,
            event_created_at: fresh_timestamp(index),
            observed_at: index,
            kind: PublicKeyPackageBarrierKind::Replacement,
        }
    }

    #[test]
    fn key_package_barriers_keep_nip01_winners_per_slot_and_target() {
        let storage = SqliteSharedStorage::in_memory().unwrap();
        let account = "aa".repeat(32);
        let base = fresh_timestamp(0);
        assert_eq!(
            storage.public_key_package_evicted_at(&account).unwrap(),
            None
        );
        let initial = PublicKeyPackageBarrierRecord {
            key_package_id: "slot-b".into(),
            event_id_hex: "bb".repeat(32),
            event_created_at: base + 20,
            observed_at: 2,
            kind: PublicKeyPackageBarrierKind::Deletion,
            ..key_package_barrier(&account, 0)
        };
        let exact = PublicKeyPackageBarrierRecord {
            deleted_event_id: Some("11".repeat(32)),
            observed_at: fresh_timestamp(8),
            ..initial.clone()
        };
        let other_target = PublicKeyPackageBarrierRecord {
            deleted_event_id: Some("22".repeat(32)),
            observed_at: fresh_timestamp(8),
            ..initial.clone()
        };
        for record in [&initial, &exact, &other_target] {
            storage.put_public_key_package_barrier(record).unwrap();
        }
        let mut slot_winner = PublicKeyPackageBarrierRecord {
            event_id_hex: "cc".repeat(32),
            event_created_at: base + 21,
            observed_at: 4,
            ..initial.clone()
        };
        storage
            .put_public_key_package_barrier(&slot_winner)
            .unwrap();
        for loser in [
            PublicKeyPackageBarrierRecord {
                event_id_hex: "00".repeat(32),
                event_created_at: base + 20,
                observed_at: 100,
                ..slot_winner.clone()
            },
            PublicKeyPackageBarrierRecord {
                event_id_hex: "dd".repeat(32),
                observed_at: 101,
                ..slot_winner.clone()
            },
        ] {
            storage.put_public_key_package_barrier(&loser).unwrap();
        }
        slot_winner.observed_at = 40;
        storage
            .put_public_key_package_barrier(&slot_winner)
            .unwrap();
        storage
            .put_public_key_package_barrier(&PublicKeyPackageBarrierRecord {
                observed_at: 1,
                ..slot_winner.clone()
            })
            .unwrap();
        let exact_winner = PublicKeyPackageBarrierRecord {
            event_id_hex: "aa".repeat(32),
            observed_at: fresh_timestamp(8),
            ..exact
        };
        storage
            .put_public_key_package_barrier(&exact_winner)
            .unwrap();
        let other_slot = PublicKeyPackageBarrierRecord {
            key_package_id: "slot-a".into(),
            ..initial.clone()
        };
        storage.put_public_key_package_barrier(&other_slot).unwrap();
        let other_account = PublicKeyPackageBarrierRecord {
            account_id_hex: "ff".repeat(32),
            ..initial
        };
        storage
            .put_public_key_package_barrier(&other_account)
            .unwrap();
        slot_winner.observed_at = 4;
        assert_eq!(
            storage.public_key_package_barriers(&account).unwrap(),
            [other_slot, slot_winner, exact_winner, other_target]
        );
        assert_eq!(
            storage
                .public_key_package_barriers(&other_account.account_id_hex)
                .unwrap(),
            [other_account]
        );
        assert_eq!(
            storage.public_key_package_evicted_at(&account).unwrap(),
            Some(fresh_timestamp(8))
        );
    }

    #[test]
    fn pruned_exact_deletions_become_slot_wide_watermark() {
        let storage = SqliteSharedStorage::in_memory().unwrap();
        let account = "aa".repeat(32);
        for (index, created_at) in [fresh_timestamp(100), fresh_timestamp(200)]
            .into_iter()
            .enumerate()
        {
            storage
                .put_public_key_package_barrier(&PublicKeyPackageBarrierRecord {
                    account_id_hex: account.clone(),
                    key_package_id: String::new(),
                    event_id_hex: format!("{:064x}", index + 1),
                    deleted_event_id: Some(format!("{:064x}", index + 10)),
                    event_created_at: created_at,
                    observed_at: fresh_timestamp(100 + index as u64),
                    kind: PublicKeyPackageBarrierKind::Deletion,
                })
                .unwrap();
        }
        for index in 0..500_u64 {
            storage
                .put_public_key_package_barrier(&PublicKeyPackageBarrierRecord {
                    account_id_hex: account.clone(),
                    key_package_id: format!("slot-{index:04}"),
                    event_id_hex: format!("{index:064x}"),
                    deleted_event_id: None,
                    event_created_at: fresh_timestamp(1_000 + index),
                    observed_at: fresh_timestamp(1_000 + index),
                    kind: PublicKeyPackageBarrierKind::Replacement,
                })
                .unwrap();
        }
        let watermark = storage
            .public_key_package_eviction_watermark(&account)
            .unwrap()
            .unwrap();
        assert_eq!(watermark.kind, PublicKeyPackageBarrierKind::ExactDeletion);
        assert_eq!(watermark.deleted_event_id, None);
        assert_eq!(watermark.event_created_at, fresh_timestamp(200));
    }

    #[test]
    fn deletion_watermark_wins_mixed_timestamp_replacements() {
        for deletion_first in [true, false] {
            for replacement_created_at in [fresh_timestamp(100), fresh_timestamp(200)] {
                let storage = SqliteSharedStorage::in_memory().unwrap();
                let account = "aa".repeat(32);
                let replacement = PublicKeyPackageBarrierRecord {
                    account_id_hex: account.clone(),
                    key_package_id: "slot".into(),
                    event_id_hex: "aa".repeat(32),
                    deleted_event_id: None,
                    event_created_at: replacement_created_at,
                    observed_at: 0,
                    kind: PublicKeyPackageBarrierKind::Replacement,
                };
                let deletion = PublicKeyPackageBarrierRecord {
                    event_id_hex: "ff".repeat(32),
                    deleted_event_id: Some("bb".repeat(32)),
                    event_created_at: fresh_timestamp(100),
                    observed_at: fresh_timestamp(0),
                    kind: PublicKeyPackageBarrierKind::Deletion,
                    ..replacement.clone()
                };
                let records = if deletion_first {
                    [deletion, replacement]
                } else {
                    [replacement, deletion]
                };
                for record in records {
                    storage.put_public_key_package_barrier(&record).unwrap();
                }
                for index in 0..500_u64 {
                    storage
                        .put_public_key_package_barrier(&PublicKeyPackageBarrierRecord {
                            account_id_hex: account.clone(),
                            key_package_id: format!("slot-{index:04}"),
                            event_id_hex: format!("{index:064x}"),
                            deleted_event_id: None,
                            event_created_at: fresh_timestamp(1_000 + index),
                            observed_at: fresh_timestamp(1_000 + index),
                            kind: PublicKeyPackageBarrierKind::Replacement,
                        })
                        .unwrap();
                }
                let watermark = storage
                    .public_key_package_eviction_watermark(&account)
                    .unwrap()
                    .unwrap();
                assert_eq!(watermark.kind, PublicKeyPackageBarrierKind::ExactDeletion);
                assert_eq!(watermark.deleted_event_id, None);
            }
        }
    }

    /// Regression for #3798: batch watermark eviction into the global fallback
    /// must follow the `exact_deletion` > `deletion` > `replacement` dominance
    /// lattice instead of dropping a stronger deletion barrier behind a newer
    /// or lower-id replacement evicted in the same prune.
    #[test]
    fn key_package_watermark_fallback_preserves_dominant_barrier_in_batch_eviction() {
        // Case 1: `exact_deletion` dominates a higher-timestamp `replacement`
        // evicted in the same prune batch.
        {
            let storage = SqliteSharedStorage::in_memory().unwrap();
            let now = unix_now_seconds_i64();
            {
                let conn = storage.lock().unwrap();
                for index in 0..1_000_i64 {
                    conn.execute(
                        "INSERT INTO public_key_package_eviction_watermarks (
                            account_id_hex, key_package_id, event_id_hex, deleted_event_id,
                            event_created_at, evicted_at, kind
                         ) VALUES (?1, 'slot', ?2, NULL, ?3, ?4, 'replacement')",
                        params![
                            format!("{:064x}", index + 10),
                            format!("{:064x}", index + 10),
                            now - 10,
                            now,
                        ],
                    )
                    .unwrap();
                }
                // Evicted exact_deletion with older created_at and larger event_id.
                conn.execute(
                    "INSERT INTO public_key_package_eviction_watermarks (
                        account_id_hex, key_package_id, event_id_hex, deleted_event_id,
                        event_created_at, evicted_at, kind
                     ) VALUES (?1, 'slot', ?2, NULL, ?3, ?4, 'exact_deletion')",
                    params!["01".repeat(32), "ff".repeat(32), now - 500, now - 100],
                )
                .unwrap();
                // Evicted replacement in the same batch with newer created_at and smaller event_id.
                conn.execute(
                    "INSERT INTO public_key_package_eviction_watermarks (
                        account_id_hex, key_package_id, event_id_hex, deleted_event_id,
                        event_created_at, evicted_at, kind
                     ) VALUES (?1, 'slot', ?2, NULL, ?3, ?4, 'replacement')",
                    params!["02".repeat(32), "00".repeat(32), now - 50, now - 200],
                )
                .unwrap();
            }
            // Trigger `prune_key_package_barriers`.
            storage
                .put_public_key_package_barrier(&key_package_barrier(&"aa".repeat(32), 0))
                .unwrap();

            let fallback = storage
                .key_package_global_eviction()
                .unwrap()
                .expect("global fallback watermark must survive batch eviction");
            assert_eq!(fallback.kind, PublicKeyPackageBarrierKind::ExactDeletion);
            assert_eq!(fallback.observed_at, (now - 100) as u64);
        }

        // Case 2: at equal `event_created_at`, `deletion` dominates a
        // `replacement` even when the replacement has a smaller `event_id_hex`.
        {
            let storage = SqliteSharedStorage::in_memory().unwrap();
            let now = unix_now_seconds_i64();
            {
                let conn = storage.lock().unwrap();
                for index in 0..1_000_i64 {
                    conn.execute(
                        "INSERT INTO public_key_package_eviction_watermarks (
                            account_id_hex, key_package_id, event_id_hex, deleted_event_id,
                            event_created_at, evicted_at, kind
                         ) VALUES (?1, 'slot', ?2, NULL, ?3, ?4, 'replacement')",
                        params![
                            format!("{:064x}", index + 10),
                            format!("{:064x}", index + 10),
                            now - 10,
                            now,
                        ],
                    )
                    .unwrap();
                }
                conn.execute(
                    "INSERT INTO public_key_package_eviction_watermarks (
                        account_id_hex, key_package_id, event_id_hex, deleted_event_id,
                        event_created_at, evicted_at, kind
                     ) VALUES (?1, 'slot', ?2, NULL, ?3, ?4, 'deletion')",
                    params!["01".repeat(32), "ff".repeat(32), now - 200, now - 150],
                )
                .unwrap();
                conn.execute(
                    "INSERT INTO public_key_package_eviction_watermarks (
                        account_id_hex, key_package_id, event_id_hex, deleted_event_id,
                        event_created_at, evicted_at, kind
                     ) VALUES (?1, 'slot', ?2, NULL, ?3, ?4, 'replacement')",
                    params!["02".repeat(32), "00".repeat(32), now - 200, now - 100],
                )
                .unwrap();
            }
            storage
                .put_public_key_package_barrier(&key_package_barrier(&"aa".repeat(32), 0))
                .unwrap();

            let fallback = storage
                .key_package_global_eviction()
                .unwrap()
                .expect("global fallback watermark must survive batch eviction");
            assert_eq!(fallback.kind, PublicKeyPackageBarrierKind::Deletion);
            assert_eq!(fallback.event_created_at, (now - 200) as u64);
            assert_eq!(fallback.observed_at, (now - 100) as u64);
        }
    }

    #[test]
    fn key_package_barriers_bound_accounts_and_keep_the_newest_pruned_fence_atomically() {
        let storage = SqliteSharedStorage::in_memory().unwrap();
        let account = "aa".repeat(32);
        let before = unix_now_seconds_i64() as u64;
        for index in 0..503 {
            let mut record = key_package_barrier(&account, index);
            if index < 3 {
                record.event_id_hex = ["cc", "aa", "bb"][index as usize].repeat(32);
                record.deleted_event_id = Some(format!("{index:064x}"));
                record.event_created_at = fresh_timestamp(50);
            } else {
                record.event_created_at += 100;
            }
            record.observed_at = fresh_timestamp(index);
            storage.put_public_key_package_barrier(&record).unwrap();
        }
        let retained = storage.public_key_package_barriers(&account).unwrap();
        assert_eq!(retained.len(), 500);
        assert_eq!(retained.first().unwrap().key_package_id, "slot-0003");
        let watermark = storage
            .public_key_package_eviction_watermark(&account)
            .unwrap()
            .unwrap();
        assert_eq!(watermark.key_package_id, "slot-0001");
        assert_eq!(watermark.event_id_hex, "aa".repeat(32));
        assert_eq!(watermark.deleted_event_id, Some(format!("{:064x}", 1)));
        assert_eq!(watermark.event_created_at, fresh_timestamp(50));
        assert!((before..=unix_now_seconds_i64() as u64).contains(&watermark.observed_at));
        assert_eq!(
            storage.public_key_package_evicted_at(&account).unwrap(),
            Some(fresh_timestamp(502))
        );

        let older = PublicKeyPackageBarrierRecord {
            event_created_at: fresh_timestamp(40),
            observed_at: 0,
            ..key_package_barrier(&account, 503)
        };
        storage.put_public_key_package_barrier(&older).unwrap();
        let observed_watermark = storage
            .public_key_package_eviction_watermark(&account)
            .unwrap()
            .unwrap();
        assert!(observed_watermark.observed_at >= watermark.observed_at);
        assert_eq!(
            observed_watermark,
            PublicKeyPackageBarrierRecord {
                observed_at: observed_watermark.observed_at,
                ..watermark
            }
        );
        let watermark = observed_watermark;
        storage.lock().unwrap().execute_batch(
            "CREATE TRIGGER reject_barrier_eviction BEFORE INSERT ON public_key_package_eviction_watermarks
             BEGIN SELECT RAISE(ABORT, 'reject eviction'); END;",
        ).unwrap();
        let error = storage
            .put_public_key_package_barrier(&PublicKeyPackageBarrierRecord {
                observed_at: 1000,
                ..key_package_barrier(&account, 504)
            })
            .unwrap_err();
        assert!(matches!(error, StorageError::Backend(message) if message.contains("1811")));
        assert_eq!(
            storage.public_key_package_barriers(&account).unwrap(),
            retained
        );
        assert_eq!(
            storage
                .public_key_package_eviction_watermark(&account)
                .unwrap(),
            Some(watermark)
        );
    }

    #[test]
    fn key_package_barriers_bound_global_state_and_fall_back_after_watermark_eviction() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shared.sqlite3");
        let storage = SqliteSharedStorage::open(&path).unwrap();
        for account in ["bb", "cc"] {
            for index in 0..500 {
                storage
                    .put_public_key_package_barrier(&PublicKeyPackageBarrierRecord {
                        observed_at: index + 100,
                        ..key_package_barrier(&account.repeat(32), index)
                    })
                    .unwrap();
            }
        }
        let account = "aa".repeat(32);
        storage
            .put_public_key_package_barrier(&PublicKeyPackageBarrierRecord {
                event_created_at: fresh_timestamp(2_000),
                observed_at: 1,
                ..key_package_barrier(&account, 0)
            })
            .unwrap();
        assert!(
            storage
                .public_key_package_barriers(&account)
                .unwrap()
                .is_empty()
        );
        let watermark = storage
            .public_key_package_eviction_watermark(&account)
            .unwrap()
            .unwrap();
        assert_eq!(watermark.event_created_at, fresh_timestamp(2_000));
        assert_eq!(
            storage.public_key_package_evicted_at(&account).unwrap(),
            Some(watermark.observed_at)
        );
        assert_eq!(
            storage
                .public_key_package_replacement_evicted_at(&account)
                .unwrap(),
            Some(watermark.observed_at)
        );
        let recreated = PublicKeyPackageBarrierRecord {
            event_created_at: fresh_timestamp(1_999),
            observed_at: 10_000,
            ..key_package_barrier(&account, 0)
        };
        storage.put_public_key_package_barrier(&recreated).unwrap();
        assert_eq!(
            storage
                .public_key_package_eviction_watermark(&account)
                .unwrap(),
            Some(watermark)
        );
        assert_eq!(
            storage
                .lock()
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM public_key_package_barriers",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            1000
        );

        storage
            .lock()
            .unwrap()
            .execute(
                "WITH RECURSIVE ids(id) AS (
                VALUES(0) UNION ALL SELECT id + 1 FROM ids WHERE id < 999
             )
             INSERT INTO public_key_package_eviction_watermarks
                (account_id_hex, key_package_id, event_id_hex, event_created_at, evicted_at, kind)
             SELECT printf('wm-%04d', id), 'slot', 'ee', ?1, 1, 'replacement' FROM ids;",
                params![fresh_timestamp(1) as i64],
            )
            .unwrap();
        storage.put_public_key_package_barrier(&recreated).unwrap();
        assert_eq!(
            storage
                .public_key_package_eviction_watermark("wm-0999")
                .unwrap(),
            None
        );
        assert_eq!(
            storage.public_key_package_evicted_at("wm-0999").unwrap(),
            Some(1)
        );
        assert_eq!(
            storage
                .lock()
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM public_key_package_eviction_watermarks",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            1000
        );
        storage
            .lock()
            .unwrap()
            .execute_batch(
                "INSERT INTO public_key_package_eviction_watermarks
                (account_id_hex, key_package_id, event_id_hex, event_created_at, evicted_at, kind)
             VALUES ('older', 'slot', 'dd', 0, 0, 'replacement');",
            )
            .unwrap();
        storage.put_public_key_package_barrier(&recreated).unwrap();
        assert_eq!(
            storage
                .public_key_package_eviction_watermark("older")
                .unwrap(),
            None
        );
        assert_eq!(
            storage.public_key_package_evicted_at("older").unwrap(),
            Some(1)
        );
        storage.close().unwrap();
        let storage = SqliteSharedStorage::open(&path).unwrap();
        assert_eq!(
            storage.public_key_package_evicted_at("older").unwrap(),
            Some(1)
        );
        assert_eq!(
            storage
                .public_key_package_eviction_watermark("older")
                .unwrap(),
            None
        );
        assert_eq!(
            storage
                .public_key_package_eviction_watermark(&account)
                .unwrap()
                .unwrap()
                .event_created_at,
            fresh_timestamp(2_000)
        );
        assert_eq!(
            storage.public_key_package_barriers(&account).unwrap(),
            [recreated]
        );
    }

    #[test]
    fn key_package_replacements_keep_nip01_winner_and_isolate_slots() {
        let storage = SqliteSharedStorage::in_memory().unwrap();
        let account_id_hex = "aa".repeat(32);
        let base = fresh_timestamp(0);
        let mut winner = PublicKeyPackageReplacementRecord {
            account_id_hex: account_id_hex.clone(),
            key_package_id: "slot-b".into(),
            event_id_hex: "bb".repeat(32),
            event_created_at: base + 20,
            observed_at: 2,
        };
        storage
            .put_public_key_package_replacement(&PublicKeyPackageReplacementRecord {
                event_id_hex: "dd".repeat(32),
                event_created_at: base + 10,
                observed_at: 1,
                ..winner.clone()
            })
            .unwrap();
        storage.put_public_key_package_replacement(&winner).unwrap();
        for loser in [
            PublicKeyPackageReplacementRecord {
                event_id_hex: "00".repeat(32),
                event_created_at: base + 19,
                observed_at: 100,
                ..winner.clone()
            },
            PublicKeyPackageReplacementRecord {
                event_id_hex: "cc".repeat(32),
                observed_at: 101,
                ..winner.clone()
            },
        ] {
            storage.put_public_key_package_replacement(&loser).unwrap();
            assert_eq!(
                storage
                    .public_key_package_replacements(&account_id_hex)
                    .unwrap(),
                [winner.clone()]
            );
        }

        winner.event_id_hex = "aa".repeat(32);
        winner.observed_at = 0;
        storage.put_public_key_package_replacement(&winner).unwrap();
        storage
            .put_public_key_package_replacement(&PublicKeyPackageReplacementRecord {
                observed_at: 102,
                ..winner.clone()
            })
            .unwrap();
        let other_slot = PublicKeyPackageReplacementRecord {
            key_package_id: "slot-a".into(),
            event_id_hex: "ee".repeat(32),
            event_created_at: base + 5,
            observed_at: 4,
            ..winner.clone()
        };
        let other_account = PublicKeyPackageReplacementRecord {
            account_id_hex: "ff".repeat(32),
            event_id_hex: "ff".repeat(32),
            event_created_at: base + 1,
            observed_at: 5,
            ..winner.clone()
        };
        storage
            .put_public_key_package_replacement(&other_account)
            .unwrap();
        storage
            .put_public_key_package_replacement(&other_slot)
            .unwrap();

        assert_eq!(
            storage
                .public_key_package_replacements(&account_id_hex)
                .unwrap(),
            [other_slot, winner]
        );
        assert_eq!(
            storage
                .public_key_package_replacements(&other_account.account_id_hex)
                .unwrap(),
            [other_account]
        );
    }

    #[test]
    fn stale_key_package_evidence_does_not_reach_watermarks() {
        let storage = SqliteSharedStorage::in_memory().unwrap();
        let account = "aa".repeat(32);
        storage
            .put_public_key_package_replacement(&PublicKeyPackageReplacementRecord {
                account_id_hex: account.clone(),
                key_package_id: "stale".into(),
                event_id_hex: "bb".repeat(32),
                event_created_at: 0,
                observed_at: 0,
            })
            .unwrap();
        assert!(
            storage
                .public_key_package_replacements(&account)
                .unwrap()
                .is_empty()
        );
        storage
            .put_public_key_package_barrier(&PublicKeyPackageBarrierRecord {
                account_id_hex: account.clone(),
                key_package_id: "stale".into(),
                event_id_hex: "cc".repeat(32),
                deleted_event_id: None,
                event_created_at: 0,
                observed_at: 0,
                kind: PublicKeyPackageBarrierKind::Replacement,
            })
            .unwrap();
        assert!(
            storage
                .public_key_package_barriers(&account)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            storage
                .public_key_package_eviction_watermark(&account)
                .unwrap(),
            None
        );

        let event_account = "ee".repeat(32);
        let event_barrier = PublicKeyPackageBarrierRecord {
            account_id_hex: event_account.clone(),
            key_package_id: String::new(),
            event_id_hex: "ff".repeat(32),
            deleted_event_id: Some("12".repeat(32)),
            event_created_at: 0,
            observed_at: unix_now_seconds_i64() as u64,
            kind: PublicKeyPackageBarrierKind::Deletion,
        };
        storage
            .put_public_key_package_barrier(&event_barrier)
            .unwrap();
        assert_eq!(
            storage.public_key_package_barriers(&event_account).unwrap(),
            [event_barrier]
        );

        let exact_account = "dd".repeat(32);
        let evicted_at = unix_now_seconds_i64();
        storage
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO public_key_package_eviction_watermarks (
                    account_id_hex, key_package_id, event_id_hex,
                    event_created_at, evicted_at, kind
                 ) VALUES (?1, 'slot', 'ee', 0, ?2, 'exact_deletion')",
                params![&exact_account, evicted_at],
            )
            .unwrap();
        storage
            .put_public_key_package_barrier(&key_package_barrier(&exact_account, 1))
            .unwrap();
        let exact = storage
            .public_key_package_eviction_watermark(&exact_account)
            .unwrap()
            .unwrap();
        assert_eq!(exact.kind, PublicKeyPackageBarrierKind::ExactDeletion);
        assert_eq!(exact.observed_at, evicted_at as u64);
    }

    #[test]
    fn key_package_replacements_are_bounded_per_account() {
        let storage = SqliteSharedStorage::in_memory().unwrap();
        let account_id_hex = "aa".repeat(32);
        for index in 0..=KEY_PACKAGE_REPLACEMENT_CAP as u64 {
            storage
                .put_public_key_package_replacement(&PublicKeyPackageReplacementRecord {
                    account_id_hex: account_id_hex.clone(),
                    key_package_id: format!("slot-{index:04}"),
                    event_id_hex: format!("{index:064x}"),
                    event_created_at: fresh_timestamp(index),
                    observed_at: index,
                })
                .unwrap();
        }
        let records = storage
            .public_key_package_replacements(&account_id_hex)
            .unwrap();
        assert!(
            storage
                .public_key_package_replacement_evicted_at(&account_id_hex)
                .unwrap()
                .is_some()
        );
        assert_eq!(records.len(), KEY_PACKAGE_REPLACEMENT_CAP as usize);
        assert!(
            !records
                .iter()
                .any(|record| record.key_package_id == "slot-0000")
        );
        assert!(
            records
                .iter()
                .any(|record| record.key_package_id == "slot-0500")
        );
    }

    #[test]
    fn key_package_replacements_are_globally_bounded() {
        let storage = SqliteSharedStorage::in_memory().unwrap();
        for account in ["aa".repeat(32), "bb".repeat(32)] {
            for index in 0..KEY_PACKAGE_REPLACEMENT_CAP as u64 {
                storage
                    .put_public_key_package_replacement(&PublicKeyPackageReplacementRecord {
                        account_id_hex: account.clone(),
                        key_package_id: format!("slot-{index:04}"),
                        event_id_hex: format!("{index:064x}"),
                        event_created_at: fresh_timestamp(index),
                        observed_at: index,
                    })
                    .unwrap();
            }
        }
        storage
            .put_public_key_package_replacement(&PublicKeyPackageReplacementRecord {
                account_id_hex: "cc".repeat(32),
                key_package_id: "latest".into(),
                event_id_hex: "ff".repeat(32),
                event_created_at: fresh_timestamp(1_000),
                observed_at: 1_000,
            })
            .unwrap();
        let count: i64 = storage
            .lock()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM directory_key_package_replacements",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, KEY_PACKAGE_REPLACEMENT_GLOBAL_CAP);
        let first_evicted = storage
            .public_key_package_replacement_evicted_at(&"aa".repeat(32))
            .unwrap()
            .is_some();
        let second_evicted = storage
            .public_key_package_replacement_evicted_at(&"bb".repeat(32))
            .unwrap()
            .is_some();
        assert!(first_evicted || second_evicted);
    }

    #[test]
    fn key_package_replacement_retention_converts_account_and_global_evictions_to_barriers() {
        let storage = SqliteSharedStorage::in_memory().unwrap();
        let account = "aa".repeat(32);
        for index in 0..501 {
            let barrier = key_package_barrier(&account, index);
            storage
                .put_public_key_package_replacement(&PublicKeyPackageReplacementRecord {
                    account_id_hex: barrier.account_id_hex,
                    key_package_id: barrier.key_package_id,
                    event_id_hex: barrier.event_id_hex,
                    event_created_at: barrier.event_created_at,
                    observed_at: barrier.observed_at,
                })
                .unwrap();
        }
        assert_eq!(
            storage
                .public_key_package_replacements(&account)
                .unwrap()
                .len(),
            500
        );
        assert_eq!(
            storage.public_key_package_barriers(&account).unwrap(),
            [key_package_barrier(&account, 0)]
        );
        assert_eq!(
            storage
                .public_key_package_replacement_evicted_at(&account)
                .unwrap(),
            Some(0)
        );
        let other_account = "bb".repeat(32);
        storage
            .lock()
            .unwrap()
            .execute(
                "WITH RECURSIVE ids(id) AS (
                VALUES(0) UNION ALL SELECT id + 1 FROM ids WHERE id < 499
             )
             INSERT INTO directory_key_package_replacements
                (account_id_hex, key_package_id, event_id_hex, event_created_at, observed_at)
             SELECT ?1, printf('slot-%04d', id), printf('%064x', id), ?2 + id, id + 1000 FROM ids",
                params![&other_account, fresh_timestamp(0) as i64],
            )
            .unwrap();
        let final_account = "cc".repeat(32);
        storage
            .put_public_key_package_replacement(&PublicKeyPackageReplacementRecord {
                account_id_hex: final_account.clone(),
                key_package_id: "slot".into(),
                event_id_hex: "ff".repeat(32),
                event_created_at: fresh_timestamp(2_000),
                observed_at: 2000,
            })
            .unwrap();
        assert_eq!(
            storage
                .public_key_package_replacements(&account)
                .unwrap()
                .len(),
            499
        );
        assert_eq!(
            storage
                .public_key_package_replacements(&other_account)
                .unwrap()
                .len(),
            500
        );
        assert_eq!(
            storage
                .public_key_package_replacements(&final_account)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            storage.public_key_package_barriers(&account).unwrap(),
            [
                key_package_barrier(&account, 0),
                key_package_barrier(&account, 1),
            ]
        );
    }

    #[test]
    fn evidence_revisions_do_not_repeat_after_pruning() {
        let storage = SqliteSharedStorage::in_memory().unwrap();
        let account = "aa".repeat(32);
        let mut conn = storage.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        bump_key_package_revision(&tx, &account).unwrap();
        let first = SqliteSharedStorage::read_key_package_evidence_revision(&tx, &account).unwrap();
        tx.execute(
            "DELETE FROM public_key_package_evidence_revisions WHERE account_id_hex = ?1",
            [&account],
        )
        .unwrap();
        bump_key_package_revision(&tx, &account).unwrap();
        let second =
            SqliteSharedStorage::read_key_package_evidence_revision(&tx, &account).unwrap();
        assert!(second > first, "{first} then {second}");
    }

    #[test]
    fn key_package_evidence_snapshot_is_atomic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shared.sqlite3");
        let storage = SqliteSharedStorage::open(&path).unwrap();
        let account = "aa".repeat(32);
        let base = fresh_timestamp(0);
        storage
            .put_public_key_package_replacement(&PublicKeyPackageReplacementRecord {
                account_id_hex: account.clone(),
                key_package_id: "slot".into(),
                event_id_hex: "bb".repeat(32),
                event_created_at: base + 20,
                observed_at: 30,
            })
            .unwrap();
        interleave(
            &storage,
            &path,
            "SELECT revision FROM public_key_package_evidence_revisions",
            format!(
                "INSERT INTO directory_key_package_replacements (
                     account_id_hex, key_package_id, event_id_hex, event_created_at, observed_at
                 ) VALUES ('{account}', 'later', '{}', {}, 31);
                 UPDATE public_key_package_evidence_revisions SET revision = 2
                 WHERE account_id_hex = '{account}';",
                "cc".repeat(32),
                base + 21,
            ),
        );
        let snapshot = storage.key_package_evidence_snapshot(&account).unwrap();
        assert_eq!(snapshot.replacements.len(), 1);
        assert_eq!(snapshot.revision, 1);
        let next = storage.key_package_evidence_snapshot(&account).unwrap();
        assert_eq!(next.replacements.len(), 2);
        assert_eq!(next.revision, 2);
    }

    #[test]
    fn key_package_replacements_survive_reopen_without_package_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shared.sqlite3");
        let storage = SqliteSharedStorage::open(&path).unwrap();
        let base = fresh_timestamp(0);
        let record = PublicKeyPackageReplacementRecord {
            account_id_hex: "aa".repeat(32),
            key_package_id: "slot".into(),
            event_id_hex: "bb".repeat(32),
            event_created_at: base + 20,
            observed_at: 30,
        };
        storage.put_public_key_package_replacement(&record).unwrap();
        let barrier = PublicKeyPackageBarrierRecord {
            account_id_hex: record.account_id_hex.clone(),
            key_package_id: record.key_package_id.clone(),
            event_id_hex: "cc".repeat(32),
            deleted_event_id: Some(record.event_id_hex.clone()),
            event_created_at: base + 25,
            observed_at: fresh_timestamp(31),
            kind: PublicKeyPackageBarrierKind::Deletion,
        };
        storage.put_public_key_package_barrier(&barrier).unwrap();
        storage.close().unwrap();

        let storage = SqliteSharedStorage::open(&path).unwrap();
        assert_eq!(
            storage
                .public_key_package_replacements(&record.account_id_hex)
                .unwrap(),
            [record]
        );
        assert_eq!(
            storage.table_columns("directory_key_package_replacements"),
            [
                "account_id_hex",
                "key_package_id",
                "event_id_hex",
                "event_created_at",
                "observed_at"
            ]
        );
        assert_eq!(
            storage
                .public_key_package_barriers(&barrier.account_id_hex)
                .unwrap(),
            [barrier]
        );
        assert_eq!(
            storage.table_columns("public_key_package_barriers"),
            [
                "account_id_hex",
                "key_package_id",
                "event_id_hex",
                "deleted_event_id",
                "event_created_at",
                "observed_at",
                "kind",
            ]
        );
        assert_eq!(
            storage.table_columns("public_key_package_eviction_watermarks"),
            [
                "account_id_hex",
                "key_package_id",
                "event_id_hex",
                "deleted_event_id",
                "event_created_at",
                "evicted_at",
                "kind",
            ]
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

#[cfg(test)]
mod migration_contract_tests {
    use super::*;

    #[test]
    fn fresh_shared_storage_records_current_version() {
        let storage = SqliteSharedStorage::in_memory().unwrap();
        let row: (i64, String) = storage
            .lock()
            .unwrap()
            .query_row(
                "SELECT version, name FROM shared_schema_migrations ORDER BY version DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(row, (6, "0006_directory_follows_created_at".into()));
    }

    #[test]
    fn shared_storage_refuses_malformed_unversioned_table() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE directory_users (account_id_hex TEXT)")
            .unwrap();
        assert_eq!(
            SqliteSharedStorage::from_connection(conn)
                .unwrap_err()
                .to_string(),
            "backend failure: invalid shared store schema shape"
        );
    }

    #[test]
    fn shared_storage_open_supports_bare_and_current_dir_paths_without_changing_cwd_mode() {
        const CHILD_ENV: &str = "MDK_TEST_SHARED_STORAGE_CWD_CHILD";
        if std::env::var_os(CHILD_ENV).is_some() {
            let bare = SqliteSharedStorage::open("bare.sqlite3")
                .expect("bare filename in CWD should open");
            bare.close().unwrap();
            let dotted = SqliteSharedStorage::open(Path::new(".").join("dotted.sqlite3"))
                .expect("./-prefixed filename in CWD should open");
            dotted.close().unwrap();
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .current_dir(dir.path())
            .args([
                "--exact",
                "shared::migration_contract_tests::shared_storage_open_supports_bare_and_current_dir_paths_without_changing_cwd_mode",
            ])
            .env(CHILD_ENV, "1")
            .status()
            .unwrap();
        assert!(status.success(), "child CWD open test failed: {status}");
        assert!(dir.path().join("bare.sqlite3").exists());
        assert!(dir.path().join("dotted.sqlite3").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                dir.path().metadata().unwrap().permissions().mode() & 0o777,
                0o755,
                "opening a shared DB in CWD must preserve CWD permissions"
            );
            assert_eq!(
                dir.path()
                    .join("bare.sqlite3")
                    .metadata()
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            assert_eq!(
                dir.path()
                    .join("dotted.sqlite3")
                    .metadata()
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
}

#[cfg(test)]
mod usage_diagnostics_tests {
    use super::*;
    #[test]
    fn migration_preserves_legacy_opt_in_interval_and_audit() {
        for enabled in [false, true] {
            let connection = rusqlite::Connection::open_in_memory().unwrap();
            connection
                .execute_batch(include_str!("shared/v1.sql"))
                .unwrap();
            connection.execute("INSERT INTO relay_telemetry_settings(id,export_enabled,export_interval_seconds,updated_at_ms) VALUES(1,?1,73,0)",[enabled]).unwrap();
            connection
                .execute(
                    "INSERT INTO audit_log_settings(id,enabled,updated_at_ms) VALUES(1,1,0)",
                    [],
                )
                .unwrap();
            let store = SqliteSharedStorage::from_connection(connection).unwrap();
            let receipt = store.usage_diagnostics_settings().unwrap();
            assert_eq!(receipt.decision, 0);
            assert_eq!(receipt.previously_enabled, enabled);
            assert_eq!(
                store
                    .relay_telemetry_settings()
                    .unwrap()
                    .export_interval_seconds,
                73
            );
            assert!(store.audit_log_settings().unwrap().enabled);
        }
    }
    #[test]
    fn receipt_and_identity_are_atomic() {
        let store = SqliteSharedStorage::in_memory().unwrap();
        let granted = StoredUsageDiagnosticsSettings {
            decision: 2,
            policy_revision: "p".into(),
            registry_revision: "r".into(),
            scope_revision: "s".into(),
            updated_at_ms: 123456,
            ..Default::default()
        };
        store
            .set_usage_diagnostics_settings(&granted, Some("new-id"))
            .unwrap();
        assert_eq!(store.usage_diagnostics_settings().unwrap(), granted);
        assert_eq!(
            store.telemetry_install_id().unwrap().as_deref(),
            Some("new-id")
        );
        // The identity write is the last statement: when it fails, the
        // receipt and the old identity's removal before it roll back.
        store
            .lock()
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER reject_install BEFORE INSERT ON telemetry_install
                 BEGIN SELECT RAISE(ABORT, 'private trigger text'); END",
            )
            .unwrap();
        let declined = StoredUsageDiagnosticsSettings {
            decision: 1,
            updated_at_ms: 123457,
            ..granted.clone()
        };
        let refused = store.set_usage_diagnostics_settings(&declined, Some("other-id"));
        assert!(
            matches!(
                &refused,
                Err(StorageError::Backend(message))
                    if message.contains("1811") && !message.contains("private")
            ),
            "{refused:?}"
        );
        assert_eq!(store.usage_diagnostics_settings().unwrap(), granted);
        assert_eq!(
            store.telemetry_install_id().unwrap().as_deref(),
            Some("new-id")
        );
        store
            .lock()
            .unwrap()
            .execute_batch("DROP TRIGGER reject_install")
            .unwrap();
        store
            .set_usage_diagnostics_settings(&declined, None)
            .unwrap();
        assert_eq!(store.usage_diagnostics_settings().unwrap(), declined);
        assert!(store.telemetry_install_id().unwrap().is_none());
    }
}
