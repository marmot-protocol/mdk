//! SQLCipher key derivation, salt persistence, and legacy-database migration.
//!
//! This module owns the security-critical key-material derivation for the
//! per-account-device SQLCipher databases: stable per-database salts, the HKDF
//! v2 key derivation, the legacy (v1) key derivation kept for migration, the
//! crash-safe salt-write/rekey sequence, and recovery for interrupted or
//! pre-fix bricked migrations.
//!
//! Every one of those recovery opens pays the full SQLCipher passphrase KDF
//! (PBKDF2-HMAC-SHA512, 256k iterations at the pinned `cipher_compatibility =
//! 4`). To keep the healthy steady state from paying that KDF twice per open,
//! a successful "this database opens under the v2 key" verdict is cached
//! in-process per database file and salt (mdk#1439). The cache is advisory
//! only: a durable migration marker or a missing verdict always re-runs the
//! recovery probe, so the crash windows keep the #219 self-heal. Key
//! presentation (passphrase vs raw key) and the KDF work factor are unchanged;
//! that decision is recorded in
//! `docs/marmot-architecture/storage-format-v2.md`.

use std::collections::{HashMap, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};

use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use storage_sqlite::{SqlCipherHardening, SqlCipherKey, open_hardened_sqlcipher};
use zeroize::Zeroizing;

use crate::{AppError, MarmotApp};
use marmot_account::EXTERNAL_SQLCIPHER_SECRET_FILE;

const SQLCIPHER_SALT_SUFFIX: &str = ".salt";
const SQLCIPHER_MIGRATION_MARKER_SUFFIX: &str = ".salt-migrating";
const SQLCIPHER_SALT_LEN: usize = 32;
const SQLCIPHER_KEY_LEN: usize = 32;

/// Bound on the in-process v2-open verdict cache. Three databases per account
/// (session, account projection, directory cache), so this covers ~85 accounts
/// per process; overflow evicts oldest-first and an evicted entry simply pays
/// one recovery probe on its next open. Tracked per the long-lived-state
/// discipline in `docs/marmot-architecture/runtime-state-bounds.md`.
const SQLCIPHER_V2_VERDICT_CACHE_CAPACITY: usize = 256;

/// Aggregate, privacy-safe counters for the opt-in app-performance export:
/// every run of the interrupted-migration probe is one full keyed open paying
/// the SQLCipher passphrase KDF, and every skip is one KDF avoided via a
/// cached verdict (mdk#1439). Counts only — no paths, accounts, or keys.
static SQLCIPHER_MIGRATION_PROBE_RUNS: AtomicU64 = AtomicU64::new(0);
static SQLCIPHER_MIGRATION_PROBE_SKIPS: AtomicU64 = AtomicU64::new(0);

/// Process-local cache of probe verdicts: database file -> salt whose derived
/// v2 key was *observed* to open that database earlier in this process (a
/// successful probe, or a legacy -> v2 rekey this process performed). A verdict
/// lets the healthy steady-state path skip the recovery probe — a full second
/// keyed open that pays the same 256k-iteration passphrase KDF as the real open
/// (mdk#1439).
///
/// Safety rules:
/// - A verdict is recorded only after the database at that path was observed
///   opening under the v2 key derived from that exact salt. Never on the
///   fresh-database path, where no database file has been observed yet.
/// - A durable migration marker always forces the probe, verdict or not: the
///   marker means a migration may have been interrupted, and those crash
///   windows must keep the #219 self-heal.
/// - A cache miss, an invalidated entry, or any doubt means probe. Eviction
///   and removal-invalidation only ever cause an *extra* probe.
static SQLCIPHER_V2_VERDICTS: LazyLock<Mutex<SqlcipherV2VerdictCache>> =
    LazyLock::new(|| Mutex::new(SqlcipherV2VerdictCache::new()));

/// Aggregate probe run/skip counts since process start
/// `(runs, skips)`, exported via the app-performance telemetry snapshot.
pub(crate) fn sqlcipher_migration_probe_counters() -> (u64, u64) {
    (
        SQLCIPHER_MIGRATION_PROBE_RUNS.load(Ordering::Relaxed),
        SQLCIPHER_MIGRATION_PROBE_SKIPS.load(Ordering::Relaxed),
    )
}

struct SqlcipherV2VerdictCache {
    by_path: HashMap<PathBuf, [u8; SQLCIPHER_SALT_LEN]>,
    insertion_order: VecDeque<PathBuf>,
}

impl SqlcipherV2VerdictCache {
    fn new() -> Self {
        Self {
            by_path: HashMap::new(),
            insertion_order: VecDeque::new(),
        }
    }

    fn contains(&self, db_path: &Path, salt: &[u8; SQLCIPHER_SALT_LEN]) -> bool {
        self.by_path.get(db_path) == Some(salt)
    }

    fn record(&mut self, db_path: PathBuf, salt: [u8; SQLCIPHER_SALT_LEN]) {
        if self.by_path.insert(db_path.clone(), salt).is_none() {
            self.insertion_order.push_back(db_path);
        }
        while self.by_path.len() > SQLCIPHER_V2_VERDICT_CACHE_CAPACITY {
            let Some(evicted) = self.insertion_order.pop_front() else {
                break;
            };
            self.by_path.remove(&evicted);
        }
    }

    fn invalidate(&mut self, db_path: &Path) {
        if self.by_path.remove(db_path).is_some() {
            self.insertion_order.retain(|path| path != db_path);
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.by_path.len()
    }
}

/// Cache key for verdicts. Canonicalizing merges spellings of the same file
/// (e.g. symlinked roots such as `/var` vs `/private/var`); on any failure the
/// literal path is used, which can only split an entry into two — never merge
/// two different databases into one verdict.
fn sqlcipher_verdict_cache_key(db_path: &Path) -> PathBuf {
    fs::canonicalize(db_path).unwrap_or_else(|_| db_path.to_path_buf())
}

fn lock_sqlcipher_v2_verdicts() -> std::sync::MutexGuard<'static, SqlcipherV2VerdictCache> {
    SQLCIPHER_V2_VERDICTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn sqlcipher_v2_verdict_cached(db_path: &Path, salt: &[u8; SQLCIPHER_SALT_LEN]) -> bool {
    lock_sqlcipher_v2_verdicts().contains(&sqlcipher_verdict_cache_key(db_path), salt)
}

fn sqlcipher_v2_verdict_record(db_path: &Path, salt: &[u8; SQLCIPHER_SALT_LEN]) {
    lock_sqlcipher_v2_verdicts().record(sqlcipher_verdict_cache_key(db_path), *salt);
}

fn sqlcipher_v2_verdict_invalidate(db_path: &Path) {
    lock_sqlcipher_v2_verdicts().invalidate(&sqlcipher_verdict_cache_key(db_path));
}

/// Test-only per-path count of recovery probes actually executed, so tests can
/// assert how often the full keyed probe open ran for one database regardless
/// of other tests sharing this process (the aggregate counters above are
/// process-global and would race under parallel test execution).
#[cfg(test)]
static PROBE_ATTEMPTS_BY_PATH: LazyLock<Mutex<HashMap<PathBuf, usize>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[cfg(test)]
fn record_probe_attempt_for_test(db_path: &Path) {
    let mut attempts = PROBE_ATTEMPTS_BY_PATH
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *attempts
        .entry(sqlcipher_verdict_cache_key(db_path))
        .or_insert(0) += 1;
}

#[cfg(test)]
fn probe_attempts_for_test(db_path: &Path) -> usize {
    PROBE_ATTEMPTS_BY_PATH
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(&sqlcipher_verdict_cache_key(db_path))
        .copied()
        .unwrap_or(0)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SqlcipherDatabaseKind {
    Session,
    AccountProjection,
    DirectoryCache,
}

impl SqlcipherDatabaseKind {
    fn hkdf_info_label(self) -> &'static [u8] {
        match self {
            Self::Session => b"marmot-app/session-sqlcipher-key/v2",
            Self::AccountProjection => b"marmot-app/account-projection-sqlcipher-key/v2",
            Self::DirectoryCache => b"marmot-app/directory-cache-sqlcipher-key/v2",
        }
    }

    fn legacy_hash_label(self) -> &'static [u8] {
        match self {
            Self::Session | Self::AccountProjection => b"marmot-app-sqlcipher-key-v1",
            Self::DirectoryCache => b"marmot-app-directory-cache-sqlcipher-key-v1",
        }
    }
}

impl MarmotApp {
    pub(crate) fn sqlcipher_key(
        &self,
        label: &str,
        keys: &nostr::Keys,
        db_path: &Path,
        kind: SqlcipherDatabaseKind,
    ) -> Result<SqlCipherKey, AppError> {
        let salt = self.sqlcipher_salt(label, keys, db_path, kind)?;
        Ok(SqlCipherKey::new(derive_sqlcipher_key_material(
            label, keys, &salt, kind,
        )?)?)
    }

    pub(crate) fn external_sqlcipher_key(
        &self,
        label: &str,
        account_id_hex: &str,
        db_path: &Path,
        kind: SqlcipherDatabaseKind,
    ) -> Result<SqlCipherKey, AppError> {
        let salt = self.external_sqlcipher_salt(db_path)?;
        let secret = self.external_sqlcipher_secret(label)?;
        Ok(SqlCipherKey::new(derive_external_sqlcipher_key_material(
            label,
            account_id_hex,
            &secret,
            &salt,
            kind,
        )?)?)
    }

    fn external_sqlcipher_secret(
        &self,
        label: &str,
    ) -> Result<Zeroizing<[u8; SQLCIPHER_KEY_LEN]>, AppError> {
        let path = self.account_dir(label).join(EXTERNAL_SQLCIPHER_SECRET_FILE);
        if path.exists() {
            let raw = fs::read_to_string(&path)?;
            let bytes = hex::decode(raw.trim())?;
            let secret: [u8; SQLCIPHER_KEY_LEN] = bytes.try_into().map_err(|_| {
                AppError::SqlcipherKeyDerivation(format!(
                    "invalid external SQLCipher secret length in {}",
                    path.display()
                ))
            })?;
            return Ok(Zeroizing::new(secret));
        }
        let mut secret = [0_u8; SQLCIPHER_KEY_LEN];
        OsRng.fill_bytes(&mut secret);
        let encoded = hex::encode(secret);
        match write_private_new(&path, encoded.as_bytes()) {
            Ok(()) => Ok(Zeroizing::new(secret)),
            Err(AppError::Io(err)) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                self.external_sqlcipher_secret(label)
            }
            Err(err) => Err(err),
        }
    }

    fn external_sqlcipher_salt(
        &self,
        db_path: &Path,
    ) -> Result<[u8; SQLCIPHER_SALT_LEN], AppError> {
        let salt_path = sqlcipher_salt_path(db_path);
        if salt_path.exists() {
            return read_sqlcipher_salt(&salt_path);
        }
        let mut salt = [0_u8; SQLCIPHER_SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let encoded = hex::encode(salt);
        match write_private_new(&salt_path, encoded.as_bytes()) {
            Ok(()) => Ok(salt),
            Err(AppError::Io(err)) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                read_sqlcipher_salt(&salt_path)
            }
            Err(err) => Err(err),
        }
    }

    fn sqlcipher_salt(
        &self,
        label: &str,
        keys: &nostr::Keys,
        db_path: &Path,
        kind: SqlcipherDatabaseKind,
    ) -> Result<[u8; SQLCIPHER_SALT_LEN], AppError> {
        let salt_path = sqlcipher_salt_path(db_path);
        let marker_path = sqlcipher_migration_marker_path(db_path);

        if salt_path.exists() {
            let salt = read_sqlcipher_salt(&salt_path)?;
            // The salt is durable, so the v2 key is reproducible. But an existing
            // on-disk database may not yet honor that key: a migration can have
            // been interrupted between making the salt durable and committing
            // `PRAGMA rekey`, leaving the database still legacy-keyed. There are
            // two shapes of this:
            //   * a marker is present — an interrupted migration started by the
            //     crash-safe path below, or
            //   * NO marker is present, but the database is still legacy-keyed —
            //     the pre-fix #219 bricked state, where the salt was written
            //     before the rekey and the process crashed in between. No marker
            //     was written back then, so a marker check alone never recovers
            //     these already-bricked accounts.
            // `finish_interrupted_sqlcipher_migration` probes the v2 key first
            // (a cheap no-op logically when the database is already migrated or
            // freshly v2-keyed — but a full keyed open paying the passphrase KDF
            // physically) and only re-runs the legacy -> v2 rekey when that
            // probe fails.
            //
            // The probe must run whenever the migration marker exists or this
            // process has not yet established that this database opens under
            // the v2 key for this salt — those are the crash windows the #219
            // self-heal exists for. Once a verdict has been established, the
            // healthy steady-state path skips the probe so a repeated open of
            // the same database pays the SQLCipher KDF once, not twice
            // (mdk#1439).
            if db_path.exists() {
                if !marker_path.exists() && sqlcipher_v2_verdict_cached(db_path, &salt) {
                    SQLCIPHER_MIGRATION_PROBE_SKIPS.fetch_add(1, Ordering::Relaxed);
                } else {
                    finish_interrupted_sqlcipher_migration(label, keys, db_path, kind, &salt)?;
                    // Success means the database was just observed opening
                    // under the v2 key (the probe) or was just rekeyed to it.
                    sqlcipher_v2_verdict_record(db_path, &salt);
                }
            }
            let _ = fs::remove_file(&marker_path);
            return Ok(salt);
        }

        let mut salt = [0_u8; SQLCIPHER_SALT_LEN];
        OsRng.fill_bytes(&mut salt);

        if db_path.exists() {
            // Legacy (v1-keyed) database present: migrate it to the salted v2
            // key. The ordering here is crash-safety critical:
            //   1. drop a durable migration marker,
            //   2. persist the salt atomically (so the v2 key is reproducible
            //      after a crash),
            //   3. rekey legacy -> v2,
            //   4. clear the marker.
            // A crash at any point before step 4 leaves the marker set, so the
            // next open runs recovery instead of deriving a v2 key the on-disk
            // database cannot honor.
            write_sqlcipher_migration_marker(&marker_path)?;
            write_sqlcipher_salt(&salt_path, &salt)?;
            let legacy_key = SqlCipherKey::new(legacy_sqlcipher_key_material(label, keys, kind))?;
            let new_key =
                SqlCipherKey::new(derive_sqlcipher_key_material(label, keys, &salt, kind)?)?;
            if let Err(err) = rekey_legacy_sqlcipher_database(db_path, &legacy_key, &new_key) {
                // `PRAGMA rekey` is transactional and rolls back on error, so
                // the database is still legacy-keyed. Roll back our sidecars so
                // the next open retries cleanly from the legacy key.
                let _ = fs::remove_file(&salt_path);
                let _ = fs::remove_file(&marker_path);
                return Err(err);
            }
            // The rekey committed: the database is now v2-keyed under this
            // salt, so later opens in this process can skip the probe.
            sqlcipher_v2_verdict_record(db_path, &salt);
            let _ = fs::remove_file(&marker_path);
        } else {
            // Fresh database: no rekey needed. Persist the salt atomically so a
            // crash mid-write cannot leave a truncated salt that bricks the
            // fresh database on the next open.
            write_sqlcipher_salt(&salt_path, &salt)?;
        }

        Ok(salt)
    }
}

fn sqlcipher_salt_path(db_path: &Path) -> PathBuf {
    let Some(file_name) = db_path.file_name() else {
        return db_path.with_extension("salt");
    };
    let mut salt_file_name = file_name.to_os_string();
    salt_file_name.push(SQLCIPHER_SALT_SUFFIX);
    db_path.with_file_name(salt_file_name)
}

fn sqlcipher_migration_marker_path(db_path: &Path) -> PathBuf {
    let Some(file_name) = db_path.file_name() else {
        return db_path.with_extension("salt-migrating");
    };
    let mut marker_file_name = file_name.to_os_string();
    marker_file_name.push(SQLCIPHER_MIGRATION_MARKER_SUFFIX);
    db_path.with_file_name(marker_file_name)
}

fn read_sqlcipher_salt(path: &Path) -> Result<[u8; SQLCIPHER_SALT_LEN], AppError> {
    let raw = fs::read_to_string(path)?;
    let bytes = hex::decode(raw.trim())?;
    bytes.try_into().map_err(|_| {
        AppError::SqlcipherKeyDerivation(format!("invalid salt length in {}", path.display()))
    })
}

/// Persist a file atomically: write to a sibling temp file, fsync its contents,
/// rename it over the target, and fsync the parent directory so both the rename
/// and the file data are durable. A crash at any point leaves either the old
/// contents or the fully written new contents — never a truncated file.
fn atomic_write(path: &Path, contents: &[u8]) -> Result<(), AppError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp_path = {
        let file_name = path
            .file_name()
            .map(|name| name.to_os_string())
            .unwrap_or_default();
        let mut tmp_name = file_name;
        // Distinguish the temp file with a pid suffix so concurrent writers do
        // not clobber each other's in-progress temp files.
        tmp_name.push(format!(".tmp.{}", std::process::id()));
        path.with_file_name(tmp_name)
    };

    // Owner-only from creation: the salt is key-derivation material and the
    // rename target inherits the temp file's mode. write_private also
    // tightens the inode before writing, so a leftover permissive temp file
    // from an older build (or pid reuse) cannot smuggle its mode into place.
    fs_private::write_private(&tmp_path, contents)?;

    if let Err(err) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(err.into());
    }

    if let Some(parent) = path.parent() {
        // Best-effort directory fsync so the rename itself is durable. Not all
        // platforms allow opening a directory for this; ignore failures.
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

fn write_private_new(path: &Path, contents: &[u8]) -> Result<(), AppError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    if let Some(parent) = path.parent()
        && let Ok(dir) = File::open(parent)
    {
        let _ = dir.sync_all();
    }
    Ok(())
}

fn write_sqlcipher_salt(path: &Path, salt: &[u8; SQLCIPHER_SALT_LEN]) -> Result<(), AppError> {
    atomic_write(path, hex::encode(salt).as_bytes())
}

fn write_sqlcipher_migration_marker(path: &Path) -> Result<(), AppError> {
    atomic_write(path, b"migrating\n")
}

/// Recover from a salt-migration that was interrupted before its marker was
/// cleared. The salt is already durable, so the v2 key is reproducible. The
/// on-disk database is in one of two states: either already rekeyed to the v2
/// key (the rekey committed but the process died before the marker was
/// removed), or still legacy-keyed (the rekey transaction never committed and
/// rolled back). Probe with the v2 key first; if it opens, the migration is
/// complete. If not, re-run the legacy -> v2 rekey. Idempotent: safe to run
/// repeatedly.
fn finish_interrupted_sqlcipher_migration(
    label: &str,
    keys: &nostr::Keys,
    db_path: &Path,
    kind: SqlcipherDatabaseKind,
    salt: &[u8; SQLCIPHER_SALT_LEN],
) -> Result<(), AppError> {
    if !db_path.exists() {
        // No database to migrate (e.g. interrupted before the fresh-DB path even
        // created a file). The durable salt is authoritative for the next open.
        return Ok(());
    }

    let new_key = SqlCipherKey::new(derive_sqlcipher_key_material(label, keys, salt, kind)?)?;

    // Does the database already open under the v2 key? This probe is a full
    // keyed open and pays the complete SQLCipher passphrase KDF (mdk#1439), so
    // it is counted for the aggregate telemetry counters and only runs when no
    // cached verdict covers this database+salt pair.
    let conn = Connection::open(db_path)?;
    SQLCIPHER_MIGRATION_PROBE_RUNS.fetch_add(1, Ordering::Relaxed);
    #[cfg(test)]
    record_probe_attempt_for_test(db_path);
    if open_hardened_sqlcipher(&conn, &new_key, SqlCipherHardening::cipher_only()).is_ok() {
        return Ok(());
    }
    drop(conn);

    // Still legacy-keyed: re-run the rekey. `PRAGMA rekey` is transactional, so
    // a crash here simply leaves the marker in place for the next attempt.
    let legacy_key = SqlCipherKey::new(legacy_sqlcipher_key_material(label, keys, kind))?;
    rekey_legacy_sqlcipher_database(db_path, &legacy_key, &new_key)
}

fn derive_sqlcipher_key_material(
    label: &str,
    keys: &nostr::Keys,
    salt: &[u8; SQLCIPHER_SALT_LEN],
    kind: SqlcipherDatabaseKind,
) -> Result<String, AppError> {
    // The account-secret copy and the raw derived key are wiped on drop; the
    // returned hex string is moved straight into `SqlCipherKey`, which
    // zeroizes it.
    let secret = Zeroizing::new(keys.secret_key().to_secret_bytes());
    let hkdf = Hkdf::<Sha256>::new(Some(salt), secret.as_ref());
    let mut info = Vec::new();
    encode_hkdf_part(&mut info, b"marmot-app-sqlcipher-key");
    encode_hkdf_part(&mut info, kind.hkdf_info_label());
    encode_hkdf_part(&mut info, label.as_bytes());
    encode_hkdf_part(&mut info, keys.public_key().to_bytes().as_slice());
    let mut output = Zeroizing::new([0_u8; SQLCIPHER_KEY_LEN]);
    hkdf.expand(&info, output.as_mut())
        .map_err(|_| AppError::SqlcipherKeyDerivation("HKDF output length rejected".to_owned()))?;
    Ok(hex::encode(&output))
}

fn derive_external_sqlcipher_key_material(
    label: &str,
    account_id_hex: &str,
    secret: &[u8; SQLCIPHER_KEY_LEN],
    salt: &[u8; SQLCIPHER_SALT_LEN],
    kind: SqlcipherDatabaseKind,
) -> Result<String, AppError> {
    let account_id = hex::decode(account_id_hex)?;
    let hkdf = Hkdf::<Sha256>::new(Some(salt), secret);
    let mut info = Vec::new();
    encode_hkdf_part(&mut info, b"marmot-app-external-signer-sqlcipher-key");
    encode_hkdf_part(&mut info, kind.hkdf_info_label());
    encode_hkdf_part(&mut info, label.as_bytes());
    encode_hkdf_part(&mut info, &account_id);
    let mut output = Zeroizing::new([0_u8; SQLCIPHER_KEY_LEN]);
    hkdf.expand(&info, output.as_mut())
        .map_err(|_| AppError::SqlcipherKeyDerivation("HKDF output length rejected".to_owned()))?;
    Ok(hex::encode(&output))
}

fn legacy_sqlcipher_key_material(
    label: &str,
    keys: &nostr::Keys,
    kind: SqlcipherDatabaseKind,
) -> String {
    // Wipe the account-secret copy and the raw digest (the legacy DB key) on
    // drop; the returned hex string is moved straight into `SqlCipherKey`,
    // which zeroizes it.
    let mut hasher = Sha256::new();
    hasher.update(kind.legacy_hash_label());
    hasher.update(label.as_bytes());
    hasher.update(keys.public_key().to_bytes());
    hasher.update(Zeroizing::new(keys.secret_key().to_secret_bytes()));
    let digest: Zeroizing<[u8; 32]> = Zeroizing::new(hasher.finalize().into());
    hex::encode(&digest)
}

fn encode_hkdf_part(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn rekey_legacy_sqlcipher_database(
    db_path: &Path,
    legacy_key: &SqlCipherKey,
    new_key: &SqlCipherKey,
) -> Result<(), AppError> {
    let conn = Connection::open(db_path)?;
    // Pin cipher_compatibility and enable cipher_memory_security before keying,
    // matching storage-sqlite, so the rekey open does not depend on SQLCipher
    // defaults and key material is wiped from the heap.
    open_hardened_sqlcipher(&conn, legacy_key, SqlCipherHardening::cipher_only())?;
    conn.pragma_update(None, "rekey", new_key.as_secret_str())?;
    Ok(())
}

pub(crate) fn remove_sqlite_file_set(path: &Path) -> Result<(), AppError> {
    // The database file is going away: any cached verdict for it is stale.
    sqlcipher_v2_verdict_invalidate(path);
    for candidate in [
        path.to_path_buf(),
        PathBuf::from(format!("{}-wal", path.display())),
        PathBuf::from(format!("{}-shm", path.display())),
    ] {
        match fs::remove_file(candidate) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use marmot_account::AccountHome;

    use crate::{MarmotApp, SESSION_DB_FILE};

    #[test]
    fn sqlcipher_keys_use_stable_per_database_salts() {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        home.create_account("alice").unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let keys = app.account_home().load_signing_keys("alice").unwrap();
        let session_path = app.account_dir("alice").join(SESSION_DB_FILE);
        let projection_path = app.legacy_account_projection_path("alice");

        let session_key = app
            .sqlcipher_key(
                "alice",
                &keys,
                &session_path,
                SqlcipherDatabaseKind::Session,
            )
            .unwrap();
        let repeated_session_key = app
            .sqlcipher_key(
                "alice",
                &keys,
                &session_path,
                SqlcipherDatabaseKind::Session,
            )
            .unwrap();
        let projection_key = app
            .sqlcipher_key(
                "alice",
                &keys,
                &projection_path,
                SqlcipherDatabaseKind::AccountProjection,
            )
            .unwrap();

        assert_eq!(
            session_key.as_secret_str(),
            repeated_session_key.as_secret_str()
        );
        assert_ne!(session_key.as_secret_str(), projection_key.as_secret_str());
        assert!(sqlcipher_salt_path(&session_path).exists());
        assert!(sqlcipher_salt_path(&projection_path).exists());
    }

    #[test]
    #[cfg(unix)]
    fn sqlcipher_salt_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let salt_path = dir.path().join("session.sqlite.salt");
        write_sqlcipher_salt(&salt_path, &[0x5a; SQLCIPHER_SALT_LEN]).unwrap();

        assert_eq!(
            std::fs::metadata(&salt_path).unwrap().permissions().mode() & 0o777,
            0o600,
            "salt is key-derivation material and must be owner-only"
        );
    }

    #[test]
    #[cfg(unix)]
    fn leftover_permissive_salt_temp_file_does_not_leak_its_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let salt_path = dir.path().join("session.sqlite.salt");
        // A crashed older build (or pid reuse) left the temp file behind at
        // umask-default permissions; the rewrite must not rename that mode
        // into the final salt path.
        let tmp_path = dir
            .path()
            .join(format!("session.sqlite.salt.tmp.{}", std::process::id()));
        std::fs::write(&tmp_path, b"stale").unwrap();
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o644)).unwrap();

        write_sqlcipher_salt(&salt_path, &[0x5a; SQLCIPHER_SALT_LEN]).unwrap();

        assert_eq!(
            std::fs::metadata(&salt_path).unwrap().permissions().mode() & 0o777,
            0o600,
            "final salt must be owner-only even when the temp inode pre-existed"
        );
    }

    #[test]
    fn sqlcipher_key_migrates_legacy_database_to_salted_key() {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        home.create_account("alice").unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let keys = app.account_home().load_signing_keys("alice").unwrap();
        let projection_path = app.legacy_account_projection_path("alice");
        fs::create_dir_all(projection_path.parent().unwrap()).unwrap();
        let legacy_key = SqlCipherKey::new(legacy_sqlcipher_key_material(
            "alice",
            &keys,
            SqlcipherDatabaseKind::AccountProjection,
        ))
        .unwrap();
        {
            let conn = Connection::open(&projection_path).unwrap();
            conn.pragma_update(None, "key", legacy_key.as_secret_str())
                .unwrap();
            conn.execute_batch(
                "CREATE TABLE marker (value TEXT NOT NULL);
                 INSERT INTO marker (value) VALUES ('kept');",
            )
            .unwrap();
        }

        let salted_key = app
            .sqlcipher_key(
                "alice",
                &keys,
                &projection_path,
                SqlcipherDatabaseKind::AccountProjection,
            )
            .unwrap();

        assert!(sqlcipher_salt_path(&projection_path).exists());
        let conn = Connection::open(&projection_path).unwrap();
        conn.pragma_update(None, "key", salted_key.as_secret_str())
            .unwrap();
        let value: String = conn
            .query_row("SELECT value FROM marker", [], |row| row.get(0))
            .unwrap();
        assert_eq!(value, "kept");

        let conn = Connection::open(&projection_path).unwrap();
        conn.pragma_update(None, "key", legacy_key.as_secret_str())
            .unwrap();
        assert!(
            conn.query_row("SELECT value FROM marker", [], |row| row
                .get::<_, String>(0))
                .is_err()
        );
    }

    #[test]
    fn sqlcipher_recovers_legacy_db_after_interrupted_migration() {
        // Simulate a crash that left the salt durable (so the v2 key is
        // reproducible) and the migration marker present, but the legacy DB was
        // never rekeyed (the `PRAGMA rekey` transaction rolled back). Before the
        // fix this bricked the account: the salt was present, the v2 key was
        // derived, and the still-legacy-keyed DB could not be opened. Recovery
        // must re-run the rekey and open cleanly.
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        home.create_account("alice").unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let keys = app.account_home().load_signing_keys("alice").unwrap();
        let projection_path = app.legacy_account_projection_path("alice");
        fs::create_dir_all(projection_path.parent().unwrap()).unwrap();

        let legacy_key = SqlCipherKey::new(legacy_sqlcipher_key_material(
            "alice",
            &keys,
            SqlcipherDatabaseKind::AccountProjection,
        ))
        .unwrap();
        {
            let conn = Connection::open(&projection_path).unwrap();
            conn.pragma_update(None, "key", legacy_key.as_secret_str())
                .unwrap();
            conn.execute_batch(
                "CREATE TABLE marker (value TEXT NOT NULL);
                 INSERT INTO marker (value) VALUES ('kept');",
            )
            .unwrap();
        }

        // Persist the v2 salt and drop the migration marker, mimicking the
        // crash window between salt-write and rekey-commit.
        let mut salt = [0_u8; SQLCIPHER_SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        write_sqlcipher_salt(&sqlcipher_salt_path(&projection_path), &salt).unwrap();
        write_sqlcipher_migration_marker(&sqlcipher_migration_marker_path(&projection_path))
            .unwrap();
        assert!(sqlcipher_migration_marker_path(&projection_path).exists());

        let recovered_key = app
            .sqlcipher_key(
                "alice",
                &keys,
                &projection_path,
                SqlcipherDatabaseKind::AccountProjection,
            )
            .unwrap();

        // Marker cleared, data preserved, DB opens under the recovered v2 key.
        assert!(!sqlcipher_migration_marker_path(&projection_path).exists());
        let conn = Connection::open(&projection_path).unwrap();
        conn.pragma_update(None, "key", recovered_key.as_secret_str())
            .unwrap();
        let value: String = conn
            .query_row("SELECT value FROM marker", [], |row| row.get(0))
            .unwrap();
        assert_eq!(value, "kept");
    }

    #[test]
    fn sqlcipher_recovery_idempotent_when_rekey_already_committed() {
        // The other crash window: the rekey committed (DB is already v2-keyed)
        // but the process died before clearing the marker. Recovery must detect
        // the DB already opens under the v2 key and simply clear the marker,
        // without attempting a legacy-key rekey that would fail.
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        home.create_account("alice").unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let keys = app.account_home().load_signing_keys("alice").unwrap();
        let projection_path = app.legacy_account_projection_path("alice");
        fs::create_dir_all(projection_path.parent().unwrap()).unwrap();

        // Create a legacy DB and run a normal migration to a v2 key.
        let legacy_key = SqlCipherKey::new(legacy_sqlcipher_key_material(
            "alice",
            &keys,
            SqlcipherDatabaseKind::AccountProjection,
        ))
        .unwrap();
        {
            let conn = Connection::open(&projection_path).unwrap();
            conn.pragma_update(None, "key", legacy_key.as_secret_str())
                .unwrap();
            conn.execute_batch(
                "CREATE TABLE marker (value TEXT NOT NULL);
                 INSERT INTO marker (value) VALUES ('kept');",
            )
            .unwrap();
        }
        let v2_key = app
            .sqlcipher_key(
                "alice",
                &keys,
                &projection_path,
                SqlcipherDatabaseKind::AccountProjection,
            )
            .unwrap();

        // The DB is now v2-keyed. Re-introduce a stale marker as if the process
        // had died after committing the rekey but before removing it.
        write_sqlcipher_migration_marker(&sqlcipher_migration_marker_path(&projection_path))
            .unwrap();

        let recovered_key = app
            .sqlcipher_key(
                "alice",
                &keys,
                &projection_path,
                SqlcipherDatabaseKind::AccountProjection,
            )
            .unwrap();

        assert_eq!(recovered_key.as_secret_str(), v2_key.as_secret_str());
        assert!(!sqlcipher_migration_marker_path(&projection_path).exists());
        let conn = Connection::open(&projection_path).unwrap();
        conn.pragma_update(None, "key", recovered_key.as_secret_str())
            .unwrap();
        let value: String = conn
            .query_row("SELECT value FROM marker", [], |row| row.get(0))
            .unwrap();
        assert_eq!(value, "kept");
    }

    #[test]
    fn sqlcipher_recovers_pre_fix_bricked_db_with_salt_present_no_marker() {
        // The pre-fix #219 bricked state: the vulnerable code wrote the salt to
        // disk and then crashed before `PRAGMA rekey` committed, so the database
        // is still legacy-keyed. Crucially that code never wrote a migration
        // marker, so the salt-present branch sees `.salt` with NO `.salt-migrating`
        // sidecar. A marker-only recovery check would skip these accounts and
        // they would stay bricked forever. Opening must self-heal: probe the v2
        // key, find it fails, and re-run the legacy -> v2 rekey.
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        home.create_account("alice").unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let keys = app.account_home().load_signing_keys("alice").unwrap();
        let projection_path = app.legacy_account_projection_path("alice");
        fs::create_dir_all(projection_path.parent().unwrap()).unwrap();

        let legacy_key = SqlCipherKey::new(legacy_sqlcipher_key_material(
            "alice",
            &keys,
            SqlcipherDatabaseKind::AccountProjection,
        ))
        .unwrap();
        {
            let conn = Connection::open(&projection_path).unwrap();
            conn.pragma_update(None, "key", legacy_key.as_secret_str())
                .unwrap();
            conn.execute_batch(
                "CREATE TABLE marker (value TEXT NOT NULL);
                 INSERT INTO marker (value) VALUES ('kept');",
            )
            .unwrap();
        }

        // Persist the v2 salt but write NO migration marker, exactly as the
        // pre-fix vulnerable code did before crashing mid-rekey.
        let mut salt = [0_u8; SQLCIPHER_SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        write_sqlcipher_salt(&sqlcipher_salt_path(&projection_path), &salt).unwrap();
        assert!(sqlcipher_salt_path(&projection_path).exists());
        assert!(!sqlcipher_migration_marker_path(&projection_path).exists());

        let recovered_key = app
            .sqlcipher_key(
                "alice",
                &keys,
                &projection_path,
                SqlcipherDatabaseKind::AccountProjection,
            )
            .unwrap();

        // The existing salt is kept as the v2 salt and the DB is rekeyed to it,
        // so data is preserved and the DB opens under the recovered v2 key.
        let conn = Connection::open(&projection_path).unwrap();
        conn.pragma_update(None, "key", recovered_key.as_secret_str())
            .unwrap();
        let value: String = conn
            .query_row("SELECT value FROM marker", [], |row| row.get(0))
            .unwrap();
        assert_eq!(value, "kept");

        // And the legacy key no longer opens it (the rekey really happened).
        let conn = Connection::open(&projection_path).unwrap();
        conn.pragma_update(None, "key", legacy_key.as_secret_str())
            .unwrap();
        assert!(
            conn.query_row("SELECT value FROM marker", [], |row| row
                .get::<_, String>(0))
                .is_err()
        );
    }

    #[test]
    fn sqlcipher_salt_written_atomically_with_no_temp_residue() {
        // A fresh-DB salt write must be atomic: the readable salt is exactly 64
        // hex chars (32 bytes) and no `.tmp` residue is left behind.
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        home.create_account("alice").unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let keys = app.account_home().load_signing_keys("alice").unwrap();
        let session_path = app.account_dir("alice").join(SESSION_DB_FILE);

        let _ = app
            .sqlcipher_key(
                "alice",
                &keys,
                &session_path,
                SqlcipherDatabaseKind::Session,
            )
            .unwrap();

        let salt_path = sqlcipher_salt_path(&session_path);
        assert!(salt_path.exists());
        let raw = fs::read_to_string(&salt_path).unwrap();
        assert_eq!(raw.trim().len(), SQLCIPHER_SALT_LEN * 2);
        // read_sqlcipher_salt enforces the exact length; a truncated write would
        // fail here.
        read_sqlcipher_salt(&salt_path).unwrap();

        // No leftover temp files in the salt's directory.
        let salt_dir = salt_path.parent().unwrap();
        for entry in fs::read_dir(salt_dir).unwrap() {
            let name = entry.unwrap().file_name();
            let name = name.to_string_lossy();
            assert!(!name.contains(".tmp."), "unexpected temp residue: {name}");
        }
    }

    /// Write a durable v2 salt and create a database already keyed with the
    /// derived v2 key — the healthy steady state every open lands in once a
    /// database has been migrated or created fresh.
    fn create_healthy_v2_database(
        label: &str,
        keys: &nostr::Keys,
        db_path: &Path,
        kind: SqlcipherDatabaseKind,
    ) {
        let mut salt = [0_u8; SQLCIPHER_SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        write_sqlcipher_salt(&sqlcipher_salt_path(db_path), &salt).unwrap();
        let v2_key =
            SqlCipherKey::new(derive_sqlcipher_key_material(label, keys, &salt, kind).unwrap())
                .unwrap();
        let conn = Connection::open(db_path).unwrap();
        open_hardened_sqlcipher(&conn, &v2_key, SqlCipherHardening::cipher_only()).unwrap();
        conn.execute_batch(
            "CREATE TABLE marker (value TEXT NOT NULL);
             INSERT INTO marker (value) VALUES ('kept');",
        )
        .unwrap();
    }

    #[test]
    fn sqlcipher_probe_runs_at_most_once_for_healthy_v2_database_across_opens() {
        // mdk#1439 acceptance: a healthy v2-keyed database opened repeatedly in
        // one process runs the interrupted-migration probe — a full keyed open
        // paying the 256k-iteration passphrase KDF — at most once. The first
        // open establishes the verdict; later opens reuse it.
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        home.create_account("alice").unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let keys = app.account_home().load_signing_keys("alice").unwrap();
        let projection_path = app.legacy_account_projection_path("alice");
        fs::create_dir_all(projection_path.parent().unwrap()).unwrap();
        create_healthy_v2_database(
            "alice",
            &keys,
            &projection_path,
            SqlcipherDatabaseKind::AccountProjection,
        );

        let first_key = app
            .sqlcipher_key(
                "alice",
                &keys,
                &projection_path,
                SqlcipherDatabaseKind::AccountProjection,
            )
            .unwrap();
        assert_eq!(
            probe_attempts_for_test(&projection_path),
            1,
            "the first open of a database with no cached verdict must probe"
        );

        for _ in 0..3 {
            let key = app
                .sqlcipher_key(
                    "alice",
                    &keys,
                    &projection_path,
                    SqlcipherDatabaseKind::AccountProjection,
                )
                .unwrap();
            assert_eq!(key.as_secret_str(), first_key.as_secret_str());
        }
        assert_eq!(
            probe_attempts_for_test(&projection_path),
            1,
            "steady-state reopens of the same database must skip the probe"
        );
    }

    #[test]
    fn sqlcipher_probe_reruns_whenever_migration_marker_is_present() {
        // mdk#1439 acceptance: a durable migration marker always forces the
        // recovery probe, even when a verdict for this database+salt is already
        // cached — the marker means a migration may have been interrupted, and
        // those crash windows keep the #219 self-heal.
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        home.create_account("alice").unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let keys = app.account_home().load_signing_keys("alice").unwrap();
        let projection_path = app.legacy_account_projection_path("alice");
        fs::create_dir_all(projection_path.parent().unwrap()).unwrap();
        create_healthy_v2_database(
            "alice",
            &keys,
            &projection_path,
            SqlcipherDatabaseKind::AccountProjection,
        );

        let _ = app
            .sqlcipher_key(
                "alice",
                &keys,
                &projection_path,
                SqlcipherDatabaseKind::AccountProjection,
            )
            .unwrap();
        assert_eq!(probe_attempts_for_test(&projection_path), 1);

        // Stale marker: the rekey committed but the process died before the
        // marker was cleared. The cached verdict must not suppress the probe.
        write_sqlcipher_migration_marker(&sqlcipher_migration_marker_path(&projection_path))
            .unwrap();
        let _ = app
            .sqlcipher_key(
                "alice",
                &keys,
                &projection_path,
                SqlcipherDatabaseKind::AccountProjection,
            )
            .unwrap();
        assert_eq!(
            probe_attempts_for_test(&projection_path),
            2,
            "a marker-present open must re-run the recovery probe even with a cached verdict"
        );
        assert!(!sqlcipher_migration_marker_path(&projection_path).exists());

        // Marker cleared: the steady-state skip applies again.
        let _ = app
            .sqlcipher_key(
                "alice",
                &keys,
                &projection_path,
                SqlcipherDatabaseKind::AccountProjection,
            )
            .unwrap();
        assert_eq!(probe_attempts_for_test(&projection_path), 2);
    }

    #[test]
    fn sqlcipher_verdict_invalidation_forces_reprobe_after_file_set_removal() {
        // A cached verdict must never cause a legacy-keyed database to be
        // opened with the wrong assumption. Removing the database file set
        // invalidates the verdict, so when a legacy-keyed database later
        // appears at the same path (with the salt still durable), the probe
        // runs again and self-heals it.
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        home.create_account("alice").unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let keys = app.account_home().load_signing_keys("alice").unwrap();
        let projection_path = app.legacy_account_projection_path("alice");
        fs::create_dir_all(projection_path.parent().unwrap()).unwrap();
        create_healthy_v2_database(
            "alice",
            &keys,
            &projection_path,
            SqlcipherDatabaseKind::AccountProjection,
        );

        let _ = app
            .sqlcipher_key(
                "alice",
                &keys,
                &projection_path,
                SqlcipherDatabaseKind::AccountProjection,
            )
            .unwrap();
        assert_eq!(probe_attempts_for_test(&projection_path), 1);

        // The database goes away (account/cache reset); the salt survives.
        remove_sqlite_file_set(&projection_path).unwrap();
        assert!(!projection_path.exists());

        // A legacy-keyed database appears at the same path.
        let legacy_key = SqlCipherKey::new(legacy_sqlcipher_key_material(
            "alice",
            &keys,
            SqlcipherDatabaseKind::AccountProjection,
        ))
        .unwrap();
        {
            let conn = Connection::open(&projection_path).unwrap();
            conn.pragma_update(None, "key", legacy_key.as_secret_str())
                .unwrap();
            conn.execute_batch(
                "CREATE TABLE marker (value TEXT NOT NULL);
                 INSERT INTO marker (value) VALUES ('restored');",
            )
            .unwrap();
        }

        let recovered_key = app
            .sqlcipher_key(
                "alice",
                &keys,
                &projection_path,
                SqlcipherDatabaseKind::AccountProjection,
            )
            .unwrap();
        assert_eq!(
            probe_attempts_for_test(&projection_path),
            2,
            "an invalidated verdict must force the probe again"
        );
        let conn = Connection::open(&projection_path).unwrap();
        conn.pragma_update(None, "key", recovered_key.as_secret_str())
            .unwrap();
        let value: String = conn
            .query_row("SELECT value FROM marker", [], |row| row.get(0))
            .unwrap();
        assert_eq!(value, "restored");
    }

    #[test]
    fn sqlcipher_probe_runs_when_database_appears_after_salt_only_open() {
        // The fresh-database path (salt durable, no database file yet) must not
        // record a verdict: no database has been observed opening under the v2
        // key. If a legacy-keyed database then appears at that path, the probe
        // still runs and heals it.
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        home.create_account("alice").unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let keys = app.account_home().load_signing_keys("alice").unwrap();
        let projection_path = app.legacy_account_projection_path("alice");
        fs::create_dir_all(projection_path.parent().unwrap()).unwrap();
        let mut salt = [0_u8; SQLCIPHER_SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        write_sqlcipher_salt(&sqlcipher_salt_path(&projection_path), &salt).unwrap();

        let _ = app
            .sqlcipher_key(
                "alice",
                &keys,
                &projection_path,
                SqlcipherDatabaseKind::AccountProjection,
            )
            .unwrap();
        assert_eq!(
            probe_attempts_for_test(&projection_path),
            0,
            "no database file means no probe and no verdict"
        );

        let legacy_key = SqlCipherKey::new(legacy_sqlcipher_key_material(
            "alice",
            &keys,
            SqlcipherDatabaseKind::AccountProjection,
        ))
        .unwrap();
        {
            let conn = Connection::open(&projection_path).unwrap();
            conn.pragma_update(None, "key", legacy_key.as_secret_str())
                .unwrap();
            conn.execute_batch(
                "CREATE TABLE marker (value TEXT NOT NULL);
                 INSERT INTO marker (value) VALUES ('appeared');",
            )
            .unwrap();
        }

        let recovered_key = app
            .sqlcipher_key(
                "alice",
                &keys,
                &projection_path,
                SqlcipherDatabaseKind::AccountProjection,
            )
            .unwrap();
        assert_eq!(
            probe_attempts_for_test(&projection_path),
            1,
            "a database never observed under the v2 key must be probed"
        );
        let conn = Connection::open(&projection_path).unwrap();
        conn.pragma_update(None, "key", recovered_key.as_secret_str())
            .unwrap();
        let value: String = conn
            .query_row("SELECT value FROM marker", [], |row| row.get(0))
            .unwrap();
        assert_eq!(value, "appeared");
    }

    #[test]
    fn sqlcipher_v2_verdict_cache_is_salt_scoped() {
        let mut cache = SqlcipherV2VerdictCache::new();
        let path = PathBuf::from("/tmp/mdk-verdict-cache-salt-scope.sqlite");
        let salt_a = [0xaa; SQLCIPHER_SALT_LEN];
        let salt_b = [0xbb; SQLCIPHER_SALT_LEN];

        cache.record(path.clone(), salt_a);
        assert!(cache.contains(&path, &salt_a));
        assert!(
            !cache.contains(&path, &salt_b),
            "a verdict for one salt must not vouch for another salt"
        );

        // A salt rotation replaces the verdict rather than stacking.
        cache.record(path.clone(), salt_b);
        assert!(!cache.contains(&path, &salt_a));
        assert!(cache.contains(&path, &salt_b));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn sqlcipher_v2_verdict_cache_is_bounded_and_evicts_oldest_first() {
        let mut cache = SqlcipherV2VerdictCache::new();
        let salt = [0x5a; SQLCIPHER_SALT_LEN];
        for index in 0..(SQLCIPHER_V2_VERDICT_CACHE_CAPACITY + 10) {
            cache.record(
                PathBuf::from(format!("/tmp/mdk-verdict-cache-churn-{index}.sqlite")),
                salt,
            );
        }

        assert_eq!(cache.len(), SQLCIPHER_V2_VERDICT_CACHE_CAPACITY);
        for index in 0..10 {
            assert!(
                !cache.contains(
                    &PathBuf::from(format!("/tmp/mdk-verdict-cache-churn-{index}.sqlite")),
                    &salt
                ),
                "the oldest entries must be evicted first"
            );
        }
        for index in 10..(SQLCIPHER_V2_VERDICT_CACHE_CAPACITY + 10) {
            assert!(
                cache.contains(
                    &PathBuf::from(format!("/tmp/mdk-verdict-cache-churn-{index}.sqlite")),
                    &salt
                ),
                "recent entries must survive eviction"
            );
        }
    }

    #[test]
    fn sqlcipher_v2_verdict_cache_invalidate_removes_the_entry() {
        let mut cache = SqlcipherV2VerdictCache::new();
        let path = PathBuf::from("/tmp/mdk-verdict-cache-invalidate.sqlite");
        let other = PathBuf::from("/tmp/mdk-verdict-cache-invalidate-other.sqlite");
        let salt = [0x5a; SQLCIPHER_SALT_LEN];

        cache.record(path.clone(), salt);
        cache.record(other.clone(), salt);
        cache.invalidate(&path);

        assert!(!cache.contains(&path, &salt));
        assert!(cache.contains(&other, &salt));
        // Re-recording after invalidation works and keeps the bound intact.
        cache.record(path.clone(), salt);
        assert!(cache.contains(&path, &salt));
        assert_eq!(cache.len(), 2);
    }
}
