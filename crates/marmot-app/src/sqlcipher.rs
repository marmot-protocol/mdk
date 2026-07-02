//! SQLCipher key derivation, salt persistence, and legacy-database migration.
//!
//! This module owns the security-critical key-material derivation for the
//! per-account-device SQLCipher databases: stable per-database salts, the HKDF
//! v2 key derivation, the legacy (v1) key derivation kept for migration, the
//! crash-safe salt-write/rekey sequence, and recovery for interrupted or
//! pre-fix bricked migrations.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use storage_sqlite::{SqlCipherHardening, SqlCipherKey, open_hardened_sqlcipher};

use crate::{AppError, MarmotApp};

const SQLCIPHER_SALT_SUFFIX: &str = ".salt";
const SQLCIPHER_MIGRATION_MARKER_SUFFIX: &str = ".salt-migrating";
const SQLCIPHER_SALT_LEN: usize = 32;
const SQLCIPHER_KEY_LEN: usize = 32;

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
            // (a cheap no-op when the database is already migrated or freshly
            // v2-keyed) and only re-runs the legacy -> v2 rekey when that probe
            // fails. Running it on every existing-database open therefore both
            // finishes interrupted migrations and self-heals the pre-fix bricked
            // state, without changing behavior for healthy databases.
            if db_path.exists() {
                finish_interrupted_sqlcipher_migration(label, keys, db_path, kind, &salt)?;
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

    {
        let mut tmp = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)?;
        tmp.write_all(contents)?;
        tmp.sync_all()?;
    }

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

    // Does the database already open under the v2 key?
    {
        let conn = Connection::open(db_path)?;
        if open_hardened_sqlcipher(&conn, &new_key, SqlCipherHardening::cipher_only()).is_ok() {
            return Ok(());
        }
    }

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
    let secret = keys.secret_key().to_secret_bytes();
    let hkdf = Hkdf::<Sha256>::new(Some(salt), &secret);
    let mut info = Vec::new();
    encode_hkdf_part(&mut info, b"marmot-app-sqlcipher-key");
    encode_hkdf_part(&mut info, kind.hkdf_info_label());
    encode_hkdf_part(&mut info, label.as_bytes());
    encode_hkdf_part(&mut info, keys.public_key().to_bytes().as_slice());
    let mut output = [0_u8; SQLCIPHER_KEY_LEN];
    hkdf.expand(&info, &mut output)
        .map_err(|_| AppError::SqlcipherKeyDerivation("HKDF output length rejected".into()))?;
    Ok(hex::encode(output))
}

fn legacy_sqlcipher_key_material(
    label: &str,
    keys: &nostr::Keys,
    kind: SqlcipherDatabaseKind,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(kind.legacy_hash_label());
    hasher.update(label.as_bytes());
    hasher.update(keys.public_key().to_bytes());
    hasher.update(keys.secret_key().to_secret_bytes());
    hex::encode(hasher.finalize())
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
}
