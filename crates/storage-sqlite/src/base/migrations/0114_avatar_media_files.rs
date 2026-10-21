//! Migration 0114: avatar and group-image bodies in the media store's cache
//! category (mdk#2314 step 9).
//!
//! `avatar_assets` is rebuilt so an image can be file-backed: its metadata
//! (`digest`, `media_type`, dimensions, `refresh_at`) is set while `bytes` is
//! `NULL`, and the new `byte_len` records the file's length. A legacy image
//! keeps its `bytes` and has no `byte_len`. `digest` alone now says an image
//! is present. The triggers that name `avatar_assets` are dropped and
//! recreated around the rebuild; the repair trigger now fires when `digest`
//! clears, which covers both layouts.
//!
//! The rebuild copies the images still held in the database while the
//! account opens, so it keeps at most [`KEPT_AVATAR_BYTES`] of them, smallest
//! first. Owners beyond that are not copied, as if evicted: their recency,
//! fetch and identity-demand rows go with them, and a screen that shows one
//! binds and fetches it again. That bounds the time and extra disk this
//! migration costs on a full 128 MiB cache.
//!
//! `avatar_file_refs` ties an owner row to a ready cache file (category 2).
//! Identical images share one file. Removing the last reference deletes the
//! file's row (its key); the store unlinks the file. A new source generation
//! (token change) drops its reference, and a store reset removes every row.
use crate::SqliteResultExt;
use cgka_traits::StorageError;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

/// Database-held image bytes the rebuild copies, smallest images first.
pub(crate) const KEPT_AVATAR_BYTES: i64 = 32 * 1024 * 1024;

/// The registry suspends enforcement for this parent rebuild and checks the
/// tables that reference it.
pub(crate) const SUSPEND_FOREIGN_KEYS: &[&str] =
    &["avatar_access", "avatar_acquisition", "avatar_file_refs"];

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    if tx
        .pragma_query_value(None, "foreign_keys", |row| row.get::<_, bool>(0))
        .storage()?
    {
        return Err(StorageError::Backend(
            "avatar asset rebuild requires migration-runner foreign-key scope".into(),
        ));
    }
    // Owners kept: every one without an image, then images smallest first
    // while their running total stays within the cap.
    tx.execute(
        "CREATE TEMP TABLE avatar_assets_kept AS SELECT token FROM (
            SELECT token, sum(coalesce(length(bytes), 0)) OVER (
                ORDER BY coalesce(length(bytes), 0), token ROWS UNBOUNDED PRECEDING) AS held
            FROM avatar_assets) WHERE held <= ?1",
        [KEPT_AVATAR_BYTES],
    )
    .storage()?;
    // The rest are dropped as eviction drops an owner.
    tx.execute_batch(
        "DELETE FROM avatar_identity_demand WHERE owner_key IN (SELECT owner_key FROM avatar_assets
            WHERE token NOT IN (SELECT token FROM temp.avatar_assets_kept));
        DELETE FROM avatar_access WHERE token NOT IN (SELECT token FROM temp.avatar_assets_kept);
        DELETE FROM avatar_acquisition
            WHERE token NOT IN (SELECT token FROM temp.avatar_assets_kept);",
    )
    .storage()?;
    tx.execute_batch(
        "DROP TRIGGER avatar_cache_store_reset;
        DROP TRIGGER avatar_chat_deleted;
        CREATE TABLE avatar_assets_next (
            owner_key TEXT PRIMARY KEY NOT NULL CHECK(length(owner_key) BETWEEN 1 AND 512),
            source_key TEXT NOT NULL CHECK(length(source_key) BETWEEN 1 AND 512),
            token BLOB NOT NULL UNIQUE CHECK(length(token) = 16),
            content_revision INTEGER NOT NULL DEFAULT 0
                CHECK(typeof(content_revision) = 'integer' AND content_revision >= 0),
            bytes BLOB CHECK(bytes IS NULL OR
                (typeof(bytes) = 'blob' AND length(bytes) BETWEEN 1 AND 10485760)),
            digest BLOB CHECK(digest IS NULL OR
                (typeof(digest) = 'blob' AND length(digest) = 32)),
            media_type TEXT,
            width INTEGER,
            height INTEGER,
            refresh_at INTEGER CHECK(refresh_at IS NULL OR
                (typeof(refresh_at) = 'integer' AND refresh_at >= 0)),
            byte_len INTEGER CHECK(byte_len IS NULL OR
                (typeof(byte_len) = 'integer' AND byte_len BETWEEN 1 AND 10485760
                    AND bytes IS NULL AND digest IS NOT NULL)),
            CHECK((bytes IS NULL AND digest IS NULL AND media_type IS NULL AND width IS NULL
                    AND height IS NULL AND refresh_at IS NULL AND byte_len IS NULL)
                OR (digest IS NOT NULL AND (bytes IS NOT NULL OR byte_len IS NOT NULL)
                    AND media_type IS NOT NULL
                    AND media_type IN ('image/png', 'image/jpeg', 'image/gif', 'image/webp')
                    AND width IS NOT NULL AND height IS NOT NULL
                    AND typeof(width) = 'integer' AND typeof(height) = 'integer'
                    AND width BETWEEN 1 AND 4096 AND height BETWEEN 1 AND 4096))
        );
        INSERT INTO avatar_assets_next(owner_key, source_key, token, content_revision, bytes,
                digest, media_type, width, height, refresh_at)
            SELECT owner_key, source_key, token, content_revision, bytes, digest, media_type,
                width, height, refresh_at FROM avatar_assets
            WHERE token IN (SELECT token FROM temp.avatar_assets_kept);
        DROP TABLE temp.avatar_assets_kept;
        DROP TABLE avatar_assets;
        ALTER TABLE avatar_assets_next RENAME TO avatar_assets;
        CREATE TABLE avatar_file_refs (
            token BLOB PRIMARY KEY NOT NULL
                REFERENCES avatar_assets(token) ON DELETE CASCADE,
            file_id BLOB NOT NULL REFERENCES media_files(id) ON DELETE CASCADE
        );
        CREATE INDEX avatar_file_refs_file ON avatar_file_refs(file_id);
        CREATE TRIGGER avatar_file_refs_ready BEFORE INSERT ON avatar_file_refs
        WHEN (SELECT state = 1 AND category = 2 FROM media_files WHERE id = NEW.file_id)
            IS NOT 1 BEGIN
            SELECT RAISE(ABORT, 'avatar file reference requires a ready cache file');
        END;
        CREATE TRIGGER avatar_file_refs_last AFTER DELETE ON avatar_file_refs
        WHEN NOT EXISTS(SELECT 1 FROM avatar_file_refs WHERE file_id = OLD.file_id) BEGIN
            DELETE FROM media_files WHERE id = OLD.file_id AND category = 2 AND state IN (1, 2);
        END;
        CREATE TRIGGER avatar_file_source_changed BEFORE UPDATE OF token ON avatar_assets
        WHEN OLD.token IS NOT NEW.token BEGIN
            DELETE FROM avatar_file_refs WHERE token = OLD.token;
        END;
        CREATE TRIGGER avatar_acquisition_source_changed BEFORE UPDATE OF token ON avatar_assets
        WHEN OLD.token IS NOT NEW.token BEGIN
            DELETE FROM avatar_acquisition WHERE token = OLD.token;
        END;
        CREATE TRIGGER avatar_acquisition_repair AFTER UPDATE OF digest ON avatar_assets
        WHEN OLD.digest IS NOT NULL AND NEW.digest IS NULL BEGIN
            UPDATE avatar_acquisition SET state = 1, due = 0, attempt = NULL WHERE token = NEW.token;
        END;
        CREATE TRIGGER avatar_identity_evicted AFTER DELETE ON avatar_assets BEGIN
            DELETE FROM avatar_identity_demand WHERE owner_key = OLD.owner_key;
        END;
        CREATE TRIGGER avatar_cache_store_reset AFTER UPDATE OF store_epoch ON chat_presentation_meta
        WHEN OLD.store_epoch IS NOT NEW.store_epoch BEGIN
            DELETE FROM avatar_assets;
        END;
        CREATE TRIGGER avatar_chat_deleted BEFORE DELETE ON chat_list_rows BEGIN
            DELETE FROM avatar_assets WHERE owner_key = 'chat:' || lower(hex(OLD.presentation_row_epoch))
                OR owner_key IN (SELECT owner_key FROM avatar_identity_demand WHERE group_id_hex = OLD.group_id_hex);
        END;",
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::{MIGRATIONS, run};

    fn count(conn: &rusqlite::Connection, query: &str) -> i64 {
        conn.query_row(query, [], |row| row.get(0)).unwrap()
    }

    const FILE: &str = "x'000000000000000000000000000000c1'";

    /// Legacy images, empty bindings, recency and acquisition rows survive the
    /// rebuild unchanged; the recreated triggers still repair, evict and reset;
    /// file references require a ready cache file and the last one deletes it.
    #[test]
    fn avatar_media_upgrade_keeps_rows_and_triggers() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        run(&mut conn, &MIGRATIONS[..113]).unwrap();
        assert_eq!(MIGRATIONS[113].version, 114);
        conn.execute_batch(
            "INSERT INTO avatar_assets(owner_key, source_key, token, content_revision, bytes,
                digest, media_type, width, height)
             VALUES('legacy', 's', x'00000000000000000000000000000001', 3, x'0102',
                zeroblob(32), 'image/png', 1, 1);
            INSERT INTO avatar_assets(owner_key, source_key, token)
             VALUES('empty', 's', x'00000000000000000000000000000002');
            INSERT INTO avatar_access VALUES(x'00000000000000000000000000000001', 7);
            INSERT INTO avatar_acquisition(token, descriptor, state, due)
             VALUES(x'00000000000000000000000000000001', x'01', 0, NULL);",
        )
        .unwrap();
        run(&mut conn, MIGRATIONS).unwrap();
        assert_eq!(count(&conn, "SELECT count(*) FROM avatar_assets"), 2);
        assert_eq!(
            count(
                &conn,
                "SELECT count(*) FROM avatar_assets
                 WHERE owner_key='legacy' AND bytes=x'0102' AND byte_len IS NULL AND content_revision=3"
            ),
            1,
            "a legacy image keeps its bytes"
        );
        assert_eq!(count(&conn, "SELECT count(*) FROM avatar_access"), 1);
        conn.execute(
            "UPDATE avatar_assets SET bytes=NULL, digest=NULL, media_type=NULL, width=NULL,
                height=NULL WHERE owner_key='legacy'",
            [],
        )
        .unwrap();
        assert_eq!(
            count(&conn, "SELECT state FROM avatar_acquisition"),
            1,
            "clearing the image still schedules a refetch"
        );

        assert!(
            conn.execute(
                "UPDATE avatar_assets SET digest=zeroblob(32), media_type='image/png', width=1,
                    height=1 WHERE owner_key='empty'",
                [],
            )
            .is_err(),
            "an image needs bytes or a file"
        );
        conn.execute(
            &format!("INSERT INTO media_files VALUES({FILE},zeroblob(32),1,1,2,zeroblob(32),1,1)"),
            [],
        )
        .unwrap();
        assert!(
            conn.execute(
                &format!("INSERT INTO avatar_file_refs VALUES(x'00000000000000000000000000000002',{FILE})"),
                []
            )
            .is_err(),
            "retained media cannot back an avatar"
        );
        conn.execute(
            &format!("UPDATE media_files SET category=2 WHERE id={FILE}"),
            [],
        )
        .unwrap();
        conn.execute_batch(&format!(
            "INSERT INTO avatar_file_refs VALUES(x'00000000000000000000000000000002',{FILE});
            UPDATE avatar_assets SET digest=zeroblob(32), media_type='image/png', width=1,
                height=1, byte_len=2 WHERE owner_key='empty';"
        ))
        .unwrap();
        conn.execute(
            "UPDATE avatar_assets SET token=x'00000000000000000000000000000003',
                digest=NULL, media_type=NULL, width=NULL, height=NULL, byte_len=NULL
             WHERE owner_key='empty'",
            [],
        )
        .unwrap();
        assert_eq!(
            count(&conn, "SELECT count(*) FROM media_files"),
            0,
            "a new source generation drops the reference and its file's key"
        );

        conn.execute(
            "UPDATE chat_presentation_meta SET store_epoch=randomblob(16) WHERE id=1",
            [],
        )
        .unwrap();
        assert_eq!(count(&conn, "SELECT count(*) FROM avatar_assets"), 0);
    }

    /// A database-held cache over the cap keeps its smallest images up to the
    /// cap; the rest are dropped with their recency, fetch and demand rows,
    /// and owners without an image are kept.
    #[test]
    fn avatar_media_upgrade_caps_what_it_copies() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        run(&mut conn, &MIGRATIONS[..113]).unwrap();
        let ten_mib = 10 * 1024 * 1024;
        // Tokens in owner order, so equal sizes are kept in that order and
        // owner-3 is the one past the cap.
        for (i, size) in [ten_mib, ten_mib, ten_mib, ten_mib, 1_000]
            .into_iter()
            .enumerate()
        {
            conn.execute(
                "INSERT INTO avatar_assets(owner_key, source_key, token, bytes, digest,
                    media_type, width, height)
                 VALUES(?1, 's', ?3, zeroblob(?2), zeroblob(32), 'image/png', 1, 1)",
                rusqlite::params![format!("owner-{i}"), size, vec![i as u8 + 1; 16]],
            )
            .unwrap();
        }
        conn.execute(
            "INSERT INTO avatar_assets(owner_key, source_key, token)
             VALUES('empty', 's', randomblob(16))",
            [],
        )
        .unwrap();
        conn.execute_batch(
            "INSERT INTO avatar_access SELECT token, 1 FROM avatar_assets;
             INSERT INTO avatar_acquisition(token, descriptor, state, due)
                SELECT token, x'01', 0, NULL FROM avatar_assets;
             PRAGMA foreign_keys = OFF;
             INSERT INTO chat_list_rows(group_id_hex, updated_at, archived, self_membership,
                unread_count, pending_confirmation) VALUES('aa', 0, 0, 0, 0, 0);
             INSERT INTO avatar_identity_demand
                SELECT owner, 'aa', 'member', zeroblob(16), 0, 1
                FROM (SELECT 'owner-0' AS owner UNION ALL SELECT 'owner-3'
                    UNION ALL SELECT 'placeholder');
             PRAGMA foreign_keys = ON;",
        )
        .unwrap();
        run(&mut conn, MIGRATIONS).unwrap();
        let demand: String = conn
            .query_row(
                "SELECT group_concat(owner_key) FROM
                    (SELECT owner_key FROM avatar_identity_demand ORDER BY owner_key)",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            demand, "owner-0,placeholder",
            "only the dropped owner's (owner-3) demand goes; a kept owner and a placeholder stay"
        );
        assert_eq!(
            count(&conn, "SELECT count(*) FROM avatar_assets"),
            5,
            "the empty owner, the small image and three 10 MiB images within 32 MiB"
        );
        assert_eq!(
            count(
                &conn,
                "SELECT count(*) FROM avatar_assets WHERE owner_key = 'empty'"
            ),
            1
        );
        assert_eq!(
            count(
                &conn,
                "SELECT coalesce(sum(length(bytes)), 0) FROM avatar_assets"
            ),
            3 * ten_mib + 1_000
        );
        assert_eq!(count(&conn, "SELECT count(*) FROM avatar_access"), 5);
        assert_eq!(count(&conn, "SELECT count(*) FROM avatar_acquisition"), 5);
        assert_eq!(
            count(
                &conn,
                "SELECT count(*) FROM sqlite_temp_master WHERE name = 'avatar_assets_kept'"
            ),
            0
        );
    }
}
