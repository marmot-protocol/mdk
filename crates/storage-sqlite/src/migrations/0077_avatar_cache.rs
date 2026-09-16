use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

/// C7-A storage foundation; acquisition and screen integration land separately.
pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE avatar_cache_meta (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            access_seq INTEGER NOT NULL DEFAULT 0
                CHECK(typeof(access_seq) = 'integer' AND access_seq >= 0)
        );
        INSERT INTO avatar_cache_meta(id) VALUES(1);
        CREATE TABLE avatar_assets (
            owner_key TEXT PRIMARY KEY NOT NULL CHECK(length(owner_key) BETWEEN 1 AND 512),
            source_key TEXT NOT NULL CHECK(length(source_key) BETWEEN 1 AND 512),
            token BLOB NOT NULL UNIQUE CHECK(length(token) = 16),
            content_revision INTEGER NOT NULL DEFAULT 0
                CHECK(typeof(content_revision) = 'integer' AND content_revision >= 0),
            bytes BLOB CHECK(bytes IS NULL OR length(bytes) BETWEEN 1 AND 10485760),
            digest BLOB CHECK(digest IS NULL OR length(digest) = 32),
            media_type TEXT,
            width INTEGER,
            height INTEGER,
            refresh_at INTEGER CHECK(refresh_at IS NULL OR
                (typeof(refresh_at) = 'integer' AND refresh_at >= 0)),
            accessed INTEGER NOT NULL CHECK(typeof(accessed) = 'integer' AND accessed >= 0),
            CHECK((bytes IS NULL AND digest IS NULL AND media_type IS NULL AND width IS NULL
                    AND height IS NULL AND refresh_at IS NULL)
                OR (bytes IS NOT NULL AND digest IS NOT NULL AND media_type IS NOT NULL
                    AND media_type IN ('image/png', 'image/jpeg', 'image/gif', 'image/webp')
                    AND width IS NOT NULL AND height IS NOT NULL
                    AND typeof(width) = 'integer' AND typeof(height) = 'integer'
                    AND width BETWEEN 1 AND 4096 AND height BETWEEN 1 AND 4096))
        );
        CREATE INDEX avatar_assets_lru ON avatar_assets(accessed, owner_key);
        CREATE TRIGGER avatar_cache_store_reset AFTER UPDATE OF store_epoch ON chat_presentation_meta
        WHEN OLD.store_epoch IS NOT NEW.store_epoch BEGIN
            DELETE FROM avatar_assets;
        END;",
    ).storage()
}
