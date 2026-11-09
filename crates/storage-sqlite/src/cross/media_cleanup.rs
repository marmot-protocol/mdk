//! The per-connection count of deleted media rows (mdk#2923 §4).
//!
//! `media_cleanup_epoch` counts deleted `media_files` and `attachment_partial`
//! rows on this connection. Those deletes (cascades, triggers, prunes) can
//! leave a file with no row, which only the media sweep removes, so the sweep
//! runs again only once this moves. TEMP objects, created at every open: no
//! migration, nothing stored, and the triggers fire for this connection
//! alone; commits from another connection show in `PRAGMA data_version`
//! instead.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;

pub(crate) fn create_media_cleanup_epoch(connection: &rusqlite::Connection) -> StorageResult<()> {
    connection
        .execute_batch(
            "CREATE TEMP TABLE IF NOT EXISTS media_cleanup_epoch (
                 singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                 deleted INTEGER NOT NULL
             );
             INSERT OR IGNORE INTO media_cleanup_epoch (singleton, deleted) VALUES (1, 0);
             CREATE TEMP TRIGGER IF NOT EXISTS media_cleanup_file_deleted
             AFTER DELETE ON main.media_files
             BEGIN
                 UPDATE media_cleanup_epoch SET deleted = deleted + 1 WHERE singleton = 1;
             END;
             CREATE TEMP TRIGGER IF NOT EXISTS media_cleanup_partial_deleted
             AFTER DELETE ON main.attachment_partial
             BEGIN
                 UPDATE media_cleanup_epoch SET deleted = deleted + 1 WHERE singleton = 1;
             END;",
        )
        .storage()
}
