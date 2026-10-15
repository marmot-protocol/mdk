//! Migration 0110: metadata for the encrypted per-file media store (mdk#2314).
//!
//! Bodies live in `<account>/media/<shard>/<id>` files; these rows hold each
//! file's random key and lifecycle. Nothing writes them until attachments move
//! onto the store, so existing accounts gain only empty tables.
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

use crate::SqliteResultExt;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    // `state`: 0 pending (row first, then file, see media_store), 1 ready,
    // 2 lost (ready row whose file disappeared; its key is zeroed).
    // `category`: 1 retained media (never deleted automatically), 2 reserved
    // for the evictable cache category (avatars, group images).
    // Deleting a row is the real erase: the account database runs with
    // `secure_delete`, so the key does not survive in free pages.
    //
    // A reference ties one attachment slot (its acquisition token) to a ready
    // file; deduplicated slots share a file. Removing the last reference
    // deletes the file's row, including when an acquisition row is deleted by
    // a source, retention or store-reset trigger. The sweep then unlinks the
    // file, which no longer has a row.
    tx.execute_batch(
        "CREATE TABLE media_files (
            id BLOB PRIMARY KEY NOT NULL CHECK(length(id)=16),
            file_key BLOB NOT NULL CHECK(length(file_key)=32),
            state INTEGER NOT NULL CHECK(state IN (0,1,2)),
            category INTEGER NOT NULL CHECK(category IN (1,2)),
            byte_len INTEGER NOT NULL CHECK(byte_len>=0),
            plaintext_digest BLOB NOT NULL CHECK(length(plaintext_digest)=32),
            created_at INTEGER NOT NULL CHECK(created_at>=0),
            last_used_at INTEGER NOT NULL CHECK(last_used_at>=0)
        );
        CREATE UNIQUE INDEX media_files_ready_digest
            ON media_files(category,plaintext_digest) WHERE state=1;
        CREATE TABLE media_file_refs (
            token BLOB PRIMARY KEY NOT NULL
                REFERENCES attachment_acquisition(token) ON DELETE CASCADE,
            file_id BLOB NOT NULL REFERENCES media_files(id)
        );
        CREATE INDEX media_file_refs_file ON media_file_refs(file_id);
        CREATE TRIGGER media_file_refs_ready BEFORE INSERT ON media_file_refs
        WHEN (SELECT state FROM media_files WHERE id=NEW.file_id) IS NOT 1 BEGIN
            SELECT RAISE(ABORT,'media file reference requires a ready file');
        END;
        CREATE TRIGGER media_file_refs_last AFTER DELETE ON media_file_refs
        WHEN NOT EXISTS(SELECT 1 FROM media_file_refs WHERE file_id=OLD.file_id) BEGIN
            DELETE FROM media_files WHERE id=OLD.file_id AND state<>0;
        END;
        CREATE TRIGGER media_files_store_reset AFTER UPDATE OF store_epoch ON chat_presentation_meta
        WHEN OLD.store_epoch IS NOT NEW.store_epoch BEGIN
            DELETE FROM media_file_refs;
            DELETE FROM media_files;
        END;",
    )
    .storage()
}
