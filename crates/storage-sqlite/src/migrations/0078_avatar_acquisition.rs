use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE avatar_acquisition (
            token BLOB PRIMARY KEY NOT NULL REFERENCES avatar_assets(token) ON DELETE CASCADE,
            descriptor BLOB NOT NULL CHECK(typeof(descriptor) = 'blob' AND length(descriptor) BETWEEN 1 AND 16384),
            state INTEGER NOT NULL DEFAULT 1 CHECK(state IN (0, 1, 2, 3, 4)),
            due INTEGER CHECK(due IS NULL OR (typeof(due) = 'integer' AND due >= 0)),
            failures INTEGER NOT NULL DEFAULT 0 CHECK(typeof(failures) = 'integer' AND failures BETWEEN 0 AND 16),
            priority INTEGER NOT NULL DEFAULT 0 CHECK(priority IN (0, 1)),
            attempt BLOB CHECK(attempt IS NULL OR (typeof(attempt) = 'blob' AND length(attempt) = 16))
        );
        CREATE TRIGGER avatar_acquisition_source_changed BEFORE UPDATE OF token ON avatar_assets
        WHEN OLD.token IS NOT NEW.token BEGIN
            DELETE FROM avatar_acquisition WHERE token = OLD.token;
        END;
        CREATE TRIGGER avatar_acquisition_repair AFTER UPDATE OF bytes ON avatar_assets
        WHEN OLD.bytes IS NOT NULL AND NEW.bytes IS NULL BEGIN
            UPDATE avatar_acquisition SET state = 1, due = 0, attempt = NULL WHERE token = NEW.token;
        END;
        CREATE INDEX avatar_acquisition_due ON avatar_acquisition(due, priority) WHERE due IS NOT NULL;
        CREATE TABLE avatar_acquisition_bootstrap (
            group_id_hex TEXT PRIMARY KEY NOT NULL REFERENCES chat_list_rows(group_id_hex) ON DELETE CASCADE
        );
        INSERT INTO avatar_acquisition_bootstrap SELECT group_id_hex FROM chat_list_rows;
        CREATE TABLE avatar_identity_demand (
            owner_key TEXT PRIMARY KEY NOT NULL,
            group_id_hex TEXT NOT NULL REFERENCES chat_list_rows(group_id_hex) ON DELETE CASCADE,
            member_id_hex TEXT NOT NULL,
            profile_epoch BLOB NOT NULL CHECK(typeof(profile_epoch) = 'blob' AND length(profile_epoch) = 16),
            profile_revision INTEGER NOT NULL CHECK(typeof(profile_revision) = 'integer' AND profile_revision >= 0),
            accessed INTEGER NOT NULL CHECK(typeof(accessed) = 'integer' AND accessed >= 0)
        );
        CREATE INDEX avatar_identity_demand_recency ON avatar_identity_demand(accessed, owner_key);
        CREATE TRIGGER avatar_identity_evicted AFTER DELETE ON avatar_assets BEGIN
            DELETE FROM avatar_identity_demand WHERE owner_key = OLD.owner_key;
        END;
        CREATE TRIGGER avatar_identity_store_reset AFTER UPDATE OF store_epoch ON chat_presentation_meta
        WHEN OLD.store_epoch IS NOT NEW.store_epoch BEGIN
            DELETE FROM avatar_identity_demand;
            DELETE FROM avatar_acquisition_bootstrap;
        END;
        CREATE TRIGGER avatar_chat_deleted BEFORE DELETE ON chat_list_rows BEGIN
            DELETE FROM avatar_assets WHERE owner_key = 'chat:' || lower(hex(OLD.presentation_row_epoch))
                OR owner_key IN (SELECT owner_key FROM avatar_identity_demand WHERE group_id_hex = OLD.group_id_hex);
        END;",
    ).storage()
}
