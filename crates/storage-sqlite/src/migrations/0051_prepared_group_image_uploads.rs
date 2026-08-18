use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE app_prepared_group_image_upload (
    upload_id          TEXT PRIMARY KEY,
    state              TEXT NOT NULL CHECK (state IN ('staged', 'uploaded', 'failed', 'consumed')),
    component_data     BLOB NOT NULL,
    encrypted_blob     BLOB,
    upload_secret      BLOB,
    group_id_hex       TEXT,
    attempt_count      INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    last_error_kind    TEXT,
    recorded_at        INTEGER NOT NULL,
    updated_at         INTEGER NOT NULL,
    CHECK (
        (state = 'consumed' AND group_id_hex IS NOT NULL)
        OR (state != 'consumed' AND group_id_hex IS NULL)
    ),
    CHECK (
        (state = 'consumed' AND length(component_data) = 0
            AND encrypted_blob IS NULL AND upload_secret IS NULL)
        OR (state != 'consumed' AND length(component_data) > 0
            AND length(encrypted_blob) > 0 AND length(upload_secret) = 32)
    )
);
CREATE INDEX app_prepared_group_image_upload_state_idx
    ON app_prepared_group_image_upload (state, updated_at, upload_id);
"#,
    )
    .storage()
}
