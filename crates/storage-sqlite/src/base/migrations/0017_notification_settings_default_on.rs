use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    // Change only the schema default for newly inserted rows. The INSERT ... SELECT
    // below copies existing per-account values verbatim so users who already
    // disabled local notifications stay disabled after the migration.
    tx.execute_batch(
        r#"
CREATE TABLE notification_settings_new (
    account_label TEXT PRIMARY KEY NOT NULL,
    account_id_hex TEXT NOT NULL,
    local_notifications_enabled INTEGER NOT NULL DEFAULT 1,
    native_push_enabled INTEGER NOT NULL DEFAULT 0,
    updated_at_ms INTEGER NOT NULL
);

INSERT INTO notification_settings_new (
    account_label,
    account_id_hex,
    local_notifications_enabled,
    native_push_enabled,
    updated_at_ms
)
SELECT
    account_label,
    account_id_hex,
    local_notifications_enabled,
    native_push_enabled,
    updated_at_ms
FROM notification_settings;

DROP TABLE notification_settings;
ALTER TABLE notification_settings_new RENAME TO notification_settings;
"#,
    )
    .storage()
}
