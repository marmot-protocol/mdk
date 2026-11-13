use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

use crate::SqliteResultExt;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "ALTER TABLE app_sticker_packs ADD COLUMN relays_json TEXT NOT NULL DEFAULT '[]';",
    )
    .storage()
}
