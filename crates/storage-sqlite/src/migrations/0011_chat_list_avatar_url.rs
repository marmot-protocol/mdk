use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    if !table_has_column(tx, "chat_list_rows", "avatar_url")? {
        tx.execute_batch(
            r#"
ALTER TABLE chat_list_rows ADD COLUMN avatar_url TEXT;
"#,
        )
        .storage()?;
    }
    tx.execute_batch(
        r#"
UPDATE chat_list_rows SET updated_at = 0;
"#,
    )
    .storage()
}

fn table_has_column(tx: &Transaction<'_>, table: &str, column: &str) -> StorageResult<bool> {
    let mut statement = tx
        .prepare(&format!("PRAGMA table_info({table})"))
        .storage()?;
    let mut rows = statement.query([]).storage()?;
    while let Some(row) = rows.next().storage()? {
        let name: String = row.get("name").storage()?;
        if name == column {
            return Ok(true);
        }
    }
    Ok(false)
}
