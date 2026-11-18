//! Latest approver inventory and authenticated pages received for a link.
//! Old stores have no report until an eligible device completes its scan.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE link_chat_reports (
            group_id TEXT NOT NULL, slot TEXT NOT NULL, link_ref TEXT NOT NULL,
            digest BLOB NOT NULL, revision INTEGER NOT NULL, total INTEGER NOT NULL,
            remaining INTEGER NOT NULL, expires_at INTEGER NOT NULL,
            PRIMARY KEY(group_id, slot)
         );
         CREATE TABLE link_chat_report_pages (
            group_id TEXT NOT NULL, link_ref TEXT NOT NULL, revision INTEGER NOT NULL,
            page INTEGER NOT NULL, total INTEGER NOT NULL, expires_at INTEGER NOT NULL,
            tokens BLOB NOT NULL, message_id BLOB,
            PRIMARY KEY(group_id, page)
         );",
    )
    .storage()
}
