//! Migration 0116: the opt-in "Keep media" setting (mdk#2314 step 10).
//!
//! - `attachment_keep_media` holds the account's window: no row or a NULL
//!   `keep_days` is Forever, the default, which removes nothing.
//! - `attachment_removal_suppression.reason` says why a slot is suppressed:
//!   0 removed by you (every existing row), 1 cleaned by the setting.
//! - `attachment_acquisition.keep_from` is when the user last asked for the
//!   body explicitly. The setting ages a retained attachment from the later
//!   of its received time and this, so an explicit download is kept for the
//!   whole window.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE attachment_keep_media (
            id INTEGER PRIMARY KEY CHECK(id=1),
            keep_days INTEGER CHECK(keep_days IS NULL OR keep_days IN (30,183,365))
        );
        ALTER TABLE attachment_removal_suppression
            ADD COLUMN reason INTEGER NOT NULL DEFAULT 0 CHECK(reason IN (0,1));
        ALTER TABLE attachment_acquisition
            ADD COLUMN keep_from INTEGER CHECK(keep_from IS NULL OR keep_from>=0);",
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::{MIGRATIONS, run};
    use rusqlite::Connection;

    /// Existing suppressions stay "removed by you", existing jobs have no
    /// explicit request time, and the setting starts as Forever.
    #[test]
    fn existing_rows_keep_their_meaning() {
        let mut conn = Connection::open_in_memory().unwrap();
        run(&mut conn, &MIGRATIONS[..115]).unwrap();
        conn.execute_batch(
            "PRAGMA foreign_keys=OFF;
            INSERT INTO attachment_removal_suppression VALUES('aa','m',0);
            INSERT INTO attachment_acquisition(token,group_id_hex,message_id_hex,attachment_index,
                source_message_id_hex,source_epoch,slot_json,plaintext_digest,due)
            VALUES(randomblob(16),'aa','n',0,'n',1,'[]',zeroblob(32),0);",
        )
        .unwrap();
        run(&mut conn, MIGRATIONS).unwrap();
        let reason: i64 = conn
            .query_row(
                "SELECT reason FROM attachment_removal_suppression",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(reason, 0);
        let keep_from: Option<i64> = conn
            .query_row("SELECT keep_from FROM attachment_acquisition", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(keep_from, None);
        let settings: i64 = conn
            .query_row("SELECT count(*) FROM attachment_keep_media", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(settings, 0);
        assert!(
            conn.execute("INSERT INTO attachment_keep_media VALUES(1,7)", [])
                .is_err(),
            "only the offered windows are stored"
        );
    }
}
