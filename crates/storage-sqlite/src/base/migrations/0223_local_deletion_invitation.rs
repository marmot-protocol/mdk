//! Keep a locally deleted chat's invitation standing on its deletion frontier,
//! so a newer message that recreates the chat restores whether the invitation
//! was ever accepted and who sent it (mdk#3555). The app row that held these
//! is wiped by the deletion. Frontiers written before this keep NULL: unknown,
//! and recreation behaves as it did.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
ALTER TABLE local_group_deletion_frontiers
    ADD COLUMN pending_confirmation INTEGER CHECK(pending_confirmation IN (0, 1));
ALTER TABLE local_group_deletion_frontiers ADD COLUMN welcomer_account_id_hex TEXT;
ALTER TABLE local_group_deletion_frontiers ADD COLUMN via_welcome_message_id_hex TEXT;
"#,
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::run_through;
    use rusqlite::{Connection, Error, ErrorCode};

    #[test]
    fn existing_frontiers_keep_an_unknown_invitation_standing() {
        let mut conn = Connection::open_in_memory().unwrap();
        run_through(&mut conn, 222).unwrap();
        conn.execute(
            "INSERT INTO local_group_deletion_frontiers (group_id_hex, message_insert_order)
             VALUES ('aa', 7)",
            [],
        )
        .unwrap();
        run_through(&mut conn, 223).unwrap();

        let row: (i64, String, Option<i64>, Option<String>, Option<String>) = conn
            .query_row(
                "SELECT message_insert_order, prior_nostr_routes_json, pending_confirmation,
                        welcomer_account_id_hex, via_welcome_message_id_hex
                 FROM local_group_deletion_frontiers WHERE group_id_hex = 'aa'",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(row, (7, "[]".to_owned(), None, None, None));
        let err = conn
            .execute(
                "UPDATE local_group_deletion_frontiers SET pending_confirmation = 2",
                [],
            )
            .expect_err("CHECK(pending_confirmation IN (0, 1)) must reject 2");
        assert!(
            matches!(
                err,
                Error::SqliteFailure(ffi, _) if ffi.code == ErrorCode::ConstraintViolation
            ),
            "expected CHECK constraint violation, got {err:?}",
        );
    }
}
