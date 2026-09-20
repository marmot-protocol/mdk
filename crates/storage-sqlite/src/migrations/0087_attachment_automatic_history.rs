use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

use crate::SqliteResultExt;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(r#"
ALTER TABLE attachment_acquisition ADD COLUMN acquisition_attempts INTEGER NOT NULL DEFAULT 0 CHECK(acquisition_attempts>=0);
ALTER TABLE attachment_acquisition ADD COLUMN network_attempts INTEGER NOT NULL DEFAULT 0 CHECK(network_attempts>=0);
ALTER TABLE attachment_acquisition ADD COLUMN body_completed INTEGER NOT NULL DEFAULT 0 CHECK(body_completed IN (0,1));
-- Existing failure streaks are a conservative lower bound; progress in older
-- versions erased the preceding history, which cannot be reconstructed.
UPDATE attachment_acquisition SET network_attempts=min(attempts,4),acquisition_attempts=min(attempts,4);
"#).storage()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::{MIGRATIONS, run};

    #[test]
    fn automatic_history_migration_is_transactional_and_repeatable() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        run(&mut conn, &MIGRATIONS[..86]).unwrap();
        let tx = conn.transaction().unwrap();
        apply(&tx).unwrap();
        tx.rollback().unwrap();
        assert!(
            conn.prepare("SELECT network_attempts FROM attachment_acquisition")
                .is_err()
        );
        run(&mut conn, MIGRATIONS).unwrap();
        run(&mut conn, MIGRATIONS).unwrap();
        assert!(
            conn.prepare("SELECT acquisition_attempts,network_attempts,body_completed FROM attachment_acquisition")
                .is_ok()
        );
    }
}
