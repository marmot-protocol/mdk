use crate::connection::retry_on_busy;
use crate::{SqliteAccountStorage, SqliteResultExt, i64_to_u64, u64_to_i64};
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{OptionalExtension, params};

/// One ordered opaque account-runtime visibility record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountVisibilityJournalRow {
    pub sequence: u64,
    pub operation_id: Vec<u8>,
    pub ordinal: u64,
    pub batch_id: Vec<u8>,
    pub record: Vec<u8>,
}

/// One opaque record to insert or replace as part of an atomic visibility
/// checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountVisibilityJournalUpsert {
    pub operation_id: Vec<u8>,
    pub ordinal: u64,
    pub batch_id: Vec<u8>,
    pub record: Vec<u8>,
}

impl SqliteAccountStorage {
    /// Load every unacknowledged visibility record in insertion order.
    pub fn load_account_visibility_journal(
        &self,
    ) -> StorageResult<Vec<AccountVisibilityJournalRow>> {
        let connection = self.lock()?;
        let mut statement = connection
            .prepare(
                "SELECT sequence, operation_id, ordinal, batch_id, record
                 FROM account_visibility_journal
                 ORDER BY sequence",
            )
            .storage()?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                ))
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        rows.into_iter()
            .map(|(sequence, operation_id, ordinal, batch_id, record)| {
                Ok(AccountVisibilityJournalRow {
                    sequence: i64_to_u64(sequence)?,
                    operation_id,
                    ordinal: i64_to_u64(ordinal)?,
                    batch_id,
                    record,
                })
            })
            .collect()
    }

    /// Insert a new stable operation/ordinal record or replace its opaque bytes.
    /// Existing rows retain their original global `sequence`.
    pub fn upsert_account_visibility_journal(
        &self,
        operation_id: &[u8],
        ordinal: u64,
        batch_id: &[u8],
        record: &[u8],
    ) -> StorageResult<u64> {
        let mut sequences =
            self.upsert_account_visibility_journal_records(&[AccountVisibilityJournalUpsert {
                operation_id: operation_id.to_vec(),
                ordinal,
                batch_id: batch_id.to_vec(),
                record: record.to_vec(),
            }])?;
        Ok(sequences.pop().expect("one input produces one sequence"))
    }

    /// Atomically insert or replace a complete visibility checkpoint. If any
    /// entry is invalid or conflicts, none of the rows are changed.
    pub fn upsert_account_visibility_journal_records(
        &self,
        records: &[AccountVisibilityJournalUpsert],
    ) -> StorageResult<Vec<u64>> {
        let validated = records
            .iter()
            .map(|record| {
                if record.operation_id.is_empty() || record.batch_id.is_empty() {
                    return Err(StorageError::Backend(
                        "account visibility operation and batch ids must be non-empty".into(),
                    ));
                }
                Ok((record, u64_to_i64(record.ordinal)?))
            })
            .collect::<StorageResult<Vec<_>>>()?;
        self.write_account_visibility_journal(|| {
            self.connection.with_transaction(|| {
                let connection = self.lock()?;
                let mut sequences = Vec::with_capacity(validated.len());
                for (record, ordinal) in &validated {
                    connection
                        .execute(
                            "INSERT INTO account_visibility_journal
                                (operation_id, ordinal, batch_id, record)
                             VALUES (?1, ?2, ?3, ?4)
                             ON CONFLICT(operation_id, ordinal) DO UPDATE SET
                                record = excluded.record
                             WHERE account_visibility_journal.batch_id = excluded.batch_id",
                            params![
                                &record.operation_id,
                                ordinal,
                                &record.batch_id,
                                &record.record,
                            ],
                        )
                        .storage()?;
                    let sequence = connection
                        .query_row(
                            "SELECT sequence FROM account_visibility_journal
                             WHERE operation_id = ?1 AND ordinal = ?2 AND batch_id = ?3",
                            params![&record.operation_id, ordinal, &record.batch_id],
                            |row| row.get::<_, i64>(0),
                        )
                        .optional()
                        .storage()?
                        .ok_or_else(|| {
                            StorageError::Backend(
                                "account visibility operation/ordinal reused with another batch id"
                                    .into(),
                            )
                        })?;
                    sequences.push(i64_to_u64(sequence)?);
                }
                Ok(sequences)
            })
        })
    }

    /// Atomically delete exactly the acknowledged stable batch ids.
    pub fn delete_account_visibility_journal_batches(
        &self,
        batch_ids: &[Vec<u8>],
    ) -> StorageResult<usize> {
        self.write_account_visibility_journal(|| {
            self.connection.with_transaction(|| {
                let connection = self.lock()?;
                let mut deleted = 0_usize;
                for batch_id in batch_ids {
                    deleted = deleted.saturating_add(
                        connection
                            .execute(
                                "DELETE FROM account_visibility_journal WHERE batch_id = ?1",
                                params![batch_id],
                            )
                            .storage()?,
                    );
                }
                Ok(deleted)
            })
        })
    }

    fn write_account_visibility_journal<T>(
        &self,
        op: impl Fn() -> StorageResult<T>,
    ) -> StorageResult<T> {
        if self.connection.is_current_thread_transaction_owner() {
            op()
        } else {
            retry_on_busy(op)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_orders_exact_bytes_upserts_in_place_and_deletes_atomically() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let operation_a = [0_u8, 0xff, 0x80];
        let operation_b = [2_u8, 0, 3];
        let batch_a = [4_u8, 0xff, 5];
        let batch_b = [6_u8, 0, 7];
        let first = [8_u8, 0xff, 9, 0];
        let second = [10_u8, 0, 11];
        let replacement = [12_u8, 0xff, 13, 0];

        let sequence_a = store
            .upsert_account_visibility_journal(&operation_a, 0, &batch_a, &first)
            .unwrap();
        let sequence_b = store
            .upsert_account_visibility_journal(&operation_b, 9, &batch_b, &second)
            .unwrap();
        assert!(sequence_a < sequence_b);
        assert_eq!(
            store
                .upsert_account_visibility_journal(&operation_a, 0, &batch_a, &replacement,)
                .unwrap(),
            sequence_a,
            "upsert must preserve global order"
        );

        assert_eq!(
            store.load_account_visibility_journal().unwrap(),
            vec![
                AccountVisibilityJournalRow {
                    sequence: sequence_a,
                    operation_id: operation_a.to_vec(),
                    ordinal: 0,
                    batch_id: batch_a.to_vec(),
                    record: replacement.to_vec(),
                },
                AccountVisibilityJournalRow {
                    sequence: sequence_b,
                    operation_id: operation_b.to_vec(),
                    ordinal: 9,
                    batch_id: batch_b.to_vec(),
                    record: second.to_vec(),
                },
            ]
        );

        assert_eq!(
            store
                .delete_account_visibility_journal_batches(&[batch_b.to_vec(), batch_a.to_vec(),])
                .unwrap(),
            2
        );
        assert!(store.load_account_visibility_journal().unwrap().is_empty());
    }

    #[test]
    fn upsert_rejects_operation_ordinal_or_batch_id_aba() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store
            .upsert_account_visibility_journal(b"operation-a", 3, b"batch-a", b"first")
            .unwrap();
        assert!(
            store
                .upsert_account_visibility_journal(b"operation-a", 3, b"batch-b", b"other")
                .is_err()
        );
        assert!(
            store
                .upsert_account_visibility_journal(b"operation-b", 4, b"batch-a", b"other")
                .is_err()
        );
        assert_eq!(
            store.load_account_visibility_journal().unwrap()[0].record,
            b"first"
        );
    }

    #[test]
    fn bulk_upsert_rolls_back_every_row_when_one_entry_conflicts() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store
            .upsert_account_visibility_journal(b"operation-a", 1, b"batch-a", b"original")
            .unwrap();

        let result = store.upsert_account_visibility_journal_records(&[
            AccountVisibilityJournalUpsert {
                operation_id: b"operation-b".to_vec(),
                ordinal: 2,
                batch_id: b"batch-b".to_vec(),
                record: vec![0, 0xff, 0x80],
            },
            AccountVisibilityJournalUpsert {
                operation_id: b"operation-a".to_vec(),
                ordinal: 1,
                batch_id: b"wrong-batch".to_vec(),
                record: b"must-not-replace".to_vec(),
            },
        ]);
        assert!(result.is_err());
        assert_eq!(
            store.load_account_visibility_journal().unwrap(),
            vec![AccountVisibilityJournalRow {
                sequence: 1,
                operation_id: b"operation-a".to_vec(),
                ordinal: 1,
                batch_id: b"batch-a".to_vec(),
                record: b"original".to_vec(),
            }]
        );
    }
}
