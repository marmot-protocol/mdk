//! The sender's record of each outbound Welcome's delivery (mdk#1706). See
//! migration 0225. The table is outside every snapshot, so rewinding a group
//! neither drops nor restores a record; its rows go with the group's
//! `cgka_groups` row.
//!
//! Inherent methods for the session's own storage handle, not a storage
//! trait: the engine never reads or writes these records.

use crate::base::connection::{CachedSql, retry_on_busy};
use crate::{SqliteAccountStorage, SqliteResultExt, deserialize, serialize};
use cgka_traits::maintenance::{DurableTransportFanout, WelcomeDeliveryRecord};
use cgka_traits::storage::{MaintenanceStorage, StorageResult};
use cgka_traits::types::{GroupId, MessageId};
use rusqlite::{OptionalExtension, params};

impl SqliteAccountStorage {
    /// Write one Welcome's record, replacing any stored for it.
    pub fn put_welcome_delivery_record(&self, record: &WelcomeDeliveryRecord) -> StorageResult<()> {
        let bytes = serialize(record)?;
        self.write_welcome_delivery_ledger(|| {
            self.lock()?
                .execute_cached(
                    "INSERT INTO cgka_welcome_delivery_ledger (welcome_id, group_id, record)
                     VALUES (?1, ?2, ?3)
                     ON CONFLICT(welcome_id) DO UPDATE SET record = excluded.record",
                    params![
                        record.welcome_id.as_slice(),
                        record.group_id.as_slice(),
                        bytes
                    ],
                )
                .storage()
        })
    }

    /// The record of the Welcome `welcome_id`, if one is stored.
    pub fn welcome_delivery_record(
        &self,
        welcome_id: &MessageId,
    ) -> StorageResult<Option<WelcomeDeliveryRecord>> {
        self.lock()?
            .query_row_cached(
                "SELECT record FROM cgka_welcome_delivery_ledger WHERE welcome_id = ?1",
                params![welcome_id.as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .storage()?
            .map(|bytes| deserialize(&bytes))
            .transpose()
    }

    /// Every stored record, or only `group_id`'s, in the order they were
    /// first written.
    pub fn welcome_delivery_records(
        &self,
        group_id: Option<&GroupId>,
    ) -> StorageResult<Vec<WelcomeDeliveryRecord>> {
        let connection = self.lock()?;
        let records = match group_id {
            Some(group_id) => connection
                .prepare_cached(
                    "SELECT record FROM cgka_welcome_delivery_ledger
                     WHERE group_id = ?1 ORDER BY rowid",
                )
                .storage()?
                .query_map(params![group_id.as_slice()], |row| row.get::<_, Vec<u8>>(0))
                .storage()?
                .collect::<Result<Vec<_>, _>>(),
            None => connection
                .prepare_cached("SELECT record FROM cgka_welcome_delivery_ledger ORDER BY rowid")
                .storage()?
                .query_map([], |row| row.get::<_, Vec<u8>>(0))
                .storage()?
                .collect::<Result<Vec<_>, _>>(),
        }
        .storage()?;
        records.iter().map(|bytes| deserialize(bytes)).collect()
    }

    /// Save a Welcome's retry record and the change to its delivery record in
    /// one transaction, so the attempt a delivery record counts is exactly the
    /// one its retry record holds. `delivery` names the Welcome and the change;
    /// its record is read inside the transaction, so a read that fails fails
    /// the whole save, and a Welcome with no record keeps none. Returns the
    /// delivery record saved. Without `delivery`, only the retry record.
    pub fn put_transport_fanout_with_welcome_delivery(
        &self,
        fanout: &DurableTransportFanout,
        delivery: Option<(&MessageId, impl FnOnce(&mut WelcomeDeliveryRecord))>,
    ) -> StorageResult<Option<WelcomeDeliveryRecord>> {
        let Some((welcome_id, change)) = delivery else {
            self.put_transport_fanout(fanout)?;
            return Ok(None);
        };
        self.connection.with_savepoint(|| {
            self.put_transport_fanout(fanout)?;
            let Some(mut record) = self.welcome_delivery_record(welcome_id)? else {
                return Ok(None);
            };
            change(&mut record);
            self.put_welcome_delivery_record(&record)?;
            Ok(Some(record))
        })
    }

    /// Write each of `records` whose Welcome has no record yet, in one
    /// transaction, leaving every stored one as it is: all of them or none.
    pub fn insert_missing_welcome_delivery_records(
        &self,
        records: &[WelcomeDeliveryRecord],
    ) -> StorageResult<()> {
        self.connection.with_savepoint(|| {
            for record in records {
                let bytes = serialize(record)?;
                self.lock()?
                    .execute_cached(
                        "INSERT INTO cgka_welcome_delivery_ledger (welcome_id, group_id, record)
                         VALUES (?1, ?2, ?3)
                         ON CONFLICT(welcome_id) DO NOTHING",
                        params![
                            record.welcome_id.as_slice(),
                            record.group_id.as_slice(),
                            bytes
                        ],
                    )
                    .storage()?;
            }
            Ok(())
        })
    }

    fn write_welcome_delivery_ledger(
        &self,
        write: impl Fn() -> StorageResult<usize>,
    ) -> StorageResult<()> {
        if self.connection.is_current_thread_transaction_owner() {
            write()?;
        } else {
            retry_on_busy(write)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::test_support::{gid, mid, sample_group};
    use cgka_traits::Timestamp;
    use cgka_traits::maintenance::WelcomeRelayCounts;
    use cgka_traits::storage::{GroupStorage, StorageError};
    use cgka_traits::types::MemberId;

    fn record(welcome: u8, group: u8) -> WelcomeDeliveryRecord {
        WelcomeDeliveryRecord {
            welcome_id: mid(welcome),
            group_id: gid(group),
            recipient: MemberId::new(vec![7; 32]),
            origin_commit_id: Some(mid(99)),
            created_at: Timestamp(10),
            attempts: 0,
            last_attempt_at: None,
            accepted_at: None,
            relays: WelcomeRelayCounts::default(),
            last_problem: None,
        }
    }

    /// A record rewritten under its Welcome's id replaces the stored one and
    /// keeps its place; listings filter by group; deleting the group deletes
    /// its records with it.
    #[test]
    fn welcome_delivery_records_update_in_place_and_go_with_their_group() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store.put_group(&sample_group(gid(1), 0, 0)).unwrap();
        store.put_group(&sample_group(gid(2), 0, 0)).unwrap();
        store.put_welcome_delivery_record(&record(1, 1)).unwrap();
        store.put_welcome_delivery_record(&record(2, 2)).unwrap();
        store.put_welcome_delivery_record(&record(3, 1)).unwrap();

        let mut sent = record(1, 1);
        sent.attempts = 1;
        store.put_welcome_delivery_record(&sent).unwrap();
        assert_eq!(
            store.welcome_delivery_record(&mid(1)).unwrap(),
            Some(sent.clone())
        );
        let ids = |records: Vec<WelcomeDeliveryRecord>| {
            records
                .into_iter()
                .map(|r| r.welcome_id)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            ids(store.welcome_delivery_records(None).unwrap()),
            vec![mid(1), mid(2), mid(3)]
        );
        assert_eq!(
            ids(store.welcome_delivery_records(Some(&gid(1))).unwrap()),
            vec![mid(1), mid(3)]
        );

        store.delete_group(&gid(1)).unwrap();
        assert_eq!(
            ids(store.welcome_delivery_records(None).unwrap()),
            vec![mid(2)]
        );
    }

    fn fanout(id: MessageId) -> DurableTransportFanout {
        use cgka_traits::transport::{TransportEnvelope, TransportMessage, TransportSource};
        use cgka_traits::{TransportEndpoint, TransportPublishTarget};
        let recipient = MemberId::new(vec![7; 32]);
        DurableTransportFanout {
            id: id.clone(),
            group_id: None,
            evolution_id: None,
            exact_message: TransportMessage {
                id,
                payload: b"wrap".to_vec(),
                timestamp: Timestamp(10),
                causal_deps: Vec::new(),
                source: TransportSource("nostr".into()),
                envelope: TransportEnvelope::Welcome {
                    recipient: recipient.clone(),
                },
            },
            target: TransportPublishTarget::Inbox {
                recipient,
                endpoints: vec![TransportEndpoint("wss://inbox.example".into())],
            },
            targets: Vec::new(),
            required_acks: 1,
            evolution_confirmed: false,
            possible_exposure: false,
            created_at: Timestamp(10),
            bounded_until: None,
        }
    }

    /// A retry record and its Welcome's delivery record are saved together
    /// or not at all: a delivery record write that fails takes the retry
    /// record back with it. A Welcome with no record keeps none.
    #[test]
    fn a_retry_record_and_its_delivery_record_are_saved_together() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store.put_group(&sample_group(gid(1), 0, 0)).unwrap();
        let count = |record: &mut WelcomeDeliveryRecord| record.attempts += 1;
        assert_eq!(
            store
                .put_transport_fanout_with_welcome_delivery(&fanout(mid(1)), Some((&mid(1), count)))
                .unwrap(),
            None,
            "no record to count on"
        );
        assert!(store.transport_fanout(&mid(1)).unwrap().is_some());
        assert_eq!(store.welcome_delivery_record(&mid(1)).unwrap(), None);

        store.put_welcome_delivery_record(&record(1, 1)).unwrap();
        let saved = store
            .put_transport_fanout_with_welcome_delivery(&fanout(mid(1)), Some((&mid(1), count)))
            .unwrap();
        let mut counted = record(1, 1);
        counted.attempts = 1;
        assert_eq!(saved, Some(counted.clone()));
        assert_eq!(
            store.welcome_delivery_record(&mid(1)).unwrap(),
            Some(counted)
        );

        store.put_welcome_delivery_record(&record(2, 1)).unwrap();
        store
            .lock()
            .unwrap()
            .execute_batch(
                "CREATE TEMP TRIGGER refuse_delivery_record BEFORE UPDATE ON cgka_welcome_delivery_ledger
                 BEGIN SELECT RAISE(ABORT, 'delivery record refused'); END;",
            )
            .unwrap();
        let result = store
            .put_transport_fanout_with_welcome_delivery(&fanout(mid(2)), Some((&mid(2), count)));
        assert!(
            matches!(&result, Err(StorageError::Backend(reason)) if reason.contains("delivery record refused")),
            "{result:?}"
        );
        assert!(store.transport_fanout(&mid(2)).unwrap().is_none());
    }
}
