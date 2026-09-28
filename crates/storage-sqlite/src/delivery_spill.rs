//! Durable overflow tail of the bounded in-memory account delivery queue.
//!
//! When the account queue is full, the relay router hands deliveries to this
//! table instead of dropping them. The account worker later admits each row
//! through the ordinary ingest path and removes it afterwards, so a spilled
//! delivery stays durable until ingest has seen it.
use crate::connection::{CachedSql, retry_on_busy};
use crate::{SqliteAccountStorage, SqliteResultExt, i64_to_u64, u64_to_i64};
use cgka_traits::TransportDelivery;
use cgka_traits::storage::StorageResult;
use rusqlite::{Connection, OptionalExtension, params};

/// Upper bounds on the spill table. A delivery that would exceed either one is
/// reported [`DeliverySpillDisposition::Full`] and left to the loss path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeliverySpillLimits {
    pub max_rows: u64,
    pub max_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliverySpillDisposition {
    /// Durably held for later admission, including a copy that was already
    /// spilled.
    Stored,
    /// Already durably seen and not released for redelivery, so there is
    /// nothing to keep.
    AlreadySeen,
    /// No room within the limits. The caller must treat the delivery as lost.
    Full,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpilledDelivery {
    pub seq: i64,
    pub delivery: TransportDelivery,
}

/// One read of due spilled rows.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SpilledDeliveryBatch {
    pub deliveries: Vec<SpilledDelivery>,
    /// Rows whose metadata no longer decodes. Their content is unknown; the
    /// caller discards them as delivery loss.
    pub undecodable: Vec<i64>,
    /// The read filled its limit, so more due rows may remain.
    pub more: bool,
    /// Earliest retry time of a deferred row that is not yet due.
    pub next_retry_at: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpilledDeliveryDeferral {
    pub attempts: u32,
    pub not_before: u64,
}

/// Artifact-local version of the `metadata` encoding.
const SPILL_FORMAT: i64 = 1;
const SPILL_RETRY_BASE_SECS: u64 = 60;
const SPILL_RETRY_CAP_SECS: u64 = 60 * 60;

/// The payload keeps its own column. JSON would inflate raw ciphertext about
/// threefold, so only the small remaining metadata is serialized.
struct EncodedDelivery {
    event_id: Vec<u8>,
    payload: Vec<u8>,
    metadata: Vec<u8>,
    bytes: u64,
}

impl EncodedDelivery {
    fn encode(delivery: &TransportDelivery) -> StorageResult<Self> {
        let mut metadata = delivery.clone();
        let payload = std::mem::take(&mut metadata.message.payload);
        let metadata = crate::codec::serialize(&metadata)?;
        Ok(Self {
            event_id: delivery.message.id.as_slice().to_vec(),
            bytes: (payload.len() + metadata.len()) as u64,
            payload,
            metadata,
        })
    }
}

fn already_seen(conn: &Connection, event_id: &[u8]) -> StorageResult<bool> {
    // Release journals the ID before the app's seen ring is rewritten, so a
    // journaled receipt still needs redelivery even while `seen_events` lists it.
    conn.query_row_cached(
        "SELECT EXISTS(SELECT 1 FROM seen_events WHERE event_id=?1)
            AND NOT EXISTS(SELECT 1 FROM cgka_released_transport_receipts WHERE id=?2)",
        params![hex::encode(event_id), event_id],
        |row| row.get(0),
    )
    .storage()
}

fn already_spilled(conn: &Connection, event_id: &[u8]) -> StorageResult<bool> {
    conn.query_row_cached(
        "SELECT EXISTS(SELECT 1 FROM account_delivery_spill WHERE event_id=?1)",
        [event_id],
        |row| row.get(0),
    )
    .storage()
}

impl SqliteAccountStorage {
    /// Spill deliveries in order and report one disposition per input.
    pub fn spill_account_deliveries(
        &self,
        deliveries: &[TransportDelivery],
        limits: DeliverySpillLimits,
        now_secs: u64,
    ) -> StorageResult<Vec<DeliverySpillDisposition>> {
        let encoded = deliveries
            .iter()
            .map(EncodedDelivery::encode)
            .collect::<StorageResult<Vec<_>>>()?;
        let spilled_at = u64_to_i64(now_secs)?;
        retry_on_busy(|| {
            self.connection.with_transaction(|| {
                let conn = self.lock()?;
                let (rows, bytes): (i64, i64) = conn
                    .query_row_cached(
                        "SELECT COUNT(*), COALESCE(SUM(bytes), 0) FROM account_delivery_spill",
                        [],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .storage()?;
                let (mut rows, mut bytes) = (i64_to_u64(rows)?, i64_to_u64(bytes)?);
                let mut dispositions = Vec::with_capacity(encoded.len());
                for delivery in &encoded {
                    let disposition = if already_seen(&conn, &delivery.event_id)? {
                        DeliverySpillDisposition::AlreadySeen
                    } else if already_spilled(&conn, &delivery.event_id)? {
                        DeliverySpillDisposition::Stored
                    } else if rows >= limits.max_rows
                        || bytes.saturating_add(delivery.bytes) > limits.max_bytes
                    {
                        DeliverySpillDisposition::Full
                    } else {
                        conn.execute_cached(
                            "INSERT INTO account_delivery_spill
                                (event_id, payload, metadata, format, bytes, spilled_at)
                             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                            params![
                                delivery.event_id,
                                delivery.payload,
                                delivery.metadata,
                                SPILL_FORMAT,
                                u64_to_i64(delivery.bytes)?,
                                spilled_at
                            ],
                        )
                        .storage()?;
                        rows += 1;
                        bytes = bytes.saturating_add(delivery.bytes);
                        DeliverySpillDisposition::Stored
                    };
                    dispositions.push(disposition);
                }
                Ok(dispositions)
            })
        })
    }

    /// Oldest due rows first. A row whose metadata no longer decodes is
    /// reported in `undecodable` and does not end the read early.
    pub fn spilled_account_deliveries(
        &self,
        limit: usize,
        now_secs: u64,
    ) -> StorageResult<SpilledDeliveryBatch> {
        let now = u64_to_i64(now_secs)?;
        let conn = self.lock()?;
        let rows = conn
            .prepare_cached(
                "SELECT seq, payload, metadata FROM account_delivery_spill
                 WHERE not_before <= ?1 ORDER BY seq LIMIT ?2",
            )
            .storage()?
            .query_map(params![now, u64_to_i64(limit as u64)?], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        let mut batch = SpilledDeliveryBatch {
            more: rows.len() == limit,
            ..SpilledDeliveryBatch::default()
        };
        for (seq, payload, metadata) in rows {
            match crate::codec::deserialize::<TransportDelivery>(&metadata) {
                Ok(mut delivery) => {
                    delivery.message.payload = payload;
                    batch.deliveries.push(SpilledDelivery { seq, delivery });
                }
                Err(_) => batch.undecodable.push(seq),
            }
        }
        let next: Option<i64> = conn
            .query_row_cached(
                "SELECT MIN(not_before) FROM account_delivery_spill WHERE not_before > ?1",
                [now],
                |row| row.get(0),
            )
            .storage()?;
        batch.next_retry_at = next.map(i64_to_u64).transpose()?;
        Ok(batch)
    }

    pub fn remove_spilled_account_delivery(&self, seq: i64) -> StorageResult<()> {
        self.lock()?
            .execute_cached("DELETE FROM account_delivery_spill WHERE seq=?1", [seq])
            .storage()?;
        Ok(())
    }

    /// Keep a spilled row whose ingest left no durable trace and retry it
    /// after a doubling delay (one minute up to an hour). Returns None when
    /// the row is already gone.
    pub fn defer_spilled_account_delivery(
        &self,
        seq: i64,
        now_secs: u64,
    ) -> StorageResult<Option<SpilledDeliveryDeferral>> {
        let conn = self.lock()?;
        let Some(attempts) = conn
            .query_row_cached(
                "UPDATE account_delivery_spill SET attempts = attempts + 1 WHERE seq=?1
                 RETURNING attempts",
                [seq],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .storage()?
        else {
            return Ok(None);
        };
        let attempts = u32::try_from(attempts).unwrap_or(u32::MAX);
        let delay = SPILL_RETRY_BASE_SECS
            .saturating_mul(1_u64 << attempts.saturating_sub(1).min(16))
            .min(SPILL_RETRY_CAP_SECS);
        let not_before = now_secs.saturating_add(delay);
        conn.execute_cached(
            "UPDATE account_delivery_spill SET not_before=?2 WHERE seq=?1",
            params![seq, u64_to_i64(not_before)?],
        )
        .storage()?;
        Ok(Some(SpilledDeliveryDeferral {
            attempts,
            not_before,
        }))
    }

    /// Remove rows the account cannot admit, record them as queue loss and
    /// import that loss into a recovery obligation, all in one transaction.
    /// Any failure leaves the rows in place.
    pub fn discard_spilled_account_deliveries(
        &self,
        seqs: &[i64],
        account_label: &str,
        loss_token: u64,
        now_secs: u64,
    ) -> StorageResult<()> {
        retry_on_busy(|| {
            self.connection.with_transaction(|| {
                let (removed, earliest_created_at) = {
                    let conn = self.lock()?;
                    let mut removed = 0_u64;
                    // The earliest wire created_at among the removed
                    // deliveries, or unknown once any row does not decode.
                    let mut earliest = Some(u64::MAX);
                    for seq in seqs {
                        let Some(metadata) = conn
                            .query_row_cached(
                                "DELETE FROM account_delivery_spill WHERE seq=?1 RETURNING metadata",
                                [seq],
                                |row| row.get::<_, Vec<u8>>(0),
                            )
                            .optional()
                            .storage()?
                        else {
                            continue;
                        };
                        removed += 1;
                        let created_at = crate::codec::deserialize::<TransportDelivery>(&metadata)
                            .ok()
                            .map(|delivery| delivery.message.timestamp.0);
                        earliest = earliest.zip(created_at).map(|(a, b)| a.min(b));
                    }
                    (removed, earliest)
                };
                if removed > 0 {
                    self.record_account_recovery_loss_bounded(
                        account_label,
                        crate::RecoveryLossCause::Queue,
                        loss_token,
                        removed,
                        now_secs,
                        earliest_created_at,
                    )?;
                    self.synchronize_account_delivery_loss(account_label)?;
                }
                Ok(())
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RecoveryLossCause;
    use crate::storage::test_support::{gid, sample_group};
    use cgka_traits::storage::GroupStorage;
    use cgka_traits::transport::{TransportEnvelope, TransportMessage, TransportSource};
    use cgka_traits::{MemberId, MessageId, TransportDeliveryPlane, TransportDeliverySource};

    const LIMITS: DeliverySpillLimits = DeliverySpillLimits {
        max_rows: 3,
        max_bytes: u64::MAX,
    };

    fn delivery(id: u8) -> TransportDelivery {
        TransportDelivery {
            account_id: MemberId::new(vec![0xAA; 32]),
            group_id_hint: None,
            message: TransportMessage {
                id: MessageId::new(vec![id; 32]),
                payload: vec![id; 64],
                timestamp: cgka_traits::transport::Timestamp(u64::from(id)),
                causal_deps: Vec::new(),
                source: TransportSource("nostr".to_owned()),
                envelope: TransportEnvelope::GroupMessage {
                    transport_group_id: vec![0x42; 32],
                },
            },
            received_at: cgka_traits::transport::Timestamp(7),
            source: TransportDeliverySource {
                transport: TransportSource("nostr".to_owned()),
                plane: TransportDeliveryPlane::Group,
                endpoint: None,
                subscription_id: Some("live".to_owned()),
                wire: None,
            },
        }
    }

    fn mark_seen(store: &SqliteAccountStorage, id: u8) {
        store
            .lock()
            .unwrap()
            .execute_cached(
                "INSERT INTO seen_events(event_id, seen_at) VALUES (?1, 1)",
                [hex::encode([id; 32])],
            )
            .unwrap();
    }

    fn due(store: &SqliteAccountStorage, now: u64) -> SpilledDeliveryBatch {
        store.spilled_account_deliveries(10, now).unwrap()
    }

    #[test]
    fn spill_round_trips_in_order_and_removes_rows() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let outcome = store
            .spill_account_deliveries(&[delivery(2), delivery(1)], LIMITS, 9)
            .unwrap();
        assert_eq!(outcome, vec![DeliverySpillDisposition::Stored; 2]);

        let spilled = due(&store, 9).deliveries;
        let deliveries: Vec<_> = spilled.iter().map(|row| row.delivery.clone()).collect();
        assert_eq!(deliveries, vec![delivery(2), delivery(1)]);

        store
            .remove_spilled_account_delivery(spilled[0].seq)
            .unwrap();
        let remaining = due(&store, 9).deliveries;
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].delivery, delivery(1));
    }

    #[test]
    fn spill_skips_seen_events_but_keeps_released_ones() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        mark_seen(&store, 1);
        mark_seen(&store, 2);
        let group = gid(1);
        store.put_group(&sample_group(group.clone(), 0, 2)).unwrap();
        store
            .lock()
            .unwrap()
            .execute_cached(
                "INSERT INTO cgka_released_transport_receipts(id, group_id, epoch) VALUES (?1, ?2, 0)",
                params![vec![2_u8; 32], group.as_slice()],
            )
            .unwrap();

        let outcome = store
            .spill_account_deliveries(&[delivery(1), delivery(2), delivery(3)], LIMITS, 9)
            .unwrap();
        assert_eq!(
            outcome,
            vec![
                DeliverySpillDisposition::AlreadySeen,
                DeliverySpillDisposition::Stored,
                DeliverySpillDisposition::Stored,
            ]
        );
    }

    #[test]
    fn spill_reports_full_at_limits_but_keeps_rows_it_already_holds() {
        use DeliverySpillDisposition::{Full, Stored};
        let store = SqliteAccountStorage::in_memory().unwrap();
        let outcome = store
            .spill_account_deliveries(
                &[delivery(1), delivery(1), delivery(2), delivery(3)],
                LIMITS,
                9,
            )
            .unwrap();
        assert_eq!(outcome, vec![Stored; 4]);
        // At the row cap, a copy of a held row is still stored; a new one is not.
        let outcome = store
            .spill_account_deliveries(&[delivery(3), delivery(4)], LIMITS, 9)
            .unwrap();
        assert_eq!(outcome, vec![Stored, Full]);
        assert_eq!(due(&store, 9).deliveries.len(), 3);

        let tight = DeliverySpillLimits {
            max_rows: u64::MAX,
            max_bytes: 0,
        };
        let empty = SqliteAccountStorage::in_memory().unwrap();
        assert_eq!(
            empty
                .spill_account_deliveries(&[delivery(5)], tight, 9)
                .unwrap(),
            vec![Full]
        );
    }

    fn loss_evidence(store: &SqliteAccountStorage) -> Vec<(i64, i64)> {
        store
            .lock()
            .unwrap()
            .prepare("SELECT cause, dropped_count FROM account_delivery_loss_evidence")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    #[test]
    fn undecodable_rows_are_reported_and_discarded_as_loss() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store.ensure_account_projection("alice").unwrap();
        store
            .spill_account_deliveries(&[delivery(1), delivery(2), delivery(3)], LIMITS, 9)
            .unwrap();
        store
            .lock()
            .unwrap()
            .execute_cached(
                "UPDATE account_delivery_spill SET metadata=x'00' WHERE event_id=?1",
                [vec![1_u8; 32]],
            )
            .unwrap();
        let first = store.spilled_account_deliveries(2, 9).unwrap();
        assert_eq!(first.undecodable.len(), 1);
        assert!(first.more, "a full read continues past the bad row");
        assert_eq!(first.deliveries.len(), 1);
        assert_eq!(first.deliveries[0].delivery, delivery(2));

        store
            .discard_spilled_account_deliveries(&first.undecodable, "alice", 77, 9)
            .unwrap();
        assert_eq!(
            loss_evidence(&store),
            vec![(RecoveryLossCause::Queue as i64, 1)]
        );
        assert_eq!(
            store
                .recovery_loss_goal_floor("alice", RecoveryLossCause::Queue)
                .unwrap(),
            None,
            "an undecodable row's time is unknown, so the loss is unbounded"
        );
        let rest: Vec<_> = due(&store, 9)
            .deliveries
            .iter()
            .map(|row| row.delivery.clone())
            .collect();
        assert_eq!(rest, vec![delivery(2), delivery(3)]);
    }

    #[test]
    fn discarded_rows_bound_the_loss_goal_by_their_created_at() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store.ensure_account_projection("alice").unwrap();
        store
            .spill_account_deliveries(&[delivery(5), delivery(3), delivery(9)], LIMITS, 9)
            .unwrap();
        let seqs: Vec<_> = due(&store, 9)
            .deliveries
            .iter()
            .filter(|row| row.delivery != delivery(9))
            .map(|row| row.seq)
            .collect();
        store
            .discard_spilled_account_deliveries(&seqs, "alice", 78, 9)
            .unwrap();
        assert_eq!(
            store
                .recovery_loss_goal_floor("alice", RecoveryLossCause::Queue)
                .unwrap(),
            Some(3),
            "the goal starts at the earliest removed delivery"
        );
    }

    #[test]
    fn deferred_rows_wait_with_doubling_delay_and_are_never_deleted_by_deferral() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store.ensure_account_projection("alice").unwrap();
        store
            .spill_account_deliveries(&[delivery(1)], LIMITS, 100)
            .unwrap();
        let seq = due(&store, 100).deliveries[0].seq;

        assert_eq!(
            store.defer_spilled_account_delivery(seq, 100).unwrap(),
            Some(SpilledDeliveryDeferral {
                attempts: 1,
                not_before: 160
            })
        );
        let waiting = due(&store, 159);
        assert!(waiting.deliveries.is_empty());
        assert_eq!(waiting.next_retry_at, Some(160));
        assert_eq!(due(&store, 160).deliveries.len(), 1);
        assert_eq!(
            store.defer_spilled_account_delivery(seq, 160).unwrap(),
            Some(SpilledDeliveryDeferral {
                attempts: 2,
                not_before: 280
            })
        );
        for _ in 0..10 {
            store.defer_spilled_account_delivery(seq, 1_000).unwrap();
        }
        let capped = due(&store, u64::MAX >> 2);
        assert_eq!(capped.deliveries.len(), 1, "deferral never deletes a row");
        assert_eq!(
            store.defer_spilled_account_delivery(seq, 5_000).unwrap(),
            Some(SpilledDeliveryDeferral {
                attempts: 13,
                not_before: 5_000 + 3_600
            })
        );

        assert!(
            store
                .discard_spilled_account_deliveries(&[seq], "unknown-account", 5, 5_000)
                .is_err(),
            "the loss record references a missing account"
        );
        assert_eq!(
            due(&store, u64::MAX >> 2).deliveries.len(),
            1,
            "a failed discard keeps the row"
        );
        store
            .discard_spilled_account_deliveries(&[seq], "alice", 5, 5_000)
            .unwrap();
        assert!(due(&store, u64::MAX >> 2).deliveries.is_empty());
        assert!(
            store
                .pending_recovery_demands()
                .unwrap()
                .iter()
                .any(|demand| demand.cause == crate::RecoveryCause::QueueLoss),
            "the loss is already an obligation when the row goes"
        );
        assert_eq!(
            loss_evidence(&store),
            vec![(RecoveryLossCause::Queue as i64, 1)]
        );
        assert_eq!(
            store.defer_spilled_account_delivery(seq, 6_000).unwrap(),
            None
        );
        store
            .discard_spilled_account_deliveries(&[seq], "alice", 6, 6_000)
            .unwrap();
        assert_eq!(
            loss_evidence(&store).len(),
            1,
            "discarding an absent row records no loss"
        );
    }
}
