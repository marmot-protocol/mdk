//! Bounded, one-time repair of advisory claims predating the release journal.
use crate::connection::{CachedSql, retry_on_busy};
use crate::storage::messages::{RELEASED_TRANSPORT_RECEIPT_CAPACITY, retire_transport_receipts};
use crate::transport_reconciliation::GROUP_ROUTE_KIND;
use crate::{
    SqliteAccountStorage, SqliteResultExt, TRANSPORT_RECONCILIATION_RETENTION_SECS,
    unix_now_seconds_i64,
};
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{OptionalExtension, named_params, params};

const BATCH_MAX: usize = 256;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TransportReceiptRepairProgress {
    /// Inventory entries inspected, including exclusions.
    pub examined: usize,
    /// IDs whose possession is uncertain, not proven releases.
    pub repaired: usize,
    pub has_more: bool,
}

impl SqliteAccountStorage {
    /// Run only after readiness and retained-route hydration, at the account's
    /// exclusive mutation boundary. Consume the release journal before and after
    /// this call, synchronously invalidating the active seen index before any
    /// checkpoint or redelivery. Claim deletion, backfill intent and cursor
    /// advancement deliberately share one commit: a crash cannot leave progress
    /// ahead of repair or allow a stale checkpoint to outlive the journal.
    /// Storage-only callers see retired claims and persisted backfill immediately;
    /// journal consumption intentionally repeats those idempotent writes to cover
    /// engine releases and intervening stale receipt checkpoints as well.
    /// Each account-device database has exactly one account_state owner/job.
    ///
    /// Keyset pages bound *examined* rows, rather than filtering uncertain rows
    /// before LIMIT (which could scan all accepted history). Fixed high waters
    /// cap the traversal; persisted cursors survive deletion and restart. No MLS,
    /// projection, retention floor or reconciliation cursor is modified.
    /// Nostr fanouts have always frozen an already-signed envelope; their
    /// message_id is the outer event ID. An indexed key probe excludes them
    /// without decoding records, including malformed ones. Normal own echoes
    /// retain outer-ID Sent rows and stay excluded after fanout settlement.
    /// Historical accepted wrappers without outer-ID evidence may be refetched;
    /// retained canonical records still deduplicate their content.
    pub fn repair_uncertain_transport_receipts(
        &self,
        limit: usize,
    ) -> StorageResult<TransportReceiptRepairProgress> {
        let limit = limit.clamp(1, BATCH_MAX);
        let repair = || {
            let conn = self.lock()?;
            let inbox = crate::TransportReconciliationRoute::Inbox;
            let (inbox_kind, inbox_route) = inbox.storage_key();
            let job = conn
                .query_row_cached(
                    "SELECT account_label, route_after, event_after, route_until, event_until
                     FROM app_historical_receipt_repair LIMIT 1",
                    [],
                    |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, Vec<u8>>(1)?,
                            r.get::<_, Vec<u8>>(2)?,
                            r.get::<_, Option<Vec<u8>>>(3)?,
                            r.get::<_, Option<Vec<u8>>>(4)?,
                        ))
                    },
                )
                .optional()
                .storage()?;
            let Some((label, mut route_after, mut event_after, route_until, event_until)) = job
            else {
                return Ok(TransportReceiptRepairProgress::default());
            };
            let (route_until, event_until) = if let Some(route_until) = route_until {
                (route_until, event_until.unwrap_or_default())
            } else {
                let (route_until, event_until) = conn.query_row_cached(
                    "SELECT route_id, event_id FROM transport_reconciliation_items WHERE route_kind = ?1
                     ORDER BY route_id DESC, event_id DESC LIMIT 1", [GROUP_ROUTE_KIND], |r| Ok((r.get::<_, Vec<u8>>(0)?,r.get::<_, Vec<u8>>(1)?)))
                    .optional().storage()?.unwrap_or_default();
                conn.execute_cached(
                    "UPDATE app_historical_receipt_repair SET route_until=?1, event_until=?2 WHERE account_label=?3",
                    params![route_until, event_until, label],
                ).storage()?;
                (route_until, event_until)
            };
            let mut progress = TransportReceiptRepairProgress {
                has_more: true,
                ..Default::default()
            };
            let rows = conn
                .prepare_cached(
                    "SELECT route_id, event_id, created_at FROM transport_reconciliation_items
                 WHERE route_kind = :group_kind
                   AND (route_id, event_id) > (:route_after, :event_after)
                   AND (route_id, event_id) <= (:route_until, :event_until)
                 ORDER BY route_id, event_id LIMIT :limit",
                )
                .storage()?
                .query_map(
                    named_params! {
                        ":group_kind": GROUP_ROUTE_KIND,
                        ":route_after": route_after,
                        ":event_after": event_after,
                        ":route_until": route_until,
                        ":event_until": event_until,
                        ":limit": limit as i64,
                    },
                    |r| {
                        Ok((
                            r.get::<_, Vec<u8>>(0)?,
                            r.get::<_, Vec<u8>>(1)?,
                            r.get::<_, i64>(2)?,
                        ))
                    },
                )
                .storage()?
                .collect::<Result<Vec<_>, _>>()
                .storage()?;
            let finished = rows.len() < limit;
            progress.examined += rows.len();
            let now = unix_now_seconds_i64();
            let retention_floor =
                now.saturating_sub(TRANSPORT_RECONCILIATION_RETENTION_SECS as i64);
            for (route, id, created_at) in rows {
                route_after = route;
                event_after = id;
                let candidate = conn.query_row_cached(
                    "SELECT g.id, g.epoch FROM cgka_transport_group_routes r
                     JOIN cgka_groups g ON g.id = r.group_id
                     WHERE r.transport_group_id = :route_id
                       AND :created_at >= MAX(:retention_floor, COALESCE((
                           SELECT inventory_since FROM transport_reconciliation_route_state
                           WHERE route_kind = :group_kind AND route_id = :route_id), 0))
                       AND NOT EXISTS(SELECT 1 FROM cgka_released_transport_receipts WHERE id = :event_id)
                       AND NOT EXISTS(SELECT 1 FROM cgka_messages WHERE id = :event_id)
                       AND NOT EXISTS(SELECT 1 FROM cgka_processed_transport_ids WHERE id = :event_id)
                       AND NOT EXISTS(SELECT 1 FROM cgka_ingress_dedup WHERE id = :event_id)
                       AND NOT EXISTS(SELECT 1 FROM cgka_outbound_fanout WHERE message_id = :event_id)
                       AND NOT EXISTS(SELECT 1 FROM cgka_welcomes WHERE message_id = :event_id)
                       AND NOT EXISTS(SELECT 1 FROM transport_reconciliation_items
                           WHERE route_kind = :inbox_kind AND route_id = :inbox_route AND event_id = :event_id)",
                    named_params! {
                        ":route_id": route_after,
                        ":event_id": event_after,
                        ":created_at": created_at,
                        ":retention_floor": retention_floor,
                        ":group_kind": GROUP_ROUTE_KIND,
                        ":inbox_kind": inbox_kind,
                        ":inbox_route": inbox_route,
                    },
                    |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, i64>(1)?)),
                ).optional().storage()?;
                let Some((group, epoch)) = candidate else {
                    continue;
                };
                // The deleted wrapper's epoch is unknowable. Arm recovery at
                // the current group epoch, the best available progress boundary.
                let inserted = conn
                    .execute_cached(
                        "INSERT INTO cgka_released_transport_receipts(id, group_id, epoch)
                     SELECT :event_id, :group_id, :epoch
                     WHERE (SELECT COUNT(*) FROM cgka_released_transport_receipts) < :capacity
                     ON CONFLICT(id) DO NOTHING",
                        named_params! {
                            ":event_id": event_after,
                            ":group_id": group,
                            ":epoch": epoch,
                            ":capacity": RELEASED_TRANSPORT_RECEIPT_CAPACITY,
                        },
                    )
                    .storage()?;
                if inserted == 0 {
                    // Do not advance past an ID that has no durable invalidation.
                    return Err(StorageError::Backend(
                        "released transport receipt journal is full".into(),
                    ));
                }
                retire_transport_receipts(
                    &conn,
                    &cgka_traits::MessageId::new(event_after.clone()),
                )?;
                conn.execute_cached("INSERT INTO app_epoch_backfill_intents(group_id,stalled_epoch,updated_at)
                    VALUES (?1,?2,?3) ON CONFLICT(group_id) DO UPDATE SET
                    stalled_epoch=MAX(app_epoch_backfill_intents.stalled_epoch,excluded.stalled_epoch),updated_at=excluded.updated_at",
                    params![group,epoch,now]).storage()?;
                progress.repaired += 1;
            }
            if finished || (route_after == route_until && event_after == event_until) {
                conn.execute_cached(
                    "DELETE FROM app_historical_receipt_repair WHERE account_label=?1",
                    [label],
                )
                .storage()?;
                progress.has_more = false;
            } else {
                conn.execute_cached("UPDATE app_historical_receipt_repair SET route_after=?1,event_after=?2 WHERE account_label=?3",
                    params![route_after,event_after,label]).storage()?;
            }
            Ok(progress)
        };
        if self.connection.is_current_thread_transaction_owner() {
            repair()
        } else {
            retry_on_busy(|| self.connection.with_transaction(repair))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn historical_claim_without_release_evidence_becomes_replayable() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        {
            let conn = store.lock().unwrap();
            conn.execute_batch(
                "INSERT INTO account_state(label, updated_at) VALUES ('alice', 0);
                INSERT INTO app_historical_receipt_repair(account_label) VALUES ('alice');
                INSERT INTO cgka_groups(id, epoch, record) VALUES (x'aa', 3, x'00');",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO cgka_transport_group_routes VALUES (?1, x'aa', 2)",
                [&[1_u8; 32][..]],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO transport_reconciliation_items VALUES (1, ?1, ?2, ?3)",
                rusqlite::params![
                    &[1_u8; 32][..],
                    &[2_u8; 32][..],
                    crate::unix_now_seconds_i64()
                ],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO seen_events VALUES (?1, 0)",
                [hex::encode([2_u8; 32])],
            )
            .unwrap();
        }
        assert!(
            store
                .consume_released_transport_receipts()
                .unwrap()
                .is_empty()
        );
        let progress = store.repair_uncertain_transport_receipts(1).unwrap();
        assert_eq!(
            progress.repaired, 1,
            "pre-journal claims need a bounded historical repair"
        );
        assert_eq!(
            store.consume_released_transport_receipts().unwrap(),
            vec![cgka_traits::MessageId::new(vec![2; 32])]
        );
        let conn = store.lock().unwrap();
        assert_eq!(
            conn.query_row("SELECT count(*) FROM seen_events", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            conn.query_row(
                "SELECT stalled_epoch FROM app_epoch_backfill_intents",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            3
        );
    }

    fn seed(store: &SqliteAccountStorage, count: u8) {
        let conn = store.lock().unwrap();
        conn.execute_batch(
            "INSERT INTO account_state(label,updated_at) VALUES ('alice',0);
            INSERT INTO app_historical_receipt_repair(account_label) VALUES ('alice');
            INSERT INTO cgka_groups(id,epoch,record) VALUES (x'aa',3,x'00');",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO cgka_transport_group_routes VALUES (?1,x'aa',2)",
            [&[1_u8; 32][..]],
        )
        .unwrap();
        for id in 1..=count {
            conn.execute(
                "INSERT INTO transport_reconciliation_items VALUES (1,?1,?2,?3)",
                params![&[1_u8; 32][..], &[id; 32][..], unix_now_seconds_i64()],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO seen_events VALUES (?1,0)",
                [hex::encode([id; 32])],
            )
            .unwrap();
        }
    }

    fn drain(store: &SqliteAccountStorage, limit: usize) -> usize {
        let mut repaired = 0;
        loop {
            let p = store.repair_uncertain_transport_receipts(limit).unwrap();
            assert!(p.examined <= limit);
            repaired += p.repaired;
            store.consume_released_transport_receipts().unwrap();
            if !p.has_more {
                return repaired;
            }
        }
    }

    #[test]
    fn repair_preserves_all_possession_evidence_welcomes_and_receipt_floors() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        seed(&store, 10);
        {
            let conn = store.lock().unwrap();
            // Processed input and an own echo with exact outer-ID Sent evidence.
            // The real settled-send outer-ID relationship is covered at app level.
            for (id, state) in [
                (
                    1_u8,
                    crate::message_state_to_i64(cgka_traits::MessageState::Processed),
                ),
                (
                    2,
                    crate::message_state_to_i64(cgka_traits::MessageState::Sent),
                ),
            ] {
                conn.execute(
                    "INSERT INTO cgka_messages(id,group_id,epoch,state,storage_format,payload)
                    VALUES (?1,x'aa',3,?2,2,x'00')",
                    params![&[id; 32][..], state],
                )
                .unwrap();
            }
            conn.execute(
                "INSERT INTO cgka_processed_transport_ids VALUES (?1,x'aa')",
                [&[3_u8; 32][..]],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO cgka_ingress_dedup(id) VALUES (?1)",
                [&[4_u8; 32][..]],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO cgka_welcomes VALUES (?1,x'aa',x'00')",
                [&[5_u8; 32][..]],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO transport_reconciliation_items VALUES (0,x'',?1,?2)",
                params![&[6_u8; 32][..], unix_now_seconds_i64()],
            )
            .unwrap();
            // Outside the retained window, and below a route's durable floor.
            conn.execute(
                "UPDATE transport_reconciliation_items SET created_at=0 WHERE event_id=?1",
                [&[7_u8; 32][..]],
            )
            .unwrap();
            conn.execute("INSERT INTO transport_reconciliation_route_state(route_kind,route_id,inventory_since,replay_after) VALUES (1,?1,?2,?3)", params![&[1_u8;32][..],unix_now_seconds_i64()-10,&[9_u8;32][..]]).unwrap();
            conn.execute(
                "UPDATE transport_reconciliation_items SET created_at=?1 WHERE event_id=?2",
                params![unix_now_seconds_i64() - 20, &[8_u8; 32][..]],
            )
            .unwrap();
        }
        // Authored time is not receipt/deletion time: even a modest future
        // clock skew can place a pre-journal wrapper past migration 0060's time.
        store
            .lock()
            .unwrap()
            .execute(
                "UPDATE transport_reconciliation_items SET created_at=?1 WHERE event_id=?2",
                params![unix_now_seconds_i64() + 60, &[10_u8; 32][..]],
            )
            .unwrap();
        assert_eq!(drain(&store, 2), 2);
        let conn = store.lock().unwrap();
        assert_eq!(
            conn.query_row("SELECT count(*) FROM seen_events", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            8
        );
        assert_eq!(
            conn.query_row("SELECT count(*) FROM cgka_messages", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            2
        );
        assert_eq!(
            conn.query_row(
                "SELECT replay_after FROM transport_reconciliation_route_state",
                [],
                |r| r.get::<_, Vec<u8>>(0)
            )
            .unwrap(),
            vec![9; 32]
        );
    }

    #[test]
    fn interrupted_batches_resume_and_failed_transaction_advances_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("account.db");
        let key = crate::SqlCipherKey::new("repair-test").unwrap();
        let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        seed(&store, 4);
        store
            .lock()
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER abort_repair BEFORE INSERT ON app_epoch_backfill_intents
            BEGIN SELECT RAISE(ABORT,'injected'); END;",
            )
            .unwrap();
        assert!(store.repair_uncertain_transport_receipts(1).is_err());
        {
            let conn = store.lock().unwrap();
            assert_eq!(
                conn.query_row("SELECT count(*) FROM seen_events", [], |r| r
                    .get::<_, i64>(0))
                    .unwrap(),
                4
            );
            assert_eq!(
                conn.query_row(
                    "SELECT count(*) FROM cgka_released_transport_receipts",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
                0
            );
            assert!(
                conn.query_row(
                    "SELECT route_until IS NULL FROM app_historical_receipt_repair",
                    [],
                    |r| r.get::<_, bool>(0)
                )
                .unwrap()
            );
            conn.execute_batch("DROP TRIGGER abort_repair").unwrap();
        }
        assert_eq!(
            store
                .repair_uncertain_transport_receipts(1)
                .unwrap()
                .repaired,
            1
        );
        store.close().unwrap();
        let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        assert_eq!(
            reopened
                .consume_released_transport_receipts()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(drain(&reopened, 1), 3);
        assert_eq!(
            reopened.repair_uncertain_transport_receipts(1).unwrap(),
            TransportReceiptRepairProgress::default()
        );
    }

    #[test]
    fn full_journal_repair_is_not_lock_contention_and_preserves_progress() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        seed(&store, 1);
        store
            .lock()
            .unwrap()
            .execute(
                "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x < ?1)
             INSERT INTO cgka_released_transport_receipts
             SELECT CAST(printf('%032x',x) AS BLOB),x'aa',3 FROM n",
                [RELEASED_TRANSPORT_RECEIPT_CAPACITY],
            )
            .unwrap();
        let error = store.repair_uncertain_transport_receipts(1).unwrap_err();
        assert!(
            matches!(error, StorageError::Backend(_)),
            "journal capacity is not retryable lock contention: {error:?}"
        );
        assert!(
            store
                .lock()
                .unwrap()
                .query_row(
                    "SELECT route_until IS NULL FROM app_historical_receipt_repair",
                    [],
                    |r| r.get::<_, bool>(0)
                )
                .unwrap()
        );
        store.consume_released_transport_receipts().unwrap();
        assert_eq!(
            store
                .repair_uncertain_transport_receipts(1)
                .unwrap()
                .repaired,
            1
        );
    }

    #[test]
    fn rotated_retained_routes_repair_but_deleted_routes_and_accounts_retire_work() {
        use cgka_traits::storage::GroupStorage;
        let store = SqliteAccountStorage::in_memory().unwrap();
        seed(&store, 2);
        {
            let conn = store.lock().unwrap();
            conn.execute(
                "INSERT INTO cgka_transport_group_routes VALUES (?1,x'aa',3)",
                [&[2_u8; 32][..]],
            )
            .unwrap();
            // Same released ID on two retained routes must not abort the batch.
            conn.execute(
                "INSERT INTO transport_reconciliation_items VALUES (1,?1,?2,?3)",
                params![&[2_u8; 32][..], &[1_u8; 32][..], unix_now_seconds_i64()],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO transport_reconciliation_items VALUES (1,?1,?2,?3)",
                params![&[3_u8; 32][..], &[3_u8; 32][..], unix_now_seconds_i64()],
            )
            .unwrap();
        }
        assert_eq!(
            store
                .repair_uncertain_transport_receipts(3)
                .unwrap()
                .repaired,
            2
        );
        store.delete_transport_group_route(&[2_u8; 32]).unwrap();
        store
            .delete_group(&cgka_traits::GroupId::new(vec![0xaa]))
            .unwrap();
        assert!(
            store
                .consume_released_transport_receipts()
                .unwrap()
                .is_empty()
        );
        assert_eq!(drain(&store, 1), 0);
        let conn = store.lock().unwrap();
        // An unretained route is never selected, even if an orphan claim remains.
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM transport_reconciliation_items",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
        conn.execute_batch("INSERT INTO app_historical_receipt_repair(account_label) VALUES ('alice'); DELETE FROM account_state;").unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM app_historical_receipt_repair",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
    }

    #[test]
    fn malformed_legacy_fanout_does_not_block_inventory_repair_after_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("account.db");
        let key = crate::SqlCipherKey::new("malformed-fanout-repair").unwrap();
        let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        seed(&store, 2);
        store.lock().unwrap().execute(
            "INSERT INTO cgka_outbound_fanout(message_id,group_id,record) VALUES (?1,x'aa',x'00')",
            [&[1_u8; 32][..]],
        ).unwrap();
        let first = store.repair_uncertain_transport_receipts(1).unwrap();
        assert_eq!(first.examined, 1);
        assert_eq!(first.repaired, 0);
        assert!(first.has_more);
        store.close().unwrap();
        let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        assert_eq!(drain(&reopened, 1), 1);
        let conn = reopened.lock().unwrap();
        // The undecodable row is preserved and still excludes its exact ID.
        assert_eq!(
            conn.query_row("SELECT record FROM cgka_outbound_fanout", [], |r| r
                .get::<_, Vec<u8>>(0))
                .unwrap(),
            vec![0]
        );
        assert_eq!(
            conn.query_row("SELECT count(*) FROM seen_events", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
}
