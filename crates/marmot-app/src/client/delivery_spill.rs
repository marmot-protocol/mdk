//! Account-worker side of the durable delivery spill.
//!
//! Spilled rows are read back in small batches and alternated with live
//! deliveries, so neither backlog starves the other. A row is removed only
//! once its event is in the seen index, the same test dedup uses, so a newer
//! live delivery can move the cursor past a spilled one without losing it.
//! Rows whose ingest left no durable trace are retried later with backoff.

use std::collections::VecDeque;

use cgka_traits::TransportDelivery;
use storage_sqlite::SpilledDelivery;

use super::AppClient;
use crate::AppError;
use crate::relay_plane::AccountDeliveryReceive;
use crate::unix_now_seconds;

const SPILL_READ_BATCH: usize = 32;
/// About three hours of doubling retries. A row still unadmitted after that
/// is removed and recorded as queue loss, so recovery keeps an obligation.
const SPILL_MAX_ATTEMPTS: u32 = 8;
/// Retry delay after a storage failure while reading or settling rows.
const SPILL_SETTLE_RETRY_SECS: u64 = 60;

pub(crate) struct DeliverySpillReader {
    buffered: VecDeque<SpilledDelivery>,
    /// Due rows may exist beyond `buffered`. Starts true, so rows left by an
    /// earlier process are admitted.
    maybe_rows: bool,
    /// Earliest retry time of a deferred row.
    next_retry_at: Option<u64>,
    live_turn: bool,
    /// Row whose delivery is with ingest, and that delivery's event ID.
    in_flight: Option<(i64, String)>,
    /// Rows just became queue loss; the next receive starts its recovery.
    loss_recorded: bool,
    #[cfg(test)]
    pub(super) fail_next_read: bool,
    #[cfg(test)]
    pub(super) fail_next_discard: bool,
}

impl Default for DeliverySpillReader {
    fn default() -> Self {
        Self {
            buffered: VecDeque::new(),
            maybe_rows: true,
            next_retry_at: None,
            live_turn: false,
            in_flight: None,
            loss_recorded: false,
            #[cfg(test)]
            fail_next_read: false,
            #[cfg(test)]
            fail_next_discard: false,
        }
    }
}

impl DeliverySpillReader {
    pub(super) fn pending(&mut self) -> bool {
        // A hand-off that was never settled, after an early error or a
        // cancelled ingest, left its row stored. Read it again.
        if self.in_flight.take().is_some() {
            self.maybe_rows = true;
        }
        if self
            .next_retry_at
            .is_some_and(|at| at <= unix_now_seconds())
        {
            self.next_retry_at = None;
            self.maybe_rows = true;
        }
        !self.buffered.is_empty() || self.maybe_rows
    }

    /// Whether spilled rows became queue loss since the last receive. Like a
    /// router overflow, that loss must start recovery even on a directly
    /// owned client with no worker to select it.
    pub(super) fn take_recorded_loss(&mut self) -> bool {
        std::mem::take(&mut self.loss_recorded)
    }

    pub(super) fn loss_recorded(&self) -> bool {
        self.loss_recorded
    }
}

impl AppClient {
    /// A delivery that is ready without waiting: while spilled rows remain,
    /// alternate a queued live delivery with the oldest spilled one.
    pub(super) fn take_ready_delivery(
        &mut self,
    ) -> Result<Option<AccountDeliveryReceive>, AppError> {
        if !self.delivery_spill.pending() {
            return Ok(None);
        }
        self.delivery_spill.live_turn = !self.delivery_spill.live_turn;
        if self.delivery_spill.live_turn
            && let Some(received) = self.adapter.try_receive_account_delivery()
        {
            return Ok(Some(received));
        }
        Ok(self
            .next_spilled_delivery()?
            .map(|delivery| AccountDeliveryReceive::Delivery(Box::new(delivery))))
    }

    fn next_spilled_delivery(&mut self) -> Result<Option<TransportDelivery>, AppError> {
        if self.delivery_spill.buffered.is_empty() && self.delivery_spill.maybe_rows {
            // Spilled rows are durable, so a failed read waits for a retry
            // instead of blocking live delivery.
            let read = self
                .app
                .account_storage(&self.state.label)
                .and_then(|storage| {
                    Ok(storage.spilled_account_deliveries(SPILL_READ_BATCH, unix_now_seconds())?)
                });
            #[cfg(test)]
            let read = if std::mem::take(&mut self.delivery_spill.fail_next_read) {
                Err(AppError::BlockingTask("injected spill read failure".into()))
            } else {
                read
            };
            match read {
                Ok(batch) => self.absorb_spill_batch(batch),
                Err(_) => {
                    self.delivery_spill.maybe_rows = false;
                    self.defer_spill_read("spill_read_failed");
                }
            }
        }
        Ok(self.delivery_spill.buffered.pop_front().map(|row| {
            let event_id = hex::encode(row.delivery.message.id.as_slice());
            self.delivery_spill.in_flight = Some((row.seq, event_id));
            row.delivery
        }))
    }

    /// Buffer one read. Undecodable rows become queue loss first. If that
    /// fails, the whole batch stays durable and is read again after a paced
    /// retry, so a quiet receive neither spins nor waits forever.
    fn absorb_spill_batch(&mut self, batch: storage_sqlite::SpilledDeliveryBatch) {
        if !batch.undecodable.is_empty() {
            if self.discard_spilled_deliveries(&batch.undecodable).is_err() {
                self.delivery_spill.maybe_rows = false;
                self.defer_spill_read("undecodable_spill_discard_failed");
                return;
            }
            tracing::warn!(
                target: "marmot_app::client::delivery_spill",
                method = "next_spilled_delivery",
                error_kind = "undecodable_spill_rows",
                discarded = batch.undecodable.len(),
                "discarded undecodable spilled deliveries as queue loss",
            );
        }
        self.delivery_spill.maybe_rows = batch.more;
        if let Some(at) = batch.next_retry_at {
            self.schedule_spill_retry(at);
        }
        self.delivery_spill.buffered.extend(batch.deliveries);
    }

    fn defer_spill_read(&mut self, error_kind: &'static str) {
        self.schedule_spill_retry(unix_now_seconds().saturating_add(SPILL_SETTLE_RETRY_SECS));
        tracing::warn!(
            target: "marmot_app::client::delivery_spill",
            method = "next_spilled_delivery",
            error_kind,
            "spilled deliveries kept for a later read",
        );
    }

    pub(super) fn note_spill_ready(&mut self) {
        self.delivery_spill.maybe_rows = true;
    }

    /// Settle the row handed to ingest or dedup. It is removed once its event
    /// is in the seen index; otherwise it stays for a later retry, and after
    /// its last retry it becomes queue loss. A failed settlement is retried.
    pub(super) fn settle_spilled_delivery(&mut self) {
        let Some((seq, event_id)) = self.delivery_spill.in_flight.take() else {
            return;
        };
        // An unreadable receipt view proves nothing either way. The row is
        // read again later without spending one of its attempts.
        let admitted = self
            .transport_receipts()
            .map(|receipts| receipts.contains(&event_id));
        let now = unix_now_seconds();
        let settled = (|| -> Result<(), AppError> {
            let admitted = admitted?;
            let storage = self.app.account_storage(&self.state.label)?;
            if admitted {
                storage.remove_spilled_account_delivery(seq)?;
                return Ok(());
            }
            let Some(deferral) = storage.defer_spilled_account_delivery(seq, now)? else {
                return Ok(());
            };
            if deferral.attempts < SPILL_MAX_ATTEMPTS {
                self.schedule_spill_retry(deferral.not_before);
                return Ok(());
            }
            self.discard_spilled_deliveries(&[seq])?;
            tracing::warn!(
                target: "marmot_app::client::delivery_spill",
                method = "settle_spilled_delivery",
                error_kind = "spill_row_unadmitted",
                "spilled delivery was never admitted; recorded as queue loss after its last retry",
            );
            Ok(())
        })();
        if settled.is_err() {
            self.schedule_spill_retry(now.saturating_add(SPILL_SETTLE_RETRY_SECS));
            tracing::warn!(
                target: "marmot_app::client::delivery_spill",
                method = "settle_spilled_delivery",
                error_kind = "spill_row_settlement_failed",
                "spilled delivery row kept after ingest; it will be read again",
            );
        }
    }

    fn schedule_spill_retry(&mut self, at: u64) {
        let next = self.delivery_spill.next_retry_at.get_or_insert(at);
        *next = (*next).min(at);
    }

    /// Remove rows and turn them into a queue-loss obligation in one
    /// transaction, then fence the cursor until recovery settles that loss.
    fn discard_spilled_deliveries(&mut self, seqs: &[i64]) -> Result<(), AppError> {
        use rand::RngCore;
        #[cfg(test)]
        if std::mem::take(&mut self.delivery_spill.fail_next_discard) {
            return Err(AppError::BlockingTask(
                "injected spill discard failure".into(),
            ));
        }
        let storage = self.app.account_storage(&self.state.label)?;
        let token = rand::rngs::OsRng.next_u64() & i64::MAX as u64;
        storage.discard_spilled_account_deliveries(
            seqs,
            &self.state.label,
            token,
            unix_now_seconds(),
        )?;
        self.delivery_overflow_recovery_pending = true;
        self.delivery_overflow_recovery_marker_token
            .get_or_insert(token);
        self.delivery_spill.loss_recorded = true;
        Ok(())
    }

    /// How long a receive wait may block before a deferred row is due.
    pub(super) fn spill_retry_wait(&self) -> Option<std::time::Duration> {
        self.delivery_spill
            .next_retry_at
            .map(|at| std::time::Duration::from_secs(at.saturating_sub(unix_now_seconds())))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use cgka_traits::transport::{Timestamp, TransportEnvelope, TransportMessage, TransportSource};
    use cgka_traits::{
        MemberId, MessageId, TransportDelivery, TransportDeliveryPlane, TransportDeliverySource,
    };
    use marmot_account::AccountHome;

    use super::SPILL_MAX_ATTEMPTS;
    use crate::relay_plane::{ACCOUNT_DELIVERY_SPILL_LIMITS, MarmotRelayPlane};
    use crate::tests::{ScriptedPushRelayClient, client_on_app_relay_plane};
    use crate::{MarmotApp, unix_now_seconds};

    fn delivery(id: u8) -> TransportDelivery {
        TransportDelivery {
            account_id: MemberId::new(vec![0xAA; 32]),
            group_id_hint: None,
            message: TransportMessage {
                id: MessageId::new(vec![id; 32]),
                payload: vec![id; 16],
                timestamp: Timestamp(1),
                causal_deps: Vec::new(),
                source: TransportSource("nostr".to_owned()),
                envelope: TransportEnvelope::GroupMessage {
                    transport_group_id: vec![0x42; 32],
                },
            },
            received_at: Timestamp(1),
            source: TransportDeliverySource {
                transport: TransportSource("nostr".to_owned()),
                plane: TransportDeliveryPlane::Group,
                endpoint: None,
                subscription_id: None,
                wire: None,
            },
        }
    }

    #[tokio::test]
    async fn spilled_row_stays_until_its_event_is_seen() {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let mut app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        app.relay_plane =
            MarmotRelayPlane::new_with_loopback(Some(Duration::from_secs(120)), relay, true);
        let mut client = client_on_app_relay_plane(&app, "alice").await;
        let storage = app.account_storage("alice").unwrap();
        let now = unix_now_seconds();
        storage
            .spill_account_deliveries(&[delivery(7)], ACCOUNT_DELIVERY_SPILL_LIMITS, now)
            .unwrap();

        // Ingest failed or kept no trace: the event never reached the seen
        // index, so the row stays and is deferred rather than deleted.
        client.delivery_spill.maybe_rows = true;
        assert_eq!(client.next_spilled_delivery().unwrap(), Some(delivery(7)));
        client.settle_spilled_delivery();
        assert!(
            storage
                .spilled_account_deliveries(10, now)
                .unwrap()
                .deliveries
                .is_empty(),
            "a deferred row is not due yet"
        );
        let kept = storage
            .spilled_account_deliveries(10, now + 24 * 60 * 60)
            .unwrap()
            .deliveries;
        assert_eq!(kept.len(), 1, "an unadmitted row is kept");

        assert!(
            client.spill_retry_wait().is_some(),
            "a receive wait wakes when the deferred row is due"
        );

        // Once the event is seen, settling removes the row.
        client.delivery_spill.in_flight = Some((kept[0].seq, hex::encode([7_u8; 32])));
        client.remember_seen_event(hex::encode([7_u8; 32]));
        client.settle_spilled_delivery();
        assert!(
            storage
                .spilled_account_deliveries(10, now + 24 * 60 * 60)
                .unwrap()
                .deliveries
                .is_empty()
        );
    }

    #[tokio::test]
    async fn unreadable_receipts_keep_the_row_without_spending_an_attempt() {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let mut app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        app.relay_plane =
            MarmotRelayPlane::new_with_loopback(Some(Duration::from_secs(120)), relay, true);
        let mut client = client_on_app_relay_plane(&app, "alice").await;
        let storage = app.account_storage("alice").unwrap();
        let now = unix_now_seconds();
        storage
            .spill_account_deliveries(&[delivery(3)], ACCOUNT_DELIVERY_SPILL_LIMITS, now)
            .unwrap();
        let seq = storage
            .spilled_account_deliveries(10, now)
            .unwrap()
            .deliveries[0]
            .seq;

        client.delivery_spill.in_flight = Some((seq, hex::encode([3_u8; 32])));
        client.released_backfill_reload_pending = true;
        client.fail_next_released_backfill_reload = true;
        client.settle_spilled_delivery();
        assert_eq!(
            storage
                .spilled_account_deliveries(10, now)
                .unwrap()
                .deliveries
                .len(),
            1,
            "the row stays due: no attempt was spent"
        );
        assert!(
            client.spill_retry_wait().is_some(),
            "the row is read again later"
        );
    }

    #[tokio::test]
    async fn a_failed_spill_read_waits_instead_of_blocking_live_delivery() {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let mut app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        app.relay_plane =
            MarmotRelayPlane::new_with_loopback(Some(Duration::from_secs(120)), relay, true);
        let mut client = client_on_app_relay_plane(&app, "alice").await;
        let storage = app.account_storage("alice").unwrap();
        storage
            .spill_account_deliveries(
                &[delivery(4)],
                ACCOUNT_DELIVERY_SPILL_LIMITS,
                unix_now_seconds(),
            )
            .unwrap();
        client.delivery_spill.maybe_rows = true;
        client.delivery_spill.fail_next_read = true;
        assert!(
            client.next_spilled_delivery().unwrap().is_none(),
            "a failed read is not a receive error"
        );
        assert!(
            !client.delivery_spill.pending(),
            "the live queue is served meanwhile"
        );
        assert!(
            client.spill_retry_wait().is_some(),
            "the read is retried later"
        );

        // Once the retry is due the row is read normally.
        client.delivery_spill.next_retry_at = Some(0);
        assert!(client.delivery_spill.pending());
        assert_eq!(client.next_spilled_delivery().unwrap(), Some(delivery(4)));
    }

    #[tokio::test]
    async fn a_failed_undecodable_discard_keeps_a_paced_retry() {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let mut app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        app.relay_plane =
            MarmotRelayPlane::new_with_loopback(Some(Duration::from_secs(120)), relay, true);
        let mut client = client_on_app_relay_plane(&app, "alice").await;
        let storage = app.account_storage("alice").unwrap();
        let now = unix_now_seconds();
        storage
            .spill_account_deliveries(&[delivery(6)], ACCOUNT_DELIVERY_SPILL_LIMITS, now)
            .unwrap();
        let seq = storage
            .spilled_account_deliveries(10, now)
            .unwrap()
            .deliveries[0]
            .seq;

        // The only row is undecodable and recording its loss fails.
        client.delivery_spill.fail_next_discard = true;
        client.absorb_spill_batch(storage_sqlite::SpilledDeliveryBatch {
            undecodable: vec![seq],
            ..Default::default()
        });
        assert!(
            !client.delivery_spill.pending(),
            "a failed discard does not re-read on every turn"
        );
        assert!(
            client.spill_retry_wait().is_some(),
            "a quiet receive still wakes for the retry"
        );
        assert_eq!(
            storage
                .spilled_account_deliveries(10, now)
                .unwrap()
                .deliveries
                .len(),
            1,
            "the row stays durable"
        );
    }

    #[tokio::test]
    async fn unsettled_hand_off_is_read_again() {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let mut app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        app.relay_plane =
            MarmotRelayPlane::new_with_loopback(Some(Duration::from_secs(120)), relay, true);
        let mut client = client_on_app_relay_plane(&app, "alice").await;
        let storage = app.account_storage("alice").unwrap();
        storage
            .spill_account_deliveries(
                &[delivery(5)],
                ACCOUNT_DELIVERY_SPILL_LIMITS,
                unix_now_seconds(),
            )
            .unwrap();
        client.delivery_spill.maybe_rows = true;
        assert_eq!(client.next_spilled_delivery().unwrap(), Some(delivery(5)));
        assert!(
            !client.delivery_spill.maybe_rows,
            "the batch held every row"
        );

        // The receive returned early or its ingest was cancelled, so the row
        // was never settled. The next receive must find it without new
        // relay traffic.
        let mut received = None;
        for _ in 0..2 {
            received = client.take_ready_delivery().unwrap();
            if received.is_some() {
                break;
            }
        }
        assert!(matches!(
            received,
            Some(crate::relay_plane::AccountDeliveryReceive::Delivery(d)) if *d == delivery(5)
        ));
    }

    #[tokio::test]
    async fn unadmitted_row_becomes_queue_loss_after_its_last_retry() {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let mut app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        app.relay_plane =
            MarmotRelayPlane::new_with_loopback(Some(Duration::from_secs(120)), relay, true);
        let mut client = client_on_app_relay_plane(&app, "alice").await;
        let storage = app.account_storage("alice").unwrap();
        storage
            .spill_account_deliveries(
                &[delivery(9)],
                ACCOUNT_DELIVERY_SPILL_LIMITS,
                unix_now_seconds(),
            )
            .unwrap();
        let seq = storage
            .spilled_account_deliveries(10, unix_now_seconds())
            .unwrap()
            .deliveries[0]
            .seq;
        let queue_loss = |storage: &storage_sqlite::SqliteAccountStorage| {
            storage
                .pending_recovery_demands()
                .unwrap()
                .iter()
                .any(|demand| demand.cause == storage_sqlite::RecoveryCause::QueueLoss)
        };
        assert!(!queue_loss(&storage));

        for attempt in 1..=SPILL_MAX_ATTEMPTS {
            client.delivery_spill.in_flight = Some((seq, hex::encode([9_u8; 32])));
            client.settle_spilled_delivery();
            let kept = !storage
                .spilled_account_deliveries(10, u64::MAX >> 2)
                .unwrap()
                .deliveries
                .is_empty();
            assert_eq!(kept, attempt < SPILL_MAX_ATTEMPTS, "attempt {attempt}");
        }
        assert!(
            queue_loss(&storage),
            "the discarded row leaves a recovery obligation"
        );
        assert!(
            client.delivery_overflow_recovery_pending,
            "the cursor stays fenced until recovery settles the loss"
        );
        // A directly owned client has no worker to select that loss. Its next
        // receive must start recovery without further relay traffic.
        let attempts = storage.recovery_retry_state().unwrap().attempt_serial;
        let _ = tokio::time::timeout(Duration::from_secs(2), client.next_event()).await;
        assert!(
            storage.recovery_retry_state().unwrap().attempt_serial > attempts,
            "next_event starts recovery for the new queue loss"
        );
    }
}
