//! Account-worker side of the durable delivery spill.
//!
//! Ordinary spilled rows alternate with live deliveries. Retained group rows
//! belong to the recovery owner's ordered native ingress until admitted.
//! A row is removed only
//! once its event is in the seen index, the same test dedup uses, so a newer
//! live delivery can move the cursor past a spilled one without losing it.
//! Rows whose ingest left no durable trace are retried later with backoff.

use std::collections::VecDeque;

use cgka_traits::TransportDelivery;
use storage_sqlite::SpilledDelivery;

use super::AppClient;
use crate::AppError;
use crate::unix_now_seconds;
use transport_nostr::AccountDeliveryReceive;

/// Durable spill bounds for one account database.
pub(crate) const ACCOUNT_DELIVERY_SPILL_LIMITS: storage_sqlite::DeliverySpillLimits =
    storage_sqlite::DeliverySpillLimits {
        max_rows: 8_192,
        max_bytes: 16 * 1024 * 1024,
    };

/// The relay plane's view of what the store did with one spilled delivery.
pub(crate) fn plane_spill_disposition(
    disposition: storage_sqlite::DeliverySpillDisposition,
) -> transport_nostr::DeliverySpillDisposition {
    use storage_sqlite::DeliverySpillDisposition as Stored;
    use transport_nostr::DeliverySpillDisposition as Plane;
    match disposition {
        Stored::Stored => Plane::Stored,
        Stored::AlreadySeen => Plane::AlreadySeen,
        Stored::Full => Plane::Full,
    }
}

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
    pub(super) fn exclude_retained_spill(&mut self) {
        self.delivery_spill.buffered.retain(|row| {
            !self
                .recovery_owner
                .retained_spill
                .contains_key(&row.delivery.message.id)
        });
    }

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
                    Ok(storage.app_storage().spilled_account_deliveries(
                        if self.recovery_owner.retained_spill.is_empty() {
                            SPILL_READ_BATCH
                        } else {
                            ACCOUNT_DELIVERY_SPILL_LIMITS.max_rows as usize
                        },
                        unix_now_seconds(),
                    )?)
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
    fn absorb_spill_batch(&mut self, mut batch: storage_sqlite::SpilledDeliveryBatch) {
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
        self.delivery_spill.maybe_rows =
            batch.more && self.recovery_owner.retained_spill.is_empty();
        batch.deliveries.retain(|row| {
            !self
                .recovery_owner
                .retained_spill
                .contains_key(&row.delivery.message.id)
        });
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
        self.settle_spill_row(seq, &event_id);
    }

    pub(super) fn settle_spill_row(&mut self, seq: i64, event_id: &str) {
        if self.try_settle_spill_row(seq, event_id).is_err() {
            self.schedule_spill_retry(unix_now_seconds().saturating_add(SPILL_SETTLE_RETRY_SECS));
            tracing::warn!(
                target: "marmot_app::client::delivery_spill",
                method = "settle_spilled_delivery",
                error_kind = "spill_row_settlement_failed",
                "spilled delivery row kept after ingest; it will be read again",
            );
        }
    }

    /// Native ingress retains its loan and sequence mapping on settlement failure.
    pub(super) fn try_settle_spill_row(
        &mut self,
        seq: i64,
        event_id: &str,
    ) -> Result<(), AppError> {
        // An unreadable receipt view proves nothing either way. The row is
        // read again later without spending one of its attempts.
        let admitted = self
            .transport_receipts()
            .map(|receipts| receipts.contains(event_id));
        let now = unix_now_seconds();
        (|| -> Result<(), AppError> {
            let admitted = admitted?;
            let storage = self.app.account_storage(&self.state.label)?.app_storage();
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
        })()
    }

    fn schedule_spill_retry(&mut self, at: u64) {
        let next = self.delivery_spill.next_retry_at.get_or_insert(at);
        *next = (*next).min(at);
    }

    /// Remove rows and turn them into a queue-loss obligation in one
    /// transaction, then fence the cursor until recovery settles that loss.
    pub(super) fn discard_spilled_deliveries(&mut self, seqs: &[i64]) -> Result<(), AppError> {
        use rand::RngCore;
        #[cfg(test)]
        if std::mem::take(&mut self.delivery_spill.fail_next_discard) {
            return Err(AppError::BlockingTask(
                "injected spill discard failure".into(),
            ));
        }
        let storage = self.app.account_storage(&self.state.label)?;
        let token = rand::rngs::OsRng.next_u64() & i64::MAX as u64;
        storage.app_storage().discard_spilled_account_deliveries(
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

    use super::ACCOUNT_DELIVERY_SPILL_LIMITS;
    use super::SPILL_MAX_ATTEMPTS;
    use crate::tests::{ScriptedPushRelayClient, client_on_app_relay_plane};
    use crate::{MarmotApp, unix_now_seconds};
    use transport_nostr::MarmotRelayPlane;

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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
        let storage = app.account_storage("alice").unwrap().app_storage();
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn retained_spill_inbox_fair() {
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
        let storage = app.account_storage("alice").unwrap().app_storage();
        let now = unix_now_seconds();
        let mut rows = (1..=34).map(delivery).collect::<Vec<_>>();
        let mut inbox = delivery(35);
        inbox.message.envelope = TransportEnvelope::Welcome {
            recipient: MemberId::new(vec![0xAA; 32]),
        };
        rows.push(inbox.clone());
        storage
            .spill_account_deliveries(&rows, ACCOUNT_DELIVERY_SPILL_LIMITS, now)
            .unwrap();
        // A buffered prefix from an earlier ordinary read also belongs to
        // native ingress once it registers its retained supplements.
        client.absorb_spill_batch(storage.spilled_account_deliveries(32, now).unwrap());
        let stored = storage
            .spilled_account_deliveries(100, now)
            .unwrap()
            .deliveries;
        for row in stored.iter().take(34) {
            client
                .recovery_owner
                .retained_spill
                .insert(row.delivery.message.id.clone(), row.seq);
        }
        client.exclude_retained_spill();
        assert_eq!(client.next_spilled_delivery().unwrap(), Some(inbox));
        assert!(client.next_spilled_delivery().unwrap().is_none());
        assert_eq!(
            storage
                .spilled_account_deliveries(100, now)
                .unwrap()
                .deliveries
                .len(),
            35
        );

        // Native settlement uses precisely the ordinary durable-receipt test.
        client.remember_seen_event(hex::encode([1_u8; 32]));
        client.settle_spill_row(stored[0].seq, &hex::encode([1_u8; 32]));
        client.settle_spill_row(stored[1].seq, &hex::encode([2_u8; 32]));
        let due = storage.spilled_account_deliveries(100, now).unwrap();
        assert!(!due.deliveries.iter().any(|row| row.seq == stored[0].seq));
        assert!(!due.deliveries.iter().any(|row| row.seq == stored[1].seq));
        assert!(
            storage
                .spilled_account_deliveries(100, i64::MAX as u64)
                .unwrap()
                .deliveries
                .iter()
                .any(|row| row.seq == stored[1].seq)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
        let storage = app.account_storage("alice").unwrap().app_storage();
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
            .app_storage()
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
        let storage = app.account_storage("alice").unwrap().app_storage();
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
            .app_storage()
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
            Some(transport_nostr::AccountDeliveryReceive::Delivery(d)) if *d == delivery(5)
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
            .app_storage()
            .spill_account_deliveries(
                &[delivery(9)],
                ACCOUNT_DELIVERY_SPILL_LIMITS,
                unix_now_seconds(),
            )
            .unwrap();
        let seq = storage
            .app_storage()
            .spilled_account_deliveries(10, unix_now_seconds())
            .unwrap()
            .deliveries[0]
            .seq;
        let queue_loss = |storage: &storage_sqlite::SqliteAccountStorage| {
            storage
                .app_storage()
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
                .app_storage()
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
        let attempts = storage
            .app_storage()
            .recovery_retry_state()
            .unwrap()
            .attempt_serial;
        let _ = tokio::time::timeout(Duration::from_secs(2), client.next_event()).await;
        assert!(
            storage
                .app_storage()
                .recovery_retry_state()
                .unwrap()
                .attempt_serial
                > attempts,
            "next_event starts recovery for the new queue loss"
        );
    }
}
