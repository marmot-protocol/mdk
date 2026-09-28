//! Durable overflow tail for a full account delivery queue.
//!
//! The shared router must never wait on one account's slow consumer. When an
//! account queue is full, the router hands the delivery to that account's
//! spill instead of dropping it. It does the same with a delivery a restart
//! would no longer fetch only because a transport-cursor checkpoint was saving
//! when it arrived, or a live ingest promoted the cursor past it, which the
//! in-memory queue must never hold. One writer task per account stores
//! hand-offs in the account database; the account worker later admits
//! spilled rows through its ordinary ingest path. A delivery is lost, and
//! becomes a queue-loss generation, only when the hand-off or the durable
//! spill is full, or the store keeps failing.

use std::collections::VecDeque;
use std::sync::{Arc, Weak};
use std::time::Duration;

use cgka_traits::{MemberId, TransportDelivery};
use storage_sqlite::{DeliverySpillDisposition, DeliverySpillLimits};

use super::{
    AccountDeliveryOverflowState, AccountDeliveryRecoveryMarker,
    AccountDeliveryRecoveryMarkerError, RelayPlaneTransport, account_deliveries_read,
    enqueue_account_delivery_overflow_signal, omit_account_delivery, persist_retired_queue_loss,
};

pub(crate) type AccountDeliverySpillStore = Arc<
    dyn Fn(
            &[TransportDelivery],
        ) -> Result<Vec<DeliverySpillDisposition>, AccountDeliveryRecoveryMarkerError>
        + Send
        + Sync
        + 'static,
>;

/// Durable spill bounds for one account database.
pub(crate) const ACCOUNT_DELIVERY_SPILL_LIMITS: DeliverySpillLimits = DeliverySpillLimits {
    max_rows: 8_192,
    max_bytes: 16 * 1024 * 1024,
};
/// Bytes and deliveries the router may hand off before the writer catches
/// up. Each delivery is charged its payload plus a fixed allowance for the ID,
/// route and source metadata it retains, so empty payloads are still bounded.
const SPILL_HANDOFF_MAX_BYTES: usize = 4 * 1024 * 1024;
const SPILL_HANDOFF_MAX_DELIVERIES: usize = 4_096;
const SPILL_DELIVERY_OVERHEAD_BYTES: usize = 512;
const SPILL_WRITE_BATCH: usize = 128;
/// Retryable store failures are retried for about two seconds before the
/// batch falls back to loss; the cursor stays fenced meanwhile.
const SPILL_WRITE_RETRIES: u32 = 20;
const SPILL_WRITE_RETRY_DELAY: Duration = Duration::from_millis(100);

pub(super) struct AccountDeliverySpill {
    store: AccountDeliverySpillStore,
    handoff: std::sync::Mutex<Handoff>,
    account_id: MemberId,
    /// Loss recorded after an adapter replacement must reach the account's
    /// current route, not the one this writer started under.
    transport: Weak<RelayPlaneTransport>,
    /// Shared by every adapter of this account, including one registered
    /// after this writer's route was retired, so fences and wakeups survive
    /// replacement.
    overflow: Arc<AccountDeliveryOverflowState>,
    /// The route's durable loss marker, kept so loss recorded after the route
    /// is retired is still durable for the next session.
    marker: Option<AccountDeliveryRecoveryMarker>,
}

#[derive(Default)]
struct Handoff {
    items: VecDeque<TransportDelivery>,
    bytes: usize,
    writing: bool,
}

impl AccountDeliverySpill {
    pub(super) fn new(
        store: AccountDeliverySpillStore,
        account_id: MemberId,
        transport: Weak<RelayPlaneTransport>,
        overflow: Arc<AccountDeliveryOverflowState>,
        marker: Option<AccountDeliveryRecoveryMarker>,
    ) -> Arc<Self> {
        Arc::new(Self {
            store,
            handoff: std::sync::Mutex::new(Handoff::default()),
            account_id,
            transport,
            overflow,
            marker,
        })
    }

    /// Accept a delivery the router placed in the spill, without blocking
    /// it. Returns false when the hand-off itself is full. The placement
    /// already counted the delivery in the account's transport-cursor fence,
    /// and the writer releases that count when it settles the delivery.
    pub(super) fn offer(self: &Arc<Self>, delivery: TransportDelivery) -> bool {
        let size = retained_size(&delivery);
        let mut handoff = self.handoff.lock().unwrap_or_else(|p| p.into_inner());
        if handoff.items.len() >= SPILL_HANDOFF_MAX_DELIVERIES
            || handoff.bytes.saturating_add(size) > SPILL_HANDOFF_MAX_BYTES
        {
            return false;
        }
        handoff.bytes += size;
        handoff.items.push_back(delivery);
        if !handoff.writing {
            handoff.writing = true;
            tokio::spawn(self.clone().write());
        }
        true
    }

    async fn write(self: Arc<Self>) {
        loop {
            let batch: Vec<_> = {
                let mut handoff = self.handoff.lock().unwrap_or_else(|p| p.into_inner());
                if handoff.items.is_empty() {
                    handoff.writing = false;
                    return;
                }
                let take = handoff.items.len().min(SPILL_WRITE_BATCH);
                let batch: Vec<_> = handoff.items.drain(..take).collect();
                let bytes: usize = batch.iter().map(retained_size).sum();
                handoff.bytes = handoff.bytes.saturating_sub(bytes);
                batch
            };
            let count = batch.len() as u64;
            let created_at: Vec<u64> = batch.iter().map(|d| d.message.timestamp.0).collect();
            let dispositions = self.store_with_retry(batch).await;
            let stored = count_of(&dispositions, DeliverySpillDisposition::Stored);
            let seen = count_of(&dispositions, DeliverySpillDisposition::AlreadySeen);
            // Record loss before releasing the spill fence, so the cursor
            // stays fenced throughout. An empty result lost the whole batch.
            for (index, created_at) in created_at.into_iter().enumerate() {
                if dispositions
                    .get(index)
                    .is_none_or(|d| *d == DeliverySpillDisposition::Full)
                {
                    self.omit(Some(created_at));
                }
            }
            self.overflow.finish_spill(count, stored, seen);
            if stored > 0 {
                self.overflow.spill_ready.notify_one();
            }
        }
    }

    /// An empty result means the whole batch must fall back to loss.
    async fn store_with_retry(
        &self,
        batch: Vec<TransportDelivery>,
    ) -> Vec<DeliverySpillDisposition> {
        let batch = Arc::new(batch);
        for attempt in 0..=SPILL_WRITE_RETRIES {
            let store = self.store.clone();
            let items = batch.clone();
            match tokio::task::spawn_blocking(move || store(&items)).await {
                Ok(Ok(dispositions)) => return dispositions,
                Ok(Err(AccountDeliveryRecoveryMarkerError::Retryable))
                    if attempt < SPILL_WRITE_RETRIES =>
                {
                    tokio::time::sleep(SPILL_WRITE_RETRY_DELAY).await;
                }
                _ => break,
            }
        }
        tracing::warn!(
            target: "marmot_app::relay_plane",
            method = "store_with_retry",
            error_kind = "spill_write_failed",
            count = batch.len(),
            "account delivery spill write failed; omitting the batch into queue loss",
        );
        Vec::new()
    }

    fn current_route(&self) -> Option<super::AccountDeliveryRoute> {
        self.transport.upgrade().and_then(|transport| {
            account_deliveries_read(&transport.account_deliveries)
                .get(&self.account_id)
                .cloned()
        })
    }

    fn omit(&self, created_at: Option<u64>) {
        match self.current_route() {
            Some(route) => omit_account_delivery(&route, created_at),
            // The route was retired while this batch was in flight. The loss
            // still fences any replacement, which shares this overflow state,
            // and becomes durable through the retired route's marker. A
            // replacement that registers later is signalled when it reuses
            // the state; one that registered meanwhile is signalled here.
            None => {
                self.overflow.record_retired_drop(created_at);
                if let Some(marker) = self.marker.clone() {
                    persist_retired_queue_loss(&self.overflow, marker);
                }
                if let Some(route) = self.current_route()
                    && let Some(generation) = self.overflow.claim_retired_loss_signal()
                {
                    enqueue_account_delivery_overflow_signal(
                        &route.sender,
                        &self.overflow,
                        generation,
                    );
                }
            }
        }
    }
}

fn retained_size(delivery: &TransportDelivery) -> usize {
    delivery.message.payload.len() + SPILL_DELIVERY_OVERHEAD_BYTES
}

fn count_of(dispositions: &[DeliverySpillDisposition], wanted: DeliverySpillDisposition) -> u64 {
    dispositions.iter().filter(|d| **d == wanted).count() as u64
}
