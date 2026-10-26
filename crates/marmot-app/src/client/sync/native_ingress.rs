//! Bounded admission of native replay, owned by the account recovery owner.
//!
//! The batch keeps each frame until ordinary ingest finishes. It contributes
//! neither comparison coverage nor loss acknowledgments; those remain with
//! the existing recovery grant and checkpoint machinery.

use cgka_traits::{GroupId, TransportEnvelope};
use transport_nostr_adapter::ReplayBatchTake;

use super::comparison_job::MAX_COMPARISON_ADMISSION_PER_TURN;
use crate::AppError;
use crate::client::delivery_spill::ACCOUNT_DELIVERY_SPILL_LIMITS;
use crate::client::{AppClient, AppPerformanceOperation};

pub(super) enum NativeFrontier {
    Ready,
    Pending,
    Empty,
}

pub(super) async fn wait_native_change(changes: &mut Option<tokio::sync::watch::Receiver<u64>>) {
    if let Some(changes) = changes
        && changes.changed().await.is_ok()
    {
        return;
    }
    std::future::pending::<()>().await;
}

impl AppClient {
    /// Register the ordered consumer before activation can release group replay.
    pub(super) async fn open_native_ingress(&mut self) -> Result<(), AppError> {
        if self
            .recovery_owner
            .native_ingress
            .as_ref()
            .is_some_and(|ingress| ingress.is_closed())
        {
            self.recovery_owner.native_batch = None;
            self.recovery_owner.native_ingress = None;
            self.recovery_owner.retained_spill.clear();
        }
        if self.recovery_owner.native_ingress.is_some() {
            return Ok(());
        }
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        // Include deferred rows: they are retained supplements, not a new retry
        // attempt, and must join the remote range before its oldest frame leaves.
        let batch = tokio::task::spawn_blocking(move || {
            storage.spilled_account_deliveries(
                ACCOUNT_DELIVERY_SPILL_LIMITS.max_rows as usize,
                i64::MAX as u64,
            )
        })
        .await
        .map_err(|error| AppError::BlockingTask(error.to_string()))??;
        if !batch.undecodable.is_empty() {
            self.discard_spilled_deliveries(&batch.undecodable)?;
        }
        let mut retained = Vec::new();
        let mut rows = std::collections::HashMap::new();
        for row in batch.deliveries {
            if matches!(
                row.delivery.message.envelope,
                TransportEnvelope::GroupMessage { .. }
            ) {
                rows.insert(row.delivery.message.id.clone(), row.seq);
                retained.push(row.delivery);
            }
        }
        let ingress = self.adapter.open_replay_ingress(retained).await?;
        self.recovery_owner.retained_spill = rows;
        self.exclude_retained_spill();
        self.recovery_owner.native_ingress = Some(ingress);
        Ok(())
    }

    /// Examine at most four frames (including receipt skips) per turn, buffering its committed
    /// summary before an acknowledgement can suspend. Dropping this future
    /// returns its unacknowledged suffix in the original per-group order.
    pub(crate) async fn admit_native_turn(&mut self) -> Result<bool, AppError> {
        let mut progressed = false;
        let mut inventory = super::InventoryBatch::default();
        for _ in 0..MAX_COMPARISON_ADMISSION_PER_TURN {
            if !matches!(self.take_native_batch(None).await, NativeFrontier::Ready) {
                break;
            }
            #[cfg(feature = "test-policy-overrides")]
            if self
                .app
                .config
                .dev_fail_sync_before_delivery
                .is_some_and(|limit| self.native_sync_deliveries >= limit)
            {
                let id = self
                    .recovery_owner
                    .native_batch
                    .as_ref()
                    .and_then(|batch| batch.delivery())
                    .map(|delivery| hex::encode(delivery.message.id.as_slice()))
                    .expect("the selected native batch is ready");
                if !self.transport_receipts()?.contains(&id) {
                    return Err(AppError::BlockingTask(
                        "injected catch-up delivery failure".to_owned(),
                    ));
                }
            }
            let (ingested, record) = self.admit_native_frame().await?;
            inventory.stage(self, record);
            self.native_sync_deliveries = self
                .native_sync_deliveries
                .saturating_add(u64::from(ingested));
            progressed = true;
        }
        inventory.flush(self);
        // The source returns this suffix behind independent ready groups;
        // its one-outstanding-batch rule still prevents same-group overtaking.
        self.recovery_owner.native_batch = None;
        if self.recovery_owner.native_cursor_target <= self.checkpointed_transport_timestamp {
            self.recovery_owner.native_cursor_target = None;
        }
        if self.recovery_owner.native_cursor_target.is_some() && !self.delivery_loss_blocks_cursor()
        {
            let observation = self.adapter.replay_admission().await;
            let drained = !observation.pending && !observation.spill_pending;
            let generation = observation.generation();
            drop(observation);
            if drained {
                self.synchronize_native_replay().await?;
                if !self.recovery_owner.native_replay_authorizes(generation) {
                    return Ok(progressed);
                }
                // Native-owned live tails do not pass through the ordinary
                // queue. Promote the fully acknowledged prefix, retaining the
                // save intent on error. Ordinary drain later settles its floor;
                // the existing large-promotion rule avoids per-message audit rows.
                let previous = self.checkpointed_transport_timestamp;
                let sealed = self.seal_transport_cursor();
                if let Err(error) =
                    self.save_state_with_pending_local_group_deletion_frontier_clears()
                {
                    self.abandon_transport_cursor(sealed);
                    return Err(error);
                }
                self.record_transport_cursor_advanced(
                    marmot_forensics::TransportCursorTrigger::LivePromotion,
                    &sealed,
                );
                if self.recovery_owner.native_cursor_target <= self.checkpointed_transport_timestamp
                {
                    self.recovery_owner.native_cursor_target = None;
                }
                progressed |= self.checkpointed_transport_timestamp != previous;
            }
        }
        Ok(progressed)
    }

    /// Receipt skips and cursor saves can advance a turn without receiving input.
    /// Actual ingests retain this follow-up intent even if ACK has to suspend.
    pub(crate) fn take_native_receive_need(&mut self) -> bool {
        std::mem::take(&mut self.recovery_owner.native_receive_pending)
    }

    /// Return a failed loan behind independent groups only after the worker
    /// has armed its admission backoff. Its source wake cannot bypass that
    /// deadline, and the next eligible turn can service another group first.
    pub(crate) fn yield_failed_native_turn(&mut self) {
        self.recovery_owner.native_batch = None;
    }

    /// Keep the selected lease on the existing owner. A group-specific lookup
    /// never mistakes an unfinished native range for an empty one.
    pub(super) async fn take_native_batch(&mut self, group: Option<&GroupId>) -> NativeFrontier {
        if self
            .recovery_owner
            .native_batch
            .as_ref()
            .is_some_and(|batch| {
                batch.delivery().is_some_and(|delivery| {
                    group.is_none_or(|group| delivery.group_id_hint.as_ref() == Some(group))
                })
            })
        {
            return NativeFrontier::Ready;
        }
        self.recovery_owner.native_batch = None;
        let taken = match self.recovery_owner.native_ingress.as_mut() {
            Some(ingress) => ingress.take_batch(group).await,
            None => ReplayBatchTake::Empty,
        };
        match taken {
            ReplayBatchTake::Ready(batch) => {
                self.recovery_owner.native_batch = Some(batch);
                NativeFrontier::Ready
            }
            ReplayBatchTake::Pending => NativeFrontier::Pending,
            ReplayBatchTake::Empty => NativeFrontier::Empty,
        }
    }

    /// Acknowledge one borrowed frame only after ordinary ingest and spill
    /// receipt settlement. The return value charges only actual ingests.
    pub(super) async fn admit_native_frame(
        &mut self,
    ) -> Result<(bool, Option<super::InventoryRecord>), AppError> {
        let Some(mut batch) = self.recovery_owner.native_batch.take() else {
            return Ok((false, None));
        };
        let Some(delivery) = batch.delivery() else {
            return Ok((false, None));
        };
        let timestamp = delivery.message.timestamp.0;
        let result = async {
            let started = std::time::Instant::now();
            let admitted = self
                .admit_recovered_delivery(delivery, super::InventoryWrite::NativeTurn)
                .await;
            if !matches!(&admitted, Ok((_, super::RecoveredDelivery::AlreadyHeld, _)))
                && let Some(telemetry) = &self.runtime_telemetry
            {
                telemetry.record(
                    AppPerformanceOperation::InboundDeliveryProjection,
                    started.elapsed(),
                    admitted.is_ok(),
                );
            }
            let (summary, settled, inventory_record) = admitted?;
            let ingested = matches!(settled, super::RecoveredDelivery::Ingested { .. });
            self.recovery_owner.native_receive_pending |= ingested;
            if self.pending_applied_sync_summary == crate::SyncSummary::default() {
                // Direct clients retain the full prefix across ACK waits. Move
                // its buffer back instead of recopying it for every frame.
                self.pending_applied_sync_summary = summary;
            } else {
                self.pending_applied_sync_summary.merge(summary);
            }
            if let Some(&seq) = self.recovery_owner.retained_spill.get(&delivery.message.id) {
                let event_id = hex::encode(delivery.message.id.as_slice());
                self.try_settle_spill_row(seq, &event_id)?;
                self.recovery_owner
                    .retained_spill
                    .remove(&delivery.message.id);
            }
            Ok((
                ingested,
                matches!(
                    settled,
                    super::RecoveredDelivery::AlreadyHeld
                        | super::RecoveredDelivery::Ingested {
                            unpersisted: false,
                            ..
                        }
                ),
                inventory_record,
            ))
        }
        .await;
        let (ingested, durable, inventory_record) = match result {
            Ok(settled) => settled,
            Err(error) => {
                // Explicit callers keep the failed frame pinned and observe
                // this error. The worker arms backoff before returning its
                // loan to the ingress's fair group rotation.
                self.recovery_owner.native_batch = Some(batch);
                return Err(error);
            }
        };
        batch.acknowledge().await;
        if durable {
            if !ingested {
                self.remember_transport_cursor(timestamp);
            }
            self.recovery_owner.native_cursor_target = self
                .recovery_owner
                .native_cursor_target
                .max(self.state.last_transport_timestamp);
        }
        if batch.delivery().is_some() {
            self.recovery_owner.native_batch = Some(batch);
        }
        Ok((ingested, inventory_record))
    }
}
