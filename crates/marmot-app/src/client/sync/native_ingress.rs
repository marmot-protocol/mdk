//! Bounded admission of native replay, owned by the account recovery owner.
//!
//! The batch keeps each frame until ordinary ingest finishes. It contributes
//! neither comparison coverage nor loss acknowledgments; those remain with
//! the existing recovery grant and checkpoint machinery.

use cgka_traits::{GroupId, TransportEnvelope};
use transport_nostr_adapter::ReplayBatchTake;

use super::comparison_job::MAX_COMPARISON_ADMISSION_PER_TURN;
use crate::AppError;
use crate::client::AppClient;
use crate::client::delivery_spill::ACCOUNT_DELIVERY_SPILL_LIMITS;

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

    /// Process at most one ordinary admission turn, buffering its committed
    /// summary before an acknowledgement can suspend. Dropping this future
    /// returns its unacknowledged suffix in the original per-group order.
    pub(crate) async fn admit_native_turn(&mut self) -> Result<bool, AppError> {
        let mut progressed = false;
        let mut spent = 0;
        while spent < MAX_COMPARISON_ADMISSION_PER_TURN {
            if !matches!(self.take_native_batch(None).await, NativeFrontier::Ready) {
                break;
            }
            spent += usize::from(self.admit_native_frame().await?);
            progressed = true;
        }
        // The source returns this suffix behind independent ready groups;
        // its one-outstanding-batch rule still prevents same-group overtaking.
        self.recovery_owner.native_batch = None;
        Ok(progressed)
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
    pub(super) async fn admit_native_frame(&mut self) -> Result<bool, AppError> {
        let Some(mut batch) = self.recovery_owner.native_batch.take() else {
            return Ok(false);
        };
        let Some(delivery) = batch.delivery() else {
            return Ok(false);
        };
        let (summary, settled) = self.admit_recovered_delivery(delivery).await?;
        self.pending_applied_sync_summary.merge(summary);
        if let Some(seq) = self
            .recovery_owner
            .retained_spill
            .remove(&delivery.message.id)
        {
            let event_id = hex::encode(delivery.message.id.as_slice());
            self.settle_spill_row(seq, &event_id);
        }
        batch.acknowledge().await;
        if batch.delivery().is_some() {
            self.recovery_owner.native_batch = Some(batch);
        }
        Ok(matches!(settled, super::RecoveredDelivery::Ingested { .. }))
    }
}
