//! Explicit, unpublished replay from a retained anchor. Relay collection stays
//! with the host; this path consumes its completed history plus local inputs.

use std::{
    collections::{HashMap, HashSet},
    path::Path,
    time::{Duration, Instant},
};

use cgka_engine::openmls_projection::{OpenMlsContentKind, project_mls_message};
use cgka_traits::engine::CgkaEngine;
use cgka_traits::storage::{
    GroupStorage, MaintenanceStorage, MessageStorage, OutboundFanoutStorage, OutboundIntentStorage,
};
use cgka_traits::{
    EpochId, GroupEvent, GroupId, MessageId, MessageState, StoredMessagePayload, TransportMessage,
};
use storage_sqlite::{GroupRecoveryStore, SqlCipherKey, SqliteAccountStorage};

use crate::{AccountDeviceSession, SessionConfig, SessionError};

const RECOVERY_DEADLINE: Duration = Duration::from_secs(300);
const MAX_RECOVERY_EVENTS: usize = 100_000;
const MAX_RECOVERY_BYTES: usize = 512 * 1024 * 1024;

/// Aggregate evidence for explicit host approval. Epoch numbers alone are not
/// proof of branch agreement with another device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupRecoveryReport {
    pub original_epoch: u64,
    pub anchor_epoch: u64,
    pub recovered_epoch: u64,
    pub recovered_members: usize,
    pub authenticated_deliveries: usize,
    pub unresolved_transport: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum GroupRecoveryError {
    #[error(transparent)]
    Session(#[from] SessionError),
    #[error(transparent)]
    Storage(#[from] cgka_traits::StorageError),
    #[error(transparent)]
    Engine(#[from] cgka_traits::EngineError),
    #[error("group recovery has no usable retained anchor")]
    MissingAnchor,
    #[error("group recovery cannot replace terminal membership")]
    TerminalMembership,
    #[error("group recovery does not support pending publication or own commits")]
    UnsupportedPublication,
    #[error("group recovery input is invalid or exceeds its resource limit")]
    InvalidHistory,
    #[error("group recovery did not finish within its deadline")]
    Incomplete,
    #[error(
        "group recovery did not authenticate progress beyond the original or previously sent epoch"
    )]
    NoProgress,
}

/// Opaque, single-use candidate. Preparation never publishes transport work.
/// Dropping it cancels promotion; encrypted backup/candidate files remain for
/// explicit host cleanup. Hosts must not edit those files.
pub struct PreparedGroupRecovery {
    store: GroupRecoveryStore,
    report: GroupRecoveryReport,
}

impl PreparedGroupRecovery {
    pub fn report(&self) -> &GroupRecoveryReport {
        &self.report
    }

    /// Apply after explicit host approval, with the account quiesced. Any
    /// intervening account write rejects this candidate. Discard the old
    /// session and reopen after success to hydrate state and replay its outbox.
    pub fn apply_group_recovery(self) -> Result<GroupRecoveryReport, GroupRecoveryError> {
        self.store.apply_group_recovery()?;
        Ok(self.report)
    }
}

impl AccountDeviceSession {
    /// Replay completed relay history and retained inputs in an encrypted copy.
    ///
    /// Use the same identity, signer, peeler, features, profile and components
    /// as ordinary session open. The host supplies complete, unfloored history
    /// for this group's authenticated routes and must report relay truncation
    /// or incomplete endpoint coverage before invoking this operation.
    ///
    /// First-version limits: no own commits or pending publication, and the
    /// candidate must advance beyond the original tip and retained sends with authenticated app
    /// deliveries. This also prevents reusing the original tip's outbound
    /// application ratchet after a rewind. Missing old keys remain unrecoverable.
    /// Requires a Tokio runtime. Backup work is synchronous; invoke off the UI thread.
    /// Keep the source account quiesced from preparation through promotion.
    pub async fn prepare_group_recovery(
        mut config: SessionConfig,
        group: GroupId,
        history: Vec<TransportMessage>,
        directory: &Path,
    ) -> Result<PreparedGroupRecovery, GroupRecoveryError> {
        if history.len() > MAX_RECOVERY_EVENTS
            || history
                .iter()
                .try_fold(0usize, |n, m| n.checked_add(m.payload.len()))
                .is_none_or(|n| n > MAX_RECOVERY_BYTES)
        {
            return Err(GroupRecoveryError::InvalidHistory);
        }
        if !config.database_path.is_file() {
            return Err(GroupRecoveryError::InvalidHistory);
        }
        let source =
            SqliteAccountStorage::open_encrypted(&config.database_path, &config.database_key)?;
        let store = GroupRecoveryStore::prepare_group_recovery(
            source,
            group.clone(),
            directory,
            SqlCipherKey::new(config.database_key.as_secret_str().to_owned())?,
        )?;
        let source = store.candidate();
        let original = source.get_group(&group)?;
        if original.removed
            || original.disbanded.is_some()
            || !original
                .members
                .iter()
                .any(|m| m.id.as_slice() == config.identity)
        {
            return Err(GroupRecoveryError::TerminalMembership);
        }
        if !source.list_queued_outbound_intents(&group)?.is_empty()
            || !source.list_own_commit_intents(Some(&group))?.is_empty()
            || !source.list_outbound_fanouts_for_group(&group)?.is_empty()
            || source
                .list_group_evolutions_for_group(&group)?
                .iter()
                .any(|e| {
                    !matches!(
                        e.phase,
                        cgka_traits::GroupEvolutionPhase::Confirmed
                            | cgka_traits::GroupEvolutionPhase::SupersededByConvergence
                    )
                })
            || source
                .list_maintenance_obligations_for_group(&group)?
                .iter()
                .any(|o| {
                    matches!(
                        o.phase,
                        cgka_traits::MaintenancePhase::PendingPublication
                            | cgka_traits::MaintenancePhase::Fanout
                            | cgka_traits::MaintenancePhase::Retry
                    )
                })
        {
            return Err(GroupRecoveryError::UnsupportedPublication);
        }
        let (anchor_epoch, anchor) = source
            .list_group_snapshots(&group)?
            .into_iter()
            .filter_map(|name| {
                name.strip_prefix("openmls-retained-anchor-")
                    .and_then(|s| s.parse::<u64>().ok())
                    .map(|epoch| (epoch, name))
            })
            .filter(|(epoch, _)| *epoch <= original.epoch.0)
            .min_by_key(|(epoch, _)| *epoch)
            .ok_or(GroupRecoveryError::MissingAnchor)?;
        let mut consumed = Vec::new();
        let mut last_sent_epoch = original.epoch.0;
        let mut inputs = HashMap::new();
        let other_routes: HashSet<_> = source
            .list_transport_group_routes()?
            .into_iter()
            .filter(|r| r.group_id != group)
            .map(|r| r.transport_group_id)
            .collect();
        for message in history {
            add_input(&mut inputs, message)?;
        }
        for row in source.list_messages(&group, EpochId(0))? {
            let payload = StoredMessagePayload::decode(&row.payload)
                .map_err(|_| GroupRecoveryError::InvalidHistory)?;
            if payload.own_commit_stamp().is_some()
                || matches!(
                    payload,
                    StoredMessagePayload::OwnCommitWire { .. }
                        | StoredMessagePayload::StagedInviteWelcome { .. }
                )
            {
                return Err(GroupRecoveryError::UnsupportedPublication);
            }
            if row.state == MessageState::Sent {
                last_sent_epoch = last_sent_epoch.max(row.epoch.0);
            }
            if let Some(wire) = payload.as_openmls_wire() {
                let projection = project_mls_message(&wire.payload)
                    .map_err(|_| GroupRecoveryError::InvalidHistory)?;
                if payload.own_application_stamp().is_some() {
                    last_sent_epoch = last_sent_epoch.max(
                        projection
                            .source_epoch
                            .ok_or(GroupRecoveryError::InvalidHistory)?,
                    );
                }
                if projection.kind == OpenMlsContentKind::Application
                    && (payload.own_application_stamp().is_some()
                        || (row.state == MessageState::Processed
                            && projection.source_epoch.is_some_and(|e| e <= anchor_epoch)))
                {
                    consumed.push(row.id.clone());
                }
            }
            if let Some(message) = payload.as_exact_transport()
                && matches!(
                    message.envelope,
                    cgka_traits::TransportEnvelope::GroupMessage { .. }
                )
            {
                add_input(&mut inputs, message.clone())?;
            }
        }
        if inputs.len() > MAX_RECOVERY_EVENTS
            || inputs
                .values()
                .try_fold(0usize, |n, m| n.checked_add(m.payload.len()))
                .is_none_or(|n| n > MAX_RECOVERY_BYTES)
        {
            return Err(GroupRecoveryError::InvalidHistory);
        }
        let prior_outputs: HashSet<_> = source
            .list_pending_application_events()?
            .into_iter()
            .filter_map(|event| match event {
                GroupEvent::MessageReceived {
                    group_id,
                    message_id,
                    ..
                } if group_id == group => Some(message_id),
                _ => None,
            })
            .collect();
        store.rewind_group(&anchor, &consumed)?;
        config.database_path = directory.join("candidate.sqlite");
        config.defer_group_hydration = true;
        // Diagnostic sinks from the live session must not observe unpublished
        // candidate state. The report is the candidate's only external output.
        config.recorder = None;
        let mut candidate = Self::open(config)?;
        candidate.engine.ensure_hydrated(&group)?;
        let mut inputs: Vec<_> = inputs.into_values().collect();
        inputs.sort_by(|a, b| {
            (a.timestamp.0, a.id.as_slice()).cmp(&(b.timestamp.0, b.id.as_slice()))
        });
        let started = Instant::now();
        for message in inputs {
            if let cgka_traits::TransportEnvelope::GroupMessage { transport_group_id } =
                &message.envelope
                && other_routes.contains(transport_group_id)
            {
                return Err(GroupRecoveryError::InvalidHistory);
            }
            if started.elapsed() >= RECOVERY_DEADLINE {
                return Err(GroupRecoveryError::Incomplete);
            }
            candidate.engine.ingest(message).await?;
            candidate.engine.advance_convergence_inputs(&group).await?;
            reject_publication(&mut candidate)?;
            tokio::task::yield_now().await;
        }
        loop {
            if started.elapsed() >= RECOVERY_DEADLINE {
                return Err(GroupRecoveryError::Incomplete);
            }
            let settled = candidate.engine.advance_convergence_inputs(&group).await?;
            reject_publication(&mut candidate)?;
            let peel = candidate.engine.deferred_peel_cutoff_delay_ms(&group)?;
            let convergence =
                CgkaEngine::prepare_convergence_cutoff_delay_ms(&mut candidate.engine, &group)?;
            if settled
                && peel != Some(0)
                && convergence.is_none()
                && !candidate.engine.has_pending_convergence_inputs(&group)?
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(
                convergence.unwrap_or(10).clamp(1, 100),
            ))
            .await;
        }
        let recovered = store.candidate().get_group(&group)?;
        if recovered.removed || recovered.disbanded.is_some() {
            return Err(GroupRecoveryError::TerminalMembership);
        }
        let deliveries = store.candidate().list_pending_application_events()?.iter().filter(|event|matches!(event,
            GroupEvent::MessageReceived { group_id, message_id, .. } if group_id == &group && !prior_outputs.contains(message_id))).count();
        // A prior rollback can leave sent ciphertext above the current tip.
        // Never promote a rebuilt sender ratchet from any known used epoch.
        if recovered.epoch.0 <= last_sent_epoch || deliveries == 0 {
            return Err(GroupRecoveryError::NoProgress);
        }
        let unresolved = store
            .candidate()
            .list_deferred_message_metadata(&group)?
            .len();
        let report = GroupRecoveryReport {
            original_epoch: original.epoch.0,
            anchor_epoch,
            recovered_epoch: recovered.epoch.0,
            recovered_members: recovered.members.len(),
            authenticated_deliveries: deliveries,
            unresolved_transport: unresolved,
        };
        drop(candidate);
        Ok(PreparedGroupRecovery { store, report })
    }
}

fn add_input(
    inputs: &mut HashMap<MessageId, TransportMessage>,
    message: TransportMessage,
) -> Result<(), GroupRecoveryError> {
    if !matches!(
        message.envelope,
        cgka_traits::TransportEnvelope::GroupMessage { .. }
    ) {
        return Err(GroupRecoveryError::InvalidHistory);
    }
    if let Some(previous) = inputs.get(&message.id) {
        if previous.payload != message.payload
            || previous.envelope != message.envelope
            || previous.timestamp != message.timestamp
        {
            return Err(GroupRecoveryError::InvalidHistory);
        }
        return Ok(());
    }
    inputs.insert(message.id.clone(), message);
    Ok(())
}

fn reject_publication(candidate: &mut AccountDeviceSession) -> Result<(), GroupRecoveryError> {
    if !candidate.engine.drain_auto_publish().is_empty()
        || !candidate.engine.drain_auto_proposals().is_empty()
    {
        return Err(GroupRecoveryError::UnsupportedPublication);
    }
    candidate.engine.drain_events();
    Ok(())
}
