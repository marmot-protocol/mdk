//! Account-addressed recovery of halted copies. MLS authorization stays in the engine.

use super::*;
use cgka_traits::EpochState;
use cgka_traits::engine::CgkaEngine;
use cgka_traits::group_recovery::{
    AuthenticatedGroupRecovery, GroupMemberRecovery, GroupRecoveryBody, GroupRecoveryMessage,
    GroupRecoverySource,
};
use cgka_traits::storage::{
    GroupStorage, MaintenanceStorage, MessageStorage, OutboundFanoutStorage, StorageProvider,
};
use storage_sqlite::{
    GroupRecoveryPhase as Phase, GroupRecoveryRecord as Record, GroupRecoveryRole as Role,
};

const REQUEST_LIFETIME_SECS: u64 = 10 * 60;
const MAX_RECIPIENT_JOBS: usize = 64;
const MAX_RECOVERY_BATCH: usize = 16;
const RECOVERY_RETRY_SECS: [u64; 5] = [5, 15, 30, 60, 120];
const MAX_RECIPIENT_ATTEMPTS: u32 = 32;
const COMMIT_COOLDOWN_SECS: u64 = 600;

/// Automatic replacement-Welcome progress for this device's group copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupRejoinStatus {
    /// No automatic rejoin episode is active for this copy.
    Inactive,
    /// Automatic work is pending; reservations include cancelled lookups.
    Pending { attempts: u32 },
    /// Automatic work stopped until fresh evidence or an explicit user retry.
    Parked { attempts: u32 },
}

struct RecipientState {
    token: [u8; 32],
    epoch: EpochId,
    candidate_set_hash: [u8; 32],
    leaf_index: u32,
    device_key_hash: [u8; 32],
    coordinators: Vec<MemberId>,
}

impl<A, R, K> AccountDeviceRuntime<A, R, K>
where
    A: TransportAdapter,
    R: TransportRoutingPolicy,
    K: KeyPackagePublisher,
{
    /// Read durable automatic rejoin progress without scheduling network work.
    pub fn group_rejoin_status(&self, group_id: &GroupId) -> AccountResult<GroupRejoinStatus> {
        let group = self.session.group_record(group_id)?;
        if !group.unrecoverable || group.is_terminal() {
            return Ok(GroupRejoinStatus::Inactive);
        }
        let record = self
            .session
            .storage
            .list_group_recoveries()
            .map_err(SessionError::from)?
            .into_iter()
            .find(|record| record.role == Role::Recipient && &record.group_id == group_id);
        Ok(match record {
            Some(record) if record.phase == Phase::Parked => GroupRejoinStatus::Parked {
                attempts: record.total_attempts,
            },
            Some(record) => GroupRejoinStatus::Pending {
                attempts: record.total_attempts,
            },
            None => GroupRejoinStatus::Inactive,
        })
    }

    /// Explicit user retry starts a fresh bounded episode, owned by this runtime.
    /// It does not authorize replacing a usable copy or publishing any Commit.
    pub fn retry_group_rejoin(&mut self, group_id: &GroupId) -> AccountResult<GroupRejoinStatus> {
        if !self.session.ensure_group_hydrated(group_id)? {
            return Ok(GroupRejoinStatus::Inactive);
        }
        let now = self.wall_clock.now().0;
        let old = self
            .session
            .storage
            .list_group_recoveries()
            .map_err(SessionError::from)?;
        let live = old.iter().find(|record| {
            record.role == Role::Recipient
                && &record.group_id == group_id
                && record.expires_at > now
                && matches!(record.phase, Phase::Grant | Phase::AwaitWelcome)
        });
        let record = match live {
            Some(previous)
                if self
                    .recipient_recovery_state(group_id)?
                    .is_some_and(|state| Some(state.token) == previous.local_state_token) =>
            {
                // A live grant still authorizes its original coordinator. Retry
                // renews the budget without creating a second authorization.
                let mut record = previous.clone();
                record.total_attempts = 0;
                record.observed_epoch = None;
                record.remote_rearmed = false;
                record.attempts = 0;
                record.retry_at = now;
                record
            }
            _ => {
                let Some(record) = self.new_recipient_recovery(group_id, None, now)? else {
                    return Ok(GroupRejoinStatus::Inactive);
                };
                record
            }
        };
        if !old
            .iter()
            .any(|previous| previous.role == Role::Recipient && &previous.group_id == group_id)
            && old
                .iter()
                .filter(|previous| previous.role == Role::Recipient)
                .count()
                >= MAX_RECIPIENT_JOBS
        {
            return Err(SessionError::from(StorageError::Capacity(
                "group rejoin recipient journal is full".into(),
            ))
            .into());
        }
        self.session
            .storage
            .with_transaction(|storage| {
                for previous in &old {
                    if previous.role == Role::Recipient && &previous.group_id == group_id {
                        storage.delete_group_recovery(
                            group_id,
                            previous.role,
                            &previous.request_id,
                        )?;
                    }
                }
                storage.put_group_recovery(&record)
            })
            .map_err(SessionError::from)?;
        self.recovery_turn
            .retain(|record| record.role != Role::Recipient || &record.group_id != group_id);
        Ok(GroupRejoinStatus::Pending { attempts: 0 })
    }

    /// Reserve one bounded recovery turn before the host resolves inbox routes.
    /// Cancellation retains the durable retry deadline, never a reusable permit.
    pub fn prepare_group_recovery(&mut self) -> AccountResult<Vec<MemberId>> {
        self.recovery_turn.clear();
        if self.maintenance_paused {
            return Ok(Vec::new());
        }
        let now = self.wall_clock.now().0;
        let mut records = self
            .session
            .storage
            .list_group_recoveries()
            .map_err(SessionError::from)?;
        let evolutions = if records.iter().any(|record| {
            record.role == Role::Coordinator
                && matches!(record.phase, Phase::Grant | Phase::Publishing)
        }) {
            self.session
                .storage
                .list_group_evolutions()
                .map_err(SessionError::from)?
        } else {
            Vec::new()
        };
        let mut publications = HashMap::new();
        for evolution in &evolutions {
            if !matches!(
                evolution.phase,
                GroupEvolutionPhase::Prepared
                    | GroupEvolutionPhase::Attempting
                    | GroupEvolutionPhase::Confirmed
            ) {
                continue;
            }
            let GroupEvolutionSemantic::RecoverMembers {
                request_ids,
                source_authenticator_hash,
            } = &evolution.semantic
            else {
                continue;
            };
            let Some(commit_id) = &evolution.signed_message_id else {
                continue;
            };
            let fanout = self
                .session
                .storage
                .outbound_fanout(commit_id)
                .map_err(SessionError::from)?;
            if fanout.is_some_and(|fanout| fanout.mls_state() == FanoutMlsState::RolledBack) {
                continue;
            }
            let message = match self.session.storage.get_message(commit_id) {
                Ok(message) => message,
                Err(StorageError::NotFound) => continue,
                Err(error) => return Err(SessionError::from(error).into()),
            };
            if matches!(
                message.state,
                MessageState::ConvergenceDeferred | MessageState::EpochInvalidated
            ) {
                continue;
            }
            for request_id in request_ids {
                publications.insert(
                    (
                        evolution.group_id.as_slice(),
                        evolution.source_epoch,
                        source_authenticator_hash,
                        request_id,
                    ),
                    commit_id,
                );
            }
        }
        for record in &mut records {
            if record.role != Role::Coordinator
                || !matches!(record.phase, Phase::Grant | Phase::Publishing)
            {
                continue;
            }
            let GroupRecoveryBody::Grant { source, .. } = &record.message.body else {
                continue;
            };
            if let Some(&commit_id) = publications.get(&(
                record.group_id.as_slice(),
                source.epoch,
                &source.epoch_authenticator_hash,
                &record.request_id,
            )) && (record.commit_id.as_ref() != Some(commit_id)
                || record.phase != Phase::Publishing)
            {
                record.commit_id = Some(commit_id.clone());
                record.phase = Phase::Publishing;
                record.retry_at = now;
                self.session
                    .storage
                    .put_group_recovery(record)
                    .map_err(SessionError::from)?;
            }
        }
        for record in &records {
            if record.role == Role::Recipient {
                if !self.session.ensure_group_hydrated(&record.group_id)? {
                    continue;
                }
                let state = self.recipient_recovery_state(&record.group_id)?;
                if state.is_none() {
                    self.session
                        .storage
                        .delete_group_recovery(&record.group_id, record.role, &record.request_id)
                        .map_err(SessionError::from)?;
                } else if let Some(state) = state {
                    let hash = state.candidate_set_hash;
                    let evidence = record.candidate_set_hash != Some(hash)
                        || record.native_epoch.is_none_or(|epoch| state.epoch > epoch);
                    if evidence
                        || (record.phase != Phase::Parked
                            && (record.expires_at <= now
                                || Some(state.token) != record.local_state_token)
                            && record.total_attempts < MAX_RECIPIENT_ATTEMPTS)
                    {
                        if let Some(mut replacement) =
                            self.new_recipient_recovery(&record.group_id, Some(&record.peer), now)?
                        {
                            replacement.total_attempts =
                                if evidence { 0 } else { record.total_attempts };
                            replacement.native_epoch =
                                Some(record.native_epoch.unwrap_or(state.epoch).max(state.epoch));
                            // A new nonce can select a lower winning source.
                            // Keep its cost and spent refill, not the old claim.
                            replacement.observed_epoch = None;
                            replacement.remote_rearmed = !evidence && record.remote_rearmed;
                            self.session
                                .storage
                                .with_transaction(|storage| {
                                    storage.delete_group_recovery(
                                        &record.group_id,
                                        record.role,
                                        &record.request_id,
                                    )?;
                                    storage.put_group_recovery(&replacement)
                                })
                                .map_err(SessionError::from)?;
                        }
                    } else if record.phase != Phase::Parked
                        && record.total_attempts >= MAX_RECIPIENT_ATTEMPTS
                        && record.expires_at <= now
                    {
                        let mut parked = record.clone();
                        parked.phase = Phase::Parked;
                        self.session
                            .storage
                            .put_group_recovery(&parked)
                            .map_err(SessionError::from)?;
                    }
                }
            } else if record.expires_at.max(
                record
                    .commit_started_at
                    .map_or(0, |start| start.saturating_add(COMMIT_COOLDOWN_SECS)),
            ) <= now
                && record.phase != Phase::Publishing
            {
                self.session
                    .storage
                    .delete_group_recovery(&record.group_id, record.role, &record.request_id)
                    .map_err(SessionError::from)?;
            } else if record.phase == Phase::Complete && self.recovery_commit_withdrawn(record)? {
                let mut retry = record.clone();
                retry.phase = Phase::Publishing;
                retry.retry_at = now;
                self.session
                    .storage
                    .put_group_recovery(&retry)
                    .map_err(SessionError::from)?;
            }
        }
        records = self
            .session
            .storage
            .list_group_recoveries()
            .map_err(SessionError::from)?;
        let recipient_count = records
            .iter()
            .filter(|record| record.role == Role::Recipient)
            .count();
        if recipient_count < MAX_RECIPIENT_JOBS {
            for group_id in self.session.engine.unrecoverable_group_ids() {
                if records
                    .iter()
                    .any(|record| record.role == Role::Recipient && record.group_id == group_id)
                {
                    continue;
                }
                if !self.session.ensure_group_hydrated(&group_id)? {
                    continue;
                }
                if let Some(record) = self.new_recipient_recovery(&group_id, None, now)? {
                    self.session
                        .storage
                        .put_group_recovery(&record)
                        .map_err(SessionError::from)?;
                    records.push(record);
                    // Start one new recipient per turn; existing jobs retain priority.
                    break;
                }
            }
        }
        records.retain(|record| {
            record.phase != Phase::Complete
                && record.phase != Phase::Parked
                && (record.role != Role::Recipient
                    || record.total_attempts < MAX_RECIPIENT_ATTEMPTS)
                && record.retry_at <= now
                && (record.expires_at > now || record.phase == Phase::Publishing)
        });
        records.sort_by_key(|record| record.retry_at);
        let Some(first) = records.first() else {
            return Ok(Vec::new());
        };
        let group_id = first.group_id.clone();
        let batch_source = match (&first.role, &first.phase, &first.message.body) {
            (Role::Coordinator, Phase::Grant, GroupRecoveryBody::Grant { source, .. }) => {
                Some(source.clone())
            }
            _ => None,
        };
        let mut selected = Vec::new();
        let mut peers = Vec::new();
        for mut record in records {
            if !selected.is_empty() {
                let Some(source) = &batch_source else {
                    break;
                };
                if record.role != Role::Coordinator
                    || record.phase != Phase::Grant
                    || record.group_id != group_id
                    || !matches!(&record.message.body, GroupRecoveryBody::Grant { source: other, .. }
                        if other.epoch == source.epoch && other.epoch_authenticator_hash == source.epoch_authenticator_hash)
                {
                    continue;
                }
                if selected
                    .iter()
                    .any(|prior: &Record| prior.leaf_index == record.leaf_index)
                {
                    continue;
                }
            }
            record.attempts = record.attempts.saturating_add(1);
            if record.role == Role::Recipient {
                record.total_attempts = record.total_attempts.saturating_add(1);
            }
            let index = usize::try_from(record.attempts.saturating_sub(1))
                .unwrap_or(usize::MAX)
                .min(RECOVERY_RETRY_SECS.len() - 1);
            record.retry_at = now.saturating_add(RECOVERY_RETRY_SECS[index]);
            if !peers.contains(&record.peer) {
                peers.push(record.peer.clone());
            }
            selected.push(record);
            if selected.len() == MAX_RECOVERY_BATCH {
                break;
            }
        }
        self.session
            .storage
            .with_transaction(|storage| {
                for record in &selected {
                    storage.put_group_recovery(record)?;
                }
                Ok::<_, StorageError>(())
            })
            .map_err(SessionError::from)?;
        self.recovery_turn = selected;
        Ok(peers)
    }

    /// Advance only work reserved by `prepare_group_recovery` on this owner.
    /// Host-held device groups cannot change their tag key or announcement.
    /// Observe appended effects even when a later recovery step returns an error.
    pub async fn advance_group_recovery(
        &mut self,
        held: &[GroupId],
        output: &mut AccountDeviceEffects,
    ) -> AccountResult<()> {
        let reserved = std::mem::take(&mut self.recovery_turn);
        if self.maintenance_paused {
            return Ok(());
        }
        let restored = self.session.drain();
        if !restored.is_empty() {
            output.extend(self.publish_session_effects(restored).await?);
        }
        let mut ready = Vec::new();
        for record in reserved {
            let current = self
                .session
                .storage
                .group_recovery(&record.group_id, record.role, &record.request_id)
                .map_err(SessionError::from)?;
            if let Some(current) = current
                && current.message == record.message
                && current.phase == record.phase
            {
                ready.push(current);
            }
        }
        // A live Challenge or Grant can reopen before background hydration.
        if let Some(record) = ready.first()
            && record.role == Role::Coordinator
            && !self.session.ensure_group_hydrated(&record.group_id)?
        {
            return Ok(());
        }
        if ready
            .first()
            .is_some_and(|record| record.role == Role::Coordinator && record.phase == Phase::Grant)
        {
            output.extend(self.stage_recovery_batch(ready).await?);
            return Ok(());
        }
        for mut record in ready {
            if record.role == Role::Recipient {
                let state = self.recipient_recovery_state(&record.group_id)?;
                if state.is_none() {
                    self.session
                        .storage
                        .delete_group_recovery(&record.group_id, record.role, &record.request_id)
                        .map_err(SessionError::from)?;
                    continue;
                }
                if state.is_some_and(|state| Some(state.token) != record.local_state_token) {
                    // Maintenance replaces this stale nonce without discarding
                    // its episode budget; never publish an old-copy grant.
                    continue;
                }
                if record.phase == Phase::Challenge {
                    let GroupRecoveryBody::Challenge { source } = &record.message.body else {
                        return Err(EngineError::Backend(
                            "invalid durable recovery challenge".into(),
                        )
                        .into());
                    };
                    let source = source.clone();
                    output.extend(self.set_device_tag_key_holding(held).await?);
                    if !self.device_tag_key_settled()? {
                        continue;
                    }
                    if self.key_package_announcement_group().is_some() {
                        output.extend(self.announce_fresh_key_package_holding(held).await?);
                        if let Some(pending) = self
                            .session
                            .key_package_lifecycle()?
                            .and_then(|state| state.pending_replacement)
                            && !self.key_package_announced(&pending.key_package_ref)?
                        {
                            continue;
                        }
                    }
                    let mut key_package = self.publish_fresh_key_package().await?;
                    let event_id = self
                        .key_package_maintenance_status()?
                        .and_then(|state| state.authored_event_id)
                        .ok_or_else(|| {
                            EngineError::Backend(
                                "published recovery KeyPackage has no event provenance".into(),
                            )
                        })?;
                    // Direct grants bypass directory decoding, which normally
                    // attaches the event reference required by a NIP-59 Welcome.
                    key_package.source = Some(cgka_traits::KeyPackageSource { event_id });
                    record.message.body = GroupRecoveryBody::Grant {
                        source,
                        key_package,
                        device_signature: Vec::new(),
                    };
                    let signature = self.session.engine.sign_group_recovery(
                        &record.group_id,
                        &record.peer,
                        &record.message,
                    )?;
                    if let GroupRecoveryBody::Grant {
                        device_signature, ..
                    } = &mut record.message.body
                    {
                        *device_signature = signature;
                    }
                    record.phase = Phase::Grant;
                    record.outbound = None;
                    self.session
                        .storage
                        .put_group_recovery(&record)
                        .map_err(SessionError::from)?;
                }
            } else if record.phase == Phase::Publishing {
                if !self.recovery_commit_withdrawn(&record)? {
                    let restored = self.session.drain();
                    if !restored.is_empty() {
                        output.extend(self.publish_session_effects(restored).await?);
                    }
                    let (resumed, _) = self
                        .resume_outbound_fanouts_for_group(Some(&record.group_id))
                        .await?;
                    output.extend(resumed);
                }
                self.reconcile_recovery_commit(&mut record)?;
                self.session
                    .storage
                    .put_group_recovery(&record)
                    .map_err(SessionError::from)?;
                if record.phase != Phase::Challenge {
                    continue;
                }
            }
            if record.role == Role::Coordinator && record.phase == Phase::Challenge {
                let ready = self.refresh_recovery_challenge(&mut record)?;
                self.session
                    .storage
                    .put_group_recovery(&record)
                    .map_err(SessionError::from)?;
                if !ready {
                    continue;
                }
            }
            self.publish_recovery_control(&mut record).await?;
        }
        Ok(())
    }

    fn recipient_recovery_state(
        &self,
        group_id: &GroupId,
    ) -> AccountResult<Option<RecipientState>> {
        match self.session.engine.check_group_live(group_id) {
            Ok(()) => {}
            Err(EngineError::UnknownGroup(_) | EngineError::GroupNotHydrated(_)) => {
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        }
        let group = self
            .session
            .storage
            .get_group(group_id)
            .map_err(SessionError::from)?;
        if !group.unrecoverable
            || group.is_terminal()
            || group.protocol_profile != self.session.new_protocol_profile()
            || !matches!(
                self.session.epoch_state(group_id),
                Some(EpochState::Unrecoverable { .. })
            )
            || self.session.leave_in_progress(group_id)?
            || self.session.disbanding_in_progress(group_id)?
        {
            return Ok(None);
        }
        let context = self.session.engine.group_context(group_id)?;
        let secret = context
            .exporter_secret("marmot/group-event", 32)
            .ok_or_else(|| EngineError::Backend("recovery source exporter unavailable".into()))?;
        let token = Sha256::digest(secret.as_slice()).into();
        let leaf_index = self.session.own_leaf_index(group_id)?;
        let device_key_hash = self.session.engine.own_recovery_key_hash(group_id)?;
        let self_id = self.session.self_id();
        let mut coordinators = self
            .session
            .admin_pubkeys(group_id)?
            .into_iter()
            .map(|key| MemberId::new(key.to_vec()))
            .collect::<Vec<_>>();
        coordinators.sort_by(|left, right| left.as_slice().cmp(right.as_slice()));
        coordinators.dedup();
        // Hash the actual administrator set before appending the own-account
        // fallback, so gaining/losing our admin role is still fresh evidence.
        let candidate_set_hash = candidate_hash(&coordinators);
        if !coordinators.contains(&self_id) {
            coordinators.push(self_id.clone());
        }
        // Another account's admin is tried first; a healthy sibling device can
        // also coordinate through this account's own inbox.
        coordinators.sort_by(|left, right| {
            (left == &self_id)
                .cmp(&(right == &self_id))
                .then_with(|| left.as_slice().cmp(right.as_slice()))
        });
        coordinators.dedup();
        Ok(Some(RecipientState {
            token,
            epoch: group.epoch,
            candidate_set_hash,
            leaf_index,
            device_key_hash,
            coordinators,
        }))
    }

    fn new_recipient_recovery(
        &self,
        group_id: &GroupId,
        previous: Option<&MemberId>,
        now: u64,
    ) -> AccountResult<Option<Record>> {
        let Some(state) = self.recipient_recovery_state(group_id)? else {
            return Ok(None);
        };
        if state.coordinators.is_empty() {
            return Ok(None);
        }
        let next = previous
            .and_then(|peer| {
                state
                    .coordinators
                    .iter()
                    .position(|candidate| candidate == peer)
            })
            .map_or(0, |index| (index + 1) % state.coordinators.len());
        let peer = state.coordinators[next].clone();
        let request_id = rand::random();
        let expires_at = now.saturating_add(REQUEST_LIFETIME_SECS);
        let message = GroupRecoveryMessage {
            group_id: group_id.clone(),
            request_id,
            expires_at,
            body: GroupRecoveryBody::Request {
                device_key_hash: state.device_key_hash,
            },
        };
        Ok(Some(Record {
            group_id: group_id.clone(),
            request_id,
            role: Role::Recipient,
            peer,
            leaf_index: state.leaf_index,
            local_state_token: Some(state.token),
            expires_at,
            retry_at: now,
            attempts: 0,
            phase: Phase::Request,
            total_attempts: 0,
            candidate_set_hash: Some(state.candidate_set_hash),
            native_epoch: Some(state.epoch),
            observed_epoch: None,
            remote_rearmed: false,
            commit_started_at: None,
            message,
            outbound: None,
            commit_id: None,
        }))
    }

    pub(super) async fn ingest_group_recovery(
        &mut self,
        carrier: &TransportMessage,
        authenticated: &AuthenticatedGroupRecovery,
    ) -> AccountResult<bool> {
        if !matches!(&carrier.envelope, TransportEnvelope::Welcome { recipient }
            if recipient == &self.session.self_id())
        {
            return Ok(false);
        }
        let AuthenticatedGroupRecovery { sender, message } = authenticated;
        let now = self.wall_clock.now().0;
        if message.expires_at <= now
            || message.expires_at
                > now.saturating_add(REQUEST_LIFETIME_SECS + KEY_PACKAGE_MAX_FUTURE_SKEW_SECS)
        {
            return Ok(false);
        }
        match self.session.ensure_group_hydrated(&message.group_id) {
            Ok(true) => {}
            Ok(false)
            | Err(SessionError::Engine(
                EngineError::UnknownGroup(_) | EngineError::GroupNotHydrated(_),
            )) => {
                return Ok(false);
            }
            Err(error) => return Err(error.into()),
        }
        match &message.body {
            GroupRecoveryBody::Request { device_key_hash } => {
                self.receive_recovery_request(sender, message, device_key_hash, now)
            }
            GroupRecoveryBody::Challenge { source } => {
                self.receive_recovery_challenge(sender, message, source, now)
            }
            GroupRecoveryBody::Grant { source, .. } => {
                self.receive_recovery_grant(sender, message, source, now)
            }
        }
    }

    fn receive_recovery_request(
        &mut self,
        sender: &MemberId,
        message: &GroupRecoveryMessage,
        device_key_hash: &[u8; 32],
        now: u64,
    ) -> AccountResult<bool> {
        let old = self
            .session
            .storage
            .group_recovery(&message.group_id, Role::Coordinator, &message.request_id)
            .map_err(SessionError::from)?;
        if let Some(old) = old {
            return Ok(old.peer == *sender
                && old.expires_at == message.expires_at
                && matches!(&old.message.body, GroupRecoveryBody::Challenge { source } | GroupRecoveryBody::Grant { source, .. }
                    if source.device_key_hash == *device_key_hash));
        }
        let source = match self.session.engine.group_recovery_source(
            &message.group_id,
            sender,
            device_key_hash,
        ) {
            Ok(source) => source,
            Err(error) if recovery_expected_refusal(&error) => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        let leaf_index = source.leaf_index;
        if self
            .session
            .storage
            .list_group_recoveries()
            .map_err(SessionError::from)?
            .iter()
            .any(|record| {
                record.role == Role::Coordinator
                    && record.group_id == message.group_id
                    && ((record.peer == *sender
                        && record
                            .commit_started_at
                            .is_some_and(|start| start.saturating_add(COMMIT_COOLDOWN_SECS) > now))
                        || (record.leaf_index == leaf_index
                            && record.expires_at > now
                            && record.phase != Phase::Complete))
            })
        {
            return Ok(false);
        }
        let mut challenge = message.clone();
        challenge.body = GroupRecoveryBody::Challenge { source };
        let record = Record {
            group_id: message.group_id.clone(),
            request_id: message.request_id,
            role: Role::Coordinator,
            peer: sender.clone(),
            leaf_index,
            local_state_token: None,
            expires_at: message.expires_at,
            retry_at: now,
            attempts: 0,
            phase: Phase::Challenge,
            total_attempts: 0,
            candidate_set_hash: None,
            native_epoch: None,
            observed_epoch: None,
            remote_rearmed: false,
            commit_started_at: None,
            message: challenge,
            outbound: None,
            commit_id: None,
        };
        match self.session.storage.put_group_recovery(&record) {
            Ok(()) => Ok(true),
            Err(StorageError::Capacity(_)) => Ok(false),
            Err(error) => Err(SessionError::from(error).into()),
        }
    }

    fn receive_recovery_challenge(
        &mut self,
        sender: &MemberId,
        message: &GroupRecoveryMessage,
        source: &GroupRecoverySource,
        now: u64,
    ) -> AccountResult<bool> {
        let Some(mut record) = self
            .session
            .storage
            .group_recovery(&message.group_id, Role::Recipient, &message.request_id)
            .map_err(SessionError::from)?
        else {
            return Ok(false);
        };
        let Some(state) = self.recipient_recovery_state(&message.group_id)? else {
            return Ok(false);
        };
        if record.peer != *sender
            || record.expires_at != message.expires_at
            || Some(state.token) != record.local_state_token
            || state.device_key_hash != source.device_key_hash
            || record
                .observed_epoch
                .is_some_and(|epoch| source.epoch < epoch)
        {
            return Ok(false);
        }
        // The account inbox can fan out to several healthy devices. The first
        // challenge selects one native MLS signer for this request; only that
        // device may refresh the source after its group advances.
        if matches!(&record.message.body,
            GroupRecoveryBody::Challenge { source: old } | GroupRecoveryBody::Grant { source: old, .. }
                if old.coordinator_key_hash != source.coordinator_key_hash)
        {
            return Ok(false);
        }
        if matches!(&record.message.body,
            GroupRecoveryBody::Challenge { source: old } | GroupRecoveryBody::Grant { source: old, .. } if old == source)
        {
            return Ok(true);
        }
        let newer = record
            .observed_epoch
            .or(record.native_epoch)
            .is_some_and(|epoch| source.epoch > epoch);
        // An authenticated account can invent epochs. Permit one refill, not
        // an unlimited sequence of fresh packages from ever-higher claims.
        let rearm = newer && !record.remote_rearmed;
        if record.phase == Phase::Parked && !rearm {
            return Ok(false);
        }
        if rearm {
            record.total_attempts = 0;
            record.remote_rearmed = true;
        }
        record.observed_epoch = Some(source.epoch);
        record.leaf_index = source.leaf_index;
        record.phase = Phase::Challenge;
        record.message = message.clone();
        record.outbound = None;
        record.retry_at = now;
        record.attempts = 0;
        self.session
            .storage
            .put_group_recovery(&record)
            .map_err(SessionError::from)?;
        Ok(true)
    }

    fn receive_recovery_grant(
        &mut self,
        sender: &MemberId,
        message: &GroupRecoveryMessage,
        source: &GroupRecoverySource,
        now: u64,
    ) -> AccountResult<bool> {
        let Some(mut record) = self
            .session
            .storage
            .group_recovery(&message.group_id, Role::Coordinator, &message.request_id)
            .map_err(SessionError::from)?
        else {
            return Ok(false);
        };
        if record.peer != *sender
            || record.leaf_index != source.leaf_index
            || record.expires_at != message.expires_at
        {
            return Ok(false);
        }
        if matches!(
            record.phase,
            Phase::Grant | Phase::Publishing | Phase::Complete
        ) {
            return Ok(record.message == *message);
        }
        if !matches!(&record.message.body, GroupRecoveryBody::Challenge { source: old } if old == source)
        {
            return Ok(false);
        }
        let GroupRecoveryBody::Grant {
            key_package,
            device_signature,
            ..
        } = &message.body
        else {
            return Ok(false);
        };
        let recovery = GroupMemberRecovery {
            member: sender.clone(),
            source: source.clone(),
            key_package: key_package.clone(),
            request_id: message.request_id,
            expires_at: message.expires_at,
            device_signature: device_signature.clone(),
        };
        match self
            .session
            .engine
            .validate_member_recovery(&message.group_id, &recovery)
        {
            Ok(()) => {}
            Err(error) if recovery_expected_refusal(&error) => return Ok(false),
            Err(error) => return Err(error.into()),
        }
        // KeyPackage ownership and exact live source are checked again by the
        // engine immediately before staging; no inbound packet mutates MLS here.
        record.message = message.clone();
        record.phase = Phase::Grant;
        record.retry_at = now;
        record.attempts = 0;
        self.session
            .storage
            .put_group_recovery(&record)
            .map_err(SessionError::from)?;
        Ok(true)
    }

    async fn publish_recovery_control(&mut self, record: &mut Record) -> AccountResult<()> {
        if record.expires_at <= self.wall_clock.now().0 {
            return Ok(());
        }
        if record.outbound.is_none() {
            let wrapped = self
                .session
                .recovery_peeler
                .wrap_group_recovery(&record.message, &record.peer)
                .await
                .map_err(EngineError::Peeler)?;
            record.outbound = Some(wrapped);
            self.session
                .storage
                .put_group_recovery(record)
                .map_err(SessionError::from)?;
        }
        let message = record
            .outbound
            .as_ref()
            .expect("outbound recovery artifact is durable");
        let target = self.routing.publish_target(message)?;
        let request = TransportPublishRequest {
            account_id: self.session.self_id(),
            message: message.clone(),
            required_acks: self.routing.required_acks(&target),
            target,
        };
        request.validate_envelope_matches_target()?;
        let report = self.adapter.publish(request).await?;
        if report.met_required_acks()
            && record.role == Role::Recipient
            && record.phase == Phase::Grant
        {
            record.phase = Phase::AwaitWelcome;
            self.session
                .storage
                .put_group_recovery(record)
                .map_err(SessionError::from)?;
        }
        Ok(())
    }

    async fn stage_recovery_batch(
        &mut self,
        mut records: Vec<Record>,
    ) -> AccountResult<AccountDeviceEffects> {
        let mut output = AccountDeviceEffects::default();
        let now = self.wall_clock.now().0;
        let retained = self
            .session
            .storage
            .list_group_recoveries()
            .map_err(SessionError::from)?;
        // A batch admitted before any Commit reservation may include several
        // leaves of one account. Later arrivals cannot bypass that account's
        // cooldown, while every already-owned continuation remains resumable.
        records.retain(|record| {
            record.commit_started_at.is_some()
                || !retained.iter().any(|old| {
                    old.role == Role::Coordinator
                        && old.group_id == record.group_id
                        && old.peer == record.peer
                        && old.request_id != record.request_id
                        && old
                            .commit_started_at
                            .is_some_and(|start| start.saturating_add(COMMIT_COOLDOWN_SECS) > now)
                })
        });
        if records.is_empty() {
            return Ok(output);
        }
        let mut members = Vec::with_capacity(records.len());
        for record in &records {
            let GroupRecoveryBody::Grant {
                source,
                key_package,
                device_signature,
            } = &record.message.body
            else {
                return Err(EngineError::Backend("invalid durable recovery grant".into()).into());
            };
            if record.expires_at <= now {
                return Ok(output);
            }
            // The retained challenge already has the correct inbox envelope.
            if let Some(carrier) = &record.outbound {
                self.routing.publish_target(carrier)?;
            }
            members.push(GroupMemberRecovery {
                member: record.peer.clone(),
                source: source.clone(),
                key_package: key_package.clone(),
                request_id: record.request_id,
                expires_at: record.expires_at,
                device_signature: device_signature.clone(),
            });
        }
        let group_id = records[0].group_id.clone();
        for record in &mut records {
            record.commit_started_at.get_or_insert(now);
        }
        self.session
            .storage
            .with_transaction(|storage| {
                for record in &records {
                    storage.put_group_recovery(record)?;
                }
                Ok::<_, StorageError>(())
            })
            .map_err(SessionError::from)?;
        let staged = self
            .session
            .send(SendIntent::RecoverMembers { group_id, members })
            .await;
        let effects = match staged {
            Ok(effects) => effects,
            Err(error) if recovery_expected_refusal(error.as_engine_error()) => {
                for record in &mut records {
                    self.refresh_recovery_challenge(record)?;
                    self.session
                        .storage
                        .put_group_recovery(record)
                        .map_err(SessionError::from)?;
                }
                return Ok(output);
            }
            Err(error) => return Err(error.into()),
        };
        let Some((commit_id, pending)) = effects.publish.iter().find_map(|work| match work {
            PublishWork::GroupEvolution { msg, pending, .. } => Some((msg.id.clone(), *pending)),
            _ => None,
        }) else {
            return Err(
                EngineError::Backend("recovery did not stage a group evolution".into()).into(),
            );
        };
        for record in &mut records {
            record.commit_id = Some(commit_id.clone());
            record.phase = Phase::Publishing;
        }
        let saved = self.session.storage.with_transaction(|storage| {
            for record in &records {
                storage.put_group_recovery(record)?;
            }
            Ok::<_, StorageError>(())
        });
        if let Err(error) = saved {
            // No transport call has occurred. Roll back the staged MLS change.
            let rollback = self.session.publish_failed(pending).await?;
            self.publish_session_effects(rollback).await?;
            return Err(SessionError::from(error).into());
        }
        // Direct recovery sends bypass the prepared-send Welcome watcher.
        for work in &effects.publish {
            if let PublishWork::GroupEvolution { welcomes, .. } = work {
                self.watch_welcomes(welcomes.iter().map(|welcome| welcome.id.clone()));
            }
        }
        output.absorb_account_effects(self.publish_session_effects(effects).await?);
        for record in &mut records {
            self.reconcile_recovery_commit(record)?;
            self.session
                .storage
                .put_group_recovery(record)
                .map_err(SessionError::from)?;
        }
        Ok(output)
    }

    fn recovery_commit_withdrawn(&self, record: &Record) -> AccountResult<bool> {
        let Some(commit_id) = &record.commit_id else {
            return Ok(false);
        };
        match self.session.storage.get_message(commit_id) {
            Ok(message) => Ok(matches!(
                message.state,
                MessageState::ConvergenceDeferred | MessageState::EpochInvalidated
            )),
            Err(StorageError::NotFound) => Ok(false),
            Err(error) => Err(SessionError::from(error).into()),
        }
    }

    fn reconcile_recovery_commit(&mut self, record: &mut Record) -> AccountResult<()> {
        let Some(commit_id) = &record.commit_id else {
            return Err(EngineError::Backend("recovery publication has no commit".into()).into());
        };
        if self.recovery_commit_withdrawn(record)? {
            return self.refresh_recovery_challenge(record).map(|_| ());
        }
        let fanout = self
            .session
            .storage
            .outbound_fanout(commit_id)
            .map_err(SessionError::from)?;
        match fanout.as_ref().map(OutboundFanout::mls_state) {
            Some(FanoutMlsState::Pending(_)) => return Ok(()),
            Some(FanoutMlsState::Confirmed) => {
                record.phase = Phase::Complete;
                return Ok(());
            }
            Some(FanoutMlsState::RolledBack) => {
                return self.refresh_recovery_challenge(record).map(|_| ());
            }
            _ => {}
        }
        match self.session.storage.get_message(commit_id) {
            Ok(message) if message.state == MessageState::Processed => {
                record.phase = Phase::Complete;
                Ok(())
            }
            Ok(_) | Err(StorageError::NotFound) => {
                self.refresh_recovery_challenge(record).map(|_| ())
            }
            Err(error) => Err(SessionError::from(error).into()),
        }
    }

    fn refresh_recovery_challenge(&mut self, record: &mut Record) -> AccountResult<bool> {
        if record.expires_at <= self.wall_clock.now().0 {
            record.phase = Phase::Complete;
            record.commit_id = None;
            return Ok(false);
        }
        let old = match &record.message.body {
            GroupRecoveryBody::Challenge { source } | GroupRecoveryBody::Grant { source, .. } => {
                source
            }
            GroupRecoveryBody::Request { .. } => {
                return Err(
                    EngineError::Backend("coordinator has no recovery challenge".into()).into(),
                );
            }
        };
        let source = match self.session.engine.group_recovery_source(
            &record.group_id,
            &record.peer,
            &old.device_key_hash,
        ) {
            Ok(source) => source,
            Err(EngineError::GroupRecoveryUnsettled { .. }) => return Ok(false),
            Err(error) if recovery_expected_refusal(&error) => {
                record.phase = Phase::Complete;
                record.commit_id = None;
                return Ok(false);
            }
            Err(error) => return Err(error.into()),
        };
        if record.phase == Phase::Challenge && *old == source {
            return Ok(true);
        }
        record.leaf_index = source.leaf_index;
        record.message.body = GroupRecoveryBody::Challenge { source };
        record.phase = Phase::Challenge;
        record.commit_id = None;
        record.outbound = None;
        record.retry_at = record.retry_at.max(self.wall_clock.now().0);
        record.attempts = 0;
        Ok(true)
    }
}

fn candidate_hash(candidates: &[MemberId]) -> [u8; 32] {
    let mut hash = Sha256::new();
    for candidate in candidates {
        hash.update((candidate.as_slice().len() as u64).to_be_bytes());
        hash.update(candidate.as_slice());
    }
    hash.finalize().into()
}

fn recovery_expected_refusal(error: &EngineError) -> bool {
    matches!(
        error,
        EngineError::UnknownGroup(_)
            | EngineError::GroupNotHydrated(_)
            | EngineError::NotAMember { .. }
            | EngineError::NotGroupAdmin { .. }
            | EngineError::UnknownMember { .. }
            | EngineError::GroupUnrecoverableRepairRequired { .. }
            | EngineError::GroupRecoveryUnsettled { .. }
            | EngineError::GroupRecoverySourceMismatch { .. }
    )
}
