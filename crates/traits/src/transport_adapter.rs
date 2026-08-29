//! Transport adapter boundary.
//!
//! A transport adapter owns network reachability and routing: account
//! activation, relay subscription state, publish quorum policy, and delivery
//! fanout. It must not decide CGKA convergence or inspect peeled MLS state.
//!
//! The engine receives [`crate::transport::TransportMessage`] values from this
//! boundary and remains the source of truth for commit ordering, branch
//! selection, and application-message validity.

use crate::engine_state::PendingStateRef;
use crate::transport::{Timestamp, TransportEnvelope, TransportMessage, TransportSource};
use crate::types::{GroupId, MemberId, MessageId};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Transport-specific endpoint label.
///
/// For Nostr this is a relay URL. Other transports may use a mesh peer id,
/// mailbox address, or service endpoint string.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TransportEndpoint(pub String);

impl TransportEndpoint {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for TransportEndpoint {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl From<String> for TransportEndpoint {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for TransportEndpoint {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl fmt::Display for TransportEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One group subscription from one local account's point of view.
///
/// `group_id` is the engine's MLS group id. `transport_group_id` is the
/// transport-visible routing id, such as a Nostr `h` tag. The 0.1 engine still
/// treats those as equal, but adapters should carry both so the later MIP-01
/// transport-data split has somewhere clean to land.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportGroupSubscription {
    pub group_id: GroupId,
    pub transport_group_id: Vec<u8>,
    pub endpoints: Vec<TransportEndpoint>,
}

/// Account-level subscription activation request.
///
/// This is deliberately signer-free. Concrete adapters obtain their signing /
/// decryption handles from the account-device layer that constructed them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportAccountActivation {
    pub account_id: MemberId,
    pub inbox_endpoints: Vec<TransportEndpoint>,
    pub group_subscriptions: Vec<TransportGroupSubscription>,
    pub since: Option<Timestamp>,
}

/// Group-only subscription refresh for an already-active account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportGroupSync {
    pub account_id: MemberId,
    pub group_subscriptions: Vec<TransportGroupSubscription>,
    pub since: Option<Timestamp>,
}

/// Publish target for an already-wrapped transport message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportPublishTarget {
    /// Publish a group message to the group's transport endpoint set.
    Group {
        group_id: GroupId,
        transport_group_id: Vec<u8>,
        endpoints: Vec<TransportEndpoint>,
    },
    /// Publish a welcome/giftwrap-style message to a recipient inbox.
    Inbox {
        recipient: MemberId,
        endpoints: Vec<TransportEndpoint>,
    },
}

impl TransportPublishTarget {
    pub fn endpoints(&self) -> &[TransportEndpoint] {
        match self {
            Self::Group { endpoints, .. } | Self::Inbox { endpoints, .. } => endpoints,
        }
    }

    fn kind_label(&self) -> &'static str {
        match self {
            Self::Group { .. } => "group",
            Self::Inbox { .. } => "inbox",
        }
    }
}

/// Publish request emitted by the application/coordinator after the peeler has
/// wrapped engine output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportPublishRequest {
    pub account_id: MemberId,
    pub message: TransportMessage,
    pub target: TransportPublishTarget,
    /// Minimum endpoint acknowledgements the adapter should try to obtain
    /// before reporting success. A value of `0` means best effort: the adapter
    /// does not wait for a specific ack count, but a publish that no endpoint
    /// accepted still fails — [`TransportPublishReport::met_required_acks`]
    /// always requires at least one acceptance.
    pub required_acks: usize,
}

impl TransportPublishRequest {
    /// Verify that the publish target matches the message's routing envelope.
    ///
    /// This catches coordinator bugs before an adapter sends a welcome to group
    /// endpoints or a group message to an inbox endpoint set.
    pub fn validate_envelope_matches_target(&self) -> Result<(), TransportAdapterError> {
        match (&self.message.envelope, &self.target) {
            (
                TransportEnvelope::GroupMessage {
                    transport_group_id: msg_group_id,
                },
                TransportPublishTarget::Group {
                    transport_group_id: target_group_id,
                    ..
                },
            ) if msg_group_id == target_group_id => Ok(()),
            (
                TransportEnvelope::Welcome {
                    recipient: msg_recipient,
                },
                TransportPublishTarget::Inbox {
                    recipient: target_recipient,
                    ..
                },
            ) if msg_recipient == target_recipient => Ok(()),
            _ => Err(TransportAdapterError::PublishTargetMismatch {
                envelope: envelope_label(&self.message.envelope).into(),
                target: self.target.kind_label().into(),
            }),
        }
    }
}

/// Durable state for one endpoint in a frozen publish fanout.
///
/// `Attempting` is written before the external send. A process that restarts
/// with an `Attempting` target treats it as outstanding and safely repeats the
/// same already-signed event bytes. Ambiguous and transient outcomes remain
/// outstanding so that exact event can be retried. Terminal callbacks are
/// idempotent: once a target is `Accepted` or `Failed`, later duplicate or
/// contradictory results do not change it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FanoutTargetStatus {
    NotAttempted,
    Attempting,
    Accepted,
    /// An explicit rejection or terminal no-exposure outcome.
    Failed,
    /// The endpoint may have exposed the event but did not acknowledge it.
    PossiblyExposed,
    /// The endpoint was transiently unavailable without a claim of exposure.
    RetryableUnavailable,
}

impl FanoutTargetStatus {
    pub fn is_outstanding(self) -> bool {
        matches!(
            self,
            Self::NotAttempted
                | Self::Attempting
                | Self::PossiblyExposed
                | Self::RetryableUnavailable
        )
    }

    pub fn is_terminal(self) -> bool {
        !self.is_outstanding()
    }
}

/// MLS half of a durable publish obligation.
///
/// Standalone application messages/proposals use `NotApplicable`. A group
/// evolution retains its opaque pending reference until the first endpoint
/// accepts, then transitions once to `Confirmed`; an all-failed first-attempt
/// fanout transitions once to `RolledBack`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state", content = "pending")]
pub enum FanoutMlsState {
    NotApplicable,
    Pending(PendingStateRef),
    Confirmed,
    RolledBack,
}

/// Engine pending lifecycle restored with a durable fanout after restart.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FanoutPendingKind {
    GroupEvolution,
    CreateGroup,
    Disband,
}

/// One durable transport fanout frozen before its first external side effect.
///
/// The request owns the exact serialized transport message and original target
/// set. `target_statuses` is positionally aligned with
/// `request.target.endpoints()`; construction is centralized in [`stage`] so a
/// valid record can never have a different status count.
///
/// [`stage`]: Self::stage
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundFanout {
    request: TransportPublishRequest,
    group_id: Option<GroupId>,
    #[serde(default)]
    pending_origin_message_id: Option<MessageId>,
    #[serde(default)]
    pending_kind: Option<FanoutPendingKind>,
    #[serde(default)]
    published_message_id: Option<MessageId>,
    target_statuses: Vec<FanoutTargetStatus>,
    #[serde(default)]
    target_failures: Vec<Option<TransportEndpointFailure>>,
    #[serde(default)]
    target_attempt_counts: Vec<u32>,
    #[serde(default)]
    target_last_attempt_at_ms: Vec<Option<u64>>,
    #[serde(default)]
    target_possible_exposure: Vec<bool>,
    /// Exact Welcome artifacts that must be released only after this fanout
    /// confirms its pending MLS transition.
    #[serde(default)]
    post_confirmation_welcomes: Vec<TransportMessage>,
    #[serde(default)]
    post_confirmation_welcomes_pending: bool,
    mls_state: FanoutMlsState,
    created_at_ms: u64,
}

impl OutboundFanout {
    pub fn stage(
        request: TransportPublishRequest,
        pending: Option<PendingStateRef>,
        pending_group_id: Option<GroupId>,
        created_at_ms: u64,
    ) -> Result<Self, TransportAdapterError> {
        let pending_origin_message_id = pending.map(|_| request.message.id.clone());
        let pending_kind = pending.map(|_| FanoutPendingKind::GroupEvolution);
        Self::stage_with_post_confirmation_welcomes(
            request,
            pending,
            pending_group_id,
            created_at_ms,
            pending_origin_message_id,
            pending_kind,
            Vec::new(),
        )
    }

    /// Freeze a publication and the Welcome artifacts released by its MLS
    /// confirmation in one durable record.
    pub fn stage_with_post_confirmation_welcomes(
        request: TransportPublishRequest,
        pending: Option<PendingStateRef>,
        pending_group_id: Option<GroupId>,
        created_at_ms: u64,
        pending_origin_message_id: Option<MessageId>,
        pending_kind: Option<FanoutPendingKind>,
        post_confirmation_welcomes: Vec<TransportMessage>,
    ) -> Result<Self, TransportAdapterError> {
        request.validate_envelope_matches_target()?;
        if pending.is_none() && !post_confirmation_welcomes.is_empty() {
            return Err(TransportAdapterError::Other(
                "post-confirmation Welcomes require pending MLS state".into(),
            ));
        }
        if pending.is_some() != pending_kind.is_some() {
            return Err(TransportAdapterError::Other(
                "pending MLS state and pending kind must be staged together".into(),
            ));
        }
        match (pending_kind, pending_origin_message_id.as_ref()) {
            (Some(FanoutPendingKind::GroupEvolution | FanoutPendingKind::Disband), None) => {
                return Err(TransportAdapterError::Other(
                    "group evolution fanout requires its stored origin commit".into(),
                ));
            }
            (Some(FanoutPendingKind::CreateGroup), Some(_)) => {
                return Err(TransportAdapterError::Other(
                    "legacy group creation has no published origin commit".into(),
                ));
            }
            (None, Some(_)) => {
                return Err(TransportAdapterError::Other(
                    "origin commit requires pending MLS state".into(),
                ));
            }
            _ => {}
        }
        if post_confirmation_welcomes
            .iter()
            .any(|message| !matches!(message.envelope, TransportEnvelope::Welcome { .. }))
        {
            return Err(TransportAdapterError::Other(
                "post-confirmation fanout continuation must contain only Welcomes".into(),
            ));
        }
        let target_group_id = match &request.target {
            TransportPublishTarget::Group { group_id, .. } => Some(group_id.clone()),
            TransportPublishTarget::Inbox { .. } => None,
        };
        if let (Some(target_group_id), Some(pending_group_id)) =
            (&target_group_id, &pending_group_id)
            && target_group_id != pending_group_id
        {
            return Err(TransportAdapterError::PublishTargetMismatch {
                envelope: "pending_group".into(),
                target: "group".into(),
            });
        }
        let target_count = request.target.endpoints().len();
        Ok(Self {
            request,
            group_id: target_group_id.or(pending_group_id),
            pending_origin_message_id,
            pending_kind,
            published_message_id: None,
            target_statuses: vec![FanoutTargetStatus::NotAttempted; target_count],
            target_failures: vec![None; target_count],
            target_attempt_counts: vec![0; target_count],
            target_last_attempt_at_ms: vec![None; target_count],
            target_possible_exposure: vec![false; target_count],
            post_confirmation_welcomes_pending: !post_confirmation_welcomes.is_empty(),
            post_confirmation_welcomes,
            mls_state: pending.map_or(FanoutMlsState::NotApplicable, FanoutMlsState::Pending),
            created_at_ms,
        })
    }

    pub fn request(&self) -> &TransportPublishRequest {
        &self.request
    }

    pub fn message_id(&self) -> &MessageId {
        &self.request.message.id
    }

    /// Transport-visible message id reported by the adapter.
    ///
    /// The frozen request remains keyed by the engine message id, while this
    /// value captures the deterministic signed-event id exposed to apps.
    pub fn published_message_id(&self) -> Option<&MessageId> {
        self.published_message_id.as_ref()
    }

    pub fn group_id(&self) -> Option<&GroupId> {
        self.group_id.as_ref()
    }

    /// Stored OpenMLS commit row used to restore this pending lifecycle.
    /// Legacy-profile creation has no published commit artifact and returns
    /// `None`; its durable Welcome plus pending-kind marker restore the edge.
    pub fn pending_origin_message_id(&self) -> Option<&MessageId> {
        self.pending_origin_message_id.as_ref().or_else(|| {
            // Compatibility for fanouts written before the explicit origin
            // field: those records could only represent group evolution, and
            // the frozen request id was the stored origin commit id.
            (self.pending_kind.is_none() && matches!(self.mls_state, FanoutMlsState::Pending(_)))
                .then_some(&self.request.message.id)
        })
    }

    pub fn pending_kind(&self) -> Option<FanoutPendingKind> {
        self.pending_kind.or_else(|| {
            matches!(self.mls_state, FanoutMlsState::Pending(_))
                .then_some(FanoutPendingKind::GroupEvolution)
        })
    }

    pub fn created_at_ms(&self) -> u64 {
        self.created_at_ms
    }

    pub fn target_statuses(&self) -> &[FanoutTargetStatus] {
        &self.target_statuses
    }

    pub fn target_status(&self, index: usize) -> Option<FanoutTargetStatus> {
        self.target_statuses.get(index).copied()
    }

    pub fn target_failure(&self, index: usize) -> Option<&TransportEndpointFailure> {
        self.target_failures.get(index).and_then(Option::as_ref)
    }

    pub fn target_attempt_count(&self, index: usize) -> u32 {
        self.target_attempt_counts.get(index).copied().unwrap_or(0)
    }

    pub fn target_last_attempt_at_ms(&self, index: usize) -> Option<u64> {
        self.target_last_attempt_at_ms.get(index).copied().flatten()
    }

    pub fn possible_exposure(&self) -> bool {
        self.target_possible_exposure.iter().any(|exposed| *exposed)
            || self
                .target_statuses
                .contains(&FanoutTargetStatus::PossiblyExposed)
    }

    pub fn pending_post_confirmation_welcomes(&self) -> &[TransportMessage] {
        if self.post_confirmation_welcomes_pending {
            &self.post_confirmation_welcomes
        } else {
            &[]
        }
    }

    pub fn mark_post_confirmation_welcomes_released(&mut self) -> bool {
        if !self.post_confirmation_welcomes_pending {
            return false;
        }
        self.post_confirmation_welcomes_pending = false;
        true
    }

    pub fn pending_ref(&self) -> Option<PendingStateRef> {
        match self.mls_state {
            FanoutMlsState::Pending(pending) => Some(pending),
            FanoutMlsState::NotApplicable
            | FanoutMlsState::Confirmed
            | FanoutMlsState::RolledBack => None,
        }
    }

    pub fn mls_state(&self) -> FanoutMlsState {
        self.mls_state
    }

    pub fn outstanding_target_indexes(&self) -> Vec<usize> {
        self.target_statuses
            .iter()
            .enumerate()
            .filter_map(|(index, status)| status.is_outstanding().then_some(index))
            .collect()
    }

    /// Persist the send-before-side-effect edge for one target.
    ///
    /// Returns `true` when an outstanding target begins or resumes an attempt.
    /// Re-marking an `Attempting` target after restart is safe and increments
    /// the durable attempt counter; terminal targets remain unchanged.
    pub fn mark_attempt_started(&mut self, index: usize) -> Result<bool, TransportAdapterError> {
        self.mark_attempt_started_at(index, self.created_at_ms)
    }

    pub fn mark_attempt_started_at(
        &mut self,
        index: usize,
        attempted_at_ms: u64,
    ) -> Result<bool, TransportAdapterError> {
        self.ensure_target_metadata_len();
        match self.target_status(index).ok_or_else(|| {
            TransportAdapterError::Other("fanout target index is out of bounds".into())
        })? {
            FanoutTargetStatus::NotAttempted
            | FanoutTargetStatus::Attempting
            | FanoutTargetStatus::PossiblyExposed
            | FanoutTargetStatus::RetryableUnavailable => {
                self.target_statuses[index] = FanoutTargetStatus::Attempting;
                self.target_attempt_counts[index] =
                    self.target_attempt_counts[index].saturating_add(1);
                self.target_last_attempt_at_ms[index] = Some(attempted_at_ms);
                self.target_failures[index] = None;
                Ok(true)
            }
            FanoutTargetStatus::Accepted | FanoutTargetStatus::Failed => Ok(false),
        }
    }

    pub fn mark_target_accepted(&mut self, index: usize) -> Result<bool, TransportAdapterError> {
        self.mark_target_terminal(index, FanoutTargetStatus::Accepted)
    }

    pub fn mark_target_failed(&mut self, index: usize) -> Result<bool, TransportAdapterError> {
        self.mark_target_terminal(index, FanoutTargetStatus::Failed)
    }

    pub fn record_target_failure(
        &mut self,
        index: usize,
        failure: TransportEndpointFailure,
    ) -> Result<bool, TransportAdapterError> {
        if self.request.target.endpoints().get(index) != Some(&failure.endpoint) {
            return Err(TransportAdapterError::Other(
                "endpoint failure does not match frozen fanout target".into(),
            ));
        }
        self.ensure_target_metadata_len();
        let current = self.target_status(index).ok_or_else(|| {
            TransportAdapterError::Other("fanout target index is out of bounds".into())
        })?;
        if current.is_terminal() {
            return Ok(false);
        }
        if failure.kind == TransportEndpointFailureKind::PossiblyExposed {
            self.target_possible_exposure[index] = true;
        }
        let next = if self.target_possible_exposure[index] {
            FanoutTargetStatus::PossiblyExposed
        } else {
            match failure.kind {
                TransportEndpointFailureKind::TerminalRejected
                | TransportEndpointFailureKind::NotExposed => FanoutTargetStatus::Failed,
                TransportEndpointFailureKind::PossiblyExposed => {
                    FanoutTargetStatus::PossiblyExposed
                }
                TransportEndpointFailureKind::RetryableUnavailable => {
                    FanoutTargetStatus::RetryableUnavailable
                }
            }
        };
        self.target_statuses[index] = next;
        self.target_failures[index] = Some(failure);
        Ok(true)
    }

    pub fn record_published_message_id(
        &mut self,
        message_id: MessageId,
    ) -> Result<bool, TransportAdapterError> {
        match &self.published_message_id {
            None => {
                self.published_message_id = Some(message_id);
                Ok(true)
            }
            Some(previous) if previous == &message_id => Ok(false),
            Some(_) => Err(TransportAdapterError::Other(
                "adapter changed the transport-visible id for a frozen fanout".into(),
            )),
        }
    }

    pub fn mark_mls_confirmed(&mut self) -> Result<bool, TransportAdapterError> {
        match self.mls_state {
            FanoutMlsState::Pending(_) => {
                self.mls_state = FanoutMlsState::Confirmed;
                Ok(true)
            }
            FanoutMlsState::Confirmed => Ok(false),
            FanoutMlsState::NotApplicable | FanoutMlsState::RolledBack => Err(
                TransportAdapterError::Other("fanout has no confirmable pending MLS state".into()),
            ),
        }
    }

    pub fn mark_mls_rolled_back(&mut self) -> Result<bool, TransportAdapterError> {
        match self.mls_state {
            FanoutMlsState::Pending(_) => {
                self.mls_state = FanoutMlsState::RolledBack;
                Ok(true)
            }
            FanoutMlsState::RolledBack => Ok(false),
            FanoutMlsState::NotApplicable | FanoutMlsState::Confirmed => Err(
                TransportAdapterError::Other("fanout has no rollbackable pending MLS state".into()),
            ),
        }
    }

    pub fn outcome(&self) -> OutboundFanoutOutcome {
        let accepted_targets = self
            .target_statuses
            .iter()
            .filter(|status| **status == FanoutTargetStatus::Accepted)
            .count();
        let failed_targets = self
            .target_statuses
            .iter()
            .filter(|status| **status == FanoutTargetStatus::Failed)
            .count();
        let outstanding_targets = self
            .target_statuses
            .iter()
            .filter(|status| status.is_outstanding())
            .count();
        OutboundFanoutOutcome {
            message_id: self
                .published_message_id
                .clone()
                .unwrap_or_else(|| self.request.message.id.clone()),
            mls_confirmation_required: accepted_targets > 0
                && matches!(self.mls_state, FanoutMlsState::Pending(_)),
            mls_confirmed: self.mls_state == FanoutMlsState::Confirmed,
            fanout_complete: outstanding_targets == 0,
            accepted_targets,
            failed_targets,
            outstanding_targets,
        }
    }

    /// Verify that `self` is a monotonic update of an already-durable fanout.
    ///
    /// The signed bytes, message id, frozen target set, policy and creation
    /// time are immutable. Per-target and MLS states may only advance. Storage
    /// implementations use this guard before replacing the serialized record,
    /// so a stale callback or regenerated request cannot reopen terminal state
    /// or silently substitute a new route.
    pub fn validate_successor_of(&self, previous: &Self) -> Result<(), TransportAdapterError> {
        let immutable_matches = self.request == previous.request
            && self.group_id == previous.group_id
            && self.pending_origin_message_id == previous.pending_origin_message_id
            && self.pending_kind == previous.pending_kind
            && self.created_at_ms == previous.created_at_ms
            && self.post_confirmation_welcomes == previous.post_confirmation_welcomes
            && self.target_statuses.len() == previous.target_statuses.len()
            && fanout_metadata_len_is_compatible(
                self.target_failures.len(),
                previous.target_failures.len(),
                self.target_statuses.len(),
            )
            && fanout_metadata_len_is_compatible(
                self.target_attempt_counts.len(),
                previous.target_attempt_counts.len(),
                self.target_statuses.len(),
            )
            && fanout_metadata_len_is_compatible(
                self.target_last_attempt_at_ms.len(),
                previous.target_last_attempt_at_ms.len(),
                self.target_statuses.len(),
            )
            && fanout_metadata_len_is_compatible(
                self.target_possible_exposure.len(),
                previous.target_possible_exposure.len(),
                self.target_statuses.len(),
            );
        let published_id_advances =
            match (&previous.published_message_id, &self.published_message_id) {
                (None, _) => true,
                (Some(previous), Some(next)) => previous == next,
                (Some(_), None) => false,
            };
        let targets_advance = immutable_matches
            && published_id_advances
            && self
                .target_statuses
                .iter()
                .zip(&previous.target_statuses)
                .all(|(next, prior)| target_status_advances(*prior, *next));
        let exposure_advances = previous.target_possible_exposure.is_empty()
            || self
                .target_possible_exposure
                .iter()
                .zip(&previous.target_possible_exposure)
                .all(|(next, prior)| !*prior || *next);
        let mls_advances = mls_state_advances(previous.mls_state, self.mls_state);
        let continuation_advances =
            previous.post_confirmation_welcomes_pending || !self.post_confirmation_welcomes_pending;
        if targets_advance && exposure_advances && mls_advances && continuation_advances {
            Ok(())
        } else {
            Err(TransportAdapterError::Other(
                "outbound fanout update is not monotonic".into(),
            ))
        }
    }

    fn target_status_mut(
        &mut self,
        index: usize,
    ) -> Result<&mut FanoutTargetStatus, TransportAdapterError> {
        self.target_statuses.get_mut(index).ok_or_else(|| {
            TransportAdapterError::Other("fanout target index is out of bounds".into())
        })
    }

    fn ensure_target_metadata_len(&mut self) {
        let target_count = self.target_statuses.len();
        self.target_failures.resize(target_count, None);
        self.target_attempt_counts.resize(target_count, 0);
        self.target_last_attempt_at_ms.resize(target_count, None);
        self.target_possible_exposure.resize(target_count, false);
    }

    fn mark_target_terminal(
        &mut self,
        index: usize,
        terminal: FanoutTargetStatus,
    ) -> Result<bool, TransportAdapterError> {
        debug_assert!(terminal.is_terminal());
        let status = self.target_status_mut(index)?;
        if status.is_terminal() {
            return Ok(false);
        }
        *status = terminal;
        Ok(true)
    }
}

fn target_status_advances(prior: FanoutTargetStatus, next: FanoutTargetStatus) -> bool {
    prior == next
        || matches!(
            (prior, next),
            (
                FanoutTargetStatus::NotAttempted,
                FanoutTargetStatus::Attempting
            ) | (
                FanoutTargetStatus::Attempting,
                FanoutTargetStatus::Accepted
                    | FanoutTargetStatus::Failed
                    | FanoutTargetStatus::PossiblyExposed
                    | FanoutTargetStatus::RetryableUnavailable
            ) | (
                FanoutTargetStatus::PossiblyExposed | FanoutTargetStatus::RetryableUnavailable,
                FanoutTargetStatus::Attempting
            )
        )
}

fn fanout_metadata_len_is_compatible(next: usize, prior: usize, targets: usize) -> bool {
    (next == targets && (prior == targets || prior == 0)) || (next == 0 && prior == 0)
}

fn mls_state_advances(prior: FanoutMlsState, next: FanoutMlsState) -> bool {
    prior == next
        || matches!(
            (prior, next),
            (
                FanoutMlsState::Pending(_),
                FanoutMlsState::Confirmed | FanoutMlsState::RolledBack
            )
        )
}

/// Privacy-safe caller/audit summary for one frozen fanout.
///
/// Counts and lifecycle booleans are exposed separately; relay endpoints are
/// deliberately absent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundFanoutOutcome {
    pub message_id: MessageId,
    pub mls_confirmation_required: bool,
    pub mls_confirmed: bool,
    pub fanout_complete: bool,
    pub accepted_targets: usize,
    pub failed_targets: usize,
    pub outstanding_targets: usize,
}

/// Successful endpoint-level publish acknowledgement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportEndpointReceipt {
    pub endpoint: TransportEndpoint,
    pub accepted_at: Option<Timestamp>,
}

/// Privacy-safe endpoint publish-rejection category.
///
/// Transport adapters may map wire-level rejection signals into this enum
/// (for example authentication-required, policy-blocked, or invalid-payload).
/// Only the category is retained; arbitrary remote suffix text is discarded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransportEndpointRejectionCategory {
    Duplicate,
    Pow,
    Blocked,
    RateLimited,
    Invalid,
    Error,
    Unsupported,
    AuthRequired,
    Restricted,
}

impl TransportEndpointRejectionCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Duplicate => "duplicate",
            Self::Pow => "pow",
            Self::Blocked => "blocked",
            Self::RateLimited => "rate-limited",
            Self::Invalid => "invalid",
            Self::Error => "error",
            Self::Unsupported => "unsupported",
            Self::AuthRequired => "auth-required",
            Self::Restricted => "restricted",
        }
    }
}

/// Exposure and retry semantics for one endpoint publish failure.
///
/// This classification is deliberately separate from the human-readable
/// reason and relay rejection category. Coordinators must make rollback and
/// retry decisions from this closed vocabulary, never by matching strings.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportEndpointFailureKind {
    /// The endpoint explicitly rejected the event. Repeating the exact event
    /// without a policy/configuration change is not useful.
    TerminalRejected,
    /// The adapter proved that no send attempt crossed its external boundary.
    NotExposed,
    /// The event may have been accepted or forwarded, but acknowledgement is
    /// unknown. This is the conservative default for older serialized data.
    #[default]
    PossiblyExposed,
    /// A pre-send connectivity/resource failure or explicitly retryable relay
    /// rejection made the endpoint unavailable; the exact event remains
    /// durably retryable without claiming exposure.
    RetryableUnavailable,
}

/// Endpoint-level publish failure. The overall publish may still succeed if
/// enough other endpoints acknowledge the message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportEndpointFailure {
    pub endpoint: TransportEndpoint,
    pub reason: String,
    #[serde(default)]
    pub kind: TransportEndpointFailureKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejection_category: Option<TransportEndpointRejectionCategory>,
}

impl TransportEndpointFailure {
    /// Whether the adapter mapped an exact, stable relay response to terminal
    /// target-absence evidence. The sentinel reason is adapter-authored and
    /// privacy-safe; arbitrary relay suffix text is never retained here.
    pub fn confirms_target_absence(&self) -> bool {
        self.rejection_category == Some(TransportEndpointRejectionCategory::Invalid)
            && self.reason == "relay rejected event (not-found)"
    }
}

/// Publish failure surfaced by transport adapters.
///
/// `summary` is safe for `Display`/logging. Per-endpoint diagnostics live in
/// `endpoint_failures` and may include endpoint identifiers only for structured
/// telemetry boundaries that do not log them verbatim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportPublishFailure {
    pub summary: String,
    /// Deterministic transport-visible id of the exact signed event, when the
    /// adapter prepared it before publication became unresolved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_id: Option<MessageId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoint_failures: Vec<TransportEndpointFailure>,
}

impl TransportPublishFailure {
    pub fn with_endpoint_failures(
        summary: impl Into<String>,
        endpoint_failures: Vec<TransportEndpointFailure>,
    ) -> Self {
        Self {
            summary: summary.into(),
            message_id: None,
            endpoint_failures,
        }
    }

    pub fn with_message_id(mut self, message_id: MessageId) -> Self {
        self.message_id = Some(message_id);
        self
    }
}

impl std::fmt::Display for TransportPublishFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.summary)
    }
}

/// Collapse identical publish failure summaries for user-facing `Display`.
///
/// Preserves first-seen order while dropping duplicates so multiple endpoints
/// rejecting with the same sanitized category do not repeat in UI text.
pub fn collapse_publish_failure_summaries<'a>(
    reasons: impl IntoIterator<Item = &'a str>,
) -> String {
    let mut unique = Vec::new();
    for reason in reasons {
        if !unique.contains(&reason) {
            unique.push(reason);
        }
    }
    unique.join("; ")
}

/// Aggregate publish result from a transport adapter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportPublishReport {
    pub message_id: MessageId,
    pub accepted: Vec<TransportEndpointReceipt>,
    pub failed: Vec<TransportEndpointFailure>,
    /// Threshold copied from the request; `0` relaxes the threshold but never
    /// the at-least-one-acceptance requirement (see [`met_required_acks`]).
    ///
    /// [`met_required_acks`]: Self::met_required_acks
    pub required_acks: usize,
}

impl TransportPublishReport {
    pub fn accepted_count(&self) -> usize {
        self.accepted.len()
    }

    /// Whether the publish reached enough endpoints to count as published.
    ///
    /// At least one acceptance is always required: a "best effort"
    /// (`required_acks == 0`) publish that no endpoint accepted reached no
    /// one, and confirming it would advance local state (epoch, membership)
    /// past a message that was never exposed.
    pub fn met_required_acks(&self) -> bool {
        self.accepted_count() >= self.required_acks.max(1)
    }
}

/// Which transport-control plane delivered a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TransportDeliveryPlane {
    Discovery,
    AccountInbox,
    Group,
    Ephemeral,
}

/// Transport wire identifiers for the event that carried a delivery, surfaced
/// to forensic auditing. Diagnostic only, never consensus input. Optional and
/// transport-generic: each field carries the wire-layer event metadata an
/// adapter has (e.g. for Nostr: the event id, kind, ephemeral pubkey, and the
/// `h`-tag transport group id). Never carries signatures, ciphertext, or keys.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportWireMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wire_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wire_kind: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wire_pubkey_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_group_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gift_wrap_event_id: Option<String>,
}

/// Adapter-side delivery metadata. This is diagnostic/routing context, never
/// consensus input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportDeliverySource {
    pub transport: TransportSource,
    pub plane: TransportDeliveryPlane,
    pub endpoint: Option<TransportEndpoint>,
    pub subscription_id: Option<String>,
    /// Wire identifiers for the carrying event, for forensic audit only.
    /// `None` for delivery paths with no inbound wire event (e.g. local
    /// publish echo).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wire: Option<TransportWireMetadata>,
}

/// Account-scoped message delivered by a transport adapter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportDelivery {
    pub account_id: MemberId,
    /// Local routing hint from the adapter's subscription registry. The engine
    /// still validates through the message envelope and peeler.
    pub group_id_hint: Option<GroupId>,
    pub message: TransportMessage,
    /// Local wall-clock observation time assigned by the receiving adapter.
    /// This is distinct from any publisher-controlled transport timestamp.
    pub received_at: Timestamp,
    pub source: TransportDeliverySource,
}

/// Errors returned by transport adapters.
#[derive(Debug, thiserror::Error)]
pub enum TransportAdapterError {
    #[error("account not active")]
    AccountNotActive(MemberId),

    /// The transport delivery stream or its backing task has closed.
    #[error("transport closed")]
    Closed,

    /// An inbound transport object failed its transport-specific syntax or
    /// exact-shape validation. Carries no attacker-controlled detail so it is
    /// safe to classify in runtime telemetry.
    #[error("invalid inbound transport encoding")]
    InvalidInboundEncoding,

    /// An inbound signed transport object reported an id that did not match
    /// its signed fields. Full signature verification remains at the peeler
    /// boundary, before decryption.
    #[error("invalid inbound transport signature")]
    InvalidInboundSignature,

    #[error("publish target does not match message envelope: envelope={envelope}, target={target}")]
    PublishTargetMismatch { envelope: String, target: String },

    #[error("subscription failed: {0}")]
    Subscription(String),

    #[error("publish failed: {0}")]
    Publish(String),

    /// Publish reached endpoints but every required acknowledgement failed.
    /// `summary` is safe for `Display`/logging; per-endpoint diagnostics are
    /// structured separately and may carry endpoint labels for non-log surfaces.
    #[error("publish failed: {0}")]
    PublishEndpoints(TransportPublishFailure),

    #[error("transport backend failure: {0}")]
    Backend(String),

    #[error("other transport adapter error: {0}")]
    Other(String),
}

impl TransportAdapterError {
    pub fn publish_endpoint_failures(&self) -> &[TransportEndpointFailure] {
        match self {
            Self::PublishEndpoints(failure) => failure.endpoint_failures.as_slice(),
            _ => &[],
        }
    }

    pub fn publish_message_id(&self) -> Option<&MessageId> {
        match self {
            Self::PublishEndpoints(failure) => failure.message_id.as_ref(),
            _ => None,
        }
    }
}

/// Account-aware network adapter that moves wrapped transport messages.
#[async_trait]
pub trait TransportAdapter: Send + Sync {
    /// Activate inbox and group subscriptions for an account.
    async fn activate_account(
        &self,
        activation: TransportAccountActivation,
    ) -> Result<(), TransportAdapterError>;

    /// Refresh only the group subscription plane for an active account.
    ///
    /// Subscribe failures for added groups fail fast and leave adapter state
    /// untouched. Unsubscribe failures for removed groups are absorbed: the
    /// removal takes effect in the adapter's routing state immediately, the
    /// relay-side unsubscribe is retried on subsequent syncs, and such
    /// failures never fail the call.
    async fn sync_account_groups(
        &self,
        sync: TransportGroupSync,
    ) -> Result<(), TransportAdapterError>;

    /// Deactivate every subscription owned by an account.
    async fn deactivate_account(&self, account_id: &MemberId) -> Result<(), TransportAdapterError>;

    /// Publish a wrapped message. Implementations should validate the request
    /// before sending and return endpoint-level receipts when available.
    async fn publish(
        &self,
        request: TransportPublishRequest,
    ) -> Result<TransportPublishReport, TransportAdapterError>;

    /// Receive the next account-scoped delivery. Returning `Ok(None)` means
    /// the adapter has shut down and will not produce more deliveries.
    async fn receive(&self) -> Result<Option<TransportDelivery>, TransportAdapterError>;
}

fn envelope_label(envelope: &TransportEnvelope) -> &'static str {
    match envelope {
        TransportEnvelope::GroupMessage { .. } => "group",
        TransportEnvelope::Welcome { .. } => "welcome",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fanout_request() -> TransportPublishRequest {
        TransportPublishRequest {
            account_id: MemberId::new(vec![0xA1; 32]),
            message: TransportMessage {
                id: MessageId::new(vec![0xB2; 32]),
                payload: b"exact signed event bytes".to_vec(),
                timestamp: Timestamp(1_700_000_000),
                causal_deps: Vec::new(),
                source: TransportSource("marmot.transport.nostr".into()),
                envelope: TransportEnvelope::GroupMessage {
                    transport_group_id: vec![0xC3; 32],
                },
            },
            target: TransportPublishTarget::Group {
                group_id: GroupId::new(vec![0xD4; 16]),
                transport_group_id: vec![0xC3; 32],
                endpoints: vec![
                    TransportEndpoint("wss://one.example".into()),
                    TransportEndpoint("wss://two.example".into()),
                    TransportEndpoint("wss://three.example".into()),
                ],
            },
            required_acks: 2,
        }
    }

    #[test]
    fn frozen_fanout_first_ack_releases_mls_before_fanout_completes() {
        let pending = crate::engine_state::PendingStateRef::new(9);
        let mut fanout = OutboundFanout::stage(
            fanout_request(),
            Some(pending),
            Some(GroupId::new(vec![0xD4; 16])),
            55,
        )
        .unwrap();

        fanout.mark_attempt_started(1).unwrap();
        assert!(fanout.mark_target_accepted(1).unwrap());

        let outcome = fanout.outcome();
        assert!(outcome.mls_confirmation_required);
        assert!(!outcome.mls_confirmed);
        assert!(!outcome.fanout_complete);
        assert_eq!(outcome.accepted_targets, 1);
        assert_eq!(outcome.outstanding_targets, 2);
        assert_eq!(fanout.pending_ref(), Some(pending));
    }

    #[test]
    fn frozen_fanout_duplicate_and_late_callbacks_are_idempotent() {
        let pending = crate::engine_state::PendingStateRef::new(9);
        let mut fanout = OutboundFanout::stage(
            fanout_request(),
            Some(pending),
            Some(GroupId::new(vec![0xD4; 16])),
            55,
        )
        .unwrap();

        fanout.mark_attempt_started(0).unwrap();
        assert!(fanout.mark_target_accepted(0).unwrap());
        fanout.mark_mls_confirmed().unwrap();

        assert!(!fanout.mark_target_accepted(0).unwrap());
        assert!(!fanout.mark_target_failed(0).unwrap());
        assert!(fanout.outcome().mls_confirmed);
        assert_eq!(fanout.outcome().accepted_targets, 1);
    }

    #[test]
    fn frozen_fanout_all_fail_is_complete_without_mls_confirmation() {
        let pending = crate::engine_state::PendingStateRef::new(9);
        let mut fanout = OutboundFanout::stage(
            fanout_request(),
            Some(pending),
            Some(GroupId::new(vec![0xD4; 16])),
            55,
        )
        .unwrap();

        for index in 0..3 {
            fanout.mark_attempt_started(index).unwrap();
            assert!(fanout.mark_target_failed(index).unwrap());
        }

        let outcome = fanout.outcome();
        assert!(outcome.fanout_complete);
        assert!(!outcome.mls_confirmation_required);
        assert!(!outcome.mls_confirmed);
        assert_eq!(outcome.failed_targets, 3);
        assert_eq!(outcome.outstanding_targets, 0);
    }

    #[test]
    fn frozen_fanout_ambiguous_failure_remains_outstanding_and_retryable() {
        let mut fanout = OutboundFanout::stage(
            fanout_request(),
            Some(crate::engine_state::PendingStateRef::new(9)),
            Some(GroupId::new(vec![0xD4; 16])),
            55,
        )
        .unwrap();
        fanout.mark_attempt_started_at(0, 100).unwrap();
        fanout
            .record_target_failure(
                0,
                TransportEndpointFailure {
                    endpoint: TransportEndpoint("wss://one.example".into()),
                    reason: "publish acknowledgement unknown".into(),
                    kind: TransportEndpointFailureKind::PossiblyExposed,
                    rejection_category: None,
                },
            )
            .unwrap();

        assert_eq!(
            fanout.target_status(0),
            Some(FanoutTargetStatus::PossiblyExposed)
        );
        assert_eq!(fanout.target_attempt_count(0), 1);
        assert_eq!(fanout.outcome().outstanding_targets, 3);
        assert!(!fanout.outcome().fanout_complete);

        let restored: OutboundFanout =
            serde_json::from_slice(&serde_json::to_vec(&fanout).unwrap()).unwrap();
        assert_eq!(restored, fanout);
    }

    #[test]
    fn later_rejection_cannot_erase_prior_possible_exposure() {
        let mut fanout = OutboundFanout::stage(
            fanout_request(),
            Some(crate::engine_state::PendingStateRef::new(9)),
            Some(GroupId::new(vec![0xD4; 16])),
            55,
        )
        .unwrap();
        fanout.mark_attempt_started_at(0, 100).unwrap();
        fanout
            .record_target_failure(
                0,
                TransportEndpointFailure {
                    endpoint: TransportEndpoint("wss://one.example".into()),
                    reason: "acknowledgement unknown".into(),
                    kind: TransportEndpointFailureKind::PossiblyExposed,
                    rejection_category: None,
                },
            )
            .unwrap();
        fanout.mark_attempt_started_at(0, 200).unwrap();
        fanout
            .record_target_failure(
                0,
                TransportEndpointFailure {
                    endpoint: TransportEndpoint("wss://one.example".into()),
                    reason: "later explicit rejection".into(),
                    kind: TransportEndpointFailureKind::TerminalRejected,
                    rejection_category: Some(TransportEndpointRejectionCategory::Blocked),
                },
            )
            .unwrap();

        assert!(fanout.possible_exposure());
        assert_eq!(
            fanout.target_status(0),
            Some(FanoutTargetStatus::PossiblyExposed)
        );
        assert!(!fanout.outcome().fanout_complete);
    }

    #[test]
    fn late_ambiguous_result_cannot_reopen_terminal_no_exposure_target() {
        let mut fanout = OutboundFanout::stage(
            fanout_request(),
            Some(crate::engine_state::PendingStateRef::new(9)),
            Some(GroupId::new(vec![0xD4; 16])),
            55,
        )
        .unwrap();
        fanout.mark_attempt_started_at(0, 100).unwrap();
        fanout
            .record_target_failure(
                0,
                TransportEndpointFailure {
                    endpoint: TransportEndpoint("wss://one.example".into()),
                    reason: "connection failed before send".into(),
                    kind: TransportEndpointFailureKind::NotExposed,
                    rejection_category: None,
                },
            )
            .unwrap();
        assert_eq!(fanout.target_status(0), Some(FanoutTargetStatus::Failed));

        assert!(
            !fanout
                .record_target_failure(
                    0,
                    TransportEndpointFailure {
                        endpoint: TransportEndpoint("wss://one.example".into()),
                        reason: "late acknowledgement unknown".into(),
                        kind: TransportEndpointFailureKind::PossiblyExposed,
                        rejection_category: None,
                    },
                )
                .unwrap()
        );
        assert!(!fanout.possible_exposure());
        assert_eq!(fanout.target_status(0), Some(FanoutTargetStatus::Failed));
    }

    #[test]
    fn endpoint_failure_without_kind_deserializes_conservatively() {
        let failure: TransportEndpointFailure = serde_json::from_value(serde_json::json!({
            "endpoint": "wss://relay.example",
            "reason": "legacy adapter error"
        }))
        .unwrap();

        assert_eq!(failure.kind, TransportEndpointFailureKind::PossiblyExposed);
    }

    #[test]
    fn frozen_fanout_round_trip_preserves_bytes_id_and_original_targets() {
        let request = fanout_request();
        let original_bytes = request.message.payload.clone();
        let original_id = request.message.id.clone();
        let original_targets = request.target.endpoints().to_vec();
        let fanout = OutboundFanout::stage(
            request,
            Some(crate::engine_state::PendingStateRef::new(9)),
            Some(GroupId::new(vec![0xD4; 16])),
            55,
        )
        .unwrap();

        let encoded = serde_json::to_vec(&fanout).unwrap();
        let restored: OutboundFanout = serde_json::from_slice(&encoded).unwrap();

        assert_eq!(restored.request().message.payload, original_bytes);
        assert_eq!(restored.request().message.id, original_id);
        assert_eq!(restored.request().target.endpoints(), original_targets);
        assert_eq!(restored.outstanding_target_indexes(), vec![0, 1, 2]);
    }

    #[test]
    fn legacy_pending_fanout_without_explicit_origin_restores_request_id() {
        let fanout = OutboundFanout::stage(
            fanout_request(),
            Some(crate::engine_state::PendingStateRef::new(9)),
            Some(GroupId::new(vec![0xD4; 16])),
            55,
        )
        .unwrap();
        let expected = fanout.message_id().clone();
        let mut encoded = serde_json::to_value(fanout).unwrap();
        let object = encoded.as_object_mut().unwrap();
        object.remove("pending_origin_message_id");
        object.remove("pending_kind");

        let restored: OutboundFanout = serde_json::from_value(encoded).unwrap();
        assert_eq!(restored.pending_origin_message_id(), Some(&expected));
        assert_eq!(
            restored.pending_kind(),
            Some(FanoutPendingKind::GroupEvolution)
        );
    }

    #[test]
    fn post_confirmation_welcome_release_is_durable_and_cannot_reopen() {
        let recipient = MemberId::new(vec![0xE5; 32]);
        let welcome = TransportMessage {
            envelope: TransportEnvelope::Welcome {
                recipient: recipient.clone(),
            },
            ..fanout_request().message
        };
        let request = TransportPublishRequest {
            account_id: MemberId::new(vec![0xA1; 32]),
            message: welcome.clone(),
            target: TransportPublishTarget::Inbox {
                recipient,
                endpoints: vec![TransportEndpoint("wss://one.example".into())],
            },
            required_acks: 1,
        };
        let mut fanout = OutboundFanout::stage_with_post_confirmation_welcomes(
            request,
            Some(crate::engine_state::PendingStateRef::new(9)),
            Some(GroupId::new(vec![0xD4; 16])),
            55,
            None,
            Some(FanoutPendingKind::CreateGroup),
            vec![welcome.clone()],
        )
        .unwrap();
        let unreleased = fanout.clone();

        assert_eq!(fanout.pending_post_confirmation_welcomes(), &[welcome]);
        assert!(fanout.mark_post_confirmation_welcomes_released());
        assert!(fanout.pending_post_confirmation_welcomes().is_empty());
        fanout.validate_successor_of(&unreleased).unwrap();
        assert!(unreleased.validate_successor_of(&fanout).is_err());

        let restored: OutboundFanout =
            serde_json::from_slice(&serde_json::to_vec(&fanout).unwrap()).unwrap();
        assert!(restored.pending_post_confirmation_welcomes().is_empty());
    }

    fn report(accepted: usize, failed: usize, required_acks: usize) -> TransportPublishReport {
        TransportPublishReport {
            message_id: MessageId::new(*b"m1"),
            accepted: (0..accepted)
                .map(|i| TransportEndpointReceipt {
                    endpoint: TransportEndpoint(format!("wss://accepted-{i}.example")),
                    accepted_at: None,
                })
                .collect(),
            failed: (0..failed)
                .map(|i| TransportEndpointFailure {
                    endpoint: TransportEndpoint(format!("wss://failed-{i}.example")),
                    reason: "unreachable".into(),
                    kind: TransportEndpointFailureKind::RetryableUnavailable,
                    rejection_category: None,
                })
                .collect(),
            required_acks,
        }
    }

    #[test]
    fn met_required_acks_zero_required_fails_with_zero_accepted() {
        assert!(!report(0, 0, 0).met_required_acks());
        assert!(!report(0, 2, 0).met_required_acks());
    }

    #[test]
    fn met_required_acks_zero_required_passes_with_one_accepted() {
        assert!(report(1, 0, 0).met_required_acks());
        assert!(report(1, 3, 0).met_required_acks());
    }

    #[test]
    fn met_required_acks_nonzero_threshold_unchanged() {
        assert!(!report(0, 0, 1).met_required_acks());
        assert!(report(1, 0, 1).met_required_acks());
        assert!(!report(1, 1, 2).met_required_acks());
        assert!(report(2, 0, 2).met_required_acks());
    }

    #[test]
    fn collapse_publish_failure_summaries_dedupes_while_preserving_order() {
        let collapsed = collapse_publish_failure_summaries([
            "relay rejected event (blocked)",
            "connect relay failed",
            "relay rejected event (blocked)",
        ]);
        assert_eq!(
            collapsed,
            "relay rejected event (blocked); connect relay failed"
        );
    }

    #[test]
    fn endpoint_failure_deserializes_legacy_records_without_rejection_category() {
        let failure: TransportEndpointFailure = serde_json::from_value(serde_json::json!({
            "endpoint": "wss://relay.example",
            "reason": "connect relay failed"
        }))
        .unwrap();

        assert_eq!(failure.rejection_category, None);
    }
}
