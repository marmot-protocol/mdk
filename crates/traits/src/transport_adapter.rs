//! Transport adapter boundary.
//!
//! A transport adapter owns network reachability and routing: account
//! activation, relay subscription state, publish quorum policy, and delivery
//! fanout. It must not decide CGKA convergence or inspect peeled MLS state.
//!
//! The engine receives [`crate::transport::TransportMessage`] values from this
//! boundary and remains the source of truth for commit ordering, branch
//! selection, and application-message validity.

use crate::app_event::AppMessageRetentionDecision;
use crate::engine_state::PendingStateRef;
use crate::transport::{Timestamp, TransportEnvelope, TransportMessage, TransportSource};
use crate::types::{EpochId, GroupId, MemberId, MessageId};
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
///
/// A group's current route comes first; the routes it retains from before a
/// route change follow it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportGroupSubscription {
    pub group_id: GroupId,
    pub transport_group_id: Vec<u8>,
    pub endpoints: Vec<TransportEndpoint>,
    /// History floor of a retained route: when it stopped being the group's
    /// current route, less the caller's clock-skew allowance.
    ///
    /// Members that have not yet applied the route change still send to the
    /// old address, so an adapter subscribes a retained route from this floor,
    /// and from no later than the activation's own `since`. `None` on the
    /// current route, which resumes from the activation's `since`. A retained
    /// route without a floor, whose switch time the caller does not know, is
    /// backfilled in full.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retained_since: Option<Timestamp>,
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
/// same already-signed event bytes. The interrupted attempt may have reached
/// the endpoint, so the target counts as possibly exposed from then on: a
/// definite answer to the retry speaks only for the retry, and must not let a
/// pending commit roll back. Ambiguous and transient outcomes remain
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

/// The sender's immutable local time of a carrier's first actual accepted
/// publication. Legacy accepted fanouts with no retained time stay unknown.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicationObservation {
    pub at_ms: u64,
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
    /// Durable app-layer identity needed to finalize an optimistic local row
    /// when this exact frozen event is acknowledged by a later retry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    application_message: Option<OutboundApplicationMessage>,
    #[serde(default)]
    pending_origin_message_id: Option<MessageId>,
    #[serde(default)]
    pending_kind: Option<FanoutPendingKind>,
    #[serde(default)]
    published_message_id: Option<MessageId>,
    #[serde(default)]
    first_acceptance_observation: Option<PublicationObservation>,
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
    /// The attempts this value started and has not recorded a result for: the
    /// identity of each target's current attempt (mdk#2332). Never
    /// serialized, so a fanout loaded from storage holds none, and a stored
    /// `Attempting` can never be reported as unexposed.
    #[serde(skip)]
    held_attempts: HeldAttempts,
}

/// Per target, whether the in-memory fanout holding this started the target's
/// current attempt and still awaits its result.
///
/// It lives only in process memory. Equality ignores it, so a stored record
/// and the value that wrote it still compare equal.
#[derive(Clone, Debug, Default)]
struct HeldAttempts(Vec<bool>);

impl HeldAttempts {
    fn start(&mut self, index: usize, targets: usize) {
        self.0.resize(targets, false);
        self.0[index] = true;
    }

    /// End the target's current attempt, saying whether this value held it.
    fn end(&mut self, index: usize) -> bool {
        self.0.get_mut(index).is_some_and(std::mem::take)
    }
}

impl PartialEq for HeldAttempts {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl Eq for HeldAttempts {}

/// What a recorded result proves about the target's exposure.
enum AttemptResult<'a> {
    Accepted,
    /// A failure with no classification.
    Unclassified,
    Failure(&'a TransportEndpointFailure),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundApplicationMessage {
    pub group_id: GroupId,
    pub app_event_id: String,
    pub source_epoch: EpochId,
    pub retention: AppMessageRetentionDecision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<crate::app_event::AppMessageAuthority>,
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
            application_message: None,
            pending_origin_message_id,
            pending_kind,
            published_message_id: None,
            first_acceptance_observation: None,
            target_statuses: vec![FanoutTargetStatus::NotAttempted; target_count],
            target_failures: vec![None; target_count],
            target_attempt_counts: vec![0; target_count],
            target_last_attempt_at_ms: vec![None; target_count],
            target_possible_exposure: vec![false; target_count],
            post_confirmation_welcomes_pending: !post_confirmation_welcomes.is_empty(),
            post_confirmation_welcomes,
            mls_state: pending.map_or(FanoutMlsState::NotApplicable, FanoutMlsState::Pending),
            created_at_ms,
            held_attempts: HeldAttempts::default(),
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

    pub fn application_message(&self) -> Option<&OutboundApplicationMessage> {
        self.application_message.as_ref()
    }

    pub fn set_application_message(
        &mut self,
        application_message: OutboundApplicationMessage,
    ) -> Result<(), TransportAdapterError> {
        if self.group_id.as_ref() != Some(&application_message.group_id) {
            return Err(TransportAdapterError::Other(
                "application-message fanout group does not match publish target".into(),
            ));
        }
        match &self.application_message {
            None => {
                self.application_message = Some(application_message);
                Ok(())
            }
            Some(previous) if previous == &application_message => Ok(()),
            Some(_) => Err(TransportAdapterError::Other(
                "application-message fanout context changed".into(),
            )),
        }
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

    /// First durable local observation of accepted publication. Legacy accepted
    /// fanouts have no recoverable boundary and remain `None`.
    pub fn first_acceptance_observation(&self) -> Option<PublicationObservation> {
        self.first_acceptance_observation
    }

    /// Called by the durable store in the transaction that first records an
    /// accepted target, before exposing a replayable publication effect.
    pub fn observe_first_acceptance(
        &mut self,
        observation: PublicationObservation,
    ) -> Result<(), TransportAdapterError> {
        if self.outcome().accepted_targets == 0 {
            return Err(TransportAdapterError::Other(
                "invalid publication observation".into(),
            ));
        }
        match self.first_acceptance_observation {
            Some(previous) if previous != observation => Err(TransportAdapterError::Other(
                "publication observation changed".into(),
            )),
            _ => {
                self.first_acceptance_observation = Some(observation);
                Ok(())
            }
        }
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

    /// Make only targets whose last attempt was proven not to reach a relay
    /// immediately eligible, leaving possibly-exposed targets on their retry
    /// clock. A restored-connectivity wake uses
    /// [`Self::wake_targets_for_restored_connectivity`] instead, which also
    /// wakes possibly-exposed targets: their retry resends the same signed
    /// event, which a relay that stored it acknowledges as a duplicate.
    pub fn wake_retryable_unavailable_targets(&mut self) -> usize {
        self.ensure_target_metadata_len();
        let mut woken = 0;
        for (index, status) in self.target_statuses.iter().enumerate() {
            if *status == FanoutTargetStatus::RetryableUnavailable
                && self.target_last_attempt_at_ms[index].take().is_some()
            {
                woken += 1;
            }
        }
        woken
    }

    /// Make every retryable target eligible now after the host observes
    /// restored connectivity, including possibly-exposed ones (mdk#2762).
    ///
    /// A retry resends the exact frozen signed event, so a relay that already
    /// stored it answers `duplicate:` and the target counts as accepted. No
    /// second logical message can result. Attempt counts are kept, so a target
    /// that fails again resumes its backoff from where it was. A send that a
    /// stale socket swallowed while the device went offline would otherwise
    /// wait out an ambiguity backoff of up to an hour after reconnecting, and
    /// hold every later send in its group behind it.
    pub fn wake_targets_for_restored_connectivity(&mut self) -> usize {
        self.ensure_target_metadata_len();
        let mut woken = 0;
        for (index, status) in self.target_statuses.iter().enumerate() {
            if matches!(
                status,
                FanoutTargetStatus::RetryableUnavailable | FanoutTargetStatus::PossiblyExposed
            ) && self.target_last_attempt_at_ms[index].take().is_some()
            {
                woken += 1;
            }
        }
        woken
    }

    /// Whether any endpoint may hold the event without having acknowledged it.
    /// An `Attempting` target counts: its bytes may already have left, and
    /// only a recorded result says otherwise.
    pub fn possible_exposure(&self) -> bool {
        self.target_possible_exposure.iter().any(|exposed| *exposed)
            || self.target_statuses.iter().any(|status| {
                matches!(
                    status,
                    FanoutTargetStatus::PossiblyExposed | FanoutTargetStatus::Attempting
                )
            })
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
    ///
    /// Only an attempt that ended without a recorded result leaves a target
    /// `Attempting` for the next pass: a crash, or an error that unwound the
    /// pass. Its bytes may have reached the endpoint, so re-marking it records
    /// possible exposure, as an in-process cancellation does. A later definite
    /// answer then cannot end the target `Failed`.
    ///
    /// The stored `Attempting` is the attempt's write-ahead record. This value
    /// also holds the attempt's identity in memory, so only it can later
    /// report the attempt as unexposed (see [`Self::record_target_failure`]).
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
            status @ (FanoutTargetStatus::NotAttempted
            | FanoutTargetStatus::Attempting
            | FanoutTargetStatus::PossiblyExposed
            | FanoutTargetStatus::RetryableUnavailable) => {
                if status == FanoutTargetStatus::Attempting {
                    self.target_possible_exposure[index] = true;
                }
                self.fold_stored_exposure(index);
                self.target_statuses[index] = FanoutTargetStatus::Attempting;
                self.target_attempt_counts[index] =
                    self.target_attempt_counts[index].saturating_add(1);
                self.target_last_attempt_at_ms[index] = Some(attempted_at_ms);
                self.target_failures[index] = None;
                self.held_attempts.start(index, self.target_statuses.len());
                Ok(true)
            }
            FanoutTargetStatus::Accepted | FanoutTargetStatus::Failed => Ok(false),
        }
    }

    /// Record an acknowledgement. It leaves the exposure bit as it was: the
    /// bit means the endpoint may hold the event without having acknowledged
    /// it, and this endpoint acknowledged it.
    pub fn mark_target_accepted(&mut self, index: usize) -> Result<bool, TransportAdapterError> {
        self.mark_target_terminal(index, FanoutTargetStatus::Accepted, AttemptResult::Accepted)
    }

    /// End the target `Failed` with no classification. Nothing proves that
    /// its frame stayed on the device, so the target counts as possibly
    /// exposed from then on.
    pub fn mark_target_failed(&mut self, index: usize) -> Result<bool, TransportAdapterError> {
        self.mark_target_terminal(
            index,
            FanoutTargetStatus::Failed,
            AttemptResult::Unclassified,
        )
    }

    /// Record one endpoint's failure (mdk#2332).
    ///
    /// The target's exposure bit is the one fact that it may hold the event.
    /// It is never cleared, and every result that moves a target out of
    /// `Attempting` sets it unless the result proves the attempt reached no
    /// relay, or the relay definitively refused it:
    /// - a failure that proves nothing was sent
    ///   ([`TransportEndpointFailure::proves_nothing_sent`]), or a definitive
    ///   refusal ([`TransportEndpointFailureKind::TerminalRejected`]), of the
    ///   *current* attempt, the one this value started with
    ///   [`Self::mark_attempt_started_at`], leaves the bit as it was;
    /// - a stored `Attempting` loaded from storage belongs to an interrupted
    ///   attempt that no value holds any more. Its frame may have left, so any
    ///   result recorded on it sets the bit;
    /// - on a target with no attempt in flight (`NotAttempted`,
    ///   `RetryableUnavailable`, `PossiblyExposed`) only a refusal that sent
    ///   nothing may be recorded without setting the bit: the commit size
    ///   floor, a known limit, a connection never made;
    /// - anything else sets the bit: a relay's retryable answer
    ///   (`rate-limited:`, `auth-required:`), a timeout, a close after the
    ///   write, an unclassified failure;
    /// - a stored status that records exposure sets the bit before it is
    ///   replaced, here or by a new attempt: `PossiblyExposed`, and a
    ///   `RetryableUnavailable` whose failure does not prove nothing was sent,
    ///   as rows stored before that proof existed record a retryable answer.
    ///
    /// A target whose bit is set stays `PossiblyExposed` whatever it is told
    /// later, so a pending commit that may have reached a relay never rolls
    /// back (mdk#1577).
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
        self.settle_exposure(index, current, AttemptResult::Failure(&failure));
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

    /// Record a refusal made before the target is marked, such as the commit
    /// size floor or a known limit, through [`Self::record_target_failure`]
    /// (mdk#2332). It sent nothing, so no attempt is marked. A target an
    /// earlier attempt may have exposed stays outstanding, though, so the
    /// refusal restarts its retry clock at `refused_at_ms` and counts toward
    /// its backoff as an attempt does; otherwise its last attempt's deadline,
    /// once passed, would make it due, and refused, on every pass.
    pub fn record_refusal_before_attempt(
        &mut self,
        index: usize,
        failure: TransportEndpointFailure,
        refused_at_ms: u64,
    ) -> Result<bool, TransportAdapterError> {
        let recorded = self.record_target_failure(index, failure)?;
        if recorded && self.target_statuses[index].is_outstanding() {
            self.target_attempt_counts[index] = self.target_attempt_counts[index].saturating_add(1);
            self.target_last_attempt_at_ms[index] = Some(refused_at_ms);
        }
        Ok(recorded)
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
            && self.application_message == previous.application_message
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
        let observation_advances = match (
            previous.first_acceptance_observation,
            self.first_acceptance_observation,
        ) {
            (Some(prior), Some(next)) => prior == next,
            (None, Some(_)) => {
                previous.outcome().accepted_targets == 0 && self.outcome().accepted_targets > 0
            }
            (None, None) => true,
            (Some(_), None) => false,
        };
        let targets_advance = immutable_matches
            && observation_advances
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
        result: AttemptResult<'_>,
    ) -> Result<bool, TransportAdapterError> {
        debug_assert!(terminal.is_terminal());
        let current = *self.target_status_mut(index)?;
        if current.is_terminal() {
            return Ok(false);
        }
        self.ensure_target_metadata_len();
        self.settle_exposure(index, current, result);
        self.target_statuses[index] = terminal;
        Ok(true)
    }

    /// The single exposure transition (mdk#2332): see
    /// [`Self::record_target_failure`]. Ends the target's current attempt and
    /// sets its exposure bit unless `result` proves that bit can stay as it
    /// was. Never clears it.
    fn settle_exposure(
        &mut self,
        index: usize,
        current: FanoutTargetStatus,
        result: AttemptResult<'_>,
    ) {
        let held = self.held_attempts.end(index);
        let keeps_bit = match result {
            AttemptResult::Accepted => true,
            AttemptResult::Unclassified => false,
            AttemptResult::Failure(failure) => match current {
                FanoutTargetStatus::Attempting => {
                    held && (failure.proves_nothing_sent()
                        || failure.kind == TransportEndpointFailureKind::TerminalRejected)
                }
                _ => failure.proves_nothing_sent(),
            },
        };
        self.fold_stored_exposure(index);
        if !keeps_bit {
            self.target_possible_exposure[index] = true;
        }
    }

    /// Set the exposure bit when the target's stored status records exposure,
    /// before anything replaces that status. A `PossiblyExposed` status does.
    /// So does a `RetryableUnavailable` whose failure does not prove nothing
    /// was sent: a row stored before that proof existed (mdk#2332) records a
    /// relay's `rate-limited:` or `auth-required:` answer that way, with the
    /// bit clear.
    fn fold_stored_exposure(&mut self, index: usize) {
        let exposed = match self.target_statuses[index] {
            FanoutTargetStatus::PossiblyExposed => true,
            FanoutTargetStatus::RetryableUnavailable => !self.target_failures[index]
                .as_ref()
                .is_some_and(TransportEndpointFailure::proves_nothing_sent),
            _ => false,
        };
        if exposed {
            self.target_possible_exposure[index] = true;
        }
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
                // A refusal recorded before marking: the commit size floor or a
                // known limit (mdk#2332). It sent nothing.
                FanoutTargetStatus::NotAttempted | FanoutTargetStatus::RetryableUnavailable,
                FanoutTargetStatus::Failed
                    | FanoutTargetStatus::PossiblyExposed
                    | FanoutTargetStatus::RetryableUnavailable
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

/// Typed provenance for an accepted endpoint publish receipt.
///
/// `None` on a receipt means this detail was unavailable, not that the relay
/// proved the event was new. In particular, reconstructed durable fanout
/// reports cannot recover the original acknowledgement kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportEndpointAckKind {
    /// The endpoint returned an affirmative acknowledgement without a typed
    /// duplicate marker.
    Affirmative,
    /// The endpoint acknowledged that it already holds this exact event.
    Duplicate,
}

/// Successful endpoint-level publish acknowledgement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportEndpointReceipt {
    pub endpoint: TransportEndpoint,
    pub accepted_at: Option<Timestamp>,
    /// Present only when the transport preserved typed acknowledgement detail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ack_kind: Option<TransportEndpointAckKind>,
}

/// Privacy-safe endpoint publish-rejection category.
///
/// Transport adapters may map wire-level rejection signals into this enum
/// (for example authentication-required, policy-blocked, or invalid-payload).
/// Only the category is retained; arbitrary remote suffix text is discarded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    /// An explicit, event-correlated refusal because the event is too large:
    /// the endpoint's answer, or, with [`TransportEndpointFailureKind::NotExposed`],
    /// the adapter's refusal to send an event over the endpoint's known limit.
    /// This category does not discover an endpoint's configured size limit.
    TooLarge,
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
            Self::TooLarge => "too-large",
        }
    }
}

/// Which event a size refusal concerns, named by the code that publishes it,
/// never inferred from ciphertext (mdk#2334).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OversizedArtifact {
    Commit,
    Welcome,
    ApplicationMessage,
    Other,
}

impl OversizedArtifact {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Commit => "commit",
            Self::Welcome => "welcome",
            Self::ApplicationMessage => "application_message",
            Self::Other => "other",
        }
    }
}

impl std::fmt::Display for OversizedArtifact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Coarse serialized-event sizes for a proven size refusal, never a relay limit.
/// Exact byte counts must not cross the host diagnostic boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventSizeClass {
    #[serde(rename = "under_64_kib")]
    Under64Kib,
    #[serde(rename = "from_64_to_128_kib")]
    From64To128Kib,
    #[serde(rename = "from_128_to_256_kib")]
    From128To256Kib,
    #[serde(rename = "from_256_to_512_kib")]
    From256To512Kib,
    #[serde(rename = "from_512_kib_to_1_mib")]
    From512KibTo1Mib,
    #[serde(rename = "from_1_to_2_mib")]
    From1To2Mib,
    #[serde(rename = "from_2_to_4_mib")]
    From2To4Mib,
    #[serde(rename = "over_4_mib")]
    Over4Mib,
}

impl EventSizeClass {
    /// Serialized event JSON bytes, excluding transport framing. All upper
    /// bounds are exclusive except 4 MiB, which belongs to `From2To4Mib`.
    pub fn of_bytes(bytes: usize) -> Self {
        match bytes {
            n if n < 64 * 1024 => Self::Under64Kib,
            n if n < 128 * 1024 => Self::From64To128Kib,
            n if n < 256 * 1024 => Self::From128To256Kib,
            n if n < 512 * 1024 => Self::From256To512Kib,
            n if n < 1024 * 1024 => Self::From512KibTo1Mib,
            n if n < 2 * 1024 * 1024 => Self::From1To2Mib,
            n if n <= 4 * 1024 * 1024 => Self::From2To4Mib,
            _ => Self::Over4Mib,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Under64Kib => "under_64_kib",
            Self::From64To128Kib => "from_64_to_128_kib",
            Self::From128To256Kib => "from_128_to_256_kib",
            Self::From256To512Kib => "from_256_to_512_kib",
            Self::From512KibTo1Mib => "from_512_kib_to_1_mib",
            Self::From1To2Mib => "from_1_to_2_mib",
            Self::From2To4Mib => "from_2_to_4_mib",
            Self::Over4Mib => "over_4_mib",
        }
    }

    /// Classify a complete, distinct target set's explicit size refusals: an
    /// endpoint's terminal answer or the adapter's unexposed refusal against a
    /// known limit, in any mix. The caller must separately establish zero
    /// acceptance and no earlier ambiguous exposure; a partial failure list
    /// cannot establish this proof.
    pub fn from_rejected_targets(
        targets: &[TransportEndpoint],
        failures: &[TransportEndpointFailure],
    ) -> Option<Self> {
        if targets.is_empty() || failures.len() != targets.len() {
            return None;
        }
        let mut class = None;
        for (index, target) in targets.iter().enumerate() {
            if targets[..index].contains(target) {
                return None;
            }
            let mut matching = failures
                .iter()
                .filter(|failure| &failure.endpoint == target);
            let failure = matching.next()?;
            if matching.next().is_some()
                || !matches!(
                    failure.kind,
                    TransportEndpointFailureKind::TerminalRejected
                        | TransportEndpointFailureKind::NotExposed
                )
                || failure.rejection_category != Some(TransportEndpointRejectionCategory::TooLarge)
            {
                return None;
            }
            let next = failure.size_class?;
            if class.is_some_and(|previous| previous != next) {
                return None;
            }
            class = Some(next);
        }
        class
    }
}

impl fmt::Display for EventSizeClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
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
    /// Locally measured signed event JSON size, only for a proven size refusal.
    /// Absent on old persisted failures and when the size cannot be established.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_class: Option<EventSizeClass>,
    /// The adapter proved that no frame of this attempt left the device: the
    /// connection was never made (a dial refusal, a DNS failure, a socket that
    /// never opened) or the adapter refused the event itself. Only a
    /// [`TransportEndpointFailureKind::RetryableUnavailable`] failure needs
    /// it; [`TransportEndpointFailureKind::NotExposed`] already says so.
    /// False, or absent on older records, means a frame may have left. A
    /// relay's retryable answer (`rate-limited:`, `auth-required:`) is never
    /// pre-send: the relay received the frame (mdk#2332).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub pre_send: bool,
}

impl TransportEndpointFailure {
    /// Whether this failure proves that nothing of its attempt left the
    /// device: an adapter refusal, or a connection that was never made.
    pub fn proves_nothing_sent(&self) -> bool {
        match self.kind {
            TransportEndpointFailureKind::NotExposed => true,
            TransportEndpointFailureKind::RetryableUnavailable => self.pre_send,
            TransportEndpointFailureKind::TerminalRejected
            | TransportEndpointFailureKind::PossiblyExposed => false,
        }
    }

    /// The fixed reason of [`Self::over_known_limit`], which audit records as
    /// a failure before exposure.
    pub const OVER_KNOWN_LIMIT_REASON: &'static str = "event exceeds the endpoint's known limit";

    /// The adapter's refusal to send an event of `event_bytes` serialized
    /// bytes over the endpoint's known limit: nothing was sent, and the same
    /// event cannot succeed there.
    pub fn over_known_limit(endpoint: TransportEndpoint, event_bytes: usize) -> Self {
        Self {
            endpoint,
            reason: Self::OVER_KNOWN_LIMIT_REASON.to_owned(),
            kind: TransportEndpointFailureKind::NotExposed,
            rejection_category: Some(TransportEndpointRejectionCategory::TooLarge),
            size_class: Some(EventSizeClass::of_bytes(event_bytes)),
            pre_send: false,
        }
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
    /// Strong aggregate proof: every distinct requested endpoint conclusively
    /// refused this same event for size, with no acceptance or unresolved target.
    /// Never infer this from a partial endpoint-failure list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_size_class: Option<EventSizeClass>,
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
            event_size_class: None,
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
    /// Stable, privacy-safe category for audit and telemetry.
    ///
    /// Never derived from `Display`, which prefixes every publish failure with
    /// `"publish failed: "` and may carry adapter detail such as endpoints.
    #[must_use]
    pub fn privacy_safe_kind(&self) -> &'static str {
        match self {
            Self::AccountNotActive(_) => "transport_account_not_active",
            Self::Closed => "transport_closed",
            Self::InvalidInboundEncoding => "transport_invalid_inbound_encoding",
            Self::InvalidInboundSignature => "transport_invalid_inbound_signature",
            Self::PublishTargetMismatch { .. } => "transport_publish_target_mismatch",
            Self::Subscription(_) => "transport_subscription_failed",
            Self::Publish(_) => "transport_publish_failed",
            Self::PublishEndpoints(_) => "insufficient_publish_acknowledgements",
            Self::Backend(_) => "transport_backend",
            Self::Other(_) => "transport_other",
        }
    }

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
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
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

    /// The size class of `message` when [`Self::publish`] would refuse it,
    /// unsent, on every endpoint of `target` it would send to, because it is
    /// over each one's known size limit. Sends nothing.
    ///
    /// A publication owner asks this before recording a fanout, so a change
    /// whose artifact fits none of its relays is refused before any of it is
    /// sent. `None` when an endpoint the adapter would send to has no known
    /// limit or fits the message, and when it would send to none, since the
    /// publish then fails for another reason. An adapter that knows no limits
    /// returns `None`.
    async fn size_class_over_known_limits(
        &self,
        _message: &TransportMessage,
        _target: &TransportPublishTarget,
    ) -> Option<EventSizeClass> {
        None
    }

    /// The endpoints of `target` that [`Self::publish_commit`] would refuse
    /// `commit` on, unsent, for its size: over the endpoint's known limit or,
    /// where the limit is unknown, over the adapter's commit size floor
    /// (mdk#2332). Sends nothing. Each refusal proves nothing was sent
    /// ([`TransportEndpointFailure::proves_nothing_sent`]) and names its
    /// endpoint as `target` does.
    ///
    /// A publication owner asks this for a target before marking it
    /// `Attempting`, so a refused target never carries an attempt that might
    /// have left. It asks for each target on its own, since a check can wait
    /// on a connection, and one target's check must not hold back another's
    /// send. An endpoint left out is sent to. The default refuses nothing.
    async fn commit_size_refusals(
        &self,
        _commit: &TransportMessage,
        _target: &TransportPublishTarget,
    ) -> Vec<TransportEndpointFailure> {
        Vec::new()
    }

    /// Publish a commit (mdk#2332): [`Self::publish`], plus the commit size
    /// floor of [`Self::commit_size_refusals`], applied again by the
    /// publication itself. The default is [`Self::publish`].
    async fn publish_commit(
        &self,
        request: TransportPublishRequest,
    ) -> Result<TransportPublishReport, TransportAdapterError> {
        self.publish(request).await
    }
}

/// Judges a founding create's Welcomes before the engine writes anything
/// (mdk#2334). The engine refuses the create with
/// [`crate::EngineError::EventTooLarge`] when this names a size class.
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait WelcomeSizeCheck: Send + Sync {
    /// The size class of the first of `welcomes` that fits none of the
    /// endpoints its publish would reach, or `None` when each fits one.
    async fn oversized_welcome(&self, welcomes: &[TransportMessage]) -> Option<EventSizeClass>;
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
                    pre_send: false,
                    size_class: None,
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
    fn connectivity_wake_only_clears_proven_unavailable_retry_clocks() {
        let mut fanout = OutboundFanout::stage(
            fanout_request(),
            Some(crate::engine_state::PendingStateRef::new(9)),
            Some(GroupId::new(vec![0xD4; 16])),
            55,
        )
        .unwrap();
        for (index, kind) in [
            TransportEndpointFailureKind::PossiblyExposed,
            TransportEndpointFailureKind::RetryableUnavailable,
        ]
        .into_iter()
        .enumerate()
        {
            fanout.mark_attempt_started_at(index, 100).unwrap();
            fanout
                .record_target_failure(
                    index,
                    TransportEndpointFailure {
                        pre_send: kind == TransportEndpointFailureKind::RetryableUnavailable,
                        size_class: None,
                        endpoint: fanout.request().target.endpoints()[index].clone(),
                        reason: "scripted failure".into(),
                        kind,
                        rejection_category: None,
                    },
                )
                .unwrap();
        }

        assert_eq!(fanout.wake_retryable_unavailable_targets(), 1);
        assert_eq!(fanout.target_last_attempt_at_ms(0), Some(100));
        assert_eq!(fanout.target_last_attempt_at_ms(1), None);
        assert_eq!(
            fanout.target_status(0),
            Some(FanoutTargetStatus::PossiblyExposed)
        );
        assert_eq!(
            fanout.target_status(1),
            Some(FanoutTargetStatus::RetryableUnavailable)
        );
    }

    #[test]
    fn restored_connectivity_wakes_every_retryable_target_and_keeps_attempt_counts() {
        let mut fanout = OutboundFanout::stage(
            fanout_request(),
            Some(crate::engine_state::PendingStateRef::new(9)),
            Some(GroupId::new(vec![0xD4; 16])),
            55,
        )
        .unwrap();
        for (index, kind) in [
            TransportEndpointFailureKind::PossiblyExposed,
            TransportEndpointFailureKind::RetryableUnavailable,
            TransportEndpointFailureKind::TerminalRejected,
        ]
        .into_iter()
        .enumerate()
        {
            fanout.mark_attempt_started_at(index, 100).unwrap();
            fanout
                .record_target_failure(
                    index,
                    TransportEndpointFailure {
                        pre_send: false,
                        size_class: None,
                        endpoint: fanout.request().target.endpoints()[index].clone(),
                        reason: "scripted failure".into(),
                        kind,
                        rejection_category: None,
                    },
                )
                .unwrap();
        }

        assert_eq!(fanout.wake_targets_for_restored_connectivity(), 2);
        assert_eq!(fanout.target_last_attempt_at_ms(0), None);
        assert_eq!(fanout.target_last_attempt_at_ms(1), None);
        assert_eq!(
            fanout.target_last_attempt_at_ms(2),
            Some(100),
            "a terminal rejection is never retried"
        );
        assert_eq!(
            fanout.target_status(0),
            Some(FanoutTargetStatus::PossiblyExposed),
            "the wake keeps the exposure record for duplicate accounting"
        );
        assert_eq!(fanout.target_attempt_count(0), 1);
        assert_eq!(
            fanout.wake_targets_for_restored_connectivity(),
            0,
            "a second edge before another attempt has nothing to wake"
        );
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
                    pre_send: false,
                    size_class: None,
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
                    pre_send: false,
                    size_class: None,
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

    /// mdk#2332: the single exposure transition. For every stored state,
    /// exposure bit and attempt result, the bit is never cleared, and stays
    /// clear only for a result proving nothing was sent, or for a definitive
    /// refusal of the attempt this value started.
    #[test]
    fn exposure_bit_stays_clear_only_for_proof_that_nothing_reached_a_relay() {
        #[derive(Clone, Copy, Debug, PartialEq)]
        enum Stored {
            NotAttempted,
            /// Marked by this value, which awaits the result.
            Current,
            /// Marked by this value, then copied: the copy holds the attempt.
            CurrentCopy,
            /// Marked, then loaded from storage: a crash interrupted it.
            Interrupted,
            Unavailable,
            Exposed,
            /// `RetryableUnavailable` stored before pre-send proof existed:
            /// its failure is a relay's `rate-limited:` answer, its bit clear.
            LegacyAnswered,
            /// Each of these, then marked again: the current attempt.
            RetriedAfterUnavailable,
            RetriedAfterAnswer,
            RetriedAfterExposure,
        }
        #[derive(Clone, Copy, Debug, PartialEq)]
        enum Outcome {
            Accepted,
            /// No connection was made.
            PreSend,
            /// The adapter refused the event unsent: a known limit or the
            /// commit size floor.
            LocalRefusal,
            /// `invalid:`, `blocked:` and the rest.
            Definitive,
            /// `rate-limited:` or `auth-required:`.
            RetryableAnswer,
            Timeout,
            CloseAfterWrite,
            Unclassified,
        }
        use FanoutTargetStatus::{
            Accepted as A, Failed as F, PossiblyExposed as PE, RetryableUnavailable as RU,
        };
        use Outcome::*;
        use Stored::*;

        let endpoint = TransportEndpoint("wss://one.example".into());
        let failure = |kind, category, pre_send| TransportEndpointFailure {
            endpoint: endpoint.clone(),
            reason: "scripted".into(),
            kind,
            rejection_category: category,
            size_class: None,
            pre_send,
        };
        let stored = |state: Stored, bit: bool| {
            let (state, retried) = match state {
                RetriedAfterUnavailable => (Unavailable, true),
                RetriedAfterAnswer => (LegacyAnswered, true),
                RetriedAfterExposure => (Exposed, true),
                state => (state, false),
            };
            let mut fanout = OutboundFanout::stage(
                fanout_request(),
                Some(crate::engine_state::PendingStateRef::new(9)),
                Some(GroupId::new(vec![0xD4; 16])),
                55,
            )
            .unwrap();
            if state != NotAttempted {
                fanout.mark_attempt_started_at(0, 100).unwrap();
            }
            match state {
                NotAttempted | Current => {}
                RetriedAfterUnavailable | RetriedAfterAnswer | RetriedAfterExposure => {
                    unreachable!("mapped to the state it retries")
                }
                CurrentCopy => fanout = fanout.clone(),
                Interrupted => {
                    fanout = serde_json::from_slice(&serde_json::to_vec(&fanout).unwrap()).unwrap();
                }
                Unavailable | LegacyAnswered => {
                    fanout
                        .record_target_failure(
                            0,
                            failure(
                                TransportEndpointFailureKind::RetryableUnavailable,
                                None,
                                true,
                            ),
                        )
                        .unwrap();
                }
                Exposed => {
                    fanout
                        .record_target_failure(
                            0,
                            failure(TransportEndpointFailureKind::PossiblyExposed, None, false),
                        )
                        .unwrap();
                }
            }
            // A clear bit on a `PossiblyExposed` target is a row written
            // before the bit existed; a set one on an outstanding target is
            // a row written by an earlier ambiguous attempt.
            fanout.target_possible_exposure[0] = bit;
            if state == LegacyAnswered {
                fanout.target_failures[0] = Some(failure(
                    TransportEndpointFailureKind::RetryableUnavailable,
                    Some(TransportEndpointRejectionCategory::RateLimited),
                    false,
                ));
                // A row with no proof serializes as one written before the
                // proof existed did.
                let row = serde_json::to_vec(&fanout).unwrap();
                assert!(!String::from_utf8_lossy(&row).contains("pre_send"));
                fanout = serde_json::from_slice(&row).unwrap();
            }
            if retried {
                fanout.mark_attempt_started_at(0, 200).unwrap();
            }
            fanout
        };
        let apply = |fanout: &mut OutboundFanout, outcome: Outcome| {
            use TransportEndpointFailureKind::*;
            use TransportEndpointRejectionCategory as Category;
            match outcome {
                Outcome::Accepted => fanout.mark_target_accepted(0),
                Unclassified => fanout.mark_target_failed(0),
                PreSend => {
                    fanout.record_target_failure(0, failure(RetryableUnavailable, None, true))
                }
                LocalRefusal => fanout.record_target_failure(
                    0,
                    TransportEndpointFailure::over_known_limit(endpoint.clone(), 70_000),
                ),
                Definitive => fanout.record_target_failure(
                    0,
                    failure(TerminalRejected, Some(Category::Invalid), false),
                ),
                RetryableAnswer => fanout.record_target_failure(
                    0,
                    failure(RetryableUnavailable, Some(Category::RateLimited), false),
                ),
                Timeout | CloseAfterWrite => {
                    fanout.record_target_failure(0, failure(PossiblyExposed, None, false))
                }
            }
            .unwrap();
        };

        // With the bit clear before the result: the status and bit after it.
        let clear_rows = [
            (NotAttempted, Accepted, A, false),
            (NotAttempted, PreSend, RU, false),
            (NotAttempted, LocalRefusal, F, false),
            (NotAttempted, Definitive, PE, true),
            (NotAttempted, RetryableAnswer, PE, true),
            (NotAttempted, Timeout, PE, true),
            (NotAttempted, CloseAfterWrite, PE, true),
            (NotAttempted, Unclassified, F, true),
            (Current, Accepted, A, false),
            (Current, PreSend, RU, false),
            (Current, LocalRefusal, F, false),
            (Current, Definitive, F, false),
            (Current, RetryableAnswer, PE, true),
            (Current, Timeout, PE, true),
            (Current, CloseAfterWrite, PE, true),
            (Current, Unclassified, F, true),
            (CurrentCopy, Accepted, A, false),
            (CurrentCopy, PreSend, RU, false),
            (CurrentCopy, LocalRefusal, F, false),
            (CurrentCopy, Definitive, F, false),
            (CurrentCopy, RetryableAnswer, PE, true),
            (CurrentCopy, Timeout, PE, true),
            (CurrentCopy, CloseAfterWrite, PE, true),
            (CurrentCopy, Unclassified, F, true),
            (Interrupted, Accepted, A, false),
            (Interrupted, PreSend, PE, true),
            (Interrupted, LocalRefusal, PE, true),
            (Interrupted, Definitive, PE, true),
            (Interrupted, RetryableAnswer, PE, true),
            (Interrupted, Timeout, PE, true),
            (Interrupted, CloseAfterWrite, PE, true),
            (Interrupted, Unclassified, F, true),
            (Unavailable, Accepted, A, false),
            (Unavailable, PreSend, RU, false),
            (Unavailable, LocalRefusal, F, false),
            (Unavailable, Definitive, PE, true),
            (Unavailable, RetryableAnswer, PE, true),
            (Unavailable, Timeout, PE, true),
            (Unavailable, CloseAfterWrite, PE, true),
            (Unavailable, Unclassified, F, true),
            // A `PossiblyExposed` status is exposure whatever its bit says.
            (Exposed, Accepted, A, true),
            (Exposed, PreSend, PE, true),
            (Exposed, LocalRefusal, PE, true),
            (Exposed, Definitive, PE, true),
            (Exposed, RetryableAnswer, PE, true),
            (Exposed, Timeout, PE, true),
            (Exposed, CloseAfterWrite, PE, true),
            (Exposed, Unclassified, F, true),
            (LegacyAnswered, Accepted, A, true),
            (LegacyAnswered, PreSend, PE, true),
            (LegacyAnswered, LocalRefusal, PE, true),
            (LegacyAnswered, Definitive, PE, true),
            (LegacyAnswered, RetryableAnswer, PE, true),
            (LegacyAnswered, Timeout, PE, true),
            (LegacyAnswered, CloseAfterWrite, PE, true),
            (LegacyAnswered, Unclassified, F, true),
            (RetriedAfterUnavailable, Accepted, A, false),
            (RetriedAfterUnavailable, PreSend, RU, false),
            (RetriedAfterUnavailable, LocalRefusal, F, false),
            (RetriedAfterUnavailable, Definitive, F, false),
            (RetriedAfterUnavailable, RetryableAnswer, PE, true),
            (RetriedAfterUnavailable, Timeout, PE, true),
            (RetriedAfterUnavailable, CloseAfterWrite, PE, true),
            (RetriedAfterUnavailable, Unclassified, F, true),
            (RetriedAfterAnswer, Accepted, A, true),
            (RetriedAfterAnswer, PreSend, PE, true),
            (RetriedAfterAnswer, LocalRefusal, PE, true),
            (RetriedAfterAnswer, Definitive, PE, true),
            (RetriedAfterAnswer, RetryableAnswer, PE, true),
            (RetriedAfterAnswer, Timeout, PE, true),
            (RetriedAfterAnswer, CloseAfterWrite, PE, true),
            (RetriedAfterAnswer, Unclassified, F, true),
            (RetriedAfterExposure, Accepted, A, true),
            (RetriedAfterExposure, PreSend, PE, true),
            (RetriedAfterExposure, LocalRefusal, PE, true),
            (RetriedAfterExposure, Definitive, PE, true),
            (RetriedAfterExposure, RetryableAnswer, PE, true),
            (RetriedAfterExposure, Timeout, PE, true),
            (RetriedAfterExposure, CloseAfterWrite, PE, true),
            (RetriedAfterExposure, Unclassified, F, true),
        ];
        for (state, outcome, status, bit) in clear_rows {
            for bit_before in [false, true] {
                let before = stored(state, bit_before);
                let mut after = before.clone();
                apply(&mut after, outcome);
                // A set bit is never cleared, and keeps every failure exposed.
                let (status, bit) = if bit_before {
                    let status = match outcome {
                        Accepted => A,
                        Unclassified => F,
                        _ => PE,
                    };
                    (status, true)
                } else {
                    (status, bit)
                };
                let case = format!("{state:?} with bit {bit_before}, then {outcome:?}");
                assert_eq!(after.target_status(0), Some(status), "{case}");
                assert_eq!(after.target_possible_exposure[0], bit, "{case}");
                assert_eq!(
                    after.possible_exposure(),
                    bit,
                    "{case}: the fanout reports the bit"
                );
                // Storage admits every result recorded out of `Attempting`,
                // and every failure recorded before marking. An acceptance
                // with no attempt in flight is not an edge this rule adds.
                if matches!(
                    state,
                    Current
                        | CurrentCopy
                        | Interrupted
                        | RetriedAfterUnavailable
                        | RetriedAfterAnswer
                        | RetriedAfterExposure
                ) || !matches!(outcome, Accepted | Unclassified)
                {
                    after
                        .validate_successor_of(&before)
                        .unwrap_or_else(|error| panic!("{case}: storage refuses it: {error}"));
                }
            }
        }
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
                    pre_send: false,
                    size_class: None,
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
                        pre_send: false,
                        size_class: None,
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

    /// A refusal before sending against a known limit proves size like a
    /// relay's size answer does, alone or mixed with relay answers, while an
    /// unexposed failure of any other cause proves nothing (mdk#2334).
    #[test]
    fn local_refusals_over_known_limits_prove_size_like_relay_refusals() {
        let a = TransportEndpoint("wss://first.example".into());
        let b = TransportEndpoint("wss://second.example".into());
        let targets = [a.clone(), b.clone()];
        let local = |endpoint: &TransportEndpoint| {
            TransportEndpointFailure::over_known_limit(endpoint.clone(), 70 * 1024)
        };
        let relay = TransportEndpointFailure {
            pre_send: false,
            endpoint: b.clone(),
            reason: "relay rejected event (too-large)".into(),
            kind: TransportEndpointFailureKind::TerminalRejected,
            rejection_category: Some(TransportEndpointRejectionCategory::TooLarge),
            size_class: Some(EventSizeClass::From64To128Kib),
        };
        assert_eq!(
            EventSizeClass::from_rejected_targets(&targets, &[local(&a), local(&b)]),
            Some(EventSizeClass::From64To128Kib)
        );
        assert_eq!(
            EventSizeClass::from_rejected_targets(&targets, &[local(&a), relay]),
            Some(EventSizeClass::From64To128Kib)
        );
        let mut offline = local(&b);
        offline.rejection_category = None;
        assert_eq!(
            EventSizeClass::from_rejected_targets(&targets, &[local(&a), offline]),
            None
        );
    }

    #[test]
    fn coarse_event_size_classes_have_fixed_boundaries() {
        for (bytes, expected) in [
            (0, EventSizeClass::Under64Kib),
            (65535, EventSizeClass::Under64Kib),
            (65536, EventSizeClass::From64To128Kib),
            (131071, EventSizeClass::From64To128Kib),
            (131072, EventSizeClass::From128To256Kib),
            (262144, EventSizeClass::From256To512Kib),
            (524288, EventSizeClass::From512KibTo1Mib),
            (1048576, EventSizeClass::From1To2Mib),
            (2097152, EventSizeClass::From2To4Mib),
            (4194304, EventSizeClass::From2To4Mib),
            (4194305, EventSizeClass::Over4Mib),
        ] {
            assert_eq!(EventSizeClass::of_bytes(bytes), expected);
            let encoded = serde_json::to_value(expected).unwrap();
            assert_eq!(encoded, serde_json::json!(expected.as_str()));
            assert_eq!(
                serde_json::from_value::<EventSizeClass>(encoded).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn endpoint_failure_without_kind_deserializes_conservatively() {
        let failure: TransportEndpointFailure = serde_json::from_value(serde_json::json!({
            "endpoint": "wss://relay.example",
            "reason": "legacy adapter error"
        }))
        .unwrap();

        assert_eq!(failure.kind, TransportEndpointFailureKind::PossiblyExposed);
        assert_eq!(
            failure.size_class, None,
            "old rows have no local size proof"
        );
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
    fn frozen_fanout_round_trip_preserves_application_message_context() {
        let mut fanout = OutboundFanout::stage(fanout_request(), None, None, 55).unwrap();
        let application = OutboundApplicationMessage {
            authority: None,
            group_id: GroupId::new(vec![0xD4; 16]),
            app_event_id: "app-event-1".into(),
            source_epoch: EpochId(7),
            retention: AppMessageRetentionDecision::new(100, 30),
        };
        fanout.set_application_message(application.clone()).unwrap();

        let encoded = serde_json::to_vec(&fanout).unwrap();
        let restored: OutboundFanout = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(restored.application_message(), Some(&application));

        let mut legacy = serde_json::to_value(fanout).unwrap();
        legacy
            .as_object_mut()
            .unwrap()
            .remove("application_message");
        let legacy: OutboundFanout = serde_json::from_value(legacy).unwrap();
        assert!(legacy.application_message().is_none());
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
    fn recovery_inbox_match() {
        let recipient = MemberId::new(vec![0xE5; 32]);
        let mut request = fanout_request();
        request.message.envelope = TransportEnvelope::Welcome {
            recipient: recipient.clone(),
        };
        assert!(request.validate_envelope_matches_target().is_err());
        request.target = TransportPublishTarget::Inbox {
            recipient,
            endpoints: vec![TransportEndpoint("wss://one.example".into())],
        };
        assert!(request.validate_envelope_matches_target().is_ok());
        if let TransportPublishTarget::Inbox { recipient, .. } = &mut request.target {
            *recipient = MemberId::new(vec![0xE6; 32]);
        }
        assert!(request.validate_envelope_matches_target().is_err());
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
                    ack_kind: None,
                })
                .collect(),
            failed: (0..failed)
                .map(|i| TransportEndpointFailure {
                    pre_send: false,
                    size_class: None,
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
    fn endpoint_receipt_ack_kind_is_optional_and_typed() {
        let legacy = r#"{"endpoint":"wss://relay.example","accepted_at":null}"#;
        let receipt: TransportEndpointReceipt = serde_json::from_str(legacy).unwrap();
        assert_eq!(receipt.ack_kind, None);
        assert_eq!(serde_json::to_string(&receipt).unwrap(), legacy);

        for (kind, encoded) in [
            (TransportEndpointAckKind::Affirmative, "affirmative"),
            (TransportEndpointAckKind::Duplicate, "duplicate"),
        ] {
            let receipt = TransportEndpointReceipt {
                ack_kind: Some(kind),
                ..receipt.clone()
            };
            let json = serde_json::to_string(&receipt).unwrap();
            assert!(json.contains(&format!("\"ack_kind\":\"{encoded}\"")));
            assert_eq!(
                serde_json::from_str::<TransportEndpointReceipt>(&json).unwrap(),
                receipt
            );
        }
        assert!(
            serde_json::from_str::<TransportEndpointReceipt>(
                r#"{"endpoint":"wss://relay.example","accepted_at":null,"ack_kind":"guessed"}"#
            )
            .is_err()
        );
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

    #[test]
    fn adapter_error_privacy_safe_kind_never_carries_display_detail() {
        let secret = "wss://secret.example/npub1secret";
        let cases = [
            (
                TransportAdapterError::AccountNotActive(MemberId::new(vec![0xA1; 32])),
                "transport_account_not_active",
            ),
            (TransportAdapterError::Closed, "transport_closed"),
            (
                TransportAdapterError::InvalidInboundEncoding,
                "transport_invalid_inbound_encoding",
            ),
            (
                TransportAdapterError::InvalidInboundSignature,
                "transport_invalid_inbound_signature",
            ),
            (
                TransportAdapterError::PublishTargetMismatch {
                    envelope: secret.into(),
                    target: secret.into(),
                },
                "transport_publish_target_mismatch",
            ),
            (
                TransportAdapterError::Subscription(secret.into()),
                "transport_subscription_failed",
            ),
            (
                TransportAdapterError::Publish(secret.into()),
                "transport_publish_failed",
            ),
            (
                TransportAdapterError::PublishEndpoints(
                    TransportPublishFailure::with_endpoint_failures(secret, Vec::new()),
                ),
                "insufficient_publish_acknowledgements",
            ),
            (
                TransportAdapterError::Backend(secret.into()),
                "transport_backend",
            ),
            (
                TransportAdapterError::Other(secret.into()),
                "transport_other",
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(error.privacy_safe_kind(), expected, "{error:?}");
        }
    }
}
