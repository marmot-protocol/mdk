//! Typed outcomes from [`crate::engine::CgkaEngine::ingest`] plus the
//! peeled-message intermediate form.
//!
//! `IngestOutcome` separates pre-convergence exclusions, convergence
//! dispositions, and canonical local state. Hard errors stay in `EngineError`.

use crate::transport::TransportMessage;
use crate::types::{EpochId, GroupId, MemberId, MessageId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum IngestOutcome {
    /// Message was validated, applied to the group's MLS state, and any
    /// resulting `GroupEvent`s were enqueued for `drain_events`.
    Processed,
    /// Message was accepted into durable storage but not yet applied because
    /// the group is temporarily not ingestible, usually during a local
    /// publish-before-apply transition. The engine replays buffered messages
    /// when the group returns to `Stable`.
    ///
    /// That replay is owned by the application's convergence drain
    /// (`drain_pending_convergence_groups` →
    /// `converge_stored_openmls_messages`), not by `replay_buffered_messages`,
    /// which only re-ingests retained raw transport rows. So an engine seam that
    /// leaves a retained content row unapplied MUST schedule the group for
    /// convergence; otherwise this outcome promises a replay that never happens.
    Buffered { group_id: GroupId, epoch: EpochId },
    /// Rejected before convergence admission because routing or deduplication
    /// proved the input cannot affect this account-device's canonical state.
    Ignored { category: InputRejectionCategory },
    /// A canonical local condition blocked processing. This is deliberately
    /// separate from convergence dispositions.
    LocalState { state: LocalIngestState },
    /// The transport object could not be decoded or decrypted with the
    /// currently available transport context, but a later canonical epoch,
    /// retained candidate, staged state, or repair may make it recoverable.
    /// The object remains outside convergence until peeling succeeds.
    ///
    /// `lineage` says which recovery can possibly help. See
    /// [`DeferralLineage`] for what that claim is and — importantly — what it
    /// is not.
    TransportDeferred {
        group_id: GroupId,
        lineage: DeferralLineage,
    },
    /// A local resource bound prevented the engine from retaining or
    /// processing an otherwise unclassified transport object. This is not a
    /// protocol rejection and must not make same-id redelivery a duplicate.
    ResourceRefused {
        group_id: GroupId,
        resource: InboundResourceLimit,
    },
    /// Message was not applied. The variant names why — callers log by
    /// category rather than pattern-matching error strings.
    Stale { reason: StaleReason },
    /// A standalone or commit-carried MLS proposal failed Marmot semantic
    /// admission before it could enter pending state or affect group state.
    Rejected { category: ProposalRejectionCategory },
}

/// Which recovery can make a [`IngestOutcome::TransportDeferred`] object
/// readable.
///
/// **This is a claim about the group, not about the message.** At the deferral
/// point decryption failed under the live context, every retained snapshot, and
/// every candidate branch the engine had materialized, so nothing observable
/// separates one unreadable object from another. What the engine can still
/// state soundly is the shape of the group's stored commit graph, and that is
/// what decides whether fetching more history from relays is even the right
/// kind of answer.
///
/// The discriminator is deliberately one-way, in the same sense as the
/// candidate-branch context set it is derived from: [`Self::ContestedFork`] is
/// positive evidence, while [`Self::Uncontested`] is the absence of evidence
/// rather than proof of its opposite.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeferralLineage {
    /// No two retained commits fork from the same source epoch, so this device
    /// holds no evidence that any of this group's traffic is sealed under a
    /// branch it has not adopted.
    ///
    /// Not a positive claim that the object is merely ahead of this device. A
    /// fork whose rival commit never reached this device looks exactly like no
    /// fork at all — and that case is precisely the one a relay backfill is the
    /// right answer for, because the commit it needs really is missing history.
    Uncontested,
    /// Two retained commits fork from the same source epoch: part of this
    /// group's traffic is sealed under a branch this device has not adopted.
    ///
    /// A relay backfill cannot help such an object. The bytes already arrived;
    /// what is missing is not history but adoption, and only convergence
    /// adjudication over the commits already stored can supply it.
    ContestedFork,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum InputRejectionCategory {
    Duplicate,
    OwnEcho,
    WrongRecipient,
    UnknownGroup,
    InvalidEncoding,
    InvalidSignature,
    UnsupportedRequiredFeature,
    AuthorizationFailed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum InboundResourceLimit {
    /// The per-group durable transport-deferred row cap is full.
    TransportDeferredCapacity,
    /// A retained transport object exhausted its changed-context retry budget
    /// and was retired without a terminal validity claim.
    TransportDeferredRetryBudget,
    /// A retained transport object exhausted its durable local residence
    /// budget and was retired without a terminal validity claim.
    TransportDeferredResidenceBudget,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LocalIngestState {
    /// Authenticated MLS state records this account-device's removal. The
    /// engine has already performed the realizing-removal side effects.
    Removed,
    /// Hydration validation froze the local group copy pending repair.
    Quarantined,
}

/// Stable rejection taxonomy for authenticated MLS proposals that fail
/// Marmot's semantic admission rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ProposalRejectionCategory {
    /// The authenticated sender is not authorized for this proposal.
    AuthorizationFailed,
    /// The active protocol profile does not admit this proposal type.
    UnsupportedProposal,
    /// Proposal bytes, component data, or resulting state are invalid.
    InvalidEncoding,
    /// The proposal cannot be authenticated to a valid current member.
    InvalidSignature,
    /// SelfRemove violates the active member-departure or admin rules.
    InvalidSelfRemove,
}

/// Why an inbound message was not processed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StaleReason {
    /// The engine has already seen this `MessageId`. Coordinator dedup.
    #[deprecated(note = "use IngestOutcome::Ignored { category: Duplicate }")]
    AlreadySeen,
    /// The engine is already at or past the message's epoch. Commonly hit
    /// when a commit arrives after a welcome that already advanced the
    /// recipient.
    AlreadyAtEpoch {
        current: EpochId,
        msg_epoch: EpochId,
    },
    /// Input addressed to another member, or whose signed transport routing
    /// metadata conflicts with the envelope presented to the engine.
    #[deprecated(note = "use IngestOutcome::Ignored { category: WrongRecipient }")]
    NotForThisClient,
    /// No local group matches this message's routing.
    #[deprecated(note = "use IngestOutcome::Ignored { category: UnknownGroup }")]
    UnknownGroup,
    /// The message is our own commit echoed back by the transport.
    #[deprecated(note = "use IngestOutcome::Ignored { category: OwnEcho }")]
    OwnEcho,
    /// The message predates this account-device's membership and can never
    /// decrypt on this local copy.
    PreMembership,
    /// Convergence excluded the input below the retained anchor.
    BeyondAnchor,
    /// Convergence excluded the input beyond the rollback horizon.
    BeyondRollbackHorizon,
    /// The application-message decryption window no longer retains its
    /// source epoch.
    BeyondAppRetention,
    /// The message belongs only to a losing canonical branch.
    LosingBranch,
    /// Authenticated input is invalid against the selected candidate state.
    InvalidAgainstCanonicalState,
    /// The local retained canonical state records our own removal from this
    /// group, so later group input can never be processed here. Terminal for
    /// the group on this client. Processing input that classifies as
    /// `SelfEvicted` also performs "realizing removal" when not already done:
    /// emit a self-removed state notification and mark the local group copy
    /// removed (spec `protocol-core/member-departure.md`, registered as the
    /// `SelfEvicted` outcome in `foundation/errors.md`). Only authenticated
    /// evidence (the local MLS state records the eviction) maps here — a bare
    /// decrypt failure is a missing-history/repair condition, never
    /// `SelfEvicted`.
    #[deprecated(note = "use IngestOutcome::LocalState { state: Removed }")]
    SelfEvicted,
    /// The group is under hydration quarantine: it failed session-open
    /// validation and is frozen until explicit repair. The message was not
    /// applied and no group state changed, but the raw input is retained
    /// durably and replays automatically once
    /// `retry_hydrate_quarantined_group` (or an authenticated re-join
    /// welcome) clears the quarantine. Terminal for the message until then.
    /// The application can read the quarantine reason from
    /// `quarantined_groups()`.
    #[deprecated(note = "use IngestOutcome::LocalState { state: Quarantined }")]
    Quarantined,
}

/// Decrypted inbound message ready for engine processing.
///
/// Produced by [`crate::peeler::TransportPeeler::peel_group_message`] /
/// [`crate::peeler::TransportPeeler::peel_welcome`]. The `kind` field is the
/// structural discriminator — application messages, MLS commits, welcomes,
/// etc.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeeledMessage {
    pub id: MessageId,
    pub group_id: Option<GroupId>,
    pub sender: Option<MemberId>,
    pub content: PeeledContent,
    pub origin: TransportMessage,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeeledContent {
    /// Inner MLS message (commit, application, proposal, etc.) — engine
    /// decides how to apply.
    MlsMessage { bytes: Vec<u8> },
    /// Welcome payload (MLS welcome bytes).
    Welcome { bytes: Vec<u8> },
}
