//! Bytes-first OpenMLS projection and canonicalization helpers.
//!
//! OpenMLS protocol objects are intentionally consumed by processing APIs.
//! The canonicalization contract should therefore retain bytes and derived
//! observations, not long-lived OpenMLS values. This module can either
//! snapshot-and-replay messages for candidate materialization or apply a
//! selected canonical branch to retained storage.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use crate::provider::EngineOpenMlsProvider;
use cgka_traits::app_event::AppMessageRetentionDecision;
use cgka_traits::engine::CommitOrderingPriority;
use cgka_traits::group::{Member, ProtocolProfile};
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::message::{MessageRecord, MessageState, StoredMessagePayload};
use cgka_traits::storage::{StorageError, StorageProvider};
use cgka_traits::transport::{TransportEnvelope, TransportMessage};
use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
use openmls::component::ComponentData;
use openmls::group::{
    MlsGroup, MlsGroupStateError, ProcessMessageError, ResolveAppDataCommitError, ValidationError,
};
use openmls::messages::proposals::AppDataUpdateOperation;
use openmls::prelude::{
    BasicCredential, ContentType, MlsMessageBodyIn, MlsMessageIn, ProcessedMessage,
    ProcessedMessageContent, Proposal, ProtocolMessage, Sender,
};
use openmls_rust_crypto::RustCrypto;
use openmls_traits::OpenMlsProvider;
use sha2::{Digest, Sha256};
use tls_codec::{Deserialize as _, Serialize as TlsSerialize};

use crate::canonicalization::{
    CanonicalizationError, CanonicalizationInput, CanonicalizationPolicy, CanonicalizationResult,
    CanonicalizationState, ConvergenceStatus, DeferredMessage, DeferredMessageReason,
    DroppedMessage, DroppedMessageReason, InvalidatedAppMessageReason, MaterializedCandidate,
    MessageKind, OutboundIntent, PeeledMessage, PeeledMessageKind,
    canonicalize_with_materialized_candidates,
};
use crate::convergence::BranchCandidate;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenMlsContentKind {
    Application,
    Proposal,
    Commit,
    Welcome,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenMlsMessageProjection {
    pub kind: OpenMlsContentKind,
    pub source_epoch: Option<u64>,
    pub message_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenMlsCandidatePath {
    pub branch_id: String,
    pub messages: Vec<TransportMessage>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenMlsMaterializedCandidate {
    pub branch_id: String,
    pub fork_epoch: u64,
    pub tip_epoch: u64,
    pub tip_priority: CommitOrderingPriority,
    pub tip_committer: Vec<u8>,
    pub tip_digest: [u8; 32],
    pub commit_message_ids: Vec<String>,
    pub consumed_proposal_refs: Vec<String>,
    pub observations: Vec<OpenMlsReplayObservation>,
}

impl OpenMlsMaterializedCandidate {
    pub fn branch_candidate(&self) -> BranchCandidate {
        BranchCandidate {
            id: self.branch_id.clone(),
            fork_epoch: self.fork_epoch,
            tip_epoch: self.tip_epoch,
            tip_priority: self.tip_priority,
            tip_committer: self.tip_committer.clone(),
            tip_digest: self.tip_digest,
            app_witnesses: vec![],
        }
    }

    pub fn canonical_materialized_candidate(&self) -> MaterializedCandidate {
        self.canonical_materialized_candidate_with_proposal_ids(&BTreeMap::new())
    }

    pub fn canonical_materialized_candidate_with_proposal_ids(
        &self,
        proposal_id_by_ref: &BTreeMap<String, String>,
    ) -> MaterializedCandidate {
        MaterializedCandidate {
            branch: self.branch_candidate(),
            commit_message_ids: self.commit_message_ids.clone(),
            consumed_proposal_ids: self
                .consumed_proposal_refs
                .iter()
                .map(|proposal_ref| {
                    proposal_id_by_ref
                        .get(proposal_ref)
                        .cloned()
                        .unwrap_or_else(|| proposal_ref.clone())
                })
                .collect(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenMlsCanonicalizationBatch {
    pub state: CanonicalizationState,
    pub candidate_paths: Vec<OpenMlsCandidatePath>,
    pub pending_messages: Vec<TransportMessage>,
    /// Hex ids of app messages in `pending_messages` already applied on a prior
    /// pass (stored `Processed`), re-admitted for witness scoring only — never
    /// re-delivered. Empty for callers that pass only fresh messages.
    pub already_delivered_app_ids: BTreeSet<String>,
    pub outbound_intents: Vec<OutboundIntent>,
    pub policy: CanonicalizationPolicy,
    pub now_ms: u64,
}

#[derive(Clone, Debug)]
struct StoredCommitMessage {
    message: TransportMessage,
    source_epoch: u64,
    digest: [u8; 32],
    state: MessageState,
}

#[derive(Clone, Debug)]
struct CandidatePathProbe {
    messages: Vec<TransportMessage>,
    digests: Vec<[u8; 32]>,
    tip_epoch: u64,
    /// The materialized candidate from the probe that produced this node (folding only
    /// pending proposals — not applications). `None` only for the empty seed node, which is
    /// never completed. Retained so a completed path can be reused by the canonicalization
    /// core without a second full replay (#635), on the app-free path where it is
    /// byte-identical to a fresh materialize.
    materialized: Option<OpenMlsMaterializedCandidate>,
}

#[derive(Clone, Debug)]
struct StoredOpenMlsCandidatePathResult {
    candidate_paths: Vec<OpenMlsCandidatePath>,
    /// Terminal materialized candidates for `candidate_paths`, in the same order. Reusable by
    /// the canonicalization core only when the pass has no pending application messages (the
    /// BFS folds proposals but not applications), otherwise the core re-materializes. Empty
    /// (or shorter than `candidate_paths`) means "do not reuse".
    materialized: Vec<OpenMlsMaterializedCandidate>,
    invalid_commit_drops: Vec<DroppedMessage>,
    /// Stored commit inputs that could not reach any candidate parent in this
    /// frozen batch and did not fail validation terminally.
    unmaterialized_commit_ids: Vec<String>,
}

/// Bounds the total OpenMLS replay round-trips a single convergence pass may perform, so
/// attacker-driven same-epoch commit branching cannot amplify into unbounded CPU/IO (#635).
/// The pass fails closed (`ReplayBudgetExceeded`) rather than returning a partial result.
struct ReplayBudget {
    remaining: u64,
    #[cfg(feature = "test-conformance-snapshot")]
    consumed: u64,
}

/// Multiplicative slack over the linear `commits × (max_rewind_commits + 1)` probe estimate.
/// Generous enough that legitimate forks never trip the budget; small enough that pathological
/// `B^D` branching fails closed well before it materializes.
pub(crate) const CANDIDATE_REPLAY_BUDGET_SLACK: u64 = 4;
/// Floor so tiny passes (few commits, shallow rewind) always have headroom.
pub(crate) const CANDIDATE_REPLAY_BUDGET_FLOOR: u64 = 32;

impl ReplayBudget {
    fn new(limit: u64) -> Self {
        Self {
            remaining: limit,
            #[cfg(feature = "test-conformance-snapshot")]
            consumed: 0,
        }
    }

    /// Unlimited budget for callers outside the bounded convergence BFS (e.g. the public
    /// `materialize_openmls_candidate_paths`, used directly by conformance vectors).
    fn unlimited() -> Self {
        Self {
            remaining: u64::MAX,
            #[cfg(feature = "test-conformance-snapshot")]
            consumed: 0,
        }
    }

    /// Derive the per-pass replay ceiling from the number of competing commits and the rewind
    /// horizon. Saturating throughout so a hostile large input cannot overflow into a small cap.
    fn for_pass(commit_count: usize, max_rewind_commits: u64) -> Self {
        let limit = (commit_count as u64)
            .saturating_mul(max_rewind_commits.saturating_add(1))
            .saturating_mul(CANDIDATE_REPLAY_BUDGET_SLACK)
            .saturating_add(CANDIDATE_REPLAY_BUDGET_FLOOR);
        Self::new(limit)
    }

    fn consume(&mut self) -> Result<(), OpenMlsProjectionError> {
        if self.remaining == 0 {
            return Err(OpenMlsProjectionError::ReplayBudgetExceeded);
        }
        self.remaining -= 1;
        #[cfg(feature = "test-conformance-snapshot")]
        {
            self.consumed = self.consumed.saturating_add(1);
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
enum CandidatePathProbeResult {
    Materialized(Option<OpenMlsMaterializedCandidate>),
    RejectedProposal {
        message_id: String,
        category: cgka_traits::ingest::ProposalRejectionCategory,
    },
    UnauthorizedCommit {
        message_id: String,
    },
    InvalidCommit {
        message_id: String,
        rejection_category: Option<cgka_traits::ingest::ProposalRejectionCategory>,
    },
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ReplayProfilePolicy {
    pub(crate) reject_legacy_group_additions: bool,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct StoredCanonicalizationOptions<'a> {
    pub(crate) replay_profile: ReplayProfilePolicy,
    pub(crate) admitted_message_ids: Option<&'a HashSet<MessageId>>,
    pub(crate) admit_app_witnesses: bool,
    pub(crate) replay_probe_budget_override: Option<u64>,
}

/// A transport peel context reconstructed from one authenticated competing
/// OpenMLS branch. It is deliberately memory-only: exporter bytes are held in
/// [`GroupContextSnapshot`] (and zeroized on drop), never copied into message
/// rows, reports, or forensic artifacts.
pub(crate) struct CandidatePeelContext {
    pub(crate) context: GroupContextSnapshot,
    pub(crate) source_epoch: EpochId,
    pub(crate) message_retention_seconds: Option<u64>,
}

impl Default for StoredCanonicalizationOptions<'_> {
    fn default() -> Self {
        Self {
            replay_profile: ReplayProfilePolicy::default(),
            admitted_message_ids: None,
            admit_app_witnesses: true,
            replay_probe_budget_override: None,
        }
    }
}

#[derive(Clone, Debug)]
struct StoredOpenMlsCanonicalizationWork {
    state: CanonicalizationState,
    commit_messages: Vec<StoredCommitMessage>,
    pending_messages: Vec<TransportMessage>,
    /// App ids in `pending_messages` re-admitted for witness scoring only (stored
    /// `Processed`). See [`OpenMlsCanonicalizationBatch::already_delivered_app_ids`].
    already_delivered_app_ids: BTreeSet<String>,
    outbound_intents: Vec<OutboundIntent>,
    policy: CanonicalizationPolicy,
    now_ms: u64,
    replay_start_epoch: u64,
    own_commits: PrevalidatedOwnCommits,
    profile_policy: ReplayProfilePolicy,
    admit_app_witnesses: bool,
    replay_probe_budget_override: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpenMlsReplayObservation {
    ProposalStored {
        message_id: String,
        source_epoch: u64,
        proposal_ref: String,
    },
    CommitStaged {
        message_id: String,
        source_epoch: u64,
        resulting_epoch: u64,
        priority: CommitOrderingPriority,
        committer: Vec<u8>,
        consumed_proposal_refs: Vec<String>,
    },
    ApplicationProcessed {
        message_id: String,
        source_epoch: u64,
        sender: Vec<u8>,
        payload: Vec<u8>,
        retention: AppMessageRetentionDecision,
        decrypted_payload_ref: String,
    },
    Ignored {
        message_id: String,
        kind: OpenMlsContentKind,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct OpenMlsReplayOutput {
    observations: Vec<OpenMlsReplayObservation>,
    final_epoch: u64,
    final_members: Vec<Member>,
}

#[derive(Debug)]
pub enum OpenMlsProjectionError {
    Decode(String),
    EmptyCandidatePath(String),
    CandidatePathDidNotCommit(String),
    UnsupportedMessageKind(OpenMlsContentKind),
    MissingGroup,
    Snapshot(String),
    Replay(String),
    RejectedProposal {
        message_id: String,
        category: cgka_traits::ingest::ProposalRejectionCategory,
    },
    UnauthorizedCommit {
        message_id: String,
    },
    InvalidCommit {
        message_id: String,
        reason: String,
        rejection_category: Option<cgka_traits::ingest::ProposalRejectionCategory>,
    },
    Serialize(String),
    Storage(String),
    InvalidPolicy(String),
    ReplayBudgetExceeded,
}

impl std::fmt::Display for OpenMlsProjectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenMlsProjectionError::Decode(e) => write!(f, "decode failed: {e}"),
            OpenMlsProjectionError::EmptyCandidatePath(path) => {
                write!(f, "candidate path has no messages: {path}")
            }
            OpenMlsProjectionError::CandidatePathDidNotCommit(path) => {
                write!(f, "candidate path did not stage a commit: {path}")
            }
            OpenMlsProjectionError::UnsupportedMessageKind(kind) => {
                write!(f, "unsupported MLS message kind for replay: {kind:?}")
            }
            OpenMlsProjectionError::MissingGroup => write!(f, "MLS group not found"),
            OpenMlsProjectionError::Snapshot(e) => write!(f, "snapshot failed: {e}"),
            OpenMlsProjectionError::Replay(e) => write!(f, "OpenMLS replay failed: {e}"),
            OpenMlsProjectionError::RejectedProposal {
                message_id,
                category,
            } => {
                write!(
                    f,
                    "rejected proposal {message_id}: {}",
                    crate::app_components::proposal_rejection_category_tag(*category)
                )
            }
            OpenMlsProjectionError::UnauthorizedCommit { message_id } => {
                write!(f, "unauthorized admin-gated commit: {message_id}")
            }
            OpenMlsProjectionError::InvalidCommit {
                message_id, reason, ..
            } => {
                write!(f, "invalid commit {message_id}: {reason}")
            }
            OpenMlsProjectionError::Serialize(e) => write!(f, "serialize failed: {e}"),
            OpenMlsProjectionError::Storage(e) => write!(f, "storage failed: {e}"),
            OpenMlsProjectionError::InvalidPolicy(e) => {
                write!(f, "invalid convergence policy: {e}")
            }
            OpenMlsProjectionError::ReplayBudgetExceeded => {
                write!(f, "convergence replay budget exceeded")
            }
        }
    }
}

impl std::error::Error for OpenMlsProjectionError {}

impl From<StorageError> for OpenMlsProjectionError {
    fn from(e: StorageError) -> Self {
        OpenMlsProjectionError::Storage(format!("{e:?}"))
    }
}

/// Own published-and-confirmed commits usable as pre-validated candidate-path
/// segments during stored-convergence materialization.
///
/// MLS cannot process a device's own commit through `process_message`, so a
/// candidate path containing one cannot be materialized by replay alone: after
/// a restart clears the in-memory `committed_from` guard, the own commit's
/// branch would silently drop out of branch selection and the device could be
/// reorged onto a losing sibling (or, with two restarted committers, the group
/// could fork permanently). Instead, an own `Processed` commit whose ordering
/// stamp was persisted at confirm time is realized by rolling the group
/// forward to the retained anchor snapshot at its resulting epoch — the exact
/// post-merge state the commit produced — and synthesizing its
/// `CommitStaged` observation from the stamp.
#[derive(Clone, Debug, Default)]
pub(crate) struct PrevalidatedOwnCommits {
    /// Confirm-stamped own `Processed` commits, keyed by wire-bytes digest.
    by_digest: BTreeMap<[u8; 32], cgka_traits::message::OwnCommitConvergenceStamp>,
    /// Digests of every `Processed` commit (own and others') — the canonical
    /// chain. An own commit is pre-validated only while the replayed path
    /// prefix stays canonical: it was created from the canonical state at its
    /// source epoch, so on any diverging prefix it must NOT apply.
    canonical_digests: BTreeSet<[u8; 32]>,
}

impl PrevalidatedOwnCommits {
    fn insert_canonical(&mut self, digest: [u8; 32]) {
        self.canonical_digests.insert(digest);
    }

    fn insert_stamped(
        &mut self,
        digest: [u8; 32],
        stamp: cgka_traits::message::OwnCommitConvergenceStamp,
    ) {
        self.by_digest.insert(digest, stamp);
    }

    fn stamp(&self, digest: &[u8; 32]) -> Option<&cgka_traits::message::OwnCommitConvergenceStamp> {
        self.by_digest.get(digest)
    }

    fn is_canonical(&self, digest: &[u8; 32]) -> bool {
        self.canonical_digests.contains(digest)
    }
}

/// Build the convergence ordering stamp for a staged local commit, captured
/// while the staged commit is still attached (confirm time). See
/// [`cgka_traits::message::OwnCommitConvergenceStamp`].
pub(crate) fn own_commit_stamp(
    staged: &openmls::group::StagedCommit,
    committer: MemberId,
) -> Result<cgka_traits::message::OwnCommitConvergenceStamp, cgka_traits::error::EngineError> {
    let priority = crate::app_components::commit_ordering_priority_for_staged(staged);
    let mut consumed_proposal_refs = staged
        .queued_proposals()
        .map(|proposal| tls_hex(proposal.proposal_reference_ref()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| cgka_traits::error::EngineError::Serialize(format!("{e}")))?;
    consumed_proposal_refs.sort();
    consumed_proposal_refs.dedup();
    Ok(cgka_traits::message::OwnCommitConvergenceStamp {
        committer,
        priority,
        consumed_proposal_refs,
    })
}

/// Give retained proposal rows the same terminal disposition when a local
/// commit is confirmed that stored convergence assigns when it selects that
/// commit. The staged commit records consumed proposal references, while
/// MessageStorage is keyed by content-derived message ids, so re-project the
/// current-epoch proposal rows against the pre-merge group and match the exact
/// authenticated references.
pub(crate) fn mark_consumed_proposal_records_processed<S: StorageProvider>(
    storage: &S,
    crypto: &RustCrypto,
    mls_group: &mut MlsGroup,
    group_id: &GroupId,
    source_epoch: EpochId,
    consumed_proposal_refs: &[String],
) -> Result<(), cgka_traits::error::EngineError> {
    if consumed_proposal_refs.is_empty() {
        return Ok(());
    }
    let consumed: BTreeSet<&str> = consumed_proposal_refs.iter().map(String::as_str).collect();
    let provider = EngineOpenMlsProvider::<S>::new(crypto, storage.mls_storage());
    for record in storage.list_messages(group_id, source_epoch)? {
        if record.epoch != source_epoch
            || !matches!(
                record.state,
                MessageState::Created | MessageState::Retryable
            )
        {
            continue;
        }
        let Ok(payload) = StoredMessagePayload::decode(&record.payload) else {
            continue;
        };
        let Some(message) = payload.as_openmls_wire() else {
            continue;
        };
        let Ok(Some(protocol)) = protocol_message_from_bytes(&message.payload) else {
            continue;
        };
        // Marmot's current handshake wire-format policy is public. Do not
        // replay a future private proposal here: OpenMLS decryption advances
        // the persisted secret tree, which is not an acceptable side effect
        // for disposition matching.
        if !matches!(&protocol, ProtocolMessage::PublicMessage(_)) {
            continue;
        }
        let Ok(processed) = mls_group.process_message(&provider, protocol) else {
            continue;
        };
        let ProcessedMessageContent::ProposalMessage(queued) = processed.into_content() else {
            continue;
        };
        let proposal_ref = tls_hex(queued.proposal_reference_ref())
            .map_err(|error| cgka_traits::error::EngineError::Serialize(error.to_string()))?;
        if consumed.contains(proposal_ref.as_str()) {
            storage.update_message_state(&record.id, MessageState::Processed)?;
        }
    }
    Ok(())
}

/// Mark the origin commit record `Processed` and, when a confirm-time stamp is
/// available, enrich its stored wire payload to `OwnCommitWire` in the same
/// write, so stored convergence can later rebuild this commit's branch as a
/// pre-validated candidate.
pub(crate) fn stamp_processed_own_commit_record<S: StorageProvider>(
    storage: &S,
    message_id: &MessageId,
    stamp: Option<cgka_traits::message::OwnCommitConvergenceStamp>,
) -> Result<(), cgka_traits::error::EngineError> {
    let Some(stamp) = stamp else {
        storage.update_message_state(message_id, MessageState::Processed)?;
        return Ok(());
    };
    let mut record = storage.get_message(message_id)?;
    let payload = StoredMessagePayload::decode(&record.payload)
        .map_err(|e| cgka_traits::error::EngineError::Serialize(format!("{e:?}")))?;
    let payload = match payload {
        StoredMessagePayload::OpenMlsWire(message)
        | StoredMessagePayload::OwnCommitWire { message, .. } => {
            StoredMessagePayload::own_commit_wire(message, stamp)
        }
        StoredMessagePayload::SignedOpenMlsWire {
            exact_message,
            openmls_message,
            ..
        } => StoredMessagePayload::SignedOpenMlsWire {
            exact_message,
            openmls_message,
            stamp: Some(stamp),
        },
        // Raw-transport rows never enter the OpenMLS candidate graph; a plain
        // state update preserves their shape.
        other @ (StoredMessagePayload::RawTransport(_)
        | StoredMessagePayload::OutboundWelcome(_)) => other,
    };
    record.state = MessageState::Processed;
    record.payload = payload
        .encode()
        .map_err(|e| cgka_traits::error::EngineError::Serialize(format!("{e:?}")))?;
    storage.put_message(&record)?;
    Ok(())
}

pub fn project_mls_message(
    bytes: &[u8],
) -> Result<OpenMlsMessageProjection, OpenMlsProjectionError> {
    let digest = message_digest(bytes);
    let msg = MlsMessageIn::tls_deserialize_exact(bytes)
        .map_err(|e| OpenMlsProjectionError::Decode(format!("{e:?}")))?;
    let body = msg.extract();
    let Some(protocol) = protocol_message_from_body(body)? else {
        return Ok(OpenMlsMessageProjection {
            kind: OpenMlsContentKind::Welcome,
            source_epoch: None,
            message_digest: digest,
        });
    };
    Ok(OpenMlsMessageProjection {
        kind: kind_from_content_type(protocol.content_type()),
        source_epoch: Some(protocol.epoch().as_u64()),
        message_digest: digest,
    })
}

/// Retire deferred commits that can no longer enter the retained candidate
/// graph.
///
/// The pass seeder intentionally lists only rows at or above the retained
/// anchor. Without this pre-seed sweep, an orphaned commit that aged below the
/// anchor would stop being admitted before canonicalization could give it a
/// terminal disposition, leaving it `ConvergenceDeferred` forever. Malformed,
/// non-OpenMLS, and non-commit rows remain untouched: this maintenance path
/// must not turn old unrelated storage damage into a convergence failure.
pub(crate) fn retire_stale_convergence_deferred_commits<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    retained_anchor_epoch: u64,
) -> Result<Vec<(MessageId, EpochId)>, OpenMlsProjectionError> {
    storage.with_transaction(|storage| {
        let records = storage.list_messages(group_id, EpochId(0))?;
        let mut retired = Vec::new();

        for record in records {
            if record.state != MessageState::ConvergenceDeferred {
                continue;
            }
            let Ok(payload) = StoredMessagePayload::decode(&record.payload) else {
                continue;
            };
            let Some(message) = payload.as_openmls_wire() else {
                continue;
            };
            let Ok(projection) = project_mls_message(&message.payload) else {
                continue;
            };
            let Some(source_epoch) = projection.source_epoch else {
                continue;
            };
            if projection.kind != OpenMlsContentKind::Commit
                || source_epoch >= retained_anchor_epoch
            {
                continue;
            }

            storage.update_message_state(&record.id, MessageState::EpochInvalidated)?;
            retired.push((record.id, EpochId(source_epoch)));
        }

        Ok(retired)
    })
}

/// Fail-open decode of a stored payload into its openmls-wire
/// [`TransportMessage`] and MLS [`OpenMlsMessageProjection`]. Returns `None`
/// when the row cannot be decoded, is not an openmls-wire payload, or does not
/// project — the three-step `decode -> as_openmls_wire -> project_mls_message`
/// chain used by the send-gate (mdk#752 review). Callers that must treat such a
/// row as an error (e.g. a `Processed` row during a convergence apply) keep
/// their own error-propagating chain rather than call this.
pub(crate) fn decode_openmls_wire_projection(
    payload: &[u8],
) -> Option<(TransportMessage, OpenMlsMessageProjection)> {
    let stored = StoredMessagePayload::decode(payload).ok()?;
    let message = stored.as_openmls_wire()?.clone();
    let projection = project_mls_message(&message.payload).ok()?;
    Some((message, projection))
}

pub fn replay_openmls_messages<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    messages: &[TransportMessage],
) -> Result<Vec<OpenMlsReplayObservation>, OpenMlsProjectionError> {
    replay_openmls_messages_prevalidated(
        storage,
        group_id,
        messages,
        &PrevalidatedOwnCommits::default(),
        ReplayProfilePolicy::default(),
    )
}

fn replay_openmls_messages_prevalidated<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    messages: &[TransportMessage],
    own_commits: &PrevalidatedOwnCommits,
    profile_policy: ReplayProfilePolicy,
) -> Result<Vec<OpenMlsReplayObservation>, OpenMlsProjectionError> {
    use crate::snapshot_guard::SnapshotRollbackGuard;
    let snapshot = replay_snapshot_name(group_id, messages);
    // RAII: on any unwind path (panic during replay, early error)
    // Drop rolls back + releases. On the happy path we explicitly
    // commit at the end. Pre-validated own-commit rollforwards inside the
    // replay land within this guard, so they are unwound with everything
    // else.
    let guard = SnapshotRollbackGuard::create(storage, group_id.clone(), snapshot)
        .map_err(|e| OpenMlsProjectionError::Snapshot(format!("{e:?}")))?;

    let result =
        process_openmls_messages_inner(storage, group_id, messages, own_commits, profile_policy)
            .map(|out| out.observations);
    guard
        .commit()
        .map_err(|e| OpenMlsProjectionError::Snapshot(format!("{e:?}")))?;
    result
}

pub fn materialize_openmls_candidate_paths<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    paths: &[OpenMlsCandidatePath],
) -> Result<Vec<OpenMlsMaterializedCandidate>, OpenMlsProjectionError> {
    materialize_openmls_candidate_paths_budgeted(
        storage,
        group_id,
        paths,
        &PrevalidatedOwnCommits::default(),
        &mut ReplayBudget::unlimited(),
        ReplayProfilePolicy::default(),
    )
}

fn materialize_openmls_candidate_paths_budgeted<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    paths: &[OpenMlsCandidatePath],
    own_commits: &PrevalidatedOwnCommits,
    budget: &mut ReplayBudget,
    profile_policy: ReplayProfilePolicy,
) -> Result<Vec<OpenMlsMaterializedCandidate>, OpenMlsProjectionError> {
    let mut candidates = Vec::with_capacity(paths.len());
    for path in paths {
        if path.messages.is_empty() {
            return Err(OpenMlsProjectionError::EmptyCandidatePath(
                path.branch_id.clone(),
            ));
        }
        budget.consume()?;
        let observations = replay_openmls_messages_prevalidated(
            storage,
            group_id,
            &path.messages,
            own_commits,
            profile_policy,
        )?;
        let mut fork_epoch: Option<u64> = None;
        let mut tip_epoch: Option<u64> = None;
        let mut tip_digest: Option<[u8; 32]> = None;
        let mut commit_message_ids = Vec::new();
        let mut consumed_proposal_refs = Vec::new();
        let mut tip_priority = None;
        let mut tip_committer = None;

        for observation in &observations {
            let OpenMlsReplayObservation::CommitStaged {
                message_id,
                source_epoch,
                resulting_epoch,
                priority,
                committer,
                consumed_proposal_refs: commit_consumed_proposal_refs,
            } = observation
            else {
                continue;
            };
            fork_epoch = Some(fork_epoch.map_or(*source_epoch, |epoch| epoch.min(*source_epoch)));
            tip_epoch = Some(*resulting_epoch);
            tip_priority = Some(*priority);
            tip_committer = Some(committer.clone());
            commit_message_ids.push(message_id.clone());
            consumed_proposal_refs.extend(commit_consumed_proposal_refs.iter().cloned());
            tip_digest = path
                .messages
                .iter()
                .find(|message| hex::encode(message.id.as_slice()) == *message_id)
                .map(|message| message_digest(&message.payload));
        }

        let Some(fork_epoch) = fork_epoch else {
            return Err(OpenMlsProjectionError::CandidatePathDidNotCommit(
                path.branch_id.clone(),
            ));
        };
        let tip_epoch = tip_epoch.expect("commit observation sets tip epoch");
        let tip_priority = tip_priority.expect("commit observation came from path message");
        let tip_committer = tip_committer.expect("commit observation came from path message");
        let tip_digest = tip_digest.expect("commit observation came from path message");
        consumed_proposal_refs.sort();
        consumed_proposal_refs.dedup();

        candidates.push(OpenMlsMaterializedCandidate {
            branch_id: path.branch_id.clone(),
            fork_epoch,
            tip_epoch,
            tip_priority,
            tip_committer,
            tip_digest,
            commit_message_ids,
            consumed_proposal_refs,
            observations,
        });
    }
    candidates.sort_by(|a, b| a.branch_id.cmp(&b.branch_id));
    Ok(candidates)
}

pub fn canonicalize_openmls_batch<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    batch: OpenMlsCanonicalizationBatch,
) -> Result<CanonicalizationResult, OpenMlsProjectionError> {
    let mut replay_budget = ReplayBudget::unlimited();
    canonicalize_openmls_batch_prevalidated(
        storage,
        group_id,
        batch,
        &PrevalidatedOwnCommits::default(),
        ReplayProfilePolicy::default(),
        true,
        &mut replay_budget,
    )
}

fn canonicalize_openmls_batch_prevalidated<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    batch: OpenMlsCanonicalizationBatch,
    own_commits: &PrevalidatedOwnCommits,
    profile_policy: ReplayProfilePolicy,
    admit_app_witnesses: bool,
    replay_budget: &mut ReplayBudget,
) -> Result<CanonicalizationResult, OpenMlsProjectionError> {
    let candidate_paths = candidate_paths_with_pending_replay_messages(
        &batch.candidate_paths,
        &batch.pending_messages,
    )?;
    let materialized = materialize_openmls_candidate_paths_budgeted(
        storage,
        group_id,
        &candidate_paths,
        own_commits,
        replay_budget,
        profile_policy,
    )?;
    canonicalize_openmls_batch_with_materialized(group_id, batch, materialized, admit_app_witnesses)
}

/// Canonicalization core over already-materialized candidates. Split out of
/// [`canonicalize_openmls_batch`] so the stored-message hot path can reuse the candidates the
/// BFS already materialized instead of replaying every completed path a second time (#635).
/// `materialized` MUST equal what `materialize_openmls_candidate_paths` would produce for
/// `batch.candidate_paths` folded with `batch.pending_messages` (same order, sorted by
/// `branch_id`); the caller guarantees this only on the app-free reuse path.
fn canonicalize_openmls_batch_with_materialized(
    group_id: &GroupId,
    batch: OpenMlsCanonicalizationBatch,
    materialized: Vec<OpenMlsMaterializedCandidate>,
    admit_app_witnesses: bool,
) -> Result<CanonicalizationResult, OpenMlsProjectionError> {
    let proposal_id_by_ref = proposal_id_by_ref(&materialized);
    let materialized_candidates: Vec<_> = materialized
        .iter()
        .map(|candidate| {
            candidate.canonical_materialized_candidate_with_proposal_ids(&proposal_id_by_ref)
        })
        .collect();
    let proposal_branch_by_id = proposal_branch_by_id(&materialized_candidates);
    let app_messages_by_id = app_messages_by_id(&materialized);
    let pending_messages = project_pending_canonicalization_messages(
        group_id,
        &batch.pending_messages,
        &batch.already_delivered_app_ids,
        &proposal_branch_by_id,
        &app_messages_by_id,
    )?;

    let input = CanonicalizationInput {
        state: batch.state,
        pending_messages,
        outbound_intents: batch.outbound_intents,
        candidate_branches: vec![],
        policy: batch.policy,
        now_ms: batch.now_ms,
    };
    #[cfg(feature = "test-policy-overrides")]
    if !admit_app_witnesses {
        return Ok(
            crate::canonicalization::canonicalize_with_materialized_candidates_for_test(
                input,
                materialized_candidates,
                false,
            ),
        );
    }
    #[cfg(not(feature = "test-policy-overrides"))]
    debug_assert!(
        admit_app_witnesses,
        "production canonicalization must admit application witnesses"
    );
    Ok(canonicalize_with_materialized_candidates(
        input,
        materialized_candidates,
    ))
}

pub fn canonicalize_stored_openmls_messages<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    state: CanonicalizationState,
    outbound_intents: Vec<OutboundIntent>,
    policy: CanonicalizationPolicy,
    now_ms: u64,
) -> Result<CanonicalizationResult, OpenMlsProjectionError> {
    canonicalize_stored_openmls_messages_with_profile_policy(
        storage,
        group_id,
        state,
        outbound_intents,
        policy,
        now_ms,
        StoredCanonicalizationOptions::default(),
    )
}

pub(crate) fn canonicalize_stored_openmls_messages_with_profile_policy<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    state: CanonicalizationState,
    outbound_intents: Vec<OutboundIntent>,
    policy: CanonicalizationPolicy,
    now_ms: u64,
    options: StoredCanonicalizationOptions<'_>,
) -> Result<CanonicalizationResult, OpenMlsProjectionError> {
    let profile_policy = options.replay_profile;
    let current_epoch = storage
        .get_group(group_id)
        .map_err(|e| OpenMlsProjectionError::Storage(format!("{e:?}")))?
        .epoch
        .0;
    let records = storage
        .list_messages(group_id, EpochId(0))
        .map_err(|e| OpenMlsProjectionError::Storage(format!("{e:?}")))?;
    let mut commit_messages = Vec::new();
    let mut pending_messages = Vec::new();
    let mut already_delivered_app_ids = BTreeSet::new();
    let mut stale_commit_drops = Vec::new();
    let mut own_commits = PrevalidatedOwnCommits::default();

    for record in records {
        if options
            .admitted_message_ids
            .is_some_and(|admitted| !admitted.contains(&record.id))
        {
            continue;
        }
        if !record_state_can_contribute_to_openmls_graph(record.state) {
            continue;
        }
        let payload = StoredMessagePayload::decode(&record.payload)
            .map_err(|e| OpenMlsProjectionError::Serialize(format!("{e:?}")))?;
        let own_commit_stamp = payload.own_commit_stamp().cloned();
        let Some(message) = payload.as_openmls_wire().cloned() else {
            continue;
        };
        if matches!(message.envelope, TransportEnvelope::Welcome { .. }) {
            continue;
        }
        let projection = project_mls_message(&message.payload)?;
        let source_epoch = projection.source_epoch;
        match projection.kind {
            OpenMlsContentKind::Commit => {
                let Some(source_epoch) = source_epoch else {
                    continue;
                };
                if source_epoch < state.retained_anchor_epoch {
                    if unresolved_commit_state(record.state) {
                        stale_commit_drops.push(DroppedMessage {
                            message_id: hex::encode(message.id.as_slice()),
                            kind: MessageKind::Commit,
                            reason: DroppedMessageReason::BeyondAnchor,
                            rejection_category: None,
                        });
                    }
                    continue;
                }
                if record.state == MessageState::Processed {
                    own_commits.insert_canonical(projection.message_digest);
                }
                // The stamp is written only at confirm time, so its presence
                // alone proves this is an own commit MLS cannot re-process.
                // Register it independently of `Processed`: a pairwise
                // CandidateWins resolution parks the displaced own incumbent
                // `ConvergenceDeferred` (see `fork_recovery`), and replaying
                // its branch still needs the stamp — the prefix-canonical
                // guard at the stamp's use site keeps a diverging prefix from
                // mis-realizing it.
                if let Some(stamp) = own_commit_stamp {
                    own_commits.insert_stamped(projection.message_digest, stamp);
                }
                commit_messages.push(StoredCommitMessage {
                    message,
                    source_epoch,
                    digest: projection.message_digest,
                    state: record.state,
                });
            }
            OpenMlsContentKind::Proposal
                if record_state_is_canonicalization_input(record.state)
                    && source_epoch.is_some_and(|epoch| epoch >= state.retained_anchor_epoch) =>
            {
                pending_messages.push(message)
            }
            // App messages within the retained window are admitted for scoring
            // when fresh (`Created`/`Retryable`/`Sent`, to be delivered) AND when
            // already `Processed` on a prior pass. A `Processed` app is re-admitted
            // for witness scoring only (tracked in `already_delivered_app_ids` so
            // it is never re-delivered): without it, a same-epoch fork resolved
            // *after* the app was delivered loses that app's witness weight, so
            // branch selection would depend on local arrival order (the
            // convergence contract requires order-independence).
            OpenMlsContentKind::Application
                if record_state_can_contribute_to_openmls_graph(record.state)
                    && source_epoch.is_some_and(|epoch| epoch >= state.retained_anchor_epoch) =>
            {
                if record.state == MessageState::Processed {
                    already_delivered_app_ids.insert(hex::encode(message.id.as_slice()));
                }
                pending_messages.push(message)
            }
            OpenMlsContentKind::Welcome | OpenMlsContentKind::Other => {}
            OpenMlsContentKind::Proposal | OpenMlsContentKind::Application => {}
        }
    }

    let historical_start_epoch = historical_replay_start_epoch(&commit_messages, current_epoch);
    let replay_start_epoch = historical_start_epoch.unwrap_or(current_epoch);
    let commit_messages: Vec<_> = if historical_start_epoch.is_some() {
        commit_messages
    } else {
        commit_messages
            .into_iter()
            .filter(|commit| unresolved_commit_state(commit.state))
            .collect()
    };

    if replay_start_epoch < current_epoch {
        let mut result = canonicalize_stored_openmls_messages_from_retained_anchor(
            storage,
            group_id,
            StoredOpenMlsCanonicalizationWork {
                state,
                commit_messages,
                pending_messages,
                already_delivered_app_ids,
                outbound_intents,
                policy,
                now_ms,
                replay_start_epoch,
                own_commits,
                profile_policy,
                admit_app_witnesses: options.admit_app_witnesses,
                replay_probe_budget_override: options.replay_probe_budget_override,
            },
        )?;
        append_dropped_messages(&mut result, stale_commit_drops);
        return Ok(result);
    }

    let mut result = canonicalize_stored_openmls_messages_from_current(
        storage,
        group_id,
        StoredOpenMlsCanonicalizationWork {
            state,
            commit_messages,
            pending_messages,
            already_delivered_app_ids,
            outbound_intents,
            policy,
            now_ms,
            replay_start_epoch,
            own_commits,
            profile_policy,
            admit_app_witnesses: options.admit_app_witnesses,
            replay_probe_budget_override: options.replay_probe_budget_override,
        },
    )?;
    append_dropped_messages(&mut result, stale_commit_drops);
    Ok(result)
}

/// Reconstruct the tip context of every currently reachable competing branch
/// inside the retained convergence horizon.
///
/// The outer transport envelope is encrypted with the sender's branch-local
/// MLS exporter. A follow-on commit can therefore be opaque to a member that
/// provisionally selected a sibling branch at the same epoch. Looking only at
/// the canonical and past-epoch snapshots creates a circular dependency: the
/// engine cannot see the follow-on that proves the losing root became deeper,
/// so it never selects the branch whose exporter would reveal that follow-on.
///
/// This helper breaks that cycle without putting transport policy into the
/// selector. It replays only already-authenticated, retained commit roots under
/// the same bounded candidate graph used by canonicalization and returns
/// memory-only peeler contexts for their tips. A successful outer peel still
/// has to pass ordinary MLS authentication and canonicalization before it can
/// affect state.
pub(crate) fn stored_candidate_peel_contexts<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    current_epoch: EpochId,
    max_rewind_commits: u64,
    profile_policy: ReplayProfilePolicy,
) -> Result<Vec<CandidatePeelContext>, OpenMlsProjectionError> {
    let retained_anchor_epoch = current_epoch.0.saturating_sub(max_rewind_commits);
    let records = storage
        .list_messages(group_id, EpochId(0))
        .map_err(|error| OpenMlsProjectionError::Storage(format!("{error:?}")))?;
    let mut commits = Vec::new();
    let mut own_commits = PrevalidatedOwnCommits::default();

    for record in records {
        if !record_state_can_contribute_to_openmls_graph(record.state) {
            continue;
        }
        let payload = StoredMessagePayload::decode(&record.payload)
            .map_err(|error| OpenMlsProjectionError::Serialize(format!("{error:?}")))?;
        let own_commit_stamp = payload.own_commit_stamp().cloned();
        let Some(message) = payload.as_openmls_wire().cloned() else {
            continue;
        };
        let projection = project_mls_message(&message.payload)?;
        if projection.kind != OpenMlsContentKind::Commit {
            continue;
        }
        let Some(source_epoch) = projection.source_epoch else {
            continue;
        };
        if source_epoch < retained_anchor_epoch {
            continue;
        }
        if record.state == MessageState::Processed {
            own_commits.insert_canonical(projection.message_digest);
        }
        if let Some(stamp) = own_commit_stamp {
            own_commits.insert_stamped(projection.message_digest, stamp);
        }
        commits.push(StoredCommitMessage {
            message,
            source_epoch,
            digest: projection.message_digest,
            state: record.state,
        });
    }
    let historical_start = historical_replay_start_epoch(&commits, current_epoch.0);
    let replay_start_epoch = historical_start.or_else(|| {
        commits
            .iter()
            .filter(|commit| {
                unresolved_commit_state(commit.state) && commit.source_epoch == current_epoch.0
            })
            .map(|commit| commit.source_epoch)
            .min()
    });
    let Some(replay_start_epoch) = replay_start_epoch else {
        return Ok(Vec::new());
    };
    if historical_start.is_none() {
        // Starting from the live epoch only unresolved roots can extend the
        // current state. Older Processed commits describe the prefix already
        // embodied by that state and must not be replayed again.
        commits.retain(|commit| {
            unresolved_commit_state(commit.state) && commit.source_epoch >= current_epoch.0
        });
        return candidate_peel_contexts_from_current(
            storage,
            group_id,
            commits,
            replay_start_epoch,
            own_commits,
            max_rewind_commits,
            profile_policy,
        );
    }

    use crate::snapshot_guard::SnapshotRollbackGuard;
    let live_snapshot = retained_anchor_probe_snapshot_name(group_id, replay_start_epoch);
    let guard = SnapshotRollbackGuard::create(storage, group_id.clone(), live_snapshot)
        .map_err(|error| OpenMlsProjectionError::Snapshot(format!("{error:?}")))?;
    let anchor_snapshot = retained_anchor_snapshot_name(replay_start_epoch);
    let result = match storage.rollback_group_to_snapshot(group_id, &anchor_snapshot) {
        Ok(()) => candidate_peel_contexts_from_current(
            storage,
            group_id,
            commits,
            replay_start_epoch,
            own_commits,
            max_rewind_commits,
            profile_policy,
        ),
        Err(StorageError::SnapshotMissing(_)) => Ok(Vec::new()),
        Err(error) => Err(OpenMlsProjectionError::Snapshot(format!("{error:?}"))),
    };
    guard
        .commit()
        .map_err(|error| OpenMlsProjectionError::Snapshot(format!("{error:?}")))?;
    result
}

fn candidate_peel_contexts_from_current<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    commits: Vec<StoredCommitMessage>,
    replay_start_epoch: u64,
    own_commits: PrevalidatedOwnCommits,
    max_rewind_commits: u64,
    profile_policy: ReplayProfilePolicy,
) -> Result<Vec<CandidatePeelContext>, OpenMlsProjectionError> {
    let mut budget = ReplayBudget::for_pass(commits.len(), max_rewind_commits);
    let paths = build_stored_openmls_candidate_paths(
        storage,
        group_id,
        commits,
        &[],
        replay_start_epoch,
        &own_commits,
        profile_policy,
        &mut budget,
    )?
    .candidate_paths;

    let mut contexts = Vec::with_capacity(paths.len());
    for path in paths {
        budget.consume()?;
        if let Some(context) = replay_candidate_peel_context(
            storage,
            group_id,
            &path.messages,
            &own_commits,
            profile_policy,
        )? {
            contexts.push(context);
        }
    }
    contexts.sort_by_key(|candidate| candidate.source_epoch);
    Ok(contexts)
}

fn replay_candidate_peel_context<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    messages: &[TransportMessage],
    own_commits: &PrevalidatedOwnCommits,
    profile_policy: ReplayProfilePolicy,
) -> Result<Option<CandidatePeelContext>, OpenMlsProjectionError> {
    use crate::snapshot_guard::SnapshotRollbackGuard;
    let snapshot = replay_snapshot_name(group_id, messages);
    let guard = SnapshotRollbackGuard::create(storage, group_id.clone(), snapshot)
        .map_err(|error| OpenMlsProjectionError::Snapshot(format!("{error:?}")))?;
    let replay =
        process_openmls_messages_inner(storage, group_id, messages, own_commits, profile_policy);
    let result = match replay {
        Ok(_) => {
            let crypto = RustCrypto::default();
            let provider = EngineOpenMlsProvider::<S>::new(&crypto, storage.mls_storage());
            let mls_group_id = openmls::group::GroupId::from_slice(group_id.as_slice());
            let mls_group = MlsGroup::load(provider.storage(), &mls_group_id)
                .map_err(|error| {
                    OpenMlsProjectionError::Replay(format!(
                        "load candidate peel context: {error:?}"
                    ))
                })?
                .ok_or(OpenMlsProjectionError::MissingGroup)?;
            let source_epoch = EpochId(mls_group.epoch().as_u64());
            let message_retention_seconds =
                crate::app_components::message_retention_seconds_of_group(&mls_group)
                    .map_err(|error| OpenMlsProjectionError::Replay(error.to_string()))?;
            let context =
                crate::group_lifecycle::build_group_context_snapshot(&mls_group, &provider)
                    .map_err(|error| OpenMlsProjectionError::Replay(error.to_string()))?;
            Ok(Some(CandidatePeelContext {
                context,
                source_epoch,
                message_retention_seconds,
            }))
        }
        // Candidate construction already rejected paths that cannot replay.
        // If a repeated materialization loses a race with retained state, skip
        // that context and let ordinary convergence re-evaluate the row.
        Err(OpenMlsProjectionError::Replay(_)) => Ok(None),
        Err(error) => Err(error),
    };
    guard
        .commit()
        .map_err(|error| OpenMlsProjectionError::Snapshot(format!("{error:?}")))?;
    result
}

fn append_dropped_messages(
    result: &mut CanonicalizationResult,
    dropped_messages: Vec<DroppedMessage>,
) {
    for dropped in dropped_messages {
        if dropped.kind == MessageKind::Proposal
            && result
                .accepted_proposals
                .iter()
                .any(|accepted| accepted == &dropped.message_id)
        {
            continue;
        }
        if let Some(existing) = result
            .dropped_messages
            .iter_mut()
            .find(|existing| existing.message_id == dropped.message_id)
        {
            if existing.rejection_category.is_none() {
                existing.rejection_category = dropped.rejection_category;
            }
            continue;
        }
        result.dropped_messages.push(dropped);
    }
    result.dropped_messages.sort();
}

fn append_missing_parent_deferred_commits(
    result: &mut CanonicalizationResult,
    message_ids: Vec<String>,
) {
    for message_id in message_ids {
        if result
            .deferred_messages
            .iter()
            .any(|existing| existing.message_id == message_id)
            || result
                .dropped_messages
                .iter()
                .any(|existing| existing.message_id == message_id)
        {
            continue;
        }
        result.deferred_messages.push(DeferredMessage {
            message_id,
            kind: MessageKind::Commit,
            reason: DeferredMessageReason::MissingCandidateParent,
        });
    }
    result.deferred_messages.sort();
}

fn canonicalize_stored_openmls_messages_from_retained_anchor<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    work: StoredOpenMlsCanonicalizationWork,
) -> Result<CanonicalizationResult, OpenMlsProjectionError> {
    use crate::snapshot_guard::SnapshotRollbackGuard;

    let live_snapshot = retained_anchor_probe_snapshot_name(group_id, work.replay_start_epoch);
    let guard = SnapshotRollbackGuard::create(storage, group_id.clone(), live_snapshot)
        .map_err(|e| OpenMlsProjectionError::Snapshot(format!("{e:?}")))?;

    let anchor_snapshot = retained_anchor_snapshot_name(work.replay_start_epoch);
    let result = match storage.rollback_group_to_snapshot(group_id, &anchor_snapshot) {
        Ok(()) => {
            crate::test_crash_hooks::pause_if_requested("retained-anchor-after-rewind");
            canonicalize_stored_openmls_messages_from_current(storage, group_id, work)
        }
        Err(StorageError::SnapshotMissing(_)) => Ok(missing_retained_anchor_result(
            work.state,
            work.outbound_intents,
            work.policy,
            work.now_ms,
        )),
        Err(e) => Err(OpenMlsProjectionError::Snapshot(format!("{e:?}"))),
    };

    guard
        .commit()
        .map_err(|e| OpenMlsProjectionError::Snapshot(format!("{e:?}")))?;
    result
}

/// Recover the live state captured before a retained-anchor probe that was
/// interrupted by process termination.
///
/// The probe snapshot is created before the durable rollback to the historical
/// anchor. A surviving snapshot therefore always contains the newer live state
/// that must win on the next open. More than one probe snapshot is not expected:
/// convergence for a group is serialized and hydrate runs before new work. If
/// storage contains several, fail closed instead of guessing which live state
/// is newest.
pub(crate) fn recover_interrupted_retained_anchor_probe<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
) -> Result<(), OpenMlsProjectionError> {
    let probes = storage
        .list_group_snapshots(group_id)
        .map_err(|e| OpenMlsProjectionError::Storage(format!("{e:?}")))?
        .into_iter()
        .filter(|name| name.starts_with(RETAINED_ANCHOR_PROBE_SNAPSHOT_PREFIX))
        .collect::<Vec<_>>();

    let Some(snapshot) = probes.first() else {
        return Ok(());
    };
    if probes.len() != 1 {
        return Err(OpenMlsProjectionError::Snapshot(
            "multiple interrupted retained-anchor probes".into(),
        ));
    }

    rollback_and_release_group_snapshot(storage, group_id, snapshot)
}

/// Whether the pass may reuse the candidates the BFS already materialized instead
/// of a second full replay (#635).
///
/// Reuse is sound only with **no pending application messages**: the BFS probes
/// fold pending proposals but not applications, so with pending apps the reused
/// candidate would lack the `ApplicationProcessed` observations the
/// canonicalization core consumes (for delivery *and* app-witness scoring), so the
/// pass falls back to a fresh full materialize.
///
/// Perf note: re-admitting already-delivered (`Processed`) app messages as
/// witnesses (see `canonicalize_stored_openmls_messages`) means `has_pending_apps`
/// is true on any pass where a delivered app is still inside the retained window —
/// so those passes pay the full-materialize cost instead of reusing. The cost is
/// bounded by `max_rewind_commits` and convergence is not the per-message hot path,
/// so it is negligible for small groups. If a benchmark ever shows it matters for
/// large, busy groups, gate the witness re-admission on the presence of a contested
/// fork (competing branches) rather than on any retained app.
fn can_reuse_bfs_materialization(
    has_pending_apps: bool,
    materialized_len: usize,
    candidate_paths_len: usize,
) -> bool {
    !has_pending_apps && materialized_len == candidate_paths_len
}

fn canonicalize_stored_openmls_messages_from_current<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    work: StoredOpenMlsCanonicalizationWork,
) -> Result<CanonicalizationResult, OpenMlsProjectionError> {
    let mut replay_budget = work.replay_probe_budget_override.map_or_else(
        || {
            ReplayBudget::for_pass(
                work.commit_messages.len(),
                work.policy.convergence.max_rewind_commits,
            )
        },
        ReplayBudget::new,
    );
    let path_result = build_stored_openmls_candidate_paths(
        storage,
        group_id,
        work.commit_messages,
        &work.pending_messages,
        work.replay_start_epoch,
        &work.own_commits,
        work.profile_policy,
        &mut replay_budget,
    )?;

    let has_pending_apps = pending_messages_contain_application(&work.pending_messages)?;
    let can_reuse_materialized = can_reuse_bfs_materialization(
        has_pending_apps,
        path_result.materialized.len(),
        path_result.candidate_paths.len(),
    );
    let batch = OpenMlsCanonicalizationBatch {
        state: work.state,
        candidate_paths: path_result.candidate_paths,
        pending_messages: work.pending_messages,
        already_delivered_app_ids: work.already_delivered_app_ids,
        outbound_intents: work.outbound_intents,
        policy: work.policy,
        now_ms: work.now_ms,
    };
    let mut result = if can_reuse_materialized {
        let mut materialized = path_result.materialized;
        materialized.sort_by(|a, b| a.branch_id.cmp(&b.branch_id));
        canonicalize_openmls_batch_with_materialized(
            group_id,
            batch,
            materialized,
            work.admit_app_witnesses,
        )?
    } else {
        canonicalize_openmls_batch_prevalidated(
            storage,
            group_id,
            batch,
            &work.own_commits,
            work.profile_policy,
            work.admit_app_witnesses,
            &mut replay_budget,
        )?
    };
    #[cfg(feature = "test-conformance-snapshot")]
    {
        result.replay_probe_count = replay_budget.consumed;
    }
    append_dropped_messages(&mut result, path_result.invalid_commit_drops);
    append_missing_parent_deferred_commits(&mut result, path_result.unmaterialized_commit_ids);
    Ok(result)
}

fn historical_replay_start_epoch(
    commits: &[StoredCommitMessage],
    current_epoch: u64,
) -> Option<u64> {
    commits
        .iter()
        .filter(|commit| {
            unresolved_commit_state(commit.state) && commit.source_epoch < current_epoch
        })
        .map(|commit| commit.source_epoch)
        .min()
}

fn missing_retained_anchor_result(
    state: CanonicalizationState,
    outbound_intents: Vec<OutboundIntent>,
    policy: CanonicalizationPolicy,
    now_ms: u64,
) -> CanonicalizationResult {
    let elapsed = now_ms.saturating_sub(state.last_convergence_relevant_input_ms);
    let convergence_status = if elapsed >= policy.settlement_quiescence_ms {
        ConvergenceStatus::Blocked
    } else {
        ConvergenceStatus::Syncing
    };
    CanonicalizationResult {
        previous_tip: state.current_tip_epoch,
        selected_tip: None,
        selected_fork_epoch: None,
        selected_branch_id: None,
        candidate_count: 0,
        eligible_count: 0,
        convergence_status,
        accepted_commits: Vec::new(),
        accepted_proposals: Vec::new(),
        accepted_app_messages: Vec::new(),
        deferred_messages: Vec::new(),
        invalidated_app_messages: Vec::new(),
        dropped_messages: Vec::new(),
        already_seen: Vec::new(),
        queued_outbound_intents: outbound_intents,
        publishable_outbound_messages: Vec::new(),
        errors: vec![CanonicalizationError::MissingRetainedAnchor],
        #[cfg(feature = "test-conformance-snapshot")]
        replay_probe_count: 0,
        selection_trace: None,
    }
}

// The last two arguments carry independent replay context; folding them into a
// struct would just relocate the same fields.
#[allow(clippy::too_many_arguments)]
fn build_stored_openmls_candidate_paths<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    mut commits: Vec<StoredCommitMessage>,
    pending_messages: &[TransportMessage],
    starting_epoch: u64,
    own_commits: &PrevalidatedOwnCommits,
    profile_policy: ReplayProfilePolicy,
    budget: &mut ReplayBudget,
) -> Result<StoredOpenMlsCandidatePathResult, OpenMlsProjectionError> {
    commits.sort_by(|a, b| {
        a.source_epoch
            .cmp(&b.source_epoch)
            .then_with(|| a.digest.cmp(&b.digest))
            .then_with(|| a.message.payload.cmp(&b.message.payload))
    });
    let unresolved_commit_ids = commits
        .iter()
        .filter(|commit| unresolved_commit_state(commit.state))
        .map(|commit| commit.message.id.to_string())
        .collect::<BTreeSet<_>>();

    let pending_proposals = pending_proposal_messages(pending_messages)?;
    let mut frontier = vec![CandidatePathProbe {
        messages: Vec::new(),
        digests: Vec::new(),
        tip_epoch: starting_epoch,
        materialized: None,
    }];
    let mut completed = Vec::new();
    let mut invalid_commit_drops = Vec::new();
    // A structurally valid commit can still fail OpenMLS validation against
    // every candidate parent state. Track those failed probes separately from
    // commits that materialize on at least one branch: only the former are
    // terminal once the BFS has exhausted every reachable parent (#962).
    let mut replay_rejected_commit_ids = BTreeSet::new();
    let mut materialized_commit_ids = BTreeSet::new();
    let mut seen_paths = BTreeSet::from([Vec::<[u8; 32]>::new()]);

    while !frontier.is_empty() {
        let mut next_frontier = Vec::new();

        for path in frontier {
            let mut extended = false;
            for commit in &commits {
                if commit.source_epoch != path.tip_epoch || path.digests.contains(&commit.digest) {
                    continue;
                }

                let mut messages = path.messages.clone();
                messages.push(commit.message.clone());
                let mut digests = path.digests.clone();
                digests.push(commit.digest);
                if !seen_paths.insert(digests.clone()) {
                    continue;
                }

                let candidate = match probe_candidate_path(
                    storage,
                    group_id,
                    messages.clone(),
                    &digests,
                    &pending_proposals,
                    own_commits,
                    budget,
                    profile_policy,
                )? {
                    CandidatePathProbeResult::Materialized(Some(candidate)) => {
                        materialized_commit_ids.insert(commit.message.id.to_string());
                        candidate
                    }
                    CandidatePathProbeResult::Materialized(None) => {
                        replay_rejected_commit_ids.insert(commit.message.id.to_string());
                        continue;
                    }
                    CandidatePathProbeResult::RejectedProposal {
                        message_id,
                        category,
                    } => {
                        invalid_commit_drops.push(DroppedMessage {
                            message_id,
                            kind: MessageKind::Proposal,
                            reason: DroppedMessageReason::InvalidAgainstCandidateState,
                            rejection_category: Some(category),
                        });
                        invalid_commit_drops.push(DroppedMessage {
                            message_id: commit.message.id.to_string(),
                            kind: MessageKind::Commit,
                            reason: DroppedMessageReason::InvalidAgainstCandidateState,
                            rejection_category: None,
                        });
                        continue;
                    }
                    CandidatePathProbeResult::UnauthorizedCommit { message_id } => {
                        invalid_commit_drops.push(DroppedMessage {
                            message_id,
                            kind: MessageKind::Commit,
                            reason: DroppedMessageReason::InvalidAgainstCandidateState,
                            rejection_category: None,
                        });
                        continue;
                    }
                    CandidatePathProbeResult::InvalidCommit {
                        message_id,
                        rejection_category,
                    } => {
                        invalid_commit_drops.push(DroppedMessage {
                            message_id,
                            kind: MessageKind::Commit,
                            reason: DroppedMessageReason::InvalidAgainstCandidateState,
                            rejection_category,
                        });
                        continue;
                    }
                };

                extended = true;
                let tip_epoch = candidate.tip_epoch;
                next_frontier.push(CandidatePathProbe {
                    messages,
                    digests,
                    tip_epoch,
                    materialized: Some(candidate),
                });
            }

            if !path.messages.is_empty() && !extended {
                completed.push(path);
            }
        }

        frontier = next_frontier;
    }

    for message_id in replay_rejected_commit_ids.difference(&materialized_commit_ids) {
        invalid_commit_drops.push(DroppedMessage {
            message_id: message_id.clone(),
            kind: MessageKind::Commit,
            reason: DroppedMessageReason::InvalidAgainstCandidateState,
            rejection_category: None,
        });
    }
    let terminal_commit_ids = invalid_commit_drops
        .iter()
        .filter(|dropped| dropped.kind == MessageKind::Commit)
        .map(|dropped| dropped.message_id.clone())
        .collect::<BTreeSet<_>>();
    let unmaterialized_commit_ids = unresolved_commit_ids
        .difference(&materialized_commit_ids)
        .filter(|message_id| !terminal_commit_ids.contains(*message_id))
        .cloned()
        .collect();

    let mut candidate_paths = Vec::with_capacity(completed.len());
    let mut materialized = Vec::with_capacity(completed.len());
    for path in completed {
        candidate_paths.push(OpenMlsCandidatePath {
            branch_id: branch_id_for_path_digests(&path.digests),
            messages: path.messages,
        });
        // Every completed path is a non-empty node created via a probe, so `materialized` is
        // always `Some`. Push in lockstep with `candidate_paths`; if the invariant is ever
        // broken the length mismatch makes the caller fall back to a fresh materialize.
        if let Some(candidate) = path.materialized {
            materialized.push(candidate);
        }
    }

    Ok(StoredOpenMlsCandidatePathResult {
        candidate_paths,
        materialized,
        invalid_commit_drops,
        unmaterialized_commit_ids,
    })
}

/// True if any pending message is an application message (used to decide whether the BFS's
/// proposal-only materialized candidates can be reused by the canonicalization core — #635).
fn pending_messages_contain_application(
    pending_messages: &[TransportMessage],
) -> Result<bool, OpenMlsProjectionError> {
    for message in pending_messages {
        if project_mls_message(&message.payload)?.kind == OpenMlsContentKind::Application {
            return Ok(true);
        }
    }
    Ok(false)
}

fn pending_proposal_messages(
    pending_messages: &[TransportMessage],
) -> Result<Vec<TransportMessage>, OpenMlsProjectionError> {
    let mut proposals = Vec::new();
    for message in pending_messages {
        if project_mls_message(&message.payload)?.kind == OpenMlsContentKind::Proposal {
            proposals.push(message.clone());
        }
    }
    Ok(proposals)
}

// See `build_stored_openmls_candidate_paths` — same shared-context argument set.
#[allow(clippy::too_many_arguments)]
fn probe_candidate_path<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    messages: Vec<TransportMessage>,
    digests: &[[u8; 32]],
    pending_proposals: &[TransportMessage],
    own_commits: &PrevalidatedOwnCommits,
    budget: &mut ReplayBudget,
    profile_policy: ReplayProfilePolicy,
) -> Result<CandidatePathProbeResult, OpenMlsProjectionError> {
    let path = OpenMlsCandidatePath {
        branch_id: branch_id_for_path_digests(digests),
        messages,
    };
    let replay_paths = candidate_paths_with_pending_replay_messages(&[path], pending_proposals)?;
    match materialize_openmls_candidate_paths_budgeted(
        storage,
        group_id,
        &replay_paths,
        own_commits,
        budget,
        profile_policy,
    ) {
        Ok(mut candidates) => Ok(CandidatePathProbeResult::Materialized(candidates.pop())),
        Err(OpenMlsProjectionError::RejectedProposal {
            message_id,
            category,
        }) => Ok(CandidatePathProbeResult::RejectedProposal {
            message_id,
            category,
        }),
        Err(OpenMlsProjectionError::UnauthorizedCommit { message_id }) => {
            Ok(CandidatePathProbeResult::UnauthorizedCommit { message_id })
        }
        Err(OpenMlsProjectionError::InvalidCommit {
            message_id,
            reason: _,
            rejection_category,
        }) => Ok(CandidatePathProbeResult::InvalidCommit {
            message_id,
            rejection_category,
        }),
        Err(OpenMlsProjectionError::Replay(_)) => Ok(CandidatePathProbeResult::Materialized(None)),
        Err(err) => Err(err),
    }
}

pub fn apply_openmls_canonicalization_result<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    result: &CanonicalizationResult,
    max_retained_anchor_rewind: u64,
) -> Result<Vec<OpenMlsReplayObservation>, OpenMlsProjectionError> {
    apply_openmls_canonicalization_result_with_profile_policy(
        storage,
        group_id,
        result,
        max_retained_anchor_rewind,
        ReplayProfilePolicy::default(),
    )
}

pub(crate) fn apply_openmls_canonicalization_result_with_profile_policy<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    result: &CanonicalizationResult,
    max_retained_anchor_rewind: u64,
    profile_policy: ReplayProfilePolicy,
) -> Result<Vec<OpenMlsReplayObservation>, OpenMlsProjectionError> {
    let current_epoch = storage
        .get_group(group_id)
        .map_err(|e| OpenMlsProjectionError::Storage(format!("{e:?}")))?
        .epoch
        .0;
    // The selected branch's already-applied prefix — leading `Processed`
    // commits below the live tip — IS the live canonical chain: skip it and
    // start state reconstruction from the first genuinely new commit. This is
    // also what lets a branch containing this device's OWN confirmed commit
    // apply at all (MLS cannot re-process own commits), and it avoids
    // re-replaying history the live state already reflects.
    let applied_prefix = already_applied_commit_prefix(storage, result, current_epoch)?;
    let has_new_commits = result.accepted_commits.len() > applied_prefix.len();
    // A displaced own commit parked `ConvergenceDeferred` by a pairwise
    // CandidateWins resolution (see `fork_recovery`) can head the selected
    // branch WITHOUT being in the already-applied prefix. MLS cannot
    // re-process own commits and this apply cannot nest the selection stage's
    // per-commit anchor rollforward, so realize such a leading run in one
    // step: skip it from the replay and rewind to the retained anchor at the
    // run's final resulting epoch — the exact post-merge state its last own
    // commit produced.
    let own_anchor_prefix =
        anchor_realizable_own_commit_prefix(storage, group_id, result, &applied_prefix)?;
    let mut skipped_prefix = applied_prefix;
    skipped_prefix.extend(own_anchor_prefix.commit_ids.iter().cloned());
    let apply_start_epoch = match own_anchor_prefix.resulting_epoch {
        Some(epoch) => epoch,
        None => apply_start_epoch_for_canonicalization_result(storage, result, &skipped_prefix)?
            .unwrap_or(current_epoch),
    };
    // The own-anchor case must rewind even when the anchor epoch equals the
    // live tip epoch: the live tip is a DIFFERENT branch's state at that
    // epoch (that is what displaced the own incumbent), while the retained
    // anchor holds the own commit's post-merge state.
    let rewind_to_retained_anchor =
        apply_start_epoch < current_epoch || own_anchor_prefix.resulting_epoch.is_some();
    let replay_messages = replay_messages_for_canonicalization_result(
        storage,
        result,
        &skipped_prefix,
        apply_start_epoch,
    )?;
    let live_message_records = storage
        .list_messages(group_id, EpochId(0))
        .map_err(|e| OpenMlsProjectionError::Storage(format!("{e:?}")))?;
    let live_queued_outbound = storage
        .list_queued_outbound_intents(group_id)
        .map_err(|e| OpenMlsProjectionError::Storage(format!("{e:?}")))?;
    let snapshot = apply_snapshot_name(group_id, result);
    storage
        .create_group_snapshot(group_id, &snapshot)
        .map_err(|e| OpenMlsProjectionError::Snapshot(format!("{e:?}")))?;

    // Never refresh the current-epoch anchor when this apply is about to
    // rewind to a retained anchor: in the own-anchor case the live tip and
    // the rewind target share an epoch number, and retaining here would
    // overwrite the own commit's post-merge state with the displacing
    // branch's state before the rollback reads it.
    let prepare_result = if has_new_commits && !rewind_to_retained_anchor {
        retain_current_group_epoch_snapshot(storage, group_id, max_retained_anchor_rewind)
    } else {
        Ok(())
    };
    if let Err(err) = prepare_result {
        rollback_and_release_group_snapshot(storage, group_id, &snapshot)?;
        return Err(err);
    }

    // The historical rewind, restoration of the complete live input/queue set,
    // selected-branch apply, and apply-snapshot release are one durable unit.
    // SQLite snapshot rollback joins this outer transaction; a crash or error
    // therefore returns to the pre-apply live state instead of committing an
    // older message/queue image and rebuilding it row by row.
    let apply_result = storage.with_transaction(|storage| {
        if rewind_to_retained_anchor {
            let anchor_snapshot = retained_anchor_snapshot_name(apply_start_epoch);
            storage
                .rollback_group_to_snapshot(group_id, &anchor_snapshot)
                .map_err(|e| OpenMlsProjectionError::Snapshot(format!("{e:?}")))?;
            restore_live_message_and_queue_records(
                storage,
                &live_message_records,
                &live_queued_outbound,
            )?;
        }

        let observations = apply_openmls_canonicalization_result_inner(
            storage,
            group_id,
            result,
            &replay_messages,
            profile_policy,
        )?;
        if apply_start_epoch < current_epoch {
            crate::test_crash_hooks::pause_if_requested("historical-apply-before-commit");
        }
        storage
            .release_group_snapshot(group_id, &snapshot)
            .map_err(|e| OpenMlsProjectionError::Snapshot(format!("{e:?}")))?;
        Ok(observations)
    });

    match apply_result {
        Ok(observations) => {
            if result.selected_tip.is_some() {
                retain_current_group_epoch_snapshot(storage, group_id, max_retained_anchor_rewind)?;
            }
            Ok(observations)
        }
        Err(err) => {
            rollback_and_release_group_snapshot(storage, group_id, &snapshot)?;
            Err(err)
        }
    }
}

pub fn persist_openmls_canonicalization_dispositions<S: StorageProvider>(
    storage: &S,
    result: &CanonicalizationResult,
) -> Result<(), OpenMlsProjectionError> {
    let mut state_by_message_id = BTreeMap::new();

    for dropped in &result.dropped_messages {
        state_by_message_id.insert(
            dropped.message_id.clone(),
            message_state_for_dropped_reason(dropped.reason),
        );
    }
    // The epoch convergence settled on: the selected branch tip, or the
    // unchanged previous tip when no branch was selected this pass.
    let resulting_tip = result.selected_tip.unwrap_or(result.previous_tip);
    for invalidated in &result.invalidated_app_messages {
        state_by_message_id.insert(
            invalidated.message_id.clone(),
            message_state_for_invalidated_reason(
                invalidated.reason,
                invalidated.epoch,
                resulting_tip,
            ),
        );
    }
    for deferred in &result.deferred_messages {
        state_by_message_id.insert(
            deferred.message_id.clone(),
            MessageState::ConvergenceDeferred,
        );
    }
    for accepted in result
        .accepted_commits
        .iter()
        .chain(&result.accepted_proposals)
        .chain(&result.accepted_app_messages)
    {
        state_by_message_id.insert(accepted.clone(), MessageState::Processed);
    }

    for (hex_message_id, state) in state_by_message_id {
        let message_id = message_id_from_hex(&hex_message_id)?;
        storage
            .update_message_state(&message_id, state)
            .map_err(|e| OpenMlsProjectionError::Storage(format!("{e:?}")))?;
    }

    Ok(())
}

/// The longest leading run of accepted commits already applied on the live
/// canonical state: `Processed` records whose source epoch sits below the live
/// tip. `Processed` means "applied on this device's canonical chain" (there is
/// at most one per epoch), so the prefix needs no re-replay — and an OWN
/// confirmed commit in it CANNOT be re-replayed (`process_message` refuses own
/// commits).
fn already_applied_commit_prefix<S: StorageProvider>(
    storage: &S,
    result: &CanonicalizationResult,
    current_epoch: u64,
) -> Result<BTreeSet<String>, OpenMlsProjectionError> {
    let mut prefix = BTreeSet::new();
    for commit_id in &result.accepted_commits {
        let message_id = message_id_from_hex(commit_id)?;
        let record = match storage.get_message(&message_id) {
            Ok(record) => record,
            Err(StorageError::NotFound) => break,
            Err(e) => return Err(OpenMlsProjectionError::Storage(format!("{e:?}"))),
        };
        if record.state != MessageState::Processed || record.epoch.0 >= current_epoch {
            break;
        }
        prefix.insert(commit_id.clone());
    }
    Ok(prefix)
}

fn apply_start_epoch_for_canonicalization_result<S: StorageProvider>(
    storage: &S,
    result: &CanonicalizationResult,
    applied_prefix: &BTreeSet<String>,
) -> Result<Option<u64>, OpenMlsProjectionError> {
    let Some(first_commit_id) = result
        .accepted_commits
        .iter()
        .find(|commit_id| !applied_prefix.contains(*commit_id))
    else {
        return Ok(None);
    };
    let message_id = message_id_from_hex(first_commit_id)?;
    let record = storage
        .get_message(&message_id)
        .map_err(|e| OpenMlsProjectionError::Storage(format!("{e:?}")))?;
    Ok(Some(record.epoch.0))
}

#[derive(Default)]
struct AnchorRealizableOwnPrefix {
    /// Selected-branch commit ids (hex) realized via the retained anchor
    /// instead of replay.
    commit_ids: BTreeSet<String>,
    /// Resulting epoch of the run's last own commit — the retained-anchor
    /// rewind target that realizes the whole run.
    resulting_epoch: Option<u64>,
}

/// The leading run — after the already-applied prefix — of this device's own
/// confirm-stamped commits on the selected branch, bounded to those whose
/// resulting-epoch retained anchor still exists. Such commits reach the apply
/// stage outside the applied prefix when a pairwise CandidateWins resolution
/// parked a displaced own incumbent `ConvergenceDeferred` (see
/// `fork_recovery`) and convergence later selected its regrown branch. MLS
/// refuses to re-process own commits, so the apply realizes the run by
/// rewinding to the retained anchor at its final resulting epoch — the exact
/// post-merge state captured when the commit confirmed — mirroring the
/// selection stage's stamp rollforward (`PrevalidatedOwnCommits`). The first
/// commit that is not an anchor-realizable own commit ends the run; anything
/// after it replays normally from that state.
fn anchor_realizable_own_commit_prefix<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    result: &CanonicalizationResult,
    applied_prefix: &BTreeSet<String>,
) -> Result<AnchorRealizableOwnPrefix, OpenMlsProjectionError> {
    let mut prefix = AnchorRealizableOwnPrefix::default();
    let mut snapshots: Option<Vec<String>> = None;
    let mut own_stamped_commit_ids_by_source_epoch: Option<BTreeMap<u64, Vec<Vec<u8>>>> = None;
    for commit_id in result
        .accepted_commits
        .iter()
        .filter(|commit_id| !applied_prefix.contains(*commit_id))
    {
        let message_id = message_id_from_hex(commit_id)?;
        let record = match storage.get_message(&message_id) {
            Ok(record) => record,
            Err(StorageError::NotFound) => break,
            Err(e) => return Err(OpenMlsProjectionError::Storage(format!("{e:?}"))),
        };
        let Ok(payload) = StoredMessagePayload::decode(&record.payload) else {
            break;
        };
        if payload.own_commit_stamp().is_none() {
            break;
        }
        let resulting_epoch = record.epoch.0.saturating_add(1);
        if snapshots.is_none() {
            snapshots = Some(
                storage
                    .list_group_snapshots(group_id)
                    .map_err(|e| OpenMlsProjectionError::Storage(format!("{e:?}")))?,
            );
        }
        let retained = snapshots
            .as_ref()
            .is_some_and(|names| names.contains(&retained_anchor_snapshot_name(resulting_epoch)));
        if !retained {
            break;
        }
        // Retained anchors are keyed by resulting epoch ALONE
        // (`openmls-retained-anchor-<epoch>`) and `create_group_snapshot`
        // replaces a same-named snapshot. So a name match does not prove the
        // anchor holds THIS commit's post-merge state: if a second own commit
        // was later confirmed at the same resulting epoch — e.g. on the branch
        // that displaced this one — its confirm overwrote the anchor, and
        // rewinding here would install the wrong state while skipping replay.
        // Re-keying the anchor scheme is out of scope (it is shared with the
        // convergence engine), so resolve the ambiguity conservatively: when
        // more than one own confirm-stamped commit row could have produced an
        // anchor at this resulting epoch, refuse the fast path and end the
        // run. The commit then replays normally, which fails closed and lets
        // convergence prune. A missed fast path is far cheaper than a wrong
        // rewind.
        if own_stamped_commit_ids_by_source_epoch.is_none() {
            own_stamped_commit_ids_by_source_epoch = Some(
                own_stamped_commit_ids_by_source_epoch_map(storage, group_id)?,
            );
        }
        let ambiguous_anchor_lineage =
            own_stamped_commit_ids_by_source_epoch
                .as_ref()
                .is_some_and(|by_source_epoch| {
                    by_source_epoch.get(&record.epoch.0).is_some_and(|ids| {
                        ids.iter().any(|id| id.as_slice() != message_id.as_slice())
                    })
                });
        if ambiguous_anchor_lineage {
            break;
        }
        prefix.commit_ids.insert(commit_id.clone());
        prefix.resulting_epoch = Some(resulting_epoch);
    }
    Ok(prefix)
}

/// Every stored own confirm-stamped commit row for the group, indexed by the
/// row's source epoch (its resulting epoch minus one — the key a retained
/// anchor is named after). Used to detect anchor-lineage ambiguity in
/// [`anchor_realizable_own_commit_prefix`]. Rows are counted regardless of
/// state: the retained anchor is written at CONFIRM time, so even a row that
/// convergence later parked or invalidated may have overwritten it.
fn own_stamped_commit_ids_by_source_epoch_map<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
) -> Result<BTreeMap<u64, Vec<Vec<u8>>>, OpenMlsProjectionError> {
    let mut by_source_epoch: BTreeMap<u64, Vec<Vec<u8>>> = BTreeMap::new();
    let records = storage
        .list_messages(group_id, EpochId(0))
        .map_err(|e| OpenMlsProjectionError::Storage(format!("{e:?}")))?;
    for record in records {
        let Ok(payload) = StoredMessagePayload::decode(&record.payload) else {
            continue;
        };
        if payload.own_commit_stamp().is_none() {
            continue;
        }
        by_source_epoch
            .entry(record.epoch.0)
            .or_default()
            .push(record.id.as_slice().to_vec());
    }
    Ok(by_source_epoch)
}

fn rollback_and_release_group_snapshot<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    snapshot: &str,
) -> Result<(), OpenMlsProjectionError> {
    storage
        .rollback_group_to_snapshot(group_id, snapshot)
        .map_err(|e| OpenMlsProjectionError::Snapshot(format!("{e:?}")))?;
    storage
        .release_group_snapshot(group_id, snapshot)
        .map_err(|e| OpenMlsProjectionError::Snapshot(format!("{e:?}")))?;
    Ok(())
}

/// Restore a pre-apply live snapshot left by a process termination and release
/// it before the group is hydrated.
///
/// A completed apply releases this snapshot in the same transaction as its
/// state changes. Consequently any surviving snapshot identifies an
/// interrupted apply. Restoring is also safe for snapshots left by older
/// versions: the captured input records allow convergence to replay any branch
/// work that had committed immediately before the crash.
pub(crate) fn recover_interrupted_apply_snapshot<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
) -> Result<(), OpenMlsProjectionError> {
    let snapshots = storage
        .list_group_snapshots(group_id)
        .map_err(|e| OpenMlsProjectionError::Storage(format!("{e:?}")))?
        .into_iter()
        .filter(|name| name.starts_with(APPLY_SNAPSHOT_PREFIX))
        .collect::<Vec<_>>();

    let Some(snapshot) = snapshots.first() else {
        return Ok(());
    };
    if snapshots.len() != 1 {
        return Err(OpenMlsProjectionError::Snapshot(
            "multiple interrupted convergence applies".into(),
        ));
    }

    rollback_and_release_group_snapshot(storage, group_id, snapshot)
}

fn restore_live_message_and_queue_records<S: StorageProvider>(
    storage: &S,
    messages: &[MessageRecord],
    queued_outbound: &[cgka_traits::storage::QueuedOutboundIntent],
) -> Result<(), OpenMlsProjectionError> {
    for message in messages {
        storage
            .put_message(message)
            .map_err(|e| OpenMlsProjectionError::Storage(format!("{e:?}")))?;
    }
    for queued in queued_outbound {
        storage
            .put_queued_outbound_intent(queued)
            .map_err(|e| OpenMlsProjectionError::Storage(format!("{e:?}")))?;
    }
    Ok(())
}

pub(crate) fn retain_current_group_epoch_snapshot<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    max_retained_anchor_rewind: u64,
) -> Result<(), OpenMlsProjectionError> {
    let epoch = storage
        .get_group(group_id)
        .map_err(|e| OpenMlsProjectionError::Storage(format!("{e:?}")))?
        .epoch
        .0;
    storage
        .create_group_snapshot(group_id, &retained_anchor_snapshot_name(epoch))
        .map_err(|e| OpenMlsProjectionError::Snapshot(format!("{e:?}")))?;
    prune_retained_anchor_snapshots(storage, group_id, epoch, max_retained_anchor_rewind)
}

fn prune_retained_anchor_snapshots<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    retained_epoch: u64,
    max_retained_anchor_rewind: u64,
) -> Result<(), OpenMlsProjectionError> {
    let oldest_retained_epoch = retained_epoch.saturating_sub(max_retained_anchor_rewind);
    let snapshots = storage
        .list_group_snapshots(group_id)
        .map_err(|e| OpenMlsProjectionError::Storage(format!("{e:?}")))?;

    for snapshot in snapshots {
        let Some(epoch) = retained_anchor_epoch_from_snapshot_name(&snapshot) else {
            continue;
        };
        if epoch >= oldest_retained_epoch {
            continue;
        }
        match storage.release_group_snapshot(group_id, &snapshot) {
            Ok(()) | Err(StorageError::SnapshotMissing(_)) => {}
            Err(e) => return Err(OpenMlsProjectionError::Snapshot(format!("{e:?}"))),
        }
    }

    Ok(())
}

fn apply_openmls_canonicalization_result_inner<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    result: &CanonicalizationResult,
    replay_messages: &[TransportMessage],
    profile_policy: ReplayProfilePolicy,
) -> Result<Vec<OpenMlsReplayObservation>, OpenMlsProjectionError> {
    // #157/#424: the convergence-apply multi-write durable sequence
    // (merge_staged_commit's 7+ provider writes, the Marmot group-record
    // refresh, and the disposition state writes) must commit or roll back as a
    // single backend transaction. Without this, a process kill (SIGKILL/OOM/
    // power loss) mid-merge leaves the persisted group torn (GroupContext/tree
    // at epoch N+1 while group_epoch_secrets/message_secrets lag at epoch N).
    //
    // The surrounding durable group snapshot (create/rollback/release in
    // `apply_openmls_canonicalization_result`) intentionally stays OUTSIDE this
    // boundary: those ops drive their own SQLite transactions and cannot nest
    // inside an open one. The snapshot guards in-process error returns; this
    // transaction guards hard crashes mid-merge.
    storage.with_transaction(|storage| {
        // No pre-validated own commits here: snapshot rollforward cannot nest
        // inside this transaction, and every own commit on the accepted
        // branch was excluded from `replay_messages` before this call —
        // either as part of the already-applied prefix or as an
        // anchor-realizable own-commit run whose retained-anchor rewind the
        // caller performs itself (`anchor_realizable_own_commit_prefix`).
        let output = process_openmls_messages_inner(
            storage,
            group_id,
            replay_messages,
            &PrevalidatedOwnCommits::default(),
            profile_policy,
        )?;
        update_group_record_from_replay(storage, group_id, &output)?;
        persist_openmls_canonicalization_dispositions(storage, result)?;
        Ok(output.observations)
    })
}

fn replay_messages_for_canonicalization_result<S: StorageProvider>(
    storage: &S,
    result: &CanonicalizationResult,
    applied_prefix: &BTreeSet<String>,
    apply_start_epoch: u64,
) -> Result<Vec<TransportMessage>, OpenMlsProjectionError> {
    let mut replay_messages = Vec::new();
    let mut seen = BTreeSet::new();
    for hex_message_id in result
        .accepted_proposals
        .iter()
        .chain(
            result
                .accepted_commits
                .iter()
                .filter(|commit_id| !applied_prefix.contains(*commit_id)),
        )
        .chain(&result.accepted_app_messages)
    {
        if !seen.insert(hex_message_id.clone()) {
            continue;
        }
        let message_id = message_id_from_hex(hex_message_id)?;
        let record = storage
            .get_message(&message_id)
            .map_err(|e| OpenMlsProjectionError::Storage(format!("{e:?}")))?;
        // An accepted proposal below the apply-start epoch was consumed by a
        // commit in the skipped already-applied prefix: its effect is inside
        // the live state, and MLS proposals are epoch-scoped, so replaying it
        // against the post-prefix state would be rejected (WrongEpoch) and
        // fail the whole apply. Skip the replay; its `Processed` disposition
        // still persists so it leaves the convergence input set.
        if result.accepted_proposals.contains(hex_message_id) && record.epoch.0 < apply_start_epoch
        {
            continue;
        }
        let Some(message) = openmls_wire_message_from_record(&record)? else {
            return Err(OpenMlsProjectionError::Decode(format!(
                "accepted message {} is not a stored OpenMLS wire payload",
                hex_message_id
            )));
        };
        replay_messages.push(message);
    }
    Ok(replay_messages)
}

fn update_group_record_from_replay<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    output: &OpenMlsReplayOutput,
) -> Result<(), OpenMlsProjectionError> {
    let mut group = match storage.get_group(group_id) {
        Ok(group) => group,
        Err(StorageError::NotFound) => return Ok(()),
        Err(e) => return Err(OpenMlsProjectionError::Storage(format!("{e:?}"))),
    };
    group.epoch = EpochId(output.final_epoch);
    group.members = output.final_members.clone();

    // The replay just merged any GCE/AppData commits on the canonical path, so
    // the live MlsGroup carries the post-canonical RequiredCapabilities and
    // app-component state. Mirror those into the Marmot record so
    // `feature_status` / `members()` / display name / admin checks all see
    // the post-canonical truth.
    let crypto = RustCrypto::default();
    let provider = EngineOpenMlsProvider::<S>::new(&crypto, storage.mls_storage());
    let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
    if let Some(mls_group) = MlsGroup::load(provider.storage(), &mls_gid)
        .map_err(|e| OpenMlsProjectionError::Replay(format!("load post-replay group: {e:?}")))?
    {
        group.required_capabilities = required_capabilities_from_group(&mls_group);
        crate::group_lifecycle::mirror_app_components_into_record(&mls_group, &mut group);
        crate::capability_manager::cache_own_capabilities_from_group(storage, group_id, &mls_group)
            .map_err(|e| {
                OpenMlsProjectionError::Replay(format!(
                    "refresh post-replay self capabilities: {e}"
                ))
            })?;
    }

    storage
        .put_group(&group)
        .map_err(|e| OpenMlsProjectionError::Storage(format!("{e:?}")))
}

fn required_capabilities_from_group(
    mls_group: &MlsGroup,
) -> cgka_traits::capabilities::GroupCapabilities {
    use openmls::extensions::Extension;
    let mut caps = cgka_traits::capabilities::GroupCapabilities::default();
    for ext in mls_group.extensions().iter() {
        if let Extension::RequiredCapabilities(rc) = ext {
            for t in rc.extension_types() {
                caps.extensions.insert(u16::from(*t));
            }
            for t in rc.proposal_types() {
                caps.proposals.insert(u16::from(*t));
            }
        }
    }
    if let Ok(components) = crate::app_components::required_app_components_of_group(mls_group) {
        caps.app_components = components;
    }
    caps
}

fn record_state_is_canonicalization_input(state: MessageState) -> bool {
    matches!(
        state,
        MessageState::Sent
            | MessageState::Created
            | MessageState::Retryable
            | MessageState::ConvergenceDeferred
    )
}

fn record_state_can_contribute_to_openmls_graph(state: MessageState) -> bool {
    record_state_is_canonicalization_input(state) || state == MessageState::Processed
}

fn unresolved_commit_state(state: MessageState) -> bool {
    matches!(
        state,
        MessageState::Sent
            | MessageState::Created
            | MessageState::Retryable
            | MessageState::ConvergenceDeferred
    )
}

fn message_state_for_dropped_reason(reason: DroppedMessageReason) -> MessageState {
    match reason {
        DroppedMessageReason::Malformed | DroppedMessageReason::UnsupportedPolicy => {
            MessageState::Failed
        }
        DroppedMessageReason::BeyondRollbackHorizon
        | DroppedMessageReason::BeyondAnchor
        | DroppedMessageReason::BeyondAppRetention
        | DroppedMessageReason::InvalidAgainstCandidateState => MessageState::EpochInvalidated,
    }
}

/// Map an app-message invalidation reason to the persisted message state.
///
/// The current canonicalizer reports an app message beyond the selected tip as
/// `DeferredMessageReason::FutureEpoch`, which persists through the explicit
/// `ConvergenceDeferred` path above. Keep the older defensive split here for
/// manually constructed or legacy results that still encode a future message
/// as `UndecryptableInCanonicalState`:
///
/// * **Future epoch (retryable).** The message targets an epoch *beyond* the
///   tip convergence settled on — the commit that advances the group to its
///   epoch has not been selected yet (ordinary out-of-order relay delivery,
///   mdk#144). Persisting it as the terminal `EpochInvalidated` would
///   permanently drop it: `record_state_is_canonicalization_input` never
///   re-admits `EpochInvalidated`, so the buffered message could never re-enter
///   convergence once that commit arrives. Keep it `Retryable` so a later
///   canonicalize pass re-feeds and applies it; ordinary current results do not
///   take this compatibility path.
///
/// * **At-or-below tip (terminal).** The message's epoch is already at or below
///   the settled tip yet still decrypts on no branch — the awaited commit has
///   come and gone on a branch this message does not belong to. It can never
///   become decryptable, so it stays terminal `EpochInvalidated`. Marking such
///   a message `Retryable` would wedge convergence: it re-classifies
///   `UndecryptableInCanonicalState` on every pass, so `Retryable` never
///   clears, and `has_unresolved_convergence_inputs` then reports the group as
///   perpetually unsettled — stalling all later sends and delivery.
///
/// `resulting_tip` is the epoch convergence settled on (`selected_tip`, falling
/// back to `previous_tip` when no branch was selected).
///
/// The remaining reasons (`LosingBranch`, `BeyondAnchor`, `BeyondAppRetention`)
/// are genuinely terminal and stay `EpochInvalidated`.
fn message_state_for_invalidated_reason(
    reason: InvalidatedAppMessageReason,
    message_epoch: u64,
    resulting_tip: u64,
) -> MessageState {
    match reason {
        InvalidatedAppMessageReason::UndecryptableInCanonicalState => {
            if message_epoch > resulting_tip {
                MessageState::Retryable
            } else {
                MessageState::EpochInvalidated
            }
        }
        InvalidatedAppMessageReason::LosingBranch
        | InvalidatedAppMessageReason::BeyondAnchor
        | InvalidatedAppMessageReason::BeyondAppRetention => MessageState::EpochInvalidated,
    }
}

fn message_id_from_hex(encoded: &str) -> Result<MessageId, OpenMlsProjectionError> {
    hex::decode(encoded)
        .map(MessageId::new)
        .map_err(|e| OpenMlsProjectionError::Decode(format!("message id {encoded}: {e:?}")))
}

fn openmls_wire_message_from_record(
    record: &MessageRecord,
) -> Result<Option<TransportMessage>, OpenMlsProjectionError> {
    let payload = StoredMessagePayload::decode(&record.payload)
        .map_err(|e| OpenMlsProjectionError::Serialize(format!("{e:?}")))?;
    Ok(payload.as_openmls_wire().cloned())
}

fn candidate_paths_with_pending_replay_messages(
    candidate_paths: &[OpenMlsCandidatePath],
    pending_messages: &[TransportMessage],
) -> Result<Vec<OpenMlsCandidatePath>, OpenMlsProjectionError> {
    let mut proposals_by_epoch: BTreeMap<u64, Vec<TransportMessage>> = BTreeMap::new();
    let mut applications = Vec::new();
    for message in pending_messages {
        let projection = project_mls_message(&message.payload)?;
        match projection.kind {
            OpenMlsContentKind::Proposal => {
                let source_epoch = projection.source_epoch.ok_or(
                    OpenMlsProjectionError::UnsupportedMessageKind(projection.kind),
                )?;
                proposals_by_epoch
                    .entry(source_epoch)
                    .or_default()
                    .push(message.clone());
            }
            OpenMlsContentKind::Application => applications.push(message.clone()),
            OpenMlsContentKind::Commit
            | OpenMlsContentKind::Welcome
            | OpenMlsContentKind::Other => {}
        }
    }
    for proposals in proposals_by_epoch.values_mut() {
        proposals.sort_by(|a, b| a.id.as_slice().cmp(b.id.as_slice()));
    }

    candidate_paths
        .iter()
        .map(
            |path| -> Result<OpenMlsCandidatePath, OpenMlsProjectionError> {
                let mut seen = BTreeSet::new();
                let mut messages = Vec::new();
                let mut final_epoch = None;
                for message in &path.messages {
                    let projection = project_mls_message(&message.payload)?;
                    if projection.kind == OpenMlsContentKind::Commit {
                        let source_epoch = projection.source_epoch.ok_or(
                            OpenMlsProjectionError::UnsupportedMessageKind(projection.kind),
                        )?;
                        if let Some(proposals) = proposals_by_epoch.get(&source_epoch) {
                            for proposal in proposals {
                                if seen.insert(hex::encode(proposal.id.as_slice())) {
                                    messages.push(proposal.clone());
                                }
                            }
                        }
                        final_epoch = Some(source_epoch.saturating_add(1));
                    }
                    if seen.insert(hex::encode(message.id.as_slice())) {
                        messages.push(message.clone());
                    }
                }
                // Proposals created at the path tip are still live evidence even
                // when no commit consumes them yet. Older proposals were either
                // folded immediately before their epoch's commit or are stale;
                // future proposals belong to a later path (#963).
                if let Some(final_epoch) = final_epoch
                    && let Some(proposals) = proposals_by_epoch.get(&final_epoch)
                {
                    for proposal in proposals {
                        if seen.insert(hex::encode(proposal.id.as_slice())) {
                            messages.push(proposal.clone());
                        }
                    }
                }
                for message in &applications {
                    if seen.insert(hex::encode(message.id.as_slice())) {
                        messages.push(message.clone());
                    }
                }
                Ok(OpenMlsCandidatePath {
                    branch_id: path.branch_id.clone(),
                    messages,
                })
            },
        )
        .collect()
}

fn proposal_id_by_ref(candidates: &[OpenMlsMaterializedCandidate]) -> BTreeMap<String, String> {
    let mut proposal_id_by_ref = BTreeMap::new();
    for candidate in candidates {
        for observation in &candidate.observations {
            let OpenMlsReplayObservation::ProposalStored {
                message_id,
                proposal_ref,
                ..
            } = observation
            else {
                continue;
            };
            proposal_id_by_ref.insert(proposal_ref.clone(), message_id.clone());
        }
    }
    proposal_id_by_ref
}

fn proposal_branch_by_id(
    materialized_candidates: &[MaterializedCandidate],
) -> BTreeMap<String, String> {
    let mut proposal_branch_by_id = BTreeMap::new();
    for candidate in materialized_candidates {
        for proposal_id in &candidate.consumed_proposal_ids {
            proposal_branch_by_id
                .entry(proposal_id.clone())
                .or_insert_with(|| candidate.branch.id.clone());
        }
    }
    proposal_branch_by_id
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AppMessageBranches {
    source_epoch: u64,
    sender: Vec<u8>,
    branch_ids: BTreeSet<String>,
    decrypted_payload_ref: String,
}

fn app_messages_by_id(
    candidates: &[OpenMlsMaterializedCandidate],
) -> BTreeMap<String, AppMessageBranches> {
    let mut app_messages = BTreeMap::new();
    for candidate in candidates {
        for observation in &candidate.observations {
            let OpenMlsReplayObservation::ApplicationProcessed {
                message_id,
                source_epoch,
                sender,
                decrypted_payload_ref,
                ..
            } = observation
            else {
                continue;
            };
            let entry =
                app_messages
                    .entry(message_id.clone())
                    .or_insert_with(|| AppMessageBranches {
                        source_epoch: *source_epoch,
                        sender: sender.clone(),
                        branch_ids: BTreeSet::new(),
                        decrypted_payload_ref: decrypted_payload_ref.clone(),
                    });
            entry.branch_ids.insert(candidate.branch_id.clone());
        }
    }
    app_messages
}

fn project_pending_canonicalization_messages(
    group_id: &GroupId,
    messages: &[TransportMessage],
    already_delivered_app_ids: &BTreeSet<String>,
    proposal_branch_by_id: &BTreeMap<String, String>,
    app_messages_by_id: &BTreeMap<String, AppMessageBranches>,
) -> Result<Vec<PeeledMessage>, OpenMlsProjectionError> {
    let mut pending = Vec::new();
    for message in messages {
        let projection = project_mls_message(&message.payload)?;
        let message_id = hex::encode(message.id.as_slice());
        let Some(source_epoch) = projection.source_epoch else {
            continue;
        };
        let kind = match projection.kind {
            OpenMlsContentKind::Proposal => PeeledMessageKind::Proposal {
                branch_id: proposal_branch_by_id
                    .get(&message_id)
                    .cloned()
                    .unwrap_or_else(|| format!("pending-proposal:{source_epoch}:{message_id}")),
            },
            OpenMlsContentKind::Application => {
                let observed = app_messages_by_id.get(&message_id);
                PeeledMessageKind::AppMessage {
                    epoch: observed
                        .map(|observed| observed.source_epoch)
                        .unwrap_or(source_epoch),
                    decrypts_on_branches: observed
                        .map(|observed| observed.branch_ids.iter().cloned().collect())
                        .unwrap_or_default(),
                    decrypted_payload_ref: observed
                        .map(|observed| observed.decrypted_payload_ref.clone()),
                    already_delivered: already_delivered_app_ids.contains(&message_id),
                }
            }
            OpenMlsContentKind::Commit
            | OpenMlsContentKind::Welcome
            | OpenMlsContentKind::Other => {
                continue;
            }
        };
        let sender = app_messages_by_id
            .get(&message_id)
            .map(|observed| observed.sender.clone())
            .unwrap_or_else(|| message.source.0.as_bytes().to_vec());
        pending.push(PeeledMessage {
            message_id,
            group_id: hex::encode(group_id.as_slice()),
            sender,
            source_epoch,
            kind,
        });
    }
    Ok(pending)
}

fn process_openmls_messages_inner<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    messages: &[TransportMessage],
    own_commits: &PrevalidatedOwnCommits,
    profile_policy: ReplayProfilePolicy,
) -> Result<OpenMlsReplayOutput, OpenMlsProjectionError> {
    let reject_legacy_group_additions = profile_policy.reject_legacy_group_additions
        && storage
            .get_group(group_id)
            .map_err(|e| OpenMlsProjectionError::Storage(format!("{e:?}")))?
            .protocol_profile
            == ProtocolProfile::Legacy;
    let crypto = RustCrypto::default();
    let provider = EngineOpenMlsProvider::<S>::new(&crypto, storage.mls_storage());
    let mls_group_id = openmls::group::GroupId::from_slice(group_id.as_slice());
    let mut mls_group = MlsGroup::load(provider.storage(), &mls_group_id)
        .map_err(|e| OpenMlsProjectionError::Replay(format!("load: {e:?}")))?
        .ok_or(OpenMlsProjectionError::MissingGroup)?;

    let mut observations = Vec::new();
    // An own commit is pre-validated only while every commit replayed before
    // it was canonical (`Processed`): it was created from the canonical state
    // at its source epoch, so on a diverging prefix its anchor state would
    // not be the state the commit actually produces there.
    let mut prefix_canonical = true;
    for message in messages {
        let projection = project_mls_message(&message.payload)?;
        let message_id = hex::encode(message.id.as_slice());
        let Some(protocol) = protocol_message_from_bytes(&message.payload)? else {
            observations.push(OpenMlsReplayObservation::Ignored {
                message_id,
                kind: projection.kind,
            });
            continue;
        };
        let source_epoch =
            projection
                .source_epoch
                .ok_or(OpenMlsProjectionError::UnsupportedMessageKind(
                    projection.kind,
                ))?;
        if projection.kind == OpenMlsContentKind::Commit
            && prefix_canonical
            && let Some(stamp) = own_commits.stamp(&projection.message_digest)
        {
            // MLS cannot process this device's own commit; realize its
            // pre-validated result by rolling the group forward to the
            // retained anchor snapshot the confirm path captured at its
            // resulting epoch, and synthesize the CommitStaged observation
            // from the confirm-time stamp. Any failure prunes this branch
            // (the pre-fix behavior) rather than failing the pass.
            let group_epoch = mls_group.epoch().as_u64();
            if group_epoch != source_epoch {
                return Err(OpenMlsProjectionError::Replay(format!(
                    "own commit source epoch {source_epoch} does not match replay state {group_epoch}"
                )));
            }
            let resulting_epoch = source_epoch.saturating_add(1);
            match storage.rollback_group_to_snapshot(
                group_id,
                &retained_anchor_snapshot_name(resulting_epoch),
            ) {
                Ok(()) => {}
                Err(StorageError::SnapshotMissing(_)) => {
                    return Err(OpenMlsProjectionError::Replay(format!(
                        "own commit anchor snapshot missing at epoch {resulting_epoch}"
                    )));
                }
                Err(e) => return Err(OpenMlsProjectionError::Snapshot(format!("{e:?}"))),
            }
            mls_group = MlsGroup::load(provider.storage(), &mls_group_id)
                .map_err(|e| OpenMlsProjectionError::Replay(format!("anchor reload: {e:?}")))?
                .ok_or(OpenMlsProjectionError::MissingGroup)?;
            let anchor_epoch = mls_group.epoch().as_u64();
            if anchor_epoch != resulting_epoch {
                return Err(OpenMlsProjectionError::Replay(format!(
                    "own commit anchor epoch {anchor_epoch} does not match resulting epoch {resulting_epoch}"
                )));
            }
            observations.push(OpenMlsReplayObservation::CommitStaged {
                message_id,
                source_epoch,
                resulting_epoch,
                priority: stamp.priority,
                committer: stamp.committer.as_slice().to_vec(),
                consumed_proposal_refs: stamp.consumed_proposal_refs.clone(),
            });
            continue;
        }
        let processed = match if projection.kind == OpenMlsContentKind::Commit {
            process_commit_with_app_data_updates(&mut mls_group, &provider, protocol)
        } else {
            mls_group.process_message(&provider, protocol)
        } {
            Ok(processed) => processed,
            Err(err) if projection.kind == OpenMlsContentKind::Commit => {
                if let Some(category) = crate::app_components::classify_process_message_rejection(
                    &err,
                    ContentType::Commit,
                ) {
                    return Err(OpenMlsProjectionError::InvalidCommit {
                        message_id,
                        reason: crate::app_components::proposal_rejection_category_tag(category)
                            .to_string(),
                        rejection_category: Some(category),
                    });
                }
                return Err(replay_error("process_message", err));
            }
            Err(err) if projection.kind == OpenMlsContentKind::Proposal => {
                if let Some(category) = crate::app_components::classify_process_message_rejection(
                    &err,
                    ContentType::Proposal,
                ) {
                    return Err(OpenMlsProjectionError::RejectedProposal {
                        message_id,
                        category,
                    });
                }
                return Err(replay_error("process_message", err));
            }
            Err(err) if projection.kind == OpenMlsContentKind::Application => {
                // App-message replay against a candidate state is best-
                // effort: an app message that doesn't apply on this branch is
                // just evidence that it belongs elsewhere, not a fatal error.
                // ValidationError covers the expected failure modes (WrongEpoch,
                // decryption fail, sender-membership, etc.); GroupStateError's
                // UseAfterEviction covers a re-admitted witness (a `Processed`
                // app, see `canonicalize_stored_openmls_messages`) whose sender
                // was evicted on this branch — it simply isn't a witness here.
                // LibraryError or any other structural failure is a real bug —
                // propagate so we don't silently mask malformed input.
                if matches!(
                    err,
                    ProcessMessageError::ValidationError(_)
                        | ProcessMessageError::GroupStateError(
                            MlsGroupStateError::UseAfterEviction
                        )
                ) {
                    observations.push(OpenMlsReplayObservation::Ignored {
                        message_id,
                        kind: projection.kind,
                    });
                    continue;
                } else {
                    return Err(replay_error("process_message", err));
                }
            }
            Err(e) => return Err(replay_error("process_message", e)),
        };
        let sender_leaf_index = match processed.sender() {
            Sender::Member(index) => Some(*index),
            _ => None,
        };
        let sender_id = crate::identity::member_id_of_sender(processed.sender(), &mls_group);

        match processed.into_content() {
            ProcessedMessageContent::ProposalMessage(queued) => {
                if reject_legacy_group_additions && matches!(queued.proposal(), Proposal::Add(_)) {
                    observations.push(OpenMlsReplayObservation::Ignored {
                        message_id,
                        kind: projection.kind,
                    });
                    continue;
                }
                if let Err(rejection) =
                    crate::app_components::authorize_standalone_proposal(&mls_group, &queued)
                {
                    return Err(OpenMlsProjectionError::RejectedProposal {
                        message_id,
                        category: rejection.category,
                    });
                }
                let proposal_ref = tls_hex(queued.proposal_reference_ref())?;
                mls_group
                    .store_pending_proposal(provider.storage(), *queued)
                    .map_err(|e| {
                        OpenMlsProjectionError::Replay(format!("store_pending_proposal: {e:?}"))
                    })?;
                observations.push(OpenMlsReplayObservation::ProposalStored {
                    message_id,
                    source_epoch,
                    proposal_ref,
                });
            }
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                if reject_legacy_group_additions && staged.add_proposals().next().is_some() {
                    return Err(OpenMlsProjectionError::InvalidCommit {
                        message_id,
                        reason: "strict cutover freezes membership additions in legacy groups"
                            .into(),
                        rejection_category: None,
                    });
                }
                if let Err(rejection) =
                    crate::app_components::authorize_staged_commit_proposals(&mls_group, &staged)
                {
                    return Err(OpenMlsProjectionError::InvalidCommit {
                        message_id,
                        reason: crate::app_components::proposal_rejection_category_tag(
                            rejection.category,
                        )
                        .to_string(),
                        rejection_category: Some(rejection.category),
                    });
                }
                if let Err(err) = crate::app_components::require_admin_for_staged_commit(
                    &mls_group,
                    group_id,
                    sender_id.as_ref(),
                    &staged,
                ) {
                    return match err {
                        cgka_traits::error::EngineError::NotGroupAdmin { .. } => {
                            Err(OpenMlsProjectionError::UnauthorizedCommit { message_id })
                        }
                        other => Err(OpenMlsProjectionError::Replay(format!(
                            "admin check: {other:?}"
                        ))),
                    };
                }
                if let Err(err) =
                    crate::app_components::validate_admin_leaf_coupling_for_staged_commit(
                        &mls_group, group_id, &staged,
                    )
                {
                    return Err(OpenMlsProjectionError::InvalidCommit {
                        message_id,
                        reason: format!("admin leaf coupling: {err}"),
                        rejection_category: None,
                    });
                }
                if let Err(err) =
                    crate::app_components::validate_app_component_integrity_for_staged_commit(
                        &mls_group, group_id, &staged,
                    )
                {
                    return Err(OpenMlsProjectionError::InvalidCommit {
                        message_id,
                        reason: format!("app component integrity: {err}"),
                        rejection_category: None,
                    });
                }
                if sender_id.is_none() {
                    return Err(OpenMlsProjectionError::Replay(
                        "commit has no authenticated member sender".into(),
                    ));
                }
                let Some(committer_index) = sender_leaf_index else {
                    return Err(OpenMlsProjectionError::Replay(
                        "commit has no authenticated member leaf".into(),
                    ));
                };
                let priority = crate::app_components::commit_ordering_priority_for_staged(&staged);
                let committer = sender_id
                    .as_ref()
                    .expect("checked above")
                    .as_slice()
                    .to_vec();
                // foundation/identity.md: deferred commits replayed during
                // convergence are an inbound credential ingress too. Reject
                // commits that introduce or mutate a member LeafNode whose
                // credential identity is invalid, lacks a valid account proof,
                // or no longer matches the member identity being updated.
                // Replay only needs the validation result; the returned added
                // member ids are used by the live apply path to emit state
                // changes before merge.
                if let Err(err) =
                    crate::account_identity_proof::validate_staged_commit_account_identity_proofs(
                        &staged,
                        &mls_group,
                        &sender_id.clone().expect("checked above"),
                        mls_group.ciphersuite(),
                    )
                {
                    return Err(OpenMlsProjectionError::InvalidCommit {
                        message_id,
                        reason: format!("invalid credential identity or account proof: {err}"),
                        rejection_category: None,
                    });
                }
                if let Err(err) =
                    crate::app_components::validate_current_profile_invariants_for_staged_commit(
                        &mls_group,
                        &staged,
                        committer_index,
                    )
                {
                    return Err(OpenMlsProjectionError::InvalidCommit {
                        message_id,
                        reason: format!("current-profile resulting state: {err}"),
                        rejection_category: None,
                    });
                }
                let resulting_epoch = mls_group.epoch().as_u64().saturating_add(1);
                let mut consumed_proposal_refs = staged
                    .queued_proposals()
                    .map(|proposal| tls_hex(proposal.proposal_reference_ref()))
                    .collect::<Result<Vec<_>, _>>()?;
                consumed_proposal_refs.sort();
                observations.push(OpenMlsReplayObservation::CommitStaged {
                    message_id: message_id.clone(),
                    source_epoch,
                    resulting_epoch,
                    priority,
                    committer,
                    consumed_proposal_refs,
                });
                // Mirror direct ingest: the staged commit is the only public
                // source for newly added members' KeyPackage capabilities.
                // The outer canonicalization transaction rolls these writes
                // back with the merge, record, and dispositions.
                crate::capability_manager::cache_from_staged_commit(storage, group_id, &staged)
                    .map_err(|e| {
                        OpenMlsProjectionError::Replay(format!(
                            "cache replayed Add capabilities: {e}"
                        ))
                    })?;
                mls_group
                    .merge_staged_commit(&provider, *staged)
                    .map_err(|e| {
                        OpenMlsProjectionError::Replay(format!("merge_staged_commit: {e:?}"))
                    })?;
                crate::app_components::validate_current_profile_group_invariants(&mls_group)
                    .map_err(|error| OpenMlsProjectionError::InvalidCommit {
                        message_id,
                        reason: format!("current-profile merged state: {error}"),
                        rejection_category: None,
                    })?;
                prefix_canonical =
                    prefix_canonical && own_commits.is_canonical(&projection.message_digest);
            }
            ProcessedMessageContent::ApplicationMessage(bytes) => {
                let payload = bytes.into_bytes();
                // Mirror the direct ingest seam (audit item S3): an
                // application message whose MLS sender does not resolve to a
                // validated member leaf is never surfaced, so a blank,
                // unauthenticated author cannot reach the app through the
                // replay seam (#383). Pushing `Ignored` keeps the message out
                // of `app_messages_by_id`; canonicalization then classifies
                // it undecryptable-in-canonical-state and the disposition
                // writer marks it terminal once its epoch is at or below the
                // settled tip. A bad-sender future-epoch message stays
                // retryable until the tip passes it — indistinguishable from
                // a legitimate future message at this point, and it converts
                // to terminal as the tip advances.
                let validated = sender_id.as_ref().and_then(|sender| {
                    crate::app_payload::validate_app_payload_for_sender(&payload, sender)
                        .ok()
                        .map(|event| (sender, event))
                });
                if let Some((sender, app_event)) = validated {
                    let retention_seconds =
                        crate::app_components::message_retention_seconds_of_group(&mls_group)
                            .map_err(|error| {
                                OpenMlsProjectionError::Replay(format!(
                                    "decode source-epoch message retention: {error}"
                                ))
                            })?
                            .unwrap_or(0);
                    observations.push(OpenMlsReplayObservation::ApplicationProcessed {
                        message_id,
                        source_epoch,
                        sender: sender.as_slice().to_vec(),
                        payload: payload.clone(),
                        retention: AppMessageRetentionDecision::new(
                            app_event.created_at,
                            retention_seconds,
                        ),
                        decrypted_payload_ref: format!(
                            "sha256:{}",
                            hex::encode(message_digest(payload.as_slice()))
                        ),
                    });
                } else {
                    observations.push(OpenMlsReplayObservation::Ignored {
                        message_id,
                        kind: projection.kind,
                    });
                }
            }
            ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
                observations.push(OpenMlsReplayObservation::Ignored {
                    message_id,
                    kind: projection.kind,
                });
            }
            ProcessedMessageContent::OwnPendingCommit
            | ProcessedMessageContent::OwnPrivateMessage => {
                // Own sends are replay evidence only. In particular, never
                // merge an OwnPendingCommit here: MDK realizes confirmed own
                // commits from retained anchor snapshots above, preserving
                // the publish-before-apply lifecycle.
                observations.push(OpenMlsReplayObservation::Ignored {
                    message_id,
                    kind: projection.kind,
                });
            }
            ProcessedMessageContent::UnresolvedAppDataCommit(_) => {
                // Commit processing above always resolves this variant before
                // returning. Treat an unexpected residual value as a replay
                // error instead of accepting a commit without applying its
                // AppDataDictionary changes.
                return Err(OpenMlsProjectionError::Replay(
                    "commit retained unresolved app-data updates".into(),
                ));
            }
        }
    }
    Ok(OpenMlsReplayOutput {
        observations,
        final_epoch: mls_group.epoch().as_u64(),
        final_members: marmot_members(&mls_group),
    })
}

fn marmot_members(group: &MlsGroup) -> Vec<Member> {
    group
        .members()
        .filter_map(|member| {
            let basic = BasicCredential::try_from(member.credential).ok()?;
            Some(Member {
                id: MemberId::new(basic.identity().to_vec()),
                credential: member.signature_key.to_vec(),
            })
        })
        .collect()
}

fn protocol_message_from_bytes(
    bytes: &[u8],
) -> Result<Option<ProtocolMessage>, OpenMlsProjectionError> {
    let msg = MlsMessageIn::tls_deserialize_exact(bytes)
        .map_err(|e| OpenMlsProjectionError::Decode(format!("{e:?}")))?;
    protocol_message_from_body(msg.extract())
}

fn protocol_message_from_body(
    body: MlsMessageBodyIn,
) -> Result<Option<ProtocolMessage>, OpenMlsProjectionError> {
    match body {
        MlsMessageBodyIn::PrivateMessage(private) => Ok(Some(private.into())),
        MlsMessageBodyIn::PublicMessage(public) => Ok(Some(public.into())),
        MlsMessageBodyIn::Welcome(_) => Ok(None),
        MlsMessageBodyIn::GroupInfo(_) | MlsMessageBodyIn::KeyPackage(_) => Err(
            OpenMlsProjectionError::UnsupportedMessageKind(OpenMlsContentKind::Other),
        ),
    }
}

fn kind_from_content_type(content_type: ContentType) -> OpenMlsContentKind {
    match content_type {
        ContentType::Application => OpenMlsContentKind::Application,
        ContentType::Proposal => OpenMlsContentKind::Proposal,
        ContentType::Commit => OpenMlsContentKind::Commit,
    }
}

fn replay_error(context: &str, error: impl std::fmt::Debug) -> OpenMlsProjectionError {
    OpenMlsProjectionError::Replay(format!("{context}: {error:?}"))
}

/// Process a commit, validating and applying any `AppDataUpdate` proposals it
/// carries before OpenMLS stages the commit. Shared by the replay/canonicalization
/// path here and the live inbound path in [`crate::message_processor`].
pub(crate) fn process_commit_with_app_data_updates<S: StorageProvider>(
    mls_group: &mut MlsGroup,
    provider: &EngineOpenMlsProvider<'_, S>,
    proto: ProtocolMessage,
) -> Result<
    ProcessedMessage,
    ProcessMessageError<
        <<S as StorageProvider>::Mls as openmls_traits::storage::StorageProvider<
            { openmls_traits::storage::CURRENT_VERSION },
        >>::Error,
    >,
> {
    let processed = mls_group.process_message(provider, proto)?;
    let ProcessedMessageContent::UnresolvedAppDataCommit(unresolved) = processed.content() else {
        return Ok(processed);
    };

    // OpenMLS has already resolved referenced proposals and ordered them by
    // component id. Clone the small proposal list so the processed message can
    // subsequently be consumed by `resolve_app_data_commit`.
    let app_data_updates = unresolved
        .app_data_update_proposals()
        .cloned()
        .collect::<Vec<_>>();
    crate::app_components::validate_app_data_update_batch(mls_group, app_data_updates.iter())
        .map_err(|_| ProcessMessageError::ValidationError(ValidationError::WrongWireFormat))?;
    let mut updater = mls_group.app_data_dictionary_updater();
    for update in app_data_updates {
        match update.operation() {
            AppDataUpdateOperation::Update(data) => {
                updater.set(ComponentData::from_parts(
                    update.component_id(),
                    data.clone(),
                ));
            }
            AppDataUpdateOperation::Remove => {
                updater.remove(&update.component_id());
            }
        }
    }

    mls_group
        .resolve_app_data_commit(provider, processed, updater.changes())
        .map_err(|error| match error {
            ResolveAppDataCommitError::StageCommit(error) => {
                ProcessMessageError::InvalidCommit(error)
            }
            ResolveAppDataCommitError::NotAnUnresolvedAppDataCommit => {
                // Guarded by the content match above. Keep this non-panicking
                // because the value still originated from inbound data.
                ProcessMessageError::ValidationError(ValidationError::WrongWireFormat)
            }
        })
}

fn message_digest(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn branch_id_for_path_digests(digests: &[[u8; 32]]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"marmot-openmls-candidate-path/v1");
    for digest in digests {
        hasher.update(digest);
    }
    let digest = hasher.finalize();
    format!("path:{}", hex::encode(&digest[..16]))
}

fn retained_anchor_snapshot_name(epoch: u64) -> String {
    format!("openmls-retained-anchor-{epoch}")
}

pub(crate) fn retained_anchor_epoch_from_snapshot_name(name: &str) -> Option<u64> {
    name.strip_prefix("openmls-retained-anchor-")?.parse().ok()
}

fn retained_anchor_probe_snapshot_name(group_id: &GroupId, epoch: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(group_id.as_slice());
    hasher.update(epoch.to_be_bytes());
    let digest = hasher.finalize();
    format!(
        "{RETAINED_ANCHOR_PROBE_SNAPSHOT_PREFIX}{}",
        hex::encode(&digest[..8])
    )
}

const RETAINED_ANCHOR_PROBE_SNAPSHOT_PREFIX: &str = "openmls-retained-probe-";

fn replay_snapshot_name(group_id: &GroupId, messages: &[TransportMessage]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(group_id.as_slice());
    for message in messages {
        hasher.update(message.id.as_slice());
        hasher.update(message.payload.as_slice());
    }
    let digest = hasher.finalize();
    format!("openmls-probe-{}", hex::encode(&digest[..8]))
}

fn apply_snapshot_name(group_id: &GroupId, result: &CanonicalizationResult) -> String {
    let mut hasher = Sha256::new();
    hasher.update(group_id.as_slice());
    if let Some(branch_id) = &result.selected_branch_id {
        hasher.update(branch_id.as_bytes());
    }
    for message_id in result
        .accepted_proposals
        .iter()
        .chain(&result.accepted_commits)
        .chain(&result.accepted_app_messages)
    {
        hasher.update(message_id.as_bytes());
    }
    let digest = hasher.finalize();
    format!("{APPLY_SNAPSHOT_PREFIX}{}", hex::encode(&digest[..8]))
}

const APPLY_SNAPSHOT_PREFIX: &str = "openmls-apply-";

fn tls_hex<T: TlsSerialize>(value: &T) -> Result<String, OpenMlsProjectionError> {
    value
        .tls_serialize_detached()
        .map(hex::encode)
        .map_err(|e| OpenMlsProjectionError::Serialize(format!("{e:?}")))
}

#[cfg(test)]
mod replay_budget_tests {
    use super::{
        CANDIDATE_REPLAY_BUDGET_FLOOR, CANDIDATE_REPLAY_BUDGET_SLACK, OpenMlsProjectionError,
        ReplayBudget,
    };

    #[test]
    fn for_pass_scales_with_commits_and_rewind_and_keeps_a_floor() {
        // Zero commits still gets the floor so tiny passes always have headroom.
        let mut empty = ReplayBudget::for_pass(0, 5);
        assert_eq!(empty.remaining, CANDIDATE_REPLAY_BUDGET_FLOOR);
        for _ in 0..CANDIDATE_REPLAY_BUDGET_FLOOR {
            empty.consume().expect("floor budget covers the floor");
        }
        assert!(matches!(
            empty.consume(),
            Err(OpenMlsProjectionError::ReplayBudgetExceeded)
        ));

        // commits × (max_rewind + 1) × slack + floor.
        let budget = ReplayBudget::for_pass(3, 5);
        assert_eq!(
            budget.remaining,
            3 * (5 + 1) * CANDIDATE_REPLAY_BUDGET_SLACK + CANDIDATE_REPLAY_BUDGET_FLOOR
        );
    }

    #[test]
    fn for_pass_saturates_instead_of_overflowing() {
        // A hostile huge input must not wrap to a small cap.
        let budget = ReplayBudget::for_pass(usize::MAX, u64::MAX);
        assert_eq!(budget.remaining, u64::MAX);
    }

    #[test]
    fn consume_fails_closed_when_exhausted() {
        let mut budget = ReplayBudget::new(2);
        budget.consume().expect("first replay within budget");
        budget.consume().expect("second replay within budget");
        assert!(matches!(
            budget.consume(),
            Err(OpenMlsProjectionError::ReplayBudgetExceeded)
        ));
    }

    #[test]
    fn unlimited_budget_never_trips() {
        let mut budget = ReplayBudget::unlimited();
        for _ in 0..10_000 {
            budget
                .consume()
                .expect("unlimited budget never fails closed");
        }
    }
}

#[cfg(test)]
mod reuse_scope_tests {
    use super::can_reuse_bfs_materialization;

    #[test]
    fn app_free_pass_reuses_bfs_materialization() {
        // has_pending_apps == false ⇒ reuse the #635 BFS materialization, so the
        // witness re-admission's full-materialize cost is scoped to app-bearing
        // passes and never taxes an app-free convergence.
        assert!(can_reuse_bfs_materialization(false, 3, 3));
    }

    #[test]
    fn pending_apps_force_full_materialize() {
        // A pending app — fresh, or a re-admitted already-delivered witness —
        // bypasses reuse so its ApplicationProcessed observations are recomputed.
        assert!(!can_reuse_bfs_materialization(true, 3, 3));
    }

    #[test]
    fn incomplete_bfs_materialization_does_not_reuse() {
        // Reuse also requires the BFS to have materialized every candidate path;
        // a partial materialization falls back to a full replay even app-free.
        assert!(!can_reuse_bfs_materialization(false, 2, 3));
    }
}

#[cfg(test)]
mod anchor_prefix_lineage_tests {
    use super::{
        AnchorRealizableOwnPrefix, anchor_realizable_own_commit_prefix,
        retained_anchor_snapshot_name,
    };
    use crate::canonicalization::{CanonicalizationResult, ConvergenceStatus};
    use cgka_traits::engine::CommitOrderingPriority;
    use cgka_traits::group::{Group, ProtocolProfile};
    use cgka_traits::message::{
        MessageRecord, MessageState, OwnCommitConvergenceStamp, StoredMessagePayload,
    };
    use cgka_traits::storage::{GroupStorage, MessageStorage};
    use cgka_traits::transport::{Timestamp, TransportEnvelope, TransportMessage, TransportSource};
    use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
    use std::collections::BTreeSet;
    use storage_sqlite::SqliteAccountStorage;

    fn group_id() -> GroupId {
        GroupId::new(vec![7u8; 32])
    }

    fn own_commit_row(id: &[u8], source_epoch: u64) -> MessageRecord {
        let message = TransportMessage {
            id: MessageId::new(id.to_vec()),
            // The prefix scan never parses MLS bytes; only the stored
            // envelope's stamp presence and the row's epoch matter here.
            payload: id.to_vec(),
            timestamp: Timestamp(0),
            causal_deps: Vec::new(),
            source: TransportSource("test".into()),
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: group_id().as_slice().to_vec(),
            },
        };
        let stamp = OwnCommitConvergenceStamp {
            committer: MemberId::new(vec![1u8; 32]),
            priority: CommitOrderingPriority::Privileged,
            consumed_proposal_refs: Vec::new(),
        };
        MessageRecord {
            id: MessageId::new(id.to_vec()),
            group_id: group_id(),
            epoch: EpochId(source_epoch),
            state: MessageState::ConvergenceDeferred,
            payload: StoredMessagePayload::own_commit_wire(message, stamp)
                .encode()
                .unwrap(),
            deferred_peel: None,
        }
    }

    fn result_accepting(commit_ids: &[&[u8]]) -> CanonicalizationResult {
        CanonicalizationResult {
            previous_tip: 2,
            selected_tip: Some(2),
            selected_fork_epoch: Some(1),
            selected_branch_id: Some("branch".into()),
            candidate_count: 1,
            eligible_count: 1,
            convergence_status: ConvergenceStatus::Settled,
            accepted_commits: commit_ids.iter().map(hex::encode).collect(),
            accepted_proposals: Vec::new(),
            accepted_app_messages: Vec::new(),
            deferred_messages: Vec::new(),
            invalidated_app_messages: Vec::new(),
            dropped_messages: Vec::new(),
            already_seen: Vec::new(),
            queued_outbound_intents: Vec::new(),
            publishable_outbound_messages: Vec::new(),
            errors: Vec::new(),
            #[cfg(feature = "test-conformance-snapshot")]
            replay_probe_count: 0,
            selection_trace: None,
        }
    }

    fn storage_with_anchor_at_epoch_2() -> SqliteAccountStorage {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        storage
            .put_group(&Group {
                id: group_id(),
                name: "anchor-lineage".into(),
                description: String::new(),
                epoch: EpochId(2),
                members: Vec::new(),
                required_capabilities: Default::default(),
                protocol_profile: ProtocolProfile::Legacy,
                removed: false,
                unrecoverable: false,
                disbanded: None,
                join_epoch: EpochId(0),
            })
            .unwrap();
        storage
            .create_group_snapshot(&group_id(), &retained_anchor_snapshot_name(2))
            .unwrap();
        storage
    }

    #[test]
    fn unambiguous_own_commit_uses_the_retained_anchor_fast_path() {
        // Baseline for the regression below: exactly one own confirm-stamped
        // commit row at source epoch 1, so the `openmls-retained-anchor-2`
        // snapshot can only hold THAT commit's post-merge state.
        let storage = storage_with_anchor_at_epoch_2();
        storage
            .put_message(&own_commit_row(b"commit-a", 1))
            .unwrap();

        let prefix = anchor_realizable_own_commit_prefix(
            &storage,
            &group_id(),
            &result_accepting(&[b"commit-a"]),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(prefix.resulting_epoch, Some(2));
        assert!(prefix.commit_ids.contains(&hex::encode(b"commit-a")));
    }

    #[test]
    fn same_epoch_own_commit_overwrite_refuses_the_anchor_fast_path() {
        // Retained anchors are named by resulting epoch alone and
        // `create_group_snapshot` REPLACES a same-named snapshot. When a
        // second own commit is confirmed at the same resulting epoch — e.g.
        // the displacing branch's own commit after the first was parked by a
        // pairwise CandidateWins — `openmls-retained-anchor-2` no longer
        // provably holds commit-a's post-merge state.
        //
        // Safe outcome asserted here: the fast path REFUSES the anchor (empty
        // prefix, no resulting epoch), so the apply falls back to pre-existing
        // behavior — normal replay, which fails closed on an own commit and
        // lets convergence prune the branch. The unsafe outcome this guards
        // against is a silent rewind to the OTHER commit's state with replay
        // skipped.
        let storage = storage_with_anchor_at_epoch_2();
        storage
            .put_message(&own_commit_row(b"commit-a", 1))
            .unwrap();
        storage
            .put_message(&own_commit_row(b"commit-a2", 1))
            .unwrap();

        let prefix = anchor_realizable_own_commit_prefix(
            &storage,
            &group_id(),
            &result_accepting(&[b"commit-a"]),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(
            prefix.resulting_epoch,
            AnchorRealizableOwnPrefix::default().resulting_epoch,
            "ambiguous anchor lineage must not yield a rewind target"
        );
        assert!(
            prefix.commit_ids.is_empty(),
            "ambiguous anchor lineage must not realize any commit via the anchor"
        );
    }

    #[test]
    fn own_commit_at_a_different_source_epoch_does_not_create_ambiguity() {
        // Only rows that could have produced an anchor at the SAME resulting
        // epoch are ambiguous; an own commit from another epoch names a
        // different anchor and must not disable the fast path.
        let storage = storage_with_anchor_at_epoch_2();
        storage
            .put_message(&own_commit_row(b"commit-a", 1))
            .unwrap();
        storage
            .put_message(&own_commit_row(b"commit-b", 5))
            .unwrap();

        let prefix = anchor_realizable_own_commit_prefix(
            &storage,
            &group_id(),
            &result_accepting(&[b"commit-a"]),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(prefix.resulting_epoch, Some(2));
    }
}
