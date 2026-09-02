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
use cgka_traits::message::{
    MessageRecord, MessageState, OwnApplicationConvergenceStamp, StoredMessagePayload,
};
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
    /// Authenticated state identity at every epoch materialized while replaying
    /// this branch. Locally authored applications use it to prove which
    /// candidate state encrypted their otherwise undecryptable own ciphertext.
    pub epoch_authenticators: BTreeMap<u64, String>,
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
            consumed: 0,
        }
    }

    /// Unlimited budget for callers outside the bounded convergence BFS (e.g. the public
    /// `materialize_openmls_candidate_paths`, used directly by conformance vectors).
    fn unlimited() -> Self {
        Self {
            remaining: u64::MAX,
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
        self.consumed = self.consumed.saturating_add(1);
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

#[derive(Clone, Debug)]
pub(crate) struct StoredCanonicalizationOptions<'a> {
    pub(crate) replay_profile: ReplayProfilePolicy,
    pub(crate) admitted_message_ids: Option<&'a HashSet<MessageId>>,
    pub(crate) admit_app_witnesses: bool,
    pub(crate) replay_probe_budget_override: Option<u64>,
    /// Engine-path seen-id snapshot, shared instead of copied into
    /// `CanonicalizationState.seen_message_ids` (up to 100k ids, up to 16
    /// canonicalizations per drain). `None` for public callers, whose state
    /// carries its own owned set.
    pub(crate) shared_seen_message_ids: Option<std::sync::Arc<BTreeSet<String>>>,
}

impl Default for StoredCanonicalizationOptions<'_> {
    fn default() -> Self {
        Self {
            replay_profile: ReplayProfilePolicy::default(),
            admitted_message_ids: None,
            admit_app_witnesses: true,
            replay_probe_budget_override: None,
            shared_seen_message_ids: None,
        }
    }
}

#[derive(Clone, Debug)]
struct StoredOpenMlsCanonicalizationWork {
    state: CanonicalizationState,
    shared_seen_message_ids: Option<std::sync::Arc<BTreeSet<String>>>,
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
    OwnApplicationSent {
        message_id: String,
        source_epoch: u64,
        sender: Vec<u8>,
        source_epoch_authenticator: String,
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
    epoch_authenticators: BTreeMap<u64, String>,
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
    /// A locally authored commit predates commit-addressed checkpoints. Its
    /// branch cannot be reconstructed safely from the network wire or an
    /// epoch-keyed anchor.
    MissingOwnCommitCheckpoint,
    /// A branch-addressed own-commit checkpoint restored state that does not
    /// match the resulting epoch and epoch authenticator stamped at confirm
    /// time. The apply is aborted and rolled back rather than installing an
    /// unverified lineage.
    CheckpointStateMismatch,
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
            OpenMlsProjectionError::MissingOwnCommitCheckpoint => {
                write!(f, "own commit has no branch-addressed checkpoint")
            }
            OpenMlsProjectionError::CheckpointStateMismatch => {
                write!(
                    f,
                    "own-commit checkpoint does not match its stamped post-merge state"
                )
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
/// candidate path containing one cannot be materialized by replay alone: the
/// own commit's branch would silently drop out of branch selection and the
/// device could be reorged onto a losing sibling (or, with two forked
/// committers, the group could fork permanently). Instead, an own `Processed`
/// commit whose ordering
/// stamp was persisted at confirm time is realized from its immutable,
/// commit-addressed canonical-state checkpoint, and its `CommitStaged`
/// observation is synthesized from that stamp.
#[derive(Clone, Debug, Default)]
pub(crate) struct PrevalidatedOwnCommits {
    /// Confirm-stamped own `Processed` commits, keyed by wire-bytes digest.
    by_digest: BTreeMap<[u8; 32], cgka_traits::message::OwnCommitConvergenceStamp>,
    /// Digests of every `Processed` commit (own and others') — the canonical
    /// chain. An own commit is pre-validated only while the replayed path
    /// prefix stays canonical: it was created from the canonical state at its
    /// source epoch, so on any diverging prefix it must NOT apply.
    canonical_digests: BTreeSet<[u8; 32]>,
    /// Locally authenticated app-message stamps, keyed by their stored wire id.
    /// These are loaded before a retained-anchor rollback because the rollback
    /// intentionally removes rows created after that anchor.
    application_by_id: BTreeMap<Vec<u8>, OwnApplicationConvergenceStamp>,
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

    fn insert_application(&mut self, message_id: MessageId, stamp: OwnApplicationConvergenceStamp) {
        self.application_by_id
            .insert(message_id.as_slice().to_vec(), stamp);
    }

    fn application_stamp(&self, message_id: &MessageId) -> Option<&OwnApplicationConvergenceStamp> {
        self.application_by_id.get(message_id.as_slice())
    }
}

/// Build the convergence ordering stamp for a staged local commit, captured
/// while the staged commit is still attached (confirm time). See
/// [`cgka_traits::message::OwnCommitConvergenceStamp`].
///
/// Checkpoint identity and resulting epoch authentication are filled in by the
/// confirm path after the commit is merged.
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
        checkpoint_id: None,
        resulting_epoch_authenticator: None,
    })
}

pub(crate) fn own_commit_checkpoint_id<S: StorageProvider>(
    storage: &S,
    message_id: &MessageId,
) -> Result<String, cgka_traits::error::EngineError> {
    let record = storage.get_message(message_id)?;
    let payload = StoredMessagePayload::decode(&record.payload)
        .map_err(|error| cgka_traits::error::EngineError::Serialize(error.to_string()))?;
    let wire = payload.as_openmls_wire().ok_or_else(|| {
        cgka_traits::error::EngineError::Serialize(
            "own commit record does not contain OpenMLS wire bytes".into(),
        )
    })?;
    let projection = project_mls_message(&wire.payload)
        .map_err(|error| cgka_traits::error::EngineError::Serialize(error.to_string()))?;
    if projection.kind != OpenMlsContentKind::Commit {
        return Err(cgka_traits::error::EngineError::Serialize(
            "own commit record is not a commit".into(),
        ));
    }
    Ok(format!(
        "openmls-own-commit-v1-{}",
        hex::encode(projection.message_digest)
    ))
}

pub(crate) fn own_commit_post_merge_epoch_authenticator(merged: &MlsGroup) -> String {
    hex::encode(merged.epoch_authenticator().as_slice())
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
            own_application_stamp,
            ..
        } => StoredMessagePayload::SignedOpenMlsWire {
            exact_message,
            openmls_message,
            stamp: Some(stamp),
            own_application_stamp,
        },
        // Raw-transport rows never enter the OpenMLS candidate graph; a plain
        // state update preserves their shape.
        other @ (StoredMessagePayload::RawTransport(_)
        | StoredMessagePayload::OutboundWelcome(_)
        | StoredMessagePayload::StagedInviteWelcome { .. }) => other,
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

/// Retire unresolved commits that a verified replacement Welcome superseded.
///
/// A replacement Welcome discards this device's live OpenMLS copy
/// (`clear_live_openmls_group_on_storage`) and installs a new one whose history
/// begins at `replacement_epoch`. Every unresolved commit retained below that
/// epoch was retained against the discarded copy: applying it needs a rewind to
/// its own source epoch, and the state that rewind would land on no longer
/// exists locally and was superseded on the fleet's branch by the very commits
/// that removed and re-added this device. Left unresolved they are not merely
/// dead — `historical_replay_start_epoch` takes the `min` source epoch over
/// unresolved rows to pick a pass's rewind target, so an anchor-less one drags
/// every later pass into `MissingRetainedAnchor` and re-halts the group the
/// Welcome just repaired.
///
/// `replacement_epoch` MUST come from the processed Welcome's own
/// `MlsGroup::epoch()` — authenticated material this device derived locally —
/// never from an inbound message's claimed epoch. A row's own claimed source
/// epoch decides only its own fate here, and only in the safe direction: a
/// forged high claim leaves the row exactly as unresolved as it already was.
///
/// Commits only. Application messages from the prior membership interval stay
/// untouched: they may still be decryptable from retained epoch secrets, which
/// is why a replacement Welcome records `join_epoch = 0` rather than applying a
/// pre-membership lower bound.
///
/// Runs on the caller's transactional handle — this is part of the join's
/// durable unit, not a separate best-effort sweep.
pub(crate) fn retire_commits_superseded_by_replacement_welcome<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    replacement_epoch: u64,
) -> Result<Vec<(MessageId, EpochId)>, cgka_traits::error::EngineError> {
    let mut retired = Vec::new();
    for record in storage.list_messages(group_id, EpochId(0))? {
        if !unresolved_commit_state(record.state) {
            continue;
        }
        // Fail open on unreadable rows, exactly as the stale-deferred sweep
        // does: this maintenance path must not turn unrelated storage damage
        // into a failed repair.
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
        if projection.kind != OpenMlsContentKind::Commit || source_epoch >= replacement_epoch {
            continue;
        }
        storage.update_message_state(&record.id, MessageState::EpochInvalidated)?;
        retired.push((record.id, EpochId(source_epoch)));
    }
    Ok(retired)
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
    replay_openmls_messages_prevalidated_output(
        storage,
        group_id,
        messages,
        own_commits,
        profile_policy,
    )
    .map(|output| output.observations)
}

fn replay_openmls_messages_prevalidated_output<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    messages: &[TransportMessage],
    own_commits: &PrevalidatedOwnCommits,
    profile_policy: ReplayProfilePolicy,
) -> Result<OpenMlsReplayOutput, OpenMlsProjectionError> {
    use crate::snapshot_guard::SnapshotRollbackGuard;
    let snapshot = replay_snapshot_name(group_id, messages);
    // RAII: on any unwind path (panic during replay, early error)
    // Drop rolls back + releases. On the happy path we explicitly
    // commit at the end. Pre-validated own-commit rollforwards inside the
    // replay land within this guard, so they are unwound with everything
    // else.
    let guard = SnapshotRollbackGuard::create_group_state(storage, group_id.clone(), snapshot)
        .map_err(|e| OpenMlsProjectionError::Snapshot(format!("{e:?}")))?;

    let result =
        process_openmls_messages_inner(storage, group_id, messages, own_commits, profile_policy);
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
        let replay = replay_openmls_messages_prevalidated_output(
            storage,
            group_id,
            &path.messages,
            own_commits,
            profile_policy,
        )?;
        let observations = replay.observations;
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
            epoch_authenticators: replay.epoch_authenticators,
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
        SharedSeenBatch {
            batch,
            shared_seen_message_ids: None,
        },
        &PrevalidatedOwnCommits::default(),
        ReplayProfilePolicy::default(),
        true,
        &mut replay_budget,
    )
}

/// [`OpenMlsCanonicalizationBatch`] plus the engine-path shared seen-id
/// snapshot (see `StoredCanonicalizationOptions::shared_seen_message_ids`);
/// the batch type itself is public and must not grow the field.
struct SharedSeenBatch {
    batch: OpenMlsCanonicalizationBatch,
    shared_seen_message_ids: Option<std::sync::Arc<BTreeSet<String>>>,
}

fn canonicalize_openmls_batch_prevalidated<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    batch: SharedSeenBatch,
    own_commits: &PrevalidatedOwnCommits,
    profile_policy: ReplayProfilePolicy,
    admit_app_witnesses: bool,
    replay_budget: &mut ReplayBudget,
) -> Result<CanonicalizationResult, OpenMlsProjectionError> {
    let candidate_paths = candidate_paths_with_pending_replay_messages(
        &batch.batch.candidate_paths,
        &batch.batch.pending_messages,
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
    batch: SharedSeenBatch,
    materialized: Vec<OpenMlsMaterializedCandidate>,
    admit_app_witnesses: bool,
) -> Result<CanonicalizationResult, OpenMlsProjectionError> {
    let SharedSeenBatch {
        batch,
        shared_seen_message_ids,
    } = batch;
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
    #[cfg(not(feature = "test-policy-overrides"))]
    debug_assert!(
        admit_app_witnesses,
        "production canonicalization must admit application witnesses"
    );
    Ok(crate::canonicalization::canonicalize_with_shared_seen(
        input,
        shared_seen_message_ids.as_ref(),
        materialized_candidates,
        admit_app_witnesses,
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
    let StoredOpenMlsGraphInputs {
        commit_messages,
        pending_messages,
        already_delivered_app_ids,
        own_commits,
        stale_commit_drops,
        current_epoch,
        replay_start_epoch,
    } = seed_stored_openmls_graph_inputs(
        storage,
        group_id,
        state.retained_anchor_epoch,
        options.admitted_message_ids,
    )?;

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
                shared_seen_message_ids: options.shared_seen_message_ids,
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
            shared_seen_message_ids: options.shared_seen_message_ids.clone(),
        },
    )?;
    append_dropped_messages(&mut result, stale_commit_drops);
    Ok(result)
}

/// Stored rows classified into the inputs the candidate-path BFS consumes.
///
/// Seeding is shared by the canonicalization pass and by
/// [`candidate_branch_peel`], so both classify a given row identically.
/// They do not necessarily see the same rows: the pass passes its frozen
/// batch as `admitted_message_ids` and context collection passes `None`, so
/// context collection may enumerate branches off commits the pass in flight has
/// not admitted. That is deliberate — a peel context is a *readability* probe,
/// and reading a branch's traffic earlier than the pass adjudicates it only
/// feeds the next pass more evidence. What must not drift is the classification
/// itself; a second copy of it would let branch-relative peeling reason about a
/// differently-shaped graph than the pass that adjudicates it.
struct StoredOpenMlsGraphInputs {
    commit_messages: Vec<StoredCommitMessage>,
    pending_messages: Vec<TransportMessage>,
    already_delivered_app_ids: BTreeSet<String>,
    own_commits: PrevalidatedOwnCommits,
    /// Commits below the retained-anchor horizon, to be reported dropped.
    stale_commit_drops: Vec<DroppedMessage>,
    current_epoch: u64,
    /// Where replay must start: the oldest unresolved commit's source epoch,
    /// or the live tip when every unresolved commit forks from it.
    replay_start_epoch: u64,
}

fn seed_stored_openmls_graph_inputs<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    retained_anchor_epoch: u64,
    admitted_message_ids: Option<&HashSet<MessageId>>,
) -> Result<StoredOpenMlsGraphInputs, OpenMlsProjectionError> {
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
        if admitted_message_ids.is_some_and(|admitted| !admitted.contains(&record.id)) {
            continue;
        }
        if !record_state_can_contribute_to_openmls_graph(record.state) {
            continue;
        }
        let payload = StoredMessagePayload::decode(&record.payload)
            .map_err(|e| OpenMlsProjectionError::Serialize(format!("{e:?}")))?;
        let own_commit_stamp = payload.own_commit_stamp().cloned();
        let own_application_stamp = payload.own_application_stamp().cloned();
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
                if source_epoch < retained_anchor_epoch {
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
                // Confirmed own commits remain prevalidated while canonical or
                // parked for convergence. Terminal states must not regain
                // checkpoint-based eligibility.
                if matches!(
                    record.state,
                    MessageState::Processed | MessageState::ConvergenceDeferred
                ) && let Some(stamp) = own_commit_stamp
                {
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
                    && source_epoch.is_some_and(|epoch| epoch >= retained_anchor_epoch) =>
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
                    && source_epoch.is_some_and(|epoch| epoch >= retained_anchor_epoch) =>
            {
                if let Some(stamp) = own_application_stamp {
                    own_commits.insert_application(message.id.clone(), stamp);
                }
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

    Ok(StoredOpenMlsGraphInputs {
        commit_messages,
        pending_messages,
        already_delivered_app_ids,
        own_commits,
        stale_commit_drops,
        current_epoch,
        replay_start_epoch,
    })
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
    let guard = SnapshotRollbackGuard::create_group_state(storage, group_id.clone(), live_snapshot)
        .map_err(|e| OpenMlsProjectionError::Snapshot(format!("{e:?}")))?;

    let anchor_snapshot = retained_anchor_snapshot_name(work.replay_start_epoch);
    let result = match storage.rollback_group_state_to_snapshot(group_id, &anchor_snapshot) {
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

/// Recover the live state captured before a rewind probe that was interrupted
/// by process termination.
///
/// Two rewinds take this shape — the convergence pass's rewind to the retained
/// anchor and the deferred-peel sweep's rewind to enumerate candidate branches.
/// Each creates its probe snapshot before the durable rollback, so a surviving
/// snapshot of either kind always holds the newer live state that must win on
/// the next open.
///
/// More than one probe snapshot is not expected: convergence for a group is
/// serialized, the two rewinds never nest, and hydrate runs before new work. If
/// storage contains several, fail closed instead of guessing which live state
/// is newest.
pub(crate) fn recover_interrupted_rewind_probe<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
) -> Result<(), OpenMlsProjectionError> {
    let probes = storage
        .list_group_snapshots(group_id)
        .map_err(|e| OpenMlsProjectionError::Storage(format!("{e:?}")))?
        .into_iter()
        .filter(|name| is_rewind_probe_snapshot(name))
        .collect::<Vec<_>>();

    let Some(snapshot) = probes.first() else {
        return Ok(());
    };
    if probes.len() != 1 {
        return Err(OpenMlsProjectionError::Snapshot(
            "multiple interrupted rewind probes".into(),
        ));
    }

    // Deliberately recover the complete pre-probe image. A surviving probe
    // snapshot may have been created by an older binary before guards became
    // state-scoped. If that binary also rewound through a legacy full retained
    // anchor, the probe snapshot is the only durable copy of the newer live
    // message ledger and outbound queue. State-only recovery would leave the
    // historical work rows stranded after upgrade.
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
    let path_result = match build_stored_openmls_candidate_paths(
        storage,
        group_id,
        work.commit_messages,
        &work.pending_messages,
        work.replay_start_epoch,
        &work.own_commits,
        work.profile_policy,
        &mut replay_budget,
    ) {
        Ok(result) => result,
        Err(OpenMlsProjectionError::MissingOwnCommitCheckpoint) => {
            // Older stamps have no exact post-merge checkpoint. Treat that as
            // missing required retained state so the convergence coordinator
            // durably halts the group instead of repeatedly selecting a branch
            // this device can never materialize.
            return Ok(missing_required_state_result(
                work.state,
                work.outbound_intents,
                work.policy,
                work.now_ms,
                CanonicalizationError::MissingOwnCommitCheckpoint,
            ));
        }
        Err(error) => return Err(error),
    };

    let has_pending_apps = pending_messages_contain_application(&work.pending_messages)?;
    let can_reuse_materialized = can_reuse_bfs_materialization(
        has_pending_apps,
        path_result.materialized.len(),
        path_result.candidate_paths.len(),
    );
    let batch = SharedSeenBatch {
        batch: OpenMlsCanonicalizationBatch {
            state: work.state,
            candidate_paths: path_result.candidate_paths,
            pending_messages: work.pending_messages,
            already_delivered_app_ids: work.already_delivered_app_ids,
            outbound_intents: work.outbound_intents,
            policy: work.policy,
            now_ms: work.now_ms,
        },
        shared_seen_message_ids: work.shared_seen_message_ids,
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
    missing_required_state_result(
        state,
        outbound_intents,
        policy,
        now_ms,
        CanonicalizationError::MissingRetainedAnchor,
    )
}

fn missing_required_state_result(
    state: CanonicalizationState,
    outbound_intents: Vec<OutboundIntent>,
    policy: CanonicalizationPolicy,
    now_ms: u64,
    error: CanonicalizationError,
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
        errors: vec![error],
        #[cfg(feature = "test-conformance-snapshot")]
        replay_probe_count: 0,
        selection_trace: None,
    }
}

/// One candidate branch tip's peel context.
///
/// Post-fork traffic is sealed under the **sender's** branch state, and the
/// transport carries no epoch hint, so a device that adopted a different branch
/// cannot peel that traffic from any state it has itself entered. Materializing
/// a candidate branch produces exactly the context that unseals it, which is
/// what lets branch depth and app witnesses be counted over evidence this
/// device has not adopted. Without it, every committer scores only its own
/// branch and a same-epoch fork is a permanent split.
///
/// The context is an owned value with the exporter secret already derived, so
/// the transient candidate state is rolled back before any peel runs against
/// it. Nothing peeled here is trusted: it re-enters through ordinary ingest and
/// is authenticated by the next pass's OpenMLS replay like any other inbound
/// message.
pub(crate) struct CandidateBranchPeelContext {
    /// Path-digest branch id, derived the same way as a selection trace's
    /// branch ids. It matches a trace's id when the pass enumerated the same
    /// path; because context collection admits every stored commit and a pass
    /// admits only its frozen batch, the two need not enumerate the same set.
    pub(crate) branch_id: String,
    pub(crate) tip_epoch: u64,
    /// Number of commit edges replayed from the retained base to capture this
    /// tip. Exposed only through aggregate metrics; never logged alongside a
    /// branch or group identifier.
    pub(crate) depth: u64,
    pub(crate) context: cgka_traits::group_context::GroupContextSnapshot,
}

/// What a deferred-peel sweep learns about this group's convergence graph.
///
/// The two fields answer different questions and are deliberately independent.
/// Contested-ness is a property of the STORED COMMIT GRAPH, decided before any
/// replay; the contexts are what enumeration managed to MATERIALIZE from it.
/// Enumeration halts for reasons that say nothing about whether the graph is
/// split — a released anchor, a missing own-commit checkpoint, an exhausted
/// replay budget — so a halt loses the contexts and never the split.
pub(crate) struct CandidateBranchPeel {
    /// Two stored commits fork from the same source epoch.
    pub(crate) contested: bool,
    /// Tip contexts enumeration captured, at most `max_contexts` of them.
    /// Empty on every halt, and empty for an uncontested graph.
    pub(crate) contexts: Vec<CandidateBranchPeelContext>,
    /// OpenMLS replay probes consumed while enumerating and capturing the
    /// candidate contexts. Aggregate work accounting only.
    pub(crate) replay_probe_count: u64,
}

impl CandidateBranchPeel {
    /// No two stored commits fork from the same source epoch, so there is no
    /// rival branch to materialize.
    const UNCONTESTED: Self = Self {
        contested: false,
        contexts: Vec::new(),
        replay_probe_count: 0,
    };

    /// Whatever enumeration captured from a graph already known to be split.
    fn contested_over(enumeration: CandidateBranchPeelEnumeration) -> Self {
        Self {
            contested: true,
            contexts: enumeration.contexts,
            replay_probe_count: enumeration.replay_probe_count,
        }
    }
}

struct CandidateBranchPeelEnumeration {
    contexts: Vec<CandidateBranchPeelContext>,
    replay_probe_count: u64,
}

#[derive(Debug)]
pub(crate) struct CandidateBranchPeelFailure {
    pub(crate) error: OpenMlsProjectionError,
    pub(crate) replay_probe_count: u64,
}

impl CandidateBranchPeelFailure {
    fn new(error: OpenMlsProjectionError, replay_probe_count: u64) -> Self {
        Self {
            error,
            replay_probe_count,
        }
    }
}

/// Survey the branches a convergence graph offers: whether it is contested, and
/// the peel context of each candidate branch tip that could be materialized.
///
/// Best-effort by contract for the CONTEXTS: the pass — not this helper — owns
/// every verdict, so an inability to enumerate branches (no retained anchor, no
/// own-commit checkpoint, exhausted replay budget) yields no contexts rather
/// than an error. Storage and snapshot faults still propagate; they mean the
/// caller's own state is in doubt.
///
/// Contested-ness is NOT best-effort. It is decided by the shared-source-epoch
/// check below, ahead of every path that can lose contexts.
pub(crate) fn candidate_branch_peel<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    retained_anchor_epoch: u64,
    max_rewind_commits: u64,
    profile_policy: ReplayProfilePolicy,
    max_contexts: usize,
) -> Result<CandidateBranchPeel, CandidateBranchPeelFailure> {
    use crate::snapshot_guard::SnapshotRollbackGuard;

    let inputs = seed_stored_openmls_graph_inputs(storage, group_id, retained_anchor_epoch, None)
        .map_err(|error| CandidateBranchPeelFailure::new(error, 0))?;
    // Cheap contested-graph gate ahead of any replay: competing branches exist
    // only where two commits share a source epoch. An uncontested graph pays
    // the seeding scan and nothing more. This is also the ONLY answer to
    // "contested?"; everything past it can only lose contexts.
    if !commits_share_a_source_epoch(&inputs.commit_messages) {
        return Ok(CandidateBranchPeel::UNCONTESTED);
    }
    if inputs.replay_start_epoch >= inputs.current_epoch {
        return candidate_branch_peel_contexts_from_current(
            storage,
            group_id,
            inputs,
            max_rewind_commits,
            profile_policy,
            max_contexts,
        )
        .map(CandidateBranchPeel::contested_over);
    }

    // Same rewind shape as the pass: probe-snapshot the live state, roll back
    // to the retained anchor, enumerate, then restore. The guard restores on
    // every path, and an interrupted probe is recovered by
    // `recover_interrupted_rewind_probe` exactly as the pass's is — under this
    // sweep's own probe name, so two interrupted probes stay distinguishable.
    let probe_snapshot = candidate_branch_probe_snapshot_name(group_id, inputs.replay_start_epoch);
    let guard =
        SnapshotRollbackGuard::create_group_state(storage, group_id.clone(), probe_snapshot)
            .map_err(|error| {
                CandidateBranchPeelFailure::new(
                    OpenMlsProjectionError::Snapshot(format!("{error:?}")),
                    0,
                )
            })?;
    let anchor_snapshot = retained_anchor_snapshot_name(inputs.replay_start_epoch);
    let contexts = match storage.rollback_group_state_to_snapshot(group_id, &anchor_snapshot) {
        Ok(()) => {
            crate::test_crash_hooks::pause_if_requested("candidate-branch-after-rewind");
            candidate_branch_peel_contexts_from_current(
                storage,
                group_id,
                inputs,
                max_rewind_commits,
                profile_policy,
                max_contexts,
            )
        }
        Err(StorageError::SnapshotMissing(_)) => Ok(CandidateBranchPeelEnumeration {
            contexts: Vec::new(),
            replay_probe_count: 0,
        }),
        Err(error) => Err(CandidateBranchPeelFailure::new(
            OpenMlsProjectionError::Snapshot(format!("{error:?}")),
            0,
        )),
    };
    let replay_probe_count = contexts.as_ref().map_or_else(
        |failure| failure.replay_probe_count,
        |enumeration| enumeration.replay_probe_count,
    );
    guard.commit().map_err(|error| {
        CandidateBranchPeelFailure::new(
            OpenMlsProjectionError::Snapshot(format!("{error:?}")),
            replay_probe_count,
        )
    })?;
    contexts.map(CandidateBranchPeel::contested_over)
}

/// Whether this group's stored commit graph is contested: two retained commits
/// at or above the retained anchor fork from the same source epoch.
///
/// The replay-free half of [`candidate_branch_peel`], and deliberately the
/// same predicate over the same seeded inputs — a second, privately restated
/// notion of "forked" would drift from the one branch enumeration acts on
/// without any test noticing. Costs the seeding scan and nothing more: no
/// snapshot, no rewind, no OpenMLS replay.
pub(crate) fn stored_graph_is_contested<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    retained_anchor_epoch: u64,
) -> Result<bool, OpenMlsProjectionError> {
    let inputs = seed_stored_openmls_graph_inputs(storage, group_id, retained_anchor_epoch, None)?;
    Ok(commits_share_a_source_epoch(&inputs.commit_messages))
}

/// Whether two distinct stored commits fork from the same source epoch — the
/// structural precondition for more than one candidate branch.
fn commits_share_a_source_epoch(commits: &[StoredCommitMessage]) -> bool {
    let mut by_epoch: BTreeMap<u64, BTreeSet<[u8; 32]>> = BTreeMap::new();
    for commit in commits {
        if by_epoch
            .entry(commit.source_epoch)
            .or_default()
            .insert(commit.digest)
            && by_epoch[&commit.source_epoch].len() > 1
        {
            return true;
        }
    }
    false
}

/// Enumerate and capture branch tips from the state currently restored.
///
/// Only ever called once the graph is known contested, so every early return
/// here means "captured nothing", never "nothing to capture" — the caller
/// stamps `contested` on whatever comes back.
fn candidate_branch_peel_contexts_from_current<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    inputs: StoredOpenMlsGraphInputs,
    max_rewind_commits: u64,
    profile_policy: ReplayProfilePolicy,
    max_contexts: usize,
) -> Result<CandidateBranchPeelEnumeration, CandidateBranchPeelFailure> {
    let mut budget = ReplayBudget::for_pass(inputs.commit_messages.len(), max_rewind_commits);
    let path_result = match build_stored_openmls_candidate_paths(
        storage,
        group_id,
        inputs.commit_messages,
        &inputs.pending_messages,
        inputs.replay_start_epoch,
        &inputs.own_commits,
        profile_policy,
        &mut budget,
    ) {
        Ok(result) => result,
        // The pass, not this helper, owns every verdict, so an inability to
        // enumerate branches yields no contexts. The graph stays contested
        // either way — the caller reads that from the source-epoch check, not
        // from this set — but a halt is still worth a greppable line, because
        // it is the fork this device has stopped being able to see.
        Err(
            err @ (OpenMlsProjectionError::MissingOwnCommitCheckpoint
            | OpenMlsProjectionError::ReplayBudgetExceeded),
        ) => {
            tracing::debug!(
                target: "cgka_engine::openmls_projection",
                method = "candidate_branch_peel",
                reason = candidate_branch_enumeration_halt_reason(&err),
                "no candidate branch peel contexts: branch enumeration halted"
            );
            return Ok(CandidateBranchPeelEnumeration {
                contexts: Vec::new(),
                replay_probe_count: budget.consumed,
            });
        }
        Err(error) => {
            return Err(CandidateBranchPeelFailure::new(error, budget.consumed));
        }
    };
    if path_result.candidate_paths.len() < 2 {
        return Ok(CandidateBranchPeelEnumeration {
            contexts: Vec::new(),
            replay_probe_count: budget.consumed,
        });
    }

    let pending_proposals = pending_proposal_messages(&inputs.pending_messages)
        .map_err(|error| CandidateBranchPeelFailure::new(error, budget.consumed))?;
    let ranked =
        candidate_paths_ranked_for_peel(&path_result.candidate_paths, &path_result.materialized);
    let mut contexts = Vec::with_capacity(max_contexts.min(ranked.len()));
    // Each tip context costs one replay of its path. The BFS already replayed
    // every node to enumerate the paths; capturing the contexts inside that
    // walk would have to carry exporter material through
    // `OpenMlsMaterializedCandidate` and into every canonicalization result, so
    // this pays a bounded second replay to keep secrets out of those types.
    for path in ranked.into_iter().take(max_contexts) {
        match candidate_path_peel_context(
            storage,
            group_id,
            path,
            &pending_proposals,
            &inputs.own_commits,
            profile_policy,
            &mut budget,
        ) {
            Ok(Some(context)) => contexts.push(context),
            Ok(None) => {}
            Err(err @ OpenMlsProjectionError::ReplayBudgetExceeded) => {
                tracing::debug!(
                    target: "cgka_engine::openmls_projection",
                    method = "candidate_branch_peel",
                    reason = candidate_branch_enumeration_halt_reason(&err),
                    captured = contexts.len() as u64,
                    "candidate branch peel contexts truncated"
                );
                break;
            }
            Err(error) => {
                return Err(CandidateBranchPeelFailure::new(error, budget.consumed));
            }
        }
    }
    Ok(CandidateBranchPeelEnumeration {
        contexts,
        replay_probe_count: budget.consumed,
    })
}

/// Order candidate paths by how much a peel context on each is worth, so the
/// context cap keeps the branches most likely to unseal retained traffic.
///
/// The BFS completes paths in level order, so the raw vector runs shallowest
/// first and a prefix would keep exactly the wrong branches: a handful of
/// one-commit rivals — the cheapest fork there is to post — would evict every
/// branch that actually carries post-fork traffic. Deeper tips rank first.
///
/// Both keys are content-derived: `tip_epoch` comes from replaying the stored
/// commits, `branch_id` from their digests. Peers holding the same evidence
/// therefore keep the same branches, which is what makes capping safe at all.
fn candidate_paths_ranked_for_peel<'a>(
    candidate_paths: &'a [OpenMlsCandidatePath],
    materialized: &[OpenMlsMaterializedCandidate],
) -> Vec<&'a OpenMlsCandidatePath> {
    // Joined on `branch_id` rather than position: `materialized` is parallel to
    // `candidate_paths` by construction but is allowed to come back short, and
    // a silent index skew would rank branches by another branch's depth.
    let tip_epochs: BTreeMap<&str, u64> = materialized
        .iter()
        .map(|candidate| (candidate.branch_id.as_str(), candidate.tip_epoch))
        .collect();
    let mut ranked: Vec<&OpenMlsCandidatePath> = candidate_paths.iter().collect();
    ranked.sort_by(|a, b| {
        tip_epochs
            .get(b.branch_id.as_str())
            .cmp(&tip_epochs.get(a.branch_id.as_str()))
            .then_with(|| a.branch_id.cmp(&b.branch_id))
    });
    ranked
}

/// Stable low-cardinality label for a halt that yields no (or fewer) candidate
/// branch peel contexts. Aggregate diagnostics only — never group or message
/// identifiers (observability.md).
fn candidate_branch_enumeration_halt_reason(err: &OpenMlsProjectionError) -> &'static str {
    match err {
        OpenMlsProjectionError::MissingOwnCommitCheckpoint => "missing_own_commit_checkpoint",
        OpenMlsProjectionError::ReplayBudgetExceeded => "replay_budget_exceeded",
        _ => "other",
    }
}

// Same shared-context argument set as `build_stored_openmls_candidate_paths`.
#[allow(clippy::too_many_arguments)]
fn candidate_path_peel_context<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    path: &OpenMlsCandidatePath,
    pending_proposals: &[TransportMessage],
    own_commits: &PrevalidatedOwnCommits,
    profile_policy: ReplayProfilePolicy,
    budget: &mut ReplayBudget,
) -> Result<Option<CandidateBranchPeelContext>, OpenMlsProjectionError> {
    use crate::snapshot_guard::SnapshotRollbackGuard;

    let replay_paths = candidate_paths_with_pending_replay_messages(
        std::slice::from_ref(path),
        pending_proposals,
    )?;
    let Some(replay_path) = replay_paths.first() else {
        return Ok(None);
    };
    budget.consume()?;

    let snapshot = replay_snapshot_name(group_id, &replay_path.messages);
    let guard = SnapshotRollbackGuard::create_group_state(storage, group_id.clone(), snapshot)
        .map_err(|e| OpenMlsProjectionError::Snapshot(format!("{e:?}")))?;
    let captured = capture_candidate_tip_context(
        storage,
        group_id,
        &replay_path.messages,
        own_commits,
        profile_policy,
    );
    guard
        .commit()
        .map_err(|e| OpenMlsProjectionError::Snapshot(format!("{e:?}")))?;

    Ok(captured?.map(|tip| CandidateBranchPeelContext {
        branch_id: path.branch_id.clone(),
        tip_epoch: tip.epoch,
        depth: path.messages.len().try_into().unwrap_or(u64::MAX),
        context: tip.context,
    }))
}

/// State read off a materialized candidate branch's tip.
struct CandidateTipState {
    context: cgka_traits::group_context::GroupContextSnapshot,
    epoch: u64,
}

/// Replay `messages` onto the restored base state and read the resulting tip's
/// exporter context. Runs inside a [`SnapshotRollbackGuard`]; the caller
/// restores the live state before the returned context is used.
fn capture_candidate_tip_context<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    messages: &[TransportMessage],
    own_commits: &PrevalidatedOwnCommits,
    profile_policy: ReplayProfilePolicy,
) -> Result<Option<CandidateTipState>, OpenMlsProjectionError> {
    // A path that fails to replay is simply not a reachable branch state; the
    // BFS already reported that outcome for adjudication.
    if process_openmls_messages_inner(storage, group_id, messages, own_commits, profile_policy)
        .is_err()
    {
        return Ok(None);
    }
    let crypto = RustCrypto::default();
    let provider = EngineOpenMlsProvider::<S>::new(&crypto, storage.mls_storage());
    let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
    let Some(mls_group) = MlsGroup::load(
        <EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(&provider),
        &mls_gid,
    )
    .map_err(|e| OpenMlsProjectionError::Storage(format!("{e:?}")))?
    else {
        return Ok(None);
    };
    let context = crate::group_lifecycle::build_group_context_snapshot(&mls_group, &provider)
        .map_err(|e| OpenMlsProjectionError::Storage(format!("{e:?}")))?;
    Ok(Some(CandidateTipState {
        context,
        epoch: mls_group.epoch().as_u64(),
    }))
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
    // per-commit checkpoint rollforward, so realize such a leading run in one
    // step: skip it from the replay and restore the commit-addressed checkpoint
    // for the run's final own commit — the exact post-merge state it produced.
    let own_checkpoint_prefix =
        checkpoint_realizable_own_commit_prefix(storage, result, &applied_prefix)?;
    let mut skipped_prefix = applied_prefix;
    skipped_prefix.extend(own_checkpoint_prefix.commit_ids.iter().cloned());
    let apply_start_epoch = match own_checkpoint_prefix.realized.as_ref() {
        Some(realized) => realized.resulting_epoch,
        None => apply_start_epoch_for_canonicalization_result(storage, result, &skipped_prefix)?
            .unwrap_or(current_epoch),
    };
    // The own-checkpoint case must restore even when its epoch equals the live
    // tip: the live tip may be a different branch's state at that epoch.
    let rewind_to_retained_anchor = apply_start_epoch < current_epoch;
    let restore_own_checkpoint = own_checkpoint_prefix.realized.is_some();
    let replay_messages = replay_messages_for_canonicalization_result(
        storage,
        result,
        &skipped_prefix,
        apply_start_epoch,
    )?;
    let (live_message_records, live_queued_outbound) =
        if rewind_to_retained_anchor && !restore_own_checkpoint {
            (
                storage
                    .list_messages(group_id, EpochId(0))
                    .map_err(|e| OpenMlsProjectionError::Storage(format!("{e:?}")))?,
                storage
                    .list_queued_outbound_intents(group_id)
                    .map_err(|e| OpenMlsProjectionError::Storage(format!("{e:?}")))?,
            )
        } else {
            (Vec::new(), Vec::new())
        };
    let snapshot = apply_snapshot_name(group_id, result);
    // Deliberately full. Unlike temporary replay/probe guards, canonical apply
    // changes message dispositions and outbound work; error recovery needs the
    // complete pre-apply image, not only canonical group/OpenMLS state.
    storage
        .create_group_snapshot(group_id, &snapshot)
        .map_err(|e| OpenMlsProjectionError::Snapshot(format!("{e:?}")))?;

    // Refresh the current-epoch anchor only in the case that always did:
    // there are new commits AND the apply starts at the live tip. The extra
    // `own_checkpoint_prefix.realized.is_none()` term avoids an
    // unnecessary epoch-anchor refresh before restoring exact checkpoint
    // state. `apply_start_epoch > current_epoch` stays skipped as before.
    let prepare_result = if has_new_commits
        && apply_start_epoch == current_epoch
        && own_checkpoint_prefix.realized.is_none()
    {
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
        if let Some(realized) = own_checkpoint_prefix.realized.as_ref() {
            storage
                .restore_group_state_checkpoint(group_id, &realized.id)
                .map_err(|e| OpenMlsProjectionError::Snapshot(format!("{e:?}")))?;
            verify_restored_own_checkpoint(
                storage,
                group_id,
                realized.resulting_epoch,
                &realized.expected_epoch_authenticator,
            )?;
        } else if rewind_to_retained_anchor {
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
        if apply_start_epoch < current_epoch || restore_own_checkpoint {
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
    for disposition in openmls_canonicalization_dispositions(result)? {
        storage
            .update_message_state(&disposition.message_id, disposition.state)
            .map_err(|e| OpenMlsProjectionError::Storage(format!("{e:?}")))?;
    }

    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OpenMlsCanonicalizationDisposition {
    pub message_id: MessageId,
    pub state: MessageState,
    pub reason: &'static str,
}

pub(crate) fn openmls_canonicalization_dispositions(
    result: &CanonicalizationResult,
) -> Result<Vec<OpenMlsCanonicalizationDisposition>, OpenMlsProjectionError> {
    let mut state_by_message_id = BTreeMap::new();

    for dropped in &result.dropped_messages {
        state_by_message_id.insert(
            dropped.message_id.clone(),
            (
                message_state_for_dropped_reason(dropped.reason),
                match dropped.reason {
                    DroppedMessageReason::Malformed => "canonicalization_dropped_malformed",
                    DroppedMessageReason::UnsupportedPolicy => {
                        "canonicalization_dropped_unsupported_policy"
                    }
                    DroppedMessageReason::BeyondRollbackHorizon => {
                        "canonicalization_dropped_beyond_rollback_horizon"
                    }
                    DroppedMessageReason::BeyondAnchor => "canonicalization_dropped_beyond_anchor",
                    DroppedMessageReason::BeyondAppRetention => {
                        "canonicalization_dropped_beyond_app_retention"
                    }
                    DroppedMessageReason::InvalidAgainstCandidateState => {
                        "canonicalization_dropped_invalid_candidate_state"
                    }
                },
            ),
        );
    }
    // The epoch convergence settled on: the selected branch tip, or the
    // unchanged previous tip when no branch was selected this pass.
    let resulting_tip = result.selected_tip.unwrap_or(result.previous_tip);
    for invalidated in &result.invalidated_app_messages {
        state_by_message_id.insert(
            invalidated.message_id.clone(),
            (
                message_state_for_invalidated_reason(
                    invalidated.reason,
                    invalidated.epoch,
                    resulting_tip,
                ),
                match invalidated.reason {
                    InvalidatedAppMessageReason::LosingBranch => {
                        "canonicalization_invalidated_losing_branch"
                    }
                    InvalidatedAppMessageReason::UndecryptableInCanonicalState => {
                        "canonicalization_invalidated_undecryptable"
                    }
                    InvalidatedAppMessageReason::BeyondAnchor => {
                        "canonicalization_invalidated_beyond_anchor"
                    }
                    InvalidatedAppMessageReason::BeyondAppRetention => {
                        "canonicalization_invalidated_beyond_app_retention"
                    }
                },
            ),
        );
    }
    for deferred in &result.deferred_messages {
        state_by_message_id.insert(
            deferred.message_id.clone(),
            (
                MessageState::ConvergenceDeferred,
                "canonicalization_deferred",
            ),
        );
    }
    for accepted in result
        .accepted_commits
        .iter()
        .chain(&result.accepted_proposals)
        .chain(&result.accepted_app_messages)
    {
        state_by_message_id.insert(
            accepted.clone(),
            (MessageState::Processed, "canonicalization_accepted"),
        );
    }

    state_by_message_id
        .into_iter()
        .map(|(hex_message_id, (state, reason))| {
            Ok(OpenMlsCanonicalizationDisposition {
                message_id: message_id_from_hex(&hex_message_id)?,
                state,
                reason,
            })
        })
        .collect()
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
struct CheckpointRealizableOwnPrefix {
    /// Selected-branch commit ids (hex) realized via an exact checkpoint
    /// instead of replay.
    commit_ids: BTreeSet<String>,
    realized: Option<RealizedCheckpoint>,
}

struct RealizedCheckpoint {
    resulting_epoch: u64,
    id: String,
    expected_epoch_authenticator: String,
}

/// The leading run — after the already-applied prefix — of this device's own
/// confirm-stamped commits on the selected branch, bounded to those whose
/// commit-addressed checkpoint still exists. Such commits reach the apply
/// stage outside the applied prefix when a pairwise CandidateWins resolution
/// parked a displaced own incumbent `ConvergenceDeferred` (see
/// `fork_recovery`) and convergence later selected its regrown branch. MLS
/// refuses to re-process own commits, so the apply realizes the run by
/// restoring the final commit's immutable checkpoint — the exact canonical
/// state captured when it confirmed. The first commit without a retained
/// checkpoint ends the run; anything after it replays normally from that
/// state. The restored epoch and epoch authenticator are verified inside the
/// apply transaction.
fn checkpoint_realizable_own_commit_prefix<S: StorageProvider>(
    storage: &S,
    result: &CanonicalizationResult,
    applied_prefix: &BTreeSet<String>,
) -> Result<CheckpointRealizableOwnPrefix, OpenMlsProjectionError> {
    let mut prefix = CheckpointRealizableOwnPrefix::default();
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
        let Some(stamp) = payload.own_commit_stamp() else {
            break;
        };
        let (Some(checkpoint_id), Some(expected_authenticator)) = (
            stamp.checkpoint_id.clone(),
            stamp.resulting_epoch_authenticator.clone(),
        ) else {
            break;
        };
        let resulting_epoch = record.epoch.0.saturating_add(1);
        prefix.commit_ids.insert(commit_id.clone());
        prefix.realized = Some(RealizedCheckpoint {
            resulting_epoch,
            id: checkpoint_id,
            expected_epoch_authenticator: expected_authenticator,
        });
    }
    Ok(prefix)
}

/// Verify the exact own-commit checkpoint after restoring it. This runs inside
/// the apply transaction so any mismatch rolls back to the pre-apply state.
fn verify_restored_own_checkpoint<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    resulting_epoch: u64,
    expected_authenticator: &str,
) -> Result<(), OpenMlsProjectionError> {
    let crypto = RustCrypto::default();
    let provider = EngineOpenMlsProvider::<S>::new(&crypto, storage.mls_storage());
    let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
    let mls_group = MlsGroup::load(provider.storage(), &mls_gid)
        .map_err(|e| {
            OpenMlsProjectionError::Snapshot(format!("load restored checkpoint group: {e:?}"))
        })?
        .ok_or(OpenMlsProjectionError::MissingGroup)?;
    let actual = own_commit_post_merge_epoch_authenticator(&mls_group);
    if mls_group.epoch().as_u64() == resulting_epoch && actual == expected_authenticator {
        return Ok(());
    }
    Err(OpenMlsProjectionError::CheckpointStateMismatch)
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
    // State-scoped: this runs on every canonical advance, and the anchor is
    // only ever consumed as an OpenMLS/group-state rewind base. The message
    // ledger is deliberately not captured — the convergence probe works from
    // pre-seeded inputs (`seed_stored_openmls_graph_inputs` runs before the
    // rewind), and the historical apply restores the live message/queue sets
    // over the rollback anyway (`restore_live_message_and_queue_records`).
    // Capturing them would make every applied commit O(retained bytes).
    storage
        .create_group_state_snapshot(group_id, &retained_anchor_snapshot_name(epoch))
        .map_err(|e| OpenMlsProjectionError::Snapshot(format!("{e:?}")))?;
    prune_retained_anchor_snapshots(storage, group_id, epoch, max_retained_anchor_rewind)?;
    prune_group_state_checkpoints(storage, group_id, epoch, max_retained_anchor_rewind)
}

fn prune_group_state_checkpoints<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    retained_epoch: u64,
    max_retained_anchor_rewind: u64,
) -> Result<(), OpenMlsProjectionError> {
    let oldest_retained_epoch = oldest_retained_epoch(retained_epoch, max_retained_anchor_rewind);
    for checkpoint in storage
        .list_group_state_checkpoints(group_id)
        .map_err(|e| OpenMlsProjectionError::Storage(format!("{e:?}")))?
    {
        if checkpoint.resulting_epoch.0 >= oldest_retained_epoch {
            continue;
        }
        match storage.release_group_state_checkpoint(group_id, &checkpoint.id) {
            Ok(()) | Err(StorageError::SnapshotMissing(_)) => {}
            Err(e) => return Err(OpenMlsProjectionError::Snapshot(format!("{e:?}"))),
        }
    }
    Ok(())
}

fn prune_retained_anchor_snapshots<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    retained_epoch: u64,
    max_retained_anchor_rewind: u64,
) -> Result<(), OpenMlsProjectionError> {
    let oldest_retained_epoch = oldest_retained_epoch(retained_epoch, max_retained_anchor_rewind);
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

fn oldest_retained_epoch(retained_epoch: u64, max_retained_anchor_rewind: u64) -> u64 {
    retained_epoch.saturating_sub(max_retained_anchor_rewind)
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
        // No pre-validated own messages here. Snapshot rollforward cannot nest
        // inside this transaction, and every own commit on the accepted
        // branch was excluded from `replay_messages` before this call —
        // either as part of the already-applied prefix or as a
        // checkpoint-realizable own-commit run whose exact restore the
        // caller performs itself (`checkpoint_realizable_own_commit_prefix`).
        // Leaving own-application stamps out is also load-bearing: those apps
        // reach OpenMLS as `OwnPrivateMessage` and remain `Ignored`, so apply
        // replay never echoes a sender's own message as `MessageReceived`.
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
    for (input_order, hex_message_id) in result
        .accepted_proposals
        .iter()
        .chain(
            result
                .accepted_commits
                .iter()
                .filter(|commit_id| !applied_prefix.contains(*commit_id)),
        )
        .chain(&result.accepted_app_messages)
        .enumerate()
    {
        if !seen.insert(hex_message_id.clone()) {
            continue;
        }
        let message_id = message_id_from_hex(hex_message_id)?;
        let record = storage
            .get_message(&message_id)
            .map_err(|e| OpenMlsProjectionError::Storage(format!("{e:?}")))?;
        let Some(message) = openmls_wire_message_from_record(&record)? else {
            return Err(OpenMlsProjectionError::Decode(format!(
                "accepted message {} is not a stored OpenMLS wire payload",
                hex_message_id
            )));
        };
        let projection = project_mls_message(&message.payload)?;
        let source_epoch =
            projection
                .source_epoch
                .ok_or(OpenMlsProjectionError::UnsupportedMessageKind(
                    projection.kind,
                ))?;
        // An accepted proposal below the apply-start epoch was consumed by a
        // commit in the skipped already-applied prefix: its effect is inside
        // the live state, and MLS proposals are epoch-scoped, so replaying it
        // against the post-prefix state would be rejected (WrongEpoch) and
        // fail the whole apply. Use the authenticated wire epoch rather than
        // mutable row metadata. Skip the replay; its `Processed` disposition
        // still persists so it leaves the convergence input set.
        if result.accepted_proposals.contains(hex_message_id) && source_epoch < apply_start_epoch {
            continue;
        }
        let kind_order = match projection.kind {
            // Proposals and applications from epoch E must be processed while
            // the group is still at E. The commit advancing E -> E+1 comes
            // last so OpenMLS cannot prune source-epoch application material
            // before the accepted application is authenticated (mdk#1171).
            OpenMlsContentKind::Proposal => 0,
            OpenMlsContentKind::Application => 1,
            OpenMlsContentKind::Commit => 2,
            OpenMlsContentKind::Welcome | OpenMlsContentKind::Other => 3,
        };
        replay_messages.push((source_epoch, kind_order, input_order, message));
    }
    replay_messages.sort_by_key(|message| (message.0, message.1, message.2));
    Ok(replay_messages
        .into_iter()
        .map(|(_, _, _, message)| message)
        .collect())
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

/// Whether a stored row in this state is an input to the OpenMLS graph the
/// convergence pass builds — the unresolved canonicalization inputs plus
/// already-applied (`Processed`) rows, which are re-admitted for scoring.
///
/// The single owner of that classification. `seed_stored_openmls_graph_inputs`
/// exists so no caller re-derives it; anything that must agree with the graph's
/// membership (the deferred-peel sweep's context fingerprint, for one) calls
/// this rather than restating the match. A restatement drifts silently: the
/// graph and its describer disagree, and nothing fails.
pub(crate) fn record_state_can_contribute_to_openmls_graph(state: MessageState) -> bool {
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
    let mut applications_by_epoch: BTreeMap<u64, Vec<TransportMessage>> = BTreeMap::new();
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
            OpenMlsContentKind::Application => {
                let source_epoch = projection.source_epoch.ok_or(
                    OpenMlsProjectionError::UnsupportedMessageKind(projection.kind),
                )?;
                applications_by_epoch
                    .entry(source_epoch)
                    .or_default()
                    .push(message.clone());
            }
            OpenMlsContentKind::Commit
            | OpenMlsContentKind::Welcome
            | OpenMlsContentKind::Other => {}
        }
    }
    for proposals in proposals_by_epoch.values_mut() {
        proposals.sort_by(|a, b| a.id.as_slice().cmp(b.id.as_slice()));
    }
    for applications in applications_by_epoch.values_mut() {
        applications.sort_by(|a, b| a.id.as_slice().cmp(b.id.as_slice()));
    }

    candidate_paths
        .iter()
        .map(
            |path| -> Result<OpenMlsCandidatePath, OpenMlsProjectionError> {
                let mut seen = BTreeSet::new();
                let mut messages = Vec::new();
                let mut final_epoch = None;
                let projected_messages = path
                    .messages
                    .iter()
                    .map(|message| Ok((message, project_mls_message(&message.payload)?)))
                    .collect::<Result<Vec<_>, OpenMlsProjectionError>>()?;
                let first_commit_epoch = projected_messages
                    .iter()
                    .find(|(_, projection)| projection.kind == OpenMlsContentKind::Commit)
                    .map(|(_, projection)| {
                        projection.source_epoch.ok_or(
                            OpenMlsProjectionError::UnsupportedMessageKind(projection.kind),
                        )
                    })
                    .transpose()?;
                // A late application from common pre-fork history can be
                // older than every commit in the candidate path. Probe it
                // against the retained base state, before the first commit;
                // that state owns the widest past-epoch decryption window.
                // The observation is shared by every candidate and therefore
                // cannot bias selection toward either fork.
                if let Some(first_commit_epoch) = first_commit_epoch {
                    for applications in applications_by_epoch
                        .range(..first_commit_epoch)
                        .map(|(_, applications)| applications)
                    {
                        for application in applications {
                            if seen.insert(hex::encode(application.id.as_slice())) {
                                messages.push(application.clone());
                            }
                        }
                    }
                }
                for (message, projection) in projected_messages {
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
                        // Authenticate applications while the candidate still
                        // owns their source-epoch state. Their branch-specific
                        // observations are retained for witness scoring and the
                        // eventual post-selection disposition; delivery itself
                        // still happens only during canonical apply.
                        if let Some(applications) = applications_by_epoch.get(&source_epoch) {
                            for application in applications {
                                if seen.insert(hex::encode(application.id.as_slice())) {
                                    messages.push(application.clone());
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
                if let Some(final_epoch) = final_epoch
                    && let Some(applications) = applications_by_epoch.get(&final_epoch)
                {
                    for application in applications {
                        if seen.insert(hex::encode(application.id.as_slice())) {
                            messages.push(application.clone());
                        }
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
    decrypted_payload_ref: Option<String>,
}

fn app_messages_by_id(
    candidates: &[OpenMlsMaterializedCandidate],
) -> BTreeMap<String, AppMessageBranches> {
    let mut app_messages = BTreeMap::new();
    for candidate in candidates {
        for observation in &candidate.observations {
            let (message_id, source_epoch, sender, decrypted_payload_ref) = match observation {
                OpenMlsReplayObservation::ApplicationProcessed {
                    message_id,
                    source_epoch,
                    sender,
                    decrypted_payload_ref,
                    ..
                } => (
                    message_id,
                    source_epoch,
                    sender,
                    Some(decrypted_payload_ref),
                ),
                OpenMlsReplayObservation::OwnApplicationSent {
                    message_id,
                    source_epoch,
                    sender,
                    source_epoch_authenticator,
                } => {
                    let matches_candidate = candidate
                        .epoch_authenticators
                        .get(source_epoch)
                        .map(|candidate_authenticator| {
                            candidate_authenticator == source_epoch_authenticator
                        })
                        // A source epoch older than the replay anchor is part
                        // of every candidate's common pre-fork history.
                        .unwrap_or(*source_epoch <= candidate.fork_epoch);
                    if !matches_candidate {
                        continue;
                    }
                    (message_id, source_epoch, sender, None)
                }
                _ => continue,
            };
            let entry =
                app_messages
                    .entry(message_id.clone())
                    .or_insert_with(|| AppMessageBranches {
                        source_epoch: *source_epoch,
                        sender: sender.clone(),
                        branch_ids: BTreeSet::new(),
                        decrypted_payload_ref: decrypted_payload_ref.cloned(),
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
                        .and_then(|observed| observed.decrypted_payload_ref.clone()),
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
    let mut epoch_authenticators = BTreeMap::from([(
        mls_group.epoch().as_u64(),
        own_commit_post_merge_epoch_authenticator(&mls_group),
    )]);
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
        if projection.kind == OpenMlsContentKind::Application
            && let Some(stamp) = own_commits.application_stamp(&message.id)
        {
            // A locally authored private message cannot be authenticated by
            // replaying its ciphertext: MLS sender ratchets are encryption-
            // only. Carry the durable send-time evidence forward and let the
            // candidate epoch-authenticator comparison below decide whether
            // this branch may claim it. Do not consult OpenMLS's unauthenticated
            // OwnPrivateMessage classification.
            observations.push(OpenMlsReplayObservation::OwnApplicationSent {
                message_id,
                source_epoch,
                sender: stamp.sender.as_slice().to_vec(),
                source_epoch_authenticator: stamp.source_epoch_authenticator.clone(),
            });
            continue;
        }
        if projection.kind == OpenMlsContentKind::Commit
            && prefix_canonical
            && let Some(stamp) = own_commits.stamp(&projection.message_digest)
        {
            // MLS cannot process this device's path-bearing own commit from
            // the public wire echo after its pending state is gone. Restore
            // the immutable post-merge checkpoint captured for this exact
            // commit instead.
            let group_epoch = mls_group.epoch().as_u64();
            if group_epoch != source_epoch {
                return Err(OpenMlsProjectionError::Replay(format!(
                    "own commit source epoch {source_epoch} does not match replay state {group_epoch}"
                )));
            }
            let resulting_epoch = source_epoch.saturating_add(1);
            let (Some(checkpoint_id), Some(expected_authenticator)) = (
                stamp.checkpoint_id.as_deref(),
                stamp.resulting_epoch_authenticator.as_deref(),
            ) else {
                return Err(OpenMlsProjectionError::MissingOwnCommitCheckpoint);
            };
            match storage.restore_group_state_checkpoint(group_id, checkpoint_id) {
                Ok(()) => {}
                Err(StorageError::SnapshotMissing(_)) => {
                    return Err(OpenMlsProjectionError::MissingOwnCommitCheckpoint);
                }
                Err(error) => {
                    return Err(OpenMlsProjectionError::Snapshot(format!("{error:?}")));
                }
            }
            mls_group = MlsGroup::load(provider.storage(), &mls_group_id)
                .map_err(|e| OpenMlsProjectionError::Replay(format!("checkpoint reload: {e:?}")))?
                .ok_or(OpenMlsProjectionError::MissingGroup)?;
            verify_restored_own_checkpoint(
                storage,
                group_id,
                resulting_epoch,
                expected_authenticator,
            )?;
            epoch_authenticators.insert(
                mls_group.epoch().as_u64(),
                own_commit_post_merge_epoch_authenticator(&mls_group),
            );
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
                epoch_authenticators.insert(
                    mls_group.epoch().as_u64(),
                    own_commit_post_merge_epoch_authenticator(&mls_group),
                );
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
                        decrypted_payload_ref: crate::app_payload::decrypted_payload_ref(
                            payload.as_slice(),
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
                // Never merge an OwnPendingCommit here: MDK realizes confirmed
                // own commits from retained anchor snapshots above, preserving
                // the publish-before-apply lifecycle. A stamped own private
                // message was handled before OpenMLS processing above; an
                // unstamped OwnPrivateMessage is not trusted as provenance.
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
        epoch_authenticators,
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
    rewind_probe_snapshot_name(RETAINED_ANCHOR_PROBE_SNAPSHOT_PREFIX, group_id, epoch)
}

/// Probe name for the deferred-peel sweep's rewind.
///
/// Deliberately distinct from the pass's probe name. Both rewinds capture the
/// same live state at the same `(group, epoch)`, so a shared name hashes to the
/// same string — and `create_group_snapshot` is INSERT OR REPLACE, so a second
/// interrupted probe would overwrite the first instead of leaving two rows for
/// `recover_interrupted_rewind_probe` to fail closed on. Distinct prefixes keep
/// that detector armed.
fn candidate_branch_probe_snapshot_name(group_id: &GroupId, epoch: u64) -> String {
    rewind_probe_snapshot_name(CANDIDATE_BRANCH_PROBE_SNAPSHOT_PREFIX, group_id, epoch)
}

fn rewind_probe_snapshot_name(prefix: &str, group_id: &GroupId, epoch: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(group_id.as_slice());
    hasher.update(epoch.to_be_bytes());
    let digest = hasher.finalize();
    format!("{prefix}{}", hex::encode(&digest[..8]))
}

const RETAINED_ANCHOR_PROBE_SNAPSHOT_PREFIX: &str = "openmls-retained-probe-";
const CANDIDATE_BRANCH_PROBE_SNAPSHOT_PREFIX: &str = "openmls-branch-probe-";

/// Whether `name` is a rewind probe of either kind.
fn is_rewind_probe_snapshot(name: &str) -> bool {
    name.starts_with(RETAINED_ANCHOR_PROBE_SNAPSHOT_PREFIX)
        || name.starts_with(CANDIDATE_BRANCH_PROBE_SNAPSHOT_PREFIX)
}

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
        CANDIDATE_REPLAY_BUDGET_FLOOR, CANDIDATE_REPLAY_BUDGET_SLACK, CandidateBranchPeelFailure,
        OpenMlsProjectionError, ReplayBudget,
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
    fn candidate_failure_preserves_consumed_replay_count() {
        let mut budget = ReplayBudget::new(3);
        budget.consume().expect("first probe");
        budget.consume().expect("second probe");
        let failure = CandidateBranchPeelFailure::new(
            OpenMlsProjectionError::Storage("injected failure".into()),
            budget.consumed,
        );

        assert_eq!(failure.replay_probe_count, 2);
        assert!(matches!(failure.error, OpenMlsProjectionError::Storage(_)));
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
mod unresolved_commit_state_tests {
    use super::unresolved_commit_state;
    use cgka_traits::message::MessageState;

    /// `Processed` staying OUT of this set is load-bearing well past the BFS.
    ///
    /// `build_stored_openmls_candidate_paths` filters `unresolved_commit_ids`
    /// through this predicate, and whatever the BFS then fails to materialize
    /// becomes a `MissingCandidateParent` deferral in
    /// `append_missing_parent_deferred_commits`. Excluding `Processed` is what
    /// makes "a `MissingCandidateParent` deferral never names a previously
    /// applied commit" true, and therefore what makes losing to a *selected*
    /// branch the only route from `Processed` to `ConvergenceDeferred`.
    ///
    /// Two state-derived reconcilers rest on exactly that. Both treat a parked
    /// commit as a genuine branch-selection withdrawal without consulting the
    /// reason that parked it:
    ///
    /// - `marmot_app::AppClient::reconcile_branch_selection_withdrawals`, which
    ///   tombstones the app rows a parked commit synthesized, and
    /// - `marmot_account::AccountDeviceRuntime::reconcile_superseded_maintenance_from_state`,
    ///   which retires the `DurableGroupEvolution` behind it and re-arms the
    ///   self-update obligation it owed.
    ///
    /// Widening this set to admit `Processed` would let a pass that selected no
    /// branch park an applied commit, and both reconcilers would then withdraw
    /// history nothing superseded. That is the blast radius; this test is the
    /// tripwire.
    #[test]
    fn processed_is_not_an_unresolved_commit_state() {
        for state in [
            MessageState::Sent,
            MessageState::Created,
            MessageState::Retryable,
            MessageState::ConvergenceDeferred,
        ] {
            assert!(
                unresolved_commit_state(state),
                "{state:?} is an unresolved commit input and must stay one"
            );
        }
        assert!(
            !unresolved_commit_state(MessageState::Processed),
            "an already-applied commit must never be reported unresolved: two \
             state-derived reconcilers withdraw history on the strength of it"
        );
    }
}

#[cfg(test)]
mod checkpoint_prefix_tests {
    use super::checkpoint_realizable_own_commit_prefix;
    use crate::canonicalization::{CanonicalizationResult, ConvergenceStatus};
    use cgka_traits::engine::CommitOrderingPriority;
    use cgka_traits::group::{Group, ProtocolProfile};
    use cgka_traits::message::{
        MessageRecord, MessageState, OwnCommitConvergenceStamp, StoredMessagePayload,
    };
    use cgka_traits::storage::{GroupStateCheckpointRef, GroupStorage, MessageStorage};
    use cgka_traits::transport::{Timestamp, TransportEnvelope, TransportMessage, TransportSource};
    use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
    use std::collections::BTreeSet;
    use storage_sqlite::SqliteAccountStorage;

    fn group_id() -> GroupId {
        GroupId::new(vec![7u8; 32])
    }

    fn checkpoint_id_for(id: &[u8]) -> String {
        format!("openmls-own-commit-v1-{}", hex::encode(id))
    }

    fn authenticator_for(id: &[u8]) -> String {
        format!("auth-{}", hex::encode(id))
    }

    fn own_commit_row(id: &[u8], source_epoch: u64) -> MessageRecord {
        own_commit_row_with_checkpoint(id, source_epoch, true)
    }

    fn own_commit_row_with_checkpoint(
        id: &[u8],
        source_epoch: u64,
        present: bool,
    ) -> MessageRecord {
        let message = TransportMessage {
            id: MessageId::new(id.to_vec()),
            // The prefix scan never parses MLS bytes; only the stored
            // envelope's stamp and the row's epoch matter here.
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
            checkpoint_id: present.then(|| checkpoint_id_for(id)),
            resulting_epoch_authenticator: present.then(|| authenticator_for(id)),
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

    fn storage_with_checkpoint(id: &[u8], resulting_epoch: u64) -> SqliteAccountStorage {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        storage
            .put_group(&Group {
                id: group_id(),
                name: "checkpoint-prefix".into(),
                description: String::new(),
                epoch: EpochId(resulting_epoch),
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
            .create_group_state_checkpoint(
                &group_id(),
                &GroupStateCheckpointRef {
                    id: checkpoint_id_for(id),
                    resulting_epoch: EpochId(resulting_epoch),
                },
            )
            .unwrap();
        storage
    }

    #[test]
    fn stamped_own_commit_selects_its_exact_checkpoint() {
        let storage = storage_with_checkpoint(b"commit-a", 2);
        storage
            .put_message(&own_commit_row(b"commit-a", 1))
            .unwrap();

        let prefix = checkpoint_realizable_own_commit_prefix(
            &storage,
            &result_accepting(&[b"commit-a"]),
            &BTreeSet::new(),
        )
        .unwrap();
        let realized = prefix.realized.expect("checkpoint should be realizable");
        assert_eq!(realized.resulting_epoch, 2);
        assert!(prefix.commit_ids.contains(&hex::encode(b"commit-a")));
        assert_eq!(realized.id, checkpoint_id_for(b"commit-a"));
        assert_eq!(
            realized.expected_epoch_authenticator,
            authenticator_for(b"commit-a")
        );
    }

    #[test]
    fn own_commit_without_a_checkpoint_refuses_the_fast_path() {
        let storage = storage_with_checkpoint(b"commit-a", 2);
        storage
            .put_message(&own_commit_row_with_checkpoint(b"commit-a", 1, false))
            .unwrap();

        let prefix = checkpoint_realizable_own_commit_prefix(
            &storage,
            &result_accepting(&[b"commit-a"]),
            &BTreeSet::new(),
        )
        .unwrap();
        assert!(
            prefix.realized.is_none(),
            "a commit without a checkpoint must not yield a restore target"
        );
        assert!(
            prefix.commit_ids.is_empty(),
            "a commit without a checkpoint must not realize any commit"
        );
    }

    #[test]
    fn a_run_of_own_commits_uses_the_last_checkpoint() {
        let storage = storage_with_checkpoint(b"commit-a", 2);
        let mut group = storage.get_group(&group_id()).unwrap();
        group.epoch = EpochId(3);
        storage.put_group(&group).unwrap();
        storage
            .create_group_state_checkpoint(
                &group_id(),
                &GroupStateCheckpointRef {
                    id: checkpoint_id_for(b"commit-a-next"),
                    resulting_epoch: EpochId(3),
                },
            )
            .unwrap();
        storage
            .put_message(&own_commit_row(b"commit-a", 1))
            .unwrap();
        storage
            .put_message(&own_commit_row(b"commit-a-next", 2))
            .unwrap();

        let prefix = checkpoint_realizable_own_commit_prefix(
            &storage,
            &result_accepting(&[b"commit-a", b"commit-a-next"]),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(prefix.commit_ids.len(), 2);
        let realized = prefix
            .realized
            .expect("last checkpoint should realize the run");
        assert_eq!(realized.resulting_epoch, 3);
        assert_eq!(realized.id, checkpoint_id_for(b"commit-a-next"));
    }

    #[test]
    fn sibling_own_rows_at_the_same_epoch_do_not_alias() {
        let storage = storage_with_checkpoint(b"commit-a", 2);
        storage
            .put_message(&own_commit_row(b"commit-a", 1))
            .unwrap();
        storage
            .put_message(&own_commit_row_with_checkpoint(b"commit-a2", 1, false))
            .unwrap();

        let prefix = checkpoint_realizable_own_commit_prefix(
            &storage,
            &result_accepting(&[b"commit-a2"]),
            &BTreeSet::new(),
        )
        .unwrap();
        assert!(
            prefix.realized.is_none(),
            "a sibling at the same epoch must not resolve to another commit's checkpoint"
        );
        assert!(prefix.commit_ids.is_empty());
    }
}

/// Producer-side coverage for [`candidate_branch_peel`]: a stored graph that is
/// contested stays contested through every enumeration halt.
///
/// These fixtures build a real forked graph out of real OpenMLS commits and
/// drive the helper into each halt for real, because the property under test is
/// exactly the one a hand-built [`CandidateBranchPeel`] cannot show: that the
/// verdict survives losing the contexts. How the sweep reads the two fields
/// apart is pinned separately, over constructed values, in
/// `message_processor::ingest`.
#[cfg(test)]
mod candidate_branch_peel_halt_tests {
    use super::{
        CANDIDATE_REPLAY_BUDGET_FLOOR, CANDIDATE_REPLAY_BUDGET_SLACK, CandidateBranchPeel,
        ReplayProfilePolicy, candidate_branch_peel, own_commit_checkpoint_id,
    };
    use crate::account_identity_proof::{AccountIdentityProofRequest, AccountIdentityProofSigner};
    use crate::convergence::V1_MAX_REWIND_COMMITS;
    use crate::message_processor::MAX_CANDIDATE_BRANCH_PEEL_CONTEXTS;
    use crate::provider::EngineOpenMlsProvider;
    use crate::{DEFAULT_CIPHERSUITE, Engine, EngineBuilder};
    use async_trait::async_trait;
    use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, SendIntent, SendResult};
    use cgka_traits::error::PeelerError;
    use cgka_traits::group_context::GroupContextSnapshot;
    use cgka_traits::ingest::{PeeledContent, PeeledMessage};
    use cgka_traits::message::{MessageRecord, MessageState, StoredMessagePayload};
    use cgka_traits::peeler::TransportPeeler;
    use cgka_traits::storage::{
        AccountDeviceSignerStorage, GroupStorage, MessageStorage, StorageProvider,
    };
    use cgka_traits::transport::{
        EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
    };
    use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
    use k256::schnorr::{SigningKey, signature::hazmat::PrehashSigner};
    use openmls::group::MlsGroup;
    use openmls::prelude::{MlsMessageIn, ProcessedMessageContent};
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_rust_crypto::RustCrypto;
    use openmls_traits::OpenMlsProvider as _;
    use sha2::{Digest, Sha256};
    use std::sync::Arc;
    use storage_sqlite::SqliteAccountStorage;
    use tls_codec::{Deserialize as _, Serialize as _};

    // --- Test devices --------------------------------------------------------

    /// Deterministic BIP-340 key for a seed label. Marmot credential identities
    /// MUST be a valid 32-byte x-only secp256k1 public key, so identities are
    /// derived rather than invented.
    fn signing_key(seed: &[u8]) -> SigningKey {
        for counter in 0u64.. {
            let mut material = [0u8; 32];
            let mut hasher = Sha256::new();
            hasher.update(b"cgka-engine-test-identity-v1");
            hasher.update(seed);
            hasher.update(counter.to_be_bytes());
            material.copy_from_slice(&hasher.finalize());
            if let Ok(key) = SigningKey::from_bytes(&material) {
                return key;
            }
        }
        unreachable!("a signing key is found within u64 counters")
    }

    fn member_id(seed: &[u8]) -> MemberId {
        MemberId::new(signing_key(seed).verifying_key().to_bytes().to_vec())
    }

    struct SeedProofSigner(SigningKey);

    impl AccountIdentityProofSigner for SeedProofSigner {
        fn sign_account_identity_proof(
            &self,
            request: &AccountIdentityProofRequest,
        ) -> Result<[u8; 64], String> {
            Ok(self
                .0
                .sign_prehash(&request.proof_event_id()?)
                .map_err(|e| e.to_string())?
                .to_bytes())
        }
    }

    /// Transport is not under test here: every message is carried verbatim.
    struct PassthroughPeeler;

    #[async_trait]
    impl TransportPeeler for PassthroughPeeler {
        async fn peel_group_message(
            &self,
            msg: &TransportMessage,
            _ctx: &GroupContextSnapshot,
        ) -> Result<PeeledMessage, PeelerError> {
            Ok(PeeledMessage {
                id: msg.id.clone(),
                group_id: None,
                sender: None,
                content: PeeledContent::MlsMessage {
                    bytes: msg.payload.clone(),
                },
                origin: msg.clone(),
            })
        }

        async fn peel_welcome(&self, msg: &TransportMessage) -> Result<PeeledMessage, PeelerError> {
            Ok(PeeledMessage {
                id: msg.id.clone(),
                group_id: None,
                sender: None,
                content: PeeledContent::Welcome {
                    bytes: msg.payload.clone(),
                },
                origin: msg.clone(),
            })
        }

        async fn wrap_group_message(
            &self,
            payload: &EncryptedPayload,
            _ctx: &GroupContextSnapshot,
        ) -> Result<TransportMessage, PeelerError> {
            Ok(transport_message(
                &payload.ciphertext,
                TransportEnvelope::GroupMessage {
                    transport_group_id: vec![],
                },
            ))
        }

        async fn wrap_welcome(
            &self,
            payload: &EncryptedPayload,
            recipient: &MemberId,
        ) -> Result<TransportMessage, PeelerError> {
            Ok(transport_message(
                &payload.ciphertext,
                TransportEnvelope::Welcome {
                    recipient: recipient.clone(),
                },
            ))
        }
    }

    fn transport_message(payload: &[u8], envelope: TransportEnvelope) -> TransportMessage {
        TransportMessage {
            id: MessageId::new(Sha256::digest(payload).to_vec()),
            payload: payload.to_vec(),
            timestamp: Timestamp(0),
            causal_deps: vec![],
            source: TransportSource("candidate-branch-peel-test".into()),
            envelope,
        }
    }

    fn build_client(seed: &[u8]) -> (Engine<SqliteAccountStorage>, SqliteAccountStorage) {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let engine = EngineBuilder::new(storage.clone())
            .legacy_compatibility_profile()
            .identity(member_id(seed).as_slice().to_vec())
            .account_identity_proof_signer(Arc::new(SeedProofSigner(signing_key(seed))))
            .peeler(Box::new(PassthroughPeeler))
            .build()
            .unwrap();
        (engine, storage)
    }

    async fn group_with(
        creator: &mut Engine<SqliteAccountStorage>,
        joiners: &mut [&mut Engine<SqliteAccountStorage>],
    ) -> GroupId {
        let mut key_packages = Vec::new();
        for joiner in joiners.iter_mut() {
            key_packages.push(joiner.fresh_key_package().await.unwrap());
        }
        let (group_id, created) = creator
            .create_group(CreateGroupRequest {
                name: "candidate branch peel".into(),
                description: String::new(),
                members: key_packages,
                required_features: vec![],
                app_components: vec![],
                initial_admins: vec![creator.self_id()],
            })
            .await
            .unwrap();
        let SendResult::GroupCreated { pending, welcomes } = created else {
            panic!("expected GroupCreated");
        };
        creator.confirm_published(pending).await.unwrap();
        for (joiner, welcome) in joiners.iter_mut().zip(welcomes) {
            joiner.join_welcome(welcome).await.unwrap();
        }
        group_id
    }

    // --- Graph fixtures ------------------------------------------------------

    /// Grind one more valid commit out of a device's live state without
    /// advancing it: the pending commit is cleared, so the next call forks from
    /// the same epoch again. This is how a wide same-epoch fork is built.
    fn rival_commit(
        storage: &SqliteAccountStorage,
        sender: &MemberId,
        group_id: &GroupId,
    ) -> TransportMessage {
        let crypto = RustCrypto::default();
        let provider =
            EngineOpenMlsProvider::<SqliteAccountStorage>::new(&crypto, storage.mls_storage());
        let mls_group_id = openmls::group::GroupId::from_slice(group_id.as_slice());
        let mut mls_group = MlsGroup::load(provider.storage(), &mls_group_id)
            .expect("load rival MLS group")
            .expect("rival has group state");
        let binding = storage
            .account_device_signer(sender)
            .expect("load signer binding")
            .expect("signer binding exists");
        let signer = SignatureKeyPair::read(
            storage.mls_storage(),
            &binding.mls_signature_public_key,
            DEFAULT_CIPHERSUITE.signature_algorithm(),
        )
        .expect("MLS signer exists");

        let bundle = mls_group
            .commit_builder()
            .load_psks(provider.storage())
            .expect("load PSKs")
            .build(provider.rand(), provider.crypto(), &signer, |_| true)
            .expect("build rival self-update commit")
            .stage_commit(&provider)
            .expect("stage rival self-update commit");
        let (commit, _welcome, _group_info) = bundle.into_contents();
        let bytes = commit
            .tls_serialize_detached()
            .expect("serialize rival self-update commit");
        mls_group
            .clear_pending_commit(provider.storage())
            .expect("clear the rival's pending commit");

        transport_message(
            &bytes,
            TransportEnvelope::GroupMessage {
                transport_group_id: group_id.as_slice().to_vec(),
            },
        )
    }

    /// Apply a commit to a device's stored state, putting it on that branch.
    /// Grinding successors out of a device ([`rival_commit`]) needs it standing
    /// where those successors fork from.
    fn adopt_branch(storage: &SqliteAccountStorage, group_id: &GroupId, commit: &TransportMessage) {
        let crypto = RustCrypto::default();
        let provider =
            EngineOpenMlsProvider::<SqliteAccountStorage>::new(&crypto, storage.mls_storage());
        let mls_group_id = openmls::group::GroupId::from_slice(group_id.as_slice());
        let mut mls_group = MlsGroup::load(provider.storage(), &mls_group_id)
            .expect("load adopting MLS group")
            .expect("adopter has group state");
        let message = MlsMessageIn::tls_deserialize_exact(commit.payload.as_slice())
            .expect("adopted commit deserializes")
            .try_into_protocol_message()
            .expect("adopted commit is a protocol message");
        let processed = mls_group
            .process_message(&provider, message)
            .expect("adopted commit processes");
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            panic!("expected a staged commit");
        };
        mls_group
            .merge_staged_commit(&provider, *staged)
            .expect("merge the adopted commit");

        let mut group = storage.get_group(group_id).unwrap();
        group.epoch = EpochId(mls_group.epoch().as_u64());
        storage.put_group(&group).unwrap();
    }

    /// Admit a rival commit into the observer's graph in the state ingest
    /// leaves behind for a peeled commit that convergence has not adjudicated.
    fn admit_rival(
        storage: &SqliteAccountStorage,
        group_id: &GroupId,
        commit: &TransportMessage,
        source_epoch: u64,
    ) {
        storage
            .put_message(&MessageRecord {
                id: commit.id.clone(),
                group_id: group_id.clone(),
                epoch: EpochId(source_epoch),
                state: MessageState::ConvergenceDeferred,
                payload: StoredMessagePayload::openmls_wire(commit.clone())
                    .encode()
                    .unwrap(),
                deferred_peel: None,
            })
            .unwrap();
    }

    /// Survey the observer's graph exactly as the deferred-peel sweep does,
    /// under the rewind allowance the caller wants to give enumeration.
    fn peel(
        storage: &SqliteAccountStorage,
        group_id: &GroupId,
        max_rewind_commits: u64,
    ) -> CandidateBranchPeel {
        let epoch = storage.get_group(group_id).unwrap().epoch.0;
        candidate_branch_peel(
            storage,
            group_id,
            epoch.saturating_sub(max_rewind_commits),
            max_rewind_commits,
            ReplayProfilePolicy::default(),
            MAX_CANDIDATE_BRANCH_PEEL_CONTEXTS,
        )
        .expect("a branch survey over healthy storage")
    }

    // --- The halts -----------------------------------------------------------

    #[tokio::test]
    async fn a_lost_own_commit_checkpoint_halts_enumeration_and_keeps_the_fork() {
        let (mut alice, alice_storage) = build_client(b"peel-halt-alice");
        let (mut bob, bob_storage) = build_client(b"peel-halt-bob");
        let group_id = group_with(&mut alice, &mut [&mut bob]).await;

        // Alice commits at epoch 1 and advances; Bob forks from the same epoch.
        let own_commit = match alice
            .send(SendIntent::SelfUpdate {
                group_id: group_id.clone(),
            })
            .await
            .unwrap()
        {
            SendResult::GroupEvolution { msg, pending, .. } => {
                alice.confirm_published(pending).await.unwrap();
                msg
            }
            other => panic!("expected GroupEvolution, got {other:?}"),
        };
        assert_eq!(alice.epoch(&group_id).unwrap(), EpochId(2));
        let rival = rival_commit(&bob_storage, &member_id(b"peel-halt-bob"), &group_id);
        admit_rival(&alice_storage, &group_id, &rival, 1);

        // Control: with the checkpoint in place both branches materialize, so
        // the halt below is what empties the contexts — not a graph that never
        // had two branches to enumerate.
        let enumerated = peel(&alice_storage, &group_id, V1_MAX_REWIND_COMMITS);
        assert!(enumerated.contested);
        assert!(
            enumerated.contexts.len() > 1,
            "a two-way epoch-1 fork offers a context per branch"
        );

        // MLS cannot replay this device's own path-bearing commit from the
        // public wire echo, so losing its post-merge checkpoint costs
        // enumeration the branch it is standing on.
        let checkpoint = own_commit_checkpoint_id(&alice_storage, &own_commit.id).unwrap();
        alice_storage
            .release_group_state_checkpoint(&group_id, &checkpoint)
            .unwrap();

        let halted = peel(&alice_storage, &group_id, V1_MAX_REWIND_COMMITS);
        assert!(
            halted.contexts.is_empty(),
            "a missing own-commit checkpoint must halt enumeration"
        );
        assert!(
            halted.contested,
            "the fork is in the stored graph, not in what enumeration managed to read"
        );
    }

    /// A same-epoch fork wide enough that probing it costs more replays than
    /// the enumeration budget allows.
    ///
    /// Every rival at the fork epoch becomes a frontier path, and every commit
    /// at the next epoch is probed against every one of those paths: the budget
    /// is linear in the commit count, the probes are its product.
    const WIDTH: usize = 10;
    const DEPTH: usize = 13;

    /// `WIDTH * (1 + DEPTH)` probes against the smallest budget a legal rewind
    /// allowance can produce. Held at compile time so that raising either
    /// budget constant lands here, with the arithmetic in view, rather than as
    /// a mystifying empty-context assertion.
    const _: () = assert!(
        (WIDTH * (1 + DEPTH)) as u64
            > CANDIDATE_REPLAY_BUDGET_SLACK * (WIDTH + DEPTH) as u64
                + CANDIDATE_REPLAY_BUDGET_FLOOR
    );

    #[tokio::test]
    async fn an_exhausted_replay_budget_halts_enumeration_and_keeps_the_fork() {
        let (mut alice, alice_storage) = build_client(b"peel-budget-alice");
        let (mut bob, bob_storage) = build_client(b"peel-budget-bob");
        let (mut carol, carol_storage) = build_client(b"peel-budget-carol");
        let group_id = group_with(&mut alice, &mut [&mut bob, &mut carol]).await;

        // Bob forks the epoch WIDTH ways. Alice never leaves epoch 1, so every
        // rival is a branch she has to enumerate.
        let bob_id = member_id(b"peel-budget-bob");
        let mut fork = Vec::new();
        for _ in 0..WIDTH {
            let commit = rival_commit(&bob_storage, &bob_id, &group_id);
            admit_rival(&alice_storage, &group_id, &commit, 1);
            fork.push(commit);
        }

        // Carol adopts one branch and commits on it DEPTH times. Those commits
        // are valid only on that branch, but enumeration cannot know that
        // without probing each of them against every branch.
        adopt_branch(&carol_storage, &group_id, &fork[0]);
        assert_eq!(
            carol_storage.get_group(&group_id).unwrap().epoch,
            EpochId(2)
        );
        let carol_id = member_id(b"peel-budget-carol");
        for _ in 0..DEPTH {
            let commit = rival_commit(&carol_storage, &carol_id, &group_id);
            admit_rival(&alice_storage, &group_id, &commit, 2);
        }

        // Control: the same graph under the production rewind allowance has
        // budget to spare, so it enumerates instead of halting.
        let enumerated = peel(&alice_storage, &group_id, V1_MAX_REWIND_COMMITS);
        assert!(enumerated.contested);
        assert!(
            enumerated.contexts.len() > 1,
            "a {WIDTH}-way fork offers a context per branch"
        );

        let halted = peel(&alice_storage, &group_id, 0);
        assert!(
            halted.contexts.is_empty(),
            "an exhausted replay budget must halt enumeration"
        );
        assert!(
            halted.contested,
            "the fork is in the stored graph, not in what enumeration managed to read"
        );
    }

    // --- The cap -------------------------------------------------------------

    /// The epoch every device in these fixtures is standing on when the fork
    /// happens, so a one-commit branch tips at `FORK_EPOCH + 1` and the
    /// two-commit branch at `FORK_EPOCH + 2`.
    const FORK_EPOCH: u64 = 1;

    /// Wide enough that the surviving branches outnumber the cap: one rival per
    /// width, minus the one Carol extends, plus her deeper branch.
    const WIDE_FORK_WIDTH: usize = MAX_CANDIDATE_BRANCH_PEEL_CONTEXTS + 2;

    /// A fork wider than the cap, with one branch carried a commit deeper, as
    /// stored by two devices that never left the fork epoch.
    ///
    /// Bob forks [`WIDE_FORK_WIDTH`] ways and Carol adopts one rival and commits
    /// on it, so each observer holds `WIDE_FORK_WIDTH - 1` one-commit branches
    /// plus one two-commit branch. Both observers are given the same evidence,
    /// which is what lets a peer comparison mean anything.
    async fn wide_fork_with_one_deep_branch()
    -> (GroupId, SqliteAccountStorage, SqliteAccountStorage) {
        let (mut alice, alice_storage) = build_client(b"peel-rank-alice");
        let (mut bob, bob_storage) = build_client(b"peel-rank-bob");
        let (mut carol, carol_storage) = build_client(b"peel-rank-carol");
        let (mut dave, dave_storage) = build_client(b"peel-rank-dave");
        let group_id = group_with(&mut alice, &mut [&mut bob, &mut carol, &mut dave]).await;

        let bob_id = member_id(b"peel-rank-bob");
        let mut fork = Vec::new();
        for _ in 0..WIDE_FORK_WIDTH {
            let commit = rival_commit(&bob_storage, &bob_id, &group_id);
            for observer in [&alice_storage, &dave_storage] {
                admit_rival(observer, &group_id, &commit, FORK_EPOCH);
            }
            fork.push(commit);
        }

        adopt_branch(&carol_storage, &group_id, &fork[0]);
        let deeper = rival_commit(&carol_storage, &member_id(b"peel-rank-carol"), &group_id);
        for observer in [&alice_storage, &dave_storage] {
            admit_rival(observer, &group_id, &deeper, FORK_EPOCH + 1);
        }

        (group_id, alice_storage, dave_storage)
    }

    fn branch_ids(survey: &CandidateBranchPeel) -> Vec<String> {
        survey
            .contexts
            .iter()
            .map(|context| context.branch_id.clone())
            .collect()
    }

    #[tokio::test]
    async fn a_fork_wider_than_the_cap_keeps_the_same_branches_on_every_peer() {
        let (group_id, alice_storage, dave_storage) = wide_fork_with_one_deep_branch().await;

        let alice = peel(&alice_storage, &group_id, V1_MAX_REWIND_COMMITS);
        let dave = peel(&dave_storage, &group_id, V1_MAX_REWIND_COMMITS);

        assert!(alice.contested && dave.contested);
        assert_eq!(
            alice.contexts.len(),
            MAX_CANDIDATE_BRANCH_PEEL_CONTEXTS,
            "a graph offering more branches than the cap must fill it exactly"
        );
        assert_eq!(
            branch_ids(&alice),
            branch_ids(&dave),
            "the capped subset is content-derived, so peers holding the same \
             evidence must keep the same branches in the same order"
        );
    }

    #[tokio::test]
    async fn a_deeper_branch_outranks_shallow_rivals_for_the_capped_contexts() {
        let (group_id, alice_storage, _dave_storage) = wide_fork_with_one_deep_branch().await;

        let survey = peel(&alice_storage, &group_id, V1_MAX_REWIND_COMMITS);

        assert_eq!(
            survey.contexts.iter().map(|c| c.tip_epoch).max(),
            Some(FORK_EPOCH + 2),
            "a branch carried two commits deep holds traffic the one-commit \
             rivals cannot unseal, so filling the cap with rivals must not \
             evict it"
        );
    }
}
