//! Bytes-first OpenMLS projection and canonicalization helpers.
//!
//! OpenMLS protocol objects are intentionally consumed by processing APIs.
//! The canonicalization contract should therefore retain bytes and derived
//! observations, not long-lived OpenMLS values. This module can either
//! snapshot-and-replay messages for candidate materialization or apply a
//! selected canonical branch to retained storage.

use std::collections::{BTreeMap, BTreeSet};

use crate::provider::EngineOpenMlsProvider;
use cgka_traits::app_components::AppComponentData;
use cgka_traits::group::Member;
use cgka_traits::message::{MessageRecord, MessageState, StoredMessagePayload};
use cgka_traits::storage::{StorageError, StorageProvider};
use cgka_traits::transport::{TransportEnvelope, TransportMessage};
use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
use openmls::component::ComponentData;
use openmls::group::{MlsGroup, ProcessMessageError, ValidationError};
use openmls::messages::proposals::{AppDataUpdateOperation, Proposal, ProposalOrRef};
use openmls::prelude::{
    BasicCredential, ContentType, MlsMessageBodyIn, MlsMessageIn, ProcessedMessage,
    ProcessedMessageContent, ProtocolMessage, ProtocolVersion, Sender,
};
use openmls_rust_crypto::RustCrypto;
use openmls_traits::OpenMlsProvider;
use sha2::{Digest, Sha256};
use tls_codec::{Deserialize as _, Serialize as TlsSerialize};

use crate::canonicalization::{
    CanonicalizationError, CanonicalizationInput, CanonicalizationPolicy, CanonicalizationResult,
    CanonicalizationState, DroppedMessage, DroppedMessageReason, MaterializedCandidate,
    MessageKind, OutboundIntent, PeeledMessage, PeeledMessageKind, SyncState,
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
}

#[derive(Clone, Debug)]
struct StoredOpenMlsCandidatePathResult {
    candidate_paths: Vec<OpenMlsCandidatePath>,
    invalid_commit_drops: Vec<DroppedMessage>,
}

#[derive(Clone, Debug)]
enum CandidatePathProbeResult {
    Materialized(Option<OpenMlsMaterializedCandidate>),
    UnauthorizedCommit { message_id: String },
}

#[derive(Clone, Debug)]
struct StoredOpenMlsCanonicalizationWork {
    state: CanonicalizationState,
    commit_messages: Vec<StoredCommitMessage>,
    pending_messages: Vec<TransportMessage>,
    outbound_intents: Vec<OutboundIntent>,
    policy: CanonicalizationPolicy,
    now_ms: u64,
    replay_start_epoch: u64,
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
        consumed_proposal_refs: Vec<String>,
    },
    ApplicationProcessed {
        message_id: String,
        source_epoch: u64,
        sender: Vec<u8>,
        payload: Vec<u8>,
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
    UnauthorizedCommit { message_id: String },
    Serialize(String),
    Storage(String),
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
            OpenMlsProjectionError::UnauthorizedCommit { message_id } => {
                write!(f, "unauthorized admin-gated commit: {message_id}")
            }
            OpenMlsProjectionError::Serialize(e) => write!(f, "serialize failed: {e}"),
            OpenMlsProjectionError::Storage(e) => write!(f, "storage failed: {e}"),
        }
    }
}

impl std::error::Error for OpenMlsProjectionError {}

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

pub fn replay_openmls_messages<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    messages: &[TransportMessage],
) -> Result<Vec<OpenMlsReplayObservation>, OpenMlsProjectionError> {
    use crate::snapshot_guard::SnapshotRollbackGuard;
    let snapshot = replay_snapshot_name(group_id, messages);
    // RAII: on any unwind path (panic during replay, early error)
    // Drop rolls back + releases. On the happy path we explicitly
    // commit at the end.
    let guard = SnapshotRollbackGuard::create(storage, group_id.clone(), snapshot)
        .map_err(|e| OpenMlsProjectionError::Snapshot(format!("{e:?}")))?;

    let result =
        process_openmls_messages_inner(storage, group_id, messages).map(|out| out.observations);
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
    let mut candidates = Vec::with_capacity(paths.len());
    for path in paths {
        if path.messages.is_empty() {
            return Err(OpenMlsProjectionError::EmptyCandidatePath(
                path.branch_id.clone(),
            ));
        }
        let observations = replay_openmls_messages(storage, group_id, &path.messages)?;
        let mut fork_epoch: Option<u64> = None;
        let mut tip_epoch: Option<u64> = None;
        let mut tip_digest: Option<[u8; 32]> = None;
        let mut commit_message_ids = Vec::new();
        let mut consumed_proposal_refs = Vec::new();

        for observation in &observations {
            let OpenMlsReplayObservation::CommitStaged {
                message_id,
                source_epoch,
                resulting_epoch,
                consumed_proposal_refs: commit_consumed_proposal_refs,
            } = observation
            else {
                continue;
            };
            fork_epoch = Some(fork_epoch.map_or(*source_epoch, |epoch| epoch.min(*source_epoch)));
            tip_epoch = Some(*resulting_epoch);
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
        let tip_digest = tip_digest.expect("commit observation came from path message");
        consumed_proposal_refs.sort();
        consumed_proposal_refs.dedup();

        candidates.push(OpenMlsMaterializedCandidate {
            branch_id: path.branch_id.clone(),
            fork_epoch,
            tip_epoch,
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
    let candidate_paths = candidate_paths_with_pending_replay_messages(
        &batch.candidate_paths,
        &batch.pending_messages,
    )?;
    let materialized = materialize_openmls_candidate_paths(storage, group_id, &candidate_paths)?;
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
        &proposal_branch_by_id,
        &app_messages_by_id,
    )?;

    Ok(canonicalize_with_materialized_candidates(
        CanonicalizationInput {
            state: batch.state,
            pending_messages,
            outbound_intents: batch.outbound_intents,
            candidate_branches: vec![],
            policy: batch.policy,
            now_ms: batch.now_ms,
        },
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
    let mut stale_commit_drops = Vec::new();

    for record in records {
        if !record_state_can_contribute_to_openmls_graph(record.state) {
            continue;
        }
        let Some(message) = openmls_wire_message_from_record(&record)? else {
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
                        });
                    }
                    continue;
                }
                commit_messages.push(StoredCommitMessage {
                    message,
                    source_epoch,
                    digest: projection.message_digest,
                    state: record.state,
                });
            }
            OpenMlsContentKind::Proposal | OpenMlsContentKind::Application
                if record_state_is_canonicalization_input(record.state)
                    && source_epoch.is_some_and(|epoch| epoch >= state.retained_anchor_epoch) =>
            {
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
                outbound_intents,
                policy,
                now_ms,
                replay_start_epoch,
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
            outbound_intents,
            policy,
            now_ms,
            replay_start_epoch,
        },
    )?;
    append_dropped_messages(&mut result, stale_commit_drops);
    Ok(result)
}

fn append_dropped_messages(
    result: &mut CanonicalizationResult,
    dropped_messages: Vec<DroppedMessage>,
) {
    for dropped in dropped_messages {
        if result
            .dropped_messages
            .iter()
            .any(|existing| existing.message_id == dropped.message_id)
        {
            continue;
        }
        result.dropped_messages.push(dropped);
    }
    result.dropped_messages.sort();
}

fn canonicalize_stored_openmls_messages_from_retained_anchor<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    work: StoredOpenMlsCanonicalizationWork,
) -> Result<CanonicalizationResult, OpenMlsProjectionError> {
    let live_snapshot = retained_anchor_probe_snapshot_name(group_id, work.replay_start_epoch);
    storage
        .create_group_snapshot(group_id, &live_snapshot)
        .map_err(|e| OpenMlsProjectionError::Snapshot(format!("{e:?}")))?;

    let anchor_snapshot = retained_anchor_snapshot_name(work.replay_start_epoch);
    let result = match storage.rollback_group_to_snapshot(group_id, &anchor_snapshot) {
        Ok(()) => canonicalize_stored_openmls_messages_from_current(storage, group_id, work),
        Err(StorageError::SnapshotMissing(_)) => Ok(missing_retained_anchor_result(
            work.state,
            work.outbound_intents,
            work.policy,
            work.now_ms,
        )),
        Err(e) => Err(OpenMlsProjectionError::Snapshot(format!("{e:?}"))),
    };

    let rollback_result = storage
        .rollback_group_to_snapshot(group_id, &live_snapshot)
        .map_err(|e| OpenMlsProjectionError::Snapshot(format!("{e:?}")));
    let release_result = storage
        .release_group_snapshot(group_id, &live_snapshot)
        .map_err(|e| OpenMlsProjectionError::Snapshot(format!("{e:?}")));

    rollback_result?;
    release_result?;
    result
}

fn canonicalize_stored_openmls_messages_from_current<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    work: StoredOpenMlsCanonicalizationWork,
) -> Result<CanonicalizationResult, OpenMlsProjectionError> {
    let path_result = build_stored_openmls_candidate_paths(
        storage,
        group_id,
        work.commit_messages,
        &work.pending_messages,
        work.replay_start_epoch,
    )?;

    let mut result = canonicalize_openmls_batch(
        storage,
        group_id,
        OpenMlsCanonicalizationBatch {
            state: work.state,
            candidate_paths: path_result.candidate_paths,
            pending_messages: work.pending_messages,
            outbound_intents: work.outbound_intents,
            policy: work.policy,
            now_ms: work.now_ms,
        },
    )?;
    append_dropped_messages(&mut result, path_result.invalid_commit_drops);
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
    let sync_state = if elapsed >= policy.stable_quiescence_ms {
        SyncState::Stable
    } else {
        SyncState::Syncing
    };
    CanonicalizationResult {
        previous_tip: state.current_tip_epoch,
        selected_tip: None,
        selected_branch_id: None,
        sync_state,
        accepted_commits: Vec::new(),
        accepted_proposals: Vec::new(),
        accepted_app_messages: Vec::new(),
        invalidated_app_messages: Vec::new(),
        dropped_messages: Vec::new(),
        already_seen: Vec::new(),
        queued_outbound_intents: outbound_intents,
        publishable_outbound_messages: Vec::new(),
        errors: vec![CanonicalizationError::MissingRetainedAnchor],
    }
}

fn build_stored_openmls_candidate_paths<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    mut commits: Vec<StoredCommitMessage>,
    pending_messages: &[TransportMessage],
    starting_epoch: u64,
) -> Result<StoredOpenMlsCandidatePathResult, OpenMlsProjectionError> {
    commits.sort_by(|a, b| {
        a.source_epoch
            .cmp(&b.source_epoch)
            .then_with(|| a.digest.cmp(&b.digest))
            .then_with(|| a.message.payload.cmp(&b.message.payload))
    });

    let pending_proposals = pending_proposal_messages(pending_messages)?;
    let mut frontier = vec![CandidatePathProbe {
        messages: Vec::new(),
        digests: Vec::new(),
        tip_epoch: starting_epoch,
    }];
    let mut completed = Vec::new();
    let mut invalid_commit_drops = Vec::new();
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
                )? {
                    CandidatePathProbeResult::Materialized(Some(candidate)) => candidate,
                    CandidatePathProbeResult::Materialized(None) => continue,
                    CandidatePathProbeResult::UnauthorizedCommit { message_id } => {
                        invalid_commit_drops.push(DroppedMessage {
                            message_id,
                            kind: MessageKind::Commit,
                            reason: DroppedMessageReason::InvalidAgainstCandidateState,
                        });
                        continue;
                    }
                };

                extended = true;
                next_frontier.push(CandidatePathProbe {
                    messages,
                    digests,
                    tip_epoch: candidate.tip_epoch,
                });
            }

            if !path.messages.is_empty() && !extended {
                completed.push(path);
            }
        }

        frontier = next_frontier;
    }

    Ok(StoredOpenMlsCandidatePathResult {
        candidate_paths: completed
            .into_iter()
            .map(|path| OpenMlsCandidatePath {
                branch_id: branch_id_for_path_digests(&path.digests),
                messages: path.messages,
            })
            .collect(),
        invalid_commit_drops,
    })
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

fn probe_candidate_path<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    messages: Vec<TransportMessage>,
    digests: &[[u8; 32]],
    pending_proposals: &[TransportMessage],
) -> Result<CandidatePathProbeResult, OpenMlsProjectionError> {
    let path = OpenMlsCandidatePath {
        branch_id: branch_id_for_path_digests(digests),
        messages,
    };
    let replay_paths = candidate_paths_with_pending_replay_messages(&[path], pending_proposals)?;
    match materialize_openmls_candidate_paths(storage, group_id, &replay_paths) {
        Ok(mut candidates) => Ok(CandidatePathProbeResult::Materialized(candidates.pop())),
        Err(OpenMlsProjectionError::UnauthorizedCommit { message_id }) => {
            Ok(CandidatePathProbeResult::UnauthorizedCommit { message_id })
        }
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
    let replay_messages = replay_messages_for_canonicalization_result(storage, result)?;
    let current_epoch = storage
        .get_group(group_id)
        .map_err(|e| OpenMlsProjectionError::Storage(format!("{e:?}")))?
        .epoch
        .0;
    let live_message_records = storage
        .list_messages(group_id, EpochId(0))
        .map_err(|e| OpenMlsProjectionError::Storage(format!("{e:?}")))?;
    let live_queued_outbound = storage
        .list_queued_outbound_intents(group_id)
        .map_err(|e| OpenMlsProjectionError::Storage(format!("{e:?}")))?;
    let apply_start_epoch =
        apply_start_epoch_for_canonicalization_result(storage, result)?.unwrap_or(current_epoch);
    let snapshot = apply_snapshot_name(group_id, result);
    storage
        .create_group_snapshot(group_id, &snapshot)
        .map_err(|e| OpenMlsProjectionError::Snapshot(format!("{e:?}")))?;

    let prepare_result =
        if !result.accepted_commits.is_empty() && apply_start_epoch == current_epoch {
            retain_current_group_epoch_snapshot(storage, group_id, max_retained_anchor_rewind)
        } else if apply_start_epoch < current_epoch {
            let anchor_snapshot = retained_anchor_snapshot_name(apply_start_epoch);
            storage
                .rollback_group_to_snapshot(group_id, &anchor_snapshot)
                .map_err(|e| OpenMlsProjectionError::Snapshot(format!("{e:?}")))
                .and_then(|()| {
                    restore_live_message_and_queue_records(
                        storage,
                        &live_message_records,
                        &live_queued_outbound,
                    )
                })
        } else {
            Ok(())
        };
    if let Err(err) = prepare_result {
        rollback_and_release_group_snapshot(storage, group_id, &snapshot)?;
        return Err(err);
    }

    let apply_result =
        apply_openmls_canonicalization_result_inner(storage, group_id, result, &replay_messages);

    match apply_result {
        Ok(observations) => {
            storage
                .release_group_snapshot(group_id, &snapshot)
                .map_err(|e| OpenMlsProjectionError::Snapshot(format!("{e:?}")))?;
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
    for invalidated in &result.invalidated_app_messages {
        state_by_message_id.insert(
            invalidated.message_id.clone(),
            MessageState::EpochInvalidated,
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

fn apply_start_epoch_for_canonicalization_result<S: StorageProvider>(
    storage: &S,
    result: &CanonicalizationResult,
) -> Result<Option<u64>, OpenMlsProjectionError> {
    let Some(first_commit_id) = result.accepted_commits.first() else {
        return Ok(None);
    };
    let message_id = message_id_from_hex(first_commit_id)?;
    let record = storage
        .get_message(&message_id)
        .map_err(|e| OpenMlsProjectionError::Storage(format!("{e:?}")))?;
    Ok(Some(record.epoch.0))
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
) -> Result<Vec<OpenMlsReplayObservation>, OpenMlsProjectionError> {
    let output = process_openmls_messages_inner(storage, group_id, replay_messages)?;
    update_group_record_from_replay(storage, group_id, &output)?;
    persist_openmls_canonicalization_dispositions(storage, result)?;
    Ok(output.observations)
}

fn replay_messages_for_canonicalization_result<S: StorageProvider>(
    storage: &S,
    result: &CanonicalizationResult,
) -> Result<Vec<TransportMessage>, OpenMlsProjectionError> {
    let mut replay_messages = Vec::new();
    let mut seen = BTreeSet::new();
    for hex_message_id in result
        .accepted_proposals
        .iter()
        .chain(&result.accepted_commits)
        .chain(&result.accepted_app_messages)
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
        MessageState::Sent | MessageState::Created | MessageState::Retryable
    )
}

fn record_state_can_contribute_to_openmls_graph(state: MessageState) -> bool {
    record_state_is_canonicalization_input(state) || state == MessageState::Processed
}

fn unresolved_commit_state(state: MessageState) -> bool {
    matches!(
        state,
        MessageState::Sent | MessageState::Created | MessageState::Retryable
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
    let mut proposals = Vec::new();
    let mut applications = Vec::new();
    for message in pending_messages {
        match project_mls_message(&message.payload)?.kind {
            OpenMlsContentKind::Proposal => proposals.push(message.clone()),
            OpenMlsContentKind::Application => applications.push(message.clone()),
            OpenMlsContentKind::Commit
            | OpenMlsContentKind::Welcome
            | OpenMlsContentKind::Other => {}
        }
    }

    Ok(candidate_paths
        .iter()
        .map(|path| {
            let mut seen = BTreeSet::new();
            let mut messages = Vec::new();
            for message in proposals.iter().chain(&path.messages).chain(&applications) {
                if seen.insert(hex::encode(message.id.as_slice())) {
                    messages.push(message.clone());
                }
            }
            OpenMlsCandidatePath {
                branch_id: path.branch_id.clone(),
                messages,
            }
        })
        .collect())
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
) -> Result<OpenMlsReplayOutput, OpenMlsProjectionError> {
    let crypto = RustCrypto::default();
    let provider = EngineOpenMlsProvider::<S>::new(&crypto, storage.mls_storage());
    let mls_group_id = openmls::group::GroupId::from_slice(group_id.as_slice());
    let mut mls_group = MlsGroup::load(provider.storage(), &mls_group_id)
        .map_err(|e| OpenMlsProjectionError::Replay(format!("load: {e:?}")))?
        .ok_or(OpenMlsProjectionError::MissingGroup)?;

    let mut observations = Vec::new();
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
        let processed = match if projection.kind == OpenMlsContentKind::Commit {
            process_commit_with_app_data_updates(&mut mls_group, &provider, protocol)
        } else {
            mls_group.process_message(&provider, protocol)
        } {
            Ok(processed) => processed,
            Err(err) if projection.kind == OpenMlsContentKind::Application => {
                // App-message replay against a candidate state is best-
                // effort: an app message that doesn't decrypt on this
                // branch is just evidence that it belongs to a different
                // branch, not a fatal error. ValidationError covers the
                // expected failure modes (WrongEpoch, decryption fail,
                // sender-membership, etc.). LibraryError or any other
                // structural failure is a real bug — propagate so we
                // don't silently mask malformed input.
                if matches!(err, ProcessMessageError::ValidationError(_)) {
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
        let sender = sender_identity(processed.sender(), &mls_group);
        let sender_id = sender.clone().map(MemberId::new);
        let sender = sender.unwrap_or_default();

        match processed.into_content() {
            ProcessedMessageContent::ProposalMessage(queued) => {
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
                let resulting_epoch = mls_group.epoch().as_u64() + 1;
                let mut consumed_proposal_refs = staged
                    .queued_proposals()
                    .map(|proposal| tls_hex(proposal.proposal_reference_ref()))
                    .collect::<Result<Vec<_>, _>>()?;
                consumed_proposal_refs.sort();
                observations.push(OpenMlsReplayObservation::CommitStaged {
                    message_id,
                    source_epoch,
                    resulting_epoch,
                    consumed_proposal_refs,
                });
                mls_group
                    .merge_staged_commit(&provider, *staged)
                    .map_err(|e| {
                        OpenMlsProjectionError::Replay(format!("merge_staged_commit: {e:?}"))
                    })?;
            }
            ProcessedMessageContent::ApplicationMessage(bytes) => {
                let payload = bytes.into_bytes();
                observations.push(OpenMlsReplayObservation::ApplicationProcessed {
                    message_id,
                    source_epoch,
                    sender,
                    payload: payload.clone(),
                    decrypted_payload_ref: format!(
                        "sha256:{}",
                        hex::encode(message_digest(payload.as_slice()))
                    ),
                });
            }
            ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
                observations.push(OpenMlsReplayObservation::Ignored {
                    message_id,
                    kind: projection.kind,
                });
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

fn process_commit_with_app_data_updates<S: StorageProvider>(
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
    let unverified = mls_group.unprotect_message(provider, proto)?;
    let mut updater = mls_group.app_data_dictionary_updater();
    if let Some(committed_proposals) = unverified.committed_proposals() {
        for proposal_or_ref in committed_proposals {
            let validated = proposal_or_ref.clone().validate(
                provider.crypto(),
                mls_group.ciphersuite(),
                ProtocolVersion::Mls10,
            )?;
            let proposal = match validated {
                ProposalOrRef::Proposal(proposal) => proposal,
                ProposalOrRef::Reference(reference) => mls_group
                    .proposal_store()
                    .proposals()
                    .find(|p| p.proposal_reference_ref() == &*reference)
                    .map(|p| Box::new(p.proposal().clone()))
                    .ok_or(ProcessMessageError::FoundAppDataUpdateProposal)?,
            };
            if let Proposal::AppDataUpdate(update) = proposal.as_ref() {
                match update.operation() {
                    AppDataUpdateOperation::Update(data) => {
                        crate::app_components::validate_app_component_update(&AppComponentData {
                            component_id: update.component_id(),
                            data: data.as_slice().to_vec(),
                        })
                        .map_err(|_| {
                            ProcessMessageError::ValidationError(ValidationError::WrongWireFormat)
                        })?;
                        updater.set(ComponentData::from_parts(
                            update.component_id(),
                            data.clone(),
                        ));
                    }
                    AppDataUpdateOperation::Remove => {
                        crate::app_components::validate_app_component_remove(update.component_id())
                            .map_err(|_| {
                                ProcessMessageError::ValidationError(
                                    ValidationError::WrongWireFormat,
                                )
                            })?;
                        updater.remove(&update.component_id());
                    }
                }
            }
        }
    }
    mls_group.process_unverified_message_with_app_data_updates(
        provider,
        unverified,
        updater.changes(),
    )
}

fn sender_identity(sender: &Sender, group: &MlsGroup) -> Option<Vec<u8>> {
    let Sender::Member(leaf_idx) = sender else {
        return None;
    };
    let member = group.member_at(*leaf_idx)?;
    let basic = BasicCredential::try_from(member.credential).ok()?;
    Some(basic.identity().to_vec())
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
    format!("openmls-retained-probe-{}", hex::encode(&digest[..8]))
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
    format!("openmls-apply-{}", hex::encode(&digest[..8]))
}

fn tls_hex<T: TlsSerialize>(value: &T) -> Result<String, OpenMlsProjectionError> {
    value
        .tls_serialize_detached()
        .map(hex::encode)
        .map_err(|e| OpenMlsProjectionError::Serialize(format!("{e:?}")))
}
