//! Cooperative candidate reconstruction. Scratch progress is memory-only;
//! every return to a caller occurs after restoring the live database state.
use super::*;
use std::collections::VecDeque;
use web_time::Instant;

/// Scheduling allowance, independent of the cumulative anti-amplification budget.
/// A started slice always finishes one probe even if preparation used its time.
pub(crate) struct ReplaySlice {
    deadline: Option<Instant>,
    limit: usize,
    started: usize,
    started_at: Instant,
}

impl ReplaySlice {
    pub(crate) fn new(deadline: Instant, limit: usize) -> Self {
        Self {
            deadline: Some(deadline),
            limit: limit.max(1),
            started: 0,
            started_at: Instant::now(),
        }
    }
    pub(super) fn unlimited() -> Self {
        Self {
            deadline: None,
            limit: usize::MAX,
            started: 0,
            started_at: Instant::now(),
        }
    }
    fn start_probe(&mut self) -> bool {
        if self.started != 0
            && (self.started >= self.limit || self.deadline.is_some_and(|d| Instant::now() >= d))
        {
            return false;
        }
        self.started += 1;
        true
    }
}

pub(super) struct CandidateSearch {
    commits: Vec<StoredCommitMessage>,
    pending_proposals: Vec<TransportMessage>,
    frontier: VecDeque<CandidatePathProbe>,
    active: Option<(CandidatePathProbe, usize, bool)>,
    completed: Vec<CandidatePathProbe>,
    unresolved_commit_ids: BTreeSet<String>,
    invalid_commit_drops: Vec<DroppedMessage>,
    replay_rejected_commit_ids: BTreeSet<String>,
    materialized_commit_ids: BTreeSet<String>,
    seen_paths: BTreeSet<Vec<[u8; 32]>>,
}

impl CandidateSearch {
    pub(super) fn new(
        mut commits: Vec<StoredCommitMessage>,
        pending: &[TransportMessage],
        starting_epoch: u64,
    ) -> Result<Self, OpenMlsProjectionError> {
        commits.sort_by(|a, b| {
            a.source_epoch
                .cmp(&b.source_epoch)
                .then_with(|| a.digest.cmp(&b.digest))
                .then_with(|| a.message.payload.cmp(&b.message.payload))
        });
        let unresolved_commit_ids = commits
            .iter()
            .filter(|c| unresolved_commit_state(c.state))
            .map(|c| c.message.id.to_string())
            .collect();
        Ok(Self {
            commits,
            pending_proposals: pending_proposal_messages(pending)?,
            frontier: VecDeque::from([CandidatePathProbe {
                messages: Vec::new(),
                digests: Vec::new(),
                tip_epoch: starting_epoch,
                materialized: None,
            }]),
            active: None,
            completed: Vec::new(),
            unresolved_commit_ids,
            invalid_commit_drops: Vec::new(),
            replay_rejected_commit_ids: BTreeSet::new(),
            materialized_commit_ids: BTreeSet::new(),
            seen_paths: BTreeSet::from([Vec::new()]),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn advance<S: StorageProvider>(
        &mut self,
        storage: &S,
        group_id: &GroupId,
        own_commits: &PrevalidatedOwnCommits,
        profile_policy: ReplayProfilePolicy,
        budget: &mut ReplayBudget,
        slice: &mut ReplaySlice,
    ) -> Result<bool, OpenMlsProjectionError> {
        loop {
            let Some((path, mut index, mut extended)) = self
                .active
                .take()
                .or_else(|| self.frontier.pop_front().map(|p| (p, 0, false)))
            else {
                return Ok(true);
            };
            while index < self.commits.len() {
                let commit = &self.commits[index];
                if commit.source_epoch != path.tip_epoch || path.digests.contains(&commit.digest) {
                    index += 1;
                    continue;
                }
                let mut digests = path.digests.clone();
                digests.push(commit.digest);
                if self.seen_paths.contains(&digests) {
                    index += 1;
                    continue;
                }
                if !slice.start_probe() {
                    self.active = Some((path, index, extended));
                    return Ok(false);
                }
                index += 1;
                self.seen_paths.insert(digests.clone());
                let mut messages = path.messages.clone();
                messages.push(commit.message.clone());
                let candidate = match probe_candidate_path(
                    storage,
                    group_id,
                    messages.clone(),
                    &digests,
                    &self.pending_proposals,
                    own_commits,
                    budget,
                    profile_policy,
                )? {
                    CandidatePathProbeResult::Materialized(Some(candidate)) => {
                        self.materialized_commit_ids
                            .insert(commit.message.id.to_string());
                        candidate
                    }
                    CandidatePathProbeResult::Materialized(None) => {
                        self.replay_rejected_commit_ids
                            .insert(commit.message.id.to_string());
                        continue;
                    }
                    CandidatePathProbeResult::RejectedProposal {
                        message_id,
                        category,
                    } => {
                        self.invalid_commit_drops.push(DroppedMessage {
                            message_id,
                            kind: MessageKind::Proposal,
                            reason: DroppedMessageReason::InvalidAgainstCandidateState,
                            rejection_category: Some(category),
                        });
                        self.invalid_commit_drops.push(DroppedMessage {
                            message_id: commit.message.id.to_string(),
                            kind: MessageKind::Commit,
                            reason: DroppedMessageReason::InvalidAgainstCandidateState,
                            rejection_category: None,
                        });
                        continue;
                    }
                    CandidatePathProbeResult::UnauthorizedCommit { message_id } => {
                        self.invalid_commit_drops.push(DroppedMessage {
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
                        self.invalid_commit_drops.push(DroppedMessage {
                            message_id,
                            kind: MessageKind::Commit,
                            reason: DroppedMessageReason::InvalidAgainstCandidateState,
                            rejection_category,
                        });
                        continue;
                    }
                };

                extended = true;
                self.frontier.push_back(CandidatePathProbe {
                    messages,
                    digests,
                    tip_epoch: candidate.tip_epoch,
                    materialized: Some(candidate),
                });
            }
            if !path.messages.is_empty() && !extended {
                self.completed.push(path);
            }
        }
    }

    pub(super) fn finish(mut self) -> StoredOpenMlsCandidatePathResult {
        for message_id in self
            .replay_rejected_commit_ids
            .difference(&self.materialized_commit_ids)
        {
            self.invalid_commit_drops.push(DroppedMessage {
                message_id: message_id.clone(),
                kind: MessageKind::Commit,
                reason: DroppedMessageReason::InvalidAgainstCandidateState,
                rejection_category: None,
            });
        }
        let terminal_commit_ids = self
            .invalid_commit_drops
            .iter()
            .filter(|dropped| dropped.kind == MessageKind::Commit)
            .map(|dropped| dropped.message_id.clone())
            .collect::<BTreeSet<_>>();
        let unmaterialized_commit_ids = self
            .unresolved_commit_ids
            .difference(&self.materialized_commit_ids)
            .filter(|message_id| !terminal_commit_ids.contains(*message_id))
            .cloned()
            .collect();

        let mut candidate_paths = Vec::with_capacity(self.completed.len());
        let mut materialized = Vec::with_capacity(self.completed.len());
        for path in self.completed {
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

        StoredOpenMlsCandidatePathResult {
            candidate_paths,
            materialized,
            invalid_commit_drops: self.invalid_commit_drops,
            unmaterialized_commit_ids,
        }
    }
}

/// Exact inputs plus canonical replay-state content when the backend can
/// fingerprint it, otherwise strict mutation-generation equality. New arrivals
/// outside a frozen selection batch do not alter that batch. Backends without
/// generation tracking use the synchronous evaluator.
#[derive(Eq)]
struct ReplaySource {
    graph: StoredOpenMlsGraphInputs,
    group: cgka_traits::group::Group,
    snapshots: Vec<String>,
    write_generation: Option<u64>,
    replay_fingerprint: Option<[u8; 32]>,
}

impl PartialEq for ReplaySource {
    fn eq(&self, other: &Self) -> bool {
        self.graph == other.graph
            && self.group == other.group
            && self.snapshots == other.snapshots
            && match (self.replay_fingerprint, other.replay_fingerprint) {
                (Some(a), Some(b)) => a == b,
                (None, None) => self.write_generation == other.write_generation,
                _ => false,
            }
    }
}

impl ReplaySource {
    fn load<S: StorageProvider>(
        storage: &S,
        group: &GroupId,
        anchor: u64,
        admitted: Option<&[MessageId]>,
    ) -> Result<Self, OpenMlsProjectionError> {
        Ok(Self {
            graph: seed_stored_openmls_graph_inputs(storage, group, anchor, admitted)?,
            group: storage.get_group(group)?,
            snapshots: storage.list_group_snapshots(group)?,
            write_generation: storage.mls_write_generation(),
            replay_fingerprint: storage.group_replay_state_fingerprint(group)?,
        })
    }
}

/// None means the retained anchor is unavailable. The guard is consumed before
/// any Pending result escapes; the inner probe may only have restored an anchor.
fn with_anchor<S: StorageProvider, T>(
    storage: &S,
    group: &GroupId,
    source: &ReplaySource,
    peel: bool,
    f: impl FnOnce() -> Result<T, OpenMlsProjectionError>,
) -> Result<Option<T>, OpenMlsProjectionError> {
    let epoch = source.graph.replay_start_epoch;
    if epoch >= source.graph.current_epoch {
        return f().map(Some);
    }
    let site = if peel {
        RewindSite::CandidateBranchSweep
    } else {
        RewindSite::RetainedAnchorPass
    };
    let guard = crate::snapshot_guard::SnapshotRollbackGuard::create_group_state(
        storage,
        group.clone(),
        site,
        &rewind_probe_snapshot_suffix(group, epoch),
    )?;
    let result = match storage
        .rollback_group_state_to_snapshot(group, &retained_anchor_snapshot_name(epoch))
    {
        Ok(()) => {
            crate::test_crash_hooks::pause_if_requested(if peel {
                "candidate-peel-slice-rewound"
            } else {
                "canonical-replay-slice-rewound"
            });
            f().map(Some)
        }
        Err(StorageError::SnapshotMissing(_)) => Ok(None),
        Err(error) => Err(error.into()),
    };
    guard.commit()?;
    result
}

pub(crate) struct CanonicalReplay {
    source: ReplaySource,
    pass_generation: u64,
    policy: CanonicalizationPolicy,
    profile_policy: ReplayProfilePolicy,
    admit_app_witnesses: bool,
    budget_override: Option<u64>,
    search: Option<CandidateSearch>,
    paths: Option<StoredOpenMlsCandidatePathResult>,
    replay_paths: Vec<OpenMlsCandidatePath>,
    materialized: Vec<OpenMlsMaterializedCandidate>,
    next_path: usize,
    budget: ReplayBudget,
}

#[cfg(test)]
impl CanonicalReplay {
    pub(super) fn completed_probes(&self) -> u64 {
        self.budget.consumed
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn canonicalize_stored_slice<S: StorageProvider>(
    storage: &S,
    group: &GroupId,
    state: CanonicalizationState,
    outbound_intents: Vec<OutboundIntent>,
    policy: CanonicalizationPolicy,
    now_ms: u64,
    options: StoredCanonicalizationOptions<'_>,
    pass_generation: u64,
    slot: &mut Option<CanonicalReplay>,
    slice: &mut ReplaySlice,
) -> Result<Option<CanonicalizationResult>, OpenMlsProjectionError> {
    if storage.mls_write_generation().is_none() {
        *slot = None;
        return canonicalize_stored_openmls_messages_with_profile_policy(
            storage,
            group,
            state,
            outbound_intents,
            policy,
            now_ms,
            options,
        )
        .map(Some);
    }
    let source = ReplaySource::load(
        storage,
        group,
        state.retained_anchor_epoch,
        options.admitted_message_ids,
    )?;
    if let Some(previous) = slot.as_ref() {
        tracing::debug!(
            target: "cgka_engine::replay_slice",
            method = "canonicalize_stored_slice",
            retained_probes = previous.budget.consumed,
            graph_changed = previous.source.graph != source.graph,
            group_changed = previous.source.group != source.group,
            snapshots_changed = previous.source.snapshots != source.snapshots,
            generation_changed = previous.source.write_generation != source.write_generation,
            fingerprint_changed = previous.source.replay_fingerprint != source.replay_fingerprint,
            pass_changed = previous.pass_generation != pass_generation,
            policy_changed = previous.policy != policy,
            "candidate continuation validation"
        );
    }
    let mut work = match slot.take().filter(|w| {
        w.source == source
            && w.pass_generation == pass_generation
            && w.policy == policy
            && w.profile_policy.reject_legacy_group_additions
                == options.replay_profile.reject_legacy_group_additions
            && w.admit_app_witnesses == options.admit_app_witnesses
            && w.budget_override == options.replay_probe_budget_override
    }) {
        Some(work) => work,
        None => CanonicalReplay {
            pass_generation,
            policy: policy.clone(),
            profile_policy: options.replay_profile,
            admit_app_witnesses: options.admit_app_witnesses,
            budget_override: options.replay_probe_budget_override,
            search: Some(CandidateSearch::new(
                source.graph.commit_messages.clone(),
                &source.graph.pending_messages,
                source.graph.replay_start_epoch,
            )?),
            budget: options.replay_probe_budget_override.map_or_else(
                || {
                    ReplayBudget::for_pass(
                        source.graph.commit_messages.len(),
                        policy.convergence.max_rewind_commits,
                    )
                },
                ReplayBudget::new,
            ),
            source,
            paths: None,
            replay_paths: Vec::new(),
            materialized: Vec::new(),
            next_path: 0,
        },
    };
    let result = with_anchor(storage, group, &work.source, false, || {
        if let Some(search) = &mut work.search {
            if !search.advance(
                storage,
                group,
                &work.source.graph.own_commits,
                work.profile_policy,
                &mut work.budget,
                slice,
            )? {
                return Ok(false);
            }
            let mut paths = work.search.take().expect("completed search").finish();
            if can_reuse_bfs_materialization(
                pending_messages_contain_application(&work.source.graph.pending_messages)?,
                paths.materialized.len(),
                paths.candidate_paths.len(),
            ) {
                work.materialized = std::mem::take(&mut paths.materialized);
                work.materialized
                    .sort_by(|a, b| a.branch_id.cmp(&b.branch_id));
            } else {
                work.replay_paths = candidate_paths_with_pending_replay_messages(
                    &paths.candidate_paths,
                    &work.source.graph.pending_messages,
                )?;
            }
            work.paths = Some(paths);
        }
        while work.next_path < work.replay_paths.len() {
            if !slice.start_probe() {
                return Ok(false);
            }
            work.materialized
                .extend(materialize_openmls_candidate_paths_budgeted(
                    storage,
                    group,
                    std::slice::from_ref(&work.replay_paths[work.next_path]),
                    &work.source.graph.own_commits,
                    &mut work.budget,
                    work.profile_policy,
                )?);
            work.next_path += 1;
        }
        Ok(true)
    });
    tracing::debug!(
        target: "cgka_engine::replay_slice",
        method = "canonicalize_stored_slice",
        slice_probes = slice.started as u64,
        total_probes = work.budget.consumed,
        duration_ms = slice.started_at.elapsed().as_millis() as u64,
        complete = matches!(&result, Ok(Some(true))),
        "candidate reconstruction slice restored"
    );
    match result {
        Ok(Some(false)) => {
            work.source.write_generation = storage.mls_write_generation();
            *slot = Some(work);
            crate::test_crash_hooks::pause_if_requested("canonical-replay-slice-restored");
            Ok(None)
        }
        Ok(None) => {
            let mut result =
                missing_retained_anchor_result(state, outbound_intents, policy, now_ms);
            append_dropped_messages(&mut result, work.source.graph.stale_commit_drops);
            Ok(Some(result))
        }
        Err(OpenMlsProjectionError::MissingOwnCommitCheckpoint) if work.search.is_some() => {
            let mut result = missing_required_state_result(
                state,
                outbound_intents,
                policy,
                now_ms,
                CanonicalizationError::MissingOwnCommitCheckpoint,
            );
            append_dropped_messages(&mut result, work.source.graph.stale_commit_drops);
            Ok(Some(result))
        }
        Err(error) => Err(error),
        Ok(Some(true)) => {
            let paths = work.paths.expect("completed candidate search");
            let batch = SharedSeenBatch {
                batch: OpenMlsCanonicalizationBatch {
                    state,
                    candidate_paths: paths.candidate_paths,
                    pending_messages: work.source.graph.pending_messages,
                    already_delivered_app_ids: work.source.graph.already_delivered_app_ids,
                    outbound_intents,
                    policy,
                    now_ms,
                },
                shared_seen_message_ids: options.shared_seen_message_ids,
            };
            let mut result = canonicalize_openmls_batch_with_materialized(
                group,
                batch,
                work.materialized,
                options.admit_app_witnesses,
            )?;
            #[cfg(feature = "test-conformance-snapshot")]
            {
                result.replay_probe_count = work.budget.consumed;
            }
            append_dropped_messages(&mut result, paths.invalid_commit_drops);
            append_missing_parent_deferred_commits(&mut result, paths.unmaterialized_commit_ids);
            append_dropped_messages(&mut result, work.source.graph.stale_commit_drops);
            Ok(Some(result))
        }
    }
}

/// Secret contexts live only in memory and are discarded with invalidated work.
/// No partially ranked context set is ever returned to a caller.
pub(crate) struct PeelReplay {
    source: ReplaySource,
    profile_policy: ReplayProfilePolicy,
    max_rewind: u64,
    max_contexts: usize,
    search: Option<CandidateSearch>,
    ranked: Vec<OpenMlsCandidatePath>,
    pending_proposals: Vec<TransportMessage>,
    contexts: Vec<CandidateBranchPeelContext>,
    next_path: usize,
    budget: ReplayBudget,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn candidate_peel_slice<S: StorageProvider>(
    storage: &S,
    group: &GroupId,
    anchor: u64,
    max_rewind: u64,
    profile_policy: ReplayProfilePolicy,
    max_contexts: usize,
    slot: &mut Option<PeelReplay>,
    slice: &mut ReplaySlice,
) -> Result<Option<CandidateBranchPeel>, CandidateBranchPeelFailure> {
    let fail = |error| CandidateBranchPeelFailure::new(error, 0);
    if storage.mls_write_generation().is_none() {
        *slot = None;
        return candidate_branch_peel(
            storage,
            group,
            anchor,
            max_rewind,
            profile_policy,
            max_contexts,
        )
        .map(Some);
    }
    let source = ReplaySource::load(storage, group, anchor, None).map_err(fail)?;
    if let Some(previous) = slot.as_ref() {
        tracing::debug!(
            target: "cgka_engine::replay_slice",
            method = "candidate_peel_slice",
            retained_probes = previous.budget.consumed,
            graph_changed = previous.source.graph != source.graph,
            group_changed = previous.source.group != source.group,
            snapshots_changed = previous.source.snapshots != source.snapshots,
            generation_changed = previous.source.write_generation != source.write_generation,
            fingerprint_changed = previous.source.replay_fingerprint != source.replay_fingerprint,
            "candidate continuation validation"
        );
    }
    if !commits_share_a_source_epoch(&source.graph.commit_messages) {
        *slot = None;
        return Ok(Some(CandidateBranchPeel::UNCONTESTED));
    }
    let mut work = match slot.take().filter(|w| {
        w.source == source
            && w.max_rewind == max_rewind
            && w.max_contexts == max_contexts
            && w.profile_policy.reject_legacy_group_additions
                == profile_policy.reject_legacy_group_additions
    }) {
        Some(work) => work,
        None => PeelReplay {
            search: Some(
                CandidateSearch::new(
                    source.graph.commit_messages.clone(),
                    &source.graph.pending_messages,
                    source.graph.replay_start_epoch,
                )
                .map_err(fail)?,
            ),
            pending_proposals: pending_proposal_messages(&source.graph.pending_messages)
                .map_err(fail)?,
            budget: ReplayBudget::for_pass(source.graph.commit_messages.len(), max_rewind),
            source,
            profile_policy,
            max_rewind,
            max_contexts,
            ranked: Vec::new(),
            contexts: Vec::new(),
            next_path: 0,
        },
    };
    let result = with_anchor(storage, group, &work.source, true, || {
        if let Some(search) = &mut work.search {
            if !search.advance(
                storage,
                group,
                &work.source.graph.own_commits,
                work.profile_policy,
                &mut work.budget,
                slice,
            )? {
                return Ok(false);
            }
            let paths = work.search.take().expect("completed search").finish();
            if paths.candidate_paths.len() >= 2 {
                work.ranked =
                    candidate_paths_ranked_for_peel(&paths.candidate_paths, &paths.materialized)
                        .into_iter()
                        .take(work.max_contexts)
                        .cloned()
                        .collect();
            }
        }
        while work.next_path < work.ranked.len() {
            if !slice.start_probe() {
                return Ok(false);
            }
            match candidate_path_peel_context(
                storage,
                group,
                &work.ranked[work.next_path],
                &work.pending_proposals,
                &work.source.graph.own_commits,
                work.profile_policy,
                &mut work.budget,
            ) {
                Ok(Some(context)) => work.contexts.push(context),
                Ok(None) => {}
                Err(OpenMlsProjectionError::ReplayBudgetExceeded) => break,
                Err(error) => return Err(error),
            }
            work.next_path += 1;
        }
        Ok(true)
    });
    tracing::debug!(
        target: "cgka_engine::replay_slice",
        method = "candidate_peel_slice",
        slice_probes = slice.started as u64,
        total_probes = work.budget.consumed,
        duration_ms = slice.started_at.elapsed().as_millis() as u64,
        complete = matches!(&result, Ok(Some(true))),
        "candidate reconstruction slice restored"
    );
    match result {
        Ok(Some(false)) => {
            work.source.write_generation = storage.mls_write_generation();
            *slot = Some(work);
            crate::test_crash_hooks::pause_if_requested("candidate-peel-slice-restored");
            Ok(None)
        }
        Ok(Some(true)) => Ok(Some(CandidateBranchPeel::contested_over(
            CandidateBranchPeelEnumeration {
                contexts: work.contexts,
                replay_probe_count: work.budget.consumed,
            },
        ))),
        Ok(None)
        | Err(
            OpenMlsProjectionError::MissingOwnCommitCheckpoint
            | OpenMlsProjectionError::ReplayBudgetExceeded,
        ) => Ok(Some(CandidateBranchPeel::contested_over(
            CandidateBranchPeelEnumeration {
                contexts: Vec::new(),
                replay_probe_count: work.budget.consumed,
            },
        ))),
        Err(error) => Err(CandidateBranchPeelFailure::new(error, work.budget.consumed)),
    }
}
