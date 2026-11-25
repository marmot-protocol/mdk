//! Account-device runtime: drives session effects through transport publish,
//! confirmation, and rollback, and the effect aggregates it produces.

mod group_recovery;
pub use group_recovery::GroupRejoinStatus;

/// Closed timing boundaries; callbacks receive no delivery or identity data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountIngestPhase {
    Engine,
    EffectPublication,
}

use std::collections::{HashMap, HashSet, VecDeque};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use cgka_engine::RollbackPass;
use cgka_traits::AppComponentId;
use cgka_traits::app_components::{DeviceRosterV1, DeviceTagClaim};
use cgka_traits::engine::{
    CreateGroupRequest, GroupEvent, GroupHydrationQuarantineReason, KeyPackage, SendIntent,
    SupersededIntentReport,
};
use cgka_traits::engine_state::PendingStateRef;
use cgka_traits::group::{Group, Member};
use cgka_traits::ingest::IngestOutcome;
use cgka_traits::maintenance::KEY_PACKAGE_GENERATION_REVISION;
use cgka_traits::maintenance::{
    CommitRefusal, DurableGroupEvolution, DurableTransportFanout, GroupEvolutionPhase,
    GroupEvolutionSemantic, GroupMaintenanceStatus, KeyPackageLifecycleState,
    MaintenanceObligation, MaintenancePhase, MaintenanceTrigger, PendingKeyPackageReplacement,
    PeriodicMaintenancePolicy, PostJoinHistoryFetch, PostJoinHistoryFetchCompletion,
    PostJoinHistoryFetchOutcome, RetainedKeyPackagePrivateMaterial, SendMaintenanceDisposition,
    TransportFanoutAttemptState, TransportFanoutTarget,
};
use cgka_traits::storage::{DeviceGroupWelcomeExpectation, RosterTagKey};
use cgka_traits::transport::{TransportEnvelope, TransportMessage};
use cgka_traits::{
    EngineError, EpochId, FanoutAcknowledgement, FanoutMlsState, FanoutPendingKind, GroupId,
    MemberId, MessageState, OutboundApplicationMessage, OutboundFanout, OutboundFanoutOutcome,
    RefusedTarget, StorageError, Timestamp, TransportAccountActivation, TransportAdapter,
    TransportAdapterError, TransportDelivery, TransportDeliveryPlane, TransportEndpoint,
    TransportEndpointAckKind, TransportEndpointFailure, TransportEndpointFailureKind,
    TransportEndpointReceipt, TransportEndpointRejectionCategory, TransportGroupSync,
    TransportPublishReport, TransportPublishRequest, TransportPublishTarget, TransportReadBack,
    WelcomeSizeCheck,
};
use futures::stream::FuturesUnordered;
use futures::{FutureExt, StreamExt};
use marmot_forensics::v5 as audit_v5;
use marmot_forensics::{
    AuditEventContext, AuditEventKind, AuditRecord, AuditTransportWire, ForensicRecorder,
    MessageArtifactKind, PendingCommitChange, PublishRelayFailure, SharedRecorder,
};
use sha2::{Digest, Sha256};

use crate::error::{AccountError, AccountResult};
use crate::key_package::{
    KeyPackagePublication, KeyPackagePublisher, KeyPackageSlotWithdrawal, NoopKeyPackagePublisher,
};
use crate::routing::{
    StaticTransportRouting, TransportRoutingPolicy, publish_target_group_id, publish_target_kind,
    publish_target_relay_urls,
};
use crate::session::{
    AccountDeviceSession, CanonicalGroupMembership, CreateGroupEffects, DetachedWelcomeHolds,
    GroupAuthorityView, HydrationProgress, IngestEffects, KeyPackageMetadata,
    KeyPackageRequirements, PublishWork, QueuedIntentRef, SessionConfig, SessionEffects,
    SessionError, SessionOpenTimings, SessionResult, WelcomeHold, WelcomeWithdrawal,
};
use crate::time::{
    EntropySource, MonotonicClock, OsEntropy, SystemMonotonicClock, SystemWallClock, WallClock,
};

mod device_roster;
pub use device_roster::{DeviceRosterEdit, DeviceRosterEditBlocked, DeviceSelfReport};
mod device_tag_key;
mod maintenance_due;
pub use maintenance_due::MaintenanceDue;
mod own_slot;
pub use own_slot::{ForeignSlotOutcome, ForeignSlotPublication};
mod private_key_packages;
mod removed_device_slot;
mod removed_slot_expiry;
mod sign_in_rejection;
mod slot_announcement;
mod welcome_audit;
mod welcome_delivery;
mod welcome_outcomes;
mod welcome_relays;
mod welcome_routes;
use welcome_audit::{InviteRefusal, V5WelcomePass};
pub use welcome_outcomes::{INVITE_DELIVERY_RETENTION_SECS, WelcomeDeliveryOutcome};
use welcome_relays::{
    RelayPublish, RemainingPass, RemainingWelcomeSends, join_relay_answers, relay_sends, until_met,
};

const TRACE_TARGET: &str = "marmot_session::runtime";
const WELCOME_PUBLISH_CONCURRENCY: usize = 8;
const KEY_PACKAGE_MAX_FUTURE_SKEW_SECS: u64 = 5 * 60;
/// A device republishes its KeyPackage slot at least weekly while it runs, so
/// an inviter can tell a device that still exists from one that was
/// uninstalled (`foundation/key-packages.md`, "Refreshing a slot"). Each
/// refresh falls due a sampled interval after publication, which spreads
/// devices that published together across a day.
const KEY_PACKAGE_REFRESH_MIN_SECS: u64 = 6 * 24 * 60 * 60;
const KEY_PACKAGE_REFRESH_MAX_SECS: u64 = 7 * 24 * 60 * 60;
/// `last_failure_code` of a pending replacement whose signed bytes the
/// publisher refused as unusable.
const KEY_PACKAGE_ARTIFACT_UNUSABLE: &str = "artifact_unusable";
/// The build recorded in
/// [`KeyPackageLifecycleState::unusable_artifact_replaced_by`].
const KEY_PACKAGE_SIGNING_BUILD: &str = env!("CARGO_PKG_VERSION");
const MAINTENANCE_EOSE_TIMEOUT_SECS: u64 = 5 * 60;
const MAINTENANCE_POST_EOSE_GRACE_SECS: u64 = 15;
const MAINTENANCE_QUIET_SECS: u64 = 60;
const PERIODIC_MIN_SECS: u64 = 24 * 24 * 60 * 60;
const PERIODIC_MAX_SECS: u64 = 36 * 24 * 60 * 60;
const COMPONENT_MIGRATION_RECHECK: Duration = Duration::from_secs(10 * 60);
const TRANSPORT_FANOUT_RETENTION_SECS: u64 = 24 * 60 * 60;
/// How long a due self-update waits for the group's previous commit to reach
/// every group relay (mdk#2255). The owed relays keep being retried, backing
/// off to once an hour, so the bound gives an unreachable relay several
/// retries without letting a dead one suppress key rotation.
const COMMIT_DELIVERY_SELF_UPDATE_HOLD_SECS: u64 = 60 * 60;
const FROZEN_FANOUT_AMBIGUOUS_RETRY_BASE_MS: u64 = 30 * 1_000;
const FROZEN_FANOUT_AMBIGUOUS_RETRY_MAX_MS: u64 = 60 * 60 * 1_000;
/// A relay that proved it never accepted the event can be retried promptly:
/// a connection never made, or a retryable answer (`rate-limited:`,
/// `auth-required:`), even though the answer exposes the target (mdk#2332).
/// Keep this aligned with the adapter's fixed reconnect interval so restoring
/// connectivity does not leave a user send behind the ambiguity backoff.
const FROZEN_FANOUT_UNAVAILABLE_RETRY_DELAY_MS: u64 = 5 * 1_000;
/// How long after a pending commit's first send attempt it is only resent
/// (mdk#2332). From then on, each retry of a relay that may hold it reads the
/// commit back from that relay first; one that returns it acknowledges it. A
/// commit that reached no relay is given up from then on, once the device is
/// online (see `AccountDeviceRuntime::abandon_unsent_pending_commit`).
const PENDING_COMMIT_READ_BACK_AFTER_MS: u64 = 10 * 60 * 1_000;
/// How often a pending commit past the bound that reached no relay is read
/// back from its relays to learn whether the device can reach any of them
/// (mdk#2332).
const PENDING_COMMIT_REACHABILITY_READ_INTERVAL_MS: u64 = 60 * 60 * 1_000;

/// Local scheduling windows for own-leaf maintenance rotations.
///
/// These are anti-contention and catch-up delays, not protocol policy. A
/// rotation waits until the group has been free of valid state-bearing input
/// for `quiet`, then a sampled delay of up to `contention_jitter_max` spreads
/// simultaneous rotations apart so freshly joined devices do not all commit in
/// the same second. Production always runs the defaults. Test harnesses that
/// drive [`AccountDeviceRuntime::run_due_maintenance`] explicitly may shorten
/// them through [`AccountDeviceRuntime::with_maintenance_timing`]. Periodic
/// rotation scheduling, its 24 to 36 day cadence and 15 minute jitter, is not
/// covered by this type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaintenanceTiming {
    /// Minimum time a group must stay free of valid commits and proposals
    /// before an obligation may rotate.
    pub quiet: Duration,
    /// Upper bound of the sampled post-quiet delay for post-join and manual
    /// rotations. Persisted deadlines have whole-second granularity.
    pub contention_jitter_max: Duration,
    /// How long a post-join obligation waits for the retained-history
    /// subscription's end-of-stored-events marker before giving up on it.
    pub eose_timeout: Duration,
    /// Grace after end-of-stored-events, or its timeout, before the quiet
    /// window starts.
    pub post_eose_grace: Duration,
}

impl MaintenanceTiming {
    /// Every window zero: a manual or post-join rotation publishes within a
    /// few consecutive maintenance sweeps. For harnesses that call
    /// `run_due_maintenance` directly, never for production runtimes.
    pub const fn immediate() -> Self {
        Self {
            quiet: Duration::ZERO,
            contention_jitter_max: Duration::ZERO,
            eose_timeout: Duration::ZERO,
            post_eose_grace: Duration::ZERO,
        }
    }

    fn contention_jitter_max_ms(self) -> u64 {
        u64::try_from(self.contention_jitter_max.as_millis()).unwrap_or(u64::MAX)
    }
}

impl Default for MaintenanceTiming {
    fn default() -> Self {
        Self {
            quiet: Duration::from_secs(MAINTENANCE_QUIET_SECS),
            contention_jitter_max: Duration::from_millis(
                cgka_traits::maintenance::POST_JOIN_CONTENTION_JITTER_MAX_MS,
            ),
            eose_timeout: Duration::from_secs(MAINTENANCE_EOSE_TIMEOUT_SECS),
            post_eose_grace: Duration::from_secs(MAINTENANCE_POST_EOSE_GRACE_SECS),
        }
    }
}

fn saturating_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct PublishStatus {
    met_required_acks: bool,
    accepted_by_any_endpoint: bool,
    possible_ambiguous_exposure: bool,
    retry_deferred: bool,
    terminal_failure: bool,
    /// The Welcome was withdrawn or retired, so nothing was published and
    /// nothing is owed.
    withdrawn: bool,
    /// The Welcome is staged with its unconfirmed commit, so nothing was
    /// published and nothing is recorded or owed yet.
    awaits_commit: bool,
}

impl PublishStatus {
    /// Whether the publish staged no fanout: nothing accepted, nothing
    /// refused for good, and nothing left to retry. A staged fanout always
    /// ends in one of those.
    fn staged_nothing(&self) -> bool {
        !self.accepted_by_any_endpoint && !self.terminal_failure && !self.retry_deferred
    }
}

/// Who asked for a send: the host, for a group change (mdk#2332), or anything
/// else, whose commits name no host change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SendOrigin {
    Host,
    Automatic,
}

struct PendingFanoutContinuation {
    pending: PendingStateRef,
    kind: FanoutPendingKind,
    post_confirmation_welcomes: Vec<TransportMessage>,
}

enum PreparedLegacyPublish {
    Complete(PublishStatus),
    Network(Box<PreparedLegacyPublishAttempt>),
}

enum LegacyPublishCompletion {
    Complete(PublishStatus),
    Network(
        Box<PreparedLegacyPublishAttempt>,
        Result<TransportPublishReport, TransportAdapterError>,
    ),
    /// What the relays a settled pass left answering said since.
    Remaining(Box<RemainingPass>),
}

struct PreparedLegacyPublishAttempt {
    message_id: cgka_traits::MessageId,
    msg_id_hex: String,
    v5_welcome: Option<V5WelcomePass>,
    wire: AuditTransportWire,
    artifact_kind: Option<MessageArtifactKind>,
    publish_context: AuditEventContext,
    fanout: DurableTransportFanout,
    retry_endpoints: Vec<TransportEndpoint>,
    accepted_before: usize,
    required_acks: usize,
    target_kind: String,
    relay_urls: Vec<String>,
    /// The group its audit rows name: the target's, or a Welcome's own.
    audit_group_id: Option<GroupId>,
    defers_remaining_fanout_until_confirmation: bool,
    /// A device link's Welcome's delivery deadline: a batch does not start
    /// the attempt from then on.
    deliver_until: Option<Timestamp>,
    request: TransportPublishRequest,
}

struct WelcomePublishMetadata {
    recipient: Option<MemberId>,
    welcome_id: cgka_traits::MessageId,
    /// The group this Welcome joins, when its wave knows it.
    group_id: Option<GroupId>,
    effects: AccountDeviceEffects,
}

struct PreparedWelcomePublish {
    group_id: Option<GroupId>,
    metadata: Vec<WelcomePublishMetadata>,
    completions: Vec<Option<LegacyPublishCompletion>>,
    pending: VecDeque<(usize, Box<PreparedLegacyPublishAttempt>)>,
    /// Records each attempt's start, when its relay I/O begins.
    audit: SharedRecorder,
}

struct CompletedWelcomePublish {
    group_id: Option<GroupId>,
    metadata: Vec<WelcomePublishMetadata>,
    completions: Vec<Option<LegacyPublishCompletion>>,
    /// Records the finished row of a pass whose results are dropped.
    audit: SharedRecorder,
}

/// Relay-only half of a prepared Welcome retry.
///
/// The account worker may run this task independently of its serialized
/// engine/SQLite owner. Preparation has already retained the exact event and
/// endpoint snapshot; [`AccountDeviceRuntime::finish_welcome_publish_task`]
/// must reconcile the returned completion before another retry is started.
#[doc(hidden)]
#[must_use = "a prepared Welcome publish task must be run and reconciled"]
pub struct PreparedWelcomePublishTask {
    message_ids: Vec<cgka_traits::MessageId>,
    run: WelcomeTaskRun,
}

enum WelcomeTaskRun {
    /// A wave's passes, each started once its hold allows.
    Wave {
        adapter: Arc<dyn TransportAdapter>,
        wall_clock: Arc<dyn WallClock>,
        prepared: PreparedWelcomePublish,
        holds: DetachedWelcomeHolds,
        selection: Arc<futures::lock::Mutex<()>>,
    },
    /// The relays a wave's passes left answering
    /// ([`CompletedWelcomePublishTask::take_remaining`]).
    Remaining(RemainingWelcomeSends<'static>),
}

/// Opaque relay results from [`PreparedWelcomePublishTask::run`].
#[doc(hidden)]
pub struct CompletedWelcomePublishTask {
    completed: CompletedWelcomePublish,
    message_ids: Vec<cgka_traits::MessageId>,
    remaining: Option<RemainingWelcomeSends<'static>>,
}

impl CompletedWelcomePublishTask {
    /// The relays this task's passes were still waiting on when each pass
    /// had met its Welcome's policy, as a task of their own that keeps
    /// asking them. Their Welcomes' reservations go with it, so this task's
    /// finish settles each pass at once, and the returned task's finish, or
    /// its abandonment, releases them. Left untaken, they stop when this task
    /// is finished, and maintenance retries them after their backoff.
    pub fn take_remaining(&mut self) -> Option<PreparedWelcomePublishTask> {
        let remaining = self.remaining.take()?;
        let message_ids = remaining.message_ids();
        self.message_ids.retain(|id| !message_ids.contains(id));
        Some(PreparedWelcomePublishTask {
            message_ids,
            run: WelcomeTaskRun::Remaining(remaining),
        })
    }

    /// Drop the results of every Welcome whose group `gone` names, so that
    /// finishing this task changes nothing of a group the host left or
    /// deleted while the task ran. Their records stay as preparation left
    /// them, as an abandoned task leaves them; finishing still releases every
    /// reservation. A dropped pass that reached relays still records its
    /// finished audit row from the answers it got. Returns how many results
    /// were dropped.
    pub fn drop_gone_groups(&mut self, gone: impl Fn(&GroupId) -> bool) -> usize {
        let completed = &mut self.completed;
        let before = completed.metadata.len();
        let audit = &completed.audit;
        let (metadata, completions) = std::mem::take(&mut completed.metadata)
            .into_iter()
            .zip(std::mem::take(&mut completed.completions))
            .filter(|(metadata, completion)| {
                if !metadata.group_id.as_ref().is_some_and(&gone) {
                    return true;
                }
                if let Some(completion) = completion {
                    record_dropped_completion(audit, completion);
                }
                false
            })
            .unzip();
        completed.metadata = metadata;
        completed.completions = completions;
        before - completed.metadata.len()
    }
}

/// The finished row of a pass that reached relays and whose results are
/// dropped unreconciled.
fn record_dropped_completion(audit: &SharedRecorder, completion: &LegacyPublishCompletion) {
    match completion {
        LegacyPublishCompletion::Network(attempt, result) => {
            if let Some(pass) = &attempt.v5_welcome {
                pass.record_dropped(
                    audit,
                    result,
                    &attempt.retry_endpoints,
                    attempt.required_acks,
                );
            }
        }
        LegacyPublishCompletion::Remaining(pass) => pass.record_dropped(audit),
        LegacyPublishCompletion::Complete(_) => {}
    }
}

impl PreparedWelcomePublishTask {
    /// Exact message ids reserved by this task while relay I/O is in flight.
    pub fn message_ids(&self) -> &[cgka_traits::MessageId] {
        &self.message_ids
    }

    /// Run only the bounded relay publication phase. This owns no engine or
    /// SQLite state and is therefore safe to poll beside the account worker.
    /// A wave returns once each of its passes is done; the relays a pass was
    /// still waiting on are left in the result
    /// ([`CompletedWelcomePublishTask::take_remaining`]), still asking.
    pub async fn run(self) -> CompletedWelcomePublishTask {
        match self.run {
            WelcomeTaskRun::Wave {
                adapter,
                wall_clock,
                prepared,
                holds,
                selection,
            } => {
                // Each relay request owns the adapter, so a relay still
                // answering can outlive this wave.
                let send = move |request| -> RelayPublish<'static> {
                    let adapter = adapter.clone();
                    async move { adapter.publish(request).await }.boxed()
                };
                let (completed, mut remaining) = prepared
                    .publish(&send, wall_clock.as_ref(), Some(&holds), Some(&selection))
                    .await;
                if let Some(remaining) = remaining.as_mut() {
                    remaining.start();
                }
                CompletedWelcomePublishTask {
                    completed,
                    message_ids: self.message_ids,
                    remaining,
                }
            }
            WelcomeTaskRun::Remaining(remaining) => CompletedWelcomePublishTask {
                completed: remaining.run().await,
                message_ids: self.message_ids,
                remaining: None,
            },
        }
    }
}

impl PreparedWelcomePublish {
    fn network_message_ids(&self) -> Vec<cgka_traits::MessageId> {
        self.pending
            .iter()
            .map(|(_, attempt)| attempt.message_id.clone())
            .collect()
    }

    /// Check the owner's current hold before starting each queued attempt.
    /// Already-started relay I/O still completes under its original contract.
    ///
    /// Each attempt asks its relays through `send`, one request per relay when
    /// it has more than its goal (`relay_sends`), and is done once their
    /// answers meet its goal or all have answered. A relay that answers while
    /// the wave still runs joins its pass. The relays still answering once
    /// every pass is done are returned, still asking.
    async fn publish<'a, S>(
        mut self,
        send: &S,
        wall_clock: &dyn WallClock,
        holds: Option<&DetachedWelcomeHolds>,
        selection: Option<&Arc<futures::lock::Mutex<()>>>,
    ) -> (CompletedWelcomePublish, Option<RemainingWelcomeSends<'a>>)
    where
        S: Fn(TransportPublishRequest) -> RelayPublish<'a> + Sync,
    {
        let audit = &self.audit;
        let publish = |index, mut attempt: Box<PreparedLegacyPublishAttempt>| async move {
            let mut selection = match selection {
                Some(selection) => Some(selection.lock().await),
                None => None,
            };
            let mut publishing: Option<futures::future::BoxFuture<'_, _>> = None;
            let result = futures::future::poll_fn(|cx| {
                if let Some(publishing) = publishing.as_mut() {
                    return publishing.poll_unpin(cx).map(Ok);
                }
                // Keep the permit locked through the adapter's first poll:
                // native selection cannot revoke it between check and start.
                let holds =
                    holds.map(|holds| holds.lock().unwrap_or_else(|error| error.into_inner()));
                let hold = if attempt
                    .deliver_until
                    .is_some_and(|deliver_until| wall_clock.now() >= deliver_until)
                {
                    Some(WelcomeHold::Expired)
                } else {
                    holds
                        .as_ref()
                        .and_then(|holds| holds.get(&attempt.message_id).copied().flatten())
                };
                if let Some(hold) = hold {
                    return std::task::Poll::Ready(Err(hold));
                }
                if let Some(pass) = attempt.v5_welcome.as_mut() {
                    pass.start(audit);
                }
                let mut future = until_met(
                    relay_sends(send, &attempt.request),
                    attempt.request.required_acks,
                )
                .boxed();
                let result = future.poll_unpin(cx).map(Ok);
                publishing = Some(future);
                drop(selection.take());
                result
            })
            .await;
            (index, attempt, result)
        };
        let mut in_flight = FuturesUnordered::new();
        while in_flight.len() < WELCOME_PUBLISH_CONCURRENCY {
            let Some((index, attempt)) = self.pending.pop_front() else {
                break;
            };
            in_flight.push(publish(index, attempt));
        }
        // Each done pass, by index, with its answers so far, and the answers
        // still to come from the relays a done pass was waiting on.
        let mut done: Vec<(usize, Box<PreparedLegacyPublishAttempt>, Vec<_>)> = Vec::new();
        let mut late = FuturesUnordered::new();
        while !in_flight.is_empty() {
            let next = futures::future::poll_fn(|cx| {
                if let std::task::Poll::Ready(Some(answer)) = late.poll_next_unpin(cx) {
                    return std::task::Poll::Ready(Err(answer));
                }
                in_flight.poll_next_unpin(cx).map(Ok)
            })
            .await;
            let (index, attempt, result) = match next {
                Ok(Some(started)) => started,
                Ok(None) => break,
                Err((index, answer)) => {
                    if let Some((_, _, answers)) = done.iter_mut().find(|done| done.0 == index) {
                        answers.push(answer);
                    }
                    continue;
                }
            };
            match result {
                Ok((answers, sends)) => {
                    for send in sends {
                        late.push(async move { (index, send.await) }.boxed());
                    }
                    done.push((index, attempt, answers));
                }
                Err(WelcomeHold::AwaitsCommit) => {
                    self.completions[index] =
                        Some(LegacyPublishCompletion::Complete(PublishStatus {
                            awaits_commit: true,
                            ..PublishStatus::default()
                        }));
                }
                Err(_) => {
                    self.completions[index] =
                        Some(LegacyPublishCompletion::Complete(PublishStatus {
                            withdrawn: true,
                            ..PublishStatus::default()
                        }));
                }
            }
            if let Some((next_index, next_attempt)) = self.pending.pop_front() {
                in_flight.push(publish(next_index, next_attempt));
            }
        }

        let mut remaining =
            RemainingWelcomeSends::new(late, self.group_id.clone(), self.audit.clone());
        for (index, attempt, answers) in done {
            remaining.push(
                index,
                &attempt,
                self.metadata[index].group_id.clone(),
                &answers,
            );
            let result = join_relay_answers(&attempt.request, answers);
            self.completions[index] = Some(LegacyPublishCompletion::Network(attempt, result));
        }

        (
            CompletedWelcomePublish {
                group_id: self.group_id,
                metadata: self.metadata,
                completions: self.completions,
                audit: self.audit.clone(),
            },
            (!remaining.is_empty()).then_some(remaining),
        )
    }
}

/// A locally staged commit whose transport publication has not started.
///
/// Keeping the pending handle beside the extracted Welcomes lets callers
/// either publish the commit after durable Welcome-intent persistence or roll
/// the staged MLS change back while external exposure is still impossible.
#[must_use = "a prepared commit must be published or rolled back; dropping it strands the staged MLS commit"]
pub struct PreparedSessionCommit {
    effects: SessionEffects,
    welcomes: Vec<TransportMessage>,
    pending: PendingStateRef,
}

/// Result of accepting an intent at the pre-publication boundary.
///
/// Convergence may durably queue an invite without staging an MLS commit. That
/// is successful `AcceptedPending` work, not a malformed prepared commit.
pub enum PreparedSessionSend {
    Commit(PreparedSessionCommit),
    Queued(SessionEffects),
    /// The invite's commit fit none of its group relays' known size limits, or
    /// one of its Welcomes fit none of its invitee's inbox relays' (mdk#2334).
    /// It was rolled back with nothing sent; the effects carry its rollback and
    /// one [`PublishFailure`] naming the oversized artifact.
    Refused(Box<AccountDeviceEffects>),
}

impl PreparedSessionCommit {
    pub fn welcomes(&self) -> &[TransportMessage] {
        &self.welcomes
    }

    pub fn into_effects_and_welcomes(self) -> (SessionEffects, Vec<TransportMessage>) {
        (self.effects, self.welcomes)
    }

    fn into_parts(self) -> (SessionEffects, Vec<TransportMessage>, PendingStateRef) {
        (self.effects, self.welcomes, self.pending)
    }
}

/// Neutral deltas since the last drain. Durable state loads are never transitions.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MaintenanceActivity {
    /// Bounded neutral execution samples; counters remain complete on overflow.
    pub attempt_durations: Vec<MaintenanceAttemptDuration>,
    pub retired_key_packages: u64,
    pub self_update_attempts: u64,
    pub key_package_attempts: u64,
    pub key_package_failed_attempts: u64,
    pub failed_attempts: u64,
    pub completed_transitions: u64,
    pub deferred_transitions: u64,
    pub failed_transitions: u64,
}
/// One actual scheduler execution, without any account or obligation identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaintenanceAttemptDuration {
    pub key_package: bool,
    pub failed: bool,
    pub duration: std::time::Duration,
}
impl MaintenanceActivity {
    /// Merge neutral execution deltas without wrapping counters.
    pub fn absorb(&mut self, previous: Self) {
        let remaining = 256usize.saturating_sub(self.attempt_durations.len());
        self.attempt_durations
            .extend(previous.attempt_durations.into_iter().take(remaining));
        self.retired_key_packages = self
            .retired_key_packages
            .saturating_add(previous.retired_key_packages);
        self.self_update_attempts = self
            .self_update_attempts
            .saturating_add(previous.self_update_attempts);
        self.key_package_attempts = self
            .key_package_attempts
            .saturating_add(previous.key_package_attempts);
        self.key_package_failed_attempts = self
            .key_package_failed_attempts
            .saturating_add(previous.key_package_failed_attempts);
        self.failed_attempts = self
            .failed_attempts
            .saturating_add(previous.failed_attempts);
        self.completed_transitions = self
            .completed_transitions
            .saturating_add(previous.completed_transitions);
        self.deferred_transitions = self
            .deferred_transitions
            .saturating_add(previous.deferred_transitions);
        self.failed_transitions = self
            .failed_transitions
            .saturating_add(previous.failed_transitions);
    }
}
type PublicationProgressObserver =
    Arc<dyn Fn(GroupAuthorityView<'_>, &PublishedApplicationMessage) + Send + Sync>;
type SecondaryRetryYield = futures::future::Shared<futures::future::BoxFuture<'static, ()>>;
#[derive(Clone)]
struct PublicationProgress {
    observe: PublicationProgressObserver,
    secondary_retry_yield: SecondaryRetryYield,
}
type PublicationProgressSlot = Arc<std::sync::Mutex<Option<PublicationProgress>>>;

/// Restore the previous observer even when the owning convergence future is dropped.
struct PublicationProgressGuard {
    slot: PublicationProgressSlot,
    previous: Option<PublicationProgress>,
}

impl Drop for PublicationProgressGuard {
    fn drop(&mut self) {
        *self.slot.lock().unwrap_or_else(|error| error.into_inner()) = self.previous.take();
    }
}

pub struct AccountDeviceRuntime<A, R = StaticTransportRouting, K = NoopKeyPackagePublisher> {
    session: AccountDeviceSession,
    /// This runtime's clone of the session's audit recorder.
    audit: SharedRecorder,
    adapter: A,
    routing: R,
    key_packages: K,
    wall_clock: Arc<dyn WallClock>,
    monotonic_clock: Arc<dyn MonotonicClock>,
    entropy: Arc<dyn EntropySource>,
    maintenance_timing: MaintenanceTiming,
    maintenance_paused: bool,
    /// This runtime was asked to withdraw the device's slot for sign-out, so
    /// it publishes nothing more, whether or not a relay accepted. The next
    /// runtime for the account republishes.
    key_package_slot_withdrawn: bool,
    /// The device group this device announces its KeyPackages in before it
    /// publishes them (mdk#2628 3.4). The host sets it; `None` publishes as
    /// a device with no device group does.
    key_package_announcement_group: Option<GroupId>,
    /// Every publication of this device's own at or before this time is to
    /// be replaced: the slot served a newer one it did not make (mdk#2628
    /// 3.4). See `runtime/own_slot.rs`.
    slot_superseded_through: Option<Timestamp>,
    /// What this device says about itself in its roster entry there (mdk#2628
    /// 3.6); every announcement writes it too.
    device_self_report: DeviceSelfReport,
    /// The device group this device tags its KeyPackages and leaves from
    /// (mdk#2628 3.1d), as the host last named it to the engine.
    device_tag_group: Option<GroupId>,
    maintenance_activity: std::sync::Mutex<MaintenanceActivity>,
    maintenance_quiet_monotonic: HashMap<cgka_traits::MessageId, Duration>,
    /// Monotonic time each group's own-leaf currency was last read from the
    /// engine. It changes only with an own commit or a new build, so the
    /// per-tick sweep reads it at most every [`COMPONENT_MIGRATION_RECHECK`]
    /// unless a stored due time arrived.
    component_migration_checked_at: HashMap<GroupId, Duration>,
    /// Secondary maintenance writes must not discard committed session effects.
    /// Keep their group-scoped reconciliation owned until a quiet retry succeeds.
    pending_leaf_reconciliations: HashMap<GroupId, Option<Timestamp>>,
    /// The publish handle detached waves run on, while the host runs every
    /// Welcome wave itself (`set_detached_welcome_waves`).
    detached_welcome_adapter: Option<Arc<dyn TransportAdapter>>,
    /// Waves prepared while detached, reserved and waiting for the host to
    /// take them (`take_prepared_welcome_tasks`).
    prepared_welcome_tasks: Vec<PreparedWelcomePublishTask>,
    /// Outbound Welcomes, staged or owed, that no attempt record holds yet,
    /// in the order this runtime met them. Maintenance publishes each once it
    /// is owed (see `welcome_delivery`).
    watched_welcomes: Vec<cgka_traits::MessageId>,
    /// Retained Welcomes this process noted, each read once
    /// ([`Self::note_retained_welcomes`]).
    v5_prepared_welcomes: HashSet<cgka_traits::MessageId>,
    /// Welcomes whose withdrawal `withdraw_welcome` recorded, so the
    /// watcher does not record it again.
    v5_withdrawn_welcomes: std::sync::Mutex<HashSet<cgka_traits::MessageId>>,
    /// The `(group, recipient)` pairs whose Welcome delivery state changed
    /// and that no host has taken yet (`take_welcome_delivery_changes`).
    welcome_delivery_changes: std::sync::Mutex<Vec<(GroupId, MemberId)>>,
    /// Recipients whose last Welcome publish found no inbox route, paced so
    /// maintenance does not prepare their Welcomes on every pass (see
    /// `welcome_routes`).
    welcome_route_retries: std::sync::Mutex<welcome_routes::WelcomeRouteRetries>,
    /// Whether the store has been read for `watched_welcomes`: the startup
    /// pass reads it, or else the first maintenance pass.
    welcome_store_read: bool,
    /// Groups that read skipped because they were not live. Maintenance
    /// reads each once it is.
    unread_welcome_groups: Vec<GroupId>,
    /// Test-only fault injection: while armed, the finish stage of a prepared
    /// legacy publish for this message id fails with a transient storage
    /// error. Never set by production code.
    finish_stage_failure: Option<cgka_traits::MessageId>,
    publication_progress: PublicationProgressSlot,
    recovery_turn: Vec<storage_sqlite::GroupRecoveryRecord>,
}

impl<A, R, K> AccountDeviceRuntime<A, R, K>
where
    A: TransportAdapter,
    R: TransportRoutingPolicy,
    K: KeyPackagePublisher,
{
    /// Open the account-device session from `config`, then build the
    /// transport half with `transport`, which runs only once the session is
    /// open, and drive the session over it. This is the only production way
    /// in: the host reaches the session through this runtime's methods.
    ///
    /// The session opens first because a host's transport can have effects
    /// when it is built, such as registering the account's delivery route; a
    /// failed open must not leave them behind.
    pub fn open<E>(
        config: SessionConfig,
        transport: impl FnOnce() -> Result<(A, R, K), E>,
    ) -> Result<Self, E>
    where
        E: From<SessionError>,
    {
        let session = AccountDeviceSession::open(config)?;
        let (adapter, routing, key_packages) = transport()?;
        Ok(Self::with_session(session, adapter, routing, key_packages))
    }

    /// Drive a session the caller opened. Tests open the session themselves
    /// to set up scenarios.
    #[cfg(any(test, feature = "test-support"))]
    pub fn new(session: AccountDeviceSession, adapter: A, routing: R, key_packages: K) -> Self {
        Self::with_session(session, adapter, routing, key_packages)
    }

    fn with_session(
        session: AccountDeviceSession,
        adapter: A,
        routing: R,
        key_packages: K,
    ) -> Self {
        Self {
            audit: session.audit_recorder().clone(),
            session,
            adapter,
            routing,
            key_packages,
            wall_clock: Arc::new(SystemWallClock),
            monotonic_clock: Arc::new(SystemMonotonicClock::default()),
            entropy: Arc::new(OsEntropy),
            maintenance_timing: MaintenanceTiming::default(),
            maintenance_paused: false,
            key_package_slot_withdrawn: false,
            key_package_announcement_group: None,
            slot_superseded_through: None,
            device_self_report: DeviceSelfReport::default(),
            device_tag_group: None,
            maintenance_activity: std::sync::Mutex::new(MaintenanceActivity::default()),
            maintenance_quiet_monotonic: HashMap::new(),
            component_migration_checked_at: HashMap::new(),
            pending_leaf_reconciliations: HashMap::new(),
            detached_welcome_adapter: None,
            prepared_welcome_tasks: Vec::new(),
            watched_welcomes: Vec::new(),
            v5_prepared_welcomes: HashSet::new(),
            v5_withdrawn_welcomes: std::sync::Mutex::new(HashSet::new()),
            welcome_delivery_changes: std::sync::Mutex::new(Vec::new()),
            welcome_route_retries: std::sync::Mutex::default(),
            welcome_store_read: false,
            unread_welcome_groups: Vec::new(),
            finish_stage_failure: None,
            publication_progress: Arc::new(std::sync::Mutex::new(None)),
            recovery_turn: Vec::new(),
        }
    }

    /// Test-only hook: arm a one-message finish-stage failure so tests can
    /// exercise reconciliation of already-exposed publishes. Not a production
    /// entry point; hidden from the public API docs.
    #[doc(hidden)]
    pub fn arm_finish_stage_failure(&mut self, message_id: cgka_traits::MessageId) {
        self.finish_stage_failure = Some(message_id);
    }

    pub fn with_maintenance_sources(
        mut self,
        wall_clock: Arc<dyn WallClock>,
        monotonic_clock: Arc<dyn MonotonicClock>,
        entropy: Arc<dyn EntropySource>,
    ) -> Self {
        self.wall_clock = wall_clock;
        self.monotonic_clock = monotonic_clock;
        self.entropy = entropy;
        self
    }

    /// Replace the monotonic clock in place, for tests that drive a worker
    /// which owns its runtime.
    #[cfg(any(test, feature = "test-support"))]
    pub fn set_monotonic_clock_for_test(&mut self, monotonic_clock: Arc<dyn MonotonicClock>) {
        self.monotonic_clock = monotonic_clock;
    }

    /// Replace the maintenance scheduling windows. Production runtimes keep
    /// [`MaintenanceTiming::default`]; this exists for test harnesses only.
    pub fn with_maintenance_timing(mut self, timing: MaintenanceTiming) -> Self {
        self.maintenance_timing = timing;
        self
    }

    pub fn maintenance_timing(&self) -> MaintenanceTiming {
        self.maintenance_timing
    }

    /// The session itself, for tests that drive it directly.
    #[cfg(any(test, feature = "test-support"))]
    pub fn session(&self) -> &AccountDeviceSession {
        &self.session
    }

    /// The session itself, for tests that drive it directly.
    #[cfg(any(test, feature = "test-support"))]
    pub fn session_mut(&mut self) -> &mut AccountDeviceSession {
        &mut self.session
    }

    /// The account-device's audit recorder. A host takes its own clone to
    /// record, rotate and finish the log without going through this runtime.
    pub fn audit_recorder(&self) -> &SharedRecorder {
        &self.audit
    }

    fn record_audit_event(
        &self,
        group_id: Option<&GroupId>,
        context: Option<AuditEventContext>,
        kind: AuditEventKind,
    ) {
        let mut record = AuditRecord::new(
            group_id.map(|group_id| hex::encode(group_id.as_slice())),
            kind,
        );
        record.context = context;
        self.audit.record(record);
    }

    /// Audit how one of this account's pending commits changed (mdk#3460):
    /// the commit by its message id, and how long since its first send
    /// attempt.
    fn record_pending_commit_change(
        &self,
        fanout: &OutboundFanout,
        context: Option<AuditEventContext>,
        change: PendingCommitChange,
        now_ms: u64,
    ) {
        let pending_secs = fanout
            .first_attempt_at_ms()
            .map_or(0, |first| now_ms.saturating_sub(first) / 1_000);
        self.record_audit_event(
            fanout.group_id(),
            context,
            AuditEventKind::PendingCommitChanged {
                change,
                msg_id: hex::encode(fanout.message_id().as_slice()),
                pending_secs,
            },
        );
    }

    /// Abandon a group locally without sending a leave or disband.
    pub fn forget_group_local(&mut self, group_id: &GroupId) -> AccountResult<bool> {
        let forgotten = self.session.forget_group_local(group_id)?;
        self.pending_leaf_reconciliations.remove(group_id);
        Ok(forgotten)
    }

    pub fn group_record(&self, group_id: &GroupId) -> AccountResult<Group> {
        Ok(self.session.group_record(group_id)?)
    }

    /// Undecryptable objects retained while stuck at the group's current
    /// epoch; see `Engine::deferred_stall_evidence`.
    pub fn deferred_stall_evidence(
        &mut self,
        group_id: &GroupId,
        limit: usize,
    ) -> AccountResult<cgka_traits::DeferredStallEvidence> {
        Ok(self.session.deferred_stall_evidence(group_id, limit)?)
    }

    /// Undecryptable objects retained since `min_epoch` up to the group's
    /// current epoch; see `Engine::deferred_stall_evidence_since`.
    pub fn deferred_stall_evidence_since(
        &mut self,
        group_id: &GroupId,
        min_epoch: EpochId,
        limit: usize,
    ) -> AccountResult<cgka_traits::DeferredStallEvidence> {
        Ok(self
            .session
            .deferred_stall_evidence_since(group_id, min_epoch, limit)?)
    }

    pub fn epoch_state(&self, group_id: &GroupId) -> Option<cgka_traits::EpochState> {
        self.session.epoch_state(group_id)
    }

    pub fn disband_request(
        &self,
        group_id: &GroupId,
    ) -> AccountResult<Option<cgka_traits::DisbandRequest>> {
        Ok(self.session.disband_request(group_id)?)
    }

    pub fn disbanding_in_progress(&self, group_id: &GroupId) -> AccountResult<bool> {
        Ok(self.session.disbanding_in_progress(group_id)?)
    }

    pub fn disbanding_support_blockers(&self, group_id: &GroupId) -> AccountResult<Vec<MemberId>> {
        Ok(self.session.disbanding_support_blockers(group_id)?)
    }

    /// Why this device cannot turn on `marmot.group.account-devices.v1` in
    /// `group_id` now, or `None` when it can. The send intent repeats the
    /// check when its Commit is prepared.
    pub fn account_devices_activation_refusal(
        &self,
        group_id: &GroupId,
    ) -> AccountResult<Option<cgka_traits::error::AccountDevicesActivationRefusal>> {
        Ok(self.session.account_devices_activation_refusal(group_id)?)
    }

    /// Why a same-account Add of `sibling` to `group_id` would be refused
    /// now, or `None`, without spending its KeyPackage. The send repeats the
    /// checks. See [`cgka_engine::engine::Engine::sibling_add_refusal`].
    pub fn sibling_add_refusal(
        &self,
        group_id: &GroupId,
        sibling: &cgka_traits::engine::SiblingKeyPackage,
    ) -> AccountResult<Option<cgka_traits::error::SiblingAddRefusal>> {
        Ok(self.session.sibling_add_refusal(group_id, sibling)?)
    }

    /// Why `group_id` takes no same-account Add of any sibling now, or
    /// `None`. See [`cgka_engine::engine::Engine::chat_sibling_add_refusal`].
    pub fn chat_sibling_add_refusal(
        &self,
        group_id: &GroupId,
    ) -> AccountResult<Option<cgka_traits::error::SiblingAddRefusal>> {
        Ok(self.session.chat_sibling_add_refusal(group_id)?)
    }

    pub fn acknowledge_disband_failure(&self, group_id: &GroupId) -> AccountResult<bool> {
        Ok(self.session.acknowledge_disband_failure(group_id)?)
    }

    pub fn new_protocol_profile(&self) -> cgka_traits::group::ProtocolProfile {
        self.session.new_protocol_profile()
    }

    pub fn live_group_ids(&self) -> AccountResult<Vec<GroupId>> {
        Ok(self.session.live_group_ids()?)
    }

    /// Stored groups that failed session-open hydration and were skipped
    /// (mdk#151 / #417), paired with their coarse quarantine reason.
    /// Backs the application's per-group recovery surface (mdk#426).
    pub fn quarantined_groups(&self) -> Vec<(GroupId, GroupHydrationQuarantineReason)> {
        self.session.quarantined_groups()
    }

    /// Number of currently quarantined groups without cloning their identities.
    pub fn quarantined_group_count(&self) -> usize {
        self.session.quarantined_group_count()
    }

    /// Re-attempt hydration of a single quarantined group. `Ok(true)` if it
    /// recovered and is now live, `Ok(false)` if still unhealthy. Errors with
    /// `UnknownGroup` if the id is not currently quarantined.
    pub fn retry_hydrate_quarantined_group(&mut self, group_id: &GroupId) -> AccountResult<bool> {
        Ok(self.session.retry_hydrate_quarantined_group(group_id)?)
    }

    pub fn admin_pubkeys(&self, group_id: &GroupId) -> AccountResult<Vec<[u8; 32]>> {
        Ok(self.session.admin_pubkeys(group_id)?)
    }

    /// Which roster slot the leaf at `leaf_index` belongs to, read from its
    /// device tag against the device group's current `roster`. `None` when
    /// `epoch` is not the group's current epoch or no leaf sits at that
    /// index. See [`cgka_engine::engine::Engine::member_device_tag_claim`].
    pub fn member_device_tag_claim(
        &self,
        group_id: &GroupId,
        epoch: EpochId,
        leaf_index: u32,
        roster: &DeviceRosterV1,
    ) -> AccountResult<Option<DeviceTagClaim>> {
        Ok(self
            .session
            .member_device_tag_claim(group_id, epoch, leaf_index, roster)?)
    }

    /// Which roster slot the leaf at `leaf_index` belonged to at `epoch`,
    /// read as [`Self::member_device_tag_claim`] does, but a past epoch from
    /// its own retained anchor. `None` when `epoch` is neither current nor
    /// retained, or no leaf sat at that index. See
    /// [`cgka_engine::engine::Engine::member_device_tag_claim_at`].
    pub fn member_device_tag_claim_at(
        &self,
        group_id: &GroupId,
        epoch: EpochId,
        leaf_index: u32,
        roster: &DeviceRosterV1,
    ) -> AccountResult<Option<DeviceTagClaim>> {
        Ok(self
            .session
            .member_device_tag_claim_at(group_id, epoch, leaf_index, roster)?)
    }

    /// This account's other leaves in `group_id`, by signature key, with the
    /// roster slot each one's device tag reads as against the device group's
    /// current `roster`. See
    /// [`cgka_engine::engine::Engine::own_account_leaf_claims`].
    pub fn own_account_leaf_claims(
        &self,
        group_id: &GroupId,
        roster: &DeviceRosterV1,
    ) -> AccountResult<Vec<(Vec<u8>, DeviceTagClaim)>> {
        Ok(self.session.own_account_leaf_claims(group_id, roster)?)
    }

    /// This account's leaves in `group_id` of its device in `slot`, each
    /// with the lifetime of the KeyPackage its Add built it from while it is
    /// still that leaf (mdk#3042). See
    /// [`cgka_engine::engine::Engine::own_device_leaves`].
    pub fn own_device_leaves(
        &self,
        group_id: &GroupId,
        roster: &DeviceRosterV1,
        slot: &cgka_traits::app_components::DeviceSlotId,
        tag_signature_key: Option<&[u8]>,
    ) -> AccountResult<Vec<cgka_traits::app_components::OwnDeviceLeaf>> {
        Ok(self
            .session
            .own_device_leaves(group_id, roster, slot, tag_signature_key)?)
    }

    /// This account's other leaves in `group_id`, by signature key, whose
    /// device tag verifies under the leaf's own key, each with the slot the
    /// tag names. See
    /// [`cgka_engine::engine::Engine::own_account_self_signed_tags`].
    pub fn own_account_self_signed_tags(
        &self,
        group_id: &GroupId,
        leaf_tag_key: &[u8; 32],
    ) -> AccountResult<Vec<(Vec<u8>, cgka_traits::app_components::DeviceSlotId)>> {
        Ok(self
            .session
            .own_account_self_signed_tags(group_id, leaf_tag_key)?)
    }

    /// This account's other leaves in `group_id`, by signature key with the
    /// slot their device tag reads as under `leaf_tag_key`, verified by one
    /// of `keys`: tag signature keys this device remembers a roster listing.
    /// See [`cgka_engine::engine::Engine::own_account_leaves_tagged_by`].
    pub fn own_account_leaves_tagged_by(
        &self,
        group_id: &GroupId,
        leaf_tag_key: &[u8; 32],
        keys: &[RosterTagKey],
    ) -> AccountResult<Vec<(Vec<u8>, cgka_traits::app_components::DeviceSlotId)>> {
        Ok(self
            .session
            .own_account_leaves_tagged_by(group_id, leaf_tag_key, keys)?)
    }

    pub fn app_component(
        &self,
        group_id: &GroupId,
        component_id: AppComponentId,
    ) -> AccountResult<Option<Vec<u8>>> {
        Ok(self.session.app_component(group_id, component_id)?)
    }

    /// Batched [`Self::app_component`]: one engine state load answers every id.
    pub fn app_components(
        &self,
        group_id: &GroupId,
        component_ids: &[AppComponentId],
    ) -> AccountResult<Vec<Option<Vec<u8>>>> {
        Ok(self.session.app_components(group_id, component_ids)?)
    }

    /// Every application-owned component the group holds, in id order: what
    /// [`Self::app_component`] answers for each app-owned id, from one load
    /// (mdk#3273).
    pub fn app_owned_components(
        &self,
        group_id: &GroupId,
    ) -> AccountResult<Vec<(AppComponentId, Vec<u8>)>> {
        Ok(self.session.app_owned_components(group_id)?)
    }

    /// Where each group's published answers stand, in order (mdk#3273). The
    /// account-wide maintenance pause, which [`Self::maintenance_status`]
    /// projects, is not in it: read [`Self::maintenance_is_paused`].
    pub fn group_change_generations<'a>(
        &self,
        group_ids: impl IntoIterator<Item = &'a GroupId>,
    ) -> Vec<cgka_engine::change_generation::GroupChangeGeneration> {
        self.session.group_change_generations(group_ids)
    }

    pub fn safe_export_secret(
        &mut self,
        group_id: &GroupId,
        component_id: AppComponentId,
    ) -> AccountResult<cgka_traits::SecretBytes> {
        Ok(self.session.safe_export_secret(group_id, component_id)?)
    }

    pub fn exporter_secret(
        &self,
        group_id: &GroupId,
        label: &str,
        length: usize,
    ) -> AccountResult<cgka_traits::SecretBytes> {
        Ok(self.session.exporter_secret(group_id, label, length)?)
    }

    pub fn epoch_pin(&self, group_id: &GroupId) -> AccountResult<cgka_traits::EpochPin> {
        Ok(self.session.epoch_pin(group_id)?)
    }

    pub fn exporter_secret_with_epoch(
        &self,
        group_id: &GroupId,
        label: &str,
        length: usize,
    ) -> AccountResult<(EpochId, cgka_traits::SecretBytes)> {
        Ok(self
            .session
            .exporter_secret_with_epoch(group_id, label, length)?)
    }

    /// Encrypted-media exporter secret of a past epoch, derived from its
    /// retained anchor; `Ok(None)` when no usable anchor remains.
    pub fn retained_encrypted_media_exporter_secret(
        &self,
        group_id: &GroupId,
        epoch: EpochId,
    ) -> AccountResult<Option<cgka_traits::SecretBytes>> {
        Ok(self
            .session
            .retained_encrypted_media_exporter_secret(group_id, epoch)?)
    }

    pub fn safe_export_secret_with_epoch(
        &mut self,
        group_id: &GroupId,
        component_id: AppComponentId,
    ) -> AccountResult<(EpochId, cgka_traits::SecretBytes)> {
        Ok(self
            .session
            .safe_export_secret_with_epoch(group_id, component_id)?)
    }

    pub fn current_safe_export_epoch(
        &self,
        group_id: &GroupId,
        component_id: AppComponentId,
    ) -> AccountResult<EpochId> {
        Ok(self
            .session
            .current_safe_export_epoch(group_id, component_id)?)
    }

    /// The one view of the session lent to code the host hands it to, such
    /// as the publication-progress observer and conversation-window captures.
    pub fn group_authority_view(&self) -> GroupAuthorityView<'_> {
        self.session.group_authority_view()
    }

    pub fn self_id(&self) -> MemberId {
        self.session.self_id()
    }

    /// This device's MLS signature key (`CgkaEngine::own_signature_key`).
    pub fn own_signature_key(&self) -> Vec<u8> {
        self.session.own_signature_key()
    }

    /// Pin original trust and destination expectation before a move Confirm.
    pub fn prepare_device_group_move(
        &mut self,
        expectation: &cgka_traits::storage::DeviceGroupWelcomeExpectation,
        own_slot: [u8; 32],
        now: u64,
    ) -> crate::session::SessionResult<bool> {
        self.session
            .prepare_device_group_move(expectation, own_slot, now)
    }

    /// Apply the present selected Made cut on the session's own connection.
    pub fn record_device_group_move_made(
        &mut self,
        destination: &GroupId,
        now: u64,
    ) -> crate::session::SessionResult<bool> {
        self.session.record_device_group_move_made(destination, now)
    }

    /// See `CgkaEngine::expect_device_group_welcome`.
    pub fn expect_device_group_welcome(
        &mut self,
        expectation: &DeviceGroupWelcomeExpectation,
    ) -> SessionResult<()> {
        Ok(self.session.expect_device_group_welcome(expectation)?)
    }

    /// The public half of this device's history key (mdk#2628 4.1),
    /// generated and stored on first use. This device's own roster entry
    /// carries it; see [`cgka_engine::engine::Engine::history_public_key`].
    pub fn history_public_key(&self) -> SessionResult<Vec<u8>> {
        self.session.history_public_key()
    }

    /// `plaintext` sealed to a sibling's history key, as its roster entry
    /// holds it, for `context`; `None` when that key is not one this device
    /// can seal to. See [`cgka_engine::history_key`].
    pub fn seal_history(
        &self,
        recipient_public_key: &[u8],
        context: &[u8],
        plaintext: &[u8],
    ) -> Option<Vec<u8>> {
        self.session
            .seal_history(recipient_public_key, context, plaintext)
    }

    /// `sealed` opened with this device's history key for `context`;
    /// `None` when it does not open or this device has no history key yet.
    pub fn open_history(&self, context: &[u8], sealed: &[u8]) -> SessionResult<Option<Vec<u8>>> {
        self.session.open_history(context, sealed)
    }

    /// The public half of the recovery key `entropy` derives (mdk#2628
    /// 4.4a); nothing is stored. See [`cgka_engine::recovery_key`].
    pub fn recovery_public_key(
        &self,
        entropy: &[u8; crate::RECOVERY_ENTROPY_LEN],
    ) -> SessionResult<Vec<u8>> {
        self.session.recovery_public_key(entropy)
    }

    /// `plaintext` sealed to a recovery key's public half, as the roster's
    /// account entry holds it, for `context`; `None` when that key is not
    /// one this device can seal to.
    pub fn seal_to_recovery_key(
        &self,
        recovery_public_key: &[u8],
        context: &[u8],
        plaintext: &[u8],
    ) -> Option<Vec<u8>> {
        self.session
            .seal_to_recovery_key(recovery_public_key, context, plaintext)
    }

    /// `sealed` opened with the recovery key `entropy` derives, for
    /// `context`; `None` when it does not open.
    pub fn open_with_recovery_key(
        &self,
        entropy: &[u8; crate::RECOVERY_ENTROPY_LEN],
        context: &[u8],
        sealed: &[u8],
    ) -> SessionResult<Option<Vec<u8>>> {
        self.session
            .open_with_recovery_key(entropy, context, sealed)
    }

    /// See `CgkaEngine::withdraw_device_group_welcome`.
    pub fn withdraw_device_group_welcome(&mut self, group_id: &GroupId) -> SessionResult<bool> {
        Ok(self.session.withdraw_device_group_welcome(group_id)?)
    }

    pub fn open_timings(&self) -> &SessionOpenTimings {
        self.session.open_timings()
    }

    pub fn unhydrated_group_ids(&self) -> Vec<GroupId> {
        self.session.unhydrated_group_ids()
    }

    pub fn ensure_group_hydrated(&mut self, group_id: &GroupId) -> SessionResult<bool> {
        self.session.ensure_group_hydrated(group_id)
    }

    pub fn hydrate_next_groups(
        &mut self,
        order: &[GroupId],
        budget: usize,
    ) -> SessionResult<HydrationProgress> {
        self.session.hydrate_next_groups(order, budget)
    }

    pub fn key_package_metadata(
        &self,
        key_package: &KeyPackage,
    ) -> Result<KeyPackageMetadata, EngineError> {
        self.session.key_package_metadata(key_package)
    }

    pub fn invite_key_package_requirements(
        &self,
        group_id: &GroupId,
    ) -> Result<KeyPackageRequirements, EngineError> {
        self.session.invite_key_package_requirements(group_id)
    }

    /// Whether the device group's leaf of this account's device in `slot`
    /// advertises what `requirements` asks of a KeyPackage. See
    /// [`cgka_engine::Engine::sibling_leaf_supports`].
    pub fn sibling_leaf_supports(
        &self,
        group_id: &GroupId,
        roster: &DeviceRosterV1,
        slot: &cgka_traits::app_components::DeviceSlotId,
        requirements: &KeyPackageRequirements,
    ) -> Result<bool, EngineError> {
        self.session
            .sibling_leaf_supports(group_id, roster, slot, requirements)
    }

    pub fn create_key_package_requirements(
        &self,
        request: &CreateGroupRequest,
    ) -> Result<KeyPackageRequirements, EngineError> {
        self.session.create_key_package_requirements(request)
    }

    pub fn maintenance_obligations_for_group(
        &self,
        group_id: &GroupId,
    ) -> SessionResult<Vec<MaintenanceObligation>> {
        self.session.maintenance_obligations_for_group(group_id)
    }

    pub fn canonical_group_membership(
        &self,
        group_id: &GroupId,
    ) -> SessionResult<CanonicalGroupMembership> {
        self.session.canonical_group_membership(group_id)
    }

    pub fn leave_in_progress(&self, group_id: &GroupId) -> Result<bool, EngineError> {
        self.session.leave_in_progress(group_id)
    }

    pub fn outbound_fanouts(&self) -> SessionResult<Vec<OutboundFanout>> {
        self.session.outbound_fanouts()
    }

    pub fn outbound_fanouts_for_group(
        &self,
        group_id: &GroupId,
    ) -> SessionResult<Vec<OutboundFanout>> {
        self.session.outbound_fanouts_for_group(group_id)
    }

    /// Groups holding a stored frozen fanout, including unhydrated ones (mdk#2762).
    pub fn outbound_fanout_group_ids(&self) -> SessionResult<Vec<GroupId>> {
        self.session.outbound_fanout_group_ids()
    }

    pub fn put_outbound_fanout(&self, fanout: &OutboundFanout) -> SessionResult<()> {
        self.session.put_outbound_fanout(fanout)
    }

    /// Whether any stored Welcome is a rejoin offer, which maintenance
    /// retries while it lasts (mdk#3265).
    pub fn has_rejoin_offers(&self) -> SessionResult<bool> {
        self.session.has_rejoin_offers()
    }

    pub async fn retry_rejoins_after_trusted_removal(&mut self) -> SessionResult<bool> {
        self.session.retry_rejoins_after_trusted_removal().await
    }

    pub fn pending_group_rejoins_for(
        &self,
        group_id: &GroupId,
    ) -> SessionResult<Vec<cgka_traits::welcome::PendingWelcome>> {
        self.session.pending_group_rejoins_for(group_id)
    }

    /// Every stored Welcome that offers a re-join, without its consent token
    /// ([`cgka_engine::Engine::stored_rejoin_welcomes`]).
    pub fn stored_rejoin_welcomes(
        &self,
    ) -> SessionResult<Vec<cgka_traits::welcome::PendingWelcome>> {
        self.session.stored_rejoin_welcomes()
    }

    /// The offers among `candidates` whose group's MLS state loads, and
    /// whether any was left out on a failure that can clear with no write
    /// ([`cgka_engine::Engine::rejoin_offers`]).
    pub fn rejoin_offers(
        &self,
        candidates: Vec<cgka_traits::welcome::PendingWelcome>,
    ) -> cgka_engine::group_lifecycle::RejoinOffers {
        self.session.rejoin_offers(candidates)
    }

    pub async fn confirm_group_rejoin(
        &mut self,
        welcome_id: &cgka_traits::MessageId,
        token: &[u8],
    ) -> SessionResult<GroupId> {
        self.session.confirm_group_rejoin(welcome_id, token).await
    }

    pub fn decline_group_rejoin(
        &mut self,
        welcome_id: &cgka_traits::MessageId,
    ) -> SessionResult<()> {
        self.session.decline_group_rejoin(welcome_id)
    }

    pub fn reinvite_recovery_records(
        &self,
    ) -> SessionResult<Vec<cgka_traits::storage::OwnCommitIntent>> {
        self.session.reinvite_recovery_records()
    }

    pub fn pending_reinvites(&self) -> SessionResult<Vec<cgka_traits::storage::OwnCommitIntent>> {
        self.session.pending_reinvites()
    }

    pub fn reserve_reinvite_lookup(
        &mut self,
        commit_id: &cgka_traits::MessageId,
        now_ms: u64,
    ) -> SessionResult<bool> {
        self.session.reserve_reinvite_lookup(commit_id, now_ms)
    }

    pub fn reissue_invite_with_key_packages(
        &mut self,
        commit_id: &cgka_traits::MessageId,
        packages: Vec<KeyPackage>,
    ) -> SessionResult<Option<SupersededIntentReport>> {
        self.session
            .reissue_invite_with_key_packages(commit_id, packages)
    }

    pub async fn activate_transport(&self, since: Option<Timestamp>) -> AccountResult<()> {
        tracing::debug!(
            target: TRACE_TARGET,
            method = "activate_transport",
            inbox_endpoint_count = self.routing.local_inbox_endpoints().len(),
            group_subscription_count = self.routing.group_subscriptions().len(),
            "activating account transport"
        );
        self.adapter
            .activate_account(TransportAccountActivation {
                account_id: self.session.self_id(),
                inbox_endpoints: self.routing.local_inbox_endpoints(),
                group_subscriptions: self.routing.group_subscriptions(),
                since,
            })
            .await?;
        Ok(())
    }

    pub async fn sync_transport_groups(&self, since: Option<Timestamp>) -> AccountResult<()> {
        tracing::debug!(
            target: TRACE_TARGET,
            method = "sync_transport_groups",
            group_subscription_count = self.routing.group_subscriptions().len(),
            "syncing account group subscriptions"
        );
        self.adapter
            .sync_account_groups(TransportGroupSync {
                account_id: self.session.self_id(),
                group_subscriptions: self.routing.group_subscriptions(),
                since,
            })
            .await?;
        Ok(())
    }

    /// Why [`Self::republish_key_package`] publishes a fresh KeyPackage
    /// instead of the current one, if it does for a reason the current
    /// lifecycle shows.
    fn current_key_package_republish_fallback(
        &self,
        lifecycle: &KeyPackageLifecycleState,
    ) -> Option<&'static str> {
        current_key_package_republish_blocker(lifecycle, self.wall_clock.now())
            .or_else(|| {
                lifecycle
                    .current_key_package
                    .as_ref()
                    .is_some_and(|current| !self.advertises_current_capabilities(current))
                    .then_some("advertised_capabilities_changed")
            })
            .or_else(|| {
                self.current_publication_superseded(lifecycle)
                    .then_some("slot_publication_superseded")
            })
    }

    /// Re-send the exact current durable authored KeyPackage event to the
    /// current authoritative publication targets without staging a replacement.
    ///
    /// When no usable current package or signed artifact exists, this falls back to
    /// [`Self::publish_fresh_key_package`].
    pub async fn republish_key_package(&mut self) -> AccountResult<KeyPackage> {
        self.ensure_key_package_slot_not_withdrawn()?;
        let Some(mut lifecycle) = self.session.key_package_lifecycle()? else {
            tracing::debug!(
                target: TRACE_TARGET,
                method = "republish_key_package",
                fallback_reason = "no_lifecycle_state",
                "no republishable current key package artifact; falling back to fresh publication"
            );
            return self.publish_fresh_key_package().await;
        };
        if lifecycle.pending_replacement.is_some() {
            return Err(AccountError::KeyPackageRotationInProgress);
        }
        if lifecycle.stable_slot_id.is_empty() {
            return Err(crate::key_package::KeyPackagePublishError::unexposed(
                "key package lifecycle is migration-blocked because the stable replaceable-event slot is unavailable",
            )
            .into());
        }
        if let Some(fallback_reason) = self.current_key_package_republish_fallback(&lifecycle) {
            tracing::debug!(
                target: TRACE_TARGET,
                method = "republish_key_package",
                fallback_reason,
                "no republishable current key package artifact; falling back to fresh publication"
            );
            return self.publish_fresh_key_package().await;
        }

        tracing::debug!(
            target: TRACE_TARGET,
            method = "republish_key_package",
            endpoint_count = self.routing.key_package_endpoints().len(),
            "republishing current key package"
        );

        let current_endpoints = self.routing.key_package_endpoints();
        merge_republish_publication_targets(&mut lifecycle.publication_targets, &current_endpoints);
        let endpoints = current_endpoints.to_vec();
        if endpoints.is_empty() {
            self.session.put_key_package_lifecycle(&lifecycle)?;
            return Err(crate::key_package::KeyPackagePublishError::unexposed(
                "no KeyPackage publication endpoints are configured",
            )
            .into());
        }

        let Some(artifact) = lifecycle.authored_signed_event.clone() else {
            tracing::debug!(
                target: TRACE_TARGET,
                method = "republish_key_package",
                fallback_reason = "missing_authored_signed_event",
                "no republishable current key package artifact; falling back to fresh publication"
            );
            return self.publish_fresh_key_package().await;
        };
        let Some(key_package) = lifecycle.current_key_package.clone() else {
            tracing::debug!(
                target: TRACE_TARGET,
                method = "republish_key_package",
                fallback_reason = "missing_current_key_package",
                "no republishable current key package artifact; falling back to fresh publication"
            );
            return self.publish_fresh_key_package().await;
        };
        self.ensure_key_package_announced(
            lifecycle
                .current_key_package_ref
                .as_deref()
                .unwrap_or_default(),
        )?;

        lifecycle.phase = cgka_traits::MaintenancePhase::Fanout;
        self.session.put_key_package_lifecycle(&lifecycle)?;
        let publication = KeyPackagePublication {
            account_id: self.session.self_id().clone(),
            key_package: key_package.clone(),
            slot_id: lifecycle.stable_slot_id.clone(),
            created_at: artifact.created_at,
            endpoints: endpoints.clone(),
        };
        match self
            .key_packages
            .publish_prepared_key_package(&publication, &artifact)
            .await
        {
            Ok(receipt) => {
                note_key_package_attempt(
                    &mut lifecycle.publication_targets,
                    &publication.endpoints,
                    &receipt.accepted,
                    &receipt.failed,
                    self.wall_clock.now(),
                );
                if receipt.accepted.is_empty() {
                    lifecycle.phase = cgka_traits::MaintenancePhase::Retry;
                    self.session.put_key_package_lifecycle(&lifecycle)?;
                    return Err(crate::key_package::KeyPackagePublishError::exposed(
                        "no KeyPackage relay acknowledged the republication",
                    )
                    .into());
                }
                lifecycle.phase = if lifecycle.publication_targets.iter().all(|target| {
                    matches!(
                        target.state,
                        TransportFanoutAttemptState::Accepted
                            | TransportFanoutAttemptState::PolicyProhibited
                    )
                }) {
                    cgka_traits::MaintenancePhase::Complete
                } else {
                    cgka_traits::MaintenancePhase::Fanout
                };
                self.session.put_key_package_lifecycle(&lifecycle)?;
                Ok(key_package)
            }
            Err(error) if error.artifact_unusable && may_replace_unusable_artifact(&lifecycle) => {
                self.replace_unusable_current_artifact(&mut lifecycle)?;
                self.publish_fresh_key_package().await
            }
            Err(error) => {
                note_key_package_attempt(
                    &mut lifecycle.publication_targets,
                    &publication.endpoints,
                    &[],
                    &[],
                    self.wall_clock.now(),
                );
                lifecycle.phase = if error.externally_exposed {
                    cgka_traits::MaintenancePhase::Fanout
                } else {
                    cgka_traits::MaintenancePhase::Retry
                };
                self.session.put_key_package_lifecycle(&lifecycle)?;
                Err(error.into())
            }
        }
    }

    /// The publisher refused the current signed event as unusable, so it is
    /// never resent. Make the current KeyPackage due for replacement now; the
    /// replacement is a freshly signed event in the same slot (D8).
    fn replace_unusable_current_artifact(
        &mut self,
        lifecycle: &mut KeyPackageLifecycleState,
    ) -> AccountResult<()> {
        tracing::info!(
            target: TRACE_TARGET,
            method = "replace_unusable_current_artifact",
            "replacing a current key package the publisher can no longer send"
        );
        lifecycle.unusable_artifact_replaced_by = Some(KEY_PACKAGE_SIGNING_BUILD.into());
        lifecycle.refresh_at = Some(self.wall_clock.now());
        lifecycle.phase = cgka_traits::MaintenancePhase::Retry;
        self.session.put_key_package_lifecycle(lifecycle)?;
        Ok(())
    }

    /// Stage the exact next KeyPackage and authored publication bytes without
    /// performing any network I/O.
    ///
    /// This is the durable local-readiness boundary for generated accounts:
    /// callers may return the identity only after this succeeds, then resume
    /// [`Self::publish_fresh_key_package`] later with the same persisted
    /// private material and signed artifact.
    pub async fn prepare_fresh_key_package(
        &mut self,
        endpoints: Vec<TransportEndpoint>,
    ) -> AccountResult<KeyPackage> {
        self.prepare_key_package_replacement(endpoints, false).await
    }

    /// [`Self::prepare_fresh_key_package`]. With `supersede_pending`, a
    /// pending replacement the publisher refused as unusable is superseded by
    /// a newly generated one even when its generator revision is current, and
    /// this build's one such replacement is spent.
    async fn prepare_key_package_replacement(
        &mut self,
        endpoints: Vec<TransportEndpoint>,
        supersede_pending: bool,
    ) -> AccountResult<KeyPackage> {
        tracing::debug!(
            target: TRACE_TARGET,
            method = "prepare_fresh_key_package",
            endpoint_count = endpoints.len(),
            "preparing fresh key package for later publication"
        );
        self.ensure_key_package_slot_not_withdrawn()?;
        // A KeyPackage staged while this device's tag signature key is due
        // would go out untagged once the key is set (mdk#2628 3.1d), so it
        // waits for the key, as publication waits for its announcement.
        if !self.device_tag_key_settled()? {
            return Err(AccountError::KeyPackageAnnouncementPending);
        }
        let now = self.wall_clock.now();
        let mut lifecycle = match self.session.key_package_lifecycle()? {
            Some(state) => state,
            None => {
                let stable_slot_id = self
                    .key_packages
                    .legacy_slot_id(&self.session.self_id())?
                    .ok_or_else(|| {
                        crate::key_package::KeyPackagePublishError::unexposed(
                            "key package slot is uninitialized; provision a durable slot before publication",
                        )
                    })?;
                KeyPackageLifecycleState {
                    stable_slot_id,
                    phase: cgka_traits::MaintenancePhase::Complete,
                    current_key_package: None,
                    current_key_package_ref: None,
                    current_not_before: None,
                    current_not_after: None,
                    authored_event_id: None,
                    authored_event_created_at: None,
                    authored_signed_event: None,
                    publication_targets: Vec::new(),
                    refresh_at: None,
                    upgrade_rotation_recorded: false,
                    generation_revision: 0,
                    last_consumed_key_package_ref: None,
                    last_consumed_at: None,
                    retained_private_material: Vec::new(),
                    pending_replacement: None,
                    unusable_artifact_replaced_by: None,
                    slot_withdrawn_at: None,
                }
            }
        };
        if lifecycle.stable_slot_id.is_empty() {
            return Err(crate::key_package::KeyPackagePublishError::unexposed(
                "key package lifecycle is migration-blocked because the stable replaceable-event slot is unavailable",
            )
            .into());
        }

        if supersede_pending
            || lifecycle
                .pending_replacement
                .as_ref()
                .is_none_or(|pending| self.pending_replacement_obsolete(&lifecycle, pending))
        {
            // Newer than every publication in the slot, a foreign one
            // included, and than its withdrawal: relays drop anything up to
            // that.
            let superseded_through = self.slot_superseded_through_signable(now);
            let created_at = Timestamp(
                lifecycle
                    .authored_event_created_at
                    .into_iter()
                    .chain(
                        lifecycle
                            .pending_replacement
                            .as_ref()
                            .map(|pending| pending.authored_created_at),
                    )
                    .chain(lifecycle.slot_withdrawn_at)
                    .chain(superseded_through)
                    .max()
                    .map(|previous| previous.0.saturating_add(1))
                    .unwrap_or(now.0)
                    .max(now.0),
            );
            if created_at.0 > now.0.saturating_add(KEY_PACKAGE_MAX_FUTURE_SKEW_SECS) {
                lifecycle.phase = cgka_traits::MaintenancePhase::ClockSkewBlocked;
                self.session.put_key_package_lifecycle(&lifecycle)?;
                return Err(AccountError::ClockSkewBlocked);
            }
            let refresh_after = self
                .entropy
                .sample_inclusive(KEY_PACKAGE_REFRESH_MIN_SECS, KEY_PACKAGE_REFRESH_MAX_SECS);
            if supersede_pending {
                // Recorded with the replacement it pays for, so a restart
                // between the two can neither repeat nor lose it.
                lifecycle.unusable_artifact_replaced_by = Some(KEY_PACKAGE_SIGNING_BUILD.into());
            }
            self.session.stage_key_package_replacement(
                &mut lifecycle,
                created_at,
                refresh_after,
                endpoints
                    .into_iter()
                    .map(|endpoint| TransportFanoutTarget {
                        endpoint,
                        state: TransportFanoutAttemptState::Unattempted,
                        attempt_count: 0,
                        last_attempt_at: None,
                        failure_code: None,
                    })
                    .collect(),
            )?;
        }

        if lifecycle
            .pending_replacement
            .as_ref()
            .is_some_and(|pending| pending.signed_event.is_none())
        {
            let pending = lifecycle
                .pending_replacement
                .as_ref()
                .expect("unsigned pending replacement exists");
            let publication = KeyPackagePublication {
                account_id: self.session.self_id().clone(),
                key_package: pending.key_package.clone(),
                slot_id: lifecycle.stable_slot_id.clone(),
                created_at: pending.authored_created_at,
                endpoints: pending
                    .targets
                    .iter()
                    .map(|target| target.endpoint.clone())
                    .collect(),
            };
            let artifact = self.key_packages.prepare_key_package(publication).await?;
            lifecycle
                .pending_replacement
                .as_mut()
                .expect("unsigned pending replacement exists")
                .signed_event = Some(artifact);
            // Exact signed bytes are durable before the first network call.
            self.session.put_key_package_lifecycle(&lifecycle)?;
        }

        Ok(lifecycle
            .pending_replacement
            .as_ref()
            .expect("prepared replacement exists")
            .key_package
            .clone())
    }

    pub async fn publish_fresh_key_package(&mut self) -> AccountResult<KeyPackage> {
        tracing::debug!(
            target: TRACE_TARGET,
            method = "publish_fresh_key_package",
            endpoint_count = self.routing.key_package_endpoints().len(),
            "publishing fresh key package"
        );
        let endpoints = self.routing.key_package_endpoints().to_vec();
        let mut supersede_pending = false;
        let (mut lifecycle, artifact, publication, receipt) = loop {
            self.prepare_key_package_replacement(endpoints.clone(), supersede_pending)
                .await?;
            let mut lifecycle = self
                .session
                .key_package_lifecycle()?
                .expect("prepared lifecycle is durable");
            // Promotion clears the marker, so move an old record's marker first.
            lifecycle.migrate_legacy_consumption_marker();

            let pending = lifecycle
                .pending_replacement
                .as_ref()
                .expect("pending replacement exists");
            // A device group's roster names it before it reaches the slot;
            // maintenance announces it.
            self.ensure_key_package_announced(&pending.key_package_ref)?;
            let artifact = pending
                .signed_event
                .as_ref()
                .expect("prepared replacement has an exact signed event")
                .clone();
            let publication = KeyPackagePublication {
                account_id: self.session.self_id().clone(),
                key_package: pending.key_package.clone(),
                slot_id: lifecycle.stable_slot_id.clone(),
                created_at: artifact.created_at,
                endpoints: pending
                    .targets
                    .iter()
                    .map(|target| target.endpoint.clone())
                    .collect(),
            };
            let error = match self
                .key_packages
                .publish_prepared_key_package(&publication, &artifact)
                .await
            {
                Ok(receipt) => break (lifecycle, artifact, publication, receipt),
                Err(error) => error,
            };
            // The publisher will never send these signed bytes, for example
            // because an earlier build signed them under rules this one no
            // longer accepts (D8). Supersede the replacement with one signed
            // now; the old one stays retained with its event id, since an
            // earlier build may have sent it. A build does this at most once,
            // so a publisher that refuses its own artifacts cannot mint a
            // bundle per attempt. Paused maintenance only finishes prepared
            // work, so it leaves the replacement for resume.
            if error.artifact_unusable
                && !self.maintenance_paused
                && may_replace_unusable_artifact(&lifecycle)
            {
                tracing::info!(
                    target: TRACE_TARGET,
                    method = "publish_fresh_key_package",
                    "superseding a key package replacement the publisher can no longer send"
                );
                supersede_pending = true;
                continue;
            }
            if let Some(pending) = lifecycle.pending_replacement.as_mut() {
                pending.attempt_count = pending.attempt_count.saturating_add(1);
                pending.last_failure_code = Some(
                    if error.artifact_unusable {
                        KEY_PACKAGE_ARTIFACT_UNUSABLE
                    } else if error.externally_exposed {
                        "ambiguous_exposure"
                    } else {
                        "publish_failed"
                    }
                    .into(),
                );
                note_key_package_attempt(
                    &mut pending.targets,
                    &publication.endpoints,
                    &[],
                    &[],
                    self.wall_clock.now(),
                );
            }
            lifecycle.phase = cgka_traits::MaintenancePhase::Retry;
            self.session.put_key_package_lifecycle(&lifecycle)?;
            return Err(error.into());
        };
        if receipt.accepted.is_empty() {
            if let Some(pending) = lifecycle.pending_replacement.as_mut() {
                pending.attempt_count = pending.attempt_count.saturating_add(1);
                pending.last_failure_code = Some("ambiguous_exposure".into());
                note_key_package_attempt(
                    &mut pending.targets,
                    &publication.endpoints,
                    &receipt.accepted,
                    &receipt.failed,
                    self.wall_clock.now(),
                );
            }
            lifecycle.phase = cgka_traits::MaintenancePhase::Retry;
            self.session.put_key_package_lifecycle(&lifecycle)?;
            return Err(crate::key_package::KeyPackagePublishError::exposed(
                "no KeyPackage relay acknowledged the replacement",
            )
            .into());
        }

        let mut replacement = lifecycle
            .pending_replacement
            .take()
            .expect("published replacement exists");
        note_key_package_attempt(
            &mut replacement.targets,
            &publication.endpoints,
            &receipt.accepted,
            &receipt.failed,
            self.wall_clock.now(),
        );
        let previous_was_consumed = lifecycle.current_key_package_ref.is_some()
            && lifecycle.current_key_package_ref == lifecycle.last_consumed_key_package_ref;
        // Inviters may still hold a replaced publication, so its private
        // material outlives this confirmed replacement by the grace period,
        // consumed or not (mdk#2344). That includes unconsumed pending
        // replacements superseded before any was confirmed; a consumed one
        // keeps the grace period it started when it was superseded.
        let confirmed_at = self.wall_clock.now();
        for material in &mut lifecycle.retained_private_material {
            if material.awaiting_confirmed_replacement {
                material.awaiting_confirmed_replacement = false;
                if !material.consumed {
                    material.replaced_at = confirmed_at;
                }
            }
        }
        let mut retired = Vec::new();
        if let Some(key_package) = lifecycle.current_key_package.clone() {
            match (
                lifecycle.current_key_package_ref.clone(),
                lifecycle.current_not_after,
            ) {
                (Some(key_package_ref), Some(not_after)) => lifecycle
                    .retained_private_material
                    .push(RetainedKeyPackagePrivateMaterial {
                        key_package,
                        key_package_ref,
                        not_after,
                        replaced_at: confirmed_at,
                        consumed: previous_was_consumed,
                        authored_event_id: lifecycle.authored_event_id.clone(),
                        awaiting_confirmed_replacement: false,
                    }),
                // Without a lifetime there is no deletion bound to retain it
                // under.
                _ if previous_was_consumed => retired.push(key_package),
                _ => {}
            }
        }
        lifecycle.current_key_package = Some(replacement.key_package.clone());
        lifecycle.current_key_package_ref = Some(replacement.key_package_ref);
        lifecycle.current_not_before = Some(replacement.not_before);
        lifecycle.current_not_after = Some(replacement.not_after);
        lifecycle.authored_event_id = Some(artifact.id.clone());
        lifecycle.authored_event_created_at = Some(artifact.created_at);
        if !withdrawn_with_slot(&lifecycle, artifact.created_at) {
            lifecycle.slot_withdrawn_at = None;
        }
        self.note_slot_publication(artifact.created_at);
        lifecycle.authored_signed_event = Some(artifact);
        lifecycle.publication_targets = replacement.targets;
        lifecycle.refresh_at = Some(replacement.refresh_at);
        lifecycle.phase = if lifecycle.publication_targets.iter().all(|target| {
            matches!(
                target.state,
                TransportFanoutAttemptState::Accepted
                    | TransportFanoutAttemptState::PolicyProhibited
            )
        }) {
            cgka_traits::MaintenancePhase::Complete
        } else {
            cgka_traits::MaintenancePhase::Fanout
        };
        lifecycle.upgrade_rotation_recorded = true;
        lifecycle.generation_revision = replacement.generation_revision;
        // A Welcome can consume the replacement before its acknowledgement,
        // which makes the new current package due for replacement in turn.
        lifecycle.last_consumed_key_package_ref = lifecycle
            .current_key_package_ref
            .clone()
            .filter(|_| replacement.consumed_at.is_some());
        lifecycle.last_consumed_at = replacement.consumed_at;
        self.session
            .promote_key_package_lifecycle(&retired, &lifecycle)?;
        Ok(replacement.key_package)
    }

    pub fn key_package_maintenance_status(
        &self,
    ) -> AccountResult<Option<KeyPackageLifecycleState>> {
        Ok(self.session.key_package_lifecycle()?)
    }

    pub fn durably_owned_key_packages(&self) -> AccountResult<Vec<KeyPackage>> {
        Ok(self.session.durably_owned_key_packages()?)
    }

    /// [`Self::durably_owned_key_packages`] with how long the list holds while
    /// nothing writes (mdk#3273).
    pub fn durably_owned_key_packages_with_validity(
        &self,
    ) -> AccountResult<cgka_engine::key_package::OwnedKeyPackages> {
        Ok(self.session.durably_owned_key_packages_with_validity()?)
    }

    /// Whether account activation owes a generator-policy upgrade. A pending
    /// replacement owns the work until ACK; its revision prevents regenerating
    /// on every retry while the acknowledged current revision is still old.
    pub fn key_package_generation_upgrade_due(&self) -> AccountResult<bool> {
        Ok(self
            .session
            .key_package_lifecycle()?
            .is_some_and(|lifecycle| {
                lifecycle.pending_replacement.as_ref().map_or_else(
                    || {
                        lifecycle.current_key_package.is_some()
                            && lifecycle.generation_revision < KEY_PACKAGE_GENERATION_REVISION
                    },
                    |pending| pending.generation_revision < KEY_PACKAGE_GENERATION_REVISION,
                )
            }))
    }

    pub fn key_package_network_maintenance_due(&self) -> AccountResult<bool> {
        if self.key_package_slot_withdrawn {
            return Ok(false);
        }
        let now = self.wall_clock.now();
        Ok(match self.session.key_package_lifecycle()? {
            None => true,
            Some(lifecycle) => match lifecycle.pending_replacement.as_ref() {
                Some(pending) => {
                    self.pending_replacement_obsolete(&lifecycle, pending)
                        || pending.signed_event.is_none()
                        || pending
                            .targets
                            .iter()
                            .any(|target| key_package_target_retry_due(target, now))
                }
                None => {
                    lifecycle.last_consumed_key_package_ref == lifecycle.current_key_package_ref
                        || self.current_key_package_replacement_due(&lifecycle, now)
                }
            },
        })
    }

    /// Whether the current KeyPackage is due for replacement for any reason
    /// other than a Welcome consuming it: there is none, its weekly refresh
    /// is due, the generator policy changed, the capabilities this client
    /// supports changed (`foundation/key-packages.md`, "Refreshing a slot"),
    /// or the slot was withdrawn at sign-out or served a foreign publication
    /// at least as new.
    fn current_key_package_replacement_due(
        &self,
        lifecycle: &KeyPackageLifecycleState,
        now: Timestamp,
    ) -> bool {
        let Some(current) = lifecycle.current_key_package.as_ref() else {
            return true;
        };
        key_package_refresh_due(lifecycle, now)
            || self.current_publication_superseded(lifecycle)
            || !lifecycle.upgrade_rotation_recorded
            || lifecycle.generation_revision < KEY_PACKAGE_GENERATION_REVISION
            || !self.advertises_current_capabilities(current)
    }

    /// Whether `pending` must be replaced before it is published: built by an
    /// older generator revision, superseded in the slot (staged before its
    /// withdrawal, or no newer than a foreign publication found there), or
    /// built without the capabilities this device now advertises, such as a
    /// device tag once this device tags (mdk#2628 3.1d).
    fn pending_replacement_obsolete(
        &self,
        lifecycle: &KeyPackageLifecycleState,
        pending: &PendingKeyPackageReplacement,
    ) -> bool {
        pending.generation_revision < KEY_PACKAGE_GENERATION_REVISION
            || self.slot_publication_superseded(lifecycle, pending.authored_created_at)
            || !self.advertises_current_capabilities(&pending.key_package)
    }

    /// Whether `key_package` advertises what one built now would. A package
    /// this device cannot read is left to the other replacement triggers, so
    /// it cannot cause a replacement on every maintenance tick.
    fn advertises_current_capabilities(&self, key_package: &KeyPackage) -> bool {
        self.session
            .key_package_advertises_current_capabilities(key_package)
            .unwrap_or(true)
    }

    pub fn key_package_has_pending_fanout(&self) -> AccountResult<bool> {
        if self.key_package_slot_withdrawn {
            return Ok(false);
        }
        // A withdrawn or superseded publication is replaced, not resent.
        Ok(self
            .session
            .key_package_lifecycle()?
            .is_some_and(|lifecycle| {
                !self.current_publication_superseded(&lifecycle)
                    && lifecycle.generation_revision >= KEY_PACKAGE_GENERATION_REVISION
                    && lifecycle.authored_signed_event.is_some()
                    && lifecycle.publication_targets.iter().any(|target| {
                        matches!(
                            target.state,
                            TransportFanoutAttemptState::Unattempted
                                | TransportFanoutAttemptState::AttemptedFailed
                        )
                    })
            }))
    }

    /// Ask the relays to stop serving this device's slot before it signs out
    /// (`foundation/key-packages.md`, "Stopping publication"). The request
    /// names this device's slot and nothing else. The withdrawal is recorded
    /// before the request goes out, so the next runtime for the account
    /// republishes, and is undone when no endpoint accepts the request.
    ///
    /// Returns how many endpoints accepted it, or 0 when this device never
    /// published into the slot. Whatever the outcome, this runtime publishes
    /// no KeyPackage afterwards: the device is signing out.
    pub async fn withdraw_key_package_slot(&mut self) -> AccountResult<usize> {
        self.key_package_slot_withdrawn = true;
        let Some(previous) = self.session.key_package_lifecycle()? else {
            return Ok(0);
        };
        let pending = previous.pending_replacement.as_ref();
        let published = previous.authored_event_id.is_some()
            || pending.is_some_and(|pending| pending.signed_event.is_some());
        if !published || previous.stable_slot_id.is_empty() {
            return Ok(0);
        }
        // The deletion covers every publication in the slot up to its time,
        // and never moves an earlier withdrawal's time back.
        let created_at = previous
            .authored_event_created_at
            .into_iter()
            .chain(pending.map(|pending| pending.authored_created_at))
            .chain(previous.slot_withdrawn_at)
            .fold(self.wall_clock.now(), Timestamp::max);
        let mut endpoints = self.routing.key_package_endpoints().to_vec();
        for target in previous
            .publication_targets
            .iter()
            .chain(pending.into_iter().flat_map(|pending| &pending.targets))
        {
            if !endpoints.contains(&target.endpoint) {
                endpoints.push(target.endpoint.clone());
            }
        }
        if endpoints.is_empty() {
            return Err(crate::key_package::KeyPackagePublishError::unexposed(
                "no KeyPackage publication endpoints are configured",
            )
            .into());
        }

        let mut withdrawn = previous.clone();
        withdrawn.slot_withdrawn_at = Some(created_at);
        self.session.put_key_package_lifecycle(&withdrawn)?;
        let withdrawal = KeyPackageSlotWithdrawal {
            account_id: self.session.self_id().clone(),
            slot_id: previous.stable_slot_id.clone(),
            created_at,
            endpoints,
        };
        let endpoint_count = withdrawal.endpoints.len();
        let error = match self
            .key_packages
            .withdraw_key_package_slot(&withdrawal)
            .await
        {
            Ok(receipt) if !receipt.accepted.is_empty() => {
                tracing::info!(
                    target: TRACE_TARGET,
                    method = "withdraw_key_package_slot",
                    endpoint_count,
                    accepted_count = receipt.accepted.len(),
                    "withdrew this device's key package slot"
                );
                return Ok(receipt.accepted.len());
            }
            Ok(_) => crate::key_package::KeyPackagePublishError::unexposed(
                "no KeyPackage relay accepted the slot withdrawal",
            ),
            Err(error) => error,
        };
        // Nothing confirms this withdrawal, so the slot stays as it was, and
        // the account's next runtime keeps it fresh.
        self.session.put_key_package_lifecycle(&previous)?;
        tracing::warn!(
            target: TRACE_TARGET,
            method = "withdraw_key_package_slot",
            endpoint_count,
            "no endpoint accepted the key package slot withdrawal"
        );
        Err(error.into())
    }

    fn ensure_key_package_slot_not_withdrawn(&self) -> AccountResult<()> {
        if self.key_package_slot_withdrawn {
            return Err(crate::key_package::KeyPackagePublishError::unexposed(
                "this device's KeyPackage slot was withdrawn for sign-out",
            )
            .into());
        }
        Ok(())
    }

    async fn retry_key_package_fanout(&mut self) -> AccountResult<()> {
        let Some(mut lifecycle) = self.session.key_package_lifecycle()? else {
            return Ok(());
        };
        if lifecycle.pending_replacement.is_some()
            || self.current_publication_superseded(&lifecycle)
            || self.key_package_slot_withdrawn
        {
            return Ok(());
        }
        let Some(artifact) = lifecycle.authored_signed_event.clone() else {
            return Ok(());
        };
        let endpoints = lifecycle
            .publication_targets
            .iter()
            .filter(|target| key_package_target_retry_due(target, self.wall_clock.now()))
            .map(|target| target.endpoint.clone())
            .collect::<Vec<_>>();
        if endpoints.is_empty() {
            return Ok(());
        }
        let Some(key_package) = lifecycle.current_key_package.clone() else {
            return Ok(());
        };
        // An unannounced event waits for maintenance to announce it.
        if !self.key_package_announced(
            lifecycle
                .current_key_package_ref
                .as_deref()
                .unwrap_or_default(),
        )? {
            return Ok(());
        }
        lifecycle.phase = cgka_traits::MaintenancePhase::Fanout;
        self.session.put_key_package_lifecycle(&lifecycle)?;
        let publication = KeyPackagePublication {
            account_id: self.session.self_id().clone(),
            key_package,
            slot_id: lifecycle.stable_slot_id.clone(),
            created_at: artifact.created_at,
            endpoints,
        };
        match self
            .key_packages
            .publish_prepared_key_package(&publication, &artifact)
            .await
        {
            Ok(receipt) => {
                note_key_package_attempt(
                    &mut lifecycle.publication_targets,
                    &publication.endpoints,
                    &receipt.accepted,
                    &receipt.failed,
                    self.wall_clock.now(),
                );
                lifecycle.phase = if lifecycle.publication_targets.iter().all(|target| {
                    matches!(
                        target.state,
                        TransportFanoutAttemptState::Accepted
                            | TransportFanoutAttemptState::PolicyProhibited
                    )
                }) {
                    cgka_traits::MaintenancePhase::Complete
                } else {
                    cgka_traits::MaintenancePhase::Fanout
                };
                self.session.put_key_package_lifecycle(&lifecycle)?;
                Ok(())
            }
            // Paused maintenance only finishes prepared work, so it leaves the
            // replacement for resume and backs off as for any failure.
            Err(error)
                if error.artifact_unusable
                    && !self.maintenance_paused
                    && may_replace_unusable_artifact(&lifecycle) =>
            {
                // Back off as for any failure in case the replacement cannot
                // be staged, so this does not repeat every tick.
                note_key_package_attempt(
                    &mut lifecycle.publication_targets,
                    &publication.endpoints,
                    &[],
                    &[],
                    self.wall_clock.now(),
                );
                self.replace_unusable_current_artifact(&mut lifecycle)?;
                Err(error.into())
            }
            Err(error) => {
                note_key_package_attempt(
                    &mut lifecycle.publication_targets,
                    &publication.endpoints,
                    &[],
                    &[],
                    self.wall_clock.now(),
                );
                lifecycle.phase = cgka_traits::MaintenancePhase::Fanout;
                self.session.put_key_package_lifecycle(&lifecycle)?;
                Err(error.into())
            }
        }
    }

    pub fn key_package_maintenance_requires_catch_up(&self) -> AccountResult<bool> {
        let now = self.wall_clock.now();
        Ok(match self.session.key_package_lifecycle()? {
            None => true,
            Some(lifecycle) => {
                lifecycle.pending_replacement.is_none()
                    && lifecycle.last_consumed_key_package_ref != lifecycle.current_key_package_ref
                    && self.current_key_package_replacement_due(&lifecycle, now)
            }
        })
    }

    /// When the current KeyPackage's refresh next comes due by time alone:
    /// its `refresh_at`, or a week after its publication, whichever is
    /// first. `None` with no lifecycle or no timed refresh. The other reasons
    /// for a catch-up (supersession, a generator or capability change, no
    /// KeyPackage) are not timed; the caller is woken for those (mdk#2923).
    pub fn key_package_maintenance_next_due(&self) -> AccountResult<Option<Timestamp>> {
        Ok(self
            .session
            .key_package_lifecycle()?
            .and_then(|lifecycle| key_package_refresh_next_due(&lifecycle)))
    }

    /// Delete expired private init-key material even when network maintenance
    /// is paused or transport cursor persistence is frozen.
    pub fn sweep_expired_key_package_private_material(&mut self) -> AccountResult<usize> {
        let now = self.wall_clock.now();
        let Some(mut lifecycle) = self.session.key_package_lifecycle()? else {
            return Ok(0);
        };
        let mut retired = Vec::new();
        if lifecycle
            .current_not_after
            .is_some_and(|deadline| deadline <= now)
            && let Some(expired) = lifecycle.current_key_package.take()
        {
            lifecycle.current_key_package_ref = None;
            lifecycle.current_not_before = None;
            lifecycle.current_not_after = None;
            lifecycle.authored_signed_event = None;
            lifecycle.publication_targets.clear();
            lifecycle.refresh_at = None;
            lifecycle.phase = cgka_traits::MaintenancePhase::Retry;
            retired.push(expired);
        }
        if lifecycle
            .pending_replacement
            .as_ref()
            .is_some_and(|pending| pending.not_after <= now)
            && let Some(expired) = lifecycle.pending_replacement.take()
        {
            lifecycle.phase = cgka_traits::MaintenancePhase::Failed;
            retired.push(expired.key_package);
        }
        let marker_migrated = lifecycle.migrate_legacy_consumption_marker();
        let mut retained = Vec::with_capacity(lifecycle.retained_private_material.len());
        for material in lifecycle.retained_private_material.drain(..) {
            if material.delete_at() <= now {
                retired.push(material.key_package);
            } else {
                retained.push(material);
            }
        }
        lifecycle.retained_private_material = retained;
        let deleted = retired.len();
        if deleted > 0 || marker_migrated {
            self.session
                .promote_key_package_lifecycle(&retired, &lifecycle)?;
            let mut activity = self
                .maintenance_activity
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            activity.retired_key_packages =
                activity.retired_key_packages.saturating_add(deleted as u64);
        }
        Ok(deleted)
    }

    pub fn maintenance_status(&self, group_id: &GroupId) -> AccountResult<GroupMaintenanceStatus> {
        self.maintenance_status_in(group_id, None)
    }

    /// [`Self::maintenance_status`], taking the account-wide rows from
    /// `rows` when given instead of loading them for this one group.
    pub fn maintenance_status_in(
        &self,
        group_id: &GroupId,
        rows: Option<&GroupMaintenanceRows>,
    ) -> AccountResult<GroupMaintenanceStatus> {
        let mut obligations = self.session.maintenance_obligations_for_group(group_id)?;
        if self.maintenance_paused {
            // Pause is intentionally process-local. Project it in status
            // without overwriting the durable phase/deadlines needed by resume.
            for obligation in &mut obligations {
                if !matches!(
                    obligation.phase,
                    MaintenancePhase::Complete | MaintenancePhase::Failed
                ) {
                    obligation.phase = MaintenancePhase::Paused;
                }
            }
        }
        Ok(GroupMaintenanceStatus {
            group_id: group_id.clone(),
            state: self.session.group_maintenance(group_id)?,
            obligations,
            evolutions: self.session.group_evolutions_for_group(group_id)?,
            fanouts: match rows {
                Some(rows) => rows.fanouts(group_id).to_vec(),
                None => self
                    .session
                    .transport_fanouts()?
                    .into_iter()
                    .filter(|fanout| fanout.group_id.as_ref() == Some(group_id))
                    .collect(),
            },
            paused: self.maintenance_paused,
        })
    }

    pub fn periodic_maintenance_policy(&self) -> AccountResult<PeriodicMaintenancePolicy> {
        Ok(self.session.periodic_maintenance_policy()?)
    }

    pub fn set_periodic_maintenance_policy(
        &self,
        policy: PeriodicMaintenancePolicy,
    ) -> AccountResult<()> {
        Ok(self.session.put_periodic_maintenance_policy(policy)?)
    }

    pub fn pause_maintenance(&mut self) {
        self.maintenance_paused = true;
    }

    pub fn resume_maintenance(&mut self) {
        self.maintenance_paused = false;
    }

    pub fn maintenance_is_paused(&self) -> bool {
        self.maintenance_paused
    }

    pub fn schedule_manual_self_update(
        &mut self,
        group_id: &GroupId,
    ) -> AccountResult<cgka_traits::MessageId> {
        use sha2::{Digest, Sha256};
        let group = self.session.group_record(group_id)?;
        // There is no leaf left to rotate, and the engine's send gate answers
        // any intent for a terminal copy with exactly this error. Refuse here
        // rather than persist an obligation the sweep can only fail.
        if group.is_terminal() {
            return Err(cgka_traits::EngineError::InvalidTransition(
                cgka_traits::engine_state::InvalidTransition {
                    from: if group.removed {
                        "Removed"
                    } else {
                        "Disbanded"
                    },
                    to: "SelfUpdate",
                    reason: "terminal local group copy has no leaf to rotate",
                },
            )
            .into());
        }
        if let Some(existing) = self
            .session
            .maintenance_obligations_for_group(group_id)?
            .into_iter()
            .find(|obligation| {
                !matches!(
                    obligation.phase,
                    MaintenancePhase::Complete | MaintenancePhase::Failed
                )
            })
        {
            return Ok(existing.id);
        }
        let now = self.wall_clock.now();
        let mut hasher = Sha256::new();
        hasher.update(b"marmot-manual-self-update-v1");
        hasher.update((group_id.as_slice().len() as u64).to_be_bytes());
        hasher.update(group_id.as_slice());
        hasher.update(now.0.to_be_bytes());
        hasher.update(self.entropy.next_u64().to_be_bytes());
        let id = cgka_traits::MessageId::new(hasher.finalize().to_vec());
        let obligation = MaintenanceObligation {
            id: id.clone(),
            group_id: group_id.clone(),
            trigger: MaintenanceTrigger::Manual,
            phase: MaintenancePhase::Quiet,
            created_at: now,
            operational_target_at: None,
            overdue: false,
            eose_deadline_at: None,
            grace_until: None,
            quiet_since: Some(now),
            own_leaf_baseline_hash: Some(self.session.own_leaf_hash(group_id)?),
            sampled_jitter_ms: self
                .entropy
                .sample_inclusive(0, self.maintenance_timing.contention_jitter_max_ms()),
            not_before: None,
            attempt_count: 0,
            semantic_rearm_count: 0,
            last_failure_code: None,
        };
        self.persist_maintenance_obligation(&obligation)?;
        self.maintenance_quiet_monotonic
            .insert(id.clone(), self.monotonic_clock.elapsed());
        Ok(id)
    }

    /// Record successful installation of the temporary post-join history
    /// subscription. The five-minute EOSE deadline starts here.
    pub fn mark_post_join_subscription_installed(&self, group_id: &GroupId) -> AccountResult<()> {
        let now = self.wall_clock.now();
        for mut obligation in self.session.maintenance_obligations_for_group(group_id)? {
            if obligation.trigger == MaintenanceTrigger::PostJoin
                && obligation.phase == MaintenancePhase::CatchUp
                && obligation.eose_deadline_at.is_none()
            {
                obligation.eose_deadline_at = Some(Timestamp(
                    now.0
                        .saturating_add(self.maintenance_timing.eose_timeout.as_secs()),
                ));
                self.persist_maintenance_obligation(&obligation)?;
            }
        }
        Ok(())
    }

    pub fn mark_post_join_eose(&self, group_id: &GroupId) -> AccountResult<()> {
        for obligation in self.post_join_eose_updates(group_id)? {
            self.persist_maintenance_obligation(&obligation)?;
        }
        Ok(())
    }

    /// Prepare the domain transition without writing. The exclusive account
    /// worker can atomically persist these records with its recovery proof on
    /// one storage connection. Already-running grace timers are left unchanged.
    pub fn post_join_eose_updates(
        &self,
        group_id: &GroupId,
    ) -> AccountResult<Vec<MaintenanceObligation>> {
        let now = self.wall_clock.now();
        let mut updates = Vec::new();
        for mut obligation in self.session.maintenance_obligations_for_group(group_id)? {
            if obligation.trigger == MaintenanceTrigger::PostJoin
                && matches!(
                    obligation.phase,
                    MaintenancePhase::CatchUp | MaintenancePhase::EoseTimeout
                )
            {
                obligation.phase = MaintenancePhase::Grace;
                obligation.grace_until = Some(Timestamp(
                    now.0
                        .saturating_add(self.maintenance_timing.post_eose_grace.as_secs()),
                ));
                updates.push(obligation);
            }
        }
        Ok(updates)
    }

    /// The group's post-join history fetch. Its completion with
    /// [`PostJoinHistoryFetchOutcome::Fetched`] means this device has fetched
    /// and processed the group messages its delivery endpoints hold from its
    /// join epoch on. A replacement Welcome starts a new fetch, so an earlier
    /// copy's completion never answers for the current one. `None` for a
    /// created group and for copies joined before fetches were recorded.
    pub fn post_join_history_fetch(
        &self,
        group_id: &GroupId,
    ) -> AccountResult<Option<PostJoinHistoryFetch>> {
        Ok(self
            .session
            .group_maintenance(group_id)?
            .and_then(|state| state.post_join_history))
    }

    /// Record that the subscription for the group's owed post-join history
    /// fetch is installed, and return that fetch's id. Its deadline starts
    /// here, and again at every installation. The self-update obligation's
    /// own deadline is [`Self::mark_post_join_subscription_installed`]'s.
    pub fn start_post_join_history_fetch(
        &self,
        group_id: &GroupId,
    ) -> AccountResult<Option<cgka_traits::MessageId>> {
        let Some(mut state) = self.session.group_maintenance(group_id)? else {
            return Ok(None);
        };
        let Some(fetch) = state
            .post_join_history
            .as_mut()
            .filter(|fetch| fetch.completion.is_none())
        else {
            return Ok(None);
        };
        fetch.deadline_at =
            Some(Timestamp(self.wall_clock.now().0.saturating_add(
                self.maintenance_timing.eose_timeout.as_secs(),
            )));
        let id = fetch.obligation_id.clone();
        self.session.put_group_maintenance(&state)?;
        Ok(Some(id))
    }

    /// End the owed post-join history fetch `fetch` as fetched: its
    /// subscription reached end-of-stored-events and everything it delivered
    /// has been processed. Returns the recorded completion, or `None` when
    /// `fetch` is no longer the group's owed fetch.
    pub fn finish_post_join_history_fetch(
        &self,
        group_id: &GroupId,
        fetch: &cgka_traits::MessageId,
    ) -> AccountResult<Option<PostJoinHistoryFetchCompletion>> {
        self.end_post_join_history_fetch(group_id, fetch, PostJoinHistoryFetchOutcome::Fetched)
    }

    /// End the owed post-join history fetch `fetch` as expired once the
    /// deadline its installation set has passed. Only for a fetch whose
    /// subscription has reached no end-of-stored-events. Returns the recorded
    /// completion, or `None` while the fetch goes on.
    pub fn expire_post_join_history_fetch(
        &self,
        group_id: &GroupId,
        fetch: &cgka_traits::MessageId,
    ) -> AccountResult<Option<PostJoinHistoryFetchCompletion>> {
        self.end_post_join_history_fetch(
            group_id,
            fetch,
            PostJoinHistoryFetchOutcome::DeadlineExpired,
        )
    }

    fn end_post_join_history_fetch(
        &self,
        group_id: &GroupId,
        fetch: &cgka_traits::MessageId,
        outcome: PostJoinHistoryFetchOutcome,
    ) -> AccountResult<Option<PostJoinHistoryFetchCompletion>> {
        let Some(mut state) = self.session.group_maintenance(group_id)? else {
            return Ok(None);
        };
        // A fetch that is no longer the group's current one is left alone.
        let Some(current) = state
            .post_join_history
            .as_mut()
            .filter(|current| current.obligation_id == *fetch && current.completion.is_none())
        else {
            return Ok(None);
        };
        if outcome == PostJoinHistoryFetchOutcome::DeadlineExpired
            && !current
                .deadline_at
                .is_some_and(|deadline| deadline <= self.wall_clock.now())
        {
            return Ok(None);
        }
        let completion = PostJoinHistoryFetchCompletion {
            outcome,
            completed_at_ms: self.wall_clock.now_ms(),
        };
        current.completion = Some(completion);
        self.session.put_group_maintenance(&state)?;
        Ok(Some(completion))
    }

    /// Only call this for authenticated, valid MLS commits or proposals.
    pub fn note_valid_state_bearing_input(&mut self, group_id: &GroupId) -> AccountResult<()> {
        let now = self.wall_clock.now();
        for obligation in self.session.maintenance_obligations_for_group(group_id)? {
            self.reset_obligation_quiet(obligation, now)?;
        }
        Ok(())
    }

    fn reset_obligation_quiet(
        &mut self,
        mut obligation: MaintenanceObligation,
        now: Timestamp,
    ) -> AccountResult<()> {
        if !matches!(
            obligation.phase,
            MaintenancePhase::CatchUp
                | MaintenancePhase::EoseTimeout
                | MaintenancePhase::Grace
                | MaintenancePhase::Quiet
                | MaintenancePhase::Jitter
                | MaintenancePhase::Overdue
        ) {
            return Ok(());
        }
        obligation.phase = MaintenancePhase::Quiet;
        obligation.quiet_since = Some(now);
        obligation.not_before = None;
        self.persist_maintenance_obligation(&obligation)?;
        self.maintenance_quiet_monotonic
            .insert(obligation.id, self.monotonic_clock.elapsed());
        Ok(())
    }

    /// Advance durable maintenance state and publish work whose safety windows
    /// have elapsed. Callers may invoke this from any timer cadence; all
    /// deadlines and sampled jitter are persisted.
    pub async fn run_due_maintenance(&mut self) -> AccountResult<AccountDeviceEffects> {
        self.run_due_maintenance_holding(&[]).await
    }

    /// [`Self::run_due_maintenance`], but no new self-update commit is
    /// authored for a `held` group. The caller holds a group it knows has
    /// moved past this device's local epoch: a commit from that epoch forks the
    /// group (mdk#2258). A held obligation stays owed and retries on a later
    /// sweep; publication of an already-staged commit is not held.
    pub async fn run_due_maintenance_holding(
        &mut self,
        held: &[GroupId],
    ) -> AccountResult<AccountDeviceEffects> {
        use sha2::{Digest, Sha256};

        self.session.refresh_welcome_holds();
        self.sweep_expired_key_package_private_material()?;
        self.reconcile_confirmed_own_leaf_rotations(&[]);
        let mut output = AccountDeviceEffects::default();
        // Hydration recreates the publication edge for a surviving staged
        // evolution. Consume that edge before consulting the semantic
        // obligation below. Otherwise a successful retry can confirm the
        // pending evolution, drain the still-buffered hydration work as part
        // of confirmation, and attempt to confirm the same PendingStateRef a
        // second time. The durable fanout backoff in publish_one still makes
        // this safe to call before a failed target is retryable.
        if self
            .session
            .recover_pending_application_authority()
            .is_err()
        {
            tracing::warn!(target: TRACE_TARGET, method = "run_due_maintenance",
                error_kind = "source_authority_retry", "source authority remains retryable");
        }
        let recovered = self.session.drain();
        if !recovered.is_empty() {
            let recovered = boxed(|| self.publish_session_effects(recovered)).await?;
            output.absorb_account_effects(recovered);
        }
        let now = self.wall_clock.now();
        // Before anything reads an evolution or an obligation: repair the
        // supersessions whose announcement never reached
        // `reconcile_superseded_maintenance`. This is the maintenance sweep, so
        // it is where a stranded evolution would otherwise do its damage.
        let superseded = self.reconcile_superseded_maintenance_from_state(now)?;
        output.superseded_intents.extend(superseded);
        // A device sets its tag signature key before it stages a KeyPackage,
        // so the KeyPackage is built tagged (mdk#2628 3.1d). Until the merged
        // roster carries the key, nothing is staged, announced or published.
        let tag_key = boxed(|| self.set_device_tag_key_for_maintenance(held)).await;
        output.absorb_account_effects(tag_key);
        let tag_key_settled = self.device_tag_key_settled()?;
        // While a device group is set, its roster names a KeyPackage before
        // it reaches the slot (mdk#2628 3.4), so announce first.
        if tag_key_settled {
            let announced = boxed(|| self.announce_key_package_for_maintenance(held)).await?;
            output.absorb_account_effects(announced);
        }
        // Fanout of an already-acknowledged exact event is publication
        // recovery, not a new preparation, so it continues while paused.
        if self.key_package_has_pending_fanout()? {
            let started = self.monotonic_clock.elapsed();
            let result = self.retry_key_package_fanout().await;
            self.note_key_package_maintenance_attempt(result.is_err());
            self.note_maintenance_duration(started, true, result.is_err());
            if let Err(error) = &result {
                tracing::warn!(
                    target: TRACE_TARGET,
                    method = "run_due_maintenance",
                    error_kind = error.key_package_failure_kind("key_package_fanout_retry"),
                    "key package exact-event fanout remains retryable"
                );
            }
        }
        let key_package_due = tag_key_settled && self.key_package_network_maintenance_due()?;
        // Paused maintenance may finish existing publication intent, but an
        // obsolete pending replacement requires fresh private material and
        // therefore waits for resume like every other new preparation.
        let key_package_prepared = self
            .session
            .key_package_lifecycle()?
            .is_some_and(|lifecycle| {
                lifecycle
                    .pending_replacement
                    .as_ref()
                    .is_some_and(|pending| !self.pending_replacement_obsolete(&lifecycle, pending))
            });
        if key_package_due && (!self.maintenance_paused || key_package_prepared) {
            let started = self.monotonic_clock.elapsed();
            match self.publish_fresh_key_package().await {
                // Nothing went out: the announcement above is not confirmed
                // yet, and a later pass publishes.
                Err(AccountError::KeyPackageAnnouncementPending) => tracing::debug!(
                    target: TRACE_TARGET,
                    method = "run_due_maintenance",
                    "key package publication waits for its announcement"
                ),
                result => {
                    self.note_key_package_maintenance_attempt(result.is_err());
                    self.note_maintenance_duration(started, true, result.is_err());
                    if let Err(error) = result {
                        tracing::warn!(
                            target: TRACE_TARGET,
                            method = "run_due_maintenance",
                            error_kind = if matches!(error, AccountError::ClockSkewBlocked) {
                                "clock_skew_blocked"
                            } else {
                                error.key_package_failure_kind("key_package_retry")
                            },
                            "key package maintenance remains retryable"
                        );
                    }
                }
            }
        }
        self.retry_confirmed_transport_fanouts(&mut output).await?;
        boxed(|| self.deliver_watched_welcomes(&mut output)).await?;
        // Roster housekeeping waits behind the KeyPackage steps' commits
        // (mdk#2628 3.1d).
        let expired = boxed(|| self.drop_expired_removed_slots_for_maintenance(held)).await;
        output.absorb_account_effects(expired);

        // Old groups have no enrollment row and are intentionally excluded.
        let active_obligations = self.session.maintenance_obligations()?;
        for group_id in if self.maintenance_paused {
            Vec::new()
        } else {
            self.session.live_group_ids()?
        } {
            if self.pending_leaf_reconciliations.contains_key(&group_id) {
                continue;
            }
            let Some(Some(mut state)) =
                skips_group_this_tick(self.session.group_maintenance(&group_id))?
            else {
                continue;
            };
            if !state.periodic_enrolled {
                continue;
            }
            let has_active = active_obligations.iter().any(|obligation| {
                obligation.group_id == group_id
                    && !matches!(
                        obligation.phase,
                        MaintenancePhase::Complete | MaintenancePhase::Failed
                    )
            });
            if has_active {
                continue;
            }
            if state.next_periodic_rotation_at.is_none() {
                let baseline = Self::periodic_baseline(&state, &active_obligations, None, now);
                state.next_periodic_rotation_at =
                    Some(self.fresh_periodic_deadline(&group_id, baseline)?);
                self.session.put_group_maintenance(&state)?;
            }
            if state
                .next_periodic_rotation_at
                .is_some_and(|deadline| deadline <= now)
            {
                let mut hasher = Sha256::new();
                hasher.update(b"marmot-periodic-self-update-v1");
                hasher.update((group_id.as_slice().len() as u64).to_be_bytes());
                hasher.update(group_id.as_slice());
                hasher.update(
                    state
                        .next_periodic_rotation_at
                        .expect("checked above")
                        .0
                        .to_be_bytes(),
                );
                let id = cgka_traits::MessageId::new(hasher.finalize().to_vec());
                let obligation = MaintenanceObligation {
                    id: id.clone(),
                    group_id: group_id.clone(),
                    trigger: MaintenanceTrigger::Periodic,
                    phase: MaintenancePhase::Quiet,
                    created_at: now,
                    operational_target_at: None,
                    overdue: false,
                    eose_deadline_at: None,
                    grace_until: None,
                    quiet_since: Some(now),
                    own_leaf_baseline_hash: Some(self.session.own_leaf_hash(&group_id)?),
                    sampled_jitter_ms: self.entropy.sample_inclusive(0, 15 * 60 * 1_000),
                    not_before: None,
                    attempt_count: 0,
                    semantic_rearm_count: 0,
                    last_failure_code: None,
                };
                self.persist_maintenance_obligation(&obligation)?;
                self.maintenance_quiet_monotonic
                    .insert(id, self.monotonic_clock.elapsed());
            }
        }

        if !self.maintenance_paused {
            self.schedule_leaf_refreshes(now)?;
        }

        let mut obligations = self.session.maintenance_obligations()?;
        obligations.sort_by_key(|obligation| obligation.created_at);
        for mut obligation in obligations {
            if self
                .pending_leaf_reconciliations
                .contains_key(&obligation.group_id)
            {
                continue;
            }
            if matches!(
                obligation.phase,
                MaintenancePhase::Complete | MaintenancePhase::Failed
            ) {
                continue;
            }
            // An obligation outlives the membership it was minted under:
            // disenrollment is event-driven only, so a removal this device
            // never saw as an event leaves it live against a terminal record.
            // Driving it means a `SelfUpdate` the removed-copy send gate is
            // guaranteed to refuse — `Retry` + `maintenance_send_failed` with
            // no attempt cap, every tick forever. Reach the event-driven
            // cleanup's verdict here instead.
            let Some(group) =
                skips_group_this_tick(self.session.group_record(&obligation.group_id))?
            else {
                continue;
            };
            if group.is_terminal() {
                obligation.phase = MaintenancePhase::Failed;
                obligation.last_failure_code = Some("local_member_removed".into());
                self.persist_maintenance_obligation(&obligation)?;
                self.maintenance_quiet_monotonic.remove(&obligation.id);
                continue;
            }
            // A pending departure refuses every send but its own. It waits
            // rather than fails: the removal landing ends it through the
            // terminal verdict above, and a reorg that restores the membership
            // must find its rotation still owed.
            if self.session.leave_in_progress(&obligation.group_id)?
                || self.session.disbanding_in_progress(&obligation.group_id)?
            {
                continue;
            }
            if let Some(baseline) = &obligation.own_leaf_baseline_hash
                && baseline.as_slice()
                    != self.session.own_leaf_hash(&obligation.group_id)?.as_slice()
            {
                // A reopen can lose the event, but not the live obligation's
                // evidence that the selected local leaf already rotated.
                self.pending_leaf_reconciliations
                    .entry(obligation.group_id.clone())
                    .or_insert(None);
                self.reconcile_confirmed_own_leaf_rotations(&[]);
                continue;
            }
            let original_obligation = obligation.clone();
            if obligation
                .operational_target_at
                .is_some_and(|target| target <= now)
            {
                obligation.overdue = true;
            }

            if self.maintenance_paused {
                let Some(evolutions) = skips_group_this_tick(
                    self.session
                        .group_evolutions_for_group(&obligation.group_id),
                )?
                else {
                    continue;
                };
                let has_prepared_evolution = evolutions.into_iter().any(|evolution| {
                    evolution.phase != GroupEvolutionPhase::SupersededByConvergence
                        && matches!(
                            &evolution.semantic,
                            GroupEvolutionSemantic::SelfUpdate {
                                obligation_id,
                                ..
                            } if obligation_id.as_ref() == Some(&obligation.id)
                        )
                        && matches!(
                            evolution.phase,
                            GroupEvolutionPhase::Prepared | GroupEvolutionPhase::Attempting
                        )
                });
                if !has_prepared_evolution {
                    self.put_maintenance_obligation_if_changed(&original_obligation, &obligation)?;
                    continue;
                }
            }

            match obligation.phase {
                MaintenancePhase::CatchUp => {
                    if obligation
                        .eose_deadline_at
                        .is_some_and(|deadline| deadline <= now)
                    {
                        obligation.phase = MaintenancePhase::EoseTimeout;
                        obligation.grace_until = Some(Timestamp(
                            now.0
                                .saturating_add(self.maintenance_timing.post_eose_grace.as_secs()),
                        ));
                    }
                    self.put_maintenance_obligation_if_changed(&original_obligation, &obligation)?;
                    continue;
                }
                MaintenancePhase::EoseTimeout | MaintenancePhase::Grace => {
                    if obligation.grace_until.is_none_or(|deadline| deadline > now) {
                        self.put_maintenance_obligation_if_changed(
                            &original_obligation,
                            &obligation,
                        )?;
                        continue;
                    }
                    obligation.phase = MaintenancePhase::Quiet;
                    obligation.quiet_since = Some(now);
                    self.maintenance_quiet_monotonic
                        .insert(obligation.id.clone(), self.monotonic_clock.elapsed());
                    self.put_maintenance_obligation_if_changed(&original_obligation, &obligation)?;
                    continue;
                }
                MaintenancePhase::Quiet => {
                    let quiet_long_enough = self
                        .maintenance_quiet_monotonic
                        .get(&obligation.id)
                        .map(|started| {
                            self.monotonic_clock.elapsed().saturating_sub(*started)
                                >= self.maintenance_timing.quiet
                        })
                        .unwrap_or_else(|| {
                            obligation.quiet_since.is_some_and(|started| {
                                now.0.saturating_sub(started.0)
                                    >= self.maintenance_timing.quiet.as_secs()
                            })
                        });
                    if !quiet_long_enough {
                        self.put_maintenance_obligation_if_changed(
                            &original_obligation,
                            &obligation,
                        )?;
                        continue;
                    }
                    // Periodic rotations keep their own wide spread; only the
                    // contention jitter of post-join and manual rotations is
                    // bounded by the configured window.
                    let jitter_ms = if obligation.trigger == MaintenanceTrigger::Periodic {
                        obligation.sampled_jitter_ms
                    } else {
                        obligation
                            .sampled_jitter_ms
                            .min(self.maintenance_timing.contention_jitter_max_ms())
                    };
                    let jitter_secs = jitter_ms.saturating_add(999) / 1_000;
                    obligation.phase = MaintenancePhase::Jitter;
                    obligation.not_before = Some(Timestamp(now.0.saturating_add(jitter_secs)));
                    self.put_maintenance_obligation_if_changed(&original_obligation, &obligation)?;
                    continue;
                }
                MaintenancePhase::Jitter => {
                    if obligation.not_before.is_none_or(|deadline| deadline > now) {
                        self.put_maintenance_obligation_if_changed(
                            &original_obligation,
                            &obligation,
                        )?;
                        continue;
                    }
                }
                MaintenancePhase::PendingPublication | MaintenancePhase::Retry => {
                    let Some(evolutions) = skips_group_this_tick(
                        self.session
                            .group_evolutions_for_group(&obligation.group_id),
                    )?
                    else {
                        continue;
                    };
                    if let Some(evolution) = evolutions.into_iter().find(|evolution| {
                        evolution.phase != GroupEvolutionPhase::SupersededByConvergence
                            && matches!(
                                &evolution.semantic,
                                GroupEvolutionSemantic::SelfUpdate {
                                    obligation_id,
                                    ..
                                } if obligation_id.as_ref() == Some(&obligation.id)
                            )
                    }) {
                        if evolution.phase == GroupEvolutionPhase::Confirmed {
                            self.complete_maintenance_obligation(&mut obligation, now)?;
                            continue;
                        }
                        // The exact commit is a pending frozen fanout. Resume it
                        // rather than staging a second rotation over it.
                        if let Some(message_id) = evolution.signed_message_id.as_ref()
                            && self
                                .session
                                .outbound_fanouts_for_group(&obligation.group_id)?
                                .iter()
                                .any(|fanout| {
                                    fanout.message_id() == message_id
                                        && matches!(fanout.mls_state(), FanoutMlsState::Pending(_))
                                })
                        {
                            self.maintenance_activity
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .self_update_attempts += 1;
                            let started = self.monotonic_clock.elapsed();
                            let resumed = boxed(|| {
                                self.resume_outbound_fanouts_for_group(Some(&obligation.group_id))
                            })
                            .await
                            .map(|(effects, _blocked_groups)| effects);
                            let confirmed = resumed.as_ref().is_ok_and(|effects| {
                                effects
                                    .pending
                                    .iter()
                                    .any(|r| matches!(r, PendingResolution::Confirmed { .. }))
                            });
                            self.note_maintenance_duration(
                                started,
                                false,
                                resumed
                                    .as_ref()
                                    .map_or(true, |e| !e.failures.is_empty() && !confirmed),
                            );
                            let resumed = resumed.inspect_err(|_error| {
                                self.maintenance_activity
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .failed_attempts += 1;
                            })?;
                            if !confirmed && !resumed.failures.is_empty() {
                                let mut activity = self
                                    .maintenance_activity
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner());
                                activity.failed_attempts =
                                    activity.failed_attempts.saturating_add(1);
                            }
                            output.absorb_account_effects(resumed);
                            if confirmed {
                                self.complete_maintenance_obligation(&mut obligation, now)?;
                            } else {
                                obligation.phase = MaintenancePhase::PendingPublication;
                                self.put_maintenance_obligation_if_changed(
                                    &original_obligation,
                                    &obligation,
                                )?;
                            }
                            continue;
                        }
                        if let (Some(pending), Some(message_id)) =
                            (evolution.pending_ref, evolution.signed_message_id)
                            && let Some(fanout) = self.session.transport_fanout(&message_id)?
                        {
                            let retry = SessionEffects {
                                events: Vec::new(),
                                publish: vec![PublishWork::AutoPublish {
                                    msg: fanout.exact_message,
                                    pending,
                                    welcomes: Vec::new(),
                                }],
                                queued: Vec::new(),
                                pending_convergence: Vec::new(),
                            };
                            self.maintenance_activity
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .self_update_attempts += 1;
                            let started = self.monotonic_clock.elapsed();
                            let retried = boxed(|| self.publish_session_effects(retry)).await;
                            self.note_maintenance_duration(
                                started,
                                false,
                                retried.as_ref().map_or(true, |e| {
                                    !e.failures.is_empty()
                                        && !e.pending.iter().any(|r| {
                                            matches!(r, PendingResolution::Confirmed { .. })
                                        })
                                }),
                            );
                            let retried = retried.inspect_err(|_error| {
                                self.maintenance_activity
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .failed_attempts += 1;
                            })?;
                            let confirmed = retried.pending.iter().any(|resolution| {
                                matches!(
                                    resolution,
                                    PendingResolution::Confirmed { pending: resolved }
                                        if *resolved == pending
                                )
                            });
                            if !confirmed && !retried.failures.is_empty() {
                                let mut activity = self
                                    .maintenance_activity
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner());
                                activity.failed_attempts =
                                    activity.failed_attempts.saturating_add(1);
                            }
                            output.absorb_account_effects(retried);
                            if !confirmed {
                                obligation.phase = MaintenancePhase::PendingPublication;
                                obligation.attempt_count =
                                    obligation.attempt_count.saturating_add(1);
                                self.put_maintenance_obligation_if_changed(
                                    &original_obligation,
                                    &obligation,
                                )?;
                            }
                            continue;
                        }
                    }
                    obligation.phase = MaintenancePhase::Retry;
                }
                MaintenancePhase::Paused
                | MaintenancePhase::Overdue
                | MaintenancePhase::ClockSkewBlocked
                | MaintenancePhase::Fanout
                | MaintenancePhase::SupersededByConvergence => {
                    obligation.phase = MaintenancePhase::Retry;
                }
                MaintenancePhase::Complete | MaintenancePhase::Failed => continue,
            }

            if self
                .session
                .has_pending_convergence_inputs(&obligation.group_id)?
                || self
                    .session
                    .quarantined_groups()
                    .iter()
                    .any(|(group_id, _)| group_id == &obligation.group_id)
            {
                obligation.phase = MaintenancePhase::Retry;
                obligation.last_failure_code = Some("safety_gate".into());
                self.put_maintenance_obligation_if_changed(&original_obligation, &obligation)?;
                continue;
            }
            if held.contains(&obligation.group_id) {
                obligation.phase = MaintenancePhase::Retry;
                obligation.last_failure_code = Some("epoch_gap_hold".into());
                self.put_maintenance_obligation_if_changed(&original_obligation, &obligation)?;
                continue;
            }
            // Each owed or refused commit holds on its own `since`: an old
            // refusal must not let a self-update build at once on a commit
            // that confirmed a minute ago and is still owed (mdk#2333).
            if self
                .undelivered_commits_in(&obligation.group_id, None)?
                .0
                .iter()
                .any(|commit| {
                    now.0.saturating_sub(commit.since.0) < COMMIT_DELIVERY_SELF_UPDATE_HOLD_SECS
                })
            {
                obligation.phase = MaintenancePhase::Retry;
                obligation.last_failure_code = Some("commit_delivery_hold".into());
                self.put_maintenance_obligation_if_changed(&original_obligation, &obligation)?;
                continue;
            }

            let group_id = obligation.group_id.clone();
            self.maintenance_activity
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .self_update_attempts += 1;
            let started = self.monotonic_clock.elapsed();
            let sent = boxed(|| {
                self.send(SendIntent::SelfUpdate {
                    group_id: group_id.clone(),
                })
            })
            .await;
            self.note_maintenance_duration(
                started,
                false,
                sent.as_ref().map_or(true, |e| {
                    !e.failures.is_empty()
                        && !e
                            .pending
                            .iter()
                            .any(|r| matches!(r, PendingResolution::Confirmed { .. }))
                }),
            );
            match sent {
                Ok(effects) => {
                    let confirmed = effects.pending.iter().any(|resolution| {
                        matches!(resolution, PendingResolution::Confirmed { .. })
                    });
                    if !confirmed && !effects.failures.is_empty() {
                        let mut activity = self
                            .maintenance_activity
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        activity.failed_attempts = activity.failed_attempts.saturating_add(1);
                    }
                    output.absorb_account_effects(effects);
                    if !confirmed {
                        obligation.phase = MaintenancePhase::PendingPublication;
                        obligation.attempt_count = obligation.attempt_count.saturating_add(1);
                        self.put_maintenance_obligation_if_changed(
                            &original_obligation,
                            &obligation,
                        )?;
                    }
                }
                Err(error) => {
                    self.maintenance_activity
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .failed_attempts += 1;
                    obligation.phase = MaintenancePhase::Retry;
                    obligation.attempt_count = obligation.attempt_count.saturating_add(1);
                    obligation.last_failure_code = Some(
                        match error {
                            AccountError::Transport(_) => "maintenance_transport_failed",
                            _ => "maintenance_send_failed",
                        }
                        .into(),
                    );
                    self.put_maintenance_obligation_if_changed(&original_obligation, &obligation)?;
                }
            }
        }
        Ok(output)
    }

    /// Queue a self-update when an own leaf is missing supported components.
    /// The normal quiet period, contention jitter, and commit holds apply.
    ///
    /// This pass only schedules. A group whose state cannot be read is skipped
    /// for this tick; it never stops maintenance for the rest of the account.
    fn schedule_leaf_refreshes(&mut self, now: Timestamp) -> AccountResult<()> {
        let active_obligations = self.session.maintenance_obligations()?;
        for group_id in self.session.live_group_ids()? {
            if self.pending_leaf_reconciliations.contains_key(&group_id) {
                continue;
            }
            if let Err(error) = self.schedule_leaf_refresh(&group_id, now, &active_obligations) {
                tracing::warn!(
                    target: TRACE_TARGET,
                    method = "schedule_leaf_refreshes",
                    error_kind = error
                        .as_engine_error()
                        .map_or("other", EngineError::privacy_safe_kind),
                    "leaf refresh scheduling skipped a group this tick"
                );
            }
        }
        Ok(())
    }

    fn schedule_leaf_refresh(
        &mut self,
        group_id: &GroupId,
        now: Timestamp,
        active_obligations: &[MaintenanceObligation],
    ) -> AccountResult<()> {
        use sha2::{Digest, Sha256};

        let elapsed = self.monotonic_clock.elapsed();
        let recently_checked = self
            .component_migration_checked_at
            .get(group_id)
            .is_some_and(|checked| elapsed.saturating_sub(*checked) < COMPONENT_MIGRATION_RECHECK);
        if recently_checked {
            return Ok(());
        }
        self.component_migration_checked_at
            .insert(group_id.clone(), elapsed);
        let Some(stored) = skips_group_this_tick(self.session.group_maintenance(group_id))? else {
            return Ok(());
        };
        let Some(missing) =
            skips_group_this_tick(self.session.own_leaf_missing_app_components(group_id))?
        else {
            return Ok(());
        };
        // Any self-update already in flight refreshes the leaf too.
        let has_active = active_obligations.iter().any(|obligation| {
            obligation.group_id == *group_id
                && !matches!(
                    obligation.phase,
                    MaintenancePhase::Complete | MaintenancePhase::Failed
                )
        });
        if !missing.is_empty() && !has_active {
            let mut hasher = Sha256::new();
            hasher.update(b"marmot-leaf-refresh-self-update-v1");
            hasher.update((group_id.as_slice().len() as u64).to_be_bytes());
            hasher.update(group_id.as_slice());
            hasher.update(now.0.to_be_bytes());
            let id = cgka_traits::MessageId::new(hasher.finalize().to_vec());
            if self.session.maintenance_obligation(&id)?.is_none() {
                let obligation = MaintenanceObligation {
                    id: id.clone(),
                    group_id: group_id.clone(),
                    trigger: MaintenanceTrigger::Periodic,
                    phase: MaintenancePhase::Quiet,
                    created_at: now,
                    operational_target_at: None,
                    overdue: false,
                    eose_deadline_at: None,
                    grace_until: None,
                    quiet_since: Some(now),
                    own_leaf_baseline_hash: Some(self.session.own_leaf_hash(group_id)?),
                    sampled_jitter_ms: self.entropy.sample_inclusive(0, 15 * 60 * 1_000),
                    not_before: None,
                    attempt_count: 0,
                    semantic_rearm_count: 0,
                    last_failure_code: None,
                };
                self.persist_maintenance_obligation(&obligation)?;
                self.maintenance_quiet_monotonic.insert(id, elapsed);
            }
        }

        // Older builds stored a separate deadline before queuing the obligation.
        if let Some(mut state) = stored
            && state.leaf_refresh_due_at.is_some()
        {
            state.leaf_refresh_due_at = None;
            self.session.put_group_maintenance(&state)?;
        }
        Ok(())
    }

    fn note_maintenance_duration(
        &self,
        started: std::time::Duration,
        key_package: bool,
        failed: bool,
    ) {
        let duration = self.monotonic_clock.elapsed().saturating_sub(started);
        let mut activity = self
            .maintenance_activity
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if activity.attempt_durations.len() < 256 {
            activity.attempt_durations.push(MaintenanceAttemptDuration {
                key_package,
                failed,
                duration,
            });
        }
    }

    fn note_key_package_maintenance_attempt(&self, failed: bool) {
        let mut activity = self
            .maintenance_activity
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        activity.key_package_attempts = activity.key_package_attempts.saturating_add(1);
        if failed {
            activity.key_package_failed_attempts =
                activity.key_package_failed_attempts.saturating_add(1);
        }
    }

    pub fn take_maintenance_activity(&self) -> MaintenanceActivity {
        std::mem::take(
            &mut *self
                .maintenance_activity
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
        )
    }
    fn persist_maintenance_obligation(&self, after: &MaintenanceObligation) -> AccountResult<()> {
        let before = self
            .session
            .maintenance_obligation(&after.id)?
            .map(|v| v.phase);
        self.session.put_maintenance_obligation(after)?;
        if before.as_ref() != Some(&after.phase) {
            let mut activity = self
                .maintenance_activity
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let count = match after.phase {
                MaintenancePhase::Complete => &mut activity.completed_transitions,
                MaintenancePhase::Failed => &mut activity.failed_transitions,
                MaintenancePhase::Retry
                | MaintenancePhase::ClockSkewBlocked
                | MaintenancePhase::EoseTimeout
                | MaintenancePhase::Paused => &mut activity.deferred_transitions,
                _ => return Ok(()),
            };
            *count = count.saturating_add(1);
        }
        Ok(())
    }

    fn put_maintenance_obligation_if_changed(
        &self,
        before: &MaintenanceObligation,
        after: &MaintenanceObligation,
    ) -> AccountResult<()> {
        if before != after {
            self.persist_maintenance_obligation(after)?;
        }
        Ok(())
    }

    pub fn maintenance_run_summary(
        &self,
        effects: &AccountDeviceEffects,
    ) -> AccountResult<cgka_traits::MaintenanceRunSummary> {
        let obligations = self.session.maintenance_obligations()?;
        let lifecycle = self.session.key_package_lifecycle()?;
        let fanouts = self.session.transport_fanouts()?;
        let deferred = obligations
            .iter()
            .filter(|obligation| {
                !matches!(
                    obligation.phase,
                    MaintenancePhase::Complete | MaintenancePhase::Failed
                )
            })
            .count()
            + usize::from(
                lifecycle
                    .as_ref()
                    .is_some_and(|state| state.pending_replacement.is_some()),
            );
        // Self-update commits publish through frozen fanouts (mdk#2255);
        // legacy records only finish rotations staged before that change.
        let evolution_commits = self
            .session
            .group_evolutions()?
            .into_iter()
            .filter_map(|evolution| evolution.signed_message_id)
            .collect::<HashSet<_>>();
        let frozen_ambiguous = self
            .session
            .outbound_fanouts()?
            .iter()
            .filter(|fanout| {
                evolution_commits.contains(fanout.message_id()) && fanout.possible_exposure()
            })
            .count();
        let ambiguous_exposure = fanouts
            .iter()
            .filter(|fanout| fanout.possible_exposure)
            .count()
            + frozen_ambiguous
            + usize::from(lifecycle.as_ref().is_some_and(|state| {
                state.pending_replacement.as_ref().is_some_and(|pending| {
                    pending.last_failure_code.as_deref() == Some("ambiguous_exposure")
                })
            }));
        let failures = effects.failures.len()
            + obligations
                .iter()
                .filter(|obligation| obligation.phase == MaintenancePhase::Failed)
                .count();
        Ok(cgka_traits::MaintenanceRunSummary {
            published: saturating_u32(effects.reports.len()),
            message_ids: effects
                .reports
                .iter()
                .map(|report| report.message_id.clone())
                .collect(),
            deferred: saturating_u32(deferred),
            ambiguous_exposure: saturating_u32(ambiguous_exposure),
            failures: saturating_u32(failures),
        })
    }

    fn complete_maintenance_obligation(
        &mut self,
        obligation: &mut MaintenanceObligation,
        completed_at: Timestamp,
    ) -> AccountResult<()> {
        if let Some(mut state) = self.session.group_maintenance(&obligation.group_id)? {
            state.last_own_leaf_rotation_at = Some(completed_at);
            state.next_periodic_rotation_at = if state.periodic_enrolled {
                Some(self.fresh_periodic_deadline(&obligation.group_id, completed_at)?)
            } else {
                None
            };
            self.session.put_group_maintenance(&state)?;
        }
        // Keep a live retry owner until the deadline write has succeeded.
        obligation.phase = MaintenancePhase::Complete;
        obligation.last_failure_code = None;
        self.persist_maintenance_obligation(obligation)?;
        self.maintenance_quiet_monotonic.remove(&obligation.id);
        Ok(())
    }

    pub async fn create_group(
        &mut self,
        request: CreateGroupRequest,
    ) -> AccountResult<(GroupId, AccountDeviceEffects)> {
        let CreateGroupEffects { group_id, effects } = self.session.create_group(request).await?;
        self.note_founding_welcomes(&effects);
        let effects = self.publish_session_effects(effects).await?;
        Ok((group_id, effects))
    }

    pub fn constructable_capabilities(
        &self,
        key_packages: &[cgka_traits::engine::KeyPackage],
    ) -> AccountResult<cgka_traits::capabilities::GroupCapabilities> {
        Ok(self.session.constructable_capabilities(key_packages)?)
    }

    pub async fn create_group_with_audit_context(
        &mut self,
        request: CreateGroupRequest,
        context: AuditEventContext,
    ) -> AccountResult<(GroupId, AccountDeviceEffects)> {
        let CreateGroupEffects { group_id, effects } = self
            .prepare_create_group_with_audit_context(request, context.clone())
            .await?;
        let effects = self
            .publish_prepared_session_effects_with_audit_context(effects, context)
            .await?;
        Ok((group_id, effects))
    }

    /// Prepare group creation without performing transport side effects.
    ///
    /// The application runtime uses this seam to durably record every
    /// current-profile founding Welcome obligation before the first publish
    /// attempt. Callers must subsequently pass the returned effects to
    /// [`Self::publish_prepared_session_effects_with_audit_context`].
    pub async fn prepare_create_group_with_audit_context(
        &mut self,
        request: CreateGroupRequest,
        context: AuditEventContext,
    ) -> AccountResult<CreateGroupEffects> {
        self.prepare_create_group_with_optional_app_components_and_audit_context(
            request,
            Vec::new(),
            context,
        )
        .await
    }

    /// A founder's Welcome that fits none of the relays its publish would
    /// reach refuses the create before anything is written, with
    /// `EngineError::EventTooLarge` (mdk#2334).
    pub async fn prepare_create_group_with_optional_app_components_and_audit_context(
        &mut self,
        request: CreateGroupRequest,
        optional_app_components: Vec<cgka_traits::app_components::AppComponentData>,
        context: AuditEventContext,
    ) -> AccountResult<CreateGroupEffects> {
        let welcome_sizes = WelcomeSizes {
            adapter: &self.adapter,
            routing: &self.routing,
        };
        let created = self
            .session
            .create_group_with_optional_app_components_and_audit_context(
                request,
                optional_app_components,
                Some(&welcome_sizes),
                context,
            )
            .await?;
        self.note_founding_welcomes(&created.effects);
        Ok(created)
    }

    /// Prepare a chat whose founding Add includes authenticated private sibling KeyPackages.
    /// The ordinary founders' Welcomes are checked as for
    /// [`Self::prepare_create_group_with_optional_app_components_and_audit_context`].
    pub async fn prepare_create_group_with_siblings_and_audit_context(
        &mut self,
        request: CreateGroupRequest,
        optional_app_components: Vec<cgka_traits::app_components::AppComponentData>,
        siblings: Vec<cgka_traits::engine::SiblingKeyPackage>,
        context: AuditEventContext,
    ) -> AccountResult<CreateGroupEffects> {
        let welcome_sizes = WelcomeSizes {
            adapter: &self.adapter,
            routing: &self.routing,
        };
        let created = self
            .session
            .prepare_create_group_with_siblings_and_audit_context(
                request,
                optional_app_components,
                siblings,
                Some(&welcome_sizes),
                context,
            )
            .await?;
        self.note_founding_welcomes(&created.effects);
        Ok(created)
    }

    /// Prepare creation of a group under a group id chosen before it exists,
    /// as a device link needs; a device group's founding Add sets the linked
    /// device's entry by `roster_update`. Publish the effects as for
    /// [`Self::prepare_create_group_with_audit_context`].
    pub async fn prepare_create_group_with_chosen_id_and_audit_context(
        &mut self,
        request: CreateGroupRequest,
        group_id: GroupId,
        roster_update: Option<Vec<u8>>,
        welcome_deliver_until: Timestamp,
        context: AuditEventContext,
    ) -> AccountResult<CreateGroupEffects> {
        let created = self
            .session
            .create_group_with_chosen_id_and_audit_context(
                request,
                group_id,
                roster_update,
                welcome_deliver_until,
                context,
            )
            .await?;
        self.note_founding_welcomes(&created.effects);
        Ok(created)
    }

    /// Publish effects returned by
    /// [`Self::prepare_create_group_with_audit_context`].
    pub async fn publish_prepared_session_effects_with_audit_context(
        &mut self,
        effects: SessionEffects,
        context: AuditEventContext,
    ) -> AccountResult<AccountDeviceEffects> {
        self.publish_session_effects_with_audit_context(effects, Some(context))
            .await
    }

    pub async fn send(&mut self, intent: SendIntent) -> AccountResult<AccountDeviceEffects> {
        let disposition_group = match &intent {
            SendIntent::AppMessage { group_id, .. } => Some(group_id.clone()),
            _ => None,
        };
        let accept_started = Instant::now();
        self.record_commit_refusals_before_disband(&intent)?;
        let effects = self.session.send(intent).await?;
        let local_accept_duration = accept_started.elapsed();
        let publish_started = Instant::now();
        let mut output = self.publish_session_effects(effects).await?;
        output.local_accept_duration =
            Some(local_accept_duration + output.local_accept_duration.unwrap_or_default());
        output.publish_duration = Some(publish_started.elapsed());
        if let Some(group_id) = disposition_group
            && self.post_join_rotation_pending(&group_id)?
        {
            output.maintenance_disposition =
                SendMaintenanceDisposition::PostJoinRotationPendingRetryable;
        }
        Ok(output)
    }

    pub async fn send_with_audit_context(
        &mut self,
        intent: SendIntent,
        context: AuditEventContext,
    ) -> AccountResult<AccountDeviceEffects> {
        self.send_with_audit_context_from(intent, context, SendOrigin::Automatic)
            .await
    }

    /// Send a group change the host asked for, as
    /// [`Self::send_with_audit_context`] does. A commit staged at once names
    /// the change on its frozen fanout, so a rollback after this call returns
    /// is recorded as not delivered (mdk#2332); see
    /// [`Self::group_changes_not_delivered`].
    pub async fn send_host_change_with_audit_context(
        &mut self,
        intent: SendIntent,
        context: AuditEventContext,
    ) -> AccountResult<AccountDeviceEffects> {
        self.send_with_audit_context_from(intent, context, SendOrigin::Host)
            .await
    }

    async fn send_with_audit_context_from(
        &mut self,
        intent: SendIntent,
        context: AuditEventContext,
        origin: SendOrigin,
    ) -> AccountResult<AccountDeviceEffects> {
        let disposition_group = match &intent {
            SendIntent::AppMessage { group_id, .. } => Some(group_id.clone()),
            _ => None,
        };
        let accept_started = Instant::now();
        self.record_commit_refusals_before_disband(&intent)?;
        let effects = self
            .send_session_intent(intent, context.clone(), origin)
            .await?;
        let local_accept_duration = accept_started.elapsed();
        let publish_started = Instant::now();
        let mut output = self
            .publish_session_effects_with_audit_context(effects, Some(context))
            .await?;
        output.local_accept_duration =
            Some(local_accept_duration + output.local_accept_duration.unwrap_or_default());
        output.publish_duration = Some(publish_started.elapsed());
        if let Some(group_id) = disposition_group
            && self.post_join_rotation_pending(&group_id)?
        {
            output.maintenance_disposition =
                SendMaintenanceDisposition::PostJoinRotationPendingRetryable;
        }
        Ok(output)
    }

    /// Accept an outbound commit intent without publishing it.
    ///
    /// A ready group returns a staged commit with extracted Welcome payloads;
    /// unsettled convergence returns the durable queued effects instead. For a
    /// staged commit, the caller must record exact Welcome delivery obligations
    /// before [`Self::publish_prepared_session_effects_with_audit_context`]
    /// exposes the commit on the wire. An invite whose commit or Welcome fits
    /// none of its relays' known limits is rolled back here instead, unsent,
    /// as [`PreparedSessionSend::Refused`]. A queued invite is judged by the
    /// same check when it drains, before its commit is published, and one
    /// that fits none is retired unsent as `QueuedIntentRefused`.
    pub async fn confirm_commit_without_publish_with_audit_context(
        &mut self,
        intent: SendIntent,
        context: AuditEventContext,
    ) -> AccountResult<PreparedSessionSend> {
        self.confirm_commit_without_publish_from(intent, context, SendOrigin::Automatic)
            .await
    }

    /// Accept a group change the host asked for without publishing it, as
    /// [`Self::confirm_commit_without_publish_with_audit_context`] does. A
    /// staged commit names the change on its frozen fanout (mdk#2332).
    pub async fn confirm_host_change_without_publish_with_audit_context(
        &mut self,
        intent: SendIntent,
        context: AuditEventContext,
    ) -> AccountResult<PreparedSessionSend> {
        self.confirm_commit_without_publish_from(intent, context, SendOrigin::Host)
            .await
    }

    async fn confirm_commit_without_publish_from(
        &mut self,
        intent: SendIntent,
        context: AuditEventContext,
        origin: SendOrigin,
    ) -> AccountResult<PreparedSessionSend> {
        if !supports_deferred_commit_publish(&intent) {
            return Err(cgka_traits::EngineError::Other(
                "deferred-publish acceptance requires a commit-producing or durably queued intent"
                    .into(),
            )
            .into());
        }
        // Only an invite: other commits that carry Welcomes (recovery, own
        // devices) keep their own handling of a Welcome that cannot be sent.
        let invite = matches!(intent, SendIntent::Invite { .. });
        let session_effects = self.send_session_intent(intent, context, origin).await?;
        let prepared = classify_prepared_session_send(session_effects)?;
        let PreparedSessionSend::Commit(commit) = prepared else {
            return Ok(prepared);
        };
        self.note_retained_welcomes(commit.welcomes());
        if invite && let Some((message_id, refusal)) = self.oversized_invite(&commit).await {
            let oversized = refusal.oversized;
            let mut output = self
                .rollback_prepared_session_commit_refused(commit, Some(refusal))
                .await?;
            output
                .failures
                .insert(0, refused_before_publishing(message_id, oversized));
            return Ok(PreparedSessionSend::Refused(Box::new(output)));
        }
        Ok(PreparedSessionSend::Commit(commit))
    }

    /// The commit's id and the oversized artifact when an invite must be
    /// refused before its commit is published (mdk#2334); see
    /// [`Self::oversized_invite_events`].
    async fn oversized_invite(
        &self,
        prepared: &PreparedSessionCommit,
    ) -> Option<(cgka_traits::MessageId, InviteRefusal)> {
        let commit = prepared
            .effects
            .publish
            .iter()
            .find_map(|work| match work {
                PublishWork::GroupEvolution { msg, pending, .. }
                    if *pending == prepared.pending =>
                {
                    Some(msg)
                }
                _ => None,
            })?;
        let refusal = self
            .oversized_invite_events(commit, &prepared.welcomes)
            .await?;
        Some((commit.id.clone(), refusal))
    }

    /// The oversized artifact when an invite's commit fits none of its group
    /// relays' known limits, or a Welcome fits none of its invitee's inbox
    /// relays'. A relay with no known limit fits; one the adapter would never
    /// send to does not count. A direct invite and a queued one the drain
    /// prepared are both judged here, before the commit is published.
    ///
    /// The future is boxed in this plain function so a caller's poll frame
    /// holds only the box; see [`refuse_too_large`].
    #[inline(never)]
    fn oversized_invite_events(
        &self,
        commit: &TransportMessage,
        welcomes: &[TransportMessage],
    ) -> Pin<Box<impl Future<Output = Option<InviteRefusal>>>> {
        Box::pin(async move {
            // A commit or Welcome without a route fails when it is published.
            let target = self.routing.publish_target(commit).ok()?;
            let adapter = &self.adapter;
            if let Some(size_class) = adapter.size_class_over_known_limits(commit, &target).await {
                return Some(InviteRefusal::from(OversizedEvent {
                    artifact: OversizedArtifact::Commit,
                    size_class,
                }));
            }
            // The same check a founding create runs on its Welcomes.
            let welcome_sizes = WelcomeSizes {
                adapter,
                routing: &self.routing,
            };
            let oversized_welcomes = welcome_sizes.oversized_welcomes(welcomes).await;
            let (_, size_class) = oversized_welcomes.first()?.clone();
            Some(InviteRefusal {
                oversized: OversizedEvent {
                    artifact: OversizedArtifact::Welcome,
                    size_class,
                },
                oversized_welcomes: oversized_welcomes.into_iter().collect(),
            })
        })
    }

    /// Roll back a prepared commit before that commit has any transport side
    /// effect, then publish any independent work generated while buffered input
    /// is replayed against the restored group state.
    pub async fn rollback_prepared_session_commit(
        &mut self,
        prepared: PreparedSessionCommit,
    ) -> AccountResult<AccountDeviceEffects> {
        self.rollback_prepared_session_commit_refused(prepared, None)
            .await
    }

    /// [`Self::rollback_prepared_session_commit`], recording why a size
    /// `refusal` retired each Welcome right after the rollback, before any
    /// later work.
    async fn rollback_prepared_session_commit_refused(
        &mut self,
        prepared: PreparedSessionCommit,
        refusal: Option<InviteRefusal>,
    ) -> AccountResult<AccountDeviceEffects> {
        let (mut prepared_effects, welcomes, pending) = prepared.into_parts();
        let unretired = refusal
            .as_ref()
            .map(|_| self.unretired_welcomes(welcomes.iter().map(|welcome| welcome.id.clone())));
        prepared_effects.publish.retain(|work| {
            !matches!(work, PublishWork::GroupEvolution { pending: own, .. } | PublishWork::GroupCreated { pending: own, .. } if *own == pending)
        });

        let mut output = AccountDeviceEffects::default();
        let mut queue = VecDeque::new();
        output.absorb_session_effects(prepared_effects, &mut queue);

        let rollback = self.session.publish_failed(pending).await;
        // A rollback can commit, retiring Welcomes, and fail after: record
        // what it retired either way.
        if let (Some(refusal), Some(unretired)) = (refusal, unretired) {
            let retired = self.retired_welcomes(unretired);
            self.record_v5_welcomes_refused(&retired, &refusal);
        }
        let rollback_effects = rollback?;
        output
            .pending
            .push(PendingResolution::RolledBack { pending });
        output.absorb_session_effects(rollback_effects, &mut queue);
        self.publish_queue(&mut output, &mut queue, None).await?;
        self.reconcile_confirmed_own_leaf_rotations(&output.events);
        let superseded = self.reconcile_superseded_maintenance(&output.events)?;
        output.superseded_intents.extend(superseded);
        Ok(output)
    }

    async fn send_session_intent(
        &mut self,
        intent: SendIntent,
        context: AuditEventContext,
        origin: SendOrigin,
    ) -> AccountResult<SessionEffects> {
        Ok(match origin {
            SendOrigin::Host => {
                self.session
                    .send_host_change_with_audit_context(intent, context)
                    .await?
            }
            SendOrigin::Automatic => {
                self.session
                    .send_with_audit_context(intent, context)
                    .await?
            }
        })
    }

    /// Confirm an outbound intent's commit without waiting for Welcome fanout,
    /// or preserve its accepted-pending disposition when convergence queued it.
    ///
    /// Founding creates and existing-group invites persist exact Welcome bytes
    /// before this returns. The caller records those obligations, returns the
    /// canonical mutation, then drives [`Self::publish_welcome_messages_with_audit_context`].
    pub async fn send_confirming_commit_with_audit_context(
        &mut self,
        intent: SendIntent,
        context: AuditEventContext,
    ) -> AccountResult<(AccountDeviceEffects, Vec<TransportMessage>)> {
        let disposition_group = match &intent {
            SendIntent::AppMessage { group_id, .. } => Some(group_id.clone()),
            _ => None,
        };
        let prepared = self
            .confirm_commit_without_publish_with_audit_context(intent, context.clone())
            .await?;
        let (session_effects, welcomes) = match prepared {
            PreparedSessionSend::Commit(prepared) => {
                let (effects, welcomes, _pending) = prepared.into_parts();
                (effects, welcomes)
            }
            PreparedSessionSend::Queued(effects) => (effects, Vec::new()),
            PreparedSessionSend::Refused(output) => return Ok((*output, Vec::new())),
        };
        let mut output = self
            .publish_session_effects_with_audit_context(session_effects, Some(context))
            .await?;
        if let Some(group_id) = disposition_group
            && self.post_join_rotation_pending(&group_id)?
        {
            output.maintenance_disposition =
                SendMaintenanceDisposition::PostJoinRotationPendingRetryable;
        }
        Ok((output, welcomes))
    }

    pub async fn queue_app_message_with_audit_context(
        &mut self,
        group_id: GroupId,
        payload: Vec<u8>,
        only_to_members: Option<Vec<MemberId>>,
        context: AuditEventContext,
    ) -> AccountResult<AccountDeviceEffects> {
        let accept_started = Instant::now();
        let effects = self
            .session
            .queue_app_message_with_audit_context(
                group_id.clone(),
                payload,
                only_to_members,
                context.clone(),
            )
            .await?;
        let local_accept_duration = accept_started.elapsed();
        let publish_started = Instant::now();
        let mut output = self
            .publish_session_effects_with_audit_context(effects, Some(context))
            .await?;
        output.local_accept_duration =
            Some(local_accept_duration + output.local_accept_duration.unwrap_or_default());
        output.publish_duration = Some(publish_started.elapsed());
        if self.post_join_rotation_pending(&group_id)? {
            output.maintenance_disposition =
                SendMaintenanceDisposition::PostJoinRotationPendingRetryable;
        }
        Ok(output)
    }

    fn post_join_rotation_pending(&self, group_id: &GroupId) -> AccountResult<bool> {
        Ok(self
            .session
            .maintenance_obligations_for_group(group_id)?
            .into_iter()
            .any(|obligation| {
                obligation.trigger == MaintenanceTrigger::PostJoin
                    && !matches!(
                        obligation.phase,
                        MaintenancePhase::Complete | MaintenancePhase::Failed
                    )
            }))
    }

    /// Advance convergence while observing each durable accepted application
    /// publication before waiting for later publications in the same batch.
    ///
    /// The synchronous observer receives the live session at the completed
    /// engine boundary. It must not panic or perform network work. Its
    /// notification uses the same acceptance rule as `published_app_messages`;
    /// it does not change quorum, MLS confirmation, or acknowledge projection
    /// persistence. Observers should handle local failures without interrupting
    /// the remaining batch. Dropping this future removes its observer; durable
    /// fanouts remain available to the ordinary recovery path.
    pub async fn advance_convergence_with_publication_progress(
        &mut self,
        group_id: &GroupId,
        observe: PublicationProgressObserver,
    ) -> AccountResult<AccountDeviceEffects> {
        self.advance_convergence_with_publication_progress_and_yield(
            group_id,
            observe,
            std::future::pending(),
        )
        .await
    }

    /// Yield only dispensable secondary relay waits when the owner has foreground work.
    /// The signal is latched for this pass. Below-quorum publications and pending MLS
    /// confirmation remain mandatory; cancelled secondary attempts retain exact bytes
    /// and conservative exposure evidence through the ordinary durable retry path.
    pub async fn advance_convergence_with_publication_progress_and_yield(
        &mut self,
        group_id: &GroupId,
        observe: PublicationProgressObserver,
        yield_requested: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> AccountResult<AccountDeviceEffects> {
        let slot = self.publication_progress.clone();
        let previous = slot
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .replace(PublicationProgress {
                observe,
                secondary_retry_yield: yield_requested.boxed().shared(),
            });
        let _guard = PublicationProgressGuard { slot, previous };
        self.advance_convergence(group_id).await
    }

    pub async fn advance_convergence(
        &mut self,
        group_id: &GroupId,
    ) -> AccountResult<AccountDeviceEffects> {
        // A deferred-open session intentionally hides this group's durable
        // fanouts until full hydration restores its pending lifecycle. Hydrate
        // before the targeted lookup so this same scheduled pass can resume
        // those exact frozen bytes instead of waiting for another wake.
        let _ = self.session.ensure_group_hydrated(group_id)?;
        // Retry the group's already-frozen transport events before producing
        // any newer convergence work. This preserves send order and ensures a
        // scheduled outbound wake actually drives the exact retained bytes.
        let (mut output, blocked_groups) = self
            .resume_outbound_fanouts_for_group(Some(group_id))
            .await?;
        // Keep exact-event retries in their original order, but do not make
        // engine-queued sends wait for secondary replication after quorum and
        // MLS confirmation. Foreground sends already use that same boundary.
        // Inspect the remaining durable state, including newer fanouts skipped
        // behind the oldest retry, so an unresolved publication stays a barrier.
        let queued_intents_blocked = blocked_groups.contains(group_id)
            && self.queued_outbound_intents_blocked_by_fanouts(group_id)?;
        // Required publication barriers must not prevent inbound convergence
        // from settling, even while the corresponding relay is unavailable.
        let effects = if queued_intents_blocked {
            self.session.advance_convergence_inputs(group_id).await?
        } else {
            self.session.advance_convergence(group_id).await?
        };
        output.extend(self.publish_session_effects(effects).await?);
        Ok(output)
    }

    pub fn has_pending_convergence_inputs(&self, group_id: &GroupId) -> AccountResult<bool> {
        Ok(self.session.has_pending_convergence_inputs(group_id)?)
    }

    /// Whether this group's convergence pass parked after repeated failures
    /// and waits for new input or an explicit retry (mdk#2684).
    pub fn convergence_pass_parked(&self, group_id: &GroupId) -> AccountResult<bool> {
        Ok(self.session.convergence_pass_parked(group_id)?)
    }

    /// Let a failed convergence pass make its next attempt now (mdk#2684).
    pub fn retry_failed_convergence_pass(&mut self, group_id: &GroupId) -> AccountResult<bool> {
        Ok(self.session.retry_failed_convergence_pass(group_id)?)
    }

    pub fn has_queued_outbound_intents(&self, group_id: &GroupId) -> AccountResult<bool> {
        Ok(self.session.has_queued_outbound_intents(group_id)?)
    }

    /// The commit a group's delivery answer names (mdk#2255, mdk#2333): the
    /// oldest confirmed commit a group relay refused that the user has not
    /// acknowledged, or else the oldest one some group relay still owes. A
    /// commit confirms on its first acknowledgement, so members who read only
    /// the other relays cannot follow the group until they accept it. Owed
    /// relays keep being retried with the exact event; a refusal is final and
    /// warns until [`Self::acknowledge_commit_refusals`]. A commit convergence
    /// withdrew from the selected branch no longer gates the group, nor does
    /// any refusal once the group is disbanded.
    pub fn undelivered_commit(
        &self,
        group_id: &GroupId,
    ) -> AccountResult<Option<UndeliveredCommit>> {
        Ok(self.undelivered_commit_until(group_id)?.0)
    }

    /// The wall-clock time this runtime's time-dependent answers, such as
    /// [`Self::undelivered_commit_until`], are computed against.
    pub fn wall_clock_now(&self) -> Timestamp {
        self.wall_clock.now()
    }

    /// [`Self::undelivered_commit`], and the wall-clock window its answer
    /// holds in without a write (mdk#3273): from the clock reading it was
    /// computed at until a legacy self-update fanout's bound passes.
    pub fn undelivered_commit_until(
        &self,
        group_id: &GroupId,
    ) -> AccountResult<(Option<UndeliveredCommit>, WallClockWindow)> {
        self.undelivered_commit_until_in(group_id, None)
    }

    /// The group's own commit that has not confirmed yet, if any (mdk#2332).
    /// The engine stages one commit at a time, so a group has at most one,
    /// and no other group change can be staged while it is pending. MDK's own
    /// commits are included, with no origin. The commit is
    /// [`PendingCommitState::Stuck`] once its first attempt is past the
    /// read-back bound while some relay may hold it and none has
    /// acknowledged it, and [`PendingCommitState::Sending`] otherwise. Only a
    /// live group answers (mdk#2602): a seeded group fails with
    /// `GroupNotHydrated` and a quarantined one with `UnknownGroup`, because
    /// the engine hides their fanouts.
    pub fn pending_commit(&self, group_id: &GroupId) -> AccountResult<Option<PendingCommit>> {
        self.session.check_group_live(group_id)?;
        let now_ms = self.wall_clock.now_ms();
        let Some(fanout) = self
            .session
            .outbound_fanouts_for_group(group_id)?
            .into_iter()
            .find(|fanout| {
                is_group_commit(fanout) && matches!(fanout.mls_state(), FanoutMlsState::Pending(_))
            })
        else {
            return Ok(None);
        };
        let endpoints = fanout.request().target.endpoints();
        let mut unconfirmed_endpoints = Vec::new();
        let mut owed_endpoints = Vec::new();
        for (index, endpoint) in endpoints.iter().enumerate() {
            let status = fanout.target_status(index);
            if status == Some(cgka_traits::FanoutTargetStatus::Accepted) {
                continue;
            }
            if fanout.target_may_hold_event(index) {
                unconfirmed_endpoints.push(endpoint.clone());
            } else if status.is_some_and(cgka_traits::FanoutTargetStatus::is_outstanding) {
                owed_endpoints.push(endpoint.clone());
            }
        }
        let first_attempt_at_ms = fanout.first_attempt_at_ms();
        let stuck = first_attempt_at_ms
            .is_some_and(|first| now_ms.saturating_sub(first) >= PENDING_COMMIT_READ_BACK_AFTER_MS)
            && fanout.outcome().accepted_targets == 0
            && !unconfirmed_endpoints.is_empty();
        let (origin, intent_kind) = if let Some(intent_id) = fanout.queued_intent_id() {
            (
                Some(cgka_traits::storage::ChangeOrigin::QueuedIntent {
                    intent_id: intent_id.clone(),
                }),
                self.session
                    .queued_intent_kind(group_id, intent_id)?
                    .map(str::to_owned),
            )
        } else if let Some(kind) = fanout.host_change_kind() {
            (
                Some(cgka_traits::storage::ChangeOrigin::Direct),
                Some(kind.to_owned()),
            )
        } else {
            (None, None)
        };
        Ok(Some(PendingCommit {
            message_id: fanout.message_id().clone(),
            origin,
            intent_kind,
            first_attempt_at: first_attempt_at_ms.map(|ms| Timestamp(ms / 1_000)),
            state: if stuck {
                PendingCommitState::Stuck
            } else {
                PendingCommitState::Sending
            },
            unconfirmed_endpoints,
            owed_endpoints,
            refused_endpoints: fanout.pending_final_answers(),
            endpoint_count: endpoints.len(),
        }))
    }

    /// [`Self::undelivered_commit_until`], taking the account-wide rows from
    /// `rows` when given instead of loading them for this one group.
    pub fn undelivered_commit_until_in(
        &self,
        group_id: &GroupId,
        rows: Option<&GroupMaintenanceRows>,
    ) -> AccountResult<(Option<UndeliveredCommit>, WallClockWindow)> {
        let (commits, window) = self.undelivered_commits_in(group_id, rows)?;
        let named = commits
            .iter()
            .position(|commit| !commit.refused_endpoints.is_empty())
            .or_else(|| (!commits.is_empty()).then_some(0))
            .map(|index| commits[index].clone());
        Ok((named, window))
    }

    /// Every confirmed own commit of `group_id` that some group relay owes,
    /// or that a group relay refused and the user has not acknowledged, oldest
    /// first, and the wall-clock window the list holds in without a write.
    /// The gate refuses a group change while any of them gates, and the
    /// self-update hold waits on each one's own `since` (mdk#2333). Empty
    /// for a group the engine has not hydrated yet, whose fanouts stay
    /// frozen until it is: hydrate it first to learn what it owes.
    pub fn undelivered_commits_in(
        &self,
        group_id: &GroupId,
        rows: Option<&GroupMaintenanceRows>,
    ) -> AccountResult<(Vec<UndeliveredCommit>, WallClockWindow)> {
        let now = self.wall_clock.now();
        let mut changes_at: Option<Timestamp> = None;
        // The ungated lists: the group-scoped lookup fails for a stored group
        // the engine has not hydrated yet. Such a group may still owe a
        // commit; its fanouts below are listed only once it is hydrated.
        let loaded;
        let rows = match rows {
            Some(rows) => rows,
            None => {
                loaded = self.group_maintenance_rows()?;
                &loaded
            }
        };
        let mut commits = Vec::new();
        // A refusal is read only where the group's fanouts are: a group the
        // engine does not hold live lists none.
        let mut stored_refusals = if self.session.check_group_live(group_id).is_ok() {
            rows.commit_refusals(group_id)
                .iter()
                .map(|refusal| (refusal.fanout_id.clone(), refusal))
                .collect::<HashMap<_, _>>()
        } else {
            HashMap::new()
        };
        for mut fanout in self.session.outbound_fanouts_for_group(group_id)? {
            if !is_confirmed_group_commit(&fanout)
                || self.commit_withdrawn(fanout_commit_id(&fanout))?
            {
                continue;
            }
            // A row stored before the successor edge may still hold an exposed
            // target a size answer refused. Read it as the next drive stores
            // it, a refusal, without writing here (mdk#2333).
            fanout.end_size_refused_targets();
            let endpoints = fanout.request().target.endpoints();
            let owed_endpoints = endpoints
                .iter()
                .zip(fanout.target_statuses())
                .filter(|(_, status)| status.is_outstanding())
                .map(|(endpoint, _)| endpoint.clone())
                .collect::<Vec<_>>();
            // The stored record, and any refusal this fanout holds that a
            // pass has not merged yet.
            let refused_endpoints = match stored_refusals.remove(fanout.message_id()) {
                Some(stored) if stored.acknowledged => Vec::new(),
                Some(stored) => {
                    let mut live = stored.clone();
                    live.merge(fanout.refused_targets());
                    live.refused
                }
                None => fanout.refused_targets(),
            };
            if !owed_endpoints.is_empty() || !refused_endpoints.is_empty() {
                commits.push(UndeliveredCommit {
                    message_id: fanout.message_id().clone(),
                    since: commit_confirmed_at(&fanout),
                    owed_endpoints,
                    refused_endpoints,
                    endpoint_count: endpoints.len(),
                });
            }
        }
        // Refused commits whose fanout is gone.
        let mut unfanned = stored_refusals.into_values().collect::<Vec<_>>();
        unfanned.sort_by(|a, b| a.fanout_id.as_slice().cmp(b.fanout_id.as_slice()));
        for refusal in unfanned {
            if refusal.acknowledged || self.commit_withdrawn(&refusal.commit_id)? {
                continue;
            }
            commits.push(UndeliveredCommit {
                message_id: refusal.fanout_id.clone(),
                since: refusal.since,
                owed_endpoints: Vec::new(),
                refused_endpoints: refusal.refused.clone(),
                endpoint_count: usize::try_from(refusal.relay_count).unwrap_or(usize::MAX),
            });
        }
        // A disband that settles keeps the group's record: its refusals are
        // moot, and no longer warn or gate.
        if commits
            .iter()
            .any(|commit| !commit.refused_endpoints.is_empty())
            && self.session.group_record(group_id)?.disbanded.is_some()
        {
            for commit in &mut commits {
                commit.refused_endpoints.clear();
            }
            commits.retain(|commit| !commit.owed_endpoints.is_empty());
        }
        // Self-updates staged before the frozen-fanout migration.
        let none_confirmed = HashSet::new();
        let confirmed_evolutions = rows
            .confirmed_evolutions
            .get(group_id)
            .unwrap_or(&none_confirmed);
        for fanout in rows.fanouts(group_id) {
            let Some(evolution_id) = fanout.evolution_id.as_ref() else {
                continue;
            };
            if let Some(until) = fanout.bounded_until.filter(|until| *until > now) {
                changes_at = Some(changes_at.map_or(until, |earliest| earliest.min(until)));
            }
            if fanout.bounded_until.is_some_and(|until| until <= now)
                || !(fanout.evolution_confirmed || confirmed_evolutions.contains(evolution_id))
                || self.commit_withdrawn(&fanout.id)?
            {
                continue;
            }
            let owed_endpoints = fanout
                .targets
                .iter()
                .filter(|target| {
                    !matches!(
                        target.state,
                        TransportFanoutAttemptState::Accepted
                            | TransportFanoutAttemptState::PolicyProhibited
                    )
                })
                .map(|target| target.endpoint.clone())
                .collect::<Vec<_>>();
            if !owed_endpoints.is_empty() {
                let first_accepted = fanout
                    .targets
                    .iter()
                    .filter(|target| target.state == TransportFanoutAttemptState::Accepted)
                    .filter_map(|target| target.last_attempt_at)
                    .min()
                    .unwrap_or(fanout.created_at);
                commits.push(UndeliveredCommit {
                    message_id: fanout.id.clone(),
                    since: first_accepted,
                    owed_endpoints,
                    refused_endpoints: Vec::new(),
                    endpoint_count: fanout.targets.len(),
                });
            }
        }
        // Oldest first; a stable sort keeps storage order among ties.
        commits.sort_by_key(|commit| commit.since);
        Ok((
            commits,
            WallClockWindow {
                from: now,
                until: changes_at,
            },
        ))
    }

    /// Acknowledge every relay refusal of `group_id`'s confirmed commits
    /// (mdk#2333): none warns or gates again, including a later refusal of
    /// the same commit by another relay. A refusal whose commit's fanout is
    /// gone is deleted; the rest stay, marked, until that fanout is.
    pub fn acknowledge_commit_refusals(&self, group_id: &GroupId) -> AccountResult<()> {
        self.merge_group_commit_refusals(group_id)?;
        self.session.acknowledge_commit_refusals(group_id)?;
        Ok(())
    }

    /// The group's changes that were not delivered (mdk#2332), oldest first.
    /// Each is a change whose caller was given an unresolved result and whose
    /// commit was then rolled back: a queued intent the drain retired, or a
    /// host's change that returned `CompletionUnknown`. A record stays until
    /// [`Self::acknowledge_change_not_delivered`] or the group's local state
    /// is removed; another commit confirming does not clear it.
    pub fn group_changes_not_delivered(
        &self,
        group_id: &GroupId,
    ) -> AccountResult<Vec<cgka_traits::storage::ChangeNotDelivered>> {
        Ok(self.session.changes_not_delivered(group_id)?)
    }

    /// Delete the group's not-delivered record for `commit_id` (mdk#2332),
    /// saying whether there was one.
    pub fn acknowledge_change_not_delivered(
        &self,
        group_id: &GroupId,
        commit_id: &cgka_traits::MessageId,
    ) -> AccountResult<bool> {
        Ok(self
            .session
            .acknowledge_change_not_delivered(group_id, commit_id)?)
    }

    /// A disband request deletes every fanout of a group whose epoch is not
    /// pending. Each confirmed commit's refusals are merged first, so a
    /// request that then fails leaves them recorded (mdk#2333).
    fn record_commit_refusals_before_disband(&self, intent: &SendIntent) -> AccountResult<()> {
        let SendIntent::Disband { group_id } = intent else {
            return Ok(());
        };
        self.merge_group_commit_refusals(group_id)
    }

    /// Merge each of the group's confirmed commits' refused relays into its
    /// refusal record. A fanout stored by a release before the successor edge
    /// may still hold an exposed target a size answer refused; it is ended
    /// and stored first, as a drive would, so its refusal is merged too
    /// (mdk#2333). A crash between the two leaves the target ended, and the
    /// next pass over the fanout merges it.
    fn merge_group_commit_refusals(&self, group_id: &GroupId) -> AccountResult<()> {
        for mut fanout in self.session.outbound_fanouts_for_group(group_id)? {
            if fanout.end_size_refused_targets() {
                self.session.put_outbound_fanout(&fanout)?;
            }
            if let Some(refusal) = commit_refusal_of(&fanout) {
                self.session.merge_commit_refusal(&refusal)?;
            }
        }
        Ok(())
    }

    /// The account-wide rows [`Self::maintenance_status_in`] and
    /// [`Self::undelivered_commit_until_in`] filter by group, loaded once: a
    /// caller answering for many groups scans the account once rather than
    /// once per group (mdk#3273).
    pub fn group_maintenance_rows(&self) -> AccountResult<GroupMaintenanceRows> {
        let mut rows = GroupMaintenanceRows::default();
        let mut names_an_evolution = false;
        for fanout in self.session.transport_fanouts()? {
            names_an_evolution |= fanout.evolution_id.is_some();
            if let Some(group_id) = fanout.group_id.clone() {
                rows.fanouts.entry(group_id).or_default().push(fanout);
            }
        }
        for refusal in self.session.commit_refusals()? {
            rows.commit_refusals
                .entry(refusal.group_id.clone())
                .or_default()
                .push(refusal);
        }
        // Only a fanout naming an evolution consults the confirmed ones.
        if names_an_evolution {
            for evolution in self.session.group_evolutions()? {
                if evolution.phase == GroupEvolutionPhase::Confirmed {
                    rows.confirmed_evolutions
                        .entry(evolution.group_id)
                        .or_default()
                        .insert(evolution.id);
                }
            }
        }
        Ok(rows)
    }

    /// Whether convergence withdrew this own commit from the selected branch:
    /// the same stored dispositions `reconcile_superseded_maintenance_from_state`
    /// reads, so the answer survives a lost announcement and a restart.
    fn commit_withdrawn(&self, commit_id: &cgka_traits::MessageId) -> AccountResult<bool> {
        Ok(matches!(
            self.session.stored_message_state(commit_id)?,
            Some(MessageState::ConvergenceDeferred | MessageState::EpochInvalidated)
        ))
    }

    /// Whether retained publications still prevent staging queued sends.
    ///
    /// Pending MLS confirmation and outstanding targets below required quorum
    /// are barriers; secondary replication after quorum is not. This inspects
    /// every retained fanout, including newer work behind an older retry. It
    /// does not establish that convergence inputs or other engine gates cleared.
    /// Unhydrated or unavailable group state is an error, never an empty outbox.
    pub fn queued_outbound_intents_blocked_by_fanouts(
        &self,
        group_id: &GroupId,
    ) -> AccountResult<bool> {
        self.session.group_record(group_id)?;
        Ok(self
            .session
            .outbound_fanouts_for_group(group_id)?
            .iter()
            .any(|fanout| {
                let outcome = fanout.outcome();
                matches!(fanout.mls_state(), FanoutMlsState::Pending(_))
                    || (outcome.outstanding_targets > 0
                        && outcome.accepted_targets < fanout.request().required_acks.max(1))
            }))
    }

    pub fn has_pending_outbound_fanouts(&self, group_id: &GroupId) -> AccountResult<bool> {
        Ok(self
            .session
            .outbound_fanouts_for_group(group_id)?
            .iter()
            .any(|fanout| {
                let outcome = fanout.outcome();
                outcome.outstanding_targets > 0
                    || matches!(fanout.mls_state(), FanoutMlsState::Pending(_))
                    || !fanout.pending_post_confirmation_welcomes().is_empty()
                    || (outcome.accepted_targets > 0 && fanout.application_message().is_some())
            }))
    }

    /// Return the earliest durable retry cutoff up to the first fanout below
    /// quorum or awaiting MLS confirmation, including earlier retained Welcomes.
    ///
    /// `None` means the group has no network retry cutoff to honor. It may
    /// still have local-only work, such as acknowledgement cleanup for an
    /// accepted application-message fanout or Welcome preparation without a
    /// stored attempt cutoff; callers should schedule that on their ordinary
    /// retry delay. A zero delay means at least one exact event
    /// is eligible now (including after a connectivity-restored wake).
    pub fn outbound_fanout_retry_delay_ms(&self, group_id: &GroupId) -> AccountResult<Option<u64>> {
        let now_ms = self.wall_clock.now_ms();
        let mut earliest = None;
        for fanout in self.session.outbound_fanouts_for_group(group_id)? {
            let outcome = fanout.outcome();
            if outcome.accepted_targets > 0
                && outcome.fanout_complete
                && fanout.application_message().is_some()
            {
                // Local projection acknowledgement cleanup should not wait
                // behind an unrelated transport backoff in the same group.
                return Ok(None);
            }
            if matches!(fanout.mls_state(), FanoutMlsState::Confirmed)
                && !fanout.pending_post_confirmation_welcomes().is_empty()
            {
                let Some(delay) = self
                    .welcome_retry_delay_ms(fanout.pending_post_confirmation_welcomes(), now_ms)?
                else {
                    return Ok(None);
                };
                earliest = Some(earliest.map_or(delay, |prior: u64| prior.min(delay)));
            }
            if outcome.outstanding_targets == 0 {
                if matches!(fanout.mls_state(), FanoutMlsState::Pending(_)) {
                    return Ok(None);
                }

                continue;
            }
            for index in fanout.outstanding_target_indexes() {
                if let Some(delay_ms) = frozen_fanout_target_retry_delay_ms(&fanout, index, now_ms)
                {
                    earliest = Some(earliest.map_or(delay_ms, |prior: u64| prior.min(delay_ms)));
                }
            }
            // The first fanout still below its required acknowledgements, or
            // awaiting MLS confirmation, is the group-scoped ordering barrier,
            // so later NotAttempted records cannot pull this cutoff forward and
            // cause a scheduler polling loop. A fanout that met quorum and owes
            // only secondary replication is not a barrier: the fanouts behind
            // it are driven in the same pass, so their clocks count too
            // (mdk#2762).
            let outcome = fanout.outcome();
            if matches!(fanout.mls_state(), FanoutMlsState::Pending(_))
                || outcome.accepted_targets < fanout.request().required_acks.max(1)
            {
                return Ok(earliest);
            }
        }
        Ok(earliest)
    }

    fn welcome_retry_delay_ms(
        &self,
        welcomes: &[TransportMessage],
        now_ms: u64,
    ) -> AccountResult<Option<u64>> {
        let mut earliest = None;
        for welcome in welcomes {
            let Some(fanout) = self.session.transport_fanout(&welcome.id)? else {
                // No durable attempt cutoff exists yet. Use the ordinary
                // scheduler delay for preparation or local bookkeeping.
                return Ok(None);
            };
            for target in &fanout.targets {
                if let Some(delay_ms) = transport_retry_delay_ms(target, now_ms) {
                    if target.last_attempt_at.is_none() {
                        return Ok(None);
                    }
                    earliest = Some(earliest.map_or(delay_ms, |prior: u64| prior.min(delay_ms)));
                }
            }
        }
        Ok(earliest)
    }

    pub fn prepare_convergence_cutoff_delay_ms(
        &mut self,
        group_id: &GroupId,
    ) -> AccountResult<Option<u64>> {
        Ok(self.session.prepare_convergence_cutoff_delay_ms(group_id)?)
    }

    pub fn deferred_peel_cutoff_delay_ms(
        &mut self,
        group_id: &GroupId,
    ) -> AccountResult<Option<u64>> {
        Ok(self.session.deferred_peel_cutoff_delay_ms(group_id)?)
    }

    /// Whether this group's durable leave request owes its next step;
    /// schedulers must keep a wakeup armed while this holds.
    pub fn leave_redrive_owed(&mut self, group_id: &GroupId) -> AccountResult<bool> {
        Ok(self.session.leave_redrive_owed(group_id)?)
    }

    /// Cancel this group's blocked leave on this device; see
    /// `Engine::cancel_leave`.
    pub fn cancel_leave(&mut self, group_id: &GroupId) -> AccountResult<()> {
        Ok(self.session.cancel_leave(group_id)?)
    }

    /// Milliseconds until a scheduled SelfRemove auto-commit for this group is
    /// due; schedulers must keep a wakeup armed while this is `Some`.
    pub fn scheduled_self_remove_auto_commit_delay_ms(
        &mut self,
        group_id: &GroupId,
    ) -> AccountResult<Option<u64>> {
        Ok(self
            .session
            .scheduled_self_remove_auto_commit_delay_ms(group_id)?)
    }

    pub fn members(&self, group_id: &GroupId) -> AccountResult<Vec<Member>> {
        Ok(self.session.members(group_id)?)
    }

    pub fn own_leaf_index(&self, group_id: &GroupId) -> AccountResult<u32> {
        Ok(self.session.own_leaf_index(group_id)?)
    }

    /// Drain any session effects queued by the engine without an inbound
    /// transport delivery (e.g. `GroupHydrationQuarantined` queued during
    /// `open()` hydration, or `GroupHydrationRecovered` queued by a successful
    /// `retry_hydrate_quarantined_group`). Without this, those events only
    /// reach app/runtime subscribers when an unrelated relay delivery happens
    /// to trigger a drain (mdk#426). Publishes any incidental transport
    /// work the same way `ingest_delivery` does.
    pub async fn drain(&mut self) -> AccountResult<AccountDeviceEffects> {
        let mut output = self.drain_without_fanout_resume().await?;
        let resumed = self.resume_outbound_fanouts().await?;
        output.extend(resumed);
        Ok(output)
    }

    /// [`Self::drain`] without resuming retained outbound fanouts, for a
    /// caller with no live transport yet. Startup hydration drains after
    /// every batch; resuming there re-drove every outstanding fanout per
    /// batch and held live transport behind them (mdk#3367). The caller's
    /// first full drain after transport activation resumes them once.
    pub async fn drain_without_fanout_resume(&mut self) -> AccountResult<AccountDeviceEffects> {
        let effects = self.session.drain();
        self.publish_session_effects(effects).await
    }

    /// Ingest a borrowed delivery through the ordinary engine and publication path.
    /// Its transport owner retains the frame until the operation is acknowledged.
    /// Recovery controls also drain independently authorized native work restored
    /// by hydration, even when the control itself is ignored.
    pub async fn ingest_delivery(
        &mut self,
        delivery: &TransportDelivery,
    ) -> AccountResult<AccountIngestEffects> {
        self.ingest_delivery_with_observer(delivery, |_, _, _| {})
            .await
    }

    /// Observe completed phase timings without changing ingest/publication ordering.
    /// Cancellation does not emit a completed phase; callers own whole-operation tracking.
    /// The delivery and its wire payload remain borrowed through every phase.
    pub async fn ingest_delivery_with_observer(
        &mut self,
        delivery: &TransportDelivery,
        mut observe: impl FnMut(AccountIngestPhase, Duration, bool) + Send,
    ) -> AccountResult<AccountIngestEffects> {
        if delivery.account_id != self.session.self_id() {
            return Err(AccountError::WrongAccountDelivery);
        }
        let started = Instant::now();
        let ingested = match self.session.ingest_delivery(delivery).await {
            Ok(IngestEffects {
                outcome: IngestOutcome::GroupRecovery { recovery },
                ..
            }) => {
                let ingested = self
                    .ingest_group_recovery(&delivery.message, &recovery)
                    .await;
                observe(
                    AccountIngestPhase::Engine,
                    started.elapsed(),
                    ingested.is_ok(),
                );
                let accepted = ingested?;
                let mut ingested = AccountIngestEffects {
                    // Preserve the authenticated classification for consumers;
                    // accepting a recovery control is not accepting a Welcome.
                    outcome: IngestOutcome::GroupRecovery { recovery },
                    left_object_unpersisted: !accepted,
                    effects: AccountDeviceEffects::default(),
                };
                let restored = self.session.drain();
                if !restored.is_empty() {
                    let started = Instant::now();
                    let published = self.publish_session_effects(restored).await;
                    observe(
                        AccountIngestPhase::EffectPublication,
                        started.elapsed(),
                        published.is_ok(),
                    );
                    // The control contributes no native effects. Move the
                    // restored batch whole, including its fanout summaries.
                    ingested.effects = published?;
                }
                return Ok(ingested);
            }
            ingested => ingested,
        };
        observe(
            AccountIngestPhase::Engine,
            started.elapsed(),
            ingested.is_ok(),
        );
        let IngestEffects {
            outcome,
            left_object_unpersisted,
            effects,
            valid_proposal_groups,
        } = ingested?;
        let started = Instant::now();
        let published = self.publish_session_effects(effects).await;
        observe(
            AccountIngestPhase::EffectPublication,
            started.elapsed(),
            published.is_ok(),
        );
        let mut effects = published?;
        if matches!(
            outcome,
            IngestOutcome::Ignored {
                category: cgka_traits::ingest::InputRejectionCategory::OwnEcho
            }
        ) {
            effects.extend(self.acknowledge_own_echo(delivery).await?);
        }
        // Publication reconciles epoch changes, including its deferred retries.
        let mut noted = HashSet::new();
        for group_id in &valid_proposal_groups {
            if noted.insert(group_id) {
                self.note_valid_state_bearing_input(group_id)?;
            }
        }
        Ok(AccountIngestEffects {
            outcome,
            left_object_unpersisted,
            effects,
        })
    }

    pub async fn publish_session_effects(
        &mut self,
        effects: SessionEffects,
    ) -> AccountResult<AccountDeviceEffects> {
        self.publish_session_effects_with_audit_context(effects, None)
            .await
    }

    async fn publish_session_effects_with_audit_context(
        &mut self,
        effects: SessionEffects,
        context: Option<AuditEventContext>,
    ) -> AccountResult<AccountDeviceEffects> {
        let mut output = AccountDeviceEffects::default();
        let mut queue = VecDeque::new();
        output.absorb_session_effects(effects, &mut queue);
        self.publish_queue(&mut output, &mut queue, context).await?;
        self.reconcile_confirmed_own_leaf_rotations(&output.events);
        let superseded = self.reconcile_superseded_maintenance(&output.events)?;
        output.superseded_intents.extend(superseded);
        Ok(output)
    }

    async fn publish_queue(
        &mut self,
        output: &mut AccountDeviceEffects,
        queue: &mut VecDeque<PublishWork>,
        context: Option<AuditEventContext>,
    ) -> AccountResult<()> {
        // Reconcile cancelled native work before consuming a restored batch.
        self.session.refresh_welcome_holds();
        while let Some(work) = queue.pop_front() {
            match work {
                PublishWork::ApplicationMessage {
                    msg,
                    queued_intent,
                    group_id,
                    app_event_id,
                    source_epoch,
                    retention,
                    authority,
                } => {
                    let status = Box::pin(self.publish_one(
                        msg,
                        None,
                        Some(OutboundApplicationMessage {
                            group_id,
                            app_event_id,
                            source_epoch,
                            retention,
                            authority,
                        }),
                        output,
                        queue,
                        context.clone(),
                    ))
                    .await?;
                    self.rearm_unstaged_queued_intent(queued_intent, status);
                }
                PublishWork::Proposal { msg, queued_intent } => {
                    let status =
                        Box::pin(self.publish_one(msg, None, None, output, queue, context.clone()))
                            .await?;
                    self.rearm_unstaged_queued_intent(queued_intent, status);
                }
                PublishWork::GroupCreated { welcomes, pending } => {
                    Box::pin(self.publish_group_created(
                        welcomes,
                        pending,
                        output,
                        queue,
                        context.clone(),
                    ))
                    .await?;
                }
                PublishWork::FoundingGroupCreated { welcomes } => {
                    self.publish_founding_group_created(welcomes, output, queue, context.clone())
                        .await?;
                }
                PublishWork::AutoPublish {
                    msg,
                    pending,
                    welcomes,
                } if welcomes.is_empty() => {
                    self.publish_pending(vec![msg], pending, output, queue, context.clone())
                        .await?;
                }
                PublishWork::GroupEvolution {
                    msg,
                    welcomes,
                    pending,
                }
                | PublishWork::AutoPublish {
                    msg,
                    welcomes,
                    pending,
                } => {
                    Box::pin(self.publish_group_evolution(
                        msg,
                        welcomes,
                        pending,
                        output,
                        queue,
                        context.clone(),
                    ))
                    .await?;
                }
            }
        }
        Ok(())
    }

    /// Resume every incomplete frozen fanout in original staging order.
    pub async fn resume_outbound_fanouts(&mut self) -> AccountResult<AccountDeviceEffects> {
        self.resume_outbound_fanouts_for_group(None)
            .await
            .map(|(effects, _blocked_groups)| effects)
    }

    /// Notify only after the ordinary durable-fanout path records acceptance.
    fn record_published_application_fanout(
        &self,
        fanout: &OutboundFanout,
        output: &mut AccountDeviceEffects,
    ) {
        let previous_count = output.published_app_messages.len();
        record_published_application_fanout(fanout, output);
        if output.published_app_messages.len() == previous_count {
            return;
        }
        let observer = self
            .publication_progress
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        if let Some(observer) = observer {
            (observer.observe)(
                self.session.group_authority_view(),
                output
                    .published_app_messages
                    .last()
                    .expect("recorded publication"),
            );
        }
    }

    /// Retire terminal accepted application fanouts only after the app has
    /// durably finalized their optimistic projections.
    ///
    /// Until this acknowledgement arrives, restart drains replay the same
    /// publication metadata. App projection is idempotent, so a crash between
    /// its database commit and this call leaves a harmless replay instead of a
    /// permanently pending message. A fanout whose queued intent has not
    /// retired stays too, for the pass that retires it (mdk#2332).
    pub fn acknowledge_published_app_messages(
        &self,
        published_messages: &[PublishedApplicationMessage],
    ) -> AccountResult<()> {
        for published in published_messages {
            let fanouts = self
                .session
                .outbound_fanouts_for_group(&published.group_id)?;
            for fanout in fanouts {
                let outcome = fanout.outcome();
                let matches_publication = fanout.application_message().is_some_and(|application| {
                    application.app_event_id == published.app_event_id
                        && outcome.message_id == published.message_id
                });
                if matches_publication
                    && outcome.accepted_targets > 0
                    && outcome.fanout_complete
                    && !matches!(fanout.mls_state(), FanoutMlsState::Pending(_))
                    && !self.names_unretired_queued_intent(&fanout)?
                {
                    self.session.delete_outbound_fanout(fanout.message_id())?;
                }
            }
        }
        Ok(())
    }

    /// Whether the owner has asked the current pass to yield dispensable
    /// secondary relay work to a waiting foreground send.
    fn secondary_retry_yield_requested(&self) -> bool {
        self.publication_progress
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
            .is_some_and(|progress| {
                progress
                    .secondary_retry_yield
                    .clone()
                    .now_or_never()
                    .is_some()
            })
    }

    /// Whether `delivery` is a group relay's copy of this account's own commit
    /// that is still pending, from one of the commit's relays not yet recorded
    /// as holding it: the copy whose ingest acknowledges that relay and
    /// confirms the commit (mdk#2332). A host that skips events it already
    /// holds before ingest must still ingest this one; it may skip every other
    /// copy of an own event.
    ///
    /// A group the session opened only seeded is judged by its stored
    /// fanouts, without hydrating it: the ingest that follows hydrates it and
    /// reports what hydration announces, which a skipped copy never would.
    /// So a commit a previous process left pending counts.
    pub fn takes_own_echo(&self, delivery: &TransportDelivery) -> AccountResult<bool> {
        Ok(self.own_echo_target(delivery)?.is_some()
            || self.seeded_own_echo_group(delivery)?.is_some())
    }

    /// The group of a copy that would be an own echo once its group, which
    /// the session opened only seeded (mdk#1161), is hydrated: a stored
    /// pending commit holds the copy's exact event and its relay among the
    /// targets that take an acknowledgement. Read without hydrating.
    fn seeded_own_echo_group<'a>(
        &self,
        delivery: &'a TransportDelivery,
    ) -> AccountResult<Option<&'a GroupId>> {
        let Some((group_id, endpoint)) = group_relay_copy(delivery) else {
            return Ok(None);
        };
        Ok(echo_target_among(
            self.session.seeded_group_outbound_fanouts(group_id)?,
            delivery,
            endpoint,
        )
        .map(|_| group_id))
    }

    /// The pending commit whose exact event `delivery` carries, and its
    /// relay's index among the commit's targets, when `delivery` is a group
    /// relay's copy and that relay is not yet recorded as holding the commit.
    /// A copy under another event id, from a relay that is not a target, or
    /// in a group not resolving a publication of its own, has none.
    fn own_echo_target(
        &self,
        delivery: &TransportDelivery,
    ) -> AccountResult<Option<(OutboundFanout, usize)>> {
        let Some((group_id, endpoint)) = group_relay_copy(delivery) else {
            return Ok(None);
        };
        // Only a group whose own publication is unresolved holds a pending
        // commit, so no other copy reads storage.
        if !self
            .session
            .epoch_state(group_id)
            .is_some_and(|state| state.is_resolving_local_publish())
        {
            return Ok(None);
        }
        Ok(echo_target_among(
            self.session.outbound_fanouts_for_group(group_id)?,
            delivery,
            endpoint,
        ))
    }

    /// The account's own subscription received a pending commit's exact event
    /// from `delivery`'s relay (mdk#2332). That relay holds the commit,
    /// whatever it answered the publish, so it acknowledged it: its target is
    /// recorded `Accepted` by echo, and the group's fanouts are driven, which
    /// confirms the commit. A copy under another event id, from a relay that
    /// is not a target, or in a group not resolving a publication of its own,
    /// shows nothing ([`Self::own_echo_target`], the rule
    /// [`Self::takes_own_echo`] applies too). The adapter's local loop-back of
    /// a publish that asked for an acknowledgement names only relays whose
    /// receipts it got, so it adds no acknowledgement the publish did not
    /// make; every commit attempt asks for one.
    ///
    /// The engine answers an own echo from its stored record without
    /// hydrating the group, so a commit a previous process left pending in a
    /// group this session opened only seeded (mdk#1161) is hidden until the
    /// group hydrates. When the group's stored fanouts show the copy is an
    /// echo, it is hydrated here, and what hydration announces goes out with
    /// this ingest's effects. A group that fails to hydrate is quarantined,
    /// and the copy then acknowledges nothing.
    async fn acknowledge_own_echo(
        &mut self,
        delivery: &TransportDelivery,
    ) -> AccountResult<AccountDeviceEffects> {
        let mut output = AccountDeviceEffects::default();
        if let Some(group_id) = self.seeded_own_echo_group(delivery)? {
            self.session.ensure_group_hydrated(group_id)?;
            let hydrated = self.session.drain();
            if !hydrated.is_empty() {
                output.extend(self.publish_session_effects(hydrated).await?);
            }
        }
        let Some((mut fanout, index)) = self.own_echo_target(delivery)? else {
            return Ok(output);
        };
        if !fanout.acknowledge_target(index, FanoutAcknowledgement::Echo)? {
            return Ok(output);
        }
        self.session
            .put_observed_outbound_fanout(&mut fanout, self.wall_clock.now_ms())?;
        tracing::debug!(
            target: TRACE_TARGET,
            method = "acknowledge_own_echo",
            "own echo acknowledged a pending commit"
        );
        let group_id = fanout.group_id().cloned();
        output.extend(
            self.resume_outbound_fanouts_for_group(group_id.as_ref())
                .await?
                .0,
        );
        Ok(output)
    }

    async fn resume_outbound_fanouts_for_group(
        &mut self,
        group_id: Option<&GroupId>,
    ) -> AccountResult<(AccountDeviceEffects, HashSet<GroupId>)> {
        let fanouts = match group_id {
            Some(group_id) => self.session.outbound_fanouts_for_group(group_id)?,
            None => self.session.outbound_fanouts()?,
        };
        let mut output = AccountDeviceEffects::default();
        let mut queue = VecDeque::new();
        let mut blocked_groups = HashSet::new();
        for fanout in fanouts {
            if fanout
                .group_id()
                .is_some_and(|fanout_group| blocked_groups.contains(fanout_group))
            {
                continue;
            }
            let outcome = fanout.outcome();
            if outcome.outstanding_targets > 0
                || matches!(fanout.mls_state(), FanoutMlsState::Pending(_))
                || !fanout.pending_post_confirmation_welcomes().is_empty()
            {
                let fanout_group = fanout.group_id().cloned();
                let status = Box::pin(self.drive_outbound_fanout(
                    fanout,
                    &mut output,
                    &mut queue,
                    None,
                    RollbackPass::Later,
                ))
                .await?;
                if status.retry_deferred
                    && (!status.met_required_acks || self.secondary_retry_yield_requested())
                    && let Some(fanout_group) = fanout_group
                {
                    // Preserve per-group staging order. An older exact event
                    // that is still in durable backoff below its required
                    // acknowledgements is a barrier for newer fanouts in this
                    // group, but must not block unrelated groups during an
                    // account-wide drain. Secondary replication after quorum
                    // is not a barrier, as for queued intents: a send one relay
                    // accepted must not hold later sends behind another
                    // relay's backoff of up to an hour (mdk#2762). Once the
                    // owner asks secondary work to yield for a foreground
                    // send, the pass stops here as before, so it does not go
                    // on to wait on later fanouts' stalled relays instead.
                    blocked_groups.insert(fanout_group);
                }
            } else if outcome.accepted_targets > 0 && fanout.application_message().is_some() {
                // A crash after the accepting result was saved, before its
                // intent was retired (mdk#2332).
                self.retire_drained_queued_intent(&fanout);
                self.record_published_application_fanout(&fanout, &mut output);
                output.fanout.push(outcome);
            } else if !self.retire_drained_queued_intent(&fanout) {
                // Kept, still naming its intent, for the next pass.
                output.fanout.push(outcome);
            } else {
                // Complete when found: a crash after its last result was saved.
                // A fanout that met its acknowledgements, such as a confirmed
                // commit, did not fail; the pass that completed it reported it.
                if !frozen_fanout_report(&fanout).met_required_acks() {
                    let reason = "insufficient publish acknowledgements".to_owned();
                    output.failures.push(PublishFailure {
                        oversized: OversizedEvent::of_fanout(&fanout),
                        no_usable_relay: has_no_usable_relay(&fanout),
                        message_id: fanout
                            .published_message_id()
                            .unwrap_or_else(|| fanout.message_id())
                            .clone(),
                        reason: reason.clone(),
                    });
                    record_failed_application_fanout(&fanout, reason, &mut output);
                }
                output.fanout.push(outcome);
                self.session
                    .retire_outbound_fanout(&fanout, commit_refusal_of(&fanout).as_ref())?;
            }
        }
        self.publish_queue(&mut output, &mut queue, None).await?;
        self.reconcile_confirmed_own_leaf_rotations(&output.events);
        let superseded = self.reconcile_superseded_maintenance(&output.events)?;
        output.superseded_intents.extend(superseded);
        Ok((output, blocked_groups))
    }

    /// Reconcile against the final canonical local leaf after all batch effects,
    /// since branch selection can restore a copy terminated earlier in the batch.
    fn reconcile_confirmed_own_leaf_rotations(&mut self, events: &[GroupEvent]) {
        for event in events {
            let (group_id, restored_at) = match event {
                GroupEvent::EpochChanged { group_id, .. }
                | GroupEvent::LocalGroupCopyTerminated { group_id, .. } => (group_id, None),
                GroupEvent::LocalGroupCopyRestored { group_id } => {
                    (group_id, Some(self.wall_clock.now()))
                }
                _ => continue,
            };
            if let Some(owned) = self.pending_leaf_reconciliations.get_mut(group_id) {
                if restored_at.is_some() {
                    *owned = restored_at;
                }
            } else {
                self.pending_leaf_reconciliations
                    .insert(group_id.clone(), restored_at);
            }
        }
        let mut pending = std::mem::take(&mut self.pending_leaf_reconciliations);
        pending.retain(|group_id, restored_at| {
            if self
                .reconcile_own_leaf_group(group_id, *restored_at)
                .is_err()
            {
                tracing::warn!(target: TRACE_TARGET,
                    method = "reconcile_confirmed_own_leaf_rotations",
                    error_kind = "maintenance_reconciliation_retry",
                    "committed group maintenance reconciliation remains owned for retry");
                return true;
            }
            false
        });
        self.pending_leaf_reconciliations = pending;
    }

    fn reconcile_own_leaf_group(
        &mut self,
        group_id: &GroupId,
        restored_at: Option<Timestamp>,
    ) -> AccountResult<()> {
        let now = self.wall_clock.now();
        // A surviving sibling keeps the account in the roster, but it
        // cannot supply this copy's removed local leaf for rotation.
        let local_member_present = !self.session.group_record(group_id)?.is_terminal()
            && self
                .session
                .canonical_group_membership(group_id)?
                .local_leaf_active;
        if !local_member_present {
            for mut obligation in self.session.maintenance_obligations_for_group(group_id)? {
                if matches!(
                    obligation.phase,
                    MaintenancePhase::Complete | MaintenancePhase::Failed
                ) {
                    continue;
                }
                obligation.phase = MaintenancePhase::Failed;
                obligation.last_failure_code = Some("local_member_removed".into());
                self.persist_maintenance_obligation(&obligation)?;
                self.maintenance_quiet_monotonic.remove(&obligation.id);
            }
            if let Some(mut state) = self.session.group_maintenance(group_id)? {
                // Enrollment is policy, not current membership. Preserve it
                // for a later canonical restoration; terminal groups are
                // excluded from the maintenance tick's live group set.
                state.next_periodic_rotation_at = None;
                self.session.put_group_maintenance(&state)?;
            }
            return Ok(());
        }
        let obligations = self.session.maintenance_obligations_for_group(group_id)?;
        if let Some(mut state) = self.session.group_maintenance(group_id)?
            && state.periodic_enrolled
            && state.next_periodic_rotation_at.is_none()
        {
            let baseline = Self::periodic_baseline(&state, &obligations, restored_at, now);
            state.next_periodic_rotation_at =
                Some(self.fresh_periodic_deadline(group_id, baseline)?);
            self.session.put_group_maintenance(&state)?;
        }
        let current = self.session.own_leaf_hash(group_id)?;
        for mut obligation in obligations {
            if matches!(
                obligation.phase,
                MaintenancePhase::Complete | MaintenancePhase::Failed
            ) {
                continue;
            }
            if obligation
                .own_leaf_baseline_hash
                .as_ref()
                .is_some_and(|baseline| baseline.as_slice() != current.as_slice())
            {
                self.complete_maintenance_obligation(&mut obligation, now)?;
            } else {
                self.reset_obligation_quiet(obligation, now)?;
            }
        }
        Ok(())
    }

    fn periodic_baseline(
        state: &cgka_traits::maintenance::GroupMaintenanceState,
        obligations: &[MaintenanceObligation],
        restored_at: Option<Timestamp>,
        now: Timestamp,
    ) -> Timestamp {
        if let Some(restored_at) = restored_at {
            return restored_at;
        }
        if obligations.iter().any(|obligation| {
            obligation.group_id == state.group_id
                && obligation.phase == MaintenancePhase::Failed
                && obligation.last_failure_code.as_deref() == Some("local_member_removed")
        }) {
            return now;
        }
        state.last_own_leaf_rotation_at.unwrap_or(now)
    }

    fn fresh_periodic_deadline(
        &mut self,
        group_id: &GroupId,
        baseline: Timestamp,
    ) -> AccountResult<Timestamp> {
        let earliest = baseline.0.saturating_add(PERIODIC_MIN_SECS);
        let latest = baseline.0.saturating_add(PERIODIC_MAX_SECS);
        let first = baseline.0.saturating_add(
            self.entropy
                .sample_inclusive(PERIODIC_MIN_SECS, PERIODIC_MAX_SECS),
        );
        let mut deadline = first;
        loop {
            let mut hasher = Sha256::new();
            hasher.update(b"marmot-periodic-self-update-v1");
            hasher.update((group_id.as_slice().len() as u64).to_be_bytes());
            hasher.update(group_id.as_slice());
            hasher.update(deadline.to_be_bytes());
            let id = cgka_traits::MessageId::new(hasher.finalize().to_vec());
            if self.session.maintenance_obligation(&id)?.is_none() {
                return Ok(Timestamp(deadline));
            }
            deadline = if deadline < latest {
                deadline + 1
            } else {
                earliest
            };
            if deadline == first {
                return Err(cgka_traits::EngineError::Backend(
                    "periodic deadline exhausted".into(),
                )
                .into());
            }
        }
    }

    /// Retire the evolutions behind commits this batch announced as
    /// superseded, and decide what becomes of the intent behind each own
    /// commit (mdk#1734). Returns the per-commit decisions for the effects.
    fn reconcile_superseded_maintenance(
        &mut self,
        events: &[GroupEvent],
    ) -> AccountResult<Vec<SupersededIntentReport>> {
        let superseded = events
            .iter()
            .filter_map(|event| match event {
                GroupEvent::GroupStateInvalidated {
                    group_id,
                    invalidated_commit_id,
                    ..
                } => Some((group_id.clone(), invalidated_commit_id.clone())),
                _ => None,
            })
            .collect::<Vec<_>>();
        if superseded.is_empty() {
            return Ok(Vec::new());
        }

        let now = self.wall_clock.now();
        let mut reports = Vec::new();
        for (group_id, invalidated_commit_id) in superseded {
            let evolutions = self.session.group_evolutions_for_group(&group_id)?;
            for evolution in evolutions.into_iter().filter(|evolution| {
                evolution.signed_message_id.as_ref() == Some(&invalidated_commit_id)
                    && evolution.phase != GroupEvolutionPhase::SupersededByConvergence
            }) {
                self.mark_evolution_superseded(evolution, now)?;
            }
            if let Some(report) = self
                .session
                .reissue_superseded_own_commit(&invalidated_commit_id)?
            {
                reports.push(report);
            }
        }
        Ok(reports)
    }

    /// Re-derive a supersession whose `GroupStateInvalidated` announcement was
    /// never consumed, from the disposition the engine already made durable.
    ///
    /// [`Self::reconcile_superseded_maintenance`] is purely event-driven, and
    /// engine events live in an in-memory buffer. The convergence apply
    /// transaction persists a superseded commit's disposition, and only *then*
    /// does this layer publish the pass's outbound work — awaited transport
    /// round trips, any of which can also return `Err` and abandon the batch —
    /// before the event reconciler runs. A process death or an error anywhere in
    /// that window loses the announcement, and both withdrawal emitters announce
    /// at most once: `emit_rolled_back_commits` skips a commit an earlier pass
    /// already parked, and `emit_superseded_processed_commits` durably retires
    /// its record so no later pass sees it as previously applied.
    ///
    /// A stranded evolution is not inert. [`Self::run_due_maintenance`] takes
    /// the first non-superseded `SelfUpdate` evolution behind an obligation: a
    /// `Confirmed` one completes the obligation outright, so the leaf rotation it
    /// owed is dropped and the next periodic rotation is rescheduled from a leaf
    /// that never actually changed; a `Prepared`/`Attempting` one keeps
    /// republishing the exact commit convergence already withdrew.
    ///
    /// Same philosophy as `AppClient::reconcile_branch_selection_withdrawals`,
    /// and derivable for the same reason: an evolution and its commit's
    /// disposition live in one account database, so the answer is a total
    /// function of stored state rather than information this layer can lose.
    /// `ConvergenceDeferred` (parked off the selected branch) and
    /// `EpochInvalidated` (terminally retired) are exactly what the two
    /// withdrawal emitters leave behind; every other state means the commit is
    /// still live or still in flight, and is left alone.
    ///
    /// Flips forward only, exactly as the event path does. Re-adoption has no
    /// account-layer consumer at all — `GroupStateRevalidated` is not handled
    /// here — and the event path never un-marks a superseded evolution, so
    /// neither does this. It is therefore a fixed point: a converged account
    /// writes nothing, and a flipped evolution is skipped on every later run.
    fn reconcile_superseded_maintenance_from_state(
        &mut self,
        now: Timestamp,
    ) -> AccountResult<Vec<SupersededIntentReport>> {
        // A refusal of a withdrawn commit no longer warns; drop its record.
        for refusal in self.session.commit_refusals()? {
            if self.commit_withdrawn(&refusal.commit_id)?
                && self.session.check_group_live(&refusal.group_id).is_ok()
            {
                self.session.delete_commit_refusal(&refusal)?;
            }
        }
        for evolution in self.session.group_evolutions()? {
            if evolution.phase == GroupEvolutionPhase::SupersededByConvergence {
                continue;
            }
            let Some(commit_id) = evolution.signed_message_id.clone() else {
                continue;
            };
            if !matches!(
                self.session.stored_message_state(&commit_id)?,
                Some(MessageState::ConvergenceDeferred | MessageState::EpochInvalidated)
            ) {
                continue;
            }
            self.mark_evolution_superseded(evolution, now)?;
        }
        // Own commits carry their intent separately from evolutions; derive
        // their supersession from the same stored dispositions (mdk#1734).
        Ok(self.session.reissue_superseded_own_commits_from_state()?)
    }

    /// Retire an evolution that branch selection superseded, and settle the
    /// self-update obligation behind it.
    ///
    /// Sole writer of [`GroupEvolutionPhase::SupersededByConvergence`], shared
    /// by the event-driven and state-derived reconcilers so the two cannot
    /// disagree about what a supersession does.
    fn mark_evolution_superseded(
        &mut self,
        mut evolution: DurableGroupEvolution,
        now: Timestamp,
    ) -> AccountResult<()> {
        let group_id = evolution.group_id.clone();
        evolution.phase = GroupEvolutionPhase::SupersededByConvergence;
        self.session.put_group_evolution(&evolution)?;

        let GroupEvolutionSemantic::SelfUpdate { obligation_id, .. } = evolution.semantic else {
            return Ok(());
        };
        let Some(obligation_id) = obligation_id else {
            return Ok(());
        };
        let Some(mut obligation) = self.session.maintenance_obligation(&obligation_id)? else {
            return Ok(());
        };
        // `Failed` is terminal here, and deliberately `Complete` is not.
        //
        // [`Self::reconcile_confirmed_own_leaf_rotations`] fails every live
        // obligation in a group whose epoch change shows this device is no
        // longer a member, stamping `local_member_removed`. There is no local
        // leaf left to rotate, so no self-update can ever satisfy it. The same
        // fork parks the commits it displaced, so the state-derived reconciler
        // reaches that obligation with a genuine supersession — and re-arming it
        // to `Quiet` would put `run_due_maintenance` back on a `SelfUpdate` in a
        // group the device has left, failing once per tick forever and
        // invisibly: `MaintenanceRunSummary.failures` counts only obligations
        // sitting in `Failed`.
        //
        // A `Complete` obligation gets no such guard because un-completing it is
        // the point. A withdrawn commit takes back the very rotation that
        // completed the obligation behind it, and re-arming there is this
        // branch's PCS re-arm mechanism, not a bug. Completion by some *other*
        // rotation is already idempotent through the leaf-hash discriminator
        // below: that rotation left `own_leaf_hash` different from the
        // evolution's `own_leaf_before_hash`, so the branch taken is
        // `complete_maintenance_obligation` again.
        if obligation.phase == MaintenancePhase::Failed {
            return Ok(());
        }
        let selected_branch_rotated_own_leaf =
            evolution
                .own_leaf_before_hash
                .as_ref()
                .is_some_and(|before| {
                    self.session
                        .own_leaf_hash(&group_id)
                        .is_ok_and(|current| current.as_slice() != before.as_slice())
                });
        if selected_branch_rotated_own_leaf {
            self.complete_maintenance_obligation(&mut obligation, now)?;
        } else {
            obligation.phase = MaintenancePhase::Quiet;
            obligation.quiet_since = Some(now);
            obligation.not_before = None;
            obligation.semantic_rearm_count = obligation.semantic_rearm_count.saturating_add(1);
            obligation.last_failure_code = Some("superseded_by_convergence".into());
            self.maintenance_quiet_monotonic
                .insert(obligation.id.clone(), self.monotonic_clock.elapsed());
            self.persist_maintenance_obligation(&obligation)?;
        }
        Ok(())
    }

    /// Re-arm a drained intent whose event was never staged, as when its
    /// publish target could not be resolved: no fanout names the intent, so
    /// the next drain prepares it again. A staged event's fanout names its
    /// intent and retires it once the event resolves (mdk#2332).
    fn rearm_unstaged_queued_intent(
        &mut self,
        intent: Option<QueuedIntentRef>,
        status: PublishStatus,
    ) {
        if let Some(intent) = intent
            && status.staged_nothing()
        {
            self.session.retry_regenerated_queued_intent(&intent);
        }
    }

    /// Whether `fanout` names a queued intent that has not retired yet, as
    /// after a failed retirement (mdk#2332). The fanout is then the intent's
    /// only durable link to the message already sent, so it stays until a
    /// later pass retires the intent; deleting it first would let a drain
    /// after a restart prepare the intent again.
    fn names_unretired_queued_intent(&self, fanout: &OutboundFanout) -> AccountResult<bool> {
        let (Some(group_id), Some(intent_id)) = (fanout.group_id(), fanout.queued_intent_id())
        else {
            return Ok(false);
        };
        Ok(self.session.is_queued_outbound_intent(&QueuedIntentRef {
            group_id: group_id.clone(),
            intent_id: intent_id.clone(),
        })?)
    }

    /// Retire the queued intent a resolved application message or proposal
    /// was drained from (mdk#2332): once a relay accepted the event, or every
    /// relay refused it for good. A commit's intent retires with the commit.
    /// Returns false when the intent could not be deleted: the fanout must
    /// then stay stored, still naming it, for a later pass to retry, since a
    /// drain that found the intent unnamed would prepare it a second time.
    fn retire_drained_queued_intent(&mut self, fanout: &OutboundFanout) -> bool {
        let outcome = fanout.outcome();
        let (Some(group_id), Some(intent_id)) = (fanout.group_id(), fanout.queued_intent_id())
        else {
            return true;
        };
        if !matches!(fanout.mls_state(), FanoutMlsState::NotApplicable)
            || (outcome.accepted_targets == 0 && outcome.outstanding_targets > 0)
        {
            return true;
        }
        let intent = QueuedIntentRef {
            group_id: group_id.clone(),
            intent_id: intent_id.clone(),
        };
        if self.session.retire_drained_queued_intent(&intent).is_err() {
            tracing::warn!(
                target: TRACE_TARGET,
                method = "retire_drained_queued_intent",
                error_kind = "queued_intent_cleanup",
                "resolved queued send could not clear its durable intent; retrying on a later pass"
            );
            return false;
        }
        true
    }

    /// Confirm a published commit, retrying on transient backend contention.
    ///
    /// `confirm_published` is the apply half of publish-before-apply: by the
    /// time it runs the commit is already on the wire, so abandoning it on a
    /// transient `SQLITE_BUSY` would leave the local device behind an epoch the
    /// group has accepted — a self-inflicted fork seam. The engine's confirm
    /// path is structured to be retry-safe (the in-memory state-machine
    /// transition only runs after its durable storage transaction commits), so
    /// re-running after a lock blip converges. The backend already blocks up to
    /// its `busy_timeout` per attempt; these few extra attempts cover the rare
    /// case where contention outlives that window. A non-transient error, or
    /// exhausted attempts, propagates as before.
    async fn confirm_published_retrying(
        &mut self,
        pending: PendingStateRef,
    ) -> AccountResult<SessionEffects> {
        const MAX_CONFIRM_ATTEMPTS: u32 = 4;
        let mut attempt = 0;
        loop {
            match self.session.confirm_published(pending).await {
                Ok(effects) => return Ok(effects),
                Err(e) if e.is_transient() && attempt + 1 < MAX_CONFIRM_ATTEMPTS => {
                    attempt += 1;
                    tracing::warn!(
                        target: TRACE_TARGET,
                        method = "confirm_published_retrying",
                        attempt,
                        "confirm hit a transient backend lock; retrying"
                    );
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    async fn confirm_published_fanout_retrying(
        &mut self,
        pending: PendingStateRef,
        fanout: &mut OutboundFanout,
    ) -> AccountResult<SessionEffects> {
        const MAX_CONFIRM_ATTEMPTS: u32 = 4;
        let mut attempt = 0;
        loop {
            match self.session.confirm_published_fanout(pending, fanout).await {
                Ok(effects) => return Ok(effects),
                Err(e) if e.is_transient() && attempt + 1 < MAX_CONFIRM_ATTEMPTS => {
                    attempt += 1;
                    tracing::warn!(
                        target: TRACE_TARGET,
                        method = "confirm_published_fanout_retrying",
                        attempt,
                        "fanout confirm hit a transient backend lock; retrying"
                    );
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    async fn publish_pending(
        &mut self,
        messages: Vec<TransportMessage>,
        pending: PendingStateRef,
        output: &mut AccountDeviceEffects,
        queue: &mut VecDeque<PublishWork>,
        context: Option<AuditEventContext>,
    ) -> AccountResult<()> {
        let maintenance_evolution = match messages.as_slice() {
            [message] => self.has_legacy_evolution_fanout(&message.id)?,
            _ => false,
        };
        if maintenance_evolution {
            // A crash can land after the first relay acknowledgement and its
            // durable maintenance-fanout write but before local MLS
            // confirmation. The accepted target is sufficient evidence to
            // apply the original staged evolution without another exposure.
            if let [message] = messages.as_slice()
                && let Some(fanout) = self.session.transport_fanout(&message.id)?
                && fanout
                    .targets
                    .iter()
                    .any(|target| target.state == TransportFanoutAttemptState::Accepted)
            {
                let effects = self.confirm_published_retrying(pending).await?;
                output
                    .pending
                    .push(PendingResolution::Confirmed { pending });
                output.absorb_session_effects(effects, queue);
                self.mark_transport_fanout_evolution_confirmed(&message.id);
                self.finish_transport_fanout(&message.id, output).await?;
                return Ok(());
            }

            let mut all_published = true;
            let mut any_accepted = false;
            let mut ambiguous_exposure = false;
            let mut retry_deferred = false;
            let mut message_ids = Vec::with_capacity(messages.len());
            for message in messages {
                message_ids.push(message.id.clone());
                let status = self
                    .publish_legacy_one(message, output, context.clone())
                    .await?;
                any_accepted |= status.accepted_by_any_endpoint;
                all_published &= status.met_required_acks;
                ambiguous_exposure |= status.possible_ambiguous_exposure;
                retry_deferred |= status.retry_deferred;
            }

            if all_published || any_accepted {
                let effects = self.confirm_published_retrying(pending).await?;
                output
                    .pending
                    .push(PendingResolution::Confirmed { pending });
                output.absorb_session_effects(effects, queue);
                for message_id in message_ids {
                    self.mark_transport_fanout_evolution_confirmed(&message_id);
                    self.finish_transport_fanout(&message_id, output).await?;
                }
            } else if !ambiguous_exposure && !retry_deferred {
                let effects = self.session.publish_failed(pending).await?;
                output
                    .pending
                    .push(PendingResolution::RolledBack { pending });
                output.absorb_session_effects(effects, queue);
            }
            return Ok(());
        }

        // A pending MLS state has one frozen group-message artifact. Its first
        // relay acknowledgement releases MLS inside `drive_outbound_fanout`;
        // remaining targets continue as an independent durable obligation.
        let mut messages = messages.into_iter();
        let Some(message) = messages.next() else {
            let effects = self.session.publish_failed(pending).await?;
            output
                .pending
                .push(PendingResolution::RolledBack { pending });
            output.absorb_session_effects(effects, queue);
            return Ok(());
        };
        debug_assert!(messages.next().is_none());
        Box::pin(self.publish_one(message, Some(pending), None, output, queue, context)).await?;
        Ok(())
    }

    async fn publish_group_created(
        &mut self,
        welcomes: Vec<TransportMessage>,
        pending: PendingStateRef,
        output: &mut AccountDeviceEffects,
        queue: &mut VecDeque<PublishWork>,
        context: Option<AuditEventContext>,
    ) -> AccountResult<()> {
        let mut welcomes = welcomes.into_iter();
        let Some(first_welcome) = welcomes.next() else {
            let effects = self.confirm_published_retrying(pending).await?;
            output
                .pending
                .push(PendingResolution::Confirmed { pending });
            output.absorb_session_effects(effects, queue);
            return Ok(());
        };
        Box::pin(self.publish_one_with_post_confirmation_welcomes(
            first_welcome,
            Some(PendingFanoutContinuation {
                pending,
                kind: FanoutPendingKind::CreateGroup,
                post_confirmation_welcomes: welcomes.collect(),
            }),
            None,
            output,
            queue,
            context,
        ))
        .await?;
        Ok(())
    }

    async fn publish_founding_group_created(
        &mut self,
        welcomes: Vec<TransportMessage>,
        output: &mut AccountDeviceEffects,
        _queue: &mut VecDeque<PublishWork>,
        context: Option<AuditEventContext>,
    ) -> AccountResult<()> {
        let group_id = output.events.iter().find_map(|event| match event {
            GroupEvent::GroupCreated { group_id } => Some(group_id.clone()),
            _ => None,
        });
        self.publish_welcome_fanout(welcomes, group_id, output, context)
            .await
    }

    async fn publish_group_evolution(
        &mut self,
        commit: TransportMessage,
        welcomes: Vec<TransportMessage>,
        pending: PendingStateRef,
        output: &mut AccountDeviceEffects,
        queue: &mut VecDeque<PublishWork>,
        context: Option<AuditEventContext>,
    ) -> AccountResult<()> {
        let commit_id = commit.id.clone();
        if self.has_legacy_evolution_fanout(&commit_id)? {
            let commit_status = self
                .publish_legacy_one(commit, output, context.clone())
                .await?;
            if commit_status.met_required_acks || commit_status.accepted_by_any_endpoint {
                let effects = self.confirm_published_retrying(pending).await?;
                output
                    .pending
                    .push(PendingResolution::Confirmed { pending });
                output.absorb_session_effects(effects, queue);
                self.mark_transport_fanout_evolution_confirmed(&commit_id);
                self.finish_transport_fanout(&commit_id, output).await?;
                debug_assert!(welcomes.is_empty());
                return Ok(());
            }
            if !commit_status.possible_ambiguous_exposure && !commit_status.retry_deferred {
                let effects = self.session.publish_failed(pending).await?;
                output
                    .pending
                    .push(PendingResolution::RolledBack { pending });
                output.absorb_session_effects(effects, queue);
            }
            return Ok(());
        }

        // Welcomes of a drained or automatic commit first reach the runtime
        // here; a host's reached it when its commit was accepted.
        self.note_retained_welcomes(&welcomes);
        // A queued invite the drain prepared is judged as a direct invite
        // is, before its commit is published: one whose commit or Welcome
        // fits none of its relays is retired unsent (mdk#2334).
        if self.session.pending_is_queued_invite(pending)?
            && let Some(refusal) = self.oversized_invite_events(&commit, &welcomes).await
        {
            let unretired =
                self.unretired_welcomes(welcomes.iter().map(|welcome| welcome.id.clone()));
            let effects = refuse_too_large(
                &mut self.session,
                pending,
                None,
                refusal.oversized,
                RollbackPass::Staging,
            )
            .await;
            // Recorded even when the rollback fails after it committed.
            let retired = self.retired_welcomes(unretired);
            self.record_v5_welcomes_refused(&retired, &refusal);
            let effects = effects?;
            output
                .pending
                .push(PendingResolution::RolledBack { pending });
            output.absorb_session_effects(effects, queue);
            return Ok(());
        }

        Box::pin(self.publish_one_with_post_confirmation_welcomes(
            commit,
            Some(PendingFanoutContinuation {
                pending,
                kind: self.session.pending_fanout_kind(pending)?,
                post_confirmation_welcomes: welcomes,
            }),
            None,
            output,
            queue,
            context,
        ))
        .await?;
        Ok(())
    }

    /// Self-update commits staged before mdk#2255 were published through the
    /// legacy `DurableTransportFanout`. Those exact events finish on the path
    /// that already holds their attempt and exposure history. Every new group
    /// evolution uses the frozen `OutboundFanout`, like every other commit.
    fn has_legacy_evolution_fanout(
        &self,
        message_id: &cgka_traits::MessageId,
    ) -> AccountResult<bool> {
        Ok(self
            .session
            .transport_fanout(message_id)?
            .is_some_and(|fanout| fanout.evolution_id.is_some()))
    }

    fn mark_transport_fanout_evolution_confirmed(&self, message_id: &cgka_traits::MessageId) {
        let Ok(Some(mut fanout)) = self.session.transport_fanout(message_id) else {
            return;
        };
        fanout.evolution_confirmed = true;
        if let Err(error) = self.session.put_transport_fanout(&fanout) {
            tracing::warn!(
                target: TRACE_TARGET,
                method = "mark_transport_fanout_evolution_confirmed",
                transient = error.is_transient(),
                "confirmed evolution fanout remains conservatively unconfirmed"
            );
        }
    }

    async fn retry_confirmed_transport_fanouts(
        &self,
        output: &mut AccountDeviceEffects,
    ) -> AccountResult<()> {
        let now = self.wall_clock.now();
        for fanout in self.session.transport_fanouts()? {
            if fanout
                .bounded_until
                .is_some_and(|bounded_until| bounded_until <= now)
            {
                // A saved acceptance that meets a Welcome's policy is
                // reconciled first; one that still cannot be keeps its record.
                let accepted = accepted_fanout_targets(&fanout);
                self.settle_met_welcome(&fanout.exact_message, accepted, fanout.required_acks);
                if self.welcome_still_owes_met_policy(&fanout, accepted) {
                    continue;
                }
                self.session.delete_transport_fanout(&fanout.id)?;
                continue;
            }
            if let Some(evolution_id) = fanout.evolution_id.as_ref()
                && !fanout.evolution_confirmed
            {
                // The marker write after confirmation is best-effort. Re-derive
                // it from the evolution the confirm transaction itself wrote,
                // so a failed marker cannot strand the remaining relays.
                let confirmed = self
                    .session
                    .group_evolutions()?
                    .into_iter()
                    .any(|evolution| {
                        &evolution.id == evolution_id
                            && evolution.phase == GroupEvolutionPhase::Confirmed
                    });
                if !confirmed {
                    continue;
                }
                self.mark_transport_fanout_evolution_confirmed(&fanout.id);
            }
            self.finish_transport_fanout(&fanout.id, output).await?;
        }
        Ok(())
    }

    /// Complete the endpoint snapshot for an already-persisted exact event.
    ///
    /// Group evolutions call this only after the first accepted acknowledgement
    /// has been applied locally. These attempts therefore cannot reopen the MLS
    /// pending state or change the canonical branch.
    async fn finish_transport_fanout(
        &self,
        message_id: &cgka_traits::MessageId,
        output: &mut AccountDeviceEffects,
    ) -> AccountResult<()> {
        if self.session.detached_welcome_publishes.contains(message_id) {
            return Ok(());
        }
        let Some(mut fanout) = self.session.transport_fanout(message_id)? else {
            return Ok(());
        };
        match self.welcome_hold(message_id, &fanout.exact_message.envelope)? {
            // A withdrawn or expired Welcome's remaining retries go with it,
            // once a saved acceptance that meets its policy is reconciled: an
            // expired Welcome the relays took is delivered, not expired. One
            // whose mark cannot land now keeps that acceptance, unpublished.
            Some(WelcomeHold::Withdrawn | WelcomeHold::Expired) => {
                let accepted = accepted_fanout_targets(&fanout);
                self.settle_met_welcome(&fanout.exact_message, accepted, fanout.required_acks);
                if !self.welcome_still_owes_met_policy(&fanout, accepted) {
                    self.session.delete_transport_fanout(message_id)?;
                }
                return Ok(());
            }
            // A staged one keeps them for when its commit confirms.
            Some(WelcomeHold::AwaitsCommit) => return Ok(()),
            None => {}
        }
        let remaining = fanout
            .targets
            .iter()
            .filter(|target| transport_fanout_target_retry_due(target, self.wall_clock.now()))
            .map(|target| target.endpoint.clone())
            .collect::<Vec<_>>();
        if remaining.is_empty() {
            // Its stored acceptances may meet the policy, though a stop
            // interrupted the mark.
            self.settle_met_welcome(
                &fanout.exact_message,
                accepted_fanout_targets(&fanout),
                fanout.required_acks,
            );
        } else {
            let required_acks = fanout.required_acks.max(1);
            let accepted_before = accepted_fanout_targets(&fanout);
            // Secondary retries are audited like the first pass, so a relay
            // that never received the exact event is visible (mdk#2255).
            let msg_id_hex = hex::encode(message_id.as_slice());
            let wire = publish_wire_metadata(&fanout.exact_message);
            let artifact_kind = match &fanout.exact_message.envelope {
                TransportEnvelope::Welcome { .. } => Some(MessageArtifactKind::Welcome),
                TransportEnvelope::GroupMessage { .. } => None,
            };
            let target_kind = publish_target_kind(&fanout.target).to_string();
            let publish_context = AuditEventContext {
                operation_id: Some(format!("publish-{msg_id_hex}")),
                ..AuditEventContext::default()
            };
            let welcome_facts = self.welcome_audit_facts(&fanout.exact_message);
            let audit_group_id = fanout
                .group_id
                .clone()
                .or_else(|| welcome_facts.as_ref().map(|facts| facts.group_id.clone()));
            let mut v5_welcome = self.v5_welcome_pass(
                welcome_facts,
                &remaining,
                required_acks,
                accepted_before,
                audit_v5::RouteSource::RetainedTarget,
            );
            // The pass's per-endpoint results, joined for its finished row
            // and a Welcome's delivery record: each report, and the endpoint
            // failures an adapter error names. One that names none leaves the
            // row's results incomplete.
            let collects_pass_report = v5_welcome.is_some()
                || matches!(
                    fanout.exact_message.envelope,
                    TransportEnvelope::Welcome { .. }
                );
            let mut pass_report = TransportPublishReport {
                message_id: message_id.clone(),
                accepted: Vec::new(),
                failed: Vec::new(),
                required_acks,
            };
            self.record_audit_event(
                audit_group_id.as_ref(),
                Some(publish_context.clone()),
                AuditEventKind::PublishAttempt {
                    msg_id: msg_id_hex.clone(),
                    artifact_kind,
                    target_kind: target_kind.clone(),
                    relay_url: None,
                    relay_urls: remaining
                        .iter()
                        .map(|endpoint| endpoint.0.clone())
                        .collect(),
                    required_acks: fanout.required_acks as u64,
                    transport: Some(wire.clone()),
                },
            );
            // The audit writes above may have waited past the deadline.
            if matches!(
                fanout.exact_message.envelope,
                TransportEnvelope::Welcome { .. }
            ) && self.welcome_past_deadline(message_id)?
            {
                return Ok(());
            }
            let mut pass_accepted = Vec::new();
            let mut pass_failed = Vec::new();
            // Concurrent single-endpoint publishes with `required_acks: 1`,
            // the per-endpoint contract the old sequential loop used; see
            // `drive_outbound_fanout` for why a multi-endpoint batch would
            // turn partial acceptance into a whole-call error.
            let adapter = &self.adapter;
            let account_id = self.session.self_id();
            let attempts = remaining.iter().map(|endpoint| {
                let request = TransportPublishRequest {
                    account_id: account_id.clone(),
                    message: fanout.exact_message.clone(),
                    target: publish_target_with_endpoints(&fanout.target, vec![endpoint.clone()]),
                    required_acks: 1,
                };
                async move { (endpoint.clone(), adapter.publish(request).await) }
            });
            if let Some(pass) = v5_welcome.as_mut() {
                pass.start(&self.audit);
            }
            for (endpoint, result) in futures::future::join_all(attempts).await {
                match result {
                    Ok(report) => {
                        if report
                            .accepted
                            .iter()
                            .any(|receipt| receipt.endpoint == endpoint)
                        {
                            pass_accepted.push(endpoint.0.clone());
                        } else {
                            pass_failed.push(PublishRelayFailure {
                                relay_url: endpoint.0.clone(),
                                reason: report
                                    .failed
                                    .iter()
                                    .find(|failure| failure.endpoint == endpoint)
                                    .map_or_else(
                                        || "publish acknowledgement unknown".to_owned(),
                                        |failure| failure.reason.clone(),
                                    ),
                            });
                        }
                        apply_report_to_fanout(
                            &mut fanout,
                            std::slice::from_ref(&endpoint),
                            &report,
                            self.wall_clock.now(),
                        );
                        if !report.met_required_acks() {
                            output.failures.push(PublishFailure {
                                oversized: None,
                                no_usable_relay: false,
                                message_id: report.message_id.clone(),
                                reason: "fanout endpoint did not acknowledge".into(),
                            });
                        }
                        if collects_pass_report {
                            pass_report.accepted.extend(report.accepted.iter().cloned());
                            pass_report.failed.extend(report.failed.iter().cloned());
                        }
                        output.reports.push(report);
                    }
                    Err(error) => {
                        if collects_pass_report {
                            pass_report
                                .failed
                                .extend(error.publish_endpoint_failures().iter().cloned());
                        }
                        pass_failed.push(PublishRelayFailure {
                            relay_url: endpoint.0.clone(),
                            reason: error.to_string(),
                        });
                        // See `finish_prepared_legacy_publish`.
                        if !publish_error_reached_no_relay(&error, std::slice::from_ref(&endpoint))
                        {
                            fanout.possible_exposure = true;
                        }
                        if let Some(target) = fanout
                            .targets
                            .iter_mut()
                            .find(|target| target.endpoint == endpoint)
                        {
                            target.attempt_count = target.attempt_count.saturating_add(1);
                            target.last_attempt_at = Some(self.wall_clock.now());
                            target.state = TransportFanoutAttemptState::AttemptedFailed;
                            target.failure_code = Some("adapter_error".into());
                        }
                        output.failures.push(PublishFailure {
                            oversized: None,
                            no_usable_relay: false,
                            message_id: message_id.clone(),
                            reason: "fanout adapter error".into(),
                        });
                    }
                }
            }
            self.put_pass_fanout(&fanout, &v5_welcome, Some(&pass_report), &remaining)?;
            let accepted_total = accepted_fanout_targets(&fanout);
            self.record_audit_event(
                audit_group_id.as_ref(),
                Some(publish_context),
                AuditEventKind::PublishOutcome {
                    msg_id: msg_id_hex,
                    artifact_kind,
                    target_kind,
                    relay_url: None,
                    accepted_relay_urls: pass_accepted,
                    failed_relays: pass_failed,
                    required_acks: fanout.required_acks as u64,
                    met_required_acks: accepted_total >= required_acks,
                    transport: Some(wire),
                    event_age_secs: publish_event_age_secs(
                        &fanout.exact_message,
                        self.wall_clock.now(),
                    ),
                },
            );
            // A Welcome is delivered by whichever attempt meets its policy,
            // this retry included, so it stops being owed now rather than at
            // the next open.
            self.settle_met_welcome(&fanout.exact_message, accepted_total, required_acks);
            // After the mark, so retention is what this pass left stored.
            self.record_v5_welcome_publish_finished(
                &v5_welcome,
                Some(&pass_report),
                &remaining,
                Some(accepted_total),
                required_acks,
            );
        }
        Ok(())
    }

    async fn publish_one(
        &mut self,
        message: TransportMessage,
        pending: Option<PendingStateRef>,
        application_message: Option<OutboundApplicationMessage>,
        output: &mut AccountDeviceEffects,
        queue: &mut VecDeque<PublishWork>,
        context: Option<AuditEventContext>,
    ) -> AccountResult<PublishStatus> {
        let continuation = match pending {
            Some(pending) => Some(PendingFanoutContinuation {
                pending,
                kind: self.session.pending_fanout_kind(pending)?,
                post_confirmation_welcomes: Vec::new(),
            }),
            None => None,
        };
        self.publish_one_with_post_confirmation_welcomes(
            message,
            continuation,
            application_message,
            output,
            queue,
            context,
        )
        .await
    }

    async fn publish_one_with_post_confirmation_welcomes(
        &mut self,
        message: TransportMessage,
        continuation: Option<PendingFanoutContinuation>,
        application_message: Option<OutboundApplicationMessage>,
        output: &mut AccountDeviceEffects,
        queue: &mut VecDeque<PublishWork>,
        context: Option<AuditEventContext>,
    ) -> AccountResult<PublishStatus> {
        let stage_started = application_message.as_ref().map(|_| Instant::now());
        let (pending, pending_kind, post_confirmation_welcomes) = match continuation {
            Some(continuation) => (
                Some(continuation.pending),
                Some(continuation.kind),
                continuation.post_confirmation_welcomes,
            ),
            None => (None, None, Vec::new()),
        };
        if matches!(message.envelope, TransportEnvelope::GroupMessage { .. }) || pending.is_some() {
            let target = match self.routing.publish_target(&message) {
                Ok(target) => target,
                Err(error) => {
                    output.failures.push(PublishFailure {
                        oversized: None,
                        no_usable_relay: false,
                        message_id: message.id,
                        reason: error.to_string(),
                    });
                    self.rollback_unstaged_pending(pending, output, queue)
                        .await?;
                    return Ok(PublishStatus::default());
                }
            };
            let required_acks = self.routing.required_acks(&target);
            let pending_group_id = match pending
                .map(|pending| self.session.pending_group_id(pending))
                .transpose()
            {
                Ok(group_id) => group_id,
                Err(error) => {
                    self.rollback_unstaged_pending(pending, output, queue)
                        .await?;
                    return Err(error.into());
                }
            };
            let pending_origin_message_id = if pending_kind == Some(FanoutPendingKind::CreateGroup)
            {
                None
            } else {
                match pending
                    .map(|pending| self.session.pending_origin_message_id(pending))
                    .transpose()
                {
                    Ok(message_id) => message_id,
                    Err(error) => {
                        self.rollback_unstaged_pending(pending, output, queue)
                            .await?;
                        return Err(error.into());
                    }
                }
            };
            let mut fanout = match OutboundFanout::stage_with_post_confirmation_welcomes(
                TransportPublishRequest {
                    account_id: self.session.self_id(),
                    message,
                    target,
                    required_acks,
                },
                pending,
                pending_group_id,
                self.wall_clock.now().0.saturating_mul(1_000),
                pending_origin_message_id,
                pending_kind,
                post_confirmation_welcomes,
            ) {
                Ok(fanout) => fanout,
                Err(error) => {
                    self.rollback_unstaged_pending(pending, output, queue)
                        .await?;
                    return Err(error.into());
                }
            };
            // A drained commit names its queued intent in the same record, so
            // a restart still retires the intent with the commit (mdk#2332).
            // So does a drained application message or proposal: its intent
            // retires when the event resolves, on whichever pass that is, and
            // no drain prepares the intent again meanwhile.
            let drained_intent = match pending {
                Some(pending) => self.session.drained_queued_intent_id(pending),
                None => self
                    .session
                    .regenerated_queued_intent_id(fanout.message_id()),
            };
            if let Some(intent_id) = drained_intent
                && let Err(error) = fanout.set_queued_intent(intent_id)
            {
                self.rollback_unstaged_pending(pending, output, queue)
                    .await?;
                return Err(error.into());
            }
            // A host's direct change is named on the same record, so a
            // rollback after this call returns is recorded (mdk#2332).
            if let Some(intent_kind) =
                pending.and_then(|pending| self.session.host_change_kind(pending))
                && let Err(error) = fanout.set_host_change(intent_kind)
            {
                self.rollback_unstaged_pending(pending, output, queue)
                    .await?;
                return Err(error.into());
            }
            if let Some(application_message) = application_message
                && let Err(error) = fanout.set_application_message(application_message)
            {
                self.rollback_unstaged_pending(pending, output, queue)
                    .await?;
                return Err(error.into());
            }
            if let Err(error) = self.session.put_outbound_fanout(&fanout) {
                self.rollback_unstaged_pending(pending, output, queue)
                    .await?;
                return Err(error.into());
            }
            if let Some(started) = stage_started {
                // Sum only local application-message preparation, before relay I/O.
                output.local_accept_duration =
                    Some(output.local_accept_duration.unwrap_or_default() + started.elapsed());
            }
            Box::pin(self.drive_outbound_fanout(
                fanout,
                output,
                queue,
                context,
                RollbackPass::Staging,
            ))
            .await
        } else {
            self.publish_legacy_one(message, output, context).await
        }
    }

    async fn rollback_unstaged_pending(
        &mut self,
        pending: Option<PendingStateRef>,
        output: &mut AccountDeviceEffects,
        queue: &mut VecDeque<PublishWork>,
    ) -> AccountResult<()> {
        if let Some(pending) = pending {
            let effects = self.session.publish_failed(pending).await?;
            output
                .pending
                .push(PendingResolution::RolledBack { pending });
            output.absorb_session_effects(effects, queue);
        }
        Ok(())
    }

    /// Drive one frozen fanout's pass. `pass` says whether it runs inside the
    /// call that staged it, which returns a rollback to its caller, or later,
    /// when a rollback of a host's change is recorded instead (mdk#2332).
    async fn drive_outbound_fanout(
        &mut self,
        mut fanout: OutboundFanout,
        output: &mut AccountDeviceEffects,
        queue: &mut VecDeque<PublishWork>,
        mut context: Option<AuditEventContext>,
        pass: RollbackPass,
    ) -> AccountResult<PublishStatus> {
        // Durable application identity connects first publication and exact
        // retries to the same logical send, including after process restart.
        if let Some(application) = fanout.application_message() {
            context.get_or_insert_with(Default::default).operation_id =
                Some(marmot_forensics::application_send_operation_id(
                    application.group_id.as_slice(),
                    &application.app_event_id,
                ));
        }
        // A confirmed commit stored with an exposed target a size refusal
        // already answered, by a release before this rule, ends that target
        // before any retry is chosen (mdk#2333). Confirmation does the same.
        if fanout.end_size_refused_targets() {
            self.session.put_outbound_fanout(&fanout)?;
        }
        let outcome = fanout.outcome();
        // A receipt persisted before cancellation can still be below quorum.
        // Finish that pass before releasing its Welcome continuation. Once a
        // pass settles, the existing exposure rule still prevents rollback of
        // a commit that reached peers even if its acknowledgement goal failed.
        if !outcome.mls_confirmation_required
            || outcome.accepted_targets >= fanout.request().required_acks.max(1)
            || outcome.fanout_complete
        {
            self.resolve_outbound_fanout_mls(&mut fanout, output, queue, context.clone(), pass)
                .await?;
        }
        let now_ms = self.wall_clock.now().0.saturating_mul(1_000);
        if self
            .read_back_pending_commit(&mut fanout, now_ms, context.clone())
            .await?
        {
            self.resolve_outbound_fanout_mls(&mut fanout, output, queue, context.clone(), pass)
                .await?;
        }
        let endpoints = fanout.request().target.endpoints().to_vec();
        let secondary_retry_yield = (fanout.outcome().accepted_targets
            >= fanout.request().required_acks.max(1)
            && !matches!(fanout.mls_state(), FanoutMlsState::Pending(_)))
        .then(|| {
            self.publication_progress
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .as_ref()
                .map(|progress| progress.secondary_retry_yield.clone())
        })
        .flatten();
        let yield_before_attempt = secondary_retry_yield
            .as_ref()
            .is_some_and(|signal| signal.clone().now_or_never().is_some());
        let due = fanout
            .outstanding_target_indexes()
            .into_iter()
            .filter(|&index| {
                !yield_before_attempt && frozen_fanout_target_retry_due(&fanout, index, now_ms)
            })
            .collect::<Vec<_>>();
        let attempted_any = !due.is_empty();
        if !due.is_empty() {
            // A commit too large for a relay is refused there before that
            // target is marked, so the refusal leaves no attempt that might
            // have left. A target already left `Attempting` by an interrupted
            // attempt is not exempt: the refusal ends it possibly exposed
            // (mdk#2332). Each target is checked on its own and sent once its
            // check passes, so a slow check, such as a connection probe to a
            // relay of unknown limit, holds back no other target's send.
            let commit = is_group_commit(&fanout);
            let mut pass_failed = Vec::new();
            if !commit {
                for &index in &due {
                    fanout.mark_attempt_started_at(index, now_ms)?;
                }
                self.session.put_outbound_fanout(&fanout)?;
            }
            // Every pass is audited, including secondary retries after the
            // first acknowledgement confirmed the pending MLS state (mdk#2255).
            self.record_audit_event(
                fanout.group_id(),
                context.clone(),
                AuditEventKind::PublishAttempt {
                    msg_id: hex::encode(fanout.message_id().as_slice()),
                    artifact_kind: None,
                    target_kind: "frozen_group_fanout".into(),
                    relay_url: None,
                    relay_urls: due
                        .iter()
                        .map(|&index| endpoints[index].0.clone())
                        .collect(),
                    required_acks: fanout.request().required_acks as u64,
                    transport: Some(publish_wire_metadata(&fanout.request().message)),
                },
            );

            // Publish every outstanding endpoint concurrently as
            // single-endpoint requests with `required_acks: 1`, the same
            // per-endpoint contract the old sequential loop used. A
            // multi-endpoint batch cannot be used here: the adapter treats an
            // unmet `required_acks` as a whole-call error that discards the
            // successful receipts, so an ordinary partial acceptance would
            // read as "every endpoint failed" and roll back a commit that
            // already reached a relay. Per-endpoint requests keep each
            // endpoint's outcome independent while removing the
            // one-awaited-ack-at-a-time serialization.
            let adapter = &self.adapter;
            let account_id = fanout.request().account_id.clone();
            let message = fanout.request().message.clone();
            let target = fanout.request().target.clone();
            let mut accepted = fanout.outcome().accepted_targets;
            let ack_goal = fanout.request().required_acks.max(1);
            // An already-met quorum alone must not cancel every retry. Only
            // explicit foreground pressure may interrupt this secondary tail.
            let finish_retries = accepted >= ack_goal;
            let mut pass_accepted = Vec::new();
            // A commit's target is first checked for size, then, once marked,
            // sent; any other target is sent at once, marked above.
            let step = |index: usize, checked: bool| {
                let message = message.clone();
                let target = publish_target_with_endpoints(&target, vec![endpoints[index].clone()]);
                let account_id = account_id.clone();
                async move {
                    if !checked {
                        let refusal = adapter
                            .commit_size_refusals(&message, &target)
                            .await
                            .into_iter()
                            .find(|failure| target.endpoints().contains(&failure.endpoint));
                        return FanoutStep::Checked { index, refusal };
                    }
                    let attempt = TransportPublishRequest {
                        account_id,
                        message,
                        target,
                        required_acks: 1,
                    };
                    let result = if commit {
                        adapter.publish_commit(attempt).await
                    } else {
                        adapter.publish(attempt).await
                    };
                    FanoutStep::Sent { index, result }
                }
            };
            let mut attempts = due
                .iter()
                .map(|&index| step(index, !commit))
                .collect::<FuturesUnordered<_>>();
            loop {
                // Drain immediately ready receipts after reaching quorum, but
                // do not hold confirmation or Welcomes behind a stalled relay.
                // Unfinished attempts stay durable and scheduler-visible for
                // exact-event retry, including after cancellation or restart.
                let next = if accepted >= ack_goal && !finish_retries {
                    attempts.next().now_or_never().flatten()
                } else if let Some(signal) = &secondary_retry_yield {
                    // Only relay futures are cancelled. No engine transaction or
                    // confirmation future is dropped, and ready receipts win ties.
                    let next = attempts.next().fuse();
                    let requested = signal.clone().fuse();
                    futures::pin_mut!(next, requested);
                    futures::select_biased! {
                        result = next => result,
                        () = requested => None,
                    }
                } else {
                    attempts.next().await
                };
                let (index, result) = match next {
                    None => break,
                    Some(FanoutStep::Checked {
                        index,
                        refusal: Some(failure),
                    }) => {
                        pass_failed.push(PublishRelayFailure {
                            relay_url: failure.endpoint.0.clone(),
                            reason: failure.reason.clone(),
                        });
                        fanout.record_refusal_before_attempt(index, failure, now_ms)?;
                        self.session.put_outbound_fanout(&fanout)?;
                        continue;
                    }
                    Some(FanoutStep::Checked {
                        index,
                        refusal: None,
                    }) => {
                        // Past quorum, a send started now would be cancelled
                        // before it could finish; the target stays unmarked
                        // for the next pass. The attempt is dated now, not when
                        // the pass began: a slow check must not move the
                        // commit's first attempt, and with it the read-back
                        // bound, earlier (mdk#2332).
                        if accepted < ack_goal || finish_retries {
                            fanout.mark_attempt_started_at(index, self.wall_clock.now_ms())?;
                            self.session.put_outbound_fanout(&fanout)?;
                            attempts.push(step(index, true));
                        }
                        continue;
                    }
                    Some(FanoutStep::Sent { index, result }) => (index, result),
                };
                let endpoint = endpoints[index].clone();
                let failure = match result {
                    Ok(report) => {
                        fanout.record_published_message_id(report.message_id)?;
                        if report
                            .accepted
                            .iter()
                            .any(|receipt| receipt.endpoint == endpoint)
                        {
                            accepted += usize::from(fanout.mark_target_accepted(index)?);
                            None
                        } else {
                            Some(
                                report
                                    .failed
                                    .iter()
                                    .find(|failure| failure.endpoint == endpoint)
                                    .cloned()
                                    .unwrap_or_else(|| ambiguous_endpoint_failure(endpoint)),
                            )
                        }
                    }
                    Err(error) => {
                        if let Some(message_id) = error.publish_message_id() {
                            fanout.record_published_message_id(message_id.clone())?;
                        }
                        Some(
                            error
                                .publish_endpoint_failures()
                                .iter()
                                .find(|failure| failure.endpoint == endpoint)
                                .cloned()
                                .unwrap_or_else(|| ambiguous_endpoint_failure(endpoint)),
                        )
                    }
                };
                match failure {
                    Some(failure) => {
                        pass_failed.push(PublishRelayFailure {
                            relay_url: failure.endpoint.0.clone(),
                            reason: failure.reason.clone(),
                        });
                        fanout.record_target_failure(index, failure)?;
                    }
                    None => pass_accepted.push(endpoints[index].0.clone()),
                }
                self.session
                    .put_observed_outbound_fanout(&mut fanout, self.wall_clock.now_ms())?;
            }
            if !attempts.is_empty() {
                // Cancelled publishes may have reached a relay. Back off their
                // exact-event retries instead of immediately blocking the worker again.
                for &index in &due {
                    if fanout.target_status(index)
                        == Some(cgka_traits::FanoutTargetStatus::Attempting)
                    {
                        let failure = ambiguous_endpoint_failure(endpoints[index].clone());
                        pass_failed.push(PublishRelayFailure {
                            relay_url: failure.endpoint.0.clone(),
                            reason: failure.reason.clone(),
                        });
                        fanout.record_target_failure(index, failure)?;
                    }
                }
                self.session.put_outbound_fanout(&fanout)?;
            }
            drop(attempts);
            let report = frozen_fanout_report(&fanout);
            // Record this artifact before confirmation releases any frozen
            // Welcome continuations, preserving transport chronology in the
            // returned effects while keeping the MLS edge atomic below.
            self.record_audit_event(
                fanout.group_id(),
                context.clone(),
                AuditEventKind::PublishOutcome {
                    msg_id: hex::encode(report.message_id.as_slice()),
                    artifact_kind: None,
                    target_kind: "frozen_group_fanout".into(),
                    relay_url: None,
                    accepted_relay_urls: pass_accepted,
                    failed_relays: pass_failed,
                    required_acks: report.required_acks as u64,
                    met_required_acks: report.met_required_acks(),
                    transport: Some(publish_wire_metadata(&fanout.request().message)),
                    event_age_secs: publish_event_age_secs(
                        &fanout.request().message,
                        self.wall_clock.now(),
                    ),
                },
            );
            output.reports.push(report);
            self.resolve_outbound_fanout_mls(&mut fanout, output, queue, context.clone(), pass)
                .await?;
        }
        boxed(|| {
            self.abandon_unsent_pending_commit(&mut fanout, output, queue, context.clone(), pass)
        })
        .await?;

        let report = frozen_fanout_report(&fanout);
        let fanout_outcome = fanout.outcome();
        let possible_ambiguous_exposure = fanout.possible_exposure();
        let status = PublishStatus {
            met_required_acks: report.met_required_acks(),
            accepted_by_any_endpoint: report.accepted_count() > 0,
            possible_ambiguous_exposure,
            retry_deferred: fanout_outcome.outstanding_targets > 0,
            terminal_failure: report.accepted_count() == 0
                && fanout_outcome.outstanding_targets == 0,
            withdrawn: false,
            awaits_commit: false,
        };
        let publish_failure_reason =
            if fanout_outcome.outstanding_targets > 0 && !status.met_required_acks {
                output.unresolved_publishes.push(UnresolvedPublish {
                    message_id: report.message_id.clone(),
                    reason: if possible_ambiguous_exposure {
                        UnresolvedPublishReason::AcknowledgementUnknown
                    } else {
                        UnresolvedPublishReason::RetryableUnavailable
                    },
                });
                None
            } else if !status.met_required_acks {
                let reason = "insufficient publish acknowledgements".to_owned();
                output.failures.push(PublishFailure {
                    oversized: OversizedEvent::of_fanout(&fanout),
                    no_usable_relay: has_no_usable_relay(&fanout),
                    message_id: report.message_id.clone(),
                    reason: reason.clone(),
                });
                Some(reason)
            } else {
                None
            };
        if matches!(
            fanout.request().message.envelope,
            TransportEnvelope::Welcome { .. }
        ) {
            if status.met_required_acks {
                self.mark_welcome_delivered_best_effort(fanout.message_id());
            } else if attempted_any
                && matches!(fanout.mls_state(), FanoutMlsState::Confirmed)
                && !self.welcome_past_deadline_now(fanout.message_id())
                && let Some(recipient) = welcome_recipient(&fanout.request().message)
            {
                output.welcome_failures.push(WelcomeDeliveryFailure {
                    size_class: OversizedEvent::of_fanout(&fanout).map(|cause| cause.size_class),
                    message_id: fanout.message_id().clone(),
                    recipient,
                    group_id: fanout.group_id().cloned(),
                    reason: publish_failure_reason
                        .clone()
                        .unwrap_or_else(|| "welcome publish failed".into()),
                });
            }
        }
        if status.accepted_by_any_endpoint {
            self.record_published_application_fanout(&fanout, output);
        } else if let Some(reason) = publish_failure_reason {
            record_failed_application_fanout(&fanout, reason, output);
        } else if let Some(application) = fanout.application_message()
            && status.retry_deferred
        {
            output
                .unresolved_app_messages
                .push(UnresolvedApplicationMessage {
                    group_id: application.group_id.clone(),
                    app_event_id: application.app_event_id.clone(),
                    message_id: report.message_id.clone(),
                    reason: if possible_ambiguous_exposure {
                        UnresolvedPublishReason::AcknowledgementUnknown
                    } else {
                        UnresolvedPublishReason::RetryableUnavailable
                    },
                });
        }
        if fanout_outcome.outstanding_targets > 0
            && let Some(group_id) = fanout.group_id()
            && !output.pending_convergence.contains(group_id)
        {
            // The exact event is already durable, but the app worker still
            // needs a scheduling edge that survives the current command. It
            // will query the stored fanout before arming and retry these same
            // bytes when the per-target delay expires.
            output.pending_convergence.push(group_id.clone());
        }
        output.fanout.push(fanout_outcome.clone());
        // A relay's refusal of a confirmed commit outlives its fanout: every
        // pass merges it into the commit's refusal record, and the delete
        // merges it first, in the same transaction (mdk#2333).
        let refusal = commit_refusal_of(&fanout);
        // The intent goes first: a crash before the fanout's retirement leaves
        // a resolved fanout a later pass retires, never an unnamed intent.
        let intent_retired = self.retire_drained_queued_intent(&fanout);
        if intent_retired
            && fanout_outcome.fanout_complete
            && !matches!(fanout.mls_state(), FanoutMlsState::Pending(_))
            && !(fanout_outcome.accepted_targets > 0 && fanout.application_message().is_some())
        {
            self.session
                .retire_outbound_fanout(&fanout, refusal.as_ref())?;
        } else if let Some(refusal) = refusal {
            self.session.merge_commit_refusal(&refusal)?;
        }
        Ok(status)
    }

    /// Read a pending commit back from each relay that may hold it and whose
    /// retry is due, once the commit's first send attempt is
    /// [`PENDING_COMMIT_READ_BACK_AFTER_MS`] old (mdk#2332). A relay that
    /// returns the exact event holds it, so it acknowledges the commit by
    /// read-back. Any other answer changes nothing: the relay is resent to as
    /// before, and nothing rolls back. Returns whether the acknowledgements
    /// met the commit's goal, for the caller to confirm it.
    ///
    /// The first read while no relay has acknowledged the commit, the state
    /// [`PendingCommitState::Stuck`] reports, audits that it went stuck
    /// (mdk#3460). That is recorded on the stored fanout before the read is
    /// sent, so a restart does not audit it again. Below a goal of more than
    /// one acknowledgement, a commit some relay acknowledged is not stuck.
    async fn read_back_pending_commit(
        &mut self,
        fanout: &mut OutboundFanout,
        now_ms: u64,
        context: Option<AuditEventContext>,
    ) -> AccountResult<bool> {
        if !is_group_commit(fanout)
            || !matches!(fanout.mls_state(), FanoutMlsState::Pending(_))
            || fanout.first_attempt_at_ms().is_none_or(|first| {
                now_ms.saturating_sub(first) < PENDING_COMMIT_READ_BACK_AFTER_MS
            })
        {
            return Ok(false);
        }
        let read = fanout
            .outstanding_target_indexes()
            .into_iter()
            .filter(|&index| {
                fanout.target_may_hold_event(index)
                    && frozen_fanout_target_retry_due(fanout, index, now_ms)
            })
            .collect::<Vec<_>>();
        if read.is_empty() {
            return Ok(false);
        }
        if fanout.outcome().accepted_targets == 0 && fanout.record_stuck(now_ms) {
            self.session.put_outbound_fanout(fanout)?;
            self.record_pending_commit_change(fanout, context, PendingCommitChange::Stuck, now_ms);
        }
        let endpoints = fanout.request().target.endpoints();
        let read_endpoints = read
            .iter()
            .map(|&index| endpoints[index].clone())
            .collect::<Vec<_>>();
        let answers = self
            .adapter
            .read_back(
                &fanout.request().account_id,
                &fanout.request().message,
                &read_endpoints,
            )
            .await;
        let mut found = 0_usize;
        for (&index, answer) in read.iter().zip(answers) {
            if answer == TransportReadBack::Found
                && fanout.acknowledge_target(index, FanoutAcknowledgement::ReadBack)?
            {
                found += 1;
            }
        }
        tracing::debug!(
            target: TRACE_TARGET,
            method = "read_back_pending_commit",
            read = read.len(),
            found,
            "read a pending commit back"
        );
        if found == 0 {
            return Ok(false);
        }
        // The acceptance is observed when the read answered.
        self.session
            .put_observed_outbound_fanout(fanout, self.wall_clock.now_ms())?;
        Ok(fanout.outcome().accepted_targets >= fanout.request().required_acks.max(1))
    }

    /// Give up a pending commit that reached no relay (mdk#2332). Past the
    /// bound, when no target accepted the commit, none may hold it
    /// ([`OutboundFanout::possible_exposure`]) and some are still owed, every
    /// relay refused it, was sent nothing, or was never reached. If one of
    /// them has answered since the bound, the device is online and the relays
    /// it never reached are down: those targets end `Abandoned` and the commit
    /// rolls back, retiring a queued intent as `not_delivered`. An answer is a
    /// definitive refusal of an attempt started since the bound, or, read at
    /// most hourly, any answer to a read of the commit from its relays. A read
    /// only shows that the device is online; whether the commit may roll back
    /// is the exposure record's alone (mdk#1577). A read that returns the
    /// commit confirms it. Offline, nothing changes and the commit waits.
    async fn abandon_unsent_pending_commit(
        &mut self,
        fanout: &mut OutboundFanout,
        output: &mut AccountDeviceEffects,
        queue: &mut VecDeque<PublishWork>,
        context: Option<AuditEventContext>,
        pass: RollbackPass,
    ) -> AccountResult<()> {
        let now_ms = self.wall_clock.now_ms();
        let outcome = fanout.outcome();
        let Some(bound_at) = fanout
            .first_attempt_at_ms()
            .map(|first| first.saturating_add(PENDING_COMMIT_READ_BACK_AFTER_MS))
        else {
            return Ok(());
        };
        if !is_group_commit(fanout)
            || !matches!(fanout.mls_state(), FanoutMlsState::Pending(_))
            || now_ms < bound_at
            || outcome.accepted_targets != 0
            || outcome.outstanding_targets == 0
            || fanout.possible_exposure()
        {
            return Ok(());
        }
        let targets = fanout.request().target.endpoints().len();
        let refused_since_bound = (0..targets).any(|index| {
            fanout.target_status(index) == Some(cgka_traits::FanoutTargetStatus::Failed)
                && fanout.target_failure(index).is_some_and(|failure| {
                    failure.kind == TransportEndpointFailureKind::TerminalRejected
                })
                && fanout
                    .target_last_attempt_at_ms(index)
                    .is_some_and(|attempted| attempted >= bound_at)
        });
        let online = if refused_since_bound {
            true
        } else if fanout.reachability_read_at_ms().is_some_and(|read| {
            now_ms.saturating_sub(read) < PENDING_COMMIT_REACHABILITY_READ_INTERVAL_MS
        }) {
            return Ok(());
        } else {
            // Record the read before it is sent, so a restart while it is in
            // flight does not read again within the hour.
            fanout.record_reachability_read(now_ms);
            self.session.put_outbound_fanout(fanout)?;
            let answers = self
                .adapter
                .read_back(
                    &fanout.request().account_id,
                    &fanout.request().message,
                    fanout.request().target.endpoints(),
                )
                .await;
            let mut found = 0_usize;
            let mut answered = 0_usize;
            for (index, answer) in answers.into_iter().enumerate().take(targets) {
                match answer {
                    TransportReadBack::Found => {
                        answered += 1;
                        found += usize::from(
                            fanout.acknowledge_target(index, FanoutAcknowledgement::ReadBack)?,
                        );
                    }
                    TransportReadBack::NotFound => answered += 1,
                    TransportReadBack::NoAnswer => {}
                }
            }
            tracing::debug!(
                target: TRACE_TARGET,
                method = "abandon_unsent_pending_commit",
                read = targets,
                answered,
                found,
                "read an unsent pending commit back to learn whether the device is online"
            );
            if found > 0 {
                // The acceptance is observed when the read answered.
                self.session
                    .put_observed_outbound_fanout(fanout, self.wall_clock.now_ms())?;
                return self
                    .resolve_outbound_fanout_mls(fanout, output, queue, context, pass)
                    .await;
            }
            answered > 0
        };
        if !online {
            return Ok(());
        }
        let Some(pending) = fanout.pending_ref() else {
            return Ok(());
        };
        let mut abandoned = fanout.clone();
        let count = abandoned.abandon_unsent_targets()?;
        let effects =
            give_up_unsent_commit(&mut self.session, pending, &mut abandoned, pass).await?;
        *fanout = abandoned;
        self.record_pending_commit_change(fanout, context, PendingCommitChange::GivenUp, now_ms);
        tracing::info!(
            target: TRACE_TARGET,
            method = "abandon_unsent_pending_commit",
            abandoned = count,
            targets,
            "gave up a pending commit that reached no relay"
        );
        output
            .pending
            .push(PendingResolution::RolledBack { pending });
        output.absorb_session_effects(effects, queue);
        Ok(())
    }

    async fn resolve_outbound_fanout_mls(
        &mut self,
        fanout: &mut OutboundFanout,
        output: &mut AccountDeviceEffects,
        queue: &mut VecDeque<PublishWork>,
        context: Option<AuditEventContext>,
        pass: RollbackPass,
    ) -> AccountResult<()> {
        let outcome = fanout.outcome();
        if outcome.mls_confirmation_required {
            let pending = fanout
                .pending_ref()
                .expect("confirmation-required fanout retains pending ref");
            let effects = self
                .confirm_published_fanout_retrying(pending, fanout)
                .await?;
            // A commit no relay's `OK` confirmed is audited once, as it
            // confirms, however a restart split its acknowledgement from
            // this confirmation (mdk#3460).
            if let Some(change) = confirmed_without_ok(fanout) {
                self.record_pending_commit_change(
                    fanout,
                    context.clone(),
                    change,
                    self.wall_clock.now_ms(),
                );
            }
            output
                .pending
                .push(PendingResolution::Confirmed { pending });
            output.absorb_session_effects(effects, queue);
        } else if outcome.fanout_complete
            && outcome.accepted_targets == 0
            && !fanout.possible_exposure()
            && let Some(pending) = fanout.pending_ref()
        {
            let oversized = OversizedEvent::of_fanout(fanout);
            // The commit's staged Welcomes, which a host's invite does not
            // carry on the fanout.
            let unretired =
                oversized.map(|_| self.unretired_welcomes(self.staged_welcomes_of_fanout(fanout)));
            let effects = roll_back_failed_fanout(&mut self.session, pending, fanout, pass).await;
            // Recorded even when the rollback fails after it committed.
            if let (Some(oversized), Some(unretired)) = (oversized, unretired) {
                let retired = self.retired_welcomes(unretired);
                self.record_v5_welcomes_refused(&retired, &InviteRefusal::from(oversized));
            }
            let effects = effects?;
            output
                .pending
                .push(PendingResolution::RolledBack { pending });
            output.absorb_session_effects(effects, queue);
        }
        if matches!(fanout.mls_state(), FanoutMlsState::Confirmed)
            && !fanout.pending_post_confirmation_welcomes().is_empty()
        {
            let welcomes = fanout.pending_post_confirmation_welcomes().to_vec();
            let group_id = fanout.group_id().cloned();
            self.publish_welcome_fanout(welcomes, group_id, output, context)
                .await?;
            if fanout.mark_post_confirmation_welcomes_released() {
                self.session.put_outbound_fanout(fanout)?;
            }
        }
        Ok(())
    }

    async fn publish_legacy_one(
        &self,
        message: TransportMessage,
        output: &mut AccountDeviceEffects,
        context: Option<AuditEventContext>,
    ) -> AccountResult<PublishStatus> {
        self.publish_one_with_retry_policy(message, output, context, false)
            .await
    }

    async fn publish_one_with_retry_policy(
        &self,
        message: TransportMessage,
        output: &mut AccountDeviceEffects,
        context: Option<AuditEventContext>,
        retry_immediately: bool,
    ) -> AccountResult<PublishStatus> {
        match self.prepare_legacy_publish(message, output, context, retry_immediately)? {
            PreparedLegacyPublish::Complete(status) => Ok(status),
            PreparedLegacyPublish::Network(mut attempt) => {
                // Preparation's writes may have waited past the deadline.
                if attempt
                    .deliver_until
                    .is_some_and(|deliver_until| self.wall_clock.now() >= deliver_until)
                {
                    return Ok(PublishStatus {
                        withdrawn: true,
                        ..PublishStatus::default()
                    });
                }
                if let Some(pass) = attempt.v5_welcome.as_mut() {
                    pass.start(&self.audit);
                }
                let result = self.adapter.publish(attempt.request.clone()).await;
                self.finish_prepared_legacy_publish(*attempt, result, output)
                    .await
            }
        }
    }

    fn prepare_legacy_publish(
        &self,
        message: TransportMessage,
        output: &mut AccountDeviceEffects,
        context: Option<AuditEventContext>,
        retry_immediately: bool,
    ) -> AccountResult<PreparedLegacyPublish> {
        let message_id = message.id.clone();
        if self
            .session
            .detached_welcome_publishes
            .contains(&message_id)
        {
            return Ok(PreparedLegacyPublish::Complete(PublishStatus {
                retry_deferred: true,
                ..PublishStatus::default()
            }));
        }
        // Every Welcome publish passes here, whichever path still holds the
        // Welcome, or through maintenance's retry of its fanout.
        match self.welcome_hold(&message_id, &message.envelope)? {
            Some(WelcomeHold::Withdrawn | WelcomeHold::Expired) => {
                return Ok(PreparedLegacyPublish::Complete(PublishStatus {
                    withdrawn: true,
                    ..PublishStatus::default()
                }));
            }
            Some(WelcomeHold::AwaitsCommit) => {
                return Ok(PreparedLegacyPublish::Complete(PublishStatus {
                    awaits_commit: true,
                    ..PublishStatus::default()
                }));
            }
            None => {}
        }
        let deliver_until = match &message.envelope {
            TransportEnvelope::Welcome { .. } => {
                self.session.sent_welcome_deliver_until(&message_id)?
            }
            TransportEnvelope::GroupMessage { .. } => None,
        };
        let msg_id_hex = hex::encode(message_id.as_slice());
        // Capture the outbound wire envelope before `message` is moved into the
        // publish request. The post-wrap relay event id / ephemeral pubkey are
        // produced inside the transport adapter and are not available here, so
        // only the transport source and transport group id are recorded.
        let wire = publish_wire_metadata(&message);
        // A welcome is unambiguously a welcome; a group message could be a
        // commit/proposal/app message, which is not distinguishable from the
        // transport envelope alone, so it is left unattributed here.
        let artifact_kind = match &message.envelope {
            TransportEnvelope::Welcome { .. } => Some(MessageArtifactKind::Welcome),
            TransportEnvelope::GroupMessage { .. } => None,
        };
        let mut publish_context = context.unwrap_or_default();
        publish_context.operation_id = Some(format!("publish-{msg_id_hex}"));
        let welcome_facts = self.welcome_audit_facts(&message);
        let existing_fanout = self.session.transport_fanout(&message_id)?;
        let route_source = if existing_fanout.is_some() {
            audit_v5::RouteSource::RetainedTarget
        } else {
            audit_v5::RouteSource::ResolvedInbox
        };
        if existing_fanout
            .as_ref()
            .is_some_and(|fanout| fanout.exact_message != message)
        {
            return Err(AccountError::Transport(TransportAdapterError::Publish(
                "persisted exact transport event does not match retry input".into(),
            )));
        }
        let target = if let Some(fanout) = existing_fanout.as_ref() {
            fanout.target.clone()
        } else {
            let routed = self.routing.publish_target(&message);
            self.note_welcome_route(&message, routed.as_ref().map(|_| ()));
            match routed {
                Ok(target) => target,
                Err(e) => {
                    self.record_v5_welcome_not_started(
                        welcome_facts.clone(),
                        welcome_routes::route_not_started_reason(&e),
                    );
                    if matches!(message.envelope, TransportEnvelope::Welcome { .. }) {
                        self.record_welcome_route_failure(&message.id);
                    }
                    self.record_audit_event(
                        welcome_facts.as_ref().map(|facts| &facts.group_id),
                        Some(publish_context),
                        AuditEventKind::PublishFailure {
                            msg_id: msg_id_hex,
                            artifact_kind,
                            stage: "routing".into(),
                            target_kind: "unknown".into(),
                            relay_url: None,
                            relay_urls: Vec::new(),
                            required_acks: None,
                            reason: e.to_string(),
                            detail: None,
                            transport: Some(wire),
                        },
                    );
                    output.failures.push(PublishFailure {
                        oversized: None,
                        no_usable_relay: false,
                        message_id,
                        reason: e.to_string(),
                    });
                    return Ok(PreparedLegacyPublish::Complete(PublishStatus::default()));
                }
            }
        };
        let required_acks = existing_fanout
            .as_ref()
            .map(|fanout| fanout.required_acks)
            .unwrap_or_else(|| self.routing.required_acks(&target));
        let target_kind = publish_target_kind(&target).to_string();
        let relay_urls = publish_target_relay_urls(&target);
        let target_group_id = publish_target_group_id(&target);
        let audit_group_id = target_group_id
            .clone()
            .or_else(|| welcome_facts.as_ref().map(|facts| facts.group_id.clone()));
        let fanout = if let Some(fanout) = existing_fanout {
            fanout
        } else {
            DurableTransportFanout {
                id: message_id.clone(),
                group_id: target_group_id.clone(),
                evolution_id: self
                    .session
                    .group_evolutions()?
                    .into_iter()
                    .find(|evolution| evolution.signed_message_id.as_ref() == Some(&message_id))
                    .map(|evolution| evolution.id),
                exact_message: message.clone(),
                target: target.clone(),
                targets: target
                    .endpoints()
                    .iter()
                    .cloned()
                    .map(|endpoint| TransportFanoutTarget {
                        endpoint,
                        state: TransportFanoutAttemptState::Unattempted,
                        attempt_count: 0,
                        last_attempt_at: None,
                        failure_code: None,
                    })
                    .collect(),
                required_acks,
                evolution_confirmed: false,
                possible_exposure: false,
                created_at: self.wall_clock.now(),
                bounded_until: Some(Timestamp(
                    self.wall_clock
                        .now()
                        .0
                        .saturating_add(TRANSPORT_FANOUT_RETENTION_SECS),
                )),
            }
        };
        // Exact signed bytes and the endpoint snapshot are durable before the
        // first network call.
        self.session.put_transport_fanout(&fanout)?;
        let defers_remaining_fanout_until_confirmation = fanout.evolution_id.is_some();
        if let Some(evolution_id) = fanout.evolution_id.as_ref()
            && let Some(mut evolution) = self
                .session
                .group_evolutions()?
                .into_iter()
                .find(|evolution| &evolution.id == evolution_id)
            && evolution.phase == GroupEvolutionPhase::Prepared
        {
            evolution.phase = GroupEvolutionPhase::Attempting;
            self.session.put_group_evolution(&evolution)?;
        }

        let retry_endpoints = fanout
            .targets
            .iter()
            .filter(|target| {
                (retry_immediately && target.state == TransportFanoutAttemptState::AttemptedFailed)
                    || transport_fanout_target_retry_due(target, self.wall_clock.now())
            })
            .map(|target| target.endpoint.clone())
            .collect::<Vec<_>>();
        let accepted_before = fanout
            .targets
            .iter()
            .filter(|target| target.state == TransportFanoutAttemptState::Accepted)
            .count();
        if retry_endpoints.is_empty() {
            let retry_deferred = accepted_before < required_acks.max(1)
                && fanout.targets.iter().any(|target| {
                    matches!(
                        target.state,
                        TransportFanoutAttemptState::Unattempted
                            | TransportFanoutAttemptState::AttemptedFailed
                    )
                });
            self.settle_met_welcome(&message, accepted_before, required_acks);
            return Ok(PreparedLegacyPublish::Complete(PublishStatus {
                met_required_acks: accepted_before >= required_acks.max(1),
                accepted_by_any_endpoint: accepted_before > 0,
                possible_ambiguous_exposure: fanout.possible_exposure,
                retry_deferred,
                terminal_failure: false,
                withdrawn: false,
                awaits_commit: false,
            }));
        }
        // Recorded only for a pass that asks a relay: one whose every relay is
        // still inside its backoff asks none.
        self.record_audit_event(
            audit_group_id.as_ref(),
            Some(publish_context.clone()),
            AuditEventKind::PublishAttempt {
                msg_id: msg_id_hex.clone(),
                artifact_kind,
                target_kind: target_kind.clone(),
                relay_url: None,
                relay_urls: relay_urls.clone(),
                required_acks: required_acks as u64,
                transport: Some(wire.clone()),
            },
        );
        let attempt_target = publish_target_with_endpoints(&target, retry_endpoints.clone());
        let attempt_required_acks = required_acks
            .max(1)
            .saturating_sub(accepted_before)
            .max(1)
            .min(retry_endpoints.len());

        let v5_welcome = self.v5_welcome_pass(
            welcome_facts,
            &retry_endpoints,
            required_acks,
            accepted_before,
            route_source,
        );

        Ok(PreparedLegacyPublish::Network(Box::new(
            PreparedLegacyPublishAttempt {
                message_id,
                msg_id_hex,
                v5_welcome,
                wire,
                artifact_kind,
                publish_context,
                fanout,
                retry_endpoints,
                accepted_before,
                required_acks,
                target_kind,
                relay_urls,
                audit_group_id,
                defers_remaining_fanout_until_confirmation,
                deliver_until,
                request: TransportPublishRequest {
                    account_id: self.session.self_id(),
                    message,
                    target: attempt_target,
                    required_acks: attempt_required_acks,
                },
            },
        )))
    }

    /// Save a publish pass's fanout bookkeeping, and a Welcome's delivery
    /// counts in the same transaction (mdk#1706). When that fails after the
    /// relays answered, the pass's finished row still records their answers,
    /// with no stored total, before the error returns.
    fn put_pass_fanout(
        &self,
        fanout: &DurableTransportFanout,
        v5_welcome: &Option<V5WelcomePass>,
        report: Option<&TransportPublishReport>,
        attempted: &[TransportEndpoint],
    ) -> AccountResult<()> {
        self.put_pass_fanout_counting(
            fanout,
            v5_welcome,
            report,
            attempted,
            welcome_outcomes::PassCounts {
                attempted,
                report,
                counts_attempt: true,
            },
        )
    }

    /// [`Self::put_pass_fanout`], counting the pass on the delivery record
    /// as `counts` says.
    fn put_pass_fanout_counting(
        &self,
        fanout: &DurableTransportFanout,
        v5_welcome: &Option<V5WelcomePass>,
        report: Option<&TransportPublishReport>,
        attempted: &[TransportEndpoint],
        counts: welcome_outcomes::PassCounts<'_>,
    ) -> AccountResult<()> {
        // Test-only fault injection (`arm_finish_stage_failure`): the write
        // fails with transient contention.
        // The counts and the retry record are one write, all or nothing: a
        // delivery record that cannot be read fails the save like any storage
        // error in it, never leaving the retry record saved without its
        // counts. As for any failed save, the pass is retried and a relay
        // that already stored the Welcome answers duplicate.
        let written: AccountResult<()> =
            if self.finish_stage_failure.as_ref() == Some(&fanout.exact_message.id) {
                Err(
                    SessionError::from(StorageError::Busy("injected finish-stage failure".into()))
                        .into(),
                )
            } else {
                let now = self.wall_clock.now();
                self.welcome_delivery_group(fanout)
                    .and_then(|group| {
                        let delivery = group.map(|group| {
                            (
                                group,
                                &fanout.exact_message.id,
                                |record: &mut cgka_traits::maintenance::WelcomeDeliveryRecord| {
                                    welcome_outcomes::record_pass(record, fanout, &counts, now)
                                },
                            )
                        });
                        Ok(self
                            .session
                            .put_transport_fanout_with_welcome_delivery(fanout, delivery)?)
                    })
                    .map(|saved| {
                        if let Some(saved) = &saved {
                            self.queue_welcome_delivery_change(saved);
                        }
                    })
            };
        if written.is_err() {
            self.record_v5_welcome_publish_finished(
                v5_welcome,
                report,
                attempted,
                None,
                fanout.required_acks,
            );
        }
        written
    }

    async fn finish_prepared_legacy_publish(
        &self,
        attempt: PreparedLegacyPublishAttempt,
        result: Result<TransportPublishReport, TransportAdapterError>,
        output: &mut AccountDeviceEffects,
    ) -> AccountResult<PublishStatus> {
        let PreparedLegacyPublishAttempt {
            message_id,
            msg_id_hex,
            v5_welcome,
            wire,
            artifact_kind,
            publish_context,
            mut fanout,
            retry_endpoints,
            accepted_before,
            required_acks,
            target_kind,
            relay_urls,
            audit_group_id,
            defers_remaining_fanout_until_confirmation,
            deliver_until: _,
            request: _,
        } = attempt;
        // Diagnostic only: no exposure, retry or rollback decision below reads
        // it. Legacy publication's coarse durable prior-attempt records cannot
        // reconstruct a definitive earlier refusal. A crash before finish
        // bookkeeping or expired records can hide an earlier exposure: this
        // diagnosis explains the observed attempt, not delivery.
        let oversized = OversizedEvent::of_first_legacy_welcome_attempt(&fanout, &result);
        let report = match result {
            Ok(report) => report,
            Err(error) => {
                // An error may follow a send, so it is a possible exposure
                // unless it proves, for every relay this attempt named, that
                // nothing was sent, as the host-safety rule's refusal of a
                // relay does (mdk#3305). That is how a report's per-relay
                // failures are read, which never set the flag: whether the
                // adapter answers with a report or an error depends on how
                // many of the request's relays it could send to, not on what
                // reached one. The proof covers this attempt only. An earlier
                // attempt's recorded exposure stays, since nothing clears the
                // flag, but one a crash hid before its bookkeeping stays
                // hidden. So the status below still owes the targets this
                // error left unaccepted, and a pre-mdk#2255 evolution commit
                // is never rolled back on an error, as before.
                if !publish_error_reached_no_relay(&error, &retry_endpoints) {
                    fanout.possible_exposure = true;
                }
                // Keep each endpoint's typed cause when the adapter reported
                // one (mdk#2264); only whole-call errors stay coarse.
                let endpoint_report = (!error.publish_endpoint_failures().is_empty()).then(|| {
                    TransportPublishReport {
                        message_id: error
                            .publish_message_id()
                            .cloned()
                            .unwrap_or_else(|| message_id.clone()),
                        accepted: Vec::new(),
                        failed: error.publish_endpoint_failures().to_vec(),
                        required_acks,
                    }
                });
                if let Some(report) = &endpoint_report {
                    apply_report_to_fanout(
                        &mut fanout,
                        &retry_endpoints,
                        report,
                        self.wall_clock.now(),
                    );
                } else {
                    for target in &mut fanout.targets {
                        if retry_endpoints.contains(&target.endpoint)
                            && target.state != TransportFanoutAttemptState::Accepted
                        {
                            target.attempt_count = target.attempt_count.saturating_add(1);
                            target.last_attempt_at = Some(self.wall_clock.now());
                            target.state = TransportFanoutAttemptState::AttemptedFailed;
                            target.failure_code = Some("adapter_error".into());
                        }
                    }
                }
                self.put_pass_fanout(
                    &fanout,
                    &v5_welcome,
                    endpoint_report.as_ref(),
                    &retry_endpoints,
                )?;
                // An earlier acceptance may already meet the policy, stored
                // before a stop interrupted its mark.
                self.settle_met_welcome(&fanout.exact_message, accepted_before, required_acks);
                self.record_v5_welcome_publish_finished(
                    &v5_welcome,
                    endpoint_report.as_ref(),
                    &retry_endpoints,
                    Some(accepted_before),
                    required_acks,
                );
                if let Some(report) = &endpoint_report {
                    self.record_audit_event(
                        audit_group_id.as_ref(),
                        Some(publish_context.clone()),
                        AuditEventKind::PublishOutcome {
                            msg_id: msg_id_hex.clone(),
                            artifact_kind,
                            target_kind: target_kind.clone(),
                            relay_url: None,
                            accepted_relay_urls: Vec::new(),
                            failed_relays: report
                                .failed
                                .iter()
                                .map(|failure| PublishRelayFailure {
                                    relay_url: failure.endpoint.0.clone(),
                                    reason: failure.reason.clone(),
                                })
                                .collect(),
                            required_acks: required_acks as u64,
                            met_required_acks: accepted_before >= required_acks.max(1),
                            transport: Some(wire.clone()),
                            event_age_secs: publish_event_age_secs(
                                &fanout.exact_message,
                                self.wall_clock.now(),
                            ),
                        },
                    );
                }
                self.record_audit_event(
                    audit_group_id.as_ref(),
                    Some(publish_context),
                    AuditEventKind::PublishFailure {
                        msg_id: msg_id_hex,
                        artifact_kind,
                        stage: "adapter".into(),
                        target_kind,
                        relay_url: None,
                        relay_urls,
                        required_acks: Some(required_acks as u64),
                        // `Display` always reads "publish failed: ..." and
                        // never passes the audit category allowlist.
                        reason: error.privacy_safe_kind().into(),
                        detail: None,
                        transport: Some(wire),
                    },
                );
                output.failures.push(PublishFailure {
                    oversized,
                    no_usable_relay: false,
                    message_id,
                    reason: error.to_string(),
                });
                let retry_deferred = accepted_before < required_acks.max(1)
                    && fanout.targets.iter().any(|target| {
                        matches!(
                            target.state,
                            TransportFanoutAttemptState::Unattempted
                                | TransportFanoutAttemptState::AttemptedFailed
                        )
                    });
                return Ok(PublishStatus {
                    met_required_acks: accepted_before >= required_acks.max(1),
                    accepted_by_any_endpoint: accepted_before > 0,
                    possible_ambiguous_exposure: fanout.possible_exposure,
                    retry_deferred,
                    terminal_failure: false,
                    withdrawn: false,
                    awaits_commit: false,
                });
            }
        };
        apply_report_to_fanout(
            &mut fanout,
            &retry_endpoints,
            &report,
            self.wall_clock.now(),
        );
        self.put_pass_fanout(&fanout, &v5_welcome, Some(&report), &retry_endpoints)?;
        let accepted_total = fanout
            .targets
            .iter()
            .filter(|target| target.state == TransportFanoutAttemptState::Accepted)
            .count();
        let published = accepted_total >= required_acks.max(1);
        // Whichever attempt meets a Welcome's policy marks it delivered; the
        // finished row then reports what the mark left stored.
        self.settle_met_welcome(&fanout.exact_message, accepted_total, required_acks);
        self.record_v5_welcome_publish_finished(
            &v5_welcome,
            Some(&report),
            &retry_endpoints,
            Some(accepted_total),
            required_acks,
        );
        let accepted_by_any_endpoint = accepted_total > 0;
        self.record_audit_event(
            audit_group_id.as_ref(),
            Some(publish_context.clone()),
            AuditEventKind::PublishOutcome {
                msg_id: hex::encode(report.message_id.as_slice()),
                artifact_kind,
                target_kind: target_kind.clone(),
                relay_url: None,
                accepted_relay_urls: report
                    .accepted
                    .iter()
                    .map(|receipt| receipt.endpoint.0.clone())
                    .collect(),
                failed_relays: report
                    .failed
                    .iter()
                    .map(|failure| PublishRelayFailure {
                        relay_url: failure.endpoint.0.clone(),
                        reason: failure.reason.clone(),
                    })
                    .collect(),
                required_acks: report.required_acks as u64,
                met_required_acks: published,
                transport: Some(wire.clone()),
                event_age_secs: publish_event_age_secs(
                    &fanout.exact_message,
                    self.wall_clock.now(),
                ),
            },
        );
        if !published {
            self.record_audit_event(
                audit_group_id.as_ref(),
                Some(publish_context),
                AuditEventKind::PublishFailure {
                    msg_id: hex::encode(report.message_id.as_slice()),
                    artifact_kind,
                    stage: "required_acks".into(),
                    target_kind,
                    relay_url: None,
                    relay_urls,
                    required_acks: Some(report.required_acks as u64),
                    reason: "insufficient publish acknowledgements".into(),
                    detail: None,
                    transport: Some(wire),
                },
            );
            output.failures.push(PublishFailure {
                oversized,
                no_usable_relay: false,
                message_id: report.message_id.clone(),
                reason: "insufficient publish acknowledgements".into(),
            });
        }
        output.reports.push(report);
        if !defers_remaining_fanout_until_confirmation {
            self.finish_transport_fanout(&message_id, output).await?;
        }
        Ok(PublishStatus {
            met_required_acks: published,
            accepted_by_any_endpoint,
            possible_ambiguous_exposure: fanout.possible_exposure,
            retry_deferred: false,
            terminal_failure: !published && !accepted_by_any_endpoint && !fanout.possible_exposure,
            withdrawn: false,
            awaits_commit: false,
        })
    }
}

/// Must this maintenance tick leave the group behind `result` alone?
///
/// Every group-scoped engine read the sweep makes passes `ensure_group_live`,
/// which fails closed on a seeded-but-unhydrated copy (`GroupNotHydrated`) and
/// on a quarantined one (`UnknownGroup`). Both clear on someone else's
/// schedule — the embedder's hydration pipeline, the per-group repair surface —
/// so the work stays owed, `Ok(None)` means skip it this tick, and one such
/// group never aborts the sweep for every group behind it. Every other error
/// still propagates.
///
/// The `UnknownGroup` arm doubles as defense in depth for the epoch-manager
/// invariant that a quarantined group holds no epoch entry: if a failed
/// hydration ever left one behind, `live_group_ids` would list the group and
/// the sweep would meet it here.
fn skips_group_this_tick<T>(result: Result<T, SessionError>) -> AccountResult<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error)
            if matches!(
                error.as_engine_error(),
                EngineError::GroupNotHydrated(_) | EngineError::UnknownGroup(_)
            ) =>
        {
            tracing::debug!(
                target: TRACE_TARGET,
                method = "run_due_maintenance",
                error_kind = "group_not_live",
                "group maintenance remains retryable"
            );
            Ok(None)
        }
        Err(error) => Err(error.into()),
    }
}

fn publish_target_with_endpoints(
    target: &TransportPublishTarget,
    endpoints: Vec<TransportEndpoint>,
) -> TransportPublishTarget {
    match target {
        TransportPublishTarget::Group {
            group_id,
            transport_group_id,
            ..
        } => TransportPublishTarget::Group {
            group_id: group_id.clone(),
            transport_group_id: transport_group_id.clone(),
            endpoints,
        },
        TransportPublishTarget::Inbox { recipient, .. } => TransportPublishTarget::Inbox {
            recipient: recipient.clone(),
            endpoints,
        },
    }
}

/// One step of a frozen fanout pass for one target (mdk#2332): a commit's
/// size check, then the send.
enum FanoutStep {
    /// The commit's size check, with the target's refusal if it has one.
    Checked {
        index: usize,
        refusal: Option<TransportEndpointFailure>,
    },
    Sent {
        index: usize,
        result: Result<TransportPublishReport, TransportAdapterError>,
    },
}

fn ambiguous_endpoint_failure(endpoint: TransportEndpoint) -> TransportEndpointFailure {
    TransportEndpointFailure {
        pre_send: false,
        size_class: None,
        endpoint,
        reason: "publish acknowledgement unknown".into(),
        kind: TransportEndpointFailureKind::PossiblyExposed,
        rejection_category: None,
    }
}

/// The group and relay a group relay's copy of an event names. The adapter
/// routes every group copy by its group, so each one names it; a copy from
/// another plane, or with no relay, is none.
fn group_relay_copy(delivery: &TransportDelivery) -> Option<(&GroupId, &TransportEndpoint)> {
    if delivery.source.plane != TransportDeliveryPlane::Group {
        return None;
    }
    Some((
        delivery.group_id_hint.as_ref()?,
        delivery.source.endpoint.as_ref()?,
    ))
}

/// Among `fanouts`, the pending commit whose exact event `delivery` carries,
/// and `endpoint`'s index among its targets, when that target takes an
/// acknowledgement.
fn echo_target_among(
    fanouts: Vec<OutboundFanout>,
    delivery: &TransportDelivery,
    endpoint: &TransportEndpoint,
) -> Option<(OutboundFanout, usize)> {
    fanouts
        .into_iter()
        .find(|fanout| fanout.is_frozen_event(&delivery.message.id))
        .and_then(|fanout| {
            let index = fanout.target_index_of(endpoint)?;
            fanout
                .takes_acknowledgement(index)
                .then_some((fanout, index))
        })
}

/// How one of this device's group commits that just confirmed was
/// acknowledged, when no relay's `OK` is among its acceptances (mdk#3460):
/// by a read-back when one is among them, otherwise by the account's own
/// echo. `None` when a relay's `OK` is among them, which the commit's
/// publish rows show.
fn confirmed_without_ok(fanout: &OutboundFanout) -> Option<PendingCommitChange> {
    if !is_group_commit(fanout) {
        return None;
    }
    let mut accepted = false;
    let mut read_back = false;
    for index in 0..fanout.request().target.endpoints().len() {
        if fanout.target_status(index) != Some(cgka_traits::FanoutTargetStatus::Accepted) {
            continue;
        }
        accepted = true;
        match fanout.target_acknowledgement(index) {
            None => return None,
            Some(FanoutAcknowledgement::ReadBack) => read_back = true,
            Some(FanoutAcknowledgement::Echo) => {}
        }
    }
    accepted.then_some(if read_back {
        PendingCommitChange::ReadBackConfirmed
    } else {
        PendingCommitChange::EchoConfirmed
    })
}

/// Whether `fanout` carries one of this device's group commits, a group
/// evolution or a disband, rather than an application message or a Welcome.
fn is_group_commit(fanout: &OutboundFanout) -> bool {
    matches!(
        fanout.pending_kind(),
        Some(FanoutPendingKind::GroupEvolution | FanoutPendingKind::Disband)
    ) && matches!(
        fanout.request().message.envelope,
        TransportEnvelope::GroupMessage { .. }
    )
}

fn frozen_fanout_target_retry_due(fanout: &OutboundFanout, index: usize, now_ms: u64) -> bool {
    frozen_fanout_target_retry_delay_ms(fanout, index, now_ms) == Some(0)
}

fn frozen_fanout_target_retry_delay_ms(
    fanout: &OutboundFanout,
    index: usize,
    now_ms: u64,
) -> Option<u64> {
    use cgka_traits::FanoutTargetStatus;

    match fanout.target_status(index) {
        Some(FanoutTargetStatus::NotAttempted | FanoutTargetStatus::Attempting) => Some(0),
        Some(
            status @ (FanoutTargetStatus::PossiblyExposed
            | FanoutTargetStatus::RetryableUnavailable),
        ) => {
            // The delay follows the last recorded failure, not the status: a
            // relay's retryable answer exposes the target, yet retries as
            // promptly as a connection never made (mdk#2332).
            let retries_promptly = fanout.target_failure(index).map_or(
                status == FanoutTargetStatus::RetryableUnavailable,
                |failure| failure.kind == TransportEndpointFailureKind::RetryableUnavailable,
            );
            let delay_ms = if retries_promptly {
                FROZEN_FANOUT_UNAVAILABLE_RETRY_DELAY_MS
            } else {
                let shift = fanout.target_attempt_count(index).saturating_sub(1).min(7);
                FROZEN_FANOUT_AMBIGUOUS_RETRY_BASE_MS
                    .saturating_mul(1_u64 << shift)
                    .min(FROZEN_FANOUT_AMBIGUOUS_RETRY_MAX_MS)
            };
            fanout
                .target_last_attempt_at_ms(index)
                .map_or(Some(0), |last| {
                    Some(last.saturating_add(delay_ms).saturating_sub(now_ms))
                })
        }
        Some(
            FanoutTargetStatus::Accepted
            | FanoutTargetStatus::Failed
            | FanoutTargetStatus::Abandoned,
        )
        | None => None,
    }
}

/// Whether `fanout` is one of this device's confirmed group commits: the
/// fanouts a commit-delivery answer reads. Application messages have no MLS
/// state, and Welcomes go to inboxes.
fn is_confirmed_group_commit(fanout: &OutboundFanout) -> bool {
    matches!(
        fanout.request().message.envelope,
        TransportEnvelope::GroupMessage { .. }
    ) && fanout.mls_state() == FanoutMlsState::Confirmed
}

/// The stored commit whose disposition says whether convergence withdrew the
/// fanout's commit.
fn fanout_commit_id(fanout: &OutboundFanout) -> &cgka_traits::MessageId {
    fanout
        .pending_origin_message_id()
        .unwrap_or_else(|| fanout.message_id())
}

/// When the commit confirmed: its accepting attempt's start, measured from the
/// first acknowledgement, not staging, which can be hours earlier.
fn commit_confirmed_at(fanout: &OutboundFanout) -> Timestamp {
    let first_accepted_ms = (0..fanout.target_statuses().len())
        .filter(|&index| {
            fanout.target_status(index) == Some(cgka_traits::FanoutTargetStatus::Accepted)
        })
        .filter_map(|index| fanout.target_last_attempt_at_ms(index))
        .min()
        .unwrap_or_else(|| fanout.created_at_ms());
    Timestamp(first_accepted_ms / 1_000)
}

/// The refusal record a confirmed commit's fanout holds now: its relays that
/// refused it for good (mdk#2333). `None` when none has.
fn commit_refusal_of(fanout: &OutboundFanout) -> Option<CommitRefusal> {
    if !is_confirmed_group_commit(fanout) {
        return None;
    }
    let refused = fanout.refused_targets();
    if refused.is_empty() {
        return None;
    }
    Some(CommitRefusal {
        fanout_id: fanout.message_id().clone(),
        commit_id: fanout_commit_id(fanout).clone(),
        group_id: fanout.group_id()?.clone(),
        since: commit_confirmed_at(fanout),
        relay_count: u32::try_from(fanout.request().target.endpoints().len()).unwrap_or(u32::MAX),
        refused,
        acknowledged: false,
    })
}

fn frozen_fanout_report(fanout: &OutboundFanout) -> TransportPublishReport {
    let endpoints = fanout.request().target.endpoints();
    let mut accepted = Vec::new();
    let mut failed = Vec::new();
    for (index, (endpoint, status)) in endpoints.iter().zip(fanout.target_statuses()).enumerate() {
        match status {
            cgka_traits::FanoutTargetStatus::Accepted => {
                accepted.push(TransportEndpointReceipt {
                    endpoint: endpoint.clone(),
                    accepted_at: None,
                    // Reconstructed state does not retain the original OK detail.
                    ack_kind: None,
                });
            }
            cgka_traits::FanoutTargetStatus::Failed
            | cgka_traits::FanoutTargetStatus::Abandoned => {
                failed.push(fanout.target_failure(index).cloned().unwrap_or_else(|| {
                    TransportEndpointFailure {
                        pre_send: false,
                        size_class: None,
                        endpoint: endpoint.clone(),
                        reason: "publish attempt failed before exposure".into(),
                        kind: TransportEndpointFailureKind::NotExposed,
                        rejection_category: None,
                    }
                }));
            }
            cgka_traits::FanoutTargetStatus::NotAttempted
            | cgka_traits::FanoutTargetStatus::Attempting => {}
            cgka_traits::FanoutTargetStatus::PossiblyExposed
            | cgka_traits::FanoutTargetStatus::RetryableUnavailable => {
                if let Some(failure) = fanout.target_failure(index) {
                    failed.push(failure.clone());
                }
            }
        }
    }
    TransportPublishReport {
        message_id: fanout
            .published_message_id()
            .unwrap_or_else(|| fanout.message_id())
            .clone(),
        accepted,
        failed,
        required_acks: fanout.request().required_acks,
    }
}

/// Replay the app-visible acknowledgement derived from a durable accepted
/// fanout. The projection is an idempotent upsert, so emitting this on every
/// recovery pass is safe until the app explicitly acknowledges persistence.
fn record_published_application_fanout(fanout: &OutboundFanout, output: &mut AccountDeviceEffects) {
    if fanout.outcome().accepted_targets == 0 {
        return;
    }
    let Some(application) = fanout.application_message() else {
        return;
    };
    let message_id = fanout
        .published_message_id()
        .unwrap_or_else(|| fanout.message_id())
        .clone();
    output
        .published_app_messages
        .push(PublishedApplicationMessage {
            group_id: application.group_id.clone(),
            app_event_id: application.app_event_id.clone(),
            message_id,
            publication_observation: fanout.first_acceptance_observation(),
            source_epoch: application.source_epoch,
            retention: application.retention,
            authority: application.authority,
        });
}

/// Report a terminal application publish with the app-event identity retained
/// on its durable fanout. This remains replayable across the crash window
/// between persisting the terminal target states and deleting the fanout.
fn record_failed_application_fanout(
    fanout: &OutboundFanout,
    reason: String,
    output: &mut AccountDeviceEffects,
) {
    let Some(application) = fanout.application_message() else {
        return;
    };
    let message_id = fanout
        .published_message_id()
        .unwrap_or_else(|| fanout.message_id())
        .clone();
    output.failed_app_messages.push(FailedApplicationMessage {
        group_id: application.group_id.clone(),
        app_event_id: application.app_event_id.clone(),
        message_id,
        reason,
    });
}

/// Whether a failed publish to `attempted` proves its attempt reached no
/// relay: the error names a failure for every endpoint attempted, and each one
/// proves nothing of the attempt was sent (mdk#3305). Any other error may have
/// followed a send.
fn publish_error_reached_no_relay(
    error: &TransportAdapterError,
    attempted: &[TransportEndpoint],
) -> bool {
    let failures = error.publish_endpoint_failures();
    !attempted.is_empty()
        && attempted.iter().all(|endpoint| {
            let mut answers = failures
                .iter()
                .filter(|failure| &failure.endpoint == endpoint)
                .peekable();
            answers.peek().is_some() && answers.all(TransportEndpointFailure::proves_nothing_sent)
        })
}

fn apply_report_to_fanout(
    fanout: &mut DurableTransportFanout,
    attempted: &[TransportEndpoint],
    report: &TransportPublishReport,
    attempted_at: Timestamp,
) {
    for target in &mut fanout.targets {
        if target.state == TransportFanoutAttemptState::Accepted
            || !attempted.contains(&target.endpoint)
        {
            continue;
        }
        let accepted = report
            .accepted
            .iter()
            .any(|receipt| receipt.endpoint == target.endpoint);
        let failed = report
            .failed
            .iter()
            .find(|failure| failure.endpoint == target.endpoint);
        target.attempt_count = target.attempt_count.saturating_add(1);
        target.last_attempt_at = Some(attempted_at);
        if accepted {
            target.state = TransportFanoutAttemptState::Accepted;
            target.failure_code = None;
        } else {
            target.state = TransportFanoutAttemptState::AttemptedFailed;
            // Persist a coarse category only. Detailed transport errors may
            // contain endpoint-specific or otherwise identifying data.
            target.failure_code = Some(
                if failed.is_none_or(|failure| failure.reason.is_empty()) {
                    "publish_failed"
                } else {
                    "transport_rejected"
                }
                .into(),
            );
        }
    }
}

/// Whether this build may still replace a KeyPackage whose signed bytes the
/// publisher refused as unusable; see
/// [`KeyPackageLifecycleState::unusable_artifact_replaced_by`].
fn may_replace_unusable_artifact(lifecycle: &KeyPackageLifecycleState) -> bool {
    lifecycle.unusable_artifact_replaced_by.as_deref() != Some(KEY_PACKAGE_SIGNING_BUILD)
}

/// The weekly refresh: due at the sampled `refresh_at`, and never later than
/// [`KEY_PACKAGE_REFRESH_MAX_SECS`] after publication. The second bound also
/// covers a record whose `refresh_at` was scheduled under the earlier 84-day
/// lifetime.
/// Whether a publication authored at `created_at` went with the slot's
/// withdrawal: relays drop every publication in the slot up to that time.
fn withdrawn_with_slot(lifecycle: &KeyPackageLifecycleState, created_at: Timestamp) -> bool {
    lifecycle
        .slot_withdrawn_at
        .is_some_and(|withdrawn_at| created_at <= withdrawn_at)
}

/// When the current KeyPackage's refresh comes due by time alone: its
/// `refresh_at`, or a week after its publication, whichever is first. The one
/// source for both the due check and the worker's deadline (mdk#2923).
fn key_package_refresh_next_due(lifecycle: &KeyPackageLifecycleState) -> Option<Timestamp> {
    let weekly = lifecycle
        .authored_event_created_at
        .map(|published| Timestamp(published.0.saturating_add(KEY_PACKAGE_REFRESH_MAX_SECS)));
    [lifecycle.refresh_at, weekly]
        .into_iter()
        .flatten()
        .min_by_key(|at| at.0)
}

fn key_package_refresh_due(lifecycle: &KeyPackageLifecycleState, now: Timestamp) -> bool {
    key_package_refresh_next_due(lifecycle).is_some_and(|at| at.0 <= now.0)
}

fn current_key_package_republish_blocker(
    lifecycle: &KeyPackageLifecycleState,
    now: Timestamp,
) -> Option<&'static str> {
    if lifecycle.slot_withdrawn_at.is_some() {
        Some("slot_withdrawn")
    } else if lifecycle.current_key_package.is_none() {
        Some("missing_current_key_package")
    } else if lifecycle.current_key_package_ref.is_none() {
        Some("missing_current_key_package_ref")
    } else if lifecycle
        .current_not_before
        .is_none_or(|not_before| not_before > now)
    {
        Some("current_not_before_unreached")
    } else if lifecycle
        .current_not_after
        .is_none_or(|not_after| not_after <= now)
    {
        Some("current_not_after_expired")
    } else if lifecycle.authored_event_id.is_none() {
        Some("missing_authored_event_id")
    } else if lifecycle.authored_event_created_at.is_none() {
        Some("missing_authored_event_created_at")
    } else if lifecycle.authored_signed_event.is_none() {
        Some("missing_authored_signed_event")
    } else if lifecycle.last_consumed_key_package_ref == lifecycle.current_key_package_ref {
        Some("current_key_package_ref_consumed")
    } else if !lifecycle.upgrade_rotation_recorded
        || lifecycle.generation_revision < KEY_PACKAGE_GENERATION_REVISION
    {
        Some("upgrade_rotation_required")
    } else {
        None
    }
}

fn merge_republish_publication_targets(
    targets: &mut Vec<TransportFanoutTarget>,
    current_endpoints: &[TransportEndpoint],
) {
    for endpoint in current_endpoints {
        if let Some(target) = targets
            .iter_mut()
            .find(|target| target.endpoint == *endpoint)
        {
            if target.state == TransportFanoutAttemptState::PolicyProhibited {
                target.state = TransportFanoutAttemptState::Unattempted;
                target.attempt_count = 0;
                target.last_attempt_at = None;
                target.failure_code = None;
            }
            continue;
        }
        targets.push(TransportFanoutTarget {
            endpoint: endpoint.clone(),
            state: TransportFanoutAttemptState::Unattempted,
            attempt_count: 0,
            last_attempt_at: None,
            failure_code: None,
        });
    }
    for target in targets.iter_mut() {
        if current_endpoints.contains(&target.endpoint) {
            continue;
        }
        if target.state == TransportFanoutAttemptState::PolicyProhibited {
            continue;
        }
        target.state = TransportFanoutAttemptState::PolicyProhibited;
        target.failure_code = Some("endpoint_removed_from_policy".into());
    }
}

fn note_key_package_attempt(
    targets: &mut [TransportFanoutTarget],
    attempted: &[TransportEndpoint],
    accepted: &[TransportEndpoint],
    failed: &[TransportEndpoint],
    attempted_at: Timestamp,
) {
    for target in targets {
        if target.state == TransportFanoutAttemptState::Accepted
            || !attempted.contains(&target.endpoint)
        {
            continue;
        }
        target.attempt_count = target.attempt_count.saturating_add(1);
        target.last_attempt_at = Some(attempted_at);
        if accepted.contains(&target.endpoint) {
            target.state = TransportFanoutAttemptState::Accepted;
            target.failure_code = None;
        } else {
            target.state = TransportFanoutAttemptState::AttemptedFailed;
            target.failure_code = Some(
                if failed.contains(&target.endpoint) {
                    "transport_rejected"
                } else {
                    "publish_failed"
                }
                .into(),
            );
        }
    }
}

fn key_package_target_retry_due(target: &TransportFanoutTarget, now: Timestamp) -> bool {
    transport_fanout_target_retry_due(target, now)
}

fn accepted_fanout_targets(fanout: &DurableTransportFanout) -> usize {
    fanout
        .targets
        .iter()
        .filter(|target| target.state == TransportFanoutAttemptState::Accepted)
        .count()
}

fn transport_fanout_target_retry_due(target: &TransportFanoutTarget, now: Timestamp) -> bool {
    transport_retry_delay_ms(target, now.0.saturating_mul(1_000)) == Some(0)
}

fn transport_retry_delay_ms(target: &TransportFanoutTarget, now_ms: u64) -> Option<u64> {
    if matches!(
        target.state,
        TransportFanoutAttemptState::Accepted | TransportFanoutAttemptState::PolicyProhibited
    ) {
        return None;
    }
    let shift = target.attempt_count.saturating_sub(1).min(7);
    let backoff = 30_u64.saturating_mul(1_u64 << shift).min(60 * 60);
    Some(target.last_attempt_at.map_or(0, |last| {
        last.0
            .saturating_add(backoff)
            .saturating_mul(1_000)
            .saturating_sub(now_ms)
    }))
}

/// The failure of an invite refused before its commit was published because
/// an artifact of it fits none of its relays' known limits (mdk#2334).
/// Welcomes judged against the relays their publish would reach: each by the
/// target the routing policy resolves for it, and the adapter's own endpoint
/// rule for that target (mdk#2334).
struct WelcomeSizes<'a, A, R> {
    adapter: &'a A,
    routing: &'a R,
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl<A, R> WelcomeSizeCheck for WelcomeSizes<'_, A, R>
where
    A: TransportAdapter,
    R: TransportRoutingPolicy,
{
    async fn oversized_welcome(
        &self,
        welcomes: &[TransportMessage],
    ) -> Option<cgka_traits::EventSizeClass> {
        self.oversized_welcomes(welcomes)
            .await
            .into_iter()
            .next()
            .map(|(_, size_class)| size_class)
    }
}

impl<A, R> WelcomeSizes<'_, A, R>
where
    A: TransportAdapter,
    R: TransportRoutingPolicy,
{
    /// Each of `welcomes` that fits none of its inbox relays' known limits,
    /// with its size class, in order.
    async fn oversized_welcomes(
        &self,
        welcomes: &[TransportMessage],
    ) -> Vec<(cgka_traits::MessageId, cgka_traits::EventSizeClass)> {
        // A Welcome without a route fails when it is published.
        let checks = welcomes.iter().filter_map(|welcome| {
            let target = self.routing.publish_target(welcome).ok()?;
            Some(async move {
                self.adapter
                    .size_class_over_known_limits(welcome, &target)
                    .await
                    .map(|size_class| (welcome.id.clone(), size_class))
            })
        });
        futures::future::join_all(checks)
            .await
            .into_iter()
            .flatten()
            .collect()
    }
}

fn refused_before_publishing(
    message_id: cgka_traits::MessageId,
    oversized: OversizedEvent,
) -> PublishFailure {
    tracing::debug!(
        target: TRACE_TARGET,
        method = "refused_before_publishing",
        artifact = oversized.artifact.as_str(),
        size_class = oversized.size_class.as_str(),
        "invite fits none of its relays' known limits; rolled back unsent"
    );
    PublishFailure {
        message_id,
        reason: TransportEndpointFailure::OVER_KNOWN_LIMIT_REASON.to_owned(),
        oversized: Some(oversized),
        no_usable_relay: false,
    }
}

/// Pull caller-owned Welcome payloads off publish work so the commit/create can confirm
/// without waiting for recipient delivery. Empty Welcome vectors remain on the
/// original work items so later publish still confirms the commit. Automatic
/// work retains its Welcomes until its own commit is acknowledged.
fn take_deferred_welcomes(effects: &mut SessionEffects) -> Vec<TransportMessage> {
    let mut welcomes = Vec::new();
    for work in &mut effects.publish {
        match work {
            PublishWork::GroupEvolution {
                welcomes: items, ..
            }
            | PublishWork::GroupCreated {
                welcomes: items, ..
            }
            | PublishWork::FoundingGroupCreated { welcomes: items } => {
                welcomes.append(items);
            }
            _ => {}
        }
    }
    welcomes
}

fn supports_deferred_commit_publish(intent: &SendIntent) -> bool {
    matches!(
        intent,
        SendIntent::Invite { .. }
            | SendIntent::RecoverMembers { .. }
            | SendIntent::RemoveMembers { .. }
            | SendIntent::AddOwnAccountDevices { .. }
            | SendIntent::RemoveOwnAccountDevices { .. }
            | SendIntent::SelfUpdate { .. }
            | SendIntent::UpdateAppComponents { .. }
            | SendIntent::ReplaceDeviceEntry { .. }
            | SendIntent::ReplaceAccountEntry { .. }
            | SendIntent::UpdateGroupData { .. }
            | SendIntent::EnableDisbanding { .. }
            | SendIntent::EnableAccountDevices { .. }
            | SendIntent::LinkDevice { .. }
            | SendIntent::UnlinkDevice { .. }
            | SendIntent::RecordRemovedSlot { .. }
            | SendIntent::ImportDeviceGroupRejections { .. }
            | SendIntent::MarkDeviceGroupMoved { .. }
    )
}

fn classify_prepared_session_send(
    mut effects: SessionEffects,
) -> AccountResult<PreparedSessionSend> {
    let pending = effects.publish.iter().find_map(|work| match work {
        PublishWork::GroupEvolution { pending, .. } | PublishWork::GroupCreated { pending, .. } => {
            Some(*pending)
        }
        _ => None,
    });
    let Some(pending) = pending else {
        if !effects.queued.is_empty() {
            return Ok(PreparedSessionSend::Queued(effects));
        }
        return Err(cgka_traits::EngineError::Backend(
            "prepared send contained neither a pending MLS evolution nor a queued intent".into(),
        )
        .into());
    };
    let welcomes = take_deferred_welcomes(&mut effects);
    Ok(PreparedSessionSend::Commit(PreparedSessionCommit {
        effects,
        welcomes,
        pending,
    }))
}

/// The welcome recipient carried in the message's transport envelope, if the
/// message is a welcome.
fn welcome_recipient(message: &TransportMessage) -> Option<MemberId> {
    match &message.envelope {
        TransportEnvelope::Welcome { recipient } => Some(recipient.clone()),
        TransportEnvelope::GroupMessage { .. } => None,
    }
}

/// How long `message` had existed at `now`, from its outer `created_at`, for
/// the `publish_outcome` row. Retries resend the exact signed event, so this
/// grows with every retry of one publish (mdk#2256).
fn publish_event_age_secs(message: &TransportMessage, now: Timestamp) -> Option<u64> {
    Some(now.0.saturating_sub(message.timestamp.0))
}

/// Build the outbound transport wire envelope for a publish, from the message's
/// transport source and (for group messages) the transport-visible group id.
/// Transport-generic: the post-wrap relay event id and ephemeral pubkey are
/// produced inside the transport adapter and are intentionally not recorded
/// here.
fn publish_wire_metadata(message: &TransportMessage) -> AuditTransportWire {
    let transport_group_id = match &message.envelope {
        TransportEnvelope::GroupMessage { transport_group_id } => {
            Some(hex::encode(transport_group_id))
        }
        TransportEnvelope::Welcome { .. } => None,
    };
    AuditTransportWire {
        transport: Some(message.source.0.clone()),
        transport_group_id,
        ..Default::default()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccountDeviceEffects {
    /// Sum of local engine acceptance and application fanout journal preparation.
    /// Excludes relay I/O; a batch can stage sibling application messages.
    /// Present only when effects return; not propagated from absorbed batches.
    pub local_accept_duration: Option<Duration>,
    /// Publication and reconciliation duration for this send's effects batch.
    /// This is not a raw relay acknowledgement or recipient-delivery timestamp.
    pub publish_duration: Option<Duration>,
    pub events: Vec<GroupEvent>,
    pub queued: Vec<QueuedIntentRef>,
    pub pending_convergence: Vec<GroupId>,
    pub reports: Vec<TransportPublishReport>,
    /// Privacy-safe summaries separate MLS release from target fanout completion.
    pub fanout: Vec<OutboundFanoutOutcome>,
    pub failures: Vec<PublishFailure>,
    /// Exact signed events retained because publication completion is not yet
    /// known. This is a typed non-failure result: callers must not create a
    /// semantically new send to recover it.
    pub unresolved_publishes: Vec<UnresolvedPublish>,
    /// Application-message identity attached to unresolved publication so app
    /// consumers can keep exactly the affected local row in a sending state.
    pub unresolved_app_messages: Vec<UnresolvedApplicationMessage>,
    /// Application messages whose publication reached a definitive terminal
    /// failure, carrying the local app-event identity needed to invalidate only
    /// the affected optimistic projection.
    pub failed_app_messages: Vec<FailedApplicationMessage>,
    /// Application messages accepted by at least one transport endpoint,
    /// carrying source-state metadata captured by the exact MLS encryption
    /// operation and the adapter-visible transport id.
    pub published_app_messages: Vec<PublishedApplicationMessage>,
    /// Welcomes whose publish failed after their commit/create was already
    /// confirmed. Unlike `failures`, each entry carries the recipient and
    /// group so the caller can re-deliver the stored welcome via
    /// [`AccountDeviceRuntime::redeliver_welcome`] without re-committing.
    pub welcome_failures: Vec<WelcomeDeliveryFailure>,
    /// Own commits that convergence superseded during this batch, with what
    /// became of the intent behind each: re-queued for the next drain, or
    /// dropped with a stated reason (mdk#1734). Hosts surface these to the
    /// user; the original command already returned success.
    pub superseded_intents: Vec<SupersededIntentReport>,
    pub pending: Vec<PendingResolution>,
    pub maintenance_disposition: SendMaintenanceDisposition,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishedApplicationMessage {
    /// Immutable first durable acceptance observation; unavailable for legacy fanouts.
    pub publication_observation: Option<cgka_traits::PublicationObservation>,
    pub group_id: GroupId,
    pub app_event_id: String,
    pub message_id: cgka_traits::MessageId,
    pub source_epoch: EpochId,
    pub retention: cgka_traits::app_event::AppMessageRetentionDecision,
    pub authority: Option<cgka_traits::app_event::AppMessageAuthority>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FailedApplicationMessage {
    pub group_id: GroupId,
    pub app_event_id: String,
    pub message_id: cgka_traits::MessageId,
    pub reason: String,
}

impl AccountDeviceEffects {
    /// Append `other`, as a later publish's effects follow an earlier one's.
    pub fn extend(&mut self, mut other: Self) {
        self.fanout.append(&mut other.fanout);
        self.absorb_account_effects(other);
    }

    fn absorb_session_effects(
        &mut self,
        effects: SessionEffects,
        queue: &mut VecDeque<PublishWork>,
    ) {
        self.events.extend(effects.events);
        self.queued.extend(effects.queued);
        self.pending_convergence.extend(effects.pending_convergence);
        queue.extend(effects.publish);
    }

    fn absorb_account_effects(&mut self, mut other: AccountDeviceEffects) {
        self.events.append(&mut other.events);
        self.queued.append(&mut other.queued);
        self.pending_convergence
            .append(&mut other.pending_convergence);
        self.reports.append(&mut other.reports);
        self.failures.append(&mut other.failures);
        self.unresolved_publishes
            .append(&mut other.unresolved_publishes);
        self.unresolved_app_messages
            .append(&mut other.unresolved_app_messages);
        self.failed_app_messages
            .append(&mut other.failed_app_messages);
        self.published_app_messages
            .append(&mut other.published_app_messages);
        self.welcome_failures.append(&mut other.welcome_failures);
        self.superseded_intents
            .append(&mut other.superseded_intents);
        self.pending.append(&mut other.pending);
        if other.maintenance_disposition
            == SendMaintenanceDisposition::PostJoinRotationPendingRetryable
        {
            self.maintenance_disposition = other.maintenance_disposition;
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountIngestEffects {
    pub outcome: IngestOutcome,
    /// The engine kept no durable trace of this delivery's transport object.
    /// Carried verbatim from the session's ingest effects.
    pub left_object_unpersisted: bool,
    pub effects: AccountDeviceEffects,
}

/// The account's transport fanouts and confirmed group evolutions, by group.
/// See [`AccountDeviceRuntime::group_maintenance_rows`].
#[derive(Debug, Default)]
pub struct GroupMaintenanceRows {
    /// Each group's fanouts, in storage order.
    fanouts: HashMap<GroupId, Vec<DurableTransportFanout>>,
    confirmed_evolutions: HashMap<GroupId, HashSet<cgka_traits::MessageId>>,
    /// Each group's stored commit refusals (mdk#2333).
    commit_refusals: HashMap<GroupId, Vec<CommitRefusal>>,
}

impl GroupMaintenanceRows {
    fn fanouts(&self, group_id: &GroupId) -> &[DurableTransportFanout] {
        self.fanouts.get(group_id).map_or(&[], Vec::as_slice)
    }

    fn commit_refusals(&self, group_id: &GroupId) -> &[CommitRefusal] {
        self.commit_refusals
            .get(group_id)
            .map_or(&[], Vec::as_slice)
    }
}

/// The wall-clock span over which a time-dependent answer holds without a
/// write (mdk#3273): from the clock reading it was computed at, until the
/// first later bound that changes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WallClockWindow {
    /// The clock reading the answer was computed at. A clock moved back
    /// before it can bring an expired bound back into force.
    pub from: Timestamp,
    /// When a bound passes and the answer can change; `None` when only a
    /// write can change it.
    pub until: Option<Timestamp>,
}

impl WallClockWindow {
    /// The window of an answer that depends on no clock reading.
    pub const ALWAYS: Self = Self {
        from: Timestamp(0),
        until: None,
    };

    /// Whether an answer computed in this window still holds at `now`.
    #[must_use]
    pub fn contains(&self, now: Timestamp) -> bool {
        self.from <= now && self.until.is_none_or(|until| now < until)
    }
}

/// A confirmed commit that some of its group relays have not accepted yet
/// (mdk#2255). See [`AccountDeviceRuntime::undelivered_commit`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UndeliveredCommit {
    pub message_id: cgka_traits::MessageId,
    /// When the first relay accepted the commit, which confirmed it.
    pub since: Timestamp,
    /// Relays still owed the exact commit.
    pub owed_endpoints: Vec<TransportEndpoint>,
    /// Relays that refused the commit for good, not yet acknowledged
    /// (mdk#2333). MDK will not deliver it there; members who read only those
    /// relays may not have it.
    pub refused_endpoints: Vec<RefusedTarget>,
    /// Relays the commit was published to.
    pub endpoint_count: usize,
}

/// The group's own commit that has not confirmed yet (mdk#2332). See
/// [`AccountDeviceRuntime::pending_commit`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingCommit {
    /// The commit: its frozen fanout's message id, which a not-delivered
    /// record names if the commit is later given up.
    pub message_id: cgka_traits::MessageId,
    /// Which call made it: a host's group change, or the queued intent it
    /// was drained from. `None` for a commit MDK made on its own, such as a
    /// scheduled self-update.
    pub origin: Option<cgka_traits::storage::ChangeOrigin>,
    /// The stable name of the change's kind, such as `update_group_data`,
    /// when `origin` is known and names it.
    pub intent_kind: Option<String>,
    /// When the first send attempt started, `None` before any has.
    pub first_attempt_at: Option<Timestamp>,
    pub state: PendingCommitState,
    /// Relays that may hold the commit without having acknowledged it. While
    /// any does, MDK never gives the commit up.
    pub unconfirmed_endpoints: Vec<TransportEndpoint>,
    /// Relays still owed the commit that it never reached.
    pub owed_endpoints: Vec<TransportEndpoint>,
    /// Each relay whose latest answer was final, with #2333's cause; such a
    /// relay can also be unconfirmed, from an earlier attempt.
    pub refused_endpoints: Vec<RefusedTarget>,
    /// Relays the commit was published to.
    pub endpoint_count: usize,
}

/// Where a pending commit stands (mdk#2332).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingCommitState {
    /// MDK is still sending it: its first attempt is less than ten minutes
    /// old (the bound past which it is read back), or no relay may hold it
    /// and MDK waits to reach one.
    Sending,
    /// Past that bound, some relay may hold it and none has acknowledged it.
    /// MDK keeps resending it, backing off to about hourly and reading it
    /// back from each such relay first, and never gives it up, since members
    /// may have seen it (mdk#1577).
    Stuck,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishFailure {
    pub message_id: cgka_traits::MessageId,
    pub reason: String,
    /// All-target size refusal on the observed attempt; absent for mixed or
    /// unknown outcomes. A legacy Welcome's earlier exposure can be unknown.
    /// This is not evidence of delivery or non-delivery and never ends retry work.
    pub oversized: Option<OversizedEvent>,
    /// The group has no relay this device may send to: the transport refused
    /// every target of a group send for the endpoint itself before sending
    /// anything, as the host-safety rule refuses a private-network relay
    /// (mdk#3276). Nothing was sent, and the outcome is final, since the
    /// transport refuses every attempt there (mdk#3305).
    pub no_usable_relay: bool,
}

pub use cgka_traits::OversizedArtifact;

/// The future `start` builds, boxed in this plain function, as
/// [`refuse_too_large`] boxes its own. Maintenance awaits each phase through
/// it: unboxed, every phase's future sat in the maintenance poll frame at once,
/// over a third of a MiB of a debug test thread's stack (mdk#2412).
#[inline(never)]
fn boxed<F: Future>(start: impl FnOnce() -> F) -> Pin<Box<F>> {
    Box::pin(start())
}

/// [`AccountDeviceSession::publish_refused_as_too_large`] for `oversized`,
/// boxed in this plain function. `Box::pin` called in an async body still
/// builds the future in that body's poll frame, and every poll of the body
/// then carries it, the paths that never refuse included. The drain and
/// fanout bodies that call these helpers run within a few KiB of a test
/// thread's stack, so they hold only the box (mdk#2334).
#[inline(never)]
fn refuse_too_large<'a>(
    session: &'a mut AccountDeviceSession,
    pending: PendingStateRef,
    fanout: Option<&'a mut OutboundFanout>,
    oversized: OversizedEvent,
    pass: RollbackPass,
) -> Pin<Box<impl Future<Output = SessionResult<SessionEffects>> + 'a>> {
    Box::pin(session.publish_refused_as_too_large(
        pending,
        fanout,
        oversized.artifact,
        oversized.size_class,
        pass,
    ))
}

/// Roll back `pending`, which no relay of `fanout` accepted, boxed as
/// [`refuse_too_large`] is. A commit every relay refused for its size cannot
/// fit on a retry: one drained from the queue is retired, not re-drained
/// (mdk#2334).
#[inline(never)]
fn roll_back_failed_fanout<'a>(
    session: &'a mut AccountDeviceSession,
    pending: PendingStateRef,
    fanout: &'a mut OutboundFanout,
    pass: RollbackPass,
) -> Pin<Box<impl Future<Output = SessionResult<SessionEffects>> + 'a>> {
    Box::pin(async move {
        match OversizedEvent::of_fanout(fanout) {
            Some(oversized) => {
                session
                    .publish_refused_as_too_large(
                        pending,
                        Some(fanout),
                        oversized.artifact,
                        oversized.size_class,
                        pass,
                    )
                    .await
            }
            None => session.publish_failed_fanout(pending, fanout, pass).await,
        }
    })
}

/// Roll back `pending`, a commit that reached no relay and was given up,
/// boxed as [`refuse_too_large`] is (mdk#2332): `fanout` carries its unsent
/// targets' `Abandoned` edge, and a queued intent it was drained from is
/// retired as `not_delivered`.
#[inline(never)]
fn give_up_unsent_commit<'a>(
    session: &'a mut AccountDeviceSession,
    pending: PendingStateRef,
    fanout: &'a mut OutboundFanout,
    pass: RollbackPass,
) -> Pin<Box<impl Future<Output = SessionResult<SessionEffects>> + 'a>> {
    Box::pin(session.publish_not_delivered(pending, fanout, pass))
}

/// Privacy-safe explanation of an observed all-target size refusal, without
/// exact sizes, identifiers, relay details, or an inferred relay limit.
/// Frozen fanouts retain their strong exposure proof. Legacy Welcomes explain
/// the observed attempt: a crash or expired bookkeeping can hide earlier
/// exposure, so this does not prove non-delivery or authorize ending retries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OversizedEvent {
    pub artifact: OversizedArtifact,
    pub size_class: cgka_traits::EventSizeClass,
}

/// Whether a finished group fanout found no relay this device may send to
/// (mdk#3305): no target accepted it, none is outstanding, none may hold it,
/// and the transport refused every target for the endpoint itself before
/// sending ([`TransportEndpointFailure::is_endpoint_prohibited`]), as the
/// host-safety rule refuses a private-network relay. The transport refuses
/// every attempt there, so no retry or relay answer changes the outcome.
fn has_no_usable_relay(fanout: &OutboundFanout) -> bool {
    let targets = fanout.request().target.endpoints().len();
    targets != 0
        && !fanout.possible_exposure()
        && fanout.outcome().accepted_targets == 0
        && fanout.outcome().outstanding_targets == 0
        && (0..targets).all(|index| {
            fanout
                .target_failure(index)
                .is_some_and(TransportEndpointFailure::is_endpoint_prohibited)
        })
}

impl OversizedEvent {
    fn of_first_legacy_welcome_attempt(
        fanout: &DurableTransportFanout,
        result: &Result<TransportPublishReport, TransportAdapterError>,
    ) -> Option<Self> {
        if !matches!(
            fanout.exact_message.envelope,
            TransportEnvelope::Welcome { .. }
        ) || fanout.possible_exposure
            || fanout.targets.iter().any(|target| {
                target.attempt_count != 0 || target.state == TransportFanoutAttemptState::Accepted
            })
        {
            return None;
        }
        let failures: &[TransportEndpointFailure] = match result {
            Ok(report) if report.accepted.is_empty() => &report.failed,
            Ok(_) => return None,
            Err(error) => error.publish_endpoint_failures(),
        };
        let size_class = cgka_traits::EventSizeClass::from_rejected_targets(
            fanout.target.endpoints(),
            failures,
        )?;
        Some(Self {
            artifact: OversizedArtifact::Welcome,
            size_class,
        })
    }

    fn of_fanout(fanout: &OutboundFanout) -> Option<Self> {
        if fanout.possible_exposure()
            || fanout.outcome().accepted_targets != 0
            || fanout.outcome().outstanding_targets != 0
        {
            return None;
        }
        let failures = (0..fanout.request().target.endpoints().len())
            .map(|index| fanout.target_failure(index).cloned())
            .collect::<Option<Vec<_>>>()?;
        let size_class = cgka_traits::EventSizeClass::from_rejected_targets(
            fanout.request().target.endpoints(),
            &failures,
        )?;
        let artifact = if matches!(
            fanout.request().message.envelope,
            TransportEnvelope::Welcome { .. }
        ) {
            OversizedArtifact::Welcome
        } else if fanout.application_message().is_some() {
            OversizedArtifact::ApplicationMessage
        } else if matches!(
            fanout.pending_kind(),
            Some(FanoutPendingKind::GroupEvolution | FanoutPendingKind::Disband)
        ) {
            OversizedArtifact::Commit
        } else {
            OversizedArtifact::Other
        };
        Some(Self {
            artifact,
            size_class,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnresolvedPublishReason {
    AcknowledgementUnknown,
    RetryableUnavailable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnresolvedPublish {
    pub message_id: cgka_traits::MessageId,
    pub reason: UnresolvedPublishReason,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnresolvedApplicationMessage {
    pub group_id: GroupId,
    pub app_event_id: String,
    pub message_id: cgka_traits::MessageId,
    pub reason: UnresolvedPublishReason,
}

/// A Welcome still owed after a canonical create or confirmed evolution (mdk#352).
///
/// Pending does not prove whether the added member received it. Confirmed group
/// state is not rolled back; ordinary re-delivery remains owed. The wrapped Welcome stays available in the
/// engine's sent-message store under `message_id`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WelcomeDeliveryFailure {
    pub message_id: cgka_traits::MessageId,
    pub recipient: MemberId,
    /// From the already-known confirmation or stored sent-welcome record;
    /// best-effort.
    pub group_id: Option<GroupId>,
    pub reason: String,
    /// Coarse size refusal on the observed attempt. A legacy Welcome's earlier
    /// exposure can be unknown after a crash or expired bookkeeping. An absent
    /// value means Unknown; neither value proves delivery or non-delivery.
    pub size_class: Option<cgka_traits::EventSizeClass>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PendingResolution {
    Confirmed { pending: PendingStateRef },
    RolledBack { pending: PendingStateRef },
}

fn v5_endpoint_ref(endpoint: &TransportEndpoint) -> Option<audit_v5::EndpointRef> {
    // TransportEndpoint is supplied by the routing owner after canonical relay
    // URL normalization; preserve its path/query in the hash input.
    audit_v5::EndpointRef::from_normalized_url(&endpoint.0).ok()
}

fn v5_local_id(domain: &[u8], message_id: &[u8], ordinal: u32) -> audit_v5::LocalId {
    let mut hash = Sha256::new();
    hash.update(b"marmot-audit-local-id/v5\0");
    hash.update(domain);
    hash.update([0]);
    hash.update(message_id);
    hash.update(ordinal.to_be_bytes());
    hex::encode(&hash.finalize()[..16])
        .try_into()
        .expect("16-byte hash")
}

fn v5_failed_endpoint_result(
    failure: &TransportEndpointFailure,
) -> Option<audit_v5::EndpointResult> {
    let endpoint_ref = v5_endpoint_ref(&failure.endpoint)?;
    let rejection_category = failure
        .rejection_category
        .filter(|category| {
            !(failure.kind == TransportEndpointFailureKind::NotExposed
                && *category == TransportEndpointRejectionCategory::TooLarge)
                // V5 describes the cumulative outcome, not merely the last
                // refusal after an earlier uncertain attempt.
                && (failure.kind != TransportEndpointFailureKind::PossiblyExposed
                    || *category == TransportEndpointRejectionCategory::Error)
        })
        .map(|category| match category {
            TransportEndpointRejectionCategory::Duplicate => audit_v5::RejectionCategory::Duplicate,
            TransportEndpointRejectionCategory::Pow => audit_v5::RejectionCategory::Pow,
            TransportEndpointRejectionCategory::Blocked => audit_v5::RejectionCategory::Blocked,
            TransportEndpointRejectionCategory::RateLimited => {
                audit_v5::RejectionCategory::RateLimited
            }
            TransportEndpointRejectionCategory::Invalid => audit_v5::RejectionCategory::Invalid,
            TransportEndpointRejectionCategory::Error => audit_v5::RejectionCategory::Error,
            TransportEndpointRejectionCategory::Unsupported => {
                audit_v5::RejectionCategory::Unsupported
            }
            TransportEndpointRejectionCategory::AuthRequired => {
                audit_v5::RejectionCategory::AuthRequired
            }
            TransportEndpointRejectionCategory::Restricted => {
                audit_v5::RejectionCategory::Restricted
            }
            TransportEndpointRejectionCategory::TooLarge => audit_v5::RejectionCategory::Invalid,
        });
    let failure_kind = match failure.kind {
        TransportEndpointFailureKind::TerminalRejected => {
            audit_v5::EndpointFailureKind::TerminalRejected
        }
        TransportEndpointFailureKind::NotExposed => audit_v5::EndpointFailureKind::NotExposed,
        TransportEndpointFailureKind::PossiblyExposed => {
            audit_v5::EndpointFailureKind::PossiblyExposed
        }
        TransportEndpointFailureKind::RetryableUnavailable => {
            audit_v5::EndpointFailureKind::RetryableUnavailable
        }
    };
    let admissible = matches!(
        (failure_kind, rejection_category),
        (
            audit_v5::EndpointFailureKind::TerminalRejected,
            Some(
                audit_v5::RejectionCategory::Pow
                    | audit_v5::RejectionCategory::Blocked
                    | audit_v5::RejectionCategory::Invalid
                    | audit_v5::RejectionCategory::Unsupported
                    | audit_v5::RejectionCategory::Restricted,
            ),
        ) | (audit_v5::EndpointFailureKind::NotExposed, None)
            | (
                audit_v5::EndpointFailureKind::PossiblyExposed,
                None | Some(audit_v5::RejectionCategory::Error),
            )
            | (
                audit_v5::EndpointFailureKind::RetryableUnavailable,
                None | Some(
                    audit_v5::RejectionCategory::RateLimited
                        | audit_v5::RejectionCategory::AuthRequired,
                ),
            )
    );
    admissible.then_some(audit_v5::EndpointResult {
        endpoint_ref,
        status: audit_v5::EndpointStatus::Failed,
        failure_kind: Some(failure_kind),
        rejection_category,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_failure_projection_keeps_cumulative_uncertainty() {
        use audit_v5::{EndpointFailureKind as AuditFailure, RejectionCategory as AuditCategory};
        use cgka_traits::{
            TransportEndpointFailureKind as Failure, TransportEndpointRejectionCategory as Category,
        };

        for (kind, category, expected_kind, expected_category) in [
            (
                Failure::PossiblyExposed,
                None,
                AuditFailure::PossiblyExposed,
                None,
            ),
            (
                Failure::PossiblyExposed,
                Some(Category::Error),
                AuditFailure::PossiblyExposed,
                Some(AuditCategory::Error),
            ),
            (
                Failure::PossiblyExposed,
                Some(Category::Invalid),
                AuditFailure::PossiblyExposed,
                None,
            ),
            (
                Failure::PossiblyExposed,
                Some(Category::TooLarge),
                AuditFailure::PossiblyExposed,
                None,
            ),
            (
                Failure::PossiblyExposed,
                Some(Category::RateLimited),
                AuditFailure::PossiblyExposed,
                None,
            ),
            (
                Failure::PossiblyExposed,
                Some(Category::AuthRequired),
                AuditFailure::PossiblyExposed,
                None,
            ),
            (
                Failure::TerminalRejected,
                Some(Category::Invalid),
                AuditFailure::TerminalRejected,
                Some(AuditCategory::Invalid),
            ),
        ] {
            let failure = TransportEndpointFailure {
                pre_send: false,
                endpoint: TransportEndpoint("wss://relay.example/".into()),
                reason: "publication refused".into(),
                kind,
                rejection_category: category,
                size_class: None,
            };
            let result = v5_failed_endpoint_result(&failure).unwrap_or_else(|| {
                panic!("the audit must retain the endpoint for {kind:?}/{category:?}")
            });
            assert_eq!(result.status, audit_v5::EndpointStatus::Failed);
            assert_eq!(result.failure_kind, Some(expected_kind));
            assert_eq!(result.rejection_category, expected_category);
        }
    }

    fn failed_frozen_fanout(kind: TransportEndpointFailureKind) -> OutboundFanout {
        let mut fanout = staged_frozen_fanout(None);
        fanout.mark_attempt_started_at(0, 1_000).unwrap();
        fanout
            .record_target_failure(
                0,
                TransportEndpointFailure {
                    // An unavailable failure here is a connect failure.
                    pre_send: kind == TransportEndpointFailureKind::RetryableUnavailable,
                    size_class: None,
                    endpoint: fanout.request().target.endpoints()[0].clone(),
                    reason: "test failure".into(),
                    kind,
                    rejection_category: None,
                },
            )
            .unwrap();
        fanout
    }

    /// One group fanout to one relay: a commit with `pending`, else an
    /// application message.
    fn staged_frozen_fanout(pending: Option<PendingStateRef>) -> OutboundFanout {
        let group_id = GroupId::new(vec![0x11; 16]);
        let transport_group_id = vec![0x22; 32];
        let endpoint = TransportEndpoint("wss://relay.example".into());
        let request = TransportPublishRequest {
            account_id: MemberId::new(vec![0x33; 32]),
            message: TransportMessage {
                id: cgka_traits::MessageId::new(vec![0x44; 32]),
                payload: vec![0x55],
                timestamp: Timestamp(1),
                causal_deps: Vec::new(),
                source: cgka_traits::transport::TransportSource("nostr".into()),
                envelope: TransportEnvelope::GroupMessage {
                    transport_group_id: transport_group_id.clone(),
                },
            },
            target: TransportPublishTarget::Group {
                group_id: group_id.clone(),
                transport_group_id,
                endpoints: vec![endpoint],
            },
            required_acks: 1,
        };
        match pending {
            Some(pending) => {
                OutboundFanout::stage(request, Some(pending), Some(group_id), 1_000).unwrap()
            }
            None => {
                let mut fanout = OutboundFanout::stage(request, None, None, 1_000).unwrap();
                fanout
                    .set_application_message(OutboundApplicationMessage {
                        group_id,
                        app_event_id: "event".into(),
                        source_epoch: EpochId(1),
                        retention: cgka_traits::app_event::AppMessageRetentionDecision::new(10, 0),
                        authority: None,
                    })
                    .unwrap();
                fanout
            }
        }
    }

    /// The retry delay follows the target's last recorded failure, not its
    /// exposure (mdk#2332). A relay's retryable answer exposes the target, yet
    /// it retries after 5 s like a connection never made; an ambiguous
    /// failure, or a definitive refusal on an exposed target, backs off from
    /// 30 s. The same for an application message and a commit.
    #[test]
    fn unavailable_fanout_retries_promptly_without_shortening_ambiguous_backoff() {
        use TransportEndpointFailureKind as Kind;
        use TransportEndpointRejectionCategory as Category;

        let failure = |kind, category, pre_send| TransportEndpointFailure {
            pre_send,
            size_class: None,
            endpoint: TransportEndpoint("wss://relay.example".into()),
            reason: "test failure".into(),
            kind,
            rejection_category: category,
        };
        let connect_failure = failure(Kind::RetryableUnavailable, None, true);
        let rate_limited = failure(
            Kind::RetryableUnavailable,
            Some(Category::RateLimited),
            false,
        );
        let auth_required = failure(
            Kind::RetryableUnavailable,
            Some(Category::AuthRequired),
            false,
        );
        let timeout = failure(Kind::PossiblyExposed, None, false);
        let invalid = failure(Kind::TerminalRejected, Some(Category::Invalid), false);

        for (publication, pending) in [
            ("application message", None),
            ("commit", Some(PendingStateRef::new(7))),
        ] {
            // Each case: its attempts' results, whether they expose the
            // target, and when the last attempt (at 1 s) is due again.
            for (case, results, exposed, due_at_ms) in [
                ("connect failure", vec![&connect_failure], false, 6_000),
                ("rate-limited answer", vec![&rate_limited], true, 6_000),
                ("auth-required answer", vec![&auth_required], true, 6_000),
                (
                    "connect failure after an answer",
                    vec![&rate_limited, &connect_failure],
                    true,
                    6_000,
                ),
                ("timeout", vec![&timeout], true, 31_000),
                // The second attempt doubles the backoff.
                (
                    "definitive refusal after an answer",
                    vec![&rate_limited, &invalid],
                    true,
                    61_000,
                ),
            ] {
                let mut fanout = staged_frozen_fanout(pending);
                for result in results {
                    fanout.mark_attempt_started_at(0, 1_000).unwrap();
                    fanout.record_target_failure(0, result.clone()).unwrap();
                }
                assert_eq!(fanout.possible_exposure(), exposed, "{publication}, {case}");
                assert!(
                    !frozen_fanout_target_retry_due(&fanout, 0, due_at_ms - 1),
                    "{publication}, {case}: not due before {due_at_ms} ms"
                );
                assert!(
                    frozen_fanout_target_retry_due(&fanout, 0, due_at_ms),
                    "{publication}, {case}: due at {due_at_ms} ms"
                );
            }
        }
    }

    #[test]
    fn size_refusal_does_not_override_prior_possible_exposure() {
        let mut fanout = failed_frozen_fanout(TransportEndpointFailureKind::PossiblyExposed);
        fanout.mark_attempt_started_at(0, 2_000).unwrap();
        fanout
            .record_target_failure(
                0,
                TransportEndpointFailure {
                    pre_send: false,
                    endpoint: fanout.request().target.endpoints()[0].clone(),
                    reason: "relay rejected event (too-large)".into(),
                    kind: TransportEndpointFailureKind::TerminalRejected,
                    rejection_category: Some(TransportEndpointRejectionCategory::TooLarge),
                    size_class: Some(cgka_traits::EventSizeClass::Under64Kib),
                },
            )
            .unwrap();
        assert!(fanout.possible_exposure());
        assert_eq!(OversizedEvent::of_fanout(&fanout), None);
    }

    /// A publish outcome records each failed relay's adapter reason, and audit
    /// v5 keeps only reasons it knows. Every rejection category must reach v5
    /// as its category, not `unclassified` as `too-large` did, and a refusal
    /// over a known limit as a failure before exposure (mdk#2334).
    #[test]
    fn every_relay_rejection_keeps_its_category_in_audit_v5() {
        use TransportEndpointRejectionCategory as Category;

        // One list feeds both an exhaustive match and the cases, so a new
        // category fails to build until it is checked here.
        macro_rules! cases {
            ($($category:ident => $expected:literal),+ $(,)?) => {{
                let _exhaustive = |category: Category| match category {
                    $(Category::$category => ()),+
                };
                [$((Category::$category, $expected)),+]
            }};
        }
        // The adapter's reason for each category (`sdk_client.rs`
        // `relay_rejection_endpoint_failure`): an `error:` answer may have
        // reached the relay, so it is reported as an unknown acknowledgement.
        let cases = cases! {
            Duplicate => "relay_rejected_duplicate",
            Pow => "relay_rejected_pow",
            Blocked => "relay_rejected_blocked",
            RateLimited => "relay_rejected_rate_limited",
            Invalid => "relay_rejected_invalid",
            Error => "publish_acknowledgement_unknown",
            Unsupported => "relay_rejected_unsupported",
            AuthRequired => "relay_rejected_auth_required",
            Restricted => "relay_rejected_restricted",
            TooLarge => "relay_rejected_invalid",
        };
        let reasons = cases
            .into_iter()
            .map(|(category, expected)| {
                let reason = match category {
                    Category::Error => "publish acknowledgement unknown (error)".to_owned(),
                    category => format!("relay rejected event ({})", category.as_str()),
                };
                (reason, expected)
            })
            .chain([(
                TransportEndpointFailure::OVER_KNOWN_LIMIT_REASON.to_owned(),
                "publish_attempt_failed_before_exposure",
            )]);
        for (reason, expected) in reasons {
            let record = AuditRecord::new(
                None,
                AuditEventKind::PublishOutcome {
                    msg_id: "00".repeat(32),
                    artifact_kind: None,
                    target_kind: "group".into(),
                    relay_url: None,
                    accepted_relay_urls: Vec::new(),
                    failed_relays: vec![PublishRelayFailure {
                        relay_url: "wss://relay.example".into(),
                        reason: reason.clone(),
                    }],
                    required_acks: 1,
                    met_required_acks: false,
                    transport: None,
                    event_age_secs: None,
                },
            );
            let event = serde_json::to_value(audit_v5::Event::Operational(Box::new(
                audit_v5::OperationalEvent::from_audit(record),
            )))
            .unwrap();
            assert_eq!(event["failed_relays"][0]["reason"], expected, "{reason}");
        }
    }

    #[test]
    fn legacy_welcome_diagnosis_requires_an_untouched_complete_snapshot() {
        let mut request = failed_frozen_fanout(TransportEndpointFailureKind::TerminalRejected)
            .request()
            .clone();
        let recipient = MemberId::new(vec![0x66; 32]);
        let endpoint = request.target.endpoints()[0].clone();
        request.message.envelope = TransportEnvelope::Welcome {
            recipient: recipient.clone(),
        };
        request.target = TransportPublishTarget::Inbox {
            recipient,
            endpoints: vec![endpoint.clone()],
        };
        let mut fanout = DurableTransportFanout {
            id: request.message.id.clone(),
            group_id: None,
            evolution_id: None,
            exact_message: request.message.clone(),
            target: request.target,
            targets: vec![TransportFanoutTarget {
                endpoint: endpoint.clone(),
                state: TransportFanoutAttemptState::Unattempted,
                attempt_count: 0,
                last_attempt_at: None,
                failure_code: None,
            }],
            required_acks: 1,
            evolution_confirmed: false,
            possible_exposure: false,
            created_at: Timestamp(1),
            bounded_until: None,
        };
        let result = Err(TransportAdapterError::PublishEndpoints(
            cgka_traits::TransportPublishFailure::with_endpoint_failures(
                "size refusal",
                vec![TransportEndpointFailure {
                    pre_send: false,
                    endpoint,
                    reason: "relay rejected event (too-large)".into(),
                    kind: TransportEndpointFailureKind::TerminalRejected,
                    rejection_category: Some(TransportEndpointRejectionCategory::TooLarge),
                    size_class: Some(cgka_traits::EventSizeClass::Under64Kib),
                }],
            ),
        ));
        assert_eq!(
            OversizedEvent::of_first_legacy_welcome_attempt(&fanout, &result),
            Some(OversizedEvent {
                artifact: OversizedArtifact::Welcome,
                size_class: cgka_traits::EventSizeClass::Under64Kib
            })
        );
        fanout.targets[0].attempt_count = 1;
        fanout.targets[0].state = TransportFanoutAttemptState::AttemptedFailed;
        fanout.targets[0].failure_code = Some("transport_rejected".into());
        assert_eq!(
            OversizedEvent::of_first_legacy_welcome_attempt(&fanout, &result),
            None,
            "coarse prior evidence cannot be reconstructed as definite"
        );
        fanout.targets[0].attempt_count = 0;
        fanout.targets[0].state = TransportFanoutAttemptState::Unattempted;
        fanout.targets[0].failure_code = None;
        fanout.possible_exposure = true;
        assert_eq!(
            OversizedEvent::of_first_legacy_welcome_attempt(&fanout, &result),
            None
        );
        fanout.possible_exposure = false;
        let other = TransportEndpoint("wss://second.example".into());
        let TransportPublishTarget::Inbox { endpoints, .. } = &mut fanout.target else {
            unreachable!()
        };
        endpoints.push(other.clone());
        fanout.targets.push(TransportFanoutTarget {
            endpoint: other,
            state: TransportFanoutAttemptState::Unattempted,
            attempt_count: 0,
            last_attempt_at: None,
            failure_code: None,
        });
        assert_eq!(
            OversizedEvent::of_first_legacy_welcome_attempt(&fanout, &result),
            None,
            "a partial endpoint list cannot prove the original snapshot refused"
        );
    }

    fn published_message(id: u8) -> PublishedApplicationMessage {
        PublishedApplicationMessage {
            publication_observation: None,
            authority: None,
            group_id: GroupId::new(vec![id]),
            app_event_id: format!("event-{id}"),
            message_id: cgka_traits::MessageId::new(vec![id]),
            source_epoch: EpochId(u64::from(id)),
            retention: cgka_traits::app_event::AppMessageRetentionDecision::new(10, 0),
        }
    }

    #[test]
    fn extending_effects_preserves_published_application_messages() {
        let first = published_message(1);
        let second = published_message(2);
        let first_superseded = SupersededIntentReport {
            group_id: GroupId::new(vec![3]),
            commit_id: cgka_traits::MessageId::new(vec![4]),
            kind: cgka_traits::engine::SupersededIntentKind::GroupProfile,
            outcome: cgka_traits::engine::SupersededIntentOutcome::Conflict,
            reason: "profile_changed",
        };
        let second_superseded = SupersededIntentReport {
            group_id: GroupId::new(vec![5]),
            commit_id: cgka_traits::MessageId::new(vec![6]),
            kind: cgka_traits::engine::SupersededIntentKind::Invite,
            outcome: cgka_traits::engine::SupersededIntentOutcome::ReinviteRequired,
            reason: "key_packages_consumed",
        };
        let mut combined = AccountDeviceEffects {
            published_app_messages: vec![first.clone()],
            superseded_intents: vec![first_superseded.clone()],
            ..AccountDeviceEffects::default()
        };
        combined.extend(AccountDeviceEffects {
            published_app_messages: vec![second.clone()],
            superseded_intents: vec![second_superseded.clone()],
            ..AccountDeviceEffects::default()
        });

        assert_eq!(combined.published_app_messages, vec![first, second]);
        assert_eq!(
            combined.superseded_intents,
            vec![first_superseded, second_superseded]
        );
    }

    #[test]
    fn prepared_send_preserves_a_durably_queued_invite() {
        let queued = QueuedIntentRef {
            group_id: GroupId::new(vec![7]),
            intent_id: cgka_traits::MessageId::new(vec![9]),
        };
        let classified = classify_prepared_session_send(SessionEffects {
            events: Vec::new(),
            publish: Vec::new(),
            queued: vec![queued.clone()],
            pending_convergence: vec![queued.group_id.clone()],
        })
        .expect("queued acceptance is not a malformed prepared commit");

        match classified {
            PreparedSessionSend::Queued(effects) => {
                assert_eq!(effects.queued, vec![queued]);
                assert_eq!(effects.pending_convergence.len(), 1);
            }
            PreparedSessionSend::Commit(_) | PreparedSessionSend::Refused(_) => {
                panic!("queued invite must not pretend to be staged")
            }
        }
    }

    #[test]
    fn deferred_publish_boundary_rejects_non_commit_intents() {
        let group_id = GroupId::new(vec![1]);
        assert!(!supports_deferred_commit_publish(&SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: Vec::new(),
            expected_epoch: None,
            only_to_members: None,
        }));
        assert!(!supports_deferred_commit_publish(&SendIntent::Leave {
            group_id: group_id.clone(),
        }));
        assert!(supports_deferred_commit_publish(
            &SendIntent::RemoveMembers {
                group_id,
                members: Vec::new(),
            }
        ));
    }
}
