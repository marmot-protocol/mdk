//! Data-only candidate types. Use `Record::new` / `Record::from_json` to enforce
//! cross-field constraints and bounds; deserializing candidates alone is not validation.
use super::operational::OperationalEvent;
use super::primitives::*;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

// deserialize_with deliberately makes nullable fields required on the wire.
fn nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemaVersion {
    #[serde(rename = "marmot-forensics-audit/v5")]
    V5,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildProfile {
    Release,
    Debug,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Ios,
    Macos,
    Android,
    Linux,
    Windows,
    Wasm,
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Founding,
    Invite,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Construction {
    Constructed,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Retention {
    Committed,
    Failed,
    NotAttempted,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreparationStage {
    Selection,
    Validation,
    Construction,
    Retention,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreparationReason {
    NoUsableKeyPackage,
    KeyPackageInvalid,
    ConstructionFailed,
    RetentionFailed,
    StorageFailed,
    InternalFailed,
    Unclassified,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteSource {
    ResolvedInbox,
    RetainedTarget,
    ConfiguredFallback,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointStatus {
    Acknowledged,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointFailureKind {
    TerminalRejected,
    NotExposed,
    PossiblyExposed,
    RetryableUnavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionCategory {
    #[serde(rename = "duplicate")]
    Duplicate,
    #[serde(rename = "pow")]
    Pow,
    #[serde(rename = "blocked")]
    Blocked,
    #[serde(rename = "rate-limited")]
    RateLimited,
    #[serde(rename = "invalid")]
    Invalid,
    #[serde(rename = "error")]
    Error,
    #[serde(rename = "unsupported")]
    Unsupported,
    #[serde(rename = "auth-required")]
    AuthRequired,
    #[serde(rename = "restricted")]
    Restricted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Policy {
    Met,
    Unmet,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetainedState {
    Pending,
    Completed,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotStartedReason {
    NoEligibleRoute,
    RouteResolutionFailed,
    RetainedStateFailed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Acquisition {
    Live,
    History,
    LocalReplay,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnwrapResult {
    Validated,
    Rejected,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnwrapReason {
    WrongRecipient,
    InvalidSignature,
    InvalidEncoding,
    UnwrapFailed,
    InternalFailed,
    Unclassified,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinResult {
    Joined,
    Duplicate,
    Deferred,
    Rejected,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinReason {
    WrongRecipient,
    InvalidSignature,
    InvalidEncoding,
    UnsupportedFeature,
    AuthorizationFailed,
    MissingKeyPackage,
    RejoinConfirmationRequired,
    Duplicate,
    StorageFailed,
    InternalFailed,
    Unclassified,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineCommit {
    Committed,
    RolledBack,
    NotAttempted,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateCause {
    WelcomeJoin,
    InviteConfirmation,
    RetainedEventReplay,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Compute {
    Completed,
    Unchanged,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Checkpoint {
    Committed,
    FailedBeforeCommit,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InviteState {
    PendingConfirmation,
    Accepted,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateReason {
    StorageFailed,
    ProjectionFailed,
    InternalFailed,
    Unclassified,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineReason {
    Created,
    Joined,
    AuditEnabled,
    Opened,
    ActiveRefresh,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Limitation {
    MemberLimit,
    MemberIdentityInvalid,
    ByteLimit,
    AdminPolicyUnavailable,
    StateUnavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capture {
    Complete,
    Partial,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordingMode {
    OptInLocalJsonl,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordingLimitation {
    BestEffortLocalWrites,
    NoCompletenessGuarantee,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordingStopReason {
    RecordingDisabled,
    CleanRuntimeShutdown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordingLossExtent {
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppUpdateCategory {
    AccountProjectionCheckpoint,
    ContentReportBackfill,
    EventProjection,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppUpdateInputScope {
    InboundOrEngineBatch,
    LocalOperation,
    Reconciliation,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppUpdateCompute {
    Updated,
    Unchanged,
    Deferred,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppUpdateTransaction {
    Committed,
    NotCommitted,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppUpdateFailureStage {
    Projection,
    Transaction,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppUpdateFailureReason {
    Storage,
    Projection,
    Unavailable,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePublicationCategory {
    SyncSummary,
    ProjectionUpdate,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Basis {
    Founding {},
    Commit { commit_ref: EngineMessageRef },
    Unavailable {},
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Producer {
    #[serde(deserialize_with = "nullable")]
    pub mdk_revision: Option<Revision>,
    pub build_profile: BuildProfile,
    pub platform: Platform,
    #[serde(deserialize_with = "nullable")]
    pub host_build: Option<BuildToken>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointResult {
    pub endpoint_ref: EndpointRef,
    pub status: EndpointStatus,
    #[serde(deserialize_with = "nullable")]
    pub failure_kind: Option<EndpointFailureKind>,
    #[serde(deserialize_with = "nullable")]
    pub rejection_category: Option<RejectionCategory>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineMember {
    pub member_ref: MemberRef,
    #[serde(deserialize_with = "nullable")]
    pub admin: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WelcomePrepared {
    pub op_id: LocalId,
    pub recipient_ref: MemberRef,
    pub mode: Mode,
    pub basis: Basis,
    #[serde(deserialize_with = "nullable")]
    pub key_package_event_ref: Option<NostrEventRef>,
    #[serde(deserialize_with = "nullable")]
    pub outer_event_ref: Option<NostrEventRef>,
    pub construction: Construction,
    pub retention: Retention,
    #[serde(deserialize_with = "nullable")]
    pub failure_stage: Option<PreparationStage>,
    #[serde(deserialize_with = "nullable")]
    pub reason: Option<PreparationReason>,
    #[serde(deserialize_with = "nullable")]
    pub elapsed_us: Option<U64String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WelcomePublishStarted {
    pub op_id: LocalId,
    pub attempt_id: LocalId,
    pub outer_event_ref: NostrEventRef,
    pub recipient_ref: MemberRef,
    pub route_source: RouteSource,
    pub targets: Vec<EndpointRef>,
    #[serde(deserialize_with = "nullable")]
    pub target_count: Option<u32>,
    pub targets_complete: bool,
    pub required_acks: u32,
    pub accepted_before_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WelcomePublishFinished {
    pub attempt_id: LocalId,
    pub outer_event_ref: NostrEventRef,
    pub results: Vec<EndpointResult>,
    pub results_complete: bool,
    #[serde(deserialize_with = "nullable")]
    pub accepted_this_attempt_count: Option<u32>,
    #[serde(deserialize_with = "nullable")]
    pub accepted_total_count: Option<u32>,
    pub required_acks: u32,
    pub policy: Policy,
    pub retained_state: RetainedState,
    #[serde(deserialize_with = "nullable")]
    pub elapsed_us: Option<U64String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WelcomePublishNotStarted {
    pub op_id: LocalId,
    pub outer_event_ref: NostrEventRef,
    pub recipient_ref: MemberRef,
    pub reason: NotStartedReason,
    #[serde(deserialize_with = "nullable")]
    pub elapsed_us: Option<U64String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WelcomeObserved {
    pub receive_id: LocalId,
    pub outer_event_ref: NostrEventRef,
    pub acquisition: Acquisition,
    #[serde(deserialize_with = "nullable")]
    pub endpoint_ref: Option<EndpointRef>,
    #[serde(deserialize_with = "nullable")]
    pub fetch_id: Option<LocalId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WelcomeUnwrapped {
    pub receive_id: LocalId,
    pub outer_event_ref: NostrEventRef,
    pub result: UnwrapResult,
    #[serde(deserialize_with = "nullable")]
    pub rumor_event_ref: Option<NostrEventRef>,
    #[serde(deserialize_with = "nullable")]
    pub key_package_event_ref: Option<NostrEventRef>,
    #[serde(deserialize_with = "nullable")]
    pub reason: Option<UnwrapReason>,
    #[serde(deserialize_with = "nullable")]
    pub elapsed_us: Option<U64String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WelcomeJoinFinished {
    pub receive_id: LocalId,
    pub outer_event_ref: NostrEventRef,
    pub result: JoinResult,
    #[serde(deserialize_with = "nullable")]
    pub reason: Option<JoinReason>,
    #[serde(deserialize_with = "nullable")]
    pub epoch: Option<U64String>,
    pub engine_commit: EngineCommit,
    #[serde(deserialize_with = "nullable")]
    pub elapsed_us: Option<U64String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppGroupUpdateFinished {
    pub update_id: LocalId,
    pub outer_event_ref: NostrEventRef,
    pub cause: UpdateCause,
    pub compute: Compute,
    pub checkpoint: Checkpoint,
    pub invite_state: InviteState,
    #[serde(deserialize_with = "nullable")]
    pub reason: Option<UpdateReason>,
    #[serde(deserialize_with = "nullable")]
    pub elapsed_us: Option<U64String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupBaseline {
    pub reason: BaselineReason,
    #[serde(deserialize_with = "nullable")]
    pub cause_outer_event_ref: Option<NostrEventRef>,
    #[serde(deserialize_with = "nullable")]
    pub epoch: Option<U64String>,
    pub basis: Basis,
    pub members: Vec<BaselineMember>,
    #[serde(deserialize_with = "nullable")]
    pub member_count: Option<u32>,
    pub members_complete: bool,
    pub limitations: Vec<Limitation>,
    pub capture: Capture,
}

/// Account-scoped coverage of the bounded opened-group snapshot. Counts describe
/// selection and reads, not successful recorder writes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupBaselineInventory {
    pub reason: BaselineReason,
    #[serde(deserialize_with = "nullable")]
    pub eligible_group_count: Option<u32>,
    #[serde(deserialize_with = "nullable")]
    pub selected_group_count: Option<u32>,
    #[serde(deserialize_with = "nullable")]
    pub omitted_by_limit_count: Option<u32>,
    #[serde(deserialize_with = "nullable")]
    pub failed_read_count: Option<u32>,
}

/// A successful local writer open. Producer provenance and source/session identity
/// are on the enclosing record; this row makes no completeness or uptime claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordingSessionStarted {
    pub mode: RecordingMode,
    pub limitations: Vec<RecordingLimitation>,
}

/// An explicitly observed local recorder closure, never inferred from Drop.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordingSessionStopped {
    pub reason: RecordingStopReason,
}

/// Failed local record attempts since the preceding successful loss report.
/// These are observed attempt counts, not a count of missing durable rows.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordingCaptureLoss {
    pub serialization_failed_attempts: U64String,
    pub write_failed_attempts: U64String,
    pub flush_failed_attempts: U64String,
    pub extent: RecordingLossExtent,
}

/// Local app projection and persistence observation. A nullable operation ref
/// means no exact correlation with a source-local operation was available.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppUpdateOutcome {
    #[serde(deserialize_with = "nullable")]
    pub operation_ref: Option<LocalId>,
    #[serde(deserialize_with = "nullable")]
    pub message_ref: Option<EngineMessageRef>,
    pub category: AppUpdateCategory,
    pub input_scope: AppUpdateInputScope,
    pub compute: AppUpdateCompute,
    pub transaction: AppUpdateTransaction,
    #[serde(deserialize_with = "nullable")]
    pub failure_stage: Option<AppUpdateFailureStage>,
    #[serde(deserialize_with = "nullable")]
    pub failure_reason: Option<AppUpdateFailureReason>,
    pub elapsed_ms: U64String,
    pub affected_group_count: U64String,
}

/// Broadcast submission in this process, never a host receipt/display claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimePublicationOutcome {
    #[serde(deserialize_with = "nullable")]
    pub operation_ref: Option<LocalId>,
    #[serde(deserialize_with = "nullable")]
    pub message_ref: Option<EngineMessageRef>,
    pub category: RuntimePublicationCategory,
    pub attempted: U64String,
    pub accepted_by_broadcast: U64String,
    pub no_subscribers: U64String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordFields {
    pub schema_version: SchemaVersion,
    pub source_ref: SourceRef,
    pub session_id: SessionId,
    pub seq: U64String,
    pub wall_time_ms: I64String,
    pub mono_us: U64String,
    pub producer: Producer,
    #[serde(deserialize_with = "nullable")]
    pub group_ref: Option<GroupRef>,
    pub event: Event,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    AppUpdateOutcome(AppUpdateOutcome),
    RuntimePublicationOutcome(RuntimePublicationOutcome),
    RecordingSessionStarted(RecordingSessionStarted),
    RecordingSessionStopped(RecordingSessionStopped),
    RecordingCaptureLoss(RecordingCaptureLoss),
    WelcomePrepared(WelcomePrepared),
    WelcomePublishStarted(WelcomePublishStarted),
    WelcomePublishFinished(WelcomePublishFinished),
    WelcomePublishNotStarted(WelcomePublishNotStarted),
    WelcomeObserved(WelcomeObserved),
    WelcomeUnwrapped(WelcomeUnwrapped),
    WelcomeJoinFinished(WelcomeJoinFinished),
    AppGroupUpdateFinished(AppGroupUpdateFinished),
    GroupBaseline(GroupBaseline),
    GroupBaselineInventory(GroupBaselineInventory),
    Operational(Box<OperationalEvent>),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum WelcomeEvent {
    AppUpdateOutcome(AppUpdateOutcome),
    RuntimePublicationOutcome(RuntimePublicationOutcome),
    RecordingSessionStarted(RecordingSessionStarted),
    RecordingSessionStopped(RecordingSessionStopped),
    RecordingCaptureLoss(RecordingCaptureLoss),
    WelcomePrepared(WelcomePrepared),
    WelcomePublishStarted(WelcomePublishStarted),
    WelcomePublishFinished(WelcomePublishFinished),
    WelcomePublishNotStarted(WelcomePublishNotStarted),
    WelcomeObserved(WelcomeObserved),
    WelcomeUnwrapped(WelcomeUnwrapped),
    WelcomeJoinFinished(WelcomeJoinFinished),
    AppGroupUpdateFinished(AppGroupUpdateFinished),
    GroupBaseline(GroupBaseline),
    GroupBaselineInventory(GroupBaselineInventory),
}

impl Serialize for Event {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let welcome = match self {
            Event::AppUpdateOutcome(e) => WelcomeEvent::AppUpdateOutcome(e.clone()),
            Event::RuntimePublicationOutcome(e) => {
                WelcomeEvent::RuntimePublicationOutcome(e.clone())
            }
            Event::RecordingSessionStarted(e) => WelcomeEvent::RecordingSessionStarted(e.clone()),
            Event::RecordingSessionStopped(e) => WelcomeEvent::RecordingSessionStopped(e.clone()),
            Event::RecordingCaptureLoss(e) => WelcomeEvent::RecordingCaptureLoss(e.clone()),
            Event::WelcomePrepared(e) => WelcomeEvent::WelcomePrepared(e.clone()),
            Event::WelcomePublishStarted(e) => WelcomeEvent::WelcomePublishStarted(e.clone()),
            Event::WelcomePublishFinished(e) => WelcomeEvent::WelcomePublishFinished(e.clone()),
            Event::WelcomePublishNotStarted(e) => WelcomeEvent::WelcomePublishNotStarted(e.clone()),
            Event::WelcomeObserved(e) => WelcomeEvent::WelcomeObserved(e.clone()),
            Event::WelcomeUnwrapped(e) => WelcomeEvent::WelcomeUnwrapped(e.clone()),
            Event::WelcomeJoinFinished(e) => WelcomeEvent::WelcomeJoinFinished(e.clone()),
            Event::AppGroupUpdateFinished(e) => WelcomeEvent::AppGroupUpdateFinished(e.clone()),
            Event::GroupBaseline(e) => WelcomeEvent::GroupBaseline(e.clone()),
            Event::GroupBaselineInventory(e) => WelcomeEvent::GroupBaselineInventory(e.clone()),
            Event::Operational(e) => return e.serialize(serializer),
        };
        welcome.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Event {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        let tag = value
            .get("type")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| serde::de::Error::custom("missing event type"))?;
        if matches!(
            tag,
            "app_update_outcome"
                | "runtime_publication_outcome"
                | "recording_session_started"
                | "recording_session_stopped"
                | "recording_capture_loss"
                | "welcome_prepared"
                | "welcome_publish_started"
                | "welcome_publish_finished"
                | "welcome_publish_not_started"
                | "welcome_observed"
                | "welcome_unwrapped"
                | "welcome_join_finished"
                | "app_group_update_finished"
                | "group_baseline"
                | "group_baseline_inventory"
        ) {
            let e: WelcomeEvent =
                serde_json::from_value(value).map_err(serde::de::Error::custom)?;
            Ok(match e {
                WelcomeEvent::AppUpdateOutcome(e) => Event::AppUpdateOutcome(e),
                WelcomeEvent::RuntimePublicationOutcome(e) => Event::RuntimePublicationOutcome(e),
                WelcomeEvent::RecordingSessionStarted(e) => Event::RecordingSessionStarted(e),
                WelcomeEvent::RecordingSessionStopped(e) => Event::RecordingSessionStopped(e),
                WelcomeEvent::RecordingCaptureLoss(e) => Event::RecordingCaptureLoss(e),
                WelcomeEvent::WelcomePrepared(e) => Event::WelcomePrepared(e),
                WelcomeEvent::WelcomePublishStarted(e) => Event::WelcomePublishStarted(e),
                WelcomeEvent::WelcomePublishFinished(e) => Event::WelcomePublishFinished(e),
                WelcomeEvent::WelcomePublishNotStarted(e) => Event::WelcomePublishNotStarted(e),
                WelcomeEvent::WelcomeObserved(e) => Event::WelcomeObserved(e),
                WelcomeEvent::WelcomeUnwrapped(e) => Event::WelcomeUnwrapped(e),
                WelcomeEvent::WelcomeJoinFinished(e) => Event::WelcomeJoinFinished(e),
                WelcomeEvent::AppGroupUpdateFinished(e) => Event::AppGroupUpdateFinished(e),
                WelcomeEvent::GroupBaseline(e) => Event::GroupBaseline(e),
                WelcomeEvent::GroupBaselineInventory(e) => Event::GroupBaselineInventory(e),
            })
        } else {
            Ok(Event::Operational(Box::new(
                OperationalEvent::from_wire(value).map_err(serde::de::Error::custom)?,
            )))
        }
    }
}
