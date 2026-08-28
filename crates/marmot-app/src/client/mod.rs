use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use cgka_session::{PublishWork, SessionEffects};
use cgka_traits::agent_text_stream::{
    AGENT_TEXT_STREAM_EXPORTER_CACHE_KEY, AgentTextStreamQuicPolicyV1,
};
use cgka_traits::app_components::{
    AppComponentData, AppComponentSet, BLOSSOM_LOCATOR_KIND_V1, BlobStoreEndpointV1,
    BlobStoreEndpointV2, ENCRYPTED_MEDIA_FORMAT_V1, ENCRYPTED_MEDIA_FORMAT_V2,
    EncryptedMediaPolicyV1, EncryptedMediaPolicyV2, GROUP_ADMIN_POLICY_COMPONENT_ID,
    GROUP_AVATAR_URL_COMPONENT_ID, GROUP_BLOSSOM_IMAGE_COMPONENT_ID,
    GROUP_ENCRYPTED_MEDIA_EXPORTER_CACHE_KEY, GROUP_MESSAGE_RETENTION_COMPONENT_ID,
    GROUP_PROFILE_COMPONENT_ID, NOSTR_ROUTING_COMPONENT_ID, encode_nostr_routing_v1,
};
use cgka_traits::app_event::MarmotAppEvent as MarmotInnerEvent;
use cgka_traits::capabilities::GroupCapabilities;
use cgka_traits::engine::{CreateGroupRequest, KeyPackage, SendIntent};
use cgka_traits::group::ProtocolProfile;
use cgka_traits::transport::TransportEnvelope;
use cgka_traits::{EngineError, GroupId, MessageId, SecretBytes, TransportEndpoint};
#[cfg(test)]
use futures::StreamExt;
use marmot_account::{
    AccountError, CompletedWelcomePublishTask, PreparedSessionSend, PreparedWelcomePublishTask,
};
use marmot_forensics::AuditEventContext;
use nostr::NostrSigner;
use rand::RngCore;
use rand::rngs::OsRng;
use storage_sqlite::{PreparedGroupImageUploadRecord, PreparedGroupImageUploadState};
use zeroize::Zeroizing;

use crate::app_telemetry::AppPerformanceOperation;
use crate::groups::{
    EventGroupProjection, GroupConfirmationProjection, add_group, fail_if_publish_failed,
    publish_failure_error, send_summary_from_effects, validate_group_profile,
};
use crate::ids::{admin_pubkey_from_account_id_hex, admin_pubkey_from_member_id};
use crate::media::{
    DEFAULT_BLOSSOM_SERVER_URLS, EncryptedMediaVersion, MediaOperationPolicy,
    download_encrypted_media, fetch_group_image, is_loopback_http_endpoint,
    prepare_group_image_upload, upload_encrypted_media, upload_group_image,
    upload_prepared_group_image,
};
use crate::messages::{AppMessageIntent, build_inner_event, encode_inner_event};
use crate::notifications;
use crate::{
    AccountState, AgentOperationEventRequest, AgentTextStreamFinishRequest, AppBlobEndpoint,
    AppCreateGroupOptions, AppDisbandRequest, AppError, AppGroupAdminPolicyComponent,
    AppGroupAvatarUrlComponent, AppGroupEncryptedMediaComponent, AppGroupImageComponent,
    AppGroupImageInput, AppGroupMemberRecord, AppGroupMessageRetentionComponent, AppGroupMlsState,
    AppGroupRecord, AppInitialGroupImage, AppPerformanceTelemetry, AppPreparedGroupImageUpload,
    AppPreparedGroupImageUploadState, AppQuarantinedGroup, AppRoutingState, AppRuntime,
    AppTransportRouting, CanonicalCreatedGroup, GroupInviteDeclineResult, MarmotApp,
    MarmotRelayPlane, MarmotRelayPlaneAccountAdapter, MediaAttachmentReference,
    MediaDownloadResult, MediaUploadRequest, MediaUploadResult, PendingWelcomeDelivery,
    SelfMembership, SendSummary, remember_seen_event, unix_now_seconds,
};

mod audit;
pub(crate) mod epoch_stall;
mod projection;
mod push;
mod retention;
mod sync;

use epoch_stall::EpochStallDetector;
use push::notification_trigger_for_intent;
// Re-exported so the crate's `tests` module can keep calling
// `client::is_own_relay_echo`; the function itself lives in `client::sync`.
#[cfg(test)]
pub(crate) use sync::epoch_stall_now_ms;
#[cfg(test)]
pub(crate) use sync::is_own_relay_echo;
pub(crate) use sync::{
    ConvergenceScheduleState, DeliveryOverflowRecoveryOutcome, EpochBackfillRunOutcome,
};

#[cfg(test)]
const CREATE_GROUP_LOOKUP_CONCURRENCY: usize = 8;
#[cfg(test)]
const INVITE_LOOKUP_CONCURRENCY: usize = CREATE_GROUP_LOOKUP_CONCURRENCY;

pub(crate) enum UnpublishedWelcomeKind {
    Founding {
        effects: SessionEffects,
        welcome_intents: Vec<String>,
    },
    Invite {
        welcomes: Vec<cgka_traits::transport::TransportMessage>,
        welcome_intents: Vec<String>,
    },
}

pub(crate) struct UnpublishedWelcomeDelivery {
    group_id: GroupId,
    audit_context: AuditEventContext,
    kind: UnpublishedWelcomeKind,
}

pub(crate) struct PendingWelcomeDeliveryRecovery {
    welcome_ids: Vec<String>,
    publish: PreparedWelcomePublishTask,
}

pub(crate) struct CompletedWelcomeDeliveryRecovery {
    welcome_ids: Vec<String>,
    publish: CompletedWelcomePublishTask,
}

impl PendingWelcomeDeliveryRecovery {
    pub(crate) fn message_ids(&self) -> &[MessageId] {
        self.publish.message_ids()
    }

    pub(crate) async fn run(self) -> CompletedWelcomeDeliveryRecovery {
        CompletedWelcomeDeliveryRecovery {
            welcome_ids: self.welcome_ids,
            publish: self.publish.run().await,
        }
    }
}

pub(crate) struct EncryptedMediaUploadHttp {
    request: MediaUploadRequest,
    source_epoch: u64,
    media_secret: SecretBytes,
    nostr_signer: Arc<dyn NostrSigner>,
    version: EncryptedMediaVersion,
    default_endpoints: Vec<AppBlobEndpoint>,
    allowed_locator_kinds: Vec<String>,
    allow_loopback_http: bool,
}

impl EncryptedMediaUploadHttp {
    pub(crate) async fn run(self) -> Result<MediaUploadResult, AppError> {
        upload_encrypted_media(
            self.request,
            self.source_epoch,
            self.media_secret.as_ref(),
            self.nostr_signer.as_ref(),
            MediaOperationPolicy {
                version: self.version,
                default_endpoints: &self.default_endpoints,
                allowed_locator_kinds: &self.allowed_locator_kinds,
                allow_loopback_http: self.allow_loopback_http,
            },
        )
        .await
    }
}

pub(crate) struct EncryptedMediaUploadFinish {
    group_id: GroupId,
    source_epoch: u64,
    media_secret: SecretBytes,
    should_send: bool,
    caption: Option<String>,
}

pub(crate) struct EncryptedMediaDownloadHttp {
    reference: MediaAttachmentReference,
    media_secret: SecretBytes,
    default_blob_endpoints: Vec<AppBlobEndpoint>,
    allowed_locator_kinds: Vec<String>,
    allow_loopback: bool,
}

impl EncryptedMediaDownloadHttp {
    pub(crate) async fn run(self) -> Result<MediaDownloadResult, AppError> {
        download_encrypted_media(
            self.reference,
            self.media_secret.as_ref(),
            &self.default_blob_endpoints,
            &self.allowed_locator_kinds,
            self.allow_loopback,
        )
        .await
    }
}

pub(crate) struct GroupImageDownloadHttp {
    image_hash_hex: String,
    image_key_hex: String,
    image_nonce_hex: String,
    media_type: String,
}

pub(crate) struct PreparedGroupImageUploadHttp {
    encrypted_blob: Vec<u8>,
    image_hash_hex: String,
    upload_secret: Zeroizing<Vec<u8>>,
    server: Option<String>,
    allow_loopback_http: bool,
}

impl PreparedGroupImageUploadHttp {
    pub(crate) async fn run(self) -> Result<(), AppError> {
        upload_prepared_group_image(
            self.encrypted_blob,
            &self.image_hash_hex,
            self.upload_secret,
            self.server.as_deref(),
            self.allow_loopback_http,
        )
        .await
    }
}

pub(crate) enum PreparedGroupImageUploadStart {
    Complete(AppPreparedGroupImageUpload),
    Http(PreparedGroupImageUploadHttp),
}

pub(crate) enum InitialGroupImageSource {
    Inline(AppInitialGroupImage),
    Prepared {
        upload_id: String,
        component_data: Vec<u8>,
    },
}

impl GroupImageDownloadHttp {
    pub(crate) async fn run(self) -> Result<Vec<u8>, AppError> {
        fetch_group_image(
            &self.image_hash_hex,
            &self.image_key_hex,
            &self.image_nonce_hex,
            &self.media_type,
            None,
        )
        .await
    }
}

/// Run independent async work with fixed fan-out while returning results in
/// input order. All started work finishes before deterministic error selection,
/// so completion timing cannot change which member error the caller observes.
#[cfg(test)]
async fn collect_bounded_ordered<I, F, T, E>(work: I, limit: usize) -> Result<Vec<T>, E>
where
    I: IntoIterator<Item = F>,
    F: std::future::Future<Output = Result<T, E>>,
{
    let mut results = futures::stream::iter(work.into_iter().enumerate())
        .map(|(index, future)| async move { (index, future.await) })
        .buffer_unordered(limit.max(1))
        .collect::<Vec<_>>()
        .await;
    results.sort_unstable_by_key(|(index, _)| *index);
    results.into_iter().map(|(_, result)| result).collect()
}

fn prepared_group_image_status(
    record: &PreparedGroupImageUploadRecord,
) -> AppPreparedGroupImageUpload {
    AppPreparedGroupImageUpload {
        upload_id: record.upload_id.clone(),
        state: match record.state {
            PreparedGroupImageUploadState::Staged => AppPreparedGroupImageUploadState::Staged,
            PreparedGroupImageUploadState::Uploaded => AppPreparedGroupImageUploadState::Uploaded,
            PreparedGroupImageUploadState::Failed => AppPreparedGroupImageUploadState::Failed,
            PreparedGroupImageUploadState::Consumed => AppPreparedGroupImageUploadState::Consumed,
        },
        attempt_count: record.attempt_count,
        last_error_kind: record.last_error_kind.clone(),
        group_id_hex: record.group_id_hex.clone(),
    }
}

/// Outcome of one [`AppClient::refresh_group_routes`] pass, separating the
/// in-memory routing-table delta from durable-state mutation: only the latter
/// obligates a state save, only the former obligates a relay-subscription
/// refresh.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct GroupRouteRefresh {
    /// The in-memory routing table changed; relay subscriptions need a
    /// `sync_runtime_groups` refresh.
    pub(crate) routing_changed: bool,
    /// `prune_prior_nostr_routes` removed retired prior routes from persisted
    /// group state; a save is required for the retirement to stick.
    pub(crate) state_pruned: bool,
}

pub struct AppClient {
    pub(crate) app: MarmotApp,
    pub(crate) runtime: AppRuntime,
    // Struct fields drop in declaration order. Keep the engine-owning runtime
    // before this guard so ownership is released only after engine teardown.
    pub(crate) _session_guard: crate::AppAccountSessionGuard,
    pub(crate) adapter: MarmotRelayPlaneAccountAdapter,
    pub(crate) routing: AppTransportRouting,
    pub(crate) relay_plane: MarmotRelayPlane,
    pub(crate) transport_signer: Arc<dyn nostr::NostrSigner>,
    pub(crate) state: AccountState,
    /// O(1) membership index over `state.seen_events`, kept in lockstep by
    /// `remember_seen_event` (which removes pruned ring entries from it).
    /// Derived state: rebuilt from the ordered ring at construction and never
    /// persisted. Before this index existed, every inbound delivery and every
    /// publish-report batch rebuilt a `HashSet` from the full 16k-entry ring.
    pub(crate) seen_events_index: HashSet<String>,
    /// Number of ids at the tail of `state.seen_events` observed since the last
    /// successful account-projection checkpoint. The count saturates at the
    /// bounded ring length, so even a catch-up batch larger than the window
    /// persists only the final retained ids. It is cleared only after commit.
    pub(crate) pending_seen_event_count: usize,
    /// Exact group projections changed since the last successful checkpoint.
    /// Live saves replace only these groups; full snapshot replacement is
    /// reserved for import/rebuild paths outside the account worker.
    pub(crate) pending_group_projection_updates: HashSet<String>,
    /// Group-system timeline rows synthesized during the most recent publish
    /// path. The runtime account worker drains this after each command and
    /// broadcasts `ProjectionUpdated` so live timeline subscriptions refresh.
    pub(crate) pending_projection_updates: Vec<crate::AppProjectionUpdate>,
    /// Sync summary for group events the engine applied as a side effect of an
    /// outbound send: a send that lands while inbound convergence input is
    /// retained folds those commits before publishing, so its effects can carry
    /// peer `GroupStateChanged` / `EpochChanged` events. The runtime account
    /// worker drains this after each command and broadcasts it like an inbound
    /// sync summary so live chat-list/group-state subscriptions observe the
    /// applied commits.
    pub(crate) pending_applied_sync_summary: crate::SyncSummary,
    /// App-visible outputs ingested during a sync whose account-projection
    /// checkpoint failed. A retained client keeps the matching projected state
    /// and outbox acknowledgements, then returns this summary after its next
    /// successful checkpoint. A reopened client recovers the same outputs from
    /// the durable engine outbox instead.
    pub(crate) pending_failed_sync_summary: crate::SyncSummary,
    /// Epoch-stall escalations the detector has raised but no caller has been
    /// handed yet.
    ///
    /// The detector latches `escalated` one-shot per unrecovered run, so an
    /// escalation dropped by a later `?` on the recording pass is never raised
    /// again. Escalations therefore land here and move onto either a successful
    /// summary or a partial-progress failure before a managed client is rebuilt
    /// (see `Self::drain_epoch_stall_escalations`).
    pub(crate) pending_epoch_stall_escalations: Vec<crate::EpochStallEscalation>,
    pub(crate) pending_convergence_groups: HashSet<GroupId>,
    /// Batch-start local-deletion frontiers crossed by authenticated fresh
    /// activity. They remain pending until the crossing projection and marker
    /// clears commit in the same account-state transaction.
    pub(crate) pending_local_group_deletion_frontier_clears: HashMap<String, u64>,
    /// Authenticated application deliveries observed by this client but not yet
    /// acknowledged on the durable engine-to-app outbox. The acknowledgement is
    /// committed with the account projection and any frontier clear.
    pub(crate) pending_application_event_acks: HashSet<MessageId>,
    /// A live ingest changed the in-memory transport routing table after its
    /// durable projection was committed. The account worker publishes the
    /// resulting app summary before it asks the relay plane to rebuild its
    /// ordinary group subscriptions; failures remain armed here for bounded
    /// background retry instead of turning the already-applied ingest into an
    /// apparent receive failure.
    pub(crate) pending_runtime_group_subscription_refresh: bool,
    /// Last transport cursor promoted by a completed drain checkpoint. Live
    /// one-at-a-time worker ingests may advance `state` for diagnostics, but
    /// they persist this older safe floor until a drain has observed any
    /// process-local overflow fence/control record.
    pub(crate) checkpointed_transport_timestamp: Option<u64>,
    /// Durable account-wide marker set when the bounded relay-plane queue
    /// omits a delivery. While true, every subscription rebuild is unfloored
    /// and EOSE-gated recovery must complete before the cursor is trusted.
    pub(crate) delivery_overflow_recovery_pending: bool,
    pub(crate) delivery_overflow_recovery_marker_token: Option<u64>,
    /// Unit-test fault injection for the account-open replay path. This keeps
    /// the live protocol group intact while exercising a missing best-effort
    /// app projection.
    #[cfg(test)]
    pub(crate) force_event_group_projection_unavailable: bool,
    /// Welcomes queued for re-delivery during the most recent create/invite.
    /// The runtime account worker drains this after the command and broadcasts a
    /// `WelcomeDeliveryPending` event so callers learn a member is unjoinable
    /// without polling (mdk#352).
    pub(crate) pending_welcome_delivery_events: Vec<PendingWelcomeDelivery>,
    /// Canonical create/invite work whose Welcome fanout has not run yet.
    /// The managed account worker replies first, then drives this delivery.
    pub(crate) unpublished_welcome_delivery: Option<UnpublishedWelcomeDelivery>,
    /// Per-group detector for the epoch-gap backfill (commit-loss recovery): it
    /// counts the distinct undecryptable messages a group accumulates at a
    /// stalled epoch. Ephemeral session state, like the pending sets above.
    pub(crate) epoch_stall: EpochStallDetector,
    /// Earliest instant an automatic seam may retry a pending epoch-gap
    /// backfill whose last attempt could not confirm its replay.
    ///
    /// Process-local on purpose: the intent it paces is durable, so a restart
    /// costs at most one unpaced attempt, while persisting a monotonic deadline
    /// would mean durable schema for a scheduling hint.
    pub(crate) epoch_backfill_retry_not_before: Option<Instant>,
    /// Armed epoch-gap recovery intent awaiting its account-wide replay.
    pub(crate) pending_epoch_backfill: Option<epoch_stall::PendingEpochBackfill>,
    /// Additional armed intents queued behind [`Self::pending_epoch_backfill`]
    /// when a replay failure must not overwrite a newer arm minted in flight.
    pub(crate) queued_epoch_backfills:
        std::collections::VecDeque<epoch_stall::PendingEpochBackfill>,
    /// Temporary full-history subscriptions installed only while a post-join
    /// maintenance obligation is waiting for its first relay EOSE.
    pub(crate) post_join_maintenance_subscriptions:
        HashMap<GroupId, (String, cgka_traits::TransportGroupSubscription)>,
    /// Per-group (in-memory) epoch at which the warm pass last confirmed the
    /// authoritative encrypted-media component is NOT required. A group's
    /// signed component can only change with a commit, and a commit always
    /// advances the epoch, so an unchanged epoch means the negative answer is
    /// still authoritative — the per-sync warm pass skips the expensive
    /// `MlsGroup::load` re-check for those groups (mdk#1380). Derived state
    /// only: never persisted, rebuilt by the first pass after open, and
    /// entries are recorded only on successful lookups so transient failures
    /// keep re-checking on the next pass.
    pub(crate) encrypted_media_not_required_epochs: HashMap<String, u64>,
    /// Count of checkpoint route recomputations actually executed (mdk#1380
    /// harness observability: an idle catch-up pass must skip the second
    /// per-sync `refresh_group_routes` because no delivery or drained effect
    /// could have changed routing since the sync-start pass).
    pub(crate) checkpoint_route_refresh_recomputes: u64,
}

/// Cross the point-of-no-return for a current-profile group mutation without
/// allowing repairable follow-up work to turn a canonical change into an
/// apparent failure. Returning `Err` after that boundary encourages a caller
/// to retry an already-applied create or invite. The engine's retained outbound
/// Welcome index and account-open reconciliation repair any missed projection
/// work.
fn recover_post_canonical_result<T: Default>(
    method: &'static str,
    result: Result<T, AppError>,
) -> T {
    match result {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(
                target: "marmot_app::client",
                method = method,
                error_kind = error.privacy_safe_kind(),
                "canonical group mutation outpaced repairable follow-up work"
            );
            T::default()
        }
    }
}

/// A point-in-time copy of the live session's read-only group projections
/// (`groups`, `members`, `group_mls_state`, `quarantined_groups`).
///
/// The account worker captures this from the live session and uses it to answer
/// read commands while a relay catch-up runs in the background. The catch-up
/// future holds `&mut AppClient`, so concurrent reads cannot touch the live
/// session and are served from this snapshot instead.
/// MLS membership/epoch only change on a committed group operation, which the
/// catch-up surfaces via `GroupStateUpdated` so subscribers re-read once it
/// lands. Storage-owned self-membership is refreshed separately when a roster
/// is served, so an observed departure during catch-up is not hidden by this
/// snapshot. The snapshot is only used until catch-up completes.
///
/// Capture is atomic: if any known group's member or MLS projection cannot be
/// read, the whole snapshot fails and the worker defers reads to live state
/// after catch-up instead of misreporting a degraded known group as unknown.
#[derive(Default)]
pub(crate) struct GroupReadSnapshot {
    groups: HashMap<GroupId, AppGroupRecord>,
    members: HashMap<GroupId, Vec<AppGroupMemberRecord>>,
    mls_state: HashMap<GroupId, AppGroupMlsState>,
    quarantined: Vec<AppQuarantinedGroup>,
}

impl GroupReadSnapshot {
    pub(crate) fn members(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<AppGroupMemberRecord>, AppError> {
        self.members
            .get(group_id)
            .cloned()
            .ok_or_else(|| AppError::UnknownGroup(hex::encode(group_id.as_slice())))
    }

    pub(crate) fn member_ids_page(
        &self,
        group_ids: &[GroupId],
    ) -> Result<Vec<crate::AppGroupMemberIds>, AppError> {
        group_ids
            .iter()
            .map(|group_id| {
                let members = self.members(group_id)?;
                let admin_ids_hex = self
                    .groups
                    .get(group_id)
                    .ok_or_else(|| AppError::UnknownGroup(hex::encode(group_id.as_slice())))?
                    .admin_policy
                    .admins
                    .clone();
                Ok(crate::AppGroupMemberIds {
                    group_id_hex: hex::encode(group_id.as_slice()),
                    member_ids_hex: members
                        .into_iter()
                        .map(|member| member.member_id_hex)
                        .collect(),
                    admin_ids_hex,
                })
            })
            .collect()
    }

    pub(crate) fn group_mls_state(&self, group_id: &GroupId) -> Result<AppGroupMlsState, AppError> {
        self.mls_state
            .get(group_id)
            .cloned()
            .ok_or_else(|| AppError::UnknownGroup(hex::encode(group_id.as_slice())))
    }

    pub(crate) fn group_roster(
        &self,
        group_id: &GroupId,
    ) -> Result<crate::groups::AppGroupRosterSession, AppError> {
        Ok(crate::groups::AppGroupRosterSession {
            group_record: self
                .groups
                .get(group_id)
                .cloned()
                .ok_or_else(|| AppError::UnknownGroup(hex::encode(group_id.as_slice())))?,
            members: self.members(group_id)?,
            mls_state: self.group_mls_state(group_id)?,
        })
    }

    pub(crate) fn quarantined_groups(&self) -> Vec<AppQuarantinedGroup> {
        self.quarantined.clone()
    }
}

struct ObservedHumanActionAudit {
    action: &'static str,
    fields: Vec<&'static str>,
    component_ids: Vec<u16>,
    target_count: Option<u64>,
    message_ids: Vec<String>,
    from_epoch: Option<u64>,
    to_epoch: Option<u64>,
}

impl ObservedHumanActionAudit {
    fn source(
        action: &'static str,
        fields: Vec<&'static str>,
        component_ids: Vec<u16>,
        source_message_id_hex: &str,
    ) -> Self {
        Self {
            action,
            fields,
            component_ids,
            target_count: None,
            message_ids: vec![source_message_id_hex.to_string()],
            from_epoch: None,
            to_epoch: None,
        }
    }

    fn messages(
        action: &'static str,
        fields: Vec<&'static str>,
        component_ids: Vec<u16>,
        message_ids: Vec<String>,
    ) -> Self {
        Self {
            action,
            fields,
            component_ids,
            target_count: None,
            message_ids,
            from_epoch: None,
            to_epoch: None,
        }
    }

    fn with_target_count(mut self, target_count: u64) -> Self {
        self.target_count = Some(target_count);
        self
    }

    fn with_epoch_range(mut self, from_epoch: Option<u64>, to_epoch: Option<u64>) -> Self {
        self.from_epoch = from_epoch;
        self.to_epoch = to_epoch;
        self
    }
}

fn record_app_performance(
    telemetry: Option<&AppPerformanceTelemetry>,
    operation: AppPerformanceOperation,
    duration: Duration,
    success: bool,
) {
    if let Some(telemetry) = telemetry {
        telemetry.record(operation, duration, success);
    }
}

impl AppClient {
    /// Persist the exact first KeyPackage and signed publication artifact
    /// without activating transport or contacting a relay.
    pub(crate) async fn prepare_initial_key_package(
        &mut self,
        endpoints: Vec<TransportEndpoint>,
    ) -> Result<KeyPackage, AppError> {
        Ok(self.runtime.prepare_fresh_key_package(endpoints).await?)
    }

    pub async fn publish_key_package(&mut self) -> Result<KeyPackage, AppError> {
        self.app
            .ensure_local_account_relay_lists(&self.state.label)
            .await?;
        self.refresh_routing()?;
        self.runtime.activate_transport(None).await?;
        self.publish_key_package_from_lifecycle().await
    }

    /// Publish the exact lifecycle-owned KeyPackage authorized by the durable
    /// setup journal without installing receive subscriptions first. The
    /// managed worker runs this only for `KeyPackagePublicationStarted`; all
    /// general publication continues through [`Self::publish_key_package`].
    pub(crate) async fn publish_setup_key_package(&mut self) -> Result<KeyPackage, AppError> {
        self.app
            .ensure_local_account_relay_lists(&self.state.label)
            .await?;
        self.refresh_routing()?;
        self.publish_key_package_from_lifecycle().await
    }

    async fn publish_key_package_from_lifecycle(&mut self) -> Result<KeyPackage, AppError> {
        let lifecycle = self.runtime.key_package_maintenance_status()?;
        if lifecycle.as_ref().is_some_and(|lifecycle| {
            lifecycle.pending_replacement.is_some() || lifecycle.current_key_package.is_none()
        }) {
            // A prior ambiguous or rejected setup attempt already owns exact
            // signed bytes and private material, or a journaled setup owns a
            // stable slot that has not promoted a current package yet. Resume
            // or prepare that replacement; republish_key_package deliberately
            // rejects pending rotations and requires a current package.
            Ok(self.runtime.publish_fresh_key_package().await?)
        } else {
            Ok(self.runtime.republish_key_package().await?)
        }
    }

    pub fn maintenance_status(
        &self,
        group_id: &GroupId,
    ) -> Result<cgka_traits::GroupMaintenanceStatus, AppError> {
        self.ensure_group(group_id)?;
        Ok(self.runtime.maintenance_status(group_id)?)
    }

    pub fn key_package_maintenance_status(
        &self,
    ) -> Result<Option<cgka_traits::KeyPackageLifecycleState>, AppError> {
        Ok(self.runtime.key_package_maintenance_status()?)
    }

    pub fn durably_owned_key_packages(&self) -> Result<Vec<KeyPackage>, AppError> {
        Ok(self.runtime.durably_owned_key_packages()?)
    }

    pub fn schedule_manual_self_update(&mut self, group_id: &GroupId) -> Result<String, AppError> {
        self.ensure_group(group_id)?;
        Ok(hex::encode(
            self.runtime
                .schedule_manual_self_update(group_id)?
                .as_slice(),
        ))
    }

    pub fn periodic_maintenance_policy(
        &self,
    ) -> Result<cgka_traits::PeriodicMaintenancePolicy, AppError> {
        Ok(self.runtime.periodic_maintenance_policy()?)
    }

    pub fn set_periodic_maintenance_policy(
        &self,
        policy: cgka_traits::PeriodicMaintenancePolicy,
    ) -> Result<(), AppError> {
        Ok(self.runtime.set_periodic_maintenance_policy(policy)?)
    }

    pub fn pause_maintenance(&mut self) {
        self.runtime.pause_maintenance();
    }

    pub fn resume_maintenance(&mut self) {
        self.runtime.resume_maintenance();
    }

    pub async fn run_due_maintenance(&mut self) -> Result<crate::MaintenanceRunSummary, AppError> {
        if self.app.cursor_persistence() == crate::CursorPersistence::Frozen {
            self.runtime.sweep_expired_key_package_private_material()?;
            let summary = self
                .runtime
                .maintenance_run_summary(&marmot_account::AccountDeviceEffects::default())?;
            return Ok(maintenance_run_summary_from_account(summary));
        }
        let effects = self.runtime.run_due_maintenance().await?;
        self.observe_recovery_evidence_then_summarize_maintenance(&effects)
    }

    /// Observe one maintenance tick's recovery evidence, then summarize the
    /// tick — split from the tick itself so the pair is exercisable against a
    /// given batch of effects.
    ///
    /// A maintenance tick publishes: it drains a recovered staged evolution and
    /// confirms it, so this batch can carry an `EpochChanged` for a group the
    /// stall detector is tracking. That passage is one-shot in these effects and
    /// reaches the detector nowhere else — a tick's own recovery is invisible to
    /// every delivery-driven seam.
    ///
    /// Hence the order the name states, and the reason this is one function
    /// rather than two calls at the seam: the summary build reads storage and so
    /// can return early, and an `Err` reached before the observation would drop
    /// that passage for good. It is the same hazard
    /// [`Self::observe_recovery_evidence_then_fail_if_publish_failed`] exists
    /// for, and it gets the same answer — a name that fixes the order.
    ///
    /// A tick can also *arm*, from a `TransportObjectResourceRefused` riding the
    /// same batch. Nothing executes that arm here: the worker does not run the
    /// pending backfill after a tick, so the intent waits for the next
    /// delivery-driven seam to drain it. The arm and its audit row are durable
    /// meanwhile, so the wait costs latency, not the recovery.
    pub(crate) fn observe_recovery_evidence_then_summarize_maintenance(
        &mut self,
        effects: &marmot_account::AccountDeviceEffects,
    ) -> Result<crate::MaintenanceRunSummary, AppError> {
        self.observe_recovery_evidence(effects);
        self.queue_own_group_system_projection_updates(effects);
        let summary = self.runtime.maintenance_run_summary(effects)?;
        Ok(maintenance_run_summary_from_account(summary))
    }

    pub(crate) fn key_package_maintenance_requires_catch_up(&self) -> bool {
        self.app.cursor_persistence() == crate::CursorPersistence::Advance
            && self
                .runtime
                .key_package_maintenance_requires_catch_up()
                .unwrap_or(false)
    }

    /// Install, poll, and retire temporary post-join full-history
    /// subscriptions. A restart reconstructs this ephemeral map from durable
    /// CatchUp obligations; the EOSE deadline itself remains persisted.
    pub(crate) async fn advance_post_join_maintenance_subscriptions(
        &mut self,
    ) -> Result<(), AppError> {
        if self.app.cursor_persistence() == crate::CursorPersistence::Frozen
            || self.runtime.maintenance_is_paused()
        {
            let active = self
                .post_join_maintenance_subscriptions
                .iter()
                .map(|(group_id, (_, route))| (group_id.clone(), route.clone()))
                .collect::<Vec<_>>();
            for (group_id, route) in active {
                if let Err(_error) = self
                    .adapter
                    .remove_group_maintenance_subscription(&route)
                    .await
                {
                    tracing::warn!(
                        target: "marmot_app::maintenance",
                        method = "advance_post_join_maintenance_subscriptions",
                        error_kind = "subscription_remove_failed",
                        "could not remove paused post-join maintenance subscription"
                    );
                    continue;
                }
                self.post_join_maintenance_subscriptions.remove(&group_id);
            }
            return Ok(());
        }
        let routes = self.routing.snapshot().group_routes;
        let mut waiting = HashSet::new();

        for group in self.state.groups.clone() {
            let group_id = match hex::decode(&group.group_id_hex) {
                Ok(bytes) => GroupId::new(bytes),
                Err(_) => {
                    tracing::warn!(
                        target: "marmot_app::maintenance",
                        method = "advance_post_join_maintenance_subscriptions",
                        error_kind = "malformed_route_identifier",
                        "skipping malformed post-join maintenance group"
                    );
                    continue;
                }
            };
            let status = match self.runtime.maintenance_status(&group_id) {
                Ok(status) => status,
                Err(_error) => {
                    tracing::warn!(
                        target: "marmot_app::maintenance",
                        method = "advance_post_join_maintenance_subscriptions",
                        error_kind = "maintenance_status_unavailable",
                        "skipping unavailable post-join maintenance group"
                    );
                    continue;
                }
            };
            let needs_subscription = status.obligations.iter().any(|obligation| {
                obligation.trigger == cgka_traits::MaintenanceTrigger::PostJoin
                    && matches!(
                        obligation.phase,
                        cgka_traits::MaintenancePhase::CatchUp
                            | cgka_traits::MaintenancePhase::EoseTimeout
                            | cgka_traits::MaintenancePhase::Grace
                    )
            });
            if !needs_subscription {
                continue;
            }
            waiting.insert(group_id.clone());

            if !self
                .post_join_maintenance_subscriptions
                .contains_key(&group_id)
            {
                let Some(route) = routes
                    .iter()
                    .find(|route| route.group_id == group_id)
                    .cloned()
                else {
                    tracing::warn!(
                        target: "marmot_app::maintenance",
                        method = "advance_post_join_maintenance_subscriptions",
                        error_kind = "missing_route",
                        "skipping post-join maintenance group without a route"
                    );
                    continue;
                };
                let subscription_id = match self
                    .adapter
                    .install_group_maintenance_subscription(route.clone())
                    .await
                {
                    Ok(subscription_id) => subscription_id,
                    Err(_error) => {
                        tracing::warn!(
                            target: "marmot_app::maintenance",
                            method = "advance_post_join_maintenance_subscriptions",
                            error_kind = "subscription_install_failed",
                            "post-join maintenance subscription installation failed"
                        );
                        continue;
                    }
                };
                if let Err(_error) = self
                    .runtime
                    .mark_post_join_subscription_installed(&group_id)
                {
                    let _ = self
                        .adapter
                        .remove_group_maintenance_subscription(&route)
                        .await;
                    tracing::warn!(
                        target: "marmot_app::maintenance",
                        method = "advance_post_join_maintenance_subscriptions",
                        error_kind = "state_update_failed",
                        "compensated post-join subscription after state update failure"
                    );
                    continue;
                }
                self.post_join_maintenance_subscriptions
                    .insert(group_id.clone(), (subscription_id, route));
            }

            let first_eose = if let Some((subscription_id, _)) =
                self.post_join_maintenance_subscriptions.get(&group_id)
            {
                self.adapter
                    .group_maintenance_any_eose(subscription_id)
                    .await
                    .unwrap_or(false)
            } else {
                false
            };
            if first_eose && let Err(_error) = self.runtime.mark_post_join_eose(&group_id) {
                tracing::warn!(
                    target: "marmot_app::maintenance",
                    method = "advance_post_join_maintenance_subscriptions",
                    error_kind = "eose_state_update_failed",
                    "could not advance post-join maintenance after EOSE"
                );
                continue;
            }
        }

        let stale = self
            .post_join_maintenance_subscriptions
            .keys()
            .filter(|group_id| !waiting.contains(*group_id))
            .cloned()
            .collect::<Vec<_>>();
        for group_id in stale {
            if let Some((_, route)) = self
                .post_join_maintenance_subscriptions
                .get(&group_id)
                .cloned()
                && let Err(_error) = self
                    .adapter
                    .remove_group_maintenance_subscription(&route)
                    .await
            {
                tracing::warn!(
                    target: "marmot_app::maintenance",
                    method = "advance_post_join_maintenance_subscriptions",
                    error_kind = "subscription_remove_failed",
                    "could not remove stale post-join maintenance subscription"
                );
                continue;
            }
            self.post_join_maintenance_subscriptions.remove(&group_id);
        }
        Ok(())
    }

    pub async fn rotate_key_package(&mut self) -> Result<KeyPackage, AppError> {
        self.app
            .ensure_local_account_relay_lists(&self.state.label)
            .await?;
        self.refresh_routing()?;
        self.runtime.activate_transport(None).await?;
        // SQLCipher lifecycle state is authoritative. On first rollout the
        // publisher imports only the legacy JSON `d` slot, then performs the
        // recorded upgrade replacement under that same slot.
        Ok(self.runtime.publish_fresh_key_package().await?)
    }

    /// Resolve and cache the current composition roster without reserving or
    /// consuming any KeyPackage. Group creation revalidates the cached bytes
    /// and the MLS mutation boundary retains its ordinary validation.
    pub async fn prewarm_group_member_key_packages(
        &self,
        member_refs: &[&str],
    ) -> Result<crate::MemberKeyPackagePrewarmSummary, AppError> {
        self.app
            .prewarm_group_member_key_packages(member_refs)
            .await
    }

    /// Validate and encrypt a founding image, then durably stage its exact
    /// ciphertext and upload authorization in the account SQLCipher database.
    /// This performs no network I/O. The returned opaque id can be resumed
    /// after cancellation or process restart.
    pub(crate) fn stage_prepared_initial_group_image(
        &self,
        plaintext: &[u8],
        media_type: &str,
    ) -> Result<AppPreparedGroupImageUpload, AppError> {
        let prepared = prepare_group_image_upload(plaintext, media_type)?;
        let component_data = hex::decode(AppGroupImageComponent::new(prepared.input).data_hex)?;
        let mut id_bytes = [0_u8; 16];
        OsRng.fill_bytes(&mut id_bytes);
        let upload_id = hex::encode(id_bytes);
        let now = unix_now_seconds();
        let record = PreparedGroupImageUploadRecord {
            upload_id: upload_id.clone(),
            state: PreparedGroupImageUploadState::Staged,
            component_data,
            encrypted_blob: Some(prepared.encrypted_blob),
            upload_secret: Some(prepared.upload_secret.to_vec()),
            group_id_hex: None,
            attempt_count: 0,
            last_error_kind: None,
            recorded_at: now,
            updated_at: now,
        };
        self.app
            .account_storage(&self.state.label)?
            .stage_prepared_group_image_upload(&record)?;
        Ok(prepared_group_image_status(&record))
    }

    pub(crate) fn prepared_initial_group_image_status(
        &self,
        upload_id: &str,
    ) -> Result<AppPreparedGroupImageUpload, AppError> {
        let record = self
            .app
            .account_storage(&self.state.label)?
            .prepared_group_image_upload(upload_id)?
            .ok_or_else(|| {
                AppError::InvalidEncryptedMedia("prepared group image upload was not found".into())
            })?;
        Ok(prepared_group_image_status(&record))
    }

    pub(crate) fn prepared_initial_group_images(
        &self,
    ) -> Result<Vec<AppPreparedGroupImageUpload>, AppError> {
        Ok(self
            .app
            .account_storage(&self.state.label)?
            .list_prepared_group_image_uploads()?
            .iter()
            .map(prepared_group_image_status)
            .collect())
    }

    pub(crate) fn prepare_initial_group_image_upload(
        &self,
        upload_id: &str,
        server: Option<String>,
        allow_loopback_http: bool,
    ) -> Result<PreparedGroupImageUploadStart, AppError> {
        let record = self
            .app
            .account_storage(&self.state.label)?
            .prepared_group_image_upload(upload_id)?
            .ok_or_else(|| {
                AppError::InvalidEncryptedMedia("prepared group image upload was not found".into())
            })?;
        if matches!(
            record.state,
            PreparedGroupImageUploadState::Uploaded | PreparedGroupImageUploadState::Consumed
        ) {
            return Ok(PreparedGroupImageUploadStart::Complete(
                prepared_group_image_status(&record),
            ));
        }
        let input =
            AppGroupImageInput::from_component_bytes(&record.component_data).ok_or_else(|| {
                AppError::InvalidEncryptedMedia("prepared group image component is invalid".into())
            })?;
        let encrypted_blob = record.encrypted_blob.ok_or_else(|| {
            AppError::InvalidEncryptedMedia("prepared group image ciphertext is missing".into())
        })?;
        let upload_secret = record.upload_secret.ok_or_else(|| {
            AppError::InvalidEncryptedMedia("prepared group image upload key is missing".into())
        })?;
        Ok(PreparedGroupImageUploadStart::Http(
            PreparedGroupImageUploadHttp {
                encrypted_blob,
                image_hash_hex: input.image_hash_hex,
                upload_secret: Zeroizing::new(upload_secret),
                server,
                allow_loopback_http,
            },
        ))
    }

    pub(crate) fn finish_initial_group_image_upload(
        &self,
        upload_id: &str,
        result: &Result<(), AppError>,
    ) -> Result<AppPreparedGroupImageUpload, AppError> {
        let storage = self.app.account_storage(&self.state.label)?;
        let now = unix_now_seconds();
        match result {
            Ok(()) => storage.mark_prepared_group_image_upload_uploaded(upload_id, now)?,
            Err(error) => storage.mark_prepared_group_image_upload_failed(
                upload_id,
                error.privacy_safe_kind(),
                now,
            )?,
        }
        let record = storage
            .prepared_group_image_upload(upload_id)?
            .ok_or_else(|| {
                AppError::InvalidEncryptedMedia("prepared group image upload was not found".into())
            })?;
        Ok(prepared_group_image_status(&record))
    }

    /// Create a locally canonical group and attempt each founding Welcome.
    ///
    /// `Ok(group_id)` reports group creation, not blanket invitation success.
    /// Any Welcome that misses its acknowledgement policy is reported through
    /// `WelcomeDeliveryPending` and remains listed by
    /// [`Self::pending_welcome_deliveries`] for explicit re-delivery.
    pub async fn create_group(
        &mut self,
        name: &str,
        member_refs: &[&str],
    ) -> Result<GroupId, AppError> {
        self.create_group_with_options(name, member_refs, AppCreateGroupOptions::default())
            .await
    }

    pub async fn create_group_with_initial_image(
        &mut self,
        name: &str,
        member_refs: &[&str],
        initial_image: Option<AppInitialGroupImage>,
    ) -> Result<GroupId, AppError> {
        self.create_group_with_options(
            name,
            member_refs,
            AppCreateGroupOptions {
                initial_image,
                ..Default::default()
            },
        )
        .await
    }

    pub async fn create_group_with_options(
        &mut self,
        name: &str,
        member_refs: &[&str],
        options: AppCreateGroupOptions,
    ) -> Result<GroupId, AppError> {
        let created = self
            .create_group_with_options_and_optional_telemetry(name, member_refs, options, None)
            .await?;
        self.drive_unpublished_welcome_delivery(None).await;
        // Direct `AppClient` callers do not have the managed account worker to
        // refresh subscriptions after its response. Preserve that API's
        // historical readiness guarantee; the managed runtime uses the
        // telemetry-aware entry point below and performs this step after
        // replying so it stays off the user-visible latency boundary.
        if let Err(error) = self.sync_runtime_groups().await {
            tracing::warn!(
                target: "marmot_app::client",
                method = "create_group",
                error_kind = error.privacy_safe_kind(),
                "confirmed group creation could not refresh subscriptions immediately"
            );
        }
        Ok(created.group_id)
    }

    pub(crate) async fn create_group_with_options_and_telemetry(
        &mut self,
        name: &str,
        member_refs: &[&str],
        options: AppCreateGroupOptions,
        telemetry: &AppPerformanceTelemetry,
    ) -> Result<CanonicalCreatedGroup, AppError> {
        self.create_group_with_options_and_optional_telemetry(
            name,
            member_refs,
            options,
            Some(telemetry),
        )
        .await
    }

    pub(crate) async fn create_group_with_prepared_initial_image_and_telemetry(
        &mut self,
        name: &str,
        member_refs: &[&str],
        options: AppCreateGroupOptions,
        upload_id: &str,
        telemetry: &AppPerformanceTelemetry,
    ) -> Result<CanonicalCreatedGroup, AppError> {
        let storage = self.app.account_storage(&self.state.label)?;
        let record = storage
            .prepared_group_image_upload(upload_id)?
            .ok_or_else(|| {
                AppError::InvalidEncryptedMedia("prepared group image upload was not found".into())
            })?;
        if record.state == PreparedGroupImageUploadState::Consumed {
            let group_id_hex = record.group_id_hex.ok_or_else(|| {
                AppError::InvalidEncryptedMedia("consumed group image artifact has no group".into())
            })?;
            return Ok(CanonicalCreatedGroup {
                group_id: GroupId::new(hex::decode(group_id_hex)?),
                chat_list_row: None,
            });
        }
        if record.state != PreparedGroupImageUploadState::Uploaded {
            return Err(AppError::InvalidEncryptedMedia(
                "prepared group image must be uploaded before group creation".into(),
            ));
        }

        // Recover a crash after canonical creation but before the artifact's
        // consumed marker. The app projection is explicitly best-effort after
        // canonical creation, so inspect authoritative live engine components
        // rather than relying on `state.groups`. The exact randomized
        // component bytes uniquely bind the artifact to the already-created
        // group, so retry returns that group rather than creating a duplicate.
        let mut matching_group_id = None;
        for group_id in self.runtime.live_group_ids()? {
            if self
                .runtime
                .app_component(&group_id, GROUP_BLOSSOM_IMAGE_COMPONENT_ID)?
                .as_deref()
                == Some(record.component_data.as_slice())
            {
                matching_group_id = Some(group_id);
                break;
            }
        }
        if let Some(group_id) = matching_group_id {
            let group_id_hex = hex::encode(group_id.as_slice());
            storage.consume_prepared_group_image_upload(
                upload_id,
                &group_id_hex,
                unix_now_seconds(),
            )?;
            return Ok(CanonicalCreatedGroup {
                group_id,
                chat_list_row: None,
            });
        }

        let AppCreateGroupOptions {
            description,
            initial_image,
            disappearing_message_secs,
        } = options;
        if initial_image.is_some() {
            return Err(AppError::InvalidEncryptedMedia(
                "group creation accepts either inline or prepared image input".into(),
            ));
        }

        self.create_group_with_initial_source_and_optional_telemetry(
            name,
            description,
            member_refs,
            Some(InitialGroupImageSource::Prepared {
                upload_id: upload_id.to_owned(),
                component_data: record.component_data,
            }),
            disappearing_message_secs,
            Some(telemetry),
        )
        .await
    }

    async fn create_group_with_options_and_optional_telemetry(
        &mut self,
        name: &str,
        member_refs: &[&str],
        options: AppCreateGroupOptions,
        telemetry: Option<&AppPerformanceTelemetry>,
    ) -> Result<CanonicalCreatedGroup, AppError> {
        let AppCreateGroupOptions {
            description,
            initial_image,
            disappearing_message_secs,
        } = options;
        self.create_group_with_initial_source_and_optional_telemetry(
            name,
            description,
            member_refs,
            initial_image.map(InitialGroupImageSource::Inline),
            disappearing_message_secs,
            telemetry,
        )
        .await
    }

    pub(crate) async fn create_group_with_initial_source_and_optional_telemetry(
        &mut self,
        name: &str,
        description: String,
        member_refs: &[&str],
        initial_image: Option<InitialGroupImageSource>,
        disappearing_message_secs: u64,
        telemetry: Option<&AppPerformanceTelemetry>,
    ) -> Result<CanonicalCreatedGroup, AppError> {
        validate_group_profile(name, &description)?;
        let key_package_started_at = Instant::now();
        let key_packages = self
            .app
            .resolve_member_key_packages_with_stats(
                member_refs
                    .iter()
                    .map(|member_ref| (*member_ref).to_owned())
                    .collect(),
            )
            .await;
        let key_package_elapsed = key_package_started_at.elapsed();
        record_app_performance(
            telemetry,
            AppPerformanceOperation::GroupCreateKeyPackageLookup,
            key_package_elapsed,
            key_packages.is_ok(),
        );
        let resolved = key_packages?;
        record_app_performance(
            telemetry,
            if resolved.stats.network_resolved_members == 0 {
                AppPerformanceOperation::GroupCreateKeyPackageCacheReuse
            } else {
                AppPerformanceOperation::GroupCreateKeyPackageNetworkResolution
            },
            key_package_elapsed,
            true,
        );
        let members = resolved.key_packages;
        self.refresh_routing()?;
        let nostr_routing = self.app.new_nostr_routing()?;
        let nostr_routing_bytes =
            encode_nostr_routing_v1(&nostr_routing).map_err(AppError::InvalidNostrRouting)?;
        let mut app_components = vec![AppComponentData {
            component_id: NOSTR_ROUTING_COMPONENT_ID,
            data: nostr_routing_bytes,
        }];
        app_components.push(
            AgentTextStreamQuicPolicyV1::user_to_agent_default()
                .to_app_component_data()
                .map_err(|err| AppError::InvalidAgentTextStreamPolicy(err.to_string()))?,
        );
        let encrypted_media = self.encrypted_media_component_for_new_group()?;
        app_components.push(encrypted_media);
        if disappearing_message_secs != 0 {
            app_components.push(
                AppGroupMessageRetentionComponent::new(disappearing_message_secs)
                    .to_app_component_data()?,
            );
        }
        let constructable = self.runtime.constructable_capabilities(&members)?;
        require_initial_group_component_support(&constructable, &app_components)?;
        let uploads_inline_image =
            matches!(&initial_image, Some(InitialGroupImageSource::Inline(_)));
        let prepared_upload_id = match &initial_image {
            Some(InitialGroupImageSource::Prepared { upload_id, .. }) => Some(upload_id.clone()),
            _ => None,
        };
        let image_started_at = Instant::now();
        let optional_app_components = async {
            let mut optional_app_components = Vec::new();
            if let Some(image) = initial_image {
                match preferred_initial_group_image_component(
                    &constructable,
                    matches!(
                        &image,
                        InitialGroupImageSource::Inline(image) if image.source_url.is_some()
                    ),
                ) {
                    Some(GROUP_BLOSSOM_IMAGE_COMPONENT_ID) => {
                        let data = match image {
                            InitialGroupImageSource::Inline(image) => {
                                let upload =
                                    upload_group_image(&image.plaintext, &image.media_type, None)
                                        .await?;
                                let input = AppGroupImageInput::from(upload);
                                hex::decode(AppGroupImageComponent::new(input).data_hex)?
                            }
                            InitialGroupImageSource::Prepared { component_data, .. } => {
                                component_data
                            }
                        };
                        optional_app_components.push(AppComponentData {
                            component_id: GROUP_BLOSSOM_IMAGE_COMPONENT_ID,
                            data,
                        });
                    }
                    Some(GROUP_AVATAR_URL_COMPONENT_ID) => match image {
                        InitialGroupImageSource::Inline(image) => {
                            if let Some(url) = image.source_url {
                                optional_app_components.push(
                                    AppGroupAvatarUrlComponent::new(
                                        url,
                                        image.dim,
                                        image.thumbhash,
                                    )?
                                    .to_app_component_data()?,
                                );
                            }
                        }
                        InitialGroupImageSource::Prepared { .. } => {
                            return Err(AppError::InvalidEncryptedMedia(
                                "prepared group images require encrypted Blossom support".into(),
                            ));
                        }
                    },
                    _ => {
                        if matches!(image, InitialGroupImageSource::Prepared { .. }) {
                            return Err(AppError::InvalidEncryptedMedia(
                                "founding members do not support prepared group images".into(),
                            ));
                        }
                    }
                }
            }
            Ok::<_, AppError>(optional_app_components)
        }
        .await;
        if uploads_inline_image {
            record_app_performance(
                telemetry,
                AppPerformanceOperation::GroupCreateImageUpload,
                image_started_at.elapsed(),
                optional_app_components.is_ok(),
            );
        }
        let optional_app_components = optional_app_components?;
        let mut touched_components = app_components
            .iter()
            .map(|component| component.component_id)
            .collect::<Vec<_>>();
        touched_components.extend(
            optional_app_components
                .iter()
                .map(|component| component.component_id),
        );
        let mut changed_fields = vec!["name", "members"];
        if !description.is_empty() {
            changed_fields.push("description");
        }
        if disappearing_message_secs != 0 {
            changed_fields.push("message_retention");
        }
        if !optional_app_components.is_empty() {
            changed_fields.push("image");
        }
        let audit_context = Self::local_human_action_context(
            "create_group",
            changed_fields,
            touched_components,
            Some(members.len() as u64),
        );

        let mls_started_at = Instant::now();
        let prepared = self
            .runtime
            .prepare_create_group_with_optional_app_components_and_audit_context(
                CreateGroupRequest {
                    name: name.to_owned(),
                    description,
                    members,
                    required_features: Vec::new(),
                    app_components,
                    initial_admins: Vec::new(),
                },
                optional_app_components,
                audit_context.clone(),
            )
            .await;
        record_app_performance(
            telemetry,
            AppPerformanceOperation::GroupCreateMlsPreparePersist,
            mls_started_at.elapsed(),
            prepared.is_ok(),
        );
        let prepared = prepared?;
        let group_id = prepared.group_id;
        // Bind the idempotency key at the first post-canonical instruction.
        // Projection and Welcome bookkeeping below are repairable and must not
        // widen the crash window in which a retry could create a second group.
        // If this best-effort write fails, retry scans the authoritative engine
        // component state above before attempting another create.
        if let Some(upload_id) = prepared_upload_id.as_deref()
            && let Err(error) = self
                .app
                .account_storage(&self.state.label)
                .and_then(|storage| {
                    storage
                        .consume_prepared_group_image_upload(
                            upload_id,
                            &hex::encode(group_id.as_slice()),
                            unix_now_seconds(),
                        )
                        .map_err(AppError::from)
                })
        {
            tracing::warn!(
                target: "marmot_app::client",
                method = "create_group",
                error_kind = error.privacy_safe_kind(),
                "confirmed group creation outpaced prepared-image consumption; retry will reconcile the engine component"
            );
        }
        // Current-profile founding creation is already canonical before
        // transport delivery: the engine transaction retained the exact
        // Welcome bytes and destinations. Derive only the in-memory ids used
        // by the post-response fanout driver here. The app convenience index
        // is populated later by delivery failure or reconciliation.
        let welcome_index_started_at = Instant::now();
        let founding_welcome_intents =
            Self::founding_welcome_delivery_intent_ids(&prepared.effects);
        let welcome_index_prepared = founding_welcome_intents.is_ok();
        let founding_welcome_intents = recover_post_canonical_result(
            "prepare_founding_welcome_delivery_index",
            founding_welcome_intents,
        );
        record_app_performance(
            telemetry,
            AppPerformanceOperation::GroupCreatePendingWelcomeIndex,
            welcome_index_started_at.elapsed(),
            welcome_index_prepared,
        );
        self.unpublished_welcome_delivery = Some(UnpublishedWelcomeDelivery {
            group_id: group_id.clone(),
            audit_context: audit_context.clone(),
            kind: UnpublishedWelcomeKind::Founding {
                effects: prepared.effects,
                welcome_intents: founding_welcome_intents,
            },
        });
        // The engine group is already canonical. If this sole remaining app
        // transaction fails, account-open reconciliation recovers the derived
        // projection. Preserve that post-canonical outcome internally so the
        // compatibility API can still return the group id and the worker can
        // drive the engine-retained Welcome. The detailed API converts the
        // missing row into a typed, non-retryable creation result.
        let local_projection_started_at = Instant::now();
        let local_projection = if cfg!(feature = "test-policy-overrides")
            && self.app.config.dev_fail_create_local_projection
        {
            Err(AppError::Publish(
                "injected create local projection failure".into(),
            ))
        } else {
            self.add_group(&group_id)
                .and_then(|()| self.save_state_with_created_chat_list_row(&group_id))
        };
        record_app_performance(
            telemetry,
            AppPerformanceOperation::GroupCreateLocalProjectionSave,
            local_projection_started_at.elapsed(),
            local_projection.is_ok(),
        );
        if let Err(error) = &local_projection {
            tracing::warn!(
                target: "marmot_app::client",
                method = "create_group",
                error_kind = error.privacy_safe_kind(),
                "canonical group creation needs local projection reconciliation"
            );
        }
        Ok(CanonicalCreatedGroup {
            group_id,
            chat_list_row: local_projection.ok(),
        })
    }

    pub fn members(&self, group_id: &GroupId) -> Result<Vec<AppGroupMemberRecord>, AppError> {
        let profiles = self.app.profiles_by_id()?;
        self.members_with_profiles(group_id, &profiles)
    }

    pub(crate) fn member_ids_page(
        &self,
        group_ids: &[GroupId],
    ) -> Result<Vec<crate::AppGroupMemberIds>, AppError> {
        group_ids
            .iter()
            .map(|group_id| {
                let group_record = self
                    .state_group_record(group_id)
                    .ok_or_else(|| AppError::UnknownGroup(hex::encode(group_id.as_slice())))?;
                let member_ids_hex = self
                    .runtime
                    .members(group_id)?
                    .into_iter()
                    .map(|member| hex::encode(member.id.as_slice()))
                    .collect();
                Ok(crate::AppGroupMemberIds {
                    group_id_hex: hex::encode(group_id.as_slice()),
                    member_ids_hex,
                    admin_ids_hex: group_record.admin_policy.admins,
                })
            })
            .collect()
    }

    /// Build a group's member records against a caller-provided account-profile
    /// map, avoiding a fresh `profiles_by_id` load per group. `members` loads the
    /// map for a single read;
    /// [`AppClient::group_read_snapshot_with_stage_telemetry`] loads it once
    /// and reuses it across every group so capturing the snapshot stays a
    /// single profile read plus in-memory engine reads (it runs on the worker
    /// readiness path).
    fn members_with_profiles(
        &self,
        group_id: &GroupId,
        profiles: &HashMap<String, String>,
    ) -> Result<Vec<AppGroupMemberRecord>, AppError> {
        self.ensure_group(group_id)?;
        self.members_with_profiles_unchecked(group_id, profiles)
    }

    fn members_with_profiles_unchecked(
        &self,
        group_id: &GroupId,
        profiles: &HashMap<String, String>,
    ) -> Result<Vec<AppGroupMemberRecord>, AppError> {
        Ok(self
            .runtime
            .members(group_id)?
            .into_iter()
            .map(|member| {
                let member_id_hex = hex::encode(member.id.as_slice());
                let account = profiles.get(&member_id_hex).cloned();
                AppGroupMemberRecord {
                    member_id_hex,
                    local: account.is_some(),
                    account,
                }
            })
            .collect())
    }

    pub fn group_mls_state(&self, group_id: &GroupId) -> Result<AppGroupMlsState, AppError> {
        self.ensure_group(group_id)?;
        self.group_mls_state_unchecked(group_id)
    }

    pub(crate) fn group_roster_session(
        &self,
        group_id: &GroupId,
    ) -> Result<crate::groups::AppGroupRosterSession, AppError> {
        let group_id_hex = hex::encode(group_id.as_slice());
        let mut group_record = self
            .state
            .groups
            .iter()
            .find(|group| group.group_id_hex == group_id_hex)
            .cloned()
            .ok_or_else(|| AppError::UnknownGroup(group_id_hex))?;
        self.overlay_storage_self_membership(&mut group_record)?;
        let profiles = self.app.profiles_by_id()?;
        let members = self.members_with_profiles_unchecked(group_id, &profiles)?;
        let mls_state = self.group_mls_state_unchecked(group_id)?;
        Ok(crate::groups::AppGroupRosterSession {
            group_record,
            members,
            mls_state,
        })
    }

    fn overlay_storage_self_membership(
        &self,
        group_record: &mut AppGroupRecord,
    ) -> Result<(), AppError> {
        if let Some(membership) = self
            .app
            .stored_group_self_membership(&self.state.label, &group_record.group_id_hex)?
        {
            group_record.self_membership = membership;
        }
        Ok(())
    }

    /// Reconcile a storage row still carrying the preserving `Member` default
    /// against one hydrated engine roster. Used by on-demand startup reads so
    /// they cannot expose a legacy migration default before the full hydration
    /// pipeline finishes its once-only backfill.
    pub(crate) fn reconcile_group_self_membership(
        &self,
        group_id: &GroupId,
    ) -> Result<(), AppError> {
        let group_id_hex = hex::encode(group_id.as_slice());
        if !matches!(
            self.app
                .stored_group_self_membership(&self.state.label, &group_id_hex)?,
            Some(SelfMembership::Member)
        ) {
            return Ok(());
        }
        let local_account_id_hex = self
            .app
            .account_home()
            .account(&self.state.label)?
            .account_id_hex;
        let members = self.runtime.members(group_id)?;
        if local_account_removed_from_roster(&members, &local_account_id_hex) {
            self.app.set_group_self_membership(
                &self.state.label,
                &group_id_hex,
                SelfMembership::Removed,
            )?;
        }
        Ok(())
    }

    fn group_mls_state_unchecked(&self, group_id: &GroupId) -> Result<AppGroupMlsState, AppError> {
        let group = self.runtime.group_record(group_id)?;
        let lifecycle_state = self
            .runtime
            .epoch_state(group_id)
            .as_ref()
            .map(cgka_traits::GroupLifecycleState::from)
            .map(Into::into)
            .unwrap_or_else(|| {
                if group.disbanded.is_some() {
                    crate::AppGroupLifecycleState::Disbanded
                } else if group.unrecoverable {
                    crate::AppGroupLifecycleState::Unrecoverable
                } else {
                    crate::AppGroupLifecycleState::Stable
                }
            });
        let disbanding_enabled = group
            .required_capabilities
            .app_components
            .contains(cgka_traits::app_components::GROUP_LIFECYCLE_COMPONENT_ID)
            && group.disbanded.is_none();
        let disbanding_blockers = if disbanding_enabled || group.disbanded.is_some() {
            Vec::new()
        } else {
            self.runtime
                .disbanding_support_blockers(group_id)?
                .into_iter()
                .map(|member| hex::encode(member.as_slice()))
                .collect()
        };
        Ok(AppGroupMlsState {
            group_id_hex: hex::encode(group_id.as_slice()),
            protocol_profile: group.protocol_profile.into(),
            lifecycle_state,
            epoch: group.epoch.0,
            member_count: group.members.len(),
            unrecoverable: group.unrecoverable,
            required_app_components: group
                .required_capabilities
                .app_components
                .ids
                .iter()
                .copied()
                .collect(),
            disbanding_enabled,
            disbanding: self.runtime.disbanding_in_progress(group_id)?,
            disbanding_blockers,
            disband_request: self.runtime.disband_request(group_id)?.map(Into::into),
        })
    }

    /// Stored groups that failed session-open hydration and were skipped so the
    /// rest of the account could open (mdk#151 / #417). The application
    /// reads this to surface a per-group recovery flow (mdk#426) — these
    /// groups are not in the live roster and otherwise vanish with no
    /// explanation. Each entry carries a coarse, privacy-safe recovery reason.
    pub fn quarantined_groups(&self) -> Vec<AppQuarantinedGroup> {
        self.runtime
            .quarantined_groups()
            .into_iter()
            .map(|(group_id, reason)| AppQuarantinedGroup {
                group_id_hex: hex::encode(group_id.as_slice()),
                reason: reason.into(),
            })
            .collect()
    }

    /// Capture a [`GroupReadSnapshot`] of every known group's read-only
    /// projections from the live (hydrated) session.
    ///
    /// Used by the account worker to answer read commands during relay catch-up
    /// without blocking on it; see [`GroupReadSnapshot`]. If a known group's
    /// member or MLS projection fails, snapshot capture
    /// fails atomically. The worker then defers reads until it can answer them
    /// from live state and preserve the underlying error classification.
    ///
    /// Returns the storage error if the one shared profile load fails, rather
    /// than masking it as empty profiles (which would make every member read
    /// `account: None` / `local: false` during the catch-up window). The worker
    /// treats that error as a failed local-readiness attempt (fail-closed
    /// through the ready/reconcile path).
    ///
    /// The per-stage startup telemetry records the shared profile load as
    /// `AccountProfileLoad` (the caller wraps the whole capture as
    /// `AccountGroupReadSnapshot`, mdk#1161).
    pub(crate) fn group_read_snapshot_with_stage_telemetry(
        &self,
        telemetry: &crate::app_telemetry::AppPerformanceTelemetry,
    ) -> Result<GroupReadSnapshot, AppError> {
        self.group_read_snapshot_inner(Some(telemetry))
    }

    pub(crate) fn group_read_snapshot(&self) -> Result<GroupReadSnapshot, AppError> {
        self.group_read_snapshot_inner(None)
    }

    fn group_read_snapshot_inner(
        &self,
        telemetry: Option<&crate::app_telemetry::AppPerformanceTelemetry>,
    ) -> Result<GroupReadSnapshot, AppError> {
        if cfg!(feature = "test-policy-overrides")
            && self.app.config.dev_force_group_read_snapshot_failure
        {
            return Err(cgka_traits::StorageError::Backend(
                "injected group-read snapshot failure".to_owned(),
            )
            .into());
        }
        // Load account profiles once and reuse across every group: the rest of
        // the capture is in-memory engine reads, so the snapshot adds a single
        // storage read to the worker readiness path regardless of group count.
        let profile_load_started = Instant::now();
        let profiles = self.app.profiles_by_id();
        if let Some(telemetry) = telemetry {
            telemetry.record(
                crate::app_telemetry::AppPerformanceOperation::AccountProfileLoad,
                profile_load_started.elapsed(),
                profiles.is_ok(),
            );
        }
        let profiles = profiles?;
        let stored_self_memberships = self.app.account_group_self_memberships(&self.state.label)?;
        let mut groups = HashMap::new();
        let mut members = HashMap::new();
        let mut mls_state = HashMap::new();
        let mut skipped_malformed_group_records = 0usize;
        for group in &self.state.groups {
            let Ok(bytes) = hex::decode(&group.group_id_hex) else {
                skipped_malformed_group_records += 1;
                continue;
            };
            let group_id = GroupId::new(bytes);
            let mut group_record = group.clone();
            if let Some(membership) = stored_self_memberships.get(&group.group_id_hex) {
                group_record.self_membership = *membership;
            }
            let records = self.members_with_profiles_unchecked(&group_id, &profiles)?;
            let state = self.group_mls_state_unchecked(&group_id)?;
            groups.insert(group_id.clone(), group_record);
            members.insert(group_id.clone(), records);
            mls_state.insert(group_id, state);
        }
        if skipped_malformed_group_records > 0 {
            tracing::warn!(
                target: "marmot_app::client",
                method = "group_read_snapshot",
                skipped_malformed_group_records,
                "skipping malformed group records while building group read snapshot"
            );
        }
        Ok(GroupReadSnapshot {
            groups,
            members,
            mls_state,
            quarantined: self.quarantined_groups(),
        })
    }

    /// Re-attempt hydration of a single quarantined group (mdk#426).
    ///
    /// This is the non-destructive, user-initiated recovery path for a
    /// transiently-bad group (e.g. a partial DB restore that has since
    /// completed). Returns `Ok(true)` if the group recovered and is now a live
    /// group, `Ok(false)` if it is still unhealthy and stays quarantined.
    /// Errors with `UnknownGroup` if the id is not currently quarantined.
    ///
    /// On success the engine queues a `GroupHydrationRecovered` event, so the
    /// caller should follow up with a sync/catch-up to surface the recovered
    /// group in chat-list projections.
    pub fn retry_hydrate_quarantined_group(
        &mut self,
        group_id: &GroupId,
    ) -> Result<bool, AppError> {
        Ok(self.runtime.retry_hydrate_quarantined_group(group_id)?)
    }

    pub fn safe_export_secret(
        &mut self,
        group_id: &GroupId,
        component_id: cgka_traits::AppComponentId,
    ) -> Result<SecretBytes, AppError> {
        self.ensure_group(group_id)?;
        Ok(self.runtime.safe_export_secret(group_id, component_id)?)
    }

    pub fn agent_text_stream_exporter_secret(
        &self,
        group_id: &GroupId,
    ) -> Result<SecretBytes, AppError> {
        self.exporter_secret(group_id, AGENT_TEXT_STREAM_EXPORTER_CACHE_KEY, 32)
    }

    pub(crate) fn exporter_secret(
        &self,
        group_id: &GroupId,
        label: &str,
        length: usize,
    ) -> Result<SecretBytes, AppError> {
        self.ensure_group(group_id)?;
        Ok(self.runtime.exporter_secret(group_id, label, length)?)
    }

    pub async fn invite_members(
        &mut self,
        group_id: &GroupId,
        member_refs: &[&str],
    ) -> Result<SendSummary, AppError> {
        let summary = self
            .invite_members_with_optional_telemetry(group_id, member_refs, &[], None)
            .await?;
        self.drive_unpublished_welcome_delivery(None).await;
        Ok(summary)
    }

    pub(crate) async fn invite_members_with_telemetry(
        &mut self,
        group_id: &GroupId,
        member_refs: &[&str],
        initial_admin_refs: &[&str],
        telemetry: &AppPerformanceTelemetry,
    ) -> Result<SendSummary, AppError> {
        self.invite_members_with_optional_telemetry(
            group_id,
            member_refs,
            initial_admin_refs,
            Some(telemetry),
        )
        .await
    }

    async fn invite_members_with_optional_telemetry(
        &mut self,
        group_id: &GroupId,
        member_refs: &[&str],
        initial_admin_refs: &[&str],
        telemetry: Option<&AppPerformanceTelemetry>,
    ) -> Result<SendSummary, AppError> {
        self.ensure_group(group_id)?;

        let key_package_started_at = Instant::now();
        let key_packages = self.app.resolve_member_key_packages(member_refs).await;
        record_app_performance(
            telemetry,
            AppPerformanceOperation::GroupInviteKeyPackageLookup,
            key_package_started_at.elapsed(),
            key_packages.is_ok(),
        );
        let key_packages = key_packages?;

        let mut initial_admins = Vec::with_capacity(initial_admin_refs.len());
        for admin in initial_admin_refs {
            initial_admins.push(self.app.member_id(admin)?);
        }

        let routing_refresh_started_at = Instant::now();
        let routing_refresh = self.refresh_routing();
        record_app_performance(
            telemetry,
            AppPerformanceOperation::GroupInviteRoutingRefresh,
            routing_refresh_started_at.elapsed(),
            routing_refresh.is_ok(),
        );
        routing_refresh?;

        let mut affected_fields = vec!["members"];
        let mut affected_components = Vec::new();
        if !initial_admin_refs.is_empty() {
            affected_fields.push("admins");
            affected_components.push(GROUP_ADMIN_POLICY_COMPONENT_ID);
        }
        let audit_context = Self::local_human_action_context(
            "invite_members",
            affected_fields,
            affected_components,
            Some(key_packages.len() as u64),
        );

        let pre_send_sync_started_at = Instant::now();
        let pre_send_sync = self.sync_runtime_groups().await;
        record_app_performance(
            telemetry,
            AppPerformanceOperation::GroupInvitePreSendSync,
            pre_send_sync_started_at.elapsed(),
            pre_send_sync.is_ok(),
        );
        pre_send_sync?;

        let engine_publish_started_at = Instant::now();
        let commit = self
            .runtime
            .confirm_commit_without_publish_with_audit_context(
                SendIntent::Invite {
                    group_id: group_id.clone(),
                    key_packages,
                    initial_admins,
                },
                audit_context.clone(),
            )
            .await
            .map_err(AppError::from);
        let prepared = match commit {
            Ok(PreparedSessionSend::Commit(prepared)) => prepared,
            Ok(PreparedSessionSend::Queued(session_effects)) => {
                let queued = self
                    .runtime
                    .publish_prepared_session_effects_with_audit_context(
                        session_effects,
                        audit_context,
                    )
                    .await
                    .map_err(AppError::from);
                record_app_performance(
                    telemetry,
                    AppPerformanceOperation::GroupInviteEnginePublish,
                    engine_publish_started_at.elapsed(),
                    queued.is_ok(),
                );
                return queued.map(|effects| send_summary_from_effects(&effects));
            }
            Err(error) => {
                record_app_performance(
                    telemetry,
                    AppPerformanceOperation::GroupInviteEnginePublish,
                    engine_publish_started_at.elapsed(),
                    false,
                );
                return Err(error);
            }
        };
        // The invite is staged locally but not canonical yet. Record every
        // Welcome destination atomically before exposing the commit; if that
        // persistence fails, roll back the staged MLS change and return the
        // original error so a retry cannot create phantom local membership.
        let welcome_intent_result = if cfg!(feature = "test-policy-overrides")
            && self.app.config.dev_fail_invite_welcome_intent
        {
            Err(AppError::Publish(
                "injected invite welcome intent failure".into(),
            ))
        } else {
            self.record_welcome_delivery_intents(group_id, prepared.welcomes())
        };
        let welcome_intents = match welcome_intent_result {
            Ok(welcome_intents) => welcome_intents,
            Err(error) => {
                let rollback = self
                    .runtime
                    .rollback_prepared_session_commit(prepared)
                    .await
                    .map_err(AppError::from);
                record_app_performance(
                    telemetry,
                    AppPerformanceOperation::GroupInviteEnginePublish,
                    engine_publish_started_at.elapsed(),
                    false,
                );
                rollback?;
                self.refresh_group(group_id);
                if let Err(refresh_error) =
                    self.save_state_with_pending_local_group_deletion_frontier_clears()
                {
                    tracing::warn!(
                        target: "marmot_app::client",
                        method = "invite_members_intent_failure_rollback",
                        error_kind = refresh_error.privacy_safe_kind(),
                        "rolled back staged invite but could not persist the refreshed app projection"
                    );
                }
                return Err(error);
            }
        };
        let (session_effects, welcomes) = prepared.into_effects_and_welcomes();
        self.unpublished_welcome_delivery = Some(UnpublishedWelcomeDelivery {
            group_id: group_id.clone(),
            audit_context: audit_context.clone(),
            kind: UnpublishedWelcomeKind::Invite {
                welcomes,
                welcome_intents,
            },
        });

        let published = match self
            .runtime
            .publish_prepared_session_effects_with_audit_context(
                session_effects,
                audit_context.clone(),
            )
            .await
            .map_err(AppError::from)
        {
            // Matched rather than chained so the gate can arm first: it
            // previously sat in a combinator closure that could not reach
            // `&mut self`.
            Ok(effects) => self
                .observe_recovery_evidence_then_fail_if_publish_failed(&effects)
                .map(|()| effects),
            Err(error) => Err(error),
        };
        record_app_performance(
            telemetry,
            AppPerformanceOperation::GroupInviteEnginePublish,
            engine_publish_started_at.elapsed(),
            published.is_ok(),
        );
        let effects = match published {
            Ok(effects) => effects,
            Err(error) => {
                // The account runtime has either rolled the unexposed commit
                // back or retained its durable fanout for exact retry. Do not
                // let this in-memory slot independently publish Welcomes after
                // a failed caller-visible commit attempt.
                self.unpublished_welcome_delivery = None;
                return Err(error);
            }
        };

        let local_refresh_started_at = Instant::now();
        let local_refresh = (|| {
            if cfg!(feature = "test-policy-overrides")
                && self.app.config.dev_fail_invite_local_refresh
            {
                return Err(AppError::Publish(
                    "injected invite local refresh failure".into(),
                ));
            }
            self.record_welcome_delivery_failures(&hex::encode(group_id.as_slice()), &effects)?;
            self.record_human_action_succeeded(group_id, &audit_context, &effects);
            self.remember_published_reports(&effects);
            self.refresh_group(group_id);
            self.prune_plaintext_retention_for_group(group_id)?;
            self.save_state_with_pending_local_group_deletion_frontier_clears()?;
            self.queue_own_group_system_projection_updates(&effects);
            Ok::<_, AppError>(())
        })();
        record_app_performance(
            telemetry,
            AppPerformanceOperation::GroupInviteLocalRefresh,
            local_refresh_started_at.elapsed(),
            local_refresh.is_ok(),
        );
        recover_post_canonical_result("invite_members_local_refresh", local_refresh);

        let summary = send_summary_from_effects(&effects);

        let notification_started_at = Instant::now();
        self.publish_notification_trigger_best_effort(
            group_id,
            notifications::NotificationTrigger::GroupInvite,
        )
        .await;
        record_app_performance(
            telemetry,
            AppPerformanceOperation::GroupInviteNotificationTrigger,
            notification_started_at.elapsed(),
            true,
        );

        Ok(summary)
    }

    pub async fn remove_members(
        &mut self,
        group_id: &GroupId,
        member_refs: &[&str],
    ) -> Result<SendSummary, AppError> {
        self.ensure_group(group_id)?;
        let mut members = Vec::with_capacity(member_refs.len());
        for member in member_refs {
            members.push(self.app.member_id(member)?);
        }
        let audit_context = Self::local_human_action_context(
            "remove_members",
            vec!["members"],
            Vec::new(),
            Some(member_refs.len() as u64),
        );
        let target_hexes = members
            .iter()
            .map(|member| hex::encode(member.as_slice()))
            .collect::<Vec<_>>();

        self.sync_runtime_groups().await?;
        let wake_snapshot = self.snapshot_group_push_tokens_for_members(group_id, &target_hexes);
        let effects = self
            .runtime
            .send_with_audit_context(
                SendIntent::RemoveMembers {
                    group_id: group_id.clone(),
                    members,
                },
                audit_context.clone(),
            )
            .await?;
        self.observe_recovery_evidence_then_fail_if_publish_failed(&effects)?;
        self.record_human_action_succeeded(group_id, &audit_context, &effects);
        self.remember_published_reports(&effects);
        self.refresh_group(group_id);
        self.cleanup_stale_push_tokens_best_effort(group_id);
        self.save_state_with_pending_local_group_deletion_frontier_clears()?;
        self.queue_own_group_system_projection_updates(&effects);
        self.publish_targeted_group_state_wake_best_effort(
            group_id,
            wake_snapshot,
            &effects.events,
        )
        .await;
        Ok(send_summary_from_effects(&effects))
    }

    pub async fn leave_group(&mut self, group_id: &GroupId) -> Result<SendSummary, AppError> {
        let audit_context = Self::local_human_action_context(
            "leave_group",
            vec!["membership"],
            Vec::new(),
            Some(1),
        );
        self.leave_group_with_audit_context(group_id, audit_context)
            .await
    }

    /// Atomically install lifecycle-v1 and make it required for this group.
    pub async fn enable_group_disbanding(
        &mut self,
        group_id: &GroupId,
    ) -> Result<SendSummary, AppError> {
        self.ensure_group(group_id)?;
        let audit_context = Self::local_human_action_context(
            "enable_group_disbanding",
            vec!["lifecycle"],
            vec![
                cgka_traits::app_components::APP_COMPONENTS_COMPONENT_ID,
                cgka_traits::app_components::GROUP_LIFECYCLE_COMPONENT_ID,
            ],
            None,
        );
        self.sync_runtime_groups().await?;
        let effects = self
            .runtime
            .send_with_audit_context(
                SendIntent::EnableDisbanding {
                    group_id: group_id.clone(),
                },
                audit_context.clone(),
            )
            .await?;
        self.observe_recovery_evidence_then_fail_if_publish_failed(&effects)?;
        self.record_human_action_succeeded(group_id, &audit_context, &effects);
        self.remember_published_reports(&effects);
        self.refresh_group(group_id);
        self.save_state_with_pending_local_group_deletion_frontier_clears()?;
        // Enabling lifecycle-v1 changes eligibility, not group history. It
        // intentionally emits no kind-1210 system row.
        Ok(send_summary_from_effects(&effects))
    }

    /// Persist the irreversible request and return without waiting for the
    /// disband Commit or its mandatory convergence pass.
    pub async fn disband_group(
        &mut self,
        group_id: &GroupId,
    ) -> Result<AppDisbandRequest, AppError> {
        self.ensure_group(group_id)?;
        let audit_context = Self::local_human_action_context(
            "disband_group",
            vec!["lifecycle", "membership", "admins"],
            vec![
                cgka_traits::app_components::GROUP_LIFECYCLE_COMPONENT_ID,
                cgka_traits::app_components::GROUP_ADMIN_POLICY_COMPONENT_ID,
            ],
            None,
        );
        self.sync_runtime_groups().await?;
        let effects = self
            .runtime
            .send_with_audit_context(
                SendIntent::Disband {
                    group_id: group_id.clone(),
                },
                audit_context,
            )
            .await?;
        self.remember_published_reports(&effects);
        if let Err(error) = self
            .app
            .delete_message_draft(&self.state.label, &hex::encode(group_id.as_slice()))
        {
            // The irreversible engine request is already durable. Treat draft
            // cleanup like the other repairable post-canonical projections:
            // report success for the request and reconcile local UI state on
            // the next account mutation/open rather than inviting a retry.
            tracing::warn!(
                target: "marmot_app::client",
                method = "disband_group",
                error_kind = error.privacy_safe_kind(),
                "durable disband request outpaced composer draft cleanup"
            );
        }
        self.save_state_with_pending_local_group_deletion_frontier_clears()?;
        self.runtime
            .disband_request(group_id)?
            .map(Into::into)
            .ok_or_else(|| AppError::UnknownGroup(hex::encode(group_id.as_slice())))
    }

    pub fn acknowledge_disband_failure(&mut self, group_id: &GroupId) -> Result<bool, AppError> {
        self.ensure_group(group_id)?;
        Ok(self.runtime.acknowledge_disband_failure(group_id)?)
    }

    /// Delete only this group's app-local data. This intentionally does not send
    /// an MLS leave and does not delete the stored MLS/OpenMLS group state; a
    /// future fresh group delivery can recreate the chat-list projection.
    ///
    /// The live transport route is removed and synced before the DB wipe so no
    /// delivery races the deletion transaction, then the current route is
    /// restored without restoring the projection. The durable deletion frontier
    /// filters historical replay until a strictly newer app message arrives.
    pub async fn delete_group_local(&mut self, group_id: &GroupId) -> Result<bool, AppError> {
        if self.runtime.disbanding_in_progress(group_id)? {
            return Err(AppError::GroupDisbanding(hex::encode(group_id.as_slice())));
        }
        // A local wipe removes this group's transport route. Any already-durable
        // removal must publish first; retaining it after the route disappears
        // would preserve bytes on disk without preserving liveness.
        self.drain_existing_push_registration_removals_for_group(group_id)
            .await?;
        let group_id_hex = hex::encode(group_id.as_slice());
        let original_groups = self.state.groups.clone();
        let original_routing = self.routing.snapshot();
        let was_live = original_groups
            .iter()
            .any(|group| group.group_id_hex == group_id_hex);

        if was_live {
            self.state
                .groups
                .retain(|group| group.group_id_hex != group_id_hex);
            if let Err(error) = self.refresh_routing() {
                self.restore_local_group_after_failed_delete(
                    original_groups,
                    original_routing.clone(),
                    false,
                )
                .await;
                return Err(error);
            }
            if let Err(error) = self.sync_runtime_groups().await {
                self.restore_local_group_after_failed_delete(
                    original_groups,
                    original_routing.clone(),
                    true,
                )
                .await;
                return Err(error);
            }
        }

        let result = match self
            .app
            .delete_group_local_data(&self.state.label, &group_id_hex)
        {
            Ok(result) => result,
            Err(error) => {
                if was_live {
                    self.restore_local_group_after_failed_delete(
                        original_groups,
                        original_routing,
                        true,
                    )
                    .await;
                }
                return Err(error);
            }
        };
        if was_live {
            // The wipe has committed. Route restoration is a best-effort
            // post-success step: a transient adapter failure must not report
            // the durable delete as failed. Startup reconciliation retries it.
            match self.ensure_local_deleted_group_route(group_id) {
                Ok(true) => {
                    if let Err(error) = self.sync_runtime_groups().await {
                        tracing::warn!(
                            target: "marmot_app::client",
                            method = "delete_group_local",
                            error_kind = error.privacy_safe_kind(),
                            "local-delete route restoration remains pending",
                        );
                    }
                }
                Ok(false) => {}
                Err(error) => {
                    tracing::warn!(
                        target: "marmot_app::client",
                        method = "delete_group_local",
                        error_kind = error.privacy_safe_kind(),
                        "local-delete route restoration remains pending",
                    );
                }
            }
        }
        Ok(was_live || result)
    }

    async fn restore_local_group_after_failed_delete(
        &mut self,
        original_groups: Vec<AppGroupRecord>,
        original_routing: AppRoutingState,
        sync_transport: bool,
    ) {
        self.state.groups = original_groups;
        self.routing.replace(original_routing);
        if sync_transport && let Err(error) = self.sync_runtime_groups().await {
            tracing::warn!(
                target: "marmot_app::client",
                method = "restore_local_group_after_failed_delete",
                error_kind = error.privacy_safe_kind(),
                "failed local-delete transport compensation remains pending",
            );
        }
    }

    async fn leave_group_with_audit_context(
        &mut self,
        group_id: &GroupId,
        audit_context: AuditEventContext,
    ) -> Result<SendSummary, AppError> {
        self.ensure_group(group_id)?;

        // Once the MLS leave commits we can no longer author an in-group token
        // removal. Drain that durable intent first; if the leave later fails,
        // queue the current registration update as compensation.
        let removed_registration = self
            .drain_push_registration_removal_before_departure(group_id)
            .await?;
        let effects = match async {
            self.sync_runtime_groups().await?;
            let effects = self
                .runtime
                .send_with_audit_context(
                    SendIntent::Leave {
                        group_id: group_id.clone(),
                    },
                    audit_context.clone(),
                )
                .await?;
            self.observe_recovery_evidence_then_fail_if_publish_failed(&effects)?;
            Ok::<_, AppError>(effects)
        }
        .await
        {
            Ok(effects) => effects,
            Err(err) => {
                self.compensate_group_push_registration_removal(
                    group_id,
                    removed_registration.as_ref(),
                );
                let _ = self
                    .retry_pending_push_registration_shares_best_effort()
                    .await;
                return Err(err);
            }
        };
        self.record_human_action_succeeded(group_id, &audit_context, &effects);
        self.remember_published_reports(&effects);
        self.save_state_with_pending_local_group_deletion_frontier_clears()?;
        self.queue_own_group_system_projection_updates(&effects);
        // A local leave / decline is a voluntary departure, recorded as `Left`
        // so the chat list can distinguish it from an involuntary removal. The
        // inbound `observe_account_device_effects` path records this for an
        // observed self-removal, but our own relay echoes are skipped, so the
        // locally initiated departure must record (and thereby suppress) here
        // too. No-op if no `account_groups` row exists yet, so it never
        // resurrects pruned projection state. This is the source-of-truth write
        // for the account unread aggregate, so propagate its error (like the
        // nearby projection writes) rather than swallow it: a silently failed
        // update would leave `account_unread_total()` returning an inflated
        // badge after a leave that otherwise reports success.
        self.app.set_group_self_membership(
            &self.state.label,
            &hex::encode(group_id.as_slice()),
            SelfMembership::Left,
        )?;
        Ok(send_summary_from_effects(&effects))
    }

    /// One-time open/upgrade backfill of `account_groups.self_membership`.
    ///
    /// Migration 0018 defaults every existing `account_groups` row to
    /// `'member'`, which means accounts that already left / were removed from a
    /// group *before* upgrading keep an inflated `account_unread_total()`: the
    /// frozen unread row has no future removal event to flip the flag to
    /// `'removed'`. This backfill closes that gap by deriving membership from
    /// current engine state once, right after the account is opened.
    ///
    /// For each row still carrying the default `'member'`, it asks the engine
    /// for the group's roster (`runtime.members`, sourced from the Marmot
    /// record's authoritative post-merge member set) and flips the row to
    /// `Removed` only when the call succeeds and the local account id is
    /// definitively absent. Engine errors / unknown groups are skipped so
    /// uncertainty never suppresses (matching the projection's existing
    /// invariant). The work is gated behind a once-only account-import marker,
    /// so subsequent opens are a single marker read and the hot path stays
    /// projection-only.
    ///
    /// A backfilled departure is recorded as `Removed`, not `Left`: roster
    /// absence cannot tell us *why* the account is gone, and `Removed`
    /// ("removed by someone") is the safer unknown bucket — claiming the user
    /// voluntarily left a group an admin actually evicted them from is the more
    /// misleading error. Both states suppress the unread aggregate identically,
    /// so the choice only affects how the chat list labels the departure.
    pub(crate) fn backfill_self_membership_once(&self) -> Result<(), AppError> {
        if self
            .app
            .account_import_marker(&self.state.label, crate::SELF_MEMBERSHIP_BACKFILL_MARKER)?
        {
            return Ok(());
        }
        let local_account_id_hex = self
            .app
            .account_home()
            .account(&self.state.label)?
            .account_id_hex;
        let mut hydration_pending = false;
        for group_id_hex in self
            .app
            .account_group_ids_defaulting_to_member(&self.state.label)?
        {
            let Ok(group_id_bytes) = hex::decode(&group_id_hex) else {
                continue;
            };
            let group_id = GroupId::new(group_id_bytes);
            // Authoritative roster from engine state. On any engine error
            // (unknown/quarantined group, partially-missing live state) leave
            // the row at the preserving default — uncertainty never suppresses.
            let members = match self.runtime.members(&group_id) {
                Ok(members) => members,
                Err(err) => {
                    // A deferred-hydration open (mdk#1161) answers every
                    // roster read with the retryable not-hydrated state.
                    // Skipping is correct, but the once-only marker must not
                    // burn on a pass that could not see any roster — the
                    // worker re-runs this after its hydration pipeline.
                    if matches!(
                        AppError::from(err).as_engine_error(),
                        Some(cgka_traits::error::EngineError::GroupNotHydrated(_))
                    ) {
                        hydration_pending = true;
                    }
                    continue;
                }
            };
            if local_account_removed_from_roster(&members, &local_account_id_hex) {
                self.app.set_group_self_membership(
                    &self.state.label,
                    &group_id_hex,
                    SelfMembership::Removed,
                )?;
            }
        }
        if !hydration_pending {
            self.app.mark_account_import_complete(
                &self.state.label,
                crate::SELF_MEMBERSHIP_BACKFILL_MARKER,
            )?;
        }
        Ok(())
    }

    /// One-time open/upgrade backfill of `direct_conversation_members`.
    ///
    /// Migration 0050 creates the peer index empty. Groups saved after that
    /// write their Direct roster on the projection path. Accounts that already
    /// had unnamed two-member chats need one serialized pass on this worker
    /// lane after hydration can read those rosters. The import marker is set
    /// only when every eligible group is indexed; a failed or not-yet-hydrated
    /// group leaves the marker unset so the next open retries. Steady-state
    /// lookup never scans for unindexed rows.
    pub(crate) fn backfill_direct_conversation_members_once(&self) -> Result<(), AppError> {
        if self.app.account_import_marker(
            &self.state.label,
            crate::DIRECT_CONVERSATION_MEMBERS_BACKFILL_MARKER,
        )? {
            return Ok(());
        }
        let storage = self.app.account_storage(&self.state.label)?;
        let unindexed = storage.unindexed_direct_conversation_group_ids()?;
        let mut hydration_pending = false;
        for group_id_hex in unindexed {
            let Ok(group_id_bytes) = hex::decode(&group_id_hex) else {
                continue;
            };
            if group_id_bytes.is_empty() {
                continue;
            }
            let group_id = GroupId::new(group_id_bytes);
            let members = match self.runtime.members(&group_id) {
                Ok(members) => members,
                Err(err) => {
                    if matches!(
                        AppError::from(err).as_engine_error(),
                        Some(cgka_traits::error::EngineError::GroupNotHydrated(_))
                    ) {
                        hydration_pending = true;
                    }
                    continue;
                }
            };
            let member_ids_hex = members
                .iter()
                .map(|member| hex::encode(member.id.as_slice()).to_ascii_lowercase())
                .collect::<Vec<_>>();
            storage.fill_unindexed_direct_conversation_members(&group_id_hex, &member_ids_hex)?;
        }
        if !hydration_pending
            && storage
                .unindexed_direct_conversation_group_ids()?
                .is_empty()
        {
            self.app.mark_account_import_complete(
                &self.state.label,
                crate::DIRECT_CONVERSATION_MEMBERS_BACKFILL_MARKER,
            )?;
        }
        Ok(())
    }

    pub fn accept_group_invite(&mut self, group_id: &GroupId) -> Result<AppGroupRecord, AppError> {
        self.set_group_invite_confirmation(group_id, false, false)
    }

    pub async fn decline_group_invite(
        &mut self,
        group_id: &GroupId,
    ) -> Result<GroupInviteDeclineResult, AppError> {
        let audit_context = Self::local_human_action_context(
            "decline_group_invite",
            vec!["membership"],
            Vec::new(),
            Some(1),
        );
        let summary = self
            .leave_group_with_audit_context(group_id, audit_context)
            .await?;
        let group = self.set_group_invite_confirmation(group_id, false, true)?;
        Ok(GroupInviteDeclineResult { group, summary })
    }

    pub async fn promote_admin(
        &mut self,
        group_id: &GroupId,
        member_ref: &str,
    ) -> Result<SendSummary, AppError> {
        self.ensure_group(group_id)?;
        let member_id = self.app.member_id(member_ref)?;
        let mut admins = self.runtime.admin_pubkeys(group_id)?;
        admins.push(admin_pubkey_from_member_id(&member_id)?);
        let audit_context = Self::local_human_action_context(
            "promote_admin",
            vec!["admins"],
            vec![GROUP_ADMIN_POLICY_COMPONENT_ID],
            Some(1),
        );
        let target_hex = hex::encode(member_id.as_slice());
        self.update_admin_policy(group_id, admins, audit_context, &[target_hex])
            .await
    }

    pub async fn demote_admin(
        &mut self,
        group_id: &GroupId,
        member_ref: &str,
    ) -> Result<SendSummary, AppError> {
        self.ensure_group(group_id)?;
        let member_id = self.app.member_id(member_ref)?;
        let target = admin_pubkey_from_member_id(&member_id)?;
        let mut admins = self.runtime.admin_pubkeys(group_id)?;
        admins.retain(|admin| admin != &target);
        let audit_context = Self::local_human_action_context(
            "demote_admin",
            vec!["admins"],
            vec![GROUP_ADMIN_POLICY_COMPONENT_ID],
            Some(1),
        );
        let target_hex = hex::encode(member_id.as_slice());
        self.update_admin_policy(group_id, admins, audit_context, &[target_hex])
            .await
    }

    pub async fn self_demote_admin(&mut self, group_id: &GroupId) -> Result<SendSummary, AppError> {
        self.ensure_group(group_id)?;
        let account = self.app.account_home().account(&self.state.label)?;
        let local = admin_pubkey_from_account_id_hex(&account.account_id_hex)?;
        let mut admins = self.runtime.admin_pubkeys(group_id)?;
        admins.retain(|admin| admin != &local);
        let audit_context = Self::local_human_action_context(
            "self_demote_admin",
            vec!["admins"],
            vec![GROUP_ADMIN_POLICY_COMPONENT_ID],
            Some(1),
        );
        self.update_admin_policy(
            group_id,
            admins,
            audit_context,
            std::slice::from_ref(&account.account_id_hex),
        )
        .await
    }

    async fn update_admin_policy(
        &mut self,
        group_id: &GroupId,
        admins: Vec<[u8; 32]>,
        audit_context: AuditEventContext,
        wake_targets: &[String],
    ) -> Result<SendSummary, AppError> {
        let component = AppGroupAdminPolicyComponent::new(admins).to_app_component_data()?;

        self.sync_runtime_groups().await?;
        let wake_snapshot = self.snapshot_group_push_tokens_for_members(group_id, wake_targets);
        let effects = self
            .runtime
            .send_with_audit_context(
                SendIntent::UpdateAppComponents {
                    group_id: group_id.clone(),
                    updates: vec![component],
                },
                audit_context.clone(),
            )
            .await?;
        self.observe_recovery_evidence_then_fail_if_publish_failed(&effects)?;
        self.record_human_action_succeeded(group_id, &audit_context, &effects);
        self.remember_published_reports(&effects);
        self.refresh_group(group_id);
        self.save_state_with_pending_local_group_deletion_frontier_clears()?;
        self.queue_own_group_system_projection_updates(&effects);
        self.publish_targeted_group_state_wake_best_effort(
            group_id,
            wake_snapshot,
            &effects.events,
        )
        .await;
        Ok(send_summary_from_effects(&effects))
    }

    pub async fn update_message_retention(
        &mut self,
        group_id: &GroupId,
        disappearing_message_secs: u64,
    ) -> Result<SendSummary, AppError> {
        self.ensure_group(group_id)?;
        let component = AppGroupMessageRetentionComponent::new(disappearing_message_secs)
            .to_app_component_data()?;
        let audit_context = Self::local_human_action_context(
            "update_message_retention",
            vec!["message_retention"],
            vec![GROUP_MESSAGE_RETENTION_COMPONENT_ID],
            None,
        );

        self.sync_runtime_groups().await?;
        let effects = self
            .runtime
            .send_with_audit_context(
                SendIntent::UpdateAppComponents {
                    group_id: group_id.clone(),
                    updates: vec![component],
                },
                audit_context.clone(),
            )
            .await?;
        self.observe_recovery_evidence_then_fail_if_publish_failed(&effects)?;
        self.record_human_action_succeeded(group_id, &audit_context, &effects);
        self.remember_published_reports(&effects);
        self.refresh_group(group_id);
        self.prune_plaintext_retention_for_group(group_id)?;
        self.save_state_with_pending_local_group_deletion_frontier_clears()?;
        self.queue_own_group_system_projection_updates(&effects);
        Ok(send_summary_from_effects(&effects))
    }

    pub async fn replace_encrypted_media_blob_endpoints(
        &mut self,
        group_id: &GroupId,
        endpoints: Vec<AppBlobEndpoint>,
    ) -> Result<SendSummary, AppError> {
        self.ensure_group(group_id)?;
        let endpoint_count = endpoints.len() as u64;
        let mut allowed_locator_kinds = Vec::new();
        for endpoint in &endpoints {
            if !allowed_locator_kinds
                .iter()
                .any(|kind| kind == &endpoint.locator_kind)
            {
                allowed_locator_kinds.push(endpoint.locator_kind.clone());
            }
        }
        let existing = self.encrypted_media_policy_for_group(group_id)?;
        let component = match existing.version {
            EncryptedMediaVersion::V1 => AppGroupEncryptedMediaComponent::new_v1(
                EncryptedMediaPolicyV1::new(
                    ENCRYPTED_MEDIA_FORMAT_V1.to_owned(),
                    allowed_locator_kinds,
                    endpoints.into_iter().map(|endpoint| BlobStoreEndpointV1 {
                        locator_kind: endpoint.locator_kind,
                        base_url: endpoint.base_url,
                    }),
                    true,
                )
                .map_err(AppError::InvalidEncryptedMedia)?,
            )?,
            EncryptedMediaVersion::V2 => AppGroupEncryptedMediaComponent::new_v2(
                EncryptedMediaPolicyV2::new(
                    ENCRYPTED_MEDIA_FORMAT_V2.to_owned(),
                    allowed_locator_kinds,
                    endpoints.into_iter().map(|endpoint| BlobStoreEndpointV2 {
                        locator_kind: endpoint.locator_kind,
                        base_url: endpoint.base_url,
                    }),
                )
                .map_err(AppError::InvalidEncryptedMedia)?,
            )?,
        }
        .to_app_component_data()?;
        let audit_context = Self::local_human_action_context(
            "replace_encrypted_media_blob_endpoints",
            vec!["encrypted_media"],
            vec![existing.component_id],
            Some(endpoint_count),
        );

        self.sync_runtime_groups().await?;
        let effects = self
            .runtime
            .send_with_audit_context(
                SendIntent::UpdateAppComponents {
                    group_id: group_id.clone(),
                    updates: vec![component],
                },
                audit_context.clone(),
            )
            .await?;
        self.observe_recovery_evidence_then_fail_if_publish_failed(&effects)?;
        self.record_human_action_succeeded(group_id, &audit_context, &effects);
        self.remember_published_reports(&effects);
        self.refresh_group(group_id);
        self.save_state_with_pending_local_group_deletion_frontier_clears()?;
        self.queue_own_group_system_projection_updates(&effects);
        Ok(send_summary_from_effects(&effects))
    }

    /// Set (or clear) the group's URL-based avatar (`marmot.group.avatar-url.v1`).
    /// Passing `url = None` clears the avatar to the absent state. The URL is
    /// validated and normalized before it is committed.
    pub async fn update_group_avatar_url(
        &mut self,
        group_id: &GroupId,
        url: Option<String>,
        dim: Option<String>,
        thumbhash: Option<String>,
    ) -> Result<SendSummary, AppError> {
        self.ensure_group(group_id)?;
        let component = match url {
            Some(url) if !url.is_empty() => {
                AppGroupAvatarUrlComponent::new(url, dim, thumbhash)?.to_app_component_data()?
            }
            _ => AppGroupAvatarUrlComponent::absent().to_app_component_data()?,
        };
        let audit_context = Self::local_human_action_context(
            "update_group_avatar_url",
            vec!["avatar_url"],
            vec![GROUP_AVATAR_URL_COMPONENT_ID],
            None,
        );

        self.sync_runtime_groups().await?;
        let effects = self
            .runtime
            .send_with_audit_context(
                SendIntent::UpdateAppComponents {
                    group_id: group_id.clone(),
                    updates: vec![component],
                },
                audit_context.clone(),
            )
            .await?;
        self.observe_recovery_evidence_then_fail_if_publish_failed(&effects)?;
        self.record_human_action_succeeded(group_id, &audit_context, &effects);
        self.remember_published_reports(&effects);
        self.refresh_group(group_id);
        self.save_state_with_pending_local_group_deletion_frontier_clears()?;
        self.queue_own_group_system_projection_updates(&effects);
        Ok(send_summary_from_effects(&effects))
    }

    pub async fn send(
        &mut self,
        group_id: &GroupId,
        payload: &[u8],
    ) -> Result<SendSummary, AppError> {
        self.send_with_local_projection(group_id, payload, |_| {})
            .await
    }

    pub(crate) async fn send_with_local_projection<F>(
        &mut self,
        group_id: &GroupId,
        payload: &[u8],
        on_local_projection: F,
    ) -> Result<SendSummary, AppError>
    where
        F: FnMut(crate::AppProjectionUpdate),
    {
        // The transport-facing `send` carries plain UTF-8 chat text; structured
        // payloads use `send_app_event` with a typed intent.
        let content = String::from_utf8(payload.to_vec()).map_err(|_| {
            AppError::InvalidAppMessagePayload("chat message must be valid UTF-8".into())
        })?;
        let (_event, summary) = self
            .send_app_event_with_local_projection(
                group_id,
                AppMessageIntent::Chat { content },
                on_local_projection,
            )
            .await?;
        Ok(summary)
    }

    /// Build, encrypt, send, and project the inner Marmot app event for `intent`.
    /// Returns the built event so callers (agent-stream start/finish) can surface
    /// its tags. The authoring account id and clock are resolved here so the
    /// inner `pubkey` always equals the MLS-authenticated sender.
    pub(crate) async fn send_app_event(
        &mut self,
        group_id: &GroupId,
        intent: AppMessageIntent,
    ) -> Result<(MarmotInnerEvent, SendSummary), AppError> {
        self.send_app_event_with_local_projection(group_id, intent, |_| {})
            .await
    }

    pub(crate) async fn send_app_event_with_local_projection<F>(
        &mut self,
        group_id: &GroupId,
        intent: AppMessageIntent,
        mut on_local_projection: F,
    ) -> Result<(MarmotInnerEvent, SendSummary), AppError>
    where
        F: FnMut(crate::AppProjectionUpdate),
    {
        self.ensure_group_application_messages_allowed(group_id)?;
        // Capture the human-action descriptor before `Unreact` is rewritten to
        // `DeleteReactions` below, so the audit log records the user's actual
        // intent.
        let audit_context = Self::message_human_action_context(&intent);
        let sender = self
            .app
            .account_home()
            .account(&self.state.label)?
            .account_id_hex;
        // NIP-25 has no native un-react: kind-7 reactions are retracted with a
        // kind-5 delete. Resolve every matching active own reaction from the
        // projection and place all ids in one tombstone so remove-all is atomic.
        let intent = match intent {
            AppMessageIntent::Unreact {
                target_message_id,
                emoji,
            } => {
                if let Some(emoji) = emoji.as_deref() {
                    crate::messages::validate_reaction_content(emoji)?;
                }
                let reaction_message_ids = self.own_reaction_event_ids(
                    group_id,
                    &sender,
                    &target_message_id,
                    emoji.as_deref(),
                )?;
                AppMessageIntent::DeleteReactions {
                    reaction_message_ids,
                }
            }
            other => other,
        };
        let event = build_inner_event(&intent, &sender, unix_now_seconds())?;
        let payload = encode_inner_event(&event)?;
        let group_id_hex = hex::encode(group_id.as_slice());
        let app_event_id = event.id.clone();

        let should_project_locally = !notifications::is_push_gossip_kind(event.kind);
        if should_project_locally {
            let update = self
                .record_local_app_event_projection(group_id, &sender, &event, None, None, false)?;
            on_local_projection(update);
        }

        let send_result = match self.sync_runtime_groups().await {
            Ok(()) => {
                let send_intent = SendIntent::AppMessage {
                    group_id: group_id.clone(),
                    payload,
                };
                // Thread the human-action context through the engine so the
                // send's audit rows carry `human_action`, matching
                // create_group/invite/etc.
                match &audit_context {
                    Some(context) => {
                        self.runtime
                            .send_with_audit_context(send_intent, context.clone())
                            .await
                    }
                    None => self.runtime.send(send_intent).await,
                }
                .map_err(AppError::from)
            }
            Err(error) if error.is_account_not_active() => {
                let context = audit_context.clone().unwrap_or_default();
                self.runtime
                    .queue_app_message_with_audit_context(group_id.clone(), payload, context)
                    .await
                    .map_err(AppError::from)
            }
            Err(error) => Err(error),
        };
        // The publish-status gate is applied separately from obtaining the
        // effects: even when the outbound publish hard-fails, the engine may
        // already have folded retained peer commits into this send, and those
        // applied `GroupStateChanged` / `EpochChanged` events must still be
        // observed and broadcast — only the local message is retracted.
        let effects = match send_result {
            Ok(effects) => effects,
            Err(err) => {
                self.retract_failed_local_projection(
                    should_project_locally,
                    &group_id_hex,
                    &app_event_id,
                    &mut on_local_projection,
                );
                return Err(err);
            }
        };
        if let Err(publish_err) = self
            .observe_recovery_evidence_then_gate_send_publish(&effects)
            .await
        {
            self.retract_failed_local_projection(
                should_project_locally,
                &group_id_hex,
                &app_event_id,
                &mut on_local_projection,
            );
            return Err(publish_err);
        }
        if let Some(context) = &audit_context {
            self.record_human_action_succeeded(group_id, context, &effects);
        }
        self.remember_published_reports(&effects);
        // Discarded deliberately, unlike on the convergence-retry path: the
        // re-record below reprojects the same row with its new source id and
        // hands that update to `on_local_projection`, so forwarding these too
        // would emit the flip twice.
        let _finalize_updates = self.finalize_published_app_message_source_retention(&effects)?;
        let published = effects.published_app_messages.iter().find(|published| {
            published.group_id == *group_id && published.app_event_id == app_event_id
        });
        let completion_unknown = effects.unresolved_app_messages.iter().any(|unresolved| {
            unresolved.group_id == *group_id && unresolved.app_event_id == app_event_id
        });
        let source_message_id_hex =
            published.map(|published| hex::encode(published.message_id.as_slice()));
        let source_state =
            published.map(|published| (published.source_epoch.0, published.retention));
        if should_project_locally {
            let update = self.record_local_app_event_projection(
                group_id,
                &sender,
                &event,
                source_message_id_hex,
                source_state,
                published.is_some(),
            )?;
            on_local_projection(update);
            self.prune_plaintext_retention_for_group(group_id)?;
        }
        // A send that lands while inbound convergence input is retained folds
        // those commits before publishing, so `effects.events` can carry peer
        // state changes (e.g. a mid-window group rename). Observe them through
        // the same pipeline as inbound deliveries — state group refresh plus
        // kind-1210 system-row synthesis (replacing the narrower
        // `queue_own_group_system_projection_updates`) — and buffer the summary
        // for the account worker to broadcast; dropping the events here leaves
        // storage renamed while chat-list/group-state subscribers never wake.
        // Best-effort: a projection failure must not fail a completed publish.
        self.observe_send_applied_effects_best_effort(&effects)
            .await;
        self.save_state_with_pending_local_group_deletion_frontier_clears()?;
        if published.is_some() && notification_trigger_for_intent(&intent).is_some() {
            self.publish_notification_trigger_best_effort(
                group_id,
                notifications::NotificationTrigger::NewMessage,
            )
            .await;
        }
        Ok((
            event,
            SendSummary {
                published: usize::from(published.is_some()),
                message_ids: vec![app_event_id],
                // Per-message, not per-pass: `published` above matched this
                // exact `app_event_id` in `effects.published_app_messages`. A
                // send that folded peer commits can publish other work in the
                // same pass, so counting `effects.reports` or the group-wide
                // queue would misreport this row. Absent means the engine
                // accepted and retained it (mdk#1177).
                accept_disposition: if published.is_some() {
                    cgka_traits::SendAcceptDisposition::Published
                } else if completion_unknown {
                    cgka_traits::SendAcceptDisposition::CompletionUnknown
                } else {
                    cgka_traits::SendAcceptDisposition::AcceptedPending
                },
                maintenance_disposition: effects.maintenance_disposition,
            },
        ))
    }

    /// Apply the publish gate to a completed send's effects — observing the same
    /// batch's epoch-gap recovery evidence first — and, when the gate fails,
    /// broadcast the peer commits the send folded before the caller surfaces the
    /// error.
    ///
    /// Split out of `send_app_event_with_local_projection` so the ordering is
    /// exercisable against a given batch of effects. The caller keeps the
    /// local-projection retraction, which needs that send's own locals.
    pub(crate) async fn observe_recovery_evidence_then_gate_send_publish(
        &mut self,
        effects: &marmot_account::AccountDeviceEffects,
    ) -> Result<(), AppError> {
        let publish_err = match self.observe_recovery_evidence_then_fail_if_publish_failed(effects)
        {
            Ok(()) => return Ok(()),
            Err(publish_err) => publish_err,
        };
        // The send itself failed to reach anyone, but any peer commits it
        // folded are durably applied — broadcast them before surfacing the
        // publish failure, best-effort so a projection error cannot mask
        // the primary error.
        self.observe_send_applied_effects_best_effort(effects).await;
        if let Err(_save_err) = self.save_state_with_pending_local_group_deletion_frontier_clears()
        {
            tracing::warn!(
                target: "marmot_app::messages",
                method = "send_app_event_with_local_projection",
                error_code = "send_applied_state_save_failed",
                "failed to persist state observed from a failed send"
            );
        }
        Err(publish_err)
    }

    /// Retract the optimistic local timeline row for a send that failed. No
    /// read-marker rollback is needed: the marker only advances in the
    /// post-publish success projection.
    fn retract_failed_local_projection<F>(
        &mut self,
        should_project_locally: bool,
        group_id_hex: &str,
        app_event_id: &str,
        on_local_projection: &mut F,
    ) where
        F: FnMut(crate::AppProjectionUpdate),
    {
        if !should_project_locally {
            return;
        }
        match self.app.invalidate_timeline_app_event(
            &self.state.label,
            group_id_hex,
            app_event_id,
            crate::LOCAL_PUBLISH_FAILED_REASON,
        ) {
            Ok(Some(update)) => on_local_projection(update),
            Ok(None) => {}
            Err(_) => {
                tracing::warn!(
                    target: "marmot_app::messages",
                    method = "send_app_event_with_local_projection",
                    error_code = "local_projection_retract_failed",
                    "failed to retract local projection after publish failure"
                );
            }
        }
    }

    /// Active reactions this account authored on `target_message_id`, filtered
    /// by exact content when requested and identified by their message ids.
    fn own_reaction_event_ids(
        &self,
        group_id: &GroupId,
        sender: &str,
        target_message_id: &str,
        emoji: Option<&str>,
    ) -> Result<Vec<String>, AppError> {
        let group_id_hex = hex::encode(group_id.as_slice());
        let reaction_message_ids = self
            .app
            .timeline_message(&self.state.label, &group_id_hex, target_message_id)?
            .map(|message| {
                message
                    .reactions
                    .user_reactions
                    .into_iter()
                    .filter(|reaction| {
                        reaction.sender == sender
                            && emoji.is_none_or(|expected| reaction.emoji == expected)
                    })
                    .map(|reaction| reaction.reaction_message_id_hex)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if reaction_message_ids.is_empty() {
            Err(AppError::ReactionNotFound)
        } else {
            Ok(reaction_message_ids)
        }
    }

    pub async fn react_to_message(
        &mut self,
        group_id: &GroupId,
        target_message_id: &str,
        emoji: &str,
    ) -> Result<SendSummary, AppError> {
        self.react_to_message_with_local_projection(group_id, target_message_id, emoji, |_| {})
            .await
    }

    pub(crate) async fn react_to_message_with_local_projection<F>(
        &mut self,
        group_id: &GroupId,
        target_message_id: &str,
        emoji: &str,
        on_local_projection: F,
    ) -> Result<SendSummary, AppError>
    where
        F: FnMut(crate::AppProjectionUpdate),
    {
        self.ensure_group_application_messages_allowed(group_id)?;
        crate::messages::validate_reaction_content(emoji)?;
        let sender = self
            .app
            .account_home()
            .account(&self.state.label)?
            .account_id_hex;
        match self.own_reaction_event_ids(group_id, &sender, target_message_id, Some(emoji)) {
            Ok(existing) => {
                let existing_id = existing.last().expect("non-empty reaction ids").clone();
                if let Some(context) =
                    Self::message_human_action_context(&AppMessageIntent::Reaction {
                        target_message_id: target_message_id.to_owned(),
                        emoji: emoji.to_owned(),
                    })
                {
                    self.record_human_action_noop_succeeded(
                        group_id,
                        &context,
                        vec![existing_id.clone()],
                    );
                }
                return Ok(SendSummary {
                    published: 0,
                    message_ids: vec![existing_id],
                    // Idempotent no-op, not a retained intent: the reaction is
                    // already canonical group output and `message_ids` names
                    // it. Nothing is being held for a later drain, so there is
                    // nothing pending to report (mdk#1177).
                    accept_disposition: cgka_traits::SendAcceptDisposition::Published,
                    maintenance_disposition: cgka_traits::SendMaintenanceDisposition::Ready,
                });
            }
            Err(AppError::ReactionNotFound) => {}
            Err(error) => return Err(error),
        }
        let (_event, summary) = self
            .send_app_event_with_local_projection(
                group_id,
                AppMessageIntent::Reaction {
                    target_message_id: target_message_id.to_owned(),
                    emoji: emoji.to_owned(),
                },
                on_local_projection,
            )
            .await?;
        Ok(summary)
    }

    pub async fn unreact_from_message(
        &mut self,
        group_id: &GroupId,
        target_message_id: &str,
    ) -> Result<SendSummary, AppError> {
        self.unreact_from_message_matching(group_id, target_message_id, None)
            .await
    }

    pub async fn unreact_from_message_matching(
        &mut self,
        group_id: &GroupId,
        target_message_id: &str,
        emoji: Option<&str>,
    ) -> Result<SendSummary, AppError> {
        if let Some(emoji) = emoji {
            crate::messages::validate_reaction_content(emoji)?;
        }
        let (_event, summary) = self
            .send_app_event(
                group_id,
                AppMessageIntent::Unreact {
                    target_message_id: target_message_id.to_owned(),
                    emoji: emoji.map(str::to_owned),
                },
            )
            .await?;
        Ok(summary)
    }

    pub async fn delete_message(
        &mut self,
        group_id: &GroupId,
        target_message_id: &str,
    ) -> Result<SendSummary, AppError> {
        let (_event, summary) = self
            .send_app_event(
                group_id,
                AppMessageIntent::Delete {
                    target_message_id: target_message_id.to_owned(),
                },
            )
            .await?;
        Ok(summary)
    }

    pub async fn reply_to_message(
        &mut self,
        group_id: &GroupId,
        target_message_id: &str,
        text: &str,
    ) -> Result<SendSummary, AppError> {
        let (_event, summary) = self
            .send_app_event(
                group_id,
                AppMessageIntent::Reply {
                    target_message_id: target_message_id.to_owned(),
                    text: text.to_owned(),
                },
            )
            .await?;
        Ok(summary)
    }

    pub async fn send_media_attachments(
        &mut self,
        group_id: &GroupId,
        attachments: Vec<MediaAttachmentReference>,
        caption: Option<String>,
    ) -> Result<SendSummary, AppError> {
        self.ensure_group_application_messages_allowed(group_id)?;
        self.sync_runtime_groups().await?;
        // Validate every outbound attachment against the group's exact,
        // profile-selected media version and locator policy.
        let policy = self.encrypted_media_policy_for_group(group_id)?;
        for attachment in &attachments {
            attachment.validate_outbound(
                policy.version,
                &policy.allowed_locator_kinds,
                self.app.allow_loopback_blob_endpoints(),
            )?;
        }
        let (_event, summary) = self
            .send_app_event(
                group_id,
                AppMessageIntent::Media {
                    attachments,
                    caption,
                },
            )
            .await?;
        Ok(summary)
    }

    /// Build one outbound encrypted-media `imeta` tag using the target
    /// group's actual profile-selected media version and locator policy.
    ///
    /// This is the checked bridge used by host apps for optimistic message
    /// records. It deliberately performs no publish.
    pub async fn build_media_imeta_tag(
        &mut self,
        group_id: &GroupId,
        reference: &MediaAttachmentReference,
    ) -> Result<Vec<String>, AppError> {
        self.ensure_group_application_messages_allowed(group_id)?;
        self.sync_runtime_groups().await?;
        let policy = self.encrypted_media_policy_for_group(group_id)?;
        reference.build_imeta_tag(
            policy.version,
            &policy.allowed_locator_kinds,
            self.app.allow_loopback_blob_endpoints(),
        )
    }

    pub async fn upload_media(
        &mut self,
        group_id: &GroupId,
        request: MediaUploadRequest,
    ) -> Result<MediaUploadResult, AppError> {
        let (http, finish) = self
            .prepare_encrypted_media_upload(group_id, request)
            .await?;
        let result = http.run().await?;
        self.finish_encrypted_media_upload(finish, result).await
    }

    /// Cheap exclusive-client setup for an encrypted-media upload. The returned
    /// HTTP job must run without holding `&mut AppClient` so the account worker
    /// can keep polling inbound delivery.
    pub(crate) async fn prepare_encrypted_media_upload(
        &mut self,
        group_id: &GroupId,
        request: MediaUploadRequest,
    ) -> Result<(EncryptedMediaUploadHttp, EncryptedMediaUploadFinish), AppError> {
        self.ensure_group_application_messages_allowed(group_id)?;
        self.sync_runtime_groups().await?;
        let policy = self.encrypted_media_policy_for_group(group_id)?;
        // `upload_encrypted_media` always performs Blossom upload semantics and
        // emits a `blossom-v1` locator, so every default upload candidate MUST be
        // a Blossom endpoint. Iterate all usable candidates in policy order so a
        // single server outage does not fail the send. Skip loopback-HTTP policy
        // endpoints unless this build is configured for dev/test: they are valid
        // component state but a production client MUST NOT upload to the local
        // host (a remote admin could point the policy at the victim's loopback
        // services). An explicit per-request `blossom_server` override is an
        // intentional single-server dev escape hatch: it bypasses endpoint
        // failover, but the group policy must still allow `blossom-v1` locators.
        let allow_loopback = self.app.allow_loopback_blob_endpoints();
        let policy_allows_blossom = policy.allowed_locator_kinds.is_empty()
            || policy
                .allowed_locator_kinds
                .iter()
                .any(|kind| kind == BLOSSOM_LOCATOR_KIND_V1);
        if !policy_allows_blossom {
            return Err(AppError::InvalidEncryptedMedia(
                "group policy has no usable Blossom endpoint for upload".into(),
            ));
        }
        let has_explicit_server = request.blossom_server.is_some();
        let default_endpoints = if has_explicit_server {
            Vec::new()
        } else {
            let endpoints = policy
                .default_blob_endpoints
                .iter()
                .filter(|endpoint| {
                    endpoint.locator_kind == BLOSSOM_LOCATOR_KIND_V1
                        && (allow_loopback || !is_loopback_http_endpoint(&endpoint.base_url))
                })
                .cloned()
                .collect::<Vec<_>>();
            if endpoints.is_empty() {
                return Err(AppError::InvalidEncryptedMedia(
                    "group policy has no usable Blossom endpoint for upload".into(),
                ));
            }
            endpoints
        };
        let (source_epoch, media_secret) = self.encrypted_media_secret(group_id)?;
        let account = self.app.account_home().account(&self.state.label)?;
        let signer = self.app.account_signer_for_summary(&account)?;
        let should_send = request.send;
        let caption = request.caption.clone();
        Ok((
            EncryptedMediaUploadHttp {
                request,
                source_epoch,
                media_secret: media_secret.clone(),
                nostr_signer: signer.as_nostr_signer(),
                version: policy.version,
                default_endpoints,
                allowed_locator_kinds: policy.allowed_locator_kinds,
                allow_loopback_http: allow_loopback,
            },
            EncryptedMediaUploadFinish {
                group_id: group_id.clone(),
                source_epoch,
                media_secret,
                should_send,
                caption,
            },
        ))
    }

    pub(crate) async fn finish_encrypted_media_upload(
        &mut self,
        finish: EncryptedMediaUploadFinish,
        mut result: MediaUploadResult,
    ) -> Result<MediaUploadResult, AppError> {
        if !finish.should_send {
            return Ok(result);
        }
        let attachments = result
            .attachments
            .iter()
            .map(|attachment| attachment.reference.clone())
            .collect();
        let summary = self
            .send_media_attachments(&finish.group_id, attachments, finish.caption)
            .await?;
        // The post-publish projection now durably references this source
        // epoch. Persist again so a prior final-reference retirement cannot
        // suppress the secret needed by the newly retained message.
        if self
            .remember_encrypted_media_epoch_secret(
                &finish.group_id,
                finish.source_epoch,
                finish.media_secret.as_ref(),
            )
            .is_err()
        {
            // Publication already succeeded. Do not report a false send
            // failure that could make the caller publish a duplicate; the
            // normal current-epoch cache pass can retry this durable write.
            tracing::warn!(
                target: "marmot_app::media",
                method = "finish_encrypted_media_upload",
                error_code = "encrypted_media_secret_cache_skipped",
                "failed to cache encrypted media source epoch secret after publish",
            );
        }
        result.sent = Some(summary);
        Ok(result)
    }

    pub async fn download_media(
        &mut self,
        group_id: &GroupId,
        reference: MediaAttachmentReference,
    ) -> Result<MediaDownloadResult, AppError> {
        self.prepare_encrypted_media_download(group_id, reference)
            .await?
            .run()
            .await
    }

    pub(crate) async fn prepare_encrypted_media_download(
        &mut self,
        group_id: &GroupId,
        reference: MediaAttachmentReference,
    ) -> Result<EncryptedMediaDownloadHttp, AppError> {
        self.ensure_group(group_id)?;
        self.sync_runtime_groups().await?;
        let policy = self.encrypted_media_policy_for_group(group_id)?;
        // The current group policy governs fetch endpoints, but the retained
        // attachment's own version governs KDF/AAD and which versioned cache
        // row contains its source-epoch exporter. Adopted V1 -> V2 migration
        // deliberately leaves historical V1 references as V1.
        let reference_version = EncryptedMediaVersion::parse(&reference.version)?;
        let media_secret = self.encrypted_media_secret_for_epoch(
            group_id,
            reference.source_epoch,
            reference_version.component_id(),
        )?;
        Ok(EncryptedMediaDownloadHttp {
            reference,
            media_secret,
            default_blob_endpoints: policy.default_blob_endpoints,
            allowed_locator_kinds: policy.allowed_locator_kinds,
            allow_loopback: self.app.allow_loopback_blob_endpoints(),
        })
    }

    /// Encrypt + upload a group avatar to Blossom, then publish the
    /// `marmot.group.blossom.image.v1` component via an MLS commit. Admin
    /// authorization is enforced by the engine on send. Passing an empty
    /// `plaintext` clears the image.
    pub async fn update_group_image(
        &mut self,
        group_id: &GroupId,
        plaintext: Vec<u8>,
        media_type: &str,
    ) -> Result<SendSummary, AppError> {
        self.ensure_group_application_messages_allowed(group_id)?;
        let audit_context = Self::local_human_action_context(
            "update_group_image",
            vec!["image"],
            vec![GROUP_BLOSSOM_IMAGE_COMPONENT_ID],
            None,
        );
        self.sync_runtime_groups().await?;
        let input = if plaintext.is_empty() {
            AppGroupImageInput::default()
        } else {
            let upload = upload_group_image(&plaintext, media_type, None).await?;
            AppGroupImageInput::from(upload)
        };
        let data = hex::decode(AppGroupImageComponent::new(input).data_hex)?;
        let effects = self
            .runtime
            .send_with_audit_context(
                SendIntent::UpdateAppComponents {
                    group_id: group_id.clone(),
                    updates: vec![AppComponentData {
                        component_id: GROUP_BLOSSOM_IMAGE_COMPONENT_ID,
                        data,
                    }],
                },
                audit_context.clone(),
            )
            .await?;
        self.observe_recovery_evidence_then_fail_if_publish_failed(&effects)?;
        self.record_human_action_succeeded(group_id, &audit_context, &effects);
        self.remember_published_reports(&effects);
        let summary = send_summary_from_effects(&effects);
        self.refresh_group(group_id);
        self.save_state_with_pending_local_group_deletion_frontier_clears()?;
        self.queue_own_group_system_projection_updates(&effects);
        Ok(summary)
    }

    /// Fetch + decrypt the group's avatar. Errors when the group has no image set.
    pub async fn download_group_blossom_image(
        &mut self,
        group_id: &GroupId,
    ) -> Result<Vec<u8>, AppError> {
        self.prepare_group_image_download(group_id)
            .await?
            .run()
            .await
    }

    pub(crate) async fn prepare_group_image_download(
        &mut self,
        group_id: &GroupId,
    ) -> Result<GroupImageDownloadHttp, AppError> {
        self.ensure_group(group_id)?;
        self.sync_runtime_groups().await?;
        let input = self.image_for_group(group_id);
        if !input.is_present() {
            return Err(AppError::InvalidEncryptedMedia(
                "group has no image set".into(),
            ));
        }
        Ok(GroupImageDownloadHttp {
            image_hash_hex: input.image_hash_hex,
            image_key_hex: input.image_key_hex,
            image_nonce_hex: input.image_nonce_hex,
            media_type: input.media_type.unwrap_or_default(),
        })
    }

    pub async fn start_agent_text_stream(
        &mut self,
        group_id: &GroupId,
        stream_id: &[u8],
        quic_candidates: Vec<String>,
    ) -> Result<(MarmotInnerEvent, SendSummary), AppError> {
        self.start_agent_text_stream_with_parent(group_id, stream_id, None, quic_candidates)
            .await
    }

    pub async fn start_agent_text_stream_with_parent(
        &mut self,
        group_id: &GroupId,
        stream_id: &[u8],
        parent_message_id: Option<String>,
        quic_candidates: Vec<String>,
    ) -> Result<(MarmotInnerEvent, SendSummary), AppError> {
        self.start_agent_text_stream_with_local_projection(
            group_id,
            stream_id,
            parent_message_id,
            quic_candidates,
            |_| {},
        )
        .await
    }

    pub(crate) async fn start_agent_text_stream_with_local_projection<F>(
        &mut self,
        group_id: &GroupId,
        stream_id: &[u8],
        parent_message_id: Option<String>,
        quic_candidates: Vec<String>,
        on_local_projection: F,
    ) -> Result<(MarmotInnerEvent, SendSummary), AppError>
    where
        F: FnMut(crate::AppProjectionUpdate),
    {
        self.send_app_event_with_local_projection(
            group_id,
            AppMessageIntent::StreamStart {
                stream_id: stream_id.to_vec(),
                parent_message_id,
                quic_candidates,
            },
            on_local_projection,
        )
        .await
    }

    pub async fn finish_agent_text_stream(
        &mut self,
        group_id: &GroupId,
        request: AgentTextStreamFinishRequest,
    ) -> Result<(MarmotInnerEvent, SendSummary), AppError> {
        self.finish_agent_text_stream_with_local_projection(group_id, request, |_| {})
            .await
    }

    pub(crate) async fn finish_agent_text_stream_with_local_projection<F>(
        &mut self,
        group_id: &GroupId,
        request: AgentTextStreamFinishRequest,
        on_local_projection: F,
    ) -> Result<(MarmotInnerEvent, SendSummary), AppError>
    where
        F: FnMut(crate::AppProjectionUpdate),
    {
        self.send_app_event_with_local_projection(
            group_id,
            AppMessageIntent::StreamFinal { request },
            on_local_projection,
        )
        .await
    }

    pub async fn send_agent_activity(
        &mut self,
        group_id: &GroupId,
        status: String,
        text: String,
        reply_to_message_id: Option<String>,
        extra: Option<serde_json::Value>,
    ) -> Result<SendSummary, AppError> {
        let (_event, summary) = self
            .send_app_event(
                group_id,
                AppMessageIntent::AgentActivity {
                    status,
                    text,
                    reply_to_message_id,
                    extra,
                },
            )
            .await?;
        Ok(summary)
    }

    pub async fn send_agent_operation_event(
        &mut self,
        group_id: &GroupId,
        request: AgentOperationEventRequest,
    ) -> Result<SendSummary, AppError> {
        let AgentOperationEventRequest {
            event_type,
            status,
            operation_id,
            run_id,
            turn_id,
            name,
            text,
            preview,
            details,
            sequence,
            ok,
            duration_ms,
            reply_to_message_id,
        } = request;
        let (_event, summary) = self
            .send_app_event(
                group_id,
                AppMessageIntent::AgentOperation {
                    event_type,
                    status,
                    operation_id,
                    run_id,
                    turn_id,
                    name,
                    text,
                    preview,
                    details,
                    sequence,
                    ok,
                    duration_ms,
                    reply_to_message_id,
                },
            )
            .await?;
        Ok(summary)
    }

    pub async fn send_group_system_event(
        &mut self,
        group_id: &GroupId,
        system_type: String,
        text: String,
        data: Option<serde_json::Value>,
    ) -> Result<SendSummary, AppError> {
        let (_event, summary) = self
            .send_app_event(
                group_id,
                AppMessageIntent::GroupSystem {
                    system_type,
                    text,
                    data,
                },
            )
            .await?;
        Ok(summary)
    }

    /// Send an app-defined event with an arbitrary non-reserved kind. `tags`
    /// and `content` pass through verbatim; kinds MDK owns (chat, reaction,
    /// edit, delete, agent, group system, push token) are rejected so an app
    /// cannot forge protocol events.
    pub async fn send_custom_event(
        &mut self,
        group_id: &GroupId,
        kind: u64,
        tags: Vec<Vec<String>>,
        content: String,
    ) -> Result<SendSummary, AppError> {
        let (_event, summary) = self
            .send_app_event(
                group_id,
                AppMessageIntent::Custom {
                    kind,
                    tags,
                    content,
                },
            )
            .await?;
        Ok(summary)
    }

    pub async fn retry_group_convergence(
        &mut self,
        group_id: &GroupId,
    ) -> Result<SendSummary, AppError> {
        self.ensure_group(group_id)?;

        self.sync_runtime_groups().await?;
        let effects = self.runtime.advance_convergence(group_id).await?;
        self.observe_convergence_retry_effects(group_id, &effects)
    }

    /// Project one convergence retry's effects, split from the advance itself so
    /// the projection is exercisable against a given batch of effects.
    pub(crate) fn observe_convergence_retry_effects(
        &mut self,
        group_id: &GroupId,
        effects: &marmot_account::AccountDeviceEffects,
    ) -> Result<SendSummary, AppError> {
        // Observe before the publish gate, for the reason spelled out in
        // `observe_drained_session_events`.
        self.observe_recovery_evidence(effects);
        fail_if_publish_failed(effects)?;
        self.remember_published_reports(effects);
        // This is the path that releases sends the engine had retained, so its
        // finalize updates carry the pending -> delivered flip for each of them.
        // Unlike the send path — which drops the same updates because it
        // immediately re-records the row and hands that update to the caller —
        // there is nothing here to re-emit them, so buffer them for the account
        // worker to broadcast. Dropping them leaves storage delivered while
        // every timeline and chat-list subscriber still shows pending.
        let finalize_updates = self.finalize_published_app_message_source_retention(effects)?;
        self.pending_projection_updates.extend(finalize_updates);
        self.refresh_group(group_id);
        self.prune_plaintext_retention_for_group(group_id)?;
        self.save_state_with_pending_local_group_deletion_frontier_clears()?;
        self.queue_own_group_system_projection_updates(effects);
        Ok(send_summary_from_effects(effects))
    }

    pub async fn update_group_profile(
        &mut self,
        group_id: &GroupId,
        name: Option<&str>,
        description: Option<&str>,
    ) -> Result<SendSummary, AppError> {
        if name.is_none() && description.is_none() {
            return Err(AppError::InvalidGroupProfile(
                "name or description is required".into(),
            ));
        }
        validate_group_profile(name.unwrap_or(""), description.unwrap_or(""))?;
        self.ensure_group(group_id)?;
        let mut fields = Vec::new();
        if name.is_some() {
            fields.push("name");
        }
        if description.is_some() {
            fields.push("description");
        }
        let audit_context = Self::local_human_action_context(
            "update_group_profile",
            fields,
            vec![GROUP_PROFILE_COMPONENT_ID],
            None,
        );

        self.sync_runtime_groups().await?;
        let effects = self
            .runtime
            .send_with_audit_context(
                SendIntent::UpdateGroupData {
                    group_id: group_id.clone(),
                    name: name.map(ToOwned::to_owned),
                    description: description.map(ToOwned::to_owned),
                },
                audit_context.clone(),
            )
            .await?;
        self.observe_recovery_evidence_then_fail_if_publish_failed(&effects)?;
        self.record_human_action_succeeded(group_id, &audit_context, &effects);
        self.remember_published_reports(&effects);
        let group_metadata = self.runtime.group_record(group_id).ok();
        let nostr_routing = self.nostr_routing_for_group(group_id)?;
        let projection = EventGroupProjection {
            nostr_routing,
            group_metadata: group_metadata.as_ref(),
            profile: self.profile_for_group(group_id),
            admin_policy: self.admin_policy_for_group(group_id),
            message_retention: self.message_retention_for_group(group_id),
            agent_text_stream: self.agent_text_stream_for_group(group_id),
            avatar_url: self.avatar_url_for_group(group_id),
            encrypted_media: self.encrypted_media_for_group(group_id),
            image: self.image_for_group(group_id),
        };
        add_group(
            &mut self.state,
            group_id,
            &projection,
            GroupConfirmationProjection::Preserve,
        );
        self.mark_group_projection_dirty(group_id);
        self.save_state_with_pending_local_group_deletion_frontier_clears()?;
        self.queue_own_group_system_projection_updates(&effects);
        Ok(send_summary_from_effects(&effects))
    }

    fn ensure_group(&self, group_id: &GroupId) -> Result<(), AppError> {
        let group_id_hex = hex::encode(group_id.as_slice());
        if self
            .state
            .groups
            .iter()
            .any(|group| group.group_id_hex == group_id_hex)
        {
            Ok(())
        } else {
            Err(AppError::UnknownGroup(group_id_hex))
        }
    }

    /// Fail before optimistic projection, media upload, or any other
    /// application-message preparation once terminal convergence has gated the
    /// group. The engine repeats this check at the authoritative mutation
    /// boundary; this app-layer preflight keeps clients from briefly rendering
    /// a message that can only be retracted.
    fn ensure_group_application_messages_allowed(
        &self,
        group_id: &GroupId,
    ) -> Result<(), AppError> {
        self.ensure_group(group_id)?;
        let terminal = self
            .runtime
            .group_record(group_id)
            .map(|group| group.disbanded.is_some())
            .unwrap_or(false);
        if terminal || self.runtime.disbanding_in_progress(group_id)? {
            return Err(AppError::GroupDisbanding(hex::encode(group_id.as_slice())));
        }
        Ok(())
    }

    /// Flip a group's local `archived` flag on the worker-owned in-memory
    /// `AccountState` and persist it. Routing archive toggles through here (and
    /// the account worker) instead of a detached `MarmotApp::set_group_archived`
    /// keeps the long-lived worker's snapshot authoritative: a later inbound
    /// delivery that re-persists `self.state` will carry the updated flag rather
    /// than silently reverting it to a stale `archived = false`.
    pub fn set_group_archived(
        &mut self,
        group_id: &GroupId,
        archived: bool,
    ) -> Result<AppGroupRecord, AppError> {
        let group_id_hex = hex::encode(group_id.as_slice());
        let group = self
            .state
            .groups
            .iter_mut()
            .find(|group| group.group_id_hex == group_id_hex)
            .ok_or_else(|| AppError::UnknownGroup(group_id_hex.clone()))?;
        let previous = group.archived;
        group.archived = archived;
        let group = group.clone();
        self.mark_group_projection_dirty_hex(group_id_hex.clone());
        // Roll the in-memory flag back if persistence fails so the worker's
        // authoritative snapshot stays consistent with what is on disk; a later
        // unrelated `save_state` must not silently re-apply a toggle the caller
        // was told had failed.
        if let Err(err) = self.save_state_with_pending_local_group_deletion_frontier_clears() {
            if let Some(group) = self
                .state
                .groups
                .iter_mut()
                .find(|group| group.group_id_hex == group_id_hex)
            {
                group.archived = previous;
            }
            return Err(err);
        }
        Ok(group)
    }

    fn set_group_invite_confirmation(
        &mut self,
        group_id: &GroupId,
        pending_confirmation: bool,
        archived: bool,
    ) -> Result<AppGroupRecord, AppError> {
        let group_id_hex = hex::encode(group_id.as_slice());
        let group = self
            .state
            .groups
            .iter_mut()
            .find(|group| group.group_id_hex == group_id_hex)
            .ok_or_else(|| AppError::UnknownGroup(group_id_hex.clone()))?;
        group.pending_confirmation = pending_confirmation;
        group.archived = archived;
        let group = group.clone();
        self.mark_group_projection_dirty_hex(group_id_hex);
        self.save_state_with_pending_local_group_deletion_frontier_clears()?;
        Ok(group)
    }

    fn encrypted_media_policy_for_group(
        &self,
        group_id: &GroupId,
    ) -> Result<crate::groups::AppEncryptedMediaPolicy, AppError> {
        self.encrypted_media_for_group(group_id).endpoint_policy()
    }

    fn encrypted_media_secret(
        &mut self,
        group_id: &GroupId,
    ) -> Result<(u64, SecretBytes), AppError> {
        let (epoch, secret) = self.runtime.exporter_secret_with_epoch(
            group_id,
            GROUP_ENCRYPTED_MEDIA_EXPORTER_CACHE_KEY,
            32,
        )?;
        self.remember_encrypted_media_epoch_secret(group_id, epoch.0, secret.as_ref())?;
        Ok((epoch.0, secret))
    }

    fn encrypted_media_secret_for_epoch(
        &mut self,
        group_id: &GroupId,
        source_epoch: u64,
        component_id: u16,
    ) -> Result<SecretBytes, AppError> {
        let group_id_hex = hex::encode(group_id.as_slice());
        if !self
            .app
            .account_storage(&self.state.label)?
            .encrypted_media_epoch_secret_may_be_served(&group_id_hex, source_epoch)?
        {
            return Err(AppError::InvalidEncryptedMedia(format!(
                "encrypted media secret retired for epoch {source_epoch}"
            )));
        }
        if let Some(secret) =
            self.cached_encrypted_media_epoch_secret(group_id, component_id, source_epoch)?
        {
            return Ok(SecretBytes::new(secret));
        }
        let (epoch, secret) = self.runtime.exporter_secret_with_epoch(
            group_id,
            GROUP_ENCRYPTED_MEDIA_EXPORTER_CACHE_KEY,
            32,
        )?;
        if epoch.0 == source_epoch {
            self.remember_encrypted_media_epoch_secret_for_component(
                group_id,
                component_id,
                epoch.0,
                secret.as_ref(),
            )?;
            if let Some(secret) =
                self.cached_encrypted_media_epoch_secret(group_id, component_id, source_epoch)?
            {
                return Ok(SecretBytes::new(secret));
            }
        }
        Err(AppError::InvalidEncryptedMedia(format!(
            "missing encrypted media secret for epoch {source_epoch}"
        )))
    }

    fn remember_current_encrypted_media_secret(&self, group_id: &GroupId) -> Result<(), AppError> {
        // Exporting the secret loads the full MLS group state, so skip it when
        // the current epoch's secret is already cached. The record epoch can
        // trail a staged commit by one epoch; that window is covered by the
        // live-export fallback in `encrypted_media_secret_for_epoch`.
        let record = self.runtime.group_record(group_id)?;
        let component_id = Self::encrypted_media_component_id(record.protocol_profile);
        if self
            .cached_encrypted_media_epoch_secret(group_id, component_id, record.epoch.0)?
            .is_some()
        {
            return Ok(());
        }
        let (epoch, secret) = self.runtime.exporter_secret_with_epoch(
            group_id,
            GROUP_ENCRYPTED_MEDIA_EXPORTER_CACHE_KEY,
            32,
        )?;
        self.remember_encrypted_media_epoch_secret(group_id, epoch.0, secret.as_ref())
    }
}

/// Per-pass accounting for one encrypted-media epoch-secret warm sweep.
/// Aggregate counts only (privacy-safe).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct EncryptedMediaWarmStats {
    /// Groups visited from the in-memory account projection.
    pub(crate) groups_considered: usize,
    /// Groups skipped because the authoritative component was already
    /// confirmed not-required at the group's current epoch in this client.
    pub(crate) skipped_unchanged_epoch: usize,
    /// Authoritative component lookups (`MlsGroup::load`) performed. This
    /// is the expensive step the epoch map exists to bound.
    pub(crate) authoritative_checks: usize,
    /// Groups whose current-epoch secret was cached this pass.
    pub(crate) warmed: usize,
    /// Groups skipped after a transient lookup/warm failure (retried next
    /// pass).
    pub(crate) failures: usize,
}

impl AppClient {
    pub(crate) fn cache_current_encrypted_media_epoch_secrets(
        &mut self,
    ) -> EncryptedMediaWarmStats {
        let mut stats = EncryptedMediaWarmStats::default();
        // Drop confirmations for groups no longer in the projection (leave,
        // archive, local deletion): the map must stay bounded by the live
        // group set.
        let live: HashSet<&str> = self
            .state
            .groups
            .iter()
            .map(|group| group.group_id_hex.as_str())
            .collect();
        self.encrypted_media_not_required_epochs
            .retain(|group_id_hex, _| live.contains(group_id_hex.as_str()));
        for group in &self.state.groups {
            stats.groups_considered += 1;
            let Ok(group_id_bytes) = hex::decode(&group.group_id_hex) else {
                tracing::warn!(
                    target: "marmot_app::media",
                    method = "cache_current_encrypted_media_epoch_secrets",
                    error_code = "encrypted_media_group_record_skipped",
                    "skipping malformed encrypted media group record",
                );
                stats.failures += 1;
                continue;
            };
            let group_id = GroupId::new(group_id_bytes);
            // The projected component is a positive-only fast path: `true`
            // warms without an MLS group load. A projected `false` may be
            // stale (a rebuild error can leave it lagging the signed
            // component), so it must re-check the authoritative component
            // before skipping — a missed warm here can strand a
            // historical epoch's media once the group advances. A confirmed
            // negative is authoritative until the next commit, and a commit
            // always advances the group epoch, so a confirmed-negative entry
            // keyed on the current engine epoch skips the re-check (mdk#1380).
            if !group.encrypted_media.required {
                let epoch = match self.runtime.group_record(&group_id) {
                    Ok(record) => record.epoch.0,
                    Err(_) => {
                        // Transient read failure: leave the group unconfirmed
                        // so a later pass retries the authoritative lookup.
                        stats.failures += 1;
                        continue;
                    }
                };
                if self
                    .encrypted_media_not_required_epochs
                    .get(&group.group_id_hex)
                    .is_some_and(|confirmed| *confirmed == epoch)
                {
                    stats.skipped_unchanged_epoch += 1;
                    continue;
                }
                let component = match self.try_encrypted_media_for_group(&group_id) {
                    Ok(component) => component,
                    Err(_) => {
                        stats.failures += 1;
                        continue;
                    }
                };
                stats.authoritative_checks += 1;
                if !component.required {
                    self.encrypted_media_not_required_epochs
                        .insert(group.group_id_hex.clone(), epoch);
                    continue;
                }
                // Authoritative required: drop any stale confirmation so the
                // map only ever holds live negatives.
                self.encrypted_media_not_required_epochs
                    .remove(&group.group_id_hex);
            }
            if self
                .remember_current_encrypted_media_secret(&group_id)
                .is_err()
            {
                tracing::warn!(
                    target: "marmot_app::media",
                    method = "cache_current_encrypted_media_epoch_secrets",
                    error_code = "encrypted_media_secret_cache_skipped",
                    "failed to cache encrypted media epoch secret for one group",
                );
                stats.failures += 1;
            } else {
                stats.warmed += 1;
            }
        }
        stats
    }

    fn remember_encrypted_media_epoch_secret(
        &self,
        group_id: &GroupId,
        source_epoch: u64,
        secret: &[u8],
    ) -> Result<(), AppError> {
        let component_id = self
            .encrypted_media_policy_for_group(group_id)?
            .component_id;
        self.remember_encrypted_media_epoch_secret_for_component(
            group_id,
            component_id,
            source_epoch,
            secret,
        )
    }

    fn remember_encrypted_media_epoch_secret_for_component(
        &self,
        group_id: &GroupId,
        component_id: u16,
        source_epoch: u64,
        secret: &[u8],
    ) -> Result<(), AppError> {
        self.app
            .account_storage(&self.state.label)?
            .remember_encrypted_media_epoch_secret(
                &hex::encode(group_id.as_slice()),
                component_id,
                source_epoch,
                secret,
            )?;
        Ok(())
    }

    fn cached_encrypted_media_epoch_secret(
        &self,
        group_id: &GroupId,
        component_id: u16,
        source_epoch: u64,
    ) -> Result<Option<Vec<u8>>, AppError> {
        Ok(self
            .app
            .account_storage(&self.state.label)?
            .encrypted_media_epoch_secret(
                &hex::encode(group_id.as_slice()),
                component_id,
                source_epoch,
            )?)
    }

    fn encrypted_media_component_for_new_group(&self) -> Result<AppComponentData, AppError> {
        let endpoints = if self
            .app
            .service_endpoints()
            .encrypted_media_blob_endpoints
            .is_empty()
        {
            DEFAULT_BLOSSOM_SERVER_URLS
                .iter()
                .map(|endpoint| (*endpoint).to_owned())
                .collect()
        } else {
            self.app
                .service_endpoints()
                .encrypted_media_blob_endpoints
                .clone()
        };
        match self.runtime.new_protocol_profile() {
            ProtocolProfile::Legacy => {
                let policy = EncryptedMediaPolicyV1::blossom_default(endpoints, true)
                    .map_err(AppError::InvalidEncryptedMedia)?;
                AppGroupEncryptedMediaComponent::new_v1(policy)?.to_app_component_data()
            }
            ProtocolProfile::Current => {
                let policy = EncryptedMediaPolicyV2::blossom_default(endpoints)
                    .map_err(AppError::InvalidEncryptedMedia)?;
                AppGroupEncryptedMediaComponent::new_v2(policy)?.to_app_component_data()
            }
        }
    }

    /// Reconcile every group's current and still-live prior transport
    /// subscriptions, returning whether any installed route changed.
    pub(crate) fn refresh_group_routes(&mut self) -> Result<GroupRouteRefresh, AppError> {
        let mut refresh = GroupRouteRefresh::default();
        for group in &mut self.state.groups {
            let Ok(group_id_bytes) = hex::decode(&group.group_id_hex) else {
                tracing::warn!(
                    target: "marmot_app::client",
                    method = "refresh_group_routes",
                    error_kind = "invalid_persisted_route_identifier",
                    "skipping malformed persisted group route",
                );
                continue;
            };
            let group_id = GroupId::new(group_id_bytes);
            if self
                .runtime
                .group_record(&group_id)
                .is_ok_and(|group| group.disbanded.is_some())
            {
                if self.routing.replace_group_routes(&group_id, Vec::new()) {
                    refresh.routing_changed = true;
                }
                continue;
            }
            // Retention is epoch-derived, never process-uptime-derived. Do not
            // prune while convergence still has unresolved inputs: the
            // retained anchor is not settled yet, so conservatively keep every
            // prior address until the next stable reconciliation.
            if !self
                .runtime
                .has_pending_convergence_inputs(&group_id)
                .unwrap_or(true)
                && let Ok(group_record) = self.runtime.group_record(&group_id)
                && group.prune_prior_nostr_routes(group_record.epoch.0)
            {
                self.pending_group_projection_updates
                    .insert(group.group_id_hex.clone());
                refresh.state_pruned = true;
            }
            let Ok(subscriptions) = group.transport_subscriptions(&group_id) else {
                tracing::warn!(
                    target: "marmot_app::client",
                    method = "refresh_group_routes",
                    error_kind = "invalid_persisted_group_route",
                    "skipping malformed persisted group route",
                );
                continue;
            };
            if self.routing.replace_group_routes(&group_id, subscriptions) {
                refresh.routing_changed = true;
            }
        }
        Ok(refresh)
    }

    fn refresh_routing(&mut self) -> Result<(), AppError> {
        let routing = self.app.routing_for(&self.state)?;
        self.preserve_local_deleted_group_routes(&routing)?;
        self.routing.replace(routing.snapshot());
        Ok(())
    }

    fn remember_published_reports(&mut self, effects: &marmot_account::AccountDeviceEffects) {
        self.pending_convergence_groups
            .extend(effects.pending_convergence.iter().cloned());
        if effects.reports.is_empty() {
            return;
        }
        for report in &effects.reports {
            let event_id = hex::encode(report.message_id.as_slice());
            self.remember_seen_event(event_id);
        }
    }

    pub(crate) fn remember_seen_event(&mut self, event_id: String) {
        if remember_seen_event(&mut self.seen_events_index, &mut self.state, event_id) {
            self.pending_seen_event_count = self
                .pending_seen_event_count
                .saturating_add(1)
                .min(self.state.seen_events.len());
        }
    }

    pub(crate) fn mark_group_projection_dirty(&mut self, group_id: &GroupId) {
        self.pending_group_projection_updates
            .insert(hex::encode(group_id.as_slice()));
    }

    pub(crate) fn mark_group_projection_dirty_hex(&mut self, group_id_hex: String) {
        self.pending_group_projection_updates.insert(group_id_hex);
    }

    /// Durably record welcomes a confirmed create/invite could not deliver, so
    /// the repair handle is not lost when the call returns (mdk#352). The commit
    /// is already confirmed and externally visible, so the added member stays in
    /// the roster but cannot join until the welcome is re-delivered.
    fn record_welcome_delivery_failures(
        &mut self,
        group_id_hex: &str,
        effects: &marmot_account::AccountDeviceEffects,
    ) -> Result<(), AppError> {
        if effects.welcome_failures.is_empty() {
            return Ok(());
        }
        let storage = self.app.account_storage(&self.state.label)?;
        let recorded_at = unix_now_seconds();
        for failure in &effects.welcome_failures {
            let message_id_hex = hex::encode(failure.message_id.as_slice());
            let recipient_hex = hex::encode(failure.recipient.as_slice());
            storage.record_pending_welcome_delivery(
                &message_id_hex,
                group_id_hex,
                &recipient_hex,
                recorded_at,
            )?;
            // Queue a runtime event so subscribers (UI/CLI/UniFFI) learn the
            // member is unjoinable without polling the durable queue.
            self.pending_welcome_delivery_events
                .push(PendingWelcomeDelivery {
                    group_id_hex: group_id_hex.to_owned(),
                    message_id_hex,
                    recipient_hex,
                    recorded_at,
                });
        }
        Ok(())
    }

    /// Derive the current-profile founding Welcome message ids needed by the
    /// in-process fanout driver. The engine's retained outbound Welcome rows
    /// are authoritative; the app repair table is convenience-only and is
    /// rebuilt on demand or populated only for actual delivery failures.
    fn founding_welcome_delivery_intent_ids(
        effects: &cgka_session::SessionEffects,
    ) -> Result<Vec<String>, AppError> {
        let mut message_ids = Vec::new();
        for work in &effects.publish {
            let PublishWork::FoundingGroupCreated { welcomes: items } = work else {
                continue;
            };
            for welcome in items {
                if !matches!(welcome.envelope, TransportEnvelope::Welcome { .. }) {
                    return Err(AppError::Publish(
                        "delivery artifact was not a Welcome".into(),
                    ));
                }
                message_ids.push(hex::encode(welcome.id.as_slice()));
            }
        }
        Ok(message_ids)
    }

    fn record_welcome_delivery_intents(
        &mut self,
        group_id: &GroupId,
        welcomes: &[cgka_traits::transport::TransportMessage],
    ) -> Result<Vec<String>, AppError> {
        let group_id_hex = hex::encode(group_id.as_slice());
        let recorded_at = unix_now_seconds();
        let storage = self.app.account_storage(&self.state.label)?;
        let mut records = Vec::with_capacity(welcomes.len());
        for welcome in welcomes {
            let TransportEnvelope::Welcome { recipient } = &welcome.envelope else {
                return Err(AppError::Publish(
                    "delivery artifact was not a Welcome".into(),
                ));
            };
            let message_id_hex = hex::encode(welcome.id.as_slice());
            records.push(storage_sqlite::PendingWelcomeDeliveryRecord {
                message_id_hex,
                group_id_hex: group_id_hex.clone(),
                recipient_hex: hex::encode(recipient.as_slice()),
                recorded_at,
            });
        }
        storage.record_pending_welcome_deliveries(&records)?;
        Ok(records
            .into_iter()
            .map(|record| record.message_id_hex)
            .collect())
    }

    /// Clear only intent rows whose exact Welcome met its acknowledgement
    /// policy. Failed or unattempted rows stay durable for re-delivery.
    fn clear_delivered_founding_welcome_intents(
        &mut self,
        message_ids: &[String],
        effects: &marmot_account::AccountDeviceEffects,
    ) -> Result<(), AppError> {
        if message_ids.is_empty() {
            return Ok(());
        }
        let storage = self.app.account_storage(&self.state.label)?;
        for message_id_hex in message_ids {
            let delivered = effects.reports.iter().any(|report| {
                hex::encode(report.message_id.as_slice()) == *message_id_hex
                    && report.met_required_acks()
            }) && !effects
                .welcome_failures
                .iter()
                .any(|failure| hex::encode(failure.message_id.as_slice()) == *message_id_hex);
            if delivered {
                storage.clear_pending_welcome_delivery(message_id_hex)?;
            }
        }
        Ok(())
    }

    /// Reconcile the app-facing repair index from the engine's authoritative
    /// retained Welcome obligations.
    ///
    /// The engine persists founding Welcomes at canonical creation and promotes
    /// invite Welcomes in the transaction that confirms their Add commit. This
    /// closes the crash window between the canonical boundary and this
    /// convenience index: a cold restart can rebuild missing rows without
    /// re-creating the group, re-committing the invite, or re-consuming
    /// KeyPackages.
    fn reconcile_pending_welcome_delivery_index(&self) -> Result<(), AppError> {
        let outstanding = self.runtime.outstanding_welcome_deliveries()?;
        let tracked_ids = self
            .runtime
            .tracked_outbound_welcome_ids()?
            .into_iter()
            .map(|id| hex::encode(id.as_slice()))
            .collect::<HashSet<_>>();
        let storage = self.app.account_storage(&self.state.label)?;
        let existing = storage.list_pending_welcome_deliveries()?;
        let outstanding_ids = outstanding
            .iter()
            .map(|(_, welcome)| hex::encode(welcome.id.as_slice()))
            .collect::<HashSet<_>>();

        for record in &existing {
            if tracked_ids.contains(&record.message_id_hex)
                && !outstanding_ids.contains(&record.message_id_hex)
            {
                storage.clear_pending_welcome_delivery(&record.message_id_hex)?;
            }
        }

        let existing_ids = existing
            .into_iter()
            .map(|record| record.message_id_hex)
            .collect::<HashSet<_>>();
        let recorded_at = unix_now_seconds();
        for (group_id, welcome) in outstanding {
            let TransportEnvelope::Welcome { recipient } = welcome.envelope else {
                continue;
            };
            let message_id_hex = hex::encode(welcome.id.as_slice());
            if existing_ids.contains(&message_id_hex) {
                continue;
            }
            storage.record_pending_welcome_delivery(
                &message_id_hex,
                &hex::encode(group_id.as_slice()),
                &hex::encode(recipient.as_slice()),
                recorded_at,
            )?;
        }
        Ok(())
    }

    /// Publish Welcome obligations stashed at the canonical create/invite
    /// boundary. Managed workers call this after replying; direct AppClient
    /// callers still await it so existing tests keep a complete delivery path.
    pub(crate) async fn drive_unpublished_welcome_delivery(
        &mut self,
        telemetry: Option<&AppPerformanceTelemetry>,
    ) {
        let Some(work) = self.unpublished_welcome_delivery.take() else {
            return;
        };
        match work.kind {
            UnpublishedWelcomeKind::Founding {
                effects,
                welcome_intents,
            } => {
                let welcome_publish_started_at = Instant::now();
                let publish_result = self
                    .runtime
                    .publish_prepared_session_effects_with_audit_context(
                        effects,
                        work.audit_context.clone(),
                    )
                    .await
                    .map_err(AppError::from);
                record_app_performance(
                    telemetry,
                    AppPerformanceOperation::GroupCreateWelcomePublish,
                    welcome_publish_started_at.elapsed(),
                    publish_result.is_ok(),
                );
                let effects = recover_post_canonical_result(
                    "publish_prepared_founding_group",
                    publish_result,
                );
                recover_post_canonical_result(
                    "clear_delivered_founding_welcome_intents",
                    self.clear_delivered_founding_welcome_intents(&welcome_intents, &effects),
                );
                // Non-fatal here: this classification only logs, so no
                // refusal is lost to an early return. It still arms through the
                // same gate, so no publishing seam reaches the bare check.
                recover_post_canonical_result(
                    "classify_founding_welcome_publish",
                    self.observe_recovery_evidence_then_fail_if_publish_failed(&effects),
                );
                recover_post_canonical_result(
                    "record_founding_welcome_delivery_failures",
                    self.record_welcome_delivery_failures(
                        &hex::encode(work.group_id.as_slice()),
                        &effects,
                    ),
                );
                self.record_human_action_succeeded(&work.group_id, &work.audit_context, &effects);
                self.remember_published_reports(&effects);
                self.queue_own_group_system_projection_updates(&effects);
            }
            UnpublishedWelcomeKind::Invite {
                welcomes,
                welcome_intents,
            } => {
                let welcome_publish_started_at = Instant::now();
                let publish_result = self
                    .runtime
                    .publish_welcome_messages_with_audit_context(
                        welcomes,
                        Some(work.group_id.clone()),
                        work.audit_context,
                    )
                    .await
                    .map_err(AppError::from);
                record_app_performance(
                    telemetry,
                    AppPerformanceOperation::GroupInviteWelcomePublish,
                    welcome_publish_started_at.elapsed(),
                    publish_result.is_ok(),
                );
                let effects = match publish_result {
                    Ok(effects) => effects,
                    Err(error) => {
                        tracing::warn!(
                            target: "marmot_app::client",
                            method = "drive_unpublished_welcome_delivery",
                            error_kind = error.privacy_safe_kind(),
                            "confirmed invite outpaced Welcome fanout; pending obligations remain retryable"
                        );
                        return;
                    }
                };
                let _ = self.clear_delivered_founding_welcome_intents(&welcome_intents, &effects);
                let _ = self.record_welcome_delivery_failures(
                    &hex::encode(work.group_id.as_slice()),
                    &effects,
                );
                self.remember_published_reports(&effects);
            }
        }
    }

    /// Drain the welcomes queued for re-delivery during the last create/invite,
    /// for the runtime worker to broadcast as `WelcomeDeliveryPending` events
    /// (mdk#352).
    pub(crate) fn take_pending_welcome_delivery_events(&mut self) -> Vec<PendingWelcomeDelivery> {
        std::mem::take(&mut self.pending_welcome_delivery_events)
    }

    /// Prepare one bounded startup retry for every engine-authoritative
    /// outstanding Welcome.
    ///
    /// Only relay I/O moves into the returned task. Exact artifacts, endpoint
    /// snapshots, and attempt reservations are durable/owned by this client so
    /// the account worker can keep processing inbound traffic and commands
    /// without creating a second retry for the same message id.
    pub(crate) fn prepare_pending_welcome_delivery_recovery_best_effort(
        &mut self,
    ) -> Option<PendingWelcomeDeliveryRecovery> {
        let pending = match self.runtime.outstanding_welcome_deliveries() {
            Ok(pending) => pending,
            Err(error) => {
                let error = AppError::from(error);
                tracing::warn!(
                    target: "marmot_app::client",
                    method = "prepare_pending_welcome_delivery_recovery_best_effort",
                    error_kind = error.privacy_safe_kind(),
                    "could not enumerate retained Welcome obligations at startup"
                );
                return None;
            }
        };
        if pending.is_empty() {
            return None;
        }
        let welcome_ids = pending
            .iter()
            .map(|(_, welcome)| hex::encode(welcome.id.as_slice()))
            .collect::<Vec<_>>();
        let welcomes = pending
            .into_iter()
            .map(|(_, welcome)| welcome)
            .collect::<Vec<_>>();
        let publish = match self
            .runtime
            .prepare_welcome_retry_task_with_audit_context(welcomes, AuditEventContext::default())
        {
            Ok(publish) => publish,
            Err(error) => {
                tracing::warn!(
                    target: "marmot_app::client",
                    method = "prepare_pending_welcome_delivery_recovery_best_effort",
                    error_kind = AppError::from(error).privacy_safe_kind(),
                    "could not prepare retained Welcome obligations at startup"
                );
                return None;
            }
        };
        Some(PendingWelcomeDeliveryRecovery {
            welcome_ids,
            publish,
        })
    }

    /// Reconcile a detached startup retry back through the serialized account
    /// owner and retire only obligations whose acknowledgement policy landed.
    pub(crate) async fn finish_pending_welcome_delivery_recovery_best_effort(
        &mut self,
        completed: CompletedWelcomeDeliveryRecovery,
    ) {
        match self
            .runtime
            .finish_welcome_publish_task(completed.publish)
            .await
        {
            Ok(effects) => {
                let _ =
                    self.clear_delivered_founding_welcome_intents(&completed.welcome_ids, &effects);
                self.remember_published_reports(&effects);
            }
            Err(error) => {
                tracing::warn!(
                    target: "marmot_app::client",
                    method = "finish_pending_welcome_delivery_recovery_best_effort",
                    error_kind = AppError::from(error).privacy_safe_kind(),
                    "startup Welcome retry left obligations pending"
                );
            }
        }
    }

    /// Release an in-memory retry reservation after its relay task panics or is
    /// cancelled. The exact durable obligation remains available for restart.
    pub(crate) fn abandon_pending_welcome_delivery_recovery(&mut self, message_ids: &[MessageId]) {
        self.runtime.abandon_welcome_publish_task(message_ids);
    }

    /// Welcomes still awaiting re-delivery for this account (mdk#352), oldest
    /// first. Each entry's `message_id_hex` is the handle for
    /// [`AppClient::redeliver_welcome`].
    pub fn pending_welcome_deliveries(&self) -> Result<Vec<PendingWelcomeDelivery>, AppError> {
        self.reconcile_pending_welcome_delivery_index()?;
        Ok(self
            .app
            .account_storage(&self.state.label)?
            .list_pending_welcome_deliveries()?
            .into_iter()
            .map(|record| PendingWelcomeDelivery {
                group_id_hex: record.group_id_hex,
                message_id_hex: record.message_id_hex,
                recipient_hex: record.recipient_hex,
                recorded_at: record.recorded_at,
            })
            .collect())
    }

    /// Re-publish a welcome that a confirmed create/invite failed to deliver,
    /// from the copy the engine stored at wrap time — no re-commit (mdk#352).
    /// Clears the pending record only once the welcome is accepted; a repeated
    /// failure leaves it queued for a later retry.
    pub async fn redeliver_welcome(
        &mut self,
        message_id_hex: &str,
    ) -> Result<SendSummary, AppError> {
        let message_id = cgka_traits::MessageId::new(hex::decode(message_id_hex)?);
        let effects = self.runtime.redeliver_welcome(&message_id).await?;
        // Only clear the durable pending record once every "still undelivered"
        // signal agrees the welcome landed: no PublishFailure, no structured
        // WelcomeDeliveryFailure, and a report that met its ack threshold.
        // These are kept in lockstep by `publish_one` today, but asserting all
        // three means a future refactor cannot drift one signal and clear the
        // queue while the welcome is still unreachable (the #375 class of bug).
        let delivered = effects.failures.is_empty()
            && effects.welcome_failures.is_empty()
            && effects
                .reports
                .last()
                .is_some_and(|report| report.met_required_acks());
        if !delivered {
            return Err(if effects.failures.is_empty() {
                AppError::Publish("welcome re-delivery did not reach the recipient".into())
            } else {
                publish_failure_error(&effects.failures)
            });
        }
        self.app
            .account_storage(&self.state.label)?
            .clear_pending_welcome_delivery(message_id_hex)?;
        Ok(send_summary_from_effects(&effects))
    }
}

fn maintenance_run_summary_from_account(
    summary: cgka_traits::MaintenanceRunSummary,
) -> crate::MaintenanceRunSummary {
    crate::MaintenanceRunSummary {
        published: summary.published,
        message_ids: summary
            .message_ids
            .into_iter()
            .map(|id| hex::encode(id.as_slice()))
            .collect(),
        deferred: summary.deferred,
        ambiguous_exposure: summary.ambiguous_exposure,
        failures: summary.failures,
    }
}

fn preferred_initial_group_image_component(
    constructable: &GroupCapabilities,
    has_source_url: bool,
) -> Option<u16> {
    if constructable
        .app_components
        .contains(GROUP_BLOSSOM_IMAGE_COMPONENT_ID)
    {
        Some(GROUP_BLOSSOM_IMAGE_COMPONENT_ID)
    } else if has_source_url
        && constructable
            .app_components
            .contains(GROUP_AVATAR_URL_COMPONENT_ID)
    {
        Some(GROUP_AVATAR_URL_COMPONENT_ID)
    } else {
        None
    }
}

fn require_initial_group_component_support(
    constructable: &GroupCapabilities,
    app_components: &[AppComponentData],
) -> Result<(), AppError> {
    let required = AppComponentSet::new(
        app_components
            .iter()
            .map(|component| component.component_id),
    );
    if required
        .missing_from(&constructable.app_components)
        .is_empty()
    {
        return Ok(());
    }
    Err(AppError::Account(AccountError::Engine(
        EngineError::MissingRequiredCapabilities {
            required: Box::new(GroupCapabilities {
                app_components: required,
                ..GroupCapabilities::default()
            }),
            had: Box::new(constructable.clone()),
        },
    )))
}

/// Whether the local account (`local_account_id_hex`) is absent from a group's
/// engine roster — the backfill's suppression decision. MLS member ids in this
/// design are the Nostr account pubkey hex, so an account is "still a member"
/// iff some roster entry's hex id matches the local id (case-insensitively).
/// An empty roster is treated as absent. Kept pure and named so
/// [`AppClient::backfill_self_membership_once`] is unit-testable without an
/// engine harness.
fn local_account_removed_from_roster(
    members: &[cgka_traits::group::Member],
    local_account_id_hex: &str,
) -> bool {
    !members
        .iter()
        .any(|member| hex::encode(member.id.as_slice()).eq_ignore_ascii_case(local_account_id_hex))
}

#[cfg(test)]
mod post_canonical_create_tests {
    use super::{
        CREATE_GROUP_LOOKUP_CONCURRENCY, INVITE_LOOKUP_CONCURRENCY, collect_bounded_ordered,
        preferred_initial_group_image_component, recover_post_canonical_result,
        require_initial_group_component_support,
    };
    use crate::AppError;
    use cgka_traits::app_components::{
        AppComponentData, GROUP_AVATAR_URL_COMPONENT_ID, GROUP_BLOSSOM_IMAGE_COMPONENT_ID,
        GROUP_MESSAGE_RETENTION_COMPONENT_ID,
    };
    use cgka_traits::capabilities::GroupCapabilities;

    #[test]
    fn founding_image_prefers_blossom_then_url_then_none() {
        let mut capabilities = GroupCapabilities::default();
        capabilities
            .app_components
            .insert(GROUP_AVATAR_URL_COMPONENT_ID);
        capabilities
            .app_components
            .insert(GROUP_BLOSSOM_IMAGE_COMPONENT_ID);
        assert_eq!(
            preferred_initial_group_image_component(&capabilities, true),
            Some(GROUP_BLOSSOM_IMAGE_COMPONENT_ID)
        );

        capabilities
            .app_components
            .ids
            .remove(&GROUP_BLOSSOM_IMAGE_COMPONENT_ID);
        assert_eq!(
            preferred_initial_group_image_component(&capabilities, true),
            Some(GROUP_AVATAR_URL_COMPONENT_ID)
        );
        assert_eq!(
            preferred_initial_group_image_component(&capabilities, false),
            None
        );
    }

    #[test]
    fn founding_required_components_are_preflighted_against_every_member() {
        let retention = AppComponentData {
            component_id: GROUP_MESSAGE_RETENTION_COMPONENT_ID,
            data: 300u64.to_be_bytes().to_vec(),
        };
        let mut capabilities = GroupCapabilities::default();
        let error = require_initial_group_component_support(
            &capabilities,
            std::slice::from_ref(&retention),
        )
        .expect_err("unsupported retention must fail before founding side effects");
        assert!(matches!(
            error,
            AppError::Account(marmot_account::AccountError::Engine(
                cgka_traits::EngineError::MissingRequiredCapabilities { ref required, .. }
            )) if required
                .app_components
                .contains(GROUP_MESSAGE_RETENTION_COMPONENT_ID)
        ));

        capabilities
            .app_components
            .insert(GROUP_MESSAGE_RETENTION_COMPONENT_ID);
        require_initial_group_component_support(&capabilities, &[retention]).unwrap();
    }

    #[test]
    fn post_canonical_failures_default_instead_of_escaping() {
        let recovered: Vec<String> = recover_post_canonical_result(
            "test_post_canonical_failure",
            Err(AppError::Publish("injected failure".into())),
        );
        assert!(recovered.is_empty());

        let successful: u8 = recover_post_canonical_result("test_post_canonical_success", Ok(7));
        assert_eq!(successful, 7);
    }

    #[tokio::test]
    async fn bounded_create_group_lookups_scale_for_cached_and_delayed_sources() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::sync::Semaphore;
        use tokio::time::{Duration, timeout};

        for item_count in [1, 5, 20] {
            let cached = collect_bounded_ordered(
                (0..item_count).map(|index| std::future::ready(Ok::<_, &'static str>(index))),
                INVITE_LOOKUP_CONCURRENCY,
            )
            .await
            .unwrap();
            assert_eq!(cached, (0..item_count).collect::<Vec<_>>());

            let active = Arc::new(AtomicUsize::new(0));
            let max_active = Arc::new(AtomicUsize::new(0));
            let release = Arc::new(Semaphore::new(0));
            let work_active = active.clone();
            let work_max_active = max_active.clone();
            let work_release = release.clone();
            let work = (0..item_count).map(move |index| {
                let active = work_active.clone();
                let max_active = work_max_active.clone();
                let release = work_release.clone();
                async move {
                    let now_active = active.fetch_add(1, Ordering::SeqCst) + 1;
                    max_active.fetch_max(now_active, Ordering::SeqCst);
                    let permit = release.acquire().await.unwrap();
                    permit.forget();
                    active.fetch_sub(1, Ordering::SeqCst);
                    Ok::<_, &'static str>(index)
                }
            });

            let expected_parallelism = item_count.min(CREATE_GROUP_LOOKUP_CONCURRENCY);
            let task = tokio::spawn(collect_bounded_ordered(
                work,
                CREATE_GROUP_LOOKUP_CONCURRENCY,
            ));
            timeout(Duration::from_secs(1), async {
                while max_active.load(Ordering::SeqCst) < expected_parallelism {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("bounded collector should start the available parallel work");
            assert_eq!(max_active.load(Ordering::SeqCst), expected_parallelism);
            release.add_permits(item_count);

            assert_eq!(
                task.await.unwrap().unwrap(),
                (0..item_count).collect::<Vec<_>>()
            );
        }
    }

    #[tokio::test]
    async fn bounded_create_group_work_reports_errors_in_input_order() {
        use tokio::time::{Duration, sleep};

        let work = (0..2).map(|index| async move {
            if index == 0 {
                sleep(Duration::from_millis(10)).await;
            }
            Err::<usize, _>(if index == 0 { "first" } else { "second" })
        });

        assert_eq!(collect_bounded_ordered(work, 2).await, Err("first"));
    }
}

#[cfg(test)]
mod self_membership_backfill_tests {
    use super::local_account_removed_from_roster;
    use cgka_traits::MemberId;
    use cgka_traits::group::Member;

    fn member(id_hex: &str) -> Member {
        Member {
            id: MemberId::new(hex::decode(id_hex).unwrap()),
            credential: Vec::new(),
        }
    }

    #[test]
    fn local_account_in_roster_is_not_removed() {
        let roster = vec![member("aa"), member("bb")];
        // Local account ("aa") is still a member: must not be flagged removed.
        assert!(!local_account_removed_from_roster(&roster, "aa"));
        // Case-insensitive id match (uppercase local id).
        assert!(!local_account_removed_from_roster(&roster, "AA"));
    }

    #[test]
    fn local_account_absent_from_roster_is_removed() {
        // Roster has only peers; the local account ("aa") was removed/left.
        let roster = vec![member("bb"), member("cc")];
        assert!(local_account_removed_from_roster(&roster, "aa"));
    }

    #[test]
    fn empty_roster_is_treated_as_removed() {
        assert!(local_account_removed_from_roster(&[], "aa"));
    }
}
