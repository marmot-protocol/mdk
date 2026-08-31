use super::*;
use async_trait::async_trait;
use cgka_traits::Timestamp;
use cgka_traits::app_event::{
    AGENT_ACTIVITY_STATUS_TAG, AGENT_OPERATION_NAME_TAG, AGENT_OPERATION_STATUS_TAG,
    AGENT_OPERATION_TYPE_TAG, EVENT_REF_TAG, GROUP_SYSTEM_TYPE_TAG,
    MARMOT_APP_EVENT_KIND_AGENT_ACTIVITY, MARMOT_APP_EVENT_KIND_AGENT_OPERATION,
    MARMOT_APP_EVENT_KIND_AGENT_STREAM_START, MARMOT_APP_EVENT_KIND_CHAT,
    MARMOT_APP_EVENT_KIND_DELETE, MARMOT_APP_EVENT_KIND_GROUP_SYSTEM,
    MARMOT_APP_EVENT_KIND_REACTION, MarmotAppEvent as MarmotInnerEvent, QUOTE_REF_TAG,
    STREAM_CHUNKS_TAG, STREAM_FINAL_KIND_TAG, STREAM_HASH_TAG, STREAM_PARENT_TAG, STREAM_START_TAG,
    STREAM_TAG, STREAM_TYPE_TAG,
};
use cgka_traits::storage::{DisbandCandidate, DisbandCandidateStorage};
use marmot_account::AccountHomeError;
use nostr::base64::Engine as _;
use nostr::base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use nostr_sdk::prelude::{
    Alphabet, EventBuilder, Keys, Kind, SingleLetterTag, Tag, TagKind, Timestamp as NostrTimestamp,
};
use storage_sqlite::StoredRelayTelemetrySettings;
use transport_nostr_adapter::{
    NostrEventPublishRequest, NostrPublishOutcome, NostrRelayClient, NostrRelayEvent,
    NostrSubscription,
};
use transport_nostr_peeler::{NOSTR_GROUP_CONTENT_MIN_LEN, NostrTransportEvent};
use transport_quic_broker::BrokerServerTrust;

use crate::audit_log::AUDIT_ID_BYTES;
use crate::client::epoch_stall::{BackfillDecision, EPOCH_STALL_BACKFILL_THRESHOLD};
use crate::conversions::{
    app_group_from_stored_group, stored_components_from_app_group, stored_group_from_app_group,
};
use crate::directory::records::{
    FetchedFollowList, profile_content_json, public_directory_user_record,
};
use crate::ids::npub_for_account_id_lossy;
use crate::key_package_records::{
    relay_list_queries, relay_list_status_from_records, require_key_package_tag,
    require_multi_value_key_package_tag_matches,
};
use crate::messages::STREAM_ROUTE_QUIC;
use crate::messages::{AppMessageIntent, build_inner_event};

fn one_pixel_png() -> Vec<u8> {
    use image::ImageEncoder;

    let mut bytes = Vec::new();
    image::codecs::png::PngEncoder::new(&mut bytes)
        .write_image(&[0, 0, 0, 255], 1, 1, image::ExtendedColorType::Rgba8)
        .unwrap();
    bytes
}

#[test]
fn prepared_group_image_create_has_no_upload_phase_and_is_idempotent() {
    run_composed_app_runtime_test("prepared-group-image-create", || async {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let mut client = app.client("alice").await.unwrap();
        let staged = client
            .stage_prepared_initial_group_image(&one_pixel_png(), "image/png")
            .unwrap();
        assert_eq!(staged.state, AppPreparedGroupImageUploadState::Staged);

        let prepared_http = client
            .prepare_initial_group_image_upload(&staged.upload_id, None, false)
            .unwrap();
        assert!(matches!(
            prepared_http,
            crate::client::PreparedGroupImageUploadStart::Http(_)
        ));
        drop(prepared_http);
        let after_cancellation = client
            .prepared_initial_group_image_status(&staged.upload_id)
            .unwrap();
        assert_eq!(
            after_cancellation.state,
            AppPreparedGroupImageUploadState::Staged
        );
        assert_eq!(after_cancellation.attempt_count, 0);

        let failed = client
            .finish_initial_group_image_upload(
                &staged.upload_id,
                &Err(AppError::BlobStore("test failure".into())),
            )
            .unwrap();
        assert_eq!(failed.state, AppPreparedGroupImageUploadState::Failed);
        assert_eq!(failed.attempt_count, 1);
        assert_eq!(failed.last_error_kind.as_deref(), Some("blob_store"));
        let uploaded = client
            .finish_initial_group_image_upload(&staged.upload_id, &Ok(()))
            .unwrap();
        assert_eq!(uploaded.state, AppPreparedGroupImageUploadState::Uploaded);
        assert_eq!(uploaded.attempt_count, 2);
        assert!(matches!(
            client
                .prepare_initial_group_image_upload(&staged.upload_id, None, false)
                .unwrap(),
            crate::client::PreparedGroupImageUploadStart::Complete(_)
        ));

        let telemetry = AppPerformanceTelemetry::default();
        let group_id = client
            .create_group_with_prepared_initial_image_and_telemetry(
                "prepared image",
                &[],
                AppCreateGroupOptions::default(),
                &staged.upload_id,
                &telemetry,
            )
            .await
            .unwrap()
            .group_id;
        let group_id_again = client
            .create_group_with_prepared_initial_image_and_telemetry(
                "ignored on idempotent retry",
                &[],
                AppCreateGroupOptions::default(),
                &staged.upload_id,
                &telemetry,
            )
            .await
            .unwrap()
            .group_id;
        assert_eq!(group_id_again, group_id);
        assert_eq!(client.state.groups.len(), 1);
        assert!(client.state.groups[0].image.present);

        let status = client
            .prepared_initial_group_image_status(&staged.upload_id)
            .unwrap();
        assert_eq!(status.state, AppPreparedGroupImageUploadState::Consumed);
        let group_id_hex = hex::encode(group_id.as_slice());
        assert_eq!(status.group_id_hex.as_deref(), Some(group_id_hex.as_str()));
        assert!(!format!("{status:?}").contains(&group_id_hex));
        let snapshot = telemetry.snapshot();
        assert_eq!(snapshot.group_create_image_upload.attempts, 0);
        assert_eq!(snapshot.group_create_mls_prepare_persist.attempts, 1);
    });
}

#[test]
fn uploaded_prepared_group_image_retry_recovers_from_engine_without_projection() {
    run_composed_app_runtime_test("prepared-group-image-engine-recovery", || async {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let mut client = app.client("alice").await.unwrap();
        let staged = client
            .stage_prepared_initial_group_image(&one_pixel_png(), "image/png")
            .unwrap();
        client
            .finish_initial_group_image_upload(&staged.upload_id, &Ok(()))
            .unwrap();
        let component_data = app
            .account_storage("alice")
            .unwrap()
            .prepared_group_image_upload(&staged.upload_id)
            .unwrap()
            .unwrap()
            .component_data;
        let telemetry = AppPerformanceTelemetry::default();

        // Simulate the narrow crash window: MLS creation is canonical, but
        // consumption fails and the best-effort app projection is absent.
        let group_id = client
            .create_group_with_initial_source_and_optional_telemetry(
                "crash-window group",
                String::new(),
                &[],
                Some(crate::client::InitialGroupImageSource::Prepared {
                    upload_id: "injected-missing-consume-row".to_owned(),
                    component_data,
                }),
                0,
                Some(&telemetry),
            )
            .await
            .unwrap()
            .group_id;
        client.state.groups.clear();
        client
            .save_state_with_pending_local_group_deletion_frontier_clears()
            .unwrap();
        assert!(client.state.groups.is_empty());
        assert_eq!(
            client
                .prepared_initial_group_image_status(&staged.upload_id)
                .unwrap()
                .state,
            AppPreparedGroupImageUploadState::Uploaded
        );

        let recovered = client
            .create_group_with_prepared_initial_image_and_telemetry(
                "must not create a duplicate",
                &[],
                AppCreateGroupOptions::default(),
                &staged.upload_id,
                &telemetry,
            )
            .await
            .unwrap()
            .group_id;

        assert_eq!(recovered, group_id);
        assert_eq!(client.runtime.live_group_ids().unwrap(), vec![group_id]);
        assert_eq!(
            client
                .prepared_initial_group_image_status(&staged.upload_id)
                .unwrap()
                .state,
            AppPreparedGroupImageUploadState::Consumed
        );
        assert_eq!(
            telemetry
                .snapshot()
                .group_create_mls_prepare_persist
                .attempts,
            1
        );
    });
}

#[test]
fn legacy_inline_group_image_create_rejects_oversized_input_before_canonical_creation() {
    run_composed_app_runtime_test("legacy-inline-group-image-budget", || async {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let mut client = app.client("alice").await.unwrap();

        let result = client
            .create_group_with_initial_image(
                "oversized legacy image",
                &[],
                Some(AppInitialGroupImage {
                    plaintext: vec![0_u8; MAX_GROUP_IMAGE_BYTES + 1],
                    media_type: "image/png".to_owned(),
                    source_url: None,
                    dim: None,
                    thumbhash: None,
                }),
            )
            .await;

        let error = result.expect_err("legacy inline create must enforce the image byte budget");
        assert!(matches!(error, AppError::InvalidEncryptedMedia(_)));
        assert!(error.to_string().contains("size limit"));
        assert!(client.runtime.live_group_ids().unwrap().is_empty());
        assert!(client.state.groups.is_empty());
    });
}

#[derive(Default)]
pub(crate) struct ScriptedPushRelayClient {
    publish_results: std::sync::Mutex<std::collections::VecDeque<bool>>,
    published_events: std::sync::Mutex<Vec<NostrTransportEvent>>,
    attempted_events: std::sync::Mutex<Vec<NostrTransportEvent>>,
    subscriptions: std::sync::Mutex<Vec<NostrSubscription>>,
    subscription_attempts: std::sync::Mutex<Vec<NostrSubscription>>,
    block_next_subscribe: std::sync::atomic::AtomicBool,
    block_subscribe_count: std::sync::atomic::AtomicUsize,
    blocked_subscribe_count: std::sync::atomic::AtomicUsize,
    group_subscribe_attempts: std::sync::atomic::AtomicUsize,
    fail_blocked_subscribe: std::sync::atomic::AtomicBool,
    fail_next_subscribe: std::sync::atomic::AtomicBool,
    block_next_unsubscribe: std::sync::atomic::AtomicBool,
    block_next_publish: std::sync::atomic::AtomicBool,
    block_publish_count: std::sync::atomic::AtomicUsize,
    blocked_publish_count: std::sync::atomic::AtomicUsize,
    block_account_subscribe_after_next_publish: std::sync::Mutex<Option<Vec<u8>>>,
    block_account_subscribe: std::sync::Mutex<Option<Vec<u8>>>,
    block_account_group_subscribe: std::sync::Mutex<Option<Vec<u8>>>,
    zero_ack_next_publish: std::sync::atomic::AtomicBool,
    fail_publish_unavailable: std::sync::atomic::AtomicBool,
    fail_publish_kind: std::sync::Mutex<Option<u64>>,
    batch_calls: std::sync::atomic::AtomicUsize,
    publish_started: tokio::sync::Notify,
    publish_release: tokio::sync::Notify,
    subscribe_started: tokio::sync::Notify,
    subscribe_release: tokio::sync::Notify,
    unsubscribe_started: tokio::sync::Notify,
    unsubscribe_release: tokio::sync::Notify,
}

#[derive(Default)]
struct MemberResolutionDirectoryFetcher {
    requests: std::sync::Mutex<Vec<crate::relay_plane::DirectoryFetchRequest>>,
    events: std::sync::Mutex<Vec<NostrTransportEvent>>,
    reject_multi_author: std::sync::atomic::AtomicBool,
    failing_single_author: std::sync::Mutex<Option<String>>,
    stalled_endpoint: std::sync::Mutex<Option<String>>,
}

#[async_trait]
impl crate::relay_plane::DirectoryRelayFetcher for MemberResolutionDirectoryFetcher {
    async fn fetch_directory_events(
        &self,
        request: crate::relay_plane::DirectoryFetchRequest,
    ) -> Result<Vec<crate::relay_plane::DirectoryRelayEventRecord>, String> {
        self.requests.lock().unwrap().push(request.clone());
        if self
            .reject_multi_author
            .load(std::sync::atomic::Ordering::SeqCst)
            && request.queries.iter().any(|query| query.authors.len() > 1)
        {
            return Err("multi-author queries unsupported".to_owned());
        }
        if let Some(failing_author) = self.failing_single_author.lock().unwrap().as_ref()
            && request.queries.iter().any(|query| {
                query.authors.len() == 1 && query.authors.first() == Some(failing_author)
            })
        {
            return Err(format!("single-author query failed for {failing_author}"));
        }
        let stalled_endpoint = self.stalled_endpoint.lock().unwrap().clone();
        if stalled_endpoint.is_some_and(|stalled| {
            request
                .endpoints
                .iter()
                .any(|endpoint| endpoint.0 == stalled)
        }) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let events = self.events.lock().unwrap().clone();
        Ok(events
            .into_iter()
            .filter(|event| {
                request
                    .queries
                    .iter()
                    .any(|query| query.kind == event.kind && query.authors.contains(&event.pubkey))
            })
            .map(|event| crate::relay_plane::DirectoryRelayEventRecord {
                endpoints: request.endpoints.clone(),
                event,
            })
            .collect())
    }
}

impl ScriptedPushRelayClient {
    fn script(&self, results: impl IntoIterator<Item = bool>) {
        *self.publish_results.lock().unwrap() = results.into_iter().collect();
    }

    fn published_event_ids(&self) -> Vec<String> {
        self.published_events
            .lock()
            .unwrap()
            .iter()
            .map(|event| event.id.clone())
            .collect()
    }

    fn attempted_event_ids(&self) -> Vec<String> {
        self.attempted_events
            .lock()
            .unwrap()
            .iter()
            .map(|event| event.id.clone())
            .collect()
    }

    fn block_next_publish(&self) {
        self.block_next_publish
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn block_account_subscribe_after_next_publish(&self, account_id: Vec<u8>) {
        *self
            .block_account_subscribe_after_next_publish
            .lock()
            .unwrap() = Some(account_id);
    }

    fn block_account_inbox_subscribe(&self, account_id: Vec<u8>) {
        *self.block_account_subscribe.lock().unwrap() = Some(account_id);
    }

    fn block_and_fail_account_group_subscribe(&self, account_id: Vec<u8>) {
        *self.block_account_group_subscribe.lock().unwrap() = Some(account_id);
        self.fail_blocked_subscribe
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn block_next_subscribe(&self) {
        self.block_next_subscribe
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn block_next_subscribes(&self, count: usize) {
        self.block_subscribe_count
            .store(count, std::sync::atomic::Ordering::SeqCst);
    }

    fn block_and_fail_next_subscribe(&self) {
        self.fail_blocked_subscribe
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.block_next_subscribe();
    }

    /// Fail the next `subscribe` immediately instead of parking it first, for
    /// tests that need a transport activation to error inside a straight-line
    /// call (no second task to release the block).
    pub(crate) fn fail_next_subscribe(&self) {
        self.fail_next_subscribe
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    pub(crate) fn subscription_count(&self) -> usize {
        self.subscriptions.lock().unwrap().len()
    }

    /// Every subscription this relay has accepted so far.
    pub(crate) fn accepted_subscriptions(&self) -> Vec<NostrSubscription> {
        self.subscriptions.lock().unwrap().clone()
    }

    pub(crate) fn unfloored_account_subscription_count(&self) -> usize {
        self.subscriptions
            .lock()
            .unwrap()
            .iter()
            .filter(|subscription| {
                matches!(
                    subscription,
                    NostrSubscription::AccountInbox { since: None, .. }
                )
            })
            .count()
    }

    async fn wait_for_blocked_subscribe(&self) {
        self.subscribe_started.notified().await;
    }

    async fn wait_for_blocked_subscribes(&self, count: usize) {
        while self
            .blocked_subscribe_count
            .load(std::sync::atomic::Ordering::SeqCst)
            < count
        {
            self.subscribe_started.notified().await;
        }
    }

    fn release_subscribe(&self) {
        self.subscribe_release.notify_waiters();
    }

    fn block_next_unsubscribe(&self) {
        self.block_next_unsubscribe
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    async fn wait_for_blocked_unsubscribe(&self) {
        self.unsubscribe_started.notified().await;
    }

    fn release_unsubscribe(&self) {
        self.unsubscribe_release.notify_waiters();
    }

    fn zero_ack_next_publish(&self) {
        self.zero_ack_next_publish
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn fail_publishes_as_unavailable(&self) {
        self.fail_publish_unavailable
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn allow_publishes(&self) {
        self.fail_publish_unavailable
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }

    fn fail_publishes_of_kind(&self, kind: u64) {
        *self.fail_publish_kind.lock().unwrap() = Some(kind);
    }

    fn allow_all_publish_kinds(&self) {
        self.fail_publish_kind.lock().unwrap().take();
    }

    async fn wait_for_blocked_publish(&self) {
        self.publish_started.notified().await;
    }

    fn block_next_publishes(&self, count: usize) {
        self.block_publish_count
            .store(count, std::sync::atomic::Ordering::SeqCst);
    }

    async fn wait_for_blocked_publishes(&self, count: usize) {
        while self
            .blocked_publish_count
            .load(std::sync::atomic::Ordering::SeqCst)
            < count
        {
            self.publish_started.notified().await;
        }
    }

    fn release_publish(&self) {
        self.publish_release.notify_waiters();
    }

    fn inbox_subscription_count(&self, expected_account_id: &MemberId) -> usize {
        self.subscriptions
            .lock()
            .unwrap()
            .iter()
            .filter(|subscription| {
                matches!(
                    subscription,
                    NostrSubscription::AccountInbox { account_id, .. }
                        if account_id == expected_account_id
                )
            })
            .count()
    }

    fn group_subscription_count(
        &self,
        expected_account_id: &MemberId,
        expected_group_id: &GroupId,
    ) -> usize {
        self.subscriptions
            .lock()
            .unwrap()
            .iter()
            .filter(|subscription| {
                matches!(
                    subscription,
                    NostrSubscription::Group { account_id, group_id, .. }
                        if account_id == expected_account_id && group_id == expected_group_id
                )
            })
            .count()
    }

    fn group_subscribe_attempts(&self) -> usize {
        self.group_subscribe_attempts
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    fn matching_group_subscribe_attempts(
        &self,
        expected_account_id: &MemberId,
        expected_group_id: &GroupId,
    ) -> usize {
        self.subscription_attempts
            .lock()
            .unwrap()
            .iter()
            .filter(|subscription| {
                matches!(
                    subscription,
                    NostrSubscription::Group { account_id, group_id, .. }
                        if account_id == expected_account_id && group_id == expected_group_id
                )
            })
            .count()
    }
}

#[async_trait]
impl NostrRelayClient for ScriptedPushRelayClient {
    async fn subscribe(
        &self,
        subscription: NostrSubscription,
    ) -> Result<(), cgka_traits::TransportAdapterError> {
        self.subscription_attempts
            .lock()
            .unwrap()
            .push(subscription.clone());
        if matches!(&subscription, NostrSubscription::Group { .. }) {
            self.group_subscribe_attempts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        if self
            .fail_next_subscribe
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(cgka_traits::TransportAdapterError::Subscription(
                "injected subscribe failure".to_owned(),
            ));
        }
        let block_for_account = {
            let mut blocked_account = self.block_account_subscribe.lock().unwrap();
            if matches!(&subscription, NostrSubscription::AccountInbox { .. })
                && blocked_account.as_deref() == Some(subscription.account_id().as_slice())
            {
                blocked_account.take();
                true
            } else {
                false
            }
        };
        let block_for_account_group = {
            let mut blocked_account = self.block_account_group_subscribe.lock().unwrap();
            if matches!(&subscription, NostrSubscription::Group { .. })
                && blocked_account.as_deref() == Some(subscription.account_id().as_slice())
            {
                blocked_account.take();
                true
            } else {
                false
            }
        };
        let blocked = block_for_account
            || block_for_account_group
            || self
                .block_next_subscribe
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            || self
                .block_subscribe_count
                .fetch_update(
                    std::sync::atomic::Ordering::SeqCst,
                    std::sync::atomic::Ordering::SeqCst,
                    |remaining| remaining.checked_sub(1),
                )
                .is_ok();
        if blocked {
            self.blocked_subscribe_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.subscribe_started.notify_one();
            self.subscribe_release.notified().await;
            if self
                .fail_blocked_subscribe
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err(cgka_traits::TransportAdapterError::Subscription(
                    "injected startup activation failure".to_owned(),
                ));
            }
        }
        self.subscriptions.lock().unwrap().push(subscription);
        Ok(())
    }

    async fn unsubscribe(
        &self,
        _subscription: NostrSubscription,
    ) -> Result<(), cgka_traits::TransportAdapterError> {
        if self
            .block_next_unsubscribe
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            self.unsubscribe_started.notify_one();
            self.unsubscribe_release.notified().await;
        }
        Ok(())
    }

    async fn unsubscribe_account(
        &self,
        _account_id: &cgka_traits::MemberId,
    ) -> Result<(), cgka_traits::TransportAdapterError> {
        Ok(())
    }

    async fn publish_event(
        &self,
        endpoints: &[TransportEndpoint],
        event: &NostrTransportEvent,
        _required_acks: usize,
    ) -> Result<NostrPublishOutcome, cgka_traits::TransportAdapterError> {
        self.attempted_events.lock().unwrap().push(event.clone());
        if self
            .fail_publish_unavailable
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(cgka_traits::TransportAdapterError::PublishEndpoints(
                cgka_traits::TransportPublishFailure::with_endpoint_failures(
                    "relay unavailable",
                    endpoints
                        .iter()
                        .cloned()
                        .map(|endpoint| cgka_traits::TransportEndpointFailure {
                            endpoint,
                            reason: "relay unavailable".into(),
                            kind: cgka_traits::TransportEndpointFailureKind::RetryableUnavailable,
                            rejection_category: None,
                        })
                        .collect(),
                ),
            ));
        }
        let block_counted_publish = self
            .block_publish_count
            .fetch_update(
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
                |remaining| remaining.checked_sub(1),
            )
            .is_ok();
        if block_counted_publish
            || self
                .block_next_publish
                .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            self.blocked_publish_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.publish_started.notify_one();
            self.publish_release.notified().await;
        }
        if self
            .zero_ack_next_publish
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Ok(NostrPublishOutcome::default());
        }
        let fail_matching_kind = *self.fail_publish_kind.lock().unwrap() == Some(event.kind);
        if fail_matching_kind {
            return Err(cgka_traits::TransportAdapterError::Publish(
                "injected publish failure".to_owned(),
            ));
        }
        if self
            .publish_results
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(true)
        {
            self.published_events.lock().unwrap().push(event.clone());
            if let Some(account_id) = self
                .block_account_subscribe_after_next_publish
                .lock()
                .unwrap()
                .take()
            {
                *self.block_account_subscribe.lock().unwrap() = Some(account_id);
            }
            Ok(NostrPublishOutcome::accepted(endpoints.to_vec()))
        } else {
            Err(cgka_traits::TransportAdapterError::Publish(
                "injected publish failure".to_owned(),
            ))
        }
    }

    async fn publish_events(
        &self,
        requests: &[NostrEventPublishRequest],
    ) -> Vec<Result<NostrPublishOutcome, cgka_traits::TransportAdapterError>> {
        self.batch_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut outcomes = Vec::with_capacity(requests.len());
        for request in requests {
            outcomes.push(
                self.publish_event(&request.endpoints, &request.event, request.required_acks)
                    .await,
            );
        }
        outcomes
    }
}

/// Cut both epoch-gap backfill timers to test scale for a test that drives its
/// relay through [`scripted_eose_pump`]: a pump that stops reporting is then a
/// fast failure rather than a 30 s stall per attempt.
pub(crate) fn bounded_epoch_backfill_config() -> MarmotAppConfig {
    MarmotAppConfig::default()
        .with_dev_epoch_backfill_eose_wait_ms(2_000)
        .with_dev_epoch_backfill_retry_backoff_ms(0)
}

/// Open a client on the app's *own* relay plane.
///
/// [`MarmotApp::client`] mints a fresh plane per client, so a test that drives
/// stored events or end-of-stored-events into `app.relay_plane` would otherwise
/// be talking to a different transport than the client reads.
pub(crate) async fn client_on_app_relay_plane(app: &MarmotApp, label: &str) -> crate::AppClient {
    let relay_plane = app.relay_plane.clone();
    app.client_with_relay_plane(label, &relay_plane, None)
        .await
        .expect("client on the app relay plane")
}

/// Stand-in for the relay pool's end-of-stored-events frames, which an injected
/// relay client never produces.
///
/// The epoch-gap backfill drain ends on EOSE rather than on silence, so a test
/// whose transport is a [`ScriptedPushRelayClient`] has to supply that signal
/// itself. The pump reports EOSE for every subscription the relay has accepted
/// and `accept` selects, on every endpoint it was issued to, and keeps doing so
/// as later subscriptions are registered. Repeat reports are ignored by the
/// adapter, so this is safe to run for the whole test.
pub(crate) struct ScriptedEosePump(tokio::task::JoinHandle<()>);

impl Drop for ScriptedEosePump {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(crate) fn scripted_eose_pump(
    plane: MarmotRelayPlane,
    relay: Arc<ScriptedPushRelayClient>,
    accept: fn(&NostrSubscription) -> bool,
) -> ScriptedEosePump {
    ScriptedEosePump(tokio::spawn(async move {
        loop {
            report_scripted_eose(&plane, &relay, accept).await;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }))
}

/// One pass of [`scripted_eose_pump`], for a test that needs the EOSE to land
/// at a moment of its own choosing.
async fn report_scripted_eose(
    plane: &MarmotRelayPlane,
    relay: &ScriptedPushRelayClient,
    accept: fn(&NostrSubscription) -> bool,
) {
    for subscription in relay.accepted_subscriptions() {
        if !accept(&subscription) {
            continue;
        }
        for endpoint in subscription.endpoints() {
            plane
                .handle_relay_eose_for_test(endpoint.clone(), subscription.subscription_id())
                .await;
        }
    }
}

/// Every subscription reaches end-of-stored-events.
pub(crate) fn every_subscription(_: &NostrSubscription) -> bool {
    true
}

const EXPLICIT_CATCH_UP_BACKFILL_DEADLINE: Duration = Duration::from_secs(5);

fn epoch_gap_probe(nostr_group_id_hex: &str, created_at: u64, marker: &str) -> NostrTransportEvent {
    let mut envelope = vec![0_u8; 12];
    envelope.extend_from_slice(format!("explicit-catch-up-probe:{marker}").as_bytes());
    assert!(envelope.len() >= NOSTR_GROUP_CONTENT_MIN_LEN);
    let event = EventBuilder::new(Kind::MlsGroupMessage, BASE64_STANDARD.encode(envelope))
        .tags([Tag::custom(
            TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::H)),
            [nostr_group_id_hex.to_owned()],
        )])
        .custom_created_at(NostrTimestamp::from_secs(created_at))
        .sign_with_keys(&Keys::generate())
        .expect("sign epoch-gap probe");
    NostrTransportEvent::from_nostr_event(&event).expect("convert epoch-gap probe")
}

async fn inject_epoch_gap_probe(app: &MarmotApp, event: NostrTransportEvent) {
    let delivered = app
        .relay_plane
        .handle_relay_event_for_test(NostrRelayEvent {
            endpoint: TransportEndpoint("wss://relay.example".to_owned()),
            subscription_id: Some("explicit-catch-up-test".to_owned()),
            event,
        })
        .await
        .expect("route epoch-gap probe");
    assert_eq!(
        delivered, 1,
        "the active group route must receive the probe"
    );
}

#[test]
fn explicit_catch_up_arms_and_replays_without_later_traffic() {
    run_composed_app_runtime_test("explicit-catch-up-backfill", || async {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let mut app = MarmotApp::with_relay_and_config(
            dir.path(),
            "wss://relay.example".to_owned(),
            bounded_epoch_backfill_config(),
        )
        .with_test_relay_client(relay.clone());
        app.set_audit_log_settings(crate::AuditLogSettings { enabled: true })
            .unwrap();
        app.relay_plane = MarmotRelayPlane::new_with_loopback(
            Some(Duration::from_secs(120)),
            relay.clone(),
            true,
        );

        let cursor = crate::unix_now_seconds();
        let group_id = {
            let mut client = app.client("alice").await.unwrap();
            let group_id = client
                .create_group("explicit catch-up epoch-gap replay", &[])
                .await
                .unwrap();
            client.state.last_transport_timestamp = Some(cursor);
            app.save_state(&client.state).unwrap();
            group_id
        };
        let group = app
            .group("alice", &hex::encode(group_id.as_slice()))
            .unwrap()
            .expect("local group projection");

        let _eose = scripted_eose_pump(app.relay_plane.clone(), relay.clone(), every_subscription);
        let runtime = MarmotAppRuntime::new(app.clone());
        runtime.start().await.unwrap();
        // This command is deferred behind startup catch-up, so its response is
        // also the steady-state barrier this regression needs.
        runtime.pause_maintenance("alice").await.unwrap();
        let unfloored_before = relay.unfloored_account_subscription_count();

        // Hold the ordinary, floored activation inside explicit CatchUp. The
        // worker is now committed to the command path and cannot consume these
        // queued deliveries through its live receive arm instead.
        relay.block_next_subscribes(2);
        let catch_up_runtime = runtime.clone();
        let catch_up = tokio::spawn(async move { catch_up_runtime.catch_up_accounts().await });
        tokio::time::timeout(
            EXPLICIT_CATCH_UP_BACKFILL_DEADLINE,
            relay.wait_for_blocked_subscribes(2),
        )
        .await
        .expect("explicit catch-up must park its complete floored activation");

        let above_floor = cursor;
        for arm in 0..EPOCH_STALL_BACKFILL_THRESHOLD {
            inject_epoch_gap_probe(
                &app,
                epoch_gap_probe(
                    &group.nostr_routing.nostr_group_id_hex,
                    above_floor,
                    &format!("arm-{arm}"),
                ),
            )
            .await;
        }

        // The next two blocked subscribes are the complete unfloored replay.
        // Without the post-CatchUp replay seam the catch-up task returns after
        // the first release and this wait times out: the regression's RED signal.
        relay.block_next_subscribes(2);
        relay.release_subscribe();
        tokio::time::timeout(
            EXPLICIT_CATCH_UP_BACKFILL_DEADLINE,
            relay.wait_for_blocked_subscribes(4),
        )
        .await
        .expect("armed explicit catch-up must park one complete unfloored replay");

        // Model the relay's stored-event response to that unfloored REQ. The
        // target is older than the persisted cursor's 120-second floor and is
        // offered only after replay starts; no later live delivery is published.
        let below_floor_target = epoch_gap_probe(
            &group.nostr_routing.nostr_group_id_hex,
            cursor.saturating_sub(600),
            "below-floor-target",
        );
        let below_floor_target_id = below_floor_target.id.clone();
        inject_epoch_gap_probe(&app, below_floor_target).await;
        relay.release_subscribe();

        tokio::time::timeout(EXPLICIT_CATCH_UP_BACKFILL_DEADLINE, catch_up)
            .await
            .expect("explicit catch-up must finish after replay activation")
            .expect("catch-up task must not panic")
            .expect("explicit catch-up must report replay success");
        assert_eq!(
            relay.unfloored_account_subscription_count(),
            unfloored_before + 1,
            "the arming catch-up must issue exactly one account-wide replay",
        );

        tokio::time::timeout(EXPLICIT_CATCH_UP_BACKFILL_DEADLINE, async {
            loop {
                if app
                    .load_state("alice")
                    .unwrap()
                    .seen_events
                    .iter()
                    .any(|event_id| event_id == &below_floor_target_id)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the below-floor target must be ingested without later traffic");

        runtime.catch_up_accounts().await.unwrap();
        assert_eq!(
            relay.unfloored_account_subscription_count(),
            unfloored_before + 1,
            "consumed evidence must not trigger a second full-history replay",
        );
        let final_local_epoch = runtime
            .group_mls_state("alice", &group_id)
            .await
            .expect("final local MLS epoch")
            .epoch;

        let audit_rows = app
            .audit_log_files()
            .unwrap()
            .into_iter()
            .flat_map(|file| {
                std::fs::read_to_string(file.path)
                    .unwrap()
                    .lines()
                    .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let armed_rows: Vec<_> = audit_rows
            .iter()
            .filter(|row| row["kind"]["type"] == "epoch_stall_backfill_armed")
            .collect();
        let started_rows: Vec<_> = audit_rows
            .iter()
            .filter(|row| row["kind"]["type"] == "epoch_stall_backfill_started")
            .collect();
        let completed_rows: Vec<_> = audit_rows
            .iter()
            .filter(|row| row["kind"]["type"] == "epoch_stall_backfill_completed")
            .collect();
        assert_eq!(
            armed_rows.len(),
            1,
            "explicit catch-up must arm exactly once: {audit_rows:?}"
        );
        assert_eq!(
            started_rows.len(),
            1,
            "explicit catch-up must start exactly one replay attempt: {audit_rows:?}"
        );
        assert_eq!(
            completed_rows.len(),
            1,
            "explicit catch-up must complete exactly one replay attempt: {audit_rows:?}"
        );
        let attempt_id = armed_rows[0]["context"]["operation_id"]
            .as_str()
            .expect("armed row must carry operation_id");
        assert_eq!(
            started_rows[0]["context"]["operation_id"].as_str(),
            Some(attempt_id)
        );
        assert_eq!(
            completed_rows[0]["context"]["operation_id"].as_str(),
            Some(attempt_id)
        );
        assert_eq!(
            started_rows[0]["kind"]["seam"].as_str(),
            Some("explicit_catch_up")
        );
        assert_eq!(
            completed_rows[0]["kind"]["activation_outcome"].as_str(),
            Some("succeeded")
        );
        assert_eq!(completed_rows[0]["kind"]["retry_ordinal"], 0);
        assert!(
            completed_rows[0]["kind"]["deliveries"]
                .as_u64()
                .is_some_and(|deliveries| deliveries >= 1),
            "the terminal row must count the below-floor delivery"
        );
        let audited_epoch_before = completed_rows[0]["kind"]["local_epoch_before"]
            .as_u64()
            .expect("completed row local epoch before");
        assert_eq!(
            completed_rows[0]["kind"]["local_epoch_after"].as_u64(),
            Some(final_local_epoch),
            "the terminal row must report the observed final local epoch"
        );
        assert_eq!(
            completed_rows[0]["kind"]["group_advanced"].as_bool(),
            Some(final_local_epoch > audited_epoch_before),
            "activation success and group epoch recovery must remain distinct"
        );

        runtime.shutdown().await;
    });
}

#[test]
fn failed_epoch_backfill_activation_retains_one_correlated_retry() {
    run_composed_app_runtime_test("failed-epoch-backfill-retry", || async {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let mut app = MarmotApp::with_relay_and_config(
            dir.path(),
            "wss://relay.example".to_owned(),
            bounded_epoch_backfill_config(),
        )
        .with_test_relay_client(relay.clone());
        app.set_audit_log_settings(crate::AuditLogSettings { enabled: true })
            .unwrap();
        app.relay_plane = MarmotRelayPlane::new_with_loopback(
            Some(Duration::from_secs(120)),
            relay.clone(),
            true,
        );
        let _eose = scripted_eose_pump(app.relay_plane.clone(), relay.clone(), every_subscription);

        let mut client = client_on_app_relay_plane(&app, "alice").await;
        let group_id = client
            .create_group("failed epoch backfill retry", &[])
            .await
            .unwrap();
        let stalled_epoch = client.group_mls_state(&group_id).unwrap().epoch;
        client.apply_backfill_decision(
            &group_id,
            stalled_epoch,
            BackfillDecision::Arm,
            marmot_forensics::EpochStallBackfillTrigger::UndecryptableThreshold,
        );

        relay.fail_next_subscribe();
        client
            .run_pending_epoch_backfill(
                marmot_forensics::EpochBackfillExecutionSeam::ExplicitCatchUp,
            )
            .await
            .expect_err("injected activation failure must surface");
        assert!(
            client.has_pending_epoch_backfill(),
            "failed activation must retain pending recovery"
        );

        let retry = client
            .run_pending_epoch_backfill(marmot_forensics::EpochBackfillExecutionSeam::Maintenance)
            .await
            .expect("retained recovery must retry");
        assert!(
            matches!(retry, crate::EpochBackfillRunOutcome::Completed(_)),
            "retry must execute the pending replay"
        );
        assert!(
            !client.has_pending_epoch_backfill(),
            "successful retry must consume pending recovery"
        );
        drop(client);

        let audit_rows = app
            .audit_log_files()
            .unwrap()
            .into_iter()
            .flat_map(|file| {
                std::fs::read_to_string(file.path)
                    .unwrap()
                    .lines()
                    .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let rows_of_kind = |kind: &str| {
            audit_rows
                .iter()
                .filter(|row| row["kind"]["type"] == kind)
                .collect::<Vec<_>>()
        };
        let armed = rows_of_kind("epoch_stall_backfill_armed");
        let started = rows_of_kind("epoch_stall_backfill_started");
        let failed = rows_of_kind("epoch_stall_backfill_failed");
        let completed = rows_of_kind("epoch_stall_backfill_completed");
        assert_eq!(armed.len(), 1, "one recovery intent must arm once");
        assert_eq!(started.len(), 2, "failure plus retry must start twice");
        assert_eq!(
            failed.len(),
            1,
            "first attempt must have one failed terminal"
        );
        assert_eq!(completed.len(), 1, "retry must have one completed terminal");
        let attempt_id = armed[0]["context"]["operation_id"]
            .as_str()
            .expect("armed operation id");
        for row in started.iter().chain(failed.iter()).chain(completed.iter()) {
            assert_eq!(
                row["context"]["operation_id"].as_str(),
                Some(attempt_id),
                "all lifecycle rows must correlate to one opaque attempt"
            );
        }
        assert_eq!(started[0]["kind"]["retry_ordinal"], 0);
        assert_eq!(failed[0]["kind"]["retry_ordinal"], 0);
        assert_eq!(started[1]["kind"]["retry_ordinal"], 1);
        assert_eq!(completed[0]["kind"]["retry_ordinal"], 1);
        assert_eq!(
            failed[0]["kind"]["activation_outcome"].as_str(),
            Some("failed")
        );
        assert_eq!(failed[0]["kind"]["deliveries"], 0);
        assert_eq!(failed[0]["kind"]["group_advanced"], false);
    });
}

/// Config every drain-completion test starts from: both epoch-gap backfill
/// timers cut to test scale, so a give-up path costs milliseconds rather than
/// the production 30 s drain budget and 15 s retry cooldown.
fn backfill_drain_test_config() -> MarmotAppConfig {
    MarmotAppConfig::default()
        .with_dev_epoch_backfill_eose_wait_ms(300)
        .with_dev_epoch_backfill_retry_backoff_ms(0)
}

/// A single-account app with one armed epoch-gap backfill intent on an injected
/// relay client: the shape every drain-completion test below starts from.
///
/// Callers shorten the drain's silence budget and the unconfirmed-retry
/// cooldown from their production values ([`crate::EPOCH_BACKFILL_EOSE_WAIT`],
/// [`crate::EPOCH_BACKFILL_RETRY_BACKOFF`]) so both give-up paths are testable
/// in wall-clock a test can afford.
async fn armed_epoch_backfill(
    dir: &tempfile::TempDir,
    relay: &Arc<ScriptedPushRelayClient>,
    config: MarmotAppConfig,
) -> (MarmotApp, crate::AppClient, cgka_traits::GroupId) {
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let mut app =
        MarmotApp::with_relay_and_config(dir.path(), "wss://relay.example".to_owned(), config)
            .with_test_relay_client(relay.clone());
    app.set_audit_log_settings(crate::AuditLogSettings { enabled: true })
        .unwrap();
    app.relay_plane =
        MarmotRelayPlane::new_with_loopback(Some(Duration::from_secs(120)), relay.clone(), true);

    let mut client = client_on_app_relay_plane(&app, "alice").await;
    let group_id = client
        .create_group("epoch backfill drain completion", &[])
        .await
        .unwrap();
    let stalled_epoch = client.group_mls_state(&group_id).unwrap().epoch;
    client.apply_backfill_decision(
        &group_id,
        stalled_epoch,
        BackfillDecision::Arm,
        marmot_forensics::EpochStallBackfillTrigger::UndecryptableThreshold,
    );
    (app, client, group_id)
}

/// Every audit row this app has recorded so far.
fn recorded_audit_rows(app: &MarmotApp) -> Vec<serde_json::Value> {
    app.audit_log_files()
        .unwrap()
        .into_iter()
        .flat_map(|file| {
            std::fs::read_to_string(file.path)
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
                .collect::<Vec<_>>()
        })
        .collect()
}

fn recorded_rows_of_kind<'rows>(
    rows: &'rows [serde_json::Value],
    kind: &str,
) -> Vec<&'rows serde_json::Value> {
    rows.iter()
        .filter(|row| row["kind"]["type"] == kind)
        .collect()
}

#[test]
fn epoch_backfill_drain_collects_history_that_lands_after_the_first_sync_wait() {
    run_composed_app_runtime_test("backfill-drain-late-history", || async {
        let dir = tempfile::tempdir().unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let (app, mut client, group_id) = armed_epoch_backfill(
            &dir,
            &relay,
            backfill_drain_test_config().with_dev_epoch_backfill_eose_wait_ms(10_000),
        )
        .await;
        let group = app
            .group("alice", &hex::encode(group_id.as_slice()))
            .unwrap()
            .expect("local group projection");

        // Model the relay the 2026-08 field export caught: it answers the
        // unfloored whole-account REQ only after the drain's first-event wait
        // has already elapsed, then reports end-of-stored-events.
        let stored_history = epoch_gap_probe(
            &group.nostr_routing.nostr_group_id_hex,
            crate::unix_now_seconds(),
            "late-stored-history",
        );
        let slow_relay = {
            let app = app.clone();
            let relay = relay.clone();
            tokio::spawn(async move {
                tokio::time::sleep(SDK_FIRST_SYNC_WAIT + Duration::from_millis(400)).await;
                inject_epoch_gap_probe(&app, stored_history).await;
                report_scripted_eose(&app.relay_plane, &relay, every_subscription).await;
            })
        };

        let outcome = client
            .run_pending_epoch_backfill(marmot_forensics::EpochBackfillExecutionSeam::Maintenance)
            .await
            .expect("armed replay must run");
        slow_relay
            .await
            .expect("scripted relay task must not panic");
        assert!(
            matches!(outcome, crate::EpochBackfillRunOutcome::Completed(_)),
            "a replay the relays confirmed they served must complete"
        );
        assert!(
            !client.has_pending_epoch_backfill(),
            "a confirmed replay must consume its pending recovery"
        );
        drop(client);

        let rows = recorded_audit_rows(&app);
        let completed = recorded_rows_of_kind(&rows, "epoch_stall_backfill_completed");
        assert_eq!(completed.len(), 1, "the replay must have one terminal row");
        assert_eq!(
            completed[0]["kind"]["deliveries"], 1,
            "the drain must still be listening when the relay answers"
        );
    });
}

#[test]
fn epoch_backfill_drain_ends_when_relays_report_end_of_stored_events() {
    run_composed_app_runtime_test("backfill-drain-prompt-eose", || async {
        let dir = tempfile::tempdir().unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        // A production-sized silence budget: reaching it would take 30s, so
        // completing promptly is what this asserts.
        let (app, mut client, _group_id) = armed_epoch_backfill(
            &dir,
            &relay,
            backfill_drain_test_config().with_dev_epoch_backfill_eose_wait_ms(30_000),
        )
        .await;
        let _eose = scripted_eose_pump(app.relay_plane.clone(), relay.clone(), every_subscription);

        let started = std::time::Instant::now();
        let outcome = client
            .run_pending_epoch_backfill(marmot_forensics::EpochBackfillExecutionSeam::Maintenance)
            .await
            .expect("armed replay must run");
        assert!(
            matches!(outcome, crate::EpochBackfillRunOutcome::Completed(_)),
            "prompt end-of-stored-events must complete the replay"
        );
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "end-of-stored-events must end the drain, not the silence budget"
        );
    });
}

/// One already-seen event redelivered every `interval` until the returned flag
/// is set or `deadline` passes, modelling a relay that keeps a drain's socket
/// warm with traffic carrying no new history.
///
/// The first injection is novel, so a caller expecting `n` skips must run the
/// pump for `n + 1` injections.
fn redelivery_pump(
    app: &MarmotApp,
    event: NostrTransportEvent,
    interval: Duration,
    deadline: Duration,
) -> (
    Arc<std::sync::atomic::AtomicBool>,
    tokio::task::JoinHandle<u64>,
) {
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let handle = {
        let app = app.clone();
        let stop = stop.clone();
        tokio::spawn(async move {
            let expires_at = std::time::Instant::now() + deadline;
            let mut sent = 0_u64;
            while !stop.load(std::sync::atomic::Ordering::Relaxed)
                && std::time::Instant::now() < expires_at
            {
                inject_epoch_gap_probe(&app, event.clone()).await;
                sent += 1;
                tokio::time::sleep(interval).await;
            }
            sent
        })
    };
    (stop, handle)
}

/// Repeatedly enqueue one already-peeled delivery directly onto an account's
/// test transport channel. This models the reachable adapter/engine route-index
/// disagreement that cannot be produced through the relay plane's outer route
/// gate.
#[cfg(feature = "test-policy-overrides")]
fn transport_delivery_redelivery_pump(
    app: &MarmotApp,
    delivery: cgka_traits::TransportDelivery,
    interval: Duration,
    deadline: Duration,
) -> (
    Arc<std::sync::atomic::AtomicBool>,
    tokio::task::JoinHandle<u64>,
) {
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let handle = {
        let app = app.clone();
        let stop = stop.clone();
        tokio::spawn(async move {
            let expires_at = std::time::Instant::now() + deadline;
            let mut sent = 0_u64;
            while !stop.load(std::sync::atomic::Ordering::Relaxed)
                && std::time::Instant::now() < expires_at
                && app
                    .relay_plane
                    .inject_delivery_for_test(delivery.clone())
                    .await
            {
                sent += 1;
                tokio::time::sleep(interval).await;
            }
            sent
        })
    };
    (stop, handle)
}

/// The end-of-stored-events gate must be reachable from the delivery path.
///
/// A relay redelivering faster than [`SDK_DRAIN_WAIT`] never lets the receive
/// timeout fire, and the timeout is where the drain consults its gate. Before
/// the delivery-path poll, a drain in this shape ran until the redelivery
/// stopped even though every subscription had reported end-of-stored-events
/// from the first moment — the drain had already won and could not say so.
#[test]
fn epoch_backfill_drain_ends_on_end_of_stored_events_while_duplicates_stream() {
    run_composed_app_runtime_test("backfill-drain-eose-under-duplicates", || async {
        let dir = tempfile::tempdir().unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let (app, mut client, group_id) = armed_epoch_backfill(
            &dir,
            &relay,
            backfill_drain_test_config().with_dev_epoch_backfill_eose_wait_ms(30_000),
        )
        .await;
        let group = app
            .group("alice", &hex::encode(group_id.as_slice()))
            .unwrap()
            .expect("local group projection");

        // Every subscription is served from the start: the gate's Complete
        // verdict is available for the whole drain.
        let _eose = scripted_eose_pump(app.relay_plane.clone(), relay.clone(), every_subscription);
        // Redelivery at 100 ms, well inside SDK_DRAIN_WAIT, for far longer than
        // the drain should need.
        let (stop, pump) = redelivery_pump(
            &app,
            epoch_gap_probe(
                &group.nostr_routing.nostr_group_id_hex,
                crate::unix_now_seconds(),
                "eose-under-duplicates",
            ),
            Duration::from_millis(100),
            Duration::from_secs(20),
        );

        let started = std::time::Instant::now();
        let outcome = client
            .run_pending_epoch_backfill(marmot_forensics::EpochBackfillExecutionSeam::Maintenance)
            .await
            .expect("armed replay must run");
        let drained_in = started.elapsed();
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = pump.await;

        assert!(
            matches!(outcome, crate::EpochBackfillRunOutcome::Completed(_)),
            "a served history must complete even while duplicates arrive"
        );
        assert!(
            drained_in < Duration::from_secs(3),
            "the delivery-path gate poll must end the drain promptly, not when \
             the redelivery stops; took {drained_in:?}"
        );
    });
}

/// Duplicate traffic is liveness but not recovery progress. It must not keep
/// the serial account worker inside one backfill drain forever when the relay
/// never reports end-of-stored-events.
#[test]
#[cfg(feature = "test-policy-overrides")]
fn epoch_backfill_drain_yields_when_duplicates_stream_without_eose() {
    run_composed_app_runtime_test("backfill-drain-duplicate-quantum", || async {
        let dir = tempfile::tempdir().unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let (app, mut client, group_id) = armed_epoch_backfill(
            &dir,
            &relay,
            backfill_drain_test_config()
                .with_dev_epoch_backfill_eose_wait_ms(30_000)
                .with_dev_epoch_backfill_execution_quantum_ms(400),
        )
        .await;
        let group = app
            .group("alice", &hex::encode(group_id.as_slice()))
            .unwrap()
            .expect("local group projection");
        let duplicate = epoch_gap_probe(
            &group.nostr_routing.nostr_group_id_hex,
            crate::unix_now_seconds(),
            "duplicates-without-eose",
        );
        client.remember_seen_event(duplicate.id.clone());
        let (stop, pump) = redelivery_pump(
            &app,
            duplicate,
            Duration::from_millis(50),
            Duration::from_secs(5),
        );

        let started = std::time::Instant::now();
        let outcome = tokio::time::timeout(
            Duration::from_millis(1_500),
            client.run_pending_epoch_backfill(
                marmot_forensics::EpochBackfillExecutionSeam::Maintenance,
            ),
        )
        .await;
        let drained_in = started.elapsed();
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = pump.await;
        let outcome = outcome
            .expect("duplicate-only replay must yield its account-worker quantum")
            .expect("a bounded incomplete replay is not a transport error");

        assert!(
            matches!(outcome, crate::EpochBackfillRunOutcome::Incomplete(_)),
            "a quantum yield without EOSE must remain incomplete"
        );
        assert!(
            drained_in < Duration::from_millis(1_500),
            "the duplicate-only drain must yield within its configured quantum; took {drained_in:?}"
        );
        assert!(
            client.has_pending_epoch_backfill(),
            "a quantum yield must retain the recovery intent"
        );
        drop(client);
        let reopened = client_on_app_relay_plane(&app, "alice").await;
        assert!(
            reopened.has_pending_epoch_backfill(),
            "an incomplete quantum must re-arm from durable recovery state after restart"
        );
        drop(reopened);

        let rows = recorded_audit_rows(&app);
        assert!(
            recorded_rows_of_kind(&rows, "epoch_stall_backfill_completed").is_empty(),
            "a quantum yield must not be reported as successful replay"
        );
        let failed = recorded_rows_of_kind(&rows, "epoch_stall_backfill_failed");
        assert_eq!(failed.len(), 1);
        assert_eq!(
            failed[0]["kind"]["error_kind"].as_str(),
            Some("backfill_drain_no_progress_quantum_yield")
        );
        assert_eq!(failed[0]["kind"]["deliveries"], 0);
        assert!(failed[0]["kind"]["skipped"].as_u64().unwrap() > 0);
        assert!(failed[0]["kind"]["completion_kind"].is_null());
    });
}

/// An unknown-group object that the engine leaves entirely unpersisted is no
/// more recovery progress than a duplicate. Re-serving it must yield into the
/// no-progress cooldown rather than keeping the account worker in immediate
/// back-to-back quanta.
#[test]
#[cfg(feature = "test-policy-overrides")]
fn unpersisted_unknown_group_stream_is_no_progress_and_paced() {
    run_composed_app_runtime_test("backfill-unpersisted-unknown-group", || async {
        let dir = tempfile::tempdir().unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let (app, mut client, group_id) = armed_epoch_backfill(
            &dir,
            &relay,
            backfill_drain_test_config()
                .with_dev_epoch_backfill_eose_wait_ms(30_000)
                .with_dev_epoch_backfill_execution_quantum_ms(400)
                .with_dev_epoch_backfill_retry_backoff_ms(60_000),
        )
        .await;
        let stalled_epoch = client.group_mls_state(&group_id).unwrap().epoch;
        let bystander = bystander_stalled_below_threshold(&mut client, stalled_epoch);
        let account_id_hex = AccountHome::open(dir.path())
            .account("alice")
            .unwrap()
            .account_id_hex;
        let unknown = unknown_route_delivery(
            &account_id_hex,
            crate::unix_now_seconds(),
            "unpersisted-backfill-prefix",
        );
        let event_id = hex::encode(unknown.message.id.as_slice());
        let (stop, pump) = transport_delivery_redelivery_pump(
            &app,
            unknown,
            Duration::from_millis(50),
            Duration::from_secs(3),
        );

        let outcome = client
            .run_pending_epoch_backfill(marmot_forensics::EpochBackfillExecutionSeam::Maintenance)
            .await
            .expect("unpersisted stream must yield without a transport error");
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let sent = pump.await.expect("redelivery pump must not panic");

        assert!(sent > 1, "the test must exercise same-id redelivery");
        assert!(matches!(
            outcome,
            crate::EpochBackfillRunOutcome::Incomplete(_)
        ));
        assert!(
            !client.seen_events_index.contains(&event_id),
            "an unpersisted object must remain fetchable"
        );
        assert!(
            client.epoch_backfill_retry_not_before.is_some(),
            "an unproductive quantum must earn the retry cooldown"
        );
        assert!(matches!(
            client
                .run_pending_epoch_backfill(marmot_forensics::EpochBackfillExecutionSeam::Receive)
                .await
                .expect("a paced seam is not a failure"),
            crate::EpochBackfillRunOutcome::Deferred
        ));
        assert_eq!(
            bystander_crosses_threshold(&mut client, bystander, stalled_epoch),
            BackfillDecision::Arm,
            "an unpersisted-only quantum must not disarm tracked recovery"
        );

        let rows = recorded_audit_rows(&app);
        let failed = recorded_rows_of_kind(&rows, "epoch_stall_backfill_failed");
        assert_eq!(failed.len(), 1);
        assert_eq!(
            failed[0]["kind"]["error_kind"].as_str(),
            Some("backfill_drain_no_progress_quantum_yield")
        );
        assert!(failed[0]["kind"]["deliveries"].as_u64().unwrap() > 0);
        assert_eq!(
            failed[0]["kind"]["refused"], 0,
            "unknown-group drops remain distinct from resource refusals"
        );
    });
}

/// Worker-quantum yields do not count as EOSE-unconfirmed attempts. Repeated
/// duplicate-only slices must retain the intent until the required coverage is
/// actually confirmed.
#[test]
#[cfg(feature = "test-policy-overrides")]
fn duplicate_only_quanta_retain_the_eose_coverage_gate() {
    run_composed_app_runtime_test("backfill-duplicate-quanta-eose-budget", || async {
        const DUPLICATE_QUANTA: u64 = 3;
        let dir = tempfile::tempdir().unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let (app, mut client, group_id) = armed_epoch_backfill(
            &dir,
            &relay,
            backfill_drain_test_config()
                .with_dev_epoch_backfill_eose_wait_ms(30_000)
                .with_dev_epoch_backfill_execution_quantum_ms(900),
        )
        .await;
        let group = app
            .group("alice", &hex::encode(group_id.as_slice()))
            .unwrap()
            .expect("local group projection");
        let duplicate = epoch_gap_probe(
            &group.nostr_routing.nostr_group_id_hex,
            crate::unix_now_seconds(),
            "duplicates-must-not-unlock-coverage",
        );
        client.remember_seen_event(duplicate.id.clone());
        let (stop, pump) = redelivery_pump(
            &app,
            duplicate,
            Duration::from_millis(50),
            Duration::from_secs(6),
        );

        for attempt in 0..DUPLICATE_QUANTA {
            let outcome = client
                .run_pending_epoch_backfill(
                    marmot_forensics::EpochBackfillExecutionSeam::ExplicitCatchUp,
                )
                .await
                .expect("duplicate-only quantum runs");
            assert!(
                matches!(outcome, crate::EpochBackfillRunOutcome::Incomplete(_)),
                "duplicate-only quantum {attempt} must retain the intent"
            );
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = pump.await;

        let outcome = client
            .run_pending_epoch_backfill(
                marmot_forensics::EpochBackfillExecutionSeam::ExplicitCatchUp,
            )
            .await
            .expect("quiet continuation runs");
        assert!(
            matches!(outcome, crate::EpochBackfillRunOutcome::Incomplete(_)),
            "worker-quantum yields must not weaken the EOSE coverage gate"
        );
        assert!(
            client.has_pending_epoch_backfill(),
            "an EOSE-unconfirmed continuation must retain the durable intent"
        );

        let _eose = scripted_eose_pump(app.relay_plane.clone(), relay.clone(), every_subscription);
        let outcome = client
            .run_pending_epoch_backfill(
                marmot_forensics::EpochBackfillExecutionSeam::ExplicitCatchUp,
            )
            .await
            .expect("EOSE-confirmed continuation runs");
        assert!(matches!(
            outcome,
            crate::EpochBackfillRunOutcome::Completed(_)
        ));
        assert!(!client.has_pending_epoch_backfill());

        let rows = recorded_audit_rows(&app);
        let failed = recorded_rows_of_kind(&rows, "epoch_stall_backfill_failed");
        assert_eq!(failed.len(), DUPLICATE_QUANTA as usize + 1);
        assert!(failed.iter().all(|row| {
            row["kind"]["error_kind"].as_str() == Some("backfill_drain_no_progress_quantum_yield")
        }));
        let completed = recorded_rows_of_kind(&rows, "epoch_stall_backfill_completed");
        assert_eq!(completed.len(), 1);
        assert_eq!(
            completed[0]["kind"]["completion_kind"].as_str(),
            Some("end_of_stored_events")
        );
    });
}

/// Productive replays use the same worker quantum, but their checkpointed
/// prefix survives the yield and they do not spend the EOSE-failure ordinal.
/// A later EOSE-confirmed quantum can therefore finish the same arm.
#[test]
#[cfg(feature = "test-policy-overrides")]
fn epoch_backfill_drain_continues_novel_history_across_worker_quanta() {
    run_composed_app_runtime_test("backfill-drain-productive-quanta", || async {
        let dir = tempfile::tempdir().unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let (app, mut client, group_id) = armed_epoch_backfill(
            &dir,
            &relay,
            backfill_drain_test_config()
                .with_dev_epoch_backfill_eose_wait_ms(30_000)
                .with_dev_epoch_backfill_execution_quantum_ms(250),
        )
        .await;
        let group = app
            .group("alice", &hex::encode(group_id.as_slice()))
            .unwrap()
            .expect("local group projection");
        // Stay below the detector's independent eight-undeliverable arm
        // threshold: this test owns one pre-armed recovery intent and is about
        // splitting its novel prefix, not coalescing a second intent into it.
        let events = (0..6_u32)
            .map(|index| {
                epoch_gap_probe(
                    &group.nostr_routing.nostr_group_id_hex,
                    crate::unix_now_seconds(),
                    &format!("productive-quantum-{index}"),
                )
            })
            .collect::<Vec<_>>();
        let event_ids = events
            .iter()
            .map(|event| event.id.clone())
            .collect::<Vec<_>>();
        let producer = {
            let app = app.clone();
            tokio::spawn(async move {
                for event in events {
                    inject_epoch_gap_probe(&app, event).await;
                    tokio::time::sleep(Duration::from_millis(120)).await;
                }
            })
        };

        let first = client
            .run_pending_epoch_backfill(marmot_forensics::EpochBackfillExecutionSeam::Maintenance)
            .await
            .expect("productive replay quantum runs");
        assert!(matches!(
            first,
            crate::EpochBackfillRunOutcome::Incomplete(_)
        ));
        assert!(
            event_ids
                .iter()
                .any(|event_id| client.seen_events_index.contains(event_id)),
            "the first quantum must retain a novel prefix"
        );
        let durable_after_first = app.load_state("alice").unwrap();
        assert!(
            event_ids
                .iter()
                .any(|event_id| durable_after_first.seen_events.contains(event_id)),
            "the yielded prefix must be checkpointed before the worker is released"
        );
        producer
            .await
            .expect("novel-history producer must not panic");

        let mut quanta = 1_u32;
        while !event_ids
            .iter()
            .all(|event_id| client.seen_events_index.contains(event_id))
        {
            let outcome = client
                .run_pending_epoch_backfill(
                    marmot_forensics::EpochBackfillExecutionSeam::Maintenance,
                )
                .await
                .expect("next productive replay quantum runs");
            assert!(matches!(
                outcome,
                crate::EpochBackfillRunOutcome::Incomplete(_)
            ));
            quanta += 1;
            assert!(quanta < 10, "novel replay must advance across quanta");
        }
        assert!(
            quanta >= 2,
            "the replay must actually cross a quantum boundary"
        );
        assert!(client.has_pending_epoch_backfill());

        let _eose = scripted_eose_pump(app.relay_plane.clone(), relay.clone(), every_subscription);
        let completed = client
            .run_pending_epoch_backfill(marmot_forensics::EpochBackfillExecutionSeam::Maintenance)
            .await
            .expect("EOSE-confirmed continuation runs");
        assert!(matches!(
            completed,
            crate::EpochBackfillRunOutcome::Completed(_)
        ));
        assert!(!client.has_pending_epoch_backfill());
        drop(client);
        let reopened = client_on_app_relay_plane(&app, "alice").await;
        assert!(
            !reopened.has_pending_epoch_backfill(),
            "EOSE completion must consume the exact durable recovery marker"
        );
        drop(reopened);

        let rows = recorded_audit_rows(&app);
        let failed = recorded_rows_of_kind(&rows, "epoch_stall_backfill_failed");
        assert_eq!(failed.len(), quanta as usize);
        assert!(failed.iter().all(|row| {
            row["kind"]["error_kind"].as_str()
                == Some("backfill_drain_novel_progress_quantum_yield")
        }));
        assert_eq!(
            failed
                .iter()
                .map(|row| row["kind"]["deliveries"].as_u64().unwrap())
                .sum::<u64>(),
            event_ids.len() as u64,
            "every novel delivery belongs to exactly one checkpointed quantum"
        );
        let completed = recorded_rows_of_kind(&rows, "epoch_stall_backfill_completed");
        assert_eq!(completed.len(), 1);
        assert_eq!(
            completed[0]["kind"]["completion_kind"].as_str(),
            Some("end_of_stored_events")
        );
    });
}

/// A command queued after a steady-state CatchUp enters duplicate-only
/// backfill must be serviced when that drain yields, rather than timing out
/// behind an open-ended receive loop.
#[test]
#[cfg(feature = "test-policy-overrides")]
fn account_worker_services_local_command_after_duplicate_backfill_quantum() {
    run_composed_app_runtime_test("backfill-worker-command-quantum", || async {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let config = MarmotAppConfig::default()
            .with_dev_epoch_backfill_eose_wait_ms(30_000)
            .with_dev_epoch_backfill_execution_quantum_ms(400)
            .with_dev_epoch_backfill_retry_backoff_ms(1_500);
        let mut app =
            MarmotApp::with_relay_and_config(dir.path(), "wss://relay.example".to_owned(), config)
                .with_test_relay_client(relay.clone());
        app.set_audit_log_settings(crate::AuditLogSettings { enabled: true })
            .unwrap();
        app.relay_plane = MarmotRelayPlane::new_with_loopback(
            Some(Duration::from_secs(120)),
            relay.clone(),
            true,
        );

        let cursor = crate::unix_now_seconds();
        let group_id = {
            let mut client = app.client("alice").await.unwrap();
            let group_id = client
                .create_group("bounded backfill worker", &[])
                .await
                .unwrap();
            client.state.last_transport_timestamp = Some(cursor);
            app.save_state(&client.state).unwrap();
            group_id
        };
        let group = app
            .group("alice", &hex::encode(group_id.as_slice()))
            .unwrap()
            .expect("local group projection");

        let runtime = MarmotAppRuntime::new(app.clone());
        runtime.start().await.unwrap();
        runtime.pause_maintenance("alice").await.unwrap();

        relay.block_next_subscribes(2);
        let catch_up_runtime = runtime.clone();
        let catch_up = tokio::spawn(async move { catch_up_runtime.catch_up_accounts().await });
        tokio::time::timeout(
            EXPLICIT_CATCH_UP_BACKFILL_DEADLINE,
            relay.wait_for_blocked_subscribes(2),
        )
        .await
        .expect("ordinary catch-up activation must block");

        let mut duplicate = None;
        for arm in 0..EPOCH_STALL_BACKFILL_THRESHOLD {
            let probe = epoch_gap_probe(
                &group.nostr_routing.nostr_group_id_hex,
                cursor,
                &format!("worker-arm-{arm}"),
            );
            duplicate.get_or_insert_with(|| probe.clone());
            inject_epoch_gap_probe(&app, probe).await;
        }

        relay.block_next_subscribes(2);
        relay.release_subscribe();
        tokio::time::timeout(
            EXPLICIT_CATCH_UP_BACKFILL_DEADLINE,
            relay.wait_for_blocked_subscribes(4),
        )
        .await
        .expect("armed catch-up must enter its unfloored replay");
        let (stop, pump) = redelivery_pump(
            &app,
            duplicate.expect("one arm probe"),
            Duration::from_millis(50),
            Duration::from_secs(5),
        );
        relay.release_subscribe();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !catch_up.is_finished(),
            "the duplicate stream must still hold the catch-up before its quantum"
        );

        let command_started = std::time::Instant::now();
        let state = tokio::time::timeout(
            Duration::from_millis(1_500),
            runtime.group_mls_state("alice", &group_id),
        )
        .await
        .expect("queued local read must be serviced after the backfill quantum")
        .expect("group MLS state remains readable");
        let command_wait = command_started.elapsed();
        assert_eq!(state.group_id_hex, hex::encode(group_id.as_slice()));
        assert!(
            command_wait < Duration::from_millis(1_500),
            "queued local read exceeded the worker-yield bound: {command_wait:?}"
        );
        catch_up
            .await
            .expect("catch-up task must not panic")
            .expect("an incomplete bounded replay is not a catch-up error");
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = pump.await;

        let rows = recorded_audit_rows(&app);
        let failed = recorded_rows_of_kind(&rows, "epoch_stall_backfill_failed");
        assert_eq!(failed.len(), 1);
        assert_eq!(
            failed[0]["kind"]["error_kind"].as_str(),
            Some("backfill_drain_no_progress_quantum_yield")
        );
        runtime.shutdown().await;
    });
}

/// `skipped` counts the receives a drain dropped as echo or duplicate, and
/// `deliveries` keeps its ingested-only meaning.
///
/// Without the split, a long drain that was doing work and one held open by
/// traffic carrying no new history are indistinguishable in a field export.
#[test]
fn epoch_backfill_drain_records_skipped_receives_beside_ingested_deliveries() {
    run_composed_app_runtime_test("backfill-drain-skipped-counter", || async {
        let dir = tempfile::tempdir().unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let (app, mut client, group_id) = armed_epoch_backfill(
            &dir,
            &relay,
            backfill_drain_test_config().with_dev_epoch_backfill_eose_wait_ms(400),
        )
        .await;
        let group = app
            .group("alice", &hex::encode(group_id.as_slice()))
            .unwrap()
            .expect("local group projection");

        // No relay reports end-of-stored-events, so the silence budget is what
        // ends this drain. Six injections of one event: the first is novel, the
        // other five are already-seen skips.
        let (stop, pump) = redelivery_pump(
            &app,
            epoch_gap_probe(
                &group.nostr_routing.nostr_group_id_hex,
                crate::unix_now_seconds(),
                "skipped-counter",
            ),
            Duration::from_millis(100),
            Duration::from_millis(550),
        );

        let outcome = client
            .run_pending_epoch_backfill(marmot_forensics::EpochBackfillExecutionSeam::Maintenance)
            .await
            .expect("armed replay must run");
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let injected = pump.await.expect("redelivery pump must not panic");
        assert!(
            matches!(outcome, crate::EpochBackfillRunOutcome::Incomplete(_)),
            "no relay reported end-of-stored-events, so the replay is unconfirmed"
        );
        drop(client);

        let rows = recorded_audit_rows(&app);
        let drains = recorded_rows_of_kind(&rows, "sync_drain");
        let backfill_drain = drains
            .iter()
            .find(|row| {
                row["kind"]["skipped"]
                    .as_u64()
                    .is_some_and(|count| count > 0)
            })
            .expect("the backfill drain must record its skipped receives");
        assert_eq!(
            backfill_drain["kind"]["deliveries"], 1,
            "only the first injection carried new history"
        );
        assert_eq!(
            backfill_drain["kind"]["skipped"].as_u64().unwrap(),
            injected - 1,
            "every later redelivery of the same event must count as skipped"
        );

        let failed = recorded_rows_of_kind(&rows, "epoch_stall_backfill_failed");
        assert_eq!(
            failed.len(),
            1,
            "the unconfirmed replay must have one terminal row"
        );
        assert_eq!(failed[0]["kind"]["deliveries"], 1);
        assert_eq!(
            failed[0]["kind"]["skipped"].as_u64().unwrap(),
            injected - 1,
            "the terminal row must carry the same split as the drain row"
        );
    });
}

/// Regression guard for the deliberate choice not to gate the silence reset on
/// progress.
///
/// The 2026-08 field export's working replays trickled novel events further
/// apart than any budget worth setting, with non-novel traffic in between. If
/// a later change stops redeliveries from resetting `silence_started` — the
/// obvious way to bound a duplicate storm that never reports
/// end-of-stored-events — this drain collects its first event and gives up.
#[test]
fn epoch_backfill_drain_collects_novel_history_that_trickles_slower_than_its_budget() {
    run_composed_app_runtime_test("backfill-drain-stuttering-history", || async {
        let dir = tempfile::tempdir().unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let (app, mut client, group_id) = armed_epoch_backfill(
            &dir,
            &relay,
            backfill_drain_test_config().with_dev_epoch_backfill_eose_wait_ms(400),
        )
        .await;
        let group = app
            .group("alice", &hex::encode(group_id.as_slice()))
            .unwrap()
            .expect("local group projection");
        let nostr_group_id_hex = group.nostr_routing.nostr_group_id_hex.clone();

        // Filler keeps the socket warm; it is bounded so the drain can still
        // end once the novel history is exhausted.
        let (stop, pump) = redelivery_pump(
            &app,
            epoch_gap_probe(
                &nostr_group_id_hex,
                crate::unix_now_seconds(),
                "stuttering-filler",
            ),
            Duration::from_millis(100),
            Duration::from_millis(3_300),
        );
        // Five novel events, 600 ms apart — every gap wider than the 400 ms
        // silence budget.
        let novel = {
            let app = app.clone();
            tokio::spawn(async move {
                for index in 0..5_u32 {
                    tokio::time::sleep(Duration::from_millis(600)).await;
                    inject_epoch_gap_probe(
                        &app,
                        epoch_gap_probe(
                            &nostr_group_id_hex,
                            crate::unix_now_seconds(),
                            &format!("stuttering-novel-{index}"),
                        ),
                    )
                    .await;
                }
            })
        };

        let outcome = client
            .run_pending_epoch_backfill(marmot_forensics::EpochBackfillExecutionSeam::Maintenance)
            .await
            .expect("armed replay must run");
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = pump.await;
        novel.abort();
        assert!(
            matches!(outcome, crate::EpochBackfillRunOutcome::Incomplete(_)),
            "no relay reported end-of-stored-events, so the replay is unconfirmed"
        );
        drop(client);

        let rows = recorded_audit_rows(&app);
        let failed = recorded_rows_of_kind(&rows, "epoch_stall_backfill_failed");
        assert_eq!(failed.len(), 1);
        assert_eq!(
            failed[0]["kind"]["deliveries"], 6,
            "the drain must collect the filler's first event and all five novel \
             ones, not stop at the first budget-wide gap"
        );
    });
}

#[test]
fn epoch_backfill_without_relay_end_of_stored_events_stays_pending() {
    run_composed_app_runtime_test("backfill-drain-no-eose", || async {
        let dir = tempfile::tempdir().unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let (app, mut client, group_id) =
            armed_epoch_backfill(&dir, &relay, backfill_drain_test_config()).await;
        let stalled_epoch = client.group_mls_state(&group_id).unwrap().epoch;

        // A second group stalled at the same time but has not armed. Only
        // `mark_replayed` suppresses its own arm, and only a replay that
        // actually served this account's history has earned that.
        let bystander = cgka_traits::GroupId::new(vec![7_u8; 32]);
        for probe in 0..EPOCH_STALL_BACKFILL_THRESHOLD - 1 {
            assert_eq!(
                client.epoch_stall.observe_undecryptable(
                    bystander.clone(),
                    format!("bystander-{probe}"),
                    cgka_traits::EpochId(stalled_epoch),
                    epoch_stall_test_now_ms(),
                ),
                BackfillDecision::Skip,
            );
        }

        // No relay reports end-of-stored-events: the subscriptions registered
        // but were never served.
        let outcome = client
            .run_pending_epoch_backfill(marmot_forensics::EpochBackfillExecutionSeam::Maintenance)
            .await
            .expect("an unconfirmed replay is not a transport error");
        assert!(
            matches!(outcome, crate::EpochBackfillRunOutcome::Incomplete(_)),
            "silence alone must not be read as a served history replay"
        );
        assert!(
            client.has_pending_epoch_backfill(),
            "an unconfirmed replay must retain its pending recovery"
        );
        assert_eq!(
            client.epoch_stall.observe_undecryptable(
                bystander,
                "bystander-threshold".to_owned(),
                cgka_traits::EpochId(stalled_epoch),
                epoch_stall_test_now_ms(),
            ),
            BackfillDecision::Arm,
            "an unconfirmed replay must not disarm a group it never recovered"
        );

        // Caller-directed repair bypasses the automatic retry floor, so the
        // retained intent runs again under the next execution ordinal in both
        // production-policy and shortened test-policy builds.
        let retry = client
            .run_pending_epoch_backfill(
                marmot_forensics::EpochBackfillExecutionSeam::ExplicitCatchUp,
            )
            .await
            .expect("retained recovery must retry");
        assert!(matches!(
            retry,
            crate::EpochBackfillRunOutcome::Incomplete(_)
        ));
        drop(client);

        let rows = recorded_audit_rows(&app);
        assert!(
            recorded_rows_of_kind(&rows, "epoch_stall_backfill_completed").is_empty(),
            "no attempt served this account's history"
        );
        let failed = recorded_rows_of_kind(&rows, "epoch_stall_backfill_failed");
        assert_eq!(failed.len(), 2, "both attempts must record a terminal row");
        assert_eq!(
            failed[0]["kind"]["activation_outcome"].as_str(),
            Some("succeeded"),
            "activation did succeed; the drain after it is what did not"
        );
        // The accelerated policy spends its 300 ms EOSE budget before the
        // unchanged 5 s quantum. Production instead yields at 5 s before its
        // 30 s EOSE ceiling.
        let expected_error_kind = if cfg!(feature = "test-policy-overrides") {
            "backfill_drain_no_relay_eose"
        } else {
            "backfill_drain_no_progress_quantum_yield"
        };
        assert_eq!(
            failed[0]["kind"]["error_kind"].as_str(),
            Some(expected_error_kind)
        );
        assert_eq!(
            failed[1]["kind"]["error_kind"].as_str(),
            Some(expected_error_kind)
        );
        assert_eq!(failed[0]["kind"]["deliveries"], 0);
        assert_eq!(failed[0]["kind"]["retry_ordinal"], 0);
        assert_eq!(failed[1]["kind"]["retry_ordinal"], 1);
    });
}

/// A tracked group stalled below the arm threshold, so `mark_replayed` is the
/// only thing that can stop it from arming when its next undecryptable lands.
///
/// Returned by the disarm tests below as the probe they read the detector
/// through: the armed group's own `arm()` has already latched its epoch, so a
/// bystander is the only place the disarm rule is observable.
fn bystander_stalled_below_threshold(
    client: &mut crate::AppClient,
    stalled_epoch: u64,
) -> cgka_traits::GroupId {
    let bystander = cgka_traits::GroupId::new(vec![7_u8; 32]);
    for probe in 0..EPOCH_STALL_BACKFILL_THRESHOLD - 1 {
        assert_eq!(
            client.epoch_stall.observe_undecryptable(
                bystander.clone(),
                format!("bystander-{probe}"),
                cgka_traits::EpochId(stalled_epoch),
                epoch_stall_test_now_ms(),
            ),
            BackfillDecision::Skip,
        );
    }
    bystander
}

/// The threshold-crossing undecryptable for [`bystander_stalled_below_threshold`].
fn bystander_crosses_threshold(
    client: &mut crate::AppClient,
    bystander: cgka_traits::GroupId,
    stalled_epoch: u64,
) -> BackfillDecision {
    client.epoch_stall.observe_undecryptable(
        bystander,
        "bystander-threshold".to_owned(),
        cgka_traits::EpochId(stalled_epoch),
        epoch_stall_test_now_ms(),
    )
}

/// A replay that completed but recovered nothing must not disarm the detector.
///
/// `mark_replayed` latches `fired_at_epoch` for *every* tracked group, which is
/// the right trade when one account-wide replay really did serve every group's
/// history. A drain that ended at end-of-stored-events having ingested nothing,
/// with no tracked group's epoch moving, served nothing — so latching on it ends
/// all automatic recovery for the process lifetime, silently. The run is still
/// recorded honestly and still consumes its intent; only the disarm is withheld.
#[test]
fn a_completed_backfill_that_recovered_nothing_does_not_disarm_the_detector() {
    run_composed_app_runtime_test("backfill-fruitless-no-disarm", || async {
        let dir = tempfile::tempdir().unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let (app, mut client, group_id) =
            armed_epoch_backfill(&dir, &relay, backfill_drain_test_config()).await;
        let stalled_epoch = client.group_mls_state(&group_id).unwrap().epoch;
        let bystander = bystander_stalled_below_threshold(&mut client, stalled_epoch);

        let execution = client
            .begin_epoch_backfill_execution(
                marmot_forensics::EpochBackfillExecutionSeam::Maintenance,
            )
            .expect("the armed intent must begin execution");
        client.test_complete_epoch_backfill_execution(execution, 0, 0);

        assert_eq!(
            bystander_crosses_threshold(&mut client, bystander, stalled_epoch),
            BackfillDecision::Arm,
            "a replay that recovered nothing must not disarm a group it never recovered",
        );
        assert!(
            !client.has_pending_epoch_backfill(),
            "the completed run still consumes its intent; only the disarm is withheld",
        );
        drop(client);

        let rows = recorded_audit_rows(&app);
        let completed = recorded_rows_of_kind(&rows, "epoch_stall_backfill_completed");
        assert_eq!(
            completed.len(),
            1,
            "a fruitless run is still recorded as the completed attempt it was",
        );
        assert_eq!(completed[0]["kind"]["deliveries"], 0);
        assert_eq!(
            completed[0]["kind"]["completion_kind"].as_str(),
            Some("end_of_stored_events"),
        );
    });
}

/// A replay whose every delivery was refused recovered nothing, and must not
/// disarm the detector — the end-to-end shape of the review finding.
///
/// This is the drain that hurts most in the field: the relays serve the exact
/// history the device is missing, the engine's retention cap is full, and every
/// object is dropped unpersisted. `deliveries` counts them (a receive really was
/// ingested, and #1553 pinned that meaning for the field exports), so keying the
/// disarm on `deliveries` alone read a total loss as a productive replay.
/// `deliveries - unpersisted` is the internal count that answers "did anything
/// land"; `refused` remains the narrower audit evidence for cap saturation.
#[test]
fn a_backfill_whose_every_delivery_was_refused_does_not_disarm_the_detector() {
    run_composed_app_runtime_test("backfill-all-refusals", || async {
        let dir = tempfile::tempdir().unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let filled_through = crate::unix_now_seconds() - 1_000;
        let (app, mut client, route) = group_at_the_undecryptable_retention_cap_with_config(
            &dir,
            &relay,
            backfill_drain_test_config(),
            filled_through,
        )
        .await;
        let stalled_epoch = client.group_mls_state(&route.group_id).unwrap().epoch;
        let bystander = bystander_stalled_below_threshold(&mut client, stalled_epoch);

        // Arm through the production seam rather than `apply_backfill_decision`:
        // a refused delivery at the receive seam reaches `observe_resource_refusal`,
        // so the armed group is tracked by the detector and its own re-arm is
        // observable here alongside the bystander's.
        client
            .ingest_received_delivery(route.probe(filled_through + 400, "refusal-that-arms"))
            .await
            .expect("a refused ingest still completes its pass");
        let attempt_id = client
            .pending_epoch_backfill
            .as_ref()
            .expect("the refusal must arm one recovery intent")
            .attempt_id
            .clone();

        // The relays have the history and serve it; the engine's retention cap
        // is full, so the replay fetches it and cannot keep any of it.
        inject_epoch_gap_probe(
            &app,
            epoch_gap_probe(
                &route.nostr_group_id_hex,
                filled_through + 500,
                "refused-during-the-replay",
            ),
        )
        .await;
        let _eose = scripted_eose_pump(app.relay_plane.clone(), relay.clone(), every_subscription);
        let outcome = client
            .run_pending_epoch_backfill(marmot_forensics::EpochBackfillExecutionSeam::Maintenance)
            .await
            .expect("the armed replay must run");
        assert!(
            matches!(outcome, crate::EpochBackfillRunOutcome::Completed(_)),
            "a served end-of-stored-events drain is a completed replay, fruitless or not",
        );

        assert_eq!(
            bystander_crosses_threshold(&mut client, bystander, stalled_epoch),
            BackfillDecision::Arm,
            "a replay that kept none of what it fetched must not disarm a bystander group",
        );
        assert!(
            !client
                .queued_epoch_backfills
                .iter()
                .chain(client.pending_epoch_backfill.iter())
                .any(|pending| pending.attempt_id == attempt_id),
            "the completed run still consumes its own intent; only the disarm is withheld",
        );

        drop(client);
        let rows = recorded_audit_rows(&app);
        let completed = recorded_rows_of_kind(&rows, "epoch_stall_backfill_completed");
        assert_eq!(completed.len(), 1, "the run records one terminal row");
        assert_eq!(
            completed[0]["kind"]["completion_kind"].as_str(),
            Some("end_of_stored_events"),
            "the row stays honest about how the drain ended",
        );
        let deliveries = completed[0]["kind"]["deliveries"].as_u64();
        assert_eq!(
            (deliveries, completed[0]["kind"]["refused"].as_u64()),
            (Some(1), Some(1)),
            "the row must self-report cap saturation: every delivery refused",
        );
        // And the ordinary drain rows carry the same evidence, so a field export
        // can read per-drain saturation without reconstructing it from raw
        // `ingest_outcome` rows.
        assert!(
            recorded_rows_of_kind(&rows, "sync_drain")
                .iter()
                .any(|row| row["kind"]["refused"].as_u64() == Some(1)),
            "the drain row must carry the refusal count too",
        );
    });
}

/// A group armed *through the detector* must be able to arm again after a
/// replay that retained none of its history.
///
/// This is the shape the merged disarm tests could not observe. They armed with
/// `apply_backfill_decision` directly, which never enters `EpochStallDetector`,
/// so the armed group was untracked and only a bystander could show the disarm
/// rule at work. Production arms through `observe_resource_refusal`, and that
/// path latches `fired_at_epoch` in `GroupStall::arm` — the same value
/// `mark_replayed` would have written. Withholding `mark_replayed` therefore did
/// nothing for the group that caused the replay: its next same-epoch refusal
/// still returned `Skip`, and because the refused commit is neither marked seen
/// nor allowed past the `since` floor, the armed backfill is the *only*
/// automatic path back to it. Nothing else clears the latch — `observe_epoch`
/// clears it only on a different epoch, and the epoch cannot move without the
/// commit the replay failed to retain. That is a permanent, silent end to
/// automatic repair for that group.
#[test]
fn a_group_armed_through_the_detector_rearms_after_a_fruitless_replay() {
    run_composed_app_runtime_test("backfill-fruitless-rearm", || async {
        let dir = tempfile::tempdir().unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let filled_through = crate::unix_now_seconds() - 1_000;
        let (app, mut client, route) = group_at_the_undecryptable_retention_cap_with_config(
            &dir,
            &relay,
            backfill_drain_test_config(),
            filled_through,
        )
        .await;
        let stalled_epoch = client.group_mls_state(&route.group_id).unwrap().epoch;

        // Arm the way production does: a refused delivery at the receive seam,
        // which reaches `observe_resource_refusal` through `detect_epoch_stall`.
        client
            .ingest_received_delivery(route.probe(filled_through + 400, "refusal-that-arms"))
            .await
            .expect("a refused ingest still completes its pass");
        assert!(
            client.has_pending_epoch_backfill(),
            "a resource refusal at the receive seam must arm one recovery intent",
        );

        // The relays serve the history; the cap is still full, so the replay
        // fetches it and retains none of it.
        inject_epoch_gap_probe(
            &app,
            epoch_gap_probe(
                &route.nostr_group_id_hex,
                filled_through + 500,
                "refused-during-the-replay",
            ),
        )
        .await;
        let _eose = scripted_eose_pump(app.relay_plane.clone(), relay.clone(), every_subscription);
        assert!(
            matches!(
                client
                    .run_pending_epoch_backfill(
                        marmot_forensics::EpochBackfillExecutionSeam::Maintenance
                    )
                    .await
                    .expect("the armed replay must run"),
                crate::EpochBackfillRunOutcome::Completed(_)
            ),
            "a served end-of-stored-events drain is a completed replay, fruitless or not",
        );

        assert_eq!(
            client.epoch_stall.observe_resource_refusal(
                route.group_id.clone(),
                cgka_traits::EpochId(stalled_epoch),
                epoch_stall_test_now_ms(),
            ),
            BackfillDecision::Arm,
            "a replay that retained none of this group's refused history must leave it \
             able to arm again at the same epoch — nothing else can clear the latch",
        );
    });
}

/// The re-arm above must not become a spin.
///
/// A re-armable group facing a cap that is still full would otherwise run
/// arm → drain → fruitless → re-arm at full speed: a fresh intent starts at
/// `execution_attempts == 0`, and before this rule a *completed* run cleared
/// `epoch_backfill_retry_not_before` unconditionally, so nothing paced the next
/// attempt. A fruitless success now pays the same cooldown an unconfirmed drain
/// does, which bounds the loop to one account-wide replay per backoff window
/// while leaving caller-directed repair exempt.
#[test]
fn consecutive_fruitless_replays_are_paced_by_the_retry_cooldown() {
    run_composed_app_runtime_test("backfill-fruitless-pacing", || async {
        let dir = tempfile::tempdir().unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let filled_through = crate::unix_now_seconds() - 1_000;
        // A backoff long enough that the second attempt cannot slip past it
        // inside this test, and a silence budget short enough to afford.
        let config = MarmotAppConfig::default()
            .with_dev_epoch_backfill_eose_wait_ms(300)
            .with_dev_epoch_backfill_retry_backoff_ms(60_000);
        let (app, mut client, route) = group_at_the_undecryptable_retention_cap_with_config(
            &dir,
            &relay,
            config,
            filled_through,
        )
        .await;

        client
            .ingest_received_delivery(route.probe(filled_through + 400, "refusal-that-arms"))
            .await
            .expect("a refused ingest still completes its pass");
        inject_epoch_gap_probe(
            &app,
            epoch_gap_probe(
                &route.nostr_group_id_hex,
                filled_through + 500,
                "refused-during-the-replay",
            ),
        )
        .await;
        let _eose = scripted_eose_pump(app.relay_plane.clone(), relay.clone(), every_subscription);
        assert!(
            matches!(
                client
                    .run_pending_epoch_backfill(
                        marmot_forensics::EpochBackfillExecutionSeam::Maintenance
                    )
                    .await
                    .expect("the armed replay must run"),
                crate::EpochBackfillRunOutcome::Completed(_)
            ),
            "the first replay completes and is fruitless",
        );
        assert!(
            client.epoch_backfill_retry_not_before.is_some(),
            "a completed-but-fruitless replay must earn a retry cooldown, not clear it",
        );

        // The re-armed group arms a second intent, which the cooldown must hold.
        client
            .ingest_received_delivery(route.probe(filled_through + 900, "refusal-after-replay"))
            .await
            .expect("a refused ingest still completes its pass");
        assert!(
            client.has_pending_epoch_backfill(),
            "the re-armed group must arm a fresh intent",
        );
        assert!(
            matches!(
                client
                    .run_pending_epoch_backfill(
                        marmot_forensics::EpochBackfillExecutionSeam::Maintenance
                    )
                    .await
                    .expect("the paced seam still returns Ok"),
                crate::EpochBackfillRunOutcome::Deferred
            ),
            "the second fruitless cycle must wait out the cooldown instead of \
             draining the account again immediately",
        );
        // A person asking for a repair is not a loop.
        assert!(
            !client.epoch_backfill_retry_is_paced(
                marmot_forensics::EpochBackfillExecutionSeam::ExplicitCatchUp
            ),
            "caller-directed catch-up stays exempt from the fruitless cooldown",
        );
    });
}

/// An execution that ends in `Err` must earn the same cooldown a fruitless or
/// unconfirmed one does.
///
/// Every error exit of `run_pending_epoch_backfill` requeues its intent and
/// returns without a verdict, so none of the verdict-derived pacing rules ever
/// runs for it. Unpaced, the receive seam re-enters a whole-account replay on
/// the very next inbound batch, and each attempt that gets as far as the drain
/// spends the full silence budget before failing again. The intent is durable;
/// the next seam past the cooldown runs it.
#[test]
fn a_failed_epoch_backfill_execution_paces_the_next_automatic_seam() {
    run_composed_app_runtime_test("backfill-error-pacing", || async {
        let dir = tempfile::tempdir().unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let filled_through = crate::unix_now_seconds() - 1_000;
        // A backoff long enough that the second batch cannot slip past it
        // inside this test, and a silence budget short enough to afford.
        let config = MarmotAppConfig::default()
            .with_dev_epoch_backfill_eose_wait_ms(300)
            .with_dev_epoch_backfill_retry_backoff_ms(60_000);
        let (_app, mut client, route) = group_at_the_undecryptable_retention_cap_with_config(
            &dir,
            &relay,
            config,
            filled_through,
        )
        .await;

        // First inbound batch: a refused delivery arms the intent.
        client
            .ingest_received_delivery(route.probe(filled_through + 400, "refusal-that-arms"))
            .await
            .expect("a refused ingest still completes its pass");
        assert!(
            client.has_pending_epoch_backfill(),
            "the refused ingest must arm an epoch-gap replay",
        );

        relay.fail_next_subscribe();
        client
            .run_pending_epoch_backfill(marmot_forensics::EpochBackfillExecutionSeam::Maintenance)
            .await
            .expect_err("the injected activation failure must surface");
        assert!(
            client.has_pending_epoch_backfill(),
            "a failed execution must retain its intent",
        );
        assert!(
            client.epoch_backfill_retry_not_before.is_some(),
            "an execution that ended in an error must earn a retry cooldown",
        );

        // Second inbound batch, immediately behind the first.
        client
            .ingest_received_delivery(route.probe(filled_through + 900, "refusal-after-failure"))
            .await
            .expect("a refused ingest still completes its pass");
        assert!(
            matches!(
                client
                    .run_pending_epoch_backfill(
                        marmot_forensics::EpochBackfillExecutionSeam::Maintenance
                    )
                    .await
                    .expect("the paced seam still returns Ok"),
                crate::EpochBackfillRunOutcome::Deferred
            ),
            "the batch behind a failed execution must wait out the cooldown instead of \
             re-entering the whole-account replay immediately",
        );
        // A person asking for a repair is not a loop.
        assert!(
            !client.epoch_backfill_retry_is_paced(
                marmot_forensics::EpochBackfillExecutionSeam::ExplicitCatchUp
            ),
            "caller-directed catch-up stays exempt from the failure cooldown",
        );
    });
}

/// The drain step's `Err` arm owes the same summary hand-off both its siblings
/// make.
///
/// `run_pending_epoch_backfill` accumulates the relay drain's summary — which
/// includes anything a previous failed pass deferred, folded in by
/// `checkpoint_sync_prefix` — and then drains the engine's no-inbound events.
/// The relay-drain arm above it merges `err.partial_summary` on failure and the
/// clear-intent arm below it merges `summary`; this one returned `Err` and
/// dropped it. The rows are durable either way, but `account_worker` publishes a
/// summary only on `Ok`, so what the drop costs is the runtime event stream:
/// projected state that persists in storage and never surfaces to a subscriber.
#[test]
#[cfg(feature = "test-policy-overrides")]
fn a_failed_event_drain_retains_the_backfill_prefix_for_the_next_seam() {
    run_composed_app_runtime_test("backfill-drain-error-summary", || async {
        let dir = tempfile::tempdir().unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let (_app, mut client, _group_id) = armed_epoch_backfill(
            &dir,
            &relay,
            backfill_drain_test_config().with_dev_fail_pending_session_event_drain(),
        )
        .await;

        // Progress this execution inherits: a prefix an earlier failed pass
        // deferred, which the drain's own checkpoint folds into the summary the
        // failing step below is holding.
        let deferred = crate::SyncSummary {
            joined_groups: vec![cgka_traits::GroupId::new(vec![0x42])],
            ..Default::default()
        };
        client.pending_failed_sync_summary.merge(deferred.clone());

        client
            .run_pending_epoch_backfill(marmot_forensics::EpochBackfillExecutionSeam::Maintenance)
            .await
            .expect_err("the injected event-drain failure must surface");

        assert_eq!(
            client.pending_failed_sync_summary, deferred,
            "a drain-step failure must hand its accumulated prefix back for the next \
             successful seam instead of dropping it off the runtime event stream",
        );
    });
}

/// A fruitless replay re-arms only the groups whose refusals it counted.
///
/// The clear is scoped to this drain's attribution rather than swept
/// account-wide: a group that never had history refused in this replay learned
/// nothing from it, and clearing its latch would re-arm groups the replay says
/// nothing about.
#[test]
fn a_fruitless_replay_rearms_only_the_groups_whose_refusals_it_counted() {
    run_composed_app_runtime_test("backfill-fruitless-rearm-scope", || async {
        let dir = tempfile::tempdir().unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let filled_through = crate::unix_now_seconds() - 1_000;
        let (app, mut client, route) = group_at_the_undecryptable_retention_cap_with_config(
            &dir,
            &relay,
            backfill_drain_test_config(),
            filled_through,
        )
        .await;
        let stalled_epoch = client.group_mls_state(&route.group_id).unwrap().epoch;

        // An untouched group that armed at the same epoch but has no refusal in
        // the replay below.
        let untouched = cgka_traits::GroupId::new(vec![9_u8; 32]);
        assert_eq!(
            client.epoch_stall.observe_resource_refusal(
                untouched.clone(),
                cgka_traits::EpochId(stalled_epoch),
                epoch_stall_test_now_ms()
            ),
            BackfillDecision::Arm,
        );

        client
            .ingest_received_delivery(route.probe(filled_through + 400, "refusal-that-arms"))
            .await
            .expect("a refused ingest still completes its pass");
        inject_epoch_gap_probe(
            &app,
            epoch_gap_probe(
                &route.nostr_group_id_hex,
                filled_through + 500,
                "refused-during-the-replay",
            ),
        )
        .await;
        let _eose = scripted_eose_pump(app.relay_plane.clone(), relay.clone(), every_subscription);
        client
            .run_pending_epoch_backfill(marmot_forensics::EpochBackfillExecutionSeam::Maintenance)
            .await
            .expect("the armed replay must run");

        assert_eq!(
            client.epoch_stall.observe_resource_refusal(
                route.group_id.clone(),
                cgka_traits::EpochId(stalled_epoch),
                epoch_stall_test_now_ms(),
            ),
            BackfillDecision::Arm,
            "the group whose refusal the replay counted re-arms",
        );
        assert_eq!(
            client.epoch_stall.observe_resource_refusal(
                untouched,
                cgka_traits::EpochId(stalled_epoch),
                epoch_stall_test_now_ms()
            ),
            BackfillDecision::Skip,
            "a group the replay refused nothing for keeps its latch",
        );
    });
}

/// A device frozen at one stalled epoch must eventually be *reported*, not
/// retry in silence forever.
///
/// This is the blind spot the `epoch_stall` module header names. Escalation
/// needs three arms in one unrecovered run; every arm after the first needs the
/// group's epoch to move; and a device whose missing commit is genuinely absent
/// from the relays never sees it move. The 2026-08 field cohort shows exactly
/// that plateau — twelve `epoch_stall_backfill_armed` rows across five devices,
/// every one at `retry_ordinal: 0`, and not one escalation row anywhere.
///
/// The escalation for this shape therefore counts relay-confirmed *evidence*
/// instead of arms: `EPOCH_STALL_FRUITLESS_COMPLETION_THRESHOLD` replays that
/// reached end-of-stored-events and recovered nothing, all at the same stalled
/// epoch. Nothing here injects a decision — every round crosses the
/// undecryptable threshold through the receive seam the way production does,
/// and every replay is a real drain the scripted pump confirms EOSE for.
#[test]
fn three_fruitless_end_of_stored_events_replays_at_one_epoch_escalate() {
    run_composed_app_runtime_test("frozen-epoch-fruitless-escalation", || async {
        let dir = tempfile::tempdir().unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        // The wedge clock is an hour in production; a test buys the second and
        // third re-arm with the dev override rather than with wall-clock.
        let config = backfill_drain_test_config().with_dev_epoch_stall_wedge_rearm_interval_ms(0);
        let (app, mut client, route) = undecryptable_probe_route(&dir, &relay, config).await;
        let stalled_epoch = client.group_mls_state(&route.group_id).unwrap().epoch;
        let _eose = scripted_eose_pump(app.relay_plane.clone(), relay.clone(), every_subscription);
        let probe_base = crate::unix_now_seconds() - 1_000;

        for round in
            0..u64::from(crate::client::epoch_stall::EPOCH_STALL_FRUITLESS_COMPLETION_THRESHOLD)
        {
            for probe in 0..crate::client::epoch_stall::EPOCH_STALL_BACKFILL_THRESHOLD {
                client
                    .ingest_received_delivery(route.probe(
                        probe_base + round * 100 + probe as u64,
                        &format!("round-{round}-probe-{probe}"),
                    ))
                    .await
                    .expect("a retained undecryptable object completes its ingest pass");
            }
            assert!(
                client.has_pending_epoch_backfill(),
                "round {round}: undecryptable traffic at a frozen epoch must arm a replay",
            );
            assert!(
                matches!(
                    client
                        .run_pending_epoch_backfill(
                            marmot_forensics::EpochBackfillExecutionSeam::Maintenance
                        )
                        .await
                        .expect("the armed replay must run"),
                    crate::EpochBackfillRunOutcome::Completed(_)
                ),
                "round {round}: a served end-of-stored-events drain is a completed replay",
            );
            assert_eq!(
                client.group_mls_state(&route.group_id).unwrap().epoch,
                stalled_epoch,
                "round {round}: the device under test stays frozen at one epoch",
            );
            if round + 1
                < u64::from(crate::client::epoch_stall::EPOCH_STALL_FRUITLESS_COMPLETION_THRESHOLD)
            {
                assert!(
                    client.pending_epoch_stall_escalations.is_empty(),
                    "round {round}: evidence short of the threshold must not report",
                );
            }
        }

        assert_eq!(
            client
                .pending_epoch_stall_escalations
                .iter()
                .map(|escalation| (escalation.group_id.clone(), escalation.stalled_epoch))
                .collect::<Vec<_>>(),
            vec![(route.group_id.clone(), stalled_epoch)],
            "three fruitless end-of-stored-events replays at one stalled epoch must report \
             the group exactly once",
        );
        drop(client);
        assert_eq!(
            recorded_audit_rows(&app)
                .iter()
                .filter(|row| row["kind"]["type"] == "epoch_stall_backfill_escalated")
                .count(),
            1,
            "the escalation must leave exactly one durable forensic row",
        );
    });
}

/// The frozen-epoch evidence a process gathers has to outlive that process.
///
/// Detector state is otherwise deliberately process-local, and for the arm run
/// that is the right trade: a discarded run is re-earned from zero, delayed
/// rather than lost. It is the wrong trade here. A wedged group accumulates one
/// confirmed fruitless replay per pacing interval, so a device restarted more
/// often than that would never reach the threshold at all — which is the field
/// shape, where frozen devices plateau at two arms and restarts wipe the count.
/// So the evidence and the wall-clock arm mark are durable, and the run is not.
#[test]
fn frozen_epoch_evidence_outlives_the_process_that_gathered_it() {
    run_composed_app_runtime_test("frozen-epoch-evidence-restart", || async {
        let dir = tempfile::tempdir().unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let config = backfill_drain_test_config().with_dev_epoch_stall_wedge_rearm_interval_ms(0);
        let (app, mut client, route) = undecryptable_probe_route(&dir, &relay, config).await;
        let stalled_epoch = client.group_mls_state(&route.group_id).unwrap().epoch;
        let _eose = scripted_eose_pump(app.relay_plane.clone(), relay.clone(), every_subscription);
        let probe_base = crate::unix_now_seconds() - 1_000;

        let threshold =
            u64::from(crate::client::epoch_stall::EPOCH_STALL_FRUITLESS_COMPLETION_THRESHOLD);
        // Every round but the last, then throw the client away.
        for round in 0..threshold - 1 {
            for probe in 0..crate::client::epoch_stall::EPOCH_STALL_BACKFILL_THRESHOLD {
                client
                    .ingest_received_delivery(route.probe(
                        probe_base + round * 100 + probe as u64,
                        &format!("round-{round}-probe-{probe}"),
                    ))
                    .await
                    .expect("a retained undecryptable object completes its ingest pass");
            }
            client
                .run_pending_epoch_backfill(
                    marmot_forensics::EpochBackfillExecutionSeam::Maintenance,
                )
                .await
                .expect("the armed replay must run");
        }
        assert!(
            client.pending_epoch_stall_escalations.is_empty(),
            "evidence short of the threshold must not report",
        );
        drop(client);

        let mut reopened = client_on_app_relay_plane(&app, "alice").await;
        for probe in 0..crate::client::epoch_stall::EPOCH_STALL_BACKFILL_THRESHOLD {
            reopened
                .ingest_received_delivery(route.probe(
                    probe_base + threshold * 100 + probe as u64,
                    &format!("after-restart-probe-{probe}"),
                ))
                .await
                .expect("a retained undecryptable object completes its ingest pass");
        }
        assert!(
            reopened.has_pending_epoch_backfill(),
            "the restored arm mark must still allow a paced re-arm",
        );
        reopened
            .run_pending_epoch_backfill(marmot_forensics::EpochBackfillExecutionSeam::Maintenance)
            .await
            .expect("the armed replay must run");

        assert_eq!(
            reopened
                .pending_epoch_stall_escalations
                .iter()
                .map(|escalation| (escalation.group_id.clone(), escalation.stalled_epoch))
                .collect::<Vec<_>>(),
            vec![(route.group_id.clone(), stalled_epoch)],
            "the replays the previous process confirmed still count toward the report",
        );
    });
}

/// A restart must not shorten the pacing interval the previous process owed.
///
/// The unit tests pin the rule on the detector's own clock; this pins it end to
/// end, through the durable row, with an interval a test can actually be inside
/// of. That combination is the whole hazard: the counter is persisted so
/// restarts cannot erase it, which is exactly what would let a restart *become*
/// the re-arm clock if the mark beside it were not wall-clock too. Three
/// force-kills would then be worth three hours of waiting.
#[test]
fn a_restart_inside_the_pacing_interval_does_not_buy_a_rearm() {
    run_composed_app_runtime_test("frozen-epoch-restart-inside-interval", || async {
        let dir = tempfile::tempdir().unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        // A real interval, long enough that this test is always inside it.
        let config = backfill_drain_test_config()
            .with_dev_epoch_stall_wedge_rearm_interval_ms(10 * 60 * 1_000);
        let (app, mut client, route) = undecryptable_probe_route(&dir, &relay, config).await;
        let _eose = scripted_eose_pump(app.relay_plane.clone(), relay.clone(), every_subscription);
        let probe_base = crate::unix_now_seconds() - 1_000;

        for probe in 0..crate::client::epoch_stall::EPOCH_STALL_BACKFILL_THRESHOLD {
            client
                .ingest_received_delivery(route.probe(
                    probe_base + probe as u64,
                    &format!("before-restart-{probe}"),
                ))
                .await
                .expect("a retained undecryptable object completes its ingest pass");
        }
        assert!(
            client.has_pending_epoch_backfill(),
            "the first arm needs no interval to have elapsed",
        );
        client
            .run_pending_epoch_backfill(marmot_forensics::EpochBackfillExecutionSeam::Maintenance)
            .await
            .expect("the armed replay must run");
        drop(client);

        let mut reopened = client_on_app_relay_plane(&app, "alice").await;
        for probe in 0..crate::client::epoch_stall::EPOCH_STALL_BACKFILL_THRESHOLD {
            reopened
                .ingest_received_delivery(route.probe(
                    probe_base + 100 + probe as u64,
                    &format!("after-restart-{probe}"),
                ))
                .await
                .expect("a retained undecryptable object completes its ingest pass");
        }
        assert!(
            !reopened.has_pending_epoch_backfill(),
            "the restored arm mark is wall-clock, so restarting owes the same wait",
        );
        assert!(
            reopened.pending_epoch_stall_escalations.is_empty(),
            "and nothing was reported off an interval nobody waited out",
        );
    });
}

/// Only a completion the relays confirmed counts as evidence.
///
/// The detector takes the caller's word for that — it is handed completions,
/// not completion kinds — so the admission test lives at this seam and is worth
/// pinning here. A drain that gives up without one relay reaching
/// end-of-stored-events proves that the drain gave up, nothing about whether the
/// history it wanted exists, and must never accumulate toward a report however
/// many times it happens.
#[test]
fn drains_that_never_confirmed_stored_history_are_not_evidence() {
    run_composed_app_runtime_test("frozen-epoch-unconfirmed-drains", || async {
        let dir = tempfile::tempdir().unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let config = backfill_drain_test_config().with_dev_epoch_stall_wedge_rearm_interval_ms(0);
        let (_app, mut client, route) = undecryptable_probe_route(&dir, &relay, config).await;
        let probe_base = crate::unix_now_seconds() - 1_000;
        // Deliberately no EOSE pump: every drain below ends unconfirmed.

        for round in
            0..u64::from(crate::client::epoch_stall::EPOCH_STALL_FRUITLESS_COMPLETION_THRESHOLD + 1)
        {
            for probe in 0..crate::client::epoch_stall::EPOCH_STALL_BACKFILL_THRESHOLD {
                client
                    .ingest_received_delivery(route.probe(
                        probe_base + round * 100 + probe as u64,
                        &format!("round-{round}-probe-{probe}"),
                    ))
                    .await
                    .expect("a retained undecryptable object completes its ingest pass");
            }
            assert!(
                matches!(
                    client
                        .run_pending_epoch_backfill(
                            marmot_forensics::EpochBackfillExecutionSeam::Maintenance
                        )
                        .await
                        .expect("the armed replay must run"),
                    crate::EpochBackfillRunOutcome::Incomplete(_)
                ),
                "round {round}: a drain no relay served is an incomplete replay",
            );
        }

        assert!(
            client.pending_epoch_stall_escalations.is_empty(),
            "unconfirmed drains must never accumulate toward a report",
        );
    });
}

/// A zero-delivery replay after which a tracked group's epoch moved is genuine
/// success: the value of the replay was letting already-deferred rows converge,
/// and that is exactly what the epoch delta reports.
#[test]
fn a_backfill_whose_epoch_moved_still_disarms_the_detector() {
    run_composed_app_runtime_test("backfill-epoch-moved-disarms", || async {
        let dir = tempfile::tempdir().unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let (_app, mut client, group_id) =
            armed_epoch_backfill(&dir, &relay, backfill_drain_test_config()).await;
        let stalled_epoch = client.group_mls_state(&group_id).unwrap().epoch;
        let bystander = bystander_stalled_below_threshold(&mut client, stalled_epoch);

        let execution = client
            .begin_epoch_backfill_execution(
                marmot_forensics::EpochBackfillExecutionSeam::Maintenance,
            )
            .expect("the armed intent must begin execution");
        client
            .update_group_profile(&group_id, Some("moved during the replay"), None)
            .await
            .expect("a solo group's commit confirms locally");
        assert!(
            client.group_mls_state(&group_id).unwrap().epoch > stalled_epoch,
            "the armed group's epoch must have moved across the run",
        );
        client.test_complete_epoch_backfill_execution(execution, 0, 0);

        assert_eq!(
            bystander_crosses_threshold(&mut client, bystander, stalled_epoch),
            BackfillDecision::Skip,
            "a replay that moved a tracked group's epoch has earned the account-wide disarm",
        );
    });
}

/// A replay that ingested deliveries has earned the disarm even with every
/// tracked epoch still where it started.
///
/// The epoch is read the moment the drain returns, and a delivery it ingested
/// can convert into an epoch long after that — one field run drained 376
/// deliveries and moved its epoch a second *after* the terminal row was written.
/// So a delivery count is never second-guessed by an epoch read taken this
/// early: the deliveries are parked awaiting convergence, not lost.
#[test]
fn a_backfill_that_ingested_deliveries_still_disarms_the_detector() {
    run_composed_app_runtime_test("backfill-deliveries-disarm", || async {
        let dir = tempfile::tempdir().unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let (_app, mut client, group_id) =
            armed_epoch_backfill(&dir, &relay, backfill_drain_test_config()).await;
        let stalled_epoch = client.group_mls_state(&group_id).unwrap().epoch;
        let bystander = bystander_stalled_below_threshold(&mut client, stalled_epoch);

        let execution = client
            .begin_epoch_backfill_execution(
                marmot_forensics::EpochBackfillExecutionSeam::Maintenance,
            )
            .expect("the armed intent must begin execution");
        // One delivery, none of it refused: a delivery the engine kept.
        client.test_complete_epoch_backfill_execution(execution, 1, 0);

        assert_eq!(
            bystander_crosses_threshold(&mut client, bystander, stalled_epoch),
            BackfillDecision::Skip,
            "a delivery the engine kept is recovery in flight, not a fruitless run",
        );
    });
}

#[test]
fn epoch_backfill_drain_needs_every_subscription_to_report() {
    run_composed_app_runtime_test("backfill-drain-partial-eose", || async {
        let dir = tempfile::tempdir().unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let (app, mut client, _group_id) =
            armed_epoch_backfill(&dir, &relay, backfill_drain_test_config()).await;
        // Only the account inbox is served. The group subscriptions carrying the
        // commits a stalled group is missing never report.
        let _eose = scripted_eose_pump(app.relay_plane.clone(), relay.clone(), |subscription| {
            matches!(subscription, NostrSubscription::AccountInbox { .. })
        });

        let outcome = client
            .run_pending_epoch_backfill(marmot_forensics::EpochBackfillExecutionSeam::Maintenance)
            .await
            .expect("an unconfirmed replay is not a transport error");
        assert!(
            matches!(outcome, crate::EpochBackfillRunOutcome::Incomplete(_)),
            "one served subscription is not a served account history"
        );
        assert!(client.has_pending_epoch_backfill());
        drop(client);

        let rows = recorded_audit_rows(&app);
        let failed = recorded_rows_of_kind(&rows, "epoch_stall_backfill_failed");
        assert_eq!(failed.len(), 1);
        // As above, the accelerated EOSE budget wins only in the
        // test-policy build; the production quantum wins in the default build.
        assert_eq!(
            failed[0]["kind"]["error_kind"].as_str(),
            Some(if cfg!(feature = "test-policy-overrides") {
                "backfill_drain_eose_timeout"
            } else {
                "backfill_drain_no_progress_quantum_yield"
            })
        );
    });
}

/// The two relays every group route below is published to: `FAST_RELAY` answers
/// the unfloored history query at once, `SLOW_RELAY` is still holding the commit
/// the stalled group is missing.
const FAST_RELAY: &str = "wss://fast.example";
const SLOW_RELAY: &str = "wss://slow.example";

/// [`armed_epoch_backfill`] with both relays on every route, and armed through
/// the detector's own observations rather than injected: only a tracked group
/// gives `mark_replayed` something to latch, which is what the drain's effect on
/// a later arm depends on.
async fn armed_epoch_backfill_across_two_relays(
    dir: &tempfile::TempDir,
    relay: &Arc<ScriptedPushRelayClient>,
    config: MarmotAppConfig,
) -> (MarmotApp, crate::AppClient, cgka_traits::GroupId) {
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let mut app = MarmotApp::with_relays_and_config(
        dir.path(),
        vec![FAST_RELAY.to_owned(), SLOW_RELAY.to_owned()],
        config,
    )
    .with_test_relay_client(relay.clone());
    app.set_audit_log_settings(crate::AuditLogSettings { enabled: true })
        .unwrap();
    app.relay_plane =
        MarmotRelayPlane::new_with_loopback(Some(Duration::from_secs(120)), relay.clone(), true);

    let mut client = client_on_app_relay_plane(&app, "alice").await;
    let group_id = client
        .create_group("epoch backfill across two relays", &[])
        .await
        .unwrap();
    let stalled_epoch = client.group_mls_state(&group_id).unwrap().epoch;
    let mut decision = BackfillDecision::Skip;
    for probe in 0..EPOCH_STALL_BACKFILL_THRESHOLD {
        decision = client.epoch_stall.observe_undecryptable(
            group_id.clone(),
            format!("two-relay-stall-{probe}"),
            cgka_traits::EpochId(stalled_epoch),
            epoch_stall_test_now_ms(),
        );
    }
    assert_eq!(decision, BackfillDecision::Arm);
    client.apply_backfill_decision(
        &group_id,
        stalled_epoch,
        decision,
        marmot_forensics::EpochStallBackfillTrigger::UndecryptableThreshold,
    );
    (app, client, group_id)
}

/// [`scripted_eose_pump`] narrowed to [`FAST_RELAY`]. This advances partial
/// coverage for every subscription while deliberately leaving the replay
/// incomplete until [`SLOW_RELAY`] answers too.
fn fast_relay_eose_pump(
    plane: MarmotRelayPlane,
    relay: Arc<ScriptedPushRelayClient>,
) -> ScriptedEosePump {
    let fast = TransportEndpoint(FAST_RELAY.to_owned());
    ScriptedEosePump(tokio::spawn(async move {
        loop {
            for subscription in relay.accepted_subscriptions() {
                plane
                    .handle_relay_eose_for_test(fast.clone(), subscription.subscription_id())
                    .await;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }))
}

/// Wait until a running replay has stopped issuing subscriptions, having issued
/// some. Its activation, group sync, and subscription rebuild each issue their
/// own, and a re-issued subscription must be confirmed again — so only past the
/// last of them is the pump above holding a gate that is actually satisfied.
async fn epoch_backfill_subscriptions_settled(relay: &ScriptedPushRelayClient, before: usize) {
    let mut last = before;
    let mut settled = 0;
    while settled < 3 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        let count = relay.subscription_count();
        settled = if count == last && count > before {
            settled + 1
        } else {
            0
        };
        last = count;
    }
}

/// One event delivered by [`SLOW_RELAY`] into the account's live routes.
async fn deliver_from_slow_relay(app: &MarmotApp, event: NostrTransportEvent) {
    let delivered = app
        .relay_plane
        .handle_relay_event_for_test(NostrRelayEvent {
            endpoint: TransportEndpoint(SLOW_RELAY.to_owned()),
            subscription_id: Some("slow-relay-test".to_owned()),
            event,
        })
        .await
        .expect("route the slow relay's commit");
    assert_eq!(delivered, 1, "the active group route must receive it");
}

#[test]
fn epoch_backfill_drain_collects_a_slow_relay_commit_inside_its_silence_window() {
    run_composed_app_runtime_test("backfill-drain-slow-relay-inside", || async {
        let dir = tempfile::tempdir().unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        // A silence budget far larger than this drain can spend, so completing
        // is the gate's doing and not the budget's.
        let (app, mut client, group_id) = armed_epoch_backfill_across_two_relays(
            &dir,
            &relay,
            backfill_drain_test_config().with_dev_epoch_backfill_eose_wait_ms(10_000),
        )
        .await;
        let group = app
            .group("alice", &hex::encode(group_id.as_slice()))
            .unwrap()
            .expect("local group projection");

        // The fast relay reports first. The slow relay then serves the missing
        // commit and only afterwards reports its EOSE, completing the frozen
        // endpoint coverage while the drain is inside its silence window.
        let _eose = fast_relay_eose_pump(app.relay_plane.clone(), relay.clone());
        let commit = epoch_gap_probe(
            &group.nostr_routing.nostr_group_id_hex,
            crate::unix_now_seconds(),
            "slow-relay-inside-window",
        );
        let slow_relay = {
            let app = app.clone();
            let relay = relay.clone();
            let plane = app.relay_plane.clone();
            let subscriptions_before = relay.subscription_count();
            tokio::spawn(async move {
                epoch_backfill_subscriptions_settled(&relay, subscriptions_before).await;
                deliver_from_slow_relay(&app, commit).await;
                let slow = TransportEndpoint(SLOW_RELAY.to_owned());
                for subscription in relay.accepted_subscriptions() {
                    plane
                        .handle_relay_eose_for_test(slow.clone(), subscription.subscription_id())
                        .await;
                }
            })
        };

        let started = std::time::Instant::now();
        let outcome = client
            .run_pending_epoch_backfill(marmot_forensics::EpochBackfillExecutionSeam::Maintenance)
            .await
            .expect("armed replay must run");
        slow_relay.await.expect("scripted relay must not panic");
        assert!(
            matches!(outcome, crate::EpochBackfillRunOutcome::Completed(_)),
            "a satisfied gate plus quiet relays is a completed replay"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the gate must end the drain, not the silence budget"
        );
        drop(client);

        let rows = recorded_audit_rows(&app);
        let completed = recorded_rows_of_kind(&rows, "epoch_stall_backfill_completed");
        assert_eq!(completed.len(), 1);
        assert_eq!(
            completed[0]["kind"]["deliveries"], 1,
            "a satisfied gate must not cut the drain off mid-silence-window"
        );
    });
}

#[test]
fn epoch_backfill_keeps_intent_until_the_slow_relay_reconnects() {
    run_composed_app_runtime_test("backfill-drain-slow-relay-reconnect", || async {
        let dir = tempfile::tempdir().unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let (app, mut client, group_id) = armed_epoch_backfill_across_two_relays(
            &dir,
            &relay,
            backfill_drain_test_config().with_dev_epoch_backfill_eose_wait_ms(10_000),
        )
        .await;
        let group = app
            .group("alice", &hex::encode(group_id.as_slice()))
            .unwrap()
            .expect("local group projection");
        let _eose = fast_relay_eose_pump(app.relay_plane.clone(), relay.clone());

        // Fast, empty A cannot complete while B is unavailable.
        let outcome = client
            .run_pending_epoch_backfill(marmot_forensics::EpochBackfillExecutionSeam::Maintenance)
            .await
            .expect("armed replay must run");
        assert!(matches!(
            outcome,
            crate::EpochBackfillRunOutcome::Incomplete(_)
        ));
        assert!(
            client.has_pending_epoch_backfill(),
            "partial relay coverage must retain the durable intent"
        );

        // B reconnects, serves the missing commit, and reports EOSE. An ongoing
        // pump covers the fresh subscriptions issued by the retry as well as
        // the current generation.
        deliver_from_slow_relay(
            &app,
            epoch_gap_probe(
                &group.nostr_routing.nostr_group_id_hex,
                crate::unix_now_seconds(),
                "slow-relay-after-window",
            ),
        )
        .await;
        let _all_eose =
            scripted_eose_pump(app.relay_plane.clone(), relay.clone(), every_subscription);
        let outcome = client
            .run_pending_epoch_backfill(
                marmot_forensics::EpochBackfillExecutionSeam::ExplicitCatchUp,
            )
            .await
            .expect("reconnect replay must run");
        assert!(matches!(
            outcome,
            crate::EpochBackfillRunOutcome::Completed(_)
        ));
        assert!(!client.has_pending_epoch_backfill());
        drop(client);

        let rows = recorded_audit_rows(&app);
        assert_eq!(
            recorded_rows_of_kind(&rows, "epoch_stall_backfill_failed").len(),
            1
        );
        let completed = recorded_rows_of_kind(&rows, "epoch_stall_backfill_completed");
        assert_eq!(completed.len(), 1);
        assert_eq!(
            completed[0]["kind"]["deliveries"], 1,
            "the confirmed reconnect drain must retain B's missing commit"
        );
        assert_eq!(
            completed[0]["kind"]["completion_kind"].as_str(),
            Some("end_of_stored_events")
        );
    });
}

#[test]
fn unconfirmed_epoch_backfill_paces_its_automatic_retries() {
    run_composed_app_runtime_test("backfill-retry-cooldown", || async {
        let dir = tempfile::tempdir().unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        // No EOSE pump: every attempt spends its silence budget and gives up.
        // The cooldown is what must stop the receive seam from paying that on
        // every inbound delivery.
        let (app, mut client, _group_id) = armed_epoch_backfill(
            &dir,
            &relay,
            backfill_drain_test_config().with_dev_epoch_backfill_retry_backoff_ms(1_500),
        )
        .await;

        let first = client
            .run_pending_epoch_backfill(marmot_forensics::EpochBackfillExecutionSeam::Receive)
            .await
            .expect("an unconfirmed replay is not a transport error");
        assert!(matches!(
            first,
            crate::EpochBackfillRunOutcome::Incomplete(_)
        ));

        let started = std::time::Instant::now();
        for _ in 0..5 {
            assert!(
                matches!(
                    client
                        .run_pending_epoch_backfill(
                            marmot_forensics::EpochBackfillExecutionSeam::Receive
                        )
                        .await
                        .expect("a paced seam is not a failure"),
                    crate::EpochBackfillRunOutcome::Deferred
                ),
                "the receive seam must skip an intent inside its cooldown"
            );
        }
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "skipped attempts must not spend the drain's silence budget"
        );
        assert!(
            client.has_pending_epoch_backfill(),
            "a paced attempt must leave the intent pending"
        );

        // Caller-directed repair is not a loop, so it is never paced.
        assert!(
            matches!(
                client
                    .run_pending_epoch_backfill(
                        marmot_forensics::EpochBackfillExecutionSeam::ExplicitCatchUp
                    )
                    .await
                    .expect("explicit catch-up runs"),
                crate::EpochBackfillRunOutcome::Incomplete(_)
            ),
            "caller-directed catch-up must bypass the cooldown"
        );
        drop(client);

        let rows = recorded_audit_rows(&app);
        assert_eq!(
            recorded_rows_of_kind(&rows, "epoch_stall_backfill_started").len(),
            2,
            "only the unpaced attempts may start a replay"
        );
    });
}

#[test]
#[cfg(feature = "test-policy-overrides")]
fn epoch_backfill_remains_pending_after_repeated_unavailable_relay_attempts() {
    run_composed_app_runtime_test("backfill-eose-remains-pending", || async {
        const UNCONFIRMED_ATTEMPTS: u64 = 3;
        let dir = tempfile::tempdir().unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let (app, mut client, group_id) =
            armed_epoch_backfill(&dir, &relay, backfill_drain_test_config()).await;
        let group = app
            .group("alice", &hex::encode(group_id.as_slice()))
            .unwrap()
            .expect("local group projection");

        // Stands in for a route whose required relay never answers. Repeated
        // bounded attempts must not convert that availability failure into
        // proof that stored history was served.
        for attempt in 0..UNCONFIRMED_ATTEMPTS {
            let outcome = client
                .run_pending_epoch_backfill(
                    marmot_forensics::EpochBackfillExecutionSeam::ExplicitCatchUp,
                )
                .await
                .expect("an unconfirmed replay is not a transport error");
            assert!(
                matches!(outcome, crate::EpochBackfillRunOutcome::Incomplete(_)),
                "attempt {attempt} must still hold the honest gate"
            );
        }

        // History the reachable relays do serve must still reach the account.
        inject_epoch_gap_probe(
            &app,
            epoch_gap_probe(
                &group.nostr_routing.nostr_group_id_hex,
                crate::unix_now_seconds(),
                "reachable-history",
            ),
        )
        .await;
        let still_unconfirmed = client
            .run_pending_epoch_backfill(
                marmot_forensics::EpochBackfillExecutionSeam::ExplicitCatchUp,
            )
            .await
            .expect("the next bounded attempt runs");
        assert!(
            matches!(
                still_unconfirmed,
                crate::EpochBackfillRunOutcome::Incomplete(_)
            ),
            "reachable history without required EOSE coverage remains unconfirmed"
        );
        assert!(
            client.has_pending_epoch_backfill(),
            "an unavailable required relay must leave the durable intent pending"
        );

        // Once the relay reconnects and reports EOSE for the current replay,
        // the same durable intent can complete and clear.
        let _eose = scripted_eose_pump(app.relay_plane.clone(), relay.clone(), every_subscription);
        let completed_after_reconnect = client
            .run_pending_epoch_backfill(
                marmot_forensics::EpochBackfillExecutionSeam::ExplicitCatchUp,
            )
            .await
            .expect("the reconnect attempt runs");
        assert!(matches!(
            completed_after_reconnect,
            crate::EpochBackfillRunOutcome::Completed(_)
        ));
        assert!(!client.has_pending_epoch_backfill());
        drop(client);

        let rows = recorded_audit_rows(&app);
        let failed = recorded_rows_of_kind(&rows, "epoch_stall_backfill_failed");
        assert_eq!(
            failed.len(),
            UNCONFIRMED_ATTEMPTS as usize + 1,
            "every unconfirmed attempt must record its own honest failure"
        );
        let completed = recorded_rows_of_kind(&rows, "epoch_stall_backfill_completed");
        assert_eq!(completed.len(), 1);
        assert_eq!(
            completed[0]["kind"]["completion_kind"].as_str(),
            Some("end_of_stored_events")
        );
        assert_eq!(
            completed[0]["kind"]["retry_ordinal"].as_u64(),
            Some(UNCONFIRMED_ATTEMPTS + 1)
        );
        assert_eq!(
            failed.last().expect("the unconfirmed delivery attempt")["kind"]["deliveries"],
            1,
            "the unconfirmed attempt still recovers reachable history"
        );
        assert_eq!(completed[0]["kind"]["deliveries"], 0);
    });
}

#[test]
fn in_flight_epoch_backfill_arm_preserves_both_operation_intents_on_failure() {
    run_composed_app_runtime_test("in-flight-backfill-arm", || async {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = MarmotApp::with_relay_and_config(
            dir.path(),
            "wss://relay.example".to_owned(),
            bounded_epoch_backfill_config(),
        )
        .with_test_relay_client(relay.clone());
        app.set_audit_log_settings(crate::AuditLogSettings { enabled: true })
            .unwrap();

        let _eose = scripted_eose_pump(app.relay_plane.clone(), relay.clone(), every_subscription);

        let mut client = client_on_app_relay_plane(&app, "alice").await;
        let group_a = client
            .create_group("in-flight backfill group a", &[])
            .await
            .unwrap();
        let group_b = client
            .create_group("in-flight backfill group b", &[])
            .await
            .unwrap();
        let stalled_epoch_a = client.group_mls_state(&group_a).unwrap().epoch;
        client.apply_backfill_decision(
            &group_a,
            stalled_epoch_a,
            BackfillDecision::Arm,
            marmot_forensics::EpochStallBackfillTrigger::UndecryptableThreshold,
        );
        let operation_a = client
            .pending_epoch_backfill
            .as_ref()
            .expect("group a must arm one recovery intent")
            .attempt_id
            .clone();

        let execution = client
            .begin_epoch_backfill_execution(
                marmot_forensics::EpochBackfillExecutionSeam::Maintenance,
            )
            .expect("the first operation must begin execution");
        assert_eq!(execution.pending.attempt_id, operation_a);

        let stalled_epoch_b = client.group_mls_state(&group_b).unwrap().epoch;
        client.apply_backfill_decision(
            &group_b,
            stalled_epoch_b,
            BackfillDecision::Arm,
            marmot_forensics::EpochStallBackfillTrigger::UndecryptableThreshold,
        );
        let operation_b = client
            .pending_epoch_backfill
            .as_ref()
            .expect("group b must arm a second recovery intent during replay")
            .attempt_id
            .clone();
        assert_ne!(operation_a, operation_b);

        client.test_finish_epoch_backfill_execution(execution, false);

        assert!(
            client.has_pending_epoch_backfill(),
            "both recovery intents must remain retryable after the in-flight failure"
        );
        assert_eq!(
            client
                .pending_epoch_backfill
                .as_ref()
                .map(|pending| pending.attempt_id.as_str()),
            Some(operation_b.as_str()),
            "the newer in-flight arm must stay scheduled ahead of the failed operation"
        );
        assert!(
            client
                .queued_epoch_backfills
                .iter()
                .any(|pending| pending.attempt_id == operation_a),
            "the failed operation must be queued instead of orphaned"
        );

        let operation_b_retry = client
            .run_pending_epoch_backfill(marmot_forensics::EpochBackfillExecutionSeam::Maintenance)
            .await
            .expect("operation b must retry");
        assert!(
            matches!(
                operation_b_retry,
                crate::EpochBackfillRunOutcome::Completed(_)
            ),
            "operation b must execute"
        );
        // Operation B completed without retaining history, so #1569's
        // fruitless-replay guard correctly paced the automatic seam. This test
        // is proving that the older queued intent still exists, so use the
        // caller-directed seam that deliberately bypasses that cooldown.
        let operation_a_retry = client
            .run_pending_epoch_backfill(
                marmot_forensics::EpochBackfillExecutionSeam::ExplicitCatchUp,
            )
            .await
            .expect("operation a must retry");
        assert!(
            matches!(
                operation_a_retry,
                crate::EpochBackfillRunOutcome::Completed(_)
            ),
            "operation a must execute"
        );
        assert!(
            !client.has_pending_epoch_backfill(),
            "both operations must be consumed after successful retries"
        );

        let audit_rows = app
            .audit_log_files()
            .unwrap()
            .into_iter()
            .flat_map(|file| {
                std::fs::read_to_string(file.path)
                    .unwrap()
                    .lines()
                    .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let rows_for_operation = |operation_id: &str, kind: &str| {
            audit_rows
                .iter()
                .filter(|row| {
                    row["kind"]["type"] == kind
                        && row["context"]["operation_id"].as_str() == Some(operation_id)
                })
                .count()
        };
        assert_eq!(
            rows_for_operation(&operation_a, "epoch_stall_backfill_armed"),
            1
        );
        assert_eq!(
            rows_for_operation(&operation_a, "epoch_stall_backfill_started"),
            2
        );
        assert_eq!(
            rows_for_operation(&operation_a, "epoch_stall_backfill_failed"),
            1
        );
        assert_eq!(
            rows_for_operation(&operation_a, "epoch_stall_backfill_completed"),
            1
        );
        assert_eq!(
            rows_for_operation(&operation_b, "epoch_stall_backfill_armed"),
            1
        );
        assert_eq!(
            rows_for_operation(&operation_b, "epoch_stall_backfill_started"),
            1
        );
        assert_eq!(
            rows_for_operation(&operation_b, "epoch_stall_backfill_completed"),
            1
        );
        assert_eq!(
            rows_for_operation(&operation_b, "epoch_stall_backfill_failed"),
            0
        );
    });
}

#[test]
fn repeated_epoch_backfill_deferral_does_not_multiply_identical_evidence() {
    run_composed_app_runtime_test("epoch-backfill-deferral", || async {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        app.set_audit_log_settings(crate::AuditLogSettings { enabled: true })
            .unwrap();

        let mut client = app.client("alice").await.unwrap();
        let group_id = client
            .create_group("epoch backfill deferral", &[])
            .await
            .unwrap();
        let stalled_epoch = client.group_mls_state(&group_id).unwrap().epoch;
        client.apply_backfill_decision(
            &group_id,
            stalled_epoch,
            BackfillDecision::Arm,
            marmot_forensics::EpochStallBackfillTrigger::UndecryptableThreshold,
        );
        let phantom_group = cgka_traits::GroupId::new(vec![0xde]);
        client
            .pending_epoch_backfill
            .as_mut()
            .expect("backfill must be armed")
            .groups
            .insert(
                phantom_group.clone(),
                crate::client::epoch_stall::PendingEpochBackfillGroup { stalled_epoch: 1 },
            );

        for _ in 0..3 {
            assert!(
                client
                    .begin_epoch_backfill_execution(
                        marmot_forensics::EpochBackfillExecutionSeam::Maintenance,
                    )
                    .is_none(),
                "unavailable group epochs must keep deferring execution"
            );
        }

        let deferred_rows = || {
            app.audit_log_files()
                .unwrap()
                .into_iter()
                .flat_map(|file| {
                    std::fs::read_to_string(file.path)
                        .unwrap()
                        .lines()
                        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
                        .collect::<Vec<_>>()
                })
                .filter(|row| row["kind"]["type"] == "epoch_stall_backfill_deferred")
                .collect::<Vec<_>>()
        };
        assert_eq!(
            deferred_rows().len(),
            1,
            "identical deferral seams must not multiply deferred evidence"
        );

        client
            .pending_epoch_backfill
            .as_mut()
            .expect("pending recovery must remain armed")
            .groups
            .remove(&phantom_group);
        client
            .pending_epoch_backfill
            .as_mut()
            .expect("pending recovery must remain armed")
            .groups
            .insert(
                cgka_traits::GroupId::new(vec![0xad]),
                crate::client::epoch_stall::PendingEpochBackfillGroup { stalled_epoch: 2 },
            );
        assert!(
            client
                .begin_epoch_backfill_execution(
                    marmot_forensics::EpochBackfillExecutionSeam::Maintenance,
                )
                .is_none(),
            "a changed armed-group identity at the same cardinality must still defer"
        );
        assert_eq!(
            deferred_rows().len(),
            2,
            "a meaningful identity transition must emit deferred evidence again"
        );
        for _ in 0..3 {
            assert!(
                client
                    .begin_epoch_backfill_execution(
                        marmot_forensics::EpochBackfillExecutionSeam::Maintenance,
                    )
                    .is_none(),
                "repeated identical deferral seams must stay debounced"
            );
        }
        assert_eq!(
            deferred_rows().len(),
            2,
            "repeated identical deferral seams must not multiply deferred evidence"
        );

        client
            .pending_epoch_backfill
            .as_mut()
            .expect("pending recovery must remain armed")
            .groups
            .retain(|group_id, _| *group_id.as_slice() != [0xad]);
        assert!(
            client
                .begin_epoch_backfill_execution(
                    marmot_forensics::EpochBackfillExecutionSeam::Maintenance,
                )
                .is_some(),
            "once every armed group is observable the replay must start"
        );
        assert_eq!(
            deferred_rows().len(),
            2,
            "starting execution must not add another deferred row"
        );
    });
}

#[test]
fn deferred_primary_epoch_backfill_rotates_behind_queued_older_operation() {
    run_composed_app_runtime_test("epoch-backfill-fair-defer", || async {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = MarmotApp::with_relay_and_config(
            dir.path(),
            "wss://relay.example".to_owned(),
            bounded_epoch_backfill_config(),
        )
        .with_test_relay_client(relay.clone());
        app.set_audit_log_settings(crate::AuditLogSettings { enabled: true })
            .unwrap();

        let _eose = scripted_eose_pump(app.relay_plane.clone(), relay.clone(), every_subscription);

        let mut client = client_on_app_relay_plane(&app, "alice").await;
        let group_a = client
            .create_group("queued older backfill group a", &[])
            .await
            .unwrap();
        let group_b = client
            .create_group("queued older backfill group b", &[])
            .await
            .unwrap();
        let stalled_epoch_a = client.group_mls_state(&group_a).unwrap().epoch;
        client.apply_backfill_decision(
            &group_a,
            stalled_epoch_a,
            BackfillDecision::Arm,
            marmot_forensics::EpochStallBackfillTrigger::UndecryptableThreshold,
        );
        let operation_a = client
            .pending_epoch_backfill
            .as_ref()
            .expect("group a must arm one recovery intent")
            .attempt_id
            .clone();

        let execution = client
            .begin_epoch_backfill_execution(
                marmot_forensics::EpochBackfillExecutionSeam::Maintenance,
            )
            .expect("the first operation must begin execution");
        assert_eq!(execution.pending.attempt_id, operation_a);

        let stalled_epoch_b = client.group_mls_state(&group_b).unwrap().epoch;
        client.apply_backfill_decision(
            &group_b,
            stalled_epoch_b,
            BackfillDecision::Arm,
            marmot_forensics::EpochStallBackfillTrigger::UndecryptableThreshold,
        );
        let operation_b = client
            .pending_epoch_backfill
            .as_ref()
            .expect("group b must arm a second recovery intent during replay")
            .attempt_id
            .clone();
        assert_ne!(operation_a, operation_b);

        client.test_finish_epoch_backfill_execution(execution, false);
        assert_eq!(
            client
                .pending_epoch_backfill
                .as_ref()
                .map(|pending| pending.attempt_id.as_str()),
            Some(operation_b.as_str()),
            "the newer in-flight arm must stay scheduled ahead of the failed operation"
        );
        assert!(
            client
                .queued_epoch_backfills
                .iter()
                .any(|pending| pending.attempt_id == operation_a),
            "the failed operation must be queued behind the newer arm"
        );

        client
            .pending_epoch_backfill
            .as_mut()
            .expect("newer operation must remain primary")
            .groups
            .insert(
                cgka_traits::GroupId::new(vec![0xde]),
                crate::client::epoch_stall::PendingEpochBackfillGroup { stalled_epoch: 1 },
            );

        assert!(
            client
                .begin_epoch_backfill_execution(
                    marmot_forensics::EpochBackfillExecutionSeam::Maintenance,
                )
                .is_none(),
            "the unavailable newer operation must defer without starving queued work"
        );
        assert_eq!(
            client
                .pending_epoch_backfill
                .as_ref()
                .map(|pending| pending.attempt_id.as_str()),
            Some(operation_a.as_str()),
            "fair deferral must rotate the queued older operation to the front"
        );
        assert!(
            client
                .queued_epoch_backfills
                .iter()
                .any(|pending| pending.attempt_id == operation_b),
            "the deferred newer operation must rotate behind the queued older work"
        );

        let older_retry = client
            .run_pending_epoch_backfill(marmot_forensics::EpochBackfillExecutionSeam::Maintenance)
            .await
            .expect("the queued older operation must retry");
        assert!(
            matches!(older_retry, crate::EpochBackfillRunOutcome::Completed(_)),
            "the queued older operation must execute"
        );
        assert!(
            client
                .queued_epoch_backfills
                .iter()
                .any(|pending| pending.attempt_id == operation_b),
            "the deferred newer operation must remain retryable after the older operation runs"
        );

        let audit_rows = app
            .audit_log_files()
            .unwrap()
            .into_iter()
            .flat_map(|file| {
                std::fs::read_to_string(file.path)
                    .unwrap()
                    .lines()
                    .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let rows_for_operation = |operation_id: &str, kind: &str| {
            audit_rows
                .iter()
                .filter(|row| {
                    row["kind"]["type"] == kind
                        && row["context"]["operation_id"].as_str() == Some(operation_id)
                })
                .count()
        };
        assert_eq!(
            rows_for_operation(&operation_a, "epoch_stall_backfill_started"),
            2,
            "the queued older operation must reach started evidence after fair deferral"
        );
        assert_eq!(
            rows_for_operation(&operation_a, "epoch_stall_backfill_failed"),
            1,
            "the older operation must retain its earlier failed terminal"
        );
        assert_eq!(
            rows_for_operation(&operation_a, "epoch_stall_backfill_completed"),
            1,
            "the queued older operation must reach completed terminal evidence"
        );
        assert_eq!(
            rows_for_operation(&operation_b, "epoch_stall_backfill_deferred"),
            1,
            "the unavailable newer operation must emit one debounced deferred row"
        );
        assert_eq!(
            rows_for_operation(&operation_b, "epoch_stall_backfill_started"),
            0,
            "the newer operation must not start while its group epochs stay unavailable"
        );
    });
}

/// Run app-runtime integration chains on a stack large enough for debug
/// OpenMLS group creation. Libtest's default 2 MiB stack is too small once a
/// test composes the account worker with maintenance and push lifecycle work.
fn run_composed_app_runtime_test<F, Fut>(thread_name: &str, body: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + 'static,
{
    let test_thread = std::thread::Builder::new()
        .name(thread_name.to_owned())
        .stack_size(4 * 1024 * 1024)
        .spawn(move || {
            let test_runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            test_runtime.block_on(body());
        })
        .unwrap();
    test_thread.join().unwrap();
}

#[test]
fn create_group_options_apply_initial_retention_atomically() {
    run_composed_app_runtime_test("initial-group-retention", || async {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let mut client = app.client("alice").await.unwrap();

        let retained = client
            .create_group_with_options(
                "retained from founding state",
                &[],
                AppCreateGroupOptions {
                    disappearing_message_secs: 300,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let disabled = client
            .create_group_with_options(
                "disabled retention compatibility",
                &[],
                AppCreateGroupOptions::default(),
            )
            .await
            .unwrap();

        assert_eq!(client.group_mls_state(&retained).unwrap().epoch, 0);
        assert_eq!(
            app.group("alice", &hex::encode(retained.as_slice()))
                .unwrap()
                .unwrap()
                .message_retention
                .disappearing_message_secs,
            300
        );
        assert_eq!(
            app.group("alice", &hex::encode(disabled.as_slice()))
                .unwrap()
                .unwrap()
                .message_retention
                .disappearing_message_secs,
            0
        );
    });
}

#[test]
fn live_group_archive_checkpoints_seen_and_target_group_deltas() {
    run_composed_app_runtime_test("account-projection-delta", || async {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let mut client = app.client("alice").await.unwrap();
        let alpha = client.create_group("alpha", &[]).await.unwrap();
        let beta = client.create_group("beta", &[]).await.unwrap();

        client.state.seen_events = (0..256).map(|index| format!("event-{index:05}")).collect();
        client.seen_events_index = client.state.seen_events.iter().cloned().collect();
        client.pending_seen_event_count = 0;
        app.save_state(&client.state).unwrap();

        client.remember_seen_event("event-new".to_owned());
        client.set_group_archived(&alpha, true).unwrap();

        assert_eq!(client.pending_seen_event_count, 0);
        assert!(client.pending_group_projection_updates.is_empty());
        let restored = app.load_state("alice").unwrap();
        assert_eq!(restored.seen_events.len(), 257);
        assert_eq!(
            restored.seen_events.last().map(String::as_str),
            Some("event-new")
        );
        assert!(
            restored
                .groups
                .iter()
                .find(|group| group.group_id_hex == hex::encode(alpha.as_slice()))
                .unwrap()
                .archived
        );
        assert!(
            !restored
                .groups
                .iter()
                .find(|group| group.group_id_hex == hex::encode(beta.as_slice()))
                .unwrap()
                .archived
        );
    });
}

#[test]
fn account_session_guard_is_exclusive_until_client_drop() {
    run_composed_app_runtime_test("account-session-guard", || async {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        home.create_account("alice").unwrap();
        home.create_account("bob").unwrap();
        let alice_account_id = home.account("alice").unwrap().account_id_hex;
        let canonical_account = home.create_nostr_account().unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));

        let alice = app.client("alice").await.unwrap();
        assert!(matches!(
            app.client("alice").await,
            Err(AppError::AccountSessionBusy)
        ));

        // Hex labels and npub refs for the same account share one canonical
        // ownership key.
        let canonical = app.client(&canonical_account.label).await.unwrap();
        let alias_open = app
            .client(&npub_for_account_id_lossy(
                &canonical_account.account_id_hex,
            ))
            .await;
        assert!(
            matches!(alias_open, Err(AppError::AccountSessionBusy)),
            "{:?}",
            alias_open.err()
        );
        drop(canonical);

        // Ownership is scoped per account, not across the whole app.
        let bob = app.client("bob").await.unwrap();
        drop(bob);

        // Managed-worker startup preserves the typed contention error instead
        // of flattening it into BlockingTask.
        let contended_runtime = MarmotAppRuntime::new(app.clone());
        assert!(matches!(
            contended_runtime.reconcile_accounts().await,
            Err(AppError::AccountSessionBusy)
        ));
        contended_runtime.shutdown().await;

        // One-shot operations can release their client and managed workers can
        // then hydrate the accounts normally.
        drop(alice);
        let runtime = MarmotAppRuntime::new(app.clone());
        runtime.start().await.unwrap();
        assert!(matches!(
            app.client("alice").await,
            Err(AppError::AccountSessionBusy)
        ));

        // Restart waits for the previous worker to release ownership before
        // opening its replacement.
        runtime.restart_account(&alice_account_id).await.unwrap();
        assert!(matches!(
            app.client("alice").await,
            Err(AppError::AccountSessionBusy)
        ));

        // Worker shutdown releases the same guard for a later one-shot open.
        runtime.shutdown().await;
        let reopened = app.client("alice").await.unwrap();
        drop(reopened);
    });
}

#[test]
fn disabling_native_push_persists_removal_before_returning_without_waiting_for_relay() {
    run_composed_app_runtime_test(
        "disable-native-push-removal",
        disable_native_push_removal_body,
    );
}

#[test]
fn account_reconcile_returns_local_readiness_before_relay_subscription_registration() {
    run_composed_app_runtime_test(
        "account-local-ready-before-subscribe",
        account_local_ready_before_subscribe_body,
    );
}

#[test]
fn invite_members_keeps_same_account_projection_reads_off_detached_catch_up() {
    run_composed_app_runtime_test(
        "invite-members-detaches-post-mutation-catch-up",
        invite_members_detaches_post_mutation_catch_up_body,
    );
}

#[test]
fn concurrent_invites_keep_both_accounts_readable_during_catch_up() {
    run_composed_app_runtime_test(
        "concurrent-invites-keep-projections-readable",
        concurrent_invites_keep_projections_readable_body,
    );
}

#[test]
fn local_ready_send_remains_pending_when_transport_activation_fails() {
    run_composed_app_runtime_test(
        "local-ready-send-pending-on-activation-failure",
        local_ready_send_pending_on_activation_failure_body,
    );
}

#[test]
fn local_ready_queued_sends_publish_once_in_order_after_activation_recovers() {
    run_composed_app_runtime_test(
        "local-ready-queued-send-ordering",
        local_ready_queued_send_ordering_body,
    );
}

#[test]
fn locally_queued_send_survives_runtime_restart_and_failed_reactivation() {
    run_composed_app_runtime_test(
        "local-ready-queued-send-restart",
        locally_queued_send_restart_body,
    );
}

#[test]
fn pending_disband_is_projected_and_blocks_optimistic_application_messages() {
    run_composed_app_runtime_test(
        "pending-disband-composer-gate",
        pending_disband_composer_gate_body,
    );
}

#[test]
fn inbound_disband_candidate_blocks_both_local_delete_entry_points() {
    run_composed_app_runtime_test(
        "inbound-disband-local-delete-gate",
        inbound_disband_candidate_blocks_local_delete_body,
    );
}

async fn inbound_disband_candidate_blocks_local_delete_body() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let mut client = app.client("alice").await.unwrap();
    let group_id = client.create_group("terminal", &[]).await.unwrap();
    let group_id_hex = hex::encode(group_id.as_slice());
    app.account_storage("alice")
        .unwrap()
        .put_disband_candidate(&DisbandCandidate {
            group_id: group_id.clone(),
            source_epoch: cgka_traits::EpochId(0),
            commit_id: cgka_traits::MessageId::new(vec![0x41; 32]),
            content_commit_id: cgka_traits::MessageId::new(vec![0x42; 32]),
            commit_digest: [0x43; 32],
            actor: cgka_traits::MemberId::new(vec![0x44; 32]),
            local_was_committer_leaf: false,
            former_members: vec![],
        })
        .unwrap();

    assert!(matches!(
        client.delete_group_local(&group_id).await,
        Err(AppError::GroupDisbanding(_))
    ));
    assert!(matches!(
        app.delete_group_local_data("alice", &group_id_hex),
        Err(AppError::GroupDisbanding(_))
    ));
}

async fn pending_disband_composer_gate_body() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let mut client = app.client("alice").await.unwrap();
    let group_id = client.create_group("terminal", &[]).await.unwrap();
    let group_id_hex = hex::encode(group_id.as_slice());

    let request = client.disband_group(&group_id).await.unwrap();
    assert!(matches!(
        request,
        AppDisbandRequest::Pending { requested_at_ms: _ }
    ));

    let mls = client.group_mls_state(&group_id).unwrap();
    assert!(mls.disbanding);
    assert!(matches!(
        mls.disband_request,
        Some(AppDisbandRequest::Pending { .. })
    ));

    let group = app.group("alice", &group_id_hex).unwrap().unwrap();
    assert!(group.disbanding);
    assert!(!group.disbanded);
    assert!(matches!(
        group.disband_request,
        Some(AppDisbandRequest::Pending { .. })
    ));

    let row = app
        .chat_list_row("alice", &group_id_hex)
        .unwrap()
        .expect("chat-list row");
    assert!(row.disbanding);
    assert!(matches!(
        row.disband_request,
        Some(cgka_traits::DisbandRequest {
            status: cgka_traits::DisbandRequestStatus::Pending,
            ..
        })
    ));

    let mut optimistic_projection_count = 0usize;
    let error = client
        .send_with_local_projection(&group_id, b"must not appear", |_| {
            optimistic_projection_count += 1;
        })
        .await
        .unwrap_err();
    assert!(matches!(error, AppError::GroupDisbanding(_)));
    assert_eq!(
        optimistic_projection_count, 0,
        "composer sends must fail before optimistic timeline projection"
    );
}

async fn account_local_ready_before_subscribe_body() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    relay.block_next_subscribe();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let runtime = MarmotAppRuntime::new(app);

    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        runtime.reconcile_accounts(),
    )
    .await
    .expect("local account readiness must not wait for relay registration")
    .unwrap();
    assert_eq!(runtime.accounts().managed_accounts().unwrap().len(), 1);
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            runtime.quarantined_groups("alice"),
        )
        .await
        .expect("worker-routed local reads must be served during registration")
        .unwrap()
        .is_empty()
    );

    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        relay.wait_for_blocked_subscribe(),
    )
    .await
    .expect("subscription registration should continue after local readiness");

    let telemetry = runtime
        .shared_services()
        .app_performance_telemetry()
        .snapshot();
    assert_eq!(telemetry.account_open.successes, 1);
    assert_eq!(telemetry.account_subscription_registration.attempts, 0);

    relay.release_subscribe();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if runtime
                .shared_services()
                .app_performance_telemetry()
                .snapshot()
                .account_subscription_registration
                .successes
                == 1
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("subscription registration telemetry should complete asynchronously");
    let telemetry = runtime
        .shared_services()
        .app_performance_telemetry()
        .snapshot();
    assert_eq!(telemetry.account_transport_activation.successes, 1);
    assert_eq!(telemetry.account_subscription_registration.successes, 1);
    runtime.shutdown().await;
}

async fn invite_members_detaches_post_mutation_catch_up_body() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let bob = home.create_account("bob").unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let runtime = MarmotAppRuntime::new(app);
    runtime.reconcile_accounts().await.unwrap();
    runtime.catch_up_accounts().await.unwrap();
    let group_id = runtime
        .create_group("alice", "invite latency", &[], None)
        .await
        .unwrap();

    relay.block_account_subscribe_after_next_publish(
        hex::decode(home.account("alice").unwrap().account_id_hex).unwrap(),
    );
    let inviting_runtime = runtime.clone();
    let invite_group_id = group_id.clone();
    let bob_account_id = bob.account_id_hex.clone();
    let invite = tokio::spawn(async move {
        inviting_runtime
            .invite_members(
                "alice",
                &invite_group_id,
                std::slice::from_ref(&bob_account_id),
            )
            .await
    });
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        relay.wait_for_blocked_subscribe(),
    )
    .await
    .expect("inviting-account catch-up should remain blocked after publication");
    tokio::time::timeout(std::time::Duration::from_millis(250), invite)
        .await
        .expect("confirmed invite must return before read-side catch-up finishes")
        .expect("invite task should not panic")
        .expect("invite should succeed");

    let (members, mls_state, roster) =
        tokio::time::timeout(std::time::Duration::from_millis(250), async {
            let members = runtime.group_members("alice", &group_id).await?;
            let mls_state = runtime.group_mls_state("alice", &group_id).await?;
            let roster = runtime.group_roster("alice", &group_id).await?;
            Ok::<_, AppError>((members, mls_state, roster))
        })
        .await
        .expect("same-account post-invite projection reads must not queue behind catch-up")
        .expect("same-account post-invite projection reads should succeed");
    assert_eq!(members.len(), 2);
    assert_eq!(mls_state.member_count, 2);
    assert_eq!(roster.members.len(), 2);
    assert_eq!(roster.epoch, mls_state.epoch);

    let before_release = runtime
        .shared_services()
        .app_performance_telemetry()
        .snapshot();
    assert_eq!(before_release.group_invite_members.successes, 1);
    assert_eq!(
        before_release.group_invite_post_mutation_catch_up.successes, 0,
        "inviting-account catch-up must remain unfinished while its subscription is blocked"
    );

    relay.release_subscribe();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if runtime
                .shared_services()
                .app_performance_telemetry()
                .snapshot()
                .group_invite_post_mutation_catch_up
                .successes
                == 1
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("detached post-mutation catch-up should finish after the relay unblocks");
    runtime.shutdown().await;
}

#[test]
fn founding_create_leaves_reconstructable_welcome_index_off_response_path() {
    run_composed_app_runtime_test("create-derived-welcome-index", || async {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        home.create_account("alice").unwrap();
        let bob = home.create_account("bob").unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        let runtime = MarmotAppRuntime::new(app.clone());
        runtime.reconcile_accounts().await.unwrap();
        runtime.catch_up_accounts().await.unwrap();
        app.chat_list_projection_warmed
            .lock()
            .unwrap()
            .remove("alice");
        app.chat_list_projection_stale
            .lock()
            .unwrap()
            .insert("alice".to_owned());

        relay.block_next_publish();
        let created = runtime
            .create_group_detailed(
                "alice",
                "derived welcome index",
                std::slice::from_ref(&bob.account_id_hex),
                None,
            )
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), relay.wait_for_blocked_publish())
            .await
            .expect("post-response Welcome publish should be blocked");

        assert!(
            app.account_storage("alice")
                .unwrap()
                .list_pending_welcome_deliveries()
                .unwrap()
                .is_empty(),
            "the engine-retained Welcome is authoritative; create must not pay a second convenience-index commit"
        );
        assert_eq!(
            app.account_storage("alice")
                .unwrap()
                .chat_list_row(&created.chat_list_row.group_id_hex)
                .unwrap(),
            Some(created.chat_list_row),
            "the remaining post-canonical commit must already contain the durable host projection"
        );
        assert!(
            app.chat_list_projection_stale
                .lock()
                .unwrap()
                .contains("alice"),
            "create refreshes only its returned row and must preserve a pre-existing full-list rebuild obligation"
        );
        assert!(
            !app.chat_list_projection_warmed
                .lock()
                .unwrap()
                .contains("alice"),
            "refreshing one created row must not claim the full chat-list projection is warmed"
        );

        relay.release_publish();
        runtime.shutdown().await;
    });
}

#[test]
fn joined_group_is_visible_before_subscription_rebuild_and_accept_is_prompt_during_catch_up() {
    run_composed_app_runtime_test("invite-catch-up-ordering", || async {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        let _alice = home.create_account("alice").unwrap();
        let bob = home.create_account("bob").unwrap();
        let bob_member = MemberId::new(hex::decode(&bob.account_id_hex).unwrap());
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        let runtime = MarmotAppRuntime::new(app.clone());
        runtime.reconcile_accounts().await.unwrap();
        runtime.catch_up_accounts().await.unwrap();
        let mut events = runtime.subscribe();

        // The first ordinary group-subscription rebuild will park and fail.
        // The distinct post-join full-history subscription remains available,
        // so this isolates the visibility boundary the regression cares about.
        relay.block_and_fail_account_group_subscribe(bob_member.as_slice().to_vec());
        let group_id = runtime
            .create_group(
                "alice",
                "invite catch-up ordering",
                std::slice::from_ref(&bob.account_id_hex),
                None,
            )
            .await
            .unwrap();

        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match events.recv().await {
                    Ok(MarmotAppEvent::GroupJoined {
                        account_id_hex,
                        group_id: joined,
                        ..
                    }) if account_id_hex == bob.account_id_hex && joined == group_id => break,
                    Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        panic!("runtime event stream closed before GroupJoined")
                    }
                }
            }
        })
        .await
        .expect("GroupJoined must publish without waiting for the ordinary subscription rebuild");

        let group_id_hex = hex::encode(group_id.as_slice());
        assert!(
            app.group("bob", &group_id_hex)
                .unwrap()
                .expect("joined group projection")
                .pending_confirmation,
            "the durable invite projection must be queryable at GroupJoined"
        );

        tokio::time::timeout(Duration::from_secs(5), relay.wait_for_blocked_subscribe())
            .await
            .expect("ordinary group subscription refresh should run in the background");
        relay.release_subscribe();

        // The parked attempt fails after release. Its durable retry intent must
        // rebuild the ordinary subscription without unrelated worker traffic.
        let retry_result = tokio::time::timeout(Duration::from_secs(5), async {
            while relay.group_subscription_count(&bob_member, &group_id) == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(
            retry_result.is_ok(),
            "failed ordinary group subscription must retry with bounded backoff (all_group_attempts={}, matching_attempts={})",
            relay.group_subscribe_attempts(),
            relay.matching_group_subscribe_attempts(&bob_member, &group_id),
        );

        // Pin Bob's next explicit catch-up at the account-inbox subscription.
        // Accept must be rejected as definitely-not-started, not retained
        // behind the relay operation or reported with ambiguous completion.
        relay.block_account_inbox_subscribe(bob_member.as_slice().to_vec());
        let catch_up_runtime = runtime.clone();
        let catch_up = tokio::spawn(async move { catch_up_runtime.catch_up_accounts().await });
        tokio::time::timeout(Duration::from_secs(5), relay.wait_for_blocked_subscribe())
            .await
            .expect("explicit catch-up should reach the pinned subscription");

        let accept_error = tokio::time::timeout(
            Duration::from_millis(250),
            runtime.accept_group_invite("bob", &group_id),
        )
        .await
        .expect("accept must answer promptly while catch-up is pinned")
        .expect_err("accept cannot start while catch-up owns the account client");
        assert!(matches!(accept_error, AppError::AccountWorkerBusy));
        assert!(
            app.group("bob", &group_id_hex)
                .unwrap()
                .expect("invite remains visible")
                .pending_confirmation,
            "busy means the accept mutation definitely did not run"
        );

        relay.release_subscribe();
        tokio::time::timeout(Duration::from_secs(5), catch_up)
            .await
            .expect("catch-up should finish after release")
            .expect("catch-up task should not panic")
            .expect("catch-up should succeed");

        let accepted = runtime.accept_group_invite("bob", &group_id).await.unwrap();
        assert!(!accepted.pending_confirmation);
        runtime.shutdown().await;
    });
}

async fn concurrent_invites_keep_projections_readable_body() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let alice = home.create_account("alice").unwrap();
    let bob = home.create_account("bob").unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let runtime = MarmotAppRuntime::new(app);
    runtime.reconcile_accounts().await.unwrap();
    runtime.catch_up_accounts().await.unwrap();
    let alice_group = runtime
        .create_group("alice", "alice invite", &[], None)
        .await
        .unwrap();
    let bob_group = runtime
        .create_group("bob", "bob invite", &[], None)
        .await
        .unwrap();
    // Hold each invite at its first publication so both mutations overlap
    // before either detached catch-up can start.
    relay.block_next_publishes(2);
    let alice_runtime = runtime.clone();
    let alice_group_for_invite = alice_group.clone();
    let bob_account_id = bob.account_id_hex.clone();
    let alice_invite = tokio::spawn(async move {
        alice_runtime
            .invite_members(
                "alice",
                &alice_group_for_invite,
                std::slice::from_ref(&bob_account_id),
            )
            .await
    });
    let bob_runtime = runtime.clone();
    let bob_group_for_invite = bob_group.clone();
    let alice_account_id = alice.account_id_hex.clone();
    let bob_invite = tokio::spawn(async move {
        bob_runtime
            .invite_members(
                "bob",
                &bob_group_for_invite,
                std::slice::from_ref(&alice_account_id),
            )
            .await
    });
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        relay.wait_for_blocked_publishes(2),
    )
    .await
    .expect("both concurrent invites should reach publication");
    relay.release_publish();
    let (alice_result, bob_result) =
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(alice_invite, bob_invite)
        })
        .await
        .expect("both confirmed invites should return while detached catch-up is coordinated");
    alice_result
        .expect("alice invite task should not panic")
        .expect("alice invite should succeed");
    bob_result
        .expect("bob invite task should not panic")
        .expect("bob invite should succeed");

    let alice_members = tokio::time::timeout(
        std::time::Duration::from_millis(250),
        runtime.group_members("alice", &alice_group),
    )
    .await
    .expect("alice members must not queue behind concurrent invite catch-up")
    .expect("alice members should succeed");
    let alice_state = tokio::time::timeout(
        std::time::Duration::from_millis(250),
        runtime.group_mls_state("alice", &alice_group),
    )
    .await
    .expect("alice MLS state must not queue behind concurrent invite catch-up")
    .expect("alice MLS state should succeed");
    let bob_members = tokio::time::timeout(
        std::time::Duration::from_millis(250),
        runtime.group_members("bob", &bob_group),
    )
    .await
    .expect("bob members must not queue behind concurrent invite catch-up")
    .expect("bob members should succeed");
    let bob_state = tokio::time::timeout(
        std::time::Duration::from_millis(250),
        runtime.group_mls_state("bob", &bob_group),
    )
    .await
    .expect("bob MLS state must not queue behind concurrent invite catch-up")
    .expect("bob MLS state should succeed");
    assert_eq!(alice_members.len(), 2);
    assert_eq!(alice_state.member_count, 2);
    assert_eq!(bob_members.len(), 2);
    assert_eq!(bob_state.member_count, 2);
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if runtime
                .shared_services()
                .app_performance_telemetry()
                .snapshot()
                .group_invite_post_mutation_catch_up
                .successes
                == 2
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("both detached catch-ups should complete after the relay unblocks");
    runtime.shutdown().await;
}

async fn local_ready_send_pending_on_activation_failure_body() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());

    // Seed the persisted conversation using an independently activated client.
    // The runtime below receives a fresh relay plane and must activate it after
    // reporting local readiness.
    let mut setup_client = app.client("alice").await.unwrap();
    let group_id = setup_client
        .create_group("local-ready send", &[])
        .await
        .unwrap();
    drop(setup_client);
    let publishes_before_runtime = relay.published_event_ids().len();

    relay.block_and_fail_next_subscribe();
    let runtime = MarmotAppRuntime::new(app.clone());
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        runtime.reconcile_accounts(),
    )
    .await
    .expect("local readiness must not wait for transport activation")
    .unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        relay.wait_for_blocked_subscribe(),
    )
    .await
    .expect("transport activation should continue after local readiness");

    let send_runtime = runtime.clone();
    let send_group_id = group_id.clone();
    let mut send = tokio::spawn(async move {
        send_runtime
            .send_message(
                "alice",
                &send_group_id,
                b"retain while transport activates".to_vec(),
            )
            .await
    });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), &mut send)
            .await
            .is_err(),
        "the send should remain deferred while initial activation is blocked"
    );

    // Hold the reconnect activation too, so the test can observe the accepted
    // local row before background convergence publishes it.
    relay.block_next_subscribe();
    relay.release_subscribe();
    let send_result = tokio::time::timeout(std::time::Duration::from_secs(5), send)
        .await
        .expect("deferred send should settle after activation failure")
        .expect("send task should not panic");
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        relay.wait_for_blocked_subscribe(),
    )
    .await
    .expect("transport reconnect should continue in the background");
    let timeline = app
        .timeline_messages_with_query(
            "alice",
            TimelineMessageQuery {
                group_id_hex: Some(hex::encode(group_id.as_slice())),
                ..TimelineMessageQuery::default()
            },
        )
        .unwrap();
    let group_id_hex = hex::encode(group_id.as_slice());
    let chat_list = app.chat_list("alice", false).unwrap();
    let chat_row = chat_list
        .iter()
        .find(|row| row.group_id_hex == group_id_hex)
        .expect("persisted conversation should remain in the chat list");
    let last_message = chat_row
        .last_message
        .as_ref()
        .expect("the locally accepted send should remain projected");

    assert_eq!(timeline.messages.len(), 1);
    assert_eq!(
        timeline.messages[0].plaintext,
        "retain while transport activates"
    );
    assert_eq!(
        last_message.delivery_state,
        ChatListMessageDeliveryState::Pending,
        "the app-facing projection must stay pending while activation recovers; \
         invalidation: {:?}; send result: {send_result:?}",
        timeline.messages[0].invalidation_status
    );
    assert_eq!(
        timeline.messages[0].invalidation_status, None,
        "a locally accepted send must remain pending while activation recovers; send result: {send_result:?}"
    );
    assert!(
        send_result.is_ok(),
        "transport lifecycle state must not become a terminal send error: {send_result:?}"
    );

    relay.release_subscribe();
    tokio::time::timeout(std::time::Duration::from_secs(8), async {
        loop {
            let timeline = app
                .timeline_messages_with_query(
                    "alice",
                    TimelineMessageQuery {
                        group_id_hex: Some(group_id_hex.clone()),
                        ..TimelineMessageQuery::default()
                    },
                )
                .unwrap();
            if timeline.messages.len() == 1 && timeline.messages[0].source_message_id_hex.is_some()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("reconnect should publish and finalize the queued row");
    let recovered_timeline = app
        .timeline_messages_with_query(
            "alice",
            TimelineMessageQuery {
                group_id_hex: Some(group_id_hex),
                ..TimelineMessageQuery::default()
            },
        )
        .unwrap();
    let published_ids = relay.published_event_ids();
    assert_eq!(
        published_ids.len() - publishes_before_runtime,
        1,
        "recovery must publish exactly one transport event"
    );
    assert_eq!(
        recovered_timeline.messages[0]
            .source_message_id_hex
            .as_deref(),
        published_ids.last().map(String::as_str),
        "the pending row must finalize with the one recovered transport event"
    );

    runtime.shutdown().await;
}

async fn local_ready_queued_send_ordering_body() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let mut setup_client = app.client("alice").await.unwrap();
    let group_id = setup_client
        .create_group("local-ready ordering", &[])
        .await
        .unwrap();
    drop(setup_client);
    let publishes_before_runtime = relay.published_event_ids().len();

    relay.block_and_fail_next_subscribe();
    let runtime = MarmotAppRuntime::new(app.clone());
    runtime.reconcile_accounts().await.unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        relay.wait_for_blocked_subscribe(),
    )
    .await
    .expect("initial activation should be in flight");

    let first_runtime = runtime.clone();
    let first_group = group_id.clone();
    let first = tokio::spawn(async move {
        first_runtime
            .send_message("alice", &first_group, b"first queued".to_vec())
            .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let second_runtime = runtime.clone();
    let second_group = group_id.clone();
    let second = tokio::spawn(async move {
        second_runtime
            .send_message("alice", &second_group, b"second queued".to_vec())
            .await
    });

    relay.block_next_subscribe();
    relay.release_subscribe();
    assert!(first.await.unwrap().is_ok());
    assert!(second.await.unwrap().is_ok());
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        relay.wait_for_blocked_subscribe(),
    )
    .await
    .expect("background transport reactivation should be attempted");

    let group_id_hex = hex::encode(group_id.as_slice());
    let pending = app
        .timeline_messages_with_query(
            "alice",
            TimelineMessageQuery {
                group_id_hex: Some(group_id_hex.clone()),
                ..TimelineMessageQuery::default()
            },
        )
        .unwrap();
    assert_eq!(pending.messages.len(), 2);
    assert!(
        pending
            .messages
            .iter()
            .all(|message| message.source_message_id_hex.is_none()
                && message.invalidation_status.is_none()),
        "both accepted sends must remain pending before activation recovers"
    );

    relay.release_subscribe();
    tokio::time::timeout(std::time::Duration::from_secs(8), async {
        loop {
            let timeline = app
                .timeline_messages_with_query(
                    "alice",
                    TimelineMessageQuery {
                        group_id_hex: Some(group_id_hex.clone()),
                        ..TimelineMessageQuery::default()
                    },
                )
                .unwrap();
            if timeline.messages.len() == 2
                && timeline
                    .messages
                    .iter()
                    .all(|message| message.source_message_id_hex.is_some())
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("both queued sends should finalize after activation");

    let delivered = app
        .timeline_messages_with_query(
            "alice",
            TimelineMessageQuery {
                group_id_hex: Some(group_id_hex),
                ..TimelineMessageQuery::default()
            },
        )
        .unwrap();
    let source_for = |plaintext: &str| {
        delivered
            .messages
            .iter()
            .find(|message| message.plaintext == plaintext)
            .and_then(|message| message.source_message_id_hex.clone())
            .expect("queued message should have one finalized source id")
    };
    let first_source = source_for("first queued");
    let second_source = source_for("second queued");
    assert_ne!(first_source, second_source);
    let published_ids = relay.published_event_ids();
    let recovered_ids = &published_ids[publishes_before_runtime..];
    assert_eq!(
        recovered_ids,
        &[first_source, second_source],
        "durable queue insertion order must be transport publication order"
    );

    runtime.shutdown().await;
}

async fn locally_queued_send_restart_body() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let mut setup_client = app.client("alice").await.unwrap();
    let group_id = setup_client
        .create_group("local-ready restart", &[])
        .await
        .unwrap();
    drop(setup_client);

    relay.block_and_fail_next_subscribe();
    let first_runtime = MarmotAppRuntime::new(app.clone());
    first_runtime.reconcile_accounts().await.unwrap();
    relay.wait_for_blocked_subscribe().await;
    let send_runtime = first_runtime.clone();
    let send_group = group_id.clone();
    let send = tokio::spawn(async move {
        send_runtime
            .send_message("alice", &send_group, b"survives restart".to_vec())
            .await
    });
    relay.release_subscribe();
    assert!(send.await.unwrap().is_ok());
    first_runtime.shutdown().await;

    let group_id_hex = hex::encode(group_id.as_slice());
    let pending = app
        .timeline_messages_with_query(
            "alice",
            TimelineMessageQuery {
                group_id_hex: Some(group_id_hex.clone()),
                ..TimelineMessageQuery::default()
            },
        )
        .unwrap();
    assert_eq!(pending.messages.len(), 1);
    assert!(pending.messages[0].source_message_id_hex.is_none());
    assert!(pending.messages[0].invalidation_status.is_none());
    let publishes_before_restart = relay.published_event_ids().len();

    // Fail the restarted worker's first activation too. Hydration must still
    // wake the durable queue, and its convergence timer must reactivate the
    // account without any new user command or inbound event.
    relay.block_and_fail_next_subscribe();
    let restarted_runtime = MarmotAppRuntime::new(app.clone());
    restarted_runtime.reconcile_accounts().await.unwrap();
    relay.wait_for_blocked_subscribe().await;
    relay.release_subscribe();

    tokio::time::timeout(std::time::Duration::from_secs(8), async {
        loop {
            let timeline = app
                .timeline_messages_with_query(
                    "alice",
                    TimelineMessageQuery {
                        group_id_hex: Some(group_id_hex.clone()),
                        ..TimelineMessageQuery::default()
                    },
                )
                .unwrap();
            if timeline.messages.len() == 1 && timeline.messages[0].source_message_id_hex.is_some()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("hydrated queue should publish after background reactivation");
    assert_eq!(
        relay.published_event_ids().len() - publishes_before_restart,
        1,
        "restart recovery must publish the logical message exactly once"
    );

    restarted_runtime.shutdown().await;
}

async fn disable_native_push_removal_body() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let runtime = MarmotAppRuntime::new(app.clone());
    runtime.reconcile_accounts().await.unwrap();
    runtime
        .create_group("alice", "alpha", &[], None)
        .await
        .unwrap();
    runtime
        .set_native_push_enabled("alice", true)
        .await
        .unwrap();
    runtime
        .upsert_push_registration(
            "alice",
            PushPlatform::Fcm,
            "retired-token",
            &nostr::Keys::generate().public_key().to_hex(),
            None,
        )
        .await
        .unwrap();

    relay.block_next_publish();
    let settings = tokio::time::timeout(
        std::time::Duration::from_millis(250),
        runtime.set_native_push_enabled("alice", false),
    )
    .await
    .expect("settings response must not wait for removal gossip")
    .unwrap();
    assert!(!settings.native_push_enabled);
    assert!(app.push_registration("alice").unwrap().is_none());
    assert_eq!(
        app.pending_push_registration_removals("alice")
            .unwrap()
            .len(),
        1,
        "removal intent must be durable before the settings response"
    );
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        relay.wait_for_blocked_publish(),
    )
    .await
    .expect("the serialized worker should start removal gossip after responding");
    relay.release_publish();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if app
                .pending_push_registration_removals("alice")
                .unwrap()
                .is_empty()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("removal gossip should drain after the relay unblocks");
    runtime.shutdown().await;
}

#[tokio::test]
async fn push_registration_update_retry_survives_failure_partial_success_and_restart() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let mut client = app.client("alice").await.unwrap();
    client.create_group("alpha", &[]).await.unwrap();
    client.create_group("beta", &[]).await.unwrap();
    app.set_native_push_enabled("alice", true).unwrap();
    let server_pubkey_hex = nostr::Keys::generate().public_key().to_hex();
    app.upsert_push_registration(
        "alice",
        PushPlatform::Fcm,
        "opaque-token",
        &server_pubkey_hex,
        None,
    )
    .unwrap();

    relay.script([false, false]);
    let all_failed = client.share_push_registration().await.unwrap();
    assert_eq!(all_failed.status, PushRegistrationShareStatus::Pending);
    assert_eq!(all_failed.attempted_groups, 2);
    assert_eq!(all_failed.succeeded_groups, 0);
    assert_eq!(all_failed.failed_groups, 2);
    assert_eq!(all_failed.pending_groups, 2);

    relay.script([true, false]);
    let partial = client.share_push_registration().await.unwrap();
    assert_eq!(partial.status, PushRegistrationShareStatus::Pending);
    assert_eq!(partial.attempted_groups, 2);
    assert_eq!(partial.succeeded_groups, 1);
    assert_eq!(partial.failed_groups, 1);
    assert_eq!(partial.pending_groups, 1);

    drop(client);
    drop(app);
    let reopened = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let runtime = MarmotAppRuntime::new(reopened.clone());
    runtime.reconcile_accounts().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let registration = reopened.push_registration("alice").unwrap().unwrap();
            if reopened
                .pending_push_registration_shares(
                    "alice",
                    &registration.token_fingerprint,
                    registration.updated_at_ms,
                )
                .unwrap()
                .is_empty()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("startup retry should drain the persisted update intent");
    runtime.shutdown().await;
}

#[test]
fn runtime_start_returns_before_initial_directory_subscription_registration() {
    run_composed_app_runtime_test(
        "runtime-local-ready-before-directory-subscribe",
        runtime_local_ready_before_directory_subscribe_body,
    );
}

async fn runtime_local_ready_before_directory_subscribe_body() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    relay.block_next_subscribe();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let runtime = MarmotAppRuntime::new(app);

    // Poll startup first so a correct implementation returns before the spawned
    // registration task can run. If startup ever awaits registration instead,
    // the blocked-subscribe signal wins immediately; the timeout only bounds a
    // genuine local-startup hang.
    let start_result = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        tokio::select! {
            biased;
            result = runtime.start() => result,
            () = relay.wait_for_blocked_subscribe() => {
                panic!("runtime start waited for network subscription registration");
            }
        }
    })
    .await
    .expect("runtime local startup must complete within the outer deadline");
    start_result.unwrap();
    assert!(runtime.shared_services().lifecycle().is_running());

    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        relay.wait_for_blocked_subscribe(),
    )
    .await
    .expect("a subscription should continue asynchronously after runtime start");
    relay.release_subscribe();
    runtime.shutdown().await;
}

#[test]
fn push_registration_idle_retry_drains_without_an_unrelated_lifecycle_event() {
    run_composed_app_runtime_test(
        "push-registration-idle-retry",
        push_registration_idle_retry_body,
    );
}

async fn push_registration_idle_retry_body() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let runtime = MarmotAppRuntime::new(app.clone());
    runtime.reconcile_accounts().await.unwrap();
    runtime
        .create_group("alice", "alpha", &[], None)
        .await
        .unwrap();
    runtime
        .set_native_push_enabled("alice", true)
        .await
        .unwrap();

    relay.script([false]);
    let result = runtime
        .upsert_push_registration(
            "alice",
            PushPlatform::Fcm,
            "opaque-token",
            &nostr::Keys::generate().public_key().to_hex(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(result.share.status, PushRegistrationShareStatus::Pending);

    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let registration = app.push_registration("alice").unwrap().unwrap();
            if app
                .pending_push_registration_shares(
                    "alice",
                    &registration.token_fingerprint,
                    registration.updated_at_ms,
                )
                .unwrap()
                .is_empty()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("bounded idle retry should drain pending gossip");
    runtime.shutdown().await;
}

#[test]
fn push_registration_local_projection_advances_only_after_publish() {
    run_composed_app_runtime_test(
        "push-registration-projection",
        push_registration_local_projection_body,
    );
}

async fn push_registration_local_projection_body() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let runtime = Arc::new(MarmotAppRuntime::new(app.clone()));
    runtime.reconcile_accounts().await.unwrap();
    let group_id = runtime
        .create_group("alice", "alpha", &[], None)
        .await
        .unwrap();
    runtime
        .set_native_push_enabled("alice", true)
        .await
        .unwrap();

    relay.block_next_publish();
    let runtime_for_upsert = runtime.clone();
    let server_pubkey_hex = nostr::Keys::generate().public_key().to_hex();
    let upsert = tokio::spawn(async move {
        runtime_for_upsert
            .upsert_push_registration(
                "alice",
                PushPlatform::Fcm,
                "opaque-token",
                &server_pubkey_hex,
                None,
            )
            .await
    });
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        relay.wait_for_blocked_publish(),
    )
    .await
    .unwrap();
    let group_id_hex = hex::encode(group_id.as_slice());
    assert!(
        app.group_push_tokens("alice", &group_id_hex)
            .unwrap()
            .is_empty(),
        "the local mirror must not advance ahead of relay publish"
    );
    relay.release_publish();
    upsert.await.unwrap().unwrap();
    assert_eq!(
        app.group_push_tokens("alice", &group_id_hex).unwrap().len(),
        1
    );
    runtime.shutdown().await;
}

#[test]
fn local_group_wipe_keeps_and_drains_durable_push_removal() {
    run_composed_app_runtime_test(
        "local-wipe-push-removal",
        local_group_wipe_push_removal_body,
    );
}

async fn local_group_wipe_push_removal_body() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let runtime = Arc::new(MarmotAppRuntime::new(app.clone()));
    runtime.reconcile_accounts().await.unwrap();
    let group_id = runtime
        .create_group("alice", "alpha", &[], None)
        .await
        .unwrap();
    runtime
        .set_native_push_enabled("alice", true)
        .await
        .unwrap();
    runtime
        .upsert_push_registration(
            "alice",
            PushPlatform::Fcm,
            "opaque-token",
            &nostr::Keys::generate().public_key().to_hex(),
            None,
        )
        .await
        .unwrap();

    app.clear_push_registration("alice").unwrap();
    relay.block_next_publish();
    let runtime_for_delete = runtime.clone();
    let group_id_for_delete = group_id.clone();
    let delete = tokio::spawn(async move {
        runtime_for_delete
            .delete_group_local("alice", &group_id)
            .await
    });
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        relay.wait_for_blocked_publish(),
    )
    .await
    .unwrap();
    assert_eq!(
        app.pending_push_registration_removals("alice")
            .unwrap()
            .len(),
        1,
        "the outbox row must remain durable while publish is blocked"
    );
    assert_eq!(
        app.group_push_tokens("alice", &hex::encode(group_id_for_delete.as_slice()))
            .unwrap()
            .len(),
        1,
        "the local projection must remain intact until removal publishes"
    );
    relay.release_publish();
    assert!(delete.await.unwrap().unwrap());
    assert!(
        app.pending_push_registration_removals("alice")
            .unwrap()
            .is_empty()
    );
    runtime.shutdown().await;
}

#[test]
fn failed_leave_restores_push_registration_after_removal_publishes() {
    run_composed_app_runtime_test(
        "failed-leave-push-compensation",
        failed_leave_push_compensation_body,
    );
}

async fn failed_leave_push_compensation_body() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let runtime = Arc::new(MarmotAppRuntime::new(app.clone()));
    runtime.reconcile_accounts().await.unwrap();
    let group_id = runtime
        .create_group("alice", "alpha", &[], None)
        .await
        .unwrap();
    runtime
        .set_native_push_enabled("alice", true)
        .await
        .unwrap();
    runtime
        .upsert_push_registration(
            "alice",
            PushPlatform::Fcm,
            "opaque-token",
            &nostr::Keys::generate().public_key().to_hex(),
            None,
        )
        .await
        .unwrap();

    relay.block_next_publish();
    let runtime_for_leave = runtime.clone();
    let group_id_for_leave = group_id.clone();
    let leave = tokio::spawn(async move {
        runtime_for_leave
            .leave_group("alice", &group_id_for_leave)
            .await
    });
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        relay.wait_for_blocked_publish(),
    )
    .await
    .unwrap();
    assert_eq!(
        app.pending_push_registration_removals("alice")
            .unwrap()
            .len(),
        1,
        "the registration removal must be durable before the MLS leave starts"
    );
    assert_eq!(
        app.group_push_tokens("alice", &hex::encode(group_id.as_slice()))
            .unwrap()
            .len(),
        1,
        "the local projection must remain intact until removal publishes"
    );

    relay.release_publish();
    assert!(matches!(
        leave.await.unwrap(),
        Err(AppError::Account(marmot_account::AccountError::Session(
            cgka_session::SessionError::Engine(
                cgka_traits::EngineError::AdminCannotSelfRemove { .. }
            )
        )))
    ));
    assert!(
        app.pending_push_registration_removals("alice")
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        app.group_push_tokens("alice", &hex::encode(group_id.as_slice()))
            .unwrap()
            .len(),
        1,
        "a failed leave must compensate by re-publishing the current registration"
    );
    runtime.shutdown().await;
}

#[test]
fn sole_admin_self_demote_surfaces_the_admin_policy_refusal() {
    run_composed_app_runtime_test("sole-admin-self-demote", || async {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let mut client = app.client("alice").await.unwrap();
        let group_id = client.create_group("sole admin", &[]).await.unwrap();

        // Alice is the only admin, so demoting herself would leave the group
        // with none. The host must receive that as the admin-policy refusal it
        // is, not as a payload-encoding fault.
        let err = client.self_demote_admin(&group_id).await.err().unwrap();
        match err {
            AppError::Account(marmot_account::AccountError::Session(
                cgka_session::SessionError::Engine(cgka_traits::EngineError::AdminDepletion {
                    ..
                }),
            )) => {}
            other => panic!("expected AdminDepletion, got {other:?}"),
        }
    });
}
#[test]
fn push_registration_removal_retry_survives_clear_and_restart() {
    run_composed_app_runtime_test(
        "push-registration-removal-retry",
        push_registration_removal_retry_body,
    );
}

async fn push_registration_removal_retry_body() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let runtime = MarmotAppRuntime::new(app.clone());
    runtime.reconcile_accounts().await.unwrap();
    runtime
        .create_group("alice", "alpha", &[], None)
        .await
        .unwrap();
    runtime
        .create_group("alice", "beta", &[], None)
        .await
        .unwrap();
    runtime
        .set_native_push_enabled("alice", true)
        .await
        .unwrap();
    let server_pubkey_hex = nostr::Keys::generate().public_key().to_hex();
    let registered = runtime
        .upsert_push_registration(
            "alice",
            PushPlatform::Fcm,
            "retired-token",
            &server_pubkey_hex,
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        registered.share.status,
        PushRegistrationShareStatus::Complete
    );

    relay.script([false, false]);
    let cleared = runtime.clear_push_registration("alice").await.unwrap();
    assert_eq!(cleared.status, PushRegistrationShareStatus::Pending);
    assert_eq!(cleared.attempted_groups, 2);
    assert_eq!(cleared.failed_groups, 2);
    assert_eq!(cleared.pending_groups, 2);
    assert!(app.push_registration("alice").unwrap().is_none());
    assert_eq!(
        app.pending_push_registration_removals("alice")
            .unwrap()
            .len(),
        2
    );

    runtime.shutdown().await;
    drop(runtime);
    drop(app);
    let reopened = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let reopened_runtime = MarmotAppRuntime::new(reopened.clone());
    reopened_runtime.reconcile_accounts().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if reopened
                .pending_push_registration_removals("alice")
                .unwrap()
                .is_empty()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("startup retry should drain the persisted removal intent");
    reopened_runtime.shutdown().await;
}

#[tokio::test]
async fn generated_account_bootstrap_uses_one_batch_and_never_refetches_after_ack() {
    let directory = tempfile::tempdir().unwrap();
    let account = AccountHome::open(directory.path())
        .create_nostr_account_for_setup()
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(directory.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let profile = UserProfileMetadata {
        name: Some("Swift Otter".into()),
        display_name: Some("Swift Otter".into()),
        created_at: 42,
        ..UserProfileMetadata::default()
    };

    let publication = app
        .publish_generated_account_bootstrap(
            &account.label,
            AccountRelayListBootstrap::new(
                vec![TransportEndpoint("wss://relay.example".into())],
                vec![TransportEndpoint("wss://relay.example".into())],
            ),
            &profile,
        )
        .await
        .expect("acknowledged bootstrap must not depend on a relay refetch");
    let status = publication.status;

    assert!(status.complete);
    assert_eq!(
        relay.batch_calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "relay lists, follow list, and profile must share one connection-amortizing batch"
    );
    let mut kinds = relay
        .published_events
        .lock()
        .unwrap()
        .iter()
        .map(|event| event.kind)
        .collect::<Vec<_>>();
    kinds.sort_unstable();
    assert_eq!(
        kinds,
        vec![
            KIND_NOSTR_METADATA,
            KIND_NOSTR_CONTACT_LIST,
            KIND_NIP65_RELAY_LIST,
            KIND_MARMOT_INBOX_RELAY_LIST,
        ]
    );
    assert_eq!(
        app.account_relay_list_status(&account.label).unwrap(),
        status,
        "the acknowledged declaration must be the durable local projection"
    );
}

#[tokio::test]
async fn generated_account_setup_records_distinct_network_ready_phases() {
    let directory = tempfile::tempdir().unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(directory.path(), "wss://relay.example")
        .with_test_relay_client(relay);
    let runtime = MarmotAppRuntime::new(app);

    let created = runtime
        .create_identity(AccountSetupRequest {
            default_relays: vec![TransportEndpoint("wss://relay.example".into())],
            bootstrap_relays: vec![TransportEndpoint("wss://relay.example".into())],
            publish_initial_key_package: true,
            ..AccountSetupRequest::default()
        })
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if runtime
                .account_setup_readiness(&created.account.label)
                .unwrap()
                == AccountSetupReadiness::NetworkReady
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("background setup must reach network readiness");

    let telemetry = runtime
        .shared_services()
        .app_performance_telemetry()
        .snapshot();
    assert_eq!(telemetry.account_worker_readiness.successes, 1);
    assert_eq!(
        telemetry
            .account_bootstrap_relay_and_follow_publish
            .successes,
        1
    );
    assert_eq!(telemetry.account_default_profile_publish.successes, 1);
    assert_eq!(telemetry.account_initial_key_package_publish.successes, 1);
    assert_eq!(telemetry.account_initial_sync_overlap.successes, 1);
    assert_eq!(
        telemetry.account_initial_sync_overlap.duration_ms.sum_ms, 0,
        "the setup-priority publication must finish before initial sync starts"
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn initial_setup_key_package_publishes_before_stalled_initial_sync_finishes() {
    let directory = tempfile::tempdir().unwrap();
    let home = AccountHome::open(directory.path());
    let account = home.create_nostr_account_for_setup().unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(directory.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    app.publish_generated_account_bootstrap(
        &account.label,
        AccountRelayListBootstrap::new(
            vec![TransportEndpoint("wss://relay.example".into())],
            vec![TransportEndpoint("wss://relay.example".into())],
        ),
        &UserProfileMetadata::default(),
    )
    .await
    .unwrap();
    home.set_account_setup_phase(
        &account.label,
        marmot_account::AccountSetupPhase::KeyPackagePublicationStarted,
    )
    .unwrap();
    relay.block_account_inbox_subscribe(hex::decode(&account.account_id_hex).unwrap());
    let runtime = MarmotAppRuntime::new(app);

    runtime.reconcile_accounts().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), relay.wait_for_blocked_subscribe())
        .await
        .expect("initial sync must reach the injected stalled subscription");
    let key_package_published_before_sync = relay
        .published_events
        .lock()
        .unwrap()
        .iter()
        .any(|event| event.kind == KIND_MARMOT_KEY_PACKAGE);
    let setup_finished_before_sync = tokio::time::timeout(
        Duration::from_millis(250),
        runtime.accounts().publish_setup_key_package(&account.label),
    )
    .await
    .expect("setup publication result must bypass stalled initial sync")
    .is_ok();

    relay.release_subscribe();
    runtime.shutdown().await;

    assert!(
        key_package_published_before_sync,
        "the journaled initial KeyPackage must publish before unrelated initial sync completes"
    );
    assert!(
        setup_finished_before_sync,
        "setup must receive the priority publication result without waiting for initial sync"
    );
}

#[tokio::test]
async fn relay_list_zero_ack_does_not_advance_the_local_projection() {
    let directory = tempfile::tempdir().unwrap();
    let account = AccountHome::open(directory.path())
        .create_account("relay-list-zero-ack")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    relay.zero_ack_next_publish();
    let app = MarmotApp::with_relay(directory.path(), "wss://relay.example")
        .with_test_relay_client(relay);

    let error = app
        .publish_account_relay_lists(
            &account.label,
            AccountRelayListBootstrap::new(
                vec![TransportEndpoint("wss://relay.example".into())],
                vec![TransportEndpoint("wss://relay.example".into())],
            ),
        )
        .await
        .expect_err("zero acknowledgements must not confirm relay-list setup");

    assert!(matches!(error, AppError::Publish(_)));
    assert!(
        !app.account_relay_list_status(&account.label)
            .unwrap()
            .complete,
        "local setup state must not advance before every required event reaches a relay"
    );
}

#[tokio::test]
async fn partial_generated_bootstrap_keeps_the_journaled_identity_for_retry() {
    let directory = tempfile::tempdir().unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    // KeyPackage publication now runs concurrently with the bootstrap batch,
    // so select the inbox record by kind instead of depending on global call
    // order across the two independent publication lanes.
    relay.fail_publishes_of_kind(KIND_MARMOT_INBOX_RELAY_LIST);
    let app = MarmotApp::with_relay(directory.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let runtime = MarmotAppRuntime::new(app.clone());
    let request = || AccountSetupRequest {
        default_relays: vec![TransportEndpoint("wss://relay.example".into())],
        bootstrap_relays: vec![TransportEndpoint("wss://relay.example".into())],
        ..AccountSetupRequest::default()
    };

    let local = runtime
        .create_identity_local_ready(request())
        .await
        .expect("relay rejection must not erase durable local readiness");
    let bootstrap_started = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if app
                .account_home()
                .account_setup_state(&local.account.label)
                .unwrap()
                .is_some_and(|state| {
                    state.phase == marmot_account::AccountSetupPhase::BootstrapPublicationStarted
                })
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(
        bootstrap_started.is_ok(),
        "background setup must record bootstrap publication intent; durable state: {:?}",
        app.account_home()
            .account_setup_state(&local.account.label)
            .unwrap()
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
    let account = app
        .account_home()
        .accounts()
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    assert_eq!(
        app.account_home()
            .account_setup_state(&account.label)
            .unwrap()
            .unwrap()
            .phase,
        marmot_account::AccountSetupPhase::BootstrapPublicationStarted,
        "a possibly exposed bootstrap batch must stop destructive rollback"
    );
    assert_eq!(
        runtime
            .account_setup_readiness(&local.account.label)
            .unwrap(),
        AccountSetupReadiness::Publishing
    );

    relay.allow_all_publish_kinds();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if runtime.account_setup_readiness(&account.label).unwrap()
                == AccountSetupReadiness::NetworkReady
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("in-session retry must complete the background setup without a manual create call");
    assert!(
        app.account_home()
            .account_setup_state(&account.label)
            .unwrap()
            .is_none(),
        "successful retry must commit and remove the setup journal"
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn generated_identity_returns_before_bootstrap_publication_unblocks() {
    let directory = tempfile::tempdir().unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    relay.block_next_publish();
    let app = MarmotApp::with_relay(directory.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let runtime = MarmotAppRuntime::new(app.clone());
    let create_runtime = runtime.clone();
    let mut create = tokio::spawn(async move {
        create_runtime
            .create_identity_local_ready(AccountSetupRequest {
                default_relays: vec![TransportEndpoint("wss://relay.example".into())],
                bootstrap_relays: vec![TransportEndpoint("wss://relay.example".into())],
                publish_initial_key_package: true,
                ..AccountSetupRequest::default()
            })
            .await
    });

    relay.wait_for_blocked_publish().await;
    let result = tokio::time::timeout(Duration::from_secs(5), &mut create)
        .await
        .expect("durable local readiness must not wait for bootstrap publication")
        .unwrap()
        .unwrap();

    assert_eq!(
        app.account_home().accounts().unwrap(),
        vec![result.account.clone()]
    );
    assert!(result.profile.is_some());
    assert_eq!(result.readiness, AccountSetupReadiness::LocalReady);
    assert_eq!(
        runtime
            .account_setup_readiness(&result.account.account_id_hex)
            .unwrap(),
        AccountSetupReadiness::Publishing
    );
    let lifecycle = app
        .account_storage(&result.account.label)
        .unwrap()
        .key_package_lifecycle()
        .unwrap()
        .unwrap();
    let pending = lifecycle.pending_replacement.unwrap();
    let signed_bytes = pending.signed_event.unwrap().bytes;

    let repeated = runtime
        .create_identity_local_ready(AccountSetupRequest {
            publish_initial_key_package: true,
            ..AccountSetupRequest::default()
        })
        .await
        .unwrap();
    assert_eq!(repeated.account, result.account);
    assert_eq!(repeated.profile, result.profile);
    assert_eq!(repeated.key_package_bytes, result.key_package_bytes);
    assert_eq!(repeated.readiness, AccountSetupReadiness::Publishing);
    assert_eq!(
        app.account_storage(&repeated.account.label)
            .unwrap()
            .key_package_lifecycle()
            .unwrap()
            .unwrap()
            .pending_replacement
            .unwrap()
            .signed_event
            .unwrap()
            .bytes,
        signed_bytes,
        "repeated create must retain the exact signed KeyPackage publication"
    );

    relay.release_publish();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if runtime
                .account_setup_readiness(&result.account.account_id_hex)
                .unwrap()
                == AccountSetupReadiness::NetworkReady
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("background setup must reach network readiness");
    runtime.shutdown().await;
}

#[tokio::test]
async fn local_ready_result_does_not_report_an_unrequested_key_package_publication() {
    let directory = tempfile::tempdir().unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(directory.path(), "wss://relay.example")
        .with_test_relay_client(relay);
    let runtime = MarmotAppRuntime::new(app.clone());

    let local = runtime
        .create_identity_local_ready(AccountSetupRequest {
            default_relays: vec![TransportEndpoint("wss://relay.example".into())],
            bootstrap_relays: vec![TransportEndpoint("wss://relay.example".into())],
            publish_initial_key_package: false,
            ..AccountSetupRequest::default()
        })
        .await
        .unwrap();

    assert_eq!(local.readiness, AccountSetupReadiness::LocalReady);
    assert_eq!(local.key_package_bytes, None);
    let lifecycle = app
        .account_storage(&local.account.label)
        .unwrap()
        .key_package_lifecycle()
        .unwrap()
        .unwrap();
    assert!(
        lifecycle.pending_replacement.is_some() || lifecycle.current_key_package.is_some(),
        "the prepared KeyPackage remains durable without being reported as published"
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn compatibility_create_identity_waits_for_network_readiness() {
    let directory = tempfile::tempdir().unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    relay.fail_publishes_of_kind(KIND_MARMOT_INBOX_RELAY_LIST);
    let app = MarmotApp::with_relay(directory.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let runtime = MarmotAppRuntime::new(app);
    tokio::time::timeout(
        Duration::from_secs(20),
        runtime.create_identity(AccountSetupRequest {
            default_relays: vec![TransportEndpoint("wss://relay.example".into())],
            bootstrap_relays: vec![TransportEndpoint("wss://relay.example".into())],
            publish_initial_key_package: true,
            ..AccountSetupRequest::default()
        }),
    )
    .await
    .expect("compatibility create must finish its network attempt")
    .expect_err("compatibility create must not report local-only success");
    runtime.shutdown().await;
}

#[tokio::test]
async fn generated_setup_resume_context_failures_do_not_block_runtime_start() {
    for (remove_context, expected_kind) in [
        (true, "setup_context_missing"),
        (false, "setup_context_unreadable"),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        relay.block_next_publish();
        let app = MarmotApp::with_relay(directory.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        let runtime = MarmotAppRuntime::new(app.clone());
        let local = runtime
            .create_identity_local_ready(AccountSetupRequest {
                default_relays: vec![TransportEndpoint("wss://relay.example".into())],
                bootstrap_relays: vec![TransportEndpoint("wss://relay.example".into())],
                publish_initial_key_package: true,
                ..AccountSetupRequest::default()
            })
            .await
            .unwrap();
        relay.wait_for_blocked_publish().await;
        runtime.shutdown().await;
        drop(runtime);
        drop(app);

        let context_path = AccountHome::open(directory.path())
            .account_dir(&local.account.label)
            .join(".account-setup-context.json");
        if remove_context {
            std::fs::remove_file(&context_path).unwrap();
        } else {
            std::fs::write(&context_path, b"not-json").unwrap();
        }

        let restarted_app = MarmotApp::with_relay(directory.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let restarted = MarmotAppRuntime::new(restarted_app);
        let mut events = restarted.subscribe();
        restarted
            .start()
            .await
            .expect("one damaged setup context must not block runtime start");
        let account_error = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if let MarmotAppEvent::AccountError(error) = events.recv().await.unwrap()
                    && error.account_id_hex == local.account.account_id_hex
                {
                    break error;
                }
            }
        })
        .await
        .expect("deferred resume must emit a host-visible account error");
        assert_eq!(
            account_error.message,
            format!("generated account setup resume deferred: {expected_kind}")
        );
        restarted.shutdown().await;
    }
}

#[tokio::test]
async fn generated_identity_restart_resumes_every_durable_setup_phase() {
    for phase in [
        marmot_account::AccountSetupPhase::LocalStateCreated,
        marmot_account::AccountSetupPhase::LocalReady,
        marmot_account::AccountSetupPhase::BootstrapPublicationStarted,
        marmot_account::AccountSetupPhase::BootstrapPublicationConfirmed,
        marmot_account::AccountSetupPhase::KeyPackagePublicationStarted,
        marmot_account::AccountSetupPhase::KeyPackagePublicationConfirmed,
    ] {
        let directory = tempfile::tempdir().unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        relay.block_next_publish();
        let app = MarmotApp::with_relay(directory.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        let runtime = MarmotAppRuntime::new(app.clone());
        let result = runtime
            .create_identity_local_ready(AccountSetupRequest {
                default_relays: vec![TransportEndpoint("wss://relay.example".into())],
                bootstrap_relays: vec![TransportEndpoint("wss://relay.example".into())],
                publish_initial_key_package: true,
                ..AccountSetupRequest::default()
            })
            .await
            .unwrap();
        relay.wait_for_blocked_publish().await;
        let signed_bytes = app
            .account_storage(&result.account.label)
            .unwrap()
            .key_package_lifecycle()
            .unwrap()
            .unwrap()
            .pending_replacement
            .unwrap()
            .signed_event
            .unwrap()
            .bytes;
        if phase == marmot_account::AccountSetupPhase::KeyPackagePublicationConfirmed {
            // This checkpoint is only valid after the exact pending package
            // has been promoted locally. Mirror that atomic durable state;
            // advancing only the setup journal would manufacture a torn state
            // the production path never writes.
            let storage = app.account_storage(&result.account.label).unwrap();
            let mut lifecycle = storage.key_package_lifecycle().unwrap().unwrap();
            let mut replacement = lifecycle.pending_replacement.take().unwrap();
            let artifact = replacement.signed_event.take().unwrap();
            for target in &mut replacement.targets {
                target.state = cgka_traits::TransportFanoutAttemptState::Accepted;
            }
            lifecycle.current_key_package = Some(replacement.key_package);
            lifecycle.current_key_package_ref = Some(replacement.key_package_ref);
            lifecycle.current_not_before = Some(replacement.not_before);
            lifecycle.current_not_after = Some(replacement.not_after);
            lifecycle.authored_event_id = Some(artifact.id.clone());
            lifecycle.authored_event_created_at = Some(artifact.created_at);
            lifecycle.authored_signed_event = Some(artifact);
            lifecycle.publication_targets = replacement.targets;
            lifecycle.refresh_at = Some(replacement.refresh_at);
            lifecycle.upgrade_rotation_recorded = true;
            storage.put_key_package_lifecycle(&lifecycle).unwrap();
        }
        runtime.shutdown().await;
        drop(runtime);
        drop(app);

        let home = AccountHome::open(directory.path());
        home.set_account_setup_phase(&result.account.label, phase)
            .unwrap();
        let restarted_app = MarmotApp::with_relay(directory.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        let restarted = MarmotAppRuntime::new(restarted_app.clone());
        restarted.start().await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if restarted
                    .account_setup_readiness(&result.account.account_id_hex)
                    .unwrap()
                    == AccountSetupReadiness::NetworkReady
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("restart did not resume phase {phase:?}"));
        let lifecycle = restarted_app
            .account_storage(&result.account.label)
            .unwrap()
            .key_package_lifecycle()
            .unwrap()
            .unwrap();
        let resumed_signed_bytes = lifecycle.authored_signed_event.unwrap().bytes;
        if phase == marmot_account::AccountSetupPhase::LocalStateCreated {
            assert!(
                !resumed_signed_bytes.is_empty(),
                "restart before KeyPackage local durability must finish preparing one exact publication"
            );
        } else {
            assert_eq!(
                resumed_signed_bytes, signed_bytes,
                "restart from {phase:?} must retain the exact signed KeyPackage publication"
            );
        }
        assert_eq!(
            restarted_app.account_home().accounts().unwrap(),
            vec![result.account]
        );
        restarted.shutdown().await;
    }
}

#[tokio::test]
async fn concurrent_generated_identity_calls_converge_on_one_local_attempt() {
    let directory = tempfile::tempdir().unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    relay.block_next_publish();
    let app = MarmotApp::with_relay(directory.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let runtime = MarmotAppRuntime::new(app);
    let request = || AccountSetupRequest {
        default_relays: vec![TransportEndpoint("wss://relay.example".into())],
        bootstrap_relays: vec![TransportEndpoint("wss://relay.example".into())],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };

    let (first, second) = tokio::join!(
        runtime.create_identity_local_ready(request()),
        runtime.create_identity_local_ready(request())
    );
    let first = first.unwrap();
    let second = second.unwrap();
    assert_eq!(first.account, second.account);
    assert_eq!(first.profile, second.profile);
    assert_eq!(first.key_package_bytes, second.key_package_bytes);
    assert_eq!(
        AccountHome::open(directory.path()).accounts().unwrap(),
        vec![first.account]
    );

    relay.release_publish();
    runtime.shutdown().await;
}

#[tokio::test]
async fn confirmed_generated_bootstrap_republishes_when_projection_is_missing() {
    let directory = tempfile::tempdir().unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    relay.block_next_publish();
    let app = MarmotApp::with_relay(directory.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let runtime = MarmotAppRuntime::new(app.clone());
    let local = runtime
        .create_identity_local_ready(AccountSetupRequest {
            default_relays: vec![TransportEndpoint("wss://relay.example".into())],
            bootstrap_relays: vec![TransportEndpoint("wss://relay.example".into())],
            ..AccountSetupRequest::default()
        })
        .await
        .unwrap();
    relay.wait_for_blocked_publish().await;
    runtime.shutdown().await;
    drop(runtime);
    drop(app);

    AccountHome::open(directory.path())
        .set_account_setup_phase(
            &local.account.label,
            marmot_account::AccountSetupPhase::BootstrapPublicationConfirmed,
        )
        .unwrap();
    let app = MarmotApp::with_relay(directory.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let runtime = MarmotAppRuntime::new(app);
    let batch_calls_before = relay.batch_calls.load(std::sync::atomic::Ordering::SeqCst);

    let retried = runtime
        .create_identity_local_ready(AccountSetupRequest {
            default_relays: vec![TransportEndpoint("wss://relay.example".into())],
            bootstrap_relays: vec![TransportEndpoint("wss://relay.example".into())],
            ..AccountSetupRequest::default()
        })
        .await
        .expect("a confirmed setup with a lost projection must republish safely");

    assert_eq!(retried.account.account_id_hex, local.account.account_id_hex);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if runtime
                .account_setup_readiness(&retried.account.label)
                .unwrap()
                == AccountSetupReadiness::NetworkReady
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("projection recovery must finish background setup");
    assert_eq!(
        relay.batch_calls.load(std::sync::atomic::Ordering::SeqCst),
        batch_calls_before + 1,
        "projection recovery should issue one idempotent bootstrap batch"
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn key_package_cutover_replacement_intent_survives_cache_retirement_and_restart() {
    let directory = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay(directory.path(), "wss://relay.example");
    let label = "cutover-crash";
    let record_path = app.key_package_record_path(label);
    write_json(
        &record_path,
        &KeyPackageRecord {
            account_label: label.into(),
            account_id_hex: "00".repeat(32),
            key_package_id: "legacy-slot".into(),
            key_package_ref_hex: String::new(),
            key_package_event_id: String::new(),
            published_at: 1,
            key_package_hex: "00".into(),
        },
    )
    .unwrap();

    assert!(
        app.retire_cached_non_current_key_package(label).await,
        "invalid/non-current cache must enter the strict cutover path"
    );
    assert!(!record_path.exists());
    assert!(app.key_package_cutover_replacement_pending(label));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(app.key_package_cutover_replacement_pending_path(label))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "cutover intent must be owner-only");
    }

    drop(app);
    let reopened = MarmotApp::with_relay(directory.path(), "wss://relay.example");
    assert!(
        reopened.key_package_cutover_replacement_pending(label),
        "a crash before current replacement must leave durable retry intent"
    );
    reopened.clear_key_package_cutover_replacement_pending(label);
    assert!(!reopened.key_package_cutover_replacement_pending(label));
}

#[tokio::test]
async fn key_package_deletion_batch_preserves_partial_results_and_cache_ownership() {
    let directory = tempfile::tempdir().unwrap();
    let account = AccountHome::open(directory.path())
        .create_account("delete-batch")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    relay.script([true, false]);
    let app = MarmotApp::with_relay(directory.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let first_event_id = "11".repeat(32);
    let retained_event_id = "22".repeat(32);
    write_json(
        app.key_package_record_path(&account.label),
        &KeyPackageRecord {
            account_label: account.label.clone(),
            account_id_hex: account.account_id_hex,
            key_package_id: "current-slot".into(),
            key_package_ref_hex: "33".repeat(32),
            key_package_event_id: retained_event_id.clone(),
            published_at: 1,
            key_package_hex: "00".into(),
        },
    )
    .unwrap();

    let results = app
        .delete_key_package_events(
            &account.label,
            vec![
                KeyPackageDeletionTarget {
                    event_id_hex: first_event_id,
                    source_relays: vec![
                        TransportEndpoint("wss://relay.example".into()),
                        TransportEndpoint("wss://relay.example".into()),
                    ],
                },
                KeyPackageDeletionTarget {
                    event_id_hex: retained_event_id,
                    source_relays: vec![TransportEndpoint("wss://second.example".into())],
                },
            ],
        )
        .await
        .unwrap();

    assert_eq!(results.len(), 2);
    assert!(results[0].result.is_ok());
    assert!(results[1].result.is_err());
    assert_eq!(
        relay.batch_calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "all deletion events must use one batch publisher"
    );
    assert!(
        app.key_package_record_path(&account.label).exists(),
        "one acknowledged event must not clear another event's retained cache"
    );
}

#[tokio::test]
async fn manual_key_package_deletion_uses_batch_and_requires_ack_before_cache_removal() {
    let directory = tempfile::tempdir().unwrap();
    let account = AccountHome::open(directory.path())
        .create_account("manual-delete")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(directory.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let event_id = "44".repeat(32);
    write_json(
        app.key_package_record_path(&account.label),
        &KeyPackageRecord {
            account_label: account.label.clone(),
            account_id_hex: account.account_id_hex,
            key_package_id: "current-slot".into(),
            key_package_ref_hex: "55".repeat(32),
            key_package_event_id: event_id.clone(),
            published_at: 1,
            key_package_hex: "00".into(),
        },
    )
    .unwrap();

    relay.zero_ack_next_publish();
    let error = app
        .delete_key_package_event(
            &account.label,
            &event_id,
            vec![TransportEndpoint("wss://relay.example".into())],
        )
        .await
        .expect_err("zero acknowledgements must not confirm deletion");
    assert!(matches!(error, AppError::Publish(_)));
    assert!(app.key_package_record_path(&account.label).exists());

    app.delete_key_package_event(
        &account.label,
        &event_id,
        vec![TransportEndpoint("wss://relay.example".into())],
    )
    .await
    .unwrap();
    assert!(!app.key_package_record_path(&account.label).exists());
    assert_eq!(
        relay.batch_calls.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "manual deletion must route through the one-item batch"
    );
}

#[tokio::test]
async fn key_package_deletion_routes_endpoints_through_relay_safety_policy() {
    let directory = tempfile::tempdir().unwrap();
    let account = AccountHome::open(directory.path())
        .create_account("safe-delete")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relays_and_account_home(
        directory.path(),
        vec!["wss://relay.example".into()],
        AccountHome::open(directory.path()),
    )
    .with_test_relay_client(relay.clone());

    let result = app
        .delete_key_package_events(
            &account.label,
            vec![KeyPackageDeletionTarget {
                event_id_hex: "66".repeat(32),
                source_relays: vec![TransportEndpoint("ws://127.0.0.1:7777".into())],
            }],
        )
        .await
        .unwrap()
        .remove(0);
    assert!(result.result.is_err());
    assert_eq!(
        relay.batch_calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "unsafe endpoint must be rejected before publisher invocation"
    );

    let dev_directory = tempfile::tempdir().unwrap();
    let dev_account = AccountHome::open(dev_directory.path())
        .create_account("dev-delete")
        .unwrap();
    let dev_relay = Arc::new(ScriptedPushRelayClient::default());
    let dev_app = MarmotApp::with_relays_and_config(
        dev_directory.path(),
        vec!["ws://127.0.0.1:7777".into()],
        MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true),
    )
    .with_test_relay_client(dev_relay.clone());
    let result = dev_app
        .delete_key_package_events(
            &dev_account.label,
            vec![KeyPackageDeletionTarget {
                event_id_hex: "77".repeat(32),
                source_relays: vec![TransportEndpoint("ws://127.0.0.1:7777".into())],
            }],
        )
        .await
        .unwrap()
        .remove(0);
    assert!(result.result.is_ok());
    assert_eq!(
        dev_relay
            .batch_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
}

#[test]
fn configured_directory_relays_stay_separate_from_operational_relays() {
    let directory = tempfile::tempdir().unwrap();
    let operational = "wss://operational.example";
    let discovery = "wss://directory.example";
    let explicit = TransportEndpoint("wss://explicit.example".into());
    let app = MarmotApp::with_relays_and_config(
        directory.path(),
        vec![operational.into()],
        MarmotAppConfig::default().with_directory_relay_urls(vec![discovery.into()]),
    );

    assert_eq!(
        app.relay_endpoints(),
        vec![TransportEndpoint(operational.into())],
        "directory configuration must not widen operational publication fanout"
    );
    assert_eq!(
        app.directory_source_relays(&[]),
        vec![TransportEndpoint(discovery.into())]
    );
    assert_eq!(
        app.directory_source_relays(std::slice::from_ref(&explicit)),
        vec![explicit],
        "per-operation discovery relays must retain precedence"
    );
}

#[tokio::test]
async fn key_package_cutover_retains_current_cache_without_scheduling_replacement() {
    let directory = tempfile::tempdir().unwrap();
    let home = AccountHome::open(directory.path());
    let account = home.create_account("current-cache").unwrap();
    let app = MarmotApp::with_relay(directory.path(), "wss://relay.example");
    let current = fresh_key_package_for_account(&app, &account, false).await;
    let metadata = cgka_engine::key_package::key_package_metadata(&current).unwrap();
    let record_path = app.key_package_record_path(&account.label);
    write_json(
        &record_path,
        &KeyPackageRecord {
            account_label: account.label.clone(),
            account_id_hex: account.account_id_hex,
            key_package_id: "current-slot".into(),
            key_package_ref_hex: metadata.key_package_ref_hex,
            key_package_event_id: String::new(),
            published_at: 1,
            key_package_hex: hex::encode(current.bytes()),
        },
    )
    .unwrap();

    assert!(
        !app.retire_cached_non_current_key_package(&account.label)
            .await,
        "current cache must not enter the strict cutover replacement path"
    );
    assert!(record_path.exists());
    assert!(!app.key_package_cutover_replacement_pending(&account.label));
}

#[tokio::test]
async fn key_package_cutover_imports_stable_slot_before_cache_retirement() {
    let directory = tempfile::tempdir().unwrap();
    let home = AccountHome::open(directory.path());
    let account = home.create_account("legacy-slot-import").unwrap();
    let app = MarmotApp::with_relay(directory.path(), "wss://relay.example");
    let legacy = fresh_key_package_for_account(&app, &account, true).await;
    let metadata = cgka_engine::key_package::key_package_metadata(&legacy).unwrap();
    write_json(
        app.key_package_record_path(&account.label),
        &KeyPackageRecord {
            account_label: account.label.clone(),
            account_id_hex: account.account_id_hex.clone(),
            key_package_id: "stable-legacy-slot".into(),
            key_package_ref_hex: metadata.key_package_ref_hex,
            key_package_event_id: "11".repeat(32),
            published_at: 1,
            key_package_hex: hex::encode(legacy.bytes()),
        },
    )
    .unwrap();

    app.ensure_strict_cutover_replacement_intent_before_session_open(&account.label)
        .unwrap();

    let lifecycle = app
        .account_storage(&account.label)
        .unwrap()
        .key_package_lifecycle()
        .unwrap()
        .unwrap();
    assert_eq!(lifecycle.stable_slot_id, "stable-legacy-slot");
    assert!(
        app.key_package_cutover_replacement_pending(&account.label),
        "the imported slot and upgrade obligation must both survive cache cleanup"
    );
}

#[tokio::test]
async fn key_package_cutover_repairs_empty_welcome_slot_without_losing_consumed_reference() {
    let directory = tempfile::tempdir().unwrap();
    let home = AccountHome::open(directory.path());
    let account = home.create_account("welcome-before-slot-import").unwrap();
    let app = MarmotApp::with_relay(directory.path(), "wss://relay.example");
    let legacy = fresh_key_package_for_account(&app, &account, true).await;
    let metadata = cgka_engine::key_package::key_package_metadata(&legacy).unwrap();
    let consumed_ref = vec![7, 8, 9];
    let mut lifecycle = cgka_traits::KeyPackageLifecycleState::slot_only(String::new());
    lifecycle.last_consumed_key_package_ref = Some(consumed_ref.clone());
    lifecycle.last_consumed_at = Some(Timestamp(42));
    app.account_storage(&account.label)
        .unwrap()
        .put_key_package_lifecycle(&lifecycle)
        .unwrap();
    write_json(
        app.key_package_record_path(&account.label),
        &KeyPackageRecord {
            account_label: account.label.clone(),
            account_id_hex: account.account_id_hex,
            key_package_id: "recovered-stable-slot".into(),
            key_package_ref_hex: metadata.key_package_ref_hex,
            key_package_event_id: "22".repeat(32),
            published_at: 1,
            key_package_hex: hex::encode(legacy.bytes()),
        },
    )
    .unwrap();

    app.ensure_strict_cutover_replacement_intent_before_session_open(&account.label)
        .unwrap();

    let repaired = app
        .account_storage(&account.label)
        .unwrap()
        .key_package_lifecycle()
        .unwrap()
        .unwrap();
    assert_eq!(repaired.stable_slot_id, "recovered-stable-slot");
    assert_eq!(
        repaired.last_consumed_key_package_ref,
        Some(consumed_ref),
        "slot repair must preserve the Welcome-consumed KeyPackage reference"
    );
    assert_eq!(repaired.last_consumed_at, Some(Timestamp(42)));
}

#[test]
fn fresh_account_persists_its_slot_before_session_open() {
    let directory = tempfile::tempdir().unwrap();
    let home = AccountHome::open(directory.path());
    let account = home.create_account("fresh-slot").unwrap();
    let app = MarmotApp::with_relay(directory.path(), "wss://relay.example");

    app.ensure_strict_cutover_replacement_intent_before_session_open(&account.label)
        .unwrap();

    let lifecycle = app
        .account_storage(&account.label)
        .unwrap()
        .key_package_lifecycle()
        .unwrap()
        .unwrap();
    assert_eq!(lifecycle.stable_slot_id.len(), 64);
    assert!(hex::decode(&lifecycle.stable_slot_id).is_ok());
    assert!(app.key_package_cutover_replacement_pending(&account.label));
}

#[test]
fn existing_account_database_without_slot_evidence_fails_closed() {
    let directory = tempfile::tempdir().unwrap();
    let home = AccountHome::open(directory.path());
    let account = home.create_account("missing-slot-evidence").unwrap();
    let app = MarmotApp::with_relay(directory.path(), "wss://relay.example");

    // Simulate an upgraded device whose encrypted account database predates
    // lifecycle migration, while its JSON cache and private bundles are gone.
    app.account_storage(&account.label).unwrap();

    app.ensure_strict_cutover_replacement_intent_before_session_open(&account.label)
        .unwrap();
    assert!(
        app.legacy_incomplete_setup_requires_recovery(&account.label)
            .unwrap()
    );

    assert!(
        app.account_storage(&account.label)
            .unwrap()
            .key_package_lifecycle()
            .unwrap()
            .is_none(),
        "an existing database must not mint a second stable slot without migration evidence"
    );
    assert!(app.key_package_cutover_replacement_pending(&account.label));
}

#[test]
fn durable_incomplete_setup_can_provision_slot_after_database_creation() {
    let directory = tempfile::tempdir().unwrap();
    let home = AccountHome::open(directory.path());
    let account = home.create_account("journaled-fresh-setup").unwrap();
    home.begin_account_setup(&account, false).unwrap();
    let app = MarmotApp::with_relay(directory.path(), "wss://relay.example");

    // Reproduce the critical ordering: an advisory/local operation creates the
    // encrypted DB before strict KeyPackage initialization runs.
    app.account_storage(&account.label).unwrap();
    app.ensure_strict_cutover_replacement_intent_before_session_open(&account.label)
        .unwrap();

    let lifecycle = app
        .account_storage(&account.label)
        .unwrap()
        .key_package_lifecycle()
        .unwrap()
        .unwrap();
    assert_eq!(lifecycle.stable_slot_id.len(), 64);
}

#[tokio::test]
async fn legacy_ambiguous_setup_requires_consent_before_reset() {
    let directory = tempfile::tempdir().unwrap();
    let home = AccountHome::open(directory.path());
    let keys = nostr::Keys::generate();
    let secret = keys.secret_key().to_secret_hex();
    let account = home.import_nostr_account(&secret).unwrap();
    let app = MarmotApp::with_relay(directory.path(), "wss://relay.example");

    app.account_storage(&account.label).unwrap();
    app.ensure_strict_cutover_replacement_intent_before_session_open(&account.label)
        .unwrap();
    assert!(
        app.legacy_incomplete_setup_requires_recovery(&account.label)
            .unwrap()
    );
    assert!(app.key_package_cutover_replacement_pending(&account.label));

    let runtime = MarmotAppRuntime::new(app.clone());
    assert_eq!(
        runtime.account_setup_readiness(&account.label).unwrap(),
        AccountSetupReadiness::RecoveryRequired
    );
    let retry_error = runtime
        .create_or_import_account(AccountSetupRequest {
            import_nsec: Some(zeroize::Zeroizing::new(secret.clone())),
            ..AccountSetupRequest::default()
        })
        .await
        .expect_err("ordinary same-nsec retry must identify the legacy recovery state");
    assert!(matches!(
        retry_error,
        AppError::AccountSetupRecoveryRequired
    ));
    assert!(matches!(
        runtime.reset_incomplete_account_setup(&secret, false).await,
        Err(AppError::AccountSetupRecoveryRequired)
    ));
    runtime
        .reset_incomplete_account_setup(&secret, true)
        .await
        .unwrap();
    assert!(matches!(
        home.account(&account.label),
        Err(AccountHomeError::UnknownAccount(_))
    ));
    assert!(!app.key_package_cutover_replacement_pending(&account.label));

    let retried = home.import_nostr_account_idempotent(&secret).unwrap();
    assert_eq!(retried.account().account_id_hex, account.account_id_hex);
    runtime.shutdown().await;
}

#[tokio::test]
async fn unpublished_legacy_session_bundle_schedules_replacement_before_open() {
    let directory = tempfile::tempdir().unwrap();
    let home = AccountHome::open(directory.path());
    let account = home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(directory.path(), "wss://relay.example");
    app.ensure_account_state(&account.label).unwrap();

    let summary = app.account_home().account(&account.label).unwrap();
    let signer = app.account_signer_for_summary(&summary).unwrap();
    let session_path = app.account_dir(&account.label).join(SESSION_DB_FILE);
    let keys = app
        .account_home()
        .load_signing_keys(&account.label)
        .unwrap();
    let session_key = app
        .sqlcipher_key(
            &account.label,
            &keys,
            &session_path,
            SqlcipherDatabaseKind::Session,
        )
        .unwrap();
    let account_id = MemberId::new(hex::decode(&account.account_id_hex).unwrap());
    let nostr_signer = signer.as_nostr_signer();
    let mut legacy_session = AccountDeviceSession::open(
        SessionConfig::new(
            &session_path,
            session_key,
            account_id.as_slice().to_vec(),
            Box::new(NostrMlsPeeler::new().with_welcome_signer(nostr_signer)),
        )
        .legacy_compatibility_profile()
        .account_identity_proof_signer(signer.as_proof_signer())
        .feature_registry(app_feature_registry()),
    )
    .unwrap();
    legacy_session.fresh_key_package().await.unwrap();
    drop(legacy_session);

    assert!(!app.key_package_record_path(&account.label).exists());

    let relay_plane = MarmotRelayPlane::with_subscription_rebuild_lookback(Duration::from_secs(30));
    app.open_account(&account.label, &relay_plane, false)
        .unwrap();
    assert!(app.key_package_cutover_replacement_pending(&account.label));
    assert!(
        app.reusable_key_package_slot_id(&account.label, &account.account_id_hex)
            .is_err(),
        "an existing account without recoverable slot metadata must fail closed"
    );

    drop(app);
    let reopened = MarmotApp::with_relay(directory.path(), "wss://relay.example");
    assert!(
        reopened.key_package_cutover_replacement_pending(&account.label),
        "replacement intent must survive restart after session retirement"
    );
}

async fn fresh_key_package_for_account(
    app: &MarmotApp,
    account: &AccountSummary,
    legacy: bool,
) -> KeyPackage {
    let signer = app.account_signer_for_summary(account).unwrap();
    let session_path = tempfile::NamedTempFile::new().unwrap().into_temp_path();
    let keys = app
        .account_home()
        .load_signing_keys(&account.label)
        .unwrap();
    let session_key = app
        .sqlcipher_key(
            &account.label,
            &keys,
            session_path.as_ref(),
            SqlcipherDatabaseKind::Session,
        )
        .unwrap();
    let account_id = MemberId::new(hex::decode(&account.account_id_hex).unwrap());
    let mut config = SessionConfig::new(
        session_path.to_path_buf(),
        session_key,
        account_id.as_slice().to_vec(),
        Box::new(NostrMlsPeeler::new().with_welcome_signer(signer.as_nostr_signer())),
    )
    .account_identity_proof_signer(signer.as_proof_signer())
    .feature_registry(app_feature_registry())
    .supported_app_components(app.supported_app_component_ids());
    if legacy {
        config = config.legacy_compatibility_profile();
    }
    let mut session = AccountDeviceSession::open(config).unwrap();
    session.fresh_key_package().await.unwrap()
}

#[tokio::test]
async fn member_key_package_skips_local_legacy_cache() {
    let directory = tempfile::tempdir().unwrap();
    let home = AccountHome::open(directory.path());
    let account = home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(directory.path(), "wss://relay.example");
    let legacy = fresh_key_package_for_account(&app, &account, true).await;
    write_json(
        app.key_package_record_path(&account.label),
        &KeyPackageRecord {
            account_label: account.label.clone(),
            account_id_hex: account.account_id_hex.clone(),
            key_package_id: "legacy-local".into(),
            key_package_ref_hex: String::new(),
            key_package_event_id: String::new(),
            published_at: 1,
            key_package_hex: hex::encode(legacy.bytes()),
        },
    )
    .unwrap();

    let result = app.member_key_package(&account.label).await;
    assert!(
        matches!(
            result,
            Err(AppError::MissingKeyPackage(_) | AppError::MissingRelayLists(_))
        ),
        "legacy local cache must not be selected for invites; fallback must fail closed"
    );
}

#[tokio::test]
async fn member_key_package_falls_back_to_current_directory_for_local_account() {
    let directory = tempfile::tempdir().unwrap();
    let home = AccountHome::open(directory.path());
    let account = home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(directory.path(), "wss://relay.example");
    let legacy = fresh_key_package_for_account(&app, &account, true).await;
    let current = fresh_key_package_for_account(&app, &account, false).await;
    let metadata = cgka_engine::key_package::key_package_metadata(&current).unwrap();
    write_json(
        app.key_package_record_path(&account.label),
        &KeyPackageRecord {
            account_label: account.label.clone(),
            account_id_hex: account.account_id_hex.clone(),
            key_package_id: "legacy-local".into(),
            key_package_ref_hex: String::new(),
            key_package_event_id: String::new(),
            published_at: 1,
            key_package_hex: hex::encode(legacy.bytes()),
        },
    )
    .unwrap();
    app.save_directory_entry(&UserDirectoryRecord {
        account_id_hex: account.account_id_hex.clone(),
        npub: npub_for_account_id_lossy(&account.account_id_hex),
        local_account: Some(UserDirectoryLocalAccount {
            label: account.label.clone(),
            local_signing: true,
        }),
        profile: None,
        follows: Vec::new(),
        follow_source_relays: Vec::new(),
        relay_lists: AccountRelayListStatus::empty(),
        key_package: Some(DirectoryKeyPackage {
            key_package_id: "current-directory".into(),
            key_package_ref_hex: metadata.key_package_ref_hex.clone(),
            key_package_event_id: String::new(),
            key_package_hex: hex::encode(current.bytes()),
            created_at: 2,
            source_relays: Vec::new(),
        }),
    })
    .unwrap();

    let selected = app.member_key_package(&account.label).await.unwrap();
    let selected_metadata = cgka_engine::key_package::key_package_metadata(&selected).unwrap();
    assert_eq!(
        selected_metadata.protocol_profile,
        cgka_traits::group::ProtocolProfile::Current
    );
    assert_eq!(
        selected_metadata.key_package_ref_hex,
        metadata.key_package_ref_hex
    );
}

#[tokio::test]
async fn member_key_package_set_canonicalizes_and_deduplicates_in_input_order() {
    let directory = tempfile::tempdir().unwrap();
    let home = AccountHome::open(directory.path());
    let bob = home.create_account("bob").unwrap();
    let carol = home.create_account("carol").unwrap();
    let app = MarmotApp::with_relay(directory.path(), "wss://relay.example");

    for account in [&bob, &carol] {
        let current = fresh_key_package_for_account(&app, account, false).await;
        let metadata = cgka_engine::key_package::key_package_metadata(&current).unwrap();
        app.save_directory_entry(&UserDirectoryRecord {
            account_id_hex: account.account_id_hex.clone(),
            npub: npub_for_account_id_lossy(&account.account_id_hex),
            local_account: Some(UserDirectoryLocalAccount {
                label: account.label.clone(),
                local_signing: true,
            }),
            profile: None,
            follows: Vec::new(),
            follow_source_relays: Vec::new(),
            relay_lists: AccountRelayListStatus::empty(),
            key_package: Some(DirectoryKeyPackage {
                key_package_id: format!("{}-slot", account.label),
                key_package_ref_hex: metadata.key_package_ref_hex,
                key_package_event_id: String::new(),
                key_package_hex: hex::encode(current.bytes()),
                created_at: 1,
                source_relays: Vec::new(),
            }),
        })
        .unwrap();
    }

    let bob_npub = npub_for_account_id_lossy(&bob.account_id_hex);
    let resolved = app
        .resolve_member_key_packages(&[
            bob.label.as_str(),
            bob_npub.as_str(),
            carol.account_id_hex.as_str(),
        ])
        .await
        .unwrap();

    assert_eq!(resolved.len(), 2, "duplicate account ids must resolve once");
    let identities = resolved
        .iter()
        .map(|key_package| {
            cgka_engine::key_package::key_package_metadata(key_package)
                .unwrap()
                .credential_identity_hex
        })
        .collect::<Vec<_>>();
    assert_eq!(identities, vec![bob.account_id_hex, carol.account_id_hex]);
}

fn member_resolution_key_package_event(
    account: &AccountSummary,
    key_package: KeyPackage,
) -> NostrTransportEvent {
    let metadata = cgka_engine::key_package::key_package_metadata(&key_package).unwrap();
    transport_nostr_adapter::NostrKeyPackagePublication {
        account_id: MemberId::new(hex::decode(&account.account_id_hex).unwrap()),
        key_package,
        key_package_slot_id: format!("{}-slot", account.label),
        key_package_ref: metadata.key_package_ref_hex,
        mls_ciphersuite: format!("0x{:04x}", metadata.ciphersuite),
        mls_extensions: metadata
            .mls_extensions
            .iter()
            .map(|id| format!("0x{id:04x}"))
            .collect(),
        mls_proposals: metadata
            .mls_proposals
            .iter()
            .map(|id| format!("0x{id:04x}"))
            .collect(),
        app_components: metadata
            .app_components
            .iter()
            .filter(|id| **id >= cgka_traits::app_components::PRIVATE_USE_APP_COMPONENT_ID_START)
            .map(|id| format!("0x{id:04x}"))
            .collect(),
        publish_endpoints: vec![TransportEndpoint("wss://shared.example".into())],
    }
    .to_event()
    .unwrap()
}

async fn member_resolution_fixture(
    count: usize,
    split_relays: bool,
) -> (
    tempfile::TempDir,
    MarmotApp,
    Vec<AccountSummary>,
    Arc<MemberResolutionDirectoryFetcher>,
) {
    let directory = tempfile::tempdir().unwrap();
    let home = AccountHome::open(directory.path());
    let accounts = (0..count)
        .map(|index| home.create_account(&format!("member-{index}")).unwrap())
        .collect::<Vec<_>>();
    let fetcher = Arc::new(MemberResolutionDirectoryFetcher::default());
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let mut app = MarmotApp::with_relay(directory.path(), "wss://directory.example")
        .with_test_relay_client(relay.clone());
    for (index, account) in accounts.iter().enumerate() {
        let key_package = fresh_key_package_for_account(&app, account, false).await;
        fetcher
            .events
            .lock()
            .unwrap()
            .push(member_resolution_key_package_event(account, key_package));
        let relay = if split_relays && index % 2 == 1 {
            "wss://split-b.example"
        } else if split_relays {
            "wss://split-a.example"
        } else {
            "wss://shared.example"
        };
        fetcher
            .events
            .lock()
            .unwrap()
            .push(NostrTransportEvent::new_unsigned(
                account.account_id_hex.clone(),
                KIND_NIP65_RELAY_LIST,
                vec![vec!["r".into(), relay.into()]],
                String::new(),
            ));
    }
    app.relay_plane = MarmotRelayPlane::new_with_directory_fetcher_for_test(relay, fetcher.clone());
    (directory, app, accounts, fetcher)
}

#[tokio::test]
async fn member_key_package_set_batches_shared_relay_and_reuses_prewarm() {
    let (_directory, app, accounts, fetcher) = member_resolution_fixture(8, false).await;
    let members = accounts
        .iter()
        .map(|account| account.account_id_hex.as_str())
        .collect::<Vec<_>>();

    let summary = app
        .prewarm_group_member_key_packages(&members)
        .await
        .unwrap();
    assert_eq!(summary.requested_members, 8);
    assert_eq!(summary.unique_members, 8);
    assert_eq!(summary.reused_members, 0);
    assert_eq!(summary.network_resolved_members, 8);

    let requests = fetcher.requests.lock().unwrap().clone();
    assert_eq!(
        requests.len(),
        2,
        "cold shared relays must use one relay-list batch and one KeyPackage batch"
    );
    assert_eq!(requests[0].queries.len(), 2);
    assert!(
        requests[0]
            .queries
            .iter()
            .all(|query| query.authors.len() == 8)
    );
    assert_eq!(requests[1].queries.len(), 1);
    assert_eq!(requests[1].queries[0].kind, KIND_MARMOT_KEY_PACKAGE);
    assert_eq!(requests[1].queries[0].authors.len(), 8);
    assert_eq!(requests[1].queries[0].limit, 8 * 12);
    drop(requests);

    for account in &accounts {
        assert!(
            app.directory_entry_for_account_id(&account.account_id_hex)
                .unwrap()
                .and_then(|entry| entry.key_package)
                .is_none(),
            "composition prewarm must not durably admit a KeyPackage"
        );
    }

    let resolved = app.resolve_member_key_packages(&members).await.unwrap();
    assert_eq!(resolved.len(), 8);
    assert_eq!(
        fetcher.requests.lock().unwrap().len(),
        2,
        "fresh prewarm entries must eliminate create-time relay requests"
    );
}

#[tokio::test]
async fn member_key_package_set_falls_back_when_multi_author_queries_are_rejected() {
    let (_directory, app, accounts, fetcher) = member_resolution_fixture(2, false).await;
    fetcher
        .reject_multi_author
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let members = accounts
        .iter()
        .map(|account| account.account_id_hex.as_str())
        .collect::<Vec<_>>();

    let summary = app
        .prewarm_group_member_key_packages(&members)
        .await
        .unwrap();

    assert_eq!(summary.network_resolved_members, 2);
    let requests = fetcher.requests.lock().unwrap();
    assert!(
        requests
            .iter()
            .any(|request| request.queries.iter().any(|query| query.authors.len() == 2))
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.queries.iter().all(|query| query.authors.len() == 1))
            .count(),
        4,
        "relay-list and KeyPackage batches must each fall back per member"
    );
}

#[tokio::test]
async fn relay_list_fallback_failure_preserves_valid_siblings_and_input_order() {
    let (_directory, app, accounts, fetcher) = member_resolution_fixture(3, false).await;
    fetcher
        .reject_multi_author
        .store(true, std::sync::atomic::Ordering::SeqCst);
    *fetcher.failing_single_author.lock().unwrap() = Some(accounts[2].account_id_hex.clone());
    fetcher.events.lock().unwrap().retain(|event| {
        event.kind != KIND_MARMOT_KEY_PACKAGE || event.pubkey != accounts[0].account_id_hex
    });
    let members = [
        accounts[0].account_id_hex.as_str(),
        accounts[1].account_id_hex.as_str(),
        accounts[2].account_id_hex.as_str(),
    ];

    let error = app
        .prewarm_group_member_key_packages(&members)
        .await
        .expect_err("the first member is missing and the third relay-list fallback fails");
    assert!(
        matches!(error, AppError::MissingKeyPackage(account_id) if account_id == accounts[0].account_id_hex),
        "the first canonical member error must win over a later relay-list failure"
    );
    let requests_after_partial = fetcher.requests.lock().unwrap().len();

    let summary = app
        .prewarm_group_member_key_packages(&[accounts[1].account_id_hex.as_str()])
        .await
        .expect("the valid sibling should remain reusable after the partial failure");
    assert_eq!(summary.reused_members, 1);
    assert_eq!(summary.network_resolved_members, 0);
    assert_eq!(
        fetcher.requests.lock().unwrap().len(),
        requests_after_partial,
        "reusing the valid sibling must not issue another relay request"
    );
}

#[tokio::test]
async fn member_key_package_set_reports_missing_packages_in_input_order() {
    let (_directory, app, accounts, fetcher) = member_resolution_fixture(2, false).await;
    fetcher
        .events
        .lock()
        .unwrap()
        .retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
    let members = [
        accounts[1].account_id_hex.as_str(),
        accounts[0].account_id_hex.as_str(),
    ];

    let error = app
        .prewarm_group_member_key_packages(&members)
        .await
        .expect_err("both packages are absent");

    assert!(
        matches!(error, AppError::MissingKeyPackage(account_id) if account_id == accounts[1].account_id_hex),
        "the first canonical input error must win regardless of batch completion order"
    );
}

#[tokio::test]
async fn malformed_batch_member_does_not_discard_valid_member_prewarm() {
    let (_directory, app, accounts, fetcher) = member_resolution_fixture(2, false).await;
    let malformed_account = accounts[1].account_id_hex.clone();
    let valid_account = accounts[0].account_id_hex.clone();
    {
        let mut events = fetcher.events.lock().unwrap();
        let malformed = events
            .iter_mut()
            .find(|event| {
                event.kind == KIND_MARMOT_KEY_PACKAGE && event.pubkey == malformed_account
            })
            .expect("malformed account KeyPackage event");
        malformed.content = "not-base64".to_owned();
    }

    let error = app
        .prewarm_group_member_key_packages(&[malformed_account.as_str(), valid_account.as_str()])
        .await
        .expect_err("the malformed member must fail");
    assert!(matches!(error, AppError::InvalidKeyPackageEvent(_)));
    let requests_after_partial = fetcher.requests.lock().unwrap().len();

    let summary = app
        .prewarm_group_member_key_packages(&[valid_account.as_str()])
        .await
        .expect("the valid member from the partial batch remains safely reusable");
    assert_eq!(summary.reused_members, 1);
    assert_eq!(summary.network_resolved_members, 0);
    assert_eq!(
        fetcher.requests.lock().unwrap().len(),
        requests_after_partial,
        "reusing the valid partial result must not issue another relay request"
    );
}

#[tokio::test]
async fn member_key_package_resolution_ignores_older_malformed_publication() {
    let (_directory, app, accounts, fetcher) = member_resolution_fixture(1, false).await;
    let account_id = accounts[0].account_id_hex.clone();
    {
        let mut events = fetcher.events.lock().unwrap();
        let current = events
            .iter()
            .find(|event| event.kind == KIND_MARMOT_KEY_PACKAGE)
            .expect("current KeyPackage event")
            .clone();
        let mut older_malformed = current.clone();
        older_malformed.created_at = current.created_at.saturating_sub(1);
        older_malformed.id = "00".repeat(32);
        older_malformed.content = "not-base64".to_owned();
        events.push(older_malformed);
    }

    let summary = app
        .prewarm_group_member_key_packages(&[account_id.as_str()])
        .await
        .expect("the newest valid KeyPackage must win over an older malformed publication");

    assert_eq!(summary.unique_members, 1);
    assert_eq!(summary.network_resolved_members, 1);
}

#[tokio::test]
async fn member_key_package_resolution_falls_back_from_newest_malformed_publication() {
    let (_directory, app, accounts, fetcher) = member_resolution_fixture(1, false).await;
    let account_id = accounts[0].account_id_hex.clone();
    {
        let mut events = fetcher.events.lock().unwrap();
        let current = events
            .iter()
            .find(|event| event.kind == KIND_MARMOT_KEY_PACKAGE)
            .expect("current KeyPackage event")
            .clone();
        let mut newer_malformed = current.clone();
        newer_malformed.created_at = current.created_at.saturating_add(1);
        newer_malformed.id = "ff".repeat(32);
        newer_malformed.content = "not-base64".to_owned();
        events.push(newer_malformed);
    }

    let summary = app
        .prewarm_group_member_key_packages(&[account_id.as_str()])
        .await
        .expect("an invalid newest publication must not hide an older valid KeyPackage");

    assert_eq!(summary.unique_members, 1);
    assert_eq!(summary.network_resolved_members, 1);
}

#[tokio::test]
async fn cancelled_member_prewarm_does_not_admit_or_reserve_results() {
    let (_directory, app, accounts, fetcher) = member_resolution_fixture(1, false).await;
    *fetcher.stalled_endpoint.lock().unwrap() = Some("wss://directory.example".to_owned());
    let member = accounts[0].account_id_hex.clone();
    let task_app = app.clone();
    let task_member = member.clone();
    let task = tokio::spawn(async move {
        task_app
            .prewarm_group_member_key_packages(&[task_member.as_str()])
            .await
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while fetcher.requests.lock().unwrap().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("prewarm should start its directory request");
    task.abort();
    let _ = task.await;
    tokio::time::sleep(Duration::from_millis(150)).await;

    assert!(
        app.directory_entry_for_account_id(&member)
            .unwrap()
            .and_then(|entry| entry.key_package)
            .is_none(),
        "cancelled composition work must not durably admit a package"
    );
    *fetcher.stalled_endpoint.lock().unwrap() = None;
    let requests_before_retry = fetcher.requests.lock().unwrap().len();
    let summary = app
        .prewarm_group_member_key_packages(&[member.as_str()])
        .await
        .unwrap();
    assert_eq!(summary.network_resolved_members, 1);
    assert!(fetcher.requests.lock().unwrap().len() > requests_before_retry);
}

#[tokio::test]
#[ignore = "member-resolution scaling benchmark; reports request count and wall clock"]
async fn member_key_package_resolution_scaling_report() {
    let mut report = vec!["invitees,scenario,requests,wall_ms,outcome".to_owned()];
    for count in [1, 8, 32] {
        let (_directory, app, accounts, fetcher) = member_resolution_fixture(count, false).await;
        let members = accounts
            .iter()
            .map(|account| account.account_id_hex.as_str())
            .collect::<Vec<_>>();
        app.prewarm_group_member_key_packages(&members)
            .await
            .unwrap();
        fetcher.requests.lock().unwrap().clear();
        let started = Instant::now();
        let outcome = app.resolve_member_key_packages(&members).await;
        report.push(format!(
            "{count},warm_cache,{},{},{}",
            fetcher.requests.lock().unwrap().len(),
            started.elapsed().as_millis(),
            if outcome.is_ok() { "ok" } else { "error" }
        ));

        let (_directory, app, accounts, fetcher) = member_resolution_fixture(count, false).await;
        let members = accounts
            .iter()
            .map(|account| account.account_id_hex.as_str())
            .collect::<Vec<_>>();
        let started = Instant::now();
        let outcome = app.prewarm_group_member_key_packages(&members).await;
        report.push(format!(
            "{count},shared_relays,{},{},{}",
            fetcher.requests.lock().unwrap().len(),
            started.elapsed().as_millis(),
            if outcome.is_ok() { "ok" } else { "error" }
        ));

        let (_directory, app, accounts, fetcher) = member_resolution_fixture(count, true).await;
        let members = accounts
            .iter()
            .map(|account| account.account_id_hex.as_str())
            .collect::<Vec<_>>();
        let started = Instant::now();
        let outcome = app.prewarm_group_member_key_packages(&members).await;
        report.push(format!(
            "{count},split_relays,{},{},{}",
            fetcher.requests.lock().unwrap().len(),
            started.elapsed().as_millis(),
            if outcome.is_ok() { "ok" } else { "error" }
        ));

        let (_directory, app, accounts, fetcher) = member_resolution_fixture(count, true).await;
        *fetcher.stalled_endpoint.lock().unwrap() = Some(
            if count == 1 {
                "wss://split-a.example"
            } else {
                "wss://split-b.example"
            }
            .to_owned(),
        );
        let members = accounts
            .iter()
            .map(|account| account.account_id_hex.as_str())
            .collect::<Vec<_>>();
        let started = Instant::now();
        let outcome = app.prewarm_group_member_key_packages(&members).await;
        report.push(format!(
            "{count},one_stalled_relay,{},{},{}",
            fetcher.requests.lock().unwrap().len(),
            started.elapsed().as_millis(),
            if outcome.is_ok() { "ok" } else { "error" }
        ));

        let (_directory, app, accounts, fetcher) = member_resolution_fixture(count, false).await;
        let missing = accounts.last().unwrap().account_id_hex.clone();
        fetcher
            .events
            .lock()
            .unwrap()
            .retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE || event.pubkey != missing);
        let members = accounts
            .iter()
            .map(|account| account.account_id_hex.as_str())
            .collect::<Vec<_>>();
        let started = Instant::now();
        let outcome = app.prewarm_group_member_key_packages(&members).await;
        report.push(format!(
            "{count},missing_package,{},{},{}",
            fetcher.requests.lock().unwrap().len(),
            started.elapsed().as_millis(),
            if outcome.is_ok() { "ok" } else { "error" }
        ));
    }
    tracing::info!(
        target: "marmot_app::member_key_packages",
        method = "member_key_package_resolution_scaling_report",
        report = %report.join("\n"),
        "member KeyPackage resolution scaling report"
    );
}

#[test]
fn nip65_relay_list_targets_only_include_write_capable_entries() {
    let event = NostrTransportEvent::new_unsigned(
        "11".repeat(32),
        KIND_NIP65_RELAY_LIST,
        vec![
            vec!["r".into(), "wss://both.example".into()],
            vec!["r".into(), "wss://read-only.example".into(), "read".into()],
            vec![
                "r".into(),
                "wss://write-only.example".into(),
                "write".into(),
            ],
            vec!["r".into(), "wss://unknown.example".into(), "future".into()],
            vec!["r".into(), "wss://both.example".into()],
        ],
        String::new(),
    );

    assert_eq!(
        relays_from_relay_list_event(&event),
        vec![
            "wss://both.example".to_owned(),
            "wss://write-only.example".to_owned(),
        ]
    );
}

#[test]
fn relay_list_declaration_validation_does_not_apply_the_dial_route_cap() {
    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let declared = (0..17)
        .map(|index| TransportEndpoint(format!("wss://relay-{index}.example")))
        .collect::<Vec<_>>();

    app.validate_account_relay_list_declarations(
        &AccountRelayListBootstrap::new(declared, Vec::new()),
        None,
    )
    .expect("published list size must not inherit the dial route's endpoint cap");
}

#[test]
fn newer_all_read_nip65_list_clears_stale_write_targets() {
    let account_id = "11".repeat(32);
    let mut older = NostrTransportEvent::new_unsigned(
        account_id.clone(),
        KIND_NIP65_RELAY_LIST,
        vec![vec!["r".into(), "wss://stale-write.example".into()]],
        String::new(),
    );
    older.created_at = 1;
    older.id = "00".repeat(32);
    let mut newer = NostrTransportEvent::new_unsigned(
        account_id.clone(),
        KIND_NIP65_RELAY_LIST,
        vec![vec![
            "r".into(),
            "wss://read-only.example".into(),
            "read".into(),
        ]],
        String::new(),
    );
    newer.created_at = 2;
    newer.id = "11".repeat(32);

    let status = relay_list_status_from_records(
        &account_id,
        vec![
            crate::relay_plane::DirectoryRelayEventRecord {
                endpoints: vec![TransportEndpoint("wss://source.example".into())],
                event: newer,
            },
            crate::relay_plane::DirectoryRelayEventRecord {
                endpoints: vec![TransportEndpoint("wss://source.example".into())],
                event: older,
            },
        ],
    );

    assert!(status.nip65.relays.is_empty());
    assert!(status.nip65.write_relays.is_empty());
    assert_eq!(status.nip65.read_relays, vec!["wss://read-only.example"]);
    assert_eq!(
        status.missing,
        vec![MissingRelayListKind::Nip65, MissingRelayListKind::Inbox]
    );
}

#[test]
fn ingesting_all_read_nip65_list_replaces_cached_write_targets() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let account_id = "22".repeat(32);
    let record = |tags| crate::relay_plane::DirectoryRelayEventRecord {
        endpoints: vec![TransportEndpoint("wss://source.example".into())],
        event: NostrTransportEvent::new_unsigned(
            account_id.clone(),
            KIND_NIP65_RELAY_LIST,
            tags,
            String::new(),
        ),
    };

    app.ingest_directory_relay_event(record(vec![vec![
        "r".into(),
        "wss://stale-write.example".into(),
    ]]))
    .unwrap();
    app.ingest_directory_relay_event(record(vec![vec![
        "r".into(),
        "wss://read-only.example".into(),
        "read".into(),
    ]]))
    .unwrap();

    let cached = app
        .directory_entry_for_account_id(&account_id)
        .unwrap()
        .expect("cached relay list");
    assert!(cached.relay_lists.nip65.relays.is_empty());
    assert!(cached.relay_lists.nip65.write_relays.is_empty());
    assert_eq!(
        cached.relay_lists.nip65.read_relays,
        vec!["wss://read-only.example"]
    );
}

#[test]
fn nip65_setter_round_trip_preserves_existing_roles() {
    let current = AccountRelayListState {
        kind: KIND_NIP65_RELAY_LIST,
        relays: vec!["wss://both.example".into(), "wss://write.example".into()],
        read_relays: vec!["wss://both.example".into(), "wss://read.example".into()],
        write_relays: vec!["wss://both.example".into(), "wss://write.example".into()],
    };
    let requested = vec![
        TransportEndpoint("wss://both.example".into()),
        TransportEndpoint("wss://read.example".into()),
        TransportEndpoint("wss://write.example".into()),
        TransportEndpoint("wss://new.example".into()),
    ];

    let next = nip65_relay_set_preserving_roles(&current, requested);

    assert_eq!(
        next.read_relays,
        vec![
            TransportEndpoint("wss://both.example".into()),
            TransportEndpoint("wss://read.example".into()),
            TransportEndpoint("wss://new.example".into()),
        ]
    );
    assert_eq!(
        next.write_relays,
        vec![
            TransportEndpoint("wss://both.example".into()),
            TransportEndpoint("wss://write.example".into()),
            TransportEndpoint("wss://new.example".into()),
        ]
    );
}

#[derive(Clone, Debug)]
struct TestExternalAccountSigner {
    keys: nostr::Keys,
}

impl nostr::NostrSigner for TestExternalAccountSigner {
    fn backend(&self) -> nostr::signer::SignerBackend<'_> {
        self.keys.backend()
    }

    fn get_public_key(
        &self,
    ) -> nostr::util::BoxedFuture<'_, Result<nostr::PublicKey, nostr::SignerError>> {
        self.keys.get_public_key()
    }

    fn sign_event(
        &self,
        unsigned: nostr::UnsignedEvent,
    ) -> nostr::util::BoxedFuture<'_, Result<nostr::Event, nostr::SignerError>> {
        self.keys.sign_event(unsigned)
    }

    fn nip04_encrypt<'a>(
        &'a self,
        public_key: &'a nostr::PublicKey,
        content: &'a str,
    ) -> nostr::util::BoxedFuture<'a, Result<String, nostr::SignerError>> {
        self.keys.nip04_encrypt(public_key, content)
    }

    fn nip04_decrypt<'a>(
        &'a self,
        public_key: &'a nostr::PublicKey,
        encrypted_content: &'a str,
    ) -> nostr::util::BoxedFuture<'a, Result<String, nostr::SignerError>> {
        self.keys.nip04_decrypt(public_key, encrypted_content)
    }

    fn nip44_encrypt<'a>(
        &'a self,
        public_key: &'a nostr::PublicKey,
        content: &'a str,
    ) -> nostr::util::BoxedFuture<'a, Result<String, nostr::SignerError>> {
        self.keys.nip44_encrypt(public_key, content)
    }

    fn nip44_decrypt<'a>(
        &'a self,
        public_key: &'a nostr::PublicKey,
        payload: &'a str,
    ) -> nostr::util::BoxedFuture<'a, Result<String, nostr::SignerError>> {
        self.keys.nip44_decrypt(public_key, payload)
    }
}

impl cgka_engine::account_identity_proof::AccountIdentityProofSigner for TestExternalAccountSigner {
    fn sign_account_identity_proof(
        &self,
        request: &cgka_engine::account_identity_proof::AccountIdentityProofRequest,
    ) -> Result<[u8; 64], String> {
        if self.keys.public_key().to_bytes().as_slice() != request.account_identity.as_slice() {
            return Err("request account identity does not match test signer".into());
        }
        let event = request.proof_event().and_then(|event| {
            event
                .sign_with_keys(&self.keys)
                .map_err(|err| err.to_string())
        })?;
        request.signature_from_signed_event(event)
    }
}

#[test]
fn legacy_projection_update_json_defaults_new_streaming_fields() {
    let update: AppProjectionUpdate = serde_json::from_str(
        r#"{"group_id_hex":"group","timeline_messages":[],"chat_list_row":null}"#,
    )
    .unwrap();

    assert!(update.timeline_changes.is_empty());
    assert_eq!(
        update.chat_list_trigger,
        ChatListUpdateTrigger::SnapshotRefresh
    );
}

#[test]
fn default_profile_word_lists_keep_expected_shape() {
    assert_profile_word_list("adjectives", DEFAULT_PROFILE_ADJECTIVES);
    assert_profile_word_list("nouns", DEFAULT_PROFILE_NOUNS);
    assert_eq!(
        DEFAULT_PROFILE_ADJECTIVES.len() * DEFAULT_PROFILE_NOUNS.len(),
        16_384
    );
}

fn assert_profile_word_list(name: &str, words: &[&str]) {
    assert_eq!(words.len(), 128, "{name} should have 128 entries");
    for word in words {
        assert!(!word.is_empty(), "{name} should not contain empty words");
        let mut chars = word.chars();
        assert!(
            chars.next().is_some_and(|ch| ch.is_ascii_uppercase()),
            "{name} word should start uppercase: {word}"
        );
        assert!(
            chars.all(|ch| ch.is_ascii_lowercase()),
            "{name} word should be title-cased ASCII: {word}"
        );
    }
    for pair in words.windows(2) {
        assert!(
            pair[0] < pair[1],
            "{name} should be sorted and unique: {} before {}",
            pair[0],
            pair[1]
        );
    }
}

fn relay_delivery(marker: &str, pubkey: String) -> cgka_traits::TransportDelivery {
    // `to_transport_message` verifies the id against the event hash (#351), so
    // the distinguishing marker lives in the content and the id is computed.
    let mut event = NostrTransportEvent {
        id: String::new(),
        pubkey,
        created_at: 1,
        kind: transport_nostr_peeler::KIND_MARMOT_GROUP_MESSAGE,
        tags: vec![vec!["h".to_owned(), "aa".repeat(32)]],
        content: format!("ciphertext {marker}"),
        sig: None,
    };
    event.id = event.computed_id();
    cgka_traits::TransportDelivery {
        account_id: MemberId::new(vec![0; 32]),
        group_id_hint: None,
        message: event.to_transport_message().unwrap(),
        received_at: cgka_traits::transport::Timestamp(1),
        source: cgka_traits::TransportDeliverySource {
            transport: cgka_traits::transport::TransportSource("nostr".to_owned()),
            plane: cgka_traits::TransportDeliveryPlane::Group,
            endpoint: None,
            subscription_id: None,
            wire: None,
        },
    }
}

#[test]
fn key_package_id_list_tag_must_be_exactly_one() {
    let make = |tags: Vec<Vec<String>>| NostrTransportEvent {
        id: "00".repeat(32),
        pubkey: "11".repeat(32),
        created_at: 1,
        kind: 30443,
        tags,
        content: String::new(),
        sig: None,
    };
    // A single id-list tag is accepted.
    let one = make(vec![vec!["mls_extensions".into(), "0x0006".into()]]);
    assert!(require_multi_value_key_package_tag_matches(&one, "mls_extensions", [0x0006]).is_ok());
    assert!(require_multi_value_key_package_tag_matches(&one, "mls_extensions", [0x0007]).is_err());
    // Two tags with the same id-list name MUST be rejected, not first-match read.
    let two = make(vec![
        vec!["mls_extensions".into(), "0x0006".into()],
        vec!["mls_extensions".into(), "0xf2f1".into()],
    ]);
    assert!(require_multi_value_key_package_tag_matches(&two, "mls_extensions", [0x0006]).is_err());
    // Extra, duplicate, and non-canonical markers are rejected even when the
    // expected marker is present.
    let extra = make(vec![vec![
        "app_components".into(),
        "0x8009".into(),
        "0x8008".into(),
    ]]);
    assert!(
        require_multi_value_key_package_tag_matches(&extra, "app_components", [0x8009]).is_err()
    );
    let duplicate = make(vec![vec![
        "app_components".into(),
        "0x8009".into(),
        "0x8009".into(),
    ]]);
    assert!(
        require_multi_value_key_package_tag_matches(&duplicate, "app_components", [0x8009])
            .is_err()
    );
    let uppercase = make(vec![vec!["app_components".into(), "0X8009".into()]]);
    assert!(
        require_multi_value_key_package_tag_matches(&uppercase, "app_components", [0x8009])
            .is_err()
    );
    // The single-value consumer (mls_ciphersuite) also rejects a duplicate.
    let two_cs = make(vec![
        vec!["mls_ciphersuite".into(), "0x0001".into()],
        vec!["mls_ciphersuite".into(), "0x0002".into()],
    ]);
    assert!(require_key_package_tag(&two_cs, "mls_ciphersuite", |_| true).is_err());
}

#[test]
fn relay_list_discovery_builds_one_limited_query_per_required_kind() {
    let account_id_hex =
        "0000000000000000000000000000000000000000000000000000000000000001".to_owned();

    let queries = relay_list_queries(account_id_hex.clone());

    assert_eq!(queries.len(), 2);
    let kinds = queries
        .iter()
        .map(|query| {
            assert_eq!(query.authors, vec![account_id_hex.clone()]);
            assert_eq!(query.limit, 12);
            query.kind
        })
        .collect::<Vec<_>>();
    assert_eq!(
        kinds,
        vec![KIND_NIP65_RELAY_LIST, KIND_MARMOT_INBOX_RELAY_LIST]
    );
}

#[test]
fn directory_search_bounds_frontier_from_cached_follow_lists() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let account = home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let cache = app.directory_cache_for_account(&account).unwrap();
    let follows = (0..USER_DIRECTORY_SEARCH_MAX_FRONTIER + 8)
        .map(|idx| format!("{:064x}", idx + 1))
        .collect::<Vec<_>>();

    cache
        .put(&UserDirectoryRecord {
            account_id_hex: account.account_id_hex.clone(),
            npub: npub_for_account_id_lossy(&account.account_id_hex),
            local_account: None,
            profile: None,
            follows: follows.clone(),
            follow_source_relays: Vec::new(),
            relay_lists: AccountRelayListStatus::empty(),
            key_package: None,
        })
        .unwrap();

    for follow in follows {
        cache
            .put(&UserDirectoryRecord {
                account_id_hex: follow.clone(),
                npub: npub_for_account_id_lossy(&follow),
                local_account: None,
                profile: Some(UserProfileMetadata {
                    name: Some("needle".into()),
                    display_name: None,
                    about: None,
                    picture: None,
                    banner: None,
                    nip05: None,
                    lud16: None,
                    created_at: 0,
                    source_relays: Vec::new(),
                    extra: Default::default(),
                }),
                follows: Vec::new(),
                follow_source_relays: Vec::new(),
                relay_lists: AccountRelayListStatus::empty(),
                key_package: None,
            })
            .unwrap();
    }

    let results = app
        .search_user_directory(UserDirectorySearch {
            searcher_account_id_hex: account.account_id_hex,
            query: "needle".into(),
            radius_start: 1,
            radius_end: 1,
            limit: None,
        })
        .unwrap();

    assert_eq!(results.len(), USER_DIRECTORY_SEARCH_MAX_FRONTIER);
}

#[test]
fn directory_search_uses_graph_cache_without_promoting_known_user() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let account = home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let cache = app.directory_cache_for_account(&account).unwrap();
    let graph_user = format!("{:064x}", 42);

    cache
        .put(&UserDirectoryRecord {
            account_id_hex: account.account_id_hex.clone(),
            npub: npub_for_account_id_lossy(&account.account_id_hex),
            local_account: None,
            profile: None,
            follows: vec![graph_user.clone()],
            follow_source_relays: Vec::new(),
            relay_lists: AccountRelayListStatus::empty(),
            key_package: None,
        })
        .unwrap();
    cache
        .put_search_graph_record(
            &directory::DirectorySearchGraphRecord {
                account_id_hex: graph_user.clone(),
                npub: npub_for_account_id_lossy(&graph_user),
                profile: Some(UserProfileMetadata {
                    name: Some("graph-needle".into()),
                    display_name: None,
                    about: None,
                    picture: None,
                    banner: None,
                    nip05: None,
                    lud16: None,
                    created_at: 1_700_000_001,
                    source_relays: Vec::new(),
                    extra: Default::default(),
                }),
                follows: Some(Vec::new()),
                metadata_updated_at: Some(1_700_000_001),
                metadata_expires_at: None,
            },
            1_700_000_002,
        )
        .unwrap();

    let results = app
        .search_user_directory(UserDirectorySearch {
            searcher_account_id_hex: account.account_id_hex.clone(),
            query: "graph-needle".into(),
            radius_start: 1,
            radius_end: 1,
            limit: None,
        })
        .unwrap();

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].account_id_hex, graph_user);
    assert!(
        app.directory_entry_for_account_id(&graph_user)
            .unwrap()
            .is_none()
    );
}

fn test_directory_record(account_id_hex: &str, name: &str, created_at: u64) -> UserDirectoryRecord {
    UserDirectoryRecord {
        account_id_hex: account_id_hex.to_owned(),
        npub: npub_for_account_id_lossy(account_id_hex),
        local_account: None,
        profile: Some(UserProfileMetadata {
            name: Some(name.to_owned()),
            display_name: None,
            about: None,
            picture: None,
            banner: None,
            nip05: None,
            lud16: None,
            created_at,
            source_relays: Vec::new(),
            extra: Default::default(),
        }),
        follows: Vec::new(),
        follow_source_relays: Vec::new(),
        relay_lists: AccountRelayListStatus::empty(),
        key_package: None,
    }
}

#[test]
fn profile_content_json_preserves_unknown_kind0_fields() {
    let profile = UserProfileMetadata {
        name: Some("alice".to_owned()),
        banner: Some("https://example.test/banner.png".to_owned()),
        extra: std::collections::BTreeMap::from([
            (
                "website".to_owned(),
                serde_json::json!("https://example.test"),
            ),
            ("bot".to_owned(), serde_json::json!(false)),
            ("name".to_owned(), serde_json::json!("spoofed-extra-name")),
        ]),
        ..UserProfileMetadata::default()
    };

    let content = profile_content_json(&profile);

    assert_eq!(content["name"], "alice");
    assert_eq!(content["website"], "https://example.test");
    assert_eq!(content["banner"], "https://example.test/banner.png");
    assert_eq!(content["bot"], false);
}

#[test]
fn duplicate_directory_entry_save_skips_cache_writes() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let account = home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let cache = app.directory_cache_for_account(&account).unwrap();
    let account_id = format!("{:064x}", 42);
    let mut entry = test_directory_record(&account_id, "cached-peer", 1_700_000_042);
    entry.profile.as_mut().unwrap().source_relays = vec!["wss://profiles.example".into()];

    cache.reset_put_count_for_test();
    app.save_directory_entry_with_reason(&entry, "message")
        .unwrap();
    assert_eq!(cache.put_count_for_test(), 1);

    cache.reset_put_count_for_test();
    app.save_directory_entry_with_reason(&entry, "message")
        .unwrap();
    assert_eq!(cache.put_count_for_test(), 0);

    entry.profile.as_mut().unwrap().display_name = Some("cached peer".into());
    app.save_directory_entry_with_reason(&entry, "message")
        .unwrap();
    assert_eq!(cache.put_count_for_test(), 1);
}

#[test]
fn remember_directory_profile_if_newer_keeps_local_edit_on_equal_timestamp() {
    // Regression for mdk#206: Nostr `created_at` is second-resolution,
    // so a rapid profile republish can carry the same timestamp as the
    // previous pre-edit kind-0. A lagging relay can then serve that stale
    // same-second copy back during a directory refresh. The cache must be
    // retained on an equal timestamp so the just-published local edit is not
    // reverted; only a strictly newer fetch replaces it.
    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let account_id = format!("{:064x}", 206);

    // Local edit cached at t=1_700_000_000 (own-account entry).
    app.save_directory_entry(&test_directory_record(
        &account_id,
        "edited-local",
        1_700_000_000,
    ))
    .unwrap();

    // Stale relay copy arrives with the SAME second-resolution timestamp.
    let stale_same_second = UserProfileMetadata {
        name: Some("stale-relay".to_owned()),
        created_at: 1_700_000_000,
        ..UserProfileMetadata::default()
    };
    app.remember_directory_profile_if_newer(&account_id, &stale_same_second)
        .unwrap();

    // The local edit must survive the equal-timestamp refresh.
    let entry = app
        .directory_entry_for_account_id(&account_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        entry.profile.and_then(|profile| profile.name),
        Some("edited-local".to_owned())
    );

    // A strictly newer fetch still wins (genuine remote update).
    let newer = UserProfileMetadata {
        name: Some("newer-remote".to_owned()),
        created_at: 1_700_000_001,
        ..UserProfileMetadata::default()
    };
    app.remember_directory_profile_if_newer(&account_id, &newer)
        .unwrap();
    let entry = app
        .directory_entry_for_account_id(&account_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        entry.profile.and_then(|profile| profile.name),
        Some("newer-remote".to_owned())
    );
}

#[test]
fn directory_entry_prefers_newer_shared_record_over_stale_cache() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let account = home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let cache = app.directory_cache_for_account(&account).unwrap();
    let contact = format!("{:064x}", 42);

    cache
        .put(&test_directory_record(&contact, "old-cache", 1))
        .unwrap();
    app.shared_storage()
        .unwrap()
        .put_public_directory_user(
            &public_directory_user_record(&test_directory_record(&contact, "new-shared", 2))
                .unwrap(),
        )
        .unwrap();

    let entry = app
        .directory_entry_for_account_id(&contact)
        .unwrap()
        .unwrap();

    assert_eq!(
        entry.profile.and_then(|profile| profile.name),
        Some("new-shared".to_owned())
    );
    assert_eq!(
        app.display_name_for_account_id(&contact).unwrap(),
        Some("new-shared".to_owned())
    );
}

#[test]
fn repeated_display_name_lookup_reuses_directory_cache_handle() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let account = home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let contact = format!("{:064x}", 44);

    app.save_directory_entry(&test_directory_record(&contact, "Cached Contact", 1))
        .unwrap();
    drop(app);
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");

    for _ in 0..5 {
        assert_eq!(
            app.display_name_for_account_id(&contact).unwrap(),
            Some("Cached Contact".to_owned())
        );
    }

    assert_eq!(app.directory_cache_open_count_for_test(), 1);
    assert!(app.directory_cache_path(&account.label).exists());
}

#[test]
fn batch_display_name_lookup_opens_one_directory_cache_per_local_account() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let bob = home.create_account("bob").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let contact = format!("{:064x}", 45);

    app.save_directory_entry(&test_directory_record(&contact, "Batch Contact", 1))
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");

    for _ in 0..5 {
        let names = app
            .display_names_for_account_ids(&[contact.clone(), bob.account_id_hex.clone()])
            .unwrap();
        assert_eq!(names.get(&contact), Some(&"Batch Contact".to_owned()));
        assert_eq!(names.get(&bob.account_id_hex), Some(&"bob".to_owned()));
    }

    assert_eq!(app.directory_cache_open_count_for_test(), 2);
}

#[test]
fn group_system_chat_preview_does_not_hydrate_its_optional_actor_as_a_nostr_sender() {
    let preview = ChatListMessagePreview {
        message_id_hex: "11".repeat(32),
        sender: String::new(),
        sender_display_name: None,
        plaintext: r#"{"v":1,"system_type":"admin_added","text":"Admin added"}"#.to_owned(),
        kind: MARMOT_APP_EVENT_KIND_GROUP_SYSTEM,
        timeline_at: 1,
        deleted: false,
        attachment_kind: None,
        attachment_count: 0,
        delivery_state: ChatListMessageDeliveryState::NotApplicable,
        media_json: None,
    };

    assert_eq!(
        MarmotApp::chat_list_sender_for_profile_hydration(&preview),
        None,
    );

    let ordinary = ChatListMessagePreview {
        kind: MARMOT_APP_EVENT_KIND_CHAT,
        sender: "22".repeat(32),
        ..preview
    };
    assert_eq!(
        MarmotApp::chat_list_sender_for_profile_hydration(&ordinary),
        Some(ordinary.sender.as_str()),
    );
}

#[test]
fn cached_identity_page_is_order_stable_and_distinguishes_local_from_remote() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let alice = home.create_account("alice").unwrap();
    let bob = home.create_account("bob").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let remote = format!("{:064x}", 46);
    let unknown = format!("{:064x}", 47);
    let malformed = "not-a-public-key".to_owned();

    app.save_directory_entry(&test_directory_record(&remote, "Remote Peer", 1))
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");

    let requested = vec![
        remote.clone(),
        alice.account_id_hex.clone(),
        malformed.clone(),
        unknown.clone(),
        remote.clone(),
        bob.account_id_hex.clone(),
    ];
    let page = app
        .cached_identity_projections_for_account_ids(&requested)
        .unwrap();

    assert_eq!(page.len(), requested.len());
    assert_eq!(page[0].requested_id, remote);
    assert_eq!(page[0].account_id_hex.as_deref(), Some(remote.as_str()));
    assert_eq!(
        page[0]
            .profile
            .as_ref()
            .and_then(|profile| profile.name.as_deref()),
        Some("Remote Peer")
    );
    assert_eq!(page[0].local_label, None);
    assert_eq!(page[0].resolved_name.as_deref(), Some("Remote Peer"));

    assert_eq!(
        page[1].account_id_hex.as_deref(),
        Some(alice.account_id_hex.as_str())
    );
    assert_eq!(page[1].profile, None);
    assert_eq!(page[1].local_label.as_deref(), Some("alice"));
    assert_eq!(page[1].resolved_name.as_deref(), Some("alice"));

    assert_eq!(page[2].requested_id, malformed);
    assert_eq!(page[2].account_id_hex, None);
    assert_eq!(page[2].profile, None);
    assert_eq!(page[2].local_label, None);
    assert_eq!(page[2].resolved_name, None);

    assert_eq!(page[3].account_id_hex.as_deref(), Some(unknown.as_str()));
    assert_eq!(page[3].profile, None);
    assert_eq!(page[3].local_label, None);
    assert_eq!(page[3].resolved_name, None);

    assert_eq!(page[4].requested_id, remote);
    assert_eq!(
        page[4]
            .profile
            .as_ref()
            .and_then(|profile| profile.name.as_deref()),
        Some("Remote Peer")
    );

    assert_eq!(page[5].local_label.as_deref(), Some("bob"));
    assert_eq!(page[5].resolved_name.as_deref(), Some("bob"));
}

#[test]
fn cached_identity_page_rejects_oversized_input() {
    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let oversized = vec!["00".repeat(32); MAX_CACHED_IDENTITY_PAGE_SIZE + 1];

    assert!(matches!(
        app.cached_identity_projections_for_account_ids(&oversized),
        Err(AppError::InvalidCachedIdentityPage(_))
    ));
}

#[test]
fn cached_identity_page_acquires_directory_handles_once_for_100_ids() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let remote = format!("{:064x}", 48);
    app.save_directory_entry(&test_directory_record(&remote, "Bulk Peer", 1))
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");

    let mut requested = vec![remote.clone()];
    requested.extend((49..148).map(|value| format!("{value:064x}")));
    assert_eq!(requested.len(), 100);

    let before = app.directory_handle_acquire_count_for_test();
    let page = app
        .cached_identity_projections_for_account_ids(&requested)
        .unwrap();
    let after_page = app.directory_handle_acquire_count_for_test();

    assert_eq!(page.len(), 100);
    assert_eq!(page[0].resolved_name.as_deref(), Some("Bulk Peer"));
    assert_eq!(after_page, before + 1);

    for account_id in &requested {
        let _ = app.directory_entry_for_account_id(account_id);
    }
    assert_eq!(
        app.directory_handle_acquire_count_for_test(),
        after_page + requested.len()
    );
}

#[test]
fn warm_directory_storage_opens_shared_and_local_directory_handles() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let alice = home.create_account("alice").unwrap();
    let bob = home.create_account("bob").unwrap();
    let public_key = nostr::Keys::generate().public_key().to_hex();
    let public_account = home.add_public_account(&public_key).unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");

    app.warm_directory_storage().unwrap();
    let open_count_after_warm = app.directory_cache_open_count_for_test();

    assert_eq!(open_count_after_warm, 2);
    assert!(app.shared_storage_path().exists());
    assert!(app.directory_cache_path(&alice.label).exists());
    assert!(app.directory_cache_path(&bob.label).exists());
    assert!(!app.directory_cache_path(&public_account.label).exists());

    assert_eq!(
        app.display_name_for_account_id(&alice.account_id_hex)
            .unwrap(),
        Some("alice".to_owned())
    );
    assert_eq!(
        app.display_names_for_account_ids(&[bob.account_id_hex.clone(), public_key])
            .unwrap()
            .get(&bob.account_id_hex),
        Some(&"bob".to_owned())
    );
    assert_eq!(
        app.directory_cache_open_count_for_test(),
        open_count_after_warm
    );
}

#[tokio::test]
async fn register_external_signer_requires_matching_external_account() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let keys = nostr::Keys::generate();
    let wrong_keys = nostr::Keys::generate();
    let account = home
        .add_external_signer_account(&keys.public_key().to_hex())
        .unwrap();
    let local_account = home.create_nostr_account().unwrap();
    let public_account = home
        .add_public_account(&nostr::Keys::generate().public_key().to_hex())
        .unwrap();
    let app = MarmotApp::with_relays_and_account_home(
        dir.path(),
        vec!["wss://relay.example".into()],
        home,
    );

    let wrong_signer = TestExternalAccountSigner { keys: wrong_keys };
    assert!(matches!(
        app.register_external_signer(&account.account_id_hex, wrong_signer)
            .await,
        Err(AppError::ExternalSignerMismatch)
    ));
    assert!(!app.has_external_signer(&account.account_id_hex));

    let local_signer = TestExternalAccountSigner { keys: keys.clone() };
    assert!(matches!(
        app.register_external_signer(&local_account.account_id_hex, local_signer)
            .await,
        Err(AppError::ExternalSignerUnavailable(account))
            if account == local_account.account_id_hex
    ));

    let public_signer = TestExternalAccountSigner { keys: keys.clone() };
    assert!(matches!(
        app.register_external_signer(&public_account.account_id_hex, public_signer)
            .await,
        Err(AppError::ExternalSignerUnavailable(account))
            if account == public_account.account_id_hex
    ));

    let signer = TestExternalAccountSigner { keys };
    app.register_external_signer(&account.account_id_hex, signer)
        .await
        .unwrap();
    assert!(app.has_external_signer(&account.account_id_hex));
}

#[test]
fn drop_account_caches_evicts_storage_and_directory_handles_and_warm_flags() {
    // Regression for mdk#220: removing an account (or rolling back a
    // failed setup) must evict the cached account-storage connection and
    // directory-cache handle before the account directory is deleted.
    // Otherwise the stale handle keeps pointing at the unlinked inode and a
    // later re-import silently splits writes across a deleted DB.
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let alice = home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");

    // Warm the account-storage connection, directory cache, and the
    // account-state / chat-list warm flags.
    app.ensure_account_state(&alice.label).unwrap();
    let account_summary = app.account_home().account(&alice.label).unwrap();
    app.ensure_chat_list_projection(&account_summary).unwrap();
    app.display_name_for_account_id(&alice.account_id_hex)
        .unwrap();

    assert!(app.account_storage_cached_for_test(&alice.label));
    assert!(app.directory_cache_cached_for_test(&alice.label));
    assert!(
        app.account_state_ready
            .lock()
            .unwrap()
            .contains(&alice.label)
    );
    assert!(
        app.chat_list_projection_warmed
            .lock()
            .unwrap()
            .contains(&alice.label)
    );

    app.drop_account_caches(&alice.label);

    assert!(!app.account_storage_cached_for_test(&alice.label));
    assert!(!app.directory_cache_cached_for_test(&alice.label));
    assert!(
        !app.account_state_ready
            .lock()
            .unwrap()
            .contains(&alice.label)
    );
    assert!(
        !app.chat_list_projection_warmed
            .lock()
            .unwrap()
            .contains(&alice.label)
    );
    assert!(
        !app.chat_list_projection_stale
            .lock()
            .unwrap()
            .contains(&alice.label)
    );
}

#[test]
fn legacy_plaintext_directory_cache_migrates_once_into_resident_cache() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let legacy_path = dir.path().join(APP_CACHE_DB_FILE);
    let cleanup_marker = dir.path().join(DIRECTORY_FUTURE_CREATED_AT_CLEANUP_MARKER);
    fs::write(cleanup_marker, b"done\n").unwrap();
    drop(Connection::open(&legacy_path).unwrap());
    let legacy_cache = DirectoryCache::open_legacy_plaintext(legacy_path.clone())
        .unwrap()
        .unwrap();
    let contact = format!("{:064x}", 46);
    legacy_cache
        .put(&test_directory_record(&contact, "Legacy Contact", 1))
        .unwrap();
    drop(legacy_cache);

    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let entry = app
        .directory_entry_for_account_id(&contact)
        .unwrap()
        .unwrap();

    assert_eq!(
        entry.profile.and_then(|profile| profile.name),
        Some("Legacy Contact".to_owned())
    );
    let shared_entry = app
        .shared_storage()
        .unwrap()
        .public_directory_user(&contact)
        .unwrap()
        .unwrap();
    assert_eq!(shared_entry.account_id_hex, contact);
    assert!(!legacy_path.exists());
    let open_count_after_migration = app.directory_cache_open_count_for_test();
    assert!(open_count_after_migration >= 1);

    let entry = app
        .directory_entry_for_account_id(&contact)
        .unwrap()
        .unwrap();
    assert_eq!(
        entry.profile.and_then(|profile| profile.name),
        Some("Legacy Contact".to_owned())
    );
    assert_eq!(
        app.directory_cache_open_count_for_test(),
        open_count_after_migration
    );
}

#[test]
fn legacy_plaintext_directory_cache_migrates_to_shared_storage_without_account_caches() {
    let dir = tempfile::tempdir().unwrap();
    let legacy_path = dir.path().join(APP_CACHE_DB_FILE);
    drop(Connection::open(&legacy_path).unwrap());
    let legacy_cache = DirectoryCache::open_legacy_plaintext(legacy_path.clone())
        .unwrap()
        .unwrap();
    let contact = format!("{:064x}", 47);
    legacy_cache
        .put(&test_directory_record(&contact, "Shared Legacy Contact", 1))
        .unwrap();
    drop(legacy_cache);

    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    app.migrate_legacy_directory_cache_once(&[]).unwrap();

    let shared_entry = app
        .shared_storage()
        .unwrap()
        .public_directory_user(&contact)
        .unwrap()
        .unwrap();
    let hydrated = app.hydrate_public_directory_record(shared_entry).unwrap();
    assert_eq!(
        hydrated.profile.and_then(|profile| profile.name),
        Some("Shared Legacy Contact".to_owned())
    );
    assert!(!legacy_path.exists());
}

#[test]
fn legacy_plaintext_directory_cache_keeps_file_when_migration_fails() {
    let dir = tempfile::tempdir().unwrap();
    let legacy_path = dir.path().join(APP_CACHE_DB_FILE);
    drop(Connection::open(&legacy_path).unwrap());
    let legacy_cache = DirectoryCache::open_legacy_plaintext(legacy_path.clone())
        .unwrap()
        .unwrap();
    legacy_cache
        .put(&UserDirectoryRecord {
            account_id_hex: "not-a-public-key".to_owned(),
            npub: "npub-invalid".to_owned(),
            local_account: None,
            profile: None,
            follows: Vec::new(),
            follow_source_relays: Vec::new(),
            relay_lists: AccountRelayListStatus::empty(),
            key_package: None,
        })
        .unwrap();
    drop(legacy_cache);

    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    assert!(app.migrate_legacy_directory_cache_once(&[]).is_err());
    assert!(legacy_path.exists());
    assert!(
        !*app
            .legacy_directory_cache_checked
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    );
}

#[test]
fn directory_entries_and_save_keep_newer_shared_record() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let account = home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let cache = app.directory_cache_for_account(&account).unwrap();
    let contact = format!("{:064x}", 43);
    let stale = test_directory_record(&contact, "old-cache", 1);
    let fresh = test_directory_record(&contact, "new-shared", 2);

    cache.put(&stale).unwrap();
    app.shared_storage()
        .unwrap()
        .put_public_directory_user(&public_directory_user_record(&fresh).unwrap())
        .unwrap();

    let listed = app.directory_entries().unwrap();
    let listed_entry = listed
        .iter()
        .find(|entry| entry.account_id_hex == contact)
        .unwrap();
    assert_eq!(
        listed_entry
            .profile
            .as_ref()
            .and_then(|profile| profile.name.as_deref()),
        Some("new-shared")
    );

    app.save_directory_entry_with_reason(&stale, "stale-cache")
        .unwrap();
    let entry = app
        .directory_entry_for_account_id(&contact)
        .unwrap()
        .unwrap();
    assert_eq!(
        entry.profile.and_then(|profile| profile.name),
        Some("new-shared".to_owned())
    );
}

#[test]
fn received_message_sender_is_admitted_to_directory_cache() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("bob").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let sender = format!("{:064x}", 42);

    assert!(
        app.directory_entry_for_account_id(&sender)
            .unwrap()
            .is_none()
    );
    app.remember_directory_message_sender(&ReceivedMessage {
        message_id_hex: "message-id".to_owned(),
        source_message_id_hex: "source-message-id".to_owned(),
        sender: sender.clone(),
        sender_display_name: None,
        group_id: GroupId::new(vec![0x01]),
        source_epoch: 0,
        retention: None,
        plaintext: "hello".to_owned(),
        kind: MARMOT_APP_EVENT_KIND_CHAT,
        tags: Vec::new(),
        recorded_at: 0,
        received_at: 0,
    })
    .unwrap();

    let entry = app
        .directory_entry_for_account_id(&sender)
        .unwrap()
        .unwrap();
    assert_eq!(entry.account_id_hex, sender);
    assert!(entry.profile.is_none());
    assert!(entry.follows.is_empty());
}

#[test]
fn directory_sync_plan_watches_local_accounts_and_known_users() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let account = home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let contact = format!("{:064x}", 42);

    app.remember_directory_user_with_reason(&contact, "message")
        .unwrap();

    let plan = app.directory_sync_plan().unwrap();
    let watched = plan
        .batches
        .iter()
        .flat_map(|batch| batch.authors.clone())
        .collect::<Vec<_>>();

    assert_eq!(
        plan.endpoints,
        vec![TransportEndpoint("wss://relay.example".to_owned())]
    );
    assert_eq!(plan.watched_user_count, 2);
    assert!(watched.contains(&account.account_id_hex));
    assert!(watched.contains(&contact));
}

#[test]
fn directory_sync_plan_does_not_subscribe_kind3_for_non_local_known_user() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let account = home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let sender = format!("{:064x}", 42);

    // A non-local known user (e.g. a message sender) is admitted to the
    // directory but must never have its kind-3 contact list subscribed: doing
    // so feeds the unbounded transitive social-graph crawl (mdk#687).
    app.remember_directory_user_with_reason(&sender, "message")
        .unwrap();

    let plan = app.directory_sync_plan().unwrap();

    let local_kinds = plan
        .batches
        .iter()
        .find(|batch| batch.authors.contains(&account.account_id_hex))
        .map(|batch| batch.kinds.clone())
        .expect("local account should be watched");
    let remote_kinds = plan
        .batches
        .iter()
        .find(|batch| batch.authors.contains(&sender))
        .map(|batch| batch.kinds.clone())
        .expect("non-local known user should be watched");

    assert!(
        local_kinds.contains(&KIND_NOSTR_CONTACT_LIST),
        "local accounts may still sync their own contact list"
    );
    assert!(
        !remote_kinds.contains(&KIND_NOSTR_CONTACT_LIST),
        "non-local known users must not be subscribed to kind-3 contact lists"
    );
    assert!(remote_kinds.contains(&KIND_NOSTR_METADATA));
    assert!(remote_kinds.contains(&KIND_MARMOT_KEY_PACKAGE));
    // The local account's own batch keeps the full kind set; it must not be
    // double-listed in a contact-list-free remote batch.
    assert_eq!(
        plan.batches
            .iter()
            .filter(|batch| batch.authors.contains(&account.account_id_hex))
            .count(),
        1
    );
}

fn contact_list_event(author_hex: &str, follows: &[String]) -> NostrTransportEvent {
    NostrTransportEvent {
        id: "00".repeat(32),
        pubkey: author_hex.to_owned(),
        created_at: 1,
        kind: KIND_NOSTR_CONTACT_LIST,
        tags: follows
            .iter()
            .map(|follow| vec!["p".to_owned(), follow.clone()])
            .collect(),
        content: String::new(),
        sig: None,
    }
}

#[test]
fn ingesting_remote_contact_list_does_not_promote_follows_and_caps_stored_follows() {
    use crate::directory::records::MAX_FOLLOW_LIST_ENTRIES;

    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let account = home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");

    // A remote, non-local user whose contact list arrives over a relay.
    let author = format!("{:064x}", 42);
    app.remember_directory_user_with_reason(&author, "message")
        .unwrap();

    // Build a contact list far larger than the per-list cap.
    let total_follows = MAX_FOLLOW_LIST_ENTRIES + 50;
    let follows = (0..total_follows)
        .map(|index| format!("{:064x}", index + 1000))
        .collect::<Vec<_>>();
    let record = crate::relay_plane::DirectoryRelayEventRecord {
        endpoints: vec![TransportEndpoint("wss://relay.example".to_owned())],
        event: contact_list_event(&author, &follows),
    };

    app.ingest_directory_relay_event(record).unwrap();

    // None of the followed pubkeys may be promoted into known directory entries.
    let known_ids = app
        .directory_entries()
        .unwrap()
        .into_iter()
        .map(|entry| entry.account_id_hex)
        .collect::<std::collections::HashSet<_>>();
    for follow in &follows {
        assert!(
            !known_ids.contains(follow),
            "ingested follows must not be promoted into known directory entries"
        );
    }

    // The author's cached follow edges are bounded by the per-list cap.
    let author_entry = app
        .directory_entry_for_account_id(&author)
        .unwrap()
        .unwrap();
    assert_eq!(author_entry.follows.len(), MAX_FOLLOW_LIST_ENTRIES);

    // The directory sync plan still watches only the author and local account,
    // never the discovered follows — so no transitive crawl is scheduled.
    let plan = app.directory_sync_plan().unwrap();
    let watched = plan
        .batches
        .iter()
        .flat_map(|batch| batch.authors.clone())
        .collect::<std::collections::HashSet<_>>();
    assert!(watched.contains(&account.account_id_hex));
    assert!(watched.contains(&author));
    for follow in &follows {
        assert!(
            !watched.contains(follow),
            "discovered follows must not become watched directory users"
        );
    }

    // The follow edges remain available for bounded directory search via the
    // per-account search graph, even though the follows are not promoted.
    let cache = app.directory_cache_for_account(&account).unwrap();
    let search_record = cache
        .search_record(&author, crate::unix_now_seconds() as i64)
        .unwrap()
        .unwrap();
    assert_eq!(search_record.follows.len(), MAX_FOLLOW_LIST_ENTRIES);
}

#[test]
fn local_account_directory_refresh_still_promotes_follows() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let account = home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let follow = format!("{:064x}", 7);

    // A user-initiated refresh of a local account's own follow list (distinct
    // from passive relay ingest) intentionally records its follows so they are
    // searchable and watched.
    app.remember_directory_user_with_reason(&account.account_id_hex, "local")
        .unwrap();
    let follow_list = FetchedFollowList {
        follows: vec![follow.clone()],
        source_relays: vec!["wss://relay.example".to_owned()],
    };
    app.remember_directory_follow_list_for_test(&account.account_id_hex, &follow_list)
        .unwrap();

    let entry = app
        .directory_entry_for_account_id(&account.account_id_hex)
        .unwrap()
        .unwrap();
    assert_eq!(entry.follows, vec![follow.clone()]);
    assert!(
        app.directory_entry_for_account_id(&follow)
            .unwrap()
            .is_some(),
        "an explicit follow-list refresh promotes follows into directory entries"
    );

    let plan = app.directory_sync_plan().unwrap();
    let local_batch = plan
        .batches
        .iter()
        .find(|batch| batch.authors.contains(&account.account_id_hex))
        .expect("local account should be watched");
    assert!(local_batch.kinds.contains(&KIND_NOSTR_CONTACT_LIST));
}

#[test]
fn empty_follow_fetch_preserves_cached_edges() {
    let account_id = format!("{:064x}", 6);
    let followed = format!("{:064x}", 7);
    let cached = UserDirectoryRecord {
        account_id_hex: account_id.clone(),
        npub: npub_for_account_id_lossy(&account_id),
        local_account: None,
        profile: None,
        follows: vec![followed.clone()],
        follow_source_relays: vec!["wss://cached.example".to_owned()],
        relay_lists: AccountRelayListStatus::empty(),
        key_package: None,
    };

    let selected = directory::cached_or_unknown_follow_list(
        Some(cached),
        &[TransportEndpoint("wss://queried.example".to_owned())],
    );

    assert_eq!(selected.follows, vec![followed]);
    assert_eq!(
        selected.source_relays,
        vec!["wss://cached.example".to_owned()]
    );
}

#[test]
fn stored_group_image_component_debug_redacts_key_material() {
    const IMAGE_KEY_HEX: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const UPLOAD_KEY_HEX: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    let group = AppGroupRecord::new(
        "aa".to_owned(),
        AppGroupNostrRoutingComponent::new(
            NostrRoutingV1::new([0xAA; 32], vec!["wss://relay.example".to_owned()]).unwrap(),
        )
        .unwrap(),
        "group".to_owned(),
        String::new(),
        AppGroupImageInput {
            image_hash_hex: hex::encode([0x11; 32]),
            image_key_hex: IMAGE_KEY_HEX.to_owned(),
            image_nonce_hex: hex::encode([0x22; 12]),
            image_upload_key_hex: UPLOAD_KEY_HEX.to_owned(),
            media_type: Some("image/png".to_owned()),
        },
        AppGroupAdminPolicyComponent::new(Vec::new()),
        AppGroupMessageRetentionComponent::disabled(),
    );

    let image_component = stored_components_from_app_group(&group)
        .into_iter()
        .find(|component| component.component_id == GROUP_BLOSSOM_IMAGE_COMPONENT_ID)
        .expect("image component");

    let rendered = format!("{image_component:?}");
    assert!(!rendered.contains(IMAGE_KEY_HEX));
    assert!(!rendered.contains(UPLOAD_KEY_HEX));
    assert!(rendered.contains("marmot.group.blossom.image.v1"));
    assert!(rendered.contains("redacted"));

    let stored = stored_group_from_app_group(&group);
    let parent_rendered = format!("{stored:?}");
    assert!(!parent_rendered.contains(IMAGE_KEY_HEX));
    assert!(!parent_rendered.contains(UPLOAD_KEY_HEX));
    assert!(parent_rendered.contains("profile_name: \"group\""));
    assert!(parent_rendered.contains("image_key_hex"));
    assert!(parent_rendered.contains("redacted"));
}

#[test]
fn profile_presence_round_trips_through_account_projection() {
    let mut group = AppGroupRecord::new(
        "aa".to_owned(),
        AppGroupNostrRoutingComponent::new(
            NostrRoutingV1::new([0xAA; 32], vec!["wss://relay.example".to_owned()]).unwrap(),
        )
        .unwrap(),
        String::new(),
        String::new(),
        AppGroupImageInput::default(),
        AppGroupAdminPolicyComponent::new(Vec::new()),
        AppGroupMessageRetentionComponent::disabled(),
    );

    assert!(group.profile.present);
    assert_eq!(group.profile.data_hex, "0000");
    let restored_present =
        app_group_from_stored_group(stored_group_from_app_group(&group)).unwrap();
    assert!(restored_present.profile.present);
    assert_eq!(restored_present.profile.data_hex, "0000");

    group.profile = AppGroupProfileComponent::absent();
    let restored_absent = app_group_from_stored_group(stored_group_from_app_group(&group)).unwrap();
    assert!(!restored_absent.profile.present);
    assert!(restored_absent.profile.data_hex.is_empty());
    assert_eq!(restored_absent.profile.name, "");
    assert_eq!(restored_absent.profile.description, "");
}

#[test]
fn unknown_optional_component_round_trips_through_account_projection() {
    let group = AppGroupRecord::new(
        "aa".to_owned(),
        AppGroupNostrRoutingComponent::new(
            NostrRoutingV1::new([0xAA; 32], vec!["wss://relay.example".to_owned()]).unwrap(),
        )
        .unwrap(),
        "group".to_owned(),
        String::new(),
        AppGroupImageInput::default(),
        AppGroupAdminPolicyComponent::new(Vec::new()),
        AppGroupMessageRetentionComponent::disabled(),
    );
    let unknown = storage_sqlite::StoredAccountGroupComponent {
        component_id: 0xf400,
        component_name: "unknown.optional.component".to_owned(),
        component_data_hex: "ff0080017f".to_owned(),
    };
    let mut stored = stored_group_from_app_group(&group);
    stored.components.push(unknown.clone());

    let restored = app_group_from_stored_group(stored).unwrap();
    let resaved = stored_group_from_app_group(&restored);
    assert!(
        resaved.components.contains(&unknown),
        "projection saves must preserve unknown optional component bytes"
    );
}

#[test]
fn avatar_url_round_trips_through_account_projection() {
    let mut group = AppGroupRecord::new(
        "aa".to_owned(),
        AppGroupNostrRoutingComponent::new(
            NostrRoutingV1::new([0xAA; 32], vec!["wss://relay.example".to_owned()]).unwrap(),
        )
        .unwrap(),
        "group".to_owned(),
        String::new(),
        AppGroupImageInput::default(),
        AppGroupAdminPolicyComponent::new(Vec::new()),
        AppGroupMessageRetentionComponent::disabled(),
    );
    group.avatar_url = AppGroupAvatarUrlComponent::new(
        "https://cdn.example.com/a.png".to_owned(),
        Some("512x512".to_owned()),
        None,
    )
    .unwrap();

    let stored = stored_group_from_app_group(&group);
    let restored = app_group_from_stored_group(stored).unwrap();
    assert_eq!(restored.avatar_url, group.avatar_url);
    assert!(restored.avatar_url.present);
    assert_eq!(restored.avatar_url.url, "https://cdn.example.com/a.png");

    // An absent avatar restores as absent.
    let mut plain = group.clone();
    plain.avatar_url = AppGroupAvatarUrlComponent::absent();
    let restored_plain = app_group_from_stored_group(stored_group_from_app_group(&plain)).unwrap();
    assert!(!restored_plain.avatar_url.present);
}

#[test]
fn encrypted_media_v2_round_trips_through_account_projection() {
    let mut group = AppGroupRecord::new(
        "bb".to_owned(),
        AppGroupNostrRoutingComponent::new(
            NostrRoutingV1::new([0xBB; 32], vec!["wss://relay.example".to_owned()]).unwrap(),
        )
        .unwrap(),
        "current group".to_owned(),
        String::new(),
        AppGroupImageInput::default(),
        AppGroupAdminPolicyComponent::new(Vec::new()),
        AppGroupMessageRetentionComponent::disabled(),
    );
    group.protocol_profile = AppProtocolProfile::Current;
    group.encrypted_media = AppGroupEncryptedMediaComponent::new_v2(
        cgka_traits::app_components::EncryptedMediaPolicyV2::blossom_default([
            "https://blossom.primal.net".to_owned(),
        ])
        .unwrap(),
    )
    .unwrap();

    let restored =
        app_group_from_stored_group(stored_group_from_app_group(&group)).expect("restore V2 group");
    assert_eq!(restored.protocol_profile, AppProtocolProfile::Current);
    assert_eq!(
        restored.encrypted_media.component_id,
        GROUP_ENCRYPTED_MEDIA_V2_COMPONENT_ID
    );
    assert_eq!(
        restored.encrypted_media.media_format,
        cgka_traits::app_components::ENCRYPTED_MEDIA_FORMAT_V2
    );
    assert_eq!(restored.encrypted_media, group.encrypted_media);
}

#[tokio::test]
async fn key_package_capabilities_advertise_every_supported_group_component() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let account = home.create_account("component-advertisement").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let supported = app.supported_app_component_ids();
    assert!(supported.contains(&GROUP_BLOSSOM_IMAGE_COMPONENT_ID));
    assert!(supported.contains(&GROUP_MESSAGE_RETENTION_COMPONENT_ID));
    assert!(supported.contains(&GROUP_AVATAR_URL_COMPONENT_ID));
    assert!(supported.contains(&GROUP_ENCRYPTED_MEDIA_V1_COMPONENT_ID));
    assert!(supported.contains(&GROUP_ENCRYPTED_MEDIA_V2_COMPONENT_ID));

    let key_package = fresh_key_package_for_account(&app, &account, false).await;
    let metadata = cgka_engine::key_package::key_package_metadata(&key_package).unwrap();
    for component_id in supported {
        assert!(
            metadata.app_components.contains(&component_id),
            "generated KeyPackage omitted supported component {component_id:#06x}"
        );
    }
}

#[test]
fn notification_settings_default_local_notifications_on_for_new_account() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let account = home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");

    let settings = app.notification_settings("alice").unwrap();

    assert_eq!(settings.account_ref, "alice");
    assert_eq!(settings.account_id_hex, account.account_id_hex);
    assert!(settings.local_notifications_enabled);
    assert!(!settings.native_push_enabled);
}

#[test]
fn legacy_account_projection_imports_once_into_account_storage() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let account = home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let keys = app.account_home().load_signing_keys("alice").unwrap();
    let legacy_path = app.legacy_account_projection_path("alice");
    let legacy_key = app
        .sqlcipher_key(
            "alice",
            &keys,
            &legacy_path,
            SqlcipherDatabaseKind::AccountProjection,
        )
        .unwrap();
    let mut legacy = LegacyAccountProjectionDb::open(legacy_path.clone(), &legacy_key).unwrap();
    let group = AppGroupRecord::new(
        "aa".to_owned(),
        AppGroupNostrRoutingComponent::new(
            NostrRoutingV1::new([0xAA; 32], vec!["wss://relay.example".to_owned()]).unwrap(),
        )
        .unwrap(),
        "legacy".to_owned(),
        String::new(),
        AppGroupImageInput::default(),
        AppGroupAdminPolicyComponent::new(Vec::new()),
        AppGroupMessageRetentionComponent::disabled(),
    );
    legacy
        .save_state(&AccountState {
            label: "alice".to_owned(),
            seen_events: vec!["seen".to_owned()],
            last_transport_timestamp: Some(1_700_000_100),
            groups: vec![group],
        })
        .unwrap();
    legacy
        .record_message(&AppMessageProjection {
            message_id_hex: "legacy-message".to_owned(),
            source_message_id_hex: None,
            direction: "received".to_owned(),
            group_id_hex: "aa".to_owned(),
            sender: account.account_id_hex.clone(),
            plaintext: "from legacy".to_owned(),
            kind: 9,
            tags: Vec::new(),
            source_epoch: None,
            retention: None,
            recorded_at: Some(1_700_000_101),
            origin_commit_id: None,
            moderation_grant: false,
        })
        .unwrap();
    legacy
        .set_native_push_enabled("alice", &account.account_id_hex, true)
        .unwrap();
    legacy
        .set_local_notifications_enabled("alice", &account.account_id_hex, false)
        .unwrap();
    legacy
        .upsert_push_registration(
            PushRegistration {
                account_ref: "alice".to_owned(),
                account_id_hex: account.account_id_hex.clone(),
                platform: PushPlatform::Apns,
                token_fingerprint: "fingerprint".to_owned(),
                server_pubkey_hex: "bb".repeat(32),
                relay_hint: Some("wss://relay.example".to_owned()),
                created_at_ms: 10,
                updated_at_ms: 11,
                last_shared_at_ms: None,
            },
            vec![1, 2, 3],
        )
        .unwrap();
    legacy
        .upsert_group_push_token(&GroupPushTokenRecord {
            group_id_hex: "aa".to_owned(),
            member_id_hex: account.account_id_hex.clone(),
            leaf_index: 7,
            platform: PushPlatform::Apns,
            token_fingerprint: "fingerprint".to_owned(),
            server_pubkey_hex: "bb".repeat(32),
            relay_hint: None,
            encrypted_token: vec![9, 8, 7],
            owner_ts: 0,
            owner_sig: String::new(),
            updated_at_ms: 12,
        })
        .unwrap();

    let groups = app.groups("alice").unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].profile.name, "legacy");
    let messages = app.messages("alice").unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].plaintext, "from legacy");
    let settings = app.notification_settings("alice").unwrap();
    assert!(!settings.local_notifications_enabled);
    assert!(settings.native_push_enabled);
    assert!(app.push_registration("alice").unwrap().is_some());
    assert_eq!(app.group_push_tokens("alice", "aa").unwrap().len(), 1);

    legacy
        .record_message(&AppMessageProjection {
            message_id_hex: "post-marker".to_owned(),
            source_message_id_hex: None,
            direction: "received".to_owned(),
            group_id_hex: "aa".to_owned(),
            sender: account.account_id_hex,
            plaintext: "should stay legacy-only".to_owned(),
            kind: 9,
            tags: Vec::new(),
            source_epoch: None,
            retention: None,
            recorded_at: Some(1_700_000_102),
            origin_commit_id: None,
            moderation_grant: false,
        })
        .unwrap();
    assert_eq!(app.messages("alice").unwrap().len(), 1);
}

#[test]
fn legacy_account_projection_clamps_poisoned_transport_cursor_on_import() {
    // mdk#182 end-to-end: a pre-clamp-era legacy account projection can carry a
    // transport cursor poisoned far above `now + skew`. The one-shot import
    // (`migrate_legacy_account_projection_if_needed`) writes that legacy state
    // into a brand-new account store through `save_account_projection_state`,
    // which must clamp the adopted cursor to `now + skew` instead of persisting
    // the poison. The storage-layer twin
    // (`account_projection_state_clamps_poisoned_snapshot_into_fresh_store`)
    // covers the same save arm directly; this test drives the real migration.
    let now_secs = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    };
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let keys = app.account_home().load_signing_keys("alice").unwrap();
    let legacy_path = app.legacy_account_projection_path("alice");
    let legacy_key = app
        .sqlcipher_key(
            "alice",
            &keys,
            &legacy_path,
            SqlcipherDatabaseKind::AccountProjection,
        )
        .unwrap();
    let mut legacy = LegacyAccountProjectionDb::open(legacy_path.clone(), &legacy_key).unwrap();

    let now_before = now_secs();
    let poisoned = now_before + 10 * 365 * 24 * 60 * 60; // ~10 years ahead
    legacy
        .save_state(&AccountState {
            label: "alice".to_owned(),
            seen_events: Vec::new(),
            last_transport_timestamp: Some(poisoned),
            groups: Vec::new(),
        })
        .unwrap();

    // First account access runs the one-shot legacy import.
    app.groups("alice").unwrap();
    let now_after = now_secs();

    let skew = TRANSPORT_CURSOR_MAX_FUTURE_SKEW.as_secs();
    let cursor = app
        .account_storage("alice")
        .unwrap()
        .load_account_projection_state("alice", MAX_SEEN_EVENT_IDS)
        .unwrap()
        .last_transport_timestamp
        .expect("imported cursor must survive the migration save");
    assert!(
        (now_before + skew..=now_after + skew).contains(&cursor),
        "legacy import must clamp a poisoned transport cursor to now + skew, got {cursor}"
    );
}

#[test]
fn durable_delivery_overflow_marker_forces_unfloored_account_reopen() {
    run_composed_app_runtime_test("delivery-overflow-reopen", || async {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let cursor = crate::unix_now_seconds() - 3_600;

        {
            let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
            app.ensure_account_state("alice").unwrap();
            let mut state = app.load_state("alice").unwrap();
            state.last_transport_timestamp = Some(cursor);
            app.save_state(&state).unwrap();
            app.account_storage("alice")
                .unwrap()
                .mark_account_delivery_recovery("alice", 17, 1)
                .unwrap();
        }

        let relay = Arc::new(ScriptedPushRelayClient::default());
        let mut reopened = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        reopened.relay_plane = MarmotRelayPlane::new_with_loopback(
            Some(Duration::from_secs(120)),
            relay.clone(),
            true,
        );
        let mut client = client_on_app_relay_plane(&reopened, "alice").await;

        assert!(client.delivery_overflow_recovery_pending);
        assert_eq!(
            client.state.last_transport_timestamp,
            Some(cursor),
            "the newer durable cursor remains diagnostic state"
        );
        assert!(
            client.subscription_rebuild_since().is_none(),
            "the pending gap must override the cursor with a full-history request"
        );
        let subscriptions = relay.accepted_subscriptions();
        assert!(!subscriptions.is_empty());
        assert!(
            subscriptions.iter().all(|subscription| match subscription {
                NostrSubscription::AccountInbox { since, .. }
                | NostrSubscription::Group { since, .. } => since.is_none(),
                NostrSubscription::GroupMaintenance { .. } => true,
            }),
            "account reopen must issue no cursor floor while overflow recovery is pending"
        );

        let group_id = client
            .create_group("overflow recovery target", &[])
            .await
            .unwrap();
        let group = reopened
            .group("alice", &hex::encode(group_id.as_slice()))
            .unwrap()
            .expect("recovery target group projection");
        let omitted = epoch_gap_probe(
            &group.nostr_routing.nostr_group_id_hex,
            cursor.saturating_sub(600),
            "overflow-redelivery",
        );
        let omitted_id = omitted.id.clone();
        inject_epoch_gap_probe(&reopened, omitted).await;

        let _eose = scripted_eose_pump(reopened.relay_plane.clone(), relay, every_subscription);
        client
            .sync()
            .await
            .expect("an EOSE-confirmed unfloored replay resolves the durable gap");
        assert!(
            reopened
                .load_state("alice")
                .unwrap()
                .seen_events
                .contains(&omitted_id),
            "the unfloored recovery must ingest the older event omitted below the ordinary cursor floor"
        );
        assert!(!client.delivery_overflow_recovery_pending);
        assert!(
            reopened
                .account_storage("alice")
                .unwrap()
                .account_delivery_recovery("alice")
                .unwrap()
                .is_none(),
            "the durable marker clears only after the recovery replay reaches EOSE"
        );
        let health = reopened.relay_plane.relay_health().await;
        assert_eq!(health.account_delivery_recovery_attempts, 1);
        assert_eq!(health.account_delivery_recovery_successes, 1);
        assert_eq!(health.account_delivery_recovery_failures, 0);
    });
}

#[test]
fn process_local_overflow_fence_freezes_cursor_while_marker_write_retries() {
    run_composed_app_runtime_test("delivery-overflow-cursor-fence", || async {
        let dir = tempfile::tempdir().unwrap();
        let account = AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let mut app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        app.relay_plane =
            MarmotRelayPlane::new_with_loopback(Some(Duration::from_secs(120)), relay, true);
        let cursor_before = crate::unix_now_seconds().saturating_sub(10_000);
        app.ensure_account_state("alice").unwrap();
        let mut seeded = app.load_state("alice").unwrap();
        seeded.last_transport_timestamp = Some(cursor_before);
        app.save_state(&seeded).unwrap();

        let mut client = client_on_app_relay_plane(&app, "alice").await;
        let group_id = client
            .create_group("overflow cursor fence", &[])
            .await
            .unwrap();
        let nostr_group_id_hex = app
            .group("alice", &hex::encode(group_id.as_slice()))
            .unwrap()
            .expect("local group projection")
            .nostr_routing
            .nostr_group_id_hex;

        let release_marker = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let marker_attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let release = release_marker.clone();
        let attempts = marker_attempts.clone();
        let storage = app.account_storage("alice").unwrap();
        let marker: crate::relay_plane::AccountDeliveryRecoveryMarker =
            Arc::new(move |marker_token, dropped| {
                attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if !release.load(std::sync::atomic::Ordering::SeqCst) {
                    return Err(crate::relay_plane::AccountDeliveryRecoveryMarkerError::Retryable);
                }
                storage
                    .mark_account_delivery_recovery("alice", marker_token, dropped)
                    .map_err(|error| {
                        if error.is_closed() {
                            crate::relay_plane::AccountDeliveryRecoveryMarkerError::Closed
                        } else {
                            crate::relay_plane::AccountDeliveryRecoveryMarkerError::Retryable
                        }
                    })
            });
        assert!(
            app.relay_plane
                .set_account_delivery_recovery_marker_for_test(
                    &MemberId::new(hex::decode(&account.account_id_hex).unwrap()),
                    marker,
                )
        );

        // Model the dangerous lead-in: several newest events are processed by
        // the live one-at-a-time worker seam before the later burst finally
        // fills its queue. Their in-memory max is above the older event that
        // will be omitted, but they must not promote the durable drain floor.
        for index in 0..3_u64 {
            inject_epoch_gap_probe(
                &app,
                epoch_gap_probe(
                    &nostr_group_id_hex,
                    cursor_before + 4_000 - index,
                    &format!("pre-overflow-cursor-{index}"),
                ),
            )
            .await;
            let received = client.receive_next_delivery().await.unwrap();
            let crate::relay_plane::AccountDeliveryReceive::Delivery(delivery) = received else {
                panic!("the pre-overflow delivery must not produce a control record");
            };
            client
                .ingest_received_delivery(*delivery)
                .await
                .expect("the pre-overflow delivery must checkpoint its projection");
        }
        assert!(
            client.state.last_transport_timestamp > Some(cursor_before + 3_000),
            "the regression needs a processed in-memory cursor above the later omitted event"
        );

        let newest = cursor_before + 2_000;
        let mut omitted_timestamp = 0;
        for index in 0..=crate::relay_plane::ACCOUNT_DELIVERY_BUFFER {
            let created_at = newest.saturating_sub(index as u64);
            if index == crate::relay_plane::ACCOUNT_DELIVERY_BUFFER {
                omitted_timestamp = created_at;
            }
            inject_epoch_gap_probe(
                &app,
                epoch_gap_probe(
                    &nostr_group_id_hex,
                    created_at,
                    &format!("overflow-cursor-{index}"),
                ),
            )
            .await;
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            while marker_attempts.load(std::sync::atomic::Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("overflow must start its one marker worker");

        let received = client.receive_next_delivery().await.unwrap();
        let crate::relay_plane::AccountDeliveryReceive::Delivery(delivery) = received else {
            panic!("the retained newest-first prefix must precede the overflow signal");
        };
        client
            .ingest_received_delivery(*delivery)
            .await
            .expect("the retained prefix delivery must checkpoint");

        let persisted = app
            .account_storage("alice")
            .unwrap()
            .load_account_projection_state("alice", MAX_SEEN_EVENT_IDS)
            .unwrap();
        assert_eq!(
            persisted.last_transport_timestamp,
            Some(cursor_before),
            "the process-local overflow fence must freeze the durable cursor before marker I/O completes"
        );
        assert!(
            app.account_storage("alice")
                .unwrap()
                .account_delivery_recovery("alice")
                .unwrap()
                .is_none(),
            "the regression must inspect the pre-marker crash window"
        );
        assert!(
            app.relay_plane
                .subscription_rebuild_since(persisted.last_transport_timestamp)
                .is_some_and(|since| since.0 <= omitted_timestamp),
            "without a marker, the frozen cursor must still request a range containing the omitted older event"
        );

        release_marker.store(true, std::sync::atomic::Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if app
                    .account_storage("alice")
                    .unwrap()
                    .account_delivery_recovery("alice")
                    .unwrap()
                    .is_some()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the single marker worker must persist after the retry clears");
    });
}

#[test]
fn ingest_applies_owner_signed_transitive_448_and_drops_spoof() {
    use nostr::base64::Engine as _;
    use nostr::base64::engine::general_purpose::STANDARD as B64;

    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    // Marmot MLS group ids are 16 bytes (variable-length in general); use that
    // here so the canonical-encoding length prefix is exercised realistically.
    let group_id = cgka_traits::GroupId::new(vec![0xEE; 16]);
    let group_id_hex = hex::encode(group_id.as_slice());

    let owner = nostr::Keys::generate();
    let owner_id = owner.public_key().to_hex();
    let relayer = nostr::Keys::generate().public_key().to_hex();

    // Build a token gossip `content` whose record is signed by `signer` but
    // claims `claimed_owner`. For an honest record the two match; for a spoof the
    // attacker signs while naming the victim.
    let gossip_content = |signer: &nostr::Keys, claimed_owner: &str, owner_ts: i64| -> String {
        let mut record = GroupPushTokenRecord {
            group_id_hex: group_id_hex.clone(),
            member_id_hex: signer.public_key().to_hex(),
            leaf_index: 1,
            platform: PushPlatform::Apns,
            token_fingerprint: crate::notifications::push_token_fingerprint(
                PushPlatform::Apns,
                &owner_ts.to_be_bytes(),
            ),
            server_pubkey_hex: "dd".repeat(32),
            relay_hint: Some("wss://relay.example".to_owned()),
            encrypted_token: vec![0_u8; crate::notifications::PUSH_ENCRYPTED_TOKEN_LEN],
            owner_ts,
            owner_sig: String::new(),
            updated_at_ms: owner_ts,
        };
        record.sign_owner(signer).unwrap();
        serde_json::json!({
            "v": "marmot-push-v1",
            "tokens": [{
                "member_id_hex": claimed_owner,
                "leaf_index": record.leaf_index,
                "platform": "apns",
                "token_fingerprint": record.token_fingerprint,
                "server_pubkey_hex": record.server_pubkey_hex,
                "relay_hint": record.relay_hint,
                "encrypted_token": B64.encode(&record.encrypted_token),
                "owner_ts": record.owner_ts,
                "owner_sig": record.owner_sig,
            }]
        })
        .to_string()
    };

    let message = |content: String, sender: &str| ReceivedMessage {
        message_id_hex: "11".repeat(32),
        source_message_id_hex: "22".repeat(32),
        sender: sender.to_owned(),
        sender_display_name: None,
        group_id: group_id.clone(),
        source_epoch: 1,
        retention: None,
        plaintext: content,
        kind: crate::notifications::MARMOT_APP_EVENT_KIND_PUSH_TOKEN_LIST,
        tags: vec![vec!["v".to_owned(), "marmot-push-v1".to_owned()]],
        recorded_at: 1,
        received_at: 1,
    };

    // Transitive list response: the owner's own-signed record, relayed by another
    // member, is applied even though `message.sender` is not the owner.
    let honest = gossip_content(&owner, &owner_id, 1000);
    app.ingest_push_gossip_message(
        "alice",
        &message(honest, &relayer),
        &[owner_id.clone(), relayer.clone()],
        cgka_traits::group::ProtocolProfile::Current,
    )
    .unwrap();
    let stored = app.group_push_tokens("alice", &group_id_hex).unwrap();
    assert_eq!(stored.len(), 1, "owner-signed transitive record applies");
    assert_eq!(stored[0].member_id_hex, owner_id);

    // Spoof: an attacker (a current member) signs a record but names the victim
    // as owner, with a strictly-newer stamp. Only the signature check can stop it
    // — and does, so the victim's record is untouched.
    let attacker = nostr::Keys::generate();
    let spoof = gossip_content(&attacker, &owner_id, 2000);
    app.ingest_push_gossip_message(
        "alice",
        &message(spoof, &relayer),
        &[owner_id.clone(), relayer, attacker.public_key().to_hex()],
        cgka_traits::group::ProtocolProfile::Current,
    )
    .unwrap();
    let stored = app.group_push_tokens("alice", &group_id_hex).unwrap();
    assert_eq!(stored.len(), 1, "spoofed record is dropped");
    assert_eq!(stored[0].owner_ts, 1000, "victim's original stamp survives");
}

#[test]
fn own_relay_echo_requires_known_event_id_not_just_pubkey() {
    let local_pubkey = "11".repeat(32);

    let known_local_delivery = relay_delivery("known", local_pubkey.clone());
    let known_event_ids = HashSet::from([hex::encode(known_local_delivery.message.id.as_slice())]);
    assert!(client::is_own_relay_echo(
        &known_local_delivery,
        &local_pubkey,
        &known_event_ids
    ));

    let same_pubkey_new_event = relay_delivery("new-cross-device", local_pubkey.clone());
    assert!(!client::is_own_relay_echo(
        &same_pubkey_new_event,
        &local_pubkey,
        &known_event_ids
    ));

    // A delivery claiming a known id under another pubkey can no longer come
    // out of the transport boundary (the id is verified against the event
    // hash, #351); forge one directly to prove the echo check independently
    // requires the local pubkey.
    let mut known_other_pubkey_delivery = relay_delivery("known", "44".repeat(32));
    known_other_pubkey_delivery.message.id = known_local_delivery.message.id.clone();
    assert!(!client::is_own_relay_echo(
        &known_other_pubkey_delivery,
        &local_pubkey,
        &known_event_ids
    ));
}

#[test]
fn account_worker_is_spawned_as_abortable_async_task() {
    let source = include_str!("runtime/account_worker.rs");

    assert!(source.contains("tokio::spawn(run_app_runtime_account_worker"));
    assert!(source.contains("managed account worker shutdown timed out; aborting"));
}

#[test]
fn account_worker_reconnect_backoff_doubles_caps_and_resets() {
    let mut backoff =
        runtime::AccountWorkerReconnectBackoff::new(Duration::from_secs(2), Duration::from_secs(8));

    assert_eq!(
        backoff.next_delay_with_jitter(Duration::ZERO),
        Duration::from_secs(2)
    );
    assert_eq!(
        backoff.next_delay_with_jitter(Duration::ZERO),
        Duration::from_secs(4)
    );
    assert_eq!(
        backoff.next_delay_with_jitter(Duration::ZERO),
        Duration::from_secs(8)
    );
    assert_eq!(
        backoff.next_delay_with_jitter(Duration::from_secs(100)),
        Duration::from_secs(8)
    );
    backoff.reset();
    assert_eq!(
        backoff.next_delay_with_jitter(Duration::ZERO),
        Duration::from_secs(2)
    );
}

#[test]
fn connectivity_recovery_interrupts_max_account_worker_reconnect_backoff() {
    run_composed_app_runtime_test("connectivity-recovery-wake", || async {
        tokio::time::pause();

        async fn wait_for_inbox_subscriptions(
            relay: &ScriptedPushRelayClient,
            account_id: &MemberId,
            minimum: usize,
        ) {
            let deadline = std::time::Instant::now() + Duration::from_secs(15);
            loop {
                let observed = relay.inbox_subscription_count(account_id);
                if observed >= minimum {
                    return;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "account inbox subscription count did not reach {minimum}; observed {observed}"
                );
                tokio::task::yield_now().await;
            }
        }

        const ACCOUNT: &str = "alice";
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        home.create_account(ACCOUNT).unwrap();
        let account_id =
            MemberId::new(hex::decode(home.account(ACCOUNT).unwrap().account_id_hex).unwrap());
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        let runtime = MarmotAppRuntime::new(app);
        runtime.start().await.unwrap();

        wait_for_inbox_subscriptions(&relay, &account_id, 1).await;

        // Preserve the bounded exponential policy and deterministically drive
        // the worker through 2, 4, 8, 16, and 32 second reconnect sleeps. The
        // next receive failure therefore arms the production 60 second cap.
        for delay in [2_u64, 4, 8, 16, 32] {
            let subscriptions_before = relay.inbox_subscription_count(&account_id);
            runtime
                .shared_services()
                .relay_plane()
                .simulate_notification_recovery_for_test(1);
            let backoff_deadline = std::time::Instant::now() + Duration::from_secs(15);
            loop {
                match runtime.unhydrated_group_count_for_test(ACCOUNT).await {
                    Err(AppError::TransportClosed) => break,
                    Ok(_) => tokio::task::yield_now().await,
                    Err(error) => panic!("unexpected reconnect probe error: {error:?}"),
                }
                assert!(
                    std::time::Instant::now() < backoff_deadline,
                    "account worker did not enter reconnect backoff"
                );
            }
            tokio::time::advance(
                Duration::from_secs(delay)
                    + Duration::from_millis(ACCOUNT_WORKER_RECONNECT_JITTER_MAX_MS + 500),
            )
            .await;
            wait_for_inbox_subscriptions(&relay, &account_id, subscriptions_before + 1).await;
        }

        let subscriptions_before_wake = relay.inbox_subscription_count(&account_id);
        let telemetry_before = runtime.app_performance_snapshot();
        runtime
            .shared_services()
            .relay_plane()
            .simulate_notification_recovery_for_test(1);
        let max_backoff_deadline = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            match runtime.unhydrated_group_count_for_test(ACCOUNT).await {
                Err(AppError::TransportClosed) => break,
                Ok(_) => tokio::task::yield_now().await,
                Err(error) => panic!("unexpected max-backoff probe error: {error:?}"),
            }
            assert!(
                std::time::Instant::now() < max_backoff_deadline,
                "account worker did not enter maximum reconnect backoff"
            );
        }

        // Repeated host recovery edges are idempotent: both callers join the
        // same reopened worker and coalesce onto its one catch-up pass.
        relay.block_next_subscribe();
        let recovery_a = {
            let runtime = runtime.clone();
            tokio::spawn(async move { runtime.catch_up_accounts().await })
        };
        let recovery_b = {
            let runtime = runtime.clone();
            tokio::spawn(async move { runtime.catch_up_accounts().await })
        };

        tokio::time::advance(Duration::from_secs(3)).await;
        let reconnect_deadline = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            if relay
                .blocked_subscribe_count
                .load(std::sync::atomic::Ordering::SeqCst)
                >= 1
            {
                break;
            }
            assert!(
                std::time::Instant::now() < reconnect_deadline,
                "connectivity recovery did not start a reconnect subscription"
            );
            tokio::task::yield_now().await;
        }
        assert_eq!(
            relay
                .blocked_subscribe_count
                .load(std::sync::atomic::Ordering::SeqCst),
            1,
            "connectivity recovery must start the reconnect subscription within three seconds"
        );
        assert!(!recovery_a.is_finished());
        assert!(!recovery_b.is_finished());
        relay.release_subscribe();

        recovery_a.await.unwrap().unwrap();
        recovery_b.await.unwrap().unwrap();
        assert_eq!(
            relay.inbox_subscription_count(&account_id),
            subscriptions_before_wake + 2,
            "two recovery signals must coalesce into one catch-up transport refresh after reconnect"
        );

        let telemetry_after = runtime.app_performance_snapshot();
        assert!(
            telemetry_after.account_transport_activation.attempts
                >= telemetry_before.account_transport_activation.attempts + 2,
            "reconnect and the one coalesced catch-up must each record a privacy-safe activation phase"
        );
        assert!(
            telemetry_after.account_subscription_registration.attempts
                >= telemetry_before.account_subscription_registration.attempts + 2,
            "reconnect and the one coalesced catch-up must each record subscription readiness"
        );

        runtime.shutdown().await;
    });
}

#[test]
fn reconnect_drains_deferred_hydration_before_steady_state_serves_groups() {
    run_composed_app_runtime_test(
        "reconnect-deferred-hydration",
        reconnect_drains_deferred_hydration_before_steady_state_serves_groups_body,
    );
}

async fn reconnect_drains_deferred_hydration_before_steady_state_serves_groups_body() {
    const ACCOUNT: &str = "bench";
    const GROUP_COUNT: usize = crate::runtime::STARTUP_HYDRATION_BATCH_SIZE_FOR_TEST + 1;

    let relay = Arc::new(ScriptedPushRelayClient::default());
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("donor").unwrap();
    home.create_account(ACCOUNT).unwrap();
    let donor_id = home.account("donor").unwrap().account_id_hex;
    let account_id =
        MemberId::new(hex::decode(home.account(ACCOUNT).unwrap().account_id_hex).unwrap());
    let mut group_ids = Vec::new();
    {
        let app_fixture = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        let mut donor = app_fixture.client("donor").await.unwrap();
        donor.publish_key_package().await.unwrap();
        let mut client = app_fixture.client(ACCOUNT).await.unwrap();
        for group in 0..GROUP_COUNT {
            group_ids.push(
                client
                    .create_group(&format!("reconnect group {group}"), &[donor_id.as_str()])
                    .await
                    .unwrap(),
            );
        }
    }
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let runtime = MarmotAppRuntime::new(app);
    runtime.start().await.unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            if relay.inbox_subscription_count(&account_id) >= 1
                && matches!(
                    runtime.unhydrated_group_count_for_test(ACCOUNT).await,
                    Ok(0)
                )
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("initial startup should finish hydration and transport activation");

    let subscriptions_before_recovery = relay.inbox_subscription_count(&account_id);
    runtime
        .shared_services()
        .relay_plane()
        .simulate_notification_recovery_for_test(3);

    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            if relay.inbox_subscription_count(&account_id) <= subscriptions_before_recovery {
                tokio::task::yield_now().await;
                continue;
            }
            match runtime.unhydrated_group_count_for_test(ACCOUNT).await {
                Ok(0) => break,
                Ok(_) | Err(AppError::TransportClosed) => tokio::task::yield_now().await,
                Err(err) => panic!("unexpected worker error during reconnect: {err:?}"),
            }
        }
    })
    .await
    .expect("notification recovery should reconnect and drain deferred hydration");

    assert_eq!(
        runtime
            .unhydrated_group_count_for_test(ACCOUNT)
            .await
            .unwrap(),
        0,
        "reconnect must drain deferred hydration before steady-state group reads"
    );

    for group_id in &group_ids {
        let members = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            runtime.group_members(ACCOUNT, group_id),
        )
        .await
        .expect("group read should succeed once reconnect is steady")
        .unwrap();
        assert!(
            !members.is_empty(),
            "every stored group must be readable once reconnect settles"
        );
    }

    runtime.shutdown().await;
}

#[test]
fn app_transport_routing_recovers_from_poisoned_lock() {
    let routing = AppTransportRouting::new(AppRoutingState {
        local_inbox_endpoints: Vec::new(),
        key_package_endpoints: Vec::new(),
        inbox_routes: HashMap::new(),
        group_routes: Vec::new(),
        required_acks: 1,
    });
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = routing.inner.write().unwrap();
        panic!("poison app routing lock");
    }));

    routing.replace(AppRoutingState {
        local_inbox_endpoints: Vec::new(),
        key_package_endpoints: Vec::new(),
        inbox_routes: HashMap::new(),
        group_routes: Vec::new(),
        required_acks: 2,
    });

    assert_eq!(routing.snapshot().required_acks, 2);
}

#[test]
fn relay_plane_rebuild_uses_persisted_cursor_with_bounded_overlap() {
    let relay_plane = MarmotRelayPlane::with_subscription_rebuild_lookback(Duration::from_secs(30));

    assert_eq!(
        relay_plane.subscription_rebuild_since(Some(1_700_000_000)),
        Some(Timestamp(1_699_999_970))
    );
    assert_eq!(
        relay_plane.subscription_rebuild_since(Some(20)),
        Some(Timestamp(0))
    );
    assert_eq!(relay_plane.subscription_rebuild_since(None), None);
    assert_eq!(
        MarmotRelayPlane::full_history().subscription_rebuild_since(Some(1_700_000_000)),
        None
    );
}

#[test]
fn agent_stream_candidate_parser_skips_malformed_quic_candidates() {
    let candidates = vec![
        "quic://".to_owned(),
        "https://127.0.0.1:4450".to_owned(),
        "quic://127.0.0.1:4450".to_owned(),
    ];

    let parsed = runtime::parse_quic_candidates(&candidates).expect("valid fallback candidate");

    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].authority, "127.0.0.1:4450");
    assert_eq!(parsed[0].server_name, "127.0.0.1");
}

#[test]
fn agent_stream_insecure_local_only_applies_to_loopback_brokers() {
    assert!(matches!(
        runtime::broker_trust_for_candidate("127.0.0.1", None, true),
        BrokerServerTrust::InsecureLocal
    ));
    assert!(matches!(
        runtime::broker_trust_for_candidate("localhost", None, true),
        BrokerServerTrust::InsecureLocal
    ));
    assert!(matches!(
        runtime::broker_trust_for_candidate("::1", None, true),
        BrokerServerTrust::InsecureLocal
    ));
    assert!(matches!(
        runtime::broker_trust_for_candidate("203.0.113.10", None, true),
        BrokerServerTrust::Platform
    ));
    assert!(matches!(
        runtime::broker_trust_for_candidate("203.0.113.10", Some(vec![1, 2, 3]), true),
        BrokerServerTrust::CertificateDer(der) if der == vec![1, 2, 3]
    ));
    // Without the explicit dev opt-in even a literal loopback candidate keeps
    // certificate verification.
    assert!(matches!(
        runtime::broker_trust_for_candidate("127.0.0.1", None, false),
        BrokerServerTrust::Platform
    ));
}

#[test]
fn agent_stream_trust_is_keyed_on_the_literal_candidate_host_not_resolution() {
    // A DOMAIN candidate never selects the no-cert-verification trust, even
    // with the dev opt-in set: a hostname that merely resolves to 127.0.0.1
    // must not downgrade trust (resolution-dependent downgrade, issue #356).
    assert!(matches!(
        runtime::broker_trust_for_candidate("broker.example", None, true),
        BrokerServerTrust::Platform
    ));
    assert!(matches!(
        runtime::broker_trust_for_candidate("broker.example", Some(vec![7]), true),
        BrokerServerTrust::CertificateDer(der) if der == vec![7]
    ));
}

#[test]
fn remembered_seen_events_are_bounded_in_memory() {
    let mut state = AccountState {
        label: "alice".to_owned(),
        seen_events: Vec::new(),
        last_transport_timestamp: None,
        groups: Vec::new(),
    };
    let mut seen = HashSet::new();

    for index in 0..(MAX_SEEN_EVENT_IDS + 2) {
        let event_id = format!("event-{index:05}");
        remember_seen_event(&mut seen, &mut state, event_id);
    }

    assert_eq!(state.seen_events.len(), MAX_SEEN_EVENT_IDS);
    // Pruning the oldest ids out of the ordered Vec must also drop them from
    // the lookup set, so the two stay the same bounded size without rebuilding.
    assert_eq!(seen.len(), MAX_SEEN_EVENT_IDS);
    assert!(!seen.contains("event-00000"));
    assert!(!seen.contains("event-00001"));
    assert!(seen.contains("event-00002"));
    assert_eq!(
        state.seen_events.first().map(String::as_str),
        Some("event-00002")
    );
    let expected_last = format!("event-{:05}", MAX_SEEN_EVENT_IDS + 1);
    assert!(seen.contains(expected_last.as_str()));
    assert_eq!(
        state.seen_events.last().map(String::as_str),
        Some(expected_last.as_str())
    );
}

#[test]
fn remember_seen_event_deduplicates_via_lookup_set() {
    let mut state = AccountState {
        label: "alice".to_owned(),
        seen_events: Vec::new(),
        last_transport_timestamp: None,
        groups: Vec::new(),
    };
    let mut seen = HashSet::new();

    remember_seen_event(&mut seen, &mut state, "dup".to_owned());
    remember_seen_event(&mut seen, &mut state, "dup".to_owned());
    remember_seen_event(&mut seen, &mut state, "other".to_owned());

    assert_eq!(
        state.seen_events,
        vec!["dup".to_owned(), "other".to_owned()]
    );
    assert_eq!(seen.len(), 2);
    assert!(seen.contains("dup"));
    assert!(seen.contains("other"));
}

const SENDER_HEX: &str = "aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55";

fn build(intent: AppMessageIntent) -> MarmotInnerEvent {
    build_inner_event(&intent, SENDER_HEX, 1_700_000_000).unwrap()
}

#[test]
fn chat_intent_builds_kind_nine_with_no_tags() {
    let event = build(AppMessageIntent::Chat {
        content: "hello".to_owned(),
    });
    assert_eq!(event.kind, MARMOT_APP_EVENT_KIND_CHAT);
    assert_eq!(event.content, "hello");
    assert!(event.tags.is_empty());
    assert_eq!(event.pubkey, SENDER_HEX);
}

#[test]
fn reaction_intent_builds_kind_seven_with_e_tag() {
    let event = build(AppMessageIntent::Reaction {
        target_message_id: "abc123".to_owned(),
        emoji: "🔥".to_owned(),
    });
    assert_eq!(event.kind, MARMOT_APP_EVENT_KIND_REACTION);
    assert_eq!(event.content, "🔥");
    assert_eq!(tag_value(&event.tags, EVENT_REF_TAG), Some("abc123"));
}

#[test]
fn reaction_intent_rejects_empty_emoji() {
    let result = build_inner_event(
        &AppMessageIntent::Reaction {
            target_message_id: "abc123".to_owned(),
            emoji: "  ".to_owned(),
        },
        SENDER_HEX,
        1,
    );
    assert!(matches!(result, Err(AppError::InvalidAppMessagePayload(_))));
}

#[test]
fn reaction_intent_rejects_padded_content() {
    for emoji in [" 👀", "👀 ", "\t👀"] {
        let error = build_inner_event(
            &AppMessageIntent::Reaction {
                target_message_id: "target-message".to_owned(),
                emoji: emoji.to_owned(),
            },
            SENDER_HEX,
            1,
        )
        .unwrap_err();
        assert!(error.to_string().contains("leading or trailing whitespace"));
    }
}

#[test]
fn reaction_intent_rejects_control_characters_and_oversized_content() {
    for emoji in ["👀\nspoof", "👀\u{001b}[31m"] {
        let result = build_inner_event(
            &AppMessageIntent::Reaction {
                target_message_id: "abc123".to_owned(),
                emoji: emoji.to_owned(),
            },
            SENDER_HEX,
            1,
        );
        assert!(matches!(result, Err(AppError::InvalidAppMessagePayload(_))));
    }

    let result = build_inner_event(
        &AppMessageIntent::Reaction {
            target_message_id: "abc123".to_owned(),
            emoji: "👍".repeat(65),
        },
        SENDER_HEX,
        1,
    );
    assert!(matches!(result, Err(AppError::InvalidAppMessagePayload(_))));
}

#[test]
fn reaction_intent_accepts_bounded_multi_scalar_emoji() {
    let event = build_inner_event(
        &AppMessageIntent::Reaction {
            target_message_id: "abc123".to_owned(),
            emoji: "👨‍👩‍👧‍👦".to_owned(),
        },
        SENDER_HEX,
        1,
    )
    .unwrap();
    assert_eq!(event.content, "👨‍👩‍👧‍👦");
}

#[test]
fn reaction_intent_accepts_exact_maximum_scalar_count() {
    let emoji = "👍".repeat(64);
    let event = build_inner_event(
        &AppMessageIntent::Reaction {
            target_message_id: "abc123".to_owned(),
            emoji: emoji.clone(),
        },
        SENDER_HEX,
        1,
    )
    .unwrap();
    assert_eq!(event.content, emoji);
}

#[test]
fn delete_intent_builds_empty_kind_five_with_e_tag() {
    let event = build(AppMessageIntent::Delete {
        target_message_id: "abc123".to_owned(),
    });
    assert_eq!(event.kind, MARMOT_APP_EVENT_KIND_DELETE);
    assert_eq!(event.content, "");
    assert_eq!(tag_value(&event.tags, EVENT_REF_TAG), Some("abc123"));
}

#[test]
fn delete_reactions_intent_builds_one_kind_five_with_all_e_tags() {
    let event = build(AppMessageIntent::DeleteReactions {
        reaction_message_ids: vec!["reaction-one".to_owned(), "reaction-two".to_owned()],
    });
    assert_eq!(event.kind, MARMOT_APP_EVENT_KIND_DELETE);
    assert_eq!(event.content, "");
    assert_eq!(
        tag_values(&event.tags, EVENT_REF_TAG),
        vec!["reaction-one", "reaction-two"]
    );
}

#[test]
fn reply_intent_builds_kind_nine_with_e_and_q_tags() {
    let event = build(AppMessageIntent::Reply {
        target_message_id: "parent".to_owned(),
        text: "sure".to_owned(),
    });
    assert_eq!(event.kind, MARMOT_APP_EVENT_KIND_CHAT);
    assert_eq!(event.content, "sure");
    assert_eq!(tag_value(&event.tags, EVENT_REF_TAG), Some("parent"));
    assert_eq!(tag_value(&event.tags, QUOTE_REF_TAG), Some("parent"));
}

#[test]
fn media_intent_builds_kind_nine_with_ordered_imeta_tags() {
    let event = build(AppMessageIntent::Media {
        attachments: vec![
            MediaAttachmentReference {
                locators: vec![MediaLocator {
                    kind: "blossom-v1".to_owned(),
                    value: format!("https://media.example/{}.bin", hex::encode([0x33_u8; 32])),
                }],
                ciphertext_sha256: hex::encode([0x33_u8; 32]),
                plaintext_sha256: hex::encode([0x11_u8; 32]),
                nonce_hex: hex::encode([0x22_u8; 12]),
                file_name: "a.png".to_owned(),
                media_type: "image/png".to_owned(),
                version: ENCRYPTED_MEDIA_VERSION.to_owned(),
                source_epoch: 7,
                dim: Some("10x20".to_owned()),
                thumbhash: Some("thumb".to_owned()),
            },
            MediaAttachmentReference {
                locators: vec![MediaLocator {
                    kind: "blossom-v1".to_owned(),
                    value: format!("https://media.example/{}.bin", hex::encode([0x44_u8; 32])),
                }],
                ciphertext_sha256: hex::encode([0x44_u8; 32]),
                plaintext_sha256: hex::encode([0x55_u8; 32]),
                nonce_hex: hex::encode([0x66_u8; 12]),
                file_name: "b.mp4".to_owned(),
                media_type: "video/mp4".to_owned(),
                version: ENCRYPTED_MEDIA_VERSION.to_owned(),
                source_epoch: 7,
                dim: None,
                thumbhash: None,
            },
        ],
        caption: Some("cap".to_owned()),
    });
    assert_eq!(event.kind, MARMOT_APP_EVENT_KIND_CHAT);
    assert_eq!(event.content, "cap");
    let imeta = event
        .tags
        .iter()
        .filter(|tag| tag.first().map(String::as_str) == Some("imeta"))
        .collect::<Vec<_>>();
    assert_eq!(imeta.len(), 2);
    assert!(imeta[0].iter().any(|field| field
        == &format!(
            "locator blossom-v1 https://media.example/{}.bin",
            hex::encode([0x33_u8; 32])
        )));
    assert!(imeta[0].iter().any(|field| field == "m image/png"));
    assert!(imeta[0].iter().any(|field| field == "filename a.png"));
    assert!(
        imeta[0]
            .iter()
            .any(|field| field == "nonce 222222222222222222222222")
    );
    assert!(imeta[0].iter().any(|field| field == "v encrypted-media-v1"));
    assert!(imeta[0].iter().any(|field| field == "thumbhash thumb"));
    assert!(imeta[1].iter().any(|field| field
        == &format!(
            "locator blossom-v1 https://media.example/{}.bin",
            hex::encode([0x44_u8; 32])
        )));
}

#[test]
fn stream_start_intent_builds_kind_1200_with_broker_tags() {
    let parent_message_id = "cd".repeat(32);
    let event = build(AppMessageIntent::StreamStart {
        stream_id: vec![0xab; 32],
        parent_message_id: Some(parent_message_id.clone()),
        quic_candidates: vec![
            "quic://broker.example:4450".to_owned(),
            "quic://[::1]:4450".to_owned(),
        ],
    });
    assert_eq!(event.kind, MARMOT_APP_EVENT_KIND_AGENT_STREAM_START);
    assert_eq!(event.content, "");
    let start = StreamStartView::from_event(event.kind, &event.tags).unwrap();
    assert_eq!(start.stream_id_hex, hex::encode([0xab; 32]));
    assert_eq!(start.route, STREAM_ROUTE_QUIC);
    assert_eq!(
        start.quic_candidates,
        vec![
            "quic://broker.example:4450".to_owned(),
            "quic://[::1]:4450".to_owned(),
        ]
    );
    assert_eq!(tag_value(&event.tags, STREAM_TYPE_TAG), Some("text"));
    assert_eq!(tag_value(&event.tags, STREAM_FINAL_KIND_TAG), Some("9"));
    assert_eq!(
        tag_value(&event.tags, STREAM_PARENT_TAG),
        Some(parent_message_id.as_str())
    );
}

#[test]
fn stream_start_intent_without_parent_omits_parent_tag() {
    let event = build(AppMessageIntent::StreamStart {
        stream_id: vec![0xab; 32],
        parent_message_id: None,
        quic_candidates: vec!["quic://broker.example:4450".to_owned()],
    });
    assert_eq!(tag_value(&event.tags, STREAM_PARENT_TAG), None);
}

#[test]
fn stream_start_intent_accepts_zero_brokers_for_durable_fallback() {
    let event = build(AppMessageIntent::StreamStart {
        stream_id: vec![0xab; 32],
        parent_message_id: None,
        quic_candidates: Vec::new(),
    });
    let start = StreamStartView::from_event(event.kind, &event.tags).unwrap();
    assert!(start.quic_candidates.is_empty());
}

#[test]
fn stream_start_intent_rejects_each_malformed_broker_value() {
    for candidate in [
        "   ",
        "https://broker.example:4450",
        "quic://broker.example",
    ] {
        let result = build_inner_event(
            &AppMessageIntent::StreamStart {
                stream_id: vec![0xab; 32],
                parent_message_id: None,
                quic_candidates: vec![candidate.to_owned()],
            },
            SENDER_HEX,
            1,
        );
        assert!(matches!(
            result,
            Err(AppError::AgentStreamInvalidCandidate(_))
        ));
    }
}

#[test]
fn stream_start_intent_rejects_a_non_message_id_parent() {
    let result = build_inner_event(
        &AppMessageIntent::StreamStart {
            stream_id: vec![0xab; 32],
            parent_message_id: Some("abcd".to_owned()),
            quic_candidates: vec!["quic://broker.example:4450".to_owned()],
        },
        SENDER_HEX,
        1,
    );
    assert!(matches!(result, Err(AppError::InvalidAppMessagePayload(_))));
}

#[test]
fn stream_final_intent_builds_kind_nine_stream_final() {
    let start_event_id = "aa".repeat(32);
    let event = build(AppMessageIntent::StreamFinal {
        request: AgentTextStreamFinishRequest {
            stream_id: vec![0xcd; 32],
            start_event_id: start_event_id.clone(),
            final_text_or_reference: "done".to_owned(),
            transcript_hash: [0xee; 32],
            chunk_count: 3,
            finished_at: 9,
        },
    });
    assert_eq!(event.kind, MARMOT_APP_EVENT_KIND_CHAT);
    assert_eq!(event.content, "done");
    assert!(is_stream_final_event(event.kind, &event.tags));
    assert_eq!(
        tag_value(&event.tags, STREAM_TAG),
        Some(hex::encode([0xcd; 32]).as_str())
    );
    assert_eq!(
        tag_value(&event.tags, STREAM_START_TAG),
        Some(start_event_id.as_str())
    );
    assert_eq!(
        tag_value(&event.tags, STREAM_HASH_TAG),
        Some(hex::encode([0xee; 32]).as_str())
    );
    assert_eq!(tag_value(&event.tags, STREAM_CHUNKS_TAG), Some("3"));
}

#[test]
fn agent_activity_intent_builds_kind_1201_json_payload() {
    let event = build(AppMessageIntent::AgentActivity {
        status: "thinking".to_owned(),
        text: "Thinking".to_owned(),
        reply_to_message_id: Some("parent".to_owned()),
        extra: None,
    });
    assert_eq!(event.kind, MARMOT_APP_EVENT_KIND_AGENT_ACTIVITY);
    assert_eq!(
        tag_value(&event.tags, AGENT_ACTIVITY_STATUS_TAG),
        Some("thinking")
    );
    assert_eq!(tag_value(&event.tags, EVENT_REF_TAG), Some("parent"));
    let content: serde_json::Value = serde_json::from_str(&event.content).unwrap();
    assert_eq!(content["v"], 1);
    assert_eq!(content["status"], "thinking");
    assert_eq!(content["text"], "Thinking");
}

#[test]
fn agent_operation_intent_builds_kind_1202_json_payload() {
    let event = build(AppMessageIntent::AgentOperation {
        event_type: "tool_call".to_owned(),
        status: "started".to_owned(),
        operation_id: Some("call-123".to_owned()),
        run_id: Some("run-1".to_owned()),
        turn_id: Some("turn-1".to_owned()),
        name: Some("search".to_owned()),
        text: "Searching".to_owned(),
        preview: Some("glp-1".to_owned()),
        details: Some(serde_json::json!({"args": {"query": "glp-1"}})),
        sequence: Some(2),
        ok: None,
        duration_ms: None,
        reply_to_message_id: Some("parent".to_owned()),
    });
    assert_eq!(event.kind, MARMOT_APP_EVENT_KIND_AGENT_OPERATION);
    assert_eq!(
        tag_value(&event.tags, AGENT_OPERATION_STATUS_TAG),
        Some("started")
    );
    assert_eq!(
        tag_value(&event.tags, AGENT_OPERATION_TYPE_TAG),
        Some("tool_call")
    );
    assert_eq!(
        tag_value(&event.tags, AGENT_OPERATION_NAME_TAG),
        Some("search")
    );
    assert_eq!(tag_value(&event.tags, EVENT_REF_TAG), Some("parent"));
    let content: serde_json::Value = serde_json::from_str(&event.content).unwrap();
    assert_eq!(content["event_type"], "tool_call");
    assert_eq!(content["status"], "started");
    assert_eq!(content["operation_id"], "call-123");
    assert_eq!(content["run_id"], "run-1");
    assert_eq!(content["turn_id"], "turn-1");
    assert_eq!(content["name"], "search");
    assert_eq!(content["preview"], "glp-1");
    assert_eq!(content["details"]["args"]["query"], "glp-1");
    assert_eq!(content["sequence"], 2);
}

#[test]
fn group_system_intent_builds_kind_1210_json_payload() {
    let event = build(AppMessageIntent::GroupSystem {
        system_type: "member_added".to_owned(),
        text: "Member added".to_owned(),
        data: Some(serde_json::json!({"member": "alice"})),
    });
    assert_eq!(event.kind, MARMOT_APP_EVENT_KIND_GROUP_SYSTEM);
    assert_eq!(
        tag_value(&event.tags, GROUP_SYSTEM_TYPE_TAG),
        Some("member_added")
    );
    let content: serde_json::Value = serde_json::from_str(&event.content).unwrap();
    assert_eq!(content["system_type"], "member_added");
    assert_eq!(content["text"], "Member added");
    assert_eq!(content["data"]["member"], "alice");
    assert!(content.get("status").is_none());
}

#[test]
fn custom_intent_passes_kind_tags_and_content_through_verbatim() {
    let event = build(AppMessageIntent::Custom {
        kind: 30078,
        tags: vec![
            vec!["d".to_owned(), "game-1".to_owned()],
            vec!["move".to_owned(), "e4".to_owned()],
        ],
        content: "{\"move\":\"e4\"}".to_owned(),
    });
    assert_eq!(event.kind, 30078);
    assert_eq!(
        event.tags,
        vec![
            vec!["d".to_owned(), "game-1".to_owned()],
            vec!["move".to_owned(), "e4".to_owned()]
        ]
    );
    assert_eq!(event.content, "{\"move\":\"e4\"}");
    assert_eq!(event.pubkey, SENDER_HEX);
}

#[test]
fn custom_intent_rejects_every_reserved_kind() {
    use cgka_traits::app_event as kinds;
    for kind in [
        kinds::MARMOT_APP_EVENT_KIND_DELETE,
        kinds::MARMOT_APP_EVENT_KIND_REACTION,
        kinds::MARMOT_APP_EVENT_KIND_CHAT,
        kinds::MARMOT_APP_EVENT_KIND_EDIT,
        kinds::MARMOT_APP_EVENT_KIND_AGENT_STREAM_START,
        kinds::MARMOT_APP_EVENT_KIND_AGENT_ACTIVITY,
        kinds::MARMOT_APP_EVENT_KIND_AGENT_OPERATION,
        kinds::MARMOT_APP_EVENT_KIND_GROUP_SYSTEM,
        MARMOT_APP_EVENT_KIND_PUSH_TOKEN_UPDATE,
        MARMOT_APP_EVENT_KIND_PUSH_TOKEN_LIST,
        MARMOT_APP_EVENT_KIND_PUSH_TOKEN_REMOVAL,
    ] {
        assert!(crate::is_reserved_app_event_kind(kind));
        let result = build_inner_event(
            &AppMessageIntent::Custom {
                kind,
                tags: Vec::new(),
                content: String::new(),
            },
            SENDER_HEX,
            1,
        );
        assert!(
            matches!(result, Err(AppError::InvalidAppMessagePayload(_))),
            "reserved kind {kind} must be rejected"
        );
    }
    assert!(!crate::is_reserved_app_event_kind(30078));
}

#[test]
fn custom_intent_audit_action_is_send_custom_event() {
    let context = AppClient::message_human_action_context(&AppMessageIntent::Custom {
        kind: 30078,
        tags: Vec::new(),
        content: String::new(),
    })
    .expect("custom events are user-authored actions");
    assert_eq!(
        context
            .human_action
            .as_ref()
            .map(|action| action.action.as_str()),
        Some("send_custom_event")
    );
}

#[test]
fn received_event_decodes_when_id_and_sender_match() {
    let event = build(AppMessageIntent::Chat {
        content: "hi".to_owned(),
    });
    let inner_created_at = event.created_at;
    let bytes = event.encode().unwrap();
    let group_id = GroupId::new(vec![0x01]);
    let message = groups::decode_received_event(
        &bytes,
        SENDER_HEX,
        None,
        &group_id,
        0,
        None,
        "msg1",
        1_700_000_000,
        Some(42),
        false,
    )
    .expect("valid event is accepted");
    assert_eq!(message.plaintext, "hi");
    assert_eq!(message.kind, MARMOT_APP_EVENT_KIND_CHAT);
    assert_eq!(message.sender, SENDER_HEX);
    assert_eq!(message.recorded_at, inner_created_at);
    assert_eq!(message.received_at, 1_700_000_000);
}

#[test]
fn received_media_message_with_out_of_policy_locator_is_still_delivered() {
    // PR #328 review Finding 2 (core regression): a delayed media message
    // whose locator kind is no longer in the group's current policy MUST
    // still be delivered. Ingest is purely structural, so `decode_received_event`
    // keeps a structurally well-formed media reference regardless of locator
    // policy; fetchability is decided later at download time.
    let event = build(AppMessageIntent::Media {
        attachments: vec![MediaAttachmentReference {
            // A locator kind that is not the default `blossom-v1` and would be
            // out of a blossom-only policy.
            locators: vec![MediaLocator {
                kind: "ipfs-v1".to_owned(),
                value: "ipfs://bafybeigdyrexample".to_owned(),
            }],
            ciphertext_sha256: hex::encode([0x33_u8; 32]),
            plaintext_sha256: hex::encode([0x11_u8; 32]),
            nonce_hex: hex::encode([0x22_u8; 12]),
            file_name: "a.png".to_owned(),
            media_type: "image/png".to_owned(),
            version: ENCRYPTED_MEDIA_VERSION.to_owned(),
            source_epoch: 7,
            dim: None,
            thumbhash: None,
        }],
        caption: Some("delayed media".to_owned()),
    });
    let bytes = event.encode().unwrap();
    let group_id = GroupId::new(vec![0x01]);
    let message = groups::decode_received_event(
        &bytes, SENDER_HEX, None, &group_id, 7, None, "msg1", 0, None, false,
    )
    .expect("an out-of-policy media locator must not drop the message");
    assert_eq!(message.plaintext, "delayed media");
    assert!(
        message
            .tags
            .iter()
            .any(|tag| tag.first().map(String::as_str) == Some("imeta")),
        "the imeta tag is preserved on the delivered message",
    );
}

fn malformed_media_message(version: &str) -> Vec<u8> {
    let mut event = build(AppMessageIntent::Media {
        attachments: vec![MediaAttachmentReference {
            locators: vec![MediaLocator {
                kind: "blossom-v1".to_owned(),
                value: "https://media.example/a.png".to_owned(),
            }],
            ciphertext_sha256: hex::encode([0x33_u8; 32]),
            plaintext_sha256: hex::encode([0x11_u8; 32]),
            nonce_hex: hex::encode([0x22_u8; 12]),
            file_name: "a.png".to_owned(),
            media_type: "image/png".to_owned(),
            version: version.to_owned(),
            source_epoch: 7,
            dim: None,
            thumbhash: None,
        }],
        caption: None,
    });
    // Corrupt the ciphertext hash in the serialized imeta tag, then recompute
    // the canonical id so the message passes id/sender checks. The malformed
    // attachment must remain local to attachment rendering.
    for tag in &mut event.tags {
        for field in tag.iter_mut() {
            if let Some(rest) = field.strip_prefix("ciphertext_sha256 ") {
                let _ = rest;
                *field = "ciphertext_sha256 not-a-valid-hash".to_owned();
            }
        }
    }
    event.id = cgka_traits::canonical_event_id(
        &event.pubkey,
        event.created_at,
        event.kind,
        &event.tags,
        &event.content,
    );
    event.encode().unwrap()
}

#[test]
fn received_media_message_with_malformed_v1_reference_is_rejected() {
    // Frozen V1 made a structurally malformed reference message-fatal. The V2
    // attachment-local rule must not silently change legacy ingest behavior.
    let bytes = malformed_media_message(ENCRYPTED_MEDIA_VERSION);
    let group_id = GroupId::new(vec![0x01]);
    assert!(
        groups::decode_received_event(
            &bytes, SENDER_HEX, None, &group_id, 7, None, "msg1", 0, None, false,
        )
        .is_none(),
        "a malformed V1 attachment must retain frozen message-fatal behavior",
    );
}

#[test]
fn received_media_message_with_malformed_v2_reference_keeps_the_message() {
    // V2 rejects malformed references attachment-locally, preserving the
    // caption, event, and any valid sibling attachments.
    let bytes = malformed_media_message(cgka_traits::app_components::ENCRYPTED_MEDIA_FORMAT_V2);
    let group_id = GroupId::new(vec![0x01]);
    assert!(
        groups::decode_received_event(
            &bytes, SENDER_HEX, None, &group_id, 7, None, "msg1", 0, None, false,
        )
        .is_some(),
        "a malformed V2 attachment must not drop its carrying message",
    );
}

#[test]
fn received_event_with_tampered_id_is_rejected() {
    let mut event = build(AppMessageIntent::Chat {
        content: "hi".to_owned(),
    });
    // Mutate the content without recomputing the id: the canonical id no
    // longer matches, so the strict decoder must reject it.
    event.content = "tampered".to_owned();
    let bytes = serde_json::to_vec(&event).unwrap();
    let group_id = GroupId::new(vec![0x01]);
    assert!(
        groups::decode_received_event(
            &bytes, SENDER_HEX, None, &group_id, 0, None, "msg1", 0, None, false,
        )
        .is_none()
    );
}

#[test]
fn received_event_with_wrong_sender_is_rejected() {
    let event = build(AppMessageIntent::Chat {
        content: "hi".to_owned(),
    });
    let bytes = event.encode().unwrap();
    let group_id = GroupId::new(vec![0x01]);
    let other_sender = "bb66bb66bb66bb66bb66bb66bb66bb66bb66bb66bb66bb66bb66bb66bb66bb66";
    // The inner pubkey is SENDER_HEX, but MLS authenticated `other_sender`.
    assert!(
        groups::decode_received_event(
            &bytes,
            other_sender,
            None,
            &group_id,
            0,
            None,
            "msg1",
            0,
            None,
            false,
        )
        .is_none()
    );
}

#[test]
fn inner_event_id_matches_nostr_sdk_event_id() {
    use nostr::{EventId, Keys, Kind, Tag, Tags, Timestamp};

    let keys = Keys::generate();
    let pubkey = keys.public_key();
    let created_at = 1_700_000_123_u64;
    let kind = MARMOT_APP_EVENT_KIND_CHAT;
    let tags = vec![
        vec![EVENT_REF_TAG.to_owned(), "parent-id".to_owned()],
        vec![QUOTE_REF_TAG.to_owned(), "parent-id".to_owned()],
    ];
    let content = "hello from marmot 🦫";

    // Our canonical id over the unsigned-event preimage.
    let ours = cgka_traits::canonical_event_id(&pubkey.to_hex(), created_at, kind, &tags, content);

    // The nostr SDK's NIP-01 id for the same {pubkey, created_at, kind,
    // tags, content}. If these diverge, external Nostr clients would reject
    // our inner event id.
    let sdk_tags = Tags::from_list(
        tags.iter()
            .map(|tag| Tag::parse(tag.clone()).unwrap())
            .collect(),
    );
    let theirs = EventId::new(
        &pubkey,
        &Timestamp::from(created_at),
        &Kind::from(kind as u16),
        &sdk_tags,
        content,
    );

    assert_eq!(ours, theirs.to_hex());
}

#[test]
fn app_error_display_does_not_expose_group_or_account_ids() {
    let group_id = "aa".repeat(32);
    let account_id = "bb".repeat(32);
    let errors = [
        AppError::UnknownGroup(group_id.clone()).to_string(),
        AppError::MissingKeyPackage(account_id.clone()).to_string(),
        AppError::MissingDirectoryEntry(account_id.clone()).to_string(),
        AppError::AccountHome(AccountHomeError::SecretNotFound(account_id.clone())).to_string(),
    ];

    for error in errors {
        assert!(!error.contains(&group_id), "{error}");
        assert!(!error.contains(&account_id), "{error}");
    }
}

#[test]
fn telemetry_install_id_is_stable_uuid_per_app_root() {
    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");

    let first = app.telemetry_install_id().unwrap();
    let second = app.telemetry_install_id().unwrap();
    let reopened = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .telemetry_install_id()
        .unwrap();

    assert_eq!(first, second);
    assert_eq!(first, reopened);
    assert_eq!(first.len(), 36);
    assert_eq!(first.as_bytes()[14], b'4');
    assert_eq!(first.chars().filter(|ch| *ch == '-').count(), 4);
    assert_ne!(first.len(), AUDIT_ID_BYTES * 2);
}

#[test]
fn relay_telemetry_settings_persist_in_shared_storage() {
    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");

    assert_eq!(
        app.relay_telemetry_settings().unwrap(),
        RelayTelemetrySettings::default()
    );

    let updated = RelayTelemetrySettings {
        export_enabled: true,
        export_interval_seconds: 30,
    };
    let stored = app.set_relay_telemetry_settings(updated).unwrap();

    assert_eq!(
        stored,
        RelayTelemetrySettings {
            export_enabled: true,
            export_interval_seconds: 30,
        }
    );
    assert_eq!(
        app.relay_telemetry_export_config().unwrap(),
        RelayTelemetryExportConfig {
            enabled: true,
            endpoint: None,
            interval: Duration::from_secs(30),
            authorization_bearer_token: None,
            resource: None,
        }
    );

    let reopened = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    assert_eq!(reopened.relay_telemetry_settings().unwrap(), stored);
}

#[test]
fn relay_telemetry_settings_reject_zero_interval() {
    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");

    let err = app
        .set_relay_telemetry_settings(RelayTelemetrySettings {
            export_interval_seconds: 0,
            ..Default::default()
        })
        .expect_err("zero interval should be rejected");

    assert!(matches!(err, AppError::InvalidRelayTelemetrySettings(_)));
}

#[test]
fn relay_telemetry_settings_reject_invalid_persisted_interval() {
    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    app.shared_storage()
        .unwrap()
        .set_relay_telemetry_settings(&StoredRelayTelemetrySettings {
            export_enabled: true,
            export_interval_seconds: 0,
        })
        .unwrap();

    let err = app
        .relay_telemetry_settings()
        .expect_err("invalid persisted interval should be rejected");

    assert!(matches!(err, AppError::InvalidRelayTelemetrySettings(_)));
}

#[test]
fn source_epoch_retention_is_app_visible_and_returns_media_hashes_when_expired() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let account = home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    app.save_state(&AccountState {
        label: "alice".to_owned(),
        seen_events: Vec::new(),
        last_transport_timestamp: None,
        groups: vec![AppGroupRecord::new(
            "aa".to_owned(),
            AppGroupNostrRoutingComponent::new(
                NostrRoutingV1::new([0xAA; 32], vec!["wss://relay.example".to_owned()]).unwrap(),
            )
            .unwrap(),
            "alpha".to_owned(),
            String::new(),
            AppGroupImageInput::default(),
            AppGroupAdminPolicyComponent::new(Vec::new()),
            AppGroupMessageRetentionComponent::disabled(),
        )],
    })
    .unwrap();
    let media_hash = "ef".repeat(32);
    app.record_account_app_event_at(
        "alice",
        &AppMessageProjection {
            message_id_hex: "old-aa".to_owned(),
            source_message_id_hex: None,
            direction: "received".to_owned(),
            group_id_hex: "aa".to_owned(),
            sender: account.account_id_hex,
            plaintext: "expired plaintext".to_owned(),
            kind: MARMOT_APP_EVENT_KIND_CHAT,
            tags: vec![vec![
                "imeta".to_owned(),
                "v encrypted-media-v1".to_owned(),
                format!("ciphertext_sha256 {media_hash}"),
            ]],
            source_epoch: Some(7),
            retention: Some(AppMessageRetentionDecision::new(10, 5)),
            recorded_at: Some(10),
            origin_commit_id: None,
            moderation_grant: false,
        },
        100,
    )
    .unwrap();
    let stored = app.messages("alice").unwrap();
    assert_eq!(stored[0].recorded_at, 10);
    assert_eq!(stored[0].received_at, 100);
    assert_eq!(
        stored[0].retention,
        Some(AppMessageRetentionDecision::new(10, 5))
    );
    // Expiry follows the authenticated source decision even though this
    // device observed the message well after its deadline.
    assert!(
        app.chat_list_row("alice", "aa")
            .unwrap()
            .unwrap()
            .last_message
            .is_some()
    );

    let outcome = app
        .secure_prune_expired_account_app_events("alice", "aa", 15)
        .unwrap();

    assert_eq!(outcome.pruned_messages, 1);
    assert_eq!(outcome.media_ciphertext_sha256, vec![media_hash]);
    assert!(
        app.chat_list_row("alice", "aa")
            .unwrap()
            .unwrap()
            .last_message
            .is_none()
    );
}

/// Issue #363 app-layer regression: a `GroupStateInvalidated` event flowing
/// through the sync loop's invalidation dispatch must tombstone every
/// persisted kind-1210 system row stamped with the superseded commit's
/// `origin_commit_id` — and only those rows. A duplicate withdrawal must be a
/// projection no-op.
#[test]
fn group_state_invalidated_event_tombstones_origin_commit_system_rows() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let account = home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    app.save_state(&AccountState {
        label: "alice".to_owned(),
        seen_events: Vec::new(),
        last_transport_timestamp: None,
        groups: vec![AppGroupRecord::new(
            "aa".to_owned(),
            AppGroupNostrRoutingComponent::new(
                NostrRoutingV1::new([0xAA; 32], vec!["wss://relay.example".to_owned()]).unwrap(),
            )
            .unwrap(),
            "alpha".to_owned(),
            String::new(),
            AppGroupImageInput::default(),
            AppGroupAdminPolicyComponent::new(Vec::new()),
            AppGroupMessageRetentionComponent::disabled(),
        )],
    })
    .unwrap();

    let losing_commit_id = cgka_traits::types::MessageId::new(vec![0xBE; 32]);
    let system_row =
        |message_id_hex: &str, origin_commit_id: Option<String>| AppMessageProjection {
            message_id_hex: message_id_hex.to_owned(),
            // Synthesized system rows carry no source id (see
            // build_group_system_projection); origin_commit_id is the 1:N link.
            source_message_id_hex: None,
            direction: "system".to_owned(),
            group_id_hex: "aa".to_owned(),
            sender: account.account_id_hex.clone(),
            plaintext: "renamed the group".to_owned(),
            kind: MARMOT_APP_EVENT_KIND_GROUP_SYSTEM,
            tags: Vec::new(),
            source_epoch: Some(2),
            retention: None,
            recorded_at: Some(10),
            origin_commit_id,
            moderation_grant: false,
        };
    // The losing commit synthesized this row (the "B renamed the group" lie).
    app.record_account_app_event(
        "alice",
        &system_row(
            "losing-rename",
            Some(hex::encode(losing_commit_id.as_slice())),
        ),
    )
    .unwrap();
    // A different (winning) commit's row must survive the withdrawal.
    app.record_account_app_event(
        "alice",
        &system_row("winning-rename", Some("cf".repeat(32))),
    )
    .unwrap();

    let withdrawal = cgka_traits::engine::GroupEvent::GroupStateInvalidated {
        group_id: GroupId::new(vec![0xAA]),
        epoch: cgka_traits::EpochId(1),
        invalidated_commit_id: losing_commit_id,
        reason: cgka_traits::engine::GroupStateInvalidationReason::SupersededByBranchSelection,
    };
    let update = app
        .projection_update_for_invalidation_event("alice", &withdrawal)
        .unwrap()
        .expect("withdrawal must invalidate the stamped system row");
    assert_eq!(update.group_id_hex, "aa");

    let rows = app
        .timeline_messages_with_query(
            "alice",
            storage_sqlite::TimelineMessageQuery {
                group_id_hex: Some("aa".to_owned()),
                ..storage_sqlite::TimelineMessageQuery::default()
            },
        )
        .unwrap()
        .messages;
    let status = |id: &str| {
        rows.iter()
            .find(|row| row.message_id_hex == id)
            .map(|row| row.invalidation_status.clone())
    };
    assert_eq!(
        status("losing-rename"),
        Some(Some("SupersededByBranchSelection".to_owned())),
        "the superseded commit's row must be tombstoned with the withdrawal reason"
    );
    assert_eq!(
        status("winning-rename"),
        Some(None),
        "rows attributed to other commits must stay live"
    );

    // Duplicate withdrawal (replayed event): projection no-op, reason kept.
    assert!(
        app.projection_update_for_invalidation_event("alice", &withdrawal)
            .unwrap()
            .is_none(),
        "a replayed withdrawal must not produce another projection update"
    );
    // Events that carry no timeline invalidation dispatch to None.
    assert!(
        app.projection_update_for_invalidation_event(
            "alice",
            &cgka_traits::engine::GroupEvent::CommitRolledBack {
                group_id: GroupId::new(vec![0xAA]),
                invalidated_commit_id: cgka_traits::types::MessageId::new(vec![0xCF; 32]),
            },
        )
        .unwrap()
        .is_none(),
        "commit-level rollback events must not tombstone; GroupStateInvalidated is authoritative"
    );
}

/// Issue #1177: a send the engine accepted but never published derives as
/// `Pending`, which is truthful only while convergence can still release it.
/// Once the group is terminal the queue is purged, so the sweep the sync loop
/// runs at that seam must stop the row claiming `Pending` forever — and must
/// leave a published send's `Delivered` alone.
///
/// The swept row's terminal outcome is asserted where it is stored, on the row
/// itself. #1384 deliberately demotes a failed local send out of the chat
/// preview ("keep failed local sends visible without letting them pin chat
/// previews", `chat_list_preview_order_desc` in `storage-sqlite/src/chat_list.rs`),
/// so once a send that did reach the relay exists the preview falls back to it
/// rather than rendering the swept row's `Failed`. That fallback is asserted
/// here too, because it is the same thing this test guards: after the sweep
/// nothing in the group may still say `Pending`. A swept row rendering `Failed`
/// when it *is* the preview is pinned by `storage-sqlite`'s
/// `latest_preview_carries_exact_media_and_delivery_projection`.
#[test]
fn sweeping_a_terminal_group_stops_a_held_send_from_claiming_pending() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let account = home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    app.save_state(&AccountState {
        label: "alice".to_owned(),
        seen_events: Vec::new(),
        last_transport_timestamp: None,
        groups: vec![AppGroupRecord::new(
            "aa".to_owned(),
            AppGroupNostrRoutingComponent::new(
                NostrRoutingV1::new([0xAA; 32], vec!["wss://relay.example".to_owned()]).unwrap(),
            )
            .unwrap(),
            "alpha".to_owned(),
            String::new(),
            AppGroupImageInput::default(),
            AppGroupAdminPolicyComponent::new(Vec::new()),
            AppGroupMessageRetentionComponent::disabled(),
        )],
    })
    .unwrap();

    let sent = |message_id_hex: &str, source_message_id_hex: Option<String>, recorded_at: u64| {
        AppMessageProjection {
            message_id_hex: message_id_hex.to_owned(),
            source_message_id_hex,
            direction: "sent".to_owned(),
            group_id_hex: "aa".to_owned(),
            sender: account.account_id_hex.clone(),
            plaintext: "hello".to_owned(),
            kind: MARMOT_APP_EVENT_KIND_CHAT,
            tags: Vec::new(),
            source_epoch: Some(2),
            retention: None,
            recorded_at: Some(recorded_at),
            origin_commit_id: None,
            moderation_grant: false,
        }
    };
    // An earlier send that reached the relay, then one the engine retained.
    app.record_account_app_event("alice", &sent("published", Some("bb".repeat(32)), 10))
        .unwrap();
    app.record_account_app_event("alice", &sent("held", None, 11))
        .unwrap();

    let preview = || {
        app.chat_list_row("alice", "aa")
            .unwrap()
            .expect("chat-list row")
            .last_message
            .expect("last message")
    };
    assert_eq!(
        (preview().message_id_hex, preview().delivery_state),
        ("held".to_owned(), ChatListMessageDeliveryState::Pending),
        "a retained send is pending while convergence can still release it"
    );

    app.invalidate_timeline_pending_sends_for_group("alice", "aa")
        .unwrap()
        .expect("a held row must produce a projection update");

    assert_eq!(
        (preview().message_id_hex, preview().delivery_state),
        (
            "published".to_owned(),
            ChatListMessageDeliveryState::Delivered
        ),
        "the swept send must stop pinning the preview as pending; the last send \
         that actually reached the relay takes over"
    );
    let rows = app
        .timeline_messages_with_query(
            "alice",
            storage_sqlite::TimelineMessageQuery {
                group_id_hex: Some("aa".to_owned()),
                ..storage_sqlite::TimelineMessageQuery::default()
            },
        )
        .unwrap()
        .messages;
    let status = |id: &str| {
        rows.iter()
            .find(|row| row.message_id_hex == id)
            .map(|row| row.invalidation_status.clone())
    };
    assert_eq!(
        status("held"),
        Some(Some("local_publish_failed".to_owned())),
        "the held row must carry the terminal outcome the app renders as failed"
    );
    assert_eq!(
        status("published"),
        Some(None),
        "a send that already reached the relay stays delivered"
    );
}

/// Issue #1177: the no-inbound drain seam owes the same terminal sweep as
/// inbound ingest.
///
/// `restore_disband_tombstone` re-emits a stored group's `GroupDisbanded` from
/// hydration, behind no delivery at all, and that replay is the only
/// reconciliation left for a disband whose live-session projection never
/// completed — a crash, or a batch that failed after the engine had already
/// drained the event one-shot. If this seam skips the sweep, a send the engine
/// accepted but never published survives the restart still claiming `Pending`.
#[tokio::test]
async fn a_drained_disband_sweeps_the_held_send_its_first_pass_never_reached() {
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://drained-disband.example")
        .with_test_relay_client(relay.clone());
    let mut client = app.client("alice").await.unwrap();
    let group_id = client.create_group("drained disband", &[]).await.unwrap();
    let group_id_hex = hex::encode(group_id.as_slice());

    // A send the engine accepted and retained: no published source id, so it
    // derives as pending until something resolves it.
    app.record_account_app_event(
        "alice",
        &AppMessageProjection {
            message_id_hex: "held".to_owned(),
            source_message_id_hex: None,
            direction: "sent".to_owned(),
            group_id_hex: group_id_hex.clone(),
            sender: account.account_id_hex.clone(),
            plaintext: "hello".to_owned(),
            kind: MARMOT_APP_EVENT_KIND_CHAT,
            tags: Vec::new(),
            source_epoch: Some(1),
            retention: None,
            recorded_at: Some(11),
            origin_commit_id: None,
            moderation_grant: false,
        },
    )
    .unwrap();

    let effects = marmot_account::AccountDeviceEffects {
        events: vec![cgka_traits::engine::GroupEvent::GroupStateChanged {
            group_id: group_id.clone(),
            epoch: cgka_traits::EpochId(1),
            actor: Some(MemberId::new(hex::decode(&account.account_id_hex).unwrap())),
            change: cgka_traits::engine::GroupStateChange::GroupDisbanded,
            origin_commit_id: None,
        }],
        ..Default::default()
    };
    client
        .observe_drained_session_events(&effects)
        .await
        .unwrap();

    let held = app
        .timeline_messages_with_query(
            "alice",
            storage_sqlite::TimelineMessageQuery {
                group_id_hex: Some(group_id_hex),
                ..storage_sqlite::TimelineMessageQuery::default()
            },
        )
        .unwrap()
        .messages
        .into_iter()
        .find(|row| row.message_id_hex == "held")
        .expect("the held send must still be on the timeline");
    assert_eq!(
        held.invalidation_status,
        Some("local_publish_failed".to_owned()),
        "a disband replayed without a delivery must still end the held send's wait"
    );
}

fn drained_seam_push_token(
    group_id_hex: &str,
    member_id_hex: &str,
    leaf_index: u32,
) -> GroupPushTokenRecord {
    GroupPushTokenRecord {
        group_id_hex: group_id_hex.to_owned(),
        member_id_hex: member_id_hex.to_owned(),
        leaf_index,
        platform: PushPlatform::Apns,
        token_fingerprint: format!("fingerprint-{member_id_hex}"),
        server_pubkey_hex: "bb".repeat(32),
        relay_hint: None,
        encrypted_token: vec![1, 2, 3],
        owner_ts: 1,
        owner_sig: String::new(),
        updated_at_ms: 1,
    }
}

/// A departed member's cached push records can never verify against current
/// membership again, so the inbound seam drops them the moment it observes the
/// departure. A departure that only ever reaches the drained seam — the live
/// projection crashed before it ran — owes the same cleanup, or the records
/// survive the restart with nothing left to sweep them.
#[tokio::test]
async fn a_drained_member_departure_removes_that_members_group_push_tokens() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://drained-departure.example")
        .with_test_relay_client(relay);
    let mut client = app.client("alice").await.unwrap();
    let group_id = client.create_group("drained departure", &[]).await.unwrap();
    let group_id_hex = hex::encode(group_id.as_slice());

    let departing = nostr::Keys::generate().public_key().to_hex();
    let staying = nostr::Keys::generate().public_key().to_hex();
    app.upsert_group_push_token(
        "alice",
        &drained_seam_push_token(&group_id_hex, &departing, 1),
    )
    .unwrap();
    app.upsert_group_push_token(
        "alice",
        &drained_seam_push_token(&group_id_hex, &staying, 2),
    )
    .unwrap();

    let effects = marmot_account::AccountDeviceEffects {
        events: vec![cgka_traits::engine::GroupEvent::GroupStateChanged {
            group_id: group_id.clone(),
            epoch: cgka_traits::EpochId(1),
            actor: None,
            change: cgka_traits::engine::GroupStateChange::MemberRemoved {
                member: MemberId::new(hex::decode(&departing).unwrap()),
            },
            origin_commit_id: None,
        }],
        ..Default::default()
    };
    client
        .observe_drained_session_events(&effects)
        .await
        .unwrap();

    assert_eq!(
        app.group_push_tokens("alice", &group_id_hex)
            .unwrap()
            .into_iter()
            .map(|token| token.member_id_hex)
            .collect::<HashSet<_>>(),
        HashSet::from([staying]),
        "a drained departure must drop the departed member's push records and keep the rest"
    );
}

/// `account_groups.self_membership` is the source of truth for the account
/// unread aggregate. A self-departure observed only on the drained seam must
/// move it, and a drained re-join must move it back — otherwise a crash during
/// a leave leaves the badge inflated forever, and a crash during a re-add
/// leaves a live group's unread permanently suppressed.
#[tokio::test]
async fn a_drained_self_departure_and_rejoin_move_stored_self_membership() {
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://drained-membership.example")
        .with_test_relay_client(relay);
    let mut client = app.client("alice").await.unwrap();
    let group_id = client
        .create_group("drained membership", &[])
        .await
        .unwrap();
    let group_id_hex = hex::encode(group_id.as_slice());
    assert_eq!(
        app.stored_group_self_membership("alice", &group_id_hex)
            .unwrap(),
        Some(SelfMembership::Member),
    );

    let departure = marmot_account::AccountDeviceEffects {
        events: vec![cgka_traits::engine::GroupEvent::GroupStateChanged {
            group_id: group_id.clone(),
            epoch: cgka_traits::EpochId(1),
            actor: None,
            change: cgka_traits::engine::GroupStateChange::MemberRemoved {
                member: MemberId::new(hex::decode(&account.account_id_hex).unwrap()),
            },
            origin_commit_id: None,
        }],
        ..Default::default()
    };
    client
        .observe_drained_session_events(&departure)
        .await
        .unwrap();
    assert_eq!(
        app.stored_group_self_membership("alice", &group_id_hex)
            .unwrap(),
        Some(SelfMembership::Removed),
        "a drained self-eviction must record how the account left"
    );

    let rejoin = marmot_account::AccountDeviceEffects {
        events: vec![cgka_traits::engine::GroupEvent::GroupJoined {
            group_id: group_id.clone(),
            via_welcome: MessageId::new(vec![0x7a; 32]),
            welcomer: None,
        }],
        ..Default::default()
    };
    client
        .observe_drained_session_events(&rejoin)
        .await
        .unwrap();
    assert_eq!(
        app.stored_group_self_membership("alice", &group_id_hex)
            .unwrap(),
        Some(SelfMembership::Member),
        "a drained re-join must un-suppress the group's unread aggregate again"
    );
}

/// A terminal group never advertises notification destinations again. The
/// inbound seam queues the current registration's removal and discards every
/// cached peer token; hydration re-emits a stored group's `GroupDisbanded`
/// behind no delivery at all, and that replay is the only reconciler left when
/// the live projection never ran.
///
/// The arm also sets `routes_dirty`, which is deliberately not asserted here: a
/// disband leaves the group's transport route in place, so the forced
/// `sync_runtime_groups` reconciles an unchanged subscription set and reaches
/// the relay as nothing observable.
#[tokio::test]
async fn a_drained_disband_performs_the_terminal_push_sweep() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://drained-sweep.example")
        .with_test_relay_client(relay);
    let mut client = app.client("alice").await.unwrap();
    let group_id = client.create_group("drained sweep", &[]).await.unwrap();
    let group_id_hex = hex::encode(group_id.as_slice());

    app.upsert_push_registration(
        "alice",
        PushPlatform::Fcm,
        "device-token",
        &nostr::Keys::generate().public_key().to_hex(),
        None,
    )
    .unwrap();
    let peer = nostr::Keys::generate().public_key().to_hex();
    app.upsert_group_push_token("alice", &drained_seam_push_token(&group_id_hex, &peer, 1))
        .unwrap();

    let effects = marmot_account::AccountDeviceEffects {
        events: vec![cgka_traits::engine::GroupEvent::GroupStateChanged {
            group_id: group_id.clone(),
            epoch: cgka_traits::EpochId(1),
            actor: None,
            change: cgka_traits::engine::GroupStateChange::GroupDisbanded,
            origin_commit_id: None,
        }],
        ..Default::default()
    };
    client
        .observe_drained_session_events(&effects)
        .await
        .unwrap();

    assert_eq!(
        app.pending_push_registration_removals("alice")
            .unwrap()
            .into_iter()
            .map(|(group, _)| group)
            .collect::<Vec<_>>(),
        vec![group_id_hex.clone()],
        "a drained disband must queue the current registration's removal"
    );
    assert!(
        app.group_push_tokens("alice", &group_id_hex)
            .unwrap()
            .is_empty(),
        "a drained disband must discard every cached peer token"
    );
}

/// `AppMessageInvalidated` is the engine's explicit timeline withdrawal. The
/// drained seam is where it lands after a crash, so skipping the dispatch
/// leaves a message the canonical branch never carried rendered as live
/// history.
#[tokio::test]
async fn a_drained_invalidation_event_withdraws_the_timeline_record() {
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://drained-invalidation.example")
        .with_test_relay_client(relay);
    let mut client = app.client("alice").await.unwrap();
    let group_id = client
        .create_group("drained invalidation", &[])
        .await
        .unwrap();
    let group_id_hex = hex::encode(group_id.as_slice());
    let source_message_id = MessageId::new(vec![0x5c; 32]);
    let source_message_id_hex = hex::encode(source_message_id.as_slice());

    app.record_account_app_event(
        "alice",
        &AppMessageProjection {
            message_id_hex: "losing-branch-row".to_owned(),
            source_message_id_hex: Some(source_message_id_hex),
            direction: "received".to_owned(),
            group_id_hex: group_id_hex.clone(),
            sender: account.account_id_hex.clone(),
            plaintext: "from the losing branch".to_owned(),
            kind: MARMOT_APP_EVENT_KIND_CHAT,
            tags: Vec::new(),
            source_epoch: Some(1),
            retention: None,
            recorded_at: Some(11),
            origin_commit_id: None,
            moderation_grant: false,
        },
    )
    .unwrap();

    let effects = marmot_account::AccountDeviceEffects {
        events: vec![cgka_traits::engine::GroupEvent::AppMessageInvalidated {
            group_id: group_id.clone(),
            message_id: source_message_id,
            epoch: cgka_traits::EpochId(1),
            reason: cgka_traits::engine::AppMessageInvalidationReason::LosingBranch,
            decrypted_payload_ref: None,
        }],
        ..Default::default()
    };
    let summary = client
        .observe_drained_session_events(&effects)
        .await
        .unwrap();

    assert!(
        !summary.projection_updates.is_empty(),
        "a drained withdrawal must reach live timeline subscribers"
    );
    assert_eq!(
        app.timeline_messages_with_query(
            "alice",
            storage_sqlite::TimelineMessageQuery {
                group_id_hex: Some(group_id_hex),
                ..storage_sqlite::TimelineMessageQuery::default()
            },
        )
        .unwrap()
        .messages
        .into_iter()
        .find(|row| row.message_id_hex == "losing-branch-row")
        .expect("the withdrawn row must still be on the timeline as a tombstone")
        .invalidation_status,
        Some("LosingBranch".to_owned()),
        "a drained withdrawal must tombstone the delivered row"
    );
}

/// Drained replay is not exclusive with live delivery: a crash can leave the
/// engine's durable outbox holding events the inbound seam already projected,
/// and hydration re-emits a disband on every open. Every write both seams share
/// must therefore be safe to apply twice — an absent push token, a membership
/// already at its target value, and an already-queued registration removal all
/// converge rather than accumulate.
#[tokio::test]
async fn replaying_a_drained_batch_the_seam_already_applied_is_a_no_op() {
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://drained-replay.example")
        .with_test_relay_client(relay);
    let mut client = app.client("alice").await.unwrap();
    let group_id = client.create_group("drained replay", &[]).await.unwrap();
    let group_id_hex = hex::encode(group_id.as_slice());

    app.upsert_push_registration(
        "alice",
        PushPlatform::Fcm,
        "device-token",
        &nostr::Keys::generate().public_key().to_hex(),
        None,
    )
    .unwrap();
    let peer = nostr::Keys::generate().public_key().to_hex();
    app.upsert_group_push_token("alice", &drained_seam_push_token(&group_id_hex, &peer, 1))
        .unwrap();

    let effects = marmot_account::AccountDeviceEffects {
        events: vec![
            cgka_traits::engine::GroupEvent::GroupStateChanged {
                group_id: group_id.clone(),
                epoch: cgka_traits::EpochId(1),
                actor: None,
                change: cgka_traits::engine::GroupStateChange::MemberRemoved {
                    member: MemberId::new(hex::decode(&account.account_id_hex).unwrap()),
                },
                origin_commit_id: None,
            },
            cgka_traits::engine::GroupEvent::GroupStateChanged {
                group_id: group_id.clone(),
                epoch: cgka_traits::EpochId(2),
                actor: None,
                change: cgka_traits::engine::GroupStateChange::GroupDisbanded,
                origin_commit_id: None,
            },
        ],
        ..Default::default()
    };
    client
        .observe_drained_session_events(&effects)
        .await
        .unwrap();
    client
        .observe_drained_session_events(&effects)
        .await
        .expect("re-observing a replayed batch must not error");

    assert_eq!(
        app.pending_push_registration_removals("alice")
            .unwrap()
            .len(),
        1,
        "a replayed disband must converge on one queued removal, not accumulate them"
    );
    assert!(
        app.group_push_tokens("alice", &group_id_hex)
            .unwrap()
            .is_empty(),
    );
    assert_eq!(
        app.stored_group_self_membership("alice", &group_id_hex)
            .unwrap(),
        Some(SelfMembership::Removed),
        "a replayed self-departure must leave membership where the first pass put it"
    );
}

/// Issue #1177 follow-up: the drained seam owes the live seam's kind-1210
/// system-row synthesis too.
///
/// `observe_account_device_effects` ends by synthesizing a durable system row
/// for every authenticated `GroupStateChanged`; the drained seam ran its own
/// projection loop and never called the synthesizer. Nothing else writes those
/// rows, and a drained batch is one-shot, so a crash-replayed rename or
/// membership change lost its timeline row permanently and silently.
#[tokio::test]
async fn a_drained_state_change_synthesizes_the_system_row_the_live_seam_does() {
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://drained-system-rows.example")
        .with_test_relay_client(relay);
    let mut client = app.client("alice").await.unwrap();
    let group_id = client
        .create_group("drained system rows", &[])
        .await
        .unwrap();
    let group_id_hex = hex::encode(group_id.as_slice());
    let actor = MemberId::new(hex::decode(&account.account_id_hex).unwrap());

    // One authenticated rename, twice: the row id is derived from the change
    // and its epoch, so the two seams take one epoch each rather than
    // converging on the same deterministic row.
    let rename = |epoch: u64, name: &str| marmot_account::AccountDeviceEffects {
        events: vec![cgka_traits::engine::GroupEvent::GroupStateChanged {
            group_id: group_id.clone(),
            epoch: cgka_traits::EpochId(epoch),
            actor: Some(actor.clone()),
            change: cgka_traits::engine::GroupStateChange::GroupRenamed {
                name: name.to_owned(),
                previous_name: Some("drained system rows".to_owned()),
            },
            origin_commit_id: None,
        }],
        ..Default::default()
    };

    // Control: the live seam, which has always synthesized the row.
    client
        .observe_send_applied_effects(&rename(2, "live rename"))
        .await
        .unwrap();

    let drained = client
        .observe_drained_session_events(&rename(3, "replayed rename"))
        .await
        .unwrap();
    // Crash replay is not exclusive with the first pass: the synthesizer is a
    // deterministic upsert, so a second drain of the same batch must converge.
    client
        .observe_drained_session_events(&rename(3, "replayed rename"))
        .await
        .expect("re-observing a replayed batch must not error");

    let rows = app
        .timeline_messages_with_query(
            "alice",
            storage_sqlite::TimelineMessageQuery {
                group_id_hex: Some(group_id_hex),
                ..storage_sqlite::TimelineMessageQuery::default()
            },
        )
        .unwrap()
        .messages;
    let system_rows = |epoch: u64| {
        rows.iter()
            .filter(|row| {
                row.kind == MARMOT_APP_EVENT_KIND_GROUP_SYSTEM && row.source_epoch == Some(epoch)
            })
            .count()
    };
    assert_eq!(
        system_rows(2),
        1,
        "control: the live seam synthesizes one kind-1210 row for the rename; got {rows:?}"
    );
    assert_eq!(
        system_rows(3),
        1,
        "a crash-replayed rename owes the same durable kind-1210 row, once; got {rows:?}"
    );
    assert!(
        drained.projection_updates.iter().any(|update| {
            update.timeline_messages.iter().any(|row| {
                row.kind == MARMOT_APP_EVENT_KIND_GROUP_SYSTEM && row.source_epoch == Some(3)
            })
        }),
        "and must surface it to runtime subscribers on the same summary the seam returns"
    );
}

/// A batch that supersedes a commit must not leave that commit's kind-1210 row
/// standing, whichever seam projects the batch.
///
/// Both seams invalidate per event inside their projection loop and synthesize
/// system rows once at the tail, so every `GroupStateInvalidated` in a batch has
/// already been applied by the time the tail upserts. The storage upsert clears
/// `invalidated` on conflict, so an unfiltered tail either revives a row the
/// same batch just withdrew or creates one the batch never should have had.
///
/// The engine reaches this by buffering two convergence passes into one batch:
/// `events_buf` has a single take site, and
/// `advance_convergence_inputs_with_execution` runs up to
/// `MAX_CONVERGENCE_REPROCESSING_PASSES` passes without one. An earlier pass
/// accepts the commit and emits its `GroupStateChanged`; a later pass reorgs and
/// emits `GroupStateInvalidated` for that same commit. Within a *single* pass
/// the two are disjoint by construction, so the single-pass shape is not the one
/// under test here.
mod superseded_system_row_shapes {
    use super::*;

    pub(super) const SUPERSEDED: &str = "SupersededByBranchSelection";

    pub(super) fn renamed(
        group_id: &GroupId,
        actor: &MemberId,
        epoch: u64,
        name: &str,
        origin_commit_id: Option<&MessageId>,
    ) -> cgka_traits::engine::GroupEvent {
        cgka_traits::engine::GroupEvent::GroupStateChanged {
            group_id: group_id.clone(),
            epoch: cgka_traits::EpochId(epoch),
            actor: Some(actor.clone()),
            change: cgka_traits::engine::GroupStateChange::GroupRenamed {
                name: name.to_owned(),
                previous_name: None,
            },
            origin_commit_id: origin_commit_id.cloned(),
        }
    }

    pub(super) fn superseded(
        group_id: &GroupId,
        epoch: u64,
        invalidated_commit_id: &MessageId,
    ) -> cgka_traits::engine::GroupEvent {
        cgka_traits::engine::GroupEvent::GroupStateInvalidated {
            group_id: group_id.clone(),
            epoch: cgka_traits::EpochId(epoch),
            invalidated_commit_id: invalidated_commit_id.clone(),
            reason: cgka_traits::engine::GroupStateInvalidationReason::SupersededByBranchSelection,
        }
    }

    pub(super) fn batch(
        events: Vec<cgka_traits::engine::GroupEvent>,
    ) -> marmot_account::AccountDeviceEffects {
        marmot_account::AccountDeviceEffects {
            events,
            ..Default::default()
        }
    }

    /// The kind-1210 row for `epoch`, as `(exists, invalidation_status)`.
    pub(super) fn system_row(
        app: &MarmotApp,
        group_id_hex: &str,
        epoch: u64,
    ) -> Option<Option<String>> {
        app.timeline_messages_with_query(
            "alice",
            storage_sqlite::TimelineMessageQuery {
                group_id_hex: Some(group_id_hex.to_owned()),
                ..storage_sqlite::TimelineMessageQuery::default()
            },
        )
        .unwrap()
        .messages
        .iter()
        .find(|row| {
            row.kind == MARMOT_APP_EVENT_KIND_GROUP_SYSTEM && row.source_epoch == Some(epoch)
        })
        .map(|row| row.invalidation_status.clone())
    }
}

/// The drained seam owes the filter: a batch carrying both a commit's
/// `GroupStateChanged` and that commit's `GroupStateInvalidated` must leave no
/// live kind-1210 row for it — whether or not an earlier batch already
/// synthesized the row.
///
/// See [`superseded_system_row_shapes`] for why one batch can carry both.
#[tokio::test]
async fn a_drained_batch_leaves_no_live_system_row_for_a_commit_it_supersedes() {
    use superseded_system_row_shapes::{SUPERSEDED, batch, renamed, superseded, system_row};

    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://drained-superseded-rows.example")
        .with_test_relay_client(relay);
    let mut client = app.client("alice").await.unwrap();
    let group_id = client
        .create_group("drained superseded rows", &[])
        .await
        .unwrap();
    let group_id_hex = hex::encode(group_id.as_slice());
    let actor = MemberId::new(hex::decode(&account.account_id_hex).unwrap());

    // Shape 1 — no pre-existing row. The earlier pass's change and the later
    // pass's withdrawal arrive together, so the invalidation sweep runs against
    // a row that does not exist yet and the tail is the only writer left. An
    // unfiltered tail creates a row for a change that canonically never
    // happened.
    let unsynthesized = MessageId::new(vec![0xBE; 32]);
    client
        .observe_drained_session_events(&batch(vec![
            renamed(
                &group_id,
                &actor,
                2,
                "superseded rename",
                Some(&unsynthesized),
            ),
            superseded(&group_id, 2, &unsynthesized),
        ]))
        .await
        .unwrap();
    assert_eq!(
        system_row(&app, &group_id_hex, 2),
        None,
        "a commit withdrawn by its own batch must not get a kind-1210 row at all"
    );

    // Shape 2 — the row already exists from an earlier batch. Here the sweep
    // does withdraw it, and the tail's upsert would clear `invalidated` again.
    let synthesized = MessageId::new(vec![0xA1; 32]);
    client
        .observe_drained_session_events(&batch(vec![renamed(
            &group_id,
            &actor,
            3,
            "revived rename",
            Some(&synthesized),
        )]))
        .await
        .unwrap();
    assert_eq!(
        system_row(&app, &group_id_hex, 3),
        Some(None),
        "control: the first batch synthesizes a live row"
    );
    client
        .observe_drained_session_events(&batch(vec![
            renamed(&group_id, &actor, 3, "revived rename", Some(&synthesized)),
            superseded(&group_id, 3, &synthesized),
        ]))
        .await
        .unwrap();
    assert_eq!(
        system_row(&app, &group_id_hex, 3),
        Some(Some(SUPERSEDED.to_owned())),
        "the tail must not revive the row the same batch's withdrawal tombstoned"
    );

    // Guard against over-filtering: a withdrawal only silences the commit it
    // names. A bystander change riding the same batch keeps its live row.
    client
        .observe_drained_session_events(&batch(vec![
            renamed(
                &group_id,
                &actor,
                4,
                "surviving rename",
                Some(&MessageId::new(vec![0xCF; 32])),
            ),
            superseded(&group_id, 3, &synthesized),
        ]))
        .await
        .unwrap();
    assert_eq!(
        system_row(&app, &group_id_hex, 4),
        Some(None),
        "a change attributed to a commit the batch did not withdraw stays live"
    );
}

/// The live seam's tail is the same shared synthesizer, reached through
/// `observe_account_device_effects`, and carries the identical defect today.
/// Fixing it at the call site would leave this failing, which is why the filter
/// belongs in `project_group_system_rows`.
#[tokio::test]
async fn a_live_batch_leaves_no_live_system_row_for_a_commit_it_supersedes() {
    use superseded_system_row_shapes::{SUPERSEDED, batch, renamed, superseded, system_row};

    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://live-superseded-rows.example")
        .with_test_relay_client(relay);
    let mut client = app.client("alice").await.unwrap();
    let group_id = client
        .create_group("live superseded rows", &[])
        .await
        .unwrap();
    let group_id_hex = hex::encode(group_id.as_slice());
    let actor = MemberId::new(hex::decode(&account.account_id_hex).unwrap());

    let unsynthesized = MessageId::new(vec![0xBE; 32]);
    client
        .observe_send_applied_effects(&batch(vec![
            renamed(
                &group_id,
                &actor,
                2,
                "superseded rename",
                Some(&unsynthesized),
            ),
            superseded(&group_id, 2, &unsynthesized),
        ]))
        .await
        .unwrap();
    assert_eq!(
        system_row(&app, &group_id_hex, 2),
        None,
        "the live seam owes the same withholding as the drained one"
    );

    let synthesized = MessageId::new(vec![0xA1; 32]);
    client
        .observe_send_applied_effects(&batch(vec![renamed(
            &group_id,
            &actor,
            3,
            "revived rename",
            Some(&synthesized),
        )]))
        .await
        .unwrap();
    assert_eq!(
        system_row(&app, &group_id_hex, 3),
        Some(None),
        "control: the first batch synthesizes a live row"
    );
    client
        .observe_send_applied_effects(&batch(vec![
            renamed(&group_id, &actor, 3, "revived rename", Some(&synthesized)),
            superseded(&group_id, 3, &synthesized),
        ]))
        .await
        .unwrap();
    assert_eq!(
        system_row(&app, &group_id_hex, 3),
        Some(Some(SUPERSEDED.to_owned())),
        "the live tail must not revive the row the same batch's withdrawal tombstoned"
    );
}

#[test]
fn transport_group_route_replacement_installs_current_and_prior_routes() {
    let routing = AppTransportRouting::new(AppRoutingState {
        local_inbox_endpoints: Vec::new(),
        key_package_endpoints: Vec::new(),
        inbox_routes: HashMap::new(),
        group_routes: Vec::new(),
        required_acks: 0,
    });
    let group_id = GroupId::new(vec![0xAB; 16]);
    let sub_x = TransportGroupSubscription {
        group_id: group_id.clone(),
        transport_group_id: vec![0x41; 32],
        endpoints: vec![TransportEndpoint("wss://x.example".to_owned())],
    };
    assert!(routing.replace_group_routes(&group_id, vec![sub_x.clone()]));
    assert!(!routing.replace_group_routes(&group_id, vec![sub_x.clone()]));

    let sub_y = TransportGroupSubscription {
        group_id: group_id.clone(),
        transport_group_id: vec![0x59; 32],
        endpoints: vec![TransportEndpoint("wss://y.example".to_owned())],
    };
    assert!(routing.replace_group_routes(&group_id, vec![sub_y.clone(), sub_x.clone()]));

    let snapshot = routing.snapshot();
    let routes: Vec<_> = snapshot
        .group_routes
        .iter()
        .filter(|route| route.group_id == group_id)
        .collect();
    assert_eq!(routes.len(), 2);
    assert!(routes.contains(&&sub_x));
    assert!(routes.contains(&&sub_y));
}

#[test]
fn reopening_account_restores_current_and_prior_group_routes() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://account.example");
    let group_id_hex = "aa".repeat(16);
    let mut group = AppGroupRecord::new(
        group_id_hex.clone(),
        AppGroupNostrRoutingComponent::new(
            NostrRoutingV1::new([0x22; 32], vec!["wss://current.example".to_owned()]).unwrap(),
        )
        .unwrap(),
        "routed".to_owned(),
        String::new(),
        AppGroupImageInput::default(),
        AppGroupAdminPolicyComponent::new(Vec::new()),
        AppGroupMessageRetentionComponent::disabled(),
    );
    group.prior_nostr_routes = vec![AppPriorNostrRoute {
        nostr_group_id_hex: hex::encode([0x11; 32]),
        relays: vec!["wss://prior.example".to_owned()],
        last_epoch: 7,
    }];
    group.nostr_routing_last_epoch = 8;
    app.save_state(&AccountState {
        label: "alice".to_owned(),
        seen_events: Vec::new(),
        last_transport_timestamp: Some(1_800_000_000),
        groups: vec![group],
    })
    .unwrap();
    drop(app);

    let reopened = MarmotApp::with_relay(dir.path(), "wss://account.example");
    let state = reopened.load_state("alice").unwrap();
    assert_eq!(state.groups[0].prior_nostr_routes[0].last_epoch, 7);
    assert_eq!(state.groups[0].nostr_routing_last_epoch, 8);
    let routes = reopened
        .routing_for(&state)
        .unwrap()
        .snapshot()
        .group_routes;
    assert_eq!(routes.len(), 2);
    assert_eq!(
        routes
            .iter()
            .map(|route| route.transport_group_id.clone())
            .collect::<HashSet<_>>(),
        HashSet::from([vec![0x11; 32], vec![0x22; 32]])
    );
}

#[tokio::test]
async fn local_delete_compensation_preserves_primary_error_and_attempts_route_restore() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let mut client = app.client("alice").await.unwrap();
    let group_id = client.create_group("compensation", &[]).await.unwrap();
    let routes_before = client.routing.snapshot().group_routes;

    relay.block_next_unsubscribe();
    let delete = tokio::spawn(async move {
        let result = client.delete_group_local(&group_id).await;
        (result, client.routing.snapshot().group_routes)
    });
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        relay.wait_for_blocked_unsubscribe(),
    )
    .await
    .unwrap();
    app.close_storage().unwrap();
    relay.fail_next_subscribe();
    relay.release_unsubscribe();

    let (result, routes_after) = delete.await.unwrap();
    let error = format!("{:?}", result.unwrap_err());
    assert!(
        error.contains("Closed"),
        "the original storage-delete failure must win over compensation failures: {error}"
    );
    assert_eq!(routes_after, routes_before);
    assert!(
        !relay
            .fail_next_subscribe
            .load(std::sync::atomic::Ordering::SeqCst),
        "runtime route restoration must still be attempted after storage compensation fails"
    );
}

#[tokio::test]
async fn local_delete_restart_preserves_rotated_route_relay_pairs_for_resurrection() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://old.example").with_test_relay_client(relay);
    let mut client = app.client("alice").await.unwrap();
    let group_id = client
        .create_group("rotated local delete", &[])
        .await
        .unwrap();
    let group_id_hex = hex::encode(group_id.as_slice());
    let old_route = app
        .group("alice", &group_id_hex)
        .unwrap()
        .unwrap()
        .nostr_routing;

    let current_route =
        NostrRoutingV1::new([0x22; 32], vec!["wss://current.example".to_owned()]).unwrap();
    let effects = client
        .runtime
        .send(cgka_traits::engine::SendIntent::UpdateAppComponents {
            group_id: group_id.clone(),
            updates: vec![cgka_traits::app_components::AppComponentData {
                component_id: NOSTR_ROUTING_COMPONENT_ID,
                data: cgka_traits::app_components::encode_nostr_routing_v1(&current_route).unwrap(),
            }],
        })
        .await
        .unwrap();
    assert!(!effects.reports.is_empty());
    client.refresh_group(&group_id);
    client.refresh_group_routes().unwrap();
    app.save_state(&client.state).unwrap();

    assert!(client.delete_group_local(&group_id).await.unwrap());
    let hidden_route =
        NostrRoutingV1::new([0x33; 32], vec!["wss://hidden.example".to_owned()]).unwrap();
    client
        .runtime
        .send(cgka_traits::engine::SendIntent::UpdateAppComponents {
            group_id: group_id.clone(),
            updates: vec![cgka_traits::app_components::AppComponentData {
                component_id: NOSTR_ROUTING_COMPONENT_ID,
                data: cgka_traits::app_components::encode_nostr_routing_v1(&hidden_route).unwrap(),
            }],
        })
        .await
        .unwrap();
    client.refresh_group(&group_id);
    client.refresh_group_routes().unwrap();
    drop(client);

    let mut reopened = app.client("alice").await.unwrap();
    let routes = reopened
        .routing
        .snapshot()
        .group_routes
        .into_iter()
        .filter(|route| route.group_id == group_id)
        .map(|route| (route.transport_group_id, route.endpoints))
        .collect::<HashSet<_>>();
    assert_eq!(
        routes,
        HashSet::from([
            (
                hex::decode(&old_route.nostr_group_id_hex).unwrap(),
                vec![TransportEndpoint("wss://old.example".to_owned())],
            ),
            (
                vec![0x22; 32],
                vec![TransportEndpoint("wss://current.example".to_owned())],
            ),
            (
                vec![0x33; 32],
                vec![TransportEndpoint("wss://hidden.example".to_owned())],
            ),
        ]),
        "a hidden group must keep each retained route paired with its authenticated relay set",
    );

    let sender = app.account_home().account("alice").unwrap().account_id_hex;
    let fresh_payload = crate::messages::encode_inner_event(
        &build_inner_event(
            &AppMessageIntent::Chat {
                content: "fresh activity".to_owned(),
            },
            &sender,
            unix_now_seconds(),
        )
        .unwrap(),
    )
    .unwrap();
    let fresh = reopened
        .runtime
        .send(cgka_traits::engine::SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: fresh_payload.clone(),
        })
        .await
        .unwrap();
    assert!(fresh.failures.is_empty());
    let effects = marmot_account::AccountDeviceEffects {
        events: vec![cgka_traits::engine::GroupEvent::MessageReceived {
            group_id: group_id.clone(),
            message_id: fresh.reports[0].message_id.clone(),
            sender: MemberId::new(hex::decode(&sender).unwrap()),
            epoch: reopened.runtime.group_record(&group_id).unwrap().epoch,
            payload: fresh_payload,
            retention: None,
        }],
        ..Default::default()
    };
    let summary = reopened
        .observe_drained_session_events(&effects)
        .await
        .unwrap();
    assert_eq!(summary.messages[0].plaintext, "fresh activity");

    let resurrected = app.group("alice", &group_id_hex).unwrap().unwrap();
    assert_eq!(
        resurrected
            .prior_nostr_routes
            .iter()
            .map(|route| (route.nostr_group_id_hex.clone(), route.relays.clone()))
            .collect::<HashSet<_>>(),
        HashSet::from([
            (
                old_route.nostr_group_id_hex,
                vec!["wss://old.example".to_owned()],
            ),
            (
                hex::encode([0x22; 32]),
                vec!["wss://current.example".to_owned()],
            ),
        ]),
        "resurrection must adopt the exact retained route history before clearing the marker",
    );
    let resurrected_routes = reopened
        .routing
        .snapshot()
        .group_routes
        .into_iter()
        .filter(|route| route.group_id == group_id)
        .map(|route| (route.transport_group_id, route.endpoints))
        .collect::<HashSet<_>>();
    assert_eq!(resurrected_routes, routes);
}

#[tokio::test]
async fn local_delete_batch_suppresses_historical_chat_in_both_event_orders() {
    for fresh_first in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app =
            MarmotApp::with_relay(dir.path(), "wss://relay.example").with_test_relay_client(relay);
        let mut client = app.client("alice").await.unwrap();
        let group_id = client.create_group("batch frontier", &[]).await.unwrap();
        let group_id_hex = hex::encode(group_id.as_slice());
        let sender_hex = app.account_home().account("alice").unwrap().account_id_hex;
        let sender = MemberId::new(hex::decode(&sender_hex).unwrap());

        let historical_payload = crate::messages::encode_inner_event(
            &build_inner_event(
                &AppMessageIntent::Chat {
                    content: "historical".to_owned(),
                },
                &sender_hex,
                unix_now_seconds(),
            )
            .unwrap(),
        )
        .unwrap();
        let historical = client
            .runtime
            .send(cgka_traits::engine::SendIntent::AppMessage {
                group_id: group_id.clone(),
                payload: historical_payload.clone(),
            })
            .await
            .unwrap();
        assert!(historical.failures.is_empty());
        assert!(client.delete_group_local(&group_id).await.unwrap());

        let fresh_payload = crate::messages::encode_inner_event(
            &build_inner_event(
                &AppMessageIntent::Chat {
                    content: "fresh".to_owned(),
                },
                &sender_hex,
                unix_now_seconds(),
            )
            .unwrap(),
        )
        .unwrap();
        let fresh = client
            .runtime
            .send(cgka_traits::engine::SendIntent::AppMessage {
                group_id: group_id.clone(),
                payload: fresh_payload.clone(),
            })
            .await
            .unwrap();
        assert!(fresh.failures.is_empty());
        let epoch = client.runtime.group_record(&group_id).unwrap().epoch;
        let historical_event = cgka_traits::engine::GroupEvent::MessageReceived {
            group_id: group_id.clone(),
            message_id: historical.reports[0].message_id.clone(),
            sender: sender.clone(),
            epoch,
            payload: historical_payload,
            retention: None,
        };
        let fresh_event = cgka_traits::engine::GroupEvent::MessageReceived {
            group_id: group_id.clone(),
            message_id: fresh.reports[0].message_id.clone(),
            sender,
            epoch,
            payload: fresh_payload,
            retention: None,
        };
        let effects = marmot_account::AccountDeviceEffects {
            events: if fresh_first {
                vec![fresh_event, historical_event]
            } else {
                vec![historical_event, fresh_event]
            },
            ..Default::default()
        };

        let summary = client
            .observe_drained_session_events(&effects)
            .await
            .unwrap();

        assert_eq!(summary.messages.len(), 1, "fresh_first={fresh_first}");
        assert_eq!(summary.messages[0].plaintext, "fresh");
        assert!(app.group("alice", &group_id_hex).unwrap().is_some());
        assert_eq!(
            app.account_storage("alice")
                .unwrap()
                .local_group_deletion_frontier(&group_id_hex)
                .unwrap(),
            None,
        );
    }
}

#[tokio::test]
async fn account_open_recovers_first_fresh_chat_after_protocol_projection_crash() {
    use cgka_traits::storage::MessageStorage;

    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app =
        MarmotApp::with_relay(dir.path(), "wss://relay.example").with_test_relay_client(relay);
    let mut client = app.client("alice").await.unwrap();
    let group_id = client.create_group("crash recovery", &[]).await.unwrap();
    let group_id_hex = hex::encode(group_id.as_slice());
    let sender_hex = app.account_home().account("alice").unwrap().account_id_hex;
    let sender = MemberId::new(hex::decode(&sender_hex).unwrap());

    assert!(client.delete_group_local(&group_id).await.unwrap());
    let fresh_payload = crate::messages::encode_inner_event(
        &build_inner_event(
            &AppMessageIntent::Chat {
                content: "first fresh chat".to_owned(),
            },
            &sender_hex,
            unix_now_seconds(),
        )
        .unwrap(),
    )
    .unwrap();
    let fresh = client
        .runtime
        .send(cgka_traits::engine::SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: fresh_payload.clone(),
        })
        .await
        .unwrap();
    assert!(fresh.failures.is_empty());
    let message_id = fresh.reports[0].message_id.clone();
    let event = cgka_traits::engine::GroupEvent::MessageReceived {
        group_id: group_id.clone(),
        message_id: message_id.clone(),
        sender,
        epoch: client.runtime.group_record(&group_id).unwrap().epoch,
        payload: fresh_payload,
        retention: None,
    };
    let storage = app.account_storage("alice").unwrap();
    storage.put_pending_application_event(&event).unwrap();

    // Simulate termination after the engine transaction committed its durable
    // delivery but before the app observed or projected it.
    drop(client);
    let mut reopened = app.client("alice").await.unwrap();
    assert!(app.group("alice", &group_id_hex).unwrap().is_none());
    let recovered = reopened.drain_pending_session_events().await.unwrap();

    assert_eq!(recovered.messages.len(), 1);
    assert_eq!(recovered.messages[0].plaintext, "first fresh chat");
    assert!(app.group("alice", &group_id_hex).unwrap().is_some());
    assert!(
        app.messages("alice")
            .unwrap()
            .iter()
            .any(|message| message.plaintext == "first fresh chat"),
        "account-open replay must persist the first crossing chat",
    );
    assert!(
        storage
            .list_pending_application_events()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        storage
            .local_group_deletion_frontier(&group_id_hex)
            .unwrap(),
        None,
    );
}

#[tokio::test]
async fn account_open_keeps_first_fresh_chat_pending_when_group_projection_is_unavailable() {
    use cgka_traits::storage::MessageStorage;

    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app =
        MarmotApp::with_relay(dir.path(), "wss://relay.example").with_test_relay_client(relay);
    let mut client = app.client("alice").await.unwrap();
    let group_id = client.create_group("crash recovery", &[]).await.unwrap();
    let group_id_hex = hex::encode(group_id.as_slice());
    let sender_hex = app.account_home().account("alice").unwrap().account_id_hex;
    let sender = MemberId::new(hex::decode(&sender_hex).unwrap());

    assert!(client.delete_group_local(&group_id).await.unwrap());
    let fresh_payload = crate::messages::encode_inner_event(
        &build_inner_event(
            &AppMessageIntent::Chat {
                content: "first fresh chat".to_owned(),
            },
            &sender_hex,
            unix_now_seconds(),
        )
        .unwrap(),
    )
    .unwrap();
    let fresh = client
        .runtime
        .send(cgka_traits::engine::SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: fresh_payload.clone(),
        })
        .await
        .unwrap();
    assert!(fresh.failures.is_empty());
    let message_id = fresh.reports[0].message_id.clone();
    let event = cgka_traits::engine::GroupEvent::MessageReceived {
        group_id: group_id.clone(),
        message_id,
        sender,
        epoch: client.runtime.group_record(&group_id).unwrap().epoch,
        payload: fresh_payload,
        retention: None,
    };
    let storage = app.account_storage("alice").unwrap();
    storage.put_pending_application_event(&event).unwrap();

    // Simulate termination after the engine transaction committed, then make
    // account-open replay take the best-effort projection path without
    // disturbing the live protocol group.
    drop(client);
    let mut reopened = app.client("alice").await.unwrap();
    reopened.force_event_group_projection_unavailable = true;
    assert!(app.group("alice", &group_id_hex).unwrap().is_none());
    let recovered = reopened.drain_pending_session_events().await.unwrap();

    assert_eq!(recovered.messages.len(), 1);
    assert_eq!(recovered.messages[0].plaintext, "first fresh chat");
    assert!(app.group("alice", &group_id_hex).unwrap().is_none());
    assert_eq!(
        storage.list_pending_application_events().unwrap(),
        vec![event]
    );
    assert!(
        storage
            .local_group_deletion_frontier(&group_id_hex)
            .unwrap()
            .is_some(),
        "a replay that cannot restore the group must retain its deletion frontier",
    );
}

#[test]
fn account_routing_skips_malformed_groups_without_discarding_valid_routes() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://account.example");
    let valid = AppGroupRecord::new(
        "aa".repeat(16),
        AppGroupNostrRoutingComponent::new(
            NostrRoutingV1::new([0x22; 32], vec!["wss://valid.example".to_owned()]).unwrap(),
        )
        .unwrap(),
        "valid".to_owned(),
        String::new(),
        AppGroupImageInput::default(),
        AppGroupAdminPolicyComponent::new(Vec::new()),
        AppGroupMessageRetentionComponent::disabled(),
    );
    let mut malformed_group_id = valid.clone();
    malformed_group_id.group_id_hex = "not-hex".to_owned();
    let mut malformed_current_route = valid.clone();
    malformed_current_route.group_id_hex = "bb".repeat(16);
    malformed_current_route.nostr_routing.nostr_group_id_hex = "not-hex".to_owned();

    let routes = app
        .routing_for(&AccountState {
            label: "alice".to_owned(),
            seen_events: Vec::new(),
            last_transport_timestamp: None,
            groups: vec![malformed_group_id, malformed_current_route, valid],
        })
        .expect("malformed group rows do not prevent account routing")
        .snapshot()
        .group_routes;

    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].transport_group_id, vec![0x22; 32]);
}

/// An escalation the detector raised during a sync pass that then fails must
/// still reach app subscribers, exactly once, on the next pass that succeeds.
///
/// The detector latches `escalated` one-shot per unrecovered run, so no later
/// arm in that run raises the decision again: an escalation dropped with the
/// failing pass's summary is lost for good, which is the 2026-07-29 field
/// failure going unreported a second time. Recording the escalation directly is
/// the pub(crate) stand-in for "the detector escalated inside a pass whose
/// later fallible step errored" — driving three real arms needs three real
/// epoch advances, and the loss does not depend on how the run got there.
#[tokio::test]
async fn an_escalation_recorded_before_a_failing_sync_is_reported_by_the_next_sync() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://escalation.example")
        .with_test_relay_client(relay.clone());
    app.set_audit_log_settings(AuditLogSettings { enabled: true })
        .unwrap();
    let mut client = app.client("alice").await.unwrap();
    let group_id = client
        .create_group("escalation redelivery", &[])
        .await
        .unwrap();

    let escalated = client
        .sync()
        .await
        .expect("baseline sync before the escalation");
    assert!(escalated.epoch_stall_escalations.is_empty());

    // The detector escalates mid-pass...
    client.apply_backfill_decision(
        &group_id,
        7,
        crate::client::epoch_stall::BackfillDecision::ArmAndEscalate { arms: 3 },
        marmot_forensics::EpochStallBackfillTrigger::UndecryptableThreshold,
    );
    // ...and a later fallible step in that same pass errors, so the summary the
    // pass was building never reaches a caller.
    relay.fail_next_subscribe();
    let failed = client.sync().await;
    assert!(
        failed.is_err(),
        "the injected transport failure must fail this sync pass"
    );

    // Forensics are written before the failing step, so the durable evidence
    // survives the pass that lost the app-visible event.
    assert_eq!(
        audit_rows_of_kind(&app, "epoch_stall_backfill_escalated"),
        1,
        "the failing pass still leaves exactly one durable escalation row"
    );

    let recovered = client.sync().await.expect("the next sync pass succeeds");
    assert_eq!(
        recovered
            .epoch_stall_escalations
            .iter()
            .map(|escalation| (
                escalation.group_id.clone(),
                escalation.stalled_epoch,
                escalation.arms
            ))
            .collect::<Vec<_>>(),
        vec![(group_id.clone(), 7, 3)],
        "the escalation recorded before the failing pass must be reported once"
    );

    let after = client
        .sync()
        .await
        .expect("a further sync pass still succeeds");
    assert!(
        after.epoch_stall_escalations.is_empty(),
        "a delivered escalation must not be reported twice"
    );
}

/// Count forensic audit rows of one kind across the account's JSONL files.
fn audit_rows_of_kind(app: &MarmotApp, kind: &str) -> usize {
    app.audit_log_files()
        .unwrap()
        .iter()
        .flat_map(|file| {
            std::fs::read_to_string(&file.path)
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
                .collect::<Vec<_>>()
        })
        .filter(|row| row["kind"]["type"] == kind)
        .count()
}

/// A resource refusal carried by a drained-effects pass must arm epoch-gap
/// recovery even when that same pass's publish check fails it.
///
/// `session.drain()` is the only source of these events and empties the engine's
/// in-memory buffer one-shot, and `TransportObjectResourceRefused` is buffered
/// only *after* its durable retention row is deleted — so a refusal this pass
/// does not arm on is unrecoverable: no later pass can re-observe it. The two
/// conditions are positively correlated rather than independent, because this
/// drain publishes: the failure and the refusal ride the same effects.
#[tokio::test]
async fn a_publish_failure_in_the_session_event_drain_still_arms_recovery() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://drain-arm.example")
        .with_test_relay_client(relay.clone());
    app.set_audit_log_settings(AuditLogSettings { enabled: true })
        .unwrap();
    let mut client = app.client("alice").await.unwrap();
    let group_id = client
        .create_group("drain arm ordering", &[])
        .await
        .unwrap();
    assert_eq!(audit_rows_of_kind(&app, "epoch_stall_backfill_armed"), 0);

    // One drained batch that carries both a resource refusal for the live group
    // and a hard publish failure (its pending commit rolled back).
    let mut effects = marmot_account::AccountDeviceEffects::default();
    effects.events.push(
        cgka_traits::engine::GroupEvent::TransportObjectResourceRefused {
            group_id: group_id.clone(),
            message_id: cgka_traits::MessageId::new(vec![0xab; 32]),
            resource: cgka_traits::ingest::InboundResourceLimit::TransportDeferredCapacity,
        },
    );
    effects.failures.push(marmot_account::PublishFailure {
        message_id: cgka_traits::MessageId::new(vec![0xab; 32]),
        reason: "injected publish failure".to_owned(),
    });
    effects
        .pending
        .push(marmot_account::PendingResolution::RolledBack {
            pending: cgka_traits::engine_state::PendingStateRef::new(7),
        });

    let result = client.observe_drained_session_events(&effects).await;

    assert!(
        result.is_err(),
        "a rolled-back publish failure must still fail the drain pass"
    );
    assert!(
        client.has_pending_epoch_backfill(),
        "the refusal is unrecoverable once drained, so it must arm before the pass can fail"
    );
    assert_eq!(
        audit_rows_of_kind(&app, "epoch_stall_backfill_armed"),
        1,
        "the arm must leave its durable forensic row even on a failing pass"
    );
}

/// One effects batch carrying both a resource refusal for `group_id` and a hard
/// publish failure whose pending commit rolled back — the shape in which a
/// refusal the pass does not arm on becomes unrecoverable.
fn a_refusal_riding_a_rolled_back_publish(
    group_id: &cgka_traits::GroupId,
) -> marmot_account::AccountDeviceEffects {
    let message_id = cgka_traits::MessageId::new(vec![0xab; 32]);
    let mut effects = marmot_account::AccountDeviceEffects::default();
    effects.events.push(
        cgka_traits::engine::GroupEvent::TransportObjectResourceRefused {
            group_id: group_id.clone(),
            message_id: message_id.clone(),
            resource: cgka_traits::ingest::InboundResourceLimit::TransportDeferredCapacity,
        },
    );
    effects.failures.push(marmot_account::PublishFailure {
        message_id,
        reason: "injected publish failure".to_owned(),
    });
    effects
        .pending
        .push(marmot_account::PendingResolution::RolledBack {
            pending: cgka_traits::engine_state::PendingStateRef::new(7),
        });
    effects
}

/// A resource refusal carried by the scheduled convergence batch must arm
/// epoch-gap recovery even when that same pass's publish check fails it.
///
/// Same one-shot loss as the drained seam: this batch's events reach the app
/// once, and the refusal was buffered only after its durable retention row was
/// deleted. The account worker calls this seam per group, so a failing advance
/// that returned before arming would drop the refusal for good.
#[tokio::test]
async fn a_publish_failure_after_scheduled_convergence_still_arms_recovery() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://advance-arm.example")
        .with_test_relay_client(relay.clone());
    app.set_audit_log_settings(AuditLogSettings { enabled: true })
        .unwrap();
    let mut client = app.client("alice").await.unwrap();
    let group_id = client
        .create_group("advance arm ordering", &[])
        .await
        .unwrap();
    assert_eq!(audit_rows_of_kind(&app, "epoch_stall_backfill_armed"), 0);

    let effects = a_refusal_riding_a_rolled_back_publish(&group_id);
    let result = client
        .observe_scheduled_convergence_effects(&group_id, &effects)
        .await;

    assert!(
        result.is_err(),
        "a rolled-back publish failure must still fail the scheduled convergence pass"
    );
    assert!(
        client.has_pending_epoch_backfill(),
        "the refusal rides this batch only once, so it must arm before the pass can fail"
    );
    assert_eq!(
        audit_rows_of_kind(&app, "epoch_stall_backfill_armed"),
        1,
        "the arm must leave its durable forensic row even on a failing pass"
    );
}

#[derive(Clone, Copy)]
enum MixedPublishObservation {
    DirectSend,
    DirectSendCurrentFailed,
    Drained,
    Scheduled,
    Retry,
}

async fn assert_mixed_publish_batch_finalizes_successful_message(
    observation: MixedPublishObservation,
) {
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://mixed-publish.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let mut client = app.client("alice").await.unwrap();
    let group_id = client.create_group("mixed publish", &[]).await.unwrap();
    let group_id_hex = hex::encode(group_id.as_slice());
    let app_event_id = "successful-app-message";
    let failed_app_event_id = "failed-app-message";
    let local_account_id_hex = account.account_id_hex;

    app.record_account_app_event(
        "alice",
        &AppMessageProjection {
            message_id_hex: app_event_id.to_owned(),
            source_message_id_hex: None,
            direction: "sent".to_owned(),
            group_id_hex: group_id_hex.clone(),
            sender: local_account_id_hex.clone(),
            plaintext: "successful sibling publish".to_owned(),
            kind: MARMOT_APP_EVENT_KIND_CHAT,
            tags: Vec::new(),
            source_epoch: Some(1),
            retention: None,
            recorded_at: Some(10),
            origin_commit_id: None,
            moderation_grant: false,
        },
    )
    .unwrap();
    app.record_account_app_event(
        "alice",
        &AppMessageProjection {
            message_id_hex: failed_app_event_id.to_owned(),
            source_message_id_hex: None,
            direction: "sent".to_owned(),
            group_id_hex: group_id_hex.clone(),
            sender: local_account_id_hex,
            plaintext: "failed sibling publish".to_owned(),
            kind: MARMOT_APP_EVENT_KIND_CHAT,
            tags: Vec::new(),
            source_epoch: Some(1),
            retention: None,
            recorded_at: Some(11),
            origin_commit_id: None,
            moderation_grant: false,
        },
    )
    .unwrap();

    let published_message_id = cgka_traits::MessageId::new(vec![0xcd; 32]);
    let failed_message_id = cgka_traits::MessageId::new(vec![0xee; 32]);
    let retention = AppMessageRetentionDecision::new(10, 0);
    let effects = marmot_account::AccountDeviceEffects {
        published_app_messages: vec![marmot_account::PublishedApplicationMessage {
            group_id: group_id.clone(),
            app_event_id: app_event_id.to_owned(),
            message_id: published_message_id.clone(),
            source_epoch: cgka_traits::EpochId(1),
            retention,
        }],
        failures: vec![marmot_account::PublishFailure {
            message_id: failed_message_id.clone(),
            reason: "unrelated sibling publish failed".to_owned(),
        }],
        failed_app_messages: vec![marmot_account::FailedApplicationMessage {
            group_id: group_id.clone(),
            app_event_id: failed_app_event_id.to_owned(),
            message_id: failed_message_id,
            reason: "unrelated sibling publish failed".to_owned(),
        }],
        ..Default::default()
    };

    let result = match observation {
        MixedPublishObservation::DirectSend => client
            .observe_recovery_evidence_then_gate_send_publish(&effects, &group_id, app_event_id)
            .await
            .and_then(|()| {
                let updates = client.finalize_published_app_message_source_retention(&effects)?;
                client.pending_projection_updates.extend(updates);
                Ok(SyncSummary::default())
            }),
        MixedPublishObservation::DirectSendCurrentFailed => client
            .observe_recovery_evidence_then_gate_send_publish(
                &effects,
                &group_id,
                "failed-current-message",
            )
            .await
            .map(|()| SyncSummary::default()),
        MixedPublishObservation::Drained => client.observe_drained_session_events(&effects).await,
        MixedPublishObservation::Scheduled => {
            client
                .observe_scheduled_convergence_effects(&group_id, &effects)
                .await
        }
        MixedPublishObservation::Retry => client
            .observe_convergence_retry_effects(&group_id, &effects)
            .map(|_| SyncSummary::default()),
    };
    if matches!(observation, MixedPublishObservation::DirectSend) {
        assert!(
            result.is_ok(),
            "an unrelated sibling failure must not fail the current delivered send"
        );
    } else {
        assert!(
            result.is_err(),
            "the unrelated hard failure must still surface to aggregate observers"
        );
    }
    assert_eq!(
        client.take_pending_projection_updates().len(),
        2,
        "the delivered and failed sibling updates must remain available for runtime broadcast"
    );

    let row = app
        .timeline_messages_with_query(
            "alice",
            storage_sqlite::TimelineMessageQuery {
                group_id_hex: Some(group_id_hex.clone()),
                ..storage_sqlite::TimelineMessageQuery::default()
            },
        )
        .unwrap()
        .messages
        .into_iter()
        .find(|message| message.message_id_hex == app_event_id)
        .expect("successful local message remains in the timeline");
    assert_eq!(
        row.source_message_id_hex,
        Some(hex::encode(published_message_id.as_slice())),
        "the successful sibling must leave Sending before the batch errors"
    );
    assert_eq!(row.source_epoch, Some(1));
    assert_eq!(row.retention_seconds, Some(retention.retention_seconds));
    let failed_row = app
        .timeline_messages_with_query(
            "alice",
            storage_sqlite::TimelineMessageQuery {
                group_id_hex: Some(group_id_hex),
                ..storage_sqlite::TimelineMessageQuery::default()
            },
        )
        .unwrap()
        .messages
        .into_iter()
        .find(|message| message.message_id_hex == failed_app_event_id)
        .expect("failed sibling remains visible in the timeline");
    assert_eq!(
        failed_row.invalidation_status.as_deref(),
        Some(crate::LOCAL_PUBLISH_FAILED_REASON),
        "a terminally failed sibling must leave Sending without failing the delivered current send"
    );
}

#[tokio::test]
async fn direct_send_mixed_batch_preserves_the_current_delivered_message() {
    assert_mixed_publish_batch_finalizes_successful_message(MixedPublishObservation::DirectSend)
        .await;
}

#[tokio::test]
async fn direct_send_mixed_batch_finalizes_successful_sibling_before_current_error() {
    assert_mixed_publish_batch_finalizes_successful_message(
        MixedPublishObservation::DirectSendCurrentFailed,
    )
    .await;
}

#[tokio::test]
async fn drained_mixed_publish_batch_finalizes_success_before_failure() {
    assert_mixed_publish_batch_finalizes_successful_message(MixedPublishObservation::Drained).await;
}

#[tokio::test]
async fn scheduled_mixed_publish_batch_finalizes_success_before_failure() {
    assert_mixed_publish_batch_finalizes_successful_message(MixedPublishObservation::Scheduled)
        .await;
}

#[tokio::test]
async fn retry_mixed_publish_batch_finalizes_success_before_failure() {
    assert_mixed_publish_batch_finalizes_successful_message(MixedPublishObservation::Retry).await;
}

#[tokio::test]
#[cfg(feature = "test-policy-overrides")]
async fn published_message_acknowledgement_failure_retries_cleanup_without_republishing() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let config = MarmotAppConfig::default().with_dev_fail_published_app_message_acknowledgement();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay_and_config(
        dir.path(),
        "wss://ack-failure.example".to_owned(),
        config,
    )
    .with_test_relay_client(relay.clone());
    let mut client = app.client("alice").await.unwrap();
    let group_id = client
        .create_group("acknowledgement failure", &[])
        .await
        .unwrap();
    let group_id_hex = hex::encode(group_id.as_slice());
    let publish_attempts_before = relay.attempted_event_ids().len();

    let summary = client
        .send(&group_id, b"delivery survives cleanup failure")
        .await
        .expect("cleanup failure must not hide an accepted message");
    assert_eq!(
        summary.accept_disposition,
        cgka_traits::SendAcceptDisposition::Published
    );
    let app_event_id = summary.message_ids[0].clone();
    assert_eq!(
        client.runtime.session().outbound_fanouts().unwrap().len(),
        1,
        "the accepted fanout must remain durable after the injected acknowledgement failure"
    );
    assert!(
        client.take_pending_convergence_groups().contains(&group_id),
        "acknowledgement failure must create its own cleanup scheduling edge"
    );
    assert!(matches!(
        client.convergence_schedule_state(&group_id).unwrap(),
        ConvergenceScheduleState::PendingOutbound {
            retry_after_ms: None
        }
    ));

    client
        .retry_group_convergence(&group_id)
        .await
        .expect("the autonomous cleanup replay must succeed after the one-shot fault");
    assert!(
        client
            .runtime
            .session()
            .outbound_fanouts()
            .unwrap()
            .is_empty(),
        "the replayed publication metadata must be acknowledged and retired"
    );
    assert_eq!(
        relay.attempted_event_ids().len(),
        publish_attempts_before + 1,
        "cleanup retry must not republish the already-accepted network event"
    );

    let row = app
        .timeline_messages_with_query(
            "alice",
            storage_sqlite::TimelineMessageQuery {
                group_id_hex: Some(group_id_hex),
                ..storage_sqlite::TimelineMessageQuery::default()
            },
        )
        .unwrap()
        .messages
        .into_iter()
        .find(|message| message.message_id_hex == app_event_id)
        .expect("the finalized local message remains in the timeline");
    assert!(row.source_message_id_hex.is_some());
}

/// A resource refusal carried by a host-requested convergence retry must arm
/// epoch-gap recovery even when that same pass's publish check fails it.
///
/// The retry seam folds and publishes exactly like the scheduled one, so it
/// carries the same refusals under the same one-shot loss — and a host that
/// retries a stuck group is the case where the recovery evidence matters most.
#[tokio::test]
async fn a_publish_failure_during_a_convergence_retry_still_arms_recovery() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://retry-arm.example")
        .with_test_relay_client(relay.clone());
    app.set_audit_log_settings(AuditLogSettings { enabled: true })
        .unwrap();
    let mut client = app.client("alice").await.unwrap();
    let group_id = client
        .create_group("retry arm ordering", &[])
        .await
        .unwrap();
    assert_eq!(audit_rows_of_kind(&app, "epoch_stall_backfill_armed"), 0);

    let effects = a_refusal_riding_a_rolled_back_publish(&group_id);
    let result = client.observe_convergence_retry_effects(&group_id, &effects);

    assert!(
        result.is_err(),
        "a rolled-back publish failure must still fail the convergence retry"
    );
    assert!(
        client.has_pending_epoch_backfill(),
        "the refusal rides this batch only once, so it must arm before the pass can fail"
    );
    assert_eq!(
        audit_rows_of_kind(&app, "epoch_stall_backfill_armed"),
        1,
        "the arm must leave its durable forensic row even on a failing pass"
    );
}

/// One effects batch carrying a resource refusal for `group_id` alongside a
/// confirmed-but-partial publish failure: the shape the gate passes as a soft
/// warning (mdk#428).
fn a_refusal_riding_a_confirmed_but_partial_publish(
    group_id: &cgka_traits::GroupId,
) -> marmot_account::AccountDeviceEffects {
    let message_id = cgka_traits::MessageId::new(vec![0xcd; 32]);
    let mut effects = marmot_account::AccountDeviceEffects::default();
    effects.events.push(
        cgka_traits::engine::GroupEvent::TransportObjectResourceRefused {
            group_id: group_id.clone(),
            message_id: message_id.clone(),
            resource: cgka_traits::ingest::InboundResourceLimit::TransportDeferredCapacity,
        },
    );
    effects.failures.push(marmot_account::PublishFailure {
        message_id,
        reason: "insufficient publish acknowledgements".to_owned(),
    });
    effects
        .pending
        .push(marmot_account::PendingResolution::Confirmed {
            pending: cgka_traits::engine_state::PendingStateRef::new(7),
        });
    effects
}

/// A resource refusal carried by an ordinary send must arm epoch-gap recovery
/// even when that send's publish gate fails it.
///
/// The engine releases deferred-peel rows in the foreground of `do_send` and of
/// the queued-outbound drain, so a plain send's effects can carry a
/// `TransportObjectResourceRefused` — buffered only after its durable retention
/// row was deleted, and delivered to the app exactly once. A gate that returned
/// before arming dropped it for good, and no send-path observer downstream of
/// the gate arms.
#[tokio::test]
async fn a_publish_failure_on_the_send_path_still_arms_recovery() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://send-arm.example")
        .with_test_relay_client(relay.clone());
    app.set_audit_log_settings(AuditLogSettings { enabled: true })
        .unwrap();
    let mut client = app.client("alice").await.unwrap();
    let group_id = client.create_group("send arm ordering", &[]).await.unwrap();
    assert_eq!(audit_rows_of_kind(&app, "epoch_stall_backfill_armed"), 0);

    let effects = a_refusal_riding_a_rolled_back_publish(&group_id);
    let result = client
        .observe_recovery_evidence_then_gate_send_publish(&effects, &group_id, "current-send")
        .await;

    assert!(
        result.is_err(),
        "a rolled-back publish failure must still fail the send"
    );
    assert!(
        client.has_pending_epoch_backfill(),
        "the refusal rides this batch only once, so it must arm before the send can fail"
    );
    assert_eq!(
        audit_rows_of_kind(&app, "epoch_stall_backfill_armed"),
        1,
        "the arm must leave its durable forensic row even on a failing send"
    );
}

/// Arming ahead of the send gate must not change what the gate accepts: a
/// confirmed-but-partial publish still passes (mdk#428), and the refusal riding
/// it is observed all the same.
#[tokio::test]
async fn a_confirmed_but_partial_send_publish_still_passes_the_arming_gate() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://send-soft-arm.example")
        .with_test_relay_client(relay.clone());
    app.set_audit_log_settings(AuditLogSettings { enabled: true })
        .unwrap();
    let mut client = app.client("alice").await.unwrap();
    let group_id = client
        .create_group("send soft arm ordering", &[])
        .await
        .unwrap();

    let effects = a_refusal_riding_a_confirmed_but_partial_publish(&group_id);
    let result = client
        .observe_recovery_evidence_then_gate_send_publish(&effects, &group_id, "current-send")
        .await;

    assert!(
        result.is_ok(),
        "a confirmed-but-partial publish must stay a soft pass on the send path"
    );
    assert!(
        client.has_pending_epoch_backfill(),
        "a refusal riding a passing batch must arm too"
    );
    assert_eq!(
        audit_rows_of_kind(&app, "epoch_stall_backfill_armed"),
        1,
        "the arm must leave exactly one durable forensic row"
    );
}

/// The arming gate is observation plus the unchanged publish check: for every
/// classification it must return exactly what the bare check returns, so no
/// caller's error path is widened or narrowed by arming ahead of it.
#[tokio::test]
async fn the_arming_publish_gate_classifies_exactly_as_the_bare_publish_check() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://gate-parity.example")
        .with_test_relay_client(relay.clone());
    let mut client = app.client("alice").await.unwrap();
    let group_id = client.create_group("gate parity", &[]).await.unwrap();

    let clean = marmot_account::AccountDeviceEffects::default();
    let mut failure_without_pending = marmot_account::AccountDeviceEffects::default();
    failure_without_pending
        .failures
        .push(marmot_account::PublishFailure {
            message_id: cgka_traits::MessageId::new(vec![0xef; 32]),
            reason: "relay rejected".to_owned(),
        });
    let batches = [
        ("no failures", clean),
        (
            "rolled back",
            a_refusal_riding_a_rolled_back_publish(&group_id),
        ),
        (
            "confirmed but partial",
            a_refusal_riding_a_confirmed_but_partial_publish(&group_id),
        ),
        ("failure without pending", failure_without_pending),
    ];

    for (label, effects) in batches {
        let bare = crate::groups::fail_if_publish_failed(&effects).map_err(|err| err.to_string());
        let armed = client
            .observe_recovery_evidence_then_fail_if_publish_failed(&effects)
            .map_err(|err| err.to_string());
        assert_eq!(
            armed, bare,
            "arming must not change how the gate classifies a {label} publish"
        );
    }
}

fn an_epoch_passage(
    group_id: &cgka_traits::GroupId,
    from: u64,
    to: u64,
) -> marmot_account::AccountDeviceEffects {
    let mut effects = marmot_account::AccountDeviceEffects::default();
    effects
        .events
        .push(cgka_traits::engine::GroupEvent::EpochChanged {
            group_id: group_id.clone(),
            from: cgka_traits::EpochId(from),
            to: cgka_traits::EpochId(to),
        });
    effects
}

/// One convergence pass that adjudicated a fork: the losing commit is rolled
/// back and every state notification it produced is withdrawn.
///
/// The epoch on the withdrawal is the fork's SOURCE epoch — the epoch the
/// superseded commit branched from — which is deliberately behind where the
/// device sits. A same-epoch reorg emits no `EpochChanged` at all, so this pair
/// is the only announcement the app ever gets that convergence moved the
/// canonical branch under it.
fn a_convergence_reorg(
    group_id: &cgka_traits::GroupId,
    fork_source_epoch: u64,
) -> marmot_account::AccountDeviceEffects {
    let invalidated_commit_id = cgka_traits::MessageId::new(vec![7u8; 32]);
    let mut effects = marmot_account::AccountDeviceEffects::default();
    effects
        .events
        .push(cgka_traits::engine::GroupEvent::CommitRolledBack {
            group_id: group_id.clone(),
            invalidated_commit_id: invalidated_commit_id.clone(),
        });
    effects
        .events
        .push(cgka_traits::engine::GroupEvent::GroupStateInvalidated {
            group_id: group_id.clone(),
            epoch: cgka_traits::EpochId(fork_source_epoch),
            invalidated_commit_id,
            reason: cgka_traits::engine::GroupStateInvalidationReason::SupersededByBranchSelection,
        });
    effects
}

/// A convergence reorg is liveness evidence and must end the unrecovered arm
/// run, exactly as a spanning epoch passage does.
///
/// Nothing else can carry it. A same-epoch reorg leaves `previous_tip ==
/// selected_tip`, so no `EpochChanged` is emitted, and the device's own epoch
/// does not move — every other signal this detector reads is identical to a
/// device that saw nothing at all. Without this the arms that accumulated
/// while convergence was busy adjudicating a fork read as one unrecovered run
/// and escalate a device onto the wrong recovery: relay backfill cannot supply
/// the branch adoption that fork-side traffic is waiting for.
#[tokio::test]
async fn a_convergence_reorg_ends_the_unrecovered_arm_run() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://convergence-reorg.example")
        .with_test_relay_client(relay.clone());
    let mut client = app.client("alice").await.unwrap();
    let group_id = client.create_group("convergence reorg", &[]).await.unwrap();

    // Two arms of one run, at two epochs the device armed at.
    assert_eq!(
        client.epoch_stall.observe_resource_refusal(
            group_id.clone(),
            cgka_traits::EpochId(10),
            epoch_stall_test_now_ms()
        ),
        crate::client::epoch_stall::BackfillDecision::Arm
    );
    assert_eq!(
        client.epoch_stall.observe_resource_refusal(
            group_id.clone(),
            cgka_traits::EpochId(11),
            epoch_stall_test_now_ms()
        ),
        crate::client::epoch_stall::BackfillDecision::Arm
    );

    // Convergence then resolves a fork this device was on the wrong side of.
    client
        .observe_recovery_evidence_then_fail_if_publish_failed(&a_convergence_reorg(&group_id, 9))
        .expect("a batch carrying only a convergence reorg passes the publish gate");

    // Without the reorg this third arm is the run's escalating one
    // (`escalates_when_arms_repeat_without_passing_cleanly_through_an_epoch`
    // pins that shape). With it, the arms before the reorg are not one
    // unrecovered run.
    assert_eq!(
        client.epoch_stall.observe_resource_refusal(
            group_id,
            cgka_traits::EpochId(12),
            epoch_stall_test_now_ms()
        ),
        crate::client::epoch_stall::BackfillDecision::Arm,
        "a group whose fork convergence just adjudicated is alive; the arms it took to get there are not evidence that a replay is failing to recover it"
    );
}

/// A maintenance tick's own epoch advance must reach the stall detector.
///
/// A tick drains a recovered staged evolution and confirms it, which emits
/// `EpochChanged` into the batch this seam projects — and nowhere else. Miss it
/// and the detector keeps believing the device sits at the epoch it armed at, so
/// the *next* passage a peer fold reports cannot end the run either: its
/// `from + 1` lands on the armed epoch and decides nothing. Two unrelated stalls
/// later, a recovered device is escalated.
#[tokio::test]
async fn a_maintenance_tick_reports_its_own_epoch_passage_to_the_stall_detector() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://maintenance-passage.example")
        .with_test_relay_client(relay.clone());
    let mut client = app.client("alice").await.unwrap();
    let group_id = client
        .create_group("maintenance passage", &[])
        .await
        .unwrap();

    // The group is stuck and arms once, at epoch 10.
    assert_eq!(
        client.epoch_stall.observe_resource_refusal(
            group_id.clone(),
            cgka_traits::EpochId(10),
            epoch_stall_test_now_ms()
        ),
        crate::client::epoch_stall::BackfillDecision::Arm
    );

    // Maintenance then confirms a recovered evolution, 10 -> 11.
    client
        .observe_recovery_evidence_then_summarize_maintenance(&an_epoch_passage(&group_id, 10, 11))
        .expect("a maintenance batch carrying only an epoch passage summarizes cleanly");

    // A peer fold carries the device on to 12. Only a detector that heard the
    // maintenance passage is sitting at 11 to have this one leave it.
    client.epoch_stall.observe_epoch_passage(
        &group_id,
        cgka_traits::EpochId(11),
        cgka_traits::EpochId(12),
    );

    // So the stalls that follow are a new run: without the maintenance report
    // the second of these is the run's escalating third arm.
    assert_eq!(
        client.epoch_stall.observe_resource_refusal(
            group_id.clone(),
            cgka_traits::EpochId(12),
            epoch_stall_test_now_ms()
        ),
        crate::client::epoch_stall::BackfillDecision::Arm
    );
    assert_eq!(
        client.epoch_stall.observe_resource_refusal(
            group_id,
            cgka_traits::EpochId(13),
            epoch_stall_test_now_ms()
        ),
        crate::client::epoch_stall::BackfillDecision::Arm,
        "the maintenance passage must have ended the run, so this is only its second arm"
    );
}

/// A confirmed local publish's epoch passage must reach the detector through the
/// publish gate.
///
/// An own commit is the strongest recovery evidence this layer ever sees — MLS
/// requires current-epoch state to commit, so the committer was at tip by
/// construction — but the engine reports it as an ordinary adjacent passage,
/// `from` synthesized as `new_epoch - 1`. So it takes two: the confirm moves the
/// detector off the armed epoch, and the next movement is what leaves an epoch
/// nothing armed at. This pins that both halves land, and that the publishing
/// seams carry the first one — the delivery-driven seams never see an own
/// confirm.
#[tokio::test]
async fn a_confirmed_local_publish_reports_its_epoch_passage_through_the_publish_gate() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://own-publish-passage.example")
        .with_test_relay_client(relay.clone());
    let mut client = app.client("alice").await.unwrap();
    let group_id = client
        .create_group("own publish passage", &[])
        .await
        .unwrap();

    // The group is stuck and arms once, at epoch 10.
    assert_eq!(
        client.epoch_stall.observe_resource_refusal(
            group_id.clone(),
            cgka_traits::EpochId(10),
            epoch_stall_test_now_ms()
        ),
        crate::client::epoch_stall::BackfillDecision::Arm
    );

    // The device then commits and the publish confirms, 10 -> 11.
    client
        .observe_recovery_evidence_then_fail_if_publish_failed(&an_epoch_passage(&group_id, 10, 11))
        .expect("a batch carrying only an epoch passage clears the publish gate");

    // One epoch per arm is a limp, so that confirm alone does not end the run —
    // the movement after it does.
    client.epoch_stall.observe_epoch_passage(
        &group_id,
        cgka_traits::EpochId(11),
        cgka_traits::EpochId(12),
    );

    assert_eq!(
        client.epoch_stall.observe_resource_refusal(
            group_id.clone(),
            cgka_traits::EpochId(12),
            epoch_stall_test_now_ms()
        ),
        crate::client::epoch_stall::BackfillDecision::Arm
    );
    assert_eq!(
        client.epoch_stall.observe_resource_refusal(
            group_id,
            cgka_traits::EpochId(13),
            epoch_stall_test_now_ms()
        ),
        crate::client::epoch_stall::BackfillDecision::Arm,
        "the confirm must have been observed, so this is only the new run's second arm"
    );
}

/// An escalation recorded while an inbound delivery is ingested must ride the
/// summary that seam returns.
///
/// `ingest_received_delivery` is the runtime's dominant receive path — the
/// account worker feeds every delivery it receives through it — and its `Ok` is
/// what the worker publishes escalations from. The other escalation tests all
/// deliver through `sync()`, so this pins the receive seam's own drain.
#[tokio::test]
async fn an_escalation_recorded_during_a_received_delivery_rides_that_seam() {
    let dir = tempfile::tempdir().unwrap();
    let account_id_hex = AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap()
        .account_id_hex;
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://ingest-seam.example")
        .with_test_relay_client(relay.clone());
    let mut client = app.client("alice").await.unwrap();
    let group_id = client.create_group("ingest seam", &[]).await.unwrap();

    client.apply_backfill_decision(
        &group_id,
        9,
        crate::client::epoch_stall::BackfillDecision::ArmAndEscalate { arms: 4 },
        marmot_forensics::EpochStallBackfillTrigger::UndecryptableThreshold,
    );

    let mut delivery = relay_delivery("escalation-seam", "55".repeat(32));
    delivery.account_id = MemberId::new(hex::decode(&account_id_hex).unwrap());
    let summary = client
        .ingest_received_delivery(delivery)
        .await
        .expect("an undecryptable delivery still completes its ingest pass");

    assert_eq!(
        summary
            .epoch_stall_escalations
            .iter()
            .map(|escalation| (
                escalation.group_id.clone(),
                escalation.stalled_epoch,
                escalation.arms
            ))
            .collect::<Vec<_>>(),
        vec![(group_id, 9, 4)],
        "the receive seam must publish the escalation recorded during its ingest"
    );
}

/// A delivery whose ingest fails must stay retryable on the same reused
/// client.
///
/// `receive_next_delivery` must not mark the id seen before
/// `ingest_received_delivery` commits it: a pre-ingest mark would poison the
/// seen-events index on failure, so the reused client would silently skip the
/// event when the relay redelivers it.
#[cfg(feature = "test-policy-overrides")]
#[tokio::test]
async fn a_failed_ingest_leaves_the_delivery_retryable_on_the_reused_client() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let bob = home.create_account("bob").unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    // One shared plane for both clients, so a publish fans out locally into
    // the other account's registered routes (`deliver_local_publish`).
    let plane = MarmotRelayPlane::new(None, relay.clone());

    let mut alice = app
        .client_with_relay_plane("alice", &plane, None)
        .await
        .unwrap();
    let mut bob_client = app
        .client_with_relay_plane("bob", &plane, None)
        .await
        .unwrap();
    // Register bob's inbox route before the welcome publishes.
    bob_client.sync().await.unwrap();
    let group_id = alice
        .create_group("retryable failed ingest", &[bob.account_id_hex.as_str()])
        .await
        .unwrap();
    let inject = |event: NostrTransportEvent| {
        let plane = plane.clone();
        async move {
            plane
                .handle_relay_event_for_test(NostrRelayEvent {
                    endpoint: TransportEndpoint("wss://relay.example".to_owned()),
                    subscription_id: None,
                    event,
                })
                .await
        }
    };
    assert!(
        bob_client
            .sync()
            .await
            .unwrap()
            .joined_groups
            .contains(&group_id),
        "bob must join before the failing application message",
    );

    let published_before_send = relay.published_events.lock().unwrap().len();
    alice
        .send(&group_id, b"must survive a failed ingest")
        .await
        .unwrap();
    let relay_event = relay
        .published_events
        .lock()
        .unwrap()
        .iter()
        .skip(published_before_send)
        .find(|event| event.kind == transport_nostr_peeler::KIND_MARMOT_GROUP_MESSAGE)
        .cloned()
        .expect("published group message backing the send");
    bob_client
        .app
        .config
        .dev_fail_ingest_after_application_event_ack = true;
    let delivery = tokio::time::timeout(Duration::from_secs(5), bob_client.receive_next_delivery())
        .await
        .expect("locally fanned-out application message")
        .unwrap();
    let crate::relay_plane::AccountDeliveryReceive::Delivery(delivery) = delivery else {
        panic!("the test did not overflow its account delivery queue");
    };
    let delivery = *delivery;
    let event_id = hex::encode(delivery.message.id.as_slice());
    assert_eq!(event_id, relay_event.id);
    bob_client
        .ingest_received_delivery(delivery)
        .await
        .expect_err("the injected post-ack failure must surface");
    assert!(
        !bob_client.seen_events_index.contains(&event_id),
        "a failed ingest must not mark the delivery seen",
    );

    // The relay redelivers (for example on resubscribe); the reused client
    // must return the delivery again instead of skipping it as already seen.
    bob_client
        .app
        .config
        .dev_fail_ingest_after_application_event_ack = false;
    assert!(
        inject(relay_event).await.expect("route the redelivery") >= 1,
        "the group route must accept the redelivery",
    );
    let redelivery =
        tokio::time::timeout(Duration::from_secs(5), bob_client.receive_next_delivery())
            .await
            .expect("redelivered application message")
            .unwrap();
    let crate::relay_plane::AccountDeliveryReceive::Delivery(redelivery) = redelivery else {
        panic!("the test did not overflow its account delivery queue");
    };
    let redelivery = *redelivery;
    assert_eq!(hex::encode(redelivery.message.id.as_slice()), event_id);
    let summary = bob_client
        .ingest_received_delivery(redelivery)
        .await
        .expect("the retry must ingest the redelivered event");
    assert!(
        bob_client.seen_events_index.contains(&event_id),
        "a successful ingest must mark the delivery seen",
    );
    // The first attempt durably projected the message before its injected
    // post-ack failure, so the retried duplicate must not project it again.
    // (Live-summary replay after a post-ack failure is pinned separately in
    // `tests/partial_sync_summary.rs`.)
    assert!(
        summary.messages.is_empty(),
        "the retried duplicate must not re-project the already-applied message",
    );
    assert_eq!(
        app.messages("bob")
            .unwrap()
            .iter()
            .map(|message| message.plaintext.as_str())
            .collect::<Vec<_>>(),
        vec!["must survive a failed ingest"],
        "the failed delivery's message must be durably projected exactly once",
    );
}
/// The clock a test uses when it drives the epoch-stall detector directly.
///
/// The very same reading production takes, deliberately. These tests arm
/// through the detector and then let real ingests observe the same group, and
/// the frozen-epoch pacing gate compares the two readings: a test clock frozen
/// at some fixed past instant would make every later production observation
/// look hours late and buy a paced re-arm nothing asked for.
fn epoch_stall_test_now_ms() -> u64 {
    crate::client::epoch_stall_now_ms()
}

/// A group whose per-group retained-undecryptable backlog is exactly full, plus
/// everything a test needs to mint one more undecryptable delivery for it.
///
/// `cgka_engine::message_processor::MAX_PEEL_DEFERRED_ROWS_PER_GROUP` is the
/// only way to reach `IngestOutcome::ResourceRefused`: the engine offers no
/// knob for the cap, so the backlog is filled for real. Below the cap an
/// unpeelable object is *retained* (`TransportDeferred`); at it the engine drops
/// the object unpersisted and keeps its id out of its own seen cache, so
/// transport redelivery is the only path back to it.
struct UndecryptableProbeRoute {
    account_id_hex: String,
    group_id: cgka_traits::GroupId,
    nostr_group_id_hex: String,
}

impl UndecryptableProbeRoute {
    /// One kind-445 delivery for this group's route whose body cannot peel.
    fn probe(&self, created_at: u64, marker: &str) -> cgka_traits::TransportDelivery {
        cgka_traits::TransportDelivery {
            account_id: MemberId::new(hex::decode(&self.account_id_hex).unwrap()),
            group_id_hint: Some(self.group_id.clone()),
            message: epoch_gap_probe(&self.nostr_group_id_hex, created_at, marker)
                .to_transport_message()
                .expect("probe converts to a transport message"),
            received_at: cgka_traits::transport::Timestamp(created_at),
            source: cgka_traits::TransportDeliverySource {
                transport: cgka_traits::transport::TransportSource("nostr".to_owned()),
                plane: cgka_traits::TransportDeliveryPlane::Group,
                endpoint: None,
                subscription_id: None,
                wire: None,
            },
        }
    }
}

/// Build [`UndecryptableProbeRoute`]'s group and fill its retained-undecryptable
/// backlog to the cap, on an app whose relay plane accepts injected events.
///
/// Every filling probe is dated `filled_through` so a later probe's effect on
/// the transport cursor is unambiguous, and each is ingested through the receive
/// seam because that is the cheapest way to reach the engine 256 times.
async fn group_at_the_undecryptable_retention_cap(
    dir: &tempfile::TempDir,
    filled_through: u64,
) -> (MarmotApp, crate::AppClient, UndecryptableProbeRoute) {
    let relay = Arc::new(ScriptedPushRelayClient::default());
    group_at_the_undecryptable_retention_cap_with_config(
        dir,
        &relay,
        MarmotAppConfig::default(),
        filled_through,
    )
    .await
}

async fn group_at_the_undecryptable_retention_cap_with_config(
    dir: &tempfile::TempDir,
    relay: &Arc<ScriptedPushRelayClient>,
    config: MarmotAppConfig,
    filled_through: u64,
) -> (MarmotApp, crate::AppClient, UndecryptableProbeRoute) {
    let (app, mut client, route) = undecryptable_probe_route(dir, relay, config).await;
    for row in 0..cgka_engine::message_processor::MAX_PEEL_DEFERRED_ROWS_PER_GROUP {
        client
            .ingest_received_delivery(route.probe(filled_through, &format!("cap-fill-{row}")))
            .await
            .expect("a retained undecryptable object completes its ingest pass");
    }
    assert_eq!(
        client.state.last_transport_timestamp,
        Some(filled_through),
        "the retained probes must have advanced the cursor to their own timestamp",
    );
    (app, client, route)
}

/// [`UndecryptableProbeRoute`]'s group with its retained-undecryptable backlog
/// still empty, for the tests that need probes to be *retained*
/// (`IngestOutcome::TransportDeferred`) rather than refused.
async fn undecryptable_probe_route(
    dir: &tempfile::TempDir,
    relay: &Arc<ScriptedPushRelayClient>,
    config: MarmotAppConfig,
) -> (MarmotApp, crate::AppClient, UndecryptableProbeRoute) {
    let account_id_hex = AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap()
        .account_id_hex;
    let mut app =
        MarmotApp::with_relay_and_config(dir.path(), "wss://relay.example".to_owned(), config)
            .with_test_relay_client(relay.clone());
    app.set_audit_log_settings(crate::AuditLogSettings { enabled: true })
        .unwrap();
    app.relay_plane =
        MarmotRelayPlane::new_with_loopback(Some(Duration::from_secs(120)), relay.clone(), true);

    let mut client = client_on_app_relay_plane(&app, "alice").await;
    let group_id = client
        .create_group("undecryptable retention cap", &[])
        .await
        .unwrap();
    let nostr_group_id_hex = app
        .group("alice", &hex::encode(group_id.as_slice()))
        .unwrap()
        .expect("local group projection")
        .nostr_routing
        .nostr_group_id_hex;
    let route = UndecryptableProbeRoute {
        account_id_hex,
        group_id,
        nostr_group_id_hex,
    };
    (app, client, route)
}

/// Every `ingest_outcome` audit row the engine recorded for `msg_id`.
fn recorded_ingest_outcomes(app: &MarmotApp, msg_id: &str) -> Vec<String> {
    recorded_audit_rows(app)
        .iter()
        .filter(|row| row["kind"]["type"] == "ingest_outcome")
        .filter(|row| row["kind"]["msg_id"].as_str() == Some(msg_id))
        .filter_map(|row| row["kind"]["outcome_kind"].as_str().map(ToOwned::to_owned))
        .collect()
}

/// One kind-445 delivery for a route this device has no group row for.
///
/// The reachable production trigger is *not* a commit racing ahead of its
/// Welcome — a device that is not in a group has no route for it, every 445
/// filter is `#h`-scoped to a known `transport_group_id`, and the adapter
/// re-gates every event against the route table before it becomes a delivery.
/// It is the engine's route-backfill probe budget: on an index miss
/// `resolve_or_backfill_group_id_for_transport` probes at most
/// `ROUTE_BACKFILL_PROBES_PER_MISS` (4) of the groups whose durable route row
/// was missing or stale at hydration, and otherwise falls back to the raw
/// transport id, which misses `MlsGroup::load` and takes the unknown-group
/// branch — for a group this device really does have. The app-side consequence
/// is the same either way and is what these two tests pin; the engine's
/// disposition contract is pinned in `cgka-engine`'s
/// `ingest_unknown_group_message_leaves_the_object_unpersisted`.
fn unknown_route_delivery(
    account_id_hex: &str,
    created_at: u64,
    marker: &str,
) -> cgka_traits::TransportDelivery {
    cgka_traits::TransportDelivery {
        account_id: MemberId::new(hex::decode(account_id_hex).unwrap()),
        group_id_hint: None,
        message: epoch_gap_probe(&"ab".repeat(32), created_at, marker)
            .to_transport_message()
            .expect("probe converts to a transport message"),
        received_at: cgka_traits::transport::Timestamp(created_at),
        source: cgka_traits::TransportDeliverySource {
            transport: cgka_traits::transport::TransportSource("nostr".to_owned()),
            plane: cgka_traits::TransportDeliveryPlane::Group,
            endpoint: None,
            subscription_id: None,
            wire: None,
        },
    }
}

/// An object the engine kept no durable trace of must not enter `seen_events`,
/// even when its outcome is an ordinary `Ignored`.
///
/// The engine sets `retryable_unpersisted_ingest_id` on the unknown-group
/// branch and suppresses its own seen-cache insertion, precisely so relay
/// redelivery can process the object once the route resolves. Recording it in
/// `seen_events` defeats that permanently: the index is persisted, has no
/// removal site short of ring overflow, and gates both
/// `receive_next_delivery` and the catch-up drain — so the object becomes
/// unfetchable across restarts and across `repair_full_history` alike.
///
/// The cursor still advances. Unknown-route input is exactly what #740 says
/// must not consume local resources, and the `since` floor is one of them: an
/// attacker minting 445s for routes we do not have could otherwise pin the
/// whole account's floor in the past. Skipping the seen-mark is what actually
/// restores the object, because the unfloored recovery replay re-serves it.
#[test]
fn an_unknown_route_delivery_is_not_marked_seen_but_still_advances_the_cursor() {
    run_composed_app_runtime_test("unknown-route-receive-seam", || async {
        let dir = tempfile::tempdir().unwrap();
        let filled_through = crate::unix_now_seconds() - 1_000;
        let (app, mut client, route) =
            group_at_the_undecryptable_retention_cap(&dir, filled_through).await;

        let unknown = unknown_route_delivery(
            &route.account_id_hex,
            filled_through + 500,
            "unknown-route-commit",
        );
        let event_id = hex::encode(unknown.message.id.as_slice());
        client
            .ingest_received_delivery(unknown.clone())
            .await
            .expect("an unknown-route ingest still completes its pass");

        assert_eq!(
            recorded_ingest_outcomes(&app, &event_id),
            vec!["ignored".to_owned()],
            "the engine classifies it as an ignore, which is why the app could not \
             tell it apart from a durably dedup-marked one",
        );
        assert!(
            !client.seen_events_index.contains(&event_id),
            "an object the engine retained nothing for must stay fetchable",
        );
        assert!(
            !client.state.seen_events.contains(&event_id),
            "and must not be persisted into the seen ring either",
        );
        assert_eq!(
            client.state.last_transport_timestamp,
            Some(filled_through + 500),
            "but the `since` floor still advances: unknown-route input must not \
             hold the whole account's cursor back (#740)",
        );

        // The contract the skipped seen-mark buys: redelivery is ingested again
        // rather than dropped, so a later drain can present the object once the
        // route resolves.
        client
            .ingest_received_delivery(unknown)
            .await
            .expect("redelivery still completes its pass");
        assert_eq!(
            recorded_ingest_outcomes(&app, &event_id).len(),
            2,
            "same-id redelivery must reach the engine a second time",
        );
    });
}

/// Why the drain seam cannot be driven with an unknown route from here, and
/// what the route-backfill miss actually looks like.
///
/// The relay plane route-gates every inbound event before it can become a
/// `TransportDelivery`: an unknown `#h` routes to nobody. That is the same gate
/// that makes "a commit racing ahead of its Welcome" unreachable — a device not
/// in a group has no route for it, so no 445 for that group is ever delivered.
/// The reachable trigger is narrower and lives one layer down: the *adapter*
/// has the route (the device really is in the group) while the *engine's*
/// in-memory route index misses it and the route-backfill probe budget runs out,
/// so `resolve_or_backfill_group_id_for_transport` falls back to the raw
/// transport id and takes the unknown-group branch.
///
/// The app-side rule that branch needs is `must_stay_fetchable`, which both
/// seams read off the identical `DeliveryIngest` field — pinned at the receive
/// seam above, and at the drain seam by
/// `a_refused_delivery_is_neither_marked_seen_nor_allowed_to_advance_the_cursor`.
/// What is pinned here is the gate itself, so the unreachability claim is a
/// test rather than a comment.
#[test]
fn an_unknown_route_event_is_never_routed_to_a_delivery() {
    run_composed_app_runtime_test("unknown-route-transport-gate", || async {
        let dir = tempfile::tempdir().unwrap();
        let filled_through = crate::unix_now_seconds() - 1_000;
        let (app, client, _route) =
            group_at_the_undecryptable_retention_cap(&dir, filled_through).await;

        let delivered = app
            .relay_plane
            .handle_relay_event_for_test(NostrRelayEvent {
                endpoint: TransportEndpoint("wss://relay.example".to_owned()),
                subscription_id: Some("unknown-route-test".to_owned()),
                event: epoch_gap_probe(
                    &"ab".repeat(32),
                    filled_through + 500,
                    "unknown-route-commit",
                ),
            })
            .await
            .expect("routing an unknown-route event is not an error");
        assert_eq!(
            delivered, 0,
            "a 445 for a route this device does not hold must not become a delivery",
        );
        drop(client);
    });
}

/// A refused object must stay fetchable: the receive seam may neither mark it
/// seen nor let it advance the relay `since` cursor.
///
/// `IngestOutcome::ResourceRefused` is an `Ok` the engine deliberately leaves
/// unpersisted — it suppresses its own seen-cache insertion so "same-id
/// redelivery is not a duplicate". Marking it seen here defeats that: the id is
/// persisted in `seen_events` with no removal site short of ring overflow, and
/// the advanced cursor puts the object below the next subscription's `since`
/// floor, so the message becomes permanently unfetchable across restarts and
/// even across `repair_full_history`.
#[test]
fn a_refused_delivery_is_neither_marked_seen_nor_allowed_to_advance_the_cursor() {
    run_composed_app_runtime_test("refused-ingest-receive-seam", || async {
        let dir = tempfile::tempdir().unwrap();
        let filled_through = crate::unix_now_seconds() - 1_000;
        let (app, mut client, route) =
            group_at_the_undecryptable_retention_cap(&dir, filled_through).await;

        // Minted once and cloned, so the redelivery below is byte-identical:
        // a re-minted probe would carry a fresh ephemeral key and a fresh id.
        let refused = route.probe(filled_through + 500, "refused-at-the-cap");
        let refused_id = hex::encode(refused.message.id.as_slice());
        client
            .ingest_received_delivery(refused.clone())
            .await
            .expect("a refused object still completes its ingest pass");

        assert_eq!(
            recorded_ingest_outcomes(&app, &refused_id),
            vec!["resource_refused".to_owned()],
            "the backlog must be full, so this object is refused rather than retained",
        );
        assert!(
            !client.seen_events_index.contains(&refused_id),
            "a refused object is not durably ingested, so it must not be marked seen",
        );
        assert!(
            !client.state.seen_events.contains(&refused_id),
            "nor persisted into the durable seen-events ring",
        );
        assert_eq!(
            client.state.last_transport_timestamp,
            Some(filled_through),
            "a refused object must not carry the relay `since` floor past itself",
        );

        // The unstick proof: the relay redelivers, and the reused client hands
        // the object to the engine again instead of skipping it as seen. It is
        // still refused — the backlog is still full — which is itself the
        // evidence that the engine reclassified it rather than deduplicating it.
        client
            .ingest_received_delivery(refused)
            .await
            .expect("the redelivered object must reach the engine again");
        assert_eq!(
            recorded_ingest_outcomes(&app, &refused_id),
            vec!["resource_refused".to_owned(), "resource_refused".to_owned()],
            "the redelivery must be reclassified, never deduplicated away",
        );
        assert!(
            !client.seen_events_index.contains(&refused_id),
            "and it stays fetchable for as long as the engine keeps refusing it",
        );
    });
}

/// The fence: a `TransportDeferred` object *is* durably retained by the engine,
/// so marking it seen is correct dedupe and stays. Only the unpersisted refusal
/// is exempt.
#[test]
fn a_transport_deferred_delivery_is_still_marked_seen() {
    run_composed_app_runtime_test("transport-deferred-marks-seen", || async {
        let dir = tempfile::tempdir().unwrap();
        let account_id_hex = AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap()
            .account_id_hex;
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let mut app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        app.set_audit_log_settings(crate::AuditLogSettings { enabled: true })
            .unwrap();
        app.relay_plane = MarmotRelayPlane::new_with_loopback(
            Some(Duration::from_secs(120)),
            relay.clone(),
            true,
        );
        let mut client = client_on_app_relay_plane(&app, "alice").await;
        let group_id = client.create_group("deferred fence", &[]).await.unwrap();
        let route = UndecryptableProbeRoute {
            account_id_hex,
            nostr_group_id_hex: app
                .group("alice", &hex::encode(group_id.as_slice()))
                .unwrap()
                .expect("local group projection")
                .nostr_routing
                .nostr_group_id_hex,
            group_id,
        };

        let created_at = crate::unix_now_seconds() - 1_000;
        let deferred = route.probe(created_at, "retained-below-the-cap");
        let deferred_id = hex::encode(deferred.message.id.as_slice());
        client
            .ingest_received_delivery(deferred)
            .await
            .expect("a retained undecryptable object completes its ingest pass");

        assert_eq!(
            recorded_ingest_outcomes(&app, &deferred_id),
            vec!["transport_deferred".to_owned()],
            "below the cap the engine retains the object durably",
        );
        assert!(
            client.seen_events_index.contains(&deferred_id),
            "a durably retained object must still be deduplicated by the seen index",
        );
        assert_eq!(
            client.state.last_transport_timestamp,
            Some(created_at),
            "and it still carries the relay `since` floor forward",
        );
    });
}

/// The same rule at the catch-up drain seam: a refused delivery must leave both
/// the seen index and the transport cursor untouched there too, so the relay
/// re-serves it on the next drain instead of the app skipping it.
#[test]
fn a_refused_delivery_stays_fetchable_through_the_catch_up_drain() {
    run_composed_app_runtime_test("refused-ingest-drain-seam", || async {
        let dir = tempfile::tempdir().unwrap();
        let filled_through = crate::unix_now_seconds() - 1_000;
        let (app, mut client, route) =
            group_at_the_undecryptable_retention_cap(&dir, filled_through).await;

        let refused = epoch_gap_probe(
            &route.nostr_group_id_hex,
            filled_through + 500,
            "refused-in-the-drain",
        );
        let refused_id = refused.id.clone();
        inject_epoch_gap_probe(&app, refused.clone()).await;
        client.sync().await.expect("the drain must complete");

        assert_eq!(
            recorded_ingest_outcomes(&app, &refused_id),
            vec!["resource_refused".to_owned()],
            "the backlog must be full, so the drain's object is refused",
        );
        assert!(
            !client.seen_events_index.contains(&refused_id),
            "the drain must not mark a refused object seen",
        );
        assert_eq!(
            client.state.last_transport_timestamp,
            Some(filled_through),
            "nor carry the relay `since` floor past it",
        );

        // The relay re-serves it on the next drain, and the drain ingests it
        // again rather than counting it as an already-seen skip.
        inject_epoch_gap_probe(&app, refused).await;
        client.sync().await.expect("the second drain must complete");
        assert_eq!(
            recorded_ingest_outcomes(&app, &refused_id),
            vec!["resource_refused".to_owned(), "resource_refused".to_owned()],
            "the re-served object must reach the engine again",
        );
    });
}

/// Every SQLite database this app can open, plus the root runtime lease, must
/// be released by one `close_storage` call — that is the whole contract iOS
/// depends on before it suspends the process (`0xdead10cc` is raised for *any*
/// lock held in the shared App Group container, not just the session database).
#[test]
fn close_storage_releases_every_database_and_the_root_lease() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let account = AccountHome::open(root).create_account("closing").unwrap();
    let app = MarmotApp::try_with_relays_and_account_home_and_config(
        root,
        Vec::new(),
        AccountHome::open(root),
        MarmotAppConfig::default(),
    )
    .unwrap();

    // Open, and dirty, all three database families. Keep the handles: they are
    // the only way to prove the *connections* were closed rather than merely
    // dropped from the app's caches.
    let session_storage = app.account_storage(&account.label).unwrap();
    session_storage.app_message_count().unwrap();
    let shared_storage = app.shared_storage().unwrap();
    shared_storage
        .set_relay_telemetry_settings(&StoredRelayTelemetrySettings {
            export_enabled: true,
            export_interval_seconds: 30,
        })
        .unwrap();
    let directory_cache = app.directory_cache_for_account(&account).unwrap();
    directory_cache.entries().unwrap();

    let session_db = app.account_storage_path(&account.label);
    let shared_db = app.shared_storage_path();
    let sidecars = |db: &std::path::Path| {
        [
            PathBuf::from(format!("{}-wal", db.display())),
            PathBuf::from(format!("{}-shm", db.display())),
        ]
    };
    assert!(
        sidecars(&shared_db).iter().all(|p| p.exists()),
        "the shared database should hold WAL sidecars while open",
    );
    // The lease is held for as long as the app is alive.
    assert!(matches!(
        MarmotRootRuntimeLease::try_acquire(root),
        Err(AppError::RuntimeBusy)
    ));

    app.close_storage().expect("close_storage should succeed");

    assert!(app.storage_is_closed());
    for db in [&session_db, &shared_db] {
        for sidecar in sidecars(db) {
            assert!(
                !sidecar.exists(),
                "{} must be gone once the last connection closes",
                sidecar.display(),
            );
        }
    }
    // The directory cache is opened in rollback-journal mode, so it has no WAL
    // sidecars to check. Its connection still has to be closed, and the handle
    // taken before the close is what proves it: a cache that was merely evicted
    // from the app's map would keep answering.
    assert!(
        matches!(
            directory_cache.entries(),
            Err(AppError::Storage(err)) if err.is_closed()
        ),
        "the directory cache connection must be closed, not just uncached",
    );
    // Same for the two WAL databases, via the handles rather than the caches.
    assert!(session_storage.is_closed());
    assert!(shared_storage.is_closed());

    // The lease is an advisory lock on a file in the same container, so it has
    // to go too; a second acquirer proves it did.
    drop(MarmotRootRuntimeLease::try_acquire(root).expect("root lease must be released"));

    // Nothing reopens: a late read must report the close instead of re-locking
    // the container the host was just told is clear.
    for error in [
        app.account_storage(&account.label).err(),
        app.shared_storage().err(),
        app.directory_cache_for_account(&account).err(),
        app.projection_status(&account.label).err(),
    ]
    .into_iter()
    .map(|error| error.expect("a closed app must not hand out a database"))
    {
        assert!(
            matches!(&error, AppError::Storage(err) if err.is_closed()),
            "expected a closed-storage error, got {error:?}",
        );
    }
}

/// `close_storage` must not return — or release the root lease — while a
/// database open is still in flight. Otherwise a host that awaited it, or
/// another process that saw the lease free, would proceed while a freshly
/// created SQLite connection still held locks in the container.
///
/// The read side of `storage_lifecycle` is exactly what an in-flight open
/// holds, so taking it here stands in for one deterministically.
#[test]
fn close_storage_waits_for_an_open_that_is_already_in_flight() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    AccountHome::open(root).create_account("racing").unwrap();
    let app = MarmotApp::try_with_relays_and_account_home_and_config(
        root,
        Vec::new(),
        AccountHome::open(root),
        MarmotAppConfig::default(),
    )
    .unwrap();

    let in_flight_open = app
        .storage_lifecycle
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let closing_app = app.clone();
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (closed_tx, closed_rx) = std::sync::mpsc::channel();
    let closer = std::thread::spawn(move || {
        // Signal from inside the thread, immediately before the call. Without
        // this the timeout assertion below would also pass if the thread had
        // simply not been scheduled yet, which proves nothing about blocking.
        let _ = started_tx.send(());
        let result = closing_app.close_storage();
        let _ = closed_tx.send(());
        result
    });
    started_rx
        .recv()
        .expect("the closing thread should reach close_storage");

    // While the open is in flight the close must make no observable progress:
    // it has not returned, and the root lease is still held.
    assert!(
        closed_rx
            .recv_timeout(std::time::Duration::from_millis(250))
            .is_err(),
        "close_storage must not return while an open is in flight",
    );
    assert!(
        matches!(
            MarmotRootRuntimeLease::try_acquire(root),
            Err(AppError::RuntimeBusy)
        ),
        "the root lease must not be released while an open is in flight",
    );

    drop(in_flight_open);
    closer
        .join()
        .unwrap()
        .expect("close_storage should succeed once the open finishes");
    drop(MarmotRootRuntimeLease::try_acquire(root).expect("root lease must be released"));
}

/// Legacy account projection import opens a short-lived raw SQLite connection
/// after the cached account storage has already been returned. That entire
/// window must count as an in-flight storage open; otherwise terminal close can
/// return and release the root lease immediately before the migration reopens
/// the legacy database in the shared container.
#[test]
fn close_storage_waits_for_legacy_projection_import() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let home = AccountHome::open(root);
    home.create_account("legacy-racing").unwrap();
    let app = MarmotApp::try_with_relays_and_account_home_and_config(
        root,
        Vec::new(),
        AccountHome::open(root),
        MarmotAppConfig::default(),
    )
    .unwrap();

    let keys = app
        .account_home()
        .load_signing_keys("legacy-racing")
        .unwrap();
    let legacy_path = app.legacy_account_projection_path("legacy-racing");
    let legacy_key = app
        .sqlcipher_key(
            "legacy-racing",
            &keys,
            &legacy_path,
            SqlcipherDatabaseKind::AccountProjection,
        )
        .unwrap();
    drop(LegacyAccountProjectionDb::open(legacy_path, &legacy_key).unwrap());

    let entered = std::sync::Arc::new(std::sync::Barrier::new(2));
    let release = std::sync::Arc::new(std::sync::Barrier::new(2));
    let hook_entered = std::sync::Arc::clone(&entered);
    let hook_release = std::sync::Arc::clone(&release);
    app.set_legacy_projection_open_hook_for_test(std::sync::Arc::new(move || {
        hook_entered.wait();
        hook_release.wait();
    }));

    let migrating_app = app.clone();
    let migration = std::thread::spawn(move || migrating_app.ensure_account_state("legacy-racing"));
    entered.wait();

    let closing_app = app.clone();
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (closed_tx, closed_rx) = std::sync::mpsc::channel();
    let closer = std::thread::spawn(move || {
        // Signal from inside the thread, immediately before the call. Without
        // this the timeout assertion below would also pass if the thread had
        // simply not been scheduled yet, which proves nothing about the import
        // window holding the close off.
        started_tx.send(()).unwrap();
        let result = closing_app.close_storage();
        closed_tx.send(()).unwrap();
        result
    });
    started_rx
        .recv()
        .expect("the closing thread should reach close_storage");
    assert!(
        closed_rx
            .recv_timeout(std::time::Duration::from_millis(250))
            .is_err(),
        "terminal close must wait for the legacy database import window",
    );
    assert!(matches!(
        MarmotRootRuntimeLease::try_acquire(root),
        Err(AppError::RuntimeBusy)
    ));

    release.wait();
    migration.join().unwrap().unwrap();
    closer.join().unwrap().unwrap();
    drop(MarmotRootRuntimeLease::try_acquire(root).expect("root lease must be released"));
}

/// Concurrent `close_storage` callers must serialize: no caller may return
/// while another is still closing connections, or the host gets a lock-free
/// answer that is not yet true.
#[test]
fn concurrent_close_storage_callers_serialize() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let account = AccountHome::open(root).create_account("closing").unwrap();
    let app = MarmotApp::try_with_relays_and_account_home_and_config(
        root,
        Vec::new(),
        AccountHome::open(root),
        MarmotAppConfig::default(),
    )
    .unwrap();
    let session_storage = app.account_storage(&account.label).unwrap();
    app.shared_storage().unwrap();
    app.directory_cache_for_account(&account).unwrap();

    let closers = (0..4)
        .map(|_| {
            let app = app.clone();
            std::thread::spawn(move || app.close_storage())
        })
        .collect::<Vec<_>>();
    for closer in closers {
        // Every caller returns only after the teardown is complete, so every
        // caller's return is a truthful "nothing is locked any more".
        closer
            .join()
            .unwrap()
            .expect("close_storage should succeed");
        assert!(session_storage.is_closed());
        drop(MarmotRootRuntimeLease::try_acquire(root).expect("root lease must be released"));
    }
}

#[test]
fn close_storage_is_idempotent() {
    let directory = tempfile::tempdir().unwrap();
    let account = AccountHome::open(directory.path())
        .create_account("closing-twice")
        .unwrap();
    let app = MarmotApp::with_relays_and_account_home(
        directory.path(),
        Vec::new(),
        AccountHome::open(directory.path()),
    );
    app.account_storage(&account.label).unwrap();

    app.close_storage().expect("first close should succeed");
    app.close_storage().expect("second close should be a no-op");
    // Closing a never-opened app is fine too.
    let untouched = MarmotApp::with_relays_and_account_home(
        directory.path(),
        Vec::new(),
        AccountHome::open(directory.path()),
    );
    untouched
        .close_storage()
        .expect("closing an app that opened nothing should succeed");
}

/// `shutdown_and_close` must work as the host's single call, with or without a
/// preceding `shutdown`, and must stay safe when repeated.
#[tokio::test]
async fn runtime_shutdown_and_close_is_idempotent_with_or_without_prior_shutdown() {
    let directory = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relays_and_account_home(
        directory.path(),
        Vec::new(),
        AccountHome::open(directory.path()),
    );
    let runtime = app.runtime();
    assert!(!runtime.storage_is_closed());

    // No preceding `shutdown`: the method performs its own.
    runtime.shutdown_and_close().await.unwrap();
    assert!(runtime.storage_is_closed());

    // Repeat, and repeat after an explicit `shutdown`, without panicking.
    runtime.shutdown_and_close().await.unwrap();
    runtime.shutdown().await;
    runtime.shutdown_and_close().await.unwrap();
}

fn open_suspension_shutdown_fixture(
    root: &std::path::Path,
) -> (
    MarmotApp,
    MarmotAppRuntime,
    SqliteAccountStorage,
    SqliteSharedStorage,
    DirectoryCache,
    PathBuf,
    PathBuf,
) {
    let home = AccountHome::open(root);
    let account = home.create_account("suspension-close").unwrap();
    let app = MarmotApp::try_with_relays_and_account_home_and_config(
        root,
        Vec::new(),
        AccountHome::open(root),
        MarmotAppConfig::default(),
    )
    .unwrap();
    let session = app.account_storage(&account.label).unwrap();
    session.app_message_count().unwrap();
    let shared = app.shared_storage().unwrap();
    shared
        .set_relay_telemetry_settings(&StoredRelayTelemetrySettings {
            export_enabled: true,
            export_interval_seconds: 30,
        })
        .unwrap();
    let directory = app.directory_cache_for_account(&account).unwrap();
    directory.entries().unwrap();
    let session_path = app.account_storage_path(&account.label);
    let shared_path = app.shared_storage_path();
    let runtime = app.runtime();
    (
        app,
        runtime,
        session,
        shared,
        directory,
        session_path,
        shared_path,
    )
}

fn assert_suspension_storage_closed(
    root: &std::path::Path,
    app: &MarmotApp,
    session: &SqliteAccountStorage,
    shared: &SqliteSharedStorage,
    directory: &DirectoryCache,
    session_path: &std::path::Path,
    shared_path: &std::path::Path,
) {
    assert!(app.storage_is_closed());
    assert!(session.is_closed());
    assert!(shared.is_closed());
    assert!(matches!(
        directory.entries(),
        Err(AppError::Storage(error)) if error.is_closed()
    ));
    for database in [session_path, shared_path] {
        for suffix in ["-wal", "-shm"] {
            let sidecar = PathBuf::from(format!("{}{suffix}", database.display()));
            assert!(
                !sidecar.exists(),
                "{} must be released by terminal shutdown",
                sidecar.display()
            );
        }
    }
    drop(MarmotRootRuntimeLease::try_acquire(root).expect("root lease must be released"));
    assert!(matches!(
        app.shared_storage(),
        Err(AppError::Storage(error)) if error.is_closed()
    ));
}

/// Every graceful subsystem can stop making progress. Terminal suspension
/// close must already have released SQLite and the root lease, and the outer
/// graceful budget must still bound the call.
#[tokio::test]
async fn runtime_shutdown_and_close_bounds_every_graceful_shutdown_phase() {
    use crate::runtime::ShutdownTestPhase;

    for phase in [
        ShutdownTestPhase::DirectorySync,
        ShutdownTestPhase::InitialDirectorySync,
        ShutdownTestPhase::AccountWorkers,
        ShutdownTestPhase::RelayPlane,
        ShutdownTestPhase::AuditTracker,
        ShutdownTestPhase::AccountOpens,
    ] {
        let temp = tempfile::tempdir().unwrap();
        let (app, runtime, session, shared, directory, session_path, shared_path) =
            open_suspension_shutdown_fixture(temp.path());
        runtime.set_shutdown_grace_wait_for_test(Duration::from_millis(50));
        let stall = runtime.stall_shutdown_for_test(phase);

        let started = Instant::now();
        runtime.shutdown_and_close().await.unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{phase:?} stall exceeded the terminal shutdown bound"
        );
        assert!(stall.was_entered(), "{phase:?} stall was not exercised");
        assert_suspension_storage_closed(
            temp.path(),
            &app,
            &session,
            &shared,
            &directory,
            &session_path,
            &shared_path,
        );

        // A fresh runtime can acquire and use the same root immediately. The
        // spent runtime remains alive, proving release is explicit rather than
        // an incidental last-Arc drop.
        let reopened = MarmotApp::try_with_relays_and_account_home_and_config(
            temp.path(),
            Vec::new(),
            AccountHome::open(temp.path()),
            MarmotAppConfig::default(),
        )
        .expect("fresh runtime should acquire the closed root");
        reopened.shared_storage().unwrap();
        reopened.close_storage().unwrap();
    }
}

/// Dropping the awaiting future models a host/UniFFI owner being cancelled.
/// The runtime-owned terminal task must continue and close storage anyway.
#[tokio::test]
async fn cancelling_shutdown_and_close_cannot_strand_storage_open() {
    use crate::runtime::ShutdownTestPhase;

    let temp = tempfile::tempdir().unwrap();
    let (app, runtime, session, shared, directory, session_path, shared_path) =
        open_suspension_shutdown_fixture(temp.path());
    let stall = runtime.stall_shutdown_for_test(ShutdownTestPhase::StorageClose);
    let closing_runtime = runtime.clone();
    let host_future = tokio::spawn(async move { closing_runtime.shutdown_and_close().await });
    stall.wait_until_entered().await;

    host_future.abort();
    assert!(host_future.await.unwrap_err().is_cancelled());
    assert!(!runtime.storage_is_closed());
    stall.release();

    tokio::time::timeout(Duration::from_secs(2), async {
        while !runtime.storage_is_closed() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("runtime-owned terminal close must survive caller cancellation");
    assert_suspension_storage_closed(
        temp.path(),
        &app,
        &session,
        &shared,
        &directory,
        &session_path,
        &shared_path,
    );
}

#[tokio::test]
async fn concurrent_runtime_shutdown_and_close_calls_are_safe() {
    let temp = tempfile::tempdir().unwrap();
    let (app, runtime, session, shared, directory, session_path, shared_path) =
        open_suspension_shutdown_fixture(temp.path());
    let callers = (0..4)
        .map(|_| {
            let runtime = runtime.clone();
            tokio::spawn(async move { runtime.shutdown_and_close().await })
        })
        .collect::<Vec<_>>();
    for caller in callers {
        caller.await.unwrap().unwrap();
    }
    assert_suspension_storage_closed(
        temp.path(),
        &app,
        &session,
        &shared,
        &directory,
        &session_path,
        &shared_path,
    );
}

const SUSPENSION_REOPEN_CHILD_ROOT: &str = "MARMOT_SUSPENSION_REOPEN_CHILD_ROOT";

#[test]
fn shutdown_and_close_allows_another_process_to_open_root_child() {
    let Some(root) = std::env::var_os(SUSPENSION_REOPEN_CHILD_ROOT) else {
        return;
    };
    let root = PathBuf::from(root);
    let app = MarmotApp::try_with_relays_and_account_home_and_config(
        &root,
        Vec::new(),
        AccountHome::open(&root),
        MarmotAppConfig::default(),
    )
    .expect("child process must acquire the released root");
    app.shared_storage().unwrap();
    app.close_storage().unwrap();
}

#[tokio::test]
async fn shutdown_and_close_allows_another_process_to_open_root() {
    let temp = tempfile::tempdir().unwrap();
    let (app, runtime, ..) = open_suspension_shutdown_fixture(temp.path());
    runtime.shutdown_and_close().await.unwrap();
    assert!(app.storage_is_closed());

    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "tests::shutdown_and_close_allows_another_process_to_open_root_child",
            "--nocapture",
        ])
        .env(SUSPENSION_REOPEN_CHILD_ROOT, temp.path())
        .status()
        .expect("run fresh-runtime child process");
    assert!(status.success(), "fresh-runtime child process failed");
}

/// #1177: an accepted send whose intent the engine retained in the group's
/// durable queue must say so. Reporting `published: 0` with no message ids
/// forces the host to infer acceptance from an empty list, which is exactly
/// the inference the criterion forbids.
#[test]
fn a_retained_send_reports_accepted_pending_rather_than_an_empty_publish() {
    let mut effects = marmot_account::AccountDeviceEffects::default();
    effects.queued.push(cgka_session::QueuedIntentRef {
        group_id: cgka_traits::GroupId::new(vec![0x11; 16]),
        intent_id: cgka_traits::MessageId::new(vec![0x22; 32]),
    });

    let summary = crate::groups::send_summary_from_effects(&effects);

    assert_eq!(
        summary.accept_disposition,
        cgka_traits::SendAcceptDisposition::AcceptedPending,
        "a retained intent is accepted work, not a silent no-op"
    );
}

/// The published half of #1177's criterion, end to end: a send that reaches the
/// transport must report `Published`, so `AcceptedPending` stays a signal a host
/// can act on rather than the value every send happens to carry.
#[tokio::test]
async fn a_send_that_reaches_the_transport_reports_published() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://accept-disposition.example")
        .with_test_relay_client(relay.clone());
    let mut setup_client = app.client("alice").await.unwrap();
    let group_id = setup_client
        .create_group("accept disposition", &[])
        .await
        .unwrap();
    drop(setup_client);

    let runtime = MarmotAppRuntime::new(app.clone());
    runtime.reconcile_accounts().await.unwrap();
    let summary = runtime
        .send_message("alice", &group_id, b"published now".to_vec())
        .await
        .expect("a send with a healthy transport must publish");

    assert_eq!(
        summary.accept_disposition,
        cgka_traits::SendAcceptDisposition::Published,
        "the message reached the transport, so nothing is being held"
    );

    runtime.shutdown().await;
}

#[tokio::test]
async fn unavailable_send_retries_the_exact_event_after_transport_recovers() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("sender")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://send-recovery.example")
        .with_test_relay_client(relay.clone());
    let mut setup_client = app.client("sender").await.unwrap();
    let group_id = setup_client
        .create_group("send recovery", &[])
        .await
        .unwrap();
    drop(setup_client);

    let runtime = MarmotAppRuntime::new(app.clone());
    runtime.reconcile_accounts().await.unwrap();
    let attempts_before = relay.attempted_event_ids().len();
    relay.fail_publishes_as_unavailable();

    let summary = runtime
        .send_message("sender", &group_id, b"recover exact event".to_vec())
        .await
        .expect("a temporary transport failure must retain the send");
    assert_eq!(
        summary.accept_disposition,
        cgka_traits::SendAcceptDisposition::CompletionUnknown
    );
    let failed_event_id = relay
        .attempted_event_ids()
        .get(attempts_before)
        .cloned()
        .expect("the initial transport attempt must expose its signed event id");

    let group_id_hex = hex::encode(group_id.as_slice());
    let pending = app
        .timeline_messages_with_query(
            "sender",
            TimelineMessageQuery {
                group_id_hex: Some(group_id_hex.clone()),
                ..TimelineMessageQuery::default()
            },
        )
        .unwrap();
    assert_eq!(pending.messages.len(), 1);
    assert!(pending.messages[0].source_message_id_hex.is_none());
    assert!(pending.messages[0].invalidation_status.is_none());

    relay.allow_publishes();
    let recovery = tokio::time::timeout(std::time::Duration::from_secs(12), async {
        loop {
            let timeline = app
                .timeline_messages_with_query(
                    "sender",
                    TimelineMessageQuery {
                        group_id_hex: Some(group_id_hex.clone()),
                        ..TimelineMessageQuery::default()
                    },
                )
                .unwrap();
            if timeline.messages[0].source_message_id_hex.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        recovery.is_ok(),
        "the retained send must publish promptly after connectivity returns; attempts={:?}; published={:?}",
        relay.attempted_event_ids(),
        relay.published_event_ids()
    );

    let recovered = app
        .timeline_messages_with_query(
            "sender",
            TimelineMessageQuery {
                group_id_hex: Some(group_id_hex),
                ..TimelineMessageQuery::default()
            },
        )
        .unwrap();
    assert_eq!(
        recovered.messages[0].source_message_id_hex.as_deref(),
        Some(failed_event_id.as_str()),
        "recovery must reuse the exact signed transport event"
    );
    assert_eq!(
        relay
            .published_event_ids()
            .iter()
            .filter(|event_id| *event_id == &failed_event_id)
            .count(),
        1,
        "the retained event must be accepted exactly once"
    );

    runtime.shutdown().await;
}

#[tokio::test]
async fn connectivity_restored_wakes_a_retained_send_before_the_retry_timer() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("sender")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://send-recovery-wake.example")
        .with_test_relay_client(relay.clone());
    let mut setup_client = app.client("sender").await.unwrap();
    let group_id = setup_client
        .create_group("send recovery wake", &[])
        .await
        .unwrap();
    drop(setup_client);

    let runtime = MarmotAppRuntime::new(app.clone());
    runtime.reconcile_accounts().await.unwrap();
    let attempts_before = relay.attempted_event_ids().len();
    relay.fail_publishes_as_unavailable();

    for plaintext in ["first wake retained send", "second wake retained send"] {
        let summary = runtime
            .send_message("sender", &group_id, plaintext.as_bytes().to_vec())
            .await
            .expect("a temporary transport failure must retain the send");
        assert_eq!(
            summary.accept_disposition,
            cgka_traits::SendAcceptDisposition::CompletionUnknown
        );
    }
    let failed_ids = relay.attempted_event_ids()[attempts_before..].to_vec();
    assert_eq!(failed_ids.len(), 2);

    relay.allow_publishes();
    runtime
        .notify_connectivity_restored()
        .await
        .expect("the host connectivity signal must reach every account worker");

    let group_id_hex = hex::encode(group_id.as_slice());
    tokio::time::timeout(std::time::Duration::from_millis(750), async {
        loop {
            let timeline = app
                .timeline_messages_with_query(
                    "sender",
                    TimelineMessageQuery {
                        group_id_hex: Some(group_id_hex.clone()),
                        ..TimelineMessageQuery::default()
                    },
                )
                .unwrap();
            if timeline.messages.len() == 2
                && timeline
                    .messages
                    .iter()
                    .all(|message| message.source_message_id_hex.is_some())
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("connectivity recovery must not wait for the normal 1.1 second convergence timer");

    let published_in_order = relay
        .published_event_ids()
        .into_iter()
        .filter(|event_id| failed_ids.contains(event_id))
        .collect::<Vec<_>>();
    assert_eq!(
        published_in_order, failed_ids,
        "one recovery wake must finalize retained sends once and in order"
    );

    runtime.shutdown().await;
}

#[tokio::test]
async fn connectivity_restored_during_reconnect_wakes_the_retained_send() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("sender")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://reconnect-send-recovery.example")
        .with_test_relay_client(relay.clone());
    let mut setup_client = app.client("sender").await.unwrap();
    let group_id = setup_client
        .create_group("reconnect send recovery", &[])
        .await
        .unwrap();
    drop(setup_client);

    let runtime = MarmotAppRuntime::new(app.clone());
    runtime.reconcile_accounts().await.unwrap();
    let attempts_before = relay.attempted_event_ids().len();
    relay.fail_publishes_as_unavailable();
    let summary = runtime
        .send_message("sender", &group_id, b"retained across reconnect".to_vec())
        .await
        .expect("a temporary transport failure must retain the send");
    assert_eq!(
        summary.accept_disposition,
        cgka_traits::SendAcceptDisposition::CompletionUnknown
    );
    let failed_event_id = relay.attempted_event_ids()[attempts_before].clone();

    relay.allow_publishes();
    runtime
        .shared_services()
        .relay_plane()
        .simulate_notification_recovery_for_test(1);
    let backoff_deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        match runtime.unhydrated_group_count_for_test("sender").await {
            Err(AppError::TransportClosed) => break,
            Ok(_) => tokio::task::yield_now().await,
            Err(error) => panic!("unexpected reconnect probe error: {error:?}"),
        }
        assert!(
            std::time::Instant::now() < backoff_deadline,
            "account worker did not enter reconnect backoff"
        );
    }

    runtime
        .notify_connectivity_restored()
        .await
        .expect("the reconnecting worker must retain the connectivity wake");

    let group_id_hex = hex::encode(group_id.as_slice());
    tokio::time::timeout(Duration::from_millis(750), async {
        loop {
            let timeline = app
                .timeline_messages_with_query(
                    "sender",
                    TimelineMessageQuery {
                        group_id_hex: Some(group_id_hex.clone()),
                        ..TimelineMessageQuery::default()
                    },
                )
                .unwrap();
            if timeline.messages.len() == 1 && timeline.messages[0].source_message_id_hex.is_some()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the retained connectivity wake must retry before the normal timer");

    assert_eq!(
        relay
            .published_event_ids()
            .iter()
            .filter(|event_id| *event_id == &failed_event_id)
            .count(),
        1,
        "reconnect recovery must accept the exact retained event once"
    );

    runtime.shutdown().await;
}

#[tokio::test]
async fn eventless_drain_projects_every_retained_send_it_publishes() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("sender")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://eventless-drain.example")
        .with_test_relay_client(relay.clone());
    let mut client = app.client("sender").await.unwrap();
    let group_id = client.create_group("eventless drain", &[]).await.unwrap();
    relay.fail_publishes_as_unavailable();

    for plaintext in ["first eventless retained", "second eventless retained"] {
        let summary = client
            .send_with_local_projection(&group_id, plaintext.as_bytes(), |_| {})
            .await
            .expect("a temporary transport failure must retain the send");
        assert_eq!(
            summary.accept_disposition,
            cgka_traits::SendAcceptDisposition::CompletionUnknown
        );
    }

    let group_id_hex = hex::encode(group_id.as_slice());
    let pending = app
        .timeline_messages_with_query(
            "sender",
            TimelineMessageQuery {
                group_id_hex: Some(group_id_hex.clone()),
                ..TimelineMessageQuery::default()
            },
        )
        .unwrap();
    assert_eq!(pending.messages.len(), 2);
    assert!(
        pending
            .messages
            .iter()
            .all(|message| message.source_message_id_hex.is_none())
    );

    relay.allow_publishes();
    assert_eq!(
        client
            .note_connectivity_restored()
            .expect("the connectivity edge must wake exact unavailable fanouts"),
        2
    );
    let summary = client
        .drain_pending_session_events()
        .await
        .expect("the eventless drain must resume the durable fanouts");
    assert_eq!(
        summary.projection_updates.len(),
        2,
        "both pending-to-sent transitions must reach runtime subscribers"
    );
    assert!(
        client
            .runtime
            .session()
            .outbound_fanouts()
            .unwrap()
            .is_empty(),
        "durably projected publications must acknowledge and retire their recovery fanouts"
    );

    let recovered = app
        .timeline_messages_with_query(
            "sender",
            TimelineMessageQuery {
                group_id_hex: Some(group_id_hex),
                ..TimelineMessageQuery::default()
            },
        )
        .unwrap();
    assert_eq!(recovered.messages.len(), 2);
    assert!(
        recovered
            .messages
            .iter()
            .all(|message| message.source_message_id_hex.is_some()),
        "eventless drain publication must persist every pending-to-sent transition"
    );
}

#[tokio::test]
async fn two_unavailable_sends_retry_once_in_order_after_transport_recovers() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("sender")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://ordered-recovery.example")
        .with_test_relay_client(relay.clone());
    let mut setup_client = app.client("sender").await.unwrap();
    let group_id = setup_client
        .create_group("ordered recovery", &[])
        .await
        .unwrap();
    drop(setup_client);

    let runtime = MarmotAppRuntime::new(app.clone());
    runtime.reconcile_accounts().await.unwrap();
    let attempts_before = relay.attempted_event_ids().len();
    relay.fail_publishes_as_unavailable();

    for plaintext in ["first retained", "second retained"] {
        let summary = runtime
            .send_message("sender", &group_id, plaintext.as_bytes().to_vec())
            .await
            .expect("each temporary failure must remain accepted");
        assert_eq!(
            summary.accept_disposition,
            cgka_traits::SendAcceptDisposition::CompletionUnknown
        );
    }
    let failed_ids = relay.attempted_event_ids()[attempts_before..].to_vec();
    assert_eq!(failed_ids.len(), 2);

    relay.allow_publishes();
    let group_id_hex = hex::encode(group_id.as_slice());
    tokio::time::timeout(std::time::Duration::from_secs(12), async {
        loop {
            let timeline = app
                .timeline_messages_with_query(
                    "sender",
                    TimelineMessageQuery {
                        group_id_hex: Some(group_id_hex.clone()),
                        ..TimelineMessageQuery::default()
                    },
                )
                .unwrap();
            if timeline.messages.len() == 2
                && timeline
                    .messages
                    .iter()
                    .all(|message| message.source_message_id_hex.is_some())
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("one recovered drain must finalize both retained sends");

    let published_in_order = relay
        .published_event_ids()
        .into_iter()
        .filter(|event_id| failed_ids.contains(event_id))
        .collect::<Vec<_>>();
    assert_eq!(
        published_in_order, failed_ids,
        "recovery must accept each exact event once in original send order"
    );

    runtime.shutdown().await;
}

#[tokio::test]
async fn unavailable_group_invite_retries_the_exact_commit_after_transport_recovers() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("sender").unwrap();
    let invited = home.create_account("invited").unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://invite-recovery.example")
        .with_test_relay_client(relay.clone());
    let runtime = MarmotAppRuntime::new(app);
    runtime.reconcile_accounts().await.unwrap();
    runtime.catch_up_accounts().await.unwrap();
    let group_id = runtime
        .create_group("sender", "invite recovery", &[], None)
        .await
        .unwrap();

    let attempts_before = relay.attempted_event_ids().len();
    relay.fail_publishes_as_unavailable();
    let summary = runtime
        .invite_members("sender", &group_id, &[invited.account_id_hex])
        .await
        .expect("a temporary invite publish failure must retain the exact commit");
    assert_eq!(
        summary.accept_disposition,
        cgka_traits::SendAcceptDisposition::CompletionUnknown
    );
    let failed_commit_id = relay
        .attempted_event_ids()
        .get(attempts_before)
        .cloned()
        .expect("the invite commit must reach the transport boundary");

    relay.allow_publishes();
    runtime
        .notify_connectivity_restored()
        .await
        .expect("the host connectivity signal must wake the retained invite");
    tokio::time::timeout(std::time::Duration::from_millis(750), async {
        loop {
            if relay
                .published_event_ids()
                .iter()
                .any(|event_id| event_id == &failed_commit_id)
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the retained invite commit must finalize without waiting for its retry timer");

    assert_eq!(
        runtime
            .group_members("sender", &group_id)
            .await
            .expect("the confirmed group remains readable")
            .len(),
        2
    );

    assert_eq!(
        relay
            .published_event_ids()
            .iter()
            .filter(|event_id| *event_id == &failed_commit_id)
            .count(),
        1,
        "group recovery must accept the original commit exactly once"
    );

    runtime.shutdown().await;
}

// ---- mdk#1380: steady-state reconciliation passes must not rescan full state ----

#[test]
fn encrypted_media_warm_skips_authoritative_rechecks_at_an_unchanged_epoch() {
    run_composed_app_runtime_test("encrypted-media-warm-epoch-skip", || async {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());

        let mut client = app.client("alice").await.unwrap();
        let group_id = client.create_group("warm pass", &[]).await.unwrap();
        let group_id_hex = hex::encode(group_id.as_slice());
        assert_eq!(client.state.groups.len(), 1);
        assert!(client.state.groups[0].encrypted_media.required);
        let epoch = client.runtime.group_record(&group_id).unwrap().epoch;

        // A group still marked as requiring encrypted media warms through the
        // per-epoch secret cache without any authoritative component load.
        for _ in 0..2 {
            let stats = client.cache_current_encrypted_media_epoch_secrets();
            assert_eq!(stats.groups_considered, 1);
            assert_eq!(stats.warmed, 1);
            assert_eq!(stats.authoritative_checks, 0);
            assert_eq!(stats.skipped_unchanged_epoch, 0);
            assert_eq!(stats.failures, 0);
        }

        // A projection saying "not required" is only a hint: with no confirmed
        // negative on record the pass re-checks the authoritative component.
        client.state.groups[0].encrypted_media = crate::AppGroupEncryptedMediaComponent::disabled();
        let stats = client.cache_current_encrypted_media_epoch_secrets();
        assert_eq!(stats.authoritative_checks, 1);
        assert_eq!(stats.skipped_unchanged_epoch, 0);
        assert!(
            !client
                .encrypted_media_not_required_epochs
                .contains_key(&group_id_hex),
            "an authoritative REQUIRED answer must not be latched as confirmed-negative"
        );

        // Seed a confirmed-negative at the current epoch (the state left by an
        // authoritative not-required answer): passes skip the expensive
        // recheck while the epoch is unchanged.
        client
            .encrypted_media_not_required_epochs
            .insert(group_id_hex.clone(), epoch.0);
        let stats = client.cache_current_encrypted_media_epoch_secrets();
        assert_eq!(stats.groups_considered, 1);
        assert_eq!(stats.skipped_unchanged_epoch, 1);
        assert_eq!(stats.authoritative_checks, 0);
        assert_eq!(stats.failures, 0);

        // A commit advances the epoch and rebuilds the projection from the
        // signed components: the group is required=true again and the stale
        // seeded negative must be evicted, with the current-epoch secret
        // re-warmed through the live projection path.
        client
            .update_group_profile(&group_id, Some("warm pass renamed"), None)
            .await
            .unwrap();
        let advanced = client.runtime.group_record(&group_id).unwrap().epoch;
        assert!(
            advanced.0 > epoch.0,
            "a profile commit must advance the epoch"
        );
        let stats = client.cache_current_encrypted_media_epoch_secrets();
        assert_eq!(stats.groups_considered, 1);
        assert_eq!(stats.warmed, 1);
        assert_eq!(stats.failures, 0);

        // If the group's projection later says "not required" again (a
        // projection rebuild healed the required flag backwards — the scenario
        // the authoritative re-check exists for), the stale map entry from the
        // OLD epoch must not suppress the re-check.
        client.state.groups[0].encrypted_media = crate::AppGroupEncryptedMediaComponent::disabled();
        let stats = client.cache_current_encrypted_media_epoch_secrets();
        assert_eq!(stats.authoritative_checks, 1);
        assert_eq!(stats.skipped_unchanged_epoch, 0);
        assert!(
            !client
                .encrypted_media_not_required_epochs
                .contains_key(&group_id_hex),
            "an authoritative REQUIRED answer must evict the stale confirmed-negative"
        );
    });
}

#[test]
fn idle_sync_skips_the_checkpoint_route_recomputation() {
    run_composed_app_runtime_test("idle-sync-checkpoint-skip", || async {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());

        let mut client = app.client("alice").await.unwrap();
        client.create_group("idle sync", &[]).await.unwrap();

        // Settle startup/replay traffic, then reset the counter: syncs below
        // drain an empty channel, so nothing can have changed routing.
        client.sync().await.unwrap();
        client.checkpoint_route_refresh_recomputes = 0;

        client.sync().await.unwrap();
        client.sync().await.unwrap();
        assert_eq!(
            client.checkpoint_route_refresh_recomputes, 0,
            "a zero-delivery, clean-routes checkpoint re-scanning every group \
             is pure read amplification (mdk#1380)"
        );
    });
}

#[test]
fn member_ids_page_reads_admins_from_the_durable_group_projection() {
    run_composed_app_runtime_test("member-ids-page-durable-admins", || async {
        let dir = tempfile::tempdir().unwrap();
        let alice = AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());

        let mut client = app.client("alice").await.unwrap();
        let group_id = client.create_group("durable admins", &[]).await.unwrap();
        assert_eq!(
            client.admin_policy_for_group(&group_id).admins,
            vec![alice.account_id_hex.clone()],
            "live MLS still reports the creator as admin"
        );

        let projected_admin = "bb4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4";
        let projected_admin_bytes: [u8; 32] = hex::decode(projected_admin)
            .expect("projected admin hex")
            .try_into()
            .expect("32-byte projected admin");
        client.state.groups[0].admin_policy =
            AppGroupAdminPolicyComponent::new(vec![projected_admin_bytes]);

        let page = client
            .member_ids_page(std::slice::from_ref(&group_id))
            .expect("steady-state page must succeed from the durable row");
        assert_eq!(page.len(), 1);
        assert_eq!(
            page[0].admin_ids_hex,
            vec![projected_admin.to_owned()],
            "admin identifiers must come from the durable projection, not a live MLS reload"
        );
        assert_ne!(
            page[0].admin_ids_hex,
            client.admin_policy_for_group(&group_id).admins,
            "a live admin-policy miss must not replace the durable admin list"
        );

        client.state.groups.clear();
        assert!(
            matches!(
                client.member_ids_page(std::slice::from_ref(&group_id)),
                Err(AppError::UnknownGroup(_))
            ),
            "a missing durable row must fail closed instead of reporting no admins"
        );
    });
}

#[test]
fn pending_group_invites_skips_malformed_rows() {
    // mdk#1380 review: one undecodable row must not disable policy
    // reconciliation for the account's valid invites.
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");

    let pending_group =
        |group_id_hex: &str, welcomer: Option<&str>| storage_sqlite::StoredAccountGroup {
            group_id_hex: group_id_hex.to_owned(),
            endpoint: "wss://relay.example".to_owned(),
            profile_name: "pending".to_owned(),
            profile_description: String::new(),
            image_hash_hex: String::new(),
            image_key_hex: String::new(),
            image_nonce_hex: String::new(),
            image_upload_key_hex: String::new(),
            image_media_type: None,
            admin_keys_hex: String::new(),
            archived: false,
            pending_confirmation: true,
            member_count: None,
            direct_member_ids_hex: None,
            welcomer_account_id_hex: welcomer.map(str::to_owned),
            via_welcome_message_id_hex: None,
            nostr_routing_last_epoch: 0,
            prior_nostr_routes: Vec::new(),
            self_membership: storage_sqlite::SelfMembership::Member,
            components: Vec::new(),
        };
    let state = storage_sqlite::StoredAccountState {
        label: "alice".to_owned(),
        seen_events: Vec::new(),
        last_transport_timestamp: None,
        groups: vec![
            pending_group("zz-not-hex", None),
            pending_group(&"aa".repeat(32), Some("not-hex-either")),
            pending_group(&"bb".repeat(32), Some(&"cc".repeat(32))),
        ],
    };
    app.account_storage("alice")
        .unwrap()
        .save_account_projection_state(&state, 16, 300)
        .unwrap();

    let invites = app.pending_group_invites("alice").unwrap();
    assert_eq!(invites.len(), 1);
    assert_eq!(hex::encode(invites[0].group_id.as_slice()), "bb".repeat(32));
    assert_eq!(
        invites[0]
            .welcomer
            .as_ref()
            .map(|welcomer| hex::encode(welcomer.as_slice())),
        Some("cc".repeat(32))
    );
}

#[test]
fn account_unread_summary_includes_badge_attention_without_session_load() {
    // mdk#1460: one cheap summary must return unread totals plus
    // attention-only rows (pending invites / manual unread) for accounts that
    // have never been started.
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let alice = home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");

    let zero = app
        .account_unread_summary()
        .unwrap()
        .into_iter()
        .find(|summary| summary.account_id_hex == alice.account_id_hex)
        .expect("zero-state account");
    assert_eq!(zero.unread_count, 0);
    assert_eq!(zero.unread_conversations, 0);
    assert_eq!(zero.attention_only_conversations, 0);
    assert!(!zero.has_unread);

    let pending_id = "aa".repeat(16);
    let manual_id = "bb".repeat(16);
    let overlap_id = "cc".repeat(16);
    let archived_id = "dd".repeat(16);
    let seed_group =
        |group_id_hex: &str, pending: bool, archived: bool| storage_sqlite::StoredAccountGroup {
            group_id_hex: group_id_hex.to_owned(),
            endpoint: "wss://relay.example".to_owned(),
            profile_name: "seeded".to_owned(),
            profile_description: String::new(),
            image_hash_hex: String::new(),
            image_key_hex: String::new(),
            image_nonce_hex: String::new(),
            image_upload_key_hex: String::new(),
            image_media_type: None,
            admin_keys_hex: String::new(),
            archived,
            pending_confirmation: pending,
            member_count: None,
            direct_member_ids_hex: None,
            welcomer_account_id_hex: None,
            via_welcome_message_id_hex: None,
            nostr_routing_last_epoch: 0,
            prior_nostr_routes: Vec::new(),
            self_membership: storage_sqlite::SelfMembership::Member,
            components: Vec::new(),
        };
    let storage = app.account_storage("alice").unwrap();
    storage
        .save_account_projection_state(
            &storage_sqlite::StoredAccountState {
                label: "alice".to_owned(),
                groups: vec![
                    seed_group(&pending_id, true, false),
                    seed_group(&manual_id, false, false),
                    seed_group(&overlap_id, false, false),
                    seed_group(&archived_id, true, true),
                ],
                ..storage_sqlite::StoredAccountState::default()
            },
            16,
            300,
        )
        .unwrap();
    storage
        .refresh_chat_list_rows(&alice.account_id_hex, &|_, _| false)
        .unwrap();

    app.set_chat_manually_unread("alice", &manual_id, true)
        .unwrap();
    app.set_chat_manually_unread("alice", &archived_id, true)
        .unwrap();

    let chat = |id: &str, at: u64| storage_sqlite::StoredAppEvent {
        group_id_hex: overlap_id.clone(),
        message_id_hex: id.to_owned(),
        source_message_id_hex: Some(format!("source-{id}")),
        source_epoch: None,
        direction: "received".to_owned(),
        sender: "ee".repeat(32),
        plaintext: "hello".to_owned(),
        kind: MARMOT_APP_EVENT_KIND_CHAT,
        tags: Vec::new(),
        recorded_at: at,
        received_at: at,
        origin_commit_id: None,
        moderation_grant: false,
    };
    storage.record_app_event(&chat("old", 10)).unwrap();
    storage
        .initialize_chat_read_state(&alice.account_id_hex, &overlap_id, &|_, _| false)
        .unwrap();
    storage.record_app_event(&chat("new", 11)).unwrap();
    storage
        .refresh_chat_list_row(&alice.account_id_hex, &overlap_id, &|_, _| false)
        .unwrap();
    app.set_chat_manually_unread("alice", &overlap_id, true)
        .unwrap();

    let summary = app
        .account_unread_summary()
        .unwrap()
        .into_iter()
        .find(|summary| summary.account_id_hex == alice.account_id_hex)
        .expect("seeded account");
    assert_eq!(summary.unread_count, 1);
    assert_eq!(summary.unread_conversations, 3);
    assert_eq!(summary.attention_only_conversations, 2);
    assert!(summary.has_unread);
}

#[test]
fn reconcile_repairs_stale_three_member_count_on_two_member_direct() {
    run_composed_app_runtime_test(
        "reconcile-stale-three-count",
        reconcile_repairs_stale_three_member_count_on_two_member_direct_body,
    );
}

async fn reconcile_repairs_stale_three_member_count_on_two_member_direct_body() {
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    home.create_account("bob").unwrap();
    let bob_id = home.account("bob").unwrap().account_id_hex;
    let app =
        MarmotApp::with_relay(dir.path(), "wss://relay.example").with_test_relay_client(relay);
    let group_id_hex;
    {
        let mut bob = app.client("bob").await.unwrap();
        bob.publish_key_package().await.unwrap();
        let mut alice = app.client("alice").await.unwrap();
        let group_id = alice.create_group("", &[bob_id.as_str()]).await.unwrap();
        group_id_hex = hex::encode(group_id.as_slice());
    }

    let mut state = app.load_state("alice").unwrap();
    let torn = state
        .groups
        .iter_mut()
        .find(|group| group.group_id_hex == group_id_hex)
        .expect("direct group");
    torn.member_count = Some(3);
    torn.direct_member_ids_hex = None;
    app.save_state(&state).unwrap();
    app.reset_direct_conversation_members_backfill_for_test("alice")
        .unwrap();

    {
        let _alice = app.client("alice").await.unwrap();
    }
    assert!(
        app.account_import_marker("alice", crate::DIRECT_CONVERSATION_MEMBERS_BACKFILL_MARKER)
            .unwrap(),
        "3-to-2 tear must let the peer-index backfill complete"
    );

    let runtime = MarmotAppRuntime::new(app.clone());
    runtime.start().await.unwrap();
    let found = runtime
        .existing_direct_conversation("alice", &bob_id)
        .await
        .expect("lookup after 3-to-2 repair")
        .expect("reusable direct must be found");
    assert_eq!(found.group_id_hex, group_id_hex);
    runtime.shutdown().await;
}

#[test]
fn reconcile_repairs_stale_two_member_count_on_three_member_group() {
    run_composed_app_runtime_test(
        "reconcile-stale-two-count",
        reconcile_repairs_stale_two_member_count_on_three_member_group_body,
    );
}

async fn reconcile_repairs_stale_two_member_count_on_three_member_group_body() {
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    home.create_account("bob").unwrap();
    home.create_account("carol").unwrap();
    let alice_id = home.account("alice").unwrap().account_id_hex;
    let bob_id = home.account("bob").unwrap().account_id_hex;
    let carol_id = home.account("carol").unwrap().account_id_hex;
    let app =
        MarmotApp::with_relay(dir.path(), "wss://relay.example").with_test_relay_client(relay);
    let group_id_hex;
    {
        let mut bob = app.client("bob").await.unwrap();
        bob.publish_key_package().await.unwrap();
        let mut carol = app.client("carol").await.unwrap();
        carol.publish_key_package().await.unwrap();
        let mut alice = app.client("alice").await.unwrap();
        let group_id = alice
            .create_group("", &[bob_id.as_str(), carol_id.as_str()])
            .await
            .unwrap();
        group_id_hex = hex::encode(group_id.as_slice());
    }

    let mut state = app.load_state("alice").unwrap();
    let torn = state
        .groups
        .iter_mut()
        .find(|group| group.group_id_hex == group_id_hex)
        .expect("three-member group");
    torn.member_count = Some(2);
    torn.direct_member_ids_hex = Some(vec![alice_id.clone(), bob_id.clone()]);
    app.save_state(&state).unwrap();
    app.reset_direct_conversation_members_backfill_for_test("alice")
        .unwrap();

    {
        let _alice = app.client("alice").await.unwrap();
    }
    assert!(
        app.account_import_marker("alice", crate::DIRECT_CONVERSATION_MEMBERS_BACKFILL_MARKER)
            .unwrap(),
        "2-to-3 tear must not leave the peer-index backfill incomplete"
    );

    let runtime = MarmotAppRuntime::new(app.clone());
    runtime.start().await.unwrap();
    let found = runtime
        .existing_direct_conversation("alice", &bob_id)
        .await
        .expect("lookup after 2-to-3 repair");
    assert!(
        found.is_none(),
        "a three-member conversation must not be reused as a direct"
    );
    runtime.shutdown().await;
}
