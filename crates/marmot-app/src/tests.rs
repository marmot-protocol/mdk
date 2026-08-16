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

#[derive(Default)]
pub(crate) struct ScriptedPushRelayClient {
    publish_results: std::sync::Mutex<std::collections::VecDeque<bool>>,
    published_events: std::sync::Mutex<Vec<NostrTransportEvent>>,
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
    batch_calls: std::sync::atomic::AtomicUsize,
    publish_started: tokio::sync::Notify,
    publish_release: tokio::sync::Notify,
    subscribe_started: tokio::sync::Notify,
    subscribe_release: tokio::sync::Notify,
    unsubscribe_started: tokio::sync::Notify,
    unsubscribe_release: tokio::sync::Notify,
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
        let mut app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        app.set_audit_log_settings(crate::AuditLogSettings {
            enabled: true,
            ..Default::default()
        })
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
        let mut app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        app.set_audit_log_settings(crate::AuditLogSettings {
            enabled: true,
            ..Default::default()
        })
        .unwrap();
        app.relay_plane = MarmotRelayPlane::new_with_loopback(
            Some(Duration::from_secs(120)),
            relay.clone(),
            true,
        );

        let mut client = app.client("alice").await.unwrap();
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

#[test]
fn in_flight_epoch_backfill_arm_preserves_both_operation_intents_on_failure() {
    run_composed_app_runtime_test("in-flight-backfill-arm", || async {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        app.set_audit_log_settings(crate::AuditLogSettings {
            enabled: true,
            ..Default::default()
        })
        .unwrap();

        let mut client = app.client("alice").await.unwrap();
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
        let operation_a_retry = client
            .run_pending_epoch_backfill(marmot_forensics::EpochBackfillExecutionSeam::Maintenance)
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
        app.set_audit_log_settings(crate::AuditLogSettings {
            enabled: true,
            ..Default::default()
        })
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
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        app.set_audit_log_settings(crate::AuditLogSettings {
            enabled: true,
            ..Default::default()
        })
        .unwrap();

        let mut client = app.client("alice").await.unwrap();
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

    let status = app
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
    // Batch order is NIP-65, inbox, contacts, profile: fail the inbox record.
    relay.script([true, false, true, true]);
    let app = MarmotApp::with_relay(directory.path(), "wss://relay.example")
        .with_test_relay_client(relay);
    let runtime = MarmotAppRuntime::new(app.clone());
    let request = || AccountSetupRequest {
        default_relays: vec![TransportEndpoint("wss://relay.example".into())],
        bootstrap_relays: vec![TransportEndpoint("wss://relay.example".into())],
        ..AccountSetupRequest::default()
    };

    runtime
        .create_identity(request())
        .await
        .expect_err("one failed member of the bootstrap batch must fail setup");
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

    let retried = runtime
        .create_identity(request())
        .await
        .expect("replaceable bootstrap records must be retryable");
    assert_eq!(retried.account.account_id_hex, account.account_id_hex);
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
async fn confirmed_generated_bootstrap_republishes_when_projection_is_missing() {
    let directory = tempfile::tempdir().unwrap();
    let home = AccountHome::open(directory.path());
    let account = home.create_nostr_account_for_setup().unwrap();
    home.set_account_setup_phase(
        &account.label,
        marmot_account::AccountSetupPhase::BootstrapPublicationConfirmed,
    )
    .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(directory.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    app.mark_key_package_cutover_scan_complete(&account.label)
        .unwrap();
    let runtime = MarmotAppRuntime::new(app);

    let retried = runtime
        .create_identity(AccountSetupRequest {
            default_relays: vec![TransportEndpoint("wss://relay.example".into())],
            bootstrap_relays: vec![TransportEndpoint("wss://relay.example".into())],
            ..AccountSetupRequest::default()
        })
        .await
        .expect("a confirmed setup with a lost projection must republish safely");

    assert_eq!(retried.account.account_id_hex, account.account_id_hex);
    assert!(retried.relay_lists.complete);
    assert_eq!(
        relay.batch_calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
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
/// previews", `CHAT_LIST_PREVIEW_ORDER_DESC` in `storage-sqlite/src/chat_list.rs`),
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
    app.set_audit_log_settings(AuditLogSettings {
        enabled: true,
        ..Default::default()
    })
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
    app.set_audit_log_settings(AuditLogSettings {
        enabled: true,
        ..Default::default()
    })
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
