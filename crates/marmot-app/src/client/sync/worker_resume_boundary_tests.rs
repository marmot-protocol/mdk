//! The owned comparison result's queue step shares the old per-route deadline
//! and error classification. These exercise the real grant executor with a
//! scripted network result and a task-local queue fault at that exact seam.

use super::*;
use crate::tests::{
    ScriptedEosePump, ScriptedPushRelayClient, client_on_app_relay_plane, every_subscription,
    scripted_eose_pump,
};
use nostr_sdk::prelude::{EventBuilder, FinalizeEvent, Keys, Kind, Tag};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::sync::Arc;
use transport_nostr_adapter::{NostrReconciliationSummary, NostrRelayEvent};

struct Fixture {
    _dir: tempfile::TempDir,
    _pump: ScriptedEosePump,
    client: AppClient,
    storage: storage_sqlite::SqliteAccountStorage,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    crate::AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = crate::MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let pump = scripted_eose_pump(app.relay_plane.clone(), relay, every_subscription);
    let mut client = client_on_app_relay_plane(&app, "alice").await;
    client
        .create_group("comparison queue boundary", &[])
        .await
        .unwrap();
    client.request_bounded_comparison().unwrap();
    let storage = app.account_storage("alice").unwrap();
    Fixture {
        _dir: dir,
        _pump: pump,
        client,
        storage,
    }
}

fn candidate() -> NostrRelayEvent {
    let signed = EventBuilder::new(Kind::MlsGroupMessage, "queue boundary")
        .tags([Tag::custom("h", [hex::encode([7; 32])])])
        .finalize(&Keys::generate())
        .unwrap();
    NostrRelayEvent {
        endpoint: cgka_traits::TransportEndpoint("wss://relay.example".into()),
        subscription_id: None,
        event: transport_nostr_peeler::NostrTransportEvent::from_nostr_event(&signed).unwrap(),
    }
}

fn scripted_results() -> VecDeque<TestComparisonResult> {
    [
        Ok(Some((
            NostrReconciliationSummary {
                relays_succeeded: 1,
                received_items: 1,
                ..Default::default()
            },
            vec![candidate()],
        ))),
        Ok(Some((
            NostrReconciliationSummary {
                relays_succeeded: 1,
                ..Default::default()
            },
            Vec::new(),
        ))),
    ]
    .into()
}

#[tokio::test]
async fn failed_worker_submission_marks_only_that_route_transient_and_attempts_next() {
    let mut fixture = fixture().await;
    let grant = fixture
        .client
        .authorize_account_recovery(None, EpochBackfillExecutionSeam::Startup)
        .unwrap()
        .unwrap();
    assert_eq!(grant.inventory.len(), 2);
    let failed_route = grant.inventory[0].route.clone();
    fixture.client.test_comparison_results = Some(scripted_results());
    TEST_COMPARISON_QUEUE_ACTIONS
        .scope(
            RefCell::new([TestComparisonQueueAction::Fail].into()),
            async {
                fixture
                    .client
                    .execute_recovery_grant(grant, None, None)
                    .await
            },
        )
        .await
        .expect("a queue error is a route result, not a whole-grant error");
    assert!(
        fixture
            .client
            .test_comparison_results
            .as_ref()
            .unwrap()
            .is_empty()
    );
    let slot = fixture.storage.recovery_comparison().unwrap();
    assert!(slot.pending());
    let plan = slot.plan.unwrap();
    assert_eq!(plan.retry_routes.len(), 1);
    let retry = plan
        .routes
        .iter()
        .find(|route| route.scope_id == plan.retry_routes[0])
        .unwrap();
    assert!(match failed_route {
        storage_sqlite::TransportReconciliationRoute::Inbox => retry.route_kind == 0,
        storage_sqlite::TransportReconciliationRoute::Group(id) => {
            retry.transport_group_id == Some(id)
        }
    });
}

#[tokio::test]
async fn blocked_worker_submission_ends_at_route_quantum_before_later_route() {
    let mut fixture = fixture().await;
    let grant = fixture
        .client
        .authorize_account_recovery(None, EpochBackfillExecutionSeam::Startup)
        .unwrap()
        .unwrap();
    assert_eq!(grant.inventory.len(), 2);
    fixture.client.test_comparison_results = Some(scripted_results());
    let result = tokio::time::timeout(
        Duration::from_secs(15),
        TEST_COMPARISON_QUEUE_ACTIONS.scope(
            RefCell::new([TestComparisonQueueAction::Block].into()),
            async {
                fixture
                    .client
                    .execute_recovery_grant(grant, None, None)
                    .await
            },
        ),
    )
    .await
    .expect("the original comparison quantum bounds queue submission");
    result.expect("route timeout leaves the owner grant checkpointable");
    assert_eq!(
        fixture
            .client
            .test_comparison_results
            .as_ref()
            .unwrap()
            .len(),
        1,
        "a later route is not started after the shared comparison deadline"
    );
    let slot = fixture.storage.recovery_comparison().unwrap();
    assert!(slot.pending());
    assert_eq!(slot.plan.unwrap().retry_routes.len(), 1);
}
