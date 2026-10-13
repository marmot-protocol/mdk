//! Retained edit dependency and per-group scheduling regressions in production policy mode.

use super::*;
use crate::tests::ScriptedPushRelayClient;
use marmot_account::AccountHome;

#[tokio::test]
async fn engine_owned_failed_original_defers_retained_edit_without_finishing_it() {
    use cgka_traits::storage::{OutboundIntentStorage, QueuedOutboundIntent};
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let mut client = app.client("alice").await.unwrap();
    let group = client.create_group("retained edit", &[]).await.unwrap();
    let sibling = client.create_group("sibling", &[]).await.unwrap();
    let group_hex = hex::encode(group.as_slice());
    let original = app
        .admit_local_message_at(
            "alice",
            &group,
            "original".into(),
            crate::local_submissions::LocalMessageRequest {
                content: "original text".into(),
                reply_to: None,
                attachments: vec![],
            },
            None,
            42,
        )
        .unwrap()
        .0;
    app.admit_local_message_with_edit_at(
        "alice",
        &group,
        "edit".into(),
        crate::local_submissions::LocalMessageRequest {
            content: "updated text".into(),
            reply_to: None,
            attachments: vec![],
        },
        None,
        Some("original".into()),
        crate::unix_now_seconds(),
    )
    .unwrap();
    let storage = app.account_storage("alice").unwrap();
    let queued = storage
        .local_submission(&group_hex, "original")
        .unwrap()
        .unwrap();
    storage
        .put_queued_outbound_intent(&QueuedOutboundIntent {
            id: cgka_traits::MessageId::new(vec![5; 32]),
            group_id: group.clone(),
            intent: cgka_traits::SendIntent::AppMessage {
                group_id: group.clone(),
                payload: queued.payload.unwrap(),
                expected_epoch: None,
            },
            created_at_ms: 1,
            reissue_attempts: 0,
        })
        .unwrap();
    assert_eq!(
        storage
            .local_submission(&group_hex, "original")
            .unwrap()
            .unwrap()
            .state,
        1
    );
    app.invalidate_timeline_app_event(
        "alice",
        &group_hex,
        &original.message_id_hex,
        crate::LOCAL_PUBLISH_FAILED_REASON,
    )
    .unwrap();
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    let edit = storage
        .local_submission(&group_hex, "edit")
        .unwrap()
        .unwrap();
    assert!(client.retained_edit_waits_for_original(&edit).unwrap());
    let retry = publish_next_local_submission(
        &mut client,
        &app,
        &runtime.shared_services(),
        &runtime.events,
        &account.account_id_hex,
        "alice",
    )
    .await;
    assert_eq!(retry, Some(Duration::from_secs(1)));
    let retained = storage
        .local_submission(&group_hex, "edit")
        .unwrap()
        .unwrap();
    assert_eq!(retained.state, 0);
    assert!(retained.request_json.is_some() && retained.payload.is_some());
    assert!(retained.outcome_json.is_none());
    for (group, token) in [(&group, "later-same-group"), (&sibling, "sibling")] {
        app.admit_local_message(
            "alice",
            group,
            token.into(),
            crate::local_submissions::LocalMessageRequest {
                content: token.into(),
                reply_to: None,
                attachments: vec![],
            },
            None,
        )
        .unwrap();
    }
    publish_next_local_submission(
        &mut client,
        &app,
        &runtime.shared_services(),
        &runtime.events,
        &account.account_id_hex,
        "alice",
    )
    .await;
    assert!(
        storage
            .local_submission(&hex::encode(sibling.as_slice()), "sibling")
            .unwrap()
            .unwrap()
            .outcome_json
            .is_some()
    );
    assert!(
        storage
            .local_submission(&group_hex, "later-same-group")
            .unwrap()
            .unwrap()
            .outcome_json
            .is_none()
    );
    assert!(
        storage
            .local_submission(&group_hex, "edit")
            .unwrap()
            .unwrap()
            .outcome_json
            .is_none()
    );
    app.clear_timeline_local_publish_failure("alice", &group_hex, &original.message_id_hex)
        .unwrap();
    assert!(!client.retained_edit_waits_for_original(&retained).unwrap());
    publish_next_local_submission(
        &mut client,
        &app,
        &runtime.shared_services(),
        &runtime.events,
        &account.account_id_hex,
        "alice",
    )
    .await;
    let resumed = storage
        .local_submission(&group_hex, "edit")
        .unwrap()
        .unwrap();
    assert_eq!(resumed.state, 1);
    assert!(resumed.outcome_json.is_some());
    app.invalidate_timeline_app_event(
        "alice",
        &group_hex,
        &original.message_id_hex,
        "convergence_invalidated",
    )
    .unwrap();
    assert!(!client.retained_edit_waits_for_original(&retained).unwrap());
}

struct RetainedEditFixture {
    _root: tempfile::TempDir,
    app: MarmotApp,
    client: AppClient,
    group: GroupId,
    sibling: GroupId,
    account_id: String,
    queued_id: cgka_traits::MessageId,
}

impl RetainedEditFixture {
    async fn new() -> Self {
        use cgka_traits::storage::{OutboundIntentStorage, QueuedOutboundIntent};
        let root = tempfile::tempdir().unwrap();
        let account = AccountHome::open(root.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(root.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let mut client = app.client("alice").await.unwrap();
        let group = client.create_group("failed dependency", &[]).await.unwrap();
        let sibling = client.create_group("independent", &[]).await.unwrap();
        let group_hex = hex::encode(group.as_slice());
        app.admit_local_message(
            "alice",
            &group,
            "original".into(),
            Self::request("original"),
            None,
        )
        .unwrap();
        app.admit_local_message_with_edit_at(
            "alice",
            &group,
            "edit".into(),
            Self::request("edit"),
            None,
            Some("original".into()),
            crate::unix_now_seconds(),
        )
        .unwrap();
        let storage = app.account_storage("alice").unwrap();
        let original = storage
            .local_submission(&group_hex, "original")
            .unwrap()
            .unwrap();
        let queued_id = cgka_traits::MessageId::new(vec![6; 32]);
        storage
            .put_queued_outbound_intent(&QueuedOutboundIntent {
                id: queued_id.clone(),
                group_id: group.clone(),
                intent: cgka_traits::SendIntent::AppMessage {
                    group_id: group.clone(),
                    payload: original.payload.unwrap(),
                    expected_epoch: None,
                },
                created_at_ms: 1,
                reissue_attempts: 0,
            })
            .unwrap();
        app.invalidate_timeline_app_event(
            "alice",
            &group_hex,
            &original.message_id_hex,
            crate::LOCAL_PUBLISH_FAILED_REASON,
        )
        .unwrap();
        Self {
            _root: root,
            app,
            client,
            group,
            sibling,
            account_id: account.account_id_hex,
            queued_id,
        }
    }

    fn request(content: &str) -> crate::local_submissions::LocalMessageRequest {
        crate::local_submissions::LocalMessageRequest {
            content: content.into(),
            reply_to: None,
            attachments: vec![],
        }
    }

    fn submission(&self, group: &GroupId, token: &str) -> storage_sqlite::LocalSubmission {
        self.app
            .account_storage("alice")
            .unwrap()
            .local_submission(&hex::encode(group.as_slice()), token)
            .unwrap()
            .unwrap()
    }

    async fn drain(&mut self) -> Option<Duration> {
        let runtime = crate::MarmotAppRuntime::new(self.app.clone());
        publish_next_local_submission(
            &mut self.client,
            &self.app,
            &runtime.shared_services(),
            &runtime.events,
            &self.account_id,
            "alice",
        )
        .await
    }
}

#[tokio::test]
async fn missing_group_rejects_retained_edit_and_does_not_stall_another_group() {
    use cgka_traits::storage::GroupStorage;
    let mut fixture = RetainedEditFixture::new().await;
    fixture
        .app
        .admit_local_message(
            "alice",
            &fixture.sibling,
            "sibling".into(),
            RetainedEditFixture::request("sibling"),
            None,
        )
        .unwrap();
    // Leave the app's retained projection intact but remove its authoritative engine row.
    fixture
        .app
        .account_storage("alice")
        .unwrap()
        .delete_group(&fixture.group)
        .unwrap();
    let edit = fixture.submission(&fixture.group, "edit");
    assert!(
        fixture
            .client
            .retained_edit_waits_for_original(&edit)
            .is_ok_and(|waits| !waits)
    );
    assert_eq!(fixture.drain().await, Some(Duration::ZERO));
    let retained = fixture.submission(&fixture.group, "edit");
    assert_eq!(retained.state, 3);
    assert!(retained.request_json.is_none() && retained.payload.is_none());
    assert!(retained.outcome_json.is_none());
    assert_eq!(fixture.drain().await, Some(Duration::ZERO));
    assert!(
        fixture
            .submission(&fixture.sibling, "sibling")
            .outcome_json
            .is_some()
    );
}

#[tokio::test]
async fn abandoned_original_rejects_retained_edit_and_unblocks_later_sends() {
    use cgka_traits::storage::{OutboundIntentStorage, QueuedOutboundIntent};
    let mut fixture = RetainedEditFixture::new().await;
    fixture
        .app
        .admit_local_message(
            "alice",
            &fixture.group,
            "later".into(),
            RetainedEditFixture::request("later"),
            None,
        )
        .unwrap();
    let storage = fixture.app.account_storage("alice").unwrap();
    storage
        .delete_queued_outbound_intent(&fixture.queued_id)
        .unwrap();
    fixture
        .app
        .admit_local_message(
            "alice",
            &fixture.group,
            "unrelated".into(),
            RetainedEditFixture::request("unrelated retained work"),
            None,
        )
        .unwrap();
    let unrelated = fixture.submission(&fixture.group, "unrelated");
    // Some other queued work in this group is insufficient: it must be the exact original.
    storage
        .put_queued_outbound_intent(&QueuedOutboundIntent {
            id: cgka_traits::MessageId::new(vec![7; 32]),
            group_id: fixture.group.clone(),
            intent: cgka_traits::SendIntent::AppMessage {
                group_id: fixture.group.clone(),
                payload: unrelated.payload.unwrap(),
                expected_epoch: None,
            },
            created_at_ms: 2,
            reissue_attempts: 0,
        })
        .unwrap();
    let edit = fixture.submission(&fixture.group, "edit");
    assert!(
        !fixture
            .client
            .retained_edit_waits_for_original(&edit)
            .unwrap()
    );
    assert_eq!(fixture.drain().await, Some(Duration::ZERO));
    let rejected = fixture.submission(&fixture.group, "edit");
    assert_eq!(rejected.state, 3);
    assert!(
        rejected.outcome_json.is_none(),
        "a rejection has no successful send summary"
    );
    assert!(rejected.request_json.is_none() && rejected.payload.is_none());
    assert!(
        fixture
            .submission(&fixture.group, "later")
            .outcome_json
            .is_none()
    );
    assert_eq!(fixture.drain().await, Some(Duration::ZERO));
    assert_eq!(fixture.submission(&fixture.group, "later").state, 1);
    assert!(
        fixture
            .submission(&fixture.group, "later")
            .outcome_json
            .is_some()
    );
}

#[tokio::test]
async fn retained_edit_lookup_backoff_skips_repeated_probes_and_keeps_sibling_progress() {
    use cgka_traits::storage::GroupStorage;
    let mut fixture = RetainedEditFixture::new().await;
    fixture
        .app
        .admit_local_message(
            "alice",
            &fixture.sibling,
            "sibling".into(),
            RetainedEditFixture::request("sibling"),
            None,
        )
        .unwrap();
    fixture
        .app
        .account_storage("alice")
        .unwrap()
        .delete_group(&fixture.group)
        .unwrap();
    let group = hex::encode(fixture.group.as_slice());
    // Model a previous uncertain backend failure without a timing-sensitive sleep.
    fixture.client.local_edit_lookup_retries.insert(
        group.clone(),
        (
            Instant::now() + Duration::from_secs(30),
            Duration::from_secs(30),
        ),
    );
    assert_eq!(fixture.drain().await, Some(Duration::ZERO));
    assert!(
        fixture
            .submission(&fixture.sibling, "sibling")
            .outcome_json
            .is_some()
    );
    assert_eq!(fixture.submission(&fixture.group, "edit").state, 0);
    let delay = fixture.drain().await.unwrap();
    assert!(delay > Duration::ZERO && delay <= Duration::from_secs(30));
    assert_eq!(fixture.submission(&fixture.group, "edit").state, 0);
    // Once eligible, the missing group is classified as permanent and retired.
    fixture
        .client
        .local_edit_lookup_retries
        .get_mut(&group)
        .unwrap()
        .0 = Instant::now();
    assert_eq!(fixture.drain().await, Some(Duration::ZERO));
    assert_eq!(fixture.submission(&fixture.group, "edit").state, 3);
    assert!(
        !fixture
            .client
            .local_edit_lookup_retries
            .contains_key(&group)
    );
}
