use super::*;

fn fixture() -> (
    tempfile::TempDir,
    MarmotApp,
    Arc<ScriptedPushRelayClient>,
    Arc<MemberResolutionDirectoryFetcher>,
    String,
) {
    let dir = tempfile::tempdir().unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let fetcher = Arc::new(MemberResolutionDirectoryFetcher::default());
    let mut app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    app.relay_plane = MarmotRelayPlane::new_with_directory_fetcher_for_test(
        None,
        relay.clone(),
        fetcher.clone(),
        false,
    );
    app.account_home().create_account("alice").unwrap();
    let target = Keys::generate().public_key().to_hex();
    (dir, app, relay, fetcher, target)
}

#[tokio::test]
async fn user_blocks_publication_failure_and_byte_identical_retry() {
    let (_dir, app, relay, fetcher, target) = fixture();
    let runtime = app.runtime();
    *fetcher.incomplete_endpoint.lock().unwrap() = Some("wss://relay.example".into());
    assert!(matches!(
        runtime.block_user("alice", &target).await,
        Err(AppError::BlockListUnavailable)
    ));
    assert!(relay.attempted_events.lock().unwrap().is_empty());
    *fetcher.incomplete_endpoint.lock().unwrap() = None;
    relay
        .fail_publish_unavailable
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(matches!(
        runtime.block_user("alice", &target).await,
        Err(AppError::BlockListUnavailable)
    ));
    assert!(
        app.account_storage("alice")
            .unwrap()
            .pending_block_publication()
            .unwrap()
            .is_none()
    );
    assert!(!runtime.is_user_blocked("alice", &target).unwrap());
    relay
        .fail_publish_unavailable
        .store(false, std::sync::atomic::Ordering::SeqCst);
    relay.script([false, true]);
    assert!(matches!(
        runtime.block_user("alice", &target).await,
        Err(AppError::BlockPublicationUncertain)
    ));
    let intent = app
        .account_storage("alice")
        .unwrap()
        .pending_block_publication()
        .unwrap()
        .unwrap()
        .event_json;
    assert!(!runtime.is_user_blocked("alice", &target).unwrap());
    runtime.block_user("alice", &target).await.unwrap();
    assert_eq!(
        serde_json::to_string(relay.attempted_events.lock().unwrap().last().unwrap()).unwrap(),
        intent
    );
    assert!(runtime.is_user_blocked("alice", &target).unwrap());
    let count = relay.attempted_events.lock().unwrap().len();
    runtime.block_user("alice", &target).await.unwrap();
    assert_eq!(relay.attempted_events.lock().unwrap().len(), count);
    runtime.unblock_user("alice", &target).await.unwrap();
    assert!(runtime.get_blocked_users("alice").unwrap().is_empty());
    let event = relay
        .published_events
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .clone();
    assert!(event.content.is_empty() && event.tags.is_empty());
    event.to_verified_nostr_event().unwrap();
}

#[tokio::test]
async fn user_blocks_remote_adoption_survives_failed_edit_and_supersedes_uncertain_intent() {
    let (_dir, app, relay, fetcher, target) = fixture();
    let runtime = app.runtime();
    relay.script([false]);
    assert!(matches!(
        runtime.block_user("alice", &target).await,
        Err(AppError::BlockPublicationUncertain)
    ));
    let old = relay
        .attempted_events
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .clone();
    let keys = app.account_home().load_signing_keys("alice").unwrap();
    let other = Keys::generate().public_key().to_hex();
    let remote = EventBuilder::new(Kind::MuteList, "")
        .tags([
            Tag::parse(["p", &other]).unwrap(),
            Tag::parse(["word", "preserve"]).unwrap(),
        ])
        .custom_created_at(NostrTimestamp::from_secs(old.created_at + 1))
        .finalize(&keys)
        .unwrap();
    fetcher
        .events
        .lock()
        .unwrap()
        .push(NostrTransportEvent::from_nostr_event(&remote).unwrap());
    relay
        .fail_publish_unavailable
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(matches!(
        runtime.block_user("alice", &target).await,
        Err(AppError::BlockListUnavailable)
    ));
    assert!(runtime.is_user_blocked("alice", &other).unwrap());
    assert!(!runtime.is_user_blocked("alice", &target).unwrap());
    assert!(
        app.account_storage("alice")
            .unwrap()
            .pending_block_publication()
            .unwrap()
            .is_none()
    );
    assert_ne!(
        relay.attempted_events.lock().unwrap().last().unwrap().id,
        old.id
    );
    relay
        .fail_publish_unavailable
        .store(false, std::sync::atomic::Ordering::SeqCst);
    runtime.block_user("alice", &target).await.unwrap();
    let published = relay
        .published_events
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .clone();
    assert!(
        published
            .tags
            .contains(&vec!["word".into(), "preserve".into()])
    );
    assert!(published.tags.contains(&vec!["p".into(), other]));
    assert!(!published.tags.iter().any(|t| t.get(1) == Some(&target)));
    assert!(!published.content.contains(&target));
}

#[tokio::test]
async fn user_blocks_concurrent_local_edits_are_serialized() {
    let (_dir, app, _relay, _fetcher, first) = fixture();
    let second = Keys::generate().public_key().to_hex();
    let runtime = app.runtime();
    let (a, b) = tokio::join!(
        runtime.block_user("alice", &first),
        runtime.block_user("alice", &second)
    );
    a.unwrap();
    b.unwrap();
    assert_eq!(runtime.get_blocked_users("alice").unwrap().len(), 2);
}

#[tokio::test]
async fn user_blocks_unreadable_live_replacement_fences_later_empty_fetch() {
    let (_dir, app, relay, fetcher, target) = fixture();
    let keys = app.account_home().load_signing_keys("alice").unwrap();
    let at = crate::unix_now_seconds();
    let unreadable = EventBuilder::new(Kind::MuteList, "unreadable")
        .custom_created_at(NostrTimestamp::from_secs(at))
        .finalize(&keys)
        .unwrap();
    assert!(
        app.ingest_block_list_event(NostrTransportEvent::from_nostr_event(&unreadable).unwrap())
            .await
            .is_err()
    );
    let runtime = app.runtime();
    assert!(matches!(
        runtime.block_user("alice", &target).await,
        Err(AppError::BlockListUnavailable)
    ));
    assert!(relay.attempted_events.lock().unwrap().is_empty());
    let repaired = EventBuilder::new(Kind::MuteList, "")
        .custom_created_at(NostrTimestamp::from_secs(at + 1))
        .finalize(&keys)
        .unwrap();
    fetcher
        .events
        .lock()
        .unwrap()
        .push(NostrTransportEvent::from_nostr_event(&repaired).unwrap());
    runtime.block_user("alice", &target).await.unwrap();
    assert!(runtime.is_user_blocked("alice", &target).unwrap());
}

#[tokio::test]
async fn user_blocks_restart_reconciles_each_publication_cut() {
    for phase in 0..3 {
        let (dir, app, relay, fetcher, target) = fixture();
        let runtime = app.runtime();
        relay.script([false]);
        assert!(matches!(
            runtime.block_user("alice", &target).await,
            Err(AppError::BlockPublicationUncertain)
        ));
        let pending = app
            .account_storage("alice")
            .unwrap()
            .pending_block_publication()
            .unwrap()
            .unwrap();
        let event: NostrTransportEvent = serde_json::from_str(&pending.event_json).unwrap();
        if phase >= 1 {
            // Relay accepted the signed event, but the caller did not observe its ACK.
            fetcher.events.lock().unwrap().push(event.clone());
        }
        if phase == 2 {
            // Local state committed; cleanup of the signed intent had not completed.
            app.ingest_block_list_event(event.clone()).await.unwrap();
            app.account_storage("alice")
                .unwrap()
                .stage_block_publication(&pending)
                .unwrap();
        }
        let attempts = relay.attempted_events.lock().unwrap().len();
        drop(runtime);
        drop(app);
        let mut reopened = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        reopened.relay_plane = MarmotRelayPlane::new_with_directory_fetcher_for_test(
            None,
            relay.clone(),
            fetcher,
            false,
        );
        let runtime = reopened.runtime();
        runtime.block_user("alice", &target).await.unwrap();
        assert!(runtime.is_user_blocked("alice", &target).unwrap());
        assert!(
            reopened
                .account_storage("alice")
                .unwrap()
                .pending_block_publication()
                .unwrap()
                .is_none()
        );
        let published = relay.attempted_events.lock().unwrap();
        assert_eq!(published.len(), attempts + usize::from(phase == 0));
        assert_eq!(
            published.last().unwrap().id,
            event.id,
            "retry must retain exact signed bytes"
        );
    }
}
