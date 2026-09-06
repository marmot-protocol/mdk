use super::*;
use crate::relay_plane::{DirectoryFetchRequest, DirectoryRelayFetcher};
use async_trait::async_trait;
use cgka_traits::{MemberId, TransportAdapterError};
use nostr::prelude::ToBech32;
use std::sync::atomic::{AtomicBool, Ordering};
use transport_nostr_adapter::{NostrPublishOutcome, NostrRelayClient, NostrSubscription};

#[derive(Default)]
struct Network {
    events: StdMutex<Vec<NostrTransportEvent>>,
    attempts: StdMutex<Vec<NostrTransportEvent>>,
    fail_reads: AtomicBool,
    zero_acks: AtomicBool,
    block_publish: AtomicBool,
    publishing: Notify,
}
#[async_trait]
impl DirectoryRelayFetcher for Network {
    async fn fetch_directory_events(
        &self,
        request: DirectoryFetchRequest,
    ) -> Result<Vec<DirectoryRelayEventRecord>, String> {
        if self.fail_reads.load(Ordering::SeqCst) {
            return Err("timeout".into());
        }
        Ok(self
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| {
                request
                    .queries
                    .iter()
                    .any(|q| q.kind == event.kind && q.authors.contains(&event.pubkey))
            })
            .cloned()
            .map(|event| DirectoryRelayEventRecord {
                endpoints: request.endpoints.clone(),
                event,
            })
            .collect())
    }
    async fn inspect_directory_events(
        &self,
        request: DirectoryFetchRequest,
        _signer: Option<Arc<dyn nostr::NostrSigner>>,
    ) -> Result<Vec<DirectoryRelayEventRecord>, String> {
        self.fetch_directory_events(request).await
    }
}
#[async_trait]
impl NostrRelayClient for Network {
    async fn subscribe(&self, _: NostrSubscription) -> Result<(), TransportAdapterError> {
        Ok(())
    }
    async fn unsubscribe(&self, _: NostrSubscription) -> Result<(), TransportAdapterError> {
        Ok(())
    }
    async fn unsubscribe_account(&self, _: &MemberId) -> Result<(), TransportAdapterError> {
        Ok(())
    }
    async fn publish_event(
        &self,
        endpoints: &[TransportEndpoint],
        event: &NostrTransportEvent,
        _: usize,
    ) -> Result<NostrPublishOutcome, TransportAdapterError> {
        self.attempts.lock().unwrap().push(event.clone());
        self.publishing.notify_one();
        if self.block_publish.load(Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
        if self.zero_acks.load(Ordering::SeqCst) {
            return Ok(NostrPublishOutcome::default());
        }
        self.events.lock().unwrap().push(event.clone());
        Ok(NostrPublishOutcome::accepted(endpoints.iter().cloned()))
    }
}
fn options() -> OnboardingOptions {
    OnboardingOptions {
        default_relays: vec!["wss://default.example".into()],
        discovery_relays: vec!["wss://index.example".into()],
    }
}
fn runtime(path: &std::path::Path, network: Arc<Network>) -> MarmotAppRuntime {
    let mut app = MarmotApp::with_relay(path, "wss://default.example")
        .with_test_relay_client(network.clone());
    app.relay_plane =
        MarmotRelayPlane::new_with_directory_fetcher_for_test(network.clone(), network);
    MarmotAppRuntime::new(app)
}
async fn fixture() -> (
    tempfile::TempDir,
    MarmotAppRuntime,
    Arc<Network>,
    nostr::Keys,
    String,
) {
    let dir = tempfile::tempdir().unwrap();
    let network = Arc::new(Network::default());
    let runtime = runtime(dir.path(), network.clone());
    let keys = nostr::Keys::generate();
    let id = keys.public_key().to_hex();
    runtime
        .accounts()
        .begin_onboarding(
            Zeroizing::new(keys.secret_key().to_bech32().unwrap()),
            options(),
        )
        .await
        .unwrap();
    (dir, runtime, network, keys, id)
}
fn signed(
    keys: &nostr::Keys,
    kind: u16,
    tags: Vec<Vec<String>>,
    content: &str,
    at: u64,
) -> NostrTransportEvent {
    let event = EventBuilder::new(Kind::from(kind), content)
        .tags(tags.into_iter().map(|t| Tag::parse(t).unwrap()))
        .custom_created_at(Timestamp::from(at))
        .sign_with_keys(keys)
        .unwrap();
    NostrTransportEvent::from_nostr_event(&event).unwrap()
}
async fn missing_relays(runtime: &MarmotAppRuntime, id: &str) {
    let manager = runtime.accounts();
    manager.run_onboarding(id).await.unwrap();
    manager
        .continue_onboarding_without(id, OnboardingStep::Profile)
        .await
        .unwrap();
    let snapshot = manager
        .continue_onboarding_without(id, OnboardingStep::Follows)
        .await
        .unwrap();
    assert_eq!(snapshot.steps[2].status, OnboardingStatus::NeedsInput);
}
#[tokio::test]
async fn failed_discovery_never_authorizes_default_replacement() {
    let (_dir, runtime, network, _keys, id) = fixture().await;
    network.fail_reads.store(true, Ordering::SeqCst);
    let result = runtime.accounts().run_onboarding(&id).await.unwrap();
    assert_eq!(result.steps[0].status, OnboardingStatus::RetryableFailure);
    runtime
        .accounts()
        .continue_onboarding_without(&id, OnboardingStep::Profile)
        .await
        .unwrap();
    let result = runtime
        .accounts()
        .continue_onboarding_without(&id, OnboardingStep::Follows)
        .await
        .unwrap();
    assert_eq!(result.steps[2].status, OnboardingStatus::RetryableFailure);
    assert!(
        runtime
            .accounts()
            .propose_onboarding_relays(&id, OnboardingStep::Relays, None)
            .await
            .is_err()
    );
    assert!(network.attempts.lock().unwrap().is_empty());
    runtime.shutdown_and_close().await.unwrap();
}
#[tokio::test]
async fn newest_malformed_profile_is_not_hidden_by_older_valid_metadata() {
    let (_dir, runtime, network, keys, id) = fixture().await;
    network.events.lock().unwrap().extend([
        signed(
            &keys,
            0,
            vec![],
            "{\"name\":\"older\"}",
            unix_now_seconds() - 2,
        ),
        signed(&keys, 0, vec![], "[]", unix_now_seconds() - 1),
    ]);
    let result = runtime.accounts().run_onboarding(&id).await.unwrap();
    assert_eq!(
        result.steps[0].findings[0].issue,
        OnboardingIssue::Malformed
    );
    assert_eq!(result.steps[0].status, OnboardingStatus::NeedsInput);
    runtime.shutdown_and_close().await.unwrap();
}
#[tokio::test]
async fn future_dated_record_is_inconclusive_and_cannot_be_repaired_automatically() {
    let (_dir, runtime, network, keys, id) = fixture().await;
    network
        .events
        .lock()
        .unwrap()
        .push(signed(&keys, 0, vec![], "{}", unix_now_seconds() + 3600));
    let result = runtime.accounts().run_onboarding(&id).await.unwrap();
    assert_eq!(
        result.steps[0].findings[0].issue,
        OnboardingIssue::FutureDated
    );
    assert_eq!(result.steps[0].status, OnboardingStatus::RetryableFailure);
    assert!(
        !result.steps[0]
            .actions
            .contains(&OnboardingAction::EditProfile)
    );
    runtime.shutdown_and_close().await.unwrap();
}
#[tokio::test]
async fn zero_ack_repair_survives_restart_and_retries_exact_signed_bytes() {
    let (dir, first, network, _keys, id) = fixture().await;
    missing_relays(&first, &id).await;
    let proposal = first
        .accounts()
        .propose_onboarding_relays(&id, OnboardingStep::Relays, None)
        .await
        .unwrap();
    network.zero_acks.store(true, Ordering::SeqCst);
    let result = first
        .accounts()
        .approve_onboarding_repair(&id, proposal.revision)
        .await
        .unwrap();
    assert_eq!(result.steps[2].status, OnboardingStatus::RetryableFailure);
    let expected = network.attempts.lock().unwrap()[0].clone();
    assert!(expected.sig.is_some());
    first.shutdown_and_close().await.unwrap();
    let second = runtime(dir.path(), network.clone());
    let mut c = second
        .accounts()
        .onboarding_checkpoint(&id)
        .unwrap()
        .unwrap();
    assert!(c.approved);
    assert_eq!(c.signed_repair, Some(expected.clone()));
    network.zero_acks.store(false, Ordering::SeqCst);
    assert!(
        second
            .accounts()
            .publish_onboarding_repair(&mut c)
            .await
            .unwrap()
    );
    assert_eq!(network.attempts.lock().unwrap()[1], expected);
    assert!(c.snapshot.steps[4].status == OnboardingStatus::Pending && !c.snapshot.ready);
    second.shutdown_and_close().await.unwrap();
}
#[tokio::test]
async fn cancelled_publication_retains_approval_and_signed_bytes() {
    let (_dir, runtime, network, _keys, id) = fixture().await;
    missing_relays(&runtime, &id).await;
    let proposal = runtime
        .accounts()
        .propose_onboarding_relays(&id, OnboardingStep::Relays, None)
        .await
        .unwrap();
    network.block_publish.store(true, Ordering::SeqCst);
    let manager = runtime.accounts();
    let account = id.clone();
    let task = tokio::spawn(async move {
        manager
            .approve_onboarding_repair(&account, proposal.revision)
            .await
    });
    network.publishing.notified().await;
    task.abort();
    let _ = task.await;
    let c = runtime
        .accounts()
        .onboarding_checkpoint(&id)
        .unwrap()
        .unwrap();
    assert!(c.approved);
    assert_eq!(
        c.signed_repair,
        Some(network.attempts.lock().unwrap()[0].clone())
    );
    assert!(
        runtime
            .accounts()
            .cancel_onboarding_repair(&id)
            .await
            .is_err()
    );
    runtime.shutdown_and_close().await.unwrap();
}
#[tokio::test]
async fn optional_repairs_preserve_unknown_profile_fields_and_follow_tag_metadata() {
    let (_dir, runtime, _network, keys, id) = fixture().await;
    let mut c = runtime
        .accounts()
        .onboarding_checkpoint(&id)
        .unwrap()
        .unwrap();
    c.records[0] = Some(signed(
        &keys,
        0,
        vec![vec!["client".into(), "keep".into()]],
        "{\"name\":7,\"custom\":{\"keep\":true},\"website\":\"https://example.com\"}",
        unix_now_seconds() - 1,
    ));
    let mut proposal = OnboardingRepairProposal {
        step: OnboardingStep::Profile,
        revision: 1,
        previous_event_id: None,
        read_relays: vec![],
        write_relays: vec![],
        profile: Some(UserProfileMetadata {
            name: Some("fixed".into()),
            ..Default::default()
        }),
        follows: None,
    };
    let (tags, content, _) = relay_repair_event(&c, &proposal);
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(json["custom"]["keep"], true);
    assert_eq!(json["name"], "fixed");
    assert_eq!(json["website"], "https://example.com");
    assert_eq!(tags[0][1], "keep");
    let retained = nostr::Keys::generate().public_key().to_hex();
    c.records[1] = Some(signed(
        &keys,
        3,
        vec![
            vec![
                "p".into(),
                retained.clone(),
                "wss://hint.example".into(),
                "petname".into(),
            ],
            vec!["p".into(), "bad".into()],
            vec!["client".into(), "keep".into()],
        ],
        "opaque legacy content",
        unix_now_seconds() - 1,
    ));
    proposal.step = OnboardingStep::Follows;
    proposal.profile = None;
    proposal.follows = Some(vec![retained]);
    let (tags, content, _) = relay_repair_event(&c, &proposal);
    assert_eq!(tags[0][3], "petname");
    assert_eq!(tags.len(), 2);
    assert_eq!(content, "opaque legacy content");
    runtime.shutdown_and_close().await.unwrap();
}
#[tokio::test]
async fn corrupt_or_future_checkpoint_fails_closed() {
    let (_dir, runtime, _network, _keys, id) = fixture().await;
    let manager = runtime.accounts();
    let mut c = manager.onboarding_checkpoint(&id).unwrap().unwrap();
    c.version += 1;
    manager
        .app
        .account_home()
        .set_account_onboarding(&id, &serde_json::to_vec(&c).unwrap())
        .unwrap();
    assert!(manager.onboarding_snapshot(&id).is_err());
    assert!(manager.reconcile().await.is_err());
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn interactive_import_without_detailed_checkpoint_remains_gated() {
    let directory = tempfile::tempdir().unwrap();
    let network = Arc::new(Network::default());
    let runtime = runtime(directory.path(), network.clone());
    let keys = nostr::Keys::generate();
    let secret = keys.secret_key().to_bech32().unwrap();
    let id = keys.public_key().to_hex();
    let manager = runtime.accounts();
    manager
        .app
        .account_home()
        .import_nostr_account_for_onboarding(&secret)
        .unwrap();
    assert!(manager.onboarding_snapshot(&id).unwrap().is_none());
    assert!(!manager.onboarding_worker_allowed(&id).unwrap());
    assert!(matches!(
        manager.require_onboarding_complete(&id),
        Err(AppError::OnboardingRequired)
    ));
    let resumed = manager
        .begin_onboarding(Zeroizing::new(secret), options())
        .await
        .unwrap();
    assert_eq!(resumed.account_id_hex, id);
    assert!(!resumed.ready);
    assert!(network.attempts.lock().unwrap().is_empty());
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn completed_checkpoint_resumes_interrupted_journal_cleanup() {
    let (_directory, runtime, _network, _keys, id) = fixture().await;
    let manager = runtime.accounts();
    let mut c = manager.onboarding_checkpoint(&id).unwrap().unwrap();
    for step in [
        OnboardingStep::Profile,
        OnboardingStep::Follows,
        OnboardingStep::Relays,
        OnboardingStep::InboxRelays,
        OnboardingStep::KeyPackage,
    ] {
        c.set(step, OnboardingStatus::Passed, Vec::new());
    }
    manager.save_onboarding(&mut c).unwrap();
    assert!(
        manager
            .app
            .account_home()
            .account_setup_state(&id)
            .unwrap()
            .is_some()
    );
    assert_eq!(
        runtime.account_setup_readiness(&id).unwrap(),
        AccountSetupReadiness::NetworkReady
    );
    assert!(manager.run_onboarding(&id).await.unwrap().ready);
    assert!(
        manager
            .app
            .account_home()
            .account_setup_state(&id)
            .unwrap()
            .is_none()
    );
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn profile_url_validation_and_explicit_clear_preserve_unrelated_fields() {
    let (_directory, runtime, _network, keys, id) = fixture().await;
    let mut c = runtime
        .accounts()
        .onboarding_checkpoint(&id)
        .unwrap()
        .unwrap();
    let record = signed(
        &keys,
        0,
        vec![],
        "{\"picture\":\"file:///private/avatar\",\"custom\":true}",
        unix_now_seconds(),
    );
    assert_eq!(
        validate_onboarding_record(&record),
        vec![finding(OnboardingIssue::Malformed)]
    );
    c.records[0] = Some(record);
    let proposal = OnboardingRepairProposal {
        step: OnboardingStep::Profile,
        revision: 1,
        previous_event_id: None,
        read_relays: vec![],
        write_relays: vec![],
        profile: Some(UserProfileMetadata {
            picture: Some(String::new()),
            ..Default::default()
        }),
        follows: None,
    };
    let (_, content, _) = relay_repair_event(&c, &proposal);
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert!(json.get("picture").is_none());
    assert_eq!(json["custom"], true);
    runtime.shutdown_and_close().await.unwrap();
}
