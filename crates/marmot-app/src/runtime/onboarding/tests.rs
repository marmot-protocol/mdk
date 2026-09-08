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
    return_off_filter_events: AtomicBool,
    fail_index_only: AtomicBool,
    zero_acks: AtomicBool,
    block_publish: AtomicBool,
    publishing: Notify,
    release_publish: Notify,
}
#[async_trait]
impl DirectoryRelayFetcher for Network {
    async fn fetch_directory_events(
        &self,
        request: DirectoryFetchRequest,
    ) -> Result<Vec<DirectoryRelayEventRecord>, String> {
        if self.fail_reads.load(Ordering::SeqCst)
            || (self.fail_index_only.load(Ordering::SeqCst)
                && request
                    .endpoints
                    .iter()
                    .any(|e| e.0.contains("index.example")))
        {
            return Err("timeout".into());
        }
        Ok(self
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| {
                if self.return_off_filter_events.load(Ordering::SeqCst) {
                    return true;
                }
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
    ) -> Result<Vec<DirectoryRelayEventRecord>, crate::relay_plane::DirectoryInspectionError> {
        self.fetch_directory_events(request)
            .await
            .map_err(|_| crate::relay_plane::DirectoryInspectionError::TimedOut)
    }
}

#[tokio::test]
async fn onboarding_older_checkpoint_restores_retry_hints_and_conservative_package_validity() {
    let (directory, first, network, _keys, id) = fixture().await;
    let manager = first.accounts();
    let mut c = manager.onboarding_checkpoint(&id).unwrap().unwrap();
    c.set(OnboardingStep::Profile, OnboardingStatus::Passed, vec![]);
    c.set(OnboardingStep::Follows, OnboardingStatus::Skipped, vec![]);
    c.snapshot.single_device_notice = Some(OnboardingSingleDeviceNotice {
        discovery: OnboardingDeviceDiscovery::OtherInstallationPossible,
        other_packages: vec![OnboardingDevicePackage {
            slot_id: "foreign".into(),
            key_package_ref_hex: Some("ref".into()),
            event_id_hex: "event".into(),
            published_at: 1,
            expires_at: Some(2),
            usable: true,
        }],
        discovery_complete: true,
        acknowledged_at: None,
    });
    let mut old = serde_json::to_value(&c).unwrap();
    for index in 0..2 {
        old["snapshot"]["steps"][index]["actions"] = serde_json::json!([]);
    }
    old["snapshot"]["single_device_notice"]["other_packages"][0]
        .as_object_mut()
        .unwrap()
        .remove("usable");
    manager
        .app
        .account_home()
        .set_account_onboarding(&id, &serde_json::to_vec(&old).unwrap())
        .unwrap();
    first.shutdown_and_close().await.unwrap();
    let reopened = runtime(directory.path(), network);
    let manager = reopened.accounts();
    let snapshot = manager.onboarding_snapshot(&id).unwrap().unwrap();
    assert!(!snapshot.single_device_notice.unwrap().other_packages[0].usable);
    for step in &snapshot.steps[..2] {
        assert!(step.actions.contains(&OnboardingAction::Retry));
    }
    let retried = manager
        .retry_onboarding_step(&id, OnboardingStep::Profile)
        .await
        .unwrap();
    assert_eq!(
        retried.steps[OnboardingStep::Follows.index()].status,
        OnboardingStatus::Skipped
    );
    manager.cancel_onboarding(&id).await.unwrap();
    assert!(manager.onboarding_snapshot(&id).unwrap().is_none());
    reopened.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn single_device_ignores_unusable_owned_slots_but_preserves_foreign_evidence() {
    let (_directory, runtime, network, keys, id) = fixture().await;
    let manager = runtime.accounts();
    manager
        .app
        .account_storage(&id)
        .unwrap()
        .put_key_package_lifecycle(&cgka_traits::KeyPackageLifecycleState::slot_only(
            "owned-slot".into(),
        ))
        .unwrap();
    let mut c = manager.onboarding_checkpoint(&id).unwrap().unwrap();
    for published_at in [
        unix_now_seconds(),
        unix_now_seconds() + FUTURE_CLOCK_SKEW + 1,
    ] {
        *network.events.lock().unwrap() = vec![signed(
            &keys,
            30443,
            vec![vec!["d".into(), "owned-slot".into()]],
            "malformed",
            published_at,
        )];
        manager
            .check_onboarding_single_device(&mut c)
            .await
            .unwrap();
        let notice = c.snapshot.single_device_notice.as_ref().unwrap();
        assert_eq!(notice.discovery, OnboardingDeviceDiscovery::NoneFound);
        assert!(notice.discovery_complete && notice.other_packages.is_empty());
        network.events.lock().unwrap().push(signed(
            &keys,
            30443,
            vec![vec!["d".into(), "foreign-slot".into()]],
            "malformed",
            published_at,
        ));
        manager
            .check_onboarding_single_device(&mut c)
            .await
            .unwrap();
        let notice = c.snapshot.single_device_notice.as_ref().unwrap();
        assert_eq!(
            notice.discovery,
            OnboardingDeviceDiscovery::OtherInstallationPossible
        );
        assert_eq!(notice.other_packages.len(), 1);
        assert!(!notice.other_packages[0].usable);
    }
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn onboarding_legacy_setup_admission_does_not_mutate_account() {
    let directory = tempfile::tempdir().unwrap();
    let network = Arc::new(Network::default());
    let runtime = runtime(directory.path(), network);
    let keys = nostr::Keys::generate();
    let secret = keys.secret_key().to_bech32().unwrap();
    let account = runtime
        .accounts()
        .app
        .account_home()
        .import_nostr_account_idempotent(&secret)
        .unwrap()
        .account()
        .clone();
    assert!(
        runtime
            .accounts()
            .begin_onboarding(Zeroizing::new(secret), options())
            .await
            .is_err()
    );
    assert_eq!(runtime.accounts().resolve(&account.label).unwrap(), account);
    assert!(
        runtime
            .accounts()
            .onboarding_snapshot(&account.label)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        runtime
            .accounts()
            .app
            .account_home()
            .account_setup_state(&account.label)
            .unwrap()
            .unwrap()
            .kind,
        AccountSetupKind::ImportedIdentity
    );
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn onboarding_legacy_import_rejects_before_reactivating_the_identity() {
    let (_dir, runtime, network, keys, id) = fixture().await;
    let home = runtime.accounts().app.account_home();
    let before = home.set_account_signed_out(&id, true).unwrap();
    let checkpoint = home.account_onboarding(&id).unwrap();
    let result = runtime
        .create_or_import_account(AccountSetupRequest {
            import_nsec: Some(Zeroizing::new(keys.secret_key().to_bech32().unwrap())),
            ..AccountSetupRequest::default()
        })
        .await;
    assert!(matches!(result, Err(AppError::OnboardingRequired)));
    assert_eq!(home.account(&id).unwrap(), before);
    assert_eq!(home.account_onboarding(&id).unwrap(), checkpoint);
    assert!(network.attempts.lock().unwrap().is_empty());
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn onboarding_retry_preserves_declined_steps_and_invalidates_device_evidence() {
    let (_directory, runtime, _network, _keys, id) = fixture().await;
    let manager = runtime.accounts();
    let pending = manager.onboarding_snapshot(&id).unwrap().unwrap();
    assert!(
        manager
            .retry_onboarding_step(&id, OnboardingStep::Follows)
            .await
            .is_err()
    );
    assert_eq!(manager.onboarding_snapshot(&id).unwrap().unwrap(), pending);
    let mut c = manager.onboarding_checkpoint(&id).unwrap().unwrap();
    c.set(OnboardingStep::Profile, OnboardingStatus::Passed, vec![]);
    c.set(OnboardingStep::Follows, OnboardingStatus::Skipped, vec![]);
    c.set(
        OnboardingStep::SingleDevice,
        OnboardingStatus::Passed,
        vec![finding(OnboardingIssue::OtherInstallationPossible)],
    );
    c.single_device_acknowledged = true;
    c.snapshot.single_device_notice = Some(OnboardingSingleDeviceNotice {
        discovery: OnboardingDeviceDiscovery::OtherInstallationPossible,
        other_packages: vec![],
        discovery_complete: false,
        acknowledged_at: Some(1),
    });
    manager.save_onboarding(&mut c).unwrap();
    let retried = manager
        .retry_onboarding_step(&id, OnboardingStep::Profile)
        .await
        .unwrap();
    assert_eq!(
        retried.steps[OnboardingStep::Follows.index()].status,
        OnboardingStatus::Skipped
    );
    assert_eq!(
        retried.steps[OnboardingStep::SingleDevice.index()].status,
        OnboardingStatus::Pending
    );
    assert!(retried.single_device_notice.is_none());
    assert!(
        !manager
            .onboarding_checkpoint(&id)
            .unwrap()
            .unwrap()
            .single_device_acknowledged
    );
    // Changing sources invalidates even an already acknowledged notice.
    manager.save_onboarding(&mut c).unwrap();
    let changed = manager
        .set_onboarding_discovery_relays(&id, vec!["wss://alternate.example".into()])
        .await
        .unwrap();
    assert!(changed.single_device_notice.is_none());
    assert_eq!(
        changed.steps[OnboardingStep::Follows.index()].status,
        OnboardingStatus::Skipped
    );
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn onboarding_partial_discovery_and_off_filter_noise_have_distinct_results() {
    let (_directory, runtime, network, keys, id) = fixture().await;
    let manager = runtime.accounts();
    let mut c = manager.onboarding_checkpoint(&id).unwrap().unwrap();
    c.options
        .discovery_relays
        .push("wss://healthy.example".into());
    network
        .events
        .lock()
        .unwrap()
        .push(signed(&keys, 0, vec![], "{}", unix_now_seconds()));
    network.fail_index_only.store(true, Ordering::SeqCst);
    let (status, findings, _) = manager
        .check_onboarding_step(&c, OnboardingStep::Profile)
        .await;
    assert_eq!(status, OnboardingStatus::Passed);
    assert!(
        findings
            .iter()
            .any(|f| f.issue == OnboardingIssue::DiscoveryIncomplete)
    );
    network.fail_index_only.store(false, Ordering::SeqCst);
    network.events.lock().unwrap().clear();
    network.events.lock().unwrap().push(signed(
        &nostr::Keys::generate(),
        30443,
        vec![vec!["d".into(), "foreign-author".into()]],
        "noise",
        unix_now_seconds(),
    ));
    network
        .return_off_filter_events
        .store(true, Ordering::SeqCst);
    manager
        .check_onboarding_single_device(&mut c)
        .await
        .unwrap();
    assert_eq!(
        c.snapshot.single_device_notice.unwrap().discovery,
        OnboardingDeviceDiscovery::NoneFound
    );
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn onboarding_cancellation_retries_local_intent_and_allows_explicit_restart() {
    let (directory, runtime, network, keys, id) = fixture().await;
    let manager = runtime.accounts();
    let mut c = manager.onboarding_checkpoint(&id).unwrap().unwrap();
    // Simulate interruption after the cancellation intent, before sign-out.
    c.snapshot.cancellation_pending = true;
    manager.save_onboarding(&mut c).unwrap();
    assert!(manager.run_onboarding(&id).await.is_err());
    manager.cancel_onboarding(&id).await.unwrap();
    manager.cancel_onboarding(&id).await.unwrap();
    assert!(manager.resolve(&id).unwrap().signed_out);
    assert!(manager.onboarding_snapshot(&id).unwrap().is_none());
    assert!(manager.require_onboarding_complete(&id).is_ok());
    assert!(
        manager
            .app
            .account_home()
            .cancelled_account_onboarding(&id)
            .unwrap()
            .is_some()
    );
    assert!(network.attempts.lock().unwrap().is_empty());
    runtime.shutdown_and_close().await.unwrap();
    let reopened = super::tests::runtime(directory.path(), network);
    let resumed = reopened
        .accounts()
        .begin_onboarding(
            Zeroizing::new(keys.secret_key().to_bech32().unwrap()),
            options(),
        )
        .await
        .unwrap();
    assert!(!resumed.cancellation_pending && !resumed.ready);
    assert!(!reopened.accounts().managed_accounts().unwrap()[0].running);
    reopened.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn onboarding_completed_checkpoint_does_not_hide_or_clear_later_setup() {
    let (_dir, runtime, _network, keys, id) = fixture().await;
    let manager = runtime.accounts();
    let mut c = manager.onboarding_checkpoint(&id).unwrap().unwrap();
    for step in c.snapshot.steps.clone() {
        c.set(step.step, OnboardingStatus::Passed, vec![]);
    }
    manager.save_onboarding(&mut c).unwrap();
    let account = manager.resolve(&id).unwrap();
    manager
        .app
        .account_home()
        .begin_account_setup_with(
            &account,
            false,
            AccountSetupKind::ImportedIdentity,
            AccountSetupPhase::KeyPackagePublicationStarted,
        )
        .unwrap();
    assert_eq!(
        runtime.account_setup_readiness(&id).unwrap(),
        AccountSetupReadiness::Publishing
    );
    for cleanup_pending in [false, true] {
        c.setup_cleanup_pending = cleanup_pending;
        manager.save_onboarding(&mut c).unwrap();
        assert!(
            manager
                .begin_onboarding(
                    Zeroizing::new(keys.secret_key().to_bech32().unwrap()),
                    options(),
                )
                .await
                .is_err()
        );
        assert!(manager.run_onboarding(&id).await.unwrap().ready);
        assert_eq!(
            runtime.account_setup_readiness(&id).unwrap(),
            AccountSetupReadiness::Publishing
        );
    }
    assert_eq!(
        manager
            .app
            .account_home()
            .account_setup_state(&id)
            .unwrap()
            .unwrap()
            .phase,
        AccountSetupPhase::KeyPackagePublicationStarted
    );
    manager
        .app
        .account_home()
        .complete_account_setup(&id)
        .unwrap();
    let _storage = manager.app.account_storage(&id).unwrap();
    assert_eq!(
        runtime.account_setup_readiness(&id).unwrap(),
        AccountSetupReadiness::RecoveryRequired
    );
    runtime.shutdown_and_close().await.unwrap();
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
            self.release_publish.notified().await;
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
    assert!(
        c.snapshot.steps[OnboardingStep::KeyPackage.index()].status == OnboardingStatus::Pending
            && !c.snapshot.ready
    );
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
    assert!(manager.reconcile().await.is_ok());
    assert!(!manager.managed_accounts().unwrap()[0].running);
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
        OnboardingStep::SingleDevice,
        OnboardingStep::KeyPackage,
    ] {
        c.set(step, OnboardingStatus::Passed, Vec::new());
    }
    c.setup_cleanup_pending = true;
    manager
        .app
        .account_home()
        .set_account_setup_phase(&id, AccountSetupPhase::KeyPackagePublicationConfirmed)
        .unwrap();
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
        AccountSetupReadiness::Publishing
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

#[tokio::test]
async fn single_device_notice_distinguishes_empty_failed_and_invalid_discovery_without_publishing()
{
    let (_directory, runtime, network, keys, id) = fixture().await;
    let manager = runtime.accounts();
    let mut c = manager.onboarding_checkpoint(&id).unwrap().unwrap();
    manager
        .check_onboarding_single_device(&mut c)
        .await
        .unwrap();
    let notice = c.snapshot.single_device_notice.as_ref().unwrap();
    assert_eq!(notice.discovery, OnboardingDeviceDiscovery::NoneFound);
    assert!(notice.discovery_complete);
    assert_eq!(
        c.snapshot.steps[OnboardingStep::SingleDevice.index()].status,
        OnboardingStatus::NeedsInput
    );
    assert!(
        c.snapshot.steps[OnboardingStep::SingleDevice.index()]
            .actions
            .contains(&OnboardingAction::CancelOnboarding)
    );
    network.fail_reads.store(true, Ordering::SeqCst);
    manager
        .check_onboarding_single_device(&mut c)
        .await
        .unwrap();
    let notice = c.snapshot.single_device_notice.as_ref().unwrap();
    assert_eq!(notice.discovery, OnboardingDeviceDiscovery::Unknown);
    assert!(!notice.discovery_complete);
    network.fail_reads.store(false, Ordering::SeqCst);
    network.events.lock().unwrap().push(signed(
        &keys,
        30443,
        vec![vec!["d".into(), "foreign".into()]],
        "malformed",
        unix_now_seconds(),
    ));
    manager
        .check_onboarding_single_device(&mut c)
        .await
        .unwrap();
    assert_eq!(
        c.snapshot.single_device_notice.as_ref().unwrap().discovery,
        OnboardingDeviceDiscovery::OtherInstallationPossible
    );
    assert!(
        c.snapshot.steps[OnboardingStep::SingleDevice.index()]
            .findings
            .iter()
            .any(|f| f.issue == OnboardingIssue::Malformed)
    );
    network.events.lock().unwrap().clear();
    network.events.lock().unwrap().push(signed(
        &keys,
        30443,
        vec![vec!["d".into(), "future".into()]],
        "ignored",
        unix_now_seconds() + 600,
    ));
    manager
        .check_onboarding_single_device(&mut c)
        .await
        .unwrap();
    assert_eq!(
        c.snapshot.single_device_notice.as_ref().unwrap().discovery,
        OnboardingDeviceDiscovery::OtherInstallationPossible
    );
    assert!(
        c.snapshot.steps[OnboardingStep::SingleDevice.index()]
            .findings
            .iter()
            .any(|f| f.issue == OnboardingIssue::FutureDated)
    );
    assert!(network.attempts.lock().unwrap().is_empty());
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn pre_notice_checkpoint_upgrade_gates_incomplete_publication_and_preserves_completed_accounts()
 {
    let (_directory, runtime, _network, _keys, id) = fixture().await;
    let manager = runtime.accounts();
    let mut c = manager.onboarding_checkpoint(&id).unwrap().unwrap();
    c.version = 1;
    c.snapshot.steps.remove(4);
    c.records.remove(4);
    for step in &mut c.snapshot.steps {
        step.status = OnboardingStatus::Passed;
    }
    c.snapshot.steps[4].status = OnboardingStatus::Checking;
    manager
        .app
        .account_home()
        .set_account_onboarding(&id, &serde_json::to_vec(&c).unwrap())
        .unwrap();
    let upgraded = manager.onboarding_checkpoint(&id).unwrap().unwrap();
    assert_eq!(upgraded.version, ONBOARDING_VERSION);
    assert_eq!(
        upgraded.snapshot.steps[4].step,
        OnboardingStep::SingleDevice
    );
    assert_eq!(upgraded.snapshot.steps[5].status, OnboardingStatus::Pending);
    assert!(!manager.onboarding_worker_allowed(&id).unwrap());
    c.snapshot.ready = true;
    c.snapshot.steps[4].status = OnboardingStatus::Passed;
    manager
        .app
        .account_home()
        .set_account_onboarding(&id, &serde_json::to_vec(&c).unwrap())
        .unwrap();
    assert!(manager.onboarding_snapshot(&id).unwrap().unwrap().ready);
    assert!(manager.onboarding_worker_allowed(&id).unwrap());
    runtime.shutdown_and_close().await.unwrap();
}

fn repair_archive_bytes(root: &std::path::Path, id: &str) -> Vec<Vec<u8>> {
    let directory = root
        .join("accounts")
        .join(id)
        .join("onboarding-repair-archive");
    let mut files = std::fs::read_dir(directory)
        .map(|entries| {
            entries
                .filter_map(|entry| entry.ok())
                .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "json"))
                .filter_map(|entry| std::fs::read(entry.path()).ok())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    files.sort();
    files
}

#[tokio::test]
async fn approved_repair_cancellation_preserves_evidence_and_requires_fresh_approval() {
    let (dir, first, network, keys, id) = fixture().await;
    missing_relays(&first, &id).await;
    let proposal = first
        .accounts()
        .propose_onboarding_relays(&id, OnboardingStep::Relays, None)
        .await
        .unwrap();
    network.zero_acks.store(true, Ordering::SeqCst);
    first
        .accounts()
        .approve_onboarding_repair(&id, proposal.revision)
        .await
        .unwrap();
    let signed = network.attempts.lock().unwrap()[0].clone();
    let mut subscription = first.accounts().subscribe_onboarding(&id).unwrap();
    first.accounts().cancel_onboarding(&id).await.unwrap();
    let terminal = subscription.recv().await.unwrap();
    assert!(terminal.cancellation_pending && !terminal.ready);
    assert!(subscription.recv().await.is_none());
    assert!(first.accounts().resolve(&id).unwrap().signed_out);
    assert!(first.accounts().onboarding_snapshot(&id).unwrap().is_none());
    assert!(!first.accounts().managed_accounts().unwrap()[0].running);
    let archives = repair_archive_bytes(dir.path(), &id);
    assert_eq!(archives.len(), 1);
    let archived: OnboardingCheckpoint = serde_json::from_slice(&archives[0]).unwrap();
    assert!(archived.approved);
    assert_eq!(archived.signed_repair, Some(signed.clone()));
    first.shutdown_and_close().await.unwrap();
    let reopened = runtime(dir.path(), network.clone());
    let resumed = reopened
        .accounts()
        .begin_onboarding(
            Zeroizing::new(keys.secret_key().to_bech32().unwrap()),
            options(),
        )
        .await
        .unwrap();
    assert!(!resumed.ready && !resumed.cancellation_pending);
    assert!(resumed.proposal.is_none());
    assert!(resumed.revision > archived.snapshot.revision);
    reopened.accounts().run_onboarding(&id).await.unwrap();
    assert_eq!(network.attempts.lock().unwrap().len(), 1);
    assert!(
        reopened
            .accounts()
            .onboarding_checkpoint(&id)
            .unwrap()
            .unwrap()
            .signed_repair
            .is_none()
    );
    reopened.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn ready_onboarding_can_be_cancelled_before_open_chats() {
    let (_dir, runtime, _network, _keys, id) = fixture().await;
    let manager = runtime.accounts();
    let mut c = manager.onboarding_checkpoint(&id).unwrap().unwrap();
    for step in c.snapshot.steps.clone() {
        c.set(step.step, OnboardingStatus::Passed, vec![]);
    }
    manager.save_onboarding(&mut c).unwrap();
    assert!(manager.onboarding_snapshot(&id).unwrap().unwrap().ready);
    manager.cancel_onboarding(&id).await.unwrap();
    manager.cancel_onboarding(&id).await.unwrap();
    assert!(manager.resolve(&id).unwrap().signed_out);
    assert!(manager.onboarding_snapshot(&id).unwrap().is_none());
    assert!(!manager.managed_accounts().unwrap()[0].running);
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn successive_approved_cancellations_keep_distinct_archives() {
    let (dir, runtime, network, keys, id) = fixture().await;
    missing_relays(&runtime, &id).await;
    let first = runtime
        .accounts()
        .propose_onboarding_relays(&id, OnboardingStep::Relays, None)
        .await
        .unwrap();
    network.zero_acks.store(true, Ordering::SeqCst);
    runtime
        .accounts()
        .approve_onboarding_repair(&id, first.revision)
        .await
        .unwrap();
    runtime.accounts().cancel_onboarding(&id).await.unwrap();
    let after_first = repair_archive_bytes(dir.path(), &id);
    assert_eq!(after_first.len(), 1);
    runtime
        .accounts()
        .begin_onboarding(
            Zeroizing::new(keys.secret_key().to_bech32().unwrap()),
            options(),
        )
        .await
        .unwrap();
    missing_relays(&runtime, &id).await;
    let second = runtime
        .accounts()
        .propose_onboarding_relays(&id, OnboardingStep::Relays, None)
        .await
        .unwrap();
    runtime
        .accounts()
        .approve_onboarding_repair(&id, second.revision)
        .await
        .unwrap();
    runtime.accounts().cancel_onboarding(&id).await.unwrap();
    assert_eq!(repair_archive_bytes(dir.path(), &id).len(), 2);
    runtime
        .accounts()
        .begin_onboarding(
            Zeroizing::new(keys.secret_key().to_bech32().unwrap()),
            options(),
        )
        .await
        .unwrap();
    runtime.accounts().cancel_onboarding(&id).await.unwrap();
    assert_eq!(repair_archive_bytes(dir.path(), &id).len(), 2);
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn cancel_during_blocked_publish_does_not_start_another_send() {
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
    let revision = proposal.revision;
    let task = tokio::spawn({
        let manager = manager.clone();
        async move { manager.approve_onboarding_repair(&account, revision).await }
    });
    network.publishing.notified().await;
    manager.cancel_onboarding(&id).await.unwrap();
    task.abort();
    let _ = task.await;
    assert_eq!(network.attempts.lock().unwrap().len(), 1);
    assert!(manager.onboarding_snapshot(&id).unwrap().is_none());
    assert!(manager.resolve(&id).unwrap().signed_out);
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn pending_cancellation_blocks_begin_until_cleanup_finishes() {
    let (_dir, runtime, _network, keys, id) = fixture().await;
    let manager = runtime.accounts();
    let mut c = manager.onboarding_checkpoint(&id).unwrap().unwrap();
    c.snapshot.cancellation_pending = true;
    manager.save_onboarding(&mut c).unwrap();
    assert!(
        manager
            .begin_onboarding(
                Zeroizing::new(keys.secret_key().to_bech32().unwrap()),
                options(),
            )
            .await
            .is_err()
    );
    manager.cancel_onboarding(&id).await.unwrap();
    assert!(
        manager
            .begin_onboarding(
                Zeroizing::new(keys.secret_key().to_bech32().unwrap()),
                options(),
            )
            .await
            .is_ok()
    );
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn cancelled_account_is_not_auto_signed_in_on_reopen() {
    let (dir, first, network, _keys, id) = fixture().await;
    first.accounts().cancel_onboarding(&id).await.unwrap();
    first.shutdown_and_close().await.unwrap();
    let reopened = runtime(dir.path(), network);
    reopened.reconcile_accounts().await.unwrap();
    let account = reopened.accounts().resolve(&id).unwrap();
    assert!(account.signed_out);
    assert!(!reopened.accounts().managed_accounts().unwrap()[0].running);
    reopened.shutdown_and_close().await.unwrap();
}

async fn approve_blocked_repair(
    runtime: &MarmotAppRuntime,
    network: &Network,
    id: &str,
    step: OnboardingStep,
) -> (
    OnboardingSnapshot,
    tokio::task::JoinHandle<Result<OnboardingSnapshot, AppError>>,
) {
    let manager = runtime.accounts();
    let proposal = match step {
        OnboardingStep::Profile => {
            manager.run_onboarding(id).await.unwrap();
            manager
                .propose_onboarding_profile(
                    id,
                    UserProfileMetadata {
                        name: Some("repair".into()),
                        ..Default::default()
                    },
                )
                .await
                .unwrap()
        }
        OnboardingStep::Follows => {
            manager.run_onboarding(id).await.unwrap();
            manager
                .continue_onboarding_without(id, OnboardingStep::Profile)
                .await
                .unwrap();
            manager
                .propose_onboarding_follows(id, vec![nostr::Keys::generate().public_key().to_hex()])
                .await
                .unwrap()
        }
        OnboardingStep::Relays => {
            missing_relays(runtime, id).await;
            manager
                .propose_onboarding_relays(id, OnboardingStep::Relays, None)
                .await
                .unwrap()
        }
        OnboardingStep::InboxRelays => {
            missing_relays(runtime, id).await;
            let mut checkpoint = manager.onboarding_checkpoint(id).unwrap().unwrap();
            checkpoint.set(OnboardingStep::Relays, OnboardingStatus::Passed, vec![]);
            checkpoint.set(
                OnboardingStep::InboxRelays,
                OnboardingStatus::NeedsInput,
                vec![finding(OnboardingIssue::Missing)],
            );
            manager.save_onboarding(&mut checkpoint).unwrap();
            manager
                .propose_onboarding_relays(id, OnboardingStep::InboxRelays, None)
                .await
                .unwrap()
        }
        _ => panic!("unsupported repair step"),
    };
    network.block_publish.store(true, Ordering::SeqCst);
    let account = id.to_owned();
    let revision = proposal.revision;
    let task = tokio::spawn({
        let manager = manager.clone();
        async move { manager.approve_onboarding_repair(&account, revision).await }
    });
    network.publishing.notified().await;
    (proposal, task)
}

async fn assert_cancelled_and_fresh(
    runtime: &MarmotAppRuntime,
    network: &Network,
    keys: &nostr::Keys,
    id: &str,
    previous_sends: usize,
) {
    let manager = runtime.accounts();
    assert!(manager.onboarding_snapshot(id).unwrap().is_none());
    assert!(manager.resolve(id).unwrap().signed_out);
    assert!(!manager.managed_accounts().unwrap()[0].running);
    assert_eq!(network.attempts.lock().unwrap().len(), previous_sends);
    let resumed = manager
        .begin_onboarding(
            Zeroizing::new(keys.secret_key().to_bech32().unwrap()),
            options(),
        )
        .await
        .unwrap();
    assert!(!resumed.ready && !resumed.cancellation_pending && resumed.proposal.is_none());
    manager.run_onboarding(id).await.unwrap();
    assert_eq!(network.attempts.lock().unwrap().len(), previous_sends);
}

#[tokio::test(flavor = "multi_thread")]
async fn late_publish_responses_do_not_resurrect_cancelled_repairs() {
    for (step, zero_acks) in [
        (OnboardingStep::Profile, false),
        (OnboardingStep::Follows, true),
        (OnboardingStep::Relays, false),
        (OnboardingStep::InboxRelays, true),
    ] {
        let (_dir, runtime, network, keys, id) = fixture().await;
        network.zero_acks.store(zero_acks, Ordering::SeqCst);
        let (_proposal, task) = approve_blocked_repair(&runtime, &network, &id, step).await;
        runtime.accounts().cancel_onboarding(&id).await.unwrap();
        network.block_publish.store(false, Ordering::SeqCst);
        network.release_publish.notify_waiters();
        let _ = task.await.unwrap();
        let sends = network.attempts.lock().unwrap().len();
        assert_cancelled_and_fresh(&runtime, &network, &keys, &id, sends).await;
        runtime.shutdown_and_close().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn late_publish_does_not_overwrite_a_newer_attempt() {
    let (_dir, runtime, network, keys, id) = fixture().await;
    let (_proposal, task) =
        approve_blocked_repair(&runtime, &network, &id, OnboardingStep::Relays).await;
    runtime.accounts().cancel_onboarding(&id).await.unwrap();
    let first_attempt = runtime
        .accounts()
        .app
        .account_home()
        .cancelled_account_onboarding(&id)
        .unwrap()
        .unwrap();
    let first: OnboardingCheckpoint = serde_json::from_slice(&first_attempt).unwrap();
    runtime
        .accounts()
        .begin_onboarding(
            Zeroizing::new(keys.secret_key().to_bech32().unwrap()),
            options(),
        )
        .await
        .unwrap();
    let newer = runtime
        .accounts()
        .onboarding_checkpoint(&id)
        .unwrap()
        .unwrap();
    assert_ne!(newer.attempt_start_revision, first.attempt_start_revision);
    network.block_publish.store(false, Ordering::SeqCst);
    network.release_publish.notify_waiters();
    let _ = task.await.unwrap();
    let after = runtime
        .accounts()
        .onboarding_checkpoint(&id)
        .unwrap()
        .unwrap();
    assert_eq!(after.attempt_start_revision, newer.attempt_start_revision);
    assert!(!after.approved && after.signed_repair.is_none());
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn cancel_during_blocked_publish_releases_begin_without_aborting_caller() {
    let (_dir, runtime, network, keys, id) = fixture().await;
    let (_proposal, task) =
        approve_blocked_repair(&runtime, &network, &id, OnboardingStep::Relays).await;
    runtime.accounts().cancel_onboarding(&id).await.unwrap();
    let signed = network.attempts.lock().unwrap()[0].clone();
    tokio::time::timeout(
        Duration::from_secs(2),
        runtime.accounts().begin_onboarding(
            Zeroizing::new(keys.secret_key().to_bech32().unwrap()),
            options(),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let queued = runtime
        .accounts()
        .retry_onboarding_step(&id, OnboardingStep::Profile)
        .await;
    assert!(queued.is_err());
    let archives = {
        let cancelled = runtime
            .accounts()
            .app
            .account_home()
            .cancelled_account_onboarding(&id)
            .unwrap()
            .unwrap();
        let archived: OnboardingCheckpoint = serde_json::from_slice(&cancelled).unwrap();
        archived
    };
    assert!(archives.approved);
    assert_eq!(archives.signed_repair, Some(signed));
    let _ = task.await;
    runtime.shutdown_and_close().await.unwrap();
}

#[derive(Clone)]
struct BlockingSigner {
    keys: nostr::Keys,
    block: Arc<AtomicBool>,
    started: Arc<Notify>,
}

impl std::fmt::Debug for BlockingSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockingSigner").finish_non_exhaustive()
    }
}

impl nostr::NostrSigner for BlockingSigner {
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
        let keys = self.keys.clone();
        let block = self.block.clone();
        let started = self.started.clone();
        Box::pin(async move {
            started.notify_one();
            if block.load(Ordering::SeqCst) {
                std::future::pending::<()>().await;
            }
            keys.sign_event(unsigned).await
        })
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

impl cgka_engine::account_identity_proof::AccountIdentityProofSigner for BlockingSigner {
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

#[tokio::test(flavor = "multi_thread")]
async fn cancel_during_blocked_signer_allows_fresh_external_begin() {
    let directory = tempfile::tempdir().unwrap();
    let network = Arc::new(Network::default());
    let runtime = runtime(directory.path(), network.clone());
    let keys = nostr::Keys::generate();
    let id = keys.public_key().to_hex();
    let block = Arc::new(AtomicBool::new(false));
    let started = Arc::new(Notify::new());
    runtime
        .accounts()
        .begin_external_signer_onboarding(
            id.clone(),
            BlockingSigner {
                keys: keys.clone(),
                block: block.clone(),
                started: started.clone(),
            },
            options(),
        )
        .await
        .unwrap();
    missing_relays(&runtime, &id).await;
    let proposal = runtime
        .accounts()
        .propose_onboarding_relays(&id, OnboardingStep::Relays, None)
        .await
        .unwrap();
    block.store(true, Ordering::SeqCst);
    let task = tokio::spawn({
        let manager = runtime.accounts();
        let account = id.clone();
        let revision = proposal.revision;
        async move { manager.approve_onboarding_repair(&account, revision).await }
    });
    started.notified().await;
    runtime.accounts().cancel_onboarding(&id).await.unwrap();
    tokio::time::timeout(
        Duration::from_secs(2),
        runtime.accounts().begin_external_signer_onboarding(
            id.clone(),
            BlockingSigner {
                keys: keys.clone(),
                block: Arc::new(AtomicBool::new(false)),
                started: Arc::new(Notify::new()),
            },
            options(),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let _ = task.await;
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn cancel_between_liveness_and_activation_keeps_account_signed_out() {
    let (_dir, runtime, network, _keys, id) = fixture().await;
    let manager = runtime.accounts();
    let mut c = manager.onboarding_checkpoint(&id).unwrap().unwrap();
    for step in [
        OnboardingStep::Profile,
        OnboardingStep::Follows,
        OnboardingStep::Relays,
        OnboardingStep::InboxRelays,
        OnboardingStep::SingleDevice,
    ] {
        c.set(step, OnboardingStatus::Passed, vec![]);
    }
    manager.save_onboarding(&mut c).unwrap();
    let hold = manager.install_onboarding_activation_hold();
    let task = tokio::spawn({
        let manager = manager.clone();
        let account = id.clone();
        async move { manager.run_onboarding(&account).await }
    });
    hold.wait_until_entered().await;
    manager.cancel_onboarding(&id).await.unwrap();
    hold.release.notify_one();
    let _ = timeout(Duration::from_secs(2), task)
        .await
        .expect("retired onboarding operation did not stop")
        .unwrap();
    assert!(manager.resolve(&id).unwrap().signed_out);
    assert!(manager.onboarding_snapshot(&id).unwrap().is_none());
    assert!(network.attempts.lock().unwrap().is_empty());
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn cancel_between_liveness_and_publish_admission_does_not_send() {
    let (_dir, runtime, network, _keys, id) = fixture().await;
    missing_relays(&runtime, &id).await;
    let proposal = runtime
        .accounts()
        .propose_onboarding_relays(&id, OnboardingStep::Relays, None)
        .await
        .unwrap();
    let hold = runtime.accounts().install_onboarding_publication_hold();
    let task = tokio::spawn({
        let manager = runtime.accounts();
        let account = id.clone();
        let revision = proposal.revision;
        async move { manager.approve_onboarding_repair(&account, revision).await }
    });
    hold.wait_until_entered().await;
    runtime.accounts().cancel_onboarding(&id).await.unwrap();
    hold.release.notify_one();
    let _ = timeout(Duration::from_secs(2), task)
        .await
        .expect("retired onboarding operation did not stop")
        .unwrap();
    assert!(network.attempts.lock().unwrap().is_empty());
    assert!(
        runtime
            .accounts()
            .onboarding_snapshot(&id)
            .unwrap()
            .is_none()
    );
    assert!(runtime.accounts().resolve(&id).unwrap().signed_out);
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn dropped_reconcile_during_worker_reap_still_reaps() {
    let (_dir, runtime, _network, _keys, id) = fixture().await;
    let manager = runtime.accounts();
    manager
        .app
        .account_home()
        .set_account_signed_out(&id, false)
        .unwrap();
    let mut c = manager.onboarding_checkpoint(&id).unwrap().unwrap();
    c.set(
        OnboardingStep::KeyPackage,
        OnboardingStatus::Checking,
        vec![],
    );
    manager.save_onboarding(&mut c).unwrap();
    manager.reconcile().await.unwrap();
    assert!(manager.onboarding_worker_tracked(&id).await);
    let mut pending = manager.onboarding_checkpoint(&id).unwrap().unwrap();
    pending.snapshot.cancellation_pending = true;
    manager.save_onboarding(&mut pending).unwrap();
    let hold = manager.install_onboarding_worker_reap_hold();
    let reconcile = tokio::spawn({
        let manager = manager.clone();
        async move { manager.reconcile().await }
    });
    hold.wait_until_entered().await;
    reconcile.abort();
    let _ = reconcile.await;
    assert!(!manager.onboarding_worker_tracked(&id).await);
    assert!(manager.onboarding_worker_reap_in_flight(&id));
    let cancel = tokio::spawn({
        let manager = manager.clone();
        let account = id.clone();
        async move { manager.cancel_onboarding(&account).await }
    });
    hold.release.notify_one();
    timeout(Duration::from_secs(2), cancel)
        .await
        .expect("cancellation did not finish reaping")
        .unwrap()
        .unwrap();
    assert!(!manager.onboarding_worker_tracked(&id).await);
    assert!(!manager.onboarding_worker_reap_in_flight(&id));
    assert!(manager.resolve(&id).unwrap().signed_out);
    runtime.shutdown_and_close().await.unwrap();
}

fn write_active_checkpoint(dir: &std::path::Path, id: &str, value: serde_json::Value) {
    let path = dir.join("accounts").join(id).join("onboarding.json");
    std::fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
}

fn omit_attempt_generation(mut value: serde_json::Value) -> serde_json::Value {
    value
        .as_object_mut()
        .expect("checkpoint object")
        .remove("attempt_start_revision");
    value
}

fn mark_ready(c: &mut OnboardingCheckpoint) {
    for step in c.snapshot.steps.clone() {
        c.set(step.step, OnboardingStatus::Passed, vec![]);
    }
}

#[tokio::test]
async fn stale_ready_cleanup_after_cancel_retains_setup_journal() {
    let (_dir, runtime, _network, _keys, id) = fixture().await;
    let manager = runtime.accounts();
    let mut c = manager.onboarding_checkpoint(&id).unwrap().unwrap();
    mark_ready(&mut c);
    c.setup_cleanup_pending = true;
    manager
        .app
        .account_home()
        .set_account_setup_phase(&id, AccountSetupPhase::KeyPackagePublicationConfirmed)
        .unwrap();
    manager
        .app
        .account_home()
        .set_account_setup_context(&id, b"retained-setup")
        .unwrap();
    manager.save_onboarding(&mut c).unwrap();
    let stale = manager.onboarding_checkpoint(&id).unwrap().unwrap();
    manager.cancel_onboarding(&id).await.unwrap();
    assert!(
        manager
            .run_captured_onboarding(&mut stale.clone())
            .await
            .is_err()
    );
    assert_eq!(
        manager
            .app
            .account_home()
            .account_setup_context(&id)
            .unwrap()
            .as_deref(),
        Some(b"retained-setup".as_slice())
    );
    assert!(
        manager
            .app
            .account_home()
            .account_setup_state(&id)
            .unwrap()
            .is_some()
    );
    let account = manager.resolve(&id).unwrap();
    manager
        .app
        .account_home()
        .begin_account_setup_with(
            &account,
            false,
            AccountSetupKind::ImportedIdentity,
            AccountSetupPhase::KeyPackagePublicationStarted,
        )
        .unwrap();
    manager
        .app
        .account_home()
        .set_account_setup_context(&id, b"later-legacy")
        .unwrap();
    assert!(
        manager
            .run_captured_onboarding(&mut stale.clone())
            .await
            .is_err()
    );
    assert_eq!(
        manager
            .app
            .account_home()
            .account_setup_state(&id)
            .unwrap()
            .unwrap()
            .kind,
        AccountSetupKind::ImportedIdentity
    );
    assert_eq!(
        manager
            .app
            .account_home()
            .account_setup_context(&id)
            .unwrap()
            .as_deref(),
        Some(b"later-legacy".as_slice())
    );
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn cancel_during_ready_cleanup_hold_retains_setup() {
    let (_dir, runtime, _network, _keys, id) = fixture().await;
    let manager = runtime.accounts();
    let mut c = manager.onboarding_checkpoint(&id).unwrap().unwrap();
    mark_ready(&mut c);
    c.setup_cleanup_pending = true;
    manager
        .app
        .account_home()
        .set_account_setup_phase(&id, AccountSetupPhase::KeyPackagePublicationConfirmed)
        .unwrap();
    manager
        .app
        .account_home()
        .set_account_setup_context(&id, b"cleanup-hold")
        .unwrap();
    manager.save_onboarding(&mut c).unwrap();
    let hold = manager.install_onboarding_setup_cleanup_hold();
    let running = tokio::spawn({
        let manager = manager.clone();
        let account = id.clone();
        async move { manager.run_onboarding(&account).await }
    });
    hold.wait_until_entered().await;
    manager.cancel_onboarding(&id).await.unwrap();
    hold.release.notify_one();
    assert!(
        timeout(Duration::from_secs(2), running)
            .await
            .expect("retired setup cleanup did not stop")
            .unwrap()
            .is_err()
    );
    assert_eq!(
        manager
            .app
            .account_home()
            .account_setup_context(&id)
            .unwrap()
            .as_deref(),
        Some(b"cleanup-hold".as_slice())
    );
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn stale_key_package_setup_after_cancel_does_not_mutate_setup() {
    let (_dir, runtime, _network, _keys, id) = fixture().await;
    let manager = runtime.accounts();
    let before = manager
        .app
        .account_home()
        .account_setup_state(&id)
        .unwrap()
        .unwrap();
    let mut stale = manager.onboarding_checkpoint(&id).unwrap().unwrap();
    for step in [
        OnboardingStep::Profile,
        OnboardingStep::Follows,
        OnboardingStep::Relays,
        OnboardingStep::InboxRelays,
        OnboardingStep::SingleDevice,
    ] {
        stale.set(step, OnboardingStatus::Passed, vec![]);
    }
    manager.save_onboarding(&mut stale).unwrap();
    let mut stale = manager.onboarding_checkpoint(&id).unwrap().unwrap();
    manager.cancel_onboarding(&id).await.unwrap();
    assert!(manager.run_captured_onboarding(&mut stale).await.is_err());
    let after = manager
        .app
        .account_home()
        .account_setup_state(&id)
        .unwrap()
        .unwrap();
    assert_eq!(after.phase, before.phase);
    assert_ne!(after.kind, AccountSetupKind::InteractiveIdentity);
    runtime.shutdown_and_close().await.unwrap();
}

fn write_legacy_checkpoint(
    dir: &std::path::Path,
    id: &str,
    mut value: serde_json::Value,
    version: u32,
) {
    value["version"] = serde_json::json!(version);
    if version == 1 {
        value["snapshot"]["steps"].as_array_mut().unwrap().remove(4);
        value["records"].as_array_mut().unwrap().remove(4);
    }
    write_active_checkpoint(dir, id, omit_attempt_generation(value));
}

#[tokio::test(flavor = "multi_thread")]
async fn pre_generation_checkpoints_resume_retry_and_cancel_without_replay() {
    let (dir, runtime, network, keys, id) = fixture().await;
    let manager = runtime.accounts();
    let pending = manager.onboarding_checkpoint(&id).unwrap().unwrap();
    write_legacy_checkpoint(dir.path(), &id, serde_json::to_value(&pending).unwrap(), 2);
    let discovered = manager.run_onboarding(&id).await.unwrap();
    assert_ne!(
        discovered.steps[OnboardingStep::Profile.index()].status,
        OnboardingStatus::Pending
    );
    write_legacy_checkpoint(dir.path(), &id, serde_json::to_value(&pending).unwrap(), 1);
    assert_ne!(
        manager.run_onboarding(&id).await.unwrap().steps[0].status,
        OnboardingStatus::Pending
    );
    missing_relays(&runtime, &id).await;
    let proposal = manager
        .propose_onboarding_relays(&id, OnboardingStep::Relays, None)
        .await
        .unwrap();
    network.zero_acks.store(true, Ordering::SeqCst);
    manager
        .approve_onboarding_repair(&id, proposal.revision)
        .await
        .unwrap();
    let signed = network.attempts.lock().unwrap()[0].clone();
    let approved = manager.onboarding_checkpoint(&id).unwrap().unwrap();
    assert!(approved.approved && approved.signed_repair == Some(signed.clone()));
    for version in [2_u32, 1] {
        write_legacy_checkpoint(
            dir.path(),
            &id,
            serde_json::to_value(&approved).unwrap(),
            version,
        );
        let loaded = manager.onboarding_checkpoint(&id).unwrap().unwrap();
        assert_eq!(loaded.attempt_start_revision, 0);
        let retried = manager
            .retry_onboarding_step(&id, OnboardingStep::Relays)
            .await
            .unwrap();
        assert!(
            retried.steps[OnboardingStep::Relays.index()]
                .actions
                .contains(&OnboardingAction::Retry)
        );
        let attempts = network.attempts.lock().unwrap().clone();
        assert!(!attempts.is_empty() && attempts.iter().all(|event| event == &signed));
    }
    write_legacy_checkpoint(dir.path(), &id, serde_json::to_value(&approved).unwrap(), 2);
    assert_eq!(
        manager
            .onboarding_checkpoint(&id)
            .unwrap()
            .unwrap()
            .attempt_start_revision,
        0
    );
    network.zero_acks.store(false, Ordering::SeqCst);
    network.block_publish.store(true, Ordering::SeqCst);
    let blocked = tokio::spawn({
        let manager = manager.clone();
        let account = id.clone();
        async move {
            manager
                .retry_onboarding_step(&account, OnboardingStep::Relays)
                .await
        }
    });
    network.publishing.notified().await;
    tokio::time::timeout(Duration::from_secs(2), manager.cancel_onboarding(&id))
        .await
        .expect("cancellation must wake a migrated generation-zero publish wait")
        .unwrap();
    let restarted = manager
        .begin_onboarding(
            Zeroizing::new(keys.secret_key().to_bech32().unwrap()),
            options(),
        )
        .await
        .unwrap();
    let fresh = manager.onboarding_checkpoint(&id).unwrap().unwrap();
    assert_ne!(fresh.attempt_start_revision, 0);
    assert_ne!(
        fresh.attempt_start_revision,
        approved.attempt_start_revision
    );
    assert!(!restarted.ready && restarted.proposal.is_none());
    assert!(fresh.signed_repair.is_none() && !fresh.approved);
    network.release_publish.notify_waiters();
    let _ = blocked.await;
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn dropped_cancel_after_reaper_finishes_still_cleans_up_and_restarts() {
    let (_dir, runtime, _network, keys, id) = fixture().await;
    let manager = runtime.accounts();
    manager
        .app
        .account_home()
        .set_account_signed_out(&id, false)
        .unwrap();
    let mut c = manager.onboarding_checkpoint(&id).unwrap().unwrap();
    c.set(
        OnboardingStep::KeyPackage,
        OnboardingStatus::Checking,
        vec![],
    );
    manager.save_onboarding(&mut c).unwrap();
    manager.reconcile().await.unwrap();
    assert!(manager.onboarding_worker_tracked(&id).await);
    let hold = manager.install_onboarding_worker_reap_hold();
    let first = tokio::spawn({
        let manager = manager.clone();
        let account = id.clone();
        async move { manager.cancel_onboarding(&account).await }
    });
    hold.wait_until_entered().await;
    first.abort();
    let _ = first.await;
    assert!(manager.onboarding_worker_reap_in_flight(&id));
    let mut completed = manager
        .onboarding_cancellations
        .lock()
        .unwrap()
        .reaping
        .get(&id)
        .unwrap()
        .subscribe();
    hold.release.notify_one();
    // Let cancellation consume and remove the map entry before observing the
    // retained receiver, reproducing the ordering that broke the old poller.
    manager.await_onboarding_owned_handles_finished().await;
    assert!(manager.onboarding_worker_reap_watch_state(&id).is_none());
    timeout(Duration::from_secs(2), completed.wait_for(|done| *done))
        .await
        .expect("worker reap did not complete")
        .expect("worker reap dropped without completion");
    assert!(!manager.onboarding_worker_reap_in_flight(&id));
    manager.cancel_onboarding(&id).await.unwrap();
    assert!(!manager.onboarding_worker_tracked(&id).await);
    assert!(manager.resolve(&id).unwrap().signed_out);
    let restarted = manager
        .begin_onboarding(
            Zeroizing::new(keys.secret_key().to_bech32().unwrap()),
            options(),
        )
        .await
        .unwrap();
    assert!(!restarted.ready && !restarted.cancellation_pending);
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn dropped_reconcile_reap_completes_with_zero_receivers_then_restarts() {
    let (_dir, runtime, _network, keys, id) = fixture().await;
    let manager = runtime.accounts();
    manager
        .app
        .account_home()
        .set_account_signed_out(&id, false)
        .unwrap();
    let mut c = manager.onboarding_checkpoint(&id).unwrap().unwrap();
    c.set(
        OnboardingStep::KeyPackage,
        OnboardingStatus::Checking,
        vec![],
    );
    manager.save_onboarding(&mut c).unwrap();
    manager.reconcile().await.unwrap();
    assert!(manager.onboarding_worker_tracked(&id).await);
    let mut pending = manager.onboarding_checkpoint(&id).unwrap().unwrap();
    pending.snapshot.cancellation_pending = true;
    manager.save_onboarding(&mut pending).unwrap();
    let hold = manager.install_onboarding_worker_reap_hold();
    let reconcile = tokio::spawn({
        let manager = manager.clone();
        async move { manager.reconcile().await }
    });
    hold.wait_until_entered().await;
    reconcile.abort();
    let _ = reconcile.await;
    assert!(!manager.onboarding_worker_tracked(&id).await);
    assert!(manager.onboarding_worker_reap_in_flight(&id));
    assert_eq!(
        manager.onboarding_worker_reap_watch_state(&id),
        Some((false, 0))
    );
    hold.release.notify_one();
    manager.await_onboarding_owned_handles_finished().await;
    assert_eq!(
        manager.onboarding_worker_reap_watch_state(&id),
        Some((true, 0))
    );
    manager.cancel_onboarding(&id).await.unwrap();
    assert!(!manager.onboarding_worker_tracked(&id).await);
    assert!(!manager.onboarding_worker_reap_in_flight(&id));
    assert!(manager.resolve(&id).unwrap().signed_out);
    let restarted = manager
        .begin_onboarding(
            Zeroizing::new(keys.secret_key().to_bech32().unwrap()),
            options(),
        )
        .await
        .unwrap();
    assert!(!restarted.ready && !restarted.cancellation_pending);
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn timed_out_reap_waiter_retains_completion_through_shutdown() {
    let (_dir, runtime, _network, _keys, id) = fixture().await;
    let manager = runtime.accounts();
    manager
        .app
        .account_home()
        .set_account_signed_out(&id, false)
        .unwrap();
    let mut c = manager.onboarding_checkpoint(&id).unwrap().unwrap();
    c.set(
        OnboardingStep::KeyPackage,
        OnboardingStatus::Checking,
        vec![],
    );
    manager.save_onboarding(&mut c).unwrap();
    manager.reconcile().await.unwrap();
    let mut pending = manager.onboarding_checkpoint(&id).unwrap().unwrap();
    pending.snapshot.cancellation_pending = true;
    manager.save_onboarding(&mut pending).unwrap();
    let hold = manager.install_onboarding_worker_reap_hold();
    let reconcile = tokio::spawn({
        let manager = manager.clone();
        async move { manager.reconcile().await }
    });
    hold.wait_until_entered().await;
    reconcile.abort();
    let _ = reconcile.await;
    let timed_out = manager
        .await_onboarding_worker_reap_with_budget(&id, Duration::from_millis(20))
        .await;
    assert!(matches!(
        timed_out,
        Err(AppError::AccountWorkerResponseTimedOut)
    ));
    assert!(manager.onboarding_worker_reap_in_flight(&id));
    hold.release.notify_one();
    manager.await_onboarding_owned_handles_finished().await;
    assert_eq!(
        manager.onboarding_worker_reap_watch_state(&id),
        Some((true, 0))
    );
    assert!(!manager.onboarding_worker_tracked(&id).await);
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn shutdown_reaps_late_onboarding_worker_after_reconcile_is_dropped() {
    let (_dir, runtime, _network, _keys, id) = fixture().await;
    let manager = runtime.accounts();
    let mut checkpoint = manager.onboarding_checkpoint(&id).unwrap().unwrap();
    checkpoint.set(
        OnboardingStep::KeyPackage,
        OnboardingStatus::Checking,
        vec![],
    );
    manager.save_onboarding(&mut checkpoint).unwrap();
    manager.reconcile().await.unwrap();
    assert!(manager.onboarding_worker_tracked(&id).await);
    checkpoint.snapshot.cancellation_pending = true;
    manager.save_onboarding(&mut checkpoint).unwrap();

    let recovery = OnboardingTestHold::new();
    *manager
        .onboarding_test_holds
        .cancellation_recovery
        .lock()
        .unwrap() = Some(recovery.clone());
    let reap = manager.install_onboarding_worker_reap_hold();
    let reconcile = tokio::spawn({
        let manager = manager.clone();
        async move { manager.reconcile().await }
    });
    recovery.wait_until_entered().await;

    // Poll shutdown through its initial handle snapshot. Reconcile still owns
    // worker_transactions, so shutdown must wait before draining the workers.
    let shutdown = manager.shutdown();
    tokio::pin!(shutdown);
    assert!(futures::poll!(&mut shutdown).is_pending());
    assert!(!manager.onboarding_cancellations.lock().unwrap().accepting);
    recovery.release.notify_one();
    reap.wait_until_entered().await;
    assert!(!manager.onboarding_worker_tracked(&id).await);
    reconcile.abort();
    timeout(Duration::from_secs(2), reconcile)
        .await
        .expect("reconcile did not stop")
        .unwrap_err();

    // The only worker is now owned by a reaper added AFTER that snapshot.
    // Shutdown must await it even though the worker map is already empty.
    assert!(manager.onboarding_worker_reap_in_flight(&id));
    assert!(futures::poll!(&mut shutdown).is_pending());
    reap.release.notify_one();
    timeout(Duration::from_secs(2), &mut shutdown)
        .await
        .expect("shutdown did not reap the late worker");
    assert_eq!(
        manager.onboarding_worker_reap_watch_state(&id),
        Some((true, 0))
    );
    assert!(
        manager
            .onboarding_cancellations
            .lock()
            .unwrap()
            .handles
            .is_empty()
    );
    runtime.shutdown_and_close().await.unwrap();
}

fn write_cancelled_checkpoint(dir: &std::path::Path, id: &str, value: serde_json::Value) {
    let path = dir
        .join("accounts")
        .join(id)
        .join("onboarding-cancelled.json");
    std::fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
}

#[tokio::test]
async fn cancelled_checkpoint_validation_rejects_malformed_archives() {
    let (dir, runtime, _network, keys, id) = fixture().await;
    let manager = runtime.accounts();
    let mut c = manager.onboarding_checkpoint(&id).unwrap().unwrap();
    c.snapshot.cancellation_pending = true;
    manager.save_onboarding(&mut c).unwrap();
    manager
        .app
        .account_home()
        .set_account_signed_out(&id, true)
        .unwrap();
    manager
        .app
        .account_home()
        .archive_account_onboarding(&id)
        .unwrap();
    let mut unsupported = serde_json::to_value(&c).unwrap();
    unsupported["version"] = serde_json::json!(999);
    write_cancelled_checkpoint(dir.path(), &id, unsupported);
    assert!(
        manager
            .begin_onboarding(
                Zeroizing::new(keys.secret_key().to_bech32().unwrap()),
                options(),
            )
            .await
            .is_err()
    );
    assert!(manager.resolve(&id).unwrap().signed_out);
    let mut empty = serde_json::to_value(&c).unwrap();
    empty["snapshot"]["steps"] = serde_json::json!([]);
    empty["records"] = serde_json::json!([]);
    write_cancelled_checkpoint(dir.path(), &id, empty);
    assert!(
        manager
            .begin_onboarding(
                Zeroizing::new(keys.secret_key().to_bech32().unwrap()),
                options(),
            )
            .await
            .is_err()
    );
    let mut order = serde_json::to_value(&c).unwrap();
    order["snapshot"]["steps"][0]["step"] = serde_json::json!("Follows");
    write_cancelled_checkpoint(dir.path(), &id, order);
    assert!(
        manager
            .begin_onboarding(
                Zeroizing::new(keys.secret_key().to_bech32().unwrap()),
                options(),
            )
            .await
            .is_err()
    );
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn cancelled_v1_and_v2_archives_migrate_and_overflow_fails_closed() {
    let (dir, runtime, _network, keys, id) = fixture().await;
    let manager = runtime.accounts();
    let mut c = manager.onboarding_checkpoint(&id).unwrap().unwrap();
    c.snapshot.cancellation_pending = true;
    manager.save_onboarding(&mut c).unwrap();
    manager
        .app
        .account_home()
        .set_account_signed_out(&id, true)
        .unwrap();
    manager
        .app
        .account_home()
        .archive_account_onboarding(&id)
        .unwrap();
    let mut v2 = serde_json::to_value(&c).unwrap();
    v2["version"] = serde_json::json!(2);
    write_cancelled_checkpoint(dir.path(), &id, v2);
    assert!(
        manager
            .begin_onboarding(
                Zeroizing::new(keys.secret_key().to_bech32().unwrap()),
                options(),
            )
            .await
            .is_ok()
    );
    manager.cancel_onboarding(&id).await.unwrap();
    let mut v1 = serde_json::to_value(&c).unwrap();
    v1["version"] = serde_json::json!(1);
    v1["snapshot"]["steps"].as_array_mut().unwrap().remove(4);
    v1["records"].as_array_mut().unwrap().remove(4);
    write_cancelled_checkpoint(dir.path(), &id, v1);
    assert!(
        manager
            .begin_onboarding(
                Zeroizing::new(keys.secret_key().to_bech32().unwrap()),
                options(),
            )
            .await
            .is_ok()
    );
    manager.cancel_onboarding(&id).await.unwrap();
    let mut overflow = serde_json::to_value(&c).unwrap();
    overflow["snapshot"]["revision"] = serde_json::json!(u64::MAX);
    overflow["attempt_start_revision"] = serde_json::json!(u64::MAX);
    overflow["snapshot"]["cancellation_pending"] = serde_json::json!(true);
    write_cancelled_checkpoint(dir.path(), &id, overflow);
    assert!(
        manager
            .begin_onboarding(
                Zeroizing::new(keys.secret_key().to_bech32().unwrap()),
                options(),
            )
            .await
            .is_err()
    );
    assert!(manager.resolve(&id).unwrap().signed_out);
    runtime.shutdown_and_close().await.unwrap();
}
