// Recovery eligibility must be checked before account-wide work or public KP rotation.
#[tokio::test]
async fn recovery_control_identity() {
    let mut peers = recovery_peers(0).await;
    let challenge = issue_recovery_challenge(&mut peers).await;
    let expected = recovery_control(b"cancel-bob", &challenge).await;
    let accepted = peers
        .recipient
        .ingest_delivery(&recovery_inbox_delivery(
            peers.recipient.self_id(),
            challenge,
        ))
        .await
        .unwrap();
    assert!(!accepted.left_object_unpersisted);
    let cgka_traits::IngestOutcome::GroupRecovery { recovery } = accepted.outcome else {
        panic!("accepted control must retain its authenticated identity");
    };
    assert_eq!(*recovery, expected);

    let expired = cgka_traits::GroupRecoveryMessage {
        expires_at: peers.wall.now().0,
        ..expected.message
    };
    let carrier = nostr_peeler(b"cancel-alice")
        .wrap_group_recovery(&expired, &peers.recipient.self_id())
        .await
        .unwrap();
    let rejected = peers
        .recipient
        .ingest_delivery(&recovery_inbox_delivery(peers.recipient.self_id(), carrier))
        .await
        .unwrap();
    assert!(rejected.left_object_unpersisted);
    let cgka_traits::IngestOutcome::GroupRecovery { recovery } = rejected.outcome else {
        panic!("rejected control must retain its authenticated identity");
    };
    assert_eq!(recovery.message, expired);
    assert_eq!(recovery.sender, peers.coordinator.self_id());
}

#[tokio::test]
async fn recovery_halted_job_retires() {
    use cgka_traits::GroupStorage;
    use storage_sqlite::{GroupRecoveryPhase, GroupRecoveryRole};

    for phase in [GroupRecoveryPhase::Challenge, GroupRecoveryPhase::Grant] {
        let mut peers = recovery_peers(0).await;
        match phase {
            GroupRecoveryPhase::Challenge => {
                issue_recovery_challenge(&mut peers).await;
                peers.wall.set(peers.wall.now().0 + 5);
                assert_eq!(
                    peers.coordinator.prepare_group_recovery().unwrap(),
                    vec![peers.recipient.self_id()]
                );
            }
            GroupRecoveryPhase::Grant => exchange_recovery(&mut peers).await,
            _ => unreachable!(),
        }
        let published = peers.adapter.publishes().len();
        let key = SqlCipherKey::new("live recovery cancellation key").unwrap();
        let storage =
            SqliteAccountStorage::open_encrypted(peers._dir.path().join("alice.sqlite"), &key)
                .unwrap();
        // Model a durable halt discovered after reservation, before the owner
        // advances. The real engine must refuse both source refresh and staging.
        let mut halted = storage.get_group(&peers.group).unwrap();
        halted.unrecoverable = true;
        storage.put_group(&halted).unwrap();
        let request_id = storage
            .list_group_recoveries()
            .unwrap()
            .into_iter()
            .find(|record| record.role == GroupRecoveryRole::Coordinator)
            .unwrap()
            .request_id;
        peers
            .coordinator
            .advance_group_recovery(&[], &mut AccountDeviceEffects::default())
            .await
            .unwrap();
        assert_eq!(peers.adapter.publishes().len(), published);
        let retired = storage
            .group_recovery(&peers.group, GroupRecoveryRole::Coordinator, &request_id)
            .unwrap()
            .unwrap();
        assert_eq!(retired.phase, GroupRecoveryPhase::Complete);
        assert!(retired.commit_id.is_none());
        assert_eq!(storage.get_group(&peers.group).unwrap(), halted);
        peers.wall.set(peers.wall.now().0 + 120);
        assert!(
            !peers
                .coordinator
                .prepare_group_recovery()
                .unwrap()
                .contains(&peers.recipient.self_id()),
            "halted coordinator must not reserve the retired peer again"
        );
    }
}

fn eligibility_legacy_session(
    path: impl Into<std::path::PathBuf>,
    key: &SqlCipherKey,
    account: &[u8],
) -> AccountDeviceSession {
    use cgka_traits::app_components::NOSTR_ROUTING_COMPONENT_ID;
    let mut components = default_group_components();
    components.insert(NOSTR_ROUTING_COMPONENT_ID);
    AccountDeviceSession::open(
        SessionConfig::new(
            path,
            SqlCipherKey::new(key.as_secret_str()).unwrap(),
            pad32(account),
            Box::new(nostr_peeler(account)),
        )
        .legacy_compatibility_profile()
        .account_identity_proof_signer(Arc::new(NostrAccountIdentityProofSigner {
            keys: deterministic_nostr_keys(account),
        }))
        .supported_app_components(components),
    )
    .unwrap()
}

fn eligibility_runtime(
    session: AccountDeviceSession,
    peer: MemberId,
    wall: Arc<TestWallClock>,
    adapter: RecordingAdapter,
    publisher: RecordingKeyPackages,
) -> RecoveryRuntime {
    let endpoint = TransportEndpoint("wss://eligibility-inbox.example".into());
    let self_id = session.self_id();
    AccountDeviceRuntime::new(
        session,
        adapter,
        StaticTransportRouting::new(vec![endpoint.clone()])
            .key_package_endpoints(vec![endpoint.clone()])
            .with_inbox_route(peer, vec![endpoint.clone()])
            .with_inbox_route(self_id, vec![endpoint]),
        publisher,
    )
    .with_maintenance_sources(
        wall,
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(0)),
    )
}

#[tokio::test]
async fn recovery_legacy_no_rotation() {
    use cgka_traits::GroupStorage;

    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("recovery profile eligibility key").unwrap();
    let bob_path = dir.path().join("bob.sqlite");
    let mut bob = Device::with_session(
        eligibility_legacy_session(&bob_path, &key, b"eligibility-bob"),
        cgka_traits::engine::KeyPackage::new(Vec::new()),
    );
    bob.publish().await;
    let bob_id = bob.runtime.self_id();
    let mut alice =
        eligibility_legacy_session(dir.path().join("alice.sqlite"), &key, b"eligibility-alice");
    let alice_id = alice.self_id();
    let (group, welcomes) = create_group(&mut alice, &[&bob.key_package], "legacy recovery").await;
    bob.ingest(&welcomes[0]).await;
    drop(bob);
    {
        let storage = SqliteAccountStorage::open_encrypted(&bob_path, &key).unwrap();
        let mut record = storage.get_group(&group).unwrap();
        record.unrecoverable = true;
        storage.put_group(&record).unwrap();
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let wall = Arc::new(TestWallClock::new(now));
    let adapter = RecordingAdapter::default();
    let bob_adapter = RecordingAdapter::default();
    let mut coordinator = eligibility_runtime(
        alice,
        bob_id.clone(),
        wall.clone(),
        adapter.clone(),
        RecordingKeyPackages::default(),
    );
    let mut recipient = eligibility_runtime(
        eligibility_legacy_session(&bob_path, &key, b"eligibility-bob"),
        alice_id.clone(),
        wall.clone(),
        bob_adapter.clone(),
        RecordingKeyPackages::default(),
    );
    // Persist a real challenged Legacy job before the host upgrades its generator.
    assert_eq!(
        recipient.prepare_group_recovery().unwrap(),
        vec![alice_id.clone()]
    );
    recipient
        .advance_group_recovery(&[], &mut AccountDeviceEffects::default())
        .await
        .unwrap();
    coordinator
        .ingest_delivery(&recovery_inbox_delivery(
            alice_id.clone(),
            bob_adapter.publishes().last().unwrap().message.clone(),
        ))
        .await
        .unwrap();
    coordinator.prepare_group_recovery().unwrap();
    coordinator
        .advance_group_recovery(&[], &mut AccountDeviceEffects::default())
        .await
        .unwrap();
    let challenged = recipient
        .ingest_delivery(&recovery_inbox_delivery(
            bob_id,
            adapter.publishes().last().unwrap().message.clone(),
        ))
        .await
        .unwrap();
    assert!(matches!(
        challenged.outcome,
        cgka_traits::IngestOutcome::GroupRecovery { .. }
    ));
    assert!(!challenged.left_object_unpersisted);
    drop(recipient);

    let publisher = RecordingKeyPackages::default();
    let adapter = RecordingAdapter::default();
    let mut recipient = eligibility_runtime(
        nostr_device_session(&bob_path, &key, b"eligibility-bob"),
        alice_id,
        wall.clone(),
        adapter.clone(),
        publisher.clone(),
    );
    assert_eq!(
        recipient.session().new_protocol_profile(),
        ProtocolProfile::Current
    );
    let stored = recipient.group_record(&group).unwrap();
    assert_eq!(stored.protocol_profile, ProtocolProfile::Legacy);
    assert!(stored.unrecoverable);
    assert!(matches!(
        recipient.epoch_state(&group),
        Some(cgka_traits::EpochState::Unrecoverable { .. })
    ));
    let keys_before = recipient.key_package_maintenance_status().unwrap();
    // Exercise both the existing challenge and repeated retry/expiry windows.
    for elapsed in [0, 5, 20, 600, 1_200, 2_400] {
        wall.set(now + elapsed);
        recipient.prepare_group_recovery().unwrap();
        let result = recipient
            .advance_group_recovery(&[], &mut AccountDeviceEffects::default())
            .await;
        assert!(
            publisher.publications().is_empty(),
            "incompatible recovery must not publish a fresh KeyPackage"
        );
        assert!(
            adapter.publishes().is_empty(),
            "incompatible recovery must not send account controls"
        );
        result.unwrap();
        assert_eq!(
            recipient.key_package_maintenance_status().unwrap(),
            keys_before
        );
    }
    assert_eq!(recipient.group_record(&group).unwrap(), stored);
}

#[tokio::test]
async fn recovery_quarantine_isolated() {
    use cgka_traits::GroupStorage;
    use storage_sqlite::{GroupRecoveryPhase, GroupRecoveryRecord, GroupRecoveryRole};

    let mut peers = recovery_peers(0).await;
    let bob_path = peers._dir.path().join("bob.sqlite");
    let key = SqlCipherKey::new("live recovery cancellation key").unwrap();
    let alice_id = peers.coordinator.self_id();
    let bob_id = peers.recipient.self_id();
    let good_before = peers.recipient.group_record(&peers.group).unwrap();
    drop(peers.recipient);
    let orphan = GroupId::new(b"orphaned-recovery-group".to_vec());
    let now = peers.wall.now().0;
    {
        let storage = SqliteAccountStorage::open_encrypted(&bob_path, &key).unwrap();
        // Clone only public metadata, never native MLS state. The good group remains intact.
        let mut broken = storage.get_group(&peers.group).unwrap();
        broken.id = orphan.clone();
        storage.put_group(&broken).unwrap();
        storage
            .put_group_recovery(&GroupRecoveryRecord {
                group_id: orphan.clone(),
                request_id: [0x71; 32],
                role: GroupRecoveryRole::Recipient,
                peer: alice_id.clone(),
                leaf_index: 0,
                local_state_token: Some([0x72; 32]),
                expires_at: now + 600,
                retry_at: now.saturating_sub(1),
                attempts: 0,
                phase: GroupRecoveryPhase::Request,
                total_attempts: 0,
                candidate_set_hash: None,
                native_epoch: None,
                observed_epoch: None,
                remote_rearmed: false,
                commit_started_at: None,
                message: cgka_traits::GroupRecoveryMessage {
                    group_id: orphan.clone(),
                    request_id: [0x71; 32],
                    expires_at: now + 600,
                    body: cgka_traits::GroupRecoveryBody::Request {
                        device_key_hash: [0x73; 32],
                    },
                },
                outbound: None,
                commit_id: None,
            })
            .unwrap();
    }
    peers.recipient = eligibility_runtime(
        nostr_device_session(&bob_path, &key, b"cancel-bob"),
        alice_id.clone(),
        peers.wall.clone(),
        peers.bob_adapter.clone(),
        RecordingKeyPackages::default(),
    );
    assert!(
        peers
            .recipient
            .quarantined_groups()
            .iter()
            .any(|(id, _)| id == &orphan)
    );
    assert_eq!(
        peers.recipient.group_record(&peers.group).unwrap(),
        good_before
    );
    // The older orphan may consume a reservation, but cannot abort this or the next turn.
    for _ in 0..2 {
        peers.recipient.prepare_group_recovery().unwrap();
        peers
            .recipient
            .advance_group_recovery(&[], &mut AccountDeviceEffects::default())
            .await
            .unwrap();
    }
    let controls = peers.bob_adapter.publishes();
    assert_eq!(
        controls.len(),
        1,
        "only the eligible group's request is published"
    );
    let authenticated = recovery_control(b"cancel-alice", &controls[0].message).await;
    assert_eq!(authenticated.message.group_id, peers.group);
    let received = peers
        .coordinator
        .ingest_delivery(&recovery_inbox_delivery(
            alice_id,
            controls[0].message.clone(),
        ))
        .await
        .unwrap();
    assert!(matches!(
        received.outcome,
        cgka_traits::IngestOutcome::GroupRecovery { .. }
    ));
    assert!(!received.left_object_unpersisted);
    peers.coordinator.prepare_group_recovery().unwrap();
    peers
        .coordinator
        .advance_group_recovery(&[], &mut AccountDeviceEffects::default())
        .await
        .unwrap();
    let challenge = peers.adapter.publishes().last().unwrap().message.clone();
    let received = peers
        .recipient
        .ingest_delivery(&recovery_inbox_delivery(bob_id, challenge))
        .await
        .unwrap();
    assert!(matches!(
        received.outcome,
        cgka_traits::IngestOutcome::GroupRecovery { .. }
    ));
    assert!(!received.left_object_unpersisted);
    peers.recipient.prepare_group_recovery().unwrap();
    peers
        .recipient
        .advance_group_recovery(&[], &mut AccountDeviceEffects::default())
        .await
        .unwrap();
    assert_eq!(
        peers.bob_adapter.publishes().len(),
        2,
        "the eligible recipient progresses to a signed grant"
    );
    assert_eq!(
        peers.recipient.group_record(&peers.group).unwrap(),
        good_before
    );
}

#[tokio::test]
async fn recovery_same_device_refresh() {
    use cgka_traits::GroupRecoveryBody;

    let mut peers = recovery_peers(0).await;
    exchange_recovery(&mut peers).await;
    let original = recovery_control(
        b"cancel-bob",
        &peers.adapter.publishes().last().unwrap().message,
    )
    .await;
    let GroupRecoveryBody::Challenge { source: old_source } = original.message.body else {
        panic!("expected the initial coordinator challenge");
    };
    // Advance real native state after the first Grant was reserved, without
    // delivering that unrelated Commit to the Unrecoverable recipient.
    peers
        .coordinator
        .send(SendIntent::SelfUpdate {
            group_id: peers.group.clone(),
        })
        .await
        .unwrap();
    let advanced_epoch = peers.coordinator.session().epoch(&peers.group).unwrap();
    assert!(advanced_epoch > old_source.epoch);
    peers
        .coordinator
        .advance_group_recovery(&[], &mut AccountDeviceEffects::default())
        .await
        .unwrap();
    peers.wall.set(peers.wall.now().0 + 5);
    assert_eq!(
        peers.coordinator.prepare_group_recovery().unwrap(),
        vec![peers.recipient.self_id()]
    );
    peers
        .coordinator
        .advance_group_recovery(&[], &mut AccountDeviceEffects::default())
        .await
        .unwrap();
    let refreshed = peers.adapter.publishes().last().unwrap().message.clone();
    let authenticated = recovery_control(b"cancel-bob", &refreshed).await;
    let GroupRecoveryBody::Challenge { source } = &authenticated.message.body else {
        panic!("stale Grant must produce a new native-source challenge");
    };
    assert_eq!(
        authenticated.message.request_id,
        original.message.request_id
    );
    assert_eq!(source.coordinator_key_hash, old_source.coordinator_key_hash);
    assert_eq!(source.epoch, advanced_epoch);
    assert_ne!(
        source.epoch_authenticator_hash,
        old_source.epoch_authenticator_hash
    );
    let bob_id = peers.recipient.self_id();
    let accepted = peers
        .recipient
        .ingest_delivery(&recovery_inbox_delivery(bob_id.clone(), refreshed))
        .await
        .unwrap();
    assert!(matches!(
        accepted.outcome,
        cgka_traits::IngestOutcome::GroupRecovery { .. }
    ));
    assert!(!accepted.left_object_unpersisted);
    peers.recipient.prepare_group_recovery().unwrap();
    peers
        .recipient
        .advance_group_recovery(&[], &mut AccountDeviceEffects::default())
        .await
        .unwrap();
    let grant = peers
        .bob_adapter
        .publishes()
        .last()
        .unwrap()
        .message
        .clone();
    let accepted = peers
        .coordinator
        .ingest_delivery(&recovery_inbox_delivery(peers.coordinator.self_id(), grant))
        .await
        .unwrap();
    assert!(matches!(
        accepted.outcome,
        cgka_traits::IngestOutcome::GroupRecovery { .. }
    ));
    assert!(!accepted.left_object_unpersisted);
    peers.coordinator.prepare_group_recovery().unwrap();
    peers
        .coordinator
        .advance_group_recovery(&[], &mut AccountDeviceEffects::default())
        .await
        .unwrap();
    let welcome = peers
        .adapter
        .publishes()
        .into_iter()
        .rfind(|attempt| matches!(attempt.message.envelope, TransportEnvelope::Welcome { .. }))
        .unwrap()
        .message;
    peers
        .recipient
        .ingest_delivery(&recovery_inbox_delivery(bob_id, welcome))
        .await
        .unwrap();
    assert!(
        !peers
            .recipient
            .group_record(&peers.group)
            .unwrap()
            .unrecoverable
    );
    assert_eq!(
        peers.recipient.session().epoch(&peers.group).unwrap(),
        peers.coordinator.session().epoch(&peers.group).unwrap()
    );
    assert_recovery_chat(
        &mut peers.coordinator,
        &peers.adapter,
        &mut peers.recipient,
        &peers.group,
    )
    .await;
}
