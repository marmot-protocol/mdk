// Exercise the runtime owner: reservations precede lookup and survive request TTLs.
#[tokio::test]
async fn recovery_batch_keeps_effects() {
    let mut peers = recovery_peers(0).await;
    exchange_recovery(&mut peers).await;
    let before = peers.coordinator.session().epoch(&peers.group).unwrap();
    let connection = rusqlite::Connection::open(peers._dir.path().join("alice.sqlite")).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &connection,
        &SqlCipherKey::new("live recovery cancellation key").unwrap(),
        storage_sqlite::SqlCipherHardening::cipher_only(),
    )
    .unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER fail_recovery_completion BEFORE UPDATE ON cgka_group_rejoin
         WHEN NEW.role = 1 AND json_extract(CAST(NEW.record AS TEXT), '$.record.phase') = 'complete'
         BEGIN SELECT RAISE(ABORT, 'injected recovery completion failure'); END;",
        )
        .unwrap();
    let mut effects = AccountDeviceEffects::default();
    assert!(
        peers
            .coordinator
            .advance_group_recovery(&[], &mut effects)
            .await
            .is_err()
    );
    let after = peers.coordinator.session().epoch(&peers.group).unwrap();
    assert_eq!(after, EpochId(before.0 + 1));
    assert!(
        effects.events.iter().any(|event| matches!(
            event, GroupEvent::EpochChanged { group_id, from, to }
                if group_id == &peers.group && from == &before && to == &after
        )),
        "a confirmed recovery Commit's effects must survive its later journal failure"
    );
}

#[tokio::test]
async fn recovery_welcome_live_retry() {
    let mut peers = recovery_peers(0).await;
    peers.coordinator.run_due_maintenance().await.unwrap();
    exchange_recovery(&mut peers).await;
    let recipient = peers.recipient.self_id();
    peers.adapter.error_for_endpoints(vec![TransportEndpoint(
        "wss://recovery-inbox.example".into(),
    )]);
    peers
        .coordinator
        .advance_group_recovery(&[], &mut AccountDeviceEffects::default())
        .await
        .unwrap();
    let welcome = peers
        .coordinator
        .outstanding_welcome_deliveries()
        .unwrap()
        .into_iter()
        .find(|(_, message)| {
            matches!(
                &message.envelope, TransportEnvelope::Welcome { recipient: target }
                    if target == &recipient
            )
        })
        .unwrap()
        .1;
    let fanout = peers
        .coordinator
        .session()
        .transport_fanout(&welcome.id)
        .unwrap()
        .expect("failed Welcome publication retains its retry attempt");
    peers.adapter.error_for_endpoints(Vec::new());
    peers.wall.set(fanout.bounded_until.unwrap().0);
    peers.coordinator.run_due_maintenance().await.unwrap();
    let attempts = peers
        .adapter
        .publishes()
        .into_iter()
        .filter(|request| request.message.id == welcome.id)
        .collect::<Vec<_>>();
    assert_eq!(
        attempts.len(),
        2,
        "an expired attempt cannot strand an owed recovery Welcome until reopen"
    );
    assert!(attempts.iter().all(|request| request.message == welcome));
    peers
        .recipient
        .ingest_delivery(&recovery_inbox_delivery(recipient, welcome))
        .await
        .unwrap();
    assert!(
        !peers
            .recipient
            .group_record(&peers.group)
            .unwrap()
            .unrecoverable
    );
    assert_recovery_chat(
        &mut peers.coordinator,
        &peers.adapter,
        &mut peers.recipient,
        &peers.group,
    )
    .await;
}

#[tokio::test]
async fn recovery_announced_key() {
    use cgka_traits::app_components::{
        DEVICE_ROSTER_COMPONENT_ID, DeviceEntryV1, DeviceRosterV1, DeviceSlotId,
        NOSTR_ROUTING_COMPONENT_ID, NostrRoutingV1, decode_device_roster_v1,
        encode_device_roster_v1, encode_nostr_routing_v1,
    };

    let mut peers = recovery_peers(0).await;
    let key = SqlCipherKey::new("live recovery cancellation key").unwrap();
    let lifecycle = peers
        .recipient
        .key_package_maintenance_status()
        .unwrap()
        .unwrap();
    drop(peers.recipient);
    let mut components = default_group_components();
    components.extend([DEVICE_ROSTER_COMPONENT_ID, NOSTR_ROUTING_COMPONENT_ID]);
    let mut session = AccountDeviceSession::open(
        SessionConfig::new(
            peers._dir.path().join("bob.sqlite"),
            key,
            pad32(b"cancel-bob"),
            Box::new(nostr_peeler(b"cancel-bob")),
        )
        .account_identity_proof_signer(Arc::new(NostrAccountIdentityProofSigner {
            keys: deterministic_nostr_keys(b"cancel-bob"),
        }))
        .protocol_profile(ProtocolProfile::Current)
        .supported_app_components(components),
    )
    .unwrap();
    let slot = DeviceSlotId::try_from(hex::decode(&lifecycle.stable_slot_id).unwrap()).unwrap();
    let mut roster = DeviceRosterV1 {
        leaf_tag_key: [0x31; 32],
        ..DeviceRosterV1::default()
    };
    roster.devices.insert(
        slot,
        DeviceEntryV1 {
            linked_at: peers.wall.now().0,
            announced_key_package: lifecycle.current_key_package_ref,
            ..DeviceEntryV1::default()
        },
    );
    let created = session
        .create_group(CreateGroupRequest {
            name: "recovery device group".into(),
            description: String::new(),
            members: Vec::new(),
            required_features: Vec::new(),
            app_components: vec![
                AppComponentData {
                    component_id: DEVICE_ROSTER_COMPONENT_ID,
                    data: encode_device_roster_v1(&roster).unwrap(),
                },
                AppComponentData {
                    component_id: NOSTR_ROUTING_COMPONENT_ID,
                    data: encode_nostr_routing_v1(
                        &NostrRoutingV1::new(
                            [0x6b; 32],
                            vec!["wss://recovery-group.example".into()],
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                },
            ],
            initial_admins: Vec::new(),
        })
        .await
        .unwrap();
    match &created.effects.publish[..] {
        [PublishWork::FoundingGroupCreated { .. }] => {}
        [PublishWork::GroupCreated { pending, .. }] => {
            session.confirm_published(*pending).await.unwrap();
        }
        _ => panic!("expected group creation publication"),
    }
    let device_group = created.group_id;
    peers.recipient = AccountDeviceRuntime::new(
        session,
        peers.bob_adapter.clone(),
        StaticTransportRouting::new(vec![TransportEndpoint(
            "wss://recovery-inbox.example".into(),
        )])
        .key_package_endpoints(vec![TransportEndpoint(
            "wss://recovery-inbox.example".into(),
        )])
        .with_group_route(
            peers.group.clone(),
            vec![0x5a; 32],
            vec![TransportEndpoint("wss://recovery-group.example".into())],
        )
        .with_group_route(
            device_group.clone(),
            vec![0x6b; 32],
            vec![TransportEndpoint("wss://recovery-group.example".into())],
        )
        .with_inbox_route(
            peers.coordinator.self_id(),
            vec![TransportEndpoint("wss://recovery-inbox.example".into())],
        ),
        RecordingKeyPackages::default(),
    )
    .with_maintenance_sources(
        peers.wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(0)),
    );
    peers
        .recipient
        .set_key_package_announcement_group(Some(device_group.clone()));
    peers
        .recipient
        .set_device_tag_group(Some(device_group.clone()))
        .unwrap();

    let challenge = issue_recovery_challenge(&mut peers).await;
    peers
        .recipient
        .ingest_delivery(&recovery_inbox_delivery(
            peers.recipient.self_id(),
            challenge,
        ))
        .await
        .unwrap();
    peers.recipient.prepare_group_recovery().unwrap();
    peers
        .recipient
        .advance_group_recovery(
            std::slice::from_ref(&device_group),
            &mut AccountDeviceEffects::default(),
        )
        .await
        .unwrap();
    let waiting = peers
        .recipient
        .key_package_maintenance_status()
        .unwrap()
        .unwrap();
    assert!(
        waiting.pending_replacement.is_none(),
        "a held tag key must prevent staging"
    );
    let store = SqliteAccountStorage::open_encrypted(
        peers._dir.path().join("bob.sqlite"),
        &SqlCipherKey::new("live recovery cancellation key").unwrap(),
    )
    .unwrap();
    let waiting = store
        .list_group_recoveries()
        .unwrap()
        .into_iter()
        .find(|record| {
            record.group_id == peers.group
                && record.role == storage_sqlite::GroupRecoveryRole::Recipient
        })
        .unwrap();
    assert_eq!(waiting.phase, storage_sqlite::GroupRecoveryPhase::Challenge);
    peers.wall.set(waiting.retry_at);
    drop(store);
    peers.recipient.prepare_group_recovery().unwrap();
    peers
        .bob_adapter
        .error_for_endpoints(vec![TransportEndpoint(
            "wss://recovery-inbox.example".into(),
        )]);
    let mut effects = AccountDeviceEffects::default();
    assert!(matches!(
        peers
            .recipient
            .advance_group_recovery(&[], &mut effects)
            .await,
        Err(AccountError::Transport(TransportAdapterError::Publish(_)))
    ));
    let store = SqliteAccountStorage::open_encrypted(
        peers._dir.path().join("bob.sqlite"),
        &SqlCipherKey::new("live recovery cancellation key").unwrap(),
    )
    .unwrap();
    let retained = store
        .list_group_recoveries()
        .unwrap()
        .into_iter()
        .find(|record| {
            record.group_id == peers.group
                && record.role == storage_sqlite::GroupRecoveryRole::Recipient
        })
        .unwrap();
    assert_eq!(retained.phase, storage_sqlite::GroupRecoveryPhase::Grant);
    let retry_at = retained.retry_at;
    let artifact = retained.outbound.unwrap();
    drop(store);
    let grant = recovery_control(b"cancel-alice", &artifact).await;
    let cgka_traits::GroupRecoveryBody::Grant { key_package, .. } = grant.message.body else {
        panic!("the authenticated recipient must advance from Challenge to Grant");
    };
    let metadata = marmot_session::key_package_metadata(&key_package).unwrap();
    let roster = peers
        .recipient
        .session_mut()
        .app_component(&device_group, DEVICE_ROSTER_COMPONENT_ID)
        .unwrap()
        .unwrap();
    let roster = decode_device_roster_v1(&roster).unwrap();
    let entry = roster.devices.get(&slot).unwrap();
    assert_eq!(
        entry.announced_key_package,
        Some(hex::decode(metadata.key_package_ref_hex).unwrap())
    );
    assert_eq!(
        entry.tag_signature_key,
        Some(peers.recipient.own_signature_key())
    );
    assert!(effects.events.iter().any(|event| matches!(event,
        GroupEvent::EpochChanged { group_id, .. } if group_id == &device_group)));
    assert!(
        effects
            .fanout
            .iter()
            .any(|outcome| outcome.mls_confirmed && outcome.fanout_complete)
    );
    peers.bob_adapter.error_for_endpoints(Vec::new());
    peers.wall.set(retry_at);
    peers.recipient.prepare_group_recovery().unwrap();
    peers
        .recipient
        .advance_group_recovery(&[], &mut AccountDeviceEffects::default())
        .await
        .unwrap();
    assert_eq!(
        peers.bob_adapter.publishes().last().unwrap().message,
        artifact
    );
}

#[tokio::test]
async fn rejoin_lower_winning_epoch() {
    let mut peers = recovery_peers(3).await;
    let frozen = peers.recipient.session().epoch(&peers.group).unwrap();
    assert!(frozen > EpochId(peers.before.0 + 1));
    exchange_recovery(&mut peers).await;
    peers
        .coordinator
        .advance_group_recovery(&[], &mut AccountDeviceEffects::default())
        .await
        .unwrap();
    let welcome = peers
        .adapter
        .publishes()
        .into_iter()
        .find(|attempt| is_recovery_welcome(&attempt.message))
        .unwrap()
        .message;
    peers
        .recipient
        .ingest_delivery(&recovery_inbox_delivery(peers.recipient.self_id(), welcome))
        .await
        .unwrap();
    let installed = peers.recipient.group_record(&peers.group).unwrap();
    assert!(!installed.unrecoverable);
    assert!(installed.epoch < frozen);
    assert_eq!(
        installed.epoch,
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

#[tokio::test]
async fn rejoin_live_grant_budget() {
    let mut peers = recovery_peers(0).await;
    exchange_recovery(&mut peers).await;
    let original = recovery_control(
        b"cancel-alice",
        &peers.bob_adapter.publishes().last().unwrap().message,
    )
    .await
    .message;
    let path = peers._dir.path().join("bob.sqlite");
    let key = SqlCipherKey::new("live recovery cancellation key").unwrap();
    drop(peers.recipient);
    {
        let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        let mut row = storage.list_group_recoveries().unwrap().remove(0);
        row.total_attempts = 32;
        storage.put_group_recovery(&row).unwrap();
    }
    peers.recipient = eligibility_runtime(
        nostr_device_session(path, &key, b"cancel-bob"),
        peers.coordinator.self_id(),
        peers.wall.clone(),
        peers.bob_adapter.clone(),
        RecordingKeyPackages::default(),
    );
    assert!(peers.recipient.prepare_group_recovery().unwrap().is_empty());
    assert_eq!(
        peers.recipient.group_rejoin_status(&peers.group).unwrap(),
        marmot_session::GroupRejoinStatus::Pending { attempts: 32 }
    );
    peers.recipient.retry_group_rejoin(&peers.group).unwrap();
    peers.recipient.prepare_group_recovery().unwrap();
    peers
        .recipient
        .advance_group_recovery(&[], &mut AccountDeviceEffects::default())
        .await
        .unwrap();
    let retried = recovery_control(
        b"cancel-alice",
        &peers.bob_adapter.publishes().last().unwrap().message,
    )
    .await
    .message;
    assert_eq!(
        retried, original,
        "retry must retain the live signed grant and selected coordinator"
    );
    peers
        .coordinator
        .advance_group_recovery(&[], &mut AccountDeviceEffects::default())
        .await
        .unwrap();
    let welcome = peers
        .adapter
        .publishes()
        .into_iter()
        .find(|attempt| is_recovery_welcome(&attempt.message))
        .unwrap()
        .message;
    peers
        .recipient
        .ingest_delivery(&recovery_inbox_delivery(peers.recipient.self_id(), welcome))
        .await
        .unwrap();
    assert!(
        !peers
            .recipient
            .group_record(&peers.group)
            .unwrap()
            .unrecoverable
    );
}

#[tokio::test]
async fn rejoin_withdrawn_expiry() {
    use cgka_traits::storage::MessageStorage;
    let mut peers = recovery_peers(0).await;
    let started = peers.wall.now().0;
    exchange_recovery(&mut peers).await;
    peers.wall.set(started + 100);
    peers
        .coordinator
        .advance_group_recovery(&[], &mut AccountDeviceEffects::default())
        .await
        .unwrap();
    let path = peers._dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("live recovery cancellation key").unwrap();
    drop(peers.coordinator);
    {
        let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        let row = storage.list_group_recoveries().unwrap().remove(0);
        storage
            .update_message_state(
                row.commit_id.as_ref().unwrap(),
                cgka_traits::MessageState::ConvergenceDeferred,
            )
            .unwrap();
    }
    peers.coordinator = eligibility_runtime(
        nostr_device_session(path, &key, b"cancel-alice"),
        peers.recipient.self_id(),
        peers.wall.clone(),
        peers.adapter.clone(),
        RecordingKeyPackages::default(),
    );
    peers.wall.set(started + 601);
    assert_eq!(
        peers.coordinator.prepare_group_recovery().unwrap(),
        vec![peers.recipient.self_id()]
    );
    peers
        .coordinator
        .advance_group_recovery(&[], &mut AccountDeviceEffects::default())
        .await
        .unwrap();
    assert!(
        peers
            .coordinator
            .prepare_group_recovery()
            .unwrap()
            .is_empty(),
        "an expired withdrawn publication must become quiescent during its cooldown"
    );
}

#[tokio::test]
async fn rejoin_retry_epoch_poison() {
    let mut peers = recovery_peers(0).await;
    let alice_id = peers.coordinator.self_id();
    let bob_id = peers.recipient.self_id();
    peers.recipient.prepare_group_recovery().unwrap();
    peers
        .recipient
        .advance_group_recovery(&[], &mut AccountDeviceEffects::default())
        .await
        .unwrap();
    let request = peers
        .bob_adapter
        .publishes()
        .last()
        .unwrap()
        .message
        .clone();
    let old_nonce = recovery_control(b"cancel-alice", &request)
        .await
        .message
        .request_id;
    peers
        .coordinator
        .ingest_delivery(&recovery_inbox_delivery(alice_id.clone(), request))
        .await
        .unwrap();
    peers.coordinator.prepare_group_recovery().unwrap();
    peers
        .coordinator
        .advance_group_recovery(&[], &mut AccountDeviceEffects::default())
        .await
        .unwrap();
    let mut poisoned = recovery_control(
        b"cancel-bob",
        &peers.adapter.publishes().last().unwrap().message,
    )
    .await
    .message;
    let cgka_traits::GroupRecoveryBody::Challenge { source } = &mut poisoned.body else {
        panic!("expected selected coordinator Challenge")
    };
    source.epoch = EpochId(u64::MAX);
    // The selected account can authenticate an invented source epoch. The
    // recipient cannot independently attest its remote MLS state.
    let wrapped = nostr_peeler(b"cancel-alice")
        .wrap_group_recovery(&poisoned, &bob_id)
        .await
        .unwrap();
    let accepted = peers
        .recipient
        .ingest_delivery(&recovery_inbox_delivery(bob_id.clone(), wrapped))
        .await
        .unwrap();
    assert!(matches!(
        accepted.outcome,
        cgka_traits::IngestOutcome::GroupRecovery { .. }
    ));
    assert!(!accepted.left_object_unpersisted);

    // Retry while the poisoned grant is live. Preserve its authorization, but
    // do not carry the unverifiable epoch into the next nonce after expiry.
    peers.recipient.prepare_group_recovery().unwrap();
    peers
        .recipient
        .advance_group_recovery(&[], &mut AccountDeviceEffects::default())
        .await
        .unwrap();
    peers.recipient.retry_group_rejoin(&peers.group).unwrap();
    let honest = peers.adapter.publishes().last().unwrap().message.clone();
    let accepted = peers
        .recipient
        .ingest_delivery(&recovery_inbox_delivery(bob_id.clone(), honest))
        .await
        .unwrap();
    assert!(
        matches!(
            accepted.outcome,
            cgka_traits::IngestOutcome::GroupRecovery { .. }
        ) && !accepted.left_object_unpersisted,
        "explicit live-grant retry must immediately release the poisoned epoch floor"
    );
    peers.wall.set(peers.wall.now().0 + 601);
    peers.coordinator.prepare_group_recovery().unwrap();
    exchange_recovery(&mut peers).await;
    let grant = peers
        .bob_adapter
        .publishes()
        .last()
        .unwrap()
        .message
        .clone();
    let authenticated = recovery_control(b"cancel-alice", &grant).await.message;
    assert_ne!(authenticated.request_id, old_nonce);
    assert!(
        matches!(authenticated.body, cgka_traits::GroupRecoveryBody::Grant { source, .. } if source.epoch == peers.before)
    );
    peers
        .coordinator
        .advance_group_recovery(&[], &mut AccountDeviceEffects::default())
        .await
        .unwrap();
    assert!(
        peers.coordinator.group_record(&peers.group).unwrap().epoch > peers.before,
        "the fresh grant must authorize real replacement Commit progress"
    );
}

#[tokio::test]
async fn rejoin_remote_epoch_budget() {
    let mut peers = recovery_peers(0).await;
    let alice_id = peers.coordinator.self_id();
    let bob_id = peers.recipient.self_id();
    exchange_recovery(&mut peers).await;
    let mut challenge = recovery_control(
        b"cancel-bob",
        &peers.adapter.publishes().last().unwrap().message,
    )
    .await
    .message;
    let path = peers._dir.path().join("bob.sqlite");
    let key = SqlCipherKey::new("live recovery cancellation key").unwrap();
    for turn in 1..=64 {
        let cgka_traits::GroupRecoveryBody::Challenge { source } = &mut challenge.body else {
            panic!("expected selected coordinator Challenge")
        };
        source.epoch = EpochId(peers.before.0 + turn);
        let wrapped = nostr_peeler(b"cancel-alice")
            .wrap_group_recovery(&challenge, &bob_id)
            .await
            .unwrap();
        peers
            .recipient
            .ingest_delivery(&recovery_inbox_delivery(bob_id.clone(), wrapped))
            .await
            .unwrap();
        peers.recipient.prepare_group_recovery().unwrap();
        peers
            .recipient
            .advance_group_recovery(&[], &mut AccountDeviceEffects::default())
            .await
            .unwrap();
        if turn == 16 {
            drop(peers.recipient);
            peers.recipient = eligibility_runtime(
                nostr_device_session(path.clone(), &key, b"cancel-bob"),
                alice_id.clone(),
                peers.wall.clone(),
                peers.bob_adapter.clone(),
                RecordingKeyPackages::default(),
            );
            // Expiry and own-account fallback must not replenish the one-shot
            // remote-evidence permission when this selects Alice again.
            for _ in 0..2 {
                peers.wall.set(peers.wall.now().0 + 601);
                let selected = peers.recipient.prepare_group_recovery().unwrap();
                peers
                    .recipient
                    .advance_group_recovery(&[], &mut AccountDeviceEffects::default())
                    .await
                    .unwrap();
                if selected == vec![alice_id.clone()] {
                    let carrier = peers
                        .bob_adapter
                        .publishes()
                        .last()
                        .unwrap()
                        .message
                        .clone();
                    let request = recovery_control(b"cancel-alice", &carrier).await.message;
                    challenge.request_id = request.request_id;
                    challenge.expires_at = request.expires_at;
                    peers
                        .coordinator
                        .ingest_delivery(&recovery_inbox_delivery(alice_id.clone(), carrier))
                        .await
                        .unwrap();
                    peers.coordinator.prepare_group_recovery().unwrap();
                    peers
                        .coordinator
                        .advance_group_recovery(&[], &mut AccountDeviceEffects::default())
                        .await
                        .unwrap();
                    let honest = peers.adapter.publishes().last().unwrap().message.clone();
                    let accepted = peers
                        .recipient
                        .ingest_delivery(&recovery_inbox_delivery(bob_id.clone(), honest))
                        .await
                        .unwrap();
                    assert!(
                        matches!(
                            accepted.outcome,
                            cgka_traits::IngestOutcome::GroupRecovery { .. }
                        ) && !accepted.left_object_unpersisted,
                        "a new nonce must accept the coordinator's lower real source without refilling its budget"
                    );
                    break;
                }
            }
        }
    }
    assert_eq!(
        peers.recipient.group_rejoin_status(&peers.group).unwrap(),
        marmot_session::GroupRejoinStatus::Pending { attempts: 32 }
    );
    assert!(
        peers.bob_adapter.publishes().len() <= 64,
        "successive authenticated epoch claims must not renew the budget indefinitely"
    );
    peers.wall.set(peers.wall.now().0 + 601);
    assert!(peers.recipient.prepare_group_recovery().unwrap().is_empty());
    assert_eq!(
        peers.recipient.group_rejoin_status(&peers.group).unwrap(),
        marmot_session::GroupRejoinStatus::Parked { attempts: 32 }
    );
}

#[tokio::test]
async fn rejoin_commit_cooldown() {
    use sha2::{Digest, Sha256};
    let mut peers = recovery_peers(0).await;
    exchange_recovery(&mut peers).await;
    let grant = recovery_control(
        b"cancel-alice",
        &peers.bob_adapter.publishes().last().unwrap().message,
    )
    .await
    .message;
    let cgka_traits::GroupRecoveryBody::Grant { key_package, .. } = grant.body else {
        panic!("expected grant")
    };
    let metadata = peers.recipient.key_package_metadata(&key_package).unwrap();
    let device_key_hash = Sha256::digest(&metadata.leaf_signature_key).into();
    peers.wall.set(peers.wall.now().0 + 590);
    peers
        .coordinator
        .advance_group_recovery(&[], &mut AccountDeviceEffects::default())
        .await
        .unwrap();
    let now = peers.wall.now().0;
    // A hostile but authenticated account can immediately claim its freshly
    // installed signer is unusable; native recovery must not mint another Commit.
    let request = cgka_traits::GroupRecoveryMessage {
        group_id: peers.group.clone(),
        request_id: [0xd4; 32],
        expires_at: now + 600,
        body: cgka_traits::GroupRecoveryBody::Request { device_key_hash },
    };
    let alice_id = peers.coordinator.self_id();
    let wrapped = nostr_peeler(b"cancel-bob")
        .wrap_group_recovery(&request, &alice_id)
        .await
        .unwrap();
    let result = peers
        .coordinator
        .ingest_delivery(&recovery_inbox_delivery(alice_id.clone(), wrapped))
        .await
        .unwrap();
    assert!(
        matches!(
            result.outcome,
            cgka_traits::IngestOutcome::GroupRecovery { .. }
        ) && result.left_object_unpersisted,
        "a different nonce and fresh device leaf must not bypass per-member Commit cooldown"
    );
    peers.wall.set(now + 11);
    peers.coordinator.prepare_group_recovery().unwrap();
    let key = SqlCipherKey::new("live recovery cancellation key").unwrap();
    let path = peers._dir.path().join("alice.sqlite");
    let bob_id = peers.recipient.self_id();
    drop(peers.coordinator);
    peers.coordinator = eligibility_runtime(
        nostr_device_session(path, &key, b"cancel-alice"),
        bob_id,
        peers.wall.clone(),
        peers.adapter.clone(),
        RecordingKeyPackages::default(),
    );
    let wrapped = nostr_peeler(b"cancel-bob")
        .wrap_group_recovery(&request, &alice_id)
        .await
        .unwrap();
    let retained = peers
        .coordinator
        .ingest_delivery(&recovery_inbox_delivery(alice_id.clone(), wrapped))
        .await
        .unwrap();
    assert!(
        matches!(
            retained.outcome,
            cgka_traits::IngestOutcome::GroupRecovery { .. }
        ) && retained.left_object_unpersisted,
        "completed cooldown must survive request expiry and coordinator reopen"
    );
    peers.wall.set(now + 601);
    peers.coordinator.prepare_group_recovery().unwrap();
    let request = cgka_traits::GroupRecoveryMessage {
        expires_at: now + 1_201,
        ..request
    };
    let wrapped = nostr_peeler(b"cancel-bob")
        .wrap_group_recovery(&request, &alice_id)
        .await
        .unwrap();
    let result = peers
        .coordinator
        .ingest_delivery(&recovery_inbox_delivery(alice_id, wrapped))
        .await
        .unwrap();
    assert!(matches!(
        result.outcome,
        cgka_traits::IngestOutcome::GroupRecovery { .. }
    ));
    assert!(!result.left_object_unpersisted);
}

#[tokio::test]
async fn rejoin_two_admin_accounts() {
    use cgka_traits::storage::GroupStorage;
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("two admin rejoin key").unwrap();
    let bob_path = dir.path().join("bob.sqlite");
    let carol_path = dir.path().join("carol.sqlite");
    let mut bob = Device::open(bob_path.clone(), &key, b"two-bob").await;
    let mut carol = Device::open(carol_path.clone(), &key, b"two-carol").await;
    let mut alice = nostr_device_session(dir.path().join("alice.sqlite"), &key, b"two-alice");
    let alice_id = alice.self_id();
    let carol_id = carol.runtime.self_id();
    let bob_id = bob.runtime.self_id();
    let created = alice
        .create_group(CreateGroupRequest {
            name: "two admin recovery".into(),
            description: String::new(),
            members: vec![bob.key_package.clone(), carol.key_package.clone()],
            required_features: vec![],
            app_components: vec![nostr_routing()],
            initial_admins: vec![alice_id.clone(), carol_id.clone()],
        })
        .await
        .unwrap();
    let group = created.group_id;
    let welcomes = match created.effects.publish.as_slice() {
        [PublishWork::FoundingGroupCreated { welcomes }] => welcomes.clone(),
        [PublishWork::GroupCreated { welcomes, pending }] => {
            alice.confirm_published(*pending).await.unwrap();
            welcomes.clone()
        }
        _ => panic!("expected founding publication"),
    };
    for welcome in &welcomes {
        if matches!(&welcome.envelope, TransportEnvelope::Welcome { recipient } if recipient == &bob_id)
        {
            bob.ingest(welcome).await;
        }
        if matches!(&welcome.envelope, TransportEnvelope::Welcome { recipient } if recipient == &carol_id)
        {
            carol.ingest(welcome).await;
        }
    }
    drop(bob);
    drop(carol);
    {
        let storage = SqliteAccountStorage::open_encrypted(&bob_path, &key).unwrap();
        let mut frozen = storage.get_group(&group).unwrap();
        frozen.unrecoverable = true;
        storage.put_group(&frozen).unwrap();
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let wall = Arc::new(TestWallClock::new(now));
    let alice_adapter = RecordingAdapter::default();
    let carol_adapter = RecordingAdapter::default();
    let bob_adapter = RecordingAdapter::default();
    let mut alice = eligibility_runtime(
        alice,
        bob_id.clone(),
        wall.clone(),
        alice_adapter.clone(),
        RecordingKeyPackages::default(),
    );
    let mut carol = eligibility_runtime(
        nostr_device_session(carol_path, &key, b"two-carol"),
        bob_id.clone(),
        wall.clone(),
        carol_adapter.clone(),
        RecordingKeyPackages::default(),
    );
    let mut routing = StaticTransportRouting::new(vec![])
        .key_package_endpoints(vec![TransportEndpoint("wss://two-keys.example".into())]);
    for peer in [&alice_id, &carol_id, &bob_id] {
        routing = routing.with_inbox_route(
            peer.clone(),
            vec![TransportEndpoint("wss://two-inbox.example".into())],
        );
    }
    let mut bob = AccountDeviceRuntime::new(
        nostr_device_session(bob_path, &key, b"two-bob"),
        bob_adapter.clone(),
        routing,
        RecordingKeyPackages::default(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(0)),
    );
    let selected = bob.prepare_group_recovery().unwrap().remove(0);
    bob.advance_group_recovery(&[], &mut AccountDeviceEffects::default())
        .await
        .unwrap();
    let request = recovery_control(
        if selected == alice_id {
            b"two-alice"
        } else {
            b"two-carol"
        },
        &bob_adapter.publishes().last().unwrap().message,
    )
    .await
    .message;
    for admin in [&mut alice, &mut carol] {
        let carrier = nostr_peeler(b"two-bob")
            .wrap_group_recovery(&request, &admin.self_id())
            .await
            .unwrap();
        admin
            .ingest_delivery(&recovery_inbox_delivery(admin.self_id(), carrier))
            .await
            .unwrap();
        admin.prepare_group_recovery().unwrap();
        admin
            .advance_group_recovery(&[], &mut AccountDeviceEffects::default())
            .await
            .unwrap();
    }
    let (chosen, other) = if selected == alice_id {
        (&alice_adapter, &carol_adapter)
    } else {
        (&carol_adapter, &alice_adapter)
    };
    let rejected = bob
        .ingest_delivery(&recovery_inbox_delivery(
            bob_id.clone(),
            other.publishes().last().unwrap().message.clone(),
        ))
        .await
        .unwrap();
    assert!(matches!(
        rejected.outcome,
        cgka_traits::IngestOutcome::GroupRecovery { .. }
    ));
    assert!(rejected.left_object_unpersisted);
    let accepted = bob
        .ingest_delivery(&recovery_inbox_delivery(
            bob_id,
            chosen.publishes().last().unwrap().message.clone(),
        ))
        .await
        .unwrap();
    assert!(matches!(
        accepted.outcome,
        cgka_traits::IngestOutcome::GroupRecovery { .. }
    ));
    assert!(!accepted.left_object_unpersisted);
    let mut tried = std::collections::HashSet::from([selected]);
    for turn in 1..32 {
        wall.set(now + turn * 601);
        tried.extend(bob.prepare_group_recovery().unwrap());
    }
    assert!(tried.contains(&alice_id) && tried.contains(&carol_id));
    wall.set(now + 32 * 601);
    assert!(
        bob.prepare_group_recovery().unwrap().is_empty(),
        "rotating between distinct admin accounts must not mint new budget"
    );
}

#[tokio::test]
async fn rejoin_unreachable_budget() {
    let mut peers = recovery_peers(0).await;
    assert_eq!(
        peers.coordinator.group_rejoin_status(&peers.group).unwrap(),
        marmot_session::GroupRejoinStatus::Inactive
    );
    let started = peers.wall.now().0;
    for turn in 0..32 {
        peers.wall.set(started + turn * 601);
        assert_eq!(peers.recipient.prepare_group_recovery().unwrap().len(), 1);
        // No directory/network continuation: dropping this reservation still spends it.
    }
    peers.wall.set(started + 32 * 601);
    assert!(
        peers.recipient.prepare_group_recovery().unwrap().is_empty(),
        "unreachable coordinators must exhaust a finite episode across nonce rotation"
    );
    assert_eq!(
        peers.recipient.group_rejoin_status(&peers.group).unwrap(),
        marmot_session::GroupRejoinStatus::Parked { attempts: 32 }
    );
    let bob_path = peers._dir.path().join("bob.sqlite");
    let key = SqlCipherKey::new("live recovery cancellation key").unwrap();
    let alice_id = peers.coordinator.self_id();
    drop(peers.recipient);
    peers.recipient = eligibility_runtime(
        nostr_device_session(bob_path, &key, b"cancel-bob"),
        alice_id,
        peers.wall.clone(),
        peers.bob_adapter.clone(),
        RecordingKeyPackages::default(),
    );
    peers.wall.set(started + 86_400);
    assert!(
        peers.recipient.prepare_group_recovery().unwrap().is_empty(),
        "reopening or waiting cannot silently recreate a parked episode"
    );
    assert_eq!(
        peers.recipient.group_rejoin_status(&peers.group).unwrap(),
        marmot_session::GroupRejoinStatus::Parked { attempts: 32 }
    );
    assert_eq!(
        peers.recipient.retry_group_rejoin(&peers.group).unwrap(),
        marmot_session::GroupRejoinStatus::Pending { attempts: 0 }
    );
    assert_eq!(peers.recipient.prepare_group_recovery().unwrap().len(), 1);
    assert_eq!(
        peers.recipient.group_rejoin_status(&peers.group).unwrap(),
        marmot_session::GroupRejoinStatus::Pending { attempts: 1 }
    );
}

#[tokio::test]
async fn rejoin_removed_budget() {
    let mut peers = recovery_peers(0).await;
    let bob_id = peers.recipient.self_id();
    let alice_id = peers.coordinator.self_id();
    evolve(
        peers.coordinator.session_mut(),
        SendIntent::RemoveMembers {
            group_id: peers.group.clone(),
            members: vec![bob_id.clone()],
        },
    )
    .await;
    let started = peers.wall.now().0;
    for turn in 0..32 {
        peers.wall.set(started + turn * 601);
        let selected = peers.recipient.prepare_group_recovery().unwrap();
        assert_eq!(selected.len(), 1);
        peers
            .recipient
            .advance_group_recovery(&[], &mut AccountDeviceEffects::default())
            .await
            .unwrap();
        if selected[0] == alice_id {
            let request = peers
                .bob_adapter
                .publishes()
                .last()
                .unwrap()
                .message
                .clone();
            let refused = peers
                .coordinator
                .ingest_delivery(&recovery_inbox_delivery(alice_id.clone(), request))
                .await
                .unwrap();
            assert!(matches!(
                refused.outcome,
                cgka_traits::IngestOutcome::GroupRecovery { .. }
            ));
            assert!(refused.left_object_unpersisted);
            assert!(
                peers
                    .coordinator
                    .prepare_group_recovery()
                    .unwrap()
                    .is_empty()
            );
        }
    }
    peers.wall.set(started + 32 * 601);
    assert!(
        peers.recipient.prepare_group_recovery().unwrap().is_empty(),
        "silently refusing current admins cannot keep a removed copy retrying forever"
    );
    assert!(peers.adapter.publishes().is_empty());
    assert!(
        peers
            .recipient
            .group_record(&peers.group)
            .unwrap()
            .unrecoverable
    );
}

#[tokio::test]
async fn rejoin_phase_budget() {
    let mut peers = recovery_peers(0).await;
    let now = peers.wall.now().0;
    let alice_id = peers.coordinator.self_id();
    let bob_id = peers.recipient.self_id();
    peers.recipient.prepare_group_recovery().unwrap();
    peers
        .recipient
        .advance_group_recovery(&[], &mut AccountDeviceEffects::default())
        .await
        .unwrap();
    let request = peers
        .bob_adapter
        .publishes()
        .last()
        .unwrap()
        .message
        .clone();
    peers
        .coordinator
        .ingest_delivery(&recovery_inbox_delivery(alice_id, request))
        .await
        .unwrap();
    peers.coordinator.prepare_group_recovery().unwrap();
    peers
        .coordinator
        .advance_group_recovery(&[], &mut AccountDeviceEffects::default())
        .await
        .unwrap();
    let challenge = peers.adapter.publishes().last().unwrap().message.clone();
    peers
        .recipient
        .ingest_delivery(&recovery_inbox_delivery(bob_id.clone(), challenge.clone()))
        .await
        .unwrap();
    // This fixture's first authenticated Challenge is genuinely one epoch
    // newer; it may rearm once, unlike its expired duplicate deliveries.
    for turn in 1..=32 {
        peers.wall.set(now + turn * 601);
        peers
            .recipient
            .ingest_delivery(&recovery_inbox_delivery(bob_id.clone(), challenge.clone()))
            .await
            .unwrap();
        // Reserve without continuation: source replay must not replenish reservations.
        peers.recipient.prepare_group_recovery().unwrap();
    }
    peers.wall.set(now + 33 * 601);
    assert!(
        peers.recipient.prepare_group_recovery().unwrap().is_empty(),
        "Challenge phase and replay must share the original recipient budget"
    );
}

#[tokio::test]
async fn rejoin_deferred_coordinator() {
    use cgka_traits::app_components::NOSTR_ROUTING_COMPONENT_ID;
    use cgka_traits::error::EngineError;

    let mut peers = recovery_peers(0).await;
    let challenge = issue_recovery_challenge(&mut peers).await;
    let expires_at = recovery_control(b"cancel-bob", &challenge)
        .await
        .message
        .expires_at;
    let alice_id = peers.coordinator.self_id();
    let bob_id = peers.recipient.self_id();
    let key = SqlCipherKey::new("live recovery cancellation key").unwrap();
    let path = peers._dir.path().join("alice.sqlite");
    // The live lease has retry authority regardless of the first backoff delay.
    peers.wall.set(expires_at - 1);
    drop(peers.coordinator);

    let mut components = default_group_components();
    components.insert(NOSTR_ROUTING_COMPONENT_ID);
    let session = AccountDeviceSession::open(
        SessionConfig::new(
            path,
            key,
            pad32(b"cancel-alice"),
            Box::new(nostr_peeler(b"cancel-alice")),
        )
        .account_identity_proof_signer(Arc::new(NostrAccountIdentityProofSigner {
            keys: deterministic_nostr_keys(b"cancel-alice"),
        }))
        .protocol_profile(ProtocolProfile::Current)
        .supported_app_components(components)
        .defer_group_hydration(),
    )
    .unwrap();
    assert!(matches!(
        session.epoch(&peers.group),
        Err(EngineError::GroupNotHydrated(_))
    ));
    peers.coordinator = eligibility_runtime(
        session,
        bob_id.clone(),
        peers.wall.clone(),
        peers.adapter.clone(),
        RecordingKeyPackages::default(),
    );

    assert_eq!(
        peers.coordinator.prepare_group_recovery().unwrap(),
        vec![bob_id.clone()]
    );
    peers
        .coordinator
        .advance_group_recovery(&[], &mut AccountDeviceEffects::default())
        .await
        .unwrap();

    let challenged = peers
        .recipient
        .ingest_delivery(&recovery_inbox_delivery(bob_id, challenge))
        .await
        .unwrap();
    assert!(matches!(
        challenged.outcome,
        cgka_traits::IngestOutcome::GroupRecovery { .. }
    ));
    assert!(!challenged.left_object_unpersisted);
    peers.recipient.prepare_group_recovery().unwrap();
    peers
        .recipient
        .advance_group_recovery(&[], &mut AccountDeviceEffects::default())
        .await
        .unwrap();
    let grant = peers.bob_adapter.publishes().pop().unwrap().message;
    let accepted = peers
        .coordinator
        .ingest_delivery(&recovery_inbox_delivery(alice_id, grant))
        .await
        .unwrap();
    assert!(matches!(
        accepted.outcome,
        cgka_traits::IngestOutcome::GroupRecovery { .. }
    ));
    assert!(!accepted.left_object_unpersisted);
}
