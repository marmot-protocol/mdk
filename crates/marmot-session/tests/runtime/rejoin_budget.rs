// Exercise the runtime owner: reservations precede lookup and survive request TTLs.
#[tokio::test]
async fn rejoin_lower_winning_epoch() {
    let mut peers = recovery_peers(3).await;
    let frozen = peers.recipient.session().epoch(&peers.group).unwrap();
    assert!(frozen > EpochId(peers.before.0 + 1));
    exchange_recovery(&mut peers).await;
    peers.coordinator.advance_group_recovery().await.unwrap();
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
    peers.recipient.advance_group_recovery().await.unwrap();
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
    peers.coordinator.advance_group_recovery().await.unwrap();
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
    peers.coordinator.advance_group_recovery().await.unwrap();
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
    peers.coordinator.advance_group_recovery().await.unwrap();
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
    peers.recipient.advance_group_recovery().await.unwrap();
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
    peers.coordinator.advance_group_recovery().await.unwrap();
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
        cgka_traits::IngestOutcome::Processed
    ));

    // Retry while the poisoned grant is live. Preserve its authorization, but
    // do not carry the unverifiable epoch into the next nonce after expiry.
    peers.recipient.prepare_group_recovery().unwrap();
    peers.recipient.advance_group_recovery().await.unwrap();
    peers.recipient.retry_group_rejoin(&peers.group).unwrap();
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
    peers.coordinator.advance_group_recovery().await.unwrap();
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
        peers.recipient.advance_group_recovery().await.unwrap();
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
                peers.recipient.advance_group_recovery().await.unwrap();
                if selected == vec![alice_id.clone()] {
                    let request = recovery_control(
                        b"cancel-alice",
                        &peers.bob_adapter.publishes().last().unwrap().message,
                    )
                    .await
                    .message;
                    challenge.request_id = request.request_id;
                    challenge.expires_at = request.expires_at;
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
    peers.coordinator.advance_group_recovery().await.unwrap();
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
            cgka_traits::IngestOutcome::Ignored {
                category: cgka_traits::InputRejectionCategory::AuthorizationFailed
            }
        ),
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
            cgka_traits::IngestOutcome::Ignored {
                category: cgka_traits::InputRejectionCategory::AuthorizationFailed
            }
        ),
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
        cgka_traits::IngestOutcome::Processed
    ));
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
    bob.advance_group_recovery().await.unwrap();
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
        admin.advance_group_recovery().await.unwrap();
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
        cgka_traits::IngestOutcome::Ignored {
            category: cgka_traits::InputRejectionCategory::AuthorizationFailed
        }
    ));
    let accepted = bob
        .ingest_delivery(&recovery_inbox_delivery(
            bob_id,
            chosen.publishes().last().unwrap().message.clone(),
        ))
        .await
        .unwrap();
    assert!(matches!(
        accepted.outcome,
        cgka_traits::IngestOutcome::Processed
    ));
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
        peers.recipient.advance_group_recovery().await.unwrap();
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
                cgka_traits::IngestOutcome::Ignored {
                    category: cgka_traits::InputRejectionCategory::AuthorizationFailed
                }
            ));
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
    peers.recipient.advance_group_recovery().await.unwrap();
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
    peers.coordinator.advance_group_recovery().await.unwrap();
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
