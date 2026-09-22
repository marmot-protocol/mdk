use super::*;
use cgka_session::GroupRecoveryError;
use cgka_traits::storage::{GroupStorage, MessageStorage, OutboundFanoutStorage};

#[tokio::test]
async fn recovery_replays_and_reopens() {
    let root = tempfile::tempdir().unwrap();
    let alice_path = root.path().join("alice.sqlite");
    let bob_path = root.path().join("bob.sqlite");
    let key = SqlCipherKey::new("recovery session test").unwrap();
    let options = storage_sqlite::SqliteStorageOptions {
        cipher_compatibility: 3,
        cipher_memory_security: false,
        journal_mode: storage_sqlite::SqliteJournalMode::Delete,
        ..storage_sqlite::SqliteStorageOptions::default()
    };
    let mut alice = AccountDeviceSession::open(config(&alice_path, &key, b"alice")).unwrap();
    let mut bob = AccountDeviceSession::open(
        config(&bob_path, &key, b"bob").storage_options(options.clone()),
    )
    .unwrap();
    let created = alice
        .create_group(CreateGroupRequest {
            name: "recover".into(),
            description: String::new(),
            members: vec![bob.fresh_key_package().await.unwrap()],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcome) = match &created.effects.publish[0] {
        PublishWork::GroupCreated { pending, welcomes } => (*pending, welcomes[0].clone()),
        other => panic!("unexpected creation: {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.ingest(welcome).await.unwrap();
    let group = created.group_id;
    let mut history = Vec::new();
    // This application has already consumed the epoch-1 receive secret when
    // the anchor is captured. Replaying it must use typed duplicate evidence.
    let sent = alice
        .send(SendIntent::AppMessage {
            group_id: group.clone(),
            payload: app_payload_for(&alice, b"already seen"),
            expected_epoch: None,
        })
        .await
        .unwrap();
    let mut known = match &sent.publish[0] {
        PublishWork::ApplicationMessage { msg, .. } => route(msg.clone(), &group),
        other => panic!("unexpected app: {other:?}"),
    };
    known.timestamp = Timestamp(1);
    bob.ingest(known.clone()).await.unwrap();
    history.push(known);
    for epoch in 2..=3 {
        let change = alice
            .send(SendIntent::SelfUpdate {
                group_id: group.clone(),
            })
            .await
            .unwrap();
        let (mut message, pending) = match &change.publish[0] {
            PublishWork::GroupEvolution { msg, pending, .. } => {
                (route(msg.clone(), &group), *pending)
            }
            other => panic!("unexpected update: {other:?}"),
        };
        alice.confirm_published(pending).await.unwrap();
        message.timestamp = Timestamp(epoch);
        if epoch == 2 {
            bob.ingest(message.clone()).await.unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
            while bob.epoch(&group).unwrap().0 < 2 {
                bob.advance_convergence_inputs(&group).await.unwrap();
                assert!(std::time::Instant::now() < deadline);
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }
        history.push(message);
    }
    let commit_only = AccountDeviceSession::prepare_group_recovery(
        config(&bob_path, &key, b"bob").storage_options(options.clone()),
        group.clone(),
        history[1..].to_vec(),
        &root.path().join("commit-only"),
    )
    .await
    .unwrap();
    assert_eq!(commit_only.report().recovered_epoch, 3);
    assert_eq!(commit_only.report().authenticated_deliveries, 0);
    for n in 0..82 {
        let payload = app_payload_for(&alice, format!("missing {n}").as_bytes());
        let sent = alice
            .send(SendIntent::AppMessage {
                group_id: group.clone(),
                payload,
                expected_epoch: None,
            })
            .await
            .unwrap();
        let mut message = match &sent.publish[0] {
            PublishWork::ApplicationMessage { msg, .. } => route(msg.clone(), &group),
            other => panic!("unexpected app: {other:?}"),
        };
        message.timestamp = Timestamp(4 + n);
        history.push(message);
    }
    let own = bob
        .send(SendIntent::AppMessage {
            group_id: group.clone(),
            payload: app_payload_for(&bob, b"sent before recovery"),
            expected_epoch: None,
        })
        .await
        .unwrap();
    let own_message = match &own.publish[0] {
        PublishWork::ApplicationMessage { msg, .. } => route(msg.clone(), &group),
        other => panic!("unexpected own app: {other:?}"),
    };
    history.push(own_message);
    assert!(matches!(
        commit_only.apply_group_recovery(),
        Err(GroupRecoveryError::SourceChanged)
    ));
    let live = SqliteAccountStorage::open_encrypted_with_options(&bob_path, &key, options.clone())
        .unwrap();
    // Model the host having committed the already-visible app projection.
    let prior = live.list_pending_application_events().unwrap();
    let ids = prior
        .iter()
        .filter_map(|e| match e {
            GroupEvent::MessageReceived { message_id, .. } => Some(message_id.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    live.delete_pending_application_events(&ids).unwrap();
    // A frozen ambiguous publication must be resolved by the host first.
    let endpoint = cgka_traits::TransportEndpoint("memory://recovery".into());
    let mut fanout = cgka_traits::OutboundFanout::stage(
        cgka_traits::TransportPublishRequest {
            account_id: bob.self_id(),
            message: history.last().unwrap().clone(),
            target: cgka_traits::TransportPublishTarget::Group {
                group_id: group.clone(),
                transport_group_id: group.as_slice().to_vec(),
                endpoints: vec![endpoint.clone()],
            },
            required_acks: 1,
        },
        None,
        Some(group.clone()),
        0,
    )
    .unwrap();
    fanout.mark_attempt_started_at(0, 0).unwrap();
    fanout
        .record_target_failure(
            0,
            cgka_traits::TransportEndpointFailure {
                endpoint,
                reason: "acknowledgement unknown".into(),
                kind: cgka_traits::TransportEndpointFailureKind::PossiblyExposed,
                rejection_category: None,
            },
        )
        .unwrap();
    live.put_outbound_fanout(&fanout).unwrap();
    let blocked = AccountDeviceSession::prepare_group_recovery(
        config(&bob_path, &key, b"bob").storage_options(options.clone()),
        group.clone(),
        history.clone(),
        &root.path().join("pending"),
    )
    .await;
    assert!(matches!(
        blocked,
        Err(GroupRecoveryError::UnsupportedPublication)
    ));
    assert_eq!(
        live.outbound_fanout(fanout.message_id()).unwrap().unwrap(),
        fanout
    );
    live.delete_outbound_fanout(fanout.message_id()).unwrap();
    let mut conflicting = history.clone();
    let mut collision = history[3].clone();
    collision.payload.push(0);
    conflicting.push(collision);
    let rejected = AccountDeviceSession::prepare_group_recovery(
        config(&bob_path, &key, b"bob").storage_options(options.clone()),
        group.clone(),
        conflicting,
        &root.path().join("conflict"),
    )
    .await;
    assert!(matches!(rejected, Err(GroupRecoveryError::InvalidHistory)));
    assert_eq!(live.get_group(&group).unwrap().epoch, EpochId(2));
    history.push(history[3].clone());
    history.reverse();
    let recovery = AccountDeviceSession::prepare_group_recovery(
        config(&bob_path, &key, b"bob").storage_options(options.clone()),
        group.clone(),
        history.clone(),
        &root.path().join("repair"),
    )
    .await
    .unwrap();
    assert_eq!(recovery.report().original_epoch, 2);
    assert_eq!(recovery.report().recovered_epoch, 3);
    assert_eq!(recovery.report().authenticated_deliveries, 82);
    assert_eq!(live.get_group(&group).unwrap().epoch, EpochId(2));
    drop(bob);
    recovery.apply_group_recovery().unwrap();
    let mut reopened = AccountDeviceSession::open(
        config(&bob_path, &key, b"bob").storage_options(options.clone()),
    )
    .unwrap();
    assert_eq!(reopened.epoch(&group).unwrap(), EpochId(3));
    let deliveries = live.list_pending_application_events().unwrap();
    assert_eq!(
        deliveries
            .iter()
            .filter(|e| matches!(e, GroupEvent::MessageReceived { .. }))
            .count(),
        82
    );
    // The recovered current epoch is safe for a new send, and the peer can
    // authenticate it after the source's prior tip has been left behind.
    let sent = reopened
        .send(SendIntent::AppMessage {
            group_id: group.clone(),
            payload: app_payload_for(&reopened, b"after recovery"),
            expected_epoch: None,
        })
        .await
        .unwrap();
    let message = match &sent.publish[0] {
        PublishWork::ApplicationMessage { msg, .. } => route(msg.clone(), &group),
        other => panic!("unexpected app: {other:?}"),
    };
    let received = alice.ingest(message).await.unwrap();
    assert!(
        received
            .effects
            .events
            .iter()
            .any(|e| matches!(e, GroupEvent::MessageReceived { .. }))
    );
    // Model a prior rollback after a send at epoch 3. Rebuilding epoch 3
    // must not reset its sender ratchet even though the current tip is 2.
    drop(reopened);
    let delivered_ids = deliveries
        .iter()
        .filter_map(|event| match event {
            GroupEvent::MessageReceived { message_id, .. } => Some(message_id.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    live.delete_pending_application_events(&delivered_ids)
        .unwrap();
    live.rollback_group_state_to_snapshot(&group, "openmls-retained-anchor-2")
        .unwrap();
    let repeated = AccountDeviceSession::prepare_group_recovery(
        config(&bob_path, &key, b"bob").storage_options(options.clone()),
        group.clone(),
        history,
        &root.path().join("used-epoch"),
    )
    .await;
    assert!(matches!(repeated, Err(GroupRecoveryError::NoProgress)));
    assert_eq!(live.get_group(&group).unwrap().epoch, EpochId(2));
}

#[tokio::test]
async fn recovery_rejects_bad_input() {
    let root = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("bad input test").unwrap();
    let mut history = Vec::new();
    // Refuse before opening even a nonexistent source database.
    for _ in 0..100_001 {
        history.push(TransportMessage {
            id: MessageId::new(vec![1]),
            payload: vec![],
            timestamp: Timestamp(0),
            causal_deps: vec![],
            source: TransportSource("test".into()),
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: vec![],
            },
        });
    }
    let result = AccountDeviceSession::prepare_group_recovery(
        config(root.path().join("absent.sqlite"), &key, b"bob"),
        GroupId::new(vec![1]),
        history,
        &root.path().join("repair"),
    )
    .await;
    assert!(matches!(result, Err(GroupRecoveryError::InvalidHistory)));
    assert!(!root.path().join("absent.sqlite").exists());
}
