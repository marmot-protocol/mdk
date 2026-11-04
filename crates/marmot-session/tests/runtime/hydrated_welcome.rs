// Native preparation deliberately stops before transport publication, then reopens
// the encrypted account as the runtime's first user operation.
#[derive(Clone, Copy)]
enum RecoveryFixtureMode {
    Staged,
    Confirmed,
    Superseded,
    Terminal,
}

async fn hydrated_recovery_fixture(
    mode: RecoveryFixtureMode,
) -> (
    tempfile::TempDir,
    AccountDeviceSession,
    GroupId,
    GroupId,
    TransportMessage,
) {
    use cgka_engine::EngineBuilder;
    use cgka_traits::StorageProvider;
    use cgka_traits::engine::{CgkaEngine, SendResult};
    use cgka_traits::group_recovery::{GroupMemberRecovery, group_recovery_grant_bytes};
    use cgka_traits::storage::AccountDeviceSignerStorage;
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_traits::signatures::Signer as _;

    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("hydrated welcome ownership key").unwrap();
    let build = |name: &[u8], storage: SqliteAccountStorage| {
        EngineBuilder::new(storage)
            .identity(pad32(name))
            .account_identity_proof_signer(Arc::new(NostrAccountIdentityProofSigner {
                keys: deterministic_nostr_keys(name),
            }))
            .peeler(Box::new(MockPeeler))
            .build()
            .unwrap()
    };
    let path = dir.path().join("alice.sqlite");
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let target_storage =
        SqliteAccountStorage::open_encrypted(dir.path().join("bob.sqlite"), &key).unwrap();
    let mut alice = build(b"hydrated-alice", storage.clone());
    let mut bob = build(b"hydrated-bob", target_storage.clone());
    let request = |name: &str, members| CreateGroupRequest {
        name: name.into(),
        description: String::new(),
        members,
        required_features: vec![],
        app_components: vec![],
        initial_admins: vec![],
    };
    let (a, _) = alice.create_group(request("A", vec![])).await.unwrap();
    let (b, created) = alice
        .create_group(request("B", vec![bob.fresh_key_package().await.unwrap()]))
        .await
        .unwrap();
    let SendResult::FoundingGroupCreated { mut welcomes } = created else {
        panic!("founding group")
    };
    let founding = welcomes.remove(0);
    bob.join_welcome(founding.clone()).await.unwrap();
    alice.mark_sent_welcome_delivered(&founding.id).unwrap();
    let source = alice
        .group_recovery_source(&b, &bob.self_id(), &bob.own_recovery_key_hash(&b).unwrap())
        .unwrap();
    let mut grant = GroupMemberRecovery {
        member: bob.self_id(),
        source,
        key_package: bob.fresh_key_package().await.unwrap(),
        request_id: [87; 32],
        expires_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600,
        device_signature: vec![],
    };
    let binding = target_storage
        .account_device_signer(&grant.member)
        .unwrap()
        .unwrap();
    let signer = SignatureKeyPair::read(
        target_storage.mls_storage(),
        &binding.mls_signature_public_key,
        cgka_engine::DEFAULT_CIPHERSUITE.signature_algorithm(),
    )
    .unwrap();
    grant.device_signature = signer
        .sign(
            &group_recovery_grant_bytes(
                &b,
                &alice.self_id(),
                &grant.request_id,
                grant.expires_at,
                &grant.source,
                &grant.key_package,
            )
            .unwrap(),
        )
        .unwrap();
    let SendResult::GroupEvolution {
        mut welcomes,
        pending,
        msg,
    } = alice
        .send(SendIntent::RecoverMembers {
            group_id: b.clone(),
            members: vec![grant],
        })
        .await
        .unwrap()
    else {
        panic!("native recovery")
    };
    let welcome = welcomes.remove(0);
    if !matches!(mode, RecoveryFixtureMode::Staged) {
        alice.confirm_published(pending).await.unwrap();
        assert!(
            alice
                .outstanding_sent_welcomes()
                .unwrap()
                .iter()
                .any(|(_, owed)| owed.id == welcome.id)
        );
        drop(alice);
        // A real failed delivery owns a durable retry before the fork. It must
        // not publish later merely because it retained the exact old bytes.
        let adapter = RecordingAdapter::default();
        adapter.accept_only_endpoints(vec![]);
        let mut runtime = AccountDeviceRuntime::new(
            current_session(&path, &key, b"hydrated-alice"),
            adapter,
            StaticTransportRouting::new(vec![]).with_inbox_route(
                bob.self_id(),
                vec![TransportEndpoint("wss://recovery-inbox.example".into())],
            ),
            RecordingKeyPackages::default(),
        );
        runtime
            .publish_welcome_messages_with_audit_context(
                vec![welcome.clone()],
                Some(b.clone()),
                Default::default(),
            )
            .await
            .unwrap();
        assert!(
            runtime
                .session()
                .transport_fanout(&welcome.id)
                .unwrap()
                .is_some()
        );
        drop(runtime);
        alice = build(b"hydrated-alice", storage.clone());
        alice.hydrate_all_stored_groups().unwrap();
    }
    if matches!(
        mode,
        RecoveryFixtureMode::Superseded | RecoveryFixtureMode::Terminal
    ) {
        use cgka_traits::MessageStorage;
        // Bob never saw the recovery Commit. His longer authenticated branch
        // wins even though the recovery is an admin Commit.
        let rounds = match mode {
            RecoveryFixtureMode::Terminal => 2 + cgka_engine::convergence::V1_MAX_REWIND_COMMITS,
            _ => 2,
        };
        for _ in 0..rounds {
            let SendResult::GroupEvolution {
                msg: rival,
                pending,
                ..
            } = bob
                .send(SendIntent::SelfUpdate {
                    group_id: b.clone(),
                })
                .await
                .unwrap()
            else {
                panic!("rival self-update")
            };
            bob.confirm_published(pending).await.unwrap();
            alice
                .buffer_openmls_convergence_message_at(&b, rival, 500)
                .unwrap();
            let selected = alice
                .converge_stored_openmls_messages_at(&b, 1_000_000)
                .unwrap();
            assert_eq!(
                selected.convergence_status,
                cgka_engine::canonicalization::ConvergenceStatus::Settled
            );
        }
        assert_eq!(alice.epoch(&b).unwrap(), bob.epoch(&b).unwrap());
        // This peeler's transport id differs from its MLS content digest.
        // Own confirmation and convergence update the returned exact id.
        let commit = storage.get_message(&msg.id).unwrap();
        let expected = match mode {
            RecoveryFixtureMode::Terminal => cgka_traits::MessageState::EpochInvalidated,
            _ => cgka_traits::MessageState::ConvergenceDeferred,
        };
        assert_eq!(
            commit.state, expected,
            "the native branch must reach the requested loss boundary"
        );
        // Drop the native event queue rather than synthesizing a withdrawal:
        // session reopen must derive the Welcome's eligibility from storage.
    }
    drop(alice);
    drop(bob);
    drop(storage);
    drop(target_storage);
    let reopened = current_session(&path, &key, b"hydrated-alice");
    (dir, reopened, a, b, welcome)
}

#[tokio::test]
async fn hydrated_welcome_stays_owned() {
    let (_dir, session, a, b, welcome) =
        hydrated_recovery_fixture(RecoveryFixtureMode::Staged).await;
    let adapter = RecordingAdapter::default();
    let a_endpoint = TransportEndpoint("wss://hydrated-a.example".into());
    let b_endpoint = TransportEndpoint("wss://hydrated-b.example".into());
    adapter.accept_only_endpoints(vec![a_endpoint.clone()]);
    let mut runtime = AccountDeviceRuntime::new(
        session,
        adapter.clone(),
        StaticTransportRouting::new(vec![])
            .with_group_route(a.clone(), a.as_slice().to_vec(), vec![a_endpoint])
            .with_group_route(b.clone(), b.as_slice().to_vec(), vec![b_endpoint]),
        RecordingKeyPackages::default(),
    );
    let before_a = runtime.session().epoch(&a).unwrap();
    let before_b = runtime.session().epoch(&b).unwrap();
    let (effects, returned) = runtime
        .send_confirming_commit_with_audit_context(
            SendIntent::SelfUpdate {
                group_id: a.clone(),
            },
            Default::default(),
        )
        .await
        .unwrap();
    assert!(
        returned.is_empty(),
        "B's Welcome must not escape as A's deferred fanout"
    );
    assert_eq!(runtime.session().epoch(&a).unwrap().0, before_a.0 + 1);
    assert!(
        effects
            .pending
            .iter()
            .any(|resolution| matches!(resolution, PendingResolution::Confirmed { .. }))
    );
    assert!(
        effects
            .pending
            .iter()
            .any(|resolution| matches!(resolution, PendingResolution::RolledBack { .. }))
    );
    assert_eq!(runtime.session().epoch(&b).unwrap().0 + 1, before_b.0);
    assert!(
        !adapter
            .publishes()
            .iter()
            .any(|request| request.message.id == welcome.id)
    );
    assert!(
        runtime
            .session()
            .outstanding_sent_welcomes()
            .unwrap()
            .iter()
            .all(|(_, message)| message.id != welcome.id)
    );
}

#[tokio::test]
async fn lost_recovery_hides_welcome() {
    for mode in [
        RecoveryFixtureMode::Superseded,
        RecoveryFixtureMode::Terminal,
    ] {
        let (_dir, session, _a, b, welcome) = hydrated_recovery_fixture(mode).await;
        let adapter = RecordingAdapter::default();
        let wall = Arc::new(TestWallClock::new(unix_now()));
        let mut runtime = AccountDeviceRuntime::new(
            session,
            adapter.clone(),
            StaticTransportRouting::new(vec![])
                .with_inbox_route(
                    MemberId::new(pad32(b"hydrated-bob")),
                    vec![TransportEndpoint("wss://recovery-inbox.example".into())],
                )
                .with_group_route(
                    b.clone(),
                    b.as_slice().to_vec(),
                    vec![TransportEndpoint("wss://recovery-group.example".into())],
                ),
            RecordingKeyPackages::default(),
        )
        .with_maintenance_sources(
            wall.clone(),
            Arc::new(TestMonotonicClock::default()),
            Arc::new(TestRandom::new(0)),
        );
        // Both exact stale continuations and state-derived automatic delivery must
        // refuse a Welcome whose confirmed recovery lost while it was still owed.
        runtime
            .publish_welcome_messages_with_audit_context(
                vec![welcome.clone()],
                Some(b),
                Default::default(),
            )
            .await
            .unwrap();
        runtime
            .retry_welcome_messages_with_audit_context(vec![welcome.clone()], Default::default())
            .await
            .unwrap();
        wall.set(wall.now().0 + 100);
        runtime.run_due_maintenance().await.unwrap();
        assert!(
            !adapter
                .publishes()
                .iter()
                .any(|request| request.message.id == welcome.id),
            "a losing recovery's owed Welcome must never reach transport after reopen"
        );
        assert!(
            runtime
                .session()
                .outstanding_sent_welcomes()
                .unwrap()
                .iter()
                .all(|(_, owed)| owed.id != welcome.id),
            "a losing recovery's Welcome must not escape through the owed-work index"
        );
        match mode {
            RecoveryFixtureMode::Terminal => assert!(
                runtime
                    .session()
                    .transport_fanout(&welcome.id)
                    .unwrap()
                    .is_none(),
                "terminal loss retires the undelivered retry"
            ),
            _ => assert!(
                runtime
                    .session()
                    .transport_fanout(&welcome.id)
                    .unwrap()
                    .is_some(),
                "a parked branch retains its retry owner across reopen and maintenance"
            ),
        }
        assert!(
            runtime
                .prepare_welcome_retry_task_with_audit_context(vec![welcome], Default::default())
                .unwrap()
                .message_ids()
                .is_empty()
        );
    }
}

#[tokio::test]
async fn recovery_welcome_reopens() {
    let (_dir, session, _a, _b, welcome) =
        hydrated_recovery_fixture(RecoveryFixtureMode::Confirmed).await;
    let adapter = RecordingAdapter::default();
    let mut runtime = AccountDeviceRuntime::new(
        session,
        adapter.clone(),
        StaticTransportRouting::new(vec![]).with_inbox_route(
            MemberId::new(pad32(b"hydrated-bob")),
            vec![TransportEndpoint("wss://recovery-inbox.example".into())],
        ),
        RecordingKeyPackages::default(),
    );
    assert!(
        runtime
            .session()
            .outstanding_sent_welcomes()
            .unwrap()
            .iter()
            .any(|(_, owed)| owed.id == welcome.id)
    );
    // Explicit redelivery bypasses automatic backoff but still requires the
    // native origin guard. Its successful ACK alone settles this Welcome.
    let delivered = runtime.redeliver_welcome(&welcome.id).await.unwrap();
    assert!(delivered.welcome_failures.is_empty());
    assert_eq!(
        adapter
            .publishes()
            .iter()
            .filter(|request| request.message.id == welcome.id)
            .count(),
        1
    );
    assert!(
        runtime
            .session()
            .outstanding_sent_welcomes()
            .unwrap()
            .iter()
            .all(|(_, owed)| owed.id != welcome.id)
    );
}
