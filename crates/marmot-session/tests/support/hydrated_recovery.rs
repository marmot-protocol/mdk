// Native preparation deliberately stops before transport publication, then reopens
// the encrypted account as the runtime's first user operation.
#[derive(Clone, Copy)]
enum RecoveryFixtureMode {
    Staged,
    Prepared,
    Confirmed,
    Superseded,
    Terminal,
    #[cfg_attr(not(feature = "test-policy-overrides"), allow(dead_code))]
    Queued,
}

async fn recovery_grant(
    admin: &cgka_engine::Engine<SqliteAccountStorage>,
    target: &mut cgka_engine::Engine<SqliteAccountStorage>,
    storage: &SqliteAccountStorage,
    group: &GroupId,
    request: u8,
) -> cgka_traits::group_recovery::GroupMemberRecovery {
    use cgka_traits::StorageProvider;
    use cgka_traits::engine::CgkaEngine as _;
    use cgka_traits::group_recovery::group_recovery_grant_bytes;
    use cgka_traits::storage::AccountDeviceSignerStorage;
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_traits::signatures::Signer as _;

    let source = admin
        .group_recovery_source(
            group,
            &target.self_id(),
            &target.own_recovery_key_hash(group).unwrap(),
        )
        .unwrap();
    let mut grant = cgka_traits::group_recovery::GroupMemberRecovery {
        member: target.self_id(),
        source,
        key_package: target.fresh_key_package().await.unwrap(),
        request_id: [request; 32],
        expires_at: unix_now() + 3600,
        device_signature: vec![],
    };
    let binding = storage
        .account_device_signer(&grant.member)
        .unwrap()
        .unwrap();
    let signer = SignatureKeyPair::read(
        storage.mls_storage(),
        &binding.mls_signature_public_key,
        cgka_engine::DEFAULT_CIPHERSUITE.signature_algorithm(),
    )
    .unwrap();
    grant.device_signature = signer
        .sign(
            &group_recovery_grant_bytes(
                group,
                &admin.self_id(),
                &grant.request_id,
                grant.expires_at,
                &grant.source,
                &grant.key_package,
            )
            .unwrap(),
        )
        .unwrap();
    grant
}

async fn seal_native_welcomes(welcomes: &[OutboundWelcome]) -> Vec<cgka_traits::SealedWelcome> {
    let mut sealed = Vec::with_capacity(welcomes.len());
    for welcome in welcomes {
        sealed.push(cgka_traits::SealedWelcome {
            local_id: welcome.local_id.clone(),
            message: MockSealer.seal_welcome(welcome).await.unwrap(),
        });
    }
    sealed
}

async fn hydrated_recovery_fixture(
    mode: RecoveryFixtureMode,
) -> (
    tempfile::TempDir,
    AccountDeviceSession,
    GroupId,
    GroupId,
    TransportMessage,
    MessageId,
) {
    use cgka_engine::EngineBuilder;
    use cgka_traits::engine::{CgkaEngine, SendResult};

    let dir = relaxed_storage_dir().unwrap();
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
    let mut peers = Vec::new();
    if matches!(mode, RecoveryFixtureMode::Queued) {
        for index in 0..9 {
            let name = format!("hydrated-peer-{index}");
            let peer_storage = if index == 8 {
                SqliteAccountStorage::open_encrypted(
                    dir.path().join(format!("peer-{index}.sqlite")),
                    &key,
                )
                .unwrap()
            } else {
                SqliteAccountStorage::in_memory_for_test().unwrap()
            };
            peers.push((build(name.as_bytes(), peer_storage.clone()), peer_storage));
        }
    }
    let request = |name: &str, members| CreateGroupRequest {
        name: name.into(),
        description: String::new(),
        members,
        required_features: vec![],
        app_components: vec![],
        initial_admins: vec![],
    };
    let (a, _) = alice.create_group(request("A", vec![])).await.unwrap();
    let mut members = vec![bob.fresh_key_package().await.unwrap()];
    for (peer, _) in &mut peers {
        members.push(peer.fresh_key_package().await.unwrap());
    }
    let (b, created) = alice.create_group(request("B", members)).await.unwrap();
    let SendResult::FoundingGroupCreated { welcomes } = created else {
        panic!("founding group")
    };
    let mut sealed = seal_native_welcomes(&welcomes).await;
    alice.bind_sealed_welcomes(&sealed, None).unwrap();
    let founding = sealed.remove(0).message;
    let unsealed = MockSealer.unseal(&founding).await.unwrap();
    bob.join_welcome(founding.clone(), unsealed).await.unwrap();
    alice.mark_sent_welcome_delivered(&founding.id).unwrap();
    for ((peer, _), sealed) in peers.iter_mut().zip(sealed) {
        let founding = sealed.message;
        let unsealed = MockSealer.unseal(&founding).await.unwrap();
        peer.join_welcome(founding.clone(), unsealed).await.unwrap();
        alice.mark_sent_welcome_delivered(&founding.id).unwrap();
    }
    let grant = recovery_grant(&alice, &mut bob, &target_storage, &b, 87).await;
    let mut grants = vec![grant];
    for (index, (peer, storage)) in peers.iter_mut().take(8).enumerate() {
        grants.push(recovery_grant(&alice, peer, storage, &b, index as u8).await);
    }
    let recovery = SendIntent::RecoverMembers {
        group_id: b.clone(),
        members: grants,
    };
    if matches!(mode, RecoveryFixtureMode::Prepared) {
        drop(alice);
        let mut runtime = AccountDeviceRuntime::new(
            current_session(&path, &key, b"hydrated-alice"),
            RecordingAdapter::default(),
            StaticTransportRouting::new(vec![]),
            RecordingKeyPackages::default(),
        );
        let marmot_session::PreparedSessionSend::Commit(prepared) = runtime
            .confirm_commit_without_publish_with_audit_context(recovery, Default::default())
            .await
            .unwrap()
        else {
            panic!("a recoverable group stages the recovery commit");
        };
        let (effects, mut welcomes) = prepared.into_effects_and_welcomes();
        let commit = effects
            .publish
            .into_iter()
            .find_map(|work| match work {
                PublishWork::GroupEvolution { msg, .. } => Some(msg.id),
                _ => None,
            })
            .unwrap();
        let welcome = welcomes.pop().unwrap();
        drop(runtime);
        let reopened = current_session(&path, &key, b"hydrated-alice");
        return (dir, reopened, a, b, welcome, commit);
    }
    let SendResult::GroupEvolution {
        welcomes,
        pending,
        msg,
    } = alice.send(recovery).await.unwrap()
    else {
        panic!("native recovery")
    };
    let sealed = seal_native_welcomes(&welcomes).await;
    let welcome = sealed[0].message.clone();
    if !matches!(mode, RecoveryFixtureMode::Staged) {
        alice.bind_sealed_welcomes(&sealed, None).unwrap();
        alice.confirm_published(pending).await.unwrap();
        assert!(
            alice
                .outstanding_sent_welcomes()
                .unwrap()
                .iter()
                .any(|(_, owed)| owed.id == welcome.id)
        );
        if let Some((witness, _)) = peers.get_mut(8) {
            witness
                .buffer_openmls_convergence_message_at(&b, msg.clone(), 500)
                .unwrap();
            witness
                .converge_stored_openmls_messages_at(&b, 1_000_000)
                .unwrap();
            assert_eq!(witness.epoch(&b).unwrap(), alice.epoch(&b).unwrap());
        }
        drop(alice);
        // A real failed delivery owns a durable retry before the fork. It must
        // not publish later merely because it retained the exact old bytes.
        // It failed a minute ago, so its relay's backoff has passed.
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
        )
        .with_maintenance_sources(
            Arc::new(TestWallClock::new(unix_now() - 60)),
            Arc::new(TestMonotonicClock::default()),
            Arc::new(TestRandom::new(0)),
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
    drop(peers);
    let reopened = current_session(&path, &key, b"hydrated-alice");
    (dir, reopened, a, b, welcome, msg.id)
}

#[cfg(feature = "test-policy-overrides")]
async fn recovery_branch_message(
    peer: &mut AccountDeviceSession,
    group: &GroupId,
) -> TransportMessage {
    let effects = peer
        .send(SendIntent::SelfUpdate {
            group_id: group.clone(),
        })
        .await
        .unwrap();
    let PublishWork::GroupEvolution {
        mut msg, pending, ..
    } = effects.publish.into_iter().next().unwrap()
    else {
        panic!("native branch self-update")
    };
    peer.confirm_published(pending).await.unwrap();
    msg.envelope = TransportEnvelope::GroupMessage {
        transport_group_id: group.as_slice().to_vec(),
    };
    msg
}

#[cfg(feature = "test-policy-overrides")]
async fn recovery_branch_step(
    runtime: &mut AccountDeviceRuntime<
        RecordingAdapter,
        StaticTransportRouting,
        RecordingKeyPackages,
    >,
    peer: &mut AccountDeviceSession,
    group: &GroupId,
) {
    let msg = recovery_branch_message(peer, group).await;
    runtime
        .ingest_delivery(&TransportDelivery {
            account_id: runtime.self_id(),
            group_id_hint: Some(group.clone()),
            message: msg,
            received_at: Timestamp(unix_now()),
            source: TransportDeliverySource {
                transport: TransportSource("marmot-account-test".into()),
                plane: TransportDeliveryPlane::Group,
                endpoint: None,
                subscription_id: None,
                wire: None,
            },
        })
        .await
        .unwrap();
    // Each host advance has a cooperative wall-time budget. Finish the
    // retained input before asserting the branch, as a scheduled host would.
    tokio::time::timeout(Duration::from_secs(5), async {
        runtime.advance_convergence(group).await.unwrap();
        while runtime.has_pending_convergence_inputs(group).unwrap() {
            assert_eq!(
                runtime.prepare_convergence_cutoff_delay_ms(group).unwrap(),
                Some(0),
                "zero-quiescence recovery input must retain its due convergence wake"
            );
            tokio::task::yield_now().await;
            runtime.advance_convergence(group).await.unwrap();
        }
    })
    .await
    .expect("scheduled recovery branch input must settle");
    assert_eq!(
        runtime.session().epoch(group).unwrap(),
        peer.epoch(group).unwrap()
    );
}
