// Native preparation deliberately stops before transport publication, then reopens
// the encrypted account as the runtime's first user operation.
async fn hydrated_recovery_fixture() -> (
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
    let mut alice = build(b"hydrated-alice", storage);
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
    let SendResult::GroupEvolution { mut welcomes, .. } = alice
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
    drop(alice);
    drop(bob);
    drop(target_storage);
    let reopened = current_session(&path, &key, b"hydrated-alice");
    (dir, reopened, a, b, welcome)
}

#[tokio::test]
async fn hydrated_welcome_stays_owned() {
    let (_dir, session, a, b, welcome) = hydrated_recovery_fixture().await;
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
async fn recovery_ingest_drains_native() {
    use cgka_traits::peeler::TransportPeeler as _;

    enum OpenMode {
        Eager,
        Deferred,
    }

    for mode in [OpenMode::Eager, OpenMode::Deferred] {
        let (dir, session, _, group, welcome) = hydrated_recovery_fixture().await;
        drop(session);
        let config = SessionConfig::new(
            dir.path().join("alice.sqlite"),
            SqlCipherKey::new("hydrated welcome ownership key").unwrap(),
            pad32(b"hydrated-alice"),
            Box::new(nostr_peeler(b"hydrated-alice")),
        )
        .account_identity_proof_signer(Arc::new(NostrAccountIdentityProofSigner {
            keys: deterministic_nostr_keys(b"hydrated-alice"),
        }))
        .protocol_profile(ProtocolProfile::Current);
        let config = match mode {
            OpenMode::Eager => config,
            OpenMode::Deferred => config.defer_group_hydration(),
        };
        let session = AccountDeviceSession::open(config).unwrap();
        let adapter = RecordingAdapter::default();
        let endpoint = TransportEndpoint("wss://recovery-hydration.example".into());
        let mut runtime = AccountDeviceRuntime::new(
            session,
            adapter.clone(),
            StaticTransportRouting::new(vec![endpoint.clone()])
                .with_group_route(
                    group.clone(),
                    group.as_slice().to_vec(),
                    vec![endpoint.clone()],
                )
                .with_inbox_route(
                    cgka_traits::types::MemberId::new(pad32(b"hydrated-bob")),
                    vec![endpoint],
                ),
            RecordingKeyPackages::default(),
        );
        let account = runtime.self_id();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let control = cgka_traits::GroupRecoveryMessage {
            group_id: group.clone(),
            request_id: [0x92; 32],
            expires_at: now + 600,
            body: cgka_traits::GroupRecoveryBody::Request {
                device_key_hash: [0x93; 32],
            },
        };
        let carrier = nostr_peeler(b"hydrated-bob")
            .wrap_group_recovery(&control, &account)
            .await
            .unwrap();

        let ingested = runtime
            .ingest_delivery(&recovery_inbox_delivery(account, carrier))
            .await
            .unwrap();

        assert!(matches!(
            ingested.outcome,
            cgka_traits::IngestOutcome::Ignored { .. }
        ));
        assert!(matches!(
            runtime.epoch_state(&group),
            Some(cgka_traits::EpochState::Stable { .. })
        ));
        assert!(
            adapter
                .publishes()
                .iter()
                .any(|request| request.message.id == welcome.id)
        );
        assert!(ingested.effects.events.iter().any(|event| matches!(
            event,
            GroupEvent::EpochChanged { group_id, .. } if group_id == &group
        )));
        assert!(
            ingested
                .effects
                .fanout
                .iter()
                .any(|outcome| { outcome.mls_confirmed && outcome.fanout_complete })
        );
    }
}
