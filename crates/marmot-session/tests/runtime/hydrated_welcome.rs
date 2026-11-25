include!("../support/hydrated_recovery.rs");

#[tokio::test]
#[cfg(feature = "test-policy-overrides")]
async fn queued_recovery_origin() {
    use marmot_session::CanonicalizationPolicy;

    for terminal in [false, true] {
        let (dir, mut session, _, group, _, origin) =
            hydrated_recovery_fixture(RecoveryFixtureMode::Queued).await;
        session
            .set_convergence_policy(CanonicalizationPolicy {
                settlement_quiescence_ms: 0,
                ..CanonicalizationPolicy::default()
            })
            .unwrap();
        let key = SqlCipherKey::new("hydrated welcome ownership key").unwrap();
        let mut rival = current_session(dir.path().join("bob.sqlite"), &key, b"hydrated-bob");
        let mut witness =
            current_session(dir.path().join("peer-8.sqlite"), &key, b"hydrated-peer-8");
        let welcomes = session
            .outstanding_sent_welcomes()
            .unwrap()
            .into_iter()
            .map(|(_, welcome)| welcome)
            .collect::<Vec<_>>();
        assert_eq!(welcomes.len(), 9);
        let queued = welcomes[8].clone();
        let mut routing = StaticTransportRouting::new(vec![]).with_group_route(
            group.clone(),
            group.as_slice().to_vec(),
            vec![TransportEndpoint("wss://recovery-group.example".into())],
        );
        for welcome in &welcomes {
            let TransportEnvelope::Welcome { recipient } = &welcome.envelope else {
                panic!("native recovery Welcome")
            };
            routing = routing.with_inbox_route(
                recipient.clone(),
                vec![TransportEndpoint("wss://recovery-inbox.example".into())],
            );
        }
        let adapter = RecordingAdapter::default();
        let wall = Arc::new(TestWallClock::new(unix_now()));
        let mut runtime = AccountDeviceRuntime::new(
            session,
            adapter.clone(),
            routing,
            RecordingKeyPackages::default(),
        )
        .with_maintenance_sources(
            wall.clone(),
            Arc::new(TestMonotonicClock::default()),
            Arc::new(TestRandom::new(0)),
        );
        runtime.set_detached_welcome_waves(true);
        assert_eq!(
            runtime.session().stored_message_state(&origin).unwrap(),
            Some(cgka_traits::MessageState::Processed)
        );
        let gate = adapter.gate_welcome_publishes();
        let task = runtime
            .prepare_welcome_retry_task_with_audit_context(welcomes, Default::default())
            .unwrap();
        assert_eq!(task.message_ids().len(), 9);
        let frozen = runtime
            .session()
            .transport_fanout(&queued.id)
            .unwrap()
            .unwrap();
        assert_eq!(frozen.exact_message, queued);
        let running = tokio::spawn(task.run());
        tokio::time::timeout(Duration::from_secs(5), async {
            while gate.active.load(Ordering::SeqCst) < 8 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("eight Welcome publishes fill the bounded worker set");
        assert_eq!(welcome_publishes(&adapter).len(), 8);
        let rounds = if terminal {
            2 + cgka_engine::convergence::V1_MAX_REWIND_COMMITS
        } else {
            2
        };
        for _ in 0..rounds {
            recovery_branch_step(&mut runtime, &mut rival, &group).await;
        }
        let lost = if terminal {
            cgka_traits::MessageState::EpochInvalidated
        } else {
            cgka_traits::MessageState::ConvergenceDeferred
        };
        assert_eq!(
            runtime.session().stored_message_state(&origin).unwrap(),
            Some(lost)
        );
        gate.release.add_permits(9);
        let finished = runtime
            .finish_welcome_publish_task(running.await.unwrap())
            .await
            .unwrap();
        assert!(finished.welcome_failures.is_empty());
        let published = welcome_publishes(&adapter);
        assert_eq!(published.len(), 8);
        assert!(published.iter().all(|welcome| welcome.id != queued.id));
        assert!(runtime.outstanding_welcome_deliveries().unwrap().is_empty());
        if terminal {
            assert!(
                runtime
                    .prepare_welcome_retry_task_with_audit_context(
                        vec![queued.clone()],
                        Default::default()
                    )
                    .unwrap()
                    .message_ids()
                    .is_empty()
            );
            wall.set(wall.now().0 + 100);
            runtime.run_due_maintenance().await.unwrap();
            assert_eq!(welcome_publishes(&adapter).len(), 8);
            assert!(
                runtime
                    .session()
                    .transport_fanout(&queued.id)
                    .unwrap()
                    .is_none()
            );
        } else {
            let parked = runtime
                .session()
                .transport_fanout(&queued.id)
                .unwrap()
                .unwrap();
            assert_eq!(parked, frozen);
            assert_eq!(
                runtime.session().stored_message_state(&queued.id).unwrap(),
                Some(cgka_traits::MessageState::Sent)
            );
            assert!(
                runtime
                    .session()
                    .sent_welcome_awaits_commit(&queued.id)
                    .unwrap()
            );
            let error = runtime.redeliver_welcome(&queued.id).await.unwrap_err();
            assert!(matches!(
                error.as_engine_error(),
                Some(cgka_traits::EngineError::Backend(reason))
                    if reason == "stored Welcome origin is not canonical"
            ));
            assert_eq!(welcome_publishes(&adapter).len(), 8);
            for _ in 0..2 {
                recovery_branch_step(&mut runtime, &mut witness, &group).await;
                if runtime.session().stored_message_state(&origin).unwrap()
                    == Some(cgka_traits::MessageState::Processed)
                {
                    break;
                }
            }
            assert_eq!(
                runtime.session().stored_message_state(&origin).unwrap(),
                Some(cgka_traits::MessageState::Processed)
            );
            assert!(
                runtime
                    .outstanding_welcome_deliveries()
                    .unwrap()
                    .iter()
                    .any(|(_, welcome)| welcome == &queued)
            );
            runtime.redeliver_welcome(&queued.id).await.unwrap();
            let retried = welcome_publishes(&adapter);
            assert_eq!(retried.len(), 9);
            assert_eq!(retried[8], queued);
            assert!(
                runtime
                    .outstanding_welcome_deliveries()
                    .unwrap()
                    .iter()
                    .all(|(_, welcome)| welcome.id != queued.id)
            );
        }
    }
}

#[tokio::test]
async fn hydrated_welcome_stays_owned() {
    let (_dir, session, a, b, welcome, _) =
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
        let (_dir, session, _a, b, welcome, _) = hydrated_recovery_fixture(mode).await;
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
    let (_dir, session, _a, _b, welcome, _) =
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

// The staged recovery uses raw fixture Welcomes, but inbound control must
// still authenticate the sender via NIP-59.
struct RecoveryControlSealer(transport_nostr_peeler::NostrInboxSealer);

#[async_trait]
impl InboxSealer for RecoveryControlSealer {
    async fn unseal(&self, message: &TransportMessage) -> Result<PeeledMessage, PeelerError> {
        self.0.unseal(message).await
    }

    async fn seal_welcome(&self, welcome: &OutboundWelcome) -> Result<TransportMessage, PeelerError> {
        MockSealer.seal_welcome(welcome).await
    }

    async fn seal_group_recovery(
        &self,
        message: &cgka_traits::GroupRecoveryMessage,
        recipient: &MemberId,
    ) -> Result<TransportMessage, PeelerError> {
        self.0.seal_group_recovery(message, recipient).await
    }

    fn sealed_welcome_len(&self, welcome: &OutboundWelcome) -> usize {
        MockSealer.sealed_welcome_len(welcome)
    }
}

#[tokio::test]
async fn recovery_ingest_drains_native() {
    enum OpenMode {
        Eager,
        Deferred,
    }

    for mode in [OpenMode::Eager, OpenMode::Deferred] {
        let (dir, session, _, group, welcome, _) =
            hydrated_recovery_fixture(RecoveryFixtureMode::Staged).await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let wall = Arc::new(TestWallClock::new(now));
        let monotonic = Arc::new(TestMonotonicClock::default());
        let obligation = MessageId::new(vec![0x94; 32]);
        // A retained obligation can lack the optional own-leaf baseline.
        session
            .put_maintenance_obligation(&cgka_traits::maintenance::MaintenanceObligation {
                id: obligation.clone(),
                group_id: group.clone(),
                trigger: cgka_traits::MaintenanceTrigger::Manual,
                phase: cgka_traits::MaintenancePhase::Quiet,
                created_at: Timestamp(now),
                operational_target_at: None,
                overdue: false,
                eose_deadline_at: None,
                grace_until: None,
                quiet_since: Some(Timestamp(now)),
                own_leaf_baseline_hash: None,
                sampled_jitter_ms: 0,
                not_before: None,
                attempt_count: 0,
                semantic_rearm_count: 0,
                last_failure_code: None,
            })
            .unwrap();
        drop(session);
        let config = SessionConfig::new(
            dir.path().join("alice.sqlite"),
            SqlCipherKey::new("hydrated welcome ownership key").unwrap(),
            pad32(b"hydrated-alice"),
            Box::new(transport_nostr_peeler::NostrMlsPeeler::default()),
            Arc::new(RecoveryControlSealer(nostr_sealer(b"hydrated-alice"))),
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
        )
        .with_maintenance_sources(
            wall.clone(),
            monotonic.clone(),
            Arc::new(TestRandom::new(0)),
        )
        .with_maintenance_timing(MaintenanceTiming {
            quiet: Duration::from_secs(60),
            ..MaintenanceTiming::immediate()
        });
        let account = runtime.self_id();
        let control = cgka_traits::GroupRecoveryMessage {
            group_id: group.clone(),
            request_id: [0x92; 32],
            expires_at: now + 600,
            body: cgka_traits::GroupRecoveryBody::Request {
                device_key_hash: [0x93; 32],
            },
        };
        let carrier = nostr_sealer(b"hydrated-bob")
            .seal_group_recovery(&control, &account)
            .await
            .unwrap();

        let connection = rusqlite::Connection::open(dir.path().join("alice.sqlite")).unwrap();
        storage_sqlite::open_hardened_sqlcipher(
            &connection,
            &SqlCipherKey::new("hydrated welcome ownership key").unwrap(),
            storage_sqlite::SqlCipherHardening::cipher_only(),
        )
        .unwrap();
        connection
            .execute_batch(
                "CREATE TRIGGER fail_quiet_reset BEFORE UPDATE ON cgka_maintenance_obligations
                 BEGIN SELECT RAISE(ABORT, 'injected quiet reset failure'); END;",
            )
            .unwrap();
        wall.set(now + 10);
        let ingested = runtime
            .ingest_delivery(&recovery_inbox_delivery(account, carrier))
            .await
            .unwrap();

        assert!(matches!(
            ingested.outcome,
            cgka_traits::IngestOutcome::GroupRecovery { .. }
        ));
        assert!(ingested.left_object_unpersisted);
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
        assert_eq!(
            runtime
                .session()
                .maintenance_obligation(&obligation)
                .unwrap()
                .unwrap()
                .quiet_since,
            Some(Timestamp(now)),
            "the injected storage fault prevented the reset"
        );
        connection
            .execute_batch("DROP TRIGGER fail_quiet_reset")
            .unwrap();
        runtime.run_due_maintenance().await.unwrap();
        assert_eq!(
            runtime
                .session()
                .maintenance_obligation(&obligation)
                .unwrap()
                .unwrap()
                .quiet_since,
            Some(Timestamp(now + 10)),
            "maintenance must retain and retry the quiet-window reconciliation"
        );
        let resumed_epoch = runtime.session().epoch(&group).unwrap();
        wall.set(now + 61);
        monotonic.set_millis(51_000);
        for _ in 0..3 {
            runtime.run_due_maintenance().await.unwrap();
        }
        assert_eq!(
            runtime.session().epoch(&group).unwrap(),
            resumed_epoch,
            "the resumed Commit restarts the obligation's full quiet window"
        );
        assert_eq!(
            runtime
                .session()
                .maintenance_obligation(&obligation)
                .unwrap()
                .unwrap()
                .phase,
            cgka_traits::MaintenancePhase::Quiet
        );
        wall.set(now + 71);
        monotonic.set_millis(61_000);
        runtime.run_due_maintenance().await.unwrap();
        assert_eq!(
            runtime
                .session()
                .maintenance_obligation(&obligation)
                .unwrap()
                .unwrap()
                .phase,
            cgka_traits::MaintenancePhase::Jitter
        );
    }
}
