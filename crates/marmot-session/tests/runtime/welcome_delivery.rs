// One delivered mark and one work list for outbound Welcomes (mdk#2628 3.5a).

/// A Welcome whose first pass failed is delivered by a maintenance retry,
/// and that retry marks it delivered: it stops being owed at once, not at
/// the next open.
#[tokio::test]
async fn maintenance_retry_that_lands_settles_the_welcome() {
    let dir = relaxed_storage_dir().unwrap();
    let OwedInviteWelcome {
        mut runtime,
        adapter,
        wall,
        welcome,
        ..
    } = owed_invite_welcome(dir.path()).await;
    assert_eq!(runtime.outstanding_welcome_deliveries().unwrap().len(), 1);
    adapter.accept_only_endpoints(vec![
        TransportEndpoint("wss://group.example".into()),
        TransportEndpoint("wss://carol-inbox.example".into()),
    ]);
    let tried = welcome_publishes(&adapter).len();

    wall.set(300_100);
    runtime.run_due_maintenance().await.unwrap();

    assert_eq!(welcome_publishes(&adapter).len(), tried + 1, "the retry ran");
    assert!(
        runtime.outstanding_welcome_deliveries().unwrap().is_empty(),
        "the retry that met the policy settled the Welcome"
    );
    assert_eq!(
        runtime.withdraw_welcome(&welcome.id).unwrap(),
        WelcomeWithdrawal::AlreadyDelivered
    );
}

/// The v5 Welcome rows the owed-invite fixture's runtime recorded in `dir`
/// for `welcome`, after checking that each names `group_id`.
fn welcome_rows(
    dir: &std::path::Path,
    welcome: &TransportMessage,
    group_id: &GroupId,
) -> Vec<serde_json::Value> {
    let outer = marmot_forensics::v5::NostrEventRef::from_validated_event_id(
        &<[u8; 32]>::try_from(welcome.id.as_slice()).unwrap(),
    );
    let group_ref = marmot_forensics::v5::GroupRef::from_group_id(group_id.as_slice()).unwrap();
    v5_audit_rows(&owed_invite_audit_path(dir))
        .into_iter()
        .filter(|row| row["event"]["outer_event_ref"] == outer.as_str())
        .inspect(|row| assert_eq!(row["group_ref"], group_ref.as_str(), "{row}"))
        .collect()
}

fn kinds(rows: &[serde_json::Value]) -> Vec<&str> {
    rows.iter()
        .map(|row| row["event"]["type"].as_str().unwrap())
        .collect()
}

/// An invite's Welcome is audited from its preparation on: a
/// `welcome_prepared` row naming the KeyPackage it answers, then one started
/// and one finished row per pass over its relays, each with its own attempt
/// id. Maintenance's retry is audited as the first pass is, and the pass that
/// meets the policy reports the Welcome completed: it was marked delivered
/// before its row.
#[tokio::test]
async fn every_pass_over_a_welcome_records_its_publish_rows() {
    let dir = relaxed_storage_dir().unwrap();
    let OwedInviteWelcome {
        mut runtime,
        adapter,
        wall,
        group_id,
        welcome,
    } = owed_invite_welcome(dir.path()).await;
    let first = welcome_rows(dir.path(), &welcome, &group_id);
    assert_eq!(
        kinds(&first),
        [
            "welcome_prepared",
            "welcome_publish_started",
            "welcome_publish_finished"
        ]
    );
    assert_eq!(
        first[0]["event"]["key_package_event_ref"],
        marmot_forensics::v5::NostrEventRef::from_validated_event_id(&[0x77; 32]).as_str()
    );
    assert_eq!(first[2]["event"]["retained_state"], "pending");
    adapter.accept_only_endpoints(vec![
        TransportEndpoint("wss://group.example".into()),
        TransportEndpoint("wss://carol-inbox.example".into()),
    ]);

    wall.set(300_100);
    runtime.run_due_maintenance().await.unwrap();

    let rows = welcome_rows(dir.path(), &welcome, &group_id);
    let retry = &rows[first.len()..];
    assert_eq!(
        kinds(retry),
        ["welcome_publish_started", "welcome_publish_finished"]
    );
    assert_eq!(retry[0]["event"]["attempt_id"], retry[1]["event"]["attempt_id"]);
    assert_ne!(retry[0]["event"]["attempt_id"], first[1]["event"]["attempt_id"]);
    assert_eq!(retry[0]["event"]["op_id"], first[0]["event"]["op_id"]);
    assert_eq!(retry[1]["event"]["policy"], "met");
    assert_eq!(retry[1]["event"]["retained_state"], "completed");
}

/// A retry after one inbox relay already met the policy keeps that
/// cumulative evidence: when the other relay's retry fails with an error that
/// names no relay, its finished row is incomplete for this pass, yet reports
/// the stored acceptance, the met policy, and the delivered Welcome.
#[tokio::test]
async fn a_retry_after_the_policy_was_met_keeps_the_stored_acceptance() {
    let dir = relaxed_storage_dir().unwrap();
    let (first, second) = (
        TransportEndpoint("wss://carol-first.example".into()),
        TransportEndpoint("wss://carol-second.example".into()),
    );
    let adapter = RecordingAdapter::default();
    adapter.accept_only_endpoints(vec![
        TransportEndpoint("wss://group.example".into()),
        first.clone(),
    ]);
    let (
        OwedInviteWelcome {
            mut runtime,
            adapter,
            wall,
            group_id,
            welcome,
        },
        effects,
    ) = invite_carol_through(dir.path(), adapter, vec![first, second.clone()]).await;
    assert!(effects.welcome_failures.is_empty(), "one relay met the policy");
    let recorded = welcome_rows(dir.path(), &welcome, &group_id).len();
    adapter.error_for_endpoints(vec![second]);

    wall.set(300_100);
    runtime.run_due_maintenance().await.unwrap();

    let rows = welcome_rows(dir.path(), &welcome, &group_id);
    let retry = &rows[recorded..];
    assert_eq!(
        kinds(retry),
        ["welcome_publish_started", "welcome_publish_finished"]
    );
    let finished = &retry[1]["event"];
    assert_eq!(finished["results_complete"], false, "{finished}");
    assert_eq!(finished["accepted_total_count"], 1);
    assert_eq!(finished["policy"], "met");
    assert_eq!(finished["retained_state"], "completed");
}

/// A Welcome sent again after its retry record expired gets a new attempt
/// id: two passes never share one, though both start the first attempt of
/// a fresh record.
#[tokio::test]
async fn a_welcome_sent_again_after_its_retry_record_expired_gets_a_new_attempt_id() {
    let dir = relaxed_storage_dir().unwrap();
    let OwedInviteWelcome {
        mut runtime,
        wall,
        group_id,
        welcome,
        ..
    } = owed_invite_welcome(dir.path()).await;

    // Past the retry record's retention it is dropped, and the owed Welcome
    // is published again under a new one.
    for step in 1..=3 {
        wall.set(300_000 + 24 * 60 * 60 + step * 600);
        runtime.run_due_maintenance().await.unwrap();
    }

    let attempts = welcome_rows(dir.path(), &welcome, &group_id)
        .into_iter()
        .filter(|row| row["event"]["type"] == "welcome_publish_started")
        .map(|row| row["event"]["attempt_id"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert!(attempts.len() >= 2, "{attempts:?}");
    let distinct = attempts.iter().collect::<std::collections::BTreeSet<_>>();
    assert_eq!(distinct.len(), attempts.len(), "{attempts:?}");
}

/// A Welcome whose inbox relay the transport refused before sending, as the
/// relay plane refuses a relay its host-safety rule rejects, reached no relay.
/// Neither its first attempt nor maintenance's retry of its stored fanout is a
/// possible exposure, while a retry that fails ambiguously still is
/// (mdk#3305).
#[tokio::test]
async fn welcome_refused_before_sending_is_not_a_possible_exposure() {
    let dir = relaxed_storage_dir().unwrap();
    let inbox = TransportEndpoint("wss://carol-inbox.example".into());
    let adapter = RecordingAdapter::default();
    adapter.fail_endpoints_with_reasons(
        TransportEndpointFailureKind::NotExposed,
        vec![(inbox.clone(), "relay endpoint refused by the host-safety rule")],
    );
    let OwedInviteWelcome {
        mut runtime,
        adapter,
        wall,
        group_id,
        welcome,
    } = owed_invite_welcome_through(dir.path(), adapter).await;
    let exposed = |runtime: &WithdrawalRuntime| {
        runtime
            .session()
            .transport_fanout(&welcome.id)
            .unwrap()
            .expect("the Welcome keeps its retry record")
            .possible_exposure
    };
    assert!(!exposed(&runtime), "the first attempt reached no relay");

    let tried = welcome_publishes(&adapter).len();
    let recorded = welcome_rows(dir.path(), &welcome, &group_id).len();
    wall.set(300_100);
    let effects = runtime.run_due_maintenance().await.unwrap();
    assert_eq!(welcome_publishes(&adapter).len(), tried + 1, "the retry ran");
    assert!(!exposed(&runtime), "the retry reached no relay either");
    // The retry's audit row names the refusal, not an unknown result.
    let finished = welcome_rows(dir.path(), &welcome, &group_id)
        .into_iter()
        .skip(recorded)
        .find(|row| row["event"]["type"] == "welcome_publish_finished")
        .expect("the retry's finished row");
    assert_eq!(finished["event"]["results_complete"], true, "{finished}");
    assert_eq!(
        finished["event"]["results"][0]["failure_kind"], "not_exposed",
        "{finished}"
    );
    assert_eq!(
        runtime
            .maintenance_run_summary(&effects)
            .unwrap()
            .ambiguous_exposure,
        0
    );

    adapter.error_for_endpoints(vec![inbox]);
    wall.set(300_200);
    let effects = runtime.run_due_maintenance().await.unwrap();
    assert_eq!(welcome_publishes(&adapter).len(), tried + 2, "the retry ran");
    assert!(exposed(&runtime), "an ambiguous failure may have reached it");
    assert_eq!(
        runtime
            .maintenance_run_summary(&effects)
            .unwrap()
            .ambiguous_exposure,
        1
    );
}

/// An invite whose commit every group relay refuses for its size rolls back,
/// and its Welcome's audit says why: `welcome_withdrawn` with
/// `commit_too_large` and the size class, once, after the rollback retired
/// it. The watcher, seeing the Welcome settle later, adds no generic row.
/// So for a host's invite, accepted first and its Welcomes taken off the
/// commit before it is published, as the app does.
#[tokio::test]
async fn an_invite_whose_commit_every_relay_refuses_for_size_records_why_its_welcome_was_withdrawn()
{
    for host_accepts_first in [false, true] {
        invite_refused_for_commit_size(host_accepts_first).await;
    }
}

async fn invite_refused_for_commit_size(host_accepts_first: bool) {
    let dir = relaxed_storage_dir().unwrap();
    let key = SqlCipherKey::new("marmot refused invite key").unwrap();
    let mut alice = nostr_welcome_session(dir.path().join("alice.sqlite"), &key, b"alice-refused");
    let mut bob = nostr_welcome_session(dir.path().join("bob.sqlite"), &key, b"bob-refused");
    let mut carol = nostr_welcome_session(dir.path().join("carol.sqlite"), &key, b"carol-refused");
    let created = alice
        .create_group(CreateGroupRequest {
            name: "refused invite".into(),
            description: String::new(),
            members: vec![bob.fresh_key_package().await.unwrap()],
            required_features: Vec::new(),
            app_components: Vec::new(),
            initial_admins: Vec::new(),
        })
        .await
        .unwrap();
    let PublishWork::GroupCreated { pending, .. } = &created.effects.publish[0] else {
        panic!("expected GroupCreated publish work");
    };
    alice.confirm_published(*pending).await.unwrap();
    let group_id = created.group_id;
    let group_relay = TransportEndpoint("wss://group.example".into());
    let policy =
        StaticTransportRouting::new(vec![TransportEndpoint("wss://alice-inbox.example".into())])
            .with_group_route(
                group_id.clone(),
                group_id.as_slice().to_vec(),
                vec![group_relay.clone()],
            )
            .with_inbox_route(
                carol.self_id(),
                vec![TransportEndpoint("wss://carol-inbox.example".into())],
            );
    let adapter = RecordingAdapter::default();
    adapter.refuse_commits_as_too_large(vec![group_relay]);
    let wall = Arc::new(TestWallClock::new(300_000));
    let mut runtime =
        AccountDeviceRuntime::new(alice, adapter.clone(), policy, RecordingKeyPackages::default())
            .with_maintenance_sources(
                wall.clone(),
                Arc::new(TestMonotonicClock::default()),
                Arc::new(TestRandom::new(0)),
            );
    let audit_path = dir.path().join("refused-audit-v5.jsonl");
    runtime
        .audit_recorder()
        .swap(v5_audit_recorder(&audit_path));

    let invite = SendIntent::Invite {
        group_id: group_id.clone(),
        key_packages: vec![cgka_traits::engine::KeyPackage {
            source: Some(cgka_traits::engine::KeyPackageSource {
                event_id: MessageId::new(vec![0x78; 32]),
            }),
            ..carol.fresh_key_package().await.unwrap()
        }],
        initial_admins: Vec::new(),
    };
    let effects = if host_accepts_first {
        let marmot_session::PreparedSessionSend::Commit(prepared) = runtime
            .confirm_host_change_without_publish_with_audit_context(invite, Default::default())
            .await
            .unwrap()
        else {
            panic!("expected a staged commit");
        };
        let (effects, welcomes) = prepared.into_effects_and_welcomes();
        assert_eq!(welcomes.len(), 1);
        runtime
            .publish_prepared_session_effects_with_audit_context(effects, Default::default())
            .await
            .unwrap()
    } else {
        runtime.send(invite).await.unwrap()
    };
    assert!(matches!(
        effects.pending.as_slice(),
        [PendingResolution::RolledBack { .. }]
    ));
    wall.set(300_100);
    runtime.run_due_maintenance().await.unwrap();

    let group_ref = marmot_forensics::v5::GroupRef::from_group_id(group_id.as_slice()).unwrap();
    let rows = v5_audit_rows(&audit_path)
        .into_iter()
        .filter(|row| {
            row["event"]["type"]
                .as_str()
                .is_some_and(|kind| kind.starts_with("welcome_"))
        })
        .inspect(|row| assert_eq!(row["group_ref"], group_ref.as_str(), "{row}"))
        .collect::<Vec<_>>();
    assert_eq!(
        kinds(&rows),
        ["welcome_prepared", "welcome_withdrawn"],
        "host accepts first: {host_accepts_first}, {rows:?}"
    );
    assert_eq!(rows[1]["event"]["reason"], "commit_too_large");
    assert_eq!(rows[1]["event"]["oversized_size_class"], "from_64_to_128_kib");
    assert_eq!(rows[0]["event"]["op_id"], rows[1]["event"]["op_id"]);
}

/// An invite refused because one invitee's Welcome is too large names that
/// Welcome, with its own size, and withdraws the other invitee's Welcome with
/// it, with no size: that one would have fit.
#[tokio::test]
async fn a_too_large_welcome_is_named_and_its_sibling_invitee_is_withdrawn() {
    let dir = relaxed_storage_dir().unwrap();
    let key = SqlCipherKey::new("marmot two welcome refusal key").unwrap();
    let mut alice = nostr_welcome_session(dir.path().join("alice.sqlite"), &key, b"alice-two");
    let mut bob = nostr_welcome_session(dir.path().join("bob.sqlite"), &key, b"bob-two");
    let mut carol = nostr_welcome_session(dir.path().join("carol.sqlite"), &key, b"carol-two");
    let mut dave = nostr_welcome_session(dir.path().join("dave.sqlite"), &key, b"dave-two");
    let created = alice
        .create_group(CreateGroupRequest {
            name: "two welcome refusal".into(),
            description: String::new(),
            members: vec![bob.fresh_key_package().await.unwrap()],
            required_features: Vec::new(),
            app_components: Vec::new(),
            initial_admins: Vec::new(),
        })
        .await
        .unwrap();
    let PublishWork::GroupCreated { pending, .. } = &created.effects.publish[0] else {
        panic!("expected GroupCreated publish work");
    };
    alice.confirm_published(*pending).await.unwrap();
    let group_id = created.group_id;
    let small_inbox = TransportEndpoint("wss://dave-small-inbox.example".into());
    let policy =
        StaticTransportRouting::new(vec![TransportEndpoint("wss://alice-inbox.example".into())])
            .with_group_route(
                group_id.clone(),
                group_id.as_slice().to_vec(),
                vec![TransportEndpoint("wss://group.example".into())],
            )
            .with_inbox_route(
                carol.self_id(),
                vec![TransportEndpoint("wss://carol-inbox.example".into())],
            )
            .with_inbox_route(dave.self_id(), vec![small_inbox.clone()]);
    let adapter = RecordingAdapter::default();
    adapter.refuse_welcomes_as_too_large(vec![small_inbox]);
    let mut runtime =
        AccountDeviceRuntime::new(alice, adapter.clone(), policy, RecordingKeyPackages::default())
            .with_maintenance_sources(
                Arc::new(TestWallClock::new(300_000)),
                Arc::new(TestMonotonicClock::default()),
                Arc::new(TestRandom::new(0)),
            );
    let audit_path = dir.path().join("two-welcome-audit-v5.jsonl");
    runtime
        .audit_recorder()
        .swap(v5_audit_recorder(&audit_path));
    let sourced = |key_package: cgka_traits::engine::KeyPackage, marker: u8| {
        cgka_traits::engine::KeyPackage {
            source: Some(cgka_traits::engine::KeyPackageSource {
                event_id: MessageId::new(vec![marker; 32]),
            }),
            ..key_package
        }
    };

    let refused = runtime
        .confirm_host_change_without_publish_with_audit_context(
            SendIntent::Invite {
                group_id: group_id.clone(),
                key_packages: vec![
                    sourced(carol.fresh_key_package().await.unwrap(), 0x7a),
                    sourced(dave.fresh_key_package().await.unwrap(), 0x7b),
                ],
                initial_admins: Vec::new(),
            },
            Default::default(),
        )
        .await
        .unwrap();
    assert!(matches!(
        refused,
        marmot_session::PreparedSessionSend::Refused(_)
    ));
    // Their deliveries read so at once.
    let states = runtime
        .welcome_delivery_outcomes(None, None)
        .unwrap()
        .into_iter()
        .flatten()
        .map(|outcome| outcome.state)
        .collect::<Vec<_>>();
    assert_eq!(
        states,
        [cgka_traits::maintenance::WelcomeDeliveryState::Cancelled {
            reason: cgka_traits::maintenance::WelcomeCancelReason::Withdrawn
        }; 2]
    );

    let member_ref = |session: &AccountDeviceSession| {
        marmot_forensics::v5::MemberRef::from_member_identity(session.self_id().as_slice())
            .unwrap()
            .as_str()
            .to_owned()
    };
    let withdrawn = v5_audit_rows(&audit_path)
        .into_iter()
        .filter(|row| row["event"]["type"] == "welcome_withdrawn")
        .map(|row| {
            (
                row["event"]["recipient_ref"].as_str().unwrap().to_owned(),
                row["event"]["reason"].as_str().unwrap().to_owned(),
                row["event"]["oversized_size_class"]
                    .as_str()
                    .map(str::to_owned),
            )
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        withdrawn,
        [
            (member_ref(&carol), "withdrawn".to_owned(), None),
            (
                member_ref(&dave),
                "welcome_too_large".to_owned(),
                Some("from_64_to_128_kib".to_owned())
            ),
        ]
        .into_iter()
        .collect()
    );
}

/// A Welcome whose stored fanout already meets its policy, from an
/// acceptance saved before a stop interrupted its delivered mark, is marked
/// delivered by the next maintenance pass, though no relay is due, and even
/// when that pass comes after the retry record's retention: the acceptance is
/// reconciled before the record is dropped, and nothing is sent again.
#[tokio::test]
async fn a_saved_acceptance_whose_mark_was_interrupted_settles_the_welcome() {
    for at in [300_100, 300_000 + 24 * 60 * 60 + 600] {
        let dir = relaxed_storage_dir().unwrap();
        let OwedInviteWelcome {
            mut runtime,
            adapter,
            wall,
            welcome,
            ..
        } = owed_invite_welcome(dir.path()).await;
        // The relay's acceptance reached storage; the mark after it did not.
        let mut fanout = runtime
            .session()
            .transport_fanout(&welcome.id)
            .unwrap()
            .unwrap();
        for target in &mut fanout.targets {
            target.state = cgka_traits::TransportFanoutAttemptState::Accepted;
        }
        runtime.session().put_transport_fanout(&fanout).unwrap();
        assert_eq!(runtime.outstanding_welcome_deliveries().unwrap().len(), 1);
        let sent = welcome_publishes(&adapter).len();

        wall.set(at);
        runtime.run_due_maintenance().await.unwrap();

        assert!(
            runtime.outstanding_welcome_deliveries().unwrap().is_empty(),
            "at {at}"
        );
        assert_eq!(
            runtime.withdraw_welcome(&welcome.id).unwrap(),
            WelcomeWithdrawal::AlreadyDelivered
        );
        assert_eq!(welcome_publishes(&adapter).len(), sent, "at {at}");
    }
}

/// A Welcome whose commit lost after its relays accepted it, with the
/// delivered mark interrupted, is audited as superseded, not withdrawn, and
/// its retry record goes once its retention passes: no later mark can close
/// it, so nothing keeps retrying one.
#[tokio::test]
async fn a_superseded_welcomes_saved_acceptance_goes_with_its_retention() {
    let dir = relaxed_storage_dir().unwrap();
    let OwedInviteWelcome {
        mut runtime,
        adapter,
        wall,
        group_id,
        welcome,
    } = owed_invite_welcome(dir.path()).await;
    let recorded = welcome_rows(dir.path(), &welcome, &group_id).len();
    let mut fanout = runtime
        .session()
        .transport_fanout(&welcome.id)
        .unwrap()
        .unwrap();
    for target in &mut fanout.targets {
        target.state = cgka_traits::TransportFanoutAttemptState::Accepted;
    }
    runtime.session().put_transport_fanout(&fanout).unwrap();
    // What convergence writes when the commit loses terminally, before it
    // retires the Welcome's row.
    use cgka_traits::storage::MessageStorage as _;
    let origin = runtime
        .session()
        .outbound_welcome_audit_facts(&welcome.id)
        .unwrap()
        .unwrap()
        .origin_commit_id
        .unwrap();
    SqliteAccountStorage::open_encrypted(
        dir.path().join("alice.sqlite"),
        &SqlCipherKey::new("marmot welcome withdrawal key").unwrap(),
    )
    .unwrap()
    .update_message_state(&origin, cgka_traits::MessageState::EpochInvalidated)
    .unwrap();
    let sent = welcome_publishes(&adapter).len();

    wall.set(300_000 + 24 * 60 * 60 + 600);
    runtime.run_due_maintenance().await.unwrap();

    assert!(
        runtime
            .session()
            .transport_fanout(&welcome.id)
            .unwrap()
            .is_none()
    );
    assert_eq!(welcome_publishes(&adapter).len(), sent);
    let rows = welcome_rows(dir.path(), &welcome, &group_id);
    assert_eq!(kinds(&rows[recorded..]), ["welcome_withdrawn"]);
    assert_eq!(rows[recorded]["event"]["reason"], "commit_superseded");
}

/// A pass whose relays answered but whose bookkeeping could not be saved
/// still records what the relays said, with no stored total, before the
/// error returns: an investigator sees the relay answered.
#[tokio::test]
async fn a_pass_whose_bookkeeping_fails_records_the_relays_answers() {
    let dir = relaxed_storage_dir().unwrap();
    let OwedInviteWelcome {
        mut runtime,
        adapter,
        wall,
        group_id,
        welcome,
    } = owed_invite_welcome(dir.path()).await;
    let recorded = welcome_rows(dir.path(), &welcome, &group_id).len();
    adapter.accept_only_endpoints(vec![
        TransportEndpoint("wss://group.example".into()),
        TransportEndpoint("wss://carol-inbox.example".into()),
    ]);
    runtime.arm_finish_stage_failure(welcome.id.clone());

    wall.set(300_100);
    let _ = runtime.run_due_maintenance().await;

    let rows = welcome_rows(dir.path(), &welcome, &group_id);
    let retry = &rows[recorded..];
    assert_eq!(
        kinds(retry),
        ["welcome_publish_started", "welcome_publish_finished"]
    );
    let finished = &retry[1]["event"];
    assert_eq!(finished["results"][0]["status"], "acknowledged", "{finished}");
    assert_eq!(finished["accepted_total_count"], serde_json::Value::Null);
    assert_eq!(finished["policy"], "unknown");
    assert_eq!(finished["retained_state"], "unknown");
}
