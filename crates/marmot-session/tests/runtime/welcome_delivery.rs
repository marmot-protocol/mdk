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
/// id. Maintenance's retry is audited as the first pass is, owed or already
/// delivered; without that a Welcome that reaches a relay only on a retry
/// leaves no sender evidence of the delivery.
#[tokio::test]
async fn every_pass_over_a_welcome_records_its_publish_rows() {
    for delivered in [false, true] {
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
        if delivered {
            // As if another inbox relay had met the policy: the retry of
            // this one still runs.
            runtime
                .session()
                .mark_sent_welcome_delivered(&welcome.id)
                .unwrap();
        }
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
            ["welcome_publish_started", "welcome_publish_finished"],
            "delivered: {delivered}"
        );
        assert_eq!(retry[0]["event"]["attempt_id"], retry[1]["event"]["attempt_id"]);
        assert_ne!(retry[0]["event"]["attempt_id"], first[1]["event"]["attempt_id"]);
        assert_eq!(retry[0]["event"]["op_id"], first[0]["event"]["op_id"]);
        assert_eq!(retry[1]["event"]["policy"], "met");
        assert_eq!(
            retry[1]["event"]["retained_state"],
            if delivered { "completed" } else { "unknown" }
        );
    }
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
