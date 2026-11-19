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

/// The v5 Welcome rows in the audit at `path` for `welcome`, after checking
/// that each names `group_id`.
fn welcome_rows(
    path: &std::path::Path,
    welcome: &TransportMessage,
    group_id: &GroupId,
) -> Vec<serde_json::Value> {
    let outer = marmot_forensics::v5::NostrEventRef::from_validated_event_id(
        &<[u8; 32]>::try_from(welcome.id.as_slice()).unwrap(),
    );
    let group_ref = marmot_forensics::v5::GroupRef::from_group_id(group_id.as_slice()).unwrap();
    v5_audit_rows(path)
        .into_iter()
        .filter(|row| row["event"]["outer_event_ref"] == outer.as_str())
        .inspect(|row| assert_eq!(row["group_ref"], group_ref.as_str(), "{row}"))
        .collect()
}

/// Maintenance's retry of a Welcome is audited as its first pass is, owed
/// or already delivered: one `welcome_publish_started` and one
/// `welcome_publish_finished` for the Welcome's outer event, in its group.
/// Without them a Welcome that reaches a relay only on a retry leaves no
/// sender evidence of that delivery.
#[tokio::test]
async fn maintenance_retry_of_a_welcome_records_its_publish_rows() {
    for delivered in [false, true] {
        let dir = relaxed_storage_dir().unwrap();
        let OwedInviteWelcome {
            mut runtime,
            adapter,
            wall,
            group_id,
            welcome,
        } = owed_invite_welcome(dir.path()).await;
        if delivered {
            // As if another inbox relay had met the policy: the retry of
            // this one still runs.
            runtime
                .session()
                .mark_sent_welcome_delivered(&welcome.id)
                .unwrap();
        }
        let audit_path = dir.path().join("audit-v5.jsonl");
        runtime
            .audit_recorder()
            .swap(v5_audit_recorder(&audit_path));
        adapter.accept_only_endpoints(vec![
            TransportEndpoint("wss://group.example".into()),
            TransportEndpoint("wss://carol-inbox.example".into()),
        ]);

        wall.set(300_100);
        runtime.run_due_maintenance().await.unwrap();

        let rows = welcome_rows(&audit_path, &welcome, &group_id);
        let kinds = rows
            .iter()
            .map(|row| row["event"]["type"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            kinds,
            ["welcome_publish_started", "welcome_publish_finished"],
            "delivered: {delivered}"
        );
        assert_eq!(rows[0]["event"]["attempt_id"], rows[1]["event"]["attempt_id"]);
        assert_eq!(rows[1]["event"]["policy"], "met");
    }
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
    let audit_path = dir.path().join("audit-v5.jsonl");
    runtime
        .audit_recorder()
        .swap(v5_audit_recorder(&audit_path));
    wall.set(300_100);
    let effects = runtime.run_due_maintenance().await.unwrap();
    assert_eq!(welcome_publishes(&adapter).len(), tried + 1, "the retry ran");
    assert!(!exposed(&runtime), "the retry reached no relay either");
    // The retry's audit row names the refusal, not an unknown result.
    let finished = welcome_rows(&audit_path, &welcome, &group_id)
        .into_iter()
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
