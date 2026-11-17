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
        welcome,
        ..
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
    wall.set(300_100);
    let effects = runtime.run_due_maintenance().await.unwrap();
    assert_eq!(welcome_publishes(&adapter).len(), tried + 1, "the retry ran");
    assert!(!exposed(&runtime), "the retry reached no relay either");
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
