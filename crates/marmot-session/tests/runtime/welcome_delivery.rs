// One delivered mark and one work list for outbound Welcomes (mdk#2628 3.5a).

/// A Welcome whose first pass failed is delivered by a maintenance retry,
/// and that retry marks it delivered: it stops being owed at once, not at
/// the next open.
#[tokio::test]
async fn maintenance_retry_that_lands_settles_the_welcome() {
    let dir = tempfile::tempdir().unwrap();
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
