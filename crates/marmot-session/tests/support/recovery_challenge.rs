async fn issue_recovery_challenge(peers: &mut RecoveryPeers) -> TransportMessage {
    let RecoveryPeers {
        coordinator,
        recipient,
        adapter,
        bob_adapter,
        wall,
        ..
    } = peers;
    let alice_id = coordinator.self_id();
    let bob_id = recipient.self_id();
    let mut selected = recipient.prepare_group_recovery().unwrap();
    if selected == vec![bob_id.clone()] {
        // This fixture has no healthy sibling. Let the own-account fallback
        // expire normally before the next known-admin turn.
        recipient
            .advance_group_recovery(&[], &mut AccountDeviceEffects::default())
            .await
            .unwrap();
        wall.set(wall.now().0 + 601);
        coordinator.prepare_group_recovery().unwrap();
        selected = recipient.prepare_group_recovery().unwrap();
    }
    assert_eq!(selected, vec![alice_id.clone()]);
    recipient
        .advance_group_recovery(&[], &mut AccountDeviceEffects::default())
        .await
        .unwrap();
    let request = bob_adapter.publishes().pop().unwrap().message;
    let received = coordinator
        .ingest_delivery(&recovery_inbox_delivery(alice_id.clone(), request))
        .await
        .unwrap();
    assert!(
        matches!(
            received.outcome,
            cgka_traits::IngestOutcome::GroupRecovery { .. }
        ) && !received.left_object_unpersisted,
        "current device remains eligible after its old leaf position changes"
    );
    coordinator.prepare_group_recovery().unwrap();
    coordinator
        .advance_group_recovery(&[], &mut AccountDeviceEffects::default())
        .await
        .unwrap();
    adapter.publishes().pop().unwrap().message
}
