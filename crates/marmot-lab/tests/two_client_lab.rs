use marmot_lab::Lab;

#[tokio::test]
async fn two_clients_exchange_message_through_file_relay() {
    let dir = tempfile::tempdir().unwrap();
    let lab = Lab::new(dir.path());

    lab.init_account("alice").await.unwrap();
    lab.init_account("bob").await.unwrap();
    let mut alice = lab.client("alice").await.unwrap();
    let mut bob = lab.client("bob").await.unwrap();
    bob.publish_key_package().await.unwrap();

    let group = alice.create_group("hello-lab", &["bob"]).await.unwrap();
    let bob_join = bob.sync().await.unwrap();
    assert!(bob_join.joined_groups.contains(&group));

    alice.send(&group, b"hello from the lab").await.unwrap();
    let bob_messages = bob.sync().await.unwrap();

    assert_eq!(
        bob_messages.messages,
        vec![("alice".to_string(), group, "hello from the lab".to_string())]
    );
}

#[tokio::test]
async fn two_clients_exchange_message_through_sdk_mock_relay() {
    let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let lab = marmot_lab::Lab::with_sdk_relay(dir.path(), relay.url().await.to_string());

    lab.init_account("alice").await.unwrap();
    lab.init_account("bob").await.unwrap();
    let mut alice = lab.client("alice").await.unwrap();
    let mut bob = lab.client("bob").await.unwrap();
    bob.publish_key_package().await.unwrap();

    let group = alice.create_group("sdk-lab", &["bob"]).await.unwrap();
    let bob_join = bob.sync().await.unwrap();
    assert!(bob_join.joined_groups.contains(&group));

    alice
        .send(&group, b"hello through sdk relay")
        .await
        .unwrap();
    let bob_messages = bob.sync().await.unwrap();

    assert_eq!(
        bob_messages.messages,
        vec![(
            "alice".to_string(),
            group,
            "hello through sdk relay".to_string()
        )]
    );
}

#[tokio::test]
async fn restart_smoke_reopens_clients_before_sending_through_file_relay() {
    let dir = tempfile::tempdir().unwrap();
    let lab = Lab::new(dir.path());

    let summary = lab.restart_smoke().await.unwrap();

    assert_eq!(
        summary.messages,
        vec![(
            "alice".to_string(),
            summary.group_id,
            "hello after marmot-lab restart".to_string()
        )]
    );
}

#[tokio::test]
async fn restart_smoke_reopens_clients_before_sending_through_sdk_mock_relay() {
    let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let lab = marmot_lab::Lab::with_sdk_relay(dir.path(), relay.url().await.to_string());

    let summary = lab.restart_smoke().await.unwrap();

    assert_eq!(
        summary.messages,
        vec![(
            "alice".to_string(),
            summary.group_id,
            "hello after marmot-lab restart".to_string()
        )]
    );
}
