//! A host's group change names itself on its fanout (mdk#2332).
//!
//! A later pass that rolls the change back reads that name to record it as
//! not delivered, for the host to read and acknowledge. The runtime's own
//! commits carry no name and are never recorded. The session's runtime tests
//! own the record's lifecycle; this test owns the host commands' wiring.
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_host_group_change_names_itself_on_its_fanout() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://not-delivered.example")
        .with_test_relay_client(relay.clone());
    let mut client = client_on_app_relay_plane(&app, "alice").await;
    let mut groups = Vec::new();
    for name in ["host change", "automatic change"] {
        groups.push(
            client
                .create_group(name, &[])
                .await
                .unwrap()
                .operation
                .expect("eligible fixture members"),
        );
    }
    let [host, automatic] = groups.as_slice() else {
        unreachable!()
    };
    let (host, automatic) = (host.clone(), automatic.clone());
    relay.fail_publishes_as_unavailable();

    let _unresolved = client
        .update_group_profile(&host, Some("renamed"), None)
        .await;
    client
        .runtime
        .send(cgka_traits::engine::SendIntent::SelfUpdate {
            group_id: automatic.clone(),
        })
        .await
        .unwrap();

    for (group, kind) in [(&host, Some("update_group_data")), (&automatic, None)] {
        let fanouts = client
            .runtime
            .session()
            .outbound_fanouts_for_group(group)
            .unwrap();
        let [fanout] = fanouts.as_slice() else {
            panic!("one unresolved commit: {fanouts:?}")
        };
        assert!(matches!(
            fanout.mls_state(),
            cgka_traits::FanoutMlsState::Pending(_)
        ));
        assert_eq!(fanout.host_change_kind(), kind);
        assert!(
            client
                .group_changes_not_delivered(group)
                .unwrap()
                .is_empty()
        );
    }

    let unknown = hex::encode(
        client
            .runtime
            .session()
            .outbound_fanouts_for_group(&host)
            .unwrap()[0]
            .message_id()
            .as_slice(),
    );
    assert!(
        !client
            .acknowledge_change_not_delivered(&host, &unknown)
            .unwrap(),
        "a commit with no record acknowledges nothing"
    );
    assert!(
        client
            .acknowledge_change_not_delivered(&host, "not hex")
            .is_err()
    );
}
