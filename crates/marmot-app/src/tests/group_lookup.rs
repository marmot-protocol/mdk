use super::*;
use cgka_traits::{DisbandFailureReason, DisbandRequest, DisbandTombstone, EpochId, LeaveRequest};

#[tokio::test]
async fn keyed_group_matches_list() {
    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    app.account_home().create_account("alice").unwrap();
    let mut client = app.client("alice").await.unwrap();
    let group_id = client.create_group("target", &[]).await.unwrap();
    let other_id = client.create_group("other", &[]).await.unwrap();
    drop(client);
    let id_hex = hex::encode(group_id.as_slice());
    let mut state = app.load_state("alice").unwrap();
    state.seen_events = (0..MAX_SEEN_EVENT_IDS)
        .map(|id| format!("{id:064x}"))
        .collect();
    for group in &mut state.groups {
        group.archived = true;
        group.pending_confirmation = true;
        group.member_count = Some(2);
        group.direct_member_ids_hex = Some(vec!["11".repeat(32), "22".repeat(32)]);
        group.presentation_member_ids_hex = group.direct_member_ids_hex.clone();
        group.unknown_components.push(AppGroupOpaqueComponent {
            component_id: 0x9000,
            component: "test.opaque".into(),
            data_hex: "1234".into(),
        });
    }
    app.save_state(&state).unwrap();
    let storage = app.account_storage("alice").unwrap();
    storage
        .set_group_self_membership(&id_hex, SelfMembership::Removed)
        .unwrap();
    let parity = || {
        let keyed = app.group("alice", &id_hex).unwrap().unwrap();
        let listed = app
            .groups("alice")
            .unwrap()
            .into_iter()
            .find(|group| group.group_id_hex == id_hex)
            .unwrap();
        assert!(keyed == listed);
        keyed
    };
    let initial = parity();
    assert!(initial.archived && initial.pending_confirmation);
    assert_eq!(initial.self_membership, SelfMembership::Removed);
    assert_eq!(initial.member_count, Some(2));
    assert_eq!(initial.unknown_components.len(), 1);
    storage
        .put_leave_request(&LeaveRequest {
            group_id: group_id.clone(),
            requested_at_ms: 42,
            last_proposed_epoch: None,
        })
        .unwrap();
    for status in [
        DisbandRequestStatus::Pending,
        DisbandRequestStatus::Failed(DisbandFailureReason::NoLongerAdmin),
    ] {
        storage
            .put_disband_request(&DisbandRequest {
                group_id: group_id.clone(),
                requested_at_ms: 51,
                status,
                last_prepared_epoch: None,
            })
            .unwrap();
        let group = parity();
        assert_eq!(group.leave_requested_at_ms, Some(42));
        assert_eq!(group.disbanding, status == DisbandRequestStatus::Pending);
        assert!(!group.disbanded);
    }

    let path = app.account_storage_path("alice");
    let keys = app.account_home().load_signing_keys("alice").unwrap();
    let key = app
        .sqlcipher_key("alice", &keys, &path, SqlcipherDatabaseKind::Session)
        .unwrap();
    let connection = rusqlite::Connection::open(path).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &connection,
        &key,
        storage_sqlite::SqlCipherHardening::cipher_only(),
    )
    .unwrap();
    // Candidate existence gates the composer without decoding the unused blob.
    connection.execute(
        "INSERT INTO cgka_disband_candidates(group_id,commit_id,record) VALUES (?1,X'01',X'00')",
        [group_id.as_slice()],
    ).unwrap();
    assert!(parity().disbanding);
    storage
        .put_disband_tombstone(
            &group_id,
            &DisbandTombstone {
                epoch: EpochId(0),
                actor: MemberId::new(vec![1; 32]),
                origin_commit_id: None,
                commit_digest: [0; 32],
                local_was_committer_leaf: false,
                former_members: vec![],
                announced: false,
            },
        )
        .unwrap();
    assert!(parity().disbanded);
    storage.clear_leave_request(&group_id).unwrap();
    storage.clear_disband_request(&group_id).unwrap();
    assert_eq!(parity().leave_requested_at_ms, None);
    assert!(parity().disband_request.is_none());

    let listed = app.groups("alice").unwrap();
    connection.execute_batch("DROP TABLE seen_events").unwrap();
    assert!(app.load_state("alice").is_err());
    assert!(app.groups("alice").unwrap() == listed);
    assert!(app.visible_groups("alice").unwrap().is_empty());
    parity();
    assert!(app.group("alice", "missing' OR 1=1 --").unwrap().is_none());
    // Corrupt unrelated rows must not be read by the keyed path.
    connection
        .execute(
            "UPDATE account_groups SET prior_nostr_routes_json='invalid' WHERE group_id_hex=?1",
            [hex::encode(other_id.as_slice())],
        )
        .unwrap();
    assert!(app.groups("alice").is_err());
    assert!(
        app.group("alice", &id_hex).unwrap().unwrap()
            == listed
                .into_iter()
                .find(|group| group.group_id_hex == id_hex)
                .unwrap()
    );
}
