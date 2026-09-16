use super::*;

#[tokio::test]
async fn report_backfill_retries_entire_batch_after_projection_failure() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://backfill.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let mut client = app.client("alice").await.unwrap();
    let mut groups = vec![
        hex::encode(client.create_group("first", &[]).await.unwrap().as_slice()),
        hex::encode(client.create_group("second", &[]).await.unwrap().as_slice()),
    ];
    groups.sort();
    client.take_pending_projection_updates();
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
    let author = keys.public_key().to_hex();
    let target = hex::encode([11; 32]);
    let report = hex::encode([12; 32]);
    let removal = hex::encode([13; 32]);
    let tags = serde_json::json!([["e", target, "spam"], ["p", author]]).to_string();
    // Model a pre-migration prefix whose raw events have not been projected.
    for group in &groups {
        for (id, kind, tags, content, grant, authority) in [
            (&target, 9, "[]".to_owned(), "retained target", 0, 0),
            (&report, 1984, tags.clone(), "report explanation", 0, 0),
        ]
        .into_iter()
        .chain((group == &groups[1]).then(|| {
            (
                &removal,
                4891,
                serde_json::json!([["e", target]]).to_string(),
                r#"{"v":1,"action":"remove"}"#,
                1,
                2,
            )
        })) {
            connection
                .execute(
                    "INSERT INTO app_events(group_id_hex,message_id_hex,direction,sender,plaintext,
                 kind,tags_json,recorded_at,received_at,moderation_grant,authority_state)
                 VALUES (?1,?2,'received',?3,?4,?5,?6,?7,?7,?8,?9)",
                    rusqlite::params![
                        group,
                        id,
                        author,
                        content,
                        kind,
                        tags,
                        i64::try_from(unix_now_seconds()).unwrap(),
                        grant,
                        authority
                    ],
                )
                .unwrap();
        }
    }
    connection.execute_batch(
        "UPDATE content_report_backfill SET after_order=0,through_order=(SELECT MAX(insert_order) FROM app_events)",
    ).unwrap();
    // The first group's conversion succeeds before the second fails.
    connection
        .execute_batch(&format!(
            "CREATE TRIGGER fail_backfill BEFORE INSERT ON chat_list_rows
         WHEN NEW.group_id_hex='{}'
         BEGIN SELECT RAISE(ABORT,'injected projection failure'); END;",
            groups[1],
        ))
        .unwrap();
    assert!(client.backfill_content_reports().is_err());
    assert!(client.take_pending_projection_updates().is_empty());
    let after: i64 = connection
        .query_row("SELECT after_order FROM content_report_backfill", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(after, 0, "the entire batch must remain retryable");
    let reports: i64 = connection
        .query_row("SELECT count(*) FROM content_reports", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        reports, 0,
        "report projections must roll back with the cursor"
    );
    connection
        .execute_batch("DROP TRIGGER fail_backfill")
        .unwrap();
    client.backfill_content_reports().unwrap();
    let updates = client.take_pending_projection_updates();
    assert_eq!(updates.len(), 2);
    for (index, group) in groups.iter().enumerate() {
        let update = updates.iter().find(|u| &u.group_id_hex == group).unwrap();
        let message = update
            .timeline_messages
            .iter()
            .find(|m| m.message_id_hex == target)
            .unwrap();
        assert!(message.has_reports);
        assert_eq!(message.deleted, index == 1);
        assert_eq!(
            message.plaintext,
            if index == 1 { "" } else { "retained target" }
        );
    }
    let finished: bool = connection
        .query_row(
            "SELECT after_order=through_order FROM content_report_backfill",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(finished);
    client.backfill_content_reports().unwrap();
    assert!(client.take_pending_projection_updates().is_empty());
}
