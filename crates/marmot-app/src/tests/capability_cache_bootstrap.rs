use super::*;
use cgka_traits::storage::CapabilityStorage;

#[tokio::test]
async fn undecodable_capability_cache_does_not_brick_account_bootstrap() {
    // Cover both first open through 0108 and corruption after migration.
    for pending_migration in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        let mut client = app.client("alice").await.unwrap();
        let bad = client.create_group("bad cache", &[]).await.unwrap();
        let good = client.create_group("good cache", &[]).await.unwrap();
        let store = app.account_storage("alice").unwrap();
        let member = store.get_group(&bad).unwrap().members[0].id.clone();
        let expected = store.member_capabilities(&bad, &member).unwrap().unwrap();
        let good_before = store.member_capabilities(&good, &member).unwrap();
        let path = app.account_storage_path("alice");
        let keys = app.account_home().load_signing_keys("alice").unwrap();
        let key = app
            .sqlcipher_key("alice", &keys, &path, SqlcipherDatabaseKind::Session)
            .unwrap();
        drop(client);
        drop(store);
        app.close_storage().unwrap();
        drop(app);
        let connection = rusqlite::Connection::open(&path).unwrap();
        storage_sqlite::open_hardened_sqlcipher(
            &connection,
            &key,
            storage_sqlite::SqlCipherHardening::cipher_only(),
        )
        .unwrap();
        // The actual unshipped checkpoint envelope is deliberately undecodable.
        connection
            .execute(
                "UPDATE cgka_member_capabilities SET capabilities = ?2 WHERE group_id = ?1",
                rusqlite::params![bad.as_slice(), br#"{"leaves":{}}"#.as_slice()],
            )
            .unwrap();
        if pending_migration {
            connection
                .execute("DELETE FROM cgka_schema_migrations WHERE version = 108", [])
                .unwrap();
        }
        drop(connection);
        let app =
            MarmotApp::with_relay(dir.path(), "wss://relay.example").with_test_relay_client(relay);
        let mut client = app
            .client("alice")
            .await
            .expect("cache corruption must not prevent bootstrap");
        let store = app.account_storage("alice").unwrap();
        assert_eq!(store.member_capabilities(&bad, &member).unwrap(), None);
        assert_eq!(
            store.member_capabilities(&good, &member).unwrap(),
            good_before
        );
        // A real MLS self-update uses the existing own-leaf cache refresh.
        let effects = client
            .runtime
            .send(cgka_traits::engine::SendIntent::SelfUpdate {
                group_id: bad.clone(),
            })
            .await
            .unwrap();
        client.finish_maintenance_effects(&effects).await.unwrap();
        assert_eq!(
            store.member_capabilities(&bad, &member).unwrap(),
            Some(expected)
        );
        assert_eq!(
            store.member_capabilities(&good, &member).unwrap(),
            good_before
        );
        assert!(client.quarantined_groups().is_empty());
    }
}
