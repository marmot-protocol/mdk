//! Transport-cursor audit rows, driven through real cursor commits and read
//! back from the account's v5 audit file.
use super::recorded_v5_rows;

#[test]
fn cursor_rows_record_settled_advances_and_only_large_live_promotions() {
    // Each step asserts what one commit persisted, and a seal that finds the
    // adapter's state lock taken defers its commit. On one thread no other
    // task runs between a commit's readiness read and its seal.
    crate::tests::run_composed_app_runtime_test_on_one_thread("recovery-audit-cursor", || async {
        let mut fixture = crate::tests::LiveCursorFixture::open_audited().await;
        let cursor_before = fixture.cursor_before;
        // A live promotion within the rebuild lookback writes no row.
        let near = fixture
            .delivery(fixture.probe(cursor_before + 60, "near"))
            .await;
        fixture
            .app
            .relay_plane
            .route_account_delivery_for_test(near);
        fixture.wait_for_queue_depth(1).await;
        fixture.ingest_next_live_delivery().await;
        assert_eq!(fixture.persisted(), Some(cursor_before + 60));
        assert!(recorded_v5_rows(&fixture.app, "transport_cursor_advanced").is_empty());

        // One past the lookback does.
        let far = fixture
            .delivery(fixture.probe(cursor_before + 4_000, "far"))
            .await;
        fixture.app.relay_plane.route_account_delivery_for_test(far);
        fixture.wait_for_queue_depth(1).await;
        fixture.ingest_next_live_delivery().await;
        assert_eq!(fixture.persisted(), Some(cursor_before + 4_000));
        let rows = recorded_v5_rows(&fixture.app, "transport_cursor_advanced");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["event"]["trigger"], "live_promotion");
        assert_eq!(rows[0]["event"]["cursor_before_secs"], cursor_before + 60);
        assert_eq!(rows[0]["event"]["cursor_after_secs"], cursor_before + 4_000);
        assert_eq!(rows[0]["event"]["lookback_secs"], 120);

        // A delivery only that promotion exposed is spilled, and counted.
        let exposed = fixture
            .delivery(fixture.probe(cursor_before + 1_000, "exposed"))
            .await;
        fixture
            .app
            .relay_plane
            .route_account_delivery_for_test(exposed);
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while fixture.client.adapter.delivery_loss_blocks_cursor() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the spill is durable");
        assert!(
            fixture
                .client
                .adapter
                .account_subscription_eose()
                .await
                .complete(),
            "no REQ was issued after the pump stopped"
        );
        fixture.client.synchronize_native_replay().await.unwrap();

        // A drain checkpoint records its advance with that count.
        fixture.client.state.last_transport_timestamp = Some(cursor_before + 5_000);
        fixture
            .client
            .checkpoint_sync_prefix(&mut crate::SyncSummary::default(), false, 0)
            .await
            .unwrap_or_else(|_| panic!("the checkpoint saves"));
        let rows = recorded_v5_rows(&fixture.app, "transport_cursor_advanced");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1]["event"]["trigger"], "drain_checkpoint");
        assert_eq!(
            rows[1]["event"]["cursor_before_secs"],
            cursor_before + 4_000
        );
        assert_eq!(rows[1]["event"]["cursor_after_secs"], cursor_before + 5_000);
        assert_eq!(rows[1]["event"]["spilled_below_floor"], 1);
        assert_eq!(rows[1]["event"]["spilled_queue_full"], 0);
        assert_eq!(rows[1]["event"]["queue_dropped"], 0);
        assert!(rows.iter().all(|row| row["group_ref"].is_null()));
    });
}
