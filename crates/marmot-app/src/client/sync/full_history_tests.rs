//! Explicit repair continuation: actual adapter coverage, checkpointed summaries,
//! and attempt identity. Short quanta are available only in the test-policy build.
use super::*;
use crate::tests::{ScriptedPushRelayClient, client_on_app_relay_plane};
use crate::{MarmotApp, MarmotAppConfig};
use marmot_account::AccountHome;
use std::sync::Arc;
#[cfg(feature = "test-policy-overrides")]
use std::sync::atomic::AtomicUsize;
#[cfg(feature = "test-policy-overrides")]
use tokio::sync::Notify;

fn fixture() -> (tempfile::TempDir, MarmotApp, Arc<ScriptedPushRelayClient>) {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay_and_config(
        dir.path(),
        "wss://relay.example".to_owned(),
        MarmotAppConfig::default()
            .with_dev_epoch_backfill_execution_quantum_ms(10)
            .with_dev_epoch_backfill_eose_wait_ms(1_000),
    )
    .with_test_relay_client(relay.clone());
    (dir, app, relay)
}

#[cfg(feature = "test-policy-overrides")]
async fn report(
    plane: &crate::MarmotRelayPlane,
    subscriptions: &[transport_nostr_adapter::NostrSubscription],
) {
    for subscription in subscriptions {
        for endpoint in subscription.endpoints() {
            plane
                .handle_relay_eose_for_test(endpoint.clone(), subscription.subscription_id())
                .await;
        }
    }
}

#[tokio::test]
async fn missing_eose_exhausts_overall_budget_and_retains_prefix() {
    let (_dir, app, relay) = fixture();
    let mut client = client_on_app_relay_plane(&app, "alice").await;
    let before = relay.subscription_count();
    let prefix = SyncSummary {
        joined_groups: vec![GroupId::new(vec![42])],
        ..Default::default()
    };
    client.pending_failed_sync_summary.merge(prefix.clone());
    // Exercise missing EOSE after activation, not the speed of route/signing
    // setup. Under CI load an 80 ms end-to-end budget can expire before the
    // repair activates; that correctly leaves the prefix buffered for later.
    client.runtime.activate_transport(None).await.unwrap();
    let (summary, verdict) = client
        .drain_full_history_repair(
            &mut DrainCounts::default(),
            &FullHistoryRepairControl {
                started: Instant::now(),
                timeout: Duration::from_millis(80),
                cancelled: &|| false,
            },
        )
        .await
        .unwrap();
    let failure = client
        .finish_full_history_repair(summary, verdict)
        .await
        .unwrap_err();
    assert!(
        failure
            .source
            .to_string()
            .contains("full_history_repair_deadline")
    );
    assert_eq!(failure.partial_summary, prefix);
    assert_eq!(
        relay.subscription_count(),
        before + 1,
        "one activation across all slices"
    );
}

#[cfg(feature = "test-policy-overrides")]
#[tokio::test]
async fn delayed_eose_completes_same_attempt_across_multiple_checkpoints() {
    let (_dir, app, relay) = fixture();
    let mut client = client_on_app_relay_plane(&app, "alice").await;
    let before = relay.subscription_count();
    let prefix = SyncSummary {
        joined_groups: vec![GroupId::new(vec![42])],
        ..Default::default()
    };
    client.pending_failed_sync_summary.merge(prefix.clone());
    let checks = AtomicUsize::new(0);
    let ready = Notify::new();
    // Entry and pre-activation are the first two checks, followed by one per
    // drain. Wait until several completed drains have yielded before EOSE.
    let cancelled = || {
        if checks.fetch_add(1, Ordering::SeqCst) >= 5 {
            ready.notify_one();
        }
        false
    };
    let control = FullHistoryRepairControl {
        started: Instant::now(),
        timeout: Duration::from_secs(2),
        cancelled: &cancelled,
    };
    let (result, ()) = tokio::join!(client.repair_full_history_with_control(&control), async {
        ready.notified().await;
        let subscriptions = relay.accepted_subscriptions();
        assert_eq!(subscriptions.len(), before + 1);
        report(&app.relay_plane, &subscriptions[before..]).await;
    });
    assert_eq!(
        result.unwrap(),
        prefix,
        "each durable prefix is returned exactly once"
    );
    assert!(checks.load(Ordering::SeqCst) >= 6);
    assert_eq!(
        relay.subscription_count(),
        before + 1,
        "EOSE belongs to the original attempt"
    );
}

#[cfg(feature = "test-policy-overrides")]
#[tokio::test]
async fn cancellation_retains_prefix_and_old_eose_cannot_complete_next_attempt() {
    let (_dir, app, relay) = fixture();
    let mut client = client_on_app_relay_plane(&app, "alice").await;
    let before = relay.subscription_count();
    let prefix = SyncSummary {
        joined_groups: vec![GroupId::new(vec![42])],
        ..Default::default()
    };
    client.pending_failed_sync_summary.merge(prefix.clone());
    let checks = AtomicUsize::new(0);
    let cancelled = || checks.fetch_add(1, Ordering::SeqCst) >= 4;
    let failure = client
        .repair_full_history_with_control(&FullHistoryRepairControl {
            started: Instant::now(),
            timeout: Duration::from_secs(2),
            cancelled: &cancelled,
        })
        .await
        .unwrap_err();
    assert!(
        failure
            .source
            .to_string()
            .contains("full_history_repair_cancelled")
    );
    assert_eq!(failure.partial_summary, prefix);
    let old = relay.accepted_subscriptions();
    assert_eq!(old.len(), before + 1);
    let control = FullHistoryRepairControl {
        started: Instant::now(),
        timeout: Duration::from_millis(100),
        cancelled: &|| false,
    };
    let (result, ()) = tokio::join!(client.repair_full_history_with_control(&control), async {
        while relay.subscription_count() == old.len() {
            tokio::task::yield_now().await;
        }
        report(&app.relay_plane, &old[before..]).await;
    });
    let failure = result.unwrap_err();
    assert!(
        failure
            .source
            .to_string()
            .contains("full_history_repair_deadline")
    );
    assert_eq!(relay.subscription_count(), before + 2);
    assert_eq!(
        failure.partial_summary,
        SyncSummary::default(),
        "old prefix is not emitted twice"
    );
}

#[tokio::test]
async fn cancelled_before_start_does_not_activate_or_clear_overflow() {
    let (_dir, app, relay) = fixture();
    let mut client = client_on_app_relay_plane(&app, "alice").await;
    let before = relay.subscription_count();
    app.account_storage("alice")
        .unwrap()
        .mark_account_delivery_recovery("alice", 7, 1)
        .unwrap();
    client.delivery_overflow_recovery_pending = true;
    client.delivery_overflow_recovery_marker_token = Some(7);
    let failure = client
        .repair_full_history_cancellable(&|| true)
        .await
        .unwrap_err();
    assert!(
        failure
            .source
            .to_string()
            .contains("full_history_repair_cancelled")
    );
    assert_eq!(relay.subscription_count(), before);
    assert!(
        app.account_storage("alice")
            .unwrap()
            .account_delivery_recovery("alice")
            .unwrap()
            .is_some()
    );
}

#[cfg(feature = "test-policy-overrides")]
#[tokio::test]
async fn delayed_overflow_repair_clears_only_its_own_durable_generation() {
    for advance_generation in [false, true] {
        let (_dir, app, relay) = fixture();
        let mut client = client_on_app_relay_plane(&app, "alice").await;
        let before = relay.subscription_count();
        let storage = app.account_storage("alice").unwrap();
        storage
            .mark_account_delivery_recovery("alice", 7, 1)
            .unwrap();
        client.delivery_overflow_recovery_pending = true;
        client.delivery_overflow_recovery_marker_token = Some(7);
        let checks = AtomicUsize::new(0);
        let ready = Notify::new();
        let cancelled = || {
            if checks.fetch_add(1, Ordering::SeqCst) >= 6 {
                ready.notify_one();
            }
            false
        };
        let control = FullHistoryRepairControl {
            started: Instant::now(),
            timeout: Duration::from_secs(2),
            cancelled: &cancelled,
        };
        let (result, ()) = tokio::join!(client.repair_full_history_with_control(&control), async {
            ready.notified().await;
            if advance_generation {
                storage
                    .mark_account_delivery_recovery("alice", 8, 2)
                    .unwrap();
            }
            report(&app.relay_plane, &relay.accepted_subscriptions()[before..]).await;
        });
        assert_eq!(relay.subscription_count(), before + 1);
        assert_eq!(result.is_ok(), !advance_generation);
        assert_eq!(
            storage
                .account_delivery_recovery("alice")
                .unwrap()
                .is_some(),
            advance_generation
        );
        assert_eq!(
            client.delivery_overflow_recovery_pending,
            advance_generation
        );
    }
}

#[tokio::test]
async fn unfinished_overflow_repair_survives_reopen() {
    let (dir, app, relay) = fixture();
    let mut client = client_on_app_relay_plane(&app, "alice").await;
    app.account_storage("alice")
        .unwrap()
        .mark_account_delivery_recovery("alice", 7, 1)
        .unwrap();
    client.delivery_overflow_recovery_pending = true;
    client.delivery_overflow_recovery_marker_token = Some(7);
    let result = client
        .repair_full_history_with_control(&FullHistoryRepairControl {
            started: Instant::now(),
            timeout: Duration::from_millis(80),
            cancelled: &|| false,
        })
        .await;
    assert!(result.is_err());
    drop(client);
    drop(app);
    let reopened =
        MarmotApp::with_relay(dir.path(), "wss://relay.example").with_test_relay_client(relay);
    assert!(
        reopened
            .account_storage("alice")
            .unwrap()
            .account_delivery_recovery("alice")
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn one_fast_endpoint_cannot_complete_full_history_repair() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relays_and_config(
        dir.path(),
        vec![
            "wss://fast.example".to_owned(),
            "wss://slow.example".to_owned(),
        ],
        MarmotAppConfig::default().with_dev_epoch_backfill_execution_quantum_ms(10),
    )
    .with_test_relay_client(relay.clone());
    let mut client = client_on_app_relay_plane(&app, "alice").await;
    let before = relay.subscription_count();
    let control = FullHistoryRepairControl {
        started: Instant::now(),
        timeout: Duration::from_millis(80),
        cancelled: &|| false,
    };
    let (result, ()) = tokio::join!(client.repair_full_history_with_control(&control), async {
        while relay.subscription_count() == before {
            tokio::task::yield_now().await;
        }
        for subscription in &relay.accepted_subscriptions()[before..] {
            assert_eq!(subscription.endpoints().len(), 2);
            app.relay_plane
                .handle_relay_eose_for_test(
                    subscription.endpoints()[0].clone(),
                    subscription.subscription_id(),
                )
                .await;
        }
    });
    assert!(result.is_err());
    let coverage = client.adapter.account_subscription_eose().await;
    assert!(coverage.any());
    assert!(!coverage.complete());
    assert_eq!(relay.subscription_count(), before + 1);
}
