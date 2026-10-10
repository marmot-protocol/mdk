use super::*;
use crate::MarmotApp;
use marmot_account::AccountHome;
use storage_sqlite::{AttachmentDemand, StoredAccountGroup, StoredAccountState, StoredAppEvent};
fn group(pending: bool) -> StoredAccountGroup {
    StoredAccountGroup {
        group_id_hex: "aa".into(),
        endpoint: String::new(),
        profile_name: String::new(),
        profile_description: String::new(),
        image_hash_hex: String::new(),
        image_key_hex: String::new(),
        image_nonce_hex: String::new(),
        image_upload_key_hex: String::new(),
        image_media_type: None,
        admin_keys_hex: String::new(),
        archived: false,
        pending_confirmation: pending,
        member_count: None,
        direct_member_ids_hex: None,
        presentation_member_ids_hex: None,
        welcomer_account_id_hex: None,
        via_welcome_message_id_hex: None,
        nostr_routing_last_epoch: 0,
        prior_nostr_routes: vec![],
        self_membership: Default::default(),
        components: vec![storage_sqlite::StoredAccountGroupComponent {
            component_id: crate::NOSTR_ROUTING_COMPONENT_ID,
            component_name: "marmot.group.nostr.routing.v1".into(),
            component_data_hex: hex::encode(
                cgka_traits::app_components::encode_nostr_routing_v1(
                    &cgka_traits::app_components::NostrRoutingV1::new(
                        [0xaa; 32],
                        vec!["wss://relay.example".into()],
                    )
                    .unwrap(),
                )
                .unwrap(),
            ),
        }],
    }
}

fn seed(s: &storage_sqlite::SqliteAccountStorage, id: u64) -> storage_sqlite::AttachmentAssetRef {
    s.save_account_projection_state(
        &StoredAccountState {
            label: "alice".into(),
            groups: vec![group(false)],
            ..Default::default()
        },
        100,
        300,
    )
    .unwrap();
    let group = "aa";
    let message = format!("{id:064x}");
    s.record_app_event(&StoredAppEvent {
        group_id_hex: group.into(),
        message_id_hex: message.clone(),
        source_message_id_hex: Some(message.clone()),
        source_epoch: Some(0),
        direction: "received".into(),
        sender: "11".repeat(32),
        plaintext: "secret caption".into(),
        kind: 9,
        tags: vec![vec![
            "imeta".into(),
            "v future".into(),
            "m image/png".into(),
            format!("x {}", "00".repeat(32)),
        ]],
        recorded_at: id,
        received_at: id,
        origin_commit_id: None,
        moderation_grant: false,
    })
    .unwrap();
    let entry = s
        .attachment_control_entry(group, &message, &message, 0, crate::unix_now_seconds())
        .unwrap()
        .unwrap();
    match s
        .request_attachment_acquisition(group, &entry, [0; 32], crate::unix_now_seconds())
        .unwrap()
    {
        AttachmentDemand::Requested(r) => r,
        _ => panic!("source"),
    }
}
#[tokio::test]
async fn group_health_projection_keeps_accounts_actions_feed_and_diagnostics_scoped() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    home.create_account("bob").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let s = app.account_storage("alice").unwrap();
    let rt = app.runtime();
    seed(&s, 1);
    let q = AttachmentJobQuery {
        group_id_hex: Some("aa".into()),
        ..Default::default()
    };
    let f = rt
        .attachment_management_snapshot("alice", q.clone())
        .await
        .unwrap();
    assert!(f.available);
    assert_eq!(f.automatic_recovery_failed, Some(false));
    assert_eq!(f.counts.active + f.counts.paused, 1);
    let diagnostics = f.redacted_diagnostics();
    assert!(diagnostics.len() < 4096);
    for value in [
        "alice",
        "aa",
        "secret caption",
        "image/png",
        "https:",
        &"11".repeat(32),
    ] {
        assert!(!diagnostics.contains(value));
    }
    assert!(!format!("{f:?}").contains("secret"));
    let action = f.page.entries[0].action.clone();
    assert!(
        !rt.control_managed_attachment("bob", action.clone(), false)
            .await
            .unwrap()
    );
    let sub = rt
        .subscribe_attachment_management("alice", q.clone())
        .await
        .unwrap();
    assert!(sub.next().await.unwrap().is_some());
    rt.accounts
        .app
        .presentation_signals
        .account_resets
        .send("bob".into())
        .unwrap();
    rt.events
        .send(super::super::MarmotAppEvent::HistoryNoticesChanged {
            account_id_hex: "00".repeat(32),
            account_label: "bob".into(),
        })
        .unwrap();
    // Force a cancellable coalescing window without changing production timing.
    sub.state.lock().await.last = tokio::time::Instant::now() + Duration::from_secs(1);

    assert!(
        rt.control_managed_attachment("alice", action.clone(), true)
            .await
            .unwrap()
    );
    assert!(
        !rt.control_managed_attachment("alice", action, false)
            .await
            .unwrap()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(20), sub.next())
            .await
            .is_err()
    );
    assert!(
        sub.state.lock().await.dirty,
        "a dropped next call must retain its invalidation"
    );
    sub.state.lock().await.last = tokio::time::Instant::now() - Duration::from_secs(1);
    let next = tokio::time::timeout(Duration::from_secs(3), sub.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(next.counts.active, 1);
    assert!(!next.version.same_as(&f.version));
    sub.close();
    assert!(sub.next().await.unwrap().is_none());
    let cursor = rt
        .begin_attachment_cancellation("alice", Some("aa".into()), false)
        .await
        .unwrap();
    assert!(
        rt.cancel_attachment_batch("bob", cursor.clone())
            .await
            .is_err()
    );
    let cancelled = rt.cancel_attachment_batch("alice", cursor).await.unwrap();
    assert_eq!(cancelled.requested, 1);
    let missing = rt.attachment_management_snapshot("bob", q).await.unwrap();
    assert!(!missing.available);
    assert_eq!(missing.automatic_recovery_failed, None);
    rt.shutdown_and_close().await.unwrap();
    assert!(
        rt.attachment_management_snapshot("alice", AttachmentJobQuery::default())
            .await
            .is_err()
    );
}
