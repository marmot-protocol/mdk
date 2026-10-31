//! Kinds sent only in a device group (mdk#2628): heartbeats (457), private
//! KeyPackage requests and hand-offs (459, 460), anomaly alerts (462) and
//! small-state updates and broadcast requests (475, 476). A device reads them
//! only in the device group it trusts. In an ordinary chat
//! they make no row, no host message and no notification, and no host sends
//! one as a custom event.

use super::*;
use crate::notifications::{notification_update_from_event, recover_notification_updates};

const DEVICE_GROUP_KINDS: [u64; 6] = [457, 459, 460, 462, 475, 476];

/// Alice cannot send any of them as a custom event, so she sends each the way
/// a device-group message goes out. Bob's chat shows the custom event and the
/// chat message she sends after them, and nothing of the four.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn device_group_kinds_in_a_chat_are_ignored_and_never_sent_as_custom_events() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let bob_id = home.create_account("bob").unwrap().account_id_hex;
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = device_group_app_at(&dir, relay.clone());
    remember_test_member_inbox(&app, &bob_id, "wss://relay.example");
    let mut bob = app.client("bob").await.unwrap();
    bob.publish_key_package().await.unwrap();
    let mut alice = app.client("alice").await.unwrap();
    let chat = alice.create_group("chat", &[&bob_id]).await.unwrap();
    let chat_hex = hex::encode(chat.as_slice());
    let mut cursor = 0;
    deliver_new(&mut bob, &relay, &mut cursor).await;
    bob.sync().await.unwrap();
    bob.accept_group_invite(&chat).unwrap();

    for kind in DEVICE_GROUP_KINDS {
        assert!(crate::is_reserved_app_event_kind(kind));
        let before = relay.published_events.lock().unwrap().len();
        let refused = alice
            .send_custom_event(&chat, kind, Vec::new(), "{\"v\":1}".to_owned())
            .await;
        assert!(
            matches!(refused, Err(AppError::InvalidAppMessagePayload(_))),
            "kind {kind}: {refused:?}"
        );
        assert_eq!(relay.published_events.lock().unwrap().len(), before);
        assert!(
            alice
                .send_device_group_message(&chat, kind, "{\"v\":1}".to_owned())
                .await
                .unwrap()
        );
    }
    alice
        .send_custom_event(&chat, 30078, Vec::new(), "{\"move\":\"e4\"}".to_owned())
        .await
        .unwrap();
    let (hello, _) = alice
        .send_app_event(
            &chat,
            AppMessageIntent::Chat {
                content: "hello".to_owned(),
            },
        )
        .await
        .unwrap();

    // The host hears of the custom event and the chat message only.
    let summary = deliver_new(&mut bob, &relay, &mut cursor).await;
    let kinds: Vec<u64> = summary
        .messages
        .iter()
        .map(|message| message.kind)
        .collect();
    assert_eq!(kinds, vec![30078, MARMOT_APP_EVENT_KIND_CHAT]);

    // Nothing of the four is stored, in the timeline or the app events.
    let timeline: Vec<u64> = app
        .timeline_messages_with_query(
            "bob",
            TimelineMessageQuery {
                group_id_hex: Some(chat_hex.clone()),
                ..TimelineMessageQuery::default()
            },
        )
        .unwrap()
        .messages
        .iter()
        .map(|message| message.kind)
        .collect();
    assert!(timeline.contains(&30078), "{timeline:?}");
    assert!(
        timeline.contains(&MARMOT_APP_EVENT_KIND_CHAT),
        "{timeline:?}"
    );
    assert!(
        timeline
            .iter()
            .all(|kind| !DEVICE_GROUP_KINDS.contains(kind)),
        "{timeline:?}"
    );
    let stored = app
        .messages_with_query(
            "bob",
            AppMessageQuery {
                group_id_hex: Some(chat_hex),
                kinds: Some(DEVICE_GROUP_KINDS.to_vec()),
                limit: None,
            },
        )
        .unwrap();
    assert!(stored.is_empty(), "{stored:?}");

    // Only the chat message notifies, live or recovered from storage.
    let live: Vec<_> = summary
        .messages
        .iter()
        .filter_map(|message| {
            notification_update_from_event(
                &app,
                &MarmotAppEvent::MessageReceived(RuntimeMessageReceived {
                    account_id_hex: bob_id.clone(),
                    account_label: "bob".to_owned(),
                    message: message.clone(),
                }),
            )
            .unwrap()
        })
        .map(|update| update.message_id_hex)
        .collect();
    assert_eq!(live, vec![Some(hello.id.clone())]);
    let recovered: Vec<_> = recover_notification_updates(&app, None)
        .unwrap()
        .into_iter()
        .filter(|update| update.account_id_hex == bob_id)
        .map(|update| update.message_id_hex)
        .collect();
    assert_eq!(recovered, vec![Some(hello.id)]);
}
