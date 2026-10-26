//! Admitted sends whose group subscription the relay refuses (mdk#2562).

use super::*;

/// mdk#2562's sequence: a group created while its relays refuse REQs,
/// then a token text send and a token draft send. Neither may ever read as
/// `Rejected`, and the draft's timeline row must not turn into a failed send.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn token_sends_to_a_group_with_a_refused_subscription_are_never_rejected() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    runtime.reconcile_accounts().await.unwrap();
    runtime
        .accounts()
        .wait_for_account_network_startup_to_settle("alice")
        .await
        .unwrap();
    relay.refuse_group_subscribes(true);
    let group = runtime
        .create_group_with_options_detailed(
            "alice",
            "unreachable",
            &[],
            crate::AppCreateGroupOptions::default(),
        )
        .await
        .unwrap()
        .group_id;
    let group_hex = hex::encode(group.as_slice());

    let text = runtime
        .submit_text("alice", &group, "text".into(), "text-token".into())
        .await
        .unwrap();
    app.save_message_draft("alice", &group_hex, "draft", None, vec![])
        .unwrap();
    let revision = app
        .selected_message_draft("alice", &group_hex)
        .unwrap()
        .revision;
    let draft = runtime
        .submit_message_draft("alice", &group, revision, vec![], "draft-token".into())
        .await
        .unwrap();

    for token in ["text-token", "draft-token"] {
        let summary = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                match runtime.local_send_status("alice", &group, token).unwrap() {
                    Some(crate::LocalSendStatus::Completed(summary)) => break summary,
                    Some(crate::LocalSendStatus::Rejected) => {
                        panic!("a refused group subscription rejected the send")
                    }
                    Some(_) => tokio::time::sleep(Duration::from_millis(5)).await,
                    None => panic!("the admitted send has no local status"),
                }
            }
        })
        .await
        .expect("the worker hands the admitted send to the engine");
        assert_eq!(
            summary.accept_disposition,
            cgka_traits::SendAcceptDisposition::Published
        );
    }
    let timeline = app
        .timeline_messages_with_query(
            "alice",
            crate::TimelineMessageQuery {
                group_id_hex: Some(group_hex),
                ..crate::TimelineMessageQuery::default()
            },
        )
        .unwrap();
    for accepted in [&text, &draft] {
        let row = timeline
            .messages
            .iter()
            .find(|message| message.message_id_hex == accepted.message_id_hex)
            .expect("each admitted send keeps its timeline row");
        assert!(
            row.invalidation_status.is_none(),
            "no sent row may read as a failed local publish"
        );
    }
    runtime.shutdown().await;
}
