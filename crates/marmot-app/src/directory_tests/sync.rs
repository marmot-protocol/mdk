//! The directory sync worker over a real `MarmotApp`, whose block lists and
//! account locks are the app's. The worker's own tests stay with the worker.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use nostr::prelude::FinalizeEvent;
use tokio::sync::{mpsc, oneshot};
use transport_nostr::MarmotRelayPlane;

use crate::MarmotApp;
use nostr_directory::DirectorySyncHandle;
use nostr_directory::{DirectorySyncCommand, run_directory_sync_worker};

async fn wait_for_background_rebuild_flag_to_clear(handle: &DirectorySyncHandle) {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while handle.rebuild_queued() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("worker should clear queued rebuild flag after dequeuing the rebuild command");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worker_clears_background_rebuild_flag_when_dequeuing_command() {
    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let relay_plane =
        MarmotRelayPlane::with_subscription_rebuild_lookback(std::time::Duration::from_secs(30));
    let handle = DirectorySyncHandle::spawn_for_test(app.directory(), relay_plane);

    handle.request_rebuild_for_test();
    wait_for_background_rebuild_flag_to_clear(&handle).await;

    handle.request_rebuild_for_test();
    wait_for_background_rebuild_flag_to_clear(&handle).await;

    handle.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocked_account_lock_does_not_stall_directory_drain_or_rebuild_completion() {
    use std::time::Duration;
    use transport_nostr::{DirectoryRelayEventRecord, DirectoryRelayPlaneEvent};
    use transport_nostr_peeler::NostrTransportEvent;

    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relays(dir.path(), vec![]);
    app.account_home().create_account("alice").unwrap();
    let keys = app.account_home().load_signing_keys("alice").unwrap();
    let storage = app.account_storage("alice").unwrap();
    let lock = app.block_update_lock("alice").await;
    let guard = lock.lock().await;
    let (commands, command_rx) = mpsc::channel(32);
    let (events, event_rx) = tokio::sync::broadcast::channel(64);
    let worker = tokio::spawn(run_directory_sync_worker(
        app.directory(),
        app.relay_plane.clone(),
        command_rx,
        event_rx,
        Arc::new(AtomicBool::new(false)),
    ));
    let mute = nostr::prelude::EventBuilder::new(nostr::prelude::Kind::MuteList, "")
        .finalize(&keys)
        .unwrap();
    // Fill and exceed the bounded adoption task set while its account is
    // busy. Public records and rebuild responses must still be serviced.
    for _ in 0..40 {
        events
            .send(DirectoryRelayPlaneEvent::Record(
                DirectoryRelayEventRecord {
                    endpoints: vec![],
                    event: NostrTransportEvent::from_nostr_event(&mute).unwrap(),
                },
            ))
            .unwrap();
    }
    let remote = nostr::prelude::Keys::generate();
    let profile = nostr::prelude::EventBuilder::new(
        nostr::prelude::Kind::Metadata,
        r#"{"name":"directory stays live"}"#,
    )
    .finalize(&remote)
    .unwrap();
    events
        .send(DirectoryRelayPlaneEvent::Record(
            DirectoryRelayEventRecord {
                endpoints: vec![],
                event: NostrTransportEvent::from_nostr_event(&profile).unwrap(),
            },
        ))
        .unwrap();
    let (respond, response) = oneshot::channel();
    commands
        .send(DirectorySyncCommand::Rebuild {
            respond: Some(respond),
        })
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), response)
        .await
        .expect("rebuild response must not wait for block reconciliation")
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if app
                .directory()
                .directory_entry_for_test(&remote.public_key().to_hex())
                .unwrap()
                .is_some_and(|entry| entry.profile.is_some())
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("blocked adoption must not park the directory event drain");
    commands.send(DirectorySyncCommand::Shutdown).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), worker)
        .await
        .unwrap()
        .unwrap();
    drop(guard);
    assert_eq!(
        storage.app_storage().block_list_revision().unwrap(),
        0,
        "queued adoption is cancelled at shutdown"
    );
}

/// Raw relay frames traverse the production SDK, live forwarder, sync worker,
/// and both real directory stores; a second author's profile fences the drain.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_directory_forgery_cannot_change_persisted_metadata() {
    use crate::MarmotAppConfig;
    use cgka_traits::TransportEndpoint;
    use futures::{SinkExt, StreamExt};
    use nostr::prelude::{Event, EventBuilder, Keys, Kind, Tag, Timestamp};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tokio::net::TcpListener;
    use tokio::time::timeout;
    use tokio_tungstenite::{accept_async, tungstenite::Message};
    use transport_nostr::{DirectorySyncBatch, DirectorySyncPlan};

    let temp = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let endpoint = TransportEndpoint(url.clone());
    let app = MarmotApp::with_relay_and_config(
        temp.path(),
        url,
        MarmotAppConfig::white_noise().with_allow_loopback_relay_endpoints(true),
    );
    app.account_home().create_account("alice").unwrap();
    let keys = app.account_home().load_signing_keys("alice").unwrap();
    let author = keys.public_key().to_hex();
    let fence_keys = Keys::generate();
    let fence_author = fence_keys.public_key().to_hex();
    let first_follow = Keys::generate().public_key().to_hex();
    let second_follow = Keys::generate().public_key().to_hex();
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 30;
    let records = |stamp, newer| {
        [
            (
                0,
                vec![],
                if newer {
                    r#"{"name":"newer"}"#
                } else {
                    r#"{"name":"original"}"#
                },
            ),
            (
                3,
                vec![
                    Tag::parse(["p", if newer { &second_follow } else { &first_follow }]).unwrap(),
                ],
                "",
            ),
            (
                10002,
                vec![
                    Tag::parse([
                        "r",
                        if newer {
                            "wss://newer.example"
                        } else {
                            "wss://original.example"
                        },
                    ])
                    .unwrap(),
                ],
                "",
            ),
            (
                10050,
                vec![
                    Tag::parse([
                        "relay",
                        if newer {
                            "wss://newer-inbox.example"
                        } else {
                            "wss://original-inbox.example"
                        },
                    ])
                    .unwrap(),
                ],
                "",
            ),
        ]
        .into_iter()
        .map(|(kind, tags, content)| {
            EventBuilder::new(Kind::from(kind), content)
                .tags(tags)
                .custom_created_at(Timestamp::from_secs(stamp))
                .finalize(&keys)
                .unwrap()
        })
        .collect::<Vec<Event>>()
    };
    let initial = records(stamp, false);
    let newer = records(stamp + 1, true);
    let (send_frames, mut frames) = mpsc::channel::<Vec<Event>>(4);
    let (ready, registered) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = accept_async(stream).await.unwrap();
        let subscription = loop {
            let message = socket.next().await.unwrap().unwrap();
            let Message::Text(text) = message else {
                continue;
            };
            let request: serde_json::Value = serde_json::from_str(&text).unwrap();
            if request[0] == "REQ" {
                break request[1].as_str().unwrap().to_owned();
            }
        };
        socket
            .send(Message::Text(
                serde_json::json!(["EOSE", subscription]).to_string().into(),
            ))
            .await
            .unwrap();
        ready.send(()).unwrap();
        while let Some(batch) = frames.recv().await {
            for event in batch {
                socket
                    .send(Message::Text(
                        serde_json::json!(["EVENT", subscription, event])
                            .to_string()
                            .into(),
                    ))
                    .await
                    .unwrap();
            }
        }
    });
    let (commands, command_rx) = mpsc::channel(8);
    let worker = tokio::spawn(run_directory_sync_worker(
        app.directory(),
        app.relay_plane.clone(),
        command_rx,
        app.relay_plane.subscribe_directory_events(),
        Arc::new(AtomicBool::new(false)),
    ));
    app.relay_plane
        .sync_directory_user_subscriptions(
            DirectorySyncPlan {
                endpoints: vec![endpoint],
                watched_user_count: 2,
                batches: vec![DirectorySyncBatch {
                    subscription_id: "directory_identity_regression".into(),
                    authors: vec![author.clone(), fence_author.clone()],
                    kinds: vec![0, 3, 10002, 10050],
                    since: None,
                }],
            },
            false,
        )
        .await
        .unwrap();
    timeout(Duration::from_secs(5), registered)
        .await
        .unwrap()
        .unwrap();
    let mut baseline = None;
    for phase in 0..3 {
        let mut batch = if phase == 0 {
            initial.clone()
        } else if phase == 2 {
            newer.clone()
        } else {
            let mut batch = initial.clone(); // Legitimate within-window duplicates.
            for (old, valid) in initial.iter().zip(&newer) {
                let mut tampered = valid.clone();
                tampered.id = old.id;
                batch.push(tampered);
                let mut invalid_signature = valid.clone();
                invalid_signature.sig = nostr::event::Signature::from_byte_array([0; 64]);
                batch.push(invalid_signature);
            }
            batch
        };
        batch.push(
            EventBuilder::new(Kind::Metadata, format!(r#"{{"name":"fence-{phase}"}}"#))
                .custom_created_at(Timestamp::from_secs(stamp + phase + 2))
                .finalize(&fence_keys)
                .unwrap(),
        );
        send_frames.send(batch).await.unwrap();
        timeout(Duration::from_secs(5), async {
            loop {
                if app
                    .directory()
                    .directory_entry_for_account_id(&fence_author)
                    .unwrap()
                    .and_then(|entry| entry.profile)
                    .and_then(|profile| profile.name)
                    .as_deref()
                    == Some(format!("fence-{phase}").as_str())
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("a later authenticated record must reach persistent storage");
        let entry = app
            .directory()
            .directory_entry_for_account_id(&author)
            .unwrap()
            .unwrap();
        let changed = phase == 2;
        assert_eq!(
            entry.profile.as_ref().unwrap().name.as_deref(),
            Some(if changed { "newer" } else { "original" })
        );
        assert_eq!(
            entry.follows,
            vec![if changed {
                second_follow.clone()
            } else {
                first_follow.clone()
            }]
        );
        assert_eq!(
            entry.relay_lists.nip65.relays,
            vec![if changed {
                "wss://newer.example"
            } else {
                "wss://original.example"
            }]
        );
        assert_eq!(
            entry.relay_lists.inbox.relays,
            vec![if changed {
                "wss://newer-inbox.example"
            } else {
                "wss://original-inbox.example"
            }]
        );
        assert_eq!(
            app.directory_caches().unwrap()[0]
                .entry(&author)
                .unwrap()
                .unwrap(),
            entry
        );
        let snapshot = (
            app.directory_caches().unwrap()[0].entry(&author).unwrap(),
            app.shared_storage()
                .unwrap()
                .public_directory_user(&author)
                .unwrap(),
        );
        if phase == 0 {
            baseline = Some(snapshot);
        } else if phase == 1 {
            assert_eq!(
                Some(snapshot),
                baseline,
                "forgeries must leave both stored rows unchanged"
            );
        }
    }
    let expected = app
        .directory()
        .directory_entry_for_account_id(&author)
        .unwrap()
        .unwrap();
    commands.send(DirectorySyncCommand::Shutdown).await.unwrap();
    timeout(Duration::from_secs(5), worker)
        .await
        .unwrap()
        .unwrap();
    app.relay_plane.shutdown().await;
    app.close_storage().unwrap();
    server.abort();
    let _ = server.await;
    let reopened = MarmotApp::with_relays(temp.path(), vec![]);
    assert_eq!(
        reopened
            .directory()
            .directory_entry_for_account_id(&author)
            .unwrap(),
        Some(expected)
    );
    reopened.close_storage().unwrap();
}
