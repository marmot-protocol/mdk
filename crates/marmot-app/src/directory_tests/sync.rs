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
