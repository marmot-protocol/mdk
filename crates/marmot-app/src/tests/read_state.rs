//! What A reuses across versions (mdk#3273 PR 2): group entries and the owned
//! KeyPackage list, each until its validity stops holding. A rebuild that
//! finds the published answers keeps them and the version, and the worker
//! publishes an answer that changes with no write when its bound passes
//! (PR 3).

#[cfg(feature = "test-policy-overrides")]
use super::canonical_membership::deliver_new;
#[cfg(feature = "test-policy-overrides")]
use super::push_token_reshare::Device;
use super::*;
use crate::client::read_state::oracle::{
    KeyPackageInputs, LifetimeBound, check_reused_key_packages,
};
use crate::client::read_state::{
    GroupAnswers, ReadState, ReadStatePublisher, UploadsInFlight, read_state_channel,
};
use tokio::sync::watch;

fn entry(state: &watch::Receiver<Arc<ReadState>>, group: &GroupId) -> (u64, Arc<GroupAnswers>) {
    let state = state.borrow();
    (state.version, state.groups[group].clone())
}

/// An application message advances only the message ratchet and stores the
/// message, which no answer in A holds, so the next publish keeps the group's
/// entry and the version; a commit replaces the entry.
#[cfg(feature = "test-policy-overrides")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_application_message_keeps_the_group_entry_and_a_commit_replaces_it() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let mut alice = Device::create(&home, &app, "alice").await;
    let mut bob = Device::create(&home, &app, "bob").await;
    let group = alice
        .client
        .create_group("cached entry", &[&bob.account_id_hex])
        .await
        .unwrap()
        .operation
        .unwrap();
    bob.join(&relay, &group).await;
    bob.client
        .start_read_state(read_state_channel().0, UploadsInFlight::default());
    let state = bob.client.subscribe_read_state().unwrap();
    let (version, joined) = entry(&state, &group);

    alice.client.send(&group, b"cached").await.unwrap();
    let received = deliver_new(&mut bob.client, &relay, &mut bob.cursor).await;
    assert_eq!(received.messages.len(), 1);
    bob.client.publish_read_state();
    let (after_message, kept) = entry(&state, &group);
    assert_eq!(after_message, version, "the stored message moved no answer");
    assert!(Arc::ptr_eq(&joined, &kept));

    alice
        .client
        .update_group_profile(&group, Some("renamed"), None)
        .await
        .unwrap();
    deliver_new(&mut bob.client, &relay, &mut bob.cursor).await;
    bob.client.publish_read_state();
    let (_, renamed) = entry(&state, &group);
    assert!(!Arc::ptr_eq(&joined, &renamed));
}

/// Commit delivery reads only the group's outbound fanouts, so retiring the
/// fanout of a commit a relay still owes is a write to nothing else the
/// entry holds. The publish after it rebuilds the entry, and the oracle that
/// checks every changed publish under test agrees with the live read.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fanout_write_alone_rebuilds_the_group_entry() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relays(
        dir.path(),
        vec![
            "wss://relay-a.example".to_owned(),
            "wss://relay-b.example".to_owned(),
        ],
    )
    .with_test_relay_client(relay.clone());
    let mut client = app.client("alice").await.unwrap();
    let group = client
        .create_group("owed", &[])
        .await
        .unwrap()
        .operation
        .unwrap();
    relay.make_endpoints_unavailable(&["wss://relay-b.example"]);
    client
        .update_group_profile(&group, Some("owed"), None)
        .await
        .unwrap();
    client.start_read_state(read_state_channel().0, UploadsInFlight::default());
    let state = client.subscribe_read_state().unwrap();
    let (_, owed) = entry(&state, &group);
    assert!(
        state
            .borrow()
            .group_commit_delivery(&group)
            .unwrap()
            .is_some()
    );

    let session = client.runtime.session();
    for fanout in session.outbound_fanouts_for_group(&group).unwrap() {
        session.delete_outbound_fanout(fanout.message_id()).unwrap();
    }
    client.publish_read_state();
    let (_, retired) = entry(&state, &group);
    assert!(!Arc::ptr_eq(&owed, &retired));
    assert_eq!(state.borrow().group_commit_delivery(&group).unwrap(), None);
}

/// A write the group's change generation counts makes the next publish
/// rebuild the group's entry; when the rebuild finds the published answers,
/// it keeps the published entry and the version, so hosts see no change and
/// the oracle no changed publish to check.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rebuild_that_finds_the_published_answers_keeps_the_version() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relays(
        dir.path(),
        vec![
            "wss://relay-a.example".to_owned(),
            "wss://relay-b.example".to_owned(),
        ],
    )
    .with_test_relay_client(relay.clone());
    let mut client = app.client("alice").await.unwrap();
    let group = client
        .create_group("rewritten", &[])
        .await
        .unwrap()
        .operation
        .unwrap();
    relay.make_endpoints_unavailable(&["wss://relay-b.example"]);
    client
        .update_group_profile(&group, Some("owed"), None)
        .await
        .unwrap();
    client.start_read_state(read_state_channel().0, UploadsInFlight::default());
    let state = client.subscribe_read_state().unwrap();
    let (version, owed) = entry(&state, &group);
    let generation = |client: &AppClient| {
        client
            .runtime
            .group_change_generations([&group])
            .pop()
            .unwrap()
    };
    let before = generation(&client);

    // Rewrites every fanout row as it was.
    app.account_storage("alice")
        .unwrap()
        .app_storage()
        .execute_batch_for_test("UPDATE cgka_outbound_fanout SET record = record")
        .unwrap();
    assert!(
        !generation(&client).state.unchanged_since(&before.state),
        "the rewrite is a write the group's generation counts"
    );
    client.publish_read_state();
    let (unchanged, kept) = entry(&state, &group);
    assert_eq!(unchanged, version);
    assert!(Arc::ptr_eq(&owed, &kept));
}

/// One unkeyed delete that retires fanouts of two groups, as a bulk path
/// would, is one write per row: the publish after it rebuilds both entries,
/// and the oracle agrees with the live read for each.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bulk_delete_rebuilds_every_group_entry_it_touches() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relays(
        dir.path(),
        vec![
            "wss://relay-a.example".to_owned(),
            "wss://relay-b.example".to_owned(),
        ],
    )
    .with_test_relay_client(relay.clone());
    let mut client = app.client("alice").await.unwrap();
    let groups = [
        client
            .create_group("first", &[])
            .await
            .unwrap()
            .operation
            .unwrap(),
        client
            .create_group("second", &[])
            .await
            .unwrap()
            .operation
            .unwrap(),
    ];
    relay.make_endpoints_unavailable(&["wss://relay-b.example"]);
    for group in &groups {
        client
            .update_group_profile(group, Some("owed"), None)
            .await
            .unwrap();
    }
    client.start_read_state(read_state_channel().0, UploadsInFlight::default());
    let state = client.subscribe_read_state().unwrap();
    let owed: Vec<_> = groups.iter().map(|group| entry(&state, group).1).collect();
    for group in &groups {
        assert!(
            state
                .borrow()
                .group_commit_delivery(group)
                .unwrap()
                .is_some()
        );
    }

    app.account_storage("alice")
        .unwrap()
        .app_storage()
        .execute_batch_for_test("DELETE FROM cgka_outbound_fanout")
        .unwrap();
    client.publish_read_state();
    for (group, owed) in groups.iter().zip(owed) {
        assert!(!Arc::ptr_eq(&owed, &entry(&state, group).1));
        assert_eq!(state.borrow().group_commit_delivery(group).unwrap(), None);
    }
}

/// A failed account read can clear with no write to the database, so A
/// rebuilds account answers at every publish instead of keeping a failure
/// until something writes. Here a TEMP table on the app's connection shadows
/// the prepared-uploads table, failing that read without writing the
/// database, and then goes away.
#[tokio::test]
async fn a_failed_account_read_recovers_without_a_write() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let mut client = app.client("alice").await.unwrap();
    client.start_read_state(read_state_channel().0, UploadsInFlight::default());
    let state = client.subscribe_read_state().unwrap();
    let storage = app.account_storage("alice").unwrap().app_storage();

    storage
        .execute_batch_for_test(
            "CREATE TEMP TABLE app_prepared_group_image_upload (shadow INTEGER)",
        )
        .unwrap();
    client.publish_read_state();
    assert!(state.borrow().account.prepared_group_images.is_err());

    storage
        .execute_batch_for_test("DROP TABLE temp.app_prepared_group_image_upload")
        .unwrap();
    client.publish_read_state();
    assert!(state.borrow().account.prepared_group_images.is_ok());
}

/// A Blossom server that takes one upload and answers it only once
/// released: its URL, a signal that the whole upload arrived, and the
/// release.
async fn held_blossom_upload() -> (String, Arc<tokio::sync::Notify>, watch::Sender<bool>) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let received = Arc::new(tokio::sync::Notify::new());
    let (release, mut released) = watch::channel(false);
    let (server, signal) = (url.clone(), received.clone());
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 16 * 1024];
        let header_end = loop {
            let read = stream.read(&mut buffer).await.unwrap();
            assert!(read > 0, "the upload closed before its headers");
            request.extend_from_slice(&buffer[..read]);
            if let Some(offset) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                break offset + 4;
            }
        };
        let headers = String::from_utf8_lossy(&request[..header_end]).into_owned();
        let header = |name: &str| {
            headers
                .lines()
                .find_map(|line| {
                    let (key, value) = line.split_once(':')?;
                    key.eq_ignore_ascii_case(name)
                        .then(|| value.trim().to_owned())
                })
                .unwrap()
        };
        let length: usize = header("content-length").parse().unwrap();
        let hash = header("x-sha-256");
        while request.len() < header_end + length {
            let read = stream.read(&mut buffer).await.unwrap();
            assert!(read > 0, "the upload closed before its body");
            request.extend_from_slice(&buffer[..read]);
        }
        signal.notify_one();
        released.wait_for(|released| *released).await.unwrap();
        let body = serde_json::json!({ "url": format!("{server}/{hash}.bin"), "sha256": hash })
            .to_string();
        let response = format!(
            "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
    });
    (url, received, release)
}

/// An upload in flight reads `Uploading` from A (mdk#3273 PR 5). The
/// worker's in-flight set is published with A, so both prepared-image reads
/// show the upload `Uploading` while its HTTP is held off the worker, and
/// `Uploaded` once its reply, which publishes first, has arrived. Neither
/// read queues on the worker.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_upload_in_flight_reads_uploading_from_the_published_state() {
    use crate::AppPreparedGroupImageUploadState::{Uploaded, Uploading};
    let (server, received, release) = held_blossom_upload().await;
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay_and_config(
        dir.path(),
        "wss://relay.example",
        crate::MarmotAppConfig::default().with_allow_loopback_blob_endpoints(true),
    )
    .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let runtime = crate::MarmotAppRuntime::new(app);
    runtime.reconcile_accounts().await.unwrap();
    crate::worker_fences::worker_startup_finished(&runtime, "alice")
        .await
        .unwrap();
    let staged = runtime
        .stage_prepared_group_image("alice", one_pixel_png(), "image/png".into())
        .await
        .unwrap();
    let uploading = tokio::spawn({
        let (runtime, upload_id) = (runtime.clone(), staged.upload_id.clone());
        async move {
            runtime
                .upload_prepared_group_image_to_server_for_test("alice", upload_id, server)
                .await
        }
    });
    tokio::time::timeout(Duration::from_secs(10), received.notified())
        .await
        .expect("the upload reaches the server");
    // The worker has left the upload's command since, so it has published
    // the upload it reserved.
    crate::worker_fences::worker_round_trip(&runtime, "alice")
        .await
        .unwrap();
    let telemetry = runtime.shared_services().app_performance_telemetry();
    let queued = || {
        telemetry
            .snapshot()
            .runtime_operations
            .into_iter()
            .find(|sample| sample.operation == crate::RuntimePerformanceOperation::ReadQueueR1)
            .unwrap()
            .started
    };
    let before = queued();
    let states = |images: Vec<crate::AppPreparedGroupImageUpload>| {
        images
            .into_iter()
            .map(|status| (status.upload_id, status.state))
            .collect::<Vec<_>>()
    };

    let status = runtime
        .prepared_group_image_status("alice", staged.upload_id.clone())
        .await
        .unwrap();
    assert_eq!(status.state, Uploading);
    assert_eq!(
        states(runtime.prepared_group_images("alice").await.unwrap()),
        [(staged.upload_id.clone(), Uploading)]
    );

    release.send_replace(true);
    let uploaded = tokio::time::timeout(Duration::from_secs(10), uploading)
        .await
        .expect("the released upload finishes")
        .unwrap()
        .unwrap();
    assert_eq!(uploaded.state, Uploaded);
    let status = runtime
        .prepared_group_image_status("alice", staged.upload_id.clone())
        .await
        .unwrap();
    assert_eq!(status.state, Uploaded);
    assert_eq!(
        states(runtime.prepared_group_images("alice").await.unwrap()),
        [(staged.upload_id, Uploaded)]
    );
    assert_eq!(
        queued(),
        before,
        "a prepared-image read queued on the worker"
    );
    runtime.shutdown_and_close().await.unwrap();
}

/// A answers one upload's status from the version's list, so where the list
/// cannot give today's answer the read asks the worker, whose single-row read
/// answers it (mdk#3273 PR 5). First an upload whose image component is text,
/// which the list does not decode but the worker's read fails on: the list and
/// the other upload's status still answer from A. Then a row whose timestamp
/// does not decode fails the list, and the other upload's status still
/// answers, from the worker.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_status_read_the_version_cannot_answer_asks_the_worker() {
    use crate::AppPreparedGroupImageUploadState::Staged;
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    runtime.reconcile_accounts().await.unwrap();
    crate::worker_fences::worker_startup_finished(&runtime, "alice")
        .await
        .unwrap();
    let stage = || runtime.stage_prepared_group_image("alice", one_pixel_png(), "image/png".into());
    let healthy = stage().await.unwrap();
    let broken = stage().await.unwrap();
    // Each corruption, then a publish after it.
    let corrupt = |set: &str| {
        app.account_storage("alice")
            .unwrap()
            .app_storage()
            .execute_batch_for_test(&format!(
                "UPDATE app_prepared_group_image_upload SET {set} WHERE upload_id = '{}'",
                broken.upload_id
            ))
            .unwrap();
        crate::worker_fences::worker_round_trip(&runtime, "alice")
    };
    let telemetry = runtime.shared_services().app_performance_telemetry();
    let queued = || {
        telemetry
            .snapshot()
            .runtime_operations
            .into_iter()
            .find(|sample| sample.operation == crate::RuntimePerformanceOperation::ReadQueueR1)
            .unwrap()
            .started
    };
    let status = |upload_id: &str| runtime.prepared_group_image_status("alice", upload_id.into());

    corrupt("component_data = 'x'").await.unwrap();
    let before = queued();
    let mut listed: Vec<_> = runtime
        .prepared_group_images("alice")
        .await
        .unwrap()
        .into_iter()
        .map(|status| (status.upload_id, status.state))
        .collect();
    listed.sort_by(|ours, theirs| ours.0.cmp(&theirs.0));
    let mut expected = vec![
        (healthy.upload_id.clone(), Staged),
        (broken.upload_id.clone(), Staged),
    ];
    expected.sort_by(|ours, theirs| ours.0.cmp(&theirs.0));
    assert_eq!(listed, expected, "the list does not decode the component");
    assert_eq!(status(&healthy.upload_id).await.unwrap().state, Staged);
    assert_eq!(
        queued(),
        before,
        "the list and a readable record answer from A"
    );
    assert!(matches!(
        status(&broken.upload_id).await,
        Err(AppError::Storage(cgka_traits::StorageError::Backend(message)))
            if message.contains("component_data")
    ));
    assert_eq!(queued(), before + 1, "an unreadable record asks the worker");

    corrupt("recorded_at = -1").await.unwrap();
    let before = queued();
    assert!(matches!(
        runtime.prepared_group_images("alice").await,
        Err(AppError::Storage(cgka_traits::StorageError::Serialization(
            _
        )))
    ));
    assert_eq!(queued(), before, "the list's failure answers from A");
    assert_eq!(status(&healthy.upload_id).await.unwrap().state, Staged);
    assert_eq!(queued(), before + 1, "the status read asks the worker");
    runtime.shutdown_and_close().await.unwrap();
}

/// The owned KeyPackage list is the one account answer A reuses: its read
/// re-checks every stored bundle's signatures. It is kept while the account
/// database's KeyPackage write count holds, which only a write to its inputs
/// moves, through any connection: a send keeps it, and a stored bundle's
/// replace or delete or an issued private KeyPackage's write ends it, here
/// through the app's own connection, not the engine. The version carries the
/// list's lifetime bound, and a read that skipped a bundle that does not
/// decode is never reused. The oracle checks a settled reuse by the list's
/// inputs, without reading the list afresh.
#[tokio::test]
async fn the_owned_key_package_list_is_reused_until_a_key_package_input_is_written() {
    use cgka_traits::storage::{IssuedPrivateKeyPackage, PrivateKeyPackageStorage as _};

    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let mut client = app.client("alice").await.unwrap();
    client.publish_key_package().await.unwrap();
    let group = client
        .create_group("sent", &[])
        .await
        .unwrap()
        .operation
        .unwrap();
    client.start_read_state(read_state_channel().0, UploadsInFlight::default());
    let state = client.subscribe_read_state().unwrap();
    let owned = state
        .borrow()
        .account
        .durably_owned_key_packages
        .clone()
        .unwrap();
    assert_eq!(owned.len(), 1);
    let not_after = cgka_engine::key_package::key_package_metadata(&owned[0])
        .unwrap()
        .not_after;
    assert_eq!(state.borrow().valid_until, Some(Timestamp(not_after)));

    client.publish_read_state();
    assert!(client.read_state_reused_key_packages());
    assert!(!client.read_state_read_key_packages_afresh());

    client.send(&group, b"kept").await.unwrap();
    client.publish_read_state();
    assert!(client.read_state_reused_key_packages(), "a send");

    let storage = app.account_storage("alice").unwrap().app_storage();
    storage
        .execute_batch_for_test(
            "INSERT OR REPLACE INTO openmls_values
             SELECT * FROM openmls_values WHERE label = CAST('KeyPackage' AS BLOB)",
        )
        .unwrap();
    client.publish_read_state();
    assert!(!client.read_state_reused_key_packages(), "a replace");
    client.publish_read_state();
    assert!(client.read_state_reused_key_packages());

    client
        .engine_storage
        .put_issued_private_key_package(&IssuedPrivateKeyPackage {
            key_package_ref: vec![0xaa; 32],
            recipient_slot: [0xbb; 32],
            not_before: 0,
            not_after: u64::MAX,
            key_package: Vec::new(),
            issued_at: 1,
            hand_off_queued: true,
            counted: true,
            request_id: None,
        })
        .unwrap();
    client.publish_read_state();
    assert!(
        !client.read_state_reused_key_packages(),
        "a private KeyPackage"
    );
    client.publish_read_state();
    assert!(client.read_state_reused_key_packages());

    storage
        .execute_batch_for_test(
            "DELETE FROM openmls_values WHERE label = CAST('KeyPackage' AS BLOB)",
        )
        .unwrap();
    client.publish_read_state();
    assert!(!client.read_state_reused_key_packages(), "a delete");
    let state_now = state.borrow().clone();
    assert!(
        state_now
            .account
            .durably_owned_key_packages
            .as_ref()
            .unwrap()
            .is_empty()
    );
    assert_eq!(state_now.valid_until, None);

    storage
        .execute_batch_for_test(
            "INSERT INTO openmls_values (provider_version, label, storage_key, value)
             VALUES (1, CAST('KeyPackage' AS BLOB), x'00ff', x'00')",
        )
        .unwrap();
    client.publish_read_state();
    client.publish_read_state();
    assert!(!client.read_state_reused_key_packages());
}

/// A write to a stored bundle through a connection no trigger counts, here
/// another SQLite connection on the account database, still ends the owned
/// KeyPackage list's reuse: reading the KeyPackage write count checks the
/// database's `data_version`, and a change no counted commit explains moves
/// the count.
#[tokio::test]
async fn an_uncounted_key_package_write_ends_the_lists_reuse() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let mut client = app.client("alice").await.unwrap();
    client.publish_key_package().await.unwrap();
    client.start_read_state(read_state_channel().0, UploadsInFlight::default());
    client.publish_read_state();
    assert!(client.read_state_reused_key_packages());

    let path = app.account_storage_path("alice");
    let keys = app.account_home().load_signing_keys("alice").unwrap();
    let key = app
        .sqlcipher_key("alice", &keys, &path, SqlcipherDatabaseKind::Session)
        .unwrap();
    storage_sqlite::expect_uncounted_writes_for_test(&path);
    let db = rusqlite::Connection::open(path).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &db,
        &key,
        storage_sqlite::SqlCipherHardening::cipher_only(),
    )
    .unwrap();
    db.execute_batch(
        "INSERT OR REPLACE INTO openmls_values
         SELECT * FROM openmls_values WHERE label = CAST('KeyPackage' AS BLOB)",
    )
    .unwrap();
    client.publish_read_state();
    assert!(!client.read_state_reused_key_packages());
}

/// A stored bundle that is not valid yet stays out of the owned list, but its
/// `not_before` bounds the list, so the publish moves `valid_until` alone and
/// carries the time the list next changes with no write.
#[tokio::test]
async fn a_bundle_not_valid_yet_bounds_the_list_it_stays_out_of() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let mut client = app.client("alice").await.unwrap();
    client.publish_key_package().await.unwrap();
    client.start_read_state(read_state_channel().0, UploadsInFlight::default());
    let state = client.subscribe_read_state().unwrap();
    let (version, published) = {
        let state = state.borrow();
        (
            state.version,
            state.account.durably_owned_key_packages.clone().unwrap(),
        )
    };

    let not_before = crate::unix_now_seconds() + 3_600;
    store_own_bundle_valid_from(&app, &published[0], not_before);
    client.publish_read_state();
    let state = state.borrow();
    assert_eq!(
        state.account.durably_owned_key_packages.as_ref().unwrap(),
        &published
    );
    assert_eq!(state.valid_until, Some(Timestamp(not_before)));
    assert!(state.version > version);
}

/// An owned KeyPackage not valid yet joins the list when its `not_before`
/// passes, with no write: the account worker publishes then, with no
/// command, delivery or write to prompt it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_worker_publishes_a_time_bound_answer_when_its_bound_passes() {
    use std::sync::atomic::AtomicBool;
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    runtime.reconcile_accounts().await.unwrap();
    runtime.publish_key_package("alice").await.unwrap();
    let accounts = runtime.accounts();
    let published = accounts.durably_owned_key_packages("alice").await.unwrap();

    let not_before = crate::unix_now_seconds() + 2;
    store_own_bundle_valid_from(&app, &published[0], not_before);
    // A reply publishes the write first.
    crate::worker_fences::worker_round_trip(&runtime, "alice")
        .await
        .unwrap();
    let lane = accounts.worker_lane("alice").await.unwrap();
    let open = AtomicBool::new(false);
    let bounded = lane.read_state.version(&open).unwrap().unwrap();
    assert_eq!(bounded.valid_until, Some(Timestamp(not_before)));
    assert_eq!(
        bounded.account.durably_owned_key_packages.as_ref().unwrap(),
        &published
    );

    let mut versions = lane.read_state.subscribe();
    let joined = tokio::time::timeout(
        Duration::from_secs(6),
        versions.wait_for(|state| {
            state
                .account
                .durably_owned_key_packages
                .as_ref()
                .unwrap()
                .len()
                > published.len()
        }),
    )
    .await
    .expect("the worker publishes the list once the bundle is valid")
    .unwrap()
    .clone();
    assert!(crate::unix_now_seconds() >= not_before);
    assert!(joined.version > bounded.version);
    assert_ne!(joined.valid_until, Some(Timestamp(not_before)));
    runtime.shutdown_and_close().await.unwrap();
}

/// The oracle skips its fresh read of a reused KeyPackage list only while
/// the list's raw inputs are the ones read before its build and the clock is
/// at or after that reading and short of the first lifetime bound after it:
/// the soonest `not_after` of a stored bundle, or `not_before` of one not
/// valid yet, decoded without OpenMLS. A stored row whose lifetime it cannot
/// find never lets it skip, and a check with no recorded inputs, with inputs
/// that no longer hold, or whose input read fails, reads the list afresh.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_oracle_rereads_a_reused_key_package_list_once_an_input_or_the_clock_moves() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let mut client = app.client("alice").await.unwrap();
    client.publish_key_package().await.unwrap();
    let published = client.durably_owned_key_packages().unwrap();
    // A read state before any build lists no KeyPackage, so a fresh read
    // differs from it: a check of it panics exactly when it reads the list
    // afresh.
    let stale =
        ReadStatePublisher::new(read_state_channel().0, UploadsInFlight::default()).current();
    assert!(
        stale
            .account
            .durably_owned_key_packages
            .as_ref()
            .unwrap()
            .is_empty()
    );
    assert!(!published.is_empty());
    let not_after = cgka_engine::key_package::key_package_metadata(&published[0])
        .unwrap()
        .not_after;

    let built_from = KeyPackageInputs::read(&client).unwrap();
    assert_eq!(
        built_from.first_bound(),
        LifetimeBound::At(Timestamp(not_after))
    );
    assert_eq!(
        check_reused_list(&client, &stale, true, Some(&built_from)),
        Some(false)
    );
    assert_eq!(check_reused_list(&client, &stale, true, None), None);
    let mut now = KeyPackageInputs::read(&client).unwrap();
    assert!(built_from.holds_at(&now));
    now.taken_at = Timestamp(not_after);
    assert!(!built_from.holds_at(&now));
    now.taken_at = Timestamp(built_from.taken_at.0 - 1);
    assert!(!built_from.holds_at(&now));

    let not_before = crate::unix_now_seconds() + 3_600;
    store_own_bundle_valid_from(&app, &published[0], not_before);
    let with_new_bundle = KeyPackageInputs::read(&client).unwrap();
    assert!(!built_from.holds_at(&with_new_bundle));
    assert_eq!(
        check_reused_list(&client, &stale, true, Some(&built_from)),
        None
    );
    assert_eq!(
        with_new_bundle.first_bound(),
        LifetimeBound::At(Timestamp(not_before))
    );

    app.account_storage("alice")
        .unwrap()
        .app_storage()
        .execute_batch_for_test(
            "INSERT INTO openmls_values (provider_version, label, storage_key, value)
             VALUES (1, CAST('KeyPackage' AS BLOB), x'00ff', x'00')",
        )
        .unwrap();
    let undecodable = KeyPackageInputs::read(&client).unwrap();
    assert_eq!(undecodable.first_bound(), LifetimeBound::Unknown);
    assert!(!undecodable.holds_at(&KeyPackageInputs::read(&client).unwrap()));

    // With storage closed the input read fails, and the fresh read's
    // `Closed` against a published list is a mismatch when storage was
    // already closed at the publish.
    app.close_storage().unwrap();
    assert!(KeyPackageInputs::read(&client).is_err());
    assert_eq!(
        check_reused_list(&client, &stale, false, Some(&undecodable)),
        None
    );
}

/// The oracle's check of a reused owned KeyPackage list against `state`:
/// whether it read the list afresh, or `None` when that fresh read differed
/// from `state` and the oracle panicked.
fn check_reused_list(
    client: &AppClient,
    state: &ReadState,
    storage_open_at_publish: bool,
    built_from: Option<&KeyPackageInputs>,
) -> Option<bool> {
    let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        check_reused_key_packages(client, state, storage_open_at_publish, built_from)
    }));
    match checked {
        Ok(read_afresh) => Some(read_afresh),
        Err(panic) => {
            let message = panic
                .downcast_ref::<String>()
                .map(String::as_str)
                .unwrap_or_default();
            assert!(
                message.starts_with(
                    "read state differs from the live read for durably owned key packages"
                ),
                "unexpected panic: {message}"
            );
            None
        }
    }
}

/// Stores a copy of alice's `template`, signed with her own key, that is
/// valid for an hour from `not_before`.
fn store_own_bundle_valid_from(app: &MarmotApp, template: &KeyPackage, not_before: u64) {
    use cgka_engine::provider::EngineOpenMlsProvider;
    use cgka_traits::storage::{AccountDeviceSignerStorage as _, StorageProvider as _};
    use openmls::prelude::{
        CredentialWithKey, KeyPackage as MlsKeyPackage, Lifetime, MlsMessageBodyIn, MlsMessageIn,
        ProtocolVersion,
    };
    use openmls_basic_credential::SignatureKeyPair;
    use tls_codec::Deserialize as _;

    let storage = app.account_storage("alice").unwrap();
    let account = app.account_home().account("alice").unwrap();
    let identity = MemberId::new(hex::decode(account.account_id_hex).unwrap());
    let binding = storage.account_device_signer(&identity).unwrap().unwrap();
    let suite = cgka_engine::DEFAULT_CIPHERSUITE;
    let signer = SignatureKeyPair::read(
        storage.mls_storage(),
        &binding.mls_signature_public_key,
        suite.signature_algorithm(),
    )
    .unwrap();
    let MlsMessageBodyIn::KeyPackage(template) =
        MlsMessageIn::tls_deserialize_exact(template.bytes())
            .unwrap()
            .extract()
    else {
        panic!("expected a KeyPackage")
    };
    let crypto = openmls_rust_crypto::RustCrypto::default();
    let template = template.validate(&crypto, ProtocolVersion::Mls10).unwrap();
    let leaf = template.leaf_node();
    MlsKeyPackage::builder()
        .leaf_node_capabilities(leaf.capabilities().clone())
        .leaf_node_extensions(leaf.extensions().clone())
        .key_package_lifetime(Lifetime::init(not_before, not_before + 3_600))
        .mark_as_last_resort()
        .build(
            suite,
            &EngineOpenMlsProvider::<storage_sqlite::SqliteAccountStorage>::new(
                &crypto,
                storage.mls_storage(),
            ),
            &signer,
            CredentialWithKey {
                credential: leaf.credential().clone(),
                signature_key: signer.public().into(),
            },
        )
        .unwrap();
}

/// The device-group check hides a group when it fails, so the host never
/// learns of a group through a check that failed. That failure can clear with
/// no write, so the entry it hides is not reused: the next publish reads the
/// check again. Here a TEMP table on the app's connection shadows the
/// device-group table, failing the check without writing the database.
#[tokio::test]
async fn a_group_hidden_by_a_failed_device_group_check_is_read_again() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let mut client = app.client("alice").await.unwrap();
    let group = client
        .create_group("visible", &[])
        .await
        .unwrap()
        .operation
        .unwrap();
    let storage = app.account_storage("alice").unwrap().app_storage();
    storage
        .execute_batch_for_test("CREATE TEMP TABLE device_groups (shadow INTEGER)")
        .unwrap();
    client.start_read_state(read_state_channel().0, UploadsInFlight::default());
    let state = client.subscribe_read_state().unwrap();
    assert_eq!(state.borrow().host_may_see(&group), Some(false));
    // A hidden group's roster is not trusted either (mdk#3273 PR 6).
    assert!(state.borrow().trusted_rosters().is_empty());

    storage
        .execute_batch_for_test("DROP TABLE temp.device_groups")
        .unwrap();
    client.publish_read_state();
    assert_eq!(state.borrow().host_may_see(&group), Some(true));
    assert_eq!(state.borrow().trusted_rosters().len(), 1);
}

/// A legacy self-update fanout owes its relays only until its bound, so the
/// entry's commit-delivery answer depends on the wall clock. An entry built
/// after the bound passed answers that nothing is owed; moving the clock back
/// before the bound brings it back into force, so the next publish rebuilds
/// the entry instead of reusing it. The answer's window starts at the reading
/// that decided it, so a step back right after that reading counts too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_clock_moved_back_rebuilds_the_time_dependent_entry() {
    use std::sync::atomic::{AtomicU64, Ordering};
    /// Reads `0`; after a read, moves to `1` once when it is set.
    struct SetClock(Arc<AtomicU64>, Arc<AtomicU64>);
    impl marmot_session::WallClock for SetClock {
        fn now(&self) -> Timestamp {
            let now = self.0.load(Ordering::SeqCst);
            let step = self.1.swap(0, Ordering::SeqCst);
            if step != 0 {
                self.0.store(step, Ordering::SeqCst);
            }
            Timestamp(now)
        }
        fn now_ms(&self) -> u64 {
            self.0.load(Ordering::SeqCst) * 1_000
        }
    }
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let mut client = app.client("alice").await.unwrap();
    let group = client
        .create_group("bounded", &[])
        .await
        .unwrap()
        .operation
        .unwrap();
    let clock = Arc::new(AtomicU64::new(1_200));
    let step_after_read = Arc::new(AtomicU64::new(0));
    client.runtime = client.runtime.with_maintenance_sources(
        Arc::new(SetClock(Arc::clone(&clock), Arc::clone(&step_after_read))),
        Arc::new(marmot_session::SystemMonotonicClock::default()),
        Arc::new(marmot_session::OsEntropy),
    );
    let id = cgka_traits::MessageId::new(vec![0x5e; 32]);
    let endpoint = |url: &str| cgka_traits::TransportEndpoint(url.to_owned());
    let target = |url: &str, state| cgka_traits::TransportFanoutTarget {
        endpoint: endpoint(url),
        state,
        attempt_count: 1,
        last_attempt_at: Some(Timestamp(1_000)),
        failure_code: None,
    };
    client
        .runtime
        .session()
        .put_transport_fanout(&cgka_traits::DurableTransportFanout {
            id: id.clone(),
            group_id: Some(group.clone()),
            evolution_id: Some(id.clone()),
            exact_message: cgka_traits::TransportMessage {
                id: id.clone(),
                payload: vec![0x5e; 16],
                timestamp: Timestamp(1_000),
                causal_deps: Vec::new(),
                source: cgka_traits::TransportSource("nostr".to_owned()),
                envelope: cgka_traits::TransportEnvelope::GroupMessage {
                    transport_group_id: vec![0x42; 32],
                },
            },
            target: cgka_traits::TransportPublishTarget::Group {
                group_id: group.clone(),
                transport_group_id: vec![0x42; 32],
                endpoints: vec![endpoint("wss://a.example"), endpoint("wss://b.example")],
            },
            targets: vec![
                target(
                    "wss://a.example",
                    cgka_traits::TransportFanoutAttemptState::Accepted,
                ),
                target(
                    "wss://b.example",
                    cgka_traits::TransportFanoutAttemptState::AttemptedFailed,
                ),
            ],
            required_acks: 1,
            evolution_confirmed: true,
            possible_exposure: false,
            created_at: Timestamp(1_000),
            bounded_until: Some(Timestamp(1_100)),
        })
        .unwrap();
    client.start_read_state(read_state_channel().0, UploadsInFlight::default());
    let state = client.subscribe_read_state().unwrap();
    let (_, expired) = entry(&state, &group);
    assert_eq!(state.borrow().group_commit_delivery(&group).unwrap(), None);

    clock.store(1_050, Ordering::SeqCst);
    client.publish_read_state();
    let (_, in_force) = entry(&state, &group);
    assert!(!Arc::ptr_eq(&expired, &in_force));
    assert!(
        state
            .borrow()
            .group_commit_delivery(&group)
            .unwrap()
            .is_some()
    );
    // The version carries the bound the owed answer holds until.
    assert_eq!(state.borrow().valid_until, Some(Timestamp(1_100)));

    clock.store(1_200, Ordering::SeqCst);
    step_after_read.store(1_050, Ordering::SeqCst);
    let (owed, window) = client.runtime.undelivered_commit_until(&group).unwrap();
    assert_eq!(owed, None);
    assert_eq!(window.from, Timestamp(1_200));
    assert!(!window.contains(client.runtime.wall_clock_now()));
}

/// Fails a save that writes a group's row while the group has none.
#[cfg(feature = "test-policy-overrides")]
const FAIL_NEW_GROUP_ROW: &str = "CREATE TRIGGER fail_new_group_row BEFORE INSERT ON account_groups
     WHEN NOT EXISTS (SELECT 1 FROM account_groups WHERE group_id_hex = NEW.group_id_hex)
     BEGIN SELECT RAISE(ABORT, 'injected group row failure'); END;";

/// Fails a save that changes a saved row's `pending_confirmation`.
#[cfg(feature = "test-policy-overrides")]
const FAIL_PENDING_CHANGE: &str = "CREATE TRIGGER fail_pending_change
     BEFORE UPDATE OF pending_confirmation ON account_groups
     WHEN OLD.pending_confirmation IS NOT NEW.pending_confirmation
     BEGIN SELECT RAISE(ABORT, 'injected pending change failure'); END;";

#[cfg(feature = "test-policy-overrides")]
fn co_members(state: &watch::Receiver<Arc<ReadState>>, local_account_id_hex: &str) -> Vec<String> {
    state.borrow().co_members(local_account_id_hex).unwrap()
}

/// Co-members judge a group by its saved row, and the save that writes the
/// row rebuilds the group's entry (mdk#3273 PR 4). A create whose save of
/// the group's row fails leaves the group in the account state but out of
/// co-members. The later save that writes the row changes neither the
/// group's record nor its engine state. It moves the group's write count,
/// so the next publish counts the group.
#[cfg(feature = "test-policy-overrides")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_created_group_counts_toward_co_members_from_the_save_of_its_row() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let mut alice = Device::create(&home, &app, "alice").await;
    let alice_id = alice.account_id_hex.clone();
    let bob = Device::create(&home, &app, "bob").await;
    alice
        .client
        .start_read_state(read_state_channel().0, UploadsInFlight::default());
    let state = alice.client.subscribe_read_state().unwrap();
    let faults = app.account_storage("alice").unwrap().app_storage();
    faults.execute_batch_for_test(FAIL_NEW_GROUP_ROW).unwrap();

    let group = alice
        .client
        .create_group("lost", &[&bob.account_id_hex])
        .await
        .expect("the engine's group is canonical when its row fails to save")
        .operation
        .unwrap();
    alice.client.publish_read_state();
    assert!(
        state.borrow().groups.contains_key(&group),
        "the account state holds the group whose row failed to save"
    );
    assert_eq!(
        co_members(&state, &alice_id),
        Vec::<String>::new(),
        "a group with no saved row counts nobody"
    );

    faults
        .execute_batch_for_test("DROP TRIGGER fail_new_group_row")
        .unwrap();
    alice
        .client
        .save_state_with_pending_local_group_deletion_frontier_clears()
        .unwrap();
    alice.client.publish_read_state();
    assert_eq!(
        co_members(&state, &alice_id),
        vec![bob.account_id_hex.clone()],
        "the publish after the save of its row counts the group"
    );
}

/// Co-members judge a group by its saved row, so an accepted invite counts
/// from the save that clears it (mdk#3273 PR 4). The device-group admission
/// path (`note_invitation_admission`) clears the account state's
/// `pending_confirmation` and leaves the save to its batch; this test makes
/// that clear itself. While the save fails, the group counts nobody, and a
/// restart, whose account state reads the saved row, answers the same. The
/// save that later writes the clear changes neither the group's record nor
/// its engine state. It moves the group's write count, so the next publish
/// counts the group.
#[cfg(feature = "test-policy-overrides")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cleared_invite_counts_toward_co_members_from_the_save_that_writes_it() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let mut alice = Device::create(&home, &app, "alice").await;
    let alice_id = alice.account_id_hex.clone();
    let mut bob = Device::create(&home, &app, "bob").await;
    let group = bob
        .client
        .create_group("invite", &[&alice.account_id_hex])
        .await
        .unwrap()
        .operation
        .unwrap();
    alice.receive(&relay).await;
    let group_hex = hex::encode(group.as_slice());
    let faults = app.account_storage("alice").unwrap().app_storage();
    assert!(
        faults
            .group_standing(&group_hex)
            .unwrap()
            .expect("the invite's row is saved")
            .pending_confirmation,
        "the invite awaits alice's confirmation"
    );
    faults.execute_batch_for_test(FAIL_PENDING_CHANGE).unwrap();
    let clear_and_fail_to_save = |client: &mut AppClient| {
        client
            .state
            .groups
            .iter_mut()
            .find(|record| record.group_id_hex == group_hex)
            .expect("the invite's record")
            .pending_confirmation = false;
        client.mark_group_projection_dirty(&group);
        assert!(
            client
                .save_state_with_pending_local_group_deletion_frontier_clears()
                .is_err(),
            "the injected fault fails the save"
        );
    };

    let mut client = alice.client;
    clear_and_fail_to_save(&mut client);
    client.start_read_state(read_state_channel().0, UploadsInFlight::default());
    let state = client.subscribe_read_state().unwrap();
    assert_eq!(
        co_members(&state, &alice_id),
        Vec::<String>::new(),
        "a clear its save lost counts nobody"
    );

    drop(client);
    let mut client = app.client("alice").await.unwrap();
    client.start_read_state(read_state_channel().0, UploadsInFlight::default());
    let state = client.subscribe_read_state().unwrap();
    assert_eq!(
        co_members(&state, &alice_id),
        Vec::<String>::new(),
        "after a restart the read answers as before it"
    );

    clear_and_fail_to_save(&mut client);
    client.publish_read_state();
    assert_eq!(co_members(&state, &alice_id), Vec::<String>::new());
    faults
        .execute_batch_for_test("DROP TRIGGER fail_pending_change")
        .unwrap();
    client
        .save_state_with_pending_local_group_deletion_frontier_clears()
        .unwrap();
    client.publish_read_state();
    assert_eq!(
        co_members(&state, &alice_id),
        vec![bob.account_id_hex.clone()],
        "the publish after the save of the clear counts the group"
    );
}

/// The members of each roster `state`'s current version trusts, read on
/// `storage` at that version's revisions, as hex per group (mdk#3273 PR 6).
fn trusted_members(
    state: &watch::Receiver<Arc<ReadState>>,
    storage: &storage_sqlite::SqliteAppStorage,
) -> Vec<(GroupId, Vec<String>)> {
    state
        .borrow()
        .trusted_roster_members(storage)
        .unwrap()
        .into_iter()
        .map(|(group_id, members)| {
            let members = members
                .ids()
                .iter()
                .map(|member_id| hex::encode(member_id.as_slice()))
                .collect();
            (group_id, members)
        })
        .collect()
}

/// A write to a group's committed roster alone, as the hydration backfill
/// makes, moves its change generation, so the next publish rebuilds the
/// entry and records the new revision, with no other answer changed
/// (mdk#3273 PR 6).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_roster_write_alone_moves_the_recorded_revision() {
    use cgka_traits::storage::{CommittedMembers, CommittedRosterStorage};

    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let alice_account = home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let mut client = app.client("alice").await.unwrap();
    let group = client
        .create_group("rewritten", &[])
        .await
        .unwrap()
        .operation
        .unwrap();
    client.start_read_state(read_state_channel().0, UploadsInFlight::default());
    let state = client.subscribe_read_state().unwrap();
    let (version, before) = entry(&state, &group);
    let storage = app.account_storage("alice").unwrap();
    let stranger = MemberId::new(vec![0xee; 32]);
    let alice = MemberId::new(hex::decode(&alice_account.account_id_hex).unwrap());
    storage
        .put_committed_roster(
            &group,
            &CommittedMembers::from_ids([alice, stranger.clone()]),
        )
        .unwrap();
    let written = storage.committed_roster_revision(&group).unwrap().unwrap();
    assert_ne!(*before.roster_revision.as_ref().unwrap(), Some(written));

    client.publish_read_state();
    let (after, rebuilt) = entry(&state, &group);
    assert!(after > version);
    assert_eq!(*rebuilt.roster_revision.as_ref().unwrap(), Some(written));
    assert_eq!(
        state.borrow().trusted_rosters(),
        vec![(group.clone(), written)]
    );
    let members = state
        .borrow()
        .trusted_roster_members(&storage.app_storage())
        .unwrap();
    assert_eq!(members.len(), 1);
    assert!(members[0].1.ids().contains(&stranger));
}

/// Between the engine's roster write and A's next publish, a read on
/// another connection bound to the published version's revisions matches
/// neither the roster that version recorded nor the one written since: the
/// write moved the revision, which the version does not name yet. The
/// publish after it records the new revision, and the read matches the new
/// roster (mdk#3273 PR 6).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_roster_written_after_the_published_version_never_matches_until_it_is_published() {
    use cgka_traits::storage::CommittedRosterStorage;

    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let alice_account = home.create_account("alice").unwrap();
    let bob_account = home.create_account("bob").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    remember_test_member_inbox(&app, &bob_account.account_id_hex, "wss://relay.example");
    app.client("bob")
        .await
        .unwrap()
        .publish_key_package()
        .await
        .unwrap();
    let mut alice = app.client("alice").await.unwrap();
    let group = alice
        .create_group("rostered", &[])
        .await
        .unwrap()
        .operation
        .unwrap();
    alice.start_read_state(read_state_channel().0, UploadsInFlight::default());
    let state = alice.subscribe_read_state().unwrap();
    // The app's cached connection; the engine writes rosters on its own.
    let storage = app.account_storage("alice").unwrap();
    let second = storage.app_storage();
    let recorded = storage.committed_roster_revision(&group).unwrap().unwrap();
    assert_eq!(
        state.borrow().trusted_rosters(),
        vec![(group.clone(), recorded)]
    );
    assert_eq!(
        trusted_members(&state, &second),
        vec![(group.clone(), vec![alice_account.account_id_hex.clone()])]
    );

    alice
        .invite_members(&group, &[&bob_account.account_id_hex])
        .await
        .unwrap();
    let written = storage.committed_roster(&group).unwrap().unwrap();
    assert!(written.revision > recorded);
    assert_eq!(written.members.ids().len(), 2);
    assert_eq!(
        state.borrow().trusted_rosters(),
        vec![(group.clone(), recorded)],
        "the version still names the revision it recorded"
    );
    assert_eq!(
        trusted_members(&state, &second),
        Vec::new(),
        "a roster the published version has not recorded matched"
    );

    alice.publish_read_state();
    assert_eq!(
        state.borrow().trusted_rosters(),
        vec![(group.clone(), written.revision)]
    );
    let mut both = vec![
        alice_account.account_id_hex.clone(),
        bob_account.account_id_hex.clone(),
    ];
    both.sort();
    assert_eq!(trusted_members(&state, &second), vec![(group, both)]);
}

/// Hydration, quarantine and a successful retry change whether A trusts a
/// group's committed roster, while the roster and its revision stay what
/// they were (mdk#3273 PR 6). A seeded group is not trusted until it is
/// hydrated; a group hydration quarantines is not trusted; the retry that
/// brings it back is trusted again at the same revision.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hydration_quarantine_and_retry_move_trust_but_not_the_roster() {
    use cgka_traits::storage::{CommittedRosterStorage, GroupStorage};

    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let alice_account = home.create_account("alice").unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let group = app
        .client("alice")
        .await
        .unwrap()
        .create_group("trusted", &[])
        .await
        .unwrap()
        .operation
        .unwrap();
    let storage = app.account_storage("alice").unwrap();
    let second = storage.app_storage();
    let roster = storage.committed_roster(&group).unwrap().unwrap();
    let trusted = vec![(group.clone(), roster.revision)];
    let members = vec![(group.clone(), vec![alice_account.account_id_hex.clone()])];

    let plane = MarmotRelayPlane::new(None, relay);
    let mut alice = app
        .local_client_with_relay_plane_and_hydration("alice", &plane, None, true, None)
        .await
        .unwrap();
    alice.start_read_state(read_state_channel().0, UploadsInFlight::default());
    let state = alice.subscribe_read_state().unwrap();
    {
        let version = state.borrow();
        let seeded = &version.groups[&group];
        assert!(seeded.awaits_hydration && !seeded.serves_reads);
        assert_eq!(
            *seeded.roster_revision.as_ref().unwrap(),
            Some(roster.revision)
        );
        assert!(version.trusted_rosters().is_empty());
    }
    assert!(trusted_members(&state, &second).is_empty());
    assert!(alice.runtime.ensure_group_hydrated(&group).unwrap());
    alice.publish_read_state();
    assert_eq!(state.borrow().trusted_rosters(), trusted, "hydrated");
    assert_eq!(trusted_members(&state, &second), members);
    drop(alice);

    // A record hydration refuses quarantines the group at the next open.
    let original = storage.get_group(&group).unwrap();
    let mut damaged = original.clone();
    damaged.protocol_profile = cgka_traits::group::ProtocolProfile::Legacy;
    assert_ne!(damaged.protocol_profile, original.protocol_profile);
    storage.put_group(&damaged).unwrap();
    let mut alice = app.client("alice").await.unwrap();
    assert_eq!(alice.quarantined_groups().len(), 1);
    alice.start_read_state(read_state_channel().0, UploadsInFlight::default());
    let state = alice.subscribe_read_state().unwrap();
    assert!(
        state
            .borrow()
            .groups
            .get(&group)
            .is_none_or(|group| !group.serves_reads)
    );
    assert!(state.borrow().trusted_rosters().is_empty(), "quarantined");
    assert!(trusted_members(&state, &second).is_empty());

    storage.put_group(&original).unwrap();
    assert!(alice.retry_hydrate_quarantined_group(&group).unwrap());
    alice.publish_read_state();
    assert_eq!(state.borrow().trusted_rosters(), trusted, "retried");
    assert_eq!(trusted_members(&state, &second), members);
    assert_eq!(storage.committed_roster(&group).unwrap(), Some(roster));
}

/// A group stored before rosters existed, which nothing else touches, is
/// trusted after the hydration that records its roster and one publish
/// (mdk#3273 PR 6). Until that publish, the version names no revision for
/// it, so the recorded roster does not match.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_group_stored_before_rosters_is_trusted_after_its_backfill_and_one_publish() {
    use cgka_traits::storage::CommittedRosterStorage;

    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let alice_account = home.create_account("alice").unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let group = app
        .client("alice")
        .await
        .unwrap()
        .create_group("backfilled", &[])
        .await
        .unwrap()
        .operation
        .unwrap();
    let storage = app.account_storage("alice").unwrap();
    let second = storage.app_storage();
    // As migration 0206 leaves a group stored before it: no roster.
    second
        .execute_batch_for_test(&format!(
            "DELETE FROM cgka_committed_rosters WHERE group_id = x'{}'",
            hex::encode(group.as_slice())
        ))
        .unwrap();
    assert_eq!(storage.committed_roster(&group).unwrap(), None);

    let plane = MarmotRelayPlane::new(None, relay);
    let mut alice = app
        .local_client_with_relay_plane_and_hydration("alice", &plane, None, true, None)
        .await
        .unwrap();
    alice.start_read_state(read_state_channel().0, UploadsInFlight::default());
    let state = alice.subscribe_read_state().unwrap();
    assert_eq!(
        *state.borrow().groups[&group]
            .roster_revision
            .as_ref()
            .unwrap(),
        None
    );
    assert!(alice.runtime.ensure_group_hydrated(&group).unwrap());
    let recorded = storage.committed_roster_revision(&group).unwrap().unwrap();
    assert!(state.borrow().trusted_rosters().is_empty());
    assert!(trusted_members(&state, &second).is_empty());

    alice.publish_read_state();
    assert_eq!(
        state.borrow().trusted_rosters(),
        vec![(group.clone(), recorded)]
    );
    assert_eq!(
        trusted_members(&state, &second),
        vec![(group, vec![alice_account.account_id_hex.clone()])]
    );
}

/// A group A trusts that a failed rewind restore quarantines in the middle of
/// the session (mdk#3272) is no longer trusted at the same publisher's next
/// publish, while its committed roster and revision stay what they were
/// (mdk#3273 PR 6). Carol applies alice's commit, then receives bob's rival
/// from the same epoch, so her pass rewinds onto the retained anchor to probe
/// it; every restore of that window's guard snapshot fails.
#[cfg(feature = "test-policy-overrides")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_rewind_restore_withdraws_trust_in_an_unchanged_roster() {
    use cgka_traits::storage::CommittedRosterStorage;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let accounts = ["alice", "bob", "carol"].map(|label| home.create_account(label).unwrap());
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay_and_config(
        dir.path(),
        "wss://relay.example",
        MarmotAppConfig::white_noise()
            .with_dev_settlement_quiescence_ms(0)
            .with_dev_scheduled_convergence_delay_ms(0),
    )
    .with_test_relay_client(relay.clone());
    for account in &accounts {
        remember_test_member_inbox(&app, &account.account_id_hex, "wss://relay.example");
    }
    let mut alice = app.client("alice").await.unwrap();
    let mut bob = app.client("bob").await.unwrap();
    let mut carol = app.client("carol").await.unwrap();
    bob.publish_key_package().await.unwrap();
    carol.publish_key_package().await.unwrap();
    let group = alice
        .create_group_with_options(
            "restore fault",
            &[&accounts[1].account_id_hex, &accounts[2].account_id_hex],
            crate::AppCreateGroupOptions {
                initial_admins: vec![accounts[1].account_id_hex.clone()],
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .operation
        .unwrap();
    let (mut bob_cursor, mut carol_cursor) = (0, 0);
    deliver_new(&mut bob, &relay, &mut bob_cursor).await;
    deliver_new(&mut carol, &relay, &mut carol_cursor).await;
    bob.accept_group_invite(&group).unwrap();
    carol.accept_group_invite(&group).unwrap();
    async fn settle(client: &mut AppClient, group: &GroupId) {
        for _ in 0..4 {
            let effects = client.runtime.advance_convergence(group).await.unwrap();
            client
                .observe_drained_session_events(&effects)
                .await
                .unwrap();
        }
    }
    // One more canonical advance, so the fork's source epoch keeps an anchor.
    alice
        .update_group_profile(&group, Some("before the fork"), None)
        .await
        .unwrap();
    deliver_new(&mut bob, &relay, &mut bob_cursor).await;
    settle(&mut bob, &group).await;
    deliver_new(&mut carol, &relay, &mut carol_cursor).await;
    settle(&mut carol, &group).await;

    // Carol applies alice's branch before she sees bob's rival.
    alice
        .update_group_profile(&group, Some("alice's branch"), None)
        .await
        .unwrap();
    deliver_new(&mut carol, &relay, &mut carol_cursor).await;
    settle(&mut carol, &group).await;
    carol.start_read_state(read_state_channel().0, UploadsInFlight::default());
    let state = carol.subscribe_read_state().unwrap();
    let storage = app.account_storage("carol").unwrap();
    let second = storage.app_storage();
    let roster = storage.committed_roster(&group).unwrap().unwrap();
    assert_eq!(roster.members.ids().len(), 3);
    assert_eq!(
        state.borrow().trusted_rosters(),
        vec![(group.clone(), roster.revision)]
    );
    assert_eq!(trusted_members(&state, &second).len(), 1);

    let rival_from = relay.published_events.lock().unwrap().len();
    bob.update_group_profile(&group, Some("bob's branch"), None)
        .await
        .unwrap();
    assert!(relay.published_events.lock().unwrap().len() > rival_from);
    let hits = Arc::new(AtomicUsize::new(0));
    let counted = hits.clone();
    carol
        .engine_storage
        .fail_snapshot_restores_for_test(Some(Arc::new(move |_, name, in_transaction| {
            if !in_transaction && name.starts_with("openmls-retained-probe-") {
                counted.fetch_add(1, Ordering::SeqCst);
                return Err(cgka_traits::StorageError::Busy(
                    "injected restore fault".into(),
                ));
            }
            Ok(())
        })));
    // The restore fails inside the rival's delivery, which reports it.
    let carol_id = MemberId::new(hex::decode(&accounts[2].account_id_hex).unwrap());
    let rival: Vec<_> = relay.published_events.lock().unwrap()[carol_cursor..]
        .iter()
        .filter(|event| event.kind == transport_nostr_peeler::KIND_MARMOT_GROUP_MESSAGE)
        .cloned()
        .collect();
    for event in rival {
        let _ = carol
            .ingest_received_delivery(cgka_traits::TransportDelivery {
                account_id: carol_id.clone(),
                group_id_hint: None,
                message: event.to_transport_message().unwrap(),
                received_at: cgka_traits::Timestamp(unix_now_seconds()),
                source: cgka_traits::TransportDeliverySource {
                    transport: cgka_traits::transport::TransportSource("nostr".into()),
                    plane: cgka_traits::TransportDeliveryPlane::Group,
                    endpoint: None,
                    subscription_id: None,
                    wire: None,
                },
            })
            .await;
    }
    for _ in 0..4 {
        if hits.load(Ordering::SeqCst) > 0 {
            break;
        }
        let _ = carol.runtime.advance_convergence(&group).await;
    }
    carol.engine_storage.fail_snapshot_restores_for_test(None);
    assert!(hits.load(Ordering::SeqCst) > 0, "no guard restore ran");
    assert!(
        carol
            .runtime
            .quarantined_groups()
            .iter()
            .any(|(quarantined, _)| *quarantined == group),
        "the failed restore quarantines the group"
    );

    carol.publish_read_state();
    assert!(!state.borrow().groups[&group].serves_reads);
    assert!(state.borrow().trusted_rosters().is_empty());
    assert!(trusted_members(&state, &second).is_empty());
    assert_eq!(storage.committed_roster(&group).unwrap(), Some(roster));
}

/// A group's re-join offer is left out of its recovery status while the
/// group's MLS state fails to load. That failure can clear with no write, so
/// the entry built during it is not reused: the next publish reads the offer
/// again. Here a TEMP table on the engine's connection shadows the OpenMLS
/// values, failing the load without writing the database.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_offer_hidden_by_a_failed_load_is_read_again() {
    use cgka_traits::storage::WelcomeStorage;
    use cgka_traits::welcome::{PendingWelcome, RejoinWelcome};

    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let mut client = app.client("alice").await.unwrap();
    let group = client
        .create_group("offered", &[])
        .await
        .unwrap()
        .operation
        .unwrap();
    let storage = app.account_storage("alice").unwrap();
    storage
        .put_welcome(&PendingWelcome {
            message_id: cgka_traits::MessageId::new(vec![0xe1; 32]),
            group_id: group.clone(),
            welcome_bytes: vec![],
            rejoin: Some(RejoinWelcome {
                epoch: cgka_traits::EpochId(0),
                content_id: cgka_traits::MessageId::new(vec![0xe2; 32]),
                welcomer: client.runtime.session().self_id(),
                local_state_token: vec![],
            }),
        })
        .unwrap();
    client.start_read_state(read_state_channel().0, UploadsInFlight::default());
    let state = client.subscribe_read_state().unwrap();
    let offers = |state: &watch::Receiver<Arc<ReadState>>| {
        state.borrow().groups[&group]
            .recovery_status
            .as_ref()
            .unwrap()
            .rejoin_invitations
            .len()
    };
    assert_eq!(offers(&state), 1);

    // Move the group's generation, then fail the load the rebuild makes on
    // the engine's connection.
    storage
        .app_storage()
        .execute_batch_for_test("UPDATE cgka_welcomes SET record = record")
        .unwrap();
    let engine = &client.engine_storage;
    let group_key =
        serde_json::to_vec(&openmls::group::GroupId::from_slice(group.as_slice())).unwrap();
    engine
        .execute_batch_for_test(&format!(
            "CREATE TEMP VIEW openmls_values AS SELECT provider_version, label, storage_key, \
             group_key, CASE WHEN label = X'{}' AND group_key = X'{}' THEN X'7b' ELSE value END \
             AS value FROM main.openmls_values",
            hex::encode(b"GroupContext"),
            hex::encode(&group_key),
        ))
        .unwrap();
    client.publish_read_state();
    // Every other answer reads the group's loaded state, so only the offer
    // fails: the entry would be reused but for the offer listing.
    assert!(state.borrow().groups[&group].mls_state.is_ok());
    assert_eq!(
        offers(&state),
        0,
        "the offer is left out while it fails to load"
    );

    engine
        .execute_batch_for_test("DROP VIEW temp.openmls_values")
        .unwrap();
    client.publish_read_state();
    assert_eq!(offers(&state), 1, "the offer comes back with no write");
}

/// A retained reinvite's KeyPackage is judged against the system clock. A
/// live one bounds its group's entry: the version names its `not_after` as
/// when an answer can change. One past its `not_after` fails the group's
/// recovery status, and a host's read serves that failure from A as an exact
/// copy, never waiting for the worker.
///
/// A kept group crossing its reinvite's real `not_after` needs a system clock
/// a test can move, and OpenMLS reads the system clock itself, so five tests
/// compose it with no seam: the version's bound is the KeyPackage's
/// `not_after` and a status built past it fails (here); the deadline the
/// worker waits for ends at that bound
/// (`client::read_state::tests::the_deadline_measures_each_bound_on_its_own_clock`);
/// the worker wakes at that deadline and publishes, with no command, delivery
/// or write (`the_worker_publishes_a_time_bound_answer_when_its_bound_passes`);
/// an entry stops holding there
/// (`client::read_state::tests::an_entry_holds_only_inside_its_key_package_window`);
/// and a publish judges a kept entry by the system-clock reading it took
/// (`client::read_state::tests::a_publish_rebuilds_an_entry_once_its_key_package_window_ends`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_live_reinvite_bounds_its_entry_and_an_expired_one_fails_as_an_exact_copy() {
    use cgka_engine::provider::EngineOpenMlsProvider;
    use cgka_traits::engine::SendIntent;
    use cgka_traits::storage::{
        AccountDeviceSignerStorage as _, OutboundIntentStorage as _, OwnCommitBaseline,
        OwnCommitIntent, ReinviteRetry, StorageProvider as _,
    };
    use openmls::prelude::{
        CredentialWithKey, KeyPackage as MlsKeyPackage, Lifetime, MlsMessageBodyIn, MlsMessageIn,
        MlsMessageOut, ProtocolVersion,
    };
    use openmls_basic_credential::SignatureKeyPair;
    use tls_codec::{Deserialize as _, Serialize as _};

    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let mut client = app.client("alice").await.unwrap();
    client.publish_key_package().await.unwrap();
    let mut groups = Vec::new();
    for name in ["live", "expired"] {
        let created = client.create_group(name, &[]).await.unwrap();
        groups.push(created.operation.unwrap());
    }
    let [live, expired] = <[GroupId; 2]>::try_from(groups).unwrap();
    let template = client.durably_owned_key_packages().unwrap().remove(0);

    // Alice's own KeyPackages at chosen lifetimes, built into a scratch store
    // so her owned list keeps its own, later, bound.
    let storage = app.account_storage("alice").unwrap();
    let account = app.account_home().account("alice").unwrap();
    let identity = MemberId::new(hex::decode(account.account_id_hex).unwrap());
    let binding = storage.account_device_signer(&identity).unwrap().unwrap();
    let suite = cgka_engine::DEFAULT_CIPHERSUITE;
    let signer = SignatureKeyPair::read(
        storage.mls_storage(),
        &binding.mls_signature_public_key,
        suite.signature_algorithm(),
    )
    .unwrap();
    let MlsMessageBodyIn::KeyPackage(parsed) =
        MlsMessageIn::tls_deserialize_exact(template.bytes())
            .unwrap()
            .extract()
    else {
        panic!("expected a KeyPackage")
    };
    let crypto = openmls_rust_crypto::RustCrypto::default();
    let parsed = parsed.validate(&crypto, ProtocolVersion::Mls10).unwrap();
    let leaf = parsed.leaf_node();
    let scratch = storage_sqlite::SqliteAccountStorage::in_memory_for_test().unwrap();
    let reinvite = |group: &GroupId, commit_byte: u8, lifetime: Lifetime| {
        let bundle = MlsKeyPackage::builder()
            .leaf_node_capabilities(leaf.capabilities().clone())
            .leaf_node_extensions(leaf.extensions().clone())
            .key_package_lifetime(lifetime)
            .build(
                suite,
                &EngineOpenMlsProvider::<storage_sqlite::SqliteAccountStorage>::new(
                    &crypto,
                    scratch.mls_storage(),
                ),
                &signer,
                CredentialWithKey {
                    credential: leaf.credential().clone(),
                    signature_key: signer.public().into(),
                },
            )
            .unwrap();
        let mut key_package = KeyPackage::new(
            MlsMessageOut::from(bundle.key_package().clone())
                .tls_serialize_detached()
                .unwrap(),
        );
        key_package.protocol_profile = template.protocol_profile;
        storage
            .put_own_commit_intent(&OwnCommitIntent {
                commit_id: cgka_traits::MessageId::new(vec![commit_byte; 32]),
                group_id: group.clone(),
                source_epoch: cgka_traits::EpochId(0),
                intent: SendIntent::Invite {
                    group_id: group.clone(),
                    key_packages: vec![key_package],
                    initial_admins: vec![],
                },
                baseline: OwnCommitBaseline::None,
                reinvite: Some(ReinviteRetry::default()),
                reissue_attempts: 0,
                created_at_ms: 0,
            })
            .unwrap();
    };
    // An hour out: no load reaches the bound during the test, and it stays
    // the version's earliest one.
    let now = crate::unix_now_seconds();
    let not_after = now + 3_600;
    reinvite(&live, 0xc1, Lifetime::init(now - 3_600, not_after));
    reinvite(&expired, 0xc2, Lifetime::init(now - 7_200, now - 3_600));

    client.start_read_state(read_state_channel().0, UploadsInFlight::default());
    let state = client.subscribe_read_state().unwrap();
    assert!(state.borrow().groups[&live].recovery_status.is_ok());
    assert_eq!(state.borrow().valid_until, Some(Timestamp(not_after)));
    assert!(
        client
            .read_state_deadline()
            .is_some_and(|deadline| deadline <= Duration::from_secs(3_600))
    );

    let published = state.borrow().groups[&expired].recovery_status.clone();
    let published = published.unwrap_err();
    assert!(
        matches!(
            published.as_engine_error(),
            Some(cgka_traits::EngineError::InvalidKeyPackageLifetime { .. })
        ),
        "the expired KeyPackage fails the status: {published:?}"
    );
    let served = crate::client::read_state::reissue_error(&published)
        .expect("the expired KeyPackage's failure has an exact copy");
    assert_eq!(format!("{served:?}"), format!("{published:?}"));
}
