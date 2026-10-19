//! mdk#2323: terminal suspension close must reach every connection to
//! `session.sqlite`, including the one each account engine opens for itself,
//! not only the connections the app caches.
use super::*;

const LABEL: &str = "suspension-worker";

struct SuspensionRoot {
    _dir: tempfile::TempDir,
    root: PathBuf,
    app: MarmotApp,
    relay: Arc<ScriptedPushRelayClient>,
    session_path: PathBuf,
}

/// An exclusive-root app with one account whose engine has written a group,
/// so `session.sqlite` is a WAL database with real content.
async fn open_suspension_root() -> (SuspensionRoot, GroupId) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    AccountHome::open(&root).create_account(LABEL).unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::try_with_relays_and_account_home_and_config(
        &root,
        vec!["wss://suspension-engine.example".to_owned()],
        AccountHome::open(&root),
        MarmotAppConfig::white_noise().with_allow_loopback_relay_endpoints(true),
    )
    .unwrap()
    .with_test_relay_client(relay.clone());
    let mut setup_client = app.client(LABEL).await.unwrap();
    let group_id = setup_client.create_group("suspension", &[]).await.unwrap();
    drop(setup_client);

    let session_path = app.account_storage_path(LABEL);
    (
        SuspensionRoot {
            _dir: dir,
            root,
            app,
            relay,
            session_path,
        },
        group_id,
    )
}

/// Nothing in this process may still hold `session.sqlite` open.
///
/// SQLite deletes the `-wal` and `-shm` sidecars only when the last connection
/// to a database in this process closes, so their absence is the in-process
/// proof. A cross-process lock probe is not: closing any other descriptor on
/// the database drops this process's POSIX locks while its connections stay
/// open, and such a probe then succeeds and deletes the sidecars from under
/// them. So check the sidecars first, before anything else touches the file.
fn assert_no_session_connection_remains(root: &SuspensionRoot) {
    for suffix in ["-wal", "-shm"] {
        let sidecar = PathBuf::from(format!("{}{suffix}", root.session_path.display()));
        assert!(
            !sidecar.exists(),
            "{} outlived terminal close: a session.sqlite connection is still open",
            sidecar.display()
        );
    }
    drop(MarmotRootRuntimeLease::try_acquire(&root.root).expect("root lease must be released"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_and_close_releases_an_idle_worker_engine_connection() {
    let (root, group_id) = open_suspension_root().await;
    let runtime = root.app.runtime();
    runtime.reconcile_accounts().await.unwrap();
    runtime
        .send_message(LABEL, &group_id, b"before suspension".to_vec())
        .await
        .expect("the worker's engine must be open and writable");

    runtime.shutdown_and_close().await.unwrap();

    assert!(runtime.storage_is_closed());
    assert_no_session_connection_remains(&root);
}

/// A worker inside a command still owns its engine, so graceful shutdown
/// cannot drop it before the budget runs out. The engine's connection must
/// already be closed when the call returns.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_and_close_releases_a_busy_worker_engine_connection() {
    let (root, group_id) = open_suspension_root().await;
    let runtime = root.app.runtime();
    runtime.reconcile_accounts().await.unwrap();
    root.relay.block_next_publish();
    let sending = runtime.clone();
    let send = tokio::spawn(async move {
        sending
            .send_message(LABEL, &group_id, b"during suspension".to_vec())
            .await
    });
    tokio::time::timeout(
        Duration::from_secs(5),
        root.relay.wait_for_blocked_publish(),
    )
    .await
    .expect("the worker should be holding its engine inside the send");
    runtime.set_shutdown_grace_wait_for_test(Duration::from_millis(50));

    runtime.shutdown_and_close().await.unwrap();

    assert!(runtime.storage_is_closed());
    assert_no_session_connection_remains(&root);
    // The worker comes back from the relay to a closed engine and must still
    // finish the command rather than wedge.
    root.relay.release_publish();
    tokio::time::timeout(Duration::from_secs(5), send)
        .await
        .expect("the interrupted send must finish")
        .unwrap()
        .expect_err("a send cut off by terminal close cannot succeed");
}

/// An account open that has built its engine but not yet handed the client to
/// its worker is the same exposure: the engine's connection exists and nothing
/// the app caches holds it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_and_close_releases_the_engine_of_an_account_open_in_flight() {
    use crate::runtime::account_worker::AccountStartupStage;

    let (root, _) = open_suspension_root().await;
    let (reached_tx, reached) = std::sync::mpsc::channel();
    let (proceed, proceed_rx) = std::sync::mpsc::channel();
    root.app
        .install_local_open_gate(
            LABEL,
            AccountStartupStage::SessionOpen,
            reached_tx,
            proceed_rx,
        )
        .unwrap();
    let runtime = root.app.runtime();
    let starting = runtime.clone();
    let reconcile = tokio::spawn(async move { starting.reconcile_accounts().await });
    tokio::task::spawn_blocking(move || reached.recv_timeout(Duration::from_secs(10)))
        .await
        .unwrap()
        .expect("the account open should reach its engine-open gate");
    runtime.set_shutdown_grace_wait_for_test(Duration::from_millis(50));

    runtime.shutdown_and_close().await.unwrap();

    assert!(runtime.storage_is_closed());
    assert_no_session_connection_remains(&root);
    proceed.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), reconcile)
        .await
        .expect("the interrupted account open must finish")
        .unwrap()
        .expect_err("an account open cut off by terminal close cannot succeed");
}
