//! A, the account's published read state, on the account worker (mdk#3273
//! PR 2). A host that awaited a mutation's reply, or saw an event, reads at
//! least the state it describes: the worker's two exits, `reply` and `emit`,
//! publish A before the answer or event leaves, and every reply and event in
//! the worker goes through one of them or names why it does not.

use super::*;
use crate::client::read_state::{ReadState, UploadsInFlight};

/// A client that publishes A, with the receiver a host would read.
async fn publishing_client(app: &MarmotApp) -> (AppClient, watch::Receiver<Arc<ReadState>>) {
    let mut client = app.client("alice").await.unwrap();
    client.start_read_state(UploadsInFlight::default());
    let state = client
        .subscribe_read_state()
        .expect("the client publishes A");
    (client, state)
}

fn app(dir: &tempfile::TempDir) -> MarmotApp {
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()))
}

/// A reply leaves after the publish that holds the write before it: the
/// group a unit created is in A when its caller has the answer.
#[tokio::test]
async fn a_reply_follows_the_publish_that_holds_its_write() {
    let dir = tempfile::tempdir().unwrap();
    let app = app(&dir);
    let (mut client, state) = publishing_client(&app).await;
    let group = client
        .create_group("replied", &[])
        .await
        .unwrap()
        .operation
        .unwrap();
    assert!(!state.borrow().groups.contains_key(&group));

    let (respond, mut answer) = oneshot::channel();
    reply(respond, group.clone(), &client).unwrap();

    let answered = answer.try_recv().unwrap();
    assert!(state.borrow().groups.contains_key(&answered));
}

/// An event at a quiescent point leaves after the publish that holds the
/// write before it; one emitted mid-unit leaves without a publish.
#[tokio::test]
async fn an_event_follows_the_publish_that_holds_its_write() {
    let dir = tempfile::tempdir().unwrap();
    let app = app(&dir);
    let (mut client, state) = publishing_client(&app).await;
    let (events, mut received) = broadcast::channel(4);

    let echoed = client
        .create_group("echoed", &[])
        .await
        .unwrap()
        .operation
        .unwrap();
    publish_app_runtime_group_state_updated(
        Emit::Unpublished(Unpublished::LocalEcho),
        &events,
        "account",
        "alice",
        &echoed,
    );
    assert!(matches!(
        received.try_recv().unwrap(),
        MarmotAppEvent::GroupStateUpdated { .. }
    ));
    assert!(!state.borrow().groups.contains_key(&echoed));

    publish_app_runtime_group_state_updated(
        Emit::Quiescent(&client),
        &events,
        "account",
        "alice",
        &echoed,
    );
    let MarmotAppEvent::GroupStateUpdated { group_id, .. } = received.try_recv().unwrap() else {
        panic!("one group state event");
    };
    assert!(state.borrow().groups.contains_key(&group_id));
}

/// Every reply and every host event the worker sends goes through `reply`
/// or `emit`, which publish A first, or through a helper that names why it
/// does not. A new raw send fails here.
#[test]
fn every_reply_and_event_leaves_the_worker_through_a_named_exit() {
    let source = include_str!("../../account_worker.rs");
    let worker = source
        .split("\n#[cfg(test)]\nmod tests {")
        .next()
        .expect("the worker module has a test module");
    let raw_events: Vec<_> = worker
        .match_indices("events.send(")
        .map(|(at, _)| at)
        .collect();
    assert_eq!(raw_events.len(), 1, "only `emit` sends a host event");
    let emit = worker.find("fn emit(").expect("the worker has an `emit`");
    assert!(raw_events[0] > emit && raw_events[0] - emit < 600);
    for raw in ["respond.send(", "respond.send_with(", ".send_reply("] {
        let sites: Vec<_> = worker.match_indices(raw).collect();
        let allowed = match raw {
            // `answer_off_quiescent`'s own send.
            "respond.send(" => 1,
            // `reply`'s own send.
            ".send_reply(" => 1,
            _ => 0,
        };
        assert_eq!(
            sites.len(),
            allowed,
            "a reply that bypasses `reply`, `respond_diagnosed` and the named exemptions: {raw}"
        );
    }
}

/// On the worker, A is live: a host that awaited a create's reply finds
/// the group in it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_worker_publishes_a() {
    let dir = tempfile::tempdir().unwrap();
    let app = app(&dir);
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    runtime.reconcile_accounts().await.unwrap();
    let (respond, subscribed) = oneshot::channel();
    runtime
        .accounts()
        .worker_commands("alice")
        .await
        .unwrap()
        .send(AccountWorkerCommand::SubscribeReadStateForTest { respond })
        .await
        .unwrap();
    let state = subscribed.await.unwrap().expect("the worker publishes A");
    let group = runtime
        .create_group("alice", "replied", &[], None)
        .await
        .unwrap()
        .operation
        .unwrap();
    assert!(state.borrow().groups.contains_key(&group));
    runtime.shutdown().await;
}
