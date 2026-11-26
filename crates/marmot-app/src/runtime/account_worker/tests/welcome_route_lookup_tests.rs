//! The account worker's inbox lookups (mdk#2261): an owed Welcome whose
//! recipient has no usable inbox route is looked up beside the writer, and
//! delivered once the lookup finds a list. The client's tests
//! (`tests/welcome_routes.rs`) own what a lookup installs and the pacing.
//! These own what only the worker decides: running the lookup beside the
//! writer, sending the Welcome once it is released, and ending a lookup at
//! shutdown.

use super::writer_hold_tests::SETTLE;
use super::*;
use crate::tests::welcome_routes::{RouteLessInvite, bob_inbox_list, route_less_invite};
use crate::{KIND_MARMOT_INBOX_RELAY_LIST, WelcomeDeliveryProblem, WelcomeDeliveryState};

const BOB_LISTED_INBOX: &str = "wss://bob-listed-inbox.example";

/// Bob's invite state as Alice's worker answers it.
async fn bob_state(runtime: &crate::MarmotAppRuntime, group: &GroupId) -> WelcomeDeliveryState {
    timeout(SETTLE, runtime.invite_deliveries("alice", Some(group)))
        .await
        .expect("the worker answers")
        .unwrap()[0]
        .state
}

/// The relay-fixture journey: Alice's route-less invite is reopened by a
/// runtime while the relays serve Bob's newer inbox list, which no cache
/// holds. At its startup retry the Welcome finds no route, the worker looks
/// Bob's list up, and the Welcome then goes out to it and is
/// `RelayAccepted`, with no re-invite.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_looked_up_inbox_list_delivers_the_owed_welcome() {
    let invite = route_less_invite().await;
    let RouteLessInvite {
        alice,
        app,
        relay,
        fetcher,
        bob_id,
        group,
        now,
        ..
    } = invite;
    drop(alice);
    fetcher
        .events
        .lock()
        .unwrap()
        .push(bob_inbox_list(&bob_id, BOB_LISTED_INBOX, now - 10));
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    let mut events = runtime.subscribe();
    runtime.reconcile_accounts().await.unwrap();

    timeout(SETTLE, async {
        loop {
            if let Ok(MarmotAppEvent::InviteDeliveryChanged { delivery, .. }) = events.recv().await
                && delivery.state == WelcomeDeliveryState::RelayAccepted
            {
                break;
            }
        }
    })
    .await
    .expect("the looked-up list delivers the Welcome");
    assert_eq!(
        bob_state(&runtime, &group).await,
        WelcomeDeliveryState::RelayAccepted
    );
    assert!(
        relay
            .attempted_routes()
            .iter()
            .any(|(kind, endpoints)| *kind == 1059
                && endpoints
                    .iter()
                    .any(|endpoint| endpoint.0.starts_with(BOB_LISTED_INBOX))),
        "sent to the list the lookup found"
    );
    runtime.shutdown().await;
}

/// A lookup runs beside the writer: while the relays leave it unanswered the
/// worker still answers the host, and at shutdown the worker ends it without
/// waiting for the relays (L2), before shutdown's bound would abort it. Nothing is sent, and the Welcome stays owed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_lookup_leaves_the_worker_answering_and_ends_at_shutdown() {
    let invite = route_less_invite().await;
    let RouteLessInvite {
        alice,
        app,
        relay,
        fetcher,
        bob_id,
        group,
        ..
    } = invite;
    drop(alice);
    let looking_up = Arc::new(tokio::sync::Notify::new());
    let entered = looking_up.clone();
    fetcher.never_answer(move |request| {
        let held = request.queries.iter().any(|query| {
            query.kind == KIND_MARMOT_INBOX_RELAY_LIST && query.authors == [bob_id.clone()]
        });
        if held {
            entered.notify_one();
        }
        held
    });
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    runtime.reconcile_accounts().await.unwrap();
    timeout(SETTLE, looking_up.notified())
        .await
        .expect("the worker looks Bob's inbox list up");

    assert_eq!(
        bob_state(&runtime, &group).await,
        WelcomeDeliveryState::Sending {
            last_problem: Some(WelcomeDeliveryProblem::NoInboxRelays)
        },
        "the worker answers while the lookup waits on the relays"
    );
    let welcome_sends = || {
        relay
            .attempted_routes()
            .iter()
            .filter(|(kind, _)| *kind == 1059)
            .count()
    };
    let sent = welcome_sends();
    // The worker ends the lookup itself, well inside the bound after which
    // shutdown aborts the worker.
    let stopping = std::time::Instant::now();
    timeout(SETTLE, runtime.shutdown())
        .await
        .expect("shutdown does not wait for the relays");
    assert!(
        stopping.elapsed() < crate::APP_RUNTIME_ACCOUNT_SHUTDOWN_WAIT,
        "the worker ended the lookup, not shutdown's abort"
    );
    assert_eq!(welcome_sends(), sent, "nothing was sent");
}
