//! The live boundary and its provisional tail (mdk#2660 phase 4): what a
//! live REQ's count proves, what its open REQ vouches for while it lasts, and
//! what ends that.
use std::time::Duration;

use storage_sqlite::{RecoveryCause, RecoveryCoverageProof, TransportReconciliationRoute};
use transport_nostr_adapter::{
    ReplayLiveCount, ReplaySourceGeneration, SubscriptionRefusal, SubscriptionRefusalDisposition,
};

use super::scenario_tests::{
    Fixture, STORED_AT, authorize, certified_routes, fixture, fixture_with_stored, owed,
    reactivate, relay, report, routes,
};
use super::{LiveCountFact, LiveCoverage, live_boundary_since, retention_floor};
use crate::unix_now_seconds;

const HOUR: u64 = 60 * 60;

/// When the counts below were requested.
const REQUESTED: u64 = 1_000;

const INBOX: TransportReconciliationRoute = TransportReconciliationRoute::Inbox;

fn count(events: usize, oldest: Option<u64>) -> ReplayLiveCount {
    ReplayLiveCount {
        events,
        oldest,
        requested_at: REQUESTED,
        live_from: REQUESTED,
    }
}

fn fact(
    routes: Vec<TransportReconciliationRoute>,
    count: ReplayLiveCount,
    ended: bool,
) -> LiveCountFact {
    LiveCountFact {
        key: (
            "req".to_owned(),
            relay(),
            ReplaySourceGeneration::from_raw_for_test(1),
        ),
        routes,
        since: 100,
        count,
        ended,
        placed: true,
    }
}

/// The ranges `facts` would write now, one per count they settle.
fn durable(live: &LiveCoverage, facts: &[LiveCountFact]) -> Vec<Option<(u64, u64)>> {
    live.durable(facts)
        .into_iter()
        .map(|(_, range)| range)
        .collect()
}

/// The last second owed on the inbox at `now` after `facts`' tails, with no
/// released second.
fn inbox_owed_until(live: &LiveCoverage, facts: &[LiveCountFact], now: u64) -> u64 {
    live.tails(facts, |_, since| Some(since))
        .owed_until(&INBOX, &relay(), now)
}

/// A count proves only what is newer than the oldest event the client saw,
/// and never before the REQ's own `since`, however many events it holds: the
/// SDK may have dropped frames the relay sent. An empty count proves nothing.
#[test]
fn a_count_proves_only_above_its_oldest_event() {
    assert_eq!(live_boundary_since(100, &count(0, None)), None);
    assert_eq!(live_boundary_since(100, &count(3, Some(150))), Some(151));
    assert_eq!(
        live_boundary_since(100, &count(500, Some(150))),
        Some(151),
        "the oldest second may hide more events"
    );
    assert_eq!(
        live_boundary_since(100, &count(3, Some(90))),
        Some(100),
        "never below the REQ's own since"
    );
}

/// The ledger holds only what the relay had stored when it ran the query:
/// through the second before the REQ went out, on every route its filter
/// carries. The open REQ vouches for the rest while it lasts, so nothing
/// after that is owed. A count is written once.
#[test]
fn a_durable_proof_stops_before_the_request_and_the_tail_runs_from_it() {
    let groups = vec![
        TransportReconciliationRoute::Group([1; 32]),
        TransportReconciliationRoute::Group([2; 32]),
    ];
    let facts = [fact(groups.clone(), count(2, Some(400)), false)];
    let mut live = LiveCoverage::opened_at(None);
    let written = live.durable(&facts);
    assert_eq!(written.len(), 1);
    assert_eq!(written[0].0.routes, groups);
    assert_eq!(written[0].1, Some((401, REQUESTED - 1)));
    let tails = live.tails(&facts, |_, since| Some(since));
    for route in &groups {
        assert_eq!(tails.owed_until(route, &relay(), 5_000), REQUESTED - 1);
        assert_eq!(
            tails.owed_until(route, &relay(), 500),
            500,
            "never past now"
        );
    }
    assert_eq!(
        tails.owed_until(&INBOX, &relay(), 5_000),
        5_000,
        "a route no REQ carries owes through now"
    );

    live.settled.insert(facts[0].key.clone());
    assert!(durable(&live, &facts).is_empty(), "written once");
}

/// An empty count settles with nothing written, and its open REQ still
/// vouches from the request on.
#[test]
fn an_empty_count_proves_nothing_but_keeps_its_tail() {
    let facts = [fact(vec![INBOX], count(0, None), false)];
    let live = LiveCoverage::opened_at(None);
    assert_eq!(durable(&live, &facts), [None]);
    assert_eq!(inbox_owed_until(&live, &facts, 5_000), REQUESTED - 1);
}

/// With every event it returned from the request on, the relay may have cut
/// what it stored after the request, so the tail starts past the oldest
/// event it returned. An older one means it sent everything stored since.
#[test]
fn a_reply_newer_than_its_request_starts_its_tail_past_the_oldest_event() {
    let live = LiveCoverage::opened_at(None);
    let newer = [fact(vec![INBOX], count(500, Some(1_200)), false)];
    assert_eq!(inbox_owed_until(&live, &newer, 5_000), 1_200);
    let older = [fact(vec![INBOX], count(500, Some(900)), false)];
    assert_eq!(inbox_owed_until(&live, &older, 5_000), REQUESTED - 1);
}

/// A REQ the relay pool sent again (on a reconnect, or after a kept
/// `CLOSED`) proves only to its stamp, which may be older than the resend,
/// but vouches only from its own EOSE, so the time the REQ was down stays
/// owed.
#[test]
fn a_resent_reqs_tail_starts_at_its_eose() {
    let resent = |events, oldest| {
        let mut count = count(events, oldest);
        count.live_from = REQUESTED + 400;
        [fact(vec![INBOX], count, false)]
    };
    let live = LiveCoverage::opened_at(None);
    let empty = resent(0, None);
    assert_eq!(durable(&live, &empty), [None]);
    assert_eq!(inbox_owed_until(&live, &empty, 5_000), REQUESTED + 399);

    let older = resent(3, Some(900));
    assert_eq!(durable(&live, &older), [Some((901, REQUESTED - 1))]);
    assert_eq!(inbox_owed_until(&live, &older, 5_000), REQUESTED + 399);

    let newer = resent(3, Some(REQUESTED + 600));
    assert_eq!(inbox_owed_until(&live, &newer, 5_000), REQUESTED + 600);
}

/// Two open REQs carrying a route each deliver what their relay stores from
/// their own start, so the earlier start stands.
#[test]
fn the_earliest_open_tail_on_a_route_stands() {
    let mut later = fact(vec![INBOX], count(0, None), false);
    later.key.0 = "later".to_owned();
    later.count.requested_at = REQUESTED + 100;
    later.count.live_from = REQUESTED + 100;
    let facts = [fact(vec![INBOX], count(0, None), false), later];
    let live = LiveCoverage::opened_at(None);
    assert_eq!(inbox_owed_until(&live, &facts, 5_000), REQUESTED - 1);
}

/// An ended generation is still written once but has no tail; a broken one
/// proves nothing and has no tail; unplaced input waits.
#[test]
fn ended_broken_and_unplaced_generations() {
    let mut live = LiveCoverage::opened_at(None);
    let ended = [fact(vec![INBOX], count(1, Some(50)), true)];
    assert_eq!(durable(&live, &ended), [Some((100, REQUESTED - 1))]);
    assert_eq!(inbox_owed_until(&live, &ended, 5_000), 5_000);

    let current = [fact(vec![INBOX], count(1, Some(50)), false)];
    live.broken.insert(current[0].key.clone());
    assert!(durable(&live, &current).is_empty());
    assert_eq!(inbox_owed_until(&live, &current, 5_000), 5_000);

    let mut unplaced = fact(vec![INBOX], count(1, Some(50)), false);
    unplaced.placed = false;
    let unplaced = [unplaced];
    let fresh = LiveCoverage::opened_at(None);
    assert!(durable(&fresh, &unplaced).is_empty(), "waits for placement");
    assert_eq!(inbox_owed_until(&fresh, &unplaced, 5_000), 5_000);
}

/// The REQ will not deliver a released event again, so its tail starts past
/// the newest second released on that route; a failed read drops the tail.
#[test]
fn the_tail_starts_past_released_seconds() {
    let first = TransportReconciliationRoute::Group([1; 32]);
    let second = TransportReconciliationRoute::Group([2; 32]);
    let facts = [fact(
        vec![first.clone(), second.clone()],
        count(0, None),
        false,
    )];
    let live = LiveCoverage::opened_at(None);
    let tails = live.tails(&facts, |route, since| {
        assert_eq!(since, REQUESTED);
        (route == &first).then_some(1_501)
    });
    assert_eq!(tails.owed_until(&first, &relay(), 5_000), 1_500);
    assert_eq!(tails.owed_until(&second, &relay(), 5_000), 5_000);
}

/// Owe every current route its retained window, as startup history does, so
/// any unproved second shows as debt.
fn owe_retained_window(fixture: &Fixture) {
    fixture
        .storage
        .app_storage()
        .widen_recovery_coverage_goals(
            &routes(&fixture.client),
            retention_floor(unix_now_seconds()),
        )
        .unwrap();
}

/// Where the relay's live boundary on `route` ends.
fn live_until(fixture: &Fixture, route: &TransportReconciliationRoute) -> Option<u64> {
    fixture
        .storage
        .app_storage()
        .recovery_coverage_ranges(route, &relay())
        .unwrap()
        .iter()
        .filter(|proved| proved.proof == RecoveryCoverageProof::LiveBoundary)
        .map(|proved| proved.range.until_seconds)
        .max()
}

fn group_route(fixture: &Fixture) -> TransportReconciliationRoute {
    routes(&fixture.client)
        .into_iter()
        .find(|route| matches!(route, TransportReconciliationRoute::Group(_)))
        .expect("the group's route")
}

/// The group's live REQ and the endpoint it was issued on.
async fn group_request(fixture: &Fixture) -> (String, String) {
    let observation = fixture.client.adapter.replay_admission().await;
    observation
        .sources()
        .find(|source| source.group_routes().next().is_some())
        .and_then(|source| {
            let endpoint = source.endpoints().next()?;
            Some((
                source.id().to_owned(),
                endpoint.endpoint().as_str().to_owned(),
            ))
        })
        .expect("the group's live REQ")
}

/// One healthy generation vouches to now without a new EOSE: an idle,
/// connected account owes nothing over hours, and the shadow report has
/// nothing to disagree about. The ledger itself holds only what the EOSE
/// proved, up to the request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_idle_connected_account_grows_no_debt_over_hours() {
    let opened = unix_now_seconds();
    let fixture = fixture().await;
    let activated = unix_now_seconds();
    owe_retained_window(&fixture);
    let later = activated + 6 * HOUR;
    for route in routes(&fixture.client) {
        assert!(!owed(&fixture, &route, later).await, "the tail vouches");
        let until = live_until(&fixture, &route).expect("a live boundary");
        assert!(
            opened <= until + 1 && until < activated,
            "{opened} {until} {activated}"
        );
    }
    assert_eq!(report(&fixture).await.disagreements(), 0);
}

/// A tail stands only on what the relay client reports when asked: a
/// reconnect it has not reported (the adapter saw no `Disconnected`, no new
/// boundary) leaves every route owed at once, and the earlier proof stays.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tail_lapses_when_the_client_reports_another_connection() {
    let fixture = fixture().await;
    owe_retained_window(&fixture);
    let later = unix_now_seconds() + HOUR;
    for route in routes(&fixture.client) {
        assert!(!owed(&fixture, &route, later).await, "the tail vouches");
    }
    fixture
        .relay
        .connection_attempt
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    for route in routes(&fixture.client) {
        assert!(owed(&fixture, &route, later).await, "{route:?}");
        assert!(live_until(&fixture, &route).is_some(), "the proof stays");
    }
}

/// An EOSE with no event before it proves nothing durable, so the account
/// owes what its REQs replayed even while they stay open; only the tail from
/// the request on is not owed. Phase 2 counted any admitted boundary as
/// covered, a silently truncated one too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_empty_count_proves_nothing() {
    let fixture = fixture_with_stored(None).await;
    let activated = unix_now_seconds();
    owe_retained_window(&fixture);
    let app = fixture.storage.app_storage();
    let later = activated + HOUR;
    let tails = fixture.client.live_tails(&app, later).await;
    for route in routes(&fixture.client) {
        assert_eq!(live_until(&fixture, &route), None);
        let until = tails.owed_until(&route, &relay(), later);
        assert!(until < activated, "the tail runs from the request");
        assert!(owed(&fixture, &route, later).await);
    }
}

/// The relay closing the group's REQ ends that generation's tail: the time
/// since its request is owed while the open inbox REQ still vouches. The
/// next generation's EOSE proves the gap only when it counted an event older
/// than the gap.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_closed_req_ends_its_tail_and_the_next_eose_proves_the_gap() {
    for stored in [Some(STORED_AT), None] {
        let mut fixture = fixture().await;
        owe_retained_window(&fixture);
        let group = group_route(&fixture);
        let (id, endpoint) = group_request(&fixture).await;
        fixture
            .client
            .relay_plane
            .handle_relay_closed_for_test(
                cgka_traits::TransportEndpoint(endpoint),
                id,
                SubscriptionRefusal {
                    category: None,
                    disposition: SubscriptionRefusalDisposition::Dropped,
                },
            )
            .await;
        let later = unix_now_seconds() + HOUR;
        assert!(
            owed(&fixture, &group, later).await,
            "the closed tail is owed"
        );
        assert!(
            !owed(&fixture, &INBOX, later).await,
            "the inbox REQ vouches"
        );

        *fixture.relay.stored_before_eose.lock().unwrap() = stored;
        // The next request goes out in a later second, so a gap exists.
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        reactivate(&mut fixture).await;
        assert_eq!(
            owed(&fixture, &group, later).await,
            stored.is_none(),
            "the reconnect's EOSE proves the gap only above an event it counted"
        );
    }
}

/// A reopened session gives no tail to a generation an earlier session of
/// the account saw begin, since loss imported between the two is behind its
/// first mark. Its own activation's generations prove the time since.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reopened_session_trusts_only_generations_it_saw_begin() {
    let Fixture {
        _dir,
        _pump,
        client,
        storage,
        group,
        relay,
    } = fixture().await;
    let before = unix_now_seconds();
    client
        .record_native_coverage_at(&storage.app_storage(), before)
        .await;
    let marmot = client.app.clone();
    drop(client);
    // Opened on the same relay plane without activating: the shared adapter
    // still reports the earlier session's REQs.
    let client = marmot
        .local_client_with_relay_plane("alice", &marmot.relay_plane.clone(), None)
        .await
        .unwrap();
    let mut fixture = Fixture {
        _dir,
        _pump,
        client,
        storage,
        group,
        relay,
    };
    owe_retained_window(&fixture);
    let later = before + HOUR;
    for route in routes(&fixture.client) {
        assert!(owed(&fixture, &route, later).await);
        assert!(live_until(&fixture, &route).is_some_and(|until| until < before));
    }

    reactivate(&mut fixture).await;
    let now = unix_now_seconds();
    for route in routes(&fixture.client) {
        assert!(
            !owed(&fixture, &route, now).await,
            "the new generation proves it"
        );
    }
}

/// Loss during a generation leaves its seconds owed: the generation it may
/// have reached has no tail again, even once the loss's own obligation is
/// gone. The next generation's EOSE proves the range again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn loss_during_a_generation_leaves_its_seconds_owed() {
    let mut fixture = fixture().await;
    let app = fixture.storage.app_storage();
    let floor = unix_now_seconds().saturating_sub(30);
    app.record_account_delivery_loss_bounded("alice", 41, 3, unix_now_seconds(), Some(floor))
        .unwrap();
    fixture.client.synchronize_recovery_loss(&app).unwrap();
    let later = unix_now_seconds() + HOUR;
    for route in routes(&fixture.client) {
        assert!(owed(&fixture, &route, later).await);
        assert!(live_until(&fixture, &route).is_none_or(|until| until < floor));
        assert!(
            !app.recovery_coverage_covers(&route, &[relay()], floor, floor)
                .unwrap(),
            "the loss's seconds stay owed"
        );
    }

    // A certified pass settles the loss's obligation and covers its window;
    // the broken generation still vouches for nothing after it.
    let grant = authorize(&mut fixture.client).await;
    fixture.client.test_comparison_results = Some(certified_routes(&grant));
    fixture
        .client
        .run_recovery_grant_for_test(grant)
        .await
        .unwrap();
    assert!(
        app.pending_recovery_demands()
            .unwrap()
            .iter()
            .all(|demand| demand.cause != RecoveryCause::QueueLoss)
    );
    for route in routes(&fixture.client) {
        assert!(owed(&fixture, &route, later).await);
    }

    reactivate(&mut fixture).await;
    let now = unix_now_seconds();
    for route in routes(&fixture.client) {
        assert!(
            !owed(&fixture, &route, now).await,
            "the new generation proves it"
        );
    }
}

/// A receipt released under an open REQ is not delivered again by it, so the
/// tail starts past its second and everything up to it is owed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_released_second_stays_owed_under_the_tail() {
    use cgka_traits::storage::MessageStorage;

    let fixture = fixture().await;
    let app = fixture.storage.app_storage();
    let group = group_route(&fixture);
    // At or after the request: inside the tail.
    let sent = unix_now_seconds();
    let item = storage_sqlite::TransportReconciliationItem {
        event_id: [0xfb; 32],
        created_at: sent,
    };
    app.record_reconciliation_items(std::iter::once((&group, &item)))
        .unwrap();
    let record = cgka_traits::MessageRecord {
        id: cgka_traits::MessageId::new(item.event_id.to_vec()),
        group_id: fixture.group.clone(),
        epoch: cgka_traits::EpochId(0),
        state: cgka_traits::MessageState::PeelDeferred,
        payload: Vec::new(),
        deferred_peel: None,
    };
    fixture.storage.put_message(&record).unwrap();
    fixture.storage.release_message_for_replay(&record).unwrap();
    let later = sent + 6 * HOUR;
    let tails = fixture.client.live_tails(&app, later).await;
    assert_eq!(tails.owed_until(&group, &relay(), later), sent);
    assert!(owed(&fixture, &group, later).await);
    assert!(
        !app.recovery_coverage_covers(&group, &[relay()], sent, sent)
            .unwrap()
    );
    assert!(
        !owed(&fixture, &INBOX, later).await,
        "the inbox does not carry it"
    );
}
