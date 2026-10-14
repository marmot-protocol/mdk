#![cfg(feature = "sdk")]
// Test fixtures dial local relays directly.
#![allow(clippy::disallowed_methods)]

//! Subscription behaviour against a relay that enforces the production
//! per-connection limits (see `support/limit_relay.rs`): at most 200 live
//! REQs, 3 filters per REQ, 16 kinds per filter, and an explicit-kind
//! allow-list. Synthetic group routes only; no MLS.
//!
//! Output is aggregate counts only: no ids, keys, URLs or payloads.

#[path = "support/limit_relay.rs"]
mod limit_relay;

use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cgka_traits::{
    GroupId, MemberId, TransportAccountActivation, TransportAdapter, TransportAdapterError,
    TransportEndpoint, TransportGroupSubscription,
};
use limit_relay::{LimitConfig, LimitRelay, LimitStats, NegFault, RejectStyle, ReqOutcome, reason};
use nostr_relay_builder::prelude::{MemoryDatabase, MemoryDatabaseOptions, NostrDatabase};
use nostr_relay_builder::{LocalRelay, RelayBuilder};
use nostr_sdk::prelude::{Client, EventBuilder, FinalizeEvent, Keys, Kind, RelayOptions, Tag};
use tokio::task::JoinHandle;
use transport_nostr_adapter::{
    NostrReconciliationFailure, NostrReconciliationProgress, NostrRelayClient, NostrSdkRelayClient,
    NostrSubscription, NostrTransportAdapter, SubscriptionAttempt, SubscriptionRouteKind,
};

const QUIET: Duration = Duration::from_millis(600);
const SETTLE_TIMEOUT: Duration = Duration::from_secs(20);
/// Observation window for retry storms after the subscription set settles.
const STORM_WINDOW: Duration = Duration::from_secs(3);
const SINCE: u64 = 1_700_000_000 - 30 * 24 * 60 * 60;
const UNTIL: u64 = 1_700_200_000;

struct Fixture {
    _upstream: LocalRelay,
    upstream_url: String,
    database: MemoryDatabase,
    limit: LimitRelay,
    sdk: NostrSdkRelayClient,
    adapter: NostrTransportAdapter,
    forwarder: JoinHandle<()>,
    account: MemberId,
}

impl Fixture {
    async fn new(config: LimitConfig, fast_reconnect: bool) -> Self {
        let database = MemoryDatabase::with_opts(MemoryDatabaseOptions {
            events: true,
            max_events: Some(8_192),
        });
        // The limit proxy owns the 500 clamp; lift the upstream's own default
        // per-filter limit (also 500) so the clamp can be switched off.
        let upstream = LocalRelay::new(
            RelayBuilder::default()
                .database(database.clone())
                .default_filter_limit(100_000),
        );
        upstream.run().await.unwrap();
        let upstream_url = upstream.url().await.to_string();
        let limit = LimitRelay::start(upstream_url.clone(), config).await;
        // Mirrors the production per-account context, which is built with
        // `from_builder` (an owned relay pool).
        let sdk = NostrSdkRelayClient::from_builder(Client::builder());
        if fast_reconnect {
            // Pre-registering the relay keeps the adapter from pinning its 5 s
            // production retry interval (it only pins relays it adds), so a
            // forced drop reconnects in well under a second. Retry timing does
            // not change which REQs the SDK re-sends.
            sdk.client()
                .add_relay(limit.url())
                .opts(fast_retry_options())
                .await
                .unwrap();
        }
        let adapter = NostrTransportAdapter::new(Arc::new(sdk.clone()));
        let forwarder = sdk.spawn_notification_forwarder(adapter.clone());
        let account = MemberId::new(Keys::generate().public_key().to_bytes().to_vec());
        Self {
            _upstream: upstream,
            upstream_url,
            database,
            limit,
            sdk,
            adapter,
            forwarder,
            account,
        }
    }

    fn activation(
        &self,
        inbox: &[String],
        groups: Vec<TransportGroupSubscription>,
    ) -> TransportAccountActivation {
        TransportAccountActivation {
            account_id: self.account.clone(),
            inbox_endpoints: inbox.iter().cloned().map(TransportEndpoint).collect(),
            group_subscriptions: groups,
            since: None,
        }
    }

    async fn store_group_events(&self, count: usize) {
        let keys = Keys::generate();
        for index in 0..count {
            let event = EventBuilder::new(Kind::MlsGroupMessage, format!("payload-{index}"))
                .tags([Tag::custom("h", [hex::encode(route(index))])])
                .finalize(&keys)
                .unwrap();
            self.database
                .save_event(&serde_json::from_str(event.as_json().as_str()).unwrap())
                .await
                .unwrap();
        }
    }

    async fn shutdown(self) {
        self.forwarder.abort();
        self.sdk.client().shutdown().await;
    }
}

fn fast_retry_options() -> RelayOptions {
    RelayOptions::new()
        .retry_interval(Duration::from_millis(200))
        .adjust_retry_interval(false)
}

fn route(index: usize) -> Vec<u8> {
    let mut route = [0x5a_u8; 32];
    route[..4].copy_from_slice(&(index as u32).to_be_bytes());
    route.to_vec()
}

fn group_id(index: usize) -> GroupId {
    GroupId::new((index as u32).to_be_bytes().repeat(4))
}

fn groups(count: usize, endpoint: &str) -> Vec<TransportGroupSubscription> {
    (0..count)
        .map(|index| TransportGroupSubscription {
            group_id: group_id(index),
            transport_group_id: route(index),
            endpoints: vec![TransportEndpoint(endpoint.to_owned())],
            retained_since: None,
        })
        .collect()
}

/// Groups for which at least one delivery arrives within `wait`, stopping
/// early once deliveries go quiet.
async fn delivered_groups(
    adapter: &NostrTransportAdapter,
    expected: usize,
    wait: Duration,
) -> HashSet<Vec<u8>> {
    const IDLE: Duration = Duration::from_millis(1_500);
    let mut delivered = HashSet::new();
    let deadline = tokio::time::Instant::now() + wait;
    while delivered.len() < expected {
        let next = deadline.min(tokio::time::Instant::now() + IDLE);
        match tokio::time::timeout_at(next, adapter.receive()).await {
            Ok(Ok(Some(delivery))) => {
                if let Some(group) = delivery.group_id_hint {
                    delivered.insert(group.as_slice().to_vec());
                }
            }
            _ => break,
        }
    }
    delivered
}

fn refusal_counts(
    adapter: &NostrTransportAdapter,
    account: &MemberId,
) -> BTreeMap<&'static str, u64> {
    let mut counts = BTreeMap::new();
    for report in adapter.take_subscription_refusals(account).reports {
        *counts.entry(report.route_kind.as_str()).or_default() += report.count;
    }
    counts
}

fn assert_filter_shapes(stats: &LimitStats) {
    assert!(
        stats.max_filters_seen <= 3,
        "a REQ carried {} filters",
        stats.max_filters_seen
    );
    assert!(
        stats.max_kinds_seen <= 16,
        "a filter carried {} kinds",
        stats.max_kinds_seen
    );
    assert!(
        stats.disallowed_kinds_seen.is_empty(),
        "disallowed kinds requested: {:?}",
        stats.disallowed_kinds_seen
    );
    for shape_reason in [
        reason::TOO_MANY_FILTERS,
        reason::TOO_MANY_KINDS,
        reason::KIND_NOT_ALLOWED,
        reason::MALFORMED,
    ] {
        assert!(
            !stats.rejections.contains_key(shape_reason),
            "{shape_reason}"
        );
    }
}

// ---------------------------------------------------------------------------
// (a) Filter shape
// ---------------------------------------------------------------------------

/// Every REQ an activation of 250 groups plus an inbox sends stays within the
/// production filter limits. The 200-REQ socket limit refuses the overflow,
/// which is reported, not asserted away.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn activation_of_250_groups_sends_only_production_shaped_reqs() {
    let fx = Fixture::new(LimitConfig::default(), false).await;
    let url = fx.limit.url();
    fx.adapter
        .activate_account(fx.activation(std::slice::from_ref(&url), groups(250, &url)))
        .await
        .unwrap();
    let stats = fx.limit.wait_quiet(QUIET, SETTLE_TIMEOUT).await;
    eprintln!("[a] G=250 {}", stats.summary());
    assert_filter_shapes(&stats);
    assert!(
        stats.req_log.iter().all(|r| r.filters == 1),
        "one filter per live REQ"
    );
    assert_eq!(stats.total_reqs, 251);
    assert_eq!(stats.open_connections(), 1, "one socket carries every REQ");
    fx.shutdown().await;
}

#[derive(Default)]
struct Cursor(Mutex<Option<[u8; 32]>>);

impl NostrReconciliationProgress for Cursor {
    fn load_cursor(&self) -> Result<Option<[u8; 32]>, TransportAdapterError> {
        Ok(*self.0.lock().unwrap())
    }

    fn save_cursor(&self, cursor: Option<[u8; 32]>) -> Result<(), TransportAdapterError> {
        *self.0.lock().unwrap() = cursor;
        Ok(())
    }
}

fn reconciliation_route(url: &str, account: &MemberId) -> NostrSubscription {
    NostrSubscription::Group {
        account_id: account.clone(),
        group_id: group_id(0),
        transport_group_id: route(0),
        endpoints: vec![TransportEndpoint(url.to_owned())],
        since: None,
        attempt: SubscriptionAttempt::INITIAL,
    }
}

async fn store_timed_events(database: &MemoryDatabase, count: usize) {
    let keys = Keys::generate();
    for index in 0..count {
        let event = EventBuilder::new(Kind::MlsGroupMessage, format!("history-{index}"))
            .tags([Tag::custom("h", [hex::encode(route(0))])])
            .custom_created_at(nostr_sdk::prelude::Timestamp::from_secs(
                1_700_000_000 + index as u64,
            ))
            .finalize(&keys)
            .unwrap();
        database
            .save_event(&serde_json::from_str(event.as_json().as_str()).unwrap())
            .await
            .unwrap();
    }
}

/// A reconciliation (NEG-OPEN plus id fetches) sends production-shaped
/// filters on its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconciliation_neg_open_and_id_fetches_are_production_shaped() {
    let fx = Fixture::new(LimitConfig::default(), false).await;
    store_timed_events(&fx.database, 40).await;
    let url = fx.limit.url();
    fx.sdk.client().add_relay(url.as_str()).await.unwrap();
    fx.sdk.client().connect().await;
    let (summary, events) = fx
        .sdk
        .reconcile_subscription(
            reconciliation_route(&url, &fx.account),
            &[],
            SINCE,
            UNTIL,
            &Cursor::default(),
        )
        .await
        .unwrap();
    let stats = fx.limit.wait_quiet(QUIET, SETTLE_TIMEOUT).await;
    eprintln!(
        "[a] reconcile relays_succeeded={} returned={} {}",
        summary.relays_succeeded,
        events.len(),
        stats.summary()
    );
    assert!(stats.neg_opens > 0, "reconciliation used NEG-OPEN");
    assert!(stats.neg_max_kinds_seen <= 16);
    assert!(stats.neg_disallowed_kinds_seen.is_empty());
    assert!(stats.neg_rejections.is_empty());
    assert_filter_shapes(&stats);
    assert_eq!(events.len(), 40);
    fx.shutdown().await;
}

/// With 200 live REQs on the socket (inbox + 199 groups), run a
/// reconciliation on the same client. `neg_counts = false` is the deployed
/// strfry 1.1.3 model (separate NEG counter); `true` is the alternative where
/// NEG sessions share the REQ cap (answered with the NEG cap NOTICE).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconciliation_on_a_full_socket_under_both_neg_policies() {
    for neg_counts in [false, true] {
        let fx = Fixture::new(
            LimitConfig {
                neg_counts_toward_limit: neg_counts,
                ..LimitConfig::default()
            },
            false,
        )
        .await;
        store_timed_events(&fx.database, 20).await;
        let url = fx.limit.url();
        fx.adapter
            .activate_account(fx.activation(std::slice::from_ref(&url), groups(199, &url)))
            .await
            .unwrap();
        fx.limit.wait_quiet(QUIET, SETTLE_TIMEOUT).await;
        let result = fx
            .sdk
            .reconcile_subscription(
                reconciliation_route(&url, &fx.account),
                &[],
                SINCE,
                UNTIL,
                &Cursor::default(),
            )
            .await;
        let stats = fx.limit.wait_quiet(QUIET, SETTLE_TIMEOUT).await;
        let (ok, relays_failed, returned) = match &result {
            Ok((summary, events)) => (true, summary.relays_failed, events.len()),
            Err(_) => (false, 0, 0),
        };
        eprintln!(
            "[a] full-socket reconcile neg_counts={neg_counts} ok={ok} relays_failed={relays_failed} \
             returned={returned} {}",
            stats.summary()
        );
        assert_eq!(
            stats.open_connections(),
            1,
            "reconciliation shares the live socket"
        );
        assert_filter_shapes(&stats);
        // Finding: the comparison may pass, but the follow-up id-fetch REQ is
        // the socket's 201st live REQ and is refused, so nothing is returned
        // and the relay counts as failed. With NEG counted, the comparison
        // itself is refused first.
        assert!(ok, "reconciliation reports the failure per relay");
        assert_eq!(relays_failed, 1);
        assert_eq!(returned, 0);
        if neg_counts {
            assert_eq!(stats.neg_rejections.get(reason::TOO_MANY_NEG), Some(&1));
        } else {
            assert!(stats.neg_rejections.is_empty());
            assert_eq!(
                stats.rejections.get(reason::TOO_MANY_SUBSCRIPTIONS),
                Some(&1),
                "the id fetch REQ is refused"
            );
        }
        fx.shutdown().await;
    }
}

// ---------------------------------------------------------------------------
// (b) 200 / 201 boundary
// ---------------------------------------------------------------------------

struct BoundaryReport {
    stats: LimitStats,
    refusals: BTreeMap<&'static str, u64>,
    delivered: usize,
    complete: bool,
    settled: bool,
    subscriptions_refused: usize,
    reqs_in_window: usize,
}

async fn activate_at_boundary(fx: &Fixture, group_count: usize) -> BoundaryReport {
    fx.store_group_events(group_count).await;
    let url = fx.limit.url();
    fx.adapter
        .activate_account(fx.activation(std::slice::from_ref(&url), groups(group_count, &url)))
        .await
        .unwrap();
    let delivered = delivered_groups(&fx.adapter, group_count, Duration::from_secs(10)).await;
    let settled_stats = fx.limit.wait_quiet(QUIET, SETTLE_TIMEOUT).await;
    let window_start = Instant::now();
    tokio::time::sleep(STORM_WINDOW).await;
    let stats = fx.limit.stats();
    let eose = fx.adapter.account_subscription_eose(&fx.account).await;
    BoundaryReport {
        reqs_in_window: stats.reqs_since(window_start),
        refusals: refusal_counts(&fx.adapter, &fx.account),
        delivered: delivered.len(),
        complete: eose.complete(),
        settled: eose.settled(),
        subscriptions_refused: eose.subscriptions_refused,
        stats: {
            assert_eq!(settled_stats.total_reqs, stats.total_reqs);
            stats
        },
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inbox_plus_199_groups_fill_the_socket_without_refusal() {
    let fx = Fixture::new(LimitConfig::default(), false).await;
    let report = activate_at_boundary(&fx, 199).await;
    eprintln!(
        "[b] G=199 delivered={} complete={} settled={} refusals={:?} reqs_in_window={} {}",
        report.delivered,
        report.complete,
        report.settled,
        report.refusals,
        report.reqs_in_window,
        report.stats.summary()
    );
    assert_eq!(report.stats.total_reqs, 200);
    assert_eq!(report.stats.rejections_total(), 0);
    assert_eq!(report.stats.active_now(), 200);
    assert_eq!(report.delivered, 199);
    assert!(report.complete);
    assert_eq!(report.reqs_in_window, 0);
    fx.shutdown().await;
}

/// Beyond 200 live REQs the relay refuses the overflow. Report which route
/// is refused, what the adapter records, whether the rest still deliver, and
/// whether anything retries. Then re-activate (the app re-activates rather
/// than reusing while coverage is incomplete) and measure the cost.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn overflow_beyond_200_is_refused_once_and_not_retried() {
    for group_count in [200_usize, 201] {
        let fx = Fixture::new(LimitConfig::default(), false).await;
        let report = activate_at_boundary(&fx, group_count).await;
        let overflow = group_count + 1 - 200;
        eprintln!(
            "[b] G={group_count} delivered={} complete={} settled={} subscriptions_refused={} \
             refusals={:?} reqs_in_window={} {}",
            report.delivered,
            report.complete,
            report.settled,
            report.subscriptions_refused,
            report.refusals,
            report.reqs_in_window,
            report.stats.summary()
        );
        assert_eq!(report.stats.total_reqs, group_count + 1);
        assert_eq!(
            report.stats.rejections.get(reason::TOO_MANY_SUBSCRIPTIONS),
            Some(&overflow)
        );
        assert_eq!(report.stats.active_now(), 200);
        assert_eq!(report.stats.peak_active(), 200);
        assert_eq!(report.reqs_in_window, 0, "no retry storm after the refusal");
        assert!(
            !report.complete,
            "a refused route never completes replay coverage"
        );
        assert!(report.settled, "the refusal settles the wait");
        assert_eq!(report.subscriptions_refused, overflow);
        let refused_groups = report.refusals.get("group").copied().unwrap_or(0) as usize;
        assert_eq!(
            report.delivered,
            group_count - refused_groups,
            "every accepted group delivers"
        );

        // Re-activation, as `MarmotRelayPlaneAccountAdapter::activate_account`
        // does on every prepare_transport while coverage is incomplete.
        let url = fx.limit.url();
        let mut per_activation = Vec::new();
        for _ in 0..3 {
            let before = fx.limit.stats();
            fx.adapter
                .activate_account(
                    fx.activation(std::slice::from_ref(&url), groups(group_count, &url)),
                )
                .await
                .unwrap();
            let after = fx.limit.wait_quiet(QUIET, SETTLE_TIMEOUT).await;
            let refusals = refusal_counts(&fx.adapter, &fx.account);
            per_activation.push((
                after.total_reqs - before.total_reqs,
                after.closes - before.closes,
                after.closes_unknown - before.closes_unknown,
                after.rejections_total() - before.rejections_total(),
                refusals,
                after.active_now(),
            ));
        }
        eprintln!(
            "[b] G={group_count} reactivations (reqs, closes, closes_unknown, rejections, refusals, active): {per_activation:?}"
        );
        for (reqs, closes, _, rejections, _, active) in &per_activation {
            assert_eq!(*reqs, group_count + 1);
            // Only the 200 live REQs are CLOSEd: the SDK already dropped the refused one.
            assert_eq!(*closes, 200);
            assert_eq!(*rejections, overflow);
            assert_eq!(*active, 200);
        }
        fx.shutdown().await;
    }
}

// ---------------------------------------------------------------------------
// (c) Reconnect storm
// ---------------------------------------------------------------------------

async fn reconnect_storm(group_count: usize, drops: usize) -> Vec<(usize, usize, usize)> {
    let fx = Fixture::new(LimitConfig::default(), true).await;
    let url = fx.limit.url();
    fx.adapter
        .activate_account(fx.activation(std::slice::from_ref(&url), groups(group_count, &url)))
        .await
        .unwrap();
    let expected = (group_count + 1).min(200);
    let first = fx.limit.wait_quiet(QUIET, SETTLE_TIMEOUT).await;
    assert_eq!(first.active_now(), expected);
    let mut rounds = Vec::new();
    for round in 0..drops {
        let before = fx.limit.stats();
        let connections_before = before.connections.len();
        fx.limit.drop_all_connections();
        assert!(
            fx.limit
                .wait_for(SETTLE_TIMEOUT, |s| {
                    s.connections.len() > connections_before && s.active_now() >= expected
                })
                .await,
            "round {round}: reconnect restored the subscriptions"
        );
        let after = fx.limit.wait_quiet(QUIET, SETTLE_TIMEOUT).await;
        let connection = after.connections.len() - 1;
        let reqs = after.reqs_on_connection(connection);
        assert_eq!(after.open_connections(), 1, "round {round}");
        assert_eq!(after.active_now(), expected, "round {round}: no growth");
        assert_eq!(
            after.connections[connection].peak_active, expected,
            "round {round}"
        );
        assert_eq!(
            reqs, expected,
            "round {round}: one REQ per live subscription"
        );
        rounds.push((
            reqs,
            after.reqs_with_active_id - before.reqs_with_active_id,
            after.rejections_total() - before.rejections_total(),
        ));
    }
    let stats = fx.limit.stats();
    eprintln!(
        "[c] G={group_count} drops={drops} per-reconnect (reqs, reqs_with_active_id, rejections)={rounds:?} {}",
        stats.summary()
    );
    fx.shutdown().await;
    rounds
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconnect_storm_resends_exactly_the_live_set() {
    let rounds = reconnect_storm(150, 10).await;
    assert!(
        rounds
            .iter()
            .all(|&(reqs, dup, rej)| reqs == 151 && dup == 0 && rej == 0)
    );
}

/// At the limit, the refused REQ was dropped from the SDK registry, so a
/// reconnect re-sends only the 200 the relay accepted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconnect_storm_at_the_limit_does_not_resend_the_refused_req() {
    let rounds = reconnect_storm(200, 5).await;
    assert!(
        rounds
            .iter()
            .all(|&(reqs, dup, rej)| reqs == 200 && dup == 0 && rej == 0)
    );
}

// ---------------------------------------------------------------------------
// (d) Aborted / failed activation leak (#2262)
// ---------------------------------------------------------------------------

/// A relay endpoint nostr-sdk refuses to operate: a closed port that has
/// failed enough connection attempts for `ensure_operational` to reject
/// sends with "not connected".
async fn dead_relay(sdk: &NostrSdkRelayClient) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    drop(listener);
    sdk.client()
        .add_relay(url.as_str())
        .opts(fast_retry_options().connect_timeout(Duration::from_millis(100)))
        .await
        .unwrap();
    sdk.client().connect().await;
    // `ensure_operational` needs >1 failed attempt and the connect timeout
    // elapsed since wake-up, measured in whole seconds.
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    url
}

// Fields are read through `Debug` in the failure messages.
#[allow(dead_code)]
#[derive(Debug)]
struct LeakCheck {
    /// Live REQs once a clean activation of 1+G settles.
    active_after_activation: usize,
    reqs_on_reconnect: usize,
    active_after_reconnect: usize,
    /// REQs re-sent on reconnect under ids the clean activation never sent.
    stale_on_reconnect: usize,
    /// Of those, ids no REQ ever carried before: registered in the SDK but
    /// never sent until the reconnect.
    stale_never_sent_before: usize,
}

/// Activate cleanly, then force a reconnect, and report REQs that are live
/// beyond the clean activation's 1+G.
async fn leak_check(fx: &Fixture, group_count: usize, label: &str) -> LeakCheck {
    let url = fx.limit.url();
    let mark = Instant::now();
    fx.adapter
        .activate_account(fx.activation(std::slice::from_ref(&url), groups(group_count, &url)))
        .await
        .unwrap();
    let settled = fx.limit.wait_quiet(QUIET, SETTLE_TIMEOUT).await;
    let ids = |stats: &LimitStats, keep: &dyn Fn(&limit_relay::ReqRecord) -> bool| {
        stats
            .req_log
            .iter()
            .filter(|r| keep(r))
            .map(|r| r.subscription_id.clone())
            .collect::<HashSet<_>>()
    };
    let activation_ids = ids(&settled, &|r| r.at >= mark);
    let earlier_ids = ids(&settled, &|r| r.at < mark);
    let connections_before = settled.connections.len();
    fx.limit.drop_all_connections();
    fx.limit
        .wait_for(SETTLE_TIMEOUT, |s| {
            s.connections.len() > connections_before && s.open_connections() == 1
        })
        .await;
    let reconnected = fx.limit.wait_quiet(QUIET, SETTLE_TIMEOUT).await;
    let connection = reconnected.connections.len() - 1;
    let reconnect_ids = ids(&reconnected, &|r| r.connection == connection);
    let stale = reconnect_ids
        .difference(&activation_ids)
        .cloned()
        .collect::<HashSet<_>>();
    let check = LeakCheck {
        active_after_activation: settled.active_now(),
        reqs_on_reconnect: reconnected.reqs_on_connection(connection),
        active_after_reconnect: reconnected.active_now(),
        stale_never_sent_before: stale.difference(&earlier_ids).count(),
        stale_on_reconnect: stale.len(),
    };
    eprintln!("[d] {label}: {check:?} {}", reconnected.summary());
    check
}

/// One group route that nostr-sdk cannot operate fails `subscribe_all`. Every
/// REQ its sibling tasks handed to the SDK must be closed by the rollback, and
/// none may come back on reconnect (#2262). Before the fix `subscribe_all`
/// aborted the siblings mid-flight and tracked ids only after the SDK call, so
/// REQs leaked on most runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_activation_rollback_leaves_no_untracked_reqs() {
    const G: usize = 150;
    const ATTEMPTS: usize = 12;
    let fx = Fixture::new(LimitConfig::default(), true).await;
    let dead = dead_relay(&fx.sdk).await;
    let url = fx.limit.url();
    let mut failures = 0;
    let mut active_after_rollback = Vec::new();
    for attempt in 0..ATTEMPTS {
        let mut routes = groups(G, &url);
        // Move the failing route through the batch so the abort lands at
        // different points in the siblings' progress.
        let failing = (attempt * 37 + 11) % G;
        routes[failing].endpoints = vec![TransportEndpoint(dead.clone())];
        let result = fx
            .adapter
            .activate_account(fx.activation(std::slice::from_ref(&url), routes))
            .await;
        failures += usize::from(result.is_err());
        let stats = fx.limit.wait_quiet(QUIET, SETTLE_TIMEOUT).await;
        active_after_rollback.push(stats.active_now());
    }
    eprintln!(
        "[d] failed activations={failures}/{ATTEMPTS} live REQs after each rollback={active_after_rollback:?} {}",
        fx.limit.stats().summary()
    );
    assert_eq!(failures, ATTEMPTS, "the dead route fails each activation");
    let check = leak_check(&fx, G, "after failed activations").await;
    assert!(
        active_after_rollback.iter().all(|&active| active == 0),
        "rollback left live REQs: {active_after_rollback:?}"
    );
    assert_eq!(check.active_after_activation, G + 1);
    assert_eq!(check.active_after_reconnect, G + 1, "{check:?}");
    assert_eq!(check.stale_on_reconnect, 0, "{check:?}");
    fx.shutdown().await;
}

/// Drop `activate_account` futures mid-flight, then activate normally and check
/// that only the final activation's REQs stay live, also after a reconnect
/// (#2262). Before the fix a drop could abort subscribe tasks after the SDK
/// registered their REQ, or cut `unsubscribe_account`'s sweep short after it
/// had already untracked every id.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dropped_activation_futures_leave_no_untracked_reqs() {
    const G: usize = 150;
    const DROPS: u32 = 60;
    let fx = Fixture::new(LimitConfig::default(), true).await;
    let url = fx.limit.url();
    // Calibrate one full activation, then cancel at fractions of it.
    let started = Instant::now();
    fx.adapter
        .activate_account(fx.activation(std::slice::from_ref(&url), groups(G, &url)))
        .await
        .unwrap();
    let full = started.elapsed();
    fx.limit.wait_quiet(QUIET, SETTLE_TIMEOUT).await;
    let mut completed = 0;
    for step in 0..DROPS {
        let fraction = f64::from(step % 15 + 1) / 16.0;
        let budget = full.mul_f64(fraction).max(Duration::from_micros(100));
        let outcome = tokio::time::timeout(
            budget,
            fx.adapter
                .activate_account(fx.activation(std::slice::from_ref(&url), groups(G, &url))),
        )
        .await;
        completed += usize::from(outcome.is_ok());
    }
    eprintln!(
        "[d] full_activation_ms={} dropped={}/{DROPS}",
        full.as_millis(),
        DROPS as usize - completed
    );
    let check = leak_check(&fx, G, "after dropped activations").await;
    assert_eq!(check.active_after_activation, G + 1, "{check:?}");
    assert_eq!(check.active_after_reconnect, G + 1, "{check:?}");
    assert_eq!(check.stale_on_reconnect, 0, "{check:?}");
    fx.shutdown().await;
}

/// A group sync reuses its activation's ids, so a late or repeated subscribe
/// can name an id another live REQ already holds. nostr-sdk refuses it without
/// registering anything; the failed call must not close the live REQ (#2262).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn duplicate_subscribe_leaves_the_live_req_open() {
    let fx = Fixture::new(LimitConfig::default(), false).await;
    let url = fx.limit.url();
    fx.adapter
        .activate_account(fx.activation(std::slice::from_ref(&url), groups(1, &url)))
        .await
        .unwrap();
    let settled = fx.limit.wait_quiet(QUIET, SETTLE_TIMEOUT).await;
    let group = groups(1, &url).remove(0);
    let duplicate = NostrSubscription::Group {
        account_id: fx.account.clone(),
        group_id: group.group_id,
        transport_group_id: group.transport_group_id,
        endpoints: group.endpoints,
        since: None,
        attempt: fx
            .adapter
            .account_subscription_attempt(&fx.account)
            .await
            .expect("the account is active"),
    };
    assert!(fx.sdk.subscribe(duplicate).await.is_err());
    let after = fx.limit.wait_quiet(QUIET, SETTLE_TIMEOUT).await;
    assert_eq!(after.closes, settled.closes, "no CLOSE for the live id");
    assert_eq!(after.active_now(), 2, "inbox and group REQs stay live");
    fx.shutdown().await;
}

// ---------------------------------------------------------------------------
// (e) Permanent rejection
// ---------------------------------------------------------------------------

fn inbox_reqs(stats: &LimitStats, since: Option<Instant>) -> usize {
    // The inbox is the only REQ refused for its kind in this fixture.
    stats
        .req_log
        .iter()
        .filter(|r| since.is_none_or(|since| r.at >= since))
        .filter(|r| r.outcome == ReqOutcome::Rejected(reason::KIND_NOT_ALLOWED))
        .count()
}

/// A relay that never allows the inbox's kind refuses it every time. Measure
/// whether MDK re-sends it on its own (time, reconnects) and per activation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn permanently_refused_inbox_is_not_resent_in_a_loop() {
    for style in [RejectStyle::Closed, RejectStyle::Notice] {
        let mut allowed = limit_relay::PRODUCTION_ALLOWED_KINDS.to_vec();
        allowed.retain(|kind| *kind != 1059);
        let config = LimitConfig {
            allowed_kinds: Some(allowed.into_iter().collect()),
            reject_style: style,
            ..LimitConfig::default()
        };
        let fx = Fixture::new(config, true).await;
        let url = fx.limit.url();
        fx.adapter
            .activate_account(fx.activation(std::slice::from_ref(&url), groups(20, &url)))
            .await
            .unwrap();
        fx.limit.wait_quiet(QUIET, SETTLE_TIMEOUT).await;
        let window = Instant::now();
        tokio::time::sleep(STORM_WINDOW).await;
        let idle = inbox_reqs(&fx.limit.stats(), Some(window));

        let mut per_reconnect = Vec::new();
        for _ in 0..3 {
            let before = fx.limit.stats();
            let connections_before = before.connections.len();
            fx.limit.drop_all_connections();
            fx.limit
                .wait_for(SETTLE_TIMEOUT, |s| {
                    s.connections.len() > connections_before && s.active_now() >= 20
                })
                .await;
            let after = fx.limit.wait_quiet(QUIET, SETTLE_TIMEOUT).await;
            per_reconnect.push(inbox_reqs(&after, None) - inbox_reqs(&before, None));
        }

        let mut per_activation = Vec::new();
        for _ in 0..3 {
            let before = fx.limit.stats();
            fx.adapter
                .activate_account(fx.activation(std::slice::from_ref(&url), groups(20, &url)))
                .await
                .unwrap();
            let after = fx.limit.wait_quiet(QUIET, SETTLE_TIMEOUT).await;
            per_activation.push(inbox_reqs(&after, None) - inbox_reqs(&before, None));
        }
        let eose = fx.adapter.account_subscription_eose(&fx.account).await;
        let refusals = refusal_counts(&fx.adapter, &fx.account);
        let stats = fx.limit.stats();
        eprintln!(
            "[e] style={style:?} inbox_reqs: idle_window={idle} per_reconnect={per_reconnect:?} \
             per_activation={per_activation:?} complete={} settled={} refusals={refusals:?} {}",
            eose.complete(),
            eose.settled(),
            stats.summary()
        );
        assert_eq!(idle, 0, "no time-driven retry");
        assert!(
            per_activation.iter().all(|&n| n == 1),
            "one inbox REQ per activation"
        );
        assert_eq!(stats.active_now(), 20, "groups stay live");
        match style {
            RejectStyle::Closed => {
                assert!(
                    per_reconnect.iter().all(|&n| n == 0),
                    "a dropped REQ is not resent"
                );
                assert!(refusals.contains_key(SubscriptionRouteKind::Inbox.as_str()));
            }
            // With no CLOSED, the SDK still believes the REQ is live and
            // re-sends it once per reconnect: bounded by reconnects.
            RejectStyle::Notice => {
                assert!(per_reconnect.iter().all(|&n| n <= 1));
            }
        }
        fx.shutdown().await;
    }
}

// ---------------------------------------------------------------------------
// (f) NEG session cleanup on a long-lived connection
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum PassOutcome {
    Ok {
        relays_failed: usize,
        returned: usize,
    },
    Err,
    Dropped,
}

#[derive(Debug)]
struct Pass {
    elapsed: Duration,
    outcome: PassOutcome,
}

impl Pass {
    fn healthy(&self) -> bool {
        matches!(self.outcome, PassOutcome::Ok { relays_failed: 0, returned } if returned > 0)
    }
}

fn route_on(endpoints: &[String], account: &MemberId) -> NostrSubscription {
    NostrSubscription::Group {
        account_id: account.clone(),
        group_id: group_id(0),
        transport_group_id: route(0),
        endpoints: endpoints.iter().cloned().map(TransportEndpoint).collect(),
        since: None,
        attempt: SubscriptionAttempt::INITIAL,
    }
}

/// One reconciliation pass as the recovery owner runs it, optionally dropped
/// after `budget`.
async fn reconcile_pass(fx: &Fixture, endpoints: &[String], budget: Option<Duration>) -> Pass {
    let cursor = Cursor::default();
    let started = Instant::now();
    let pass =
        fx.sdk
            .reconcile_subscription(route_on(endpoints, &fx.account), &[], SINCE, UNTIL, &cursor);
    let result = match budget {
        Some(budget) => tokio::time::timeout(budget, pass).await.ok(),
        None => Some(pass.await),
    };
    let outcome = match result {
        Some(Ok((summary, events))) => PassOutcome::Ok {
            relays_failed: summary.relays_failed,
            returned: events.len(),
        },
        Some(Err(_)) => PassOutcome::Err,
        None => PassOutcome::Dropped,
    };
    Pass {
        elapsed: started.elapsed(),
        outcome,
    }
}

/// A fixture whose account connection to the limit relay is already open.
async fn connected_fixture(config: LimitConfig, events: usize) -> (Fixture, String) {
    let fx = Fixture::new(config, true).await;
    store_timed_events(&fx.database, events).await;
    fx.sdk.client().connect().await;
    assert!(
        fx.limit
            .wait_for(SETTLE_TIMEOUT, |s| s.open_connections() == 1)
            .await
    );
    let url = fx.limit.url();
    (fx, url)
}

/// Live NEG sessions left on the relay once a pass's cleanup frames land.
async fn neg_sessions_after_pass(fx: &Fixture) -> usize {
    fx.limit
        .wait_for(Duration::from_secs(1), |s| s.neg_active_now() == 0)
        .await;
    fx.limit.stats().neg_active_now()
}

/// Hundreds of completed passes on one connection: the NEG session count
/// returns to zero after every pass and never approaches the 200 cap.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn neg_sessions_return_to_zero_after_each_completed_pass() {
    const PASSES: usize = 250;
    let (fx, url) = connected_fixture(LimitConfig::default(), 10).await;
    let mut lingering = Vec::new();
    let mut unhealthy = 0;
    let started = Instant::now();
    for _ in 0..PASSES {
        let pass = reconcile_pass(&fx, std::slice::from_ref(&url), None).await;
        unhealthy += usize::from(!pass.healthy());
        lingering.push(neg_sessions_after_pass(&fx).await);
    }
    let stats = fx.limit.stats();
    eprintln!(
        "[f] passes={PASSES} elapsed_ms={} unhealthy={unhealthy} max_lingering={} peak_neg={} {}",
        started.elapsed().as_millis(),
        lingering.iter().max().unwrap(),
        stats
            .connections
            .iter()
            .map(|c| c.neg_peak)
            .max()
            .unwrap_or(0),
        stats.summary()
    );
    assert_eq!(stats.connections.len(), 1, "one long-lived connection");
    assert_eq!(unhealthy, 0);
    assert!(lingering.iter().all(|&n| n == 0), "{lingering:?}");
    assert_eq!(stats.neg_cap_notices, 0);
    assert_eq!(
        stats.neg_opens, stats.neg_closes,
        "every NEG-OPEN is NEG-CLOSEd"
    );
    fx.shutdown().await;
}

/// With 199 of 200 NEG slots pre-filled, any leaked session makes the next
/// healthy pass hit the cap. Exercise every failure path, then a healthy pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn neg_sessions_are_freed_on_every_failure_path() {
    let config = LimitConfig {
        neg_prefilled_sessions: 199,
        ..LimitConfig::default()
    };
    let (fx, url) = connected_fixture(config, 10).await;
    let endpoints = std::slice::from_ref(&url);
    let cases: [(&str, NegFault, Option<Duration>, usize); 6] = [
        ("completion", NegFault::None, None, 3),
        ("neg_err", NegFault::ErrOnOpen, None, 3),
        ("first_reply_timeout", NegFault::SilentOpen, None, 3),
        ("route_deadline", NegFault::FingerprintThenStall, None, 2),
        (
            "dropped_awaiting_reply",
            NegFault::SilentOpen,
            Some(Duration::from_millis(100)),
            3,
        ),
        (
            "dropped_mid_pass",
            NegFault::None,
            Some(Duration::from_millis(2)),
            6,
        ),
    ];
    let mut report = Vec::new();
    for (label, fault, budget, passes) in cases {
        fx.limit.set_neg_fault(fault);
        let mut latencies = Vec::new();
        let mut outcomes = Vec::new();
        for _ in 0..passes {
            let pass = reconcile_pass(&fx, endpoints, budget).await;
            latencies.push(pass.elapsed.as_millis());
            outcomes.push(format!("{:?}", pass.outcome));
        }
        let lingering = neg_sessions_after_pass(&fx).await;
        fx.limit.set_neg_fault(NegFault::None);
        let notices_before = fx.limit.stats().neg_cap_notices;
        let probe = reconcile_pass(&fx, endpoints, None).await;
        let probe_lingering = neg_sessions_after_pass(&fx).await;
        let notices = fx.limit.stats().neg_cap_notices - notices_before;
        eprintln!(
            "[f] {label}: latencies_ms={latencies:?} outcomes={outcomes:?} lingering={lingering} \
             probe_healthy={} probe_cap_notices={notices}",
            probe.healthy()
        );
        report.push((label, lingering, probe.healthy(), notices, probe_lingering));
    }
    eprintln!("[f] prefilled-199 {}", fx.limit.stats().summary());
    for (label, lingering, healthy, notices, probe_lingering) in report {
        assert_eq!(lingering, 0, "{label}: NEG session leaked");
        assert!(
            healthy && notices == 0,
            "{label}: next pass hit the NEG cap"
        );
        assert_eq!(probe_lingering, 0, "{label}");
    }
    assert_eq!(fx.limit.stats().connections.len(), 1);
    fx.shutdown().await;
}

// ---------------------------------------------------------------------------
// (g) Fast and slow reconciliation failures
// ---------------------------------------------------------------------------

async fn timed_failures(fx: &Fixture, endpoints: &[String], passes: usize) -> Vec<(u128, String)> {
    let mut out = Vec::new();
    for _ in 0..passes {
        let pass = reconcile_pass(fx, endpoints, None).await;
        out.push((pass.elapsed.as_millis(), format!("{:?}", pass.outcome)));
    }
    out
}

fn all_failed(results: &[(u128, String)], endpoints: usize) -> bool {
    let needle = format!("relays_failed: {endpoints},");
    results.iter().all(|(_, outcome)| outcome.contains(&needle))
}

/// The relay answers NEG-OPEN with strfry's NEG-cap NOTICE (no session id).
/// nostr-sdk's first-reply check ignores that NOTICE, so the pass waits out
/// the 500 ms first-reply timeout and the endpoint counts as failed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn neg_cap_notice_fails_after_the_first_reply_timeout() {
    let config = LimitConfig {
        max_neg_sessions: 0,
        ..LimitConfig::default()
    };
    let (fx, url) = connected_fixture(config.clone(), 10).await;
    let second = LimitRelay::start(fx.upstream_url.clone(), config).await;
    fx.sdk
        .client()
        .add_relay(second.url())
        .opts(fast_retry_options())
        .await
        .unwrap();
    fx.sdk.client().connect().await;
    second
        .wait_for(SETTLE_TIMEOUT, |s| s.open_connections() == 1)
        .await;
    let endpoints = [url, second.url()];
    let results = timed_failures(&fx, &endpoints, 3).await;
    let stats = fx.limit.stats();
    eprintln!(
        "[g] NEG cap NOTICE, 2 endpoints: (ms, outcome)={results:?} {}",
        stats.summary()
    );
    assert!(all_failed(&results, 2), "{results:?}");
    assert!(
        results.iter().all(|(ms, _)| (450..1_500).contains(ms)),
        "{results:?}"
    );
    assert!(stats.neg_cap_notices >= 3);
    assert_eq!(
        stats.connections.len(),
        1,
        "a NOTICE does not drop the connection"
    );
    fx.shutdown().await;
}

/// Failure paths with no relay round trip: an endpoint the account's SDK pool
/// does not hold (`client.relay()` is `None`), and a disconnected relay whose
/// connection success rate is below nostr-sdk's 90 % (`ensure_operational`).
/// Contrast: a relay still in the pool that just dropped (good history) queues
/// the NEG-OPEN and waits out the first-reply timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fast_and_slow_reconciliation_failure_paths() {
    let (fx, _url) = connected_fixture(LimitConfig::default(), 10).await;

    // Not in the pool: never added to this SDK client.
    let absent = |port: u16| format!("ws://127.0.0.1:{port}");
    let not_in_pool = [absent(9), absent(10)];
    let not_in_pool_results = timed_failures(&fx, &not_in_pool, 3).await;

    // In the pool, disconnected, low success rate.
    let dead = [dead_relay(&fx.sdk).await, dead_relay(&fx.sdk).await];
    let refused_results = timed_failures(&fx, &dead, 3).await;

    // In the pool with a good history, dropped a moment ago, slow to return.
    let flaky = LimitRelay::start(fx.upstream_url.clone(), LimitConfig::default()).await;
    fx.sdk
        .client()
        .add_relay(flaky.url())
        .opts(
            RelayOptions::new()
                .retry_interval(Duration::from_secs(30))
                .adjust_retry_interval(false),
        )
        .await
        .unwrap();
    fx.sdk.client().connect().await;
    flaky
        .wait_for(SETTLE_TIMEOUT, |s| s.open_connections() == 1)
        .await;
    flaky.drop_all_connections();
    flaky
        .wait_for(SETTLE_TIMEOUT, |s| s.open_connections() == 0)
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let dropped_results = timed_failures(&fx, &[flaky.url()], 2).await;

    eprintln!(
        "[g] not_in_pool (ms, outcome)={not_in_pool_results:?}\n[g] low_success_rate={refused_results:?}\n\
         [g] dropped_good_history={dropped_results:?}"
    );
    assert!(
        all_failed(&not_in_pool_results, 2),
        "{not_in_pool_results:?}"
    );
    assert!(not_in_pool_results.iter().all(|(ms, _)| *ms < 100));
    assert!(all_failed(&refused_results, 2), "{refused_results:?}");
    assert!(refused_results.iter().all(|(ms, _)| *ms < 100));
    assert!(all_failed(&dropped_results, 1), "{dropped_results:?}");
    fx.shutdown().await;
}

/// One pass's failure class per endpoint, in endpoint order.
async fn failure_classes(fx: &Fixture, endpoints: &[String]) -> Vec<NostrReconciliationFailure> {
    let (summary, _) = fx
        .sdk
        .reconcile_subscription(
            route_on(endpoints, &fx.account),
            &[],
            SINCE,
            UNTIL,
            &Cursor::default(),
        )
        .await
        .unwrap();
    assert_eq!(
        summary
            .endpoint_failures
            .iter()
            .map(|failure| failure.endpoint.clone())
            .collect::<Vec<_>>(),
        summary.failed_endpoints,
        "every failed endpoint has exactly one class"
    );
    let mut sorted = endpoints.to_vec();
    sorted.sort();
    sorted
        .iter()
        .map(|endpoint| {
            summary
                .endpoint_failures
                .iter()
                .find(|failure| failure.endpoint.as_str().trim_end_matches('/') == endpoint)
                .map(|failure| failure.failure)
                .unwrap_or_else(|| panic!("endpoint did not fail: {:?}", summary.endpoint_failures))
        })
        .collect()
}

/// Each way a relay can fail a comparison keeps its own class (#2265):
/// NEG-ERR with its reason's prefix, the negentropy-cap NOTICE, no first
/// reply, the pass deadline, an endpoint outside the pool, and a relay the SDK
/// will not use.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconciliation_names_why_each_relay_failed() {
    use NostrReconciliationFailure as Failure;
    let (fx, url) = connected_fixture(LimitConfig::default(), 10).await;
    let one = std::slice::from_ref(&url);
    let mut observed = Vec::new();
    for (fault, expected) in [
        (
            NegFault::ErrOnOpen,
            Failure::NegErr(Some(
                cgka_traits::TransportEndpointRejectionCategory::Blocked,
            )),
        ),
        (NegFault::SilentOpen, Failure::FirstReplyTimeout),
        (NegFault::FingerprintThenStall, Failure::RouteTimeout),
    ] {
        fx.limit.set_neg_fault(fault);
        observed.push((
            format!("{fault:?}"),
            failure_classes(&fx, one).await,
            expected,
        ));
    }
    fx.limit.set_neg_fault(NegFault::None);

    let capped = LimitRelay::start(
        fx.upstream_url.clone(),
        LimitConfig {
            max_neg_sessions: 0,
            ..LimitConfig::default()
        },
    )
    .await;
    fx.sdk
        .client()
        .add_relay(capped.url())
        .opts(fast_retry_options())
        .await
        .unwrap();
    fx.sdk.client().connect().await;
    capped
        .wait_for(SETTLE_TIMEOUT, |s| s.open_connections() == 1)
        .await;
    observed.push((
        "neg_cap".into(),
        failure_classes(&fx, &[capped.url()]).await,
        Failure::NegCapNotice,
    ));
    observed.push((
        "not_in_pool".into(),
        failure_classes(&fx, &["ws://127.0.0.1:9".to_owned()]).await,
        Failure::NotInPool,
    ));
    let dead = dead_relay(&fx.sdk).await;
    observed.push((
        "not_operational".into(),
        failure_classes(&fx, &[dead]).await,
        Failure::NotOperational,
    ));
    eprintln!("[g] failure classes: {observed:?}");
    for (label, classes, expected) in observed {
        assert_eq!(classes, vec![expected], "{label}");
    }
    assert!(capped.stats().neg_cap_notices >= 1);
    fx.shutdown().await;
}

// ---------------------------------------------------------------------------
// (h) The 500-event REQ clamp (#2263)
// ---------------------------------------------------------------------------

/// Distinct messages delivered until the adapter goes quiet.
async fn distinct_deliveries(adapter: &NostrTransportAdapter, wait: Duration) -> usize {
    const IDLE: Duration = Duration::from_millis(1_500);
    let deadline = tokio::time::Instant::now() + wait;
    let mut seen = HashSet::new();
    loop {
        let next = deadline.min(tokio::time::Instant::now() + IDLE);
        match tokio::time::timeout_at(next, adapter.receive()).await {
            Ok(Ok(Some(delivery))) => {
                seen.insert(delivery.message.id);
            }
            _ => return seen.len(),
        }
    }
}

/// Store kind-445 events for group route 0 at the given `created_at` seconds.
async fn store_events_at(database: &MemoryDatabase, timestamps: impl IntoIterator<Item = u64>) {
    let keys = Keys::generate();
    for (index, created_at) in timestamps.into_iter().enumerate() {
        let event = EventBuilder::new(Kind::MlsGroupMessage, format!("history-{index}"))
            .tags([Tag::custom("h", [hex::encode(route(0))])])
            .custom_created_at(nostr_sdk::prelude::Timestamp::from_secs(created_at))
            .finalize(&keys)
            .unwrap();
        database
            .save_event(&serde_json::from_str(event.as_json().as_str()).unwrap())
            .await
            .unwrap();
    }
}

/// Replay one group route over `stored` events and report what arrived.
async fn replay_one_group(stored: usize, clamp: Option<u64>) -> (usize, bool, LimitStats) {
    replay_one_group_at((0..stored as u64).map(|index| 1_700_000_000 + index), clamp).await
}

/// Replay one group route over events stored at `timestamps`.
async fn replay_one_group_at(
    timestamps: impl IntoIterator<Item = u64>,
    clamp: Option<u64>,
) -> (usize, bool, LimitStats) {
    let fx = Fixture::new(
        LimitConfig {
            req_limit_clamp: clamp,
            ..LimitConfig::default()
        },
        false,
    )
    .await;
    let timestamps = timestamps.into_iter().collect::<Vec<_>>();
    let stored = timestamps.len();
    store_events_at(&fx.database, timestamps).await;
    let url = fx.limit.url();
    fx.adapter
        .activate_account(fx.activation(std::slice::from_ref(&url), groups(1, &url)))
        .await
        .unwrap();
    let delivered = distinct_deliveries(&fx.adapter, Duration::from_secs(15)).await;
    let complete = fx
        .adapter
        .account_subscription_eose(&fx.account)
        .await
        .complete();
    let stats = fx.limit.stats();
    eprintln!(
        "[h] clamp={clamp:?} stored={stored} delivered={delivered} complete={complete} {}",
        stats.summary()
    );
    fx.shutdown().await;
    (delivered, complete, stats)
}

/// A live group REQ carries no `limit`, so strfry serves at most 500 stored
/// events (newest first) and then EOSE. The adapter must page the rest of the
/// window backwards before that relay's EOSE counts as coverage, instead of
/// reporting complete with the older history silently missing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stored_replay_beyond_500_is_paged_before_counting_complete() {
    const STORED: usize = 1_200;
    for clamp in [None, Some(limit_relay::REQ_LIMIT_CLAMP)] {
        let (delivered, complete, stats) = replay_one_group(STORED, clamp).await;
        assert_eq!(
            delivered, STORED,
            "clamp={clamp:?}: every stored event arrives"
        );
        assert!(complete, "clamp={clamp:?}: coverage completes once paged");
        if clamp.is_some() {
            assert!(stats.clamped_filters >= 1);
            // The live inbox and group REQs, plus at least two backward pages.
            assert!(stats.total_reqs >= 4, "paged: {}", stats.summary());
        }
    }
}

/// More than a page of events sharing one second saturates the inclusive
/// `until` bound: the backward page cannot move past that second, so the rest
/// of it and everything older stay unfetched. Coverage must stay incomplete
/// rather than count that relay's EOSE.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn saturated_boundary_second_keeps_replay_incomplete() {
    const BOUNDARY: u64 = 1_700_100_000;
    let older = (0..100).map(|index| BOUNDARY - 1_000 + index);
    let boundary = std::iter::repeat_n(BOUNDARY, 600);
    let (delivered, complete, _) =
        replay_one_group_at(older.chain(boundary), Some(limit_relay::REQ_LIMIT_CLAMP)).await;
    assert!(delivered < 700, "the clamp hides part of the window");
    assert!(!complete, "a saturated boundary must not count as coverage");
}

/// A stored event that does not map to a transport message (here a kind-445
/// with an extra tag) is skipped by the live replay. A backward page holding
/// one must skip it too and keep paging, or the relay would stay in paging and
/// the cursor would never promote.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unmappable_event_on_a_backward_page_does_not_wedge_paging() {
    const VALID: usize = 600;
    let fx = Fixture::new(
        LimitConfig {
            req_limit_clamp: Some(limit_relay::REQ_LIMIT_CLAMP),
            ..LimitConfig::default()
        },
        false,
    )
    .await;
    store_events_at(
        &fx.database,
        (0..VALID as u64).map(|index| 1_700_000_000 + index),
    )
    .await;
    // Older than the live replay's newest 500, so it lands on the first page.
    let keys = Keys::generate();
    let unmappable = EventBuilder::new(Kind::MlsGroupMessage, "extra-tagged")
        .tags([
            Tag::custom("h", [hex::encode(route(0))]),
            Tag::custom("x", ["unexpected"]),
        ])
        .custom_created_at(nostr_sdk::prelude::Timestamp::from_secs(1_700_000_010))
        .finalize(&keys)
        .unwrap();
    fx.database
        .save_event(&serde_json::from_str(unmappable.as_json().as_str()).unwrap())
        .await
        .unwrap();
    let url = fx.limit.url();
    fx.adapter
        .activate_account(fx.activation(std::slice::from_ref(&url), groups(1, &url)))
        .await
        .unwrap();
    let delivered = distinct_deliveries(&fx.adapter, Duration::from_secs(15)).await;
    let complete = fx
        .adapter
        .account_subscription_eose(&fx.account)
        .await
        .complete();
    fx.shutdown().await;
    assert_eq!(delivered, VALID, "every valid event arrives");
    assert!(complete, "the unmappable event does not wedge paging");
}

/// A replay that stays under a full page is complete as delivered and opens
/// no backward page.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stored_replay_under_a_page_is_not_paged() {
    const STORED: usize = 499;
    let (delivered, complete, stats) =
        replay_one_group(STORED, Some(limit_relay::REQ_LIMIT_CLAMP)).await;
    assert_eq!(delivered, STORED);
    assert!(complete);
    assert_eq!(
        stats.total_reqs,
        2,
        "only the live inbox and group REQs: {}",
        stats.summary()
    );
}

/// With a simulated ~20 ms round trip, a relay that refuses promptly fails a
/// pass in one or two round trips, not a timeout: NEG-ERR on NEG-OPEN costs
/// one, and a full socket (the comparison succeeds, the id-fetch REQ is the
/// 201st and is CLOSED) costs about two.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prompt_relay_refusals_fail_in_round_trips() {
    const RTT: Duration = Duration::from_millis(20);
    let (fx, url) = connected_fixture(LimitConfig::default(), 10).await;
    fx.limit.set_client_delay(RTT);
    let endpoints = std::slice::from_ref(&url);
    let healthy = timed_failures(&fx, endpoints, 2).await;
    fx.limit.set_neg_fault(NegFault::ErrOnOpen);
    let neg_err = timed_failures(&fx, endpoints, 3).await;
    fx.limit.set_neg_fault(NegFault::None);
    fx.limit.set_client_delay(Duration::ZERO);
    fx.adapter
        .activate_account(fx.activation(endpoints, groups(199, &url)))
        .await
        .unwrap();
    fx.limit.wait_quiet(QUIET, SETTLE_TIMEOUT).await;
    fx.limit.set_client_delay(RTT);
    let full_socket = timed_failures(&fx, endpoints, 3).await;
    eprintln!(
        "[g] rtt_ms={} healthy={healthy:?}\n[g] neg_err={neg_err:?}\n[g] full_socket={full_socket:?}\n[g] {}",
        RTT.as_millis(),
        fx.limit.stats().summary()
    );
    assert!(all_failed(&neg_err, 1), "{neg_err:?}");
    assert!(
        neg_err.iter().all(|(ms, _)| (15..150).contains(ms)),
        "{neg_err:?}"
    );
    assert!(all_failed(&full_socket, 1), "{full_socket:?}");
    assert!(
        full_socket.iter().all(|(ms, _)| (30..250).contains(ms)),
        "{full_socket:?}"
    );
    fx.shutdown().await;
}
