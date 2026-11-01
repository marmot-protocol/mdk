//! Recovery-runner proofs (mdk#2660 phase 4, PR 5f) under production policy,
//! through public runtime APIs and the relay's wire only. Bob runs in this
//! process with his recovery runner owning history debt; the relay and every
//! other participant run in their own processes. Both relay endpoints share
//! one store and publish the production NIP-11 document.
//!
//! Until the gate flips (5g), the earlier recovery owner still runs beside
//! the runner, and in these runs it does the startup recovery itself. So the
//! wire bounds count both of bob's owners, and the runner's own numbers (read
//! from its debug trace) are recorded; the runner is held only to what it
//! does beside the earlier owner, such as re-proving after a reconnect. 5g
//! adds the runner-alone bounds, the fence control and the upgrade journey.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cgka_conformance_simulator::app_runtime::{HistoryRequestV1, RelayDeliveryPath};
use cgka_conformance_simulator::{
    AppRuntimeHarness, AppRuntimeProbe, ConvergenceSubject, SubjectCreateGroup,
};
use cgka_traits::GroupId;
use serde_json::{Value, json};

use super::recovery_scorecard::{percentiles, status_summary};
use super::{SETTLEMENT, TestResult, journey_artifacts, save};

/// They publish the owed backlog in parallel, so bob is the only account
/// that owes it.
const SENDERS: [&str; 3] = ["s1", "s2", "s3"];
/// Tens of thousands of events in one group, owed on both endpoints.
const OWED_MESSAGES: usize = 20_000;
/// A few thousand, as in 0.14.0's looping accounts: more than one attempt
/// fetches.
const LOOP_MESSAGES: usize = 3_000;
const LOOP_WINDOW: Duration = Duration::from_secs(16 * 60);
/// Past the restart's 120-second rebuild lookback (ledger A7) and how far a
/// stopped cursor may trail, so the quiet group has no event in its live
/// range. (Its live count is its REQ's, which it may share with a busy group.)
const QUIET_AGE: Duration = Duration::from_secs(200);
const RECOVERY_DEADLINE: Duration = Duration::from_secs(30 * 60);
const RESWEEP_DEADLINE: Duration = Duration::from_secs(5 * 60);
const OUTAGE_MS: u64 = 10_000;
const WATCHDOG: Duration = Duration::from_secs(90 * 60);
/// Requests on one endpoint at most this far apart form one burst.
const BURST_GAP_MS: u64 = 2_000;
/// Minutes of the loop's eight-minute second half in which the stalled relay
/// may be asked anything: every other one at most. 0.14.0 asked in each.
const LOOP_SECOND_HALF_MINUTES: usize = 4;
/// Bursts of history requests per endpoint while the owed group drains: the
/// wire's view of the attempts, both owners together.
const OWED_BURSTS: usize = 4;
/// How long the last live sends get to arrive after sending stops: a fence
/// holds a group's live frames for at most one 30-second replay deadline.
const LIVE_HELD_AT_MOST: Duration = Duration::from_secs(60);

fn clients() -> Vec<String> {
    let named = ["alice", "bob"].into_iter().chain(SENDERS);
    named.map(String::from).collect()
}

fn note(started: Instant, what: &str) {
    eprintln!(
        "runner proof +{:.0}s {what}",
        started.elapsed().as_secs_f64()
    );
}

async fn wait_for(
    what: &str,
    limit: Duration,
    mut done: impl AsyncFnMut() -> TestResult<bool>,
) -> TestResult {
    let deadline = Instant::now() + limit;
    while !done().await? {
        if Instant::now() >= deadline {
            return Err(format!("timed out waiting for {what}").into());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    Ok(())
}

async fn create(
    subject: &mut AppRuntimeHarness,
    label: &str,
    members: &[String],
) -> TestResult<GroupId> {
    let action = format!("create-{label}");
    subject.select_scenario_group(label, true)?;
    let create = SubjectCreateGroup {
        action_id: &action,
        creator: &members[0],
        name: label,
        invitees: &members[1..],
        required_features: &[],
        initial_admins: &members[..1],
        pending: &action,
    };
    subject.create_group(create).await?;
    subject.tick(members).await?;
    subject
        .await_observable_settlement(members, SETTLEMENT)
        .await?;
    Ok(subject.scenario_group_id(label)?)
}

/// Wait until no member has own-leaf maintenance left to publish, so no
/// post-join commit lands inside a measured phase.
async fn settle_maintenance(
    subject: &AppRuntimeHarness,
    members: &[String],
    groups: &[GroupId],
) -> TestResult {
    let probes = members
        .iter()
        .map(|member| subject.probe(member))
        .collect::<Result<Vec<_>, _>>()?;
    let settled = async || {
        for (probe, group) in probes
            .iter()
            .flat_map(|p| groups.iter().map(move |g| (p, g)))
        {
            // A member outside this group answers with an error; skip it.
            if probe
                .open_maintenance(group)
                .await
                .is_ok_and(|open| !open.is_empty())
            {
                return Ok(false);
            }
        }
        Ok(true)
    };
    wait_for("post-join maintenance", Duration::from_secs(600), settled).await
}

/// How one send completed, for the report.
#[derive(Clone)]
struct Sent {
    payload: String,
    /// The relay publications the send reported; none when the app queued
    /// it for a later drain.
    published: usize,
    /// The app message id the send named, queued or not.
    app_id: Option<String>,
    /// A `transport_closed` refusal answered by finding the message in the
    /// sender's own timeline.
    shown_after_closed: bool,
}

impl Sent {
    fn how(&self) -> &'static str {
        match (self.published, self.shown_after_closed) {
            (_, true) => "shown_after_closed",
            (0, false) => "queued",
            (_, false) => "published",
        }
    }
}

/// Send once, repeating a `transport_closed` refusal only while the sender's
/// own timeline lacks the message.
async fn send(probe: &AppRuntimeProbe, group: &GroupId, payload: &str) -> Result<Sent, String> {
    let sent = |published, app_id, shown_after_closed| Sent {
        payload: payload.to_owned(),
        published,
        app_id,
        shown_after_closed,
    };
    for _ in 0..20 {
        match probe.send_message_receipt(group, payload).await {
            Ok((published, ids)) => return Ok(sent(published, ids.into_iter().next(), false)),
            Err(error) if error.message.ends_with("transport_closed") => {
                tokio::time::sleep(Duration::from_secs(2)).await;
                let recent = probe.chat_view(group, Some(1_024)).await;
                let (_, recent) = recent.map_err(|error| error.to_string())?;
                if recent.iter().any(|text| text == payload) {
                    return Ok(sent(0, None, true));
                }
            }
            Err(error) => return Err(format!("sending {payload}: {error}")),
        }
    }
    Err(format!(
        "sending {payload}: transport_closed for 40 seconds"
    ))
}

/// Publish `{prefix}{index:05}` for every index below `count`, spread over
/// the senders sending in parallel.
async fn publish(
    subject: &AppRuntimeHarness,
    group: &GroupId,
    prefix: &str,
    count: usize,
) -> TestResult<Vec<Sent>> {
    let mut lanes = tokio::task::JoinSet::new();
    for (lane, sender) in SENDERS.iter().enumerate() {
        let (probe, group) = (subject.probe(sender)?, group.clone());
        let payloads = (lane..count)
            .step_by(SENDERS.len())
            .map(|index| format!("{prefix}{index:05}"))
            .collect::<Vec<_>>();
        lanes.spawn(async move {
            let mut sent = Vec::with_capacity(payloads.len());
            for payload in &payloads {
                sent.push(send(&probe, &group, payload).await?);
            }
            Ok::<_, String>(sent)
        });
    }
    let mut sent = Vec::with_capacity(count);
    while let Some(lane) = lanes.join_next().await {
        sent.extend(lane??);
    }
    Ok(sent)
}

fn payloads(sent: &[Sent]) -> Vec<String> {
    sent.iter().map(|sent| sent.payload.clone()).collect()
}

/// Each endpoint's proxy clock now.
async fn relay_clocks(subject: &AppRuntimeHarness) -> TestResult<Vec<u64>> {
    let traffic = subject.relay_traffic(&[u64::MAX, u64::MAX], false).await?;
    Ok(traffic.iter().map(|relay| relay.now_ms).collect())
}

/// Every history request over bob's own connections that each endpoint
/// logged at or after its `from` clock. The other participants' requests
/// share the endpoints, and after a relay cut they reconnect too.
async fn history_since(
    subject: &AppRuntimeHarness,
    from: &[u64],
) -> TestResult<Vec<Vec<HistoryRequestV1>>> {
    let traffic = subject.client_history_requests("bob", &[0, 0]).await?;
    Ok(traffic
        .into_iter()
        .zip(from)
        .map(|(requests, from)| {
            let requests = requests.into_iter();
            requests.filter(|request| request.at_ms >= *from).collect()
        })
        .collect())
}

/// Requests within [`BURST_GAP_MS`] of the one before form one burst: the
/// wire's view of one attempt. Returns each burst's first clock.
fn bursts<'a>(requests: impl IntoIterator<Item = &'a HistoryRequestV1>) -> Vec<u64> {
    let mut starts = Vec::new();
    let mut last = None;
    for request in requests {
        if last.is_none_or(|last: u64| request.at_ms > last + BURST_GAP_MS) {
            starts.push(request.at_ms);
        }
        last = Some(request.at_ms);
    }
    starts
}

/// Minutes of `[from, to)` on the proxy clock in which `requests` asked
/// anything. Bursts chain requests that never pause, so a loop that never
/// stops is one burst; it fills every minute.
fn minutes_asked<'a>(
    requests: impl IntoIterator<Item = &'a HistoryRequestV1>,
    from: u64,
    to: u64,
) -> usize {
    let asked = requests
        .into_iter()
        .filter(|request| (from..to).contains(&request.at_ms));
    asked
        .map(|request| (request.at_ms - from) / 60_000)
        .collect::<BTreeSet<_>>()
        .len()
}

/// Whether every live message was sent and arrived, and at least half as
/// many were sent as the send interval allowed.
fn live_complete(visibility: &Value) -> bool {
    let (sends, expected) = (
        visibility["sends"].as_u64(),
        visibility["expected_sends"].as_u64(),
    );
    let enough = sends
        .zip(expected)
        .is_some_and(|(sends, expected)| sends > 0 && sends * 2 >= expected);
    enough && visibility["not_visible"] == 0 && visibility["failed_sends"] == 0
}

/// One endpoint's history requests: counts by verb and by route label, and
/// sweep windows (`REQ` filters by time, not ids) asked more than once.
pub(super) fn history_summary(
    requests: &[HistoryRequestV1],
    labels: &BTreeMap<String, String>,
) -> Value {
    let mut by_verb = BTreeMap::<&str, u64>::new();
    let mut by_route = BTreeMap::<&str, u64>::new();
    for request in requests {
        *by_verb.entry(&request.verb).or_default() += 1;
        let route = request.route.as_deref().unwrap_or("none");
        let label = labels.get(route).map_or("other", String::as_str);
        *by_route.entry(label).or_default() += 1;
    }
    let windows = window_counts(requests);
    let repeated = windows.values().filter(|count| **count > 1);
    let repeats = repeated.clone().map(|count| count - 1).sum::<u64>();
    json!({
        "requests": requests.len(),
        "withheld": requests.iter().filter(|request| request.withheld).count(),
        "by_verb": by_verb,
        "by_route": by_route,
        "bursts": bursts(requests).len(),
        "windows_asked_more_than_once": repeated.count(),
        "repeated_window_requests": repeats,
    })
}

/// How often one endpoint was asked each history window: a `REQ` without
/// ids, or a `NEG-OPEN`, by route (not label, which several routes may
/// share), bounds and limit.
fn window_counts(requests: &[HistoryRequestV1]) -> BTreeMap<impl Ord + '_, u64> {
    let mut windows = BTreeMap::<_, u64>::new();
    for request in requests.iter().filter(|request| request.ids == 0) {
        let route = request.route.as_deref();
        let window = (route, request.since, request.until, request.limit);
        *windows.entry((request.verb.as_str(), window)).or_default() += 1;
    }
    windows
}

/// Requests on one endpoint that repeat a history window asked before.
fn repeated_windows(requests: &[HistoryRequestV1]) -> u64 {
    window_counts(requests)
        .values()
        .map(|count| count - 1)
        .sum()
}

/// The recovery runner's own attempts, from the `quantum` and `recheck`
/// debug events of bob's in-process runtime. They carry aggregate fields
/// only (outcome, end, requests, newly covered seconds), never which unit.
mod runner_trace {
    use std::sync::{Mutex, OnceLock};
    use std::time::Instant;

    use serde_json::{Map, Value, json};
    use tracing::field::{Field, Visit};
    use tracing_subscriber::filter::Targets;
    use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
    use tracing_subscriber::util::SubscriberInitExt;

    const TARGET: &str = "marmot_app::recovery_runner";
    static EVENTS: Mutex<Vec<Value>> = Mutex::new(Vec::new());
    static STARTED: OnceLock<Instant> = OnceLock::new();

    struct Capture;

    struct Fields(Map<String, Value>);

    impl Visit for Fields {
        fn record_u64(&mut self, field: &Field, value: u64) {
            self.0.insert(field.name().into(), json!(value));
        }
        fn record_i64(&mut self, field: &Field, value: i64) {
            self.0.insert(field.name().into(), json!(value));
        }
        fn record_bool(&mut self, field: &Field, value: bool) {
            self.0.insert(field.name().into(), json!(value));
        }
        fn record_str(&mut self, field: &Field, value: &str) {
            self.0.insert(field.name().into(), json!(value));
        }
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.0
                .insert(field.name().into(), json!(format!("{value:?}")));
        }
    }

    impl<S: tracing::Subscriber> Layer<S> for Capture {
        fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
            let mut fields = Fields(Map::new());
            event.record(&mut fields);
            let method = fields.0.get("method").and_then(Value::as_str);
            if matches!(method, Some("quantum" | "recheck")) {
                fields.0.insert("at_ms".into(), json!(now_ms()));
                EVENTS
                    .lock()
                    .expect("runner trace lock")
                    .push(Value::Object(fields.0));
            }
        }
    }

    /// Start capturing, dropping what an earlier test in this binary left.
    pub(super) fn start() -> Result<(), String> {
        static INSTALLED: OnceLock<bool> = OnceLock::new();
        let installed = *INSTALLED.get_or_init(|| {
            STARTED.get_or_init(Instant::now);
            let only = Targets::new().with_target(TARGET, tracing::Level::DEBUG);
            let capture = Capture.with_filter(only);
            tracing_subscriber::registry()
                .with(capture)
                .try_init()
                .is_ok()
        });
        EVENTS.lock().expect("runner trace lock").clear();
        if installed {
            Ok(())
        } else {
            Err("another tracing subscriber is installed".into())
        }
    }

    /// The trace clock.
    pub(super) fn now_ms() -> u64 {
        let started = STARTED.get_or_init(Instant::now);
        u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Every event captured at or after `from` on the trace clock.
    pub(super) fn since(from: u64) -> Vec<Value> {
        let events = EVENTS.lock().expect("runner trace lock");
        let after = events
            .iter()
            .filter(|event| event["at_ms"].as_u64() >= Some(from));
        after.cloned().collect()
    }
}

/// The runner's attempts: counts by method and outcome, and their summed
/// requests and progress.
fn runner_summary(events: &[Value]) -> Value {
    let mut outcomes = BTreeMap::<String, u64>::new();
    let mut ends = BTreeMap::<String, u64>::new();
    let sum = |field: &str| {
        let values = events.iter().filter_map(|event| event[field].as_u64());
        values.sum::<u64>()
    };
    for event in events {
        let key = |field: &str| {
            format!(
                "{}:{}",
                event["method"].as_str().unwrap_or("?"),
                event[field].as_str().unwrap_or("?")
            )
        };
        *outcomes.entry(key("outcome")).or_default() += 1;
        *ends.entry(key("end")).or_default() += 1;
    }
    json!({
        "attempts": events.len(),
        "by_outcome": outcomes,
        "by_end": ends,
        "compared": events.iter().filter(|event| event["compared"] == true).count(),
        "requests": sum("requests"),
        "newly_covered_seconds": sum("newly_covered_seconds"),
        "proved_events": sum("proved_events"),
    })
}

/// Runner attempts that asked a relay and ended without progress. A re-check
/// owes nothing, so one that finished is an answer, whatever it found (the
/// runner reports it as `no_progress`).
fn wasted(events: &[Value]) -> usize {
    let asked = |event: &&Value| event["requests"].as_u64() > Some(0);
    let progress = |event: &&Value| {
        let answered = event["method"] == "recheck" && event["end"] == "finished";
        answered || matches!(event["outcome"].as_str(), Some("advanced" | "nothing_owed"))
    };
    events
        .iter()
        .filter(asked)
        .filter(|event| !progress(event))
        .count()
}

/// Seconds of debt the runner's advancing attempts newly covered.
fn advanced_seconds(events: &[Value]) -> u64 {
    let advanced = events.iter().filter(|event| event["outcome"] == "advanced");
    advanced
        .filter_map(|event| event["newly_covered_seconds"].as_u64())
        .sum()
}

/// History requests with each route replaced by its label, so the saved
/// evidence carries no route ids or account keys.
fn labeled(history: &[Vec<HistoryRequestV1>], labels: &BTreeMap<String, String>) -> Value {
    let label = |request: &HistoryRequestV1| {
        let route = request.route.as_deref();
        route.map(|route| labels.get(route).map_or("other", String::as_str))
    };
    let endpoints = history.iter().map(|requests| {
        let requests = requests.iter().map(|request| {
            let mut value = json!(request);
            value["route"] = json!(label(request));
            value
        });
        requests.collect::<Vec<_>>()
    });
    json!(endpoints.collect::<Vec<_>>())
}

/// The runner's attempts captured in `[from, to)` on the trace clock.
fn trace_between(from: u64, to: u64) -> Vec<Value> {
    let events = runner_trace::since(from).into_iter();
    events
        .filter(|event| event["at_ms"].as_u64() < Some(to))
        .collect()
}

/// Alice's live sends to one group, and when each became visible to bob.
struct Live {
    stop: Arc<AtomicBool>,
    stop_watch: Arc<AtomicBool>,
    t0: Instant,
    every: Duration,
    seen: Arc<Mutex<BTreeMap<String, f64>>>,
    sends: tokio::task::JoinHandle<Vec<(String, f64, bool)>>,
    watch: tokio::task::JoinHandle<()>,
}

impl Live {
    fn start(
        alice: AppRuntimeProbe,
        bob: AppRuntimeProbe,
        group: GroupId,
        every: Duration,
        prefix: &'static str,
    ) -> Self {
        let (stop, stop_watch) = (
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        );
        let t0 = Instant::now();
        let sends = tokio::spawn({
            let (stop, group) = (stop.clone(), group.clone());
            async move {
                let mut ticks = tokio::time::interval(every);
                ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                let mut sent = Vec::new();
                for index in 0.. {
                    ticks.tick().await;
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    let payload = format!("{prefix}{index:04}");
                    let at = t0.elapsed().as_secs_f64();
                    let ok = alice.send_message(&group, &payload).await.is_ok();
                    sent.push((payload, at, ok));
                }
                sent
            }
        });
        let seen = Arc::new(Mutex::new(BTreeMap::new()));
        let watch = tokio::spawn({
            let (stop, seen) = (stop_watch.clone(), seen.clone());
            async move {
                while !stop.load(Ordering::Relaxed) {
                    if let Ok((_, chat)) = bob.chat_view(&group, Some(256)).await {
                        let now = t0.elapsed().as_secs_f64();
                        let mut seen = seen.lock().expect("live visibility lock");
                        for text in chat.into_iter().filter(|t| t.starts_with(prefix)) {
                            seen.entry(text).or_insert(now);
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        });
        Self {
            stop,
            stop_watch,
            t0,
            every,
            seen,
            sends,
            watch,
        }
    }

    /// Stop sending, give the last sends up to one fence's hold
    /// ([`LIVE_HELD_AT_MOST`]) to arrive, and return the payloads that were
    /// sent and their visibility at bob.
    async fn finish(self) -> TestResult<(Vec<String>, Value)> {
        self.stop.store(true, Ordering::Relaxed);
        let sent = self.sends.await?;
        let ticks = self.t0.elapsed().as_millis() / self.every.as_millis().max(1) + 1;
        let arrived = || {
            let seen = self.seen.lock().expect("live visibility lock");
            let mut ok = sent.iter().filter(|(_, _, ok)| *ok);
            ok.all(|(payload, _, _)| seen.contains_key(payload))
        };
        let waiting = Instant::now();
        while !arrived() && waiting.elapsed() < LIVE_HELD_AT_MOST {
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        self.stop_watch.store(true, Ordering::Relaxed);
        self.watch.await?;
        let seen = std::mem::take(&mut *self.seen.lock().expect("live visibility lock"));
        let ok = sent.iter().filter(|(_, _, ok)| *ok);
        let visible = ok.clone().filter_map(|(payload, at, _)| {
            seen.get(payload).map(|seen| (seen - at).max(0.0) * 1e3)
        });
        let mut summary = percentiles(visible);
        let sent_ok = ok.clone().count() as u64;
        summary["sends"] = json!(sent.len());
        summary["expected_sends"] = json!(ticks);
        summary["failed_sends"] = json!(sent.len() as u64 - sent_ok);
        summary["not_visible"] = json!(sent_ok - summary["n"].as_u64().unwrap_or(0));
        // The slowest arrivals and when they were sent, to place them in the run.
        let mut slowest = ok
            .clone()
            .filter_map(|(payload, at, _)| Some((seen.get(payload)? - at, *at)))
            .collect::<Vec<_>>();
        slowest.sort_by(|a, b| b.0.total_cmp(&a.0));
        slowest.truncate(8);
        let slowest = slowest
            .iter()
            .map(|(ms, at)| json!({"sent_at_seconds": at, "ms": ms * 1e3}));
        summary["slowest"] = json!(slowest.collect::<Vec<_>>());
        let payloads = ok.map(|(payload, _, _)| payload.clone()).collect();
        Ok((payloads, summary))
    }
}

/// How long one message takes to reach bob's timeline, or `None` past
/// `limit`.
async fn visible_after(
    alice: &AppRuntimeProbe,
    bob: &AppRuntimeProbe,
    group: &GroupId,
    payload: &str,
    limit: Duration,
) -> TestResult<Option<f64>> {
    let started = Instant::now();
    send(alice, group, payload).await?;
    while started.elapsed() < limit {
        let (_, chat) = bob.chat_view(group, Some(64)).await?;
        if chat.iter().any(|text| text == payload) {
            return Ok(Some(started.elapsed().as_secs_f64() * 1e3));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Ok(None)
}

/// Whether bob's timeline in `group` holds exactly `expected`, each once.
async fn holds_exactly(
    bob: &AppRuntimeProbe,
    group: &GroupId,
    expected: &[String],
) -> TestResult<bool> {
    let (_, mut observed) = bob.chat_view(group, None).await?;
    let mut expected = expected.to_vec();
    observed.sort();
    expected.sort();
    Ok(observed == expected)
}

/// How bob's timeline holds `expected`, for the report: messages shown,
/// distinct ones, and the first few missing or shown more than once.
async fn timeline_view(
    bob: &AppRuntimeProbe,
    group: &GroupId,
    expected: &[String],
) -> TestResult<Value> {
    let (_, observed) = bob.chat_view(group, None).await?;
    let mut shown = BTreeMap::<&str, usize>::new();
    for text in &observed {
        *shown.entry(text).or_default() += 1;
    }
    let missing = expected
        .iter()
        .filter(|text| !shown.contains_key(text.as_str()));
    let repeated = shown
        .iter()
        .filter(|(_, count)| **count > 1)
        .map(|(text, _)| *text);
    Ok(json!({
        "shown": observed.len(),
        "distinct": shown.len(),
        "missing": missing.clone().count(),
        "first_missing": missing.take(10).collect::<Vec<_>>(),
        "repeated": repeated.clone().count(),
        "first_repeated": repeated.take(10).collect::<Vec<_>>(),
    }))
}

fn tally<T: Ord>(items: impl IntoIterator<Item = T>) -> BTreeMap<T, usize> {
    let mut counts = BTreeMap::new();
    for item in items {
        *counts.entry(item).or_default() += 1;
    }
    counts
}

/// A forensic audit record's event and its fields. The app writes v5, which
/// keeps it under `event`; v4 kept it under `kind`.
fn audit_event(record: &Value) -> &Value {
    record.get("event").unwrap_or(&record["kind"])
}

/// Audit rows of one kind, such as `ingest_outcome`, in record order.
fn audit_rows<'a>(audit: &'a [Value], kind: &'a str) -> impl Iterator<Item = &'a Value> + 'a {
    audit
        .iter()
        .map(audit_event)
        .filter(move |row| row["type"] == kind)
}

/// An audit field that v5 writes as a decimal string and v4 as a number.
fn audit_number(value: &Value) -> Option<u64> {
    value.as_u64().or_else(|| value.as_str()?.parse().ok())
}

/// Put audit records in the order they were written, across files and the
/// runtime's reopening.
fn audit_order(records: &mut [Value]) {
    let key = |record: &Value| {
        let at = audit_number(&record["wall_time_ms"]).unwrap_or_default();
        (at, audit_number(&record["seq"]).unwrap_or_default())
    };
    records.sort_by_key(key);
}

/// The audit's reference to a message id given in hex: v5 hashes each one.
fn audit_message_ref(id_hex: &str) -> Option<String> {
    let bytes = hex::decode(id_hex).ok()?;
    let reference = marmot_forensics::v5::EngineMessageRef::from_message_id(&bytes).ok()?;
    Some(reference.as_str().to_owned())
}

/// A row's `what`, qualified by its `why` when it has one: both are fixed
/// labels, never ids.
fn audit_label(row: &Value, what: &str, why: Option<&str>) -> String {
    let what = row[what].as_str().unwrap_or("unnamed");
    match why.and_then(|why| row[why].as_str()) {
        Some(why) => format!("{what}:{why}"),
        None => what.to_owned(),
    }
}

/// What bob's audit says about inbound messages over the run, by kind and
/// reason. An ingest outcome doesn't say whether the message was a chat
/// message or a commit.
fn audit_summary(audit: &[Value]) -> Value {
    let rows = |kind| audit_rows(audit, kind);
    json!({
        "records": audit.len(),
        "by_type": tally(audit.iter().filter_map(|record| audit_event(record)["type"].as_str())),
        "ingest_outcomes": tally(rows("ingest_outcome").map(|row| audit_label(row, "outcome_kind", Some("stale_reason")))),
        "ingest_errors": tally(rows("ingest_error").map(|row| audit_label(row, "error_kind", None))),
        "message_states": tally(rows("message_state_changed").map(|row| audit_label(row, "new_state", Some("reason")))),
        "peeler_outcomes": tally(rows("peeler_outcome").map(|row| audit_label(row, "outcome", Some("error_kind")))),
    })
}

/// Every sender in the loop: the backlog's, then alice with the live ticks.
const LANES: [&str; 4] = ["s1", "s2", "s3", "alice"];

/// Alice's live messages in the loop.
const TICK_PREFIX: &str = "tick-";
/// How the relay delivered an event to bob, by the `REQ` that carried it
/// ([`RelayDeliveryPath`]): event ids, an unlimited window, a limited window,
/// a group maintenance subscription, or any other subscription. A path is a
/// request shape; both owners send ids and unlimited windows.
const PATHS: [&str; 5] = ["ids", "window", "paged_window", "maintenance", "live"];

fn path_label(path: RelayDeliveryPath) -> &'static str {
    match path {
        RelayDeliveryPath::Ids => PATHS[0],
        RelayDeliveryPath::Window => PATHS[1],
        RelayDeliveryPath::PagedWindow => PATHS[2],
        RelayDeliveryPath::Maintenance => PATHS[3],
        RelayDeliveryPath::Live => PATHS[4],
    }
}

/// A message's sender (its lane in [`LANES`]) and its position among that
/// sender's messages, in the order the journey sent them. This is not its
/// generation in the sender's ratchet: a send that queues behind a pending
/// commit is encrypted after later direct sends (mdk#2842), and only the
/// sender's audit shows the order it encrypted them in.
fn send_position(payload: &str) -> Option<(usize, usize)> {
    let index = payload.rsplit('-').next()?.parse::<usize>().ok()?;
    if payload.starts_with(TICK_PREFIX) {
        return Some((SENDERS.len(), index));
    }
    Some((index % SENDERS.len(), index / SENDERS.len()))
}

/// What bob's audit recorded for one send's event.
#[derive(Clone, Default)]
struct Seen {
    received: usize,
    entries: usize,
    outcomes: Vec<String>,
    errors: Vec<String>,
    states: Vec<String>,
    /// Bob first deferred it: its peel failed until a later re-peel.
    deferred: bool,
}

/// Bob's audit rows for each send's event. The audit names an inbound message
/// by the event that carried it.
fn bob_seen(events: &[Option<String>], audit: &[Value]) -> Vec<Seen> {
    let mut by_ref = BTreeMap::new();
    for (index, id) in events.iter().enumerate() {
        if let Some(id) = id {
            by_ref.insert(id.clone(), index);
            if let Some(reference) = audit_message_ref(id) {
                by_ref.insert(reference, index);
            }
        }
    }
    let mut seen = vec![Seen::default(); events.len()];
    for row in audit.iter().map(audit_event) {
        let message = row.get("message_ref").unwrap_or(&row["msg_id"]);
        let index = message.as_str().and_then(|id| by_ref.get(id));
        let Some(&index) = index else { continue };
        let seen = &mut seen[index];
        match row["type"].as_str() {
            Some("transport_received") => seen.received += 1,
            Some("ingest_entry") => seen.entries += 1,
            Some("ingest_outcome") => {
                seen.outcomes
                    .push(audit_label(row, "outcome_kind", Some("stale_reason")));
            }
            Some("ingest_error") => seen.errors.push(audit_label(row, "error_kind", None)),
            Some("message_state_changed") => {
                seen.states
                    .push(audit_label(row, "new_state", Some("reason")));
                seen.deferred |= row["new_state"] == "peel_deferred";
            }
            _ => {}
        }
    }
    seen
}

/// The relay event that carried each send, from its sender's own timeline.
/// A receiver's timeline names a different source id, which no relay holds.
async fn carrying_events(
    subject: &AppRuntimeHarness,
    group: &GroupId,
    sent: &[Sent],
) -> TestResult<Vec<Option<String>>> {
    let mut events = vec![None; sent.len()];
    for (lane, sender) in LANES.iter().enumerate() {
        let asked = sent
            .iter()
            .enumerate()
            .filter(|(_, sent)| send_position(&sent.payload).is_some_and(|(at, _)| at == lane));
        let asked = asked
            .filter_map(|(index, sent)| Some((index, sent.app_id.clone()?)))
            .collect::<Vec<_>>();
        let ids = asked.iter().map(|(_, id)| id.clone()).collect();
        let sources = subject.probe(sender)?.message_sources(group, ids).await?;
        for ((index, _), source) in asked.into_iter().zip(sources) {
            events[index] = source;
        }
    }
    Ok(events)
}

/// Where the backlog went, as counts and send positions, never ids. For every
/// send: how it completed, and how many of the events it published the relay
/// holds and bob's audit names (the controls). How the relay delivered the
/// events to bob's connections since he came back, by [`PATHS`]: all of them,
/// and the first on each relay. Per sender: how many messages bob deferred
/// and how many of each he lacks. For each message bob's timeline lacks:
/// which other members show it, whether bob holds it only as an invalidated
/// tombstone, how its send completed, how the relay delivered its event to
/// bob, and what bob's audit recorded for it. `per_send` repeats the
/// delivery for every send with its event's audit ref, a hash, so the saved
/// audits can be read offline.
async fn delivery_view(
    subject: &AppRuntimeHarness,
    bob: &AppRuntimeProbe,
    group: &GroupId,
    backlog: &[Sent],
    ticks: &[String],
    bob_sessions: &[u64],
    audit: &[Value],
) -> TestResult<Value> {
    // Alice's ticks join the backlog, each named by her own app message id.
    let alice_ids = subject.probe("alice")?.chat_message_ids(group).await?;
    let alice_ids = alice_ids.into_iter().collect::<BTreeMap<_, _>>();
    let tick = |payload: &String| Sent {
        payload: payload.clone(),
        published: 1,
        app_id: alice_ids.get(payload).cloned(),
        shown_after_closed: false,
    };
    let sent = backlog.iter().cloned().chain(ticks.iter().map(tick));
    let sent = sent.collect::<Vec<_>>();
    let sent = sent.as_slice();
    let distinct = |texts: Vec<String>| texts.into_iter().collect::<BTreeSet<_>>();
    let held = distinct(bob.chat_view(group, None).await?.1);
    let lacks = |sent: &Sent| !held.contains(&sent.payload);
    let payload_index = sent
        .iter()
        .enumerate()
        .map(|(index, sent)| (sent.payload.as_str(), index));
    let payload_index = payload_index.collect::<BTreeMap<_, _>>();
    let missing = sent.iter().filter(|sent| lacks(sent)).collect::<Vec<_>>();
    let count_in = |texts: &BTreeSet<String>| {
        missing
            .iter()
            .filter(|sent| texts.contains(&sent.payload))
            .count()
    };
    let mut shown_by = BTreeMap::new();
    for member in ["alice"].into_iter().chain(SENDERS) {
        let chat = subject.probe(member)?.chat_view(group, None).await?.1;
        shown_by.insert(member, count_in(&distinct(chat)));
    }
    let invalidated = count_in(&distinct(bob.invalidated_chat(group).await?));
    let events = carrying_events(subject, group, sent).await?;
    let relay = subject.relay_publication_ids().await?;
    let relay = relay.into_iter().map(|(id, _)| id).collect::<BTreeSet<_>>();
    // Per event: deliveries by path, the paths of its first delivery on each
    // relay, the earliest of those deliveries on the proxies' clock, and the
    // event's `created_at`.
    let mut to_bob = BTreeMap::<String, ([u64; PATHS.len()], BTreeSet<&str>)>::new();
    let mut timing = BTreeMap::<String, (Option<u64>, u64)>::new();
    for endpoint in subject.relay_traffic(bob_sessions, true).await? {
        for (id, delivery) in endpoint.events {
            let (at, created) = timing.entry(id.clone()).or_default();
            if let Some((_, first_at)) = delivery.first {
                *at = Some(at.map_or(first_at, |at| at.min(first_at)));
            }
            *created = delivery.created_at;
            let (via, first) = to_bob.entry(id).or_default();
            let counts = [
                delivery.via_ids,
                delivery.via_window,
                delivery.via_paged_window,
                delivery.via_maintenance,
                delivery.via_live,
            ];
            for (total, count) in via.iter_mut().zip(counts) {
                *total += count;
            }
            first.extend(delivery.first.map(|(path, _)| path_label(path)));
        }
    }
    let index_of = |sent: &Sent| payload_index[sent.payload.as_str()];
    let delivered = |sent: &Sent| {
        events[index_of(sent)]
            .as_ref()
            .and_then(|id| to_bob.get(id))
    };
    let via = |sent: &Sent| delivered(sent).map_or([0; PATHS.len()], |(via, _)| *via);
    // The paths that delivered it, joined, or "never".
    let path = |sent: &Sent| {
        let via = via(sent);
        let named = PATHS.iter().zip(via).filter(|(_, count)| *count > 0);
        let named = named.map(|(name, _)| *name).collect::<Vec<_>>();
        if named.is_empty() {
            "never".to_owned()
        } else {
            named.join("+")
        }
    };
    let first = |sent: &Sent| {
        let first = delivered(sent).map(|(_, first)| first.iter().copied().collect::<Vec<_>>());
        first
            .filter(|first| !first.is_empty())
            .map_or("never".to_owned(), |first| first.join("+"))
    };
    let seen = bob_seen(&events, audit);
    let (backlog, ticks) = sent.split_at(backlog.len());
    let audited = seen[..backlog.len()]
        .iter()
        .filter(|seen| seen.entries > 0)
        .count();
    let mut by_sender = BTreeMap::new();
    for (lane, sender) in LANES.iter().enumerate() {
        let sends = sent
            .iter()
            .zip(&seen)
            .filter(|(sent, _)| send_position(&sent.payload).is_some_and(|(at, _)| at == lane));
        let sends = sends.collect::<Vec<_>>();
        by_sender.insert(
            *sender,
            json!({
                "sends": sends.len(),
                "missing": sends.iter().filter(|(sent, _)| lacks(sent)).count(),
                "deferred": sends.iter().filter(|(_, seen)| seen.deferred).count(),
                "deferred_missing": sends.iter().filter(|(sent, seen)| seen.deferred && lacks(sent)).count(),
            }),
        );
    }
    let missing_detail = sent.iter().zip(&seen).filter(|(sent, _)| lacks(sent)).map(
        |(sent, seen)| {
            let (lane, position) = send_position(&sent.payload).unwrap_or((usize::MAX, usize::MAX));
            json!({
                "sender": LANES.get(lane),
                "position": position,
                "how": sent.how(),
                "relay_to_bob": PATHS.iter().copied().zip(via(sent)).collect::<BTreeMap<_, _>>(),
                "first_path": first(sent),
                "received": seen.received,
                "entries": seen.entries,
                "outcomes": tally(seen.outcomes.iter()),
                "errors": tally(seen.errors.iter()),
                "states": tally(seen.states.iter()),
                "deferred": seen.deferred,
            })
        },
    );
    let event_counts = |sent: &[&Sent]| {
        let ids = sent
            .iter()
            .filter_map(|sent| events[index_of(sent)].as_ref());
        let ids = ids.collect::<Vec<_>>();
        json!({
            "found": ids.len(),
            "on_relay": ids.iter().filter(|id| relay.contains(**id)).count(),
        })
    };
    let all = backlog.iter().collect::<Vec<_>>();
    // Local evidence for reading bob's audit offline: each send's lane and
    // position, its event's audit ref (a hash), and how it reached bob.
    let per_send = sent.iter().map(|sent| {
        let (lane, position) = send_position(&sent.payload).unwrap_or((usize::MAX, usize::MAX));
        let event = events[index_of(sent)].as_deref();
        let reference = event.and_then(audit_message_ref);
        let (first_at_ms, created_at) = event
            .and_then(|id| timing.get(id))
            .copied()
            .unwrap_or_default();
        json!({
            "sender": LANES.get(lane),
            "position": position,
            "how": sent.how(),
            "audit_ref": reference,
            "created_at": created_at,
            "first_at_ms": first_at_ms,
            "paths": PATHS.iter().copied().zip(via(sent)).collect::<BTreeMap<_, _>>(),
            "first_path": first(sent),
            "missing": lacks(sent),
        })
    });
    Ok(json!({
        "per_send": per_send.collect::<Vec<_>>(),
        "sends": {
            "by_how": tally(backlog.iter().map(Sent::how)),
            "events": event_counts(&all),
            "in_bob_audit": audited,
            "relay_to_bob": tally(backlog.iter().map(path)),
            "first_path_to_bob": tally(backlog.iter().map(first)),
            "ticks": ticks.len(),
            "ticks_relay_to_bob": tally(ticks.iter().map(path)),
            "ticks_first_path_to_bob": tally(ticks.iter().map(first)),
        },
        "by_sender": by_sender,
        "missing": {
            "count": missing.len(),
            "shown_by": shown_by,
            "invalidated_at_bob": invalidated,
            "by_how": tally(missing.iter().map(|sent| sent.how())),
            "events": event_counts(&missing),
            "relay_to_bob": tally(missing.iter().map(|sent| path(sent))),
            "first_path_to_bob": tally(missing.iter().map(|sent| first(sent))),
            "each": missing_detail.collect::<Vec<_>>(),
        },
    }))
}

/// The queued intents each other member's engine refused at drain: its
/// process's tally of `QueuedIntentRefused` events (by intent kind and reason,
/// with the events it missed by lagging) and the refusal rows in its forensic
/// audit, which it saves to `out`. Refusing a plain chat message in a healthy
/// group is never right.
async fn refusals_view(subject: &AppRuntimeHarness, out: &Path) -> TestResult<Value> {
    let mut by_member = BTreeMap::new();
    for member in ["alice"].into_iter().chain(SENDERS) {
        let probe = subject.probe(member)?;
        let tally = probe.queued_intent_refusals().await?;
        let audit = probe.finish_audit_log().await?;
        // Local evidence: the sender side of what bob saw.
        save(out, &format!("{member}-audit.json"), &audit)?;
        let rows = audit_rows(&audit, "rejection")
            .filter(|row| row["reason"] == "queued_outbound_intent_refused_on_settled_state")
            .count();
        let refusals = json!({
            "events": tally.by_kind_and_reason,
            "lagged_events": tally.lagged_events,
            "audit_rows": rows,
        });
        by_member.insert(member, refusals);
    }
    Ok(json!(by_member))
}

/// Whether the runner reports nothing left to fetch and nothing parked, read
/// after one of its attempts since `trace_from` (trace clock). The status
/// lists nothing until a runner has surveyed, and keeps its last survey's
/// answer across a reconnect, so a clear status read before such an attempt
/// proves nothing: the runner surveys before each attempt. A parked unit
/// leaves the catching-up fields and shows only as a notice.
async fn caught_up(bob: &AppRuntimeProbe, trace_from: u64) -> TestResult<bool> {
    if runner_trace::since(trace_from).is_empty() {
        return Ok(false);
    }
    let status = bob.account_recovery_status().await?;
    Ok(status.catching_up_group_ids_hex.is_empty()
        && !status.inbox_catching_up
        && status.notices.is_empty())
}

/// Run a proof journey with bob in this process and his recovery runner
/// owning debt, under the watchdog; save its report, close every runtime, and
/// return the report or the journey's error.
async fn run_proof<J>(label: &str, journey: J) -> Value
where
    J: AsyncFnOnce(&mut AppRuntimeHarness, &Path) -> TestResult<Value>,
{
    let artifacts = journey_artifacts(label);
    let clients = clients();
    runner_trace::start().expect("capture the runner's trace");
    let mut subject = AppRuntimeHarness::new_with_relay_pair_owning_debt(&clients, &clients[1..2])
        .await
        .expect("runner proof harness setup");
    let outcome = tokio::time::timeout(WATCHDOG, journey(&mut subject, artifacts.path()))
        .await
        .unwrap_or_else(|_| {
            Err(format!("exceeded its {}-second watchdog", WATCHDOG.as_secs()).into())
        });
    let mut record = outcome
        .as_ref()
        .map_or_else(|error| json!({"error": error.to_string()}), Clone::clone);
    let snapshots = subject.performance_snapshots().ok();
    record["bob_telemetry_at_end"] = json!(snapshots.and_then(|mut all| all.remove("bob")));
    save(artifacts.path(), "report.json", &record).unwrap();
    println!(
        "{label}: {}",
        serde_json::to_string_pretty(&record["proof"]).unwrap()
    );
    // Close every runtime before asserting (see APP_PATH_COVERAGE.md).
    let mut close_errors = Vec::new();
    for client in &clients {
        if let Err(error) = subject.set_online(client, false).await {
            close_errors.push(error.to_string());
        }
    }
    if let Err(error) = subject.shutdown().await {
        close_errors.push(format!("shutdown: {error}"));
    }
    drop(subject);
    eprintln!("{label} evidence: {}", artifacts.keep().display());
    let report = outcome.unwrap_or_else(|error| panic!("{label} did not complete: {error}"));
    assert!(
        close_errors.is_empty(),
        "runtime close failed: {close_errors:?}"
    );
    report
}

/// Phase 1's 0.14.0 loop: a relay that stays connected but never answers
/// history, while live traffic arrives every two seconds. On 0.14.0 every
/// attempt there was cut with nothing fetched and the next one followed
/// about 20 s later, for as long as the app ran. The account must recover
/// from the healthy endpoint, live messages must keep arriving, and the
/// stalled endpoint's attempts must thin out instead of repeating.
pub(super) async fn stalled_relay_loop() {
    let report = run_proof("runner-loop", async |subject, out| {
        let started = Instant::now();
        let clients = clients();
        let group = create(subject, "loop", &clients).await?;
        settle_maintenance(subject, &clients, std::slice::from_ref(&group)).await?;
        note(started, "group created and settled");
        // Kept in each app's settings, so bob's reopened runtime records too.
        for member in &clients {
            subject.probe(member)?.start_audit_log().await?;
        }
        subject.set_online("bob", false).await?;
        let sent = publish(subject, &group, "loop-", LOOP_MESSAGES).await?;
        let backlog = payloads(&sent);
        note(started, "backlog published");
        subject.stall_relay_history(1, true).await?;
        let clocks = relay_clocks(subject).await?;
        // Every connection from here on is bob's: the others keep theirs.
        let traffic = subject.relay_traffic(&[u64::MAX, u64::MAX], false).await?;
        let bob_sessions = traffic.iter().map(|relay| relay.next_session).collect::<Vec<_>>();
        let t0 = Instant::now();
        let trace_t0 = runner_trace::now_ms();
        subject.set_online("bob", true).await?;
        let (alice, bob) = (subject.probe("alice")?, subject.probe("bob")?);
        let live = Live::start(alice, bob.clone(), group.clone(), Duration::from_secs(2), TICK_PREFIX);
        let mut recovered = None;
        while t0.elapsed() < LOOP_WINDOW {
            if recovered.is_none() {
                let (_, chat) = bob.chat_view(&group, None).await?;
                let held = chat.iter().filter(|text| text.starts_with("loop-")).count();
                if held == backlog.len() {
                    recovered = Some(t0.elapsed().as_secs_f64());
                    note(started, "backlog recovered from the healthy endpoint");
                }
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        let (ticks, live_visibility) = live.finish().await?;
        let sent_ticks = ticks.clone();
        let status = bob.account_recovery_status().await?;
        let mut expected = backlog.clone();
        expected.extend(ticks);
        let complete = holds_exactly(&bob, &group, &expected).await?;
        let timeline = timeline_view(&bob, &group, &expected).await?;
        // Report-only: a read that fails leaves its error in the report.
        let mut audit = bob.finish_audit_log().await.map_err(|error| error.to_string());
        if let Ok(records) = &mut audit {
            audit_order(records);
        }
        let records = audit.as_deref().unwrap_or_default();
        let mut delivery =
            delivery_view(subject, &bob, &group, &sent, &sent_ticks, &bob_sessions, records).await;
        // Kept apart from the report: per send, and bob's own rows.
        if let Ok(view) = &mut delivery
            && let Some(per_send) = view.as_object_mut().and_then(|view| view.remove("per_send"))
        {
            save(out, "bob-sends.json", &per_send)?;
        }
        save(out, "bob-audit.json", &records)?;
        let refusals = refusals_view(subject, out).await;
        let history = history_since(subject, &clocks).await?;
        let route = bob.nostr_route(&group).await?.ok_or("bob holds no route")?;
        let labels = BTreeMap::from([(route.clone(), "loop".to_owned())]);
        let stalled = &history[1];
        let starts = bursts(stalled.iter().filter(|request| request.withheld));
        let window_ms = u64::try_from(LOOP_WINDOW.as_millis())?;
        let half = clocks[1] + window_ms / 2;
        let per_minute = |from: u64, to: u64| {
            let minutes = (to - from) as f64 / 60_000.0;
            starts.iter().filter(|at| (from..to).contains(at)).count() as f64 / minutes
        };
        let gaps = starts.windows(2).map(|pair| (pair[1] - pair[0]) as f64 / 1e3);
        let withheld = stalled.iter().filter(|request| request.withheld);
        let second_half_minutes = minutes_asked(withheld, half, clocks[1] + window_ms);
        let trace_half = trace_t0 + window_ms / 2;
        let runner = [trace_between(trace_t0, trace_half), trace_between(trace_half, trace_t0 + window_ms)];
        let proof = json!({
            "backlog": backlog.len(),
            "recovered_seconds": recovered,
            "timeline_exact": complete,
            "timeline": timeline,
            "delivery": delivery.unwrap_or_else(|error| json!({"error": error.to_string()})),
            "bob_audit": audit.as_deref().map_or_else(|error| json!({"error": error}), audit_summary),
            "refusals": refusals.unwrap_or_else(|error| json!({"error": error.to_string()})),
            "live_visibility_ms": live_visibility,
            "stalled_endpoint_bursts": starts.len(),
            "stalled_bursts_per_minute": {
                "first_half": per_minute(clocks[1], half),
                "second_half": per_minute(half, clocks[1] + window_ms),
            },
            "seconds_between_stalled_bursts": gaps.collect::<Vec<_>>(),
            "stalled_minutes_asked_in_second_half": second_half_minutes,
            "runner": {
                "first_half": runner_summary(&runner[0]),
                "second_half": runner_summary(&runner[1]),
                "second_half_wasted": wasted(&runner[1]),
            },
            "history": history.iter().map(|requests| history_summary(requests, &labels)).collect::<Vec<_>>(),
            "status_at_end": status_summary(&status),
        });
        save(out, "history.json", &labeled(&history, &labels))?;
        save(out, "runner-trace.json", &runner_trace::since(trace_t0))?;
        if !complete || recovered.is_none() {
            return Err(format!("the backlog did not recover exactly from the healthy endpoint: {proof}").into());
        }
        if !live_complete(&live_visibility) {
            return Err(format!("live messages failed or stopped arriving behind the stalled relay: {proof}").into());
        }
        // The control: something did try the stalled relay.
        if per_minute(clocks[1], half) == 0.0 {
            return Err(format!("nothing attempted the stalled relay: {proof}").into());
        }
        // 0.14.0 attempted about twice a minute for as long as it ran. Bursts
        // alone miss a loop that never pauses, so count asked minutes too.
        if per_minute(half, clocks[1] + window_ms) > 0.5 || second_half_minutes > LOOP_SECOND_HALF_MINUTES {
            return Err(format!("the stalled relay is still attempted every two minutes or more often: {proof}").into());
        }
        Ok(json!({"proof": proof}))
    })
    .await;
    assert_eq!(report["proof"]["timeline_exact"], true);
}

/// Tens of thousands of events owed in one group, with live traffic every
/// three seconds, then a reconnect after the account has caught up.
///
/// - The owed group finishes over successive attempts, each live message
///   arrives, nothing is fetched twice, and the attempt count stays bounded.
/// - After the restart and after the reconnect, each route's gap since its
///   last durable proof is swept as cold-start work: the busy group's and the
///   quiet group's, which has no event in its live range. Live messages to
///   the quiet group are never held behind it.
pub(super) async fn owed_history() {
    let report = run_proof("runner-owed-history", async |subject, out| {
        let started = Instant::now();
        let clients = clients();
        let pair = clients[..2].to_vec();
        let busy = create(subject, "busy", &clients).await?;
        let quiet = create(subject, "quiet", &pair).await?;
        settle_maintenance(subject, &clients, &[busy.clone(), quiet.clone()]).await?;
        let (alice, bob) = (subject.probe("alice")?, subject.probe("bob")?);
        let labels = BTreeMap::from([
            (bob.nostr_route(&busy).await?.ok_or("bob holds no busy route")?, "busy".to_owned()),
            (bob.nostr_route(&quiet).await?.ok_or("bob holds no quiet route")?, "quiet".to_owned()),
        ]);
        let route = |label: &str| labels.iter().find(|(_, l)| *l == label).map(|(r, _)| r.clone()).unwrap();
        let (busy_route, quiet_route) = (route("busy"), route("quiet"));
        let mut quiet_expected = Vec::new();
        for index in 0..3 {
            let payload = format!("quiet-early-{index}");
            send(&alice, &quiet, &payload).await?;
            quiet_expected.push(payload);
        }
        wait_for("quiet history at bob", SETTLEMENT, async || {
            holds_exactly(&bob, &quiet, &quiet_expected).await
        })
        .await?;
        tokio::time::sleep(QUIET_AGE).await;
        note(started, "groups created, quiet group aged");

        // The owed backlog, while bob is stopped.
        subject.set_online("bob", false).await?;
        let backlog_started = Instant::now();
        let mut expected = payloads(&publish(subject, &busy, "owed-", OWED_MESSAGES).await?);
        let backlog_seconds = backlog_started.elapsed().as_secs_f64();
        note(started, "backlog published");

        // Restart: every route owes its gap since its last durable proof.
        let restart_clocks = relay_clocks(subject).await?;
        let t0 = Instant::now();
        let trace_restart = runner_trace::now_ms();
        subject.set_online("bob", true).await?;
        let bob = subject.probe("bob")?;
        let live = Live::start(alice.clone(), bob.clone(), busy.clone(), Duration::from_secs(3), "live-");
        let quiet_after_restart =
            visible_after(&alice, &bob, &quiet, "quiet-after-restart", Duration::from_secs(60)).await?;
        quiet_expected.push("quiet-after-restart".into());
        // It proves nothing unless the busy group was still owed then.
        let (_, chat) = bob.chat_view(&busy, None).await?;
        let busy_visible_when_quiet_seen = chat.iter().filter(|text| text.starts_with("owed-")).count();
        // Beside the earlier owner the runner may make no attempt at all here,
        // so its caught-up report is recorded, not awaited: sampled from the
        // drain through the idle window below.
        let (mut drained, mut reported_caught_up) = (None, None);
        while drained.is_none() {
            if t0.elapsed() >= RECOVERY_DEADLINE {
                break;
            }
            if drained.is_none() {
                let (_, chat) = bob.chat_view(&busy, None).await?;
                if chat.iter().filter(|text| text.starts_with("owed-")).count() == OWED_MESSAGES {
                    drained = Some(t0.elapsed().as_secs_f64());
                    note(started, "owed backlog visible");
                }
            }
            if drained.is_some() && reported_caught_up.is_none() && caught_up(&bob, trace_restart).await? {
                reported_caught_up = Some(t0.elapsed().as_secs_f64());
                note(started, "runner reports caught up");
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        let (live_sent, live_visibility) = live.finish().await?;
        expected.extend(live_sent);
        let busy_exact = holds_exactly(&bob, &busy, &expected).await?;
        let busy_timeline = timeline_view(&bob, &busy, &expected).await?;
        let after_restart = history_since(subject, &restart_clocks).await?;
        let trace_idle = runner_trace::now_ms();
        let restart_trace = trace_between(trace_restart, trace_idle);

        // Idle: nothing is owed, so nothing is fetched. (A status read is local.)
        let idle_clocks = relay_clocks(subject).await?;
        let idle_started = Instant::now();
        while idle_started.elapsed() < QUIET_AGE {
            if drained.is_some() && reported_caught_up.is_none() && caught_up(&bob, trace_restart).await? {
                reported_caught_up = Some(t0.elapsed().as_secs_f64());
                note(started, "runner reports caught up");
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        let idle = history_since(subject, &idle_clocks).await?;
        let trace_cut = runner_trace::now_ms();
        let idle_trace = trace_between(trace_idle, trace_cut);

        // Reconnect: endpoint 0's live generations end. Their ranges were only
        // provisional, and with no event inside the rebuild lookback every
        // route's new live count is empty, so each is owed again there. The
        // interruption returns once the relay is back; only what follows
        // counts as the reconnect's re-proof.
        let reconnect_clocks = relay_clocks(subject).await?;
        subject.interrupt_relay("reconnect", "relay:shared", OUTAGE_MS).await?;
        let reconnected = Instant::now();
        let trace_reconnect = runner_trace::now_ms();
        let quiet_after_reconnect =
            visible_after(&alice, &bob, &quiet, "quiet-after-reconnect", Duration::from_secs(60)).await?;
        quiet_expected.push("quiet-after-reconnect".into());
        let mut resweep = BTreeSet::new();
        // Each route asked again on endpoint 0, by either of bob's owners.
        let resweeps = async || {
            let history = history_since(subject, &reconnect_clocks).await?;
            resweep = history[0].iter().filter_map(|request| request.route.clone()).collect();
            Ok(resweep.contains(&busy_route) && resweep.contains(&quiet_route) && caught_up(&bob, trace_reconnect).await?)
        };
        let left = RESWEEP_DEADLINE.saturating_sub(reconnected.elapsed());
        let resweep_result = wait_for("the reconnect's re-sweep", left, resweeps).await;
        let resweep_seconds = reconnected.elapsed().as_secs_f64();
        let after_reconnect = history_since(subject, &reconnect_clocks).await?;
        let reconnect_trace = runner_trace::since(trace_reconnect);
        let outage_trace = trace_between(trace_cut, trace_reconnect);
        let quiet_exact = holds_exactly(&bob, &quiet, &quiet_expected).await?;
        let status = bob.account_recovery_status().await?;
        let summaries = |history: &[Vec<HistoryRequestV1>]| {
            history.iter().map(|requests| history_summary(requests, &labels)).collect::<Vec<_>>()
        };
        let swept = |history: &[Vec<HistoryRequestV1>], route: &str| {
            history.iter().map(|requests| requests.iter().any(|r| r.route.as_deref() == Some(route))).collect::<Vec<_>>()
        };
        let per_endpoint = |history: &[Vec<HistoryRequestV1>], of: fn(&[HistoryRequestV1]) -> u64| {
            history.iter().map(|requests| of(requests)).collect::<Vec<_>>()
        };
        let restart_repeats = per_endpoint(&after_restart, repeated_windows);
        let reconnect_repeats = per_endpoint(&after_reconnect, repeated_windows);
        let restart_bursts = per_endpoint(&after_restart, |requests| bursts(requests).len() as u64);
        let proof = json!({
            "owed_messages": OWED_MESSAGES,
            "backlog_publish_seconds": backlog_seconds,
            "restart": {
                "owed_visible_seconds": drained,
                "runner_caught_up_seconds": reported_caught_up,
                "deadline_seconds": RECOVERY_DEADLINE.as_secs(),
                "busy_timeline_exact": busy_exact,
                "busy_timeline": busy_timeline,
                "live_visibility_ms": live_visibility,
                "quiet_message_visible_ms": quiet_after_restart,
                "busy_visible_when_quiet_seen": busy_visible_when_quiet_seen,
                "busy_swept_per_endpoint": swept(&after_restart, &busy_route),
                "quiet_swept_per_endpoint": swept(&after_restart, &quiet_route),
                "repeated_window_requests_per_endpoint": restart_repeats,
                "bursts_per_endpoint": restart_bursts,
                "runner": runner_summary(&restart_trace),
                "runner_wasted": wasted(&restart_trace),
                "history": summaries(&after_restart),
            },
            "idle": {"seconds": QUIET_AGE.as_secs(), "history": summaries(&idle), "runner": runner_summary(&idle_trace)},
            "reconnect": {
                "outage_ms": OUTAGE_MS,
                "resweep": resweep_result.as_ref().map_or_else(|error| json!(error.to_string()), |()| json!("swept")),
                "resweep_seconds": resweep_seconds,
                "routes_swept_on_endpoint_0": resweep.iter().map(|r| labels.get(r).map_or("other", String::as_str)).collect::<Vec<_>>(),
                "quiet_message_visible_ms": quiet_after_reconnect,
                "quiet_timeline_exact": quiet_exact,
                "repeated_window_requests_per_endpoint": reconnect_repeats,
                "history": summaries(&after_reconnect),
                "runner": runner_summary(&reconnect_trace),
                "runner_during_outage": runner_summary(&outage_trace),
            },
            "status_at_end": status_summary(&status),
        });
        let history = json!({
            "restart": labeled(&after_restart, &labels),
            "idle": labeled(&idle, &labels),
            "reconnect": labeled(&after_reconnect, &labels),
        });
        save(out, "history.json", &history)?;
        save(out, "runner-trace.json", &runner_trace::since(trace_restart))?;
        let failure = |what: &str| Err::<Value, _>(format!("{what}: {proof}").into());
        if drained.is_none() || !busy_exact {
            return failure("the owed group did not finish exactly within the deadline");
        }
        if !live_complete(&live_visibility) {
            return failure("live messages failed or were lost while the backlog was owed");
        }
        if restart_repeats.iter().any(|repeats| *repeats > 0) {
            return failure("a history window was asked twice on one endpoint");
        }
        if restart_bursts.iter().any(|bursts| *bursts as usize > OWED_BURSTS) {
            return failure("the owed group took too many attempts");
        }
        if !swept(&after_restart, &busy_route).iter().all(|swept| *swept) {
            return failure("the owed group was not fetched from both endpoints");
        }
        if !swept(&after_restart, &quiet_route).iter().all(|swept| *swept) {
            return failure("the quiet group's gap was not swept after the restart");
        }
        if quiet_after_restart.is_none() || quiet_after_reconnect.is_none() || !quiet_exact {
            return failure("a live message to the quiet group was held back");
        }
        if busy_visible_when_quiet_seen >= OWED_MESSAGES {
            return failure("the busy group finished before the quiet group's message showed");
        }
        if resweep_result.is_err() {
            return failure("the reconnect's owed ranges were not swept");
        }
        // A failed quantum or an inbox re-check alone is no re-proof, and every
        // route's owed range there spans at least the outage.
        if advanced_seconds(&reconnect_trace) < OUTAGE_MS / 1000 {
            return failure("the runner re-proved less than the outage after the reconnect");
        }
        Ok(json!({"proof": proof}))
    })
    .await;
    assert_eq!(report["proof"]["restart"]["busy_timeline_exact"], true);
}
