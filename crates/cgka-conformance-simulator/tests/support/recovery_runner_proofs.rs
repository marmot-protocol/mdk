//! Recovery-runner proofs (mdk#2660 phase 4, PR 5f) under production policy,
//! through public runtime APIs and the relay's wire only. Bob runs in this
//! process with his recovery runner owning history debt; the relay and every
//! other participant run in their own processes. Both relay endpoints share
//! one store and publish the production NIP-11 document.
//!
//! The runner owns recovery with both native backward-paging entry points
//! disabled. Gate-off control builds retain them. Assertions require positive
//! runner work and wire evidence, exact visible timelines and bounded holds.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cgka_conformance_simulator::app_runtime::{
    ConnectionTrafficV1, HistoryRequestV1, LiveGroupReplyV1, RelayDeliveryPath,
};
use cgka_conformance_simulator::{
    AppRuntimeHarness, AppRuntimeProbe, ConvergenceSubject, SubjectCreateGroup,
    SubjectRemoveMembers, SubjectSelfUpdate,
};
use cgka_traits::GroupId;
use serde_json::{Value, json};

use super::recovery_scorecard::{percentiles, status_summary};
use super::{SETTLEMENT, TestResult, journey_artifacts, save};

/// They publish the owed backlog in parallel, so bob is the only account
/// that owes it.
const SENDERS: [&str; 3] = ["s1", "s2", "s3"];
/// Large repeated backlog, owed on both endpoints and beyond the staging bound.
const OWED_MESSAGES: usize = 5_000;
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
/// Runner attempts without progress in the stalled relay's second half.
const LOOP_SECOND_HALF_ATTEMPTS: usize = 4;
/// Attempts without progress while two healthy endpoints drain owed history.
const OWED_WASTED_ATTEMPTS: usize = 4;

/// Bursts of history requests per endpoint while the owed group drains: the
/// wire's view of the attempts, both owners together.
const OWED_BURSTS: usize = 4;
/// Tail-drain allowance after backlog recovery and after sending stops.
/// Earlier live messages may wait for the affected group's older backlog.
const LIVE_HELD_AT_MOST: Duration = Duration::from_secs(60);
const UPGRADE_MESSAGES: usize = 2_000;
const BEFORE_UPGRADE: Duration = Duration::from_secs(60);
/// Past every member's push join window: two minutes it could fetch, which
/// the worker counts every 15 seconds, plus the 15 seconds it watches a
/// catch-up settle. Each member announces once when its window ends.
const JOIN_ANNOUNCES: Duration = Duration::from_secs(3 * 60);
/// No group message on the relay for this long: none is still going out.
const GROUP_QUIET: Duration = Duration::from_secs(15);
const COUNTED_MESSAGES: usize = 30;
const FENCE_STALL: Duration = Duration::from_secs(12);
const FENCE_RELEASE: Duration = Duration::from_secs(30);
/// Both endpoints stall history in the fence proof, so a nonempty phase's
/// group is stranded: its live message waits for the runner's next attempt
/// once history returns, 30 seconds after an unreachable one.
const STRANDED_RELEASE: Duration = Duration::from_secs(60);

/// The frozen comparison driver sets this only for the signed old-owner
/// control. Missing runner evidence never selects control behavior by itself:
/// default/new-owner runs must still obtain every positive runner verdict.
fn old_owner_control() -> bool {
    std::env::var("MDK_RECOVERY_PROOF_CONTROL").as_deref() == Ok("old-owner")
}

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

/// Wait until every one of `payloads` that `sender` sent to `group` is on
/// the relay. A send returns once the app accepts it, and it may still be
/// queued; a member that comes online while a backlog's tail is still going
/// out takes that tail as live input ahead of the older history.
async fn wait_published(
    subject: &AppRuntimeHarness,
    group: &GroupId,
    sender: &str,
    payloads: &[String],
    limit: Duration,
) -> TestResult {
    let probe = subject.probe(sender)?;
    let wanted = payloads.iter().map(String::as_str).collect::<BTreeSet<_>>();
    wait_for(
        &format!("{sender}'s backlog published"),
        limit,
        async || {
            let ids = probe
                .chat_message_ids(group)
                .await?
                .into_iter()
                .filter(|(text, _)| wanted.contains(text.as_str()))
                .map(|(_, id)| id)
                .collect::<Vec<_>>();
            if ids.len() != wanted.len() {
                return Ok(false);
            }
            let sources = probe.message_sources(group, ids).await?;
            let published = subject
                .relay_publication_ids()
                .await?
                .into_iter()
                .filter(|(_, kind)| *kind == 445)
                .map(|(id, _)| id)
                .collect::<BTreeSet<_>>();
            Ok(sources
                .iter()
                .all(|source| source.as_ref().is_some_and(|id| published.contains(id))))
        },
    )
    .await
}

/// [`wait_published`] for every lane [`publish`] sent.
async fn wait_lanes_published(
    subject: &AppRuntimeHarness,
    group: &GroupId,
    prefix: &str,
    count: usize,
    limit: Duration,
) -> TestResult {
    for (lane, sender) in SENDERS.iter().enumerate() {
        let payloads = (lane..count)
            .step_by(SENDERS.len())
            .map(|index| format!("{prefix}{index:05}"))
            .collect::<Vec<_>>();
        wait_published(subject, group, sender, &payloads, limit).await?;
    }
    Ok(())
}

/// How many group messages the relay holds.
async fn group_messages(subject: &AppRuntimeHarness) -> TestResult<usize> {
    let ids = subject.relay_publication_ids().await?;
    Ok(ids.into_iter().filter(|(_, kind)| *kind == 445).count())
}

/// Wait until no group message has reached the relay for [`GROUP_QUIET`],
/// returning how many it holds.
async fn wait_group_quiet(subject: &AppRuntimeHarness, limit: Duration) -> TestResult<usize> {
    let deadline = Instant::now() + limit;
    let (mut held, mut since) = (group_messages(subject).await?, Instant::now());
    while since.elapsed() < GROUP_QUIET {
        if Instant::now() >= deadline {
            return Err("timed out waiting for group traffic to go quiet".into());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
        let now = group_messages(subject).await?;
        if now != held {
            (held, since) = (now, Instant::now());
        }
    }
    Ok(held)
}

fn payloads(sent: &[Sent]) -> Vec<String> {
    sent.iter().map(|sent| sent.payload.clone()).collect()
}

/// Each endpoint's next connection index: every connection from here on is
/// newer, whoever opens it.
async fn next_sessions(subject: &AppRuntimeHarness) -> TestResult<Vec<u64>> {
    let traffic = subject.relay_traffic(&[u64::MAX, u64::MAX], false).await?;
    Ok(traffic.iter().map(|relay| relay.next_session).collect())
}

/// Bob's wire cost per endpoint over his own connections from `sessions` on.
async fn bob_traffic(
    subject: &AppRuntimeHarness,
    sessions: &[u64],
) -> TestResult<Vec<ConnectionTrafficV1>> {
    Ok(subject.client_traffic("bob", sessions).await?)
}

/// `later` less `earlier`, both read over the same connections.
fn traffic_delta(
    later: &[ConnectionTrafficV1],
    earlier: &[ConnectionTrafficV1],
) -> Vec<ConnectionTrafficV1> {
    let minus = |later: &BTreeMap<String, u64>, earlier: &BTreeMap<String, u64>| {
        later
            .iter()
            .map(|(path, value)| {
                let before = earlier.get(path).copied().unwrap_or(0);
                (path.clone(), value.saturating_sub(before))
            })
            .collect()
    };
    later
        .iter()
        .zip(earlier)
        .map(|(later, earlier)| ConnectionTrafficV1 {
            upstream_bytes: later.upstream_bytes.saturating_sub(earlier.upstream_bytes),
            downstream_bytes: later
                .downstream_bytes
                .saturating_sub(earlier.downstream_bytes),
            event_frames: minus(&later.event_frames, &earlier.event_frames),
            event_bytes: minus(&later.event_bytes, &earlier.event_bytes),
        })
        .collect()
}

/// The `REQ` shapes that fetch history; the rest replay a live subscription.
const HISTORY_PATHS: [&str; 3] = ["ids", "window", "paged_window"];

/// Report-only bandwidth: per endpoint and summed, bytes each way, every
/// relay-to-Bob `EVENT` frame and its bytes, and the history-request share.
/// The same fields in both owners' runs make the comparison.
fn bandwidth_view(traffic: &[ConnectionTrafficV1]) -> Value {
    let sum = |map: &BTreeMap<String, u64>, history: bool| {
        map.iter()
            .filter(|(path, _)| !history || HISTORY_PATHS.contains(&path.as_str()))
            .map(|(_, value)| value)
            .sum::<u64>()
    };
    let view = |traffic: &ConnectionTrafficV1| {
        json!({
            "downstream_bytes": traffic.downstream_bytes,
            "upstream_bytes": traffic.upstream_bytes,
            "event_frames": sum(&traffic.event_frames, false),
            "event_bytes": sum(&traffic.event_bytes, false),
            "history_event_frames": sum(&traffic.event_frames, true),
            "history_event_bytes": sum(&traffic.event_bytes, true),
            "event_frames_by_path": traffic.event_frames,
        })
    };
    let mut total = ConnectionTrafficV1::default();
    for endpoint in traffic {
        total.upstream_bytes += endpoint.upstream_bytes;
        total.downstream_bytes += endpoint.downstream_bytes;
        for (path, frames) in &endpoint.event_frames {
            *total.event_frames.entry(path.clone()).or_default() += frames;
        }
        for (path, bytes) in &endpoint.event_bytes {
            *total.event_bytes.entry(path.clone()).or_default() += bytes;
        }
    }
    json!({
        "per_endpoint": traffic.iter().map(view).collect::<Vec<_>>(),
        "total": view(&total),
    })
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
            if matches!(
                method,
                Some("quantum" | "recheck" | "conversion" | "attempt_started")
            ) {
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
            // Opt-in logs for the in-process subject, for example
            // `MDK_PROOF_TRACE=marmot_app::recovery_runner=debug`. Other
            // participants run in their own processes and are not traced.
            // The filter is taken as given: a broad one such as `debug` also
            // prints dependencies' records, which may name the loopback
            // relays and keys of this run.
            let logs = std::env::var("MDK_PROOF_TRACE").ok().map(|filter| {
                tracing_subscriber::fmt::layer()
                    .with_ansi(false)
                    .with_writer(std::io::stderr)
                    .with_filter(tracing_subscriber::EnvFilter::new(filter))
            });
            tracing_subscriber::registry()
                .with(capture)
                .with(logs)
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

    /// Conversion rows captured before the first attempt in this phase.
    pub(super) fn conversion_before_first_attempt(from: u64) -> Vec<Value> {
        let events = EVENTS.lock().expect("runner trace lock");
        events
            .iter()
            .filter(|event| event["at_ms"].as_u64() >= Some(from))
            .take_while(|event| {
                !matches!(
                    event["method"].as_str(),
                    Some("attempt_started" | "quantum" | "recheck")
                )
            })
            .filter(|event| event["method"] == "conversion")
            .cloned()
            .collect()
    }

    pub(super) fn first_attempt_started(from: u64) -> Option<Value> {
        EVENTS
            .lock()
            .expect("runner trace lock")
            .iter()
            .find(|event| {
                event["at_ms"].as_u64() >= Some(from) && event["method"] == "attempt_started"
            })
            .cloned()
    }

    /// Every event captured at or after `from` on the trace clock.
    pub(super) fn since(from: u64) -> Vec<Value> {
        let events = EVENTS.lock().expect("runner trace lock");
        let after = events
            .iter()
            .filter(|event| event["at_ms"].as_u64() >= Some(from))
            .filter(|event| matches!(event["method"].as_str(), Some("quantum" | "recheck")));
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

/// Owner capture and autonomous clamp continuation both use window REQs
/// without a limit (ReplayWindow::acquisition_scope -> acquisition_filter).
/// Runner slices and by-id fetches carry limits; live REQs have no `until`.
pub(super) fn native_pages(history: &[Vec<HistoryRequestV1>]) -> Vec<usize> {
    history
        .iter()
        .map(|requests| {
            requests
                .iter()
                .filter(|request| {
                    request.verb == "REQ"
                        && request.until.is_some()
                        && request.ids == 0
                        && request.limit.is_none()
                })
                .count()
        })
        .collect()
}

fn advancing(events: &[Value]) -> usize {
    events
        .iter()
        .filter(|event| event["outcome"] == "advanced")
        .count()
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
    run_proof_with_owner_mode(label, true, journey).await
}

async fn run_proof_with_owner_mode<J>(label: &str, owns: bool, journey: J) -> Value
where
    J: AsyncFnOnce(&mut AppRuntimeHarness, &Path) -> TestResult<Value>,
{
    let artifacts = journey_artifacts(label);
    let clients = clients();
    runner_trace::start().expect("capture the runner's trace");
    let mut subject = if owns {
        AppRuntimeHarness::new_with_relay_pair_owning_debt(&clients, &clients[1..2]).await
    } else {
        AppRuntimeHarness::new_with_relay_pair_owner_mode(&clients, &clients[1..2], false).await
    }
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
    if outcome.is_err() && close_errors.is_empty() {
        subject
            .retain_stopped_diagnostic_fixture(&artifacts.path().join("retained-fixture"))
            .await
            .expect("preserve the closed failure fixture");
    } else {
        drop(subject);
    }
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
#[derive(Clone, Copy)]
enum LoopCase {
    BobBehind,
    BobCurrent,
}

impl LoopCase {
    fn name(self) -> &'static str {
        match self {
            Self::BobBehind => "bob-behind",
            Self::BobCurrent => "bob-current",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::BobBehind => "runner-loop-bob-behind",
            Self::BobCurrent => "runner-loop-bob-current",
        }
    }

    fn matches(self, bob: u64, peers: &BTreeMap<String, u64>) -> bool {
        let Some(first) = peers.values().next() else {
            return false;
        };
        peers.values().all(|epoch| epoch == first)
            && match self {
                Self::BobBehind => *first > bob,
                Self::BobCurrent => *first == bob,
            }
    }
}

async fn loop_epochs(
    subject: &AppRuntimeHarness,
    group: &GroupId,
    members: &[String],
) -> TestResult<BTreeMap<String, u64>> {
    let mut epochs = BTreeMap::new();
    for member in members {
        epochs.insert(member.clone(), subject.probe(member)?.epoch(group).await?);
    }
    Ok(epochs)
}

/// Force the missing-epoch and plain-reconnect cases at public boundaries,
/// without changing the post-join maintenance helper or any production timing.
async fn prepare_loop_case(
    subject: &mut AppRuntimeHarness,
    group: &GroupId,
    members: &[String],
    case: LoopCase,
) -> TestResult<Value> {
    wait_for(
        "all loop members at one epoch",
        Duration::from_secs(600),
        async || {
            let epochs = loop_epochs(subject, group, members).await?;
            Ok(epochs
                .values()
                .all(|epoch| Some(epoch) == epochs.values().next()))
        },
    )
    .await?;
    let before = loop_epochs(subject, group, members).await?;
    // Direct probes do not refresh the harness's cached offline projection.
    // Take the public snapshot that the close will preserve, and use its epoch.
    let stopping = subject.observations(&["bob".to_owned()]).await?;
    let bob = stopping
        .first()
        .ok_or("no bob observation before close")?
        .protocol
        .epoch;
    subject.set_online("bob", false).await?;
    let peers = members
        .iter()
        .filter(|member| *member != "bob")
        .cloned()
        .collect::<Vec<_>>();
    if matches!(case, LoopCase::BobBehind) {
        // The public manual operation schedules the same own-leaf maintenance
        // used by periodic rotation. Its production quiet/jitter windows stand.
        subject
            .self_update(SubjectSelfUpdate {
                action_id: "loop-sender-maintenance",
                client: SENDERS[0],
                pending: "loop-sender-maintenance",
            })
            .await?;
        wait_for(
            "sender maintenance reaches every online member",
            Duration::from_secs(600),
            async || {
                subject.run_due_maintenance(&peers).await?;
                Ok(case.matches(bob, &loop_epochs(subject, group, &peers).await?))
            },
        )
        .await?;
    }
    let after = loop_epochs(subject, group, &peers).await?;
    if !case.matches(bob, &after) {
        return Err(format!(
            "{} setup has wrong epochs: bob={bob}, peers={after:?}",
            case.name()
        )
        .into());
    }
    Ok(json!({
        "requested": case.name(),
        "epochs_before_offline": before,
        "bob_before_stop_epoch": bob,
        "peers_after_stop": after,
        "manual_maintenance_sender": matches!(case, LoopCase::BobBehind).then_some(SENDERS[0]),
    }))
}

pub(super) async fn stalled_relay_loop() {
    stalled_relay_loop_case(LoopCase::BobBehind).await;
}

pub(super) async fn stalled_relay_loop_bob_current() {
    stalled_relay_loop_case(LoopCase::BobCurrent).await;
}

async fn stalled_relay_loop_case(case: LoopCase) {
    let report = run_proof(case.label(), async |subject, out| {
        let started = Instant::now();
        let clients = clients();
        let group = create(subject, "loop", &clients).await?;
        settle_maintenance(subject, &clients, std::slice::from_ref(&group)).await?;
        note(started, "group created and settled");
        // Kept in each app's settings, so bob's reopened runtime records too.
        for member in &clients {
            subject.probe(member)?.start_audit_log().await?;
        }
        let mut epoch_case = prepare_loop_case(subject, &group, &clients, case).await?;
        save(out, "epoch-case.json", &epoch_case)?;
        let sent = publish(subject, &group, "loop-", LOOP_MESSAGES).await?;
        let backlog = payloads(&sent);
        note(started, "backlog published");
        subject.stall_relay_history(1, true).await?;
        let clocks = relay_clocks(subject).await?;
        // Every connection from here on is bob's: the others keep theirs.
        let traffic = subject.relay_traffic(&[u64::MAX, u64::MAX], false).await?;
        let bob_sessions = traffic.iter().map(|relay| relay.next_session).collect::<Vec<_>>();
        // The close captures this last public observation before shutdown.
        // Keep it distinct from the first live read: recovery may already have
        // applied the missing commit before that read returns.
        let stopped = subject.observations(&["bob".to_owned()]).await?;
        let stopped = stopped.first().ok_or("no stopped bob observation")?;
        let visible_backlog = stopped.application.visible_plaintexts.iter()
            .filter(|text| text.starts_with("loop-")).count();
        if stopped.local.online || visible_backlog != 0 {
            return Err("bob must be stopped and owe the entire backlog before reconnect".into());
        }
        let bob_epoch = stopped.protocol.epoch;
        let peers = clients.iter().filter(|member| *member != "bob").cloned().collect::<Vec<_>>();
        let peer_epochs = loop_epochs(subject, &group, &peers).await?;
        if !case.matches(bob_epoch, &peer_epochs) {
            return Err(format!("{} reconnect has wrong epochs: bob={bob_epoch}, peers={peer_epochs:?}", case.name()).into());
        }
        epoch_case["bob_stopped_at_reconnect"] = json!(!stopped.local.online);
        epoch_case["bob_visible_backlog_at_reconnect"] = json!(visible_backlog);
        epoch_case["bob_last_close_observation_epoch"] = json!(bob_epoch);
        epoch_case["peers_at_reconnect"] = json!(peer_epochs);
        save(out, "epoch-case.json", &epoch_case)?;
        let t0 = Instant::now();
        let trace_t0 = runner_trace::now_ms();
        subject.set_online("bob", true).await?;
        let (alice, bob) = (subject.probe("alice")?, subject.probe("bob")?);
        epoch_case["bob_first_live_epoch"] = json!(bob.epoch(&group).await.ok());
        epoch_case["bob_first_live_epoch_read_ms"] = json!(t0.elapsed().as_millis());
        save(out, "epoch-case.json", &epoch_case)?;
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
        epoch_case["epoch_stall_arm_count"] = json!(audit.as_ref().ok().map(|records| {
            audit_rows(records, "epoch_stall_backfill_armed").count()
        }));
        save(out, "epoch-case.json", &epoch_case)?;
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
        // Report-only: Bob's whole window, healthy and stalled endpoints.
        let bandwidth = bob_traffic(subject, &bob_sessions).await;
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
            "epoch_case": epoch_case,
            // Wire observation, kept separate from the aggregate runner trace:
            // bounded by-id group requests, not route identities in tracing.
            "bounded_group_id_fetches": history.iter().map(|requests| {
                requests.iter().filter(|request| request.verb == "REQ"
                    && request.route.as_deref() == Some(route.as_str())
                    && request.until.is_some() && request.ids > 0).count()
            }).collect::<Vec<_>>(),
            "native_paging_requests_per_endpoint": native_pages(&history),
            "backlog": backlog.len(),
            "recovered_seconds": recovered,
            "timeline_exact": complete,
            "timeline": timeline,
            "delivery": delivery.unwrap_or_else(|error| json!({"error": error.to_string()})),
            "bandwidth": bandwidth.map_or_else(|error| json!({"error": error.to_string()}), |traffic| bandwidth_view(&traffic)),
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
        if native_pages(&history).iter().any(|pages| *pages > 0) {
            return Err(format!("native backward paging still ran: {proof}").into());
        }
        if wasted(&runner[0]) == 0 {
            return Err(format!("the runner never attempted stalled work in the first half: {proof}").into());
        }
        if wasted(&runner[1]) > LOOP_SECOND_HALF_ATTEMPTS {
            return Err(format!("the runner kept wasting attempts in the second half: {proof}").into());
        }
        Ok(json!({"proof": proof}))
    })
    .await;
    assert_eq!(report["proof"]["timeline_exact"], true);
}

/// Five thousand events owed in one group, with live traffic every
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
        let control = old_owner_control();
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
        let restart_sessions = next_sessions(subject).await?;
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
        // Visible history and the runner's own surveyed verdict must both
        // finish; neither the initial empty status nor a prior survey proves it.
        let (mut drained, mut reported_caught_up) = (None, None);
        while drained.is_none() || (!control && reported_caught_up.is_none()) {
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
        let restart_traffic = bob_traffic(subject, &restart_sessions).await?;
        let trace_idle = runner_trace::now_ms();
        let restart_trace = trace_between(trace_restart, trace_idle);

        // Record an idle interval; outstanding hybrid debt may still cause
        // requests. This interval has no silence assertion. Status reads are local.
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
        let idle_traffic = traffic_delta(&bob_traffic(subject, &restart_sessions).await?, &restart_traffic);
        let trace_cut = runner_trace::now_ms();
        let idle_trace = trace_between(trace_idle, trace_cut);

        // Reconnect: endpoint 0's live generations end. Their ranges were only
        // provisional, and with no event inside the rebuild lookback every
        // route's new live count is empty, so each is owed again there. The
        // interruption returns once the relay is back; only what follows
        // counts as the reconnect's re-proof.
        let reconnect_clocks = relay_clocks(subject).await?;
        let reconnect_sessions = next_sessions(subject).await?;
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
            Ok(resweep.contains(&busy_route) && resweep.contains(&quiet_route)
                && (control || caught_up(&bob, trace_reconnect).await?))
        };
        let left = RESWEEP_DEADLINE.saturating_sub(reconnected.elapsed());
        let resweep_result = wait_for("the reconnect's re-sweep", left, resweeps).await;
        let resweep_seconds = reconnected.elapsed().as_secs_f64();
        let after_reconnect = history_since(subject, &reconnect_clocks).await?;
        let reconnect_traffic = bob_traffic(subject, &reconnect_sessions).await?;
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
            "old_owner_control": control,
            "backlog_publish_seconds": backlog_seconds,
            "restart": {
                "native_paging_requests_per_endpoint": native_pages(&after_restart),
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
                "bandwidth": bandwidth_view(&restart_traffic),
            },
            "idle": {"seconds": QUIET_AGE.as_secs(), "history": summaries(&idle), "runner": runner_summary(&idle_trace),
                "bandwidth": bandwidth_view(&idle_traffic)},
            "reconnect": {
                "native_paging_requests_per_endpoint": native_pages(&after_reconnect),
                "outage_ms": OUTAGE_MS,
                "resweep": resweep_result.as_ref().map_or_else(|error| json!(error.to_string()), |()| json!("swept")),
                "resweep_seconds": resweep_seconds,
                "routes_swept_on_endpoint_0": resweep.iter().map(|r| labels.get(r).map_or("other", String::as_str)).collect::<Vec<_>>(),
                "quiet_message_visible_ms": quiet_after_reconnect,
                "quiet_timeline_exact": quiet_exact,
                "repeated_window_requests_per_endpoint": reconnect_repeats,
                "history": summaries(&after_reconnect),
                "bandwidth": bandwidth_view(&reconnect_traffic),
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
        // Aggregate runner progress, including inbox comparisons, must cover
        // at least the outage. The route checks above count both owners; this
        // hybrid bound does not attribute group re-proof to the runner alone.
        if advanced_seconds(&reconnect_trace) < OUTAGE_MS / 1000 {
            return failure("the runner re-proved less than the outage after the reconnect");
        }
        if native_pages(&after_restart).into_iter().chain(native_pages(&after_reconnect)).any(|pages| pages > 0) {
            return failure("native backward paging still supplied history");
        }
        if advancing(&restart_trace) < 2 || reported_caught_up.is_none() {
            return failure("the runner did not advance over successive attempts and report caught up");
        }
        if wasted(&restart_trace) > OWED_WASTED_ATTEMPTS {
            return failure("the runner kept ending healthy recovery attempts without progress");
        }
        if reconnect_repeats.iter().any(|repeats| *repeats > 0) {
            return failure("a window was requested twice on one endpoint after reconnect");
        }
        let backlog_and_tail = drained.unwrap_or_default() + LIVE_HELD_AT_MOST.as_secs_f64();
        if live_visibility["max"].as_f64().is_none_or(|ms| ms > backlog_and_tail * 1e3) {
            return failure("live visibility exceeded backlog recovery plus the tail-drain allowance");
        }
        Ok(json!({"proof": proof}))
    })
    .await;
    assert_eq!(report["proof"]["restart"]["busy_timeline_exact"], true);
}

/// Captured three-sender failure: ordinary subscription replay overtook the
/// older recovery input in a 6,000-message backlog. Keep the real wire/MLS/
/// SQLite boundary and prove the resulting timeline survives a full reopen.
pub(super) async fn ordered_backlog_regression() {
    let report = run_proof("runner-ordered-backlog-6000", async |subject, out| {
        let started = Instant::now();
        let clients = clients();
        let group = create(subject, "ordered-backlog", &clients).await?;
        settle_maintenance(subject, &clients, std::slice::from_ref(&group)).await?;
        note(started, "group created and settled");
        let bob = subject.probe("bob")?;
        bob.start_audit_log().await?;
        subject.set_online("bob", false).await?;
        let sent = publish(subject, &group, "owed-", 6_000).await?;
        let mut expected = payloads(&sent);
        save(out, "expected.json", &expected)?;
        note(started, "6,000-message failure backlog published");
        let clocks = relay_clocks(subject).await?;
        let trace_from = runner_trace::now_ms();
        let t0 = Instant::now();
        subject.set_online("bob", true).await?;
        let (alice, bob) = (subject.probe("alice")?, subject.probe("bob")?);
        let live = Live::start(
            alice,
            bob.clone(),
            group.clone(),
            Duration::from_secs(3),
            "live-",
        );
        let recovery = wait_for(
            "all 6,000 older messages visible",
            Duration::from_secs(180),
            async || {
                let (_, chat) = bob.chat_view(&group, None).await?;
                Ok(chat.iter().filter(|text| text.starts_with("owed-")).count() == 6_000)
            },
        )
        .await;
        let recovery_seconds = t0.elapsed().as_secs_f64();
        let (live_sent, visibility) = live.finish().await?;
        expected.extend(live_sent);
        let exact = holds_exactly(&bob, &group, &expected).await?;
        let timeline = timeline_view(&bob, &group, &expected).await?;
        let history = history_since(subject, &clocks).await?;
        save(
            out,
            "history.json",
            &history
                .iter()
                .map(|requests| history_summary(requests, &BTreeMap::new()))
                .collect::<Vec<_>>(),
        )?;
        save(out, "runner-trace.json", &runner_trace::since(trace_from))?;
        save(out, "audit.json", &bob.finish_audit_log().await?)?;
        save(out, "expected.json", &expected)?;
        let proof = json!({"owed_messages": 6_000, "recovery_seconds": recovery_seconds,
            "timeline_exact": exact, "timeline": timeline, "live_visibility_ms": visibility,
            "native_paging_requests_per_endpoint": native_pages(&history)});
        save(out, "before-reopen.json", &proof)?;
        if recovery.is_err() || !exact || !live_complete(&visibility) {
            return Err(format!("ordered backlog lost history: {proof}").into());
        }
        if native_pages(&history).iter().any(|pages| *pages > 0) {
            return Err(
                format!("native paging supplied ordered backlog regression: {proof}").into(),
            );
        }
        subject.set_online("bob", false).await?;
        subject.set_online("bob", true).await?;
        let reopened = subject.probe("bob")?;
        if !holds_exactly(&reopened, &group, &expected).await? {
            return Err(format!("ordered backlog was not durable across reopen: {proof}").into());
        }
        Ok(json!({"proof": proof, "exact_after_reopen": true}))
    })
    .await;
    assert_eq!(report["exact_after_reopen"], true);
}

/// Proof 4, the upgrade end to end: the earlier owner plans the debt and
/// leaves its rows, then bob opens with the runner owning debt, 5g converts
/// those rows before the runner's first start, and the runner alone finishes
/// the debt.
///
/// 5d's fixtures are storage-only (synthetic routes and relays, no account or
/// MLS state), so a runtime cannot open them; 5d's storage tests convert
/// every row kind of both. Here the earlier owner writes its rows the way a
/// nightly build does: bob restarts owing 2,000 events with the gate off
/// while history goes unanswered, so the earlier owner plans the debt and
/// cannot finish it.
pub(super) async fn upgrade() {
    let report = run_proof_with_owner_mode("runner-upgrade", false, async |subject, out| {
        let control = old_owner_control();
        let started = Instant::now();
        let clients = clients();
        let busy = create(subject, "busy", &clients).await?;
        let created = Instant::now();
        settle_maintenance(subject, &clients, std::slice::from_ref(&busy)).await?;
        note(started, "group created and settled");

        // Before the upgrade: the earlier owner plans the debt, against
        // history no endpoint answers. Any group message that reaches it
        // then is live input ahead of that history: once it opens one more
        // than 100 generations past a sender's oldest owed message, that
        // sender's older messages can never be opened, by any owner. The
        // earlier owner takes such input after its page times out, so the
        // fixture lets no group traffic reach it: every member's push
        // announce goes out first, and the whole backlog is on the relay
        // before bob opens.
        tokio::time::sleep(JOIN_ANNOUNCES.saturating_sub(created.elapsed())).await;
        wait_group_quiet(subject, SETTLEMENT).await?;
        note(started, "every member announced");
        subject.set_online("bob", false).await?;
        let mut expected = payloads(&publish(subject, &busy, "owed-", UPGRADE_MESSAGES).await?);
        wait_lanes_published(subject, &busy, "owed-", UPGRADE_MESSAGES, SETTLEMENT).await?;
        let backlog = wait_group_quiet(subject, SETTLEMENT).await?;
        for endpoint in 0..2 {
            subject.stall_relay_history(endpoint, true).await?;
        }
        subject.set_online("bob", true).await?;
        tokio::time::sleep(BEFORE_UPGRADE).await;
        let bob = subject.probe("bob")?;
        let (_, chat) = bob.chat_view(&busy, None).await?;
        let owed_at_upgrade = UPGRADE_MESSAGES.saturating_sub(chat.iter().filter(|text| text.starts_with("owed-")).count());
        subject.set_online("bob", false).await?;
        let reached_earlier_owner = group_messages(subject).await?.saturating_sub(backlog);
        if reached_earlier_owner > 0 {
            return Err(format!(
                "{reached_earlier_owner} group messages reached the earlier owner ahead of its unanswered history"
            )
            .into());
        }
        for endpoint in 0..2 {
            subject.stall_relay_history(endpoint, false).await?;
        }
        note(started, "the earlier owner left its rows");

        // The upgrade: the runner owns the debt from this open on.
        subject.set_runner_owns_debt(true);
        let clocks = relay_clocks(subject).await?;
        let (t0, trace_from) = (Instant::now(), runner_trace::now_ms());
        subject.set_online("bob", true).await?;
        let (alice, bob) = (subject.probe("alice")?, subject.probe("bob")?);
        let live = Live::start(alice, bob.clone(), busy.clone(), Duration::from_secs(3), "live-");
        let (mut drained, mut reported_caught_up) = (None, None);
        while (drained.is_none() || (!control && reported_caught_up.is_none())) && t0.elapsed() < RECOVERY_DEADLINE {
            if drained.is_none() {
                let (_, chat) = bob.chat_view(&busy, None).await?;
                if chat.iter().filter(|text| text.starts_with("owed-")).count() == UPGRADE_MESSAGES {
                    drained = Some(t0.elapsed().as_secs_f64());
                }
            }
            if drained.is_some() && reported_caught_up.is_none() && caught_up(&bob, trace_from).await? {
                reported_caught_up = Some(t0.elapsed().as_secs_f64());
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        let (live_sent, live_visibility) = live.finish().await?;
        expected.extend(live_sent);
        let exact = holds_exactly(&bob, &busy, &expected).await?;
        let (_, chat) = bob.chat_view(&busy, None).await?;
        let owed_visible_at_end = chat.iter().filter(|text| text.starts_with("owed-")).count();
        let history = history_since(subject, &clocks).await?;
        let trace = runner_trace::since(trace_from);
        let capture_pages = native_pages(&history);
        let conversion = runner_trace::conversion_before_first_attempt(trace_from);
        let first_attempt_started = runner_trace::first_attempt_started(trace_from);

        let converted_rows = conversion.iter().map(|row| ["pending", "parked", "dismissed", "settled"]
            .iter().filter_map(|field| row[*field].as_u64()).sum::<u64>()).sum::<u64>();
        let status = bob.account_recovery_status().await?;
        let proof = json!({
            "first_attempt_started": first_attempt_started,
            "conversion_before_first_attempt": conversion,
            "converted_obligations": converted_rows,
            "owed_messages": UPGRADE_MESSAGES,
            "old_owner_control": control,
            "owed_at_upgrade": owed_at_upgrade,
            "owed_visible_seconds": drained,
            "owed_visible_at_end": owed_visible_at_end,
            "runner_caught_up_seconds": reported_caught_up,
            "timeline_exact": exact,
            "live_visibility_ms": live_visibility,
            "native_paging_requests_per_endpoint": capture_pages,
            "runner": runner_summary(&trace),
            "history": history.iter().map(|requests| history_summary(requests, &BTreeMap::new())).collect::<Vec<_>>(),
            "status_at_end": status,
        });
        let labels = BTreeMap::from([(bob.nostr_route(&busy).await?.ok_or("bob holds no busy route")?, "busy".to_owned())]);
        save(out, "history.json", &labeled(&history, &labels))?;
        save(out, "conversion.json", &conversion)?;
        save(out, "runner-trace.json", &trace)?;
        let failure = |what: &str| Err::<Value, _>(format!("{what}: {proof}").into());
        if first_attempt_started.is_none() || converted_rows == 0 {
            return failure("no nonzero conversion was recorded before the first runner attempt");
        }
        if owed_at_upgrade == 0 {
            return failure("nothing was owed at the upgrade, so it proves nothing");
        }
        if drained.is_none() || !exact {
            return failure("the owed group did not finish exactly after the upgrade");
        }
        if !live_complete(&live_visibility) {
            return failure("live messages failed or were lost after the upgrade");
        }
        if reported_caught_up.is_none() {
            return failure("the runner never reported the account caught up");
        }
        if advancing(&trace) == 0 {
            return failure("the runner did not work the converted debt");
        }
        // The rest holds only once 5g converts the rows and turns capture off.
        if capture_pages.iter().any(|pages| *pages > 0) {
            return failure("a native backward pager still supplied history after the upgrade");
        }
        if !status.notices.is_empty() {
            return failure("a converted notice outlived the debt it named");
        }
        Ok(json!({"proof": proof}))
    })
    .await;
    assert_eq!(report["proof"]["timeline_exact"], true);
}

/// Observe the actual packed live reply on Bob's own connections before
/// sending the messages whose hold is measured. No private adapter reads.
async fn packed_live_replies(
    subject: &AppRuntimeHarness,
    clocks: &[u64],
    routes: &[String],
    nonempty: bool,
) -> TestResult<Vec<Value>> {
    let started = Instant::now();
    loop {
        let replies = own_live_replies(subject, clocks)
            .await?
            .into_iter()
            .map(|replies| {
                replies
                    .into_iter()
                    .rev()
                    .find(|reply| routes.iter().all(|route| reply.routes.contains(route)))
                    .map(|reply| {
                        json!({"raw_events": reply.raw_events,
                    "packed_routes": reply.routes.len(), "at_ms": reply.at_ms})
                    })
            })
            .collect::<Option<Vec<_>>>();
        if let Some(replies) = replies {
            if replies.len() != 2
                || replies.iter().any(|reply| {
                    let count = reply["raw_events"].as_u64().unwrap_or(u64::MAX);
                    if nonempty {
                        !(COUNTED_MESSAGES as u64..500).contains(&count)
                    } else {
                        count != 0
                    }
                })
            {
                return Err(format!(
                    "wrong packed live counts for nonempty={nonempty}: {replies:?}"
                )
                .into());
            }
            return Ok(replies);
        }
        if started.elapsed() >= FENCE_RELEASE {
            return Err("no EOSE for Bob's packed group REQ on both endpoints".into());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Bob's packed live group replies through their EOSE that each endpoint
/// logged at or after its clock, oldest first. The other participants share
/// the endpoints, so only connections carrying Bob's inbox and no other
/// participant's count.
async fn own_live_replies(
    subject: &AppRuntimeHarness,
    clocks: &[u64],
) -> TestResult<Vec<Vec<LiveGroupReplyV1>>> {
    let own = subject.account_identity("bob")?.to_owned();
    let others = clients()
        .into_iter()
        .filter(|member| member != "bob")
        .map(|member| subject.account_identity(&member).map(str::to_owned))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let traffic = subject.relay_traffic(&[0, 0], true).await?;
    Ok(traffic
        .into_iter()
        .zip(clocks)
        .map(|(relay, clock)| {
            let owned = |reply: &LiveGroupReplyV1| {
                relay
                    .connection_inboxes
                    .get(&reply.connection)
                    .is_some_and(|inboxes| {
                        inboxes.contains(&own)
                            && inboxes.iter().all(|inbox| !others.contains(inbox))
                    })
            };
            relay
                .live_group_replies
                .iter()
                .filter(|reply| reply.at_ms >= *clock && owned(reply))
                .cloned()
                .collect()
        })
        .collect())
}

async fn watch_live_until(
    bob: &AppRuntimeProbe,
    watched: &[(&GroupId, &str)],
    from: Instant,
    until: Duration,
    seen: &mut BTreeMap<String, f64>,
    expected: &[(&GroupId, &[String])],
) -> TestResult {
    while from.elapsed() < until {
        for (group, payload) in watched {
            if !seen.contains_key(*payload) {
                let (_, chat) = bob.chat_view(group, Some(256)).await?;
                if chat.iter().any(|text| text == payload) {
                    let prior = expected
                        .iter()
                        .find(|(candidate, _)| candidate == group)
                        .ok_or("no expected backlog for watched group")?;
                    if !holds_exactly(bob, group, prior.1).await? {
                        return Err(
                            "live input became visible before its known backlog was exact".into(),
                        );
                    }
                    seen.insert((*payload).to_owned(), from.elapsed().as_secs_f64());
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok(())
}

/// Move Bob's saved cursor past both measured groups the way production
/// does. A restart asks each packed group REQ from that cursor less the
/// rebuild lookback, and only an ingested group event (kind 445) moves it:
/// a Welcome or elapsed time never does. Every group on the same relays
/// shares one REQ, so the reply is empty only when Bob's newest group event
/// belongs to a group he no longer subscribes to. Here Alice removes him
/// from `exit` after the measured groups aged past the lookback; her commit
/// is his newest event, and its route retires with the membership. Bob may
/// park that commit while `exit` is not yet stable (`Buffered`) and still
/// move the cursor past it, so the route retires only once his convergence
/// drain applies it: wait until his live REQs on both endpoints drop it.
async fn advance_fence_fixture_cursor(
    subject: &mut AppRuntimeHarness,
    out: &Path,
    exit: &str,
) -> TestResult {
    let bob = subject.probe("bob")?;
    let exit_route = bob
        .nostr_route(&subject.scenario_group_id(exit)?)
        .await?
        .ok_or("no exit route")?;
    bob.start_audit_log().await?;
    let at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let clocks = relay_clocks(subject).await?;
    let pair = clients()[..2].to_vec();
    subject.select_scenario_group(exit, false)?;
    subject
        .remove_members(SubjectRemoveMembers {
            action_id: "remove-bob-from-exit",
            remover: "alice",
            members: &pair[1..],
            pending: "remove-bob-from-exit",
        })
        .await?;
    subject.tick(&pair).await?;
    let started = Instant::now();
    let mut audit = Vec::new();
    let mut advanced = false;
    loop {
        audit.extend(bob.finish_audit_log().await?);
        advanced = advanced
            || audit.iter().any(|row| {
                row["event"]["type"] == "transport_cursor_advanced"
                    && row["event"]["cursor_after_secs"]
                        .as_u64()
                        .is_some_and(|cursor| cursor >= at)
            });
        let retired = own_live_replies(subject, &clocks)
            .await?
            .iter()
            .all(|replies| {
                replies
                    .last()
                    .is_some_and(|reply| !reply.routes.contains(&exit_route))
            });
        if advanced && retired {
            save(out, "empty-cursor-audit.json", &audit)?;
            return Ok(());
        }
        if started.elapsed() >= SETTLEMENT {
            save(out, "empty-cursor-audit.json", &audit)?;
            return Err(if advanced {
                "Bob's live REQs still carry the group he was removed from"
            } else {
                "the removal commit did not advance Bob's saved transport cursor"
            }
            .into());
        }
        bob.start_audit_log().await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Per-REQ positive and negative controls, with two restarts on the same
/// account. A nonempty reply may hold newer input while its backlog is
/// active, also while every source has left the frontier. Whenever live
/// input becomes visible its known backlog must already be exact. A
/// genuinely empty packed reply must not hold either group's live input.
pub(super) async fn fence_control() {
    let report = run_proof("runner-fence-control", async |subject, out| {
        let started = Instant::now();
        let pair = clients()[..2].to_vec();
        let counted = create(subject, "counted", &pair).await?;
        let quiet = create(subject, "quiet", &pair).await?;
        let groups = [counted.clone(), quiet.clone()];
        settle_maintenance(subject, &pair, &groups).await?;
        let (alice, bob) = (subject.probe("alice")?, subject.probe("bob")?);
        let routes = [bob.nostr_route(&counted).await?.ok_or("no counted route")?,
            bob.nostr_route(&quiet).await?.ok_or("no quiet route")?];
        let labels = BTreeMap::from([(routes[0].clone(), "counted".into()),
            (routes[1].clone(), "quiet".into())]);
        let mut counted_expected = Vec::new();
        let mut quiet_expected = vec!["quiet-early".to_owned()];
        send(&alice, &quiet, "quiet-early").await?;
        wait_for("quiet seed visible", SETTLEMENT, async ||
            holds_exactly(&bob, &quiet, &quiet_expected).await).await?;
        let mut phases = Vec::new();
        let mut errors = Vec::new();
        for nonempty in [true, false] {
            settle_maintenance(subject, &pair, &groups).await?;
            if !nonempty {
                // Join a third group, age the two measured groups past the
                // rebuild lookback, then leave Bob's newest group event in
                // that third group as Alice removes him from it.
                let exit = create(subject, "exit", &pair).await?;
                settle_maintenance(subject, &pair, std::slice::from_ref(&exit)).await?;
                tokio::time::sleep(QUIET_AGE).await;
                advance_fence_fixture_cursor(subject, out, "exit").await?;
                subject.select_scenario_group("counted", false)?;
            }
            subject.set_online("bob", false).await?;
            if nonempty {
                for index in 0..COUNTED_MESSAGES {
                    let payload = format!("counted-{index:03}");
                    send(&alice, &counted, &payload).await?;
                    counted_expected.push(payload);
                }
                // Establish the real relay backlog before restarting Bob,
                // rather than sleeping until the sender happens to finish
                // its initial catch-up.
                wait_published(subject, &counted, "alice", &counted_expected, QUIET_AGE + FENCE_RELEASE).await?;
            }
            for endpoint in 0..2 { subject.stall_relay_history(endpoint, true).await?; }
            let clocks = relay_clocks(subject).await?;
            let trace_from = runner_trace::now_ms();
            subject.set_online("bob", true).await?;
            let bob = subject.probe("bob")?;
            let replies = packed_live_replies(subject, &clocks, &routes, nonempty).await?;
            let ready = Instant::now();
            let suffix = if nonempty { "counted" } else { "empty" };
            let counted_live = format!("counted-live-{suffix}");
            let quiet_live = format!("quiet-live-{suffix}");
            send(&alice, &counted, &counted_live).await?;
            send(&alice, &quiet, &quiet_live).await?;
            counted_expected.push(counted_live.clone());
            quiet_expected.push(quiet_live.clone());
            let watched = [(&counted, counted_live.as_str()), (&quiet, quiet_live.as_str())];
            let mut seen = BTreeMap::new();
            let expected = [(&counted, counted_expected.as_slice()), (&quiet, quiet_expected.as_slice())];
            watch_live_until(&bob, &watched, ready, FENCE_STALL, &mut seen, &expected).await?;
            let during = seen.clone();
            for endpoint in 0..2 { subject.stall_relay_history(endpoint, false).await?; }
            watch_live_until(&bob, &watched, ready, STRANDED_RELEASE, &mut seen, &expected).await?;
            let exact = wait_for("both fence timelines exact", Duration::from_secs(120), async || {
                Ok(holds_exactly(&bob, &counted, &counted_expected).await?
                    && holds_exactly(&bob, &quiet, &quiet_expected).await?)
            }).await;
            let history = history_since(subject, &clocks).await?;
            let trace = runner_trace::since(trace_from);
            let phase = json!({"nonempty": nonempty, "live_replies": replies,
                "stall_seconds": FENCE_STALL.as_secs(), "release_bound_seconds": STRANDED_RELEASE.as_secs(),
                "seen_during_stall_seconds": during, "live_visibility_seconds": seen,
                "known_backlog_exact_at_first_live": seen.len() == 2,
                "timelines_exact": exact.is_ok(),
                "counted_timeline": timeline_view(&bob, &counted, &counted_expected).await?,
                "quiet_timeline": timeline_view(&bob, &quiet, &quiet_expected).await?,
                "native_paging_requests_per_endpoint": native_pages(&history),
                "runner": runner_summary(&trace), "status_at_end": bob.account_recovery_status().await?});
            save(out, &format!("{suffix}-phase.json"), &phase)?;
            save(out, &format!("{suffix}-history.json"), &labeled(&history, &labels))?;
            save(out, &format!("{suffix}-runner-trace.json"), &trace)?;
            phases.push(phase);
            if exact.is_err() {
                return Err(format!("fence timelines lost or repeated history: {}", json!({"phases": phases})).into());
            }
            if !nonempty && during.len() != 2 { errors.push("empty REQ held a group's live message"); }
            if seen.len() != 2 { errors.push("a hold outlived its release bound"); }
            if native_pages(&history).iter().any(|pages| *pages > 0) {
                errors.push("native backward paging supplied the fence proof");
            }
            note(started, &format!("{suffix} REQ phase complete"));
        }
        let proof = json!({"phases": phases, "errors": errors});
        if !errors.is_empty() { return Err(format!("fence contract failed: {proof}").into()); }
        Ok(json!({"proof": proof}))
    }).await;
    assert_eq!(report["proof"]["phases"].as_array().unwrap().len(), 2);
}

/// Every relay stalls history while Bob owes a large backlog and its senders
/// go on talking. With no relay left to serve the group, its live messages
/// wait: opened ahead of the backlog, they would put most of it past the
/// ratchet's out-of-order window for good. Once history returns, the whole
/// backlog shows before any live message, and the timeline is exact.
pub(super) async fn stranded_history() {
    const OWED: usize = 1_500;
    /// Long enough for the runner to find both endpoints unreachable.
    const BEFORE_LIVE: Duration = Duration::from_secs(30);
    const LIVE_STALL: Duration = Duration::from_secs(30);
    /// After history returns: the runner's next attempt, which may wait out
    /// a first relay cooldown, and the sweep.
    const RECOVERY: Duration = Duration::from_secs(5 * 60);
    let report = run_proof("runner-stranded-history", async |subject, out| {
        let started = Instant::now();
        let clients = clients();
        let busy = create(subject, "busy", &clients).await?;
        let created = Instant::now();
        settle_maintenance(subject, &clients, std::slice::from_ref(&busy)).await?;
        tokio::time::sleep(JOIN_ANNOUNCES.saturating_sub(created.elapsed())).await;
        wait_group_quiet(subject, SETTLEMENT).await?;
        note(started, "every member announced");
        subject.set_online("bob", false).await?;
        let mut expected = payloads(&publish(subject, &busy, "owed-", OWED).await?);
        wait_lanes_published(subject, &busy, "owed-", OWED, SETTLEMENT).await?;
        wait_group_quiet(subject, SETTLEMENT).await?;
        for endpoint in 0..2 {
            subject.stall_relay_history(endpoint, true).await?;
        }
        let clocks = relay_clocks(subject).await?;
        let trace_from = runner_trace::now_ms();
        subject.set_online("bob", true).await?;
        let bob = subject.probe("bob")?;
        let route = bob.nostr_route(&busy).await?.ok_or("no busy route")?;
        note(started, "bob online against stalled history");
        tokio::time::sleep(BEFORE_LIVE).await;
        let live = SENDERS.map(|sender| format!("live-{sender}"));
        for (sender, payload) in SENDERS.iter().zip(&live) {
            send(&subject.probe(sender)?, &busy, payload).await?;
        }
        expected.extend(live.iter().cloned());
        let mut sorted = expected.clone();
        sorted.sort();
        let ready = Instant::now();
        let mut owed_at_unstall = None;
        // When a live message first showed, and how many owed ones had.
        let mut first_live = None;
        let exact_after = loop {
            let (_, mut chat) = bob.chat_view(&busy, None).await?;
            let owed = chat.iter().filter(|text| text.starts_with("owed-")).count();
            if first_live.is_none() && chat.iter().any(|text| live.contains(text)) {
                first_live = Some((ready.elapsed().as_secs_f64(), owed));
            }
            if owed_at_unstall.is_none() && ready.elapsed() >= LIVE_STALL {
                owed_at_unstall = Some(owed);
                for endpoint in 0..2 {
                    subject.stall_relay_history(endpoint, false).await?;
                }
                note(started, "history answered again");
            }
            chat.sort();
            if owed_at_unstall.is_some() && chat == sorted {
                break Some(ready.elapsed().as_secs_f64());
            }
            if ready.elapsed() >= LIVE_STALL + RECOVERY {
                break None;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        };
        let trace = runner_trace::since(trace_from);
        let history = history_since(subject, &clocks).await?;
        save(out, "runner-trace.json", &trace)?;
        let labels = BTreeMap::from([(route, "busy".to_owned())]);
        save(out, "history.json", &labeled(&history, &labels))?;
        let native = native_pages(&history);
        let proof = json!({
            "owed": OWED,
            "native_paging_requests_per_endpoint": native,
            "live_stall_seconds": LIVE_STALL.as_secs(),
            "first_live": first_live.map(|(seconds, owed)| json!({
                "seconds": seconds,
                "owed_visible": owed,
            })),
            "owed_visible_at_unstall": owed_at_unstall,
            "exact_after_seconds": exact_after,
            "timeline": timeline_view(&bob, &busy, &expected).await?,
            "runner": runner_summary(&trace),
        });
        if first_live.is_some_and(|(_, owed)| owed < OWED) {
            return Err(format!("live input showed ahead of its backlog: {proof}").into());
        }
        if exact_after.is_none() {
            return Err(format!("timeline not exact after history returned: {proof}").into());
        }
        if native.iter().any(|pages| *pages > 0) {
            return Err(format!("native backward paging supplied the proof: {proof}").into());
        }
        Ok(json!({"proof": proof}))
    })
    .await;
    assert!(report["proof"]["exact_after_seconds"].is_number());
}
