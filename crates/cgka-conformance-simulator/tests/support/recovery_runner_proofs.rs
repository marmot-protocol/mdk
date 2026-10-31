//! Recovery-runner proofs (mdk#2660 phase 4, PR 5f) under production policy,
//! through public runtime APIs and the relay's wire only. Bob runs in this
//! process with his recovery runner owning history debt; the relay and every
//! other participant run in their own processes. Both relay endpoints share
//! one store and publish the production NIP-11 document.
//!
//! Until the gate flips (5g), the earlier recovery owner still runs beside
//! the runner, and in these runs it does the startup recovery itself. So each
//! journey runs in two modes ([`Owners`]): beside the earlier owner, where the
//! wire bounds count both owners' requests and the runner's own numbers
//! (read from its debug trace) are only recorded; and alone, ignored until
//! 5g, where the runner's bounds and their controls hold too. The fence
//! control and the upgrade likewise wait for 5g's fence wiring and
//! conversion.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use cgka_conformance_simulator::app_runtime::HistoryRequestV1;
use cgka_conformance_simulator::{
    AppRuntimeHarness, AppRuntimeProbe, ConvergenceSubject, SubjectCreateGroup,
};
use cgka_traits::GroupId;
use serde_json::{Value, json};

use super::recovery_scorecard::percentiles;
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
/// stopped cursor may trail, so the quiet group's live range is empty.
const QUIET_AGE: Duration = Duration::from_secs(200);
const RECOVERY_DEADLINE: Duration = Duration::from_secs(30 * 60);
const RESWEEP_DEADLINE: Duration = Duration::from_secs(5 * 60);
const OUTAGE_MS: u64 = 10_000;
const WATCHDOG: Duration = Duration::from_secs(90 * 60);
/// Requests on one endpoint at most this far apart form one burst.
const BURST_GAP_MS: u64 = 2_000;
/// Runner attempts on the stalled relay in the loop's second half. 0.14.0
/// made one about every 30 seconds (a 10-second attempt, then the next about
/// 20 seconds later), about 16 there.
const LOOP_SECOND_HALF_ATTEMPTS: usize = 4;
/// Runner attempts that asked a relay and ended without progress while the
/// owed group drains from two healthy endpoints.
const OWED_WASTED_ATTEMPTS: usize = 4;
/// Bursts of history requests per endpoint while the owed group drains: the
/// wire's view of the attempts, both owners together.
const OWED_BURSTS: usize = 4;
/// The longest a live message may wait with the runner alone: a fence holds
/// for at most one 30-second replay deadline. Beside the earlier owner its
/// capture holds live frames until the whole backlog lands.
const LIVE_HELD_AT_MOST_MS: f64 = 60_000.0;
/// Messages inside the rebuild lookback (120 s) when bob restarts, so the
/// counted group's live count is non-empty and under the 500-event clamp.
const COUNTED_MESSAGES: usize = 30;
/// History stays unanswered on both endpoints this long after the restart:
/// well inside the 30-second replay deadline a fence holds for at most.
const FENCE_STALL: Duration = Duration::from_secs(12);
/// Owed before the upgrade, and how long the earlier owner works on it
/// against stalled history.
const UPGRADE_MESSAGES: usize = 2_000;
const BEFORE_UPGRADE: Duration = Duration::from_secs(60);

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

/// Send once, repeating a `transport_closed` refusal only while the sender's
/// own timeline lacks the message.
async fn send(probe: &AppRuntimeProbe, group: &GroupId, payload: &str) -> Result<(), String> {
    for _ in 0..20 {
        match probe.send_message(group, payload).await {
            Ok(_) => return Ok(()),
            Err(error) if error.message.ends_with("transport_closed") => {
                tokio::time::sleep(Duration::from_secs(2)).await;
                let recent = probe.chat_view(group, Some(1_024)).await;
                let (_, recent) = recent.map_err(|error| error.to_string())?;
                if recent.iter().any(|text| text == payload) {
                    return Ok(());
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
) -> TestResult<Vec<String>> {
    let mut lanes = tokio::task::JoinSet::new();
    for (lane, sender) in SENDERS.iter().enumerate() {
        let (probe, group) = (subject.probe(sender)?, group.clone());
        let payloads = (lane..count)
            .step_by(SENDERS.len())
            .map(|index| format!("{prefix}{index:05}"))
            .collect::<Vec<_>>();
        lanes.spawn(async move {
            for payload in &payloads {
                send(&probe, &group, payload).await?;
            }
            Ok::<_, String>(payloads)
        });
    }
    let mut payloads = Vec::with_capacity(count);
    while let Some(lane) = lanes.join_next().await {
        payloads.extend(lane??);
    }
    Ok(payloads)
}

/// Each endpoint's proxy clock now.
async fn relay_clocks(subject: &AppRuntimeHarness) -> TestResult<Vec<u64>> {
    let traffic = subject.relay_traffic(&[u64::MAX, u64::MAX], false).await?;
    Ok(traffic.iter().map(|relay| relay.now_ms).collect())
}

/// Every history request each endpoint logged at or after its `from` clock.
async fn history_since(
    subject: &AppRuntimeHarness,
    from: &[u64],
) -> TestResult<Vec<Vec<HistoryRequestV1>>> {
    let traffic = subject.relay_traffic(&[0, 0], true).await?;
    Ok(traffic
        .into_iter()
        .zip(from)
        .map(|(relay, from)| {
            let requests = relay.history_requests.into_iter();
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

/// Who works history debt in a run.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Owners {
    /// The runner beside the earlier owner, as until 5g: wire bounds count
    /// both, and the runner's own numbers are recorded only.
    Both,
    /// The runner alone, from 5g: its own bounds and their controls hold too.
    RunnerAlone,
}

impl Owners {
    fn label(self, proof: &str) -> String {
        match self {
            Self::Both => format!("runner-{proof}"),
            Self::RunnerAlone => format!("runner-alone-{proof}"),
        }
    }
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

/// Runner attempts that newly covered part of a unit's debt.
fn advanced(events: &[Value]) -> usize {
    let covered = |event: &&Value| event["newly_covered_seconds"].as_u64() > Some(0);
    let advanced = events.iter().filter(|event| event["outcome"] == "advanced");
    advanced.filter(covered).count()
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
    sends: tokio::task::JoinHandle<Vec<(String, f64, bool)>>,
    watch: tokio::task::JoinHandle<BTreeMap<String, f64>>,
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
        let watch = tokio::spawn({
            let stop = stop_watch.clone();
            async move {
                let mut seen = BTreeMap::new();
                while !stop.load(Ordering::Relaxed) {
                    if let Ok((_, chat)) = bob.chat_view(&group, Some(256)).await {
                        let now = t0.elapsed().as_secs_f64();
                        for text in chat.into_iter().filter(|t| t.starts_with(prefix)) {
                            seen.entry(text).or_insert(now);
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                seen
            }
        });
        Self {
            stop,
            stop_watch,
            sends,
            watch,
        }
    }

    /// Stop sending, let the last sends arrive, and return the payloads that
    /// were sent and their visibility at bob.
    async fn finish(self) -> TestResult<(Vec<String>, Value)> {
        self.stop.store(true, Ordering::Relaxed);
        let sent = self.sends.await?;
        tokio::time::sleep(Duration::from_secs(5)).await;
        self.stop_watch.store(true, Ordering::Relaxed);
        let seen = self.watch.await?;
        let ok = sent.iter().filter(|(_, _, ok)| *ok);
        let visible = ok.clone().filter_map(|(payload, at, _)| {
            seen.get(payload).map(|seen| (seen - at).max(0.0) * 1e3)
        });
        let mut summary = percentiles(visible);
        let sent_ok = ok.clone().count() as u64;
        summary["sends"] = json!(sent.len());
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

/// Whether the runner reports nothing left to fetch.
async fn caught_up(bob: &AppRuntimeProbe) -> TestResult<bool> {
    let status = bob.account_recovery_status().await?;
    Ok(status.catching_up_group_ids_hex.is_empty() && !status.inbox_catching_up)
}

/// Run a proof journey under the watchdog, save its report, close every
/// runtime, and return the report or the journey's error.
/// Run `journey` with bob in this process, his recovery runner owning debt
/// from the start or, without `owning_debt`, only once the journey turns it on.
async fn run_proof<J>(label: &str, owning_debt: bool, journey: J) -> Value
where
    J: AsyncFnOnce(&mut AppRuntimeHarness, &Path) -> TestResult<Value>,
{
    let artifacts = journey_artifacts(label);
    let clients = clients();
    runner_trace::start().expect("capture the runner's trace");
    let subject = if owning_debt {
        AppRuntimeHarness::new_with_relay_pair_owning_debt(&clients, &clients[1..2]).await
    } else {
        AppRuntimeHarness::new_with_relay_pair(&clients, &clients[1..2]).await
    };
    let mut subject = subject.expect("runner proof harness setup");
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
pub(super) async fn stalled_relay_loop(owners: Owners) {
    let report = run_proof(&owners.label("loop"), true, async |subject, out| {
        let started = Instant::now();
        let clients = clients();
        let group = create(subject, "loop", &clients).await?;
        settle_maintenance(subject, &clients, std::slice::from_ref(&group)).await?;
        note(started, "group created and settled");
        subject.set_online("bob", false).await?;
        let backlog = publish(subject, &group, "loop-", LOOP_MESSAGES).await?;
        note(started, "backlog published");
        subject.stall_relay_history(1, true).await?;
        let clocks = relay_clocks(subject).await?;
        let t0 = Instant::now();
        let trace_t0 = runner_trace::now_ms();
        subject.set_online("bob", true).await?;
        let (alice, bob) = (subject.probe("alice")?, subject.probe("bob")?);
        let live = Live::start(alice, bob.clone(), group.clone(), Duration::from_secs(2), "tick-");
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
        let status = bob.account_recovery_status().await?;
        let mut expected = backlog.clone();
        expected.extend(ticks);
        let complete = holds_exactly(&bob, &group, &expected).await?;
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
        let trace_half = trace_t0 + window_ms / 2;
        let runner = [trace_between(trace_t0, trace_half), trace_between(trace_half, trace_t0 + window_ms)];
        let proof = json!({
            "backlog": backlog.len(),
            "recovered_seconds": recovered,
            "timeline_exact": complete,
            "live_visibility_ms": live_visibility,
            "stalled_endpoint_bursts": starts.len(),
            "stalled_bursts_per_minute": {
                "first_half": per_minute(clocks[1], half),
                "second_half": per_minute(half, clocks[1] + window_ms),
            },
            "seconds_between_stalled_bursts": gaps.collect::<Vec<_>>(),
            "runner": {
                "first_half": runner_summary(&runner[0]),
                "second_half": runner_summary(&runner[1]),
                "second_half_wasted": wasted(&runner[1]),
            },
            "history": history.iter().map(|requests| history_summary(requests, &labels)).collect::<Vec<_>>(),
            "status_at_end": status,
        });
        save(out, "history.json", &history)?;
        save(out, "runner-trace.json", &runner_trace::since(trace_t0))?;
        if !complete || recovered.is_none() {
            return Err("the backlog did not recover exactly from the healthy endpoint".into());
        }
        if live_visibility["not_visible"] != 0 {
            return Err("live messages stopped arriving behind the stalled relay".into());
        }
        // The control: something did try the stalled relay.
        if per_minute(clocks[1], half) == 0.0 {
            return Err(format!("nothing attempted the stalled relay: {proof}").into());
        }
        // 0.14.0 attempted about twice a minute for as long as it ran.
        if per_minute(half, clocks[1] + window_ms) > 0.5 {
            return Err(format!("the stalled relay is still attempted every two minutes or more often: {proof}").into());
        }
        if owners == Owners::Both {
            return Ok(json!({"proof": proof}));
        }
        // The control: the runner did try the stalled relay, so the bound
        // below is not met by a runner that never looked at it.
        if wasted(&runner[0]) == 0 {
            return Err(format!("the runner never attempted the stalled relay: {proof}").into());
        }
        if wasted(&runner[1]) > LOOP_SECOND_HALF_ATTEMPTS {
            return Err(format!("the runner keeps attempting the stalled relay: {proof}").into());
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
///   quiet group's, whose live range is empty. Live messages to the quiet
///   group are never held behind it.
pub(super) async fn owed_history(owners: Owners) {
    let report = run_proof(&owners.label("owed-history"), true, async |subject, out| {
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
        let mut expected = publish(subject, &busy, "owed-", OWED_MESSAGES).await?;
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
        let (mut drained, mut reported_caught_up) = (None, None);
        while drained.is_none() || reported_caught_up.is_none() {
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
            if drained.is_some() && reported_caught_up.is_none() && caught_up(&bob).await? {
                reported_caught_up = Some(t0.elapsed().as_secs_f64());
                note(started, "runner reports caught up");
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        let (live_sent, live_visibility) = live.finish().await?;
        expected.extend(live_sent);
        let busy_exact = holds_exactly(&bob, &busy, &expected).await?;
        let after_restart = history_since(subject, &restart_clocks).await?;
        let trace_idle = runner_trace::now_ms();
        let restart_trace = trace_between(trace_restart, trace_idle);

        // Idle: nothing is owed, so nothing is fetched.
        let idle_clocks = relay_clocks(subject).await?;
        tokio::time::sleep(QUIET_AGE).await;
        let idle = history_since(subject, &idle_clocks).await?;
        let trace_reconnect = runner_trace::now_ms();
        let idle_trace = trace_between(trace_idle, trace_reconnect);

        // Reconnect: endpoint 0's live generations end. Their ranges were only
        // provisional, and with no event inside the rebuild lookback every
        // route's new live count is empty, so each is owed again there.
        let reconnect_clocks = relay_clocks(subject).await?;
        subject.interrupt_relay("reconnect", "relay:shared", OUTAGE_MS).await?;
        let quiet_after_reconnect =
            visible_after(&alice, &bob, &quiet, "quiet-after-reconnect", Duration::from_secs(60)).await?;
        quiet_expected.push("quiet-after-reconnect".into());
        let reconnected = Instant::now();
        let mut resweep = BTreeSet::new();
        // Each route asked again on endpoint 0, by either owner.
        let resweeps = async || {
            let history = history_since(subject, &reconnect_clocks).await?;
            resweep = history[0].iter().filter_map(|request| request.route.clone()).collect();
            Ok(resweep.contains(&busy_route) && resweep.contains(&quiet_route) && caught_up(&bob).await?)
        };
        let resweep_result = wait_for("the reconnect's re-sweep", RESWEEP_DEADLINE, resweeps).await;
        let resweep_seconds = reconnected.elapsed().as_secs_f64();
        let after_reconnect = history_since(subject, &reconnect_clocks).await?;
        let reconnect_trace = runner_trace::since(trace_reconnect);
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
                "live_visibility_ms": live_visibility,
                "quiet_message_visible_ms": quiet_after_restart,
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
            },
            "status_at_end": status,
        });
        save(out, "history.json", &json!({"restart": after_restart, "idle": idle, "reconnect": after_reconnect}))?;
        save(out, "runner-trace.json", &runner_trace::since(trace_restart))?;
        let failure = |what: &str| Err::<Value, _>(format!("{what}: {proof}").into());
        if drained.is_none() || !busy_exact {
            return failure("the owed group did not finish exactly within the deadline");
        }
        if reported_caught_up.is_none() {
            return failure("the runner never reported the account caught up");
        }
        if live_visibility["not_visible"] != 0 {
            return failure("live messages were lost while the backlog was owed");
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
        if resweep_result.is_err() {
            return failure("the reconnect's owed ranges were not swept");
        }
        if reconnect_trace.is_empty() {
            return failure("the runner re-proved nothing after the reconnect");
        }
        if owners == Owners::Both {
            return Ok(json!({"proof": proof}));
        }
        // The control: the runner itself worked the owed group over
        // successive attempts, so an idle runner does not meet the bounds.
        if advanced(&restart_trace) < 2 {
            return failure("the runner did not work the debt over successive attempts");
        }
        if wasted(&restart_trace) > OWED_WASTED_ATTEMPTS {
            return failure("the runner's attempts kept ending without progress");
        }
        if reconnect_repeats.iter().any(|repeats| *repeats > 0) {
            return failure("a history window was asked twice on one endpoint after the reconnect");
        }
        if live_visibility["max"].as_f64() > Some(LIVE_HELD_AT_MOST_MS) {
            return failure("a live message waited longer than one fence");
        }
        Ok(json!({"proof": proof}))
    })
    .await;
    assert_eq!(report["proof"]["restart"]["busy_timeline_exact"], true);
}

/// When each payload first showed in bob's timeline, polled until `until`.
async fn watch_until(
    bob: &AppRuntimeProbe,
    watched: &[(&GroupId, &str)],
    from: Instant,
    until: Duration,
) -> TestResult<BTreeMap<String, f64>> {
    let mut seen = BTreeMap::new();
    while from.elapsed() < until {
        for (group, payload) in watched {
            if seen.contains_key(*payload) {
                continue;
            }
            let (_, chat) = bob.chat_view(group, Some(256)).await?;
            if chat.iter().any(|text| text == payload) {
                seen.insert((*payload).to_owned(), from.elapsed().as_secs_f64());
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok(seen)
}

/// Proof 5's positive control: a non-empty admitted live count fences its
/// group's live frames past the range it leaves unproven, while a quiet
/// group's empty count fences nothing. Without it, "never fenced" passes as
/// well with fences that never engage.
///
/// Bob restarts with 30 messages inside the rebuild lookback in one group and
/// none in the other, and history goes unanswered on both endpoints for 12
/// seconds, so nothing can prove the counted range. A live message to each
/// group during the stall: the quiet one must arrive during it, the counted
/// one only after it, and both timelines must end exact.
pub(super) async fn fence_control() {
    let report = run_proof("runner-fence-control", true, async |subject, out| {
        let started = Instant::now();
        let pair = clients()[..2].to_vec();
        let counted = create(subject, "counted", &pair).await?;
        let quiet = create(subject, "quiet", &pair).await?;
        settle_maintenance(subject, &pair, &[counted.clone(), quiet.clone()]).await?;
        let (alice, bob) = (subject.probe("alice")?, subject.probe("bob")?);
        let mut quiet_expected = vec!["quiet-early".to_owned()];
        send(&alice, &quiet, "quiet-early").await?;
        wait_for("quiet history at bob", SETTLEMENT, async || {
            holds_exactly(&bob, &quiet, &quiet_expected).await
        })
        .await?;
        tokio::time::sleep(QUIET_AGE).await;
        note(started, "groups created, quiet group aged");

        subject.set_online("bob", false).await?;
        let mut counted_expected = Vec::new();
        for index in 0..COUNTED_MESSAGES {
            let payload = format!("counted-{index:03}");
            send(&alice, &counted, &payload).await?;
            counted_expected.push(payload);
        }
        for endpoint in 0..2 {
            subject.stall_relay_history(endpoint, true).await?;
        }
        let clocks = relay_clocks(subject).await?;
        let trace_from = runner_trace::now_ms();
        subject.set_online("bob", true).await?;
        let restarted = Instant::now();
        let bob = subject.probe("bob")?;
        tokio::time::sleep(Duration::from_secs(2)).await;
        let sent_at = restarted.elapsed().as_secs_f64();
        send(&alice, &counted, "counted-live").await?;
        send(&alice, &quiet, "quiet-live").await?;
        counted_expected.push("counted-live".into());
        quiet_expected.push("quiet-live".into());
        let watched = [(&counted, "counted-live"), (&quiet, "quiet-live")];
        let during = watch_until(&bob, &watched, restarted, FENCE_STALL).await?;
        let (_, chat) = bob.chat_view(&counted, None).await?;
        let backlog_during = chat.iter().filter(|text| text.starts_with("counted-0")).count();
        for endpoint in 0..2 {
            subject.stall_relay_history(endpoint, false).await?;
        }
        note(started, "history answered again");
        let settled = wait_for("both timelines exact", Duration::from_secs(120), async || {
            Ok(holds_exactly(&bob, &counted, &counted_expected).await?
                && holds_exactly(&bob, &quiet, &quiet_expected).await?)
        })
        .await;
        let after = watch_until(&bob, &watched, restarted, restarted.elapsed()).await?;
        let history = history_since(subject, &clocks).await?;
        let trace = runner_trace::since(trace_from);
        let proof = json!({
            "counted_messages": COUNTED_MESSAGES,
            "stall_seconds": FENCE_STALL.as_secs(),
            "live_sent_at_seconds": sent_at,
            "seen_during_stall_at_seconds": during,
            "seen_by_end_at_seconds": after,
            "counted_backlog_visible_during_stall": backlog_during,
            "timelines_exact": settled.is_ok(),
            "runner": runner_summary(&trace),
            "history": history.iter().map(|requests| history_summary(requests, &BTreeMap::new())).collect::<Vec<_>>(),
            "status_at_end": bob.account_recovery_status().await?,
        });
        save(out, "history.json", &history)?;
        save(out, "runner-trace.json", &trace)?;
        let failure = |what: &str| Err::<Value, _>(format!("{what}: {proof}").into());
        if settled.is_err() {
            return failure("the timelines did not end exact");
        }
        if !during.contains_key("quiet-live") {
            return failure("the quiet group's live message was held behind the stall");
        }
        // The control itself, last: it holds only once 5g wires live fences.
        if during.contains_key("counted-live") {
            return failure("the counted group's live message went ahead of its unproven range");
        }
        Ok(json!({"proof": proof}))
    })
    .await;
    assert_eq!(report["proof"]["timelines_exact"], true);
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
    let report = run_proof("runner-upgrade", false, async |subject, out| {
        let started = Instant::now();
        let clients = clients();
        let busy = create(subject, "busy", &clients).await?;
        settle_maintenance(subject, &clients, std::slice::from_ref(&busy)).await?;
        note(started, "group created and settled");

        // Before the upgrade: the earlier owner plans the debt, against
        // history no endpoint answers.
        subject.set_online("bob", false).await?;
        let mut expected = publish(subject, &busy, "owed-", UPGRADE_MESSAGES).await?;
        for endpoint in 0..2 {
            subject.stall_relay_history(endpoint, true).await?;
        }
        subject.set_online("bob", true).await?;
        tokio::time::sleep(BEFORE_UPGRADE).await;
        let bob = subject.probe("bob")?;
        let (_, chat) = bob.chat_view(&busy, None).await?;
        let owed_at_upgrade = UPGRADE_MESSAGES - chat.iter().filter(|text| text.starts_with("owed-")).count();
        subject.set_online("bob", false).await?;
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
        while (drained.is_none() || reported_caught_up.is_none()) && t0.elapsed() < RECOVERY_DEADLINE {
            if drained.is_none() {
                let (_, chat) = bob.chat_view(&busy, None).await?;
                if chat.iter().filter(|text| text.starts_with("owed-")).count() == UPGRADE_MESSAGES {
                    drained = Some(t0.elapsed().as_secs_f64());
                }
            }
            if drained.is_some() && reported_caught_up.is_none() && caught_up(&bob).await? {
                reported_caught_up = Some(t0.elapsed().as_secs_f64());
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        let (live_sent, live_visibility) = live.finish().await?;
        expected.extend(live_sent);
        let exact = holds_exactly(&bob, &busy, &expected).await?;
        let history = history_since(subject, &clocks).await?;
        let trace = runner_trace::since(trace_from);
        // The earlier owner's capture pages are the only history `REQ`s
        // without a limit; 5g turns capture off.
        let capture_pages = history.iter().map(|requests| {
            let pages = requests.iter().filter(|r| r.verb == "REQ" && r.ids == 0 && r.limit.is_none());
            pages.count()
        });
        let capture_pages = capture_pages.collect::<Vec<_>>();
        let status = bob.account_recovery_status().await?;
        let proof = json!({
            "owed_messages": UPGRADE_MESSAGES,
            "owed_at_upgrade": owed_at_upgrade,
            "owed_visible_seconds": drained,
            "runner_caught_up_seconds": reported_caught_up,
            "timeline_exact": exact,
            "live_visibility_ms": live_visibility,
            "capture_pages_per_endpoint": capture_pages,
            "runner": runner_summary(&trace),
            "history": history.iter().map(|requests| history_summary(requests, &BTreeMap::new())).collect::<Vec<_>>(),
            "status_at_end": status,
        });
        save(out, "history.json", &history)?;
        save(out, "runner-trace.json", &trace)?;
        let failure = |what: &str| Err::<Value, _>(format!("{what}: {proof}").into());
        if owed_at_upgrade == 0 {
            return failure("nothing was owed at the upgrade, so it proves nothing");
        }
        if drained.is_none() || !exact {
            return failure("the owed group did not finish exactly after the upgrade");
        }
        if live_visibility["not_visible"] != 0 {
            return failure("live messages were lost after the upgrade");
        }
        if reported_caught_up.is_none() {
            return failure("the runner never reported the account caught up");
        }
        if advanced(&trace) == 0 {
            return failure("the runner did not work the converted debt");
        }
        // The rest holds only once 5g converts the rows and turns capture off.
        if capture_pages.iter().any(|pages| *pages > 0) {
            return failure("the earlier owner still captured history after the upgrade");
        }
        if !status.notices.is_empty() {
            return failure("a converted notice outlived the debt it named");
        }
        Ok(json!({"proof": proof}))
    })
    .await;
    assert_eq!(report["proof"]["timeline_exact"], true);
}
