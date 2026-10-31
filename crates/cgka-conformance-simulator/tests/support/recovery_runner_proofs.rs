//! Recovery-runner proofs (mdk#2660 phase 4, PR 5f) under production policy,
//! through public runtime APIs and the relay's wire only. Bob runs in this
//! process with his recovery runner owning history debt; the relay and every
//! other participant run in their own processes. Both relay endpoints share
//! one store and publish the production NIP-11 document.
//!
//! Until the gate flips (5g), the earlier recovery owner still runs beside
//! the runner. Every bound here holds for both owners together, so it only
//! tightens once the runner works alone.

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
    let mut windows = BTreeMap::<(&str, Option<u64>, Option<u64>, Option<u64>), u64>::new();
    for request in requests {
        *by_verb.entry(&request.verb).or_default() += 1;
        let route = request.route.as_deref().unwrap_or("none");
        let label = labels.get(route).map_or("other", String::as_str);
        *by_route.entry(label).or_default() += 1;
        if request.verb == "REQ" && request.ids == 0 {
            let window = (label, request.since, request.until, request.limit);
            *windows.entry(window).or_default() += 1;
        }
    }
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

/// Sweep windows on `route` asked more than once on one endpoint.
fn repeated_windows(requests: &[HistoryRequestV1], route: &str) -> u64 {
    let mut windows = BTreeMap::<(Option<u64>, Option<u64>, Option<u64>), u64>::new();
    let sweeps = requests.iter().filter(|request| {
        request.verb == "REQ" && request.ids == 0 && request.route.as_deref() == Some(route)
    });
    for request in sweeps {
        *windows
            .entry((request.since, request.until, request.limit))
            .or_default() += 1;
    }
    windows.values().map(|count| count - 1).sum()
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
async fn run_proof<J>(label: &str, journey: J) -> Value
where
    J: AsyncFnOnce(&mut AppRuntimeHarness, &Path) -> TestResult<Value>,
{
    let artifacts = journey_artifacts(label);
    let clients = clients();
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
        subject.set_online("bob", false).await?;
        let backlog = publish(subject, &group, "loop-", LOOP_MESSAGES).await?;
        note(started, "backlog published");
        subject.stall_relay_history(1, true).await?;
        let clocks = relay_clocks(subject).await?;
        let t0 = Instant::now();
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
            "history": history.iter().map(|requests| history_summary(requests, &labels)).collect::<Vec<_>>(),
            "status_at_end": status,
        });
        save(out, "history.json", &history)?;
        if !complete || recovered.is_none() {
            return Err("the backlog did not recover exactly from the healthy endpoint".into());
        }
        if live_visibility["not_visible"] != 0 {
            return Err("live messages stopped arriving behind the stalled relay".into());
        }
        // 0.14.0 attempted about twice a minute for as long as it ran.
        if per_minute(half, clocks[1] + window_ms) > 0.5 {
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
///   quiet group's, whose live range is empty. Live messages to the quiet
///   group are never held behind it.
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
        let mut expected = publish(subject, &busy, "owed-", OWED_MESSAGES).await?;
        let backlog_seconds = backlog_started.elapsed().as_secs_f64();
        note(started, "backlog published");

        // Restart: every route owes its gap since its last durable proof.
        let restart_clocks = relay_clocks(subject).await?;
        let t0 = Instant::now();
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

        // Idle: nothing is owed, so nothing is fetched.
        let idle_clocks = relay_clocks(subject).await?;
        tokio::time::sleep(QUIET_AGE).await;
        let idle = history_since(subject, &idle_clocks).await?;

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
        let resweeps = async || {
            let history = history_since(subject, &reconnect_clocks).await?;
            resweep = history[0].iter().filter_map(|request| request.route.clone()).collect();
            Ok(resweep.contains(&busy_route) && resweep.contains(&quiet_route) && caught_up(&bob).await?)
        };
        let resweep_result = wait_for("the reconnect's re-sweep", RESWEEP_DEADLINE, resweeps).await;
        let resweep_seconds = reconnected.elapsed().as_secs_f64();
        let after_reconnect = history_since(subject, &reconnect_clocks).await?;
        let quiet_exact = holds_exactly(&bob, &quiet, &quiet_expected).await?;
        let status = bob.account_recovery_status().await?;
        let summaries = |history: &[Vec<HistoryRequestV1>]| {
            history.iter().map(|requests| history_summary(requests, &labels)).collect::<Vec<_>>()
        };
        let swept = |history: &[Vec<HistoryRequestV1>], route: &str| {
            history.iter().map(|requests| requests.iter().any(|r| r.route.as_deref() == Some(route))).collect::<Vec<_>>()
        };
        let repeats = after_restart.iter().map(|requests| repeated_windows(requests, &busy_route)).collect::<Vec<_>>();
        let busy_bursts = after_restart
            .iter()
            .map(|requests| bursts(requests.iter().filter(|r| r.route.as_deref() == Some(busy_route.as_str()))).len())
            .collect::<Vec<_>>();
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
                "busy_repeated_window_requests": repeats,
                "busy_bursts": busy_bursts,
                "history": summaries(&after_restart),
            },
            "idle": {"seconds": QUIET_AGE.as_secs(), "history": summaries(&idle)},
            "reconnect": {
                "outage_ms": OUTAGE_MS,
                "resweep": resweep_result.as_ref().map_or_else(|error| json!(error.to_string()), |()| json!("swept")),
                "resweep_seconds": resweep_seconds,
                "routes_swept_on_endpoint_0": resweep.iter().map(|r| labels.get(r).map_or("other", String::as_str)).collect::<Vec<_>>(),
                "quiet_message_visible_ms": quiet_after_reconnect,
                "quiet_timeline_exact": quiet_exact,
                "history": summaries(&after_reconnect),
            },
            "status_at_end": status,
        });
        save(out, "history.json", &json!({"restart": after_restart, "idle": idle, "reconnect": after_reconnect}))?;
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
        if repeats.iter().any(|repeats| *repeats > 0) {
            return failure("a sweep window was requested twice on one endpoint");
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
        Ok(json!({"proof": proof}))
    })
    .await;
    assert_eq!(report["proof"]["restart"]["busy_timeline_exact"], true);
}
