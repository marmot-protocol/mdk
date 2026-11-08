//! Report-only recovery scorecard for the #1945 large-account workload.
//! Production policy and public runtime APIs only, so recovery internals can
//! change underneath it. Only recovery correctness is asserted; latency,
//! traffic and attempt proxies are recorded to compare versions.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use cgka_conformance_simulator::app_runtime::{
    ConnectionTrafficV1, RelayDeliveryPath, RelayTrafficV1,
};
use cgka_conformance_simulator::{
    AppRuntimeHarness, AppRuntimeProbe, ConvergenceSubject, ScenarioMessageSelectorV2,
    SubjectCreateGroup, SubjectError, SubjectSendApplication, SubjectUpdateGroupData,
};
use cgka_traits::GroupId;
use serde_json::{Value, json};

use super::recovery_runner_proofs::{history_summary, notices_view, unix_ms};
use super::{SETTLEMENT, TestResult, journey_artifacts, save};

const LARGE_GROUP_MEMBERS: usize = 51;
/// Alice's groups and retained chat messages. With 32 history groups this is
/// 36 groups and about 11,000 kind-445 events, all held by bob.
const GROUPS: [(&str, usize); 4] = [
    ("large", 1_000),
    ("gap", GAP_MESSAGES),
    ("live", 120),
    ("send", 120),
];
const GAP_MESSAGES: usize = 800;
const HISTORY_GROUPS: usize = 32;
const HISTORY_MESSAGES: usize = 280;
/// History groups belong to these senders, so bob is the only large account.
const HISTORY_SENDERS: [&str; 4] = ["s1", "s2", "s3", "s4"];
const LATER_MESSAGES: usize = 40;
const BATCH: usize = 200;
const MIN_MEASURED: Duration = Duration::from_secs(120);
const RECOVERY_DEADLINE: Duration = Duration::from_secs(600);
const IDLE_WINDOW: Duration = Duration::from_secs(60);
const WATCHDOG: Duration = Duration::from_secs(2_700);
const GAP_NAME: &str = "gap commit applied";
/// marmot-app's `APP_RUNTIME_RELAY_REBUILD_LOOKBACK` (ledger A7): a restart
/// re-subscribes this far below its cursor, by design.
const REBUILD_LOOKBACK_SECS: u64 = 120;
/// How far bob's cursor may trail the moment he stops.
const CURSOR_TRAIL_SECS: u64 = 60;

struct Workload {
    groups: BTreeMap<String, GroupId>,
    /// Relay events admitted before the measured restart, except the gap commit.
    held: BTreeSet<String>,
    commit: String,
    /// Events created at or after this second are inside the restart's
    /// rebuild lookback.
    lookback_from: u64,
    summary: Value,
}

/// (group label, chat messages, creator and sender).
fn plan() -> Vec<(String, usize, &'static str)> {
    let history = (0..HISTORY_GROUPS).map(|i| {
        let sender = HISTORY_SENDERS[i % HISTORY_SENDERS.len()];
        (format!("history-{i:02}"), HISTORY_MESSAGES, sender)
    });
    let fixed = GROUPS
        .iter()
        .map(|(label, count)| ((*label).to_owned(), *count, "alice"));
    fixed.chain(history).collect()
}

fn clients() -> Vec<String> {
    let members = (1..LARGE_GROUP_MEMBERS - 1).map(|index| format!("m{index:02}"));
    let named = ["alice", "bob"].into_iter().chain(HISTORY_SENDERS);
    named.map(String::from).chain(members).collect()
}

/// Setup progress, kept for the report so a failed setup shows its last phase.
static PROGRESS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

fn note(started: Instant, what: &str) {
    let line = format!("+{:.0}s {what}", started.elapsed().as_secs_f64());
    eprintln!("scorecard {line}");
    PROGRESS.lock().expect("progress lock").push(line);
}

fn since(t0: Instant, at: Instant) -> f64 {
    at.duration_since(t0).as_secs_f64()
}

async fn wait_for(what: &str, limit: Duration, mut done: impl AsyncFnMut() -> bool) -> TestResult {
    let deadline = Instant::now() + limit;
    while !done().await {
        if Instant::now() >= deadline {
            return Err(format!("scorecard setup timed out waiting for {what}").into());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    Ok(())
}

async fn chat_count(bob: &AppRuntimeProbe, group: &GroupId, prefix: &str) -> usize {
    let view = bob.chat_view(group, None).await;
    view.map_or(0, |(_, chat)| {
        chat.iter().filter(|t| t.starts_with(prefix)).count()
    })
}

async fn next_sessions(subject: &AppRuntimeHarness) -> TestResult<Vec<u64>> {
    let traffic = subject.relay_traffic(&[u64::MAX, u64::MAX], false).await?;
    Ok(traffic.iter().map(|relay| relay.next_session).collect())
}

/// Setup sends ride out a sender whose account worker is reconnecting. A
/// `transport_closed` send is repeated only if the sender's own timeline
/// lacks it; repeats are counted in the report, since the measured phase
/// reports its own send failures instead.
async fn send_once(
    sender: &AppRuntimeProbe,
    group: &GroupId,
    payload: &str,
    retries: &mut u64,
) -> TestResult {
    // Longer than the notification consumer's 30-second restart backoff.
    for _ in 0..20 {
        match sender.send_message(group, payload).await {
            Ok(_) => return Ok(()),
            Err(error) if error.message.ends_with("transport_closed") => {
                *retries += 1;
                tokio::time::sleep(Duration::from_secs(2)).await;
                if chat_count(sender, group, payload).await > 0 {
                    return Ok(());
                }
            }
            Err(error) => return Err(format!("sending {payload}: {error}").into()),
        }
    }
    Err(format!("sending {payload}: transport_closed for 40 seconds").into())
}

/// Like [`send_once`], through a named scenario action in the active group.
async fn send_action_once(
    subject: &mut AppRuntimeHarness,
    sender: &AppRuntimeProbe,
    group: &GroupId,
    payload: &str,
    retries: &mut u64,
) -> TestResult {
    for _ in 0..20 {
        let action = SubjectSendApplication {
            action_id: payload,
            sender: "alice",
            payload,
        };
        match subject.send_application(action).await {
            Ok(()) => return Ok(()),
            Err(error) if error.message.ends_with("transport_closed") => {
                *retries += 1;
                tokio::time::sleep(Duration::from_secs(2)).await;
                if chat_count(sender, group, payload).await > 0 {
                    return Err(format!(
                        "sending {payload}: published without its action id after a refusal"
                    )
                    .into());
                }
            }
            Err(error) => return Err(format!("sending {payload}: {error}").into()),
        }
    }
    Err(format!("sending {payload}: transport_closed for 40 seconds").into())
}

async fn setup(subject: &mut AppRuntimeHarness, clients: &[String]) -> TestResult<Workload> {
    let started = Instant::now();
    let bob_only = vec!["bob".to_owned()];
    let large_invitees = std::iter::once("bob".to_owned())
        .chain(clients.iter().filter(|c| c.starts_with('m')).cloned())
        .collect::<Vec<_>>();
    let mut groups = BTreeMap::new();
    for (label, _, creator) in plan() {
        // The large group's other invitees only publish KeyPackages; bob alone joins.
        let invitees = if label == "large" {
            &large_invitees
        } else {
            &bob_only
        };
        let (action, pair) = (
            format!("create-{label}"),
            vec![creator.to_owned(), "bob".to_owned()],
        );
        subject.select_scenario_group(&label, true)?;
        let create = SubjectCreateGroup {
            action_id: &action,
            creator,
            name: &label,
            invitees,
            required_features: &[],
            initial_admins: &pair[..1],
            pending: &action,
        };
        subject.create_group(create).await?;
        subject.tick(&pair).await?;
        subject
            .await_observable_settlement(&pair, SETTLEMENT)
            .await?;
        groups.insert(label.clone(), subject.scenario_group_id(&label)?);
        if label == "large" {
            for member in &large_invitees[1..] {
                subject.set_online(member, false).await?;
            }
        }
    }
    note(started, "36 groups created");
    let bob = subject.probe("bob")?;
    // Bob's post-join rotations publish commits and re-subscribe; land them
    // while history is small, and before the gap so none can fork its commit.
    // A rotation can wait out the 5-minute EOSE timeout, grace, quiet window
    // and jitter (about 7 minutes) when its history subscription was replaced.
    let mut open = BTreeMap::<String, usize>::new();
    let settled = async || {
        open.clear();
        for group in groups.values() {
            match bob.open_maintenance(group).await {
                Ok(phases) => phases
                    .into_iter()
                    .for_each(|p| *open.entry(p).or_default() += 1),
                Err(error) => *open.entry(error.code).or_default() += 1,
            }
        }
        open.is_empty()
    };
    let waited = wait_for("post-join maintenance", Duration::from_secs(600), settled).await;
    waited.map_err(|error| format!("{error}; open obligation phases: {open:?}"))?;
    note(started, "post-join maintenance settled");
    let mut send_retries = 0;
    for (label, count, sender) in plan() {
        let (group, prefix, sender) =
            (&groups[&label], format!("{label}-"), subject.probe(sender)?);
        for start in (0..count).step_by(BATCH) {
            let end = (start + BATCH).min(count);
            for index in start..end {
                let payload = format!("{label}-{index:05}");
                send_once(&sender, group, &payload, &mut send_retries).await?;
            }
            // Bound the backlog so live delivery, not recovery, retains history.
            let retained = async || chat_count(&bob, group, &prefix).await >= end;
            wait_for(
                &format!("{label} history"),
                Duration::from_secs(300),
                retained,
            )
            .await?;
        }
        note(started, &format!("{label}: {count} messages retained"));
    }
    let gap = groups["gap"].clone();
    let history_seconds = started.elapsed().as_secs_f64();

    // The gap: bob misses one commit, then retains the messages that need it.
    // Hiding an event needs every participant offline; the history senders
    // stay offline from here on.
    for sender in HISTORY_SENDERS {
        subject.set_online(sender, false).await?;
    }
    subject.set_online("bob", false).await?;
    subject.select_scenario_group("gap", false)?;
    let before = subject.relay_admitted_events().await?;
    let commit_action = SubjectUpdateGroupData {
        action_id: "gap-commit",
        client: "alice",
        name: Some(GAP_NAME),
        description: None,
        pending: "gap-commit",
    };
    subject.update_group_data(commit_action).await?;
    let after = subject.relay_admitted_events().await?;
    let selector = ScenarioMessageSelectorV2 {
        action_id: Some("gap-commit".into()),
        ..Default::default()
    };
    subject.set_online("alice", false).await?;
    subject.set_relay_event_visibility("relay:shared", &selector, &[], false)?;
    subject.set_online("alice", true).await?;
    // Named actions, so the relay can withhold them from the measured phase.
    let alice = subject.probe("alice")?;
    for index in 0..LATER_MESSAGES {
        let payload = format!("gap-later-{index:02}");
        send_action_once(subject, &alice, &gap, &payload, &mut send_retries).await?;
    }
    let published = subject.relay_publication_ids().await?;
    let group_events = |range: std::ops::Range<usize>| {
        let events = published[range].iter().filter(|(_, kind)| *kind == 445);
        events.map(|(id, _)| id.clone()).collect::<Vec<_>>()
    };
    let [commit] = <[String; 1]>::try_from(group_events(before..after))
        .map_err(|events| format!("gap commit published {} group events", events.len()))?;
    let later = group_events(after..published.len());
    if later.len() != LATER_MESSAGES {
        return Err(format!("{} later group events were published", later.len()).into());
    }
    let mark = next_sessions(subject).await?;
    subject.set_online("bob", true).await?;
    // The startup catch-up normally suffices; the wire check below decides.
    let catch_up_error = subject.catch_up(&bob_only).await.err();
    let received = async || {
        let traffic = subject.relay_traffic(&mark, true).await;
        traffic.is_ok_and(|traffic| {
            let seen = delivered(&traffic);
            later.iter().all(|id| seen.contains(id.as_str()))
        })
    };
    wait_for(
        "later messages on the wire",
        Duration::from_secs(120),
        received,
    )
    .await?;
    tokio::time::sleep(Duration::from_secs(5)).await;
    subject.set_online("bob", false).await?;
    let stopped_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let lookback_from = stopped_at.saturating_sub(REBUILD_LOOKBACK_SECS + CURSOR_TRAIL_SECS);
    // The relays keep withholding the later messages for the rest of the run,
    // so the final timeline can only come from what bob retained. The relay
    // changes presence only while every participant is offline.
    subject.set_online("alice", false).await?;
    for index in 0..LATER_MESSAGES {
        let later = ScenarioMessageSelectorV2 {
            action_id: Some(format!("gap-later-{index:02}")),
            ..Default::default()
        };
        subject.set_relay_event_visibility("relay:shared", &later, &[], false)?;
    }
    subject.set_relay_event_visibility("relay:shared", &selector, &[], true)?;
    subject.set_online("alice", true).await?;
    note(
        started,
        "gap commit restored; later messages withheld; bob stopped",
    );
    // Held history: every group event bob retained before the measured restart.
    let published = subject.relay_publication_ids().await?;
    let held = published
        .iter()
        .filter(|(id, kind)| *kind == 445 && *id != commit);
    let held = held.map(|(id, _)| id.clone()).collect::<BTreeSet<_>>();
    let summary = json!({
        "groups": groups.len(),
        "large_group_members": LARGE_GROUP_MEMBERS,
        "chat_messages": plan().iter().map(|(_, count, _)| count).sum::<usize>() + LATER_MESSAGES,
        "history_senders": HISTORY_SENDERS.len(),
        "later_messages_needing_missing_commit": LATER_MESSAGES,
        "kind445_events_held_before_restart": held.len(),
        "relay_events_admitted_before_restart": published.len(),
        "setup_send_retries_after_transport_closed": send_retries,
        "setup_explicit_catch_up_error": catch_up_error.map(|error| error.to_string()),
        "setup_seconds": {"history": history_seconds, "total": started.elapsed().as_secs_f64()},
    });
    Ok(Workload {
        groups,
        held,
        commit,
        lookback_from,
        summary,
    })
}

/// Event ids either endpoint delivered.
fn delivered(traffic: &[RelayTrafficV1]) -> BTreeSet<&str> {
    let ids = traffic.iter().flat_map(|relay| relay.events.keys());
    ids.map(String::as_str).collect()
}

/// Bytes both ways and relay-to-client EVENT frames.
fn totals(relay: &RelayTrafficV1) -> (u64, u64) {
    let frames = relay.downstream_messages.get("EVENT").copied().unwrap_or(0);
    (relay.upstream_bytes + relay.downstream_bytes, frames)
}

/// Connections, bytes, verbs and close sides of one endpoint.
fn wire_totals(relay: &RelayTrafficV1) -> Value {
    let mut totals = serde_json::to_value(relay).unwrap_or_default();
    if let Some(fields) = totals.as_object_mut() {
        fields.remove("events");
        fields.remove("history_requests");
        fields.remove("connection_inboxes");
        fields.remove("now_ms");
    }
    totals
}

/// Wire totals plus EVENT frames split into held history, novel events and the
/// missing commit, and counted per event kind.
fn summarize(relay: &RelayTrafficV1, workload: &Workload) -> Value {
    let (mut held, mut held_bytes, mut novel, mut repeats) = (0, 0, 0, 0);
    let mut held_beyond_lookback = 0;
    let mut by_kind = BTreeMap::<u16, u64>::new();
    for (id, delivery) in &relay.events {
        repeats += delivery.count - 1;
        *by_kind.entry(delivery.kind).or_default() += delivery.count;
        if workload.held.contains(id) {
            (held, held_bytes) = (held + delivery.count, held_bytes + delivery.bytes);
            if delivery.created_at < workload.lookback_from {
                held_beyond_lookback += delivery.count;
            }
        } else if *id != workload.commit {
            novel += delivery.count;
        }
    }
    let mut summary = wire_totals(relay);
    summary["event_frames"] = json!(totals(relay).1);
    summary["held_history_frames"] = json!(held);
    summary["held_history_bytes"] = json!(held_bytes);
    summary["held_history_frames_beyond_lookback"] = json!(held_beyond_lookback);
    let commit = relay.events.get(&workload.commit);
    summary["missing_commit_frames"] = json!(commit.map_or(0, |delivery| delivery.count));
    // Inside the lookback the restart's replay also carries the commit.
    summary["missing_commit_in_lookback"] =
        json!(commit.is_some_and(|delivery| delivery.created_at >= workload.lookback_from));
    summary["novel_frames"] = json!(novel);
    summary["same_relay_repeat_frames"] = json!(repeats);
    summary["event_frames_by_kind"] = json!(by_kind);
    summary["download_split"] = download_split(relay, workload);
    summary
}

/// Every copy of an event this endpoint sent after bob's restart, by cause,
/// so amplification reads apart from what bob had to fetch. Copies count per
/// endpoint; events both endpoints sent are `events_delivered_by_both_relays`.
///
/// - first fetch: the first copy of an event bob did not hold;
/// - reconnect amplification: a held event's first copy through a live or
///   maintenance subscription (the restart's rebuild-lookback replay), and
///   every further copy such a subscription, or one never seen, brought;
/// - retry amplification: every further copy a history request (ids, window
///   or paged window) brought, which that endpoint had already sent;
/// - fallback amplification: a held event's first copy through a history
///   request, fetched rather than proved by comparison.
///
/// Copies are counted exactly; bytes are apportioned. The relay records one
/// byte total per event, so a copy's bytes are its event's bytes over its
/// copies (copies differ only by subscription id), the remainder on the
/// first, and the four sum to the per-event totals by construction. Those
/// totals are checked against the connections' own per-path EVENT counts,
/// kept frame by frame: `matches_wire_totals` fails if the per-event record
/// missed a frame, and `unknown_path_frames` counts copies through a
/// subscription bob never asked for, which no cause can name.
fn download_split(relay: &RelayTrafficV1, workload: &Workload) -> Value {
    const CAUSES: [&str; 4] = [
        "first_fetch",
        "reconnect_amplification",
        "retry_amplification",
        "fallback_amplification",
    ];
    let (first_fetch, reconnect, retry, fallback) = (0, 1, 2, 3);
    let mut causes = [(0_u64, 0_u64); 4];
    let (mut frames, mut bytes) = (0, 0);
    for (id, delivery) in relay
        .events
        .iter()
        .filter(|(_, delivery)| delivery.count > 0)
    {
        (frames, bytes) = (frames + delivery.count, bytes + delivery.bytes);
        let copy = delivery.bytes / delivery.count;
        let repeats = delivery.count - 1;
        let first_by_history = matches!(
            delivery.first,
            Some((
                RelayDeliveryPath::Ids | RelayDeliveryPath::Window | RelayDeliveryPath::PagedWindow,
                _
            ))
        );
        let first = match (workload.held.contains(id), first_by_history) {
            (false, _) => first_fetch,
            (true, false) => reconnect,
            (true, true) => fallback,
        };
        causes[first].0 += 1;
        causes[first].1 += delivery.bytes - copy * repeats;
        let by_history = delivery.via_ids + delivery.via_window + delivery.via_paged_window;
        let retried = by_history
            .saturating_sub(u64::from(first_by_history))
            .min(repeats);
        causes[retry].0 += retried;
        causes[retry].1 += copy * retried;
        causes[reconnect].0 += repeats - retried;
        causes[reconnect].1 += copy * (repeats - retried);
    }
    let summed = causes
        .iter()
        .fold((0, 0), |(f, b), (frames, bytes)| (f + frames, b + bytes));
    let mut split = serde_json::Map::new();
    for (cause, (frames, bytes)) in CAUSES.iter().zip(causes) {
        split.insert(
            (*cause).to_owned(),
            json!({"frames": frames, "bytes": bytes}),
        );
    }
    split.insert("total".into(), json!({"frames": frames, "bytes": bytes}));
    split.insert("sums_to_total".into(), json!(summed == (frames, bytes)));
    let wire = relay
        .connection_traffic
        .values()
        .fold((0, 0), |(f, b), traffic| {
            (
                f + traffic.event_frames.values().sum::<u64>(),
                b + traffic.event_bytes.values().sum::<u64>(),
            )
        });
    split.insert("matches_wire_totals".into(), json!(wire == (frames, bytes)));
    let unknown = relay.connection_traffic.values();
    let unknown = unknown.filter_map(|traffic| traffic.event_frames.get("unknown"));
    split.insert("unknown_path_frames".into(), json!(unknown.sum::<u64>()));
    Value::Object(split)
}

/// EVENT frames and bytes over bob's own connections on one endpoint, beside
/// the per-event split, which counts every connection opened after the
/// restart.
fn own_events(traffic: &ConnectionTrafficV1) -> Value {
    json!({
        "frames": traffic.event_frames.values().sum::<u64>(),
        "bytes": traffic.event_bytes.values().sum::<u64>(),
    })
}

/// An account recovery status in counts, without group or notice ids, for
/// printed and saved reports.
pub(super) fn status_summary(status: &marmot_app::AccountRecoveryStatus) -> Value {
    let mut notices = BTreeMap::<String, usize>::new();
    for notice in &status.notices {
        let cause = serde_json::to_value(notice.cause).ok();
        let cause = cause.as_ref().and_then(Value::as_str).unwrap_or("unknown");
        *notices.entry(cause.to_owned()).or_default() += 1;
    }
    json!({
        "catching_up_groups": status.catching_up_group_ids_hex.len(),
        "inbox_catching_up": status.inbox_catching_up,
        "notices_by_cause": notices,
    })
}

/// Nearest-rank percentiles of millisecond samples.
pub(super) fn percentiles(samples: impl IntoIterator<Item = f64>) -> Value {
    let mut sorted = samples.into_iter().collect::<Vec<_>>();
    sorted.sort_by(f64::total_cmp);
    // Nearest rank: the smallest sample with at least p% of samples at or
    // below it.
    let rank = |p: usize| {
        let index = (sorted.len() * p).div_ceil(100).checked_sub(1)?;
        sorted.get(index).copied()
    };
    json!({"n": sorted.len(), "p50": rank(50), "p95": rank(95), "max": sorted.last()})
}

/// One probe call: its index, start offset (s), latency (ms) and failure.
#[derive(Clone)]
pub(super) struct Sample {
    index: u64,
    at: f64,
    ms: f64,
    error: Option<String>,
}

/// Call `probe` every `every` until `stop`, recording each call.
pub(super) fn periodic<F, Fut>(
    stop: &Arc<AtomicBool>,
    every: Duration,
    t0: Instant,
    mut probe: F,
) -> tokio::task::JoinHandle<Vec<Sample>>
where
    F: FnMut(u64) -> Fut + Send + 'static,
    Fut: Future<Output = Result<usize, SubjectError>> + Send,
{
    let stop = stop.clone();
    tokio::spawn(async move {
        let mut ticks = tokio::time::interval(every);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut samples = Vec::new();
        for index in 0.. {
            ticks.tick().await;
            if stop.load(Ordering::Relaxed) {
                break;
            }
            let started = Instant::now();
            let error = probe(index).await.err().map(|error| error.message);
            let (at, ms) = (since(t0, started), started.elapsed().as_secs_f64() * 1e3);
            samples.push(Sample {
                index,
                at,
                ms,
                error,
            });
        }
        samples
    })
}

/// Latency percentiles of successful calls, plus failures by kind and the
/// first failure's offset. Failed calls return early, so they are excluded.
pub(super) fn latencies(samples: &[Sample]) -> Value {
    let ok = samples.iter().filter(|sample| sample.error.is_none());
    let mut summary = percentiles(ok.map(|sample| sample.ms));
    let mut errors = BTreeMap::<&str, u64>::new();
    for error in samples.iter().filter_map(|sample| sample.error.as_deref()) {
        *errors.entry(error).or_default() += 1;
    }
    let first_error = samples.iter().find(|sample| sample.error.is_some());
    summary["calls"] = json!(samples.len());
    summary["errors"] = json!(errors);
    summary["first_error_at_seconds"] = json!(first_error.map(|sample| sample.at));
    summary
}

/// [`latencies`] of the calls that started within `[from, to]`, in seconds
/// on the probe's own clock.
pub(super) fn latencies_within(samples: &[Sample], from: f64, to: f64) -> Value {
    let inside = samples
        .iter()
        .filter(|sample| (from..=to).contains(&sample.at));
    let mut summary = latencies(&inside.cloned().collect::<Vec<_>>());
    summary["window_seconds"] = json!([from, to]);
    summary
}

async fn measure(subject: &mut AppRuntimeHarness, workload: &Workload) -> TestResult<Value> {
    let group = |label: &str| workload.groups[label].clone();
    let (gap, live, send) = (group("gap"), group("live"), group("send"));
    let mark = next_sessions(subject).await?;
    let restart_unix_ms = unix_ms();
    let t0 = Instant::now();
    subject.set_online("bob", true).await?;
    let cold_reopen_ms = t0.elapsed().as_secs_f64() * 1e3;
    let (alice, bob) = (subject.probe("alice")?, subject.probe("bob")?);
    let alice_final = alice.clone();
    let snapshots = subject.performance_snapshots()?;
    let telemetry_before = serde_json::to_value(&snapshots["bob"])?;
    let alice_before = serde_json::to_value(&snapshots["alice"])?;
    let (stop, stop_watch) = (
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicBool::new(false)),
    );
    let status = periodic(&stop, Duration::from_millis(250), t0, {
        let (bob, gap) = (bob.clone(), gap.clone());
        move |_| {
            let (bob, gap) = (bob.clone(), gap.clone());
            async move { bob.group_recovery_status(&gap).await.map(|_| 0) }
        }
    });
    let sends = periodic(&stop, Duration::from_secs(2), t0, {
        let bob = bob.clone();
        move |index| {
            let (bob, send) = (bob.clone(), send.clone());
            async move { bob.send_message(&send, &format!("probe-{index:04}")).await }
        }
    });
    let live_sends = periodic(&stop, Duration::from_secs(1), t0, {
        let live = live.clone();
        move |index| {
            let (alice, live) = (alice.clone(), live.clone());
            async move { alice.send_message(&live, &format!("tick-{index:04}")).await }
        }
    });
    let watcher = tokio::spawn({
        let (bob, stop) = (bob.clone(), stop_watch.clone());
        async move {
            let mut seen = BTreeMap::<u64, f64>::new();
            while !stop.load(Ordering::Relaxed) {
                if let Ok((_, chat)) = bob.chat_view(&live, Some(512)).await {
                    let now = since(t0, Instant::now());
                    for index in chat
                        .iter()
                        .filter_map(|t| t.strip_prefix("tick-")?.parse().ok())
                    {
                        seen.entry(index).or_insert(now);
                    }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            seen
        }
    });
    let (mut applied, mut decrypted) = (None, None);
    loop {
        if let Ok((name, chat)) = bob.chat_view(&gap, Some(2 * LATER_MESSAGES)).await {
            let now = since(t0, Instant::now());
            if applied.is_none() && name.as_deref() == Some(GAP_NAME) {
                applied = Some(now);
            }
            let later = chat.iter().filter(|t| t.starts_with("gap-later-"));
            if decrypted.is_none() && later.collect::<BTreeSet<_>>().len() == LATER_MESSAGES {
                decrypted = Some(now);
            }
        }
        let elapsed = t0.elapsed();
        if (decrypted.is_some() && elapsed >= MIN_MEASURED) || elapsed >= RECOVERY_DEADLINE {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let measured_seconds = t0.elapsed().as_secs_f64();
    stop.store(true, Ordering::Relaxed);
    // Public state at the end of the measured phase, whatever recovery did.
    let recovery_status = bob.group_recovery_status(&gap).await.map(|status| {
        let failed = status.automatic_recovery_failed;
        json!({"automatic_recovery_failed": failed, "rejoin_offers": status.rejoin_invitations.len()})
    });
    let final_state = json!({
        "bob_gap_epoch": bob.epoch(&gap).await.map_err(|error| error.message),
        "alice_gap_epoch": alice_final.epoch(&gap).await.map_err(|error| error.message),
        "bob_gap_recovery_status": recovery_status.map_err(|error| error.message),
    });
    let (status, sends, live_sends) = (status.await?, sends.await?, live_sends.await?);
    // Let the last live messages arrive before judging visibility.
    tokio::time::sleep(Duration::from_secs(5)).await;
    stop_watch.store(true, Ordering::Relaxed);
    let seen = watcher.await?;
    let snapshots = subject.performance_snapshots()?;
    let telemetry_after = serde_json::to_value(&snapshots["bob"])?;
    let alice_after = serde_json::to_value(&snapshots["alice"])?;
    let measured = subject.relay_traffic(&mark, true).await?;
    let own = subject.client_traffic("bob", &mark).await?;
    tokio::time::sleep(IDLE_WINDOW).await;
    let idle_end = subject.relay_traffic(&mark, true).await?;

    let mut labels = BTreeMap::new();
    for (label, group) in &workload.groups {
        if let Some(route) = bob.nostr_route(group).await? {
            labels.insert(route, label.clone());
        }
    }
    // Group labels collapse to their kind, so the report stays short.
    let kinds = labels
        .iter()
        .map(|(route, label)| {
            let kind = if label.starts_with("history-") {
                "history-*"
            } else {
                label
            };
            (route.clone(), kind.to_owned())
        })
        .collect();
    // Bob's own connections only: the others share both endpoints.
    let bobs = subject.client_history_requests("bob", &mark).await?;
    let history_requests = bobs
        .iter()
        .map(|requests| history_summary(requests, &kinds));
    let history_requests = history_requests.collect::<Vec<_>>();
    let account_status = bob.account_recovery_status().await;
    let group_labels = workload
        .groups
        .iter()
        .map(|(label, group)| (hex::encode(group.as_slice()), label.as_str()))
        .collect::<BTreeMap<_, _>>();
    let notices_at_end = account_status
        .as_ref()
        .ok()
        .map(|status| notices_view(status, &group_labels, restart_unix_ms));
    let (_, mut observed) = bob.chat_view(&gap, None).await?;
    let mut expected = (0..GAP_MESSAGES)
        .map(|i| format!("gap-{i:05}"))
        .collect::<Vec<_>>();
    expected.extend((0..LATER_MESSAGES).map(|i| format!("gap-later-{i:02}")));
    observed.sort();
    expected.sort();
    // Visibility counts only live messages whose send succeeded. It runs from
    // the start of alice's send, so a slow send reads as slow visibility;
    // bob's own share runs from the send's return, negative when he saw the
    // message before her call returned.
    let sent = live_sends.iter().filter(|sample| sample.error.is_none());
    let visible = |sample: &Sample| Some((seen.get(&sample.index)? - sample.at) * 1e3);
    let mut live_visibility = percentiles(sent.clone().filter_map(visible));
    let mut after_send = percentiles(
        sent.clone()
            .filter_map(|sample| Some(visible(sample)? - sample.ms)),
    );
    // The slowest messages from the send's start, split into alice's send
    // call and bob's share.
    let mut slowest = sent
        .clone()
        .filter_map(|sample| Some((sample, visible(sample)?)))
        .collect::<Vec<_>>();
    slowest.sort_by(|a, b| b.1.total_cmp(&a.1));
    slowest.truncate(5);
    live_visibility["slowest"] = json!(
        slowest
            .iter()
            .map(|(sample, visible_ms)| json!({
                "sent_at_seconds": sample.at,
                "visible_ms": visible_ms,
                "send_ms": sample.ms,
                "after_send_ms": visible_ms - sample.ms,
            }))
            .collect::<Vec<_>>()
    );
    let not_visible = sent.count() as u64 - live_visibility["n"].as_u64().unwrap_or(0);
    live_visibility["not_visible"] = json!(not_visible);
    live_visibility["sends"] = latencies(&live_sends);
    after_send["not_visible"] = json!(not_visible);
    let first = &measured[0].events;
    let both = measured[1]
        .events
        .keys()
        .filter(|id| first.contains_key(*id));
    let idle = measured.iter().zip(&idle_end).map(|(before, after)| {
        let ((bytes, events), (bytes_after, events_after)) = (totals(before), totals(after));
        json!({"bytes": bytes_after - bytes, "event_frames": events_after - events})
    });
    // Both observations must land within the deadline; a read after it does
    // not count.
    let in_time = |at: Option<f64>| at.is_some_and(|at| at <= RECOVERY_DEADLINE.as_secs_f64());
    let completed = in_time(applied) && in_time(decrypted);
    Ok(json!({
        "cold_reopen_ms": cold_reopen_ms,
        "measured_seconds": measured_seconds,
        "recovery": {
            "completed": completed,
            "commit_applied_seconds": applied,
            "later_messages_decrypted_seconds": decrypted,
            "deadline_seconds": RECOVERY_DEADLINE.as_secs(),
            // Presence, not order: replay order need not match send order.
            "gap_messages_each_once": observed == expected,
        },
        "final_state": final_state,
        "status_command_ms": latencies(&status),
        "send_ms": latencies(&sends),
        "live_visibility_ms": live_visibility,
        "live_visibility_after_send_ms": after_send,
        "relays": measured.iter().zip(&own).map(|(relay, own)| {
            let mut summary = summarize(relay, workload);
            summary["bob_connections_events"] = own_events(own);
            summary
        }).collect::<Vec<_>>(),
        "events_delivered_by_both_relays": both.count(),
        "history_requests": history_requests,
        "native_paging_requests_per_endpoint": super::recovery_runner_proofs::native_pages(&bobs),
        "account_recovery_status_at_end": account_status.as_ref().map(status_summary).map_err(|error| &error.message),
        // Each notice's route and park time, in seconds after bob's restart.
        "notices_at_end": notices_at_end,
        "runner_history_requests_after_restart": bobs.iter().map(Vec::len).sum::<usize>(),
        "idle_window": {"seconds": IDLE_WINDOW.as_secs(), "relays": idle.collect::<Vec<_>>()},
        "telemetry": {"before": telemetry_before, "after": telemetry_after},
        // What alice's runtime did while she sent the live messages, which
        // explains a slow send.
        "alice_runtime_operations": operation_deltas(&alice_before, &alice_after),
    }))
}

/// The #1945 targets, evaluated for the record but not enforced yet.
fn targets(report: &Value) -> Value {
    let p95 = |key: &str| report[key]["p95"].as_f64();
    let under = |key: &str, limit: f64| p95(key).is_some_and(|value| value < limit);
    let total = |list: &Value, field: &str| {
        let values = list.as_array().into_iter().flatten();
        values
            .filter_map(|value| value[field].as_u64())
            .sum::<u64>()
    };
    let held = total(&report["relays"], "held_history_frames_beyond_lookback");
    // Frames beyond the one copy the lookback replay carries.
    let commit_by_relay = report["relays"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|relay| {
            let frames = relay["missing_commit_frames"].as_u64().unwrap_or(0);
            frames.saturating_sub(u64::from(relay["missing_commit_in_lookback"] == true))
        })
        .collect::<Vec<_>>();
    let idle = total(&report["idle_window"]["relays"], "event_frames");
    let visible = report["live_visibility_ms"]["not_visible"] == 0;
    let recovered = report["recovery"]["completed"] == true;
    let failed = |key: &str| {
        let errors = report[key]["errors"].as_object().into_iter().flatten();
        errors.filter_map(|(_, count)| count.as_u64()).sum::<u64>()
    };
    let target = |name: &str, met: bool, observed: Value| json!({"target": name, "met": met, "observed": observed});
    let latency = |key: &str| {
        let observed = json!({"p95": p95(key), "failed_calls": failed(key)});
        (failed(key) == 0 && under(key, 500.0), observed)
    };
    let ((status_met, status), (send_met, send)) =
        (latency("status_command_ms"), latency("send_ms"));
    json!([
        target("status p95 < 500 ms, no failed calls", status_met, status),
        target("send p95 < 500 ms, no failed calls", send_met, send),
        target(
            "live visibility after alice's send returns p95 < 2 s, all visible",
            visible && under("live_visibility_after_send_ms", 2_000.0),
            json!(p95("live_visibility_after_send_ms")),
        ),
        target(
            "no re-download of held history beyond the rebuild lookback",
            held == 0,
            json!(held),
        ),
        target(
            "missing commit fetched at most once per relay beyond the lookback replay",
            recovered && commit_by_relay.iter().all(|frames| *frames <= 1),
            json!(commit_by_relay)
        ),
        target("no EVENT downloads while idle", idle == 0, json!(idle)),
    ])
}

/// Each runtime operation that started, finished or was in flight during
/// the measured phase: its counts' deltas, the time its finished runs took,
/// and what was in flight at either end.
fn operation_deltas(before: &Value, after: &Value) -> Value {
    const COUNTS: [&str; 5] = ["started", "completed", "failures", "timeouts", "cancelled"];
    let operations = |snapshot: &Value| {
        let operations = snapshot["runtime_operations"]
            .as_array()
            .into_iter()
            .flatten();
        operations
            .map(|operation| (operation["operation"].to_string(), operation.clone()))
            .collect::<BTreeMap<_, _>>()
    };
    let before = operations(before);
    let changed = operations(after).into_iter().filter_map(|(name, after)| {
        let earlier = before.get(&name);
        let delta = |field: &str| {
            let was = earlier
                .and_then(|operation| operation[field].as_u64())
                .unwrap_or(0);
            after[field].as_u64().unwrap_or(0).saturating_sub(was)
        };
        let deltas = COUNTS.map(|field| (field, delta(field)));
        let in_flight = after["in_flight"].as_u64().unwrap_or(0);
        let was_in_flight = earlier
            .and_then(|operation| operation["in_flight"].as_u64())
            .unwrap_or(0);
        (deltas.iter().any(|(_, count)| *count > 0) || in_flight + was_in_flight > 0).then(|| {
            let mut row = serde_json::Map::new();
            row.insert("operation".into(), after["operation"].clone());
            for (field, count) in deltas {
                row.insert(field.into(), json!(count));
            }
            row.insert("in_flight_before".into(), json!(was_in_flight));
            row.insert("in_flight_after".into(), json!(in_flight));
            let sum = |operation: &Value| operation["duration_ms"]["sum_ms"].as_u64().unwrap_or(0);
            let was = earlier.map_or(0, sum);
            row.insert(
                "duration_sum_ms".into(),
                json!(sum(&after).saturating_sub(was)),
            );
            Value::Object(row)
        })
    });
    json!(changed.collect::<Vec<_>>())
}

/// Aggregate telemetry deltas over the measured phase. The public API has no
/// recovery-attempt counter; these and upstream REQ/NEG-OPEN counts are proxies.
fn telemetry_deltas(before: &Value, after: &Value) -> Value {
    let read = |snapshot: &Value, name: &str| {
        let mut operations = snapshot["runtime_operations"]
            .as_array()
            .into_iter()
            .flatten();
        let operation = operations.find(|operation| operation["operation"] == name);
        let started = operation.map_or(&snapshot[name]["attempts"], |o| &o["started"]);
        started.as_u64().unwrap_or(0)
    };
    let names = [
        "account_sync",
        "account_catch_up",
        "catch_up_requested",
        "worker_catch_up",
    ];
    let delta = |name: &str| json!(read(after, name).saturating_sub(read(before, name)));
    Value::Object(
        names
            .iter()
            .map(|name| ((*name).to_owned(), delta(name)))
            .collect(),
    )
}

fn print_table(report: &Value) {
    println!("\nlarge-account recovery scorecard (report only; production policy)");
    println!("history owner: {}", report["workload"]["history_owner"]);
    println!(
        "{:<34}{:>9}{:>9}{:>9}{:>7}{:>8}",
        "latency of successful calls (ms)", "p50", "p95", "max", "ok", "failed"
    );
    let live = &report["live_visibility_ms"];
    for (name, row) in [
        (
            "status: group_recovery_status",
            &report["status_command_ms"],
        ),
        ("send: bob, healthy group", &report["send_ms"]),
        ("send: alice, live group", &live["sends"]),
        ("live visibility: from alice's send", live),
        (
            "live visibility: after it returns",
            &report["live_visibility_after_send_ms"],
        ),
    ] {
        let cell = |cell: &str| row[cell].as_f64().map_or("-".into(), |v| format!("{v:.1}"));
        let [p50, p95, max] = ["p50", "p95", "max"].map(cell);
        // Visibility rows count messages never seen as failed.
        let failed = match row.get("not_visible") {
            Some(missing) => missing.to_string(),
            None => row["errors"]
                .as_object()
                .map_or(0, |e| e.values().filter_map(Value::as_u64).sum())
                .to_string(),
        };
        println!(
            "{name:<34}{p50:>9}{p95:>9}{max:>9}{:>7}{failed:>8}",
            row["n"].to_string()
        );
    }
    for key in [
        "cold_reopen_ms",
        "recovery",
        "final_state",
        "events_delivered_by_both_relays",
        "idle_window",
        "history_requests",
        "account_recovery_status_at_end",
    ] {
        println!("{key}: {}", report[key]);
    }
    for key in ["status_command_ms", "send_ms"] {
        println!("{key} errors: {}", report[key]["errors"]);
    }
    for (index, relay) in report["relays"]
        .as_array()
        .into_iter()
        .flatten()
        .enumerate()
    {
        println!("relay-{index}: {relay}");
    }
    println!("telemetry deltas: {}", report["telemetry_deltas"]);
    for target in report["targets"].as_array().into_iter().flatten() {
        let met = if target["met"] == true {
            "met"
        } else {
            "NOT MET"
        };
        println!(
            "target: {} -> {met} ({})",
            target["target"], target["observed"]
        );
    }
}

pub(super) async fn run() {
    // Opt-in tracing for the in-process subject, for example
    // `MDK_SCORECARD_TRACE=marmot_app::relay_plane=warn`. Other participants
    // run in their own processes and are not traced.
    if let Some(filter) = std::env::var_os("MDK_SCORECARD_TRACE") {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter.to_string_lossy().as_ref())
            .with_ansi(false)
            .with_writer(std::io::stderr)
            .try_init();
    }
    let artifacts = journey_artifacts("scorecard");
    let clients = clients();
    let mut subject = AppRuntimeHarness::new_with_relay_pair(&clients, &clients[1..2])
        .await
        .expect("scorecard harness setup");
    save(
        artifacts.path(),
        "execution-layout.json",
        &subject.process_layout(),
    )
    .unwrap();
    let journey = async {
        let workload = setup(&mut subject, &clients).await?;
        let mut report = measure(&mut subject, &workload).await?;
        report["workload"] = workload.summary;
        report["workload"]["layout"] =
            json!("bob in the coordinator process; relay and others in their own processes");
        report["workload"]["relays"] =
            json!("two endpoints of one relay process over one retained store");
        report["workload"]["source_commit"] = json!(std::env::var("GITHUB_SHA").ok());
        report["workload"]["history_owner"] =
            json!("recovery runner; the adapter has no native backward pager");
        let (before, after) = (
            &report["telemetry"]["before"],
            &report["telemetry"]["after"],
        );
        report["telemetry_deltas"] = telemetry_deltas(before, after);
        report["targets"] = targets(&report);
        TestResult::Ok(report)
    };
    let outcome = tokio::time::timeout(WATCHDOG, journey)
        .await
        .unwrap_or_else(|_| {
            Err(format!(
                "scorecard exceeded its {}-second watchdog",
                WATCHDOG.as_secs()
            )
            .into())
        });
    let mut record = outcome
        .as_ref()
        .map_or_else(|error| json!({"error": error.to_string()}), Clone::clone);
    record["progress"] = json!(*PROGRESS.lock().expect("progress lock"));
    let snapshots = subject.performance_snapshots().ok();
    record["bob_telemetry_at_end"] = json!(snapshots.and_then(|mut all| all.remove("bob")));
    // Every connection each endpoint accepted during the run, reconnects included.
    let whole_run = subject
        .relay_traffic(&[0, 0], false)
        .await
        .ok()
        .unwrap_or_default();
    record["relay_whole_run"] = json!(whole_run.iter().map(wire_totals).collect::<Vec<_>>());
    save(artifacts.path(), "scorecard.json", &record).unwrap();
    if let Ok(report) = &outcome {
        print_table(report);
    }
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
    eprintln!("scorecard evidence: {}", artifacts.keep().display());
    let report = outcome.unwrap_or_else(|error| panic!("scorecard did not complete: {error}"));
    assert!(
        close_errors.is_empty(),
        "runtime close failed: {close_errors:?}"
    );
    assert!(
        report["native_paging_requests_per_endpoint"]
            .as_array()
            .unwrap()
            .iter()
            .all(|count| count.as_u64() == Some(0)),
        "a native backward pager supplied the scorecard"
    );
    // Correctness assertions: within the deadline the missing commit is
    // applied and the later messages decrypt, and every gap chat message is
    // present exactly once. Performance targets are only recorded.
    assert_eq!(
        report["recovery"]["completed"], true,
        "gap not recovered in {RECOVERY_DEADLINE:?}"
    );
    assert_eq!(
        report["recovery"]["gap_messages_each_once"], true,
        "gap messages missing or duplicated"
    );
    // The account must end with nothing left to fetch. The status lists
    // nothing until a runner has surveyed, so it counts only after bob's
    // runner asked for history since the restart; it surveys before each
    // attempt and after the last one. A notice in this healthy run is its own
    // failure, named by route and park time.
    assert!(
        report["runner_history_requests_after_restart"].as_u64() > Some(0),
        "bob's runner asked no history after the restart, so his status proves nothing"
    );
    let end = &report["account_recovery_status_at_end"]["Ok"];
    assert!(
        end["catching_up_groups"] == 0 && end["inbox_catching_up"] == false,
        "the scorecard ended with history still catching up: {end}"
    );
    assert!(
        report["notices_at_end"]
            .as_array()
            .is_some_and(Vec::is_empty),
        "a healthy run raised a history notice: {}",
        report["notices_at_end"]
    );
    for relay in report["relays"].as_array().into_iter().flatten() {
        let split = &relay["download_split"];
        assert!(
            split["sums_to_total"] == true
                && split["matches_wire_totals"] == true
                && split["unknown_path_frames"] == 0,
            "the download split must classify every EVENT copy the endpoint sent: {split}"
        );
    }
}

#[test]
fn percentiles_use_the_nearest_rank() {
    let six = percentiles([10.0, 20.0, 30.0, 40.0, 50.0, 342.0]);
    assert_eq!(six["p50"], json!(30.0));
    assert_eq!(
        six["p95"],
        json!(342.0),
        "p95 of six samples is the maximum"
    );
    let one = percentiles([7.0]);
    assert_eq!(
        (one["p50"].clone(), one["p95"].clone()),
        (json!(7.0), json!(7.0))
    );
    let none = percentiles(std::iter::empty());
    assert!(none["p50"].is_null() && none["p95"].is_null());
    let hundred = percentiles((1..=100).map(f64::from));
    assert_eq!(hundred["p95"], json!(95.0));
}
