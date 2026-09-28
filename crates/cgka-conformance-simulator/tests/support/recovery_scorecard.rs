//! Report-only recovery scorecard for the #1945 large-account workload.
//! Production policy and public runtime APIs only, so recovery internals can
//! change underneath it. Only recovery correctness is asserted; latency,
//! traffic and attempt proxies are recorded to compare versions.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use cgka_conformance_simulator::app_runtime::RelayTrafficV1;
use cgka_conformance_simulator::{
    AppRuntimeHarness, AppRuntimeProbe, ConvergenceSubject, ScenarioMessageSelectorV2,
    SubjectCreateGroup, SubjectError, SubjectSendApplication, SubjectUpdateGroupData,
};
use cgka_traits::GroupId;
use serde_json::{Value, json};

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

struct Workload {
    groups: BTreeMap<String, GroupId>,
    /// Relay events admitted before the measured restart, except the gap commit.
    held: BTreeSet<String>,
    commit: String,
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
    }
    totals
}

/// Wire totals plus EVENT frames split into held history, novel events and the
/// missing commit, and counted per event kind.
fn summarize(relay: &RelayTrafficV1, workload: &Workload) -> Value {
    let (mut held, mut held_bytes, mut novel, mut repeats) = (0, 0, 0, 0);
    let mut by_kind = BTreeMap::<u16, u64>::new();
    for (id, delivery) in &relay.events {
        repeats += delivery.count - 1;
        *by_kind.entry(delivery.kind).or_default() += delivery.count;
        if workload.held.contains(id) {
            (held, held_bytes) = (held + delivery.count, held_bytes + delivery.bytes);
        } else if *id != workload.commit {
            novel += delivery.count;
        }
    }
    let mut summary = wire_totals(relay);
    summary["event_frames"] = json!(totals(relay).1);
    summary["held_history_frames"] = json!(held);
    summary["held_history_bytes"] = json!(held_bytes);
    let commit = relay.events.get(&workload.commit);
    summary["missing_commit_frames"] = json!(commit.map_or(0, |delivery| delivery.count));
    summary["novel_frames"] = json!(novel);
    summary["same_relay_repeat_frames"] = json!(repeats);
    summary["event_frames_by_kind"] = json!(by_kind);
    summary
}

/// Nearest-rank percentiles of millisecond samples.
fn percentiles(samples: impl IntoIterator<Item = f64>) -> Value {
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
struct Sample {
    index: u64,
    at: f64,
    ms: f64,
    error: Option<String>,
}

/// Call `probe` every `every` until `stop`, recording each call.
fn periodic<F, Fut>(
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
fn latencies(samples: &[Sample]) -> Value {
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

async fn measure(subject: &mut AppRuntimeHarness, workload: &Workload) -> TestResult<Value> {
    let group = |label: &str| workload.groups[label].clone();
    let (gap, live, send) = (group("gap"), group("live"), group("send"));
    let mark = next_sessions(subject).await?;
    let t0 = Instant::now();
    subject.set_online("bob", true).await?;
    let cold_reopen_ms = t0.elapsed().as_secs_f64() * 1e3;
    let (alice, bob) = (subject.probe("alice")?, subject.probe("bob")?);
    let alice_final = alice.clone();
    let telemetry_before = serde_json::to_value(&subject.performance_snapshots()?["bob"])?;
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
    let telemetry_after = serde_json::to_value(&subject.performance_snapshots()?["bob"])?;
    let measured = subject.relay_traffic(&mark, true).await?;
    tokio::time::sleep(IDLE_WINDOW).await;
    let idle_end = subject.relay_traffic(&mark, true).await?;

    let (_, mut observed) = bob.chat_view(&gap, None).await?;
    let mut expected = (0..GAP_MESSAGES)
        .map(|i| format!("gap-{i:05}"))
        .collect::<Vec<_>>();
    expected.extend((0..LATER_MESSAGES).map(|i| format!("gap-later-{i:02}")));
    observed.sort();
    expected.sort();
    // Visibility counts only live messages whose send succeeded.
    let sent = live_sends.iter().filter(|sample| sample.error.is_none());
    let visible = sent.clone().filter_map(|sample| {
        let visible = seen.get(&sample.index)?;
        Some((visible - sample.at) * 1e3)
    });
    let mut live_visibility = percentiles(visible);
    let not_visible = sent.count() as u64 - live_visibility["n"].as_u64().unwrap_or(0);
    live_visibility["not_visible"] = json!(not_visible);
    live_visibility["sends"] = latencies(&live_sends);
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
        "relays": measured.iter().map(|relay| summarize(relay, workload)).collect::<Vec<_>>(),
        "events_delivered_by_both_relays": both.count(),
        "idle_window": {"seconds": IDLE_WINDOW.as_secs(), "relays": idle.collect::<Vec<_>>()},
        "telemetry": {"before": telemetry_before, "after": telemetry_after},
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
    let held = total(&report["relays"], "held_history_frames");
    let commit_by_relay = report["relays"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|relay| relay["missing_commit_frames"].as_u64().unwrap_or(0))
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
            "live visibility p95 < 2 s, all visible",
            visible && under("live_visibility_ms", 2_000.0),
            json!(p95("live_visibility_ms")),
        ),
        target("no re-download of held history", held == 0, json!(held)),
        target(
            "missing commit fetched at most once per relay",
            recovered && commit_by_relay.iter().all(|frames| *frames <= 1),
            json!(commit_by_relay)
        ),
        target("no EVENT downloads while idle", idle == 0, json!(idle)),
    ])
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
    println!(
        "{:<34}{:>9}{:>9}{:>9}{:>7}{:>8}",
        "latency of successful calls (ms)", "p50", "p95", "max", "ok", "failed"
    );
    for (name, key) in [
        ("status: group_recovery_status", "status_command_ms"),
        ("send: bob, healthy group", "send_ms"),
        ("live visibility: alice to bob", "live_visibility_ms"),
    ] {
        let row = &report[key];
        let cell = |cell: &str| row[cell].as_f64().map_or("-".into(), |v| format!("{v:.1}"));
        let [p50, p95, max] = ["p50", "p95", "max"].map(cell);
        let failed = match key {
            "live_visibility_ms" => row["not_visible"].to_string(),
            _ => row["errors"]
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
    // The only hard assertions: within the deadline the missing commit is
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
