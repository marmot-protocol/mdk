//! Relay health's inbox check through a running app against loopback relays:
//! what each relay's answer makes its row, which warnings and events follow,
//! and that the check runs beside the account worker.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio::sync::{Notify, broadcast};
use tokio::time::timeout;
use tokio_tungstenite::{accept_async, tungstenite::Message};

use crate::{
    MarmotAppEvent, RelayHealthFault, RelayHealthState, RelayWarningKind, RelayWarningSeverity,
};

/// How a [`scripted_relay`] answers.
#[derive(Clone, Copy)]
enum Script {
    /// Close every REQ as `ERROR: auth-required:`, challenge, and refuse
    /// every AUTH.
    RefusesAuth,
    /// Close every REQ as `rate-limited:`.
    RateLimited,
    /// Never answer the inbox check's REQ (kind 1059, limit 1); answer any
    /// other REQ with EOSE.
    HoldsCheck,
}

/// A loopback relay running `script` on every connection.
struct Scripted {
    url: String,
    /// Inbox-check REQs it saw.
    checks: Arc<AtomicUsize>,
    /// Notified at each inbox-check REQ.
    checked: Arc<Notify>,
    /// Connections that carried an inbox check and have closed.
    probes_closed: Arc<AtomicUsize>,
    /// Notified as each of those closes.
    probe_closed: Arc<Notify>,
    /// Aborting it drops every connection, which ends a held check.
    server: tokio::task::JoinHandle<()>,
}

async fn scripted_relay(script: Script) -> Scripted {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let checks = Arc::new(AtomicUsize::new(0));
    let checked = Arc::new(Notify::new());
    let probes_closed = Arc::new(AtomicUsize::new(0));
    let probe_closed = Arc::new(Notify::new());
    let server = tokio::spawn({
        let (checks, checked) = (checks.clone(), checked.clone());
        let (probes_closed, probe_closed) = (probes_closed.clone(), probe_closed.clone());
        async move {
            let mut connections = tokio::task::JoinSet::new();
            while let Ok((stream, _)) = listener.accept().await {
                let (checks, checked) = (checks.clone(), checked.clone());
                let (probes_closed, probe_closed) = (probes_closed.clone(), probe_closed.clone());
                connections.spawn(async move {
                    let Ok(mut socket) = accept_async(stream).await else {
                        return;
                    };
                    let mut probe = false;
                    while let Some(Ok(message)) = socket.next().await {
                        let Message::Text(text) = message else {
                            continue;
                        };
                        let Ok(frame) = serde_json::from_str::<serde_json::Value>(&text) else {
                            continue;
                        };
                        let inbox_check = frame[2]["kinds"][0] == 1059 && frame[2]["limit"] == 1;
                        let replies = match (frame[0].as_str(), script) {
                            (Some("REQ"), _) if inbox_check => {
                                probe = true;
                                checks.fetch_add(1, Ordering::SeqCst);
                                checked.notify_one();
                                match script {
                                    Script::RefusesAuth => vec![
                                        serde_json::json!([
                                            "CLOSED",
                                            frame[1],
                                            "ERROR: auth-required: sign in"
                                        ]),
                                        serde_json::json!(["AUTH", "check-challenge"]),
                                    ],
                                    Script::RateLimited => vec![serde_json::json!([
                                        "CLOSED",
                                        frame[1],
                                        "rate-limited: slow down"
                                    ])],
                                    Script::HoldsCheck => continue,
                                }
                            }
                            (Some("REQ"), Script::HoldsCheck) => {
                                vec![serde_json::json!(["EOSE", frame[1]])]
                            }
                            (Some("REQ"), _) => vec![serde_json::json!([
                                "CLOSED",
                                frame[1],
                                "restricted: not here"
                            ])],
                            (Some("EVENT"), _) => {
                                vec![serde_json::json!(["OK", frame[1]["id"], true, ""])]
                            }
                            (Some("AUTH"), _) => vec![serde_json::json!([
                                "OK",
                                frame[1]["id"],
                                false,
                                "restricted: not a member"
                            ])],
                            _ => continue,
                        };
                        for reply in replies {
                            if socket
                                .send(Message::Text(reply.to_string().into()))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                    }
                    if probe {
                        probes_closed.fetch_add(1, Ordering::SeqCst);
                        probe_closed.notify_one();
                    }
                });
            }
        }
    });
    Scripted {
        url,
        checks,
        checked,
        probes_closed,
        probe_closed,
        server,
    }
}

/// A port nothing listens on.
fn closed_port() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    format!("ws://{}", listener.local_addr().unwrap())
}

fn retired_relay() -> String {
    format!(
        "wss://{}",
        crate::retired_relay_hosts()
            .first()
            .expect("a configured retired host")
    )
}

/// An app on `dir` holding `inbox` as `account_id_hex`'s published inbox
/// list beside a NIP-65 list of `write`.
fn app_with_inbox(
    dir: &std::path::Path,
    account_id_hex: &str,
    write: &str,
    inbox: &[&str],
) -> crate::MarmotApp {
    let app = crate::MarmotApp::with_relay_and_config(
        dir,
        write.to_owned(),
        crate::MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true),
    );
    let mut lists = crate::AccountRelayListStatus::empty();
    lists.nip65.created_at = crate::unix_now_seconds();
    lists.nip65.relays = vec![write.to_owned()];
    lists.inbox.created_at = lists.nip65.created_at;
    lists.inbox.relays = inbox.iter().map(|relay| (*relay).to_owned()).collect();
    lists.refresh();
    app.directory()
        .remember_directory_relay_lists(account_id_hex, &lists)
        .unwrap();
    app
}

type Row = (String, RelayHealthState, Option<RelayHealthFault>, bool);

fn rows(health: &crate::AccountRelayHealth) -> Vec<Row> {
    health
        .rows
        .iter()
        .filter(|row| row.roles.contains(&crate::RelayRole::Inbox))
        .map(|row| {
            (
                row.url.clone(),
                row.state,
                row.fault,
                row.checked_at_unix.is_some(),
            )
        })
        .collect()
}

fn sorted(mut rows: Vec<Row>) -> Vec<Row> {
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    rows
}

async fn next_health_change(events: &mut broadcast::Receiver<MarmotAppEvent>, id: &str) {
    timeout(Duration::from_secs(20), async {
        loop {
            if let MarmotAppEvent::RelayHealthChanged { account_id_hex, .. } =
                events.recv().await.unwrap()
                && account_id_hex == id
            {
                return;
            }
        }
    })
    .await
    .expect("a RelayHealthChanged for the account");
}

/// A local-key account's worker checks its inbox relays once at its start.
/// A relay that serves the inbox, after demanding authentication or not, is
/// `Healthy`; one that closes the inbox read as `ERROR: auth-required:` and
/// refuses the account's own key is `Failing` and raises a Warning beside the
/// usable ones; a closed port is only `Suspected` because another relay
/// answered; a rate limit establishes nothing. The answer that check changed
/// is announced, and a later check that confirms it announces nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_worker_start_check_fails_only_a_relay_that_refuses_the_local_key() {
    use nostr_relay_builder::prelude::{RelayBuilder, RelayBuilderNip42, RelayBuilderNip42Mode};

    let served = nostr_relay_builder::MockRelay::run().await.unwrap();
    let served = served_url(&served).await;
    let demands_auth =
        nostr_relay_builder::LocalRelay::new(RelayBuilder::default().nip42(RelayBuilderNip42 {
            mode: RelayBuilderNip42Mode::Read,
        }));
    demands_auth.run().await.unwrap();
    let demands_auth_url = transport_nostr::canonical_relay(&demands_auth.url().await.to_string());
    let refusing = scripted_relay(Script::RefusesAuth).await;
    let (refuses, refuses_server) = (refusing.url.clone(), refusing.server);
    let limiting = scripted_relay(Script::RateLimited).await;
    let (limited, limited_server) = (limiting.url.clone(), limiting.server);
    let dead = closed_port();

    let dir = tempfile::tempdir().unwrap();
    let account = marmot_account::AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = app_with_inbox(
        dir.path(),
        &account.account_id_hex,
        &served,
        &[&served, &demands_auth_url, &refuses, &limited, &dead],
    );
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    let mut events = runtime.subscribe();
    runtime.reconcile_accounts().await.unwrap();

    let expected = sorted(vec![
        (served.clone(), RelayHealthState::Healthy, None, true),
        (
            demands_auth_url.clone(),
            RelayHealthState::Healthy,
            None,
            true,
        ),
        (
            refuses.clone(),
            RelayHealthState::Failing,
            Some(RelayHealthFault::AuthenticationRequired),
            true,
        ),
        (limited.clone(), RelayHealthState::Unchecked, None, false),
        (
            dead.clone(),
            RelayHealthState::Suspected,
            Some(RelayHealthFault::Unreachable),
            true,
        ),
    ]);
    timeout(Duration::from_secs(30), async {
        loop {
            next_health_change(&mut events, &account.account_id_hex).await;
            let health = runtime.account_relay_health(&account.label).await.unwrap();
            if rows(&health) == expected {
                return;
            }
        }
    })
    .await
    .expect("the worker's own check settles every inbox relay");

    let health = runtime.account_relay_health(&account.label).await.unwrap();
    assert_eq!(
        health
            .warnings
            .iter()
            .map(|warning| (warning.kind, warning.severity, warning.relays.clone()))
            .collect::<Vec<_>>(),
        vec![(
            RelayWarningKind::InboxRelayFailing,
            RelayWarningSeverity::Warning,
            vec![refuses.clone()]
        )]
    );
    assert!(health.rows.iter().all(|row| !row.checking));

    // Asked again, every relay answers as before: nothing to announce. The
    // worker takes the check's wake before a command sent after it.
    let checked = runtime.check_account_relays(&account.label).await.unwrap();
    assert_eq!(rows(&checked), expected);
    runtime
        .reconnect_relay(&account.label, &served)
        .await
        .unwrap();
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, MarmotAppEvent::RelayHealthChanged { .. }),
            "a check that confirms the answer announces nothing"
        );
    }

    runtime.shutdown().await;
    refuses_server.abort();
    limited_server.abort();
    demands_auth.shutdown();
}

async fn served_url(relay: &nostr_relay_builder::MockRelay) -> String {
    transport_nostr::canonical_relay(&relay.url().await.to_string())
}

/// Under a remote or host signer a relay that refuses authentication is
/// only `Suspected`: the signer may not have answered its challenge. The
/// worker of such an account never checks unprompted, so its signer is never
/// asked to sign a challenge nobody requested.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refusal_under_a_remote_signer_is_only_suspected() {
    let served = nostr_relay_builder::MockRelay::run().await.unwrap();
    let served = served_url(&served).await;
    let Scripted {
        url: refuses,
        checks: refused_checks,
        server: refuses_server,
        ..
    } = scripted_relay(Script::RefusesAuth).await;

    let dir = tempfile::tempdir().unwrap();
    let keys = nostr::prelude::Keys::generate();
    let account = marmot_account::AccountHome::open(dir.path())
        .add_external_signer_account(&keys.public_key().to_hex())
        .unwrap();
    let app = app_with_inbox(
        dir.path(),
        &account.account_id_hex,
        &served,
        &[&served, &refuses],
    );
    app.register_external_signer(
        &account.account_id_hex,
        super::TestExternalAccountSigner { keys },
    )
    .await
    .unwrap();
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    runtime.reconcile_accounts().await.unwrap();
    crate::worker_fences::worker_startup_finished(&runtime, &account.label)
        .await
        .unwrap();
    // A command after the worker's first relay configuration: by then it
    // would have started its own check.
    runtime
        .reconnect_relay(&account.label, &served)
        .await
        .unwrap();
    let unprompted = runtime.account_relay_health(&account.label).await.unwrap();
    assert!(
        unprompted
            .rows
            .iter()
            .all(|row| row.state == RelayHealthState::Unchecked && !row.checking),
        "no check runs unprompted under a remote signer"
    );

    let health = runtime.check_account_relays(&account.label).await.unwrap();
    assert_eq!(
        rows(&health),
        sorted(vec![
            (served.clone(), RelayHealthState::Healthy, None, true),
            (
                refuses.clone(),
                RelayHealthState::Suspected,
                Some(RelayHealthFault::AuthenticationRequired),
                true,
            ),
        ])
    );
    assert!(health.warnings.iter().all(|warning| {
        warning.kind != RelayWarningKind::InboxRelayFailing
            && warning.severity != RelayWarningSeverity::Critical
    }));
    assert_eq!(refused_checks.load(Ordering::SeqCst), 1);
    runtime.shutdown().await;
    refuses_server.abort();
}

/// A check needs the account's running worker: without one the call fails
/// as the account not being active and dials nothing. A check in which no
/// relay answers establishes nothing: the device may be offline.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_check_no_relay_answered_changes_nothing() {
    let served = nostr_relay_builder::MockRelay::run().await.unwrap();
    let served = served_url(&served).await;
    let Scripted {
        url: holder,
        checks: held_checks,
        server: holder_server,
        ..
    } = scripted_relay(Script::HoldsCheck).await;
    let (dead, also_dead) = (closed_port(), closed_port());

    let dir = tempfile::tempdir().unwrap();
    let home = marmot_account::AccountHome::open(dir.path());
    let idle = home.create_account("idle").unwrap();
    let offline = home.create_account("offline").unwrap();
    let app = app_with_inbox(dir.path(), &idle.account_id_hex, &served, &[&holder]);
    let mut lists = crate::AccountRelayListStatus::empty();
    lists.nip65.created_at = crate::unix_now_seconds();
    lists.nip65.relays = vec![served.clone()];
    lists.inbox.created_at = lists.nip65.created_at;
    lists.inbox.relays = vec![dead.clone(), also_dead.clone()];
    lists.refresh();
    app.directory()
        .remember_directory_relay_lists(&offline.account_id_hex, &lists)
        .unwrap();
    let runtime = crate::MarmotAppRuntime::new(app.clone());

    let refused = runtime.check_account_relays(&idle.label).await;
    assert!(
        matches!(&refused, Err(error) if error.is_account_not_active()),
        "{refused:?}"
    );
    assert_eq!(held_checks.load(Ordering::SeqCst), 0, "nothing was dialed");

    runtime.reconcile_accounts().await.unwrap();
    crate::worker_fences::worker_startup_finished(&runtime, &offline.label)
        .await
        .unwrap();
    // The worker's own check runs now or already ran; either way a check
    // asked once it ends finds only silent relays.
    let after = timeout(Duration::from_secs(30), async {
        loop {
            match runtime.check_account_relays(&offline.label).await {
                Err(crate::AppError::RelayCheckRunning) => tokio::task::yield_now().await,
                result => return result.unwrap(),
            }
        }
    })
    .await
    .expect("a check of the offline account ends");
    assert_eq!(
        rows(&after),
        sorted(vec![
            (dead.clone(), RelayHealthState::Unchecked, None, false),
            (also_dead.clone(), RelayHealthState::Unchecked, None, false),
        ])
    );
    runtime.shutdown().await;
    holder_server.abort();
}

/// The inbox check runs beside the account worker: while a relay holds the
/// check's read open, the worker answers commands, the row says a check is
/// running, and another check is refused at once. A relay the policy refuses
/// is never part of the check. Shutdown ends a check still in flight well
/// within the probe's own 8-second answer window, and its relay connection
/// closes with it: nothing of the probe outlives the worker.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_worker_answers_while_a_check_is_held_open() {
    let Scripted {
        url: holder,
        checks: held_checks,
        checked: held,
        probes_closed,
        probe_closed,
        server: holder_server,
    } = scripted_relay(Script::HoldsCheck).await;

    let dir = tempfile::tempdir().unwrap();
    let account = marmot_account::AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let retired = retired_relay();
    let app = app_with_inbox(
        dir.path(),
        &account.account_id_hex,
        &holder,
        &[&holder, &retired],
    );
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    let notified = held.notified();
    runtime.reconcile_accounts().await.unwrap();
    timeout(Duration::from_secs(20), notified)
        .await
        .expect("the worker's check reaches the holding relay");

    timeout(
        Duration::from_secs(10),
        runtime.reconnect_relay(&account.label, &holder),
    )
    .await
    .expect("the worker answers while the check is held")
    .unwrap();
    assert!(matches!(
        timeout(
            Duration::from_secs(10),
            runtime.check_account_relays(&account.label)
        )
        .await
        .expect("a second check is refused at once"),
        Err(crate::AppError::RelayCheckRunning)
    ));
    let health = runtime.account_relay_health(&account.label).await.unwrap();
    let checking = health
        .rows
        .iter()
        .map(|row| (row.url.clone(), row.state, row.checking))
        .collect::<Vec<_>>();
    assert_eq!(
        checking,
        sorted_states(vec![
            (holder.clone(), RelayHealthState::Unchecked, true),
            (retired.clone(), RelayHealthState::NotAllowed, false),
        ])
    );
    let closed = probe_closed.notified();
    timeout(Duration::from_secs(5), runtime.shutdown())
        .await
        .expect("shutdown cancels the held check rather than waiting it out");
    if probes_closed.load(Ordering::SeqCst) == 0 {
        timeout(Duration::from_secs(3), closed)
            .await
            .expect("the held check's relay connection closes with the worker");
    }
    assert_eq!(held_checks.load(Ordering::SeqCst), 1);
    assert_eq!(probes_closed.load(Ordering::SeqCst), 1);
    holder_server.abort();
}

fn sorted_states(
    mut rows: Vec<(String, RelayHealthState, bool)>,
) -> Vec<(String, RelayHealthState, bool)> {
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    rows
}
