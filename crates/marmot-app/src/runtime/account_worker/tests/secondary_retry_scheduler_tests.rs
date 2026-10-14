//! Real managed-worker scheduling under overdue confirmed relay replication.
use super::*;

#[derive(Clone, Debug)]
enum Observation {
    Turn {
        pending: usize,
        buffered: usize,
        yielded: bool,
    },
    Command(bool),
    Drain(TokioInstant),
    Pass,
}

struct Probe {
    observations: Mutex<Vec<Observation>>,
    tail_barrier: Mutex<Option<Arc<tokio::sync::Barrier>>>,
    tail_delay: Duration,
}

static PROBES: std::sync::LazyLock<Mutex<HashMap<String, Arc<Probe>>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

fn probe(account: &str) -> Option<Arc<Probe>> {
    PROBES.lock().unwrap().get(account).cloned()
}

pub(in crate::runtime::account_worker) fn record_turn(
    account: &str,
    pending: usize,
    buffered: usize,
    yielded: bool,
) {
    if let Some(probe) = probe(account) {
        probe.observations.lock().unwrap().push(Observation::Turn {
            pending,
            buffered,
            yielded,
        });
    }
}

pub(in crate::runtime::account_worker) fn record_command(
    account: &str,
    command: &AccountWorkerCommand,
) {
    if let AccountWorkerCommand::SetGroupArchived { archived, .. } = command
        && let Some(probe) = probe(account)
    {
        probe
            .observations
            .lock()
            .unwrap()
            .push(Observation::Command(*archived));
    }
}

pub(in crate::runtime::account_worker) fn record_drain(account: &str) {
    if let Some(probe) = probe(account) {
        probe
            .observations
            .lock()
            .unwrap()
            .push(Observation::Drain(TokioInstant::now()));
    }
}

pub(in crate::runtime::account_worker) async fn pass_tail(account: &str) {
    if let Some(probe) = probe(account) {
        probe.observations.lock().unwrap().push(Observation::Pass);
        let barrier = probe.tail_barrier.lock().unwrap().take();
        if let Some(barrier) = barrier {
            barrier.wait().await;
            barrier.wait().await;
        }
        // Model ordinary local tail work exceeding the existing 10ms floor;
        // no production interval or frozen retry timestamp is changed.
        sleep(probe.tail_delay).await;
    }
}

struct ProbeGuard(String);
impl Drop for ProbeGuard {
    fn drop(&mut self) {
        PROBES.lock().unwrap().remove(&self.0);
        HELD_SCHEDULED_CONVERGENCE_ACCOUNTS
            .lock()
            .unwrap()
            .remove(&self.0);
    }
}

/// Both queued commands and confirmed secondary retries precede this durable
/// send. Overdue local passes must eventually give the durable owner a turn.
#[tokio::test]
async fn overdue_secondary_groups_service_durable_send_after_deferred_predecessors() {
    overdue_secondary_groups_service_durable_send(2).await;
}

#[tokio::test]
async fn overdue_secondary_groups_service_durable_send_after_buffered_predecessors() {
    overdue_secondary_groups_service_durable_send(0).await;
}

async fn overdue_secondary_groups_service_durable_send(deferred_count: usize) {
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://progress.example")
        .with_test_relay_client(relay.clone());
    let mut client = client_on_app_relay_plane(&app, "alice").await;
    let mut groups = Vec::new();
    for name in ["first due group", "second due group"] {
        groups.push(
            client
                .create_group_with_options(
                    name,
                    &[],
                    AppCreateGroupOptions {
                        relays: Some(vec![
                            "wss://index.example".into(),
                            "wss://progress.example".into(),
                        ]),
                        ..Default::default()
                    },
                )
                .await
                .unwrap(),
        );
    }
    relay
        .block_indexer_publish
        .store(true, std::sync::atomic::Ordering::SeqCst);
    for group in &groups {
        client
            .send(group, b"confirmed secondary fixture")
            .await
            .unwrap();
        let retained = client
            .runtime
            .session()
            .outbound_fanouts_for_group(group)
            .unwrap();
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].outcome().accepted_targets, 1);
        assert_eq!(retained[0].outcome().outstanding_targets, 1);
    }
    let last_seed = TokioInstant::now();
    drop(client);
    HELD_SCHEDULED_CONVERGENCE_ACCOUNTS
        .lock()
        .unwrap()
        .insert(account.account_id_hex.clone());
    let probe_guard = ProbeGuard(account.account_id_hex.clone());
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    runtime.reconcile_accounts().await.unwrap();
    runtime.catch_up_accounts().await.unwrap();
    let commands = runtime.accounts().worker_commands("alice").await.unwrap();
    let mut window = runtime
        .open_conversation_window("alice", &groups[0], Default::default())
        .await
        .unwrap();
    while window.snapshot.presentation.header.epoch.is_none() {
        window.snapshot = timeout(Duration::from_secs(5), window.recv())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
    // Both real persisted 30s fanout cutoffs must expire before the held pass.
    tokio::time::sleep_until(last_seed + Duration::from_secs(31)).await;
    let first_pass = Arc::new(tokio::sync::Barrier::new(2));
    runtime
        .shared_services()
        .set_next_scheduled_convergence_barrier(first_pass.clone());
    let tail = Arc::new(tokio::sync::Barrier::new(2));
    let probe = Arc::new(Probe {
        observations: Mutex::new(Vec::new()),
        tail_barrier: Mutex::new(Some(tail.clone())),
        tail_delay: Duration::from_millis(25),
    });
    PROBES
        .lock()
        .unwrap()
        .insert(account.account_id_hex.clone(), probe.clone());
    HELD_SCHEDULED_CONVERGENCE_ACCOUNTS
        .lock()
        .unwrap()
        .remove(&account.account_id_hex);
    let (respond, _response) = oneshot::channel();
    commands
        .try_send(AccountWorkerCommand::GroupRecoveryStatus {
            group_id: groups[0].clone(),
            respond,
        })
        .unwrap();
    timeout(Duration::from_secs(5), first_pass.wait())
        .await
        .unwrap();
    let mut predecessors = Vec::new();
    for archived in [true, false].into_iter().take(deferred_count) {
        let (respond, response) = oneshot::channel();
        commands
            .try_send(AccountWorkerCommand::SetGroupArchived {
                group_id: groups[0].clone(),
                archived,
                respond,
            })
            .unwrap();
        predecessors.push(response);
    }
    // This snapshot read fences the two mutation commands into the deferred FIFO.
    let (respond, response) = oneshot::channel();
    commands
        .try_send(AccountWorkerCommand::Members {
            group_id: groups[0].clone(),
            respond,
        })
        .unwrap();
    timeout(Duration::from_secs(5), response)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let accepted = runtime
        .submit_text(
            "alice",
            &groups[0],
            "durable after command predecessors".into(),
            "overdue-durable".into(),
        )
        .await
        .unwrap();
    let admission_gate = runtime
        .shared_services()
        .local_submission_gate(&account.account_id_hex);
    let held_admission = admission_gate.lock().await;
    first_pass.wait().await;
    timeout(Duration::from_secs(5), tail.wait()).await.unwrap();
    // These are still buffered in the channel when the finished pass returns.
    for archived in [true, false, true, false]
        .into_iter()
        .take(4 - deferred_count)
    {
        let (respond, response) = oneshot::channel();
        commands
            .try_send(AccountWorkerCommand::SetGroupArchived {
                group_id: groups[0].clone(),
                archived,
                respond,
            })
            .unwrap();
        predecessors.push(response);
    }
    tail.wait().await;
    // Repeated optional passes must preserve the ordinary 100ms gate-contention backoff.
    sleep(Duration::from_millis(700)).await;
    let admission_released = TokioInstant::now();
    drop(held_admission);
    let observed = timeout(Duration::from_secs(3), async {
        loop {
            let snapshot = window.recv().await.unwrap().unwrap();
            if snapshot.page.page().messages.iter().any(|row| {
                row.message_id_hex == accepted.message_id_hex && row.source_message_id_hex.is_some()
            }) {
                break;
            }
        }
    })
    .await;
    let observations = probe.observations.lock().unwrap().clone();
    drop(probe_guard);
    relay
        .block_indexer_publish
        .store(false, std::sync::atomic::Ordering::SeqCst);
    relay.indexer_publish_release.notify_waiters();
    runtime.shutdown_and_close().await.unwrap();
    observed.expect("overdue confirmed secondary groups must service the durable send while their ACKs remain held");
    for response in predecessors {
        response.await.unwrap().unwrap();
    }
    let first_drain = observations
        .iter()
        .position(|event| matches!(event, Observation::Drain(_)))
        .unwrap();
    let prior_commands = observations[..first_drain]
        .iter()
        .filter_map(|event| match event {
            Observation::Command(value) => Some(*value),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        prior_commands,
        vec![true, false, true, false],
        "all deferred and buffered predecessors must run before durable execution"
    );
    if deferred_count > 0 {
        assert!(observations.iter().any(|event| matches!(event, Observation::Turn { pending, .. } if *pending >= deferred_count)), "fixture must exercise the deferred FIFO");
    } else {
        assert!(observations.iter().any(|event| matches!(event, Observation::Turn { pending: 0, buffered, yielded: true } if *buffered > 0)), "fixture must exercise a buffered predecessor while the command arm is fairness-gated");
    }
    let blocked_drains = observations
        .iter()
        .filter_map(|event| match event {
            Observation::Drain(at) if *at < admission_released => Some(*at),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(
        blocked_drains.len() >= 2,
        "fixture must exercise repeated unavailable-row drains"
    );
    assert!(
        blocked_drains
            .windows(2)
            .all(|times| times[1].duration_since(times[0]) >= Duration::from_millis(100)),
        "secondary pressure must not reset the ordinary drain's 100ms retry backoff"
    );
    assert!(
        observations
            .iter()
            .filter(|event| matches!(event, Observation::Pass))
            .count()
            >= 2
    );
}
