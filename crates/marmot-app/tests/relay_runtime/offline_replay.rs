use super::*;

use std::collections::BTreeSet;
use std::sync::Mutex as StdMutex;

use futures::{SinkExt, StreamExt};
use nostr_relay_builder::prelude::{MemoryDatabase, MemoryDatabaseOptions};
use serde_json::{Value, json};
use tokio_tungstenite::{accept_async, connect_async, tungstenite::Message};

#[derive(Default)]
struct ReplayRequests {
    next_connection: usize,
    filters: Vec<ReplayFilter>,
    completed_group_pages: Vec<usize>,
    refused_comparisons: usize,
}

struct ReplayFilter {
    connection: usize,
    filter: Value,
}

/// Keep real relay storage, signatures, newest-first replay and live fanout;
/// impose only the two production constraints relevant to these regressions.
struct OfflineReplayRelay {
    _upstream: LocalRelay,
    url: String,
    requests: Arc<StdMutex<ReplayRequests>>,
    accept: tokio::task::JoinHandle<()>,
}

impl OfflineReplayRelay {
    async fn start() -> Self {
        let upstream = LocalRelay::new(
            RelayBuilder::default()
                .database(MemoryDatabase::with_opts(MemoryDatabaseOptions {
                    events: true,
                    max_events: Some(8_192),
                }))
                .default_filter_limit(100_000)
                .rate_limit(nostr_relay_builder::builder::RateLimit {
                    notes_per_minute: 10_000,
                    ..Default::default()
                }),
        );
        upstream.run().await.unwrap();
        let upstream_url = upstream.url().await.to_string();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let requests = Arc::new(StdMutex::new(ReplayRequests::default()));
        let captured = requests.clone();
        let accept = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            while let Ok((socket, _)) = listener.accept().await {
                let connection = {
                    let mut requests = captured.lock().unwrap();
                    let connection = requests.next_connection;
                    requests.next_connection += 1;
                    connection
                };
                let upstream_url = upstream_url.clone();
                let requests = captured.clone();
                connections.spawn(async move {
                    let client = accept_async(socket).await.unwrap();
                    let (relay, _) = connect_async(&upstream_url).await.unwrap();
                    let (mut client_write, mut client_read) = client.split();
                    let (mut relay_write, mut relay_read) = relay.split();
                    let mut group_pages = HashMap::<String, usize>::new();
                    loop {
                        tokio::select! {
                            frame = client_read.next() => {
                                let Some(Ok(message)) = frame else { break };
                                let Message::Text(text) = &message else { continue };
                                let mut frame: Value = serde_json::from_str(text).unwrap();
                                match frame[0].as_str() {
                                    Some("NEG-OPEN") => {
                                        requests.lock().unwrap().refused_comparisons += 1;
                                        let reply = json!(["NEG-ERR", frame[1], "blocked: NIP-77 unavailable"]);
                                        if client_write.send(Message::Text(reply.to_string().into())).await.is_err() {
                                            break;
                                        }
                                        continue;
                                    }
                                    Some("REQ") => {
                                        let id = frame[1].as_str().unwrap().to_owned();
                                        for filter in frame.as_array_mut().unwrap().iter_mut().skip(2) {
                                            requests.lock().unwrap().filters.push(ReplayFilter {
                                                connection,
                                                filter: filter.clone(),
                                            });
                                            if filter.get("#h").is_some() {
                                                group_pages.insert(id.clone(), 0);
                                            }
                                            let limit = filter.get("limit").and_then(Value::as_u64).unwrap_or(500);
                                            filter["limit"] = json!(limit.min(500));
                                        }
                                    }
                                    Some("CLOSE") => {
                                        group_pages.remove(frame[1].as_str().unwrap());
                                    }
                                    _ => {}
                                }
                                if relay_write.send(Message::Text(frame.to_string().into())).await.is_err() {
                                    break;
                                }
                            }
                            frame = relay_read.next() => {
                                let Some(Ok(message)) = frame else { break };
                                if let Message::Text(text) = &message {
                                    let frame: Value = serde_json::from_str(text).unwrap();
                                    if let Some(id) = frame[1].as_str() {
                                        match frame[0].as_str() {
                                            Some("EVENT") => {
                                                if let Some(count) = group_pages.get_mut(id) {
                                                    *count += 1;
                                                }
                                            }
                                            Some("EOSE") => {
                                                if let Some(count) = group_pages.remove(id) {
                                                    requests.lock().unwrap().completed_group_pages.push(count);
                                                }
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                                if client_write.send(message).await.is_err() { break; }
                            }
                        }
                    }
                });
            }
        });
        Self {
            _upstream: upstream,
            url,
            requests,
            accept,
        }
    }
}

impl Drop for OfflineReplayRelay {
    fn drop(&mut self) {
        self.accept.abort();
    }
}

fn replay_app(root: &Path, url: &str, policy: marmot_app::CursorPersistence) -> MarmotApp {
    MarmotApp::with_relay_and_config(
        root,
        url.to_owned(),
        MarmotAppConfig::white_noise()
            .with_allow_loopback_relay_endpoints(true)
            .with_cursor_persistence(policy),
    )
}

async fn offline_plaintext_replay(senders: usize, per_sender: usize, offline: Duration) {
    let relay = OfflineReplayRelay::start().await;
    let roots: Vec<_> = (0..=senders)
        .map(|_| tempfile::tempdir().unwrap())
        .collect();
    let mut runtimes = Vec::with_capacity(senders + 1);
    let mut accounts = Vec::with_capacity(senders + 1);
    for (index, root) in roots.iter().enumerate() {
        // A real wake-collection runtime may have joined a group without ever
        // advancing its durable transport cursor. Its next full app launch
        // must not rely on NIP-77 to recover history older than the live tail.
        let policy = if index == senders {
            marmot_app::CursorPersistence::Frozen
        } else {
            marmot_app::CursorPersistence::Advance
        };
        let runtime = MarmotAppRuntime::new(replay_app(root.path(), &relay.url, policy));
        let account = create_network_ready_identity(
            &runtime,
            AccountSetupRequest {
                default_relays: vec![endpoint(&relay.url)],
                bootstrap_relays: vec![endpoint(&relay.url)],
                publish_initial_key_package: true,
                ..Default::default()
            },
        )
        .await
        .account
        .account_id_hex;
        accounts.push(account);
        runtimes.push(runtime);
    }
    let group = runtimes[0]
        .create_group(&accounts[0], "offline replay", &accounts[1..], None)
        .await
        .unwrap();
    for index in 1..=senders {
        accept_group_invite_retrying_busy(&runtimes[index], &accounts[index], &group)
            .await
            .unwrap();
    }
    let baseline = "decrypted before going offline";
    let mut initial = runtimes[senders]
        .subscribe_messages(
            &accounts[senders],
            AppMessageQuery {
                group_id_hex: Some(hex::encode(group.as_slice())),
                kinds: Some(vec![MARMOT_APP_EVENT_KIND_CHAT]),
                limit: Some(1),
            },
        )
        .await
        .unwrap();
    runtimes[0]
        .send_message(&accounts[0], &group, baseline.as_bytes().to_vec())
        .await
        .unwrap();
    timeout(Duration::from_secs(30), async {
        loop {
            if let RuntimeMessageUpdate::Message(message) = initial.recv().await.unwrap()
                && message.message.plaintext == baseline
            {
                break;
            }
        }
    })
    .await
    .expect("the receiver decrypts the first message before disconnecting");
    drop(initial);
    let receiver = runtimes.pop().unwrap();
    receiver.shutdown_and_close().await.unwrap();
    drop(receiver);

    let mut expected = BTreeSet::from([baseline.to_owned()]);
    for sender in 0..senders {
        for index in 0..per_sender {
            // Preserve the real 100-generation ratchet. A second's outer ids
            // are random, so keep timestamp ties below that tolerance; the
            // regression concerns ordering across the complete replay range.
            if index != 0 && index % 50 == 0 {
                let second = NostrTimestamp::now();
                while NostrTimestamp::now() == second {
                    sleep(Duration::from_millis(10)).await;
                }
            }
            let plaintext = format!("offline sender {sender} message {index:03}");
            let sent = runtimes[sender]
                .send_message(&accounts[sender], &group, plaintext.as_bytes().to_vec())
                .await
                .unwrap();
            assert!(
                sent.published > 0,
                "every offline message reaches the real relay"
            );
            assert!(expected.insert(plaintext));
        }
    }
    if !offline.is_zero() {
        // Public runtime sends use wall-clock authored timestamps and expose no
        // injectable clock. Wait the reported 150 seconds instead of adding a
        // production timestamp override or weakening the actual long-gap case.
        sleep(offline).await;
    }
    {
        let mut requests = relay.requests.lock().unwrap();
        *requests = ReplayRequests {
            next_connection: requests.next_connection,
            ..Default::default()
        };
    }
    let receiver_app = replay_app(
        roots[senders].path(),
        &relay.url,
        marmot_app::CursorPersistence::Advance,
    );
    let receiver_account = &accounts[senders];
    let route = receiver_app
        .group(receiver_account, &hex::encode(group.as_slice()))
        .unwrap()
        .unwrap()
        .nostr_routing
        .nostr_group_id_hex;
    let receiver = MarmotAppRuntime::new(receiver_app.clone());
    receiver.reconcile_accounts().await.unwrap();
    let mut subscription = receiver
        .subscribe_messages(
            receiver_account,
            AppMessageQuery {
                group_id_hex: Some(hex::encode(group.as_slice())),
                kinds: Some(vec![MARMOT_APP_EVENT_KIND_CHAT]),
                limit: Some(expected.len()),
            },
        )
        .await
        .unwrap();
    let mut observed: BTreeSet<_> = subscription
        .snapshot
        .iter()
        .map(|message| message.plaintext.clone())
        .collect();
    let complete = timeout(Duration::from_secs(60), async {
        while observed.len() < expected.len() {
            if let RuntimeMessageUpdate::Message(message) = subscription
                .recv()
                .await
                .expect("permanent message consumer stays open")
            {
                assert!(
                    expected.contains(&message.message.plaintext),
                    "only the expected authenticated chat texts are delivered"
                );
                observed.insert(message.message.plaintext);
            }
        }
    })
    .await;
    let stored: BTreeSet<_> = receiver_app
        .messages_with_query(
            receiver_account,
            AppMessageQuery {
                group_id_hex: Some(hex::encode(group.as_slice())),
                kinds: Some(vec![MARMOT_APP_EVENT_KIND_CHAT]),
                limit: Some(expected.len()),
            },
        )
        .unwrap()
        .into_iter()
        .map(|message| message.plaintext)
        .collect();
    assert!(
        complete.is_ok(),
        "permanent consumer saw {} of {} texts; durable projection holds {}",
        observed.len(),
        expected.len(),
        stored.len()
    );
    assert_eq!(
        observed, expected,
        "every exact MLS plaintext reaches the permanent consumer"
    );
    assert_eq!(
        stored, expected,
        "all plaintexts remain available after catch-up"
    );
    if !offline.is_zero() {
        timeout(Duration::from_secs(20), async {
            while relay.requests.lock().unwrap().refused_comparisons == 0 {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the recovery owner attempts its separately authorized comparison");
    }
    {
        let requests = relay.requests.lock().unwrap();
        assert!(
            requests.completed_group_pages.contains(&500),
            "the relay actually applied its newest-first 500-event clamp"
        );
        assert!(
            requests
                .filters
                .iter()
                .any(|request| request.filter.get("#h").is_some()
                    && request.filter.get("until").is_some()),
            "group replay issues backward until paging"
        );
        let receiver_connection = requests
            .filters
            .iter()
            .filter(|request| {
                request
                    .filter
                    .get("#p")
                    .and_then(Value::as_array)
                    .is_some_and(|recipients| {
                        recipients
                            .iter()
                            .any(|recipient| recipient.as_str() == Some(receiver_account.as_str()))
                    })
            })
            .map(|request| request.connection)
            .min()
            .expect("the receiver installs its own inbox on a new connection");
        let activation = requests
            .filters
            .iter()
            .find(|request| {
                request.connection == receiver_connection
                    && request
                        .filter
                        .get("#h")
                        .and_then(Value::as_array)
                        .is_some_and(|routes| {
                            routes
                                .iter()
                                .any(|candidate| candidate.as_str() == Some(route.as_str()))
                        })
            })
            .expect("the receiver activates the persisted group route");
        assert!(
            activation.filter.get("since").is_none() && activation.filter.get("until").is_none(),
            "the receiver's first group REQ requests full history, before maintenance or paging"
        );
        if !offline.is_zero() {
            assert!(
                requests.refused_comparisons > 0,
                "the long-gap recovery encountered a relay without NIP-77"
            );
        }
    }
    receiver.shutdown_and_close().await.unwrap();
    for runtime in runtimes {
        runtime.shutdown_and_close().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn offline_sender_600_replay() {
    offline_plaintext_replay(1, 600, Duration::ZERO).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn offline_replay_crosses_queue() {
    offline_plaintext_replay(1, 1_600, Duration::ZERO).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn offline_150s_six_sender_replay() {
    offline_plaintext_replay(6, 100, Duration::from_secs(150)).await;
}
