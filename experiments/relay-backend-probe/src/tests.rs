use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use nostr_sdk::NotificationUpdate;
use nostr_sdk::authenticator::{Authenticator, SignerAuthenticator};
use nostr_sdk::local_relay::{LocalRelay, QueryPolicy, QueryPolicyResult};
use nostr_sdk::prelude::*;
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::tungstenite::Message;

const DEADLINE: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, Default)]
struct Connections(Arc<Mutex<BTreeMap<String, BTreeSet<SocketAddr>>>>);

impl QueryPolicy for Connections {
    fn admit_query<'a>(
        &'a self,
        query: &'a mut Filter,
        addr: &'a SocketAddr,
    ) -> Pin<Box<dyn Future<Output = QueryPolicyResult> + Send + 'a>> {
        Box::pin(async move {
            let filter = serde_json::to_value(query).unwrap();
            let recipient = filter["#p"][0].as_str().unwrap_or("anonymous");
            self.0
                .lock()
                .unwrap()
                .entry(recipient.to_owned())
                .or_default()
                .insert(*addr);
            QueryPolicyResult::Accept
        })
    }
}

#[derive(Debug)]
struct CountingAuth {
    signer: SignerAuthenticator<Keys>,
    calls: Arc<AtomicUsize>,
}

impl Authenticator for CountingAuth {
    fn make_auth_event<'a>(
        &'a self,
        relay_url: &'a RelayUrl,
        challenge: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Event, nostr_sdk::error::Error>> + Send + 'a>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.signer.make_auth_event(relay_url, challenge)
    }
}

fn account(keys: &Keys) -> (Client, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let client = Client::builder()
        .authenticator(CountingAuth {
            signer: SignerAuthenticator::new(keys.clone()),
            calls: calls.clone(),
        })
        .build();
    (client, calls)
}

async fn connect(client: &Client, url: &RelayUrl) {
    client.add_relay(url).await.unwrap();
    client.try_connect_relay(url, DEADLINE).await.unwrap();
}

async fn fetch(client: &Client, filter: Filter) -> BTreeSet<EventId> {
    client
        .fetch_events(filter)
        .timeout(DEADLINE)
        .await
        .unwrap()
        .into_iter()
        .map(|event| event.id)
        .collect()
}

fn inbox(keys: &Keys) -> Filter {
    Filter::new().kind(Kind::GiftWrap).pubkey(keys.public_key())
}

async fn auth_isolation(replace_relay_generation: bool) {
    let connections = Connections::default();
    let relay = LocalRelay::builder()
        .auth_dm(true)
        .query_policy(connections.clone())
        .build();
    relay.run().await.unwrap();
    let url = relay.url().await;
    let alice = Keys::generate();
    let bob = Keys::generate();
    let sender = Keys::generate();
    let mut expected = Vec::new();
    for recipient in [&alice, &bob] {
        // Synthetic signed envelopes exercise relay access control, not NIP-59 decryption.
        let event = EventBuilder::new(Kind::GiftWrap, "synthetic private envelope")
            .tag(Tag::public_key(recipient.public_key()))
            .finalize(&sender)
            .unwrap();
        expected.push(event.id);
        relay.add_event(event).await.unwrap();
    }
    let public = EventBuilder::new(Kind::TextNote, "synthetic public note")
        .finalize(&sender)
        .unwrap();
    relay.add_event(public.clone()).await.unwrap();
    let (a, a_auth) = account(&alice);
    let (b, b_auth) = account(&bob);
    tokio::join!(connect(&a, &url), connect(&b, &url));
    let (a_first, b_first) = tokio::join!(fetch(&a, inbox(&alice)), fetch(&b, inbox(&bob)));
    assert_eq!(a_first, BTreeSet::from([expected[0]]));
    assert_eq!(b_first, BTreeSet::from([expected[1]]));
    assert_eq!(a_auth.load(Ordering::SeqCst), 1);
    assert_eq!(b_auth.load(Ordering::SeqCst), 1);

    for _ in 0..3 {
        let (a_repeat, b_repeat) = tokio::join!(fetch(&a, inbox(&alice)), fetch(&b, inbox(&bob)));
        assert_eq!(a_repeat, a_first);
        assert_eq!(b_repeat, b_first);
    }
    {
        let seen = connections.0.lock().unwrap();
        let a_sockets = &seen[&alice.public_key().to_hex()];
        let b_sockets = &seen[&bob.public_key().to_hex()];
        assert_eq!(a_sockets.len(), 1, "same-account requests reuse a socket");
        assert_eq!(b_sockets.len(), 1);
        assert!(
            a_sockets.is_disjoint(b_sockets),
            "accounts must not share authenticated sockets"
        );
    }

    // Negative control: an Alice-authenticated connection cannot read Bob's inbox.
    let mut rejected = a.notifications();
    assert!(fetch(&a, inbox(&bob)).await.is_empty());
    loop {
        if let ClientNotification::Message { message, .. } = rejected.next().await.unwrap()
            && let RelayMessage::Closed { message, .. } = *message
        {
            assert!(message.contains("cannot request another user's gift wrap"));
            break;
        }
    }
    assert_eq!(
        a_auth.load(Ordering::SeqCst),
        1,
        "must not switch identity on rejection"
    );
    let bob_query_sockets_before_reconnect =
        connections.0.lock().unwrap()[&bob.public_key().to_hex()].clone();

    // Reconnect Alice while Bob is actively requesting data.
    let a_relay = a.relay(&url).await.unwrap().unwrap();
    let mut lifecycle = a_relay.notifications();
    let mut a_live = a.notifications();
    let mut b_live = b.notifications();
    let a_subscription = SubscriptionId::new("alice-live-reconnect");
    let b_subscription = SubscriptionId::new("bob-live-reconnect");
    let mut b_live_event = None;
    if !replace_relay_generation {
        assert!(
            a.subscribe(inbox(&alice))
                .with_id(a_subscription.clone())
                .await
                .unwrap()
                .failed
                .is_empty()
        );
        assert!(
            b.subscribe(inbox(&bob))
                .with_id(b_subscription.clone())
                .await
                .unwrap()
                .failed
                .is_empty()
        );
        for (stream, id) in [
            (&mut a_live, &a_subscription),
            (&mut b_live, &b_subscription),
        ] {
            tokio::time::timeout(DEADLINE, async {
                loop {
                    if let ClientNotification::Message { message, .. } = stream.next().await.expect("live stream closed before EOSE")
                        && matches!(*message, RelayMessage::EndOfStoredEvents(ref received) if received.as_ref() == id)
                    {
                        break;
                    }
                }
            }).await.unwrap();
        }
    }
    let a_auth_before_reconnect = a_auth.load(Ordering::SeqCst);
    let b_auth_before_reconnect = b_auth.load(Ordering::SeqCst);
    a.disconnect_relay(&url).await.unwrap();
    // disconnect_relay requests shutdown; its return is not a socket-close barrier.
    tokio::time::timeout(DEADLINE, async {
        loop {
            if let RelayNotification::RelayStatus {
                status: RelayStatus::Terminated,
            } = lifecycle
                .next()
                .await
                .expect("relay lifecycle stream closed")
            {
                break;
            }
        }
    })
    .await
    .unwrap();
    let ((), b_during) = tokio::join!(
        async {
            if replace_relay_generation {
                // Terminated is not a task-join barrier. Retire this relay object
                // rather than racing its teardown with a new socket generation.
                a.remove_relay(&url).force().await.unwrap();
                connect(&a, &url).await;
            } else {
                // connect_relay queues reactivation while the old task owns the
                // relay; try_connect_relay is a one-shot attempt and can report
                // that ownership conflict after Terminated.
                a.connect_relay(&url).await.unwrap();
                tokio::time::timeout(DEADLINE, async {
                    loop {
                        if let RelayNotification::RelayStatus {
                            status: RelayStatus::Connected,
                        } = lifecycle
                            .next()
                            .await
                            .expect("relay lifecycle stream closed")
                        {
                            break;
                        }
                    }
                })
                .await
                .unwrap();
            }
        },
        fetch(&b, inbox(&bob))
    );
    assert_eq!(b_during, b_first);
    assert_eq!(fetch(&a, inbox(&alice)).await, a_first);
    assert!(a_auth.load(Ordering::SeqCst) > a_auth_before_reconnect);
    assert_eq!(b_auth.load(Ordering::SeqCst), b_auth_before_reconnect);
    if !replace_relay_generation {
        // The restored Alice subscription reaches EOSE before testing live
        // delivery. Bob's subscription stays on its original connection.
        tokio::time::timeout(DEADLINE, async {
            loop {
                if let ClientNotification::Message { message, .. } = a_live.next().await.expect("Alice live stream closed before EOSE")
                    && matches!(*message, RelayMessage::EndOfStoredEvents(ref received) if received.as_ref() == &a_subscription)
                {
                    break;
                }
            }
        }).await.unwrap();
        let a_event = EventBuilder::new(Kind::GiftWrap, "live after same-relay reconnect")
            .tag(Tag::public_key(alice.public_key()))
            .finalize(&sender)
            .unwrap();
        let b_event = EventBuilder::new(Kind::GiftWrap, "live during other-account reconnect")
            .tag(Tag::public_key(bob.public_key()))
            .finalize(&sender)
            .unwrap();
        b_live_event = Some(b_event.id);
        relay.add_event(a_event.clone()).await.unwrap();
        relay.add_event(b_event.clone()).await.unwrap();
        for (stream, subscription, event_id) in [
            (&mut a_live, &a_subscription, a_event.id),
            (&mut b_live, &b_subscription, b_event.id),
        ] {
            tokio::time::timeout(DEADLINE, async {
                loop {
                    if let ClientNotification::Event {
                        subscription_id,
                        event,
                        ..
                    } = stream
                        .next()
                        .await
                        .expect("live stream closed before event")
                        && &subscription_id == subscription
                        && event.id == event_id
                    {
                        break;
                    }
                }
            })
            .await
            .unwrap();
        }
        {
            let seen = connections.0.lock().unwrap();
            assert_eq!(
                seen[&alice.public_key().to_hex()].len(),
                2,
                "Alice reconnected with a new socket"
            );
            assert_eq!(
                seen[&bob.public_key().to_hex()],
                bob_query_sockets_before_reconnect,
                "Bob kept his original query sockets during Alice's reconnect"
            );
        }
        assert!(fetch(&a, inbox(&bob)).await.is_empty());
        assert!(a_auth.load(Ordering::SeqCst) > a_auth_before_reconnect);
        assert_eq!(b_auth.load(Ordering::SeqCst), b_auth_before_reconnect);
    }

    // Removal invalidates only Alice's client. Bob retains his authenticated session.
    a.shutdown().await;
    let mut expected_b = b_first;
    expected_b.extend(b_live_event);
    assert_eq!(fetch(&b, inbox(&bob)).await, expected_b);
    assert_eq!(b_auth.load(Ordering::SeqCst), b_auth_before_reconnect);

    // A separate anonymous client has no account signer to reveal on a challenge.
    let anonymous = Client::default();
    connect(&anonymous, &url).await;
    assert_eq!(
        fetch(&anonymous, Filter::new().kind(Kind::TextNote)).await,
        BTreeSet::from([public.id])
    );
    let mut anonymous_messages = anonymous.notifications_with_gaps();
    assert!(fetch(&anonymous, inbox(&alice)).await.is_empty());
    let mut challenged = false;
    let mut denied = false;
    tokio::time::timeout(DEADLINE, async {
        while !(challenged && denied) {
            if let NotificationUpdate::Notification(ClientNotification::Message {
                message, ..
            }) = anonymous_messages
                .next()
                .await
                .expect("anonymous notification stream closed before challenge")
            {
                match *message {
                    RelayMessage::Auth { .. } => challenged = true,
                    RelayMessage::Closed { message, .. }
                        if message.starts_with("auth-required:") =>
                    {
                        denied = true;
                    }
                    _ => {}
                }
            }
        }
    })
    .await
    .unwrap();
    assert!(a_auth.load(Ordering::SeqCst) > a_auth_before_reconnect);
    assert_eq!(b_auth.load(Ordering::SeqCst), b_auth_before_reconnect);
    println!(
        "auth: isolated account sockets; repeated requests reused each; Alice reauthenticated on a new socket; Bob survived Alice removal; cross-account private read denied; anonymous challenge and auth-required CLOSED observed without an account authenticator"
    );
    anonymous.shutdown().await;
    b.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authenticated_accounts_reuse_only_their_own_sessions() {
    tokio::time::timeout(Duration::from_secs(60), auth_isolation(true))
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sdk_immediate_reconnect_after_terminated_restores_live_delivery() {
    tokio::time::timeout(Duration::from_secs(60), auth_isolation(false))
        .await
        .unwrap();
}

/// Test-only admission evidence; out-of-band control cannot be displaced by EVENTs.
/// Generation is supplied by the test's owner. No durable storage is modeled here.
#[derive(Debug)]
struct End {
    generation: u64,
    dropped: usize,
    events: usize,
    bytes: usize,
}

impl End {
    fn can_complete(&self, current_generation: u64, admitted: usize) -> bool {
        self.generation == current_generation && self.dropped == 0 && admitted == self.events
    }
}

async fn owned_acquisition(
    url: &RelayUrl,
    generation: u64,
    backpressure: bool,
) -> (
    mpsc::Receiver<Event>,
    oneshot::Receiver<End>,
    tokio::task::JoinHandle<()>,
) {
    // Explicit loopback-only dial; this is not the production host-safety dialer.
    assert_eq!(url.host(), Some(Host::Ipv4(std::net::Ipv4Addr::LOCALHOST)));
    let (mut socket, _) = tokio_tungstenite::connect_async(url.as_str())
        .await
        .unwrap();
    socket
        .send(Message::Text(
            serde_json::json!(["REQ", "owned", {"kinds": [1], "limit": 64}])
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
    let (tx, rx) = mpsc::channel(4);
    let (end_tx, end_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut end = End {
            generation,
            dropped: 0,
            events: 0,
            bytes: 0,
        };
        while let Some(frame) = socket.next().await {
            let frame = frame.unwrap();
            if !frame.is_text() {
                continue;
            }
            let text = frame.to_text().unwrap();
            end.bytes += text.len();
            let message: serde_json::Value = serde_json::from_str(text).unwrap();
            match message[0].as_str() {
                Some("EVENT") => {
                    assert_eq!(message[1], "owned");
                    let event: Event = serde_json::from_value(message[2].clone()).unwrap();
                    event.verify().unwrap();
                    end.events += 1;
                    if backpressure {
                        if tx.send(event).await.is_err() {
                            return;
                        }
                        continue;
                    }
                    match tx.try_send(event) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(_)) => end.dropped += 1,
                        Err(mpsc::error::TrySendError::Closed(_)) => return,
                    }
                }
                Some("EOSE") => {
                    assert_eq!(message[1], "owned");
                    end_tx.send(end).unwrap();
                    socket.close(None).await.unwrap();
                    return;
                }
                _ => {}
            }
        }
        panic!("connection ended without scoped EOSE");
    });
    (rx, end_rx, task)
}

async fn ingress_loss() {
    let relay = LocalRelay::new();
    relay.run().await.unwrap();
    let url = relay.url().await;
    let keys = Keys::generate();
    let mut expected = BTreeSet::new();
    for n in 0..64 {
        let event = EventBuilder::new(Kind::TextNote, format!("synthetic event {n}"))
            .finalize(&keys)
            .unwrap();
        expected.insert(event.id);
        relay.add_event(event).await.unwrap();
    }
    let client = Client::builder()
        .notification_channel_size(NonZeroUsize::new(4).unwrap())
        .build();
    connect(&client, &url).await;
    let mut stalled = client.notifications_with_gaps();
    let mut observer = client.notifications_with_gaps();
    let observed_eose = tokio::spawn(async move {
        while let Some(notification) = observer.next().await {
            if let NotificationUpdate::Notification(ClientNotification::Message { message, .. }) =
                notification
                && matches!(*message, RelayMessage::EndOfStoredEvents(_))
            {
                return;
            }
        }
        panic!("no EOSE");
    });
    client
        .subscribe(Filter::new().kind(Kind::TextNote).limit(64))
        .await
        .unwrap();
    observed_eose.await.unwrap();
    let mut retained = BTreeSet::new();
    let mut skipped = 0;
    loop {
        match stalled.next().await.unwrap() {
            NotificationUpdate::Lagged { skipped: gap } => skipped += gap,
            NotificationUpdate::Notification(ClientNotification::Message { message, .. }) => {
                match *message {
                    RelayMessage::Event { event, .. } => {
                        retained.insert(event.id);
                    }
                    RelayMessage::EndOfStoredEvents(_) => break,
                    _ => {}
                }
            }
            _ => {}
        }
    }
    assert!(skipped > 0, "forced receiver saturation must be visible");
    assert!(
        retained.len() < expected.len(),
        "forced SDK saturation must lose data"
    );
    let sdk_retained = retained.len();
    // Seen-ID caches must not prevent explicit reacquisition through the same client.
    assert_eq!(
        fetch(&client, Filter::new().kind(Kind::TextNote).limit(64)).await,
        expected
    );
    client
        .subscribe(Filter::new().kind(Kind::Metadata))
        .await
        .unwrap();
    let later = EventBuilder::new(Kind::Metadata, "after receiver gap")
        .finalize(&keys)
        .unwrap();
    relay.add_event(later.clone()).await.unwrap();
    tokio::time::timeout(DEADLINE, async {
        loop {
            if let NotificationUpdate::Notification(ClientNotification::Message { message, .. }) =
                stalled
                    .next()
                    .await
                    .expect("stalled notification stream closed before later event")
                && let RelayMessage::Event { event, .. } = *message
                && event.id == later.id
            {
                break;
            }
        }
    })
    .await
    .unwrap();
    client.shutdown().await;

    // Bypass SDK fanout: deliberately stall a four-slot account admission queue.
    let (mut rx, end_rx, task) = owned_acquisition(&url, 1, false).await;
    let end = end_rx.await.unwrap();
    task.await.unwrap();
    retained.clear();
    while let Some(event) = rx.recv().await {
        retained.insert(event.id);
    }
    assert_eq!(end.events, 64);
    assert_eq!(retained.len(), 4);
    assert_eq!(end.dropped, 60);
    assert!(
        !end.can_complete(1, retained.len()),
        "EOSE cannot clear a lossy obligation"
    );
    let first_bytes = end.bytes;

    // Retry the same bounded scope. A sender that awaits admission supplies backpressure;
    // no broad automatic replay or fixture-only missing-ID oracle is used.
    let (mut rx, end_rx, task) = owned_acquisition(&url, 2, true).await;
    let mut duplicate = 0;
    let mut admitted = 0;
    while let Some(event) = rx.recv().await {
        admitted += 1;
        if !retained.insert(event.id) {
            duplicate += 1;
        }
    }
    let retry = end_rx.await.unwrap();
    task.await.unwrap();
    assert_eq!(retained, expected);
    assert_eq!(duplicate, 4);
    assert!(retry.can_complete(2, admitted));
    assert!(
        !retry.can_complete(2, admitted - 1),
        "queued but unadmitted work cannot complete"
    );
    assert!(
        !retry.can_complete(3, admitted),
        "stale generation cannot clear new work"
    );
    println!(
        "ingress: SDK EOSE with {sdk_retained}/64 EVENTs retained and gap={skipped}; explicit reacquisition returned 64/64; owned queue gap=60, retained=4, completion=false; retry new=60 duplicate=4; connection text bytes first={first_bytes} retry={}",
        retry.bytes
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn saturation_must_not_turn_eose_into_false_completion() {
    tokio::time::timeout(Duration::from_secs(60), ingress_loss())
        .await
        .unwrap();
}
