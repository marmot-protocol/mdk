//! Reading a pending commit back (mdk#2332): what a relay's answer proves,
//! and what a read never does.

use std::sync::Arc;
use std::time::Duration;

use cgka_traits::{
    MemberId, TransportAdapter, TransportEndpoint, TransportMessage, TransportReadBack,
};
use futures::{SinkExt, StreamExt};
use nostr_sdk::prelude::{Event, EventBuilder, FinalizeEvent, Keys, Kind, Tag};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_tungstenite::{accept_async, tungstenite::Message};
use transport_nostr_peeler::NostrTransportEvent;

use super::read_back::{READ_BACK_REQS_PER_RELAY_HOUR, READ_BACK_WAIT, ReadBackBudget, answer_of};
use super::*;
use transport_nostr_adapter::{NostrAcquisitionEnd, NostrAcquisitionEndpoint};

use TransportReadBack::{Found, NoAnswer, NotFound};

/// How a scripted relay answers each REQ.
#[derive(Clone)]
enum Reply {
    /// These events, then EOSE.
    Events(Vec<Value>),
    /// An AUTH challenge, then CLOSED with this reason.
    Closed(&'static str),
    /// Nothing at all.
    Silent,
}

/// A loopback relay that answers every REQ, on every connection, with
/// `reply`, and reports each frame a client sends it.
async fn scripted_relay(reply: Reply) -> (TransportEndpoint, mpsc::UnboundedReceiver<Value>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = TransportEndpoint(format!("ws://{}", listener.local_addr().unwrap()));
    let (frames_tx, frames) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let reply = reply.clone();
            let frames_tx = frames_tx.clone();
            tokio::spawn(async move {
                let Ok(mut socket) = accept_async(stream).await else {
                    return;
                };
                while let Some(Ok(frame)) = socket.next().await {
                    let Message::Text(text) = frame else {
                        continue;
                    };
                    let frame: Value = serde_json::from_str(&text).unwrap();
                    let subscription = (frame[0] == "REQ").then(|| frame[1].clone());
                    let _ = frames_tx.send(frame);
                    let Some(subscription) = subscription else {
                        continue;
                    };
                    let answers = match &reply {
                        Reply::Events(events) => events
                            .iter()
                            .map(|event| json!(["EVENT", subscription, event]))
                            .chain([json!(["EOSE", subscription])])
                            .collect(),
                        Reply::Closed(reason) => vec![
                            json!(["AUTH", "read-back-challenge"]),
                            json!(["CLOSED", subscription, reason]),
                        ],
                        Reply::Silent => Vec::new(),
                    };
                    for answer in answers {
                        if socket
                            .send(Message::Text(answer.to_string().into()))
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                }
            });
        }
    });
    (endpoint, frames)
}

fn frames_sent(frames: &mut mpsc::UnboundedReceiver<Value>) -> Vec<Value> {
    std::iter::from_fn(|| frames.try_recv().ok()).collect()
}

fn group_event(content: &str) -> Event {
    EventBuilder::new(Kind::MlsGroupMessage, content)
        .tags([Tag::custom("h", [hex::encode([0xD5; 32])])])
        .finalize(&Keys::generate())
        .unwrap()
}

fn frozen(event: &Event) -> TransportMessage {
    NostrTransportEvent::from_nostr_event(event)
        .unwrap()
        .to_transport_message()
        .unwrap()
}

fn account_adapter(
    plane: &MarmotRelayPlane,
    account_id: &MemberId,
) -> MarmotRelayPlaneAccountAdapter {
    let client = plane
        .inner
        .transport
        .sdk_relay_client
        .as_ref()
        .unwrap()
        .clone();
    plane.account_adapter(account_id.clone(), Arc::new(client))
}

async fn read(
    adapter: &MarmotRelayPlaneAccountAdapter,
    account_id: &MemberId,
    message: &TransportMessage,
    endpoints: &[TransportEndpoint],
) -> Vec<TransportReadBack> {
    timeout(
        Duration::from_secs(30),
        adapter.read_back(account_id, message, endpoints),
    )
    .await
    .unwrap()
}

fn account() -> MemberId {
    MemberId::new(Keys::generate().public_key().to_bytes().to_vec())
}

/// Proofs 3 and 4. Only a copy that verifies as the exact event is found: a
/// copy with altered content, a forged signature, or another event is not,
/// nor is an EOSE alone; a CLOSED answers nothing, an `auth-required:` one
/// included. Every relay gets one REQ for the event's id with limit 1, and no
/// AUTH. Two spellings of a relay share its REQ, and a relay the host-safety
/// rule refuses is never asked. The events reach no ingest.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_the_exact_event_reads_back_found() {
    let commit = group_event("pending commit");
    let other = group_event("another commit");
    let exact = serde_json::to_value(&commit).unwrap();
    let mut altered = exact.clone();
    altered["content"] = json!("an altered commit");
    let mut forged = exact.clone();
    forged["sig"] = serde_json::to_value(&other).unwrap()["sig"].clone();
    let mut relays = Vec::new();
    for reply in [
        Reply::Events(vec![exact]),
        Reply::Events(vec![altered]),
        Reply::Events(vec![forged]),
        Reply::Events(vec![serde_json::to_value(&other).unwrap()]),
        Reply::Events(Vec::new()),
        Reply::Closed("auth-required: read back"),
        Reply::Closed("error: read back"),
    ] {
        relays.push(scripted_relay(reply).await);
    }
    let plane = MarmotRelayPlane::runtime_default_with_loopback(Duration::from_secs(30), true);
    let account_id = account();
    let adapter = account_adapter(&plane, &account_id);
    let mut endpoints = relays
        .iter()
        .map(|(endpoint, _)| endpoint.clone())
        .collect::<Vec<_>>();
    endpoints.push(TransportEndpoint(format!("{}/", endpoints[0].0)));
    endpoints.push(TransportEndpoint("ws://10.20.30.40:7777".into()));

    let answers = timeout(
        Duration::from_secs(30),
        adapter.read_back(&account_id, &frozen(&commit), &endpoints),
    )
    .await
    .unwrap();

    assert_eq!(
        answers,
        [
            Found, NotFound, NotFound, NotFound, NotFound, NoAnswer, NoAnswer, Found, NoAnswer
        ]
    );
    for (_, frames) in &mut relays {
        let frames = frames_sent(frames);
        let requests = frames
            .iter()
            .filter(|frame| frame[0] == "REQ")
            .collect::<Vec<_>>();
        assert_eq!(requests.len(), 1, "{frames:?}");
        assert_eq!(requests[0].as_array().unwrap().len(), 3, "{frames:?}");
        assert_eq!(
            requests[0][2],
            json!({"ids": [commit.id.to_hex()], "limit": 1})
        );
        assert!(frames.iter().all(|frame| frame[0] != "AUTH"), "{frames:?}");
    }
    let metrics = plane.relay_telemetry().await.metrics;
    assert_eq!(metrics.inbound_events_seen, 0);
    assert_eq!(
        (metrics.read_back_requests, metrics.read_back_found),
        (relays.len(), 1)
    );
    plane.shutdown().await;
}

/// Proof 3, at the adapter's own check: the SDK drops a copy that fails
/// verification before the adapter sees it, so only a direct call shows the
/// adapter would not count a copy under the exact id with altered content or
/// a forged signature either.
#[test]
fn only_a_verified_copy_counts_as_found() {
    let commit = group_event("pending commit");
    let exact = NostrTransportEvent::from_nostr_event(&commit).unwrap();
    let mut altered = exact.clone();
    altered.content = "an altered commit".into();
    let mut forged = exact.clone();
    forged.sig = NostrTransportEvent::from_nostr_event(&group_event("another commit"))
        .unwrap()
        .sig;
    let answer = |events| {
        answer_of(
            &NostrAcquisitionEndpoint {
                endpoint: TransportEndpoint("wss://read-back-check.example".into()),
                session_generation: None,
                events,
                end: NostrAcquisitionEnd::RequestPolicySatisfied,
                stats: Default::default(),
            },
            commit.id,
        )
    };

    assert_eq!(answer(vec![exact]), Found);
    assert_eq!(answer(vec![altered]), NotFound);
    assert_eq!(answer(vec![forged]), NotFound);
}

/// A relay that never ends the read answers nothing once the read's wait
/// runs out.
// Pauses the clock, which needs the current-thread runtime.
#[tokio::test(flavor = "current_thread")]
async fn a_silent_relay_answers_nothing() {
    let commit = group_event("unanswered commit");
    let (endpoint, mut frames) = scripted_relay(Reply::Silent).await;
    let plane = MarmotRelayPlane::runtime_default_with_loopback(Duration::from_secs(30), true);
    let account_id = account();
    let adapter = account_adapter(&plane, &account_id);
    let message = frozen(&commit);
    let read =
        tokio::spawn(async move { adapter.read_back(&account_id, &message, &[endpoint]).await });
    timeout(Duration::from_secs(10), async {
        while frames.recv().await.unwrap()[0] != "REQ" {}
    })
    .await
    .expect("the relay must receive the read");

    tokio::time::pause();
    tokio::time::advance(READ_BACK_WAIT).await;
    let answers = read.await.unwrap();
    tokio::time::resume();

    assert_eq!(answers, [NoAnswer]);
    plane.shutdown().await;
}

/// One account sends a relay at most eight read-backs an hour, whichever of
/// its adapters reads; a read past the cap sends no REQ and answers nothing.
/// Another account's reads are its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn read_backs_past_the_hourly_cap_are_not_sent() {
    let commit = group_event("capped commit");
    let (endpoint, mut frames) =
        scripted_relay(Reply::Events(vec![serde_json::to_value(&commit).unwrap()])).await;
    let plane = MarmotRelayPlane::runtime_default_with_loopback(Duration::from_secs(30), true);
    let account_id = account();
    let adapter = account_adapter(&plane, &account_id);
    let message = frozen(&commit);
    let endpoints = [endpoint];
    for _ in 0..READ_BACK_REQS_PER_RELAY_HOUR {
        assert_eq!(
            read(&adapter, &account_id, &message, &endpoints).await,
            [Found]
        );
    }
    assert_eq!(
        read(&adapter, &account_id, &message, &endpoints).await,
        [NoAnswer]
    );
    let again = account_adapter(&plane, &account_id);
    assert_eq!(
        read(&again, &account_id, &message, &endpoints).await,
        [NoAnswer]
    );
    let requests = frames_sent(&mut frames)
        .iter()
        .filter(|frame| frame[0] == "REQ")
        .count();
    assert_eq!(requests, READ_BACK_REQS_PER_RELAY_HOUR);

    let other_id = account();
    let other = account_adapter(&plane, &other_id);
    assert_eq!(read(&other, &other_id, &message, &endpoints).await, [Found]);
    plane.shutdown().await;
}

/// The cap counts the last hour: a read an hour after the eighth is sent.
#[test]
fn a_read_back_budget_refills_after_an_hour() {
    let budget = ReadBackBudget::default();
    let account_id = MemberId::new(vec![1; 32]);
    let relay = "wss://read-back-budget.example";
    let start = tokio::time::Instant::now();
    for _ in 0..READ_BACK_REQS_PER_RELAY_HOUR {
        assert!(budget.take(&account_id, relay, start));
    }
    assert!(!budget.take(&account_id, relay, start + Duration::from_secs(3_599)));
    assert!(budget.take(&account_id, relay, start + Duration::from_secs(3_600)));
}
