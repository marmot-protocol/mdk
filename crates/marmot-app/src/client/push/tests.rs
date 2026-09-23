use crate::*;
use nostr::base64::Engine as _;
use nostr::base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use nostr_relay_builder::builder::{RateLimit, RelayBuilderNip42, RelayBuilderNip42Mode};
use nostr_relay_builder::prelude::{BoxedFuture, PolicyResult, WritePolicy};
use nostr_relay_builder::{LocalRelay, RelayBuilder};
use nostr_sdk::prelude::{Client, Event, Filter, Keys, Kind};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
enum PushRelay {
    LiveSubscriptions,
    StoppedSubscriptions,
    Authenticated,
    MixedEndpoints,
    RejectFirstChunk,
}

#[derive(Clone, Debug, Default)]
struct RejectFirstPush(Arc<OnceLock<Event>>);

impl WritePolicy for RejectFirstPush {
    fn admit_event<'a>(
        &'a self,
        event: &'a nostr_relay_builder::prelude::Event,
        _: &'a std::net::SocketAddr,
    ) -> BoxedFuture<'a, PolicyResult> {
        Box::pin(async move {
            if event.kind == nostr_relay_builder::prelude::Kind::GiftWrap {
                let first = self.0.get_or_init(|| {
                    serde_json::from_value(serde_json::to_value(event).unwrap()).unwrap()
                });
                if first.id.to_bytes() == event.id.to_bytes() {
                    return PolicyResult::Reject("injected push rejection".into());
                }
            }
            PolicyResult::Accept
        })
    }
}

async fn push_batch_case(
    tokens: usize,
    mode: PushRelay,
    repeats: usize,
    endpoint: Option<&str>,
) -> Vec<f64> {
    let rejection = RejectFirstPush::default();
    let builder = RelayBuilder::default().rate_limit(RateLimit {
        notes_per_minute: 10_000,
        ..Default::default()
    });
    let builder = match mode {
        PushRelay::Authenticated => builder.nip42(RelayBuilderNip42 {
            mode: RelayBuilderNip42Mode::Write,
        }),
        PushRelay::RejectFirstChunk => builder.write_policy(rejection.clone()),
        _ => builder,
    };
    let relay = LocalRelay::new(builder);
    relay.run().await.unwrap();
    let url = match endpoint {
        Some(url) => url.to_owned(),
        None => relay.url().await.to_string(),
    };
    // Accept TCP but never finish a WebSocket handshake.
    let stalled = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stalled_url = format!("ws://{}", stalled.local_addr().unwrap());
    let home = tempfile::tempdir().unwrap();
    AccountHome::open(home.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relays_and_config(
        home.path(),
        vec![url.clone()],
        MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true),
    );
    let mut client = app.client("alice").await.unwrap();
    let group = client.create_group("push batch", &[]).await.unwrap();
    let group_hex = hex::encode(group.as_slice());
    let server = Keys::generate();
    let mut expected = std::collections::BTreeSet::new();
    for index in 0..tokens {
        let mut encrypted_token = vec![0; notifications::PUSH_ENCRYPTED_TOKEN_LEN];
        encrypted_token[..8].copy_from_slice(&(index as u64).to_be_bytes());
        expected.insert(encrypted_token.clone());
        app.upsert_group_push_token(
            "alice",
            &GroupPushTokenRecord {
                group_id_hex: group_hex.clone(),
                member_id_hex: format!("{index:064x}"),
                leaf_index: index as u32 + 1,
                platform: PushPlatform::Fcm,
                token_fingerprint: format!("token-{index}"),
                server_pubkey_hex: server.public_key().to_hex(),
                relay_hint: Some(
                    if matches!(mode, PushRelay::MixedEndpoints) && index % 2 == 0 {
                        stalled_url.clone()
                    } else {
                        url.clone()
                    },
                ),
                encrypted_token,
                owner_ts: 1,
                owner_sig: String::new(),
                updated_at_ms: 1,
            },
        )
        .unwrap();
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        while client.relay_plane.relay_health().await.connected != 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    if matches!(mode, PushRelay::StoppedSubscriptions) {
        client.relay_plane.shutdown().await;
    }
    let reader = Client::builder().build();
    reader.add_relay(&url).await.unwrap();
    reader.connect().await;
    let mut known = std::collections::HashSet::new();
    let mut samples = Vec::with_capacity(repeats);
    for _ in 0..repeats {
        let started = Instant::now();
        let deadline = if matches!(mode, PushRelay::MixedEndpoints) {
            3
        } else {
            30
        };
        let result = tokio::time::timeout(
            Duration::from_secs(deadline),
            client.publish_notification_trigger(&group, NotificationTrigger::NewMessage),
        )
        .await
        .expect("notification publication exceeded its deadline");
        samples.push(started.elapsed().as_secs_f64() * 1000.0);
        let mut expected = expected.clone();
        let mut expected_chunks = tokens.div_ceil(19);
        if matches!(mode, PushRelay::RejectFirstChunk) {
            assert!(result.is_err(), "the rejected chunk must be reported");
            let rejected = rejection.0.get().unwrap();
            let gift = nostr::nips::nip59::extract_rumor(&server, rejected).unwrap();
            let content = BASE64_STANDARD.decode(gift.rumor.content).unwrap();
            for token in content.chunks_exact(notifications::PUSH_ENCRYPTED_TOKEN_LEN) {
                assert!(expected.remove(token));
            }
            expected_chunks -= 1;
        } else {
            result.unwrap();
        }
        let events = reader
            .fetch_events(nostr_sdk::prelude::ReqTarget::single(
                &url,
                [Filter::new()
                    .kind(Kind::GiftWrap)
                    .pubkey(server.public_key())],
            ))
            .timeout(Duration::from_secs(5))
            .await
            .unwrap();
        let mut actual = std::collections::BTreeSet::new();
        let mut chunks = 0;
        for event in events {
            if !known.insert(event.id) {
                continue;
            }
            chunks += 1;
            assert!(serde_json::to_vec(&event).unwrap().len() <= 65_536);
            let gift = nostr::nips::nip59::extract_rumor(&server, &event).unwrap();
            assert_eq!(gift.rumor.kind, Kind::Custom(446));
            let content = BASE64_STANDARD.decode(&gift.rumor.content).unwrap();
            assert_eq!(content.len() % notifications::PUSH_ENCRYPTED_TOKEN_LEN, 0);
            assert!(content.len() <= 19 * notifications::PUSH_ENCRYPTED_TOKEN_LEN);
            for token in content.chunks_exact(notifications::PUSH_ENCRYPTED_TOKEN_LEN) {
                assert!(actual.insert(token.to_vec()), "recipient appears twice");
            }
        }
        assert_eq!(
            chunks, expected_chunks,
            "all non-rejected chunks are drained"
        );
        assert_eq!(
            actual, expected,
            "every accepted recipient appears exactly once"
        );
    }
    reader.shutdown().await;
    client.relay_plane.shutdown().await;
    samples
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn push_batch_delivery() {
    for tokens in [0, 19, 20, 128] {
        push_batch_case(tokens, PushRelay::LiveSubscriptions, 1, None).await;
    }
    push_batch_case(128, PushRelay::StoppedSubscriptions, 1, None).await;
    push_batch_case(33, PushRelay::Authenticated, 1, None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn push_batch_ignores_slow_hint() {
    push_batch_case(128, PushRelay::MixedEndpoints, 1, None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn push_drains_after_rejection() {
    push_batch_case(128, PushRelay::RejectFirstChunk, 1, None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "notification publication scaling diagnostic; PUSH_RELAY selects an external relay"]
async fn push_batch_scaling() {
    let endpoint = std::env::var("PUSH_RELAY").ok();
    let environment = if endpoint.is_some() {
        "configured_endpoint"
    } else {
        "local_loopback"
    };
    for (label, mode) in [
        ("live_subscriptions", PushRelay::LiveSubscriptions),
        ("stopped_subscriptions", PushRelay::StoppedSubscriptions),
    ] {
        for tokens in [0, 19, 20, 32, 33, 128, 512] {
            let samples = push_batch_case(tokens, mode, 9, endpoint.as_deref()).await;
            let mut measured = samples[1..].to_vec();
            measured.sort_by(f64::total_cmp);
            eprintln!(
                "push_batch environment={environment} mode={label} tokens={tokens} samples={} mean_ms={:.3} median_ms={:.3} max_ms={:.3}",
                measured.len(),
                measured.iter().sum::<f64>() / measured.len() as f64,
                (measured[3] + measured[4]) / 2.0,
                measured.last().unwrap()
            );
        }
    }
}
