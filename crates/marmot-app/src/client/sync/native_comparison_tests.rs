//! Real MLS coverage for native replay ingress: leased native batches, slow
//! peers, failures and cursor checkpoints.

use super::*;
use crate::messages::{AppMessageIntent, build_inner_event, encode_inner_event};
use crate::tests::{
    ScriptedPushRelayClient, client_on_app_relay_plane, remember_test_member_inbox,
};
use cgka_traits::engine::SendIntent;
use cgka_traits::{TransportAccountActivation, TransportAdapter};
use marmot_session::PublishWork;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use transport_nostr_adapter::{NostrRelayEvent, ReplayBatchTake};
use transport_nostr_peeler::NostrTransportEvent;

const TEXTS: usize = 212;
const ENDPOINT: &str = "wss://relay.example";

mod future_cursor_tests;
mod live_rejoin_tests;
mod native_failure_tests;

struct CryptoFixture {
    _dir: tempfile::TempDir,
    relay: Arc<ScriptedPushRelayClient>,
    sender: AppClient,
    receiver: AppClient,
    group: GroupId,
}

async fn crypto_fixture() -> CryptoFixture {
    let dir = tempfile::tempdir().unwrap();
    let home = crate::AccountHome::open(dir.path());
    home.create_account("sender").unwrap();
    let recipient = home.create_account("receiver").unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app =
        crate::MarmotApp::with_relay(dir.path(), ENDPOINT).with_test_relay_client(relay.clone());
    remember_test_member_inbox(&app, &recipient.account_id_hex, ENDPOINT);
    let mut receiver = client_on_app_relay_plane(&app, "receiver").await;
    receiver.publish_key_package().await.unwrap();
    receiver.prepare_transport().await.unwrap();
    let mut sender = client_on_app_relay_plane(&app, "sender").await;
    let group = sender
        .create_group("mixed ingress plaintext", &[&recipient.account_id_hex])
        .await
        .unwrap()
        .operation
        .expect("eligible fixture members");
    assert!(
        receiver
            .sync()
            .await
            .unwrap()
            .joined_groups
            .contains(&group)
    );
    assert_eq!(
        receiver.runtime.group_record(&group).unwrap().members.len(),
        2
    );
    receiver.take_pending_applied_sync_summary();
    receiver.take_pending_projection_updates();
    CryptoFixture {
        _dir: dir,
        relay,
        sender,
        receiver,
        group,
    }
}

async fn encrypted_texts(
    sender: &mut AppClient,
    group: &GroupId,
) -> (Vec<NostrRelayEvent>, BTreeMap<String, String>) {
    let mut events = Vec::with_capacity(TEXTS);
    let mut expected = BTreeMap::new();
    let author = sender
        .app
        .account_home()
        .account(&sender.state.label)
        .unwrap()
        .account_id_hex;
    let since = unix_now_seconds().saturating_sub(30);
    for index in 0..TEXTS {
        let text = format!("mixed ingress real plaintext {index:03}");
        // Keep at most forty generations in each timestamp bucket. Random
        // outer event IDs can then reorder a bucket without exceeding the
        // unchanged production skipped-key tolerance of one hundred.
        let inner = build_inner_event(
            &AppMessageIntent::Chat {
                content: text.clone(),
            },
            &author,
            since + index as u64 / 40,
        )
        .unwrap();
        expected.insert(inner.id.clone(), text);
        // Capture a real session send before publication: neither source is
        // accidentally delivered through the live fanout during generation.
        let effects = sender
            .runtime
            .session_mut()
            .send(SendIntent::AppMessage {
                group_id: group.clone(),
                payload: encode_inner_event(&inner).unwrap(),
                expected_epoch: None,
            })
            .await
            .unwrap();
        assert!(effects.queued.is_empty());
        let mut published = effects.publish.into_iter();
        let Some(PublishWork::ApplicationMessage { msg, .. }) = published.next() else {
            panic!("a real MLS application send must produce its encrypted envelope");
        };
        assert!(published.next().is_none());
        let event = NostrTransportEvent::from_transport_message(&msg).unwrap();
        assert_eq!(event.created_at, inner.created_at);
        event.to_verified_nostr_event().unwrap();
        events.push(NostrRelayEvent {
            endpoint: cgka_traits::TransportEndpoint(ENDPOINT.into()),
            subscription_id: None,
            event,
        });
    }
    (events, expected)
}

async fn lease_native(client: &mut AppClient, group: &GroupId, events: Vec<NostrRelayEvent>) {
    let mut deliveries = Vec::with_capacity(events.len());
    for event in events {
        let mut recovered = client.adapter.recovered_deliveries(event).await.unwrap();
        assert_eq!(recovered.len(), 1);
        let delivery = recovered.pop().unwrap();
        assert_eq!(delivery.group_id_hint.as_ref(), Some(group));
        deliveries.push(delivery);
    }
    assert!(client.recovery_owner.native_batch.is_none());
    client.recovery_owner.native_ingress = None;
    // Retained native input is a real ingress source: for example, a restart
    // can retain old spill bodies after a relay has pruned them to a newer
    // comparison subset. Acquire its actual lease before the owner joins the
    // already finished comparison, not merely an ordered vector of mock DTOs.
    let mut ingress = client
        .adapter
        .open_replay_ingress(deliveries)
        .await
        .unwrap();
    let batch = timeout(Duration::from_secs(30), async {
        loop {
            let mut changes = client.adapter.replay_changes().await;
            match ingress.take_batch(Some(group)).await {
                ReplayBatchTake::Ready(batch) => break batch,
                ReplayBatchTake::Pending => {
                    super::native_ingress::wait_native_change(&mut changes).await;
                }
                ReplayBatchTake::Empty => panic!("retained native input must own a group range"),
            }
        }
    })
    .await
    .expect("native source reaches its complete group boundary");
    // The first timestamp bucket is deliberately not assumed to preserve
    // sender order; it is smaller than the real skipped-key tolerance.
    assert!(batch.delivery().is_some());
    client.recovery_owner.native_ingress = Some(ingress);
    client.recovery_owner.native_batch = Some(batch);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_peer_keeps_plaintext() {
    timeout(Duration::from_secs(120), async {
        assert_eq!(cgka_engine::wire_format::DEFAULT_OUT_OF_ORDER_TOLERANCE, 100);
        let mut fixture = crypto_fixture().await;
        let (events, expected) = encrypted_texts(&mut fixture.sender, &fixture.group).await;
        let first = fixture.receiver.adapter.recovered_deliveries(events[0].clone()).await.unwrap().pop().unwrap();
        let TransportEnvelope::GroupMessage { transport_group_id } = first.message.envelope else {
            panic!("the fixture must produce actual MLS group ciphertext");
        };
        let account = first.account_id;
        let fast = cgka_traits::TransportEndpoint(ENDPOINT.into());
        let slow = cgka_traits::TransportEndpoint("wss://slow.example".into());
        // Separate scripted relay streams feed the real adapter/ingress, not
        // pre-sorted DTOs or retained local copies. The receiver still uses its
        // ordinary recovery-owner ingest, MLS state and durable projections.
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let adapter = transport_nostr_adapter::NostrTransportAdapter::new(relay.clone());
        fixture.receiver.recovery_owner.native_batch = None;
        fixture.receiver.recovery_owner.native_ingress = None;
        let ingress = adapter.open_replay_ingress(&account, Vec::new()).await.unwrap();
        adapter.activate_account(TransportAccountActivation {
            account_id: account.clone(),
            inbox_endpoints: Vec::new(),
            group_subscriptions: vec![cgka_traits::TransportGroupSubscription {
                group_id: fixture.group.clone(),
                transport_group_id,
                endpoints: vec![fast.clone(), slow.clone()],
                retained_since: None,
            }],
            since: None,
        }).await.unwrap();
        let id = relay.accepted_subscriptions().into_iter().find(|subscription| subscription.carries_group(&fixture.group)).unwrap().subscription_id();
        fixture.receiver.recovery_owner.native_ingress = Some(ingress);
        let started = tokio::time::Instant::now();
        for event in events[180..].iter().rev() {
            let mut event = event.clone();
            event.subscription_id = Some(id.clone());
            adapter.observe_relay_event(&hex::decode(&event.event.id).unwrap(), &event.endpoint, event.subscription_id.as_deref(), event.event.created_at).await;
            adapter.handle_group_relay_copy(event, Some(&account)).await.unwrap();
        }
        adapter.handle_relay_eose(fast, id.clone()).await;
        assert!(adapter.take_replay_status(&account).await.pending);
        assert!(!adapter.account_subscription_eose(&account).await.complete());
        for _ in 0..3 {
            assert!(
                !fixture.receiver.admit_native_turn().await.unwrap(),
                "a complete newer subset must not advance MLS while an in-deadline peer still owes its first payload"
            );
        }
        assert!(fixture.receiver.take_pending_applied_sync_summary().messages.is_empty());
        let storage = fixture.receiver.app.account_storage("receiver").unwrap().app_storage();
        let query = || storage_sqlite::StoredAppMessageQuery {
            group_id_hex: Some(hex::encode(fixture.group.as_slice())),
            kinds: Some(vec![MARMOT_APP_EVENT_KIND_CHAT]),
            limit: None,
        };
        assert!(storage.app_messages(query()).unwrap().is_empty(), "no newer plaintext may be committed early");
        // The prefix spans more than one hundred generations. Releasing even
        // one newer frame above would evict skipped keys needed by this prefix.
        for event in events[..180].iter().rev() {
            let mut event = event.clone();
            event.endpoint = slow.clone();
            event.subscription_id = Some(id.clone());
            adapter.observe_relay_event(&hex::decode(&event.event.id).unwrap(), &event.endpoint, event.subscription_id.as_deref(), event.event.created_at).await;
            adapter.handle_group_relay_copy(event, Some(&account)).await.unwrap();
        }
        assert!(started.elapsed() < Duration::from_secs(30), "the older prefix arrives inside the production service lease");
        assert!(!fixture.receiver.admit_native_turn().await.unwrap(), "payload arrival alone does not settle the older source");
        adapter.handle_relay_eose(slow, id).await;
        for turn in 0..=TEXTS {
            if !fixture.receiver.admit_native_turn().await.unwrap() {
                break;
            }
            assert!(turn < TEXTS, "settled replay drains in bounded native turns");
        }
        let summary = fixture.receiver.take_pending_applied_sync_summary();
        assert_eq!(summary.messages.len(), TEXTS);
        assert_eq!(summary.messages.into_iter().map(|message| (message.message_id_hex, message.plaintext)).collect::<BTreeMap<_, _>>(), expected);
        let persisted = storage.app_messages(query()).unwrap();
        assert_eq!(persisted.len(), TEXTS);
        assert!(persisted.iter().all(|message| !message.invalidated));
        assert_eq!(persisted.into_iter().map(|message| (message.message_id_hex, message.plaintext)).collect::<BTreeMap<_, _>>(), expected, "every actual MLS plaintext must survive the slow-peer boundary");
        let status = adapter.take_replay_status(&account).await;
        assert!(!status.pending);
        assert!(status.loss.is_none());
    }).await.expect("bounded real MLS slow-peer regression");
}
