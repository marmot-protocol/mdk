use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use cgka_traits::transport::{Timestamp, TransportEnvelope};
use cgka_traits::{
    MemberId, TransportAccountActivation, TransportAdapter, TransportDeliveryPlane,
    TransportEndpoint, TransportGroupSubscription, TransportGroupSync, TransportPublishRequest,
    TransportPublishTarget,
};
use transport_nostr_adapter::{
    NostrPublishOutcome, NostrRelayClient, NostrRelayEvent, NostrSubscription,
    NostrTransportAdapter, RelayExportConsent, RelayIndex,
};
use transport_nostr_peeler::{KIND_MARMOT_GROUP_MESSAGE, NostrTransportEvent};

#[derive(Default)]
struct FakeRelayClient {
    subscriptions: Mutex<Vec<transport_nostr_adapter::NostrSubscription>>,
    unsubscribed: Mutex<Vec<transport_nostr_adapter::NostrSubscription>>,
    unsubscribed_accounts: Mutex<Vec<MemberId>>,
    published: Mutex<Vec<(Vec<TransportEndpoint>, NostrTransportEvent, usize)>>,
}

#[async_trait]
impl NostrRelayClient for FakeRelayClient {
    async fn subscribe(
        &self,
        subscription: transport_nostr_adapter::NostrSubscription,
    ) -> Result<(), cgka_traits::TransportAdapterError> {
        self.subscriptions.lock().unwrap().push(subscription);
        Ok(())
    }

    async fn unsubscribe(
        &self,
        subscription: transport_nostr_adapter::NostrSubscription,
    ) -> Result<(), cgka_traits::TransportAdapterError> {
        self.unsubscribed.lock().unwrap().push(subscription);
        Ok(())
    }

    async fn unsubscribe_account(
        &self,
        account_id: &MemberId,
    ) -> Result<(), cgka_traits::TransportAdapterError> {
        self.unsubscribed_accounts
            .lock()
            .unwrap()
            .push(account_id.clone());
        Ok(())
    }

    async fn publish_event(
        &self,
        endpoints: &[TransportEndpoint],
        event: &NostrTransportEvent,
        required_acks: usize,
    ) -> Result<NostrPublishOutcome, cgka_traits::TransportAdapterError> {
        self.published
            .lock()
            .unwrap()
            .push((endpoints.to_vec(), event.clone(), required_acks));
        Ok(NostrPublishOutcome::accepted(endpoints.to_vec()))
    }
}

#[tokio::test]
async fn group_subscription_id_fans_out_to_matching_accounts_and_replays_route_again() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay);
    let alice = MemberId::new(vec![0xA1; 32]);
    let bob = MemberId::new(vec![0xB2; 32]);
    let group_id = cgka_traits::GroupId::new(vec![0xC3; 32]);
    let transport_group_id = vec![0xD4; 32];
    let endpoint = TransportEndpoint("wss://group.example".into());
    let subscription = TransportGroupSubscription {
        group_id: group_id.clone(),
        transport_group_id: transport_group_id.clone(),
        endpoints: vec![endpoint.clone()],
    };

    adapter
        .activate_account(TransportAccountActivation {
            account_id: alice.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://alice-inbox.example".into())],
            group_subscriptions: vec![subscription.clone()],
            since: None,
        })
        .await
        .expect("alice activation succeeds");
    adapter
        .activate_account(TransportAccountActivation {
            account_id: bob.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://bob-inbox.example".into())],
            group_subscriptions: vec![subscription.clone()],
            since: None,
        })
        .await
        .expect("bob activation succeeds");

    let alice_subscription_id = NostrSubscription::Group {
        account_id: alice.clone(),
        group_id: group_id.clone(),
        transport_group_id: transport_group_id.clone(),
        endpoints: vec![endpoint.clone()],
        since: None,
    }
    .subscription_id();
    let bob_subscription_id = NostrSubscription::Group {
        account_id: bob.clone(),
        group_id: group_id.clone(),
        transport_group_id: transport_group_id.clone(),
        endpoints: vec![endpoint.clone()],
        since: None,
    }
    .subscription_id();

    let delivered = adapter
        .handle_relay_event(NostrRelayEvent {
            endpoint: endpoint.clone(),
            subscription_id: Some(alice_subscription_id),
            event: group_event("20", &transport_group_id),
        })
        .await
        .expect("relay event handled");

    assert_eq!(delivered, 2);
    let first = adapter.receive().await.unwrap().unwrap();
    let second = adapter.receive().await.unwrap().unwrap();
    let accounts = [first.account_id.clone(), second.account_id.clone()];
    assert!(accounts.contains(&alice));
    assert!(accounts.contains(&bob));
    assert_eq!(first.group_id_hint, Some(group_id.clone()));
    assert_eq!(second.group_id_hint, Some(group_id));

    let replayed = adapter
        .handle_relay_event(NostrRelayEvent {
            endpoint,
            subscription_id: Some(bob_subscription_id),
            event: group_event("20", &transport_group_id),
        })
        .await
        .expect("duplicate relay event handled");

    assert_eq!(replayed, 2);
    let first_replay = adapter.receive().await.unwrap().unwrap();
    let second_replay = adapter.receive().await.unwrap().unwrap();
    let replay_accounts = [
        first_replay.account_id.clone(),
        second_replay.account_id.clone(),
    ];
    assert!(replay_accounts.contains(&alice));
    assert!(replay_accounts.contains(&bob));
}

#[tokio::test]
async fn subscribed_group_event_becomes_account_scoped_delivery() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account_id = MemberId::new(vec![0xA1; 32]);
    let group_id = cgka_traits::GroupId::new(vec![0xB2; 32]);
    let transport_group_id = vec![0xC3; 32];
    let endpoint = TransportEndpoint("wss://group.example".into());

    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://inbox.example".into())],
            group_subscriptions: vec![TransportGroupSubscription {
                group_id: group_id.clone(),
                transport_group_id: transport_group_id.clone(),
                endpoints: vec![endpoint.clone()],
            }],
            since: Some(Timestamp(1_700_000_000)),
        })
        .await
        .expect("activation succeeds");

    let event = group_event("11", &transport_group_id);

    let delivered = adapter
        .handle_relay_event(NostrRelayEvent {
            endpoint: endpoint.clone(),
            subscription_id: Some("group-sub".into()),
            event,
        })
        .await
        .expect("relay event handled");

    assert_eq!(delivered, 1);
    let delivery = adapter
        .receive()
        .await
        .expect("receive succeeds")
        .expect("delivery available");

    assert_eq!(delivery.account_id, account_id);
    assert_eq!(delivery.group_id_hint, Some(group_id));
    assert_eq!(delivery.source.plane, TransportDeliveryPlane::Group);
    assert_eq!(delivery.source.endpoint, Some(endpoint));
    assert_eq!(
        delivery.source.subscription_id.as_deref(),
        Some("group-sub")
    );
    assert_eq!(
        delivery.message.envelope,
        TransportEnvelope::GroupMessage { transport_group_id }
    );
}

#[tokio::test]
async fn observe_relay_event_records_every_relay_copy_for_spread() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay);
    let transport_group_id = vec![0xC3; 32];
    let endpoints = [
        TransportEndpoint("wss://group-a.example".into()),
        TransportEndpoint("wss://group-b.example".into()),
        TransportEndpoint("wss://group-c.example".into()),
    ];

    // The same logical event seen from three relays on the raw per-relay tap.
    for endpoint in &endpoints {
        adapter
            .observe_relay_event(NostrRelayEvent {
                endpoint: endpoint.clone(),
                subscription_id: Some("group-sub".into()),
                event: group_event("11", &transport_group_id),
            })
            .await;
    }

    let spread = adapter.delivery_spread().await;
    assert_eq!(spread.observed, 1, "one logical message observed");
    assert_eq!(spread.corroborated, 1, "corroborated by later relay copies");
    assert_eq!(
        spread.spread.sample_count(),
        2,
        "two laggard copies recorded as spread samples"
    );
    // Per-relay attribution: the first relay delivered first, the rest later.
    // Indices are assigned in first-seen order (a, b, c) and reported ascending.
    assert_eq!(spread.per_relay.len(), 3);
    assert_eq!(spread.per_relay[0].delivered_first, 1);
    assert_eq!(spread.per_relay[0].first_deliverer_rate(), Some(1.0));
    assert_eq!(spread.per_relay[1].delivered_later, 1);
    assert_eq!(spread.per_relay[2].delivered_later, 1);
}

#[tokio::test]
async fn resolve_relay_labels_maps_observed_indices_to_endpoints() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay);
    let transport_group_id = vec![0xC3; 32];
    let endpoints = [
        TransportEndpoint("wss://group-a.example".into()),
        TransportEndpoint("wss://group-b.example".into()),
    ];

    // Observing per-relay copies assigns opaque indices in first-seen order.
    for endpoint in &endpoints {
        adapter
            .observe_relay_event(NostrRelayEvent {
                endpoint: endpoint.clone(),
                subscription_id: Some("group-sub".into()),
                event: group_event("11", &transport_group_id),
            })
            .await;
    }

    // The export boundary resolves those indices back to relay URLs, but only
    // when handed an explicit opt-in consent token.
    let resolution = adapter
        .resolve_relay_labels(RelayExportConsent::affirm())
        .await;
    assert_eq!(resolution.len(), 2);
    assert_eq!(resolution.label_for(RelayIndex(0)), Some(&endpoints[0]));
    assert_eq!(resolution.label_for(RelayIndex(1)), Some(&endpoints[1]));
    assert_eq!(resolution.label_for(RelayIndex(2)), None);
}

#[tokio::test]
async fn deduplicated_delivery_path_does_not_record_spread() {
    // The relay pool delivers one deduplicated `Event` per message, so the
    // delivery path must never feed cross-relay spread; otherwise the metric
    // would only ever see the first relay's copy.
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay);
    let transport_group_id = vec![0xC3; 32];

    adapter
        .handle_relay_event(NostrRelayEvent {
            endpoint: TransportEndpoint("wss://group.example".into()),
            subscription_id: Some("group-sub".into()),
            event: group_event("11", &transport_group_id),
        })
        .await
        .expect("relay event handled");

    let spread = adapter.delivery_spread().await;
    assert_eq!(spread.observed, 0, "delivery path must not feed spread");
    assert_eq!(spread.spread.sample_count(), 0);
}

#[tokio::test]
async fn initial_sync_gate_closes_only_after_every_endpoint_eoses() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account_id = MemberId::new(vec![0xA1; 32]);
    let group_id = cgka_traits::GroupId::new(vec![0xB2; 32]);
    let transport_group_id = vec![0xC3; 32];
    let endpoint_a = TransportEndpoint("wss://group-a.example".into());
    let endpoint_b = TransportEndpoint("wss://group-b.example".into());

    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://inbox.example".into())],
            group_subscriptions: vec![TransportGroupSubscription {
                group_id: group_id.clone(),
                transport_group_id: transport_group_id.clone(),
                endpoints: vec![endpoint_a.clone(), endpoint_b.clone()],
            }],
            since: None,
        })
        .await
        .expect("activation succeeds");

    // Reconstruct the group subscription id the adapter issued.
    let sub_id = NostrSubscription::Group {
        account_id,
        group_id,
        transport_group_id: transport_group_id.clone(),
        endpoints: vec![endpoint_a.clone(), endpoint_b.clone()],
        since: None,
    }
    .subscription_id();

    // Tracked but not yet synced: no endpoint has reached EOSE.
    assert_eq!(adapter.subscription_synced(&sub_id).await, Some(false));

    // A first event (observed on the per-relay tap) then EOSE from endpoint A:
    // still draining endpoint B.
    adapter
        .observe_relay_event(NostrRelayEvent {
            endpoint: endpoint_a.clone(),
            subscription_id: Some(sub_id.clone()),
            event: group_event("11", &transport_group_id),
        })
        .await;
    adapter.handle_relay_eose(endpoint_a, sub_id.clone()).await;
    assert_eq!(adapter.subscription_synced(&sub_id).await, Some(false));

    // EOSE from endpoint B closes the gate.
    adapter.handle_relay_eose(endpoint_b, sub_id.clone()).await;
    assert_eq!(adapter.subscription_synced(&sub_id).await, Some(true));

    let sync = adapter.relay_sync().await;
    // Inbox + group subscriptions are both tracked.
    assert_eq!(sync.tracked_subscriptions, 2);
    assert_eq!(sync.synced_subscriptions, 1);
    assert_eq!(sync.eose.sample_count(), 2);
    assert_eq!(sync.first_event.sample_count(), 1);

    // Unknown subscriptions report no sync state.
    assert_eq!(adapter.subscription_synced("nope").await, None);
}

#[tokio::test]
async fn synced_group_subscriptions_replace_old_routes() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account_id = MemberId::new(vec![0xA1; 32]);
    let old_group_id = cgka_traits::GroupId::new(vec![0xB2; 32]);
    let old_transport_group_id = vec![0xC3; 32];
    let new_group_id = cgka_traits::GroupId::new(vec![0xD4; 32]);
    let new_transport_group_id = vec![0xE5; 32];
    let endpoint = TransportEndpoint("wss://group.example".into());

    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://inbox.example".into())],
            group_subscriptions: vec![TransportGroupSubscription {
                group_id: old_group_id,
                transport_group_id: old_transport_group_id.clone(),
                endpoints: vec![endpoint.clone()],
            }],
            since: None,
        })
        .await
        .expect("activation succeeds");
    adapter
        .sync_account_groups(TransportGroupSync {
            account_id,
            group_subscriptions: vec![TransportGroupSubscription {
                group_id: new_group_id.clone(),
                transport_group_id: new_transport_group_id.clone(),
                endpoints: vec![endpoint.clone()],
            }],
            since: Some(Timestamp(1_700_000_100)),
        })
        .await
        .expect("sync succeeds");

    let old_delivered = adapter
        .handle_relay_event(NostrRelayEvent {
            endpoint: endpoint.clone(),
            subscription_id: Some("old-group-sub".into()),
            event: group_event("12", &old_transport_group_id),
        })
        .await
        .expect("old relay event handled");
    let new_delivered = adapter
        .handle_relay_event(NostrRelayEvent {
            endpoint,
            subscription_id: Some("new-group-sub".into()),
            event: group_event("13", &new_transport_group_id),
        })
        .await
        .expect("new relay event handled");

    assert_eq!(old_delivered, 0);
    assert_eq!(new_delivered, 1);
    let delivery = adapter.receive().await.unwrap().unwrap();
    assert_eq!(delivery.group_id_hint, Some(new_group_id));

    let unsubscribed = relay.unsubscribed.lock().unwrap();
    assert_eq!(
        unsubscribed.as_slice(),
        &[transport_nostr_adapter::NostrSubscription::Group {
            account_id: MemberId::new(vec![0xA1; 32]),
            group_id: cgka_traits::GroupId::new(vec![0xB2; 32]),
            transport_group_id: old_transport_group_id,
            endpoints: vec![TransportEndpoint("wss://group.example".into())],
            since: None,
        }]
    );
}

#[tokio::test]
async fn adapter_metrics_record_routing_publish_and_stale_cleanup() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay);
    let account_id = MemberId::new(vec![0xA1; 32]);
    let group_id = cgka_traits::GroupId::new(vec![0xB2; 32]);
    let old_transport_group_id = vec![0xC3; 32];
    let new_transport_group_id = vec![0xD4; 32];
    let endpoint = TransportEndpoint("wss://group.example".into());

    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://inbox.example".into())],
            group_subscriptions: vec![TransportGroupSubscription {
                group_id: group_id.clone(),
                transport_group_id: old_transport_group_id.clone(),
                endpoints: vec![endpoint.clone()],
            }],
            since: None,
        })
        .await
        .expect("activation succeeds");
    adapter
        .handle_relay_event(NostrRelayEvent {
            endpoint: endpoint.clone(),
            subscription_id: Some("matched".into()),
            event: group_event("15", &old_transport_group_id),
        })
        .await
        .expect("matched relay event handled");
    adapter
        .handle_relay_event(NostrRelayEvent {
            endpoint: endpoint.clone(),
            subscription_id: Some("dropped".into()),
            event: group_event("16", &[0xEE; 32]),
        })
        .await
        .expect("unmatched relay event handled");
    let message = group_event("17", &old_transport_group_id)
        .to_transport_message()
        .expect("event maps");
    adapter
        .publish(TransportPublishRequest {
            account_id: account_id.clone(),
            message,
            target: TransportPublishTarget::Group {
                group_id: group_id.clone(),
                transport_group_id: old_transport_group_id.clone(),
                endpoints: vec![endpoint.clone()],
            },
            required_acks: 1,
        })
        .await
        .expect("publish succeeds");
    adapter
        .sync_account_groups(TransportGroupSync {
            account_id,
            group_subscriptions: vec![TransportGroupSubscription {
                group_id,
                transport_group_id: new_transport_group_id,
                endpoints: vec![endpoint],
            }],
            since: None,
        })
        .await
        .expect("sync succeeds");

    let metrics = adapter.metrics().await;
    assert_eq!(metrics.active_accounts, 1);
    assert_eq!(metrics.active_group_subscriptions, 1);
    assert_eq!(metrics.subscriptions_created, 3);
    assert_eq!(metrics.subscriptions_removed, 1);
    assert_eq!(metrics.inbound_events_seen, 2);
    assert_eq!(metrics.inbound_events_delivered, 1);
    assert_eq!(metrics.inbound_events_dropped, 1);
    assert_eq!(metrics.publish_attempts, 1);
    assert_eq!(metrics.publish_successes, 1);
    assert_eq!(metrics.publish_failures, 0);
}

#[tokio::test]
async fn group_sync_treats_endpoint_order_as_the_same_subscription() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account_id = MemberId::new(vec![0xA1; 32]);
    let group_id = cgka_traits::GroupId::new(vec![0xB2; 32]);
    let transport_group_id = vec![0xC3; 32];
    let endpoint_a = TransportEndpoint("wss://a.example".into());
    let endpoint_b = TransportEndpoint("wss://b.example".into());

    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://inbox.example".into())],
            group_subscriptions: vec![TransportGroupSubscription {
                group_id: group_id.clone(),
                transport_group_id: transport_group_id.clone(),
                endpoints: vec![endpoint_a.clone(), endpoint_b.clone()],
            }],
            since: None,
        })
        .await
        .expect("activation succeeds");
    adapter
        .sync_account_groups(TransportGroupSync {
            account_id,
            group_subscriptions: vec![TransportGroupSubscription {
                group_id,
                transport_group_id,
                endpoints: vec![endpoint_b, endpoint_a],
            }],
            since: Some(Timestamp(1_700_000_100)),
        })
        .await
        .expect("sync succeeds");

    assert_eq!(relay.subscriptions.lock().unwrap().len(), 2);
    assert!(relay.unsubscribed.lock().unwrap().is_empty());
    let metrics = adapter.metrics().await;
    assert_eq!(metrics.subscriptions_created, 2);
    assert_eq!(metrics.subscriptions_removed, 0);
}

#[tokio::test]
async fn activating_existing_account_replaces_old_relay_state() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account_id = MemberId::new(vec![0xA1; 32]);
    let old_group_id = cgka_traits::GroupId::new(vec![0xB2; 32]);
    let old_transport_group_id = vec![0xC3; 32];
    let new_group_id = cgka_traits::GroupId::new(vec![0xD4; 32]);
    let new_transport_group_id = vec![0xE5; 32];
    let endpoint = TransportEndpoint("wss://group.example".into());

    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://old-inbox.example".into())],
            group_subscriptions: vec![TransportGroupSubscription {
                group_id: old_group_id,
                transport_group_id: old_transport_group_id.clone(),
                endpoints: vec![endpoint.clone()],
            }],
            since: None,
        })
        .await
        .expect("first activation succeeds");
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://new-inbox.example".into())],
            group_subscriptions: vec![TransportGroupSubscription {
                group_id: new_group_id.clone(),
                transport_group_id: new_transport_group_id.clone(),
                endpoints: vec![endpoint.clone()],
            }],
            since: Some(Timestamp(1_700_000_100)),
        })
        .await
        .expect("second activation succeeds");

    assert_eq!(
        relay.unsubscribed_accounts.lock().unwrap().as_slice(),
        std::slice::from_ref(&account_id)
    );
    let old_delivered = adapter
        .handle_relay_event(NostrRelayEvent {
            endpoint: endpoint.clone(),
            subscription_id: Some("old-group-sub".into()),
            event: group_event("18", &old_transport_group_id),
        })
        .await
        .expect("old relay event handled");
    let new_delivered = adapter
        .handle_relay_event(NostrRelayEvent {
            endpoint,
            subscription_id: Some("new-group-sub".into()),
            event: group_event("19", &new_transport_group_id),
        })
        .await
        .expect("new relay event handled");

    assert_eq!(old_delivered, 0);
    assert_eq!(new_delivered, 1);
    let delivery = adapter.receive().await.unwrap().unwrap();
    assert_eq!(delivery.group_id_hint, Some(new_group_id));
    let metrics = adapter.metrics().await;
    assert_eq!(metrics.active_accounts, 1);
    assert_eq!(metrics.active_group_subscriptions, 1);
    assert_eq!(metrics.subscriptions_created, 4);
    assert_eq!(metrics.subscriptions_removed, 2);
}

#[tokio::test]
async fn publish_group_message_sends_nostr_event_to_target_endpoints() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account_id = MemberId::new(vec![0xA1; 32]);
    let group_id = cgka_traits::GroupId::new(vec![0xB2; 32]);
    let transport_group_id = vec![0xC3; 32];
    let endpoint = TransportEndpoint("wss://group.example".into());
    let event = group_event("14", &transport_group_id);
    let message = event.to_transport_message().expect("event maps");

    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://inbox.example".into())],
            group_subscriptions: vec![TransportGroupSubscription {
                group_id: group_id.clone(),
                transport_group_id: transport_group_id.clone(),
                endpoints: vec![endpoint.clone()],
            }],
            since: None,
        })
        .await
        .expect("activation succeeds");

    let report = adapter
        .publish(TransportPublishRequest {
            account_id,
            message,
            target: TransportPublishTarget::Group {
                group_id,
                transport_group_id,
                endpoints: vec![endpoint.clone()],
            },
            required_acks: 1,
        })
        .await
        .expect("publish succeeds");

    assert!(report.met_required_acks());
    assert_eq!(report.accepted[0].endpoint, endpoint);
    let published = relay.published.lock().unwrap();
    assert_eq!(published.len(), 1);
    assert_eq!(published[0].0, vec![endpoint]);
    assert_eq!(published[0].1, event);
    assert_eq!(published[0].2, 1);
}

#[tokio::test]
async fn signed_welcome_event_becomes_account_inbox_delivery() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay);
    let sender =
        nostr::Keys::parse("6b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e")
            .unwrap();
    let receiver =
        nostr::Keys::parse("7b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e")
            .unwrap();
    let account_id = MemberId::new(receiver.public_key().to_bytes().to_vec());
    let inbox_endpoint = TransportEndpoint("wss://inbox.example".into());

    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![inbox_endpoint.clone()],
            group_subscriptions: vec![],
            since: None,
        })
        .await
        .expect("activation succeeds");

    let rumor = nostr::EventBuilder::text_note("not yet peeled here").build(sender.public_key());
    let gift_wrap = nostr::EventBuilder::gift_wrap(&sender, &receiver.public_key(), rumor, [])
        .await
        .unwrap();
    let event = NostrTransportEvent::from_nostr_event(&gift_wrap).unwrap();

    let delivered = adapter
        .handle_relay_event(NostrRelayEvent {
            endpoint: inbox_endpoint.clone(),
            subscription_id: Some("inbox-sub".into()),
            event,
        })
        .await
        .expect("relay event handled");

    assert_eq!(delivered, 1);
    let delivery = adapter.receive().await.unwrap().unwrap();
    assert_eq!(delivery.account_id, account_id);
    assert_eq!(delivery.group_id_hint, None);
    assert_eq!(delivery.source.plane, TransportDeliveryPlane::AccountInbox);
    assert_eq!(delivery.source.endpoint, Some(inbox_endpoint));
    assert_eq!(
        delivery.source.subscription_id.as_deref(),
        Some("inbox-sub")
    );
    assert_eq!(
        delivery.message.envelope,
        TransportEnvelope::Welcome {
            recipient: account_id
        }
    );
}

#[tokio::test]
async fn inbox_subscription_since_is_widened_by_the_nip59_tweak_window() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account_id = MemberId::new(vec![0xA1; 32]);
    let cursor = 1_700_000_000_u64;

    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://inbox.example".into())],
            group_subscriptions: vec![TransportGroupSubscription {
                group_id: cgka_traits::GroupId::new(vec![0xC3; 32]),
                transport_group_id: vec![0xD4; 32],
                endpoints: vec![TransportEndpoint("wss://group.example".into())],
            }],
            since: Some(Timestamp(cursor)),
        })
        .await
        .expect("activation succeeds");

    let issued = relay.subscriptions.lock().unwrap().clone();
    let inbox_since = issued
        .iter()
        .find_map(|subscription| match subscription {
            NostrSubscription::AccountInbox { since, .. } => Some(since.clone()),
            _ => None,
        })
        .expect("inbox subscription issued");
    let group_since = issued
        .iter()
        .find_map(|subscription| match subscription {
            NostrSubscription::Group { since, .. } => Some(since.clone()),
            _ => None,
        })
        .expect("group subscription issued");

    // Welcomes arrive as NIP-59 gift wraps whose created_at is backdated up to
    // the full tweak range; the inbox window must reach that far back or
    // welcomes published while offline are skipped.
    assert_eq!(
        inbox_since,
        Some(Timestamp(
            cursor - transport_nostr_adapter::NIP59_TIMESTAMP_TWEAK_SECS
        ))
    );
    assert_eq!(group_since, Some(Timestamp(cursor)));
}

#[tokio::test]
async fn inbox_subscription_since_saturates_at_zero() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());

    adapter
        .activate_account(TransportAccountActivation {
            account_id: MemberId::new(vec![0xA1; 32]),
            inbox_endpoints: vec![TransportEndpoint("wss://inbox.example".into())],
            group_subscriptions: vec![],
            since: Some(Timestamp(1)),
        })
        .await
        .expect("activation succeeds");

    let issued = relay.subscriptions.lock().unwrap().clone();
    let inbox_since = issued
        .iter()
        .find_map(|subscription| match subscription {
            NostrSubscription::AccountInbox { since, .. } => Some(since.clone()),
            _ => None,
        })
        .expect("inbox subscription issued");
    assert_eq!(inbox_since, Some(Timestamp(0)));
}

fn group_event(id_byte: &str, transport_group_id: &[u8]) -> NostrTransportEvent {
    NostrTransportEvent {
        id: id_byte.repeat(32),
        pubkey: "22".repeat(32),
        created_at: 1_700_000_010,
        kind: KIND_MARMOT_GROUP_MESSAGE,
        tags: vec![vec!["h".into(), hex::encode(transport_group_id)]],
        content: "outer encrypted body".into(),
        sig: None,
    }
}
