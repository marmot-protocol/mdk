use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_publish_keeps_history() {
    timeout(Duration::from_secs(120), async {
        assert_eq!(cgka_engine::wire_format::DEFAULT_OUT_OF_ORDER_TOLERANCE, 100);
        let mut fixture = crypto_fixture().await;
        let (events, expected) = encrypted_texts(&mut fixture.sender, &fixture.group).await;
        let first = fixture.receiver.adapter.recovered_deliveries(events[0].clone()).await.unwrap().pop().unwrap();
        let TransportEnvelope::GroupMessage { transport_group_id } = first.message.envelope else {
            panic!("the fixture produces real MLS group ciphertext");
        };
        let account = first.account_id;
        let sender = cgka_traits::MemberId::new(hex::decode(fixture.sender.app.account_home().account("sender").unwrap().account_id_hex).unwrap());
        assert_ne!(sender, account);
        let endpoint = cgka_traits::TransportEndpoint(ENDPOINT.into());
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let adapter = transport_nostr_adapter::NostrTransportAdapter::new(relay.clone());
        let group = cgka_traits::TransportGroupSubscription {
            group_id: fixture.group.clone(),
            transport_group_id,
            endpoints: vec![endpoint.clone()],
            retained_since: None,
        };
        // Both real account identities are locally active. The sender keeps a
        // legacy adapter consumer, while the receiver owns native replay.
        adapter.activate_account(TransportAccountActivation {
            account_id: sender.clone(),
            inbox_endpoints: Vec::new(),
            group_subscriptions: vec![group.clone()],
            since: None,
        }).await.unwrap();
        fixture.receiver.recovery_owner.native_batch = None;
        fixture.receiver.recovery_owner.native_ingress = None;
        let ingress = adapter.open_replay_ingress(&account, Vec::new()).await.unwrap();
        adapter.activate_account(TransportAccountActivation {
            account_id: account.clone(),
            inbox_endpoints: Vec::new(),
            group_subscriptions: vec![group],
            since: None,
        }).await.unwrap();
        fixture.receiver.recovery_owner.native_ingress = Some(ingress);
        let id = relay.accepted_subscriptions().into_iter().find(|subscription| subscription.account_id() == &account && subscription.carries_group(&fixture.group)).unwrap().subscription_id();
        for event in events[..180].iter().rev() {
            let mut event = event.clone();
            event.subscription_id = Some(id.clone());
            adapter.observe_relay_event(&hex::decode(&event.event.id).unwrap(), &event.endpoint, event.subscription_id.as_deref(), event.event.created_at).await;
            adapter.handle_group_relay_copy(event, Some(&account)).await.unwrap();
        }
        // A newer real send is locally fanned out before the receiver's older
        // history reaches EOF. Publication must not introduce a second group
        // lane or pretend to settle that historical source.
        for event in &events[180..] {
            let message = event.event.to_transport_message().unwrap();
            assert_eq!(adapter.deliver_local_publish(&message, std::slice::from_ref(&endpoint)).await.unwrap(), 2);
        }
        let mut legacy = BTreeSet::new();
        for _ in 180..TEXTS {
            let delivery = timeout(Duration::from_secs(5), adapter.receive()).await.unwrap().unwrap().unwrap();
            assert_eq!(delivery.account_id, sender, "only the legacy-only account may receive local group fanout through the ordinary queue");
            assert_eq!(delivery.source.subscription_id.as_deref(), Some("local-publish"));
            assert!(delivery.source.wire.is_none());
            legacy.insert(hex::encode(delivery.message.id.as_slice()));
        }
        assert_eq!(legacy, events[180..].iter().map(|event| event.event.id.clone()).collect::<BTreeSet<_>>());
        assert!(timeout(Duration::from_millis(25), adapter.receive()).await.is_err(), "the native receiver's local fanout never enters the ordinary queue");
        assert!(!adapter.account_subscription_eose(&account).await.complete());
        assert!(!fixture.receiver.admit_native_turn().await.unwrap(), "new local ciphertext cannot overtake an in-deadline historical prefix");
        assert!(fixture.receiver.take_pending_applied_sync_summary().messages.is_empty());
        adapter.handle_relay_eose(endpoint, id).await;
        for turn in 0..=TEXTS {
            if !fixture.receiver.admit_native_turn().await.unwrap() {
                break;
            }
            assert!(turn < TEXTS, "the combined group lane drains in bounded owner turns");
        }
        let summary = fixture.receiver.take_pending_applied_sync_summary();
        assert_eq!(summary.messages.len(), TEXTS);
        assert_eq!(summary.messages.into_iter().map(|message| (message.message_id_hex, message.plaintext)).collect::<BTreeMap<_, _>>(), expected);
        let stored = fixture.receiver.app.account_storage("receiver").unwrap().app_storage().app_messages(storage_sqlite::StoredAppMessageQuery {
            group_id_hex: Some(hex::encode(fixture.group.as_slice())),
            kinds: Some(vec![MARMOT_APP_EVENT_KIND_CHAT]),
            limit: None,
        }).unwrap();
        assert_eq!(stored.len(), TEXTS);
        assert!(stored.iter().all(|message| !message.invalidated));
        assert_eq!(stored.into_iter().map(|message| (message.message_id_hex, message.plaintext)).collect::<BTreeMap<_, _>>(), expected, "all real MLS plaintexts survive local fanout while older native history is pending");
        let status = adapter.take_replay_status(&account).await;
        assert!(!status.pending);
        assert!(status.loss.is_none());
    }).await.expect("bounded real MLS local-fanout ordering proof");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn queued_live_rejoins() {
    timeout(Duration::from_secs(120), async {
        assert_eq!(
            cgka_engine::wire_format::DEFAULT_OUT_OF_ORDER_TOLERANCE,
            100
        );
        let mut fixture = crypto_fixture().await;
        let (events, expected) = encrypted_texts(&mut fixture.sender, &fixture.group).await;
        let first = fixture
            .receiver
            .adapter
            .recovered_deliveries(events[0].clone())
            .await
            .unwrap()
            .pop()
            .unwrap();
        let TransportEnvelope::GroupMessage { transport_group_id } = first.message.envelope else {
            panic!("the fixture produces real MLS group ciphertext");
        };
        let account = first.account_id;
        let a = cgka_traits::TransportEndpoint(ENDPOINT.into());
        let b = cgka_traits::TransportEndpoint("wss://new-peer.example".into());
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let adapter = transport_nostr_adapter::NostrTransportAdapter::new(relay.clone());
        fixture.receiver.recovery_owner.native_batch = None;
        fixture.receiver.recovery_owner.native_ingress = None;
        let mut ingress = adapter
            .open_replay_ingress(&account, Vec::new())
            .await
            .unwrap();
        let mut group = cgka_traits::TransportGroupSubscription {
            group_id: fixture.group.clone(),
            transport_group_id,
            endpoints: vec![a.clone()],
            retained_since: None,
        };
        adapter
            .activate_account(TransportAccountActivation {
                account_id: account.clone(),
                inbox_endpoints: Vec::new(),
                group_subscriptions: vec![group.clone()],
                since: None,
            })
            .await
            .unwrap();
        let old = relay
            .accepted_subscriptions()
            .into_iter()
            .find(|subscription| subscription.carries_group(&fixture.group))
            .unwrap()
            .subscription_id();
        adapter.handle_relay_eose(a.clone(), old.clone()).await;
        // Raw post-EOSE input uses the production adapter producer, not direct
        // account-router injection or the retained-spill seeding API. No
        // consumer ingests the prefix before the source membership changes.
        for event in &events[..180] {
            let mut event = event.clone();
            event.subscription_id = Some(old.clone());
            adapter
                .observe_relay_event(
                    &hex::decode(&event.event.id).unwrap(),
                    &event.endpoint,
                    event.subscription_id.as_deref(),
                    event.event.created_at,
                )
                .await;
            adapter
                .handle_group_relay_copy(event, Some(&account))
                .await
                .unwrap();
        }
        assert!(
            timeout(Duration::from_millis(25), adapter.receive())
                .await
                .is_err(),
            "registered native consumers must never receive group tails through the ordinary queue"
        );
        let ReplayBatchTake::Ready(prefix) = ingress.take_batch(Some(&fixture.group)).await else {
            panic!("the live prefix remains owned by the native group lane");
        };
        assert!(prefix.delivery().is_some());
        fixture.receiver.recovery_owner.native_batch = Some(prefix);
        fixture.receiver.recovery_owner.native_ingress = Some(ingress);
        group.endpoints.push(b.clone());
        adapter
            .sync_account_groups(cgka_traits::TransportGroupSync {
                account_id: account.clone(),
                group_subscriptions: vec![group],
                since: None,
            })
            .await
            .unwrap();
        let current = relay
            .accepted_subscriptions()
            .into_iter()
            .rev()
            .find(|subscription| subscription.carries_group(&fixture.group))
            .unwrap()
            .subscription_id();
        assert_ne!(old, current);
        assert!(
            fixture
                .receiver
                .recovery_owner
                .native_batch
                .as_ref()
                .unwrap()
                .delivery()
                .is_none(),
            "new peer metadata revokes the unstarted live-prefix loan"
        );
        assert!(!fixture.receiver.admit_native_turn().await.unwrap());
        for event in events[180..].iter().rev() {
            let mut event = event.clone();
            event.endpoint = b.clone();
            event.subscription_id = Some(current.clone());
            adapter
                .observe_relay_event(
                    &hex::decode(&event.event.id).unwrap(),
                    &event.endpoint,
                    event.subscription_id.as_deref(),
                    event.event.created_at,
                )
                .await;
            adapter
                .handle_group_relay_copy(event, Some(&account))
                .await
                .unwrap();
        }
        assert!(
            !fixture.receiver.admit_native_turn().await.unwrap(),
            "the native lane waits for the current source boundary"
        );
        adapter.handle_relay_eose(b, current.clone()).await;
        adapter.handle_relay_eose(a, current).await;
        for turn in 0..=TEXTS {
            if !fixture.receiver.admit_native_turn().await.unwrap() {
                break;
            }
            assert!(
                turn < TEXTS,
                "one native lane drains in bounded owner turns"
            );
        }
        let summary = fixture.receiver.take_pending_applied_sync_summary();
        assert_eq!(summary.messages.len(), TEXTS);
        assert_eq!(
            summary
                .messages
                .into_iter()
                .map(|message| (message.message_id_hex, message.plaintext))
                .collect::<BTreeMap<_, _>>(),
            expected
        );
        let stored = fixture
            .receiver
            .app
            .account_storage("receiver")
            .unwrap()
            .app_storage()
            .app_messages(storage_sqlite::StoredAppMessageQuery {
                group_id_hex: Some(hex::encode(fixture.group.as_slice())),
                kinds: Some(vec![MARMOT_APP_EVENT_KIND_CHAT]),
                limit: None,
            })
            .unwrap();
        assert_eq!(stored.len(), TEXTS);
        assert!(stored.iter().all(|message| !message.invalidated));
        assert_eq!(
            stored
                .into_iter()
                .map(|message| (message.message_id_hex, message.plaintext))
                .collect::<BTreeMap<_, _>>(),
            expected,
            "the real post-EOSE prefix and new-peer replay must preserve all durable MLS plaintexts"
        );
        let status = adapter.take_replay_status(&account).await;
        assert!(!status.pending);
        assert!(status.loss.is_none());
    })
    .await
    .expect("bounded raw live-prefix and repacked history proof");
}
