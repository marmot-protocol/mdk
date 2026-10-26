use super::*;
use transport_nostr_adapter::NostrSubscription;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn future_cursor_keeps_old_text() {
    let mut fixture = crypto_fixture().await;
    let storage = fixture
        .receiver
        .app
        .account_storage("receiver")
        .unwrap()
        .app_storage();
    timeout(Duration::from_secs(10), async {
        loop {
            fixture.receiver.admit_native_turn().await.unwrap();
            fixture.receiver.synchronize_native_replay().await.unwrap();
            if storage
                .pending_recovery_demands()
                .unwrap()
                .iter()
                .all(|demand| demand.cause != storage_sqlite::RecoveryCause::SubscriptionReplay)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("setup must settle its original unfloored native duty");

    let mut app = fixture.receiver.app.clone();
    app.relay_plane = crate::MarmotRelayPlane::new_with_directory_fetcher_for_test(
        Some(Duration::from_secs(120)),
        fixture.relay.clone(),
        fixture.relay.clone(),
        app.config.allow_loopback_relay_endpoints,
    );
    fixture.receiver.state.last_transport_timestamp = Some(unix_now_seconds() + 300);
    app.save_state(&fixture.receiver.state).unwrap();
    let first_request = fixture.relay.subscription_count();
    drop(fixture.receiver);
    fixture.receiver = client_on_app_relay_plane(&app, "receiver").await;
    fixture.receiver.prepare_transport().await.unwrap();
    let request = fixture
        .relay
        .accepted_subscriptions()
        .into_iter()
        .skip(first_request)
        .find(|request| request.is_group_route() && request.carries_group(&fixture.group))
        .expect("reopening activates the persisted group");
    let since = match request {
        NostrSubscription::Group { since, .. } | NostrSubscription::GroupBatch { since, .. } => {
            since
        }
        _ => unreachable!("the selected request is a live group route"),
    };
    assert!(
        since.is_none(),
        "the first activation must not replace an untrusted future cursor with a recent tail"
    );

    let text = "authenticated history older than the rebuild tail";
    let author = fixture
        .sender
        .app
        .account_home()
        .account("sender")
        .unwrap()
        .account_id_hex;
    let inner = build_inner_event(
        &AppMessageIntent::Chat {
            content: text.into(),
        },
        &author,
        unix_now_seconds().saturating_sub(600),
    )
    .unwrap();
    let effects = fixture
        .sender
        .runtime
        .session_mut()
        .send(SendIntent::AppMessage {
            group_id: fixture.group.clone(),
            payload: encode_inner_event(&inner).unwrap(),
            expected_epoch: None,
        })
        .await
        .unwrap();
    let Some(PublishWork::ApplicationMessage { msg, .. }) = effects.publish.into_iter().next()
    else {
        panic!("the real MLS send must produce its encrypted envelope");
    };
    let event = NostrTransportEvent::from_transport_message(&msg).unwrap();
    event.to_verified_nostr_event().unwrap();
    let copy = NostrRelayEvent {
        endpoint: cgka_traits::TransportEndpoint(ENDPOINT.into()),
        subscription_id: None,
        event,
    };
    let delivery = fixture
        .receiver
        .adapter
        .recovered_deliveries(copy.clone())
        .await
        .unwrap()
        .pop()
        .unwrap();
    let TransportEnvelope::GroupMessage { transport_group_id } = delivery.message.envelope else {
        panic!("the old message must carry the authenticated group route");
    };
    let account = delivery.account_id;
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let adapter = transport_nostr_adapter::NostrTransportAdapter::new(relay.clone());
    fixture.receiver.recovery_owner.native_batch = None;
    fixture.receiver.recovery_owner.native_ingress = None;
    let ingress = adapter
        .open_replay_ingress(&account, Vec::new())
        .await
        .unwrap();
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account.clone(),
            inbox_endpoints: Vec::new(),
            group_subscriptions: vec![cgka_traits::TransportGroupSubscription {
                group_id: fixture.group.clone(),
                transport_group_id,
                endpoints: vec![copy.endpoint.clone()],
                retained_since: None,
            }],
            since,
        })
        .await
        .unwrap();
    let id = relay
        .accepted_subscriptions()
        .into_iter()
        .find(|request| request.carries_group(&fixture.group))
        .unwrap()
        .subscription_id();
    let mut copy = copy;
    copy.subscription_id = Some(id.clone());
    adapter
        .observe_relay_event(
            &hex::decode(&copy.event.id).unwrap(),
            &copy.endpoint,
            copy.subscription_id.as_deref(),
            copy.event.created_at,
        )
        .await;
    adapter
        .handle_group_relay_copy(copy.clone(), Some(&account))
        .await
        .unwrap();
    adapter.handle_relay_eose(copy.endpoint, id).await;
    fixture.receiver.recovery_owner.native_ingress = Some(ingress);
    assert!(fixture.receiver.admit_native_turn().await.unwrap());
    let messages = fixture
        .receiver
        .take_pending_applied_sync_summary()
        .messages;
    assert_eq!(
        messages
            .into_iter()
            .map(|message| message.plaintext)
            .collect::<Vec<_>>(),
        [text]
    );
    let messages = storage
        .app_messages(storage_sqlite::StoredAppMessageQuery {
            group_id_hex: Some(hex::encode(fixture.group.as_slice())),
            kinds: Some(vec![MARMOT_APP_EVENT_KIND_CHAT]),
            limit: None,
        })
        .unwrap();
    assert_eq!(
        messages
            .into_iter()
            .map(|message| message.plaintext)
            .collect::<Vec<_>>(),
        [text]
    );
}
