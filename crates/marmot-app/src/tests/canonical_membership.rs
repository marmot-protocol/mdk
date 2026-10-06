//! Real account-runtime membership changes through the app projection boundary.

use super::*;
use crate::conversation_presentation::ConversationAuthority;
use cgka_traits::engine::{GroupEvent, GroupStateChange, SendIntent};
use cgka_traits::{CgkaEngine as _, MessageStorage as _};

fn app_at(dir: &tempfile::TempDir, relay: Arc<ScriptedPushRelayClient>) -> MarmotApp {
    MarmotApp::with_relay_and_config(
        dir.path(),
        "wss://relay.example",
        MarmotAppConfig::default()
            .with_dev_settlement_quiescence_ms(0)
            .with_dev_scheduled_convergence_delay_ms(0),
    )
    .with_test_relay_client(relay)
}

/// Deliver actual signed publications through the app's normal inbound seam.
async fn deliver_new(client: &mut AppClient, relay: &ScriptedPushRelayClient, cursor: &mut usize) {
    let events = relay.published_events.lock().unwrap().clone();
    let account = client
        .app
        .account_home()
        .account(&client.state.label)
        .unwrap();
    for event in &events[*cursor..] {
        let plane = match event.kind {
            1059 if event.tags.iter().any(|tag| {
                tag.first().is_some_and(|v| v == "p") && tag.get(1) == Some(&account.account_id_hex)
            }) =>
            {
                cgka_traits::TransportDeliveryPlane::AccountInbox
            }
            transport_nostr_peeler::KIND_MARMOT_GROUP_MESSAGE => {
                cgka_traits::TransportDeliveryPlane::Group
            }
            _ => continue,
        };
        client
            .ingest_received_delivery(cgka_traits::TransportDelivery {
                account_id: MemberId::new(hex::decode(&account.account_id_hex).unwrap()),
                group_id_hint: None,
                message: event.to_transport_message().unwrap(),
                received_at: cgka_traits::Timestamp(unix_now_seconds()),
                source: cgka_traits::TransportDeliverySource {
                    transport: cgka_traits::transport::TransportSource("nostr".into()),
                    plane,
                    endpoint: None,
                    subscription_id: None,
                    wire: None,
                },
            })
            .await
            .unwrap();
    }
    *cursor = events.len();
}

/// Deliver publication echoes and settle real post-join maintenance before forking.
async fn settle_group(
    clients: &mut [(&mut AppClient, &mut usize)],
    relay: &ScriptedPushRelayClient,
    group: &GroupId,
) {
    for _ in 0..2 {
        for (client, cursor) in clients.iter_mut() {
            deliver_new(client, relay, cursor).await;
            client.sync().await.unwrap();
            client.retry_group_convergence(group).await.unwrap();
        }
    }
}

/// Attach the real published KeyPackage event needed by the Welcome wrapper.
async fn published_key_package(
    client: &mut AppClient,
    relay: &ScriptedPushRelayClient,
) -> cgka_traits::KeyPackage {
    let mut kp = client.publish_key_package().await.unwrap();
    let account = client
        .app
        .account_home()
        .account(&client.state.label)
        .unwrap();
    let event = relay
        .published_events
        .lock()
        .unwrap()
        .iter()
        .rev()
        .find(|event| event.kind == 30443 && event.pubkey == account.account_id_hex)
        .unwrap()
        .clone();
    kp.source = Some(cgka_traits::engine::KeyPackageSource {
        event_id: MessageId::new(hex::decode(event.id).unwrap()),
    });
    kp
}

/// Read the same stored membership and live authority inputs used by conversation capture.
fn can_send(client: &AppClient, group: &GroupId) -> bool {
    let authority = client.runtime.session().group_authority(group).unwrap();
    let facts = authority.facts;
    ConversationAuthority {
        is_member: facts.is_member,
        self_membership: client
            .app
            .stored_group_self_membership(&client.state.label, &hex::encode(group.as_slice()))
            .unwrap()
            .unwrap(),
        is_admin: facts.is_admin,
        admin_count: facts.admin_count,
        pending_confirmation: false,
        leave_request_pending: client.runtime.session().leave_in_progress(group).unwrap(),
        lifecycle: authority.lifecycle.into(),
        unrecoverable: facts.unrecoverable,
        disbanding: authority.disbanding,
        disbanding_enabled: facts.disbanding_enabled,
        has_disbanding_blockers: facts.has_disbanding_blockers,
    }
    .capabilities()
    .can_send
}

/// A real sibling SelfRemove must not terminate the surviving device's projection.
#[tokio::test]
async fn sibling_selfremove_preserves_surviving_app_device_after_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let sibling_dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let bob = home.create_account("bob").unwrap();
    let secret = home
        .load_signing_keys("bob")
        .unwrap()
        .secret_key()
        .to_secret_hex();
    AccountHome::open(sibling_dir.path())
        .import_account("bob", &secret)
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = app_at(&dir, relay.clone());
    let sibling_app = app_at(&sibling_dir, relay.clone());
    remember_test_member_inbox(&app, &bob.account_id_hex, "wss://relay.example");
    let mut bob_client = app.client("bob").await.unwrap();
    bob_client.publish_key_package().await.unwrap();
    bob_client.sync().await.unwrap();
    let mut alice = app.client("alice").await.unwrap();
    let mut alice_cursor = 0;
    let mut bob_cursor = 0;
    let group = alice
        .create_group("sibling departure", &[&bob.account_id_hex])
        .await
        .unwrap();
    deliver_new(&mut bob_client, &relay, &mut bob_cursor).await;
    bob_client.sync().await.unwrap();
    bob_client.accept_group_invite(&group).unwrap();
    let mut sibling = sibling_app.client("bob").await.unwrap();
    sibling.sync().await.unwrap();
    let mut sibling_cursor = relay.published_events.lock().unwrap().len();
    let kp = published_key_package(&mut sibling, &relay).await;
    let effects = alice
        .runtime
        .send(SendIntent::Invite {
            group_id: group.clone(),
            key_packages: vec![kp],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    alice
        .observe_drained_session_events(&effects)
        .await
        .unwrap();
    deliver_new(&mut sibling, &relay, &mut sibling_cursor).await;
    sibling.sync().await.unwrap();
    sibling.accept_group_invite(&group).unwrap();
    deliver_new(&mut bob_client, &relay, &mut bob_cursor).await;
    bob_client.sync().await.unwrap();
    bob_client.retry_group_convergence(&group).await.unwrap();
    let group_hex = hex::encode(group.as_slice());
    let surviving_leaf = bob_client.runtime.own_leaf_index(&group).unwrap();
    let departing_leaf = sibling.runtime.own_leaf_index(&group).unwrap();
    assert_ne!(surviving_leaf, departing_leaf);
    for leaf in [surviving_leaf, departing_leaf] {
        let mut token = drained_seam_push_token(&group_hex, &bob.account_id_hex, leaf);
        token.token_fingerprint = format!("device-{leaf}");
        app.upsert_group_push_token("bob", &token).unwrap();
    }
    relay.fail_publishes_as_unavailable();
    bob_client
        .send(&group, b"retained sibling send")
        .await
        .unwrap();
    let mut fanout = bob_client
        .runtime
        .session()
        .outbound_fanouts_for_group(&group)
        .unwrap()
        .remove(0);
    for index in fanout.outstanding_target_indexes() {
        let failure = fanout.target_failure(index).unwrap().clone();
        for _ in 0..6 {
            fanout
                .mark_attempt_started_at(index, notifications::unix_now_ms().try_into().unwrap())
                .unwrap();
            fanout
                .record_target_failure(index, failure.clone())
                .unwrap();
        }
    }
    bob_client
        .runtime
        .session()
        .put_outbound_fanout(&fanout)
        .unwrap();
    relay.allow_publishes();
    sibling.leave_group(&group).await.unwrap();
    deliver_new(&mut alice, &relay, &mut alice_cursor).await;
    alice.sync().await.unwrap();
    let delay = alice
        .runtime
        .scheduled_self_remove_auto_commit_delay_ms(&group)
        .unwrap()
        .unwrap();
    tokio::time::sleep(Duration::from_millis(delay + 1)).await;
    alice.retry_group_convergence(&group).await.unwrap();
    deliver_new(&mut bob_client, &relay, &mut bob_cursor).await;
    bob_client.sync().await.unwrap();
    bob_client.retry_group_convergence(&group).await.unwrap();
    assert_eq!(
        app.stored_group_self_membership("bob", &group_hex).unwrap(),
        Some(SelfMembership::Member)
    );
    assert!(can_send(&bob_client, &group));
    let tokens = app.group_push_tokens("bob", &group_hex).unwrap();
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].leaf_index, surviving_leaf);
    let assert_held = |app: &MarmotApp| {
        let rows = app
            .timeline_messages_with_query(
                "bob",
                TimelineMessageQuery {
                    group_id_hex: Some(group_hex.clone()),
                    ..Default::default()
                },
            )
            .unwrap()
            .messages;
        let held = rows
            .iter()
            .find(|row| row.plaintext == "retained sibling send")
            .unwrap();
        assert_eq!(held.invalidation_status, None);
        assert!(rows.iter().any(|row| {
            row.group_system
                .as_ref()
                .is_some_and(|event| event.system_type == "member_left")
        }));
    };
    assert_held(&app);
    assert!(
        !bob_client
            .runtime
            .session()
            .outbound_fanouts_for_group(&group)
            .unwrap()
            .is_empty()
    );
    let registration = app
        .upsert_push_registration(
            "bob",
            PushPlatform::Fcm,
            "surviving-device-token",
            &nostr::prelude::Keys::generate().public_key().to_hex(),
            None,
        )
        .unwrap();
    assert!(
        app.pending_push_registration_shares(
            "bob",
            &registration.token_fingerprint,
            registration.updated_at_ms
        )
        .unwrap()
        .contains(&group_hex)
    );
    drop(bob_client);
    drop(alice);
    drop(app);
    let reopened = app_at(&dir, relay);
    let client = reopened.client("bob").await.unwrap();
    assert!(can_send(&client, &group));
    assert!(
        !client
            .runtime
            .session()
            .outbound_fanouts_for_group(&group)
            .unwrap()
            .is_empty()
    );
    assert!(
        reopened
            .pending_push_registration_shares(
                "bob",
                &registration.token_fingerprint,
                registration.updated_at_ms
            )
            .unwrap()
            .contains(&group_hex)
    );
    assert_eq!(
        reopened.group_push_tokens("bob", &group_hex).unwrap()[0].leaf_index,
        surviving_leaf
    );
    assert_held(&reopened);
}

/// A real losing removal restores app participation without a fabricated self invitation.
#[tokio::test]
async fn losing_removal_restores_app_membership_unread_and_reopen() {
    losing_removal_restores_membership(false, false).await;
}

/// Open repairs a canonical rollback whose application announcement was not projected.
#[tokio::test]
async fn reopen_repairs_unobserved_removal_withdrawal() {
    losing_removal_restores_membership(true, false).await;
}

/// Canonical membership repair must preserve an independent local archive choice.
#[tokio::test]
async fn removal_withdrawal_preserves_local_archive() {
    losing_removal_restores_membership(false, true).await;
}

async fn losing_removal_restores_membership(reopen_before_observation: bool, archived: bool) {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let bob = home.create_account("bob").unwrap();
    let carol = home.create_account("carol").unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = app_at(&dir, relay.clone());
    for account in [&bob, &carol] {
        remember_test_member_inbox(&app, &account.account_id_hex, "wss://relay.example");
    }
    let mut bob_client = app.client("bob").await.unwrap();
    let mut carol_client = app.client("carol").await.unwrap();
    bob_client.publish_key_package().await.unwrap();
    bob_client.sync().await.unwrap();
    carol_client.publish_key_package().await.unwrap();
    carol_client.sync().await.unwrap();
    let mut alice = app.client("alice").await.unwrap();
    let mut alice_cursor = 0;
    let mut bob_cursor = 0;
    let group = alice
        .create_group("before fork", &[&bob.account_id_hex])
        .await
        .unwrap();
    let mut carol_cursor = 0;
    let kp = published_key_package(&mut carol_client, &relay).await;
    let effects = alice
        .runtime
        .send(SendIntent::Invite {
            group_id: group.clone(),
            key_packages: vec![kp],
            initial_admins: vec![MemberId::new(hex::decode(&carol.account_id_hex).unwrap())],
        })
        .await
        .unwrap();
    alice
        .observe_drained_session_events(&effects)
        .await
        .unwrap();
    deliver_new(&mut bob_client, &relay, &mut bob_cursor).await;
    deliver_new(&mut carol_client, &relay, &mut carol_cursor).await;
    bob_client.sync().await.unwrap();
    carol_client.sync().await.unwrap();
    bob_client.accept_group_invite(&group).unwrap();
    carol_client.accept_group_invite(&group).unwrap();
    settle_group(
        &mut [
            (&mut alice, &mut alice_cursor),
            (&mut bob_client, &mut bob_cursor),
            (&mut carol_client, &mut carol_cursor),
        ],
        &relay,
        &group,
    )
    .await;
    app.initialize_chat_read_state("bob", &hex::encode(group.as_slice()))
        .unwrap();
    // A genuine retained chat makes unread eligibility observable before,
    // during and after the removal; group-system activities alone do not count.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    carol_client
        .send(&group, b"unread before removal")
        .await
        .unwrap();
    settle_group(
        &mut [
            (&mut alice, &mut alice_cursor),
            (&mut bob_client, &mut bob_cursor),
            (&mut carol_client, &mut carol_cursor),
        ],
        &relay,
        &group,
    )
    .await;
    assert!(
        app.timeline_messages_with_query(
            "bob",
            TimelineMessageQuery {
                group_id_hex: Some(hex::encode(group.as_slice())),
                ..Default::default()
            }
        )
        .unwrap()
        .messages
        .iter()
        .any(|row| row.plaintext == "unread before removal"),
        "fixture must deliver the genuine chat"
    );
    // Direct AppClients do not run the managed worker's chat-list refresh.
    // Materialize the genuinely received chat using that same normal selector.
    app.refresh_chat_list_row("bob", &hex::encode(group.as_slice()))
        .unwrap();
    let unread = || {
        app.account_unread_summary()
            .unwrap()
            .into_iter()
            .find(|summary| summary.account_id_hex == bob.account_id_hex)
            .unwrap()
            .unread_count
    };
    let original_unread = unread();
    assert!(
        original_unread > 0,
        "fixture must contain a real unread chat"
    );
    let group_hex = hex::encode(group.as_slice());
    if archived {
        bob_client.set_group_archived(&group, true).unwrap();
    }
    // Equal-depth privileged forks choose the smaller authenticated committer.
    let alice_id = app
        .account_home()
        .account(&alice.state.label)
        .unwrap()
        .account_id_hex;
    let carol_id = app
        .account_home()
        .account(&carol_client.state.label)
        .unwrap()
        .account_id_hex;
    if alice_id < carol_id {
        std::mem::swap(&mut alice, &mut carol_client);
    }
    assert_eq!(
        alice.runtime.group_record(&group).unwrap().epoch,
        carol_client.runtime.group_record(&group).unwrap().epoch
    );
    let bob_leaf = bob_client.runtime.session().own_leaf_index(&group).unwrap();
    app.upsert_group_push_token(
        "bob",
        &drained_seam_push_token(&group_hex, &bob.account_id_hex, bob_leaf),
    )
    .unwrap();
    alice
        .remove_members(&group, &[&bob.account_id_hex])
        .await
        .unwrap();
    deliver_new(&mut bob_client, &relay, &mut bob_cursor).await;
    bob_client.sync().await.unwrap();
    bob_client.retry_group_convergence(&group).await.unwrap();
    assert!(bob_client.runtime.group_record(&group).unwrap().removed);
    assert_eq!(
        app.stored_group_self_membership("bob", &group_hex).unwrap(),
        Some(SelfMembership::Removed)
    );
    assert!(!can_send(&bob_client, &group));
    assert_eq!(unread(), 0, "terminal membership suppresses account unread");
    assert!(
        app.group_push_tokens("bob", &group_hex).unwrap().is_empty(),
        "full account removal still clears its notification destinations"
    );
    // The other admin stayed on the common source epoch. Retain its genuine
    // winning commit at the stored-history replay seam: live input on an
    // already evicted copy is intentionally quarantined as SelfEvicted.
    let effects = carol_client
        .runtime
        .send(SendIntent::UpdateGroupData {
            group_id: group.clone(),
            name: Some("winning rename".into()),
            description: None,
        })
        .await
        .unwrap();
    let commit_id = effects
        .events
        .iter()
        .find_map(|event| match event {
            GroupEvent::GroupStateChanged {
                origin_commit_id: Some(id),
                ..
            } => Some(id.clone()),
            _ => None,
        })
        .expect("real rename emits its content commit id");
    carol_client
        .observe_drained_session_events(&effects)
        .await
        .unwrap();
    let mut retained = app
        .account_storage(&carol_client.state.label)
        .unwrap()
        .get_message(&commit_id)
        .unwrap();
    // Receive the exact MLS bytes, without the author's local own-commit
    // checkpoint stamp: that snapshot belongs only to the author device.
    let wire = cgka_traits::message::StoredMessagePayload::decode(&retained.payload)
        .unwrap()
        .as_openmls_wire()
        .unwrap()
        .clone();
    retained.payload = cgka_traits::message::StoredMessagePayload::openmls_wire(wire)
        .encode()
        .unwrap();
    retained.state = cgka_traits::message::MessageState::Created;
    app.account_storage("bob")
        .unwrap()
        .put_message(&retained)
        .unwrap();
    // Use the same retained-message convergence entry point as the engine's
    // superseded-removal contract test. The account scheduler intentionally
    // declines to advance a terminal copy; no synthetic app event is injected.
    let signer = app.account_signer_for_summary(&bob).unwrap();
    let mut replay = cgka_engine::EngineBuilder::new(app.account_storage("bob").unwrap())
        .identity(hex::decode(&bob.account_id_hex).unwrap())
        .account_identity_proof_signer(signer.as_proof_signer())
        .feature_registry(app_feature_registry())
        .supported_app_components(app.supported_app_component_ids())
        .peeler(Box::new(
            NostrMlsPeeler::new().with_welcome_signer_arc(signer.as_nostr_signer()),
        ))
        .build()
        .unwrap();
    replay.hydrate_all_stored_groups().unwrap();
    replay.drain_events();
    replay
        .converge_stored_openmls_messages_at(&group, 1_000_000)
        .unwrap();
    replay
        .converge_stored_openmls_messages_at(&group, u64::MAX)
        .unwrap();
    assert!(
        !app.account_storage("bob")
            .unwrap()
            .get_group(&group)
            .unwrap()
            .removed,
        "winning rename must restore canonical membership"
    );
    let events = replay.drain_events();
    assert!(
        events
            .iter()
            .any(|event| matches!(event, GroupEvent::GroupStateInvalidated { .. })),
        "real convergence must withdraw the removal"
    );
    assert!(!events.iter().any(|event| matches!(event,
        GroupEvent::GroupStateChanged { change: GroupStateChange::MemberAdded { member }, .. }
        if hex::encode(member.as_slice()) == bob.account_id_hex)));
    drop(replay);
    if reopen_before_observation {
        assert_eq!(
            app.stored_group_self_membership("bob", &group_hex).unwrap(),
            Some(SelfMembership::Removed)
        );
        drop(bob_client);
        bob_client = app.client("bob").await.unwrap();
    } else {
        bob_client
            .observe_drained_session_events(&marmot_account::AccountDeviceEffects {
                events,
                ..Default::default()
            })
            .await
            .unwrap();
    }
    assert_eq!(
        app.stored_group_self_membership("bob", &group_hex).unwrap(),
        Some(SelfMembership::Member)
    );
    assert!(can_send(&bob_client, &group));
    assert_eq!(
        unread(),
        if archived { 0 } else { original_unread },
        "restored membership respects retained unread and local archive intent"
    );
    assert_eq!(
        app.group("bob", &group_hex).unwrap().unwrap().archived,
        archived
    );
    bob_client
        .send(&group, b"restored member can send")
        .await
        .unwrap();
    drop(bob_client);
    drop(alice);
    drop(carol_client);
    drop(app);
    let reopened = app_at(&dir, relay);
    let client = reopened.client("bob").await.unwrap();
    assert!(can_send(&client, &group));
    assert_eq!(
        reopened.group("bob", &group_hex).unwrap().unwrap().archived,
        archived
    );
    assert_eq!(
        reopened
            .stored_group_self_membership("bob", &group_hex)
            .unwrap(),
        Some(SelfMembership::Member)
    );
}
