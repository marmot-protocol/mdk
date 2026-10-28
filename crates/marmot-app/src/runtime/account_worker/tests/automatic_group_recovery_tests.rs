//! Real account workers recovering a durably halted copy over NIP-59.
use super::*;
use cgka_traits::storage::GroupStorage;
use nostr_relay_builder::prelude::{BoxedFuture, Event, Kind, PolicyResult, WritePolicy};
use nostr_relay_builder::{LocalRelay, RelayBuilder};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[derive(Clone, Debug, Default)]
struct UnavailableRecoveryInbox {
    unavailable: Arc<AtomicBool>,
    refused: Arc<AtomicUsize>,
}

impl WritePolicy for UnavailableRecoveryInbox {
    fn admit_event<'a>(
        &'a self,
        event: &'a Event,
        _addr: &'a SocketAddr,
    ) -> BoxedFuture<'a, PolicyResult> {
        Box::pin(async move {
            if self.unavailable.load(Ordering::SeqCst) && event.kind == Kind::GiftWrap {
                self.refused.fetch_add(1, Ordering::SeqCst);
                PolicyResult::Reject("recovery inbox temporarily unavailable".into())
            } else {
                PolicyResult::Accept
            }
        })
    }
}

async fn wait_for_chat(app: &MarmotApp, account: &str, group: &GroupId, text: &str) {
    timeout(Duration::from_secs(30), async {
        loop {
            if app.messages(account).unwrap().iter().any(|message| {
                message.group_id_hex == hex::encode(group.as_slice())
                    && message.plaintext == text
                    && !message.invalidated
            }) {
                return;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("real MLS chat reaches the retained app projection");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auto_rejoin_keeps_history() {
    let _serial = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
    let unavailable = UnavailableRecoveryInbox::default();
    let relay = LocalRelay::new(RelayBuilder::default().write_policy(unavailable.clone()));
    relay.run().await.unwrap();
    let url = relay.url().await.to_string();
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let alice = home.create_account("alice").unwrap();
    let bob = home.create_account("bob").unwrap();
    let carol = home.create_account("carol").unwrap();
    let app = MarmotApp::with_relay_and_config(
        dir.path(),
        url.clone(),
        crate::MarmotAppConfig::white_noise()
            .with_allow_loopback_relay_endpoints(true)
            .with_dev_settlement_quiescence_ms(0),
    );
    for member in [&alice, &bob, &carol] {
        crate::tests::remember_test_member_inbox(&app, &member.account_id_hex, &url);
    }

    // Fixture construction precedes final worker ownership. This is the state
    // an already-pruned device opens, not a forged control or undecryptable
    // ciphertext persuading a healthy live engine to discard its usable copy.
    let mut bob_setup = app.client(&bob.label).await.unwrap();
    bob_setup.publish_key_package().await.unwrap();
    let mut carol_setup = app.client(&carol.label).await.unwrap();
    carol_setup.publish_key_package().await.unwrap();
    let mut alice_setup = app.client(&alice.label).await.unwrap();
    let group = alice_setup
        .create_group("automatic repair", &["bob", "carol"])
        .await
        .unwrap();
    bob_setup.sync().await.unwrap();
    carol_setup.sync().await.unwrap();
    bob_setup.accept_group_invite(&group).unwrap();
    carol_setup.accept_group_invite(&group).unwrap();
    alice_setup
        .send(&group, b"history before pruning")
        .await
        .unwrap();
    bob_setup.sync().await.unwrap();
    carol_setup.sync().await.unwrap();
    let initial = bob_setup.group_mls_state(&group).unwrap().epoch;
    let original_welcome = app
        .group(&bob.label, &hex::encode(group.as_slice()))
        .unwrap()
        .unwrap()
        .via_welcome_message_id_hex;
    let original_install_epoch = app
        .account_storage(&bob.label)
        .unwrap()
        .get_group(&group)
        .unwrap()
        .local_copy_install_epoch;
    drop(bob_setup);
    let history_window =
        marmot_session::CanonicalizationPolicy::default().app_message_past_epoch_limit;
    // The healthy devices discard Bob's frozen epoch before recovery starts;
    // an ordinary group-encrypted request can no longer bridge that gap.
    for epoch in 0..history_window + 2 {
        let name = format!("automatic repair {epoch}");
        alice_setup
            .update_group_profile(&group, Some(&name), None)
            .await
            .unwrap();
        alice_setup.sync().await.unwrap();
        let published_epoch = alice_setup.group_mls_state(&group).unwrap().epoch;
        timeout(Duration::from_secs(10), async {
            while carol_setup.group_mls_state(&group).unwrap().epoch != published_epoch {
                carol_setup.sync().await.unwrap();
                sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("the healthy peer follows each fixture Commit");
    }
    let healthy_epoch = alice_setup.group_mls_state(&group).unwrap().epoch;
    assert!(healthy_epoch - initial > history_window);
    assert_eq!(
        carol_setup.group_mls_state(&group).unwrap().epoch,
        healthy_epoch
    );
    drop(alice_setup);
    drop(carol_setup);
    let storage = app.account_storage(&bob.label).unwrap();
    let mut halted = storage.get_group(&group).unwrap();
    halted.unrecoverable = true;
    storage.put_group(&halted).unwrap();
    unavailable.unavailable.store(true, Ordering::SeqCst);

    // All three final workers are started once and remain alive throughout
    // failed publication, durable retry, replacement Commit and fresh Welcome.
    // There is no UI repair command, manual maintenance, sync or reopen here.
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    runtime.reconcile_accounts().await.unwrap();
    let group_hex = hex::encode(group.as_slice());
    let mut live_group = runtime
        .subscribe_group_state(&bob.label, &group_hex)
        .await
        .unwrap();
    assert!(
        runtime
            .group_mls_state(&bob.label, &group)
            .await
            .unwrap()
            .unrecoverable
    );
    timeout(Duration::from_secs(60), async {
        while unavailable.refused.load(Ordering::SeqCst) == 0 {
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("autonomous worker attempts the authenticated recovery inbox");
    assert!(storage.get_group(&group).unwrap().unrecoverable);
    assert_eq!(
        runtime
            .group_mls_state(&alice.label, &group)
            .await
            .unwrap()
            .epoch,
        healthy_epoch
    );
    // A missing acknowledgement must not spin the account worker or mutate
    // membership. Its next durable turn waits for the ordinary maintenance tick.
    let refused = unavailable.refused.load(Ordering::SeqCst);
    sleep(Duration::from_secs(2)).await;
    assert_eq!(unavailable.refused.load(Ordering::SeqCst), refused);
    assert_eq!(
        runtime
            .group_members(&carol.label, &group)
            .await
            .unwrap()
            .len(),
        3
    );
    unavailable.unavailable.store(false, Ordering::SeqCst);

    timeout(Duration::from_secs(180), async {
        loop {
            let state = storage.get_group(&group).unwrap();
            if !state.unrecoverable && state.local_copy_install_epoch > original_install_epoch {
                break;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("fresh Welcome repairs the already-running recipient automatically");
    let repaired = storage.get_group(&group).unwrap();
    assert!(repaired.local_copy_install_epoch > original_install_epoch);
    assert!(repaired.epoch.0 > initial);
    assert!(!repaired.removed);
    // The subscription opened before repair must see the repaired copy without
    // being torn down and rebuilt by a host.
    timeout(Duration::from_secs(15), async {
        if !live_group.snapshot.unrecoverable
            && live_group.snapshot.via_welcome_message_id_hex != original_welcome
        {
            return;
        }
        loop {
            let update = live_group.recv().await.unwrap();
            if !update.unrecoverable && update.via_welcome_message_id_hex != original_welcome {
                break;
            }
        }
    })
    .await
    .expect("live group projection clears its unrecoverable flag");
    for member in [&alice, &bob, &carol] {
        assert_eq!(
            runtime
                .group_members(&member.label, &group)
                .await
                .unwrap()
                .len(),
            3
        );
        wait_for_chat(&app, &member.label, &group, "history before pruning").await;
    }
    runtime
        .send_message(&alice.label, &group, b"admin after repair".to_vec())
        .await
        .unwrap();
    wait_for_chat(&app, &bob.label, &group, "admin after repair").await;
    wait_for_chat(&app, &carol.label, &group, "admin after repair").await;
    runtime
        .send_message(&bob.label, &group, b"recipient after repair".to_vec())
        .await
        .unwrap();
    wait_for_chat(&app, &alice.label, &group, "recipient after repair").await;
    wait_for_chat(&app, &carol.label, &group, "recipient after repair").await;
    let chats = app
        .messages_with_query(
            &bob.label,
            crate::AppMessageQuery {
                group_id_hex: Some(group_hex),
                kinds: Some(vec![cgka_traits::app_event::MARMOT_APP_EVENT_KIND_CHAT]),
                limit: None,
            },
        )
        .unwrap();
    assert_eq!(
        chats.len(),
        3,
        "recovery controls must not invent chat entries"
    );
    assert!(chats.iter().all(|message| !message.invalidated));
    runtime
        .remove_members(
            &alice.label,
            &group,
            std::slice::from_ref(&bob.account_id_hex),
        )
        .await
        .unwrap();
    timeout(Duration::from_secs(30), async {
        while !storage.get_group(&group).unwrap().removed {
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("authenticated removal terminates the repaired recipient copy");
    let refused_after_removal = unavailable.refused.load(Ordering::SeqCst);
    unavailable.unavailable.store(true, Ordering::SeqCst);
    // Cross two production maintenance intervals without a manual catch-up:
    // removal must never be reinterpreted as permission to request recovery.
    sleep(Duration::from_secs(32)).await;
    assert_eq!(
        unavailable.refused.load(Ordering::SeqCst),
        refused_after_removal
    );
    assert!(storage.get_group(&group).unwrap().removed);
    assert_eq!(
        runtime
            .group_members(&alice.label, &group)
            .await
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        runtime
            .group_members(&carol.label, &group)
            .await
            .unwrap()
            .len(),
        2
    );
    runtime.shutdown_and_close().await.unwrap();
    relay.shutdown();
}
