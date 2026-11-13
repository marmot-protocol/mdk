//! Composed app-client evidence across a third sibling's durable reopen.
//! Pairing cryptography, rename conflict rules and invitation codecs have
//! cheaper owners. This journey checks that their real app scheduling and
//! persisted state still compose with an independent chat participant.

use super::*;
use crate::tests::device_group::history_delivery::send_text;

/// Passes of [`settle`] one phase may take. Settlement is bounded by work,
/// not elapsed time: each phase settled within three passes in 64 local runs
/// with up to 48 copies of this test in parallel, while one pass, nearly all
/// of it maintenance, grew from about 0.4 s to over 2 s under that load.
const SETTLE_PASSES: u32 = 8;

/// Catches a pass that never returns. It is no settlement bound: the slowest
/// loaded local phase took 6.5 s.
const SETTLE_HANG_BACKSTOP: Duration = Duration::from_secs(120);

/// Drive normal inbound, convergence and maintenance until the three
/// independently stored copies agree and each satisfies `done`. No
/// wall-clock sleep supplies settlement, and a phase that needs more than
/// [`SETTLE_PASSES`] passes fails however fast or slow the machine is.
async fn settle(
    relay: &ScriptedPushRelayClient,
    devices: &mut [&mut Device],
    group: &GroupId,
    phase: &str,
    done: impl Fn(&Device) -> bool,
) {
    let started = std::time::Instant::now();
    tokio::time::timeout(SETTLE_HANG_BACKSTOP, async {
        for _ in 0..SETTLE_PASSES {
            for device in devices.iter_mut() {
                device.step(relay).await;
                let effects = device
                    .client
                    .runtime
                    .advance_convergence(group)
                    .await
                    .unwrap();
                device
                    .client
                    .observe_drained_session_events(&effects)
                    .await
                    .unwrap();
                device.client.run_due_maintenance().await.unwrap();
            }
            let roster = devices[0].roster(group);
            let epoch = devices[0].client.runtime.group_record(group).unwrap().epoch;
            let published = relay.published_events.lock().unwrap().len();
            if devices.iter().all(|device| {
                device.cursor == published
                    && device.client.trusted_device_group().unwrap().as_ref() == Some(group)
                    && device.roster(group) == roster
                    && device.client.runtime.group_record(group).unwrap().epoch == epoch
                    && matches!(
                        device.client.runtime.epoch_state(group),
                        Some(cgka_traits::EpochState::Stable { .. })
                    )
                    && !device
                        .client
                        .runtime
                        .has_pending_convergence_inputs(group)
                        .unwrap()
                    && done(device)
            }) {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!(
            "{phase}: all linked copies settle through their ordinary app paths \
             within {SETTLE_PASSES} passes ({:?})",
            started.elapsed()
        );
    })
    .await
    .unwrap_or_else(|_| {
        panic!("{phase}: a settle pass did not return within {SETTLE_HANG_BACKSTOP:?}")
    });
}

fn assert_messages(client: &AppClient, chat: &GroupId, expected: &[(String, &str)]) {
    let rows = client
        .app
        .timeline_messages_with_query(
            &client.state.label,
            storage_sqlite::TimelineMessageQuery {
                group_id_hex: Some(hex::encode(chat.as_slice())),
                ..Default::default()
            },
        )
        .unwrap()
        .messages;
    let mut actual: Vec<_> = rows
        .into_iter()
        .filter(|row| row.kind == MARMOT_APP_EVENT_KIND_CHAT)
        .map(|row| (row.message_id_hex, row.plaintext))
        .collect();
    let mut expected: Vec<_> = expected
        .iter()
        .map(|(id, text)| (id.clone(), (*text).to_owned()))
        .collect();
    actual.sort();
    expected.sort();
    assert_eq!(
        actual, expected,
        "exact logical messages, with no extra copies"
    );
}

/// One acceptance reaches both siblings. The third sibling is then fully
/// closed while two real roster branches compete; reopening its encrypted
/// home must retain the acceptance and adopt the winning label without
/// breaking exact chat delivery to any of the four participants.
#[test]
fn three_linked_devices_converge_after_competing_edits_and_a_durable_reopen() {
    run_composed_app_runtime_test("three-linked-devices-reopen", || async {
        let (relay, [mut phone, mut tablet, mut laptop]) = alice_devices::<3>().await;
        let group = link(&relay, &mut phone, &mut tablet, "Tablet").await;
        assert_eq!(link(&relay, &mut phone, &mut laptop, "Laptop").await, group);
        settle(
            &relay,
            &mut [&mut phone, &mut tablet, &mut laptop],
            &group,
            "after linking all three devices",
            |_| true,
        )
        .await;
        assert_eq!(phone.roster(&group).devices.len(), 3);
        let laptop_slot = laptop.slot_hex();
        let laptop_slot_bytes: [u8; 32] = hex::decode(&laptop_slot).unwrap().try_into().unwrap();
        let alice = phone
            .app
            .account_home()
            .account("alice")
            .unwrap()
            .account_id_hex;

        let bob_dir = tempfile::tempdir().unwrap();
        AccountHome::open(bob_dir.path())
            .create_account("bob")
            .unwrap();
        let bob_app = crate::tests::canonical_membership::app_at(&bob_dir, relay.clone());
        remember_test_member_inbox(&bob_app, &alice, "wss://relay.example");
        let mut bob = bob_app.client("bob").await.unwrap();
        let mut bob_cursor = 0;
        let chat = bob
            .create_group("Three linked copies", &[&alice])
            .await
            .unwrap()
            .operation
            .expect("eligible fixture members");
        for device in [&mut phone, &mut tablet, &mut laptop] {
            device.step(&relay).await;
            assert!(
                device
                    .client
                    .state_group_record(&chat)
                    .unwrap()
                    .pending_confirmation
            );
        }
        assert_eq!(
            bob.members(&chat)
                .unwrap()
                .iter()
                .find(|member| member.member_id_hex == alice)
                .unwrap()
                .device_count,
            3,
            "one external invitation admitted all three independent leaves"
        );
        tablet.client.accept_group_invite(&chat).unwrap();
        settle(
            &relay,
            &mut [&mut phone, &mut tablet, &mut laptop],
            &group,
            "sharing Accept: one Accept reaches both linked siblings",
            |device| {
                !device
                    .client
                    .state_group_record(&chat)
                    .unwrap()
                    .pending_confirmation
            },
        )
        .await;
        let before = send_text(&mut bob, &chat, "before Laptop closes").await;
        for device in [&mut phone, &mut tablet, &mut laptop] {
            device.step(&relay).await;
            assert_messages(
                &device.client,
                &chat,
                &[(before.clone(), "before Laptop closes")],
            );
        }
        settle(
            &relay,
            &mut [&mut phone, &mut tablet, &mut laptop],
            &group,
            "before closing Laptop",
            |_| true,
        )
        .await;

        // Drop both owner and client, not only the client's in-memory view.
        // This is orderly close/reopen, not an abrupt process crash.
        let Device {
            _dir,
            app,
            client,
            cursor,
        } = laptop;
        let config = app.config.clone();
        drop(client);
        drop(app);

        let base = phone.client.runtime.group_record(&group).unwrap().epoch;
        assert_eq!(
            tablet.client.runtime.group_record(&group).unwrap().epoch,
            base
        );
        phone
            .client
            .rename_linked_device(&laptop_slot, "Phone edit")
            .await
            .unwrap();
        let phone_tip = phone.client.runtime.group_record(&group).unwrap().epoch;
        assert!(phone_tip > base);
        assert_eq!(
            tablet.client.runtime.group_record(&group).unwrap().epoch,
            base,
            "Tablet has not received Phone's edit: the branches really compete"
        );
        tablet
            .client
            .rename_linked_device(&laptop_slot, "Tablet edit")
            .await
            .unwrap();
        assert_eq!(
            tablet.client.runtime.group_record(&group).unwrap().epoch,
            phone_tip,
            "both edits must be competing children of the common base"
        );
        assert_eq!(
            phone.roster(&group).devices[&laptop_slot_bytes].label,
            "Phone edit"
        );
        assert_eq!(
            tablet.roster(&group).devices[&laptop_slot_bytes].label,
            "Tablet edit"
        );
        tablet
            .client
            .rename_linked_device(&laptop_slot, "Tablet wins")
            .await
            .unwrap();
        assert!(tablet.client.runtime.group_record(&group).unwrap().epoch > phone_tip);
        let while_closed = send_text(&mut bob, &chat, "while Laptop is closed").await;

        let app = MarmotApp::with_relay_and_config(_dir.path(), "wss://relay.example", config)
            .with_test_relay_client(relay.clone());
        remember_test_member_inbox(&app, &alice, "wss://relay.example");
        let client = app.client("alice").await.unwrap();
        let mut laptop = Device {
            _dir,
            app,
            client,
            cursor,
        };
        assert!(
            !laptop
                .client
                .state_group_record(&chat)
                .unwrap()
                .pending_confirmation
        );
        assert_messages(
            &laptop.client,
            &chat,
            &[(before.clone(), "before Laptop closes")],
        );
        settle(
            &relay,
            &mut [&mut phone, &mut tablet, &mut laptop],
            &group,
            "after reopening Laptop",
            |_| true,
        )
        .await;
        for device in [&phone, &tablet, &laptop] {
            assert_eq!(
                device.roster(&group).devices[&laptop_slot_bytes].label,
                "Tablet wins"
            );
            assert!(
                !device
                    .client
                    .state_group_record(&chat)
                    .unwrap()
                    .pending_confirmation
            );
        }

        let phone_message = send_text(&mut phone.client, &chat, "Phone after convergence").await;
        let tablet_message = send_text(&mut tablet.client, &chat, "Tablet after convergence").await;
        let laptop_message = send_text(&mut laptop.client, &chat, "Laptop after reopen").await;
        let peer_message = send_text(&mut bob, &chat, "Bob after convergence").await;
        for device in [&mut phone, &mut tablet, &mut laptop] {
            device.step(&relay).await;
        }
        deliver_new(&mut bob, &relay, &mut bob_cursor).await;
        let expected = [
            (before, "before Laptop closes"),
            (while_closed, "while Laptop is closed"),
            (phone_message, "Phone after convergence"),
            (tablet_message, "Tablet after convergence"),
            (laptop_message, "Laptop after reopen"),
            (peer_message, "Bob after convergence"),
        ];
        for client in [&phone.client, &tablet.client, &laptop.client, &bob] {
            assert_messages(client, &chat, &expected);
            let members = client.members(&chat).unwrap();
            assert_eq!(members.len(), 2);
            assert_eq!(
                members
                    .iter()
                    .find(|member| member.member_id_hex == alice)
                    .unwrap()
                    .device_count,
                3,
                "reopen and ordinary maintenance must not add duplicate device leaves"
            );
        }
    });
}
