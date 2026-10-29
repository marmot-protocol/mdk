//! Linking a new device through pairing (mdk#2628 item 3.3b): both screens
//! show the same seven emoji, both users confirm, and the existing device
//! adds the confirmed KeyPackage in one commit that writes its roster entry.
//! The new device joins only through the Welcome from the leaf that
//! confirmation named, and the commit's Welcome goes out only once the
//! commit is confirmed.

use super::canonical_membership::{deliver_new, published_key_package};
use super::*;
use crate::client::device_group::LINK_DEADLINE_SECS;
use crate::{
    DeviceLinkChoices, DeviceLinkEndReason, DeviceLinkOp, DeviceLinkPromptState,
    DeviceLinkSnapshot, NewDeviceLinkState,
};
use cgka_traits::app_components::{
    DEVICE_ROSTER_COMPONENT_ID, DeviceEntryV1, DeviceRosterOperationV1, DeviceRosterUpdateV1,
    DeviceRosterV1, MAX_LEAVES_PER_ACCOUNT, decode_device_roster_v1,
    encode_device_roster_update_v1,
};
use cgka_traits::engine::SendIntent;
use storage_sqlite::{DeviceGroupTrust, DeviceLinkOutcome};

/// One of Alice's devices, with its own cursor over the shared relay.
struct Device {
    _dir: tempfile::TempDir,
    app: MarmotApp,
    client: AppClient,
    cursor: usize,
}

impl Device {
    /// Deliver what the relay holds that this device has not seen, then
    /// read linking as it now stands.
    async fn step(&mut self, relay: &ScriptedPushRelayClient) -> DeviceLinkSnapshot {
        deliver_new(&mut self.client, relay, &mut self.cursor).await;
        self.client.device_link(DeviceLinkOp::Read).await.unwrap()
    }

    async fn op(&mut self, op: DeviceLinkOp) -> DeviceLinkSnapshot {
        self.client.device_link(op).await.unwrap()
    }

    fn slot_hex(&self) -> String {
        self.app
            .account_storage("alice")
            .unwrap()
            .key_package_lifecycle()
            .unwrap()
            .unwrap()
            .stable_slot_id
    }

    fn trust(&self, group: &GroupId) -> Option<DeviceGroupTrust> {
        self.app
            .account_storage("alice")
            .unwrap()
            .app_storage()
            .device_group(&hex::encode(group.as_slice()))
            .unwrap()
            .map(|record| record.trust)
    }

    fn roster(&self, group: &GroupId) -> DeviceRosterV1 {
        let bytes = self
            .client
            .runtime
            .app_component(group, DEVICE_ROSTER_COMPONENT_ID)
            .unwrap()
            .unwrap();
        decode_device_roster_v1(&bytes).unwrap()
    }
}

/// Alice's devices, each signed in with the same key and with a published
/// KeyPackage, sharing one scripted relay.
async fn alice_devices<const N: usize>() -> (Arc<ScriptedPushRelayClient>, [Device; N]) {
    alice_devices_settling_after::<N>(0).await
}

/// [`alice_devices`], with a settlement window of `settlement_ms`.
async fn alice_devices_settling_after<const N: usize>(
    settlement_ms: u64,
) -> (Arc<ScriptedPushRelayClient>, [Device; N]) {
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let dirs: [tempfile::TempDir; N] = std::array::from_fn(|_| tempfile::tempdir().unwrap());
    let home = AccountHome::open(dirs[0].path());
    let alice_id = home.create_account("alice").unwrap().account_id_hex;
    let secret = home
        .load_signing_keys("alice")
        .unwrap()
        .secret_key()
        .to_secret_hex();
    let mut devices = Vec::with_capacity(N);
    for (index, dir) in dirs.into_iter().enumerate() {
        if index > 0 {
            AccountHome::open(dir.path())
                .import_account("alice", &secret)
                .unwrap();
        }
        let app = MarmotApp::with_relay_and_config(
            dir.path(),
            "wss://relay.example",
            MarmotAppConfig::white_noise()
                .with_dev_settlement_quiescence_ms(settlement_ms)
                .with_dev_scheduled_convergence_delay_ms(0)
                .with_dev_device_groups(true),
        )
        .with_test_relay_client(relay.clone());
        remember_test_member_inbox(&app, &alice_id, "wss://relay.example");
        let mut client = app.client("alice").await.unwrap();
        published_key_package(&mut client, &relay).await;
        devices.push(Device {
            _dir: dir,
            app,
            client,
            cursor: 0,
        });
    }
    let Ok(devices) = devices.try_into() else {
        unreachable!("one device per directory")
    };
    (relay, devices)
}

fn comparing_code(state: &NewDeviceLinkState) -> Vec<crate::DeviceLinkEmoji> {
    match state {
        NewDeviceLinkState::Comparing { code } => code.clone(),
        other => panic!("expected the code, got {other:?}"),
    }
}

/// The new device's KeyPackage slot, which the existing device's prompt
/// names once it found the KeyPackage.
fn prompt_code(
    snapshot: &DeviceLinkSnapshot,
    slot_hex: &str,
) -> (String, Vec<crate::DeviceLinkEmoji>) {
    let prompt = snapshot
        .prompt_for_slot(slot_hex)
        .expect("a prompt for the sign-in");
    match &prompt.state {
        DeviceLinkPromptState::Comparing { code } => (prompt.prompt_id.clone(), code.clone()),
        other => panic!("expected the code, got {other:?}"),
    }
}

/// Run a link from `new` to `existing` through to the Welcome, the new
/// device confirming first. Returns the device group.
async fn link(
    relay: &ScriptedPushRelayClient,
    existing: &mut Device,
    new: &mut Device,
    label: &str,
) -> GroupId {
    let started = new.op(DeviceLinkOp::Start).await;
    assert_eq!(
        started.new_device,
        Some(NewDeviceLinkState::WaitingForAnswer)
    );
    existing.step(relay).await; // request in, answer out
    let revealed = new.step(relay).await; // answer in, reveal out
    let new_code = comparing_code(revealed.new_device.as_ref().unwrap());
    assert_eq!(new_code.len(), 7);
    assert!(new_code.iter().all(|emoji| !emoji.description.is_empty()));
    let prompt = existing.step(relay).await; // reveal in: the code
    let (prompt_id, existing_code) = prompt_code(&prompt, &new.slot_hex());
    assert_eq!(existing_code, new_code, "both screens show the same emoji");

    let waiting = new.op(DeviceLinkOp::ConfirmMatch).await;
    assert_eq!(
        waiting.new_device,
        Some(NewDeviceLinkState::WaitingForOtherDevice)
    );
    let linking = existing
        .op(DeviceLinkOp::Link {
            prompt_id,
            choices: DeviceLinkChoices::new(label),
        })
        .await;
    assert_eq!(
        linking.prompt_for_slot(&new.slot_hex()).unwrap().state,
        DeviceLinkPromptState::Linking
    );
    let joining = new.step(relay).await; // existing confirm in, own confirm out
    assert_eq!(joining.new_device, Some(NewDeviceLinkState::Joining));
    let committed = existing.step(relay).await; // new confirm in: the commit
    assert_eq!(
        committed.prompt_for_slot(&new.slot_hex()).unwrap().state,
        DeviceLinkPromptState::Linking,
        "only the new device's first commit makes the link"
    );
    join_then_linked(relay, existing, new).await;
    new.client.trusted_device_group().unwrap().unwrap()
}

/// The new device joins through its Welcome and makes its first commit in
/// the device group on the same drive. The device that linked it reads that
/// commit and shows the link made, after its settlement window if it waits
/// one.
async fn join_then_linked(
    relay: &ScriptedPushRelayClient,
    existing: &mut Device,
    new: &mut Device,
) {
    let joined = new.step(relay).await; // the Welcome, and its first commit
    assert_eq!(joined.new_device, Some(NewDeviceLinkState::Linked));
    let give_up = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let read = existing.step(relay).await; // that commit
        let state = read.prompt_for_slot(&new.slot_hex()).unwrap().state.clone();
        if state == DeviceLinkPromptState::Linked || std::time::Instant::now() >= give_up {
            assert_eq!(state, DeviceLinkPromptState::Linked);
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        // The worker's timer would take the held commit once the window
        // passed.
        let group = existing.client.trusted_device_group().unwrap().unwrap();
        let advanced = existing
            .client
            .runtime
            .advance_convergence(&group)
            .await
            .unwrap();
        existing
            .client
            .observe_drained_session_events(&advanced)
            .await
            .unwrap();
    }
}

/// The link of `slot` that `device` recorded in `group`.
fn link_record(
    device: &Device,
    group: &GroupId,
    slot_hex: &str,
) -> storage_sqlite::DeviceLinkRecord {
    device
        .app
        .account_storage("alice")
        .unwrap()
        .app_storage()
        .device_link(&hex::encode(group.as_slice()), slot_hex)
        .unwrap()
        .unwrap()
}

/// A first link: the new device names its KeyPackage, both screens show the
/// same seven emoji, the new device's user confirms first, and Link device
/// creates the device group with the new device and its label and settings.
/// The link is made once the new device's first commit there, setting its
/// tag signature key, is on the quiet group.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_first_link_creates_the_device_group_with_the_chosen_label_and_settings() {
    let (relay, [mut phone, mut laptop]) = alice_devices::<2>().await;
    let group = link(&relay, &mut phone, &mut laptop, "Laptop").await;

    assert_eq!(phone.trust(&group), Some(DeviceGroupTrust::Created));
    assert_eq!(laptop.trust(&group), Some(DeviceGroupTrust::Linked));
    let laptop_slot: [u8; 32] = hex::decode(laptop.slot_hex()).unwrap().try_into().unwrap();
    let phone_slot: [u8; 32] = hex::decode(phone.slot_hex()).unwrap().try_into().unwrap();
    for device in [&phone, &laptop] {
        let roster = device.roster(&group);
        assert_eq!(roster.devices.len(), 2);
        let entry = &roster.devices[&laptop_slot];
        assert_eq!(entry.label, "Laptop");
        assert_eq!(entry.linked_by, Some(phone_slot));
        assert!(entry.settings.add_to_all_chats && entry.settings.bring_history);
        // The founder's entry takes the same defaults.
        let founder = &roster.devices[&phone_slot].settings;
        assert!(founder.add_to_all_chats && founder.bring_history);
    }

    let record = link_record(&phone, &group, &laptop.slot_hex());
    assert_eq!(record.outcome, DeviceLinkOutcome::Linked);
    assert!(record.decided_at.is_some_and(|at| at >= record.linked_at));
    assert!(record.welcome_id_hex.is_some());
    assert_eq!(
        Some(hex::decode(&record.leaf_signature_key_hex).unwrap()),
        phone.roster(&group).devices[&laptop_slot].tag_signature_key
    );
    // The new device forgets its join once its first commit there landed.
    laptop.step(&relay).await;
    let joins = laptop.app.account_storage("alice").unwrap().app_storage();
    assert!(joins.device_group_joins().unwrap().is_empty());
}

/// A later link adds the new device to the device group in one commit, by a
/// device that joined through a Welcome. First ready wins: the other
/// sibling's session ends, and its prompt then says who added the device.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sibling_adds_a_later_device_and_the_other_prompt_says_who() {
    let (relay, [mut phone, mut laptop, mut tablet]) = alice_devices::<3>().await;
    let group = link(&relay, &mut phone, &mut laptop, "Laptop").await;
    phone.step(&relay).await;

    tablet.op(DeviceLinkOp::Start).await;
    laptop.step(&relay).await; // laptop answers first
    let revealed = tablet.step(&relay).await; // takes the laptop's answer
    let tablet_code = comparing_code(revealed.new_device.as_ref().unwrap());
    // The phone reads the request and the reveal naming the laptop together,
    // so it never answers. Its prompt for the laptop's own link stays listed.
    let other = phone.step(&relay).await;
    assert_eq!(
        other.prompts.last().map(|prompt| &prompt.state),
        Some(&DeviceLinkPromptState::Ended {
            reason: DeviceLinkEndReason::AnsweredElsewhere
        }),
        "{other:?}"
    );
    let prompt = laptop.step(&relay).await;
    let (prompt_id, code) = prompt_code(&prompt, &tablet.slot_hex());
    assert_eq!(code, tablet_code);
    laptop
        .op(DeviceLinkOp::Link {
            prompt_id,
            choices: DeviceLinkChoices {
                label: "Tablet".into(),
                add_to_all_chats: true,
                bring_history: false,
            },
        })
        .await;
    tablet.step(&relay).await;
    let joining = tablet.op(DeviceLinkOp::ConfirmMatch).await;
    assert_eq!(joining.new_device, Some(NewDeviceLinkState::Joining));
    let committed = laptop.step(&relay).await; // the link commit
    assert_eq!(
        committed.prompt_for_slot(&tablet.slot_hex()).unwrap().state,
        DeviceLinkPromptState::Linking
    );
    join_then_linked(&relay, &mut laptop, &mut tablet).await;
    assert_eq!(tablet.trust(&group), Some(DeviceGroupTrust::Linked));

    let added = phone.step(&relay).await;
    assert_eq!(
        added.prompt_for_slot(&tablet.slot_hex()).unwrap().state,
        DeviceLinkPromptState::AddedElsewhere {
            device_label: "Tablet".into(),
            added_by_label: "Laptop".into(),
        }
    );
    let tablet_slot: [u8; 32] = hex::decode(tablet.slot_hex()).unwrap().try_into().unwrap();
    for device in [&phone, &laptop, &tablet] {
        let roster = device.roster(&group);
        assert_eq!(roster.devices.len(), 3);
        assert!(!roster.devices[&tablet_slot].settings.bring_history);
    }
}

/// Not now on the existing device ends the session on both: its prompt goes,
/// and the new device learns the other side cancelled.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn not_now_ends_the_session_on_both_devices() {
    let (relay, [mut phone, mut laptop]) = alice_devices::<2>().await;
    laptop.op(DeviceLinkOp::Start).await;
    phone.step(&relay).await;
    laptop.step(&relay).await;
    let prompt = phone.step(&relay).await;
    let (prompt_id, _) = prompt_code(&prompt, &laptop.slot_hex());
    let declined = phone.op(DeviceLinkOp::Decline { prompt_id }).await;
    assert!(declined.prompts.is_empty());
    let ended = laptop.step(&relay).await;
    assert_eq!(
        ended.new_device,
        Some(NewDeviceLinkState::Ended {
            reason: DeviceLinkEndReason::CancelledElsewhere
        })
    );
}

/// Two sign-ins asking at once: Link is offered for neither, and neither is
/// answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_requests_at_once_offer_link_for_neither() {
    let (relay, [mut phone, mut laptop, mut tablet]) = alice_devices::<3>().await;
    laptop.op(DeviceLinkOp::Start).await;
    tablet.op(DeviceLinkOp::Start).await;
    let prompts = phone.step(&relay).await;
    assert_eq!(prompts.prompts.len(), 2);
    assert!(
        prompts
            .prompts
            .iter()
            .all(|prompt| prompt.state == DeviceLinkPromptState::CompetingRequests)
    );
    let waiting = laptop.step(&relay).await;
    assert_eq!(
        waiting.new_device,
        Some(NewDeviceLinkState::WaitingForAnswer)
    );
}

/// An account with 20 linked devices can't link a 21st: the prompt asks to
/// remove one first, and the new device learns it can't be linked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_twenty_first_device_is_refused() {
    let (relay, [mut phone, mut laptop, mut tablet]) = alice_devices::<3>().await;
    let group = link(&relay, &mut phone, &mut laptop, "Laptop").await;
    phone.step(&relay).await;
    let fillers = (0..MAX_LEAVES_PER_ACCOUNT - 2)
        .map(|index| {
            DeviceRosterOperationV1::SetDevice([index as u8 + 0xa0; 32], DeviceEntryV1::default())
        })
        .collect();
    let update =
        encode_device_roster_update_v1(&DeviceRosterUpdateV1::new(fillers).unwrap()).unwrap();
    let effects = phone
        .client
        .runtime
        .send(SendIntent::UpdateAppComponents {
            group_id: group.clone(),
            updates: vec![cgka_traits::app_components::AppComponentData {
                component_id: DEVICE_ROSTER_COMPONENT_ID,
                data: update,
            }],
        })
        .await
        .unwrap();
    phone
        .client
        .observe_drained_session_events(&effects)
        .await
        .unwrap();
    assert_eq!(phone.roster(&group).devices.len(), MAX_LEAVES_PER_ACCOUNT);

    tablet.op(DeviceLinkOp::Start).await;
    let refused = phone.step(&relay).await;
    assert_eq!(
        refused.prompt_for_slot(&tablet.slot_hex()).unwrap().state,
        DeviceLinkPromptState::TooManyDevices
    );
    let ended = tablet.step(&relay).await;
    assert_eq!(
        ended.new_device,
        Some(NewDeviceLinkState::Ended {
            reason: DeviceLinkEndReason::CannotLink
        })
    );
}

/// A new device that cancels while waiting for its Welcome withdraws the
/// engine's expectation first, so the Welcome that comes after is refused
/// and the device never holds the group.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelling_while_joining_refuses_the_welcome() {
    let (relay, [mut phone, mut laptop]) = alice_devices::<2>().await;
    laptop.op(DeviceLinkOp::Start).await;
    phone.step(&relay).await;
    laptop.step(&relay).await;
    let prompt = phone.step(&relay).await;
    let (prompt_id, _) = prompt_code(&prompt, &laptop.slot_hex());
    phone
        .op(DeviceLinkOp::Link {
            prompt_id,
            choices: DeviceLinkChoices::new("Laptop"),
        })
        .await;
    laptop.step(&relay).await;
    let joining = laptop.op(DeviceLinkOp::ConfirmMatch).await;
    assert_eq!(joining.new_device, Some(NewDeviceLinkState::Joining));
    let cancelled = laptop.op(DeviceLinkOp::Cancel).await;
    assert_eq!(
        cancelled.new_device,
        Some(NewDeviceLinkState::Ended {
            reason: DeviceLinkEndReason::Cancelled
        })
    );
    // The phone took the confirmation before the cancel and added the laptop.
    phone.step(&relay).await;
    let group = phone.client.trusted_device_group().unwrap().unwrap();
    laptop.step(&relay).await;
    assert_eq!(laptop.trust(&group), None);
    assert!(
        !laptop
            .client
            .runtime
            .live_group_ids()
            .unwrap()
            .contains(&group)
    );
    assert_eq!(laptop.client.trusted_device_group().unwrap(), None);
}

/// Runs a link from `new` to `existing` up to the existing device's Link
/// device, and returns the new device's slot.
async fn choose_link(
    relay: &ScriptedPushRelayClient,
    existing: &mut Device,
    new: &mut Device,
) -> String {
    new.op(DeviceLinkOp::Start).await;
    existing.step(relay).await; // request in, answer out
    new.step(relay).await; // answer in, reveal out
    let prompt = existing.step(relay).await; // reveal in: the code
    let slot = new.slot_hex();
    let (prompt_id, _) = prompt_code(&prompt, &slot);
    let linking = existing
        .op(DeviceLinkOp::Link {
            prompt_id,
            choices: DeviceLinkChoices::new("Laptop"),
        })
        .await;
    assert_eq!(
        linking.prompt_for_slot(&slot).unwrap().state,
        DeviceLinkPromptState::Linking
    );
    slot
}

/// A new device that never confirms ends the link on the device that chose
/// Link device once the session times out, rather than leaving it Linking.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_link_the_new_device_never_confirms_times_out() {
    let (relay, [mut phone, mut laptop]) = alice_devices::<2>().await;
    let slot = choose_link(&relay, &mut phone, &mut laptop).await;

    phone
        .client
        .drive_device_pairing_at(crate::unix_now_seconds() + 3_600)
        .await;
    let ended = phone.client.device_link(DeviceLinkOp::Read).await.unwrap();
    assert_eq!(
        ended.prompt_for_slot(&slot).unwrap().state,
        DeviceLinkPromptState::Ended {
            reason: DeviceLinkEndReason::TimedOut
        }
    );
    assert_eq!(phone.client.trusted_device_group().unwrap(), None);
}

/// A confirmation that reaches the device that chose Link device after the
/// new device's Welcome wait, less the minute its Welcome needs, adds no
/// device, though the pairing session would still take it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_confirmation_after_the_welcome_wait_adds_no_device() {
    let (relay, [mut phone, mut laptop]) = alice_devices::<2>().await;
    let slot = choose_link(&relay, &mut phone, &mut laptop).await;
    laptop.op(DeviceLinkOp::ConfirmMatch).await;
    let joining = laptop.step(&relay).await; // phone's confirm in, laptop's out
    assert_eq!(joining.new_device, Some(NewDeviceLinkState::Joining));

    deliver_new(&mut phone.client, &relay, &mut phone.cursor).await;
    phone
        .client
        .drive_device_pairing_at(crate::unix_now_seconds() + 560)
        .await;
    let ended = phone.client.device_link(DeviceLinkOp::Read).await.unwrap();
    assert_eq!(
        ended.prompt_for_slot(&slot).unwrap().state,
        DeviceLinkPromptState::Ended {
            reason: DeviceLinkEndReason::LinkFailed
        }
    );
    assert_eq!(phone.client.trusted_device_group().unwrap(), None);
    assert!(
        phone
            .app
            .account_storage("alice")
            .unwrap()
            .app_storage()
            .device_links()
            .unwrap()
            .is_empty()
    );
}

/// Runs a first link, of `laptop` by `phone`, up to the group's creation,
/// with every publish failing from then: the device group exists on the
/// phone, but its Welcome reached no relay. Returns the group and the
/// laptop's slot.
async fn create_device_group_unpublished(
    relay: &ScriptedPushRelayClient,
    phone: &mut Device,
    laptop: &mut Device,
) -> (GroupId, String) {
    let slot = choose_link(relay, phone, laptop).await;
    laptop.op(DeviceLinkOp::ConfirmMatch).await;
    let joining = laptop.step(relay).await; // phone's confirm in, laptop's out
    assert_eq!(joining.new_device, Some(NewDeviceLinkState::Joining));

    relay.fail_publishes_as_unavailable();
    let created = phone.step(relay).await; // laptop's confirm in: the group
    assert_eq!(
        created.prompt_for_slot(&slot).unwrap().state,
        DeviceLinkPromptState::Linking,
        "a device group whose Welcome reached no relay is not linked"
    );
    let group = phone.client.trusted_device_group().unwrap().unwrap();
    assert_eq!(phone.trust(&group), Some(DeviceGroupTrust::Created));
    (group, slot)
}

/// A first link's founding Welcome that no relay took keeps the link
/// linking. It is published again, and once it lands the new device joins,
/// and its first commit makes the link.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_first_links_undelivered_welcome_is_published_again_until_it_lands() {
    let (relay, [mut phone, mut laptop]) = alice_devices::<2>().await;
    let (group, slot) = create_device_group_unpublished(&relay, &mut phone, &mut laptop).await;
    let waiting = laptop.step(&relay).await;
    assert_eq!(waiting.new_device, Some(NewDeviceLinkState::Joining));

    relay.allow_publishes();
    // Past the redelivery backoff: the Welcome goes out again.
    phone
        .client
        .drive_device_pairing_at(crate::unix_now_seconds() + 10)
        .await;
    let published = phone.step(&relay).await;
    assert_eq!(
        published.prompt_for_slot(&slot).unwrap().state,
        DeviceLinkPromptState::Linking
    );
    join_then_linked(&relay, &mut phone, &mut laptop).await;
    assert_eq!(laptop.trust(&group), Some(DeviceGroupTrust::Linked));
}

/// Not now is refused once both users confirmed: the new device waits for
/// its Welcome and would hear no cancel. The link runs to its outcome, here
/// its undelivered founding Welcome published again until it lands.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn not_now_is_refused_while_a_links_welcome_is_owed() {
    let (relay, [mut phone, mut laptop]) = alice_devices::<2>().await;
    let (_, slot) = create_device_group_unpublished(&relay, &mut phone, &mut laptop).await;
    let linking = phone.op(DeviceLinkOp::Read).await;
    let prompt_id = linking.prompt_for_slot(&slot).unwrap().prompt_id.clone();

    let refused = phone
        .client
        .device_link(DeviceLinkOp::Decline { prompt_id })
        .await;
    assert!(matches!(
        refused,
        Err(AppError::DeviceGroupRefused("link_in_progress"))
    ));

    relay.allow_publishes();
    phone
        .client
        .drive_device_pairing_at(crate::unix_now_seconds() + 10)
        .await;
    let published = phone.step(&relay).await;
    assert_eq!(
        published.prompt_for_slot(&slot).unwrap().state,
        DeviceLinkPromptState::Linking
    );
    join_then_linked(&relay, &mut phone, &mut laptop).await;
}

/// A first link whose founding Welcome no relay takes stays linking past the
/// new device's Welcome wait and its request's deadline: only the link's
/// deadline, an hour after it, fails it. The device that linked it then
/// withdraws the Welcome and removes the device it added, and the new device,
/// which stopped waiting, never joins.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_first_link_whose_welcome_never_lands_fails_at_the_deadline() {
    let (relay, [mut phone, mut laptop]) = alice_devices::<2>().await;
    let (group, slot) = create_device_group_unpublished(&relay, &mut phone, &mut laptop).await;
    let laptop_slot: [u8; 32] = hex::decode(&slot).unwrap().try_into().unwrap();
    // The request was made eleven minutes before the link, so its deadline
    // passes before the new device stops waiting.
    phone.client.backdate_link_requests(660);
    let now = crate::unix_now_seconds();

    for later in [560, 601, LINK_DEADLINE_SECS - 60] {
        phone.client.drive_device_pairing_at(now + later).await;
        let waiting = phone.client.device_link(DeviceLinkOp::Read).await.unwrap();
        assert_eq!(
            waiting.prompt_for_slot(&slot).unwrap().state,
            DeviceLinkPromptState::Linking
        );
    }

    relay.allow_publishes();
    phone
        .client
        .drive_device_pairing_at(now + LINK_DEADLINE_SECS + 1)
        .await;
    let ended = phone.client.device_link(DeviceLinkOp::Read).await.unwrap();
    assert_eq!(
        ended.prompt_for_slot(&slot).unwrap().state,
        DeviceLinkPromptState::Ended {
            reason: DeviceLinkEndReason::LinkFailed
        }
    );
    assert_eq!(
        link_record(&phone, &group, &slot).outcome,
        DeviceLinkOutcome::Failed
    );
    assert!(
        phone
            .client
            .runtime
            .outstanding_welcome_deliveries()
            .unwrap()
            .is_empty(),
        "the link's Welcome is withdrawn"
    );
    assert!(!phone.roster(&group).devices.contains_key(&laptop_slot));
    let leaf = hex::decode(link_record(&phone, &group, &slot).leaf_signature_key_hex).unwrap();
    assert!(
        !phone
            .app
            .account_storage("alice")
            .unwrap()
            .get_group(&group)
            .unwrap()
            .members
            .iter()
            .any(|member| member.credential == leaf)
    );

    laptop.client.drive_device_pairing_at(now + 601).await;
    let gave_up = laptop.step(&relay).await;
    assert!(matches!(
        gave_up.new_device,
        Some(NewDeviceLinkState::Ended { .. })
    ));
    assert_eq!(laptop.trust(&group), None);
}

/// A device that joins but makes no commit in the device group by the
/// link's deadline is removed by the device that linked it, with its roster
/// entry, in one commit. Joining the Welcome late, it then reads its own
/// removal: it forgets the group and tells its user that linking failed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_with_no_first_commit_by_the_deadline_is_removed_and_told() {
    let (relay, [mut phone, mut laptop]) = alice_devices::<2>().await;
    let slot = choose_link(&relay, &mut phone, &mut laptop).await;
    laptop.op(DeviceLinkOp::ConfirmMatch).await;
    laptop.step(&relay).await; // phone's confirm in, laptop's out
    let committed = phone.step(&relay).await; // laptop's confirm in: the group
    assert_eq!(
        committed.prompt_for_slot(&slot).unwrap().state,
        DeviceLinkPromptState::Linking
    );
    let group = phone.client.trusted_device_group().unwrap().unwrap();
    let laptop_slot: [u8; 32] = hex::decode(&slot).unwrap().try_into().unwrap();

    phone
        .client
        .drive_device_pairing_at(crate::unix_now_seconds() + LINK_DEADLINE_SECS + 1)
        .await;
    let ended = phone.step(&relay).await;
    assert_eq!(
        ended.prompt_for_slot(&slot).unwrap().state,
        DeviceLinkPromptState::Ended {
            reason: DeviceLinkEndReason::LinkFailed
        }
    );
    assert_eq!(
        link_record(&phone, &group, &slot).outcome,
        DeviceLinkOutcome::Failed
    );
    assert!(!phone.roster(&group).devices.contains_key(&laptop_slot));

    let removed = laptop.step(&relay).await; // the Welcome, then its removal
    assert_eq!(
        removed.new_device,
        Some(NewDeviceLinkState::Ended {
            reason: DeviceLinkEndReason::LinkFailed
        })
    );
    assert_eq!(laptop.client.trusted_device_group().unwrap(), None);
    assert_eq!(laptop.trust(&group), None);
    let laptop_storage = laptop.app.account_storage("alice").unwrap().app_storage();
    assert!(laptop_storage.device_group_joins().unwrap().is_empty());

    // A failed link stays failed: the commit it waited for changes nothing.
    phone.step(&relay).await;
    assert_eq!(
        link_record(&phone, &group, &slot).outcome,
        DeviceLinkOutcome::Failed
    );
}

/// Closes `device`'s client and opens it again, as a restart does: pairing
/// keeps nothing across it.
async fn reopen(device: Device) -> Device {
    let Device {
        _dir,
        app,
        client,
        cursor,
    } = device;
    drop(client);
    let client = app.client("alice").await.unwrap();
    Device {
        _dir,
        app,
        client,
        cursor,
    }
}

/// A restart drops a first link's prompt while no relay has taken its
/// founding Welcome. The link is decided by the same gate: pending past the
/// new device's Welcome wait, failed at the link's deadline.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_link_whose_welcome_is_owed_across_a_restart_fails_at_the_deadline() {
    let (relay, [mut phone, mut laptop]) = alice_devices::<2>().await;
    let (group, slot) = create_device_group_unpublished(&relay, &mut phone, &mut laptop).await;
    let mut phone = reopen(phone).await;

    let now = crate::unix_now_seconds();
    for later in [0, 1, 601] {
        phone.client.drive_device_pairing_at(now + later).await;
        assert_eq!(
            link_record(&phone, &group, &slot).outcome,
            DeviceLinkOutcome::Pending,
            "a roster entry is no link until the new device's first commit"
        );
    }
    phone
        .client
        .drive_device_pairing_at(now + LINK_DEADLINE_SECS + 1)
        .await;
    assert_eq!(
        link_record(&phone, &group, &slot).outcome,
        DeviceLinkOutcome::Failed
    );
}

/// A restart drops a later link's prompt after its commit. The new device's
/// first commit still makes the link.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_link_is_made_across_a_restart_by_the_new_devices_first_commit() {
    let (relay, [mut phone, mut laptop, mut tablet]) = alice_devices::<3>().await;
    let (group, slot) =
        link_tablet_until_commit(&relay, &mut phone, &mut laptop, &mut tablet).await;
    phone.step(&relay).await; // tablet's confirm in: the commit
    let mut phone = reopen(phone).await;
    assert_eq!(
        link_record(&phone, &group, &slot).outcome,
        DeviceLinkOutcome::Pending
    );

    let joined = tablet.step(&relay).await; // the Welcome, and its first commit
    assert_eq!(joined.new_device, Some(NewDeviceLinkState::Linked));
    phone.step(&relay).await; // that commit
    assert_eq!(
        link_record(&phone, &group, &slot).outcome,
        DeviceLinkOutcome::Linked
    );
}

/// Prompt ids never repeat across a reopen, so an id a host kept from
/// before it approves nothing after it, even for a new request in the same
/// place.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_prompt_id_from_before_a_reopen_approves_nothing() {
    let (relay, [mut phone, mut laptop]) = alice_devices::<2>().await;
    laptop.op(DeviceLinkOp::Start).await;
    phone.step(&relay).await; // request in, answer out
    laptop.step(&relay).await; // answer in, reveal out
    let before = phone.step(&relay).await; // reveal in: the code
    let (stale_id, _) = prompt_code(&before, &laptop.slot_hex());

    let mut phone = reopen(phone).await;
    laptop.op(DeviceLinkOp::Cancel).await;
    laptop.op(DeviceLinkOp::Start).await;
    phone.step(&relay).await; // the new request in, answer out
    laptop.step(&relay).await; // answer in, reveal out
    let after = phone.step(&relay).await; // reveal in: the code
    let (fresh_id, _) = prompt_code(&after, &laptop.slot_hex());
    assert_ne!(stale_id, fresh_id);

    let refused = phone
        .client
        .device_link(DeviceLinkOp::Link {
            prompt_id: stale_id,
            choices: DeviceLinkChoices::new("Laptop"),
        })
        .await;
    assert!(matches!(
        refused,
        Err(AppError::DeviceGroupRefused("unknown_prompt"))
    ));
    let unchanged = phone.step(&relay).await;
    assert!(matches!(
        unchanged.prompt_for_slot(&laptop.slot_hex()).unwrap().state,
        DeviceLinkPromptState::Comparing { .. }
    ));
}

/// Runs a second link, of `tablet` by `phone`, up to the commit: the tablet
/// waits for its Welcome. Returns the device group and the tablet's slot.
async fn link_tablet_until_commit(
    relay: &ScriptedPushRelayClient,
    phone: &mut Device,
    laptop: &mut Device,
    tablet: &mut Device,
) -> (GroupId, String) {
    let group = link(relay, phone, laptop, "Laptop").await;
    phone.step(relay).await;
    let slot = choose_link(relay, phone, tablet).await;
    tablet.op(DeviceLinkOp::ConfirmMatch).await;
    let joining = tablet.step(relay).await; // phone's confirm in, tablet's out
    assert_eq!(joining.new_device, Some(NewDeviceLinkState::Joining));
    (group, slot)
}

/// A later link's commit lands, but no relay takes its Welcome. The link
/// stays linking while that Welcome is published again; once it lands the
/// new device joins, and its first commit makes the link.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_link_commits_undelivered_welcome_is_published_again_until_it_lands() {
    let (relay, [mut phone, mut laptop, mut tablet]) = alice_devices::<3>().await;
    let (group, slot) =
        link_tablet_until_commit(&relay, &mut phone, &mut laptop, &mut tablet).await;

    relay.fail_publishes_of_kind(transport_nostr_peeler::KIND_NIP59_GIFT_WRAP);
    let committed = phone.step(&relay).await; // tablet's confirm in: the commit
    assert_eq!(
        committed.prompt_for_slot(&slot).unwrap().state,
        DeviceLinkPromptState::Linking,
        "a link whose Welcome reached no relay is not linked"
    );
    assert!(
        phone
            .client
            .runtime
            .epoch_state(&group)
            .is_some_and(|state| !state.is_resolving_local_publish()),
        "the commit landed"
    );

    relay.allow_all_publish_kinds();
    // Past the redelivery backoff: the Welcome goes out again.
    phone
        .client
        .drive_device_pairing_at(crate::unix_now_seconds() + 10)
        .await;
    let landed = phone.step(&relay).await;
    assert_eq!(
        landed.prompt_for_slot(&slot).unwrap().state,
        DeviceLinkPromptState::Linking
    );
    join_then_linked(&relay, &mut phone, &mut tablet).await;
    assert_eq!(tablet.trust(&group), Some(DeviceGroupTrust::Linked));
}

/// Date the failed attempts of the publishes `client` retains in `group` ten
/// seconds back, so the next drive retries them rather than waiting out the
/// five-second backoff of an unavailable relay.
fn make_retained_publish_due(client: &AppClient, group: &GroupId) {
    let attempted_ms = u64::try_from(crate::notifications::unix_now_ms()).unwrap() - 10_000;
    for mut fanout in client
        .runtime
        .session()
        .outbound_fanouts_for_group(group)
        .unwrap()
    {
        for index in fanout.outstanding_target_indexes() {
            let failure = fanout.target_failure(index).unwrap().clone();
            fanout.mark_attempt_started_at(index, attempted_ms).unwrap();
            fanout.record_target_failure(index, failure).unwrap();
        }
        client
            .runtime
            .session()
            .put_outbound_fanout(&fanout)
            .unwrap();
    }
}

/// A link commit whose publish fails before any relay takes it stays with
/// the runtime, which retries it. The link stays linking and the new device
/// gets no Welcome until the commit lands; then both devices are linked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_link_commit_that_failed_in_transit_links_once_it_lands() {
    let (relay, [mut phone, mut laptop, mut tablet]) = alice_devices::<3>().await;
    let (group, slot) =
        link_tablet_until_commit(&relay, &mut phone, &mut laptop, &mut tablet).await;

    relay.fail_publishes_as_unavailable();
    let committed = phone.step(&relay).await; // tablet's confirm in: the commit
    relay.allow_publishes();
    assert_eq!(
        committed.prompt_for_slot(&slot).unwrap().state,
        DeviceLinkPromptState::Linking
    );
    assert!(
        phone
            .client
            .runtime
            .epoch_state(&group)
            .is_some_and(|state| state.is_resolving_local_publish()),
        "the runtime keeps the commit to retry"
    );
    // Later drives publish no Welcome of the link while its commit waits.
    phone
        .client
        .drive_device_pairing_at(crate::unix_now_seconds() + 60)
        .await;
    let still_linking = phone.step(&relay).await;
    assert_eq!(
        still_linking.prompt_for_slot(&slot).unwrap().state,
        DeviceLinkPromptState::Linking
    );
    let waiting = tablet.step(&relay).await;
    assert_eq!(waiting.new_device, Some(NewDeviceLinkState::Joining));
    assert_eq!(
        tablet.trust(&group),
        Some(DeviceGroupTrust::AwaitingWelcome)
    );

    make_retained_publish_due(&phone.client, &group);
    let retried = phone
        .client
        .runtime
        .advance_convergence(&group)
        .await
        .unwrap();
    phone
        .client
        .observe_drained_session_events(&retried)
        .await
        .unwrap();
    let landed = phone.step(&relay).await;
    assert_eq!(
        landed.prompt_for_slot(&slot).unwrap().state,
        DeviceLinkPromptState::Linking
    );
    join_then_linked(&relay, &mut phone, &mut tablet).await;
    assert_eq!(tablet.trust(&group), Some(DeviceGroupTrust::Linked));
}

/// A link the device group is too unsettled to commit waits as an approval,
/// retried while the new device waits for its Welcome. Not now is refused
/// for it too, so the approval is not dropped while the new device waits.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn not_now_is_refused_while_an_approval_waits() {
    let (relay, [mut phone, mut laptop, mut tablet]) = alice_devices::<3>().await;
    let (group, slot) =
        link_tablet_until_commit(&relay, &mut phone, &mut laptop, &mut tablet).await;
    // A roster commit of the phone's own in flight leaves the device group
    // unsettled.
    relay.fail_publishes_as_unavailable();
    let _ = phone.client.rotate_key_package().await;
    assert!(
        phone
            .client
            .runtime
            .epoch_state(&group)
            .is_some_and(|state| state.is_resolving_local_publish()),
        "the phone's own commit is in flight"
    );

    let waiting = phone.step(&relay).await; // tablet's confirm in: no commit yet
    let prompt = waiting.prompt_for_slot(&slot).unwrap();
    assert_eq!(prompt.state, DeviceLinkPromptState::Linking);
    let refused = phone
        .client
        .device_link(DeviceLinkOp::Decline {
            prompt_id: prompt.prompt_id.clone(),
        })
        .await;
    assert!(matches!(
        refused,
        Err(AppError::DeviceGroupRefused("link_in_progress"))
    ));
    assert_eq!(
        phone
            .step(&relay)
            .await
            .prompt_for_slot(&slot)
            .unwrap()
            .state,
        DeviceLinkPromptState::Linking
    );
}

/// A retained link commit whose retry the relay refuses rolls back: the link
/// ends on both devices, and the new device never got a Welcome.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_retained_link_commit_that_rolls_back_ends_the_link() {
    let (relay, [mut phone, mut laptop, mut tablet]) = alice_devices::<3>().await;
    let (group, slot) =
        link_tablet_until_commit(&relay, &mut phone, &mut laptop, &mut tablet).await;

    relay.fail_publishes_as_unavailable();
    let committed = phone.step(&relay).await; // tablet's confirm in: the commit
    relay.allow_publishes();
    assert_eq!(
        committed.prompt_for_slot(&slot).unwrap().state,
        DeviceLinkPromptState::Linking
    );

    relay.reject_next_publish();
    make_retained_publish_due(&phone.client, &group);
    let retried = phone
        .client
        .runtime
        .advance_convergence(&group)
        .await
        .unwrap();
    assert!(matches!(
        phone.client.observe_drained_session_events(&retried).await,
        Err(AppError::Publish(_))
    ));
    assert!(
        !phone
            .client
            .runtime
            .epoch_state(&group)
            .is_some_and(|state| state.is_resolving_local_publish()),
        "the refused retry rolled the commit back"
    );
    let failed = phone.step(&relay).await;
    assert_eq!(
        failed.prompt_for_slot(&slot).unwrap().state,
        DeviceLinkPromptState::Ended {
            reason: DeviceLinkEndReason::LinkFailed
        }
    );
    let ended = tablet.step(&relay).await;
    assert_eq!(
        ended.new_device,
        Some(NewDeviceLinkState::Ended {
            reason: DeviceLinkEndReason::CannotLink
        })
    );
    assert_eq!(tablet.trust(&group), None);
}

/// A link commit the relay refused rolls back, so the link ends on both
/// devices and its record fails once the quiet roster has gone a whole
/// settlement window without it, since branch selection might still bring
/// the commit back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_link_commit_ends_the_link_on_both_devices() {
    let (relay, [mut phone, mut laptop, mut tablet]) =
        alice_devices_settling_after::<3>(1_500).await;
    let (group, slot) =
        link_tablet_until_commit(&relay, &mut phone, &mut laptop, &mut tablet).await;

    relay.reject_next_publish();
    let failed = phone.step(&relay).await; // tablet's confirm in: the commit
    assert_eq!(
        failed.prompt_for_slot(&slot).unwrap().state,
        DeviceLinkPromptState::Ended {
            reason: DeviceLinkEndReason::LinkFailed
        }
    );
    let ended = tablet.step(&relay).await;
    assert_eq!(
        ended.new_device,
        Some(NewDeviceLinkState::Ended {
            reason: DeviceLinkEndReason::CannotLink
        })
    );
    assert_eq!(tablet.trust(&group), None);
    assert_eq!(
        link_record(&phone, &group, &slot).outcome,
        DeviceLinkOutcome::Pending
    );
    tokio::time::sleep(Duration::from_millis(1_600)).await;
    phone.step(&relay).await;
    assert_eq!(
        link_record(&phone, &group, &slot).outcome,
        DeviceLinkOutcome::Failed
    );
}

/// A link is recorded before its commit. One whose device group was never
/// created, as after a crash between the two, fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_approval_whose_device_group_never_existed_fails() {
    let (_relay, [mut phone]) = alice_devices::<1>().await;
    let (group_hex, slot_hex) = ("ab".repeat(16), "cd".repeat(32));
    let storage = phone.app.account_storage("alice").unwrap().app_storage();
    storage
        .record_device_link(&group_hex, &slot_hex, &"ef".repeat(32), &"12".repeat(32), 1)
        .unwrap();

    phone
        .client
        .drive_device_pairing_at(crate::unix_now_seconds())
        .await;
    assert_eq!(
        storage
            .device_link(&group_hex, &slot_hex)
            .unwrap()
            .unwrap()
            .outcome,
        DeviceLinkOutcome::Failed
    );
}

/// Without device groups, linking is refused and nothing runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn linking_is_refused_without_device_groups() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay_and_config(
        dir.path(),
        "wss://relay.example",
        MarmotAppConfig::white_noise(),
    )
    .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let mut client = app.client("alice").await.unwrap();
    assert!(matches!(
        client.device_link(DeviceLinkOp::Start).await,
        Err(AppError::DeviceGroupRefused("pairing_unsupported"))
    ));
    assert!(!client.take_device_link_changed());
}

/// A client opens owing hosts one `DeviceLinkChanged`, since an open ends
/// any link in progress. After that, each change in linking as the device
/// shows it raises one, and a read or a delivery that changes nothing
/// raises none.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_change_in_linking_is_announced_once() {
    let (relay, [mut phone, mut laptop]) = alice_devices::<2>().await;
    assert!(phone.client.take_device_link_changed());
    assert!(laptop.client.take_device_link_changed());
    phone.step(&relay).await;
    assert!(!phone.client.take_device_link_changed());

    laptop.op(DeviceLinkOp::Start).await;
    assert!(laptop.client.take_device_link_changed());
    laptop.op(DeviceLinkOp::Read).await;
    assert!(!laptop.client.take_device_link_changed());
    phone.step(&relay).await; // request in: a prompt
    assert!(phone.client.take_device_link_changed());
    laptop.step(&relay).await; // answer in: the code
    assert!(laptop.client.take_device_link_changed());
    laptop.step(&relay).await;
    assert!(!laptop.client.take_device_link_changed());
}

/// The runtime announces linking when the account's worker opens, and after
/// a link starts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_runtime_announces_linking() {
    let (relay, [phone]) = alice_devices::<1>().await;
    let Device {
        _dir, app, client, ..
    } = phone;
    drop(client);
    let account_id_hex = app.account_home().account("alice").unwrap().account_id_hex;
    let _eose = scripted_eose_pump(app.relay_plane.clone(), relay, every_subscription);
    let runtime = MarmotAppRuntime::new(app.clone());
    let mut events = runtime.subscribe();
    runtime.reconcile_accounts().await.unwrap();
    next_device_link_changed(&mut events, &account_id_hex).await;

    let started = runtime.start_device_link("alice").await.unwrap();
    assert_eq!(
        started.new_device,
        Some(NewDeviceLinkState::WaitingForAnswer)
    );
    next_device_link_changed(&mut events, &account_id_hex).await;
    runtime.shutdown().await;
}

/// Waits for the account's next `DeviceLinkChanged`.
async fn next_device_link_changed(
    events: &mut tokio::sync::broadcast::Receiver<MarmotAppEvent>,
    account_id_hex: &str,
) {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            match events.recv().await {
                Ok(MarmotAppEvent::DeviceLinkChanged {
                    account_id_hex: changed,
                    account_label,
                }) if changed == account_id_hex && account_label == "alice" => break,
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => panic!("events closed"),
            }
        }
    })
    .await
    .expect("DeviceLinkChanged");
}
