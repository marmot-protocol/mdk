//! Linking a new device through pairing (mdk#2628 item 3.3b): both screens
//! show the same seven emoji, both users confirm, and the existing device
//! adds the confirmed KeyPackage in one commit that writes its roster entry.
//! The new device joins only through the Welcome from the leaf that
//! confirmation named, and the commit's Welcome goes out only once the
//! commit is confirmed.

use super::canonical_membership::{deliver_new, published_key_package};
use super::*;
use crate::client::device_group::{LINK_DEADLINE_SECS, WELCOME_WAIT_SECS};
use crate::{
    DeviceLinkChoices, DeviceLinkEndReason, DeviceLinkOp, DeviceLinkPromptState,
    DeviceLinkSnapshot, NewDeviceLinkState, SignInResponse,
};
use cgka_traits::app_components::{
    DEVICE_ROSTER_COMPONENT_ID, DeviceEntryV1, DeviceRosterOperationV1, DeviceRosterUpdateV1,
    DeviceRosterV1, MAX_LEAVES_PER_ACCOUNT, decode_device_roster_v1,
    encode_device_roster_update_v1,
};
use cgka_traits::engine::SendIntent;
use storage_sqlite::{DeviceGroupTrust, DeviceLinkOutcome};

mod device_group_moves;
mod linked_device_chats;
mod three_device_journeys;

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
    link_with(relay, existing, new, DeviceLinkChoices::new(label)).await
}

/// [`link`], with `choices` for the new device.
async fn link_with(
    relay: &ScriptedPushRelayClient,
    existing: &mut Device,
    new: &mut Device,
    choices: DeviceLinkChoices,
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
    let linking = existing.op(DeviceLinkOp::Link { prompt_id, choices }).await;
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
    link_record_of(&device.app, group, slot_hex)
}

/// [`link_record`], read through `app`.
fn link_record_of(
    app: &MarmotApp,
    group: &GroupId,
    slot_hex: &str,
) -> storage_sqlite::DeviceLinkRecord {
    app.account_storage("alice")
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
    let key_package_ref = hex::decode(&record.key_package_ref_hex).unwrap();
    assert_eq!(
        phone
            .client
            .runtime
            .welcomes_for_key_package(&group, &key_package_ref)
            .unwrap()
            .len(),
        1,
        "the link's Welcome is found by its KeyPackage's event id"
    );
    assert_eq!(
        Some(hex::decode(&record.leaf_signature_key_hex).unwrap()),
        phone.roster(&group).devices[&laptop_slot].tag_signature_key
    );
    // The new device forgets its join once its first commit there landed.
    laptop.step(&relay).await;
    let joins = laptop.app.account_storage("alice").unwrap().app_storage();
    assert!(joins.device_group_joins().unwrap().is_empty());
}

/// A real made link can disappear from the approver's selected roster. Its
/// local context never authenticates a new publication; explicit reset and
/// fresh code pairing preserve ordinary chat data through encrypted reopen.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_completed_link_can_disappear_from_the_approvers_selected_roster() {
    use crate::tests::device_group::converge_device_group;

    let (relay, [mut phone, mut tablet, mut laptop]) = alice_devices::<3>().await;
    // A real ordinary chat and its local content must survive resetting only
    // the hidden device group. This uses the same existing three-device world.
    let chat = laptop
        .client
        .create_group("Keep my chat", &[])
        .await
        .unwrap()
        .operation
        .expect("eligible fixture members");
    let message = crate::tests::device_group::history_delivery::send_text(
        &mut laptop.client,
        &chat,
        "Keep my local history",
    )
    .await;
    let chat_hex = hex::encode(chat.as_slice());
    let saved_draft = laptop
        .app
        .account_storage("alice")
        .unwrap()
        .app_storage()
        .save_message_draft(&chat_hex, "Keep my unfinished message", None, &[])
        .unwrap();
    let saved_settings = laptop
        .app
        .account_storage("alice")
        .unwrap()
        .app_storage()
        .set_chat_muted(&chat_hex, None)
        .unwrap();
    let account_id = laptop.client.runtime.self_id().clone();
    let group = link(&relay, &mut phone, &mut tablet, "Tablet").await;
    let pre_add_epoch = tablet.client.runtime.group_record(&group).unwrap().epoch;
    let tablet_slot_hex = tablet.slot_hex();
    let tablet_slot: [u8; 32] = hex::decode(&tablet_slot_hex).unwrap().try_into().unwrap();
    let laptop_slot_hex = laptop.slot_hex();
    let laptop_slot: [u8; 32] = hex::decode(&laptop_slot_hex).unwrap().try_into().unwrap();

    let linked_group = link(&relay, &mut phone, &mut laptop, "Laptop").await;
    assert!(linked_group == group);
    // Have an ordinary unconsumed publication BEFORE the split, so both
    // discovery and the busy-comparison control use real existing supply.
    // Its announcement is fully delivered before Tablet's deeper fork wins.
    let replacement = laptop.client.rotate_key_package().await.unwrap();
    let replacement_ref = marmot_session::key_package_metadata(&replacement)
        .unwrap()
        .key_package_ref_hex;
    converge_device_group(&mut phone.client, &relay, &mut phone.cursor, &group, 8).await;
    assert_eq!(
        phone.roster(&group).devices[&laptop_slot]
            .announced_key_package
            .as_deref(),
        Some(hex::decode(&replacement_ref).unwrap().as_slice())
    );
    let made = link_record(&phone, &group, &laptop_slot_hex);
    assert_eq!(made.outcome, DeviceLinkOutcome::Linked);
    assert!(made.decided_at.is_some());
    assert!(phone.roster(&group).devices.contains_key(&laptop_slot));
    assert!(matches!(
        phone.client.runtime.epoch_state(&group),
        Some(cgka_traits::EpochState::Stable { .. })
    ));
    assert!(
        !phone
            .client
            .runtime
            .has_pending_convergence_inputs(&group)
            .unwrap()
    );
    let linked_epoch = phone.client.runtime.group_record(&group).unwrap().epoch;
    assert!(linked_epoch > pre_add_epoch);
    assert!(tablet.client.runtime.group_record(&group).unwrap().epoch == pre_add_epoch);
    assert!(!tablet.roster(&group).devices.contains_key(&laptop_slot));

    // No Laptop traffic was delivered to Tablet. Each real own roster edit
    // advances its branch from the epoch before the Add, without constructing
    // a replacement roster or touching stored branch state.
    let mut winning_label = String::new();
    for index in 1..=4 {
        if tablet.client.runtime.group_record(&group).unwrap().epoch > linked_epoch {
            break;
        }
        winning_label = format!("Tablet branch {index}");
        tablet
            .client
            .rename_linked_device(&tablet_slot_hex, &winning_label)
            .await
            .unwrap();
    }
    let branch_epoch = tablet.client.runtime.group_record(&group).unwrap().epoch;
    assert!(
        branch_epoch > linked_epoch,
        "the genuine sibling branch must be deeper"
    );
    converge_device_group(&mut phone.client, &relay, &mut phone.cursor, &group, 8).await;
    let selected = phone.roster(&group);
    let selected_deeper_branch = selected
        .devices
        .get(&tablet_slot)
        .is_some_and(|entry| entry.label == winning_label)
        && phone.client.runtime.group_record(&group).unwrap().epoch >= branch_epoch;
    let approver_lists_target = selected.devices.contains_key(&laptop_slot);
    let durable_link_unchanged = link_record(&phone, &group, &laptop_slot_hex) == made;
    eprintln!(
        "completed_link_loss: selected_deeper_branch={selected_deeper_branch}, approver_lists_target={approver_lists_target}, durable_link_unchanged={durable_link_unchanged}"
    );
    assert!(
        selected_deeper_branch,
        "normal branch selection must choose the genuine deeper branch"
    );
    assert!(
        !approver_lists_target,
        "the selected pre-Add branch does not admit Laptop"
    );
    assert!(
        durable_link_unchanged,
        "a made approval remains durable Linked after branch selection"
    );

    // Present those actual published commits to Laptop as well. It joined
    // after their fork point, so a removal notification must not be inferred
    // merely from another device selecting a branch it cannot follow.
    converge_device_group(&mut laptop.client, &relay, &mut laptop.cursor, &group, 8).await;
    let target_group_retained = laptop.client.runtime.group_record(&group).is_ok();
    let target_lists_own_key =
        laptop
            .roster(&group)
            .devices
            .get(&laptop_slot)
            .is_some_and(|entry| {
                entry.tag_signature_key.as_ref() == Some(&laptop.client.runtime.own_signature_key())
            });
    let target_unlinked = laptop.client.device_unlinked();
    let target_still_trusts = laptop.trust(&group) == Some(DeviceGroupTrust::Linked);
    let target_view = laptop.op(DeviceLinkOp::Read).await;
    let target_view_linked = target_view.new_device == Some(NewDeviceLinkState::Linked);
    eprintln!(
        "completed_link_loss: target_group_retained={target_group_retained}, target_lists_own_key={target_lists_own_key}, target_unlinked={target_unlinked}, target_still_trusts={target_still_trusts}, target_view_linked={target_view_linked}"
    );
    assert!(target_group_retained && target_lists_own_key && target_still_trusts);
    assert!(
        !target_unlinked,
        "no selected removal has unlinked the target"
    );
    assert!(
        target_view_linked,
        "the current pairing view has no failed-link/removal notice"
    );

    // Prerequisite for the explicit local reset: these are the real
    // existing helpers used by old-copy cleanup, including accepted native
    // application bookkeeping awaiting its App ACK. No retained row is
    // removed or synthetic acknowledgement supplied to make them quiet.
    let pending_fanout = laptop
        .client
        .runtime
        .has_pending_outbound_fanouts(&group)
        .unwrap();
    let queued_intent = laptop
        .client
        .runtime
        .has_queued_outbound_intents(&group)
        .unwrap();
    eprintln!(
        "repair_reset_prerequisite: pending_fanout={pending_fanout}, queued_intent={queued_intent}"
    );
    assert!(
        !pending_fanout,
        "the actual split copy must have no unsettled native fanout or accepted bookkeeping"
    );
    assert!(
        !queued_intent,
        "the actual split copy must have no queued native work"
    );

    // Read the authentic publication the relay already holds. Publishing
    // anew while Laptop still trusts its split copy also announces the KP
    // in a native group Commit, which can heal the split during pairing.
    // Observation alone must not introduce that separate producer here.
    phone.client.check_sign_ins().await.unwrap();
    assert!(!phone.roster(&group).devices.contains_key(&laptop_slot));
    let sign_ins = phone.client.unrecognized_sign_ins().unwrap();
    let missing = sign_ins
        .iter()
        .find(|row| row.slot_id_hex == laptop_slot_hex)
        .unwrap();
    assert_eq!(missing.state, crate::UnrecognizedSignInState::Prompt);
    assert!(missing.signed_in);
    assert!(
        missing.previously_linked_here,
        "the actual retained made link must annotate this missing slot"
    );

    let used = made.key_package_ref_hex.clone();
    // Refuse an active comparison while the old trusted copy still exists.
    laptop.op(DeviceLinkOp::Start).await;
    let busy = laptop
        .client
        .device_link(DeviceLinkOp::ResetForRepair)
        .await;
    assert!(
        matches!(busy, Err(AppError::DeviceGroupRefused("device_group_busy"))),
        "{busy:?}"
    );
    assert_eq!(laptop.trust(&group), Some(DeviceGroupTrust::Linked));
    laptop.op(DeviceLinkOp::Cancel).await;
    let reset = laptop.op(DeviceLinkOp::ResetForRepair).await;
    assert_eq!(reset.new_device, None);
    assert_eq!(laptop.client.trusted_device_group().unwrap(), None);
    assert!(laptop.client.runtime.group_record(&group).is_err());
    assert!(
        !laptop.client.device_unlinked(),
        "an explicit local reset is not a removal"
    );
    assert!(laptop.client.runtime.group_record(&chat).is_ok());
    laptop = reopen(laptop).await;
    assert_eq!(laptop.slot_hex(), laptop_slot_hex);
    assert_eq!(laptop.client.runtime.self_id(), account_id);
    assert_eq!(laptop.client.trusted_device_group().unwrap(), None);
    let app = laptop.app.account_storage("alice").unwrap().app_storage();
    assert!(app.timeline_message(&chat_hex, &message).unwrap().is_some());
    assert!(app.message_draft(&chat_hex).unwrap().as_ref() == Some(&saved_draft));
    assert_eq!(
        app.chat_notification_settings(&chat_hex).unwrap(),
        saved_settings
    );
    assert!(laptop.client.runtime.group_record(&chat).is_ok());

    // A cancelled fresh comparison leaves needs-link; it never restores the
    // discarded copy. Publishing a new reference follows the ordinary owner.
    assert_eq!(laptop.client.trusted_device_group().unwrap(), None);
    let fresh = laptop.client.rotate_key_package().await.unwrap();
    let fresh_ref = marmot_session::key_package_metadata(&fresh)
        .unwrap()
        .key_package_ref_hex;
    assert_ne!(fresh_ref, used);
    assert_ne!(fresh_ref, replacement_ref);
    assert_eq!(laptop.client.trusted_device_group().unwrap(), None);
    laptop.op(DeviceLinkOp::Start).await;
    let already_reset = laptop
        .client
        .device_link(DeviceLinkOp::ResetForRepair)
        .await;
    assert!(
        matches!(
            already_reset,
            Err(AppError::DeviceGroupRefused("no_device_group"))
        ),
        "{already_reset:?}"
    );
    assert!(laptop.op(DeviceLinkOp::Read).await.new_device.is_some());
    laptop.op(DeviceLinkOp::Cancel).await;
    laptop = reopen(laptop).await;
    assert_eq!(laptop.client.trusted_device_group().unwrap(), None);
    assert!(laptop.client.runtime.group_record(&group).is_err());
    // Re-deliver the real relay history, including the old Welcome. Existing
    // replay/authentication owners, not an inferred unlink signal, reject it.
    let mut replay_cursor = 0;
    deliver_new(&mut laptop.client, &relay, &mut replay_cursor).await;
    assert_eq!(laptop.client.trusted_device_group().unwrap(), None);
    assert!(laptop.client.runtime.group_record(&group).is_err());
    let current = laptop
        .app
        .account_storage("alice")
        .unwrap()
        .key_package_lifecycle()
        .unwrap()
        .unwrap();
    assert_ne!(
        current
            .current_key_package_ref
            .as_ref()
            .map(hex::encode)
            .as_deref(),
        Some(used.as_str()),
        "fresh pairing must not name the installed KeyPackage"
    );
    assert_eq!(
        current
            .current_key_package_ref
            .as_ref()
            .map(hex::encode)
            .as_deref(),
        Some(fresh_ref.as_str())
    );
    let private_init_present = laptop
        .client
        .runtime
        .durably_owned_key_packages()
        .unwrap()
        .iter()
        .any(|kp| {
            marmot_session::key_package_metadata(kp)
                .unwrap()
                .key_package_ref_hex
                == fresh_ref
        });
    assert!(
        private_init_present,
        "the fresh confirmed reference must still own its private OpenMLS bundle"
    );
    let own_key = laptop.client.runtime.own_signature_key();
    let selected_members = phone.client.runtime.group_record(&group).unwrap().members;
    let old_leaf_present = selected_members
        .iter()
        .any(|member| member.credential == own_key);
    eprintln!(
        "repair_admission_prerequisite: selected_leaf_count={}, old_leaf_present={old_leaf_present}",
        selected_members.len()
    );
    assert!(
        !old_leaf_present,
        "ordinary fresh admission requires the approver not to retain the old signature key"
    );
    let exact = phone
        .client
        .runtime
        .own_account_leaf_claims(&group, &phone.roster(&group))
        .unwrap();
    assert!(
        !exact.iter().any(|(key, _)| *key == own_key),
        "the actual native tree must permit ordinary readmission"
    );

    assert_eq!(
        link(&relay, &mut phone, &mut laptop, "Laptop repaired").await,
        group
    );
    assert_eq!(laptop.trust(&group), Some(DeviceGroupTrust::Linked));
    let repaired = link_record(&phone, &group, &laptop_slot_hex);
    assert_eq!(repaired.outcome, DeviceLinkOutcome::Linked);
    assert_ne!(repaired.key_package_ref_hex, used);
    assert_eq!(laptop.slot_hex(), laptop_slot_hex);
    assert!(phone.roster(&group).devices.contains_key(&laptop_slot));
    assert!(laptop.roster(&group).devices.contains_key(&laptop_slot));
    assert!(
        !phone
            .client
            .unrecognized_sign_ins()
            .unwrap()
            .iter()
            .any(|row| row.slot_id_hex == laptop_slot_hex && row.previously_linked_here)
    );
    assert!(
        laptop
            .app
            .account_storage("alice")
            .unwrap()
            .app_storage()
            .timeline_message(&chat_hex, &message)
            .unwrap()
            .is_some()
    );

    // A real selected removal of the first linked sibling is different from
    // branch selection dropping an Add. Its still-published sign-in must not
    // become a lost-link warning, even with the made approval retained.
    let departed = link_record(&phone, &group, &tablet_slot_hex);
    assert_eq!(departed.outcome, DeviceLinkOutcome::Linked);
    let departed_key = hex::decode(&departed.leaf_signature_key_hex).unwrap();
    let claims = phone
        .client
        .runtime
        .own_account_leaf_claims(&group, &phone.roster(&group))
        .unwrap();
    assert!(claims.iter().any(|(key, claim)| {
        *key == departed_key
            && *claim == cgka_traits::app_components::DeviceTagClaim::Device(tablet_slot)
    }));
    phone
        .client
        .unlink_device_from_group(
            &group,
            departed_key.clone(),
            vec![DeviceRosterOperationV1::RemoveDevice(tablet_slot)],
        )
        .await
        .unwrap();
    let selected = phone.roster(&group);
    assert!(!selected.devices.contains_key(&tablet_slot));
    assert!(!selected.rejected_slots.contains_key(&tablet_slot));
    assert!(
        !phone
            .app
            .account_storage("alice")
            .unwrap()
            .app_storage()
            .has_device_removal(&hex::encode(group.as_slice()), &tablet_slot_hex)
            .unwrap()
    );
    assert!(
        phone
            .client
            .runtime
            .group_record(&group)
            .unwrap()
            .device_roster_departures
            .iter()
            .any(|fact| fact.slot == tablet_slot
                && fact.tag_signature_key.as_ref() == Some(&departed_key))
    );
    assert_eq!(
        link_record(&phone, &group, &tablet_slot_hex).outcome,
        DeviceLinkOutcome::Linked
    );
    assert!(phone.client.trusted_device_group().unwrap() == Some(group.clone()));
    assert!(matches!(
        phone.client.runtime.epoch_state(&group),
        Some(cgka_traits::EpochState::Stable { .. })
    ));
    assert!(
        !phone
            .client
            .runtime
            .has_pending_convergence_inputs(&group)
            .unwrap()
    );
    use cgka_traits::storage::RosterTagKeyStorage as _;
    assert!(
        phone
            .app
            .account_storage("alice")
            .unwrap()
            .roster_tag_keys(&group, 0)
            .unwrap()
            .iter()
            .all(|known| known.slot != tablet_slot
                || known.tag_signature_key != departed_key
                || !known.held_as_removed)
    );
    phone.client.check_sign_ins().await.unwrap();
    let rows = phone.client.unrecognized_sign_ins().unwrap();
    let known_departure = rows
        .iter()
        .find(|row| row.slot_id_hex == tablet_slot_hex)
        .expect("the authentic still-published sibling is listed");
    assert!(known_departure.signed_in);
    assert!(!known_departure.previously_linked_here);
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

const REJECTED: DeviceLinkPromptState = DeviceLinkPromptState::Ended {
    reason: DeviceLinkEndReason::Rejected,
};

/// mdk#3010: a device with no device group keeps its own rejections, and a
/// request from a slot it rejected gets no Link.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_from_a_slot_rejected_here_is_refused_without_a_device_group() {
    let (relay, [mut phone, mut laptop]) = alice_devices::<2>().await;
    let laptop_slot = laptop.slot_hex();
    phone.client.check_sign_ins().await.unwrap();
    phone
        .client
        .answer_sign_in(&laptop_slot, SignInResponse::Reject)
        .await
        .unwrap();
    assert_eq!(phone.client.trusted_device_group().unwrap(), None);

    laptop.op(DeviceLinkOp::Start).await;
    let refused = phone.step(&relay).await;
    assert_eq!(
        refused.prompt_for_slot(&laptop_slot).unwrap().state,
        REJECTED
    );
}

/// mdk#3010: in a device group whose roster does not hold this device's
/// rejection yet (an earlier commit of its own is still in flight, so the
/// rejection waits), a request from the rejected slot is refused as it
/// would be once the roster holds it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_from_a_slot_whose_rejection_the_roster_lacks_is_refused() {
    let (relay, [mut phone, mut laptop, mut tablet]) = alice_devices::<3>().await;
    let group = link(&relay, &mut phone, &mut laptop, "Laptop").await;
    let tablet_slot = tablet.slot_hex();
    phone.client.check_sign_ins().await.unwrap();
    relay.fail_publishes_as_unavailable();
    let _ = phone.client.rotate_key_package().await;
    phone
        .client
        .answer_sign_in(&tablet_slot, SignInResponse::Reject)
        .await
        .unwrap();
    relay.allow_publishes();
    let rejection = phone
        .app
        .account_storage("alice")
        .unwrap()
        .app_storage()
        .sign_in(&tablet_slot)
        .unwrap()
        .unwrap();
    assert!(rejection.roster_pending);

    tablet.op(DeviceLinkOp::Start).await;
    let refused = phone.step(&relay).await;
    assert_eq!(
        refused.prompt_for_slot(&tablet_slot).unwrap().state,
        REJECTED
    );
    let tablet_slot_id: [u8; 32] = hex::decode(&tablet_slot).unwrap().try_into().unwrap();
    assert!(
        !phone
            .roster(&group)
            .rejected_slots
            .contains_key(&tablet_slot_id),
        "refused on this device's own rejection alone"
    );
}

/// mdk#3010: Not now leaves a sign-in linkable, so its request gets the
/// ordinary Link prompt. Rejected while that prompt shows its code, it gets
/// no link: Link device is refused, the prompt ends rejected, and the new
/// device is told its session ended, as Not now tells it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sign_in_put_off_is_offered_link_until_it_is_rejected() {
    let (relay, [mut phone, mut laptop]) = alice_devices::<2>().await;
    let laptop_slot = laptop.slot_hex();
    phone.client.check_sign_ins().await.unwrap();
    phone
        .client
        .answer_sign_in(&laptop_slot, SignInResponse::NotNow)
        .await
        .unwrap();

    laptop.op(DeviceLinkOp::Start).await;
    phone.step(&relay).await; // request in, answer out
    laptop.step(&relay).await; // answer in, reveal out
    let prompt = phone.step(&relay).await; // reveal in: the code
    let (prompt_id, _) = prompt_code(&prompt, &laptop_slot);

    phone
        .client
        .answer_sign_in(&laptop_slot, SignInResponse::Reject)
        .await
        .unwrap();
    let refused = phone
        .client
        .device_link(DeviceLinkOp::Link {
            prompt_id,
            choices: DeviceLinkChoices::new("Laptop"),
        })
        .await;
    assert!(
        matches!(
            refused,
            Err(AppError::DeviceGroupRefused("sign_in_rejected"))
        ),
        "{refused:?}"
    );
    let ended = phone.op(DeviceLinkOp::Read).await;
    assert_eq!(ended.prompt_for_slot(&laptop_slot).unwrap().state, REJECTED);
    // The new device, shown the code, learns the session ended.
    let told = laptop.step(&relay).await;
    assert_eq!(
        told.new_device,
        Some(NewDeviceLinkState::Ended {
            reason: DeviceLinkEndReason::CancelledElsewhere
        })
    );
    let still = phone.step(&relay).await;
    assert_eq!(still.prompt_for_slot(&laptop_slot).unwrap().state, REJECTED);
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
    assert!(
        link_record(&phone, &group, &slot).welcome_withdrawn,
        "a withdrawn Welcome is not withdrawn again"
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
    assert!(link_record(&phone, &group, &slot).welcome_withdrawn);

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

/// The laptop selects its first commit in the device group, but the phone
/// reads none of it by the link's deadline and undoes the link on a deeper
/// branch, which supersedes that commit. The roster the undo left has no
/// entry for the laptop's slot, so the laptop tells its user that linking
/// failed, is not unlinked, and links again (mdk#3011).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_undo_that_supersedes_the_new_devices_first_commit_fails_the_link() {
    undo_after_the_first_commit_fails_the_link(true, false).await;
}

/// [`an_undo_that_supersedes_the_new_devices_first_commit_fails_the_link`],
/// with the laptop's branch the deeper one: it drops the phone's first undo,
/// and the phone undoes the link again after the laptop's first commit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_undo_after_the_new_devices_first_commit_fails_the_link() {
    undo_after_the_first_commit_fails_the_link(false, false).await;
}

/// [`an_undo_that_supersedes_the_new_devices_first_commit_fails_the_link`],
/// where the laptop also keeps a move into the same group with the same
/// KeyPackage that ended before Made, as one whose Welcome never came leaves
/// it. Only a made move makes a removal an unlink, so the link still fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_undo_after_a_move_that_ended_before_made_fails_the_link() {
    undo_after_the_first_commit_fails_the_link(true, true).await;
}

async fn undo_after_the_first_commit_fails_the_link(supersedes: bool, ended_move: bool) {
    let (relay, [mut phone, mut laptop]) = alice_devices::<2>().await;
    let slot = choose_link(&relay, &mut phone, &mut laptop).await;
    laptop.op(DeviceLinkOp::ConfirmMatch).await;
    laptop.step(&relay).await; // phone's confirm in, laptop's out
    phone.step(&relay).await; // laptop's confirm in: the group
    let group = phone.client.trusted_device_group().unwrap().unwrap();
    let laptop_slot: [u8; 32] = hex::decode(&slot).unwrap().try_into().unwrap();
    let joined = laptop.step(&relay).await; // the Welcome, and its first commit
    assert_eq!(joined.new_device, Some(NewDeviceLinkState::Linked));
    laptop
        .client
        .drive_device_pairing_at(crate::unix_now_seconds())
        .await;
    let laptop_storage = laptop.app.account_storage("alice").unwrap().app_storage();
    assert!(
        laptop_storage.device_group_joins().unwrap().is_empty(),
        "the laptop's first commit is selected, so it forgot its join"
    );
    assert!(
        laptop.roster(&group).devices[&laptop_slot]
            .tag_signature_key
            .is_some()
    );
    if ended_move {
        // The store writes such a row when a move ends before Made: phase 3,
        // with no captured rejected slots.
        let key_package_ref = laptop_storage
            .device_group(&hex::encode(group.as_slice()))
            .unwrap()
            .unwrap()
            .key_package_ref_hex
            .unwrap();
        linked_device_chats::account_database(&laptop.app)
            .execute(
                "INSERT INTO device_group_moves (destination_id, original_id, original_trust,
                 original_key_package_ref_hex, original_recorded_at, sender_signature_key,
                 key_package_ref, expires_at, own_slot, siblings, phase)
                 VALUES (?1, ?2, 'linked', '00', 0, X'01', ?3, 0, ?4, CAST('[]' AS BLOB), 3)",
                rusqlite::params![
                    group.as_slice(),
                    [9u8; 16].as_slice(),
                    hex::decode(key_package_ref).unwrap(),
                    laptop_slot.as_slice(),
                ],
            )
            .unwrap();
        let ended = laptop_storage.device_group_move(&group).unwrap().unwrap();
        assert_eq!(ended.phase, storage_sqlite::DeviceGroupMovePhase::Finished);
        assert!(ended.rejected_slots.is_none());
    }

    // One more commit from the epoch both fork at makes that side's branch
    // the deeper one. The phone reads nothing from the laptop meanwhile.
    let deeper = if supersedes { &mut phone } else { &mut laptop };
    let effects = deeper
        .client
        .runtime
        .send(SendIntent::SelfUpdate {
            group_id: group.clone(),
        })
        .await
        .unwrap();
    deeper
        .client
        .observe_drained_session_events(&effects)
        .await
        .unwrap();
    let deadline = crate::unix_now_seconds() + LINK_DEADLINE_SECS + 1;
    phone.client.drive_device_pairing_at(deadline).await;
    assert_eq!(
        link_record(&phone, &group, &slot).outcome,
        DeviceLinkOutcome::Failed
    );
    assert!(!phone.roster(&group).devices.contains_key(&laptop_slot));
    let undone_at = phone.client.runtime.group_record(&group).unwrap().epoch;
    super::device_group::converge_device_group(
        &mut phone.client,
        &relay,
        &mut phone.cursor,
        &group,
        2,
    )
    .await;
    if supersedes {
        assert_eq!(
            phone.client.runtime.group_record(&group).unwrap().epoch,
            undone_at,
            "the phone keeps its undo over the laptop's first commit"
        );
    } else {
        // The phone adopts the laptop's branch, which lists the laptop with
        // its key, and undoes the link again on top of it.
        assert!(phone.roster(&group).devices.contains_key(&laptop_slot));
        phone.client.drive_device_pairing_at(deadline + 1).await;
        assert!(!phone.roster(&group).devices.contains_key(&laptop_slot));
        assert_eq!(
            link_record(&phone, &group, &slot).outcome,
            DeviceLinkOutcome::Failed
        );
    }

    super::device_group::converge_device_group(
        &mut laptop.client,
        &relay,
        &mut laptop.cursor,
        &group,
        2,
    )
    .await;
    assert!(laptop.client.runtime.group_record(&group).unwrap().removed);
    let ended = laptop.step(&relay).await;
    assert_eq!(
        ended.new_device,
        Some(NewDeviceLinkState::Ended {
            reason: DeviceLinkEndReason::LinkFailed
        })
    );
    assert!(!laptop.client.device_unlinked());
    let account = laptop.app.account_home().account("alice").unwrap();
    assert!(!account.unlinked && !account.signed_out);
    assert_eq!(laptop.client.trusted_device_group().unwrap(), None);
    assert_eq!(laptop.trust(&group), None);

    published_key_package(&mut laptop.client, &relay).await;
    assert_eq!(link(&relay, &mut phone, &mut laptop, "Laptop").await, group);
    assert_eq!(laptop.trust(&group), Some(DeviceGroupTrust::Linked));
}

/// A device whose link failed discarded its copy of the device group, so a
/// later link's Welcome into that same group is a first join, and the link
/// is made.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_whose_link_failed_links_again_into_the_same_device_group() {
    links_again_after_a_failed_link(false).await;
}

/// [`a_device_whose_link_failed_links_again_into_the_same_device_group`],
/// with the new device restarting in between.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_whose_link_failed_links_again_after_a_restart() {
    links_again_after_a_failed_link(true).await;
}

async fn links_again_after_a_failed_link(restart: bool) {
    let (relay, [mut phone, mut laptop]) = alice_devices::<2>().await;
    let slot = choose_link(&relay, &mut phone, &mut laptop).await;
    laptop.op(DeviceLinkOp::ConfirmMatch).await;
    laptop.step(&relay).await; // phone's confirm in, laptop's out
    phone.step(&relay).await; // laptop's confirm in: the group
    let group = phone.client.trusted_device_group().unwrap().unwrap();
    phone
        .client
        .drive_device_pairing_at(crate::unix_now_seconds() + LINK_DEADLINE_SECS + 1)
        .await;
    phone.step(&relay).await; // the removal
    let removed = laptop.step(&relay).await; // the Welcome, then its removal
    assert_eq!(
        removed.new_device,
        Some(NewDeviceLinkState::Ended {
            reason: DeviceLinkEndReason::LinkFailed
        })
    );
    assert!(laptop.client.runtime.group_record(&group).is_err());
    let used = link_record(&phone, &group, &slot).key_package_ref_hex;
    if restart {
        laptop = reopen(laptop).await;
    }
    // The KeyPackage the laptop joined by names no later link.
    assert!(matches!(
        laptop.client.device_link(DeviceLinkOp::Start).await,
        Err(AppError::DeviceGroupRefused("key_package_not_published"))
    ));
    published_key_package(&mut laptop.client, &relay).await;

    assert_eq!(link(&relay, &mut phone, &mut laptop, "Laptop").await, group);
    assert_eq!(laptop.trust(&group), Some(DeviceGroupTrust::Linked));
    let relinked = link_record(&phone, &group, &slot);
    assert_eq!(relinked.outcome, DeviceLinkOutcome::Linked);
    assert_ne!(
        relinked.key_package_ref_hex, used,
        "a link never names a KeyPackage the device already joined by"
    );
    let laptop_slot: [u8; 32] = hex::decode(&slot).unwrap().try_into().unwrap();
    assert!(phone.roster(&group).devices.contains_key(&laptop_slot));
    assert!(laptop.roster(&group).devices.contains_key(&laptop_slot));
}

/// A slot linked again after a failed link is a new entry with a fresh
/// rename id (mdk#2628 3.6a). A rename the phone made of its earlier entry,
/// still kept because the phone settles renames only in a later pass, reads
/// that id as another rename's: the phone drops its rename rather than make
/// it again over the label the second link chose. Only the second link's
/// commit matters here, so the tablet never joins.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slot_linked_again_keeps_its_new_label_over_an_earlier_rename() {
    let (relay, [mut phone, mut laptop, mut tablet]) = alice_devices::<3>().await;
    let group = link(&relay, &mut phone, &mut laptop, "Laptop").await;
    let slot = choose_link(&relay, &mut phone, &mut tablet).await;
    tablet.op(DeviceLinkOp::ConfirmMatch).await;
    tablet.step(&relay).await; // phone's confirm in, tablet's out
    phone.step(&relay).await; // tablet's confirm in: the link commit
    let tablet_slot: [u8; 32] = hex::decode(&slot).unwrap().try_into().unwrap();
    let first = phone.roster(&group).devices[&tablet_slot].rename_id;
    assert!(
        first.is_some(),
        "a linked entry is created with a rename id"
    );

    let give_up = std::time::Instant::now() + Duration::from_secs(5);
    while let Err(error) = phone.client.rename_linked_device(&slot, "Kitchen").await {
        assert!(std::time::Instant::now() < give_up, "{error:?}");
        tokio::time::sleep(Duration::from_millis(100)).await;
        let advanced = phone
            .client
            .runtime
            .advance_convergence(&group)
            .await
            .unwrap();
        phone
            .client
            .observe_drained_session_events(&advanced)
            .await
            .unwrap();
    }
    let renames = |phone: &Device| {
        phone
            .app
            .account_storage("alice")
            .unwrap()
            .app_storage()
            .device_renames()
            .unwrap()
    };
    assert_eq!(renames(&phone).len(), 1);

    // The tablet never makes its first commit, so the phone removes it.
    phone
        .client
        .drive_device_pairing_at(crate::unix_now_seconds() + LINK_DEADLINE_SECS + 1)
        .await;
    phone.step(&relay).await;
    assert!(!phone.roster(&group).devices.contains_key(&tablet_slot));
    tablet.step(&relay).await; // the Welcome, then its removal
    assert_eq!(renames(&phone).len(), 1, "no rename pass ran meanwhile");

    // Linked again, as "Laptop" again, by a KeyPackage it has not joined by:
    // the phone's commit creates the entry anew.
    published_key_package(&mut tablet.client, &relay).await;
    assert_eq!(choose_link(&relay, &mut phone, &mut tablet).await, slot);
    tablet.op(DeviceLinkOp::ConfirmMatch).await;
    tablet.step(&relay).await; // phone's confirm in, tablet's out
    phone.step(&relay).await; // tablet's confirm in: the second link commit
    let again = phone.roster(&group).devices[&tablet_slot].rename_id;
    assert!(again.is_some() && again != first);
    phone.client.try_device_rename_upkeep().await.unwrap();
    assert_eq!(phone.roster(&group).devices[&tablet_slot].label, "Laptop");
    assert!(renames(&phone).is_empty());
}

/// Closes `device`'s client and opens it again, as a restart does: pairing
/// keeps nothing across it.
/// A new device applies its failed link's removal and closes before it
/// forgets its copy. The next process finds that removal stored and stops
/// the account's publishing until a client tells it apart; the client's
/// open finds a failed link, which stops nothing (D40), and lifts the stop.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_links_removal_found_after_a_restart_stops_nothing() {
    let (relay, [mut phone, mut laptop]) = alice_devices::<2>().await;
    choose_link(&relay, &mut phone, &mut laptop).await;
    laptop.op(DeviceLinkOp::ConfirmMatch).await;
    laptop.step(&relay).await; // phone's confirm in, laptop's out
    phone.step(&relay).await; // laptop's confirm in: the group
    let group = phone.client.trusted_device_group().unwrap().unwrap();
    phone
        .client
        .drive_device_pairing_at(crate::unix_now_seconds() + LINK_DEADLINE_SECS + 1)
        .await;
    phone.step(&relay).await; // the removal
    // The Welcome, then its removal, with no drive to forget the copy.
    deliver_new(&mut laptop.client, &relay, &mut laptop.cursor).await;
    assert!(laptop.client.runtime.group_record(&group).unwrap().removed);
    assert!(!laptop.client.device_unlinked());
    let Device {
        _dir, app, client, ..
    } = laptop;
    drop((client, app));

    let app = MarmotApp::with_relay_and_config(
        _dir.path(),
        "wss://relay.example",
        MarmotAppConfig::white_noise()
            .with_dev_settlement_quiescence_ms(0)
            .with_dev_scheduled_convergence_delay_ms(0)
            .with_dev_device_groups(true),
    )
    .with_test_relay_client(relay.clone());
    let bootstrap = || {
        AccountRelayListBootstrap::new(
            vec![TransportEndpoint("wss://relay.example".into())],
            vec![TransportEndpoint("wss://relay.example".into())],
        )
    };
    let attempted = relay.attempted_events().len();
    app.publish_user_profile("alice", UserProfileMetadata::default(), bootstrap())
        .await
        .unwrap_err();
    assert_eq!(
        relay.attempted_events().len(),
        attempted,
        "stopped until a client tells the removal apart"
    );
    let client = app.client("alice").await.unwrap();
    assert!(!client.device_unlinked());
    assert!(!app.account_home().account("alice").unwrap().unlinked);
    app.publish_user_profile("alice", UserProfileMetadata::default(), bootstrap())
        .await
        .unwrap();
    drop(client);
}

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

/// A failed link's removal that the runtime keeps to retry is not sent again
/// meanwhile; once its retry is refused and rolls back, the next drive sends
/// it again, and it removes both the leaf and the roster entry.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_links_removal_that_rolls_back_is_sent_again() {
    let (relay, [mut phone, mut laptop]) = alice_devices::<2>().await;
    let slot = choose_link(&relay, &mut phone, &mut laptop).await;
    laptop.op(DeviceLinkOp::ConfirmMatch).await;
    laptop.step(&relay).await; // phone's confirm in, laptop's out
    phone.step(&relay).await; // laptop's confirm in: the group
    let group = phone.client.trusted_device_group().unwrap().unwrap();
    let laptop_slot: [u8; 32] = hex::decode(&slot).unwrap().try_into().unwrap();
    let leaf = hex::decode(link_record(&phone, &group, &slot).leaf_signature_key_hex).unwrap();
    let state = |phone: &Device| {
        let has_leaf = phone
            .app
            .account_storage("alice")
            .unwrap()
            .get_group(&group)
            .unwrap()
            .members
            .iter()
            .any(|member| member.credential == leaf);
        (
            has_leaf,
            phone.roster(&group).devices.contains_key(&laptop_slot),
        )
    };
    let resolving = |phone: &Device| {
        phone
            .client
            .runtime
            .epoch_state(&group)
            .is_some_and(|state| state.is_resolving_local_publish())
    };

    let deadline = crate::unix_now_seconds() + LINK_DEADLINE_SECS + 1;
    relay.fail_publishes_as_unavailable();
    phone.client.drive_device_pairing_at(deadline).await;
    assert!(resolving(&phone), "the runtime keeps the removal to retry");
    phone.client.drive_device_pairing_at(deadline + 1).await;
    assert!(resolving(&phone));
    assert!(
        !phone
            .client
            .runtime
            .has_queued_outbound_intents(&group)
            .unwrap(),
        "no roster-only removal waits behind the kept one"
    );

    relay.allow_publishes();
    relay.reject_next_publish();
    make_retained_publish_due(&phone.client, &group);
    let retried = phone
        .client
        .runtime
        .advance_convergence(&group)
        .await
        .unwrap();
    assert!(
        phone
            .client
            .observe_drained_session_events(&retried)
            .await
            .is_err()
    );
    assert!(
        !resolving(&phone),
        "the refused retry rolled the removal back"
    );
    assert_eq!(state(&phone), (true, true));

    phone.client.drive_device_pairing_at(deadline + 2).await;
    assert_eq!(state(&phone), (false, false));
    assert_eq!(
        link_record(&phone, &group, &slot).outcome,
        DeviceLinkOutcome::Failed
    );
}

/// A crash after a failed link's removal is staged, before its publish is
/// stored, leaves the removal unsent: the group reads as settled, its stored
/// members already lack the leaf, and its roster still lists the device. The
/// next drive removes the leaf and the entry together, as the group's own
/// tree has them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_links_removal_lost_to_a_crash_is_sent_again_whole() {
    let (relay, [mut phone, mut laptop]) = alice_devices::<2>().await;
    let slot = choose_link(&relay, &mut phone, &mut laptop).await;
    laptop.op(DeviceLinkOp::ConfirmMatch).await;
    laptop.step(&relay).await; // phone's confirm in, laptop's out
    phone.step(&relay).await; // laptop's confirm in: the group
    let group = phone.client.trusted_device_group().unwrap().unwrap();
    let laptop_slot: [u8; 32] = hex::decode(&slot).unwrap().try_into().unwrap();
    let leaf = hex::decode(link_record(&phone, &group, &slot).leaf_signature_key_hex).unwrap();
    let state = |phone: &Device| {
        let has_leaf = phone
            .app
            .account_storage("alice")
            .unwrap()
            .get_group(&group)
            .unwrap()
            .members
            .iter()
            .any(|member| member.credential == leaf);
        (
            has_leaf,
            phone.roster(&group).devices.contains_key(&laptop_slot),
        )
    };

    let deadline = crate::unix_now_seconds() + LINK_DEADLINE_SECS + 1;
    relay.fail_publishes_as_unavailable();
    phone.client.drive_device_pairing_at(deadline).await;
    // The crash: the removal's publish was never stored.
    let session = phone.client.runtime.session();
    for fanout in session.outbound_fanouts_for_group(&group).unwrap() {
        session.delete_outbound_fanout(fanout.message_id()).unwrap();
    }
    let mut phone = reopen(phone).await;
    assert_eq!(
        state(&phone),
        (false, true),
        "the stored members lost the leaf; the roster still lists the device"
    );

    relay.allow_publishes();
    phone.client.drive_device_pairing_at(deadline + 1).await;
    assert_eq!(state(&phone), (false, false));
    let phone = reopen(phone).await;
    assert_eq!(state(&phone), (false, false), "the leaf left the tree");
}

/// A crash right after a link's commit loses nothing its failure needs: the
/// link is recorded before the commit, with its KeyPackage's ref, and a
/// failed link finds its Welcome by that ref. Here the restart keeps only
/// what was written before the commit. At the deadline the Welcome is withdrawn,
/// and no recovery publishes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_link_that_crashed_after_its_commit_still_withdraws_its_welcome() {
    let (relay, [mut phone, mut laptop]) = alice_devices::<2>().await;
    let (group, slot) = create_device_group_unpublished(&relay, &mut phone, &mut laptop).await;
    let owed = phone
        .client
        .runtime
        .outstanding_welcome_deliveries()
        .unwrap();
    let [(_, welcome)] = owed.as_slice() else {
        panic!("the first link owes one Welcome")
    };
    let welcome_id = hex::encode(welcome.id.as_slice());
    assert!(relay.attempted_event_ids().contains(&welcome_id));
    assert!(!relay.published_event_ids().contains(&welcome_id));
    // The crash: the link's row as it was written before the commit.
    let link = link_record(&phone, &group, &slot);
    phone
        .app
        .account_storage("alice")
        .unwrap()
        .app_storage()
        .record_device_link(
            &link.group_id_hex,
            &link.slot_hex,
            &link.key_package_ref_hex,
            &link.leaf_signature_key_hex,
            link.linked_at,
        )
        .unwrap();
    let mut phone = reopen(phone).await;

    phone
        .client
        .drive_device_pairing_at(crate::unix_now_seconds() + LINK_DEADLINE_SECS + 1)
        .await;
    assert_eq!(
        link_record(&phone, &group, &slot).outcome,
        DeviceLinkOutcome::Failed
    );
    assert!(link_record(&phone, &group, &slot).welcome_withdrawn);
    assert!(
        phone
            .client
            .runtime
            .outstanding_welcome_deliveries()
            .unwrap()
            .is_empty(),
        "the link's Welcome is withdrawn"
    );

    relay.allow_publishes();
    let mut phone = reopen(phone).await; // startup recovery
    phone.step(&relay).await;
    assert!(
        !relay.published_event_ids().contains(&welcome_id),
        "no recovery publishes the withdrawn Welcome"
    );
}

/// Move a stored link Welcome's delivery deadline to `deliver_until`, as if
/// the new device's wait for it ended then.
fn set_welcome_deadline(device: &Device, welcome: &cgka_traits::MessageId, deliver_until: u64) {
    use cgka_traits::storage::MessageStorage as _;
    let storage = device.app.account_storage("alice").unwrap();
    let mut record = storage.get_message(welcome).unwrap();
    let mut payload = cgka_traits::message::StoredMessagePayload::decode(&record.payload).unwrap();
    let cgka_traits::message::StoredMessagePayload::OutboundWelcome {
        deliver_until: deadline,
        ..
    } = &mut payload
    else {
        panic!("an owed Welcome")
    };
    assert!(
        deadline.is_some(),
        "a link's Welcome has a delivery deadline"
    );
    *deadline = Some(cgka_traits::Timestamp(deliver_until));
    record.payload = payload.encode().unwrap();
    storage.put_message(&record).unwrap();
}

/// The account worker publishes owed Welcomes at startup before the link gate
/// runs: in its recovery pass, and in any maintenance pass a host queued
/// while initial sync ran, which replays first. A link's Welcome whose new
/// device stopped waiting still never reaches a relay: the Welcome's own
/// deadline holds it on every publish path, whatever ran first. (A launch with
/// device groups off opens nothing of the account; mdk#3012.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn startup_never_publishes_an_expired_links_welcome() {
    let (relay, [mut phone, mut laptop]) = alice_devices::<2>().await;
    let (group, slot) = create_device_group_unpublished(&relay, &mut phone, &mut laptop).await;
    let owed = phone
        .client
        .runtime
        .outstanding_welcome_deliveries()
        .unwrap();
    let [(_, welcome)] = owed.as_slice() else {
        panic!("the first link owes one Welcome")
    };
    let welcome_id = hex::encode(welcome.id.as_slice());
    // The restart comes after the new device stopped waiting, with the
    // link still pending.
    set_welcome_deadline(&phone, &welcome.id, crate::unix_now_seconds() - 1);
    assert_eq!(
        link_record(&phone, &group, &slot).outcome,
        DeviceLinkOutcome::Pending
    );
    // The device stayed off longer than the Welcome's fanout is kept, so
    // no attempt record holds it and maintenance would publish it as owed.
    phone
        .client
        .runtime
        .session()
        .delete_transport_fanout(&welcome.id)
        .unwrap();
    let Device {
        _dir, app, client, ..
    } = phone;
    drop(client);

    relay.allow_publishes();
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    let startup = Arc::new(tokio::sync::Barrier::new(2));
    runtime
        .shared_services()
        .set_next_startup_sync_barrier(startup.clone());
    runtime.reconcile_accounts().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), startup.wait())
        .await
        .expect("the worker reaches initial sync");
    let maintenance = runtime.run_due_maintenance("alice");
    tokio::pin!(maintenance);
    assert!(
        tokio::time::timeout(Duration::from_millis(150), &mut maintenance)
            .await
            .is_err(),
        "a maintenance pass waits for initial sync"
    );
    // Answered during startup, behind the queued pass, so that pass is
    // deferred before initial sync is released.
    runtime.quarantined_groups("alice").await.unwrap();
    startup.wait().await;
    maintenance.await.unwrap();
    runtime.drain_in_flight_work().await.unwrap();
    runtime.shutdown().await;
    assert!(
        !relay.published_event_ids().contains(&welcome_id),
        "startup published an expired link's Welcome"
    );
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

/// A restart drops a later link's prompt after its commit. Its Welcome is
/// still found by its KeyPackage's ref, and the new device's first commit
/// still makes the link.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_link_is_made_across_a_restart_by_the_new_devices_first_commit() {
    let (relay, [mut phone, mut laptop, mut tablet]) = alice_devices::<3>().await;
    let (group, slot) =
        link_tablet_until_commit(&relay, &mut phone, &mut laptop, &mut tablet).await;
    phone.step(&relay).await; // tablet's confirm in: the commit
    let mut phone = reopen(phone).await;
    let record = link_record(&phone, &group, &slot);
    assert_eq!(record.outcome, DeviceLinkOutcome::Pending);
    assert!(phone.client.trusted_device_group().unwrap() == Some(group.clone()));
    let reset = phone.client.device_link(DeviceLinkOp::ResetForRepair).await;
    assert!(matches!(
        reset,
        Err(AppError::DeviceGroupRefused("device_group_busy"))
    ));
    assert!(phone.client.trusted_device_group().unwrap() == Some(group.clone()));
    assert_eq!(link_record(&phone, &group, &slot), record);
    let key_package_ref = hex::decode(&record.key_package_ref_hex).unwrap();
    assert_eq!(
        phone
            .client
            .runtime
            .welcomes_for_key_package(&group, &key_package_ref)
            .unwrap()
            .len(),
        1,
        "a later link's Welcome is found by its KeyPackage's ref"
    );

    let joined = tablet.step(&relay).await; // the Welcome, and its first commit
    assert_eq!(joined.new_device, Some(NewDeviceLinkState::Linked));
    phone.step(&relay).await; // that commit
    assert_eq!(
        link_record(&phone, &group, &slot).outcome,
        DeviceLinkOutcome::Linked
    );
}

/// A failed link's removal does not wait for its Welcome: one that cannot
/// be found yet is left to withdraw on a later drive, and the device still
/// leaves the device group. The restart drops the prompt, so only the link's
/// row names the KeyPackage.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_links_removal_does_not_wait_for_its_welcome() {
    let (relay, [mut phone, mut laptop, mut tablet]) = alice_devices::<3>().await;
    let (group, slot) =
        link_tablet_until_commit(&relay, &mut phone, &mut laptop, &mut tablet).await;
    phone.step(&relay).await; // tablet's confirm in: the commit
    let mut phone = reopen(phone).await;
    let link = link_record(&phone, &group, &slot);
    phone
        .app
        .account_storage("alice")
        .unwrap()
        .app_storage()
        .record_device_link(
            &link.group_id_hex,
            &link.slot_hex,
            "zz",
            &link.leaf_signature_key_hex,
            link.linked_at,
        )
        .unwrap();

    phone
        .client
        .drive_device_pairing_at(crate::unix_now_seconds() + LINK_DEADLINE_SECS + 1)
        .await;
    let record = link_record(&phone, &group, &slot);
    assert_eq!(record.outcome, DeviceLinkOutcome::Failed);
    assert!(
        !record.welcome_withdrawn,
        "a Welcome not yet withdrawn is withdrawn on a later drive"
    );
    let tablet_slot: [u8; 32] = hex::decode(&slot).unwrap().try_into().unwrap();
    assert!(!phone.roster(&group).devices.contains_key(&tablet_slot));
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
    assert_eq!(
        link_record(&phone, &group, &slot).outcome,
        DeviceLinkOutcome::Pending,
        "a waiting approval is not decided"
    );

    // The phone's own commit lands; the approval then commits the link, and
    // the tablet joins.
    relay.allow_publishes();
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
    let committed = phone.step(&relay).await;
    assert_eq!(
        committed.prompt_for_slot(&slot).unwrap().state,
        DeviceLinkPromptState::Linking
    );
    join_then_linked(&relay, &mut phone, &mut tablet).await;
    assert_eq!(tablet.trust(&group), Some(DeviceGroupTrust::Linked));
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

/// A failing link whose Welcome cannot be withdrawn stays pending while that
/// Welcome's deadline may be ahead, so no failed link has a Welcome still
/// publishable. Once the new device's wait from `linked_at` is over, the
/// runtime refuses the Welcome anyway and the failure is recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failing_link_waits_for_its_welcomes_withdrawal_until_its_deadline() {
    let (_relay, [mut phone]) = alice_devices::<1>().await;
    let (group_hex, slot_hex) = ("ab".repeat(16), "cd".repeat(32));
    let linked_at = crate::unix_now_seconds();
    let storage = phone.app.account_storage("alice").unwrap().app_storage();
    // A KeyPackage ref that cannot be read, so every withdrawal fails.
    storage
        .record_device_link(&group_hex, &slot_hex, "zz", &"12".repeat(32), linked_at)
        .unwrap();
    let outcome = || {
        storage
            .device_link(&group_hex, &slot_hex)
            .unwrap()
            .unwrap()
            .outcome
    };

    phone
        .client
        .drive_device_pairing_at(linked_at + WELCOME_WAIT_SECS - 1)
        .await;
    assert_eq!(outcome(), DeviceLinkOutcome::Pending);
    phone
        .client
        .drive_device_pairing_at(linked_at + WELCOME_WAIT_SECS)
        .await;
    assert_eq!(outcome(), DeviceLinkOutcome::Failed);
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
    let (_relay, [phone]) = alice_devices::<1>().await;
    let Device {
        _dir, app, client, ..
    } = phone;
    drop(client);
    let account_id_hex = app.account_home().account("alice").unwrap().account_id_hex;
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
