//! `marmot.account.device-roster.v1` (0x800e), the roster of an account's
//! device group (mdk#2628 item 3.1, D16, D21 and D32).
//!
//! A group that requires the roster is a device group. For such a group:
//! - the roster is GroupContext state from creation, and an update is a diff
//!   of keyed entries that every member applies to the parent's roster;
//! - the roster keeps its own invariants (at most `MAX_LEAVES_PER_ACCOUNT`
//!   devices, no slot both a device and rejected, no two devices with one tag
//!   signature key);
//! - every leaf is the same account;
//! - the group requires the roster from creation or never.
//!
//! Before a group requires the roster, its bytes are unknown data. Each rule
//! is shown from the committer's side and the receiver's side, as in the
//! account-devices tests.

use super::activation::{buffer_unsettled, queued_intents};
use super::*;
use cgka_engine::ManualConvergenceClock;
use cgka_traits::app_components::{
    DEVICE_ROSTER_COMPONENT_ID, DeviceEntryV1, DeviceRosterOperationV1, DeviceRosterUpdateV1,
    DeviceRosterV1, DeviceSlotId, RejectedSlotReasonV1, RejectedSlotV1, decode_device_roster_v1,
    encode_device_roster_update_v1, encode_device_roster_v1,
};
use cgka_traits::engine::{SupersededIntentKind, SupersededIntentOutcome, SupersededIntentReport};
use cgka_traits::storage::{DeviceGroupWelcomeExpectation, GroupStorage as _};

/// A device of `account` that advertises the device roster beside
/// account-devices.
pub(super) fn roster_device(account: &[u8]) -> Device {
    roster_device_on(SqliteAccountStorage::in_memory_for_test().unwrap(), account)
}

/// [`roster_device`] over `storage`, as a reopened session builds it. The
/// caller hydrates its groups.
pub(super) fn roster_device_on(storage: SqliteAccountStorage, account: &[u8]) -> Device {
    build_roster_device(storage, account, None)
}

/// [`roster_device`] on a manual convergence clock.
fn clocked_roster_device(account: &[u8], clock: &ManualConvergenceClock) -> Device {
    build_roster_device(
        SqliteAccountStorage::in_memory_for_test().unwrap(),
        account,
        Some(clock),
    )
}

fn build_roster_device(
    storage: SqliteAccountStorage,
    account: &[u8],
    clock: Option<&ManualConvergenceClock>,
) -> Device {
    let mut supported: Vec<_> = default_group_components().into_iter().collect();
    supported.extend([ACCOUNT_DEVICES_COMPONENT_ID, DEVICE_ROSTER_COMPONENT_ID]);
    let mut builder = EngineBuilder::new(storage.clone())
        .identity(pad32(account))
        .account_identity_proof_signer(proof_signer(account))
        .protocol_profile(ProtocolProfile::Current)
        .feature_registry(registry())
        .supported_app_components(supported)
        .peeler(Box::<MockPeeler>::default());
    if let Some(clock) = clock {
        builder = builder.convergence_clock(std::sync::Arc::new(clock.clone()));
    }
    let engine = builder.build().unwrap();
    Device { engine, storage }
}

/// `joiner` expects `author`'s Welcome into the device group `gid`, adding
/// it by `key_package`, as a confirmed device link makes it (mdk#2628 D28,
/// D30, D41). The engine joins a device group only through such a Welcome.
pub(super) fn expect_link_welcome(
    joiner: &mut Device,
    gid: &GroupId,
    author: &Device,
    key_package: &KeyPackage,
) {
    joiner
        .engine
        .expect_device_group_welcome(&DeviceGroupWelcomeExpectation {
            group_id: gid.clone(),
            sender_signature_key: author.engine.own_signature_key(),
            key_package_ref: key_package_ref(key_package),
            expires_at: u64::MAX,
        })
        .unwrap();
}

pub(super) fn slot(n: u8) -> DeviceSlotId {
    [n; 32]
}

pub(super) fn entry(label: &str) -> DeviceEntryV1 {
    DeviceEntryV1 {
        label: label.into(),
        client: "test-client".into(),
        ..DeviceEntryV1::default()
    }
}

/// A roster with one device per `(slot, label)`. Its leaf tag key is not
/// zero, so a test that compares rosters sees it carried through updates.
pub(super) fn roster(devices: &[(u8, &str)]) -> DeviceRosterV1 {
    DeviceRosterV1 {
        leaf_tag_key: [0x33; 32],
        devices: devices
            .iter()
            .map(|(n, label)| (slot(*n), entry(label)))
            .collect(),
        ..DeviceRosterV1::default()
    }
}

fn roster_component(roster: &DeviceRosterV1) -> AppComponentData {
    AppComponentData {
        component_id: DEVICE_ROSTER_COMPONENT_ID,
        data: encode_device_roster_v1(roster).unwrap(),
    }
}

pub(super) fn update_bytes(operations: Vec<DeviceRosterOperationV1>) -> Vec<u8> {
    encode_device_roster_update_v1(&DeviceRosterUpdateV1::new(operations).unwrap()).unwrap()
}

pub(super) fn roster_update(gid: &GroupId, operations: Vec<DeviceRosterOperationV1>) -> SendIntent {
    SendIntent::UpdateAppComponents {
        group_id: gid.clone(),
        updates: vec![AppComponentData {
            component_id: DEVICE_ROSTER_COMPONENT_ID,
            data: update_bytes(operations),
        }],
    }
}

fn roster_bytes_of(device: &Device, gid: &GroupId) -> Option<Vec<u8>> {
    load_group(device, gid)
        .extensions()
        .app_data_dictionary()?
        .dictionary()
        .get(&DEVICE_ROSTER_COMPONENT_ID)
        .map(<[u8]>::to_vec)
}

pub(super) fn roster_of(device: &Device, gid: &GroupId) -> DeviceRosterV1 {
    decode_device_roster_v1(&roster_bytes_of(device, gid).expect("the group holds a roster"))
        .unwrap()
}

fn requires_roster(device: &Device, gid: &GroupId) -> bool {
    required(&device.engine, gid).contains(DEVICE_ROSTER_COMPONENT_ID)
}

/// `creator` founds a device group that `joiners` join, each by the Add that
/// sets its entry, as every device group grows (D41). The joiners take the
/// last slots of `initial`, in order, and the founding roster lists the rest.
/// The founding Add adds the first joiner, and the creator links each later
/// one. Once all have joined, the group holds `initial` with each joiner's
/// entry announcing the KeyPackage it joined with.
pub(super) async fn found_device_group(
    creator: &mut Device,
    initial: &DeviceRosterV1,
    joiners: &mut [&mut Device],
) -> GroupId {
    let (founding, joiner_slots) = founding_roster(initial, joiners.len());
    let Some((first, rest)) = joiners.split_first_mut() else {
        let (gid, created) = creator
            .engine
            .create_group(device_group_request(&founding, vec![]))
            .await
            .unwrap();
        assert!(
            matches!(created, SendResult::FoundingGroupCreated { .. }),
            "current-profile founding group"
        );
        return gid;
    };
    let key_package = first.engine.fresh_key_package().await.unwrap();
    let roster_update = update_bytes(vec![DeviceRosterOperationV1::SetDevice(
        joiner_slots[0],
        announced_entry(initial, &joiner_slots[0], &key_package),
    )]);
    let chosen = fresh_device_group_id();
    expect_link_welcome(first, &chosen, creator, &key_package);
    let (gid, created) = creator
        .engine
        .create_group_with_chosen_id_and_audit_context(
            device_group_request(&founding, vec![key_package]),
            chosen,
            Some(roster_update),
            NO_WELCOME_DEADLINE,
            None,
        )
        .await
        .unwrap();
    let SendResult::FoundingGroupCreated { welcomes } = created else {
        panic!("current-profile founding group")
    };
    assert_joins(first, &welcomes[0], &gid, creator).await;
    for index in 0..rest.len() {
        let (joined, waiting) = rest.split_at_mut(index);
        let joiner = &mut waiting[0];
        let joiner_slot = joiner_slots[index + 1];
        let key_package = joiner.engine.fresh_key_package().await.unwrap();
        let roster_update = update_bytes(vec![DeviceRosterOperationV1::SetDevice(
            joiner_slot,
            announced_entry(initial, &joiner_slot, &key_package),
        )]);
        expect_link_welcome(joiner, &gid, creator, &key_package);
        let SendResult::GroupEvolution {
            msg,
            welcomes,
            pending,
        } = creator
            .engine
            .send(SendIntent::LinkDevice {
                group_id: gid.clone(),
                key_package,
                roster_update,
                deliver_until: NO_WELCOME_DEADLINE,
            })
            .await
            .unwrap()
        else {
            panic!("a link is a group evolution")
        };
        creator.engine.confirm_published(pending).await.unwrap();
        let commit = route_to_group(&msg, &gid);
        assert_accepted(first, &commit, &gid).await;
        for member in joined.iter_mut() {
            assert_accepted(member, &commit, &gid).await;
        }
        assert_joins(joiner, &welcomes[0], &gid, creator).await;
    }
    gid
}

/// `initial` without its last `joiners` slots, which it returns: the roster
/// a device group is founded with when those devices join it afterwards.
fn founding_roster(
    initial: &DeviceRosterV1,
    joiners: usize,
) -> (DeviceRosterV1, Vec<DeviceSlotId>) {
    let slots: Vec<DeviceSlotId> = initial.devices.keys().copied().collect();
    let joiner_slots = slots[slots.len() - joiners..].to_vec();
    let mut founding = initial.clone();
    for joiner_slot in &joiner_slots {
        founding.devices.remove(joiner_slot);
    }
    (founding, joiner_slots)
}

/// `initial`'s entry for `slot`, announcing `key_package`, as the Add that
/// brings that device writes it.
pub(super) fn announced_entry(
    initial: &DeviceRosterV1,
    slot: &DeviceSlotId,
    key_package: &KeyPackage,
) -> DeviceEntryV1 {
    DeviceEntryV1 {
        announced_key_package: Some(key_package_ref(key_package)),
        ..initial.devices[slot].clone()
    }
}

pub(super) fn key_package_ref(key_package: &KeyPackage) -> Vec<u8> {
    hex::decode(
        cgka_engine::key_package::key_package_metadata(key_package)
            .unwrap()
            .key_package_ref_hex,
    )
    .unwrap()
}

/// Whether `device` holds any OpenMLS state for `gid`.
fn holds_mls_state(device: &Device, gid: &GroupId) -> bool {
    let crypto = RustCrypto::default();
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(&crypto, device.storage.mls_storage());
    MlsGroup::load(
        provider.storage(),
        &openmls::group::GroupId::from_slice(gid.as_slice()),
    )
    .expect("load MLS group")
    .is_some()
}

/// A device-group id no other founding in this test process uses.
fn fresh_device_group_id() -> GroupId {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let mut id = vec![0xD6; 16];
    id[8..].copy_from_slice(
        &NEXT
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .to_be_bytes(),
    );
    GroupId::new(id)
}

/// The founding request of a device group holding `initial` and adding
/// `key_packages`.
pub(super) fn device_group_request(
    initial: &DeviceRosterV1,
    key_packages: Vec<KeyPackage>,
) -> CreateGroupRequest {
    CreateGroupRequest {
        name: String::new(),
        description: String::new(),
        members: key_packages,
        required_features: vec![],
        app_components: vec![roster_component(initial)],
        initial_admins: vec![],
    }
}

/// A device link Welcome's delivery deadline that no test reaches.
pub(super) const NO_WELCOME_DEADLINE: Timestamp = Timestamp(u64::MAX);

/// `creator` founds a device group under `chosen`, the id a device link
/// chose before the group existed. The device in `key_packages`, if any,
/// takes the last slot of `initial`, as in [`found_device_group`].
pub(super) async fn create_under(
    creator: &mut Device,
    initial: &DeviceRosterV1,
    key_packages: Vec<KeyPackage>,
    chosen: &GroupId,
) -> Result<(GroupId, SendResult), EngineError> {
    let (founding, joiner_slots) = founding_roster(initial, key_packages.len().min(1));
    let roster_update =
        key_packages
            .first()
            .zip(joiner_slots.first())
            .map(|(key_package, joiner_slot)| {
                update_bytes(vec![DeviceRosterOperationV1::SetDevice(
                    *joiner_slot,
                    announced_entry(initial, joiner_slot, key_package),
                )])
            });
    creator
        .engine
        .create_group_with_chosen_id_and_audit_context(
            device_group_request(&founding, key_packages),
            chosen.clone(),
            roster_update,
            NO_WELCOME_DEADLINE,
            None,
        )
        .await
}

pub(super) async fn phone_and_laptop() -> (Device, Device, GroupId) {
    let mut phone = roster_device(b"alice");
    let mut laptop = roster_device(b"alice");
    let gid = found_device_group(
        &mut phone,
        &roster(&[(1, "Phone"), (2, "Laptop")]),
        &mut [&mut laptop],
    )
    .await;
    (phone, laptop, gid)
}

fn roster_error(result: Result<SendResult, EngineError>) -> String {
    result
        .expect_err("the committer refuses the roster update")
        .to_string()
}

#[test]
fn test_policy_builds_may_advertise_the_device_roster() {
    let mut supported: Vec<_> = default_group_components().into_iter().collect();
    supported.push(DEVICE_ROSTER_COMPONENT_ID);
    try_build(supported).expect("the roster is advertisable in test-policy builds");
}

#[tokio::test]
async fn a_device_group_holds_its_roster_from_creation() {
    let (phone, laptop, gid) = phone_and_laptop().await;
    // The founding Add set the laptop's entry, announcing the KeyPackage it
    // joined with (D41).
    let mut expected = roster(&[(1, "Phone"), (2, "Laptop")]);
    let announced = roster_of(&phone, &gid).devices[&slot(2)]
        .announced_key_package
        .clone();
    assert!(announced.is_some());
    expected
        .devices
        .get_mut(&slot(2))
        .unwrap()
        .announced_key_package = announced;
    for device in [&phone, &laptop] {
        assert!(requires_roster(device, &gid));
        assert_eq!(roster_of(device, &gid), expected);
    }
}

#[tokio::test]
async fn a_device_group_is_created_under_the_id_its_link_chose() {
    let mut phone = roster_device(b"alice");
    let mut laptop = roster_device(b"alice");
    let chosen = GroupId::new(vec![0x42; 16]);
    let key_package = laptop.engine.fresh_key_package().await.unwrap();
    let initial = roster(&[(1, "Phone"), (2, "Laptop")]);
    let (gid, created) = create_under(&mut phone, &initial, vec![key_package.clone()], &chosen)
        .await
        .unwrap();
    assert_eq!(gid, chosen);
    let SendResult::FoundingGroupCreated { welcomes } = created else {
        panic!("current-profile founding group")
    };
    expect_link_welcome(&mut laptop, &chosen, &phone, &key_package);
    assert_joins(&mut laptop, &welcomes[0], &chosen, &phone).await;
    let mut expected = initial.clone();
    expected
        .devices
        .insert(slot(2), announced_entry(&initial, &slot(2), &key_package));
    for device in [&phone, &laptop] {
        assert!(requires_roster(device, &chosen));
        assert_eq!(roster_of(device, &chosen), expected);
    }
}

/// A device group's founding Add is a link's (D41): it adds exactly one
/// KeyPackage and sets that device's entry, for a slot the founding roster
/// does not list, announcing that KeyPackage. Every other founding with a
/// member, and a roster update on any other create, is refused and leaves no
/// group state behind.
#[tokio::test]
async fn a_device_groups_founding_add_sets_exactly_its_one_devices_entry() {
    let mut phone = roster_device(b"alice");
    let mut laptop = roster_device(b"alice");
    let mut tablet = roster_device(b"alice");
    let chosen = GroupId::new(vec![0x42; 16]);
    let founding = roster(&[(1, "Phone")]);
    let full = roster(&[(1, "Phone"), (2, "Laptop")]);
    let key_package = laptop.engine.fresh_key_package().await.unwrap();
    let other_key_package = tablet.engine.fresh_key_package().await.unwrap();
    let sets_laptop = |key_package: &KeyPackage| {
        update_bytes(vec![DeviceRosterOperationV1::SetDevice(
            slot(2),
            announced_entry(&full, &slot(2), key_package),
        )])
    };
    let exactly_one = "adds exactly one device and sets its roster entry";
    let needs_founding_add = "a founding roster update needs a device group's founding Add";
    let refusals = [
        (
            "no roster update",
            device_group_request(&founding, vec![key_package.clone()]),
            None,
            exactly_one,
        ),
        (
            "two KeyPackages",
            device_group_request(
                &founding,
                vec![key_package.clone(), other_key_package.clone()],
            ),
            Some(sets_laptop(&key_package)),
            exactly_one,
        ),
        (
            "no KeyPackage",
            device_group_request(&founding, vec![]),
            Some(sets_laptop(&key_package)),
            needs_founding_add,
        ),
        (
            "a chat",
            CreateGroupRequest {
                name: String::new(),
                description: String::new(),
                members: vec![key_package.clone()],
                required_features: vec![],
                app_components: vec![],
                initial_admins: vec![],
            },
            Some(sets_laptop(&key_package)),
            needs_founding_add,
        ),
        (
            "two entries set",
            device_group_request(&founding, vec![key_package.clone()]),
            Some(update_bytes(vec![
                DeviceRosterOperationV1::SetDevice(
                    slot(2),
                    announced_entry(&full, &slot(2), &key_package),
                ),
                DeviceRosterOperationV1::SetDevice(slot(3), entry("Tablet")),
            ])),
            "",
        ),
        (
            "a slot the founding roster lists",
            device_group_request(&full, vec![key_package.clone()]),
            Some(sets_laptop(&key_package)),
            "",
        ),
        (
            "another KeyPackage announced",
            device_group_request(&founding, vec![key_package.clone()]),
            Some(sets_laptop(&other_key_package)),
            "",
        ),
    ];
    for (case, request, roster_update, error) in refusals {
        let refused = phone
            .engine
            .create_group_with_chosen_id_and_audit_context(
                request,
                chosen.clone(),
                roster_update,
                NO_WELCOME_DEADLINE,
                None,
            )
            .await
            .expect_err(case)
            .to_string();
        assert!(refused.contains(error), "{case}: {refused}");
        assert!(
            phone.storage.get_group(&chosen).is_err(),
            "{case}: no group record"
        );
        assert!(
            !holds_mls_state(&phone, &chosen),
            "{case}: no MLS state ({refused})"
        );
    }

    // An ordinary create founds a device group only with no member.
    let refused = phone
        .engine
        .create_group(device_group_request(&founding, vec![key_package.clone()]))
        .await
        .expect_err("an ordinary create adds no device")
        .to_string();
    assert!(refused.contains(exactly_one), "{refused}");

    // The refusals left the id free: the link's founding goes through.
    let (gid, created) = phone
        .engine
        .create_group_with_chosen_id_and_audit_context(
            device_group_request(&founding, vec![key_package.clone()]),
            chosen.clone(),
            Some(sets_laptop(&key_package)),
            NO_WELCOME_DEADLINE,
            None,
        )
        .await
        .unwrap();
    let SendResult::FoundingGroupCreated { welcomes } = created else {
        panic!("current-profile founding group")
    };
    expect_link_welcome(&mut laptop, &gid, &phone, &key_package);
    assert_joins(&mut laptop, &welcomes[0], &gid, &phone).await;
}

#[tokio::test]
async fn a_chosen_group_id_names_no_group_the_device_holds() {
    let (mut phone, mut laptop, gid) = phone_and_laptop().await;
    let initial = roster(&[(1, "Phone")]);
    let epoch = phone.engine.epoch(&gid).unwrap();
    let held = roster_of(&phone, &gid);

    // Live state: refused before anything is written, and the held group is
    // untouched.
    let refused = create_under(&mut phone, &initial, vec![], &gid).await;
    assert!(
        refused
            .expect_err("the chosen id names a live group")
            .to_string()
            .contains("a group with the chosen id already exists")
    );
    assert_eq!(phone.engine.epoch(&gid).unwrap(), epoch);
    assert_eq!(roster_of(&phone, &gid), held);

    // A Marmot record with no live MLS state, as a removed or forgotten copy
    // keeps: refused, and the record survives the refusal.
    let mut fresh = roster_device(b"alice");
    let record = phone.storage.get_group(&gid).unwrap();
    fresh.storage.put_group(&record).unwrap();
    let refused = create_under(&mut fresh, &initial, vec![], &gid).await;
    assert!(
        refused
            .expect_err("the chosen id names a held record")
            .to_string()
            .contains("a group with the chosen id already exists")
    );
    assert_eq!(fresh.storage.get_group(&gid).unwrap(), record);

    // A group this device forgot: refused, and it stays forgotten.
    assert!(laptop.engine.forget_group_local(&gid).unwrap());
    let refused = create_under(&mut laptop, &initial, vec![], &gid).await;
    assert!(
        refused
            .expect_err("the chosen id names a forgotten group")
            .to_string()
            .contains("the chosen id names a group this device forgot")
    );
    assert!(laptop.storage.is_group_forgotten(&gid).unwrap());

    // Lengths outside 1 to 255 bytes.
    for len in [0, 256] {
        let refused =
            create_under(&mut laptop, &initial, vec![], &GroupId::new(vec![7; len])).await;
        assert!(
            refused
                .expect_err("the chosen id has a bad length")
                .to_string()
                .contains("a chosen group id has 1 to 255 bytes"),
            "{len} bytes"
        );
    }
    let longest = GroupId::new(vec![7; 255]);
    let (created, _) = create_under(&mut laptop, &initial, vec![], &longest)
        .await
        .expect("255 bytes is allowed");
    assert_eq!(created, longest);
}

#[tokio::test]
async fn a_roster_update_sets_and_removes_single_entries() {
    let (mut phone, mut laptop, gid) = phone_and_laptop().await;
    let rejected = RejectedSlotV1 {
        reason: RejectedSlotReasonV1::NotMe,
        rejected_at: 1_700_000_000,
        tag_signature_key: None,
    };
    let operations = vec![
        DeviceRosterOperationV1::SetRejectedSlot(slot(9), rejected.clone()),
        DeviceRosterOperationV1::SetDevice(slot(2), entry("Work laptop")),
    ];
    let mut expected = roster_of(&phone, &gid);
    expected.devices.insert(slot(2), entry("Work laptop"));
    expected.rejected_slots.insert(slot(9), rejected);

    let commit = send_commit(&mut phone, roster_update(&gid, operations), &gid).await;
    assert_accepted(&mut laptop, &commit, &gid).await;
    assert_eq!(roster_of(&phone, &gid), expected);
    assert_eq!(roster_of(&laptop, &gid), expected);

    // Any device edits any entry: the laptop removes what the phone wrote.
    let commit = send_commit(
        &mut laptop,
        roster_update(
            &gid,
            vec![
                DeviceRosterOperationV1::RemoveDevice(slot(1)),
                DeviceRosterOperationV1::RemoveRejectedSlot(slot(9)),
            ],
        ),
        &gid,
    )
    .await;
    assert_accepted(&mut phone, &commit, &gid).await;
    // No update touches the leaf tag key.
    let expected = DeviceRosterV1 {
        devices: [(slot(2), entry("Work laptop"))].into_iter().collect(),
        ..roster(&[])
    };
    assert_eq!(roster_of(&phone, &gid), expected);
    assert_eq!(roster_of(&laptop, &gid), expected);
}

#[tokio::test]
async fn the_committer_refuses_a_roster_update_that_breaks_the_roster() {
    let (mut phone, _laptop, gid) = phone_and_laptop().await;
    let founded = roster_of(&phone, &gid);
    let too_many = (10..10 + MAX_LEAVES_PER_ACCOUNT as u8)
        .map(|n| DeviceRosterOperationV1::SetDevice(slot(n), entry("Spare")))
        .collect();
    for (rule, operations) in [
        (
            "removes a device it does not hold",
            vec![DeviceRosterOperationV1::RemoveDevice(slot(7))],
        ),
        (
            "both a device and rejected",
            vec![DeviceRosterOperationV1::SetRejectedSlot(
                slot(2),
                RejectedSlotV1 {
                    reason: RejectedSlotReasonV1::Removed,
                    rejected_at: 0,
                    tag_signature_key: None,
                },
            )],
        ),
        (
            "a not-me slot a tag signature key",
            vec![DeviceRosterOperationV1::SetRejectedSlot(
                slot(9),
                RejectedSlotV1 {
                    reason: RejectedSlotReasonV1::NotMe,
                    rejected_at: 0,
                    tag_signature_key: Some(vec![0x0c; 32]),
                },
            )],
        ),
        ("more than 20 devices", too_many),
        (
            "one tag signature key",
            vec![
                DeviceRosterOperationV1::SetDevice(
                    slot(1),
                    DeviceEntryV1 {
                        tag_signature_key: Some(vec![0x0a; 32]),
                        ..entry("Phone")
                    },
                ),
                DeviceRosterOperationV1::SetDevice(
                    slot(2),
                    DeviceEntryV1 {
                        tag_signature_key: Some(vec![0x0a; 32]),
                        ..entry("Laptop")
                    },
                ),
            ],
        ),
    ] {
        let error = roster_error(phone.engine.send(roster_update(&gid, operations)).await);
        assert!(error.contains(rule), "{rule}: {error}");
    }
    // A whole roster is not an update.
    let whole = AppComponentData {
        component_id: DEVICE_ROSTER_COMPONENT_ID,
        data: encode_device_roster_v1(&roster(&[(1, "Phone")])).unwrap(),
    };
    let error = roster_error(
        phone
            .engine
            .send(SendIntent::UpdateAppComponents {
                group_id: gid.clone(),
                updates: vec![whole],
            })
            .await,
    );
    assert!(error.contains("device roster update"), "{error}");
    assert_eq!(roster_of(&phone, &gid), founded);
}

/// A member that resolves a roster update its own way, for example by taking
/// the update's bytes as the new state, computes a different GroupContext
/// from every other member's, so its Commit never becomes an edge.
#[tokio::test]
async fn receivers_apply_the_update_to_the_parents_roster() {
    let (phone, mut laptop, gid) = phone_and_laptop().await;
    let operations = vec![DeviceRosterOperationV1::SetDevice(slot(3), entry("Tablet"))];
    let update = update_bytes(operations.clone());
    let commit_with = |state: Vec<u8>| {
        craft(
            &phone,
            &gid,
            Parts {
                app_data: vec![AppDataUpdateProposal::update(
                    DEVICE_ROSTER_COMPONENT_ID,
                    update.clone(),
                )],
                app_data_state: vec![(DEVICE_ROSTER_COMPONENT_ID, state)],
                ..Parts::default()
            },
        )
        .1
    };

    let whole_replacement = commit_with(update.clone());
    assert_rejected_on_replay(&mut laptop, &whole_replacement, &gid).await;

    let mut applied = roster_of(&phone, &gid);
    applied.devices.insert(slot(3), entry("Tablet"));
    let diff = commit_with(encode_device_roster_v1(&applied).unwrap());
    assert_accepted(&mut laptop, &diff, &gid).await;
    assert_eq!(roster_of(&laptop, &gid), applied);
}

#[tokio::test]
async fn receivers_reject_a_roster_update_that_breaks_the_roster() {
    let (phone, mut laptop, gid) = phone_and_laptop().await;
    // The committer keeps the parent's roster as the resulting state, so the
    // only fault is the operation itself.
    let removes_absent = update_bytes(vec![DeviceRosterOperationV1::RemoveDevice(slot(7))]);
    let (_, crafted) = craft(
        &phone,
        &gid,
        Parts {
            app_data: vec![AppDataUpdateProposal::update(
                DEVICE_ROSTER_COMPONENT_ID,
                removes_absent.clone(),
            )],
            app_data_state: vec![(
                DEVICE_ROSTER_COMPONENT_ID,
                roster_bytes_of(&phone, &gid).unwrap(),
            )],
            ..Parts::default()
        },
    );
    assert_rejected_on_replay(&mut laptop, &crafted, &gid).await;
    let removes_roster = crafted_commit(
        &phone,
        &gid,
        vec![],
        vec![AppDataUpdateProposal::remove(DEVICE_ROSTER_COMPONENT_ID)],
        None,
    );
    assert_rejected_on_replay(&mut laptop, &removes_roster, &gid).await;

    let standalone = standalone_app_data_update(
        &phone,
        &gid,
        DEVICE_ROSTER_COMPONENT_ID,
        AppDataUpdateOperation::Update(removes_absent.into()),
    );
    assert_rejected_at_ingest(&mut laptop, &standalone).await;
}

#[tokio::test]
async fn a_device_group_holds_only_its_accounts_devices() {
    let mut phone = roster_device(b"alice");
    let mut bob = roster_device(b"bob");
    let bob_kp = bob.engine.fresh_key_package().await.unwrap();
    let error = phone
        .engine
        .create_group_with_chosen_id_and_audit_context(
            device_group_request(&roster(&[(1, "Phone")]), vec![bob_kp.clone()]),
            GroupId::new(vec![0x42; 16]),
            Some(update_bytes(vec![DeviceRosterOperationV1::SetDevice(
                slot(2),
                announced_entry(&roster(&[(2, "Bob")]), &slot(2), &bob_kp),
            )])),
            NO_WELCOME_DEADLINE,
            None,
        )
        .await
        .expect_err("a device group founded with another account is refused");
    assert!(error.to_string().contains("another account"), "{error}");

    let (mut phone, mut laptop, gid) = phone_and_laptop().await;
    let error = phone
        .engine
        .send(SendIntent::Invite {
            group_id: gid.clone(),
            key_packages: vec![bob_kp.clone()],
            initial_admins: vec![],
        })
        .await
        .expect_err("inviting another account into a device group is refused");
    // The sender refuses every Invite into a device group; a receiver
    // rejects another account's leaf in one.
    assert!(
        error.to_string().contains("only through LinkDevice"),
        "{error}"
    );

    let crafted = crafted_commit(&phone, &gid, vec![bob_kp.clone()], vec![], None);
    assert_rejected_on_replay(&mut laptop, &crafted, &gid).await;
    let welcome = crafted_welcome(&phone, &gid, &[bob_kp], vec![], vec![], &bob);
    assert_eq!(
        join_outcome(&mut bob, &welcome).await,
        refused(InputRejectionCategory::InvalidEncoding)
    );
}

#[tokio::test]
async fn a_group_requires_the_roster_from_creation_or_never() {
    // An ordinary group whose members all support the roster cannot start
    // requiring it.
    let mut alice = roster_device(b"alice");
    let mut bob = roster_device(b"bob");
    let bob_kp = bob.engine.fresh_key_package().await.unwrap();
    let gid = found_group(&mut alice, vec![bob_kp], true, &mut [&mut bob]).await;
    assert!(!requires_roster(&alice, &gid));
    let mut ids = required(&alice.engine, &gid);
    ids.insert(DEVICE_ROSTER_COMPONENT_ID);
    let activation = vec![
        required_list_update(&ids),
        AppDataUpdateProposal::update(
            DEVICE_ROSTER_COMPONENT_ID,
            encode_device_roster_v1(&roster(&[(1, "Phone")])).unwrap(),
        ),
    ];
    let error = alice
        .engine
        .send(SendIntent::UpdateAppComponents {
            group_id: gid.clone(),
            updates: vec![
                AppComponentData {
                    component_id: APP_COMPONENTS_COMPONENT_ID,
                    data: encode_components_list(&ids.ids),
                },
                roster_component(&roster(&[(1, "Phone")])),
            ],
        })
        .await
        .expect_err("activating the roster is refused");
    assert!(
        error.to_string().contains("from creation or never"),
        "{error}"
    );
    let crafted = crafted_commit(&alice, &gid, vec![], activation, None);
    assert_rejected_on_replay(&mut bob, &crafted, &gid).await;
    for proposal in [
        standalone_app_data_update(
            &alice,
            &gid,
            APP_COMPONENTS_COMPONENT_ID,
            AppDataUpdateOperation::Update(encode_components_list(&ids.ids).into()),
        ),
        standalone_required_list_extensions(&alice, &gid, &ids),
    ] {
        assert_rejected_at_ingest(&mut bob, &proposal).await;
    }

    // A device group never stops requiring it.
    let (mut phone, mut laptop, gid) = phone_and_laptop().await;
    let mut ids = required(&phone.engine, &gid);
    ids.ids.remove(&DEVICE_ROSTER_COMPONENT_ID);
    let error = phone
        .engine
        .send(update_required(&gid, &ids))
        .await
        .expect_err("un-requiring the roster is refused");
    assert!(
        error.to_string().contains("from creation or never"),
        "{error}"
    );
    let crafted = crafted_commit(
        &phone,
        &gid,
        vec![],
        vec![
            required_list_update(&ids),
            AppDataUpdateProposal::remove(DEVICE_ROSTER_COMPONENT_ID),
        ],
        None,
    );
    assert_rejected_on_replay(&mut laptop, &crafted, &gid).await;
    for proposal in [
        standalone_app_data_update(
            &phone,
            &gid,
            APP_COMPONENTS_COMPONENT_ID,
            AppDataUpdateOperation::Update(encode_components_list(&ids.ids).into()),
        ),
        standalone_required_list_extensions(&phone, &gid, &ids),
        // Nor drops its roster, or keeps requiring it with bytes that aren't
        // a roster. No Commit could carry either, so neither is admitted.
        standalone_app_data_update(
            &phone,
            &gid,
            DEVICE_ROSTER_COMPONENT_ID,
            AppDataUpdateOperation::Remove,
        ),
        standalone_dictionary_extensions(&phone, &gid, DEVICE_ROSTER_COMPONENT_ID, vec![0xff]),
    ] {
        assert_rejected_at_ingest(&mut laptop, &proposal).await;
    }
    // A whole valid roster in a GroupContextExtensions proposal is admitted.
    let replacement = standalone_dictionary_extensions(
        &phone,
        &gid,
        DEVICE_ROSTER_COMPONENT_ID,
        encode_device_roster_v1(&roster(&[(1, "Phone"), (2, "Laptop"), (3, "Tablet")])).unwrap(),
    );
    let outcome = laptop.engine.ingest(replacement).await.unwrap();
    assert!(
        !matches!(outcome, IngestOutcome::Rejected { .. }),
        "unexpected rejection: {outcome:?}"
    );
}

/// Before a group requires the roster, bytes under its id are unknown data:
/// an update replaces them whole and nobody parses them.
#[tokio::test]
async fn roster_bytes_are_unknown_data_in_other_groups() {
    let mut alice = roster_device(b"alice");
    let mut bob = roster_device(b"bob");
    let bob_kp = bob.engine.fresh_key_package().await.unwrap();
    let gid = found_group(&mut alice, vec![bob_kp], true, &mut [&mut bob]).await;
    let commit = send_commit(
        &mut alice,
        SendIntent::UpdateAppComponents {
            group_id: gid.clone(),
            updates: vec![AppComponentData {
                component_id: DEVICE_ROSTER_COMPONENT_ID,
                data: vec![0xff, 0x00],
            }],
        },
        &gid,
    )
    .await;
    assert_accepted(&mut bob, &commit, &gid).await;
    assert_eq!(roster_bytes_of(&bob, &gid), Some(vec![0xff, 0x00]));

    // Creation never writes a roster into a group that does not require it.
    let mut carol = roster_device(b"carol");
    let carol_kp = carol.engine.fresh_key_package().await.unwrap();
    let error = alice
        .engine
        .create_group_with_optional_app_components(
            CreateGroupRequest {
                name: String::new(),
                description: String::new(),
                members: vec![carol_kp],
                required_features: vec![],
                app_components: vec![],
                initial_admins: vec![],
            },
            vec![roster_component(&roster(&[(1, "Phone")]))],
        )
        .await
        .expect_err("an optional roster is refused");
    assert!(
        error.to_string().contains("optional device roster"),
        "{error}"
    );
}

/// `device` renames the entry of slot `n` to `label`, computed from the entry
/// it reads now.
fn replace(device: &Device, gid: &GroupId, n: u8, label: &str) -> SendIntent {
    let expected = roster_of(device, gid).devices[&slot(n)].clone();
    SendIntent::ReplaceDeviceEntry {
        group_id: gid.clone(),
        slot: slot(n),
        entry: Box::new(DeviceEntryV1 {
            label: label.into(),
            ..expected.clone()
        }),
        expected: Box::new(expected),
    }
}

fn now_wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn refused_replacement(events: &[GroupEvent]) -> bool {
    events.iter().any(|event| {
        matches!(event, GroupEvent::QueuedIntentRefused { intent_kind, reason, .. }
            if intent_kind == "replace_device_entry" && reason == "device_entry_changed")
    })
}

/// A device entry replacement names the entry it was computed from, because
/// `SetDevice` replaces an entry whole. A sibling's rename of the same entry
/// is still buffered when the replacement is sent, so the replacement waits
/// in the queue. The drain applies the rename first and then refuses the
/// replacement: it is retired and announced, and the rename stands. Computed
/// again from the new entry, the edit goes out.
#[tokio::test]
async fn a_queued_device_entry_replacement_never_lands_on_a_changed_entry() {
    let clock = ManualConvergenceClock::new(1_000_000, now_wall_ms());
    let mut phone = clocked_roster_device(b"alice", &clock);
    let mut laptop = roster_device(b"alice");
    let gid = found_device_group(
        &mut phone,
        &roster(&[(1, "Phone"), (2, "Laptop")]),
        &mut [&mut laptop],
    )
    .await;
    let rename = replace(&laptop, &gid, 2, "Mine");
    let laptop_rename = send_commit(&mut laptop, rename, &gid).await;
    buffer_unsettled(&mut phone, &laptop_rename).await;

    let queued = phone
        .engine
        .send(replace(&phone, &gid, 2, "Work"))
        .await
        .unwrap();
    assert!(matches!(queued, SendResult::Queued { .. }), "{queued:?}");
    assert_eq!(queued_intents(&phone, &gid).len(), 1);
    phone.engine.drain_events();

    clock.advance_ms(30_000);
    let drained = phone.engine.advance_convergence(&gid).await.unwrap();
    assert!(drained.is_empty(), "{drained:?}");
    assert!(queued_intents(&phone, &gid).is_empty());
    assert!(refused_replacement(&phone.engine.drain_events()));
    assert_eq!(roster_of(&phone, &gid).devices[&slot(2)].label, "Mine");

    let SendResult::GroupEvolution { pending, .. } = phone
        .engine
        .send(replace(&phone, &gid, 2, "Work"))
        .await
        .unwrap()
    else {
        panic!("expected GroupEvolution")
    };
    phone.engine.confirm_published(pending).await.unwrap();
    assert_eq!(roster_of(&phone, &gid).devices[&slot(2)].label, "Work");
}

/// Every send settles the group's convergence input first, deferred peels
/// included, and that can apply a sibling's rename of the entry being
/// replaced. The replacement is then refused and nothing is kept.
#[tokio::test]
async fn a_device_entry_replacement_never_lands_on_an_entry_its_send_changed() {
    let clock = ManualConvergenceClock::new(1_000_000, now_wall_ms());
    let mut phone = clocked_roster_device(b"alice", &clock);
    let mut laptop = roster_device(b"alice");
    let gid = found_device_group(
        &mut phone,
        &roster(&[(1, "Phone"), (2, "Laptop")]),
        &mut [&mut laptop],
    )
    .await;
    let read_at = phone.engine.epoch(&gid).unwrap();
    let rename = replace(&laptop, &gid, 2, "Mine");
    let laptop_rename = send_commit(&mut laptop, rename, &gid).await;
    buffer_unsettled(&mut phone, &laptop_rename).await;
    clock.advance_ms(30_000);

    let stale = replace(&phone, &gid, 2, "Work");
    let refused = phone.engine.send(stale).await;
    assert!(
        matches!(&refused, Err(EngineError::DeviceEntryChanged { group_id }) if *group_id == gid),
        "{refused:?}"
    );
    assert!(
        phone.engine.epoch(&gid).unwrap() > read_at,
        "the send applied the laptop's rename"
    );
    assert_eq!(roster_of(&phone, &gid).devices[&slot(2)].label, "Mine");
    assert!(queued_intents(&phone, &gid).is_empty());
}

/// The settlement a send runs can also switch the group to a rival branch at
/// the same epoch: a sibling's rename forked from the parent of the
/// self-update this device adopted, and a privileged commit outranks an
/// ordinary one. The epoch does not move, the entry does, and the
/// replacement is refused.
#[tokio::test]
async fn a_device_entry_replacement_never_lands_on_a_rival_branch_at_the_same_epoch() {
    let clock = ManualConvergenceClock::new(1_000_000, now_wall_ms());
    let mut phone = clocked_roster_device(b"alice", &clock);
    let mut laptop = roster_device(b"alice");
    let mut tablet = roster_device(b"alice");
    let gid = found_device_group(
        &mut phone,
        &roster(&[(1, "Phone"), (2, "Laptop"), (3, "Tablet")]),
        &mut [&mut laptop, &mut tablet],
    )
    .await;
    let rename = replace(&laptop, &gid, 2, "Mine");
    let laptop_rename = send_commit(&mut laptop, rename, &gid).await;
    let tablet_update = send_commit(
        &mut tablet,
        SendIntent::SelfUpdate {
            group_id: gid.clone(),
        },
        &gid,
    )
    .await;
    buffer_unsettled(&mut phone, &tablet_update).await;
    clock.advance_ms(30_000);
    phone.engine.advance_convergence_inputs(&gid).await.unwrap();
    let read_at = phone.engine.epoch(&gid).unwrap();
    assert_eq!(roster_of(&phone, &gid).devices[&slot(2)].label, "Laptop");
    buffer_unsettled(&mut phone, &laptop_rename).await;
    clock.advance_ms(30_000);

    let stale = replace(&phone, &gid, 2, "Work");
    let refused = phone.engine.send(stale).await;
    assert!(
        matches!(&refused, Err(EngineError::DeviceEntryChanged { group_id }) if *group_id == gid),
        "{refused:?}"
    );
    assert_eq!(
        phone.engine.epoch(&gid).unwrap(),
        read_at,
        "the same height"
    );
    assert_eq!(roster_of(&phone, &gid).devices[&slot(2)].label, "Mine");
    assert!(queued_intents(&phone, &gid).is_empty());
}

/// The phone replaces the entry of `phone_slot` and the laptop the entry of
/// `laptop_slot`, both from the same epoch, and each adjudicates the
/// other's commit. Both are one account, so which commit wins is up to the
/// tip digest; returns the loser, the winner, the group and the loser's
/// supersession report.
async fn race_entry_replacements(
    phone_slot: u8,
    laptop_slot: u8,
) -> (Device, Device, GroupId, SupersededIntentReport) {
    let mut phone = roster_device(b"alice");
    let mut laptop = roster_device(b"alice");
    let gid = found_device_group(
        &mut phone,
        &roster(&[(1, "Phone"), (2, "Laptop")]),
        &mut [&mut laptop],
    )
    .await;
    let by_phone = replace(&phone, &gid, phone_slot, "By phone");
    let phone_commit = send_commit(&mut phone, by_phone, &gid).await;
    let by_laptop = replace(&laptop, &gid, laptop_slot, "By laptop");
    let laptop_commit = send_commit(&mut laptop, by_laptop, &gid).await;
    for (device, rival) in [(&mut phone, &laptop_commit), (&mut laptop, &phone_commit)] {
        device
            .engine
            .buffer_openmls_convergence_message_at(&gid, rival.clone(), 500)
            .unwrap();
        device
            .engine
            .converge_stored_openmls_messages_at(&gid, 1_000_000)
            .unwrap();
    }
    let phone_reports = phone
        .engine
        .reissue_superseded_own_commits_from_state()
        .unwrap();
    let laptop_reports = laptop
        .engine
        .reissue_superseded_own_commits_from_state()
        .unwrap();
    match (phone_reports.as_slice(), laptop_reports.as_slice()) {
        ([report], []) => (phone, laptop, gid, report.clone()),
        ([], [report]) => (laptop, phone, gid, report.clone()),
        other => panic!("exactly one commit loses: {other:?}"),
    }
}

/// A superseded replacement is re-issued when the winning branch left its
/// entry alone, even though the winner changed the roster.
#[tokio::test]
async fn a_superseded_device_entry_replacement_is_reissued_when_the_winner_left_its_entry_alone() {
    let (mut loser, _winner, gid, report) = race_entry_replacements(1, 2).await;
    assert_eq!(report.kind, SupersededIntentKind::AppComponents);
    assert_eq!(report.outcome, SupersededIntentOutcome::Reissued);
    assert_eq!(queued_intents(&loser, &gid).len(), 1);

    let drained = loser
        .engine
        .converge_and_drain_queued_outbound_intents(&gid, 2_000_000)
        .await
        .unwrap();
    let [SendResult::GroupEvolution { pending, .. }] = drained.as_slice() else {
        panic!("the re-issued replacement is prepared: {drained:?}")
    };
    loser.engine.confirm_published(*pending).await.unwrap();
    let devices = roster_of(&loser, &gid).devices;
    assert_eq!(devices[&slot(1)].label, "By phone");
    assert_eq!(devices[&slot(2)].label, "By laptop");
}

/// A superseded replacement whose entry the winning branch changed is a
/// conflict: the winner's entry stands and nothing is queued.
#[tokio::test]
async fn a_superseded_device_entry_replacement_of_an_entry_the_winner_changed_is_a_conflict() {
    let (loser, winner, gid, report) = race_entry_replacements(2, 2).await;
    assert_eq!(report.outcome, SupersededIntentOutcome::Conflict);
    assert!(queued_intents(&loser, &gid).is_empty());
    assert_eq!(
        roster_of(&loser, &gid).devices[&slot(2)].label,
        roster_of(&winner, &gid).devices[&slot(2)].label
    );
}
