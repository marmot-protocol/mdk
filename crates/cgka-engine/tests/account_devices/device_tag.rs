//! `marmot.member.device-tag.v1` (0x800f), the LeafNode tag that says which
//! of an account's devices holds a leaf (mdk#2628 item 3.1d, D32).
//!
//! Read through the engine, a member's leaf belongs to the roster slot its
//! tag names, in the current tree only, or, read at an epoch, in the tree of
//! that epoch: the current one, or a past one from its retained anchor, a
//! read that writes nothing. A tag never makes a Commit invalid. No group may
//! require 0x800f, and a GroupContext entry under it is unknown data that
//! this engine never writes. The tag crypto and the spec vector are tested in
//! the engine's `device_tag` module.
//!
//! A device tags from the roster of the device group its host names, once its
//! entry there, the one at its KeyPackage publication slot, carries its MLS
//! signature key. Another entry carrying that key is not its own. It sets that key in a roster
//! update whose UpdatePath already carries a tag. From then on every
//! KeyPackage it builds carries a fresh tag, and so does every replacement of
//! a leaf whose tag does not read as its own, whichever own Commit makes it.

use super::device_roster::{
    clocked_roster_device, entry, found_device_group, phone_and_laptop, roster, roster_device,
    roster_device_on, roster_of, roster_update, slot,
};
use super::tagged_siblings::{found_routed_group, handed};
use super::*;
use cgka_engine::device_tag::{DeviceTagClaim, device_tag_claim, seal_device_tag};
use cgka_traits::app_components::{
    DEVICE_TAG_COMPONENT_ID, DeviceRosterOperationV1, DeviceRosterV1, DeviceSlotId,
    decode_components_list,
};
use cgka_traits::maintenance::KeyPackageLifecycleState;
use cgka_traits::storage::{GroupStorage as _, MaintenanceStorage as _, RosterTagKey};
use cgka_traits::types::EpochId;
use openmls_traits::types::SignatureScheme;

/// A tag signature key pair other than the device's MLS one.
fn tag_key_pair() -> (SignatureKeyPair, Vec<u8>) {
    let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    let public_key = signer.to_public_vec();
    (signer, public_key)
}

/// The phone-and-laptop roster, with `tag_public_key` as the laptop's.
fn roster_with_laptop_key(tag_public_key: Vec<u8>) -> DeviceRosterV1 {
    let mut roster = roster(&[(1, "Phone"), (2, "Laptop")]);
    roster.devices.get_mut(&slot(2)).unwrap().tag_signature_key = Some(tag_public_key);
    roster
}

/// A tag for `device`'s leaf naming `slot`, signed by `signer` under
/// `roster`'s leaf tag key.
fn tag_for(
    device: &Device,
    roster: &DeviceRosterV1,
    slot: &DeviceSlotId,
    signer: &SignatureKeyPair,
) -> Vec<u8> {
    seal_device_tag(
        &RustCrypto::default(),
        &roster.leaf_tag_key,
        slot,
        signer,
        device_signer(device).public(),
    )
    .unwrap()
}

/// `device`'s current leaf extensions with `entry` under 0x800f, which the
/// leaf also advertises.
fn with_tag_entry(device: &Device, gid: &GroupId, entry: Vec<u8>) -> Extensions<LeafNode> {
    let mut extensions = load_group(device, gid)
        .own_leaf_node()
        .unwrap()
        .extensions()
        .clone();
    let mut dictionary = extensions
        .app_data_dictionary()
        .unwrap()
        .dictionary()
        .clone();
    let mut advertised =
        decode_components_list(dictionary.get(&APP_COMPONENTS_COMPONENT_ID).unwrap()).unwrap();
    advertised.insert(DEVICE_TAG_COMPONENT_ID);
    dictionary.insert(
        APP_COMPONENTS_COMPONENT_ID,
        encode_components_list(&advertised),
    );
    dictionary.insert(DEVICE_TAG_COMPONENT_ID, entry);
    extensions
        .add_or_replace(Extension::AppDataDictionary(
            AppDataDictionaryExtension::new(dictionary),
        ))
        .unwrap();
    extensions
}

fn leaf_index(device: &Device, gid: &GroupId) -> u32 {
    load_group(device, gid).own_leaf_index().u32()
}

fn claim(
    reader: &Device,
    gid: &GroupId,
    epoch: EpochId,
    leaf_index: u32,
    roster: &DeviceRosterV1,
) -> Option<DeviceTagClaim> {
    reader
        .engine
        .member_device_tag_claim_at(gid, epoch, leaf_index, roster)
        .unwrap()
}

#[tokio::test]
async fn a_member_leaf_reads_as_the_device_its_tag_names() {
    let (mut phone, laptop, gid) = phone_and_laptop().await;
    let (signer, public_key) = tag_key_pair();
    let tagged = roster_with_laptop_key(public_key);
    let remembered = RosterTagKey {
        slot: slot(2),
        tag_signature_key: tagged.devices[&slot(2)].tag_signature_key.clone().unwrap(),
        held_as_removed: true,
    };
    let laptop_leaf = leaf_index(&laptop, &gid);
    let before = phone.engine.epoch(&gid).unwrap();
    assert_eq!(
        claim(&phone, &gid, before, laptop_leaf, &tagged),
        Some(DeviceTagClaim::Unclaimed),
        "a leaf from before the link carries no tag"
    );
    assert!(
        phone
            .engine
            .own_account_leaves_tagged_by(
                &gid,
                &tagged.leaf_tag_key,
                std::slice::from_ref(&remembered),
            )
            .unwrap()
            .is_empty()
    );

    let entry = tag_for(&laptop, &tagged, &slot(2), &signer);
    let commit = crafted_commit(
        &laptop,
        &gid,
        vec![],
        vec![],
        Some(with_tag_entry(&laptop, &gid, entry)),
    );
    assert_accepted(&mut phone, &commit, &gid).await;
    let after = phone.engine.epoch(&gid).unwrap();
    assert_eq!(
        claim(&phone, &gid, after, laptop_leaf, &tagged),
        Some(DeviceTagClaim::Device(slot(2)))
    );

    // The current-tree reader reads only the current epoch.
    let current = |epoch| {
        phone
            .engine
            .member_device_tag_claim(&gid, epoch, laptop_leaf, &tagged)
            .unwrap()
    };
    assert_eq!(current(after), Some(DeviceTagClaim::Device(slot(2))));
    assert_eq!(current(before), None);
    let reads = |leaf_tag_key: &[u8; 32], keys: &[RosterTagKey]| {
        phone
            .engine
            .own_account_leaves_tagged_by(&gid, leaf_tag_key, keys)
            .unwrap()
    };
    let wrong_key = RosterTagKey {
        tag_signature_key: vec![0x01; 32],
        ..remembered.clone()
    };
    assert_eq!(
        reads(
            &tagged.leaf_tag_key,
            &[wrong_key.clone(), remembered.clone()]
        ),
        vec![signature_key(&laptop, &gid)],
        "remembered keys read the actual current leaf even without a current roster entry",
    );
    for keys in [
        vec![wrong_key],
        vec![RosterTagKey {
            slot: slot(3),
            ..remembered.clone()
        }],
        vec![],
    ] {
        assert!(reads(&tagged.leaf_tag_key, &keys).is_empty());
    }
    assert!(reads(&[0x34; 32], std::slice::from_ref(&remembered)).is_empty());

    // Read at an epoch, an older one reads the leaf as it was then, from its
    // retained anchor, and leaves the group's state and snapshots as they
    // were; an epoch with no anchor, or an index with no leaf, reads nothing.
    let state = phone.storage.group_replay_state_fingerprint(&gid).unwrap();
    let snapshots = phone.storage.list_group_snapshots(&gid).unwrap();
    assert_eq!(
        claim(&phone, &gid, before, laptop_leaf, &tagged),
        Some(DeviceTagClaim::Unclaimed)
    );
    assert_eq!(
        phone.storage.group_replay_state_fingerprint(&gid).unwrap(),
        state
    );
    assert_eq!(phone.storage.list_group_snapshots(&gid).unwrap(), snapshots);
    assert_eq!(
        claim(&phone, &gid, EpochId(after.0 + 1), laptop_leaf, &tagged),
        None
    );
    assert_eq!(claim(&phone, &gid, after, 9, &tagged), None);
    assert_eq!(claim(&phone, &gid, before, 9, &tagged), None);
    // Against a roster in which the laptop has not set its key, the same
    // leaf is unclaimed.
    let without_key = DeviceRosterV1 {
        devices: roster(&[(1, "Phone"), (2, "Laptop")]).devices,
        ..tagged.clone()
    };
    assert_eq!(
        claim(&phone, &gid, after, laptop_leaf, &without_key),
        Some(DeviceTagClaim::Unclaimed)
    );

    // After a later commit, the tagged epoch still reads as the laptop, from
    // its own anchor, again writing nothing.
    send_commit(
        &mut phone,
        SendIntent::SelfUpdate {
            group_id: gid.clone(),
        },
        &gid,
    )
    .await;
    let state = phone.storage.group_replay_state_fingerprint(&gid).unwrap();
    let snapshots = phone.storage.list_group_snapshots(&gid).unwrap();
    assert_eq!(
        claim(&phone, &gid, after, laptop_leaf, &tagged),
        Some(DeviceTagClaim::Device(slot(2)))
    );
    assert_eq!(
        phone.storage.group_replay_state_fingerprint(&gid).unwrap(),
        state
    );
    assert_eq!(phone.storage.list_group_snapshots(&gid).unwrap(), snapshots);

    // Once later commits have pruned an epoch's anchor, it reads nothing,
    // never the current tree's tag.
    for _ in 0..5 {
        send_commit(
            &mut phone,
            SendIntent::SelfUpdate {
                group_id: gid.clone(),
            },
            &gid,
        )
        .await;
    }
    assert_eq!(
        claim(
            &phone,
            &gid,
            phone.engine.epoch(&gid).unwrap(),
            laptop_leaf,
            &tagged
        ),
        Some(DeviceTagClaim::Device(slot(2)))
    );
    assert_eq!(claim(&phone, &gid, before, laptop_leaf, &tagged), None);
}

/// Most members cannot open a tag, so a tag that does not decode, open or
/// verify is accepted like any other leaf and reads as no tag.
#[tokio::test]
async fn a_tag_that_does_not_open_never_makes_a_commit_invalid() {
    let (mut phone, laptop, gid) = phone_and_laptop().await;
    let (_, public_key) = tag_key_pair();
    let commit = crafted_commit(
        &laptop,
        &gid,
        vec![],
        vec![],
        Some(with_tag_entry(&laptop, &gid, vec![0xff; 3])),
    );
    assert_accepted(&mut phone, &commit, &gid).await;
    assert_eq!(
        claim(
            &phone,
            &gid,
            phone.engine.epoch(&gid).unwrap(),
            leaf_index(&laptop, &gid),
            &roster_with_laptop_key(public_key),
        ),
        Some(DeviceTagClaim::Unclaimed)
    );
}

/// Tags are read only on the reader's own account's leaves. A tag that would
/// read as one of Alice's devices names nothing when Bob's leaf carries it.
#[tokio::test]
async fn another_accounts_leaf_reads_as_unclaimed() {
    let mut alice = roster_device(b"alice");
    let mut bob = roster_device(b"bob");
    let bob_kp = bob.engine.fresh_key_package().await.unwrap();
    let gid = found_group(&mut alice, vec![bob_kp], true, &mut [&mut bob]).await;
    let (signer, public_key) = tag_key_pair();
    let alices_roster = roster_with_laptop_key(public_key);

    let entry = tag_for(&bob, &alices_roster, &slot(2), &signer);
    let commit = crafted_commit(
        &bob,
        &gid,
        vec![],
        vec![],
        Some(with_tag_entry(&bob, &gid, entry)),
    );
    assert_accepted(&mut alice, &commit, &gid).await;
    assert_eq!(
        claim(
            &alice,
            &gid,
            alice.engine.epoch(&gid).unwrap(),
            leaf_index(&bob, &gid),
            &alices_roster,
        ),
        Some(DeviceTagClaim::Unclaimed)
    );
}

/// No group may require 0x800f: a Commit, a standalone proposal and a Welcome
/// that would are each rejected, even with an entry under the id, so the
/// requirement fails as unsupported rather than for missing state.
#[tokio::test]
async fn no_group_may_require_the_device_tag() {
    let mut alice = roster_device(b"alice");
    let mut bob = roster_device(b"bob");
    let bob_kp = bob.engine.fresh_key_package().await.unwrap();
    let gid = found_group(&mut alice, vec![bob_kp], true, &mut [&mut bob]).await;
    let mut ids = required(&alice.engine, &gid);
    ids.insert(DEVICE_TAG_COMPONENT_ID);
    let requiring = || {
        vec![
            required_list_update(&ids),
            AppDataUpdateProposal::update(DEVICE_TAG_COMPONENT_ID, vec![1]),
        ]
    };

    let commit = crafted_commit(&alice, &gid, vec![], requiring(), None);
    assert_rejected_on_replay(&mut bob, &commit, &gid).await;

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

    let mut carol = roster_device(b"carol");
    let carol_kp = carol.engine.fresh_key_package().await.unwrap();
    let welcome = crafted_welcome(
        &alice,
        &gid,
        std::slice::from_ref(&carol_kp),
        requiring(),
        vec![],
        &carol,
    );
    assert_eq!(
        join_outcome(&mut carol, &welcome).await,
        refused(InputRejectionCategory::InvalidEncoding)
    );
    let welcome = crafted_welcome(&alice, &gid, &[carol_kp], vec![], vec![], &carol);
    assert_joins(&mut carol, &welcome, &gid, &alice).await;
}

/// A GroupContext entry under 0x800f is unknown data: this engine never
/// writes one, and accepts one another client wrote.
#[tokio::test]
async fn a_group_context_device_tag_entry_is_unknown_data() {
    let mut alice = roster_device(b"alice");
    let mut bob = roster_device(b"bob");
    let bob_kp = bob.engine.fresh_key_package().await.unwrap();
    let gid = found_group(&mut alice, vec![bob_kp], true, &mut [&mut bob]).await;

    assert_refused(
        alice
            .engine
            .send(SendIntent::UpdateAppComponents {
                group_id: gid.clone(),
                updates: vec![AppComponentData {
                    component_id: DEVICE_TAG_COMPONENT_ID,
                    data: vec![1],
                }],
            })
            .await,
        "lives only in LeafNodes",
    );

    let commit = crafted_commit(
        &alice,
        &gid,
        vec![],
        vec![AppDataUpdateProposal::update(
            DEVICE_TAG_COMPONENT_ID,
            vec![1],
        )],
        None,
    );
    assert_accepted(&mut bob, &commit, &gid).await;
}

/// Gives `device` the KeyPackage publication slot `slot`, which makes the
/// roster entry there its own.
pub(super) fn hold_slot(device: &Device, slot: DeviceSlotId) {
    device
        .storage
        .put_key_package_lifecycle(&KeyPackageLifecycleState::slot_only(hex::encode(slot)))
        .unwrap();
}

/// `device` sets its own `tag_signature_key` in its entry at `own_slot` in
/// the device group `gid`, and `others` apply the roster update.
pub(super) async fn set_own_key(
    device: &mut Device,
    own_slot: DeviceSlotId,
    gid: &GroupId,
    others: &mut [&mut Device],
) {
    let mut own_entry = roster_of(device, gid).devices[&own_slot].clone();
    own_entry.tag_signature_key = Some(device.engine.own_signature_key());
    let update = roster_update(
        gid,
        vec![DeviceRosterOperationV1::SetDevice(own_slot, own_entry)],
    );
    let commit = send_commit(device, update, gid).await;
    for other in others.iter_mut() {
        assert_accepted(other, &commit, gid).await;
    }
}

/// What `device`'s own leaf in `gid` reads as against `roster`.
fn own_leaf_claim(device: &Device, gid: &GroupId, roster: &DeviceRosterV1) -> DeviceTagClaim {
    device_tag_claim(load_group(device, gid).own_leaf_node().unwrap(), roster)
}

fn key_package_claim(key_package: &KeyPackage, roster: &DeviceRosterV1) -> DeviceTagClaim {
    device_tag_claim(parse_key_package(key_package).leaf_node(), roster)
}

/// `key_package`'s 0x800f entry, if it carries one, and whether it
/// advertises 0x800f.
fn key_package_tag(key_package: &KeyPackage) -> (Option<Vec<u8>>, bool) {
    let parsed = parse_key_package(key_package);
    let dictionary = parsed
        .leaf_node()
        .extensions()
        .app_data_dictionary()
        .unwrap()
        .dictionary()
        .clone();
    let advertised =
        decode_components_list(dictionary.get(&APP_COMPONENTS_COMPONENT_ID).unwrap()).unwrap();
    (
        dictionary.get(&DEVICE_TAG_COMPONENT_ID).map(<[u8]>::to_vec),
        advertised.contains(&DEVICE_TAG_COMPONENT_ID),
    )
}

fn tag_is_due(device: &Device, gid: &GroupId) -> bool {
    device
        .engine
        .own_leaf_missing_app_components(gid)
        .unwrap()
        .contains(DEVICE_TAG_COMPONENT_ID)
}

/// The laptop sets its own key in a roster update whose UpdatePath already
/// carries a tag under that key, so its device-group leaf reads as its own
/// from that Commit on. Every KeyPackage it builds then carries a fresh tag,
/// and one built before is due for replacement. Without a device group named
/// by its host it tags nothing.
#[tokio::test]
async fn setting_its_own_key_starts_tagging() {
    let (mut phone, mut laptop, gid) = phone_and_laptop().await;
    hold_slot(&laptop, slot(2));
    laptop
        .engine
        .set_device_tag_group(Some(gid.clone()))
        .unwrap();
    let untagged = laptop.engine.fresh_key_package().await.unwrap();
    assert_eq!(key_package_tag(&untagged), (None, false));
    assert!(
        laptop
            .engine
            .key_package_advertises_current_capabilities(&untagged)
            .unwrap()
    );
    assert!(!tag_is_due(&laptop, &gid), "the laptop cannot tag yet");

    set_own_key(&mut laptop, slot(2), &gid, &mut [&mut phone]).await;
    let tagged = roster_of(&phone, &gid);
    assert_eq!(
        tagged.devices[&slot(2)].tag_signature_key,
        Some(laptop.engine.own_signature_key())
    );
    assert_eq!(
        claim(
            &phone,
            &gid,
            phone.engine.epoch(&gid).unwrap(),
            leaf_index(&laptop, &gid),
            &tagged,
        ),
        Some(DeviceTagClaim::Device(slot(2)))
    );
    assert_eq!(
        own_leaf_claim(&laptop, &gid, &tagged),
        DeviceTagClaim::Device(slot(2))
    );
    assert!(!tag_is_due(&laptop, &gid));

    let first = laptop.engine.fresh_key_package().await.unwrap();
    let second = laptop.engine.fresh_key_package().await.unwrap();
    for key_package in [&first, &second] {
        assert!(
            key_package_tag(key_package).1,
            "a tagged leaf advertises 0x800f"
        );
        assert_eq!(
            key_package_claim(key_package, &tagged),
            DeviceTagClaim::Device(slot(2))
        );
        assert!(
            laptop
                .engine
                .key_package_advertises_current_capabilities(key_package)
                .unwrap()
        );
    }
    assert_ne!(
        key_package_tag(&first).0,
        key_package_tag(&second).0,
        "every tag draws a fresh nonce"
    );
    assert!(
        !laptop
            .engine
            .key_package_advertises_current_capabilities(&untagged)
            .unwrap(),
        "a KeyPackage from before the key is due for replacement"
    );

    laptop.engine.set_device_tag_group(None).unwrap();
    let after = laptop.engine.fresh_key_package().await.unwrap();
    assert_eq!(key_package_tag(&after), (None, false));
    assert!(
        !laptop
            .engine
            .key_package_advertises_current_capabilities(&first)
            .unwrap()
    );
    assert!(!tag_is_due(&laptop, &gid));
}

/// The laptop tags only from its own entry, the one at its slot. While
/// another entry carries its key and its own entry does not, it tags nothing.
/// Once its own entry carries the key it tags, and when that entry moves to
/// another slot its tags are stale and it builds untagged again.
#[tokio::test]
async fn only_the_entry_at_its_own_slot_tags() {
    let (mut phone, mut laptop, gid) = phone_and_laptop().await;
    hold_slot(&laptop, slot(2));
    laptop
        .engine
        .set_device_tag_group(Some(gid.clone()))
        .unwrap();
    let mut elsewhere = entry("Tablet");
    elsewhere.tag_signature_key = Some(laptop.engine.own_signature_key());
    let update = roster_update(
        &gid,
        vec![DeviceRosterOperationV1::SetDevice(slot(3), elsewhere)],
    );
    let commit = send_commit(&mut phone, update, &gid).await;
    assert_accepted(&mut laptop, &commit, &gid).await;
    let untagged = laptop.engine.fresh_key_package().await.unwrap();
    assert_eq!(key_package_tag(&untagged), (None, false));
    assert!(
        laptop
            .engine
            .key_package_advertises_current_capabilities(&untagged)
            .unwrap()
    );
    assert!(!tag_is_due(&laptop, &gid));

    let remove = roster_update(&gid, vec![DeviceRosterOperationV1::RemoveDevice(slot(3))]);
    let commit = send_commit(&mut phone, remove, &gid).await;
    assert_accepted(&mut laptop, &commit, &gid).await;
    set_own_key(&mut laptop, slot(2), &gid, &mut [&mut phone]).await;
    let tagged = laptop.engine.fresh_key_package().await.unwrap();
    assert_eq!(
        key_package_claim(&tagged, &roster_of(&laptop, &gid)),
        DeviceTagClaim::Device(slot(2))
    );

    // A tag that no longer reads as the laptop's is stale even though its
    // KeyPackage advertises 0x800f.
    let own_entry = roster_of(&phone, &gid).devices[&slot(2)].clone();
    let moved = roster_update(
        &gid,
        vec![
            DeviceRosterOperationV1::RemoveDevice(slot(2)),
            DeviceRosterOperationV1::SetDevice(slot(3), own_entry),
        ],
    );
    let commit = send_commit(&mut phone, moved, &gid).await;
    assert_accepted(&mut laptop, &commit, &gid).await;
    assert!(
        !laptop
            .engine
            .key_package_advertises_current_capabilities(&tagged)
            .unwrap()
    );
    assert!(!tag_is_due(&laptop, &gid));
    assert_eq!(
        key_package_tag(&laptop.engine.fresh_key_package().await.unwrap()),
        (None, false)
    );
}

/// A founder whose entry in the roster it founds carries its key tags its
/// founding leaf from that roster, so the device that joins reads the leaf as
/// the founder's at once.
#[tokio::test]
async fn a_founder_tags_its_founding_leaf_from_the_roster_it_founds() {
    let mut phone = roster_device(b"alice");
    let mut laptop = roster_device(b"alice");
    hold_slot(&phone, slot(1));
    let mut initial = roster(&[(1, "Phone"), (2, "Laptop")]);
    initial.devices.get_mut(&slot(1)).unwrap().tag_signature_key =
        Some(phone.engine.own_signature_key());
    let gid = found_device_group(&mut phone, &initial, &mut [&mut laptop]).await;
    assert_eq!(
        own_leaf_claim(&phone, &gid, &initial),
        DeviceTagClaim::Device(slot(1))
    );
    assert_eq!(
        claim(
            &laptop,
            &gid,
            laptop.engine.epoch(&gid).unwrap(),
            leaf_index(&phone, &gid),
            &initial,
        ),
        Some(DeviceTagClaim::Device(slot(1)))
    );

    // A founder whose key sits in another entry founds an untagged leaf.
    let mut tablet = roster_device(b"carol");
    let mut watch = roster_device(b"carol");
    hold_slot(&tablet, slot(1));
    let mut misplaced = roster(&[(1, "Tablet"), (2, "Watch")]);
    misplaced
        .devices
        .get_mut(&slot(2))
        .unwrap()
        .tag_signature_key = Some(tablet.engine.own_signature_key());
    let gid = found_device_group(&mut tablet, &misplaced, &mut [&mut watch]).await;
    assert_eq!(
        own_leaf_claim(&tablet, &gid, &misplaced),
        DeviceTagClaim::Unclaimed
    );
}

/// Once the laptop can tag, its leaf in each group it joined before carries
/// no tag, so a refresh is due. Whichever own Commit replaces the leaf next
/// tags it, and the other members accept that Commit.
#[tokio::test]
async fn every_kind_of_own_commit_tags_a_leaf_that_needs_a_tag() {
    let clock = manual_convergence_clock();
    let mut phone = roster_device(b"alice");
    let mut laptop = clocked_roster_device(b"alice", &clock);
    let device_gid = found_device_group(
        &mut phone,
        &roster(&[(1, "Phone"), (2, "Laptop")]),
        &mut [&mut laptop],
    )
    .await;
    let mut bob = roster_device(b"bob");
    let mut groups = Vec::new();
    for index in 0..6 {
        // The same-account Add's chat names a relay for its sibling Welcome.
        let gid = if index == 3 {
            found_routed_group(&mut laptop, &mut [&mut bob]).await
        } else {
            let bob_kp = bob.engine.fresh_key_package().await.unwrap();
            found_group(&mut laptop, vec![bob_kp], true, &mut [&mut bob]).await
        };
        groups.push(gid);
    }
    hold_slot(&laptop, slot(2));
    laptop
        .engine
        .set_device_tag_group(Some(device_gid.clone()))
        .unwrap();
    set_own_key(&mut laptop, slot(2), &device_gid, &mut [&mut phone]).await;
    // The phone, tagged too, hands the laptop the KeyPackage it adds.
    hold_slot(&phone, slot(1));
    phone
        .engine
        .set_device_tag_group(Some(device_gid.clone()))
        .unwrap();
    set_own_key(&mut phone, slot(1), &device_gid, &mut [&mut laptop]).await;
    let tagged = roster_of(&laptop, &device_gid);
    let mut carol = roster_device(b"carol");
    let carol_kp = carol.engine.fresh_key_package().await.unwrap();
    let phone_kp = handed(&mut phone, slot(1), slot(2));

    let intents = [
        SendIntent::SelfUpdate {
            group_id: groups[0].clone(),
        },
        SendIntent::Invite {
            group_id: groups[1].clone(),
            key_packages: vec![carol_kp],
            initial_admins: vec![],
        },
        SendIntent::UpdateGroupData {
            group_id: groups[2].clone(),
            name: Some("Renamed".into()),
            description: None,
        },
        add_own_devices(&groups[3], vec![phone_kp]),
        SendIntent::RemoveMembers {
            group_id: groups[4].clone(),
            members: vec![bob.engine.self_id()],
        },
    ];
    for (gid, intent) in groups.iter().zip(intents) {
        assert!(tag_is_due(&laptop, gid));
        let commit = send_commit(&mut laptop, intent, gid).await;
        assert_eq!(
            own_leaf_claim(&laptop, gid, &tagged),
            DeviceTagClaim::Device(slot(2))
        );
        assert!(!tag_is_due(&laptop, gid));
        if gid != &groups[4] {
            assert_accepted(&mut bob, &commit, gid).await;
        }
    }

    // The laptop's auto-commit of bob's SelfRemove.
    let gid = &groups[5];
    assert!(tag_is_due(&laptop, gid));
    let SendResult::Proposal { msg } = bob
        .engine
        .send(SendIntent::Leave {
            group_id: gid.clone(),
        })
        .await
        .unwrap()
    else {
        panic!("expected a SelfRemove proposal")
    };
    laptop
        .engine
        .ingest(route_to_group(&msg, gid))
        .await
        .unwrap();
    clock.advance_ms(75);
    laptop.engine.advance_convergence(gid).await.unwrap();
    let mut publications = laptop.engine.drain_auto_publish();
    assert_eq!(publications.len(), 1);
    laptop
        .engine
        .confirm_published(publications.remove(0).pending)
        .await
        .unwrap();
    assert_eq!(
        own_leaf_claim(&laptop, gid, &tagged),
        DeviceTagClaim::Device(slot(2))
    );
}

/// A leaf whose tag already reads as the device's keeps it: the device's next
/// own Commit leaves the leaf's extensions as they are, rather than sealing a
/// fresh tag into every UpdatePath.
#[tokio::test]
async fn a_leaf_whose_tag_reads_as_its_own_keeps_it() {
    let (mut phone, mut laptop, gid) = phone_and_laptop().await;
    hold_slot(&phone, slot(1));
    phone
        .engine
        .set_device_tag_group(Some(gid.clone()))
        .unwrap();
    set_own_key(&mut phone, slot(1), &gid, &mut [&mut laptop]).await;
    let leaf_before = load_group(&phone, &gid).own_leaf_node().unwrap().clone();
    let tagged = roster_of(&phone, &gid);
    assert_eq!(
        own_leaf_claim(&phone, &gid, &tagged),
        DeviceTagClaim::Device(slot(1))
    );

    let rename = roster_update(
        &gid,
        vec![DeviceRosterOperationV1::SetDevice(
            slot(2),
            entry("Work laptop"),
        )],
    );
    let commit = send_commit(&mut phone, rename, &gid).await;
    assert_accepted(&mut laptop, &commit, &gid).await;
    let leaf_after = load_group(&phone, &gid).own_leaf_node().unwrap().clone();
    assert_eq!(
        leaf_after.extensions(),
        leaf_before.extensions(),
        "the UpdatePath keeps the leaf's extensions, tag included"
    );
}

/// The device reads its roster only from a live device group. Naming a group
/// the session only seeded hydrates it first. A quarantined device group,
/// whose MLS state may still load, tags nothing: KeyPackages are built
/// untagged, and the KeyPackage check cannot tell, so a tagged KeyPackage is
/// not replaced meanwhile.
#[tokio::test]
async fn only_a_live_device_group_tags() {
    let (mut phone, mut laptop, gid) = phone_and_laptop().await;
    hold_slot(&laptop, slot(2));
    laptop
        .engine
        .set_device_tag_group(Some(gid.clone()))
        .unwrap();
    set_own_key(&mut laptop, slot(2), &gid, &mut [&mut phone]).await;
    let tagged = laptop.engine.fresh_key_package().await.unwrap();
    let storage = laptop.storage.clone();
    drop(laptop);

    let mut seeded = roster_device_on(storage.clone(), b"alice");
    seeded.engine.hydrate_stable_groups_from_storage().unwrap();
    assert_eq!(seeded.engine.unhydrated_group_ids(), vec![gid.clone()]);
    seeded
        .engine
        .set_device_tag_group(Some(gid.clone()))
        .unwrap();
    assert!(seeded.engine.unhydrated_group_ids().is_empty());
    assert!(
        seeded
            .engine
            .key_package_advertises_current_capabilities(&tagged)
            .unwrap()
    );
    assert!(key_package_tag(&seeded.engine.fresh_key_package().await.unwrap()).1);

    // A named group with no MLS state behind it can't say either.
    let missing = GroupId::new(vec![0xab; 16]);
    seeded
        .engine
        .set_device_tag_group(Some(missing.clone()))
        .unwrap();
    assert_eq!(
        key_package_tag(&seeded.engine.fresh_key_package().await.unwrap()),
        (None, false)
    );
    assert!(matches!(
        seeded
            .engine
            .key_package_advertises_current_capabilities(&tagged),
        Err(EngineError::UnknownGroup(group_id)) if group_id == missing
    ));
    drop(seeded);

    // A stored profile that disagrees with the group's quarantines it when
    // naming it hydrates it. Naming it says so every time, and it stays
    // named: with no group named, the tagged KeyPackage would read as stale.
    let mut record = storage.get_group(&gid).unwrap();
    record.protocol_profile = ProtocolProfile::Legacy;
    storage.put_group(&record).unwrap();
    let mut quarantined = roster_device_on(storage, b"alice");
    quarantined
        .engine
        .hydrate_stable_groups_from_storage()
        .unwrap();
    assert_eq!(quarantined.engine.unhydrated_group_ids(), vec![gid.clone()]);
    for _ in 0..2 {
        assert!(matches!(
            quarantined
                .engine
                .set_device_tag_group(Some(gid.clone())),
            Err(EngineError::UnknownGroup(group_id)) if group_id == gid
        ));
    }
    assert_eq!(quarantined.engine.quarantined_groups().len(), 1);
    assert_eq!(
        key_package_tag(&quarantined.engine.fresh_key_package().await.unwrap()),
        (None, false)
    );
    assert!(matches!(
        quarantined
            .engine
            .key_package_advertises_current_capabilities(&tagged),
        Err(EngineError::UnknownGroup(group_id)) if group_id == gid
    ));
}

/// Native DG acceptance owns source facts for application, Commit and standalone
/// Proposal traffic. Probes/buffering never observe; selected replay does, and
/// the captured source survives a changed live tree and rewrapped duplicates.
#[tokio::test]
async fn accepted_device_group_application_commit_and_proposal_retain_their_exact_source() {
    use super::tagged_siblings::tagged_devices;
    for through_convergence in [false, true] {
        let (mut phone, mut siblings, gid) = tagged_devices(b"source-observation", 2).await;
        let mut laptop = siblings.remove(0);
        let mut tablet = siblings.remove(0);
        let roster = roster_of(&phone, &gid);
        for (id, _) in phone
            .storage
            .pending_authenticated_device_group_sources(&gid, true, None, None, 32)
            .unwrap()
        {
            phone
                .storage
                .app_storage()
                .ignore_sibling_welcome_activity(&gid, &id)
                .unwrap();
        }
        let event = cgka_traits::MarmotAppEvent::new(
            hex::encode(laptop.engine.self_id().as_slice()),
            1,
            49_999,
            vec![],
            "activity",
        );
        let SendResult::ApplicationMessage { msg, .. } = laptop
            .engine
            .send(SendIntent::AppMessage {
                group_id: gid.clone(),
                payload: event.encode().unwrap(),
                expected_epoch: None,
            })
            .await
            .unwrap()
        else {
            panic!("application");
        };
        let application = route_to_group(&msg, &gid);
        let source_epoch = phone.engine.epoch(&gid).unwrap();
        if through_convergence {
            phone
                .engine
                .buffer_openmls_convergence_message_at(&gid, application.clone(), 1)
                .unwrap();
            phone
                .engine
                .advance_convergence_inputs_until_settled(&gid, 1_000_000)
                .await
                .unwrap();
        } else {
            phone.engine.ingest(application.clone()).await.unwrap();
        }
        let app_id = hash_id(&application.payload);
        let facts = phone
            .storage
            .pending_authenticated_device_group_sources(&gid, true, None, None, 32)
            .unwrap();
        let (_, source) = facts.iter().find(|(id, _)| *id == app_id).unwrap_or_else(|| panic!("accepted application fact missing: convergence={through_convergence}, facts={facts:?}, state={:?}", phone.storage.get_message(&app_id).unwrap().state));
        assert_eq!(source.epoch, source_epoch);
        assert_eq!(source.sender, laptop.engine.self_id());
        assert_eq!(source.leaf_index, leaf_index(&laptop, &gid));
        assert_eq!(
            source.leaf.as_ref().unwrap().signature_key,
            device_signer(&laptop).to_public_vec()
        );
        assert!(
            phone
                .engine
                .pending_device_group_activity(&gid, &roster)
                .unwrap()
                .contains(&(app_id.clone(), source_epoch, Some(slot(2))))
        );
        let mut key_unready = roster.clone();
        key_unready
            .devices
            .get_mut(&slot(2))
            .unwrap()
            .tag_signature_key = None;
        assert!(
            phone
                .engine
                .pending_device_group_activity(&gid, &key_unready)
                .unwrap()
                .is_empty(),
            "missing current tag key is pending, not a definitive rejection"
        );
        assert!(
            phone
                .engine
                .pending_device_group_activity(&gid, &roster)
                .unwrap()
                .contains(&(app_id.clone(), source_epoch, Some(slot(2)))),
            "restored current key reuses immutable accepted source"
        );
        let mut wrong_roster = roster.clone();
        wrong_roster
            .devices
            .get_mut(&slot(2))
            .unwrap()
            .tag_signature_key = Some(device_signer(&phone).to_public_vec());
        assert!(
            phone
                .engine
                .pending_device_group_activity(&gid, &wrong_roster)
                .unwrap()
                .contains(&(app_id.clone(), source_epoch, None))
        );
        phone
            .storage
            .app_storage()
            .ignore_sibling_welcome_activity(&gid, &app_id)
            .unwrap();
        let commit = send_commit(
            &mut laptop,
            SendIntent::SelfUpdate {
                group_id: gid.clone(),
            },
            &gid,
        )
        .await;
        let commit_id = hash_id(&commit.payload);
        phone
            .engine
            .buffer_openmls_convergence_message_at(&gid, commit.clone(), 1)
            .unwrap();
        assert!(
            phone
                .storage
                .pending_authenticated_device_group_sources(&gid, true, None, None, 32)
                .unwrap()
                .is_empty(),
            "unauthenticated buffering/probes cannot observe source activity"
        );
        phone
            .engine
            .converge_stored_openmls_messages_at(&gid, 1_000_000)
            .unwrap();
        let facts = phone
            .storage
            .pending_authenticated_device_group_sources(&gid, true, None, None, 32)
            .unwrap();
        let (_, source) = facts.iter().find(|(id, _)| *id == commit_id).unwrap();
        assert_eq!(
            source.epoch, source_epoch,
            "Commit source is its parent epoch, not merged result"
        );
        assert!(
            phone
                .engine
                .pending_device_group_activity(&gid, &roster)
                .unwrap()
                .contains(&(commit_id.clone(), source_epoch, Some(slot(2))))
        );
        assert_accepted(&mut tablet, &commit, &gid).await;
        let mut rewrapped = commit;
        rewrapped.id = MessageId::new(vec![0x55; 32]);
        phone.engine.ingest(rewrapped).await.unwrap();
        assert_eq!(
            phone
                .storage
                .pending_authenticated_device_group_sources(&gid, true, None, None, 32)
                .unwrap(),
            facts
        );
        phone
            .storage
            .app_storage()
            .ignore_sibling_welcome_activity(&gid, &commit_id)
            .unwrap();
        // A new MLS encryption of the exact valid event remains the original
        // accepted inner content even after the source epoch advanced.
        let SendResult::ApplicationMessage { msg: alias, .. } = laptop
            .engine
            .send(SendIntent::AppMessage {
                group_id: gid.clone(),
                payload: event.encode().unwrap(),
                expected_epoch: None,
            })
            .await
            .unwrap()
        else {
            panic!("alias application");
        };
        phone
            .engine
            .ingest(route_to_group(&alias, &gid))
            .await
            .unwrap();
        assert!(
            phone
                .storage
                .pending_authenticated_device_group_sources(&gid, true, None, None, 32)
                .unwrap()
                .is_empty(),
            "a valid application alias cannot become fresh after attribution/epoch change"
        );
        // MLS-authenticated malformed application content still has an immutable
        // inner identity, even though no MessageReceived app output can be emitted.
        let shared = cgka_traits::MarmotAppEvent::new(
            hex::encode(laptop.engine.self_id().as_slice()),
            2,
            457,
            vec![],
            "",
        );
        for sender in [&mut laptop, &mut tablet] {
            let SendResult::ApplicationMessage { msg, .. } = sender
                .engine
                .send(SendIntent::AppMessage {
                    group_id: gid.clone(),
                    payload: shared.encode().unwrap(),
                    expected_epoch: None,
                })
                .await
                .unwrap()
            else {
                panic!("shared account heartbeat");
            };
            phone
                .engine
                .ingest(route_to_group(&msg, &gid))
                .await
                .unwrap();
        }
        let shared_facts = phone
            .engine
            .pending_device_group_activity(&gid, &roster)
            .unwrap();
        assert_eq!(
            shared_facts.len(),
            2,
            "same account/kind/content/second app id belongs to two authenticated source devices"
        );
        assert!(
            shared_facts
                .iter()
                .any(|(_, _, source)| *source == Some(slot(2)))
        );
        assert!(
            shared_facts
                .iter()
                .any(|(_, _, source)| *source == Some(slot(3)))
        );
        for (id, _, _) in shared_facts {
            phone
                .storage
                .app_storage()
                .ignore_sibling_welcome_activity(&gid, &id)
                .unwrap();
        }
        let crypto = RustCrypto::default();
        let provider = EngineOpenMlsProvider::<SqliteAccountStorage>::new(
            &crypto,
            laptop.storage.mls_storage(),
        );
        phone.engine.drain_events();
        for _ in 0..2 {
            let raw = load_group(&laptop, &gid)
                .create_message(
                    &provider,
                    &device_signer(&laptop),
                    b"malformed Marmot application",
                )
                .unwrap();
            let malformed = group_transport(raw, &gid, "malformed-source");
            if through_convergence {
                phone
                    .engine
                    .buffer_openmls_convergence_message_at(&gid, malformed, 2_000_000)
                    .unwrap();
                phone
                    .engine
                    .advance_convergence_inputs_until_settled(&gid, 3_000_000)
                    .await
                    .unwrap();
            } else {
                phone.engine.ingest(malformed).await.unwrap();
            }
        }
        let malformed = phone
            .storage
            .pending_authenticated_device_group_sources(&gid, true, None, None, 32)
            .unwrap();
        assert_eq!(
            malformed.len(),
            1,
            "reencryption of the same malformed inner content cannot create fresh activity"
        );
        assert!(
            !phone
                .engine
                .drain_events()
                .iter()
                .any(|event| matches!(event, GroupEvent::MessageReceived { .. })),
            "malformed traffic produces no application effect"
        );
        phone
            .storage
            .app_storage()
            .ignore_sibling_welcome_activity(&gid, &malformed[0].0)
            .unwrap();
        let crypto = RustCrypto::default();
        let provider = EngineOpenMlsProvider::<SqliteAccountStorage>::new(
            &crypto,
            laptop.storage.mls_storage(),
        );
        let (proposal, _) = load_group(&laptop, &gid)
            .propose_self_update(
                &provider,
                &device_signer(&laptop),
                LeafNodeParameters::default(),
            )
            .unwrap();
        let proposal = group_transport(proposal, &gid, "standalone-source");
        phone.engine.drain_events();
        let next_epoch = phone.engine.epoch(&gid).unwrap();
        if through_convergence {
            phone
                .engine
                .buffer_openmls_convergence_message_at(&gid, proposal.clone(), 4_000_000)
                .unwrap();
            let (_, committing) = craft(
                &tablet,
                &gid,
                Parts {
                    by_reference: vec![proposal.clone()],
                    ..Parts::default()
                },
            );
            phone
                .engine
                .buffer_openmls_convergence_message_at(&gid, committing, 4_000_000)
                .unwrap();
            phone
                .engine
                .converge_stored_openmls_messages_at(&gid, 5_000_000)
                .map(|result| {
                    assert!(
                        result
                            .accepted_proposals
                            .contains(&hex::encode(hash_id(&proposal.payload).as_slice())),
                        "proposal result: {result:?}"
                    );
                    result
                })
                .unwrap();
        } else {
            assert_eq!(
                phone.engine.ingest(proposal.clone()).await.unwrap(),
                IngestOutcome::Processed
            );
        }
        assert!(
            !phone
                .engine
                .drain_events()
                .iter()
                .any(|event| matches!(event, GroupEvent::MessageReceived { .. })),
            "standalone control has no application output"
        );
        let proposal_id = hash_id(&proposal.payload);
        assert!(
            phone
                .engine
                .pending_device_group_activity(&gid, &roster)
                .unwrap()
                .contains(&(proposal_id, next_epoch, Some(slot(2)))),
            "proposal activity missing convergence={through_convergence}, facts={:?}",
            phone
                .engine
                .pending_device_group_activity(&gid, &roster)
                .unwrap()
        );
    }
}

/// A real storage read failure during proposal admission must remain inside
/// native receive's rollback boundary. The independent file observer verifies
/// ratchets, wrapper/source provenance and the group row before exact retry.
#[tokio::test]
async fn device_group_proposal_profile_read_failure_keeps_native_receive_retryable() {
    use super::tagged_siblings::tag_devices;
    use cgka_traits::storage::StorageError;
    use storage_sqlite::{SqlCipherHardening, SqlCipherKey, open_hardened_sqlcipher};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("proposal-source.sqlite");
    let key = SqlCipherKey::raw([0x52; 32]);
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let account = b"proposal-profile-failure";
    let (mut phone, mut siblings, gid) = tag_devices(vec![
        roster_device_on(storage.clone(), account),
        roster_device(account),
    ])
    .await;
    let laptop = siblings.remove(0);
    let mut new_device = roster_device(account);
    let package = new_device.engine.fresh_key_package().await.unwrap();
    let crypto = RustCrypto::default();
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(&crypto, laptop.storage.mls_storage());
    let (proposal, _) = load_group(&laptop, &gid)
        .propose_add_member(
            &provider,
            &device_signer(&laptop),
            &parse_key_package(&package),
        )
        .unwrap();
    let mut proposal = group_transport(proposal, &gid, "proposal-source-failure");
    proposal.id = MessageId::new(vec![0xdd; 32]);
    let content_id = hash_id(&proposal.payload);
    let observer = rusqlite::Connection::open(&path).unwrap();
    open_hardened_sqlcipher(&observer, &key, SqlCipherHardening::live_cache()).unwrap();
    let group_row = || {
        observer
            .query_row(
                "SELECT record FROM cgka_groups WHERE id = ?1",
                [gid.as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .unwrap()
    };
    let mls_rows = || {
        let group_key =
            serde_json::to_vec(&openmls::group::GroupId::from_slice(gid.as_slice())).unwrap();
        observer.prepare("SELECT provider_version, label, storage_key, group_key, value FROM openmls_values WHERE group_key = ?1 ORDER BY storage_key")
            .unwrap().query_map([group_key], |row| (0..5).map(|i| row.get::<_, rusqlite::types::Value>(i)).collect::<rusqlite::Result<Vec<_>>>())
            .unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap()
    };
    let before_group = group_row();
    let before_mls = mls_rows();
    assert!(!before_mls.is_empty());
    for operation in ["INSERT", "UPDATE"] {
        observer
            .execute_batch(&format!(
            "CREATE TRIGGER fail_proposal_profile_{operation} AFTER {operation} ON cgka_messages
             WHEN NEW.id = X'{}' AND NEW.openmls_content = 2
             BEGIN UPDATE cgka_groups SET record = X'ff' WHERE id = NEW.group_id; END;",
            hex::encode(content_id.as_slice()),
        ))
            .unwrap();
    }
    let failed = phone.engine.ingest(proposal.clone()).await;
    assert!(
        matches!(
            failed,
            Err(EngineError::Storage(StorageError::Serialization(_)))
        ),
        "corrupting the native input's group record must reach the actual profile read"
    );
    assert!(
        group_row() == before_group,
        "profile-read failure must roll back its native storage unit"
    );
    assert!(
        mls_rows() == before_mls,
        "receive ratchet cannot commit without accepted source provenance"
    );
    assert!(!storage.has_processed_transport_id(&proposal.id).unwrap());
    let observations: i64 = observer.query_row(
        "SELECT count(*) FROM cgka_processed_transport_ids WHERE content_id = ?1 AND source_observed_order IS NOT NULL",
        [content_id.as_slice()], |row| row.get(0),
    ).unwrap();
    assert_eq!(observations, 0);
    observer
        .execute_batch(
            "DROP TRIGGER fail_proposal_profile_INSERT; DROP TRIGGER fail_proposal_profile_UPDATE;",
        )
        .unwrap();
    assert_eq!(
        phone.engine.ingest(proposal).await.unwrap(),
        IngestOutcome::Processed
    );
    let current_roster = roster_of(&phone, &gid);
    assert!(
        phone
            .engine
            .pending_device_group_activity(&gid, &current_roster)
            .unwrap()
            .iter()
            .any(|(id, _, slot)| *id == content_id && *slot == Some(super::device_roster::slot(2))),
        "exact retry must authenticate and retain the real target source"
    );
    drop(observer);
    storage.close().unwrap();
}

/// A lifetime-old unavailable prefix must not prevent later exact-source
/// recovery. All facts are produced by real past-epoch native admission.
#[tokio::test]
async fn partial_device_group_source_recovery_pages_past_unavailable_history() {
    use storage_sqlite::{SqlCipherHardening, SqlCipherKey, open_hardened_sqlcipher};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("source-recovery.sqlite");
    let key = SqlCipherKey::raw([0x63; 32]);
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let (mut phone, mut siblings, gid) = super::tagged_siblings::tag_devices(vec![
        roster_device_on(storage, b"source-page"),
        roster_device(b"source-page"),
    ])
    .await;
    let observer = rusqlite::Connection::open(&path).unwrap();
    open_hardened_sqlcipher(&observer, &key, SqlCipherHardening::live_cache()).unwrap();
    let mut laptop = siblings.remove(0);
    let roster = roster_of(&phone, &gid);
    let mut old = Vec::new();
    for n in 0..33 {
        let payload = cgka_traits::MarmotAppEvent::new(
            hex::encode(laptop.engine.self_id().as_slice()),
            n,
            49_999,
            vec![],
            "unavailable",
        )
        .encode()
        .unwrap();
        let SendResult::ApplicationMessage { msg, .. } = laptop
            .engine
            .send(SendIntent::AppMessage {
                group_id: gid.clone(),
                payload,
                expected_epoch: None,
            })
            .await
            .unwrap()
        else {
            panic!("application");
        };
        old.push(route_to_group(&msg, &gid));
    }
    let update = send_commit(
        &mut phone,
        SendIntent::SelfUpdate {
            group_id: gid.clone(),
        },
        &gid,
    )
    .await;
    assert_accepted(&mut laptop, &update, &gid).await;
    for message in old {
        phone.engine.ingest(message).await.unwrap();
    }
    assert_eq!(
        phone
            .storage
            .pending_authenticated_device_group_sources(&gid, false, None, None, 64)
            .unwrap()
            .len(),
        33
    );
    for snapshot in phone.storage.list_group_snapshots(&gid).unwrap() {
        phone
            .storage
            .release_group_snapshot(&gid, &snapshot)
            .unwrap();
    }
    let payload = cgka_traits::MarmotAppEvent::new(
        hex::encode(laptop.engine.self_id().as_slice()),
        100,
        49_999,
        vec![],
        "recoverable",
    )
    .encode()
    .unwrap();
    let SendResult::ApplicationMessage { msg, .. } = laptop
        .engine
        .send(SendIntent::AppMessage {
            group_id: gid.clone(),
            payload,
            expected_epoch: None,
        })
        .await
        .unwrap()
    else {
        panic!("application");
    };
    let update = send_commit(
        &mut phone,
        SendIntent::SelfUpdate {
            group_id: gid.clone(),
        },
        &gid,
    )
    .await;
    assert_accepted(&mut laptop, &update, &gid).await;
    let recoverable = route_to_group(&msg, &gid);
    let id = hash_id(&recoverable.payload);
    phone.engine.ingest(recoverable).await.unwrap();
    assert_eq!(
        phone
            .storage
            .pending_authenticated_device_group_sources(&gid, false, None, None, 64)
            .unwrap()
            .len(),
        34
    );
    let before = phone.storage.group_replay_state_fingerprint(&gid).unwrap();
    // Fail the real guard's restoration after its anchor rewind succeeded.
    // The enclosing native savepoint must restore selected state despite this.
    let current_epoch = phone.engine.epoch(&gid).unwrap().0;
    observer.execute_batch(&format!("CREATE TRIGGER fail_source_restore BEFORE INSERT ON cgka_groups WHEN NEW.epoch={current_epoch} BEGIN SELECT RAISE(ABORT, 'injected source restore failure'); END;")).unwrap();
    let mut saw_restore_failure = false;
    for _ in 0..3 {
        match phone.engine.recover_pending_device_group_sources(&gid) {
            Err(EngineError::Storage(cgka_traits::StorageError::Backend(message)))
                if message.contains("injected source restore failure") =>
            {
                saw_restore_failure = true;
                break;
            }
            Ok(()) => {}
            other => panic!("unexpected recovery: {other:?}"),
        }
    }
    assert!(
        saw_restore_failure,
        "must reach the later recoverable row despite unavailable prefix"
    );
    assert_eq!(
        phone.storage.group_replay_state_fingerprint(&gid).unwrap(),
        before,
        "failed optional recovery must restore selected state"
    );
    let persisted_epoch: i64 = observer
        .query_row(
            "SELECT epoch FROM cgka_groups WHERE id=?1",
            [gid.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        persisted_epoch,
        i64::try_from(current_epoch).unwrap(),
        "independent observer must see selected epoch after failed rewind restoration"
    );
    assert_eq!(
        load_group(&phone, &gid).epoch().as_u64(),
        current_epoch,
        "live selected OpenMLS view survives optional recovery failure"
    );
    assert_eq!(
        phone.engine.epoch_pin(&gid).unwrap().epoch.0,
        current_epoch,
        "actual send/read selected pin stays current"
    );
    observer
        .execute_batch("DROP TRIGGER fail_source_restore")
        .unwrap();
    for _ in 0..4 {
        phone
            .engine
            .recover_pending_device_group_sources(&gid)
            .unwrap();
    }
    assert!(
        phone
            .engine
            .pending_device_group_activity(&gid, &roster)
            .unwrap()
            .iter()
            .any(|(content, _, slot_id)| content == &id && *slot_id == Some(slot(2))),
        "later exact ciphertext/source anchor must be recovered beyond unavailable prefix"
    );
    assert_eq!(
        phone
            .storage
            .pending_authenticated_device_group_sources(&gid, false, None, None, 64)
            .unwrap()
            .len(),
        33,
        "unavailable facts remain pending, not permission to release aliases"
    );
    assert_eq!(
        phone.storage.group_replay_state_fingerprint(&gid).unwrap(),
        before,
        "recovery restores selected state"
    );
}
