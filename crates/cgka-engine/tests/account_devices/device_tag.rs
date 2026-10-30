//! `marmot.member.device-tag.v1` (0x800f), the LeafNode tag that says which
//! of an account's devices holds a leaf (mdk#2628 item 3.1d, D32).
//!
//! Read through the engine, a member's leaf belongs to the roster slot its
//! tag names, in the tree of the epoch asked for: the current one, or a past
//! one from its retained anchor, a read that writes nothing. A tag never makes
//! a Commit invalid. No group may require 0x800f, and a GroupContext entry
//! under it is unknown data that this engine never writes. The tag crypto and
//! the spec vector are tested in the engine's `device_tag` module.
//!
//! A device tags from the roster of the device group its host names, once its
//! entry there, the one at its KeyPackage publication slot, carries its MLS
//! signature key. Another entry carrying that key is not its own. It sets that key in a roster
//! update whose UpdatePath already carries a tag. From then on every
//! KeyPackage it builds carries a fresh tag, and so does every replacement of
//! a leaf whose tag does not read as its own, whichever own Commit makes it.

use super::device_roster::{
    entry, found_device_group, phone_and_laptop, roster, roster_device, roster_device_on,
    roster_of, roster_update, slot,
};
use super::*;
use cgka_engine::device_tag::{DeviceTagClaim, device_tag_claim, seal_device_tag};
use cgka_traits::app_components::{
    DEVICE_TAG_COMPONENT_ID, DeviceRosterOperationV1, DeviceRosterV1, DeviceSlotId,
    decode_components_list,
};
use cgka_traits::maintenance::KeyPackageLifecycleState;
use cgka_traits::storage::{GroupStorage as _, MaintenanceStorage as _};
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
        .member_device_tag_claim(gid, epoch, leaf_index, roster)
        .unwrap()
}

#[tokio::test]
async fn a_member_leaf_reads_as_the_device_its_tag_names() {
    let (mut phone, laptop, gid) = phone_and_laptop().await;
    let (signer, public_key) = tag_key_pair();
    let tagged = roster_with_laptop_key(public_key);
    let laptop_leaf = leaf_index(&laptop, &gid);
    let before = phone.engine.epoch(&gid).unwrap();
    assert_eq!(
        claim(&phone, &gid, before, laptop_leaf, &tagged),
        Some(DeviceTagClaim::Unclaimed),
        "a leaf from before the link carries no tag"
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

    // An older epoch reads the leaf as it was then, from its retained
    // anchor, and leaves the group's state and snapshots as they were; an
    // epoch with no anchor, or an index with no leaf, reads nothing.
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

    // Once later commits have pruned that epoch's anchor, it reads nothing,
    // never the current tree's tag.
    for _ in 0..6 {
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
    let (mut phone, mut laptop, device_gid) = phone_and_laptop().await;
    let mut bob = roster_device(b"bob");
    let mut groups = Vec::new();
    for _ in 0..6 {
        let bob_kp = bob.engine.fresh_key_package().await.unwrap();
        groups.push(found_group(&mut laptop, vec![bob_kp], true, &mut [&mut bob]).await);
    }
    hold_slot(&laptop, slot(2));
    laptop
        .engine
        .set_device_tag_group(Some(device_gid.clone()))
        .unwrap();
    set_own_key(&mut laptop, slot(2), &device_gid, &mut [&mut phone]).await;
    let tagged = roster_of(&laptop, &device_gid);
    let mut carol = roster_device(b"carol");
    let carol_kp = carol.engine.fresh_key_package().await.unwrap();
    let phone_kp = phone.engine.fresh_key_package().await.unwrap();

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
    tokio::time::sleep(std::time::Duration::from_millis(75)).await;
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
    seeded
        .engine
        .set_device_tag_group(Some(GroupId::new(vec![0xab; 16])))
        .unwrap();
    assert_eq!(
        key_package_tag(&seeded.engine.fresh_key_package().await.unwrap()),
        (None, false)
    );
    assert!(
        seeded
            .engine
            .key_package_advertises_current_capabilities(&tagged)
            .is_err()
    );
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
        assert!(
            quarantined
                .engine
                .set_device_tag_group(Some(gid.clone()))
                .is_err()
        );
    }
    assert_eq!(quarantined.engine.quarantined_groups().len(), 1);
    assert_eq!(
        key_package_tag(&quarantined.engine.fresh_key_package().await.unwrap()),
        (None, false)
    );
    assert!(
        quarantined
            .engine
            .key_package_advertises_current_capabilities(&tagged)
            .is_err()
    );
}
