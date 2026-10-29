//! `marmot.member.device-tag.v1` (0x800f), the LeafNode tag that says which
//! of an account's devices holds a leaf (mdk#2628 item 3.1d, D32).
//!
//! Read through the engine, a member's leaf belongs to the roster slot its
//! tag names, against the device group's current tree only. A tag never makes
//! a Commit invalid. No group may require 0x800f, and a GroupContext entry
//! under it is unknown data that this engine never writes. The tag crypto and
//! the spec vector are tested in the engine's `device_tag` module.

use super::device_roster::{phone_and_laptop, roster, roster_device, slot};
use super::*;
use cgka_engine::device_tag::{DeviceTagClaim, seal_device_tag};
use cgka_traits::app_components::{
    DEVICE_TAG_COMPONENT_ID, DeviceRosterV1, DeviceSlotId, decode_components_list,
};
use cgka_traits::types::EpochId;
use openmls_traits::crypto::OpenMlsCrypto as _;
use openmls_traits::types::SignatureScheme;

/// A device's tag signature key pair: a 32-byte Ed25519 seed and its public
/// key.
fn tag_key_pair() -> (Vec<u8>, Vec<u8>) {
    RustCrypto::default()
        .signature_key_gen(SignatureScheme::ED25519)
        .unwrap()
}

/// The phone-and-laptop roster, with `tag_public_key` as the laptop's.
fn roster_with_laptop_key(tag_public_key: Vec<u8>) -> DeviceRosterV1 {
    let mut roster = roster(&[(1, "Phone"), (2, "Laptop")]);
    roster.devices.get_mut(&slot(2)).unwrap().tag_signature_key = Some(tag_public_key);
    roster
}

/// A tag for `device`'s leaf naming `slot`, under `roster`'s leaf tag key.
fn tag_for(device: &Device, roster: &DeviceRosterV1, slot: &DeviceSlotId, key: &[u8]) -> Vec<u8> {
    seal_device_tag(
        &RustCrypto::default(),
        &roster.leaf_tag_key,
        slot,
        key,
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
    let (private_key, public_key) = tag_key_pair();
    let tagged = roster_with_laptop_key(public_key);
    let laptop_leaf = leaf_index(&laptop, &gid);
    let before = phone.engine.epoch(&gid).unwrap();
    assert_eq!(
        claim(&phone, &gid, before, laptop_leaf, &tagged),
        Some(DeviceTagClaim::Unclaimed),
        "a leaf from before the link carries no tag"
    );

    let entry = tag_for(&laptop, &tagged, &slot(2), &private_key);
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

    // Only the current tree is read: an older epoch, or an index with no
    // leaf, reads nothing.
    assert_eq!(claim(&phone, &gid, before, laptop_leaf, &tagged), None);
    assert_eq!(claim(&phone, &gid, after, 9, &tagged), None);
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
    let (private_key, public_key) = tag_key_pair();
    let alices_roster = roster_with_laptop_key(public_key);

    let entry = tag_for(&bob, &alices_roster, &slot(2), &private_key);
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
