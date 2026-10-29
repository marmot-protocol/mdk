//! Device tags (`marmot.member.device-tag.v1`, mdk#2628 D32): sealing a tag
//! for one of this device's leaves, and reading which roster slot a leaf
//! belongs to.
//!
//! The wire structures live in `cgka_traits::app_components`. A tag is signed
//! under the device group's ciphersuite. MDK builds every group under
//! `DEFAULT_CIPHERSUITE` (`0x0001`), so tags are Ed25519; another ciphersuite
//! would need its signature scheme passed in here. A tag never makes anything
//! invalid: reading one that does not decode, open or verify gives
//! [`DeviceTagClaim::Unclaimed`], never an error.

pub use cgka_traits::app_components::DeviceTagClaim;
use cgka_traits::app_components::{
    DEVICE_TAG_COMPONENT_ID, DEVICE_TAG_NONCE_LEN, DeviceRosterV1, DeviceSlotId,
    DeviceTagContentV1, DeviceTagV1, RejectedSlotReasonV1, decode_device_tag_content_v1,
    decode_device_tag_v1, encode_component_vectors, encode_device_tag_content_v1,
    encode_device_tag_signed_content_v1, encode_device_tag_v1,
};
use cgka_traits::error::EngineError;
use openmls::prelude::LeafNode;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::random::OpenMlsRand;
use openmls_traits::types::{AeadType, SignatureScheme};
use std::sync::LazyLock;

/// `SignWithLabel`'s label for "Marmot DeviceTag" (RFC 9420, section 5.1.2).
const SIGN_LABEL: &[u8] = b"MLS 1.0 Marmot DeviceTag";

// Reading only verifies and opens, so it needs no RNG-bearing provider of the
// caller's; this one never draws randomness.
static VERIFY_CRYPTO: LazyLock<RustCrypto> = LazyLock::new(RustCrypto::default);

/// The `0x800f` entry for a leaf whose signature key is
/// `leaf_signature_key`: `slot` signed with the device's tag signature
/// private key (a 32-byte Ed25519 seed), sealed under the roster's
/// `leaf_tag_key` with a nonce drawn from `crypto`.
pub fn seal_device_tag<C: OpenMlsCrypto + OpenMlsRand>(
    crypto: &C,
    leaf_tag_key: &[u8; 32],
    slot: &DeviceSlotId,
    tag_signature_private_key: &[u8],
    leaf_signature_key: &[u8],
) -> Result<Vec<u8>, EngineError> {
    let nonce = crypto
        .random_array::<DEVICE_TAG_NONCE_LEN>()
        .map_err(|e| EngineError::Backend(format!("device tag nonce: {e:?}")))?;
    seal_with_nonce(
        crypto,
        leaf_tag_key,
        slot,
        tag_signature_private_key,
        leaf_signature_key,
        nonce,
    )
}

fn seal_with_nonce(
    crypto: &impl OpenMlsCrypto,
    leaf_tag_key: &[u8; 32],
    slot: &DeviceSlotId,
    tag_signature_private_key: &[u8],
    leaf_signature_key: &[u8],
    nonce: [u8; DEVICE_TAG_NONCE_LEN],
) -> Result<Vec<u8>, EngineError> {
    let signature = crypto
        .sign(
            SignatureScheme::ED25519,
            &sign_content(slot, leaf_signature_key),
            tag_signature_private_key,
        )
        .map_err(|e| EngineError::Backend(format!("device tag signature: {e:?}")))?;
    let content = encode_device_tag_content_v1(&DeviceTagContentV1 {
        slot: *slot,
        signature,
    })
    .map_err(EngineError::Serialize)?;
    let sealed = crypto
        .aead_encrypt(
            AeadType::ChaCha20Poly1305,
            leaf_tag_key,
            &content,
            &nonce,
            leaf_signature_key,
        )
        .map_err(|e| EngineError::Backend(format!("device tag seal: {e:?}")))?;
    encode_device_tag_v1(&DeviceTagV1 { nonce, sealed }).map_err(EngineError::Serialize)
}

/// Which roster slot `leaf` belongs to, as its device tag says
/// (device-tag-v1.md, "Reading tags"), read against `roster`, the device
/// group's current roster.
///
/// The spec reads tags only on leaves whose credential identity is the
/// reader's own account; the caller checks that first, as
/// `Engine::member_device_tag_claim` does.
pub fn device_tag_claim(leaf: &LeafNode, roster: &DeviceRosterV1) -> DeviceTagClaim {
    let Some(entry) = leaf
        .extensions()
        .app_data_dictionary()
        .and_then(|dictionary| dictionary.dictionary().get(&DEVICE_TAG_COMPONENT_ID))
    else {
        return DeviceTagClaim::Unclaimed;
    };
    read_entry(entry, leaf.signature_key().as_slice(), roster)
}

fn read_entry(entry: &[u8], leaf_signature_key: &[u8], roster: &DeviceRosterV1) -> DeviceTagClaim {
    let Some(content) = open_entry(entry, leaf_signature_key, &roster.leaf_tag_key) else {
        return DeviceTagClaim::Unclaimed;
    };
    let signed = sign_content(&content.slot, leaf_signature_key);
    let verifies = |key: &[u8]| {
        VERIFY_CRYPTO
            .verify_signature(SignatureScheme::ED25519, &signed, key, &content.signature)
            .is_ok()
    };
    let device_key = roster
        .devices
        .get(&content.slot)
        .and_then(|device| device.tag_signature_key.as_deref());
    if device_key.is_some_and(verifies) {
        return DeviceTagClaim::Device(content.slot);
    }
    let removed_key = roster
        .rejected_slots
        .get(&content.slot)
        .filter(|rejected| rejected.reason == RejectedSlotReasonV1::Removed)
        .and_then(|rejected| rejected.tag_signature_key.as_deref());
    if removed_key.is_some_and(verifies) {
        return DeviceTagClaim::RejectedSlot(content.slot);
    }
    DeviceTagClaim::Unclaimed
}

fn open_entry(
    entry: &[u8],
    leaf_signature_key: &[u8],
    leaf_tag_key: &[u8; 32],
) -> Option<DeviceTagContentV1> {
    let tag = decode_device_tag_v1(entry).ok()?;
    let content = VERIFY_CRYPTO
        .aead_decrypt(
            AeadType::ChaCha20Poly1305,
            leaf_tag_key,
            &tag.sealed,
            &tag.nonce,
            leaf_signature_key,
        )
        .ok()?;
    decode_device_tag_content_v1(&content).ok()
}

/// `SignContent { label<V>; content<V> }` over `DeviceTagSignedContentV1`.
fn sign_content(slot: &DeviceSlotId, leaf_signature_key: &[u8]) -> Vec<u8> {
    encode_component_vectors(&[
        SIGN_LABEL,
        &encode_device_tag_signed_content_v1(slot, leaf_signature_key),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use cgka_traits::app_components::{DeviceEntryV1, RejectedSlotV1};

    const LEAF_TAG_KEY: [u8; 32] = [0x33; 32];
    const SLOT: DeviceSlotId = [0x11; 32];
    const LEAF_SIGNATURE_KEY: [u8; 32] = [0x66; 32];
    const TAG_PRIVATE_KEY: [u8; 32] = [0x55; 32];
    const TAG_PUBLIC_KEY: &str = "c6822637c7d310ec57627be00ba259d253749f4aaf644470cffbe53a35f73242";

    fn spec_tag() -> Vec<u8> {
        seal_with_nonce(
            &RustCrypto::default(),
            &LEAF_TAG_KEY,
            &SLOT,
            &TAG_PRIVATE_KEY,
            &LEAF_SIGNATURE_KEY,
            [0x77; 12],
        )
        .unwrap()
    }

    fn roster_with_device(tag_signature_key: Option<Vec<u8>>) -> DeviceRosterV1 {
        let mut roster = DeviceRosterV1 {
            leaf_tag_key: LEAF_TAG_KEY,
            ..DeviceRosterV1::default()
        };
        roster.devices.insert(
            SLOT,
            DeviceEntryV1 {
                tag_signature_key,
                ..DeviceEntryV1::default()
            },
        );
        roster
    }

    fn tag_public_key() -> Vec<u8> {
        hex::decode(TAG_PUBLIC_KEY).unwrap()
    }

    /// device-tag-v1.md, "Test vectors".
    #[test]
    fn sealing_reproduces_the_spec_vector() {
        assert_eq!(
            hex::encode(sign_content(&SLOT, &LEAF_SIGNATURE_KEY)),
            concat!(
                "18",
                "4d4c5320312e30204d61726d6f7420446576696365546167",
                "4041",
                "1111111111111111111111111111111111111111111111111111111111111111",
                "20",
                "6666666666666666666666666666666666666666666666666666666666666666",
            )
        );
        assert_eq!(
            hex::encode(spec_tag()),
            concat!(
                "777777777777777777777777",
                "4072",
                "711af2f06f38f0f04032cfdf0f23a8ea57773ecac4fde7f4b8e7d4789c38ba13",
                "4a727afee6b3858640acf81557466cdb6abd9251bafa8de2c6cb69d4e15993fe",
                "39ed1ca968e78f4b4e804bf74ed76d782a2ba3d3a3ac51afda04f00318e3a2a5",
                "7e181129d2430033adf59c6160510eae4782",
            )
        );
        let content = open_entry(&spec_tag(), &LEAF_SIGNATURE_KEY, &LEAF_TAG_KEY).unwrap();
        assert_eq!(
            hex::encode(content.signature),
            concat!(
                "601cd5e2a4fc4fc0871cac3ce66a8f2376b199110700f92abb693460bb282849",
                "695ff8afe6da3432ca7a60a1b409195e9cac96b3ed1ff25a31ab138f8c455e01",
            )
        );
    }

    #[test]
    fn a_tag_reads_as_the_device_whose_key_verifies_it() {
        let roster = roster_with_device(Some(tag_public_key()));
        assert_eq!(
            read_entry(&spec_tag(), &LEAF_SIGNATURE_KEY, &roster),
            DeviceTagClaim::Device(SLOT)
        );
    }

    #[test]
    fn a_removed_slot_that_keeps_its_key_reads_as_rejected() {
        let mut roster = roster_with_device(None);
        roster.devices.clear();
        roster.rejected_slots.insert(
            SLOT,
            RejectedSlotV1 {
                reason: RejectedSlotReasonV1::Removed,
                rejected_at: 1,
                tag_signature_key: Some(tag_public_key()),
            },
        );
        assert_eq!(
            read_entry(&spec_tag(), &LEAF_SIGNATURE_KEY, &roster),
            DeviceTagClaim::RejectedSlot(SLOT)
        );

        // A dropped record, or one that kept no key, leaves the leaf unclaimed.
        roster
            .rejected_slots
            .get_mut(&SLOT)
            .unwrap()
            .tag_signature_key = None;
        assert_eq!(
            read_entry(&spec_tag(), &LEAF_SIGNATURE_KEY, &roster),
            DeviceTagClaim::Unclaimed
        );
    }

    #[test]
    fn anything_that_does_not_decode_open_or_verify_is_unclaimed() {
        let roster = roster_with_device(Some(tag_public_key()));
        let unclaimed = |entry: &[u8], leaf_signature_key: &[u8], roster: &DeviceRosterV1| {
            assert_eq!(
                read_entry(entry, leaf_signature_key, roster),
                DeviceTagClaim::Unclaimed
            );
        };

        // Copied onto a leaf with another signature key: the aad differs.
        unclaimed(&spec_tag(), &[0x67; 32], &roster);
        // Another account's leaf_tag_key.
        let other_key = DeviceRosterV1 {
            leaf_tag_key: [0x34; 32],
            ..roster.clone()
        };
        unclaimed(&spec_tag(), &LEAF_SIGNATURE_KEY, &other_key);
        // The slot's device has not set its key yet, or holds another one.
        unclaimed(&spec_tag(), &LEAF_SIGNATURE_KEY, &roster_with_device(None));
        unclaimed(
            &spec_tag(),
            &LEAF_SIGNATURE_KEY,
            &roster_with_device(Some(vec![0x01; 32])),
        );
        // A slot the roster does not hold.
        let mut moved = roster.clone();
        let device = moved.devices.remove(&SLOT).unwrap();
        moved.devices.insert([0x12; 32], device);
        unclaimed(&spec_tag(), &LEAF_SIGNATURE_KEY, &moved);
        // Trailing bytes, truncation and a flipped sealed byte.
        let mut trailing = spec_tag();
        trailing.push(0);
        unclaimed(&trailing, &LEAF_SIGNATURE_KEY, &roster);
        unclaimed(&spec_tag()[..127], &LEAF_SIGNATURE_KEY, &roster);
        let mut flipped = spec_tag();
        flipped[20] ^= 1;
        unclaimed(&flipped, &LEAF_SIGNATURE_KEY, &roster);
        unclaimed(&[], &LEAF_SIGNATURE_KEY, &roster);
    }

    #[test]
    fn a_not_me_record_never_claims_a_leaf() {
        // A valid roster never gives a not-me record a key; reading still
        // refuses one rather than trusting validation upstream.
        let mut roster = roster_with_device(None);
        roster.devices.clear();
        roster.rejected_slots.insert(
            SLOT,
            RejectedSlotV1 {
                reason: RejectedSlotReasonV1::NotMe,
                rejected_at: 1,
                tag_signature_key: Some(tag_public_key()),
            },
        );
        assert_eq!(
            read_entry(&spec_tag(), &LEAF_SIGNATURE_KEY, &roster),
            DeviceTagClaim::Unclaimed
        );
    }

    #[test]
    fn sealing_draws_a_fresh_nonce_and_reads_back() {
        let crypto = RustCrypto::default();
        let seal = || {
            seal_device_tag(
                &crypto,
                &LEAF_TAG_KEY,
                &SLOT,
                &TAG_PRIVATE_KEY,
                &LEAF_SIGNATURE_KEY,
            )
            .unwrap()
        };
        let (first, second) = (seal(), seal());
        assert_eq!(first.len(), 128);
        assert_ne!(first[..12], second[..12]);
        let roster = roster_with_device(Some(tag_public_key()));
        for tag in [first, second] {
            assert_eq!(
                read_entry(&tag, &LEAF_SIGNATURE_KEY, &roster),
                DeviceTagClaim::Device(SLOT)
            );
        }
    }
}
