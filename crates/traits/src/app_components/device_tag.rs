//! `marmot.member.device-tag.v1` wire structures.
//!
//! A device tag is a LeafNode `app_data_dictionary` entry that tells an
//! account's devices which of its leaves belongs to which device (mdk#2628
//! D32). It names the device's slot, is signed by that device's tag
//! signature key over the leaf's signature key, and is sealed under the
//! device roster's `leaf_tag_key`. This module holds the encodings only;
//! sealing, signing and reading need the MLS crypto provider and live in the
//! engine. A tag never makes anything invalid: a tag that does not decode,
//! open or verify reads as no tag.

use super::codec::{decode_var_bytes, encode_var_bytes};
use super::device_roster::DeviceSlotId;

/// Length of a tag's ChaCha20-Poly1305 nonce.
pub const DEVICE_TAG_NONCE_LEN: usize = 12;
/// Largest `sealed` value, and largest `signature`, in bytes.
pub const DEVICE_TAG_VECTOR_MAX_LEN: usize = 255;

/// The entry's value: a nonce and the sealed [`DeviceTagContentV1`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceTagV1 {
    pub nonce: [u8; DEVICE_TAG_NONCE_LEN],
    pub sealed: Vec<u8>,
}

/// What a tag opens to: the device's slot and its signature over
/// `DeviceTagSignedContentV1`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceTagContentV1 {
    pub slot: DeviceSlotId,
    pub signature: Vec<u8>,
}

/// Which roster slot a leaf belongs to, as its device tag says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceTagClaim {
    /// The tag names a linked device and verifies under its tag signature
    /// key.
    Device(DeviceSlotId),
    /// The tag names a `removed` slot and verifies under the key that slot's
    /// record keeps.
    RejectedSlot(DeviceSlotId),
    /// No tag, or one that does not decode, open or verify, or that names a
    /// slot the roster holds no key for.
    Unclaimed,
}

pub fn encode_device_tag_v1(tag: &DeviceTagV1) -> Result<Vec<u8>, String> {
    validate_vector(&tag.sealed, "device tag sealed content")?;
    let mut out = tag.nonce.to_vec();
    encode_var_bytes(&tag.sealed, &mut out);
    Ok(out)
}

/// Decode exactly one [`DeviceTagV1`]; trailing bytes are an error.
pub fn decode_device_tag_v1(bytes: &[u8]) -> Result<DeviceTagV1, String> {
    let (nonce, mut cursor) = bytes
        .split_first_chunk::<DEVICE_TAG_NONCE_LEN>()
        .ok_or("device tag nonce is truncated")?;
    let sealed = decode_var_bytes(
        &mut cursor,
        DEVICE_TAG_VECTOR_MAX_LEN,
        "device tag sealed content",
    )?;
    validate_vector(&sealed, "device tag sealed content")?;
    if !cursor.is_empty() {
        return Err("device tag has trailing bytes".into());
    }
    Ok(DeviceTagV1 {
        nonce: *nonce,
        sealed,
    })
}

pub fn encode_device_tag_content_v1(content: &DeviceTagContentV1) -> Result<Vec<u8>, String> {
    validate_vector(&content.signature, "device tag signature")?;
    let mut out = content.slot.to_vec();
    encode_var_bytes(&content.signature, &mut out);
    Ok(out)
}

/// Decode exactly one [`DeviceTagContentV1`]; trailing bytes are an error.
pub fn decode_device_tag_content_v1(bytes: &[u8]) -> Result<DeviceTagContentV1, String> {
    let (slot, mut cursor) = bytes
        .split_first_chunk::<32>()
        .ok_or("device tag slot is truncated")?;
    let signature = decode_var_bytes(
        &mut cursor,
        DEVICE_TAG_VECTOR_MAX_LEN,
        "device tag signature",
    )?;
    validate_vector(&signature, "device tag signature")?;
    if !cursor.is_empty() {
        return Err("device tag content has trailing bytes".into());
    }
    Ok(DeviceTagContentV1 {
        slot: *slot,
        signature,
    })
}

/// `DeviceTagSignedContentV1`: the slot and the leaf's signature key, the
/// content a device signs with its tag signature key.
pub fn encode_device_tag_signed_content_v1(
    slot: &DeviceSlotId,
    leaf_signature_key: &[u8],
) -> Vec<u8> {
    let mut out = slot.to_vec();
    encode_var_bytes(leaf_signature_key, &mut out);
    out
}

fn validate_vector(value: &[u8], label: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > DEVICE_TAG_VECTOR_MAX_LEN {
        return Err(format!("{label} must be 1 to 255 bytes"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The structures of marmot#452's device tag vector, as encodings: the
    /// crypto that produces `sealed` and `signature` is tested in the engine.
    #[test]
    fn spec_vector_structures_round_trip() {
        let signature = hex::decode(concat!(
            "601cd5e2a4fc4fc0871cac3ce66a8f2376b199110700f92abb693460bb282849",
            "695ff8afe6da3432ca7a60a1b409195e9cac96b3ed1ff25a31ab138f8c455e01",
        ))
        .unwrap();
        let content = DeviceTagContentV1 {
            slot: [0x11; 32],
            signature,
        };
        let content_bytes = encode_device_tag_content_v1(&content).unwrap();
        assert_eq!(content_bytes.len(), 98);
        assert_eq!(&content_bytes[32..34], [0x40, 0x40]);
        assert_eq!(
            decode_device_tag_content_v1(&content_bytes).unwrap(),
            content
        );

        let tag = DeviceTagV1 {
            nonce: [0x77; 12],
            sealed: vec![0xab; 114],
        };
        let tag_bytes = encode_device_tag_v1(&tag).unwrap();
        assert_eq!(tag_bytes.len(), 128);
        assert_eq!(&tag_bytes[12..14], [0x40, 0x72]);
        assert_eq!(decode_device_tag_v1(&tag_bytes).unwrap(), tag);

        let signed = encode_device_tag_signed_content_v1(&[0x11; 32], &[0x66; 32]);
        assert_eq!(signed.len(), 65);
        assert_eq!(signed[32], 0x20);
    }

    #[test]
    fn decoding_is_exact() {
        let tag = encode_device_tag_v1(&DeviceTagV1 {
            nonce: [1; 12],
            sealed: vec![2; 20],
        })
        .unwrap();
        let mut trailing = tag.clone();
        trailing.push(0);
        assert!(decode_device_tag_v1(&trailing).is_err());
        assert!(decode_device_tag_v1(&tag[..tag.len() - 1]).is_err());
        assert!(decode_device_tag_v1(&tag[..11]).is_err());

        let content = encode_device_tag_content_v1(&DeviceTagContentV1 {
            slot: [3; 32],
            signature: vec![4; 64],
        })
        .unwrap();
        let mut trailing = content.clone();
        trailing.push(0);
        assert!(decode_device_tag_content_v1(&trailing).is_err());

        // Empty and over-long vectors are not tags.
        let mut empty = vec![1; 12];
        empty.push(0);
        assert!(decode_device_tag_v1(&empty).is_err());
        assert!(
            encode_device_tag_v1(&DeviceTagV1 {
                nonce: [1; 12],
                sealed: vec![0; 256],
            })
            .is_err()
        );
    }
}
