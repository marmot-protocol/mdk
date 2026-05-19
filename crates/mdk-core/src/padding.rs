//! Bucket-based length padding for encrypted plaintexts.
//!
//! Both kind:445 group messages (MIP-03) and gift-wrapped Welcome events
//! (MIP-02) historically leaked information through their on-the-wire size:
//!
//! - SelfRemove proposals are empty `MlsMessage::PublicMessage`s and stand out
//!   as the smallest possible kind:445 events (issue #37).
//! - Welcomes carry the full MLS ratchet tree, so the encrypted gift-wrap size
//!   scales with the group's member count (issue #33).
//!
//! Padding the plaintext to a power-of-two bucket before encryption maps every
//! plaintext into one of a small number of length classes, so a relay observer
//! cannot distinguish messages within the same bucket.
//!
//! Padding is appended as zero bytes. The on-the-wire MLS framing uses TLS
//! length-prefixed encoding, so the decoder consumes exactly the framed
//! message and the trailing zero bytes are ignored. The deserialization sites
//! that depend on this property are `process_mls_message` in
//! `crate::messages::process` and `process_welcome` in [`crate::welcomes`].

/// Minimum bucket size for kind:445 group message plaintexts.
///
/// Chosen so that the smallest possible MLS message (an empty SelfRemove
/// `PublicMessage`) and a typical short text message land in the same bucket.
/// A bare text rumor — pubkey, kind, created_at, id, sig, plus a few-byte
/// `content` — already serializes to ~280 bytes of MLS `PrivateMessage`
/// plaintext, so a 256-byte floor would leave SelfRemove proposals
/// distinguishable. 512 bytes absorbs both classes.
///
/// Guards marmot-security issue #37 (SelfRemove size fingerprinting).
pub(crate) const MESSAGE_PADDING_FLOOR: usize = 512;

/// Minimum bucket size for the Welcome rumor payload (raw MLS bytes, before
/// base64 encoding and NIP-59 gift wrapping).
///
/// Welcomes always carry the full ratchet tree, so they are inherently larger
/// than chat messages; a higher floor keeps tiny groups indistinguishable from
/// each other.
pub(crate) const WELCOME_PADDING_FLOOR: usize = 1024;

/// Returns the smallest power-of-two bucket that fits `len` bytes and is at
/// least `floor` bytes wide.
///
/// `floor` MUST itself be a power of two; this is a programmer-controlled
/// constant in this crate, so we debug-assert it rather than returning a
/// runtime error.
fn bucket_for_len(len: usize, floor: usize) -> usize {
    debug_assert!(
        floor.is_power_of_two(),
        "padding floor must be a power of two"
    );

    if len <= floor {
        return floor;
    }

    len.checked_next_power_of_two()
        .expect("padded payload length overflowed usize")
}

/// Returns a padded copy of `plaintext` whose length is rounded up to the next
/// power-of-two bucket of at least `floor` bytes. The bytes added beyond the
/// original length are all zero.
///
/// The receiver-side MLS deserializers (`MlsMessageIn::tls_deserialize` and
/// `Welcome::tls_deserialize`) consume exactly the framed message bytes and
/// ignore trailing padding.
pub(crate) fn pad_to_bucket(plaintext: &[u8], floor: usize) -> Vec<u8> {
    let target = bucket_for_len(plaintext.len(), floor);
    let mut padded = Vec::with_capacity(target);
    padded.extend_from_slice(plaintext);
    padded.resize(target, 0);
    padded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_floors_small_lengths() {
        assert_eq!(bucket_for_len(0, 256), 256);
        assert_eq!(bucket_for_len(1, 256), 256);
        assert_eq!(bucket_for_len(255, 256), 256);
        assert_eq!(bucket_for_len(256, 256), 256);
    }

    #[test]
    fn bucket_rounds_up_to_next_power_of_two() {
        assert_eq!(bucket_for_len(257, 256), 512);
        assert_eq!(bucket_for_len(512, 256), 512);
        assert_eq!(bucket_for_len(513, 256), 1024);
        assert_eq!(bucket_for_len(1023, 256), 1024);
        assert_eq!(bucket_for_len(1024, 256), 1024);
        assert_eq!(bucket_for_len(1025, 256), 2048);
    }

    #[test]
    fn welcome_floor_buckets() {
        assert_eq!(bucket_for_len(0, WELCOME_PADDING_FLOOR), 1024);
        assert_eq!(bucket_for_len(1024, WELCOME_PADDING_FLOOR), 1024);
        assert_eq!(bucket_for_len(1025, WELCOME_PADDING_FLOOR), 2048);
        assert_eq!(bucket_for_len(4097, WELCOME_PADDING_FLOOR), 8192);
    }

    #[test]
    fn pad_appends_zero_bytes_to_bucket_size() {
        let payload = vec![0xAAu8; 100];
        let padded = pad_to_bucket(&payload, 256);

        assert_eq!(padded.len(), 256);
        assert_eq!(&padded[..100], &payload[..]);
        assert!(padded[100..].iter().all(|&b| b == 0));
    }

    #[test]
    fn pad_no_op_when_exact_bucket() {
        let payload = vec![0x55u8; 256];
        let padded = pad_to_bucket(&payload, 256);

        assert_eq!(padded.len(), 256);
        assert_eq!(padded, payload);
    }

    #[test]
    fn pad_different_inputs_share_bucket() {
        let small_a = pad_to_bucket(&[0xAA; 10], MESSAGE_PADDING_FLOOR);
        let small_b = pad_to_bucket(&[0xBB; 200], MESSAGE_PADDING_FLOOR);
        let empty = pad_to_bucket(&[], MESSAGE_PADDING_FLOOR);

        assert_eq!(small_a.len(), small_b.len());
        assert_eq!(small_b.len(), empty.len());
        assert_eq!(empty.len(), MESSAGE_PADDING_FLOOR);
    }

    #[test]
    fn pad_promotes_to_next_bucket() {
        let medium = pad_to_bucket(&[0xCC; 600], MESSAGE_PADDING_FLOOR);
        let larger = pad_to_bucket(&[0xDD; 1000], MESSAGE_PADDING_FLOOR);

        assert_eq!(medium.len(), 1024);
        assert_eq!(larger.len(), 1024);
    }
}
