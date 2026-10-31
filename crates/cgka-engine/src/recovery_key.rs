//! Recovery keys (mdk#2628 4.4a, D34 item 2): the key pair an account's
//! backups are sealed to, derived from the 128 bits of entropy its 12
//! recovery words carry.
//!
//! The derivation is fixed and independent of any group, because a device
//! that restores may hold none:
//!
//! ```text
//! prk = HKDF-Extract(SHA-256, salt = "marmot recovery key v1", ikm = entropy)
//! ikm = HKDF-Expand(SHA-256, prk, info = "marmot recovery key pair", 32)
//! key pair = DeriveKeyPair(ikm), DHKEM(X25519, HKDF-SHA256)
//! ```
//!
//! That is the KEM of ciphersuite `0x0001`, whatever ciphersuite the
//! account's device group uses. Devices keep only the public half, in the
//! roster's account entry; the private half exists only while the user's
//! words are in hand.
//!
//! Sealing is MLS's `EncryptWithLabel` (RFC 9420, section 5.1.3) with the
//! label "Marmot Backup" and the caller's context, under `0x0001`'s HPKE, as
//! history keys seal under "Marmot History" ([`crate::history_key`]). What the
//! context binds is the caller's to decide. A bad recipient key, or a value
//! that does not decode exactly or open, gives `None`, never an error.

use crate::engine::Engine;
use crate::history_key::{open_with_label, seal_with_label};
use cgka_traits::error::EngineError;
use cgka_traits::storage::StorageProvider;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::{Ciphersuite, HashType, HpkeKeyPair};

/// The entropy the 12 recovery words carry: 128 bits.
pub const RECOVERY_ENTROPY_LEN: usize = 16;

/// Recovery keys use ciphersuite `0x0001`'s KEM and HPKE, whatever the
/// device group's ciphersuite.
const RECOVERY_CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
const DERIVE_SALT: &[u8] = b"marmot recovery key v1";
const DERIVE_INFO: &[u8] = b"marmot recovery key pair";
/// `EncryptWithLabel`'s label for "Marmot Backup" (RFC 9420, section 5.1.3).
const ENCRYPT_LABEL: &[u8] = b"MLS 1.0 Marmot Backup";

/// The recovery key pair `entropy` derives.
pub fn derive_recovery_key_pair<C: OpenMlsCrypto>(
    crypto: &C,
    entropy: &[u8; RECOVERY_ENTROPY_LEN],
) -> Result<HpkeKeyPair, EngineError> {
    // Both HKDF outputs are `SecretVLBytes`, zeroized on drop.
    let prk = crypto
        .hkdf_extract(HashType::Sha2_256, DERIVE_SALT, entropy)
        .map_err(|e| EngineError::Backend(format!("recovery key extract: {e:?}")))?;
    let ikm = crypto
        .hkdf_expand(
            HashType::Sha2_256,
            prk.as_slice(),
            DERIVE_INFO,
            RECOVERY_CIPHERSUITE.hash_length(),
        )
        .map_err(|e| EngineError::Backend(format!("recovery key expand: {e:?}")))?;
    crypto
        .derive_hpke_keypair(RECOVERY_CIPHERSUITE.hpke_config(), ikm.as_slice())
        .map_err(|e| EngineError::Backend(format!("recovery key derivation: {e:?}")))
}

/// `plaintext` sealed to `recovery_public_key` for `context`, or `None` when
/// the key is not an X25519 public key.
pub fn seal_to_recovery_key<C: OpenMlsCrypto>(
    crypto: &C,
    recovery_public_key: &[u8],
    context: &[u8],
    plaintext: &[u8],
) -> Option<Vec<u8>> {
    seal_with_label(
        crypto,
        RECOVERY_CIPHERSUITE,
        ENCRYPT_LABEL,
        recovery_public_key,
        context,
        plaintext,
    )
}

/// `sealed` opened with the recovery key `entropy` derives, for `context`;
/// `None` when it does not decode exactly or does not open: it was sealed to
/// other words, for another context, or altered.
pub fn open_with_recovery_key<C: OpenMlsCrypto>(
    crypto: &C,
    entropy: &[u8; RECOVERY_ENTROPY_LEN],
    context: &[u8],
    sealed: &[u8],
) -> Result<Option<Vec<u8>>, EngineError> {
    let pair = derive_recovery_key_pair(crypto, entropy)?;
    Ok(open_with_label(
        crypto,
        RECOVERY_CIPHERSUITE,
        ENCRYPT_LABEL,
        &pair.private,
        context,
        sealed,
    ))
}

impl<S: StorageProvider> Engine<S> {
    /// The public half of the recovery key `entropy` derives. Nothing is
    /// stored.
    pub fn recovery_public_key(
        &self,
        entropy: &[u8; RECOVERY_ENTROPY_LEN],
    ) -> Result<Vec<u8>, EngineError> {
        Ok(derive_recovery_key_pair(&self.crypto, entropy)?.public)
    }

    /// See [`seal_to_recovery_key`].
    pub fn seal_to_recovery_key(
        &self,
        recovery_public_key: &[u8],
        context: &[u8],
        plaintext: &[u8],
    ) -> Option<Vec<u8>> {
        seal_to_recovery_key(&self.crypto, recovery_public_key, context, plaintext)
    }

    /// See [`open_with_recovery_key`].
    pub fn open_with_recovery_key(
        &self,
        entropy: &[u8; RECOVERY_ENTROPY_LEN],
        context: &[u8],
        sealed: &[u8],
    ) -> Result<Option<Vec<u8>>, EngineError> {
        open_with_recovery_key(&self.crypto, entropy, context, sealed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history_key::{generate_history_key_pair, seal_history};
    use openmls_rust_crypto::RustCrypto;

    const CONTEXT: &[u8] = b"backup id and index hash";

    #[test]
    fn the_same_entropy_always_derives_the_same_x25519_key() {
        let crypto = RustCrypto::default();
        let first = derive_recovery_key_pair(&crypto, &[7; RECOVERY_ENTROPY_LEN]).unwrap();
        let again = derive_recovery_key_pair(&crypto, &[7; RECOVERY_ENTROPY_LEN]).unwrap();
        let other = derive_recovery_key_pair(&crypto, &[8; RECOVERY_ENTROPY_LEN]).unwrap();
        assert_eq!(first.public.len(), 32);
        assert_eq!(first.public, again.public);
        assert_eq!(first.private.as_ref(), again.private.as_ref());
        assert_ne!(first.public, other.public);
    }

    /// The derivation's test vectors, shared with the spec: all-zero
    /// entropy, whose words are "abandon" eleven times then "about", and
    /// `0x7f` repeated, whose words are "legal winner thank year wave sausage
    /// worth useful legal winner thank yellow". Checked against an independent
    /// implementation of HKDF and RFC 9180's `DeriveKeyPair`.
    #[test]
    fn the_published_vectors_derive() {
        let crypto = RustCrypto::default();
        for (entropy, private, public) in [
            (
                [0; RECOVERY_ENTROPY_LEN],
                "f99da3bd75751479570bd7d7a807bebb49c8da68aed12e813862cccdff5a577d",
                "aed5608fc1960f7992decafb36786d19508dce48e02288785cf24e557d58a368",
            ),
            (
                [0x7f; RECOVERY_ENTROPY_LEN],
                "8570ead0cc10c1ae63c6357959fdb15996475dabe3b781c4ebecdacb2015ef83",
                "9076c238afd9311184e7dda595f7d42f5c73b48bff561e88482c4435d5cb5f10",
            ),
        ] {
            let pair = derive_recovery_key_pair(&crypto, &entropy).unwrap();
            assert_eq!(hex::encode(pair.private.as_ref()), private);
            assert_eq!(hex::encode(&pair.public), public);
        }
    }

    #[test]
    fn a_sealed_value_opens_only_with_its_words_and_context() {
        let crypto = RustCrypto::default();
        let entropy = [3; RECOVERY_ENTROPY_LEN];
        let public = derive_recovery_key_pair(&crypto, &entropy).unwrap().public;
        let sealed = seal_to_recovery_key(&crypto, &public, CONTEXT, b"archive key").unwrap();

        assert_eq!(
            open_with_recovery_key(&crypto, &entropy, CONTEXT, &sealed).unwrap(),
            Some(b"archive key".to_vec())
        );
        assert_eq!(
            open_with_recovery_key(&crypto, &entropy, b"another", &sealed).unwrap(),
            None
        );
        assert_eq!(
            open_with_recovery_key(&crypto, &[4; RECOVERY_ENTROPY_LEN], CONTEXT, &sealed).unwrap(),
            None
        );
        let mut trailing = sealed.clone();
        trailing.push(0);
        assert_eq!(
            open_with_recovery_key(&crypto, &entropy, CONTEXT, &trailing).unwrap(),
            None
        );
    }

    #[test]
    fn a_key_that_is_no_x25519_public_key_seals_nothing() {
        let crypto = RustCrypto::default();
        for bad in [vec![], vec![7; 31], vec![7; 33]] {
            assert_eq!(
                seal_to_recovery_key(&crypto, &bad, CONTEXT, b"archive key"),
                None
            );
        }
    }

    /// A value sealed to the same key and context as history never opens as
    /// a backup value, nor the other way round.
    #[test]
    fn the_label_separates_backups_from_history() {
        let crypto = RustCrypto::default();
        let entropy = [5; RECOVERY_ENTROPY_LEN];
        let public = derive_recovery_key_pair(&crypto, &entropy).unwrap().public;
        let as_history = seal_history(
            &crypto,
            RECOVERY_CIPHERSUITE,
            &public,
            CONTEXT,
            b"archive key",
        )
        .unwrap();
        assert_eq!(
            open_with_recovery_key(&crypto, &entropy, CONTEXT, &as_history).unwrap(),
            None
        );

        let history = generate_history_key_pair(&crypto, RECOVERY_CIPHERSUITE).unwrap();
        let as_backup =
            seal_to_recovery_key(&crypto, &history.public, CONTEXT, b"bundle key").unwrap();
        assert_eq!(
            crate::history_key::open_history(
                &crypto,
                RECOVERY_CIPHERSUITE,
                &history.private,
                CONTEXT,
                &as_backup
            ),
            None
        );
    }
}
