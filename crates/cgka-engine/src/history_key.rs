//! History keys (mdk#2628 4.1, D34 item 2): this device's HPKE key pair for
//! account sync, and sealing to and opening with it.
//!
//! A device's history key is an HPKE key pair under its device group's
//! ciphersuite. MDK builds every group under `DEFAULT_CIPHERSUITE`
//! (`0x0001`), so the key is X25519. The private half stays in this device's
//! account-device storage next to its MLS signer
//! ([`cgka_traits::storage::AccountDeviceHistoryKeyStorage`]); the public half
//! goes in this device's own roster entry (`history_key`), so siblings can seal
//! chat history to it. A device has one key and never rotates it.
//!
//! Sealing is MLS's `EncryptWithLabel` (RFC 9420, section 5.1.3) with the label
//! "Marmot History": HPKE base mode, with the label and the caller's context
//! as `info` and an empty AAD. The context says what the sealed value is for,
//! so a value sealed for one purpose never opens for another. The sealed form
//! is MLS's `HPKECiphertext`. A value that does not decode or open, or a
//! recipient key that is not one of the ciphersuite's public keys, gives
//! `None`, never an error: the roster may hold any bytes as a history key, and
//! a bad one only means that device gets no history.

use crate::engine::Engine;
use cgka_traits::app_components::encode_component_vectors;
use cgka_traits::error::EngineError;
use cgka_traits::storage::{AccountDeviceHistoryKey, StorageProvider};
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::random::OpenMlsRand;
use openmls_traits::types::{Ciphersuite, HpkeCiphertext, HpkeKeyPair, HpkePrivateKey};
use tls_codec::{Deserialize as _, Serialize as _};

/// `EncryptWithLabel`'s label for "Marmot History" (RFC 9420, section 5.1.3).
const ENCRYPT_LABEL: &[u8] = b"MLS 1.0 Marmot History";

/// A fresh history key pair under `ciphersuite`, derived from random input
/// keying material the way MLS derives leaf encryption keys.
pub fn generate_history_key_pair<C: OpenMlsCrypto + OpenMlsRand>(
    crypto: &C,
    ciphersuite: Ciphersuite,
) -> Result<HpkeKeyPair, EngineError> {
    // Held as a private key so it is zeroized on drop.
    let ikm = HpkePrivateKey::from(
        crypto
            .random_vec(ciphersuite.hash_length())
            .map_err(|e| EngineError::Backend(format!("history key input: {e:?}")))?,
    );
    crypto
        .derive_hpke_keypair(ciphersuite.hpke_config(), &ikm)
        .map_err(|e| EngineError::Backend(format!("history key derivation: {e:?}")))
}

/// `plaintext` sealed to `recipient_public_key` for `context`, or `None`
/// when the key is not one HPKE under `ciphersuite` can seal to.
pub fn seal_history<C: OpenMlsCrypto>(
    crypto: &C,
    ciphersuite: Ciphersuite,
    recipient_public_key: &[u8],
    context: &[u8],
    plaintext: &[u8],
) -> Option<Vec<u8>> {
    seal_with_label(
        crypto,
        ciphersuite,
        ENCRYPT_LABEL,
        recipient_public_key,
        context,
        plaintext,
    )
}

/// MLS's `EncryptWithLabel` under `label` (already prefixed "MLS 1.0 "),
/// as [`seal_history`] describes, for any of Marmot's sealing labels.
pub(crate) fn seal_with_label<C: OpenMlsCrypto>(
    crypto: &C,
    ciphersuite: Ciphersuite,
    label: &[u8],
    recipient_public_key: &[u8],
    context: &[u8],
    plaintext: &[u8],
) -> Option<Vec<u8>> {
    let sealed = crypto
        .hpke_seal(
            ciphersuite.hpke_config(),
            recipient_public_key,
            &encrypt_context(label, context),
            &[],
            plaintext,
        )
        .ok()?;
    sealed.tls_serialize_detached().ok()
}

/// `sealed` opened with `private_key` for `context`, or `None` when it does
/// not decode exactly or does not open: it was sealed to another key, for
/// another context, or altered.
pub fn open_history<C: OpenMlsCrypto>(
    crypto: &C,
    ciphersuite: Ciphersuite,
    private_key: &[u8],
    context: &[u8],
    sealed: &[u8],
) -> Option<Vec<u8>> {
    open_with_label(
        crypto,
        ciphersuite,
        ENCRYPT_LABEL,
        private_key,
        context,
        sealed,
    )
}

/// MLS's `DecryptWithLabel` under `label`, as [`open_history`] describes.
pub(crate) fn open_with_label<C: OpenMlsCrypto>(
    crypto: &C,
    ciphersuite: Ciphersuite,
    label: &[u8],
    private_key: &[u8],
    context: &[u8],
    sealed: &[u8],
) -> Option<Vec<u8>> {
    let mut cursor = sealed;
    let ciphertext = HpkeCiphertext::tls_deserialize(&mut cursor).ok()?;
    if !cursor.is_empty() {
        return None;
    }
    crypto
        .hpke_open(
            ciphersuite.hpke_config(),
            &ciphertext,
            private_key,
            &encrypt_context(label, context),
            &[],
        )
        .ok()
}

/// MLS's `EncryptContext`: the label, then the context, each a vector.
fn encrypt_context(label: &[u8], context: &[u8]) -> Vec<u8> {
    encode_component_vectors(&[label, context])
}

impl<S: StorageProvider> Engine<S> {
    /// The public half of this device's history key. The first call
    /// generates the key pair and stores it before returning, so the key a
    /// roster entry is given is always one this device can open with.
    pub fn history_public_key(&self) -> Result<Vec<u8>, EngineError> {
        if let Some(key) = self.stored_history_key()? {
            return Ok(key.public_key);
        }
        let pair = generate_history_key_pair(&self.crypto, self.ciphersuite)?;
        let stored =
            self.storage
                .put_account_device_history_key_if_absent(&AccountDeviceHistoryKey {
                    marmot_identity: self.identity.self_id().clone(),
                    ciphersuite: u16::from(self.ciphersuite),
                    public_key: pair.public,
                    private_key: pair.private.to_vec().into(),
                })?;
        self.check_history_key_ciphersuite(&stored)?;
        Ok(stored.public_key)
    }

    /// `plaintext` sealed to a sibling's history key for `context`, or
    /// `None` when that key is not one this device can seal to.
    pub fn seal_history(
        &self,
        recipient_public_key: &[u8],
        context: &[u8],
        plaintext: &[u8],
    ) -> Option<Vec<u8>> {
        seal_history(
            &self.crypto,
            self.ciphersuite,
            recipient_public_key,
            context,
            plaintext,
        )
    }

    /// `sealed` opened with this device's history key for `context`, or
    /// `None` when it does not open or this device has no history key yet.
    pub fn open_history(
        &self,
        context: &[u8],
        sealed: &[u8],
    ) -> Result<Option<Vec<u8>>, EngineError> {
        let Some(key) = self.stored_history_key()? else {
            return Ok(None);
        };
        Ok(open_history(
            &self.crypto,
            self.ciphersuite,
            &key.private_key,
            context,
            sealed,
        ))
    }

    fn stored_history_key(&self) -> Result<Option<AccountDeviceHistoryKey>, EngineError> {
        let Some(key) = self
            .storage
            .account_device_history_key(self.identity.self_id())?
        else {
            return Ok(None);
        };
        self.check_history_key_ciphersuite(&key)?;
        Ok(Some(key))
    }

    fn check_history_key_ciphersuite(
        &self,
        key: &AccountDeviceHistoryKey,
    ) -> Result<(), EngineError> {
        if key.ciphersuite == u16::from(self.ciphersuite) {
            Ok(())
        } else {
            Err(EngineError::UnsupportedCiphersuite {
                got: key.ciphersuite,
                required: u16::from(self.ciphersuite),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::DEFAULT_CIPHERSUITE;
    use openmls_rust_crypto::RustCrypto;

    const CONTEXT: &[u8] = b"chat, slots and offer";

    fn key_pair(crypto: &RustCrypto) -> HpkeKeyPair {
        generate_history_key_pair(crypto, DEFAULT_CIPHERSUITE).unwrap()
    }

    #[test]
    fn a_sealed_value_opens_only_with_its_key_and_context() {
        let crypto = RustCrypto::default();
        let pair = key_pair(&crypto);
        assert_eq!(pair.public.len(), 32);
        let sealed = seal_history(
            &crypto,
            DEFAULT_CIPHERSUITE,
            &pair.public,
            CONTEXT,
            b"bundle",
        )
        .unwrap();

        assert_eq!(
            open_history(
                &crypto,
                DEFAULT_CIPHERSUITE,
                &pair.private,
                CONTEXT,
                &sealed
            ),
            Some(b"bundle".to_vec())
        );
        assert_eq!(
            open_history(
                &crypto,
                DEFAULT_CIPHERSUITE,
                &pair.private,
                b"another",
                &sealed
            ),
            None
        );
        let other = key_pair(&crypto);
        assert_eq!(
            open_history(
                &crypto,
                DEFAULT_CIPHERSUITE,
                &other.private,
                CONTEXT,
                &sealed
            ),
            None
        );
    }

    #[test]
    fn a_sealed_value_is_mls_hpke_ciphertext_and_opens_only_exactly() {
        let crypto = RustCrypto::default();
        let pair = key_pair(&crypto);
        let sealed = seal_history(
            &crypto,
            DEFAULT_CIPHERSUITE,
            &pair.public,
            CONTEXT,
            b"bundle",
        )
        .unwrap();
        // kem_output<V> (32 bytes) then ciphertext<V> (6 + 16 bytes).
        assert_eq!(sealed.len(), 1 + 32 + 1 + 6 + 16);
        assert_eq!(sealed[0], 32);

        let mut trailing = sealed.clone();
        trailing.push(0);
        assert_eq!(
            open_history(
                &crypto,
                DEFAULT_CIPHERSUITE,
                &pair.private,
                CONTEXT,
                &trailing
            ),
            None
        );
        let mut altered = sealed.clone();
        *altered.last_mut().unwrap() ^= 1;
        assert_eq!(
            open_history(
                &crypto,
                DEFAULT_CIPHERSUITE,
                &pair.private,
                CONTEXT,
                &altered
            ),
            None
        );
        assert_eq!(
            open_history(
                &crypto,
                DEFAULT_CIPHERSUITE,
                &pair.private,
                CONTEXT,
                &sealed[..10]
            ),
            None
        );
    }

    #[test]
    fn a_key_that_is_no_public_key_seals_nothing() {
        let crypto = RustCrypto::default();
        for bad in [vec![], vec![7; 31], vec![7; 33]] {
            assert_eq!(
                seal_history(&crypto, DEFAULT_CIPHERSUITE, &bad, CONTEXT, b"bundle"),
                None
            );
        }
    }

    #[test]
    fn the_label_separates_history_from_other_mls_encryption() {
        let crypto = RustCrypto::default();
        let pair = key_pair(&crypto);
        // The same key and context under MLS's own Welcome label.
        let welcome_info = encode_component_vectors(&[b"MLS 1.0 Welcome", CONTEXT]);
        let sealed = crypto
            .hpke_seal(
                DEFAULT_CIPHERSUITE.hpke_config(),
                &pair.public,
                &welcome_info,
                &[],
                b"bundle",
            )
            .unwrap()
            .tls_serialize_detached()
            .unwrap();
        assert_eq!(
            open_history(
                &crypto,
                DEFAULT_CIPHERSUITE,
                &pair.private,
                CONTEXT,
                &sealed
            ),
            None
        );
    }
}
