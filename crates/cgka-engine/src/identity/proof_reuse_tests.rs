use super::*;
use crate::account_identity_proof::{AccountIdentityProofRequest, AccountIdentityProofSigner};
use cgka_traits::storage::AccountDeviceSignerStorage;
use nostr::prelude::{FinalizeEvent, Keys};
use std::sync::Mutex;
use storage_sqlite::{SqlCipherKey, SqliteAccountStorage};

const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

struct Signer {
    keys: Keys,
    requests: Mutex<Vec<AccountIdentityProofRequest>>,
    reject: bool,
}

impl Signer {
    fn new() -> Self {
        Self {
            keys: Keys::generate(),
            requests: Mutex::new(Vec::new()),
            reject: false,
        }
    }
    fn identity(&self) -> Vec<u8> {
        self.keys.public_key().to_bytes().to_vec()
    }
    fn open(&self, store: &SqliteAccountStorage) -> Result<Identity, String> {
        Identity::load_or_generate(
            SUITE,
            self.identity(),
            store,
            ProtocolProfile::Current,
            self,
        )
    }
}

impl AccountIdentityProofSigner for Signer {
    fn sign_account_identity_proof(
        &self,
        request: &AccountIdentityProofRequest,
    ) -> Result<[u8; 64], String> {
        self.requests.lock().unwrap().push(request.clone());
        if self.reject {
            return Err("cancelled".into());
        }
        Ok(request
            .proof_event()?
            .finalize(&self.keys)
            .map_err(|e| e.to_string())?
            .sig
            .to_bytes())
    }
}

fn component(identity: &Identity) -> &[u8] {
    match &identity.account_identity_proof {
        crate::account_identity_proof::AccountIdentityProofMaterial::CurrentComponent(raw) => raw,
        _ => panic!("expected current proof"),
    }
}

#[test]
fn encrypted_reopen_reuses_identical_proof_without_calling_external_signer() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("account.sqlite");
    let key = SqlCipherKey::new("proof reuse test").unwrap();
    let signer = Signer::new();
    let (proof, mls_key) = {
        let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        let identity = signer.open(&store).unwrap();
        let result = (
            component(&identity).to_vec(),
            identity.signer.to_public_vec(),
        );
        drop(identity);
        store.close().unwrap();
        result
    };
    assert_eq!(signer.requests.lock().unwrap().len(), 1);
    let rejecting = Signer {
        reject: true,
        ..signer
    };
    let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let identity = rejecting.open(&reopened).unwrap();
    assert_eq!(component(&identity), proof);
    assert_eq!(identity.signer.to_public_vec(), mls_key);
    assert_eq!(rejecting.requests.lock().unwrap().len(), 1);
}

#[test]
fn old_proof_keeps_original_timestamp_and_new_proof_uses_unix_seconds() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let signer = Signer::new();
    let before = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let identity = signer.open(&store).unwrap();
    let after = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let request = signer.requests.lock().unwrap()[0].clone();
    assert!((before..=after).contains(&request.created_at));
    let old = crate::account_identity_proof::account_identity_proof_component(
        &signer.identity(),
        &identity.signer.to_public_vec(),
        SUITE,
        SUITE.signature_algorithm(),
        1,
        &signer,
    )
    .unwrap();
    let mut binding = store
        .account_device_signer(identity.self_id())
        .unwrap()
        .unwrap();
    binding.account_identity_proof = Some(old.clone());
    store.put_account_device_signer(&binding).unwrap();
    let count = signer.requests.lock().unwrap().len();
    assert_eq!(component(&signer.open(&store).unwrap()), old);
    assert_eq!(signer.requests.lock().unwrap().len(), count);
}

#[test]
fn missing_or_invalid_stored_proof_requires_one_successful_acquisition() {
    for mode in 0..5 {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let signer = Signer::new();
        let identity = signer.open(&store).unwrap();
        let mut binding = store
            .account_device_signer(identity.self_id())
            .unwrap()
            .unwrap();
        binding.account_identity_proof = match mode {
            0 => None,
            1 => Some(vec![0; 103]),
            2 => {
                let mut raw = component(&identity).to_vec();
                raw[40] ^= 1;
                Some(raw)
            }
            3 => {
                let other = Signer::new();
                Some(
                    component(
                        &other
                            .open(&SqliteAccountStorage::in_memory().unwrap())
                            .unwrap(),
                    )
                    .to_vec(),
                )
            }
            _ => Some(
                crate::account_identity_proof::account_identity_proof_component(
                    &signer.identity(),
                    &[7; 32],
                    SUITE,
                    SUITE.signature_algorithm(),
                    1,
                    &signer,
                )
                .unwrap(),
            ),
        };
        store.put_account_device_signer(&binding).unwrap();
        let count = signer.requests.lock().unwrap().len();
        let repaired = signer.open(&store).unwrap();
        assert_eq!(signer.requests.lock().unwrap().len(), count + 1);
        assert_eq!(
            repaired.signer.to_public_vec(),
            identity.signer.to_public_vec()
        );
        assert_eq!(
            component(&signer.open(&store).unwrap()),
            component(&repaired)
        );
        assert_eq!(signer.requests.lock().unwrap().len(), count + 1);
    }
}

#[test]
fn cancelled_acquisition_preserves_key_and_retry_persists_proof() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let mut signer = Signer {
        reject: true,
        ..Signer::new()
    };
    assert!(signer.open(&store).err().unwrap().contains("cancelled"));
    let id = MemberId::new(signer.identity());
    let original = store.account_device_signer(&id).unwrap().unwrap();
    assert_eq!(original.account_identity_proof, None);
    signer.reject = false;
    let identity = signer.open(&store).unwrap();
    assert_eq!(
        identity.signer.to_public_vec(),
        original.mls_signature_public_key
    );
    signer.reject = true;
    assert!(signer.open(&store).is_ok());
    assert_eq!(signer.requests.lock().unwrap().len(), 2);
}

#[test]
fn current_and_legacy_proof_domains_remain_separate() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let signer = Signer::new();
    let current = signer.open(&store).unwrap();
    let legacy = Identity::load_or_generate(
        SUITE,
        signer.identity(),
        &store,
        ProtocolProfile::Legacy,
        &signer,
    )
    .unwrap();
    assert_eq!(legacy.protocol_profile(), ProtocolProfile::Legacy);
    assert_eq!(signer.requests.lock().unwrap()[1].created_at, 0);
    assert_eq!(
        component(&signer.open(&store).unwrap()),
        component(&current)
    );
    assert_eq!(signer.requests.lock().unwrap().len(), 2);
}

#[test]
fn invalid_new_signature_is_never_persisted_or_returned() {
    struct InvalidSigner;
    impl AccountIdentityProofSigner for InvalidSigner {
        fn sign_account_identity_proof(
            &self,
            _request: &AccountIdentityProofRequest,
        ) -> Result<[u8; 64], String> {
            Ok([0; 64])
        }
    }
    let store = SqliteAccountStorage::in_memory().unwrap();
    let identity = Signer::new().identity();
    assert!(
        Identity::load_or_generate(
            SUITE,
            identity.clone(),
            &store,
            ProtocolProfile::Current,
            &InvalidSigner,
        )
        .is_err()
    );
    let binding = store
        .account_device_signer(&MemberId::new(identity))
        .unwrap()
        .unwrap();
    assert_eq!(binding.account_identity_proof, None);
}

#[test]
fn failed_proof_persistence_reopens_with_the_same_key_and_retries_acquisition() {
    struct ClosingSigner<'a> {
        inner: &'a Signer,
        store: &'a SqliteAccountStorage,
    }
    impl AccountIdentityProofSigner for ClosingSigner<'_> {
        fn sign_account_identity_proof(
            &self,
            request: &AccountIdentityProofRequest,
        ) -> Result<[u8; 64], String> {
            let signature = self.inner.sign_account_identity_proof(request)?;
            self.store.close().map_err(|e| e.to_string())?;
            Ok(signature)
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("account.sqlite");
    let key = SqlCipherKey::new("proof persistence failure test").unwrap();
    let signer = Signer::new();
    {
        let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        assert!(
            Identity::load_or_generate(
                SUITE,
                signer.identity(),
                &store,
                ProtocolProfile::Current,
                &ClosingSigner {
                    inner: &signer,
                    store: &store
                },
            )
            .is_err()
        );
    }
    let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let id = MemberId::new(signer.identity());
    let original = reopened.account_device_signer(&id).unwrap().unwrap();
    assert_eq!(original.account_identity_proof, None);
    let identity = signer.open(&reopened).unwrap();
    assert_eq!(
        identity.signer.to_public_vec(),
        original.mls_signature_public_key
    );
    assert_eq!(signer.requests.lock().unwrap().len(), 2);
    assert!(
        reopened
            .account_device_signer(&id)
            .unwrap()
            .unwrap()
            .account_identity_proof
            .is_some()
    );
}

#[test]
fn stored_component_verification_binds_suite_scheme_key_and_account() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let signer = Signer::new();
    let identity = signer.open(&store).unwrap();
    let raw = component(&identity);
    let verify = crate::account_identity_proof::validate_current_proof_for_key;
    assert!(
        verify(
            raw,
            &signer.identity(),
            &identity.signer.to_public_vec(),
            SUITE
        )
        .is_ok()
    );
    assert!(
        verify(
            raw,
            &Signer::new().identity(),
            &identity.signer.to_public_vec(),
            SUITE
        )
        .is_err()
    );
    assert!(verify(raw, &signer.identity(), &[7; 32], SUITE).is_err());
    // Same Ed25519 scheme, distinct ciphersuite is still a different binding.
    assert!(
        verify(
            raw,
            &signer.identity(),
            &identity.signer.to_public_vec(),
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
        )
        .is_err()
    );
    // A different signature scheme also changes the signed request.
    assert!(
        verify(
            raw,
            &signer.identity(),
            &identity.signer.to_public_vec(),
            Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
        )
        .is_err()
    );
}
