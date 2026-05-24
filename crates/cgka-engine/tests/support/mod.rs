use std::sync::Arc;

use cgka_engine::account_identity_proof::{
    AccountIdentityProofRequest, AccountIdentityProofSigner,
};
use k256::schnorr::{SigningKey, signature::hazmat::PrehashSigner};
use sha2::{Digest, Sha256};

pub fn proof_signer(seed: &[u8]) -> Arc<dyn AccountIdentityProofSigner> {
    Arc::new(TestAccountIdentityProofSigner(signing_key(seed)))
}

fn signing_key(seed: &[u8]) -> SigningKey {
    let mut counter = 0u64;
    loop {
        let mut material = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(b"cgka-engine-test-identity-v1");
        hasher.update(seed);
        hasher.update(counter.to_be_bytes());
        material.copy_from_slice(&hasher.finalize());
        if let Ok(sk) = SigningKey::from_bytes(&material) {
            return sk;
        }
        counter += 1;
    }
}

struct TestAccountIdentityProofSigner(SigningKey);

impl AccountIdentityProofSigner for TestAccountIdentityProofSigner {
    fn sign_account_identity_proof(
        &self,
        request: &AccountIdentityProofRequest,
    ) -> Result<[u8; 64], String> {
        if self.0.verifying_key().to_bytes().as_slice() != request.account_identity.as_slice() {
            return Err("request account identity does not match test key".into());
        }
        let signature = self
            .0
            .sign_prehash(&request.signing_digest())
            .map_err(|e| e.to_string())?;
        Ok(signature.to_bytes())
    }
}
