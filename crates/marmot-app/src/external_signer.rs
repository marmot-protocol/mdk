use std::fmt;
use std::sync::Arc;

use cgka_engine::account_identity_proof::{
    AccountIdentityProofRequest, AccountIdentityProofSigner,
};
use nostr::signer::SignerBackend;
use nostr::{
    Event, NostrSigner, PublicKey, SignerError, UnsignedEvent, secp256k1::schnorr::Signature,
};

pub const EXTERNAL_SIGNER_REJECTED: &str = "external_signer_rejected";

/// Host-provided signer for accounts whose Nostr secret never enters MDK.
///
/// This extends the standard Nostr signer surface with Marmot's MLS
/// account-identity proof signature. The proof signature is produced by signing
/// a canonical unpublished Nostr event, so Amber/NIP-55-style signers can
/// participate without exposing raw digest signing.
pub trait ExternalAccountSigner: NostrSigner + AccountIdentityProofSigner {}

impl<T> ExternalAccountSigner for T where T: NostrSigner + AccountIdentityProofSigner {}

#[derive(Clone)]
pub(crate) enum AccountSigner {
    Local(nostr::Keys),
    External(RegisteredExternalSigner),
}

impl AccountSigner {
    pub(crate) fn as_nostr_signer(&self) -> Arc<dyn NostrSigner> {
        match self {
            Self::Local(keys) => Arc::new(keys.clone()),
            Self::External(signer) => Arc::new(signer.clone()),
        }
    }

    pub(crate) fn as_proof_signer(&self) -> Arc<dyn AccountIdentityProofSigner> {
        match self {
            Self::Local(keys) => Arc::new(LocalAccountIdentityProofSigner { keys: keys.clone() }),
            Self::External(signer) => Arc::new(signer.clone()),
        }
    }
}

impl fmt::Debug for AccountSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local(_) => f.write_str("AccountSigner::Local(..)"),
            Self::External(_) => f.write_str("AccountSigner::External(..)"),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct LocalAccountIdentityProofSigner {
    keys: nostr::Keys,
}

impl AccountIdentityProofSigner for LocalAccountIdentityProofSigner {
    fn sign_account_identity_proof(
        &self,
        request: &AccountIdentityProofRequest,
    ) -> Result<[u8; 64], String> {
        if self.keys.public_key().to_bytes().as_slice() != request.account_identity.as_slice() {
            return Err("request account identity does not match local Nostr key".into());
        }
        let event = request.proof_event().and_then(|event| {
            event
                .sign_with_keys(&self.keys)
                .map_err(|err| err.to_string())
        })?;
        request.signature_from_signed_event(event)
    }
}

#[derive(Clone)]
pub(crate) struct RegisteredExternalSigner {
    public_key: PublicKey,
    signer: Arc<dyn ExternalAccountSigner>,
}

impl RegisteredExternalSigner {
    pub(crate) fn new(public_key: PublicKey, signer: Arc<dyn ExternalAccountSigner>) -> Self {
        Self { public_key, signer }
    }

    pub(crate) fn account_signer(&self) -> AccountSigner {
        AccountSigner::External(self.clone())
    }
}

impl fmt::Debug for RegisteredExternalSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegisteredExternalSigner")
            .field("public_key", &self.public_key.to_hex())
            .finish_non_exhaustive()
    }
}

impl NostrSigner for RegisteredExternalSigner {
    fn backend(&self) -> SignerBackend<'_> {
        self.signer.backend()
    }

    fn get_public_key(&self) -> nostr::util::BoxedFuture<'_, Result<PublicKey, SignerError>> {
        let public_key = self.public_key;
        Box::pin(async move { Ok(public_key) })
    }

    fn sign_event(
        &self,
        unsigned: UnsignedEvent,
    ) -> nostr::util::BoxedFuture<'_, Result<Event, SignerError>> {
        let public_key = self.public_key;
        let signer = self.signer.clone();
        Box::pin(async move {
            let expected_id = unsigned
                .id
                .ok_or_else(|| SignerError::from("unsigned event id was not set"))?;
            let event = signer.sign_event(unsigned).await?;
            if event.pubkey != public_key || event.id != expected_id {
                return Err(SignerError::from(
                    "external signer returned a different event than requested",
                ));
            }
            event
                .verify()
                .map_err(|err| SignerError::from(err.to_string()))?;
            Ok(event)
        })
    }

    fn nip04_encrypt<'a>(
        &'a self,
        public_key: &'a PublicKey,
        content: &'a str,
    ) -> nostr::util::BoxedFuture<'a, Result<String, SignerError>> {
        self.signer.nip04_encrypt(public_key, content)
    }

    fn nip04_decrypt<'a>(
        &'a self,
        public_key: &'a PublicKey,
        encrypted_content: &'a str,
    ) -> nostr::util::BoxedFuture<'a, Result<String, SignerError>> {
        self.signer.nip04_decrypt(public_key, encrypted_content)
    }

    fn nip44_encrypt<'a>(
        &'a self,
        public_key: &'a PublicKey,
        content: &'a str,
    ) -> nostr::util::BoxedFuture<'a, Result<String, SignerError>> {
        self.signer.nip44_encrypt(public_key, content)
    }

    fn nip44_decrypt<'a>(
        &'a self,
        public_key: &'a PublicKey,
        payload: &'a str,
    ) -> nostr::util::BoxedFuture<'a, Result<String, SignerError>> {
        self.signer.nip44_decrypt(public_key, payload)
    }
}

impl AccountIdentityProofSigner for RegisteredExternalSigner {
    fn sign_account_identity_proof(
        &self,
        request: &AccountIdentityProofRequest,
    ) -> Result<[u8; 64], String> {
        if self.public_key.to_bytes().as_slice() != request.account_identity.as_slice() {
            return Err(
                "request account identity does not match registered external signer".into(),
            );
        }
        let signature = self.signer.sign_account_identity_proof(request)?;
        let proof_event = request.proof_event()?;
        let signature_value = Signature::from_slice(&signature).map_err(|err| err.to_string())?;
        proof_event
            .add_signature(signature_value)
            .map_err(|err| err.to_string())?;
        Ok(signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Debug)]
    struct TestExternalSigner {
        keys: nostr::Keys,
    }

    impl NostrSigner for TestExternalSigner {
        fn backend(&self) -> SignerBackend<'_> {
            self.keys.backend()
        }

        fn get_public_key(&self) -> nostr::util::BoxedFuture<'_, Result<PublicKey, SignerError>> {
            self.keys.get_public_key()
        }

        fn sign_event(
            &self,
            unsigned: UnsignedEvent,
        ) -> nostr::util::BoxedFuture<'_, Result<Event, SignerError>> {
            self.keys.sign_event(unsigned)
        }

        fn nip04_encrypt<'a>(
            &'a self,
            public_key: &'a PublicKey,
            content: &'a str,
        ) -> nostr::util::BoxedFuture<'a, Result<String, SignerError>> {
            self.keys.nip04_encrypt(public_key, content)
        }

        fn nip04_decrypt<'a>(
            &'a self,
            public_key: &'a PublicKey,
            encrypted_content: &'a str,
        ) -> nostr::util::BoxedFuture<'a, Result<String, SignerError>> {
            self.keys.nip04_decrypt(public_key, encrypted_content)
        }

        fn nip44_encrypt<'a>(
            &'a self,
            public_key: &'a PublicKey,
            content: &'a str,
        ) -> nostr::util::BoxedFuture<'a, Result<String, SignerError>> {
            self.keys.nip44_encrypt(public_key, content)
        }

        fn nip44_decrypt<'a>(
            &'a self,
            public_key: &'a PublicKey,
            payload: &'a str,
        ) -> nostr::util::BoxedFuture<'a, Result<String, SignerError>> {
            self.keys.nip44_decrypt(public_key, payload)
        }
    }

    impl AccountIdentityProofSigner for TestExternalSigner {
        fn sign_account_identity_proof(
            &self,
            request: &AccountIdentityProofRequest,
        ) -> Result<[u8; 64], String> {
            let event = request.proof_event().and_then(|event| {
                event
                    .sign_with_keys(&self.keys)
                    .map_err(|err| err.to_string())
            })?;
            request.signature_from_signed_event(event)
        }
    }

    #[tokio::test]
    async fn account_signer_uses_registered_public_key_for_external_accounts() {
        use nostr::{EventBuilder, Kind};

        let registered_keys = nostr::Keys::generate();
        let stale_callback_keys = nostr::Keys::generate();
        let registered = RegisteredExternalSigner::new(
            registered_keys.public_key(),
            Arc::new(TestExternalSigner {
                keys: stale_callback_keys,
            }),
        );

        let signer = registered.account_signer().as_nostr_signer();

        assert_eq!(
            signer.get_public_key().await.unwrap(),
            registered_keys.public_key()
        );

        let unsigned =
            EventBuilder::new(Kind::TextNote, "hello").build(registered_keys.public_key());
        assert!(
            signer.sign_event(unsigned).await.is_err(),
            "registered external signer must reject events signed by a stale callback key"
        );
    }
}
