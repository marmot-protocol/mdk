use std::fmt;
use std::sync::Arc;

use cgka_engine::account_identity_proof::{
    AccountIdentityProofRequest, AccountIdentityProofSigner,
};
use nostr::prelude::{Event, FinalizeEvent, PublicKey, Signature, UnsignedEvent};
use transport_nostr_peeler::{MarmotNostrSigner, MarmotSignerError, SignerFuture};

pub const EXTERNAL_SIGNER_REJECTED: &str = "external_signer_rejected";

/// Host-provided signer for accounts whose Nostr secret never enters MDK.
///
/// This extends the standard Nostr signer surface with Marmot's MLS
/// account-identity proof signature. The proof signature is produced by signing
/// a canonical unpublished Nostr event, so Amber/NIP-55-style signers can
/// participate without exposing raw digest signing.
pub trait ExternalAccountSigner: MarmotNostrSigner + AccountIdentityProofSigner {}

impl<T> ExternalAccountSigner for T where T: MarmotNostrSigner + AccountIdentityProofSigner {}

#[derive(Clone)]
pub(crate) enum AccountSigner {
    Local(nostr::prelude::Keys),
    External(RegisteredExternalSigner),
}

impl AccountSigner {
    pub(crate) fn as_nostr_signer(&self) -> Arc<dyn MarmotNostrSigner> {
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
    keys: nostr::prelude::Keys,
}

impl AccountIdentityProofSigner for LocalAccountIdentityProofSigner {
    fn sign_account_identity_proof(
        &self,
        request: &AccountIdentityProofRequest,
    ) -> Result<[u8; 64], String> {
        if self.keys.public_key().to_bytes().as_slice() != request.account_identity.as_slice() {
            return Err("request account identity does not match local Nostr key".into());
        }
        let event = request
            .proof_event()
            .and_then(|event| event.finalize(&self.keys).map_err(|err| err.to_string()))?;
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

impl MarmotNostrSigner for RegisteredExternalSigner {
    fn get_public_key(&self) -> SignerFuture<'_, Result<PublicKey, MarmotSignerError>> {
        let public_key = self.public_key;
        Box::pin(async move { Ok(public_key) })
    }

    fn sign_event(
        &self,
        unsigned: UnsignedEvent,
    ) -> SignerFuture<'_, Result<Event, MarmotSignerError>> {
        let public_key = self.public_key;
        let signer = self.signer.clone();
        Box::pin(async move {
            let expected_id = unsigned
                .id
                .ok_or_else(|| MarmotSignerError::from("unsigned event id was not set"))?;
            let event = signer.sign_event(unsigned).await?;
            if event.pubkey != public_key || event.id != expected_id {
                return Err(MarmotSignerError::from(
                    "external signer returned a different event than requested",
                ));
            }
            event
                .verify()
                .map_err(|err| MarmotSignerError::from(err.to_string()))?;
            Ok(event)
        })
    }

    fn nip04_encrypt<'a>(
        &'a self,
        public_key: &'a PublicKey,
        content: &'a str,
    ) -> SignerFuture<'a, Result<String, MarmotSignerError>> {
        self.signer.nip04_encrypt(public_key, content)
    }

    fn nip04_decrypt<'a>(
        &'a self,
        public_key: &'a PublicKey,
        encrypted_content: &'a str,
    ) -> SignerFuture<'a, Result<String, MarmotSignerError>> {
        self.signer.nip04_decrypt(public_key, encrypted_content)
    }

    fn nip44_encrypt<'a>(
        &'a self,
        public_key: &'a PublicKey,
        content: &'a str,
    ) -> SignerFuture<'a, Result<String, MarmotSignerError>> {
        self.signer.nip44_encrypt(public_key, content)
    }

    fn nip44_decrypt<'a>(
        &'a self,
        public_key: &'a PublicKey,
        payload: &'a str,
    ) -> SignerFuture<'a, Result<String, MarmotSignerError>> {
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
    use nostr::prelude::FinalizeUnsignedEvent;

    #[derive(Clone, Debug)]
    struct TestExternalSigner {
        keys: nostr::prelude::Keys,
    }

    impl MarmotNostrSigner for TestExternalSigner {
        fn get_public_key(&self) -> SignerFuture<'_, Result<PublicKey, MarmotSignerError>> {
            MarmotNostrSigner::get_public_key(&self.keys)
        }

        fn sign_event(
            &self,
            unsigned: UnsignedEvent,
        ) -> SignerFuture<'_, Result<Event, MarmotSignerError>> {
            MarmotNostrSigner::sign_event(&self.keys, unsigned)
        }

        fn nip04_encrypt<'a>(
            &'a self,
            public_key: &'a PublicKey,
            content: &'a str,
        ) -> SignerFuture<'a, Result<String, MarmotSignerError>> {
            MarmotNostrSigner::nip04_encrypt(&self.keys, public_key, content)
        }

        fn nip04_decrypt<'a>(
            &'a self,
            public_key: &'a PublicKey,
            encrypted_content: &'a str,
        ) -> SignerFuture<'a, Result<String, MarmotSignerError>> {
            MarmotNostrSigner::nip04_decrypt(&self.keys, public_key, encrypted_content)
        }

        fn nip44_encrypt<'a>(
            &'a self,
            public_key: &'a PublicKey,
            content: &'a str,
        ) -> SignerFuture<'a, Result<String, MarmotSignerError>> {
            MarmotNostrSigner::nip44_encrypt(&self.keys, public_key, content)
        }

        fn nip44_decrypt<'a>(
            &'a self,
            public_key: &'a PublicKey,
            payload: &'a str,
        ) -> SignerFuture<'a, Result<String, MarmotSignerError>> {
            MarmotNostrSigner::nip44_decrypt(&self.keys, public_key, payload)
        }
    }

    impl AccountIdentityProofSigner for TestExternalSigner {
        fn sign_account_identity_proof(
            &self,
            request: &AccountIdentityProofRequest,
        ) -> Result<[u8; 64], String> {
            let event = request
                .proof_event()
                .and_then(|event| event.finalize(&self.keys).map_err(|err| err.to_string()))?;
            request.signature_from_signed_event(event)
        }
    }

    #[tokio::test]
    async fn account_signer_uses_registered_public_key_for_external_accounts() {
        use nostr::prelude::{EventBuilder, Kind};

        let registered_keys = nostr::prelude::Keys::generate();
        let stale_callback_keys = nostr::prelude::Keys::generate();
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

        let unsigned = EventBuilder::new(Kind::TextNote, "hello")
            .finalize_unsigned(registered_keys.public_key());
        assert!(
            signer.sign_event(unsigned).await.is_err(),
            "registered external signer must reject events signed by a stale callback key"
        );
    }
}
