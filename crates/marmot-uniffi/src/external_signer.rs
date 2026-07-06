use std::fmt;
use std::sync::Arc;

use cgka_engine::account_identity_proof::{
    AccountIdentityProofRequest, AccountIdentityProofSigner,
};
use nostr::prelude::JsonUtil;
use nostr::signer::SignerBackend;
use nostr::{Event, NostrSigner, PublicKey, SignerError, UnsignedEvent};

use crate::MarmotKitError;

#[uniffi::export(with_foreign)]
pub trait ExternalAccountSignerFfi: Send + Sync {
    /// Return the signer account public key as hex or npub.
    fn public_key(&self) -> Result<String, MarmotKitError>;

    /// Sign a serialized unsigned Nostr event and return the signed event JSON.
    ///
    /// MDK uses this for normal Nostr publishing, relay auth, push ownership,
    /// Blossom upload auth, and account identity proofs.
    fn sign_event(&self, unsigned_event_json: String) -> Result<String, MarmotKitError>;

    /// NIP-04 encrypt/decrypt support for legacy Nostr surfaces.
    ///
    /// Current MDK protocol flows do not require NIP-04. Clients that cannot
    /// support it should return a clear unsupported signer error.
    fn nip04_encrypt(&self, public_key: String, content: String) -> Result<String, MarmotKitError>;
    fn nip04_decrypt(
        &self,
        public_key: String,
        encrypted_content: String,
    ) -> Result<String, MarmotKitError>;

    /// NIP-44 encrypt/decrypt support for gift-wrap and encrypted app data.
    fn nip44_encrypt(&self, public_key: String, content: String) -> Result<String, MarmotKitError>;
    fn nip44_decrypt(&self, public_key: String, payload: String) -> Result<String, MarmotKitError>;
}

#[derive(Clone)]
pub(crate) struct ExternalAccountSignerAdapter {
    signer: Arc<dyn ExternalAccountSignerFfi>,
}

impl ExternalAccountSignerAdapter {
    pub(crate) fn new(signer: Arc<dyn ExternalAccountSignerFfi>) -> Self {
        Self { signer }
    }
}

impl fmt::Debug for ExternalAccountSignerAdapter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExternalAccountSignerAdapter(..)")
    }
}

impl NostrSigner for ExternalAccountSignerAdapter {
    fn backend(&self) -> SignerBackend<'_> {
        SignerBackend::Custom("external-account-signer".into())
    }

    fn get_public_key(&self) -> nostr::util::BoxedFuture<'_, Result<PublicKey, SignerError>> {
        let signer = self.signer.clone();
        Box::pin(async move {
            let public_key = tokio::task::spawn_blocking(move || signer.public_key())
                .await
                .map_err(signer_error)?
                .map_err(callback_signer_error)?;
            PublicKey::parse(&public_key).map_err(signer_error)
        })
    }

    fn sign_event(
        &self,
        unsigned: UnsignedEvent,
    ) -> nostr::util::BoxedFuture<'_, Result<Event, SignerError>> {
        let signer = self.signer.clone();
        Box::pin(async move {
            let expected_id = unsigned
                .id
                .ok_or_else(|| SignerError::from("unsigned event id was not set"))?;
            let expected_pubkey = unsigned.pubkey;
            let unsigned_json = unsigned.as_json();
            let event_json = tokio::task::spawn_blocking(move || signer.sign_event(unsigned_json))
                .await
                .map_err(signer_error)?
                .map_err(callback_signer_error)?;
            let event = Event::from_json(event_json).map_err(signer_error)?;
            if event.id != expected_id || event.pubkey != expected_pubkey {
                return Err(SignerError::from(
                    "external signer returned a different event than requested",
                ));
            }
            event.verify().map_err(signer_error)?;
            Ok(event)
        })
    }

    fn nip04_encrypt<'a>(
        &'a self,
        public_key: &'a PublicKey,
        content: &'a str,
    ) -> nostr::util::BoxedFuture<'a, Result<String, SignerError>> {
        let signer = self.signer.clone();
        let public_key = public_key.to_hex();
        let content = content.to_owned();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || signer.nip04_encrypt(public_key, content))
                .await
                .map_err(signer_error)?
                .map_err(callback_signer_error)
        })
    }

    fn nip04_decrypt<'a>(
        &'a self,
        public_key: &'a PublicKey,
        encrypted_content: &'a str,
    ) -> nostr::util::BoxedFuture<'a, Result<String, SignerError>> {
        let signer = self.signer.clone();
        let public_key = public_key.to_hex();
        let encrypted_content = encrypted_content.to_owned();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || signer.nip04_decrypt(public_key, encrypted_content))
                .await
                .map_err(signer_error)?
                .map_err(callback_signer_error)
        })
    }

    fn nip44_encrypt<'a>(
        &'a self,
        public_key: &'a PublicKey,
        content: &'a str,
    ) -> nostr::util::BoxedFuture<'a, Result<String, SignerError>> {
        let signer = self.signer.clone();
        let public_key = public_key.to_hex();
        let content = content.to_owned();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || signer.nip44_encrypt(public_key, content))
                .await
                .map_err(signer_error)?
                .map_err(callback_signer_error)
        })
    }

    fn nip44_decrypt<'a>(
        &'a self,
        public_key: &'a PublicKey,
        payload: &'a str,
    ) -> nostr::util::BoxedFuture<'a, Result<String, SignerError>> {
        let signer = self.signer.clone();
        let public_key = public_key.to_hex();
        let payload = payload.to_owned();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || signer.nip44_decrypt(public_key, payload))
                .await
                .map_err(signer_error)?
                .map_err(callback_signer_error)
        })
    }
}

impl AccountIdentityProofSigner for ExternalAccountSignerAdapter {
    fn sign_account_identity_proof(
        &self,
        request: &AccountIdentityProofRequest,
    ) -> Result<[u8; 64], String> {
        let unsigned_event_json = request.proof_event_json()?;
        let signed_event_json = self
            .signer
            .sign_event(unsigned_event_json)
            .map_err(|err| err.to_string())?;
        let signed_event = Event::from_json(signed_event_json).map_err(|err| err.to_string())?;
        request.signature_from_signed_event(signed_event)
    }
}

fn callback_signer_error(error: MarmotKitError) -> SignerError {
    match error {
        MarmotKitError::ExternalSignerRejected => {
            SignerError::from(marmot_app::EXTERNAL_SIGNER_REJECTED)
        }
        other => SignerError::from(other.to_string()),
    }
}

fn signer_error(error: impl ToString) -> SignerError {
    SignerError::from(error.to_string())
}
