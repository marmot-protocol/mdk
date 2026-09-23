//! Marmot's account signer boundary across the rust-nostr 0.45 trait split.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use nostr::prelude::{
    AsyncGetPublicKey, AsyncNip04, AsyncNip44, AsyncSignEvent, Event, Keys, Nip04, Nip44,
    PublicKey, SignEvent, UnsignedEvent,
};

pub type SignerFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug)]
pub struct MarmotSignerError(String);

impl MarmotSignerError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for MarmotSignerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for MarmotSignerError {}

impl From<&str> for MarmotSignerError {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for MarmotSignerError {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

/// Object-safe account signer interface retained by MDK's engine, media and
/// binding layers. SDK authentication receives a fixed clone of this signer
/// when its account client is constructed; callers never mutate a client key.
pub trait MarmotNostrSigner: fmt::Debug + Send + Sync {
    fn get_public_key(&self) -> SignerFuture<'_, Result<PublicKey, MarmotSignerError>>;
    fn sign_event(
        &self,
        unsigned: UnsignedEvent,
    ) -> SignerFuture<'_, Result<Event, MarmotSignerError>>;
    fn nip04_encrypt<'a>(
        &'a self,
        public_key: &'a PublicKey,
        content: &'a str,
    ) -> SignerFuture<'a, Result<String, MarmotSignerError>>;
    fn nip04_decrypt<'a>(
        &'a self,
        public_key: &'a PublicKey,
        payload: &'a str,
    ) -> SignerFuture<'a, Result<String, MarmotSignerError>>;
    fn nip44_encrypt<'a>(
        &'a self,
        public_key: &'a PublicKey,
        content: &'a str,
    ) -> SignerFuture<'a, Result<String, MarmotSignerError>>;
    fn nip44_decrypt<'a>(
        &'a self,
        public_key: &'a PublicKey,
        payload: &'a str,
    ) -> SignerFuture<'a, Result<String, MarmotSignerError>>;
}

impl MarmotNostrSigner for Keys {
    fn get_public_key(&self) -> SignerFuture<'_, Result<PublicKey, MarmotSignerError>> {
        Box::pin(async move { Ok(self.public_key()) })
    }

    fn sign_event(
        &self,
        unsigned: UnsignedEvent,
    ) -> SignerFuture<'_, Result<Event, MarmotSignerError>> {
        Box::pin(async move {
            SignEvent::sign_event(self, unsigned)
                .map_err(|err| MarmotSignerError::new(err.to_string()))
        })
    }

    fn nip04_encrypt<'a>(
        &'a self,
        public_key: &'a PublicKey,
        content: &'a str,
    ) -> SignerFuture<'a, Result<String, MarmotSignerError>> {
        Box::pin(async move {
            Nip04::nip04_encrypt(self, public_key, content)
                .map_err(|err| MarmotSignerError::new(err.to_string()))
        })
    }

    fn nip04_decrypt<'a>(
        &'a self,
        public_key: &'a PublicKey,
        payload: &'a str,
    ) -> SignerFuture<'a, Result<String, MarmotSignerError>> {
        Box::pin(async move {
            Nip04::nip04_decrypt(self, public_key, payload)
                .map_err(|err| MarmotSignerError::new(err.to_string()))
        })
    }

    fn nip44_encrypt<'a>(
        &'a self,
        public_key: &'a PublicKey,
        content: &'a str,
    ) -> SignerFuture<'a, Result<String, MarmotSignerError>> {
        Box::pin(async move {
            Nip44::nip44_encrypt(self, public_key, content)
                .map_err(|err| MarmotSignerError::new(err.to_string()))
        })
    }

    fn nip44_decrypt<'a>(
        &'a self,
        public_key: &'a PublicKey,
        payload: &'a str,
    ) -> SignerFuture<'a, Result<String, MarmotSignerError>> {
        Box::pin(async move {
            Nip44::nip44_decrypt(self, public_key, payload)
                .map_err(|err| MarmotSignerError::new(err.to_string()))
        })
    }
}

/// Implements the SDK's split asynchronous traits for one immutable MDK
/// signer. The clone retains exactly the selected account context.
#[derive(Clone, Debug)]
pub struct SdkSigner(pub Arc<dyn MarmotNostrSigner>);

impl AsyncGetPublicKey for SdkSigner {
    type Error = MarmotSignerError;

    fn get_public_key_async(&self) -> SignerFuture<'_, Result<PublicKey, Self::Error>> {
        self.0.get_public_key()
    }
}

impl AsyncSignEvent for SdkSigner {
    type Error = MarmotSignerError;

    fn sign_event_async(
        &self,
        unsigned: UnsignedEvent,
    ) -> SignerFuture<'_, Result<Event, Self::Error>> {
        self.0.sign_event(unsigned)
    }
}

impl AsyncNip04 for SdkSigner {
    type Error = MarmotSignerError;

    fn nip04_encrypt_async<'a>(
        &'a self,
        public_key: &'a PublicKey,
        content: &'a str,
    ) -> SignerFuture<'a, Result<String, Self::Error>> {
        self.0.nip04_encrypt(public_key, content)
    }

    fn nip04_decrypt_async<'a>(
        &'a self,
        public_key: &'a PublicKey,
        payload: &'a str,
    ) -> SignerFuture<'a, Result<String, Self::Error>> {
        self.0.nip04_decrypt(public_key, payload)
    }
}

impl AsyncNip44 for SdkSigner {
    type Error = MarmotSignerError;

    fn nip44_encrypt_async<'a>(
        &'a self,
        public_key: &'a PublicKey,
        content: &'a str,
    ) -> SignerFuture<'a, Result<String, Self::Error>> {
        self.0.nip44_encrypt(public_key, content)
    }

    fn nip44_decrypt_async<'a>(
        &'a self,
        public_key: &'a PublicKey,
        payload: &'a str,
    ) -> SignerFuture<'a, Result<String, Self::Error>> {
        self.0.nip44_decrypt(public_key, payload)
    }
}
