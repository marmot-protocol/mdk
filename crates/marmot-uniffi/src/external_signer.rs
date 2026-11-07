use std::fmt;
use std::sync::Arc;

use marmot_app::{AccountIdentityProofRequest, AccountIdentityProofSigner};
use nostr::prelude::{Event, PublicKey, UnsignedEvent};
use transport_nostr_peeler::{MarmotNostrSigner, MarmotSignerError, SignerFuture};

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

impl MarmotNostrSigner for ExternalAccountSignerAdapter {
    fn get_public_key(&self) -> SignerFuture<'_, Result<PublicKey, MarmotSignerError>> {
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
    ) -> SignerFuture<'_, Result<Event, MarmotSignerError>> {
        let signer = self.signer.clone();
        Box::pin(async move {
            let expected_id = unsigned
                .id
                .ok_or_else(|| MarmotSignerError::from("unsigned event id was not set"))?;
            let expected_pubkey = unsigned.pubkey;
            let unsigned_json = unsigned.as_json();
            let event_json = tokio::task::spawn_blocking(move || signer.sign_event(unsigned_json))
                .await
                .map_err(signer_error)?
                .map_err(callback_signer_error)?;
            let event = Event::from_json(event_json).map_err(signer_error)?;
            if event.id != expected_id || event.pubkey != expected_pubkey {
                return Err(MarmotSignerError::from(
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
    ) -> SignerFuture<'a, Result<String, MarmotSignerError>> {
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
    ) -> SignerFuture<'a, Result<String, MarmotSignerError>> {
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
    ) -> SignerFuture<'a, Result<String, MarmotSignerError>> {
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
    ) -> SignerFuture<'a, Result<String, MarmotSignerError>> {
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
        // The proof is signed through the same foreign `sign_event` callback as
        // every other Nostr signature, so a cancelled Amber prompt must survive
        // as the typed rejection rather than a generic string. The trait method
        // is synchronous, so it cannot `spawn_blocking(...).await` like the
        // `NostrSigner` methods above — but it does not need to. The engine
        // builds this proof once, synchronously, inside `AccountDevice::open`,
        // which the app already runs under `blocking_app_task` (spawn_blocking),
        // so the interactive prompt runs on a blocking thread and never parks a
        // Tokio worker. We therefore only need to preserve the rejection type:
        // map it to the `EXTERNAL_SIGNER_REJECTED` sentinel — mirroring
        // `callback_signer_error` — so the app layer can recover
        // `AppError::ExternalSignerRejected` end to end.
        let unsigned_event_json = request.proof_event_json()?;
        let signed_event_json = self
            .signer
            .sign_event(unsigned_event_json)
            .map_err(callback_proof_signer_error)?;
        let signed_event = Event::from_json(signed_event_json).map_err(|err| err.to_string())?;
        request.signature_from_signed_event(signed_event)
    }
}

fn callback_signer_error(error: MarmotKitError) -> MarmotSignerError {
    match error {
        MarmotKitError::ExternalSignerRejected => {
            MarmotSignerError::from(marmot_app::EXTERNAL_SIGNER_REJECTED)
        }
        other => MarmotSignerError::from(other.to_string()),
    }
}

/// Preserve a cancelled proof prompt across the `String`-typed proof-signer
/// trait boundary. A rejected callback becomes the `EXTERNAL_SIGNER_REJECTED`
/// sentinel string so the app layer can map it back to the typed
/// `AppError::ExternalSignerRejected`, matching `callback_signer_error` on the
/// async signer paths.
fn callback_proof_signer_error(error: MarmotKitError) -> String {
    match error {
        MarmotKitError::ExternalSignerRejected => marmot_app::EXTERNAL_SIGNER_REJECTED.to_string(),
        other => other.to_string(),
    }
}

fn signer_error(error: impl ToString) -> MarmotSignerError {
    MarmotSignerError::from(error.to_string())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::thread::ThreadId;

    use nostr::prelude::{
        EventBuilder, FinalizeEvent, FinalizeUnsignedEvent, Keys, Kind, Timestamp, ToBech32,
    };

    use super::*;

    #[derive(Clone)]
    enum Reply {
        Json(String),
        Rejected,
    }

    struct Callback {
        method: &'static str,
        peer: Option<String>,
        payload: String,
        thread: ThreadId,
    }

    struct HostSigner {
        public_key: Mutex<String>,
        reply: Mutex<Reply>,
        calls: Mutex<Vec<Callback>>,
    }

    impl HostSigner {
        fn record(&self, method: &'static str, peer: Option<String>, payload: String) {
            self.calls.lock().unwrap().push(Callback {
                method,
                peer,
                payload,
                thread: std::thread::current().id(),
            });
        }

        fn crypt(
            &self,
            method: &'static str,
            peer: String,
            payload: String,
        ) -> Result<String, MarmotKitError> {
            self.record(method, Some(peer), payload);
            match &*self.reply.lock().unwrap() {
                Reply::Rejected => Err(MarmotKitError::ExternalSignerRejected),
                Reply::Json(_) => Ok(format!("host-{method}-result")),
            }
        }

        fn assert_call(
            &self,
            method: &str,
            peer: Option<&str>,
            payload: &str,
            asynchronous_caller: Option<ThreadId>,
        ) {
            let calls = std::mem::take(&mut *self.calls.lock().unwrap());
            assert_eq!(calls.len(), 1, "one foreign operation per request");
            let call = &calls[0];
            assert_eq!(call.method, method);
            assert_eq!(call.peer.as_deref(), peer);
            assert_eq!(call.payload, payload);
            if let Some(caller) = asynchronous_caller {
                assert_ne!(
                    call.thread, caller,
                    "blocking foreign callback ran on the polling worker"
                );
            }
        }
    }

    impl ExternalAccountSignerFfi for HostSigner {
        fn public_key(&self) -> Result<String, MarmotKitError> {
            self.record("public_key", None, String::new());
            Ok(self.public_key.lock().unwrap().clone())
        }

        fn sign_event(&self, unsigned_event_json: String) -> Result<String, MarmotKitError> {
            self.record("sign_event", None, unsigned_event_json);
            match self.reply.lock().unwrap().clone() {
                Reply::Json(json) => Ok(json),
                Reply::Rejected => Err(MarmotKitError::ExternalSignerRejected),
            }
        }

        fn nip04_encrypt(&self, peer: String, content: String) -> Result<String, MarmotKitError> {
            self.crypt("nip04_encrypt", peer, content)
        }

        fn nip04_decrypt(&self, peer: String, content: String) -> Result<String, MarmotKitError> {
            self.crypt("nip04_decrypt", peer, content)
        }

        fn nip44_encrypt(&self, peer: String, content: String) -> Result<String, MarmotKitError> {
            self.crypt("nip44_encrypt", peer, content)
        }

        fn nip44_decrypt(&self, peer: String, content: String) -> Result<String, MarmotKitError> {
            self.crypt("nip44_decrypt", peer, content)
        }
    }

    fn host(keys: &Keys, response: String) -> Arc<HostSigner> {
        Arc::new(HostSigner {
            public_key: Mutex::new(keys.public_key().to_bech32().unwrap()),
            reply: Mutex::new(Reply::Json(response)),
            calls: Mutex::new(Vec::new()),
        })
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn foreign_signer_preserves_host_arguments_json_and_interactive_rejection() {
        let keys = Keys::parse(&"01".repeat(32)).unwrap();
        let mut unsigned = EventBuilder::new(Kind::TextNote, "binding request")
            .custom_created_at(Timestamp::from_secs(17))
            .finalize_unsigned(keys.public_key());
        unsigned.ensure_id();
        let signed = unsigned.clone().finalize(&keys).unwrap();
        let host = host(&keys, signed.as_json());
        let adapter = ExternalAccountSignerAdapter::new(host.clone());
        // Formatting cannot expose host identity/event state or open a signer prompt.
        assert_eq!(format!("{adapter:?}"), "ExternalAccountSignerAdapter(..)");
        assert!(host.calls.lock().unwrap().is_empty());
        let caller = std::thread::current().id();

        assert_eq!(adapter.get_public_key().await.unwrap(), keys.public_key());
        host.assert_call("public_key", None, "", Some(caller));
        *host.public_key.lock().unwrap() = keys.public_key().to_hex();
        assert_eq!(adapter.get_public_key().await.unwrap(), keys.public_key());
        host.assert_call("public_key", None, "", Some(caller));

        let returned = adapter.sign_event(unsigned.clone()).await.unwrap();
        assert_eq!(returned.id, signed.id);
        assert_eq!(returned.pubkey, keys.public_key());
        assert_eq!(returned.content, "binding request");
        host.assert_call("sign_event", None, &unsigned.as_json(), Some(caller));

        let mut no_id = unsigned.clone();
        no_id.id = None;
        assert_eq!(
            adapter.sign_event(no_id).await.unwrap_err().to_string(),
            "unsigned event id was not set"
        );
        assert!(
            host.calls.lock().unwrap().is_empty(),
            "invalid requests must not open a host prompt"
        );

        *host.reply.lock().unwrap() = Reply::Json("{".into());
        let malformed = adapter.sign_event(unsigned.clone()).await.unwrap_err();
        assert!(
            malformed
                .to_string()
                .contains("EOF while parsing an object"),
            "wrong malformed-JSON diagnostic: {malformed}"
        );
        host.assert_call("sign_event", None, &unsigned.as_json(), Some(caller));

        *host.reply.lock().unwrap() = Reply::Rejected;
        assert_eq!(
            adapter
                .sign_event(unsigned.clone())
                .await
                .unwrap_err()
                .to_string(),
            marmot_app::EXTERNAL_SIGNER_REJECTED
        );
        host.assert_call("sign_event", None, &unsigned.as_json(), Some(caller));

        *host.reply.lock().unwrap() = Reply::Json(signed.as_json());
        let peer = Keys::parse(&"02".repeat(32)).unwrap().public_key();
        let hex = peer.to_hex();
        assert_eq!(
            adapter.nip04_encrypt(&peer, "plain04").await.unwrap(),
            "host-nip04_encrypt-result"
        );
        host.assert_call("nip04_encrypt", Some(&hex), "plain04", Some(caller));
        assert_eq!(
            adapter.nip04_decrypt(&peer, "cipher04").await.unwrap(),
            "host-nip04_decrypt-result"
        );
        host.assert_call("nip04_decrypt", Some(&hex), "cipher04", Some(caller));
        assert_eq!(
            adapter.nip44_encrypt(&peer, "plain44").await.unwrap(),
            "host-nip44_encrypt-result"
        );
        host.assert_call("nip44_encrypt", Some(&hex), "plain44", Some(caller));
        assert_eq!(
            adapter.nip44_decrypt(&peer, "cipher44").await.unwrap(),
            "host-nip44_decrypt-result"
        );
        host.assert_call("nip44_decrypt", Some(&hex), "cipher44", Some(caller));
        *host.reply.lock().unwrap() = Reply::Rejected;
        assert_eq!(
            adapter
                .nip44_decrypt(&peer, "rejected44")
                .await
                .unwrap_err()
                .to_string(),
            marmot_app::EXTERNAL_SIGNER_REJECTED
        );
        host.assert_call("nip44_decrypt", Some(&hex), "rejected44", Some(caller));
    }

    #[test]
    fn foreign_proof_signer_preserves_requested_json_signature_and_rejection() {
        let keys = Keys::parse(&"03".repeat(32)).unwrap();
        let request = AccountIdentityProofRequest {
            account_identity: keys.public_key().to_bytes().to_vec(),
            mls_signature_public_key: vec![7; 32],
            ciphersuite: 1,
            signature_scheme: 0x0807,
            created_at: 1_700_000_000,
            protocol_profile: cgka_traits::group::ProtocolProfile::Current,
        };
        let unsigned = request.proof_event().unwrap();
        let signed = unsigned.clone().finalize(&keys).unwrap();
        let host = host(&keys, signed.as_json());
        let adapter = ExternalAccountSignerAdapter::new(host.clone());
        assert_eq!(
            adapter.sign_account_identity_proof(&request).unwrap(),
            signed.sig.to_bytes()
        );
        host.assert_call("sign_event", None, &unsigned.as_json(), None);
        *host.reply.lock().unwrap() = Reply::Rejected;
        assert_eq!(
            adapter.sign_account_identity_proof(&request).unwrap_err(),
            marmot_app::EXTERNAL_SIGNER_REJECTED
        );
        host.assert_call("sign_event", None, &unsigned.as_json(), None);
    }
}
