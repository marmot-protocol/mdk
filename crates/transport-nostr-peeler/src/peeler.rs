use crate::error::to_peeler_error;
use crate::event::{decode_hex, decode_hex_exact};
use crate::{
    DEFAULT_EXPORTER_LABEL, GROUP_TAG, KIND_MARMOT_GROUP_MESSAGE, KIND_MARMOT_WELCOME_RUMOR,
    KIND_NIP59_GIFT_WRAP, NOSTR_GROUP_KEY_LEN, NostrTransportEvent, RECIPIENT_TAG,
};
use async_trait::async_trait;
use cgka_traits::error::PeelerError;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{PeeledContent, PeeledMessage};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::transport::{EncryptedPayload, TransportEnvelope, TransportMessage};
use cgka_traits::types::{GroupId, MemberId};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use nostr::{EventBuilder, Kind, NostrSigner, PublicKey, UnsignedEvent};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

const NONCE_LEN: usize = 12;
const GROUP_CONTENT_VERSION: u8 = 1;
const WELCOME_SIGNER_CONTEXT: &str = "nostr_welcome_signer";

/// Nostr implementation of the Marmot transport peeler.
#[derive(Clone, Debug)]
pub struct NostrMlsPeeler {
    exporter_label: String,
    author_pubkey: String,
    welcome_signer: Option<Arc<dyn NostrSigner>>,
}

impl NostrMlsPeeler {
    /// Build a peeler with the current engine exporter label and an author
    /// public key. A real adapter signs the resulting event before publishing.
    pub fn new(author_pubkey: impl Into<String>) -> Self {
        Self {
            exporter_label: DEFAULT_EXPORTER_LABEL.into(),
            author_pubkey: author_pubkey.into(),
            welcome_signer: None,
        }
    }

    /// Override the exporter label used for kind-445 group envelopes.
    pub fn with_exporter_label(mut self, label: impl Into<String>) -> Self {
        self.exporter_label = label.into();
        self
    }

    /// Inject the local Nostr signer/decrypter used for NIP-59 welcomes.
    ///
    /// The peeler does not own account lifecycle. Callers provide the signer
    /// from the account-device layer that already owns local identity keys.
    pub fn with_welcome_signer<T>(mut self, signer: T) -> Self
    where
        T: NostrSigner + 'static,
    {
        self.welcome_signer = Some(Arc::new(signer));
        self
    }

    fn welcome_signer(&self) -> Result<&Arc<dyn NostrSigner>, PeelerError> {
        self.welcome_signer
            .as_ref()
            .ok_or_else(|| PeelerError::MissingContext {
                label: WELCOME_SIGNER_CONTEXT.into(),
            })
    }

    fn group_key<'a>(&self, ctx: &'a GroupContextSnapshot) -> Result<&'a [u8], PeelerError> {
        let secret = ctx.exporter_secret(&self.exporter_label).ok_or_else(|| {
            PeelerError::MissingContext {
                label: self.exporter_label.clone(),
            }
        })?;
        if secret.len() != NOSTR_GROUP_KEY_LEN {
            return Err(PeelerError::MissingContext {
                label: format!("{} (must be 32 bytes)", self.exporter_label),
            });
        }
        Ok(secret)
    }

    fn recipient_pubkey(recipient: &MemberId) -> Result<PublicKey, PeelerError> {
        PublicKey::from_slice(recipient.as_slice()).map_err(|e| {
            PeelerError::WrapFailed(format!("recipient MemberId is not a Nostr pubkey: {e}"))
        })
    }
}

impl Default for NostrMlsPeeler {
    fn default() -> Self {
        Self::new("00".repeat(32))
    }
}

#[async_trait]
impl TransportPeeler for NostrMlsPeeler {
    async fn peel_group_message(
        &self,
        msg: &TransportMessage,
        ctx: &GroupContextSnapshot,
    ) -> Result<PeeledMessage, PeelerError> {
        let event = NostrTransportEvent::from_transport_message(msg).map_err(to_peeler_error)?;
        if event.kind != KIND_MARMOT_GROUP_MESSAGE {
            return Err(PeelerError::Malformed(format!(
                "expected kind {KIND_MARMOT_GROUP_MESSAGE}, got {}",
                event.kind
            )));
        }
        ensure_group_routing_matches(&event, msg)?;

        let content: GroupEnvelopeContent = serde_json::from_str(&event.content)
            .map_err(|e| PeelerError::Malformed(e.to_string()))?;
        if content.version != GROUP_CONTENT_VERSION {
            return Err(PeelerError::Malformed(format!(
                "unsupported group envelope version {}",
                content.version
            )));
        }

        let key = self.group_key(ctx)?;
        let nonce =
            decode_hex_exact("group nonce", &content.nonce, NONCE_LEN).map_err(to_peeler_error)?;
        let ciphertext =
            decode_hex("group ciphertext", &content.ciphertext).map_err(to_peeler_error)?;
        let aad = decode_hex("group aad", &content.aad).map_err(to_peeler_error)?;
        let cipher =
            ChaCha20Poly1305::new_from_slice(key).map_err(|_| PeelerError::DecryptFailed)?;
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| PeelerError::DecryptFailed)?;
        let sender = decode_hex_exact("event pubkey", &event.pubkey, 32)
            .ok()
            .map(MemberId::new);

        Ok(PeeledMessage {
            id: msg.id.clone(),
            group_id: transport_group_id(msg),
            sender,
            content: PeeledContent::MlsMessage { bytes: plaintext },
            origin: msg.clone(),
        })
    }

    async fn peel_welcome(&self, msg: &TransportMessage) -> Result<PeeledMessage, PeelerError> {
        let signer = self.welcome_signer()?;
        let event = NostrTransportEvent::from_transport_message(msg).map_err(to_peeler_error)?;
        if event.kind != KIND_NIP59_GIFT_WRAP {
            return Err(PeelerError::Malformed(format!(
                "expected kind {KIND_NIP59_GIFT_WRAP}, got {}",
                event.kind
            )));
        }
        ensure_welcome_routing_matches(&event, msg)?;
        let gift_wrap = event.to_verified_nostr_event().map_err(to_peeler_error)?;
        let unwrapped = nostr::nips::nip59::extract_rumor(signer, &gift_wrap)
            .await
            .map_err(map_nip59_error)?;

        if unwrapped.rumor.kind != Kind::Custom(KIND_MARMOT_WELCOME_RUMOR) {
            return Err(PeelerError::Malformed(format!(
                "expected Marmot welcome rumor kind {KIND_MARMOT_WELCOME_RUMOR}, got {}",
                u16::from(unwrapped.rumor.kind)
            )));
        }
        let welcome_bytes = decode_hex("welcome rumor content", &unwrapped.rumor.content)
            .map_err(to_peeler_error)?;
        if welcome_bytes.is_empty() {
            return Err(PeelerError::Malformed(
                "welcome rumor contained empty MLS welcome bytes".into(),
            ));
        }

        Ok(PeeledMessage {
            id: msg.id.clone(),
            group_id: None,
            sender: Some(MemberId::new(unwrapped.sender.to_bytes().to_vec())),
            content: PeeledContent::Welcome {
                bytes: welcome_bytes,
            },
            origin: msg.clone(),
        })
    }

    async fn wrap_group_message(
        &self,
        payload: &EncryptedPayload,
        ctx: &GroupContextSnapshot,
    ) -> Result<TransportMessage, PeelerError> {
        let group_id = ctx
            .transport_group_id()
            .ok_or_else(|| PeelerError::MissingContext {
                label: "transport_group_id".into(),
            })?;
        let key = self.group_key(ctx)?;
        let mut nonce = [0_u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce);
        let cipher = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|e| PeelerError::WrapFailed(e.to_string()))?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &payload.ciphertext,
                    aad: &payload.aad,
                },
            )
            .map_err(|_| PeelerError::WrapFailed("group encryption failed".into()))?;
        let content = GroupEnvelopeContent {
            version: GROUP_CONTENT_VERSION,
            nonce: hex::encode(nonce),
            ciphertext: hex::encode(ciphertext),
            aad: hex::encode(&payload.aad),
        };
        let event = NostrTransportEvent::new_local(
            self.author_pubkey.clone(),
            KIND_MARMOT_GROUP_MESSAGE,
            vec![vec![GROUP_TAG.into(), hex::encode(group_id)]],
            serde_json::to_string(&content).map_err(|e| PeelerError::WrapFailed(e.to_string()))?,
        );
        event.to_transport_message().map_err(to_peeler_error)
    }

    async fn wrap_welcome(
        &self,
        payload: &EncryptedPayload,
        recipient: &MemberId,
    ) -> Result<TransportMessage, PeelerError> {
        if !payload.aad.is_empty() {
            return Err(PeelerError::WrapFailed(
                "Nostr welcome wrap does not currently encode payload AAD".into(),
            ));
        }
        if payload.ciphertext.is_empty() {
            return Err(PeelerError::WrapFailed(
                "welcome payload cannot be empty".into(),
            ));
        }
        let signer = self.welcome_signer()?;
        let sender_pubkey = signer
            .get_public_key()
            .await
            .map_err(|e| PeelerError::WrapFailed(format!("signer public key: {e}")))?;
        let recipient_pubkey = Self::recipient_pubkey(recipient)?;
        let rumor: UnsignedEvent = EventBuilder::new(
            Kind::Custom(KIND_MARMOT_WELCOME_RUMOR),
            hex::encode(&payload.ciphertext),
        )
        .build(sender_pubkey);
        let gift_wrap = EventBuilder::gift_wrap(signer, &recipient_pubkey, rumor, [])
            .await
            .map_err(|e| PeelerError::WrapFailed(format!("NIP-59 gift wrap: {e}")))?;
        let event = NostrTransportEvent::from_nostr_event(&gift_wrap).map_err(to_peeler_error)?;
        event.to_transport_message().map_err(to_peeler_error)
    }
}

#[derive(Serialize, Deserialize)]
struct GroupEnvelopeContent {
    version: u8,
    nonce: String,
    ciphertext: String,
    aad: String,
}

fn transport_group_id(msg: &TransportMessage) -> Option<GroupId> {
    match &msg.envelope {
        TransportEnvelope::GroupMessage { transport_group_id } => {
            Some(GroupId::new(transport_group_id.clone()))
        }
        TransportEnvelope::Welcome { .. } => None,
    }
}

fn ensure_group_routing_matches(
    event: &NostrTransportEvent,
    msg: &TransportMessage,
) -> Result<(), PeelerError> {
    let event_group_id = event
        .tag_value(GROUP_TAG)
        .ok_or_else(|| PeelerError::Malformed("missing h tag".into()))
        .and_then(|h| decode_hex("group h tag", h).map_err(to_peeler_error))?;
    match &msg.envelope {
        TransportEnvelope::GroupMessage { transport_group_id }
            if *transport_group_id == event_group_id =>
        {
            Ok(())
        }
        TransportEnvelope::GroupMessage { .. } => Err(PeelerError::Malformed(
            "event h tag does not match transport envelope".into(),
        )),
        TransportEnvelope::Welcome { .. } => Err(PeelerError::Malformed(
            "group peeler received welcome envelope".into(),
        )),
    }
}

fn ensure_welcome_routing_matches(
    event: &NostrTransportEvent,
    msg: &TransportMessage,
) -> Result<(), PeelerError> {
    let event_recipient = event
        .tag_value(RECIPIENT_TAG)
        .ok_or_else(|| PeelerError::Malformed("missing p tag".into()))
        .and_then(|p| decode_hex_exact("recipient p tag", p, 32).map_err(to_peeler_error))?;
    match &msg.envelope {
        TransportEnvelope::Welcome { recipient } if recipient.as_slice() == event_recipient => {
            Ok(())
        }
        TransportEnvelope::Welcome { .. } => Err(PeelerError::Malformed(
            "event p tag does not match transport envelope".into(),
        )),
        TransportEnvelope::GroupMessage { .. } => Err(PeelerError::Malformed(
            "welcome peeler received group envelope".into(),
        )),
    }
}

fn map_nip59_error(err: nostr::nips::nip59::Error) -> PeelerError {
    match err {
        nostr::nips::nip59::Error::NotGiftWrap => {
            PeelerError::Malformed("Nostr event was not a gift wrap".into())
        }
        nostr::nips::nip59::Error::SenderMismatch
        | nostr::nips::nip59::Error::Signer(_)
        | nostr::nips::nip59::Error::Event(_) => PeelerError::DecryptFailed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DEFAULT_EXPORTER_LABEL, KIND_MARMOT_GROUP_MESSAGE};
    use cgka_traits::group_context::GroupContextSnapshot;
    use cgka_traits::ingest::PeeledContent;
    use cgka_traits::types::EpochId;
    use std::collections::HashMap;

    #[tokio::test]
    async fn group_wrap_and_peel_round_trips_mls_bytes() {
        let secret = vec![0x7a; NOSTR_GROUP_KEY_LEN];
        let group_id = vec![0x99; 32];
        let ctx = GroupContextSnapshot::new(
            EpochId(9),
            HashMap::from([(DEFAULT_EXPORTER_LABEL.to_string(), secret)]),
            Some(group_id.clone()),
        );
        let peeler = NostrMlsPeeler::default();

        let wrapped = peeler
            .wrap_group_message(
                &EncryptedPayload {
                    ciphertext: b"inner mls bytes".to_vec(),
                    aad: b"aad".to_vec(),
                },
                &ctx,
            )
            .await
            .expect("wrap succeeds");

        assert!(matches!(
            wrapped.envelope,
            TransportEnvelope::GroupMessage {
                ref transport_group_id,
            } if *transport_group_id == group_id
        ));

        let event = NostrTransportEvent::from_transport_message(&wrapped).expect("payload parses");
        assert_eq!(event.kind, KIND_MARMOT_GROUP_MESSAGE);
        assert_eq!(event.tag_value("h"), Some(hex::encode(&group_id).as_str()));

        let peeled = peeler
            .peel_group_message(&wrapped, &ctx)
            .await
            .expect("peel succeeds");

        assert_eq!(peeled.id, wrapped.id);
        assert_eq!(
            peeled.content,
            PeeledContent::MlsMessage {
                bytes: b"inner mls bytes".to_vec(),
            }
        );
    }

    #[tokio::test]
    async fn group_peel_with_wrong_secret_fails_cleanly() {
        let group_id = vec![0x99; 32];
        let wrap_ctx = GroupContextSnapshot::new(
            EpochId(9),
            HashMap::from([(DEFAULT_EXPORTER_LABEL.to_string(), vec![0x7a; 32])]),
            Some(group_id),
        );
        let peel_ctx = GroupContextSnapshot::new(
            EpochId(9),
            HashMap::from([(DEFAULT_EXPORTER_LABEL.to_string(), vec![0x7b; 32])]),
            None,
        );
        let peeler = NostrMlsPeeler::default();
        let wrapped = peeler
            .wrap_group_message(
                &EncryptedPayload {
                    ciphertext: b"inner mls bytes".to_vec(),
                    aad: vec![],
                },
                &wrap_ctx,
            )
            .await
            .expect("wrap succeeds");

        let err = peeler
            .peel_group_message(&wrapped, &peel_ctx)
            .await
            .expect_err("wrong secret should not decrypt");

        assert!(matches!(err, PeelerError::DecryptFailed));
    }

    #[tokio::test]
    async fn group_peel_rejects_mismatched_h_tag_and_envelope() {
        let wrap_ctx = GroupContextSnapshot::new(
            EpochId(9),
            HashMap::from([(DEFAULT_EXPORTER_LABEL.to_string(), vec![0x7a; 32])]),
            Some(vec![0x99; 32]),
        );
        let peel_ctx = GroupContextSnapshot::new(
            EpochId(9),
            HashMap::from([(DEFAULT_EXPORTER_LABEL.to_string(), vec![0x7a; 32])]),
            None,
        );
        let peeler = NostrMlsPeeler::default();
        let mut wrapped = peeler
            .wrap_group_message(
                &EncryptedPayload {
                    ciphertext: b"inner mls bytes".to_vec(),
                    aad: vec![],
                },
                &wrap_ctx,
            )
            .await
            .expect("wrap succeeds");
        wrapped.envelope = TransportEnvelope::GroupMessage {
            transport_group_id: vec![0x55; 32],
        };

        let err = peeler
            .peel_group_message(&wrapped, &peel_ctx)
            .await
            .expect_err("mismatched route should not peel");

        assert!(matches!(err, PeelerError::Malformed(_)));
    }

    #[tokio::test]
    async fn welcome_wrap_and_peel_round_trips_mls_welcome_bytes() {
        let sender = sender_keys();
        let receiver = receiver_keys();
        let recipient = MemberId::new(receiver.public_key().to_bytes().to_vec());
        let sender_peeler =
            NostrMlsPeeler::new(sender.public_key().to_hex()).with_welcome_signer(sender.clone());
        let receiver_peeler = NostrMlsPeeler::new(receiver.public_key().to_hex())
            .with_welcome_signer(receiver.clone());

        let wrapped = sender_peeler
            .wrap_welcome(
                &EncryptedPayload {
                    ciphertext: b"mls welcome bytes".to_vec(),
                    aad: vec![],
                },
                &recipient,
            )
            .await
            .expect("wrap succeeds");

        assert!(matches!(
            wrapped.envelope,
            TransportEnvelope::Welcome {
                ref recipient,
            } if recipient.as_slice() == receiver.public_key().as_bytes()
        ));
        let event = NostrTransportEvent::from_transport_message(&wrapped).unwrap();
        assert_eq!(event.kind, KIND_NIP59_GIFT_WRAP);
        assert!(event.sig.is_some());
        assert_eq!(
            event.tag_value("p"),
            Some(receiver.public_key().to_hex().as_str())
        );

        let peeled = receiver_peeler
            .peel_welcome(&wrapped)
            .await
            .expect("peel succeeds");

        assert_eq!(peeled.id, wrapped.id);
        assert_eq!(
            peeled.sender,
            Some(MemberId::new(sender.public_key().to_bytes().to_vec()))
        );
        assert_eq!(
            peeled.content,
            PeeledContent::Welcome {
                bytes: b"mls welcome bytes".to_vec(),
            }
        );
    }

    #[tokio::test]
    async fn welcome_peel_with_wrong_private_key_fails_closed() {
        let sender = sender_keys();
        let receiver = receiver_keys();
        let wrong_receiver = wrong_receiver_keys();
        let recipient = MemberId::new(receiver.public_key().to_bytes().to_vec());
        let sender_peeler =
            NostrMlsPeeler::new(sender.public_key().to_hex()).with_welcome_signer(sender);
        let wrong_peeler = NostrMlsPeeler::new(wrong_receiver.public_key().to_hex())
            .with_welcome_signer(wrong_receiver);
        let wrapped = sender_peeler
            .wrap_welcome(
                &EncryptedPayload {
                    ciphertext: b"mls welcome bytes".to_vec(),
                    aad: vec![],
                },
                &recipient,
            )
            .await
            .expect("wrap succeeds");

        let err = wrong_peeler
            .peel_welcome(&wrapped)
            .await
            .expect_err("wrong recipient key cannot decrypt");

        assert!(matches!(err, PeelerError::DecryptFailed));
    }

    #[tokio::test]
    async fn welcome_peel_rejects_mismatched_p_tag_and_envelope() {
        let sender = sender_keys();
        let receiver = receiver_keys();
        let recipient = MemberId::new(receiver.public_key().to_bytes().to_vec());
        let peeler =
            NostrMlsPeeler::new(sender.public_key().to_hex()).with_welcome_signer(sender.clone());
        let mut wrapped = peeler
            .wrap_welcome(
                &EncryptedPayload {
                    ciphertext: b"mls welcome bytes".to_vec(),
                    aad: vec![],
                },
                &recipient,
            )
            .await
            .expect("wrap succeeds");
        wrapped.envelope = TransportEnvelope::Welcome {
            recipient: MemberId::new(vec![0x55; 32]),
        };

        let err = NostrMlsPeeler::new(receiver.public_key().to_hex())
            .with_welcome_signer(receiver)
            .peel_welcome(&wrapped)
            .await
            .expect_err("mismatched route should not peel");

        assert!(matches!(err, PeelerError::Malformed(_)));
    }

    #[tokio::test]
    async fn welcome_peel_rejects_authentic_non_welcome_rumor() {
        let sender = sender_keys();
        let receiver = receiver_keys();
        let rumor = EventBuilder::text_note("not a Marmot welcome").build(sender.public_key());
        let gift_wrap = EventBuilder::gift_wrap(&sender, &receiver.public_key(), rumor, [])
            .await
            .unwrap();
        let wrapped = NostrTransportEvent::from_nostr_event(&gift_wrap)
            .unwrap()
            .to_transport_message()
            .unwrap();

        let err = NostrMlsPeeler::new(receiver.public_key().to_hex())
            .with_welcome_signer(receiver)
            .peel_welcome(&wrapped)
            .await
            .expect_err("wrong rumor kind should not peel");

        assert!(matches!(err, PeelerError::Malformed(_)));
    }

    fn sender_keys() -> nostr::Keys {
        nostr::Keys::parse("6b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e")
            .unwrap()
    }

    fn receiver_keys() -> nostr::Keys {
        nostr::Keys::parse("7b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e")
            .unwrap()
    }

    fn wrong_receiver_keys() -> nostr::Keys {
        nostr::Keys::parse("5b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e")
            .unwrap()
    }
}
