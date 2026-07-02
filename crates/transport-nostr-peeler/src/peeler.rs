use crate::error::to_peeler_error;
use crate::event::{decode_hex, decode_hex_exact};
use crate::{
    DEFAULT_EXPORTER_LABEL, GROUP_TAG, KIND_MARMOT_GROUP_MESSAGE, KIND_MARMOT_WELCOME_RUMOR,
    KIND_NIP59_GIFT_WRAP, NOSTR_GROUP_CONTENT_MIN_LEN, NOSTR_GROUP_KEY_LEN, NostrTransportEvent,
    RECIPIENT_TAG,
};
use async_trait::async_trait;
use cgka_traits::engine::WelcomeMetadata;
use cgka_traits::error::PeelerError;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{PeeledContent, PeeledMessage};
use cgka_traits::peeler::{GroupMessageMetadata, TransportPeeler};
use cgka_traits::transport::{EncryptedPayload, TransportEnvelope, TransportMessage};
use cgka_traits::types::{GroupId, MemberId};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use nostr::base64::Engine as _;
use nostr::base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use nostr::{EventBuilder, Keys, Kind, NostrSigner, PublicKey, Tag, UnsignedEvent};
use rand::RngCore;
use std::sync::Arc;

const NONCE_LEN: usize = 12;
const WELCOME_SIGNER_CONTEXT: &str = "nostr_welcome_signer";
const KEY_PACKAGE_EVENT_TAG: &str = "e";
const EXPIRATION_TAG: &str = "expiration";
const WELCOME_RELAYS_TAG: &str = "relays";

/// Empty AAD for the outer kind-445 ChaCha20-Poly1305 sealing
/// (`spec/transports/nostr.md`: `aad = ""`).
const GROUP_AAD: &[u8] = b"";

/// Nostr implementation of the Marmot transport peeler.
#[derive(Clone, Debug)]
pub struct NostrMlsPeeler {
    exporter_label: String,
    welcome_signer: Option<Arc<dyn NostrSigner>>,
}

impl NostrMlsPeeler {
    /// Build a peeler with the current engine exporter label.
    ///
    /// The peeler does not hold the account identity: kind-445 group events are
    /// signed by a fresh ephemeral key per event
    /// (`spec/transports/nostr.md:32-34`), and NIP-59 welcomes use the injected
    /// `with_welcome_signer`.
    pub fn new() -> Self {
        Self {
            exporter_label: DEFAULT_EXPORTER_LABEL.into(),
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

    fn wrap_group_message_inner(
        &self,
        payload: &EncryptedPayload,
        ctx: &GroupContextSnapshot,
        metadata: Option<&GroupMessageMetadata>,
    ) -> Result<TransportMessage, PeelerError> {
        let group_id = ctx
            .transport_group_id()
            .ok_or_else(|| PeelerError::MissingContext {
                label: "transport_group_id".into(),
            })?;
        // spec/transports/nostr.md: the AEAD AAD is the empty byte string and is
        // never serialized into the event. Callers that pass a non-empty AAD are
        // off-spec; fail closed rather than silently dropping bytes.
        if !payload.aad.is_empty() {
            return Err(PeelerError::WrapFailed(
                "Nostr kind-445 group wrap requires empty AAD".into(),
            ));
        }
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
                    aad: GROUP_AAD,
                },
            )
            .map_err(|_| PeelerError::WrapFailed("group encryption failed".into()))?;
        // content = base64(nonce || ciphertext).
        let mut framed = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        framed.extend_from_slice(&nonce);
        framed.extend_from_slice(&ciphertext);
        let content = BASE64_STANDARD.encode(&framed);

        // spec/transports/nostr.md:32-34 — the outer kind-445 event MUST be
        // signed by a fresh ephemeral Nostr key generated for this event, never
        // the sender's account identity and never reused. Generate one per
        // call and sign here so the adapter publishes the event as-is rather
        // than re-signing it with the account signer.
        let ephemeral = Keys::generate();
        let mut tags = vec![Tag::custom(
            nostr::TagKind::custom(GROUP_TAG),
            [hex::encode(group_id)],
        )];
        if let Some(expiration) = metadata
            .map(|metadata| metadata.expiration_timestamp())
            .transpose()
            .map_err(|err| {
                PeelerError::WrapFailed(format!("invalid group-message metadata: {err:?}"))
            })?
            .flatten()
        {
            tags.push(Tag::custom(
                nostr::TagKind::custom(EXPIRATION_TAG),
                [expiration.to_string()],
            ));
        }
        // Package E (#630 cross-client): bind the outer kind-445 `created_at` to
        // the inner app event's sender-authenticated `created_at` so the sender
        // and every receiver record the same `recorded_at`. Without this the
        // builder defaults to wrap-time `now()`, which only receivers agree on.
        // Commits/proposals carry no inner timestamp, so they keep the default.
        let mut builder =
            EventBuilder::new(Kind::Custom(KIND_MARMOT_GROUP_MESSAGE as u16), content).tags(tags);
        if let Some(created_at) = metadata.and_then(GroupMessageMetadata::outer_created_at) {
            builder = builder.custom_created_at(nostr::Timestamp::from_secs(created_at));
        }
        let signed = builder
            .sign_with_keys(&ephemeral)
            .map_err(|e| PeelerError::WrapFailed(format!("ephemeral kind-445 sign: {e}")))?;
        let event = NostrTransportEvent::from_nostr_event(&signed).map_err(to_peeler_error)?;
        event.to_transport_message().map_err(to_peeler_error)
    }

    fn recipient_pubkey(recipient: &MemberId) -> Result<PublicKey, PeelerError> {
        PublicKey::from_slice(recipient.as_slice()).map_err(|e| {
            PeelerError::WrapFailed(format!("recipient MemberId is not a Nostr pubkey: {e}"))
        })
    }
}

impl Default for NostrMlsPeeler {
    fn default() -> Self {
        Self::new()
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
        event.to_verified_nostr_event().map_err(to_peeler_error)?;
        ensure_group_routing_matches(&event, msg)?;

        // spec/transports/nostr.md: content = base64(nonce || ciphertext).
        // Reject content that is not valid base64 or that decodes to fewer than
        // 28 bytes (12 nonce + 16 AEAD tag) before attempting to peel.
        let decoded = BASE64_STANDARD
            .decode(event.content.as_bytes())
            .map_err(|e| PeelerError::Malformed(format!("kind-445 content is not base64: {e}")))?;
        if decoded.len() < NOSTR_GROUP_CONTENT_MIN_LEN {
            return Err(PeelerError::Malformed(format!(
                "kind-445 content decodes to {} bytes, need at least {NOSTR_GROUP_CONTENT_MIN_LEN}",
                decoded.len()
            )));
        }
        let (nonce, ciphertext) = decoded.split_at(NONCE_LEN);

        let key = self.group_key(ctx)?;
        let cipher =
            ChaCha20Poly1305::new_from_slice(key).map_err(|_| PeelerError::DecryptFailed)?;
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: GROUP_AAD,
                },
            )
            .map_err(|_| PeelerError::DecryptFailed)?;
        Ok(PeeledMessage {
            id: msg.id.clone(),
            group_id: transport_group_id(msg),
            sender: None,
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

        // spec/transports/nostr.md — the kind-444 welcome rumor links to the
        // KeyPackage event consumed for this welcome and carries the group
        // relay list the new member should use next.
        let key_package_event_id = rumor_tag_value(&unwrapped.rumor, KEY_PACKAGE_EVENT_TAG)
            .ok_or_else(|| PeelerError::Malformed("welcome rumor is missing e tag".into()))?;
        decode_hex_exact("welcome e tag", key_package_event_id, 32).map_err(to_peeler_error)?;
        let relays = rumor_tag_values(&unwrapped.rumor, WELCOME_RELAYS_TAG)
            .ok_or_else(|| PeelerError::Malformed("welcome rumor is missing relays tag".into()))?;
        if relays.is_empty() || relays.iter().any(|relay| relay.is_empty()) {
            return Err(PeelerError::Malformed(
                "welcome rumor relays tag must contain at least one non-empty relay".into(),
            ));
        }

        let welcome_bytes = BASE64_STANDARD
            .decode(unwrapped.rumor.content.as_bytes())
            .map_err(|e| {
                PeelerError::Malformed(format!("welcome rumor content is not base64: {e}"))
            })?;
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
        self.wrap_group_message_inner(payload, ctx, None)
    }

    async fn wrap_group_message_with_metadata(
        &self,
        payload: &EncryptedPayload,
        ctx: &GroupContextSnapshot,
        metadata: &GroupMessageMetadata,
    ) -> Result<TransportMessage, PeelerError> {
        self.wrap_group_message_inner(payload, ctx, Some(metadata))
    }

    async fn wrap_welcome(
        &self,
        payload: &EncryptedPayload,
        recipient: &MemberId,
    ) -> Result<TransportMessage, PeelerError> {
        let _ = (payload, recipient);
        Err(PeelerError::MissingContext {
            label: "welcome_metadata".into(),
        })
    }

    async fn wrap_welcome_with_metadata(
        &self,
        payload: &EncryptedPayload,
        recipient: &MemberId,
        metadata: &WelcomeMetadata,
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
        if metadata.relays.is_empty() {
            return Err(PeelerError::WrapFailed(
                "Nostr welcome relays tag must not be empty".into(),
            ));
        }
        let rumor: UnsignedEvent = EventBuilder::new(
            Kind::Custom(KIND_MARMOT_WELCOME_RUMOR),
            BASE64_STANDARD.encode(&payload.ciphertext),
        )
        .tags([
            Tag::custom(
                nostr::TagKind::custom(KEY_PACKAGE_EVENT_TAG),
                [hex::encode(metadata.key_package_event_id.as_slice())],
            ),
            Tag::custom(
                nostr::TagKind::custom(WELCOME_RELAYS_TAG),
                metadata.relays.iter().map(|relay| relay.as_str()),
            ),
        ])
        .build(sender_pubkey);
        let gift_wrap = EventBuilder::gift_wrap(signer, &recipient_pubkey, rumor, [])
            .await
            .map_err(|e| PeelerError::WrapFailed(format!("NIP-59 gift wrap: {e}")))?;
        let event = NostrTransportEvent::from_nostr_event(&gift_wrap).map_err(to_peeler_error)?;
        event.to_transport_message().map_err(to_peeler_error)
    }
}

/// First value of a tag on an unwrapped NIP-59 rumor (`tag[0] == name` →
/// `tag[1]`).
fn rumor_tag_value<'a>(rumor: &'a UnsignedEvent, name: &str) -> Option<&'a str> {
    rumor.tags.iter().find_map(|tag| {
        let slice = tag.as_slice();
        match (slice.first(), slice.get(1)) {
            (Some(tag_name), Some(value)) if tag_name == name => Some(value.as_str()),
            _ => None,
        }
    })
}

fn rumor_tag_values<'a>(rumor: &'a UnsignedEvent, name: &str) -> Option<Vec<&'a str>> {
    rumor.tags.iter().find_map(|tag| {
        let slice = tag.as_slice();
        match slice.first() {
            Some(tag_name) if tag_name == name => {
                Some(slice.iter().skip(1).map(String::as_str).collect())
            }
            _ => None,
        }
    })
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
        .single_tag_value(GROUP_TAG)
        .map_err(to_peeler_error)
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
    use cgka_traits::TransportEndpoint;
    use cgka_traits::group_context::GroupContextSnapshot;
    use cgka_traits::ingest::PeeledContent;
    use cgka_traits::types::{EpochId, MessageId};
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
                    aad: vec![],
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
        // The outer event is signed by an ephemeral key generated for this
        // event (spec/transports/nostr.md:32-34).
        assert!(event.sig.is_some());
        // content = base64(nonce || ciphertext); standard base64, decodes to at
        // least the 28-byte minimum.
        let decoded = BASE64_STANDARD
            .decode(event.content.as_bytes())
            .expect("content is standard base64");
        assert!(decoded.len() >= NOSTR_GROUP_CONTENT_MIN_LEN);

        let peeled = peeler
            .peel_group_message(&wrapped, &ctx)
            .await
            .expect("peel succeeds");

        assert_eq!(peeled.id, wrapped.id);
        assert_eq!(peeled.sender, None);
        assert_eq!(
            peeled.content,
            PeeledContent::MlsMessage {
                bytes: b"inner mls bytes".to_vec(),
            }
        );
    }

    #[tokio::test]
    async fn group_peel_rejects_unsigned_kind_445() {
        let secret = vec![0x7a; NOSTR_GROUP_KEY_LEN];
        let group_id = vec![0x99; 32];
        let ctx = GroupContextSnapshot::new(
            EpochId(9),
            HashMap::from([(DEFAULT_EXPORTER_LABEL.to_string(), secret)]),
            Some(group_id),
        );
        let peeler = NostrMlsPeeler::default();
        let wrapped = peeler
            .wrap_group_message(
                &EncryptedPayload {
                    ciphertext: b"inner mls bytes".to_vec(),
                    aad: vec![],
                },
                &ctx,
            )
            .await
            .expect("wrap succeeds");
        let mut event = NostrTransportEvent::from_transport_message(&wrapped).unwrap();
        event.sig = None;
        let unsigned_msg = event.to_transport_message().unwrap();

        assert!(matches!(
            peeler.peel_group_message(&unsigned_msg, &ctx).await,
            Err(PeelerError::Malformed(_))
        ));
    }

    #[tokio::test]
    async fn group_wrap_rejects_non_empty_aad() {
        let ctx = GroupContextSnapshot::new(
            EpochId(9),
            HashMap::from([(DEFAULT_EXPORTER_LABEL.to_string(), vec![0x7a; 32])]),
            Some(vec![0x99; 32]),
        );
        let err = NostrMlsPeeler::default()
            .wrap_group_message(
                &EncryptedPayload {
                    ciphertext: b"inner mls bytes".to_vec(),
                    aad: b"not empty".to_vec(),
                },
                &ctx,
            )
            .await
            .expect_err("non-empty AAD is off-spec for kind-445");
        assert!(matches!(err, PeelerError::WrapFailed(_)));
    }

    #[tokio::test]
    async fn group_wrap_metadata_adds_expiration_for_app_messages() {
        let group_id = vec![0x99; 32];
        let ctx = GroupContextSnapshot::new(
            EpochId(9),
            HashMap::from([(DEFAULT_EXPORTER_LABEL.to_string(), vec![0x7a; 32])]),
            Some(group_id.clone()),
        );
        let wrapped = NostrMlsPeeler::default()
            .wrap_group_message_with_metadata(
                &EncryptedPayload {
                    ciphertext: b"inner mls bytes".to_vec(),
                    aad: vec![],
                },
                &ctx,
                &GroupMessageMetadata::application(1_700_000_000, Some(60)),
            )
            .await
            .expect("wrap succeeds");

        let event = NostrTransportEvent::from_transport_message(&wrapped).expect("payload parses");
        let expected_group_id = hex::encode(group_id);
        assert_eq!(event.tag_value("h"), Some(expected_group_id.as_str()));
        assert_eq!(event.tag_value(EXPIRATION_TAG), Some("1700000060"));
        assert_eq!(event.tag_values(EXPIRATION_TAG).len(), 1);
    }

    #[tokio::test]
    async fn group_wrap_binds_outer_created_at_to_inner_for_app_messages() {
        // Package E (#630 cross-client): the outer kind-445 `created_at` is bound
        // to the inner app event's sender-authenticated `created_at`, so the
        // sender and every receiver record the same `recorded_at` for a message.
        let group_id = vec![0x99; 32];
        let ctx = GroupContextSnapshot::new(
            EpochId(9),
            HashMap::from([(DEFAULT_EXPORTER_LABEL.to_string(), vec![0x7a; 32])]),
            Some(group_id),
        );
        let inner_created_at = 1_700_000_123;
        let wrapped = NostrMlsPeeler::default()
            .wrap_group_message_with_metadata(
                &EncryptedPayload {
                    ciphertext: b"inner mls bytes".to_vec(),
                    aad: vec![],
                },
                &ctx,
                &GroupMessageMetadata::application(inner_created_at, None),
            )
            .await
            .expect("wrap succeeds");

        let event = NostrTransportEvent::from_transport_message(&wrapped).expect("payload parses");
        assert_eq!(event.created_at, inner_created_at);
    }

    #[tokio::test]
    async fn group_wrap_metadata_omits_expiration_for_control_or_disabled_retention() {
        let ctx = GroupContextSnapshot::new(
            EpochId(9),
            HashMap::from([(DEFAULT_EXPORTER_LABEL.to_string(), vec![0x7a; 32])]),
            Some(vec![0x99; 32]),
        );
        for metadata in [
            GroupMessageMetadata::commit_or_proposal(),
            GroupMessageMetadata::application(1_700_000_000, None),
            GroupMessageMetadata::application(1_700_000_000, Some(0)),
        ] {
            let wrapped = NostrMlsPeeler::default()
                .wrap_group_message_with_metadata(
                    &EncryptedPayload {
                        ciphertext: b"inner mls bytes".to_vec(),
                        aad: vec![],
                    },
                    &ctx,
                    &metadata,
                )
                .await
                .expect("wrap succeeds");
            let event =
                NostrTransportEvent::from_transport_message(&wrapped).expect("payload parses");
            assert_eq!(event.tag_value(EXPIRATION_TAG), None);
        }
    }

    #[tokio::test]
    async fn group_wrap_rejects_overflowing_expiration_metadata() {
        let ctx = GroupContextSnapshot::new(
            EpochId(9),
            HashMap::from([(DEFAULT_EXPORTER_LABEL.to_string(), vec![0x7a; 32])]),
            Some(vec![0x99; 32]),
        );

        let err = NostrMlsPeeler::default()
            .wrap_group_message_with_metadata(
                &EncryptedPayload {
                    ciphertext: b"inner mls bytes".to_vec(),
                    aad: vec![],
                },
                &ctx,
                &GroupMessageMetadata::application(u64::MAX, Some(1)),
            )
            .await
            .expect_err("overflow should fail closed");

        assert!(matches!(err, PeelerError::WrapFailed(_)));
    }

    #[tokio::test]
    async fn kind_445_pubkey_is_ephemeral_and_unique_across_sends() {
        // spec/transports/nostr.md:32-34 — the kind-445 pubkey MUST be a fresh
        // ephemeral key, MUST NOT be the account identity, and MUST NOT repeat.
        let account = sender_keys();
        let ctx = GroupContextSnapshot::new(
            EpochId(9),
            HashMap::from([(DEFAULT_EXPORTER_LABEL.to_string(), vec![0x7a; 32])]),
            Some(vec![0x99; 32]),
        );
        let peeler = NostrMlsPeeler::new().with_welcome_signer(account.clone());
        let payload = EncryptedPayload {
            ciphertext: b"inner mls bytes".to_vec(),
            aad: vec![],
        };

        let first = peeler
            .wrap_group_message(&payload, &ctx)
            .await
            .expect("wrap one");
        let second = peeler
            .wrap_group_message(&payload, &ctx)
            .await
            .expect("wrap two");

        let first_event = NostrTransportEvent::from_transport_message(&first).unwrap();
        let second_event = NostrTransportEvent::from_transport_message(&second).unwrap();

        let account_pubkey_hex = account.public_key().to_hex();
        assert_ne!(first_event.pubkey, account_pubkey_hex);
        assert_ne!(second_event.pubkey, account_pubkey_hex);
        assert_ne!(first_event.pubkey, second_event.pubkey);
        // Each ephemeral event is independently signed and verifies.
        assert!(first_event.to_verified_nostr_event().is_ok());
        assert!(second_event.to_verified_nostr_event().is_ok());
    }

    #[tokio::test]
    async fn group_peel_rejects_non_base64_and_short_content() {
        let secret = vec![0x7a; 32];
        let group_id = vec![0x99; 32];
        let ctx = GroupContextSnapshot::new(
            EpochId(9),
            HashMap::from([(DEFAULT_EXPORTER_LABEL.to_string(), secret)]),
            Some(group_id.clone()),
        );
        let peeler = NostrMlsPeeler::default();

        // Not valid base64.
        let bad_msg = signed_group_transport_message(&group_id, "!!! not base64 !!!");
        assert!(matches!(
            peeler.peel_group_message(&bad_msg, &ctx).await,
            Err(PeelerError::Malformed(_))
        ));

        // Valid base64 but fewer than 28 decoded bytes.
        let short_msg =
            signed_group_transport_message(&group_id, &BASE64_STANDARD.encode([0u8; 10]));
        assert!(matches!(
            peeler.peel_group_message(&short_msg, &ctx).await,
            Err(PeelerError::Malformed(_))
        ));
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
        let sender_peeler = NostrMlsPeeler::new().with_welcome_signer(sender.clone());
        let receiver_peeler = NostrMlsPeeler::new().with_welcome_signer(receiver.clone());

        let wrapped = sender_peeler
            .wrap_welcome_with_metadata(
                &EncryptedPayload {
                    ciphertext: b"mls welcome bytes".to_vec(),
                    aad: vec![],
                },
                &recipient,
                &sample_welcome_metadata(),
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
        let sender_peeler = NostrMlsPeeler::new().with_welcome_signer(sender);
        let wrong_peeler = NostrMlsPeeler::new().with_welcome_signer(wrong_receiver);
        let wrapped = sender_peeler
            .wrap_welcome_with_metadata(
                &EncryptedPayload {
                    ciphertext: b"mls welcome bytes".to_vec(),
                    aad: vec![],
                },
                &recipient,
                &sample_welcome_metadata(),
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
        let peeler = NostrMlsPeeler::new().with_welcome_signer(sender.clone());
        let mut wrapped = peeler
            .wrap_welcome_with_metadata(
                &EncryptedPayload {
                    ciphertext: b"mls welcome bytes".to_vec(),
                    aad: vec![],
                },
                &recipient,
                &sample_welcome_metadata(),
            )
            .await
            .expect("wrap succeeds");
        wrapped.envelope = TransportEnvelope::Welcome {
            recipient: MemberId::new(vec![0x55; 32]),
        };

        let err = NostrMlsPeeler::new()
            .with_welcome_signer(receiver)
            .peel_welcome(&wrapped)
            .await
            .expect_err("mismatched route should not peel");

        assert!(matches!(err, PeelerError::Malformed(_)));
    }

    #[tokio::test]
    async fn welcome_peel_rejects_unsigned_gift_wrap_after_route_mapping() {
        let receiver = receiver_keys();
        let unsigned = NostrTransportEvent {
            id: "33".repeat(32),
            pubkey: "44".repeat(32),
            created_at: 1_700_000_001,
            kind: KIND_NIP59_GIFT_WRAP,
            tags: vec![vec!["p".into(), receiver.public_key().to_hex()]],
            content: "gift wrap body".into(),
            sig: None,
        }
        .to_transport_message()
        .expect("route mapping accepts unverified gift-wrap envelope");

        let err = NostrMlsPeeler::new()
            .with_welcome_signer(receiver)
            .peel_welcome(&unsigned)
            .await
            .expect_err("peeling verifies the signed gift wrap");

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

        let err = NostrMlsPeeler::new()
            .with_welcome_signer(receiver)
            .peel_welcome(&wrapped)
            .await
            .expect_err("wrong rumor kind should not peel");

        assert!(matches!(err, PeelerError::Malformed(_)));
    }

    #[tokio::test]
    async fn welcome_wrap_emits_required_key_package_and_relays_tags() {
        let sender = sender_keys();
        let receiver = receiver_keys();
        let recipient = MemberId::new(receiver.public_key().to_bytes().to_vec());
        let metadata = sample_welcome_metadata();
        let wrapped = NostrMlsPeeler::new()
            .with_welcome_signer(sender.clone())
            .wrap_welcome_with_metadata(
                &EncryptedPayload {
                    ciphertext: b"mls welcome bytes".to_vec(),
                    aad: vec![],
                },
                &recipient,
                &metadata,
            )
            .await
            .expect("wrap succeeds");
        let gift_wrap = NostrTransportEvent::from_transport_message(&wrapped)
            .unwrap()
            .to_verified_nostr_event()
            .unwrap();
        let unwrapped = nostr::nips::nip59::extract_rumor(&receiver, &gift_wrap)
            .await
            .expect("unwrap");
        assert_eq!(
            rumor_tag_value(&unwrapped.rumor, KEY_PACKAGE_EVENT_TAG),
            Some(hex::encode(metadata.key_package_event_id.as_slice()).as_str())
        );
        assert_eq!(
            rumor_tag_values(&unwrapped.rumor, WELCOME_RELAYS_TAG),
            Some(vec!["wss://group-a.example", "wss://group-b.example"])
        );
        assert_eq!(rumor_tag_value(&unwrapped.rumor, "encoding"), None);
        // Content is base64 of the welcome bytes.
        assert_eq!(
            BASE64_STANDARD
                .decode(unwrapped.rumor.content.as_bytes())
                .unwrap(),
            b"mls welcome bytes".to_vec()
        );
    }

    #[tokio::test]
    async fn welcome_peel_rejects_missing_key_package_or_relays_tags() {
        let sender = sender_keys();
        let receiver = receiver_keys();
        let receiver_peeler = NostrMlsPeeler::new().with_welcome_signer(receiver.clone());

        let missing_key_package = welcome_rumor_gift_wrap(&sender, &receiver, false, true).await;
        assert!(matches!(
            receiver_peeler.peel_welcome(&missing_key_package).await,
            Err(PeelerError::Malformed(_))
        ));

        let missing_relays = welcome_rumor_gift_wrap(&sender, &receiver, true, false).await;
        assert!(matches!(
            receiver_peeler.peel_welcome(&missing_relays).await,
            Err(PeelerError::Malformed(_))
        ));
    }

    /// Build a kind-444 welcome rumor gift wrap with optional required tags,
    /// used to exercise receiver-side metadata validation.
    async fn welcome_rumor_gift_wrap(
        sender: &nostr::Keys,
        receiver: &nostr::Keys,
        include_key_package: bool,
        include_relays: bool,
    ) -> TransportMessage {
        let mut builder = EventBuilder::new(
            Kind::Custom(KIND_MARMOT_WELCOME_RUMOR),
            BASE64_STANDARD.encode(b"mls welcome bytes"),
        );
        let mut tags = Vec::new();
        if include_key_package {
            tags.push(Tag::custom(
                nostr::TagKind::custom(KEY_PACKAGE_EVENT_TAG),
                [hex::encode(
                    sample_welcome_metadata().key_package_event_id.as_slice(),
                )],
            ));
        }
        if include_relays {
            tags.push(Tag::custom(
                nostr::TagKind::custom(WELCOME_RELAYS_TAG),
                ["wss://group-a.example"],
            ));
        }
        if !tags.is_empty() {
            builder = builder.tags(tags);
        }
        let rumor = builder.build(sender.public_key());
        let gift_wrap = EventBuilder::gift_wrap(sender, &receiver.public_key(), rumor, [])
            .await
            .unwrap();
        NostrTransportEvent::from_nostr_event(&gift_wrap)
            .unwrap()
            .to_transport_message()
            .unwrap()
    }

    fn signed_group_transport_message(group_id: &[u8], content: &str) -> TransportMessage {
        let signed = EventBuilder::new(Kind::Custom(KIND_MARMOT_GROUP_MESSAGE as u16), content)
            .tags([Tag::custom(
                nostr::TagKind::custom(GROUP_TAG),
                [hex::encode(group_id)],
            )])
            .sign_with_keys(&Keys::generate())
            .expect("sign kind-445");
        NostrTransportEvent::from_nostr_event(&signed)
            .unwrap()
            .to_transport_message()
            .unwrap()
    }

    fn sample_welcome_metadata() -> WelcomeMetadata {
        WelcomeMetadata {
            key_package_event_id: MessageId::new(vec![0x44; 32]),
            relays: vec![
                TransportEndpoint("wss://group-a.example".into()),
                TransportEndpoint("wss://group-b.example".into()),
            ],
        }
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
