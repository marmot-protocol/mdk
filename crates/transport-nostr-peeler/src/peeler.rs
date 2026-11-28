use crate::error::to_peeler_error;
use crate::event::decode_hex_exact;
use crate::{
    DEFAULT_EXPORTER_LABEL, EXPIRATION_TAG, GROUP_TAG, KIND_MARMOT_GROUP_MESSAGE,
    NOSTR_GROUP_CONTENT_MIN_LEN, NOSTR_GROUP_KEY_LEN, NostrTransportEvent,
};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use cgka_traits::error::PeelerError;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{PeeledContent, PeeledMessage};
use cgka_traits::peeler::{GroupMessageMetadata, PreparedGroupMessage, TransportPeeler};
use cgka_traits::transport::{EncryptedPayload, TransportEnvelope, TransportMessage};
use cgka_traits::types::GroupId;
use cgka_traits::{EntropySource, OsEntropy, SystemWallClock, WallClock};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use nostr::prelude::{
    Event, EventBuilder, FinalizeUnsignedEvent, Keys, Kind, SecretKey, Tag,
    Timestamp as NostrTimestamp,
};
use secp256k1::{All, Secp256k1};
use std::fmt;
use std::sync::{Arc, OnceLock};
use zeroize::Zeroizing;

const NONCE_LEN: usize = 12;
const MAX_EPHEMERAL_KEY_DRAWS: usize = 16;

/// Empty AAD for the outer kind-445 ChaCha20-Poly1305 sealing
/// (`spec/transports/nostr.md`: `aad = ""`).
const GROUP_AAD: &[u8] = b"";

/// Nostr implementation of the Marmot group-message peeler.
#[derive(Clone)]
pub struct NostrMlsPeeler {
    exporter_label: String,
    entropy: Arc<dyn EntropySource>,
    clock: Arc<dyn WallClock>,
    signing_context: Arc<OnceLock<Secp256k1<All>>>,
}

impl fmt::Debug for NostrMlsPeeler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NostrMlsPeeler")
            .field("exporter_label", &self.exporter_label)
            .finish_non_exhaustive()
    }
}

impl NostrMlsPeeler {
    /// Use the supplied entropy for kind-445 signing and sealing, and the
    /// supplied clock for default event timestamps.
    ///
    /// The peeler does not hold the account identity: kind-445 group events are
    /// signed by a fresh ephemeral key per event
    /// (`spec/transports/nostr.md:32-34`), and NIP-59 account-inbox messages
    /// are sealed by [`crate::NostrInboxSealer`].
    pub fn new(entropy: Arc<dyn EntropySource>, clock: Arc<dyn WallClock>) -> Self {
        Self {
            exporter_label: DEFAULT_EXPORTER_LABEL.into(),
            entropy,
            clock,
            signing_context: Arc::new(OnceLock::new()),
        }
    }

    /// Override the exporter label used for kind-445 group envelopes.
    pub fn with_exporter_label(mut self, label: impl Into<String>) -> Self {
        self.exporter_label = label.into();
        self
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

    fn ephemeral_secret(&self) -> Result<SecretKey, PeelerError> {
        let mut candidate = Zeroizing::new([0_u8; 32]);
        for _ in 0..MAX_EPHEMERAL_KEY_DRAWS {
            self.entropy.fill_bytes(&mut candidate[..]);
            if let Ok(secret) = SecretKey::from_slice(&candidate[..]) {
                return Ok(secret);
            }
        }
        Err(PeelerError::WrapFailed(
            "invalid ephemeral kind-445 secret key".into(),
        ))
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
        self.entropy.fill_bytes(&mut nonce);
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
        let secret = self.ephemeral_secret()?;
        let context = self.signing_context.get_or_init(|| {
            let mut context = Secp256k1::new();
            let mut seed = Zeroizing::new([0_u8; 32]);
            self.entropy.fill_bytes(&mut seed[..]);
            context.seeded_randomize(&seed);
            context
        });
        let ephemeral = Keys::new_with_ctx(context, secret);
        let mut tags = vec![Tag::custom(GROUP_TAG, [hex::encode(group_id)])];
        if let Some(expiration) = metadata.and_then(GroupMessageMetadata::expiration_timestamp) {
            tags.push(Tag::custom(EXPIRATION_TAG, [expiration.to_string()]));
        }
        // Package E (#630 cross-client): bind the outer kind-445 `created_at` to
        // the inner app event's sender-authenticated `created_at` so the sender
        // and receivers agree on `recorded_at`. Commits and proposals use wrap time.
        let created_at = metadata
            .and_then(GroupMessageMetadata::outer_created_at)
            .unwrap_or_else(|| self.clock.now().0);
        let unsigned = EventBuilder::new(Kind::Custom(KIND_MARMOT_GROUP_MESSAGE as u16), content)
            .tags(tags)
            .custom_created_at(NostrTimestamp::from_secs(created_at))
            .finalize_unsigned(ephemeral.public_key());
        let id = unsigned.compute_id();
        let mut aux = Zeroizing::new([0_u8; 32]);
        self.entropy.fill_bytes(&mut aux[..]);
        let sig = ephemeral.sign_schnorr_with_aux_rand(context, id.as_bytes(), &aux);
        let signed = Event::new(
            id,
            unsigned.pubkey,
            unsigned.created_at,
            unsigned.kind,
            unsigned.tags,
            unsigned.content,
            sig,
        );
        let event = NostrTransportEvent::from_nostr_event(&signed).map_err(to_peeler_error)?;
        event.to_transport_message().map_err(to_peeler_error)
    }
}

impl Default for NostrMlsPeeler {
    fn default() -> Self {
        Self::new(Arc::new(OsEntropy), Arc::new(SystemWallClock))
    }
}

impl TransportPeeler for NostrMlsPeeler {
    fn prepare_group_message<'a>(
        &self,
        msg: &'a TransportMessage,
    ) -> Result<PreparedGroupMessage<'a>, PeelerError> {
        let event = NostrTransportEvent::from_transport_message(msg).map_err(to_peeler_error)?;
        if event.kind != KIND_MARMOT_GROUP_MESSAGE {
            return Err(PeelerError::Malformed(format!(
                "expected kind {KIND_MARMOT_GROUP_MESSAGE}, got {}",
                event.kind
            )));
        }
        ensure_group_routing_matches(&event, msg)?;
        // The ingest boundary verifies signatures. Bind arbitrary message
        // payloads to their admitted identity without another SDK round trip.
        ensure_event_identity_matches(&event, msg)?;

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
        Ok(PreparedGroupMessage {
            message: msg,
            content: decoded.into(),
        })
    }

    fn peel_group_message(
        &self,
        prepared: &PreparedGroupMessage<'_>,
        ctx: &GroupContextSnapshot,
    ) -> Result<PeeledMessage, PeelerError> {
        // Prepared bytes belong to this operation, not a cross-input cache.
        let Some((nonce, ciphertext)) = prepared.content.split_at_checked(NONCE_LEN) else {
            return Err(PeelerError::Malformed(
                "prepared content is too short".into(),
            ));
        };
        let msg = prepared.message;

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

    fn wrap_group_message(
        &self,
        payload: &EncryptedPayload,
        ctx: &GroupContextSnapshot,
    ) -> Result<TransportMessage, PeelerError> {
        self.wrap_group_message_inner(payload, ctx, None)
    }

    fn wrap_group_message_with_metadata(
        &self,
        payload: &EncryptedPayload,
        ctx: &GroupContextSnapshot,
        metadata: &GroupMessageMetadata,
    ) -> Result<TransportMessage, PeelerError> {
        self.wrap_group_message_inner(payload, ctx, Some(metadata))
    }
}

fn transport_group_id(msg: &TransportMessage) -> Option<GroupId> {
    match &msg.envelope {
        TransportEnvelope::GroupMessage { transport_group_id } => {
            Some(GroupId::new(transport_group_id.clone()))
        }
        TransportEnvelope::Welcome { .. } => None,
    }
}

pub(crate) fn ensure_event_identity_matches(
    event: &NostrTransportEvent,
    msg: &TransportMessage,
) -> Result<(), PeelerError> {
    let event_id = event.computed_id();
    if !event.id.eq_ignore_ascii_case(&event_id)
        || decode_hex_exact("event id", &event_id, 32).map_err(to_peeler_error)?
            != msg.id.as_slice()
    {
        return Err(PeelerError::InvalidSignature);
    }
    Ok(())
}

fn ensure_group_routing_matches(
    event: &NostrTransportEvent,
    msg: &TransportMessage,
) -> Result<(), PeelerError> {
    let event_group_id = event
        .kind_445_transport_group_id()
        .map_err(to_peeler_error)?;
    match &msg.envelope {
        TransportEnvelope::GroupMessage { transport_group_id }
            if *transport_group_id == event_group_id =>
        {
            Ok(())
        }
        TransportEnvelope::GroupMessage { .. } => Err(PeelerError::WrongRecipient),
        TransportEnvelope::Welcome { .. } => Err(PeelerError::Malformed(
            "group peeler received welcome envelope".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DEFAULT_EXPORTER_LABEL, KIND_MARMOT_GROUP_MESSAGE};
    use cgka_traits::Timestamp;
    use cgka_traits::group_context::GroupContextSnapshot;
    use cgka_traits::ingest::PeeledContent;
    use cgka_traits::types::EpochId;
    use nostr::prelude::FinalizeEvent;
    use rand::{RngCore, SeedableRng, rngs::StdRng};
    use std::collections::HashMap;
    use std::sync::Mutex;

    const FIXED_CREATED_AT: Timestamp = Timestamp(1_700_000_321);

    struct FixedClock;

    impl WallClock for FixedClock {
        fn now(&self) -> Timestamp {
            FIXED_CREATED_AT
        }

        fn now_ms(&self) -> u64 {
            FIXED_CREATED_AT.0 * 1_000
        }
    }

    struct TestEntropy(Mutex<StdRng>);

    impl EntropySource for TestEntropy {
        fn fill_bytes(&self, dest: &mut [u8]) {
            self.0.lock().unwrap().fill_bytes(dest);
        }
    }

    fn group_wrap_inputs() -> (EncryptedPayload, GroupContextSnapshot) {
        let payload = EncryptedPayload {
            ciphertext: b"inner mls bytes".to_vec(),
            aad: vec![],
        };
        let ctx = GroupContextSnapshot::new(
            EpochId(9),
            HashMap::from([(
                DEFAULT_EXPORTER_LABEL.into(),
                vec![0x7a; NOSTR_GROUP_KEY_LEN],
            )]),
            Some(vec![0x99; 32]),
        );
        (payload, ctx)
    }

    #[test]
    fn kind_445_uses_sources() {
        let (payload, ctx) = group_wrap_inputs();
        let peeler = || {
            NostrMlsPeeler::new(
                Arc::new(TestEntropy(Mutex::new(StdRng::seed_from_u64(3497)))),
                Arc::new(FixedClock),
            )
        };
        let first = peeler();
        let a = first.wrap_group_message(&payload, &ctx).unwrap();
        let b = peeler().wrap_group_message(&payload, &ctx).unwrap();
        assert_eq!(a.timestamp, FIXED_CREATED_AT);
        assert_eq!(b.timestamp, FIXED_CREATED_AT);

        let a_dto = NostrTransportEvent::from_transport_message(&a).unwrap();
        let b_dto = NostrTransportEvent::from_transport_message(&b).unwrap();
        let nonce = |event: &NostrTransportEvent| -> [u8; NONCE_LEN] {
            BASE64_STANDARD.decode(&event.content).unwrap()[..NONCE_LEN]
                .try_into()
                .unwrap()
        };
        assert_eq!(nonce(&a_dto), nonce(&b_dto));
        assert_eq!(a_dto.pubkey, b_dto.pubkey);
        assert_eq!(a_dto.sig, b_dto.sig);
        for (dto, message) in [(&a_dto, &a), (&b_dto, &b)] {
            assert_eq!(dto.created_at, FIXED_CREATED_AT.0);
            let verified = dto.to_verified_nostr_event().unwrap();
            assert_eq!(verified.id.as_bytes(), message.id.as_slice());
        }

        let explicit = 1_700_000_123;
        let c = first
            .wrap_group_message_with_metadata(
                &payload,
                &ctx,
                &GroupMessageMetadata::application(explicit, None),
            )
            .unwrap();
        assert_eq!(c.timestamp, Timestamp(explicit));
        let c = NostrTransportEvent::from_transport_message(&c).unwrap();
        assert_eq!(c.created_at, explicit);
        assert_ne!(nonce(&a_dto), nonce(&c));
        assert_ne!(a_dto.pubkey, c.pubkey);
    }

    #[test]
    fn kind_445_rejects_bad_scalar() {
        struct ZeroEntropy;

        impl EntropySource for ZeroEntropy {
            fn fill_bytes(&self, dest: &mut [u8]) {
                dest.fill(0);
            }
        }

        let (payload, ctx) = group_wrap_inputs();
        let peeler = NostrMlsPeeler::new(Arc::new(ZeroEntropy), Arc::new(FixedClock));
        let err = peeler.wrap_group_message(&payload, &ctx).unwrap_err();
        assert!(
            matches!(err, PeelerError::WrapFailed(reason) if reason == "invalid ephemeral kind-445 secret key")
        );
    }

    #[test]
    fn group_wrap_and_peel_round_trips_mls_bytes() {
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

        let prepared = peeler.prepare_group_message(&wrapped).unwrap();
        let wrong_context = GroupContextSnapshot::new(
            EpochId(10),
            HashMap::from([(DEFAULT_EXPORTER_LABEL.to_string(), vec![0x7b; 32])]),
            Some(group_id),
        );
        assert!(matches!(
            peeler.peel_group_message(&prepared, &wrong_context),
            Err(PeelerError::DecryptFailed)
        ));
        let peeled = peeler
            .peel_group_message(&prepared, &ctx)
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

    #[test]
    fn group_peel_rejects_payload_hash_mismatch() {
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
            .expect("wrap succeeds");
        let mut event = NostrTransportEvent::from_transport_message(&wrapped).unwrap();
        event.content.push('A');
        let mut tampered = wrapped;
        tampered.payload = serde_json::to_vec(&event).unwrap();

        assert!(matches!(
            peeler.prepare_group_message(&tampered),
            Err(PeelerError::InvalidSignature)
        ));
    }

    #[test]
    fn group_peel_rejects_payload_identity_mismatch_before_decryption() {
        let group_id = vec![0x99; 32];
        let wrap_ctx = GroupContextSnapshot::new(
            EpochId(9),
            HashMap::from([(
                DEFAULT_EXPORTER_LABEL.to_string(),
                vec![0x7a; NOSTR_GROUP_KEY_LEN],
            )]),
            Some(group_id.clone()),
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
            .expect("wrap succeeds");
        let unrelated = peeler
            .wrap_group_message(
                &EncryptedPayload {
                    ciphertext: b"unrelated inner bytes".to_vec(),
                    aad: vec![],
                },
                &wrap_ctx,
            )
            .expect("second wrap succeeds");
        let mut tampered = wrapped;
        tampered.payload = unrelated.payload;

        let err = peeler
            .prepare_group_message(&tampered)
            .expect_err("different event identity must fail before decryption");

        assert!(matches!(err, PeelerError::InvalidSignature));
    }

    #[test]
    fn group_peel_rejects_extra_tag_before_decryption() {
        let group_id = vec![0x99; 32];
        let signed = EventBuilder::new(
            Kind::Custom(KIND_MARMOT_GROUP_MESSAGE as u16),
            BASE64_STANDARD.encode([0u8; NOSTR_GROUP_CONTENT_MIN_LEN]),
        )
        .tags([
            Tag::custom(GROUP_TAG, [hex::encode(&group_id)]),
            Tag::custom("e", ["11".repeat(32)]),
        ])
        .finalize(&Keys::generate())
        .expect("sign structurally invalid kind-445");
        let event = NostrTransportEvent::from_nostr_event(&signed).expect("map signed event");
        let msg = TransportMessage {
            id: cgka_traits::types::MessageId::new(hex::decode(&event.id).expect("event id hex")),
            payload: serde_json::to_vec(&event).expect("serialize event"),
            timestamp: cgka_traits::transport::Timestamp(event.created_at),
            causal_deps: vec![],
            source: cgka_traits::transport::TransportSource(crate::NOSTR_SOURCE.into()),
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: group_id.clone(),
            },
        };
        let err = NostrMlsPeeler::default()
            .prepare_group_message(&msg)
            .expect_err("extra tag must fail before ciphertext decryption");

        assert!(matches!(err, PeelerError::Malformed(_)));
    }

    #[test]
    fn group_wrap_rejects_non_empty_aad() {
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
            .expect_err("non-empty AAD is off-spec for kind-445");
        assert!(matches!(err, PeelerError::WrapFailed(_)));
    }

    #[test]
    fn group_wrap_metadata_adds_expiration_for_app_messages() {
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
            .expect("wrap succeeds");

        let event = NostrTransportEvent::from_transport_message(&wrapped).expect("payload parses");
        let expected_group_id = hex::encode(group_id);
        assert_eq!(event.tag_value("h"), Some(expected_group_id.as_str()));
        assert_eq!(event.tag_value(EXPIRATION_TAG), Some("1700000060"));
        assert_eq!(event.tag_values(EXPIRATION_TAG).len(), 1);
    }

    /// The bound is exact for an event whose timestamps are as wide as a `u64`
    /// allows, and holds for real wraps across base64 padding boundaries.
    #[test]
    fn group_event_json_len_bound_covers_published_events() {
        for mls_len in [0, 1, 2, 3, 100, 65_000] {
            let widest = NostrTransportEvent {
                id: "a".repeat(64),
                pubkey: "b".repeat(64),
                created_at: u64::MAX,
                kind: KIND_MARMOT_GROUP_MESSAGE,
                tags: vec![
                    vec![GROUP_TAG.to_string(), "c".repeat(64)],
                    vec![EXPIRATION_TAG.to_string(), u64::MAX.to_string()],
                ],
                content: BASE64_STANDARD.encode(vec![0; NOSTR_GROUP_CONTENT_MIN_LEN + mls_len]),
                sig: Some("d".repeat(128)),
            };
            assert_eq!(
                serde_json::to_vec(&widest).unwrap().len(),
                crate::group_event_json_len_bound(mls_len),
                "{mls_len}-byte MLS message"
            );
        }

        let ctx = GroupContextSnapshot::new(
            EpochId(9),
            HashMap::from([(DEFAULT_EXPORTER_LABEL.to_string(), vec![0x7a; 32])]),
            Some(vec![0x99; 32]),
        );
        for (mls_len, metadata) in [
            (0, GroupMessageMetadata::commit_or_proposal()),
            (
                1,
                GroupMessageMetadata::application(1_700_000_000, Some(60)),
            ),
            (2, GroupMessageMetadata::application(1_700_000_000, None)),
            (
                65_000,
                GroupMessageMetadata::application(1_700_000_000, Some(60)),
            ),
        ] {
            let wrapped = NostrMlsPeeler::default()
                .wrap_group_message_with_metadata(
                    &EncryptedPayload {
                        ciphertext: vec![0x42; mls_len],
                        aad: vec![],
                    },
                    &ctx,
                    &metadata,
                )
                .expect("wrap succeeds");
            let event =
                NostrTransportEvent::from_transport_message(&wrapped).expect("payload parses");
            assert!(event.sig.is_some());
            assert!(
                serde_json::to_vec(&event).unwrap().len()
                    <= crate::group_event_json_len_bound(mls_len),
                "{mls_len}-byte MLS message"
            );
        }
    }

    #[test]
    fn group_peel_accepts_valid_events_before_and_after_expiration() {
        let group_id = vec![0x99; 32];
        let ctx = GroupContextSnapshot::new(
            EpochId(9),
            HashMap::from([(DEFAULT_EXPORTER_LABEL.to_string(), vec![0x7a; 32])]),
            Some(group_id),
        );
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for (label, created_at, retention_seconds) in
            [("already expired", 1, 1), ("not yet expired", now, 3_600)]
        {
            let wrapped = NostrMlsPeeler::default()
                .wrap_group_message_with_metadata(
                    &EncryptedPayload {
                        ciphertext: b"inner mls bytes".to_vec(),
                        aad: vec![],
                    },
                    &ctx,
                    &GroupMessageMetadata::application(created_at, Some(retention_seconds)),
                )
                .expect("wrap succeeds");

            NostrMlsPeeler::default()
                .peel_group_message(
                    &NostrMlsPeeler::default()
                        .prepare_group_message(&wrapped)
                        .unwrap(),
                    &ctx,
                )
                .unwrap_or_else(|err| panic!("{label} event should peel: {err}"));
        }
    }

    #[test]
    fn group_wrap_binds_outer_created_at_to_inner_for_app_messages() {
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
            .expect("wrap succeeds");

        let event = NostrTransportEvent::from_transport_message(&wrapped).expect("payload parses");
        assert_eq!(event.created_at, inner_created_at);
    }

    #[test]
    fn group_wrap_metadata_omits_expiration_for_control_or_disabled_retention() {
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
                .expect("wrap succeeds");
            let event =
                NostrTransportEvent::from_transport_message(&wrapped).expect("payload parses");
            assert_eq!(event.tag_value(EXPIRATION_TAG), None);
        }
    }

    #[test]
    fn group_wrap_omits_unrepresentable_expiration_metadata() {
        let ctx = GroupContextSnapshot::new(
            EpochId(9),
            HashMap::from([(DEFAULT_EXPORTER_LABEL.to_string(), vec![0x7a; 32])]),
            Some(vec![0x99; 32]),
        );

        let wrapped = NostrMlsPeeler::default()
            .wrap_group_message_with_metadata(
                &EncryptedPayload {
                    ciphertext: b"inner mls bytes".to_vec(),
                    aad: vec![],
                },
                &ctx,
                &GroupMessageMetadata::application(u64::MAX, Some(1)),
            )
            .expect("an optional expiration overflow does not reject the message");

        let event = NostrTransportEvent::from_transport_message(&wrapped).expect("payload parses");
        assert_eq!(event.created_at, u64::MAX);
        assert_eq!(event.tag_value(EXPIRATION_TAG), None);
    }

    #[test]
    fn kind_445_pubkey_is_ephemeral_and_unique_across_sends() {
        // spec/transports/nostr.md:32-34 — the kind-445 pubkey MUST be a fresh
        // ephemeral key and MUST NOT repeat. The peeler holds no account key.
        let ctx = GroupContextSnapshot::new(
            EpochId(9),
            HashMap::from([(DEFAULT_EXPORTER_LABEL.to_string(), vec![0x7a; 32])]),
            Some(vec![0x99; 32]),
        );
        let peeler = NostrMlsPeeler::default();
        let payload = EncryptedPayload {
            ciphertext: b"inner mls bytes".to_vec(),
            aad: vec![],
        };

        let first = peeler.wrap_group_message(&payload, &ctx).expect("wrap one");
        let second = peeler.wrap_group_message(&payload, &ctx).expect("wrap two");

        let first_event = NostrTransportEvent::from_transport_message(&first).unwrap();
        let second_event = NostrTransportEvent::from_transport_message(&second).unwrap();

        assert_ne!(first_event.pubkey, second_event.pubkey);
        // Each ephemeral event is independently signed and verifies.
        assert!(first_event.to_verified_nostr_event().is_ok());
        assert!(second_event.to_verified_nostr_event().is_ok());
    }

    #[test]
    fn group_peel_rejects_non_base64_and_short_content() {
        let group_id = vec![0x99; 32];
        let peeler = NostrMlsPeeler::default();

        // Not valid base64.
        let bad_msg = signed_group_transport_message(&group_id, "!!! not base64 !!!");
        assert!(matches!(
            peeler.prepare_group_message(&bad_msg),
            Err(PeelerError::Malformed(_))
        ));

        // Valid base64 but fewer than 28 decoded bytes.
        let short_msg =
            signed_group_transport_message(&group_id, &BASE64_STANDARD.encode([0u8; 10]));
        assert!(matches!(
            peeler.prepare_group_message(&short_msg),
            Err(PeelerError::Malformed(_))
        ));
    }

    #[test]
    fn group_peel_with_wrong_secret_fails_cleanly() {
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
            .expect("wrap succeeds");

        let err = peeler
            .peel_group_message(&peeler.prepare_group_message(&wrapped).unwrap(), &peel_ctx)
            .expect_err("wrong secret should not decrypt");

        assert!(matches!(err, PeelerError::DecryptFailed));
    }

    #[test]
    fn group_peel_rejects_mismatched_h_tag_and_envelope() {
        let wrap_ctx = GroupContextSnapshot::new(
            EpochId(9),
            HashMap::from([(DEFAULT_EXPORTER_LABEL.to_string(), vec![0x7a; 32])]),
            Some(vec![0x99; 32]),
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
            .expect("wrap succeeds");
        wrapped.envelope = TransportEnvelope::GroupMessage {
            transport_group_id: vec![0x55; 32],
        };

        let err = peeler
            .prepare_group_message(&wrapped)
            .expect_err("mismatched route should not peel");

        assert!(matches!(err, PeelerError::WrongRecipient));
    }

    fn signed_group_transport_message(group_id: &[u8], content: &str) -> TransportMessage {
        let signed = EventBuilder::new(Kind::Custom(KIND_MARMOT_GROUP_MESSAGE as u16), content)
            .tags([Tag::custom(GROUP_TAG, [hex::encode(group_id)])])
            .finalize(&Keys::generate())
            .expect("sign kind-445");
        NostrTransportEvent::from_nostr_event(&signed)
            .unwrap()
            .to_transport_message()
            .unwrap()
    }
}
