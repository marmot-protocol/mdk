//! NIP-59 sealing and unsealing of account-inbox messages: Welcomes (rumor
//! kind 444) and MDK-private recovery control (rumor kind 1159).

use crate::error::to_peeler_error;
use crate::event::decode_hex_exact;
use crate::peeler::ensure_event_identity_matches;
use crate::signer::{MarmotNostrSigner, SdkSigner};
use crate::{
    GROUP_RECOVERY_PROTOCOL_TAG, GROUP_RECOVERY_PROTOCOL_VERSION, KIND_MARMOT_WELCOME_RUMOR,
    KIND_MDK_GROUP_RECOVERY_RUMOR, KIND_NIP59_GIFT_WRAP, MAX_GROUP_RECOVERY_EVENT_BYTES,
    NostrTransportEvent, RECIPIENT_TAG,
};
use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use cgka_traits::WallClock;
use cgka_traits::engine::{OutboundWelcome, WelcomeMetadata};
use cgka_traits::error::PeelerError;
use cgka_traits::group_recovery::{AuthenticatedGroupRecovery, GroupRecoveryMessage};
use cgka_traits::ingest::{PeeledContent, PeeledMessage};
use cgka_traits::peeler::InboxSealer;
use cgka_traits::transport::{EncryptedPayload, TransportEnvelope, TransportMessage};
use cgka_traits::types::{MemberId, MessageId};
use nostr::nips::nip59::UnwrappedGift;
use nostr::prelude::{
    Event, EventBuilder, FinalizeUnsignedEvent, Kind, PublicKey, RelayUrl, Tag,
    Timestamp as NostrTimestamp, UnsignedEvent,
};
use std::fmt;
use std::sync::Arc;

const KEY_PACKAGE_EVENT_TAG: &str = "e";
const WELCOME_RELAYS_TAG: &str = "relays";
/// Bound on the welcome rumor `relays` tag value count (#392). Parity with
/// `MAX_RELAY_ENDPOINTS_PER_ROUTE` in `marmot-app`'s relay safety policy.
const MAX_WELCOME_RELAYS: usize = 16;
/// Bound on each welcome rumor relay URL length in bytes (#392).
const MAX_WELCOME_RELAY_URL_LEN: usize = 512;

/// JSON bytes of a signed kind-13 seal with empty tags and empty content,
/// for a 10-digit `created_at`.
const SEAL_JSON_OVERHEAD: usize = 343;
/// JSON bytes of a signed kind-1059 wrap with one `["p", <hex>]` tag and
/// empty content, for a 10-digit `created_at`.
const WRAP_JSON_OVERHEAD: usize = 417;
/// x coordinate of the secp256k1 generator: a valid x-only key that stands in
/// for the signer's when only the serialized width matters.
const WIDTH_PROBE_KEY: [u8; 32] = [
    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
    0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
];

/// Canonical public event identities established by one successful Welcome peel.
/// The rumor ID is computed from authenticated fields, never read from the
/// optional, self-reported ID on an unsigned rumor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WelcomePeelProvenance {
    pub rumor_event_id: [u8; 32],
    pub key_package_event_id: [u8; 32],
}

/// A gift wrap to the account, opened once.
#[derive(Debug)]
pub enum AccountGiftWrap {
    /// A Welcome rumor, peeled and validated.
    Welcome(Box<PeeledMessage>, WelcomePeelProvenance),
    /// A private recovery control, authenticated and validated, not a Welcome.
    GroupRecovery(Box<PeeledMessage>),
    /// Any other rumor. NIP-59 verified the wrap and seal and matched the
    /// rumor's author to the seal's; nothing else about it is checked.
    Other(Box<UnwrappedGift>),
}

impl AccountGiftWrap {
    /// The Welcome or private recovery control, with provenance only for a Welcome.
    pub fn into_welcome(
        self,
    ) -> Result<(PeeledMessage, Option<WelcomePeelProvenance>), PeelerError> {
        match self {
            Self::Welcome(peeled, provenance) => Ok((*peeled, Some(provenance))),
            Self::GroupRecovery(peeled) => Ok((*peeled, None)),
            Self::Other(unwrapped) => Err(PeelerError::Malformed(format!(
                "expected Marmot welcome rumor kind {KIND_MARMOT_WELCOME_RUMOR}, got {}",
                u16::from(unwrapped.rumor.kind)
            ))),
        }
    }
}

/// Nostr implementation of the account-inbox sealer. It holds the account
/// signer, which may be remote, and the clock that stamps rumors.
#[derive(Clone)]
pub struct NostrInboxSealer {
    signer: Arc<dyn MarmotNostrSigner>,
    clock: Arc<dyn WallClock>,
}

impl fmt::Debug for NostrInboxSealer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NostrInboxSealer").finish_non_exhaustive()
    }
}

impl NostrInboxSealer {
    /// Seal and unseal with `signer`; stamp rumors with `clock`.
    pub fn new(signer: Arc<dyn MarmotNostrSigner>, clock: Arc<dyn WallClock>) -> Self {
        Self { signer, clock }
    }

    /// Unseal once and return public Welcome IDs only for authenticated Welcomes.
    /// Account-control rumors have no Welcome provenance. [`InboxSealer::unseal`]
    /// discards this metadata without repeating decryption.
    pub async fn unseal_with_provenance(
        &self,
        msg: &TransportMessage,
    ) -> Result<(PeeledMessage, Option<WelcomePeelProvenance>), PeelerError> {
        self.open_account_gift_wrap(msg).await?.into_welcome()
    }

    /// Open a gift wrap to the account once. A Welcome rumor is peeled as
    /// [`Self::unseal_with_provenance`] peels it; any other rumor comes
    /// back opened and unread, for the caller to read under its own rules
    /// (device pairing's, for one).
    pub async fn open_account_gift_wrap(
        &self,
        msg: &TransportMessage,
    ) -> Result<AccountGiftWrap, PeelerError> {
        let signer = &self.signer;
        let event = NostrTransportEvent::from_transport_message(msg).map_err(to_peeler_error)?;
        if event.kind != KIND_NIP59_GIFT_WRAP {
            return Err(PeelerError::Malformed(format!(
                "expected kind {KIND_NIP59_GIFT_WRAP}, got {}",
                event.kind
            )));
        }
        ensure_welcome_routing_matches(&event, msg)?;
        let recipient = event
            .single_tag_value(RECIPIENT_TAG)
            .map_err(to_peeler_error)?;
        let recipient =
            decode_hex_exact("recipient p tag", recipient, 32).map_err(to_peeler_error)?;
        ensure_event_identity_matches(&event, msg)?;
        if event.sig.is_none() {
            return Err(PeelerError::InvalidSignature);
        }
        // NIP-59 verifies the outer event and seal. Decode the original payload
        // directly instead of rebuilding and verifying the DTO a second time.
        let gift_wrap =
            Event::from_json(&msg.payload).map_err(|_| PeelerError::InvalidSignature)?;
        let unwrapped =
            nostr::nips::nip59::extract_rumor_async(&SdkSigner(signer.clone()), &gift_wrap)
                .await
                .map_err(map_nip59_error)?;

        // The outer carrier carries no recovery discriminator. Only the verified
        // seal author's authenticated inner kind and singleton version dispatch.
        if unwrapped.rumor.kind == Kind::Custom(KIND_MDK_GROUP_RECOVERY_RUMOR) {
            let local = signer
                .get_public_key()
                .await
                .map_err(|_| PeelerError::DecryptFailed)?;
            if recipient.as_slice() != local.as_bytes() {
                return Err(PeelerError::WrongRecipient);
            }
            if msg.payload.len() > MAX_GROUP_RECOVERY_EVENT_BYTES {
                return Err(PeelerError::Malformed(
                    "recovery carrier exceeds limit".into(),
                ));
            }
            let protocol = rumor_single_tag(&unwrapped.rumor, GROUP_RECOVERY_PROTOCOL_TAG)?;
            if protocol.len() != 2 || protocol[1] != GROUP_RECOVERY_PROTOCOL_VERSION {
                return Err(PeelerError::Malformed(
                    "invalid authenticated recovery protocol tag".into(),
                ));
            }
            let inner_recipient = rumor_single_tag(&unwrapped.rumor, RECIPIENT_TAG)?;
            if inner_recipient.len() != 2
                || decode_hex_exact("recovery recipient", &inner_recipient[1], 32)
                    .map_err(to_peeler_error)?
                    != recipient
            {
                return Err(PeelerError::WrongRecipient);
            }
            let message = GroupRecoveryMessage::decode(unwrapped.rumor.content.as_bytes())?;
            return Ok(AccountGiftWrap::GroupRecovery(Box::new(PeeledMessage {
                id: msg.id.clone(),
                group_id: None,
                sender: None,
                content: PeeledContent::GroupRecovery {
                    recovery: Box::new(AuthenticatedGroupRecovery {
                        sender: MemberId::new(unwrapped.sender.to_bytes().to_vec()),
                        message,
                    }),
                },
                origin: msg.clone(),
            })));
        }
        if unwrapped.rumor.kind != Kind::Custom(KIND_MARMOT_WELCOME_RUMOR) {
            return Ok(AccountGiftWrap::Other(Box::new(unwrapped)));
        }

        // NIP-59 verifies the signed gift wrap and seal and matches the rumor
        // author to the seal. It does not verify UnsignedEvent.id; compute the
        // canonical ID from those authenticated rumor fields instead.
        let rumor_event_id = unwrapped.rumor.compute_id().to_bytes();
        // spec/transports/nostr.md — the kind-444 welcome rumor links to the
        // KeyPackage event consumed for this welcome and carries the group
        // relay list the new member should use next. Both tags are
        // routing-significant, so duplicates are rejected and the relay values
        // are content-validated before anything downstream sees them (#709).
        let key_package_event_id = rumor_single_tag_value(&unwrapped.rumor, KEY_PACKAGE_EVENT_TAG)?;
        let key_package_event_id: [u8; 32] =
            decode_hex_exact("welcome e tag", key_package_event_id, 32)
                .map_err(to_peeler_error)?
                .try_into()
                .map_err(|_| PeelerError::Malformed("welcome e tag is not 32 bytes".into()))?;
        let relays = rumor_single_tag_values(&unwrapped.rumor, WELCOME_RELAYS_TAG)?;
        validate_welcome_relays(&relays).map_err(PeelerError::Malformed)?;

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

        Ok(AccountGiftWrap::Welcome(
            Box::new(PeeledMessage {
                id: msg.id.clone(),
                group_id: None,
                sender: Some(MemberId::new(unwrapped.sender.to_bytes().to_vec())),
                content: PeeledContent::Welcome {
                    created_at: Some(cgka_traits::Timestamp(unwrapped.rumor.created_at.as_secs())),
                    bytes: welcome_bytes,
                    key_package_event_id: Some(MessageId::new(key_package_event_id.to_vec())),
                },
                origin: msg.clone(),
            }),
            WelcomePeelProvenance {
                rumor_event_id,
                key_package_event_id,
            },
        ))
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl InboxSealer for NostrInboxSealer {
    async fn unseal(&self, msg: &TransportMessage) -> Result<PeeledMessage, PeelerError> {
        self.unseal_with_provenance(msg)
            .await
            .map(|(peeled, _)| peeled)
    }

    async fn seal_welcome(
        &self,
        welcome: &OutboundWelcome,
    ) -> Result<TransportMessage, PeelerError> {
        let Some(metadata) = &welcome.metadata else {
            return Err(PeelerError::MissingContext {
                label: "welcome_metadata".into(),
            });
        };
        let payload = &welcome.payload;
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
        let sender_pubkey = self
            .signer
            .get_public_key()
            .await
            .map_err(|e| PeelerError::WrapFailed(format!("signer public key: {e}")))?;
        let recipient_pubkey = recipient_pubkey(&welcome.recipient)?;
        // Outbound parity with `unseal`: never emit a relays tag this sealer
        // would reject on ingest (#392).
        let relay_strs: Vec<&str> = metadata.relays.iter().map(|relay| relay.as_str()).collect();
        validate_welcome_relays(&relay_strs).map_err(PeelerError::WrapFailed)?;
        let rumor = welcome_rumor(payload, metadata, self.clock.now().0, sender_pubkey);
        let gift_wrap =
            crate::gift_wrap_rumor(self.signer.clone(), recipient_pubkey, rumor).await?;
        let event = NostrTransportEvent::from_nostr_event(&gift_wrap).map_err(to_peeler_error)?;
        event.to_transport_message().map_err(to_peeler_error)
    }

    async fn seal_group_recovery(
        &self,
        message: &GroupRecoveryMessage,
        recipient: &MemberId,
    ) -> Result<TransportMessage, PeelerError> {
        let content = String::from_utf8(message.encode()?)
            .map_err(|_| PeelerError::WrapFailed("invalid recovery JSON".into()))?;
        let sender = self
            .signer
            .get_public_key()
            .await
            .map_err(|_| PeelerError::WrapFailed("recovery signer unavailable".into()))?;
        let receiver = recipient_pubkey(recipient)?;
        let rumor = EventBuilder::new(Kind::Custom(KIND_MDK_GROUP_RECOVERY_RUMOR), content)
            .tags([
                Tag::custom(
                    GROUP_RECOVERY_PROTOCOL_TAG,
                    [GROUP_RECOVERY_PROTOCOL_VERSION],
                ),
                Tag::public_key(receiver),
            ])
            .custom_created_at(NostrTimestamp::from_secs(self.clock.now().0))
            .finalize_unsigned(sender);
        let gift_wrap = crate::gift_wrap_rumor(self.signer.clone(), receiver, rumor).await?;
        let event = NostrTransportEvent::from_nostr_event(&gift_wrap).map_err(to_peeler_error)?;
        event.to_transport_message().map_err(to_peeler_error)
    }

    fn sealed_welcome_len(&self, welcome: &OutboundWelcome) -> usize {
        sealed_welcome_event_len(welcome)
    }
}

/// Exact JSON byte length of the kind-1059 event [`InboxSealer::seal_welcome`]
/// produces for `welcome`, computed without the signer. `0` when `welcome` has
/// no metadata, since such a Welcome cannot be sealed.
///
/// Exact while the rumor, seal and wrap `created_at` values each have ten
/// decimal digits (2001-09-09 to 2286-11-20). That covers the NIP-59 seal and
/// wrap timestamps (now minus up to two days) and any plausible clock.
pub fn sealed_welcome_event_len(welcome: &OutboundWelcome) -> usize {
    let Some(metadata) = &welcome.metadata else {
        return 0;
    };
    // Any valid x-only key and a ten-digit time serialize to the same width
    // as the real ones. Building the real rumor gets JSON escaping right.
    let author = PublicKey::from_slice(&WIDTH_PROBE_KEY).expect("the generator is a valid key");
    let mut rumor = welcome_rumor(&welcome.payload, metadata, 1_000_000_000, author);
    rumor.ensure_id();
    let rumor_len = rumor.as_json().len();
    let seal_len = SEAL_JSON_OVERHEAD + nip44_payload_len(rumor_len);
    WRAP_JSON_OVERHEAD + nip44_payload_len(seal_len)
}

/// Base64 length of a NIP-44 v2 payload for an `n`-byte plaintext: version,
/// nonce, length prefix, padded plaintext and MAC.
fn nip44_payload_len(n: usize) -> usize {
    let prefix = if n < 65_536 { 2 } else { 6 };
    let padded = if n <= 32 {
        32
    } else {
        let next_power = n.next_power_of_two();
        let chunk = if next_power <= 256 {
            32
        } else {
            next_power / 8
        };
        chunk * n.div_ceil(chunk)
    };
    (1 + 32 + prefix + padded + 32).div_ceil(3) * 4
}

/// The kind-444 rumor a Welcome is sealed in.
fn welcome_rumor(
    payload: &EncryptedPayload,
    metadata: &WelcomeMetadata,
    created_at: u64,
    author: PublicKey,
) -> UnsignedEvent {
    EventBuilder::new(
        Kind::Custom(KIND_MARMOT_WELCOME_RUMOR),
        BASE64_STANDARD.encode(&payload.ciphertext),
    )
    .tags([
        Tag::custom(
            KEY_PACKAGE_EVENT_TAG,
            [hex::encode(metadata.key_package_event_id.as_slice())],
        ),
        Tag::custom(
            WELCOME_RELAYS_TAG,
            metadata.relays.iter().map(|relay| relay.as_str()),
        ),
    ])
    .custom_created_at(NostrTimestamp::from_secs(created_at))
    .finalize_unsigned(author)
}

fn recipient_pubkey(recipient: &MemberId) -> Result<PublicKey, PeelerError> {
    PublicKey::from_slice(recipient.as_slice()).map_err(|e| {
        PeelerError::WrapFailed(format!("recipient MemberId is not a Nostr pubkey: {e}"))
    })
}

/// Exactly one `[name, ...]` tag on an unwrapped NIP-59 rumor.
///
/// Boundary validation contract (#709): routing-significant rumor tags are
/// single-valued, so a missing tag and a duplicate tag are both rejected
/// instead of first-matched, mirroring `single_tag_value` on the outer event.
fn rumor_single_tag<'a>(rumor: &'a UnsignedEvent, name: &str) -> Result<&'a [String], PeelerError> {
    let mut matches = rumor.tags.iter().filter_map(|tag| {
        let slice = tag.as_slice();
        match slice.first() {
            Some(tag_name) if tag_name == name => Some(slice),
            _ => None,
        }
    });
    let first = matches
        .next()
        .ok_or_else(|| PeelerError::Malformed(format!("welcome rumor is missing {name} tag")))?;
    if matches.next().is_some() {
        return Err(PeelerError::Malformed(format!(
            "welcome rumor must contain exactly one {name} tag"
        )));
    }
    Ok(first)
}

/// Value of the single `[name, value]` tag on an unwrapped NIP-59 rumor.
fn rumor_single_tag_value<'a>(
    rumor: &'a UnsignedEvent,
    name: &str,
) -> Result<&'a str, PeelerError> {
    rumor_single_tag(rumor, name)?
        .get(1)
        .map(String::as_str)
        .ok_or_else(|| PeelerError::Malformed(format!("welcome rumor {name} tag has no value")))
}

/// All values of the single `[name, value, ...]` tag on an unwrapped NIP-59
/// rumor. The tag itself must appear exactly once; its values stay multi.
fn rumor_single_tag_values<'a>(
    rumor: &'a UnsignedEvent,
    name: &str,
) -> Result<Vec<&'a str>, PeelerError> {
    Ok(rumor_single_tag(rumor, name)?
        .iter()
        .skip(1)
        .map(String::as_str)
        .collect())
}

/// Content-validate welcome `relays` values on both seal and unseal (#392):
/// bounded count, bounded per-entry length, and well-formed ws/wss relay URLs
/// via [`RelayUrl::parse`]. The relay strings are attacker-controlled on
/// ingest, so error messages carry only aggregate values, never the URL.
fn validate_welcome_relays(relays: &[&str]) -> Result<(), String> {
    if relays.is_empty() {
        return Err("welcome relays tag must contain at least one relay".into());
    }
    if relays.len() > MAX_WELCOME_RELAYS {
        return Err(format!(
            "welcome relays tag lists {} relays, limit is {MAX_WELCOME_RELAYS}",
            relays.len()
        ));
    }
    for relay in relays {
        if relay.len() > MAX_WELCOME_RELAY_URL_LEN {
            return Err(format!(
                "welcome relay URL is {} bytes, limit is {MAX_WELCOME_RELAY_URL_LEN}",
                relay.len()
            ));
        }
        if RelayUrl::parse(relay).is_err() {
            return Err("welcome relay is not a valid ws/wss relay URL".into());
        }
    }
    Ok(())
}

fn ensure_welcome_routing_matches(
    event: &NostrTransportEvent,
    msg: &TransportMessage,
) -> Result<(), PeelerError> {
    let event_recipient = event
        .single_tag_value(RECIPIENT_TAG)
        .map_err(to_peeler_error)
        .and_then(|p| decode_hex_exact("recipient p tag", p, 32).map_err(to_peeler_error))?;
    match &msg.envelope {
        TransportEnvelope::Welcome { recipient } if recipient.as_slice() == event_recipient => {
            Ok(())
        }
        TransportEnvelope::Welcome { .. } => Err(PeelerError::WrongRecipient),
        TransportEnvelope::GroupMessage { .. } => Err(PeelerError::Malformed(
            "welcome peeler received group envelope".into(),
        )),
    }
}

fn map_nip59_error(_err: nostr::error::Error) -> PeelerError {
    // The outer kind is checked before unwrap. Remaining errors are failed
    // verification/decryption; never disclose SDK error text to the caller.
    PeelerError::DecryptFailed
}

#[cfg(test)]
mod tests {
    use super::*;
    use cgka_traits::{Timestamp, TransportEndpoint};
    use nostr::nips::nip59::GiftWrapBuilder;
    use nostr::prelude::{FinalizeEvent, Keys};
    use rand::{Rng, RngCore, SeedableRng, rngs::StdRng};

    const FIXED_CREATED_AT: Timestamp = Timestamp(1_700_000_321);

    struct FixedClock(Timestamp);

    impl WallClock for FixedClock {
        fn now(&self) -> Timestamp {
            self.0
        }

        fn now_ms(&self) -> u64 {
            self.0.0 * 1_000
        }
    }

    fn sealer(keys: &Keys) -> NostrInboxSealer {
        NostrInboxSealer::new(
            Arc::new(keys.clone()),
            Arc::new(FixedClock(FIXED_CREATED_AT)),
        )
    }

    fn outbound(
        recipient: &MemberId,
        ciphertext: Vec<u8>,
        metadata: WelcomeMetadata,
    ) -> OutboundWelcome {
        OutboundWelcome {
            local_id: MessageId::new([0x01; 32]),
            recipient: recipient.clone(),
            payload: EncryptedPayload {
                ciphertext,
                aad: vec![],
            },
            metadata: Some(metadata),
        }
    }

    /// The length the size check uses before sealing is the length of the
    /// event sealing produces, across both NIP-44 length prefixes, every
    /// padding chunk size, and relay lists of any length.
    #[tokio::test]
    async fn sealed_len_matches_sealed_event_json() {
        let mut rng = StdRng::seed_from_u64(3498);
        let sender = NostrInboxSealer::new(
            Arc::new(Keys::generate()),
            Arc::new(FixedClock(Timestamp(1_700_000_000))),
        );
        for case in 0..256 {
            let mut ciphertext = vec![0; rng.gen_range(1..=70_000)];
            rng.fill_bytes(&mut ciphertext);
            let relays = (0..rng.gen_range(1..=16))
                .map(|_| {
                    let host: String = (0..rng.gen_range(1..=400))
                        .map(|_| char::from(rng.gen_range(b'a'..=b'z')))
                        .collect();
                    TransportEndpoint(format!("wss://{host}.example"))
                })
                .collect();
            let mut key_package_event_id = [0; 32];
            rng.fill_bytes(&mut key_package_event_id);
            let recipient = MemberId::new(Keys::generate().public_key().to_bytes().to_vec());
            let welcome = outbound(
                &recipient,
                ciphertext,
                WelcomeMetadata {
                    key_package_event_id: MessageId::new(key_package_event_id),
                    relays,
                },
            );

            let sealed = sender.seal_welcome(&welcome).await.expect("seal succeeds");

            assert_eq!(
                sealed.payload.len(),
                sealed_welcome_event_len(&welcome),
                "case {case}"
            );
        }
    }

    #[tokio::test]
    async fn welcome_wrap_and_peel_round_trips_mls_welcome_bytes() {
        let sender = sender_keys();
        let receiver = receiver_keys();
        let recipient = MemberId::new(receiver.public_key().to_bytes().to_vec());
        let sender_peeler = sealer(&sender);
        let receiver_peeler = sealer(&receiver);

        let wrapped = sender_peeler
            .seal_welcome(&outbound(
                &recipient,
                b"mls welcome bytes".to_vec(),
                sample_welcome_metadata(),
            ))
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
            .unseal(&wrapped)
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
                created_at: Some(FIXED_CREATED_AT),
                bytes: b"mls welcome bytes".to_vec(),
                // The engine decides from the `e` claim whether the delivery
                // is addressed to this device, so it travels with the bytes.
                key_package_event_id: Some(sample_welcome_metadata().key_package_event_id),
            }
        );
    }

    /// A one-invitee Welcome into a group of about 150 members carries about
    /// 55 KB of MLS bytes. Its rumor and its seal both reach 65,536 bytes, so
    /// both NIP-44 layers need the extended length prefix (#2335).
    #[tokio::test]
    async fn welcome_wrap_and_peel_round_trip_nip44_extended_length_payloads() {
        let sender = sender_keys();
        let receiver = receiver_keys();
        let recipient = MemberId::new(receiver.public_key().to_bytes().to_vec());
        let welcome: Vec<u8> = (0..55_176u32).map(|i| i as u8).collect();

        let wrapped = sealer(&sender)
            .seal_welcome(&outbound(
                &recipient,
                welcome.clone(),
                sample_welcome_metadata(),
            ))
            .await
            .expect("wrap succeeds");

        let gift_wrap = NostrTransportEvent::from_transport_message(&wrapped)
            .unwrap()
            .to_verified_nostr_event()
            .unwrap();
        let seal_json = nostr::nips::nip44::decrypt(
            receiver.secret_key(),
            &gift_wrap.pubkey,
            &gift_wrap.content,
        )
        .unwrap();
        assert_nip44_extended_length(&gift_wrap.content, seal_json.len());
        let seal = Event::from_json(&seal_json).unwrap();
        let rumor_json =
            nostr::nips::nip44::decrypt(receiver.secret_key(), &seal.pubkey, &seal.content)
                .unwrap();
        assert_nip44_extended_length(&seal.content, rumor_json.len());

        let peeled = sealer(&receiver)
            .unseal(&wrapped)
            .await
            .expect("peel succeeds");
        assert!(matches!(
            peeled.content,
            PeeledContent::Welcome { ref bytes, .. } if *bytes == welcome
        ));
    }

    /// `payload` is a NIP-44 v2 payload of a `plaintext_len`-byte plaintext
    /// with the 6-byte extended length prefix: version, nonce, prefix, padded
    /// plaintext and MAC.
    #[track_caller]
    fn assert_nip44_extended_length(payload: &str, plaintext_len: usize) {
        assert!(plaintext_len >= 65_536, "{plaintext_len}-byte plaintext");
        let decoded = BASE64_STANDARD.decode(payload).unwrap();
        assert_eq!(
            decoded.len(),
            1 + 32 + 6 + nip44_padded_len(plaintext_len) + 32
        );
    }

    /// NIP-44 v2 `calc_padded_len`.
    fn nip44_padded_len(len: usize) -> usize {
        if len <= 32 {
            return 32;
        }
        let next_power = 1usize << (usize::BITS - (len - 1).leading_zeros());
        let chunk = if next_power <= 256 {
            32
        } else {
            next_power / 8
        };
        chunk * ((len - 1) / chunk + 1)
    }

    #[tokio::test]
    async fn welcome_provenance_uses_computed_unsigned_rumor_id() {
        let sender = sender_keys();
        let receiver = receiver_keys();
        let peeler = sealer(&receiver);
        let base = EventBuilder::new(
            Kind::Custom(KIND_MARMOT_WELCOME_RUMOR),
            BASE64_STANDARD.encode(b"mls welcome bytes"),
        )
        .tags([
            Tag::custom(KEY_PACKAGE_EVENT_TAG, ["44".repeat(32)]),
            Tag::custom(WELCOME_RELAYS_TAG, ["wss://group-a.example"]),
        ])
        .finalize_unsigned(sender.public_key());
        let expected = base.compute_id().to_bytes();
        for claimed in [
            None,
            Some(nostr::prelude::EventId::from_byte_array([0x77; 32])),
        ] {
            let mut rumor = base.clone();
            rumor.id = claimed;
            let wrap = GiftWrapBuilder::new(receiver.public_key(), rumor)
                .finalize(&sender)
                .unwrap();
            let message = NostrTransportEvent::from_nostr_event(&wrap)
                .unwrap()
                .to_transport_message()
                .unwrap();
            let (peeled, provenance) = peeler.unseal_with_provenance(&message).await.unwrap();
            assert!(matches!(peeled.content, PeeledContent::Welcome { .. }));
            let provenance = provenance.expect("Welcome has authenticated provenance");
            assert_eq!(provenance.rumor_event_id, expected);
            assert_eq!(provenance.key_package_event_id, [0x44; 32]);
        }
    }

    #[tokio::test]
    async fn welcome_peel_with_wrong_private_key_fails_closed() {
        let sender = sender_keys();
        let receiver = receiver_keys();
        let wrong_receiver = wrong_receiver_keys();
        let recipient = MemberId::new(receiver.public_key().to_bytes().to_vec());
        let sender_peeler = sealer(&sender);
        let wrong_peeler = sealer(&wrong_receiver);
        let wrapped = sender_peeler
            .seal_welcome(&outbound(
                &recipient,
                b"mls welcome bytes".to_vec(),
                sample_welcome_metadata(),
            ))
            .await
            .expect("wrap succeeds");

        let err = wrong_peeler
            .unseal(&wrapped)
            .await
            .expect_err("wrong recipient key cannot decrypt");

        assert!(matches!(err, PeelerError::DecryptFailed));
    }

    #[tokio::test]
    async fn welcome_peel_rejects_mismatched_p_tag_and_envelope() {
        let sender = sender_keys();
        let receiver = receiver_keys();
        let recipient = MemberId::new(receiver.public_key().to_bytes().to_vec());
        let peeler = sealer(&sender);
        let mut wrapped = peeler
            .seal_welcome(&outbound(
                &recipient,
                b"mls welcome bytes".to_vec(),
                sample_welcome_metadata(),
            ))
            .await
            .expect("wrap succeeds");
        wrapped.envelope = TransportEnvelope::Welcome {
            recipient: MemberId::new(vec![0x55; 32]),
        };

        let err = sealer(&receiver)
            .unseal(&wrapped)
            .await
            .expect_err("mismatched route should not peel");

        assert!(matches!(err, PeelerError::WrongRecipient));
    }

    #[tokio::test]
    async fn welcome_peel_rejects_duplicate_recipient_tags() {
        // #336 — `ensure_welcome_routing_matches` runs before gift-wrap
        // signature verification, so a multi-`p` payload is rejected at the
        // routing boundary even when the envelope names a valid recipient.
        let sender = sender_keys();
        let receiver = receiver_keys();
        let recipient = MemberId::new(receiver.public_key().to_bytes().to_vec());
        let mut wrapped = sealer(&sender)
            .seal_welcome(&outbound(
                &recipient,
                b"mls welcome bytes".to_vec(),
                sample_welcome_metadata(),
            ))
            .await
            .expect("wrap succeeds");
        let mut event = NostrTransportEvent::from_transport_message(&wrapped).unwrap();
        event.tags.push(vec!["p".into(), "66".repeat(32)]);
        event.id = event.computed_id();
        wrapped.payload = serde_json::to_vec(&event).unwrap();

        let err = sealer(&receiver)
            .unseal(&wrapped)
            .await
            .expect_err("duplicate p tags should not peel");

        assert!(matches!(err, PeelerError::Malformed(_)));
    }

    #[tokio::test]
    async fn welcome_peel_rejects_unsigned_gift_wrap_after_route_mapping() {
        let receiver = receiver_keys();
        let mut event = NostrTransportEvent {
            id: String::new(),
            pubkey: "44".repeat(32),
            created_at: 1_700_000_001,
            kind: KIND_NIP59_GIFT_WRAP,
            tags: vec![vec!["p".into(), receiver.public_key().to_hex()]],
            content: "gift wrap body".into(),
            sig: None,
        };
        event.id = event.computed_id();
        let unsigned = event
            .to_transport_message()
            .expect("route mapping accepts unverified gift-wrap envelope");

        let err = sealer(&receiver)
            .unseal(&unsigned)
            .await
            .expect_err("peeling verifies the signed gift wrap");

        assert!(matches!(err, PeelerError::InvalidSignature));
    }

    #[tokio::test]
    async fn welcome_peel_rejects_authentic_non_welcome_rumor() {
        let sender = sender_keys();
        let receiver = receiver_keys();
        let rumor = EventBuilder::new(Kind::TextNote, "not a Marmot welcome")
            .finalize_unsigned(sender.public_key());
        let gift_wrap = GiftWrapBuilder::new(receiver.public_key(), rumor)
            .finalize(&sender)
            .unwrap();
        let wrapped = NostrTransportEvent::from_nostr_event(&gift_wrap)
            .unwrap()
            .to_transport_message()
            .unwrap();

        let peeler = sealer(&receiver);
        let err = peeler
            .unseal(&wrapped)
            .await
            .expect_err("wrong rumor kind should not peel");

        assert!(matches!(err, PeelerError::Malformed(_)));

        // Opened once as a gift wrap to the account, the rumor comes back
        // unread, authored by the seal's signer.
        let AccountGiftWrap::Other(unwrapped) = peeler
            .open_account_gift_wrap(&wrapped)
            .await
            .expect("an authentic gift wrap opens")
        else {
            panic!("a non-Welcome rumor is not a Welcome");
        };
        assert_eq!(unwrapped.rumor.kind, Kind::TextNote);
        assert_eq!(unwrapped.sender, sender.public_key());
    }

    #[tokio::test]
    async fn welcome_wrap_emits_required_key_package_and_relays_tags() {
        let sender = sender_keys();
        let receiver = receiver_keys();
        let recipient = MemberId::new(receiver.public_key().to_bytes().to_vec());
        let metadata = sample_welcome_metadata();
        let wrapped = sealer(&sender)
            .seal_welcome(&outbound(
                &recipient,
                b"mls welcome bytes".to_vec(),
                metadata.clone(),
            ))
            .await
            .expect("wrap succeeds");
        let gift_wrap = NostrTransportEvent::from_transport_message(&wrapped)
            .unwrap()
            .to_verified_nostr_event()
            .unwrap();
        let unwrapped = nostr::nips::nip59::extract_rumor(&receiver, &gift_wrap).expect("unwrap");
        assert_eq!(
            rumor_single_tag_value(&unwrapped.rumor, KEY_PACKAGE_EVENT_TAG).unwrap(),
            hex::encode(metadata.key_package_event_id.as_slice()).as_str()
        );
        assert_eq!(
            rumor_single_tag_values(&unwrapped.rumor, WELCOME_RELAYS_TAG).unwrap(),
            vec!["wss://group-a.example", "wss://group-b.example"]
        );
        assert!(rumor_single_tag_value(&unwrapped.rumor, "encoding").is_err());
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
        let receiver_peeler = sealer(&receiver);

        let missing_key_package =
            welcome_rumor_gift_wrap(&sender, &receiver, 0, &[&["wss://group-a.example"]]).await;
        assert!(matches!(
            receiver_peeler.unseal(&missing_key_package).await,
            Err(PeelerError::Malformed(_))
        ));

        let missing_relays = welcome_rumor_gift_wrap(&sender, &receiver, 1, &[]).await;
        assert!(matches!(
            receiver_peeler.unseal(&missing_relays).await,
            Err(PeelerError::Malformed(_))
        ));
    }

    #[tokio::test]
    async fn welcome_peel_rejects_duplicate_key_package_or_relays_tags() {
        // #350 — the rumor `e` and `relays` tags are strict single-tag, matching
        // the kind-445 `h` path; duplicates are rejected, not first-matched.
        let sender = sender_keys();
        let receiver = receiver_keys();
        let receiver_peeler = sealer(&receiver);

        let duplicate_key_package =
            welcome_rumor_gift_wrap(&sender, &receiver, 2, &[&["wss://group-a.example"]]).await;
        assert!(matches!(
            receiver_peeler.unseal(&duplicate_key_package).await,
            Err(PeelerError::Malformed(_))
        ));

        let duplicate_relays = welcome_rumor_gift_wrap(
            &sender,
            &receiver,
            1,
            &[&["wss://group-a.example"], &["wss://group-b.example"]],
        )
        .await;
        assert!(matches!(
            receiver_peeler.unseal(&duplicate_relays).await,
            Err(PeelerError::Malformed(_))
        ));
    }

    #[tokio::test]
    async fn welcome_peel_rejects_unvalidated_relay_values() {
        // #392 — the relay strings are attacker-controlled: bound the count,
        // bound each entry's length, and require well-formed ws/wss URLs.
        let sender = sender_keys();
        let receiver = receiver_keys();
        let receiver_peeler = sealer(&receiver);

        let too_many: Vec<String> = (0..MAX_WELCOME_RELAYS + 1)
            .map(|i| format!("wss://relay-{i}.example"))
            .collect();
        let oversized_entry = format!("wss://{}.example", "a".repeat(MAX_WELCOME_RELAY_URL_LEN));
        let cases: Vec<Vec<&str>> = vec![
            too_many.iter().map(String::as_str).collect(),
            vec![oversized_entry.as_str()],
            vec!["https://relay.example"],
            vec!["not a relay url"],
            vec![],
        ];

        for relays in cases {
            let relay_tag: Vec<&[&str]> = vec![&relays[..]];
            let msg = welcome_rumor_gift_wrap(&sender, &receiver, 1, &relay_tag).await;
            assert!(
                matches!(
                    receiver_peeler.unseal(&msg).await,
                    Err(PeelerError::Malformed(_))
                ),
                "relay list {:?}... (len {}) should be rejected",
                relays.first(),
                relays.len()
            );
        }
    }

    #[tokio::test]
    async fn welcome_wrap_rejects_relay_metadata_it_would_not_peel() {
        // Outbound parity for #392: the wrap path applies the same relay
        // validation, so a misconfigured local relay list fails closed.
        let sender = sender_keys();
        let receiver = receiver_keys();
        let recipient = MemberId::new(receiver.public_key().to_bytes().to_vec());
        let peeler = sealer(&sender);

        let too_many: Vec<TransportEndpoint> = (0..MAX_WELCOME_RELAYS + 1)
            .map(|i| TransportEndpoint(format!("wss://relay-{i}.example")))
            .collect();
        for relays in [
            vec![],
            vec![TransportEndpoint("https://relay.example".into())],
            too_many,
        ] {
            let metadata = WelcomeMetadata {
                key_package_event_id: MessageId::new(vec![0x44; 32]),
                relays,
            };
            let err = peeler
                .seal_welcome(&outbound(
                    &recipient,
                    b"mls welcome bytes".to_vec(),
                    metadata,
                ))
                .await
                .expect_err("invalid relay metadata should not wrap");
            assert!(matches!(err, PeelerError::WrapFailed(_)));
        }
    }

    /// Build a kind-444 welcome rumor gift wrap with `key_package_tags` copies
    /// of the `e` tag and one `relays` tag per entry of `relays_tags`, used to
    /// exercise receiver-side metadata validation.
    async fn welcome_rumor_gift_wrap(
        sender: &Keys,
        receiver: &Keys,
        key_package_tags: usize,
        relays_tags: &[&[&str]],
    ) -> TransportMessage {
        let mut builder = EventBuilder::new(
            Kind::Custom(KIND_MARMOT_WELCOME_RUMOR),
            BASE64_STANDARD.encode(b"mls welcome bytes"),
        );
        let mut tags = Vec::new();
        for _ in 0..key_package_tags {
            tags.push(Tag::custom(
                KEY_PACKAGE_EVENT_TAG,
                [hex::encode(
                    sample_welcome_metadata().key_package_event_id.as_slice(),
                )],
            ));
        }
        for relays in relays_tags {
            tags.push(Tag::custom(WELCOME_RELAYS_TAG, relays.iter().copied()));
        }
        if !tags.is_empty() {
            builder = builder.tags(tags);
        }
        let rumor = builder.finalize_unsigned(sender.public_key());
        let gift_wrap = GiftWrapBuilder::new(receiver.public_key(), rumor)
            .finalize(sender)
            .unwrap();
        NostrTransportEvent::from_nostr_event(&gift_wrap)
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

    fn sender_keys() -> Keys {
        Keys::parse("6b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e").unwrap()
    }

    fn receiver_keys() -> Keys {
        Keys::parse("7b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e").unwrap()
    }

    fn wrong_receiver_keys() -> Keys {
        Keys::parse("5b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e").unwrap()
    }
}
