//! Device pairing messages as Nostr events (#2628).
//!
//! A pairing message is a rumor authored by the account, of the message's
//! pairing kind, with no tags and the message's content, gift-wrapped to the
//! account's own public key through [`transport_nostr_peeler::gift_wrap_rumor`],
//! the one NIP-59 construction Welcomes use. Every device of the account can
//! open it; nobody else can.
//!
//! Holding the account key proves only that a message came from the account.
//! It never authenticates a device: `marmot-pairing` does that with the code
//! both screens show. A reader here checks only that the rumor's author is
//! the account, and ignores any tags.
//!
//! Unreleased: compiled only with the `unreleased-device-pairing` feature, and
//! in this crate's tests, until the pairing spec merges.

use std::fmt;
use std::sync::Arc;

use marmot_pairing::{PAIRING_KINDS, PairingMessage, PairingMessageError};
use nostr::nips::nip59::{self, UnwrappedGift};
use nostr::prelude::{
    EventBuilder, FinalizeUnsignedEvent, Kind, PublicKey, Timestamp, UnsignedEvent,
};
use transport_nostr_peeler::{
    KIND_NIP59_GIFT_WRAP, MarmotNostrSigner, NostrTransportEvent, SdkSigner, gift_wrap_rumor,
};

/// A pairing message read from a gift wrap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboundPairingMessage {
    pub message: PairingMessage,
    /// The rumor's `created_at`, the time its sender stamped on it. The seal
    /// and wrap times are randomized, so this is the only real one.
    pub created_at: u64,
}

/// Why a pairing message could not be wrapped or read. Carries no keys, ids
/// or content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingEventError {
    /// The account signer could not give its key, wrap or decrypt.
    Signer,
    /// The event is not one gift wrap to the account.
    NotForAccount,
    /// The gift wrap or its seal did not verify.
    Unwrap,
    /// The rumor's author is not the account.
    ForeignSender,
    /// The rumor's content is not a valid pairing message.
    Content(PairingMessageError),
}

impl fmt::Display for PairingEventError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Signer => f.write_str("the account signer failed"),
            Self::NotForAccount => f.write_str("the event is not a gift wrap to the account"),
            Self::Unwrap => f.write_str("the gift wrap did not verify"),
            Self::ForeignSender => f.write_str("the pairing message is not from the account"),
            Self::Content(error) => write!(f, "pairing content: {error}"),
        }
    }
}

impl std::error::Error for PairingEventError {}

/// The rumor that carries `message` for `account`, stamped `created_at`.
pub fn pairing_rumor(
    account: PublicKey,
    message: &PairingMessage,
    created_at: u64,
) -> UnsignedEvent {
    EventBuilder::new(Kind::Custom(message.kind()), message.to_content())
        .custom_created_at(Timestamp::from_secs(created_at))
        .finalize_unsigned(account)
}

/// Gift-wraps `message`, stamped `created_at`, to the account `signer` holds.
pub async fn wrap_pairing_message(
    signer: Arc<dyn MarmotNostrSigner>,
    message: &PairingMessage,
    created_at: u64,
) -> Result<NostrTransportEvent, PairingEventError> {
    let account = signer
        .get_public_key()
        .await
        .map_err(|_| PairingEventError::Signer)?;
    let rumor = pairing_rumor(account, message, created_at);
    let wrap = gift_wrap_rumor(signer, account, rumor)
        .await
        .map_err(|_| PairingEventError::Signer)?;
    NostrTransportEvent::from_nostr_event(&wrap).map_err(|_| PairingEventError::Signer)
}

/// Reads the pairing message in an opened gift wrap to `account`. `None` when
/// the rumor is not of a pairing kind, such as a Welcome.
pub fn read_pairing_rumor(
    account: &PublicKey,
    unwrapped: &UnwrappedGift,
) -> Result<Option<InboundPairingMessage>, PairingEventError> {
    let kind = unwrapped.rumor.kind.as_u16();
    if !PAIRING_KINDS.contains(&kind) {
        return Ok(None);
    }
    // NIP-59 unwrapping already matched the rumor's author to the seal's.
    if &unwrapped.sender != account || &unwrapped.rumor.pubkey != account {
        return Err(PairingEventError::ForeignSender);
    }
    let message = PairingMessage::from_content(kind, &unwrapped.rumor.content)
        .map_err(PairingEventError::Content)?;
    Ok(Some(InboundPairingMessage {
        message,
        created_at: unwrapped.rumor.created_at.as_secs(),
    }))
}

/// Opens `gift_wrap` with the account `signer` holds and reads its pairing
/// message. `None` when it carries another kind of rumor.
pub async fn unwrap_pairing_message(
    signer: Arc<dyn MarmotNostrSigner>,
    gift_wrap: &NostrTransportEvent,
) -> Result<Option<InboundPairingMessage>, PairingEventError> {
    let account = signer
        .get_public_key()
        .await
        .map_err(|_| PairingEventError::Signer)?;
    let recipient = gift_wrap
        .single_tag_value("p")
        .map_err(|_| PairingEventError::NotForAccount)?;
    if gift_wrap.kind != KIND_NIP59_GIFT_WRAP || recipient != account.to_hex() {
        return Err(PairingEventError::NotForAccount);
    }
    let event = gift_wrap
        .to_verified_nostr_event()
        .map_err(|_| PairingEventError::Unwrap)?;
    let unwrapped = nip59::extract_rumor_async(&SdkSigner(signer), &event)
        .await
        .map_err(|_| PairingEventError::Unwrap)?;
    read_pairing_rumor(&account, &unwrapped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use marmot_pairing::{
        CancelReason, ExchangeKey, KIND_PAIRING_ANSWER, PairingAnswer, PairingCancel, SessionId,
        SlotId,
    };
    use nostr::prelude::Keys;

    const CREATED_AT: u64 = 1_800_000_000;

    fn answer() -> PairingMessage {
        PairingMessage::Answer(PairingAnswer {
            session_id: SessionId::new([1; 32]),
            slot: SlotId::new([2; 32]),
            key: ExchangeKey::new([3; 32]),
        })
    }

    fn signer(keys: &Keys) -> Arc<dyn MarmotNostrSigner> {
        Arc::new(keys.clone())
    }

    #[test]
    fn pairing_rumor_is_authored_by_the_account_with_no_tags() {
        let account = Keys::generate().public_key();
        let rumor = pairing_rumor(account, &answer(), CREATED_AT);
        assert_eq!(rumor.kind, Kind::Custom(KIND_PAIRING_ANSWER));
        assert_eq!(rumor.pubkey, account);
        assert!(rumor.tags.is_empty());
        assert_eq!(rumor.content, answer().to_content());
        assert_eq!(rumor.created_at.as_secs(), CREATED_AT);
    }

    #[tokio::test]
    async fn pairing_message_round_trips_through_a_gift_wrap_to_the_account() {
        let account = Keys::generate();
        let message = PairingMessage::Cancel(PairingCancel {
            session_id: SessionId::new([1; 32]),
            reason: CancelReason::Timeout,
        });
        let wrap = wrap_pairing_message(signer(&account), &message, CREATED_AT)
            .await
            .expect("wrap");
        assert_eq!(wrap.kind, KIND_NIP59_GIFT_WRAP);
        assert_ne!(
            wrap.pubkey,
            account.public_key().to_hex(),
            "one-time wrap key"
        );
        assert_eq!(
            wrap.single_tag_value("p").ok(),
            Some(account.public_key().to_hex().as_str())
        );
        assert!(!wrap.content.contains(&message.to_content()));

        // Another device of the account holds the same key.
        let inbound = unwrap_pairing_message(signer(&account), &wrap)
            .await
            .expect("unwrap")
            .expect("a pairing message");
        assert_eq!(inbound.message, message);
        assert_eq!(inbound.created_at, CREATED_AT);
    }

    #[tokio::test]
    async fn pairing_message_from_another_account_is_refused() {
        let account = Keys::generate();
        let stranger = Keys::generate();
        let rumor = pairing_rumor(stranger.public_key(), &answer(), CREATED_AT);
        let wrap = gift_wrap_rumor(signer(&stranger), account.public_key(), rumor)
            .await
            .expect("wrap");
        let wrap = NostrTransportEvent::from_nostr_event(&wrap).expect("dto");
        assert_eq!(
            unwrap_pairing_message(signer(&account), &wrap).await,
            Err(PairingEventError::ForeignSender)
        );
    }

    #[tokio::test]
    async fn pairing_gift_wrap_to_someone_else_is_not_read() {
        let account = Keys::generate();
        let other = Keys::generate();
        let wrap = wrap_pairing_message(signer(&other), &answer(), CREATED_AT)
            .await
            .expect("wrap");
        assert_eq!(
            unwrap_pairing_message(signer(&account), &wrap).await,
            Err(PairingEventError::NotForAccount)
        );
    }

    #[tokio::test]
    async fn pairing_gift_wrap_that_fails_verification_is_refused() {
        let account = Keys::generate();
        let mut wrap = wrap_pairing_message(signer(&account), &answer(), CREATED_AT)
            .await
            .expect("wrap");
        wrap.created_at += 1;
        assert_eq!(
            unwrap_pairing_message(signer(&account), &wrap).await,
            Err(PairingEventError::Unwrap)
        );
    }

    #[tokio::test]
    async fn pairing_reader_skips_other_rumors_and_refuses_bad_content() {
        let account = Keys::generate();
        let welcome =
            EventBuilder::new(Kind::Custom(444), "AAAA").finalize_unsigned(account.public_key());
        let wrap = gift_wrap_rumor(signer(&account), account.public_key(), welcome)
            .await
            .expect("wrap");
        let wrap = NostrTransportEvent::from_nostr_event(&wrap).expect("dto");
        assert_eq!(
            unwrap_pairing_message(signer(&account), &wrap).await,
            Ok(None)
        );

        let bad = EventBuilder::new(Kind::Custom(KIND_PAIRING_ANSWER), r#"{"v":1}"#)
            .finalize_unsigned(account.public_key());
        let wrap = gift_wrap_rumor(signer(&account), account.public_key(), bad)
            .await
            .expect("wrap");
        let wrap = NostrTransportEvent::from_nostr_event(&wrap).expect("dto");
        assert_eq!(
            unwrap_pairing_message(signer(&account), &wrap).await,
            Err(PairingEventError::Content(PairingMessageError::Malformed))
        );
    }
}
