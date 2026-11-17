//! A Welcome's content dedup marker (mdk#3514).
//!
//! One Welcome can reach its recipient in several deliveries: the inviter's
//! own, a resend, or another invitee's rewrap of the same bytes. Each
//! delivery has its own wrapper id, and all of them share one content id, the
//! hash of the MLS bytes. The content marker makes every later delivery of
//! those bytes a duplicate.
//!
//! Only what settles a Welcome marks its content: a completed join, which
//! also settles every older rejoin offer for its group, and an explicit
//! decline of a rejoin offer. A refusal marks only its delivery's wrapper.
//! Some refusals depend on the delivery: across a local forget, its
//! authenticated time and its sender. Others depend on local state that can
//! change, such as a capability this build lacks or a device link not yet
//! confirmed. Marking the content on such a refusal would drop a later honest
//! delivery of the same bytes, and a co-invitee holding them could keep the
//! recipient out. A refusal that depends on the bytes alone gains nothing
//! from the marker either, because a sender can vary the bytes.
//!
//! [`WelcomeContentId`] keeps its id to this module, so nothing else can
//! write its marker: [`record_join`] and [`decline_rejoin_offer`] are its only
//! writers. A stored rejoin offer carries the id as a plain field of a
//! host-visible type; only those two functions mark an offer's content.

use cgka_traits::error::{EngineError, PeelerError};
use cgka_traits::ingest::{PeeledContent, PeeledMessage};
use cgka_traits::message::{MessageRecord, MessageState, StoredMessagePayload};
use cgka_traits::storage::{MessageStorage, StorageProvider, StorageResult};
use cgka_traits::transport::TransportMessage;
use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
use cgka_traits::welcome::RejoinWelcome;

/// The content id every delivery of one Welcome shares: the hash of its MLS
/// bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WelcomeContentId(MessageId);

impl WelcomeContentId {
    /// The content id of a peeled Welcome.
    pub(crate) fn of(peeled: &PeeledMessage) -> Result<Self, EngineError> {
        match &peeled.content {
            PeeledContent::Welcome { bytes, .. } => {
                Ok(Self(crate::message_processor::content_dedup_id(bytes)))
            }
            _ => Err(EngineError::Peeler(PeelerError::Malformed(
                "peeled content was not a Welcome".into(),
            ))),
        }
    }

    /// Whether a join or a decline settled this Welcome.
    pub(crate) fn is_settled(
        &self,
        storage: &(impl MessageStorage + ?Sized),
    ) -> StorageResult<bool> {
        storage.has_ingress_dedup_marker(&self.0)
    }

    /// The rejoin offer a delivery of this Welcome stores.
    pub(crate) fn rejoin_offer(
        &self,
        epoch: EpochId,
        welcomer: MemberId,
        local_state_token: Vec<u8>,
    ) -> RejoinWelcome {
        RejoinWelcome {
            epoch,
            content_id: self.0.clone(),
            welcomer,
            local_state_token,
        }
    }

    /// Whether `offer` was stored for a delivery of this Welcome.
    pub(crate) fn offered_by(&self, offer: &RejoinWelcome) -> bool {
        offer.content_id == self.0
    }
}

/// Record a completed join of `content` through `welcome` into `group_id`,
/// inside the join's transaction: the delivery's processed row and both its
/// markers. The join settles every older rejoin offer for the group too, so
/// each is retired with its wrapper and its content marked.
pub(crate) fn record_join<S: StorageProvider>(
    storage: &S,
    welcome: TransportMessage,
    content: WelcomeContentId,
    group_id: &GroupId,
    epoch: EpochId,
) -> Result<(), EngineError> {
    for offer in storage.list_welcomes()? {
        if &offer.group_id == group_id
            && let Some(rejoin) = offer.rejoin
        {
            storage.take_welcome(&offer.message_id)?;
            settle_offer(storage, &offer.message_id, &rejoin)?;
        }
    }
    let welcome_id = welcome.id.clone();
    // Direct join callers need the same durable dedup disposition as the
    // transport-ingest path.
    let payload = StoredMessagePayload::raw_transport(welcome)
        .encode()
        .map_err(|error| EngineError::Serialize(format!("{error:?}")))?;
    storage.put_message(&MessageRecord {
        id: welcome_id.clone(),
        group_id: group_id.clone(),
        epoch,
        state: MessageState::Processed,
        payload,
        deferred_peel: None,
    })?;
    storage.put_ingress_dedup_marker(&welcome_id)?;
    storage.put_ingress_dedup_marker(&content.0)?;
    Ok(())
}

/// Decline the stored rejoin offer `welcome_id`, inside the caller's
/// transaction: take it and mark its wrapper and its content, so no later
/// delivery of that Welcome offers it again. Anything but a rejoin offer is
/// refused.
pub(crate) fn decline_rejoin_offer<S: StorageProvider>(
    storage: &S,
    welcome_id: &MessageId,
) -> Result<(), EngineError> {
    let offer = storage.take_welcome(welcome_id)?;
    let rejoin = offer.rejoin.ok_or(EngineError::InvalidWelcome)?;
    settle_offer(storage, welcome_id, &rejoin)
}

fn settle_offer<S: StorageProvider>(
    storage: &S,
    welcome_id: &MessageId,
    rejoin: &RejoinWelcome,
) -> Result<(), EngineError> {
    storage.put_ingress_dedup_marker(welcome_id)?;
    storage.put_ingress_dedup_marker(&rejoin.content_id)?;
    Ok(())
}
