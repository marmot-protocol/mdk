//! The one NIP-59 gift-wrap construction Marmot uses for every outbound wrap.
use crate::signer::{MarmotNostrSigner, SdkSigner};
use crate::{GROUP_RECOVERY_PROTOCOL_TAG, KIND_MDK_GROUP_RECOVERY_RUMOR};
use cgka_traits::error::PeelerError;
use nostr::nips::nip59::GiftWrapBuilder;
use nostr::prelude::{Event, FinalizeEventAsync, PublicKey, UnsignedEvent};
use std::sync::Arc;

/// Gift-wrap `rumor` to `receiver` per NIP-59.
///
/// The kind-13 seal is NIP-44 encrypted to `receiver` and signed by `signer`;
/// the kind-1059 wrap is NIP-44 encrypted to `receiver`, carries one
/// `["p", receiver]` tag and is signed by a one-time key that is generated for
/// this wrap and dropped when it returns. Both `created_at` values are
/// randomized up to two days into the past. Welcomes, moderation reports and
/// MDK-private recovery share this path; do not build a second implementation.
/// Recovery copies its protocol marker onto the signed outer carrier solely
/// for inbox dispatch; receivers still authenticate the inner marker and seal.
pub async fn gift_wrap_rumor(
    signer: Arc<dyn MarmotNostrSigner>,
    receiver: PublicKey,
    rumor: UnsignedEvent,
) -> Result<Event, PeelerError> {
    let routing_tags = if rumor.kind.as_u16() == KIND_MDK_GROUP_RECOVERY_RUMOR {
        rumor
            .tags
            .iter()
            .filter(|tag| {
                tag.as_slice()
                    .first()
                    .is_some_and(|name| name == GROUP_RECOVERY_PROTOCOL_TAG)
            })
            .cloned()
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    GiftWrapBuilder::new(receiver, rumor)
        .extra_tags(routing_tags)
        .finalize_async(&SdkSigner(signer))
        .await
        .map_err(|e| PeelerError::WrapFailed(format!("NIP-59 gift wrap: {e}")))
}
