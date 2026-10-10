//! The one NIP-59 gift-wrap construction Marmot uses for every outbound wrap.
use crate::signer::{MarmotNostrSigner, SdkSigner};
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
/// randomized up to two days into the past. Welcomes and moderation reports
/// share this path; do not build a second wrap implementation.
pub async fn gift_wrap_rumor(
    signer: Arc<dyn MarmotNostrSigner>,
    receiver: PublicKey,
    rumor: UnsignedEvent,
) -> Result<Event, PeelerError> {
    GiftWrapBuilder::new(receiver, rumor)
        .finalize_async(&SdkSigner(signer))
        .await
        .map_err(|e| PeelerError::WrapFailed(format!("NIP-59 gift wrap: {e}")))
}
