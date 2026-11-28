//! When an outbound Welcome stops being deliverable (mdk#3589).
//!
//! Every Welcome this engine stages or founds carries a delivery deadline,
//! after which no path publishes it and it settles as
//! [`crate::engine::WelcomeSettlement::Expired`]. A device link's is the end
//! of the new device's wait (D40); every other one's is
//! [`welcome_deliver_until`].

use cgka_traits::message::{StoredMessagePayload, UnsealedWelcomeOrigin};
use cgka_traits::transport::Timestamp;

/// How long an invite's or a founding create's Welcome stays deliverable
/// after it is staged, when its KeyPackage does not end sooner.
///
/// A recipient deletes the private key of a replaced KeyPackage 24 hours
/// after its replacement is confirmed, and refreshes its KeyPackages every 6
/// to 7 days, so a Welcome is usually useless about 8 days after it was
/// made, well inside the KeyPackage's 30-day lifetime. The number is a
/// product choice and may change.
pub(crate) const WELCOME_DELIVERY_WINDOW_SECS: u64 = 7 * 24 * 60 * 60;

/// The delivery deadline of an invite's or a founding create's Welcome
/// staged at `staged_at` for a KeyPackage valid until
/// `key_package_not_after`: the window, or the KeyPackage's end if sooner.
pub(crate) fn welcome_deliver_until(staged_at: Timestamp, key_package_not_after: u64) -> Timestamp {
    Timestamp(
        staged_at
            .0
            .saturating_add(WELCOME_DELIVERY_WINDOW_SECS)
            .min(key_package_not_after),
    )
}

/// The delivery deadline a stored staged or owed Welcome is held to; `None`
/// for any other payload. A sealed Welcome stored before Welcomes kept a
/// deadline is held to its transport timestamp plus the window: when it was staged is
/// not stored, and a transport may date a wrap earlier than that (a Nostr
/// gift wrap by up to two days), never later.
pub(crate) fn stored_welcome_deliver_until(payload: &StoredMessagePayload) -> Option<Timestamp> {
    match payload {
        StoredMessagePayload::UnsealedWelcome {
            origin: UnsealedWelcomeOrigin::Founding,
            deliver_until,
            ..
        } => *deliver_until,
        StoredMessagePayload::OutboundWelcome {
            message,
            deliver_until,
            ..
        }
        | StoredMessagePayload::StagedInviteWelcome {
            message,
            deliver_until,
            ..
        } => Some(deliver_until.unwrap_or_else(|| {
            Timestamp(
                message
                    .timestamp
                    .0
                    .saturating_add(WELCOME_DELIVERY_WINDOW_SECS),
            )
        })),
        _ => None,
    }
}
