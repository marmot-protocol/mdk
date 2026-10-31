//! "History may be incomplete" notices: parked recovery occurrences, and the
//! account's recovery status.

use marmot_app::{AccountRecoveryStatus, HistoryNotice, HistoryNoticeCause};

/// Why recovery parked; choose the host's wording from it. Current policy
/// parks only the first five. `KnownEvent` and `MaintenanceBoundary` are
/// reserved so exhaustive switches stay source-compatible if a later policy
/// parks them, and `UnprovenHistory` is not raised until the recovery runner
/// owns history (mdk#2660).
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum HistoryNoticeCauseFfi {
    /// Deliveries were dropped from a full account queue, or spilled rows
    /// could not be admitted, and comparison could not recover them.
    DeliveryLoss,
    /// The relay notification stream lagged and skipped deliveries.
    NotificationLoss,
    /// A group's missing epoch could not be fetched from its relays.
    EpochGap,
    /// History since this device's last checkpoint could not be proven complete.
    IncrementalHistory,
    /// An explicit full-history repair ended without proof of completeness.
    ExplicitRepair,
    /// One known missing event could not be retrieved.
    KnownEvent,
    /// A post-join maintenance boundary was never observed.
    MaintenanceBoundary,
    /// The recovery runner could not prove this history on a route's relays
    /// and stopped retrying them: a group's (`group_id_hex` names it) or the
    /// account inbox's.
    UnprovenHistory,
}

impl From<HistoryNoticeCause> for HistoryNoticeCauseFfi {
    fn from(value: HistoryNoticeCause) -> Self {
        match value {
            HistoryNoticeCause::DeliveryLoss => Self::DeliveryLoss,
            HistoryNoticeCause::NotificationLoss => Self::NotificationLoss,
            HistoryNoticeCause::EpochGap => Self::EpochGap,
            HistoryNoticeCause::IncrementalHistory => Self::IncrementalHistory,
            HistoryNoticeCause::ExplicitRepair => Self::ExplicitRepair,
            HistoryNoticeCause::KnownEvent => Self::KnownEvent,
            HistoryNoticeCause::MaintenanceBoundary => Self::MaintenanceBoundary,
            HistoryNoticeCause::UnprovenHistory => Self::UnprovenHistory,
        }
    }
}

/// One occurrence of "history may be incomplete": automatic recovery could
/// not prove this history complete and stopped retrying. It disappears when
/// new evidence re-arms recovery (a later parking is a new notice), when an
/// explicit repair completes it, or when the user dismisses it.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct HistoryNoticeFfi {
    /// Opaque occurrence id (48 lowercase hex characters) for
    /// `dismiss_history_notice`. It changes when recovery re-arms; never
    /// store it as an identity of the group or account.
    pub notice_id: String,
    pub cause: HistoryNoticeCauseFfi,
    /// The affected group for a group-scoped occurrence (an epoch gap);
    /// `None` when the account's history as a whole may be incomplete.
    pub group_id_hex: Option<String>,
    /// When recovery parked, in milliseconds since the Unix epoch; `None`
    /// for occurrences parked before this was recorded.
    pub parked_at_ms: Option<u64>,
}

impl From<HistoryNotice> for HistoryNoticeFfi {
    fn from(value: HistoryNotice) -> Self {
        Self {
            notice_id: value.notice_id,
            cause: value.cause.into(),
            group_id_hex: value.group_id_hex,
            parked_at_ms: value.parked_at_ms,
        }
    }
}

/// The account's recovery: what is still being fetched, and every "history
/// may be incomplete" notice. Re-read on `RecoveryStatusChanged`. Until the
/// recovery runner owns history (mdk#2660), nothing is ever catching up.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct AccountRecoveryStatusFfi {
    /// Groups whose history is still being fetched, as lowercase hex group
    /// ids, sorted.
    pub catching_up_group_ids_hex: Vec<String>,
    /// The account inbox's history (Welcomes) is still being fetched.
    pub inbox_catching_up: bool,
    /// Every current notice, as `history_notices` lists them.
    pub notices: Vec<HistoryNoticeFfi>,
}

impl From<AccountRecoveryStatus> for AccountRecoveryStatusFfi {
    fn from(value: AccountRecoveryStatus) -> Self {
        Self {
            catching_up_group_ids_hex: value.catching_up_group_ids_hex,
            inbox_catching_up: value.inbox_catching_up,
            notices: value.notices.into_iter().map(Into::into).collect(),
        }
    }
}
