//! "History may be incomplete" notices: parked recovery occurrences.

use marmot_app::{HistoryNotice, HistoryNoticeCause};

/// Why recovery parked; choose the host's wording from it. Current policy
/// parks only the first five. `KnownEvent` and `MaintenanceBoundary` are
/// reserved so exhaustive switches stay source-compatible if a later policy
/// parks them.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notice_fields_cross_the_boundary_unchanged() {
        let notice = HistoryNotice {
            notice_id: "ab".repeat(24),
            cause: HistoryNoticeCause::EpochGap,
            group_id_hex: Some("11".repeat(16)),
            parked_at_ms: Some(1_700_000_000_000),
        };
        assert_eq!(
            HistoryNoticeFfi::from(notice),
            HistoryNoticeFfi {
                notice_id: "ab".repeat(24),
                cause: HistoryNoticeCauseFfi::EpochGap,
                group_id_hex: Some("11".repeat(16)),
                parked_at_ms: Some(1_700_000_000_000),
            }
        );
        for (cause, ffi) in [
            (
                HistoryNoticeCause::DeliveryLoss,
                HistoryNoticeCauseFfi::DeliveryLoss,
            ),
            (
                HistoryNoticeCause::NotificationLoss,
                HistoryNoticeCauseFfi::NotificationLoss,
            ),
            (
                HistoryNoticeCause::EpochGap,
                HistoryNoticeCauseFfi::EpochGap,
            ),
            (
                HistoryNoticeCause::IncrementalHistory,
                HistoryNoticeCauseFfi::IncrementalHistory,
            ),
            (
                HistoryNoticeCause::ExplicitRepair,
                HistoryNoticeCauseFfi::ExplicitRepair,
            ),
            (
                HistoryNoticeCause::KnownEvent,
                HistoryNoticeCauseFfi::KnownEvent,
            ),
            (
                HistoryNoticeCause::MaintenanceBoundary,
                HistoryNoticeCauseFfi::MaintenanceBoundary,
            ),
        ] {
            assert_eq!(HistoryNoticeCauseFfi::from(cause), ffi);
        }
    }
}
