//! "History may be incomplete" notices: parked recovery occurrences that
//! automatic recovery stopped retrying, and the opaque ids hosts dismiss them
//! with. See `docs/marmot-architecture/further-context/account-recovery.md`.
use serde::{Deserialize, Serialize};
use storage_sqlite::{ParkedRecoveryObligation, RecoveryCause, RecoveryDemandTicket};

use crate::AppError;

/// Why recovery parked. Hosts choose wording from this; it carries no
/// identities. Current policy parks the first five causes. `KnownEvent` and
/// `MaintenanceBoundary` are reserved for demand that may park in a later
/// policy, so exhaustive host switches stay source-compatible.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryNoticeCause {
    /// Deliveries were dropped from a full account queue, or spilled rows
    /// could not be admitted, and comparison could not recover or rule out
    /// what they carried.
    DeliveryLoss,
    /// The relay notification stream lagged and skipped deliveries that
    /// comparison could not recover or rule out.
    NotificationLoss,
    /// A group's missing epoch could not be fetched from its relays.
    EpochGap,
    /// History since this device's last checkpoint could not be proven
    /// complete by comparing the retained window with the relays.
    IncrementalHistory,
    /// An explicit full-history repair ended without proof of completeness.
    ExplicitRepair,
    /// One known missing event could not be retrieved.
    KnownEvent,
    /// A post-join maintenance boundary was never observed.
    MaintenanceBoundary,
}

impl HistoryNoticeCause {
    /// Stable low-cardinality label, safe for diagnostics.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DeliveryLoss => "delivery_loss",
            Self::NotificationLoss => "notification_loss",
            Self::EpochGap => "epoch_gap",
            Self::IncrementalHistory => "incremental_history",
            Self::ExplicitRepair => "explicit_repair",
            Self::KnownEvent => "known_event",
            Self::MaintenanceBoundary => "maintenance_boundary",
        }
    }

    pub(crate) fn from_recovery(cause: RecoveryCause) -> Self {
        match cause {
            RecoveryCause::QueueLoss => Self::DeliveryLoss,
            RecoveryCause::NotificationLoss => Self::NotificationLoss,
            RecoveryCause::EpochGap => Self::EpochGap,
            RecoveryCause::IncrementalHistory => Self::IncrementalHistory,
            RecoveryCause::ExplicitHistory => Self::ExplicitRepair,
            RecoveryCause::KnownEvent => Self::KnownEvent,
            RecoveryCause::Maintenance => Self::MaintenanceBoundary,
        }
    }
}

/// One occurrence of "history may be incomplete": automatic recovery could
/// not prove this history complete and stopped retrying. It stays until new
/// evidence re-arms recovery (the notice disappears, and a later parking is a
/// new notice with a new id), an explicit deep repair completes it, or the
/// user dismisses it. Dismissal is durable and is recorded as its own
/// outcome, never as recovered history.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryNotice {
    /// Opaque occurrence id for `dismiss_history_notice`: 48 lowercase hex
    /// characters. It changes whenever the underlying recovery re-arms, so
    /// never persist it as a stable identity of a group or of the account.
    pub notice_id: String,
    pub cause: HistoryNoticeCause,
    /// The affected group for a group-scoped occurrence (an epoch gap);
    /// `None` when the whole account's history may be incomplete.
    pub group_id_hex: Option<String>,
    /// When recovery parked, in milliseconds since the Unix epoch; `None`
    /// for occurrences parked before this was recorded.
    pub parked_at_ms: Option<u64>,
}

const NOTICE_ID_BYTES: usize = 24;

pub(crate) fn encode_notice_id(ticket: RecoveryDemandTicket) -> String {
    let mut bytes = [0_u8; NOTICE_ID_BYTES];
    bytes[..16].copy_from_slice(&ticket.id);
    bytes[16..].copy_from_slice(&ticket.revision.to_be_bytes());
    hex::encode(bytes)
}

/// A malformed id is a caller error (`AppError::Hex`); a well-formed id that
/// names no current occurrence is a stale notice, not an error.
pub(crate) fn decode_notice_id(notice_id: &str) -> Result<RecoveryDemandTicket, AppError> {
    let bytes = hex::decode(notice_id)?;
    let bytes: [u8; NOTICE_ID_BYTES] = bytes
        .try_into()
        .map_err(|_| AppError::Hex(hex::FromHexError::InvalidStringLength))?;
    let mut id = [0_u8; 16];
    id.copy_from_slice(&bytes[..16]);
    let mut revision = [0_u8; 8];
    revision.copy_from_slice(&bytes[16..]);
    Ok(RecoveryDemandTicket {
        id,
        revision: u64::from_be_bytes(revision),
    })
}

pub(crate) fn history_notice(parked: &ParkedRecoveryObligation) -> HistoryNotice {
    HistoryNotice {
        notice_id: encode_notice_id(parked.ticket),
        cause: HistoryNoticeCause::from_recovery(parked.cause),
        group_id_hex: parked.group_id.as_ref().map(hex::encode),
        parked_at_ms: parked.parked_at_ms,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notice_ids_round_trip_and_reject_malformed_input() {
        let ticket = RecoveryDemandTicket {
            id: [0xab; 16],
            revision: 0x0102_0304_0506_0708,
        };
        let encoded = encode_notice_id(ticket);
        assert_eq!(encoded.len(), 48);
        assert_eq!(&encoded[32..], "0102030405060708");
        assert!(decode_notice_id(&encoded).unwrap() == ticket);
        assert!(decode_notice_id(&encoded.to_uppercase()).unwrap() == ticket);
        for malformed in ["", "zz", &encoded[..46], &format!("{encoded}00")] {
            assert!(matches!(decode_notice_id(malformed), Err(AppError::Hex(_))));
        }
    }

    #[test]
    fn every_recovery_cause_has_a_stable_notice_cause() {
        use RecoveryCause as C;
        let labels: Vec<_> = [
            C::QueueLoss,
            C::NotificationLoss,
            C::EpochGap,
            C::IncrementalHistory,
            C::ExplicitHistory,
            C::KnownEvent,
            C::Maintenance,
        ]
        .into_iter()
        .map(|cause| HistoryNoticeCause::from_recovery(cause).as_str())
        .collect();
        assert_eq!(
            labels,
            [
                "delivery_loss",
                "notification_loss",
                "epoch_gap",
                "incremental_history",
                "explicit_repair",
                "known_event",
                "maintenance_boundary",
            ]
        );
    }
}
