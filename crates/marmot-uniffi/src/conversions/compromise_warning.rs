//! The account's compromise warning.

use marmot_app::{CompromiseWarningItem, CompromiseWarningReason};

/// Why something is in the compromise warning. Later releases add reasons;
/// show one the app does not know as a generic one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum CompromiseWarningReasonFfi {
    /// A sign-in the user answered This wasn't me, on this device or another.
    RejectedSignIn,
    /// A KeyPackage this device found in its own slot that it did not make.
    /// This device has replaced it.
    ForeignOwnSlotKeyPackage,
}

/// One thing the open compromise warning gathers.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct CompromiseWarningItemFfi {
    pub reason: CompromiseWarningReasonFfi,
    /// The KeyPackage slot the item names: the rejected sign-in's, or this
    /// device's own for a KeyPackage found there. 64 lowercase hex
    /// characters.
    pub slot_id_hex: String,
    /// The found KeyPackage's `KeyPackageRef` in lowercase hex, for
    /// `ForeignOwnSlotKeyPackage`; `None` otherwise.
    pub key_package_ref_hex: Option<String>,
    /// In Unix seconds: when the rejection was made, as the device that made
    /// it wrote it, or when this device found the KeyPackage.
    pub occurred_at: u64,
}

impl From<CompromiseWarningItem> for CompromiseWarningItemFfi {
    fn from(value: CompromiseWarningItem) -> Self {
        Self {
            reason: match value.reason {
                CompromiseWarningReason::RejectedSignIn => {
                    CompromiseWarningReasonFfi::RejectedSignIn
                }
                CompromiseWarningReason::ForeignOwnSlotKeyPackage => {
                    CompromiseWarningReasonFfi::ForeignOwnSlotKeyPackage
                }
            },
            slot_id_hex: value.slot_id_hex,
            key_package_ref_hex: value.key_package_ref_hex,
            occurred_at: value.occurred_at,
        }
    }
}
