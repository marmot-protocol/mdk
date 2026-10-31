//! C mirrors of the account's compromise warning.

use marmot_uniffi::conversions::{CompromiseWarningItemFfi, CompromiseWarningReasonFfi};

use crate::macros::{c_enum, c_mirror};

c_enum! {
    /// Why something is in the compromise warning. Later releases add
    /// values: show one the host does not know as a generic reason.
    MarmotCompromiseWarningReason from CompromiseWarningReasonFfi {
        /// A sign-in the user answered This wasn't me, on this device or
        /// another.
        RejectedSignIn,
        /// A KeyPackage one of the account's devices found where they had
        /// not published, and rejected.
        RejectedKeyPackage,
    }
}

c_mirror! {
    /// One thing the open compromise warning gathers. `reason` is a
    /// `MarmotCompromiseWarningReason` discriminant carried as `uint32_t`, so
    /// a host can show a value it does not know as a generic reason.
    /// `slot_id_hex` is the KeyPackage slot the rejection names.
    /// `key_package_ref_hex` is set only for `RejectedKeyPackage`.
    /// `occurred_at` is when the rejection was made, in Unix seconds, as the
    /// device that made it wrote it.
    MarmotCompromiseWarningItem from CompromiseWarningItemFfi,
    list(MarmotCompromiseWarningItemList, marmot_compromise_warning_item_list_free) {
        enum_val reason: MarmotCompromiseWarningReason,
        str slot_id_hex,
        opt_str key_package_ref_hex,
        copy occurred_at: u64,
    }
}

#[cfg(all(test, feature = "alloc-audit"))]
mod tests {
    use super::*;
    use crate::memory::{audit, boxed};

    #[test]
    fn compromise_warning_item_list_deep_free_preserves_every_field() {
        let _lock = audit::test_lock();
        let before = audit::live_allocations();
        let list = boxed(MarmotCompromiseWarningItemList::from(vec![
            CompromiseWarningItemFfi {
                reason: CompromiseWarningReasonFfi::RejectedSignIn,
                slot_id_hex: "ab".repeat(32),
                key_package_ref_hex: None,
                occurred_at: 7,
            },
            CompromiseWarningItemFfi {
                reason: CompromiseWarningReasonFfi::RejectedKeyPackage,
                slot_id_hex: "cd".repeat(32),
                key_package_ref_hex: Some("ef".repeat(32)),
                occurred_at: 9,
            },
        ]));
        unsafe {
            assert_eq!((*list).len, 2);
            let first = &*(*list).items;
            assert_eq!(
                first.reason,
                MarmotCompromiseWarningReason::RejectedSignIn as u32
            );
            assert_eq!(
                std::ffi::CStr::from_ptr(first.slot_id_hex)
                    .to_str()
                    .unwrap(),
                "ab".repeat(32)
            );
            assert!(first.key_package_ref_hex.is_null());
            assert_eq!(first.occurred_at, 7);
            let second = &*(*list).items.add(1);
            assert_eq!(
                second.reason,
                MarmotCompromiseWarningReason::RejectedKeyPackage as u32
            );
            assert_eq!(
                std::ffi::CStr::from_ptr(second.key_package_ref_hex)
                    .to_str()
                    .unwrap(),
                "ef".repeat(32)
            );
            marmot_compromise_warning_item_list_free(list);
            marmot_compromise_warning_item_list_free(std::ptr::null_mut());
        }
        assert_eq!(audit::live_allocations(), before);
    }
}
