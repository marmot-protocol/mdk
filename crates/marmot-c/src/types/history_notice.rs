//! C mirrors of the "history may be incomplete" notice conversions.

use marmot_uniffi::conversions::{HistoryNoticeCauseFfi, HistoryNoticeFfi};

use crate::macros::{c_enum, c_mirror};

c_enum! {
    /// Why recovery parked. Current policy parks only the first five;
    /// `KnownEvent` and `MaintenanceBoundary` are reserved.
    MarmotHistoryNoticeCause from HistoryNoticeCauseFfi {
        /// Deliveries were dropped from a full account queue, or spilled
        /// rows could not be admitted, and comparison could not recover them.
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
}

c_mirror! {
    /// One "history may be incomplete" occurrence. `notice_id` is opaque and
    /// changes when recovery re-arms; `group_id_hex` is NULL for an
    /// account-wide occurrence; `has_parked_at_ms` is false when the parking
    /// time was not recorded.
    MarmotHistoryNotice from HistoryNoticeFfi,
    list(MarmotHistoryNoticeList, marmot_history_notice_list_free) {
        str notice_id,
        copy cause: MarmotHistoryNoticeCause,
        opt_str group_id_hex,
        opt_copy has_parked_at_ms/parked_at_ms: u64,
    }
}

#[cfg(all(test, feature = "alloc-audit"))]
mod tests {
    use super::*;
    use crate::memory::{audit, boxed};

    #[test]
    fn notice_list_deep_free_preserves_every_field() {
        let _lock = audit::test_lock();
        let before = audit::live_allocations();
        let list = boxed(MarmotHistoryNoticeList::from(vec![
            HistoryNoticeFfi {
                notice_id: "ab".repeat(24),
                cause: HistoryNoticeCauseFfi::EpochGap,
                group_id_hex: Some("11".repeat(16)),
                parked_at_ms: Some(7),
            },
            HistoryNoticeFfi {
                notice_id: "cd".repeat(24),
                cause: HistoryNoticeCauseFfi::DeliveryLoss,
                group_id_hex: None,
                parked_at_ms: None,
            },
        ]));
        unsafe {
            assert_eq!((*list).len, 2);
            let first = &*(*list).items;
            assert_eq!(first.cause, MarmotHistoryNoticeCause::EpochGap);
            assert!(!first.group_id_hex.is_null());
            assert!(first.has_parked_at_ms);
            assert_eq!(first.parked_at_ms, 7);
            let second = &*(*list).items.add(1);
            assert_eq!(second.cause, MarmotHistoryNoticeCause::DeliveryLoss);
            assert!(second.group_id_hex.is_null());
            assert!(!second.has_parked_at_ms);
            marmot_history_notice_list_free(list);
            marmot_history_notice_list_free(std::ptr::null_mut());
        }
        assert_eq!(audit::live_allocations(), before);
    }
}
