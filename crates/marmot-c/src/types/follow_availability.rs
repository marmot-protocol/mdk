//! C mirrors for direct-follow KeyPackage availability and refresh progress.
use crate::macros::{c_enum, c_mirror};
use marmot_uniffi::{
    FollowAvailabilityFfi, FollowAvailabilityPageFfi, FollowAvailabilityRefreshPhaseFfi,
    FollowAvailabilityRefreshStatusFfi, FollowAvailabilitySourceFfi, FollowAvailabilityStateFfi,
};

c_enum! { MarmotFollowAvailabilityState from FollowAvailabilityStateFfi { Ready, Unknown, NotFound } }
c_enum! { MarmotFollowAvailabilitySource from FollowAvailabilitySourceFfi { None, Network } }
c_enum! { MarmotFollowAvailabilityRefreshPhase from FollowAvailabilityRefreshPhaseFfi { Idle, Running, Complete, Partial, Cancelled, Throttled, Failed } }

c_mirror! { MarmotFollowAvailability from FollowAvailabilityFfi {
    str account_id_hex,
    copy state: MarmotFollowAvailabilityState,
    opt_copy has_checked_at/checked_at: u64,
    opt_copy has_fresh_until/fresh_until: u64,
    opt_str key_package_event_id,
    copy source: MarmotFollowAvailabilitySource,
} }

c_mirror! { MarmotFollowAvailabilityPage from FollowAvailabilityPageFfi, free marmot_follow_availability_page_free {
    vec rows/rows_len: MarmotFollowAvailability,
    opt_str next_cursor,
} }

c_mirror! { MarmotFollowAvailabilityRefreshStatus from FollowAvailabilityRefreshStatusFfi, free marmot_follow_availability_refresh_status_free {
    opt_copy has_operation_id/operation_id: u64,
    copy phase: MarmotFollowAvailabilityRefreshPhase,
    copy total: u32,
    copy completed: u32,
    copy ready: u32,
    copy unknown: u32,
    copy not_found: u32,
    copy failed: u32,
    copy truncated: bool,
} }

#[cfg(all(test, feature = "alloc-audit"))]
mod tests {
    use super::*;
    use crate::memory::{audit, boxed};

    #[test]
    fn availability_deep_free() {
        let _guard = audit::test_lock();
        let before = audit::live_allocations();
        let page = boxed(MarmotFollowAvailabilityPage::from(
            FollowAvailabilityPageFfi {
                rows: vec![
                    FollowAvailabilityFfi {
                        account_id_hex: "ready".into(),
                        state: FollowAvailabilityStateFfi::Ready,
                        checked_at: Some(10),
                        fresh_until: Some(20),
                        key_package_event_id: Some("event".into()),
                        source: FollowAvailabilitySourceFfi::Network,
                    },
                    FollowAvailabilityFfi {
                        account_id_hex: "missing".into(),
                        state: FollowAvailabilityStateFfi::NotFound,
                        checked_at: None,
                        fresh_until: None,
                        key_package_event_id: None,
                        source: FollowAvailabilitySourceFfi::None,
                    },
                ],
                next_cursor: Some("cursor".into()),
            },
        ));
        let running = boxed(MarmotFollowAvailabilityRefreshStatus::from(
            FollowAvailabilityRefreshStatusFfi {
                operation_id: Some(7),
                phase: FollowAvailabilityRefreshPhaseFfi::Running,
                total: 2,
                completed: 1,
                ready: 1,
                unknown: 1,
                not_found: 0,
                failed: 0,
                truncated: true,
            },
        ));
        let idle = boxed(MarmotFollowAvailabilityRefreshStatus::from(
            FollowAvailabilityRefreshStatusFfi {
                operation_id: None,
                phase: FollowAvailabilityRefreshPhaseFfi::Idle,
                total: 0,
                completed: 0,
                ready: 0,
                unknown: 0,
                not_found: 0,
                failed: 0,
                truncated: false,
            },
        ));

        unsafe {
            assert_eq!((*page).rows_len, 2);
            let rows = (*page).rows;
            assert!((*rows).has_checked_at);
            assert_eq!((*rows).checked_at, 10);
            assert!((*rows).has_fresh_until);
            assert!(!(*rows).key_package_event_id.is_null());
            assert!(!(*rows.add(1)).has_checked_at);
            assert!(!(*rows.add(1)).has_fresh_until);
            assert!((*rows.add(1)).key_package_event_id.is_null());
            assert!(!(*page).next_cursor.is_null());
            assert!((*running).has_operation_id);
            assert_eq!((*running).operation_id, 7);
            assert!(!(*idle).has_operation_id);
            assert_eq!((*idle).operation_id, 0);

            marmot_follow_availability_page_free(page);
            marmot_follow_availability_page_free(std::ptr::null_mut());
            marmot_follow_availability_refresh_status_free(running);
            marmot_follow_availability_refresh_status_free(idle);
            marmot_follow_availability_refresh_status_free(std::ptr::null_mut());
        }
        assert_eq!(audit::live_allocations(), before);
    }
}
