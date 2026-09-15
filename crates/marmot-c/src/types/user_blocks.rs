//! C mirrors for the account-private block list.
use crate::macros::c_mirror;
use marmot_uniffi::{BlockListSnapshotFfi, BlockedUserFfi};
c_mirror! {
    MarmotBlockedUser from BlockedUserFfi,
    list(MarmotBlockedUserList, marmot_blocked_user_list_free) {
        str public_key,
        copy is_private: bool,
        copy created_at_ms: i64,
    }
}
c_mirror! {
    MarmotBlockListSnapshot from BlockListSnapshotFfi,
    free marmot_block_list_snapshot_free {
        copy revision: u64,
        vec users/users_len: MarmotBlockedUser,
    }
}

#[cfg(all(test, feature = "alloc-audit"))]
mod tests {
    use super::*;
    use crate::memory::{audit, boxed};
    #[test]
    fn blocked_user_snapshot_deep_free() {
        let _lock = audit::test_lock();
        let before = audit::live_allocations();
        let snapshot = boxed(MarmotBlockListSnapshot::from(BlockListSnapshotFfi {
            revision: u64::MAX,
            users: vec![BlockedUserFfi {
                public_key: "ab".repeat(32),
                is_private: true,
                created_at_ms: 123,
            }],
        }));
        unsafe {
            assert_eq!((*snapshot).revision, u64::MAX);
            assert_eq!((*snapshot).users_len, 1);
            assert!((*(*snapshot).users).is_private);
            marmot_block_list_snapshot_free(snapshot);
            marmot_block_list_snapshot_free(std::ptr::null_mut());
        }
        assert_eq!(audit::live_allocations(), before);
    }
}
