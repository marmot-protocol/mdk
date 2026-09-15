//! Additive native screen DTOs; every returned snapshot owns its nested allocations.
use crate::macros::{c_enum, c_mirror};
use crate::memory::{CFree, free_c_string, owned_c_string};
use crate::types::presentation::MarmotPresentedChatRow;
use marmot_uniffi::conversions::*;
use std::ffi::c_char;
c_enum! { MarmotChatListView from ChatListViewFfi { Chats, Unread, Archived, Left, } }
c_enum! { MarmotChatListPageDirection from ChatListPageDirectionFfi { Forward, Backward, } }
c_enum! { MarmotAccountAttentionUnavailable from AccountAttentionUnavailableFfi { Preparing, ReadFailed, Resetting, } }
#[repr(C)]
pub enum MarmotChatListAnchorOutcome {
    Top,
    Retained {
        group_id_hex: *mut c_char,
        index: u32,
    },
    Recovered {
        group_id_hex: *mut c_char,
        index: u32,
    },
    Reset,
}
impl From<ChatListAnchorOutcomeFfi> for MarmotChatListAnchorOutcome {
    fn from(v: ChatListAnchorOutcomeFfi) -> Self {
        match v {
            ChatListAnchorOutcomeFfi::Top => Self::Top,
            ChatListAnchorOutcomeFfi::Reset => Self::Reset,
            ChatListAnchorOutcomeFfi::Retained {
                group_id_hex,
                index,
            } => Self::Retained {
                group_id_hex: owned_c_string(group_id_hex),
                index,
            },
            ChatListAnchorOutcomeFfi::Recovered {
                group_id_hex,
                index,
            } => Self::Recovered {
                group_id_hex: owned_c_string(group_id_hex),
                index,
            },
        }
    }
}
impl CFree for MarmotChatListAnchorOutcome {
    unsafe fn free_in_place(&mut self) {
        match self {
            Self::Retained { group_id_hex, .. } | Self::Recovered { group_id_hex, .. } => unsafe {
                free_c_string(*group_id_hex)
            },
            _ => {}
        }
    }
}
c_mirror! { MarmotChatListWindowSnapshot from ChatListWindowSnapshotFfi, free marmot_chat_list_window_snapshot_free {
    str subscription_generation,
    copy sequence: u64,
    copy view: MarmotChatListView,
    vec rows/rows_len: MarmotPresentedChatRow,
    copy has_more_before: bool,
    copy has_more_after: bool,
    rec anchor: MarmotChatListAnchorOutcome,
} }
c_mirror! { MarmotAccountAttentionTotal from AccountAttentionTotalFfi {
    copy unread_count: u64,
    copy unread_mention_count: u64,
    copy unread_conversations: u64,
    /// Active unarchived pending invitations (one each) and accepted manual-only reminders.
    /// Application badge = unread_count + attention_only_conversations; do not add invites again.
    /// Invite messages/mentions remain suppressed; archived and departed/departing chats do not count.
    copy attention_only_conversations: u64,
} }
#[repr(C)]
pub enum MarmotAccountAttentionState {
    Ready {
        total: MarmotAccountAttentionTotal,
    },
    Unavailable {
        reason: MarmotAccountAttentionUnavailable,
    },
}
impl From<AccountAttentionStateFfi> for MarmotAccountAttentionState {
    fn from(v: AccountAttentionStateFfi) -> Self {
        match v {
            AccountAttentionStateFfi::Ready { total } => Self::Ready {
                total: total.into(),
            },
            AccountAttentionStateFfi::Unavailable { reason } => Self::Unavailable {
                reason: reason.into(),
            },
        }
    }
}
impl CFree for MarmotAccountAttentionState {
    unsafe fn free_in_place(&mut self) {}
}
c_mirror! { MarmotAccountAttentionEntry from AccountAttentionEntryFfi {
    str account_id_hex,
    rec state: MarmotAccountAttentionState,
} }
c_mirror! { MarmotAccountAttentionSnapshot from AccountAttentionSnapshotFfi, free marmot_account_attention_snapshot_free {
    str subscription_generation,
    copy sequence: u64,
    vec accounts/accounts_len: MarmotAccountAttentionEntry,
} }
impl MarmotChatListView {
    pub(crate) fn to_ffi(self) -> ChatListViewFfi {
        match self {
            Self::Chats => ChatListViewFfi::Chats,
            Self::Unread => ChatListViewFfi::Unread,
            Self::Archived => ChatListViewFfi::Archived,
            Self::Left => ChatListViewFfi::Left,
        }
    }
}
impl MarmotChatListPageDirection {
    pub(crate) fn to_ffi(self) -> ChatListPageDirectionFfi {
        match self {
            Self::Forward => ChatListPageDirectionFfi::Forward,
            Self::Backward => ChatListPageDirectionFfi::Backward,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{audit, boxed};
    #[test]
    fn screen_snapshots_deep_free_all_anchor_and_availability_variants() {
        let _guard = audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let before = audit::live_allocations();
        for anchor in [
            ChatListAnchorOutcomeFfi::Top,
            ChatListAnchorOutcomeFfi::Retained {
                group_id_hex: "aa".into(),
                index: 0,
            },
            ChatListAnchorOutcomeFfi::Recovered {
                group_id_hex: "bb".into(),
                index: 1,
            },
            ChatListAnchorOutcomeFfi::Reset,
        ] {
            let snapshot = ChatListWindowSnapshotFfi {
                subscription_generation: "generation".into(),
                sequence: 42,
                view: ChatListViewFfi::Unread,
                rows: vec![],
                has_more_before: true,
                has_more_after: false,
                anchor,
            };
            let mirror: MarmotChatListWindowSnapshot = snapshot.into();
            assert_eq!(mirror.sequence, 42);
            assert_eq!(mirror.view, MarmotChatListView::Unread);
            unsafe {
                marmot_chat_list_window_snapshot_free(boxed(mirror));
            }
        }
        let states = vec![
            AccountAttentionStateFfi::Ready {
                total: AccountAttentionTotalFfi {
                    unread_count: u64::MAX,
                    unread_mention_count: 3,
                    unread_conversations: 2,
                    attention_only_conversations: 1,
                },
            },
            AccountAttentionStateFfi::Unavailable {
                reason: AccountAttentionUnavailableFfi::Preparing,
            },
            AccountAttentionStateFfi::Unavailable {
                reason: AccountAttentionUnavailableFfi::ReadFailed,
            },
            AccountAttentionStateFfi::Unavailable {
                reason: AccountAttentionUnavailableFfi::Resetting,
            },
        ];
        let mirror: MarmotAccountAttentionSnapshot = AccountAttentionSnapshotFfi {
            subscription_generation: "generation".into(),
            sequence: 7,
            accounts: states
                .into_iter()
                .map(|state| AccountAttentionEntryFfi {
                    account_id_hex: "identity".into(),
                    state,
                })
                .collect(),
        }
        .into();
        assert_eq!(mirror.accounts_len, 4);
        assert!(
            matches!(unsafe{&(*mirror.accounts).state}, MarmotAccountAttentionState::Ready {total} if total.unread_count==u64::MAX && total.unread_mention_count==3)
        );
        unsafe {
            marmot_account_attention_snapshot_free(boxed(mirror));
            marmot_account_attention_snapshot_free(std::ptr::null_mut());
            marmot_chat_list_window_snapshot_free(std::ptr::null_mut());
        }
        #[cfg(feature = "alloc-audit")]
        assert_eq!(audit::live_allocations(), before);
        assert!(MarmotChatListView::from_c(4).is_err());
        assert!(MarmotChatListPageDirection::from_c(u32::MAX).is_err());
    }
}
