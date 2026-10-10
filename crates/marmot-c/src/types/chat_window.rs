//! Additive native screen DTOs; every returned snapshot owns its nested allocations.
use crate::macros::{c_enum, c_mirror};
use crate::memory::{CFree, free_c_string, owned_c_string};
use crate::types::presentation::MarmotPresentedChatRow;
use marmot_uniffi::conversions::*;
use std::ffi::c_char;

/// Borrowed input. Keep all strings/arrays live through the capture call; the
/// library copies them and never frees caller memory. NULL keyword means absent.
#[repr(C)]
pub struct MarmotChatFolderSelectionRule {
    pub version: u32,
    pub include_member_ids: *const *const c_char,
    pub include_member_ids_len: usize,
    pub keyword: *const c_char,
    pub unread_only: u8,
    pub unread_mentions_only: u8,
    pub groups_only: u8,
    pub direct_chats_only: u8,
    pub pinned_only: u8,
    pub include_all: u8,
    pub archived_only: u8,
    pub include_muted: u8,
    pub smart_filter_json: *const c_char,
    pub manual_include_ids: *const *const c_char,
    pub manual_include_ids_len: usize,
    pub manual_exclude_ids: *const *const c_char,
    pub manual_exclude_ids_len: usize,
}
impl MarmotChatFolderSelectionRule {
    /// # Safety
    /// Every non-NULL pointer must refer to the stated live borrowed input.
    pub(crate) unsafe fn to_ffi(&self) -> Result<ChatFolderSelectionRuleFfi, crate::MarmotStatus> {
        // Reject excessive lengths before pointer traversal or allocation.
        if self.version != 1
            || self.include_member_ids_len > 256
            || self.manual_include_ids_len > 1024
            || self.manual_exclude_ids_len > 1024
        {
            crate::status::set_last_error("invalid folder rule version or excessive input counts");
            return Err(crate::MarmotStatus::ChatSelectionInvalidFilter);
        }
        let value = ChatFolderSelectionRuleFfi {
            version: self.version,
            include_member_ids: unsafe {
                crate::memory::str_array(self.include_member_ids, self.include_member_ids_len)
            }?,
            keyword: unsafe { crate::memory::optional_str(self.keyword) }?,
            unread_only: self.unread_only != 0,
            unread_mentions_only: self.unread_mentions_only != 0,
            groups_only: self.groups_only != 0,
            direct_chats_only: self.direct_chats_only != 0,
            pinned_only: self.pinned_only != 0,
            include_all: self.include_all != 0,
            archived_only: self.archived_only != 0,
            include_muted: self.include_muted != 0,
            smart_filter_json: unsafe { crate::memory::optional_str(self.smart_filter_json) }?,
            manual_include_ids: unsafe {
                crate::memory::str_array(self.manual_include_ids, self.manual_include_ids_len)
            }?,
            manual_exclude_ids: unsafe {
                crate::memory::str_array(self.manual_exclude_ids, self.manual_exclude_ids_len)
            }?,
        };
        value
            .validate()
            .map_err(|error| crate::status::status_from_error(&error))?;
        Ok(value)
    }
}

#[cfg(test)]
mod folder_input_tests {
    use super::*;
    fn rule() -> MarmotChatFolderSelectionRule {
        MarmotChatFolderSelectionRule {
            version: 1,
            include_member_ids: std::ptr::null(),
            include_member_ids_len: 0,
            keyword: std::ptr::null(),
            unread_only: 0,
            unread_mentions_only: 0,
            groups_only: 0,
            direct_chats_only: 0,
            pinned_only: 0,
            include_all: 0,
            archived_only: 0,
            include_muted: 0,
            smart_filter_json: std::ptr::null(),
            manual_include_ids: std::ptr::null(),
            manual_include_ids_len: 0,
            manual_exclude_ids: std::ptr::null(),
            manual_exclude_ids_len: 0,
        }
    }
    #[test]
    fn excessive_input_counts_fail_before_pointer_traversal() {
        let mut input = rule();
        input.include_member_ids_len = 257;
        input.include_member_ids = std::ptr::dangling();
        assert!(matches!(
            unsafe { input.to_ffi() },
            Err(crate::MarmotStatus::ChatSelectionInvalidFilter)
        ));
        input = rule();
        input.manual_include_ids_len = 1025;
        assert!(matches!(
            unsafe { input.to_ffi() },
            Err(crate::MarmotStatus::ChatSelectionInvalidFilter)
        ));
    }
    #[test]
    fn borrowed_arrays_and_byte_booleans_follow_c_input_contract() {
        let mut input = rule();
        input.include_muted = 255;
        input.unread_mentions_only = 255;
        input.direct_chats_only = 255;
        input.pinned_only = 255;
        input.include_all = 255;
        let smart = std::ffi::CString::new(
            r#"{"version":1,"root":{"kind":"group","all":true,"not":false,"children":[]}}"#,
        )
        .unwrap();
        input.smart_filter_json = smart.as_ptr();
        let value = unsafe { input.to_ffi() }.unwrap();
        assert!(
            value.include_muted
                && value.unread_mentions_only
                && value.direct_chats_only
                && value.pinned_only
                && value.include_all
        );
        assert_eq!(value.smart_filter_json.as_deref(), smart.to_str().ok());
        let invalid = std::ffi::CString::new(
            r#"{"version":2,"root":{"kind":"group","all":true,"not":false,"children":[]}}"#,
        )
        .unwrap();
        input.smart_filter_json = invalid.as_ptr();
        assert!(matches!(
            unsafe { input.to_ffi() },
            Err(crate::MarmotStatus::ChatSelectionInvalidFilter)
        ));
        input.smart_filter_json = std::ptr::null();
        input.manual_include_ids_len = 1;
        assert!(matches!(
            unsafe { input.to_ffi() },
            Err(crate::MarmotStatus::NullPointer)
        ));
    }
}
c_mirror! { MarmotChatSelectionSummary from ChatSelectionSummaryFfi, free marmot_chat_selection_summary_free {
    copy revision: u64,
    copy count: u64,
} }
c_mirror! { MarmotChatSelectionPage from ChatSelectionPageFfi, free marmot_chat_selection_page_free {
    rec summary: MarmotChatSelectionSummary,
    str_vec group_ids/group_ids_len,
} }
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
    fn chat_selection_pages_preserve_count_revision_and_deep_free_ids() {
        let _guard = audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let before = audit::live_allocations();
        for count in [0, 1, 200] {
            let page = ChatSelectionPageFfi {
                summary: ChatSelectionSummaryFfi {
                    revision: 42,
                    count: 501,
                },
                group_ids: (0..count).map(|i| format!("{i:04x}")).collect(),
            };
            let mirror: MarmotChatSelectionPage = page.into();
            assert_eq!(mirror.summary.revision, 42);
            assert_eq!(mirror.summary.count, 501);
            assert_eq!(mirror.group_ids_len, count);
            unsafe {
                marmot_chat_selection_page_free(boxed(mirror));
            }
        }
        let summary: MarmotChatSelectionSummary = ChatSelectionSummaryFfi {
            revision: u64::MAX,
            count: u64::MAX,
        }
        .into();
        assert_eq!(summary.count, u64::MAX);
        unsafe {
            marmot_chat_selection_summary_free(boxed(summary));
            marmot_chat_selection_page_free(std::ptr::null_mut());
            marmot_chat_selection_summary_free(std::ptr::null_mut());
        }
        #[cfg(feature = "alloc-audit")]
        assert_eq!(audit::live_allocations(), before);
    }
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
