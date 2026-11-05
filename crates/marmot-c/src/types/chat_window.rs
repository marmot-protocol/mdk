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
c_enum! {
    /// A chat fact a filter node tests; see `ChatListConditionFfi` in the
    /// MarmotKit API reference for each one's meaning.
    MarmotChatListCondition from ChatListConditionFfi {
        Active,
        Archived,
        Left,
        PendingInvite,
        Unread,
        ManualUnread,
        Mention,
        Pinned,
        PendingLeave,
        Disbanding,
        HasDraft,
        PendingSend,
        FailedSend,
    }
}
c_enum! {
    /// Why a chat-list query was refused (`MARMOT_STATUS_INVALID_CHAT_LIST_QUERY`);
    /// the last-error detail names it.
    MarmotChatListQueryError from ChatListQueryErrorFfi {
        TooDeep,
        TooManyNodes,
        TooManyGroupIds,
        ChildOutOfRange,
        ChildNotAfterParent,
        SharedChild,
        UnreachableNode,
    }
}
c_enum! {
    /// Which fields of a `MarmotChatListFilterNode` are read.
    MarmotChatListFilterNodeKind {
        /// Every child matches; no children matches every chat.
        All,
        /// Some child matches; no children matches none.
        Any,
        /// Exactly one child, which must not match.
        Not,
        /// `condition` holds.
        Condition,
        /// The chat's group ID is in `group_ids` (hex, any case).
        GroupIds,
    }
}

/// One borrowed filter node. Child entries are indices into the query's node
/// array; fields the kind does not read may hold anything (pointers NULL).
#[repr(C)]
pub struct MarmotChatListFilterNode {
    /// A `MarmotChatListFilterNodeKind` discriminant.
    pub kind: u32,
    /// For CONDITION: a `MarmotChatListCondition` discriminant.
    pub condition: u32,
    /// For ALL and ANY: the children. For NOT: exactly one child.
    pub children: *const u32,
    pub children_len: usize,
    /// For GROUP_IDS: the listed group IDs.
    pub group_ids: *const *const c_char,
    pub group_ids_len: usize,
}

/// Borrowed chat-list query: a view narrowed by an optional filter. A NULL
/// `filter` with `filter_len` 0 is no filter (the whole view). Node 0 is the
/// root; every other node is the child of exactly one node listed before it.
#[repr(C)]
pub struct MarmotChatListViewQuery {
    /// A `MarmotChatListView` discriminant.
    pub view: u32,
    pub filter: *const MarmotChatListFilterNode,
    pub filter_len: usize,
}

impl MarmotChatListViewQuery {
    /// # Safety
    /// `filter` must be NULL with length 0 or point to `filter_len` nodes, each
    /// with valid arrays for the fields its kind reads.
    pub(crate) unsafe fn to_ffi(&self) -> Result<ChatListViewQueryFfi, crate::MarmotStatus> {
        let nodes: &[MarmotChatListFilterNode] = if self.filter.is_null() {
            if self.filter_len != 0 {
                crate::status::set_last_error("filter was NULL with nonzero length");
                return Err(crate::MarmotStatus::NullPointer);
            }
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(self.filter, self.filter_len) }
        };
        let children = |node: &MarmotChatListFilterNode| {
            Ok::<_, crate::MarmotStatus>(
                unsafe { crate::memory::opt_num_array(node.children, node.children_len) }?
                    .unwrap_or_default(),
            )
        };
        let filter = nodes
            .iter()
            .map(|node| {
                Ok(match MarmotChatListFilterNodeKind::from_c(node.kind)? {
                    MarmotChatListFilterNodeKind::All => ChatListFilterNodeFfi::All {
                        children: children(node)?,
                    },
                    MarmotChatListFilterNodeKind::Any => ChatListFilterNodeFfi::Any {
                        children: children(node)?,
                    },
                    MarmotChatListFilterNodeKind::Not => match children(node)?.as_slice() {
                        [child] => ChatListFilterNodeFfi::Not { child: *child },
                        _ => {
                            crate::status::set_last_error(
                                "a NOT filter node needs exactly one child",
                            );
                            return Err(crate::MarmotStatus::InvalidArgument);
                        }
                    },
                    MarmotChatListFilterNodeKind::Condition => ChatListFilterNodeFfi::Condition {
                        condition: MarmotChatListCondition::from_c(node.condition)?.to_ffi(),
                    },
                    MarmotChatListFilterNodeKind::GroupIds => ChatListFilterNodeFfi::GroupIds {
                        group_ids: unsafe {
                            crate::memory::str_array(node.group_ids, node.group_ids_len)
                        }?,
                    },
                })
            })
            .collect::<Result<_, crate::MarmotStatus>>()?;
        Ok(ChatListViewQueryFfi {
            view: MarmotChatListView::from_c(self.view)?.to_ffi(),
            filter,
        })
    }
}
impl MarmotChatListCondition {
    fn to_ffi(self) -> ChatListConditionFfi {
        match self {
            Self::Active => ChatListConditionFfi::Active,
            Self::Archived => ChatListConditionFfi::Archived,
            Self::Left => ChatListConditionFfi::Left,
            Self::PendingInvite => ChatListConditionFfi::PendingInvite,
            Self::Unread => ChatListConditionFfi::Unread,
            Self::ManualUnread => ChatListConditionFfi::ManualUnread,
            Self::Mention => ChatListConditionFfi::Mention,
            Self::Pinned => ChatListConditionFfi::Pinned,
            Self::PendingLeave => ChatListConditionFfi::PendingLeave,
            Self::Disbanding => ChatListConditionFfi::Disbanding,
            Self::HasDraft => ChatListConditionFfi::HasDraft,
            Self::PendingSend => ChatListConditionFfi::PendingSend,
            Self::FailedSend => ChatListConditionFfi::FailedSend,
        }
    }
}
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
        for (expected, anchor) in [
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
        ]
        .into_iter()
        .enumerate()
        {
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
            assert!(mirror.has_more_before);
            assert!(!mirror.has_more_after);
            match (expected, &mirror.anchor) {
                (0, MarmotChatListAnchorOutcome::Top) | (3, MarmotChatListAnchorOutcome::Reset) => {
                }
                (
                    1,
                    MarmotChatListAnchorOutcome::Retained {
                        group_id_hex,
                        index,
                    },
                ) => {
                    assert_eq!(*index, 0);
                    assert_eq!(
                        unsafe { std::ffi::CStr::from_ptr(*group_id_hex) }.to_bytes(),
                        b"aa"
                    );
                }
                (
                    2,
                    MarmotChatListAnchorOutcome::Recovered {
                        group_id_hex,
                        index,
                    },
                ) => {
                    assert_eq!(*index, 1);
                    assert_eq!(
                        unsafe { std::ffi::CStr::from_ptr(*group_id_hex) }.to_bytes(),
                        b"bb"
                    );
                }
                _ => panic!("anchor tag does not match source row {expected}"),
            }
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
        for (expected, entry) in
            unsafe { std::slice::from_raw_parts(mirror.accounts, mirror.accounts_len) }
                .iter()
                .enumerate()
        {
            match (expected, &entry.state) {
                (0, MarmotAccountAttentionState::Ready { total }) => {
                    assert_eq!(total.unread_count, u64::MAX);
                    assert_eq!(total.unread_mention_count, 3);
                    assert_eq!(total.unread_conversations, 2);
                    assert_eq!(total.attention_only_conversations, 1);
                }
                (1, MarmotAccountAttentionState::Unavailable { reason }) => {
                    assert_eq!(*reason, MarmotAccountAttentionUnavailable::Preparing)
                }
                (2, MarmotAccountAttentionState::Unavailable { reason }) => {
                    assert_eq!(*reason, MarmotAccountAttentionUnavailable::ReadFailed)
                }
                (3, MarmotAccountAttentionState::Unavailable { reason }) => {
                    assert_eq!(*reason, MarmotAccountAttentionUnavailable::Resetting)
                }
                _ => panic!("availability tag does not match source row {expected}"),
            }
        }
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
