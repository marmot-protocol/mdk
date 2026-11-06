//! Native screen contracts. Storage cursors stay inside the runtime-owned window.
use super::PresentedChatRowFfi;
use marmot_app as app;

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ChatListViewFfi {
    Chats,
    Unread,
    Archived,
    Left,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ChatListPageDirectionFfi {
    Forward,
    Backward,
}
macro_rules! enums {
    ($ffi:ident, $app:ident, $($variant:ident),+) => {
        impl From<$ffi> for app::$app {
            fn from(v: $ffi) -> Self { match v { $($ffi::$variant => Self::$variant),+ } }
        }
        impl From<app::$app> for $ffi {
            fn from(v: app::$app) -> Self { match v { $(app::$app::$variant => Self::$variant),+ } }
        }
    };
}
enums!(ChatListViewFfi, ChatListView, Chats, Unread, Archived, Left);
enums!(
    ChatListPageDirectionFfi,
    ChatListPageDirection,
    Forward,
    Backward
);

/// A chat-list query: a native view narrowed by an optional filter, matched in
/// SQL over every chat in the view before paging. The live window, select-all
/// IDs and revalidation all take it, so list, count and selection agree.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ChatListViewQueryFfi {
    pub view: ChatListViewFfi,
    /// The filter as a flat node list. Empty means no filter (the whole view).
    /// Node 0 is the root; every other node is the child of exactly one node
    /// listed before it. At most 64 nodes, 8 levels and 500 group IDs in all.
    pub filter: Vec<ChatListFilterNodeFfi>,
}

/// One filter node. Child entries are indices into the query's node list.
/// An empty `All` matches every chat in the view; an empty `Any` matches none.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ChatListFilterNodeFfi {
    All {
        children: Vec<u32>,
    },
    Any {
        children: Vec<u32>,
    },
    Not {
        child: u32,
    },
    Condition {
        condition: ChatListConditionFfi,
    },
    /// Chats whose group ID is listed (hex, any case). Inclusion never adds a
    /// chat outside the view; to exclude IDs, wrap this node in `Not`.
    GroupIds {
        group_ids: Vec<String>,
    },
}

/// Chat facts a filter can test. Each matches what the presented row shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ChatListConditionFfi {
    /// Neither archived nor departed, including invitations.
    Active,
    /// Archived and not departed.
    Archived,
    /// Departed, disbanded, or with a leave or disband outstanding.
    Left,
    /// An invitation not yet accepted or declined.
    PendingInvite,
    /// Shows an unread badge: unread messages or a manual mark. Never an
    /// invitation or a Left chat.
    Unread,
    /// Unread because the user marked it so.
    ManualUnread,
    /// Unread with an unread mention of this account.
    Mention,
    Pinned,
    /// A leave request is still outstanding.
    PendingLeave,
    /// A local or inbound disband awaits convergence.
    Disbanding,
    /// A draft with non-blank text or an attachment.
    HasDraft,
    /// The row's last message shows a pending send (`ChatListMessageDeliveryStateFfi::Pending`).
    PendingSend,
    /// The row's last message shows a failed send (`ChatListMessageDeliveryStateFfi::Failed`).
    FailedSend,
}
enums!(
    ChatListConditionFfi,
    ChatListCondition,
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
    FailedSend
);

/// Why a chat-list query was refused. Nothing was read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ChatListQueryErrorFfi {
    /// More than 8 nested levels.
    TooDeep,
    /// More than 64 nodes.
    TooManyNodes,
    /// More than 500 group IDs across all `GroupIds` nodes.
    TooManyGroupIds,
    /// A child index is past the end of the node list.
    ChildOutOfRange,
    /// A child index is at or before its parent's index.
    ChildNotAfterParent,
    /// A node is the child of more than one node.
    SharedChild,
    /// A node after the root is nobody's child.
    UnreachableNode,
}
impl From<app::ChatListQueryError> for ChatListQueryErrorFfi {
    fn from(v: app::ChatListQueryError) -> Self {
        use app::ChatListQueryError as E;
        match v {
            E::TooDeep => Self::TooDeep,
            E::TooManyNodes => Self::TooManyNodes,
            E::TooManyGroupIds => Self::TooManyGroupIds,
            E::ChildOutOfRange => Self::ChildOutOfRange,
            E::ChildNotAfterParent => Self::ChildNotAfterParent,
            E::SharedChild => Self::SharedChild,
            E::UnreachableNode => Self::UnreachableNode,
        }
    }
}
impl std::fmt::Display for ChatListQueryErrorFfi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::TooDeep => "too_deep",
            Self::TooManyNodes => "too_many_nodes",
            Self::TooManyGroupIds => "too_many_group_ids",
            Self::ChildOutOfRange => "child_out_of_range",
            Self::ChildNotAfterParent => "child_not_after_parent",
            Self::SharedChild => "shared_child",
            Self::UnreachableNode => "unreachable_node",
        })
    }
}
impl From<ChatListViewFfi> for ChatListViewQueryFfi {
    fn from(view: ChatListViewFfi) -> Self {
        Self {
            view,
            filter: Vec::new(),
        }
    }
}
impl TryFrom<ChatListViewQueryFfi> for app::ChatListViewQuery {
    type Error = app::ChatListQueryError;
    fn try_from(v: ChatListViewQueryFfi) -> Result<Self, Self::Error> {
        let nodes = v
            .filter
            .into_iter()
            .map(|node| match node {
                ChatListFilterNodeFfi::All { children } => app::ChatListFilterNode::All(children),
                ChatListFilterNodeFfi::Any { children } => app::ChatListFilterNode::Any(children),
                ChatListFilterNodeFfi::Not { child } => app::ChatListFilterNode::Not(child),
                ChatListFilterNodeFfi::Condition { condition } => {
                    app::ChatListFilterNode::Condition(condition.into())
                }
                ChatListFilterNodeFfi::GroupIds { group_ids } => {
                    app::ChatListFilterNode::GroupIds(group_ids)
                }
            })
            .collect();
        Ok(Self {
            view: v.view.into(),
            filter: app::ChatListFilter::from_nodes(nodes)?,
        })
    }
}

#[derive(Clone, uniffi::Enum)]
pub enum ChatListAnchorOutcomeFfi {
    Top,
    Retained { group_id_hex: String, index: u32 },
    Recovered { group_id_hex: String, index: u32 },
    Reset,
}
#[derive(Clone, uniffi::Record)]
pub struct ChatListWindowSnapshotFfi {
    pub subscription_generation: String,
    pub sequence: u64,
    pub view: ChatListViewFfi,
    pub rows: Vec<PresentedChatRowFfi>,
    pub has_more_before: bool,
    pub has_more_after: bool,
    pub anchor: ChatListAnchorOutcomeFfi,
}
impl From<app::ChatListWindowSnapshot> for ChatListWindowSnapshotFfi {
    fn from(v: app::ChatListWindowSnapshot) -> Self {
        Self {
            subscription_generation: v.subscription_generation,
            sequence: v.sequence,
            view: v.view.into(),
            rows: v.rows.into_iter().map(Into::into).collect(),
            has_more_before: v.has_more_before,
            has_more_after: v.has_more_after,
            anchor: match v.anchor {
                app::ChatListAnchorOutcome::Top => ChatListAnchorOutcomeFfi::Top,
                app::ChatListAnchorOutcome::Reset => ChatListAnchorOutcomeFfi::Reset,
                app::ChatListAnchorOutcome::Retained {
                    group_id_hex,
                    index,
                } => ChatListAnchorOutcomeFfi::Retained {
                    group_id_hex,
                    index: super::saturating_u32(index),
                },
                app::ChatListAnchorOutcome::Recovered {
                    group_id_hex,
                    index,
                } => ChatListAnchorOutcomeFfi::Recovered {
                    group_id_hex,
                    index: super::saturating_u32(index),
                },
            },
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum AccountAttentionUnavailableFfi {
    Preparing,
    ReadFailed,
    Resetting,
}
/// Account/application badge counters; archived and departed/departing chats are excluded.
/// Pending invitations add one attention-only item each, with no unread messages or mentions.
/// The application badge is `unread_count + attention_only_conversations`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct AccountAttentionTotalFfi {
    pub unread_count: u64,
    pub unread_mention_count: u64,
    pub unread_conversations: u64,
    pub attention_only_conversations: u64,
}
#[derive(Clone, uniffi::Enum)]
pub enum AccountAttentionStateFfi {
    Ready {
        total: AccountAttentionTotalFfi,
    },
    Unavailable {
        reason: AccountAttentionUnavailableFfi,
    },
}
#[derive(Clone, uniffi::Record)]
pub struct AccountAttentionEntryFfi {
    pub account_id_hex: String,
    pub state: AccountAttentionStateFfi,
}
#[derive(Clone, uniffi::Record)]
pub struct AccountAttentionSnapshotFfi {
    pub subscription_generation: String,
    pub sequence: u64,
    pub accounts: Vec<AccountAttentionEntryFfi>,
}
impl From<app::AccountAttentionSnapshot> for AccountAttentionSnapshotFfi {
    fn from(v: app::AccountAttentionSnapshot) -> Self {
        Self {
            subscription_generation: v.subscription_generation,
            sequence: v.sequence,
            accounts: v
                .accounts
                .into_iter()
                .map(|a| AccountAttentionEntryFfi {
                    account_id_hex: a.account_id_hex,
                    state: match a.state {
                        app::AccountAttentionState::Ready(t) => AccountAttentionStateFfi::Ready {
                            total: AccountAttentionTotalFfi {
                                unread_count: t.unread_count,
                                unread_mention_count: t.unread_mention_count,
                                unread_conversations: t.unread_conversations,
                                attention_only_conversations: t.attention_only_conversations,
                            },
                        },
                        app::AccountAttentionState::Unavailable(r) => {
                            AccountAttentionStateFfi::Unavailable {
                                reason: match r {
                                    app::AccountAttentionUnavailable::Preparing => {
                                        AccountAttentionUnavailableFfi::Preparing
                                    }
                                    app::AccountAttentionUnavailable::ReadFailed => {
                                        AccountAttentionUnavailableFfi::ReadFailed
                                    }
                                    app::AccountAttentionUnavailable::Resetting => {
                                        AccountAttentionUnavailableFfi::Resetting
                                    }
                                },
                            }
                        }
                    },
                })
                .collect(),
        }
    }
}
