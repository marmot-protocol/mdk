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
