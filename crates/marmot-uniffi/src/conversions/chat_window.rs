//! Native screen contracts. Storage cursors stay inside the runtime-owned window.
use super::PresentedChatRowFfi;
use marmot_app as app;

#[derive(Clone, uniffi::Record)]
pub struct ChatFolderSelectionRuleFfi {
    pub version: u32,
    pub include_member_ids: Vec<String>,
    pub keyword: Option<String>,
    pub unread_only: bool,
    pub unread_mentions_only: bool,
    pub groups_only: bool,
    pub direct_chats_only: bool,
    pub pinned_only: bool,
    pub include_all: bool,
    pub archived_only: bool,
    pub include_muted: bool,
    pub smart_filter_json: Option<String>,
    pub manual_include_ids: Vec<String>,
    pub manual_exclude_ids: Vec<String>,
}
impl ChatFolderSelectionRuleFfi {
    pub fn validate(&self) -> Result<(), crate::MarmotKitError> {
        let native: app::ChatFolderSelectionRule = self.clone().into();
        native
            .validate()
            .map_err(|_| crate::MarmotKitError::ChatSelectionInvalidFilter)
    }
}
impl From<ChatFolderSelectionRuleFfi> for app::ChatFolderSelectionRule {
    fn from(v: ChatFolderSelectionRuleFfi) -> Self {
        Self {
            version: v.version,
            include_member_ids: v.include_member_ids,
            keyword: v.keyword,
            unread_only: v.unread_only,
            unread_mentions_only: v.unread_mentions_only,
            groups_only: v.groups_only,
            direct_chats_only: v.direct_chats_only,
            pinned_only: v.pinned_only,
            include_all: v.include_all,
            archived_only: v.archived_only,
            include_muted: v.include_muted,
            smart_filter_json: v.smart_filter_json,
            manual_include_ids: v.manual_include_ids,
            manual_exclude_ids: v.manual_exclude_ids,
        }
    }
}

#[cfg(test)]
mod folder_rule_tests {
    use super::*;
    #[test]
    fn folder_conversion_preserves_flags_ids_and_literal_text() {
        let value = ChatFolderSelectionRuleFfi {
            version: 1,
            include_member_ids: vec!["AB".repeat(32)],
            keyword: Some(" 中文 ".into()),
            unread_only: true,
            unread_mentions_only: true,
            groups_only: true,
            direct_chats_only: true,
            pinned_only: true,
            include_all: true,
            archived_only: true,
            include_muted: true,
            smart_filter_json: Some(
                r#"{"version":1,"root":{"kind":"group","all":true,"not":false,"children":[]}}"#
                    .into(),
            ),
            manual_include_ids: vec!["aa".into()],
            manual_exclude_ids: vec!["bb".into()],
        };
        value.validate().unwrap();
        let native: app::ChatFolderSelectionRule = value.into();
        assert!(
            native.unread_only
                && native.groups_only
                && native.archived_only
                && native.include_muted
                && native.unread_mentions_only
                && native.direct_chats_only
                && native.pinned_only
                && native.include_all
        );
        assert_eq!(native.keyword.as_deref(), Some(" 中文 "));
        assert_eq!(native.include_member_ids, ["AB".repeat(32)]);
        assert_eq!(native.manual_include_ids, ["aa"]);
        assert_eq!(native.manual_exclude_ids, ["bb"]);
        assert_eq!(
            native.smart_filter_json.as_deref(),
            Some(r#"{"version":1,"root":{"kind":"group","all":true,"not":false,"children":[]}}"#)
        );
    }
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ChatSelectionSummaryFfi {
    pub revision: u64,
    pub count: u64,
}
impl From<app::ChatSelectionSummary> for ChatSelectionSummaryFfi {
    fn from(v: app::ChatSelectionSummary) -> Self {
        Self {
            revision: v.revision,
            count: v.count,
        }
    }
}
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct ChatSelectionPageFfi {
    pub summary: ChatSelectionSummaryFfi,
    pub group_ids: Vec<String>,
}
impl From<app::ChatSelectionPage> for ChatSelectionPageFfi {
    fn from(v: app::ChatSelectionPage) -> Self {
        Self {
            summary: v.summary.into(),
            group_ids: v.group_ids,
        }
    }
}

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
