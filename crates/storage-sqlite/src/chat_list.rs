use crate::account_projection::chat_mute_is_effective;
use crate::storage::disband_requests::{
    disband_requests_by_group_hex_tx, disbanding_group_ids_hex_tx,
    disbanding_group_ids_hex_with_requests_tx,
};
use crate::storage::leave_requests::pending_leave_requests_by_group_hex_tx;
use crate::{
    SelfMembership, SqliteAccountStorage, SqliteResultExt, StoredAccountState, bool_i64,
    i64_to_u64, optional_u64_to_i64, u64_to_i64, unix_now_ms, unix_now_seconds,
};
use cgka_traits::app_components::{GROUP_AVATAR_URL_COMPONENT_ID, decode_group_avatar_url_v1};
use cgka_traits::app_event::{
    GROUP_SYSTEM_TYPE_ADMIN_ADDED, GROUP_SYSTEM_TYPE_ADMIN_REMOVED, GROUP_SYSTEM_TYPE_MEMBER_ADDED,
    GROUP_SYSTEM_TYPE_MEMBER_LEFT, GROUP_SYSTEM_TYPE_MEMBER_REMOVED, GROUP_SYSTEM_TYPE_TAG,
    MARMOT_APP_EVENT_KIND_CHAT, MARMOT_APP_EVENT_KIND_GROUP_SYSTEM,
};
use cgka_traits::storage::StorageResult;
use rusqlite::{Connection, OptionalExtension, Params, params};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChatListQuery {
    pub include_archived: bool,
}

/// Authoritative device-local order of every currently pinned chat.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChatPinState {
    /// Group ids in normalized zero-based display order.
    pub ordered_group_ids: Vec<String>,
}

/// Typed validation and persistence failures for local chat pin mutations.
#[derive(Debug, thiserror::Error)]
pub enum ChatPinError {
    #[error(transparent)]
    Storage(#[from] cgka_traits::storage::StorageError),
    #[error("unknown local group")]
    UnknownGroup(String),
    #[error("archived chats cannot be pinned")]
    ArchivedChat,
    #[error("invalid pinned chat order: {0}")]
    InvalidOrder(String),
}

/// Predicate deciding whether a timeline message (by plaintext + tag set)
/// mentions the local account. Injected by the caller so the storage layer
/// stays free of nostr/NIP parsing.
pub type MentionClassifier<'a> = dyn Fn(&str, &[Vec<String>]) -> bool + 'a;

/// Cheap per-account unread aggregate computed directly from the materialized
/// `chat_list_rows` projection — no timeline/session load required. Archived
/// conversations are excluded so the total matches what the unarchived chat
/// list would show.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountUnreadTotal {
    /// Sum of `unread_count` across all unarchived conversations.
    pub unread_count: u64,
    /// Number of unarchived conversations that require badge attention:
    /// unread messages, a manual-unread reminder, or a pending invitation.
    pub unread_conversations: u64,
    /// Unarchived conversations that contribute badge attention solely because
    /// they are manually marked unread or pending confirmation. A row that
    /// already has `unread_count > 0` is omitted so
    /// `unread_count + attention_only_conversations` is the application badge.
    pub attention_only_conversations: u64,
}

impl AccountUnreadTotal {
    /// Whether the account has any badge-worthy conversation, including a
    /// manual-only reminder or pending invitation with no unread incoming
    /// messages.
    pub fn has_unread(&self) -> bool {
        self.unread_conversations > 0
    }
}

/// `image_key_hex`/`image_upload_key_hex` are key material. They are
/// intentionally serialized into the SQLCipher-protected projection, but the
/// hand-written `Debug` impl below redacts them so a `{:?}` never prints key
/// material into logs.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChatListAvatar {
    pub image_hash_hex: String,
    pub image_key_hex: String,
    pub image_nonce_hex: String,
    pub image_upload_key_hex: String,
    pub media_type: Option<String>,
}

impl std::fmt::Debug for ChatListAvatar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatListAvatar")
            .field("image_hash_hex", &self.image_hash_hex)
            .field("image_key_hex", &"<redacted>")
            .field("image_nonce_hex", &self.image_nonce_hex)
            .field("image_upload_key_hex", &"<redacted>")
            .field("media_type", &self.media_type)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatConversationKind {
    #[default]
    Unknown,
    Direct,
    Group,
}

/// Authoritative reuse decision for one existing direct conversation.
///
/// MDK owns this policy so hosts do not re-derive directness, membership, or
/// lifecycle eligibility from a full chat list. `reusable` is true only when
/// the selected group can be opened instead of creating another direct group
/// with the same peer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExistingDirectConversation {
    pub group_id_hex: String,
    pub reusable: bool,
    pub lifecycle_state: cgka_traits::GroupLifecycleState,
    pub self_membership: SelfMembership,
    pub pending_confirmation: bool,
    pub leave_request_pending: bool,
    pub disbanding: bool,
    pub archived: bool,
    pub activity_sort_at: u64,
}

/// Select the reusable direct conversation with `peer_account_id_hex`, if any.
///
/// A row is a **direct** conversation when its group name is empty and the
/// projected roster size is exactly two (`ChatConversationKind::Direct`).
/// It is **reusable** with that peer when all of the following hold:
///
/// - `self_membership` is [`SelfMembership::Member`]
/// - lifecycle is not terminal (`Disbanded`)
/// - the group is not `disbanding`
/// - no leave request is outstanding
/// - the current roster is exactly `{local, peer}`
///
/// Pending confirmation does not block reuse: the invite is the same
/// conversation. Archived rows remain reusable so hosts do not create a
/// duplicate. Named groups, 3+ member groups, `Unknown` kind, `Left`,
/// `Removed`, and a different peer are not matches.
///
/// When several reusable matches exist, selection follows durable chat-list
/// activity order: highest `activity_sort_at`, then lowest `group_id_hex`.
/// That is the same durable clock as the chat-list projection, not the
/// local pin order used by [`SqliteAccountStorage::chat_list_rows`]. A pin
/// must not change which historical duplicate is reused.
pub fn select_reusable_direct_conversation(
    candidates: &[ChatListRow],
    local_account_id_hex: &str,
    peer_account_id_hex: &str,
    memberships: &HashMap<String, Vec<String>>,
) -> Option<ExistingDirectConversation> {
    let local = local_account_id_hex.trim().to_ascii_lowercase();
    let peer = peer_account_id_hex.trim().to_ascii_lowercase();
    if local.is_empty() || peer.is_empty() || local == peer {
        return None;
    }

    let mut selected: Option<&ChatListRow> = None;
    for row in candidates {
        if !direct_row_is_reusable(row) {
            continue;
        }
        let Some(members) = memberships.get(&row.group_id_hex) else {
            continue;
        };
        if !roster_is_direct_with_peer(members, &local, &peer) {
            continue;
        }
        selected = Some(match selected {
            Some(current) if !direct_activity_orders_before(row, current) => current,
            _ => row,
        });
    }

    selected.map(existing_direct_conversation_from_row)
}

fn direct_row_is_reusable(row: &ChatListRow) -> bool {
    row.conversation_kind == ChatConversationKind::Direct
        && row.self_membership == SelfMembership::Member
        && row.lifecycle_state != cgka_traits::GroupLifecycleState::Disbanded
        && !row.disbanding
        && row.leave_requested_at_ms.is_none()
}

fn indexable_group_id_hex(group_id_hex: &str) -> bool {
    hex::decode(group_id_hex)
        .ok()
        .is_some_and(|bytes| !bytes.is_empty())
}

fn roster_is_direct_with_peer(members: &[String], local: &str, peer: &str) -> bool {
    let ids = members
        .iter()
        .map(|member| member.trim().to_ascii_lowercase())
        .filter(|member| !member.is_empty())
        .collect::<HashSet<_>>();
    ids.len() == 2 && ids.contains(local) && ids.contains(peer)
}

fn direct_activity_orders_before(left: &ChatListRow, right: &ChatListRow) -> bool {
    left.activity_sort_at > right.activity_sort_at
        || (left.activity_sort_at == right.activity_sort_at
            && left.group_id_hex < right.group_id_hex)
}

fn existing_direct_conversation_from_row(row: &ChatListRow) -> ExistingDirectConversation {
    ExistingDirectConversation {
        group_id_hex: row.group_id_hex.clone(),
        reusable: true,
        lifecycle_state: row.lifecycle_state,
        self_membership: row.self_membership,
        pending_confirmation: row.pending_confirmation,
        leave_request_pending: row.leave_requested_at_ms.is_some(),
        disbanding: row.disbanding,
        archived: row.archived,
        activity_sort_at: row.activity_sort_at,
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatListAttachmentKind {
    Photo,
    Video,
    Audio,
    File,
    Mixed,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatListMessageDeliveryState {
    #[default]
    NotApplicable,
    Pending,
    Delivered,
    Failed,
}

impl ChatListMessageDeliveryState {
    fn as_str(self) -> &'static str {
        match self {
            Self::NotApplicable => "not_applicable",
            Self::Pending => "pending",
            Self::Delivered => "delivered",
            Self::Failed => "failed",
        }
    }

    fn from_storage(value: &str) -> Self {
        match value {
            "pending" => Self::Pending,
            "delivered" => Self::Delivered,
            "failed" => Self::Failed,
            _ => Self::NotApplicable,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChatListMessagePreview {
    pub message_id_hex: String,
    pub sender: String,
    pub sender_display_name: Option<String>,
    pub plaintext: String,
    pub kind: u64,
    pub timeline_at: u64,
    pub deleted: bool,
    pub attachment_kind: Option<ChatListAttachmentKind>,
    pub attachment_count: u32,
    pub delivery_state: ChatListMessageDeliveryState,
    /// Internal durable projection input. The app layer validates these tags
    /// with the authoritative encrypted-media parser and populates the bounded
    /// attachment fields above. Never serialized or exposed through bindings.
    #[serde(skip)]
    pub media_json: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChatListRow {
    pub group_id_hex: String,
    /// Whether this row belongs to the device-local manually ordered section.
    pub pinned: bool,
    /// Normalized zero-based position in the pinned section. The stored
    /// ordinal is internal and may contain gaps after an archive-triggered
    /// deletion.
    pub pinned_position: Option<u32>,
    pub archived: bool,
    pub pending_confirmation: bool,
    /// Durable lifecycle classification. Ephemeral merge/publish states are
    /// exposed by the live MLS-state API; the chat-list projection guarantees
    /// terminal Disbanded survives restarts and local history deletion.
    #[serde(default)]
    pub lifecycle_state: cgka_traits::GroupLifecycleState,
    /// Ordinary outbound group work is gated while a local disband request or
    /// authenticated inbound disband candidate awaits convergence.
    #[serde(default)]
    pub disbanding: bool,
    /// Local request outcome, when this account initiated disbanding. An
    /// inbound candidate can set `disbanding` without creating this request.
    #[serde(default)]
    pub disband_request: Option<cgka_traits::DisbandRequest>,
    pub title: String,
    pub group_name: String,
    pub avatar_url: Option<String>,
    pub avatar: Option<ChatListAvatar>,
    pub last_message: Option<ChatListMessagePreview>,
    pub unread_count: u64,
    pub has_unread: bool,
    pub manually_marked_unread: bool,
    pub unread_mention_count: u64,
    pub has_unread_mention: bool,
    pub first_unread_message_id_hex: Option<String>,
    pub last_read_message_id_hex: Option<String>,
    pub last_read_timeline_at: Option<u64>,
    /// Immutable local observation time for the conversation's creation.
    pub conversation_created_at: u64,
    /// Durable user-visible activity anchor. Projection maintenance never
    /// advances this value.
    pub activity_sort_at: u64,
    pub updated_at: u64,
    /// The local account's membership in this group (active member, left, or
    /// removed). Denormalized from `account_groups.self_membership`.
    pub self_membership: SelfMembership,
    /// Current locally projected classification. `Unknown` is retained for
    /// legacy groups until their live roster has been hydrated and persisted.
    pub conversation_kind: ChatConversationKind,
    /// Effective MDK timed/indefinite mute state at the time this row was read.
    pub muted: bool,
    /// Absolute Unix epoch milliseconds for a finite mute. `None` is either
    /// unmuted (`muted == false`) or indefinite (`muted == true`).
    pub muted_until_ms: Option<i64>,
    /// When the local account asked to leave this group, if a durable leave
    /// request is still outstanding.
    ///
    /// This is *not* a `chat_list_rows` column. It is derived at read time from
    /// the engine-owned `cgka_leave_requests` table, which is the only source of
    /// truth for unresolved intent.
    ///
    /// Orthogonal to [`Self::self_membership`], and the two combine freely.
    /// `self_membership` records the locally *classified departure*: the leave
    /// path writes `Left` as soon as the SelfRemove proposal publishes, without
    /// waiting for another member to commit it. This field tracks whether the
    /// request itself has *resolved*. So `Left` + `Some(..)` means the leave
    /// published and is awaiting a committer, `Member` + `Some(..)` means the
    /// publish failed (or the process died before the membership write), and
    /// `None` means no leave is outstanding.
    #[serde(default)]
    pub leave_requested_at_ms: Option<u64>,
}

#[derive(Clone, Debug)]
struct AccountGroupRow {
    group_id_hex: String,
    archived: bool,
    pending_confirmation: bool,
    profile_name: String,
    avatar_url: Option<String>,
    avatar: Option<ChatListAvatar>,
    conversation_created_at: u64,
    self_membership: SelfMembership,
}

#[derive(Clone, Debug)]
struct ConversationReadState {
    last_read_message_id_hex: Option<String>,
    last_read_timeline_at: Option<u64>,
    last_read_order_class: Option<u8>,
    last_read_order_primary: Option<u64>,
    last_read_order_phase: Option<u8>,
    last_read_order_at: Option<u64>,
    initialized_at: u64,
    manually_marked_unread: bool,
}

impl ConversationReadState {
    fn canonical_order_key(&self) -> Option<(u8, u64, u8, u64, &str)> {
        Some((
            self.last_read_order_class?,
            self.last_read_order_primary?,
            self.last_read_order_phase?,
            self.last_read_order_at?,
            self.last_read_message_id_hex.as_deref()?,
        ))
    }
}

#[derive(Clone, Debug)]
struct TimelineReadMarker {
    message_id_hex: String,
    source_message_id_hex: Option<String>,
    source_epoch: Option<u64>,
    invalidation_status: Option<String>,
    kind: u64,
    timeline_at: u64,
}

impl TimelineReadMarker {
    fn canonical_order_key(&self) -> (u8, u64, u8, u64, &str) {
        crate::timeline::canonical_timeline_order_key(
            self.source_message_id_hex.as_deref(),
            self.source_epoch,
            self.invalidation_status.as_deref(),
            self.kind,
            self.timeline_at,
            &self.message_id_hex,
        )
    }
}

impl SqliteAccountStorage {
    pub fn chat_list_rows(&self, query: ChatListQuery) -> StorageResult<Vec<ChatListRow>> {
        let conn = self.lock()?;
        chat_list_rows_tx(&conn, query)
    }

    pub fn chat_list_row(&self, group_id_hex: &str) -> StorageResult<Option<ChatListRow>> {
        let conn = self.lock()?;
        chat_list_row_tx(&conn, group_id_hex)
    }

    /// Direct-conversation candidates for a peer-keyed reuse lookup.
    ///
    /// Returns only rows whose durable projection is currently classified as
    /// [`ChatConversationKind::Direct`] (empty group name and roster size 2)
    /// and whose persisted member index contains `peer_account_id_hex`.
    /// Named chats, 3+ member chats, and Direct chats with a different peer
    /// are excluded in SQL so lookup work does not grow with those rows.
    /// Membership, leave, and disband stamps are applied the same way as
    /// [`Self::chat_list_rows`].
    ///
    /// Candidate order is durable activity (`activity_sort_at DESC`, then
    /// `group_id_hex`), not the pin-first order used by the visible chat
    /// list. Reuse must follow conversation activity, not local pin state.
    ///
    /// The query is driven by `idx_direct_conversation_members_member`, then
    /// joins the matching chat-list rows. It does not scan every chat to
    /// find the peer.
    pub fn direct_conversation_candidate_rows(
        &self,
        peer_account_id_hex: &str,
    ) -> StorageResult<Vec<ChatListRow>> {
        let conn = self.lock()?;
        direct_conversation_candidate_rows_tx(&conn, peer_account_id_hex)
    }

    /// `EXPLAIN QUERY PLAN` for the peer-keyed candidate read.
    ///
    /// Used by the regression that requires
    /// `idx_direct_conversation_members_member` as the driving index.
    pub fn direct_conversation_candidate_query_plan(
        &self,
        peer_account_id_hex: &str,
    ) -> StorageResult<Vec<String>> {
        let peer_account_id_hex = peer_account_id_hex.trim().to_ascii_lowercase();
        if peer_account_id_hex.is_empty() {
            return Ok(Vec::new());
        }
        let conn = self.lock()?;
        let sql = format!("EXPLAIN QUERY PLAN {}", direct_conversation_candidate_sql());
        let mut statement = conn.prepare(&sql).storage()?;
        statement
            .query_map(params![peer_account_id_hex], |row| row.get::<_, String>(3))
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()
    }

    /// Direct groups that still have no peer-index rows.
    ///
    /// Used only by the once-per-open upgrade backfill. Steady-state lookup
    /// does not call this. Malformed or empty group-id hex is omitted so a
    /// corrupt row cannot keep the completion marker unset.
    pub fn unindexed_direct_conversation_group_ids(&self) -> StorageResult<Vec<String>> {
        let conn = self.lock()?;
        let mut statement = conn
            .prepare(
                "SELECT ag.group_id_hex
                 FROM account_groups AS ag
                 JOIN chat_list_rows AS row ON row.group_id_hex = ag.group_id_hex
                 WHERE TRIM(row.group_name) = ''
                   AND ag.member_count = 2
                   AND NOT EXISTS (
                        SELECT 1 FROM direct_conversation_members AS dcm
                        WHERE dcm.group_id_hex = ag.group_id_hex
                   )
                 ORDER BY ag.group_id_hex",
            )
            .storage()?;
        let group_ids = statement
            .query_map([], |row| row.get(0))
            .storage()?
            .collect::<Result<Vec<String>, _>>()
            .storage()?;
        Ok(group_ids
            .into_iter()
            .filter(|group_id_hex| indexable_group_id_hex(group_id_hex))
            .collect())
    }

    /// Pin or unpin one unarchived local chat and return the complete
    /// authoritative pin order after the transaction.
    ///
    /// A newly pinned chat is inserted at the top. Repeating the current state
    /// is idempotent and does not move an existing pin.
    pub fn set_chat_pinned(
        &self,
        group_id_hex: &str,
        pinned: bool,
    ) -> Result<ChatPinState, ChatPinError> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let archived = conn
                .query_row(
                    "SELECT archived FROM account_groups WHERE group_id_hex = ?1",
                    params![group_id_hex],
                    |row| row.get::<_, i64>(0),
                )
                .optional()
                .storage()?
                .ok_or_else(|| ChatPinError::UnknownGroup(group_id_hex.to_owned()))?
                != 0;
            if pinned && archived {
                return Err(ChatPinError::ArchivedChat);
            }

            let mut ordered_group_ids = pinned_chat_order_tx(&conn)?;
            let existing = ordered_group_ids
                .iter()
                .position(|candidate| candidate == group_id_hex);
            match (pinned, existing) {
                (true, None) => {
                    ordered_group_ids.insert(0, group_id_hex.to_owned());
                    rewrite_pinned_chat_order_tx(&conn, &ordered_group_ids)?;
                }
                (false, Some(position)) => {
                    ordered_group_ids.remove(position);
                    rewrite_pinned_chat_order_tx(&conn, &ordered_group_ids)?;
                }
                _ => {}
            }
            Ok(ChatPinState { ordered_group_ids })
        })
    }

    /// Replace the manual order of the complete current pinned set.
    ///
    /// `ordered_group_ids` must contain every currently pinned group exactly
    /// once. This strict compare-and-set contract deliberately rejects stale
    /// client orders with [`ChatPinError::InvalidOrder`] instead of silently
    /// merging them. A client receiving that error should refresh its chat-list
    /// snapshot and retry from the authoritative pinned set.
    pub fn set_pinned_chat_order(
        &self,
        ordered_group_ids: &[String],
    ) -> Result<ChatPinState, ChatPinError> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            for group_id_hex in ordered_group_ids {
                let exists = conn
                    .query_row(
                        "SELECT EXISTS(
                            SELECT 1 FROM account_groups WHERE group_id_hex = ?1
                         )",
                        params![group_id_hex],
                        |row| row.get::<_, bool>(0),
                    )
                    .storage()?;
                if !exists {
                    return Err(ChatPinError::UnknownGroup(group_id_hex.clone()));
                }
            }
            if ordered_group_ids.iter().collect::<HashSet<_>>().len() != ordered_group_ids.len() {
                return Err(ChatPinError::InvalidOrder(
                    "group ids must not contain duplicates".to_owned(),
                ));
            }

            let current = pinned_chat_order_tx(&conn)?;
            let current_set = current.iter().collect::<HashSet<_>>();
            let requested_set = ordered_group_ids.iter().collect::<HashSet<_>>();
            if current_set != requested_set {
                return Err(ChatPinError::InvalidOrder(
                    "order must contain every currently pinned chat exactly once".to_owned(),
                ));
            }
            if current != ordered_group_ids {
                rewrite_pinned_chat_order_tx(&conn, ordered_group_ids)?;
            }
            Ok(ChatPinState {
                ordered_group_ids: ordered_group_ids.to_vec(),
            })
        })
    }

    /// Cheap unread aggregate over the materialized `chat_list_rows`
    /// projection. Reads only the projection table (a single grouped
    /// `COUNT`/`SUM`), so it does not materialize timelines or load a session.
    /// Archived conversations are excluded. Groups the local account is no
    /// longer in — `account_groups.self_membership` of `'left'` or `'removed'`
    /// — are also excluded; unknown membership (`'member'`, the default, or no
    /// matching `account_groups` row) preserves the unread count so uncertainty
    /// never suppresses. Pending invitations and manual-only unread rows count
    /// as badge attention; a row with unread messages is not counted again in
    /// `attention_only_conversations`.
    pub fn account_unread_total(&self) -> StorageResult<AccountUnreadTotal> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT COALESCE(SUM(row.unread_count), 0),
                    COUNT(CASE
                        WHEN row.unread_count > 0
                          OR row.manually_marked_unread = 1
                          OR row.pending_confirmation = 1
                        THEN 1
                    END),
                    COUNT(CASE
                        WHEN row.unread_count = 0
                         AND (row.manually_marked_unread = 1
                           OR row.pending_confirmation = 1)
                        THEN 1
                    END)
             FROM chat_list_rows AS row
             LEFT JOIN account_groups AS ag ON ag.group_id_hex = row.group_id_hex
             WHERE row.archived = 0
               AND COALESCE(ag.self_membership, 'member') NOT IN ('left', 'removed')
               AND NOT EXISTS (
                   SELECT 1 FROM cgka_disband_tombstones AS tomb
                   WHERE lower(hex(tomb.group_id)) = lower(row.group_id_hex)
               )",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .storage()
        .and_then(
            |(unread_count, unread_conversations, attention_only_conversations)| {
                Ok(AccountUnreadTotal {
                    unread_count: i64_to_u64(unread_count)?,
                    unread_conversations: i64_to_u64(unread_conversations)?,
                    attention_only_conversations: i64_to_u64(attention_only_conversations)?,
                })
            },
        )
    }

    pub fn ensure_chat_list_rows(
        &self,
        local_account_id_hex: &str,
        mention_classifier: &MentionClassifier<'_>,
    ) -> StorageResult<()> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            if !chat_list_projection_complete_tx(&conn, local_account_id_hex, mention_classifier)? {
                rebuild_all_chat_list_rows_tx(&conn, local_account_id_hex, mention_classifier)?;
            }
            Ok(())
        })
    }

    pub fn refresh_chat_list_rows(
        &self,
        local_account_id_hex: &str,
        mention_classifier: &MentionClassifier<'_>,
    ) -> StorageResult<()> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            rebuild_all_chat_list_rows_tx(&conn, local_account_id_hex, mention_classifier)
        })
    }

    pub fn refresh_chat_list_row(
        &self,
        local_account_id_hex: &str,
        group_id_hex: &str,
        mention_classifier: &MentionClassifier<'_>,
    ) -> StorageResult<Option<ChatListRow>> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            refresh_chat_list_row_tx(
                &conn,
                local_account_id_hex,
                group_id_hex,
                mention_classifier,
            )
        })
    }

    /// Persist an exact account-projection delta and materialize one chat-list
    /// row in the same SQLCipher transaction, returning the committed row.
    ///
    /// Group creation uses this boundary so the host-visible row is durable
    /// when the response is handed off, without a second projection commit or
    /// a follow-up storage read merely to assemble that response.
    #[allow(clippy::too_many_arguments)]
    pub fn save_account_projection_delta_and_refresh_chat_list_row(
        &self,
        state: &StoredAccountState,
        max_seen_events: usize,
        max_future_skew_secs: u64,
        frontiers_to_clear: &[(String, u64)],
        application_event_ids_to_ack: &[cgka_traits::MessageId],
        local_account_id_hex: &str,
        group_id_hex: &str,
        mention_classifier: &MentionClassifier<'_>,
    ) -> StorageResult<Option<ChatListRow>> {
        self.connection.with_transaction(|| {
            // `with_transaction` is intentionally nestable on the owning
            // thread, so the projection helper participates in this outer
            // transaction and cannot commit before the chat-list row exists.
            self.save_account_projection_delta_clearing_local_group_deletion_frontiers_and_acking_application_events(
                state,
                max_seen_events,
                max_future_skew_secs,
                frontiers_to_clear,
                application_event_ids_to_ack,
            )?;
            let conn = self.lock()?;
            refresh_chat_list_row_tx(
                &conn,
                local_account_id_hex,
                group_id_hex,
                mention_classifier,
            )
        })
    }

    pub fn initialize_chat_read_state(
        &self,
        local_account_id_hex: &str,
        group_id_hex: &str,
        mention_classifier: &MentionClassifier<'_>,
    ) -> StorageResult<Option<ChatListRow>> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let Some(group) = account_group_tx(&conn, group_id_hex)? else {
                return Ok(None);
            };
            if read_state_tx(&conn, group_id_hex)?.is_none() {
                insert_initial_read_state_tx(&conn, group_id_hex, false)?;
            }
            rebuild_chat_list_row_for_group_tx(
                &conn,
                local_account_id_hex,
                group,
                mention_classifier,
            )?;
            chat_list_row_tx(&conn, group_id_hex)
        })
    }

    /// Set or clear the durable manual-unread reminder without moving the
    /// monotonic message read marker.
    pub fn set_chat_manually_unread(
        &self,
        local_account_id_hex: &str,
        group_id_hex: &str,
        manually_unread: bool,
        mention_classifier: &MentionClassifier<'_>,
    ) -> StorageResult<Option<ChatListRow>> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let Some(group) = account_group_tx(&conn, group_id_hex)? else {
                return Ok(None);
            };
            let now = unix_now_seconds();
            if read_state_tx(&conn, group_id_hex)?.is_none() {
                // Before a read-state row exists, retained history is implicitly
                // read. Preserve that baseline when creating the manual flag so
                // "mark unread" does not suddenly count the whole backlog.
                insert_initial_read_state_tx(&conn, group_id_hex, manually_unread)?;
            } else {
                conn.execute(
                    "UPDATE conversation_read_state
                     SET manually_marked_unread = ?2, updated_at = ?3
                     WHERE group_id_hex = ?1",
                    params![group_id_hex, bool_i64(manually_unread), u64_to_i64(now)?],
                )
                .storage()?;
            }
            rebuild_chat_list_row_for_group_tx(
                &conn,
                local_account_id_hex,
                group,
                mention_classifier,
            )?;
            chat_list_row_tx(&conn, group_id_hex)
        })
    }

    pub fn mark_timeline_message_read(
        &self,
        local_account_id_hex: &str,
        group_id_hex: &str,
        message_id_hex: &str,
        mention_classifier: &MentionClassifier<'_>,
    ) -> StorageResult<Option<ChatListRow>> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            if let Some(target) =
                timeline_message_for_read_marker_tx(&conn, group_id_hex, message_id_hex)?
            {
                let target_order = target.canonical_order_key();
                let should_advance = match read_state_tx(&conn, group_id_hex)? {
                    None => true,
                    Some(state) => match state.canonical_order_key() {
                        Some(current_order) => target_order > current_order,
                        None => state
                            .last_read_timeline_at
                            .zip(state.last_read_message_id_hex.as_deref())
                            .is_none_or(|(at, id)| {
                                timeline_tuple_after(
                                    target.timeline_at,
                                    &target.message_id_hex,
                                    at,
                                    id,
                                )
                            }),
                    },
                };

                if should_advance {
                    let (order_class, order_primary, order_phase, order_at, _id) = target_order;
                    conn.execute(
                        "INSERT INTO conversation_read_state (
                            group_id_hex, last_read_message_id_hex, last_read_timeline_at,
                            last_read_order_class, last_read_order_primary,
                            last_read_order_phase, last_read_order_at,
                            initialized_at, updated_at, manually_marked_unread
                         )
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, 0)
                         ON CONFLICT(group_id_hex) DO UPDATE SET
                            last_read_message_id_hex = excluded.last_read_message_id_hex,
                            last_read_timeline_at = excluded.last_read_timeline_at,
                            last_read_order_class = excluded.last_read_order_class,
                            last_read_order_primary = excluded.last_read_order_primary,
                            last_read_order_phase = excluded.last_read_order_phase,
                            last_read_order_at = excluded.last_read_order_at,
                            updated_at = excluded.updated_at,
                            manually_marked_unread = 0",
                        params![
                            group_id_hex,
                            &target.message_id_hex,
                            u64_to_i64(target.timeline_at)?,
                            i64::from(order_class),
                            u64_to_i64(order_primary)?,
                            i64::from(order_phase),
                            u64_to_i64(order_at)?,
                            u64_to_i64(unix_now_seconds())?
                        ],
                    )
                    .storage()?;
                }
            }
            // Explicitly marking a message read clears a manual-only reminder
            // even when the target does not advance the already-newer marker.
            conn.execute(
                "UPDATE conversation_read_state
                 SET manually_marked_unread = 0, updated_at = ?2
                 WHERE group_id_hex = ?1 AND manually_marked_unread != 0",
                params![group_id_hex, u64_to_i64(unix_now_seconds())?],
            )
            .storage()?;
            refresh_chat_list_row_tx(
                &conn,
                local_account_id_hex,
                group_id_hex,
                mention_classifier,
            )
        })
    }
}

fn pinned_chat_order_tx(tx: &Connection) -> Result<Vec<String>, ChatPinError> {
    let mut statement = tx
        .prepare(
            "SELECT group_id_hex
             FROM chat_pin_positions
             ORDER BY ordinal ASC, group_id_hex ASC",
        )
        .storage()?;
    statement
        .query_map([], |row| row.get(0))
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()
        .map_err(Into::into)
}

fn rewrite_pinned_chat_order_tx(
    tx: &Connection,
    ordered_group_ids: &[String],
) -> Result<(), ChatPinError> {
    tx.execute("DELETE FROM chat_pin_positions", []).storage()?;
    for (ordinal, group_id_hex) in ordered_group_ids.iter().enumerate() {
        tx.execute(
            "INSERT INTO chat_pin_positions (group_id_hex, ordinal)
             VALUES (?1, ?2)",
            params![
                group_id_hex,
                i64::try_from(ordinal)
                    .map_err(|_| ChatPinError::InvalidOrder("too many pinned chats".to_owned()))?
            ],
        )
        .storage()?;
    }
    Ok(())
}

fn rebuild_all_chat_list_rows_tx(
    tx: &Connection,
    local_account_id_hex: &str,
    mention_classifier: &MentionClassifier<'_>,
) -> StorageResult<()> {
    let groups = account_groups_tx(tx)?;
    for group in groups {
        rebuild_chat_list_row_for_group_tx(tx, local_account_id_hex, group, mention_classifier)?;
    }
    // Upsert in place so durable activity anchors survive a projection rebuild
    // after their preview rows have been securely pruned. Remove only true
    // orphans; normal account-group deletion already cascades this table.
    tx.execute(
        "DELETE FROM chat_list_rows
         WHERE NOT EXISTS (
             SELECT 1 FROM account_groups AS ag
             WHERE ag.group_id_hex = chat_list_rows.group_id_hex
         )",
        [],
    )
    .storage()?;
    // A full rebuild reconciles every derived field covered by the current
    // projection contract, including mentions and kind-1210 activity.
    set_chat_list_projection_version_tx(tx, CHAT_LIST_PROJECTION_VERSION)?;
    Ok(())
}

fn refresh_chat_list_row_tx(
    tx: &Connection,
    local_account_id_hex: &str,
    group_id_hex: &str,
    mention_classifier: &MentionClassifier<'_>,
) -> StorageResult<Option<ChatListRow>> {
    let Some(group) = account_group_tx(tx, group_id_hex)? else {
        tx.execute(
            "DELETE FROM chat_list_rows WHERE group_id_hex = ?1",
            params![group_id_hex],
        )
        .storage()?;
        return Ok(None);
    };
    rebuild_chat_list_row_for_group_tx(tx, local_account_id_hex, group, mention_classifier)?;
    chat_list_row_tx(tx, group_id_hex)
}

/// Current chat-list projection reconciliation version.
///
/// Version 1 covered unread-mention counts (#750). Version 2 additionally
/// projects kind-1210 group-system rows into preview, activity, and unread state
/// (#822). The persisted column keeps its legacy `mention_counts_version` name
/// for schema compatibility, but now gates the complete derived-row contract.
const CHAT_LIST_PROJECTION_VERSION: i64 = 2;

const CHAT_LIST_GROUP_ACTIVITY_TYPES: [&str; 5] = [
    GROUP_SYSTEM_TYPE_MEMBER_ADDED,
    GROUP_SYSTEM_TYPE_MEMBER_REMOVED,
    GROUP_SYSTEM_TYPE_MEMBER_LEFT,
    GROUP_SYSTEM_TYPE_ADMIN_ADDED,
    GROUP_SYSTEM_TYPE_ADMIN_REMOVED,
];

/// SQL predicate for activity that should behave like a chat message in the
/// chat list. Kind-1210 also carries metadata changes; #822 intentionally
/// promotes only membership/admin rows, leaving unrelated system events alone.
pub(crate) fn chat_list_activity_filter_sql(column_prefix: &str) -> String {
    let group_activity_tags = CHAT_LIST_GROUP_ACTIVITY_TYPES
        .iter()
        .map(|system_type| format!(r#"'[["{GROUP_SYSTEM_TYPE_TAG}","{system_type}"]]'"#))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "({column_prefix}kind = {MARMOT_APP_EVENT_KIND_CHAT} OR \
         ({column_prefix}kind = {MARMOT_APP_EVENT_KIND_GROUP_SYSTEM} AND \
          {column_prefix}tags_json IN ({group_activity_tags}) AND \
          EXISTS (SELECT 1 FROM account_groups AS activity_group \
                  WHERE activity_group.group_id_hex = {column_prefix}group_id_hex \
                    AND (trim(activity_group.profile_name) != '' OR \
                         (activity_group.member_count IS NOT NULL AND \
                          activity_group.member_count != 2)))))"
    )
}

/// One authoritative latest-preview order for rebuild, completeness, and
/// secure-prune repair. A pending local send stays at the preview head only
/// until accepted activity is first persisted later on this device. The stable
/// `app_events.insert_order` boundary is intentional: relay replay can rewrite
/// `received_at` on an older row and must not make old history look new. The
/// canonical timeline deliberately keeps every unresolved local row at its
/// head, but reusing that unconditional class here lets one orphaned send pin a
/// chat-list preview forever. Failed local sends remain visible in the timeline
/// without outranking accepted history.
pub(crate) fn chat_list_preview_order_desc(column_prefix: &str) -> String {
    let accepted_activity_filter = chat_list_activity_filter_sql("accepted.");
    format!(
        "CASE
            WHEN {column_prefix}direction = 'sent'
             AND {column_prefix}invalidation_status = 'local_publish_failed' THEN 0
            ELSE 1
         END DESC,
         CASE
            WHEN {column_prefix}direction = 'sent'
             AND {column_prefix}source_message_id_hex IS NULL
             AND {column_prefix}invalidation_status IS NULL
             AND NOT EXISTS (
                SELECT 1
                FROM message_timeline AS accepted
                JOIN app_events AS accepted_source
                  ON accepted_source.group_id_hex = accepted.group_id_hex
                 AND accepted_source.message_id_hex = accepted.message_id_hex
                WHERE accepted.group_id_hex = {column_prefix}group_id_hex
                  AND {accepted_activity_filter}
                  AND accepted.invalidation_status IS NULL
                  AND NOT (
                      accepted.direction = 'sent'
                      AND accepted.source_message_id_hex IS NULL
                  )
                  AND accepted_source.insert_order > COALESCE((
                      SELECT current_source.insert_order
                      FROM app_events AS current_source
                      WHERE current_source.group_id_hex = {column_prefix}group_id_hex
                        AND current_source.message_id_hex = {column_prefix}message_id_hex
                  ), -1)
             ) THEN 2
            WHEN {column_prefix}direction = 'sent'
             AND {column_prefix}source_message_id_hex IS NULL
             AND {column_prefix}invalidation_status IS NULL THEN 0
            ELSE 1
         END DESC,
         {column_prefix}timeline_order_class DESC,
         {column_prefix}timeline_order_primary DESC,
         {column_prefix}timeline_order_phase DESC,
         {column_prefix}timeline_order_at DESC,
         {column_prefix}message_id_hex DESC"
    )
}

struct LatestChatListMessage {
    preview: ChatListMessagePreview,
    canonical_order_prefix: (u8, u64, u8, u64),
}

fn chat_list_projection_version_tx(tx: &Connection) -> StorageResult<i64> {
    Ok(tx
        .query_row(
            "SELECT mention_counts_version FROM chat_list_projection_meta WHERE id = 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .storage()?
        .unwrap_or(0))
}

fn set_chat_list_projection_version_tx(tx: &Connection, version: i64) -> StorageResult<()> {
    tx.execute(
        "UPDATE chat_list_projection_meta SET mention_counts_version = ?1 WHERE id = 1",
        params![version],
    )
    .storage()?;
    Ok(())
}

/// Deliberately does not consider pending-leave state.
/// `ChatListRow::leave_requested_at_ms` is derived at read time rather than
/// materialized, so there is no stored value that can drift out of date — and
/// comparing a read-time-only field here would mark every row stale forever.
fn chat_list_projection_complete_tx(
    tx: &Connection,
    local_account_id_hex: &str,
    mention_classifier: &MentionClassifier<'_>,
) -> StorageResult<bool> {
    let activity_filter = chat_list_activity_filter_sql("mt.");
    let preview_order = chat_list_preview_order_desc("mt.");
    if projection_has_rows_tx(
        tx,
        "SELECT EXISTS(
                SELECT 1
                FROM account_groups AS ag
                LEFT JOIN chat_list_rows AS row
                    ON row.group_id_hex = ag.group_id_hex
                WHERE row.group_id_hex IS NULL
             )",
        [],
    )? {
        return Ok(false);
    }
    if projection_has_rows_tx(
        tx,
        "SELECT EXISTS(
                SELECT 1
                FROM chat_list_rows AS row
                LEFT JOIN account_groups AS ag
                    ON ag.group_id_hex = row.group_id_hex
                WHERE ag.group_id_hex IS NULL
             )",
        [],
    )? {
        return Ok(false);
    }
    if projection_has_rows_tx(
        tx,
        "SELECT EXISTS(
                SELECT 1
                FROM account_groups AS ag
                LEFT JOIN account_group_app_components AS avatar_url
                    ON avatar_url.group_id_hex = ag.group_id_hex
                   AND avatar_url.component_id = ?1
                JOIN chat_list_rows AS row
                    ON row.group_id_hex = ag.group_id_hex
                WHERE row.archived IS NOT ag.archived
                   OR row.pending_confirmation IS NOT ag.pending_confirmation
                   OR row.title IS NOT CASE
                        WHEN trim(ag.profile_name) = '' THEN ag.group_id_hex
                        ELSE ag.profile_name
                      END
                   OR row.group_name IS NOT ag.profile_name
                   OR row.avatar_image_hash_hex IS NOT ag.image_hash_hex
                   OR row.avatar_image_key_hex IS NOT ag.image_key_hex
                   OR row.avatar_image_nonce_hex IS NOT ag.image_nonce_hex
                   OR row.avatar_image_upload_key_hex IS NOT ag.image_upload_key_hex
                   OR row.avatar_media_type IS NOT ag.image_media_type
                   OR (row.avatar_url IS NOT NULL AND avatar_url.component_data_hex IS NULL)
                   -- Normalize like `SelfMembership::from_storage` (unknown ->
                   -- 'member'), matching what a rebuild stores, so a value from a
                   -- newer schema does not look perpetually stale.
                   OR row.self_membership IS NOT CASE ag.self_membership
                        WHEN 'left' THEN 'left'
                        WHEN 'removed' THEN 'removed'
                        ELSE 'member'
                      END
                   OR row.conversation_created_at IS NOT ag.conversation_created_at
                   OR row.updated_at < COALESCE(avatar_url.updated_at, 0)
                   OR row.updated_at < ag.updated_at
             )",
        params![GROUP_AVATAR_URL_COMPONENT_ID],
    )? {
        return Ok(false);
    }
    if projection_has_rows_tx(
        tx,
        "SELECT EXISTS(
                SELECT 1
                FROM conversation_read_state AS read_state
                JOIN chat_list_rows AS row
                    ON row.group_id_hex = read_state.group_id_hex
                WHERE row.last_read_message_id_hex IS NOT read_state.last_read_message_id_hex
                   OR row.last_read_timeline_at IS NOT read_state.last_read_timeline_at
                   OR row.manually_marked_unread IS NOT read_state.manually_marked_unread
                   OR row.updated_at < read_state.updated_at
             )",
        [],
    )? {
        return Ok(false);
    }
    if projection_has_rows_tx(
        tx,
        &format!(
            "SELECT EXISTS(
                SELECT 1
                FROM account_groups AS ag
                JOIN chat_list_rows AS row
                    ON row.group_id_hex = ag.group_id_hex
                WHERE row.updated_at < COALESCE((
                        SELECT MAX(mt.received_at)
                        FROM message_timeline AS mt
                        WHERE mt.group_id_hex = ag.group_id_hex
                     ), 0)
                   OR (
                        row.last_message_id_hex,
                        row.last_message_sender,
                        row.last_message_preview,
                        row.last_message_kind,
                        row.last_message_timeline_at,
                        row.last_message_media_json
                     ) IS NOT (
                        SELECT mt.message_id_hex, mt.sender, mt.plaintext,
                               mt.kind, mt.timeline_at, mt.media_json
                        FROM message_timeline AS mt
                        WHERE mt.group_id_hex = ag.group_id_hex
                          AND {activity_filter}
                          AND (
                              mt.invalidation_status IS NULL
                              OR (
                                  mt.direction = 'sent'
                                  AND mt.invalidation_status = 'local_publish_failed'
                              )
                          )
                        ORDER BY {preview_order}
                        LIMIT 1
                     )
                   OR row.last_message_deleted IS NOT COALESCE((
                        SELECT mt.deleted
                        FROM message_timeline AS mt
                        WHERE mt.group_id_hex = ag.group_id_hex
                          AND mt.message_id_hex = row.last_message_id_hex
                     ), 0)
                   OR row.last_message_delivery_state IS NOT COALESCE((
                        SELECT CASE
                            WHEN mt.direction != 'sent' THEN 'not_applicable'
                            WHEN mt.invalidation_status = 'local_publish_failed' THEN 'failed'
                            WHEN mt.source_message_id_hex IS NULL THEN 'pending'
                            ELSE 'delivered'
                        END
                        FROM message_timeline AS mt
                        WHERE mt.group_id_hex = ag.group_id_hex
                          AND mt.message_id_hex = row.last_message_id_hex
                     ), 'not_applicable')
                   OR row.activity_sort_at IS NOT MAX(
                        row.retained_activity_sort_at,
                        COALESCE(row.last_message_timeline_at, 0),
                        COALESCE((
                            SELECT read_state.last_read_timeline_at
                            FROM conversation_read_state AS read_state
                            WHERE read_state.group_id_hex = ag.group_id_hex
                        ), 0),
                        ag.conversation_created_at
                     )
             )"
        ),
        [],
    )? {
        return Ok(false);
    }
    if chat_list_projection_version_tx(tx)? >= CHAT_LIST_PROJECTION_VERSION {
        return Ok(true);
    }
    // The version marker can lag behind rows that a targeted refresh already
    // brought current. Re-derive the unread summary once and rebuild only when
    // a row is actually stale; this preserves the cheap warm path after the
    // marker advances without turning a metadata-only open into needless SQL.
    for (group_id_hex, stored) in chat_list_stored_unread_summaries_tx(tx)? {
        let read_state = read_state_tx(tx, &group_id_hex)?;
        let derived = unread_summary_tx(
            tx,
            local_account_id_hex,
            &group_id_hex,
            read_state.as_ref(),
            mention_classifier,
        )?;
        if derived.count != stored.count
            || derived.mention_count != stored.mention_count
            || derived.first_message_id != stored.first_message_id
        {
            return Ok(false);
        }
    }
    set_chat_list_projection_version_tx(tx, CHAT_LIST_PROJECTION_VERSION)?;
    Ok(true)
}

fn chat_list_stored_unread_summaries_tx(
    tx: &Connection,
) -> StorageResult<Vec<(String, UnreadSummary)>> {
    let mut stmt = tx
        .prepare(
            "SELECT group_id_hex, unread_count, unread_mention_count,
                    first_unread_message_id_hex
             FROM chat_list_rows",
        )
        .storage()?;
    stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, Option<String>>(3)?,
        ))
    })
    .storage()?
    .map(|entry| {
        let (group_id_hex, count, mention_count, first_message_id) = entry.storage()?;
        Ok((
            group_id_hex,
            UnreadSummary {
                count: i64_to_u64(count)?,
                mention_count: i64_to_u64(mention_count)?,
                first_message_id,
            },
        ))
    })
    .collect()
}

fn projection_has_rows_tx<P: Params>(tx: &Connection, sql: &str, params: P) -> StorageResult<bool> {
    let exists: i64 = tx.query_row(sql, params, |row| row.get(0)).storage()?;
    Ok(exists != 0)
}

/// Deliberately writes no pending-leave state. `ChatListRow::leave_requested_at_ms`
/// is derived from `cgka_leave_requests` when the row is *read*, so there is no
/// column here to keep in sync and no rebuild to trigger when the engine clears a
/// leave request behind the projection's back.
fn rebuild_chat_list_row_for_group_tx(
    tx: &Connection,
    local_account_id_hex: &str,
    group: AccountGroupRow,
    mention_classifier: &MentionClassifier<'_>,
) -> StorageResult<()> {
    let latest = latest_chat_list_activity_tx(tx, &group.group_id_hex)?;
    let latest_message = latest.as_ref().map(|latest| &latest.preview);
    let read_state = read_state_tx(tx, &group.group_id_hex)?;
    let unread = unread_summary_tx(
        tx,
        local_account_id_hex,
        &group.group_id_hex,
        read_state.as_ref(),
        mention_classifier,
    )?;
    let activity_sort_at = latest_message
        .map(|message| message.timeline_at)
        .into_iter()
        .chain(
            read_state
                .as_ref()
                .and_then(|state| state.last_read_timeline_at),
        )
        .fold(group.conversation_created_at, u64::max);
    let now = unix_now_seconds();
    tx.execute(
        "INSERT INTO chat_list_rows (
            group_id_hex, archived, pending_confirmation, title, group_name,
            avatar_url,
            avatar_image_hash_hex, avatar_image_key_hex, avatar_image_nonce_hex,
            avatar_image_upload_key_hex, avatar_media_type,
            last_message_id_hex, last_message_sender, last_message_preview,
            last_message_kind, last_message_timeline_at, last_message_deleted,
            last_message_media_json, last_message_delivery_state,
            unread_count, manually_marked_unread, unread_mention_count,
            first_unread_message_id_hex,
            last_read_message_id_hex, last_read_timeline_at,
            conversation_created_at, activity_sort_at, retained_activity_sort_at,
            updated_at, self_membership
         )
         VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
            ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20,
            ?21, ?22, ?23, ?24, ?25, ?26, ?27, 0, ?28, ?29
         )
         ON CONFLICT(group_id_hex) DO UPDATE SET
            archived = excluded.archived,
            pending_confirmation = excluded.pending_confirmation,
            title = excluded.title,
            group_name = excluded.group_name,
            avatar_url = excluded.avatar_url,
            avatar_image_hash_hex = excluded.avatar_image_hash_hex,
            avatar_image_key_hex = excluded.avatar_image_key_hex,
            avatar_image_nonce_hex = excluded.avatar_image_nonce_hex,
            avatar_image_upload_key_hex = excluded.avatar_image_upload_key_hex,
            avatar_media_type = excluded.avatar_media_type,
            last_message_id_hex = excluded.last_message_id_hex,
            last_message_sender = excluded.last_message_sender,
            last_message_preview = excluded.last_message_preview,
            last_message_kind = excluded.last_message_kind,
            last_message_timeline_at = excluded.last_message_timeline_at,
            last_message_deleted = excluded.last_message_deleted,
            last_message_media_json = excluded.last_message_media_json,
            last_message_delivery_state = excluded.last_message_delivery_state,
            unread_count = excluded.unread_count,
            manually_marked_unread = excluded.manually_marked_unread,
            unread_mention_count = excluded.unread_mention_count,
            first_unread_message_id_hex = excluded.first_unread_message_id_hex,
            last_read_message_id_hex = excluded.last_read_message_id_hex,
            last_read_timeline_at = excluded.last_read_timeline_at,
            conversation_created_at = excluded.conversation_created_at,
            activity_sort_at = MAX(
                excluded.activity_sort_at,
                chat_list_rows.retained_activity_sort_at
            ),
            retained_activity_sort_at = chat_list_rows.retained_activity_sort_at,
            updated_at = excluded.updated_at,
            self_membership = excluded.self_membership",
        params![
            &group.group_id_hex,
            bool_i64(group.archived),
            bool_i64(group.pending_confirmation),
            chat_title(&group),
            &group.profile_name,
            group.avatar_url.as_deref(),
            group
                .avatar
                .as_ref()
                .map(|avatar| avatar.image_hash_hex.as_str())
                .unwrap_or(""),
            group
                .avatar
                .as_ref()
                .map(|avatar| avatar.image_key_hex.as_str())
                .unwrap_or(""),
            group
                .avatar
                .as_ref()
                .map(|avatar| avatar.image_nonce_hex.as_str())
                .unwrap_or(""),
            group
                .avatar
                .as_ref()
                .map(|avatar| avatar.image_upload_key_hex.as_str())
                .unwrap_or(""),
            group
                .avatar
                .as_ref()
                .and_then(|avatar| avatar.media_type.as_deref()),
            latest_message.map(|message| message.message_id_hex.as_str()),
            latest_message.map(|message| message.sender.as_str()),
            latest_message.map(|message| message.plaintext.as_str()),
            optional_u64_to_i64(latest_message.map(|message| message.kind))?,
            optional_u64_to_i64(latest_message.map(|message| message.timeline_at))?,
            latest_message
                .map(|message| bool_i64(message.deleted))
                .unwrap_or(0),
            latest_message.and_then(|message| message.media_json.as_deref()),
            latest_message
                .map(|message| message.delivery_state.as_str())
                .unwrap_or_else(|| ChatListMessageDeliveryState::NotApplicable.as_str()),
            u64_to_i64(unread.count)?,
            bool_i64(
                read_state
                    .as_ref()
                    .is_some_and(|state| state.manually_marked_unread)
            ),
            u64_to_i64(unread.mention_count)?,
            unread.first_message_id.as_deref(),
            read_state
                .as_ref()
                .and_then(|state| state.last_read_message_id_hex.as_deref()),
            optional_u64_to_i64(
                read_state
                    .as_ref()
                    .and_then(|state| state.last_read_timeline_at)
            )?,
            u64_to_i64(group.conversation_created_at)?,
            u64_to_i64(activity_sort_at)?,
            u64_to_i64(now)?,
            group.self_membership.as_str(),
        ],
    )
    .storage()?;
    Ok(())
}

#[derive(Clone, Debug)]
struct UnreadSummary {
    count: u64,
    mention_count: u64,
    first_message_id: Option<String>,
}

fn unread_summary_tx(
    tx: &Connection,
    local_account_id_hex: &str,
    group_id_hex: &str,
    read_state: Option<&ConversationReadState>,
    mention_classifier: &MentionClassifier<'_>,
) -> StorageResult<UnreadSummary> {
    let Some(read_state) = read_state else {
        return Ok(UnreadSummary {
            count: 0,
            mention_count: 0,
            first_message_id: None,
        });
    };
    let (where_sql, marker_params, order_sql) =
        if let Some((class, primary, phase, at, id)) = read_state.canonical_order_key() {
            (
                "(timeline_order_class,
              timeline_order_primary,
              timeline_order_phase,
              timeline_order_at,
              message_id_hex) > (?3, ?4, ?5, ?6, ?7)",
                vec![
                    rusqlite::types::Value::Integer(i64::from(class)),
                    rusqlite::types::Value::Integer(u64_to_i64(primary)?),
                    rusqlite::types::Value::Integer(i64::from(phase)),
                    rusqlite::types::Value::Integer(u64_to_i64(at)?),
                    rusqlite::types::Value::Text(id.to_owned()),
                ],
                "timeline_order_class ASC,
              timeline_order_primary ASC,
              timeline_order_phase ASC,
              timeline_order_at ASC,
              message_id_hex ASC",
            )
        } else if let Some(last_read_at) = read_state.last_read_timeline_at {
            let marker_id = read_state.last_read_message_id_hex.as_deref().unwrap_or("");
            (
                "(timeline_at > ?3 OR (timeline_at = ?3 AND message_id_hex > ?4))",
                vec![
                    rusqlite::types::Value::Integer(u64_to_i64(last_read_at)?),
                    rusqlite::types::Value::Text(marker_id.to_owned()),
                ],
                "timeline_at ASC, message_id_hex ASC",
            )
        } else {
            (
                "timeline_at > ?3 AND (?4 = ?4)",
                vec![
                    rusqlite::types::Value::Integer(u64_to_i64(read_state.initialized_at)?),
                    rusqlite::types::Value::Text(String::new()),
                ],
                "timeline_at ASC, message_id_hex ASC",
            )
        };
    // Derive count + first-unread id + mention_count from one ordered scan over
    // the unread window. Persisted canonical anchors use the same accepted-history
    // key as timeline pagination even after retention prunes the marker row.
    // Legacy states without a canonical anchor use wall-clock predicate + order.
    let activity_filter = chat_list_activity_filter_sql("");
    let scan_sql = format!(
        "SELECT message_id_hex, plaintext, tags_json, kind
         FROM message_timeline
         WHERE group_id_hex = ?1
           AND {activity_filter}
           AND deleted = 0
           AND invalidation_status IS NULL
           AND sender != ?2
           AND {where_sql}
         ORDER BY {order_sql}"
    );
    let mut query_params = vec![
        rusqlite::types::Value::Text(group_id_hex.to_owned()),
        rusqlite::types::Value::Text(local_account_id_hex.to_owned()),
    ];
    query_params.extend(marker_params);
    let mut scan_stmt = tx.prepare(&scan_sql).storage()?;
    let mut scan_rows = scan_stmt
        .query(rusqlite::params_from_iter(query_params))
        .storage()?;
    let mut count: u64 = 0;
    let mut mention_count: u64 = 0;
    let mut first_message_id: Option<String> = None;
    while let Some(row) = scan_rows.next().storage()? {
        let message_id_hex: String = row.get(0).storage()?;
        let plaintext: String = row.get(1).storage()?;
        let tags_json: String = row.get(2).storage()?;
        let kind = i64_to_u64(row.get(3).storage()?)?;
        if first_message_id.is_none() {
            first_message_id = Some(message_id_hex);
        }
        count += 1;
        let tags = crate::tags_from_json(tags_json).unwrap_or_default();
        if kind == MARMOT_APP_EVENT_KIND_CHAT && mention_classifier(&plaintext, &tags) {
            mention_count += 1;
        }
    }
    Ok(UnreadSummary {
        count,
        mention_count,
        first_message_id,
    })
}

pub(crate) fn refresh_chat_list_unread_after_secure_prune_tx(
    tx: &Connection,
    local_account_id_hex: &str,
    group_id_hex: &str,
    mention_classifier: &MentionClassifier<'_>,
) -> StorageResult<()> {
    let read_state = read_state_tx(tx, group_id_hex)?;
    let unread = unread_summary_tx(
        tx,
        local_account_id_hex,
        group_id_hex,
        read_state.as_ref(),
        mention_classifier,
    )?;
    tx.execute(
        "UPDATE chat_list_rows
         SET unread_count = ?2,
             unread_mention_count = ?3,
             first_unread_message_id_hex = ?4
         WHERE group_id_hex = ?1",
        params![
            group_id_hex,
            u64_to_i64(unread.count)?,
            u64_to_i64(unread.mention_count)?,
            unread.first_message_id
        ],
    )
    .storage()?;
    Ok(())
}

fn account_groups_tx(tx: &Connection) -> StorageResult<Vec<AccountGroupRow>> {
    let mut stmt = tx
        .prepare(
            "SELECT ag.group_id_hex, ag.archived, ag.pending_confirmation, ag.profile_name,
                    image_hash_hex, image_key_hex, image_nonce_hex,
                    image_upload_key_hex, image_media_type, avatar_url.component_data_hex,
                    ag.conversation_created_at, ag.self_membership
             FROM account_groups AS ag
             LEFT JOIN account_group_app_components AS avatar_url
                ON avatar_url.group_id_hex = ag.group_id_hex
               AND avatar_url.component_id = ?1",
        )
        .storage()?;
    stmt.query_map(
        params![GROUP_AVATAR_URL_COMPONENT_ID],
        account_group_from_row,
    )
    .storage()?
    .collect::<Result<Vec<_>, _>>()
    .storage()
}

fn account_group_tx(tx: &Connection, group_id_hex: &str) -> StorageResult<Option<AccountGroupRow>> {
    tx.query_row(
        "SELECT ag.group_id_hex, ag.archived, ag.pending_confirmation, ag.profile_name,
                image_hash_hex, image_key_hex, image_nonce_hex,
                image_upload_key_hex, image_media_type, avatar_url.component_data_hex,
                ag.conversation_created_at, ag.self_membership
         FROM account_groups AS ag
         LEFT JOIN account_group_app_components AS avatar_url
            ON avatar_url.group_id_hex = ag.group_id_hex
           AND avatar_url.component_id = ?2
         WHERE ag.group_id_hex = ?1",
        params![group_id_hex, GROUP_AVATAR_URL_COMPONENT_ID],
        account_group_from_row,
    )
    .optional()
    .storage()
}

fn account_group_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AccountGroupRow> {
    let image_hash_hex: String = row.get(4)?;
    let image_key_hex: String = row.get(5)?;
    let image_nonce_hex: String = row.get(6)?;
    let image_upload_key_hex: String = row.get(7)?;
    let media_type: Option<String> = row.get(8)?;
    let avatar_url_component_hex: Option<String> = row.get(9)?;
    let conversation_created_at = row.get::<_, i64>(10)?.try_into().unwrap_or_default();
    let self_membership: String = row.get(11)?;
    let has_avatar = !image_hash_hex.is_empty()
        || !image_key_hex.is_empty()
        || !image_nonce_hex.is_empty()
        || !image_upload_key_hex.is_empty()
        || media_type.is_some();
    Ok(AccountGroupRow {
        group_id_hex: row.get(0)?,
        archived: row.get::<_, i64>(1)? != 0,
        pending_confirmation: row.get::<_, i64>(2)? != 0,
        profile_name: row.get(3)?,
        avatar_url: decoded_avatar_url(avatar_url_component_hex.as_deref()),
        avatar: has_avatar.then_some(ChatListAvatar {
            image_hash_hex,
            image_key_hex,
            image_nonce_hex,
            image_upload_key_hex,
            media_type,
        }),
        conversation_created_at,
        self_membership: SelfMembership::from_storage(&self_membership),
    })
}

fn latest_chat_list_activity_tx(
    tx: &Connection,
    group_id_hex: &str,
) -> StorageResult<Option<LatestChatListMessage>> {
    let activity_filter = chat_list_activity_filter_sql("preview.");
    let preview_order = chat_list_preview_order_desc("preview.");
    let sql = format!(
        "SELECT preview.message_id_hex, preview.sender, preview.plaintext,
                preview.kind, preview.timeline_at, preview.deleted,
                preview.media_json, preview.direction,
                preview.source_message_id_hex, preview.invalidation_status,
                preview.timeline_order_class, preview.timeline_order_primary,
                preview.timeline_order_phase, preview.timeline_order_at
         FROM message_timeline AS preview
         WHERE preview.group_id_hex = ?1 AND {activity_filter}
           AND (
               preview.invalidation_status IS NULL
               OR (
                   preview.direction = 'sent'
                   AND preview.invalidation_status = 'local_publish_failed'
               )
           )
         ORDER BY {preview_order}
         LIMIT 1"
    );
    tx.query_row(&sql, params![group_id_hex], |row| {
        Ok(LatestChatListMessage {
            preview: chat_list_message_from_row(row)?,
            canonical_order_prefix: (
                row.get::<_, i64>(10)?.try_into().unwrap_or_default(),
                row.get::<_, i64>(11)?.try_into().unwrap_or_default(),
                row.get::<_, i64>(12)?.try_into().unwrap_or_default(),
                row.get::<_, i64>(13)?.try_into().unwrap_or_default(),
            ),
        })
    })
    .optional()
    .storage()
}

fn timeline_message_for_read_marker_tx(
    tx: &Connection,
    group_id_hex: &str,
    message_id_hex: &str,
) -> StorageResult<Option<TimelineReadMarker>> {
    let activity_filter = chat_list_activity_filter_sql("");
    tx.query_row(
        &format!(
            "SELECT message_id_hex, source_message_id_hex, source_epoch,
                invalidation_status, kind, timeline_at
         FROM message_timeline
         WHERE group_id_hex = ?1
           AND message_id_hex = ?2
           AND {activity_filter}"
        ),
        params![group_id_hex, message_id_hex],
        |row| {
            Ok(TimelineReadMarker {
                message_id_hex: row.get(0)?,
                source_message_id_hex: row.get(1)?,
                source_epoch: row
                    .get::<_, Option<i64>>(2)?
                    .and_then(|value| value.try_into().ok()),
                invalidation_status: row.get(3)?,
                kind: row.get::<_, i64>(4)?.try_into().unwrap_or_default(),
                timeline_at: row.get::<_, i64>(5)?.try_into().unwrap_or_default(),
            })
        },
    )
    .optional()
    .storage()
}

fn chat_list_message_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ChatListMessagePreview> {
    let direction = row.get::<_, String>(7)?;
    let source_message_id_hex = row.get::<_, Option<String>>(8)?;
    let invalidation_status = row.get::<_, Option<String>>(9)?;
    let delivery_state = if direction != "sent" {
        ChatListMessageDeliveryState::NotApplicable
    } else if invalidation_status.as_deref() == Some("local_publish_failed") {
        ChatListMessageDeliveryState::Failed
    } else if source_message_id_hex.is_some() {
        ChatListMessageDeliveryState::Delivered
    } else {
        ChatListMessageDeliveryState::Pending
    };
    Ok(ChatListMessagePreview {
        message_id_hex: row.get(0)?,
        sender: row.get(1)?,
        sender_display_name: None,
        plaintext: row.get(2)?,
        kind: row.get::<_, i64>(3)?.try_into().unwrap_or_default(),
        timeline_at: row.get::<_, i64>(4)?.try_into().unwrap_or_default(),
        deleted: row.get::<_, i64>(5)? != 0,
        attachment_kind: None,
        attachment_count: 0,
        delivery_state,
        media_json: row.get(6)?,
    })
}

fn insert_initial_read_state_tx(
    tx: &Connection,
    group_id_hex: &str,
    manually_marked_unread: bool,
) -> StorageResult<()> {
    let latest = latest_chat_list_activity_tx(tx, group_id_hex)?;
    let (message_id, timeline_at, order_class, order_primary, order_phase, order_at) = match latest
    {
        Some(latest) => (
            Some(latest.preview.message_id_hex),
            Some(latest.preview.timeline_at),
            Some(latest.canonical_order_prefix.0),
            Some(latest.canonical_order_prefix.1),
            Some(latest.canonical_order_prefix.2),
            Some(latest.canonical_order_prefix.3),
        ),
        None => (None, None, None, None, None, None),
    };
    // Match first-open semantics: with no retained chat or group-system
    // activity there is no read anchor yet, so a subsequently recorded row
    // counts even when its sender timestamp predates this local interaction.
    let initialized_at = timeline_at.unwrap_or(0);
    tx.execute(
        "INSERT INTO conversation_read_state (
            group_id_hex, last_read_message_id_hex, last_read_timeline_at,
            last_read_order_class, last_read_order_primary,
            last_read_order_phase, last_read_order_at,
            initialized_at, updated_at, manually_marked_unread
         )
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            group_id_hex,
            message_id,
            optional_u64_to_i64(timeline_at)?,
            order_class.map(i64::from),
            optional_u64_to_i64(order_primary)?,
            order_phase.map(i64::from),
            optional_u64_to_i64(order_at)?,
            u64_to_i64(initialized_at)?,
            u64_to_i64(unix_now_seconds())?,
            bool_i64(manually_marked_unread),
        ],
    )
    .storage()?;
    Ok(())
}

fn read_state_tx(
    tx: &Connection,
    group_id_hex: &str,
) -> StorageResult<Option<ConversationReadState>> {
    tx.query_row(
        "SELECT last_read_message_id_hex, last_read_timeline_at,
                last_read_order_class, last_read_order_primary,
                last_read_order_phase, last_read_order_at,
                initialized_at, manually_marked_unread
         FROM conversation_read_state
         WHERE group_id_hex = ?1",
        params![group_id_hex],
        |row| {
            Ok(ConversationReadState {
                last_read_message_id_hex: row.get(0)?,
                last_read_timeline_at: row
                    .get::<_, Option<i64>>(1)?
                    .and_then(|value| value.try_into().ok()),
                last_read_order_class: row
                    .get::<_, Option<i64>>(2)?
                    .and_then(|value| value.try_into().ok()),
                last_read_order_primary: row
                    .get::<_, Option<i64>>(3)?
                    .and_then(|value| value.try_into().ok()),
                last_read_order_phase: row
                    .get::<_, Option<i64>>(4)?
                    .and_then(|value| value.try_into().ok()),
                last_read_order_at: row
                    .get::<_, Option<i64>>(5)?
                    .and_then(|value| value.try_into().ok()),
                initialized_at: row.get::<_, i64>(6)?.try_into().unwrap_or_default(),
                manually_marked_unread: row.get::<_, i64>(7)? != 0,
            })
        },
    )
    .optional()
    .storage()
}

fn chat_list_rows_tx(tx: &Connection, query: ChatListQuery) -> StorageResult<Vec<ChatListRow>> {
    let sql = if query.include_archived {
        format!(
            "{CHAT_LIST_ROW_SELECT_AND_JOINS}
             ORDER BY pin.ordinal IS NULL, pin.ordinal ASC,
                      row.activity_sort_at DESC, row.group_id_hex"
        )
    } else {
        format!(
            "{CHAT_LIST_ROW_SELECT_AND_JOINS}
             WHERE row.archived = 0
             ORDER BY pin.ordinal IS NULL, pin.ordinal ASC,
                      row.activity_sort_at DESC, row.group_id_hex"
        )
    };
    let now_ms = unix_now_ms();
    let mut stmt = tx.prepare(&sql).storage()?;
    let mut rows = stmt
        .query_map([], |row| chat_list_row_from_row(row, now_ms))
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()?;
    // Derived at read time, inside the same transaction as the projection read,
    // so the pending-leave stamp is always consistent with the row it rides on.
    let pending = pending_leave_requests_by_group_hex_tx(tx)?;
    if !pending.is_empty() {
        for row in &mut rows {
            row.leave_requested_at_ms = pending.get(&row.group_id_hex).copied();
        }
    }
    let disbanding = disbanding_group_ids_hex_tx(tx)?;
    let disband_requests = disband_requests_by_group_hex_tx(tx)?;
    for row in &mut rows {
        row.disbanding = disbanding.contains(&row.group_id_hex);
        row.disband_request = disband_requests.get(&row.group_id_hex).cloned();
    }
    Ok(rows)
}

fn direct_conversation_candidate_sql() -> String {
    // Drive from the peer index, then join the matching chat-list row.
    // Durable activity order, not pin-first chat-list order.
    format!(
        "{CHAT_LIST_ROW_SELECT_LIST}
         FROM direct_conversation_members AS dcm
         JOIN chat_list_rows AS row ON row.group_id_hex = dcm.group_id_hex
         LEFT JOIN account_groups AS ag ON ag.group_id_hex = row.group_id_hex
         LEFT JOIN chat_notification_settings AS mute
            ON mute.group_id_hex = row.group_id_hex
         LEFT JOIN chat_pin_positions AS pin
            ON pin.group_id_hex = row.group_id_hex
         WHERE dcm.member_id_hex = ?1
           AND TRIM(row.group_name) = ''
           AND ag.member_count = 2
         ORDER BY row.activity_sort_at DESC, row.group_id_hex"
    )
}

fn direct_conversation_candidate_rows_tx(
    tx: &Connection,
    peer_account_id_hex: &str,
) -> StorageResult<Vec<ChatListRow>> {
    let peer_account_id_hex = peer_account_id_hex.trim().to_ascii_lowercase();
    if peer_account_id_hex.is_empty() {
        return Ok(Vec::new());
    }
    let sql = direct_conversation_candidate_sql();
    let now_ms = unix_now_ms();
    let mut stmt = tx.prepare(&sql).storage()?;
    let mut rows = stmt
        .query_map(params![peer_account_id_hex], |row| {
            chat_list_row_from_row(row, now_ms)
        })
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()?;
    let pending = pending_leave_requests_by_group_hex_tx(tx)?;
    if !pending.is_empty() {
        for row in &mut rows {
            row.leave_requested_at_ms = pending.get(&row.group_id_hex).copied();
        }
    }
    let disbanding = disbanding_group_ids_hex_tx(tx)?;
    let disband_requests = disband_requests_by_group_hex_tx(tx)?;
    for row in &mut rows {
        row.disbanding = disbanding.contains(&row.group_id_hex);
        row.disband_request = disband_requests.get(&row.group_id_hex).cloned();
    }
    Ok(rows)
}

fn chat_list_row_tx(tx: &Connection, group_id_hex: &str) -> StorageResult<Option<ChatListRow>> {
    let now_ms = unix_now_ms();
    let sql = format!(
        "{CHAT_LIST_ROW_SELECT_AND_JOINS}
         WHERE row.group_id_hex = ?1"
    );
    tx.query_row(&sql, params![group_id_hex], |row| {
        chat_list_row_from_row(row, now_ms)
    })
    .optional()
    .storage()?
    .map(|mut row| {
        // Same read-time derivation as `chat_list_rows_tx`; see there.
        row.leave_requested_at_ms = pending_leave_requests_by_group_hex_tx(tx)?
            .get(&row.group_id_hex)
            .copied();
        let disband_requests = disband_requests_by_group_hex_tx(tx)?;
        row.disbanding = disbanding_group_ids_hex_with_requests_tx(tx, &disband_requests)?
            .contains(&row.group_id_hex);
        row.disband_request = disband_requests.get(&row.group_id_hex).cloned();
        Ok(row)
    })
    .transpose()
}

// Keep this projection in one place: `chat_list_row_from_row` decodes it by
// index, so list and single-row queries must never drift in column order.
// `CHAT_LIST_ROW_SELECT_LIST` must stay column-identical to
// `CHAT_LIST_ROW_SELECT_AND_JOINS` so the peer-driven candidate query
// decodes the same way.
const CHAT_LIST_ROW_SELECT_LIST: &str =
    "SELECT row.group_id_hex, row.archived, row.pending_confirmation,
            row.title, row.group_name, row.avatar_url,
            row.avatar_image_hash_hex, row.avatar_image_key_hex,
            row.avatar_image_nonce_hex, row.avatar_image_upload_key_hex,
            row.avatar_media_type, row.last_message_id_hex,
            row.last_message_sender, row.last_message_preview,
            row.last_message_kind, row.last_message_timeline_at,
            row.last_message_deleted, row.last_message_media_json,
            row.last_message_delivery_state, row.unread_count,
            row.manually_marked_unread, row.unread_mention_count,
            row.first_unread_message_id_hex, row.last_read_message_id_hex,
            row.last_read_timeline_at, row.conversation_created_at,
            row.activity_sort_at, row.updated_at, row.self_membership,
            ag.member_count,
            mute.group_id_hex IS NOT NULL,
            mute.muted_until_ms,
            EXISTS (
                SELECT 1 FROM cgka_disband_tombstones AS tomb
                WHERE lower(hex(tomb.group_id)) = lower(row.group_id_hex)
            ),
            pin.group_id_hex IS NOT NULL,
            CASE WHEN pin.ordinal IS NULL THEN NULL ELSE (
                SELECT COUNT(*)
                FROM chat_pin_positions AS earlier_pin
                WHERE earlier_pin.ordinal < pin.ordinal
            ) END";

const CHAT_LIST_ROW_SELECT_AND_JOINS: &str =
    "SELECT row.group_id_hex, row.archived, row.pending_confirmation,
            row.title, row.group_name, row.avatar_url,
            row.avatar_image_hash_hex, row.avatar_image_key_hex,
            row.avatar_image_nonce_hex, row.avatar_image_upload_key_hex,
            row.avatar_media_type, row.last_message_id_hex,
            row.last_message_sender, row.last_message_preview,
            row.last_message_kind, row.last_message_timeline_at,
            row.last_message_deleted, row.last_message_media_json,
            row.last_message_delivery_state, row.unread_count,
            row.manually_marked_unread, row.unread_mention_count,
            row.first_unread_message_id_hex, row.last_read_message_id_hex,
            row.last_read_timeline_at, row.conversation_created_at,
            row.activity_sort_at, row.updated_at, row.self_membership,
            ag.member_count,
            mute.group_id_hex IS NOT NULL,
            mute.muted_until_ms,
            EXISTS (
                SELECT 1 FROM cgka_disband_tombstones AS tomb
                WHERE lower(hex(tomb.group_id)) = lower(row.group_id_hex)
            ),
            pin.group_id_hex IS NOT NULL,
            CASE WHEN pin.ordinal IS NULL THEN NULL ELSE (
                SELECT COUNT(*)
                FROM chat_pin_positions AS earlier_pin
                WHERE earlier_pin.ordinal < pin.ordinal
            ) END
     FROM chat_list_rows AS row
     LEFT JOIN account_groups AS ag ON ag.group_id_hex = row.group_id_hex
     LEFT JOIN chat_notification_settings AS mute
        ON mute.group_id_hex = row.group_id_hex
     LEFT JOIN chat_pin_positions AS pin
        ON pin.group_id_hex = row.group_id_hex";

fn chat_list_row_from_row(row: &rusqlite::Row<'_>, now_ms: i64) -> rusqlite::Result<ChatListRow> {
    let group_name: String = row.get(4)?;
    let avatar_url: Option<String> = row.get(5)?;
    let image_hash_hex: String = row.get(6)?;
    let image_key_hex: String = row.get(7)?;
    let image_nonce_hex: String = row.get(8)?;
    let image_upload_key_hex: String = row.get(9)?;
    let media_type: Option<String> = row.get(10)?;
    let has_avatar = !image_hash_hex.is_empty()
        || !image_key_hex.is_empty()
        || !image_nonce_hex.is_empty()
        || !image_upload_key_hex.is_empty()
        || media_type.is_some();
    let last_message_id_hex: Option<String> = row.get(11)?;
    let last_message = last_message_id_hex.map(|message_id_hex| ChatListMessagePreview {
        message_id_hex,
        sender: row.get(12).unwrap_or_default(),
        sender_display_name: None,
        plaintext: row.get(13).unwrap_or_default(),
        kind: row
            .get::<_, Option<i64>>(14)
            .unwrap_or_default()
            .and_then(|value| value.try_into().ok())
            .unwrap_or_default(),
        timeline_at: row
            .get::<_, Option<i64>>(15)
            .unwrap_or_default()
            .and_then(|value| value.try_into().ok())
            .unwrap_or_default(),
        deleted: row.get::<_, i64>(16).unwrap_or_default() != 0,
        attachment_kind: None,
        attachment_count: 0,
        delivery_state: ChatListMessageDeliveryState::from_storage(
            &row.get::<_, String>(18).unwrap_or_default(),
        ),
        media_json: row.get(17).unwrap_or_default(),
    });
    let raw_unread_count = row.get::<_, i64>(19)?;
    let unread_count = raw_unread_count
        .try_into()
        .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(19, raw_unread_count))?;
    let manually_marked_unread = row.get::<_, i64>(20)? != 0;
    let raw_unread_mention_count = row.get::<_, i64>(21)?;
    let unread_mention_count = raw_unread_mention_count
        .try_into()
        .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(21, raw_unread_mention_count))?;
    let member_count = row
        .get::<_, Option<i64>>(29)?
        .and_then(|value| u64::try_from(value).ok());
    let mute_row_exists = row.get::<_, i64>(30)? != 0;
    let stored_muted_until_ms = row.get::<_, Option<i64>>(31)?;
    let lifecycle_state = if row.get::<_, i64>(32)? != 0 {
        cgka_traits::GroupLifecycleState::Disbanded
    } else {
        cgka_traits::GroupLifecycleState::Stable
    };
    let muted = chat_mute_is_effective(mute_row_exists, stored_muted_until_ms, now_ms);
    let pinned = row.get::<_, i64>(33)? != 0;
    let pinned_position = row
        .get::<_, Option<i64>>(34)?
        .and_then(|value| u32::try_from(value).ok());
    Ok(ChatListRow {
        group_id_hex: row.get(0)?,
        pinned,
        pinned_position,
        archived: row.get::<_, i64>(1)? != 0,
        pending_confirmation: row.get::<_, i64>(2)? != 0,
        lifecycle_state,
        disbanding: false,
        disband_request: None,
        title: row.get(3)?,
        group_name: group_name.clone(),
        avatar_url,
        avatar: has_avatar.then_some(ChatListAvatar {
            image_hash_hex,
            image_key_hex,
            image_nonce_hex,
            image_upload_key_hex,
            media_type,
        }),
        last_message,
        unread_count,
        has_unread: unread_count > 0 || manually_marked_unread,
        manually_marked_unread,
        unread_mention_count,
        has_unread_mention: unread_mention_count > 0,
        first_unread_message_id_hex: row.get(22)?,
        last_read_message_id_hex: row.get(23)?,
        last_read_timeline_at: row
            .get::<_, Option<i64>>(24)?
            .and_then(|value| value.try_into().ok()),
        conversation_created_at: row.get::<_, i64>(25)?.try_into().unwrap_or_default(),
        activity_sort_at: row.get::<_, i64>(26)?.try_into().unwrap_or_default(),
        updated_at: row.get::<_, i64>(27)?.try_into().unwrap_or_default(),
        self_membership: SelfMembership::from_storage(&row.get::<_, String>(28)?),
        conversation_kind: conversation_kind(&group_name, member_count),
        muted,
        muted_until_ms: muted.then_some(stored_muted_until_ms).flatten(),
        // Not a `chat_list_rows` column; the callers above stamp it from
        // `cgka_leave_requests` after the row is decoded.
        leave_requested_at_ms: None,
    })
}

fn conversation_kind(group_name: &str, member_count: Option<u64>) -> ChatConversationKind {
    if !group_name.trim().is_empty() {
        return ChatConversationKind::Group;
    }
    match member_count {
        Some(2) => ChatConversationKind::Direct,
        Some(_) => ChatConversationKind::Group,
        None => ChatConversationKind::Unknown,
    }
}

fn chat_title(group: &AccountGroupRow) -> &str {
    if group.profile_name.trim().is_empty() {
        &group.group_id_hex
    } else {
        &group.profile_name
    }
}

fn decoded_avatar_url(component_data_hex: Option<&str>) -> Option<String> {
    let bytes = hex::decode(component_data_hex?).ok()?;
    let avatar = decode_group_avatar_url_v1(&bytes).ok()?;
    (!avatar.url.is_empty()).then_some(avatar.url)
}

fn timeline_tuple_after(left_at: u64, left_id: &str, right_at: u64, right_id: &str) -> bool {
    left_at > right_at || (left_at == right_at && left_id > right_id)
}

#[cfg(test)]
mod tests;
