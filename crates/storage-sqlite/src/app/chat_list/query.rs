//! Typed chat-list queries: one native view plus an optional filter, compiled to
//! SQL on top of the view's indexed condition and evaluated before keyset paging.
//!
//! The live window, select-all IDs and revalidation all read through
//! [`ChatListViewQuery::compile`], so list, count and selection cannot disagree.
//! Every leaf but `MessageText` reads a `chat_list_rows` column or an indexed
//! per-chat lookup, so cost grows with the chats the view's index walks, never
//! with message history. `MessageText` scans each chat's history, so it compiles
//! only for select-all IDs and revalidation; a window refuses it.
//! Values (group IDs, search text, the draft whitespace set, the read's time)
//! are bound parameters; the SQL text depends only on the filter's shape.
use super::ChatListView;
use rusqlite::types::Value;
use std::fmt;

/// Deepest allowed filter nesting; a single condition has depth 1.
pub const MAX_CHAT_LIST_FILTER_DEPTH: usize = 8;
/// Most filter nodes (operators and leaves) in one query.
pub const MAX_CHAT_LIST_FILTER_NODES: usize = 64;
/// Most group IDs across every `GroupIds` leaf in one query.
pub const MAX_CHAT_LIST_FILTER_GROUP_IDS: usize = 500;
/// Most bytes of search text across every `Text` and `MessageText` leaf in
/// one query, measured before normalization.
pub const MAX_CHAT_LIST_FILTER_TEXT_BYTES: usize = 1024;

/// A native view as the base scope, narrowed by an optional filter. `filter: None`
/// is the whole view, so the four views are the predefined queries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChatListViewQuery {
    pub view: ChatListView,
    pub filter: Option<ChatListFilter>,
}

impl From<ChatListView> for ChatListViewQuery {
    fn from(view: ChatListView) -> Self {
        Self { view, filter: None }
    }
}

/// Boolean expression over one chat. An empty `All` matches every chat in the view
/// and an empty `Any` matches none. Folder rules are ordinary filters: "excluded IDs
/// always win" is `All[Not(GroupIds(excluded)), Any[GroupIds(included), rule]]`.
/// Including an ID never adds a chat outside the base view.
#[derive(Clone, PartialEq, Eq)]
pub enum ChatListFilter {
    All(Vec<ChatListFilter>),
    Any(Vec<ChatListFilter>),
    Not(Box<ChatListFilter>),
    Condition(ChatListCondition),
    /// Chats whose group ID is in the list, compared as case-insensitive hex.
    GroupIds(Vec<String>),
    /// Chats whose searchable text contains this text: the title, group name,
    /// description and a direct chat's peer profile names, matched as a
    /// literal substring after trimming and Unicode lowercasing (the user
    /// directory's rule). Localized fallback titles are not searchable, and
    /// text that is empty after trimming matches no chat. While any chat in
    /// the view still has presentation pending, a query with this leaf is not
    /// ready rather than partial.
    Text(String),
    /// Chats with a visible message whose text contains this text, matched by
    /// the same rule as `Text` and the timeline's `search`: trim and Unicode
    /// lowercase, then a literal substring of the message's current text (an
    /// edited message matches its latest edit). A visible message is a chat
    /// message or poll question the timeline shows: not deleted, not
    /// invalidated (an own send that reached no one still shows, as failed),
    /// not past its disappearing-message expiry at the read's time, and not
    /// from a blocked account. Text that is empty after trimming
    /// matches no chat. This scans each chat's message history, so only
    /// select-all IDs and revalidation accept it; a window refuses it with
    /// [`ChatListQueryError::MessageTextInWindow`]. While retained deletions
    /// and edits are still being backfilled, a query with this leaf is not
    /// ready rather than partial.
    MessageText(String),
}

impl fmt::Debug for ChatListFilter {
    // Group IDs and search text never reach logs; show the shape and list sizes only.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::All(children) => f.debug_tuple("All").field(children).finish(),
            Self::Any(children) => f.debug_tuple("Any").field(children).finish(),
            Self::Not(child) => f.debug_tuple("Not").field(child).finish(),
            Self::Condition(condition) => condition.fmt(f),
            Self::GroupIds(ids) => write!(f, "GroupIds({})", ids.len()),
            Self::Text(_) => f.write_str("Text"),
            Self::MessageText(_) => f.write_str("MessageText"),
        }
    }
}

/// Facts the chat list already stores. Each matches what the presented row shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ChatListCondition {
    /// Neither archived nor departed (the Chats and Unread scope), including invitations.
    Active,
    /// Archived and not departed (the Archived scope).
    Archived,
    /// Departed, disbanded, or with a leave or disband outstanding (the Left scope).
    Left,
    /// An invitation the account has not accepted or declined.
    PendingInvite,
    /// The row shows an unread badge: unread messages or a manual unread mark.
    /// Never an invitation or a chat in the Left scope, whose badges are hidden.
    Unread,
    /// Unread because the user marked it so (`manually_marked_unread`).
    ManualUnread,
    /// Unread with at least one unread mention of this account.
    Mention,
    Pinned,
    /// This account asked to leave and the request is still outstanding.
    PendingLeave,
    /// A local disband request or an inbound disband awaits convergence.
    Disbanding,
    /// A composer draft with non-blank text or an attachment; a reply-only draft
    /// does not count.
    HasDraft,
    /// The row's preview message is a send still waiting for relay acceptance,
    /// as its delivery state shows. An older send behind newer history does not count.
    PendingSend,
    /// The row's preview message is a send whose publish failed, as its delivery
    /// state shows. An older send behind newer history does not count.
    FailedSend,
    /// A one-to-one chat: the row's `conversation_kind` is
    /// [`ChatConversationKind::Direct`](crate::ChatConversationKind::Direct).
    /// A chat whose kind is still Unknown never matches.
    Direct,
    /// A group chat: the row's `conversation_kind` is
    /// [`ChatConversationKind::Group`](crate::ChatConversationKind::Group).
    /// A chat whose kind is still Unknown never matches.
    Group,
    /// Muted at the time of the read, as the row's `muted` shows: muted until
    /// unmuted, or until a time later than the read's. Nothing is written when
    /// a mute expires; a live window testing this wakes at the next expiry.
    Muted,
}

/// One node of the flat encoding the bindings use. Node 0 is the root; every
/// other node is the child of exactly one earlier node.
#[derive(Clone, PartialEq, Eq)]
pub enum ChatListFilterNode {
    All(Vec<u32>),
    Any(Vec<u32>),
    Not(u32),
    Condition(ChatListCondition),
    GroupIds(Vec<String>),
    Text(String),
    MessageText(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ChatListQueryError {
    #[error("chat-list filter nests deeper than {MAX_CHAT_LIST_FILTER_DEPTH} levels")]
    TooDeep,
    #[error("chat-list filter has more than {MAX_CHAT_LIST_FILTER_NODES} nodes")]
    TooManyNodes,
    #[error("chat-list filter lists more than {MAX_CHAT_LIST_FILTER_GROUP_IDS} group IDs")]
    TooManyGroupIds,
    #[error("chat-list filter search text exceeds {MAX_CHAT_LIST_FILTER_TEXT_BYTES} bytes")]
    TextTooLong,
    #[error("chat-list filter node names a child index outside the node list")]
    ChildOutOfRange,
    #[error("chat-list filter node names a child at or before its own index")]
    ChildNotAfterParent,
    #[error("chat-list filter node is the child of more than one node")]
    SharedChild,
    #[error("chat-list filter node is not reachable from the root")]
    UnreachableNode,
    /// Message text scans history, so a live window does not accept it until
    /// a cost check on a large history allows it. Select-all IDs and
    /// revalidation do.
    #[error("chat-list window filters cannot test message text")]
    MessageTextInWindow,
}

impl ChatListFilter {
    /// Build the tree from its flat encoding. An empty list is no filter.
    /// Children must come after their parent, so the list is acyclic; each
    /// non-root node must have exactly one parent, so it is a single tree.
    pub fn from_nodes(
        nodes: Vec<ChatListFilterNode>,
    ) -> Result<Option<ChatListFilter>, ChatListQueryError> {
        if nodes.is_empty() {
            return Ok(None);
        }
        if nodes.len() > MAX_CHAT_LIST_FILTER_NODES {
            return Err(ChatListQueryError::TooManyNodes);
        }
        let mut parented = vec![false; nodes.len()];
        for (index, node) in nodes.iter().enumerate() {
            let children: &[u32] = match node {
                ChatListFilterNode::All(children) | ChatListFilterNode::Any(children) => children,
                ChatListFilterNode::Not(child) => std::slice::from_ref(child),
                _ => &[],
            };
            for &child in children {
                let child = child as usize;
                if child >= nodes.len() {
                    return Err(ChatListQueryError::ChildOutOfRange);
                }
                if child <= index {
                    return Err(ChatListQueryError::ChildNotAfterParent);
                }
                if std::mem::replace(&mut parented[child], true) {
                    return Err(ChatListQueryError::SharedChild);
                }
            }
        }
        if parented.iter().skip(1).any(|parented| !parented) {
            return Err(ChatListQueryError::UnreachableNode);
        }
        let mut slots = nodes.into_iter().map(Some).collect::<Vec<_>>();
        let filter = Self::take_node(&mut slots, 0, 1)?;
        let query = ChatListViewQuery {
            view: ChatListView::Chats,
            filter: Some(filter),
        };
        query.validate()?;
        Ok(query.filter)
    }

    fn take_node(
        slots: &mut [Option<ChatListFilterNode>],
        index: usize,
        depth: usize,
    ) -> Result<ChatListFilter, ChatListQueryError> {
        if depth > MAX_CHAT_LIST_FILTER_DEPTH {
            return Err(ChatListQueryError::TooDeep);
        }
        // Validated above: each index is taken once, by its only parent.
        let node = slots[index].take().expect("tree node taken once");
        let mut children = |indices: Vec<u32>| {
            indices
                .into_iter()
                .map(|child| Self::take_node(slots, child as usize, depth + 1))
                .collect::<Result<Vec<_>, _>>()
        };
        Ok(match node {
            ChatListFilterNode::All(indices) => Self::All(children(indices)?),
            ChatListFilterNode::Any(indices) => Self::Any(children(indices)?),
            ChatListFilterNode::Not(child) => {
                Self::Not(Box::new(Self::take_node(slots, child as usize, depth + 1)?))
            }
            ChatListFilterNode::Condition(condition) => Self::Condition(condition),
            ChatListFilterNode::GroupIds(ids) => Self::GroupIds(ids),
            ChatListFilterNode::Text(text) => Self::Text(text),
            ChatListFilterNode::MessageText(text) => Self::MessageText(text),
        })
    }

    /// Whether any leaf is `condition`. The live window uses it to widen
    /// invalidation for facts it otherwise only watches on visible rows.
    pub fn references(&self, condition: ChatListCondition) -> bool {
        match self {
            Self::All(children) | Self::Any(children) => {
                children.iter().any(|child| child.references(condition))
            }
            Self::Not(child) => child.references(condition),
            Self::Condition(leaf) => *leaf == condition,
            Self::GroupIds(_) | Self::Text(_) | Self::MessageText(_) => false,
        }
    }

    /// Whether any leaf is `Text`. Such a query waits for presentation across
    /// its whole view, and a live window re-reads on any presentation change.
    pub fn references_text(&self) -> bool {
        match self {
            Self::All(children) | Self::Any(children) => children.iter().any(Self::references_text),
            Self::Not(child) => child.references_text(),
            Self::Text(_) => true,
            Self::Condition(_) | Self::GroupIds(_) | Self::MessageText(_) => false,
        }
    }

    /// Whether any leaf is `MessageText`. Such a query is refused by windows
    /// and waits for the retained deletion and edit backfill.
    pub fn references_message_text(&self) -> bool {
        match self {
            Self::All(children) | Self::Any(children) => {
                children.iter().any(Self::references_message_text)
            }
            Self::Not(child) => child.references_message_text(),
            Self::MessageText(_) => true,
            Self::Condition(_) | Self::GroupIds(_) | Self::Text(_) => false,
        }
    }

    /// Mutable access to every `GroupIds` list, for callers that normalize IDs.
    pub fn group_id_lists_mut(&mut self) -> Vec<&mut Vec<String>> {
        let mut lists = Vec::new();
        let mut stack = vec![self];
        while let Some(node) = stack.pop() {
            match node {
                Self::All(children) | Self::Any(children) => stack.extend(children.iter_mut()),
                Self::Not(child) => stack.push(child),
                Self::Condition(_) | Self::Text(_) | Self::MessageText(_) => {}
                Self::GroupIds(ids) => lists.push(ids),
            }
        }
        lists
    }
}

/// Which read a query compiles for. Only `Selection` accepts leaves whose
/// cost grows with history.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum QueryScope {
    /// A live window page; refuses `MessageText`.
    Window,
    /// Select-all IDs and revalidation.
    Selection,
}

/// SQL for one query: the view's condition and the filter, numbered `?1..?n`
/// in `params` order. Callers number their own parameters after these.
pub(super) struct CompiledQuery {
    pub(super) view: ChatListView,
    pub(super) predicate: String,
    pub(super) params: Vec<Value>,
}

impl ChatListViewQuery {
    pub fn references(&self, condition: ChatListCondition) -> bool {
        self.filter
            .as_ref()
            .is_some_and(|filter| filter.references(condition))
    }

    pub fn references_text(&self) -> bool {
        self.filter
            .as_ref()
            .is_some_and(ChatListFilter::references_text)
    }

    pub fn references_message_text(&self) -> bool {
        self.filter
            .as_ref()
            .is_some_and(ChatListFilter::references_message_text)
    }

    /// [`Self::validate`], then refuse what a live window may not evaluate:
    /// a `MessageText` leaf. Every window read checks this before reading.
    pub fn validate_for_window(&self) -> Result<(), ChatListQueryError> {
        self.validate()?;
        if self.references_message_text() {
            return Err(ChatListQueryError::MessageTextInWindow);
        }
        Ok(())
    }

    /// Check the size bounds. Every read validates; callers may check earlier.
    pub fn validate(&self) -> Result<(), ChatListQueryError> {
        let Some(filter) = &self.filter else {
            return Ok(());
        };
        let (mut nodes, mut ids, mut text) = (0usize, 0usize, 0usize);
        let mut stack = vec![(filter, 1usize)];
        while let Some((node, depth)) = stack.pop() {
            if depth > MAX_CHAT_LIST_FILTER_DEPTH {
                return Err(ChatListQueryError::TooDeep);
            }
            nodes += 1;
            if nodes > MAX_CHAT_LIST_FILTER_NODES {
                return Err(ChatListQueryError::TooManyNodes);
            }
            match node {
                ChatListFilter::All(children) | ChatListFilter::Any(children) => {
                    stack.extend(children.iter().map(|child| (child, depth + 1)));
                }
                ChatListFilter::Not(child) => stack.push((child, depth + 1)),
                ChatListFilter::Condition(_) => {}
                ChatListFilter::GroupIds(list) => {
                    ids += list.len();
                    if ids > MAX_CHAT_LIST_FILTER_GROUP_IDS {
                        return Err(ChatListQueryError::TooManyGroupIds);
                    }
                }
                ChatListFilter::Text(value) | ChatListFilter::MessageText(value) => {
                    text += value.len();
                    if text > MAX_CHAT_LIST_FILTER_TEXT_BYTES {
                        return Err(ChatListQueryError::TextTooLong);
                    }
                }
            }
        }
        Ok(())
    }

    /// Compile for a read at `now_ms` (Unix milliseconds), the time a `Muted`
    /// leaf tests mute expiry and a `MessageText` leaf tests message expiry
    /// against. A window scope refuses `MessageText` before writing any SQL.
    pub(super) fn compile(
        &self,
        now_ms: i64,
        scope: QueryScope,
    ) -> Result<CompiledQuery, ChatListQueryError> {
        match scope {
            QueryScope::Window => self.validate_for_window()?,
            QueryScope::Selection => self.validate()?,
        }
        let mut compiled = CompiledQuery {
            view: self.view,
            predicate: self.view.predicate().to_owned(),
            params: Vec::new(),
        };
        if let Some(filter) = &self.filter {
            compiled.predicate.push_str(" AND ");
            let mut writer = FilterWriter {
                sql: &mut compiled.predicate,
                params: &mut compiled.params,
                now_ms,
                now_param: None,
                now_seconds_param: None,
            };
            writer.filter(filter);
        }
        Ok(compiled)
    }
}

/// Up to `limit` chats in `view` whose presentation, and so whose search
/// text, is still pending: never prepared, or invalidated since. A query with
/// a `Text` leaf is not ready while any exist. Walks only the pending index.
pub(super) fn pending_search_text(
    conn: &rusqlite::Connection,
    view: ChatListView,
    limit: usize,
) -> rusqlite::Result<Vec<String>> {
    let sql = format!(
        "SELECT group_id_hex FROM chat_list_rows INDEXED BY chat_presentation_pending
         WHERE (presentation_json IS NULL
                OR presentation_applied_source_revision != presentation_source_revision)
           AND {}
         ORDER BY group_id_hex LIMIT ?1",
        view.predicate()
    );
    let mut statement = conn.prepare_cached(&sql)?;
    statement
        .query_map([i64::try_from(limit).unwrap_or(i64::MAX)], |row| row.get(0))?
        .collect()
}

/// Whether retained deletions, edits and moderation removals from before
/// content reports existed are still being applied to the timeline. Until they
/// are, a message the timeline will hide can still show its text, so a query
/// with a `MessageText` leaf is not ready. One row read.
pub(super) fn message_text_backfill_owed(conn: &rusqlite::Connection) -> rusqlite::Result<bool> {
    use crate::base::connection::CachedSql;
    conn.query_row_cached(
        "SELECT EXISTS(SELECT 1 FROM content_report_backfill WHERE after_order < through_order)",
        [],
        |row| row.get(0),
    )
}

// Correlated subqueries name the outer table `chat_list_rows`, unaliased in every
// statement that embeds a predicate. Every leaf is a non-NULL boolean, so `NOT`
// is plain negation.
struct FilterWriter<'a> {
    sql: &'a mut String,
    params: &'a mut Vec<Value>,
    now_ms: i64,
    /// The read's time is bound once, however many `Muted` leaves use it.
    now_param: Option<usize>,
    /// The read's time in Unix seconds, the unit of message expiry, bound once.
    now_seconds_param: Option<usize>,
}

impl FilterWriter<'_> {
    fn filter(&mut self, filter: &ChatListFilter) {
        match filter {
            ChatListFilter::All(children) | ChatListFilter::Any(children)
                if children.is_empty() =>
            {
                self.sql
                    .push_str(if matches!(filter, ChatListFilter::All(_)) {
                        "1"
                    } else {
                        "0"
                    });
            }
            ChatListFilter::All(children) | ChatListFilter::Any(children) => {
                let joiner = if matches!(filter, ChatListFilter::All(_)) {
                    " AND "
                } else {
                    " OR "
                };
                self.sql.push('(');
                for (index, child) in children.iter().enumerate() {
                    if index > 0 {
                        self.sql.push_str(joiner);
                    }
                    self.filter(child);
                }
                self.sql.push(')');
            }
            ChatListFilter::Not(child) => {
                self.sql.push_str("NOT (");
                self.filter(child);
                self.sql.push(')');
            }
            ChatListFilter::Condition(condition) => self.condition(*condition),
            ChatListFilter::GroupIds(ids) => {
                // One JSON parameter per list keeps the SQL text independent of its size.
                let index = self.bind(Value::Text(
                    serde_json::to_string(ids).expect("string list encodes"),
                ));
                self.sql.push_str(&format!(
                    "lower(chat_list_rows.group_id_hex) IN (SELECT lower(value) FROM json_each(?{index}))"
                ));
            }
            ChatListFilter::Text(text) => {
                // `instr` is a literal match, so `%` and `_` need no escaping.
                // The column holds no control characters, so a query with one
                // could only match across a field separator: it matches nothing.
                let needle = super::search_text::normalize_search_text(text);
                if needle.is_empty() || needle.chars().any(char::is_control) {
                    self.sql.push('0');
                } else {
                    let index = self.bind(Value::Text(needle));
                    self.sql
                        .push_str(&format!("instr(chat_list_rows.search_text, ?{index}) > 0"));
                }
            }
            ChatListFilter::MessageText(text) => {
                let needle = super::search_text::normalize_search_text(text);
                if needle.is_empty() {
                    self.sql.push('0');
                    return;
                }
                let needle = self.bind(Value::Text(needle));
                let now_seconds = match self.now_seconds_param {
                    Some(index) => index,
                    None => {
                        let index = self.bind(Value::Integer(self.now_ms.div_euclid(1000)));
                        self.now_seconds_param = Some(index);
                        index
                    }
                };
                // What the timeline shows as message text: chat messages and
                // poll questions, from accounts not blocked, not deleted (whose
                // text is cleared anyway), not invalidated except an own send
                // that reached no one (shown as failed, as the row's preview
                // does), and not past the expiry the retention sweep prunes at
                // (`<=`, seconds).
                self.sql.push_str(&format!(
                    "EXISTS(SELECT 1 FROM visible_message_timeline AS message
                        WHERE message.group_id_hex = chat_list_rows.group_id_hex
                          AND message.kind IN ({chat}, {poll})
                          AND message.deleted = 0
                          AND (message.invalidation_status IS NULL
                               OR (message.direction = 'sent'
                                   AND message.invalidation_status = '{failed}'))
                          AND {contains}(message.plaintext, ?{needle})
                          AND NOT EXISTS(SELECT 1 FROM app_events AS source
                              WHERE source.group_id_hex = message.group_id_hex
                                AND source.message_id_hex = message.message_id_hex
                                AND source.retention_expires_at <= ?{now_seconds}))",
                    chat = cgka_traits::app_event::MARMOT_APP_EVENT_KIND_CHAT,
                    poll = cgka_traits::MARMOT_APP_EVENT_KIND_POLL,
                    contains = crate::base::text_search::SQL_CONTAINS_FUNCTION,
                    failed = crate::app::timeline::LOCAL_PUBLISH_FAILED_REASON,
                ));
            }
        }
    }

    fn bind(&mut self, value: Value) -> usize {
        self.params.push(value);
        self.params.len()
    }

    fn condition(&mut self, condition: ChatListCondition) {
        // Badges are hidden for invitations (`list_unread` already excludes them) and
        // in the Left scope, so attention leaves never match there.
        const SHOWS_UNREAD: &str =
            "chat_list_rows.list_unread = 1 AND chat_list_rows.list_scope != 2";
        let text = match condition {
            ChatListCondition::Active => "chat_list_rows.list_scope = 0".to_owned(),
            ChatListCondition::Archived => "chat_list_rows.list_scope = 1".to_owned(),
            ChatListCondition::Left => "chat_list_rows.list_scope = 2".to_owned(),
            ChatListCondition::PendingInvite => {
                "COALESCE((SELECT pending.pending_confirmation FROM account_groups AS pending
                    WHERE pending.group_id_hex = chat_list_rows.group_id_hex),
                    chat_list_rows.pending_confirmation) != 0"
                    .to_owned()
            }
            ChatListCondition::Unread => format!("({SHOWS_UNREAD})"),
            ChatListCondition::ManualUnread => {
                format!("({SHOWS_UNREAD} AND chat_list_rows.manually_marked_unread != 0)")
            }
            ChatListCondition::Mention => {
                format!("({SHOWS_UNREAD} AND chat_list_rows.unread_mention_count > 0)")
            }
            ChatListCondition::Pinned => "chat_list_rows.list_pin_ordinal >= 0".to_owned(),
            ChatListCondition::PendingLeave => {
                crate::cross::views::CHAT_LIST_FILTER_PENDING_LEAVE_SQL.to_owned()
            }
            ChatListCondition::Disbanding => {
                crate::cross::views::CHAT_LIST_FILTER_DISBANDING_SQL.to_owned()
            }
            ChatListCondition::HasDraft => {
                let white_space = self.bind(Value::Text(
                    crate::app::chat_presentation::row_contract::DRAFT_WHITE_SPACE.to_owned(),
                ));
                format!(
                    "EXISTS(SELECT 1 FROM message_drafts AS draft
                        WHERE draft.group_id_hex = chat_list_rows.group_id_hex
                          AND (trim(draft.content, ?{white_space}) != ''
                               OR EXISTS(SELECT 1 FROM message_draft_attachments AS attachment
                                   WHERE attachment.group_id_hex = draft.group_id_hex)))"
                )
            }
            // The delivery state the row shows for its preview message, so the leaf
            // agrees with the row and reads no message history.
            ChatListCondition::PendingSend => {
                "chat_list_rows.last_message_delivery_state = 'pending'".to_owned()
            }
            ChatListCondition::FailedSend => {
                "chat_list_rows.last_message_delivery_state = 'failed'".to_owned()
            }
            // `list_kind` is maintained from the classifier's inputs (migration
            // 0179): 0 Unknown, 1 Direct, 2 Group.
            ChatListCondition::Direct => "chat_list_rows.list_kind = 1".to_owned(),
            ChatListCondition::Group => "chat_list_rows.list_kind = 2".to_owned(),
            // The rule the row's `muted` follows (`chat_mute_is_effective`), at the
            // read's time, so an expired mute needs no write.
            ChatListCondition::Muted => {
                let now = match self.now_param {
                    Some(index) => index,
                    None => {
                        let index = self.bind(Value::Integer(self.now_ms));
                        self.now_param = Some(index);
                        index
                    }
                };
                format!(
                    "EXISTS(SELECT 1 FROM chat_notification_settings AS mute
                        WHERE mute.group_id_hex = chat_list_rows.group_id_hex
                          AND (mute.muted_until_ms IS NULL OR mute.muted_until_ms > ?{now}))"
                )
            }
        };
        self.sql.push_str(&text);
    }
}

#[cfg(test)]
mod tests;
