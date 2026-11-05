//! Typed chat-list queries: one native view plus an optional filter, compiled to
//! SQL on top of the view's indexed condition and evaluated before keyset paging.
//!
//! The live window, select-all IDs and revalidation all read through
//! [`ChatListViewQuery::compile`], so list, count and selection cannot disagree.
//! Every leaf reads a `chat_list_rows` column or an indexed per-chat lookup, so
//! cost grows with the chats the view's index walks, never with message history.
//! Values (group IDs, the draft whitespace set) are bound parameters; the SQL text
//! depends only on the filter's shape.
use super::ChatListView;
use rusqlite::types::Value;
use std::fmt;

/// Deepest allowed filter nesting; a single condition has depth 1.
pub const MAX_CHAT_LIST_FILTER_DEPTH: usize = 8;
/// Most filter nodes (operators and leaves) in one query.
pub const MAX_CHAT_LIST_FILTER_NODES: usize = 64;
/// Most group IDs across every `GroupIds` leaf in one query.
pub const MAX_CHAT_LIST_FILTER_GROUP_IDS: usize = 500;

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
}

impl fmt::Debug for ChatListFilter {
    // Group IDs never reach logs; show the shape and list sizes only.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::All(children) => f.debug_tuple("All").field(children).finish(),
            Self::Any(children) => f.debug_tuple("Any").field(children).finish(),
            Self::Not(child) => f.debug_tuple("Not").field(child).finish(),
            Self::Condition(condition) => condition.fmt(f),
            Self::GroupIds(ids) => write!(f, "GroupIds({})", ids.len()),
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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ChatListQueryError {
    #[error("chat-list filter nests deeper than {MAX_CHAT_LIST_FILTER_DEPTH} levels")]
    TooDeep,
    #[error("chat-list filter has more than {MAX_CHAT_LIST_FILTER_NODES} nodes")]
    TooManyNodes,
    #[error("chat-list filter lists more than {MAX_CHAT_LIST_FILTER_GROUP_IDS} group IDs")]
    TooManyGroupIds,
    #[error("chat-list filter node names a child index outside the node list")]
    ChildOutOfRange,
    #[error("chat-list filter node names a child at or before its own index")]
    ChildNotAfterParent,
    #[error("chat-list filter node is the child of more than one node")]
    SharedChild,
    #[error("chat-list filter node is not reachable from the root")]
    UnreachableNode,
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
            Self::GroupIds(_) => false,
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
                Self::Condition(_) => {}
                Self::GroupIds(ids) => lists.push(ids),
            }
        }
        lists
    }
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

    /// Check the size bounds. Every read validates; callers may check earlier.
    pub fn validate(&self) -> Result<(), ChatListQueryError> {
        let Some(filter) = &self.filter else {
            return Ok(());
        };
        let (mut nodes, mut ids) = (0usize, 0usize);
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
            }
        }
        Ok(())
    }

    pub(super) fn compile(&self) -> Result<CompiledQuery, ChatListQueryError> {
        self.validate()?;
        let mut compiled = CompiledQuery {
            view: self.view,
            predicate: self.view.predicate().to_owned(),
            params: Vec::new(),
        };
        if let Some(filter) = &self.filter {
            compiled.predicate.push_str(" AND ");
            write_filter(filter, &mut compiled.predicate, &mut compiled.params);
        }
        Ok(compiled)
    }
}

// Correlated subqueries name the outer table `chat_list_rows`, unaliased in every
// statement that embeds a predicate. Every leaf is a non-NULL boolean, so `NOT`
// is plain negation.
fn write_filter(filter: &ChatListFilter, sql: &mut String, params: &mut Vec<Value>) {
    match filter {
        ChatListFilter::All(children) | ChatListFilter::Any(children) if children.is_empty() => {
            sql.push_str(if matches!(filter, ChatListFilter::All(_)) {
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
            sql.push('(');
            for (index, child) in children.iter().enumerate() {
                if index > 0 {
                    sql.push_str(joiner);
                }
                write_filter(child, sql, params);
            }
            sql.push(')');
        }
        ChatListFilter::Not(child) => {
            sql.push_str("NOT (");
            write_filter(child, sql, params);
            sql.push(')');
        }
        ChatListFilter::Condition(condition) => write_condition(*condition, sql, params),
        ChatListFilter::GroupIds(ids) => {
            // One JSON parameter per list keeps the SQL text independent of its size.
            params.push(Value::Text(
                serde_json::to_string(ids).expect("string list encodes"),
            ));
            sql.push_str(&format!(
                "lower(chat_list_rows.group_id_hex) IN (SELECT lower(value) FROM json_each(?{}))",
                params.len()
            ));
        }
    }
}

fn write_condition(condition: ChatListCondition, sql: &mut String, params: &mut Vec<Value>) {
    // Badges are hidden for invitations (`list_unread` already excludes them) and
    // in the Left scope, so attention leaves never match there.
    const SHOWS_UNREAD: &str = "chat_list_rows.list_unread = 1 AND chat_list_rows.list_scope != 2";
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
            params.push(Value::Text(
                crate::app::chat_presentation::row_contract::DRAFT_WHITE_SPACE.to_owned(),
            ));
            format!(
                "EXISTS(SELECT 1 FROM message_drafts AS draft
                    WHERE draft.group_id_hex = chat_list_rows.group_id_hex
                      AND (trim(draft.content, ?{}) != ''
                           OR EXISTS(SELECT 1 FROM message_draft_attachments AS attachment
                               WHERE attachment.group_id_hex = draft.group_id_hex)))",
                params.len()
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
    };
    sql.push_str(&text);
}

#[cfg(test)]
mod tests;
