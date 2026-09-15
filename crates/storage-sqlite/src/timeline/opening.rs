//! Bounded, read-only conversation opening over existing timeline/read projections.
use super::*;

/// Account-store/group scoped canonical anchor. Opaque, local, and not a wire cursor.
#[derive(Clone, PartialEq, Eq)]
pub struct ConversationAnchor {
    store_epoch: Vec<u8>,
    group_id_hex: String,
    key: OwnedTimelineOrderKey,
}
impl ConversationAnchor {
    pub fn message_id_hex(&self) -> &str {
        &self.key.4
    }
}
#[derive(Clone, Default)]
pub enum ConversationOpenTarget {
    /// First unread in accepted conversations; otherwise the latest row.
    #[default]
    Automatic,
    Latest,
    /// A missing explicit target is an error, never a silent jump to latest.
    Message(String),
    /// Retain identity, or recover next/previous using its saved canonical key.
    Anchor(ConversationAnchor),
}
#[derive(Clone)]
pub struct ConversationOpenQuery {
    pub target: ConversationOpenTarget,
    /// Total rows, including the anchor: 1..=200; default 50.
    pub limit: usize,
}
impl Default for ConversationOpenQuery {
    fn default() -> Self {
        Self {
            target: ConversationOpenTarget::Automatic,
            limit: DEFAULT_TIMELINE_LIMIT,
        }
    }
}
/// Re-read a bounded live window around its retained viewport anchor. The runtime
/// owns the anchor token and row budget; clients retain pixel offsets separately.
#[derive(Clone, Default)]
pub struct ConversationWindowQuery {
    pub opening: ConversationOpenQuery,
    /// Desired rows before the anchor. None preserves the centered opening policy.
    /// Must be smaller than the row limit; missing context is filled from the other side.
    pub before_anchor: Option<usize>,
}

/// Raw retained read state. These are not C4 account-attention totals.
/// This narrow projection deliberately avoids `chat_list_row_tx` and its
/// account-wide leave/disband scans. Keep opening bounded when integrating
/// the keyed group/header reads from #1793.
#[derive(Clone, PartialEq, Eq)]
pub struct ConversationOpenReadState {
    pub initialized: bool,
    pub last_read_message_id_hex: Option<String>,
    pub last_read_timeline_at: Option<u64>,
    pub manually_marked_unread: bool,
    pub unread_count: u64,
    pub unread_mention_count: u64,
    pub first_unread_message_id_hex: Option<String>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConversationOpenAnchorOutcome {
    Empty,
    Latest { index: usize },
    FirstUnread { index: usize },
    Message { index: usize },
    Retained { index: usize },
    RecoveredNext { index: usize },
    RecoveredPrevious { index: usize },
}
#[derive(Clone)]
pub struct ConversationOpenSnapshot {
    pub page: TimelinePage,
    pub read_state: ConversationOpenReadState,
    pub pending_confirmation: bool,
    pub anchor: ConversationOpenAnchorOutcome,
    /// One token per returned row, in the same order as `page.messages`.
    pub anchors: Vec<ConversationAnchor>,
}
#[derive(Debug, thiserror::Error)]
pub enum ConversationOpenError {
    #[error("conversation opening limit must be between 1 and 200")]
    InvalidLimit,
    #[error("conversation anchor position must be smaller than the row limit")]
    InvalidAnchorPosition,
    #[error("conversation read projection requires preparation")]
    ReadStateNotReady,
    #[error("conversation anchor belongs to a different account store or group")]
    AnchorScopeMismatch,
    #[error("conversation target message is no longer retained")]
    MessageNotFound,
    #[error(transparent)]
    Storage(#[from] StorageError),
}
impl SqliteAccountStorage {
    /// Read opening history and retained read state in one deferred transaction.
    /// No preparation, read acknowledgement, roster load or network work occurs.
    /// A dirty/missing unread projection returns `ReadStateNotReady`; its existing
    /// owner must prepare it before retrying. Nested callers retain their transaction.
    pub fn conversation_open(
        &self,
        group_id_hex: &str,
        query: ConversationOpenQuery,
    ) -> Result<ConversationOpenSnapshot, ConversationOpenError> {
        self.conversation_window(
            group_id_hex,
            ConversationWindowQuery {
                opening: query,
                before_anchor: None,
            },
        )
    }

    /// Reuse opening's canonical ordering, recovery and readiness under one read
    /// transaction. Paging changes placement, never appends an independently read page.
    pub fn conversation_window(
        &self,
        group_id_hex: &str,
        query: ConversationWindowQuery,
    ) -> Result<ConversationOpenSnapshot, ConversationOpenError> {
        if !(1..=MAX_TIMELINE_LIMIT).contains(&query.opening.limit) {
            return Err(ConversationOpenError::InvalidLimit);
        }
        if query
            .before_anchor
            .is_some_and(|before| before >= query.opening.limit)
        {
            return Err(ConversationOpenError::InvalidAnchorPosition);
        }
        let conn = self.lock()?;
        let transaction = if conn.is_autocommit() {
            Some(conn.unchecked_transaction().storage()?)
        } else {
            None
        };
        let snapshot = opening_tx(&conn, group_id_hex, query.opening, query.before_anchor)?;
        if let Some(transaction) = transaction {
            transaction.commit().storage()?;
        }
        Ok(snapshot)
    }
}

fn opening_read_state_tx(
    conn: &Connection,
    group: &str,
) -> Result<ConversationOpenReadState, ConversationOpenError> {
    let ready: bool = conn
        .query_row_cached(
            "SELECT EXISTS(SELECT 1 FROM chat_list_unread_ready_groups WHERE group_id_hex = ?1)
            AND NOT EXISTS(SELECT 1 FROM chat_list_unread_dirty_messages WHERE group_id_hex = ?1)",
            [group],
            |row| row.get(0),
        )
        .storage()?;
    if !ready {
        return Err(ConversationOpenError::ReadStateNotReady);
    }
    // Readiness uses durable membership and structural marker agreement, never
    // independently sampled wall-clock timestamps (which can move backwards).
    const READ_STATE_SQL: &str =
        "SELECT s.group_id_hex IS NOT NULL, s.last_read_message_id_hex, s.last_read_timeline_at,
                COALESCE(s.manually_marked_unread, 0), r.unread_count, r.unread_mention_count,
                r.first_unread_message_id_hex,
                r.last_read_message_id_hex IS s.last_read_message_id_hex
                AND r.last_read_timeline_at IS s.last_read_timeline_at
                AND r.manually_marked_unread = COALESCE(s.manually_marked_unread, 0)
         FROM chat_list_rows r LEFT JOIN conversation_read_state s USING(group_id_hex)
         WHERE r.group_id_hex = ?1";
    let state = conn
        .query_row_cached(READ_STATE_SQL, [group], |row| {
            Ok((
                row.get::<_, bool>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<i64>>(2)?,
                row.get::<_, bool>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, bool>(7)?,
            ))
        })
        .optional()
        .storage()?;
    let Some((initialized, last_id, last_at, manual, count, mentions, first_id, aligned)) = state
    else {
        return Err(ConversationOpenError::ReadStateNotReady);
    };
    // The indexed unread membership is maintained with the counters. This keyed
    // check detects incomplete composition without counting/scanning that set.
    const FIRST_UNREAD_SQL: &str =
        "SELECT message_id_hex FROM chat_list_unread_messages WHERE group_id_hex = ?1
         ORDER BY timeline_order_class, timeline_order_primary, timeline_order_phase,
                  timeline_order_at, message_id_hex LIMIT 1";
    let indexed_first: Option<String> = conn
        .query_row_cached(FIRST_UNREAD_SQL, [group], |row| row.get(0))
        .optional()
        .storage()?;
    if !aligned
        || first_id != indexed_first
        || (count > 0) != first_id.is_some()
        || mentions > count
    {
        return Err(ConversationOpenError::ReadStateNotReady);
    }
    Ok(ConversationOpenReadState {
        initialized,
        last_read_message_id_hex: last_id,
        last_read_timeline_at: last_at.map(i64_to_u64).transpose()?,
        manually_marked_unread: manual,
        unread_count: i64_to_u64(count)?,
        unread_mention_count: i64_to_u64(mentions)?,
        first_unread_message_id_hex: first_id,
    })
}

fn opening_tx(
    conn: &Connection,
    group: &str,
    query: ConversationOpenQuery,
    before_anchor: Option<usize>,
) -> Result<ConversationOpenSnapshot, ConversationOpenError> {
    let pending_confirmation: bool = conn
        .query_row_cached(
            "SELECT pending_confirmation FROM account_groups WHERE group_id_hex = ?1",
            [group],
            |row| row.get(0),
        )
        .optional()
        .storage()?
        .ok_or(StorageError::NotFound)?;
    let store_epoch: Vec<u8> = conn
        .query_row_cached(
            "SELECT store_epoch FROM chat_presentation_meta WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .storage()?;
    if let ConversationOpenTarget::Anchor(anchor) = &query.target
        && (anchor.store_epoch != store_epoch || anchor.group_id_hex != group)
    {
        return Err(ConversationOpenError::AnchorScopeMismatch);
    }
    let read_state = opening_read_state_tx(conn, group)?;
    let mut outcome = ConversationOpenAnchorOutcome::Latest { index: 0 };
    let key = match query.target {
        ConversationOpenTarget::Automatic
            if !pending_confirmation && read_state.first_unread_message_id_hex.is_some() =>
        {
            outcome = ConversationOpenAnchorOutcome::FirstUnread { index: 0 };
            let id = read_state
                .first_unread_message_id_hex
                .as_deref()
                .expect("checked above");
            Some(match timeline_order_cursor_tx(conn, group, id) {
                Err(StorageError::TimelineCursorExpired) => {
                    return Err(ConversationOpenError::ReadStateNotReady);
                }
                result => result?,
            })
        }
        ConversationOpenTarget::Automatic | ConversationOpenTarget::Latest => None,
        ConversationOpenTarget::Message(id) => {
            outcome = ConversationOpenAnchorOutcome::Message { index: 0 };
            Some(match timeline_order_cursor_tx(conn, group, &id) {
                Err(StorageError::TimelineCursorExpired) => {
                    return Err(ConversationOpenError::MessageNotFound);
                }
                result => result?,
            })
        }
        ConversationOpenTarget::Anchor(anchor) => {
            match timeline_order_cursor_tx(conn, group, anchor.message_id_hex()) {
                Ok(key) => {
                    outcome = ConversationOpenAnchorOutcome::Retained { index: 0 };
                    Some(key)
                }
                Err(StorageError::TimelineCursorExpired) => {
                    if let Some(key) = neighbor_key(conn, group, &anchor.key, true)? {
                        outcome = ConversationOpenAnchorOutcome::RecoveredNext { index: 0 };
                        Some(key)
                    } else if let Some(key) = neighbor_key(conn, group, &anchor.key, false)? {
                        outcome = ConversationOpenAnchorOutcome::RecoveredPrevious { index: 0 };
                        Some(key)
                    } else {
                        None
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }
    };
    let (mut messages, has_more_before, has_more_after, index) = if let Some(key) = key {
        // Keep the requested viewport placement, or center the initial opening.
        // Fill missing context from the other side; hydrate reply previews once.
        let left_limit = 1 + before_anchor.unwrap_or((query.limit - 1) / 2);
        let (mut left, mut more_before) =
            slice(conn, group, Some(&key), CursorDirection::Before, left_limit)?;
        let (right, more_after) = slice(
            conn,
            group,
            Some(&key),
            CursorDirection::After,
            query.limit - left.len(),
        )?;
        if left.len() + right.len() < query.limit && more_before {
            (left, more_before) = slice(
                conn,
                group,
                Some(&key),
                CursorDirection::Before,
                query.limit - right.len(),
            )?;
        }
        let index = left.len() - 1;
        left.extend(right);
        (left, more_before, more_after, index)
    } else {
        let (rows, more) = slice(conn, group, None, CursorDirection::None, query.limit)?;
        let index = rows.len().saturating_sub(1);
        (rows, more, false, index)
    };
    if messages.is_empty() {
        outcome = ConversationOpenAnchorOutcome::Empty;
    } else {
        match &mut outcome {
            ConversationOpenAnchorOutcome::Latest { index: i }
            | ConversationOpenAnchorOutcome::FirstUnread { index: i }
            | ConversationOpenAnchorOutcome::Message { index: i }
            | ConversationOpenAnchorOutcome::Retained { index: i }
            | ConversationOpenAnchorOutcome::RecoveredNext { index: i }
            | ConversationOpenAnchorOutcome::RecoveredPrevious { index: i } => *i = index,
            ConversationOpenAnchorOutcome::Empty => unreachable!(),
        }
    }
    attach_reply_previews(conn, &mut messages)?;
    let anchors = messages
        .iter()
        .map(|message| {
            let (class, primary, phase, at, id) = message.canonical_order_key();
            ConversationAnchor {
                store_epoch: store_epoch.clone(),
                group_id_hex: group.to_owned(),
                key: (class, primary, phase, at, id.to_owned()),
            }
        })
        .collect();
    Ok(ConversationOpenSnapshot {
        page: TimelinePage {
            messages,
            has_more_before,
            has_more_after,
        },
        read_state,
        pending_confirmation,
        anchor: outcome,
        anchors,
    })
}

fn slice(
    conn: &Connection,
    group: &str,
    key: Option<&OwnedTimelineOrderKey>,
    direction: CursorDirection,
    limit: usize,
) -> StorageResult<(Vec<TimelineMessageRecord>, bool)> {
    let query = TimelineMessageQuery {
        group_id_hex: Some(group.to_owned()),
        ..Default::default()
    };
    let pagination = ValidatedPagination {
        direction,
        cursor_at: None,
        cursor_message_id_hex: None,
        cursor_order: key.cloned(),
        inclusive: true,
        limit,
    };
    let rows = select_timeline_rows_tx(conn, &query, &pagination, true)?;
    let more = rows.len() > limit;
    let mut rows = rows.into_iter().take(limit).collect::<Vec<_>>();
    if direction != CursorDirection::After {
        rows.reverse();
    }
    Ok((rows, more))
}

fn neighbor_key(
    conn: &Connection,
    group: &str,
    key: &OwnedTimelineOrderKey,
    next: bool,
) -> StorageResult<Option<OwnedTimelineOrderKey>> {
    let op = if next { ">" } else { "<" };
    let order = if next {
        TIMELINE_GROUP_ORDER_BY_ASC
    } else {
        TIMELINE_GROUP_ORDER_BY_DESC
    };
    let sql = format!("SELECT timeline_order_class, timeline_order_primary, timeline_order_phase, timeline_order_at, message_id_hex
        FROM message_timeline AS timeline WHERE group_id_hex = ? AND
        (timeline_order_class, timeline_order_primary, timeline_order_phase, timeline_order_at, message_id_hex) {op} (?, ?, ?, ?, ?)
        {order} LIMIT 1");
    let mut values = vec![rusqlite::types::Value::Text(group.to_owned())];
    values.extend(canonical_cursor_params(key.0, key.1, key.2, key.3, &key.4)?);
    let key = conn
        .query_row_cached(&sql, params_from_iter(values), |row| {
            Ok((
                row.get::<_, u8>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, u8>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .optional()
        .storage()?;
    key.map(|(class, primary, phase, at, id)| {
        Ok((class, i64_to_u64(primary)?, phase, i64_to_u64(at)?, id))
    })
    .transpose()
}

#[cfg(test)]
mod tests;
