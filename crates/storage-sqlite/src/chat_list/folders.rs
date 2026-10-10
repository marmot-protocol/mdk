//! Complete, account-local existing-folder matching, independent of display rows.
//! Includes bounded smart expressions, not time-dependent filtered live windows.
use super::selection::ChatListSelectionError;
use crate::connection::CachedSql;
use crate::{SqliteAccountStorage, SqliteResultExt, deserialize};
use cgka_traits::group::Group;
use cgka_traits::storage::StorageResult;
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
mod smart;

// Unicode White_Space, matching Rust str::trim and native conversation_kind.
const WHITE_SPACE: &str = "\u{0009}\u{000a}\u{000b}\u{000c}\u{000d}\u{0020}\u{0085}\u{00a0}\u{1680}\u{2000}\u{2001}\u{2002}\u{2003}\u{2004}\u{2005}\u{2006}\u{2007}\u{2008}\u{2009}\u{200a}\u{2028}\u{2029}\u{202f}\u{205f}\u{3000}";

/// Version 1 mirrors the existing Android folder rule. Members and keyword are
/// ORed, then category/archive/mute constraints are ANDed. A smart envelope, if
/// present, replaces flat automatic criteria. An empty automatic
/// rule matches nothing. Manual includes bypass automatic rules; exclusions win.
/// Missing/blocked/departed conversations are never resurrected by manual IDs.
/// Rules and names remain private client preferences. Edits require recapture.
#[derive(Clone, PartialEq, Eq)]
pub struct ChatFolderSelectionRule {
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
impl std::fmt::Debug for ChatFolderSelectionRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatFolderSelectionRule")
            .field("version", &self.version)
            .field("member_count", &self.include_member_ids.len())
            .field("has_keyword", &self.keyword.is_some())
            .finish_non_exhaustive()
    }
}
impl Default for ChatFolderSelectionRule {
    fn default() -> Self {
        Self {
            version: 1,
            include_member_ids: Vec::new(),
            keyword: None,
            unread_only: false,
            unread_mentions_only: false,
            groups_only: false,
            direct_chats_only: false,
            pinned_only: false,
            include_all: false,
            archived_only: false,
            include_muted: false,
            smart_filter_json: None,
            manual_include_ids: Vec::new(),
            manual_exclude_ids: Vec::new(),
        }
    }
}

/// Unicode default lowercase, without locale, compatibility/diacritic folding
/// or regex. Rust's whole-string lowercase preserves contextual final sigma.
pub(crate) fn fold_literal(value: &str) -> String {
    value.to_lowercase()
}

impl ChatFolderSelectionRule {
    pub fn validate(&self) -> Result<(), ChatListSelectionError> {
        let valid_ids = |ids: &[String], members: bool| {
            ids.len() <= (if members { 256 } else { 1024 })
                && ids.iter().all(|id| {
                    !id.is_empty()
                        && id.len().is_multiple_of(2)
                        && (if members {
                            id.len() == 64
                        } else {
                            id.len() <= 512
                        })
                        && id.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
        };
        if self.version != 1
            || self.keyword.as_ref().is_some_and(|text| text.len() > 1024)
            || !valid_ids(&self.include_member_ids, true)
            || !valid_ids(&self.manual_include_ids, false)
            || !valid_ids(&self.manual_exclude_ids, false)
        {
            return Err(ChatListSelectionError::InvalidFilter);
        }
        if let Some(raw) = &self.smart_filter_json {
            smart::compile(raw)?;
        }
        Ok(())
    }

    /// Literal selected-title inputs need the shared-directory catch-up fence.
    pub fn requires_text(&self) -> Result<bool, ChatListSelectionError> {
        self.validate()?;
        Ok(match &self.smart_filter_json {
            Some(raw) => smart::compile(raw)?.title,
            None => self
                .keyword
                .as_deref()
                .is_some_and(|s| !s.trim().is_empty()),
        })
    }

    pub(super) fn eligible_ids(
        &self,
        conn: &Connection,
    ) -> Result<Vec<String>, ChatListSelectionError> {
        self.validate()?;
        let smart = self
            .smart_filter_json
            .as_deref()
            .map(smart::compile)
            .transpose()?;
        let ids_json = |ids: &[String]| {
            // Bound JSON arrays keep the SQL variable count independent of ID count.
            serde_json::to_string(
                &ids.iter()
                    .map(|id| id.to_ascii_lowercase())
                    .collect::<BTreeSet<_>>(),
            )
            .expect("strings serialize")
        };
        let members = ids_json(&self.include_member_ids);
        let includes = ids_json(&self.manual_include_ids);
        let excludes = ids_json(&self.manual_exclude_ids);
        let keyword = self
            .keyword
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(fold_literal);
        let has_members = !self.include_member_ids.is_empty();
        let has_keyword = keyword.is_some();
        let needs_roster = smart.as_ref().map_or(has_members, |s| s.roster);
        let needs_text = smart.as_ref().map_or(has_keyword, |s| s.title);
        let needs_kind = smart
            .as_ref()
            .map_or(self.groups_only || self.direct_chats_only, |s| s.kind);
        // Check required sources before selecting ANY ids, including negative
        // membership tests. A partial roster/title must not authorize a partial
        // destructive selection. Manual-only candidates need neither input.
        let candidates = "list_scope IN (0,1)
            AND group_id_hex NOT IN (SELECT group_id_hex FROM blocked_pending_invites)
            AND group_id_hex NOT IN (SELECT value FROM json_each(?1))";
        let needs_inputs = format!(
            "{candidates}
            AND group_id_hex NOT IN (SELECT value FROM json_each(?2))
            AND (?8 OR archived=?3)"
        );
        let missing: bool = conn.query_row_cached(
            &format!("SELECT EXISTS(SELECT 1 FROM chat_list_rows r WHERE {needs_inputs} AND (
                (?4 AND NOT EXISTS(SELECT 1 FROM chat_folder_rosters roster
                    WHERE roster.group_id_hex=r.group_id_hex AND roster.complete=1
                    AND NOT EXISTS(SELECT 1 FROM chat_folder_roster_work work WHERE work.group_id=roster.group_id)))
                OR (?5 AND (folder_title_fold IS NULL OR folder_description_fold IS NULL
                    OR presentation_json IS NULL
                    OR presentation_applied_source_revision!=presentation_source_revision))
                OR (?6 AND trim(group_name,?7)='' AND (SELECT member_count FROM account_groups a
                    WHERE a.group_id_hex=r.group_id_hex) IS NULL)))"),
            params![excludes, includes, self.archived_only, needs_roster, needs_text, needs_kind, WHITE_SPACE, smart.is_some()],
            |row| row.get(0),
        ).storage()?;
        if missing {
            return Err(ChatListSelectionError::ProjectionNotReady);
        }
        let automatic = has_members
            || has_keyword
            || self.unread_only
            || self.unread_mentions_only
            || self.groups_only
            || self.direct_chats_only
            || self.pinned_only
            || self.include_all
            || self.archived_only;
        let automatic_sql = smart.as_ref().map(|s| s.sql.clone()).unwrap_or_else(||
            "?4 AND archived=?3 AND (NOT ?5 OR list_unread=1)
                    AND (NOT ?14 OR (list_unread=1 AND unread_mention_count>0))
                    AND (NOT ?15 OR (trim(group_name,?13)='' AND EXISTS(SELECT 1 FROM account_groups a
                        WHERE a.group_id_hex=r.group_id_hex AND a.member_count=2)))
                    AND (NOT ?16 OR list_pin_ordinal>=0)
                    AND (NOT ?6 OR trim(group_name,?13)!='' OR EXISTS(SELECT 1 FROM account_groups a
                        WHERE a.group_id_hex=r.group_id_hex AND a.member_count!=2))
                    AND (?7 OR NOT EXISTS(SELECT 1 FROM chat_notification_settings mute
                        WHERE mute.group_id_hex=r.group_id_hex
                        AND (mute.muted_until_ms IS NULL OR mute.muted_until_ms>?8)))
                    AND ((NOT ?9 AND NOT ?10)
                        OR (?9 AND EXISTS(SELECT 1 FROM chat_folder_rosters roster
                            JOIN chat_folder_members member ON member.group_id=roster.group_id
                            WHERE roster.group_id_hex=r.group_id_hex AND roster.complete=1
                            AND member.member_id_hex IN (SELECT value FROM json_each(?11))))
                        OR (?10 AND (instr(folder_title_fold,?12)>0 OR instr(folder_description_fold,?12)>0)))".into());
        let sql = format!(
            "SELECT group_id_hex FROM chat_list_rows r INDEXED BY idx_chat_list_page
            WHERE {candidates} AND (?16 IS NULL OR ?16 IS NOT NULL) AND (
                group_id_hex IN (SELECT value FROM json_each(?2)) OR ({automatic_sql}))
                ORDER BY {}",
            super::pages::KEY_COLUMNS
        );
        use rusqlite::types::Value;
        let mut values = vec![
            Value::Text(excludes),
            Value::Text(includes),
            Value::Integer(self.archived_only.into()),
            Value::Integer(automatic.into()),
            Value::Integer(self.unread_only.into()),
            Value::Integer(self.groups_only.into()),
            Value::Integer(self.include_muted.into()),
            Value::Integer(crate::unix_now_ms()),
            Value::Integer(has_members.into()),
            Value::Integer(has_keyword.into()),
            Value::Text(members),
            keyword.map_or(Value::Null, Value::Text),
            Value::Text(WHITE_SPACE.into()),
            Value::Integer(self.unread_mentions_only.into()),
            Value::Integer(self.direct_chats_only.into()),
            Value::Integer(self.pinned_only.into()),
        ];
        if let Some(smart) = smart {
            values.extend(smart.values);
        }
        let mut statement = conn.prepare_cached(&sql).storage()?;
        // rusqlite requires only referenced parameters. Smart compilation reserves
        // slots1..16 via a harmless true expression before using slots17+.
        Ok(statement
            .query_map(rusqlite::params_from_iter(values), |row| row.get(0))
            .storage()?
            .collect::<Result<_, _>>()
            .storage()?)
    }
}

pub(crate) fn replace_roster(conn: &Connection, group: &Group) -> StorageResult<()> {
    let members: BTreeSet<_> = group
        .members
        .iter()
        .filter(|member| member.id.as_slice().len() == 32)
        .map(|member| hex::encode(member.id.as_slice()))
        .collect();
    let complete = members.len() == group.members.len();
    let mut digest = Sha256::new();
    digest.update(b"marmot.chat-folder-roster.v1");
    for member in &members {
        digest.update(member.as_bytes());
    }
    let digest = digest.finalize().to_vec();
    let existing: Option<(Vec<u8>,bool,i64)> = conn.query_row_cached(
        "SELECT members_digest,complete,member_count FROM chat_folder_rosters WHERE group_id=?1",
        [group.id.as_slice()], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
    ).optional().storage()?;
    if existing == Some((digest.clone(), complete, group.members.len() as i64)) {
        conn.execute_cached(
            "DELETE FROM chat_folder_roster_work WHERE group_id=?1",
            [group.id.as_slice()],
        )
        .storage()?;
        return Ok(());
    }
    conn.execute_cached(
        "DELETE FROM chat_folder_rosters WHERE group_id=?1",
        [group.id.as_slice()],
    )
    .storage()?;
    conn.execute_cached("INSERT INTO chat_folder_rosters(group_id,group_id_hex,complete,member_count,members_digest) VALUES(?1,?2,?3,?4,?5)",
        params![group.id.as_slice(),hex::encode(group.id.as_slice()),complete,group.members.len() as i64,digest]).storage()?;
    for member in members {
        conn.execute_cached(
            "INSERT INTO chat_folder_members(group_id,member_id_hex) VALUES(?1,?2)",
            params![group.id.as_slice(), member],
        )
        .storage()?;
    }
    conn.execute_cached(
        "DELETE FROM chat_folder_roster_work WHERE group_id=?1",
        [group.id.as_slice()],
    )
    .storage()?;
    Ok(())
}

impl SqliteAccountStorage {
    /// One bounded local upgrade/import/rollback catch-up; never a history scan,
    /// network request or query-time roster fanout. Returns whether work remains.
    pub fn prepare_chat_folder_rosters(&self) -> StorageResult<bool> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let mut statement = conn
                .prepare_cached(
                    "SELECT g.record FROM chat_folder_roster_work work
                JOIN cgka_groups g ON g.id=work.group_id ORDER BY work.group_id LIMIT 50",
                )
                .storage()?;
            let records = statement
                .query_map([], |row| row.get::<_, Vec<u8>>(0))
                .storage()?
                .collect::<Result<Vec<_>, _>>()
                .storage()?;
            drop(statement);
            for record in records {
                replace_roster(&conn, &deserialize::<Group>(&record)?)?;
            }
            conn.query_row_cached(
                "SELECT EXISTS(SELECT 1 FROM chat_folder_roster_work)",
                [],
                |row| row.get(0),
            )
            .storage()
        })
    }
}

#[cfg(test)]
mod tests;
