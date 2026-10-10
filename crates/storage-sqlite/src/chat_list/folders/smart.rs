//! Strict private version-1 smart-folder envelope. Compile bounded validated
//! nodes into parameterized SQL; user text never becomes SQL syntax.
use super::{ChatListSelectionError, fold_literal};
use rusqlite::types::Value;
use serde::Deserialize;
use std::collections::BTreeSet;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u32,
    root: Node,
}
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
enum Node {
    Group {
        all: bool,
        not: bool,
        children: Vec<Node>,
    },
    Condition {
        field: Field,
        mode: Mode,
        values: Vec<String>,
        not: bool,
    },
}
#[derive(Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Field {
    Unread,
    Mentions,
    Participants,
    Draft,
    PendingSend,
    Muted,
    Archived,
    Accepted,
    Type,
    Title,
    Pinned,
}
#[derive(Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Mode {
    Present,
    None,
    AnyOf,
    AllOf,
    Excludes,
    Direct,
    Group,
    Contains,
}

#[derive(Default)]
pub(super) struct Compiled {
    pub sql: String,
    pub values: Vec<Value>,
    pub roster: bool,
    pub title: bool,
    pub kind: bool,
    nodes: usize,
}
pub(super) fn compile(raw: &str) -> Result<Compiled, ChatListSelectionError> {
    if raw.len() > 65536 {
        return Err(ChatListSelectionError::InvalidFilter);
    }
    // serde_json's own recursion bound prevents a deeply nested raw envelope
    // from overflowing the parser before the stricter semantic-depth check.
    let envelope: Envelope =
        serde_json::from_str(raw).map_err(|_| ChatListSelectionError::InvalidFilter)?;
    if envelope.version != 1 || !matches!(&envelope.root, Node::Group { .. }) {
        return Err(ChatListSelectionError::InvalidFilter);
    }
    let mut result = Compiled::default();
    result.sql = result.node(envelope.root, 0)?;
    Ok(result)
}
impl Compiled {
    fn bind(&mut self, text: String) -> String {
        self.values.push(Value::Text(text));
        format!("?{}", 16 + self.values.len())
    }
    fn node(&mut self, node: Node, depth: usize) -> Result<String, ChatListSelectionError> {
        self.nodes += 1;
        if depth > 4 || self.nodes > 64 {
            return Err(ChatListSelectionError::InvalidFilter);
        }
        let (sql, not) = match node {
            Node::Group { all, not, children } => {
                if children.len() > 64 || (depth > 0 && children.is_empty()) {
                    return Err(ChatListSelectionError::InvalidFilter);
                }
                // Root-empty is manual-only, even NOT(empty), matching the editor.
                if children.is_empty() {
                    return Ok("0".into());
                }
                let sql = children
                    .into_iter()
                    .map(|n| self.node(n, depth + 1))
                    .collect::<Result<Vec<_>, _>>()?
                    .join(if all { " AND " } else { " OR " });
                (sql, not)
            }
            Node::Condition {
                field,
                mode,
                values,
                not,
            } => {
                if values.len() > 64 || values.iter().collect::<BTreeSet<_>>().len() != values.len()
                {
                    return Err(ChatListSelectionError::InvalidFilter);
                }
                let sql = match field {
                    Field::Participants => {
                        if values.is_empty()
                            || !matches!(mode, Mode::AnyOf | Mode::AllOf | Mode::Excludes)
                            || values.iter().any(|v| {
                                v.len() != 64
                                    || !v
                                        .bytes()
                                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                            })
                        {
                            return Err(ChatListSelectionError::InvalidFilter);
                        }
                        self.roster = true;
                        let count = values.len();
                        let parameter =
                            self.bind(serde_json::to_string(&values).expect("strings serialize"));
                        let found = format!(
                            "SELECT count(*) FROM chat_folder_rosters roster JOIN chat_folder_members member ON member.group_id=roster.group_id WHERE roster.group_id_hex=r.group_id_hex AND member.member_id_hex IN (SELECT value FROM json_each({parameter}))"
                        );
                        match mode {
                            Mode::AnyOf => format!("({found})>0"),
                            Mode::AllOf => format!("({found})={count}"),
                            _ => format!("({found})=0"),
                        }
                    }
                    Field::Title => {
                        if !matches!(mode, Mode::Contains)
                            || values.len() != 1
                            || values[0].trim().is_empty()
                            || values[0].encode_utf16().count() > 256
                        {
                            return Err(ChatListSelectionError::InvalidFilter);
                        }
                        self.title = true;
                        let parameter = self.bind(fold_literal(&values[0]));
                        format!("instr(folder_title_fold,{parameter})>0")
                    }
                    Field::Type => {
                        if !values.is_empty() || !matches!(mode, Mode::Direct | Mode::Group) {
                            return Err(ChatListSelectionError::InvalidFilter);
                        }
                        self.kind = true;
                        let direct = "trim(group_name,?13)='' AND EXISTS(SELECT 1 FROM account_groups a WHERE a.group_id_hex=r.group_id_hex AND a.member_count=2)";
                        if matches!(mode, Mode::Direct) {
                            direct.into()
                        } else {
                            format!("NOT ({direct})")
                        }
                    }
                    field => {
                        if !values.is_empty() || !matches!(mode, Mode::Present | Mode::None) {
                            return Err(ChatListSelectionError::InvalidFilter);
                        }
                        let present=match field {
                            Field::Unread=>"list_unread=1".into(),
                            Field::Mentions=>"list_unread=1 AND unread_mention_count>0".into(),
                            Field::Pinned=>"list_pin_ordinal>=0".into(),
                            Field::Archived=>"list_scope=1".into(),
                            Field::Accepted=>"list_scope IN (0,1) AND NOT COALESCE((SELECT pending_confirmation FROM account_groups a WHERE a.group_id_hex=r.group_id_hex),pending_confirmation)".into(),
                            Field::Muted=>"EXISTS(SELECT 1 FROM chat_notification_settings mute WHERE mute.group_id_hex=r.group_id_hex AND (mute.muted_until_ms IS NULL OR mute.muted_until_ms>?8))".into(),
                            Field::Draft=>"EXISTS(SELECT 1 FROM message_drafts draft WHERE draft.group_id_hex=r.group_id_hex AND (length(CAST(trim(draft.content,?13) AS BLOB))>0 OR EXISTS(SELECT 1 FROM message_draft_attachments attachment WHERE attachment.group_id_hex=draft.group_id_hex)))".into(),
                            // Complete local pending intent, not just the latest preview.
                            Field::PendingSend=>"EXISTS(SELECT 1 FROM local_message_submissions submission WHERE submission.group_id_hex=r.group_id_hex AND submission.state=0) OR EXISTS(SELECT 1 FROM message_timeline pending INDEXED BY idx_chat_folder_pending_send WHERE pending.group_id_hex=r.group_id_hex AND pending.direction='sent' AND pending.source_message_id_hex IS NULL AND pending.invalidation_status IS NULL AND pending.deleted=0)".into(),
                            _=>unreachable!("handled structured conditions"),
                        };
                        if matches!(mode, Mode::None) {
                            format!("NOT ({present})")
                        } else {
                            present
                        }
                    }
                };
                (sql, not)
            }
        };
        Ok(if not {
            format!("NOT ({sql})")
        } else {
            format!("({sql})")
        })
    }
}
