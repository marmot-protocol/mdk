//! Agent events carried in Marmot app messages: an agent item (kind 1201) and
//! an answer or a control (kind 1202).
//!
//! The shape follows marmot-protocol/marmot-agents `docs/design/agent-kinds.md`
//! (decision D-076): the content is a plain rendering every client can show,
//! and everything else is in tags. A later version of an item is a kind-1009
//! edit that names the item's first event with its single `e` tag and carries
//! the whole item again with a higher `v`.
//!
//! MDK renames one tag of that design: the chat message that started a turn is
//! named by `started_by`, not `e`, so that an edit of the item, which carries
//! every tag of the item, still has exactly one `e` tag naming its target.
//!
//! An item in a subagent's thread (marmot-agents D-121) carries NIP-22's tags
//! as NIP-22 defines them: `E`/`K`/`P` name the thread root, the top-level
//! subagent's `task` item, and `e`/`k`/`p` the immediate parent. Only a first
//! event carries the parent's `e`. An edit carries no `e` but its target's and
//! may repeat `E`/`K`/`P`; MDK keeps an item in the thread its first event
//! names, since an item never moves.
//!
//! The parsers here are what MDK interprets: the version, state, title,
//! harness, item id, `seq`, the item type from `fields`, session, turn,
//! `started_by` and `settles` of an item; the agent, item and action of a
//! request. Every other tag (`native`, `left_out`, `cut` and later additions)
//! is carried unchanged and never read.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

/// An agent item: a turn, a tool call, an approval, a question, a plan, a
/// task, a notice, an error, reasoning or a session.
pub const MARMOT_APP_EVENT_KIND_AGENT_ITEM: u64 = 1201;
/// An answer or a control a person's app sends to an agent.
pub const MARMOT_APP_EVENT_KIND_AGENT_REQUEST: u64 = 1202;

/// The largest an agent item, an edit of one, or a request may be, as the
/// encoded inner app event (D-026). The agent core keeps every event it makes
/// within this, measured with an id, author and signature an inner event lacks.
pub const AGENT_EVENT_MAX_BYTES: usize = 64 * 1024;

/// The item's version, from 1. The highest version of an item wins.
pub const AGENT_ITEM_VERSION_TAG: &str = "v";
/// `running`, `waiting`, `done`, `failed`, `declined` or `cancelled`.
pub const AGENT_ITEM_STATE_TAG: &str = "state";
/// A few words: "Running a command".
pub const AGENT_ITEM_TITLE_TAG: &str = "title";
/// The harness's name.
pub const AGENT_ITEM_HARNESS_TAG: &str = "harness";
/// The harness's own id for the item.
pub const AGENT_ITEM_ID_TAG: &str = "item_id";
/// The event's place among its session's events, from 1.
pub const AGENT_ITEM_SEQ_TAG: &str = "seq";
/// The item type and its own fields, as JSON: `{"type": "tool", "body": {...}}`.
pub const AGENT_ITEM_FIELDS_TAG: &str = "fields";
/// The harness's session, when there is one.
pub const AGENT_ITEM_SESSION_TAG: &str = "session";
/// The turn the item belongs to, when there is one. The agent's words, a chat
/// message, carry it too (D-022).
pub const AGENT_TURN_TAG: &str = "turn";
/// On a turn: the chat message that started it. The design names it with an
/// `e` tag; MDK keeps `e` for an edit's target.
pub const AGENT_ITEM_STARTED_BY_TAG: &str = "started_by";
/// An answer or a control whose effect this version shows; one tag each.
pub const AGENT_ITEM_SETTLES_TAG: &str = "settles";
/// On a request: the agent it is for.
pub const AGENT_REQUEST_AGENT_TAG: &str = "p";
/// On a request: the first event of the item it acts on.
pub const AGENT_REQUEST_ITEM_TAG: &str = "e";
/// On a request: what it asks, as JSON with an `action`.
pub const AGENT_REQUEST_DETAILS_TAG: &str = "details";
/// On the agent's words: `["phase", "commentary"]` marks a remark made while
/// the agent works, which does not alert (D-078).
pub const AGENT_PHASE_TAG: &str = "phase";
pub const AGENT_PHASE_COMMENTARY: &str = "commentary";

/// Why an event is not a readable agent item or request. Names no value the
/// event holds.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum AgentEventError {
    #[error("agent event is missing its {0} tag")]
    Missing(&'static str),
    #[error("agent event repeats its {0} tag")]
    Repeated(&'static str),
    #[error("agent event has an invalid {0} tag")]
    Invalid(&'static str),
    #[error("an agent item names an `e` outside a thread; use started_by for the turn's message")]
    EventReference,
    #[error("agent event is larger than {AGENT_EVENT_MAX_BYTES} bytes")]
    TooLarge,
}

/// An item's state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentItemState {
    Running,
    Waiting,
    Done,
    Failed,
    Declined,
    Cancelled,
}

impl AgentItemState {
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "running" => Self::Running,
            "waiting" => Self::Waiting,
            "done" => Self::Done,
            "failed" => Self::Failed,
            "declined" => Self::Declined,
            "cancelled" => Self::Cancelled,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Waiting => "waiting",
            Self::Done => "done",
            Self::Failed => "failed",
            Self::Declined => "declined",
            Self::Cancelled => "cancelled",
        }
    }
}

/// What MDK reads of one version of an agent item.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentItem {
    pub version: u64,
    pub state: AgentItemState,
    pub title: String,
    pub harness: String,
    pub item_id: String,
    pub seq: u64,
    /// The `type` inside `fields`: `turn`, `tool`, `approval`, `question`, ...
    pub item_type: String,
    /// The `fields` tag as sent: the type and its own fields, as JSON.
    pub fields_json: String,
    pub session: Option<String>,
    pub turn: Option<String>,
    /// The chat message that started the turn.
    pub started_by_message_id_hex: Option<String>,
    /// The answers and controls whose effect this version shows, in tag order.
    pub settles: Vec<String>,
}

/// Names the type, state and version, and nothing the harness said.
impl std::fmt::Debug for AgentItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentItem")
            .field("version", &self.version)
            .field("state", &self.state)
            .field("item_type", &self.item_type)
            .field("settles", &self.settles.len())
            .finish_non_exhaustive()
    }
}

impl AgentItem {
    /// Read an agent item from its tags: an item's first event, or an edit of
    /// one (whose `e` tag names the target and is not read here).
    pub fn from_tags(tags: &[Vec<String>]) -> Result<Self, AgentEventError> {
        let one = |name: &'static str| single(tags, name)?.ok_or(AgentEventError::Missing(name));
        let version = positive(one(AGENT_ITEM_VERSION_TAG)?, AGENT_ITEM_VERSION_TAG)?;
        let state = AgentItemState::parse(one(AGENT_ITEM_STATE_TAG)?)
            .ok_or(AgentEventError::Invalid(AGENT_ITEM_STATE_TAG))?;
        let title = one(AGENT_ITEM_TITLE_TAG)?.to_owned();
        let harness = non_empty(one(AGENT_ITEM_HARNESS_TAG)?, AGENT_ITEM_HARNESS_TAG)?;
        let item_id = non_empty(one(AGENT_ITEM_ID_TAG)?, AGENT_ITEM_ID_TAG)?;
        let seq = positive(one(AGENT_ITEM_SEQ_TAG)?, AGENT_ITEM_SEQ_TAG)?;
        let fields_json = one(AGENT_ITEM_FIELDS_TAG)?;
        let item_type = json_object_string(fields_json, "type")
            .ok_or(AgentEventError::Invalid(AGENT_ITEM_FIELDS_TAG))?;
        let started_by_message_id_hex = single(tags, AGENT_ITEM_STARTED_BY_TAG)?
            .map(|id| event_id(id, AGENT_ITEM_STARTED_BY_TAG))
            .transpose()?;
        let settles = values(tags, AGENT_ITEM_SETTLES_TAG)
            .map(|id| event_id(id, AGENT_ITEM_SETTLES_TAG))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            version,
            state,
            title,
            harness,
            item_id,
            seq,
            item_type,
            fields_json: fields_json.to_owned(),
            session: single(tags, AGENT_ITEM_SESSION_TAG)?.map(str::to_owned),
            turn: single(tags, AGENT_TURN_TAG)?.map(str::to_owned),
            started_by_message_id_hex,
            settles,
        })
    }

    /// Whether this version alerts people (D-024): an approval or a question
    /// while it is waiting, or a turn that ended failed. Nothing else does.
    pub fn alerts(&self) -> bool {
        matches!(
            (self.item_type.as_str(), self.state),
            ("approval" | "question", AgentItemState::Waiting) | ("turn", AgentItemState::Failed)
        )
    }
}

/// What MDK reads of an answer or a control.
#[derive(Clone, PartialEq, Eq)]
pub struct AgentRequest {
    /// The agent it is for.
    pub agent_pubkey_hex: String,
    /// The first event of the item it acts on, when it names one.
    pub item_message_id_hex: Option<String>,
    /// The `action` inside `details`: `choice`, `questions`, `interrupt`,
    /// `new_session`, `set` or `own`.
    pub action: String,
    /// The `details` tag as sent.
    pub details_json: String,
}

/// Names the action, and nothing it asks.
impl std::fmt::Debug for AgentRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentRequest")
            .field("action", &self.action)
            .field("names_item", &self.item_message_id_hex.is_some())
            .finish_non_exhaustive()
    }
}

impl AgentRequest {
    pub fn from_tags(tags: &[Vec<String>]) -> Result<Self, AgentEventError> {
        let agent = single(tags, AGENT_REQUEST_AGENT_TAG)?
            .ok_or(AgentEventError::Missing(AGENT_REQUEST_AGENT_TAG))?;
        let agent_pubkey_hex = event_id(agent, AGENT_REQUEST_AGENT_TAG)?;
        let item_message_id_hex = single(tags, AGENT_REQUEST_ITEM_TAG)?
            .map(|id| event_id(id, AGENT_REQUEST_ITEM_TAG))
            .transpose()?;
        let details_json = single(tags, AGENT_REQUEST_DETAILS_TAG)?
            .ok_or(AgentEventError::Missing(AGENT_REQUEST_DETAILS_TAG))?;
        let action = json_object_string(details_json, "action")
            .ok_or(AgentEventError::Invalid(AGENT_REQUEST_DETAILS_TAG))?;
        Ok(Self {
            agent_pubkey_hex,
            item_message_id_hex,
            action,
            details_json: details_json.to_owned(),
        })
    }
}

/// The version an edit of an agent item carries, when it is a readable item.
pub fn agent_item_version(tags: &[Vec<String>]) -> Option<u64> {
    AgentItem::from_tags(tags).ok().map(|item| item.version)
}

/// The `seq` an item's first event gives its row, or 0 for any other event.
/// A turn's rows are ordered by it within one second (D-059).
pub fn agent_item_order_seq(kind: u64, tags: &[Vec<String>]) -> u64 {
    if kind != MARMOT_APP_EVENT_KIND_AGENT_ITEM {
        return 0;
    }
    AgentItem::from_tags(tags).map_or(0, |item| item.seq)
}

/// Whether a chat message is the agent's remark during a turn, which does not
/// alert (D-078).
pub fn is_agent_commentary(tags: &[Vec<String>]) -> bool {
    tags.iter().any(|tag| {
        tag.first().is_some_and(|name| name == AGENT_PHASE_TAG)
            && tag
                .get(1)
                .is_some_and(|phase| phase == AGENT_PHASE_COMMENTARY)
    })
}

/// On an item in a thread: the thread root, the top-level subagent's `task`
/// item (NIP-22's `E`).
pub const AGENT_ITEM_THREAD_ROOT_TAG: &str = "E";

/// The parent of an agent item in a thread: the item its `e` tag names, or
/// else the thread root its `E` names. `None` for an item outside a thread.
pub fn agent_item_thread_parent(tags: &[Vec<String>]) -> Option<&str> {
    let root = crate::thread_root_tag(tags)?;
    Some(values(tags, AGENT_REQUEST_ITEM_TAG).next().unwrap_or(root))
}

/// What a client without a thread view quotes above an agent item: the chat
/// message that started its turn, else the parent of an item in a thread. An
/// unreadable item names nothing.
pub fn agent_item_reply_target(tags: &[Vec<String>]) -> Option<String> {
    let item = AgentItem::from_tags(tags).ok()?;
    item.started_by_message_id_hex
        .or_else(|| agent_item_thread_parent(tags).map(str::to_owned))
}

/// Check an agent item's first event a program sends: readable, with at most
/// one thread root `E` naming an event, and with an `e` tag only as the parent
/// of an item in a thread, once, beside that `E`. Any other `e` would read as
/// an edit's target, which is MDK's to place.
pub fn validate_agent_item_tags(tags: &[Vec<String>]) -> Result<AgentItem, AgentEventError> {
    let root = single(tags, AGENT_ITEM_THREAD_ROOT_TAG)?
        .map(|root| event_id(root, AGENT_ITEM_THREAD_ROOT_TAG))
        .transpose()?;
    if let Some(parent) = single(tags, AGENT_REQUEST_ITEM_TAG)? {
        if root.is_none() {
            return Err(AgentEventError::EventReference);
        }
        event_id(parent, AGENT_REQUEST_ITEM_TAG)?;
    }
    AgentItem::from_tags(tags)
}

/// Check the item an edit carries: readable, with no `e` tag, since the edit's
/// own `e` names its target. It may repeat its first event's `E`/`K`/`P`.
pub fn validate_agent_item_edit_tags(tags: &[Vec<String>]) -> Result<AgentItem, AgentEventError> {
    if values(tags, AGENT_REQUEST_ITEM_TAG).next().is_some() {
        return Err(AgentEventError::EventReference);
    }
    AgentItem::from_tags(tags)
}

/// Whether a thread message is an agent's own words in a thread whose root is
/// one of its agent items: a comment naming its root with `E`, whose `K` is
/// 1201 and whose `P` is its author. It does not alert or wake anyone (marmot-agents D-122). Read from
/// the comment's own tags, so it also holds where the root is not stored, and
/// a sender can only silence its own message with it.
pub fn is_agent_own_thread_comment(kind: u64, tags: &[Vec<String>], sender_hex: &str) -> bool {
    let value = |name: &'static str| values(tags, name).next();
    crate::thread_message_parent(kind, tags).is_some()
        && crate::thread_root_tag(tags).is_some()
        && value("K").and_then(|kind| kind.parse().ok()) == Some(MARMOT_APP_EVENT_KIND_AGENT_ITEM)
        && value("P").is_some_and(|author| author.eq_ignore_ascii_case(sender_hex))
}

fn values<'a>(tags: &'a [Vec<String>], name: &'a str) -> impl Iterator<Item = &'a str> {
    tags.iter()
        .filter(move |tag| tag.first().is_some_and(|tag_name| tag_name == name))
        .map(|tag| tag.get(1).map_or("", String::as_str))
}

fn single<'a>(
    tags: &'a [Vec<String>],
    name: &'static str,
) -> Result<Option<&'a str>, AgentEventError> {
    let mut found = values(tags, name);
    let first = found.next();
    if found.next().is_some() {
        return Err(AgentEventError::Repeated(name));
    }
    Ok(first)
}

fn positive(value: &str, name: &'static str) -> Result<u64, AgentEventError> {
    // Plain decimal only: no sign, no leading zeros, so one version has one
    // spelling. At most `i64::MAX`, the largest number SQLite stores.
    let canonical = !value.is_empty()
        && value.bytes().all(|b| b.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'));
    match value.parse::<u64>() {
        Ok(number) if canonical && number > 0 && i64::try_from(number).is_ok() => Ok(number),
        _ => Err(AgentEventError::Invalid(name)),
    }
}

fn non_empty(value: &str, name: &'static str) -> Result<String, AgentEventError> {
    if value.is_empty() {
        return Err(AgentEventError::Invalid(name));
    }
    Ok(value.to_owned())
}

fn event_id(value: &str, name: &'static str) -> Result<String, AgentEventError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(value.to_owned())
    } else {
        Err(AgentEventError::Invalid(name))
    }
}

fn json_object_string(json: &str, key: &str) -> Option<String> {
    let value: Value = serde_json::from_str(json).ok()?;
    value
        .as_object()?
        .get(key)?
        .as_str()
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tag(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| (*part).to_owned()).collect()
    }

    fn id(byte: char) -> String {
        byte.to_string().repeat(64)
    }

    fn item_tags(item_type: &str, state: &str) -> Vec<Vec<String>> {
        vec![
            tag(&["v", "3"]),
            tag(&["state", state]),
            tag(&["title", "Allow this command?"]),
            tag(&["harness", "codex"]),
            tag(&["item_id", "call-1"]),
            tag(&["seq", "7"]),
            tag(&[
                "fields",
                &format!(r#"{{"type":"{item_type}","body":{{"command":"ls"}}}}"#),
            ]),
            tag(&["session", "s-1"]),
            tag(&["turn", "t-1"]),
            tag(&["started_by", &id('a')]),
            tag(&["settles", &id('b')]),
            tag(&["settles", &id('c')]),
            tag(&["native", "item/started", r#"{"id":"call-1"}"#]),
            tag(&["left_out", "native", "70000"]),
            tag(&["cut", "output", "90000"]),
        ]
    }

    #[test]
    fn an_item_reads_every_tag_it_interprets() {
        let item = AgentItem::from_tags(&item_tags("approval", "waiting")).unwrap();
        assert_eq!(item.version, 3);
        assert_eq!(item.state, AgentItemState::Waiting);
        assert_eq!(item.title, "Allow this command?");
        assert_eq!(item.harness, "codex");
        assert_eq!(item.item_id, "call-1");
        assert_eq!(item.seq, 7);
        assert_eq!(item.item_type, "approval");
        assert_eq!(
            item.fields_json,
            r#"{"type":"approval","body":{"command":"ls"}}"#
        );
        assert_eq!(item.session.as_deref(), Some("s-1"));
        assert_eq!(item.turn.as_deref(), Some("t-1"));
        assert_eq!(item.started_by_message_id_hex, Some(id('a')));
        assert_eq!(item.settles, [id('b'), id('c')]);
    }

    #[test]
    fn an_item_without_its_optional_tags_is_readable() {
        let tags: Vec<_> = item_tags("tool", "running").into_iter().take(7).collect();
        let item = AgentItem::from_tags(&tags).unwrap();
        assert_eq!((item.session, item.turn), (None, None));
        assert_eq!(item.started_by_message_id_hex, None);
        assert!(item.settles.is_empty());
    }

    #[test]
    fn an_item_is_unreadable_without_a_required_tag_or_with_a_bad_one() {
        for missing in ["v", "state", "title", "harness", "item_id", "seq", "fields"] {
            let tags: Vec<_> = item_tags("tool", "done")
                .into_iter()
                .filter(|t| t[0] != missing)
                .collect();
            assert_eq!(
                AgentItem::from_tags(&tags),
                Err(AgentEventError::Missing(match missing {
                    "v" => AGENT_ITEM_VERSION_TAG,
                    "state" => AGENT_ITEM_STATE_TAG,
                    "title" => AGENT_ITEM_TITLE_TAG,
                    "harness" => AGENT_ITEM_HARNESS_TAG,
                    "item_id" => AGENT_ITEM_ID_TAG,
                    "seq" => AGENT_ITEM_SEQ_TAG,
                    _ => AGENT_ITEM_FIELDS_TAG,
                })),
                "{missing}"
            );
        }
        for (name, value) in [
            ("v", "0"),
            ("v", "01"),
            ("v", "+1"),
            ("seq", "x"),
            // Past what SQLite stores, where a row's seq is kept.
            ("seq", "9223372036854775808"),
            ("state", "paused"),
            ("fields", "[]"),
            ("fields", r#"{"body":{}}"#),
            ("started_by", "not-an-id"),
            ("settles", &id('A')),
        ] {
            let mut tags = item_tags("tool", "done");
            tags.retain(|t| t[0] != name);
            tags.push(tag(&[name, value]));
            assert!(AgentItem::from_tags(&tags).is_err(), "{name}={value}");
        }
        let mut largest = item_tags("tool", "done");
        largest.retain(|t| t[0] != "seq");
        largest.push(tag(&["seq", &i64::MAX.to_string()]));
        assert_eq!(
            AgentItem::from_tags(&largest).map(|item| item.seq),
            Ok(i64::MAX as u64)
        );
        let mut repeated = item_tags("tool", "done");
        repeated.push(tag(&["v", "4"]));
        assert_eq!(
            AgentItem::from_tags(&repeated),
            Err(AgentEventError::Repeated("v"))
        );
    }

    #[test]
    fn the_old_shape_is_unreadable() {
        // What today's connectors send under kind 1201 (D-051).
        let old = [tag(&["status", "error"]), tag(&["e", &id('a')])];
        assert_eq!(
            AgentItem::from_tags(&old),
            Err(AgentEventError::Missing("v"))
        );
        assert_eq!(
            agent_item_order_seq(MARMOT_APP_EVENT_KIND_AGENT_ITEM, &old),
            0
        );
    }

    fn thread_tags(root: char, parent: char) -> Vec<Vec<String>> {
        let agent = id('9');
        vec![
            tag(&["E", &id(root), "", &agent]),
            tag(&["K", "1201"]),
            tag(&["P", &agent]),
            tag(&["e", &id(parent), "", &agent]),
            tag(&["k", "1201"]),
            tag(&["p", &agent]),
        ]
    }

    #[test]
    fn a_program_cannot_name_an_edit_target_on_an_item() {
        let mut tags = item_tags("turn", "running");
        tags.push(tag(&["e", &id('d')]));
        assert_eq!(
            validate_agent_item_tags(&tags),
            Err(AgentEventError::EventReference)
        );
        assert_eq!(
            validate_agent_item_edit_tags(&tags),
            Err(AgentEventError::EventReference)
        );
    }

    #[test]
    fn an_item_in_a_thread_names_its_parent_with_e_on_its_first_event_only() {
        let mut first = item_tags("tool", "running");
        first.retain(|tag| tag[0] != "started_by");
        first.extend(thread_tags('d', 'f'));
        assert!(validate_agent_item_tags(&first).is_ok());
        assert_eq!(agent_item_thread_parent(&first), Some(id('f').as_str()));
        assert_eq!(agent_item_reply_target(&first), Some(id('f')));
        // A turn's starting message stays what it quotes.
        let mut turn = item_tags("turn", "running");
        turn.extend(thread_tags('d', 'f'));
        assert_eq!(agent_item_reply_target(&turn), Some(id('a')));

        let mut twice = first.clone();
        twice.push(tag(&["e", &id('1')]));
        assert_eq!(
            validate_agent_item_tags(&twice),
            Err(AgentEventError::Repeated("e"))
        );
        // The root must name an event too, with or without a parent.
        for bad_root in [
            vec![tag(&["E", ""])],
            vec![tag(&["E", "root"]), tag(&["e", &id('f')])],
        ] {
            let mut tags = item_tags("tool", "running");
            tags.extend(bad_root);
            assert_eq!(
                validate_agent_item_tags(&tags),
                Err(AgentEventError::Invalid("E"))
            );
        }
        // An item with a root and no parent answers the root.
        let mut root_only = item_tags("tool", "running");
        root_only.retain(|tag| tag[0] != "started_by");
        root_only.push(tag(&["E", &id('d')]));
        assert!(validate_agent_item_tags(&root_only).is_ok());
        assert_eq!(agent_item_reply_target(&root_only), Some(id('d')));
        let mut bad_parent = item_tags("tool", "running");
        bad_parent.extend(thread_tags('d', 'f'));
        bad_parent.retain(|tag| tag[0] != "e");
        bad_parent.push(tag(&["e", "not-an-id"]));
        assert_eq!(
            validate_agent_item_tags(&bad_parent),
            Err(AgentEventError::Invalid("e"))
        );

        // An edit names its target with `e`, so it carries the root alone.
        let mut edit = item_tags("tool", "done");
        edit.extend(thread_tags('d', 'f').into_iter().take(3));
        assert!(validate_agent_item_edit_tags(&edit).is_ok());
        assert!(validate_agent_item_edit_tags(&first).is_err());
    }

    #[test]
    fn only_an_agents_comment_under_its_own_item_is_its_own_thread_comment() {
        let agent = id('9');
        let comment = |root_kind: &str, root_author: &str| {
            vec![
                tag(&["E", &id('d'), "", root_author]),
                tag(&["K", root_kind]),
                tag(&["P", root_author]),
                tag(&["e", &id('d'), "", root_author]),
                tag(&["k", root_kind]),
            ]
        };
        assert!(is_agent_own_thread_comment(
            1111,
            &comment("1201", &agent),
            &agent
        ));
        assert!(is_agent_own_thread_comment(
            1111,
            &comment("1201", &agent.to_uppercase()),
            &agent
        ));
        // A person's comment in the agent's thread, a comment under a chat
        // message, and a chat message joining the thread all alert.
        assert!(!is_agent_own_thread_comment(
            1111,
            &comment("1201", &agent),
            &id('8')
        ));
        assert!(!is_agent_own_thread_comment(
            1111,
            &comment("9", &agent),
            &agent
        ));
        assert!(!is_agent_own_thread_comment(
            9,
            &comment("1201", &agent),
            &agent
        ));
        // Without `E` the root is found by walking parents, and may be chat.
        let mut rootless = comment("1201", &agent);
        rootless.remove(0);
        assert!(!is_agent_own_thread_comment(1111, &rootless, &agent));
    }

    #[test]
    fn only_waiting_approvals_and_questions_and_failed_turns_alert() {
        let types = [
            "turn",
            "message",
            "reasoning",
            "tool",
            "approval",
            "question",
            "plan",
            "task",
            "notice",
            "error",
            "session",
        ];
        let states = [
            "running",
            "waiting",
            "done",
            "failed",
            "declined",
            "cancelled",
        ];
        for item_type in types {
            for state in states {
                let item = AgentItem::from_tags(&item_tags(item_type, state)).unwrap();
                let expected = matches!(
                    (item_type, state),
                    ("approval" | "question", "waiting") | ("turn", "failed")
                );
                assert_eq!(item.alerts(), expected, "{item_type} {state}");
            }
        }
    }

    #[test]
    fn a_request_reads_its_agent_item_and_action() {
        for (details, action) in [
            (r#"{"action":"choice","choice":"allow_once"}"#, "choice"),
            (
                r#"{"action":"questions","questions":[{"question":"q1","options":["o1"],"text":"x"}]}"#,
                "questions",
            ),
            (r#"{"action":"interrupt"}"#, "interrupt"),
            (r#"{"action":"new_session"}"#, "new_session"),
            (r#"{"action":"set","setting":"model","value":"o3"}"#, "set"),
            (r#"{"action":"own","id":"compact"}"#, "own"),
        ] {
            let tags = vec![
                tag(&["p", &id('1')]),
                tag(&["e", &id('2')]),
                tag(&["details", details]),
            ];
            let request = AgentRequest::from_tags(&tags).unwrap();
            assert_eq!(request.agent_pubkey_hex, id('1'));
            assert_eq!(request.item_message_id_hex, Some(id('2')));
            assert_eq!(request.action, action);
            assert_eq!(request.details_json, details);
        }
        let no_item = [
            tag(&["p", &id('1')]),
            tag(&["details", r#"{"action":"interrupt"}"#]),
        ];
        assert_eq!(
            AgentRequest::from_tags(&no_item)
                .unwrap()
                .item_message_id_hex,
            None
        );
    }

    #[test]
    fn a_request_needs_one_agent_and_details_with_an_action() {
        let details = tag(&["details", r#"{"action":"interrupt"}"#]);
        assert!(AgentRequest::from_tags(std::slice::from_ref(&details)).is_err());
        assert!(
            AgentRequest::from_tags(&[tag(&["p", &id('1')]), tag(&["p", &id('2')]), details])
                .is_err()
        );
        assert!(
            AgentRequest::from_tags(&[
                tag(&["p", &id('1')]),
                tag(&["details", r#"{"choice":"x"}"#])
            ])
            .is_err()
        );
        // The old shape of kind 1202.
        assert!(
            AgentRequest::from_tags(&[
                tag(&["operation", "tool"]),
                tag(&["operation-status", "done"])
            ])
            .is_err()
        );
    }

    #[test]
    fn commentary_is_the_phase_tag() {
        assert!(is_agent_commentary(&[
            tag(&["turn", "t"]),
            tag(&["phase", "commentary"])
        ]));
        assert!(!is_agent_commentary(&[tag(&["phase", "final"])]));
        assert!(!is_agent_commentary(&[tag(&["phase"])]));
    }
}
