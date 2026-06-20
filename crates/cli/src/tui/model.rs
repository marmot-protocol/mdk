//! TUI data model: row/view/state types, JSON parsers, and pure helpers.

use super::*;
use unicode_properties::{GeneralCategory, UnicodeGeneralCategory};

#[derive(Debug, thiserror::Error)]
pub(crate) enum TuiError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Cli(String),
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct DmInvocation {
    pub(crate) args: Vec<String>,
    pub(crate) stdin: Option<String>,
}

pub(crate) fn account_setup_invocation(identity: Option<String>) -> DmInvocation {
    match identity {
        Some(identity) if crate::is_nostr_secret(&identity) => DmInvocation {
            args: vec!["login".to_owned(), "--nsec-stdin".to_owned()],
            stdin: Some(format!("{identity}\n")),
        },
        Some(identity) => DmInvocation {
            args: vec!["login".to_owned(), identity],
            stdin: None,
        },
        None => DmInvocation {
            args: vec!["create-identity".to_owned()],
            stdin: None,
        },
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AccountRow {
    pub(crate) account_id: String,
    pub(crate) npub: String,
    pub(crate) display_name: Option<String>,
    pub(crate) local_signing: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ChatRow {
    pub(crate) group_id: String,
    pub(crate) name: String,
    pub(crate) archived: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MessageRow {
    pub(crate) message_id: String,
    pub(crate) direction: String,
    pub(crate) from: String,
    pub(crate) from_display_name: Option<String>,
    pub(crate) plaintext: String,
    pub(crate) display_text: String,
    pub(crate) recorded_at: u64,
    pub(crate) received_at: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct DaemonView {
    pub(crate) running: bool,
    pub(crate) pid: Option<u64>,
    pub(crate) last_runtime_activity: Option<DaemonRuntimeActivityView>,
    pub(crate) stream_watches: Vec<DaemonStreamWatchView>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DaemonRuntimeActivityView {
    pub(crate) accounts: u64,
    pub(crate) events: u64,
    pub(crate) joined_groups: u64,
    pub(crate) messages: u64,
    pub(crate) errors: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DaemonStreamWatchView {
    pub(crate) watch_id: String,
    pub(crate) group_id: String,
    pub(crate) stream_id: Option<String>,
    pub(crate) status: String,
    pub(crate) text: Option<String>,
    pub(crate) transcript_hash: Option<String>,
    pub(crate) chunk_count: Option<u64>,
    pub(crate) error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LiveStreamPreview {
    pub(crate) group_id: String,
    pub(crate) stream_id: String,
    pub(crate) author: String,
    pub(crate) status: String,
    pub(crate) text: String,
    pub(crate) error: Option<String>,
    pub(crate) optimistic: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GroupDiagnostics {
    pub(crate) group_id: String,
    pub(crate) epoch: Option<u64>,
    pub(crate) member_count: Option<u64>,
    pub(crate) components: Vec<GroupComponentDiagnostics>,
    pub(crate) error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GroupComponentDiagnostics {
    pub(crate) component: String,
    pub(crate) component_id: Option<u64>,
    pub(crate) data_hex: String,
}

#[derive(Debug)]
pub(crate) enum SubscriptionEvent {
    Result(Value),
    Error(String),
    Ended,
}

pub(crate) struct MessageSubscription {
    pub(crate) account_id: String,
    pub(crate) child: Child,
    pub(crate) rx: Receiver<SubscriptionEvent>,
}

impl Drop for MessageSubscription {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub(crate) struct ChatSubscription {
    pub(crate) account_id: String,
    pub(crate) include_archived: bool,
    pub(crate) child: Child,
    pub(crate) rx: Receiver<SubscriptionEvent>,
}

impl Drop for ChatSubscription {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub(crate) struct GroupStateSubscription {
    pub(crate) account_id: String,
    pub(crate) group_id: String,
    pub(crate) child: Child,
    pub(crate) rx: Receiver<SubscriptionEvent>,
}

impl Drop for GroupStateSubscription {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Focus {
    Accounts,
    Chats,
    Messages,
    Composer,
}

impl Focus {
    pub(crate) fn next(self) -> Self {
        match self {
            Self::Accounts => Self::Chats,
            Self::Chats => Self::Messages,
            Self::Messages => Self::Composer,
            Self::Composer => Self::Accounts,
        }
    }

    pub(crate) fn previous(self) -> Self {
        match self {
            Self::Accounts => Self::Composer,
            Self::Chats => Self::Accounts,
            Self::Messages => Self::Chats,
            Self::Composer => Self::Messages,
        }
    }

    pub(crate) fn title(self) -> &'static str {
        match self {
            Self::Accounts => "accounts",
            Self::Chats => "chats",
            Self::Messages => "messages",
            Self::Composer => "composer",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SlashCommand {
    Help,
    Refresh,
    Account(String),
    AccountCreate,
    AccountAddPublic(String),
    AccountImportSecret(String),
    DaemonStatus,
    DaemonStart,
    DaemonStop,
    ChatNew {
        name: String,
        members: Vec<String>,
    },
    ChatRename(String),
    ChatDescribe(String),
    ChatArchive,
    ChatUnarchive,
    ChatArchived(bool),
    MembersAdd(Vec<String>),
    MembersRemove(Vec<String>),
    MembersList,
    KeysFetch(String),
    KeysRotate,
    ProfileName(String),
    StreamCompose {
        stream_id: Option<String>,
        quic_candidates: Vec<String>,
    },
    StreamStart {
        stream_id: Option<String>,
        quic_candidates: Vec<String>,
    },
    StreamWatch {
        stream_id: Option<String>,
        insecure_local: bool,
    },
    StreamStatus,
    StreamFinish {
        stream_id: String,
        transcript_hash: String,
        chunk_count: u64,
        text: String,
    },
    StreamVerify {
        stream_id: String,
        transcript_hash: String,
        chunk_count: Option<u64>,
    },
    Quit,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct SlashCommandSuggestion {
    pub(crate) usage: &'static str,
    pub(crate) description: &'static str,
}

pub(crate) const SLASH_COMMAND_SUGGESTIONS: &[SlashCommandSuggestion] = &[
    SlashCommandSuggestion {
        usage: "/help",
        description: "show full TUI help",
    },
    SlashCommandSuggestion {
        usage: "/refresh",
        description: "reload accounts and chats",
    },
    SlashCommandSuggestion {
        usage: "/account <npub-or-hex>",
        description: "select an account",
    },
    SlashCommandSuggestion {
        usage: "/create-identity",
        description: "create a local signing identity",
    },
    SlashCommandSuggestion {
        usage: "/login <nsec-or-npub>",
        description: "import or add an identity",
    },
    SlashCommandSuggestion {
        usage: "/daemon status",
        description: "show daemon state",
    },
    SlashCommandSuggestion {
        usage: "/daemon start",
        description: "start the daemon",
    },
    SlashCommandSuggestion {
        usage: "/daemon stop",
        description: "stop the daemon",
    },
    SlashCommandSuggestion {
        usage: "/chat new <name> [member-npub-or-hex ...]",
        description: "create a chat",
    },
    SlashCommandSuggestion {
        usage: "/chat rename <name>",
        description: "rename the selected chat",
    },
    SlashCommandSuggestion {
        usage: "/chat describe <description>",
        description: "update the selected chat description",
    },
    SlashCommandSuggestion {
        usage: "/chat archive",
        description: "archive the selected chat",
    },
    SlashCommandSuggestion {
        usage: "/chat unarchive",
        description: "unarchive the selected chat",
    },
    SlashCommandSuggestion {
        usage: "/chat archived [on|off]",
        description: "toggle archived chat visibility",
    },
    SlashCommandSuggestion {
        usage: "/members add <npub-or-hex> [...]",
        description: "add members to the selected chat",
    },
    SlashCommandSuggestion {
        usage: "/members remove <npub-or-hex> [...]",
        description: "remove members from the selected chat",
    },
    SlashCommandSuggestion {
        usage: "/members list",
        description: "show selected chat members",
    },
    SlashCommandSuggestion {
        usage: "/keys fetch <npub-or-hex>",
        description: "fetch another account's KeyPackage",
    },
    SlashCommandSuggestion {
        usage: "/keys rotate",
        description: "mint and publish a replacement KeyPackage",
    },
    SlashCommandSuggestion {
        usage: "/name <display-name>",
        description: "publish a profile display name",
    },
    SlashCommandSuggestion {
        usage: "/profile name <display-name>",
        description: "publish a profile display name",
    },
    SlashCommandSuggestion {
        usage: "/stream [--stream-id <id>] [--quic-candidate <url>]",
        description: "open the streaming composer",
    },
    SlashCommandSuggestion {
        usage: "/stream start <quic-candidate> [...]",
        description: "anchor an agent stream start",
    },
    SlashCommandSuggestion {
        usage: "/stream watch [stream-id] [--insecure-local]",
        description: "watch brokered stream previews",
    },
    SlashCommandSuggestion {
        usage: "/stream status",
        description: "show daemon stream-watch state",
    },
    SlashCommandSuggestion {
        usage: "/stream finish <stream-id> <transcript-hash> <chunk-count> <text>",
        description: "anchor an agent stream final",
    },
    SlashCommandSuggestion {
        usage: "/stream verify <stream-id> <transcript-hash> [chunk-count]",
        description: "verify a stream transcript",
    },
    SlashCommandSuggestion {
        usage: "/quit",
        description: "exit the TUI",
    },
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StreamComposer {
    pub(crate) stream_id: String,
    pub(crate) group_id: String,
    pub(crate) pending_text: String,
    pub(crate) last_flush: Instant,
}

pub(crate) fn subscription_event_from_json(envelope: Value) -> SubscriptionEvent {
    if envelope.get("stream_end").and_then(Value::as_bool) == Some(true) {
        return SubscriptionEvent::Ended;
    }
    if envelope.get("ok").and_then(Value::as_bool) == Some(true) {
        return SubscriptionEvent::Result(envelope.get("result").cloned().unwrap_or(Value::Null));
    }
    if envelope.get("ok").and_then(Value::as_bool) == Some(false) {
        return SubscriptionEvent::Error(subscription_error_message(&envelope));
    }
    if let Some(result) = envelope.get("result") {
        return SubscriptionEvent::Result(result.clone());
    }
    if envelope.get("error").is_some() {
        return SubscriptionEvent::Error(subscription_error_message(&envelope));
    }
    SubscriptionEvent::Error("message subscription returned an unrecognized event".to_owned())
}

pub(crate) fn subscription_error_message(envelope: &Value) -> String {
    envelope
        .get("error")
        .and_then(|error| error.get("message"))
        .and_then(Value::as_str)
        .or_else(|| {
            envelope
                .get("error")
                .and_then(|error| error.get("code"))
                .and_then(Value::as_str)
        })
        .unwrap_or("message subscription failed")
        .to_owned()
}

pub(crate) fn parse_account(value: &Value) -> Option<AccountRow> {
    Some(AccountRow {
        account_id: value_string(value, "account_id")?,
        npub: value_string(value, "npub")?,
        display_name: non_empty_value_string(value, "display_name").or_else(|| {
            value
                .get("profile")
                .and_then(profile_display_name_from_value)
        }),
        local_signing: value.get("local_signing").and_then(Value::as_bool)?,
    })
}

pub(crate) fn parse_chat(value: &Value) -> Option<ChatRow> {
    let profile = value.get("profile")?;
    Some(ChatRow {
        group_id: value_string(value, "group_id")?,
        name: value_string(profile, "name").unwrap_or_else(|| "unnamed".to_owned()),
        archived: value
            .get("archived")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

pub(crate) fn parse_message(value: &Value) -> Option<MessageRow> {
    let plaintext = value_string(value, "plaintext")?;
    if value
        .get("agent_text_stream")
        .and_then(|stream| stream.get("kind"))
        .and_then(Value::as_str)
        == Some("start")
    {
        return None;
    }
    let display_text = if value.get("kind").and_then(Value::as_u64) == Some(GROUP_SYSTEM_KIND) {
        group_system_summary(value, &plaintext).unwrap_or_else(|| plaintext.clone())
    } else {
        value
            .get("agent_text_stream")
            .and_then(agent_text_stream_summary)
            .unwrap_or_else(|| plaintext.clone())
    };
    Some(MessageRow {
        message_id: value_string(value, "message_id").unwrap_or_default(),
        direction: value_string(value, "direction").unwrap_or_else(|| "received".to_owned()),
        from: value_string(value, "from").unwrap_or_else(|| "unknown".to_owned()),
        from_display_name: non_empty_value_string(value, "from_display_name"),
        plaintext,
        display_text,
        recorded_at: value
            .get("recorded_at")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        received_at: value
            .get("received_at")
            .and_then(Value::as_u64)
            .unwrap_or(0),
    })
}

pub(crate) fn sort_messages_chronologically(messages: &mut [MessageRow]) {
    messages.sort_by(|left, right| {
        left.recorded_at
            .cmp(&right.recorded_at)
            .then_with(|| left.received_at.cmp(&right.received_at))
            .then_with(|| left.message_id.cmp(&right.message_id))
    });
}

pub(crate) fn sort_and_cap_messages(messages: &mut Vec<MessageRow>) {
    sort_messages_chronologically(messages);
    cap_message_scrollback(messages);
}

pub(crate) fn cap_message_scrollback(messages: &mut Vec<MessageRow>) {
    if messages.len() <= TUI_MESSAGE_SCROLLBACK_LIMIT {
        return;
    }
    let excess = messages.len() - TUI_MESSAGE_SCROLLBACK_LIMIT;
    messages.drain(0..excess);
}

/// Inner app-event kind for durable group system rows (membership/admin/profile).
pub(crate) const GROUP_SYSTEM_KIND: u64 = 1210;

/// Friendly one-line rendering of a kind-1210 group system row from its JSON
/// content, e.g. "alice added bob". Falls back to the embedded `text` field, or
/// `None` when the content is not a parseable group system event.
pub(crate) fn group_system_summary(value: &Value, plaintext: &str) -> Option<String> {
    let content: Value = serde_json::from_str(plaintext).ok()?;
    let system_type = content.get("system_type").and_then(Value::as_str)?;
    let data = content.get("data");
    // `actor` is absent for unattributed changes (e.g. a convergence reorg,
    // where the committer isn't resolved). Render the passive voice then rather
    // than implying an unknown actor performed the action.
    let actor = non_empty_value_string(value, "from_display_name").or_else(|| {
        value_string(value, "from")
            .filter(|from| !from.is_empty())
            .map(|from| shorten(&from, 12))
    });
    let subject = data
        .and_then(|data| data.get("subject"))
        .and_then(Value::as_str)
        .map_or_else(|| "someone".to_owned(), |subject| shorten(subject, 12));
    let name = data
        .and_then(|data| data.get("name"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let summary = match (system_type, actor.as_deref()) {
        ("member_added", Some(actor)) => format!("{actor} added {subject}"),
        ("member_added", None) => format!("{subject} was added"),
        ("member_removed", Some(actor)) => format!("{actor} removed {subject}"),
        ("member_removed", None) => format!("{subject} was removed"),
        ("member_left", Some(actor)) => format!("{actor} left"),
        ("member_left", None) => format!("{subject} left"),
        ("admin_added", Some(actor)) => format!("{actor} made {subject} an admin"),
        ("admin_added", None) => format!("{subject} was made an admin"),
        ("admin_removed", Some(actor)) => format!("{actor} removed {subject} as admin"),
        ("admin_removed", None) => format!("{subject} is no longer an admin"),
        ("group_renamed", Some(actor)) => format!("{actor} renamed the group to \"{name}\""),
        ("group_renamed", None) => format!("the group was renamed to \"{name}\""),
        ("group_avatar_changed", Some(actor)) => format!("{actor} changed the group avatar"),
        ("group_avatar_changed", None) => "the group avatar changed".to_owned(),
        _ => content
            .get("text")
            .and_then(Value::as_str)
            .unwrap_or(system_type)
            .to_owned(),
    };
    Some(summary)
}

pub(crate) fn agent_text_stream_summary(value: &Value) -> Option<String> {
    let stream_id = value_string(value, "stream_id")
        .map(|stream_id| shorten(&stream_id, 18))
        .unwrap_or_else(|| "unknown".to_owned());
    match value.get("kind").and_then(Value::as_str)? {
        "start" => {
            let route = value_string(value, "route").unwrap_or_else(|| "unknown".to_owned());
            let candidates = value
                .get("quic_candidates")
                .and_then(Value::as_array)
                .map_or(0, Vec::len);
            Some(format!(
                "stream start {stream_id} route={route} candidates={candidates}"
            ))
        }
        "final" => {
            let text = value_string(value, "final_text_or_reference")
                .filter(|text| !text.is_empty())
                .unwrap_or_else(|| format!("stream final {stream_id}"));
            Some(text)
        }
        _ => None,
    }
}

pub(crate) fn value_string(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_owned)
}

pub(crate) fn non_empty_value_string(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

pub(crate) fn profile_display_name_from_value(value: &Value) -> Option<String> {
    non_empty_value_string(value, "display_name")
        .or_else(|| non_empty_value_string(value, "displayName"))
        .or_else(|| non_empty_value_string(value, "name"))
}

pub(crate) fn account_display_label(account: &AccountRow) -> String {
    account
        .display_name
        .clone()
        .unwrap_or_else(|| account.npub.clone())
}

pub(crate) fn message_author_label(
    message: &MessageRow,
    selected_account: Option<&AccountRow>,
) -> String {
    if message.direction == "sent" {
        return "me".to_owned();
    }
    if selected_account.is_some_and(|account| {
        message.from == account.account_id
            || message.from == account.npub
            || message.from == account_display_label(account)
    }) {
        return "me".to_owned();
    }
    message
        .from_display_name
        .clone()
        .unwrap_or_else(|| shorten(&message.from, 18))
}

pub(crate) fn stream_preview_author(
    message: &Value,
    selected_account: Option<&AccountRow>,
) -> String {
    let direction = value_string(message, "direction").unwrap_or_else(|| "received".to_owned());
    let from = value_string(message, "from").unwrap_or_else(|| "stream".to_owned());
    if direction == "sent" {
        return "me".to_owned();
    }
    if selected_account.is_some_and(|account| {
        from == account.account_id || from == account.npub || from == account_display_label(account)
    }) {
        return "me".to_owned();
    }
    non_empty_value_string(message, "from_display_name").unwrap_or_else(|| shorten(&from, 18))
}

pub(crate) fn unix_now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(crate) fn selected_account_index(
    accounts: &[AccountRow],
    selector: Option<&str>,
) -> Option<usize> {
    selector.and_then(|selector| {
        accounts
            .iter()
            .position(|account| account_matches(account, selector))
    })
}

pub(crate) fn selected_chat_index(chats: &[ChatRow], group_id: Option<&str>) -> Option<usize> {
    group_id.and_then(|group_id| chats.iter().position(|chat| chat.group_id == group_id))
}

pub(crate) fn apply_chat_subscription_result(
    chats: &mut Vec<ChatRow>,
    selected_chat: &mut usize,
    show_archived_chats: bool,
    result: &Value,
) -> Option<String> {
    if result.get("type").and_then(Value::as_str) != Some("chat") {
        return None;
    }
    let chat = result.get("chat").and_then(parse_chat)?;
    let previous_group_id = chats.get(*selected_chat).map(|chat| chat.group_id.clone());
    upsert_chat(chats, chat, show_archived_chats);
    *selected_chat = selected_chat_index(chats, previous_group_id.as_deref())
        .unwrap_or_else(|| (*selected_chat).min(chats.len().saturating_sub(1)));
    Some(format!("live chat update: chats={}", chats.len()))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GroupStateSubscriptionUpdate {
    pub(crate) group_id: String,
    pub(crate) status: Option<String>,
    pub(crate) diagnostics: Option<GroupDiagnostics>,
}

pub(crate) fn group_state_subscription_update(
    result: &Value,
    selected_group_id: &str,
) -> Option<GroupStateSubscriptionUpdate> {
    if result.get("type").and_then(Value::as_str) != Some("group_state") {
        return None;
    }
    let group_id = value_string(result, "group_id").or_else(|| {
        result
            .get("group")
            .and_then(|group| value_string(group, "group_id"))
    })?;
    if group_id != selected_group_id {
        return None;
    }
    let status = if result.get("trigger").and_then(Value::as_str) == Some("InitialGroupState") {
        None
    } else {
        Some(format!(
            "live group state update: {}",
            group_state_subscription_label(result, &group_id)
        ))
    };
    let diagnostics = parse_group_diagnostics(result);
    Some(GroupStateSubscriptionUpdate {
        group_id,
        status,
        diagnostics,
    })
}

pub(crate) fn group_state_subscription_label(result: &Value, group_id: &str) -> String {
    result
        .get("group")
        .and_then(parse_chat)
        .map(|chat| shorten(&chat.name, 18))
        .unwrap_or_else(|| shorten(group_id, 18))
}

pub(crate) fn upsert_chat(chats: &mut Vec<ChatRow>, chat: ChatRow, show_archived_chats: bool) {
    if chat.archived && !show_archived_chats {
        chats.retain(|existing| existing.group_id != chat.group_id);
        return;
    }
    if let Some(existing) = chats
        .iter_mut()
        .find(|existing| existing.group_id == chat.group_id)
    {
        *existing = chat;
    } else {
        chats.push(chat);
    }
}

pub(crate) fn account_matches(account: &AccountRow, selector: &str) -> bool {
    account.account_id == selector || account.npub == selector
}

pub(crate) fn move_index(current: usize, len: usize, delta: isize) -> usize {
    if len == 0 {
        return 0;
    }
    let max = len.saturating_sub(1) as isize;
    (current as isize + delta).clamp(0, max) as usize
}

// `scrollback` counts lines up from the bottom (0 keeps the newest pinned). Returns the
// clamped scrollback and the top-line offset to hand to `Paragraph::scroll`.
pub(crate) fn messages_scroll_offsets(total: u16, viewport: u16, scrollback: u16) -> (u16, u16) {
    let max_scroll = total.saturating_sub(viewport);
    let clamped = scrollback.min(max_scroll);
    (clamped, max_scroll - clamped)
}

pub(crate) fn publish_status(action: &str, result: &Value) -> String {
    let published = result
        .get("published")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    format!("{action}; published={published}")
}

pub(crate) fn parse_daemon_view(value: &Value) -> DaemonView {
    DaemonView {
        running: value
            .get("running")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        pid: value.get("pid").and_then(Value::as_u64),
        last_runtime_activity: value
            .get("last_runtime_activity")
            .and_then(parse_daemon_runtime_activity_view),
        stream_watches: value
            .get("stream_watches")
            .and_then(Value::as_array)
            .map(|watches| {
                watches
                    .iter()
                    .filter_map(parse_daemon_stream_watch)
                    .collect()
            })
            .unwrap_or_default(),
    }
}

pub(crate) fn parse_daemon_runtime_activity_view(
    value: &Value,
) -> Option<DaemonRuntimeActivityView> {
    Some(DaemonRuntimeActivityView {
        accounts: value.get("accounts").and_then(Value::as_u64)?,
        events: value.get("events").and_then(Value::as_u64).unwrap_or(0),
        joined_groups: value
            .get("joined_groups")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        messages: value.get("messages").and_then(Value::as_u64).unwrap_or(0),
        errors: value
            .get("errors")
            .and_then(Value::as_array)
            .map_or(0, Vec::len),
    })
}

pub(crate) fn parse_daemon_stream_watch(value: &Value) -> Option<DaemonStreamWatchView> {
    Some(DaemonStreamWatchView {
        watch_id: value_string(value, "watch_id")?,
        group_id: value_string(value, "group_id")?,
        stream_id: value_string(value, "stream_id"),
        status: value_string(value, "status").unwrap_or_else(|| "unknown".to_owned()),
        text: value_string(value, "text"),
        transcript_hash: value_string(value, "transcript_hash"),
        chunk_count: value.get("chunk_count").and_then(Value::as_u64),
        error: value_string(value, "error"),
    })
}

pub(crate) fn apply_tui_subscription_result(
    messages: &mut Vec<MessageRow>,
    live_previews: &mut Vec<LiveStreamPreview>,
    unread_counts: &mut HashMap<String, usize>,
    selected_group_id: Option<&str>,
    result: &Value,
) -> Option<String> {
    if is_initial_subscription_result(result) {
        return None;
    }
    if let Some(group_id) = subscription_result_group_id(result)
        && Some(group_id.as_str()) != selected_group_id
    {
        if subscription_result_counts_as_unread(result) {
            let unread_count = unread_counts.entry(group_id.clone()).or_default();
            *unread_count += 1;
            let status = Some(format!(
                "unread message in {}; count={}",
                shorten(&group_id, 18),
                unread_count
            ));
            let _ = apply_subscription_result(messages, live_previews, result, true);
            return status;
        }
        let _ = apply_subscription_result(messages, live_previews, result, true);
        return None;
    }
    apply_subscription_result(messages, live_previews, result, false)
}

pub(crate) fn is_initial_subscription_result(result: &Value) -> bool {
    matches!(
        result.get("trigger").and_then(Value::as_str),
        Some("InitialMessage" | "InitialAgentStreamWatch")
    )
}

pub(crate) fn subscription_result_group_id(result: &Value) -> Option<String> {
    match result.get("type").and_then(Value::as_str) {
        Some(
            "message" | "reaction" | "message_delete" | "media" | "agent_stream_start"
            | "agent_stream_final",
        ) => result
            .get("message")
            .and_then(|message| value_string(message, "group_id")),
        Some("agent_stream_delta") => result
            .get("agent_stream_delta")
            .and_then(|delta| value_string(delta, "group_id")),
        Some("stream_preview") => result
            .get("stream_preview")
            .and_then(|preview| value_string(preview, "group_id")),
        _ => None,
    }
}

pub(crate) fn subscription_result_counts_as_unread(result: &Value) -> bool {
    matches!(
        result.get("type").and_then(Value::as_str),
        Some("message" | "reaction" | "media" | "agent_stream_final")
    )
}

pub(crate) fn apply_subscription_result(
    messages: &mut Vec<MessageRow>,
    live_previews: &mut Vec<LiveStreamPreview>,
    result: &Value,
    suppress_message_append: bool,
) -> Option<String> {
    match result.get("type").and_then(Value::as_str) {
        Some("message" | "reaction" | "message_delete" | "media" | "agent_stream_final") => {
            let message_value = result.get("message")?;
            if result.get("type").and_then(Value::as_str) == Some("agent_stream_final")
                && let Some(stream_id) = message_value
                    .get("agent_text_stream")
                    .and_then(|stream| value_string(stream, "stream_id"))
            {
                let group_id = value_string(message_value, "group_id");
                remove_live_stream_preview(live_previews, group_id.as_deref(), &stream_id);
            }
            if suppress_message_append {
                return None;
            }
            let message = parse_message(message_value)?;
            upsert_message(messages, message);
            sort_and_cap_messages(messages);
            Some(format!("live update: messages={}", messages.len()))
        }
        Some("agent_stream_start") => {
            let message = result.get("message")?;
            let stream = message
                .get("agent_text_stream")
                .and_then(|stream| value_string(stream, "stream_id"))?;
            let group_id = value_string(message, "group_id")?;
            let author = stream_preview_author(message, None);
            upsert_live_stream_preview(
                live_previews,
                LiveStreamPreview {
                    group_id,
                    stream_id: stream.clone(),
                    author,
                    status: "streaming".to_owned(),
                    text: String::new(),
                    error: None,
                    optimistic: false,
                },
                false,
            );
            Some(format!("stream started {}", shorten(&stream, 18)))
        }
        Some("agent_stream_delta") => {
            let delta = result.get("agent_stream_delta")?;
            let group_id = value_string(delta, "group_id")?;
            let stream_id = value_string(delta, "stream_id")?;
            let text = value_string(delta, "text").unwrap_or_default();
            append_live_stream_delta(live_previews, group_id, stream_id.clone(), text);
            Some(format!("streaming {}", shorten(&stream_id, 18)))
        }
        Some("stream_preview") => {
            let preview = result.get("stream_preview")?;
            let group_id = value_string(preview, "group_id")?;
            let stream_id =
                value_string(preview, "stream_id").or_else(|| value_string(preview, "watch_id"))?;
            let status = value_string(preview, "status").unwrap_or_else(|| "streaming".to_owned());
            let text = value_string(preview, "text").unwrap_or_default();
            let error = value_string(preview, "error");
            upsert_live_stream_preview(
                live_previews,
                LiveStreamPreview {
                    group_id,
                    stream_id: stream_id.clone(),
                    author: "stream".to_owned(),
                    status: status.clone(),
                    text,
                    error,
                    optimistic: false,
                },
                true,
            );
            Some(format!("stream {status} {}", shorten(&stream_id, 18)))
        }
        _ => None,
    }
}

pub(crate) fn upsert_message(messages: &mut Vec<MessageRow>, message: MessageRow) {
    if !message.message_id.is_empty()
        && let Some(existing) = messages
            .iter_mut()
            .find(|existing| existing.message_id == message.message_id)
    {
        *existing = message;
        return;
    }
    messages.push(message);
}

pub(crate) fn append_live_stream_delta(
    live_previews: &mut Vec<LiveStreamPreview>,
    group_id: String,
    stream_id: String,
    text: String,
) {
    if let Some(preview) = live_previews
        .iter_mut()
        .find(|preview| preview.group_id == group_id && preview.stream_id == stream_id)
    {
        if preview.optimistic {
            return;
        }
        preview.status = "streaming".to_owned();
        preview.text.push_str(&text);
        cap_live_stream_text(&mut preview.text);
        preview.error = None;
        return;
    }
    let mut preview = LiveStreamPreview {
        group_id,
        stream_id,
        author: "stream".to_owned(),
        status: "streaming".to_owned(),
        text,
        error: None,
        optimistic: false,
    };
    cap_live_stream_preview(&mut preview);
    live_previews.push(preview);
    cap_live_stream_previews(live_previews);
}

pub(crate) fn upsert_live_stream_preview(
    live_previews: &mut Vec<LiveStreamPreview>,
    mut preview: LiveStreamPreview,
    replace_text: bool,
) {
    cap_live_stream_preview(&mut preview);
    if let Some(existing) = live_previews.iter_mut().find(|existing| {
        existing.group_id == preview.group_id && existing.stream_id == preview.stream_id
    }) {
        if existing.optimistic && !preview.optimistic && !replace_text {
            existing.status = preview.status;
            existing.error = preview.error;
            return;
        }
        existing.author = preview.author;
        existing.status = preview.status;
        existing.error = preview.error;
        existing.optimistic = preview.optimistic;
        if replace_text || existing.text.is_empty() {
            existing.text = preview.text;
        }
        cap_live_stream_preview(existing);
        return;
    }
    live_previews.push(preview);
    cap_live_stream_previews(live_previews);
}

pub(crate) fn cap_live_stream_previews(live_previews: &mut Vec<LiveStreamPreview>) {
    if live_previews.len() <= TUI_LIVE_STREAM_PREVIEW_LIMIT {
        return;
    }
    let excess = live_previews.len() - TUI_LIVE_STREAM_PREVIEW_LIMIT;
    live_previews.drain(0..excess);
}

pub(crate) fn cap_live_stream_preview(preview: &mut LiveStreamPreview) {
    cap_live_stream_text(&mut preview.text);
}

pub(crate) fn cap_live_stream_text(text: &mut String) {
    if text.len() <= TUI_LIVE_STREAM_TEXT_LIMIT {
        return;
    }
    let mut start = text.len() - TUI_LIVE_STREAM_TEXT_LIMIT;
    while !text.is_char_boundary(start) {
        start += 1;
    }
    text.drain(..start);
}

pub(crate) fn remove_live_stream_preview(
    live_previews: &mut Vec<LiveStreamPreview>,
    group_id: Option<&str>,
    stream_id: &str,
) {
    live_previews.retain(|preview| {
        if preview.stream_id != stream_id {
            return true;
        }
        if let Some(group_id) = group_id {
            return preview.group_id != group_id;
        }
        false
    });
}

pub(crate) fn unique_member_refs(members: Vec<String>) -> Vec<String> {
    let mut unique = Vec::new();
    for member in members {
        if !member.is_empty() && !unique.iter().any(|existing| existing == &member) {
            unique.push(member);
        }
    }
    unique
}

pub(crate) fn member_ref_summary(members: &[String]) -> String {
    members
        .iter()
        .map(|member| shorten(&terminal_safe_text(member), 14))
        .collect::<Vec<_>>()
        .join(", ")
}

pub(crate) fn group_members_status(result: &Value) -> String {
    let members = result
        .get("members")
        .and_then(Value::as_array)
        .map(|members| {
            members
                .iter()
                .filter_map(|member| {
                    value_string(member, "npub").or_else(|| value_string(member, "member_id"))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if members.is_empty() {
        return "members: none".to_owned();
    }
    format!("members: {}", member_ref_summary(&members))
}

pub(crate) fn retain_unread_counts_for_chats(
    unread_counts: &mut HashMap<String, usize>,
    chats: &[ChatRow],
) {
    unread_counts.retain(|group_id, _| chats.iter().any(|chat| chat.group_id == *group_id));
}

impl GroupDiagnostics {
    pub(crate) fn unavailable(group_id: &str, error: impl Into<String>) -> Self {
        Self {
            group_id: group_id.to_owned(),
            epoch: None,
            member_count: None,
            components: Vec::new(),
            error: Some(error.into()),
        }
    }
}

pub(crate) fn parse_group_diagnostics(value: &Value) -> Option<GroupDiagnostics> {
    let group = value.get("group")?;
    let group_id = value_string(group, "group_id")?;
    let mls = value.get("mls");
    Some(GroupDiagnostics {
        group_id,
        epoch: mls
            .and_then(|mls| mls.get("epoch"))
            .and_then(Value::as_u64)
            .or_else(|| group.get("epoch").and_then(Value::as_u64)),
        member_count: mls
            .and_then(|mls| mls.get("member_count"))
            .and_then(Value::as_u64)
            .or_else(|| group.get("member_count").and_then(Value::as_u64)),
        components: group_component_diagnostics(group),
        error: None,
    })
}

pub(crate) fn group_component_diagnostics(group: &Value) -> Vec<GroupComponentDiagnostics> {
    [
        "profile",
        "image",
        "admin_policy",
        "nostr_routing",
        "agent_text_stream",
    ]
    .into_iter()
    .filter_map(|key| {
        let component = group.get(key)?;
        Some(GroupComponentDiagnostics {
            component: value_string(component, "component").unwrap_or_else(|| key.to_owned()),
            component_id: component.get("component_id").and_then(Value::as_u64),
            data_hex: value_string(component, "data_hex").unwrap_or_default(),
        })
    })
    .collect()
}

pub(crate) fn terminal_safe_text(value: &str) -> String {
    value.chars().filter(|ch| is_terminal_safe(*ch)).collect()
}

/// Decide whether a single `char` may be rendered in untrusted terminal text
/// (message bodies, sender names, chat labels, stream previews).
///
/// This replaces the earlier hardcoded BiDi/zero-width denylist (see #201 /
/// PR #459) with a width-aware whitelist, as #201 anticipated. The denylist
/// inevitably drifted: a residual class of invisible / format characters
/// (SOFT HYPHEN, the invisible math operators, language-tag characters, the
/// interlinear-annotation controls, the Hangul fillers, BRAILLE PATTERN BLANK,
/// ...) still flowed through and enabled the same homograph / hidden-content
/// spoofing. See #473.
///
/// Policy:
/// - Drop every C0/C1 control (`char::is_control()`), preserving the prior
///   behavior of stripping ANSI/OSC escapes, newlines, and tabs.
/// - Drop the entire Unicode `Cf` (Format) general category. This subsumes
///   every BiDi override, zero-width joiner/space, word joiner, invisible
///   operator (U+2061–U+2064), deprecated shaping control (U+206A–U+206F),
///   interlinear-annotation control (U+FFF9–U+FFFB), SOFT HYPHEN, MONGOLIAN
///   VOWEL SEPARATOR, the musical-beam formatter, the BOM, and the language
///   tag / tag characters (U+E0001, U+E0020–U+E007F) — now and for any future
///   `Cf` additions, so the guard no longer drifts as Unicode evolves.
/// - Drop a small, explicit set of invisible glyphs that render blank but are
///   *not* `Cf` (so a category-only rule would miss them) and cannot be
///   distinguished from legitimate text by category alone: the Hangul fillers
///   (category `Lo`, alongside real CJK) and BRAILLE PATTERN BLANK (category
///   `So`, alongside real emoji).
///
/// Legitimate zero-width characters are intentionally kept: combining marks
/// (categories `Mn`/`Mc`/`Me`, e.g. accents, the Devanagari virama, Arabic
/// vowel marks, and emoji variation selectors) render as part of a visible base
/// glyph and must not be stripped, or accented/Indic/Arabic/emoji text would be
/// mangled. They are excluded from the `Cf` and explicit-filler rules above.
fn is_terminal_safe(ch: char) -> bool {
    if ch.is_control() {
        return false;
    }
    if matches!(ch.general_category(), GeneralCategory::Format) {
        return false;
    }
    !is_invisible_non_format_glyph(ch)
}

/// Invisible glyphs that are not Unicode `Cf` and therefore are not caught by
/// the general-category rule, yet render as a blank cell and can be used for
/// the same name/label spoofing. Enumerated explicitly because their categories
/// (`Lo`, `So`) also contain legitimate, visible text (CJK, emoji).
fn is_invisible_non_format_glyph(ch: char) -> bool {
    matches!(
        ch,
        // Hangul fillers (category Lo) — render invisible.
        '\u{115f}' | '\u{1160}' | '\u{3164}' | '\u{ffa0}'
        // BRAILLE PATTERN BLANK (category So) — renders as a blank cell.
            | '\u{2800}'
    )
}

pub(crate) fn shorten(value: &str, max_len: usize) -> String {
    if value.len() <= max_len {
        return value.to_owned();
    }
    if max_len <= 3 {
        return value.chars().take(max_len).collect();
    }
    let prefix_len = (max_len - 3) / 2;
    let suffix_len = max_len - 3 - prefix_len;
    let prefix = value.chars().take(prefix_len).collect::<String>();
    let suffix = value
        .chars()
        .rev()
        .take(suffix_len)
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>();
    format!("{prefix}...{suffix}")
}

pub(crate) fn composer_display_text(input: &str) -> String {
    let trimmed = input.trim();
    if let Some(command_input) = trimmed.strip_prefix('/')
        && let Ok(words) = split_slash_command_words(command_input)
        && words.first().map(String::as_str) == Some("login")
        && words.iter().skip(1).any(|word| word.starts_with("nsec"))
    {
        return "/login <hidden nsec>".to_owned();
    }
    input.to_owned()
}

pub(crate) fn message_subscription_args() -> Vec<String> {
    vec![
        "messages".to_owned(),
        "subscribe".to_owned(),
        "--limit".to_owned(),
        "0".to_owned(),
    ]
}
