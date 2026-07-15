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
pub(crate) struct WnInvocation {
    pub(crate) args: Vec<String>,
    pub(crate) stdin: Option<String>,
}

pub(crate) fn account_setup_invocation(identity: Option<String>) -> WnInvocation {
    match identity {
        Some(identity) if crate::is_nostr_secret(&identity) => WnInvocation {
            args: vec!["login".to_owned(), "--nsec-stdin".to_owned()],
            stdin: Some(format!("{identity}\n")),
        },
        Some(identity) => WnInvocation {
            args: vec!["login".to_owned(), identity],
            stdin: None,
        },
        None => WnInvocation {
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

pub(crate) struct TimelineSubscription {
    pub(crate) account_id: String,
    pub(crate) group_id: String,
    pub(crate) child: Child,
    pub(crate) rx: Receiver<SubscriptionEvent>,
}

impl Drop for TimelineSubscription {
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
    ChatMute(String),
    ChatUnmute,
    ChatArchived(bool),
    MembersAdd(Vec<String>),
    MembersRemove(Vec<String>),
    MembersList,
    Image {
        file_path: String,
        caption: Option<String>,
    },
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
        usage: "/chat mute <duration>",
        description: "mute selected-chat notifications",
    },
    SlashCommandSuggestion {
        usage: "/chat unmute",
        description: "unmute selected-chat notifications",
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
        usage: "/image <file-path> [caption]",
        description: "encrypt, upload, and send image/media",
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

/// Inner app-event kind for durable group system rows (membership/admin/profile).
pub(crate) const GROUP_SYSTEM_KIND: u64 = 1210;

/// Friendly one-line rendering of a kind-1210 group system row from its JSON
/// content, e.g. "alice added bob". Falls back to the embedded `text` field, or
/// `None` when the content is not a parseable group system event.
pub(crate) fn group_system_summary(value: &Value, plaintext: &str) -> Option<String> {
    if let Some(summary) = value
        .get("group_system")
        .and_then(|system| system.get("summary"))
        .and_then(Value::as_str)
        .filter(|summary| !summary.trim().is_empty())
    {
        return Some(summary.to_owned());
    }

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

/// Phase 1 `wn tui` timeline core: row parsing, the idempotent projection fold,
/// the message-offset scroll model, and rendering (per-row heights, the
/// visibility walk, and line building). Consumed by the timeline
/// client/app/view wiring in this crate.
mod timeline {
    use super::*;
    use ratatui::style::{Color, Modifier, Style};
    use ratatui::text::{Line, Span};
    use ratatui::widgets::{Paragraph, Wrap};
    use serde_json::Value;

    use super::super::{TIMELINE_MESSAGE_SEPARATOR_ROWS, TUI_MESSAGE_SCROLLBACK_LIMIT};

    /// A row of the materialized message timeline (`messages timeline`), as folded by
    /// the runtime: reactions, reply preview, deletion tombstones, and structured
    /// media are already resolved server-side. This is the messages-pane row for
    /// Phase 1; the plain feed now carries only live stream previews and unread counts.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub(crate) struct TimelineRow {
        pub(crate) message_id: String,
        pub(crate) direction: String,
        pub(crate) from: String,
        pub(crate) from_display_name: Option<String>,
        pub(crate) plaintext: String,
        pub(crate) display_text: String,
        pub(crate) timeline_at: u64,
        pub(crate) received_at: u64,
        pub(crate) deleted: bool,
        pub(crate) reactions: Vec<TimelineReaction>,
        pub(crate) reply: Option<TimelineReply>,
        pub(crate) attachments: Vec<TimelineAttachment>,
    }

    /// One emoji's reaction tally on a timeline row, from `reactions.by_emoji`.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub(crate) struct TimelineReaction {
        pub(crate) emoji: String,
        pub(crate) count: usize,
    }

    /// Reply context for a timeline row: the parent message id plus the hydrated
    /// preview when the runtime resolved it.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub(crate) struct TimelineReply {
        pub(crate) reply_to_message_id: String,
        pub(crate) preview: Option<TimelineReplyPreview>,
    }

    /// The hydrated parent-message preview carried on a reply row.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub(crate) struct TimelineReplyPreview {
        pub(crate) sender: Option<String>,
        pub(crate) plaintext: String,
        pub(crate) deleted: bool,
    }

    /// A media attachment placeholder parsed from a row's `media.imeta` tags. Phase 1
    /// keeps only the fields needed to render a placeholder; no download yet.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub(crate) struct TimelineAttachment {
        pub(crate) mime: Option<String>,
        pub(crate) filename: Option<String>,
    }

    /// Parse a materialized timeline row. Returns `None` for rows the pane does not
    /// render: `agent_text_stream` `start` markers are skipped.
    pub(crate) fn parse_timeline_row(value: &Value) -> Option<TimelineRow> {
        if value
            .get("agent_text_stream")
            .and_then(|stream| stream.get("kind"))
            .and_then(Value::as_str)
            == Some("start")
        {
            return None;
        }
        let plaintext = value_string(value, "plaintext").unwrap_or_default();
        let display_text = if value.get("kind").and_then(Value::as_u64) == Some(GROUP_SYSTEM_KIND) {
            group_system_summary(value, &plaintext).unwrap_or_else(|| plaintext.clone())
        } else {
            value
                .get("agent_text_stream")
                .and_then(agent_text_stream_summary)
                .unwrap_or_else(|| plaintext.clone())
        };
        Some(TimelineRow {
            message_id: value_string(value, "message_id").unwrap_or_default(),
            direction: value_string(value, "direction").unwrap_or_else(|| "received".to_owned()),
            from: value_string(value, "from").unwrap_or_else(|| "unknown".to_owned()),
            from_display_name: non_empty_value_string(value, "from_display_name"),
            plaintext,
            display_text,
            timeline_at: value
                .get("timeline_at")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            received_at: value
                .get("received_at")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            deleted: value
                .get("deleted")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            reactions: parse_timeline_reactions(value),
            reply: parse_timeline_reply(value),
            attachments: parse_timeline_attachments(value),
        })
    }

    fn parse_timeline_reactions(value: &Value) -> Vec<TimelineReaction> {
        let Some(by_emoji) = value
            .get("reactions")
            .and_then(|reactions| reactions.get("by_emoji"))
            .and_then(Value::as_object)
        else {
            return Vec::new();
        };
        let mut reactions = by_emoji
            .iter()
            .filter_map(|(emoji, reactors)| {
                let count = reactors.as_array().map_or(0, Vec::len);
                (count > 0).then(|| TimelineReaction {
                    emoji: emoji.clone(),
                    count,
                })
            })
            .collect::<Vec<_>>();
        // Deterministic order independent of the JSON map's iteration order.
        reactions.sort_by(|left, right| left.emoji.cmp(&right.emoji));
        reactions
    }

    fn parse_timeline_reply(value: &Value) -> Option<TimelineReply> {
        let reply_to_message_id = non_empty_value_string(value, "reply_to_message_id")?;
        let preview = value
            .get("reply_preview")
            .filter(|preview| !preview.is_null())
            .map(|preview| TimelineReplyPreview {
                sender: non_empty_value_string(preview, "sender"),
                plaintext: value_string(preview, "plaintext").unwrap_or_default(),
                deleted: preview
                    .get("deleted")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            });
        Some(TimelineReply {
            reply_to_message_id,
            preview,
        })
    }

    fn parse_timeline_attachments(value: &Value) -> Vec<TimelineAttachment> {
        value
            .get("media")
            .and_then(|media| media.get("imeta"))
            .and_then(Value::as_array)
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(parse_timeline_attachment)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Parse one `imeta` tag (an array of space-delimited `key value` strings) into a
    /// placeholder attachment, reading only `m` (mime) and `filename` for Phase 1.
    fn parse_timeline_attachment(entry: &Value) -> Option<TimelineAttachment> {
        let fields = entry.as_array()?;
        let mut mime = None;
        let mut filename = None;
        for field in fields.iter().filter_map(Value::as_str) {
            match field.split_once(' ') {
                Some(("m", value)) => mime = non_empty_string(value),
                Some(("filename", value)) => filename = non_empty_string(value),
                _ => {}
            }
        }
        (mime.is_some() || filename.is_some()).then_some(TimelineAttachment { mime, filename })
    }

    fn non_empty_string(value: &str) -> Option<String> {
        let value = value.trim();
        (!value.is_empty()).then(|| value.to_owned())
    }

    /// A parsed `messages timeline subscribe` event. The caller filters
    /// `ProjectionUpdated` by `group_id` before applying the changes.
    #[derive(Debug)]
    pub(crate) enum TimelineEvent {
        /// The subscription is live; no state change.
        Ready,
        /// The initial bulk page plus whether older history remains.
        InitialPage {
            rows: Vec<TimelineRow>,
            has_more_before: bool,
        },
        /// Typed upsert/remove changes for one group.
        ProjectionUpdated {
            group_id: String,
            changes: Vec<TimelineChange>,
        },
        /// Any other or unrecognized event; no state change.
        Other,
    }

    /// One change inside a `timeline_projection_updated` event. Upserts carry the
    /// full folded row (reactions and `deleted` already applied); removes carry only
    /// the id to drop.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub(crate) enum TimelineChange {
        /// Boxed so a `Vec<TimelineChange>` is not sized to the large row for
        /// every element (most changes are small removes).
        Upsert(Box<TimelineRow>),
        Remove {
            message_id: String,
        },
    }

    pub(crate) fn parse_timeline_event(result: &Value) -> TimelineEvent {
        match result.get("type").and_then(Value::as_str) {
            Some("timeline_subscription_ready") => TimelineEvent::Ready,
            Some("initial_timeline_page") => TimelineEvent::InitialPage {
                rows: parse_timeline_rows(result.get("messages")),
                has_more_before: result
                    .get("has_more_before")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            },
            Some("timeline_projection_updated") => TimelineEvent::ProjectionUpdated {
                group_id: value_string(result, "group_id").unwrap_or_default(),
                changes: result
                    .get("changes")
                    .and_then(Value::as_array)
                    .map(|changes| changes.iter().filter_map(parse_timeline_change).collect())
                    .unwrap_or_default(),
            },
            _ => TimelineEvent::Other,
        }
    }

    fn parse_timeline_rows(messages: Option<&Value>) -> Vec<TimelineRow> {
        messages
            .and_then(Value::as_array)
            .map(|rows| rows.iter().filter_map(parse_timeline_row).collect())
            .unwrap_or_default()
    }

    /// Parse the `messages` array of a `messages timeline list` response into rows
    /// sorted ascending by the backend's `(timeline_at, message_id)` order (oldest
    /// first, newest last — the order the scroll model's bottom-anchored offset
    /// expects).
    pub(crate) fn parse_timeline_page(result: &Value) -> Vec<TimelineRow> {
        let mut rows = parse_timeline_rows(result.get("messages"));
        sort_timeline_rows(&mut rows);
        rows
    }

    /// Read `has_more_before` from a `messages timeline list` response; missing or
    /// non-boolean means no older history remains.
    pub(crate) fn timeline_page_has_more_before(result: &Value) -> bool {
        result
            .get("has_more_before")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    }

    fn parse_timeline_change(change: &Value) -> Option<TimelineChange> {
        match change.get("type").and_then(Value::as_str)? {
            "upsert" => Some(TimelineChange::Upsert(Box::new(parse_timeline_row(
                change.get("message")?,
            )?))),
            "remove" => Some(TimelineChange::Remove {
                message_id: value_string(change, "message_id")?,
            }),
            _ => None,
        }
    }

    /// Sort timeline rows ascending by the backend's deterministic order,
    /// `(timeline_at, message_id)`. Same-second rows tiebreak by id, which can
    /// differ from send order; that is accepted (the tiebreak is deterministic).
    pub(crate) fn sort_timeline_rows(rows: &mut [TimelineRow]) {
        rows.sort_by(|left, right| {
            left.timeline_at
                .cmp(&right.timeline_at)
                .then_with(|| left.message_id.cmp(&right.message_id))
        });
    }

    /// Insert or replace a row by `message_id`, keeping the list sorted. Idempotent
    /// in effect: projection events arrive duplicated (optimistic write plus relay
    /// echo), so re-applying the same row must not append a second copy.
    pub(crate) fn upsert_timeline_row(rows: &mut Vec<TimelineRow>, row: TimelineRow) {
        upsert_timeline_row_unsorted(rows, row);
        sort_timeline_rows(rows);
    }

    /// Insert or replace by `message_id` without re-sorting; callers that upsert a
    /// batch sort once at the end.
    fn upsert_timeline_row_unsorted(rows: &mut Vec<TimelineRow>, row: TimelineRow) {
        match rows
            .iter()
            .position(|existing| existing.message_id == row.message_id)
        {
            Some(index) => rows[index] = row,
            None => rows.push(row),
        }
    }

    /// Drop the row with `message_id`, returning the index it occupied. Removing
    /// preserves sort order, so no re-sort is needed.
    pub(crate) fn remove_timeline_row(
        rows: &mut Vec<TimelineRow>,
        message_id: &str,
    ) -> Option<usize> {
        let index = rows.iter().position(|row| row.message_id == message_id)?;
        rows.remove(index);
        Some(index)
    }

    /// What applying a single change did to the row list, so the caller can adjust
    /// the scroll model. Indices are into the sorted list after the change.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum TimelineFoldOutcome {
        /// A new row landed at this index.
        Inserted(usize),
        /// An existing row (same id) was replaced at this index.
        Updated(usize),
        /// A row was dropped from this index.
        Removed(usize),
        /// Nothing changed (e.g. a remove for an id that is not present).
        Unchanged,
    }

    /// Apply one projection change to the row list, reporting the effect.
    pub(crate) fn apply_timeline_change(
        rows: &mut Vec<TimelineRow>,
        change: TimelineChange,
    ) -> TimelineFoldOutcome {
        match change {
            TimelineChange::Upsert(row) => {
                let message_id = row.message_id.clone();
                let existed = rows
                    .iter()
                    .any(|existing| existing.message_id == message_id);
                upsert_timeline_row(rows, *row);
                let index = rows
                    .iter()
                    .position(|existing| existing.message_id == message_id)
                    .unwrap_or(0);
                if existed {
                    TimelineFoldOutcome::Updated(index)
                } else {
                    TimelineFoldOutcome::Inserted(index)
                }
            }
            TimelineChange::Remove { message_id } => match remove_timeline_row(rows, &message_id) {
                Some(index) => TimelineFoldOutcome::Removed(index),
                None => TimelineFoldOutcome::Unchanged,
            },
        }
    }

    /// Apply one parsed `messages timeline subscribe` event to the pane's rows and
    /// scroll model. `InitialPage` folds each row (idempotent by id) and drives the
    /// scroll model by the reported outcome — so rows that arrived between the
    /// snapshot and the subscribe shift a scrolled-up anchor instead of moving the
    /// view — then adopts its `has_more_before`. `ProjectionUpdated` is gated on the
    /// loaded group, then folds each change and drives the scroll model by the
    /// reported outcome (`on_insert` / `on_remove`; updates and no-ops leave scroll
    /// alone), capping scrollback afterward. `Ready` and `Other` carry no state
    /// change.
    pub(crate) fn apply_timeline_event(
        rows: &mut Vec<TimelineRow>,
        scroll: &mut TimelineScroll,
        loaded_group_id: Option<&str>,
        event: TimelineEvent,
    ) {
        match event {
            TimelineEvent::Ready | TimelineEvent::Other => {}
            TimelineEvent::InitialPage {
                rows: page,
                has_more_before,
            } => {
                // Fold each row through the same change path as the projection
                // arm and drive the scroll on the reported outcome. The common
                // case — the snapshot already loaded every row — degenerates to
                // Updated/Unchanged no-ops; only rows that arrived between the
                // snapshot and the subscribe are Inserted, and those must shift a
                // scrolled-up anchor rather than move the view.
                for row in page {
                    match apply_timeline_change(rows, TimelineChange::Upsert(Box::new(row))) {
                        TimelineFoldOutcome::Inserted(index) => scroll.on_insert(index, rows.len()),
                        TimelineFoldOutcome::Removed(index) => scroll.on_remove(index, rows.len()),
                        TimelineFoldOutcome::Updated(_) | TimelineFoldOutcome::Unchanged => {}
                    }
                }
                scroll.has_more_before = has_more_before;
            }
            TimelineEvent::ProjectionUpdated { group_id, changes } => {
                if loaded_group_id != Some(group_id.as_str()) {
                    return;
                }
                for change in changes {
                    match apply_timeline_change(rows, change) {
                        TimelineFoldOutcome::Inserted(index) => scroll.on_insert(index, rows.len()),
                        TimelineFoldOutcome::Removed(index) => scroll.on_remove(index, rows.len()),
                        TimelineFoldOutcome::Updated(_) | TimelineFoldOutcome::Unchanged => {}
                    }
                }
                cap_timeline_scrollback(rows, scroll);
            }
        }
    }

    /// The exclusive `(timeline_at, message_id)` cursor of the oldest loaded row, for
    /// building the `--before` / `--before-message-id` history-paging flags.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub(crate) struct TimelineCursor {
        pub(crate) timeline_at: u64,
        pub(crate) message_id: String,
    }

    pub(crate) fn oldest_timeline_cursor(rows: &[TimelineRow]) -> Option<TimelineCursor> {
        rows.first().map(|row| TimelineCursor {
            timeline_at: row.timeline_at,
            message_id: row.message_id.clone(),
        })
    }

    /// Trim the timeline to `TUI_MESSAGE_SCROLLBACK_LIMIT`, dropping the oldest rows,
    /// but only while pinned to the bottom. Capping while scrolled up would fight
    /// history paging (it drops rows the user just paged in), so it is skipped then.
    /// The selection and visible range are absolute indices, so they shift down by
    /// the number of dropped rows to stay on the same messages.
    pub(crate) fn cap_timeline_scrollback(
        rows: &mut Vec<TimelineRow>,
        scroll: &mut TimelineScroll,
    ) {
        if !scroll.is_pinned() || rows.len() <= TUI_MESSAGE_SCROLLBACK_LIMIT {
            return;
        }
        let excess = rows.len() - TUI_MESSAGE_SCROLLBACK_LIMIT;
        rows.drain(0..excess);
        scroll.selection = scroll.selection.map(|sel| sel.saturating_sub(excess));
        if let Some((first, last)) = scroll.visible_range {
            scroll.visible_range =
                Some((first.saturating_sub(excess), last.saturating_sub(excess)));
        }
    }

    /// Message-offset scroll state for the messages pane. `offset` counts messages up
    /// from the bottom (0 = pinned to the newest). `selection` is an absolute index
    /// into the row list (`None` tracks the
    /// newest). `visible_range` is fed back by the renderer each frame so navigation
    /// only nudges the viewport when the selection leaves what is on screen.
    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    pub(crate) struct TimelineScroll {
        pub(crate) offset: usize,
        pub(crate) selection: Option<usize>,
        pub(crate) visible_range: Option<(usize, usize)>,
        pub(crate) has_more_before: bool,
        pub(crate) loading_older: bool,
    }

    impl TimelineScroll {
        /// True when pinned to the newest message (auto-follow on arrival).
        pub(crate) fn is_pinned(&self) -> bool {
            self.offset == 0
        }

        /// The selected absolute index, defaulting to the newest row. `None` when the
        /// list is empty.
        pub(crate) fn resolved_selection(&self, len: usize) -> Option<usize> {
            (len > 0).then(|| self.selection.map_or(len - 1, |sel| sel.min(len - 1)))
        }

        /// Adjust for a row inserted at `index` (new length `new_len`). A row newer
        /// than the current anchor bumps the offset by one while scrolled up (so the
        /// content being read does not move) and stays pinned at the bottom
        /// otherwise; a row at or older than the anchor shifts the selection instead.
        pub(crate) fn on_insert(&mut self, index: usize, new_len: usize) {
            let old_len = new_len.saturating_sub(1);
            let anchor = old_len.saturating_sub(1).saturating_sub(self.offset);
            if index > anchor && !self.is_pinned() {
                self.offset += 1;
            }
            if let Some(sel) = self.selection
                && index <= sel
            {
                self.selection = Some(sel + 1);
            }
            if let Some((first, last)) = self.visible_range {
                self.visible_range = Some((
                    first + usize::from(index <= first),
                    last + usize::from(index <= last),
                ));
            }
        }

        /// Adjust for `n` older rows prepended at the front (history paging). The
        /// offset counts from the unchanged bottom, so it stays put; the selection
        /// and last visible range are absolute indices, so they shift by `n` to keep
        /// the same rows selected and on screen.
        pub(crate) fn on_prepend(&mut self, n: usize) {
            if n == 0 {
                return;
            }
            if let Some(sel) = self.selection {
                self.selection = Some(sel + n);
            }
            if let Some((first, last)) = self.visible_range {
                self.visible_range = Some((first + n, last + n));
            }
        }

        /// Adjust for the row at `index` being removed (new length `new_len`). The
        /// mirror of `on_insert`: a row newer than the anchor pulls the offset down
        /// while scrolled up; a row at or older than the selection shifts it down.
        pub(crate) fn on_remove(&mut self, index: usize, new_len: usize) {
            let old_len = new_len + 1;
            let anchor = (old_len - 1).saturating_sub(self.offset);
            if index > anchor && !self.is_pinned() {
                self.offset -= 1;
            }
            self.selection = self.selection.and_then(|sel| {
                let shifted = sel - usize::from(index < sel);
                (new_len > 0).then(|| shifted.min(new_len - 1))
            });
            if let Some((first, last)) = self.visible_range {
                self.visible_range = Some((
                    first - usize::from(index < first),
                    last - usize::from(index < last),
                ));
            }
        }

        /// Move the selection one row toward older messages (`k`).
        pub(crate) fn select_up(&mut self, len: usize) {
            self.move_selection(len, |sel| sel.saturating_sub(1));
        }

        /// Move the selection one row toward newer messages (`j`).
        pub(crate) fn select_down(&mut self, len: usize) {
            self.move_selection(len, |sel| sel + 1);
        }

        /// Move the selection up by the number of currently visible messages
        /// (`PageUp`), clamped.
        pub(crate) fn page_up(&mut self, len: usize) {
            let count = self.visible_count();
            self.move_selection(len, |sel| sel.saturating_sub(count));
        }

        /// Move the selection down by the number of currently visible messages
        /// (`PageDown`), clamped.
        pub(crate) fn page_down(&mut self, len: usize) {
            let count = self.visible_count();
            self.move_selection(len, |sel| sel + count);
        }

        /// The number of messages the last render reported on screen (at least one).
        fn visible_count(&self) -> usize {
            self.visible_range
                .map_or(1, |(first, last)| last.saturating_sub(first) + 1)
                .max(1)
        }

        /// Select the newest message and pin to the bottom (`G`).
        pub(crate) fn jump_newest(&mut self, _len: usize) {
            self.selection = None;
            self.offset = 0;
        }

        /// Select the oldest loaded message and scroll to the top (`g`).
        pub(crate) fn jump_oldest(&mut self, len: usize) {
            if len == 0 {
                return;
            }
            self.selection = Some(0);
            self.offset = len - 1;
        }

        fn move_selection(&mut self, len: usize, step: impl FnOnce(usize) -> usize) {
            let Some(sel) = self.resolved_selection(len) else {
                return;
            };
            self.selection = Some(step(sel).min(len - 1));
            self.follow_selection(len);
        }

        /// Record the message range the renderer put on screen this frame. The
        /// follow-scroll logic reads it to decide when to move the viewport, and
        /// it also renormalizes a stale over-large offset down to what the render
        /// geometry actually shows.
        ///
        /// `jump_oldest` (and any offset larger than the list can scroll) sets an
        /// offset the renderer clamps when it anchors and fills forward, so the
        /// stored offset can exceed the largest offset that still draws the same
        /// bottom row (`last`). Left uncorrected, a later `on_prepend` — which
        /// leaves the offset put (rule 6) — would anchor below the true top and
        /// jump the view. The drawn `last` pins the effective offset to
        /// `(len - 1) - last`; clamp down to it, never up (a legitimately smaller
        /// offset always has `last` at the anchor, so this leaves it untouched).
        pub(crate) fn record_visible_range(&mut self, first: usize, last: usize, len: usize) {
            self.visible_range = Some((first, last));
            let effective = len.saturating_sub(1).saturating_sub(last);
            if self.offset > effective {
                self.offset = effective;
            }
        }

        /// True when the selection is on the oldest loaded row.
        pub(crate) fn at_oldest(&self, len: usize) -> bool {
            self.resolved_selection(len) == Some(0)
        }

        /// True when the caller should fetch an older history page: the selection is
        /// at the oldest loaded row, more history exists, and no request is in
        /// flight. The caller sets `loading_older` when it fires the request and,
        /// once the page arrives, prepends the rows, calls `on_prepend`, and updates
        /// `has_more_before` / `loading_older`.
        pub(crate) fn should_request_older(&self, len: usize) -> bool {
            self.has_more_before && !self.loading_older && self.at_oldest(len)
        }

        /// Nudge the viewport so the selection stays on screen, using the visible
        /// range reported by the last render. Movement inside the range scrolls
        /// nothing; leaving it moves the offset by exactly the overshoot.
        fn follow_selection(&mut self, len: usize) {
            let (Some(sel), Some((first, last))) =
                (self.resolved_selection(len), self.visible_range)
            else {
                return;
            };
            if sel < first {
                self.offset = (self.offset + (first - sel)).min(len.saturating_sub(1));
            } else if sel > last {
                self.offset = self.offset.saturating_sub(sel - last);
            }
        }
    }

    /// Build the display lines for one timeline row: `[HH:MM] author: content`, with
    /// an optional reply line above, an optional reactions line below, and
    /// attachment placeholders. Deleted rows render a tombstone in place. Every
    /// untrusted string passes through `terminal_safe_text`. Selection highlight is
    /// applied by the renderer; this returns only the content lines (the blank
    /// separator counted by `timeline_row_height` is added when rendering).
    pub(crate) fn timeline_row_lines(
        row: &TimelineRow,
        selected_account: Option<&AccountRow>,
    ) -> Vec<Line<'static>> {
        let prefix = format!("[{}] ", local_hhmm(row.timeline_at));
        let author_prefix = format!("{}: ", terminal_safe_text(&timeline_author_label(row)));
        let indent = prefix.chars().count() + author_prefix.chars().count();
        let author_style = Style::default()
            .fg(if timeline_row_is_self(row, selected_account) {
                Color::Green
            } else {
                Color::Cyan
            })
            .add_modifier(Modifier::BOLD);
        let timestamp_style = Style::default().fg(Color::DarkGray);

        let mut lines = Vec::new();
        if let Some(reply) = &row.reply {
            lines.push(timeline_reply_line(reply, indent));
        }
        if row.deleted {
            lines.push(Line::from(vec![
                Span::styled(prefix, timestamp_style),
                Span::styled(author_prefix, author_style),
                Span::styled("message deleted", timeline_muted_italic_style()),
            ]));
            return lines;
        }
        for (index, part) in row.display_text.split('\n').enumerate() {
            let part = terminal_safe_text(part);
            if index == 0 {
                lines.push(Line::from(vec![
                    Span::styled(prefix.clone(), timestamp_style),
                    Span::styled(author_prefix.clone(), author_style),
                    Span::raw(part),
                ]));
            } else {
                lines.push(Line::from(vec![
                    Span::raw(" ".repeat(indent)),
                    Span::raw(part),
                ]));
            }
        }
        if !row.reactions.is_empty() {
            lines.push(timeline_reactions_line(&row.reactions, indent));
        }
        for attachment in &row.attachments {
            lines.push(timeline_attachment_line(attachment, indent));
        }
        lines
    }

    /// The rendered height of a timeline row at `width`: the wrapped line count of
    /// its content plus the blank separator row. The separator makes a row's block
    /// height, so the visibility walk and the renderer stay in lockstep.
    pub(crate) fn timeline_row_height(
        row: &TimelineRow,
        selected_account: Option<&AccountRow>,
        width: u16,
    ) -> u16 {
        let lines = timeline_row_lines(row, selected_account);
        let content = if width == 0 {
            lines.len()
        } else {
            Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .line_count(width)
        };
        u16::try_from(content)
            .unwrap_or(u16::MAX)
            .saturating_add(TIMELINE_MESSAGE_SEPARATOR_ROWS)
    }

    /// The rendered height of every row at `width`, for the visibility walk.
    pub(crate) fn timeline_row_heights(
        rows: &[TimelineRow],
        selected_account: Option<&AccountRow>,
        width: u16,
    ) -> Vec<u16> {
        rows.iter()
            .map(|row| timeline_row_height(row, selected_account, width))
            .collect()
    }

    /// Compute the visible message range `(first, last)` (both inclusive, forward
    /// order) for a viewport, given per-row `heights` and the scroll `offset`. The
    /// anchor is `newest - offset`; the walk fills backward from it until the
    /// viewport is full, then renders forward from where it stopped. The anchor is
    /// always included, so a message taller than the viewport still renders (never a
    /// blank pane). `bottom_block_height` reserves rows for a bottom-pinned block
    /// (live stream previews) but only when the anchor is the newest message.
    ///
    /// This is the single algorithm the renderer also uses to draw, so the reported
    /// range and the drawn rows never diverge.
    pub(crate) fn timeline_visible_range(
        heights: &[u16],
        viewport_height: u16,
        offset: usize,
        bottom_block_height: u16,
    ) -> Option<(usize, usize)> {
        let total = heights.len();
        if total == 0 || viewport_height == 0 {
            return None;
        }
        let anchor = total - 1 - offset.min(total - 1);
        let viewport = if anchor == total - 1 {
            viewport_height.saturating_sub(bottom_block_height)
        } else {
            viewport_height
        };
        let viewport = usize::from(viewport.max(1));
        let height = |index: usize| usize::from(heights[index].max(1));

        // Fill backward from the anchor to the topmost row that still fits.
        let mut first = anchor;
        let mut used = height(anchor);
        for index in (0..anchor).rev() {
            let next = used + height(index);
            if next > viewport {
                break;
            }
            used = next;
            first = index;
        }

        // Render forward from `first`, filling the viewport. The anchor always
        // renders (the `index != first` guard), so an oversized message is shown.
        let mut last = first;
        let mut filled = 0;
        for index in first..total {
            let next = filled + height(index);
            if index != first && next > viewport {
                break;
            }
            filled = next;
            last = index;
        }
        Some((first, last))
    }

    /// The author label shown before a timeline message: the sender's display name,
    /// falling back to a shortened id. Color (not "me") signals ownership.
    fn timeline_author_label(row: &TimelineRow) -> String {
        row.from_display_name
            .clone()
            .unwrap_or_else(|| shorten(&row.from, 18))
    }

    /// Whether a timeline row was authored by the selected account (rendered green).
    fn timeline_row_is_self(row: &TimelineRow, selected_account: Option<&AccountRow>) -> bool {
        row.direction == "sent"
            || selected_account.is_some_and(|account| {
                row.from == account.account_id
                    || row.from == account.npub
                    || row.from == account_display_label(account)
            })
    }

    /// Format a Unix timestamp as local wall-clock `HH:MM`. This is the seam the
    /// line builder calls; it depends on the machine's timezone, so tests assert
    /// the `[HH:MM]` shape (fixed 8-column prefix) rather than the value and cover
    /// the arithmetic through the pure `format_hhmm_with_offset` below. Falls back
    /// to UTC when the timestamp is out of `DateTime`'s range.
    fn local_hhmm(timeline_at: u64) -> String {
        chrono::DateTime::from_timestamp(timeline_at as i64, 0)
            .map(|instant| {
                instant
                    .with_timezone(&chrono::Local)
                    .format("%H:%M")
                    .to_string()
            })
            .unwrap_or_else(|| format_hhmm(timeline_at))
    }

    /// Format a Unix timestamp as `HH:MM` in UTC. Pure and deterministic; kept as
    /// the `local_hhmm` fallback and as the zero-offset case of the tested
    /// `format_hhmm_with_offset`.
    fn format_hhmm(timeline_at: u64) -> String {
        format_hhmm_with_offset(timeline_at, 0)
    }

    /// Format a Unix timestamp as `HH:MM` shifted by `offset_seconds` from UTC.
    /// Pure and deterministic (no clock read), so tests can pin an offset and
    /// assert an exact value; `rem_euclid` keeps a negative wall-clock in range.
    pub(crate) fn format_hhmm_with_offset(timeline_at: u64, offset_seconds: i64) -> String {
        let seconds_of_day = (timeline_at as i64 + offset_seconds).rem_euclid(86_400);
        format!(
            "{:02}:{:02}",
            seconds_of_day / 3_600,
            (seconds_of_day % 3_600) / 60
        )
    }

    fn timeline_muted_italic_style() -> Style {
        Style::default()
            .fg(Color::DarkGray)
            .add_modifier(Modifier::ITALIC)
    }

    /// The reply-context line rendered above a reply's content: dark gray italic
    /// `reply to <name>: "<first 30 chars>"`, falling back to a shortened parent id
    /// when the preview is absent.
    fn timeline_reply_line(reply: &TimelineReply, indent: usize) -> Line<'static> {
        let label = match &reply.preview {
            Some(preview) => {
                let name = preview
                    .sender
                    .as_deref()
                    .map(terminal_safe_text)
                    .filter(|sender| !sender.is_empty())
                    .unwrap_or_else(|| {
                        terminal_safe_text(&shorten(&reply.reply_to_message_id, 12))
                    });
                let body = if preview.deleted {
                    "message deleted".to_owned()
                } else {
                    terminal_safe_text(&preview.plaintext)
                };
                let clipped = body.chars().take(30).collect::<String>();
                if body.chars().count() > 30 {
                    format!("reply to {name}: \"{clipped}...\"")
                } else {
                    format!("reply to {name}: \"{clipped}\"")
                }
            }
            None => format!(
                "reply to {}",
                terminal_safe_text(&shorten(&reply.reply_to_message_id, 12))
            ),
        };
        Line::from(vec![
            Span::raw(" ".repeat(indent)),
            Span::styled(label, timeline_muted_italic_style()),
        ])
    }

    /// The reactions line rendered below a message: yellow `<emoji> <count>` pairs
    /// two spaces apart, in the row's deterministic emoji order.
    fn timeline_reactions_line(reactions: &[TimelineReaction], indent: usize) -> Line<'static> {
        let summary = reactions
            .iter()
            .map(|reaction| format!("{} {}", terminal_safe_text(&reaction.emoji), reaction.count))
            .collect::<Vec<_>>()
            .join("  ");
        Line::from(vec![
            Span::raw(" ".repeat(indent)),
            Span::styled(summary, Style::default().fg(Color::Yellow)),
        ])
    }

    /// A placeholder line for a media attachment: `[img name]` for images,
    /// `[file name]` otherwise. Phase 1 renders no inline media.
    fn timeline_attachment_line(attachment: &TimelineAttachment, indent: usize) -> Line<'static> {
        let name = attachment
            .filename
            .as_deref()
            .map(terminal_safe_text)
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| "file".to_owned());
        let label = if attachment
            .mime
            .as_deref()
            .is_some_and(|mime| mime.starts_with("image/"))
        {
            format!("[img {name}]")
        } else {
            format!("[file {name}]")
        };
        Line::from(vec![
            Span::raw(" ".repeat(indent)),
            Span::styled(label, Style::default().fg(Color::DarkGray)),
        ])
    }
}

pub(crate) use timeline::*;

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
        let status = subscription_result_counts_as_unread(result).then(|| {
            let unread_count = unread_counts.entry(group_id.clone()).or_default();
            *unread_count += 1;
            format!(
                "unread message in {}; count={}",
                shorten(&group_id, 18),
                unread_count
            )
        });
        apply_subscription_result(live_previews, result);
        return status;
    }
    apply_subscription_result(live_previews, result)
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

/// Apply one plain `messages subscribe` event to the account-wide live-stream
/// preview state. The materialized-timeline feed owns the messages pane now, so
/// message/reaction/media/delete rows drive nothing here; the plain feed is kept
/// only for what the timeline feed does not carry — the QUIC preview types that
/// render in the pane's bottom block, plus the preview cleanup when an agent
/// stream's final row lands. Unread counting for off-screen groups is the
/// caller's (`apply_tui_subscription_result`) job.
pub(crate) fn apply_subscription_result(
    live_previews: &mut Vec<LiveStreamPreview>,
    result: &Value,
) -> Option<String> {
    match result.get("type").and_then(Value::as_str) {
        Some("agent_stream_final") => {
            let message_value = result.get("message")?;
            let stream_id = message_value
                .get("agent_text_stream")
                .and_then(|stream| value_string(stream, "stream_id"))?;
            let group_id = value_string(message_value, "group_id");
            remove_live_stream_preview(live_previews, group_id.as_deref(), &stream_id);
            None
        }
        Some("message" | "reaction" | "message_delete" | "media") => None,
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

/// Args for the per-group materialized-timeline subscription. Passes `--limit`
/// with the TUI page size so the subscription's initial page matches the
/// snapshot load; without it the daemon's default 50-row page transiently
/// clobbers the snapshot's accurate `has_more_before` (a spurious "loaded 0
/// older message(s)" fetch for 51-100-message groups).
pub(crate) fn timeline_subscription_args(group_id: &str) -> Vec<String> {
    vec![
        "messages".to_owned(),
        "timeline".to_owned(),
        "subscribe".to_owned(),
        group_id.to_owned(),
        "--limit".to_owned(),
        TUI_TIMELINE_PAGE_SIZE.to_string(),
    ]
}
