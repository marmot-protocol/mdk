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

/// Build the `wn` invocation for account setup. `setup_relay` supplies the
/// first-run relay to `create-identity` / `login` through the one relay flag
/// those commands actually accept — the (global, for `create-identity`;
/// command-local, for `login`) `--relay` — appended only when the caller has no
/// other `--relay` source, so it is never passed twice.
pub(crate) fn account_setup_invocation(
    identity: Option<String>,
    setup_relay: Option<String>,
) -> WnInvocation {
    let mut invocation = match identity {
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
    };
    if let Some(relay) = setup_relay.filter(|relay| !relay.trim().is_empty()) {
        invocation.args.push("--relay".to_owned());
        invocation.args.push(relay);
    }
    invocation
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AccountRow {
    pub(crate) account_id: String,
    pub(crate) npub: String,
    pub(crate) display_name: Option<String>,
    pub(crate) local_signing: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ChatRow {
    pub(crate) group_id: String,
    pub(crate) name: String,
    pub(crate) archived: bool,
    /// Runtime-backed unread + last-message projection. Bootstrapped from the
    /// `chats list` row at load, then kept live by the timeline feed's
    /// `chat_list_row` and the `chats mark-read` response. Phase 4 replaced the
    /// TUI-local unread tally with this durable, restart-surviving state.
    pub(crate) projection: ChatProjection,
}

/// The durable chat-list projection carried, key-for-key, on a `chats list`/
/// `subscribe` row, the timeline feed's `chat_list_row`, and the `chats
/// mark-read` response. Parsed tolerantly: a missing or null field takes its
/// empty default so a partial object never fails to parse.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ChatProjection {
    pub(crate) unread_count: usize,
    pub(crate) has_unread: bool,
    pub(crate) last_message: Option<ChatLastMessage>,
    pub(crate) last_read_message_id_hex: Option<String>,
    pub(crate) last_read_timeline_at: Option<u64>,
}

/// The last-message preview embedded in a chat projection (`last_message`). The
/// chat list renders `sender`/`plaintext` and orders by `timeline_at`; `kind`
/// lets a group-system row render its summary instead of raw JSON. Every field
/// is parsed tolerantly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ChatLastMessage {
    pub(crate) sender: Option<String>,
    pub(crate) sender_display_name: Option<String>,
    pub(crate) plaintext: String,
    pub(crate) kind: Option<u64>,
    pub(crate) timeline_at: u64,
    pub(crate) deleted: bool,
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

/// The runtime-wide `notifications subscribe` feed (daemon-only). It is *not*
/// account-scoped: the daemon ignores `--account` and streams every local
/// account's notifications, so the drain filters events by the envelope account
/// against `account_id` before acting on them. `account_id` is the selected
/// account this subscription was opened for (the filter target), not a server
/// key. Same child/reader/Drop lifecycle as the other feeds.
pub(crate) struct NotificationSubscription {
    pub(crate) account_id: String,
    pub(crate) child: Child,
    pub(crate) rx: Receiver<SubscriptionEvent>,
}

impl Drop for NotificationSubscription {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The pane holding keyboard focus in the chat-first main view. The accounts
/// pane is gone in Phase 2; account switching moves to the login/account-select
/// screen (reopened with `A`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Focus {
    Chats,
    Messages,
    Composer,
}

impl Focus {
    pub(crate) fn next(self) -> Self {
        match self {
            Self::Chats => Self::Messages,
            Self::Messages => Self::Composer,
            Self::Composer => Self::Chats,
        }
    }

    pub(crate) fn previous(self) -> Self {
        match self {
            Self::Chats => Self::Composer,
            Self::Messages => Self::Chats,
            Self::Composer => Self::Messages,
        }
    }
}

/// The top-level screen the TUI is showing: the login/account-select flow, the
/// chat-first main view, and the Phase 5 full-view screens (group detail, user
/// search, own profile, relay health). Each non-Main screen is a one-shot load
/// entered by key or slash command; `Esc` returns to Main.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Screen {
    Login(LoginMode),
    Main,
    GroupDetail,
    UserSearch,
    Profile,
    RelayHealth,
}

/// A single modal popup. While one is open it captures every key and the screen
/// behind it sees nothing (routed at the top of `handle_key`, ahead of the
/// screen dispatch). `TuiApp` holds at most one as `Option<Popup>`.
///
/// The variants mirror the spec's interaction groups; the per-purpose enums are
/// what keep the popup count low, so 5b extends by adding purpose variants (and
/// their `PopupSubmit` arms), not new `Popup` shapes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Popup {
    /// Text entry. `Enter` submits when non-empty, `Esc` cancels. Reuses the
    /// composer's `Input` so cursor editing and masking behave identically.
    Text {
        purpose: TextPurpose,
        title: String,
        input: Input,
    },
    /// Confirm. `y`/`Enter` confirms, `n`/`Esc` cancels.
    Confirm {
        purpose: ConfirmPurpose,
        title: String,
        body: Vec<String>,
    },
    /// List picker. `j`/`k` (and arrows) navigate; per-purpose action keys act;
    /// `Esc` closes.
    Picker {
        purpose: PickerPurpose,
        title: String,
        items: Vec<PickerItem>,
        selected: usize,
    },
    /// Dismiss-on-any-key card: help, info, and error surfaces. Any key closes it.
    Card { title: String, body: Vec<String> },
    /// Full-size inline-image viewer (the `o` key). Any key closes it. Holds only
    /// the plaintext hash keying the decoded protocol in `MediaState`; the pixels
    /// live on the app, not in this pure enum.
    Image { title: String, hash: String },
}

/// What a text-entry popup does on submit. The per-purpose design keeps the
/// popup count low: 5b adds profile-field edits, follow-by-pubkey, and the
/// start-a-chat-with-a-found-user name prompt here rather than new `Popup` shapes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum TextPurpose {
    RenameGroup {
        group_id: String,
    },
    AddMemberByPubkey {
        group_id: String,
    },
    /// Edit one own-profile field; publishes only that field on submit.
    EditProfileField {
        field: ProfileField,
    },
    /// Follow a user by npub/hex from the profile screen.
    FollowByPubkey,
    /// Name a new chat started with a found user from the search screen.
    NewChatWithUser {
        pubkey: String,
    },
}

/// What a confirm popup does on `y`/`Enter`. 5b adds unfollow and
/// add-found-user-to-the-current-chat here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ConfirmPurpose {
    RemoveMember { group_id: String, pubkey: String },
    PromoteMember { group_id: String, pubkey: String },
    LeaveGroup { group_id: String },
    Unfollow { pubkey: String },
    AddUserToChat { group_id: String, pubkey: String },
}

/// An editable own-profile field. Each maps to exactly one `profile update`
/// flag, so a single-field edit publishes only that field (the CLI fetches the
/// current profile, overlays the flag, and republishes, preserving the rest).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProfileField {
    Name,
    DisplayName,
    About,
    Picture,
    Nip05,
    Lud16,
}

impl ProfileField {
    /// The six editable fields, in display order.
    pub(crate) const ALL: [ProfileField; 6] = [
        ProfileField::Name,
        ProfileField::DisplayName,
        ProfileField::About,
        ProfileField::Picture,
        ProfileField::Nip05,
        ProfileField::Lud16,
    ];

    /// The `profile update` flag that publishes this field alone.
    pub(crate) fn flag(self) -> &'static str {
        match self {
            ProfileField::Name => "--name",
            ProfileField::DisplayName => "--display-name",
            ProfileField::About => "--about",
            ProfileField::Picture => "--picture",
            ProfileField::Nip05 => "--nip05",
            ProfileField::Lud16 => "--lud16",
        }
    }

    /// The human label shown in the profile screen and the edit popup title.
    pub(crate) fn label(self) -> &'static str {
        match self {
            ProfileField::Name => "name",
            ProfileField::DisplayName => "display name",
            ProfileField::About => "about",
            ProfileField::Picture => "picture",
            ProfileField::Nip05 => "nip05",
            ProfileField::Lud16 => "lud16",
        }
    }
}

/// What a list picker acts on. Extends for 5b (group picker for user search).
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PickerPurpose {
    Invites,
}

/// One row of a list-picker popup: an opaque id the action targets plus a
/// display label. For invites, `id` is the group id.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PickerItem {
    pub(crate) id: String,
    pub(crate) label: String,
}

/// The outcome of routing one key into an open popup. `None` means the popup
/// handled the key internally (edit/navigate) and stays open; `Dismiss` closes
/// it with no side effect; `Submit` closes it and asks the app to run one CLI
/// call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PopupAction {
    None,
    Dismiss,
    Submit(PopupSubmit),
}

/// A resolved popup submission: exactly one CLI call, chosen by mapping the
/// popup's purpose plus its captured value. The app executes it; canceling
/// produces no `PopupSubmit` at all.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PopupSubmit {
    RenameGroup { group_id: String, name: String },
    AddMember { group_id: String, pubkey: String },
    RemoveMember { group_id: String, pubkey: String },
    PromoteMember { group_id: String, pubkey: String },
    LeaveGroup { group_id: String },
    AcceptInvite { group_id: String },
    DeclineInvite { group_id: String },
    UpdateProfileField { field: ProfileField, value: String },
    FollowUser { pubkey: String },
    Unfollow { pubkey: String },
    NewChat { name: String, pubkey: String },
    AddUserToChat { group_id: String, pubkey: String },
}

impl Popup {
    /// The help card: dismiss-on-any-key, so `q` under it closes the card instead
    /// of quitting the app (the pre-popup help overlay had that bug).
    pub(crate) fn help() -> Self {
        Popup::Card {
            title: "Help".to_owned(),
            body: help_card_lines(),
        }
    }

    /// A dismiss-on-any-key info card with a single-line body.
    pub(crate) fn info(title: &str, message: &str) -> Self {
        Popup::Card {
            title: title.to_owned(),
            body: vec![message.to_owned()],
        }
    }

    /// The pending-invites list picker. Shared by the initial open and the
    /// after-action refold so the title/purpose live in one place.
    pub(crate) fn invites(items: Vec<PickerItem>, selected: usize) -> Self {
        Popup::Picker {
            purpose: PickerPurpose::Invites,
            title: "Pending Invites".to_owned(),
            items,
            selected,
        }
    }

    /// The card/confirm title (only these variants carry a shown title).
    pub(crate) fn title(&self) -> &str {
        match self {
            Popup::Text { title, .. }
            | Popup::Confirm { title, .. }
            | Popup::Picker { title, .. }
            | Popup::Card { title, .. }
            | Popup::Image { title, .. } => title,
        }
    }
}

/// Route one key into an open popup, mutating its editing/navigation state in
/// place and returning the resulting action. Pure over the popup and key so the
/// capture-all-keys and submit/cancel flows are reducer-tested without a process.
pub(crate) fn popup_key(popup: &mut Popup, key: KeyCode) -> PopupAction {
    match popup {
        // Any key dismisses a card or the image viewer. This is what makes `q`
        // under help safe.
        Popup::Card { .. } | Popup::Image { .. } => PopupAction::Dismiss,
        Popup::Text { purpose, input, .. } => match key {
            KeyCode::Enter => {
                let value = input.value().trim().to_owned();
                if value.is_empty() {
                    PopupAction::None
                } else {
                    PopupAction::Submit(text_purpose_submit(purpose, value))
                }
            }
            KeyCode::Esc => PopupAction::Dismiss,
            KeyCode::Backspace => {
                input.backspace();
                PopupAction::None
            }
            KeyCode::Delete => {
                input.delete();
                PopupAction::None
            }
            KeyCode::Left => {
                input.left();
                PopupAction::None
            }
            KeyCode::Right => {
                input.right();
                PopupAction::None
            }
            KeyCode::Home => {
                input.home();
                PopupAction::None
            }
            KeyCode::End => {
                input.end();
                PopupAction::None
            }
            KeyCode::Char(character) => {
                input.insert(character);
                PopupAction::None
            }
            _ => PopupAction::None,
        },
        Popup::Confirm { purpose, .. } => match key {
            KeyCode::Char('y') | KeyCode::Enter => {
                PopupAction::Submit(confirm_purpose_submit(purpose))
            }
            KeyCode::Char('n') | KeyCode::Esc => PopupAction::Dismiss,
            _ => PopupAction::None,
        },
        Popup::Picker {
            purpose,
            items,
            selected,
            ..
        } => match key {
            KeyCode::Up | KeyCode::Char('k') => {
                *selected = selected.saturating_sub(1);
                PopupAction::None
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if *selected + 1 < items.len() {
                    *selected += 1;
                }
                PopupAction::None
            }
            KeyCode::Esc => PopupAction::Dismiss,
            _ => picker_purpose_action(purpose, items.get(*selected), key),
        },
    }
}

fn text_purpose_submit(purpose: &TextPurpose, value: String) -> PopupSubmit {
    match purpose {
        TextPurpose::RenameGroup { group_id } => PopupSubmit::RenameGroup {
            group_id: group_id.clone(),
            name: value,
        },
        TextPurpose::AddMemberByPubkey { group_id } => PopupSubmit::AddMember {
            group_id: group_id.clone(),
            pubkey: value,
        },
        TextPurpose::EditProfileField { field } => PopupSubmit::UpdateProfileField {
            field: *field,
            value,
        },
        TextPurpose::FollowByPubkey => PopupSubmit::FollowUser { pubkey: value },
        TextPurpose::NewChatWithUser { pubkey } => PopupSubmit::NewChat {
            name: value,
            pubkey: pubkey.clone(),
        },
    }
}

fn confirm_purpose_submit(purpose: &ConfirmPurpose) -> PopupSubmit {
    match purpose {
        ConfirmPurpose::RemoveMember { group_id, pubkey } => PopupSubmit::RemoveMember {
            group_id: group_id.clone(),
            pubkey: pubkey.clone(),
        },
        ConfirmPurpose::PromoteMember { group_id, pubkey } => PopupSubmit::PromoteMember {
            group_id: group_id.clone(),
            pubkey: pubkey.clone(),
        },
        ConfirmPurpose::LeaveGroup { group_id } => PopupSubmit::LeaveGroup {
            group_id: group_id.clone(),
        },
        ConfirmPurpose::Unfollow { pubkey } => PopupSubmit::Unfollow {
            pubkey: pubkey.clone(),
        },
        ConfirmPurpose::AddUserToChat { group_id, pubkey } => PopupSubmit::AddUserToChat {
            group_id: group_id.clone(),
            pubkey: pubkey.clone(),
        },
    }
}

fn picker_purpose_action(
    purpose: &PickerPurpose,
    item: Option<&PickerItem>,
    key: KeyCode,
) -> PopupAction {
    let Some(item) = item else {
        return PopupAction::None;
    };
    match purpose {
        PickerPurpose::Invites => match key {
            KeyCode::Char('a') | KeyCode::Enter => PopupAction::Submit(PopupSubmit::AcceptInvite {
                group_id: item.id.clone(),
            }),
            KeyCode::Char('d') => PopupAction::Submit(PopupSubmit::DeclineInvite {
                group_id: item.id.clone(),
            }),
            _ => PopupAction::None,
        },
    }
}

/// The bottom `[key] action` hint row for a popup, chosen by its interaction
/// group. Kept in lockstep with `popup_key`.
pub(crate) fn popup_hint(popup: &Popup) -> &'static str {
    match popup {
        Popup::Text { .. } => "[Enter] submit  [Esc] cancel",
        Popup::Confirm { .. } => "[y] yes  [n] no",
        Popup::Picker {
            purpose: PickerPurpose::Invites,
            ..
        } => "[a] accept  [d] decline  [j/k] move  [Esc] close",
        Popup::Card { .. } | Popup::Image { .. } => "[any key] dismiss",
    }
}

/// The help-card body, mirrored by the README "TUI" section and the hints lines.
pub(crate) fn help_card_lines() -> Vec<String> {
    [
        "Chats + messages fill the screen; the composer, hints, and status sit below.",
        "Tab/BackTab cycle chats, messages, and composer. Ctrl-C quits.",
        "Chats: j/k move; Enter opens; g detail; s search; p profile; h relays; I invites; A accounts.",
        "Messages: j/k or arrows move; PageUp/PageDown page; G/g newest/oldest.",
        "On the selected message: r react (Enter sends +), u unreact, d delete, R reply.",
        "Composer: cursor editing (arrows/Home/End, Backspace/Delete); Enter sends.",
        "Group detail: j/k move; A add member; x remove; P promote; R rename; L leave.",
        "User search: type + Enter searches; Enter opens a card; c chat; a add to open chat.",
        "Profile: j/k move; Enter edits a field; f follow; x unfollow. Relay health: r refresh.",
        "Popups capture every key; Esc or the shown key closes them.",
        "",
        "/refresh   /diagnostics   /account <npub-or-hex>   /create-identity",
        "/login <nsec-or-npub>   /daemon status|start|stop   /users [query]",
        "/chat new|rename|describe|archive|unarchive|archived",
        "/members add|remove|list   /react [emoji]   /unreact   /delete   /reply <text>   /retry <id>",
        "/keys fetch|rotate   /profile name <display-name>   /quit",
    ]
    .iter()
    .map(|line| (*line).to_owned())
    .collect()
}

/// The exact admin-leave-guard messages, kept as constants so the guard branches
/// and the tests reference one source of truth (verbatim from wn-tui's final
/// commit).
pub(crate) const CANNOT_LEAVE_TITLE: &str = "Cannot Leave Group";
pub(crate) const LEAVE_SOLE_ADMIN_MESSAGE: &str =
    "You're the only admin. Promote another member to admin before you can leave.";
pub(crate) const LEAVE_CO_ADMIN_MESSAGE: &str =
    "You're an admin of this group. Step down as admin before leaving.";

/// The client-side leave guard: an admin cannot leave. `Blocked` carries the
/// exact info-card body; a non-admin gets the normal confirm.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum LeaveDecision {
    Blocked(&'static str),
    Confirm,
}

pub(crate) fn leave_group_decision(account_is_admin: bool, admin_count: usize) -> LeaveDecision {
    if !account_is_admin {
        return LeaveDecision::Confirm;
    }
    if admin_count <= 1 {
        LeaveDecision::Blocked(LEAVE_SOLE_ADMIN_MESSAGE)
    } else {
        LeaveDecision::Blocked(LEAVE_CO_ADMIN_MESSAGE)
    }
}

/// The loaded group-detail screen state. Owned as `Option<GroupDetailView>` and
/// dropped when leaving the screen (no per-view subscriptions to tear down; the
/// data is a one-shot load).
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GroupDetailView {
    pub(crate) group_id: String,
    pub(crate) name: String,
    pub(crate) description: String,
    pub(crate) members: Vec<GroupMemberRow>,
    pub(crate) relays: Vec<String>,
    pub(crate) account_is_admin: bool,
    pub(crate) admin_count: usize,
    pub(crate) selected: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GroupMemberRow {
    pub(crate) member_id: String,
    pub(crate) npub: String,
    pub(crate) is_admin: bool,
    pub(crate) is_self: bool,
}

impl GroupDetailView {
    pub(crate) fn select_up(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    pub(crate) fn select_down(&mut self) {
        if self.selected + 1 < self.members.len() {
            self.selected += 1;
        }
    }

    pub(crate) fn selected_member(&self) -> Option<&GroupMemberRow> {
        self.members.get(self.selected)
    }
}

/// Combine a group's members with its admin set into the group-detail view,
/// tagging each member with admin/self flags and deriving the account's own
/// admin status and the admin count that the leave guard needs.
pub(crate) fn build_group_detail(
    group_id: &str,
    name: &str,
    description: &str,
    members: &[(String, String)],
    admin_ids: &[String],
    relays: &[String],
    self_account_id: &str,
) -> GroupDetailView {
    let members = members
        .iter()
        .map(|(member_id, npub)| GroupMemberRow {
            member_id: member_id.clone(),
            npub: npub.clone(),
            is_admin: admin_ids.iter().any(|admin| admin == member_id),
            is_self: member_id == self_account_id,
        })
        .collect();
    GroupDetailView {
        group_id: group_id.to_owned(),
        name: name.to_owned(),
        description: description.to_owned(),
        members,
        relays: relays.to_vec(),
        account_is_admin: admin_ids.iter().any(|admin| admin == self_account_id),
        admin_count: admin_ids.len(),
        selected: 0,
    }
}

/// Parse `(member_id_hex, npub)` pairs from a `groups members` result.
pub(crate) fn parse_group_members(result: &Value) -> Vec<(String, String)> {
    result
        .get("members")
        .and_then(Value::as_array)
        .map(|members| {
            members
                .iter()
                .filter_map(|member| {
                    Some((
                        value_string(member, "member_id")?,
                        value_string(member, "npub").unwrap_or_default(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Parse admin account-id hex strings from a `groups admins` result.
pub(crate) fn parse_group_admins(result: &Value) -> Vec<String> {
    result
        .get("admins")
        .and_then(Value::as_array)
        .map(|admins| {
            admins
                .iter()
                .filter_map(|admin| value_string(admin, "admin_id"))
                .collect()
        })
        .unwrap_or_default()
}

/// Parse relay hint strings from a `groups relays` result.
pub(crate) fn parse_group_relays(result: &Value) -> Vec<String> {
    result
        .get("relays")
        .and_then(Value::as_array)
        .map(|relays| {
            relays
                .iter()
                .filter_map(Value::as_str)
                .filter(|relay| !relay.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Parse `(name, description)` from a `groups show` result's `profile` object.
pub(crate) fn parse_group_profile(result: &Value) -> Option<(String, String)> {
    let profile = result.get("profile")?;
    Some((
        value_string(profile, "name").unwrap_or_else(|| "unnamed".to_owned()),
        value_string(profile, "description").unwrap_or_default(),
    ))
}

/// Parse the pending-invite rows from a `groups invites` result into picker
/// items: chat rows with `pending_confirmation: true`, id = group id.
pub(crate) fn parse_invite_items(result: &Value) -> Vec<PickerItem> {
    result
        .get("invites")
        .and_then(Value::as_array)
        .map(|invites| {
            invites
                .iter()
                .filter(|invite| {
                    invite
                        .get("pending_confirmation")
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
                })
                .filter_map(parse_chat)
                .map(|chat| PickerItem {
                    id: chat.group_id,
                    label: chat.name,
                })
                .collect()
        })
        .unwrap_or_default()
}

// ---- Phase 5b: user search, profile, and relay health screens ----

/// Which region of the user-search screen has the keys. The screen has two
/// regions (a query field and a result list) and one editable text sink, so a
/// two-state focus disambiguates `Enter` (run the query vs open the selected
/// result) without overloading it: in `Query` focus typing edits the query and
/// `Enter` runs the search; in `Results` focus `j`/`k` navigate and `Enter`
/// opens the selected user's profile card.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UserSearchFocus {
    Query,
    Results,
}

/// One `users search` result row: the profile display fields plus the match
/// attribution (`matched_field`/`match_quality`/`radius`) the CLI returns.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UserSearchResultRow {
    pub(crate) pubkey: String,
    pub(crate) npub: String,
    pub(crate) display_name: Option<String>,
    pub(crate) matched_field: String,
    pub(crate) match_quality: String,
    pub(crate) radius: u8,
}

impl UserSearchResultRow {
    /// The primary label: the display/name, else a shortened npub.
    pub(crate) fn display_label(&self) -> String {
        self.display_name
            .clone()
            .unwrap_or_else(|| shorten(&self.npub, 16))
    }
}

/// The user-search screen state: a reusable query [`Input`], the one-shot
/// results, the selection, and which region has focus. `users search` is a
/// one-shot call (no streaming), so the results only change on `Enter`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UserSearchView {
    pub(crate) query: Input,
    pub(crate) results: Vec<UserSearchResultRow>,
    pub(crate) selected: usize,
    pub(crate) focus: UserSearchFocus,
}

impl Default for UserSearchView {
    fn default() -> Self {
        Self {
            query: Input::default(),
            results: Vec::new(),
            selected: 0,
            focus: UserSearchFocus::Query,
        }
    }
}

impl UserSearchView {
    pub(crate) fn select_up(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    pub(crate) fn select_down(&mut self) {
        if self.selected + 1 < self.results.len() {
            self.selected += 1;
        }
    }

    pub(crate) fn selected_result(&self) -> Option<&UserSearchResultRow> {
        self.results.get(self.selected)
    }
}

/// Parse `users search` result rows from the `users` array.
pub(crate) fn parse_user_search_results(result: &Value) -> Vec<UserSearchResultRow> {
    result
        .get("users")
        .and_then(Value::as_array)
        .map(|users| users.iter().filter_map(parse_user_search_result).collect())
        .unwrap_or_default()
}

fn parse_user_search_result(value: &Value) -> Option<UserSearchResultRow> {
    let pubkey =
        value_string(value, "account_id_hex").or_else(|| value_string(value, "account_id"))?;
    let profile = value.get("profile");
    let display_name = profile
        .and_then(|profile| non_empty_value_string(profile, "display_name"))
        .or_else(|| profile.and_then(|profile| non_empty_value_string(profile, "name")));
    Some(UserSearchResultRow {
        pubkey,
        npub: value_string(value, "npub").unwrap_or_default(),
        display_name,
        matched_field: value_string(value, "matched_field").unwrap_or_default(),
        match_quality: value_string(value, "match_quality").unwrap_or_default(),
        radius: value
            .get("radius")
            .and_then(Value::as_u64)
            .unwrap_or_default() as u8,
    })
}

/// The dismiss-on-any-key profile card body for a `users show` result. Picture
/// URLs render as literal text (no fetch — remote avatars are out per the TUI
/// decisions). Every field passes through `terminal_safe_text`.
pub(crate) fn profile_card_lines(result: &Value) -> Vec<String> {
    let user = result.get("user").unwrap_or(result);
    let profile = user.get("profile");
    let mut lines = Vec::new();
    if let Some(name) = profile
        .and_then(|profile| non_empty_value_string(profile, "display_name"))
        .or_else(|| profile.and_then(|profile| non_empty_value_string(profile, "name")))
    {
        lines.push(terminal_safe_text(&name));
    }
    if let Some(npub) = non_empty_value_string(user, "npub") {
        lines.push(format!("npub {}", terminal_safe_text(&shorten(&npub, 24))));
    }
    for (label, key) in [
        ("about", "about"),
        ("nip05", "nip05"),
        ("lud16", "lud16"),
        ("picture", "picture"),
    ] {
        if let Some(value) = profile.and_then(|profile| non_empty_value_string(profile, key)) {
            lines.push(format!("{label}: {}", terminal_safe_text(&value)));
        }
    }
    let follows = user
        .get("follows")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    lines.push(format!("follows: {follows}"));
    if lines.is_empty() {
        lines.push("no profile metadata".to_owned());
    }
    lines
}

/// A selectable target on the profile screen: one of the six editable fields or
/// one follow row. The screen threads a single cursor over the fields then the
/// follows so `Enter`/`x`/`f` know what they act on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProfileTarget {
    Field(ProfileField),
    Follow(usize),
}

/// The own-profile screen state: the npub, the six editable fields (indexed by
/// [`ProfileField::ALL`] order), the follow list (npubs), and a single cursor
/// over fields-then-follows.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ProfileView {
    pub(crate) npub: String,
    pub(crate) fields: [Option<String>; 6],
    pub(crate) follows: Vec<String>,
    pub(crate) selected: usize,
}

impl ProfileView {
    /// Selectable rows: the six fields plus each follow.
    pub(crate) fn row_count(&self) -> usize {
        ProfileField::ALL.len() + self.follows.len()
    }

    pub(crate) fn field_value(&self, field: ProfileField) -> Option<&str> {
        let index = ProfileField::ALL.iter().position(|f| *f == field)?;
        self.fields[index].as_deref()
    }

    pub(crate) fn select_up(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    pub(crate) fn select_down(&mut self) {
        if self.selected + 1 < self.row_count() {
            self.selected += 1;
        }
    }

    /// Resolve the cursor to a field or a follow row.
    pub(crate) fn selected_target(&self) -> Option<ProfileTarget> {
        let fields = ProfileField::ALL.len();
        if self.selected < fields {
            Some(ProfileTarget::Field(ProfileField::ALL[self.selected]))
        } else {
            let follow = self.selected - fields;
            (follow < self.follows.len()).then_some(ProfileTarget::Follow(follow))
        }
    }
}

/// Build the profile view from a `profile show` result and a `follows list`
/// result. Absent fields stay `None`; the follow list keeps npubs.
pub(crate) fn parse_profile_view(show: &Value, follows: &Value) -> ProfileView {
    let profile = show.get("profile");
    let field = |key: &str| profile.and_then(|profile| non_empty_value_string(profile, key));
    ProfileView {
        npub: value_string(show, "npub").unwrap_or_default(),
        fields: [
            field("name"),
            field("display_name"),
            field("about"),
            field("picture"),
            field("nip05"),
            field("lud16"),
        ],
        follows: parse_follow_npubs(follows),
        selected: 0,
    }
}

/// Parse the follow npubs from a `follows list` result's `follows` array.
pub(crate) fn parse_follow_npubs(result: &Value) -> Vec<String> {
    result
        .get("follows")
        .and_then(Value::as_array)
        .map(|follows| {
            follows
                .iter()
                .filter_map(|follow| {
                    value_string(follow, "npub").or_else(|| value_string(follow, "account_id"))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// One relay's redacted health row, keyed by opaque device-local index. No relay
/// URL exists in the source; the index is all that identifies a relay here.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct RelayHealthRow {
    pub(crate) relay_index: u32,
    pub(crate) first_deliverer: String,
    pub(crate) delivered_first: u64,
    pub(crate) delivered_later: u64,
    pub(crate) first_event_p50: String,
    pub(crate) eose_p50: String,
}

/// The parsed, redacted `relay-stats` snapshot the health screen renders. All
/// per-relay attribution is keyed by opaque index; there are no relay URLs in
/// the source and none are stored here (decision 3).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct RelayHealthData {
    pub(crate) daemon_running: bool,
    pub(crate) active_accounts: u64,
    pub(crate) active_group_subscriptions: u64,
    pub(crate) subscriptions_created: u64,
    pub(crate) subscriptions_removed: u64,
    pub(crate) inbound_seen: u64,
    pub(crate) inbound_delivered: u64,
    pub(crate) inbound_dropped: u64,
    pub(crate) publish_attempts: u64,
    pub(crate) publish_successes: u64,
    pub(crate) publish_failures: u64,
    pub(crate) observed: u64,
    pub(crate) corroborated: u64,
    pub(crate) single_source: u64,
    pub(crate) spread_samples: u64,
    pub(crate) spread_p50: String,
    pub(crate) spread_p99: String,
    pub(crate) tracked_subscriptions: u64,
    pub(crate) synced_subscriptions: u64,
    pub(crate) first_event_p50: String,
    pub(crate) eose_p50: String,
    pub(crate) sdk_backed: bool,
    pub(crate) total_relays: u64,
    pub(crate) connected: u64,
    pub(crate) connecting: u64,
    pub(crate) disconnected: u64,
    pub(crate) connection_attempts: u64,
    pub(crate) connection_successes: u64,
    pub(crate) per_relay: Vec<RelayHealthRow>,
}

/// The relay-health screen state: the parsed snapshot and a line scroll offset.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct RelayHealthView {
    pub(crate) data: RelayHealthData,
    pub(crate) scroll: u16,
}

fn u64_at(value: &Value, key: &str) -> u64 {
    value.get(key).and_then(Value::as_u64).unwrap_or_default()
}

/// The upper bound (in ms) of the bucket a percentile falls in, mirroring the
/// `relay-stats` CLI: `n/a` with no samples, `>Nms` when the percentile lands in
/// the overflow region above the largest bucket, else `Nms`. Honest about what
/// fixed-bucket histograms support — no interpolated value is invented.
pub(crate) fn histogram_percentile_label(histogram: &Value, percentile: f64) -> String {
    let buckets: Vec<(u64, u64)> = histogram
        .get("buckets")
        .and_then(Value::as_array)
        .map(|buckets| {
            buckets
                .iter()
                .filter_map(|bucket| {
                    Some((
                        bucket.get("upper_bound_ms")?.as_u64()?,
                        bucket.get("count")?.as_u64()?,
                    ))
                })
                .collect()
        })
        .unwrap_or_default();
    let overflow = u64_at(histogram, "overflow_count");
    let total = buckets.iter().map(|(_, count)| count).sum::<u64>() + overflow;
    if total == 0 {
        return "n/a".to_owned();
    }
    let target = ((percentile.clamp(0.0, 1.0) * total as f64).ceil() as u64).max(1);
    let mut cumulative = 0;
    for (bound, count) in &buckets {
        cumulative += count;
        if cumulative >= target {
            return format!("{bound}ms");
        }
    }
    match buckets.last() {
        Some((bound, _)) => format!(">{bound}ms"),
        None => "n/a".to_owned(),
    }
}

fn first_deliverer_label(delivered_first: u64, delivered_later: u64) -> String {
    let total = delivered_first + delivered_later;
    if total == 0 {
        "n/a".to_owned()
    } else {
        format!("{:.0}%", delivered_first as f64 / total as f64 * 100.0)
    }
}

/// Parse the redacted `relay-stats` snapshot into the health-screen view model.
/// Reads only counters, opaque relay indices, and millisecond histograms — never
/// any relay URL (there are none in the source).
pub(crate) fn parse_relay_health(result: &Value, daemon_running: bool) -> RelayHealthData {
    let metrics = result.get("metrics").cloned().unwrap_or(Value::Null);
    let spread = result
        .get("delivery_spread")
        .cloned()
        .unwrap_or(Value::Null);
    let sync = result.get("sync").cloned().unwrap_or(Value::Null);
    let health = result.get("health").cloned().unwrap_or(Value::Null);
    let spread_hist = spread.get("spread").cloned().unwrap_or(Value::Null);
    let first_event = sync.get("first_event").cloned().unwrap_or(Value::Null);
    let eose = sync.get("eose").cloned().unwrap_or(Value::Null);

    let per_relay = build_relay_health_rows(&spread, &sync);

    RelayHealthData {
        daemon_running,
        active_accounts: u64_at(&metrics, "active_accounts"),
        active_group_subscriptions: u64_at(&metrics, "active_group_subscriptions"),
        subscriptions_created: u64_at(&metrics, "subscriptions_created"),
        subscriptions_removed: u64_at(&metrics, "subscriptions_removed"),
        inbound_seen: u64_at(&metrics, "inbound_events_seen"),
        inbound_delivered: u64_at(&metrics, "inbound_events_delivered"),
        inbound_dropped: u64_at(&metrics, "inbound_events_dropped"),
        publish_attempts: u64_at(&metrics, "publish_attempts"),
        publish_successes: u64_at(&metrics, "publish_successes"),
        publish_failures: u64_at(&metrics, "publish_failures"),
        observed: u64_at(&spread, "observed"),
        corroborated: u64_at(&spread, "corroborated"),
        single_source: u64_at(&spread, "single_source"),
        spread_samples: histogram_sample_count(&spread_hist),
        spread_p50: histogram_percentile_label(&spread_hist, 0.5),
        spread_p99: histogram_percentile_label(&spread_hist, 0.99),
        tracked_subscriptions: u64_at(&sync, "tracked_subscriptions"),
        synced_subscriptions: u64_at(&sync, "synced_subscriptions"),
        first_event_p50: histogram_percentile_label(&first_event, 0.5),
        eose_p50: histogram_percentile_label(&eose, 0.5),
        sdk_backed: health
            .get("sdk_backed")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        total_relays: u64_at(&health, "total_relays"),
        connected: u64_at(&health, "connected"),
        connecting: u64_at(&health, "connecting"),
        disconnected: u64_at(&health, "disconnected"),
        connection_attempts: u64_at(&health, "connection_attempts"),
        connection_successes: u64_at(&health, "connection_successes"),
        per_relay,
    }
}

fn relay_row_by_index(rows: Option<&Vec<Value>>, index: u32) -> Option<&Value> {
    rows?
        .iter()
        .find(|row| row.get("relay_index").and_then(Value::as_u64) == Some(u64::from(index)))
}

fn histogram_sample_count(histogram: &Value) -> u64 {
    let buckets = histogram
        .get("buckets")
        .and_then(Value::as_array)
        .map(|buckets| buckets.iter().map(|bucket| u64_at(bucket, "count")).sum())
        .unwrap_or(0);
    buckets + u64_at(histogram, "overflow_count")
}

/// Join the per-relay delivery attribution and sync-timing rows by opaque relay
/// index, mirroring the `relay-stats` CLI's per-relay rows.
fn build_relay_health_rows(spread: &Value, sync: &Value) -> Vec<RelayHealthRow> {
    let delivery = spread.get("per_relay").and_then(Value::as_array);
    let latency = sync.get("per_relay").and_then(Value::as_array);
    let mut indices: Vec<u32> = delivery
        .into_iter()
        .flatten()
        .chain(latency.into_iter().flatten())
        .filter_map(|row| row.get("relay_index").and_then(Value::as_u64))
        .map(|index| index as u32)
        .collect();
    indices.sort_unstable();
    indices.dedup();

    indices
        .into_iter()
        .map(|index| {
            let delivery_row = relay_row_by_index(delivery, index);
            let latency_row = relay_row_by_index(latency, index);
            let delivered_first = delivery_row
                .map(|row| u64_at(row, "delivered_first"))
                .unwrap_or(0);
            let delivered_later = delivery_row
                .map(|row| u64_at(row, "delivered_later"))
                .unwrap_or(0);
            RelayHealthRow {
                relay_index: index,
                first_deliverer: first_deliverer_label(delivered_first, delivered_later),
                delivered_first,
                delivered_later,
                first_event_p50: latency_row
                    .map(|row| {
                        histogram_percentile_label(
                            row.get("first_event").unwrap_or(&Value::Null),
                            0.5,
                        )
                    })
                    .unwrap_or_else(|| "n/a".to_owned()),
                eose_p50: latency_row
                    .map(|row| {
                        histogram_percentile_label(row.get("eose").unwrap_or(&Value::Null), 0.5)
                    })
                    .unwrap_or_else(|| "n/a".to_owned()),
            }
        })
        .collect()
}

/// The user-search hints line, keyed by the screen's internal focus (the shared
/// `hints_line` cannot see it, so `render_hints` calls this for the search screen).
pub(crate) fn user_search_hint(focus: UserSearchFocus) -> &'static str {
    match focus {
        UserSearchFocus::Query => "type query  Enter search  Down results  Esc back",
        UserSearchFocus::Results => "j/k move  Enter profile  c chat  a add  i query  Esc back",
    }
}

/// The three states of the login screen: the create/login menu (no accounts),
/// the account picker (several accounts), and the masked nsec entry field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LoginMode {
    Menu,
    AccountSelect,
    NsecEntry,
}

/// Route the startup screen from the number of loaded accounts: no accounts
/// opens the login menu, exactly one drops straight into the main view with it
/// selected, and several open the account picker — unless `initial_selected` is
/// set (a `--account`/`WN_ACCOUNT` selector resolved to a loaded account), which
/// enters the main view directly with that account.
pub(crate) fn startup_screen(account_count: usize, initial_selected: bool) -> Screen {
    match account_count {
        0 => Screen::Login(LoginMode::Menu),
        1 => Screen::Main,
        _ if initial_selected => Screen::Main,
        _ => Screen::Login(LoginMode::AccountSelect),
    }
}

/// The login mode to return to when leaving nsec entry: the menu when there are
/// no accounts yet, otherwise the account picker (the two screens that open it).
pub(crate) fn login_mode_for_accounts(account_count: usize) -> LoginMode {
    if account_count == 0 {
        LoginMode::Menu
    } else {
        LoginMode::AccountSelect
    }
}

/// Render a secret as one `*` per character, preserving length without exposing
/// the value. Used for the nsec-entry field (key material never renders).
pub(crate) fn masked_secret(value: &str) -> String {
    "*".repeat(value.chars().count())
}

/// The composer's text-editing model: a value, a char-index cursor, and a masked
/// flag. Indexing by char (not byte) keeps multi-byte UTF-8 intact for insert,
/// delete, and cursor movement. It is not grapheme-cluster aware — a ZWJ emoji is
/// several cursor stops — which matches the ported wn-tui `Input` behavior.
/// Masked mode renders one `*` per char while preserving the value; the login
/// nsec-entry field reuses it so key material never renders.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct Input {
    value: String,
    cursor: usize,
    masked: bool,
}

impl Input {
    /// The raw edited value (never rendered directly when masked).
    pub(crate) fn value(&self) -> &str {
        &self.value
    }

    /// The cursor position as a char index in `0..=char_count`.
    pub(crate) fn cursor(&self) -> usize {
        self.cursor
    }

    pub(crate) fn set_masked(&mut self, masked: bool) {
        self.masked = masked;
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    /// The char count of the value; the cursor's upper bound.
    fn char_len(&self) -> usize {
        self.value.chars().count()
    }

    /// The display string: `*` per char when masked, otherwise the value.
    pub(crate) fn display(&self) -> String {
        if self.masked {
            masked_secret(&self.value)
        } else {
            self.value.clone()
        }
    }

    /// The byte offset of char index `char_index`, clamped to the value's end so a
    /// cursor at (or past) the end splices at the tail.
    fn byte_offset(&self, char_index: usize) -> usize {
        self.value
            .char_indices()
            .nth(char_index)
            .map_or(self.value.len(), |(offset, _)| offset)
    }

    /// Replace the value and place the cursor at the end. Backs the accelerator
    /// prefills (`/react `, `/delete`).
    pub(crate) fn set_value(&mut self, value: impl Into<String>) {
        self.value = value.into();
        self.cursor = self.char_len();
    }

    pub(crate) fn clear(&mut self) {
        self.value.clear();
        self.cursor = 0;
    }

    /// Insert a char at the cursor and advance past it.
    pub(crate) fn insert(&mut self, ch: char) {
        let at = self.byte_offset(self.cursor);
        self.value.insert(at, ch);
        self.cursor += 1;
    }

    /// Insert a whole string at the cursor (paste), advancing past it. Multi-byte
    /// and multi-line content is inserted verbatim.
    pub(crate) fn insert_str(&mut self, text: &str) {
        let at = self.byte_offset(self.cursor);
        self.value.insert_str(at, text);
        self.cursor += text.chars().count();
    }

    /// Delete the char before the cursor (Backspace).
    pub(crate) fn backspace(&mut self) {
        if self.cursor == 0 {
            return;
        }
        let start = self.byte_offset(self.cursor - 1);
        let end = self.byte_offset(self.cursor);
        self.value.replace_range(start..end, "");
        self.cursor -= 1;
    }

    /// Delete the char at the cursor (Delete/forward-delete).
    pub(crate) fn delete(&mut self) {
        if self.cursor >= self.char_len() {
            return;
        }
        let start = self.byte_offset(self.cursor);
        let end = self.byte_offset(self.cursor + 1);
        self.value.replace_range(start..end, "");
    }

    pub(crate) fn left(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    pub(crate) fn right(&mut self) {
        self.cursor = (self.cursor + 1).min(self.char_len());
    }

    pub(crate) fn home(&mut self) {
        self.cursor = 0;
    }

    pub(crate) fn end(&mut self) {
        self.cursor = self.char_len();
    }
}

/// The one-line status bar for the main view:
/// `{account} · daemon {on|off} · {n} chats · {u} unread · {latest status}`.
/// Untrusted fields (the account label and the status message) pass through
/// `terminal_safe_text`, and the assembled line is shortened to `width`.
pub(crate) fn status_bar_line(
    account_label: &str,
    daemon_running: bool,
    chats: usize,
    unread: usize,
    status: &str,
    width: usize,
) -> String {
    let account = shorten(&terminal_safe_text(account_label), 24);
    let daemon = if daemon_running { "on" } else { "off" };
    let status = terminal_safe_text(status);
    let line = format!("{account} · daemon {daemon} · {chats} chats · {unread} unread · {status}");
    shorten(&line, width)
}

/// The per-screen, per-focus hints line. Terse and kept in lockstep with the
/// real keymap (the README and in-app help mirror these strings). `entered_main`
/// gates the account picker's `Esc back` hint: `Esc` only returns to the main
/// view when a session is already active, so the startup picker omits it.
pub(crate) fn hints_line(screen: Screen, focus: Focus, entered_main: bool) -> &'static str {
    match screen {
        Screen::Login(LoginMode::Menu) => "c create identity  l nsec login  q quit",
        Screen::Login(LoginMode::AccountSelect) if entered_main => {
            "j/k navigate  Enter select  c create  l nsec  Esc back  q quit"
        }
        Screen::Login(LoginMode::AccountSelect) => {
            "j/k navigate  Enter select  c create  l nsec  q quit"
        }
        Screen::Login(LoginMode::NsecEntry) => "Enter submit  Esc back",
        Screen::GroupDetail => {
            "j/k move  A add  x remove  P promote  R rename  L leave  I invites  ? help  Esc back"
        }
        // The search screen has an internal focus the shared signature cannot
        // carry; `render_hints` calls `user_search_hint` instead. This arm keeps
        // `hints_line` total and returns the query-focus hint as the fallback.
        Screen::UserSearch => user_search_hint(UserSearchFocus::Query),
        Screen::Profile => "j/k move  Enter edit  f follow  x unfollow  Esc back",
        Screen::RelayHealth => "r refresh  j/k scroll  Esc back",
        Screen::Main => match focus {
            Focus::Chats => {
                "j/k move  Enter open  g detail  s search  p profile  h relays  I invites  A accounts  ? help"
            }
            Focus::Messages => {
                "j/k select  G/g ends  r react  u unreact  d delete  R reply  i compose"
            }
            Focus::Composer => "Enter send  Ctrl-U clear",
        },
    }
}

/// A composer prefix that arms a selected-message interaction, paired with the
/// verb and the Enter action the persistent hint advertises. When the composer
/// begins with one of these, Enter acts on the selected message instead of
/// sending a chat message, so the armed state must stay visible until resolved.
struct ArmedInteraction {
    command: &'static str,
    verb: &'static str,
    action: &'static str,
}

const ARMED_INTERACTIONS: &[ArmedInteraction] = &[
    ArmedInteraction {
        command: "/react",
        verb: "reacting to",
        action: "Enter sends the reaction",
    },
    ArmedInteraction {
        command: "/reply",
        verb: "replying to",
        action: "Enter sends the reply",
    },
    ArmedInteraction {
        command: "/delete",
        verb: "deleting",
        action: "Enter deletes",
    },
];

/// The armed interaction the composer text begins with, if any: `input` is the
/// command exactly (`/delete`) or the command followed by whitespace (`/react `,
/// `/reply hello`). Matching on the whole command word (not a bare prefix) keeps
/// `/refresh` and `/reactor` from counting. Shared by the persistent armed hint
/// and the `Esc` escape hatch so they agree on what "armed" means.
fn armed_interaction(input: &str) -> Option<&'static ArmedInteraction> {
    ARMED_INTERACTIONS.iter().find(|armed| {
        input
            .strip_prefix(armed.command)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with(|ch: char| ch.is_whitespace()))
    })
}

/// True when the composer holds an armed selected-message interaction, so `Esc`
/// should clear it as the escape hatch rather than leaving the user trapped.
pub(crate) fn is_armed_interaction(input: &str) -> bool {
    armed_interaction(input).is_some()
}

/// The persistent hint shown while the composer holds an armed interaction: what
/// Enter will do and to which message, plus the `Esc` escape hatch. Recomputed
/// from the composer text and the selected row at render time (not stored as a
/// one-shot status a later event would overwrite), so the armed state stays
/// visible until the command is sent or cleared. `None` when not armed.
pub(crate) fn armed_interaction_hint(input: &str, row: Option<&TimelineRow>) -> Option<String> {
    let armed = armed_interaction(input)?;
    let target = match row {
        Some(row) => timeline_target_label(row),
        None => "the selected message".to_owned(),
    };
    Some(format!(
        "{} {target} — {}, Esc clears",
        armed.verb, armed.action
    ))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SlashCommand {
    Help,
    Refresh,
    Diagnostics,
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
    /// React to the selected message. `emoji` defaults to `+` when the command
    /// carries none (the `r` accelerator sends the default on a bare Enter).
    React {
        emoji: String,
    },
    /// Remove your own reaction from the selected message.
    Unreact,
    /// Delete the selected message (own messages only).
    Delete,
    /// Reply to the selected message. The text is required; the target message
    /// resolves at submit against the selected row (like react/delete). The `R`
    /// accelerator prefills `/reply ` in the composer.
    Reply {
        text: String,
    },
    /// Retry a failed outbound event by id. Not a selected-message accelerator:
    /// timeline rows carry no failed-send state to target from (see the README).
    Retry {
        event_id: String,
    },
    Image {
        file_path: String,
        caption: Option<String>,
    },
    KeysFetch(String),
    KeysRotate,
    ProfileName(String),
    /// Open the user-search screen, optionally pre-running a query.
    UsersSearch {
        query: Option<String>,
    },
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
        usage: "/diagnostics",
        description: "toggle the MLS group diagnostics panel",
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
        usage: "/react [emoji]",
        description: "react to the selected message (default +)",
    },
    SlashCommandSuggestion {
        usage: "/unreact",
        description: "remove your reaction from the selected message",
    },
    SlashCommandSuggestion {
        usage: "/delete",
        description: "delete the selected message (own messages only)",
    },
    SlashCommandSuggestion {
        usage: "/reply <text>",
        description: "reply to the selected message",
    },
    SlashCommandSuggestion {
        usage: "/retry <event-id>",
        description: "retry a failed outbound event",
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
        usage: "/users [query]",
        description: "open user search (optionally run a query)",
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
        projection: parse_chat_projection(value),
    })
}

/// Parse the five chat-projection keys off any object that carries them: a
/// `chats list`/`subscribe` row, the timeline feed's `chat_list_row`, or the
/// `chats mark-read` response. Every field is optional — a group with no
/// projection yet (or a row missing a key) takes the empty default — so the
/// parser never fails on a partial object.
pub(crate) fn parse_chat_projection(value: &Value) -> ChatProjection {
    ChatProjection {
        unread_count: value
            .get("unread_count")
            .and_then(Value::as_u64)
            .and_then(|count| usize::try_from(count).ok())
            .unwrap_or(0),
        has_unread: value
            .get("has_unread")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        last_message: value
            .get("last_message")
            .filter(|message| !message.is_null())
            .map(parse_chat_last_message),
        last_read_message_id_hex: non_empty_value_string(value, "last_read_message_id_hex"),
        last_read_timeline_at: value.get("last_read_timeline_at").and_then(Value::as_u64),
    }
}

fn parse_chat_last_message(value: &Value) -> ChatLastMessage {
    ChatLastMessage {
        sender: non_empty_value_string(value, "sender"),
        sender_display_name: non_empty_value_string(value, "sender_display_name"),
        plaintext: value_string(value, "plaintext").unwrap_or_default(),
        kind: value.get("kind").and_then(Value::as_u64),
        timeline_at: value
            .get("timeline_at")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        deleted: value
            .get("deleted")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    }
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

    use super::super::{
        MEDIA_IMAGE_ROWS, TIMELINE_MESSAGE_SEPARATOR_ROWS, TUI_MESSAGE_SCROLLBACK_LIMIT,
    };
    use std::collections::HashMap;

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

    /// A media attachment parsed from a row's `media.imeta` tags: mime and
    /// filename for the placeholder, plus the plaintext SHA-256 hash that keys
    /// inbound-media download/decode state and is the argument `wn media download`
    /// takes.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub(crate) struct TimelineAttachment {
        pub(crate) mime: Option<String>,
        pub(crate) filename: Option<String>,
        /// Plaintext SHA-256 hex (`imeta` `plaintext_sha256`). `None` when the tag
        /// carried none, in which case the attachment cannot be downloaded.
        pub(crate) plaintext_hash: Option<String>,
    }

    impl TimelineAttachment {
        /// Whether this attachment is an inline image (mime `image/*`).
        pub(crate) fn is_image(&self) -> bool {
            self.mime
                .as_deref()
                .is_some_and(|mime| mime.starts_with("image/"))
        }

        /// The plaintext hash to download by, but only for images that carry one.
        pub(crate) fn image_hash(&self) -> Option<&str> {
            self.is_image().then_some(self.plaintext_hash.as_deref())?
        }

        /// The display name for a placeholder, sanitized, defaulting to `file`.
        pub(crate) fn display_name(&self) -> String {
            self.filename
                .as_deref()
                .map(terminal_safe_text)
                .filter(|name| !name.is_empty())
                .unwrap_or_else(|| "file".to_owned())
        }
    }

    /// How an inbound image, keyed by plaintext hash, is progressing. Set by the
    /// pure reducer in `media.rs`; the `Ready` transition also builds the terminal
    /// protocol, so `Ready` implies a drawable protocol exists.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub(crate) enum MediaStatus {
        Downloading,
        Decoding,
        Ready,
        Failed(String),
    }

    /// A borrowed, `Copy` snapshot of media state for the pure layout functions:
    /// per-hash statuses plus whether the terminal has an image protocol. The
    /// `Default` (no statuses, unsupported) reproduces the pre-media placeholder
    /// behavior, so callers that do not render images pass it and stay unchanged.
    #[derive(Clone, Copy, Default)]
    pub(crate) struct MediaView<'a> {
        statuses: Option<&'a HashMap<String, MediaStatus>>,
        supported: bool,
    }

    /// How one attachment lays out in the message pane.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub(crate) enum MediaSlot {
        /// A reserved block of `rows` blank lines; the renderer draws the decoded
        /// image over it.
        Image { rows: u16 },
        /// A single placeholder text line.
        Placeholder(String),
    }

    impl<'a> MediaView<'a> {
        /// Build a view over a live status map for a capability-detected terminal.
        pub(crate) fn new(statuses: &'a HashMap<String, MediaStatus>, supported: bool) -> Self {
            Self {
                statuses: Some(statuses),
                supported,
            }
        }

        fn status(&self, hash: &str) -> Option<&MediaStatus> {
            self.statuses.and_then(|statuses| statuses.get(hash))
        }

        /// Decide how an attachment lays out. The placeholder ladder mirrors
        /// `tui.md`: `[img name]` before download and when the terminal has no
        /// image protocol, `[downloading name...]`, `[loading name...]` while
        /// decoding, `[name failed: err]` on error, and a reserved image block
        /// once `Ready`.
        pub(crate) fn slot(&self, attachment: &TimelineAttachment) -> MediaSlot {
            let name = attachment.display_name();
            if !attachment.is_image() {
                return MediaSlot::Placeholder(format!("[file {name}]"));
            }
            let placeholder_img = || MediaSlot::Placeholder(format!("[img {name}]"));
            let Some(hash) = attachment.image_hash().filter(|_| self.supported) else {
                return placeholder_img();
            };
            match self.status(hash) {
                Some(MediaStatus::Ready) => MediaSlot::Image {
                    rows: MEDIA_IMAGE_ROWS,
                },
                Some(MediaStatus::Downloading) => {
                    MediaSlot::Placeholder(format!("[downloading {name}...]"))
                }
                Some(MediaStatus::Decoding) => {
                    MediaSlot::Placeholder(format!("[loading {name}...]"))
                }
                Some(MediaStatus::Failed(error)) => MediaSlot::Placeholder(format!(
                    "[{name} failed: {}]",
                    terminal_safe_text(error)
                )),
                None => placeholder_img(),
            }
        }
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

    /// Parse one `imeta` tag (an array of space-delimited `key value` strings)
    /// into an attachment, reading `m` (mime), `filename`, and `plaintext_sha256`
    /// (the download key). Other fields (locators, ciphertext hash, nonce) are
    /// resolved server-side by `wn media download` and not needed here.
    fn parse_timeline_attachment(entry: &Value) -> Option<TimelineAttachment> {
        let fields = entry.as_array()?;
        let mut mime = None;
        let mut filename = None;
        let mut plaintext_hash = None;
        for field in fields.iter().filter_map(Value::as_str) {
            match field.split_once(' ') {
                Some(("m", value)) => mime = non_empty_string(value),
                Some(("filename", value)) => filename = non_empty_string(value),
                Some(("plaintext_sha256", value)) => plaintext_hash = valid_plaintext_hash(value),
                _ => {}
            }
        }
        (mime.is_some() || filename.is_some()).then_some(TimelineAttachment {
            mime,
            filename,
            plaintext_hash,
        })
    }

    fn non_empty_string(value: &str) -> Option<String> {
        let value = value.trim();
        (!value.is_empty()).then(|| value.to_owned())
    }

    /// Accept an `imeta` `plaintext_sha256` only when it is exactly 64 lowercase
    /// hex characters — the shape storage always emits (`hex::encode`). This is
    /// the security boundary for inbound media: the hash is later joined into the
    /// on-disk cache path and passed on the `wn media download` argv, so anything
    /// path-like or otherwise attacker-shaped (traversal segments, separators,
    /// wrong length, non-hex) must be rejected here. Uppercase hex is rejected
    /// rather than normalized: storage never emits it, so its presence is
    /// anomalous. A rejected hash leaves the attachment with `plaintext_hash:
    /// None`, which renders as a plain placeholder and never downloads, so no
    /// downstream code needs its own path validation.
    fn valid_plaintext_hash(value: &str) -> Option<String> {
        let value = value.trim();
        let is_lower_hex = value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'));
        is_lower_hex.then(|| value.to_owned())
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
    /// Convenience wrapper over `timeline_row_lines_media` with an empty media
    /// view (all placeholders), used by the reducer tests; the live renderer
    /// always passes a real view.
    #[cfg(test)]
    pub(crate) fn timeline_row_lines(
        row: &TimelineRow,
        selected_account: Option<&AccountRow>,
    ) -> Vec<Line<'static>> {
        timeline_row_lines_media(row, selected_account, MediaView::default())
    }

    /// As `timeline_row_lines`, but laying out attachments through `media`: a
    /// ready image reserves a blank block the renderer draws over; everything
    /// else is a placeholder text line. `timeline_row_lines` is this with an empty
    /// view, so both share one implementation and never diverge.
    pub(crate) fn timeline_row_lines_media(
        row: &TimelineRow,
        selected_account: Option<&AccountRow>,
        media: MediaView,
    ) -> Vec<Line<'static>> {
        timeline_row_layout(row, selected_account, media).0
    }

    /// The row's rendered lines plus, for each ready image, the line index at
    /// which its reserved blank block begins. Both `timeline_row_lines_media` and
    /// `timeline_row_image_blocks` read this one layout, so a drawn image lands
    /// exactly on its reserved blanks no matter where the image sits among the
    /// row's attachments.
    fn timeline_row_layout(
        row: &TimelineRow,
        selected_account: Option<&AccountRow>,
        media: MediaView,
    ) -> (Vec<Line<'static>>, Vec<(String, usize)>) {
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
            return (lines, Vec::new());
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
        let mut images = Vec::new();
        for attachment in &row.attachments {
            match media.slot(attachment) {
                // A reserved block of blank lines; the renderer draws the decoded
                // image over it. Blank lines never wrap, so the reserved height
                // and the drawn height stay exact and in lockstep. Record where
                // the block starts so the image is drawn on exactly these lines,
                // wherever the image sits among the attachments.
                MediaSlot::Image { rows } => {
                    if let Some(hash) = attachment.image_hash() {
                        images.push((hash.to_owned(), lines.len()));
                    }
                    for _ in 0..rows {
                        lines.push(Line::from(""));
                    }
                }
                MediaSlot::Placeholder(label) => {
                    lines.push(timeline_attachment_line(&label, indent));
                }
            }
        }
        (lines, images)
    }

    /// The rendered height of a timeline row at `width`: the wrapped line count of
    /// its content plus the blank separator row. The separator makes a row's block
    /// height, so the visibility walk and the renderer stay in lockstep.
    #[cfg(test)]
    pub(crate) fn timeline_row_height(
        row: &TimelineRow,
        selected_account: Option<&AccountRow>,
        width: u16,
    ) -> u16 {
        timeline_row_height_media(row, selected_account, width, MediaView::default())
    }

    /// As `timeline_row_height`, counting the reserved image block through
    /// `media` so the visibility walk and the renderer agree once an image is
    /// ready.
    pub(crate) fn timeline_row_height_media(
        row: &TimelineRow,
        selected_account: Option<&AccountRow>,
        width: u16,
        media: MediaView,
    ) -> u16 {
        let lines = timeline_row_lines_media(row, selected_account, media);
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
    #[cfg(test)]
    pub(crate) fn timeline_row_heights(
        rows: &[TimelineRow],
        selected_account: Option<&AccountRow>,
        width: u16,
    ) -> Vec<u16> {
        timeline_row_heights_media(rows, selected_account, width, MediaView::default())
    }

    /// As `timeline_row_heights`, media-aware for the live renderer.
    pub(crate) fn timeline_row_heights_media(
        rows: &[TimelineRow],
        selected_account: Option<&AccountRow>,
        width: u16,
        media: MediaView,
    ) -> Vec<u16> {
        rows.iter()
            .map(|row| timeline_row_height_media(row, selected_account, width, media))
            .collect()
    }

    /// The ready-image blocks in a row: `(hash, top_offset, rows)`, where
    /// `top_offset` is rows below the top of the row's rendered block. Each
    /// offset is the wrapped height of the lines above that image's reserved
    /// block in the actual row layout, so the drawn image lands on its blanks
    /// even when a placeholder (a file, or a not-yet-ready image) follows it.
    pub(crate) fn timeline_row_image_blocks(
        row: &TimelineRow,
        selected_account: Option<&AccountRow>,
        width: u16,
        media: MediaView,
    ) -> Vec<(String, u16, u16)> {
        let (lines, images) = timeline_row_layout(row, selected_account, media);
        images
            .into_iter()
            .map(|(hash, start)| {
                // Wrapping is per-line, so the wrapped height of the lines above
                // the block is exactly the block's top row.
                let offset = if width == 0 {
                    u16::try_from(start).unwrap_or(u16::MAX)
                } else {
                    u16::try_from(
                        Paragraph::new(lines[..start].to_vec())
                            .wrap(Wrap { trim: false })
                            .line_count(width),
                    )
                    .unwrap_or(u16::MAX)
                };
                (hash, offset, MEDIA_IMAGE_ROWS)
            })
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
    /// This is the single ownership predicate: `direction == "sent"` OR the row's
    /// `from` resolves to the loaded account's id, npub, or display label. Own
    /// messages arriving on the received path (a second device, a re-sync echo,
    /// projection upserts overwriting `direction`) render as yours through the
    /// `from` match, so the delete guard shares this to stay in lockstep with the
    /// render.
    pub(crate) fn timeline_row_is_self(
        row: &TimelineRow,
        selected_account: Option<&AccountRow>,
    ) -> bool {
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

    /// `<name>: "<first 30 chars>"` for a timeline row: the sender's display name
    /// (falling back to a shortened id) and a clipped, terminal-control-stripped
    /// body preview. Shared by the reply status line and the armed-interaction
    /// hint so they name the target identically.
    pub(crate) fn timeline_target_label(row: &TimelineRow) -> String {
        let name = match row.from_display_name.as_deref() {
            Some(name) if !name.is_empty() => terminal_safe_text(name),
            _ => terminal_safe_text(&shorten(&row.from, 12)),
        };
        let body = if row.deleted {
            "message deleted".to_owned()
        } else {
            terminal_safe_text(&row.display_text)
        };
        let clipped = body.chars().take(30).collect::<String>();
        if body.chars().count() > 30 {
            format!("{name}: \"{clipped}...\"")
        } else {
            format!("{name}: \"{clipped}\"")
        }
    }

    /// The `R`-accelerator status line naming the reply target:
    /// `replying to <name>: "<first 30 chars>"`. Mirrors `timeline_reply_line`'s
    /// clip and terminal-control stripping; the author falls back to a shortened
    /// sender id when the row carries no display name.
    pub(crate) fn reply_target_status(row: &TimelineRow) -> String {
        format!("replying to {}", timeline_target_label(row))
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
    /// An attachment placeholder line: an indented, muted `[...]` label already
    /// chosen by `MediaView::slot`.
    fn timeline_attachment_line(label: &str, indent: usize) -> Line<'static> {
        Line::from(vec![
            Span::raw(" ".repeat(indent)),
            Span::styled(label.to_owned(), Style::default().fg(Color::DarkGray)),
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

/// The activity timestamp a chat orders by: its last message's `timeline_at`, or
/// `0` when it has no messages yet (message-less chats sort to the bottom).
pub(crate) fn chat_activity(chat: &ChatRow) -> u64 {
    chat.projection
        .last_message
        .as_ref()
        .map_or(0, |message| message.timeline_at)
}

/// Order chats by last activity, newest first. A stable sort keyed only on
/// activity, so equal-activity rows (all message-less chats, or same-second
/// activity) keep the order `chats list` returned — the documented fallback.
pub(crate) fn sort_chats_by_activity(chats: &mut [ChatRow]) {
    chats.sort_by_key(|chat| std::cmp::Reverse(chat_activity(chat)));
}

/// Re-order chats by activity while keeping the highlight on the same chat by
/// group id, so a background re-list or a live projection fold never yanks the
/// selection (the Phase 4 selection-stability invariant). Falls back to the
/// clamped previous index only when the selected group has vanished.
pub(crate) fn resort_chats_preserving_selection(chats: &mut [ChatRow], selected_chat: &mut usize) {
    let selected_group_id = chats.get(*selected_chat).map(|chat| chat.group_id.clone());
    sort_chats_by_activity(chats);
    *selected_chat = selected_chat_index(chats, selected_group_id.as_deref())
        .unwrap_or_else(|| (*selected_chat).min(chats.len().saturating_sub(1)));
}

/// Fold a refreshed projection into the matching chat row — from the timeline
/// feed's `chat_list_row` or the `chats mark-read` response — then re-order and
/// preserve the selection. Returns whether a row matched `group_id`.
pub(crate) fn fold_chat_projection(
    chats: &mut [ChatRow],
    selected_chat: &mut usize,
    group_id: &str,
    projection: ChatProjection,
) -> bool {
    let Some(row) = chats.iter_mut().find(|chat| chat.group_id == group_id) else {
        return false;
    };
    row.projection = projection;
    resort_chats_preserving_selection(chats, selected_chat);
    true
}

/// Whether folding `projection` for `folded_group_id` should schedule a
/// mark-read: it is the loaded (viewed) chat and still shows unread. Viewing is
/// reading, so the loaded chat's badge is cleared by a `chats mark-read` (issued
/// at most once per tick) rather than re-accruing as the timeline fold imports
/// the runtime's growing count. Once mark-read folds the count back to zero this
/// returns false, so it does not loop.
pub(crate) fn should_mark_loaded_chat_read(
    loaded_group_id: Option<&str>,
    folded_group_id: &str,
    projection: &ChatProjection,
) -> bool {
    loaded_group_id == Some(folded_group_id) && projection.unread_count > 0
}

/// The total unread count across all chats, summed from the runtime-backed
/// per-chat projections. The status bar's `{u} unread` is this sum — no local
/// counting.
pub(crate) fn total_unread(chats: &[ChatRow]) -> usize {
    chats.iter().map(|chat| chat.projection.unread_count).sum()
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
    upsert_chat(chats, chat, show_archived_chats);
    resort_chats_preserving_selection(chats, selected_chat);
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

pub(crate) fn upsert_chat(chats: &mut Vec<ChatRow>, mut chat: ChatRow, show_archived_chats: bool) {
    if chat.archived && !show_archived_chats {
        chats.retain(|existing| existing.group_id != chat.group_id);
        return;
    }
    if let Some(existing) = chats
        .iter_mut()
        .find(|existing| existing.group_id == chat.group_id)
    {
        // A chats-feed row whose projection collapsed to all-default keys is the
        // producer conflating a transient projection read-failure with "empty".
        // Merge, don't replace: keep the existing non-default projection so the
        // full-row upsert never zeroes a live badge/preview. Every legitimate
        // lowering (read, delete, reorder) arrives via mark-read/timeline/relist
        // instead, never via this feed collapsing to defaults.
        if chat.projection == ChatProjection::default()
            && existing.projection != ChatProjection::default()
        {
            chat.projection = existing.projection.clone();
        }
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

/// Whether a `messages subscribe` result is an initial-replay event rather than
/// a live one. The plain feed exists only for QUIC stream previews now, so the
/// drain skips these replays; unread is runtime-backed and never counted here.
pub(crate) fn is_initial_subscription_result(result: &Value) -> bool {
    matches!(
        result.get("trigger").and_then(Value::as_str),
        Some("InitialMessage" | "InitialAgentStreamWatch")
    )
}

/// Extract the `chat_list_row` projection embedded on a
/// `timeline_projection_updated` event, paired with the event's `group_id`. The
/// `chats subscribe` feed does not push on unread/last-message changes, so this
/// is the TUI's live source for the loaded chat's badge and preview. `None` for
/// any event without a projection (ready, initial page, or a remove-only update).
pub(crate) fn timeline_chat_list_row(result: &Value) -> Option<(String, ChatProjection)> {
    if result.get("type").and_then(Value::as_str) != Some("timeline_projection_updated") {
        return None;
    }
    let group_id = value_string(result, "group_id")?;
    let chat_list_row = result.get("chat_list_row").filter(|row| !row.is_null())?;
    Some((group_id, parse_chat_projection(chat_list_row)))
}

/// A parsed `notifications subscribe` event, reduced to what ambient state needs.
/// The daemon wraps the runtime `NotificationUpdate` under a `notification`
/// object; the trigger, group, dedup key, and group name all live there.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum NotificationEvent {
    /// A new message landed in `group_id`.
    NewMessage {
        group_id: String,
        notification_key: String,
    },
    /// A group invite arrived. Surfaced as a status-line notice this phase.
    GroupInvite {
        group_name: Option<String>,
        notification_key: String,
    },
    /// Subscription-ready, an unrecognized trigger, or a malformed event.
    Other,
}

/// Parse one `notifications subscribe` result into a [`NotificationEvent`]. Reads
/// the nested `notification` object (the runtime DTO carries the real trigger and
/// group); the envelope's top-level fields are only routing metadata.
pub(crate) fn parse_notification_event(result: &Value) -> NotificationEvent {
    if result.get("type").and_then(Value::as_str) != Some("notification") {
        return NotificationEvent::Other;
    }
    let Some(notification) = result.get("notification") else {
        return NotificationEvent::Other;
    };
    let Some(notification_key) = non_empty_value_string(notification, "notification_key")
        .or_else(|| non_empty_value_string(result, "notification_key"))
    else {
        return NotificationEvent::Other;
    };
    match notification.get("trigger").and_then(Value::as_str) {
        Some("NewMessage") => NotificationEvent::NewMessage {
            group_id: value_string(notification, "group_id_hex")
                .or_else(|| value_string(result, "group_id"))
                .unwrap_or_default(),
            notification_key,
        },
        Some("GroupInvite") => NotificationEvent::GroupInvite {
            group_name: non_empty_value_string(notification, "group_name"),
            notification_key,
        },
        _ => NotificationEvent::Other,
    }
}

/// The account an envelope on the runtime-wide `notifications subscribe` feed
/// belongs to, read from the top-level `account_id`/`account_ref` routing
/// fields the daemon stamps on every event. `None` when the envelope carries
/// neither (kept then — there is nothing to reject against).
pub(crate) fn notification_event_account(result: &Value) -> Option<String> {
    non_empty_value_string(result, "account_id")
        .or_else(|| non_empty_value_string(result, "account_ref"))
}

/// What a notification event asks the app to do, after dedup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum NotificationOutcome {
    /// Nothing to do: a duplicate key, a message in the loaded chat, or an
    /// unrecognized event.
    Ignored,
    /// A new message in a non-loaded chat — schedule a debounced chats re-list.
    ScheduledRelist,
    /// A group invite — show this one-line status notice.
    Invite(String),
}

/// A FIFO-bounded dedup set for notification `notification_key`s. Membership is
/// O(1); once it holds `TUI_SEEN_NOTIFICATION_KEYS_LIMIT` keys, inserting a new
/// one evicts the oldest. Invariant: dedup only needs to cover the recent event
/// window — the runtime feed's duplicate emissions arrive close together — so
/// aging out the oldest keys is safe: a long-evicted key re-arriving costs at
/// worst one redundant ambient re-list, never incorrect state.
#[derive(Debug, Default)]
pub(crate) struct SeenNotificationKeys {
    order: VecDeque<String>,
    keys: HashSet<String>,
}

impl SeenNotificationKeys {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Record `key`, returning whether it was newly inserted (not already seen).
    /// A new key past the cap evicts the oldest.
    pub(crate) fn insert(&mut self, key: String) -> bool {
        if !self.keys.insert(key.clone()) {
            return false;
        }
        self.order.push_back(key);
        if self.order.len() > TUI_SEEN_NOTIFICATION_KEYS_LIMIT
            && let Some(oldest) = self.order.pop_front()
        {
            self.keys.remove(&oldest);
        }
        true
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.order.len()
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.order.is_empty()
    }
}

/// Fold one notification event into ambient state, deduplicating by
/// `notification_key`. A first-seen NewMessage for a chat other than the loaded
/// pane sets `pending_relist` (the tick loop coalesces every such event since the
/// last tick into a single re-list); a first-seen GroupInvite returns a notice.
/// Re-applying a seen key is a no-op, so the duplicated emissions the runtime
/// feed produces never trigger twice. A NewMessage for the loaded chat is
/// ignored: its badge is kept fresh by the timeline feed and `chats mark-read`.
pub(crate) fn apply_notification_event(
    seen_keys: &mut SeenNotificationKeys,
    pending_relist: &mut bool,
    loaded_group_id: Option<&str>,
    event: NotificationEvent,
) -> NotificationOutcome {
    let notification_key = match &event {
        NotificationEvent::NewMessage {
            notification_key, ..
        }
        | NotificationEvent::GroupInvite {
            notification_key, ..
        } => notification_key.clone(),
        NotificationEvent::Other => return NotificationOutcome::Ignored,
    };
    if !seen_keys.insert(notification_key) {
        return NotificationOutcome::Ignored;
    }
    match event {
        NotificationEvent::NewMessage { group_id, .. } => {
            if loaded_group_id == Some(group_id.as_str()) {
                NotificationOutcome::Ignored
            } else {
                *pending_relist = true;
                NotificationOutcome::ScheduledRelist
            }
        }
        NotificationEvent::GroupInvite { group_name, .. } => {
            let name = group_name
                .map(|name| shorten(&terminal_safe_text(&name), 24))
                .unwrap_or_else(|| "a group".to_owned());
            NotificationOutcome::Invite(format!("invited to {name} — press I to view invites"))
        }
        NotificationEvent::Other => NotificationOutcome::Ignored,
    }
}

/// Apply one plain `messages subscribe` event to the account-wide live-stream
/// preview state. The materialized-timeline feed owns the messages pane now, so
/// message/reaction/media/delete rows drive nothing here; the plain feed is kept
/// only for what the timeline feed does not carry — the QUIC preview types that
/// render in the pane's bottom block, plus the preview cleanup when an agent
/// stream's final row lands. Unread is runtime-backed (the chat projection), so
/// nothing here counts messages.
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

/// Args for the `daemon start` child, forwarding the TUI's first-run relay
/// flags. `wn daemon start` accepts comma-delimited `--discovery-relays` /
/// `--default-account-relays`, so each non-empty list is joined and passed as
/// the same flag the daemon exposes (flag passthrough, no JSON change).
pub(crate) fn daemon_start_args(
    discovery_relays: &[String],
    default_account_relays: &[String],
) -> Vec<String> {
    let mut args = vec!["daemon".to_owned(), "start".to_owned()];
    if !discovery_relays.is_empty() {
        args.push("--discovery-relays".to_owned());
        args.push(discovery_relays.join(","));
    }
    if !default_account_relays.is_empty() {
        args.push("--default-account-relays".to_owned());
        args.push(default_account_relays.join(","));
    }
    args
}

pub(crate) fn message_subscription_args() -> Vec<String> {
    vec![
        "messages".to_owned(),
        "subscribe".to_owned(),
        "--limit".to_owned(),
        "0".to_owned(),
    ]
}

/// Args for the runtime-wide notification subscription (`notifications
/// subscribe`). Daemon-only; drives the debounced ambient badge refresh for
/// non-selected chats.
pub(crate) fn notification_subscription_args() -> Vec<String> {
    vec!["notifications".to_owned(), "subscribe".to_owned()]
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
