//! Declarative `clap` command-line argument surface for the `dm` CLI.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};

#[derive(Parser, Clone, Debug, Serialize, Deserialize)]
#[command(
    name = "dm",
    about = "Darkmatter account, group, message, stream, and daemon CLI",
    disable_help_subcommand = true
)]
pub(crate) struct Cli {
    #[arg(
        long,
        global = true,
        value_name = "PATH",
        help = "Use this Darkmatter data directory"
    )]
    pub(crate) home: Option<PathBuf>,
    #[arg(
        long,
        global = true,
        value_name = "PATH",
        help = "Connect to this dmd daemon socket"
    )]
    pub(crate) socket: Option<PathBuf>,
    #[arg(long, global = true, value_name = "URL", hide = true)]
    pub(crate) relay: Option<String>,
    #[arg(skip)]
    #[serde(default)]
    pub(crate) daemon_discovery_relays: Vec<String>,
    #[arg(skip)]
    #[serde(default)]
    pub(crate) daemon_default_account_relays: Vec<String>,
    #[arg(
        long,
        global = true,
        value_enum,
        value_name = "STORE",
        help = "Store account secrets in the OS keychain or local files"
    )]
    pub(crate) secret_store: Option<SecretStoreKind>,
    #[arg(
        long,
        global = true,
        value_name = "SERVICE",
        help = "Use this OS keychain service name for local secret storage"
    )]
    pub(crate) keychain_service: Option<String>,
    #[arg(
        long,
        value_name = "NPUB_OR_HEX",
        help = "Select the account by npub or hex pubkey"
    )]
    pub(crate) account: Option<String>,
    #[arg(long, global = true, help = "Emit machine-readable JSON")]
    pub(crate) json: bool,
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ValueEnum)]
pub enum SecretStoreKind {
    Keychain,
    File,
}

impl SecretStoreKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            SecretStoreKind::Keychain => "keychain",
            SecretStoreKind::File => "file",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Subcommand)]
pub(crate) enum Command {
    #[command(about = "Open the interactive terminal UI")]
    Tui,
    #[command(about = "Inspect local runtime diagnostics")]
    Debug {
        #[command(subcommand)]
        command: DebugCommand,
    },
    #[command(
        name = "create-identity",
        about = "Create a new local signing identity"
    )]
    CreateIdentity,
    #[command(about = "Import an nsec from stdin or add a public npub identity")]
    Login {
        #[arg(
            value_name = "NPUB_OR_HEX",
            help = "npub or hex pubkey to track as a public account"
        )]
        identity: Option<String>,
        #[serde(default)]
        #[arg(long, help = "Read an nsec private key from stdin instead of argv")]
        nsec_stdin: bool,
        #[arg(
            long,
            value_name = "URL",
            help = "Command-local relay used for account setup"
        )]
        relay: Option<String>,
    },
    #[command(about = "Show current account identities")]
    Whoami,
    #[command(about = "Log out and remove a local account")]
    Logout {
        #[arg(value_name = "NPUB_OR_HEX", help = "Account to remove")]
        pubkey: String,
    },
    #[command(
        name = "export-nsec",
        about = "Exporting private keys is disabled by Darkmatter CLI policy"
    )]
    ExportNsec {
        #[arg(
            value_name = "NPUB_OR_HEX",
            help = "Account whose secret key was requested"
        )]
        pubkey: String,
    },
    #[command(hide = true)]
    Account {
        #[command(subcommand)]
        command: AccountCommand,
    },
    #[command(about = "Manage local account identities and relay lists")]
    Accounts {
        #[command(subcommand)]
        command: AccountCommand,
    },
    #[command(about = "Inspect and repair MLS KeyPackage publication")]
    Keys {
        #[command(subcommand)]
        command: KeyPackageCommand,
    },
    #[command(about = "List chats and subscribe to chat projection updates")]
    Chats {
        #[command(subcommand)]
        command: ChatsCommand,
    },
    #[command(about = "List media references in a group")]
    Media {
        #[command(subcommand)]
        command: MediaCommand,
    },
    #[command(hide = true)]
    Group {
        #[command(subcommand)]
        command: GroupCommand,
    },
    #[command(about = "Create groups and manage membership and admin state")]
    Groups {
        #[command(subcommand)]
        command: GroupsCommand,
    },
    #[command(hide = true)]
    Message {
        #[command(subcommand)]
        command: MessageCommand,
    },
    #[command(about = "Send, list, search, delete, retry, and react to messages")]
    Messages {
        #[command(subcommand)]
        command: MessageCommand,
    },
    #[command(about = "Manage the local account follow list")]
    Follows {
        #[command(subcommand)]
        command: FollowsCommand,
    },
    #[command(about = "Show or publish the selected account Nostr profile")]
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
    },
    #[command(about = "Inspect and update account relay lists")]
    Relays {
        #[command(subcommand)]
        command: RelaysCommand,
    },
    #[command(about = "Read and update local CLI preferences")]
    Settings {
        #[command(subcommand)]
        command: SettingsCommand,
    },
    #[command(about = "Look up known Nostr users from the local directory")]
    Users {
        #[command(subcommand)]
        command: UsersCommand,
    },
    #[command(hide = true)]
    Notifications {
        #[command(subcommand)]
        command: NotificationsCommand,
    },
    #[command(about = "Start, watch, finish, and verify agent text streams")]
    Stream {
        #[command(subcommand)]
        command: StreamCommand,
    },
    #[command(about = "Start, stop, and inspect the local dmd runtime")]
    Daemon {
        #[command(subcommand)]
        command: DaemonCommand,
    },
    #[command(hide = true)]
    Sync,
    #[command(
        name = "relay-stats",
        about = "Show device-local relay performance telemetry (aggregate, no relay URLs)"
    )]
    RelayStats,
    #[command(about = "Delete all local Darkmatter CLI data after confirmation")]
    Reset {
        #[arg(long, help = "Required safety flag before deleting local data")]
        confirm: bool,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, Subcommand)]
pub(crate) enum DebugCommand {
    #[command(
        name = "relay-control-state",
        about = "Show the relay-plane subscription and control-state snapshot"
    )]
    RelayControlState,
    #[command(about = "Run a local runtime health check for the selected account")]
    Health,
    #[command(name = "ratchet-tree", hide = true)]
    RatchetTree { group_id: String },
}

#[derive(Clone, Debug, Serialize, Deserialize, Subcommand)]
pub(crate) enum AccountCommand {
    #[command(about = "Create a local account and publish its bootstrap records")]
    Create {
        #[arg(
            value_name = "NPUB_OR_HEX",
            help = "Optional npub or hex pubkey to track"
        )]
        identity: Option<String>,
        #[serde(default)]
        #[arg(long, help = "Read an nsec private key from stdin instead of argv")]
        nsec_stdin: bool,
        #[arg(
            long,
            value_name = "URLS",
            value_delimiter = ',',
            help = "Comma-separated account relay list to publish"
        )]
        default_relays: Vec<String>,
        #[arg(
            long,
            value_name = "URLS",
            value_delimiter = ',',
            help = "Comma-separated bootstrap relays used to find account records"
        )]
        bootstrap_relays: Vec<String>,
        #[arg(
            long,
            help = "Publish missing relay-list records during account creation"
        )]
        publish_missing_relay_lists: bool,
    },
    #[command(about = "List local accounts")]
    List,
    #[command(about = "Show account readiness, relay-list, and KeyPackage status")]
    Status {
        #[arg(
            value_name = "NPUB_OR_HEX",
            help = "Optional account npub or hex pubkey"
        )]
        account: Option<String>,
    },
    #[command(
        name = "relay-lists",
        about = "Fetch and inspect published relay lists"
    )]
    RelayLists {
        #[arg(
            value_name = "NPUB_OR_HEX",
            help = "Account to inspect; defaults to selected account"
        )]
        account: Option<String>,
        #[arg(
            long,
            value_name = "URLS",
            value_delimiter = ',',
            help = "Comma-separated relays to use for relay-list discovery"
        )]
        bootstrap_relays: Vec<String>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, Subcommand)]
pub(crate) enum KeyPackageCommand {
    #[command(about = "List local KeyPackage publication records")]
    List,
    #[command(about = "Republish the currently cached KeyPackage")]
    Publish,
    #[command(
        about = "Force mint and publish a fresh replacement KeyPackage",
        alias = "force-publish"
    )]
    Rotate,
    #[command(hide = true)]
    Delete { event_id: String },
    #[command(name = "delete-all", hide = true)]
    DeleteAll {
        #[arg(long)]
        confirm: bool,
    },
    #[command(about = "Check whether a user has relay lists and a fetchable KeyPackage")]
    Check {
        #[arg(value_name = "NPUB_OR_HEX", help = "User to check")]
        pubkey: String,
    },
    #[command(about = "Fetch and cache another user's KeyPackage")]
    Fetch {
        #[arg(
            value_name = "NPUB_OR_HEX",
            help = "User to fetch; defaults to selected account"
        )]
        account: Option<String>,
        #[arg(
            long,
            value_name = "URLS",
            value_delimiter = ',',
            help = "Comma-separated relays to use for relay-list discovery"
        )]
        bootstrap_relays: Vec<String>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, Subcommand)]
pub(crate) enum ChatsCommand {
    #[command(about = "List current chats")]
    List {
        #[arg(long, help = "Include archived chats")]
        include_archived: bool,
    },
    #[command(about = "Show one chat")]
    Show {
        #[arg(help = "Group id to show")]
        group: String,
    },
    #[command(about = "Subscribe to live chat-list updates through the daemon")]
    Subscribe,
    #[command(about = "Archive a chat locally")]
    Archive {
        #[arg(help = "Group id to archive")]
        group: String,
    },
    #[command(about = "Unarchive a chat locally")]
    Unarchive {
        #[arg(help = "Group id to unarchive")]
        group: String,
    },
    #[command(name = "list-archived", about = "List archived chats")]
    ListArchived,
    #[command(
        name = "subscribe-archived",
        about = "Subscribe to live archived-chat updates through the daemon"
    )]
    SubscribeArchived,
    #[command(hide = true)]
    Mute { group: String, duration: String },
    #[command(hide = true)]
    Unmute { group: String },
}

#[derive(Clone, Debug, Serialize, Deserialize, Subcommand)]
pub(crate) enum MediaCommand {
    #[command(about = "Encrypt and upload a media file to Blossom")]
    Upload {
        #[arg(help = "Group id that owns the media key")]
        group: String,
        #[arg(help = "Path to the plaintext media file")]
        file_path: String,
        #[arg(long, help = "Send a kind-9 media message after upload")]
        send: bool,
        #[arg(long, help = "Caption to send with --send")]
        message: Option<String>,
        #[arg(long, value_name = "MIME", help = "Override MIME type")]
        media_type: Option<String>,
        #[arg(
            long,
            value_name = "URL",
            help = "Blossom server URL for upload; defaults to the group's encrypted-media endpoint"
        )]
        server: Option<String>,
    },
    #[command(about = "Download and decrypt a media file from Blossom")]
    Download {
        #[arg(help = "Group id that owns the media key")]
        group: String,
        #[arg(help = "Plaintext SHA-256 hash from media list")]
        file_hash: String,
        #[arg(
            long,
            value_name = "PATH",
            help = "Output path; defaults to the original filename"
        )]
        output: Option<String>,
    },
    #[command(about = "List media references for a group")]
    List {
        #[arg(help = "Group id to inspect")]
        group: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, Subcommand)]
pub(crate) enum GroupCommand {
    Create {
        name: String,
        #[arg(value_name = "MEMBER")]
        members: Vec<String>,
        #[arg(long)]
        description: Option<String>,
    },
    Members {
        group: String,
    },
    Invite {
        group: String,
        #[arg(value_name = "MEMBER", required = true)]
        members: Vec<String>,
    },
    Remove {
        group: String,
        #[arg(value_name = "MEMBER", required = true)]
        members: Vec<String>,
    },
    Update {
        group: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        description: Option<String>,
    },
    #[command(name = "set-avatar-url")]
    SetAvatarUrl {
        group: String,
        #[arg(long, conflicts_with = "clear", required_unless_present = "clear")]
        url: Option<String>,
        #[arg(long, requires = "url")]
        dim: Option<String>,
        #[arg(long, requires = "url")]
        thumbhash: Option<String>,
        #[arg(long)]
        clear: bool,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, Subcommand)]
pub(crate) enum GroupsCommand {
    #[command(about = "List groups for the selected account")]
    List,
    #[command(about = "Create a group and invite members by pubkey")]
    Create {
        #[arg(help = "Group display name")]
        name: String,
        #[arg(value_name = "MEMBER", help = "Member npub or hex pubkey to add")]
        members: Vec<String>,
        #[arg(long, help = "Optional group description")]
        description: Option<String>,
    },
    #[command(about = "Show group metadata and membership state")]
    Show {
        #[arg(help = "Group id to show")]
        group_id: String,
    },
    #[command(name = "add-members", about = "Add members to a group")]
    AddMembers {
        #[arg(help = "Group id to update")]
        group_id: String,
        #[arg(
            value_name = "MEMBER",
            required = true,
            help = "Member npub or hex pubkey to add"
        )]
        members: Vec<String>,
    },
    #[command(name = "remove-members", about = "Remove members from a group")]
    RemoveMembers {
        #[arg(help = "Group id to update")]
        group_id: String,
        #[arg(
            value_name = "MEMBER",
            required = true,
            help = "Member npub or hex pubkey to remove"
        )]
        members: Vec<String>,
    },
    #[command(about = "List group members")]
    Members {
        #[arg(help = "Group id to inspect")]
        group_id: String,
    },
    #[command(about = "List group admins")]
    Admins {
        #[arg(help = "Group id to inspect")]
        group_id: String,
    },
    #[command(about = "List group relay hints")]
    Relays {
        #[arg(help = "Group id to inspect")]
        group_id: String,
    },
    #[command(about = "Leave a group")]
    Leave {
        #[arg(help = "Group id to leave")]
        group_id: String,
    },
    #[command(about = "Rename a group")]
    Rename {
        #[arg(help = "Group id to rename")]
        group_id: String,
        #[arg(help = "New group name")]
        name: String,
    },
    #[command(
        name = "set-avatar-url",
        about = "Set, update, or clear the group URL avatar"
    )]
    SetAvatarUrl {
        #[arg(help = "Group id to update")]
        group_id: String,
        #[arg(
            long,
            conflicts_with = "clear",
            required_unless_present = "clear",
            help = "HTTPS avatar URL"
        )]
        url: Option<String>,
        #[arg(long, requires = "url", help = "Optional avatar dimensions as WxH")]
        dim: Option<String>,
        #[arg(long, requires = "url", help = "Optional thumbhash hex")]
        thumbhash: Option<String>,
        #[arg(long, help = "Clear the group URL avatar")]
        clear: bool,
    },
    #[command(hide = true)]
    Invites,
    #[command(hide = true)]
    Accept { group_id: String },
    #[command(hide = true)]
    Decline { group_id: String },
    #[command(about = "Promote a member to group admin")]
    Promote {
        #[arg(help = "Group id to update")]
        group_id: String,
        #[arg(help = "Member npub or hex pubkey to promote")]
        pubkey: String,
    },
    #[command(about = "Demote a group admin")]
    Demote {
        #[arg(help = "Group id to update")]
        group_id: String,
        #[arg(help = "Admin npub or hex pubkey to demote")]
        pubkey: String,
    },
    #[command(name = "self-demote", about = "Demote the selected account from admin")]
    SelfDemote {
        #[arg(help = "Group id to update")]
        group_id: String,
    },
    #[command(
        name = "subscribe-state",
        about = "Subscribe to live group-state updates through the daemon"
    )]
    SubscribeState {
        #[arg(help = "Group id to watch")]
        group_id: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, Subcommand)]
pub(crate) enum MessageCommand {
    #[command(about = "Send a message to a group")]
    Send {
        #[arg(long = "group", value_name = "GROUP", help = "Group id to send to")]
        group_flag: Option<String>,
        #[arg(
            value_name = "GROUP_OR_TEXT",
            allow_hyphen_values = true,
            help = "Either GROUP TEXT... or TEXT... when --group is provided"
        )]
        args: Vec<String>,
    },
    #[command(about = "Delete a message for the selected account's local view")]
    Delete {
        #[arg(help = "Group id containing the message")]
        group_id: String,
        #[arg(help = "Message id to delete")]
        message_id: String,
    },
    #[command(about = "Retry a failed outbound message event")]
    Retry {
        #[arg(help = "Group id containing the failed event")]
        group_id: String,
        #[arg(help = "Event id to retry")]
        event_id: String,
    },
    #[command(about = "React to a message")]
    React {
        #[arg(help = "Group id containing the message")]
        group_id: String,
        #[arg(help = "Message id to react to")]
        message_id: String,
        #[arg(default_value = "+", help = "Emoji reaction to add")]
        emoji: String,
    },
    #[command(about = "Remove your reaction from a message")]
    Unreact {
        #[arg(help = "Group id containing the message")]
        group_id: String,
        #[arg(help = "Message id to unreact from")]
        message_id: String,
    },
    #[command(about = "List messages from one group")]
    List {
        #[arg(value_name = "GROUP", help = "Group id to list")]
        group_id: Option<String>,
        #[arg(long, help = "Group id to list")]
        group: Option<String>,
        #[arg(long, help = "Only include messages before this unix timestamp")]
        before: Option<u64>,
        #[arg(long, help = "Only include messages before this message id")]
        before_message_id: Option<String>,
        #[arg(long, help = "Only include messages after this unix timestamp")]
        after: Option<u64>,
        #[arg(long, help = "Only include messages after this message id")]
        after_message_id: Option<String>,
        #[arg(long, help = "Maximum number of messages to return")]
        limit: Option<usize>,
    },
    #[command(about = "List, search, and subscribe to the materialized message timeline")]
    Timeline {
        #[command(subcommand)]
        command: MessageTimelineCommand,
    },
    #[command(about = "Search messages in one group")]
    Search {
        #[arg(help = "Group id to search")]
        group_id: String,
        #[arg(help = "Search query")]
        query: String,
        #[arg(long, help = "Maximum number of results to return")]
        limit: Option<usize>,
    },
    #[command(name = "search-all", about = "Search messages across all local groups")]
    SearchAll {
        #[arg(help = "Search query")]
        query: String,
        #[arg(long, help = "Maximum number of results to return")]
        limit: Option<usize>,
    },
    #[command(about = "Subscribe to live message updates through the daemon")]
    Subscribe {
        #[arg(help = "Group id to watch; omit to watch all local groups")]
        group: Option<String>,
        #[arg(long, help = "Initial replay limit")]
        limit: Option<usize>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, Subcommand)]
pub(crate) enum MessageTimelineCommand {
    #[command(about = "List materialized timeline messages")]
    List {
        #[arg(value_name = "GROUP", help = "Group id to list")]
        group_id: Option<String>,
        #[arg(long, help = "Group id to list")]
        group: Option<String>,
        #[arg(long, help = "Only include timeline rows before this unix timestamp")]
        before: Option<u64>,
        #[arg(long, help = "Only include timeline rows before this message id")]
        before_message_id: Option<String>,
        #[arg(long, help = "Only include timeline rows after this unix timestamp")]
        after: Option<u64>,
        #[arg(long, help = "Only include timeline rows after this message id")]
        after_message_id: Option<String>,
        #[arg(long, help = "Maximum number of timeline rows to return")]
        limit: Option<usize>,
    },
    #[command(about = "Search materialized timeline messages")]
    Search {
        #[arg(help = "Search query")]
        query: String,
        #[arg(value_name = "GROUP", help = "Optional group id to search")]
        group_id: Option<String>,
        #[arg(long, help = "Group id to search")]
        group: Option<String>,
        #[arg(long, help = "Maximum number of results to return")]
        limit: Option<usize>,
    },
    #[command(about = "Subscribe to live materialized timeline updates through the daemon")]
    Subscribe {
        #[arg(help = "Group id to watch; omit to watch all local groups")]
        group: Option<String>,
        #[arg(long, help = "Initial replay limit")]
        limit: Option<usize>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, Subcommand)]
pub(crate) enum FollowsCommand {
    #[command(about = "List followed users")]
    List,
    #[command(about = "Follow a user")]
    Add {
        #[arg(value_name = "NPUB_OR_HEX", help = "User to follow")]
        pubkey: String,
    },
    #[command(about = "Unfollow a user")]
    Remove {
        #[arg(value_name = "NPUB_OR_HEX", help = "User to unfollow")]
        pubkey: String,
    },
    #[command(about = "Check whether a user is followed")]
    Check {
        #[arg(value_name = "NPUB_OR_HEX", help = "User to check")]
        pubkey: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, Subcommand)]
pub(crate) enum ProfileCommand {
    #[command(about = "Show the selected account Nostr profile")]
    Show,
    #[command(about = "Update and publish the selected account Nostr profile")]
    Update {
        #[arg(long, help = "Set the short profile name")]
        name: Option<String>,
        #[arg(long, help = "Set the display name")]
        display_name: Option<String>,
        #[arg(long, help = "Set the profile bio")]
        about: Option<String>,
        #[arg(long, help = "Set the profile picture URL")]
        picture: Option<String>,
        #[arg(long, help = "Set the NIP-05 identifier")]
        nip05: Option<String>,
        #[arg(long, help = "Set the Lightning address")]
        lud16: Option<String>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, Subcommand)]
pub(crate) enum RelaysCommand {
    #[command(about = "List account relay URLs")]
    List {
        #[arg(
            long = "type",
            value_name = "TYPE",
            help = "Relay list type: nip65 or inbox"
        )]
        relay_type: Option<String>,
    },
    #[command(about = "Add a relay URL to an account relay list")]
    Add {
        #[arg(help = "Relay URL to add")]
        url: String,
        #[arg(
            long = "type",
            value_name = "TYPE",
            help = "Relay list type: nip65 or inbox"
        )]
        relay_type: String,
    },
    #[command(about = "Remove a relay URL from an account relay list")]
    Remove {
        #[arg(help = "Relay URL to remove")]
        url: String,
        #[arg(
            long = "type",
            value_name = "TYPE",
            help = "Relay list type: nip65 or inbox"
        )]
        relay_type: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, Subcommand)]
pub(crate) enum SettingsCommand {
    #[command(about = "Show local CLI settings")]
    Show,
    #[command(about = "Set the local TUI theme")]
    Theme {
        #[arg(help = "Theme mode such as system, light, or dark")]
        mode: String,
    },
    #[command(about = "Set the local UI language")]
    Language {
        #[arg(help = "Language tag such as en")]
        lang: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, Subcommand)]
pub(crate) enum UsersCommand {
    #[command(about = "Show a known user from the local directory")]
    Show {
        #[arg(value_name = "NPUB_OR_HEX", help = "User to show")]
        pubkey: String,
    },
    #[command(about = "Search known users in the local directory")]
    Search {
        #[arg(help = "Search query")]
        query: String,
        #[arg(
            long,
            default_value = "0..2",
            value_parser = parse_radius,
            help = "Directory graph radius as START..END"
        )]
        radius: (u8, u8),
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, Subcommand)]
pub(crate) enum NotificationsCommand {
    #[command(about = "Subscribe to notification updates")]
    Subscribe,
}

#[derive(Clone, Debug, Serialize, Deserialize, Subcommand)]
pub(crate) enum StreamCommand {
    #[command(about = "Anchor a durable agent text stream start over the MLS message path")]
    Start {
        #[arg(help = "Group id to anchor the stream in")]
        group: String,
        #[arg(long, value_name = "HEX", help = "Optional stream id to use")]
        stream_id: Option<String>,
        #[arg(
            long = "quic-candidate",
            value_name = "ADDR",
            help = "QUIC candidate URI such as quic://127.0.0.1:4450"
        )]
        quic_candidates: Vec<String>,
    },
    #[command(about = "Receive one provisional QUIC agent text stream")]
    Receive {
        #[arg(
            long,
            default_value = "127.0.0.1:4450",
            value_name = "ADDR",
            help = "Local address to bind"
        )]
        bind: SocketAddr,
        #[arg(long, value_name = "HEX", help = "Expected stream-start event id")]
        start_event_id: Option<String>,
    },
    #[command(about = "Send one provisional QUIC agent text stream")]
    Send {
        #[arg(
            long,
            help = "Use the broker protocol instead of direct QUIC stream receive"
        )]
        broker: bool,
        #[arg(long, value_name = "ADDR", help = "Remote QUIC address")]
        connect: SocketAddr,
        #[arg(
            long,
            default_value = "localhost",
            value_name = "NAME",
            help = "TLS server name"
        )]
        server_name: String,
        #[arg(
            long,
            value_name = "HEX",
            help = "Pinned server certificate DER bytes as hex"
        )]
        server_cert_der_hex: Option<String>,
        #[arg(long, help = "Trust loopback QUIC certificates for local testing")]
        insecure_local: bool,
        #[arg(long, value_name = "HEX", help = "Optional stream id to use")]
        stream_id: Option<String>,
        #[arg(long, value_name = "HEX", help = "Expected stream-start event id")]
        start_event_id: Option<String>,
        #[arg(
            long,
            default_value_t = 1024,
            value_name = "BYTES",
            help = "Maximum bytes per streamed chunk"
        )]
        chunk_bytes: usize,
        #[arg(
            long,
            default_value_t = 0,
            value_name = "MILLIS",
            help = "Delay between streamed chunks"
        )]
        chunk_delay_ms: u64,
        #[arg(
            value_name = "TEXT",
            required = true,
            allow_hyphen_values = true,
            help = "Text to stream"
        )]
        text: Vec<String>,
    },
    #[command(about = "Watch one brokered QUIC agent text stream from a durable MLS start payload")]
    Watch {
        #[arg(help = "Group id containing the stream start")]
        group: String,
        #[arg(long, value_name = "HEX", help = "Stream id to watch")]
        stream_id: Option<String>,
        #[arg(
            long,
            value_name = "HEX",
            help = "Pinned server certificate DER bytes as hex"
        )]
        server_cert_der_hex: Option<String>,
        #[arg(long, help = "Trust loopback QUIC certificates for local testing")]
        insecure_local: bool,
        #[arg(
            long,
            help = "Register the watch with the daemon and return immediately"
        )]
        background: bool,
    },
    #[command(hide = true)]
    ComposeOpen {
        group: String,
        #[arg(long, value_name = "HEX")]
        stream_id: Option<String>,
        #[arg(long = "quic-candidate", value_name = "ADDR")]
        quic_candidates: Vec<String>,
        #[arg(long)]
        insecure_local: bool,
        #[arg(long, default_value_t = 32, value_name = "BYTES")]
        chunk_bytes: usize,
    },
    #[command(hide = true)]
    ComposeAppend {
        #[arg(long, value_name = "HEX")]
        stream_id: String,
        #[arg(value_name = "TEXT", required = true, allow_hyphen_values = true)]
        text: Vec<String>,
    },
    #[command(hide = true)]
    ComposeFinish {
        #[arg(long, value_name = "HEX")]
        stream_id: String,
    },
    #[command(hide = true)]
    ComposeCancel {
        #[arg(long, value_name = "HEX")]
        stream_id: String,
    },
    #[command(about = "Commit the final agent text stream transcript over the MLS message path")]
    Finish {
        #[arg(help = "Group id containing the stream")]
        group: String,
        #[arg(long, value_name = "HEX", help = "Stream id to finish")]
        stream_id: String,
        #[arg(long, value_name = "HEX", help = "Stream-start message id")]
        start_event_id: String,
        #[arg(long, value_name = "HEX", help = "Final transcript hash")]
        transcript_hash: String,
        #[arg(long, help = "Number of streamed chunks")]
        chunk_count: u64,
        #[arg(
            value_name = "TEXT",
            required = true,
            allow_hyphen_values = true,
            help = "Final text"
        )]
        text: Vec<String>,
    },
    #[command(about = "Verify a local QUIC transcript against the durable MLS final payload")]
    Verify {
        #[arg(help = "Group id containing the stream")]
        group: String,
        #[arg(long, value_name = "HEX", help = "Stream id to verify")]
        stream_id: String,
        #[arg(long, value_name = "HEX", help = "Expected transcript hash")]
        transcript_hash: String,
        #[arg(long, help = "Expected streamed chunk count")]
        chunk_count: Option<u64>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, Subcommand)]
pub(crate) enum DaemonCommand {
    #[command(about = "Start dmd in the background")]
    Start {
        #[arg(
            long,
            value_name = "PATH",
            help = "Use this Darkmatter data directory (alias for --home)"
        )]
        data_dir: Option<PathBuf>,
        #[arg(
            long,
            value_name = "URLS",
            value_delimiter = ',',
            help = "Comma-separated discovery relays for profiles, relay lists, and KeyPackages"
        )]
        discovery_relays: Vec<String>,
        #[arg(
            long,
            value_name = "URLS",
            value_delimiter = ',',
            help = "Comma-separated default account relays used when creating identities"
        )]
        default_account_relays: Vec<String>,
        #[arg(
            long,
            value_name = "PATH",
            help = "Write daemon logs in this directory"
        )]
        logs_dir: Option<PathBuf>,
    },
    #[command(about = "Stop the background dmd daemon")]
    Stop,
    #[command(about = "Show daemon status, relay health, and stream watches")]
    Status,
}

pub(crate) fn parse_radius(s: &str) -> Result<(u8, u8), String> {
    let Some((start, end)) = s.split_once("..") else {
        return Err("expected format START..END".to_owned());
    };
    let start = start
        .parse::<u8>()
        .map_err(|_| format!("invalid radius start: {start}"))?;
    let end = end
        .parse::<u8>()
        .map_err(|_| format!("invalid radius end: {end}"))?;
    if start > end {
        return Err(format!("radius start ({start}) must be <= end ({end})"));
    }
    Ok((start, end))
}
