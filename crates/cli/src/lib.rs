use std::ffi::OsString;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cgka_traits::TransportEndpoint;
use cgka_traits::agent_text_stream::{
    AgentTextStreamAppPayloadEnvelopeV1, AgentTextStreamAppPayloadError,
    AgentTextStreamAppPayloadV1, AgentTextStreamRouteV1, AgentTextStreamStartPayloadV1,
};
use cgka_traits::error::EngineError;
use cgka_traits::{GroupId, MarmotAppMessagePayloadV1, MessageId};
use clap::{Parser, Subcommand, ValueEnum};
use marmot_account::{AccountError, AccountHome, AccountHomeError, DEFAULT_KEYCHAIN_SERVICE_NAME};
use marmot_app::{
    AccountRelayListBootstrap, AccountRelayListStatus, AccountSetupRequest, AccountSetupResult,
    AgentTextStreamFinishRequest, AppError, AppGroupMemberRecord, AppGroupMlsState, AppGroupRecord,
    AppMessageQuery, AppMessageRecord, AppStatus, FetchedKeyPackage, MarmotApp, MarmotAppRuntime,
    SyncSummary, UserDirectorySearch, UserProfileMetadata,
};
use nostr::ToBech32;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use transport_quic_broker::{
    BrokerServerTrust, PublishTextToBroker, SubscribeTextFromBroker, publish_text_to_broker,
    subscribe_text_from_broker_with_updates,
};
use transport_quic_stream::{
    QuicTextStreamReceiver, SendTextStream, ServerTrust, send_text_stream,
};

pub mod daemon;
pub mod tui;

#[derive(Parser, Clone, Debug, Serialize, Deserialize)]
#[command(
    name = "dm",
    about = "Darkmatter account, group, message, stream, and daemon CLI",
    disable_help_subcommand = true
)]
struct Cli {
    #[arg(
        long,
        global = true,
        value_name = "PATH",
        help = "Use this Darkmatter data directory"
    )]
    home: Option<PathBuf>,
    #[arg(
        long,
        global = true,
        value_name = "PATH",
        help = "Connect to this dmd daemon socket"
    )]
    socket: Option<PathBuf>,
    #[arg(long, global = true, value_name = "URL", hide = true)]
    relay: Option<String>,
    #[arg(skip)]
    #[serde(default)]
    daemon_discovery_relays: Vec<String>,
    #[arg(skip)]
    #[serde(default)]
    daemon_default_account_relays: Vec<String>,
    #[arg(
        long,
        global = true,
        value_enum,
        value_name = "STORE",
        help = "Store account secrets in the OS keychain or local files"
    )]
    secret_store: Option<SecretStoreKind>,
    #[arg(
        long,
        global = true,
        value_name = "SERVICE",
        help = "Use this OS keychain service name for local secret storage"
    )]
    keychain_service: Option<String>,
    #[arg(
        long,
        value_name = "ACCOUNT",
        help = "Select the local account label, npub, or hex pubkey"
    )]
    account: Option<String>,
    #[arg(long, global = true, help = "Emit machine-readable JSON")]
    json: bool,
    #[command(subcommand)]
    command: Command,
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

#[derive(Clone, Debug)]
struct CliRuntimeInfo {
    secret_store: SecretStoreKind,
    keychain_service: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Subcommand)]
enum Command {
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
    #[command(about = "Log in with an nsec or add a public npub identity")]
    Login {
        #[arg(
            value_name = "NSEC_OR_NPUB",
            help = "nsec to import or npub to track as a public account"
        )]
        identity: Option<String>,
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
    #[command(about = "Delete all local Darkmatter CLI data after confirmation")]
    Reset {
        #[arg(long, help = "Required safety flag before deleting local data")]
        confirm: bool,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, Subcommand)]
enum DebugCommand {
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
enum AccountCommand {
    #[command(about = "Create a local account and publish its bootstrap records")]
    Create {
        #[arg(
            value_name = "NSEC_OR_NPUB",
            help = "Optional nsec to import or npub to track"
        )]
        identity: Option<String>,
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
        #[arg(help = "Optional account label, npub, or hex pubkey")]
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
enum KeyPackageCommand {
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
enum ChatsCommand {
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
enum MediaCommand {
    #[command(hide = true)]
    Upload {
        group: String,
        file_path: String,
        #[arg(long)]
        send: bool,
        #[arg(long)]
        message: Option<String>,
    },
    #[command(hide = true)]
    Download { group: String, file_hash: String },
    #[command(about = "List media references for a group")]
    List {
        #[arg(help = "Group id to inspect")]
        group: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, Subcommand)]
enum GroupCommand {
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
}

#[derive(Clone, Debug, Serialize, Deserialize, Subcommand)]
enum GroupsCommand {
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
enum MessageCommand {
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
        #[arg(help = "Group id to watch")]
        group: String,
        #[arg(long, help = "Initial replay limit")]
        limit: Option<usize>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, Subcommand)]
enum FollowsCommand {
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
enum ProfileCommand {
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
enum RelaysCommand {
    #[command(about = "List account relay URLs")]
    List {
        #[arg(
            long = "type",
            value_name = "TYPE",
            help = "Relay list type: nip65, inbox, or key_package"
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
            help = "Relay list type: nip65, inbox, or key_package"
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
            help = "Relay list type: nip65, inbox, or key_package"
        )]
        relay_type: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, Subcommand)]
enum SettingsCommand {
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
enum UsersCommand {
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
enum NotificationsCommand {
    #[command(about = "Subscribe to notification updates")]
    Subscribe,
}

#[derive(Clone, Debug, Serialize, Deserialize, Subcommand)]
enum StreamCommand {
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
enum DaemonCommand {
    #[command(about = "Start dmd in the background")]
    Start {
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
    },
    #[command(about = "Stop the background dmd daemon")]
    Stop,
    #[command(about = "Show daemon status, relay health, and stream watches")]
    Status,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CliOutput {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

pub(crate) type AgentStreamDelta = marmot_app::AgentStreamDelta;

#[derive(Debug)]
pub(crate) struct CommandOutput {
    plain: String,
    json: Value,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum DmError {
    #[error(transparent)]
    AccountHome(#[from] AccountHomeError),
    #[error(transparent)]
    App(#[from] AppError),
    #[error(transparent)]
    QuicStream(#[from] transport_quic_stream::QuicTextStreamError),
    #[error(transparent)]
    QuicBroker(#[from] transport_quic_broker::QuicBrokerError),
    #[error(transparent)]
    AgentTextStreamPayload(#[from] AgentTextStreamAppPayloadError),
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("message text is required")]
    EmptyMessage,
    #[error("group id is required")]
    MissingGroupId,
    #[error("relay URL cannot be empty")]
    EmptyRelayUrl,
    #[error("invalid relay URL: {0}")]
    InvalidRelayUrl(String),
    #[error(
        "relay URL is required; start the daemon with --discovery-relays and --default-account-relays, or pass setup relays for account creation"
    )]
    MissingRelay,
    #[error("no account selected")]
    MissingAccount,
    #[error("multiple accounts exist; pass --account or set DM_ACCOUNT")]
    MultipleAccounts,
    #[error("account not found: {0}")]
    UnknownLocalAccount(String),
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("public Nostr accounts do not have local signing keys")]
    PublicAccountCannotSign,
    #[error("invalid secret store: {0}")]
    InvalidSecretStore(String),
    #[error("stream text is required")]
    EmptyStreamText,
    #[error("no brokered stream start found")]
    MissingStreamStart,
    #[error("brokered stream start has no QUIC candidates")]
    MissingQuicCandidate,
    #[error("unsupported stream route for broker watch: {0}")]
    UnsupportedStreamRoute(String),
    #[error("invalid QUIC candidate: {0}")]
    InvalidQuicCandidate(String),
    #[error("failed to resolve QUIC candidate {candidate}: {source}")]
    QuicCandidateResolve {
        candidate: String,
        source: std::io::Error,
    },
    #[error("transcript hash must be 32 bytes, got {0}")]
    InvalidTranscriptHashLength(usize),
    #[error("choose either --server-cert-der-hex or --insecure-local")]
    ConflictingStreamTrust,
    #[error("--insecure-local is only allowed for loopback QUIC endpoints, got {0}")]
    InsecureLocalRequiresLoopback(SocketAddr),
    #[error("messages subscribe requires the daemon; start it with `dm daemon start`")]
    MessagesSubscribeRequiresDaemon,
    #[error("login requires an nsec or npub identity")]
    MissingLoginIdentity,
    #[error("{command} is not implemented yet: {reason}")]
    UnsupportedCommand {
        command: &'static str,
        reason: &'static str,
    },
    #[error("missing account relay lists: {0:?}")]
    MissingRelayLists(Vec<String>, Box<AccountRelayListStatus>),
}

pub async fn run_from<I, T>(args: I) -> CliOutput
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    let argv = args.into_iter().map(Into::into).collect::<Vec<_>>();
    let wants_json = argv.iter().any(|arg| arg.to_string_lossy() == "--json");
    let cli = match Cli::try_parse_from(argv) {
        Ok(cli) => cli,
        Err(err) => {
            if wants_json {
                return json_error(err.exit_code(), "usage", err.to_string());
            }
            return CliOutput {
                code: err.exit_code(),
                stdout: String::new(),
                stderr: err.to_string(),
            };
        }
    };

    if let Command::Daemon { command } = cli.command.clone() {
        return daemon::run_daemon_command(cli, command).await;
    }

    if matches!(cli.command, Command::Tui) {
        return tui::run_tui(cli).await;
    }

    let home = resolve_home(cli.home.clone());
    if is_background_stream_watch(&cli) {
        let socket = daemon_socket_path_for_client(&cli, &home);
        return match daemon::send_stream_watch(&socket, cli.clone()).await {
            Ok(output) => output,
            Err(err) => daemon_client_error(cli.json, err),
        };
    }

    if is_messages_subscribe(&cli) {
        let socket = daemon_socket_path_for_client(&cli, &home);
        return match daemon::send_messages_subscribe(&socket, cli.clone()).await {
            Ok(output) => output,
            Err(err) => daemon_client_error(cli.json, err),
        };
    }

    if is_chats_subscribe(&cli) {
        let socket = daemon_socket_path_for_client(&cli, &home);
        return match daemon::send_chats_subscribe(&socket, cli.clone()).await {
            Ok(output) => output,
            Err(err) => daemon_client_error(cli.json, err),
        };
    }

    if is_group_state_subscribe(&cli) {
        let socket = daemon_socket_path_for_client(&cli, &home);
        return match daemon::send_group_state_subscribe(&socket, cli.clone()).await {
            Ok(output) => output,
            Err(err) => daemon_client_error(cli.json, err),
        };
    }

    if let Some(socket) = daemon_socket_for_client(&cli, &home) {
        match daemon::send_execute(&socket, cli.clone()).await {
            Ok(output) => return output,
            Err(err) if cli.socket.is_some() || std::env::var_os("DM_SOCKET").is_some() => {
                return daemon_client_error(cli.json, err);
            }
            Err(_) => {}
        }
    }

    run_cli_local(cli).await
}

fn is_background_stream_watch(cli: &Cli) -> bool {
    matches!(
        &cli.command,
        Command::Stream {
            command: StreamCommand::Watch {
                background: true,
                ..
            }
        }
    )
}

fn is_messages_subscribe(cli: &Cli) -> bool {
    matches!(
        &cli.command,
        Command::Message {
            command: MessageCommand::Subscribe { .. },
        } | Command::Messages {
            command: MessageCommand::Subscribe { .. },
        }
    )
}

fn is_chats_subscribe(cli: &Cli) -> bool {
    matches!(
        &cli.command,
        Command::Chats {
            command: ChatsCommand::Subscribe | ChatsCommand::SubscribeArchived,
        }
    )
}

fn is_group_state_subscribe(cli: &Cli) -> bool {
    matches!(
        &cli.command,
        Command::Groups {
            command: GroupsCommand::SubscribeState { .. },
        }
    )
}

pub(crate) async fn run_cli_local(cli: Cli) -> CliOutput {
    match execute(cli).await {
        Ok((json_output, output)) => command_output_result(json_output, Ok(output)),
        Err((json_output, err)) => command_output_result(json_output, Err(err)),
    }
}

pub(crate) fn command_output_result(
    json_output: bool,
    result: Result<CommandOutput, DmError>,
) -> CliOutput {
    match result {
        Ok(output) if json_output => CliOutput {
            code: 0,
            stdout: format!(
                "{}\n",
                serde_json::to_string(&json!({
                    "ok": true,
                    "result": output.json,
                }))
                .expect("JSON response serialization cannot fail")
            ),
            stderr: String::new(),
        },
        Ok(output) => CliOutput {
            code: 0,
            stdout: ensure_trailing_newline(output.plain),
            stderr: String::new(),
        },
        Err(err) if json_output => json_dm_error(err),
        Err(err) => CliOutput {
            code: 1,
            stdout: String::new(),
            stderr: format!("error: {err}\n"),
        },
    }
}

pub(crate) async fn run_stream_watch_local_with_observer<F>(cli: Cli, on_delta: F) -> CliOutput
where
    F: FnMut(AgentStreamDelta) + Send,
{
    let json_output = cli.json;
    match execute_stream_watch_with_observer(cli, on_delta).await {
        Ok(output) if json_output => CliOutput {
            code: 0,
            stdout: format!(
                "{}\n",
                serde_json::to_string(&json!({
                    "ok": true,
                    "result": output.json,
                }))
                .expect("JSON response serialization cannot fail")
            ),
            stderr: String::new(),
        },
        Ok(output) => CliOutput {
            code: 0,
            stdout: ensure_trailing_newline(output.plain),
            stderr: String::new(),
        },
        Err(err) if json_output => json_dm_error(err),
        Err(err) => CliOutput {
            code: 1,
            stdout: String::new(),
            stderr: format!("error: {err}\n"),
        },
    }
}

async fn execute_stream_watch_with_observer<F>(
    cli: Cli,
    on_delta: F,
) -> Result<CommandOutput, DmError>
where
    F: FnMut(AgentStreamDelta) + Send,
{
    let home = resolve_home(cli.home.clone());
    let account_flag = cli.account.clone();
    let command = cli.command.clone();
    let Command::Stream {
        command:
            StreamCommand::Watch {
                group,
                stream_id,
                server_cert_der_hex,
                insecure_local,
                background,
            },
    } = command
    else {
        return unsupported_command(
            "stream watch",
            "daemon stream observers only support stream watch",
        );
    };
    let secret_store = resolve_secret_store(cli.secret_store)?;
    let keychain_service = resolve_keychain_service(cli.keychain_service);
    let account_home = open_account_home(&home, secret_store, &keychain_service)?;
    let relay = resolve_relay(cli.relay)?;
    let app = app_for(home, relay, account_home.clone());
    stream_watch_command_app(
        &account_home,
        &app,
        StreamCommand::Watch {
            group,
            stream_id,
            server_cert_der_hex,
            insecure_local,
            background,
        },
        account_flag,
        on_delta,
    )
    .await
}

async fn execute(cli: Cli) -> Result<(bool, CommandOutput), (bool, DmError)> {
    let json_output = cli.json;
    execute_inner(cli)
        .await
        .map(|output| (json_output, output))
        .map_err(|err| (json_output, err))
}

async fn execute_inner(cli: Cli) -> Result<CommandOutput, DmError> {
    let home = resolve_home(cli.home.clone());
    let account_flag = cli.account.clone();
    let command = cli.command.clone();
    if let Command::Stream { command } = &command
        && matches!(
            command,
            StreamCommand::Receive { .. } | StreamCommand::Send { .. }
        )
    {
        return stream_command_local(command.clone()).await;
    }
    let secret_store = resolve_secret_store(cli.secret_store)?;
    let keychain_service = resolve_keychain_service(cli.keychain_service);
    let runtime_info = CliRuntimeInfo {
        secret_store,
        keychain_service: keychain_service.clone(),
    };
    let account_home = open_account_home(&home, secret_store, &keychain_service)?;
    let command_relay = match &command {
        Command::Login { relay, .. } => relay.clone().or_else(|| cli.relay.clone()),
        _ => cli.relay.clone(),
    };
    let relay = resolve_relay(command_relay)?;
    let app = app_for(
        home.clone(),
        relay
            .clone()
            .or_else(|| cli.daemon_discovery_relays.first().cloned())
            .or_else(|| cli.daemon_default_account_relays.first().cloned()),
        account_home.clone(),
    );
    match command {
        Command::Debug { command } => debug_command(&account_home, &app, command, account_flag),
        Command::CreateIdentity => {
            identity_create_command(
                &app,
                runtime_info,
                relay,
                cli.daemon_default_account_relays,
                cli.daemon_discovery_relays,
            )
            .await
        }
        Command::Login { identity, relay: _ } => {
            identity_login_command(
                &app,
                runtime_info,
                identity,
                relay,
                cli.daemon_default_account_relays,
                cli.daemon_discovery_relays,
            )
            .await
        }
        Command::Whoami => whoami_command(&account_home, &app, runtime_info, account_flag),
        Command::Logout { pubkey } => logout_command(&account_home, pubkey),
        Command::ExportNsec { pubkey } => export_nsec_command(pubkey),
        Command::Account { command } => {
            account_command(
                &account_home,
                &app,
                command,
                runtime_info,
                account_flag,
                relay,
            )
            .await
        }
        Command::Accounts { command } => {
            account_command(
                &account_home,
                &app,
                command,
                runtime_info,
                account_flag,
                relay,
            )
            .await
        }
        Command::Keys { command } => {
            key_package_command(&account_home, &app, command, account_flag).await
        }
        Command::Chats { command } => {
            chats_command(&account_home, &app, command, account_flag).await
        }
        Command::Media { command } => {
            media_command(&account_home, &app, command, account_flag).await
        }
        Command::Group { command } => {
            group_command(&account_home, &app, command, account_flag).await
        }
        Command::Groups { command } => {
            groups_command(&account_home, &app, command, account_flag).await
        }
        Command::Message { command } => {
            message_command(&account_home, &app, command, account_flag).await
        }
        Command::Messages { command } => {
            message_command(&account_home, &app, command, account_flag).await
        }
        Command::Follows { command } => {
            follows_command(&account_home, &app, command, account_flag, relay).await
        }
        Command::Profile { command } => {
            profile_command(&account_home, &app, command, account_flag, relay).await
        }
        Command::Relays { command } => {
            relays_command(&account_home, &app, command, account_flag, relay).await
        }
        Command::Settings { command } => settings_command(&home, command),
        Command::Users { command } => users_command(&account_home, &app, command, account_flag),
        Command::Notifications { command } => notifications_command(command),
        Command::Stream { command } => {
            stream_command_app(&account_home, &app, command, account_flag).await
        }
        Command::Daemon { .. } => Ok(CommandOutput {
            plain: "daemon command is handled by dm".to_owned(),
            json: json!({"handled": "client"}),
        }),
        Command::Tui => Ok(CommandOutput {
            plain: "tui command is handled by dm".to_owned(),
            json: json!({"handled": "client"}),
        }),
        Command::Sync => {
            let account = resolve_account(&account_home, account_flag)?;
            ensure_local_signing(&account)?;
            sync_command(&app, account).await
        }
        Command::Reset { confirm } => reset_command(&home, confirm),
    }
}

fn daemon_socket_for_client(cli: &Cli, home: &Path) -> Option<PathBuf> {
    let socket = daemon_socket_path_for_client(cli, home);
    if cli.socket.is_some() || std::env::var_os("DM_SOCKET").is_some() || socket.exists() {
        Some(socket)
    } else {
        None
    }
}

fn daemon_socket_path_for_client(cli: &Cli, home: &Path) -> PathBuf {
    let env_socket = std::env::var_os("DM_SOCKET").map(PathBuf::from);
    cli.socket
        .clone()
        .or(env_socket.clone())
        .unwrap_or_else(|| daemon::default_socket_path(home))
}

fn daemon_client_error(json_output: bool, err: daemon::DaemonClientError) -> CliOutput {
    if json_output {
        return CliOutput {
            code: 1,
            stdout: format!(
                "{}\n",
                serde_json::to_string(&json!({
                    "ok": false,
                    "error": {
                        "code": "daemon_unavailable",
                        "message": err.to_string(),
                    }
                }))
                .expect("JSON response serialization cannot fail")
            ),
            stderr: String::new(),
        };
    }
    CliOutput {
        code: 1,
        stdout: String::new(),
        stderr: format!("error: {err}\n"),
    }
}

async fn identity_create_command(
    app: &MarmotApp,
    runtime_info: CliRuntimeInfo,
    relay: Option<String>,
    default_relays: Vec<String>,
    bootstrap_relays: Vec<String>,
) -> Result<CommandOutput, DmError> {
    create_or_import_account_command(
        app,
        None,
        default_relays,
        bootstrap_relays,
        false,
        true,
        runtime_info,
        relay,
    )
    .await
}

async fn identity_login_command(
    app: &MarmotApp,
    runtime_info: CliRuntimeInfo,
    identity: Option<String>,
    relay: Option<String>,
    default_relays: Vec<String>,
    bootstrap_relays: Vec<String>,
) -> Result<CommandOutput, DmError> {
    let Some(identity) = identity else {
        return Err(DmError::MissingLoginIdentity);
    };
    create_or_import_account_command(
        app,
        Some(identity),
        default_relays,
        bootstrap_relays,
        true,
        true,
        runtime_info,
        relay,
    )
    .await
}

fn whoami_command(
    account_home: &AccountHome,
    app: &MarmotApp,
    runtime_info: CliRuntimeInfo,
    account_flag: Option<String>,
) -> Result<CommandOutput, DmError> {
    if account_flag.is_some() {
        let account = resolve_account(account_home, account_flag)?;
        let status = if account.local_signing {
            app.status(&account.label)?;
            dm_status_json(app.status(&account.label)?, &runtime_info)
        } else {
            public_account_status_json(
                &account,
                app.account_relay_list_status_for_account_id(&account.account_id_hex)?,
            )
        };
        return Ok(CommandOutput {
            plain: serde_json::to_string_pretty(&status)
                .expect("JSON response serialization cannot fail"),
            json: status,
        });
    }

    let accounts = account_home.accounts()?;
    let accounts_json = accounts
        .into_iter()
        .map(|account| account_summary_json(app, account))
        .collect::<Vec<_>>();
    let plain = if accounts_json.is_empty() {
        "no accounts".to_owned()
    } else {
        accounts_json
            .iter()
            .map(|account| {
                format!(
                    "{} {} local-signing={}",
                    account_display_name_or_npub(account),
                    account
                        .get("account_id")
                        .and_then(Value::as_str)
                        .unwrap_or(""),
                    account
                        .get("local_signing")
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    Ok(CommandOutput {
        plain,
        json: json!({ "accounts": accounts_json }),
    })
}

fn debug_command(
    account_home: &AccountHome,
    app: &MarmotApp,
    command: DebugCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, DmError> {
    match command {
        DebugCommand::RelayControlState => {
            let accounts = account_home.accounts()?;
            let statuses = accounts
                .into_iter()
                .map(|account| {
                    let relay_lists = app
                        .account_relay_list_status_for_account_id(&account.account_id_hex)
                        .map(relay_lists_json)
                        .unwrap_or_else(|err| json!({"error": err.to_string()}));
                    json!({
                        "account_id": account.account_id_hex,
                        "npub": npub_for_account_id(&account.account_id_hex),
                        "relay_lists": relay_lists,
                    })
                })
                .collect::<Vec<_>>();
            Ok(CommandOutput {
                plain: serde_json::to_string_pretty(&statuses)
                    .expect("JSON response serialization cannot fail"),
                json: json!({ "accounts": statuses }),
            })
        }
        DebugCommand::Health => {
            let account = resolve_account(account_home, account_flag)?;
            let status = app.status(&account.label)?;
            Ok(CommandOutput {
                plain: format!(
                    "healthy account={} groups={} messages={}",
                    account.account_id_hex, status.group_count, status.message_count
                ),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex),
                    "healthy": true,
                    "groups": status.group_count,
                    "messages": status.message_count,
                    "seen_events": status.seen_events,
                }),
            })
        }
        DebugCommand::RatchetTree { .. } => unsupported_command(
            "debug ratchet-tree",
            "ratchet-tree diagnostics are not exposed by marmot-app yet",
        ),
    }
}

fn logout_command(account_home: &AccountHome, pubkey: String) -> Result<CommandOutput, DmError> {
    let account_id = parse_public_key(&pubkey)?;
    account_home.remove_account(&account_id)?;
    Ok(CommandOutput {
        plain: format!("logged out {}", npub_for_account_id(&account_id)),
        json: json!({
            "account_id": account_id,
            "npub": npub_for_account_id(&account_id),
            "logged_out": true,
        }),
    })
}

fn export_nsec_command(_pubkey: String) -> Result<CommandOutput, DmError> {
    unsupported_command(
        "export-nsec",
        "Darkmatter CLI policy forbids printing private keys",
    )
}

fn unsupported_command<T>(command: &'static str, reason: &'static str) -> Result<T, DmError> {
    Err(DmError::UnsupportedCommand { command, reason })
}

#[allow(clippy::too_many_arguments)]
async fn create_or_import_account_command(
    app: &MarmotApp,
    identity: Option<String>,
    mut default_relays: Vec<String>,
    mut bootstrap_relays: Vec<String>,
    publish_missing_relay_lists: bool,
    publish_initial_key_package: bool,
    _runtime_info: CliRuntimeInfo,
    relay: Option<String>,
) -> Result<CommandOutput, DmError> {
    let global_relay_defaults =
        apply_global_relay_defaults(&mut default_relays, &mut bootstrap_relays, relay);
    let imports_private_key = identity.as_deref().is_some_and(is_nostr_secret);
    let creates_new_private_key = identity.is_none();
    let adds_public_account = identity
        .as_deref()
        .is_some_and(|value| !is_nostr_secret(value));
    if creates_new_private_key && default_relays.is_empty() {
        return Err(DmError::MissingRelay);
    }
    if imports_private_key && default_relays.is_empty() && bootstrap_relays.is_empty() {
        return Err(DmError::MissingRelay);
    }
    if adds_public_account && bootstrap_relays.is_empty() && default_relays.is_empty() {
        return Err(DmError::MissingRelay);
    }
    if adds_public_account && !default_relays.is_empty() && !global_relay_defaults.default_relays {
        return Err(DmError::PublicAccountCannotSign);
    }

    let default_relays = relay_endpoints(default_relays)?;
    let bootstrap_relays = relay_endpoints(bootstrap_relays)?;
    let setup = app
        .runtime()
        .create_or_import_account(AccountSetupRequest {
            identity,
            default_relays,
            bootstrap_relays,
            publish_missing_relay_lists,
            publish_initial_key_package,
        })
        .await
        .map_err(map_account_setup_error)?;

    account_setup_command_output(setup)
}

pub(crate) fn account_setup_command_output(
    setup: AccountSetupResult,
) -> Result<CommandOutput, DmError> {
    let key_package_plain = setup
        .key_package_bytes
        .map(|bytes| format!(" key-package-bytes={bytes}"))
        .unwrap_or_default();
    Ok(CommandOutput {
        plain: format!(
            "created identity {} local-signing={} relay-lists={}{}",
            npub_for_account_id(&setup.account.account_id_hex),
            setup.account.local_signing,
            relay_setup_plain(&setup.relay_lists),
            key_package_plain
        ),
        json: json!({
            "account_id": setup.account.account_id_hex,
            "npub": npub_for_account_id(&setup.account.account_id_hex),
            "local_signing": setup.account.local_signing,
            "relay_lists": relay_lists_json(setup.relay_lists),
            "key_package": setup.key_package_bytes.map(|bytes| json!({
                "published": true,
                "bytes": bytes,
            })),
            "profile": setup.profile,
        }),
    })
}

pub(crate) fn map_account_setup_error(err: AppError) -> DmError {
    if let AppError::MissingRelayLists(missing) = &err {
        let status = missing_relay_list_status(missing.clone());
        return DmError::MissingRelayLists(missing.clone(), Box::new(status));
    }
    err.into()
}

fn missing_relay_list_status(missing: Vec<String>) -> AccountRelayListStatus {
    AccountRelayListStatus {
        complete: false,
        missing,
        default_relays: Vec::new(),
        bootstrap_relays: Vec::new(),
        nip65: marmot_app::AccountRelayListState {
            kind: 10002,
            relays: Vec::new(),
        },
        inbox: marmot_app::AccountRelayListState {
            kind: 10050,
            relays: Vec::new(),
        },
        key_package: marmot_app::AccountRelayListState {
            kind: 10051,
            relays: Vec::new(),
        },
    }
}

async fn account_command(
    account_home: &AccountHome,
    app: &MarmotApp,
    command: AccountCommand,
    runtime_info: CliRuntimeInfo,
    account_flag: Option<String>,
    relay: Option<String>,
) -> Result<CommandOutput, DmError> {
    match command {
        AccountCommand::Create {
            identity,
            default_relays,
            bootstrap_relays,
            publish_missing_relay_lists,
        } => {
            create_or_import_account_command(
                app,
                identity,
                default_relays,
                bootstrap_relays,
                publish_missing_relay_lists,
                false,
                runtime_info,
                relay,
            )
            .await
        }
        AccountCommand::List => {
            let accounts = account_home.accounts()?;
            let accounts_json = accounts
                .into_iter()
                .map(|account| account_summary_json(app, account))
                .collect::<Vec<_>>();
            let plain = if accounts_json.is_empty() {
                "no accounts".to_owned()
            } else {
                accounts_json
                    .iter()
                    .map(|account| {
                        format!(
                            "{} {} local-signing={}",
                            account_display_name_or_npub(account),
                            account
                                .get("account_id")
                                .and_then(Value::as_str)
                                .unwrap_or(""),
                            account
                                .get("local_signing")
                                .and_then(Value::as_bool)
                                .unwrap_or(false)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            Ok(CommandOutput {
                plain,
                json: json!({ "accounts": accounts_json }),
            })
        }
        AccountCommand::Status { account } => {
            let account = resolve_account(account_home, account.or(account_flag))?;
            if !account.local_signing {
                let relay_lists =
                    app.account_relay_list_status_for_account_id(&account.account_id_hex)?;
                let json = public_account_status_json(&account, relay_lists);
                return Ok(CommandOutput {
                    plain: serde_json::to_string_pretty(&json)
                        .expect("JSON response serialization cannot fail"),
                    json,
                });
            }
            let status = app.status(&account.label)?;
            Ok(CommandOutput {
                plain: serde_json::to_string_pretty(&dm_status_json(status.clone(), &runtime_info))
                    .expect("JSON response serialization cannot fail"),
                json: dm_status_json(status, &runtime_info),
            })
        }
        AccountCommand::RelayLists {
            account,
            bootstrap_relays,
        } => {
            let account_id = account_selector_or_default(account_home, account, account_flag)?;
            let relay_lists = relay_list_status_for_account_id(
                app,
                &account_id,
                relay_endpoints(bootstrap_relays)?,
            )
            .await?;
            Ok(CommandOutput {
                plain: relay_setup_plain(&relay_lists),
                json: json!({
                    "account_id": account_id,
                    "npub": npub_for_account_id(&account_id),
                    "relay_lists": relay_lists_json(relay_lists),
                }),
            })
        }
    }
}

async fn key_package_command(
    account_home: &AccountHome,
    app: &MarmotApp,
    command: KeyPackageCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, DmError> {
    let runtime = app.runtime();
    key_package_command_with_runtime(account_home, app, &runtime, command, account_flag).await
}

pub(crate) async fn key_package_command_with_runtime(
    account_home: &AccountHome,
    app: &MarmotApp,
    runtime: &MarmotAppRuntime,
    command: KeyPackageCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, DmError> {
    match command {
        KeyPackageCommand::List => {
            let account = resolve_account(account_home, account_flag)?;
            let relay_lists =
                app.account_relay_list_status_for_account_id(&account.account_id_hex)?;
            let fetched = if relay_lists.key_package.relays.is_empty() {
                None
            } else {
                app.fetch_latest_key_package_for_account_id(
                    &account.account_id_hex,
                    relay_endpoints(relay_lists.key_package.relays.clone())?,
                )
                .await
                .ok()
            };
            let keys = fetched
                .into_iter()
                .map(key_package_fetch_json)
                .collect::<Vec<_>>();
            Ok(CommandOutput {
                plain: if keys.is_empty() {
                    "no key packages".to_owned()
                } else {
                    format!("{} key package(s)", keys.len())
                },
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex),
                    "keys": keys,
                }),
            })
        }
        KeyPackageCommand::Publish => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let key_package_bytes = runtime.publish_key_package(&account.label).await?;
            Ok(CommandOutput {
                plain: format!(
                    "published key package for {} bytes={}",
                    npub_for_account_id(&account.account_id_hex),
                    key_package_bytes
                ),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex),
                    "key_package_bytes": key_package_bytes,
                }),
            })
        }
        KeyPackageCommand::Rotate => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let key_package_bytes = runtime.rotate_key_package(&account.label).await?;
            Ok(CommandOutput {
                plain: format!(
                    "rotated key package for {} bytes={}",
                    npub_for_account_id(&account.account_id_hex),
                    key_package_bytes
                ),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex),
                    "key_package_bytes": key_package_bytes,
                    "rotated": true,
                }),
            })
        }
        KeyPackageCommand::Fetch {
            account,
            bootstrap_relays,
        } => {
            let account_id = account_selector_or_default(account_home, account, account_flag)?;
            let fetched = app
                .fetch_latest_key_package_for_account_id(
                    &account_id,
                    relay_endpoints(bootstrap_relays)?,
                )
                .await?;
            Ok(CommandOutput {
                plain: format!(
                    "fetched key package for {account_id} bytes={} relays={}",
                    fetched.key_package.0.len(),
                    fetched.source_relays.join(",")
                ),
                json: key_package_fetch_json(fetched),
            })
        }
        KeyPackageCommand::Check { pubkey } => {
            let account_id = parse_public_key(&pubkey)?;
            let fetched = app
                .fetch_latest_key_package_for_account_id(&account_id, Vec::new())
                .await?;
            Ok(CommandOutput {
                plain: format!("key package available for {account_id}"),
                json: json!({
                    "account_id": account_id,
                    "npub": npub_for_account_id(&account_id),
                    "available": true,
                    "key_package": key_package_fetch_json(fetched),
                }),
            })
        }
        KeyPackageCommand::Delete { .. } => unsupported_command(
            "keys delete",
            "relay deletion for KeyPackage events is not implemented yet",
        ),
        KeyPackageCommand::DeleteAll { confirm } => {
            if !confirm {
                return unsupported_command(
                    "keys delete-all",
                    "pass --confirm once relay deletion is implemented",
                );
            }
            unsupported_command(
                "keys delete-all",
                "relay deletion for KeyPackage events is not implemented yet",
            )
        }
    }
}

async fn chats_command(
    account_home: &AccountHome,
    app: &MarmotApp,
    command: ChatsCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, DmError> {
    match command {
        ChatsCommand::List { include_archived } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let chats = if include_archived {
                app.groups(&account.label)?
            } else {
                app.visible_groups(&account.label)?
            };
            Ok(CommandOutput {
                plain: group_list_plain(&chats),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex),
                    "include_archived": include_archived,
                    "chats": chats.into_iter().map(group_json).collect::<Vec<_>>(),
                }),
            })
        }
        ChatsCommand::Show { group } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            group_show_output(app, account, group, None)
        }
        ChatsCommand::Subscribe => Err(DmError::MessagesSubscribeRequiresDaemon),
        ChatsCommand::Archive { group } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            group_archive_output(app, account, group, true)
        }
        ChatsCommand::Unarchive { group } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            group_archive_output(app, account, group, false)
        }
        ChatsCommand::ListArchived => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let chats = app
                .groups(&account.label)?
                .into_iter()
                .filter(|group| group.archived)
                .collect::<Vec<_>>();
            Ok(CommandOutput {
                plain: group_list_plain(&chats),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex),
                    "chats": chats.into_iter().map(group_json).collect::<Vec<_>>(),
                }),
            })
        }
        ChatsCommand::SubscribeArchived => Err(DmError::MessagesSubscribeRequiresDaemon),
        ChatsCommand::Mute { .. } => unsupported_command(
            "chats mute",
            "chat notification mute state is not modeled in marmot-app yet",
        ),
        ChatsCommand::Unmute { .. } => unsupported_command(
            "chats unmute",
            "chat notification mute state is not modeled in marmot-app yet",
        ),
    }
}

async fn media_command(
    account_home: &AccountHome,
    app: &MarmotApp,
    command: MediaCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, DmError> {
    let runtime = app.runtime();
    media_command_with_runtime(account_home, app, &runtime, command, account_flag).await
}

pub(crate) async fn media_command_with_runtime(
    account_home: &AccountHome,
    app: &MarmotApp,
    runtime: &MarmotAppRuntime,
    command: MediaCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, DmError> {
    match command {
        MediaCommand::Upload { .. } => unsupported_command(
            "media upload",
            "encrypted media upload/download is not implemented in Darkmatter yet",
        ),
        MediaCommand::Download { .. } => unsupported_command(
            "media download",
            "encrypted media upload/download is not implemented in Darkmatter yet",
        ),
        MediaCommand::List { group } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id_hex = normalize_group_id_hex(&group)?;
            let messages = runtime.messages_with_query(
                &account.account_id_hex,
                AppMessageQuery {
                    group_id_hex: Some(group_id_hex.clone()),
                    limit: None,
                },
            )?;
            let media = media_records_json(messages);
            Ok(CommandOutput {
                plain: if media.is_empty() {
                    "no media".to_owned()
                } else {
                    media
                        .iter()
                        .filter_map(|item| item.get("file_name").and_then(Value::as_str))
                        .collect::<Vec<_>>()
                        .join("\n")
                },
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex),
                    "group_id": group_id_hex,
                    "media": media,
                }),
            })
        }
    }
}

async fn group_command(
    account_home: &AccountHome,
    app: &MarmotApp,
    command: GroupCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, DmError> {
    let runtime = app.runtime();
    group_command_with_runtime(account_home, app, &runtime, command, account_flag).await
}

pub(crate) async fn group_command_with_runtime(
    account_home: &AccountHome,
    app: &MarmotApp,
    runtime: &MarmotAppRuntime,
    command: GroupCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, DmError> {
    match command {
        GroupCommand::Create {
            name,
            members,
            description,
        } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id = runtime
                .create_group(&account.label, &name, &members, description.clone())
                .await?;
            let group_id_hex = hex::encode(group_id.as_slice());
            let group = app
                .group(&account.label, &group_id_hex)?
                .ok_or_else(|| AppError::UnknownGroup(group_id_hex.clone()))?;
            Ok(CommandOutput {
                plain: format!("created group {group_id_hex}"),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex),
                    "group_id": group.group_id_hex,
                    "name": group.profile.name.clone(),
                    "profile": group.profile,
                    "image": group.image,
                    "admin_policy": group.admin_policy,
                    "agent_text_stream": group.agent_text_stream,
                    "members": members,
                }),
            })
        }
        GroupCommand::Members { group } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id = GroupId::new(hex::decode(normalize_group_id_hex(&group)?)?);
            let members = runtime.group_members(&account.label, &group_id).await?;
            Ok(CommandOutput {
                plain: group_members_plain(&members),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex),
                    "group_id": hex::encode(group_id.as_slice()),
                    "members": group_members_json(members),
                }),
            })
        }
        GroupCommand::Invite { group, members } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id = GroupId::new(hex::decode(normalize_group_id_hex(&group)?)?);
            let summary = runtime
                .invite_members(&account.label, &group_id, &members)
                .await?;
            Ok(CommandOutput {
                plain: format!(
                    "invited {} member(s) published={}",
                    members.len(),
                    summary.published
                ),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex),
                    "group_id": hex::encode(group_id.as_slice()),
                    "members": members,
                    "published": summary.published,
                    "message_ids": summary.message_ids,
                }),
            })
        }
        GroupCommand::Remove { group, members } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id = GroupId::new(hex::decode(normalize_group_id_hex(&group)?)?);
            let summary = runtime
                .remove_members(&account.label, &group_id, &members)
                .await?;
            Ok(CommandOutput {
                plain: format!(
                    "removed {} member(s) published={}",
                    members.len(),
                    summary.published
                ),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex),
                    "group_id": hex::encode(group_id.as_slice()),
                    "members": members,
                    "published": summary.published,
                    "message_ids": summary.message_ids,
                }),
            })
        }
        GroupCommand::Update {
            group,
            name,
            description,
        } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id = GroupId::new(hex::decode(normalize_group_id_hex(&group)?)?);
            let summary = runtime
                .update_group_profile(&account.label, &group_id, name, description)
                .await?;
            let group_id_hex = hex::encode(group_id.as_slice());
            let group = app
                .group(&account.label, &group_id_hex)?
                .ok_or_else(|| AppError::UnknownGroup(group_id_hex.clone()))?;
            Ok(CommandOutput {
                plain: format!(
                    "updated group {group_id_hex} published={}",
                    summary.published
                ),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex),
                    "group": group_json(group),
                    "published": summary.published,
                    "message_ids": summary.message_ids,
                }),
            })
        }
    }
}

async fn groups_command(
    account_home: &AccountHome,
    app: &MarmotApp,
    command: GroupsCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, DmError> {
    let runtime = app.runtime();
    groups_command_with_runtime(account_home, app, &runtime, command, account_flag).await
}

pub(crate) async fn groups_command_with_runtime(
    account_home: &AccountHome,
    app: &MarmotApp,
    runtime: &MarmotAppRuntime,
    command: GroupsCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, DmError> {
    match command {
        GroupsCommand::List => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let groups = app.visible_groups(&account.label)?;
            Ok(CommandOutput {
                plain: group_list_plain(&groups),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex),
                    "groups": groups.into_iter().map(group_json).collect::<Vec<_>>(),
                }),
            })
        }
        GroupsCommand::Create {
            name,
            members,
            description,
        } => {
            group_command_with_runtime(
                account_home,
                app,
                runtime,
                GroupCommand::Create {
                    name,
                    members,
                    description,
                },
                account_flag,
            )
            .await
        }
        GroupsCommand::Show { group_id } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id_hex = normalize_group_id_hex(&group_id)?;
            let group_id = GroupId::new(hex::decode(&group_id_hex)?);
            let mls = runtime
                .group_mls_state(&account.label, &group_id)
                .await
                .map(group_mls_state_json)?;
            group_show_output(app, account, group_id_hex, Some(mls))
        }
        GroupsCommand::AddMembers { group_id, members } => {
            group_command_with_runtime(
                account_home,
                app,
                runtime,
                GroupCommand::Invite {
                    group: group_id,
                    members,
                },
                account_flag,
            )
            .await
        }
        GroupsCommand::RemoveMembers { group_id, members } => {
            group_command_with_runtime(
                account_home,
                app,
                runtime,
                GroupCommand::Remove {
                    group: group_id,
                    members,
                },
                account_flag,
            )
            .await
        }
        GroupsCommand::Members { group_id } => {
            group_command_with_runtime(
                account_home,
                app,
                runtime,
                GroupCommand::Members { group: group_id },
                account_flag,
            )
            .await
        }
        GroupsCommand::Admins { group_id } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id = normalize_group_id_hex(&group_id)?;
            let group = app
                .group(&account.label, &group_id)?
                .ok_or_else(|| AppError::UnknownGroup(group_id.clone()))?;
            let admins = group
                .admin_policy
                .admins
                .iter()
                .map(|admin| {
                    json!({
                        "admin_id": admin,
                        "npub": npub_for_account_id(admin),
                    })
                })
                .collect::<Vec<_>>();
            Ok(CommandOutput {
                plain: if admins.is_empty() {
                    "no admins".to_owned()
                } else {
                    admins
                        .iter()
                        .filter_map(|admin| admin.get("npub").and_then(Value::as_str))
                        .collect::<Vec<_>>()
                        .join("\n")
                },
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex),
                    "group_id": group_id,
                    "admins": admins,
                }),
            })
        }
        GroupsCommand::Relays { group_id } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id = normalize_group_id_hex(&group_id)?;
            let group = app
                .group(&account.label, &group_id)?
                .ok_or_else(|| AppError::UnknownGroup(group_id.clone()))?;
            Ok(CommandOutput {
                plain: group.endpoint.clone(),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex),
                    "group_id": group_id,
                    "relays": [group.endpoint],
                }),
            })
        }
        GroupsCommand::Leave { group_id } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id = GroupId::new(hex::decode(normalize_group_id_hex(&group_id)?)?);
            let summary = runtime.leave_group(&account.label, &group_id).await?;
            Ok(CommandOutput {
                plain: format!(
                    "left group {} published={}",
                    hex::encode(group_id.as_slice()),
                    summary.published
                ),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex),
                    "group_id": hex::encode(group_id.as_slice()),
                    "published": summary.published,
                    "message_ids": summary.message_ids,
                }),
            })
        }
        GroupsCommand::Rename { group_id, name } => {
            group_command_with_runtime(
                account_home,
                app,
                runtime,
                GroupCommand::Update {
                    group: group_id,
                    name: Some(name),
                    description: None,
                },
                account_flag,
            )
            .await
        }
        GroupsCommand::Invites => unsupported_command(
            "groups invites",
            "user-driven invite accept/decline state is not modeled yet",
        ),
        GroupsCommand::Accept { .. } => unsupported_command(
            "groups accept",
            "welcomes are auto-accepted today; user-driven accept is not modeled yet",
        ),
        GroupsCommand::Decline { .. } => unsupported_command(
            "groups decline",
            "user-driven invite decline is not modeled yet",
        ),
        GroupsCommand::Promote { group_id, pubkey } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            group_admin_policy_output(
                app,
                runtime,
                account,
                group_id,
                GroupAdminAction::Promote(pubkey),
            )
            .await
        }
        GroupsCommand::Demote { group_id, pubkey } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            group_admin_policy_output(
                app,
                runtime,
                account,
                group_id,
                GroupAdminAction::Demote(pubkey),
            )
            .await
        }
        GroupsCommand::SelfDemote { group_id } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            group_admin_policy_output(
                app,
                runtime,
                account,
                group_id,
                GroupAdminAction::SelfDemote,
            )
            .await
        }
        GroupsCommand::SubscribeState { .. } => Err(DmError::MessagesSubscribeRequiresDaemon),
    }
}

enum GroupAdminAction {
    Promote(String),
    Demote(String),
    SelfDemote,
}

async fn group_admin_policy_output(
    app: &MarmotApp,
    runtime: &MarmotAppRuntime,
    account: marmot_account::AccountSummary,
    group_id: String,
    action: GroupAdminAction,
) -> Result<CommandOutput, DmError> {
    app.status(&account.label)?;
    let group_id = GroupId::new(hex::decode(normalize_group_id_hex(&group_id)?)?);
    let group_id_hex = hex::encode(group_id.as_slice());
    let (verb, admin_id, summary) = match action {
        GroupAdminAction::Promote(pubkey) => {
            let admin_id = parse_public_key(&pubkey)?;
            let summary = runtime
                .promote_admin(&account.label, &group_id, &pubkey)
                .await?;
            ("promoted", admin_id, summary)
        }
        GroupAdminAction::Demote(pubkey) => {
            let admin_id = parse_public_key(&pubkey)?;
            let summary = runtime
                .demote_admin(&account.label, &group_id, &pubkey)
                .await?;
            ("demoted", admin_id, summary)
        }
        GroupAdminAction::SelfDemote => {
            let admin_id = account.account_id_hex.clone();
            let summary = runtime.self_demote_admin(&account.label, &group_id).await?;
            ("self-demoted", admin_id, summary)
        }
    };
    let group = app
        .group(&account.label, &group_id_hex)?
        .ok_or_else(|| AppError::UnknownGroup(group_id_hex.clone()))?;
    let admin_npub = npub_for_account_id(&admin_id);
    Ok(CommandOutput {
        plain: format!("{verb} admin {} published={}", admin_id, summary.published),
        json: json!({
            "account_id": account.account_id_hex,
            "npub": npub_for_account_id(&account.account_id_hex),
            "group_id": group_id_hex,
            "admin_id": admin_id,
            "admin_npub": admin_npub,
            "group": group_json(group),
            "published": summary.published,
            "message_ids": summary.message_ids,
        }),
    })
}

fn group_show_output(
    app: &MarmotApp,
    account: marmot_account::AccountSummary,
    group: String,
    mls: Option<Value>,
) -> Result<CommandOutput, DmError> {
    app.status(&account.label)?;
    let group_id = normalize_group_id_hex(&group)?;
    let group = app
        .group(&account.label, &group_id)?
        .ok_or_else(|| AppError::UnknownGroup(group_id.clone()))?;
    let plain = group_plain(&group);
    let group = group_json(group);
    let json = match mls {
        Some(mls) => json!({
            "account_id": account.account_id_hex,
            "npub": npub_for_account_id(&account.account_id_hex),
            "group": group,
            "mls": mls,
        }),
        None => json!({
            "account_id": account.account_id_hex,
            "npub": npub_for_account_id(&account.account_id_hex),
            "group": group,
        }),
    };
    Ok(CommandOutput { plain, json })
}

fn group_archive_output(
    app: &MarmotApp,
    account: marmot_account::AccountSummary,
    group: String,
    archived: bool,
) -> Result<CommandOutput, DmError> {
    app.status(&account.label)?;
    let group_id = normalize_group_id_hex(&group)?;
    let group = app.set_group_archived(&account.label, &group_id, archived)?;
    let verb = if archived { "archived" } else { "unarchived" };
    Ok(CommandOutput {
        plain: format!("{verb} group {group_id}"),
        json: json!({
            "account_id": account.account_id_hex,
            "npub": npub_for_account_id(&account.account_id_hex),
            "group": group_json(group),
        }),
    })
}

fn message_target_and_text(
    group_flag: Option<String>,
    mut args: Vec<String>,
) -> Result<(String, Vec<String>), DmError> {
    if let Some(group) = group_flag {
        return Ok((group, args));
    }
    if args.is_empty() {
        return Err(DmError::MissingGroupId);
    }
    let group = args.remove(0);
    Ok((group, args))
}

async fn message_command(
    account_home: &AccountHome,
    app: &MarmotApp,
    command: MessageCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, DmError> {
    let runtime = app.runtime();
    message_command_with_runtime(account_home, app, &runtime, command, account_flag).await
}

pub(crate) async fn message_command_with_runtime(
    account_home: &AccountHome,
    app: &MarmotApp,
    runtime: &MarmotAppRuntime,
    command: MessageCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, DmError> {
    match command {
        MessageCommand::Send { group_flag, args } => {
            let (group, text) = message_target_and_text(group_flag, args)?;
            if text.is_empty() {
                return Err(DmError::EmptyMessage);
            }
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id = GroupId::new(hex::decode(group)?);
            let payload = text.join(" ");
            let summary = runtime
                .send_message(&account.label, &group_id, payload.into_bytes())
                .await?;
            Ok(CommandOutput {
                plain: format!("sent message published={}", summary.published),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex),
                    "group_id": hex::encode(group_id.as_slice()),
                    "published": summary.published,
                    "message_ids": summary.message_ids,
                }),
            })
        }
        MessageCommand::Delete {
            group_id,
            message_id,
        } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id = GroupId::new(hex::decode(normalize_group_id_hex(&group_id)?)?);
            let summary = runtime
                .delete_message(&account.label, &group_id, &message_id)
                .await?;
            Ok(CommandOutput {
                plain: format!(
                    "deleted message {message_id} published={}",
                    summary.published
                ),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex),
                    "group_id": hex::encode(group_id.as_slice()),
                    "target_message_id": message_id,
                    "published": summary.published,
                    "message_ids": summary.message_ids,
                }),
            })
        }
        MessageCommand::Retry { group_id, event_id } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id = GroupId::new(hex::decode(normalize_group_id_hex(&group_id)?)?);
            let summary = runtime
                .retry_group_convergence(&account.label, &group_id)
                .await?;
            Ok(CommandOutput {
                plain: format!(
                    "retried group convergence for {event_id} published={}",
                    summary.published
                ),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex),
                    "group_id": hex::encode(group_id.as_slice()),
                    "target_event_id": event_id,
                    "retry_scope": "group_convergence",
                    "published": summary.published,
                    "message_ids": summary.message_ids,
                }),
            })
        }
        MessageCommand::React {
            group_id,
            message_id,
            emoji,
        } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id = GroupId::new(hex::decode(normalize_group_id_hex(&group_id)?)?);
            let summary = runtime
                .react_to_message(&account.label, &group_id, &message_id, &emoji)
                .await?;
            Ok(CommandOutput {
                plain: format!(
                    "reacted {emoji} to {message_id} published={}",
                    summary.published
                ),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex),
                    "group_id": hex::encode(group_id.as_slice()),
                    "target_message_id": message_id,
                    "emoji": emoji,
                    "published": summary.published,
                    "message_ids": summary.message_ids,
                }),
            })
        }
        MessageCommand::Unreact {
            group_id,
            message_id,
        } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id = GroupId::new(hex::decode(normalize_group_id_hex(&group_id)?)?);
            let summary = runtime
                .unreact_from_message(&account.label, &group_id, &message_id)
                .await?;
            Ok(CommandOutput {
                plain: format!(
                    "removed reaction from {message_id} published={}",
                    summary.published
                ),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex),
                    "group_id": hex::encode(group_id.as_slice()),
                    "target_message_id": message_id,
                    "published": summary.published,
                    "message_ids": summary.message_ids,
                }),
            })
        }
        MessageCommand::List {
            group_id,
            group,
            before,
            before_message_id,
            after,
            after_message_id,
            limit,
        } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group = group.or(group_id);
            let uses_cursor = before.is_some()
                || before_message_id.is_some()
                || after.is_some()
                || after_message_id.is_some();
            let mut messages = app.messages_with_query(
                &account.label,
                AppMessageQuery {
                    group_id_hex: group
                        .map(|group| normalize_group_id_hex(&group))
                        .transpose()?,
                    limit: if uses_cursor { None } else { limit },
                },
            )?;
            if uses_cursor {
                messages = apply_message_cursors(
                    messages,
                    before,
                    before_message_id.as_deref(),
                    after,
                    after_message_id.as_deref(),
                    limit,
                );
            }
            Ok(CommandOutput {
                plain: message_list_plain(&messages),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex),
                    "messages": message_list_json_with_profiles(app, messages),
                }),
            })
        }
        MessageCommand::Search {
            group_id,
            query,
            limit,
        } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let messages = search_messages(app, &account.label, Some(group_id), &query, limit)?;
            Ok(CommandOutput {
                plain: message_list_plain(&messages),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex),
                    "query": query,
                    "messages": message_list_json_with_profiles(app, messages),
                }),
            })
        }
        MessageCommand::SearchAll { query, limit } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let messages = search_messages(app, &account.label, None, &query, limit)?;
            Ok(CommandOutput {
                plain: message_list_plain(&messages),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex),
                    "query": query,
                    "messages": message_list_json_with_profiles(app, messages),
                }),
            })
        }
        MessageCommand::Subscribe { .. } => Err(DmError::MessagesSubscribeRequiresDaemon),
    }
}

fn search_messages(
    app: &MarmotApp,
    label: &str,
    group_id: Option<String>,
    query: &str,
    limit: Option<usize>,
) -> Result<Vec<AppMessageRecord>, DmError> {
    let group_id_hex = group_id
        .map(|group| normalize_group_id_hex(&group))
        .transpose()?;
    let mut matches = app
        .messages_with_query(
            label,
            AppMessageQuery {
                group_id_hex,
                limit: None,
            },
        )?
        .into_iter()
        .filter(|message| message.plaintext.contains(query))
        .collect::<Vec<_>>();
    if let Some(limit) = limit {
        matches.truncate(limit);
    }
    Ok(matches)
}

async fn follows_command(
    account_home: &AccountHome,
    app: &MarmotApp,
    command: FollowsCommand,
    account_flag: Option<String>,
    relay: Option<String>,
) -> Result<CommandOutput, DmError> {
    let runtime = app.runtime();
    follows_command_with_runtime(account_home, app, &runtime, command, account_flag, relay).await
}

pub(crate) async fn follows_command_with_runtime(
    account_home: &AccountHome,
    app: &MarmotApp,
    runtime: &MarmotAppRuntime,
    command: FollowsCommand,
    account_flag: Option<String>,
    relay: Option<String>,
) -> Result<CommandOutput, DmError> {
    let account = resolve_account(account_home, account_flag)?;
    ensure_local_signing(&account)?;
    match command {
        FollowsCommand::List => {
            let follows = app
                .directory_entry_for_account_id(&account.account_id_hex)?
                .map(|entry| entry.follows)
                .unwrap_or_default();
            follows_output(account.account_id_hex, follows)
        }
        FollowsCommand::Check { pubkey } => {
            let target = parse_public_key(&pubkey)?;
            let follows = app
                .directory_entry_for_account_id(&account.account_id_hex)?
                .map(|entry| entry.follows)
                .unwrap_or_default();
            let follows_target = follows.iter().any(|follow| follow == &target);
            Ok(CommandOutput {
                plain: format!("follows {}: {follows_target}", npub_for_account_id(&target)),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex),
                    "pubkey": target,
                    "user": npub_for_account_id(&target),
                    "follows": follows_target,
                }),
            })
        }
        FollowsCommand::Add { pubkey } => {
            update_follows_command(app, runtime, account, relay, pubkey, true).await
        }
        FollowsCommand::Remove { pubkey } => {
            update_follows_command(app, runtime, account, relay, pubkey, false).await
        }
    }
}

async fn update_follows_command(
    app: &MarmotApp,
    runtime: &MarmotAppRuntime,
    account: marmot_account::AccountSummary,
    relay: Option<String>,
    pubkey: String,
    add: bool,
) -> Result<CommandOutput, DmError> {
    let target = parse_public_key(&pubkey)?;
    let relay = relay.ok_or(DmError::MissingRelay)?;
    let endpoint = TransportEndpoint(validate_relay_url(&relay)?);
    let mut follows = app
        .directory_entry_for_account_id(&account.account_id_hex)?
        .map(|entry| entry.follows)
        .unwrap_or_default();
    if add {
        if !follows.contains(&target) {
            follows.push(target);
        }
    } else {
        follows.retain(|follow| follow != &target);
    }
    follows.sort();
    follows.dedup();
    runtime
        .publish_account_follow_list(
            &account.label,
            &follows,
            AccountRelayListBootstrap::new(vec![endpoint.clone()], vec![endpoint.clone()]),
        )
        .await?;
    let _ = runtime
        .refresh_user_directory_for_account_id(&account.account_id_hex, vec![endpoint])
        .await;
    follows_output(account.account_id_hex, follows)
}

fn follows_output(account_id: String, follows: Vec<String>) -> Result<CommandOutput, DmError> {
    let follows_json = follows
        .iter()
        .map(|follow| {
            json!({
                "account_id": follow,
                "npub": npub_for_account_id(follow),
            })
        })
        .collect::<Vec<_>>();
    Ok(CommandOutput {
        plain: if follows_json.is_empty() {
            "no follows".to_owned()
        } else {
            follows_json
                .iter()
                .filter_map(|follow| follow.get("npub").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("\n")
        },
        json: json!({
            "account_id": account_id,
            "npub": npub_for_account_id(&account_id),
            "follows": follows_json,
        }),
    })
}

async fn profile_command(
    account_home: &AccountHome,
    app: &MarmotApp,
    command: ProfileCommand,
    account_flag: Option<String>,
    relay: Option<String>,
) -> Result<CommandOutput, DmError> {
    let runtime = app.runtime();
    profile_command_with_runtime(account_home, app, &runtime, command, account_flag, relay).await
}

pub(crate) async fn profile_command_with_runtime(
    account_home: &AccountHome,
    app: &MarmotApp,
    runtime: &MarmotAppRuntime,
    command: ProfileCommand,
    account_flag: Option<String>,
    relay: Option<String>,
) -> Result<CommandOutput, DmError> {
    let account = resolve_account(account_home, account_flag)?;
    ensure_local_signing(&account)?;
    match command {
        ProfileCommand::Show => {
            let entry = app.directory_entry_for_account_id(&account.account_id_hex)?;
            Ok(CommandOutput {
                plain: serde_json::to_string_pretty(&entry)
                    .expect("JSON response serialization cannot fail"),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex),
                    "profile": entry.and_then(|entry| entry.profile),
                }),
            })
        }
        ProfileCommand::Update {
            name,
            display_name,
            about,
            picture,
            nip05,
            lud16,
        } => {
            let relay = relay.ok_or(DmError::MissingRelay)?;
            let endpoint = TransportEndpoint(validate_relay_url(&relay)?);
            let profile = UserProfileMetadata {
                name,
                display_name,
                about,
                picture,
                nip05,
                lud16,
                created_at: unix_now_seconds(),
                source_relays: Vec::new(),
            };
            runtime
                .publish_user_profile(
                    &account.label,
                    profile.clone(),
                    AccountRelayListBootstrap::new(vec![endpoint.clone()], vec![endpoint]),
                )
                .await?;
            Ok(CommandOutput {
                plain: format!(
                    "updated profile {}",
                    npub_for_account_id(&account.account_id_hex)
                ),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex),
                    "profile": profile,
                }),
            })
        }
    }
}

async fn relays_command(
    account_home: &AccountHome,
    app: &MarmotApp,
    command: RelaysCommand,
    account_flag: Option<String>,
    relay: Option<String>,
) -> Result<CommandOutput, DmError> {
    let runtime = app.runtime();
    relays_command_with_runtime(account_home, app, &runtime, command, account_flag, relay).await
}

pub(crate) async fn relays_command_with_runtime(
    account_home: &AccountHome,
    app: &MarmotApp,
    runtime: &MarmotAppRuntime,
    command: RelaysCommand,
    account_flag: Option<String>,
    relay: Option<String>,
) -> Result<CommandOutput, DmError> {
    let account = resolve_account(account_home, account_flag)?;
    ensure_local_signing(&account)?;
    match command {
        RelaysCommand::List { relay_type } => {
            let status = app.account_relay_list_status(&account.label)?;
            let relays = relays_for_type(&status, relay_type.as_deref())?;
            Ok(CommandOutput {
                plain: if relays.is_empty() {
                    "no relays".to_owned()
                } else {
                    relays.join("\n")
                },
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex),
                    "relay_type": relay_type,
                    "relays": relays,
                    "relay_lists": relay_lists_json(status),
                }),
            })
        }
        RelaysCommand::Add { url, relay_type } => {
            update_relay_list(app, runtime, account, relay, relay_type, url, true).await
        }
        RelaysCommand::Remove { url, relay_type } => {
            update_relay_list(app, runtime, account, relay, relay_type, url, false).await
        }
    }
}

async fn update_relay_list(
    app: &MarmotApp,
    runtime: &MarmotAppRuntime,
    account: marmot_account::AccountSummary,
    relay: Option<String>,
    relay_type: String,
    url: String,
    add: bool,
) -> Result<CommandOutput, DmError> {
    let relay_type = normalize_relay_type(&relay_type)?;
    let url = validate_relay_url(&url)?;
    let status = app.account_relay_list_status(&account.label)?;
    let mut relays = relays_for_type(&status, Some(&relay_type))?;
    if add {
        if !relays.contains(&url) {
            relays.push(url.clone());
        }
    } else {
        relays.retain(|relay| relay != &url);
    }
    relays.sort();
    relays.dedup();
    let publish_relays = relay_endpoints(relays.clone())?;
    let bootstrap = relay
        .map(validate_relay_url)
        .transpose()?
        .or_else(|| relays.first().cloned())
        .ok_or(DmError::MissingRelay)?;
    let bootstrap_relays = vec![TransportEndpoint(bootstrap)];
    let status = runtime
        .publish_account_relay_list_kind(
            &account.label,
            &relay_type,
            publish_relays,
            bootstrap_relays,
        )
        .await?;
    Ok(CommandOutput {
        plain: relays.join("\n"),
        json: json!({
            "account_id": account.account_id_hex,
            "npub": npub_for_account_id(&account.account_id_hex),
            "relay_type": relay_type,
            "relays": relays,
            "relay_lists": relay_lists_json(status),
        }),
    })
}

fn relays_for_type(
    status: &AccountRelayListStatus,
    relay_type: Option<&str>,
) -> Result<Vec<String>, DmError> {
    match relay_type.map(normalize_relay_type).transpose()?.as_deref() {
        Some("nip65") => Ok(status.nip65.relays.clone()),
        Some("inbox") => Ok(status.inbox.relays.clone()),
        Some("key_package") => Ok(status.key_package.relays.clone()),
        None => {
            let mut relays = status.default_relays.clone();
            relays.extend(status.inbox.relays.clone());
            relays.extend(status.key_package.relays.clone());
            relays.sort();
            relays.dedup();
            Ok(relays)
        }
        Some(_) => unreachable!("normalize_relay_type constrains values"),
    }
}

fn normalize_relay_type(value: &str) -> Result<String, DmError> {
    match value {
        "nip65" => Ok("nip65".to_owned()),
        "inbox" => Ok("inbox".to_owned()),
        "key_package" | "key-package" => Ok("key_package".to_owned()),
        _ => unsupported_command("relays", "relay type must be nip65, inbox, or key_package"),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CliSettings {
    theme: String,
    language: String,
}

impl Default for CliSettings {
    fn default() -> Self {
        Self {
            theme: "system".to_owned(),
            language: "system".to_owned(),
        }
    }
}

fn settings_command(home: &Path, command: SettingsCommand) -> Result<CommandOutput, DmError> {
    let mut settings = read_settings(home)?;
    match command {
        SettingsCommand::Show => {}
        SettingsCommand::Theme { mode } => {
            settings.theme = mode;
            write_settings(home, &settings)?;
        }
        SettingsCommand::Language { lang } => {
            settings.language = lang;
            write_settings(home, &settings)?;
        }
    }
    Ok(CommandOutput {
        plain: format!("theme={} language={}", settings.theme, settings.language),
        json: json!({
            "theme": settings.theme,
            "language": settings.language,
        }),
    })
}

fn settings_path(home: &Path) -> PathBuf {
    home.join("dev").join("settings.json")
}

fn read_settings(home: &Path) -> Result<CliSettings, DmError> {
    let path = settings_path(home);
    if !path.exists() {
        return Ok(CliSettings::default());
    }
    let bytes = std::fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn write_settings(home: &Path, settings: &CliSettings) -> Result<(), DmError> {
    let path = settings_path(home);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(settings)?;
    std::fs::write(path, bytes)?;
    Ok(())
}

fn users_command(
    account_home: &AccountHome,
    app: &MarmotApp,
    command: UsersCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, DmError> {
    match command {
        UsersCommand::Show { pubkey } => {
            let account_id = parse_public_key(&pubkey)?;
            let entry = app
                .directory_entry_for_account_id(&account_id)?
                .ok_or_else(|| AppError::MissingDirectoryEntry(account_id.clone()))?;
            Ok(CommandOutput {
                plain: serde_json::to_string_pretty(&entry)
                    .expect("JSON response serialization cannot fail"),
                json: json!({ "user": entry }),
            })
        }
        UsersCommand::Search { query, radius } => {
            let account = resolve_account(account_home, account_flag)?;
            let results = app.search_user_directory(UserDirectorySearch {
                searcher_account_id_hex: account.account_id_hex.clone(),
                query: query.clone(),
                radius_start: radius.0,
                radius_end: radius.1,
                limit: None,
            })?;
            Ok(CommandOutput {
                plain: if results.is_empty() {
                    "no users".to_owned()
                } else {
                    results
                        .iter()
                        .map(|result| result.npub.clone())
                        .collect::<Vec<_>>()
                        .join("\n")
                },
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex),
                    "query": query,
                    "users": results,
                }),
            })
        }
    }
}

fn notifications_command(command: NotificationsCommand) -> Result<CommandOutput, DmError> {
    match command {
        NotificationsCommand::Subscribe => unsupported_command(
            "notifications subscribe",
            "notification derivation and delivery are not exposed by the daemon yet",
        ),
    }
}

fn reset_command(home: &Path, confirm: bool) -> Result<CommandOutput, DmError> {
    if !confirm {
        return unsupported_command(
            "reset",
            "pass --confirm to delete all local Darkmatter data",
        );
    }
    match std::fs::remove_dir_all(home) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }
    Ok(CommandOutput {
        plain: format!("deleted {}", home.display()),
        json: json!({
            "deleted": true,
            "home": home,
        }),
    })
}

fn parse_radius(s: &str) -> Result<(u8, u8), String> {
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

async fn stream_command_local(command: StreamCommand) -> Result<CommandOutput, DmError> {
    match command {
        StreamCommand::Receive {
            bind,
            start_event_id,
        } => {
            let (start_event_id, anchored) = stream_start_event_id(start_event_id)?;
            let receiver = QuicTextStreamReceiver::bind(bind)?;
            let local_addr = receiver.local_addr()?;
            let server_cert_der_hex = hex::encode(receiver.server_cert_der());
            let received = receiver.receive_once(start_event_id).await?;
            let stream_id = hex::encode(&received.stream_id);
            Ok(CommandOutput {
                plain: format!(
                    "received stream {stream_id} chunks={}\n{}",
                    received.chunk_count, received.text
                ),
                json: json!({
                    "local_addr": local_addr.to_string(),
                    "server_cert_der_hex": server_cert_der_hex,
                    "stream_id": stream_id,
                    "anchored": anchored,
                    "chunks": received.chunks.into_iter().map(|chunk| {
                        json!({
                            "seq": chunk.seq,
                            "record_type": chunk.record_type,
                            "flags": chunk.flags,
                            "text": chunk.text,
                        })
                    }).collect::<Vec<_>>(),
                    "text": received.text,
                    "transcript_hash": hex::encode(received.transcript_hash),
                    "chunk_count": received.chunk_count,
                }),
            })
        }
        StreamCommand::Send {
            broker,
            connect,
            server_name,
            server_cert_der_hex,
            insecure_local,
            stream_id,
            start_event_id,
            chunk_bytes,
            chunk_delay_ms,
            text,
        } => {
            if text.is_empty() {
                return Err(DmError::EmptyStreamText);
            }
            let text = text.join(" ");
            let stream_id = stream_id
                .map(hex::decode)
                .transpose()?
                .unwrap_or_else(transport_quic_stream::random_stream_id);
            let (start_event_id, anchored) = stream_start_event_id(start_event_id)?;
            if broker {
                let trust = broker_trust(connect, server_cert_der_hex, insecure_local)?;
                let sent = publish_text_to_broker(PublishTextToBroker {
                    broker_addr: connect,
                    server_name: server_name.clone(),
                    trust: trust.clone(),
                    stream_id: stream_id.clone(),
                    start_event_id,
                    text: text.clone(),
                    max_chunk_bytes: chunk_bytes,
                    chunk_delay: Duration::from_millis(chunk_delay_ms),
                })
                .await?;
                return Ok(CommandOutput {
                    plain: format!(
                        "sent brokered stream {} chunks={}",
                        hex::encode(&stream_id),
                        sent.chunk_count
                    ),
                    json: json!({
                        "brokered": true,
                        "connect": connect.to_string(),
                        "server_name": server_name,
                        "trust": broker_trust_name(&trust),
                        "stream_id": hex::encode(sent.stream_id),
                        "anchored": anchored,
                        "text_bytes": text.len(),
                        "transcript_hash": hex::encode(sent.transcript_hash),
                        "chunk_count": sent.chunk_count,
                    }),
                });
            }
            let trust = stream_trust(connect, server_cert_der_hex, insecure_local)?;
            let sent = send_text_stream(SendTextStream {
                server_addr: connect,
                server_name: server_name.clone(),
                trust: trust.clone(),
                stream_id: stream_id.clone(),
                start_event_id,
                text: text.clone(),
                max_chunk_bytes: chunk_bytes,
                chunk_delay: Duration::from_millis(chunk_delay_ms),
            })
            .await?;
            Ok(CommandOutput {
                plain: format!(
                    "sent stream {} chunks={}",
                    hex::encode(&stream_id),
                    sent.chunk_count
                ),
                json: json!({
                    "brokered": false,
                    "connect": connect.to_string(),
                    "server_name": server_name,
                    "trust": stream_trust_name(&trust),
                    "stream_id": hex::encode(sent.stream_id),
                    "anchored": anchored,
                    "text_bytes": text.len(),
                    "transcript_hash": hex::encode(sent.transcript_hash),
                    "chunk_count": sent.chunk_count,
                }),
            })
        }
        StreamCommand::Start { .. }
        | StreamCommand::Watch { .. }
        | StreamCommand::ComposeOpen { .. }
        | StreamCommand::ComposeAppend { .. }
        | StreamCommand::ComposeFinish { .. }
        | StreamCommand::ComposeCancel { .. }
        | StreamCommand::Finish { .. }
        | StreamCommand::Verify { .. } => {
            unreachable!("durable stream commands require app setup")
        }
    }
}

async fn stream_command_app(
    account_home: &AccountHome,
    app: &MarmotApp,
    command: StreamCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, DmError> {
    let runtime = app.runtime();
    stream_command_app_with_runtime(account_home, app, &runtime, command, account_flag).await
}

pub(crate) async fn stream_command_app_with_runtime(
    account_home: &AccountHome,
    app: &MarmotApp,
    runtime: &MarmotAppRuntime,
    command: StreamCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, DmError> {
    match command {
        StreamCommand::Start {
            group,
            stream_id,
            quic_candidates,
        } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id = GroupId::new(hex::decode(group)?);
            let stream_id = stream_id
                .map(hex::decode)
                .transpose()?
                .unwrap_or_else(transport_quic_stream::random_stream_id);
            let (payload, summary) = runtime
                .start_agent_text_stream(
                    &account.label,
                    &group_id,
                    &stream_id,
                    unix_now_seconds(),
                    quic_candidates,
                )
                .await?;
            let agent_text_stream = agent_text_stream_payload_value(&payload);
            Ok(CommandOutput {
                plain: format!(
                    "started stream {} published={}",
                    hex::encode(&stream_id),
                    summary.published
                ),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex),
                    "group_id": hex::encode(group_id.as_slice()),
                    "stream_id": hex::encode(stream_id),
                    "published": summary.published,
                    "message_ids": summary.message_ids,
                    "agent_text_stream": agent_text_stream,
                }),
            })
        }
        StreamCommand::Watch {
            group,
            stream_id,
            server_cert_der_hex,
            insecure_local,
            background,
        } => {
            stream_watch_command_app(
                account_home,
                app,
                StreamCommand::Watch {
                    group,
                    stream_id,
                    server_cert_der_hex,
                    insecure_local,
                    background,
                },
                account_flag,
                |_| {},
            )
            .await
        }
        StreamCommand::ComposeOpen { .. }
        | StreamCommand::ComposeAppend { .. }
        | StreamCommand::ComposeFinish { .. }
        | StreamCommand::ComposeCancel { .. } => unsupported_command(
            "stream compose",
            "stream compose sessions require the daemon",
        ),
        StreamCommand::Finish {
            group,
            stream_id,
            transcript_hash,
            chunk_count,
            text,
        } => {
            if text.is_empty() {
                return Err(DmError::EmptyStreamText);
            }
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id = GroupId::new(hex::decode(group)?);
            let stream_id = hex::decode(stream_id)?;
            let transcript_hash = transcript_hash_from_hex(&transcript_hash)?;
            let (payload, summary) = runtime
                .finish_agent_text_stream(
                    &account.label,
                    &group_id,
                    AgentTextStreamFinishRequest {
                        stream_id: stream_id.clone(),
                        final_text_or_reference: text.join(" "),
                        transcript_hash,
                        chunk_count,
                        finished_at: unix_now_seconds(),
                    },
                )
                .await?;
            let agent_text_stream = agent_text_stream_payload_value(&payload);
            Ok(CommandOutput {
                plain: format!(
                    "finished stream {} published={}",
                    hex::encode(&stream_id),
                    summary.published
                ),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex),
                    "group_id": hex::encode(group_id.as_slice()),
                    "stream_id": hex::encode(stream_id),
                    "published": summary.published,
                    "message_ids": summary.message_ids,
                    "agent_text_stream": agent_text_stream,
                }),
            })
        }
        StreamCommand::Verify {
            group,
            stream_id,
            transcript_hash,
            chunk_count,
        } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id_hex = normalize_group_id_hex(&group)?;
            let stream_id_hex = normalize_hex(&stream_id)?;
            let transcript_hash_hex = hex::encode(transcript_hash_from_hex(&transcript_hash)?);
            let messages = app.messages_with_query(
                &account.label,
                AppMessageQuery {
                    group_id_hex: Some(group_id_hex.clone()),
                    limit: None,
                },
            )?;
            let final_message = messages.into_iter().rev().find_map(|message| {
                let payload = agent_text_stream_payload(&message.plaintext)?;
                match payload.payload {
                    AgentTextStreamAppPayloadV1::Final(final_payload)
                        if final_payload.stream_id == stream_id_hex =>
                    {
                        Some((message, final_payload))
                    }
                    _ => None,
                }
            });
            let (verified, final_message_json) = match final_message {
                Some((message, final_payload)) => {
                    let transcript_hash_matches =
                        final_payload.transcript_hash == transcript_hash_hex;
                    let chunk_count_matches =
                        chunk_count.is_none_or(|count| count == final_payload.chunk_count);
                    (
                        transcript_hash_matches && chunk_count_matches,
                        json!({
                            "message_id": message.message_id_hex,
                            "stream_id": final_payload.stream_id,
                            "transcript_hash": final_payload.transcript_hash,
                            "chunk_count": final_payload.chunk_count,
                            "final_text_or_reference": final_payload.final_text_or_reference,
                            "finished_at": final_payload.finished_at,
                            "checks": {
                                "transcript_hash": transcript_hash_matches,
                                "chunk_count": chunk_count_matches,
                            },
                        }),
                    )
                }
                None => (false, Value::Null),
            };
            Ok(CommandOutput {
                plain: format!("stream {stream_id_hex} verified={verified}"),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex),
                    "group_id": group_id_hex,
                    "stream_id": stream_id_hex,
                    "verified": verified,
                    "expected": {
                        "transcript_hash": transcript_hash_hex,
                        "chunk_count": chunk_count,
                    },
                    "final_message": final_message_json,
                }),
            })
        }
        StreamCommand::Receive { .. } | StreamCommand::Send { .. } => {
            unreachable!("local QUIC stream commands return before app setup")
        }
    }
}

async fn stream_watch_command_app<F>(
    account_home: &AccountHome,
    app: &MarmotApp,
    command: StreamCommand,
    account_flag: Option<String>,
    mut on_delta: F,
) -> Result<CommandOutput, DmError>
where
    F: FnMut(AgentStreamDelta) + Send,
{
    let StreamCommand::Watch {
        group,
        stream_id,
        server_cert_der_hex,
        insecure_local,
        background: _,
    } = command
    else {
        unreachable!("stream watch helper only accepts stream watch commands");
    };
    let account = resolve_account(account_home, account_flag.clone())?;
    ensure_local_signing(&account)?;
    app.status(&account.label)?;
    let group_id_hex = normalize_group_id_hex(&group)?;
    let expected_stream_id_hex = stream_id.map(|value| normalize_hex(&value)).transpose()?;
    let messages = app.messages_with_query(
        &account.label,
        AppMessageQuery {
            group_id_hex: Some(group_id_hex.clone()),
            limit: None,
        },
    )?;
    let (start_message_id_hex, start_payload) =
        latest_stream_start(messages, expected_stream_id_hex.as_deref())?;
    if start_payload.route != AgentTextStreamRouteV1::BrokeredQuic {
        return Err(DmError::UnsupportedStreamRoute(
            route_name(&start_payload.route).to_owned(),
        ));
    }
    let candidate = start_payload
        .quic_candidates
        .iter()
        .find(|candidate| candidate.trim().starts_with("quic://"))
        .ok_or(DmError::MissingQuicCandidate)?;
    let candidate = parse_quic_candidate(candidate)?;
    let trust = broker_trust(candidate.addr, server_cert_der_hex, insecure_local)?;
    let stream_id = hex::decode(&start_payload.stream_id)?;
    let stream_id_hex = start_payload.stream_id.clone();
    let start_event_id = MessageId::new(hex::decode(&start_message_id_hex)?);
    let delta_account = account_flag.or(Some(account.account_id_hex.clone()));
    let delta_group_id = group_id_hex.clone();
    let delta_stream_id = stream_id_hex.clone();
    let received = subscribe_text_from_broker_with_updates(
        SubscribeTextFromBroker {
            broker_addr: candidate.addr,
            server_name: candidate.server_name.clone(),
            trust: trust.clone(),
            stream_id,
            start_event_id,
        },
        |chunk| {
            on_delta(AgentStreamDelta {
                account: delta_account.clone(),
                group_id: delta_group_id.clone(),
                stream_id: delta_stream_id.clone(),
                seq: chunk.seq,
                record_type: chunk.record_type,
                flags: chunk.flags,
                text: chunk.text.clone(),
            });
        },
    )
    .await?;
    Ok(CommandOutput {
        plain: format!(
            "received brokered stream {} chunks={}\n{}",
            hex::encode(&received.stream_id),
            received.chunk_count,
            received.text
        ),
        json: json!({
            "brokered": true,
            "candidate": candidate.original,
            "connect": candidate.addr.to_string(),
            "server_name": candidate.server_name,
            "trust": broker_trust_name(&trust),
            "stream_id": hex::encode(&received.stream_id),
            "start_message_id": start_message_id_hex,
            "chunks": received.chunks.into_iter().map(|chunk| {
                json!({
                    "seq": chunk.seq,
                    "record_type": chunk.record_type,
                    "flags": chunk.flags,
                    "text": chunk.text,
                })
            }).collect::<Vec<_>>(),
            "text": received.text,
            "transcript_hash": hex::encode(received.transcript_hash),
            "chunk_count": received.chunk_count,
        }),
    })
}

fn stream_start_event_id(start_event_id: Option<String>) -> Result<(MessageId, bool), DmError> {
    match start_event_id {
        Some(value) => Ok((MessageId::new(hex::decode(value)?), true)),
        None => Ok((MessageId::new(vec![0; 32]), false)),
    }
}

fn latest_stream_start(
    messages: Vec<AppMessageRecord>,
    stream_id_hex: Option<&str>,
) -> Result<(String, AgentTextStreamStartPayloadV1), DmError> {
    messages
        .into_iter()
        .rev()
        .find_map(|message| {
            let payload = agent_text_stream_payload(&message.plaintext)?;
            match payload.payload {
                AgentTextStreamAppPayloadV1::Start(start)
                    if stream_id_hex.is_none_or(|stream_id| stream_id == start.stream_id) =>
                {
                    Some((message.message_id_hex, start))
                }
                _ => None,
            }
        })
        .ok_or(DmError::MissingStreamStart)
}

struct ParsedQuicCandidate {
    original: String,
    addr: SocketAddr,
    server_name: String,
}

fn parse_quic_candidate(candidate: &str) -> Result<ParsedQuicCandidate, DmError> {
    let trimmed = candidate.trim();
    let Some(rest) = trimmed.strip_prefix("quic://") else {
        return Err(DmError::InvalidQuicCandidate(trimmed.to_owned()));
    };
    let authority = rest.split('/').next().unwrap_or(rest);
    if authority.is_empty() {
        return Err(DmError::InvalidQuicCandidate(trimmed.to_owned()));
    }
    let server_name = candidate_server_name(authority)?;
    let mut addrs =
        authority
            .to_socket_addrs()
            .map_err(|source| DmError::QuicCandidateResolve {
                candidate: trimmed.to_owned(),
                source,
            })?;
    let addr = addrs
        .next()
        .ok_or_else(|| DmError::InvalidQuicCandidate(trimmed.to_owned()))?;
    Ok(ParsedQuicCandidate {
        original: trimmed.to_owned(),
        addr,
        server_name,
    })
}

fn candidate_server_name(authority: &str) -> Result<String, DmError> {
    if let Some(rest) = authority.strip_prefix('[') {
        let Some((host, _)) = rest.split_once(']') else {
            return Err(DmError::InvalidQuicCandidate(authority.to_owned()));
        };
        return Ok(host.to_owned());
    }
    authority
        .rsplit_once(':')
        .map(|(host, _)| host.to_owned())
        .filter(|host| !host.is_empty())
        .ok_or_else(|| DmError::InvalidQuicCandidate(authority.to_owned()))
}

fn transcript_hash_from_hex(value: &str) -> Result<[u8; 32], DmError> {
    let bytes = hex::decode(value)?;
    let actual = bytes.len();
    bytes
        .try_into()
        .map_err(|_| DmError::InvalidTranscriptHashLength(actual))
}

fn normalize_hex(value: &str) -> Result<String, DmError> {
    Ok(hex::encode(hex::decode(value)?))
}

fn unix_now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn agent_text_stream_payload(plaintext: &str) -> Option<AgentTextStreamAppPayloadEnvelopeV1> {
    AgentTextStreamAppPayloadEnvelopeV1::decode(plaintext.as_bytes())
        .ok()
        .flatten()
}

fn agent_text_stream_payload_json(plaintext: &str) -> Option<Value> {
    agent_text_stream_payload(plaintext).map(|payload| agent_text_stream_payload_value(&payload))
}

fn agent_text_stream_payload_value(payload: &AgentTextStreamAppPayloadEnvelopeV1) -> Value {
    match &payload.payload {
        AgentTextStreamAppPayloadV1::Start(start) => json!({
            "kind": "start",
            "stream_id": start.stream_id.clone(),
            "created_at": start.created_at,
            "route": route_name(&start.route),
            "quic_candidates": start.quic_candidates.clone(),
        }),
        AgentTextStreamAppPayloadV1::Final(final_payload) => json!({
            "kind": "final",
            "stream_id": final_payload.stream_id.clone(),
            "final_text_or_reference": final_payload.final_text_or_reference.clone(),
            "transcript_hash": final_payload.transcript_hash.clone(),
            "chunk_count": final_payload.chunk_count,
            "finished_at": final_payload.finished_at,
        }),
    }
}

fn route_name(route: &AgentTextStreamRouteV1) -> &'static str {
    match route {
        AgentTextStreamRouteV1::DirectQuic => "direct_quic",
        AgentTextStreamRouteV1::BrokeredQuic => "brokered_quic",
    }
}

fn broker_trust(
    server_addr: SocketAddr,
    server_cert_der_hex: Option<String>,
    insecure_local: bool,
) -> Result<BrokerServerTrust, DmError> {
    if insecure_local && server_cert_der_hex.is_some() {
        return Err(DmError::ConflictingStreamTrust);
    }
    if insecure_local {
        ensure_insecure_local_endpoint(server_addr)?;
        return Ok(BrokerServerTrust::InsecureLocal);
    }
    server_cert_der_hex
        .map(|value| hex::decode(value).map(BrokerServerTrust::CertificateDer))
        .transpose()
        .map(|trust| trust.unwrap_or(BrokerServerTrust::Platform))
        .map_err(Into::into)
}

fn broker_trust_name(trust: &BrokerServerTrust) -> &'static str {
    match trust {
        BrokerServerTrust::Platform => "platform",
        BrokerServerTrust::CertificateDer(_) => "certificate_der",
        BrokerServerTrust::InsecureLocal => "insecure_local",
    }
}

fn stream_trust(
    server_addr: SocketAddr,
    server_cert_der_hex: Option<String>,
    insecure_local: bool,
) -> Result<ServerTrust, DmError> {
    if insecure_local && server_cert_der_hex.is_some() {
        return Err(DmError::ConflictingStreamTrust);
    }
    if insecure_local {
        ensure_insecure_local_endpoint(server_addr)?;
        return Ok(ServerTrust::InsecureLocal);
    }
    server_cert_der_hex
        .map(|value| hex::decode(value).map(ServerTrust::CertificateDer))
        .transpose()
        .map(|trust| trust.unwrap_or(ServerTrust::Platform))
        .map_err(Into::into)
}

fn ensure_insecure_local_endpoint(server_addr: SocketAddr) -> Result<(), DmError> {
    if server_addr.ip().is_loopback() {
        return Ok(());
    }
    Err(DmError::InsecureLocalRequiresLoopback(server_addr))
}

fn stream_trust_name(trust: &ServerTrust) -> &'static str {
    match trust {
        ServerTrust::Platform => "platform",
        ServerTrust::CertificateDer(_) => "certificate_der",
        ServerTrust::InsecureLocal => "insecure_local",
    }
}

async fn sync_command(
    app: &MarmotApp,
    account: marmot_account::AccountSummary,
) -> Result<CommandOutput, DmError> {
    app.status(&account.label)?;
    let mut client = app.client(&account.label).await?;
    let summary = client.sync().await?;
    Ok(CommandOutput {
        plain: sync_plain(&summary),
        json: sync_json(app, account, summary),
    })
}

fn sync_plain(summary: &SyncSummary) -> String {
    let mut lines = Vec::new();
    for group_id in &summary.joined_groups {
        lines.push(format!("joined group {}", hex::encode(group_id.as_slice())));
    }
    for message in &summary.messages {
        lines.push(format!(
            "received group={} from={}: {}",
            hex::encode(message.group_id.as_slice()),
            message.sender,
            message.plaintext
        ));
    }
    if lines.is_empty() {
        if summary.events.is_empty() {
            "no new events".to_owned()
        } else {
            format!("processed {} event(s)", summary.events.len())
        }
    } else {
        lines.join("\n")
    }
}

fn sync_json(
    app: &MarmotApp,
    account: marmot_account::AccountSummary,
    summary: SyncSummary,
) -> Value {
    json!({
        "account_id": account.account_id_hex,
        "npub": npub_for_account_id(&account.account_id_hex),
        "joined_groups": summary.joined_groups.into_iter().map(|group_id| {
            hex::encode(group_id.as_slice())
        }).collect::<Vec<_>>(),
        "messages": summary.messages.into_iter().map(|message| {
            let agent_text_stream = agent_text_stream_payload_json(&message.plaintext);
            let from_display_name = message
                .sender_display_name
                .clone()
                .or_else(|| display_name_for_sender(app, &message.sender));
            let app_message = message.app_message;
            let mut value = json!({
                "message_id": message.message_id_hex,
                "direction": "received",
                "from": message.sender,
                "from_display_name": from_display_name,
                "group_id": hex::encode(message.group_id.as_slice()),
                "plaintext": message.plaintext,
            });
            if let Some(agent_text_stream) = agent_text_stream {
                value["agent_text_stream"] = agent_text_stream;
            }
            if let Some(app_message) = app_message {
                value["app_message"] = json!(app_message);
            }
            value
        }).collect::<Vec<_>>(),
        "events": summary.events.len(),
    })
}

fn account_summary_json(app: &MarmotApp, account: marmot_account::AccountSummary) -> Value {
    let profile = app
        .directory_entry_for_account_id(&account.account_id_hex)
        .ok()
        .flatten()
        .and_then(|entry| entry.profile);
    let display_name = profile_display_name(profile.as_ref());
    json!({
        "account_id": account.account_id_hex,
        "npub": npub_for_account_id(&account.account_id_hex),
        "display_name": display_name,
        "profile": profile,
        "local_signing": account.local_signing,
    })
}

fn account_display_name_or_npub(account: &Value) -> &str {
    account
        .get("display_name")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .or_else(|| account.get("npub").and_then(Value::as_str))
        .unwrap_or("")
}

fn profile_display_name(profile: Option<&UserProfileMetadata>) -> Option<String> {
    let profile = profile?;
    profile
        .display_name
        .as_deref()
        .or(profile.name.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn group_list_plain(groups: &[AppGroupRecord]) -> String {
    if groups.is_empty() {
        return "no groups".to_owned();
    }
    groups
        .iter()
        .map(group_plain)
        .collect::<Vec<_>>()
        .join("\n")
}

fn group_plain(group: &AppGroupRecord) -> String {
    format!(
        "{} name={} endpoint={}",
        group.group_id_hex, group.profile.name, group.endpoint
    )
}

fn group_json(group: AppGroupRecord) -> Value {
    json!({
        "group_id": group.group_id_hex,
        "endpoint": group.endpoint,
        "profile": group.profile,
        "image": group.image,
        "admin_policy": group.admin_policy,
        "nostr_routing": group.nostr_routing,
        "agent_text_stream": group.agent_text_stream,
        "archived": group.archived,
    })
}

fn group_mls_state_json(state: AppGroupMlsState) -> Value {
    json!({
        "group_id": state.group_id_hex,
        "epoch": state.epoch,
        "member_count": state.member_count,
        "required_app_components": state.required_app_components,
    })
}

fn group_members_plain(members: &[AppGroupMemberRecord]) -> String {
    if members.is_empty() {
        return "no members".to_owned();
    }
    members
        .iter()
        .map(|member| npub_for_account_id(&member.member_id_hex))
        .collect::<Vec<_>>()
        .join("\n")
}

fn group_members_json(members: Vec<AppGroupMemberRecord>) -> Vec<Value> {
    members
        .into_iter()
        .map(|member| {
            json!({
                "member_id": member.member_id_hex,
                "npub": npub_for_account_id(&member.member_id_hex),
                "local": member.local,
            })
        })
        .collect()
}

fn apply_message_cursors(
    mut messages: Vec<AppMessageRecord>,
    before: Option<u64>,
    before_message_id: Option<&str>,
    after: Option<u64>,
    after_message_id: Option<&str>,
    limit: Option<usize>,
) -> Vec<AppMessageRecord> {
    messages.retain(|message| {
        let before_matches = before.is_none_or(|cursor| {
            message.recorded_at < cursor
                || (message.recorded_at == cursor
                    && before_message_id
                        .is_some_and(|message_id| message.message_id_hex.as_str() < message_id))
        });
        let after_matches = after.is_none_or(|cursor| {
            message.recorded_at > cursor
                || (message.recorded_at == cursor
                    && after_message_id
                        .is_some_and(|message_id| message.message_id_hex.as_str() > message_id))
        });
        before_matches && after_matches
    });

    if let Some(limit) = limit
        && messages.len() > limit
    {
        if before.is_some() && after.is_none() {
            messages = messages.split_off(messages.len() - limit);
        } else {
            messages.truncate(limit);
        }
    }
    messages
}

fn message_list_plain(messages: &[AppMessageRecord]) -> String {
    if messages.is_empty() {
        return "no messages".to_owned();
    }
    messages
        .iter()
        .map(|message| {
            format!(
                "group={} from={}: {}",
                message.group_id_hex, message.sender, message.plaintext
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn message_list_json_with_profiles(app: &MarmotApp, messages: Vec<AppMessageRecord>) -> Vec<Value> {
    messages
        .into_iter()
        .map(|message| {
            let from_display_name = display_name_for_sender(app, &message.sender);
            message_record_json(message, from_display_name)
        })
        .collect()
}

fn message_record_json(message: AppMessageRecord, from_display_name: Option<String>) -> Value {
    let agent_text_stream = agent_text_stream_payload_json(&message.plaintext);
    let app_message = message.app_message;
    let mut value = json!({
        "message_id": message.message_id_hex,
        "direction": message.direction,
        "group_id": message.group_id_hex,
        "from": message.sender,
        "from_display_name": from_display_name,
        "plaintext": message.plaintext,
        "recorded_at": message.recorded_at,
        "received_at": message.received_at,
    });
    if let Some(agent_text_stream) = agent_text_stream {
        value["agent_text_stream"] = agent_text_stream;
    }
    if let Some(app_message) = app_message {
        value["app_message"] = json!(app_message);
    }
    value
}

fn display_name_for_sender(app: &MarmotApp, sender: &str) -> Option<String> {
    let account_id = parse_public_key(sender).ok()?;
    let profile = app
        .directory_entry_for_account_id(&account_id)
        .ok()
        .flatten()
        .and_then(|entry| entry.profile);
    profile_display_name(profile.as_ref())
}

fn media_records_json(messages: Vec<AppMessageRecord>) -> Vec<Value> {
    messages
        .into_iter()
        .filter_map(|message| match message.app_message {
            Some(MarmotAppMessagePayloadV1::Media { reference, caption }) => Some(json!({
                "message_id": message.message_id_hex,
                "direction": message.direction,
                "group_id": message.group_id_hex,
                "from": message.sender,
                "file_hash_hex": reference.file_hash_hex,
                "file_name": reference.file_name,
                "media_type": reference.media_type,
                "size_bytes": reference.size_bytes,
                "caption": caption,
                "recorded_at": message.recorded_at,
                "received_at": message.received_at,
            })),
            _ => None,
        })
        .collect()
}

fn key_package_fetch_json(fetched: FetchedKeyPackage) -> Value {
    json!({
        "account_id": fetched.account_id_hex,
        "key_package_id": fetched.key_package_id,
        "key_package_bytes": fetched.key_package.0.len(),
        "created_at": fetched.created_at,
        "source_relays": fetched.source_relays,
        "relay_lists": relay_lists_json(fetched.relay_lists),
    })
}

fn dm_status_json(status: AppStatus, runtime_info: &CliRuntimeInfo) -> Value {
    json!({
        "account_id": status.account_id_hex,
        "npub": npub_for_account_id(&status.account_id_hex),
        "local_signing": true,
        "transport": status.transport,
        "groups": status.groups,
        "seen_events": status.seen_events,
        "counts": {
            "groups": status.group_count,
            "messages": status.message_count,
            "seen_events": status.seen_events,
        },
        "secret_store": secret_store_json(runtime_info),
        "projections": status.projections,
        "relay_lists": relay_lists_json(status.relay_lists),
    })
}

fn secret_store_json(runtime_info: &CliRuntimeInfo) -> Value {
    match runtime_info.secret_store {
        SecretStoreKind::File => json!({
            "backend": runtime_info.secret_store.as_str(),
        }),
        SecretStoreKind::Keychain => json!({
            "backend": runtime_info.secret_store.as_str(),
            "service": runtime_info.keychain_service,
        }),
    }
}

fn is_nostr_secret(value: &str) -> bool {
    value.starts_with("nsec")
}

fn public_account_status_json(
    account: &marmot_account::AccountSummary,
    relay_lists: AccountRelayListStatus,
) -> Value {
    json!({
        "account_id": account.account_id_hex,
        "npub": npub_for_account_id(&account.account_id_hex),
        "local_signing": false,
        "relay_lists": relay_lists_json(relay_lists),
    })
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct GlobalRelayDefaults {
    default_relays: bool,
    bootstrap_relays: bool,
}

fn apply_global_relay_defaults(
    default_relays: &mut Vec<String>,
    bootstrap_relays: &mut Vec<String>,
    relay: Option<String>,
) -> GlobalRelayDefaults {
    let mut applied = GlobalRelayDefaults::default();
    let Some(relay) = relay.map(|relay| relay.trim().to_owned()) else {
        return applied;
    };
    if relay.is_empty() {
        return applied;
    }
    if default_relays.is_empty() {
        default_relays.push(relay.clone());
        applied.default_relays = true;
    }
    if bootstrap_relays.is_empty() {
        bootstrap_relays.push(relay);
        applied.bootstrap_relays = true;
    }
    applied
}

fn resolve_relay(relay: Option<String>) -> Result<Option<String>, DmError> {
    match relay.or_else(|| std::env::var("DM_RELAY").ok()) {
        Some(relay) => validate_relay_url(relay).map(Some),
        None => Ok(None),
    }
}

fn validate_relay_url(relay: impl AsRef<str>) -> Result<String, DmError> {
    let relay = relay.as_ref().trim();
    if relay.is_empty() {
        return Err(DmError::EmptyRelayUrl);
    }
    let parsed = url::Url::parse(relay).map_err(|_| DmError::InvalidRelayUrl(relay.to_owned()))?;
    if !matches!(parsed.scheme(), "ws" | "wss") || parsed.host().is_none() {
        return Err(DmError::InvalidRelayUrl(relay.to_owned()));
    }
    Ok(relay.to_owned())
}

fn relay_endpoints(values: Vec<String>) -> Result<Vec<TransportEndpoint>, DmError> {
    let mut endpoints = Vec::new();
    for value in values {
        let endpoint = TransportEndpoint(validate_relay_url(value)?);
        if !endpoints.contains(&endpoint) {
            endpoints.push(endpoint);
        }
    }
    Ok(endpoints)
}

async fn relay_list_status_for_account_id(
    app: &MarmotApp,
    account_id: &str,
    bootstrap_relays: Vec<TransportEndpoint>,
) -> Result<AccountRelayListStatus, DmError> {
    if bootstrap_relays.is_empty() {
        Ok(app.account_relay_list_status_for_account_id(account_id)?)
    } else {
        Ok(app
            .fetch_account_relay_list_status_for_account_id(account_id, bootstrap_relays)
            .await?)
    }
}

fn account_selector_or_default(
    account_home: &AccountHome,
    account_ref: Option<String>,
    default_account: Option<String>,
) -> Result<String, DmError> {
    if let Some(account_ref) = account_ref {
        return parse_public_key(&account_ref);
    }
    Ok(resolve_account(account_home, default_account)?.account_id_hex)
}

fn resolve_account(
    account_home: &AccountHome,
    explicit: Option<String>,
) -> Result<marmot_account::AccountSummary, DmError> {
    if let Some(account) = explicit
        .or_else(|| std::env::var("DM_ACCOUNT").ok())
        .filter(|account| !account.trim().is_empty())
    {
        return resolve_account_ref(account_home, &account);
    }

    let accounts = account_home.accounts()?;
    match accounts.as_slice() {
        [] => Err(DmError::MissingAccount),
        [account] => Ok(account.clone()),
        _ => Err(DmError::MultipleAccounts),
    }
}

fn resolve_account_ref(
    account_home: &AccountHome,
    value: &str,
) -> Result<marmot_account::AccountSummary, DmError> {
    let account_id_hex = parse_public_key(value)?;
    for account in account_home.accounts()? {
        if account.account_id_hex == account_id_hex {
            return Ok(account);
        }
    }

    Err(DmError::UnknownLocalAccount(value.to_owned()))
}

fn ensure_local_signing(account: &marmot_account::AccountSummary) -> Result<(), DmError> {
    if account.local_signing {
        Ok(())
    } else {
        Err(DmError::PublicAccountCannotSign)
    }
}

fn parse_public_key(value: &str) -> Result<String, DmError> {
    nostr::PublicKey::parse(value)
        .map(|pubkey| pubkey.to_hex())
        .map_err(|_| DmError::InvalidPublicKey)
}

fn npub_for_account_id(account_id: &str) -> String {
    nostr::PublicKey::parse(account_id)
        .expect("stored account ids are valid Nostr public keys")
        .to_bech32()
        .expect("stored account ids can be encoded as npub")
}

fn normalize_group_id_hex(value: &str) -> Result<String, DmError> {
    Ok(hex::encode(hex::decode(value)?))
}

fn relay_setup_plain(status: &AccountRelayListStatus) -> String {
    if status.complete {
        "complete".to_owned()
    } else {
        format!("missing:{}", status.missing.join(","))
    }
}

fn relay_lists_json(status: AccountRelayListStatus) -> Value {
    json!({
        "complete": status.complete,
        "missing": status.missing,
        "default_relays": status.default_relays,
        "bootstrap_relays": status.bootstrap_relays,
        "nip65": status.nip65,
        "inbox": status.inbox,
        "key_package": status.key_package,
    })
}

fn app_for(home: PathBuf, relay: Option<String>, account_home: AccountHome) -> MarmotApp {
    MarmotApp::with_relays_and_account_home(home, relay.into_iter().collect(), account_home)
}

fn open_account_home(
    home: &std::path::Path,
    secret_store: SecretStoreKind,
    keychain_service: &str,
) -> Result<AccountHome, DmError> {
    match secret_store {
        SecretStoreKind::File => Ok(AccountHome::open(home)),
        SecretStoreKind::Keychain => Ok(AccountHome::open_with_keychain(home, keychain_service)?),
    }
}

fn resolve_keychain_service(keychain_service: Option<String>) -> String {
    keychain_service
        .or_else(|| std::env::var("DM_KEYCHAIN_SERVICE").ok())
        .unwrap_or_else(|| DEFAULT_KEYCHAIN_SERVICE_NAME.to_owned())
}

fn resolve_secret_store(secret_store: Option<SecretStoreKind>) -> Result<SecretStoreKind, DmError> {
    if let Some(secret_store) = secret_store {
        return Ok(secret_store);
    }
    match std::env::var("DM_SECRET_STORE") {
        Ok(value) => match value.trim() {
            "keychain" => Ok(SecretStoreKind::Keychain),
            "file" | "local-file" | "local_file" => Ok(SecretStoreKind::File),
            other => Err(DmError::InvalidSecretStore(other.to_owned())),
        },
        Err(_) => Ok(SecretStoreKind::Keychain),
    }
}

fn resolve_home(home: Option<PathBuf>) -> PathBuf {
    home.or_else(|| std::env::var_os("DM_HOME").map(PathBuf::from))
        .unwrap_or_else(default_home)
}

fn default_home() -> PathBuf {
    default_home_from_env(|name| std::env::var_os(name))
}

fn default_home_from_env(mut var: impl FnMut(&str) -> Option<OsString>) -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Some(appdata) = var("APPDATA") {
            return PathBuf::from(appdata).join("darkmatter");
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(home) = var("HOME") {
            return PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("darkmatter");
        }
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(xdg_data_home) = var("XDG_DATA_HOME") {
            return PathBuf::from(xdg_data_home).join("darkmatter");
        }
        if let Some(home) = var("HOME") {
            return PathBuf::from(home)
                .join(".local")
                .join("share")
                .join("darkmatter");
        }
    }

    PathBuf::from(".darkmatter")
}

fn ensure_trailing_newline(mut value: String) -> String {
    if !value.ends_with('\n') {
        value.push('\n');
    }
    value
}

fn json_error(code: i32, error_code: &str, message: String) -> CliOutput {
    CliOutput {
        code,
        stdout: format!(
            "{}\n",
            serde_json::to_string(&json!({
                "ok": false,
                "error": {
                    "code": error_code,
                    "message": message,
                }
            }))
            .expect("JSON response serialization cannot fail")
        ),
        stderr: String::new(),
    }
}

fn json_dm_error(err: DmError) -> CliOutput {
    let error = dm_error_json(&err);
    CliOutput {
        code: 1,
        stdout: format!(
            "{}\n",
            serde_json::to_string(&json!({
                "ok": false,
                "error": error,
            }))
            .expect("JSON response serialization cannot fail")
        ),
        stderr: String::new(),
    }
}

fn dm_error_json(err: &DmError) -> Value {
    match err {
        DmError::MissingRelayLists(missing, status) => json!({
            "code": "missing_relay_lists",
            "message": "account is missing required relay lists",
            "missing": missing,
            "relay_lists": relay_lists_json(status.as_ref().clone()),
            "repair": {
                "requires": "--default-relays",
                "publish_missing": "--publish-missing-relay-lists",
            },
        }),
        DmError::AccountHome(err) => account_home_error_json(err),
        DmError::App(err) => app_error_json(err),
        DmError::QuicStream(err) => json!({
            "code": "quic_stream",
            "message": err.to_string(),
        }),
        DmError::QuicBroker(err) => json!({
            "code": "quic_broker",
            "message": err.to_string(),
        }),
        DmError::AgentTextStreamPayload(err) => json!({
            "code": "agent_text_stream_payload",
            "message": err.to_string(),
        }),
        DmError::Hex(err) => json!({
            "code": "invalid_hex",
            "message": err.to_string(),
        }),
        DmError::Io(err) => json!({
            "code": "io_error",
            "message": err.to_string(),
        }),
        DmError::Json(err) => json!({
            "code": "json_error",
            "message": err.to_string(),
        }),
        DmError::EmptyMessage => json!({
            "code": "empty_message",
            "message": err.to_string(),
        }),
        DmError::EmptyStreamText => json!({
            "code": "empty_stream_text",
            "message": err.to_string(),
        }),
        DmError::MissingStreamStart => json!({
            "code": "missing_stream_start",
            "message": err.to_string(),
        }),
        DmError::MissingQuicCandidate => json!({
            "code": "missing_quic_candidate",
            "message": err.to_string(),
        }),
        DmError::UnsupportedStreamRoute(route) => json!({
            "code": "unsupported_stream_route",
            "message": err.to_string(),
            "route": route,
        }),
        DmError::InvalidQuicCandidate(candidate) => json!({
            "code": "invalid_quic_candidate",
            "message": err.to_string(),
            "candidate": candidate,
        }),
        DmError::QuicCandidateResolve { candidate, source } => json!({
            "code": "quic_candidate_resolve",
            "message": err.to_string(),
            "candidate": candidate,
            "source": source.to_string(),
        }),
        DmError::InvalidTranscriptHashLength(actual) => json!({
            "code": "invalid_transcript_hash",
            "message": err.to_string(),
            "actual_bytes": actual,
            "expected_bytes": 32,
        }),
        DmError::ConflictingStreamTrust => json!({
            "code": "conflicting_stream_trust",
            "message": err.to_string(),
        }),
        DmError::InsecureLocalRequiresLoopback(addr) => json!({
            "code": "insecure_local_requires_loopback",
            "message": err.to_string(),
            "addr": addr.to_string(),
        }),
        DmError::MessagesSubscribeRequiresDaemon => json!({
            "code": "daemon_required",
            "message": err.to_string(),
            "repair": {
                "start": "dm daemon start",
            },
        }),
        DmError::MissingLoginIdentity => json!({
            "code": "missing_login_identity",
            "message": err.to_string(),
            "repair": {
                "login": "dm login <nsec-or-npub>",
            },
        }),
        DmError::UnsupportedCommand { command, reason } => json!({
            "code": "unsupported_command",
            "message": err.to_string(),
            "command": command,
            "reason": reason,
        }),
        DmError::MissingGroupId => json!({
            "code": "missing_group_id",
            "message": err.to_string(),
        }),
        DmError::EmptyRelayUrl => json!({
            "code": "empty_relay_url",
            "message": err.to_string(),
        }),
        DmError::InvalidRelayUrl(_) => json!({
            "code": "invalid_relay_url",
            "message": err.to_string(),
            "repair": {
                "login": "dm login <nsec> --relay <ws-or-wss-url>",
                "daemon": "dm daemon start --discovery-relays <url> --default-account-relays <url>",
                "account_setup": "--default-relays <ws-or-wss-url> --bootstrap-relays <ws-or-wss-url>",
            },
        }),
        DmError::MissingRelay => json!({
            "code": "missing_relay_url",
            "message": err.to_string(),
            "repair": {
                "daemon": "dm daemon start --discovery-relays <url> --default-account-relays <url>",
                "account_setup": "--default-relays <url> --bootstrap-relays <url>",
            },
        }),
        DmError::MissingAccount => json!({
            "code": "missing_account",
            "message": err.to_string(),
            "repair": {
                "create": "dm account create [nsec-or-npub]",
                "select": "--account <npub-or-hex>",
            },
        }),
        DmError::MultipleAccounts => json!({
            "code": "multiple_accounts",
            "message": err.to_string(),
            "repair": {
                "flag": "--account",
                "env": "DM_ACCOUNT",
            },
        }),
        DmError::UnknownLocalAccount(account) => json!({
            "code": "unknown_account",
            "message": err.to_string(),
            "account_ref": account,
        }),
        DmError::InvalidPublicKey => json!({
            "code": "invalid_public_key",
            "message": err.to_string(),
        }),
        DmError::PublicAccountCannotSign => json!({
            "code": "public_account_cannot_sign",
            "message": err.to_string(),
        }),
        DmError::InvalidSecretStore(store) => json!({
            "code": "invalid_secret_store",
            "message": err.to_string(),
            "secret_store": store,
        }),
    }
}

fn account_home_error_json(err: &AccountHomeError) -> Value {
    match err {
        AccountHomeError::AccountExists(account) => json!({
            "code": "account_exists",
            "message": err.to_string(),
            "account_ref": account,
        }),
        AccountHomeError::UnknownAccount(account) => json!({
            "code": "unknown_account",
            "message": err.to_string(),
            "account_ref": account,
        }),
        AccountHomeError::InvalidSecretKey => json!({
            "code": "invalid_secret_key",
            "message": err.to_string(),
        }),
        AccountHomeError::InvalidPublicKey => json!({
            "code": "invalid_public_key",
            "message": err.to_string(),
        }),
        AccountHomeError::InvalidAccountLabel(account) => json!({
            "code": "invalid_account_label",
            "message": err.to_string(),
            "label": account,
        }),
        AccountHomeError::SecretNotFound(account_id) => json!({
            "code": "secret_not_found",
            "message": err.to_string(),
            "account_id": account_id,
        }),
        AccountHomeError::EmptySecretStoreService => json!({
            "code": "empty_secret_store_service",
            "message": err.to_string(),
        }),
        other => json!({
            "code": "account_home_error",
            "message": other.to_string(),
        }),
    }
}

fn app_error_json(err: &AppError) -> Value {
    match err {
        AppError::AccountHome(err) => account_home_error_json(err),
        AppError::Account(AccountError::Engine(err)) => engine_error_json(err),
        AppError::Account(AccountError::Session(cgka_session::SessionError::Engine(err))) => {
            engine_error_json(err)
        }
        AppError::MissingKeyPackage(account) => json!({
            "code": "missing_key_package",
            "message": err.to_string(),
            "account_id": account,
            "repair": {
                "local": format!("dm --account {account} keys publish"),
                "remote": "dm keys fetch <npub-or-hex> --bootstrap-relays <relay-url>"
            },
        }),
        AppError::UnknownGroup(group_id) => json!({
            "code": "unknown_group",
            "message": err.to_string(),
            "group_id": group_id,
        }),
        AppError::Transport(err) => json!({
            "code": "relay_transport",
            "message": err.to_string(),
        }),
        AppError::Publish(reason) => json!({
            "code": "publish_failed",
            "message": err.to_string(),
            "reason": reason,
        }),
        AppError::MissingDefaultRelays => json!({
            "code": "missing_default_relays",
            "message": err.to_string(),
            "repair": {
                "flag": "--default-relays",
            },
        }),
        AppError::MissingRelayLists(missing) => json!({
            "code": "missing_relay_lists",
            "message": err.to_string(),
            "missing": missing,
        }),
        AppError::RelayDirectory(reason) => json!({
            "code": "relay_directory_failed",
            "message": err.to_string(),
            "reason": reason,
        }),
        AppError::InvalidPublicKey => json!({
            "code": "invalid_public_key",
            "message": err.to_string(),
        }),
        AppError::InvalidKeyPackageEvent(reason) => json!({
            "code": "invalid_key_package_event",
            "message": err.to_string(),
            "reason": reason,
        }),
        AppError::MissingDirectoryEntry(account_id) => json!({
            "code": "missing_directory_entry",
            "message": err.to_string(),
            "account_id": account_id,
            "repair": {
                "command": format!("dm keys fetch {account_id} --bootstrap-relays <relay-url>")
            },
        }),
        AppError::InvalidGroupProfile(reason) => json!({
            "code": "invalid_group_profile",
            "message": err.to_string(),
            "reason": reason,
        }),
        AppError::Hex(err) => json!({
            "code": "invalid_hex",
            "message": err.to_string(),
        }),
        other => json!({
            "code": "command_failed",
            "message": other.to_string(),
        }),
    }
}

fn engine_error_json(err: &EngineError) -> Value {
    match err {
        EngineError::UnknownGroup(group_id) => json!({
            "code": "unknown_group",
            "message": err.to_string(),
            "group_id": hex::encode(group_id.as_slice()),
        }),
        EngineError::NotGroupAdmin { group_id } => json!({
            "code": "not_group_admin",
            "message": err.to_string(),
            "group_id": hex::encode(group_id.as_slice()),
        }),
        EngineError::UnknownMember { group_id, member } => json!({
            "code": "unknown_member",
            "message": err.to_string(),
            "group_id": hex::encode(group_id.as_slice()),
            "member": hex::encode(member.as_slice()),
        }),
        EngineError::AdminCannotSelfRemove { group_id }
        | EngineError::AdminDepletion { group_id } => json!({
            "code": "admin_policy",
            "message": err.to_string(),
            "group_id": hex::encode(group_id.as_slice()),
        }),
        EngineError::MissingRequiredCapabilities { required, had } => json!({
            "code": "missing_required_capabilities",
            "message": err.to_string(),
            "required": format!("{required:?}"),
            "had": format!("{had:?}"),
        }),
        EngineError::InvalidTransition(transition) => json!({
            "code": "invalid_transition",
            "message": transition.to_string(),
        }),
        other => json!({
            "code": "engine_error",
            "message": other.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::PathBuf;

    use super::{
        AppMessageRecord, DmError, GlobalRelayDefaults, apply_global_relay_defaults,
        apply_message_cursors, default_home_from_env, relay_endpoints, resolve_relay,
    };

    #[test]
    fn default_home_uses_user_data_location_instead_of_current_directory() {
        let home = default_home_from_env(|name| match name {
            "HOME" => Some(OsString::from("/Users/alice")),
            "XDG_DATA_HOME" | "APPDATA" => None,
            _ => None,
        });

        #[cfg(target_os = "macos")]
        assert_eq!(
            home,
            PathBuf::from("/Users/alice/Library/Application Support/darkmatter")
        );
        #[cfg(all(unix, not(target_os = "macos")))]
        assert_eq!(home, PathBuf::from("/Users/alice/.local/share/darkmatter"));
    }

    #[test]
    fn default_home_prefers_xdg_data_home_on_non_macos_unix() {
        let home = default_home_from_env(|name| match name {
            "HOME" => Some(OsString::from("/home/alice")),
            "XDG_DATA_HOME" => Some(OsString::from("/tmp/xdg-data")),
            "APPDATA" => None,
            _ => None,
        });

        #[cfg(all(unix, not(target_os = "macos")))]
        assert_eq!(home, PathBuf::from("/tmp/xdg-data/darkmatter"));
        #[cfg(target_os = "macos")]
        assert_eq!(
            home,
            PathBuf::from("/home/alice/Library/Application Support/darkmatter")
        );
    }

    #[test]
    fn global_relay_defaults_backfill_default_and_bootstrap_independently() {
        let mut default_relays = vec!["wss://explicit-default.example".to_owned()];
        let mut bootstrap_relays = Vec::new();

        let applied = apply_global_relay_defaults(
            &mut default_relays,
            &mut bootstrap_relays,
            Some(" wss://global.example ".to_owned()),
        );

        assert_eq!(
            applied,
            GlobalRelayDefaults {
                default_relays: false,
                bootstrap_relays: true,
            }
        );
        assert_eq!(default_relays, vec!["wss://explicit-default.example"]);
        assert_eq!(bootstrap_relays, vec!["wss://global.example"]);

        let mut default_relays = Vec::new();
        let mut bootstrap_relays = vec!["wss://explicit-bootstrap.example".to_owned()];

        let applied = apply_global_relay_defaults(
            &mut default_relays,
            &mut bootstrap_relays,
            Some("wss://global.example".to_owned()),
        );

        assert_eq!(
            applied,
            GlobalRelayDefaults {
                default_relays: true,
                bootstrap_relays: false,
            }
        );
        assert_eq!(default_relays, vec!["wss://global.example"]);
        assert_eq!(bootstrap_relays, vec!["wss://explicit-bootstrap.example"]);
    }

    #[test]
    fn relay_url_helpers_reject_malformed_or_non_websocket_urls() {
        assert!(matches!(
            resolve_relay(Some("not-a-relay-url".to_owned())),
            Err(DmError::InvalidRelayUrl(value)) if value == "not-a-relay-url"
        ));
        assert!(matches!(
            resolve_relay(Some("https://relay.example".to_owned())),
            Err(DmError::InvalidRelayUrl(value)) if value == "https://relay.example"
        ));
        assert!(matches!(
            relay_endpoints(vec!["mailto:relay@example.com".to_owned()]),
            Err(DmError::InvalidRelayUrl(value)) if value == "mailto:relay@example.com"
        ));
        assert_eq!(
            resolve_relay(Some(" wss://relay.example/path ".to_owned())).unwrap(),
            Some("wss://relay.example/path".to_owned())
        );
    }

    #[test]
    fn message_cursors_match_whitenoise_forward_order_paging_shape() {
        let messages = ["a", "b", "c", "d"]
            .into_iter()
            .enumerate()
            .map(|(index, id)| AppMessageRecord {
                message_id_hex: id.to_owned(),
                direction: "received".to_owned(),
                group_id_hex: "group".to_owned(),
                sender: "sender".to_owned(),
                plaintext: id.to_owned(),
                app_message: None,
                recorded_at: 100 + u64::try_from(index / 2).unwrap(),
                received_at: 100 + u64::try_from(index / 2).unwrap(),
            })
            .collect::<Vec<_>>();

        let before =
            apply_message_cursors(messages.clone(), Some(101), Some("d"), None, None, Some(2));
        assert_eq!(
            before
                .iter()
                .map(|message| message.message_id_hex.as_str())
                .collect::<Vec<_>>(),
            vec!["b", "c"]
        );

        let after = apply_message_cursors(messages, None, None, Some(100), Some("a"), Some(2));
        assert_eq!(
            after
                .iter()
                .map(|message| message.message_id_hex.as_str())
                .collect::<Vec<_>>(),
            vec!["b", "c"]
        );
    }
}
