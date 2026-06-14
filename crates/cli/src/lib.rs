use std::collections::HashMap;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cgka_traits::TransportEndpoint;
use cgka_traits::app_event::{
    MARMOT_APP_EVENT_KIND_AGENT_STREAM_START, STREAM_CHUNKS_TAG, STREAM_HASH_TAG, STREAM_START_TAG,
    STREAM_TAG,
};
use cgka_traits::error::EngineError;
use cgka_traits::{GroupId, MessageId};
use clap::{Parser, Subcommand, ValueEnum};
use marmot_account::{AccountError, AccountHome, AccountHomeError, DEFAULT_KEYCHAIN_SERVICE_NAME};
use marmot_app::{
    AccountRelayListBootstrap, AccountRelayListStatus, AccountSetupRequest, AccountSetupResult,
    AgentTextStreamFinishRequest, AppError, AppGroupMemberRecord, AppGroupMlsState, AppGroupRecord,
    AppMessageQuery, AppMessageRecord, AppStatus, DurationHistogramSnapshot, FetchedKeyPackage,
    MarmotApp, MarmotAppConfig, MarmotAppRuntime, MediaAttachmentReference, MediaLocator,
    MediaUploadAttachmentRequest, MediaUploadRequest, RelayDeliverySpread, RelayDeliveryStats,
    RelayLatencyStats, RelaySyncSnapshot, RelayTelemetrySnapshot, StreamStartView, SyncSummary,
    TimelineMessageQuery, TimelineMessageRecord, TimelinePage, TimelinePagination,
    UserDirectorySearch, UserProfileMetadata, tag_value,
};
use nostr::ToBech32;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use transport_quic_broker::{
    BrokerServerTrust, PublishTextToBroker, SubscribeTextFromBroker, publish_text_to_broker,
    subscribe_text_from_broker_with_limits,
};
use transport_quic_stream::{
    AgentTextStreamReceiveLimits, QuicTextStreamReceiver, SendTextStream, ServerTrust,
    send_text_stream,
};

pub mod daemon;
pub mod tui;

pub(crate) const DEFAULT_PRODUCTION_QUIC_BROKER_CANDIDATE: &str = "quic://quic-broker.ipf.dev:4450";
const AGENT_STREAM_START_LOOKBACK_LIMIT: usize = 200;
const PRIVATE_DIR_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;

pub(crate) fn create_private_dir_all(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(PRIVATE_DIR_MODE))?;
    Ok(())
}

pub(crate) fn write_private_file(path: &Path, bytes: impl AsRef<[u8]>) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        create_private_dir_all(parent)?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(PRIVATE_FILE_MODE);
    let mut file = options.open(path)?;
    file.write_all(bytes.as_ref())?;
    #[cfg(unix)]
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(PRIVATE_FILE_MODE))?;
    Ok(())
}

pub(crate) fn open_private_append_file(path: &Path) -> std::io::Result<std::fs::File> {
    if let Some(parent) = path.parent() {
        create_private_dir_all(parent)?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    options.mode(PRIVATE_FILE_MODE);
    let file = options.open(path)?;
    #[cfg(unix)]
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(PRIVATE_FILE_MODE))?;
    Ok(file)
}

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
enum MessageTimelineCommand {
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
    #[error("brokered stream start has no confirmed message id yet")]
    StreamStartNotConfirmed,
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
    #[error("login requires --nsec-stdin or an npub identity")]
    MissingLoginIdentity,
    #[error(
        "{command} does not accept private keys as command-line arguments; pipe the nsec to --nsec-stdin"
    )]
    SecretArgumentRejected { command: &'static str },
    #[error("{command} expects either a public identity argument or --nsec-stdin, not both")]
    ConflictingSecretInput { command: &'static str },
    #[error("{command} --nsec-stdin received empty input")]
    MissingStdinSecret { command: &'static str },
    #[error("{command} --nsec-stdin requires an nsec secret key")]
    InvalidStdinSecret { command: &'static str },
    #[error("no media attachment found for plaintext hash {0}")]
    MediaAttachmentNotFound(String),
    #[error("invalid media attachment: {0}")]
    InvalidMediaAttachment(String),
    #[error("{command} is not implemented yet: {reason}")]
    UnsupportedCommand {
        command: &'static str,
        reason: &'static str,
    },
    #[error("missing account relay lists: {0:?}")]
    MissingRelayLists(Vec<String>, Box<AccountRelayListStatus>),
    #[error(
        "cannot safely update {list} replaceable list for {account_id}: no current list event found on the selected relays"
    )]
    ReplaceableListInconclusive {
        list: String,
        account_id: String,
        source_relays: Vec<String>,
    },
    #[error("message pagination requires {timestamp_flag} and {message_id_flag} together")]
    MessagePaginationCursorMismatch {
        timestamp_flag: &'static str,
        message_id_flag: &'static str,
    },
    #[error("message pagination cannot use before and after cursors together")]
    MessagePaginationConflictingCursors,
    #[error("profile update requires at least one field flag (e.g. --name, --about, --picture)")]
    EmptyProfileUpdate,
    #[error(
        "cannot safely update profile for {account_id}: no current profile event found on the selected relays"
    )]
    ProfileUpdateInconclusive {
        account_id: String,
        source_relays: Vec<String>,
    },
}

pub async fn run_from<I, T>(args: I) -> CliOutput
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    let argv = args.into_iter().map(Into::into).collect::<Vec<_>>();
    let wants_json = argv.iter().any(|arg| arg.to_string_lossy() == "--json");
    let mut cli = match Cli::try_parse_from(argv) {
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
    if let Err(err) = materialize_secret_inputs(&mut cli) {
        return command_output_result(cli.json, Err(err));
    }

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
            // An oversized request is a client-side limit violation, not a
            // daemon-unavailable condition: the encoder rejects it before it
            // ever reaches `dmd`. Surface it as a terminal error even on the
            // implicit-socket path, otherwise the request silently falls
            // through to `run_cli_local` and masks the size cap (see #190).
            Err(err @ daemon::DaemonClientError::RequestTooLarge { .. }) => {
                return daemon_client_error(cli.json, err);
            }
            Err(err) if cli.socket.is_some() || std::env::var_os("DM_SOCKET").is_some() => {
                return daemon_client_error(cli.json, err);
            }
            Err(_) => {}
        }
    }

    run_cli_local(cli).await
}

fn materialize_secret_inputs(cli: &mut Cli) -> Result<(), DmError> {
    match &mut cli.command {
        Command::Login {
            identity,
            nsec_stdin,
            ..
        } => materialize_identity_secret_input("login", identity, *nsec_stdin),
        Command::Account {
            command:
                AccountCommand::Create {
                    identity,
                    nsec_stdin,
                    ..
                },
        }
        | Command::Accounts {
            command:
                AccountCommand::Create {
                    identity,
                    nsec_stdin,
                    ..
                },
        } => materialize_identity_secret_input("account create", identity, *nsec_stdin),
        _ => Ok(()),
    }
}

fn materialize_identity_secret_input(
    command: &'static str,
    identity: &mut Option<String>,
    nsec_stdin: bool,
) -> Result<(), DmError> {
    if nsec_stdin {
        if identity.is_some() {
            return Err(DmError::ConflictingSecretInput { command });
        }
        *identity = Some(read_nsec_from_stdin(command)?);
    }
    validate_materialized_secret_identity(command, identity, nsec_stdin)
}

fn read_nsec_from_stdin(command: &'static str) -> Result<String, DmError> {
    let mut value = String::new();
    std::io::stdin().read_to_string(&mut value)?;
    let value = value.trim().to_owned();
    if value.is_empty() {
        return Err(DmError::MissingStdinSecret { command });
    }
    if !is_nostr_secret(&value) {
        return Err(DmError::InvalidStdinSecret { command });
    }
    Ok(value)
}

pub(crate) fn validate_materialized_secret_identity(
    command: &'static str,
    identity: &Option<String>,
    nsec_stdin: bool,
) -> Result<(), DmError> {
    if identity.as_deref().is_some_and(is_nostr_secret) && !nsec_stdin {
        return Err(DmError::SecretArgumentRejected { command });
    }
    Ok(())
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
        } | Command::Message {
            command: MessageCommand::Timeline {
                command: MessageTimelineCommand::Subscribe { .. },
            },
        } | Command::Messages {
            command: MessageCommand::Timeline {
                command: MessageTimelineCommand::Subscribe { .. },
            },
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
        && matches!(command, StreamCommand::Receive { .. })
    {
        return stream_command_local(command.clone()).await;
    }
    if let Command::Stream {
        command:
            stream_command @ StreamCommand::Send {
                start_event_id: None,
                ..
            },
    } = &command
    {
        return stream_command_local(stream_command.clone()).await;
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
        Command::Login {
            identity,
            nsec_stdin,
            relay: _,
        } => {
            identity_login_command(
                &app,
                runtime_info,
                identity,
                nsec_stdin,
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
        Command::RelayStats => relay_stats_command(&app).await,
        Command::Reset { confirm } => reset_command(&home, confirm),
    }
}

fn daemon_socket_for_client(cli: &Cli, home: &Path) -> Option<PathBuf> {
    if let Command::Stream { command } = &cli.command
        && client_hosted_stream_command(command).is_some()
    {
        return None;
    }

    let socket = daemon_socket_path_for_client(cli, home);
    if cli.socket.is_some() || std::env::var_os("DM_SOCKET").is_some() || socket.exists() {
        Some(socket)
    } else {
        None
    }
}

pub(crate) fn client_hosted_stream_command(
    command: &StreamCommand,
) -> Option<(&'static str, &'static str)> {
    match command {
        StreamCommand::Receive { .. } => Some((
            "stream receive",
            "it waits for incoming stream traffic; run dm stream receive directly without --socket",
        )),
        StreamCommand::Send {
            start_event_id: None,
            ..
        } => Some((
            "stream send",
            "it opens a client-hosted stream; anchor the send to an existing stream or run it directly without --socket",
        )),
        StreamCommand::Watch {
            background: false, ..
        } => Some((
            "stream watch",
            "foreground stream watches run until the stream ends; use --background or run directly without --socket",
        )),
        _ => None,
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
        false,
        runtime_info,
        relay,
    )
    .await
}

async fn identity_login_command(
    app: &MarmotApp,
    runtime_info: CliRuntimeInfo,
    identity: Option<String>,
    nsec_stdin: bool,
    relay: Option<String>,
    default_relays: Vec<String>,
    bootstrap_relays: Vec<String>,
) -> Result<CommandOutput, DmError> {
    validate_materialized_secret_identity("login", &identity, nsec_stdin)?;
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
        nsec_stdin,
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
    nsec_stdin: bool,
    _runtime_info: CliRuntimeInfo,
    relay: Option<String>,
) -> Result<CommandOutput, DmError> {
    validate_materialized_secret_identity("account create", &identity, nsec_stdin)?;
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
            nsec_stdin,
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
                nsec_stdin,
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
            let fetched = if relay_lists.nip65.relays.is_empty() {
                None
            } else {
                app.fetch_latest_key_package_for_account_id(
                    &account.account_id_hex,
                    relay_endpoints(relay_lists.nip65.relays.clone())?,
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
                    fetched.key_package.bytes().len(),
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
    let runtime = app.runtime();
    chats_command_with_runtime(account_home, app, &runtime, command, account_flag).await
}

pub(crate) async fn chats_command_with_runtime(
    account_home: &AccountHome,
    app: &MarmotApp,
    runtime: &MarmotAppRuntime,
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
            group_archive_output(runtime, account, group, true).await
        }
        ChatsCommand::Unarchive { group } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            group_archive_output(runtime, account, group, false).await
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
        MediaCommand::Upload {
            group,
            file_path,
            send,
            message,
            media_type,
            server,
        } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id_hex = normalize_group_id_hex(&group)?;
            let group_id = GroupId::new(hex::decode(&group_id_hex)?);
            let path = PathBuf::from(&file_path);
            let plaintext = std::fs::read(&path)?;
            let file_name = media_file_name(&path)?;
            let media_type = media_type.unwrap_or_else(|| guess_media_type(&path).to_owned());
            let upload = runtime
                .upload_media(
                    &account.account_id_hex,
                    &group_id,
                    MediaUploadRequest {
                        attachments: vec![MediaUploadAttachmentRequest {
                            file_name,
                            media_type,
                            plaintext,
                            dim: None,
                            thumbhash: None,
                        }],
                        caption: message,
                        send,
                        blossom_server: server,
                    },
                )
                .await?;
            let first = upload.attachments.first().ok_or_else(|| {
                DmError::InvalidMediaAttachment("upload returned no attachments".to_owned())
            })?;
            Ok(CommandOutput {
                plain: if upload.sent.is_some() {
                    format!("uploaded and sent {}", first.reference.file_name)
                } else {
                    format!("uploaded {}", first.reference.file_name)
                },
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex),
                    "group_id": group_id_hex,
                    "attachments": upload.attachments.iter().map(media_upload_attachment_json).collect::<Vec<_>>(),
                    "sent": upload.sent.map(send_summary_json),
                }),
            })
        }
        MediaCommand::Download {
            group,
            file_hash,
            output,
        } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id_hex = normalize_group_id_hex(&group)?;
            let group_id = GroupId::new(hex::decode(&group_id_hex)?);
            let file_hash_hex = normalize_sha256_hex(&file_hash)?;
            let messages = runtime.messages_with_query(
                &account.account_id_hex,
                AppMessageQuery {
                    group_id_hex: Some(group_id_hex.clone()),
                    limit: None,
                },
            )?;
            let reference = media_attachment_for_hash(messages, &file_hash_hex)?;
            let output_path = media_output_path(output, &reference.file_name);
            let download = runtime
                .download_media(&account.account_id_hex, &group_id, reference.clone())
                .await?;
            write_private_file(&output_path, &download.plaintext)?;
            Ok(CommandOutput {
                plain: output_path.display().to_string(),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex),
                    "group_id": group_id_hex,
                    "media": media_attachment_json(&reference),
                    "output_path": output_path.display().to_string(),
                    "size_bytes": download.size_bytes,
                }),
            })
        }
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
            let media = media_records_json(messages)?;
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

async fn group_archive_output(
    runtime: &MarmotAppRuntime,
    account: marmot_account::AccountSummary,
    group: String,
    archived: bool,
) -> Result<CommandOutput, DmError> {
    let group_id = normalize_group_id_hex(&group)?;
    let group = runtime
        .set_group_archived(&account.label, &group_id, archived)
        .await?;
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
            validate_message_list_cursors(
                before,
                before_message_id.as_deref(),
                after,
                after_message_id.as_deref(),
            )?;
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
        MessageCommand::Timeline { command } => {
            handle_message_timeline_command(app, account_home, command, account_flag)
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

fn handle_message_timeline_command(
    app: &MarmotApp,
    account_home: &AccountHome,
    command: MessageTimelineCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, DmError> {
    match command {
        MessageTimelineCommand::List {
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
            let page = app.timeline_messages_with_query(
                &account.label,
                TimelineMessageQuery {
                    group_id_hex: group
                        .map(|group| normalize_group_id_hex(&group))
                        .transpose()?,
                    search: None,
                    pagination: TimelinePagination {
                        before,
                        before_message_id,
                        after,
                        after_message_id,
                        limit,
                    },
                },
            )?;
            Ok(timeline_page_output(
                app,
                &account.account_id_hex,
                page,
                None,
            ))
        }
        MessageTimelineCommand::Search {
            query,
            group_id,
            group,
            limit,
        } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group = group.or(group_id);
            let page = app.timeline_messages_with_query(
                &account.label,
                TimelineMessageQuery {
                    group_id_hex: group
                        .map(|group| normalize_group_id_hex(&group))
                        .transpose()?,
                    search: Some(query.clone()),
                    pagination: TimelinePagination {
                        limit,
                        ..TimelinePagination::default()
                    },
                },
            )?;
            Ok(timeline_page_output(
                app,
                &account.account_id_hex,
                page,
                Some(query),
            ))
        }
        MessageTimelineCommand::Subscribe { .. } => Err(DmError::MessagesSubscribeRequiresDaemon),
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

fn replaceable_list_inconclusive(
    list: &str,
    account_id: &str,
    source_relays: &[TransportEndpoint],
) -> DmError {
    DmError::ReplaceableListInconclusive {
        list: list.to_owned(),
        account_id: account_id.to_owned(),
        source_relays: source_relays
            .iter()
            .map(|endpoint| endpoint.0.clone())
            .collect(),
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
        .fetch_current_follow_list_for_account_id(&account.account_id_hex, vec![endpoint.clone()])
        .await?
        .ok_or_else(|| {
            replaceable_list_inconclusive(
                "follows",
                &account.account_id_hex,
                std::slice::from_ref(&endpoint),
            )
        })?;
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
            // A flag-per-field update is partial by intent: the user names the
            // fields they want to change and expects the rest of their kind:0
            // profile to survive. kind:0 is a *replaceable* event, though, so a
            // naive publish of just the passed flags overwrites the whole
            // profile and silently wipes every unset field. Reject the
            // no-flags call outright (it would publish an empty {} and erase
            // everything), then fetch the current published profile, overlay
            // only the provided fields, and publish the merged result. This
            // mirrors the relays-add replaceable-list flow (fetch current,
            // merge, refuse to clobber when the relay has no current event).
            if name.is_none()
                && display_name.is_none()
                && about.is_none()
                && picture.is_none()
                && nip05.is_none()
                && lud16.is_none()
            {
                return Err(DmError::EmptyProfileUpdate);
            }
            let relay = relay.ok_or(DmError::MissingRelay)?;
            let endpoint = TransportEndpoint(validate_relay_url(&relay)?);
            let mut profile = app
                .fetch_current_user_profile_for_account_id(
                    &account.account_id_hex,
                    vec![endpoint.clone()],
                )
                .await?
                .ok_or_else(|| DmError::ProfileUpdateInconclusive {
                    account_id: account.account_id_hex.clone(),
                    source_relays: vec![endpoint.0.clone()],
                })?;
            if let Some(name) = name {
                profile.name = Some(name);
            }
            if let Some(display_name) = display_name {
                profile.display_name = Some(display_name);
            }
            if let Some(about) = about {
                profile.about = Some(about);
            }
            if let Some(picture) = picture {
                profile.picture = Some(picture);
            }
            if let Some(nip05) = nip05 {
                profile.nip05 = Some(nip05);
            }
            if let Some(lud16) = lud16 {
                profile.lud16 = Some(lud16);
            }
            profile.created_at = unix_now_seconds();
            profile.source_relays = Vec::new();
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
    let explicit_bootstrap = relay.map(validate_relay_url).transpose()?;
    let cached_status = app.account_relay_list_status(&account.label)?;
    let source_relays = if let Some(relay) = explicit_bootstrap.as_ref() {
        vec![TransportEndpoint(relay.clone())]
    } else if !cached_status.bootstrap_relays.is_empty() {
        relay_endpoints(cached_status.bootstrap_relays.clone())?
    } else {
        relay_endpoints(relays_for_type(&cached_status, None)?)?
    };
    if source_relays.is_empty() {
        return Err(replaceable_list_inconclusive(
            &format!("relays:{relay_type}"),
            &account.account_id_hex,
            &source_relays,
        ));
    }
    let status = app
        .fetch_current_account_relay_list_status_for_account_id(
            &account.account_id_hex,
            source_relays.clone(),
            Some(&relay_type),
        )
        .await?
        .ok_or_else(|| {
            replaceable_list_inconclusive(
                &format!("relays:{relay_type}"),
                &account.account_id_hex,
                &source_relays,
            )
        })?;
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
    let bootstrap = explicit_bootstrap
        .or_else(|| source_relays.first().map(|endpoint| endpoint.0.clone()))
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
        None => {
            let mut relays = status.default_relays.clone();
            relays.extend(status.inbox.relays.clone());
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
        _ => unsupported_command("relays", "relay type must be nip65 or inbox"),
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
    let bytes = serde_json::to_vec_pretty(settings)?;
    write_private_file(&path, bytes)?;
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
            let received = receiver.receive_once(start_event_id, None).await?;
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
                if !anchored {
                    return Err(DmError::MissingStreamStart);
                }
                let sent = publish_text_to_broker(PublishTextToBroker {
                    broker_addr: connect,
                    server_name: server_name.clone(),
                    trust: trust.clone(),
                    stream_id: stream_id.clone(),
                    start_event_id,
                    text: text.clone(),
                    max_chunk_bytes: chunk_bytes,
                    chunk_delay: Duration::from_millis(chunk_delay_ms),
                    crypto: None,
                    max_plaintext_frame_len: None,
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
                crypto: None,
                max_plaintext_frame_len: None,
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
            let agent_text_stream =
                agent_text_stream_payload_value(payload.kind, &payload.tags, &payload.content);
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
            stream_watch_command_app_with_runtime(
                account_home,
                app,
                runtime,
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
            let selected_account = resolve_selected_account(account_home, account_flag)?;
            if let Some(account) = selected_account.as_ref() {
                ensure_local_signing(account)?;
            }
            let selected_account_id_hex = selected_account
                .as_ref()
                .map(|account| account.account_id_hex.as_str());
            let start_event_id_hex = start_event_id.ok_or(DmError::MissingStreamStart)?;
            let expected_stream_id_hex =
                stream_id.map(|value| normalize_hex(&value)).transpose()?;
            let (stream_id, crypto, policy_max_plaintext_frame_len) =
                stream_crypto_for_start_event(
                    runtime,
                    selected_account_id_hex,
                    None,
                    expected_stream_id_hex.as_deref(),
                    &start_event_id_hex,
                )
                .await?;
            let start_event_id = MessageId::new(hex::decode(normalize_hex(&start_event_id_hex)?)?);
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
                    crypto: Some(crypto),
                    max_plaintext_frame_len: policy_max_plaintext_frame_len,
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
                        "anchored": true,
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
                crypto: Some(crypto),
                max_plaintext_frame_len: policy_max_plaintext_frame_len,
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
                    "anchored": true,
                    "text_bytes": text.len(),
                    "transcript_hash": hex::encode(sent.transcript_hash),
                    "chunk_count": sent.chunk_count,
                }),
            })
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
            start_event_id,
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
                        start_event_id,
                        final_text_or_reference: text.join(" "),
                        transcript_hash,
                        chunk_count,
                        finished_at: unix_now_seconds(),
                    },
                )
                .await?;
            let agent_text_stream =
                agent_text_stream_payload_value(payload.kind, &payload.tags, &payload.content);
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
            let final_message = messages.into_iter().rev().find(|message| {
                marmot_app::is_stream_final_event(message.kind, &message.tags)
                    && tag_value(&message.tags, STREAM_TAG) == Some(stream_id_hex.as_str())
            });
            let (verified, final_message_json) = match final_message {
                Some(message) => {
                    let final_transcript_hash =
                        tag_value(&message.tags, STREAM_HASH_TAG).unwrap_or_default();
                    let final_chunk_count = tag_value(&message.tags, STREAM_CHUNKS_TAG)
                        .and_then(|count| count.parse::<u64>().ok())
                        .unwrap_or_default();
                    let transcript_hash_matches = final_transcript_hash == transcript_hash_hex;
                    let chunk_count_matches =
                        chunk_count.is_none_or(|count| count == final_chunk_count);
                    (
                        transcript_hash_matches && chunk_count_matches,
                        json!({
                            "message_id": message.message_id_hex,
                            "stream_id": stream_id_hex,
                            "transcript_hash": final_transcript_hash,
                            "chunk_count": final_chunk_count,
                            "final_text_or_reference": message.plaintext,
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
        StreamCommand::Receive { .. } => {
            unreachable!("local QUIC stream commands return before app setup")
        }
    }
}

pub(crate) async fn stream_watch_command_app_with_runtime<F>(
    account_home: &AccountHome,
    app: &MarmotApp,
    runtime: &MarmotAppRuntime,
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
            limit: Some(AGENT_STREAM_START_LOOKBACK_LIMIT),
        },
    )?;
    let (start_message_id_hex, start_payload, _start_sender_hex) =
        latest_stream_start(messages, expected_stream_id_hex.as_deref())?;
    if start_message_id_hex.is_empty() {
        return Err(DmError::StreamStartNotConfirmed);
    }
    if start_payload.route != "quic" {
        return Err(DmError::UnsupportedStreamRoute(
            stream_route_label(&start_payload.route).to_owned(),
        ));
    }
    let candidate = start_payload
        .quic_candidates
        .iter()
        .find(|candidate| candidate.trim().starts_with("quic://"))
        .ok_or(DmError::MissingQuicCandidate)?;
    let candidate = parse_quic_candidate(candidate)?;
    let candidate_addr = resolve_quic_candidate_addr(&candidate).await?;
    let trust = broker_trust(candidate_addr, server_cert_der_hex, insecure_local)?;
    let stream_id_hex = start_payload.stream_id_hex.clone();
    let start_event_id = MessageId::new(hex::decode(&start_message_id_hex)?);
    let (stream_id, crypto, policy_max_plaintext_frame_len) = stream_crypto_for_start_event(
        runtime,
        Some(&account.account_id_hex),
        Some(&group_id_hex),
        Some(&stream_id_hex),
        &start_message_id_hex,
    )
    .await?;
    let crypto = Some(crypto);
    let mut limits = AgentTextStreamReceiveLimits::default();
    if let Some(max_plaintext_frame_len) = policy_max_plaintext_frame_len {
        limits.max_plaintext_frame_len =
            max_plaintext_frame_len.min(limits.max_plaintext_frame_len);
    }
    let delta_account = account_flag.or(Some(account.account_id_hex.clone()));
    let delta_group_id = group_id_hex.clone();
    let delta_stream_id = stream_id_hex.clone();
    let received = subscribe_text_from_broker_with_limits(
        SubscribeTextFromBroker {
            broker_addr: candidate_addr,
            server_name: candidate.server_name.clone(),
            trust: trust.clone(),
            stream_id,
            start_event_id,
            crypto,
        },
        limits,
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
            "connect": candidate_addr.to_string(),
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
) -> Result<(String, StreamStartView, String), DmError> {
    let stream_id_hex = stream_id_hex.map(normalize_hex).transpose()?;
    messages
        .into_iter()
        .rev()
        .find_map(|message| {
            let start = StreamStartView::from_event(message.kind, &message.tags)?;
            let start_stream_id_hex = normalize_hex(&start.stream_id_hex).ok()?;
            if stream_id_hex
                .as_deref()
                .is_none_or(|stream_id| stream_id == start_stream_id_hex)
            {
                Some((message.message_id_hex, start, message.sender))
            } else {
                None
            }
        })
        .ok_or(DmError::MissingStreamStart)
}

pub(crate) async fn stream_crypto_for_start_event(
    runtime: &MarmotAppRuntime,
    resolved_account_id_hex: Option<&str>,
    group_id_hex: Option<&str>,
    stream_id_hex: Option<&str>,
    start_message_id_hex: &str,
) -> Result<
    (
        Vec<u8>,
        transport_quic_stream::AgentTextStreamCrypto,
        Option<u32>,
    ),
    DmError,
> {
    let context = runtime
        .agent_text_stream_crypto_for_start_event(
            resolved_account_id_hex,
            group_id_hex,
            stream_id_hex,
            start_message_id_hex,
        )
        .await
        .map_err(map_agent_stream_crypto_error)?;
    Ok((
        context.stream_id,
        context.crypto,
        context.policy_max_plaintext_frame_len,
    ))
}

fn map_agent_stream_crypto_error(err: AppError) -> DmError {
    match err {
        AppError::AgentStreamMissingStart => DmError::MissingStreamStart,
        AppError::AgentStreamStartNotConfirmed => DmError::StreamStartNotConfirmed,
        AppError::AgentStreamUnsupportedRoute => {
            DmError::UnsupportedStreamRoute("non-quic".to_owned())
        }
        AppError::AgentStreamMissingCandidate => DmError::MissingQuicCandidate,
        AppError::AgentStreamInvalidCandidate(candidate) => {
            DmError::InvalidQuicCandidate(candidate)
        }
        AppError::Hex(err) => DmError::Hex(err),
        other => DmError::App(other),
    }
}

struct ParsedQuicCandidate {
    original: String,
    authority: String,
    server_name: String,
}

/// Extract the `host:port` (or `[ipv6]:port`) authority from a `quic://` URL
/// remainder, ignoring any path, query, or fragment after it. Per
/// `transports/quic.md` the authority ends at the first `/`, `?`, or `#`. Shared
/// by both quic-candidate parsers below (and mirrors `marmot_app`'s
/// `parse_quic_candidate`) so the rule cannot drift.
fn quic_authority(rest: &str) -> &str {
    rest.split(['/', '?', '#']).next().unwrap_or(rest)
}

fn parse_quic_candidate(candidate: &str) -> Result<ParsedQuicCandidate, DmError> {
    let trimmed = candidate.trim();
    let Some(rest) = trimmed.strip_prefix("quic://") else {
        return Err(DmError::InvalidQuicCandidate(trimmed.to_owned()));
    };
    let authority = quic_authority(rest);
    if authority.is_empty() {
        return Err(DmError::InvalidQuicCandidate(trimmed.to_owned()));
    }
    let server_name = candidate_server_name(authority)?;
    Ok(ParsedQuicCandidate {
        original: trimmed.to_owned(),
        authority: authority.to_owned(),
        server_name,
    })
}

async fn resolve_quic_candidate_addr(
    candidate: &ParsedQuicCandidate,
) -> Result<SocketAddr, DmError> {
    let mut addrs = tokio::net::lookup_host(&candidate.authority)
        .await
        .map_err(|source| DmError::QuicCandidateResolve {
            candidate: candidate.original.clone(),
            source,
        })?;
    addrs
        .next()
        .ok_or_else(|| DmError::InvalidQuicCandidate(candidate.original.clone()))
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

pub(crate) fn first_quic_candidate_is_loopback(candidates: &[String]) -> bool {
    candidates
        .iter()
        .find(|candidate| candidate.trim().starts_with("quic://"))
        .and_then(|candidate| quic_candidate_host(candidate))
        .is_some_and(|host| quic_host_is_loopback(&host))
}

fn quic_candidate_host(candidate: &str) -> Option<String> {
    let rest = candidate.trim().strip_prefix("quic://")?;
    let authority = quic_authority(rest);
    if let Some(rest) = authority.strip_prefix('[') {
        return rest.split_once(']').map(|(host, _)| host.to_owned());
    }
    authority
        .rsplit_once(':')
        .map(|(host, _)| host.to_owned())
        .filter(|host| !host.is_empty())
}

fn quic_host_is_loopback(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
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

/// Render the `agent_text_stream` JSON view for a message's inner-event kind,
/// tags, and content, or `None` if the message is neither a kind-1200 start nor
/// a kind-9 stream-final. The shape stays stable for the TUI and daemon.
fn agent_text_stream_payload_value(
    kind: u64,
    tags: &[Vec<String>],
    content: &str,
) -> Option<Value> {
    if kind == MARMOT_APP_EVENT_KIND_AGENT_STREAM_START {
        let start = StreamStartView::from_event(kind, tags)?;
        return Some(json!({
            "kind": "start",
            "stream_id": start.stream_id_hex,
            "route": stream_route_label(&start.route),
            "quic_candidates": start.quic_candidates,
        }));
    }
    if marmot_app::is_stream_final_event(kind, tags) {
        return Some(json!({
            "kind": "final",
            "stream_id": tag_value(tags, STREAM_TAG).unwrap_or_default(),
            "start_event_id": tag_value(tags, STREAM_START_TAG).unwrap_or_default(),
            "final_text_or_reference": content,
            "transcript_hash": tag_value(tags, STREAM_HASH_TAG).unwrap_or_default(),
            "chunk_count": tag_value(tags, STREAM_CHUNKS_TAG)
                .and_then(|count| count.parse::<u64>().ok())
                .unwrap_or_default(),
        }));
    }
    None
}

/// Map the inner-event `route` tag value to the historical JSON route label.
fn stream_route_label(route: &str) -> &str {
    match route {
        "quic" => "brokered_quic",
        other => other,
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

async fn relay_stats_command(app: &MarmotApp) -> Result<CommandOutput, DmError> {
    relay_stats_output(app.relay_telemetry().await)
}

pub(crate) async fn relay_stats_command_with_runtime(
    runtime: &MarmotAppRuntime,
) -> Result<CommandOutput, DmError> {
    relay_stats_output(
        runtime
            .shared_services()
            .relay_plane()
            .relay_telemetry()
            .await,
    )
}

fn relay_stats_output(snapshot: RelayTelemetrySnapshot) -> Result<CommandOutput, DmError> {
    let json = serde_json::to_value(&snapshot)?;
    Ok(CommandOutput {
        plain: relay_stats_plain(&snapshot),
        json,
    })
}

/// Render a percentile of a duration histogram for the human view.
///
/// `n/a` when there are no samples; `>Nms` when the percentile falls in the
/// overflow region above the largest bucket bound.
fn relay_stats_percentile(hist: &DurationHistogramSnapshot, percentile: f64) -> String {
    if hist.sample_count() == 0 {
        return "n/a".to_owned();
    }
    match hist.approx_percentile_ms(percentile) {
        Some(ms) => format!("{ms}ms"),
        None => match hist.buckets.last() {
            Some(bucket) => format!(">{}ms", bucket.upper_bound_ms),
            None => "n/a".to_owned(),
        },
    }
}

fn relay_stats_plain(snapshot: &RelayTelemetrySnapshot) -> String {
    let metrics = &snapshot.metrics;
    let spread = &snapshot.delivery_spread;
    let sync = &snapshot.sync;
    let health = &snapshot.health;

    let mut lines = vec!["relay telemetry (device-local, aggregate, no relay URLs)".to_owned()];
    lines.push(format!(
        "accounts={} group_subscriptions={} created={} removed={}",
        metrics.active_accounts,
        metrics.active_group_subscriptions,
        metrics.subscriptions_created,
        metrics.subscriptions_removed,
    ));
    lines.push(format!(
        "inbound: seen={} delivered={} dropped={}",
        metrics.inbound_events_seen,
        metrics.inbound_events_delivered,
        metrics.inbound_events_dropped,
    ));
    lines.push(format!(
        "publish: attempts={} successes={} failures={}",
        metrics.publish_attempts, metrics.publish_successes, metrics.publish_failures,
    ));
    lines.push(format!(
        "delivery spread: observed={} corroborated={} single_source={} samples={} p50={} p99={}",
        spread.observed,
        spread.corroborated,
        spread.single_source,
        spread.spread.sample_count(),
        relay_stats_percentile(&spread.spread, 0.5),
        relay_stats_percentile(&spread.spread, 0.99),
    ));
    lines.push(format!(
        "sync: tracked_subscriptions={} synced={} first_event_p50={} eose_p50={}",
        sync.tracked_subscriptions,
        sync.synced_subscriptions,
        relay_stats_percentile(&sync.first_event, 0.5),
        relay_stats_percentile(&sync.eose, 0.5),
    ));

    let per_relay = relay_stats_per_relay_rows(spread, sync);
    if per_relay.is_empty() {
        lines.push("per-relay: none observed yet".to_owned());
    } else {
        lines.push("per-relay (opaque device-local index):".to_owned());
        lines.extend(per_relay);
    }

    lines.push(format!(
        "relay health: sdk_backed={} total={} connected={} connecting={} disconnected={} attempts={} successes={}",
        health.sdk_backed,
        health.total_relays,
        health.connected,
        health.connecting,
        health.disconnected,
        health.connection_attempts,
        health.connection_successes,
    ));
    lines.join("\n")
}

/// Join the per-relay delivery attribution and sync-timing rows by opaque relay
/// index into one line per relay.
fn relay_stats_per_relay_rows(
    spread: &RelayDeliverySpread,
    sync: &RelaySyncSnapshot,
) -> Vec<String> {
    let mut indices: Vec<u32> = spread
        .per_relay
        .iter()
        .map(|stats| stats.relay_index)
        .chain(sync.per_relay.iter().map(|stats| stats.relay_index))
        .collect();
    indices.sort_unstable();
    indices.dedup();

    indices
        .into_iter()
        .map(|index| {
            let delivery = spread
                .per_relay
                .iter()
                .find(|stats| stats.relay_index == index);
            let latency = sync
                .per_relay
                .iter()
                .find(|stats| stats.relay_index == index);
            relay_stats_per_relay_line(index, delivery, latency)
        })
        .collect()
}

fn relay_stats_per_relay_line(
    index: u32,
    delivery: Option<&RelayDeliveryStats>,
    latency: Option<&RelayLatencyStats>,
) -> String {
    let mut parts = vec![format!("  relay#{index}")];
    if let Some(delivery) = delivery {
        let rate = delivery
            .first_deliverer_rate()
            .map(|rate| format!("{:.0}%", rate * 100.0))
            .unwrap_or_else(|| "n/a".to_owned());
        parts.push(format!(
            "first_deliverer={rate} delivered_first={} delivered_later={}",
            delivery.delivered_first, delivery.delivered_later,
        ));
    }
    if let Some(latency) = latency {
        parts.push(format!(
            "first_event_p50={} eose_p50={}",
            relay_stats_percentile(&latency.first_event, 0.5),
            relay_stats_percentile(&latency.eose, 0.5),
        ));
    }
    parts.join(" ")
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
            let agent_text_stream = agent_text_stream_payload_value(
                message.kind,
                &message.tags,
                &message.plaintext,
            );
            let from_display_name = message
                .sender_display_name
                .clone()
                .or_else(|| display_name_for_sender(app, &message.sender));
            let mut value = json!({
                "message_id": message.message_id_hex,
                "direction": "received",
                "from": message.sender,
                "from_display_name": from_display_name,
                "group_id": hex::encode(message.group_id.as_slice()),
                "plaintext": message.plaintext,
                "kind": message.kind,
                "tags": message.tags,
            });
            if let Some(agent_text_stream) = agent_text_stream {
                value["agent_text_stream"] = agent_text_stream;
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
        "encrypted_media": group.encrypted_media,
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

fn validate_message_list_cursors(
    before: Option<u64>,
    before_message_id: Option<&str>,
    after: Option<u64>,
    after_message_id: Option<&str>,
) -> Result<(), DmError> {
    if before.is_some() != before_message_id.is_some() {
        return Err(DmError::MessagePaginationCursorMismatch {
            timestamp_flag: "--before",
            message_id_flag: "--before-message-id",
        });
    }
    if after.is_some() != after_message_id.is_some() {
        return Err(DmError::MessagePaginationCursorMismatch {
            timestamp_flag: "--after",
            message_id_flag: "--after-message-id",
        });
    }
    if before.is_some() && after.is_some() {
        return Err(DmError::MessagePaginationConflictingCursors);
    }
    Ok(())
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
    let mut display_names_by_sender: HashMap<String, Option<String>> = HashMap::new();
    messages
        .into_iter()
        .map(|message| {
            let from_display_name = display_names_by_sender
                .entry(message.sender.clone())
                .or_insert_with(|| display_name_for_sender(app, &message.sender))
                .clone();
            message_record_json(message, from_display_name)
        })
        .collect()
}

fn timeline_page_output(
    app: &MarmotApp,
    account_id_hex: &str,
    page: TimelinePage,
    query: Option<String>,
) -> CommandOutput {
    let plain = timeline_message_list_plain(&page.messages);
    let messages = timeline_message_list_json_with_profiles(app, page.messages);
    let mut json = json!({
        "account_id": account_id_hex,
        "npub": npub_for_account_id(account_id_hex),
        "messages": messages,
        "has_more_before": page.has_more_before,
        "has_more_after": page.has_more_after,
    });
    if let Some(query) = query {
        json["query"] = json!(query);
    }
    CommandOutput { plain, json }
}

fn timeline_message_list_plain(messages: &[TimelineMessageRecord]) -> String {
    if messages.is_empty() {
        return "no timeline messages".to_owned();
    }
    messages
        .iter()
        .map(|message| {
            let deleted = if message.deleted { " deleted=true" } else { "" };
            format!(
                "group={} from={}: {}{}",
                message.group_id_hex, message.sender, message.plaintext, deleted
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn timeline_message_list_json_with_profiles(
    app: &MarmotApp,
    messages: Vec<TimelineMessageRecord>,
) -> Vec<Value> {
    let mut display_names_by_sender: HashMap<String, Option<String>> = HashMap::new();
    messages
        .into_iter()
        .map(|message| {
            let from_display_name = display_names_by_sender
                .entry(message.sender.clone())
                .or_insert_with(|| display_name_for_sender(app, &message.sender))
                .clone();
            timeline_message_record_json(message, from_display_name)
        })
        .collect()
}

fn timeline_message_record_json(
    message: TimelineMessageRecord,
    from_display_name: Option<String>,
) -> Value {
    json!({
        "message_id": message.message_id_hex,
        "source_message_id": message.source_message_id_hex,
        "direction": message.direction,
        "group_id": message.group_id_hex,
        "from": message.sender,
        "from_display_name": from_display_name,
        "plaintext": message.plaintext,
        "kind": message.kind,
        "tags": message.tags,
        "timeline_at": message.timeline_at,
        "received_at": message.received_at,
        "reply_to_message_id": message.reply_to_message_id_hex,
        "reply_preview": message.reply_preview,
        "media": message.media,
        "agent_text_stream": message.agent_text_stream,
        "reactions": message.reactions,
        "deleted": message.deleted,
        "deleted_by_message_id": message.deleted_by_message_id_hex,
    })
}

fn message_record_json(message: AppMessageRecord, from_display_name: Option<String>) -> Value {
    let agent_text_stream =
        agent_text_stream_payload_value(message.kind, &message.tags, &message.plaintext);
    let mut value = json!({
        "message_id": message.message_id_hex,
        "direction": message.direction,
        "group_id": message.group_id_hex,
        "from": message.sender,
        "from_display_name": from_display_name,
        "plaintext": message.plaintext,
        "kind": message.kind,
        "tags": message.tags,
        "recorded_at": message.recorded_at,
        "received_at": message.received_at,
    });
    if let Some(agent_text_stream) = agent_text_stream {
        value["agent_text_stream"] = agent_text_stream;
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

fn media_records_json(messages: Vec<AppMessageRecord>) -> Result<Vec<Value>, DmError> {
    let mut records = Vec::new();
    for message in messages {
        let caption = (!message.plaintext.is_empty()).then(|| message.plaintext.clone());
        for (attachment_index, reference) in media_attachments_from_message(&message)?
            .into_iter()
            .enumerate()
        {
            records.push(json!({
                "message_id": message.message_id_hex,
                "attachment_index": attachment_index,
                "direction": message.direction,
                "group_id": message.group_id_hex,
                "from": message.sender,
                "media": media_attachment_json(&reference),
                "locators": media_locators_json(&reference.locators),
                "ciphertext_sha256": reference.ciphertext_sha256,
                "plaintext_sha256": reference.plaintext_sha256,
                "file_name": reference.file_name,
                "nonce_hex": reference.nonce_hex,
                "version": reference.version,
                "media_type": reference.media_type,
                "source_epoch": reference.source_epoch,
                "dim": reference.dim,
                "thumbhash": reference.thumbhash,
                "caption": caption,
                "recorded_at": message.recorded_at,
                "received_at": message.received_at,
            }));
        }
    }
    Ok(records)
}

fn media_upload_attachment_json(attachment: &marmot_app::MediaUploadAttachmentResult) -> Value {
    json!({
        "media": media_attachment_json(&attachment.reference),
        "encrypted_size_bytes": attachment.encrypted_size_bytes,
    })
}

fn media_attachment_json(reference: &MediaAttachmentReference) -> Value {
    json!({
        "locators": media_locators_json(&reference.locators),
        "ciphertext_sha256": reference.ciphertext_sha256,
        "plaintext_sha256": reference.plaintext_sha256,
        "file_name": reference.file_name,
        "nonce_hex": reference.nonce_hex,
        "version": reference.version,
        "media_type": reference.media_type,
        "source_epoch": reference.source_epoch,
        "dim": reference.dim,
        "thumbhash": reference.thumbhash,
    })
}

fn media_locators_json(locators: &[MediaLocator]) -> Vec<Value> {
    locators
        .iter()
        .map(|locator| {
            json!({
                "kind": locator.kind,
                "value": locator.value,
            })
        })
        .collect()
}

fn send_summary_json(summary: marmot_app::SendSummary) -> Value {
    json!({
        "published": summary.published,
        "message_ids": summary.message_ids,
    })
}

fn media_attachment_for_hash(
    messages: Vec<AppMessageRecord>,
    file_hash_hex: &str,
) -> Result<MediaAttachmentReference, DmError> {
    for message in messages {
        for reference in media_attachments_from_message(&message)? {
            if reference.plaintext_sha256 == file_hash_hex {
                return Ok(reference);
            }
        }
    }
    Err(DmError::MediaAttachmentNotFound(file_hash_hex.to_owned()))
}

fn media_attachments_from_message(
    message: &AppMessageRecord,
) -> Result<Vec<MediaAttachmentReference>, DmError> {
    message
        .tags
        .iter()
        .filter(|tag| tag.first().map(String::as_str) == Some("imeta"))
        .map(|tag| media_attachment_from_imeta_tag(tag, message.source_epoch))
        .collect()
}

fn media_attachment_from_imeta_tag(
    tag: &[String],
    source_epoch: Option<u64>,
) -> Result<MediaAttachmentReference, DmError> {
    let mut locators = Vec::new();
    let mut fields = HashMap::new();
    for field in tag.iter().skip(1) {
        if field.starts_with("blurhash ") {
            return Err(DmError::InvalidMediaAttachment("blurhash".to_owned()));
        }
        if let Some(rest) = field.strip_prefix("locator ") {
            let (kind, value) = rest
                .split_once(' ')
                .ok_or_else(|| DmError::InvalidMediaAttachment("locator".to_owned()))?;
            locators.push(MediaLocator {
                kind: kind.to_owned(),
                value: value.to_owned(),
            });
            continue;
        }
        if let Some((key, value)) = field.split_once(' ') {
            fields.insert(key.to_owned(), value.to_owned());
        }
    }
    let required = |key: &'static str| {
        fields
            .get(key)
            .cloned()
            .filter(|value| !value.trim().is_empty())
            .ok_or(DmError::InvalidMediaAttachment(key.to_owned()))
    };
    Ok(MediaAttachmentReference {
        locators,
        ciphertext_sha256: required("ciphertext_sha256")?,
        plaintext_sha256: required("plaintext_sha256")?,
        nonce_hex: required("nonce")?,
        file_name: required("filename")?,
        media_type: required("m")?,
        version: required("v")?,
        source_epoch: source_epoch
            .ok_or_else(|| DmError::InvalidMediaAttachment("source_epoch".to_owned()))?,
        dim: fields.get("dim").cloned(),
        thumbhash: fields.get("thumbhash").cloned(),
    })
}

fn normalize_sha256_hex(value: &str) -> Result<String, DmError> {
    let decoded = hex::decode(value)?;
    if decoded.len() != 32 {
        return Err(DmError::InvalidMediaAttachment(
            "file hash must be 32 bytes".to_owned(),
        ));
    }
    Ok(hex::encode(decoded))
}

fn media_file_name(path: &Path) -> Result<String, DmError> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| DmError::InvalidMediaAttachment("file name".to_owned()))
}

fn media_output_path(output: Option<String>, file_name: &str) -> PathBuf {
    output.map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(
            Path::new(file_name)
                .file_name()
                .and_then(|name| name.to_str())
                .filter(|name| !name.is_empty())
                .unwrap_or("media.bin"),
        )
    })
}

fn guess_media_type(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| extension.to_ascii_lowercase())
        .as_deref()
    {
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("png") => "image/png",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("heic") => "image/heic",
        Some("mp4") => "video/mp4",
        Some("mov") => "video/quicktime",
        Some("mp3") => "audio/mpeg",
        Some("m4a") => "audio/mp4",
        Some("wav") => "audio/wav",
        Some("ogg") => "audio/ogg",
        Some("txt") => "text/plain",
        Some("pdf") => "application/pdf",
        _ => "application/octet-stream",
    }
}

fn key_package_fetch_json(fetched: FetchedKeyPackage) -> Value {
    json!({
        "account_id": fetched.account_id_hex,
        "key_package_id": fetched.key_package_id,
        "key_package_ref": fetched.key_package_ref_hex,
        "key_package_bytes": fetched.key_package.bytes().len(),
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

fn resolve_selected_account(
    account_home: &AccountHome,
    explicit: Option<String>,
) -> Result<Option<marmot_account::AccountSummary>, DmError> {
    let Some(account) = explicit
        .or_else(|| std::env::var("DM_ACCOUNT").ok())
        .filter(|account| !account.trim().is_empty())
    else {
        return Ok(None);
    };
    Ok(Some(resolve_account_ref(account_home, &account)?))
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
    })
}

fn app_for(home: PathBuf, relay: Option<String>, account_home: AccountHome) -> MarmotApp {
    // Loopback-HTTP blob endpoints are only acted on when explicitly enabled for
    // dev/test (see MarmotAppConfig::allow_loopback_blob_endpoints). Opt in via
    // DM_ALLOW_LOOPBACK_BLOB_ENDPOINTS=1 for local Blossom servers; production
    // installs leave it unset.
    let mut config = MarmotAppConfig::default()
        .with_allow_loopback_blob_endpoints(dm_allow_loopback_blob_endpoints());
    // Dev/test only: DM_DEV_SETTLEMENT_QUIESCENCE_MS overrides the pinned
    // convergence settlement window (e.g. `0` for instant settlement in
    // integration tests). Production installs leave it unset and use the pinned
    // default.
    if let Some(ms) = dm_dev_settlement_quiescence_ms() {
        config = config.with_dev_settlement_quiescence_ms(ms);
    }
    MarmotApp::with_relays_and_account_home_and_config(
        home,
        relay.into_iter().collect(),
        account_home,
        config,
    )
}

fn dm_allow_loopback_blob_endpoints() -> bool {
    matches!(
        std::env::var("DM_ALLOW_LOOPBACK_BLOB_ENDPOINTS").as_deref(),
        Ok("1") | Ok("true")
    )
}

fn dm_dev_settlement_quiescence_ms() -> Option<u64> {
    std::env::var("DM_DEV_SETTLEMENT_QUIESCENCE_MS")
        .ok()
        .and_then(|value| value.trim().parse().ok())
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
        DmError::ReplaceableListInconclusive {
            list,
            account_id,
            source_relays,
        } => json!({
            "code": "replaceable_list_inconclusive",
            "message": err.to_string(),
            "list": list,
            "account_id": account_id,
            "source_relays": source_relays,
            "repair": {
                "retry_with_relay": "--relay <relay-that-has-the-current-list>",
            },
        }),
        DmError::MessagePaginationCursorMismatch {
            timestamp_flag,
            message_id_flag,
        } => json!({
            "code": "message_pagination_cursor_mismatch",
            "message": err.to_string(),
            "timestamp_flag": timestamp_flag,
            "message_id_flag": message_id_flag,
            "repair": {
                "supply_both": format!("pass {timestamp_flag} and {message_id_flag} together"),
            },
        }),
        DmError::MessagePaginationConflictingCursors => json!({
            "code": "message_pagination_conflicting_cursors",
            "message": err.to_string(),
        }),
        DmError::EmptyProfileUpdate => json!({
            "code": "empty_profile_update",
            "message": err.to_string(),
        }),
        DmError::ProfileUpdateInconclusive {
            account_id,
            source_relays,
        } => json!({
            "code": "profile_update_inconclusive",
            "message": err.to_string(),
            "account_id": account_id,
            "source_relays": source_relays,
            "repair": {
                "retry_with_relay": "--relay <relay-that-has-the-current-profile>",
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
        DmError::StreamStartNotConfirmed => json!({
            "code": "stream_start_not_confirmed",
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
                "login": "dm login <npub-or-hex>",
                "import_nsec": "printf '%s\\n' \"$NSEC\" | dm login --nsec-stdin",
            },
        }),
        DmError::SecretArgumentRejected { command } => json!({
            "code": "secret_argument_rejected",
            "message": err.to_string(),
            "command": command,
            "repair": {
                "login": "printf '%s\\n' \"$NSEC\" | dm login --nsec-stdin",
                "account_create": "printf '%s\\n' \"$NSEC\" | dm account create --nsec-stdin",
            },
        }),
        DmError::ConflictingSecretInput { command } => json!({
            "code": "conflicting_secret_input",
            "message": err.to_string(),
            "command": command,
        }),
        DmError::MissingStdinSecret { command } => json!({
            "code": "missing_stdin_secret",
            "message": err.to_string(),
            "command": command,
        }),
        DmError::InvalidStdinSecret { command } => json!({
            "code": "invalid_stdin_secret",
            "message": err.to_string(),
            "command": command,
        }),
        DmError::MediaAttachmentNotFound(file_hash) => json!({
            "code": "media_attachment_not_found",
            "message": err.to_string(),
            "plaintext_sha256": file_hash,
        }),
        DmError::InvalidMediaAttachment(reason) => json!({
            "code": "invalid_media_attachment",
            "message": err.to_string(),
            "reason": reason,
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
                "login": "printf '%s\\n' \"$NSEC\" | dm login --nsec-stdin --relay <ws-or-wss-url>",
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
                "create": "dm account create [npub-or-hex]",
                "import_nsec": "printf '%s\\n' \"$NSEC\" | dm account create --nsec-stdin",
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
        AccountHomeError::AccountIdInUse(account_id) => json!({
            "code": "account_id_in_use",
            "message": err.to_string(),
            "account_id_hex": account_id,
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
    use std::path::Path;
    use std::path::PathBuf;

    use super::{
        AppMessageRecord, Cli, Command, DmError, GlobalRelayDefaults, StreamCommand,
        apply_global_relay_defaults, apply_message_cursors, daemon_socket_for_client,
        default_home_from_env, first_quic_candidate_is_loopback, parse_quic_candidate,
        quic_candidate_host, relay_endpoints, relay_stats_output, relay_stats_plain, resolve_relay,
        validate_message_list_cursors,
    };
    use marmot_app::{
        DurationHistogramSnapshot, HistogramBucket, NostrAdapterMetrics, RelayDeliverySpread,
        RelayDeliveryStats, RelayLatencyStats, RelayPlaneHealth, RelaySyncSnapshot,
        RelayTelemetrySnapshot,
    };

    fn one_sample_histogram(upper_bound_ms: u64) -> DurationHistogramSnapshot {
        DurationHistogramSnapshot {
            buckets: vec![HistogramBucket {
                upper_bound_ms,
                count: 1,
            }],
            overflow_count: 0,
        }
    }

    fn sample_relay_telemetry() -> RelayTelemetrySnapshot {
        RelayTelemetrySnapshot {
            metrics: NostrAdapterMetrics {
                active_accounts: 1,
                active_group_subscriptions: 2,
                inbound_events_seen: 9,
                inbound_events_delivered: 7,
                inbound_events_dropped: 2,
                publish_attempts: 3,
                publish_successes: 3,
                ..NostrAdapterMetrics::default()
            },
            delivery_spread: RelayDeliverySpread {
                observed: 5,
                corroborated: 4,
                single_source: 1,
                spread: one_sample_histogram(50),
                per_relay: vec![RelayDeliveryStats {
                    relay_index: 0,
                    delivered_first: 3,
                    delivered_later: 1,
                }],
            },
            sync: RelaySyncSnapshot {
                tracked_subscriptions: 2,
                synced_subscriptions: 1,
                first_event: one_sample_histogram(20),
                eose: one_sample_histogram(100),
                per_relay: vec![RelayLatencyStats {
                    relay_index: 0,
                    first_event: one_sample_histogram(20),
                    eose: one_sample_histogram(100),
                }],
            },
            health: RelayPlaneHealth {
                sdk_backed: true,
                total_relays: 1,
                connected: 1,
                connection_attempts: 1,
                connection_successes: 1,
                ..RelayPlaneHealth::default()
            },
        }
    }

    fn test_cli(command: Command) -> Cli {
        Cli {
            home: None,
            socket: Some(PathBuf::from("/tmp/dmd.sock")),
            relay: None,
            daemon_discovery_relays: Vec::new(),
            daemon_default_account_relays: Vec::new(),
            secret_store: None,
            keychain_service: None,
            account: None,
            json: true,
            command,
        }
    }

    fn loopback_stream_addr() -> std::net::SocketAddr {
        "127.0.0.1:4450".parse().expect("loopback address")
    }

    #[test]
    fn daemon_execute_socket_skips_stream_commands_that_must_run_in_client() {
        let home = Path::new("/tmp/dm-home");
        let commands = [
            StreamCommand::Receive {
                bind: loopback_stream_addr(),
                start_event_id: None,
            },
            StreamCommand::Send {
                broker: false,
                connect: loopback_stream_addr(),
                server_name: "localhost".to_owned(),
                server_cert_der_hex: None,
                insecure_local: true,
                stream_id: None,
                start_event_id: None,
                chunk_bytes: 1024,
                chunk_delay_ms: 0,
                text: vec!["hello".to_owned()],
            },
            StreamCommand::Watch {
                group: "aa".repeat(32),
                stream_id: None,
                server_cert_der_hex: None,
                insecure_local: true,
                background: false,
            },
        ];

        for command in commands {
            let cli = test_cli(Command::Stream { command });
            assert_eq!(daemon_socket_for_client(&cli, home), None);
        }
    }

    #[test]
    fn daemon_execute_socket_keeps_finite_stream_commands() {
        let home = Path::new("/tmp/dm-home");
        let socket = Path::new("/tmp/dmd.sock");
        let commands = [
            StreamCommand::Start {
                group: "aa".repeat(32),
                stream_id: None,
                quic_candidates: vec!["quic://127.0.0.1:4450".to_owned()],
            },
            StreamCommand::Send {
                broker: false,
                connect: loopback_stream_addr(),
                server_name: "localhost".to_owned(),
                server_cert_der_hex: None,
                insecure_local: true,
                stream_id: None,
                start_event_id: Some("bb".repeat(32)),
                chunk_bytes: 1024,
                chunk_delay_ms: 0,
                text: vec!["hello".to_owned()],
            },
            StreamCommand::Finish {
                group: "aa".repeat(32),
                stream_id: "cc".repeat(32),
                start_event_id: "bb".repeat(32),
                transcript_hash: "dd".repeat(32),
                chunk_count: 1,
                text: vec!["hello".to_owned()],
            },
        ];

        for command in commands {
            let cli = test_cli(Command::Stream { command });
            assert_eq!(
                daemon_socket_for_client(&cli, home).as_deref(),
                Some(socket)
            );
        }
    }

    #[test]
    fn relay_stats_plain_reports_aggregates_with_opaque_relay_indices() {
        let plain = relay_stats_plain(&sample_relay_telemetry());
        assert!(plain.contains("inbound: seen=9 delivered=7 dropped=2"));
        assert!(plain.contains("delivery spread: observed=5 corroborated=4"));
        // Per-relay rows use the opaque index and never a relay URL.
        assert!(plain.contains("relay#0"));
        assert!(plain.contains("first_deliverer=75%"));
        assert!(plain.contains("eose_p50=100ms"));
        assert!(
            !plain.contains("wss://") && !plain.contains("ws://"),
            "local relay stats must not surface relay URLs: {plain}"
        );
    }

    #[test]
    fn relay_stats_output_json_preserves_snapshot_shape() {
        let output = relay_stats_output(sample_relay_telemetry()).expect("snapshot serializes");
        assert_eq!(output.json["metrics"]["inbound_events_delivered"], 7);
        assert_eq!(
            output.json["delivery_spread"]["per_relay"][0]["relay_index"],
            0
        );
        assert_eq!(output.json["sync"]["synced_subscriptions"], 1);
        assert_eq!(output.json["health"]["connected"], 1);
    }

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
    fn first_quic_candidate_loopback_detection_is_literal_and_localhost_only() {
        assert!(first_quic_candidate_is_loopback(&[
            "quic://127.0.0.1:4450".to_owned()
        ]));
        assert!(first_quic_candidate_is_loopback(&[
            "quic://[::1]:4450".to_owned()
        ]));
        assert!(first_quic_candidate_is_loopback(&[
            "quic://localhost:4450".to_owned()
        ]));
        assert!(!first_quic_candidate_is_loopback(&[
            "quic://quic-broker.ipf.dev:4450".to_owned()
        ]));
    }

    #[test]
    fn parse_quic_candidate_ignores_path_query_and_fragment() {
        // The authority ends at the first `/`, `?`, or `#` (transports/quic.md);
        // a path/query/fragment after it MUST be ignored, not folded into the
        // host:port (which would break server_name + host resolution). Mirrors
        // the marmot-app `parse_quic_candidate` fix (#230).
        for candidate in [
            "quic://broker.example:4450/path",
            "quic://broker.example:4450?x=1",
            "quic://broker.example:4450#frag",
            "quic://broker.example:4450/p?x=1#frag",
        ] {
            let parsed = parse_quic_candidate(candidate).expect("candidate parses");
            assert_eq!(
                parsed.authority, "broker.example:4450",
                "authority must stop at the first /?#: {candidate}"
            );
            assert_eq!(
                quic_candidate_host(candidate),
                Some("broker.example".to_owned())
            );
        }
        let parsed =
            parse_quic_candidate("quic://[2001:db8::1]:4450?x=1").expect("ipv6 candidate parses");
        assert_eq!(parsed.authority, "[2001:db8::1]:4450");
        assert_eq!(
            quic_candidate_host("quic://[2001:db8::1]:4450#frag"),
            Some("2001:db8::1".to_owned())
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
                kind: cgka_traits::app_event::MARMOT_APP_EVENT_KIND_CHAT,
                tags: Vec::new(),
                source_epoch: None,
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

    #[test]
    fn message_list_cursors_accept_valid_compound_and_no_cursor() {
        assert!(validate_message_list_cursors(None, None, None, None).is_ok());
        assert!(validate_message_list_cursors(Some(101), Some("d"), None, None).is_ok());
        assert!(validate_message_list_cursors(None, None, Some(100), Some("a")).is_ok());
    }

    #[test]
    fn message_list_cursors_reject_lone_before_message_id() {
        let err = validate_message_list_cursors(None, Some("d"), None, None)
            .expect_err("lone --before-message-id must be rejected");
        assert!(matches!(
            err,
            DmError::MessagePaginationCursorMismatch {
                timestamp_flag: "--before",
                message_id_flag: "--before-message-id",
            }
        ));
    }

    #[test]
    fn message_list_cursors_reject_lone_after_message_id() {
        let err = validate_message_list_cursors(None, None, None, Some("a"))
            .expect_err("lone --after-message-id must be rejected");
        assert!(matches!(
            err,
            DmError::MessagePaginationCursorMismatch {
                timestamp_flag: "--after",
                message_id_flag: "--after-message-id",
            }
        ));
    }

    #[test]
    fn message_list_cursors_reject_lone_before_timestamp() {
        let err = validate_message_list_cursors(Some(101), None, None, None)
            .expect_err("lone --before timestamp must be rejected");
        assert!(matches!(
            err,
            DmError::MessagePaginationCursorMismatch {
                timestamp_flag: "--before",
                message_id_flag: "--before-message-id",
            }
        ));
    }

    #[test]
    fn message_list_cursors_reject_before_and_after_together() {
        let err = validate_message_list_cursors(Some(101), Some("d"), Some(100), Some("a"))
            .expect_err("before and after cursors cannot be combined");
        assert!(matches!(err, DmError::MessagePaginationConflictingCursors));
    }

    // Regression for #190: an oversized request on the *implicit* daemon socket
    // path (default socket merely exists, no `--socket`/`DM_SOCKET`) must surface
    // the client-side size-limit error instead of silently falling through to
    // local execution. Without the terminal `RequestTooLarge` arm in `run_from`,
    // the encoder rejects the request and the request silently runs locally,
    // masking the cap.
    #[tokio::test]
    async fn run_from_oversized_request_on_implicit_socket_fails_locally() {
        // DM_SOCKET would force the explicit-socket branch and invalidate the
        // implicit-path assertion; only run the check when it is unset.
        if std::env::var_os("DM_SOCKET").is_some() {
            return;
        }

        let home = tempfile::tempdir().expect("temp home");
        // Materialize the default socket path so `daemon_socket_for_client`
        // takes the implicit-socket branch without us passing `--socket`.
        let socket = crate::daemon::default_socket_path(home.path());
        std::fs::create_dir_all(socket.parent().expect("socket parent"))
            .expect("create socket dir");
        std::fs::File::create(&socket).expect("create placeholder socket file");

        // A message body over the 1 MiB request cap; the encoder rejects this
        // before any connection attempt.
        let huge_text = "a".repeat(2 * 1024 * 1024);
        let args: Vec<OsString> = vec![
            OsString::from("dm"),
            OsString::from("--json"),
            OsString::from("--home"),
            home.path().as_os_str().to_owned(),
            OsString::from("messages"),
            OsString::from("send"),
            OsString::from("group-1"),
            OsString::from(huge_text),
        ];

        let output = super::run_from(args).await;

        assert_eq!(output.code, 1, "oversized request must fail");
        assert!(
            output.stdout.contains("byte limit"),
            "expected a client-side size-limit error, got stdout: {}",
            output.stdout
        );
    }
}
