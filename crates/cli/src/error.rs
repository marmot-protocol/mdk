//! CLI error type and its `--json` error-rendering functions.

use cgka_traits::error::EngineError;
use marmot_account::AccountHomeError;
use marmot_app::{
    AccountError, AccountRelayListStatus, AppError, DirectoryError, MissingKeyPackageReason,
    MissingRelayListKind,
};
use serde_json::{Value, json};

use crate::relay_lists_json;

#[derive(thiserror::Error)]
#[error("sync failed")]
pub(crate) struct SyncCommandError {
    #[source]
    pub(crate) source: AppError,
    pub(crate) partial_plain: String,
    pub(crate) partial_json: Value,
}

impl std::fmt::Debug for SyncCommandError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SyncCommandError")
            .field("source", &self.source)
            .field("partial", &"redacted")
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum WnError {
    #[error(transparent)]
    AccountHome(#[from] AccountHomeError),
    #[error(transparent)]
    App(#[from] AppError),
    #[error(transparent)]
    Sync(Box<SyncCommandError>),
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
    #[error("--reply-to must come before the message text; it was read as literal text here")]
    ReplyToAfterMessageText,
    #[error("custom event kind {0} is reserved for Marmot protocol use")]
    ReservedAppEventKind(u64),
    #[error("invalid --tag value (expected a JSON array of strings): {0}")]
    InvalidEventTag(String),
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
    #[error("multiple accounts exist; pass --account or set WN_ACCOUNT")]
    MultipleAccounts,
    #[error("account not found: {0}")]
    UnknownLocalAccount(String),
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("public Nostr accounts do not have signing keys")]
    PublicAccountCannotSign,
    #[error("invalid secret store: {0}")]
    InvalidSecretStore(String),
    #[error(
        "WN_DEV_SETTLEMENT_QUIESCENCE_MS requires a test-policy-overrides build; unset it in normal binaries"
    )]
    DevSettlementOverrideInRelease,
    #[error(
        "devices requires a running wnd with device groups and relay defaults; start it with `wn daemon start --discovery-relays <urls> --default-account-relays <urls>` with `WN_DEVICE_GROUPS` unset (0, false, off or no turns device groups off)"
    )]
    DevicesRequireDaemon,
    #[error("messages subscribe requires the daemon; start it with `wn daemon start`")]
    MessagesSubscribeRequiresDaemon,
    #[error("chats subscribe requires the daemon; start it with `wn daemon start`")]
    ChatsSubscribeRequiresDaemon,
    #[error("notifications subscribe requires the daemon; start it with `wn daemon start`")]
    NotificationsSubscribeRequiresDaemon,
    #[error("login requires --nsec-stdin, --bunker-stdin, --nostrconnect, or an npub identity")]
    MissingLoginIdentity,
    #[error(
        "{command} does not accept private keys as command-line arguments; pipe the nsec to --nsec-stdin"
    )]
    SecretArgumentRejected { command: &'static str },
    #[error(
        "{command} does not accept NIP-46 URIs as command-line arguments; pipe the bunker:// URI to --bunker-stdin or use --nostrconnect"
    )]
    BunkerArgumentRejected { command: &'static str },
    #[error("{command} expects either a public identity argument or --nsec-stdin, not both")]
    ConflictingSecretInput { command: &'static str },
    #[error("{command} cannot combine multiple login/pairing modes")]
    ConflictingLoginInput { command: &'static str },
    #[error("{command} --nsec-stdin received empty input")]
    MissingStdinSecret { command: &'static str },
    #[error("{command} --nsec-stdin requires an nsec secret key")]
    InvalidStdinSecret { command: &'static str },
    #[error("{command} --bunker-stdin received empty input")]
    MissingBunkerStdin { command: &'static str },
    #[error("{command} --bunker-stdin requires a bunker:// URI")]
    InvalidBunkerStdin { command: &'static str },
    #[error("{command} requires either --bunker-stdin or --nostrconnect")]
    MissingNip46Mode { command: &'static str },
    #[error(
        "NIP-46 --nostrconnect pairing requires at least one signer relay (--signer-relays or default relay)"
    )]
    MissingNip46SignerRelays,
    #[error(
        "NIP-46 permissions (version {version}) require explicit approval; confirm interactively or pass --approve-permissions"
    )]
    Nip46PermissionApprovalRequired { version: u32, grants: Vec<String> },
    #[error("account {0} is not an external-signing account")]
    Nip46RequiresExternalAccount(String),
    #[error("no media attachment found for plaintext hash {0}")]
    MediaAttachmentNotFound(String),
    #[error("invalid media attachment: {0}")]
    InvalidMediaAttachment(String),
    #[error("invalid mute duration: {0}")]
    InvalidMuteDuration(String),
    #[error("invalid retention duration: {0}")]
    InvalidRetentionDuration(String),
    #[error("message {0} is not in the local projection for this group")]
    UnknownMessage(String),
    #[error("message {message_id} was not authored by the selected account")]
    NotMessageAuthor { message_id: String },
    #[error("group image file is empty; use clear-image to remove the current image")]
    EmptyGroupImage,
    #[error("group {0} has no encrypted group image")]
    GroupImageAbsent(String),
    #[error("rejoin token must be 32 bytes of hex copied from recovery-status")]
    InvalidRejoinToken,
    #[error("welcome id must be non-empty hex")]
    InvalidWelcomeId,
    #[error("initial admin {0} is not one of the invited members")]
    InitialAdminNotInvited(String),
    #[error("exporting private keys is disabled by White Noise CLI policy")]
    PrivateKeyExportDisabled,
    #[error("{command} requires {flag}: {reason}")]
    ConfirmationRequired {
        command: &'static str,
        flag: &'static str,
        reason: &'static str,
    },
    #[error("invalid relay type: {0}")]
    InvalidRelayType(String),
    #[error("missing account relay lists: {0:?}")]
    MissingRelayLists(Vec<MissingRelayListKind>, Box<AccountRelayListStatus>),
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
    #[error("user search did not complete: {0}")]
    UserSearch(String),
}

/// Directory failures render as the `AppError` they convert to, so `--json`
/// codes stay the same whichever layer reported them.
impl From<DirectoryError> for WnError {
    fn from(error: DirectoryError) -> Self {
        Self::App(error.into())
    }
}

pub(crate) fn wn_error_json(err: &WnError) -> Value {
    match err {
        WnError::MissingRelayLists(missing, status) => json!({
            "code": "missing_relay_lists",
            "message": "account is missing required relay lists",
            "missing": missing.iter().map(|k| k.token()).collect::<Vec<_>>(),
            "relay_lists": relay_lists_json(status.as_ref().clone()),
            "repair": {
                "requires": "--default-relays",
                "publish_missing": "--publish-missing-relay-lists",
            },
        }),
        WnError::ReplaceableListInconclusive {
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
        WnError::MessagePaginationCursorMismatch {
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
        WnError::MessagePaginationConflictingCursors => json!({
            "code": "message_pagination_conflicting_cursors",
            "message": err.to_string(),
        }),
        WnError::EmptyProfileUpdate => json!({
            "code": "empty_profile_update",
            "message": err.to_string(),
        }),
        WnError::ProfileUpdateInconclusive {
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
        WnError::UserSearch(_) => json!({
            "code": "user_search_failed",
            "message": err.to_string(),
        }),
        WnError::AccountHome(err) => account_home_error_json(err),
        WnError::App(err) => app_error_json(err),
        WnError::Sync(sync) => {
            // Preserve the source AppError's established top-level code and
            // repair metadata for existing CLI consumers. Partial progress is
            // additive; it must not force scripts to unwrap a new `cause` layer.
            let mut value = app_error_json(&sync.source);
            if let Some(object) = value.as_object_mut() {
                object.insert("partial".to_owned(), sync.partial_json.clone());
            }
            value
        }
        WnError::Hex(err) => json!({
            "code": "invalid_hex",
            "message": err.to_string(),
        }),
        WnError::Io(err) => json!({
            "code": "io_error",
            "message": err.to_string(),
        }),
        WnError::Json(err) => json!({
            "code": "json_error",
            "message": err.to_string(),
        }),
        WnError::EmptyMessage => json!({
            "code": "empty_message",
            "message": err.to_string(),
        }),
        WnError::ReservedAppEventKind(kind) => json!({
            "code": "reserved_app_event_kind",
            "message": err.to_string(),
            "kind": kind,
        }),
        WnError::InvalidEventTag(_) => json!({
            "code": "invalid_event_tag",
            "message": err.to_string(),
        }),
        WnError::DevicesRequireDaemon => json!({
            "code": "daemon_required",
            "message": err.to_string(),
            "repair": {"start": "wn daemon start --discovery-relays <urls> --default-account-relays <urls>", "env": "unset WN_DEVICE_GROUPS, or set it to a value other than 0, false, off or no"},
        }),
        WnError::MessagesSubscribeRequiresDaemon => json!({
            "code": "daemon_required",
            "message": err.to_string(),
            "repair": {
                "start": "wn daemon start",
            },
        }),
        WnError::ChatsSubscribeRequiresDaemon => json!({
            "code": "daemon_required",
            "message": err.to_string(),
            "repair": {
                "start": "wn daemon start",
            },
        }),
        WnError::NotificationsSubscribeRequiresDaemon => json!({
            "code": "daemon_required",
            "message": err.to_string(),
            "repair": {
                "start": "wn daemon start",
            },
        }),
        WnError::MissingLoginIdentity => json!({
            "code": "missing_login_identity",
            "message": err.to_string(),
            "repair": {
                "login": "wn login <npub-or-hex>",
                "import_nsec": "printf '%s\\n' \"$NSEC\" | wn login --nsec-stdin",
                "nip46_bunker": "printf '%s\\n' \"$BUNKER_URI\" | wn login --bunker-stdin --approve-permissions",
                "nip46_nostrconnect": "wn login --nostrconnect --signer-relays <relay-url>",
            },
        }),
        WnError::SecretArgumentRejected { command } => json!({
            "code": "secret_argument_rejected",
            "message": err.to_string(),
            "command": command,
            "repair": {
                "login": "printf '%s\\n' \"$NSEC\" | wn login --nsec-stdin",
                "account_create": "printf '%s\\n' \"$NSEC\" | wn account create --nsec-stdin",
            },
        }),
        WnError::BunkerArgumentRejected { command } => json!({
            "code": "secret_argument_rejected",
            "message": err.to_string(),
            "command": command,
            "repair": {
                "login": "printf '%s\\n' \"$BUNKER_URI\" | wn login --bunker-stdin --approve-permissions",
                "nostrconnect": "wn login --nostrconnect --signer-relays <relay-url>",
            },
        }),
        WnError::ConflictingSecretInput { command } => json!({
            "code": "conflicting_secret_input",
            "message": err.to_string(),
            "command": command,
        }),
        WnError::ConflictingLoginInput { command } => json!({
            "code": "conflicting_login_input",
            "message": err.to_string(),
            "command": command,
        }),
        WnError::MissingStdinSecret { command } => json!({
            "code": "missing_stdin_secret",
            "message": err.to_string(),
            "command": command,
        }),
        WnError::InvalidStdinSecret { command } => json!({
            "code": "invalid_stdin_secret",
            "message": err.to_string(),
            "command": command,
        }),
        WnError::MissingBunkerStdin { command } => json!({
            "code": "missing_stdin_bunker_uri",
            "message": err.to_string(),
            "command": command,
        }),
        WnError::InvalidBunkerStdin { command } => json!({
            "code": "invalid_stdin_bunker_uri",
            "message": err.to_string(),
            "command": command,
        }),
        WnError::MissingNip46Mode { command } => json!({
            "code": "missing_nip46_mode",
            "message": err.to_string(),
            "command": command,
            "repair": {
                "bunker": "printf '%s\\n' \"$BUNKER_URI\" | wn accounts nip46 login --bunker-stdin --approve-permissions",
                "nostrconnect": "wn accounts nip46 login --nostrconnect --signer-relays <relay-url>",
            },
        }),
        WnError::MissingNip46SignerRelays => json!({
            "code": "missing_nip46_signer_relays",
            "message": err.to_string(),
            "repair": {
                "flag": "--signer-relays <ws-or-wss-url>",
            },
        }),
        WnError::Nip46PermissionApprovalRequired { version, grants } => json!({
            "code": "nip46_permission_approval_required",
            "message": err.to_string(),
            "version": version,
            "grants": grants,
            "repair": {
                "flag": "--approve-permissions",
            },
        }),
        WnError::Nip46RequiresExternalAccount(account_id) => json!({
            "code": "nip46_requires_external_account",
            "message": err.to_string(),
            "account_id": account_id,
        }),
        WnError::MediaAttachmentNotFound(file_hash) => json!({
            "code": "media_attachment_not_found",
            "message": err.to_string(),
            "plaintext_sha256": file_hash,
        }),
        WnError::InvalidMediaAttachment(reason) => json!({
            "code": "invalid_media_attachment",
            "message": err.to_string(),
            "reason": reason,
        }),
        WnError::InvalidRetentionDuration(duration) => json!({
            "code": "invalid_retention_duration",
            "message": err.to_string(),
            "duration": duration,
            "repair": {
                "format": "seconds, or a number with s/m/h/d/w suffix; 0 or off disables",
            },
        }),
        WnError::UnknownMessage(message_id) => json!({
            "code": "unknown_message",
            "message": err.to_string(),
            "target_message_id": message_id,
            "repair": {
                "action": "sync the group and pass a message id from `messages list`",
            },
        }),
        WnError::NotMessageAuthor { message_id } => json!({
            "code": "not_message_author",
            "message": err.to_string(),
            "target_message_id": message_id,
        }),
        WnError::EmptyGroupImage => json!({
            "code": "empty_group_image",
            "message": err.to_string(),
            "repair": {
                "clear": "wn groups clear-image <group-hex>",
            },
        }),
        WnError::GroupImageAbsent(group_id) => json!({
            "code": "group_image_absent",
            "message": err.to_string(),
            "group_id": group_id,
        }),
        WnError::InvalidRejoinToken => json!({
            "code": "invalid_rejoin_token",
            "message": err.to_string(),
            "repair": {
                "source": "wn groups recovery-status <group-hex>",
            },
        }),
        WnError::InvalidWelcomeId => json!({
            "code": "invalid_welcome_id",
            "message": err.to_string(),
        }),
        WnError::InitialAdminNotInvited(member) => json!({
            "code": "initial_admin_not_invited",
            "message": err.to_string(),
            "member": member,
        }),
        WnError::InvalidMuteDuration(duration) => json!({
            "code": "invalid_mute_duration",
            "message": err.to_string(),
            "duration": duration,
            "repair": {
                "examples": ["15m", "1h", "8h", "1d", "1w", "forever"],
            },
        }),
        WnError::PrivateKeyExportDisabled => json!({
            "code": "private_key_export_disabled",
            "message": err.to_string(),
            "repair": {
                "import_nsec": "printf '%s\\n' \"$NSEC\" | wn login --nsec-stdin",
            },
        }),
        WnError::ConfirmationRequired {
            command,
            flag,
            reason,
        } => json!({
            "code": "confirmation_required",
            "message": err.to_string(),
            "command": command,
            "flag": flag,
            "reason": reason,
        }),
        WnError::InvalidRelayType(relay_type) => json!({
            "code": "invalid_relay_type",
            "message": err.to_string(),
            "relay_type": relay_type,
            "allowed": ["nip65", "inbox"],
        }),
        WnError::MissingGroupId => json!({
            "code": "missing_group_id",
            "message": err.to_string(),
        }),
        WnError::ReplyToAfterMessageText => json!({
            "code": "reply_to_after_message_text",
            "message": err.to_string(),
            "repair": {
                "reorder": "put --reply-to before the text: wn messages send --group <group> --reply-to <message-id> <text>",
            },
        }),
        WnError::EmptyRelayUrl => json!({
            "code": "empty_relay_url",
            "message": err.to_string(),
        }),
        WnError::InvalidRelayUrl(_) => json!({
            "code": "invalid_relay_url",
            "message": err.to_string(),
            "repair": {
                "login": "printf '%s\\n' \"$NSEC\" | wn login --nsec-stdin --relay <ws-or-wss-url>",
                "daemon": "wn daemon start --discovery-relays <url> --default-account-relays <url>",
                "account_setup": "--default-relays <ws-or-wss-url> --bootstrap-relays <ws-or-wss-url>",
            },
        }),
        WnError::MissingRelay => json!({
            "code": "missing_relay_url",
            "message": err.to_string(),
            "repair": {
                "daemon": "wn daemon start --discovery-relays <url> --default-account-relays <url>",
                "account_setup": "--default-relays <url> --bootstrap-relays <url>",
            },
        }),
        WnError::MissingAccount => json!({
            "code": "missing_account",
            "message": err.to_string(),
            "repair": {
                "create": "wn account create [npub-or-hex]",
                "import_nsec": "printf '%s\\n' \"$NSEC\" | wn account create --nsec-stdin",
                "select": "--account <npub-or-hex>",
            },
        }),
        WnError::MultipleAccounts => json!({
            "code": "multiple_accounts",
            "message": err.to_string(),
            "repair": {
                "flag": "--account",
                "env": "WN_ACCOUNT",
            },
        }),
        WnError::UnknownLocalAccount(account) => json!({
            "code": "unknown_account",
            "message": err.to_string(),
            "account_ref": account,
        }),
        WnError::InvalidPublicKey => json!({
            "code": "invalid_public_key",
            "message": err.to_string(),
        }),
        WnError::PublicAccountCannotSign => json!({
            "code": "public_account_cannot_sign",
            "message": err.to_string(),
        }),
        WnError::InvalidSecretStore(store) => json!({
            "code": "invalid_secret_store",
            "message": err.to_string(),
            "secret_store": store,
        }),
        WnError::DevSettlementOverrideInRelease => json!({
            "code": "dev_settlement_override_in_release",
            "message": err.to_string(),
            "repair": {
                "unset": "WN_DEV_SETTLEMENT_QUIESCENCE_MS",
            },
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
        AccountHomeError::AccountUnlinked(account) => json!({
            "code": "account_unlinked",
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
    if let Some(cause) = err.as_oversized_event() {
        return json!({
            "code": "event_too_large",
            "message": format!("event too large: {} ({})", cause.artifact, cause.size_class),
            "artifact": cause.artifact.as_str(),
            "size_class": cause.size_class.as_str(),
        });
    }
    if let Some(engine_error) = err.as_engine_error() {
        return engine_error_json(engine_error);
    }
    match err {
        AppError::AccountHome(err) => account_home_error_json(err),
        // Keep the existing JSON code while the Rust caller-contract error
        // stops masquerading as an engine serialization failure.
        AppError::Account(AccountError::InvalidDeviceRosterEdit) => json!({
            "code": "engine_error",
            "message": err.to_string(),
        }),
        AppError::MissingKeyPackage { account, reason } => json!({
            "code": "missing_key_package",
            "message": err.to_string(),
            "account_id": account,
            "reason": reason.as_str(),
            "repair": {
                "local": format!("wn --account {account} keys publish"),
                // Another fetch cannot find a current package the recipient never published.
                "remote": match reason {
                    MissingKeyPackageReason::NotFound => {
                        "wn keys fetch <npub-or-hex> --bootstrap-relays <relay-url>"
                    }
                    MissingKeyPackageReason::ObsoleteOnly => {
                        "ask the recipient to update their app and publish a current KeyPackage"
                    }
                },
            },
        }),
        AppError::MissingMemberInboxRoute(account) => json!({
            "code": "missing_member_inbox_route",
            "message": err.to_string(),
            "account_id": account,
            "repair": {
                "action": "ask the recipient to publish a valid Marmot inbox relay list",
            },
        }),
        AppError::DirectoryLookupIncomplete(account) => json!({
            "code": "directory_lookup_incomplete",
            "message": err.to_string(),
            "account_id": account,
            "repair": {
                "action": "retry; nothing is known to be missing",
            },
        }),
        AppError::UnknownGroup(group_id) => json!({
            "code": "unknown_group",
            "message": err.to_string(),
            "group_id": group_id,
        }),
        // Terminal for outbound work and not an engine bug: without this arm
        // a removed sender's refusal renders as the catch-all `command_failed`,
        // which scripts cannot distinguish from a transient fault.
        AppError::GroupRemoved(group_id) => json!({
            "code": "group_removed",
            "message": err.to_string(),
            "group_id": group_id,
        }),
        // A durable disband request or an authenticated inbound disband
        // candidate gates ordinary outbound work. Scripts must be able to
        // tell "this group is ending" from a transient fault.
        AppError::GroupDisbanding(group_id) => json!({
            "code": "group_disbanding",
            "message": err.to_string(),
            "group_id": group_id,
            "repair": {
                "status": "wn groups disband-status <group-hex>",
            },
        }),
        // Retryable, unlike the terminal arms above: the group moved past
        // this device and recovery has not caught it up, so a commit now
        // would fork it (mdk#2258).
        AppError::GroupCatchingUp(group_id) => json!({
            "code": "group_catching_up",
            "message": err.to_string(),
            "group_id": group_id,
        }),
        // Retryable: the group's last change has not reached every relay yet
        // and is still being retried (mdk#2255).
        AppError::GroupCommitUndelivered(group_id) => json!({
            "code": "group_commit_undelivered",
            "message": err.to_string(),
            "group_id": group_id,
            "next_commands": {
                "status": "wn groups commit-delivery <group-hex>",
            },
        }),
        // Retryable: the group's own last commit has not confirmed yet, so it
        // cannot take another change (mdk#2332).
        AppError::GroupCommitPending(group_id) => json!({
            "code": "group_commit_pending",
            "message": err.to_string(),
            "group_id": group_id,
            "next_commands": {
                "status": "wn groups pending-commit <group-hex>",
            },
        }),
        AppError::GroupInviteNotPending => json!({
            "code": "group_invite_not_pending",
            "message": err.to_string(),
        }),
        AppError::InvalidEncryptedMedia(reason) => json!({
            "code": "invalid_encrypted_media",
            "message": err.to_string(),
            "reason": reason,
        }),
        // Raised by the CLI pre-check and, if a commit lands in between, by the
        // account worker itself; both surface the same typed code and fields.
        AppError::MediaReferenceStaleEpoch {
            source_epoch,
            current_epoch,
        } => json!({
            "code": "media_reference_stale_epoch",
            "message": err.to_string(),
            "source_epoch": source_epoch,
            "current_epoch": current_epoch,
            "repair": {
                "action": "wn media upload <group-hex> <file-path> [--send]",
            },
        }),
        // Raised by the account worker when the group's epoch is mid-change: a
        // commit this device staged awaits its publish outcome, or retained
        // peer commits are not yet applied. Nothing was published.
        AppError::MediaReferenceEpochUnsettled { source_epoch } => json!({
            "code": "media_reference_epoch_unsettled",
            "message": err.to_string(),
            "source_epoch": source_epoch,
            "repair": {
                "action": "wn sync, then retry `wn media send`; if the group epoch advanced, `wn media upload <group-hex> <file-path> [--send]`",
            },
        }),
        AppError::InvalidAppMessagePayload(reason) => json!({
            "code": "invalid_app_message_payload",
            "message": err.to_string(),
            "reason": reason,
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
        AppError::EventTooLarge {
            artifact,
            size_class,
        } => json!({
            "code": "event_too_large",
            "message": err.to_string(),
            "artifact": artifact.as_str(),
            "size_class": size_class.as_str(),
        }),
        // Every group relay is one MDK refuses to send to, such as a
        // private-network address; nothing was sent, and a retry fails the same
        // way while the group's relays stay the same (mdk#3305).
        AppError::NoUsableRelay => json!({
            "code": "no_usable_relay",
            "message": err.to_string(),
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
            "missing": missing.iter().map(|k| k.token()).collect::<Vec<_>>(),
        }),
        // Terminal for this list: it holds more follows than MDK reads from
        // one kind-3 event, so an edit could drop some. Nothing was published.
        AppError::FollowListTooLarge => json!({
            "code": "follow_list_too_large",
            "message": err.to_string(),
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
        AppError::UnexpectedPrivateKey => json!({
            "code": "unexpected_private_key",
            "message": err.to_string(),
        }),
        AppError::IdentityKeyMismatch => json!({
            "code": "identity_key_mismatch",
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
                "command": format!("wn keys fetch {account_id} --bootstrap-relays <relay-url>")
            },
        }),
        AppError::InvalidGroupProfile(reason) => json!({
            "code": "invalid_group_profile",
            "message": err.to_string(),
            "reason": reason,
        }),
        AppError::InvalidGroupAvatarUrl(reason) => json!({
            "code": "invalid_group_avatar_url",
            "message": err.to_string(),
            "reason": reason,
        }),
        AppError::Hex(err) => json!({
            "code": "invalid_hex",
            "message": err.to_string(),
        }),
        AppError::AccountCatchUp(_) => json!({
            "code": "account_catch_up",
            "message": err.to_string(),
        }),
        AppError::AccountWorkerBusy => json!({
            "code": "account_worker_busy",
            "message": err.to_string(),
            "safe_to_retry": true,
        }),
        AppError::AccountWorkerResponseTimedOut => json!({
            "code": "account_worker_response_timed_out",
            "message": err.to_string(),
            "completion_unknown": true,
            "repair": { "action": "refresh authoritative state before retrying" },
        }),
        AppError::AccountSetupRecoveryRequired => json!({
            "code": "account_setup_recovery_required",
            "message": err.to_string(),
            "repair": {
                "action": "confirm possible orphaned KeyPackage exposure, then retry with the host recovery API",
            },
        }),
        AppError::AccountSetupRetryRequired => json!({
            "code": "account_setup_retry_required",
            "message": err.to_string(),
            "repair": { "action": "retry the original account setup operation" },
        }),
        AppError::AccountSetupResetNotApplicable => json!({
            "code": "account_setup_reset_not_applicable",
            "message": err.to_string(),
        }),
        AppError::AccountSetupKeyPackageRecoveryAvailable => json!({
            "code": "account_setup_key_package_recovery_available",
            "message": err.to_string(),
            "repair": { "action": "retry the original account setup operation" },
        }),
        AppError::InvalidEditTarget => json!({
            "code": "invalid_edit_target",
            "message": err.to_string(),
            "repair": {
                "action": "edit only an available chat message this account sent; nothing was published",
            },
        }),
        AppError::ExternalSignerUnavailable(account_id) => json!({
            "code": "external_signer_unavailable",
            "message": err.to_string(),
            "account_id": account_id,
            "repair": {
                "register": "wn accounts nip46 register --bunker-stdin --approve-permissions",
            },
        }),
        AppError::ExternalSignerMismatch => json!({
            "code": "external_signer_mismatch",
            "message": err.to_string(),
        }),
        AppError::Nip46(nip46_err) => nip46_error_json(nip46_err),
        other => json!({
            "code": "command_failed",
            "message": other.to_string(),
        }),
    }
}

fn nip46_error_json(err: &marmot_app::Nip46Error) -> Value {
    use marmot_app::Nip46Error;
    let code = match err {
        Nip46Error::Invalid => "nip46_invalid",
        Nip46Error::ProxyConfig => "nip46_proxy_config",
        Nip46Error::Unavailable => "nip46_unavailable",
        Nip46Error::RelayPublish => "nip46_relay_publish",
        Nip46Error::Rejected => "nip46_rejected",
        Nip46Error::Mismatch => "nip46_mismatch",
        Nip46Error::Timeout => "nip46_timeout",
        Nip46Error::Cancelled => "nip46_cancelled",
        Nip46Error::LoggedOut => "nip46_logged_out",
        Nip46Error::Unsupported => "nip46_unsupported",
        Nip46Error::PermissionApprovalRequired => "nip46_permission_approval_required",
        Nip46Error::Storage => "nip46_storage",
        Nip46Error::Busy => "nip46_busy",
        Nip46Error::Disconnected => "nip46_disconnected",
        Nip46Error::RequestNotFound => "nip46_request_not_found",
    };
    json!({
        "code": code,
        "message": err.to_string(),
    })
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
        EngineError::LeaveAlreadyRequested { group_id } => json!({
            "code": "leave_already_requested",
            "message": err.to_string(),
            "group_id": hex::encode(group_id.as_slice()),
        }),
        EngineError::LeaveNotBlocked { group_id } => json!({
            "code": "leave_not_blocked",
            "message": err.to_string(),
            "group_id": hex::encode(group_id.as_slice()),
        }),
        EngineError::DisbandingNotEnabled { group_id } => json!({
            "code": "disbanding_not_enabled",
            "message": err.to_string(),
            "group_id": hex::encode(group_id.as_slice()),
            "repair": {
                "enable": "wn groups enable-disbanding <group-hex>",
            },
        }),
        EngineError::DisbandingUnsupportedMembers { group_id, members } => json!({
            "code": "disbanding_unsupported_members",
            "message": err.to_string(),
            "group_id": hex::encode(group_id.as_slice()),
            "members": members
                .iter()
                .map(|member| hex::encode(member.as_slice()))
                .collect::<Vec<_>>(),
        }),
        other => json!({
            "code": "engine_error",
            "message": other.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use marmot_app::AccountError;

    use super::*;

    #[test]
    fn invalid_edit_target_has_a_distinct_code() {
        let invalid = wn_error_json(&WnError::App(AppError::InvalidEditTarget));
        assert_eq!(invalid["code"], "invalid_edit_target");
        assert!(
            invalid["repair"]["action"]
                .as_str()
                .unwrap()
                .contains("this account sent")
        );
    }

    #[test]
    fn missing_key_package_errors_include_repair_guidance() {
        let account = "11".repeat(32);
        for (reason, token, remote) in [
            (
                MissingKeyPackageReason::NotFound,
                "not_found",
                "wn keys fetch <npub-or-hex> --bootstrap-relays <relay-url>",
            ),
            (
                MissingKeyPackageReason::ObsoleteOnly,
                "obsolete_only",
                "ask the recipient to update their app and publish a current KeyPackage",
            ),
        ] {
            let error = wn_error_json(&WnError::App(AppError::MissingKeyPackage {
                account: account.clone(),
                reason,
            }));

            assert_eq!(error["code"], "missing_key_package");
            assert_eq!(error["account_id"], account);
            assert_eq!(error["reason"], token);
            assert_eq!(
                error["repair"]["local"],
                format!("wn --account {account} keys publish")
            );
            assert_eq!(error["repair"]["remote"], remote);
        }
    }

    #[test]
    /// The CLI JSON contract keeps recipient identity out of text while exposing repair data.
    fn missing_member_inbox_errors_identify_the_recipient_and_repair() {
        let account = "22".repeat(32);
        let error = wn_error_json(&WnError::App(AppError::MissingMemberInboxRoute(
            account.clone(),
        )));

        assert_eq!(error["code"], "missing_member_inbox_route");
        assert_eq!(error["account_id"], account);
        assert_eq!(
            error["repair"]["action"],
            "ask the recipient to publish a valid Marmot inbox relay list"
        );
    }

    #[test]
    fn incomplete_directory_lookup_identifies_the_account_and_offers_retry() {
        let account = "33".repeat(32);
        let error = wn_error_json(&WnError::App(AppError::DirectoryLookupIncomplete(
            account.clone(),
        )));

        assert_eq!(error["code"], "directory_lookup_incomplete");
        assert_eq!(error["account_id"], account);
        assert!(!error["message"].as_str().unwrap().contains(&account));
        assert_eq!(
            error["repair"]["action"],
            "retry; nothing is known to be missing"
        );
    }

    #[test]
    fn secret_identity_errors_do_not_echo_nsec_material() {
        let nsec = "nsec1j4c6269y9w0q2er2xjw8sv2ehyrtfxq3jwgdlxj6qfn8z4gjsq5qfvfk99";
        let identity = Some(nsec.to_owned());
        let cases = [
            (
                crate::validate_materialized_secret_identity("login", &identity, false)
                    .expect_err("private argv is refused"),
                "secret_argument_rejected",
            ),
            (
                crate::read_identity_secret_input("login", &identity, true)
                    .expect_err("conflicting private input is refused before reading stdin"),
                "conflicting_secret_input",
            ),
            (
                WnError::MissingStdinSecret { command: "login" },
                "missing_stdin_secret",
            ),
            (
                WnError::InvalidStdinSecret {
                    command: "account create",
                },
                "invalid_stdin_secret",
            ),
        ];
        for (err, code) in cases {
            let message = err.to_string();
            assert!(!message.contains(nsec), "{message}");
            let json = wn_error_json(&err);
            assert_eq!(json["code"], code);
            assert!(!json.to_string().contains(nsec));
        }
    }

    #[test]
    fn account_setup_recovery_errors_have_stable_json_codes() {
        let cases = [
            (
                AppError::AccountSetupRecoveryRequired,
                "account_setup_recovery_required",
            ),
            (
                AppError::AccountSetupRetryRequired,
                "account_setup_retry_required",
            ),
            (
                AppError::AccountSetupResetNotApplicable,
                "account_setup_reset_not_applicable",
            ),
            (
                AppError::AccountSetupKeyPackageRecoveryAvailable,
                "account_setup_key_package_recovery_available",
            ),
        ];
        for (error, code) in cases {
            assert_eq!(wn_error_json(&WnError::App(error))["code"], code);
        }
    }

    #[test]
    fn account_worker_errors_preserve_retry_safety_in_json() {
        let busy = wn_error_json(&WnError::App(AppError::AccountWorkerBusy));
        assert_eq!(busy["code"], "account_worker_busy");
        assert_eq!(busy["safe_to_retry"], true);
        assert!(busy.get("completion_unknown").is_none());

        let timed_out = wn_error_json(&WnError::App(AppError::AccountWorkerResponseTimedOut));
        assert_eq!(timed_out["code"], "account_worker_response_timed_out");
        assert_eq!(timed_out["completion_unknown"], true);
        assert!(timed_out.get("safe_to_retry").is_none());
        assert_eq!(
            timed_out["repair"]["action"],
            "refresh authoritative state before retrying"
        );
    }

    #[test]
    fn retryable_group_gates_keep_group_context_and_delivery_guidance() {
        let group_id = "ab".repeat(16);
        let catching_up = wn_error_json(&WnError::App(AppError::GroupCatchingUp(group_id.clone())));
        assert_eq!(catching_up["code"], "group_catching_up");
        assert_eq!(catching_up["group_id"], group_id);
        let undelivered = wn_error_json(&WnError::App(AppError::GroupCommitUndelivered(
            group_id.clone(),
        )));
        assert_eq!(undelivered["code"], "group_commit_undelivered");
        assert_eq!(undelivered["group_id"], group_id);
        assert_eq!(
            undelivered["next_commands"]["status"],
            "wn groups commit-delivery <group-hex>"
        );
        let pending = wn_error_json(&WnError::App(AppError::GroupCommitPending(
            group_id.clone(),
        )));
        assert_eq!(pending["code"], "group_commit_pending");
        assert_eq!(pending["group_id"], group_id);
        assert_eq!(
            pending["next_commands"]["status"],
            "wn groups pending-commit <group-hex>"
        );
    }

    #[test]
    fn media_epoch_errors_distinguish_stale_from_unsettled_references() {
        let stale = wn_error_json(&WnError::App(AppError::MediaReferenceStaleEpoch {
            source_epoch: 7,
            current_epoch: 11,
        }));
        assert_eq!(stale["code"], "media_reference_stale_epoch");
        assert_eq!(stale["source_epoch"], 7);
        assert_eq!(stale["current_epoch"], 11);
        assert_eq!(
            stale["repair"]["action"],
            "wn media upload <group-hex> <file-path> [--send]"
        );
        let unsettled = wn_error_json(&WnError::App(AppError::MediaReferenceEpochUnsettled {
            source_epoch: 13,
        }));
        assert_eq!(unsettled["code"], "media_reference_epoch_unsettled");
        assert_eq!(unsettled["source_epoch"], 13);
        assert!(unsettled.get("current_epoch").is_none());
        assert_eq!(
            unsettled["repair"]["action"],
            "wn sync, then retry `wn media send`; if the group epoch advanced, `wn media upload <group-hex> <file-path> [--send]`"
        );
    }

    #[test]
    fn cursor_mismatch_errors_identify_the_matching_pair_of_flags() {
        for (timestamp_flag, message_id_flag) in [
            ("--before", "--before-message-id"),
            ("--after", "--after-message-id"),
        ] {
            let error = wn_error_json(&WnError::MessagePaginationCursorMismatch {
                timestamp_flag,
                message_id_flag,
            });
            assert_eq!(error["code"], "message_pagination_cursor_mismatch");
            assert_eq!(error["timestamp_flag"], timestamp_flag);
            assert_eq!(error["message_id_flag"], message_id_flag);
            assert_eq!(
                error["repair"]["supply_both"],
                format!("pass {timestamp_flag} and {message_id_flag} together")
            );
        }
        assert_eq!(
            wn_error_json(&WnError::MessagePaginationConflictingCursors)["code"],
            "message_pagination_conflicting_cursors"
        );
    }

    #[test]
    fn engine_errors_have_the_same_json_across_app_wrappers() {
        let rendered = [
            AppError::Session(EngineError::InvalidWelcome.into()),
            AppError::Account(AccountError::Session(EngineError::InvalidWelcome.into())),
            AppError::Account(AccountError::Engine(EngineError::InvalidWelcome)),
        ]
        .map(|error| wn_error_json(&WnError::App(error)));

        assert_eq!(rendered[0]["code"], "engine_error");
        assert!(rendered.windows(2).all(|pair| pair[0] == pair[1]));
    }

    #[test]
    fn nip46_errors_have_typed_codes_and_never_echo_bunker_secrets() {
        let secret = "super-secret-bunker-token-9999";
        let bunker_err = WnError::BunkerArgumentRejected { command: "login" };
        assert!(!bunker_err.to_string().contains(secret));
        let bunker_json = wn_error_json(&bunker_err);
        assert_eq!(bunker_json["code"], "secret_argument_rejected");

        let invalid_stdin = WnError::InvalidBunkerStdin { command: "login" };
        assert_eq!(
            wn_error_json(&invalid_stdin)["code"],
            "invalid_stdin_bunker_uri"
        );

        let perms = marmot_app::Nip46Session::permissions();
        let approval_err = WnError::Nip46PermissionApprovalRequired {
            version: perms.version,
            grants: perms.grants.clone(),
        };
        let approval_json = wn_error_json(&approval_err);
        assert_eq!(approval_json["code"], "nip46_permission_approval_required");
        assert_eq!(approval_json["version"], perms.version);
        assert_eq!(approval_json["grants"], json!(perms.grants));
        assert_eq!(approval_json["repair"]["flag"], "--approve-permissions");

        assert_eq!(
            wn_error_json(&WnError::App(AppError::Nip46(
                marmot_app::Nip46Error::Rejected
            )))["code"],
            "nip46_rejected"
        );
        assert_eq!(
            wn_error_json(&WnError::App(AppError::Nip46(
                marmot_app::Nip46Error::Unavailable
            )))["code"],
            "nip46_unavailable"
        );
        assert_eq!(
            wn_error_json(&WnError::App(AppError::ExternalSignerUnavailable(
                "aa".repeat(32)
            )))["code"],
            "external_signer_unavailable"
        );
    }

    /// The CLI column of `marmot-app`'s lower-stack error table: the code
    /// follows what the error is, however the lower stack wrapped it.
    #[test]
    fn lower_stack_errors_get_a_code_by_kind_not_by_wrapping() {
        let mismatches: Vec<String> = marmot_app::error_kind_table::lower_stack_rows()
            .into_iter()
            .filter_map(|row| {
                let json = wn_error_json(&WnError::App(row.error));
                let code = json["code"].as_str().unwrap_or_default().to_owned();
                (code != row.expected.cli_code)
                    .then(|| format!("{}: {code}, expected {}", row.name, row.expected.cli_code))
            })
            .collect();
        assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
    }
}
