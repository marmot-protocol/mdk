//! CLI error type and its `--json` error-rendering functions.

use std::net::SocketAddr;

use cgka_traits::error::EngineError;
use marmot_account::{AccountError, AccountHomeError};
use marmot_app::{AccountRelayListStatus, AppError, MissingRelayListKind};
use serde_json::{Value, json};

use crate::relay_lists_json;

#[derive(Debug, thiserror::Error)]
pub(crate) enum WnError {
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
    #[error("--reply-to must come before the message text; it was read as literal text here")]
    ReplyToAfterMessageText,
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
    #[error("public Nostr accounts do not have local signing keys")]
    PublicAccountCannotSign,
    #[error("invalid secret store: {0}")]
    InvalidSecretStore(String),
    #[error(
        "WN_DEV_SETTLEMENT_QUIESCENCE_MS is only available in debug builds; unset it when running a release binary"
    )]
    DevSettlementOverrideInRelease,
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
    #[error(
        "QUIC candidate {candidate} resolved to a local/private endpoint {addr}; pass --insecure-local to allow local endpoints"
    )]
    UnsafeQuicCandidateEndpoint { candidate: String, addr: SocketAddr },
    #[error("transcript hash must be 32 bytes, got {0}")]
    InvalidTranscriptHashLength(usize),
    #[error("choose either --server-cert-der-hex or --insecure-local")]
    ConflictingStreamTrust,
    #[error("--insecure-local is only allowed for loopback QUIC endpoints, got {0}")]
    InsecureLocalRequiresLoopback(SocketAddr),
    #[error("messages subscribe requires the daemon; start it with `wn daemon start`")]
    MessagesSubscribeRequiresDaemon,
    #[error("chats subscribe requires the daemon; start it with `wn daemon start`")]
    ChatsSubscribeRequiresDaemon,
    #[error("notifications subscribe requires the daemon; start it with `wn daemon start`")]
    NotificationsSubscribeRequiresDaemon,
    #[error("stream compose requires the daemon; start it with `wn daemon start`")]
    StreamComposeRequiresDaemon,
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
    #[error("invalid mute duration: {0}")]
    InvalidMuteDuration(String),
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
        WnError::AccountHome(err) => account_home_error_json(err),
        WnError::App(err) => app_error_json(err),
        WnError::QuicStream(err) => json!({
            "code": "quic_stream",
            "message": err.to_string(),
        }),
        WnError::QuicBroker(err) => json!({
            "code": "quic_broker",
            "message": err.to_string(),
        }),
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
        WnError::EmptyStreamText => json!({
            "code": "empty_stream_text",
            "message": err.to_string(),
        }),
        WnError::MissingStreamStart => json!({
            "code": "missing_stream_start",
            "message": err.to_string(),
        }),
        WnError::StreamStartNotConfirmed => json!({
            "code": "stream_start_not_confirmed",
            "message": err.to_string(),
        }),
        WnError::MissingQuicCandidate => json!({
            "code": "missing_quic_candidate",
            "message": err.to_string(),
        }),
        WnError::UnsupportedStreamRoute(route) => json!({
            "code": "unsupported_stream_route",
            "message": err.to_string(),
            "route": route,
        }),
        WnError::InvalidQuicCandidate(candidate) => json!({
            "code": "invalid_quic_candidate",
            "message": err.to_string(),
            "candidate": candidate,
        }),
        WnError::QuicCandidateResolve { candidate, source } => json!({
            "code": "quic_candidate_resolve",
            "message": err.to_string(),
            "candidate": candidate,
            "source": source.to_string(),
        }),
        WnError::UnsafeQuicCandidateEndpoint { candidate, addr } => json!({
            "code": "unsafe_quic_candidate_endpoint",
            "message": err.to_string(),
            "candidate": candidate,
            "addr": addr.to_string(),
        }),
        WnError::InvalidTranscriptHashLength(actual) => json!({
            "code": "invalid_transcript_hash",
            "message": err.to_string(),
            "actual_bytes": actual,
            "expected_bytes": 32,
        }),
        WnError::ConflictingStreamTrust => json!({
            "code": "conflicting_stream_trust",
            "message": err.to_string(),
        }),
        WnError::InsecureLocalRequiresLoopback(addr) => json!({
            "code": "insecure_local_requires_loopback",
            "message": err.to_string(),
            "addr": addr.to_string(),
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
        WnError::StreamComposeRequiresDaemon => json!({
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
        WnError::ConflictingSecretInput { command } => json!({
            "code": "conflicting_secret_input",
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
                "local": format!("wn --account {account} keys publish"),
                "remote": "wn keys fetch <npub-or-hex> --bootstrap-relays <relay-url>"
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
            "missing": missing.iter().map(|k| k.token()).collect::<Vec<_>>(),
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
