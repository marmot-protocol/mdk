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
use cgka_traits::{GroupId, MessageId};
use clap::{Parser, Subcommand, ValueEnum};
use marmot_account::{AccountError, AccountHome, AccountHomeError, DEFAULT_KEYCHAIN_SERVICE_NAME};
use marmot_app::{
    AccountRelayListBootstrap, AccountRelayListStatus, AppError, AppGroupMemberRecord,
    AppGroupRecord, AppMessageQuery, AppMessageRecord, AppStatus, FetchedKeyPackage, MarmotApp,
    SyncSummary,
};
use nostr::ToBech32;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use transport_quic_broker::{
    BrokerServerTrust, PublishTextToBroker, SubscribeTextFromBroker, publish_text_to_broker,
    subscribe_text_from_broker,
};
use transport_quic_stream::{
    QuicTextStreamReceiver, SendTextStream, ServerTrust, send_text_stream,
};

pub mod daemon;
pub mod tui;

#[derive(Parser, Clone, Debug, Serialize, Deserialize)]
#[command(name = "dm", about = "Darkmatter CLI", disable_help_subcommand = true)]
struct Cli {
    #[arg(long, global = true, value_name = "PATH")]
    home: Option<PathBuf>,
    #[arg(long, global = true, value_name = "PATH")]
    socket: Option<PathBuf>,
    #[arg(long, global = true, value_name = "URL")]
    relay: Option<String>,
    #[arg(long, global = true, value_enum, value_name = "STORE")]
    secret_store: Option<SecretStoreKind>,
    #[arg(long, global = true, value_name = "SERVICE")]
    keychain_service: Option<String>,
    #[arg(long, value_name = "ACCOUNT")]
    account: Option<String>,
    #[arg(long, global = true)]
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
    Account {
        #[command(subcommand)]
        command: AccountCommand,
    },
    Keys {
        #[command(subcommand)]
        command: KeyPackageCommand,
    },
    Chats {
        #[command(subcommand)]
        command: ChatsCommand,
    },
    Group {
        #[command(subcommand)]
        command: GroupCommand,
    },
    Message {
        #[command(subcommand)]
        command: MessageCommand,
    },
    Stream {
        #[command(subcommand)]
        command: StreamCommand,
    },
    Daemon {
        #[command(subcommand)]
        command: DaemonCommand,
    },
    Sync,
}

#[derive(Clone, Debug, Serialize, Deserialize, Subcommand)]
enum AccountCommand {
    Create {
        #[arg(value_name = "NSEC_OR_NPUB")]
        identity: Option<String>,
        #[arg(long, value_name = "URLS", value_delimiter = ',')]
        default_relays: Vec<String>,
        #[arg(long, value_name = "URLS", value_delimiter = ',')]
        bootstrap_relays: Vec<String>,
        #[arg(long)]
        publish_missing_relay_lists: bool,
    },
    List,
    Status {
        account: Option<String>,
    },
    #[command(name = "relay-lists")]
    RelayLists {
        #[arg(value_name = "NPUB_OR_HEX")]
        account: Option<String>,
        #[arg(long, value_name = "URLS", value_delimiter = ',')]
        bootstrap_relays: Vec<String>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, Subcommand)]
enum KeyPackageCommand {
    Publish,
    Fetch {
        #[arg(value_name = "NPUB_OR_HEX")]
        account: Option<String>,
        #[arg(long, value_name = "URLS", value_delimiter = ',')]
        bootstrap_relays: Vec<String>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, Subcommand)]
enum ChatsCommand {
    List {
        #[arg(long)]
        include_archived: bool,
    },
    Show {
        group: String,
    },
    Archive {
        group: String,
    },
    Unarchive {
        group: String,
    },
    #[command(name = "list-archived")]
    ListArchived,
}

#[derive(Clone, Debug, Serialize, Deserialize, Subcommand)]
enum GroupCommand {
    Create {
        name: String,
        #[arg(value_name = "MEMBER")]
        members: Vec<String>,
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
enum MessageCommand {
    Send {
        #[arg(long = "group", value_name = "GROUP")]
        group_flag: Option<String>,
        #[arg(value_name = "GROUP_OR_TEXT", allow_hyphen_values = true)]
        args: Vec<String>,
    },
    List {
        #[arg(long)]
        group: Option<String>,
        #[arg(long)]
        limit: Option<usize>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, Subcommand)]
enum StreamCommand {
    #[command(about = "Anchor a durable agent text stream start over the MLS message path")]
    Start {
        group: String,
        #[arg(long, value_name = "HEX")]
        stream_id: Option<String>,
        #[arg(long = "quic-candidate", value_name = "ADDR")]
        quic_candidates: Vec<String>,
    },
    #[command(about = "Receive one provisional QUIC agent text stream")]
    Receive {
        #[arg(long, default_value = "127.0.0.1:4450", value_name = "ADDR")]
        bind: SocketAddr,
        #[arg(long, value_name = "HEX")]
        start_event_id: Option<String>,
    },
    #[command(about = "Send one provisional QUIC agent text stream")]
    Send {
        #[arg(long)]
        broker: bool,
        #[arg(long, value_name = "ADDR")]
        connect: SocketAddr,
        #[arg(long, default_value = "localhost", value_name = "NAME")]
        server_name: String,
        #[arg(long, value_name = "HEX")]
        server_cert_der_hex: Option<String>,
        #[arg(long)]
        insecure_local: bool,
        #[arg(long, value_name = "HEX")]
        stream_id: Option<String>,
        #[arg(long, value_name = "HEX")]
        start_event_id: Option<String>,
        #[arg(long, default_value_t = 1024, value_name = "BYTES")]
        chunk_bytes: usize,
        #[arg(long, default_value_t = 0, value_name = "MILLIS")]
        chunk_delay_ms: u64,
        #[arg(value_name = "TEXT", required = true, allow_hyphen_values = true)]
        text: Vec<String>,
    },
    #[command(about = "Watch one brokered QUIC agent text stream from a durable MLS start payload")]
    Watch {
        group: String,
        #[arg(long, value_name = "HEX")]
        stream_id: Option<String>,
        #[arg(long, value_name = "HEX")]
        server_cert_der_hex: Option<String>,
        #[arg(long)]
        insecure_local: bool,
    },
    #[command(about = "Commit the final agent text stream transcript over the MLS message path")]
    Finish {
        group: String,
        #[arg(long, value_name = "HEX")]
        stream_id: String,
        #[arg(long, value_name = "HEX")]
        transcript_hash: String,
        #[arg(long)]
        chunk_count: u64,
        #[arg(value_name = "TEXT", required = true, allow_hyphen_values = true)]
        text: Vec<String>,
    },
    #[command(about = "Verify a local QUIC transcript against the durable MLS final payload")]
    Verify {
        group: String,
        #[arg(long, value_name = "HEX")]
        stream_id: String,
        #[arg(long, value_name = "HEX")]
        transcript_hash: String,
        #[arg(long)]
        chunk_count: Option<u64>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, Subcommand)]
enum DaemonCommand {
    Start {
        #[arg(long, value_name = "MILLIS")]
        sync_interval_ms: Option<u64>,
    },
    Stop,
    Status,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CliOutput {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug)]
struct CommandOutput {
    plain: String,
    json: Value,
}

#[derive(Debug, thiserror::Error)]
enum DmError {
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
    #[error("message text is required")]
    EmptyMessage,
    #[error("group id is required")]
    MissingGroupId,
    #[error("relay URL cannot be empty")]
    EmptyRelayUrl,
    #[error("invalid relay URL: {0}")]
    InvalidRelayUrl(String),
    #[error(
        "relay URL is required; pass --relay, set DM_RELAY, or provide setup relays for account creation"
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
    #[error("missing account relay lists: {0:?}")]
    MissingRelayLists(Vec<String>, Box<AccountRelayListStatus>),
    #[error(
        "failed to roll back account {account} after setup failure: {source}; rollback error: {rollback}"
    )]
    AccountRollback {
        account: String,
        source: Box<DmError>,
        rollback: AccountHomeError,
    },
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

pub(crate) async fn run_cli_local(cli: Cli) -> CliOutput {
    match execute(cli).await {
        Ok((json_output, output)) => {
            if json_output {
                CliOutput {
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
                }
            } else {
                CliOutput {
                    code: 0,
                    stdout: ensure_trailing_newline(output.plain),
                    stderr: String::new(),
                }
            }
        }
        Err((json_output, err)) => {
            if json_output {
                json_dm_error(err)
            } else {
                CliOutput {
                    code: 1,
                    stdout: String::new(),
                    stderr: format!("error: {err}\n"),
                }
            }
        }
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
    let relay = resolve_relay(cli.relay.clone())?;
    let app = app_for(home, relay.clone(), account_home.clone());
    match command {
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
        Command::Keys { command } => {
            key_package_command(&account_home, &app, command, account_flag).await
        }
        Command::Chats { command } => {
            chats_command(&account_home, &app, command, account_flag).await
        }
        Command::Group { command } => {
            group_command(&account_home, &app, command, account_flag).await
        }
        Command::Message { command } => {
            message_command(&account_home, &app, command, account_flag).await
        }
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
    }
}

fn daemon_socket_for_client(cli: &Cli, home: &Path) -> Option<PathBuf> {
    let env_socket = std::env::var_os("DM_SOCKET").map(PathBuf::from);
    let socket = cli
        .socket
        .clone()
        .or(env_socket.clone())
        .unwrap_or_else(|| daemon::default_socket_path(home));
    if cli.socket.is_some() || env_socket.is_some() || socket.exists() {
        Some(socket)
    } else {
        None
    }
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
            mut default_relays,
            mut bootstrap_relays,
            publish_missing_relay_lists,
        } => {
            let global_relay_defaults =
                apply_global_relay_defaults(&mut default_relays, &mut bootstrap_relays, relay);
            let directory_bootstrap_relays = bootstrap_relays.clone();
            let imports_private_key = identity.as_deref().is_some_and(is_nostr_secret);
            let creates_new_private_key = identity.is_none();
            let account = create_nostr_account(account_home, identity)?;
            let relay_lists = match account.local_signing {
                true => {
                    if creates_new_private_key && default_relays.is_empty() {
                        rollback_account_after_setup_failure(
                            account_home,
                            &account.label,
                            DmError::MissingRelay,
                        )?;
                    }
                    if imports_private_key
                        && default_relays.is_empty()
                        && bootstrap_relays.is_empty()
                    {
                        rollback_account_after_setup_failure(
                            account_home,
                            &account.label,
                            DmError::MissingRelay,
                        )?;
                    }
                    if imports_private_key
                        && (!default_relays.is_empty() || !bootstrap_relays.is_empty())
                    {
                        let bootstrap =
                            match relay_bootstrap(default_relays.clone(), bootstrap_relays.clone())
                            {
                                Ok(Some(bootstrap)) => bootstrap,
                                Ok(None) => unreachable!("import relay setup checked above"),
                                Err(err) => rollback_account_after_setup_failure(
                                    account_home,
                                    &account.label,
                                    err,
                                )?,
                            };
                        let current_status = match relay_list_status_for_account_id(
                            app,
                            &account.account_id_hex,
                            bootstrap.bootstrap_relays.clone(),
                        )
                        .await
                        {
                            Ok(status) => status,
                            Err(err) => rollback_account_after_setup_failure(
                                account_home,
                                &account.label,
                                err,
                            )?,
                        };
                        if current_status.complete {
                            current_status
                        } else if !publish_missing_relay_lists || default_relays.is_empty() {
                            rollback_account_after_setup_failure(
                                account_home,
                                &account.label,
                                DmError::MissingRelayLists(
                                    current_status.missing.clone(),
                                    Box::new(current_status),
                                ),
                            )?
                        } else {
                            let bootstrap = match relay_bootstrap_from_endpoints(
                                default_relays,
                                bootstrap.bootstrap_relays,
                            )
                            .and_then(|bootstrap| {
                                bootstrap.ok_or_else(|| AppError::MissingDefaultRelays.into())
                            }) {
                                Ok(bootstrap) => bootstrap,
                                Err(err) => rollback_account_after_setup_failure(
                                    account_home,
                                    &account.label,
                                    err,
                                )?,
                            };
                            match app
                                .publish_missing_account_relay_lists_from_status(
                                    &account.label,
                                    bootstrap,
                                    current_status,
                                )
                                .await
                            {
                                Ok(relay_lists) => relay_lists,
                                Err(err) => rollback_account_after_setup_failure(
                                    account_home,
                                    &account.label,
                                    err.into(),
                                )?,
                            }
                        }
                    } else {
                        let bootstrap = match relay_bootstrap(default_relays, bootstrap_relays) {
                            Ok(bootstrap) => bootstrap,
                            Err(err) => rollback_account_after_setup_failure(
                                account_home,
                                &account.label,
                                err,
                            )?,
                        };
                        match maybe_publish_relay_lists(app, &account.label, bootstrap).await {
                            Ok(relay_lists) => relay_lists,
                            Err(err) => rollback_account_after_setup_failure(
                                account_home,
                                &account.label,
                                err,
                            )?,
                        }
                    }
                }
                false => {
                    if bootstrap_relays.is_empty() {
                        rollback_account_after_setup_failure(
                            account_home,
                            &account.label,
                            DmError::MissingRelay,
                        )?;
                    }
                    if !default_relays.is_empty() && !global_relay_defaults.default_relays {
                        return Err(DmError::PublicAccountCannotSign);
                    }
                    relay_list_status_for_account_id(
                        app,
                        &account.account_id_hex,
                        relay_endpoints(bootstrap_relays)?,
                    )
                    .await?
                }
            };
            warm_user_directory_after_account_setup(
                app,
                &account.account_id_hex,
                directory_bootstrap_relays,
            )
            .await;
            Ok(CommandOutput {
                plain: format!(
                    "created account {} local-signing={} relay-lists={}",
                    npub_for_account_id(&account.account_id_hex),
                    account.local_signing,
                    relay_setup_plain(&relay_lists)
                ),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex),
                    "local_signing": account.local_signing,
                    "relay_lists": relay_lists_json(relay_lists),
                }),
            })
        }
        AccountCommand::List => {
            let accounts = account_home.accounts()?;
            let plain = if accounts.is_empty() {
                "no accounts".to_owned()
            } else {
                accounts
                    .iter()
                    .map(|account| {
                        format!(
                            "{} {} local-signing={}",
                            npub_for_account_id(&account.account_id_hex),
                            account.account_id_hex,
                            account.local_signing
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            let accounts_json = accounts
                .into_iter()
                .map(|account| {
                    json!({
                        "account_id": account.account_id_hex,
                        "npub": npub_for_account_id(&account.account_id_hex),
                        "local_signing": account.local_signing,
                    })
                })
                .collect::<Vec<_>>();
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

async fn warm_user_directory_after_account_setup(
    app: &MarmotApp,
    account_id_hex: &str,
    bootstrap_relays: Vec<String>,
) {
    let Ok(bootstrap_relays) = relay_endpoints(bootstrap_relays) else {
        return;
    };
    let _ = app
        .refresh_user_directory_for_account_id(account_id_hex, bootstrap_relays)
        .await;
}

async fn key_package_command(
    account_home: &AccountHome,
    app: &MarmotApp,
    command: KeyPackageCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, DmError> {
    match command {
        KeyPackageCommand::Publish => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let mut client = app.client(&account.label).await?;
            let key_package = client.publish_key_package().await?;
            Ok(CommandOutput {
                plain: format!(
                    "published key package for {} bytes={}",
                    npub_for_account_id(&account.account_id_hex),
                    key_package.0.len()
                ),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex),
                    "key_package_bytes": key_package.0.len(),
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
            group_show_output(app, account, group)
        }
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
    }
}

async fn group_command(
    account_home: &AccountHome,
    app: &MarmotApp,
    command: GroupCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, DmError> {
    match command {
        GroupCommand::Create { name, members } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let mut client = app.client(&account.label).await?;
            let member_refs = members.iter().map(String::as_str).collect::<Vec<_>>();
            let group_id = client.create_group(&name, &member_refs).await?;
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
            let client = app.client(&account.label).await?;
            let members = client.members(&group_id)?;
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
            let mut client = app.client(&account.label).await?;
            let member_refs = members.iter().map(String::as_str).collect::<Vec<_>>();
            let summary = client.invite_members(&group_id, &member_refs).await?;
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
            let mut client = app.client(&account.label).await?;
            let member_refs = members.iter().map(String::as_str).collect::<Vec<_>>();
            let summary = client.remove_members(&group_id, &member_refs).await?;
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
            let mut client = app.client(&account.label).await?;
            let summary = client
                .update_group_profile(&group_id, name.as_deref(), description.as_deref())
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

fn group_show_output(
    app: &MarmotApp,
    account: marmot_account::AccountSummary,
    group: String,
) -> Result<CommandOutput, DmError> {
    app.status(&account.label)?;
    let group_id = normalize_group_id_hex(&group)?;
    let group = app
        .group(&account.label, &group_id)?
        .ok_or_else(|| AppError::UnknownGroup(group_id.clone()))?;
    Ok(CommandOutput {
        plain: group_plain(&group),
        json: json!({
            "account_id": account.account_id_hex,
            "npub": npub_for_account_id(&account.account_id_hex),
            "group": group_json(group),
        }),
    })
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
            let mut client = app.client(&account.label).await?;
            let summary = client.send(&group_id, payload.as_bytes()).await?;
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
        MessageCommand::List { group, limit } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let messages = app.messages_with_query(
                &account.label,
                AppMessageQuery {
                    group_id_hex: group
                        .map(|group| normalize_group_id_hex(&group))
                        .transpose()?,
                    limit,
                },
            )?;
            Ok(CommandOutput {
                plain: message_list_plain(&messages),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex),
                    "messages": message_list_json(messages),
                }),
            })
        }
    }
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
            let payload = AgentTextStreamAppPayloadEnvelopeV1::start(
                &stream_id,
                unix_now_seconds(),
                quic_candidates,
            );
            let payload_bytes = payload.encode()?;
            let agent_text_stream = agent_text_stream_payload_value(&payload);
            let mut client = app.client(&account.label).await?;
            let summary = client.send(&group_id, &payload_bytes).await?;
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
        } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id_hex = normalize_group_id_hex(&group)?;
            let expected_stream_id_hex =
                stream_id.map(|value| normalize_hex(&value)).transpose()?;
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
            let start_event_id = MessageId::new(hex::decode(&start_message_id_hex)?);
            let received = subscribe_text_from_broker(SubscribeTextFromBroker {
                broker_addr: candidate.addr,
                server_name: candidate.server_name.clone(),
                trust: trust.clone(),
                stream_id,
                start_event_id,
            })
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
            let payload = AgentTextStreamAppPayloadEnvelopeV1::final_payload(
                &stream_id,
                text.join(" "),
                transcript_hash,
                chunk_count,
                unix_now_seconds(),
            );
            let payload_bytes = payload.encode()?;
            let agent_text_stream = agent_text_stream_payload_value(&payload);
            let mut client = app.client(&account.label).await?;
            let summary = client.send(&group_id, &payload_bytes).await?;
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
        json: sync_json(account, summary),
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

fn sync_json(account: marmot_account::AccountSummary, summary: SyncSummary) -> Value {
    json!({
        "account_id": account.account_id_hex,
        "npub": npub_for_account_id(&account.account_id_hex),
        "joined_groups": summary.joined_groups.into_iter().map(|group_id| {
            hex::encode(group_id.as_slice())
        }).collect::<Vec<_>>(),
        "messages": summary.messages.into_iter().map(|message| {
            let agent_text_stream = agent_text_stream_payload_json(&message.plaintext);
            let mut value = json!({
                "message_id": message.message_id_hex,
                "direction": "received",
                "from": message.sender,
                "group_id": hex::encode(message.group_id.as_slice()),
                "plaintext": message.plaintext,
            });
            if let Some(agent_text_stream) = agent_text_stream {
                value["agent_text_stream"] = agent_text_stream;
            }
            value
        }).collect::<Vec<_>>(),
        "events": summary.events.len(),
    })
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
        "agent_text_stream": group.agent_text_stream,
        "archived": group.archived,
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

fn message_list_json(messages: Vec<AppMessageRecord>) -> Vec<Value> {
    messages
        .into_iter()
        .map(|message| {
            let agent_text_stream = agent_text_stream_payload_json(&message.plaintext);
            let mut value = json!({
                "message_id": message.message_id_hex,
                "direction": message.direction,
                "group_id": message.group_id_hex,
                "from": message.sender,
                "plaintext": message.plaintext,
                "recorded_at": message.recorded_at,
                "received_at": message.received_at,
            });
            if let Some(agent_text_stream) = agent_text_stream {
                value["agent_text_stream"] = agent_text_stream;
            }
            value
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

fn create_nostr_account(
    account_home: &AccountHome,
    identity: Option<String>,
) -> Result<marmot_account::AccountSummary, DmError> {
    match identity {
        Some(value) if is_nostr_secret(&value) => Ok(account_home.import_nostr_account(&value)?),
        Some(value) => Ok(account_home.add_public_account(&value)?),
        None => Ok(account_home.create_nostr_account()?),
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

async fn maybe_publish_relay_lists(
    app: &MarmotApp,
    label: &str,
    bootstrap: Option<AccountRelayListBootstrap>,
) -> Result<AccountRelayListStatus, DmError> {
    match bootstrap {
        Some(bootstrap) => Ok(app.publish_account_relay_lists(label, bootstrap).await?),
        None => Ok(app.account_relay_list_status(label)?),
    }
}

fn rollback_account_after_setup_failure<T>(
    account_home: &AccountHome,
    account: &str,
    source: DmError,
) -> Result<T, DmError> {
    match account_home.remove_account(account) {
        Ok(()) => Err(source),
        Err(rollback) => Err(DmError::AccountRollback {
            account: account.to_owned(),
            source: Box::new(source),
            rollback,
        }),
    }
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

fn relay_bootstrap(
    default_relays: Vec<String>,
    bootstrap_relays: Vec<String>,
) -> Result<Option<AccountRelayListBootstrap>, DmError> {
    relay_bootstrap_from_endpoints(default_relays, relay_endpoints(bootstrap_relays)?)
}

fn relay_bootstrap_from_endpoints(
    default_relays: Vec<String>,
    bootstrap_relays: Vec<TransportEndpoint>,
) -> Result<Option<AccountRelayListBootstrap>, DmError> {
    if default_relays.is_empty() && bootstrap_relays.is_empty() {
        return Ok(None);
    }
    let default_relays = relay_endpoints(default_relays)?;
    Ok(Some(AccountRelayListBootstrap::new(
        default_relays,
        bootstrap_relays,
    )))
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
                "flag": "--relay <ws-or-wss-url>",
                "env": "DM_RELAY",
                "account_setup": "--default-relays <ws-or-wss-url> --bootstrap-relays <ws-or-wss-url>",
            },
        }),
        DmError::MissingRelay => json!({
            "code": "missing_relay_url",
            "message": err.to_string(),
            "repair": {
                "flag": "--relay <ws-or-wss-url>",
                "env": "DM_RELAY",
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
        DmError::AccountRollback {
            account,
            source,
            rollback,
        } => json!({
            "code": "account_rollback_failed",
            "message": err.to_string(),
            "account_ref": account,
            "source": dm_error_json(source),
            "rollback": account_home_error_json(rollback),
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
        DmError, GlobalRelayDefaults, apply_global_relay_defaults, default_home_from_env,
        relay_endpoints, resolve_relay,
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
}
