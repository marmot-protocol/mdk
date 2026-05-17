use std::ffi::OsString;
use std::path::{Path, PathBuf};

use cgka_traits::GroupId;
use cgka_traits::TransportEndpoint;
use cgka_traits::error::EngineError;
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
    Hex(#[from] hex::FromHexError),
    #[error("message text is required")]
    EmptyMessage,
    #[error("group id is required")]
    MissingGroupId,
    #[error("relay URL cannot be empty")]
    EmptyRelayUrl,
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
    let secret_store = resolve_secret_store(cli.secret_store)?;
    let keychain_service = resolve_keychain_service(cli.keychain_service);
    let runtime_info = CliRuntimeInfo {
        secret_store,
        keychain_service: keychain_service.clone(),
    };
    let account_home = open_account_home(&home, secret_store, &keychain_service)?;
    let app = app_for(home, cli.relay, account_home.clone());
    let account_flag = cli.account.clone();
    match cli.command {
        Command::Account { command } => {
            account_command(&account_home, &app, command, runtime_info, account_flag).await
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
) -> Result<CommandOutput, DmError> {
    match command {
        AccountCommand::Create {
            identity,
            default_relays,
            bootstrap_relays,
        } => {
            let directory_bootstrap_relays = bootstrap_relays.clone();
            let imports_private_key = identity.as_deref().is_some_and(is_nostr_secret);
            let account = create_nostr_account(account_home, identity)?;
            let relay_lists = match account.local_signing {
                true => {
                    if imports_private_key && !bootstrap_relays.is_empty() {
                        let bootstrap_endpoints = match relay_endpoints(bootstrap_relays.clone()) {
                            Ok(endpoints) => endpoints,
                            Err(err) => rollback_account_after_setup_failure(
                                account_home,
                                &account.label,
                                err,
                            )?,
                        };
                        let current_status = match relay_list_status_for_account_id(
                            app,
                            &account.account_id_hex,
                            bootstrap_endpoints.clone(),
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
                        } else if default_relays.is_empty() {
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
                                bootstrap_endpoints,
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
                    if !default_relays.is_empty() {
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
            json!({
                "message_id": message.message_id_hex,
                "direction": "received",
                "from": message.sender,
                "group_id": hex::encode(message.group_id.as_slice()),
                "plaintext": message.plaintext,
            })
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
            json!({
                "message_id": message.message_id_hex,
                "direction": message.direction,
                "group_id": message.group_id_hex,
                "from": message.sender,
                "plaintext": message.plaintext,
                "recorded_at": message.recorded_at,
                "received_at": message.received_at,
            })
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
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(DmError::EmptyRelayUrl);
        }
        let endpoint = TransportEndpoint(trimmed.to_owned());
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
    if let Some(url) = relay {
        return MarmotApp::with_relays_and_account_home(home, vec![url], account_home);
    }
    MarmotApp::local_with_account_home(home, account_home)
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
            },
        }),
        DmError::AccountHome(err) => account_home_error_json(err),
        DmError::App(err) => app_error_json(err),
        DmError::Hex(err) => json!({
            "code": "invalid_hex",
            "message": err.to_string(),
        }),
        DmError::EmptyMessage => json!({
            "code": "empty_message",
            "message": err.to_string(),
        }),
        DmError::MissingGroupId => json!({
            "code": "missing_group_id",
            "message": err.to_string(),
        }),
        DmError::EmptyRelayUrl => json!({
            "code": "empty_relay_url",
            "message": err.to_string(),
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

    use super::default_home_from_env;

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
}
