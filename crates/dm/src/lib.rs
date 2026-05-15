use std::ffi::OsString;
use std::path::PathBuf;

use cgka_traits::GroupId;
use cgka_traits::TransportEndpoint;
use cgka_traits::error::EngineError;
use clap::{Parser, Subcommand, ValueEnum};
use marmot_account::{AccountError, AccountHome, AccountHomeError, DEFAULT_KEYCHAIN_SERVICE_NAME};
use marmot_app::{
    AccountRelayListBootstrap, AccountRelayListStatus, AppError, AppGroupMemberRecord,
    AppGroupRecord, AppMessageQuery, AppMessageRecord, AppStatus, DirectoryEntry,
    FetchedKeyPackage, MarmotApp, SyncSummary,
};
use serde_json::{Value, json};

#[derive(Parser, Debug)]
#[command(name = "dm", about = "Darkmatter CLI", disable_help_subcommand = true)]
struct Cli {
    #[arg(long, global = true, value_name = "PATH")]
    home: Option<PathBuf>,
    #[arg(long, global = true, value_name = "URL")]
    relay: Option<String>,
    #[arg(long, global = true, value_enum, value_name = "STORE")]
    secret_store: Option<SecretStoreKind>,
    #[arg(long, global = true, value_name = "SERVICE")]
    keychain_service: Option<String>,
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum SecretStoreKind {
    Keychain,
    File,
}

impl SecretStoreKind {
    fn as_str(self) -> &'static str {
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

#[derive(Subcommand, Debug)]
enum Command {
    Account {
        #[command(subcommand)]
        command: AccountCommand,
    },
    #[command(name = "key-package", alias = "keypkg")]
    KeyPackage {
        #[command(subcommand)]
        command: KeyPackageCommand,
    },
    Group {
        #[command(subcommand)]
        command: GroupCommand,
    },
    Message {
        #[command(subcommand)]
        command: MessageCommand,
    },
    Directory {
        #[command(subcommand)]
        command: DirectoryCommand,
    },
    Sync {
        #[arg(long)]
        account: String,
    },
}

#[derive(Subcommand, Debug)]
enum AccountCommand {
    Create {
        name: String,
        #[arg(long, value_name = "URLS", value_delimiter = ',')]
        default_relays: Vec<String>,
        #[arg(long, value_name = "URLS", value_delimiter = ',')]
        bootstrap_relays: Vec<String>,
    },
    Import {
        name: String,
        #[arg(long, alias = "insec", value_name = "NSEC_OR_HEX")]
        nsec: String,
        #[arg(long, value_name = "URLS", value_delimiter = ',')]
        default_relays: Vec<String>,
        #[arg(long, value_name = "URLS", value_delimiter = ',')]
        bootstrap_relays: Vec<String>,
        #[arg(long)]
        publish_missing_relay_lists: bool,
    },
    List,
    Status {
        name: String,
    },
    #[command(name = "relay-lists")]
    RelayLists {
        name: Option<String>,
        #[arg(long, value_name = "NPUB_OR_HEX")]
        pubkey: Option<String>,
        #[arg(long, value_name = "URLS", value_delimiter = ',')]
        bootstrap_relays: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
enum KeyPackageCommand {
    Publish {
        #[arg(long)]
        account: String,
    },
    Fetch {
        name: Option<String>,
        #[arg(long, value_name = "NPUB_OR_HEX")]
        pubkey: Option<String>,
        #[arg(long, value_name = "URLS", value_delimiter = ',')]
        bootstrap_relays: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
enum GroupCommand {
    Create {
        #[arg(long)]
        account: String,
        #[arg(long)]
        name: String,
        #[arg(long = "member", required = true)]
        members: Vec<String>,
    },
    List {
        #[arg(long)]
        account: String,
        #[arg(long)]
        include_archived: bool,
    },
    Show {
        #[arg(long)]
        account: String,
        group: String,
    },
    Members {
        #[arg(long)]
        account: String,
        group: String,
    },
    Invite {
        #[arg(long)]
        account: String,
        group: String,
        #[arg(long = "member", required = true)]
        members: Vec<String>,
    },
    Remove {
        #[arg(long)]
        account: String,
        group: String,
        #[arg(long = "member", required = true)]
        members: Vec<String>,
    },
    Archive {
        #[arg(long)]
        account: String,
        group: String,
    },
    Unarchive {
        #[arg(long)]
        account: String,
        group: String,
    },
    Update {
        #[arg(long)]
        account: String,
        group: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        description: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum MessageCommand {
    Send {
        #[arg(long)]
        account: String,
        #[arg(long)]
        group: String,
        text: Vec<String>,
    },
    List {
        #[arg(long)]
        account: String,
        #[arg(long)]
        group: Option<String>,
        #[arg(long)]
        limit: Option<usize>,
    },
}

#[derive(Subcommand, Debug)]
enum DirectoryCommand {
    Get {
        name: Option<String>,
        #[arg(long, value_name = "NPUB_OR_HEX")]
        pubkey: Option<String>,
    },
    Refresh {
        name: Option<String>,
        #[arg(long, value_name = "NPUB_OR_HEX")]
        pubkey: Option<String>,
        #[arg(long, value_name = "URLS", value_delimiter = ',')]
        bootstrap_relays: Vec<String>,
    },
}

#[derive(Debug)]
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
    #[error("relay URL cannot be empty")]
    EmptyRelayUrl,
    #[error("pass either an account name or --pubkey")]
    MissingAccountSelector,
    #[error("pass an account name or --pubkey, not both")]
    AmbiguousAccountSelector,
    #[error("invalid public key")]
    InvalidPublicKey,
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
    let home = resolve_home(cli.home);
    let secret_store = resolve_secret_store(cli.secret_store)?;
    let keychain_service = resolve_keychain_service(cli.keychain_service);
    let runtime_info = CliRuntimeInfo {
        secret_store,
        keychain_service: keychain_service.clone(),
    };
    let account_home = open_account_home(&home, secret_store, &keychain_service)?;
    let app = app_for(home, cli.relay, account_home.clone());
    match cli.command {
        Command::Account { command } => {
            account_command(&account_home, &app, command, runtime_info).await
        }
        Command::KeyPackage { command } => key_package_command(&account_home, &app, command).await,
        Command::Group { command } => group_command(&app, command).await,
        Command::Message { command } => message_command(&app, command).await,
        Command::Directory { command } => directory_command(&account_home, &app, command).await,
        Command::Sync { account } => sync_command(&app, account).await,
    }
}

async fn account_command(
    account_home: &AccountHome,
    app: &MarmotApp,
    command: AccountCommand,
    runtime_info: CliRuntimeInfo,
) -> Result<CommandOutput, DmError> {
    match command {
        AccountCommand::Create {
            name,
            default_relays,
            bootstrap_relays,
        } => {
            let account = account_home.create_account(&name)?;
            let relay_lists = match maybe_publish_relay_lists(
                app,
                &name,
                relay_bootstrap(default_relays, bootstrap_relays)?,
            )
            .await
            {
                Ok(relay_lists) => relay_lists,
                Err(err) => rollback_account_after_setup_failure(account_home, &name, err)?,
            };
            Ok(CommandOutput {
                plain: format!(
                    "created account {name} {} relay-lists={}",
                    account.account_id_hex,
                    relay_setup_plain(&relay_lists)
                ),
                json: json!({
                    "account": name,
                    "account_id": account.account_id_hex,
                    "relay_lists": relay_lists_json(relay_lists),
                }),
            })
        }
        AccountCommand::Import {
            name,
            nsec,
            default_relays,
            bootstrap_relays,
            publish_missing_relay_lists,
        } => {
            let account_id = AccountHome::account_id_for_secret(&nsec)?;
            let bootstrap_endpoints = relay_endpoints(bootstrap_relays.clone())?;
            let current_status =
                relay_list_status_for_account_id(app, &account_id, bootstrap_endpoints.clone())
                    .await?;
            if !current_status.complete && !publish_missing_relay_lists {
                return Err(DmError::MissingRelayLists(
                    current_status.missing.clone(),
                    Box::new(current_status),
                ));
            }
            if !current_status.complete && default_relays.is_empty() {
                return Err(AppError::MissingDefaultRelays.into());
            }
            let account = account_home.import_account(&name, &nsec)?;
            let relay_lists = if publish_missing_relay_lists && !current_status.complete {
                let bootstrap =
                    relay_bootstrap_from_endpoints(default_relays, bootstrap_endpoints)?
                        .ok_or(AppError::MissingDefaultRelays)?;
                match app
                    .publish_missing_account_relay_lists_from_status(
                        &name,
                        bootstrap,
                        current_status,
                    )
                    .await
                {
                    Ok(relay_lists) => relay_lists,
                    Err(err) => {
                        rollback_account_after_setup_failure(account_home, &name, err.into())?
                    }
                }
            } else {
                current_status
            };
            Ok(CommandOutput {
                plain: format!(
                    "imported account {name} {} relay-lists={}",
                    account.account_id_hex,
                    relay_setup_plain(&relay_lists)
                ),
                json: json!({
                    "account": name,
                    "account_id": account.account_id_hex,
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
                    .map(|account| format!("{} {}", account.label, account.account_id_hex))
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            let accounts_json = accounts
                .into_iter()
                .map(|account| {
                    json!({
                        "account": account.label,
                        "account_id": account.account_id_hex,
                    })
                })
                .collect::<Vec<_>>();
            Ok(CommandOutput {
                plain,
                json: json!({ "accounts": accounts_json }),
            })
        }
        AccountCommand::Status { name } => {
            let status = app.status(&name)?;
            Ok(CommandOutput {
                plain: serde_json::to_string_pretty(&dm_status_json(status.clone(), &runtime_info))
                    .expect("JSON response serialization cannot fail"),
                json: dm_status_json(status, &runtime_info),
            })
        }
        AccountCommand::RelayLists {
            name,
            pubkey,
            bootstrap_relays,
        } => {
            let account_id = account_selector(account_home, name, pubkey)?;
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
) -> Result<CommandOutput, DmError> {
    match command {
        KeyPackageCommand::Publish { account } => {
            app.status(&account)?;
            let mut client = app.client(&account).await?;
            let key_package = client.publish_key_package().await?;
            Ok(CommandOutput {
                plain: format!(
                    "published key package for {account} bytes={}",
                    key_package.0.len()
                ),
                json: json!({
                    "account": account,
                    "key_package_bytes": key_package.0.len(),
                }),
            })
        }
        KeyPackageCommand::Fetch {
            name,
            pubkey,
            bootstrap_relays,
        } => {
            let account_id = account_selector(account_home, name, pubkey)?;
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

async fn group_command(app: &MarmotApp, command: GroupCommand) -> Result<CommandOutput, DmError> {
    match command {
        GroupCommand::Create {
            account,
            name,
            members,
        } => {
            app.status(&account)?;
            let mut client = app.client(&account).await?;
            let member_refs = members.iter().map(String::as_str).collect::<Vec<_>>();
            let group_id = client.create_group(&name, &member_refs).await?;
            let group_id_hex = hex::encode(group_id.as_slice());
            let group = app
                .group(&account, &group_id_hex)?
                .ok_or_else(|| AppError::UnknownGroup(group_id_hex.clone()))?;
            Ok(CommandOutput {
                plain: format!("created group {group_id_hex}"),
                json: json!({
                    "account": account,
                    "group_id": group.group_id_hex,
                    "name": group.profile.name.clone(),
                    "profile": group.profile,
                    "image": group.image,
                    "members": members,
                }),
            })
        }
        GroupCommand::List {
            account,
            include_archived,
        } => {
            app.status(&account)?;
            let groups = if include_archived {
                app.groups(&account)?
            } else {
                app.visible_groups(&account)?
            };
            Ok(CommandOutput {
                plain: group_list_plain(&groups),
                json: json!({
                    "account": account,
                    "include_archived": include_archived,
                    "groups": groups.into_iter().map(group_json).collect::<Vec<_>>(),
                }),
            })
        }
        GroupCommand::Show { account, group } => {
            app.status(&account)?;
            let group_id = normalize_group_id_hex(&group)?;
            let group = app
                .group(&account, &group_id)?
                .ok_or_else(|| AppError::UnknownGroup(group_id.clone()))?;
            Ok(CommandOutput {
                plain: group_plain(&group),
                json: json!({
                    "account": account,
                    "group": group_json(group),
                }),
            })
        }
        GroupCommand::Members { account, group } => {
            app.status(&account)?;
            let group_id = GroupId::new(hex::decode(normalize_group_id_hex(&group)?)?);
            let client = app.client(&account).await?;
            let members = client.members(&group_id)?;
            Ok(CommandOutput {
                plain: group_members_plain(&members),
                json: json!({
                    "account": account,
                    "group_id": hex::encode(group_id.as_slice()),
                    "members": group_members_json(members),
                }),
            })
        }
        GroupCommand::Invite {
            account,
            group,
            members,
        } => {
            app.status(&account)?;
            let group_id = GroupId::new(hex::decode(normalize_group_id_hex(&group)?)?);
            let mut client = app.client(&account).await?;
            let member_refs = members.iter().map(String::as_str).collect::<Vec<_>>();
            let summary = client.invite_members(&group_id, &member_refs).await?;
            Ok(CommandOutput {
                plain: format!(
                    "invited {} member(s) published={}",
                    members.len(),
                    summary.published
                ),
                json: json!({
                    "account": account,
                    "group_id": hex::encode(group_id.as_slice()),
                    "members": members,
                    "published": summary.published,
                    "message_ids": summary.message_ids,
                }),
            })
        }
        GroupCommand::Remove {
            account,
            group,
            members,
        } => {
            app.status(&account)?;
            let group_id = GroupId::new(hex::decode(normalize_group_id_hex(&group)?)?);
            let mut client = app.client(&account).await?;
            let member_refs = members.iter().map(String::as_str).collect::<Vec<_>>();
            let summary = client.remove_members(&group_id, &member_refs).await?;
            Ok(CommandOutput {
                plain: format!(
                    "removed {} member(s) published={}",
                    members.len(),
                    summary.published
                ),
                json: json!({
                    "account": account,
                    "group_id": hex::encode(group_id.as_slice()),
                    "members": members,
                    "published": summary.published,
                    "message_ids": summary.message_ids,
                }),
            })
        }
        GroupCommand::Archive { account, group } => {
            app.status(&account)?;
            let group_id = normalize_group_id_hex(&group)?;
            let group = app.set_group_archived(&account, &group_id, true)?;
            Ok(CommandOutput {
                plain: format!("archived group {group_id}"),
                json: json!({
                    "account": account,
                    "group": group_json(group),
                }),
            })
        }
        GroupCommand::Unarchive { account, group } => {
            app.status(&account)?;
            let group_id = normalize_group_id_hex(&group)?;
            let group = app.set_group_archived(&account, &group_id, false)?;
            Ok(CommandOutput {
                plain: format!("unarchived group {group_id}"),
                json: json!({
                    "account": account,
                    "group": group_json(group),
                }),
            })
        }
        GroupCommand::Update {
            account,
            group,
            name,
            description,
        } => {
            app.status(&account)?;
            let group_id = GroupId::new(hex::decode(normalize_group_id_hex(&group)?)?);
            let mut client = app.client(&account).await?;
            let summary = client
                .update_group_profile(&group_id, name.as_deref(), description.as_deref())
                .await?;
            let group_id_hex = hex::encode(group_id.as_slice());
            let group = app
                .group(&account, &group_id_hex)?
                .ok_or_else(|| AppError::UnknownGroup(group_id_hex.clone()))?;
            Ok(CommandOutput {
                plain: format!(
                    "updated group {group_id_hex} published={}",
                    summary.published
                ),
                json: json!({
                    "account": account,
                    "group": group_json(group),
                    "published": summary.published,
                    "message_ids": summary.message_ids,
                }),
            })
        }
    }
}

async fn message_command(
    app: &MarmotApp,
    command: MessageCommand,
) -> Result<CommandOutput, DmError> {
    match command {
        MessageCommand::Send {
            account,
            group,
            text,
        } => {
            if text.is_empty() {
                return Err(DmError::EmptyMessage);
            }
            app.status(&account)?;
            let group_id = GroupId::new(hex::decode(group)?);
            let payload = text.join(" ");
            let mut client = app.client(&account).await?;
            let summary = client.send(&group_id, payload.as_bytes()).await?;
            Ok(CommandOutput {
                plain: format!("sent message published={}", summary.published),
                json: json!({
                    "account": account,
                    "group_id": hex::encode(group_id.as_slice()),
                    "published": summary.published,
                    "message_ids": summary.message_ids,
                }),
            })
        }
        MessageCommand::List {
            account,
            group,
            limit,
        } => {
            app.status(&account)?;
            let messages = app.messages_with_query(
                &account,
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
                    "account": account,
                    "messages": message_list_json(messages),
                }),
            })
        }
    }
}

async fn sync_command(app: &MarmotApp, account: String) -> Result<CommandOutput, DmError> {
    app.status(&account)?;
    let mut client = app.client(&account).await?;
    let summary = client.sync().await?;
    Ok(CommandOutput {
        plain: sync_plain(&summary),
        json: sync_json(account, summary),
    })
}

async fn directory_command(
    account_home: &AccountHome,
    app: &MarmotApp,
    command: DirectoryCommand,
) -> Result<CommandOutput, DmError> {
    match command {
        DirectoryCommand::Get { name, pubkey } => {
            let account_id = account_selector(account_home, name, pubkey)?;
            let entry = app
                .directory_entry_for_account_id(&account_id)?
                .ok_or_else(|| AppError::MissingDirectoryEntry(account_id.clone()))?;
            Ok(CommandOutput {
                plain: directory_entry_plain(&entry),
                json: directory_entry_json(entry),
            })
        }
        DirectoryCommand::Refresh {
            name,
            pubkey,
            bootstrap_relays,
        } => {
            let account_id = account_selector(account_home, name, pubkey)?;
            let entry = app
                .refresh_directory_entry_for_account_id(
                    &account_id,
                    relay_endpoints(bootstrap_relays)?,
                )
                .await?;
            Ok(CommandOutput {
                plain: directory_entry_plain(&entry),
                json: directory_entry_json(entry),
            })
        }
    }
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

fn sync_json(account: String, summary: SyncSummary) -> Value {
    json!({
        "account": account,
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
        "archived": group.archived,
    })
}

fn group_members_plain(members: &[AppGroupMemberRecord]) -> String {
    if members.is_empty() {
        return "no members".to_owned();
    }
    members
        .iter()
        .map(|member| {
            member
                .account
                .clone()
                .unwrap_or_else(|| member.member_id_hex.clone())
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn group_members_json(members: Vec<AppGroupMemberRecord>) -> Vec<Value> {
    members
        .into_iter()
        .map(|member| {
            json!({
                "member_id": member.member_id_hex,
                "account": member.account,
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

fn directory_entry_plain(entry: &DirectoryEntry) -> String {
    let key_package = if entry.key_package.is_some() {
        "key-package=yes"
    } else {
        "key-package=no"
    };
    format!(
        "directory {} relay-lists={} {key_package}",
        entry.account_id_hex,
        relay_setup_plain(&entry.relay_lists)
    )
}

fn directory_entry_json(entry: DirectoryEntry) -> Value {
    let key_package = entry.key_package.map(|key_package| {
        json!({
            "key_package_id": key_package.key_package_id,
            "bytes": hex::decode(&key_package.key_package_hex)
                .map(|bytes| bytes.len())
                .unwrap_or_default(),
            "created_at": key_package.created_at,
            "source_relays": key_package.source_relays,
        })
    });
    json!({
        "account_id": entry.account_id_hex,
        "relay_lists": relay_lists_json(entry.relay_lists),
        "key_package": key_package,
    })
}

fn dm_status_json(status: AppStatus, runtime_info: &CliRuntimeInfo) -> Value {
    json!({
        "account": status.account,
        "account_id": status.account_id_hex,
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

fn account_selector(
    account_home: &AccountHome,
    name: Option<String>,
    pubkey: Option<String>,
) -> Result<String, DmError> {
    match (name, pubkey) {
        (Some(_), Some(_)) => Err(DmError::AmbiguousAccountSelector),
        (None, None) => Err(DmError::MissingAccountSelector),
        (Some(name), None) => Ok(account_home.account(&name)?.account_id_hex),
        (None, Some(pubkey)) => parse_public_key(&pubkey),
    }
}

fn parse_public_key(value: &str) -> Result<String, DmError> {
    nostr::PublicKey::parse(value)
        .map(|pubkey| pubkey.to_hex())
        .map_err(|_| DmError::InvalidPublicKey)
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
                "flag": "--publish-missing-relay-lists",
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
        DmError::EmptyRelayUrl => json!({
            "code": "empty_relay_url",
            "message": err.to_string(),
        }),
        DmError::MissingAccountSelector => json!({
            "code": "missing_account_selector",
            "message": err.to_string(),
        }),
        DmError::AmbiguousAccountSelector => json!({
            "code": "ambiguous_account_selector",
            "message": err.to_string(),
        }),
        DmError::InvalidPublicKey => json!({
            "code": "invalid_public_key",
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
            "account": account,
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
            "account": account,
        }),
        AccountHomeError::UnknownAccount(account) => json!({
            "code": "unknown_account",
            "message": err.to_string(),
            "account": account,
        }),
        AccountHomeError::InvalidSecretKey => json!({
            "code": "invalid_secret_key",
            "message": err.to_string(),
        }),
        AccountHomeError::InvalidAccountLabel(account) => json!({
            "code": "invalid_account_label",
            "message": err.to_string(),
            "account": account,
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
        AppError::MissingKeyPackage(account) => json!({
            "code": "missing_key_package",
            "message": err.to_string(),
            "account": account,
            "repair": {
                "local": format!("dm key-package publish --account {account}"),
                "remote": format!("dm key-package fetch --pubkey {account} --bootstrap-relays <relay-url>")
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
                "command": format!("dm directory refresh --pubkey {account_id} --bootstrap-relays <relay-url>")
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
