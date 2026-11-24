use std::ffi::OsString;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use cgka_traits::TransportEndpoint;
use clap::Parser;
use marmot_account::AccountHome;
use marmot_app::{
    AccountRelayListStatus, AppError, AppGroupRecord, ChatListRow, MarmotApp, MarmotAppConfig,
    SelfMembership, UserProfileMetadata,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

mod args;
pub(crate) mod commands;
pub mod daemon;
mod error;
mod secret;
mod terminal;

pub(crate) use terminal::{terminal_safe_json_display, terminal_safe_text};

pub use args::SecretStoreKind;
pub(crate) use args::{
    AccountCommand, ChatsCommand, Cli, Command, DaemonCommand, DebugCommand, FollowsCommand,
    GroupCommand, GroupsCommand, KeyPackageCommand, MaintenancePolicySetting, MediaCommand,
    MessageCommand, MessageTimelineCommand, NotificationsCommand, ProfileCommand, RelaysCommand,
    SettingsCommand, UsageDiagnosticsCommand, UsersCommand,
};
pub(crate) use error::{WnError, wn_error_json};
pub(crate) use secret::ImportNsec;

const PRIVATE_DIR_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;

pub(crate) fn create_private_dir_all(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(PRIVATE_DIR_MODE))?;
    Ok(())
}

/// The directory a private file must be created in, or `None` when the path is
/// a bare file name: `Path::parent` reports `Some("")` for `avatar.png`, and
/// creating or chmod-ing `""` fails with `ENOENT` on Unix before the file is
/// even opened.
pub(crate) fn private_parent_dir(path: &Path) -> Option<&Path> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
}

/// Write a file inside the `wn` home layout. Every directory on the way to
/// it is created if missing and tightened to `0700`: those directories are
/// `wn`'s own, and their contents (databases, secrets, sockets, logs) must
/// never be readable by other local users.
pub(crate) fn write_private_file(path: &Path, bytes: impl AsRef<[u8]>) -> std::io::Result<()> {
    if let Some(parent) = private_parent_dir(path) {
        create_private_dir_all(parent)?;
    }
    write_private_file_contents(path, bytes)
}

/// Write a caller-chosen output file — a decrypted download — with private
/// mode, without touching directories that already exist. The destination is
/// the caller's working directory or an `--output` directory of their
/// choosing; a shared `0755` directory is theirs to keep shared, and one owned
/// by another user cannot be chmod-ed at all. Only directories this call has
/// to create are made `0700`; the file itself is always `0600`.
pub(crate) fn write_private_output_file(
    path: &Path,
    bytes: impl AsRef<[u8]>,
) -> std::io::Result<()> {
    if let Some(parent) = private_parent_dir(path) {
        create_missing_dirs_private(parent)?;
    }
    write_private_file_contents(path, bytes)
}

/// `create_dir_all` whose newly created directories are `0700`. Directories
/// that already exist are left exactly as found: `DirBuilder::recursive` does
/// not revisit them, so no existing mode is changed.
fn create_missing_dirs_private(path: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, PRIVATE_DIR_MODE);
    builder.create(path)
}

fn write_private_file_contents(path: &Path, bytes: impl AsRef<[u8]>) -> std::io::Result<()> {
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
    if let Some(parent) = private_parent_dir(path) {
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

#[derive(Clone, Debug)]
pub(crate) struct CliRuntimeInfo {
    pub(crate) secret_store: SecretStoreKind,
    pub(crate) keychain_service: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CliOutput {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug)]
pub(crate) struct CommandOutput {
    pub(crate) plain: String,
    pub(crate) json: Value,
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
            use clap::error::ErrorKind;
            // clap reports explicit `--help`/`--version` as `Err` with exit code
            // 0; the rendered string is the help/version text, which belongs on
            // stdout (clap's own default). Real usage errors go to stderr.
            //
            // Crucially, gate on the exit code, not just the kind:
            // `DisplayHelpOnMissingArgumentOrSubcommand` is also rendered as help
            // text but exits nonzero (e.g. `wn messages` with no subcommand). That
            // is a genuine usage error and must stay on stderr / `ok:false`, never
            // be reported as success. Only zero-exit display errors are real
            // help/version requests.
            let is_zero_exit_display = err.exit_code() == 0
                && matches!(
                    err.kind(),
                    ErrorKind::DisplayHelp
                        | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
                        | ErrorKind::DisplayVersion
                );
            if is_zero_exit_display {
                let label = if err.kind() == ErrorKind::DisplayVersion {
                    "version"
                } else {
                    "help"
                };
                if wants_json {
                    return clap_display_json(err.exit_code(), label, err.to_string());
                }
                return CliOutput {
                    code: err.exit_code(),
                    stdout: err.to_string(),
                    stderr: String::new(),
                };
            }
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
    if let Err(err) = validate_secret_input_flags(&cli) {
        return command_output_result(cli.json, Err(err));
    }
    let import_nsec = match read_import_nsec_for_cli(&cli) {
        Ok(import_nsec) => import_nsec,
        Err(err) => return command_output_result(cli.json, Err(err)),
    };

    run_cli_with_import_nsec(cli, import_nsec).await
}

async fn run_cli_with_import_nsec(mut cli: Cli, mut import_nsec: Option<ImportNsec>) -> CliOutput {
    if let Command::Daemon { command } = cli.command.clone() {
        return daemon::run_daemon_command(cli, command).await;
    }

    // File inputs and output destinations mean the caller's files. A forwarded
    // command runs inside `wnd`, whose working directory is unrelated, so pin
    // them to the caller's directory before either execution path.
    if let Ok(caller_dir) = std::env::current_dir() {
        resolve_relative_paths(&mut cli, &caller_dir);
    }

    let home = resolve_home(cli.home.clone());
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

    if is_notifications_subscribe(&cli) {
        let socket = daemon_socket_path_for_client(&cli, &home);
        return match daemon::send_notifications_subscribe(&socket, cli.clone()).await {
            Ok(output) => output,
            Err(err) => daemon_client_error(cli.json, err),
        };
    }

    if let Some(socket) = daemon_socket_for_client(&cli, &home) {
        let explicit_daemon_socket =
            cli.socket.is_some() || std::env::var_os("WN_SOCKET").is_some();
        let json_output = cli.json;
        match daemon::send_execute(&socket, cli, import_nsec).await {
            Ok(output) => return output,
            Err(recover) => {
                if matches!(
                    recover.err,
                    daemon::DaemonClientError::RequestTooLarge { .. }
                ) {
                    return daemon_client_error(json_output, recover.err);
                }
                if should_fallback_to_local_after_daemon_execute_error(
                    explicit_daemon_socket,
                    &recover.err,
                ) {
                    cli = recover.cli;
                    import_nsec = recover.import_nsec;
                } else {
                    return daemon_execute_error(json_output, recover.err);
                }
            }
        }
    }

    run_cli_local(cli, import_nsec, None).await
}

fn validate_secret_input_flags(cli: &Cli) -> Result<(), WnError> {
    match &cli.command {
        Command::Login {
            identity,
            nsec_stdin,
            ..
        } => validate_materialized_secret_identity("login", identity, *nsec_stdin),
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
        } => validate_materialized_secret_identity("account create", identity, *nsec_stdin),
        _ => Ok(()),
    }
}

fn read_import_nsec_for_cli(cli: &Cli) -> Result<Option<ImportNsec>, WnError> {
    match &cli.command {
        Command::Login {
            identity,
            nsec_stdin,
            ..
        } => read_identity_secret_input("login", identity, *nsec_stdin),
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
        } => read_identity_secret_input("account create", identity, *nsec_stdin),
        _ => Ok(None),
    }
}

fn read_identity_secret_input(
    command: &'static str,
    identity: &Option<String>,
    nsec_stdin: bool,
) -> Result<Option<ImportNsec>, WnError> {
    if nsec_stdin {
        if identity.is_some() {
            return Err(WnError::ConflictingSecretInput { command });
        }
        return Ok(Some(read_nsec_from_stdin(command)?));
    }
    Ok(None)
}

/// Classify CLI input consistently before display, subprocess routing, or argv
/// rejection. Stdin import already treats surrounding whitespace as padding.
pub(crate) fn is_nostr_secret(value: &str) -> bool {
    marmot_app::is_nostr_secret(value.trim())
}

fn read_nsec_from_stdin(command: &'static str) -> Result<ImportNsec, WnError> {
    use zeroize::Zeroizing;

    let mut value = Zeroizing::new(String::new());
    std::io::stdin().read_to_string(&mut value)?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(WnError::MissingStdinSecret { command });
    }
    if !is_nostr_secret(trimmed) {
        return Err(WnError::InvalidStdinSecret { command });
    }
    Ok(ImportNsec::new(Zeroizing::new(trimmed.to_owned())))
}

pub(crate) fn validate_materialized_secret_identity(
    command: &'static str,
    identity: &Option<String>,
    nsec_stdin: bool,
) -> Result<(), WnError> {
    if identity.as_deref().is_some_and(is_nostr_secret) && !nsec_stdin {
        return Err(WnError::SecretArgumentRejected { command });
    }
    Ok(())
}

/// Resolve every caller-relative file input and output destination in `cli`
/// against `base`, and turn an absent download destination into `base` itself
/// (the handlers treat a directory output as "default file name in there").
/// Relative paths are joined, never canonicalized, so an output that does not
/// exist yet still resolves.
pub(crate) fn resolve_relative_paths(cli: &mut Cli, base: &Path) {
    fn resolve(base: &Path, value: &mut String) {
        if Path::new(value.as_str()).is_relative() {
            *value = base.join(value.as_str()).to_string_lossy().into_owned();
        }
    }
    let base_dir = || base.to_string_lossy().into_owned();
    match &mut cli.command {
        Command::Groups { command, .. } => match command {
            GroupsCommand::Create {
                image: Some(image), ..
            } => resolve(base, image),
            GroupsCommand::SetImage { file_path, .. } => resolve(base, file_path),
            GroupsCommand::DownloadImage { output, .. } => match output {
                Some(output) => resolve(base, output),
                None => *output = Some(base_dir()),
            },
            _ => {}
        },
        Command::Media { command } => match command {
            MediaCommand::Upload { file_paths, .. } => {
                for file_path in file_paths {
                    resolve(base, file_path);
                }
            }
            MediaCommand::Download { output, .. } => match output {
                Some(output) => resolve(base, output),
                None => *output = Some(base_dir()),
            },
            _ => {}
        },
        _ => {}
    }
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
            ..
        }
    )
}

fn is_notifications_subscribe(cli: &Cli) -> bool {
    matches!(
        &cli.command,
        Command::Notifications {
            command: NotificationsCommand::Subscribe,
        }
    )
}

pub(crate) async fn run_cli_local(
    cli: Cli,
    import_nsec: Option<ImportNsec>,
    root_context: Option<(&marmot_app::MarmotRootRuntimeLease, AccountHome)>,
) -> CliOutput {
    match execute(cli, import_nsec, root_context).await {
        Ok((json_output, output)) => command_output_result(json_output, Ok(output)),
        Err((json_output, err)) => command_output_result(json_output, Err(err)),
    }
}

pub(crate) fn command_output_result(
    json_output: bool,
    result: Result<CommandOutput, WnError>,
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
        Err(err) if json_output => json_wn_error(err),
        Err(WnError::Sync(sync)) => CliOutput {
            code: 1,
            stdout: String::new(),
            // Partial message plaintext belongs only in this explicit CLI
            // presentation path. Keep it out of `Error::Display`, which can be
            // logged by callers and must remain privacy-safe.
            stderr: format!(
                "error: sync failed; completed prefix:\n{}\nerror: {}\n",
                sync.partial_plain,
                terminal_safe_text(&sync.source.to_string())
            ),
        },
        Err(err) => CliOutput {
            code: 1,
            stdout: String::new(),
            stderr: format!("error: {}\n", terminal_safe_text(&err.to_string())),
        },
    }
}

async fn execute(
    cli: Cli,
    import_nsec: Option<ImportNsec>,
    root_context: Option<(&marmot_app::MarmotRootRuntimeLease, AccountHome)>,
) -> Result<(bool, CommandOutput), (bool, WnError)> {
    let json_output = cli.json;
    execute_inner(cli, import_nsec, root_context)
        .await
        .map(|output| (json_output, output))
        .map_err(|err| (json_output, err))
}

async fn execute_inner(
    cli: Cli,
    mut import_nsec: Option<ImportNsec>,
    root_context: Option<(&marmot_app::MarmotRootRuntimeLease, AccountHome)>,
) -> Result<CommandOutput, WnError> {
    let settlement_quiescence_ms = wn_dev_settlement_quiescence_ms()?;
    let home = resolve_home(cli.home.clone());
    if let Command::Reset { confirm } = cli.command {
        return reset_command(&home, confirm);
    }
    #[cfg(unix)]
    let home = if root_context.is_none() {
        normalize_standalone_home(home)?
    } else {
        home
    };
    let account_flag = cli.account.clone();
    let command = cli.command.clone();
    let secret_store = resolve_secret_store(cli.secret_store)?;
    let keychain_service = resolve_keychain_service(cli.keychain_service);
    let runtime_info = CliRuntimeInfo {
        secret_store,
        keychain_service: keychain_service.clone(),
    };
    let (root_owner, account_home) = match root_context {
        Some((root_owner, account_home)) => (Some(root_owner), account_home),
        None => (
            None,
            open_account_home(&home, secret_store, &keychain_service)?,
        ),
    };
    let command_relay = match &command {
        Command::Login { relay, .. } => relay.clone().or_else(|| cli.relay.clone()),
        _ => cli.relay.clone(),
    };
    let relay = resolve_relay(command_relay)?;
    let app = || {
        let mut config = cli_app_config(
            cli.daemon_discovery_relays.clone(),
            settlement_quiescence_ms,
        );
        config.usage_diagnostics_silent = true;
        app_for_config(
            home.clone(),
            relay
                .clone()
                .or_else(|| cli.daemon_discovery_relays.first().cloned())
                .or_else(|| cli.daemon_default_account_relays.first().cloned()),
            account_home.clone(),
            root_owner,
            config,
        )
    };
    match command {
        Command::UsageDiagnostics { command } => {
            let runtime = app()?.runtime();
            marmot_app::configure_product_analytics_from_environment(&runtime, "daemon");
            usage_diagnostics_command(&runtime, command)
        }
        Command::Devices { .. } => Err(WnError::DevicesRequireDaemon),
        Command::Debug { command } => {
            commands::debug::debug_command(&account_home, &app()?, command, account_flag)
        }
        Command::CreateIdentity => {
            commands::account::identity_create_command(
                &app()?,
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
            commands::account::identity_login_command(
                &app()?,
                runtime_info,
                identity,
                import_nsec.take(),
                nsec_stdin,
                relay,
                cli.daemon_default_account_relays,
                cli.daemon_discovery_relays,
            )
            .await
        }
        Command::Whoami => {
            commands::account::whoami_command(&account_home, &app()?, runtime_info, account_flag)
        }
        Command::Logout { pubkey } => commands::account::logout_command(&account_home, pubkey),
        Command::ExportNsec { pubkey } => commands::account::export_nsec_command(pubkey),
        Command::Account { command } => {
            commands::account::account_command(
                &account_home,
                &app()?,
                command,
                runtime_info,
                account_flag,
                relay,
                import_nsec.take(),
            )
            .await
        }
        Command::Accounts { command } => {
            commands::account::account_command(
                &account_home,
                &app()?,
                command,
                runtime_info,
                account_flag,
                relay,
                import_nsec.take(),
            )
            .await
        }
        Command::Keys { command } => {
            commands::key_package::key_package_command(
                &account_home,
                &app()?,
                command,
                account_flag,
            )
            .await
        }
        Command::Chats { command } => {
            commands::chats::chats_command(&account_home, &app()?, command, account_flag).await
        }
        Command::Media { command } => {
            commands::media::media_command(&account_home, &app()?, command, account_flag).await
        }
        Command::Group {
            command,
            accept_stale,
            accept_undelivered,
        } => {
            commands::groups::group_command(
                &account_home,
                &app()?,
                command,
                account_flag,
                crate::commands::groups::AcceptedGroupChangeRisks {
                    stale: accept_stale,
                    undelivered: accept_undelivered,
                },
            )
            .await
        }
        Command::Groups {
            command,
            accept_stale,
            accept_undelivered,
        } => {
            commands::groups::groups_command(
                &account_home,
                &app()?,
                command,
                account_flag,
                crate::commands::groups::AcceptedGroupChangeRisks {
                    stale: accept_stale,
                    undelivered: accept_undelivered,
                },
            )
            .await
        }
        Command::Message { command } => {
            commands::messages::message_command(&account_home, &app()?, command, account_flag).await
        }
        Command::Messages { command } => {
            commands::messages::message_command(&account_home, &app()?, command, account_flag).await
        }
        Command::Follows { command } => {
            commands::follows::follows_command(&account_home, &app()?, command, account_flag, relay)
                .await
        }
        Command::Profile { command } => {
            commands::profile::profile_command(&account_home, &app()?, command, account_flag, relay)
                .await
        }
        Command::Relays { command } => {
            commands::relays::relays_command(&account_home, &app()?, command, account_flag, relay)
                .await
        }
        Command::Settings { command } => commands::settings::settings_command(&home, command),
        Command::Users { command } => {
            commands::users::users_command(&account_home, &app()?, command, account_flag).await
        }
        Command::Notifications { command } => {
            commands::notifications::notifications_command(command)
        }
        Command::Daemon { .. } => Ok(CommandOutput {
            plain: "daemon command is handled by wn".to_owned(),
            json: json!({"handled": "client"}),
        }),
        Command::Sync => {
            let account = resolve_account(&account_home, account_flag)?;
            ensure_local_signing(&account)?;
            commands::sync::sync_command(&app()?, account).await
        }
        Command::RelayStats => commands::relay_stats::relay_stats_command(&app()?).await,
        Command::Reset { .. } => unreachable!("reset runs without opening the account home"),
    }
}

fn daemon_socket_for_client(cli: &Cli, home: &Path) -> Option<PathBuf> {
    let socket = daemon_socket_path_for_client(cli, home);
    let explicit_daemon_socket = cli.socket.is_some() || std::env::var_os("WN_SOCKET").is_some();
    if matches!(cli.command, Command::Logout { .. }) && !explicit_daemon_socket {
        return None;
    }
    if explicit_daemon_socket || socket.exists() {
        Some(socket)
    } else {
        None
    }
}

fn daemon_socket_path_for_client(cli: &Cli, home: &Path) -> PathBuf {
    let env_socket = std::env::var_os("WN_SOCKET").map(PathBuf::from);
    cli.socket
        .clone()
        .or(env_socket.clone())
        .unwrap_or_else(|| daemon::default_socket_path(home))
}

fn should_fallback_to_local_after_daemon_execute_error(
    explicit_daemon_socket: bool,
    err: &daemon::DaemonClientError,
) -> bool {
    !explicit_daemon_socket && matches!(err, daemon::DaemonClientError::Connect { .. })
}

fn daemon_execute_error(json_output: bool, err: daemon::DaemonClientError) -> CliOutput {
    match err {
        err @ daemon::DaemonClientError::Connect { .. } => daemon_client_error(json_output, err),
        err @ daemon::DaemonClientError::ServerBusy => {
            daemon_client_error_with_code(json_output, "server_busy", err)
        }
        err => daemon_execute_state_unknown_error(json_output, err),
    }
}

fn daemon_execute_state_unknown_error(
    json_output: bool,
    err: daemon::DaemonClientError,
) -> CliOutput {
    let message = format!(
        "daemon response was lost after the request was sent; command state is unknown: {err}"
    );
    if json_output {
        return CliOutput {
            code: 1,
            stdout: format!(
                "{}\n",
                serde_json::to_string(&json!({
                    "ok": false,
                    "error": {
                        "code": "daemon_state_unknown",
                        "message": message,
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
        stderr: format!("error: {message}\n"),
    }
}

fn daemon_client_error(json_output: bool, err: daemon::DaemonClientError) -> CliOutput {
    daemon_client_error_with_code(json_output, "daemon_unavailable", err)
}

fn daemon_client_error_with_code(
    json_output: bool,
    code: &str,
    err: daemon::DaemonClientError,
) -> CliOutput {
    if json_output {
        return CliOutput {
            code: 1,
            stdout: format!(
                "{}\n",
                serde_json::to_string(&json!({
                    "ok": false,
                    "error": {
                        "code": code,
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
        stderr: format!("error: {}\n", terminal_safe_text(&err.to_string())),
    }
}

pub(crate) fn group_show_output(
    app: &MarmotApp,
    account: marmot_account::AccountSummary,
    group: String,
    mls: Option<Value>,
) -> Result<CommandOutput, WnError> {
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
            "npub": npub_for_account_id(&account.account_id_hex)?,
            "group": group,
            "mls": mls,
        }),
        None => json!({
            "account_id": account.account_id_hex,
            "npub": npub_for_account_id(&account.account_id_hex)?,
            "group": group,
        }),
    };
    Ok(CommandOutput { plain, json })
}

pub(crate) fn replaceable_list_inconclusive(
    list: &str,
    account_id: &str,
    source_relays: &[TransportEndpoint],
) -> WnError {
    WnError::ReplaceableListInconclusive {
        list: list.to_owned(),
        account_id: account_id.to_owned(),
        source_relays: source_relays
            .iter()
            .map(|endpoint| endpoint.0.clone())
            .collect(),
    }
}

fn reset_command(home: &Path, confirm: bool) -> Result<CommandOutput, WnError> {
    if !confirm {
        return Err(WnError::ConfirmationRequired {
            command: "reset",
            flag: "--confirm",
            reason: "pass --confirm to delete all local White Noise data",
        });
    }
    #[cfg(unix)]
    let reset = reset_tree::reset_home(home);
    #[cfg(not(unix))]
    let reset: Result<(), WnError> = Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "local reset requires Unix directory descriptors",
    )
    .into());
    reset?;
    Ok(CommandOutput {
        plain: format!("deleted local data in {}", home.display()),
        json: json!({
            "deleted": true,
            "home": home,
        }),
    })
}

#[cfg(unix)]
mod reset_tree {
    use std::ffi::{CStr, CString, OsStr};
    use std::io;
    use std::mem::MaybeUninit;
    use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    use std::ptr::NonNull;

    use fs_private::{PrivateExclusiveFileLease, try_acquire_lease_at};
    use marmot_account::{CREDENTIAL_STORE_LOCK_FILE, ROOT_MUTATION_LOCK_FILE};
    use marmot_app::{AppError, MARMOT_ROOT_RUNTIME_LOCK_FILE};

    use super::WnError;

    const RUNTIME_BUSY: &str = "marmot runtime root is already in use";
    const MUTATION_BUSY: &str = "account mutation is already in progress";
    const CREDENTIAL_BUSY: &str = "credential store is already in use";
    const COORDINATION: [(&str, &str); 3] = [
        (MARMOT_ROOT_RUNTIME_LOCK_FILE, RUNTIME_BUSY),
        (ROOT_MUTATION_LOCK_FILE, MUTATION_BUSY),
        (CREDENTIAL_STORE_LOCK_FILE, CREDENTIAL_BUSY),
    ];

    pub(super) fn reset_home(home: &Path) -> Result<(), WnError> {
        if home.as_os_str().is_empty() {
            return Err(
                io::Error::new(io::ErrorKind::InvalidInput, "home path must not be empty").into(),
            );
        }
        if let Some(root) = fs_private::inspect_directory_path(home)? {
            ResetPlan::new(root.as_fd(), home)?.delete()?;
        }
        Ok(())
    }

    struct ResetPlan<'a> {
        root: BorrowedFd<'a>,
        _runtime: PrivateExclusiveFileLease,
        _mutation: PrivateExclusiveFileLease,
        _credential: PrivateExclusiveFileLease,
        lock_names: [CString; 3],
        leases: Vec<PrivateExclusiveFileLease>,
        entries: Vec<ResetEntry>,
        survivors: usize,
    }

    struct ResetEntry {
        name: CString,
        identity: (u64, u64),
        kind: ResetEntryKind,
    }

    enum ResetEntryKind {
        File,
        Lease,
        Directory(ResetChildren),
    }

    struct ResetChildren {
        len: usize,
        survivors: usize,
    }

    impl<'a> ResetPlan<'a> {
        fn new(root: BorrowedFd<'a>, home: &Path) -> Result<Self, WnError> {
            let runtime =
                match try_acquire_lease_at(root, OsStr::new(MARMOT_ROOT_RUNTIME_LOCK_FILE)) {
                    Ok(lease) => lease,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        return Err(AppError::RuntimeBusy.into());
                    }
                    Err(error) => return Err(error.into()),
                };
            let mut plan = Self {
                root,
                _runtime: runtime,
                _mutation: acquire_lease(
                    root,
                    home,
                    OsStr::new(ROOT_MUTATION_LOCK_FILE),
                    MUTATION_BUSY,
                )?,
                _credential: acquire_lease(
                    root,
                    home,
                    OsStr::new(CREDENTIAL_STORE_LOCK_FILE),
                    CREDENTIAL_BUSY,
                )?,
                lock_names: COORDINATION.map(|(name, _)| CString::new(name).unwrap()),
                leases: Vec::new(),
                entries: Vec::new(),
                survivors: 0,
            };
            plan.survivors = plan.scan(root, &mut home.to_path_buf())?;
            Ok(plan)
        }

        fn scan(&mut self, parent: BorrowedFd<'_>, path: &mut PathBuf) -> io::Result<usize> {
            let is_root = parent.as_raw_fd() == self.root.as_raw_fd();
            // Resolve canonical names as the writers do, including on case-insensitive volumes.
            let mut locked = [None; COORDINATION.len()];
            for (slot, (name, (_, busy))) in locked
                .iter_mut()
                .zip(self.lock_names.iter().zip(COORDINATION))
            {
                match stat_at(parent, name) {
                    Ok(stat) => {
                        if !is_root {
                            self.leases.push(acquire_lease(
                                parent,
                                path,
                                OsStr::from_bytes(name.to_bytes()),
                                busy,
                            )?);
                        }
                        *slot = Some(stat.identity);
                    }
                    Err(error) if !is_root && error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                }
            }
            let mut stream = DirStream::open(parent)?;
            let mut survivors = 0;
            while let Some(name) = stream.next_name()? {
                let file_name = OsStr::from_bytes(name.to_bytes());
                let stat = stat_at(parent, name)?;
                let is_lease = locked.contains(&Some(stat.identity));
                if is_lease {
                    survivors += 1;
                }

                let index = self.entries.len();
                self.entries.push(ResetEntry {
                    name: name.to_owned(),
                    identity: stat.identity,
                    kind: if is_lease {
                        ResetEntryKind::Lease
                    } else {
                        ResetEntryKind::File
                    },
                });
                if stat.directory && !is_lease {
                    let child = self.entries[index].open_dir(parent)?;
                    path.push(file_name);
                    let child_survivors = self.scan(child.as_fd(), path)?;
                    path.pop();
                    self.entries[index].kind = ResetEntryKind::Directory(ResetChildren {
                        len: self.entries.len() - index - 1,
                        survivors: child_survivors,
                    });
                    survivors += usize::from(child_survivors != 0);
                }
            }
            Ok(survivors)
        }

        fn delete(self) -> io::Result<()> {
            remove_entries(self.root, &self.entries)?;
            check_remaining(self.root, &self.entries, self.survivors)
        }
    }

    impl ResetEntry {
        fn open_dir(&self, parent: BorrowedFd<'_>) -> io::Result<OwnedFd> {
            let directory = open_dir_at(parent, &self.name)?;
            self.check_identity(stat_at(directory.as_fd(), c".")?.identity)?;
            Ok(directory)
        }

        fn check_identity(&self, identity: (u64, u64)) -> io::Result<()> {
            if self.identity == identity {
                Ok(())
            } else {
                Err(io::Error::other(format!(
                    "reset entry changed: {:?}",
                    self.name
                )))
            }
        }
    }

    // Preorder entries encode each directory's descendants in a contiguous span.
    // Reopen only those directories, and never recursively unlink new arrivals.
    fn remove_entries(parent: BorrowedFd<'_>, mut entries: &[ResetEntry]) -> io::Result<()> {
        while let Some((entry, rest)) = entries.split_first() {
            let flags = match &entry.kind {
                ResetEntryKind::Lease => {
                    entries = rest;
                    continue;
                }
                ResetEntryKind::Directory(children) => {
                    let child = entry.open_dir(parent)?;
                    let (descendants, siblings) = rest.split_at(children.len);
                    remove_entries(child.as_fd(), descendants)?;
                    entries = siblings;
                    if children.survivors != 0 {
                        check_remaining(child.as_fd(), descendants, children.survivors)?;
                        entry.check_identity(stat_at(parent, &entry.name)?.identity)?;
                        continue;
                    }
                    libc::AT_REMOVEDIR
                }
                ResetEntryKind::File => {
                    entries = rest;
                    0
                }
            };
            entry.check_identity(stat_at(parent, &entry.name)?.identity)?;
            // The parent remains pinned and the name is one directory entry.
            if unsafe { libc::unlinkat(parent.as_raw_fd(), entry.name.as_ptr(), flags) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    // Retained directories do not get the emptiness check from unlinkat.
    fn check_remaining(
        parent: BorrowedFd<'_>,
        mut entries: &[ResetEntry],
        survivors: usize,
    ) -> io::Result<()> {
        while let Some((entry, rest)) = entries.split_first() {
            entries = rest;
            let retained = match &entry.kind {
                ResetEntryKind::Lease => true,
                ResetEntryKind::File => false,
                ResetEntryKind::Directory(children) => {
                    entries = &rest[children.len..];
                    children.survivors != 0
                }
            };
            if retained {
                entry.check_identity(stat_at(parent, &entry.name)?.identity)?;
            }
        }
        let mut stream = DirStream::open(parent)?;
        for _ in 0..survivors {
            if stream.next_name()?.is_none() {
                return Err(io::Error::other("reset directory lost a retained entry"));
            }
        }
        if stream.next_name()?.is_some() {
            return Err(io::Error::other(
                "reset directory gained an unplanned entry",
            ));
        }
        Ok(())
    }

    fn acquire_lease(
        parent: BorrowedFd<'_>,
        path: &Path,
        name: &OsStr,
        busy: &str,
    ) -> io::Result<PrivateExclusiveFileLease> {
        try_acquire_lease_at(parent, name).map_err(|error| {
            let path = path.join(name);
            let message = if error.kind() == io::ErrorKind::WouldBlock {
                format!("{busy}: {}", path.display())
            } else {
                format!("acquire reset lease at {}: {error}", path.display())
            };
            io::Error::new(error.kind(), message)
        })
    }

    fn open_dir_at(parent: BorrowedFd<'_>, name: &CStr) -> io::Result<OwnedFd> {
        // name is either one directory entry or `.`.
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // openat returned a new descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    struct EntryStat {
        identity: (u64, u64),
        directory: bool,
    }

    #[allow(clippy::unnecessary_cast)] // libc stat field widths vary across Unix targets.
    fn stat_at(parent: BorrowedFd<'_>, name: &CStr) -> io::Result<EntryStat> {
        let mut stat = MaybeUninit::uninit();
        // fstatat initializes stat on success without following a leaf symlink.
        if unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let stat = unsafe { stat.assume_init() };
        Ok(EntryStat {
            identity: (stat.st_dev as u64, stat.st_ino as u64),
            directory: stat.st_mode & libc::S_IFMT == libc::S_IFDIR,
        })
    }

    struct DirStream(NonNull<libc::DIR>);

    impl DirStream {
        fn open(directory: BorrowedFd<'_>) -> io::Result<Self> {
            let fd = open_dir_at(directory, c".")?;
            // On success fdopendir owns the descriptor; on error fd still owns it.
            let stream = NonNull::new(unsafe { libc::fdopendir(fd.as_raw_fd()) })
                .ok_or_else(io::Error::last_os_error)?;
            let _ = fd.into_raw_fd();
            Ok(Self(stream))
        }

        fn next_name(&mut self) -> io::Result<Option<&CStr>> {
            loop {
                // readdir returns null both at EOF and on error. Clear this
                // thread's errno so the two cases are distinguishable.
                let entry = unsafe {
                    *errno_location() = 0;
                    libc::readdir(self.0.as_ptr())
                };
                if entry.is_null() {
                    let error = unsafe { *errno_location() };
                    return if error == 0 {
                        Ok(None)
                    } else {
                        Err(io::Error::from_raw_os_error(error))
                    };
                }
                // The stream owns this NUL-terminated name until the next read.
                let name = unsafe { CStr::from_ptr((&raw const (*entry).d_name).cast()) };
                if !matches!(name.to_bytes(), b"." | b"..") {
                    return Ok(Some(name));
                }
            }
        }
    }

    impl Drop for DirStream {
        fn drop(&mut self) {
            // closedir releases both the stream and its descriptor.
            unsafe { libc::closedir(self.0.as_ptr()) };
        }
    }

    unsafe extern "C" {
        #[cfg_attr(
            any(target_vendor = "apple", target_os = "freebsd"),
            link_name = "__error"
        )]
        #[cfg_attr(
            any(
                target_os = "android",
                target_os = "netbsd",
                target_os = "openbsd",
                target_os = "cygwin",
                target_env = "newlib"
            ),
            link_name = "__errno"
        )]
        #[cfg_attr(
            any(target_os = "illumos", target_os = "solaris"),
            link_name = "___errno"
        )]
        #[cfg_attr(target_os = "haiku", link_name = "_errnop")]
        #[cfg_attr(
            any(
                target_os = "linux",
                target_os = "dragonfly",
                target_os = "hurd",
                target_os = "emscripten",
                target_os = "redox"
            ),
            link_name = "__errno_location"
        )]
        #[cfg_attr(target_os = "aix", link_name = "_Errno")]
        #[cfg_attr(target_os = "nto", link_name = "__get_errno_ptr")]
        fn errno_location() -> *mut libc::c_int;
    }

    #[cfg(test)]
    mod tests {
        use std::fs;
        use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

        use super::*;

        const OUTSIDE_FILES: [&str; 4] = [
            "payload",
            MARMOT_ROOT_RUNTIME_LOCK_FILE,
            ROOT_MUTATION_LOCK_FILE,
            CREDENTIAL_STORE_LOCK_FILE,
        ];

        fn outside_fixture(path: &Path) -> [fs::File; 4] {
            fs::create_dir(path).unwrap();
            OUTSIDE_FILES.map(|name| {
                let file = path.join(name);
                fs::write(&file, b"outside reset").unwrap();
                fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
                fs::File::open(file).unwrap()
            })
        }

        fn assert_outside_unchanged(path: &Path, originals: &[fs::File; 4]) {
            for (name, original) in OUTSIDE_FILES.into_iter().zip(originals) {
                let file = path.join(name);
                assert_eq!(fs::read(&file).unwrap(), b"outside reset");
                let before = original.metadata().unwrap();
                let after = file.metadata().unwrap();
                assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
                assert_eq!(after.mode() & 0o777, 0o644);
            }
            assert_eq!(fs::read_dir(path).unwrap().count(), OUTSIDE_FILES.len());
        }

        #[test]
        fn reset_respects_lock_aliases() {
            let home = tempfile::tempdir().unwrap();
            let nested = home.path().join("vault");
            fs::create_dir(&nested).unwrap();
            let lock_dirs = [home.path(), &nested];
            for path in lock_dirs {
                for (name, _) in COORDINATION {
                    fs::write(path.join(name.to_ascii_uppercase()), b"").unwrap();
                }
            }
            let insensitive = home.path().join(ROOT_MUTATION_LOCK_FILE).exists();
            let payload = nested.join("payload");
            fs::write(&payload, b"remove").unwrap();

            reset_home(home.path()).unwrap();
            assert!(!payload.exists());
            for path in lock_dirs {
                for (name, _) in COORDINATION {
                    assert_eq!(path.join(name.to_ascii_uppercase()).exists(), insensitive);
                }
            }
        }

        #[test]
        fn reset_stays_on_verified_root() {
            let base = tempfile::tempdir().unwrap();
            let home = base.path().join("home");
            let original = base.path().join("original");
            let outside = base.path().join("outside");
            let outside_files = outside_fixture(&outside);
            fs::create_dir(&home).unwrap();
            let data = OsStr::from_bytes(b"payload-\xff");
            fs::write(home.join(data), b"inside reset").unwrap();
            let root = fs_private::inspect_directory_path(&home).unwrap().unwrap();

            fs::rename(&home, &original).unwrap();
            symlink(&outside, &home).unwrap();

            ResetPlan::new(root.as_fd(), &home)
                .unwrap()
                .delete()
                .unwrap();
            assert!(!original.join(data).try_exists().unwrap());
            for name in &OUTSIDE_FILES[1..] {
                assert!(original.join(name).is_file());
            }
            assert_eq!(fs::read_link(&home).unwrap(), outside);
            assert_outside_unchanged(&outside, &outside_files);
        }

        #[test]
        fn reset_refuses_nested_symlink() {
            let base = tempfile::tempdir().unwrap();
            let home = base.path().join("home");
            let accounts = home.join("accounts");
            let original = base.path().join("original");
            let outside = base.path().join("outside");
            let outside_files = outside_fixture(&outside);
            fs::create_dir_all(&accounts).unwrap();
            fs::write(accounts.join("payload"), b"inside reset").unwrap();
            let root = fs_private::inspect_directory_path(&home).unwrap().unwrap();
            let plan = ResetPlan::new(root.as_fd(), &home).unwrap();

            fs::rename(&accounts, &original).unwrap();
            symlink(&outside, &accounts).unwrap();

            let error = plan.delete().unwrap_err();
            assert!(
                matches!(error.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR)),
                "{error}"
            );
            assert_eq!(fs::read_link(&accounts).unwrap(), outside);
            assert_eq!(fs::read(original.join("payload")).unwrap(), b"inside reset");
            assert_outside_unchanged(&outside, &outside_files);
        }

        #[test]
        fn reset_refuses_replaced_dir() {
            let base = tempfile::tempdir().unwrap();
            let home = base.path().join("home");
            let accounts = home.join("accounts");
            let original = base.path().join("original");
            fs::create_dir_all(&accounts).unwrap();
            fs::write(accounts.join("payload"), b"inside reset").unwrap();
            let root = fs_private::inspect_directory_path(&home).unwrap().unwrap();
            let plan = ResetPlan::new(root.as_fd(), &home).unwrap();

            fs::rename(&accounts, &original).unwrap();
            let replacement_files = outside_fixture(&accounts);

            let error = plan.delete().unwrap_err();
            assert_eq!(error.to_string(), "reset entry changed: \"accounts\"");
            assert_eq!(fs::read(original.join("payload")).unwrap(), b"inside reset");
            assert_outside_unchanged(&accounts, &replacement_files);
        }

        #[test]
        fn reset_reports_new_entries() {
            let base = tempfile::tempdir().unwrap();
            let home = base.path().join("home");
            fs::create_dir(&home).unwrap();
            let root = fs_private::inspect_directory_path(&home).unwrap().unwrap();
            let plan = ResetPlan::new(root.as_fd(), &home).unwrap();
            let new = home.join("new");
            fs::create_dir(&new).unwrap();
            fs::write(new.join("payload"), b"not in snapshot").unwrap();

            let error = plan.delete().unwrap_err();
            assert_eq!(
                error.to_string(),
                "reset directory gained an unplanned entry"
            );
            assert_eq!(fs::read(new.join("payload")).unwrap(), b"not in snapshot");
        }

        #[test]
        fn reset_checks_retained_locks() {
            for (directory, replacement) in [
                ("", "identity-copy.json"),
                ("nested", "identity-copy.json"),
                ("", ROOT_MUTATION_LOCK_FILE),
                ("nested", ROOT_MUTATION_LOCK_FILE),
            ] {
                let base = tempfile::tempdir().unwrap();
                let home = base.path().join("home");
                let parent = home.join(directory);
                fs::create_dir_all(&parent).unwrap();
                fs::write(parent.join(ROOT_MUTATION_LOCK_FILE), b"").unwrap();
                fs::write(home.join("payload"), b"inside reset").unwrap();
                let root = fs_private::inspect_directory_path(&home).unwrap().unwrap();
                let plan = ResetPlan::new(root.as_fd(), &home).unwrap();

                fs::rename(
                    parent.join(ROOT_MUTATION_LOCK_FILE),
                    base.path().join("old-lock"),
                )
                .unwrap();
                let unplanned = parent.join(replacement);
                fs::write(&unplanned, b"unplanned secret").unwrap();

                assert!(plan.delete().is_err(), "{directory}: {replacement}");
                assert_eq!(fs::read(unplanned).unwrap(), b"unplanned secret");
            }
        }
    }
}

pub(crate) fn unix_now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(crate) fn profile_display_name(profile: Option<&UserProfileMetadata>) -> Option<String> {
    let profile = profile?;
    profile
        .display_name
        .as_deref()
        .or(profile.name.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

pub(crate) fn group_list_plain(groups: &[AppGroupRecord]) -> String {
    if groups.is_empty() {
        return "no groups".to_owned();
    }
    groups
        .iter()
        .map(group_plain)
        .collect::<Vec<_>>()
        .join("\n")
}

pub(crate) fn group_plain(group: &AppGroupRecord) -> String {
    let mut line = format!(
        "{} name={} endpoint={}",
        terminal_safe_text(&group.group_id_hex),
        terminal_safe_text(&group.profile.name),
        terminal_safe_text(&group.endpoint)
    );
    if group.avatar_url.present {
        line.push_str(&format!(
            " avatar_url={}",
            terminal_safe_text(&group.avatar_url.url)
        ));
        if let Some(dim) = &group.avatar_url.dim {
            line.push_str(&format!(" avatar_dim={}", terminal_safe_text(dim)));
        }
        if let Some(thumbhash) = &group.avatar_url.thumbhash {
            line.push_str(&format!(
                " avatar_thumbhash={}",
                terminal_safe_text(thumbhash)
            ));
        }
    }
    line
}

pub(crate) fn group_json(group: AppGroupRecord) -> Value {
    json!({
        "group_id": group.group_id_hex,
        "endpoint": group.endpoint,
        "profile": group.profile,
        // Presence, hash, and type only. The full component carries the avatar
        // decryption key, the Blossom upload secret, and key-bearing `data_hex`;
        // none of the CLI or daemon consumers need them (mdk#1253).
        "image": crate::commands::groups::group_image_summary_json(&group.image),
        "avatar_url": group.avatar_url,
        "admin_policy": group.admin_policy,
        "nostr_routing": group.nostr_routing,
        "encrypted_media": group.encrypted_media,
        "message_retention": group.message_retention,
        "archived": group.archived,
        "pending_confirmation": group.pending_confirmation,
        "welcomer_account_id": group.welcomer_account_id_hex,
        "via_welcome_message_id": group.via_welcome_message_id_hex,
        // Lifecycle projection (additive, mdk#1788): whether ordinary outbound
        // work is gated by a disband in flight, the durable local request
        // outcome, the terminal flag, and the local membership classification.
        "disbanding": group.disbanding,
        "disbanded": group.disbanded,
        "disband_request": group.disband_request,
        "unrecoverable": group.unrecoverable,
        "self_membership": self_membership_json(&group),
        "leave_requested_at_ms": group.leave_requested_at_ms,
    })
}

/// The local membership classification as a stable snake_case token, matching
/// the other lifecycle strings in CLI JSON rather than the storage enum's Rust
/// variant spelling.
pub(crate) fn self_membership_json(group: &AppGroupRecord) -> Value {
    json!(self_membership_token(group.self_membership))
}

/// `member`, `left`, `removed`, or `device_removed` (this device's leaf was
/// removed while the account stays in the group, mdk#2628 D62).
fn self_membership_token(membership: SelfMembership) -> &'static str {
    match membership {
        SelfMembership::Member => "member",
        SelfMembership::Left => "left",
        SelfMembership::Removed => "removed",
        SelfMembership::DeviceRemoved => "device_removed",
    }
}

/// Render a `chats` row: the group record (`group_json`) enriched with the
/// runtime's durable per-chat projection state so a chat-list UI can bootstrap
/// unread badges and a last-message preview without a second query. Consumed by
/// `chats list`, `chats list-archived`, and the `chats subscribe`/
/// `subscribe-archived` feeds so those surfaces stay byte-identical.
pub(crate) fn chat_json(group: AppGroupRecord, chat_list_row: Option<ChatListRow>) -> Value {
    let mut value = group_json(group);
    insert_chat_projection(&mut value, chat_list_row);
    value
}

/// Project the durable `ChatListRow` state onto a chats row as additive keys.
///
/// The field names and the `last_message` preview shape mirror the
/// `chat_list_row` object embedded on every `timeline_projection_updated`
/// event, so the snapshot feed (`chats list`/`subscribe`) and the live timeline
/// feed agree key-for-key. The surface is deliberately the minimal reviewed set
/// — unread state, durable `activity_sort_at`, a last-message preview, and the
/// last-read marker — rather than the full `ChatListRow` (whose title/avatar/membership fields either
/// duplicate `group_json` or are group-state concerns).
///
/// The keys are always present: a group with no projection row yet (or no
/// messages/reads) reports empty defaults (`0`/`false`/`null`), matching the
/// always-present `avatar_url` block convention rather than omitting keys.
pub(crate) fn insert_chat_projection(value: &mut Value, chat_list_row: Option<ChatListRow>) {
    let Some(object) = value.as_object_mut() else {
        return;
    };
    let (
        unread_count,
        has_unread,
        activity_sort_at,
        last_message,
        last_read_message_id_hex,
        last_read_timeline_at,
    ) = match chat_list_row {
        Some(row) => (
            json!(row.unread_count),
            json!(row.has_unread),
            json!(row.activity_sort_at),
            json!(row.last_message),
            json!(row.last_read_message_id_hex),
            json!(row.last_read_timeline_at),
        ),
        None => (
            json!(0),
            json!(false),
            json!(0),
            Value::Null,
            Value::Null,
            Value::Null,
        ),
    };
    object.insert("unread_count".to_owned(), unread_count);
    object.insert("has_unread".to_owned(), has_unread);
    object.insert("activity_sort_at".to_owned(), activity_sort_at);
    object.insert("last_message".to_owned(), last_message);
    object.insert(
        "last_read_message_id_hex".to_owned(),
        last_read_message_id_hex,
    );
    object.insert("last_read_timeline_at".to_owned(), last_read_timeline_at);
}

pub(crate) fn display_name_for_sender(app: &MarmotApp, sender: &str) -> Option<String> {
    let account_id = parse_public_key(sender).ok()?;
    let profile = app
        .directory()
        .directory_entry_for_account_id(&account_id)
        .ok()
        .flatten()
        .and_then(|entry| entry.profile);
    profile_display_name(profile.as_ref())
}

fn resolve_relay(relay: Option<String>) -> Result<Option<String>, WnError> {
    match relay.or_else(|| std::env::var("WN_RELAY").ok()) {
        Some(relay) => validate_relay_url(relay).map(Some),
        None => Ok(None),
    }
}

pub(crate) fn validate_relay_url(relay: impl AsRef<str>) -> Result<String, WnError> {
    let relay = relay.as_ref().trim();
    if relay.is_empty() {
        return Err(WnError::EmptyRelayUrl);
    }
    let parsed = url::Url::parse(relay).map_err(|_| WnError::InvalidRelayUrl(relay.to_owned()))?;
    let Some(host) = parsed.host() else {
        return Err(WnError::InvalidRelayUrl(relay.to_owned()));
    };
    let scheme_allowed = parsed.scheme() == "wss"
        || (parsed.scheme() == "ws"
            && wn_allow_loopback_relays()
            && cgka_traits::app_components::is_loopback_host(host));
    if !scheme_allowed {
        return Err(WnError::InvalidRelayUrl(relay.to_owned()));
    }
    Ok(relay.to_owned())
}

pub(crate) fn relay_endpoints(values: Vec<String>) -> Result<Vec<TransportEndpoint>, WnError> {
    let mut endpoints = Vec::new();
    for value in values {
        let endpoint = TransportEndpoint(validate_relay_url(value)?);
        if !endpoints.contains(&endpoint) {
            endpoints.push(endpoint);
        }
    }
    Ok(endpoints)
}

pub(crate) fn account_selector_or_default(
    account_home: &AccountHome,
    account_ref: Option<String>,
    default_account: Option<String>,
) -> Result<String, WnError> {
    if let Some(account_ref) = account_ref {
        return parse_public_key(&account_ref);
    }
    Ok(resolve_account(account_home, default_account)?.account_id_hex)
}

pub(crate) fn resolve_account(
    account_home: &AccountHome,
    explicit: Option<String>,
) -> Result<marmot_account::AccountSummary, WnError> {
    if let Some(account) = explicit
        .or_else(|| std::env::var("WN_ACCOUNT").ok())
        .filter(|account| !account.trim().is_empty())
    {
        return resolve_account_ref(account_home, &account);
    }

    let accounts = account_home.accounts()?;
    match accounts.as_slice() {
        [] => Err(WnError::MissingAccount),
        [account] => Ok(account.clone()),
        _ => Err(WnError::MultipleAccounts),
    }
}

pub(crate) fn resolve_account_ref(
    account_home: &AccountHome,
    value: &str,
) -> Result<marmot_account::AccountSummary, WnError> {
    let account_id_hex = parse_public_key(value)?;
    for account in account_home.accounts()? {
        if account.account_id_hex == account_id_hex {
            return Ok(account);
        }
    }

    Err(WnError::UnknownLocalAccount(value.to_owned()))
}

pub(crate) fn ensure_local_signing(
    account: &marmot_account::AccountSummary,
) -> Result<(), WnError> {
    if account.local_signing {
        Ok(())
    } else {
        Err(WnError::PublicAccountCannotSign)
    }
}

pub(crate) fn parse_public_key(value: &str) -> Result<String, WnError> {
    nostr::prelude::PublicKey::parse(value)
        .map(|pubkey| pubkey.to_hex())
        .map_err(|_| WnError::InvalidPublicKey)
}

pub(crate) fn npub_for_account_id(account_id: &str) -> Result<String, WnError> {
    marmot_app::npub_for_account_id(account_id).map_err(WnError::from)
}

pub(crate) fn normalize_group_id_hex(value: &str) -> Result<String, WnError> {
    Ok(hex::encode(hex::decode(value)?))
}

pub(crate) fn relay_lists_json(status: AccountRelayListStatus) -> Value {
    json!({
        "complete": status.complete,
        "missing": status.missing,
        "default_relays": status.default_relays,
        "bootstrap_relays": status.bootstrap_relays,
        "nip65": status.nip65,
        "inbox": status.inbox,
    })
}

fn app_for(
    home: PathBuf,
    relay: Option<String>,
    directory_relays: Vec<String>,
    account_home: AccountHome,
    root_owner: Option<&marmot_app::MarmotRootRuntimeLease>,
) -> Result<MarmotApp, WnError> {
    app_for_role(
        home,
        relay,
        directory_relays,
        account_home,
        true,
        root_owner,
    )
}

fn app_for_role(
    home: PathBuf,
    relay: Option<String>,
    directory_relays: Vec<String>,
    account_home: AccountHome,
    silent: bool,
    root_owner: Option<&marmot_app::MarmotRootRuntimeLease>,
) -> Result<MarmotApp, WnError> {
    let settlement_quiescence_ms = wn_dev_settlement_quiescence_ms()?;
    let mut config = cli_app_config(directory_relays, settlement_quiescence_ms);
    config.usage_diagnostics_silent = silent;
    app_for_config(home, relay, account_home, root_owner, config)
}

fn cli_app_config(
    directory_relays: Vec<String>,
    settlement_quiescence_ms: Option<u64>,
) -> MarmotAppConfig {
    // Loopback-HTTP blob endpoints are only acted on when explicitly enabled for
    // dev/test (see MarmotAppConfig::allow_loopback_blob_endpoints). Opt in via
    // WN_ALLOW_LOOPBACK_BLOB_ENDPOINTS=1 for local Blossom servers; production
    // installs leave it unset.
    let mut config = MarmotAppConfig::white_noise()
        .with_allow_loopback_blob_endpoints(wn_allow_loopback_blob_endpoints())
        .with_allow_loopback_relay_endpoints(wn_allow_loopback_relays())
        .with_directory_relay_urls(directory_relays)
        .with_device_groups(wn_device_groups());
    // Explicit test builds only: WN_DEV_SETTLEMENT_QUIESCENCE_MS overrides the
    // pinned convergence settlement window (e.g. `0` for integration tests).
    if let Some(ms) = settlement_quiescence_ms {
        config = config.with_dev_settlement_quiescence_ms(ms);
    }
    config
}

fn app_for_config(
    home: PathBuf,
    relay: Option<String>,
    account_home: AccountHome,
    root_owner: Option<&marmot_app::MarmotRootRuntimeLease>,
    config: MarmotAppConfig,
) -> Result<MarmotApp, WnError> {
    if root_owner.is_none() {
        return Ok(MarmotApp::try_with_relays_and_account_home_and_config(
            home,
            relay.into_iter().collect(),
            account_home,
            config,
        )?);
    }
    // The daemon owns the lease until its requests and runtime have shut down.
    Ok(MarmotApp::with_relays_and_account_home_and_config(
        home,
        relay.into_iter().collect(),
        account_home,
        config,
    ))
}

fn wn_allow_loopback_blob_endpoints() -> bool {
    matches!(
        std::env::var("WN_ALLOW_LOOPBACK_BLOB_ENDPOINTS").as_deref(),
        Ok("1") | Ok("true")
    )
}

/// Multi-device (device linking with `wn devices`, the device roster, admin
/// step-down on Leave) is on unless `WN_DEVICE_GROUPS` turns it off; `wn` and
/// `wnd` must share the setting.
pub(crate) fn wn_device_groups() -> bool {
    device_groups_setting(std::env::var("WN_DEVICE_GROUPS").ok().as_deref())
}

/// `0`, `false`, `off` or `no` (any case) turns device groups off; anything
/// else, or no value, leaves them on.
fn device_groups_setting(value: Option<&str>) -> bool {
    !value.is_some_and(|value| {
        ["0", "false", "off", "no"]
            .iter()
            .any(|off| value.trim().eq_ignore_ascii_case(off))
    })
}

/// Dev/test opt-in for opening relay connections to loopback/private endpoints
/// (e.g. a local `nostr-rs-relay` or an in-process `MockRelay`). Production
/// installs leave `WN_ALLOW_LOOPBACK_RELAYS` unset, so the relay-safety
/// chokepoint rejects non-public relay hosts. Mirrors
/// `WN_ALLOW_LOOPBACK_BLOB_ENDPOINTS`.
fn wn_allow_loopback_relays() -> bool {
    matches!(
        std::env::var("WN_ALLOW_LOOPBACK_RELAYS").as_deref(),
        Ok("1") | Ok("true")
    )
}

fn resolve_dev_settlement_quiescence_ms(
    value: Option<&str>,
    dev_overrides_enabled: bool,
) -> Result<Option<u64>, WnError> {
    if value.is_some() && !dev_overrides_enabled {
        return Err(WnError::DevSettlementOverrideInRelease);
    }
    Ok(value.and_then(|value| value.trim().parse().ok()))
}

fn wn_dev_settlement_quiescence_ms() -> Result<Option<u64>, WnError> {
    let value = std::env::var("WN_DEV_SETTLEMENT_QUIESCENCE_MS").ok();
    resolve_dev_settlement_quiescence_ms(value.as_deref(), cfg!(feature = "test-policy-overrides"))
}

fn open_account_home(
    home: &std::path::Path,
    secret_store: SecretStoreKind,
    keychain_service: &str,
) -> Result<AccountHome, WnError> {
    match secret_store {
        SecretStoreKind::File => Ok(AccountHome::open(home)),
        SecretStoreKind::Keychain => Ok(AccountHome::open_with_keychain(
            home,
            keychain_service,
            marmot_account::IosOptions::default(),
        )?),
    }
}

fn resolve_keychain_service(keychain_service: Option<String>) -> String {
    keychain_service
        .or_else(|| std::env::var("WN_KEYCHAIN_SERVICE").ok())
        .unwrap_or_else(|| marmot_app::MarmotDeployment::white_noise().keychain_service)
}

fn resolve_secret_store(secret_store: Option<SecretStoreKind>) -> Result<SecretStoreKind, WnError> {
    if let Some(secret_store) = secret_store {
        return Ok(secret_store);
    }
    match std::env::var("WN_SECRET_STORE") {
        Ok(value) => match value.trim() {
            "keychain" => Ok(SecretStoreKind::Keychain),
            "file" | "local-file" | "local_file" => Ok(SecretStoreKind::File),
            other => Err(WnError::InvalidSecretStore(other.to_owned())),
        },
        Err(_) => Ok(SecretStoreKind::Keychain),
    }
}

fn resolve_home(home: Option<PathBuf>) -> PathBuf {
    home.or_else(|| std::env::var_os("WN_HOME").map(PathBuf::from))
        .unwrap_or_else(default_home)
}

#[cfg(unix)]
fn normalize_standalone_home(home: PathBuf) -> std::io::Result<PathBuf> {
    use std::path::Component;

    let mut parts = home.components().peekable();
    if parts.peek() == Some(&Component::CurDir) {
        parts.next();
    }
    if parts.peek() != Some(&Component::ParentDir) {
        return Ok(home);
    }
    // Start above the caller's physical cwd; leave the rest to the no-follow walk.
    let mut path = std::env::current_dir()?;
    while parts.next_if_eq(&Component::ParentDir).is_some() {
        path.pop();
    }
    path.extend(parts);
    Ok(path)
}

fn default_home() -> PathBuf {
    default_home_from_env(|name| std::env::var_os(name))
}

fn default_home_from_env(mut var: impl FnMut(&str) -> Option<OsString>) -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Some(appdata) = var("APPDATA") {
            return PathBuf::from(appdata).join("whitenoise");
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(home) = var("HOME") {
            return PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("whitenoise");
        }
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(xdg_data_home) = var("XDG_DATA_HOME") {
            return PathBuf::from(xdg_data_home).join("whitenoise");
        }
        if let Some(home) = var("HOME") {
            return PathBuf::from(home)
                .join(".local")
                .join("share")
                .join("whitenoise");
        }
    }

    PathBuf::from(".whitenoise")
}

fn ensure_trailing_newline(mut value: String) -> String {
    if !value.ends_with('\n') {
        value.push('\n');
    }
    value
}

/// Render clap's help/version text as a successful JSON response. These clap
/// "errors" carry exit code 0 and their rendered string is the help/version
/// payload, so they must be reported as `ok: true` rather than wrapped as an
/// error object. `field` is `"help"` or `"version"`.
fn clap_display_json(code: i32, field: &str, text: String) -> CliOutput {
    CliOutput {
        code,
        stdout: format!(
            "{}\n",
            serde_json::to_string(&json!({
                "ok": true,
                "result": { field: text },
            }))
            .expect("JSON response serialization cannot fail")
        ),
        stderr: String::new(),
    }
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

fn json_wn_error(err: WnError) -> CliOutput {
    let error = wn_error_json(&err);
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

pub(crate) fn usage_diagnostics_command(
    runtime: &marmot_app::MarmotAppRuntime,
    command: UsageDiagnosticsCommand,
) -> Result<CommandOutput, WnError> {
    if !matches!(command, UsageDiagnosticsCommand::Show) {
        runtime
            .set_usage_diagnostics_consent(matches!(command, UsageDiagnosticsCommand::Enable))?;
    }
    let settings = runtime.stored_usage_diagnostics_settings()?;
    let mut status = runtime.usage_diagnostics_status();
    status.consent = runtime.usage_diagnostics_settings()?.decision;
    Ok(CommandOutput {
        plain: format!(
            "Saved usage and diagnostics permission: {:?}\nOTLP: {:?}\nProduct analytics: {:?}\n{}\n",
            settings.decision,
            status.telemetry,
            status.product_analytics,
            marmot_app::USAGE_DIAGNOSTICS_DISCLOSURE
        ),
        json: json!({"settings":settings,"status":status,"disclosure":marmot_app::USAGE_DIAGNOSTICS_DISCLOSURE}),
    })
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    use clap::Parser;

    use super::commands::account::{GlobalRelayDefaults, apply_global_relay_defaults};
    use super::commands::messages::{
        apply_message_cursors, reject_misplaced_reply_to, validate_message_list_cursors,
    };
    use super::commands::relay_stats::{relay_stats_output, relay_stats_plain};
    use super::{
        Cli, Command, WnError, daemon, daemon_socket_for_client, default_home_from_env,
        insert_chat_projection, npub_for_account_id, relay_endpoints,
        resolve_dev_settlement_quiescence_ms, resolve_relay, run_from,
    };

    use serde_json::json;

    /// `WN_DEVICE_GROUPS` turns device groups off only with an explicit off
    /// value; unset, `1`, `true` and anything unrecognized leave them on.
    #[test]
    fn device_groups_are_on_unless_explicitly_turned_off() {
        for on in [None, Some("1"), Some("true"), Some("yes"), Some("")] {
            assert!(super::device_groups_setting(on), "{on:?} keeps them on");
        }
        for off in ["0", "false", "FALSE", "off", "Off", "no", " 0 "] {
            assert!(
                !super::device_groups_setting(Some(off)),
                "{off:?} turns them off"
            );
        }
    }

    #[test]
    fn cli_wipe_needs_root_lease() {
        let home = tempfile::tempdir().unwrap();
        let pending = home.path().join(".wipe-tombstones").join("pending");
        crate::create_private_dir_all(&pending).unwrap();
        crate::write_private_file(
            &pending.join(".wipe-cleanup.json"),
            b"unreadable wipe intent",
        )
        .unwrap();
        crate::write_private_file(&pending.join("payload"), b"removed account payload").unwrap();

        let owner = marmot_app::MarmotRootRuntimeLease::try_acquire(home.path()).unwrap();
        let account_home = crate::open_account_home(
            home.path(),
            crate::SecretStoreKind::File,
            "wn-test-keychain",
        )
        .unwrap();
        assert!(pending.join("payload").exists());
        assert!(matches!(
            crate::app_for(
                home.path().to_path_buf(),
                None,
                Vec::new(),
                account_home.clone(),
                None,
            ),
            Err(WnError::App(marmot_app::AppError::RuntimeBusy))
        ));
        assert!(pending.join(".wipe-cleanup.json").exists());
        assert!(pending.join("payload").exists());

        drop(owner);
        let app = crate::app_for(
            home.path().to_path_buf(),
            None,
            Vec::new(),
            account_home,
            None,
        )
        .unwrap();
        assert!(!pending.join("payload").exists());
        assert!(pending.join(".wipe-cleanup.json").exists());
        drop(app);
    }

    #[test]
    fn chat_projection_emits_empty_defaults_when_no_row() {
        // A group with no chat-list projection row yet keeps every base key and
        // gains the projection keys as empty defaults (never absent).
        let mut value = json!({ "group_id": "abcd", "archived": false });
        insert_chat_projection(&mut value, None);
        assert_eq!(value["group_id"], "abcd");
        assert_eq!(value["archived"], false);
        assert_eq!(value["unread_count"], 0);
        assert_eq!(value["has_unread"], false);
        assert_eq!(value["activity_sort_at"], 0);
        assert!(value["last_message"].is_null());
        assert!(value["last_read_message_id_hex"].is_null());
        assert!(value["last_read_timeline_at"].is_null());
    }

    #[test]
    fn chat_projection_mirrors_timeline_chat_list_row_fields() {
        // `ChatListRow` is the exact type serialized as `chat_list_row` on the
        // timeline feed; deserializing from that shape proves the chats row
        // agrees key-for-key.
        let row: marmot_app::ChatListRow = serde_json::from_value(json!({
            "group_id_hex": "abcd",
            "pinned": false,
            "pinned_position": null,
            "archived": false,
            "pending_confirmation": false,
            "title": "General",
            "group_name": "General",
            "avatar_url": null,
            "avatar": null,
            "last_message": {
                "message_id_hex": "m1",
                "sender": "bob_hex",
                "sender_display_name": "Bob",
                "plaintext": "hello alice",
                "kind": 9,
                "timeline_at": 1_700_000_050_u64,
                "deleted": false,
                "attachment_kind": null,
                "attachment_count": 0,
                "delivery_state": "not_applicable"
            },
            "unread_count": 3_u64,
            "has_unread": true,
            "manually_marked_unread": false,
            "unread_mention_count": 1_u64,
            "has_unread_mention": true,
            "first_unread_message_id_hex": "m0",
            "last_read_message_id_hex": "r1",
            "last_read_timeline_at": 1_700_000_000_u64,
            "conversation_created_at": 1_699_999_000_u64,
            "activity_sort_at": 1_700_000_050_u64,
            "updated_at": 1_700_000_060_u64,
            "self_membership": "Member",
            "conversation_kind": "group",
            "muted": false,
            "muted_until_ms": null
        }))
        .expect("valid chat list row");
        assert!(!row.pinned);
        assert_eq!(row.pinned_position, None);

        let mut value = json!({ "group_id": "abcd" });
        insert_chat_projection(&mut value, Some(row));

        assert_eq!(value["unread_count"], 3);
        assert_eq!(value["has_unread"], true);
        assert_eq!(value["activity_sort_at"], 1_700_000_050_u64);
        assert_eq!(value["last_read_message_id_hex"], "r1");
        assert_eq!(value["last_read_timeline_at"], 1_700_000_000_u64);
        // `last_message` is byte-identical to the timeline feed's preview.
        assert_eq!(value["last_message"]["message_id_hex"], "m1");
        assert_eq!(value["last_message"]["sender"], "bob_hex");
        assert_eq!(value["last_message"]["sender_display_name"], "Bob");
        assert_eq!(value["last_message"]["plaintext"], "hello alice");
        assert_eq!(value["last_message"]["timeline_at"], 1_700_000_050_u64);
        assert_eq!(value["last_message"]["deleted"], false);
        // Minimal surface: mention state and the full row are not dumped here.
        assert!(value.get("unread_mention_count").is_none());
        assert!(value.get("first_unread_message_id_hex").is_none());
        assert!(value.get("self_membership").is_none());
    }

    /// Every membership reads as its stored snake_case token.
    #[test]
    fn self_membership_tokens_are_snake_case() {
        use super::{SelfMembership, self_membership_token};

        for (membership, token) in [
            (SelfMembership::Member, "member"),
            (SelfMembership::Left, "left"),
            (SelfMembership::Removed, "removed"),
            (SelfMembership::DeviceRemoved, "device_removed"),
        ] {
            assert_eq!(self_membership_token(membership), token);
        }
    }

    use marmot_app::{
        AppMessageRecord, DurationHistogramSnapshot, HistogramBucket, NostrAdapterMetrics,
        RelayDeliverySpread, RelayDeliveryStats, RelayLatencyStats, RelayPlaneHealth,
        RelayRefusalStats, RelaySyncSnapshot, RelayTelemetrySnapshot,
        SubscriptionRefusalDisposition, SubscriptionRouteKind,
    };

    fn one_sample_histogram(upper_bound_ms: u64) -> DurationHistogramSnapshot {
        DurationHistogramSnapshot {
            buckets: vec![HistogramBucket {
                upper_bound_ms,
                count: 1,
            }],
            overflow_count: 0,
            sum_ms: upper_bound_ms,
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
                refusals: vec![RelayRefusalStats {
                    relay_index: 0,
                    route_kind: SubscriptionRouteKind::Inbox,
                    category: Some(cgka_traits::TransportEndpointRejectionCategory::AuthRequired),
                    disposition: SubscriptionRefusalDisposition::Dropped,
                    count: 2,
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

    #[test]
    fn npub_for_account_id_rejects_invalid_input_without_panicking() {
        let npub =
            npub_for_account_id("aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4")
                .expect("valid account ids must render as npub");
        assert_eq!(
            npub,
            "npub14f8usejl26twx0dhuxjh9cas7keav9vr0v8nvtwtrjqx3vycc76qqh9nsy"
        );

        let err = npub_for_account_id("not-a-public-key")
            .expect_err("invalid account ids must surface as a CLI error");
        let rendered = super::wn_error_json(&err);
        assert_eq!(rendered["code"], "invalid_public_key");
    }

    #[test]
    fn dev_settlement_override_is_available_in_explicit_test_builds() {
        assert_eq!(
            resolve_dev_settlement_quiescence_ms(Some("0"), true).unwrap(),
            Some(0)
        );
    }

    #[test]
    fn dev_settlement_override_is_rejected_without_test_feature() {
        let error =
            resolve_dev_settlement_quiescence_ms(Some("0"), false).expect_err("feature rejection");
        assert!(matches!(&error, WnError::DevSettlementOverrideInRelease));
        assert_eq!(
            super::wn_error_json(&error)["code"],
            "dev_settlement_override_in_release"
        );
        assert_eq!(
            resolve_dev_settlement_quiescence_ms(None, false).unwrap(),
            None
        );
    }

    #[test]
    fn invalid_or_missing_dev_settlement_override_remains_inactive_when_enabled() {
        assert_eq!(
            resolve_dev_settlement_quiescence_ms(Some("not-a-duration"), true).unwrap(),
            None
        );
        assert_eq!(
            resolve_dev_settlement_quiescence_ms(None, true).unwrap(),
            None
        );
    }

    fn test_cli(command: Command) -> Cli {
        Cli {
            home: None,
            socket: Some(PathBuf::from("/tmp/wnd.sock")),
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

    #[test]
    fn daemon_execute_socket_skips_implicit_logout() {
        // WN_SOCKET makes the socket selection explicit; this regression covers
        // the auto-discovered daemon socket path that previously forwarded
        // `wn logout` even though the user did not pass `--socket`.
        assert!(
            std::env::var_os("WN_SOCKET").is_none(),
            "run this implicit-socket regression with WN_SOCKET unset"
        );

        let home = tempfile::tempdir().expect("temp home");
        let socket = daemon::default_socket_path(home.path());
        std::fs::create_dir_all(socket.parent().expect("socket parent"))
            .expect("create socket dir");
        std::fs::File::create(&socket).expect("create placeholder socket file");

        let mut cli = test_cli(Command::Logout {
            pubkey: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        });
        cli.socket = None;

        assert_eq!(daemon_socket_for_client(&cli, home.path()), None);
    }

    #[test]
    fn daemon_execute_socket_keeps_explicit_logout() {
        let home = Path::new("/tmp/wn-home");
        let socket = Path::new("/tmp/wnd.sock");
        let cli = test_cli(Command::Logout {
            pubkey: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        });

        assert_eq!(
            daemon_socket_for_client(&cli, home).as_deref(),
            Some(socket)
        );
    }

    #[cfg(unix)]
    fn account_list_args(home: &Path, socket: Option<&Path>) -> Vec<OsString> {
        let mut args = vec![
            OsString::from("wn"),
            OsString::from("--home"),
            home.as_os_str().to_owned(),
            OsString::from("--secret-store"),
            OsString::from("file"),
            OsString::from("--json"),
        ];
        if let Some(socket) = socket {
            args.extend([OsString::from("--socket"), socket.as_os_str().to_owned()]);
        }
        args.extend([OsString::from("account"), OsString::from("list")]);
        args
    }

    #[cfg(unix)]
    fn spawn_empty_response_daemon(socket: &Path) -> tokio::task::JoinHandle<()> {
        std::fs::create_dir_all(socket.parent().expect("socket parent")).expect("socket dir");
        let listener = tokio::net::UnixListener::bind(socket).expect("bind daemon socket");
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept daemon request");
            let request = crate::daemon::read_daemon_request(&mut stream)
                .await
                .expect("read daemon request");
            assert!(
                matches!(request, crate::daemon::DaemonRequest::Execute { .. }),
                "client must send an execute request before daemon disappears"
            );
            // Drop without writing a response. This simulates a daemon crash after
            // the request was delivered and possibly executed.
        })
    }

    #[cfg(unix)]
    fn assert_daemon_state_unknown(output: &super::CliOutput, expected_detail: &str) {
        assert_eq!(
            output.code, 1,
            "post-delivery daemon loss must not run the command locally"
        );
        assert!(output.stderr.is_empty());
        let value: serde_json::Value =
            serde_json::from_str(output.stdout.trim()).expect("json error");
        assert_eq!(value["ok"], false);
        assert_eq!(value["error"]["code"], "daemon_state_unknown");
        let message = value["error"]["message"].as_str().expect("message");
        assert!(message.contains("state is unknown"), "{message}");
        assert!(message.contains(expected_detail), "{message}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn auto_discovered_daemon_connect_error_falls_back_to_local_execution() {
        let home = tempfile::tempdir().expect("tempdir");
        let socket = daemon::default_socket_path(home.path());
        std::fs::create_dir_all(socket.parent().expect("socket parent")).expect("socket dir");
        std::fs::write(&socket, b"stale socket path").expect("stale socket file");

        let output = run_from(account_list_args(home.path(), None)).await;

        assert_eq!(
            output.code, 0,
            "stale auto-discovered socket should fall back to local execution: stdout={} stderr={}",
            output.stdout, output.stderr
        );
        assert!(output.stderr.is_empty());
        let value: serde_json::Value =
            serde_json::from_str(output.stdout.trim()).expect("json output");
        assert_eq!(value["ok"], true);
        assert_eq!(
            value["result"]["accounts"]
                .as_array()
                .expect("accounts array")
                .len(),
            0
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn auto_discovered_daemon_empty_response_reports_unknown_state_without_local_fallback() {
        let home = tempfile::tempdir().expect("tempdir");
        let socket = daemon::default_socket_path(home.path());
        let server = spawn_empty_response_daemon(&socket);

        let output = run_from(account_list_args(home.path(), None)).await;

        server.await.expect("daemon task");
        assert_daemon_state_unknown(&output, "daemon closed the connection without responding");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn explicit_socket_empty_response_reports_unknown_state_without_local_fallback() {
        let home = tempfile::tempdir().expect("tempdir");
        let socket = home.path().join("explicit.sock");
        let server = spawn_empty_response_daemon(&socket);

        let output = run_from(account_list_args(home.path(), Some(&socket))).await;

        server.await.expect("daemon task");
        assert_daemon_state_unknown(&output, "daemon closed the connection without responding");
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
        assert!(plain.contains("relay#0 inbox auth-required dropped x2"));
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
        assert_eq!(
            output.json["sync"]["refusals"][0]["category"],
            "auth-required"
        );
        assert_eq!(output.json["sync"]["refusals"][0]["route_kind"], "inbox");
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
            PathBuf::from("/Users/alice/Library/Application Support/whitenoise")
        );
        #[cfg(all(unix, not(target_os = "macos")))]
        assert_eq!(home, PathBuf::from("/Users/alice/.local/share/whitenoise"));
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
        assert_eq!(home, PathBuf::from("/tmp/xdg-data/whitenoise"));
        #[cfg(target_os = "macos")]
        assert_eq!(
            home,
            PathBuf::from("/home/alice/Library/Application Support/whitenoise")
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
            Err(WnError::InvalidRelayUrl(value)) if value == "not-a-relay-url"
        ));
        assert!(matches!(
            resolve_relay(Some("https://relay.example".to_owned())),
            Err(WnError::InvalidRelayUrl(value)) if value == "https://relay.example"
        ));
        assert!(matches!(
            relay_endpoints(vec!["mailto:relay@example.com".to_owned()]),
            Err(WnError::InvalidRelayUrl(value)) if value == "mailto:relay@example.com"
        ));
        assert!(matches!(
            resolve_relay(Some("ws://relay.example".to_owned())),
            Err(WnError::InvalidRelayUrl(value)) if value == "ws://relay.example"
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
                authority: None,
                message_id_hex: id.to_owned(),
                direction: "received".to_owned(),
                group_id_hex: "group".to_owned(),
                sender: "sender".to_owned(),
                plaintext: id.to_owned(),
                kind: cgka_traits::app_event::MARMOT_APP_EVENT_KIND_CHAT,
                tags: Vec::new(),
                source_epoch: None,
                retention: None,
                recorded_at: 100 + u64::try_from(index / 2).unwrap(),
                received_at: 100 + u64::try_from(index / 2).unwrap(),
                insert_order: i64::try_from(index).unwrap(),
                invalidated: false,
                moderation_grant: false,
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

    fn parse_send(argv: &[&str]) -> (Option<String>, Option<String>, Vec<String>) {
        let cli = Cli::try_parse_from(argv.iter().copied()).expect("send args parse");
        match cli.command {
            Command::Message {
                command:
                    crate::MessageCommand::Send {
                        group_flag,
                        reply_to,
                        args,
                    },
            }
            | Command::Messages {
                command:
                    crate::MessageCommand::Send {
                        group_flag,
                        reply_to,
                        args,
                    },
            } => (group_flag, reply_to, args),
            other => panic!("expected a message send command, got {other:?}"),
        }
    }

    #[test]
    fn message_send_reply_to_flag_parses_before_positional_text() {
        // `--group` + `--reply-to` before the text: the canonical reply form.
        let (group_flag, reply_to, args) = parse_send(&[
            "wn",
            "messages",
            "send",
            "--group",
            "GROUP",
            "--reply-to",
            "PARENT",
            "hello",
            "world",
        ]);
        assert_eq!(group_flag.as_deref(), Some("GROUP"));
        assert_eq!(reply_to.as_deref(), Some("PARENT"));
        assert_eq!(args, vec!["hello".to_owned(), "world".to_owned()]);

        // Positional group works too, as long as `--reply-to` precedes the
        // positional group (the older singular `message` surface shares the enum).
        let (group_flag, reply_to, args) = parse_send(&[
            "wn",
            "message",
            "send",
            "--reply-to",
            "PARENT",
            "GROUP",
            "hi",
        ]);
        assert_eq!(group_flag, None);
        assert_eq!(reply_to.as_deref(), Some("PARENT"));
        assert_eq!(args, vec!["GROUP".to_owned(), "hi".to_owned()]);
    }

    #[test]
    fn message_send_reply_to_after_positional_group_is_literal_text() {
        // The trailing positional text uses `allow_hyphen_values`, so once a
        // positional group is consumed everything after it (including a stray
        // `--reply-to`) is literal message text — the same rule that lets
        // `send --group <g> "--dash text"` work. Callers must use the `--group`
        // form to attach `--reply-to`. This locks that intentional behavior.
        let (group_flag, reply_to, args) = parse_send(&[
            "wn",
            "messages",
            "send",
            "GROUP",
            "--reply-to",
            "PARENT",
            "text",
        ]);
        assert_eq!(group_flag, None);
        assert_eq!(reply_to, None);
        assert_eq!(
            args,
            vec![
                "GROUP".to_owned(),
                "--reply-to".to_owned(),
                "PARENT".to_owned(),
                "text".to_owned(),
            ]
        );
    }

    #[test]
    fn private_parent_dir_skips_bare_file_names() {
        assert_eq!(crate::private_parent_dir(Path::new("avatar.png")), None);
        assert_eq!(
            crate::private_parent_dir(Path::new("out/avatar.png")),
            Some(Path::new("out"))
        );
        assert_eq!(
            crate::private_parent_dir(Path::new("/tmp/avatar.png")),
            Some(Path::new("/tmp"))
        );
    }

    #[test]
    fn write_private_file_writes_bytes_and_creates_nested_parents() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bare.bin");
        crate::write_private_file(&path, b"ok").expect("absolute path writes");
        assert_eq!(std::fs::read(&path).unwrap(), b"ok");
        let nested = dir.path().join("nested").join("deep.bin");
        crate::write_private_file(&nested, b"ok").expect("nested path creates parents");
        assert_eq!(std::fs::read(&nested).unwrap(), b"ok");
    }

    #[cfg(unix)]
    #[test]
    fn write_private_output_file_leaves_existing_directories_alone() {
        use std::os::unix::fs::PermissionsExt;
        fn mode(path: &Path) -> u32 {
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777
        }
        // A download destination is the caller's directory, not wn's: a
        // shared 0755 directory must stay 0755 after the file lands in it.
        let dir = tempfile::tempdir().expect("tempdir");
        let shared = dir.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o755)).unwrap();

        let direct = shared.join("note.txt");
        crate::write_private_output_file(&direct, b"ok").expect("download into existing dir");
        assert_eq!(std::fs::read(&direct).unwrap(), b"ok");
        assert_eq!(mode(&shared), 0o755, "existing parent must keep its mode");
        assert_eq!(
            mode(&direct),
            0o600,
            "the plaintext file itself stays private"
        );

        // Directories the download has to create are private; the existing
        // ancestor above them is still untouched.
        let nested = shared.join("a").join("b").join("note.txt");
        crate::write_private_output_file(&nested, b"ok").expect("download creates missing dirs");
        assert_eq!(mode(&shared), 0o755);
        assert_eq!(mode(&shared.join("a")), 0o700);
        assert_eq!(mode(&shared.join("a").join("b")), 0o700);
        assert_eq!(mode(&nested), 0o600);

        // The home-layout writer is the one that tightens: same shape, and the
        // directory it created for the file is 0700.
        let home_file = dir.path().join("home").join("state.json");
        crate::write_private_file(&home_file, b"ok").expect("home write");
        assert_eq!(mode(&dir.path().join("home")), 0o700);
    }

    #[test]
    fn relative_file_paths_resolve_against_the_caller_directory_before_forwarding() {
        let base = Path::new("/callers/cwd");
        let mut cli = Cli::try_parse_from([
            "wn",
            "media",
            "upload",
            "GROUP",
            "a.png",
            "/abs/b.png",
            "--send",
        ])
        .expect("upload parses");
        crate::resolve_relative_paths(&mut cli, base);
        match &cli.command {
            Command::Media {
                command: crate::MediaCommand::Upload { file_paths, .. },
            } => assert_eq!(
                file_paths,
                &vec!["/callers/cwd/a.png".to_owned(), "/abs/b.png".to_owned()]
            ),
            other => panic!("expected media upload, got {other:?}"),
        }

        let mut cli = Cli::try_parse_from(["wn", "groups", "set-image", "GROUP", "avatar.png"])
            .expect("set-image parses");
        crate::resolve_relative_paths(&mut cli, base);
        match &cli.command {
            Command::Groups {
                command: crate::GroupsCommand::SetImage { file_path, .. },
                ..
            } => assert_eq!(file_path, "/callers/cwd/avatar.png"),
            other => panic!("expected groups set-image, got {other:?}"),
        }

        let mut cli =
            Cli::try_parse_from(["wn", "groups", "create", "pics", "--image", "founding.png"])
                .expect("create parses");
        crate::resolve_relative_paths(&mut cli, base);
        match &cli.command {
            Command::Groups {
                command: crate::GroupsCommand::Create { image, .. },
                ..
            } => assert_eq!(image.as_deref(), Some("/callers/cwd/founding.png")),
            other => panic!("expected groups create, got {other:?}"),
        }

        // An absent download destination becomes the caller's directory so a
        // forwarded download never lands in the daemon's working directory.
        let mut cli = Cli::try_parse_from(["wn", "groups", "download-image", "GROUP"])
            .expect("download-image parses");
        crate::resolve_relative_paths(&mut cli, base);
        match &cli.command {
            Command::Groups {
                command: crate::GroupsCommand::DownloadImage { output, .. },
                ..
            } => assert_eq!(output.as_deref(), Some("/callers/cwd")),
            other => panic!("expected groups download-image, got {other:?}"),
        }
        let mut cli = Cli::try_parse_from([
            "wn",
            "media",
            "download",
            "GROUP",
            "aa",
            "--output",
            "out/file.bin",
        ])
        .expect("media download parses");
        crate::resolve_relative_paths(&mut cli, base);
        match &cli.command {
            Command::Media {
                command: crate::MediaCommand::Download { output, .. },
            } => assert_eq!(output.as_deref(), Some("/callers/cwd/out/file.bin")),
            other => panic!("expected media download, got {other:?}"),
        }
    }

    #[test]
    fn message_edit_parses_hyphen_leading_replacement_text() {
        let cli = Cli::try_parse_from([
            "wn", "messages", "edit", "GROUP", "TARGET", "fixed", "--typo",
        ])
        .expect("edit args parse");
        match cli.command {
            Command::Messages {
                command:
                    crate::MessageCommand::Edit {
                        group_id,
                        message_id,
                        text,
                    },
            } => {
                assert_eq!(group_id, "GROUP");
                assert_eq!(message_id, "TARGET");
                assert_eq!(text, vec!["fixed".to_owned(), "--typo".to_owned()]);
            }
            other => panic!("expected a messages edit command, got {other:?}"),
        }
        let error = Cli::try_parse_from(["wn", "messages", "edit", "GROUP", "TARGET"])
            .expect_err("edit requires replacement text");
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn message_retry_event_id_is_optional_context() {
        let cli = Cli::try_parse_from(["wn", "messages", "retry", "GROUP"]).expect("retry parses");
        match cli.command {
            Command::Messages {
                command: crate::MessageCommand::Retry { group_id, event_id },
            } => {
                assert_eq!(group_id, "GROUP");
                assert_eq!(event_id, None);
            }
            other => panic!("expected a messages retry command, got {other:?}"),
        }
        let cli = Cli::try_parse_from(["wn", "message", "retry", "GROUP", "EVENT"])
            .expect("legacy retry with event id parses");
        match cli.command {
            Command::Message {
                command: crate::MessageCommand::Retry { event_id, .. },
            } => assert_eq!(event_id.as_deref(), Some("EVENT")),
            other => panic!("expected a message retry command, got {other:?}"),
        }
    }

    /// mdk#2258: `--accept-stale` is opt-in and parses on either side of the
    /// group subcommand.
    #[test]
    fn groups_accept_stale_flag_parses() {
        for args in [
            &["wn", "groups", "rename", "GROUP", "NAME"][..],
            &["wn", "groups", "rename", "GROUP", "NAME", "--accept-stale"][..],
            &["wn", "groups", "--accept-stale", "rename", "GROUP", "NAME"][..],
        ] {
            let cli = Cli::try_parse_from(args).expect("rename parses");
            match cli.command {
                Command::Groups {
                    command: crate::GroupsCommand::Rename { .. },
                    accept_stale,
                    ..
                } => assert_eq!(accept_stale, args.contains(&"--accept-stale")),
                other => panic!("expected a groups rename command, got {other:?}"),
            }
        }
    }

    /// mdk#2255: `--accept-undelivered` is opt-in, parses on either side of the
    /// group subcommand, and combines with `--accept-stale`.
    #[test]
    fn groups_accept_undelivered_flag_parses() {
        for args in [
            &["wn", "groups", "rename", "GROUP", "NAME"][..],
            &[
                "wn",
                "groups",
                "rename",
                "GROUP",
                "NAME",
                "--accept-undelivered",
            ][..],
            &[
                "wn",
                "groups",
                "--accept-undelivered",
                "--accept-stale",
                "rename",
                "GROUP",
                "NAME",
            ][..],
        ] {
            let cli = Cli::try_parse_from(args).expect("rename parses");
            match cli.command {
                Command::Groups {
                    command: crate::GroupsCommand::Rename { .. },
                    accept_stale,
                    accept_undelivered,
                } => {
                    assert_eq!(accept_stale, args.contains(&"--accept-stale"));
                    assert_eq!(accept_undelivered, args.contains(&"--accept-undelivered"));
                }
                other => panic!("expected a groups rename command, got {other:?}"),
            }
        }
        let cli = Cli::try_parse_from(["wn", "groups", "commit-delivery", "GROUP"])
            .expect("commit-delivery parses");
        assert!(matches!(
            cli.command,
            Command::Groups {
                command: crate::GroupsCommand::CommitDelivery { .. },
                ..
            }
        ));
        let cli = Cli::try_parse_from(["wn", "groups", "pending-commit", "GROUP"])
            .expect("pending-commit parses");
        assert!(matches!(
            cli.command,
            Command::Groups {
                command: crate::GroupsCommand::PendingCommit { .. },
                ..
            }
        ));
        let cli = Cli::try_parse_from(["wn", "groups", "changes-not-delivered", "GROUP"])
            .expect("changes-not-delivered parses");
        assert!(matches!(
            cli.command,
            Command::Groups {
                command: crate::GroupsCommand::ChangesNotDelivered { .. },
                ..
            }
        ));
        let cli = Cli::try_parse_from([
            "wn",
            "groups",
            "acknowledge-change-not-delivered",
            "GROUP",
            "COMMIT",
        ])
        .expect("acknowledge-change-not-delivered parses");
        assert!(matches!(
            cli.command,
            Command::Groups {
                command: crate::GroupsCommand::AcknowledgeChangeNotDelivered { group_id, commit_id },
                ..
            } if group_id == "GROUP" && commit_id == "COMMIT"
        ));
    }

    #[test]
    fn groups_retention_disband_and_admin_flags_parse() {
        let cli = Cli::try_parse_from(["wn", "groups", "retention", "GROUP", "--set", "1h"])
            .expect("retention parses");
        match cli.command {
            Command::Groups {
                command: crate::GroupsCommand::Retention { group_id, set },
                ..
            } => {
                assert_eq!(group_id, "GROUP");
                assert_eq!(set.as_deref(), Some("1h"));
            }
            other => panic!("expected a groups retention command, got {other:?}"),
        }
        let cli =
            Cli::try_parse_from(["wn", "groups", "disband", "GROUP"]).expect("disband parses");
        match cli.command {
            Command::Groups {
                command: crate::GroupsCommand::Disband { confirm, .. },
                ..
            } => assert!(
                !confirm,
                "confirmation is an explicit flag, never a default"
            ),
            other => panic!("expected a groups disband command, got {other:?}"),
        }
        let cli = Cli::try_parse_from([
            "wn",
            "groups",
            "add-members",
            "GROUP",
            "carol",
            "dave",
            "--admin",
            "carol",
        ])
        .expect("add-members parses");
        match cli.command {
            Command::Groups {
                command:
                    crate::GroupsCommand::AddMembers {
                        members, admins, ..
                    },
                ..
            } => {
                assert_eq!(members, vec!["carol".to_owned(), "dave".to_owned()]);
                assert_eq!(admins, vec!["carol".to_owned()]);
            }
            other => panic!("expected a groups add-members command, got {other:?}"),
        }
        let cli = Cli::try_parse_from([
            "wn",
            "groups",
            "create",
            "ephemeral",
            "--retention",
            "1d",
            "--image",
            "avatar.png",
        ])
        .expect("create with founding options parses");
        match cli.command {
            Command::Groups {
                command:
                    crate::GroupsCommand::Create {
                        retention, image, ..
                    },
                ..
            } => {
                assert_eq!(retention.as_deref(), Some("1d"));
                assert_eq!(image.as_deref(), Some("avatar.png"));
            }
            other => panic!("expected a groups create command, got {other:?}"),
        }
        let error = Cli::try_parse_from(["wn", "groups", "update", "GROUP"])
            .expect_err("groups update needs --name or --description");
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
        let error = Cli::try_parse_from(["wn", "group", "update", "GROUP"])
            .expect_err("legacy group update needs --name or --description");
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn media_upload_accepts_many_files_and_send_takes_references() {
        let cli = Cli::try_parse_from([
            "wn",
            "media",
            "upload",
            "GROUP",
            "a.png",
            "b.png",
            "--send",
            "--message",
            "two",
        ])
        .expect("multi-file upload parses");
        match cli.command {
            Command::Media {
                command:
                    crate::MediaCommand::Upload {
                        file_paths, send, ..
                    },
            } => {
                assert_eq!(file_paths, vec!["a.png".to_owned(), "b.png".to_owned()]);
                assert!(send);
            }
            other => panic!("expected a media upload command, got {other:?}"),
        }
        let error = Cli::try_parse_from(["wn", "media", "upload", "GROUP"])
            .expect_err("upload needs at least one file");
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
        let cli = Cli::try_parse_from(["wn", "media", "send", "GROUP", "{\"x\":1}", "ab"])
            .expect("media send parses");
        match cli.command {
            Command::Media {
                command: crate::MediaCommand::Send { attachments, .. },
            } => assert_eq!(attachments.len(), 2),
            other => panic!("expected a media send command, got {other:?}"),
        }
        let cli = Cli::try_parse_from([
            "wn",
            "media",
            "set-endpoints",
            "GROUP",
            "https://a",
            "https://b",
        ])
        .expect("set-endpoints parses");
        match cli.command {
            Command::Media {
                command:
                    crate::MediaCommand::SetEndpoints {
                        urls, locator_kind, ..
                    },
            } => {
                assert_eq!(urls.len(), 2);
                assert_eq!(locator_kind, "blossom-v1");
            }
            other => panic!("expected a media set-endpoints command, got {other:?}"),
        }
    }

    #[test]
    fn retention_duration_parser_accepts_seconds_suffixes_and_off() {
        use super::commands::groups::parse_retention_duration;
        assert_eq!(parse_retention_duration("0").unwrap(), 0);
        assert_eq!(parse_retention_duration("off").unwrap(), 0);
        assert_eq!(parse_retention_duration("90").unwrap(), 90);
        assert_eq!(parse_retention_duration("45s").unwrap(), 45);
        assert_eq!(parse_retention_duration("2m").unwrap(), 120);
        assert_eq!(parse_retention_duration("1h").unwrap(), 3_600);
        assert_eq!(parse_retention_duration("1d").unwrap(), 86_400);
        assert_eq!(parse_retention_duration("1w").unwrap(), 604_800);
        for invalid in [
            "",
            "soon",
            "-1",
            "1x",
            "h",
            "1.5h",
            "1💥",
            "18446744073709551615w",
        ] {
            let error = parse_retention_duration(invalid).expect_err("invalid retention");
            assert!(matches!(error, WnError::InvalidRetentionDuration(value) if value == invalid));
        }
    }

    #[test]
    fn message_send_event_parses_kind_tags_and_content() {
        let cli = Cli::try_parse_from([
            "wn",
            "messages",
            "send-event",
            "GROUP",
            "30078",
            "--tag",
            "[\"d\",\"game-1\"]",
            "{\"move\":\"e4\"}",
        ])
        .expect("send-event args parse");
        match cli.command {
            Command::Messages {
                command:
                    crate::MessageCommand::SendEvent {
                        group_id,
                        kind,
                        tags,
                        content,
                    },
            } => {
                assert_eq!(group_id, "GROUP");
                assert_eq!(kind, 30078);
                assert_eq!(tags, vec!["[\"d\",\"game-1\"]".to_owned()]);
                assert_eq!(content, vec!["{\"move\":\"e4\"}".to_owned()]);
            }
            other => panic!("expected a messages send-event command, got {other:?}"),
        }
    }

    #[test]
    fn message_list_and_subscribe_parse_repeatable_kind_filters() {
        let cli = Cli::try_parse_from([
            "wn", "messages", "list", "GROUP", "--kind", "9", "--kind", "30078",
        ])
        .expect("list args parse");
        match cli.command {
            Command::Messages {
                command: crate::MessageCommand::List { kinds, .. },
            } => assert_eq!(kinds, vec![9, 30078]),
            other => panic!("expected a messages list command, got {other:?}"),
        }

        let cli = Cli::try_parse_from(["wn", "messages", "subscribe", "--kind", "30078"])
            .expect("subscribe args parse");
        match cli.command {
            Command::Messages {
                command:
                    crate::MessageCommand::Subscribe {
                        group,
                        kinds,
                        limit,
                    },
            } => {
                assert_eq!(group, None);
                assert_eq!(kinds, vec![30078]);
                assert_eq!(limit, None);
            }
            other => panic!("expected a messages subscribe command, got {other:?}"),
        }
    }

    #[test]
    fn message_send_reply_to_after_group_flag_text_is_literal_text() {
        // The `--group` form carries the same footgun as the positional-group form
        // above: the trailing message args use `allow_hyphen_values`, so a
        // `--reply-to` placed *after* the text is swallowed as literal message text
        // (`reply_to` stays `None`) instead of setting the reply target. The send
        // handler turns this exact parse into a loud error (see
        // `reject_misplaced_reply_to`); this locks the parse the guard fires on.
        let (group_flag, reply_to, args) = parse_send(&[
            "wn",
            "messages",
            "send",
            "--group",
            "GROUP",
            "hello",
            "--reply-to",
            "PARENT",
        ]);
        assert_eq!(group_flag.as_deref(), Some("GROUP"));
        assert_eq!(reply_to, None);
        assert_eq!(
            args,
            vec![
                "hello".to_owned(),
                "--reply-to".to_owned(),
                "PARENT".to_owned(),
            ]
        );
    }

    #[test]
    fn message_send_without_reply_to_leaves_it_unset() {
        let (group_flag, reply_to, args) =
            parse_send(&["wn", "messages", "send", "GROUP", "hello"]);
        assert_eq!(group_flag, None);
        assert_eq!(reply_to, None);
        assert_eq!(args, vec!["GROUP".to_owned(), "hello".to_owned()]);
    }

    #[test]
    fn message_send_reply_to_guard_allows_real_replies_and_plain_text() {
        // A parsed `--reply-to` already did its job (the flag was consumed), so an
        // identical token surviving in the body is fine and the guard stays quiet.
        assert!(
            reject_misplaced_reply_to(Some("PARENT"), &["--reply-to".to_owned(), "b".to_owned()])
                .is_ok()
        );
        // Plain text with no stray flag is always fine.
        assert!(reject_misplaced_reply_to(None, &["hello".to_owned(), "world".to_owned()]).is_ok());
    }

    #[test]
    fn reply_to_after_message_text_error_renders_reply_to_code() {
        let value = super::wn_error_json(&WnError::ReplyToAfterMessageText);
        assert_eq!(value["code"], "reply_to_after_message_text");
        assert_eq!(
            value["message"],
            "--reply-to must come before the message text; it was read as literal text here"
        );
    }

    #[test]
    fn message_send_reply_to_footgun_is_rejected_on_both_send_surfaces() {
        // The guard lives on the shared `MessageCommand::Send` arm, so the plural
        // `messages send` and the older singular `message send` are protected
        // identically. With `--group`, the parsed positional args are the message
        // text, so a trailing `--reply-to` is exactly what the guard rejects.
        for argv in [
            [
                "wn",
                "messages",
                "send",
                "--group",
                "GROUP",
                "hello",
                "--reply-to",
                "PARENT",
            ],
            [
                "wn",
                "message",
                "send",
                "--group",
                "GROUP",
                "hello",
                "--reply-to",
                "PARENT",
            ],
        ] {
            let (group_flag, reply_to, text) = parse_send(&argv);
            assert_eq!(group_flag.as_deref(), Some("GROUP"));
            assert_eq!(reply_to, None);
            let err = reject_misplaced_reply_to(reply_to.as_deref(), &text)
                .expect_err("stray --reply-to must be rejected on both send surfaces");
            assert!(matches!(err, WnError::ReplyToAfterMessageText));
        }
    }

    #[test]
    fn message_send_stray_reply_to_equals_form_is_rejected() {
        // The equals spelling `--reply-to=PARENT` placed *after* the text is also
        // swallowed as one literal `allow_hyphen_values` token (verified: it parses
        // to `reply_to=None`, args `["hello", "--reply-to=PARENT"]`). An exact-token
        // guard would miss it and publish a body carrying a stray reply flag, so the
        // guard must reject the `=` form on both send surfaces too.
        let cases: [&[&str]; 2] = [
            &[
                "wn",
                "messages",
                "send",
                "--group",
                "GROUP",
                "hello",
                "--reply-to=PARENT",
            ],
            &[
                "wn",
                "messages",
                "send",
                "GROUP",
                "hello",
                "--reply-to=PARENT",
            ],
        ];
        for argv in cases {
            let (group_flag, reply_to, args) = parse_send(argv);
            assert_eq!(reply_to, None);
            // Mirror the handler: the positional-group form drops the leading group.
            let text = if group_flag.is_some() {
                args.as_slice()
            } else {
                &args[1..]
            };
            let err = reject_misplaced_reply_to(reply_to.as_deref(), text)
                .expect_err("a stray --reply-to=<id> in the text must be rejected");
            assert!(matches!(err, WnError::ReplyToAfterMessageText));
        }
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
            WnError::MessagePaginationCursorMismatch {
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
            WnError::MessagePaginationCursorMismatch {
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
            WnError::MessagePaginationCursorMismatch {
                timestamp_flag: "--before",
                message_id_flag: "--before-message-id",
            }
        ));
    }

    #[test]
    fn uppercase_nsec_argv_rejected_at_early_identity_gate() {
        for command in ["login", "account create"] {
            for identity in [" nsec1synthetic", "\tNsEc1synthetic \n"] {
                let error = super::validate_materialized_secret_identity(
                    command,
                    &Some(identity.to_owned()),
                    false,
                )
                .expect_err("padded nsec argv must be rejected before materialization");
                assert!(matches!(
                    error,
                    WnError::SecretArgumentRejected { command: actual } if actual == command
                ));
            }
            super::validate_materialized_secret_identity(
                command,
                &Some("npub1synthetic".to_owned()),
                false,
            )
            .expect("public identities remain valid argv input");
        }
        let identity =
            Some("NSEC1J4C6269Y9W0Q2ER2XJW8SV2EHYRTFXQ3JWGDLXJ6QFN8Z4GJSQ5QFVFK99".to_owned());
        let err = super::validate_materialized_secret_identity("login", &identity, false)
            .expect_err("uppercase nsec argv must be rejected before daemon/json materialization");
        assert!(matches!(
            err,
            WnError::SecretArgumentRejected { command: "login" }
        ));
    }

    #[test]
    fn message_list_cursors_reject_before_and_after_together() {
        let err = validate_message_list_cursors(Some(101), Some("d"), Some(100), Some("a"))
            .expect_err("before and after cursors cannot be combined");
        assert!(matches!(err, WnError::MessagePaginationConflictingCursors));
    }

    // `chats subscribe` / `chats subscribe-archived` without a daemon must surface
    // a chat-specific message, not the messages-namespace text, while keeping the
    // shared `daemon_required` JSON code and repair hint so scripts that branch
    // on `code` keep working.
    #[test]
    fn chats_subscribe_requires_daemon_renders_chat_specific_message() {
        let chats = super::wn_error_json(&WnError::ChatsSubscribeRequiresDaemon);
        assert_eq!(chats["code"], "daemon_required");
        assert_eq!(chats["repair"]["start"], "wn daemon start");
        let message = chats["message"].as_str().expect("chats message");
        assert!(
            message.starts_with("chats subscribe"),
            "expected chat-specific subscribe message, got {message:?}"
        );

        // The messages variant must stay messages-specific so the two namespaces
        // do not drift back into the same text.
        let messages = super::wn_error_json(&WnError::MessagesSubscribeRequiresDaemon);
        let messages_message = messages["message"].as_str().expect("messages message");
        assert!(
            messages_message.starts_with("messages subscribe"),
            "expected messages-specific subscribe message, got {messages_message:?}"
        );
        assert_ne!(message, messages_message);

        let notifications = super::wn_error_json(&WnError::NotificationsSubscribeRequiresDaemon);
        assert_eq!(notifications["code"], "daemon_required");
        assert_eq!(notifications["repair"]["start"], "wn daemon start");
        let notifications_message = notifications["message"]
            .as_str()
            .expect("notifications message");
        assert!(
            notifications_message.starts_with("notifications subscribe"),
            "expected notification-specific subscribe message, got {notifications_message:?}"
        );
    }

    // Regression for #190: an oversized request on the *implicit* daemon socket
    // path (default socket merely exists, no `--socket`/`WN_SOCKET`) must surface
    // the client-side size-limit error instead of silently falling through to
    // local execution. Without the terminal `RequestTooLarge` arm in `run_from`,
    // the encoder rejects the request and the request silently runs locally,
    // masking the cap.
    #[tokio::test]
    async fn run_from_oversized_request_on_implicit_socket_fails_locally() {
        // WN_SOCKET would select a different branch, so reject invalid test
        // setup instead of reporting a passing test without exercising it.
        assert!(
            std::env::var_os("WN_SOCKET").is_none(),
            "run this implicit-socket regression with WN_SOCKET unset"
        );

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
            OsString::from("wn"),
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
        assert!(output.stderr.is_empty());
        let value: serde_json::Value = serde_json::from_str(&output.stdout).expect("JSON error");
        assert_eq!(value["ok"], false);
        assert_eq!(value["error"]["code"], "daemon_unavailable");
        assert!(
            value["error"]["message"]
                .as_str()
                .unwrap()
                .contains("byte limit")
        );
    }

    // Regression for #192: clap renders `--help`/`--version` as `Err` with exit
    // code 0; that text is the help/version payload and must go to stdout (not
    // stderr), so piping and scripting work.
    #[tokio::test]
    async fn top_level_help_goes_to_stdout_not_stderr() {
        let output = run_from([OsString::from("wn"), OsString::from("--help")]).await;
        assert_eq!(output.code, 0, "help exit code must be 0");
        assert!(
            !output.stdout.is_empty(),
            "help text must be on stdout, got empty stdout"
        );
        assert!(
            output.stderr.is_empty(),
            "help must not write to stderr, got: {}",
            output.stderr
        );
        assert!(
            output.stdout.contains("Usage"),
            "expected usage text on stdout, got: {}",
            output.stdout
        );
    }

    #[tokio::test]
    async fn subcommand_help_goes_to_stdout_not_stderr() {
        let output = run_from([
            OsString::from("wn"),
            OsString::from("messages"),
            OsString::from("--help"),
        ])
        .await;
        assert_eq!(output.code, 0, "subcommand help exit code must be 0");
        assert!(
            !output.stdout.is_empty(),
            "subcommand help text must be on stdout"
        );
        assert!(
            output.stderr.is_empty(),
            "subcommand help must not write to stderr, got: {}",
            output.stderr
        );
    }

    #[tokio::test]
    async fn version_goes_to_stdout_not_stderr() {
        let output = run_from([OsString::from("wn"), OsString::from("--version")]).await;
        assert_eq!(output.code, 0, "version exit code must be 0");
        assert!(
            !output.stdout.is_empty(),
            "version text must be on stdout, got empty stdout"
        );
        assert!(
            output.stderr.is_empty(),
            "version must not write to stderr, got: {}",
            output.stderr
        );
    }

    #[tokio::test]
    async fn help_in_json_mode_is_reported_as_ok() {
        let output = run_from([
            OsString::from("wn"),
            OsString::from("--json"),
            OsString::from("--help"),
        ])
        .await;
        assert_eq!(output.code, 0, "json help exit code must be 0");
        assert!(output.stderr.is_empty(), "json help must not use stderr");
        let value: serde_json::Value =
            serde_json::from_str(output.stdout.trim()).expect("json help must be valid JSON");
        assert_eq!(
            value["ok"], true,
            "help with exit 0 must be ok:true, got: {value}"
        );
        assert!(
            value["result"]["help"].is_string(),
            "expected result.help string, got: {value}"
        );
    }

    #[tokio::test]
    async fn version_in_json_mode_is_reported_as_ok() {
        let output = run_from([
            OsString::from("wn"),
            OsString::from("--json"),
            OsString::from("--version"),
        ])
        .await;
        assert_eq!(output.code, 0, "json version exit code must be 0");
        assert!(output.stderr.is_empty(), "json version must not use stderr");
        let value: serde_json::Value =
            serde_json::from_str(output.stdout.trim()).expect("json version must be valid JSON");
        assert_eq!(value["ok"], true, "version with exit 0 must be ok:true");
        assert!(
            value["result"]["version"].is_string(),
            "expected result.version string, got: {value}"
        );
    }

    #[tokio::test]
    async fn real_usage_error_still_goes_to_stderr() {
        // An unknown subcommand is a genuine usage error (nonzero exit) and must
        // keep going to stderr.
        let output = run_from([OsString::from("wn"), OsString::from("definitely-not-a-cmd")]).await;
        assert_ne!(output.code, 0, "usage error must have nonzero exit");
        assert!(
            output.stdout.is_empty(),
            "usage error must not write to stdout, got: {}",
            output.stdout
        );
        assert!(
            !output.stderr.is_empty(),
            "usage error must write to stderr"
        );
    }

    #[tokio::test]
    async fn real_usage_error_in_json_mode_is_reported_as_error() {
        let output = run_from([
            OsString::from("wn"),
            OsString::from("--json"),
            OsString::from("definitely-not-a-cmd"),
        ])
        .await;
        assert_ne!(output.code, 0, "json usage error must have nonzero exit");
        let value: serde_json::Value =
            serde_json::from_str(output.stdout.trim()).expect("json error must be valid JSON");
        assert_eq!(value["ok"], false, "usage error must be ok:false");
        assert_eq!(value["error"]["code"], "usage");
    }

    #[tokio::test]
    async fn missing_subcommand_is_a_usage_error_not_help() {
        // `wn messages` with no subcommand renders help text but exits nonzero
        // (clap's DisplayHelpOnMissingArgumentOrSubcommand). It is a genuine
        // usage error and must go to stderr, never stdout, despite resembling
        // help output. Regression for mdk#192 adversarial review.
        let output = run_from([OsString::from("wn"), OsString::from("messages")]).await;
        assert_ne!(output.code, 0, "missing subcommand must have nonzero exit");
        assert!(
            output.stdout.is_empty(),
            "missing subcommand must not write to stdout, got: {}",
            output.stdout
        );
        assert!(
            !output.stderr.is_empty(),
            "missing subcommand must write help/usage text to stderr"
        );
    }

    #[tokio::test]
    async fn missing_subcommand_in_json_mode_is_reported_as_error() {
        // `wn --json messages` with no subcommand must be ok:false with a
        // nonzero exit, not wrapped as a success help object. Regression for
        // mdk#192 adversarial review.
        let output = run_from([
            OsString::from("wn"),
            OsString::from("--json"),
            OsString::from("messages"),
        ])
        .await;
        assert_ne!(
            output.code, 0,
            "missing subcommand in json mode must have nonzero exit"
        );
        let value: serde_json::Value =
            serde_json::from_str(output.stdout.trim()).expect("json error must be valid JSON");
        assert_eq!(
            value["ok"], false,
            "missing subcommand must be ok:false, got: {value}"
        );
        assert_eq!(value["error"]["code"], "usage");
    }

    fn sample_group(name: &str) -> marmot_app::AppGroupRecord {
        serde_json::from_value(json!({
            "group_id_hex": "aa".repeat(16),
            "endpoint": "wss://relay.example\u{1b}]8;;https://evil.example\u{7}",
            "nostr_routing": {
                "component_id": 1,
                "component": "marmot.transport.nostr.routing.v1",
                "nostr_group_id_hex": "bb".repeat(16),
                "relays": ["wss://relay.example"],
                "data_hex": ""
            },
            "profile": {
                "component_id": 2,
                "component": "marmot.group.profile.v1",
                "name": name,
                "description": "",
                "data_hex": ""
            },
            "image": {
                "component_id": 3,
                "component": "marmot.group.blossom-image.v1",
                "present": false,
                "image_hash_hex": "",
                "image_key_hex": "",
                "image_nonce_hex": "",
                "image_upload_key_hex": "",
                "data_hex": ""
            },
            "admin_policy": {
                "component_id": 4,
                "component": "marmot.group.admin-policy.v1",
                "admins": [],
                "data_hex": ""
            },
            "avatar_url": {
                "component_id": 5,
                "component": "marmot.group.avatar-url.v1",
                "present": true,
                "url": "https://cdn.example/a\u{1b}[2J.png",
                "dim": "64x64\u{7}",
                "thumbhash": "thumb\u{202e}",
                "data_hex": ""
            }
        }))
        .expect("sample group")
    }

    const SENTINEL_IMAGE_KEY: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";
    const SENTINEL_UPLOAD_KEY: &str =
        "2222222222222222222222222222222222222222222222222222222222222222";
    const SENTINEL_IMAGE_NONCE: &str = "333333333333333333333333";
    const SENTINEL_IMAGE_DATA: &str = "4444deadbeef4444";

    /// A group whose encrypted image component carries sentinel capability keys.
    fn sample_group_with_image_secrets() -> marmot_app::AppGroupRecord {
        let mut group = sample_group("pictures");
        group.image = serde_json::from_value(json!({
            "component_id": 3,
            "component": "marmot.group.blossom-image.v1",
            "present": true,
            "image_hash_hex": "55".repeat(32),
            "image_key_hex": SENTINEL_IMAGE_KEY,
            "image_nonce_hex": SENTINEL_IMAGE_NONCE,
            "image_upload_key_hex": SENTINEL_UPLOAD_KEY,
            "media_type": "image/png",
            "data_hex": SENTINEL_IMAGE_DATA,
        }))
        .expect("image component");
        group
    }

    fn assert_no_image_secrets(label: &str, value: &serde_json::Value) {
        let rendered = value.to_string();
        for secret in [
            SENTINEL_IMAGE_KEY,
            SENTINEL_UPLOAD_KEY,
            SENTINEL_IMAGE_NONCE,
            SENTINEL_IMAGE_DATA,
        ] {
            assert!(
                !rendered.contains(secret),
                "{label} must not carry image capability material: {rendered}"
            );
        }
        let image = &value["image"];
        for key in [
            "image_key_hex",
            "image_upload_key_hex",
            "image_nonce_hex",
            "data_hex",
        ] {
            assert!(image.get(key).is_none(), "{label} image must omit {key}");
        }
        assert_eq!(image["present"], true, "{label}");
        assert_eq!(image["image_hash_hex"], "55".repeat(32), "{label}");
        assert_eq!(image["media_type"], "image/png", "{label}");
        assert_eq!(
            image["component"], "marmot.group.blossom-image.v1",
            "{label}"
        );
    }

    /// mdk#1253: every `wn` surface that renders a group (`groups show`/`list`,
    /// `chats` rows, the daemon group-state feed, and the create response)
    /// reports image presence, hash, and type but never the decryption key,
    /// upload secret, or key-bearing component bytes.
    #[test]
    fn group_json_surfaces_redact_image_capability_keys() {
        let group = sample_group_with_image_secrets();
        assert_no_image_secrets("group_json", &crate::group_json(group.clone()));
        assert_no_image_secrets("chat_json", &crate::chat_json(group.clone(), None));
        assert_no_image_secrets(
            "group_state_stream_response",
            &serde_json::to_value(crate::daemon::group_state_stream_response(
                group.clone(),
                "InitialGroupState",
                None,
            ))
            .expect("stream response serializes")["result"]["group"],
        );
        let created =
            crate::commands::groups::created_group_json(&"66".repeat(32), group, Vec::new())
                .expect("create json");
        assert_no_image_secrets("created_group_json", &created);
        assert_eq!(created["name"], "pictures");
        assert_no_image_secrets(
            "group_image_summary_json",
            &json!({ "image": crate::commands::groups::group_image_summary_json(
                &sample_group_with_image_secrets().image
            ) }),
        );
    }

    #[test]
    fn group_plain_sanitizes_profile_and_avatar_fields() {
        let group = sample_group("ops\u{1b}]52;c;YXR0YWNr\u{7}\nforged");
        let listed = crate::group_list_plain(&[group]);
        assert_eq!(
            listed,
            format!(
                "{} name=ops]52;c;YXR0YWNrforged endpoint=wss://relay.example]8;;https://evil.example avatar_url=https://cdn.example/a[2J.png avatar_dim=64x64 avatar_thumbhash=thumb",
                "aa".repeat(16)
            )
        );
        assert!(!listed.contains('\n'));
        assert!(!listed.contains('\u{1b}'));
    }
}
