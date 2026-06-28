use std::ffi::OsString;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use cgka_traits::TransportEndpoint;
use cgka_traits::app_event::{
    MARMOT_APP_EVENT_KIND_AGENT_STREAM_START, STREAM_CHUNKS_TAG, STREAM_HASH_TAG, STREAM_START_TAG,
    STREAM_TAG,
};
use clap::Parser;
use marmot_account::{AccountHome, DEFAULT_KEYCHAIN_SERVICE_NAME};
use marmot_app::{
    AccountRelayListStatus, AppError, AppGroupRecord, MarmotApp, MarmotAppConfig, StreamStartView,
    UserProfileMetadata, tag_value,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

mod args;
pub(crate) mod commands;
pub mod daemon;
mod error;
pub mod tui;

pub use args::SecretStoreKind;
pub(crate) use args::{
    AccountCommand, ChatsCommand, Cli, Command, DaemonCommand, DebugCommand, FollowsCommand,
    GroupCommand, GroupsCommand, KeyPackageCommand, MediaCommand, MessageCommand,
    MessageTimelineCommand, NotificationsCommand, ProfileCommand, RelaysCommand, SettingsCommand,
    StreamCommand, UsersCommand,
};
pub(crate) use error::{DmError, dm_error_json};

pub(crate) const DEFAULT_PRODUCTION_QUIC_BROKER_CANDIDATE: &str = "quic://quic-broker.ipf.dev:4450";
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

pub(crate) type AgentStreamDelta = marmot_app::AgentStreamDelta;

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
    let mut cli = match Cli::try_parse_from(argv) {
        Ok(cli) => cli,
        Err(err) => {
            use clap::error::ErrorKind;
            // clap reports explicit `--help`/`--version` as `Err` with exit code
            // 0; the rendered string is the help/version text, which belongs on
            // stdout (clap's own default). Real usage errors go to stderr.
            //
            // Crucially, gate on the exit code, not just the kind:
            // `DisplayHelpOnMissingArgumentOrSubcommand` is also rendered as help
            // text but exits nonzero (e.g. `dm messages` with no subcommand). That
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
        let explicit_daemon_socket =
            cli.socket.is_some() || std::env::var_os("DM_SOCKET").is_some();
        match daemon::send_execute(&socket, cli.clone()).await {
            Ok(output) => return output,
            // An oversized request is a client-side limit violation, not a
            // daemon-unavailable or lost-response condition: the encoder rejects
            // it before it ever reaches `dmd`. Surface it as a terminal error
            // even on the implicit-socket path, otherwise the request silently
            // falls through to `run_cli_local` and masks the size cap (see #190).
            Err(err @ daemon::DaemonClientError::RequestTooLarge { .. }) => {
                return daemon_client_error(cli.json, err);
            }
            // Only fall back to local execution when the client could not reach
            // `dmd` over an auto-discovered socket. If the daemon accepted the
            // command but the response was lost/malformed, do NOT re-run locally
            // (that would double-execute); report it via `daemon_execute_error`.
            Err(err)
                if should_fallback_to_local_after_daemon_execute_error(
                    explicit_daemon_socket,
                    &err,
                ) => {}
            Err(err) => return daemon_execute_error(cli.json, err),
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
        return commands::stream::stream_command_local(command.clone()).await;
    }
    if let Command::Stream {
        command:
            stream_command @ StreamCommand::Send {
                start_event_id: None,
                ..
            },
    } = &command
    {
        return commands::stream::stream_command_local(stream_command.clone()).await;
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
        Command::Debug { command } => {
            commands::debug::debug_command(&account_home, &app, command, account_flag)
        }
        Command::CreateIdentity => {
            commands::account::identity_create_command(
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
            commands::account::identity_login_command(
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
        Command::Whoami => {
            commands::account::whoami_command(&account_home, &app, runtime_info, account_flag)
        }
        Command::Logout { pubkey } => commands::account::logout_command(&account_home, pubkey),
        Command::ExportNsec { pubkey } => commands::account::export_nsec_command(pubkey),
        Command::Account { command } => {
            commands::account::account_command(
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
            commands::account::account_command(
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
            commands::key_package::key_package_command(&account_home, &app, command, account_flag)
                .await
        }
        Command::Chats { command } => {
            commands::chats::chats_command(&account_home, &app, command, account_flag).await
        }
        Command::Media { command } => {
            commands::media::media_command(&account_home, &app, command, account_flag).await
        }
        Command::Group { command } => {
            commands::groups::group_command(&account_home, &app, command, account_flag).await
        }
        Command::Groups { command } => {
            commands::groups::groups_command(&account_home, &app, command, account_flag).await
        }
        Command::Message { command } => {
            commands::messages::message_command(&account_home, &app, command, account_flag).await
        }
        Command::Messages { command } => {
            commands::messages::message_command(&account_home, &app, command, account_flag).await
        }
        Command::Follows { command } => {
            commands::follows::follows_command(&account_home, &app, command, account_flag, relay)
                .await
        }
        Command::Profile { command } => {
            commands::profile::profile_command(&account_home, &app, command, account_flag, relay)
                .await
        }
        Command::Relays { command } => {
            commands::relays::relays_command(&account_home, &app, command, account_flag, relay)
                .await
        }
        Command::Settings { command } => commands::settings::settings_command(&home, command),
        Command::Users { command } => {
            commands::users::users_command(&account_home, &app, command, account_flag)
        }
        Command::Notifications { command } => {
            commands::notifications::notifications_command(command)
        }
        Command::Stream { command } => {
            commands::stream::stream_command_app(&account_home, &app, command, account_flag).await
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
            commands::sync::sync_command(&app, account).await
        }
        Command::RelayStats => commands::relay_stats::relay_stats_command(&app).await,
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
    let explicit_daemon_socket = cli.socket.is_some() || std::env::var_os("DM_SOCKET").is_some();
    if matches!(cli.command, Command::Logout { .. }) && !explicit_daemon_socket {
        return None;
    }
    if explicit_daemon_socket || socket.exists() {
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

fn should_fallback_to_local_after_daemon_execute_error(
    explicit_daemon_socket: bool,
    err: &daemon::DaemonClientError,
) -> bool {
    !explicit_daemon_socket && matches!(err, daemon::DaemonClientError::Connect { .. })
}

fn daemon_execute_error(json_output: bool, err: daemon::DaemonClientError) -> CliOutput {
    match err {
        err @ daemon::DaemonClientError::Connect { .. } => daemon_client_error(json_output, err),
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

pub(crate) fn unsupported_command<T>(
    command: &'static str,
    reason: &'static str,
) -> Result<T, DmError> {
    Err(DmError::UnsupportedCommand { command, reason })
}

pub(crate) fn group_show_output(
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

pub(crate) fn unix_now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Render the `agent_text_stream` JSON view for a message's inner-event kind,
/// tags, and content, or `None` if the message is neither a kind-1200 start nor
/// a kind-9 stream-final. The shape stays stable for the TUI and daemon.
pub(crate) fn agent_text_stream_payload_value(
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
pub(crate) fn stream_route_label(route: &str) -> &str {
    match route {
        "quic" => "brokered_quic",
        other => other,
    }
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

fn group_plain(group: &AppGroupRecord) -> String {
    let mut line = format!(
        "{} name={} endpoint={}",
        group.group_id_hex, group.profile.name, group.endpoint
    );
    if group.avatar_url.present {
        line.push_str(&format!(" avatar_url={}", group.avatar_url.url));
        if let Some(dim) = &group.avatar_url.dim {
            line.push_str(&format!(" avatar_dim={dim}"));
        }
        if let Some(thumbhash) = &group.avatar_url.thumbhash {
            line.push_str(&format!(" avatar_thumbhash={thumbhash}"));
        }
    }
    line
}

pub(crate) fn group_json(group: AppGroupRecord) -> Value {
    json!({
        "group_id": group.group_id_hex,
        "endpoint": group.endpoint,
        "profile": group.profile,
        "image": group.image,
        "avatar_url": group.avatar_url,
        "admin_policy": group.admin_policy,
        "nostr_routing": group.nostr_routing,
        "agent_text_stream": group.agent_text_stream,
        "encrypted_media": group.encrypted_media,
        "archived": group.archived,
    })
}

pub(crate) fn display_name_for_sender(app: &MarmotApp, sender: &str) -> Option<String> {
    let account_id = parse_public_key(sender).ok()?;
    let profile = app
        .directory_entry_for_account_id(&account_id)
        .ok()
        .flatten()
        .and_then(|entry| entry.profile);
    profile_display_name(profile.as_ref())
}

pub(crate) fn is_nostr_secret(value: &str) -> bool {
    value.starts_with("nsec")
}

fn resolve_relay(relay: Option<String>) -> Result<Option<String>, DmError> {
    match relay.or_else(|| std::env::var("DM_RELAY").ok()) {
        Some(relay) => validate_relay_url(relay).map(Some),
        None => Ok(None),
    }
}

pub(crate) fn validate_relay_url(relay: impl AsRef<str>) -> Result<String, DmError> {
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

pub(crate) fn relay_endpoints(values: Vec<String>) -> Result<Vec<TransportEndpoint>, DmError> {
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
) -> Result<String, DmError> {
    if let Some(account_ref) = account_ref {
        return parse_public_key(&account_ref);
    }
    Ok(resolve_account(account_home, default_account)?.account_id_hex)
}

pub(crate) fn resolve_account(
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

pub(crate) fn resolve_account_ref(
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

pub(crate) fn ensure_local_signing(
    account: &marmot_account::AccountSummary,
) -> Result<(), DmError> {
    if account.local_signing {
        Ok(())
    } else {
        Err(DmError::PublicAccountCannotSign)
    }
}

pub(crate) fn parse_public_key(value: &str) -> Result<String, DmError> {
    nostr::PublicKey::parse(value)
        .map(|pubkey| pubkey.to_hex())
        .map_err(|_| DmError::InvalidPublicKey)
}

pub(crate) fn npub_for_account_id(account_id: &str) -> Result<String, DmError> {
    marmot_app::npub_for_account_id(account_id).map_err(DmError::from)
}

pub(crate) fn normalize_group_id_hex(value: &str) -> Result<String, DmError> {
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

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    use super::commands::account::{GlobalRelayDefaults, apply_global_relay_defaults};
    use super::commands::messages::{apply_message_cursors, validate_message_list_cursors};
    use super::commands::relay_stats::{relay_stats_output, relay_stats_plain};
    use super::commands::stream::{
        first_quic_candidate_is_loopback, parse_quic_candidate, quic_candidate_host,
    };
    use super::{
        Cli, Command, DmError, StreamCommand, daemon, daemon_socket_for_client,
        default_home_from_env, npub_for_account_id, relay_endpoints, resolve_relay, run_from,
    };

    use marmot_app::{
        AppMessageRecord, DurationHistogramSnapshot, HistogramBucket, NostrAdapterMetrics,
        RelayDeliverySpread, RelayDeliveryStats, RelayLatencyStats, RelayPlaneHealth,
        RelaySyncSnapshot, RelayTelemetrySnapshot,
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
        let rendered = super::dm_error_json(&err);
        assert_eq!(rendered["code"], "invalid_public_key");
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
    fn daemon_execute_socket_skips_implicit_logout() {
        // DM_SOCKET makes the socket selection explicit; this regression covers
        // the auto-discovered daemon socket path that previously forwarded
        // `dm logout` even though the user did not pass `--socket`.
        if std::env::var_os("DM_SOCKET").is_some() {
            return;
        }

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
        let home = Path::new("/tmp/dm-home");
        let socket = Path::new("/tmp/dmd.sock");
        let cli = test_cli(Command::Logout {
            pubkey: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        });

        assert_eq!(
            daemon_socket_for_client(&cli, home).as_deref(),
            Some(socket)
        );
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

    #[cfg(unix)]
    fn account_list_args(home: &Path, socket: Option<&Path>) -> Vec<OsString> {
        let mut args = vec![
            OsString::from("dm"),
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
            let mut request = Vec::new();
            use tokio::io::AsyncReadExt;
            stream
                .read_to_end(&mut request)
                .await
                .expect("read daemon request");
            assert!(
                !request.is_empty(),
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

    // `chats subscribe` / `chats subscribe-archived` without a daemon must surface
    // a chat-specific message, not the messages-namespace text, while keeping the
    // shared `daemon_required` JSON code and repair hint so the TUI/scripts that
    // branch on `code` keep working.
    #[test]
    fn chats_subscribe_requires_daemon_renders_chat_specific_message() {
        let chats = super::dm_error_json(&DmError::ChatsSubscribeRequiresDaemon);
        assert_eq!(chats["code"], "daemon_required");
        assert_eq!(chats["repair"]["start"], "dm daemon start");
        let message = chats["message"].as_str().expect("chats message");
        assert!(
            message.starts_with("chats subscribe"),
            "expected chat-specific subscribe message, got {message:?}"
        );

        // The messages variant must stay messages-specific so the two namespaces
        // do not drift back into the same text.
        let messages = super::dm_error_json(&DmError::MessagesSubscribeRequiresDaemon);
        let messages_message = messages["message"].as_str().expect("messages message");
        assert!(
            messages_message.starts_with("messages subscribe"),
            "expected messages-specific subscribe message, got {messages_message:?}"
        );
        assert_ne!(message, messages_message);
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

    // Regression for #192: clap renders `--help`/`--version` as `Err` with exit
    // code 0; that text is the help/version payload and must go to stdout (not
    // stderr), so piping and scripting work.
    #[tokio::test]
    async fn top_level_help_goes_to_stdout_not_stderr() {
        let output = run_from([OsString::from("dm"), OsString::from("--help")]).await;
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
            OsString::from("dm"),
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
        let output = run_from([OsString::from("dm"), OsString::from("--version")]).await;
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
            OsString::from("dm"),
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
            OsString::from("dm"),
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
        let output = run_from([OsString::from("dm"), OsString::from("definitely-not-a-cmd")]).await;
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
            OsString::from("dm"),
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
        // `dm messages` with no subcommand renders help text but exits nonzero
        // (clap's DisplayHelpOnMissingArgumentOrSubcommand). It is a genuine
        // usage error and must go to stderr, never stdout, despite resembling
        // help output. Regression for darkmatter#192 adversarial review.
        let output = run_from([OsString::from("dm"), OsString::from("messages")]).await;
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
        // `dm --json messages` with no subcommand must be ok:false with a
        // nonzero exit, not wrapped as a success help object. Regression for
        // darkmatter#192 adversarial review.
        let output = run_from([
            OsString::from("dm"),
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
}
