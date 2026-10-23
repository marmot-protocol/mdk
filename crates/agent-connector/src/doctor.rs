//! Read-only `wn-agent doctor`: local setup checks plus one `diagnostic_status`
//! request, reported without paths, identifiers, relay URLs or tokens.
//!
//! Nothing here changes state. The doctor never chmods, removes sockets,
//! creates accounts, publishes KeyPackages or writes relay lists; every repair
//! is a printed next step. Account records are parsed directly rather than
//! through `AccountHome`, whose reads may tighten file modes.

use std::fs::Metadata;
use std::io::{ErrorKind, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use agent_control::{
    AGENT_CONTROL_PROTOCOL_V2, AgentControlAccountSelection, AgentControlDiagnosticStatus,
    AgentControlError, AgentControlKeyPackageAvailability, AgentControlReplayState,
    AgentControlRequest, AgentControlResponse,
};
use marmot_account::AccountSummary;
use serde::Serialize;
use zeroize::Zeroizing;

use crate::AGENT_SOCKET_DIR_MODE;
use crate::bootstrap::{
    BootstrapError, ControlClient, bootstrap_auth_token_file, resolve_bootstrap_home,
    resolve_bootstrap_relays, resolve_bootstrap_socket,
};
use crate::socket::{
    SocketDirViolation, SocketPathState, current_effective_uid, is_stale_socket_error,
    socket_dir_is_connector_owned, socket_dir_violation, socket_path_occupant,
};
use crate::validation::validate_control_plane_mode;

/// Bound on the one live `diagnostic_status` request.
const DOCTOR_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Larger token files are reported, not read.
const MAX_TOKEN_FILE_BYTES: u64 = 64 * 1024;

const NO_ACTION: &str = "None.";
const RERUN_AFTER_DAEMON: &str = "Fix the daemon check, then rerun wn-agent doctor.";
const START_DAEMON: &str = "Start `wn-agent --home <home>` (add `--socket <socket>` for a custom socket), \
                            then rerun wn-agent doctor.";
const BOOTSTRAP_ACCOUNT: &str = "With wn-agent running, run `wn-agent bootstrap --home <home>`, or import \
                                 an identity first with `wn-agent import-identity`.";
const REPUBLISH_KEY_PACKAGE: &str = "With wn-agent running, run `wn-agent bootstrap --home <home>`; it \
                                     publishes or repairs this account's KeyPackage.";
const SAME_RELEASE: &str = "Run the same wn-agent release for the daemon and this CLI, then restart \
                            the daemon.";
const BUSY_DAEMON: &str = "Check the daemon's log, restart wn-agent, then rerun wn-agent doctor.";
const DELIVERY_NOTE: &str = "Passing these checks does not prove end-to-end delivery. Send a test \
                             message from the phone app and wait for the agent's reply.";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DoctorStatus {
    Ok,
    Warn,
    Fail,
    Unknown,
}

impl DoctorStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warn => "warn",
            Self::Fail => "fail",
            Self::Unknown => "unknown",
        }
    }
}

/// Whether a check reads local files or asks the running daemon.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DoctorScope {
    Local,
    Live,
}

/// One check. `id` is stable for scripts; `summary` and `next_step` carry only
/// counts, modes and statuses.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DoctorCheck {
    pub id: &'static str,
    pub scope: DoctorScope,
    pub status: DoctorStatus,
    pub summary: String,
    pub next_step: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct DoctorCounts {
    pub ok: u32,
    pub warn: u32,
    pub fail: u32,
    pub unknown: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DoctorReport {
    pub version: &'static str,
    pub redacted: bool,
    pub counts: DoctorCounts,
    pub checks: Vec<DoctorCheck>,
    pub note: &'static str,
}

impl DoctorReport {
    fn new(checks: Vec<DoctorCheck>) -> Self {
        let mut counts = DoctorCounts::default();
        for check in &checks {
            let count = match check.status {
                DoctorStatus::Ok => &mut counts.ok,
                DoctorStatus::Warn => &mut counts.warn,
                DoctorStatus::Fail => &mut counts.fail,
                DoctorStatus::Unknown => &mut counts.unknown,
            };
            *count += 1;
        }
        Self {
            version: env!("CARGO_PKG_VERSION"),
            redacted: true,
            counts,
            checks,
            note: DELIVERY_NOTE,
        }
    }

    pub fn has_failures(&self) -> bool {
        self.counts.fail > 0
    }

    /// One result line and one next-step line per check.
    pub fn render_text(&self) -> String {
        let mut out = format!(
            "wn-agent doctor {} (redacted: no paths, identifiers, relay URLs or tokens)\n\n",
            self.version
        );
        for check in &self.checks {
            out.push_str(&format!(
                "{:<7} {:<15} {}\n{:<24}next: {}\n",
                check.status.label(),
                check.id,
                check.summary,
                "",
                check.next_step
            ));
        }
        out.push_str(&format!(
            "\n{} ok, {} warn, {} fail, {} unknown\n{}\n",
            self.counts.ok, self.counts.warn, self.counts.fail, self.counts.unknown, self.note
        ));
        out
    }
}

/// Where the relay list `serve` would use came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RelaySource {
    Flag,
    Environment,
    Defaults,
}

/// The control token, resolved as `bootstrap` resolves it.
enum DoctorAuth {
    /// `MARMOT_AGENT_AUTH_TOKEN` is set, possibly to an empty value.
    Environment(Zeroizing<String>),
    /// The flag or `MARMOT_AGENT_AUTH_TOKEN_FILE` named this file (`explicit`),
    /// or it is the default `<home>/control.token`.
    File { path: PathBuf, explicit: bool },
}

/// Doctor inputs. Holds the inline token, so it deliberately has no `Debug`.
pub struct DoctorOptions {
    home: PathBuf,
    socket: PathBuf,
    socket_dir_mode: u32,
    auth: DoctorAuth,
    relays: Vec<String>,
    relay_source: RelaySource,
    request_timeout: Duration,
}

impl DoctorOptions {
    /// Resolve flags, then `MARMOT_*` environment, then defaults, exactly as
    /// `wn-agent bootstrap` does.
    pub fn resolve(
        home: Option<PathBuf>,
        socket: Option<PathBuf>,
        auth_token_file: Option<PathBuf>,
        relays: Vec<String>,
        socket_dir_mode: u32,
    ) -> Self {
        let home = resolve_bootstrap_home(home);
        let socket = resolve_bootstrap_socket(&home, socket);
        let auth = match std::env::var("MARMOT_AGENT_AUTH_TOKEN") {
            Ok(token) => DoctorAuth::Environment(Zeroizing::new(token)),
            Err(_) => {
                let (path, explicit) = bootstrap_auth_token_file(auth_token_file, &home);
                DoctorAuth::File { path, explicit }
            }
        };
        let relay_env = std::env::var("MARMOT_RELAYS")
            .or_else(|_| std::env::var("MARMOT_RELAY"))
            .ok();
        let relay_source = relay_source(&relays, relay_env.as_deref());
        Self {
            relays: resolve_bootstrap_relays(relays),
            home,
            socket,
            socket_dir_mode,
            auth,
            relay_source,
            request_timeout: DOCTOR_REQUEST_TIMEOUT,
        }
    }
}

/// Where `resolve_bootstrap_relays` takes its list from, following its
/// precedence: any nonempty flag list is final, even one that cleans to
/// nothing; then a `MARMOT_RELAYS` (else `MARMOT_RELAY`) value with at least
/// one entry; then the defaults.
fn relay_source(flags: &[String], env: Option<&str>) -> RelaySource {
    if !flags.is_empty() {
        RelaySource::Flag
    } else if env.is_some_and(|value| value.split(',').any(|part| !part.trim().is_empty())) {
        RelaySource::Environment
    } else {
        RelaySource::Defaults
    }
}

/// Run every check. Local checks always run; live checks run only when a
/// listener answers at the socket path.
pub async fn run_doctor(options: &DoctorOptions) -> DoctorReport {
    let effective_uid = current_effective_uid();
    let auth = inspect_auth(&options.auth);
    let socket = probe_socket(&options.socket, options.request_timeout).await;
    let accounts = scan_accounts(&options.home);
    let mut checks = vec![
        check_home(&options.home, effective_uid),
        check_socket_dir(options, effective_uid, auth.token.is_some()),
        check_socket_path(&socket),
        auth.check,
        check_relays(&options.relays, options.relay_source),
        check_accounts(&accounts),
        check_account_files(&accounts),
    ];
    let live = query_daemon(options, &socket, auth.token).await;
    checks.extend(live_checks(&live, &accounts));
    DoctorReport::new(checks)
}

fn check(
    id: &'static str,
    scope: DoctorScope,
    status: DoctorStatus,
    summary: impl Into<String>,
    next_step: impl Into<String>,
) -> DoctorCheck {
    DoctorCheck {
        id,
        scope,
        status,
        summary: summary.into(),
        next_step: next_step.into(),
    }
}

fn local(
    id: &'static str,
    status: DoctorStatus,
    summary: impl Into<String>,
    next_step: impl Into<String>,
) -> DoctorCheck {
    check(id, DoctorScope::Local, status, summary, next_step)
}

fn live(
    id: &'static str,
    status: DoctorStatus,
    summary: impl Into<String>,
    next_step: impl Into<String>,
) -> DoctorCheck {
    check(id, DoctorScope::Live, status, summary, next_step)
}

fn mode_of(metadata: &Metadata) -> u32 {
    metadata.permissions().mode() & 0o7777
}

fn plural(count: u32, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}

/// Open `path` as wn-agent's directory preparation would, without creating
/// or changing anything: no symlinks except trusted platform aliases.
fn inspect_directory(path: &Path) -> Result<Option<(u32, libc::uid_t)>, ErrorKind> {
    fs_private::inspect_directory_path(path)
        .map(|inspected| inspected.map(|directory| (directory.mode() & 0o7777, directory.uid())))
        .map_err(|error| error.kind())
}

const UNSAFE_PATH_STEP: &str = "Run doctor as the user that runs wn-agent, and use a path whose every component \
                                is a real directory that user can open: no symlinks, and on macOS not under /tmp \
                                (a symlink to a shared directory).";

fn check_home(home: &Path, effective_uid: libc::uid_t) -> DoctorCheck {
    use DoctorStatus::{Fail, Warn};
    let (mode, uid) = match inspect_directory(home) {
        Ok(Some(directory)) => directory,
        Ok(None) => {
            return local(
                "home",
                Warn,
                "The home directory does not exist yet; wn-agent creates it owner-only on first start.",
                "Check --home or MARMOT_HOME if you expected an existing home.",
            );
        }
        Err(kind) => {
            return local(
                "home",
                Fail,
                format!("wn-agent cannot open the home directory safely ({kind:?})."),
                UNSAFE_PATH_STEP,
            );
        }
    };
    if uid != effective_uid {
        return local(
            "home",
            Fail,
            "The home directory is owned by another user.",
            "Run wn-agent and doctor as the home's owner, or give the service user its own home.",
        );
    }
    if mode & 0o077 != 0 {
        return local(
            "home",
            Warn,
            format!("The home directory is owned by this user but has mode {mode:04o}."),
            "Run `chmod 700 <home>` so other users cannot list it.",
        );
    }
    local(
        "home",
        DoctorStatus::Ok,
        format!("The home directory exists, is owned by this user and has mode {mode:04o}."),
        NO_ACTION,
    )
}

fn check_socket_dir(
    options: &DoctorOptions,
    effective_uid: libc::uid_t,
    token_configured: bool,
) -> DoctorCheck {
    use DoctorStatus::{Fail, Warn};
    let requested = options.socket_dir_mode;
    if validate_control_plane_mode(requested, "socket directory mode").is_err() {
        return local(
            "socket_dir",
            Fail,
            format!(
                "Socket directory mode {requested:04o} is refused (world access or bits outside 0777)."
            ),
            "Use the default --socket-dir-mode 0700, or 0770 with a token for a split-user gateway.",
        );
    }
    if requested != AGENT_SOCKET_DIR_MODE && !token_configured {
        return local(
            "socket_dir",
            Fail,
            format!(
                "Socket directory mode {requested:04o} is not the default, and no token is configured; wn-agent refuses to start."
            ),
            "Pass --auth-token-file to wn-agent and doctor, or use the default --socket-dir-mode 0700.",
        );
    }
    let parent = match options.socket.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let (mode, uid) = match inspect_directory(parent) {
        Ok(Some((mode, uid))) => (mode & 0o777, uid),
        Ok(None) => {
            return local(
                "socket_dir",
                DoctorStatus::Ok,
                format!(
                    "The socket directory does not exist yet; wn-agent creates it with mode {requested:04o}."
                ),
                NO_ACTION,
            );
        }
        Err(kind) => {
            return local(
                "socket_dir",
                Fail,
                format!(
                    "wn-agent cannot open the socket directory safely ({kind:?}) and refuses to start."
                ),
                UNSAFE_PATH_STEP,
            );
        }
    };
    if socket_dir_is_connector_owned(parent, Some(&options.home)) {
        // wn-agent re-applies its own `<home>/dev` mode at start, which needs
        // ownership unless it runs as root, and then applies the owner rule.
        let foreign = uid != effective_uid && effective_uid != 0;
        if foreign || socket_dir_violation(requested, requested, uid, effective_uid).is_some() {
            return local(
                "socket_dir",
                Fail,
                "The socket directory belongs to another user, so wn-agent cannot apply its mode and refuses to start.",
                "Run wn-agent as the owner of <home>/dev, or give the service user its own --home.",
            );
        }
        if mode != requested {
            return local(
                "socket_dir",
                Warn,
                format!(
                    "The socket directory has mode {mode:04o}; wn-agent resets it to {requested:04o} when it starts."
                ),
                format!("Restart wn-agent, or run `chmod {requested:o} <home>/dev` now."),
            );
        }
        return local(
            "socket_dir",
            DoctorStatus::Ok,
            format!("The socket directory is wn-agent's own, with mode {mode:04o}."),
            NO_ACTION,
        );
    }
    match socket_dir_violation(mode, requested, uid, effective_uid) {
        Some(SocketDirViolation::WorldAccessible) => local(
            "socket_dir",
            Fail,
            format!(
                "The socket directory has mode {mode:04o}, so other users can reach it; wn-agent refuses to start."
            ),
            "Run `chmod 700` (or 0770 for a split-user gateway) on the socket's directory.",
        ),
        Some(SocketDirViolation::UnexpectedGroupWritable) => local(
            "socket_dir",
            Fail,
            format!(
                "The socket directory has mode {mode:04o}, group-writable, but the requested mode is {requested:04o}; wn-agent refuses to start."
            ),
            "Run `chmod 700` on the socket's directory, or start wn-agent and doctor with the matching --socket-dir-mode and a token.",
        ),
        Some(SocketDirViolation::ForeignOwner) => local(
            "socket_dir",
            Fail,
            "The socket directory is owned by another user (not root); wn-agent refuses to start.",
            "Choose a --socket in a directory owned by the service user or root.",
        ),
        None => local(
            "socket_dir",
            DoctorStatus::Ok,
            format!("The socket directory meets wn-agent's rules (mode {mode:04o})."),
            NO_ACTION,
        ),
    }
}

/// What sits at the socket path, as the bind path would see it.
enum SocketProbe {
    TooLong,
    State(SocketPathState),
    Error(ErrorKind),
}

/// Probe as the bind path does, but connect without blocking and within
/// `timeout`, so a stuck listener with a full backlog cannot hang the doctor.
async fn probe_socket(socket: &Path, timeout: Duration) -> SocketProbe {
    if fs_private::validate_private_unix_socket_path(socket).is_err() {
        return SocketProbe::TooLong;
    }
    match socket_path_occupant(socket) {
        Ok(Some(state)) => return SocketProbe::State(state),
        Ok(None) => {}
        Err(error) => return SocketProbe::Error(error.kind()),
    }
    match tokio::time::timeout(timeout, tokio::net::UnixStream::connect(socket)).await {
        Ok(Ok(_)) => SocketProbe::State(SocketPathState::Live),
        Ok(Err(error)) if is_stale_socket_error(&error) => {
            SocketProbe::State(SocketPathState::Stale)
        }
        Ok(Err(error)) => SocketProbe::Error(error.kind()),
        Err(_) => SocketProbe::Error(ErrorKind::TimedOut),
    }
}

fn check_socket_path(socket: &SocketProbe) -> DoctorCheck {
    use DoctorStatus::*;
    match socket {
        SocketProbe::TooLong => local(
            "socket_path",
            Fail,
            "The socket path is too long for wn-agent's private bind.",
            "Use a shorter --home or --socket path.",
        ),
        SocketProbe::State(SocketPathState::Missing) => local(
            "socket_path",
            Ok,
            "Nothing is at the socket path; wn-agent creates the socket when it starts.",
            NO_ACTION,
        ),
        SocketProbe::State(SocketPathState::Live) => local(
            "socket_path",
            Ok,
            "A listening socket is at the socket path.",
            NO_ACTION,
        ),
        SocketProbe::State(SocketPathState::Stale) => local(
            "socket_path",
            Warn,
            "A stale socket from a stopped wn-agent is at the socket path; wn-agent replaces it when it starts.",
            "Start wn-agent; it removes the stale socket itself.",
        ),
        SocketProbe::State(SocketPathState::NotSocket) => local(
            "socket_path",
            Fail,
            "Something other than a socket is at the socket path; wn-agent refuses to start.",
            "Move that file aside or pass a different --socket, then start wn-agent.",
        ),
        SocketProbe::Error(kind @ (ErrorKind::WouldBlock | ErrorKind::TimedOut)) => local(
            "socket_path",
            Fail,
            format!(
                "A socket is at the socket path, but its listener is not accepting connections ({kind:?})."
            ),
            BUSY_DAEMON,
        ),
        SocketProbe::Error(kind) => local(
            "socket_path",
            Fail,
            format!("The socket path cannot be inspected or connected to ({kind:?})."),
            "Run doctor as the user that runs the gateway, and check the socket and directory modes.",
        ),
    }
}

struct AuthInspection {
    check: DoctorCheck,
    /// The token for the live request, when one resolved and is nonempty.
    token: Option<String>,
}

fn inspect_auth(auth: &DoctorAuth) -> AuthInspection {
    use DoctorStatus::{Fail, Warn};
    let (path, explicit) = match auth {
        DoctorAuth::Environment(token) => {
            let token = token.trim();
            return if token.is_empty() {
                AuthInspection {
                    check: local(
                        "auth_token",
                        Fail,
                        "MARMOT_AGENT_AUTH_TOKEN is set but empty.",
                        "Unset MARMOT_AGENT_AUTH_TOKEN, or set it to the daemon's token.",
                    ),
                    token: None,
                }
            } else {
                AuthInspection {
                    check: local(
                        "auth_token",
                        DoctorStatus::Ok,
                        "The token comes from MARMOT_AGENT_AUTH_TOKEN (not checked against the daemon here).",
                        NO_ACTION,
                    ),
                    token: Some(token.to_owned()),
                }
            };
        }
        DoctorAuth::File { path, explicit } => (path, *explicit),
    };
    let fail = |summary: String, next_step: &str| AuthInspection {
        check: local("auth_token", Fail, summary, next_step),
        token: None,
    };
    let symlinked =
        std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink());
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound && !explicit => {
            return AuthInspection {
                check: local(
                    "auth_token",
                    DoctorStatus::Ok,
                    "No token is configured; the daemon then admits only clients running as its own user.",
                    NO_ACTION,
                ),
                token: None,
            };
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return fail(
                "The configured token file does not exist.".to_owned(),
                "Fix --auth-token-file or MARMOT_AGENT_AUTH_TOKEN_FILE so it names the daemon's token file.",
            );
        }
        Err(error) => {
            return fail(
                format!("The token file cannot be inspected ({:?}).", error.kind()),
                "Run doctor as the gateway's user, which must be able to read the token file.",
            );
        }
    };
    if !metadata.is_file() {
        return fail(
            "The token file is not a regular file.".to_owned(),
            "Point --auth-token-file or MARMOT_AGENT_AUTH_TOKEN_FILE at a regular file.",
        );
    }
    let mode = mode_of(&metadata) & 0o777;
    let mut contents = Zeroizing::new(String::new());
    let read = std::fs::File::open(path).and_then(|file| {
        file.take(MAX_TOKEN_FILE_BYTES + 1)
            .read_to_string(&mut contents)
    });
    match read {
        Err(error) => {
            return fail(
                format!("The token file cannot be read ({:?}).", error.kind()),
                "Run doctor as the gateway's user, which must be able to read the token file.",
            );
        }
        Ok(bytes) if bytes as u64 > MAX_TOKEN_FILE_BYTES => {
            return fail(
                "The token file is larger than 64 KiB.".to_owned(),
                "Write only the token (for example `openssl rand -hex 32`) into the token file.",
            );
        }
        Ok(_) => {}
    }
    let token = contents.trim();
    if token.is_empty() {
        return fail(
            "The token file is empty.".to_owned(),
            "Write the daemon's token into the file (for example `openssl rand -hex 32`), then restart wn-agent.",
        );
    }
    let token = Some(token.to_owned());
    if mode & 0o007 != 0 {
        return AuthInspection {
            check: local(
                "auth_token",
                Fail,
                format!("The token file has mode {mode:04o}; other users can use it."),
                "Run `chmod 600 <token-file>` (0640 only for a split-user gateway group), then rotate the token.",
            ),
            token,
        };
    }
    // wn-agent and bootstrap follow a symlinked token file, as secret-volume
    // mounts need, so this warns rather than fails.
    if symlinked {
        return AuthInspection {
            check: local(
                "auth_token",
                Warn,
                format!(
                    "The token path is a symlink to a nonempty regular file with mode {mode:04o}."
                ),
                "Keep the symlink and every directory above it writable only by trusted users, or point at \
                 the file itself.",
            ),
            token,
        };
    }
    if mode & 0o070 != 0 {
        return AuthInspection {
            check: local(
                "auth_token",
                Warn,
                format!("The token file has mode {mode:04o}; its group can use it."),
                "Keep it at 0600 unless a split-user gateway group needs to read it.",
            ),
            token,
        };
    }
    AuthInspection {
        check: local(
            "auth_token",
            DoctorStatus::Ok,
            format!("The token file is a nonempty regular file with mode {mode:04o}."),
            NO_ACTION,
        ),
        token,
    }
}

fn check_relays(relays: &[String], source: RelaySource) -> DoctorCheck {
    use DoctorStatus::*;
    let source = match source {
        RelaySource::Flag => "the --relay flag",
        RelaySource::Environment => "MARMOT_RELAYS or MARMOT_RELAY",
        RelaySource::Defaults => "the built-in defaults",
    };
    let count = u32::try_from(relays.len()).unwrap_or(u32::MAX);
    if relays.is_empty() {
        return local(
            "relays",
            Fail,
            format!("No relays resolve from {source}."),
            "Pass wss:// relay URLs with --relay or MARMOT_RELAYS.",
        );
    }
    if marmot_app::validate_relay_urls(relays).is_err() {
        return local(
            "relays",
            Fail,
            format!(
                "{} from {source}, and at least one is not a valid relay URL.",
                plural(count, "relay", "relays")
            ),
            "Pass only wss:// relay URLs with --relay or MARMOT_RELAYS.",
        );
    }
    local(
        "relays",
        Ok,
        format!("{} from {source}.", plural(count, "relay", "relays")),
        NO_ACTION,
    )
}

/// Account records and file modes under `<home>/accounts`, read without
/// changing anything.
#[derive(Debug, Default)]
struct AccountScan {
    /// `<home>/accounts` exists.
    present: bool,
    error: Option<ErrorKind>,
    records: u32,
    local_signing: u32,
    /// Local-signing accounts marked signed out, which wn-agent does not start.
    signed_out: u32,
    unreadable: u32,
    /// Entries with any group or other permission bit, and symlinks.
    loose: u32,
    /// Entries the group can read or change through the directories above them.
    group_exposed: u32,
    /// Entries other users can read or change through the directories above them.
    world_exposed: u32,
    /// Entries whose metadata or listing could not be read, or beyond the walk bounds.
    uninspected: u32,
    visited: u32,
}

const MAX_ACCOUNT_WALK_DEPTH: u32 = 8;
const MAX_ACCOUNT_WALK_ENTRIES: u32 = 100_000;

/// Which other users can traverse down to an entry: every directory from the
/// home down must grant that class execute permission.
#[derive(Clone, Copy)]
struct Reach {
    group: bool,
    world: bool,
}

impl Reach {
    fn through(self, mode: u32) -> Self {
        Self {
            group: self.group && mode & 0o010 != 0,
            world: self.world && mode & 0o001 != 0,
        }
    }
}

impl AccountScan {
    /// Count one entry that `reach` can get to; directories recurse.
    fn walk(&mut self, path: &Path, metadata: &Metadata, reach: Reach, depth: u32) {
        if metadata.file_type().is_symlink() {
            self.loose += 1;
            return;
        }
        let mode = mode_of(metadata);
        if mode & 0o077 != 0 {
            self.loose += 1;
        }
        // A file exposes its contents; a directory lets others replace entries.
        let (group_exposes, world_exposes) = if metadata.is_dir() {
            (mode & 0o030 == 0o030, mode & 0o003 == 0o003)
        } else {
            (mode & 0o060 != 0, mode & 0o006 != 0)
        };
        if reach.world && world_exposes {
            self.world_exposed += 1;
        } else if reach.group && group_exposes {
            self.group_exposed += 1;
        }
        if !metadata.is_dir() {
            return;
        }
        if depth >= MAX_ACCOUNT_WALK_DEPTH {
            self.uninspected += 1;
            return;
        }
        let Ok(entries) = std::fs::read_dir(path) else {
            self.uninspected += 1;
            return;
        };
        let reach = reach.through(mode);
        for entry in entries {
            if self.visited >= MAX_ACCOUNT_WALK_ENTRIES {
                self.uninspected += 1;
                return;
            }
            self.visited += 1;
            let child = entry.and_then(|entry| {
                let path = entry.path();
                std::fs::symlink_metadata(&path).map(|metadata| (path, metadata))
            });
            match child {
                Ok((path, metadata)) => self.walk(&path, &metadata, reach, depth + 1),
                Err(_) => self.uninspected += 1,
            }
        }
    }
}

/// Account records are small JSON files.
const MAX_ACCOUNT_RECORD_BYTES: u64 = 64 * 1024;

/// Read one account record without blocking on a FIFO or reading an
/// oversized file. `Ok(None)` means there is no record.
fn read_account_record(path: &Path) -> Result<Option<AccountSummary>, ()> {
    use std::os::unix::fs::OpenOptionsExt;

    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if matches!(error.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => {
            return Ok(None);
        }
        Err(_) => return Err(()),
    };
    if !file.metadata().is_ok_and(|metadata| metadata.is_file()) {
        return Err(());
    }
    let mut bytes = Vec::new();
    file.take(MAX_ACCOUNT_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() as u64 > MAX_ACCOUNT_RECORD_BYTES {
        return Err(());
    }
    serde_json::from_slice(&bytes).map(Some).map_err(|_| ())
}

fn scan_accounts(home: &Path) -> AccountScan {
    let mut scan = AccountScan::default();
    let accounts_dir = home.join("accounts");
    let accounts_meta = match std::fs::metadata(&accounts_dir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return scan,
        Err(error) => {
            scan.error = Some(error.kind());
            return scan;
        }
    };
    scan.present = true;
    let entries = match std::fs::read_dir(&accounts_dir) {
        Ok(entries) => entries,
        Err(error) => {
            scan.error = Some(error.kind());
            return scan;
        }
    };
    // Records are found as `AccountHome` finds them, following symlinks.
    for entry in entries.flatten() {
        match read_account_record(&entry.path().join("account.json")) {
            Ok(Some(account)) => {
                scan.records += 1;
                scan.local_signing += u32::from(account.local_signing);
                scan.signed_out += u32::from(account.local_signing && account.signed_out);
            }
            Ok(None) => {}
            Err(()) => scan.unreadable += 1,
        }
    }
    let home_mode = std::fs::metadata(home).map_or(0, |metadata| mode_of(&metadata));
    let reach = Reach {
        group: true,
        world: true,
    }
    .through(home_mode);
    scan.walk(&accounts_dir, &accounts_meta, reach, 0);
    scan
}

fn check_accounts(scan: &AccountScan) -> DoctorCheck {
    use DoctorStatus::*;
    if let Some(kind) = scan.error {
        return local(
            "accounts",
            Unknown,
            format!("The account directory cannot be read ({kind:?})."),
            "Run doctor as the user that runs wn-agent, with the same --home.",
        );
    }
    let mut notes = String::new();
    if scan.signed_out > 0 {
        notes.push_str(&format!(" {} signed out.", scan.signed_out));
    }
    if scan.unreadable > 0 {
        notes.push_str(&format!(
            " {} could not be read.",
            plural(scan.unreadable, "account record", "account records")
        ));
    }
    if scan.local_signing > 0 && scan.signed_out == scan.local_signing {
        return local(
            "accounts",
            Fail,
            format!(
                "Every local-signing account is signed out, so wn-agent starts none of them.{notes}"
            ),
            "Sign the account back in from the app that signed it out, or bootstrap a different agent account.",
        );
    }
    let (status, summary, next_step) = match scan.local_signing {
        0 => (
            Fail,
            format!(
                "No local-signing account ({} in this home).",
                plural(scan.records, "account record", "account records")
            ),
            BOOTSTRAP_ACCOUNT,
        ),
        1 => (
            Ok,
            "One local-signing account; requests select it automatically.".to_owned(),
            NO_ACTION,
        ),
        count => (
            Warn,
            format!(
                "{count} local-signing accounts; a request that names no account is ambiguous."
            ),
            "Name the account in your integration (for example `wn-agent bootstrap --account-id-hex`), \
             or run one wn-agent home per agent account.",
        ),
    };
    if !notes.is_empty() && status == Ok {
        return local(
            "accounts",
            Warn,
            format!("{summary}{notes}"),
            "Check that this user can read every account record under <home>/accounts, and that the \
             account is signed in.",
        );
    }
    local("accounts", status, format!("{summary}{notes}"), next_step)
}

fn check_account_files(scan: &AccountScan) -> DoctorCheck {
    use DoctorStatus::*;
    const TIGHTEN: &str = "Run `chmod 700` on <home>/accounts and the directories under it and \
                           `chmod 600` on the files, and replace any symlinks there with the files themselves.";
    if let Some(kind) = scan.error {
        return local(
            "account_files",
            Unknown,
            format!("The account directory cannot be read ({kind:?})."),
            "Run doctor as the user that runs wn-agent, with the same --home.",
        );
    }
    if !scan.present {
        return local(
            "account_files",
            Ok,
            "No account files exist yet.",
            NO_ACTION,
        );
    }
    let uninspected = if scan.uninspected > 0 {
        format!(
            " {} could not be inspected.",
            plural(scan.uninspected, "account entry", "account entries")
        )
    } else {
        String::new()
    };
    if scan.world_exposed > 0 {
        return local(
            "account_files",
            Fail,
            format!(
                "Other users can read or change {}.{uninspected}",
                plural(scan.world_exposed, "account entry", "account entries")
            ),
            TIGHTEN,
        );
    }
    if scan.group_exposed > 0 {
        return local(
            "account_files",
            Warn,
            format!(
                "The group can read or change {}.{uninspected}",
                plural(scan.group_exposed, "account entry", "account entries")
            ),
            TIGHTEN,
        );
    }
    if scan.loose > 0 {
        return local(
            "account_files",
            Warn,
            format!(
                "{}; no other user can reach them through the directories above.{uninspected}",
                plural(
                    scan.loose,
                    "account entry has group or other permission bits or is a symlink",
                    "account entries have group or other permission bits or are symlinks"
                )
            ),
            TIGHTEN,
        );
    }
    if scan.uninspected > 0 {
        return local(
            "account_files",
            Unknown,
            format!("The inspected account files are owner-only.{uninspected}"),
            "Run doctor as the user that runs wn-agent, which must be able to list every account directory.",
        );
    }
    local(
        "account_files",
        Ok,
        "Account directories and files are owner-only.",
        NO_ACTION,
    )
}

/// What the one `diagnostic_status` request produced.
enum LiveOutcome {
    NotRunning,
    Unreachable(ErrorKind),
    TimedOut,
    WrongProtocol,
    Rejected(Option<String>),
    Unexpected,
    Report(Box<AgentControlDiagnosticStatus>),
}

async fn query_daemon(
    options: &DoctorOptions,
    socket: &SocketProbe,
    token: Option<String>,
) -> LiveOutcome {
    match socket {
        SocketProbe::State(SocketPathState::Live) => {}
        SocketProbe::Error(kind) => return LiveOutcome::Unreachable(*kind),
        _ => return LiveOutcome::NotRunning,
    }
    let client = ControlClient::new(options.socket.clone(), token, options.request_timeout);
    let request = AgentControlRequest::DiagnosticStatus {
        account_id_hex: None,
        home_group_id_hex: None,
    };
    match client.request(request).await {
        Ok(envelope) => match envelope.payload {
            AgentControlResponse::DiagnosticStatus { report } => {
                LiveOutcome::Report(Box::new(report))
            }
            AgentControlResponse::Error { code, .. } => {
                LiveOutcome::Rejected(safe_code(&code).map(str::to_owned))
            }
            _ => LiveOutcome::Unexpected,
        },
        Err(BootstrapError::RequestTimedOut) => LiveOutcome::TimedOut,
        Err(BootstrapError::Control(AgentControlError::WrongProtocol(_))) => {
            LiveOutcome::WrongProtocol
        }
        Err(BootstrapError::Control(AgentControlError::Io(error))) => {
            LiveOutcome::Unreachable(error.kind())
        }
        Err(_) => LiveOutcome::Unexpected,
    }
}

/// Error codes and reasons are snake_case labels; anything else from the wire
/// is withheld.
fn safe_code(value: &str) -> Option<&str> {
    (!value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_'))
    .then_some(value)
}

fn safe_version(value: &str) -> Option<&str> {
    (!value.is_empty()
        && value.len() <= 32
        && value.contains('.')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+')))
    .then_some(value)
}

const LIVE_IDS: [&str; 5] = [
    "protocol",
    "daemon_accounts",
    "key_package",
    "relay_health",
    "replay",
];

fn live_checks(outcome: &LiveOutcome, accounts: &AccountScan) -> Vec<DoctorCheck> {
    use DoctorStatus::*;
    let daemon = match outcome {
        LiveOutcome::Report(_) => live(
            "daemon",
            Ok,
            "wn-agent answered diagnostic_status on the control socket.",
            NO_ACTION,
        ),
        LiveOutcome::NotRunning => live(
            "daemon",
            Fail,
            "wn-agent is not running at the configured socket.",
            START_DAEMON,
        ),
        LiveOutcome::Unreachable(ErrorKind::PermissionDenied) => live(
            "daemon",
            Fail,
            "This user may not connect to the control socket.",
            "Run doctor as the gateway's user; a different user needs a token and group socket modes.",
        ),
        LiveOutcome::Unreachable(kind @ (ErrorKind::WouldBlock | ErrorKind::TimedOut)) => live(
            "daemon",
            Fail,
            format!("wn-agent is not accepting connections ({kind:?})."),
            BUSY_DAEMON,
        ),
        LiveOutcome::Unreachable(kind) => live(
            "daemon",
            Fail,
            format!("wn-agent could not be reached ({kind:?})."),
            START_DAEMON,
        ),
        LiveOutcome::TimedOut => live(
            "daemon",
            Fail,
            format!(
                "wn-agent did not answer within {} seconds.",
                DOCTOR_REQUEST_TIMEOUT.as_secs()
            ),
            BUSY_DAEMON,
        ),
        LiveOutcome::WrongProtocol => live(
            "daemon",
            Ok,
            "wn-agent answered on the control socket.",
            NO_ACTION,
        ),
        LiveOutcome::Rejected(Some(code)) if code == "unauthorized" => live(
            "daemon",
            Fail,
            "wn-agent rejected the request as unauthorized.",
            "Pass the daemon's token with --auth-token-file or MARMOT_AGENT_AUTH_TOKEN_FILE, or run \
             doctor as the daemon's user when it has no token.",
        ),
        LiveOutcome::Rejected(code) => live(
            "daemon",
            Fail,
            format!(
                "wn-agent refused diagnostic_status with error code {}.",
                code.as_deref().unwrap_or("(withheld)")
            ),
            SAME_RELEASE,
        ),
        LiveOutcome::Unexpected => live(
            "daemon",
            Fail,
            "wn-agent sent an unexpected answer.",
            SAME_RELEASE,
        ),
    };
    let report = match outcome {
        LiveOutcome::Report(report) => report,
        LiveOutcome::WrongProtocol => {
            let mut checks = vec![
                daemon,
                live(
                    "protocol",
                    Fail,
                    "The daemon speaks a different control protocol than this CLI.",
                    SAME_RELEASE,
                ),
            ];
            checks.extend(LIVE_IDS[1..].iter().copied().map(|id| {
                live(
                    id,
                    Unknown,
                    "Needs a daemon that speaks this CLI's protocol.",
                    SAME_RELEASE,
                )
            }));
            return checks;
        }
        _ => {
            let mut checks = vec![daemon];
            checks.extend(
                LIVE_IDS
                    .iter()
                    .copied()
                    .map(|id| live(id, Unknown, "Needs a reachable daemon.", RERUN_AFTER_DAEMON)),
            );
            return checks;
        }
    };
    vec![
        daemon,
        check_protocol(report),
        check_daemon_accounts(report, accounts),
        check_key_package(report),
        check_relay_health(report),
        check_replay(report),
    ]
}

fn check_protocol(report: &AgentControlDiagnosticStatus) -> DoctorCheck {
    use DoctorStatus::*;
    let cli_version = env!("CARGO_PKG_VERSION");
    if report.protocol != AGENT_CONTROL_PROTOCOL_V2 {
        return live(
            "protocol",
            Fail,
            "The daemon reports a different control protocol than this CLI.",
            SAME_RELEASE,
        );
    }
    match safe_version(&report.connector_version) {
        Some(version) if version == cli_version => live(
            "protocol",
            Ok,
            format!(
                "The CLI and daemon both speak {AGENT_CONTROL_PROTOCOL_V2} at version {version}."
            ),
            NO_ACTION,
        ),
        version => live(
            "protocol",
            Warn,
            format!(
                "Both speak {AGENT_CONTROL_PROTOCOL_V2}, but the CLI is {cli_version} and the daemon is {}.",
                version.unwrap_or("(unrecognized)")
            ),
            SAME_RELEASE,
        ),
    }
}

fn check_daemon_accounts(
    report: &AgentControlDiagnosticStatus,
    accounts: &AccountScan,
) -> DoctorCheck {
    use DoctorStatus::*;
    let count = report.local_signing_account_count;
    let (status, summary, next_step) = match report.selection {
        AgentControlAccountSelection::None => (
            Fail,
            "The daemon has no local-signing account.".to_owned(),
            BOOTSTRAP_ACCOUNT,
        ),
        AgentControlAccountSelection::Selected => (
            Ok,
            "The daemon selected its only local-signing account.".to_owned(),
            NO_ACTION,
        ),
        AgentControlAccountSelection::Ambiguous => (
            Warn,
            format!("The daemon has {count} local-signing accounts and cannot pick one."),
            "Name the account in your integration, or run one wn-agent home per agent account.",
        ),
        AgentControlAccountSelection::ExplicitUnavailable => (
            Unknown,
            "The daemon could not resolve an account for this report.".to_owned(),
            SAME_RELEASE,
        ),
    };
    let same_home = accounts.error.is_some() || accounts.local_signing == count;
    if !same_home {
        // Repairing either side would act on the wrong instance.
        return live(
            "daemon_accounts",
            if status == Fail { Fail } else { Warn },
            format!(
                "The daemon reports {count} local-signing accounts but this home has {}.",
                accounts.local_signing
            ),
            "Point --home and --socket at the same wn-agent instance.",
        );
    }
    live("daemon_accounts", status, summary, next_step)
}

fn check_key_package(report: &AgentControlDiagnosticStatus) -> DoctorCheck {
    use DoctorStatus::*;
    let key_package = &report.key_package;
    let accepted = key_package.accepted_fanout_targets;
    let failed = key_package.failed_fanout_targets;
    match key_package.availability {
        AgentControlKeyPackageAvailability::Unavailable
            if report.selection == AgentControlAccountSelection::Selected =>
        {
            live(
                "key_package",
                Fail,
                "The selected account's KeyPackage cannot be read: the account is signed out or its worker is \
                 not running.",
                "Check the accounts check for a signed-out account; otherwise restart wn-agent and rerun \
                 wn-agent doctor.",
            )
        }
        AgentControlKeyPackageAvailability::Unavailable => live(
            "key_package",
            Unknown,
            "The daemon cannot report a KeyPackage without exactly one selected account.",
            "Resolve the daemon_accounts check, then rerun wn-agent doctor.",
        ),
        AgentControlKeyPackageAvailability::Absent => live(
            "key_package",
            Fail,
            "This device has no current KeyPackage, so invites cannot reach the agent.",
            REPUBLISH_KEY_PACKAGE,
        ),
        AgentControlKeyPackageAvailability::Pending => live(
            "key_package",
            Warn,
            "A KeyPackage replacement is in progress.",
            "Rerun wn-agent doctor in a minute; if it stays pending, run `wn-agent bootstrap --home <home>`.",
        ),
        AgentControlKeyPackageAvailability::Present
        | AgentControlKeyPackageAvailability::Degraded => {
            if key_package.expired == Some(true) {
                return live(
                    "key_package",
                    Fail,
                    "This device's current KeyPackage has expired.",
                    REPUBLISH_KEY_PACKAGE,
                );
            }
            if accepted == 0 {
                return live(
                    "key_package",
                    Warn,
                    format!(
                        "This device has a KeyPackage, but no relay has accepted it ({} failed).",
                        failed
                    ),
                    "Check relay_health; if relays are connected, run `wn-agent bootstrap --home <home>`.",
                );
            }
            let unattempted = key_package.unattempted_fanout_targets;
            let prohibited = key_package.policy_prohibited_fanout_targets;
            if unattempted > 0 || prohibited > 0 {
                return live(
                    "key_package",
                    Warn,
                    format!(
                        "This device's KeyPackage is current, but publication is incomplete: {} accepted, \
                         {failed} failed, {unattempted} not yet attempted, {prohibited} refused by relay policy.",
                        plural(accepted, "relay", "relays")
                    ),
                    "Rerun wn-agent doctor in a minute; if targets stay unattempted or refused, check \
                     relay_health and the relay list.",
                );
            }
            if failed > 0 {
                return live(
                    "key_package",
                    Warn,
                    format!(
                        "This device's KeyPackage is current; {} accepted it and {} rejected it.",
                        plural(accepted, "relay", "relays"),
                        failed
                    ),
                    "Check relay_health; wn-agent retries the failed relays.",
                );
            }
            live(
                "key_package",
                Ok,
                format!(
                    "This device's KeyPackage is current and {} accepted it.",
                    plural(accepted, "relay", "relays")
                ),
                NO_ACTION,
            )
        }
    }
}

fn check_relay_health(report: &AgentControlDiagnosticStatus) -> DoctorCheck {
    use DoctorStatus::*;
    let relays = &report.relays;
    let counts = format!(
        "{} connected, {} disconnected, {} configured",
        relays.connected, relays.disconnected, relays.configured
    );
    if relays.configured == 0 {
        return live(
            "relay_health",
            Fail,
            "The running daemon has no relays configured.",
            "Restart wn-agent with --relay (see Run locally in the connector README).",
        );
    }
    if relays.connected == 0 && relays.disconnected == 0 {
        return live(
            "relay_health",
            Warn,
            format!(
                "No relay connection has been made yet ({counts}); wn-agent connects once an account runs."
            ),
            "Resolve the daemon_accounts check, then rerun wn-agent doctor after the account starts.",
        );
    }
    if relays.connected == 0 {
        return live(
            "relay_health",
            Fail,
            format!("No relay is connected ({counts})."),
            "Check outbound network access to the relays; wn-agent reconnects on its own.",
        );
    }
    if relays.disconnected > 0 {
        return live(
            "relay_health",
            Warn,
            format!("Some relays are disconnected ({counts})."),
            "Check outbound network access to the relays; wn-agent reconnects on its own.",
        );
    }
    live("relay_health", Ok, format!("Relays: {counts}."), NO_ACTION)
}

fn check_replay(report: &AgentControlDiagnosticStatus) -> DoctorCheck {
    use DoctorStatus::*;
    let replay = &report.replay;
    let passes = format!(
        "{} passes completed, {} failed",
        replay.success_count, replay.failure_count
    );
    match replay.state {
        AgentControlReplayState::Failed => live(
            "replay",
            Warn,
            format!(
                "The last inbound catch-up pass failed (reason: {}; {passes}).",
                replay
                    .last_reason
                    .as_deref()
                    .and_then(safe_code)
                    .unwrap_or("not reported")
            ),
            "wn-agent retries on its own; if this persists, check relay_health and restart wn-agent.",
        ),
        AgentControlReplayState::Running => live(
            "replay",
            Ok,
            format!("Inbound catch-up is running ({passes})."),
            NO_ACTION,
        ),
        AgentControlReplayState::Idle => live(
            "replay",
            Ok,
            format!("Inbound catch-up is idle ({passes})."),
            NO_ACTION,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::DEFAULT_RELAYS;
    use agent_control::{
        AgentControlDiagnosticHome, AgentControlDiagnosticKeyPackage, AgentControlDiagnosticRelays,
        AgentControlDiagnosticReplay, AgentControlEnvelope, read_envelope, write_frame,
    };
    use tokio::io::{AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;

    const ACCOUNT_ID: &str = "aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4";
    const SECOND_ACCOUNT_ID: &str =
        "bb4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b5";
    const TOKEN: &str = "doctor-fixture-token-6f1d2c";
    const RELAY: &str = "wss://doctor-fixture.example.org";

    /// A home under a short, canonical temp root so socket paths fit.
    struct Fixture {
        _root: tempfile::TempDir,
        home: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let base = std::fs::canonicalize(std::env::temp_dir()).unwrap();
            let base = if base.as_os_str().len() > 40 {
                std::fs::canonicalize("/tmp").unwrap()
            } else {
                base
            };
            let root = tempfile::tempdir_in(base).unwrap();
            let home = root.path().join("h");
            std::fs::create_dir(&home).unwrap();
            chmod(&home, 0o700);
            Self { _root: root, home }
        }

        fn socket(&self) -> PathBuf {
            crate::default_socket_path(&self.home)
        }

        fn dev_dir(&self, mode: u32) {
            let dev = self.home.join("dev");
            std::fs::create_dir_all(&dev).unwrap();
            chmod(&dev, mode);
        }

        fn account(&self, label: &str, account_id_hex: &str, local_signing: bool) {
            self.account_record(label, account_id_hex, local_signing, false);
        }

        fn account_record(
            &self,
            label: &str,
            account_id_hex: &str,
            local_signing: bool,
            signed_out: bool,
        ) {
            let dir = self.home.join("accounts").join(label);
            std::fs::create_dir_all(&dir).unwrap();
            chmod(&self.home.join("accounts"), 0o700);
            chmod(&dir, 0o700);
            let record = AccountSummary {
                label: label.to_owned(),
                account_id_hex: account_id_hex.to_owned(),
                local_signing,
                external_signing: false,
                signed_out,
            };
            let path = dir.join("account.json");
            std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
            chmod(&path, 0o600);
            let secret = dir.join("secret.json");
            std::fs::write(&secret, b"{}").unwrap();
            chmod(&secret, 0o600);
        }

        fn token_file(&self, contents: &str, mode: u32) -> PathBuf {
            let path = self.home.join("control.token");
            std::fs::write(&path, contents).unwrap();
            chmod(&path, mode);
            path
        }

        fn options(&self) -> DoctorOptions {
            self.options_with(DoctorAuth::File {
                path: self.home.join("control.token"),
                explicit: false,
            })
        }

        fn options_with(&self, auth: DoctorAuth) -> DoctorOptions {
            DoctorOptions {
                home: self.home.clone(),
                socket: self.socket(),
                socket_dir_mode: AGENT_SOCKET_DIR_MODE,
                auth,
                relays: DEFAULT_RELAYS
                    .iter()
                    .map(|relay| (*relay).to_owned())
                    .collect(),
                relay_source: RelaySource::Defaults,
                request_timeout: Duration::from_secs(5),
            }
        }
    }

    fn chmod(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn find<'a>(report: &'a DoctorReport, id: &str) -> &'a DoctorCheck {
        report
            .checks
            .iter()
            .find(|check| check.id == id)
            .unwrap_or_else(|| panic!("missing check {id}"))
    }

    fn assert_check(report: &DoctorReport, id: &str, status: DoctorStatus, next_step: &str) {
        let check = find(report, id);
        assert_eq!(check.status, status, "{id}: {}", check.summary);
        assert!(
            check.next_step.contains(next_step),
            "{id} next step {:?} lacks {next_step:?}",
            check.next_step
        );
    }

    fn diagnostic(key_package: AgentControlDiagnosticKeyPackage) -> AgentControlDiagnosticStatus {
        AgentControlDiagnosticStatus {
            protocol: AGENT_CONTROL_PROTOCOL_V2.to_owned(),
            connector_version: env!("CARGO_PKG_VERSION").to_owned(),
            account_count: 1,
            local_signing_account_count: 1,
            selection: AgentControlAccountSelection::Selected,
            welcomer_count: 1,
            allow_any: false,
            key_package,
            relays: AgentControlDiagnosticRelays {
                configured: 2,
                connected: 2,
                disconnected: 0,
            },
            replay: AgentControlDiagnosticReplay {
                state: AgentControlReplayState::Idle,
                last_reason: None,
                success_count: 3,
                failure_count: 0,
                resync_count: 0,
                cancelled_count: 0,
            },
            home: AgentControlDiagnosticHome::not_requested(),
        }
    }

    fn current_key_package() -> AgentControlDiagnosticKeyPackage {
        AgentControlDiagnosticKeyPackage {
            availability: AgentControlKeyPackageAvailability::Present,
            phase: Some("idle".to_owned()),
            present: true,
            expired: Some(false),
            accepted_fanout_targets: 2,
            unattempted_fanout_targets: 0,
            failed_fanout_targets: 0,
            policy_prohibited_fanout_targets: 0,
        }
    }

    /// Serve `response` to every `diagnostic_status` request, checking the token.
    async fn serve_daemon(
        socket: PathBuf,
        expected_token: Option<&'static str>,
        response: AgentControlResponse,
    ) -> tokio::task::JoinHandle<()> {
        let listener = UnixListener::bind(&socket).unwrap();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let (reader, mut writer) = tokio::io::split(stream);
                let mut reader = BufReader::new(reader);
                let Ok(Some(envelope)) = read_envelope::<_, AgentControlRequest>(&mut reader).await
                else {
                    continue;
                };
                assert!(matches!(
                    envelope.payload,
                    AgentControlRequest::DiagnosticStatus {
                        account_id_hex: None,
                        home_group_id_hex: None
                    }
                ));
                let payload = if envelope.auth_token.as_deref() == expected_token {
                    response.clone()
                } else {
                    AgentControlResponse::Error {
                        code: "unauthorized".to_owned(),
                        message: "agent control request is unauthorized".to_owned(),
                        retryable: false,
                    }
                };
                let reply = AgentControlEnvelope::new(envelope.id, payload);
                write_frame(&mut writer, &reply).await.unwrap();
                writer.shutdown().await.ok();
            }
        })
    }

    #[tokio::test]
    async fn empty_home_fails_accounts_and_daemon() {
        let fixture = Fixture::new();
        let report = run_doctor(&fixture.options()).await;
        assert_check(&report, "home", DoctorStatus::Ok, NO_ACTION);
        assert_check(&report, "socket_dir", DoctorStatus::Ok, NO_ACTION);
        assert_check(&report, "socket_path", DoctorStatus::Ok, NO_ACTION);
        assert_check(&report, "auth_token", DoctorStatus::Ok, NO_ACTION);
        assert_check(&report, "relays", DoctorStatus::Ok, NO_ACTION);
        assert_check(
            &report,
            "accounts",
            DoctorStatus::Fail,
            "wn-agent bootstrap",
        );
        assert_check(&report, "account_files", DoctorStatus::Ok, NO_ACTION);
        assert_check(&report, "daemon", DoctorStatus::Fail, "Start `wn-agent");
        for id in LIVE_IDS {
            assert_check(&report, id, DoctorStatus::Unknown, RERUN_AFTER_DAEMON);
        }
        assert!(report.has_failures());
    }

    #[tokio::test]
    async fn missing_home_warns_and_is_not_created() {
        let fixture = Fixture::new();
        std::fs::remove_dir(&fixture.home).unwrap();
        let report = run_doctor(&fixture.options()).await;
        assert_check(&report, "home", DoctorStatus::Warn, "--home");
        assert!(!fixture.home.exists(), "doctor must not create the home");
    }

    #[tokio::test]
    async fn loose_home_warns_with_chmod() {
        let fixture = Fixture::new();
        chmod(&fixture.home, 0o755);
        let report = run_doctor(&fixture.options()).await;
        assert_check(&report, "home", DoctorStatus::Warn, "chmod 700 <home>");
        assert_eq!(
            mode_of(&std::fs::metadata(&fixture.home).unwrap()),
            0o755,
            "doctor must not change modes"
        );
    }

    #[tokio::test]
    async fn stale_socket_warns_and_is_left_in_place() {
        let fixture = Fixture::new();
        fixture.dev_dir(0o700);
        let socket = fixture.socket();
        drop(std::os::unix::net::UnixListener::bind(&socket).unwrap());
        let report = run_doctor(&fixture.options()).await;
        assert_check(
            &report,
            "socket_path",
            DoctorStatus::Warn,
            "removes the stale socket",
        );
        assert_check(&report, "daemon", DoctorStatus::Fail, "Start `wn-agent");
        assert!(socket.exists(), "doctor must not remove a stale socket");
    }

    #[tokio::test]
    async fn regular_file_at_socket_path_fails() {
        let fixture = Fixture::new();
        fixture.dev_dir(0o700);
        std::fs::write(fixture.socket(), b"not a socket").unwrap();
        let report = run_doctor(&fixture.options()).await;
        assert_check(
            &report,
            "socket_path",
            DoctorStatus::Fail,
            "Move that file aside",
        );
        assert_check(&report, "daemon", DoctorStatus::Fail, "Start `wn-agent");
        assert!(fixture.socket().is_file());
    }

    #[tokio::test]
    async fn world_accessible_socket_dir_fails_for_custom_socket() {
        let fixture = Fixture::new();
        let shared = fixture.home.join("shared");
        std::fs::create_dir(&shared).unwrap();
        chmod(&shared, 0o777);
        let mut options = fixture.options();
        options.socket = shared.join("s.sock");
        let report = run_doctor(&options).await;
        assert_check(&report, "socket_dir", DoctorStatus::Fail, "chmod 700");
        assert_eq!(mode_of(&std::fs::metadata(&shared).unwrap()), 0o777);
    }

    #[tokio::test]
    async fn world_accessible_own_socket_dir_warns_because_serve_resets_it() {
        let fixture = Fixture::new();
        fixture.dev_dir(0o777);
        let report = run_doctor(&fixture.options()).await;
        assert_check(
            &report,
            "socket_dir",
            DoctorStatus::Warn,
            "chmod 700 <home>/dev",
        );
        assert_eq!(
            mode_of(&std::fs::metadata(fixture.home.join("dev")).unwrap()),
            0o777
        );
    }

    #[tokio::test]
    async fn group_writable_socket_dir_needs_matching_mode_and_token() {
        let fixture = Fixture::new();
        let shared = fixture.home.join("shared");
        std::fs::create_dir(&shared).unwrap();
        chmod(&shared, 0o770);
        let mut options = fixture.options();
        options.socket = shared.join("s.sock");
        let report = run_doctor(&options).await;
        assert_check(
            &report,
            "socket_dir",
            DoctorStatus::Fail,
            "--socket-dir-mode",
        );

        options.socket_dir_mode = 0o770;
        let report = run_doctor(&options).await;
        assert_check(
            &report,
            "socket_dir",
            DoctorStatus::Fail,
            "--auth-token-file",
        );

        fixture.token_file(TOKEN, 0o640);
        let report = run_doctor(&options).await;
        assert_check(&report, "socket_dir", DoctorStatus::Ok, NO_ACTION);
    }

    #[tokio::test]
    async fn symlinked_home_or_socket_dir_fails_like_serve() {
        let fixture = Fixture::new();
        let link = fixture.home.parent().unwrap().join("link");
        std::os::unix::fs::symlink(&fixture.home, &link).unwrap();
        let mut options = fixture.options();
        options.home = link.clone();
        options.socket = crate::default_socket_path(&link);
        let report = run_doctor(&options).await;
        assert_check(&report, "home", DoctorStatus::Fail, "no symlinks");
        assert_check(&report, "socket_dir", DoctorStatus::Fail, "no symlinks");
        assert!(!fixture.home.join("dev").exists());
    }

    #[tokio::test]
    async fn token_file_fixtures() {
        let fixture = Fixture::new();
        let explicit = |fixture: &Fixture| {
            fixture.options_with(DoctorAuth::File {
                path: fixture.home.join("control.token"),
                explicit: true,
            })
        };

        let report = run_doctor(&explicit(&fixture)).await;
        assert_check(
            &report,
            "auth_token",
            DoctorStatus::Fail,
            "--auth-token-file",
        );

        fixture.token_file("  \n", 0o600);
        let report = run_doctor(&explicit(&fixture)).await;
        assert_check(
            &report,
            "auth_token",
            DoctorStatus::Fail,
            "openssl rand -hex 32",
        );

        fixture.token_file(TOKEN, 0o644);
        let report = run_doctor(&explicit(&fixture)).await;
        assert_check(
            &report,
            "auth_token",
            DoctorStatus::Fail,
            "chmod 600 <token-file>",
        );

        fixture.token_file(TOKEN, 0o640);
        let report = run_doctor(&explicit(&fixture)).await;
        assert_check(&report, "auth_token", DoctorStatus::Warn, "0600");

        fixture.token_file(TOKEN, 0o600);
        let report = run_doctor(&explicit(&fixture)).await;
        assert_check(&report, "auth_token", DoctorStatus::Ok, NO_ACTION);

        let target = fixture.home.join("real.token");
        std::fs::rename(fixture.home.join("control.token"), &target).unwrap();
        std::os::unix::fs::symlink(&target, fixture.home.join("control.token")).unwrap();
        let report = run_doctor(&explicit(&fixture)).await;
        assert_check(&report, "auth_token", DoctorStatus::Warn, "symlink");
        chmod(&target, 0o644);
        let report = run_doctor(&explicit(&fixture)).await;
        assert_check(
            &report,
            "auth_token",
            DoctorStatus::Fail,
            "chmod 600 <token-file>",
        );

        std::fs::remove_file(fixture.home.join("control.token")).unwrap();
        std::fs::remove_file(&target).unwrap();
        std::fs::create_dir(fixture.home.join("control.token")).unwrap();
        let report = run_doctor(&explicit(&fixture)).await;
        assert_check(&report, "auth_token", DoctorStatus::Fail, "regular file");

        let report = run_doctor(
            &fixture.options_with(DoctorAuth::Environment(Zeroizing::new(" ".to_owned()))),
        )
        .await;
        assert_check(
            &report,
            "auth_token",
            DoctorStatus::Fail,
            "MARMOT_AGENT_AUTH_TOKEN",
        );
    }

    #[tokio::test]
    async fn local_signing_account_counts() {
        let fixture = Fixture::new();
        fixture.account("watcher", SECOND_ACCOUNT_ID, false);
        let report = run_doctor(&fixture.options()).await;
        assert_check(
            &report,
            "accounts",
            DoctorStatus::Fail,
            "wn-agent bootstrap",
        );

        fixture.account("agent", ACCOUNT_ID, true);
        let report = run_doctor(&fixture.options()).await;
        assert_check(&report, "accounts", DoctorStatus::Ok, NO_ACTION);
        assert_check(&report, "account_files", DoctorStatus::Ok, NO_ACTION);

        fixture.account("agent-two", SECOND_ACCOUNT_ID, true);
        let report = run_doctor(&fixture.options()).await;
        assert_check(&report, "accounts", DoctorStatus::Warn, "--account-id-hex");
    }

    #[tokio::test]
    async fn account_file_modes() {
        let fixture = Fixture::new();
        fixture.account("agent", ACCOUNT_ID, true);
        let dir = fixture.home.join("accounts").join("agent");
        let record = dir.join("account.json");

        // The 0644 record older builds wrote stays private behind 0700 dirs.
        chmod(&record, 0o644);
        let report = run_doctor(&fixture.options()).await;
        assert_check(&report, "account_files", DoctorStatus::Warn, "chmod 600");

        // Every directory on the way down now lets other users in.
        chmod(&fixture.home, 0o755);
        chmod(&fixture.home.join("accounts"), 0o755);
        chmod(&dir, 0o755);
        let report = run_doctor(&fixture.options()).await;
        assert_check(&report, "account_files", DoctorStatus::Fail, "chmod 700");
        assert_eq!(mode_of(&std::fs::metadata(&record).unwrap()), 0o644);
    }

    #[tokio::test]
    async fn signed_out_only_account_fails() {
        let fixture = Fixture::new();
        fixture.account_record("agent", ACCOUNT_ID, true, true);
        let report = run_doctor(&fixture.options()).await;
        assert_check(
            &report,
            "accounts",
            DoctorStatus::Fail,
            "Sign the account back in",
        );
    }

    #[tokio::test]
    async fn account_walk_covers_writable_dirs_nested_files_and_symlinks() {
        let fixture = Fixture::new();
        fixture.account("agent", ACCOUNT_ID, true);
        let dir = fixture.home.join("accounts").join("agent");

        // Private ancestors keep a symlink unreachable, but it is still flagged.
        std::os::unix::fs::symlink(dir.join("secret.json"), dir.join("alias.json")).unwrap();
        let report = run_doctor(&fixture.options()).await;
        assert_check(
            &report,
            "account_files",
            DoctorStatus::Warn,
            "replace any symlinks",
        );
        std::fs::remove_file(dir.join("alias.json")).unwrap();

        chmod(&fixture.home, 0o755);
        chmod(&fixture.home.join("accounts"), 0o755);
        // A reachable world-writable account directory lets others replace files.
        chmod(&dir, 0o777);
        let report = run_doctor(&fixture.options()).await;
        assert_check(&report, "account_files", DoctorStatus::Fail, "chmod 700");

        // A world-readable file below a nested directory is found too.
        chmod(&dir, 0o755);
        let nested = dir.join("handoff");
        std::fs::create_dir(&nested).unwrap();
        chmod(&nested, 0o755);
        std::fs::write(nested.join("copy.bin"), b"x").unwrap();
        chmod(&nested.join("copy.bin"), 0o644);
        let report = run_doctor(&fixture.options()).await;
        assert_check(&report, "account_files", DoctorStatus::Fail, "chmod 600");
    }

    #[tokio::test]
    async fn own_socket_dir_owned_by_another_user_fails() {
        let fixture = Fixture::new();
        fixture.dev_dir(0o700);
        let options = fixture.options();
        let other_user = current_effective_uid().wrapping_add(1).max(1);
        let check = check_socket_dir(&options, other_user, false);
        assert_eq!(check.status, DoctorStatus::Fail, "{}", check.summary);
        assert!(check.next_step.contains("owner of <home>/dev"));
    }

    #[test]
    fn relay_source_follows_resolver_precedence() {
        let defaults = DEFAULT_RELAYS.join(",");
        assert_eq!(
            relay_source(&[" ".to_owned()], Some(RELAY)),
            RelaySource::Flag
        );
        assert_eq!(relay_source(&[], Some(&defaults)), RelaySource::Environment);
        assert_eq!(relay_source(&[], Some(" , ")), RelaySource::Defaults);
        assert_eq!(relay_source(&[], None), RelaySource::Defaults);
    }

    #[tokio::test]
    async fn fifo_or_oversized_account_record_is_unreadable_not_blocking() {
        let fixture = Fixture::new();
        fixture.account("agent", ACCOUNT_ID, true);
        let fifo_dir = fixture.home.join("accounts").join("fifo");
        std::fs::create_dir(&fifo_dir).unwrap();
        chmod(&fifo_dir, 0o700);
        let fifo =
            std::ffi::CString::new(fifo_dir.join("account.json").as_os_str().as_encoded_bytes())
                .unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let big_dir = fixture.home.join("accounts").join("big");
        std::fs::create_dir(&big_dir).unwrap();
        chmod(&big_dir, 0o700);
        std::fs::write(
            big_dir.join("account.json"),
            vec![b' '; MAX_ACCOUNT_RECORD_BYTES as usize + 1],
        )
        .unwrap();
        chmod(&big_dir.join("account.json"), 0o600);

        let report = tokio::time::timeout(Duration::from_secs(10), run_doctor(&fixture.options()))
            .await
            .expect("doctor does not block on a FIFO record");
        assert_check(
            &report,
            "accounts",
            DoctorStatus::Warn,
            "can read every account record",
        );
        assert!(
            find(&report, "accounts")
                .summary
                .contains("2 account records could not be read")
        );
    }

    #[test]
    fn whitespace_relay_flag_stays_the_source() {
        let fixture = Fixture::new();
        let options = DoctorOptions::resolve(
            Some(fixture.home.clone()),
            None,
            None,
            vec![" ".to_owned()],
            AGENT_SOCKET_DIR_MODE,
        );
        assert_eq!(options.relay_source, RelaySource::Flag);
        let check = check_relays(&options.relays, options.relay_source);
        assert_eq!(check.status, DoctorStatus::Fail);
        assert!(check.summary.contains("--relay flag"), "{}", check.summary);
    }

    #[tokio::test]
    async fn unlistable_account_directory_is_not_reported_ok() {
        if current_effective_uid() == 0 {
            return; // root lists every directory
        }
        let fixture = Fixture::new();
        fixture.account("agent", ACCOUNT_ID, true);
        let dir = fixture.home.join("accounts").join("agent");
        chmod(&dir, 0o300);
        let report = run_doctor(&fixture.options()).await;
        chmod(&dir, 0o700);
        // The record itself is still readable through the traversable directory.
        assert_check(&report, "accounts", DoctorStatus::Ok, NO_ACTION);
        assert_check(
            &report,
            "account_files",
            DoctorStatus::Unknown,
            "list every account directory",
        );
    }

    #[tokio::test]
    async fn saturated_listener_cannot_hang_the_doctor() {
        let fixture = Fixture::new();
        fixture.dev_dir(0o700);
        // Never accepts, so its backlog fills.
        let _listener = std::os::unix::net::UnixListener::bind(fixture.socket()).unwrap();
        let mut held = Vec::new();
        for _ in 0..4096 {
            match tokio::time::timeout(
                Duration::from_millis(200),
                tokio::net::UnixStream::connect(fixture.socket()),
            )
            .await
            {
                Ok(Ok(stream)) => held.push(stream),
                _ => break,
            }
        }
        let mut options = fixture.options();
        options.request_timeout = Duration::from_millis(500);
        let report = tokio::time::timeout(Duration::from_secs(10), run_doctor(&options))
            .await
            .expect("doctor finishes against a saturated listener");
        assert_eq!(find(&report, "daemon").status, DoctorStatus::Fail);
    }

    #[tokio::test]
    async fn invalid_relay_flag_fails() {
        let fixture = Fixture::new();
        let mut options = fixture.options();
        options.relays = vec!["not a relay".to_owned()];
        options.relay_source = RelaySource::Flag;
        let report = run_doctor(&options).await;
        assert_check(&report, "relays", DoctorStatus::Fail, "--relay");
        assert!(find(&report, "relays").summary.contains("--relay flag"));
    }

    #[tokio::test]
    async fn daemon_up_with_current_key_package() {
        let fixture = Fixture::new();
        fixture.dev_dir(0o700);
        fixture.account("agent", ACCOUNT_ID, true);
        let server = serve_daemon(
            fixture.socket(),
            None,
            AgentControlResponse::DiagnosticStatus {
                report: diagnostic(current_key_package()),
            },
        )
        .await;
        let report = run_doctor(&fixture.options()).await;
        server.abort();
        for check in &report.checks {
            assert_eq!(
                check.status,
                DoctorStatus::Ok,
                "{}: {}",
                check.id,
                check.summary
            );
            assert_eq!(check.next_step, NO_ACTION);
        }
        assert!(!report.has_failures());
    }

    #[tokio::test]
    async fn daemon_up_without_current_key_package() {
        let fixture = Fixture::new();
        fixture.dev_dir(0o700);
        fixture.account("agent", ACCOUNT_ID, true);
        let mut absent = AgentControlDiagnosticKeyPackage::unavailable();
        absent.availability = AgentControlKeyPackageAvailability::Absent;
        let mut expired = current_key_package();
        expired.availability = AgentControlKeyPackageAvailability::Degraded;
        expired.expired = Some(true);
        for key_package in [absent, expired] {
            let socket = fixture.socket();
            let _ = std::fs::remove_file(&socket);
            let server = serve_daemon(
                socket,
                None,
                AgentControlResponse::DiagnosticStatus {
                    report: diagnostic(key_package),
                },
            )
            .await;
            let report = run_doctor(&fixture.options()).await;
            server.abort();
            assert_check(&report, "daemon", DoctorStatus::Ok, NO_ACTION);
            assert_check(
                &report,
                "key_package",
                DoctorStatus::Fail,
                "wn-agent bootstrap",
            );
        }
    }

    #[test]
    fn key_package_unread_or_incomplete_is_not_ok() {
        let mut status = diagnostic(AgentControlDiagnosticKeyPackage::unavailable());
        assert_eq!(check_key_package(&status).status, DoctorStatus::Fail);
        status.selection = AgentControlAccountSelection::Ambiguous;
        assert_eq!(check_key_package(&status).status, DoctorStatus::Unknown);

        let mut incomplete = current_key_package();
        incomplete.accepted_fanout_targets = 1;
        incomplete.unattempted_fanout_targets = 2;
        let check = check_key_package(&diagnostic(incomplete));
        assert_eq!(check.status, DoctorStatus::Warn);
        assert!(
            check.summary.contains("2 not yet attempted"),
            "{}",
            check.summary
        );
    }

    #[test]
    fn daemon_without_accounts_but_home_with_one_points_at_instance() {
        let mut status = diagnostic(current_key_package());
        status.local_signing_account_count = 0;
        status.selection = AgentControlAccountSelection::None;
        let accounts = AccountScan {
            present: true,
            records: 1,
            local_signing: 1,
            ..AccountScan::default()
        };
        let check = check_daemon_accounts(&status, &accounts);
        assert_eq!(check.status, DoctorStatus::Fail);
        assert!(check.next_step.contains("same wn-agent instance"));
    }

    #[tokio::test]
    async fn daemon_requiring_token_reports_unauthorized() {
        let fixture = Fixture::new();
        fixture.dev_dir(0o700);
        fixture.account("agent", ACCOUNT_ID, true);
        let server = serve_daemon(
            fixture.socket(),
            Some(TOKEN),
            AgentControlResponse::DiagnosticStatus {
                report: diagnostic(current_key_package()),
            },
        )
        .await;
        let report = run_doctor(&fixture.options()).await;
        assert_check(&report, "daemon", DoctorStatus::Fail, "--auth-token-file");
        assert_check(
            &report,
            "protocol",
            DoctorStatus::Unknown,
            RERUN_AFTER_DAEMON,
        );

        fixture.token_file(TOKEN, 0o600);
        let report = run_doctor(&fixture.options()).await;
        server.abort();
        assert_check(&report, "daemon", DoctorStatus::Ok, NO_ACTION);
        assert_check(&report, "key_package", DoctorStatus::Ok, NO_ACTION);
    }

    #[tokio::test]
    async fn daemon_with_no_relays_or_other_home_is_flagged() {
        let fixture = Fixture::new();
        fixture.dev_dir(0o700);
        let mut status = diagnostic(current_key_package());
        status.relays = AgentControlDiagnosticRelays::default();
        status.connector_version = "0.0.1".to_owned();
        let server = serve_daemon(
            fixture.socket(),
            None,
            AgentControlResponse::DiagnosticStatus { report: status },
        )
        .await;
        let report = run_doctor(&fixture.options()).await;
        server.abort();
        assert_check(&report, "relay_health", DoctorStatus::Fail, "--relay");
        assert_check(
            &report,
            "protocol",
            DoctorStatus::Warn,
            "same wn-agent release",
        );
        // The daemon has one account; this home has none.
        assert_check(
            &report,
            "daemon_accounts",
            DoctorStatus::Warn,
            "same wn-agent instance",
        );
    }

    #[test]
    fn relay_health_statuses() {
        for (connected, disconnected, configured, status) in [
            (2, 0, 2, DoctorStatus::Ok),
            (1, 1, 2, DoctorStatus::Warn),
            (0, 0, 2, DoctorStatus::Warn),
            (0, 2, 2, DoctorStatus::Fail),
            (0, 0, 0, DoctorStatus::Fail),
        ] {
            let mut status_report = diagnostic(current_key_package());
            status_report.relays = AgentControlDiagnosticRelays {
                configured,
                connected,
                disconnected,
            };
            assert_eq!(
                check_relay_health(&status_report).status,
                status,
                "{connected}/{disconnected}/{configured}"
            );
        }
    }

    #[test]
    fn json_shape_snapshot() {
        let mut checks = vec![local(
            "home",
            DoctorStatus::Ok,
            "The home directory exists.",
            NO_ACTION,
        )];
        checks.extend(live_checks(
            &LiveOutcome::NotRunning,
            &AccountScan::default(),
        ));
        let json = serde_json::to_string_pretty(&DoctorReport::new(checks))
            .unwrap()
            .replace(env!("CARGO_PKG_VERSION"), "<version>");
        let unknown = |id: &str| {
            format!(
                r#"    {{
      "id": "{id}",
      "scope": "live",
      "status": "unknown",
      "summary": "Needs a reachable daemon.",
      "next_step": "{RERUN_AFTER_DAEMON}"
    }}"#
            )
        };
        let expected = format!(
            r#"{{
  "version": "<version>",
  "redacted": true,
  "counts": {{
    "ok": 1,
    "warn": 0,
    "fail": 1,
    "unknown": 5
  }},
  "checks": [
    {{
      "id": "home",
      "scope": "local",
      "status": "ok",
      "summary": "The home directory exists.",
      "next_step": "None."
    }},
    {{
      "id": "daemon",
      "scope": "live",
      "status": "fail",
      "summary": "wn-agent is not running at the configured socket.",
      "next_step": "{START_DAEMON}"
    }},
{}
  ],
  "note": "{DELIVERY_NOTE}"
}}"#,
            LIVE_IDS.map(unknown).join(",\n")
        );
        assert_eq!(json, expected);
    }

    #[tokio::test]
    async fn output_contains_no_paths_identifiers_relays_or_tokens() {
        let fixture = Fixture::new();
        fixture.dev_dir(0o777);
        fixture.account("agent-label-secret", ACCOUNT_ID, true);
        fixture.account("agent-label-other", SECOND_ACCOUNT_ID, true);
        let token_path = fixture.token_file(TOKEN, 0o644);
        let mut options = fixture.options_with(DoctorAuth::File {
            path: token_path.clone(),
            explicit: true,
        });
        options.relays = vec![RELAY.to_owned(), "not a relay".to_owned()];
        options.relay_source = RelaySource::Flag;
        let mut status = diagnostic(current_key_package());
        status.replay.state = AgentControlReplayState::Failed;
        status.replay.last_reason = Some(ACCOUNT_ID.to_owned());
        status.connector_version = ACCOUNT_ID.to_owned();
        let server = serve_daemon(
            fixture.socket(),
            Some(TOKEN),
            AgentControlResponse::DiagnosticStatus { report: status },
        )
        .await;
        let report = run_doctor(&options).await;
        server.abort();
        let outputs = [
            report.render_text(),
            serde_json::to_string(&report).unwrap(),
        ];
        let root = fixture.home.parent().unwrap().to_str().unwrap().to_owned();
        let socket = fixture.socket();
        let forbidden = [
            root.as_str(),
            fixture.home.to_str().unwrap(),
            socket.to_str().unwrap(),
            token_path.to_str().unwrap(),
            ACCOUNT_ID,
            SECOND_ACCOUNT_ID,
            "agent-label-secret",
            "agent-label-other",
            RELAY,
            DEFAULT_RELAYS[0],
            TOKEN,
        ];
        for output in &outputs {
            for value in forbidden {
                assert!(!output.contains(value), "output leaks {value:?}:\n{output}");
            }
        }
        assert_check(&report, "daemon", DoctorStatus::Ok, NO_ACTION);
        assert_check(&report, "replay", DoctorStatus::Warn, "relay_health");
    }
}
