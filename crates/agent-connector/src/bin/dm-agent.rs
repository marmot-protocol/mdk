use std::path::PathBuf;
use std::process::{Command, ExitCode};
use std::time::Duration;

use agent_connector::{
    AgentConnectorConfig, BootstrapOptions, BootstrapResult, ConnectorError,
    DEFAULT_BOOTSTRAP_LABEL, default_socket_path, read_bootstrap_auth_token,
    resolve_bootstrap_home, resolve_bootstrap_quic_candidates, resolve_bootstrap_relays,
    resolve_bootstrap_socket, run_bootstrap, serve_socket,
};
use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "dm-agent",
    version,
    about = "Marmot local agent connector for Hermes and OpenClaw gateways"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
    #[command(flatten)]
    serve: ServeArgs,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Create or reuse a local agent account and print phone bootstrap details
    Bootstrap(BootstrapArgs),
}

#[derive(Debug, Args)]
struct ServeArgs {
    #[arg(long, value_name = "PATH", help = "Use this Darkmatter data directory")]
    home: Option<PathBuf>,
    #[arg(long, value_name = "PATH", help = "Listen on this Unix socket")]
    socket: Option<PathBuf>,
    #[arg(
        long,
        value_name = "URL",
        value_delimiter = ',',
        help = "Default relay URLs for hosted app runtime state"
    )]
    relay: Vec<String>,
    #[arg(
        long,
        help = "Accept all welcome invites without consulting the allowlist"
    )]
    allow_any: bool,
    #[arg(
        long,
        value_name = "PATH",
        help = "Require this local control-plane bearer token file for every request"
    )]
    auth_token_file: Option<PathBuf>,
    #[arg(
        long,
        value_name = "OCTAL",
        default_value = "0700",
        help = "Mode for the parent directory of the Unix control socket"
    )]
    socket_dir_mode: String,
    #[arg(
        long,
        value_name = "OCTAL",
        default_value = "0600",
        help = "Mode for the Unix control socket"
    )]
    socket_mode: String,
    #[arg(long, hide = true, help = "Enable debug-only local control requests")]
    debug_controls: bool,
}

#[derive(Debug, Args)]
struct BootstrapArgs {
    #[arg(
        long,
        value_name = "PATH",
        help = "Use this Marmot agent home directory"
    )]
    home: Option<PathBuf>,
    #[arg(
        long,
        value_name = "PATH",
        help = "Connect to this dm-agent Unix control socket"
    )]
    socket: Option<PathBuf>,
    #[arg(
        long,
        value_name = "LABEL",
        default_value = DEFAULT_BOOTSTRAP_LABEL,
        help = "Agent account label to create or reuse"
    )]
    label: String,
    #[arg(
        long,
        value_name = "HEX",
        help = "Reuse this local signing account instead of selecting by label"
    )]
    account_id_hex: Option<String>,
    #[arg(long, value_name = "TOKEN", help = "Control-plane auth token")]
    auth_token: Option<String>,
    #[arg(long, value_name = "PATH", help = "Control-plane auth token file")]
    auth_token_file: Option<PathBuf>,
    #[arg(
        long,
        value_name = "URL",
        help = "Public Nostr relay used for invite output; may be repeated"
    )]
    relay: Vec<String>,
    #[arg(
        long,
        value_name = "URI",
        help = "QUIC preview candidate included in bootstrap output; may be repeated"
    )]
    quic_candidate: Vec<String>,
    #[arg(
        long,
        value_name = "CSV",
        help = "Comma-separated QUIC preview candidates"
    )]
    quic_candidates: Option<String>,
    #[arg(long, help = "Omit default QUIC preview candidate from output")]
    no_quic: bool,
    #[arg(
        long,
        help = "Fail instead of creating an account when none exists locally"
    )]
    no_create: bool,
    #[arg(long, help = "Skip KeyPackage publish or repair during bootstrap")]
    no_publish_key_package: bool,
    #[arg(long, help = "Render invite URI as a terminal QR code using qrencode")]
    qr: bool,
    #[arg(long, help = "Print machine-readable JSON only")]
    json: bool,
    #[arg(
        long,
        value_name = "SECS",
        default_value = "15",
        help = "Seconds to wait for dm-agent control socket"
    )]
    wait_for_socket: f64,
    #[arg(
        long,
        value_name = "SECS",
        default_value = "30",
        help = "Seconds per control socket request"
    )]
    request_timeout: f64,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Some(Commands::Bootstrap(args)) => run_bootstrap_command(args).await,
        None => run_serve_command(cli.serve).await,
    }
}

async fn run_serve_command(args: ServeArgs) -> ExitCode {
    let Some(home) = args.home else {
        eprintln!("dm-agent: startup failed code=missing_home detail=--home is required");
        return ExitCode::FAILURE;
    };
    let socket = args.socket.unwrap_or_else(|| default_socket_path(&home));
    let socket_dir_mode = match parse_octal_mode(&args.socket_dir_mode) {
        Ok(mode) => mode,
        Err(message) => {
            eprintln!("dm-agent: startup failed code=invalid_socket_mode detail={message}");
            return ExitCode::FAILURE;
        }
    };
    let socket_mode = match parse_octal_mode(&args.socket_mode) {
        Ok(mode) => mode,
        Err(message) => {
            eprintln!("dm-agent: startup failed code=invalid_socket_mode detail={message}");
            return ExitCode::FAILURE;
        }
    };
    let auth_token = match read_auth_token(args.auth_token_file.as_ref()) {
        Ok(token) => token,
        Err(message) => {
            eprintln!("dm-agent: startup failed code=auth_token_file detail={message}");
            return ExitCode::FAILURE;
        }
    };
    let config = AgentConnectorConfig {
        home,
        socket,
        socket_dir_mode,
        socket_mode,
        relays: args.relay,
        allow_any: args.allow_any,
        debug_controls: args.debug_controls,
        auth_token,
    };
    match serve_socket(config).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("dm-agent: {}", safe_error_message(&err));
            ExitCode::FAILURE
        }
    }
}

async fn run_bootstrap_command(args: BootstrapArgs) -> ExitCode {
    let home = resolve_bootstrap_home(args.home);
    let socket = resolve_bootstrap_socket(&home, args.socket);
    let auth_token = match read_bootstrap_auth_token(args.auth_token, args.auth_token_file, &home) {
        Ok(token) => token,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };
    let relays = resolve_bootstrap_relays(args.relay);
    let quic_candidates =
        resolve_bootstrap_quic_candidates(args.quic_candidate, args.quic_candidates, args.no_quic);
    let options = BootstrapOptions {
        home,
        socket,
        label: args.label,
        account_id_hex: args.account_id_hex,
        auth_token,
        relays,
        quic_candidates,
        create_if_missing: !args.no_create,
        publish_key_package: !args.no_publish_key_package,
        wait_for_socket: Duration::from_secs_f64(args.wait_for_socket.max(0.0)),
        request_timeout: Duration::from_secs_f64(args.request_timeout.max(0.0)),
    };
    match run_bootstrap(options).await {
        Ok(result) => match write_bootstrap_output(&result, args.json, args.qr) {
            Ok(()) => ExitCode::SUCCESS,
            Err(message) => {
                eprintln!("error: {message}");
                ExitCode::FAILURE
            }
        },
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn write_bootstrap_output(
    result: &BootstrapResult,
    json_output: bool,
    render_qr: bool,
) -> Result<(), String> {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(result).map_err(|err| err.to_string())?
        );
        return Ok(());
    }

    let action = if result.created { "created" } else { "reused" };
    println!("Marmot agent bootstrap complete");
    println!("Status: {action}");
    println!("Agent label: {}", result.label);
    println!("Agent account hex: {}", result.account_id_hex);
    println!("Agent npub: {}", result.npub);
    println!("Agent nprofile: {}", result.nprofile);
    println!("Relay(s): {}", result.relays.join(", "));
    if result.quic_candidates.is_empty() {
        println!("QUIC candidate(s): none");
    } else {
        println!("QUIC candidate(s): {}", result.quic_candidates.join(", "));
    }
    if result.key_package_published {
        println!("KeyPackage: published or repaired");
    } else {
        println!("KeyPackage: skipped");
    }
    println!("QR payload: {}", result.qr_payload);

    if render_qr {
        render_bootstrap_qr(&result.qr_payload)?;
    }
    Ok(())
}

fn render_bootstrap_qr(payload: &str) -> Result<(), String> {
    println!();
    let Some(qrencode) = which_qrencode() else {
        println!("QR code: qrencode is not installed; use the QR payload above.");
        return Ok(());
    };
    println!("QR code:");
    let status = Command::new(qrencode)
        .args(["-t", "ANSIUTF8", payload])
        .status()
        .map_err(|err| format!("failed to run qrencode: {err}"))?;
    if status.success() {
        Ok(())
    } else {
        Err("qrencode failed".to_owned())
    }
}

fn which_qrencode() -> Option<String> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).find_map(|dir| {
            let candidate = dir.join("qrencode");
            candidate.is_file().then(|| candidate.display().to_string())
        })
    })
}

fn safe_error_message(err: &ConnectorError) -> String {
    format!("startup failed code={}", err.privacy_safe_code())
}

fn parse_octal_mode(value: &str) -> Result<u32, String> {
    let value = value.trim();
    let value = value.strip_prefix("0o").unwrap_or(value);
    let value = value.strip_prefix('0').unwrap_or(value);
    if value.is_empty() || value.len() > 3 || !value.chars().all(|ch| ('0'..='7').contains(&ch)) {
        return Err(format!("expected three octal digits, got {value:?}"));
    }
    u32::from_str_radix(value, 8).map_err(|err| err.to_string())
}

fn read_auth_token(path: Option<&PathBuf>) -> Result<Option<String>, String> {
    let Some(path) = path else {
        return Ok(None);
    };
    let token = std::fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    let token = token.trim().to_owned();
    if token.is_empty() {
        return Err(format!("{} is empty", path.display()));
    }
    Ok(Some(token))
}
