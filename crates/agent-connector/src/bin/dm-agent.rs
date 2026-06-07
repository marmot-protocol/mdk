use std::path::PathBuf;
use std::process::ExitCode;

use agent_connector::{AgentConnectorConfig, ConnectorError, default_socket_path, serve_socket};
use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "dm-agent",
    about = "Marmot local agent connector for Hermes and OpenClaw gateways"
)]
struct Args {
    #[arg(long, value_name = "PATH", help = "Use this Darkmatter data directory")]
    home: PathBuf,
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
    #[arg(long, hide = true, help = "Enable debug-only local control requests")]
    debug_controls: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();
    let socket = args
        .socket
        .unwrap_or_else(|| default_socket_path(&args.home));
    let config = AgentConnectorConfig {
        home: args.home,
        socket,
        relays: args.relay,
        allow_any: args.allow_any,
        debug_controls: args.debug_controls,
    };
    match serve_socket(config).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("dm-agent: {}", safe_error_message(&err));
            ExitCode::FAILURE
        }
    }
}

fn safe_error_message(err: &ConnectorError) -> String {
    format!("startup failed code={}", err.privacy_safe_code())
}
