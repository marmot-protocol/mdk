mod config;
mod opencode;

use std::process::ExitCode;

use clap::Parser;
use marmot_terminal_harness::Result;
use tracing::error;

#[derive(Debug, Parser)]
#[command(
    name = "wn-opencode",
    version,
    about = "Marmot harness that routes allowed group messages to opencode"
)]
struct Cli {}

#[tokio::main]
async fn main() -> ExitCode {
    let _cli = Cli::parse();
    init_tracing();

    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            error!(
                target: marmot_terminal_harness::TRACE_TARGET,
                method = "main",
                error_kind = err.privacy_safe_kind(),
                "wn-opencode exiting after error"
            );
            eprintln!("wn-opencode: {err}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    let config = config::Config::from_env()?;
    let (config, backend) = config.into_harness();
    marmot_terminal_harness::run(config, backend).await
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,wn_opencode=info")),
        )
        .init();
}
