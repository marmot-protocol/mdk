mod config;
mod prime;

use std::process::ExitCode;

use clap::Parser;
use marmot_terminal_harness::Result;
use tracing::error;

#[derive(Debug, Parser)]
#[command(
    name = "wn-prime-agent",
    version,
    about = "Marmot adapter that routes allowed group messages to Prime Agent"
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
                "wn-prime-agent exiting after error"
            );
            eprintln!("wn-prime-agent: {err}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    let config = config::Config::from_env()?;
    let (harness, backend) = config.into_harness();
    marmot_terminal_harness::run(harness, backend).await
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new("info,marmot_terminal_harness=info")
            }),
        )
        .init();
}
