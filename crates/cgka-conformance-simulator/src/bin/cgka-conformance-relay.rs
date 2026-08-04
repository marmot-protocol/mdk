//! Retained in-memory Nostr relay for isolated distributed campaigns.

use std::net::SocketAddr;
use std::process::ExitCode;

use nostr_relay_builder::{LocalRelay, RelayBuilder};

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("conformance relay failed: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let bind = match (args.next().as_deref(), args.next()) {
        (None, None) => "0.0.0.0:8080".parse::<SocketAddr>()?,
        (Some("--bind"), Some(value)) if args.next().is_none() => value.parse()?,
        _ => return Err("usage: cgka-conformance-relay [--bind IP:PORT]".into()),
    };
    let relay = LocalRelay::new(RelayBuilder::default().addr(bind.ip()).port(bind.port()));
    relay.run().await?;
    println!("ready ws://{bind}");
    std::future::pending::<()>().await;
    Ok(())
}
