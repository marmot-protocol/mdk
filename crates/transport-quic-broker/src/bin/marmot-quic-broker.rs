use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use transport_quic_broker::{QuicBrokerConfig, QuicBrokerServer, QuicBrokerTlsConfig};

#[derive(Debug, Parser)]
#[command(
    name = "marmot-quic-broker",
    about = "Memory-only Marmot QUIC stream broker"
)]
struct Args {
    #[arg(long, default_value = "0.0.0.0:4450", value_name = "ADDR")]
    bind: SocketAddr,
    #[arg(long, default_value_t = transport_quic_broker::DEFAULT_SUBSCRIBER_QUEUE_DEPTH)]
    per_subscriber_queue: usize,
    #[arg(long, default_value_t = transport_quic_broker::DEFAULT_BROKER_BACKLOG_DEPTH)]
    max_backlog: usize,
    /// Replay window (seconds) for serving retained backlog to late
    /// subscribers. 0 retains no replay; the hard cap is 300.
    #[arg(long, default_value_t = transport_quic_broker::DEFAULT_BROKER_REPLAY_TTL.as_secs())]
    replay_ttl_secs: u64,
    #[arg(long, value_name = "PATH", requires = "key_pem")]
    cert_pem: Option<PathBuf>,
    #[arg(long, value_name = "PATH", requires = "cert_pem")]
    key_pem: Option<PathBuf>,
    #[arg(long)]
    json: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let tls = match (args.cert_pem, args.key_pem) {
        (Some(cert_path), Some(key_path)) => QuicBrokerTlsConfig::PemFiles {
            cert_path,
            key_path,
        },
        (None, None) => QuicBrokerTlsConfig::GenerateSelfSigned {
            subject_alt_names: vec!["localhost".to_owned()],
        },
        _ => unreachable!("clap requires cert-pem and key-pem together"),
    };
    let tls_mode = match &tls {
        QuicBrokerTlsConfig::GenerateSelfSigned { .. } => "generated_self_signed",
        QuicBrokerTlsConfig::PemFiles { .. } => "pem_files",
    };
    let server = QuicBrokerServer::bind(QuicBrokerConfig {
        bind_addr: args.bind,
        per_subscriber_queue: args.per_subscriber_queue,
        max_backlog: args.max_backlog,
        replay_ttl: Duration::from_secs(args.replay_ttl_secs),
        tls,
        ..QuicBrokerConfig::default()
    })?;
    let local_addr = server.local_addr()?;
    let server_cert_sha256_fingerprint = server.server_cert_sha256_fingerprint();

    if args.json {
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({
                "ok": true,
                "result": {
                    "local_addr": local_addr.to_string(),
                    "server_cert_sha256_fingerprint": server_cert_sha256_fingerprint,
                    "tls": tls_mode,
                    "persistence": "none",
                    "per_subscriber_queue": args.per_subscriber_queue,
                    "max_backlog": args.max_backlog,
                    "replay_ttl_secs": args.replay_ttl_secs,
                }
            }))?
        );
    } else {
        eprintln!("listening on {local_addr}");
        eprintln!("server_cert_sha256_fingerprint={server_cert_sha256_fingerprint}");
        eprintln!("tls={tls_mode}");
        eprintln!("persistence=none");
        eprintln!("max_backlog={}", args.max_backlog);
        eprintln!("replay_ttl_secs={}", args.replay_ttl_secs);
    }

    server
        .run_until(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
