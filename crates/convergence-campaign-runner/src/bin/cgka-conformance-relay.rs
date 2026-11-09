//! Retained in-memory Nostr relay for isolated distributed campaigns.
//!
//! The relay library serves no NIP-11 document, and the app's recovery runner
//! sizes and proves its history sweeps from one. A front on the campaign
//! listener answers NIP-11 requests with the document the in-process and
//! process routes' relays serve, and passes every other connection to the
//! relay on loopback unchanged.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use cgka_conformance_simulator::{PRODUCTION_RELAY_INFORMATION, asks_for_information};
use convergence_campaign_runner::file_control_relay_builder;
use nostr_relay_builder::LocalRelay;
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};

// A NIP-11 request or WebSocket upgrade head is far smaller.
const MAX_REQUEST_HEAD: usize = 16 * 1024;
const REQUEST_HEAD_TIMEOUT: Duration = Duration::from_secs(5);
const RELAY_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(100);

struct RelayOptions {
    bind: SocketAddr,
    advertise_ip: IpAddr,
    control_root: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> ExitCode {
    init_diagnostics();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            tracing::error!(
                target: "convergence_campaign_runner",
                method = "cgka_conformance_relay_main",
                failure = "relay_io"
            );
            ExitCode::FAILURE
        }
    }
}

fn init_diagnostics() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_writer(std::io::stderr)
        .try_init();
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let options = parse_relay_options(std::env::args().skip(1))?;
    let builder = match options.control_root {
        Some(control_root) => file_control_relay_builder(&control_root)?,
        None => cgka_conformance_simulator::harness_relay_builder(),
    };
    let relay = LocalRelay::new(builder.addr(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    relay.run().await?;
    let upstream = relay
        .url()
        .await
        .as_str()
        .strip_prefix("ws://")
        .ok_or("relay must listen on ws")?
        .trim_end_matches('/')
        .parse::<SocketAddr>()?;
    let listener = TcpListener::bind(options.bind).await?;
    tokio::spawn(serve_front(listener, upstream));
    tracing::info!(
        target: "convergence_campaign_runner",
        method = "run_relay",
        state = "ready",
        loopback_advertisement = options.advertise_ip.is_loopback()
    );
    std::future::pending::<()>().await;
    Ok(())
}

async fn serve_front(listener: TcpListener, upstream: SocketAddr) {
    loop {
        let (inbound, _) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(_) => {
                tracing::warn!(
                    target: "convergence_campaign_runner",
                    method = "serve_front",
                    failure = "accept"
                );
                sleep(ACCEPT_RETRY_DELAY).await;
                continue;
            }
        };
        tokio::spawn(serve_connection(inbound, upstream));
    }
}

/// Answer one NIP-11 request, or replay the bytes read so far to the relay and
/// relay the rest of the connection.
async fn serve_connection(mut inbound: TcpStream, upstream: SocketAddr) {
    let Ok(Some(opening)) = timeout(REQUEST_HEAD_TIMEOUT, read_opening(&mut inbound)).await else {
        return;
    };
    if asks_for_information(&opening) {
        let response = information_response(PRODUCTION_RELAY_INFORMATION);
        let _ = inbound.write_all(response.as_bytes()).await;
        let _ = inbound.shutdown().await;
        return;
    }
    // The relay's own loopback listener, pinned at startup; no DNS or external dial.
    let mut outbound = match timeout(RELAY_CONNECT_TIMEOUT, TcpStream::connect(upstream)).await {
        Ok(Ok(outbound)) => outbound,
        _ => {
            tracing::warn!(
                target: "convergence_campaign_runner",
                method = "serve_front",
                failure = "relay_connect"
            );
            return;
        }
    };
    if outbound.write_all(&opening).await.is_err() {
        return;
    }
    let _ = copy_bidirectional(&mut inbound, &mut outbound).await;
}

/// The bytes a client sent through the end of its request head, or every byte
/// read once the head limit is reached; `None` if it closed first.
async fn read_opening(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut opening = Vec::new();
    let mut buffer = [0; 4096];
    while !opening.windows(4).any(|window| window == b"\r\n\r\n")
        && opening.len() < MAX_REQUEST_HEAD
    {
        let read = stream.read(&mut buffer).await.ok()?;
        if read == 0 {
            return None;
        }
        opening.extend_from_slice(&buffer[..read]);
    }
    Some(opening)
}

fn information_response(document: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/nostr+json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{document}",
        document.len()
    )
}

fn parse_relay_options(
    args: impl Iterator<Item = String>,
) -> Result<RelayOptions, Box<dyn std::error::Error>> {
    let args = args.collect::<Vec<_>>();
    let mut bind = "0.0.0.0:8080".parse::<SocketAddr>()?;
    let mut advertise_ip = None;
    let mut control_root = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--bind" if index + 1 < args.len() => {
                bind = args[index + 1].parse()?;
                index += 2;
            }
            "--advertise-ip" if index + 1 < args.len() => {
                advertise_ip = Some(args[index + 1].parse()?);
                index += 2;
            }
            "--control-root" if index + 1 < args.len() => {
                control_root = Some(PathBuf::from(&args[index + 1]));
                index += 2;
            }
            _ => {
                return Err(
                    "usage: cgka-conformance-relay [--bind IP:PORT] [--advertise-ip IP] [--control-root PATH]".into(),
                );
            }
        }
    }
    let advertise_ip = advertise_ip.unwrap_or_else(|| {
        if bind.ip().is_unspecified() {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        } else {
            bind.ip()
        }
    });
    if advertise_ip.is_unspecified() {
        return Err("advertised relay address must be dialable".into());
    }
    Ok(RelayOptions {
        bind,
        advertise_ip,
        control_root,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn front_with_upstream() -> (SocketAddr, TcpListener) {
        let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let front = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = front.local_addr().unwrap();
        tokio::spawn(serve_front(front, upstream.local_addr().unwrap()));
        (address, upstream)
    }

    #[tokio::test]
    async fn campaign_relay_front_serves_the_production_information_document() {
        let (front, upstream) = front_with_upstream().await;
        let mut client = TcpStream::connect(front).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: relay\r\nAccept: application/nostr+json\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).await.unwrap();
        let (head, body) = response.split_once("\r\n\r\n").unwrap();
        assert!(head.starts_with("HTTP/1.1 200 OK"), "{head}");
        assert!(
            head.contains("Content-Type: application/nostr+json"),
            "{head}"
        );
        assert_eq!(body, PRODUCTION_RELAY_INFORMATION);
        assert!(
            timeout(Duration::from_millis(200), upstream.accept())
                .await
                .is_err(),
            "a NIP-11 request must not open a relay connection"
        );
    }

    #[tokio::test]
    async fn campaign_relay_front_passes_other_connections_through_unchanged() {
        let (front, upstream) = front_with_upstream().await;
        let opening = b"GET / HTTP/1.1\r\nHost: relay\r\nUpgrade: websocket\r\nAccept: application/nostr+json\r\n\r\nframe";
        let mut client = TcpStream::connect(front).await.unwrap();
        client.write_all(opening).await.unwrap();
        let (mut relay, _) = upstream.accept().await.unwrap();
        let mut received = vec![0; opening.len()];
        relay.read_exact(&mut received).await.unwrap();
        assert_eq!(received, opening);
        relay.write_all(b"reply").await.unwrap();
        let mut reply = [0; 5];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"reply");
    }

    #[test]
    fn wildcard_listener_advertises_loopback_by_default() {
        let options = parse_relay_options(std::iter::empty()).unwrap();
        assert!(options.bind.ip().is_unspecified());
        assert_eq!(options.advertise_ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert!(options.control_root.is_none());
    }

    #[test]
    fn advertised_address_is_separate_from_listener() {
        let options = parse_relay_options(
            ["--bind", "0.0.0.0:9000", "--advertise-ip", "192.0.2.4"]
                .into_iter()
                .map(str::to_owned),
        )
        .unwrap();
        assert_eq!(options.bind, "0.0.0.0:9000".parse().unwrap());
        assert_eq!(options.advertise_ip, "192.0.2.4".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn file_control_root_is_explicitly_configurable() {
        let options = parse_relay_options(
            ["--control-root", "/campaign-relay-control"]
                .into_iter()
                .map(str::to_owned),
        )
        .unwrap();
        assert_eq!(
            options.control_root,
            Some(PathBuf::from("/campaign-relay-control"))
        );
    }
}
