//! Application-runtime node for isolated distributed campaigns.
//!
//! The JSONL node protocol remains simulator-owned. Real sockets and the
//! campaign-only relay bridge live here at the OS orchestration boundary.

use std::net::{IpAddr, SocketAddr};
use std::process::ExitCode;
use std::time::Duration;

use convergence_campaign_runner::{ISOLATED_RELAY_NETWORK_ALIAS, ISOLATED_RELAY_PORT};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream, lookup_host};
use tokio::time::{sleep, timeout};

const DEFAULT_RELAY_PROXY_LISTEN: &str = "127.0.0.1:18080";
const RELAY_PROXY_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const RELAY_PROXY_ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(100);

#[derive(Debug, PartialEq, Eq)]
struct RelayProxyOptions {
    listen: SocketAddr,
}

struct NodeOptions {
    relay_proxy: Option<RelayProxyOptions>,
}

#[tokio::main]
async fn main() -> ExitCode {
    init_diagnostics();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            tracing::error!(
                target: "convergence_campaign_runner",
                method = "cgka_conformance_node_main",
                failure = "node_io"
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
    let options = parse_node_options(std::env::args().skip(1))?;
    if let Some(proxy) = options.relay_proxy {
        let listener = TcpListener::bind(proxy.listen).await?;
        tokio::spawn(run_relay_proxy(listener));
    }
    cgka_conformance_simulator::node_protocol::run_node_stdio().await?;
    Ok(())
}

fn parse_node_options(
    mut args: impl Iterator<Item = String>,
) -> Result<NodeOptions, Box<dyn std::error::Error>> {
    let Some(argument) = args.next() else {
        return Ok(NodeOptions { relay_proxy: None });
    };
    if argument != "--allow-cleartext-isolated-relay" {
        return Err(usage().into());
    }
    let listen = match args.next() {
        None => DEFAULT_RELAY_PROXY_LISTEN.parse::<SocketAddr>()?,
        Some(flag) if flag == "--relay-proxy-listen" => args
            .next()
            .ok_or("missing relay proxy listen address")?
            .parse::<SocketAddr>()?,
        Some(_) => return Err("unexpected node argument".into()),
    };
    if args.next().is_some() {
        return Err("unexpected node argument".into());
    }
    if !listen.ip().is_loopback() {
        return Err("relay proxy listener must be loopback-only".into());
    }
    Ok(NodeOptions {
        relay_proxy: Some(RelayProxyOptions { listen }),
    })
}

fn usage() -> &'static str {
    "usage: cgka-conformance-node [--allow-cleartext-isolated-relay [--relay-proxy-listen LOOPBACK:PORT]]"
}

async fn resolve_authorized_campaign_relay()
-> Result<SocketAddr, Box<dyn std::error::Error + Send + Sync>> {
    // This is not a general host dial. The runner owns this fixed alias and
    // attaches it only to the relay on the isolated campaign network. General
    // outbound dials must use the shared public-host safety gate instead.
    let mut addresses = lookup_host((ISOLATED_RELAY_NETWORK_ALIAS, ISOLATED_RELAY_PORT))
        .await?
        .collect::<Vec<_>>();
    if addresses.is_empty()
        || addresses
            .iter()
            .any(|address| !is_private_container_ip(address.ip()))
    {
        return Err(
            "relay proxy upstream must resolve only inside the private container network".into(),
        );
    }
    addresses.sort_unstable();
    Ok(addresses[0])
}

fn is_private_container_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private(),
        IpAddr::V6(ip) => ip.is_unique_local(),
    }
}

async fn run_relay_proxy(listener: TcpListener) {
    loop {
        let (mut inbound, _) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(_) => {
                tracing::warn!(
                    target: "convergence_campaign_runner",
                    method = "run_relay_proxy",
                    failure = "accept"
                );
                sleep(RELAY_PROXY_ACCEPT_RETRY_DELAY).await;
                continue;
            }
        };
        tokio::spawn(async move {
            let resolved = match timeout(
                RELAY_PROXY_CONNECT_TIMEOUT,
                resolve_authorized_campaign_relay(),
            )
            .await
            {
                Ok(Ok(resolved)) => resolved,
                Ok(Err(_)) => {
                    tracing::warn!(
                        target: "convergence_campaign_runner",
                        method = "run_relay_proxy",
                        failure = "resolve"
                    );
                    return;
                }
                Err(_) => {
                    tracing::warn!(
                        target: "convergence_campaign_runner",
                        method = "run_relay_proxy",
                        failure = "resolve_timeout"
                    );
                    return;
                }
            };
            let mut outbound =
                match timeout(RELAY_PROXY_CONNECT_TIMEOUT, TcpStream::connect(resolved)).await {
                    Ok(Ok(outbound)) => outbound,
                    Ok(Err(_)) => {
                        tracing::warn!(
                            target: "convergence_campaign_runner",
                            method = "run_relay_proxy",
                            failure = "connect"
                        );
                        return;
                    }
                    Err(_) => {
                        tracing::warn!(
                            target: "convergence_campaign_runner",
                            method = "run_relay_proxy",
                            failure = "connect_timeout"
                        );
                        return;
                    }
                };
            let _ = copy_bidirectional(&mut inbound, &mut outbound).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args<'a>(values: &'a [&'a str]) -> impl Iterator<Item = String> + 'a {
        values.iter().copied().map(str::to_owned)
    }

    #[test]
    fn relay_proxy_requires_explicit_cleartext_boundary_opt_in() {
        let error = parse_node_options(args(&["--relay-proxy-listen", "127.0.0.1:18080"]))
            .err()
            .unwrap();
        assert_eq!(error.to_string(), usage());
    }

    #[test]
    fn relay_proxy_listen_is_explicitly_configurable() {
        let options = parse_node_options(args(&[
            "--allow-cleartext-isolated-relay",
            "--relay-proxy-listen",
            "127.0.0.1:28080",
        ]))
        .unwrap();
        assert_eq!(
            options.relay_proxy,
            Some(RelayProxyOptions {
                listen: "127.0.0.1:28080".parse().unwrap(),
            })
        );
    }

    #[test]
    fn relay_proxy_rejects_non_loopback_listener() {
        let error = parse_node_options(args(&[
            "--allow-cleartext-isolated-relay",
            "--relay-proxy-listen",
            "0.0.0.0:28080",
        ]))
        .err()
        .unwrap();
        assert_eq!(
            error.to_string(),
            "relay proxy listener must be loopback-only"
        );
    }

    #[test]
    fn relay_proxy_rejects_configurable_upstream() {
        let error = parse_node_options(args(&[
            "--allow-cleartext-isolated-relay",
            "--relay-proxy",
            "other-service:8080",
        ]))
        .err()
        .unwrap();
        assert_eq!(error.to_string(), "unexpected node argument");
    }

    #[test]
    fn container_ip_policy_rejects_public_and_loopback_addresses() {
        assert!(is_private_container_ip("172.18.0.2".parse().unwrap()));
        assert!(is_private_container_ip("fd00::2".parse().unwrap()));
        assert!(!is_private_container_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_private_container_ip("127.0.0.1".parse().unwrap()));
    }
}
