//! Retained in-memory Nostr relay for isolated distributed campaigns.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::ExitCode;

use nostr_relay_builder::{LocalRelay, RelayBuilder};

struct RelayOptions {
    bind: SocketAddr,
    advertise_ip: IpAddr,
}

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
    let options = parse_relay_options(std::env::args().skip(1))?;
    let relay = LocalRelay::new(
        RelayBuilder::default()
            .addr(options.bind.ip())
            .port(options.bind.port()),
    );
    relay.run().await?;
    println!(
        "ready ws://{}",
        SocketAddr::new(options.advertise_ip, options.bind.port())
    );
    std::future::pending::<()>().await;
    Ok(())
}

fn parse_relay_options(
    args: impl Iterator<Item = String>,
) -> Result<RelayOptions, Box<dyn std::error::Error>> {
    let args = args.collect::<Vec<_>>();
    let mut bind = "0.0.0.0:8080".parse::<SocketAddr>()?;
    let mut advertise_ip = None;
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
            _ => {
                return Err(
                    "usage: cgka-conformance-relay [--bind IP:PORT] [--advertise-ip IP]".into(),
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
    Ok(RelayOptions { bind, advertise_ip })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_listener_advertises_loopback_by_default() {
        let options = parse_relay_options(std::iter::empty()).unwrap();
        assert!(options.bind.ip().is_unspecified());
        assert_eq!(options.advertise_ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
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
}
