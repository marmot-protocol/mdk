use std::process::ExitCode;

use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};

const DEFAULT_RELAY_PROXY_LISTEN: &str = "127.0.0.1:18080";

struct NodeOptions {
    relay_proxy: Option<(String, String)>,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("conformance node I/O failed: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let options = parse_node_options(std::env::args().skip(1))?;
    if let Some((upstream, listen)) = options.relay_proxy {
        let listener = TcpListener::bind(listen).await?;
        tokio::spawn(run_relay_proxy(listener, upstream));
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
    if argument != "--relay-proxy" {
        return Err("usage: cgka-conformance-node [--relay-proxy HOST:PORT [--relay-proxy-listen HOST:PORT]]".into());
    }
    let upstream = args.next().ok_or("missing relay proxy upstream")?;
    let listen = match args.next() {
        None => DEFAULT_RELAY_PROXY_LISTEN.to_owned(),
        Some(flag) if flag == "--relay-proxy-listen" => {
            args.next().ok_or("missing relay proxy listen address")?
        }
        Some(_) => return Err("unexpected node argument".into()),
    };
    if args.next().is_some() {
        return Err("unexpected node argument".into());
    }
    Ok(NodeOptions {
        relay_proxy: Some((upstream, listen)),
    })
}

async fn run_relay_proxy(listener: TcpListener, upstream: String) {
    loop {
        let Ok((mut inbound, _)) = listener.accept().await else {
            return;
        };
        let upstream = upstream.clone();
        tokio::spawn(async move {
            let Ok(mut outbound) = TcpStream::connect(upstream).await else {
                return;
            };
            let _ = copy_bidirectional(&mut inbound, &mut outbound).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_proxy_listen_is_explicitly_configurable() {
        let options = parse_node_options(
            [
                "--relay-proxy",
                "relay:8080",
                "--relay-proxy-listen",
                "127.0.0.1:28080",
            ]
            .into_iter()
            .map(str::to_owned),
        )
        .unwrap();
        assert_eq!(
            options.relay_proxy,
            Some(("relay:8080".into(), "127.0.0.1:28080".into()))
        );
    }

    #[test]
    fn relay_proxy_default_is_stable_for_container_namespaces() {
        let options = parse_node_options(
            ["--relay-proxy", "relay:8080"]
                .into_iter()
                .map(str::to_owned),
        )
        .unwrap();
        assert_eq!(
            options.relay_proxy,
            Some(("relay:8080".into(), DEFAULT_RELAY_PROXY_LISTEN.into()))
        );
    }
}
