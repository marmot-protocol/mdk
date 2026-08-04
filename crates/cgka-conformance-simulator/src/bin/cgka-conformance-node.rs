use std::process::ExitCode;

use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};

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
    let mut args = std::env::args().skip(1);
    if let Some(argument) = args.next() {
        if argument != "--relay-proxy" {
            return Err("usage: cgka-conformance-node [--relay-proxy HOST:PORT]".into());
        }
        let upstream = args.next().ok_or("missing relay proxy upstream")?;
        if args.next().is_some() {
            return Err("unexpected node argument".into());
        }
        let listener = TcpListener::bind("127.0.0.1:18080").await?;
        tokio::spawn(run_relay_proxy(listener, upstream));
    }
    cgka_conformance_simulator::node_protocol::run_node_stdio().await?;
    Ok(())
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
