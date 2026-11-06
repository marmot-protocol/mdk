//! Shared relay fixture with a truthful NIP-11 page: the filter limit the
//! relay enforces, or none when it enforces none.
//!
//! Tests of ingestion and projection must reach those seams without depending
//! on unknown-cap, tied-second replay fences. Unknown-limit behavior has its
//! own transport fence and sweep proofs.

use nostr_relay_builder::{LocalRelay, RelayBuilder};
use std::time::Duration;
use tokio::time::timeout;

/// Advertise the same cap the relay enforces, so short replay fixtures do not
/// accidentally exercise the unknown-cap saturated-second fence. That fence's
/// bounded expiry is covered by replay_fence's paused-clock tests.
pub(crate) struct TestRelay {
    _relay: LocalRelay,
    proxy: tokio::task::JoinHandle<()>,
}

impl Drop for TestRelay {
    fn drop(&mut self) {
        self.proxy.abort();
    }
}

pub(crate) async fn mock_relay() -> (TestRelay, String) {
    relay_publishing(Some(500)).await
}

/// A relay that enforces and publishes `limit`, or publishes a page with no
/// limit and enforces none.
pub(crate) async fn relay_publishing(limit: Option<usize>) -> (TestRelay, String) {
    relay_publishing_with(RelayBuilder::default(), limit).await
}

/// As [`relay_publishing`], over a relay built from `builder` (a write
/// policy, say).
pub(crate) async fn relay_publishing_with(
    builder: RelayBuilder,
    limit: Option<usize>,
) -> (TestRelay, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    let (builder, body) = match limit {
        Some(limit) => (
            builder.max_filter_limit(limit),
            format!(r#"{{"supported_nips":[],"limitation":{{"max_limit":{limit}}}}}"#),
        ),
        None => (builder, r#"{"supported_nips":[]}"#.to_owned()),
    };
    let relay = LocalRelay::new(builder);
    relay.run().await.unwrap();
    let upstream = relay.url().await.to_string();
    let upstream = upstream
        .trim_start_matches("ws://")
        .trim_end_matches('/')
        .to_owned();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let proxy = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (mut client, _) = accepted.unwrap();
                    let upstream = upstream.clone();
                    let body = body.clone();
                    connections.spawn(async move {
                        let mut header = Vec::new();
                        let read_header = async {
                            while !header.windows(4).any(|w| w == b"\r\n\r\n") {
                                let mut bytes = [0; 1024];
                                let n = client.read(&mut bytes).await.ok()?;
                                if n == 0 || header.len() + n > 8192 { return None; }
                                header.extend_from_slice(&bytes[..n]);
                            }
                            Some(())
                        };
                        if timeout(Duration::from_secs(5), read_header).await != Ok(Some(())) { return; }
                        let info = String::from_utf8_lossy(&header).lines().any(|line| {
                            line.split_once(':').is_some_and(|(name, value)|
                                name.eq_ignore_ascii_case("accept") && value.contains("application/nostr+json"))
                        });
                        if info {
                            let reply = format!("HTTP/1.1 200 OK\r\nContent-Type: application/nostr+json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                            let _ = client.write_all(reply.as_bytes()).await;
                        } else if let Ok(mut server) = TcpStream::connect(&upstream).await
                            && server.write_all(&header).await.is_ok()
                        {
                            let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
                        }
                    });
                }
                Some(_) = connections.join_next(), if !connections.is_empty() => {}
            }
        }
    });
    (
        TestRelay {
            _relay: relay,
            proxy,
        },
        url,
    )
}
