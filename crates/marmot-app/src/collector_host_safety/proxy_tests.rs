use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_tungstenite::tungstenite::handshake::server::{
    Callback, ErrorResponse, Request, Response,
};

struct CaptureHeaders<'a>(&'a mut Vec<Vec<(String, String)>>);

impl Callback for CaptureHeaders<'_> {
    fn on_request(self, request: &Request, response: Response) -> Result<Response, ErrorResponse> {
        let mut headers: Vec<_> = request
            .headers()
            .iter()
            .filter(|(name, _)| name.as_str() != "sec-websocket-key")
            .map(|(name, value)| (name.as_str().to_owned(), value.to_str().unwrap().to_owned()))
            .collect();
        headers.sort_unstable();
        self.0.push(headers);
        Ok(response)
    }
}

struct ForbiddenDns(Arc<AtomicUsize>);

impl reqwest::dns::Resolve for ForbiddenDns {
    fn resolve(&self, _: reqwest::dns::Name) -> reqwest::dns::Resolving {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(std::io::Error::other("second DNS lookup").into()) })
    }
}

fn clear_proxy_environment() {
    // SAFETY: This isolated subprocess runs only this test on a current-thread
    // runtime. Its sole policy consumer has already taken the process snapshot;
    // no other thread reads these variables while they are removed.
    unsafe {
        std::env::remove_var("WN_SOCKS5_PROXY");
        std::env::remove_var("WN_SOCKS5_USERNAME");
        std::env::remove_var("WN_SOCKS5_PASSWORD");
    }
}

// Run the environment-sensitive consumer in a subprocess so parallel tests
// never observe changes to their process-wide network policy.
#[tokio::test]
async fn socks5_pins_dns_fail_closed() {
    use crate::relay_plane::{
        DirectoryEventQuery, DirectoryFetchRequest, DirectoryRelayFetcher,
        NostrSdkDirectoryRelayFetcher,
    };
    use cgka_traits::TransportEndpoint;
    use futures::{SinkExt, StreamExt};

    const CHILD: &str = "WN_PROXY_ROUTING_TEST_CHILD";
    const MODE: &str = "WN_PROXY_ROUTING_TEST_MODE";
    const USERNAME: &str = "proxy-ü:@/%";
    const PASSWORD: &str = "proxy-secret:@/%";
    let directory = |relay: String| async move {
        let request = DirectoryFetchRequest::new(
            vec![TransportEndpoint(relay)],
            vec![DirectoryEventQuery::new(
                0,
                vec![nostr_sdk::prelude::Keys::generate().public_key().to_hex()],
                10,
            )],
        )
        .unwrap();
        NostrSdkDirectoryRelayFetcher::standalone()
            .fetch_directory_events_with_completion(request)
            .await
            .unwrap()
    };
    if let Ok(origin) = std::env::var(CHILD) {
        let mode = std::env::var(MODE).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        // Builder fixture only: production resolution rejects loopback answers
        // for ordinary hostnames. An unresolvable name proves use of the pin.
        let pin = PinnedCollector {
            url: Url::parse(&format!("http://pin-only.invalid:{origin}/metrics")).unwrap(),
            addrs: vec![format!("127.0.0.1:{origin}").parse().unwrap()],
        };
        if mode == "partial" || mode == "orphan" {
            assert!(pin.build_client().is_err());
            clear_proxy_environment();
            assert!(
                pin.build_client().is_err(),
                "invalid snapshot must stay blocked"
            );
            let relays = crate::network_proxy::nostr_builder().build();
            let relay = format!("ws://127.0.0.1:{origin}");
            relays.add_relay(&relay).await.unwrap();
            assert!(
                relays
                    .try_connect_relay(&relay, Duration::from_secs(5))
                    .await
                    .is_err()
            );
            relays.shutdown().await;
            assert!(!directory(relay).await.complete);
            return;
        }
        let client = pin
            .build_client_from(
                reqwest::Client::builder().dns_resolver(Arc::new(ForbiddenDns(calls.clone()))),
            )
            .unwrap();
        let response = client.post(pin.url.clone()).send().await;
        if mode == "rejected" {
            assert!(response.is_err());
        } else {
            assert!(response.unwrap().status().is_success());
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "SOCKS must use the validated pin"
        );

        let relays = crate::network_proxy::nostr_builder().build();
        let relay = if mode == "rejected" {
            format!("ws://127.0.0.1:{origin}")
        } else {
            "ws://proxy-dns.invalid".to_owned()
        };
        relays.add_relay(&relay).await.unwrap();
        let connection = relays
            .try_connect_relay(&relay, Duration::from_secs(5))
            .await;
        assert_eq!(connection.is_err(), mode == "rejected");
        relays.shutdown().await;
        let outcome = directory(relay).await;
        assert_eq!(outcome.complete, mode != "rejected");
        assert!(outcome.records.is_empty());

        clear_proxy_environment();
        // The proxy has closed. Later clients must retain its policy despite
        // cleared variables, a reachable origin, and NO_PROXY matching everything.
        let client = pin.build_client().unwrap();
        assert!(client.post(pin.url).send().await.is_err());
        let relay = format!("ws://127.0.0.1:{origin}");
        let relays = crate::network_proxy::nostr_builder().build();
        relays.add_relay(&relay).await.unwrap();
        assert!(
            relays
                .try_connect_relay(&relay, Duration::from_secs(5))
                .await
                .is_err()
        );
        relays.shutdown().await;
        assert!(!directory(relay).await.complete);
        return;
    }

    let mut anonymous_headers = None;
    for mode in [
        "anonymous",
        "authenticated",
        "rejected",
        "partial",
        "orphan",
    ] {
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_port = origin.local_addr().unwrap().port();
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let (shutdown, finished) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            if mode == "partial" || mode == "orphan" {
                return Vec::new();
            }
            let mut websocket_headers = Vec::new();
            let serve = async {
                let mut relay_sockets = Vec::new();
                for route in ["http", "relay", "directory"] {
                    let (mut stream, _) = proxy.accept().await.unwrap();
                    let mut greeting = [0; 2];
                    stream.read_exact(&mut greeting).await.unwrap();
                    assert_eq!(greeting[0], 5);
                    let mut methods = vec![0; greeting[1] as usize];
                    stream.read_exact(&mut methods).await.unwrap();
                    if mode == "anonymous" {
                        assert!(methods.contains(&0));
                        stream.write_all(&[5, 0]).await.unwrap();
                    } else {
                        assert!(
                            methods.contains(&2),
                            "client must offer RFC1929 authentication"
                        );
                        stream.write_all(&[5, 2]).await.unwrap();
                        assert_eq!(stream.read_u8().await.unwrap(), 1);
                        let len = stream.read_u8().await.unwrap() as usize;
                        let mut username = vec![0; len];
                        stream.read_exact(&mut username).await.unwrap();
                        let len = stream.read_u8().await.unwrap() as usize;
                        let mut password = vec![0; len];
                        stream.read_exact(&mut password).await.unwrap();
                        assert!(username == USERNAME.as_bytes(), "unexpected username bytes");
                        if mode == "rejected" {
                            assert!(
                                password != PASSWORD.as_bytes(),
                                "test must provide rejected credentials"
                            );
                            stream.write_all(&[1, 1]).await.unwrap();
                            assert!(
                                stream.read_u8().await.is_err(),
                                "no CONNECT after authentication rejection"
                            );
                            continue;
                        }
                        assert!(password == PASSWORD.as_bytes(), "unexpected password bytes");
                        stream.write_all(&[1, 0]).await.unwrap();
                    }
                    let mut request = [0; 4];
                    stream.read_exact(&mut request).await.unwrap();
                    assert_eq!(&request[..3], &[5, 1, 0]);
                    if route != "http" {
                        assert_eq!(request[3], 3, "relay DNS must be proxy-side");
                        let len = stream.read_u8().await.unwrap() as usize;
                        let mut domain = vec![0; len];
                        stream.read_exact(&mut domain).await.unwrap();
                        assert_eq!(domain, b"proxy-dns.invalid");
                        assert_eq!(stream.read_u16().await.unwrap(), 80);
                        stream
                            .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                            .await
                            .unwrap();
                        let mut socket = tokio_tungstenite::accept_hdr_async(
                            stream,
                            CaptureHeaders(&mut websocket_headers),
                        )
                        .await
                        .unwrap();
                        if route == "directory" {
                            loop {
                                let message = socket.next().await.unwrap().unwrap();
                                let Some(text) = message.to_text().ok() else {
                                    continue;
                                };
                                let request: serde_json::Value =
                                    serde_json::from_str(text).unwrap();
                                if request[0] != "REQ" {
                                    continue;
                                }
                                socket
                                    .send(tokio_tungstenite::tungstenite::Message::Text(
                                        serde_json::json!(["EOSE", request[1]]).to_string().into(),
                                    ))
                                    .await
                                    .unwrap();
                                break;
                            }
                        }
                        relay_sockets.push(socket);
                    } else {
                        assert_eq!(
                            request[3], 1,
                            "HTTP must send the vetted IP, not the hostname"
                        );
                        let mut ip = [0; 4];
                        stream.read_exact(&mut ip).await.unwrap();
                        assert_eq!(ip, [127, 0, 0, 1]);
                        assert_eq!(stream.read_u16().await.unwrap(), origin_port);
                        stream
                            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                            .await
                            .unwrap();
                        let mut headers = Vec::new();
                        while !headers.ends_with(b"\r\n\r\n") {
                            headers.push(stream.read_u8().await.unwrap());
                            assert!(headers.len() < 8192);
                        }
                        let headers = String::from_utf8(headers).unwrap().to_lowercase();
                        assert!(headers.starts_with("post /metrics http/1.1\r\n"));
                        assert!(
                            headers.contains(&format!("host: pin-only.invalid:{origin_port}\r\n"))
                        );
                        stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                        )
                        .await
                        .unwrap();
                    }
                }
                relay_sockets
            };
            let socket = tokio::time::timeout(Duration::from_secs(20), serve)
                .await
                .unwrap();
            // Refuse subsequent HTTP attempts, but keep the relay alive until
            // the client has observed its completed WebSocket handshake.
            drop(proxy);
            finished.await.unwrap();
            drop(socket);
            websocket_headers
        });
        let output = tokio::task::spawn_blocking(move || {
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "collector_host_safety::proxy_tests::socks5_pins_dns_fail_closed",
                    "--nocapture",
                ])
                .env(CHILD, origin_port.to_string())
                .env(MODE, mode)
                .env(
                    "WN_SOCKS5_PROXY",
                    if mode == "orphan" {
                        String::new()
                    } else {
                        proxy_addr.to_string()
                    },
                )
                .env(
                    "WN_SOCKS5_USERNAME",
                    if mode == "anonymous" { "" } else { USERNAME },
                )
                .env(
                    "WN_SOCKS5_PASSWORD",
                    match mode {
                        "anonymous" | "partial" => "",
                        "rejected" => "incorrect",
                        _ => PASSWORD,
                    },
                )
                .env("ALL_PROXY", "http://127.0.0.1:1")
                .env("NO_PROXY", "*")
                .output()
                .unwrap()
        })
        .await
        .unwrap();
        if mode != "partial" && mode != "orphan" {
            shutdown.send(()).unwrap();
        }
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let headers = server.await.unwrap();
        if mode == "anonymous" || mode == "authenticated" {
            assert_eq!(
                headers.len(),
                2,
                "capture relay and strict directory handshakes"
            );
            assert_eq!(
                headers[0], headers[1],
                "subsystems must not fingerprint handshakes"
            );
            assert!(
                headers[0]
                    .iter()
                    .any(|(name, value)| name == "user-agent" && !value.is_empty()),
                "capture the SDK User-Agent"
            );
            if mode == "anonymous" {
                anonymous_headers = Some(headers);
            } else {
                assert_eq!(
                    anonymous_headers.as_ref().unwrap(),
                    &headers,
                    "authentication must not fingerprint WebSocket headers or User-Agent"
                );
            }
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(100), origin.accept())
                .await
                .is_err(),
            "explicit proxy failure must not dial the origin directly"
        );
    }
}
